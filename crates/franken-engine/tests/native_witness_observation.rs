//! Real source -> native execution -> signed empirical Draft regressions.
//! Signing keys and static Draft inputs are test fixtures; all observation
//! counts, completions and host-effect comparisons come from actual execution.

use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability_witness::native_observation::{
    NATIVE_OBSERVATION_CORPUS_SCHEMA, NativeObservationCase, NativeObservationConfig,
    NativeObservationCorpus, NativeObservationFailureClass, NativeObservedCompletion,
    SignedNativeObservationTranscript, observe_native_witness,
};
use frankenengine_engine::capability_witness::{
    CapabilityWitness, CapabilityWitnessTrustRoot, ConfidenceInterval, LifecycleState, ProofKind,
    ProofObligation, WitnessBuilder, WitnessValidator,
};
use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::{SigningKey, sign_preimage};
use frankenengine_extension_host::host_io::{HostIoRequest, HostIoResponse};

const CLOCK_SOURCE: &str = "console.log(Date.now());";
const MIN_CLOCK_CAPS: &[&str] = &["vm_dispatch", "heap_allocate", "builtin", "console"];
const BASELINE_CAPS: &[&str] = &[
    "vm_dispatch",
    "heap_allocate",
    "builtin",
    "console",
    "timer",
    "gc_invoke",
    "ir_lowering",
];

fn key() -> SigningKey {
    SigningKey::from_bytes([0x73; 32]).expect("test signing key")
}

fn root() -> CapabilityWitnessTrustRoot {
    CapabilityWitnessTrustRoot::single_authority(key().verification_key())
}

fn caps(names: &[&str]) -> BTreeSet<Capability> {
    names.iter().map(|name| Capability::new(*name)).collect()
}

fn draft(source: &str, names: &[&str]) -> CapabilityWitness {
    let schema = SchemaId::from_definition(b"NativeObservationTestInput.v1");
    let extension = derive_id(
        ObjectDomain::Attestation,
        "native-observation-test",
        &schema,
        source.as_bytes(),
    )
    .unwrap();
    let policy = derive_id(
        ObjectDomain::PolicyObject,
        "native-observation-test",
        &schema,
        b"test-policy",
    )
    .unwrap();
    let proof_id = derive_id(
        ObjectDomain::EvidenceRecord,
        "native-observation-test",
        &schema,
        b"static-test-input",
    )
    .unwrap();
    let source_hash = ContentHash::compute(source.as_bytes());
    let mut builder = WitnessBuilder::new(extension, policy, SecurityEpoch::from_raw(7), 1, key())
        .confidence(ConfidenceInterval::from_trials(0, 0))
        .meta("source_sha256", source_hash.to_hex())
        .meta("parse_goal", "script")
        .meta(
            "trusted_synthesizer_verification_key",
            key().verification_key().to_hex(),
        );
    for cap in caps(names) {
        builder = builder.require(cap.clone()).proof(ProofObligation {
            capability: cap,
            kind: ProofKind::StaticAnalysis,
            proof_artifact_id: proof_id.clone(),
            artifact_hash: source_hash,
            justification: "Test static input fixture; no empirical trials have been asserted"
                .to_string(),
        });
    }
    builder.build().unwrap()
}

fn corpus(count: usize) -> NativeObservationCorpus {
    NativeObservationCorpus {
        schema_version: NATIVE_OBSERVATION_CORPUS_SCHEMA.to_string(),
        cases: (0..count)
            .map(|index| NativeObservationCase {
                case_id: format!("clock-{index}"),
                process_argv: Vec::new(),
                clock_epoch_ms: 1_800_000_000_000 + index as i64,
                host_effects: Vec::new(),
            })
            .collect(),
    }
}

fn config(candidate: &[&str]) -> NativeObservationConfig {
    NativeObservationConfig {
        expected_epoch: SecurityEpoch::from_raw(7),
        candidate_capabilities: Some(caps(candidate)),
        timestamp_ns: 2,
        ..NativeObservationConfig::default()
    }
}

#[test]
fn native_clock_cases_produce_signed_draft_from_actual_final_envelope_trials() {
    let input = draft(CLOCK_SOURCE, BASELINE_CAPS);
    let corpus = corpus(40);
    let result = observe_native_witness(
        &input,
        CLOCK_SOURCE,
        &corpus,
        &config(MIN_CLOCK_CAPS),
        &root(),
        &key(),
    )
    .unwrap();
    let witness = result
        .witness
        .as_ref()
        .expect("real baseline/candidate parity");
    let body = &result.transcript.body;
    assert!(body.candidate_matches_baseline);
    assert_eq!(body.baseline_executions, 40);
    assert_eq!(body.candidate_executions, 40);
    assert_eq!(body.ablation_executions, 160);
    assert_eq!(body.ablation_breakages, 160);
    assert_eq!(
        witness.confidence,
        ConfidenceInterval::from_trials(160, 160)
    );
    assert!(
        WitnessValidator::new()
            .validate_structural(witness)
            .is_empty()
    );
    assert_eq!(witness.lifecycle_state, LifecycleState::Draft);
    assert!(witness.promotion_signatures.is_empty());
    assert_ne!(witness.witness_id, input.witness_id);
    assert_eq!(witness.required_capabilities, caps(MIN_CLOCK_CAPS));
    assert!(
        witness
            .denied_capabilities
            .contains(&Capability::new("timer"))
    );
    for (case, record) in corpus.cases.iter().zip(&body.records) {
        assert_eq!(record.baseline.console_output.len(), 1);
        assert_eq!(
            record.baseline.console_output[0].message,
            case.clock_epoch_ms.to_string()
        );
        assert_eq!(record.candidate.as_ref(), Some(&record.baseline));
        assert_eq!(record.ablations.len(), 4);
        assert!(record.ablations.iter().all(|trial| trial.behavior_changed));
    }
    result
        .transcript
        .verify(&root(), SecurityEpoch::from_raw(7))
        .unwrap();
    result
        .transcript
        .verify_witness(witness, &root(), SecurityEpoch::from_raw(7))
        .unwrap();
}

#[test]
fn unused_retained_authorities_lower_confidence_without_inventing_necessity() {
    let input = draft(CLOCK_SOURCE, BASELINE_CAPS);
    let result = observe_native_witness(
        &input,
        CLOCK_SOURCE,
        &corpus(2),
        &config(BASELINE_CAPS),
        &root(),
        &key(),
    )
    .unwrap();
    let witness = result.witness.unwrap();
    assert_eq!(result.transcript.body.ablation_executions, 14);
    assert_eq!(result.transcript.body.ablation_breakages, 8);
    assert_eq!(witness.confidence, ConfidenceInterval::from_trials(14, 8));
    assert!(
        !WitnessValidator::new()
            .validate_structural(&witness)
            .is_empty()
    );
    assert!(
        !witness
            .proof_obligations
            .iter()
            .any(|proof| proof.kind == ProofKind::DynamicAblation
                && proof.capability == Capability::new("timer"))
    );
}

#[test]
fn candidate_denial_preserves_actual_failed_observation_and_issues_no_witness() {
    let input = draft(CLOCK_SOURCE, BASELINE_CAPS);
    let result = observe_native_witness(
        &input,
        CLOCK_SOURCE,
        &corpus(2),
        &config(&["vm_dispatch", "heap_allocate", "builtin"]),
        &root(),
        &key(),
    )
    .unwrap();
    assert!(result.witness.is_none());
    assert!(!result.transcript.body.candidate_matches_baseline);
    assert_eq!(result.transcript.body.baseline_executions, 1);
    assert_eq!(result.transcript.body.candidate_executions, 1);
    assert_eq!(result.transcript.body.ablation_executions, 0);
    let record = &result.transcript.body.records[0];
    assert_eq!(record.baseline.console_output.len(), 1);
    assert!(matches!(
        record.candidate.as_ref().unwrap().completion,
        NativeObservedCompletion::Failed {
            class: NativeObservationFailureClass::CapabilityDenied,
            ..
        }
    ));
    result
        .transcript
        .verify(&root(), SecurityEpoch::from_raw(7))
        .unwrap();
}

#[test]
fn duplicate_input_contexts_cannot_multiply_trials_by_changing_case_labels() {
    let input = draft(CLOCK_SOURCE, MIN_CLOCK_CAPS);
    let mut cases = corpus(2);
    cases.cases[1].clock_epoch_ms = cases.cases[0].clock_epoch_ms;
    let error = observe_native_witness(
        &input,
        CLOCK_SOURCE,
        &cases,
        &config(MIN_CLOCK_CAPS),
        &root(),
        &key(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("duplicate input context"));
}

#[test]
fn exact_source_epoch_and_signer_are_required_before_observation() {
    let input = draft(CLOCK_SOURCE, MIN_CLOCK_CAPS);
    let corpus = corpus(1);
    let policy = config(MIN_CLOCK_CAPS);
    assert!(
        observe_native_witness(&input, "console.log(1);", &corpus, &policy, &root(), &key())
            .unwrap_err()
            .to_string()
            .contains("source SHA256")
    );
    let mut wrong_epoch = policy.clone();
    wrong_epoch.expected_epoch = SecurityEpoch::from_raw(8);
    assert!(
        observe_native_witness(&input, CLOCK_SOURCE, &corpus, &wrong_epoch, &root(), &key())
            .unwrap_err()
            .to_string()
            .contains("epoch")
    );
    let other = SigningKey::from_bytes([0x74; 32]).unwrap();
    assert!(
        observe_native_witness(&input, CLOCK_SOURCE, &corpus, &policy, &root(), &other)
            .unwrap_err()
            .to_string()
            .contains("not authorized")
    );
    // Even another authorized synthesis key cannot impersonate the key that
    // authenticated the supplied Draft.
    let expanded = CapabilityWitnessTrustRoot::new(
        [key().verification_key(), other.verification_key()],
        [key().verification_key()],
        1,
    )
    .unwrap();
    assert!(
        observe_native_witness(&input, CLOCK_SOURCE, &corpus, &policy, &expanded, &other).is_err()
    );
}

#[test]
fn authority_expansion_and_unbounded_work_are_rejected_before_execution() {
    let input = draft(CLOCK_SOURCE, MIN_CLOCK_CAPS);
    let corpus = corpus(1);
    let mut expanded = config(MIN_CLOCK_CAPS);
    expanded
        .candidate_capabilities
        .as_mut()
        .unwrap()
        .insert(Capability::new("fs_write"));
    assert!(
        observe_native_witness(&input, CLOCK_SOURCE, &corpus, &expanded, &root(), &key())
            .unwrap_err()
            .to_string()
            .contains("subset")
    );
    let mut bounded = config(MIN_CLOCK_CAPS);
    bounded.max_executions = 5;
    assert!(
        observe_native_witness(&input, CLOCK_SOURCE, &corpus, &bounded, &root(), &key())
            .unwrap_err()
            .to_string()
            .contains("budget exceeded before execution")
    );
}

#[test]
fn baseline_budget_failure_is_signed_and_cannot_become_a_trial_success() {
    let input = draft(CLOCK_SOURCE, MIN_CLOCK_CAPS);
    let mut bounded = config(MIN_CLOCK_CAPS);
    bounded.instruction_budget = 1;
    let result =
        observe_native_witness(&input, CLOCK_SOURCE, &corpus(1), &bounded, &root(), &key())
            .unwrap();
    assert!(result.witness.is_none());
    assert_eq!(result.transcript.body.baseline_executions, 1);
    assert_eq!(result.transcript.body.candidate_executions, 0);
    assert_eq!(
        result.transcript.body.confidence,
        ConfidenceInterval::from_trials(0, 0)
    );
    assert!(matches!(
        result.transcript.body.records[0].baseline.completion,
        NativeObservedCompletion::Failed {
            class: NativeObservationFailureClass::ResourceLimit,
            ..
        }
    ));
    result
        .transcript
        .verify(&root(), SecurityEpoch::from_raw(7))
        .unwrap();
}

#[test]
fn replayed_write_is_a_real_native_crossing_without_live_filesystem_mutation() {
    let path = format!(
        "native-observation-no-live-write-{}.txt",
        std::process::id()
    );
    assert!(!std::path::Path::new(&path).exists());
    let source = format!("require('fs').writeFileSync('{path}', 'payload');");
    let names = &["vm_dispatch", "heap_allocate", "builtin", "fs_write"];
    let input = draft(&source, names);
    let mut cases = corpus(1);
    cases.cases[0].host_effects.push((
        HostIoRequest::FsWrite {
            path: path.clone(),
            data: b"payload".to_vec(),
        },
        Ok(HostIoResponse::FsWrite { bytes_written: 7 }),
    ));
    let result =
        observe_native_witness(&input, &source, &cases, &config(names), &root(), &key()).unwrap();
    assert!(
        result.witness.is_some(),
        "{:?}",
        result.transcript.body.failure
    );
    let record = &result.transcript.body.records[0];
    assert_eq!(record.baseline.host_effects, cases.cases[0].host_effects);
    assert_eq!(
        record.candidate.as_ref().unwrap().host_effects,
        cases.cases[0].host_effects
    );
    let removed_write = record
        .ablations
        .iter()
        .find(|a| a.removed_runtime_capability == RuntimeCapability::FsWrite)
        .unwrap();
    assert!(removed_write.behavior_changed);
    assert!(removed_write.observation.host_effects.is_empty());
    assert!(removed_write.observation.replay_error.is_some());
    assert!(
        !std::path::Path::new(&path).exists(),
        "shadow replay must not write a real file"
    );
}

#[test]
fn unused_host_tape_is_a_signed_baseline_failure_even_with_normal_completion() {
    let input = draft(CLOCK_SOURCE, MIN_CLOCK_CAPS);
    let mut cases = corpus(1);
    cases.cases[0].host_effects.push((
        HostIoRequest::FsRead {
            path: "unused".to_string(),
        },
        Ok(HostIoResponse::FsRead { bytes: vec![1] }),
    ));
    let result = observe_native_witness(
        &input,
        CLOCK_SOURCE,
        &cases,
        &config(MIN_CLOCK_CAPS),
        &root(),
        &key(),
    )
    .unwrap();
    assert!(result.witness.is_none());
    let baseline = &result.transcript.body.records[0].baseline;
    assert!(matches!(
        baseline.completion,
        NativeObservedCompletion::Completed { .. }
    ));
    assert!(baseline.host_effects.is_empty());
    assert!(baseline.replay_error.as_deref().unwrap().contains("unused"));
}

#[test]
fn signed_transcript_rejects_outcome_count_corpus_and_epoch_tampering() {
    let input = draft(CLOCK_SOURCE, MIN_CLOCK_CAPS);
    let result = observe_native_witness(
        &input,
        CLOCK_SOURCE,
        &corpus(1),
        &config(MIN_CLOCK_CAPS),
        &root(),
        &key(),
    )
    .unwrap();
    let witness = result.witness.as_ref().unwrap();
    result
        .transcript
        .verify_witness(witness, &root(), SecurityEpoch::from_raw(7))
        .unwrap();
    let mut changed = result.transcript.clone();
    changed.body.ablation_breakages += 1;
    assert!(changed.verify(&root(), SecurityEpoch::from_raw(7)).is_err());
    let mut changed = result.transcript.clone();
    changed.body.corpus.cases[0].clock_epoch_ms += 1;
    assert!(changed.verify(&root(), SecurityEpoch::from_raw(7)).is_err());
    let mut changed = result.transcript.clone();
    changed.body.records[0].baseline.console_output[0]
        .message
        .push('0');
    assert!(changed.verify(&root(), SecurityEpoch::from_raw(7)).is_err());
    assert!(
        result
            .transcript
            .verify(&root(), SecurityEpoch::from_raw(8))
            .is_err()
    );
    assert!(
        result
            .transcript
            .verify_witness(&input, &root(), SecurityEpoch::from_raw(7))
            .is_err()
    );
}

#[test]
fn runtime_aliases_do_not_duplicate_necessity_trials() {
    let names = &[
        "vm_dispatch",
        "heap_allocate",
        "builtin",
        "console",
        "builtin:DateNow",
    ];
    let input = draft(CLOCK_SOURCE, names);
    let result = observe_native_witness(
        &input,
        CLOCK_SOURCE,
        &corpus(1),
        &config(names),
        &root(),
        &key(),
    )
    .unwrap();
    assert!(result.witness.is_some());
    assert_eq!(result.transcript.body.ablation_executions, 4);
    let aliases = &result.transcript.body.records[0]
        .ablations
        .iter()
        .find(|a| a.removed_runtime_capability == RuntimeCapability::Builtin)
        .unwrap()
        .removed_witness_capabilities;
    assert_eq!(aliases.len(), 2);
}

#[test]
fn canonical_authority_selection_retains_parent_operation_tags_for_runtime_admission() {
    let names = &[
        "vm_dispatch",
        "heap_allocate",
        "builtin",
        "console",
        "builtin:DateNow",
        "console:log",
        "timer",
    ];
    let input = draft(CLOCK_SOURCE, names);
    let result = observe_native_witness(
        &input,
        CLOCK_SOURCE,
        &corpus(1),
        &config(MIN_CLOCK_CAPS),
        &root(),
        &key(),
    )
    .unwrap();
    let witness = result.witness.as_ref().unwrap();
    for alias in ["builtin:DateNow", "console:log"] {
        assert!(
            witness
                .required_capabilities
                .contains(&Capability::new(alias))
        );
        assert!(
            !witness
                .denied_capabilities
                .contains(&Capability::new(alias))
        );
    }
    assert!(
        witness
            .denied_capabilities
            .contains(&Capability::new("timer"))
    );
    assert_eq!(result.transcript.body.ablation_executions, 4);
    result
        .transcript
        .verify_witness(witness, &root(), SecurityEpoch::from_raw(7))
        .unwrap();
}

#[test]
fn caught_replay_divergence_cannot_accumulate_unmetered_request_copies() {
    let source = "const fs = require('fs'); const payload = 'x'.repeat(1024); for (let i = 0; i < 64; i++) { try { fs.writeFileSync('not-in-tape', payload); } catch (error) {} } 0;";
    let names = &["vm_dispatch", "heap_allocate", "builtin", "fs_write"];
    let input = draft(source, names);
    let result =
        observe_native_witness(&input, source, &corpus(1), &config(names), &root(), &key())
            .unwrap();
    assert!(result.witness.is_none());
    let baseline = &result.transcript.body.records[0].baseline;
    assert_eq!(
        baseline.host_effects.len(),
        1,
        "retain only the first unexpected request"
    );
    assert!(
        baseline
            .recording_error
            .as_deref()
            .unwrap()
            .contains("repeated host requests")
    );
    assert!(matches!(
        baseline.completion,
        NativeObservedCompletion::Failed {
            class: NativeObservationFailureClass::ResourceLimit,
            ..
        }
    ));
    assert_eq!(result.transcript.body.ablation_breakages, 0);
    result
        .transcript
        .verify(&root(), SecurityEpoch::from_raw(7))
        .unwrap();
}

#[test]
fn unsupported_reference_completion_is_signed_failure_not_handle_equality() {
    let source = "({ answer: 42 });";
    let names = &["vm_dispatch", "heap_allocate", "builtin"];
    let input = draft(source, names);
    let result =
        observe_native_witness(&input, source, &corpus(1), &config(names), &root(), &key())
            .unwrap();
    assert!(result.witness.is_none());
    assert!(matches!(
        result.transcript.body.records[0].baseline.completion,
        NativeObservedCompletion::Failed {
            class: NativeObservationFailureClass::UnsupportedCompletion,
            ..
        }
    ));
    assert_eq!(result.transcript.body.candidate_executions, 0);
    result
        .transcript
        .verify(&root(), SecurityEpoch::from_raw(7))
        .unwrap();
}

#[test]
fn identical_real_execution_inputs_produce_identical_signed_observations() {
    let input = draft(CLOCK_SOURCE, MIN_CLOCK_CAPS);
    let cases = corpus(1);
    let policy = config(MIN_CLOCK_CAPS);
    let first =
        observe_native_witness(&input, CLOCK_SOURCE, &cases, &policy, &root(), &key()).unwrap();
    let second =
        observe_native_witness(&input, CLOCK_SOURCE, &cases, &policy, &root(), &key()).unwrap();
    assert_eq!(first, second);
}

#[test]
fn authenticated_contradictory_parent_aliases_are_rejected_by_the_library() {
    let source = CLOCK_SOURCE;
    let mut input = draft(source, MIN_CLOCK_CAPS);
    input
        .denied_capabilities
        .insert(Capability::new("builtin:DateNow"));
    let unsigned = input.synthesis_unsigned_bytes();
    input.content_hash = ContentHash::compute(&unsigned);
    input.synthesizer_signature = sign_preimage(&key(), &unsigned)
        .unwrap()
        .to_bytes()
        .to_vec();
    assert!(
        observe_native_witness(
            &input,
            source,
            &corpus(1),
            &config(MIN_CLOCK_CAPS),
            &root(),
            &key()
        )
        .unwrap_err()
        .to_string()
        .contains("same runtime authority")
    );
    input.required_capabilities.clear();
    input.proof_obligations.clear();
    let unsigned = input.synthesis_unsigned_bytes();
    input.content_hash = ContentHash::compute(&unsigned);
    input.synthesizer_signature = sign_preimage(&key(), &unsigned)
        .unwrap()
        .to_bytes()
        .to_vec();
    assert!(
        observe_native_witness(
            &input,
            source,
            &corpus(1),
            &config(MIN_CLOCK_CAPS),
            &root(),
            &key()
        )
        .unwrap_err()
        .to_string()
        .contains("empty or contradictory")
    );
}

fn resign_transcript(transcript: &mut SignedNativeObservationTranscript) {
    let mut bytes = b"frankenengine.native-witness-observation.v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(&transcript.body).unwrap());
    transcript.content_hash = ContentHash::compute(&bytes);
    transcript.signature = sign_preimage(&key(), &bytes).unwrap().to_bytes().to_vec();
}

#[test]
fn even_valid_signatures_cannot_hide_inconsistent_parity_or_necessity_summaries() {
    let input = draft(CLOCK_SOURCE, MIN_CLOCK_CAPS);
    let result = observe_native_witness(
        &input,
        CLOCK_SOURCE,
        &corpus(1),
        &config(MIN_CLOCK_CAPS),
        &root(),
        &key(),
    )
    .unwrap();
    let mut changed = result.transcript.clone();
    changed.body.candidate_matches_baseline = false;
    resign_transcript(&mut changed);
    assert!(
        changed
            .verify(&root(), SecurityEpoch::from_raw(7))
            .unwrap_err()
            .to_string()
            .contains("parity summary")
    );
    let mut changed = result.transcript.clone();
    changed.body.records[0].ablations[0].behavior_changed = false;
    changed.body.ablation_breakages -= 1;
    changed.body.confidence = ConfidenceInterval::from_trials(
        changed.body.ablation_executions as u32,
        changed.body.ablation_breakages as u32,
    );
    resign_transcript(&mut changed);
    assert!(
        changed
            .verify(&root(), SecurityEpoch::from_raw(7))
            .unwrap_err()
            .to_string()
            .contains("necessity result")
    );
    let mut changed = result.transcript.clone();
    changed.body.records[0].case_id = "other-case".to_string();
    resign_transcript(&mut changed);
    assert!(
        changed
            .verify(&root(), SecurityEpoch::from_raw(7))
            .unwrap_err()
            .to_string()
            .contains("ordered corpus context")
    );
}
