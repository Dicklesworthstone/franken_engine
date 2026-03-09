//! Integration tests for the `flow_envelope` module.
//!
//! Exercises the public API from outside the crate: FlowEnvelope construction,
//! signing/verification, content addressing, synthesis passes, synthesizer
//! lifecycle, error conditions, serde round-trips, Display impls, determinism,
//! and edge cases.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::flow_envelope::{
    EnvelopeError, EnvelopeEvent, EnvelopeInput, FallbackQuality, FlowConfidenceInterval,
    FlowDiscoveryMethod, FlowEnvelope, FlowEnvelopeRef, FlowEnvelopeSynthesizer, FlowProofMethod,
    FlowProofObligation, FlowRequirement, SynthesisPass, SynthesisPassResult, error_code,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::{FlowRule, Label};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::signature_preimage::SigningKey;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rule(source: Label, sink: Label) -> FlowRule {
    FlowRule {
        source_label: source,
        sink_clearance: sink,
    }
}

fn test_upper_bound() -> BTreeSet<FlowRule> {
    let mut flows = BTreeSet::new();
    flows.insert(rule(Label::Public, Label::Internal));
    flows.insert(rule(Label::Internal, Label::Confidential));
    flows.insert(rule(Label::Confidential, Label::Public));
    flows.insert(rule(Label::Secret, Label::Internal));
    flows
}

fn test_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x42;
    bytes[31] = 0xFF;
    SigningKey::from_bytes(bytes)
}

fn valid_input() -> EnvelopeInput {
    let upper = test_upper_bound();
    let required: BTreeSet<FlowRule> = upper
        .iter()
        .filter(|r| r.source_label.can_flow_to(&r.sink_clearance))
        .cloned()
        .collect();
    let denied: BTreeSet<FlowRule> = upper
        .iter()
        .filter(|r| !r.source_label.can_flow_to(&r.sink_clearance))
        .cloned()
        .collect();

    let obligations: Vec<FlowProofObligation> = required
        .iter()
        .map(|r| FlowProofObligation {
            rule: r.clone(),
            required_method: FlowProofMethod::StaticAnalysis,
            justification: "test".to_string(),
            proof_artifact_hash: None,
        })
        .collect();

    EnvelopeInput {
        extension_id: "ext-integ-001".to_string(),
        static_upper_bound: upper,
        ablation_required: required,
        ablation_removable: denied,
        proof_obligations: obligations,
        confidence: FlowConfidenceInterval {
            lower_millionths: 950_000,
            upper_millionths: 1_000_000,
            n_trials: 4,
            n_essential: 2,
        },
        pass_results: Vec::new(),
        validity_epoch: SecurityEpoch::from_raw(1),
        policy_id: "policy-integ-001".to_string(),
        is_fallback: false,
        fallback_quality: None,
        timestamp_ns: 1_700_000_000_000_000_000,
    }
}

// ---------------------------------------------------------------------------
// 1. FlowDiscoveryMethod Display impls
// ---------------------------------------------------------------------------

#[test]
fn flow_discovery_method_display_static_analysis() {
    assert_eq!(
        FlowDiscoveryMethod::StaticAnalysis.to_string(),
        "static_analysis"
    );
}

#[test]
fn flow_discovery_method_display_dynamic_ablation() {
    assert_eq!(
        FlowDiscoveryMethod::DynamicAblation.to_string(),
        "dynamic_ablation"
    );
}

#[test]
fn flow_discovery_method_display_runtime_observation() {
    assert_eq!(
        FlowDiscoveryMethod::RuntimeObservation.to_string(),
        "runtime_observation"
    );
}

#[test]
fn flow_discovery_method_display_manifest_declaration() {
    assert_eq!(
        FlowDiscoveryMethod::ManifestDeclaration.to_string(),
        "manifest_declaration"
    );
}

// ---------------------------------------------------------------------------
// 2. FlowProofMethod Display impls
// ---------------------------------------------------------------------------

#[test]
fn flow_proof_method_display_all_variants() {
    assert_eq!(
        FlowProofMethod::StaticAnalysis.to_string(),
        "static_analysis"
    );
    assert_eq!(FlowProofMethod::RuntimeCheck.to_string(), "runtime_check");
    assert_eq!(
        FlowProofMethod::Declassification.to_string(),
        "declassification"
    );
    assert_eq!(
        FlowProofMethod::OperatorAttestation.to_string(),
        "operator_attestation"
    );
}

// ---------------------------------------------------------------------------
// 3. SynthesisPass Display impls
// ---------------------------------------------------------------------------

#[test]
fn synthesis_pass_display_all_variants() {
    assert_eq!(
        SynthesisPass::StaticFlowAnalysis.to_string(),
        "static_flow_analysis"
    );
    assert_eq!(
        SynthesisPass::DynamicFlowAblation.to_string(),
        "dynamic_flow_ablation"
    );
}

// ---------------------------------------------------------------------------
// 4. FallbackQuality Display impls
// ---------------------------------------------------------------------------

#[test]
fn fallback_quality_display_all_variants() {
    assert_eq!(FallbackQuality::StaticBound.to_string(), "static_bound");
    assert_eq!(
        FallbackQuality::PartialAblation.to_string(),
        "partial_ablation"
    );
}

// ---------------------------------------------------------------------------
// 5. EnvelopeError Display and error_code
// ---------------------------------------------------------------------------

#[test]
fn error_display_empty_extension_id() {
    let err = EnvelopeError::EmptyExtensionId;
    assert!(err.to_string().contains("empty"));
}

#[test]
fn error_display_empty_upper_bound() {
    let err = EnvelopeError::EmptyUpperBound;
    assert!(err.to_string().contains("no flows"));
}

#[test]
fn error_display_overlapping_flows() {
    let err = EnvelopeError::OverlappingFlows { overlap_count: 3 };
    assert!(err.to_string().contains("3"));
}

#[test]
fn error_display_missing_proof_obligation() {
    let err = EnvelopeError::MissingProofObligation {
        rule: rule(Label::Secret, Label::Public),
    };
    assert!(err.to_string().contains("no proof obligation"));
}

#[test]
fn error_display_id_derivation() {
    let err = EnvelopeError::IdDerivation("bad seed".to_string());
    assert!(err.to_string().contains("bad seed"));
}

#[test]
fn error_display_signature_error() {
    let err = EnvelopeError::SignatureError("bad sig".to_string());
    assert!(err.to_string().contains("bad sig"));
}

#[test]
fn error_display_budget_exhausted() {
    let err = EnvelopeError::BudgetExhausted {
        phase: "dynamic".to_string(),
    };
    assert!(err.to_string().contains("dynamic"));
}

#[test]
fn error_codes_are_stable() {
    assert_eq!(
        error_code(&EnvelopeError::EmptyExtensionId),
        "ENVELOPE_EMPTY_EXTENSION_ID"
    );
    assert_eq!(
        error_code(&EnvelopeError::EmptyUpperBound),
        "ENVELOPE_EMPTY_UPPER_BOUND"
    );
    assert_eq!(
        error_code(&EnvelopeError::OverlappingFlows { overlap_count: 1 }),
        "ENVELOPE_OVERLAPPING_FLOWS"
    );
    assert_eq!(
        error_code(&EnvelopeError::MissingProofObligation {
            rule: rule(Label::Public, Label::Public),
        }),
        "ENVELOPE_MISSING_PROOF"
    );
    assert_eq!(
        error_code(&EnvelopeError::IdDerivation(String::new())),
        "ENVELOPE_ID_DERIVATION"
    );
    assert_eq!(
        error_code(&EnvelopeError::SignatureError(String::new())),
        "ENVELOPE_SIGNATURE_ERROR"
    );
    assert_eq!(
        error_code(&EnvelopeError::BudgetExhausted {
            phase: String::new()
        }),
        "ENVELOPE_BUDGET_EXHAUSTED"
    );
}

#[test]
fn envelope_error_is_std_error() {
    let err = EnvelopeError::EmptyExtensionId;
    let _as_std: &dyn std::error::Error = &err;
}

// ---------------------------------------------------------------------------
// 6. FlowEnvelope construction and validation
// ---------------------------------------------------------------------------

#[test]
fn build_valid_envelope_succeeds() {
    let envelope = FlowEnvelope::build(valid_input()).expect("build");
    assert_eq!(envelope.extension_id, "ext-integ-001");
    assert_eq!(envelope.required_flows.len(), 2);
    assert_eq!(envelope.denied_flows.len(), 2);
    assert!(!envelope.is_fallback);
    assert!(envelope.fallback_quality.is_none());
}

#[test]
fn build_rejects_empty_extension_id() {
    let mut input = valid_input();
    input.extension_id = String::new();
    let err = FlowEnvelope::build(input).unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyExtensionId);
}

#[test]
fn build_rejects_empty_upper_bound_and_no_ablation() {
    let mut input = valid_input();
    input.static_upper_bound = BTreeSet::new();
    input.ablation_required = BTreeSet::new();
    let err = FlowEnvelope::build(input).unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyUpperBound);
}

#[test]
fn build_rejects_overlapping_required_and_removable() {
    let mut input = valid_input();
    let overlap_rule = rule(Label::Public, Label::Internal);
    input.ablation_required.insert(overlap_rule.clone());
    input.ablation_removable.insert(overlap_rule);
    let err = FlowEnvelope::build(input).unwrap_err();
    assert!(matches!(err, EnvelopeError::OverlappingFlows { .. }));
}

#[test]
fn build_with_only_static_upper_bound_no_ablation() {
    let mut input = valid_input();
    input.ablation_required = BTreeSet::new();
    input.ablation_removable = BTreeSet::new();
    let envelope = FlowEnvelope::build(input).unwrap();
    // Falls back to entire static upper bound as required
    assert_eq!(envelope.required_flows.len(), 4);
    assert_eq!(envelope.denied_flows.len(), 0);
}

#[test]
fn build_fallback_envelope() {
    let mut input = valid_input();
    input.is_fallback = true;
    input.fallback_quality = Some(FallbackQuality::PartialAblation);
    let envelope = FlowEnvelope::build(input).unwrap();
    assert!(envelope.is_fallback);
    assert_eq!(
        envelope.fallback_quality,
        Some(FallbackQuality::PartialAblation)
    );
}

// ---------------------------------------------------------------------------
// 7. Content addressing
// ---------------------------------------------------------------------------

#[test]
fn content_address_is_deterministic() {
    let e1 = FlowEnvelope::build(valid_input()).unwrap();
    let e2 = FlowEnvelope::build(valid_input()).unwrap();
    assert_eq!(e1.envelope_id, e2.envelope_id);
}

#[test]
fn different_inputs_produce_different_ids() {
    let e1 = FlowEnvelope::build(valid_input()).unwrap();
    let mut input2 = valid_input();
    input2.extension_id = "ext-different".to_string();
    let e2 = FlowEnvelope::build(input2).unwrap();
    assert_ne!(e1.envelope_id, e2.envelope_id);
}

#[test]
fn verify_content_address_passes_for_valid_envelope() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    assert!(envelope.verify_content_address());
}

#[test]
fn verify_content_address_fails_after_tampering() {
    let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
    assert!(envelope.verify_content_address());
    envelope.timestamp_ns = 999;
    assert!(!envelope.verify_content_address());
}

#[test]
fn content_address_stable_across_signing() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let mut signed = envelope.clone();
    signed.sign(&test_signing_key()).unwrap();
    // Signing changes the signature field but not the envelope_id.
    assert_eq!(signed.envelope_id, envelope.envelope_id);
    assert!(signed.verify_content_address());
}

// ---------------------------------------------------------------------------
// 8. Signing and verification
// ---------------------------------------------------------------------------

#[test]
fn sign_and_verify_roundtrip() {
    let key = test_signing_key();
    let vk = key.verification_key();
    let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
    envelope.sign(&key).expect("sign");
    envelope.verify(&vk).expect("verify");
}

#[test]
fn verify_fails_with_wrong_key() {
    let key = test_signing_key();
    let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
    envelope.sign(&key).expect("sign");
    let wrong = SigningKey::from_bytes([0xBB; 32]);
    assert!(envelope.verify(&wrong.verification_key()).is_err());
}

// ---------------------------------------------------------------------------
// 9. Epoch validity
// ---------------------------------------------------------------------------

#[test]
fn is_valid_at_correct_epoch() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    assert!(envelope.is_valid_at_epoch(SecurityEpoch::from_raw(1)));
}

#[test]
fn is_invalid_at_different_epoch() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    assert!(!envelope.is_valid_at_epoch(SecurityEpoch::from_raw(2)));
    assert!(!envelope.is_valid_at_epoch(SecurityEpoch::GENESIS));
}

// ---------------------------------------------------------------------------
// 10. Flow queries
// ---------------------------------------------------------------------------

#[test]
fn allows_flow_for_required() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let safe = rule(Label::Public, Label::Internal);
    assert!(envelope.allows_flow(&safe));
}

#[test]
fn denies_flow_for_denied() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let denied_rule = rule(Label::Confidential, Label::Public);
    assert!(envelope.denies_flow(&denied_rule));
}

#[test]
fn is_out_of_envelope_for_unknown_flow() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let unknown = rule(Label::Secret, Label::Secret);
    assert!(envelope.is_out_of_envelope(&unknown));
}

#[test]
fn source_labels_extracted() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let labels = envelope.source_labels();
    assert!(labels.contains(&Label::Public));
    assert!(labels.contains(&Label::Internal));
}

#[test]
fn sink_clearances_extracted() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let clearances = envelope.sink_clearances();
    assert!(clearances.contains(&Label::Internal));
    assert!(clearances.contains(&Label::Confidential));
}

#[test]
fn unsatisfied_obligations_count() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    // All proof obligations have None artifact hashes
    assert_eq!(envelope.unsatisfied_obligations(), 2);
}

#[test]
fn satisfied_obligations_count_zero() {
    let mut input = valid_input();
    for obl in &mut input.proof_obligations {
        obl.proof_artifact_hash = Some(ContentHash::compute(b"proof-artifact"));
    }
    let envelope = FlowEnvelope::build(input).unwrap();
    assert_eq!(envelope.unsatisfied_obligations(), 0);
}

// ---------------------------------------------------------------------------
// 11. Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn envelope_serde_roundtrip() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let json = serde_json::to_string(&envelope).unwrap();
    let deser: FlowEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope, deser);
}

#[test]
fn flow_requirement_serde_roundtrip() {
    let req = FlowRequirement {
        rule: rule(Label::Confidential, Label::Public),
        discovery_method: FlowDiscoveryMethod::DynamicAblation,
        source_location: Some("src/handler.rs:42".to_string()),
        sink_location: Some("src/output.rs:10".to_string()),
    };
    let json = serde_json::to_string(&req).unwrap();
    let deser: FlowRequirement = serde_json::from_str(&json).unwrap();
    assert_eq!(req, deser);
}

#[test]
fn flow_requirement_with_none_locations_serde_roundtrip() {
    let req = FlowRequirement {
        rule: rule(Label::Public, Label::Secret),
        discovery_method: FlowDiscoveryMethod::StaticAnalysis,
        source_location: None,
        sink_location: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    let deser: FlowRequirement = serde_json::from_str(&json).unwrap();
    assert_eq!(req, deser);
}

#[test]
fn flow_discovery_method_serde_roundtrip_all_variants() {
    for m in [
        FlowDiscoveryMethod::StaticAnalysis,
        FlowDiscoveryMethod::DynamicAblation,
        FlowDiscoveryMethod::RuntimeObservation,
        FlowDiscoveryMethod::ManifestDeclaration,
    ] {
        let json = serde_json::to_string(&m).unwrap();
        let deser: FlowDiscoveryMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(m, deser);
    }
}

#[test]
fn flow_proof_method_serde_roundtrip_all_variants() {
    for m in [
        FlowProofMethod::StaticAnalysis,
        FlowProofMethod::RuntimeCheck,
        FlowProofMethod::Declassification,
        FlowProofMethod::OperatorAttestation,
    ] {
        let json = serde_json::to_string(&m).unwrap();
        let deser: FlowProofMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(m, deser);
    }
}

#[test]
fn synthesis_pass_serde_roundtrip_all_variants() {
    for p in [
        SynthesisPass::StaticFlowAnalysis,
        SynthesisPass::DynamicFlowAblation,
    ] {
        let json = serde_json::to_string(&p).unwrap();
        let deser: SynthesisPass = serde_json::from_str(&json).unwrap();
        assert_eq!(p, deser);
    }
}

#[test]
fn fallback_quality_serde_roundtrip_all_variants() {
    for q in [
        FallbackQuality::StaticBound,
        FallbackQuality::PartialAblation,
    ] {
        let json = serde_json::to_string(&q).unwrap();
        let deser: FallbackQuality = serde_json::from_str(&json).unwrap();
        assert_eq!(q, deser);
    }
}

#[test]
fn envelope_error_serde_roundtrip_all_variants() {
    let errors = vec![
        EnvelopeError::EmptyExtensionId,
        EnvelopeError::EmptyUpperBound,
        EnvelopeError::OverlappingFlows { overlap_count: 3 },
        EnvelopeError::MissingProofObligation {
            rule: rule(Label::Secret, Label::Public),
        },
        EnvelopeError::IdDerivation("test".to_string()),
        EnvelopeError::SignatureError("test".to_string()),
        EnvelopeError::BudgetExhausted {
            phase: "dynamic".to_string(),
        },
    ];
    for err in errors {
        let json = serde_json::to_string(&err).unwrap();
        let deser: EnvelopeError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, deser);
    }
}

#[test]
fn envelope_event_serde_roundtrip() {
    let ev = EnvelopeEvent {
        trace_id: "t1".to_string(),
        component: "flow_envelope".to_string(),
        event: "synthesis_complete".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        extension_id: Some("ext-001".to_string()),
        flow_count: Some(4),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let deser: EnvelopeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, deser);
}

#[test]
fn envelope_event_with_error_code_serde_roundtrip() {
    let ev = EnvelopeEvent {
        trace_id: "t2".to_string(),
        component: "flow_envelope".to_string(),
        event: "synthesis_error".to_string(),
        outcome: "error".to_string(),
        error_code: Some("ENVELOPE_BUDGET_EXHAUSTED".to_string()),
        extension_id: Some("ext-002".to_string()),
        flow_count: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let deser: EnvelopeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, deser);
}

#[test]
fn flow_envelope_ref_serde_roundtrip() {
    let r = FlowEnvelopeRef {
        envelope_id: EngineObjectId([0xAA; 32]),
        envelope_hash: ContentHash::compute(b"test"),
        envelope_epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&r).unwrap();
    let deser: FlowEnvelopeRef = serde_json::from_str(&json).unwrap();
    assert_eq!(r, deser);
}

#[test]
fn confidence_interval_serde_roundtrip() {
    let ci = FlowConfidenceInterval {
        lower_millionths: 950_000,
        upper_millionths: 1_000_000,
        n_trials: 100,
        n_essential: 80,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let deser: FlowConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, deser);
}

#[test]
fn flow_proof_obligation_serde_roundtrip() {
    let obl = FlowProofObligation {
        rule: rule(Label::Secret, Label::Public),
        required_method: FlowProofMethod::Declassification,
        justification: "needs declass".to_string(),
        proof_artifact_hash: Some(ContentHash::compute(b"proof")),
    };
    let json = serde_json::to_string(&obl).unwrap();
    let deser: FlowProofObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(obl, deser);
}

#[test]
fn flow_proof_obligation_without_hash_serde_roundtrip() {
    let obl = FlowProofObligation {
        rule: rule(Label::Internal, Label::Confidential),
        required_method: FlowProofMethod::StaticAnalysis,
        justification: "lattice-legal".to_string(),
        proof_artifact_hash: None,
    };
    let json = serde_json::to_string(&obl).unwrap();
    let deser: FlowProofObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(obl, deser);
}

#[test]
fn synthesis_pass_result_serde_roundtrip() {
    let result = SynthesisPassResult {
        pass: SynthesisPass::StaticFlowAnalysis,
        required_flows: {
            let mut s = BTreeSet::new();
            s.insert(rule(Label::Public, Label::Internal));
            s
        },
        removable_flows: BTreeSet::new(),
        time_consumed_ns: 42_000,
        completed: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let deser: SynthesisPassResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, deser);
}

// ---------------------------------------------------------------------------
// 12. Synthesizer lifecycle
// ---------------------------------------------------------------------------

#[test]
fn synthesizer_static_pass_separates_safe_from_unsafe_flows() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-s1", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let result = synth.static_pass(&upper, "trace-integ-1");

    assert!(result.completed);
    assert_eq!(result.pass, SynthesisPass::StaticFlowAnalysis);
    // 2 safe flows: Public->Internal, Internal->Confidential
    assert_eq!(result.required_flows.len(), 2);
    assert!(
        result
            .required_flows
            .contains(&rule(Label::Public, Label::Internal))
    );
    assert!(
        result
            .required_flows
            .contains(&rule(Label::Internal, Label::Confidential))
    );
    // 2 declassification flows: Confidential->Public, Secret->Internal
    assert_eq!(result.removable_flows.len(), 2);
    assert!(
        result
            .removable_flows
            .contains(&rule(Label::Confidential, Label::Public))
    );
    assert!(
        result
            .removable_flows
            .contains(&rule(Label::Secret, Label::Internal))
    );
}

#[test]
fn synthesizer_dynamic_pass_promotes_essential_flows() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-d1", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let static_result = synth.static_pass(&upper, "trace-integ-2");

    // Oracle says Confidential->Public is essential, Secret->Internal is not
    let oracle =
        |r: &FlowRule| r.source_label == Label::Confidential && r.sink_clearance == Label::Public;
    let dynamic_result = synth.dynamic_pass(&static_result, &oracle, "trace-integ-2");

    // 3 required: 2 safe + 1 promoted
    assert_eq!(dynamic_result.required_flows.len(), 3);
    assert!(
        dynamic_result
            .required_flows
            .contains(&rule(Label::Confidential, Label::Public))
    );
    // 1 still removable: Secret->Internal
    assert_eq!(dynamic_result.removable_flows.len(), 1);
    assert!(
        dynamic_result
            .removable_flows
            .contains(&rule(Label::Secret, Label::Internal))
    );
}

#[test]
fn synthesizer_dynamic_pass_all_essential() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-d2", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let static_result = synth.static_pass(&upper, "trace-integ-3");

    let oracle = |_: &FlowRule| true; // Everything is essential
    let dynamic_result = synth.dynamic_pass(&static_result, &oracle, "trace-integ-3");

    assert_eq!(dynamic_result.required_flows.len(), 4);
    assert_eq!(dynamic_result.removable_flows.len(), 0);
}

#[test]
fn synthesizer_dynamic_pass_none_essential() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-d3", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let static_result = synth.static_pass(&upper, "trace-integ-4");

    let oracle = |_: &FlowRule| false; // Nothing is essential
    let dynamic_result = synth.dynamic_pass(&static_result, &oracle, "trace-integ-4");

    // Only the 2 safe flows remain required
    assert_eq!(dynamic_result.required_flows.len(), 2);
    assert_eq!(dynamic_result.removable_flows.len(), 2);
}

#[test]
fn synthesizer_full_synthesis_no_essential() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-fs1", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    let envelope = synth
        .synthesize(
            &upper,
            &oracle,
            "policy-integ-001",
            1_700_000_000_000_000_000,
            "trace-integ-fs1",
        )
        .unwrap();

    assert_eq!(envelope.extension_id, "ext-integ-fs1");
    assert!(!envelope.is_fallback);
    assert!(envelope.verify_content_address());
    assert_eq!(envelope.required_flows.len(), 2);
    assert_eq!(envelope.denied_flows.len(), 2);
}

#[test]
fn synthesizer_full_synthesis_all_essential() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-fs2", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| true;
    let envelope = synth
        .synthesize(
            &upper,
            &oracle,
            "policy-integ-002",
            1_700_000_000_000_000_000,
            "trace-integ-fs2",
        )
        .unwrap();

    assert_eq!(envelope.required_flows.len(), 4);
    assert_eq!(envelope.denied_flows.len(), 0);
    assert!(envelope.verify_content_address());
}

#[test]
fn synthesizer_fallback_static_bound() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-fb1", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let envelope = synth
        .synthesize_fallback(
            &upper,
            "policy-integ-003",
            1_700_000_000_000_000_000,
            FallbackQuality::StaticBound,
            "trace-integ-fb1",
        )
        .unwrap();

    assert!(envelope.is_fallback);
    assert_eq!(
        envelope.fallback_quality,
        Some(FallbackQuality::StaticBound)
    );
    // Fallback uses full upper bound
    assert_eq!(envelope.required_flows.len(), 4);
    assert_eq!(envelope.denied_flows.len(), 0);
    assert!(envelope.verify_content_address());
}

#[test]
fn synthesizer_fallback_partial_ablation() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-fb2", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let envelope = synth
        .synthesize_fallback(
            &upper,
            "policy-integ-004",
            1_700_000_000_000_000_000,
            FallbackQuality::PartialAblation,
            "trace-integ-fb2",
        )
        .unwrap();

    assert!(envelope.is_fallback);
    assert_eq!(
        envelope.fallback_quality,
        Some(FallbackQuality::PartialAblation)
    );
}

// ---------------------------------------------------------------------------
// 13. Synthesizer error conditions
// ---------------------------------------------------------------------------

#[test]
fn synthesizer_rejects_empty_extension_id() {
    let mut synth = FlowEnvelopeSynthesizer::new("", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    let err = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyExtensionId);
}

#[test]
fn synthesizer_rejects_empty_upper_bound() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-err", 30_000_000_000, SecurityEpoch::from_raw(1));
    let empty = BTreeSet::new();
    let oracle = |_: &FlowRule| false;
    let err = synth.synthesize(&empty, &oracle, "p", 0, "t").unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyUpperBound);
}

#[test]
fn synthesizer_fallback_rejects_empty_extension_id() {
    let mut synth = FlowEnvelopeSynthesizer::new("", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let err = synth
        .synthesize_fallback(&upper, "p", 0, FallbackQuality::StaticBound, "t")
        .unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyExtensionId);
}

#[test]
fn synthesizer_fallback_rejects_empty_upper_bound() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-err2", 30_000_000_000, SecurityEpoch::from_raw(1));
    let empty = BTreeSet::new();
    let err = synth
        .synthesize_fallback(&empty, "p", 0, FallbackQuality::StaticBound, "t")
        .unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyUpperBound);
}

// ---------------------------------------------------------------------------
// 14. Synthesizer events
// ---------------------------------------------------------------------------

#[test]
fn synthesizer_events_emitted_for_full_synthesis() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-ev1", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    synth
        .synthesize(&upper, &oracle, "p", 0, "trace-ev-integ")
        .unwrap();

    assert!(synth.events.len() >= 5);
    assert_eq!(synth.events[0].event, "synthesis_start");
    assert_eq!(synth.events.last().unwrap().event, "synthesis_complete");
}

#[test]
fn synthesizer_events_trace_id_preserved() {
    let oracle = |_: &FlowRule| false;
    let upper = test_upper_bound();
    let mut synth = FlowEnvelopeSynthesizer::new(
        "ext-integ-trace",
        30_000_000_000,
        SecurityEpoch::from_raw(1),
    );
    synth
        .synthesize(&upper, &oracle, "policy-1", 100, "my-integ-trace-42")
        .unwrap();
    for event in &synth.events {
        assert_eq!(event.trace_id, "my-integ-trace-42");
    }
}

#[test]
fn synthesizer_events_component_is_flow_envelope() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-comp", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    for event in &synth.events {
        assert_eq!(event.component, "flow_envelope");
    }
}

#[test]
fn synthesizer_events_for_fallback() {
    let mut synth = FlowEnvelopeSynthesizer::new(
        "ext-integ-fb-ev",
        30_000_000_000,
        SecurityEpoch::from_raw(1),
    );
    let upper = test_upper_bound();
    synth
        .synthesize_fallback(&upper, "p", 0, FallbackQuality::StaticBound, "trace-fb-ev")
        .unwrap();
    assert!(!synth.events.is_empty());
    assert_eq!(synth.events[0].event, "fallback_synthesis_start");
}

// ---------------------------------------------------------------------------
// 15. Deterministic replay
// ---------------------------------------------------------------------------

#[test]
fn determinism_build_100_times() {
    let first = FlowEnvelope::build(valid_input()).unwrap();
    for _ in 0..100 {
        let e = FlowEnvelope::build(valid_input()).unwrap();
        assert_eq!(e.envelope_id, first.envelope_id);
        assert_eq!(e.required_flows, first.required_flows);
        assert_eq!(e.denied_flows, first.denied_flows);
    }
}

#[test]
fn synthesis_is_deterministic_across_instances() {
    let oracle = |_: &FlowRule| false;
    let upper = test_upper_bound();

    let mut s1 =
        FlowEnvelopeSynthesizer::new("ext-det-integ", 30_000_000_000, SecurityEpoch::from_raw(1));
    let e1 = s1.synthesize(&upper, &oracle, "p1", 100, "t1").unwrap();

    let mut s2 =
        FlowEnvelopeSynthesizer::new("ext-det-integ", 30_000_000_000, SecurityEpoch::from_raw(1));
    let e2 = s2.synthesize(&upper, &oracle, "p1", 100, "t2").unwrap();

    assert_eq!(e1.envelope_id, e2.envelope_id);
    assert_eq!(e1.required_flows, e2.required_flows);
    assert_eq!(e1.denied_flows, e2.denied_flows);
}

#[test]
fn synthesizer_determinism_100_times() {
    let oracle = |_: &FlowRule| false;
    let upper = test_upper_bound();
    let mut first_synth = FlowEnvelopeSynthesizer::new(
        "ext-det-100-integ",
        30_000_000_000,
        SecurityEpoch::from_raw(1),
    );
    let first = first_synth
        .synthesize(&upper, &oracle, "p1", 100, "t1")
        .unwrap();

    for _ in 0..100 {
        let mut synth = FlowEnvelopeSynthesizer::new(
            "ext-det-100-integ",
            30_000_000_000,
            SecurityEpoch::from_raw(1),
        );
        let e = synth.synthesize(&upper, &oracle, "p1", 100, "t2").unwrap();
        assert_eq!(e.envelope_id, first.envelope_id);
        assert_eq!(e.required_flows, first.required_flows);
    }
}

// ---------------------------------------------------------------------------
// 16. Exfiltration and security-oriented scenarios
// ---------------------------------------------------------------------------

#[test]
fn envelope_blocks_exfiltration_flow() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let exfil = rule(Label::Secret, Label::Internal);
    assert!(envelope.denies_flow(&exfil));
    assert!(!envelope.allows_flow(&exfil));
}

#[test]
fn envelope_allows_safe_flow() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let safe_flow = rule(Label::Public, Label::Internal);
    assert!(envelope.allows_flow(&safe_flow));
    assert!(!envelope.denies_flow(&safe_flow));
}

#[test]
fn dynamic_pass_promotes_essential_flow_to_required() {
    let oracle = |r: &FlowRule| r.source_label == Label::Secret;
    let upper = test_upper_bound();
    let mut synth = FlowEnvelopeSynthesizer::new(
        "ext-promo-integ",
        30_000_000_000,
        SecurityEpoch::from_raw(1),
    );
    let envelope = synth.synthesize(&upper, &oracle, "p1", 100, "t1").unwrap();
    let secret_flow = rule(Label::Secret, Label::Internal);
    assert!(envelope.allows_flow(&secret_flow));
    assert!(!envelope.denies_flow(&secret_flow));
}

// ---------------------------------------------------------------------------
// 17. FlowEnvelopeRef equality and deterministic content hash
// ---------------------------------------------------------------------------

#[test]
fn flow_envelope_ref_equality() {
    let r1 = FlowEnvelopeRef {
        envelope_id: EngineObjectId([0xBB; 32]),
        envelope_hash: ContentHash::compute(b"test-ref"),
        envelope_epoch: SecurityEpoch::from_raw(5),
    };
    let r2 = FlowEnvelopeRef {
        envelope_id: EngineObjectId([0xBB; 32]),
        envelope_hash: ContentHash::compute(b"test-ref"),
        envelope_epoch: SecurityEpoch::from_raw(5),
    };
    assert_eq!(r1, r2);
}

#[test]
fn flow_envelope_ref_inequality_on_id() {
    let r1 = FlowEnvelopeRef {
        envelope_id: EngineObjectId([0xAA; 32]),
        envelope_hash: ContentHash::compute(b"same"),
        envelope_epoch: SecurityEpoch::from_raw(1),
    };
    let r2 = FlowEnvelopeRef {
        envelope_id: EngineObjectId([0xBB; 32]),
        envelope_hash: ContentHash::compute(b"same"),
        envelope_epoch: SecurityEpoch::from_raw(1),
    };
    assert_ne!(r1, r2);
}

// ---------------------------------------------------------------------------
// 18. FlowEnvelopeSynthesizer serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn synthesizer_serde_roundtrip() {
    let synth = FlowEnvelopeSynthesizer::new("ext-ser", 30_000_000_000, SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&synth).unwrap();
    let deser: FlowEnvelopeSynthesizer = serde_json::from_str(&json).unwrap();
    assert_eq!(synth.extension_id, deser.extension_id);
    assert_eq!(synth.time_budget_ns, deser.time_budget_ns);
    assert_eq!(synth.epoch, deser.epoch);
}

#[test]
fn synthesizer_serde_roundtrip_with_events() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-ser-ev", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    assert!(!synth.events.is_empty());
    let json = serde_json::to_string(&synth).unwrap();
    let deser: FlowEnvelopeSynthesizer = serde_json::from_str(&json).unwrap();
    assert_eq!(synth.events.len(), deser.events.len());
}

// ---------------------------------------------------------------------------
// 19. FlowConfidenceInterval edge cases
// ---------------------------------------------------------------------------

#[test]
fn confidence_interval_zero_trials() {
    let ci = FlowConfidenceInterval {
        lower_millionths: 0,
        upper_millionths: 1_000_000,
        n_trials: 0,
        n_essential: 0,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let deser: FlowConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, deser);
}

#[test]
fn confidence_interval_negative_lower() {
    let ci = FlowConfidenceInterval {
        lower_millionths: -50_000,
        upper_millionths: 500_000,
        n_trials: 10,
        n_essential: 3,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let deser: FlowConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, deser);
}

// ---------------------------------------------------------------------------
// 20. Fallback envelope is machine-readable (JSON contains is_fallback)
// ---------------------------------------------------------------------------

#[test]
fn fallback_envelope_machine_readable() {
    let mut input = valid_input();
    input.is_fallback = true;
    input.fallback_quality = Some(FallbackQuality::StaticBound);
    let envelope = FlowEnvelope::build(input).unwrap();
    let json = serde_json::to_string(&envelope).unwrap();
    assert!(json.contains("\"is_fallback\":true"));
}

// ---------------------------------------------------------------------------
// 21. Single-flow envelope (minimal)
// ---------------------------------------------------------------------------

#[test]
fn single_flow_envelope() {
    let mut flows = BTreeSet::new();
    flows.insert(rule(Label::Public, Label::Internal));

    let input = EnvelopeInput {
        extension_id: "ext-single".to_string(),
        static_upper_bound: flows.clone(),
        ablation_required: flows,
        ablation_removable: BTreeSet::new(),
        proof_obligations: vec![FlowProofObligation {
            rule: rule(Label::Public, Label::Internal),
            required_method: FlowProofMethod::StaticAnalysis,
            justification: "only flow".to_string(),
            proof_artifact_hash: None,
        }],
        confidence: FlowConfidenceInterval {
            lower_millionths: 1_000_000,
            upper_millionths: 1_000_000,
            n_trials: 1,
            n_essential: 1,
        },
        pass_results: Vec::new(),
        validity_epoch: SecurityEpoch::from_raw(1),
        policy_id: "policy-single".to_string(),
        is_fallback: false,
        fallback_quality: None,
        timestamp_ns: 100,
    };

    let envelope = FlowEnvelope::build(input).unwrap();
    assert_eq!(envelope.required_flows.len(), 1);
    assert_eq!(envelope.denied_flows.len(), 0);
    assert!(envelope.verify_content_address());
}

// ---------------------------------------------------------------------------
// 22. Custom label flows through synthesizer
// ---------------------------------------------------------------------------

#[test]
fn synthesizer_with_custom_labels() {
    let custom_low = Label::Custom {
        name: "audit_log".to_string(),
        level: 1,
    };
    let custom_high = Label::Custom {
        name: "key_material".to_string(),
        level: 5,
    };

    let mut upper = BTreeSet::new();
    upper.insert(rule(custom_low.clone(), custom_high.clone())); // safe: 1 <= 5
    upper.insert(rule(custom_high.clone(), custom_low.clone())); // unsafe: 5 > 1

    let mut synth = FlowEnvelopeSynthesizer::new(
        "ext-custom-labels",
        30_000_000_000,
        SecurityEpoch::from_raw(1),
    );
    let oracle = |_: &FlowRule| false;
    let envelope = synth
        .synthesize(&upper, &oracle, "policy-custom", 100, "t-custom")
        .unwrap();

    // Low -> High is safe, High -> Low is denied
    assert!(envelope.allows_flow(&rule(custom_low.clone(), custom_high.clone())));
    assert!(envelope.denies_flow(&rule(custom_high, custom_low)));
}

// ---------------------------------------------------------------------------
// 23. Proof obligations from synthesizer match required flows
// ---------------------------------------------------------------------------

#[test]
fn synthesizer_proof_obligations_match_required() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-po", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| true; // all essential
    let envelope = synth.synthesize(&upper, &oracle, "p", 100, "t").unwrap();

    // Each required flow should have a proof obligation
    for flow in &envelope.required_flows {
        assert!(
            envelope
                .proof_obligations
                .iter()
                .any(|obl| obl.rule == *flow),
            "missing proof obligation for flow {:?}",
            flow
        );
    }
}

#[test]
fn synthesizer_proof_methods_match_flow_safety() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-pm", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| true;
    let envelope = synth.synthesize(&upper, &oracle, "p", 100, "t").unwrap();

    for obl in &envelope.proof_obligations {
        if obl.rule.source_label.can_flow_to(&obl.rule.sink_clearance) {
            assert_eq!(obl.required_method, FlowProofMethod::StaticAnalysis);
        } else {
            assert_eq!(obl.required_method, FlowProofMethod::Declassification);
        }
    }
}

// ---------------------------------------------------------------------------
// 24. Confidence interval in synthesized envelope
// ---------------------------------------------------------------------------

#[test]
fn synthesizer_confidence_reflects_pass_results() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-ci", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    let envelope = synth.synthesize(&upper, &oracle, "p", 100, "t").unwrap();

    // n_trials = ablation trials only, n_essential = promoted by oracle
    assert_eq!(envelope.confidence.n_trials, 2); // 2 removable flows tested
    assert_eq!(envelope.confidence.n_essential, 0); // oracle returned false for all
    assert_eq!(envelope.confidence.upper_millionths, 1_000_000);
}

#[test]
fn fallback_confidence_is_zero() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-integ-fbc", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let envelope = synth
        .synthesize_fallback(&upper, "p", 100, FallbackQuality::StaticBound, "t")
        .unwrap();

    assert_eq!(envelope.confidence.lower_millionths, 0);
    assert_eq!(envelope.confidence.n_trials, 0);
    assert_eq!(envelope.confidence.n_essential, 0);
}
