//! Integration edge-case tests for the `flow_envelope` module.
//!
//! Covers FlowRequirement, FlowDiscoveryMethod, FlowProofObligation,
//! FlowProofMethod, FlowConfidenceInterval, SynthesisPassResult, SynthesisPass,
//! FlowEnvelope build/sign/verify/query, FallbackQuality, EnvelopeError,
//! error_code, FlowEnvelopeSynthesizer, EnvelopeEvent, and FlowEnvelopeRef.

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

// ===========================================================================
// Helpers
// ===========================================================================

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

fn signing_key() -> SigningKey {
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
        extension_id: "ext-test-001".to_string(),
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
        policy_id: "policy-001".to_string(),
        is_fallback: false,
        fallback_quality: None,
        timestamp_ns: 1_700_000_000_000_000_000,
    }
}

// ===========================================================================
// FlowDiscoveryMethod — ordering, hash, display, serde
// ===========================================================================

#[test]
fn discovery_method_ordering() {
    let methods = [
        FlowDiscoveryMethod::StaticAnalysis,
        FlowDiscoveryMethod::DynamicAblation,
        FlowDiscoveryMethod::RuntimeObservation,
        FlowDiscoveryMethod::ManifestDeclaration,
    ];
    for i in 0..methods.len() {
        for j in (i + 1)..methods.len() {
            assert!(
                methods[i] < methods[j],
                "{:?} should be < {:?}",
                methods[i],
                methods[j]
            );
        }
    }
}

#[test]
fn discovery_method_hash_distinct() {
    use std::collections::HashSet;
    let set: HashSet<FlowDiscoveryMethod> = [
        FlowDiscoveryMethod::StaticAnalysis,
        FlowDiscoveryMethod::DynamicAblation,
        FlowDiscoveryMethod::RuntimeObservation,
        FlowDiscoveryMethod::ManifestDeclaration,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn discovery_method_display_all() {
    assert_eq!(
        FlowDiscoveryMethod::StaticAnalysis.to_string(),
        "static_analysis"
    );
    assert_eq!(
        FlowDiscoveryMethod::DynamicAblation.to_string(),
        "dynamic_ablation"
    );
    assert_eq!(
        FlowDiscoveryMethod::RuntimeObservation.to_string(),
        "runtime_observation"
    );
    assert_eq!(
        FlowDiscoveryMethod::ManifestDeclaration.to_string(),
        "manifest_declaration"
    );
}

#[test]
fn discovery_method_clone_eq() {
    let m = FlowDiscoveryMethod::RuntimeObservation;
    let cloned = m;
    assert_eq!(m, cloned);
}

// ===========================================================================
// FlowProofMethod — ordering, hash, display, serde
// ===========================================================================

#[test]
fn proof_method_ordering() {
    let methods = [
        FlowProofMethod::StaticAnalysis,
        FlowProofMethod::RuntimeCheck,
        FlowProofMethod::Declassification,
        FlowProofMethod::OperatorAttestation,
    ];
    for i in 0..methods.len() {
        for j in (i + 1)..methods.len() {
            assert!(
                methods[i] < methods[j],
                "{:?} should be < {:?}",
                methods[i],
                methods[j]
            );
        }
    }
}

#[test]
fn proof_method_hash_distinct() {
    use std::collections::HashSet;
    let set: HashSet<FlowProofMethod> = [
        FlowProofMethod::StaticAnalysis,
        FlowProofMethod::RuntimeCheck,
        FlowProofMethod::Declassification,
        FlowProofMethod::OperatorAttestation,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn proof_method_display_all() {
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

// ===========================================================================
// SynthesisPass — ordering, hash, display, serde
// ===========================================================================

#[test]
fn synthesis_pass_ordering() {
    assert!(SynthesisPass::StaticFlowAnalysis < SynthesisPass::DynamicFlowAblation);
}

#[test]
fn synthesis_pass_hash_distinct() {
    use std::collections::HashSet;
    let set: HashSet<SynthesisPass> = [
        SynthesisPass::StaticFlowAnalysis,
        SynthesisPass::DynamicFlowAblation,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 2);
}

#[test]
fn synthesis_pass_display_all() {
    assert_eq!(
        SynthesisPass::StaticFlowAnalysis.to_string(),
        "static_flow_analysis"
    );
    assert_eq!(
        SynthesisPass::DynamicFlowAblation.to_string(),
        "dynamic_flow_ablation"
    );
}

// ===========================================================================
// FallbackQuality — display, serde
// ===========================================================================

#[test]
fn fallback_quality_display_all() {
    assert_eq!(FallbackQuality::StaticBound.to_string(), "static_bound");
    assert_eq!(
        FallbackQuality::PartialAblation.to_string(),
        "partial_ablation"
    );
}

#[test]
fn fallback_quality_serde_roundtrip() {
    for q in [
        FallbackQuality::StaticBound,
        FallbackQuality::PartialAblation,
    ] {
        let json = serde_json::to_string(&q).unwrap();
        let deser: FallbackQuality = serde_json::from_str(&json).unwrap();
        assert_eq!(q, deser);
    }
}

// ===========================================================================
// EnvelopeError — Display, std::error::Error, error_code, serde
// ===========================================================================

#[test]
fn envelope_error_display_empty_extension_id() {
    let err = EnvelopeError::EmptyExtensionId;
    assert_eq!(err.to_string(), "extension_id is empty");
}

#[test]
fn envelope_error_display_empty_upper_bound() {
    let err = EnvelopeError::EmptyUpperBound;
    assert_eq!(err.to_string(), "upper bound has no flows");
}

#[test]
fn envelope_error_display_overlapping_flows() {
    let err = EnvelopeError::OverlappingFlows { overlap_count: 3 };
    assert_eq!(err.to_string(), "3 flows in both required and denied sets");
}

#[test]
fn envelope_error_display_missing_proof() {
    let err = EnvelopeError::MissingProofObligation {
        rule: rule(Label::Secret, Label::Public),
    };
    let s = err.to_string();
    assert!(s.contains("secret"));
    assert!(s.contains("public"));
    assert!(s.contains("no proof obligation"));
}

#[test]
fn envelope_error_display_id_derivation() {
    let err = EnvelopeError::IdDerivation("some detail".to_string());
    assert_eq!(err.to_string(), "id derivation: some detail");
}

#[test]
fn envelope_error_display_signature_error() {
    let err = EnvelopeError::SignatureError("bad sig".to_string());
    assert_eq!(err.to_string(), "signature: bad sig");
}

#[test]
fn envelope_error_display_budget_exhausted() {
    let err = EnvelopeError::BudgetExhausted {
        phase: "dynamic".to_string(),
    };
    assert_eq!(err.to_string(), "budget exhausted during dynamic");
}

#[test]
fn envelope_error_std_error() {
    use std::error::Error;
    let err = EnvelopeError::EmptyExtensionId;
    let _: &dyn std::error::Error = &err;
    assert!(err.source().is_none());
}

#[test]
fn envelope_error_std_error_all_variants() {
    let errors: Vec<EnvelopeError> = vec![
        EnvelopeError::EmptyExtensionId,
        EnvelopeError::EmptyUpperBound,
        EnvelopeError::OverlappingFlows { overlap_count: 1 },
        EnvelopeError::MissingProofObligation {
            rule: rule(Label::Public, Label::Public),
        },
        EnvelopeError::IdDerivation(String::new()),
        EnvelopeError::SignatureError(String::new()),
        EnvelopeError::BudgetExhausted {
            phase: String::new(),
        },
    ];
    for err in &errors {
        let _dyn: &dyn std::error::Error = err;
    }
}

#[test]
fn error_code_all_7_variants() {
    assert_eq!(
        error_code(&EnvelopeError::EmptyExtensionId),
        "ENVELOPE_EMPTY_EXTENSION_ID"
    );
    assert_eq!(
        error_code(&EnvelopeError::EmptyUpperBound),
        "ENVELOPE_EMPTY_UPPER_BOUND"
    );
    assert_eq!(
        error_code(&EnvelopeError::OverlappingFlows { overlap_count: 42 }),
        "ENVELOPE_OVERLAPPING_FLOWS"
    );
    assert_eq!(
        error_code(&EnvelopeError::MissingProofObligation {
            rule: rule(Label::Public, Label::Public),
        }),
        "ENVELOPE_MISSING_PROOF"
    );
    assert_eq!(
        error_code(&EnvelopeError::IdDerivation("x".to_string())),
        "ENVELOPE_ID_DERIVATION"
    );
    assert_eq!(
        error_code(&EnvelopeError::SignatureError("x".to_string())),
        "ENVELOPE_SIGNATURE_ERROR"
    );
    assert_eq!(
        error_code(&EnvelopeError::BudgetExhausted {
            phase: "x".to_string(),
        }),
        "ENVELOPE_BUDGET_EXHAUSTED"
    );
}

#[test]
fn error_code_is_unique_per_variant() {
    let codes: BTreeSet<&str> = [
        error_code(&EnvelopeError::EmptyExtensionId),
        error_code(&EnvelopeError::EmptyUpperBound),
        error_code(&EnvelopeError::OverlappingFlows { overlap_count: 0 }),
        error_code(&EnvelopeError::MissingProofObligation {
            rule: rule(Label::Public, Label::Public),
        }),
        error_code(&EnvelopeError::IdDerivation(String::new())),
        error_code(&EnvelopeError::SignatureError(String::new())),
        error_code(&EnvelopeError::BudgetExhausted {
            phase: String::new(),
        }),
    ]
    .into_iter()
    .collect();
    assert_eq!(codes.len(), 7, "all error codes must be unique");
}

#[test]
fn envelope_error_serde_all_7() {
    let errors = [
        EnvelopeError::EmptyExtensionId,
        EnvelopeError::EmptyUpperBound,
        EnvelopeError::OverlappingFlows { overlap_count: 3 },
        EnvelopeError::MissingProofObligation {
            rule: rule(Label::Secret, Label::Public),
        },
        EnvelopeError::IdDerivation("msg".to_string()),
        EnvelopeError::SignatureError("msg".to_string()),
        EnvelopeError::BudgetExhausted {
            phase: "dynamic".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let deser: EnvelopeError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, deser);
    }
}

// ===========================================================================
// FlowRequirement — serde, all discovery methods
// ===========================================================================

#[test]
fn flow_requirement_serde_all_discovery_methods() {
    for method in [
        FlowDiscoveryMethod::StaticAnalysis,
        FlowDiscoveryMethod::DynamicAblation,
        FlowDiscoveryMethod::RuntimeObservation,
        FlowDiscoveryMethod::ManifestDeclaration,
    ] {
        let req = FlowRequirement {
            rule: rule(Label::Confidential, Label::Public),
            discovery_method: method,
            source_location: Some("src/foo.rs:1".to_string()),
            sink_location: Some("src/bar.rs:2".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deser: FlowRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(req, deser);
    }
}

#[test]
fn flow_requirement_none_locations() {
    let req = FlowRequirement {
        rule: rule(Label::Public, Label::Internal),
        discovery_method: FlowDiscoveryMethod::StaticAnalysis,
        source_location: None,
        sink_location: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    let deser: FlowRequirement = serde_json::from_str(&json).unwrap();
    assert_eq!(req, deser);
}

#[test]
fn flow_requirement_ordering() {
    let a = FlowRequirement {
        rule: rule(Label::Public, Label::Internal),
        discovery_method: FlowDiscoveryMethod::StaticAnalysis,
        source_location: None,
        sink_location: None,
    };
    let b = FlowRequirement {
        rule: rule(Label::Secret, Label::TopSecret),
        discovery_method: FlowDiscoveryMethod::ManifestDeclaration,
        source_location: None,
        sink_location: None,
    };
    // FlowRequirement derives Ord — should be comparable.
    assert!(a < b || b < a);
}

// ===========================================================================
// FlowProofObligation — serde, with/without artifact hash
// ===========================================================================

#[test]
fn proof_obligation_with_artifact_hash() {
    let obl = FlowProofObligation {
        rule: rule(Label::Secret, Label::Public),
        required_method: FlowProofMethod::Declassification,
        justification: "declass".to_string(),
        proof_artifact_hash: Some(ContentHash::compute(b"proof-artifact")),
    };
    let json = serde_json::to_string(&obl).unwrap();
    let deser: FlowProofObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(obl, deser);
}

#[test]
fn proof_obligation_without_artifact_hash() {
    let obl = FlowProofObligation {
        rule: rule(Label::Internal, Label::Public),
        required_method: FlowProofMethod::RuntimeCheck,
        justification: "runtime check needed".to_string(),
        proof_artifact_hash: None,
    };
    let json = serde_json::to_string(&obl).unwrap();
    let deser: FlowProofObligation = serde_json::from_str(&json).unwrap();
    assert_eq!(obl, deser);
}

#[test]
fn proof_obligation_all_methods_serde() {
    for method in [
        FlowProofMethod::StaticAnalysis,
        FlowProofMethod::RuntimeCheck,
        FlowProofMethod::Declassification,
        FlowProofMethod::OperatorAttestation,
    ] {
        let obl = FlowProofObligation {
            rule: rule(Label::Public, Label::Public),
            required_method: method,
            justification: "test".to_string(),
            proof_artifact_hash: None,
        };
        let json = serde_json::to_string(&obl).unwrap();
        let deser: FlowProofObligation = serde_json::from_str(&json).unwrap();
        assert_eq!(obl, deser);
    }
}

// ===========================================================================
// FlowConfidenceInterval — serde, edge values
// ===========================================================================

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
        lower_millionths: -100_000,
        upper_millionths: 500_000,
        n_trials: 10,
        n_essential: 3,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let deser: FlowConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, deser);
}

#[test]
fn confidence_interval_max_values() {
    let ci = FlowConfidenceInterval {
        lower_millionths: i64::MAX,
        upper_millionths: i64::MAX,
        n_trials: u32::MAX,
        n_essential: u32::MAX,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let deser: FlowConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, deser);
}

// ===========================================================================
// SynthesisPassResult — serde
// ===========================================================================

#[test]
fn synthesis_pass_result_serde() {
    let mut required = BTreeSet::new();
    required.insert(rule(Label::Public, Label::Internal));
    let mut removable = BTreeSet::new();
    removable.insert(rule(Label::Secret, Label::Public));
    let result = SynthesisPassResult {
        pass: SynthesisPass::DynamicFlowAblation,
        required_flows: required,
        removable_flows: removable,
        time_consumed_ns: 42_000,
        completed: true,
    };
    let json = serde_json::to_string(&result).unwrap();
    let deser: SynthesisPassResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, deser);
}

#[test]
fn synthesis_pass_result_incomplete() {
    let result = SynthesisPassResult {
        pass: SynthesisPass::DynamicFlowAblation,
        required_flows: BTreeSet::new(),
        removable_flows: BTreeSet::new(),
        time_consumed_ns: 0,
        completed: false,
    };
    let json = serde_json::to_string(&result).unwrap();
    let deser: SynthesisPassResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, deser);
    assert!(!deser.completed);
}

// ===========================================================================
// FlowEnvelope::build — edge cases
// ===========================================================================

#[test]
fn build_valid_envelope() {
    let envelope = FlowEnvelope::build(valid_input()).expect("build");
    assert_eq!(envelope.extension_id, "ext-test-001");
    assert_eq!(envelope.required_flows.len(), 2);
    assert_eq!(envelope.denied_flows.len(), 2);
    assert!(!envelope.is_fallback);
    assert!(envelope.verify_content_address());
}

#[test]
fn build_rejects_empty_extension_id() {
    let mut input = valid_input();
    input.extension_id = String::new();
    let err = FlowEnvelope::build(input).unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyExtensionId);
}

#[test]
fn build_rejects_empty_upper_bound_and_ablation() {
    let mut input = valid_input();
    input.static_upper_bound = BTreeSet::new();
    input.ablation_required = BTreeSet::new();
    let err = FlowEnvelope::build(input).unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyUpperBound);
}

#[test]
fn build_rejects_overlapping_required_and_removable() {
    let mut input = valid_input();
    let overlap = rule(Label::Public, Label::Internal);
    input.ablation_required.insert(overlap.clone());
    input.ablation_removable.insert(overlap);
    let err = FlowEnvelope::build(input).unwrap_err();
    match err {
        EnvelopeError::OverlappingFlows { overlap_count } => {
            assert!(overlap_count >= 1);
        }
        other => panic!("expected OverlappingFlows, got {:?}", other),
    }
}

#[test]
fn build_with_static_only_no_ablation() {
    let upper = test_upper_bound();
    let input = EnvelopeInput {
        extension_id: "ext-static-only".to_string(),
        static_upper_bound: upper.clone(),
        ablation_required: BTreeSet::new(),
        ablation_removable: BTreeSet::new(),
        proof_obligations: Vec::new(),
        confidence: FlowConfidenceInterval {
            lower_millionths: 0,
            upper_millionths: 1_000_000,
            n_trials: 0,
            n_essential: 0,
        },
        pass_results: Vec::new(),
        validity_epoch: SecurityEpoch::from_raw(1),
        policy_id: "policy-static".to_string(),
        is_fallback: true,
        fallback_quality: Some(FallbackQuality::StaticBound),
        timestamp_ns: 100,
    };
    let envelope = FlowEnvelope::build(input).unwrap();
    // With no ablation_required, required_flows should be the full static_upper_bound.
    assert_eq!(envelope.required_flows, upper);
    assert!(envelope.denied_flows.is_empty());
    assert!(envelope.is_fallback);
}

#[test]
fn build_single_flow_envelope() {
    let mut upper = BTreeSet::new();
    upper.insert(rule(Label::Public, Label::Internal));
    let mut required = BTreeSet::new();
    required.insert(rule(Label::Public, Label::Internal));
    let input = EnvelopeInput {
        extension_id: "ext-single".to_string(),
        static_upper_bound: upper,
        ablation_required: required,
        ablation_removable: BTreeSet::new(),
        proof_obligations: Vec::new(),
        confidence: FlowConfidenceInterval {
            lower_millionths: 1_000_000,
            upper_millionths: 1_000_000,
            n_trials: 1,
            n_essential: 1,
        },
        pass_results: Vec::new(),
        validity_epoch: SecurityEpoch::from_raw(1),
        policy_id: "p1".to_string(),
        is_fallback: false,
        fallback_quality: None,
        timestamp_ns: 0,
    };
    let envelope = FlowEnvelope::build(input).unwrap();
    assert_eq!(envelope.required_flows.len(), 1);
    assert_eq!(envelope.denied_flows.len(), 0);
    assert!(envelope.verify_content_address());
}

#[test]
fn build_many_flows_50() {
    let mut upper = BTreeSet::new();
    let mut required = BTreeSet::new();
    for i in 0..50 {
        let r = FlowRule {
            source_label: Label::Custom {
                name: format!("src_{i}"),
                level: i,
            },
            sink_clearance: Label::Custom {
                name: format!("sink_{i}"),
                level: i + 100,
            },
        };
        upper.insert(r.clone());
        required.insert(r);
    }
    let input = EnvelopeInput {
        extension_id: "ext-many".to_string(),
        static_upper_bound: upper,
        ablation_required: required,
        ablation_removable: BTreeSet::new(),
        proof_obligations: Vec::new(),
        confidence: FlowConfidenceInterval {
            lower_millionths: 0,
            upper_millionths: 1_000_000,
            n_trials: 50,
            n_essential: 50,
        },
        pass_results: Vec::new(),
        validity_epoch: SecurityEpoch::from_raw(1),
        policy_id: "p1".to_string(),
        is_fallback: false,
        fallback_quality: None,
        timestamp_ns: 0,
    };
    let envelope = FlowEnvelope::build(input).unwrap();
    assert_eq!(envelope.required_flows.len(), 50);
    assert!(envelope.verify_content_address());
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

// ===========================================================================
// Content addressing
// ===========================================================================

#[test]
fn content_address_deterministic() {
    let e1 = FlowEnvelope::build(valid_input()).unwrap();
    let e2 = FlowEnvelope::build(valid_input()).unwrap();
    assert_eq!(e1.envelope_id, e2.envelope_id);
}

#[test]
fn content_address_changes_with_extension_id() {
    let e1 = FlowEnvelope::build(valid_input()).unwrap();
    let mut input2 = valid_input();
    input2.extension_id = "ext-different".to_string();
    let e2 = FlowEnvelope::build(input2).unwrap();
    assert_ne!(e1.envelope_id, e2.envelope_id);
}

#[test]
fn content_address_changes_with_policy_id() {
    let e1 = FlowEnvelope::build(valid_input()).unwrap();
    let mut input2 = valid_input();
    input2.policy_id = "policy-different".to_string();
    let e2 = FlowEnvelope::build(input2).unwrap();
    assert_ne!(e1.envelope_id, e2.envelope_id);
}

#[test]
fn content_address_changes_with_timestamp() {
    let e1 = FlowEnvelope::build(valid_input()).unwrap();
    let mut input2 = valid_input();
    input2.timestamp_ns = 999;
    let e2 = FlowEnvelope::build(input2).unwrap();
    assert_ne!(e1.envelope_id, e2.envelope_id);
}

#[test]
fn content_address_changes_with_epoch() {
    let e1 = FlowEnvelope::build(valid_input()).unwrap();
    let mut input2 = valid_input();
    input2.validity_epoch = SecurityEpoch::from_raw(99);
    let e2 = FlowEnvelope::build(input2).unwrap();
    assert_ne!(e1.envelope_id, e2.envelope_id);
}

#[test]
fn verify_content_address_detects_tampered_timestamp() {
    let mut e = FlowEnvelope::build(valid_input()).unwrap();
    assert!(e.verify_content_address());
    e.timestamp_ns = 42;
    assert!(!e.verify_content_address());
}

#[test]
fn verify_content_address_detects_tampered_extension_id() {
    let mut e = FlowEnvelope::build(valid_input()).unwrap();
    e.extension_id = "tampered".to_string();
    assert!(!e.verify_content_address());
}

#[test]
fn verify_content_address_detects_tampered_policy_id() {
    let mut e = FlowEnvelope::build(valid_input()).unwrap();
    e.policy_id = "tampered-policy".to_string();
    assert!(!e.verify_content_address());
}

#[test]
fn verify_content_address_detects_tampered_required_flows() {
    let mut e = FlowEnvelope::build(valid_input()).unwrap();
    e.required_flows
        .insert(rule(Label::TopSecret, Label::TopSecret));
    assert!(!e.verify_content_address());
}

#[test]
fn verify_content_address_detects_tampered_denied_flows() {
    let mut e = FlowEnvelope::build(valid_input()).unwrap();
    e.denied_flows.clear();
    assert!(!e.verify_content_address());
}

// ===========================================================================
// Signing / verification
// ===========================================================================

#[test]
fn sign_and_verify_roundtrip() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
    envelope.sign(&key).expect("sign");
    envelope.verify(&vk).expect("verify");
}

#[test]
fn verify_fails_with_wrong_key() {
    let key = signing_key();
    let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
    envelope.sign(&key).expect("sign");
    let wrong = SigningKey::from_bytes([0xBB; 32]);
    assert!(envelope.verify(&wrong.verification_key()).is_err());
}

#[test]
fn sign_preserves_envelope_id() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let id_before = envelope.envelope_id.clone();
    let mut signed = envelope;
    signed.sign(&signing_key()).unwrap();
    assert_eq!(signed.envelope_id, id_before);
}

#[test]
fn sign_preserves_content_address() {
    let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
    envelope.sign(&signing_key()).unwrap();
    assert!(envelope.verify_content_address());
}

#[test]
fn double_sign_overwrites_signature() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
    envelope.sign(&key).unwrap();
    let sig1 = envelope.signature.clone();
    envelope.sign(&key).unwrap();
    // Re-signing should produce the same signature (deterministic).
    assert_eq!(envelope.signature, sig1);
    envelope.verify(&vk).unwrap();
}

#[test]
fn sign_with_different_keys_produces_different_signatures() {
    let key1 = signing_key();
    let key2 = SigningKey::from_bytes([0xCC; 32]);
    let mut e1 = FlowEnvelope::build(valid_input()).unwrap();
    let mut e2 = FlowEnvelope::build(valid_input()).unwrap();
    e1.sign(&key1).unwrap();
    e2.sign(&key2).unwrap();
    assert_ne!(e1.signature, e2.signature);
}

// ===========================================================================
// Epoch validity
// ===========================================================================

#[test]
fn is_valid_at_matching_epoch() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    assert!(envelope.is_valid_at_epoch(SecurityEpoch::from_raw(1)));
}

#[test]
fn is_invalid_at_different_epoch() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    assert!(!envelope.is_valid_at_epoch(SecurityEpoch::from_raw(2)));
    assert!(!envelope.is_valid_at_epoch(SecurityEpoch::from_raw(0)));
}

#[test]
fn is_invalid_at_epoch_zero_vs_one() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    assert!(!envelope.is_valid_at_epoch(SecurityEpoch::from_raw(0)));
}

// ===========================================================================
// Flow queries — allows_flow, denies_flow, is_out_of_envelope
// ===========================================================================

#[test]
fn allows_flow_for_required() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    assert!(envelope.allows_flow(&rule(Label::Public, Label::Internal)));
    assert!(envelope.allows_flow(&rule(Label::Internal, Label::Confidential)));
}

#[test]
fn denies_flow_for_denied() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    assert!(envelope.denies_flow(&rule(Label::Confidential, Label::Public)));
    assert!(envelope.denies_flow(&rule(Label::Secret, Label::Internal)));
}

#[test]
fn is_out_of_envelope_for_unknown() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    assert!(envelope.is_out_of_envelope(&rule(Label::Secret, Label::Secret)));
    assert!(envelope.is_out_of_envelope(&rule(Label::TopSecret, Label::Public)));
}

#[test]
fn flow_not_simultaneously_allowed_and_denied() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    for r in &envelope.required_flows {
        assert!(
            !envelope.denies_flow(r),
            "required flow should not be denied"
        );
        assert!(!envelope.is_out_of_envelope(r));
    }
    for r in &envelope.denied_flows {
        assert!(
            !envelope.allows_flow(r),
            "denied flow should not be allowed"
        );
        assert!(!envelope.is_out_of_envelope(r));
    }
}

#[test]
fn source_labels_extracted() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let sources = envelope.source_labels();
    assert!(sources.contains(&Label::Public));
    assert!(sources.contains(&Label::Internal));
    assert!(!sources.contains(&Label::Secret));
}

#[test]
fn sink_clearances_extracted() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let sinks = envelope.sink_clearances();
    assert!(sinks.contains(&Label::Internal));
    assert!(sinks.contains(&Label::Confidential));
    assert!(!sinks.contains(&Label::Public));
}

#[test]
fn unsatisfied_obligations_all_unsatisfied() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    // All obligations have proof_artifact_hash = None.
    assert_eq!(
        envelope.unsatisfied_obligations(),
        envelope.proof_obligations.len()
    );
}

#[test]
fn unsatisfied_obligations_all_satisfied() {
    let mut input = valid_input();
    for obl in &mut input.proof_obligations {
        obl.proof_artifact_hash = Some(ContentHash::compute(b"proof"));
    }
    let envelope = FlowEnvelope::build(input).unwrap();
    assert_eq!(envelope.unsatisfied_obligations(), 0);
}

#[test]
fn unsatisfied_obligations_partial() {
    let mut input = valid_input();
    if let Some(first) = input.proof_obligations.first_mut() {
        first.proof_artifact_hash = Some(ContentHash::compute(b"proof1"));
    }
    let envelope = FlowEnvelope::build(input).unwrap();
    assert_eq!(
        envelope.unsatisfied_obligations(),
        envelope.proof_obligations.len() - 1
    );
}

// ===========================================================================
// Serde roundtrips
// ===========================================================================

#[test]
fn envelope_serde_roundtrip() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let json = serde_json::to_string(&envelope).unwrap();
    let deser: FlowEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope, deser);
}

#[test]
fn envelope_serde_preserves_content_address() {
    let envelope = FlowEnvelope::build(valid_input()).unwrap();
    let json = serde_json::to_string(&envelope).unwrap();
    let deser: FlowEnvelope = serde_json::from_str(&json).unwrap();
    assert!(deser.verify_content_address());
}

#[test]
fn envelope_serde_roundtrip_signed() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut envelope = FlowEnvelope::build(valid_input()).unwrap();
    envelope.sign(&key).unwrap();
    let json = serde_json::to_string(&envelope).unwrap();
    let deser: FlowEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope, deser);
    deser.verify(&vk).unwrap();
}

#[test]
fn envelope_event_serde_roundtrip() {
    let ev = EnvelopeEvent {
        trace_id: "t1".to_string(),
        component: "flow_envelope".to_string(),
        event: "custom_event".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("ERR_CODE".to_string()),
        extension_id: Some("ext-001".to_string()),
        flow_count: Some(42),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let deser: EnvelopeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, deser);
}

#[test]
fn envelope_event_serde_none_fields() {
    let ev = EnvelopeEvent {
        trace_id: "t2".to_string(),
        component: "flow_envelope".to_string(),
        event: "test".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        extension_id: None,
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
        envelope_epoch: SecurityEpoch::from_raw(42),
    };
    let json = serde_json::to_string(&r).unwrap();
    let deser: FlowEnvelopeRef = serde_json::from_str(&json).unwrap();
    assert_eq!(r, deser);
}

// ===========================================================================
// Synthesizer — static_pass
// ===========================================================================

#[test]
fn synthesizer_static_pass_safe_flows() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-001", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let result = synth.static_pass(&upper, "trace-1");
    assert!(result.completed);
    assert_eq!(result.pass, SynthesisPass::StaticFlowAnalysis);
    // Public→Internal and Internal→Confidential are safe.
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
    // Confidential→Public and Secret→Internal need declassification.
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
fn synthesizer_static_pass_all_safe() {
    let mut synth = FlowEnvelopeSynthesizer::new("ext-safe", 1_000, SecurityEpoch::from_raw(1));
    let mut upper = BTreeSet::new();
    upper.insert(rule(Label::Public, Label::Internal));
    upper.insert(rule(Label::Public, Label::Confidential));
    upper.insert(rule(Label::Internal, Label::Secret));
    let result = synth.static_pass(&upper, "t");
    assert_eq!(result.required_flows.len(), 3);
    assert_eq!(result.removable_flows.len(), 0);
}

#[test]
fn synthesizer_static_pass_all_unsafe() {
    let mut synth = FlowEnvelopeSynthesizer::new("ext-unsafe", 1_000, SecurityEpoch::from_raw(1));
    let mut upper = BTreeSet::new();
    upper.insert(rule(Label::Secret, Label::Public));
    upper.insert(rule(Label::Confidential, Label::Public));
    upper.insert(rule(Label::TopSecret, Label::Internal));
    let result = synth.static_pass(&upper, "t");
    assert_eq!(result.required_flows.len(), 0);
    assert_eq!(result.removable_flows.len(), 3);
}

#[test]
fn synthesizer_static_pass_empty_upper_bound() {
    let mut synth = FlowEnvelopeSynthesizer::new("ext-empty", 1_000, SecurityEpoch::from_raw(1));
    let upper = BTreeSet::new();
    let result = synth.static_pass(&upper, "t");
    assert!(result.required_flows.is_empty());
    assert!(result.removable_flows.is_empty());
    assert!(result.completed);
}

// ===========================================================================
// Synthesizer — dynamic_pass
// ===========================================================================

#[test]
fn synthesizer_dynamic_pass_promotes_essential() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-dyn", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let static_result = synth.static_pass(&upper, "t");
    // Oracle: Confidential→Public is essential.
    let oracle =
        |r: &FlowRule| r.source_label == Label::Confidential && r.sink_clearance == Label::Public;
    let dynamic = synth.dynamic_pass(&static_result, &oracle, "t");
    assert_eq!(dynamic.required_flows.len(), 3);
    assert_eq!(dynamic.removable_flows.len(), 1);
    assert!(
        dynamic
            .required_flows
            .contains(&rule(Label::Confidential, Label::Public))
    );
    assert!(
        dynamic
            .removable_flows
            .contains(&rule(Label::Secret, Label::Internal))
    );
}

#[test]
fn synthesizer_dynamic_pass_all_essential() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-all", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let static_result = synth.static_pass(&upper, "t");
    let oracle = |_: &FlowRule| true;
    let dynamic = synth.dynamic_pass(&static_result, &oracle, "t");
    assert_eq!(dynamic.required_flows.len(), 4);
    assert_eq!(dynamic.removable_flows.len(), 0);
}

#[test]
fn synthesizer_dynamic_pass_none_essential() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-none", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let static_result = synth.static_pass(&upper, "t");
    let oracle = |_: &FlowRule| false;
    let dynamic = synth.dynamic_pass(&static_result, &oracle, "t");
    // Only safe flows remain required.
    assert_eq!(dynamic.required_flows.len(), 2);
    assert_eq!(dynamic.removable_flows.len(), 2);
}

// ===========================================================================
// Synthesizer — synthesize (full)
// ===========================================================================

#[test]
fn synthesize_full_nothing_essential() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-full", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    let envelope = synth
        .synthesize(&upper, &oracle, "policy-001", 100, "trace-full")
        .unwrap();
    assert_eq!(envelope.extension_id, "ext-full");
    assert!(!envelope.is_fallback);
    assert_eq!(envelope.required_flows.len(), 2);
    assert_eq!(envelope.denied_flows.len(), 2);
    assert!(envelope.verify_content_address());
    assert_eq!(envelope.pass_results.len(), 2);
}

#[test]
fn synthesize_full_all_essential() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-all", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| true;
    let envelope = synth
        .synthesize(&upper, &oracle, "policy-002", 200, "trace-all")
        .unwrap();
    assert_eq!(envelope.required_flows.len(), 4);
    assert_eq!(envelope.denied_flows.len(), 0);
}

#[test]
fn synthesize_proof_obligations_match_required() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-proof", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |r: &FlowRule| r.source_label == Label::Secret;
    let envelope = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    // Each required flow should have a corresponding proof obligation.
    let obligation_rules: BTreeSet<_> = envelope
        .proof_obligations
        .iter()
        .map(|o| o.rule.clone())
        .collect();
    assert_eq!(obligation_rules, envelope.required_flows);
}

#[test]
fn synthesize_proof_methods_static_vs_declass() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-methods", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| true;
    let envelope = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    for obl in &envelope.proof_obligations {
        if obl.rule.source_label.can_flow_to(&obl.rule.sink_clearance) {
            assert_eq!(obl.required_method, FlowProofMethod::StaticAnalysis);
        } else {
            assert_eq!(obl.required_method, FlowProofMethod::Declassification);
        }
    }
}

#[test]
fn synthesize_confidence_computed() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-conf", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    let envelope = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    // 2 ablation trials, 0 promoted → n_trials = 2, n_essential = 0
    assert_eq!(envelope.confidence.n_trials, 2);
    assert_eq!(envelope.confidence.n_essential, 0);
    assert_eq!(envelope.confidence.lower_millionths, 0);
    assert_eq!(envelope.confidence.upper_millionths, 1_000_000);
}

#[test]
fn synthesize_confidence_all_essential() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-ce", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| true;
    let envelope = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    // 2 ablation trials, 2 promoted → n_trials = 2, n_essential = 2
    assert_eq!(envelope.confidence.n_trials, 2);
    assert_eq!(envelope.confidence.n_essential, 2);
    assert_eq!(envelope.confidence.lower_millionths, 1_000_000);
}

#[test]
fn synthesize_rejects_empty_extension_id() {
    let mut synth = FlowEnvelopeSynthesizer::new("", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    let err = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyExtensionId);
}

#[test]
fn synthesize_rejects_empty_upper_bound() {
    let mut synth = FlowEnvelopeSynthesizer::new("ext", 30_000_000_000, SecurityEpoch::from_raw(1));
    let empty = BTreeSet::new();
    let oracle = |_: &FlowRule| false;
    let err = synth.synthesize(&empty, &oracle, "p", 0, "t").unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyUpperBound);
}

// ===========================================================================
// Synthesizer — synthesize_fallback
// ===========================================================================

#[test]
fn synthesize_fallback_static_bound() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-fb", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let envelope = synth
        .synthesize_fallback(&upper, "p", 100, FallbackQuality::StaticBound, "t")
        .unwrap();
    assert!(envelope.is_fallback);
    assert_eq!(
        envelope.fallback_quality,
        Some(FallbackQuality::StaticBound)
    );
    // All upper-bound flows are required in fallback.
    assert_eq!(envelope.required_flows, upper);
    assert!(envelope.denied_flows.is_empty());
    assert!(envelope.verify_content_address());
}

#[test]
fn synthesize_fallback_partial_ablation() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-pa", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let envelope = synth
        .synthesize_fallback(&upper, "p", 200, FallbackQuality::PartialAblation, "t")
        .unwrap();
    assert!(envelope.is_fallback);
    assert_eq!(
        envelope.fallback_quality,
        Some(FallbackQuality::PartialAblation)
    );
}

#[test]
fn synthesize_fallback_proof_method_is_runtime_check() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-fbrm", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let envelope = synth
        .synthesize_fallback(&upper, "p", 0, FallbackQuality::StaticBound, "t")
        .unwrap();
    for obl in &envelope.proof_obligations {
        assert_eq!(obl.required_method, FlowProofMethod::RuntimeCheck);
        assert_eq!(obl.justification, "fallback: static upper bound");
    }
}

#[test]
fn synthesize_fallback_confidence_zero() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-fbc", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let envelope = synth
        .synthesize_fallback(&upper, "p", 0, FallbackQuality::StaticBound, "t")
        .unwrap();
    assert_eq!(envelope.confidence.n_trials, 0);
    assert_eq!(envelope.confidence.n_essential, 0);
    assert_eq!(envelope.confidence.lower_millionths, 0);
}

#[test]
fn synthesize_fallback_rejects_empty_extension_id() {
    let mut synth = FlowEnvelopeSynthesizer::new("", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let err = synth
        .synthesize_fallback(&upper, "p", 0, FallbackQuality::StaticBound, "t")
        .unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyExtensionId);
}

#[test]
fn synthesize_fallback_rejects_empty_upper_bound() {
    let mut synth = FlowEnvelopeSynthesizer::new("ext", 30_000_000_000, SecurityEpoch::from_raw(1));
    let empty = BTreeSet::new();
    let err = synth
        .synthesize_fallback(&empty, "p", 0, FallbackQuality::StaticBound, "t")
        .unwrap_err();
    assert_eq!(err, EnvelopeError::EmptyUpperBound);
}

// ===========================================================================
// Synthesizer — events
// ===========================================================================

#[test]
fn synthesize_emits_events_correct_order() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-ev", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    synth
        .synthesize(&upper, &oracle, "p", 0, "trace-ev")
        .unwrap();
    let event_names: Vec<&str> = synth.events.iter().map(|e| e.event.as_str()).collect();
    assert_eq!(event_names[0], "synthesis_start");
    assert_eq!(event_names[1], "static_pass_start");
    assert_eq!(event_names[2], "static_pass_complete");
    assert_eq!(event_names[3], "dynamic_pass_start");
    assert_eq!(event_names[4], "dynamic_pass_complete");
    assert_eq!(event_names[5], "synthesis_complete");
    assert_eq!(synth.events.len(), 6);
}

#[test]
fn synthesize_events_carry_trace_id() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-tid", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    synth
        .synthesize(&upper, &oracle, "p", 0, "my-trace-99")
        .unwrap();
    for event in &synth.events {
        assert_eq!(event.trace_id, "my-trace-99");
        assert_eq!(event.component, "flow_envelope");
    }
}

#[test]
fn synthesize_events_carry_extension_id() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-eid-check", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    for event in &synth.events {
        assert_eq!(event.extension_id.as_deref(), Some("ext-eid-check"));
    }
}

#[test]
fn fallback_emits_events_correct_order() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-fb-ev", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    synth
        .synthesize_fallback(&upper, "p", 0, FallbackQuality::StaticBound, "trace-fb")
        .unwrap();
    let event_names: Vec<&str> = synth.events.iter().map(|e| e.event.as_str()).collect();
    assert_eq!(event_names[0], "fallback_synthesis_start");
    assert_eq!(event_names[1], "static_pass_start");
    assert_eq!(event_names[2], "static_pass_complete");
    assert_eq!(event_names[3], "fallback_synthesis_complete");
    assert_eq!(synth.events.len(), 4);
}

#[test]
fn synthesizer_events_accumulate_across_calls() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-acc", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    synth.synthesize(&upper, &oracle, "p", 0, "t1").unwrap();
    let count_after_first = synth.events.len();
    synth
        .synthesize_fallback(&upper, "p", 0, FallbackQuality::StaticBound, "t2")
        .unwrap();
    assert!(synth.events.len() > count_after_first);
}

// ===========================================================================
// Synthesizer — serde
// ===========================================================================

#[test]
fn synthesizer_serde_roundtrip() {
    let synth =
        FlowEnvelopeSynthesizer::new("ext-serde", 30_000_000_000, SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&synth).unwrap();
    let deser: FlowEnvelopeSynthesizer = serde_json::from_str(&json).unwrap();
    assert_eq!(synth.extension_id, deser.extension_id);
    assert_eq!(synth.time_budget_ns, deser.time_budget_ns);
}

#[test]
fn synthesizer_serde_with_events() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-sev", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |_: &FlowRule| false;
    synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    let json = serde_json::to_string(&synth).unwrap();
    let deser: FlowEnvelopeSynthesizer = serde_json::from_str(&json).unwrap();
    assert_eq!(synth.events, deser.events);
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn build_deterministic_100_times() {
    let first = FlowEnvelope::build(valid_input()).unwrap();
    for _ in 0..100 {
        let e = FlowEnvelope::build(valid_input()).unwrap();
        assert_eq!(e.envelope_id, first.envelope_id);
        assert_eq!(e.required_flows, first.required_flows);
        assert_eq!(e.denied_flows, first.denied_flows);
    }
}

#[test]
fn synthesize_deterministic_100_times() {
    let oracle = |_: &FlowRule| false;
    let upper = test_upper_bound();
    let mut first_synth =
        FlowEnvelopeSynthesizer::new("ext-d100", 30_000_000_000, SecurityEpoch::from_raw(1));
    let first = first_synth
        .synthesize(&upper, &oracle, "p", 100, "t")
        .unwrap();
    for _ in 0..100 {
        let mut synth =
            FlowEnvelopeSynthesizer::new("ext-d100", 30_000_000_000, SecurityEpoch::from_raw(1));
        let e = synth.synthesize(&upper, &oracle, "p", 100, "t2").unwrap();
        assert_eq!(e.envelope_id, first.envelope_id);
        assert_eq!(e.required_flows, first.required_flows);
        assert_eq!(e.denied_flows, first.denied_flows);
    }
}

// ===========================================================================
// Custom label flows
// ===========================================================================

#[test]
fn custom_labels_in_flow_envelope() {
    let src = Label::Custom {
        name: "sensor_data".to_string(),
        level: 2,
    };
    let sink = Label::Custom {
        name: "analytics_clearance".to_string(),
        level: 3,
    };
    let mut upper = BTreeSet::new();
    upper.insert(rule(src.clone(), sink.clone()));
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-custom", 30_000_000_000, SecurityEpoch::from_raw(1));
    let oracle = |_: &FlowRule| false;
    let envelope = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    // level 2 → level 3 is safe (upward flow).
    assert!(envelope.allows_flow(&rule(src, sink)));
    assert!(envelope.denied_flows.is_empty());
}

#[test]
fn custom_labels_downward_flow_removable() {
    let src = Label::Custom {
        name: "high".to_string(),
        level: 5,
    };
    let sink = Label::Custom {
        name: "low".to_string(),
        level: 1,
    };
    let mut upper = BTreeSet::new();
    upper.insert(rule(src.clone(), sink.clone()));
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-down", 30_000_000_000, SecurityEpoch::from_raw(1));
    let oracle = |_: &FlowRule| false;
    let envelope = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    // level 5 → level 1 is unsafe.
    assert!(envelope.denies_flow(&rule(src, sink)));
}

// ===========================================================================
// FlowEnvelopeRef
// ===========================================================================

#[test]
fn flow_envelope_ref_different_hashes() {
    let r1 = FlowEnvelopeRef {
        envelope_id: EngineObjectId([0xAA; 32]),
        envelope_hash: ContentHash::compute(b"aaa"),
        envelope_epoch: SecurityEpoch::from_raw(1),
    };
    let r2 = FlowEnvelopeRef {
        envelope_id: EngineObjectId([0xAA; 32]),
        envelope_hash: ContentHash::compute(b"bbb"),
        envelope_epoch: SecurityEpoch::from_raw(1),
    };
    assert_ne!(r1, r2);
}

#[test]
fn flow_envelope_ref_clone_eq() {
    let r = FlowEnvelopeRef {
        envelope_id: EngineObjectId([0x11; 32]),
        envelope_hash: ContentHash::compute(b"clone_test"),
        envelope_epoch: SecurityEpoch::from_raw(5),
    };
    let cloned = r.clone();
    assert_eq!(r, cloned);
}

// ===========================================================================
// Integration: envelope from synthesizer, then sign, verify, query
// ===========================================================================

#[test]
fn integration_synthesize_sign_verify_query() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-int", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle =
        |r: &FlowRule| r.source_label == Label::Confidential && r.sink_clearance == Label::Public;
    let mut envelope = synth
        .synthesize(&upper, &oracle, "policy-int", 1000, "trace-int")
        .unwrap();

    // Sign and verify.
    envelope.sign(&key).unwrap();
    envelope.verify(&vk).unwrap();
    assert!(envelope.verify_content_address());

    // Query flows.
    assert!(envelope.allows_flow(&rule(Label::Public, Label::Internal)));
    assert!(envelope.allows_flow(&rule(Label::Internal, Label::Confidential)));
    assert!(envelope.allows_flow(&rule(Label::Confidential, Label::Public)));
    assert!(envelope.denies_flow(&rule(Label::Secret, Label::Internal)));
    assert!(envelope.is_out_of_envelope(&rule(Label::TopSecret, Label::TopSecret)));

    // Check epoch.
    assert!(envelope.is_valid_at_epoch(SecurityEpoch::from_raw(1)));
    assert!(!envelope.is_valid_at_epoch(SecurityEpoch::from_raw(2)));

    // Source/sink labels.
    let sources = envelope.source_labels();
    assert!(sources.contains(&Label::Public));
    assert!(sources.contains(&Label::Internal));
    assert!(sources.contains(&Label::Confidential));
}

#[test]
fn integration_fallback_then_full() {
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-fb-full", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();

    // First: fallback (all flows required).
    let fallback = synth
        .synthesize_fallback(&upper, "p", 100, FallbackQuality::StaticBound, "t1")
        .unwrap();
    assert_eq!(fallback.required_flows.len(), 4);
    assert!(fallback.is_fallback);

    // Second: full synthesis (tighter).
    let oracle = |_: &FlowRule| false;
    let full = synth.synthesize(&upper, &oracle, "p", 200, "t2").unwrap();
    assert_eq!(full.required_flows.len(), 2);
    assert!(!full.is_fallback);

    // Fallback is looser than full.
    assert!(full.required_flows.is_subset(&fallback.required_flows));
}

#[test]
fn integration_serde_preserves_full_envelope() {
    let key = signing_key();
    let vk = key.verification_key();
    let mut synth =
        FlowEnvelopeSynthesizer::new("ext-serde-full", 30_000_000_000, SecurityEpoch::from_raw(1));
    let upper = test_upper_bound();
    let oracle = |r: &FlowRule| r.source_label == Label::Secret;
    let mut envelope = synth.synthesize(&upper, &oracle, "p", 0, "t").unwrap();
    envelope.sign(&key).unwrap();

    let json = serde_json::to_string(&envelope).unwrap();
    let deser: FlowEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope, deser);
    deser.verify(&vk).unwrap();
    assert!(deser.verify_content_address());
    assert_eq!(deser.required_flows, envelope.required_flows);
    assert_eq!(deser.denied_flows, envelope.denied_flows);
}
