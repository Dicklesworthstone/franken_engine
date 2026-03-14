#![forbid(unsafe_code)]

//! Enrichment integration tests for the `flow_envelope` module.

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

use frankenengine_engine::flow_envelope::{
    EnvelopeError, EnvelopeEvent, EnvelopeInput, FallbackQuality, FlowConfidenceInterval,
    FlowDiscoveryMethod, FlowEnvelope, FlowEnvelopeRef, FlowEnvelopeSynthesizer, FlowProofMethod,
    FlowProofObligation, FlowRequirement, SynthesisPass, SynthesisPassResult, error_code,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::{FlowRule, Label};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn rule(source: Label, sink: Label) -> FlowRule {
    FlowRule {
        source_label: source,
        sink_clearance: sink,
    }
}

fn upper_bound_3() -> BTreeSet<FlowRule> {
    let mut flows = BTreeSet::new();
    flows.insert(rule(Label::Public, Label::Internal));
    flows.insert(rule(Label::Internal, Label::Confidential));
    flows.insert(rule(Label::Confidential, Label::Public)); // unsafe: Conf -> Public
    flows
}

fn make_input(ext: &str) -> EnvelopeInput {
    let ub = upper_bound_3();
    EnvelopeInput {
        extension_id: ext.to_string(),
        static_upper_bound: ub.clone(),
        ablation_required: ub.clone(),
        ablation_removable: BTreeSet::new(),
        proof_obligations: vec![],
        confidence: FlowConfidenceInterval {
            lower_millionths: 900_000,
            upper_millionths: 1_000_000,
            n_trials: 10,
            n_essential: 9,
        },
        pass_results: vec![],
        validity_epoch: epoch(),
        policy_id: "policy-1".to_string(),
        is_fallback: false,
        fallback_quality: None,
        timestamp_ns: 1_000_000,
    }
}

fn build_envelope(ext: &str) -> FlowEnvelope {
    FlowEnvelope::build(make_input(ext)).unwrap()
}

// ===========================================================================
// FlowDiscoveryMethod — Copy, BTreeSet, Debug/Display unique, as_str
// ===========================================================================

#[test]
fn enrichment_flow_discovery_method_copy_semantics() {
    let a = FlowDiscoveryMethod::StaticAnalysis;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_flow_discovery_method_btreeset_dedup_4() {
    let set: BTreeSet<FlowDiscoveryMethod> = [
        FlowDiscoveryMethod::StaticAnalysis,
        FlowDiscoveryMethod::DynamicAblation,
        FlowDiscoveryMethod::RuntimeObservation,
        FlowDiscoveryMethod::ManifestDeclaration,
        FlowDiscoveryMethod::StaticAnalysis,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_flow_discovery_method_debug_all_unique() {
    let variants = [
        FlowDiscoveryMethod::StaticAnalysis,
        FlowDiscoveryMethod::DynamicAblation,
        FlowDiscoveryMethod::RuntimeObservation,
        FlowDiscoveryMethod::ManifestDeclaration,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_flow_discovery_method_display_all_unique() {
    let variants = [
        FlowDiscoveryMethod::StaticAnalysis,
        FlowDiscoveryMethod::DynamicAblation,
        FlowDiscoveryMethod::RuntimeObservation,
        FlowDiscoveryMethod::ManifestDeclaration,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_flow_discovery_method_clone_independence() {
    let a = FlowDiscoveryMethod::RuntimeObservation;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_flow_discovery_method_serde_all_variants() {
    let variants = [
        FlowDiscoveryMethod::StaticAnalysis,
        FlowDiscoveryMethod::DynamicAblation,
        FlowDiscoveryMethod::RuntimeObservation,
        FlowDiscoveryMethod::ManifestDeclaration,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: FlowDiscoveryMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// FlowProofMethod — Copy, BTreeSet, Debug/Display unique
// ===========================================================================

#[test]
fn enrichment_flow_proof_method_copy_semantics() {
    let a = FlowProofMethod::Declassification;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_flow_proof_method_btreeset_dedup_4() {
    let set: BTreeSet<FlowProofMethod> = [
        FlowProofMethod::StaticAnalysis,
        FlowProofMethod::RuntimeCheck,
        FlowProofMethod::Declassification,
        FlowProofMethod::OperatorAttestation,
        FlowProofMethod::StaticAnalysis,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_flow_proof_method_debug_all_unique() {
    let variants = [
        FlowProofMethod::StaticAnalysis,
        FlowProofMethod::RuntimeCheck,
        FlowProofMethod::Declassification,
        FlowProofMethod::OperatorAttestation,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strs.len(), 4);
}

#[test]
fn enrichment_flow_proof_method_display_all_unique() {
    let variants = [
        FlowProofMethod::StaticAnalysis,
        FlowProofMethod::RuntimeCheck,
        FlowProofMethod::Declassification,
        FlowProofMethod::OperatorAttestation,
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 4);
}

// ===========================================================================
// SynthesisPass — Copy, BTreeSet, Debug/Display unique
// ===========================================================================

#[test]
fn enrichment_synthesis_pass_copy_semantics() {
    let a = SynthesisPass::StaticFlowAnalysis;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_synthesis_pass_btreeset_dedup_2() {
    let set: BTreeSet<SynthesisPass> = [
        SynthesisPass::StaticFlowAnalysis,
        SynthesisPass::DynamicFlowAblation,
        SynthesisPass::StaticFlowAnalysis,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_synthesis_pass_debug_all_unique() {
    let strs: BTreeSet<String> = [
        SynthesisPass::StaticFlowAnalysis,
        SynthesisPass::DynamicFlowAblation,
    ]
    .iter()
    .map(|v| format!("{v:?}"))
    .collect();
    assert_eq!(strs.len(), 2);
}

// ===========================================================================
// FallbackQuality — Copy, BTreeSet, Debug/Display unique
// ===========================================================================

#[test]
fn enrichment_fallback_quality_copy_semantics() {
    let a = FallbackQuality::StaticBound;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_fallback_quality_debug_all_unique() {
    let strs: BTreeSet<String> = [
        FallbackQuality::StaticBound,
        FallbackQuality::PartialAblation,
    ]
    .iter()
    .map(|v| format!("{v:?}"))
    .collect();
    assert_eq!(strs.len(), 2);
}

#[test]
fn enrichment_fallback_quality_display_all_unique() {
    let strs: BTreeSet<String> = [
        FallbackQuality::StaticBound,
        FallbackQuality::PartialAblation,
    ]
    .iter()
    .map(|v| format!("{v}"))
    .collect();
    assert_eq!(strs.len(), 2);
}

// ===========================================================================
// FlowRequirement — Clone, Debug, JSON field names, serde
// ===========================================================================

#[test]
fn enrichment_flow_requirement_clone_independence() {
    let mut a = FlowRequirement {
        rule: rule(Label::Public, Label::Internal),
        discovery_method: FlowDiscoveryMethod::StaticAnalysis,
        source_location: Some("file.rs:10".to_string()),
        sink_location: Some("file.rs:20".to_string()),
    };
    let b = a.clone();
    a.source_location = Some("changed".to_string());
    assert_ne!(a.source_location, b.source_location);
}

#[test]
fn enrichment_flow_requirement_debug_nonempty() {
    let req = FlowRequirement {
        rule: rule(Label::Public, Label::Internal),
        discovery_method: FlowDiscoveryMethod::DynamicAblation,
        source_location: None,
        sink_location: None,
    };
    let dbg = format!("{req:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("FlowRequirement"));
}

#[test]
fn enrichment_flow_requirement_json_field_names() {
    let req = FlowRequirement {
        rule: rule(Label::Public, Label::Internal),
        discovery_method: FlowDiscoveryMethod::RuntimeObservation,
        source_location: Some("src.rs".to_string()),
        sink_location: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"rule\""));
    assert!(json.contains("\"discovery_method\""));
    assert!(json.contains("\"source_location\""));
    assert!(json.contains("\"sink_location\""));
}

// ===========================================================================
// FlowProofObligation — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_flow_proof_obligation_clone_independence() {
    let mut a = FlowProofObligation {
        rule: rule(Label::Public, Label::Internal),
        required_method: FlowProofMethod::StaticAnalysis,
        justification: "needed".to_string(),
        proof_artifact_hash: None,
    };
    let b = a.clone();
    a.justification = "changed".to_string();
    assert_ne!(a.justification, b.justification);
}

#[test]
fn enrichment_flow_proof_obligation_debug_nonempty() {
    let obl = FlowProofObligation {
        rule: rule(Label::Internal, Label::Confidential),
        required_method: FlowProofMethod::Declassification,
        justification: "test".to_string(),
        proof_artifact_hash: Some(ContentHash::compute(b"proof")),
    };
    let dbg = format!("{obl:?}");
    assert!(dbg.contains("FlowProofObligation"));
}

#[test]
fn enrichment_flow_proof_obligation_json_field_names() {
    let obl = FlowProofObligation {
        rule: rule(Label::Public, Label::Internal),
        required_method: FlowProofMethod::OperatorAttestation,
        justification: "j".to_string(),
        proof_artifact_hash: None,
    };
    let json = serde_json::to_string(&obl).unwrap();
    assert!(json.contains("\"rule\""));
    assert!(json.contains("\"required_method\""));
    assert!(json.contains("\"justification\""));
    assert!(json.contains("\"proof_artifact_hash\""));
}

// ===========================================================================
// FlowConfidenceInterval — Copy, Clone, Debug, JSON fields
// ===========================================================================

#[test]
fn enrichment_confidence_interval_copy_semantics() {
    let a = FlowConfidenceInterval {
        lower_millionths: 900_000,
        upper_millionths: 1_000_000,
        n_trials: 10,
        n_essential: 9,
    };
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_confidence_interval_debug_nonempty() {
    let ci = FlowConfidenceInterval {
        lower_millionths: 500_000,
        upper_millionths: 750_000,
        n_trials: 5,
        n_essential: 3,
    };
    let dbg = format!("{ci:?}");
    assert!(dbg.contains("FlowConfidenceInterval"));
    assert!(dbg.contains("500000"));
}

#[test]
fn enrichment_confidence_interval_json_field_names() {
    let ci = FlowConfidenceInterval {
        lower_millionths: 100_000,
        upper_millionths: 200_000,
        n_trials: 2,
        n_essential: 1,
    };
    let json = serde_json::to_string(&ci).unwrap();
    assert!(json.contains("\"lower_millionths\""));
    assert!(json.contains("\"upper_millionths\""));
    assert!(json.contains("\"n_trials\""));
    assert!(json.contains("\"n_essential\""));
}

#[test]
fn enrichment_confidence_interval_clone_independence() {
    let a = FlowConfidenceInterval {
        lower_millionths: 400_000,
        upper_millionths: 800_000,
        n_trials: 20,
        n_essential: 15,
    };
    let mut b = a;
    b.n_trials = 99;
    assert_ne!(a.n_trials, b.n_trials);
}

// ===========================================================================
// SynthesisPassResult — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_synthesis_pass_result_clone_independence() {
    let mut a = SynthesisPassResult {
        pass: SynthesisPass::StaticFlowAnalysis,
        required_flows: BTreeSet::new(),
        removable_flows: BTreeSet::new(),
        time_consumed_ns: 100,
        completed: true,
    };
    let b = a.clone();
    a.time_consumed_ns = 999;
    assert_ne!(a.time_consumed_ns, b.time_consumed_ns);
}

#[test]
fn enrichment_synthesis_pass_result_debug_nonempty() {
    let spr = SynthesisPassResult {
        pass: SynthesisPass::DynamicFlowAblation,
        required_flows: BTreeSet::new(),
        removable_flows: BTreeSet::new(),
        time_consumed_ns: 0,
        completed: false,
    };
    let dbg = format!("{spr:?}");
    assert!(dbg.contains("SynthesisPassResult"));
}

#[test]
fn enrichment_synthesis_pass_result_json_field_names() {
    let spr = SynthesisPassResult {
        pass: SynthesisPass::StaticFlowAnalysis,
        required_flows: BTreeSet::new(),
        removable_flows: BTreeSet::new(),
        time_consumed_ns: 42,
        completed: true,
    };
    let json = serde_json::to_string(&spr).unwrap();
    assert!(json.contains("\"pass\""));
    assert!(json.contains("\"required_flows\""));
    assert!(json.contains("\"removable_flows\""));
    assert!(json.contains("\"time_consumed_ns\""));
    assert!(json.contains("\"completed\""));
}

// ===========================================================================
// EnvelopeError — Clone, BTreeSet-like dedup, Debug/Display unique, error_code
// ===========================================================================

#[test]
fn enrichment_envelope_error_clone_independence() {
    let a = EnvelopeError::OverlappingFlows { overlap_count: 5 };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_envelope_error_debug_all_unique() {
    let variants: Vec<EnvelopeError> = vec![
        EnvelopeError::EmptyExtensionId,
        EnvelopeError::EmptyUpperBound,
        EnvelopeError::OverlappingFlows { overlap_count: 2 },
        EnvelopeError::MissingProofObligation {
            rule: rule(Label::Public, Label::Internal),
        },
        EnvelopeError::IdDerivation("test".to_string()),
        EnvelopeError::SignatureError("test".to_string()),
        EnvelopeError::BudgetExhausted {
            phase: "dyn".to_string(),
        },
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strs.len(), 7);
}

#[test]
fn enrichment_envelope_error_display_all_unique() {
    let variants: Vec<EnvelopeError> = vec![
        EnvelopeError::EmptyExtensionId,
        EnvelopeError::EmptyUpperBound,
        EnvelopeError::OverlappingFlows { overlap_count: 2 },
        EnvelopeError::MissingProofObligation {
            rule: rule(Label::Public, Label::Internal),
        },
        EnvelopeError::IdDerivation("test".to_string()),
        EnvelopeError::SignatureError("test".to_string()),
        EnvelopeError::BudgetExhausted {
            phase: "dyn".to_string(),
        },
    ];
    let strs: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(strs.len(), 7);
}

#[test]
fn enrichment_envelope_error_display_contains_details() {
    let err = EnvelopeError::OverlappingFlows { overlap_count: 3 };
    assert!(format!("{err}").contains("3"));

    let err2 = EnvelopeError::BudgetExhausted {
        phase: "dynamic".to_string(),
    };
    assert!(format!("{err2}").contains("dynamic"));
}

#[test]
fn enrichment_envelope_error_error_code_all_7_unique() {
    let variants: Vec<EnvelopeError> = vec![
        EnvelopeError::EmptyExtensionId,
        EnvelopeError::EmptyUpperBound,
        EnvelopeError::OverlappingFlows { overlap_count: 1 },
        EnvelopeError::MissingProofObligation {
            rule: rule(Label::Public, Label::Internal),
        },
        EnvelopeError::IdDerivation("x".to_string()),
        EnvelopeError::SignatureError("y".to_string()),
        EnvelopeError::BudgetExhausted {
            phase: "z".to_string(),
        },
    ];
    let codes: BTreeSet<&str> = variants.iter().map(|v| error_code(v)).collect();
    assert_eq!(codes.len(), 7);
}

#[test]
fn enrichment_envelope_error_serde_all_7() {
    let variants: Vec<EnvelopeError> = vec![
        EnvelopeError::EmptyExtensionId,
        EnvelopeError::EmptyUpperBound,
        EnvelopeError::OverlappingFlows { overlap_count: 1 },
        EnvelopeError::MissingProofObligation {
            rule: rule(Label::Public, Label::Internal),
        },
        EnvelopeError::IdDerivation("x".to_string()),
        EnvelopeError::SignatureError("y".to_string()),
        EnvelopeError::BudgetExhausted {
            phase: "z".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: EnvelopeError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ===========================================================================
// FlowEnvelope — Clone independence, Debug, JSON fields, content address
// ===========================================================================

#[test]
fn enrichment_flow_envelope_clone_independence() {
    let env = build_envelope("ext-a");
    let mut cloned = env.clone();
    cloned.timestamp_ns = 999_999;
    assert_ne!(env.timestamp_ns, cloned.timestamp_ns);
}

#[test]
fn enrichment_flow_envelope_debug_nonempty() {
    let env = build_envelope("ext-b");
    let dbg = format!("{env:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("FlowEnvelope"));
}

#[test]
fn enrichment_flow_envelope_json_field_names() {
    let env = build_envelope("ext-c");
    let json = serde_json::to_string(&env).unwrap();
    for field in &[
        "envelope_id",
        "extension_id",
        "required_flows",
        "denied_flows",
        "proof_obligations",
        "confidence",
        "pass_results",
        "validity_epoch",
        "policy_id",
        "is_fallback",
        "fallback_quality",
        "timestamp_ns",
        "signature",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing field: {field}"
        );
    }
}

#[test]
fn enrichment_flow_envelope_serde_roundtrip() {
    let env = build_envelope("ext-d");
    let json = serde_json::to_string(&env).unwrap();
    let back: FlowEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, back);
}

#[test]
fn enrichment_flow_envelope_content_address_stable() {
    let env1 = build_envelope("ext-e");
    let env2 = build_envelope("ext-e");
    assert_eq!(env1.envelope_id, env2.envelope_id);
}

#[test]
fn enrichment_flow_envelope_different_ext_different_id() {
    let env1 = build_envelope("ext-f");
    let env2 = build_envelope("ext-g");
    assert_ne!(env1.envelope_id, env2.envelope_id);
}

#[test]
fn enrichment_flow_envelope_verify_content_address() {
    let env = build_envelope("ext-h");
    assert!(env.verify_content_address());
}

#[test]
fn enrichment_flow_envelope_allows_required_flows() {
    let env = build_envelope("ext-i");
    for r in &env.required_flows {
        assert!(env.allows_flow(r));
    }
}

#[test]
fn enrichment_flow_envelope_out_of_envelope_for_unknown() {
    let env = build_envelope("ext-j");
    let unknown = rule(Label::TopSecret, Label::Public);
    assert!(env.is_out_of_envelope(&unknown));
}

#[test]
fn enrichment_flow_envelope_source_labels_subset_of_required() {
    let env = build_envelope("ext-k");
    let sources = env.source_labels();
    for r in &env.required_flows {
        assert!(sources.contains(&r.source_label));
    }
}

#[test]
fn enrichment_flow_envelope_sink_clearances_subset_of_required() {
    let env = build_envelope("ext-l");
    let sinks = env.sink_clearances();
    for r in &env.required_flows {
        assert!(sinks.contains(&r.sink_clearance));
    }
}

#[test]
fn enrichment_flow_envelope_valid_at_construction_epoch() {
    let env = build_envelope("ext-m");
    assert!(env.is_valid_at_epoch(epoch()));
}

#[test]
fn enrichment_flow_envelope_invalid_at_different_epoch() {
    let env = build_envelope("ext-n");
    assert!(!env.is_valid_at_epoch(SecurityEpoch::from_raw(999)));
}

// ===========================================================================
// EnvelopeInput — Clone, Debug
// ===========================================================================

#[test]
fn enrichment_envelope_input_clone_independence() {
    let mut a = make_input("ext-1");
    let b = a.clone();
    a.extension_id = "changed".to_string();
    assert_ne!(a.extension_id, b.extension_id);
}

#[test]
fn enrichment_envelope_input_debug_nonempty() {
    let inp = make_input("ext-2");
    let dbg = format!("{inp:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("EnvelopeInput"));
}

// ===========================================================================
// EnvelopeEvent — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_envelope_event_clone_independence() {
    let mut a = EnvelopeEvent {
        trace_id: "t1".to_string(),
        component: "flow_envelope".to_string(),
        event: "start".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        extension_id: Some("ext".to_string()),
        flow_count: Some(3),
    };
    let b = a.clone();
    a.outcome = "fail".to_string();
    assert_ne!(a.outcome, b.outcome);
}

#[test]
fn enrichment_envelope_event_debug_nonempty() {
    let ev = EnvelopeEvent {
        trace_id: "t2".to_string(),
        component: "flow_envelope".to_string(),
        event: "test".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        extension_id: None,
        flow_count: None,
    };
    let dbg = format!("{ev:?}");
    assert!(dbg.contains("EnvelopeEvent"));
}

#[test]
fn enrichment_envelope_event_json_field_names() {
    let ev = EnvelopeEvent {
        trace_id: "t3".to_string(),
        component: "flow_envelope".to_string(),
        event: "ev".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("E001".to_string()),
        extension_id: Some("ext".to_string()),
        flow_count: Some(5),
    };
    let json = serde_json::to_string(&ev).unwrap();
    for field in &[
        "trace_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "extension_id",
        "flow_count",
    ] {
        assert!(json.contains(&format!("\"{field}\"")), "missing: {field}");
    }
}

// ===========================================================================
// FlowEnvelopeRef — Clone, Debug, JSON fields, serde
// ===========================================================================

#[test]
fn enrichment_flow_envelope_ref_clone_independence() {
    let a = FlowEnvelopeRef {
        envelope_id: build_envelope("ref-a").envelope_id,
        envelope_hash: ContentHash::compute(b"ref"),
        envelope_epoch: epoch(),
    };
    let mut b = a.clone();
    b.envelope_epoch = SecurityEpoch::from_raw(99);
    assert_ne!(a.envelope_epoch, b.envelope_epoch);
}

#[test]
fn enrichment_flow_envelope_ref_debug_nonempty() {
    let r = FlowEnvelopeRef {
        envelope_id: build_envelope("ref-b").envelope_id,
        envelope_hash: ContentHash::compute(b"ref2"),
        envelope_epoch: epoch(),
    };
    let dbg = format!("{r:?}");
    assert!(dbg.contains("FlowEnvelopeRef"));
}

#[test]
fn enrichment_flow_envelope_ref_json_field_names() {
    let r = FlowEnvelopeRef {
        envelope_id: build_envelope("ref-c").envelope_id,
        envelope_hash: ContentHash::compute(b"ref3"),
        envelope_epoch: epoch(),
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"envelope_id\""));
    assert!(json.contains("\"envelope_hash\""));
    assert!(json.contains("\"envelope_epoch\""));
}

// ===========================================================================
// FlowEnvelopeSynthesizer — Clone, Debug, serde, JSON fields
// ===========================================================================

#[test]
fn enrichment_synthesizer_clone_independence() {
    let mut a = FlowEnvelopeSynthesizer::new("ext-s1", 1_000_000, epoch());
    let b = a.clone();
    a.time_budget_ns = 0;
    assert_ne!(a.time_budget_ns, b.time_budget_ns);
}

#[test]
fn enrichment_synthesizer_debug_nonempty() {
    let s = FlowEnvelopeSynthesizer::new("ext-s2", 500_000, epoch());
    let dbg = format!("{s:?}");
    assert!(dbg.contains("FlowEnvelopeSynthesizer"));
}

#[test]
fn enrichment_synthesizer_json_field_names() {
    let s = FlowEnvelopeSynthesizer::new("ext-s3", 999, epoch());
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"extension_id\""));
    assert!(json.contains("\"time_budget_ns\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"events\""));
}

#[test]
fn enrichment_synthesizer_new_has_empty_events() {
    let s = FlowEnvelopeSynthesizer::new("ext-s4", 1_000, epoch());
    assert!(s.events.is_empty());
}

// ===========================================================================
// Synthesizer — static_pass properties
// ===========================================================================

#[test]
fn enrichment_synthesizer_static_pass_partitions_flows() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-sp", 1_000_000, epoch());
    let ub = upper_bound_3();
    let result = syn.static_pass(&ub, "t1");
    // required + removable should equal the upper bound
    let mut all = result.required_flows.clone();
    all.extend(result.removable_flows.iter().cloned());
    assert_eq!(all, ub);
    // no overlap
    let overlap: BTreeSet<_> = result
        .required_flows
        .intersection(&result.removable_flows)
        .collect();
    assert!(overlap.is_empty());
}

#[test]
fn enrichment_synthesizer_static_pass_completed() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-sp2", 1_000_000, epoch());
    let ub = upper_bound_3();
    let result = syn.static_pass(&ub, "t2");
    assert!(result.completed);
    assert_eq!(result.pass, SynthesisPass::StaticFlowAnalysis);
}

#[test]
fn enrichment_synthesizer_static_pass_safe_flows_required() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-sp3", 1_000_000, epoch());
    // Public -> Internal is safe (level 0 -> 1)
    let mut ub = BTreeSet::new();
    ub.insert(rule(Label::Public, Label::Internal));
    let result = syn.static_pass(&ub, "t3");
    assert!(
        result
            .required_flows
            .contains(&rule(Label::Public, Label::Internal))
    );
    assert!(result.removable_flows.is_empty());
}

#[test]
fn enrichment_synthesizer_static_pass_unsafe_flows_removable() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-sp4", 1_000_000, epoch());
    // Confidential -> Public is unsafe (level 2 -> 0)
    let mut ub = BTreeSet::new();
    ub.insert(rule(Label::Confidential, Label::Public));
    let result = syn.static_pass(&ub, "t4");
    assert!(
        result
            .removable_flows
            .contains(&rule(Label::Confidential, Label::Public))
    );
    assert!(result.required_flows.is_empty());
}

// ===========================================================================
// Synthesizer — dynamic_pass properties
// ===========================================================================

#[test]
fn enrichment_synthesizer_dynamic_pass_promotes_essential() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-dp", 1_000_000, epoch());
    let ub = upper_bound_3();
    let static_result = syn.static_pass(&ub, "t1");
    // Oracle: all removable flows are essential (removing breaks extension)
    let dynamic_result = syn.dynamic_pass(&static_result, &|_| true, "t2");
    assert!(dynamic_result.removable_flows.is_empty());
    // All flows should now be required
    assert_eq!(dynamic_result.required_flows, ub);
}

#[test]
fn enrichment_synthesizer_dynamic_pass_keeps_non_essential_removable() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-dp2", 1_000_000, epoch());
    let ub = upper_bound_3();
    let static_result = syn.static_pass(&ub, "t1");
    // Oracle: no removable flows are essential
    let dynamic_result = syn.dynamic_pass(&static_result, &|_| false, "t2");
    assert_eq!(
        dynamic_result.removable_flows,
        static_result.removable_flows
    );
}

// ===========================================================================
// Synthesizer — full synthesis cross-cutting properties
// ===========================================================================

#[test]
fn enrichment_synthesizer_full_synthesis_required_union_denied_covers_upper_bound() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-fc", 1_000_000, epoch());
    let ub = upper_bound_3();
    let env = syn
        .synthesize(&ub, &|_| true, "policy", 1000, "t1")
        .unwrap();
    let mut union = env.required_flows.clone();
    union.extend(env.denied_flows.iter().cloned());
    assert_eq!(union, ub);
}

#[test]
fn enrichment_synthesizer_proof_obligations_per_required_flow() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-po", 1_000_000, epoch());
    let ub = upper_bound_3();
    let env = syn
        .synthesize(&ub, &|_| true, "policy", 1000, "t1")
        .unwrap();
    // Every required flow should have a proof obligation
    let obligation_rules: BTreeSet<_> = env.proof_obligations.iter().map(|o| &o.rule).collect();
    for r in &env.required_flows {
        assert!(obligation_rules.contains(r));
    }
}

#[test]
fn enrichment_synthesizer_events_count_for_full_synthesis() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-ev", 1_000_000, epoch());
    let ub = upper_bound_3();
    let _env = syn
        .synthesize(&ub, &|_| true, "policy", 1000, "t1")
        .unwrap();
    // Should have events: synthesis_start, static_pass_start, static_pass_complete,
    // dynamic_pass_start, dynamic_pass_complete, synthesis_complete
    assert!(syn.events.len() >= 6);
}

#[test]
fn enrichment_synthesizer_all_events_have_component_flow_envelope() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-comp", 1_000_000, epoch());
    let ub = upper_bound_3();
    let _env = syn
        .synthesize(&ub, &|_| true, "policy", 1000, "t1")
        .unwrap();
    for ev in &syn.events {
        assert_eq!(ev.component, "flow_envelope");
    }
}

#[test]
fn enrichment_synthesizer_all_events_preserve_trace_id() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-tid", 1_000_000, epoch());
    let ub = upper_bound_3();
    let _env = syn
        .synthesize(&ub, &|_| true, "policy", 1000, "my-trace-42")
        .unwrap();
    for ev in &syn.events {
        assert_eq!(ev.trace_id, "my-trace-42");
    }
}

// ===========================================================================
// Synthesizer — fallback properties
// ===========================================================================

#[test]
fn enrichment_synthesizer_fallback_is_fallback_true() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-fb", 1_000_000, epoch());
    let ub = upper_bound_3();
    let env = syn
        .synthesize_fallback(&ub, "policy", 1000, FallbackQuality::StaticBound, "t1")
        .unwrap();
    assert!(env.is_fallback);
    assert_eq!(env.fallback_quality, Some(FallbackQuality::StaticBound));
}

#[test]
fn enrichment_synthesizer_fallback_confidence_zero_trials() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-fb2", 1_000_000, epoch());
    let ub = upper_bound_3();
    let env = syn
        .synthesize_fallback(&ub, "policy", 1000, FallbackQuality::PartialAblation, "t1")
        .unwrap();
    assert_eq!(env.confidence.n_trials, 0);
    assert_eq!(env.confidence.n_essential, 0);
}

#[test]
fn enrichment_synthesizer_non_fallback_is_fallback_false() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-nf", 1_000_000, epoch());
    let ub = upper_bound_3();
    let env = syn
        .synthesize(&ub, &|_| true, "policy", 1000, "t1")
        .unwrap();
    assert!(!env.is_fallback);
    assert_eq!(env.fallback_quality, None);
}

// ===========================================================================
// 5-run determinism
// ===========================================================================

#[test]
fn enrichment_five_run_determinism_envelope_id() {
    let ids: Vec<_> = (0..5)
        .map(|_| build_envelope("det-1").envelope_id)
        .collect();
    for id in &ids {
        assert_eq!(*id, ids[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_serde_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let env = build_envelope("det-2");
            let json = serde_json::to_string(&env).unwrap();
            ContentHash::compute(json.as_bytes())
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_synthesizer() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let mut syn = FlowEnvelopeSynthesizer::new("det-3", 1_000_000, epoch());
            let ub = upper_bound_3();
            let env = syn
                .synthesize(&ub, &|_| true, "policy", 1000, "t1")
                .unwrap();
            let json = serde_json::to_string(&env).unwrap();
            ContentHash::compute(json.as_bytes())
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

#[test]
fn enrichment_five_run_determinism_fallback() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let mut syn = FlowEnvelopeSynthesizer::new("det-4", 1_000_000, epoch());
            let ub = upper_bound_3();
            let env = syn
                .synthesize_fallback(&ub, "policy", 1000, FallbackQuality::StaticBound, "t1")
                .unwrap();
            let json = serde_json::to_string(&env).unwrap();
            ContentHash::compute(json.as_bytes())
        })
        .collect();
    for h in &hashes {
        assert_eq!(*h, hashes[0]);
    }
}

// ===========================================================================
// Envelope build edge cases
// ===========================================================================

#[test]
fn enrichment_build_rejects_empty_extension_id() {
    let mut input = make_input("");
    input.extension_id = String::new();
    let result = FlowEnvelope::build(input);
    assert!(result.is_err());
    assert_eq!(
        error_code(&result.unwrap_err()),
        "ENVELOPE_EMPTY_EXTENSION_ID"
    );
}

#[test]
fn enrichment_build_rejects_empty_static_and_ablation() {
    let mut input = make_input("ext");
    input.static_upper_bound = BTreeSet::new();
    input.ablation_required = BTreeSet::new();
    let result = FlowEnvelope::build(input);
    assert!(result.is_err());
    assert_eq!(
        error_code(&result.unwrap_err()),
        "ENVELOPE_EMPTY_UPPER_BOUND"
    );
}

#[test]
fn enrichment_build_rejects_overlapping_required_removable() {
    let mut input = make_input("ext");
    let flow = rule(Label::Public, Label::Internal);
    input.ablation_required = BTreeSet::from([flow.clone()]);
    input.ablation_removable = BTreeSet::from([flow]);
    let result = FlowEnvelope::build(input);
    assert!(result.is_err());
    assert_eq!(
        error_code(&result.unwrap_err()),
        "ENVELOPE_OVERLAPPING_FLOWS"
    );
}

#[test]
fn enrichment_build_with_static_only_uses_upper_bound() {
    let mut input = make_input("ext-ub");
    let ub = input.static_upper_bound.clone();
    input.ablation_required = BTreeSet::new();
    input.ablation_removable = BTreeSet::new();
    let env = FlowEnvelope::build(input).unwrap();
    assert_eq!(env.required_flows, ub);
    assert!(env.denied_flows.is_empty());
}

// ===========================================================================
// Cross-cutting: unsatisfied obligations count
// ===========================================================================

#[test]
fn enrichment_unsatisfied_obligations_all_unsatisfied() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-uo", 1_000_000, epoch());
    let ub = upper_bound_3();
    let env = syn
        .synthesize(&ub, &|_| true, "policy", 1000, "t1")
        .unwrap();
    // All proof obligations should be unsatisfied (hash is None)
    assert_eq!(env.unsatisfied_obligations(), env.proof_obligations.len());
}

#[test]
fn enrichment_envelope_denied_flows_disjoint_from_required() {
    let mut syn = FlowEnvelopeSynthesizer::new("ext-dj", 1_000_000, epoch());
    let ub = upper_bound_3();
    // Oracle: nothing essential → some flows denied
    let env = syn
        .synthesize(&ub, &|_| false, "policy", 1000, "t1")
        .unwrap();
    let overlap: BTreeSet<_> = env.required_flows.intersection(&env.denied_flows).collect();
    assert!(overlap.is_empty());
}

// ===========================================================================
// Serde roundtrips for types not covered in base integration tests
// ===========================================================================

#[test]
fn enrichment_serde_roundtrip_flow_confidence_interval() {
    let ci = FlowConfidenceInterval {
        lower_millionths: 333_333,
        upper_millionths: 666_666,
        n_trials: 7,
        n_essential: 4,
    };
    let json = serde_json::to_string(&ci).unwrap();
    let back: FlowConfidenceInterval = serde_json::from_str(&json).unwrap();
    assert_eq!(ci, back);
}

#[test]
fn enrichment_serde_roundtrip_synthesis_pass_result() {
    let spr = SynthesisPassResult {
        pass: SynthesisPass::DynamicFlowAblation,
        required_flows: BTreeSet::from([rule(Label::Public, Label::Internal)]),
        removable_flows: BTreeSet::from([rule(Label::Confidential, Label::Public)]),
        time_consumed_ns: 42,
        completed: true,
    };
    let json = serde_json::to_string(&spr).unwrap();
    let back: SynthesisPassResult = serde_json::from_str(&json).unwrap();
    assert_eq!(spr, back);
}

#[test]
fn enrichment_serde_roundtrip_envelope_event() {
    let ev = EnvelopeEvent {
        trace_id: "rt".to_string(),
        component: "flow_envelope".to_string(),
        event: "test".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("E1".to_string()),
        extension_id: Some("ext".to_string()),
        flow_count: Some(10),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: EnvelopeEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn enrichment_serde_roundtrip_flow_envelope_ref() {
    let r = FlowEnvelopeRef {
        envelope_id: build_envelope("serde-ref").envelope_id,
        envelope_hash: ContentHash::compute(b"serde-ref"),
        envelope_epoch: epoch(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: FlowEnvelopeRef = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}
