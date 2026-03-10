//! Integration tests for the kernel synthesis contract module (RGC-613A).

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::kernel_synthesis_contract::{
    EligibilityDecision, EligibilityStatus, ForbiddenReason, KERNEL_SYNTH_COMPONENT,
    KERNEL_SYNTH_POLICY_ID, KERNEL_SYNTH_SCHEMA_VERSION, KernelCorpus, KernelFamily, KernelSchema,
    KernelSynthCertificate, KernelSynthError, KernelSynthEvidenceManifest, MILLIONTHS,
    ProofRequirement, SynthesisBudget, SynthesisEnvelope, build_synthesis_envelope,
    evaluate_eligibility, mine_canonical_kernels, run_kernel_synth_evidence,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn eligible_schema(id: &str) -> KernelSchema {
    KernelSchema {
        id: id.into(),
        family: KernelFamily::ArithmeticLoop,
        pattern_description: "pure arithmetic loop".into(),
        instruction_count: 10,
        hotness_millionths: 900_000,
        purity_score_millionths: 950_000,
        side_effect_free: true,
        deterministic: true,
        bounded_time: true,
        source_hash: ContentHash::compute(id.as_bytes()),
    }
}

fn side_effectful_schema(id: &str) -> KernelSchema {
    KernelSchema {
        side_effect_free: false,
        ..eligible_schema(id)
    }
}

fn nondeterministic_schema(id: &str) -> KernelSchema {
    KernelSchema {
        deterministic: false,
        ..eligible_schema(id)
    }
}

fn unbounded_schema(id: &str) -> KernelSchema {
    KernelSchema {
        bounded_time: false,
        ..eligible_schema(id)
    }
}

fn low_purity_schema(id: &str) -> KernelSchema {
    KernelSchema {
        purity_score_millionths: 500_000,
        ..eligible_schema(id)
    }
}

fn zero_hotness_schema(id: &str) -> KernelSchema {
    KernelSchema {
        hotness_millionths: 0,
        ..eligible_schema(id)
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version_nonempty() {
    assert!(!KERNEL_SYNTH_SCHEMA_VERSION.is_empty());
    assert!(KERNEL_SYNTH_SCHEMA_VERSION.contains("kernel-synthesis-contract"));
}

#[test]
fn integration_component_name() {
    assert_eq!(KERNEL_SYNTH_COMPONENT, "kernel_synthesis_contract");
}

#[test]
fn integration_policy_id() {
    assert_eq!(KERNEL_SYNTH_POLICY_ID, "RGC-613A");
}

#[test]
fn integration_millionths_constant() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// KernelFamily serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_kernel_family_serde_all_variants() {
    let families = [
        KernelFamily::ArithmeticLoop,
        KernelFamily::CollectionIteration,
        KernelFamily::StringProcessing,
        KernelFamily::RegExpMatch,
        KernelFamily::PropertyAccess,
        KernelFamily::TypeGuard,
        KernelFamily::MemoryAllocation,
        KernelFamily::HostcallBatch,
        KernelFamily::ReactRender,
        KernelFamily::ModuleInit,
    ];
    for f in families {
        let json = serde_json::to_string(&f).unwrap();
        let back: KernelFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
}

#[test]
fn integration_kernel_family_display() {
    assert_eq!(KernelFamily::ArithmeticLoop.to_string(), "arithmetic_loop");
    assert_eq!(KernelFamily::ReactRender.to_string(), "react_render");
}

// ---------------------------------------------------------------------------
// EligibilityStatus serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_eligibility_status_serde_all_variants() {
    let statuses = vec![
        EligibilityStatus::Eligible,
        EligibilityStatus::Forbidden,
        EligibilityStatus::Conditional {
            requirements: vec!["need purity".into()],
        },
        EligibilityStatus::Deferred {
            reason: "no data".into(),
        },
    ];
    for s in statuses {
        let json = serde_json::to_string(&s).unwrap();
        let back: EligibilityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

// ---------------------------------------------------------------------------
// ForbiddenReason serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_forbidden_reason_serde_roundtrip() {
    let reasons = [
        ForbiddenReason::SideEffect,
        ForbiddenReason::NonDeterministic,
        ForbiddenReason::UnboundedComplexity,
        ForbiddenReason::SecuritySensitive,
        ForbiddenReason::InsufficientEvidence,
        ForbiddenReason::PolicyRestriction,
    ];
    for r in reasons {
        let json = serde_json::to_string(&r).unwrap();
        let back: ForbiddenReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn integration_forbidden_reason_display() {
    assert_eq!(ForbiddenReason::SideEffect.to_string(), "side_effect");
    assert_eq!(
        ForbiddenReason::NonDeterministic.to_string(),
        "non_deterministic"
    );
}

// ---------------------------------------------------------------------------
// ProofRequirement serde
// ---------------------------------------------------------------------------

#[test]
fn integration_proof_requirement_serde_roundtrip() {
    let reqs = [
        ProofRequirement::None,
        ProofRequirement::BestEffort,
        ProofRequirement::Mandatory,
    ];
    for r in reqs {
        let json = serde_json::to_string(&r).unwrap();
        let back: ProofRequirement = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

// ---------------------------------------------------------------------------
// evaluate_eligibility
// ---------------------------------------------------------------------------

#[test]
fn integration_evaluate_eligible_kernel() {
    let schema = eligible_schema("k1");
    let decision = evaluate_eligibility(&schema);
    assert_eq!(decision.kernel_id, "k1");
    assert_eq!(decision.status, EligibilityStatus::Eligible);
    assert!(decision.forbidden_reasons.is_empty());
    assert_eq!(decision.confidence_millionths, MILLIONTHS);
}

#[test]
fn integration_evaluate_side_effect_forbidden() {
    let decision = evaluate_eligibility(&side_effectful_schema("k2"));
    assert_eq!(decision.status, EligibilityStatus::Forbidden);
    assert!(
        decision
            .forbidden_reasons
            .contains(&ForbiddenReason::SideEffect)
    );
}

#[test]
fn integration_evaluate_nondeterministic_forbidden() {
    let decision = evaluate_eligibility(&nondeterministic_schema("k3"));
    assert_eq!(decision.status, EligibilityStatus::Forbidden);
    assert!(
        decision
            .forbidden_reasons
            .contains(&ForbiddenReason::NonDeterministic)
    );
}

#[test]
fn integration_evaluate_unbounded_forbidden() {
    let decision = evaluate_eligibility(&unbounded_schema("k4"));
    assert_eq!(decision.status, EligibilityStatus::Forbidden);
    assert!(
        decision
            .forbidden_reasons
            .contains(&ForbiddenReason::UnboundedComplexity)
    );
}

#[test]
fn integration_evaluate_low_purity_conditional() {
    let decision = evaluate_eligibility(&low_purity_schema("k5"));
    assert!(matches!(
        decision.status,
        EligibilityStatus::Conditional { .. }
    ));
}

#[test]
fn integration_evaluate_zero_hotness_deferred() {
    let decision = evaluate_eligibility(&zero_hotness_schema("k6"));
    assert!(matches!(
        decision.status,
        EligibilityStatus::Deferred { .. }
    ));
    assert_eq!(decision.confidence_millionths, 0);
    assert_eq!(decision.evidence_count, 0);
}

#[test]
fn integration_evaluate_multiple_forbidden_reasons() {
    let schema = KernelSchema {
        side_effect_free: false,
        deterministic: false,
        bounded_time: false,
        ..eligible_schema("k7")
    };
    let decision = evaluate_eligibility(&schema);
    assert_eq!(decision.status, EligibilityStatus::Forbidden);
    assert!(decision.forbidden_reasons.len() >= 3);
}

// ---------------------------------------------------------------------------
// build_synthesis_envelope
// ---------------------------------------------------------------------------

#[test]
fn integration_envelope_categorizes_correctly() {
    let schemas = vec![
        eligible_schema("e1"),
        side_effectful_schema("e2"),
        zero_hotness_schema("e3"),
        low_purity_schema("e4"),
    ];
    let envelope = build_synthesis_envelope(&schemas);
    assert!(!envelope.eligible.is_empty());
    assert!(!envelope.forbidden.is_empty());
    assert!(!envelope.deferred.is_empty()); // zero_hotness + low_purity -> deferred
}

#[test]
fn integration_envelope_hash_determinism() {
    let schemas = vec![eligible_schema("h1"), side_effectful_schema("h2")];
    let e1 = build_synthesis_envelope(&schemas);
    let e2 = build_synthesis_envelope(&schemas);
    assert_eq!(e1.envelope_hash, e2.envelope_hash);
}

#[test]
fn integration_envelope_serde_roundtrip() {
    let schemas = vec![eligible_schema("s1")];
    let envelope = build_synthesis_envelope(&schemas);
    let json = serde_json::to_string(&envelope).unwrap();
    let back: SynthesisEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope, back);
}

// ---------------------------------------------------------------------------
// mine_canonical_kernels
// ---------------------------------------------------------------------------

#[test]
fn integration_canonical_corpus_has_schemas() {
    let corpus = mine_canonical_kernels();
    assert!(corpus.schemas.len() >= 10);
    assert_eq!(corpus.schemas.len(), corpus.decisions.len());
}

#[test]
fn integration_canonical_corpus_hash_determinism() {
    let c1 = mine_canonical_kernels();
    let c2 = mine_canonical_kernels();
    assert_eq!(c1.corpus_hash, c2.corpus_hash);
}

#[test]
fn integration_canonical_corpus_serde_roundtrip() {
    let corpus = mine_canonical_kernels();
    let json = serde_json::to_string(&corpus).unwrap();
    let back: KernelCorpus = serde_json::from_str(&json).unwrap();
    assert_eq!(corpus, back);
}

#[test]
fn integration_canonical_corpus_has_mixed_verdicts() {
    let corpus = mine_canonical_kernels();
    let eligible_count = corpus
        .decisions
        .iter()
        .filter(|d| d.status == EligibilityStatus::Eligible)
        .count();
    let forbidden_count = corpus
        .decisions
        .iter()
        .filter(|d| d.status == EligibilityStatus::Forbidden)
        .count();
    assert!(
        eligible_count > 0,
        "should have at least one eligible kernel"
    );
    assert!(
        forbidden_count > 0,
        "should have at least one forbidden kernel"
    );
}

// ---------------------------------------------------------------------------
// KernelSynthError serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_error_serde_roundtrip() {
    let errors = vec![
        KernelSynthError::EmptyCorpus,
        KernelSynthError::DuplicateKernel { id: "dup".into() },
        KernelSynthError::InvalidBudget {
            reason: "negative".into(),
        },
        KernelSynthError::InvalidSchema {
            reason: "empty id".into(),
        },
    ];
    for e in errors {
        let json = serde_json::to_string(&e).unwrap();
        let back: KernelSynthError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

#[test]
fn integration_error_display() {
    assert!(
        KernelSynthError::EmptyCorpus
            .to_string()
            .contains("empty corpus")
    );
    let dk = KernelSynthError::DuplicateKernel { id: "dup".into() };
    assert!(dk.to_string().contains("dup"));
}

// ---------------------------------------------------------------------------
// SynthesisBudget serde
// ---------------------------------------------------------------------------

#[test]
fn integration_synthesis_budget_serde_roundtrip() {
    let budget = SynthesisBudget {
        max_kernels: 32,
        max_instruction_expansion: 4,
        time_budget_millionths: 5_000_000,
        proof_requirement: ProofRequirement::BestEffort,
    };
    let json = serde_json::to_string(&budget).unwrap();
    let back: SynthesisBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, back);
}

// ---------------------------------------------------------------------------
// Evidence manifest
// ---------------------------------------------------------------------------

#[test]
fn integration_run_evidence_produces_manifest() {
    let manifest = run_kernel_synth_evidence();
    assert_eq!(manifest.schema_version, KERNEL_SYNTH_SCHEMA_VERSION);
    assert!(manifest.kernels_evaluated >= 10);
    assert!(manifest.error.is_none());
    assert!(!manifest.certificates.is_empty());
}

#[test]
fn integration_evidence_hash_determinism() {
    let m1 = run_kernel_synth_evidence();
    let m2 = run_kernel_synth_evidence();
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn integration_evidence_serde_roundtrip() {
    let manifest = run_kernel_synth_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: KernelSynthEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn integration_evidence_certificates_have_schema_version() {
    let manifest = run_kernel_synth_evidence();
    for cert in &manifest.certificates {
        assert_eq!(cert.schema_version, KERNEL_SYNTH_SCHEMA_VERSION);
    }
}

#[test]
fn integration_evidence_counts_add_up() {
    let m = run_kernel_synth_evidence();
    assert_eq!(
        m.eligible_count + m.forbidden_count + m.deferred_count,
        m.kernels_evaluated
    );
}

// ---------------------------------------------------------------------------
// KernelSchema serde
// ---------------------------------------------------------------------------

#[test]
fn integration_kernel_schema_serde_roundtrip() {
    let schema = eligible_schema("roundtrip");
    let json = serde_json::to_string(&schema).unwrap();
    let back: KernelSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, back);
}

// ---------------------------------------------------------------------------
// EligibilityDecision serde
// ---------------------------------------------------------------------------

#[test]
fn integration_eligibility_decision_serde_roundtrip() {
    let decision = evaluate_eligibility(&eligible_schema("serde-test"));
    let json = serde_json::to_string(&decision).unwrap();
    let back: EligibilityDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

// ---------------------------------------------------------------------------
// KernelSynthCertificate serde
// ---------------------------------------------------------------------------

#[test]
fn integration_certificate_serde_roundtrip() {
    let manifest = run_kernel_synth_evidence();
    let cert = &manifest.certificates[0];
    let json = serde_json::to_string(cert).unwrap();
    let back: KernelSynthCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(*cert, back);
}
