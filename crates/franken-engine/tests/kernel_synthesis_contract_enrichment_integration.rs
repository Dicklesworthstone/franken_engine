//! Enrichment integration tests for `kernel_synthesis_contract`.
//!
//! Covers Copy/Clone semantics, BTreeSet dedup, Debug/Display uniqueness,
//! serde JSON field stability, Clone independence, determinism, and
//! cross-cutting invariants NOT already tested in the base integration file.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::kernel_synthesis_contract::{
    EligibilityStatus, ForbiddenReason, KERNEL_SYNTH_COMPONENT, KERNEL_SYNTH_POLICY_ID,
    KERNEL_SYNTH_SCHEMA_VERSION, KernelFamily, KernelSchema, KernelSynthError,
    KernelSynthEvidenceManifest, MILLIONTHS, ProofRequirement, SynthesisBudget,
    build_synthesis_envelope, evaluate_eligibility, mine_canonical_kernels,
    run_kernel_synth_evidence, validate_schemas,
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

fn forbidden_schema(id: &str) -> KernelSchema {
    KernelSchema {
        side_effect_free: false,
        deterministic: false,
        bounded_time: false,
        ..eligible_schema(id)
    }
}

fn zero_hotness_schema(id: &str) -> KernelSchema {
    KernelSchema {
        hotness_millionths: 0,
        ..eligible_schema(id)
    }
}

fn low_purity_schema(id: &str) -> KernelSchema {
    KernelSchema {
        purity_score_millionths: 500_000,
        ..eligible_schema(id)
    }
}

// ===========================================================================
// KernelFamily enrichment
// ===========================================================================

#[test]
fn enrichment_family_copy_semantics() {
    let a = KernelFamily::ReactRender;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(format!("{a}"), "react_render");
}

#[test]
fn enrichment_family_btreeset_dedup() {
    let all = [
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
    let mut set = BTreeSet::new();
    for &f in &all {
        set.insert(f);
        set.insert(f);
    }
    assert_eq!(set.len(), 10);
}

#[test]
fn enrichment_family_debug_all_unique() {
    let all = [
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
    let debugs: BTreeSet<String> = all.iter().map(|f| format!("{f:?}")).collect();
    assert_eq!(debugs.len(), 10);
}

#[test]
fn enrichment_family_display_all_unique() {
    let all = [
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
    let displays: BTreeSet<String> = all.iter().map(|f| format!("{f}")).collect();
    assert_eq!(displays.len(), 10);
}

// ===========================================================================
// ForbiddenReason enrichment
// ===========================================================================

#[test]
fn enrichment_forbidden_copy_semantics() {
    let a = ForbiddenReason::SecuritySensitive;
    let b = a;
    assert_eq!(a, b);
    assert_eq!(format!("{a}"), "security_sensitive");
}

#[test]
fn enrichment_forbidden_btreeset_dedup() {
    let all = [
        ForbiddenReason::SideEffect,
        ForbiddenReason::NonDeterministic,
        ForbiddenReason::UnboundedComplexity,
        ForbiddenReason::SecuritySensitive,
        ForbiddenReason::InsufficientEvidence,
        ForbiddenReason::PolicyRestriction,
    ];
    let mut set = BTreeSet::new();
    for &r in &all {
        set.insert(r);
        set.insert(r);
    }
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_forbidden_debug_all_unique() {
    let all = [
        ForbiddenReason::SideEffect,
        ForbiddenReason::NonDeterministic,
        ForbiddenReason::UnboundedComplexity,
        ForbiddenReason::SecuritySensitive,
        ForbiddenReason::InsufficientEvidence,
        ForbiddenReason::PolicyRestriction,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|r| format!("{r:?}")).collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_forbidden_display_all_unique() {
    let all = [
        ForbiddenReason::SideEffect,
        ForbiddenReason::NonDeterministic,
        ForbiddenReason::UnboundedComplexity,
        ForbiddenReason::SecuritySensitive,
        ForbiddenReason::InsufficientEvidence,
        ForbiddenReason::PolicyRestriction,
    ];
    let displays: BTreeSet<String> = all.iter().map(|r| format!("{r}")).collect();
    assert_eq!(displays.len(), 6);
}

// ===========================================================================
// ProofRequirement enrichment
// ===========================================================================

#[test]
fn enrichment_proof_copy_semantics() {
    let a = ProofRequirement::Mandatory;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_proof_btreeset_dedup() {
    let all = [
        ProofRequirement::None,
        ProofRequirement::BestEffort,
        ProofRequirement::Mandatory,
    ];
    let mut set = BTreeSet::new();
    for &p in &all {
        set.insert(p);
        set.insert(p);
    }
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_proof_debug_all_unique() {
    let all = [
        ProofRequirement::None,
        ProofRequirement::BestEffort,
        ProofRequirement::Mandatory,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|p| format!("{p:?}")).collect();
    assert_eq!(debugs.len(), 3);
}

// ===========================================================================
// EligibilityStatus enrichment
// ===========================================================================

#[test]
fn enrichment_status_clone_independence() {
    let original = EligibilityStatus::Conditional {
        requirements: vec!["purity >= 80%".into()],
    };
    let mut cloned = original.clone();
    if let EligibilityStatus::Conditional {
        ref mut requirements,
    } = cloned
    {
        requirements.push("extra".into());
    }
    if let EligibilityStatus::Conditional { requirements } = &original {
        assert_eq!(requirements.len(), 1);
    }
}

#[test]
fn enrichment_status_debug_all_unique() {
    let statuses = vec![
        EligibilityStatus::Eligible,
        EligibilityStatus::Forbidden,
        EligibilityStatus::Conditional {
            requirements: vec!["x".into()],
        },
        EligibilityStatus::Deferred { reason: "y".into() },
    ];
    let debugs: BTreeSet<String> = statuses.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

// ===========================================================================
// KernelSchema enrichment
// ===========================================================================

#[test]
fn enrichment_schema_clone_independence() {
    let original = eligible_schema("s1");
    let mut cloned = original.clone();
    cloned.id = "s2".to_string();
    assert_eq!(original.id, "s1");
    assert_eq!(cloned.id, "s2");
}

#[test]
fn enrichment_schema_json_field_names() {
    let s = eligible_schema("s1");
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"family\""));
    assert!(json.contains("\"pattern_description\""));
    assert!(json.contains("\"instruction_count\""));
    assert!(json.contains("\"hotness_millionths\""));
    assert!(json.contains("\"purity_score_millionths\""));
    assert!(json.contains("\"side_effect_free\""));
    assert!(json.contains("\"deterministic\""));
    assert!(json.contains("\"bounded_time\""));
    assert!(json.contains("\"source_hash\""));
}

#[test]
fn enrichment_schema_debug_nonempty() {
    let s = eligible_schema("s1");
    let dbg = format!("{s:?}");
    assert!(dbg.contains("KernelSchema"));
}

// ===========================================================================
// EligibilityDecision enrichment
// ===========================================================================

#[test]
fn enrichment_decision_clone_independence() {
    let original = evaluate_eligibility(&eligible_schema("d1"));
    let mut cloned = original.clone();
    cloned.kernel_id = "mutated".to_string();
    assert_eq!(original.kernel_id, "d1");
    assert_eq!(cloned.kernel_id, "mutated");
}

#[test]
fn enrichment_decision_json_field_names() {
    let d = evaluate_eligibility(&eligible_schema("d1"));
    let json = serde_json::to_string(&d).unwrap();
    assert!(json.contains("\"kernel_id\""));
    assert!(json.contains("\"status\""));
    assert!(json.contains("\"forbidden_reasons\""));
    assert!(json.contains("\"confidence_millionths\""));
    assert!(json.contains("\"evidence_count\""));
}

#[test]
fn enrichment_decision_debug_nonempty() {
    let d = evaluate_eligibility(&eligible_schema("d1"));
    let dbg = format!("{d:?}");
    assert!(dbg.contains("EligibilityDecision"));
}

// ===========================================================================
// SynthesisEnvelope enrichment
// ===========================================================================

#[test]
fn enrichment_envelope_clone_independence() {
    let schemas = vec![eligible_schema("e1")];
    let original = build_synthesis_envelope(&schemas);
    let mut cloned = original.clone();
    cloned.eligible.clear();
    assert!(!original.eligible.is_empty());
    assert!(cloned.eligible.is_empty());
}

#[test]
fn enrichment_envelope_json_field_names() {
    let e = build_synthesis_envelope(&[eligible_schema("e1")]);
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"eligible\""));
    assert!(json.contains("\"forbidden\""));
    assert!(json.contains("\"deferred\""));
    assert!(json.contains("\"envelope_hash\""));
}

#[test]
fn enrichment_envelope_debug_nonempty() {
    let e = build_synthesis_envelope(&[]);
    let dbg = format!("{e:?}");
    assert!(dbg.contains("SynthesisEnvelope"));
}

// ===========================================================================
// KernelCorpus enrichment
// ===========================================================================

#[test]
fn enrichment_corpus_clone_independence() {
    let original = mine_canonical_kernels();
    let mut cloned = original.clone();
    cloned.schemas.clear();
    assert!(!original.schemas.is_empty());
    assert!(cloned.schemas.is_empty());
}

#[test]
fn enrichment_corpus_json_field_names() {
    let c = mine_canonical_kernels();
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"schemas\""));
    assert!(json.contains("\"decisions\""));
    assert!(json.contains("\"corpus_hash\""));
}

#[test]
fn enrichment_corpus_debug_nonempty() {
    let c = mine_canonical_kernels();
    let dbg = format!("{c:?}");
    assert!(dbg.contains("KernelCorpus"));
}

// ===========================================================================
// SynthesisBudget enrichment
// ===========================================================================

#[test]
fn enrichment_budget_clone_independence() {
    let original = SynthesisBudget {
        max_kernels: 32,
        max_instruction_expansion: 4,
        time_budget_millionths: 5_000_000,
        proof_requirement: ProofRequirement::BestEffort,
    };
    let mut cloned = original.clone();
    cloned.max_kernels = 99;
    assert_eq!(original.max_kernels, 32);
    assert_eq!(cloned.max_kernels, 99);
}

#[test]
fn enrichment_budget_json_field_names() {
    let b = SynthesisBudget {
        max_kernels: 32,
        max_instruction_expansion: 4,
        time_budget_millionths: 5_000_000,
        proof_requirement: ProofRequirement::BestEffort,
    };
    let json = serde_json::to_string(&b).unwrap();
    assert!(json.contains("\"max_kernels\""));
    assert!(json.contains("\"max_instruction_expansion\""));
    assert!(json.contains("\"time_budget_millionths\""));
    assert!(json.contains("\"proof_requirement\""));
}

#[test]
fn enrichment_budget_debug_nonempty() {
    let b = SynthesisBudget {
        max_kernels: 32,
        max_instruction_expansion: 4,
        time_budget_millionths: 5_000_000,
        proof_requirement: ProofRequirement::Mandatory,
    };
    let dbg = format!("{b:?}");
    assert!(dbg.contains("SynthesisBudget"));
}

// ===========================================================================
// KernelSynthCertificate enrichment
// ===========================================================================

#[test]
fn enrichment_certificate_clone_independence() {
    let manifest = run_kernel_synth_evidence();
    let original = &manifest.certificates[0];
    let mut cloned = original.clone();
    cloned.kernel_id = "mutated".to_string();
    assert_ne!(original.kernel_id, "mutated");
    assert_eq!(cloned.kernel_id, "mutated");
}

#[test]
fn enrichment_certificate_json_field_names() {
    let manifest = run_kernel_synth_evidence();
    let cert = &manifest.certificates[0];
    let json = serde_json::to_string(cert).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"kernel_id\""));
    assert!(json.contains("\"decision\""));
    assert!(json.contains("\"budget_consumed\""));
    assert!(json.contains("\"certificate_hash\""));
}

#[test]
fn enrichment_certificate_debug_nonempty() {
    let manifest = run_kernel_synth_evidence();
    let cert = &manifest.certificates[0];
    let dbg = format!("{cert:?}");
    assert!(dbg.contains("KernelSynthCertificate"));
}

// ===========================================================================
// KernelSynthEvidenceManifest enrichment
// ===========================================================================

#[test]
fn enrichment_manifest_clone_independence() {
    let original = run_kernel_synth_evidence();
    let mut cloned = original.clone();
    cloned.kernels_evaluated = 999;
    assert_ne!(original.kernels_evaluated, 999);
    assert_eq!(cloned.kernels_evaluated, 999);
}

#[test]
fn enrichment_manifest_json_field_names() {
    let m = run_kernel_synth_evidence();
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"kernels_evaluated\""));
    assert!(json.contains("\"eligible_count\""));
    assert!(json.contains("\"forbidden_count\""));
    assert!(json.contains("\"deferred_count\""));
    assert!(json.contains("\"certificates\""));
    assert!(json.contains("\"manifest_hash\""));
    assert!(json.contains("\"error\""));
}

#[test]
fn enrichment_manifest_debug_nonempty() {
    let m = run_kernel_synth_evidence();
    let dbg = format!("{m:?}");
    assert!(dbg.contains("KernelSynthEvidenceManifest"));
}

// ===========================================================================
// KernelSynthError enrichment
// ===========================================================================

#[test]
fn enrichment_error_clone_independence() {
    let original = KernelSynthError::DuplicateKernel { id: "dup".into() };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_error_debug_all_unique() {
    let errors = vec![
        KernelSynthError::EmptyCorpus,
        KernelSynthError::DuplicateKernel { id: "dup".into() },
        KernelSynthError::InvalidBudget { reason: "r".into() },
        KernelSynthError::InvalidSchema { reason: "s".into() },
    ];
    let debugs: BTreeSet<String> = errors.iter().map(|e| format!("{e:?}")).collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_error_display_all_unique() {
    let errors = vec![
        KernelSynthError::EmptyCorpus,
        KernelSynthError::DuplicateKernel { id: "dup".into() },
        KernelSynthError::InvalidBudget { reason: "r".into() },
        KernelSynthError::InvalidSchema { reason: "s".into() },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| format!("{e}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_error_display_contains_context() {
    let e = KernelSynthError::DuplicateKernel {
        id: "kern-xyz".into(),
    };
    assert!(format!("{e}").contains("kern-xyz"));
}

// ===========================================================================
// Cross-cutting: evaluate_eligibility boundary conditions
// ===========================================================================

#[test]
fn enrichment_purity_exactly_at_threshold_eligible() {
    // Purity threshold is 800_000
    let s = KernelSchema {
        purity_score_millionths: 800_000,
        ..eligible_schema("exact-purity")
    };
    let d = evaluate_eligibility(&s);
    assert_eq!(d.status, EligibilityStatus::Eligible);
}

#[test]
fn enrichment_purity_one_below_threshold_conditional() {
    let s = KernelSchema {
        purity_score_millionths: 799_999,
        ..eligible_schema("below-purity")
    };
    let d = evaluate_eligibility(&s);
    assert!(matches!(d.status, EligibilityStatus::Conditional { .. }));
}

#[test]
fn enrichment_forbidden_has_full_confidence() {
    let d = evaluate_eligibility(&forbidden_schema("f1"));
    assert_eq!(d.confidence_millionths, MILLIONTHS);
}

#[test]
fn enrichment_deferred_has_zero_confidence() {
    let d = evaluate_eligibility(&zero_hotness_schema("z1"));
    assert_eq!(d.confidence_millionths, 0);
    assert_eq!(d.evidence_count, 0);
}

#[test]
fn enrichment_conditional_confidence_equals_purity() {
    let s = low_purity_schema("lp1");
    let d = evaluate_eligibility(&s);
    if let EligibilityStatus::Conditional { .. } = &d.status {
        assert_eq!(d.confidence_millionths, 500_000);
    } else {
        panic!("expected Conditional, got {:?}", d.status);
    }
}

// ===========================================================================
// Cross-cutting: canonical corpus invariants
// ===========================================================================

#[test]
fn enrichment_canonical_unique_ids() {
    let corpus = mine_canonical_kernels();
    let ids: BTreeSet<&str> = corpus.schemas.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids.len(), corpus.schemas.len());
}

#[test]
fn enrichment_canonical_all_families_covered() {
    let corpus = mine_canonical_kernels();
    let families: BTreeSet<KernelFamily> = corpus.schemas.iter().map(|s| s.family).collect();
    assert_eq!(families.len(), 10);
}

#[test]
fn enrichment_canonical_decisions_match_schemas() {
    let corpus = mine_canonical_kernels();
    for (schema, decision) in corpus.schemas.iter().zip(corpus.decisions.iter()) {
        assert_eq!(schema.id, decision.kernel_id);
    }
}

// ===========================================================================
// Cross-cutting: evidence manifest invariants
// ===========================================================================

#[test]
fn enrichment_manifest_certificates_count_matches() {
    let m = run_kernel_synth_evidence();
    assert_eq!(m.certificates.len() as u32, m.kernels_evaluated);
}

#[test]
fn enrichment_manifest_serde_preserves_counts() {
    let m = run_kernel_synth_evidence();
    let json = serde_json::to_string(&m).unwrap();
    let back: KernelSynthEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m.eligible_count, back.eligible_count);
    assert_eq!(m.forbidden_count, back.forbidden_count);
    assert_eq!(m.deferred_count, back.deferred_count);
    assert_eq!(m.manifest_hash, back.manifest_hash);
}

// ===========================================================================
// Cross-cutting: determinism (5-run)
// ===========================================================================

#[test]
fn enrichment_evidence_determinism_five_runs() {
    let mut hashes = BTreeSet::new();
    for _ in 0..5 {
        let m = run_kernel_synth_evidence();
        hashes.insert(m.manifest_hash);
    }
    assert_eq!(hashes.len(), 1);
}

#[test]
fn enrichment_envelope_determinism_five_runs() {
    let schemas = vec![
        eligible_schema("d1"),
        forbidden_schema("d2"),
        zero_hotness_schema("d3"),
        low_purity_schema("d4"),
    ];
    let mut hashes = BTreeSet::new();
    for _ in 0..5 {
        let e = build_synthesis_envelope(&schemas);
        hashes.insert(e.envelope_hash);
    }
    assert_eq!(hashes.len(), 1);
}

#[test]
fn enrichment_envelope_hash_changes_when_conditional_payload_changes() {
    let lower_purity = low_purity_schema("same-kernel");
    let even_lower_purity = KernelSchema {
        purity_score_millionths: 400_000,
        ..low_purity_schema("same-kernel")
    };

    let first = build_synthesis_envelope(&[lower_purity]);
    let second = build_synthesis_envelope(&[even_lower_purity]);

    assert_ne!(first.envelope_hash, second.envelope_hash);
}

// ===========================================================================
// Cross-cutting: constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stable() {
    assert_eq!(
        KERNEL_SYNTH_SCHEMA_VERSION,
        "franken-engine.kernel-synthesis-contract.v1"
    );
    assert_eq!(KERNEL_SYNTH_COMPONENT, "kernel_synthesis_contract");
    assert_eq!(KERNEL_SYNTH_POLICY_ID, "RGC-613A");
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ===========================================================================
// Cross-cutting: validate_schemas edge cases
// ===========================================================================

#[test]
fn enrichment_validate_single_valid_schema_ok() {
    assert!(validate_schemas(&[eligible_schema("v1")]).is_ok());
}

#[test]
fn enrichment_validate_canonical_schemas_ok() {
    let corpus = mine_canonical_kernels();
    assert!(validate_schemas(&corpus.schemas).is_ok());
}

// ===========================================================================
// Cross-cutting: envelope categorization
// ===========================================================================

#[test]
fn enrichment_envelope_conditional_goes_to_deferred() {
    let schemas = vec![low_purity_schema("cond1")];
    let e = build_synthesis_envelope(&schemas);
    // Conditional goes to deferred bucket
    assert!(e.eligible.is_empty());
    assert!(e.forbidden.is_empty());
    assert_eq!(e.deferred.len(), 1);
}

#[test]
fn enrichment_envelope_all_buckets_populated() {
    let schemas = vec![
        eligible_schema("e1"),
        forbidden_schema("f1"),
        zero_hotness_schema("z1"),
    ];
    let e = build_synthesis_envelope(&schemas);
    assert_eq!(e.eligible.len(), 1);
    assert_eq!(e.forbidden.len(), 1);
    assert_eq!(e.deferred.len(), 1);
}
