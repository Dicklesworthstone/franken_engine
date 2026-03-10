//! Integration tests for the trace fusion superinstruction module (RGC-604B).

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
use frankenengine_engine::trace_fusion_superinstruction::{
    FusionCandidate, FusionCertificate, FusionDecision, FusionProof, FusionRejectReason,
    MILLIONTHS, MotifKind, SideEffectKind, SideExitDescriptor, Superinstruction,
    TRACE_FUSION_COMPONENT, TRACE_FUSION_POLICY_ID, TRACE_FUSION_SCHEMA_VERSION, TraceFusionConfig,
    TraceFusionError, TraceFusionEvidenceManifest, TraceSegment, build_proof,
    build_superinstruction, can_fuse_segments, certify_fusion, evaluate_candidate,
    run_trace_fusion_evidence, validate_candidate,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn policy_legal_segment(id: &str, motif: MotifKind) -> TraceSegment {
    TraceSegment {
        id: id.into(),
        motif,
        instruction_count: 10,
        hotness_millionths: 800_000,
        is_policy_legal: true,
        side_effects: Vec::new(),
    }
}

fn segment_with_effects(id: &str, effects: Vec<SideEffectKind>) -> TraceSegment {
    TraceSegment {
        id: id.into(),
        motif: MotifKind::ArithmeticChain,
        instruction_count: 5,
        hotness_millionths: 800_000,
        is_policy_legal: true,
        side_effects: effects,
    }
}

fn make_candidate(segments: Vec<TraceSegment>) -> FusionCandidate {
    FusionCandidate::from_segments(segments, 1_500_000)
}

fn default_config() -> TraceFusionConfig {
    TraceFusionConfig::default_config()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version_nonempty() {
    assert!(!TRACE_FUSION_SCHEMA_VERSION.is_empty());
    assert!(TRACE_FUSION_SCHEMA_VERSION.contains("trace-fusion-superinstruction"));
}

#[test]
fn integration_component_name() {
    assert_eq!(TRACE_FUSION_COMPONENT, "trace_fusion_superinstruction");
}

#[test]
fn integration_policy_id() {
    assert_eq!(TRACE_FUSION_POLICY_ID, "RGC-604B");
}

#[test]
fn integration_millionths_constant() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// MotifKind serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_motif_kind_serde_all_variants() {
    let motifs = [
        MotifKind::HostcallSequence,
        MotifKind::PropertyAccess,
        MotifKind::ArithmeticChain,
        MotifKind::GuardChain,
        MotifKind::LoadStoreSequence,
        MotifKind::BranchPattern,
        MotifKind::CallSequence,
    ];
    for m in motifs {
        let json = serde_json::to_string(&m).unwrap();
        let back: MotifKind = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}

// ---------------------------------------------------------------------------
// SideEffectKind serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_side_effect_kind_serde_all_variants() {
    let effects = [
        SideEffectKind::MemoryWrite,
        SideEffectKind::HostcallInvocation,
        SideEffectKind::ExceptionThrow,
        SideEffectKind::PropertyDefine,
        SideEffectKind::AllocationTrigger,
        SideEffectKind::GcSafepoint,
    ];
    for e in effects {
        let json = serde_json::to_string(&e).unwrap();
        let back: SideEffectKind = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

// ---------------------------------------------------------------------------
// FusionRejectReason serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_reject_reason_serde_all_variants() {
    let reasons = [
        FusionRejectReason::PolicyViolation,
        FusionRejectReason::SideEffectConflict,
        FusionRejectReason::UnboundedLoop,
        FusionRejectReason::InsufficientHotness,
        FusionRejectReason::ProofMissing,
        FusionRejectReason::GuardFailure,
    ];
    for r in reasons {
        let json = serde_json::to_string(&r).unwrap();
        let back: FusionRejectReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

// ---------------------------------------------------------------------------
// FusionDecision serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn integration_fusion_decision_serde_all_variants() {
    let decisions = vec![
        FusionDecision::Fuse {
            superinstruction_id: "si-abc".into(),
        },
        FusionDecision::Reject {
            reason: FusionRejectReason::PolicyViolation,
        },
        FusionDecision::Defer {
            reason: "waiting".into(),
        },
    ];
    for d in decisions {
        let json = serde_json::to_string(&d).unwrap();
        let back: FusionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

// ---------------------------------------------------------------------------
// TraceFusionError serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_error_serde_roundtrip() {
    let errors = vec![
        TraceFusionError::EmptyCandidate,
        TraceFusionError::DuplicateSegment { id: "seg1".into() },
        TraceFusionError::InvalidConfig {
            reason: "bad".into(),
        },
        TraceFusionError::ProofFailure {
            reason: "failed".into(),
        },
    ];
    for e in errors {
        let json = serde_json::to_string(&e).unwrap();
        let back: TraceFusionError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

#[test]
fn integration_error_display() {
    assert_eq!(
        TraceFusionError::EmptyCandidate.to_string(),
        "empty candidate"
    );
    let ds = TraceFusionError::DuplicateSegment { id: "seg1".into() };
    assert!(ds.to_string().contains("seg1"));
}

// ---------------------------------------------------------------------------
// FusionCandidate
// ---------------------------------------------------------------------------

#[test]
fn integration_candidate_from_segments_computes_totals() {
    let segs = vec![
        policy_legal_segment("s1", MotifKind::ArithmeticChain),
        policy_legal_segment("s2", MotifKind::PropertyAccess),
    ];
    let candidate = FusionCandidate::from_segments(segs, 1_200_000);
    assert_eq!(candidate.total_instructions, 20); // 10 + 10
    assert_eq!(candidate.estimated_speedup_millionths, 1_200_000);
}

#[test]
fn integration_candidate_compute_hash_determinism() {
    let segs = vec![policy_legal_segment("s1", MotifKind::ArithmeticChain)];
    let h1 = FusionCandidate::compute_hash(&segs);
    let h2 = FusionCandidate::compute_hash(&segs);
    assert_eq!(h1, h2);
}

#[test]
fn integration_candidate_serde_roundtrip() {
    let candidate = make_candidate(vec![policy_legal_segment("s1", MotifKind::ArithmeticChain)]);
    let json = serde_json::to_string(&candidate).unwrap();
    let back: FusionCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(candidate, back);
}

// ---------------------------------------------------------------------------
// validate_candidate
// ---------------------------------------------------------------------------

#[test]
fn integration_validate_candidate_valid() {
    let candidate = make_candidate(vec![
        policy_legal_segment("v1", MotifKind::ArithmeticChain),
        policy_legal_segment("v2", MotifKind::PropertyAccess),
    ]);
    assert!(validate_candidate(&candidate).is_ok());
}

#[test]
fn integration_validate_candidate_empty() {
    let candidate = FusionCandidate::from_segments(Vec::new(), 0);
    assert_eq!(
        validate_candidate(&candidate).unwrap_err(),
        TraceFusionError::EmptyCandidate
    );
}

#[test]
fn integration_validate_candidate_duplicate_segment() {
    let candidate = make_candidate(vec![
        policy_legal_segment("dup", MotifKind::ArithmeticChain),
        policy_legal_segment("dup", MotifKind::PropertyAccess),
    ]);
    let err = validate_candidate(&candidate).unwrap_err();
    assert!(matches!(err, TraceFusionError::DuplicateSegment { .. }));
}

// ---------------------------------------------------------------------------
// evaluate_candidate
// ---------------------------------------------------------------------------

#[test]
fn integration_evaluate_candidate_fuse_accepted() {
    let candidate = make_candidate(vec![
        policy_legal_segment("e1", MotifKind::ArithmeticChain),
        policy_legal_segment("e2", MotifKind::PropertyAccess),
    ]);
    let decision = evaluate_candidate(&candidate, &default_config());
    assert!(matches!(decision, FusionDecision::Fuse { .. }));
}

#[test]
fn integration_evaluate_candidate_reject_too_many_instructions() {
    let mut seg = policy_legal_segment("big", MotifKind::ArithmeticChain);
    seg.instruction_count = 200;
    let candidate = FusionCandidate::from_segments(vec![seg], 1_000_000);
    let decision = evaluate_candidate(&candidate, &default_config());
    assert!(matches!(
        decision,
        FusionDecision::Reject {
            reason: FusionRejectReason::UnboundedLoop,
        }
    ));
}

#[test]
fn integration_evaluate_candidate_reject_policy_violation() {
    let mut seg = policy_legal_segment("illegal", MotifKind::ArithmeticChain);
    seg.is_policy_legal = false;
    let candidate = make_candidate(vec![seg]);
    let decision = evaluate_candidate(&candidate, &default_config());
    assert!(matches!(
        decision,
        FusionDecision::Reject {
            reason: FusionRejectReason::PolicyViolation,
        }
    ));
}

#[test]
fn integration_evaluate_candidate_reject_insufficient_hotness() {
    let mut seg = policy_legal_segment("cold", MotifKind::ArithmeticChain);
    seg.hotness_millionths = 100_000; // below default 500_000 threshold
    let candidate = make_candidate(vec![seg]);
    let decision = evaluate_candidate(&candidate, &default_config());
    assert!(matches!(
        decision,
        FusionDecision::Reject {
            reason: FusionRejectReason::InsufficientHotness,
        }
    ));
}

#[test]
fn integration_evaluate_candidate_reject_hostcall_not_allowed() {
    let config = TraceFusionConfig {
        allow_hostcall_fusion: false,
        ..default_config()
    };
    let candidate = make_candidate(vec![policy_legal_segment(
        "hc",
        MotifKind::HostcallSequence,
    )]);
    let decision = evaluate_candidate(&candidate, &config);
    assert!(matches!(
        decision,
        FusionDecision::Reject {
            reason: FusionRejectReason::PolicyViolation,
        }
    ));
}

// ---------------------------------------------------------------------------
// can_fuse_segments
// ---------------------------------------------------------------------------

#[test]
fn integration_can_fuse_no_effects() {
    let a = policy_legal_segment("a", MotifKind::ArithmeticChain);
    let b = policy_legal_segment("b", MotifKind::PropertyAccess);
    assert!(can_fuse_segments(&a, &b));
}

#[test]
fn integration_cannot_fuse_memory_write_plus_exception() {
    let a = segment_with_effects("a", vec![SideEffectKind::MemoryWrite]);
    let b = segment_with_effects("b", vec![SideEffectKind::ExceptionThrow]);
    assert!(!can_fuse_segments(&a, &b));
}

#[test]
fn integration_cannot_fuse_two_hostcall_invocations() {
    let a = segment_with_effects("a", vec![SideEffectKind::HostcallInvocation]);
    let b = segment_with_effects("b", vec![SideEffectKind::HostcallInvocation]);
    assert!(!can_fuse_segments(&a, &b));
}

#[test]
fn integration_can_fuse_memory_write_plus_allocation() {
    let a = segment_with_effects("a", vec![SideEffectKind::MemoryWrite]);
    let b = segment_with_effects("b", vec![SideEffectKind::AllocationTrigger]);
    assert!(can_fuse_segments(&a, &b));
}

// ---------------------------------------------------------------------------
// build_proof
// ---------------------------------------------------------------------------

#[test]
fn integration_build_proof_policy_legal_candidate() {
    let candidate = make_candidate(vec![policy_legal_segment("p1", MotifKind::ArithmeticChain)]);
    let proof = build_proof(&candidate);
    assert!(proof.policy_check_passed);
    assert!(proof.determinism_verified);
    assert_eq!(proof.side_exit_coverage, 1);
    assert_eq!(proof.candidate_hash, candidate.fusion_hash);
}

#[test]
fn integration_build_proof_hash_determinism() {
    let candidate = make_candidate(vec![policy_legal_segment("p2", MotifKind::ArithmeticChain)]);
    let proof1 = build_proof(&candidate);
    let proof2 = build_proof(&candidate);
    assert_eq!(proof1.proof_hash, proof2.proof_hash);
}

#[test]
fn integration_build_proof_serde_roundtrip() {
    let candidate = make_candidate(vec![policy_legal_segment("p3", MotifKind::ArithmeticChain)]);
    let proof = build_proof(&candidate);
    let json = serde_json::to_string(&proof).unwrap();
    let back: FusionProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, back);
}

// ---------------------------------------------------------------------------
// build_superinstruction
// ---------------------------------------------------------------------------

#[test]
fn integration_build_superinstruction_sets_fields() {
    let candidate = make_candidate(vec![
        policy_legal_segment("si1", MotifKind::ArithmeticChain),
        policy_legal_segment("si2", MotifKind::PropertyAccess),
    ]);
    let proof = build_proof(&candidate);
    let si = build_superinstruction(&candidate, &proof);
    assert!(si.id.starts_with("si-"));
    assert_eq!(si.fused_segments.len(), 2);
    assert_eq!(si.side_exits.len(), 2);
    assert!(si.disable_token.is_some());
    assert_eq!(
        si.total_speedup_millionths,
        candidate.estimated_speedup_millionths
    );
    assert_eq!(si.proof_hash, proof.proof_hash);
}

#[test]
fn integration_superinstruction_serde_roundtrip() {
    let candidate = make_candidate(vec![policy_legal_segment(
        "si3",
        MotifKind::ArithmeticChain,
    )]);
    let proof = build_proof(&candidate);
    let si = build_superinstruction(&candidate, &proof);
    let json = serde_json::to_string(&si).unwrap();
    let back: Superinstruction = serde_json::from_str(&json).unwrap();
    assert_eq!(si, back);
}

// ---------------------------------------------------------------------------
// certify_fusion
// ---------------------------------------------------------------------------

#[test]
fn integration_certify_fusion_accepted() {
    let candidate = make_candidate(vec![policy_legal_segment(
        "cf1",
        MotifKind::ArithmeticChain,
    )]);
    let cert = certify_fusion(&candidate, &default_config());
    assert_eq!(cert.schema_version, TRACE_FUSION_SCHEMA_VERSION);
    assert!(matches!(cert.decision, FusionDecision::Fuse { .. }));
    assert!(cert.proof.is_some());
    assert!(cert.superinstruction.is_some());
}

#[test]
fn integration_certify_fusion_rejected() {
    let mut seg = policy_legal_segment("cf2", MotifKind::ArithmeticChain);
    seg.is_policy_legal = false;
    let candidate = make_candidate(vec![seg]);
    let cert = certify_fusion(&candidate, &default_config());
    assert!(matches!(cert.decision, FusionDecision::Reject { .. }));
    assert!(cert.proof.is_none());
    assert!(cert.superinstruction.is_none());
}

#[test]
fn integration_certify_fusion_hash_determinism() {
    let candidate = make_candidate(vec![policy_legal_segment(
        "cf3",
        MotifKind::ArithmeticChain,
    )]);
    let c1 = certify_fusion(&candidate, &default_config());
    let c2 = certify_fusion(&candidate, &default_config());
    assert_eq!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn integration_certify_fusion_serde_roundtrip() {
    let candidate = make_candidate(vec![policy_legal_segment(
        "cf4",
        MotifKind::ArithmeticChain,
    )]);
    let cert = certify_fusion(&candidate, &default_config());
    let json = serde_json::to_string(&cert).unwrap();
    let back: FusionCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// TraceFusionConfig
// ---------------------------------------------------------------------------

#[test]
fn integration_config_default_values() {
    let config = TraceFusionConfig::default_config();
    assert_eq!(config.min_hotness_millionths, 500_000);
    assert_eq!(config.max_fused_instructions, 128);
    assert_eq!(config.max_side_exits, 16);
    assert!(config.require_proof);
    assert!(config.allow_hostcall_fusion);
}

#[test]
fn integration_config_serde_roundtrip() {
    let config = TraceFusionConfig::default_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: TraceFusionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// SideExitDescriptor serde
// ---------------------------------------------------------------------------

#[test]
fn integration_side_exit_descriptor_serde_roundtrip() {
    let desc = SideExitDescriptor {
        exit_id: "exit-0".into(),
        guard_index: 0,
        target_pc: 16,
        deopt_state_hash: ContentHash::compute(b"deopt"),
    };
    let json = serde_json::to_string(&desc).unwrap();
    let back: SideExitDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, back);
}

// ---------------------------------------------------------------------------
// Evidence manifest
// ---------------------------------------------------------------------------

#[test]
fn integration_run_evidence_produces_manifest() {
    let manifest = run_trace_fusion_evidence();
    assert_eq!(manifest.schema_version, TRACE_FUSION_SCHEMA_VERSION);
    assert!(manifest.candidates_evaluated > 0);
    assert!(manifest.error.is_none());
    assert!(!manifest.certificates.is_empty());
}

#[test]
fn integration_evidence_hash_determinism() {
    let m1 = run_trace_fusion_evidence();
    let m2 = run_trace_fusion_evidence();
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn integration_evidence_serde_roundtrip() {
    let manifest = run_trace_fusion_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: TraceFusionEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn integration_evidence_counts_add_up() {
    let m = run_trace_fusion_evidence();
    assert_eq!(
        m.fused_count + m.rejected_count + m.deferred_count,
        m.candidates_evaluated
    );
}

#[test]
fn integration_evidence_certificates_have_schema_version() {
    let manifest = run_trace_fusion_evidence();
    for cert in &manifest.certificates {
        assert_eq!(cert.schema_version, TRACE_FUSION_SCHEMA_VERSION);
    }
}

// ---------------------------------------------------------------------------
// TraceSegment serde
// ---------------------------------------------------------------------------

#[test]
fn integration_trace_segment_serde_roundtrip() {
    let seg = policy_legal_segment("serde-seg", MotifKind::GuardChain);
    let json = serde_json::to_string(&seg).unwrap();
    let back: TraceSegment = serde_json::from_str(&json).unwrap();
    assert_eq!(seg, back);
}
