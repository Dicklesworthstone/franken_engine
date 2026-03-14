//! Enrichment integration tests for `trace_fusion_superinstruction`.
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
use frankenengine_engine::trace_fusion_superinstruction::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn arith_segment(id: &str, hotness: u64) -> TraceSegment {
    TraceSegment {
        id: id.to_string(),
        motif: MotifKind::ArithmeticChain,
        instruction_count: 5,
        hotness_millionths: hotness,
        is_policy_legal: true,
        side_effects: vec![],
    }
}

fn good_candidate() -> FusionCandidate {
    let s1 = arith_segment("enrich-a", 800_000);
    let s2 = arith_segment("enrich-b", 800_000);
    FusionCandidate::from_segments(vec![s1, s2], 200_000)
}

// ===========================================================================
// MotifKind enrichment
// ===========================================================================

#[test]
fn enrichment_motif_kind_btreeset_dedup() {
    let all = vec![
        MotifKind::HostcallSequence,
        MotifKind::PropertyAccess,
        MotifKind::ArithmeticChain,
        MotifKind::GuardChain,
        MotifKind::LoadStoreSequence,
        MotifKind::BranchPattern,
        MotifKind::CallSequence,
    ];
    let mut set = BTreeSet::new();
    for k in &all {
        set.insert(k.clone());
        set.insert(k.clone());
    }
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_motif_kind_debug_all_unique() {
    let all = vec![
        MotifKind::HostcallSequence,
        MotifKind::PropertyAccess,
        MotifKind::ArithmeticChain,
        MotifKind::GuardChain,
        MotifKind::LoadStoreSequence,
        MotifKind::BranchPattern,
        MotifKind::CallSequence,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(debugs.len(), 7);
}

#[test]
fn enrichment_motif_kind_clone_independence() {
    let original = MotifKind::PropertyAccess;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// ===========================================================================
// SideEffectKind enrichment
// ===========================================================================

#[test]
fn enrichment_side_effect_kind_btreeset_dedup() {
    let all = vec![
        SideEffectKind::MemoryWrite,
        SideEffectKind::HostcallInvocation,
        SideEffectKind::ExceptionThrow,
        SideEffectKind::PropertyDefine,
        SideEffectKind::AllocationTrigger,
        SideEffectKind::GcSafepoint,
    ];
    let mut set = BTreeSet::new();
    for k in &all {
        set.insert(k.clone());
        set.insert(k.clone());
    }
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_side_effect_kind_debug_all_unique() {
    let all = vec![
        SideEffectKind::MemoryWrite,
        SideEffectKind::HostcallInvocation,
        SideEffectKind::ExceptionThrow,
        SideEffectKind::PropertyDefine,
        SideEffectKind::AllocationTrigger,
        SideEffectKind::GcSafepoint,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|k| format!("{k:?}")).collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_side_effect_kind_serde_all_variants() {
    let all = vec![
        SideEffectKind::MemoryWrite,
        SideEffectKind::HostcallInvocation,
        SideEffectKind::ExceptionThrow,
        SideEffectKind::PropertyDefine,
        SideEffectKind::AllocationTrigger,
        SideEffectKind::GcSafepoint,
    ];
    for k in &all {
        let json = serde_json::to_string(k).unwrap();
        let back: SideEffectKind = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, k);
    }
}

// ===========================================================================
// TraceSegment enrichment
// ===========================================================================

#[test]
fn enrichment_trace_segment_clone_independence() {
    let original = arith_segment("clone-test", 900_000);
    let mut cloned = original.clone();
    cloned.id = "mutated".to_string();
    assert_eq!(original.id, "clone-test");
    assert_eq!(cloned.id, "mutated");
}

#[test]
fn enrichment_trace_segment_debug_nonempty() {
    let seg = arith_segment("debug-test", 800_000);
    let dbg = format!("{seg:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("TraceSegment"));
}

#[test]
fn enrichment_trace_segment_json_field_names() {
    let seg = arith_segment("json-test", 800_000);
    let json = serde_json::to_string(&seg).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"motif\""));
    assert!(json.contains("\"instruction_count\""));
    assert!(json.contains("\"hotness_millionths\""));
    assert!(json.contains("\"is_policy_legal\""));
    assert!(json.contains("\"side_effects\""));
}

#[test]
fn enrichment_trace_segment_serde_roundtrip() {
    let seg = TraceSegment {
        id: "roundtrip".to_string(),
        motif: MotifKind::LoadStoreSequence,
        instruction_count: 10,
        hotness_millionths: 750_000,
        is_policy_legal: true,
        side_effects: vec![SideEffectKind::MemoryWrite, SideEffectKind::GcSafepoint],
    };
    let json = serde_json::to_string(&seg).unwrap();
    let back: TraceSegment = serde_json::from_str(&json).unwrap();
    assert_eq!(back, seg);
}

// ===========================================================================
// FusionCandidate enrichment
// ===========================================================================

#[test]
fn enrichment_fusion_candidate_clone_independence() {
    let original = good_candidate();
    let mut cloned = original.clone();
    cloned.estimated_speedup_millionths = 999_999;
    assert_eq!(original.estimated_speedup_millionths, 200_000);
    assert_eq!(cloned.estimated_speedup_millionths, 999_999);
}

#[test]
fn enrichment_fusion_candidate_json_field_names() {
    let cand = good_candidate();
    let json = serde_json::to_string(&cand).unwrap();
    assert!(json.contains("\"segments\""));
    assert!(json.contains("\"total_instructions\""));
    assert!(json.contains("\"estimated_speedup_millionths\""));
    assert!(json.contains("\"fusion_hash\""));
}

#[test]
fn enrichment_fusion_candidate_serde_roundtrip() {
    let cand = good_candidate();
    let json = serde_json::to_string(&cand).unwrap();
    let back: FusionCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cand);
}

// ===========================================================================
// FusionRejectReason enrichment
// ===========================================================================

#[test]
fn enrichment_fusion_reject_reason_btreeset_dedup() {
    let all = vec![
        FusionRejectReason::PolicyViolation,
        FusionRejectReason::SideEffectConflict,
        FusionRejectReason::UnboundedLoop,
        FusionRejectReason::InsufficientHotness,
        FusionRejectReason::ProofMissing,
        FusionRejectReason::GuardFailure,
    ];
    let mut set = BTreeSet::new();
    for r in &all {
        set.insert(r.clone());
        set.insert(r.clone());
    }
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_fusion_reject_reason_debug_all_unique() {
    let all = vec![
        FusionRejectReason::PolicyViolation,
        FusionRejectReason::SideEffectConflict,
        FusionRejectReason::UnboundedLoop,
        FusionRejectReason::InsufficientHotness,
        FusionRejectReason::ProofMissing,
        FusionRejectReason::GuardFailure,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|r| format!("{r:?}")).collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_fusion_reject_reason_serde_all_variants() {
    let all = vec![
        FusionRejectReason::PolicyViolation,
        FusionRejectReason::SideEffectConflict,
        FusionRejectReason::UnboundedLoop,
        FusionRejectReason::InsufficientHotness,
        FusionRejectReason::ProofMissing,
        FusionRejectReason::GuardFailure,
    ];
    for r in &all {
        let json = serde_json::to_string(r).unwrap();
        let back: FusionRejectReason = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, r);
    }
}

// ===========================================================================
// FusionDecision enrichment
// ===========================================================================

#[test]
fn enrichment_fusion_decision_clone_independence() {
    let original = FusionDecision::Fuse {
        superinstruction_id: "si-test".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_fusion_decision_debug_all_variants_unique() {
    let variants = vec![
        FusionDecision::Fuse {
            superinstruction_id: "si-1".to_string(),
        },
        FusionDecision::Reject {
            reason: FusionRejectReason::PolicyViolation,
        },
        FusionDecision::Defer {
            reason: "need more data".to_string(),
        },
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 3);
}

#[test]
fn enrichment_fusion_decision_serde_all_variants() {
    let variants = vec![
        FusionDecision::Fuse {
            superinstruction_id: "si-round".to_string(),
        },
        FusionDecision::Reject {
            reason: FusionRejectReason::GuardFailure,
        },
        FusionDecision::Defer {
            reason: "deferred".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: FusionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

// ===========================================================================
// TraceFusionError enrichment
// ===========================================================================

#[test]
fn enrichment_trace_fusion_error_display_all_unique() {
    let variants = vec![
        TraceFusionError::EmptyCandidate,
        TraceFusionError::DuplicateSegment {
            id: "dup".to_string(),
        },
        TraceFusionError::InvalidConfig {
            reason: "bad".to_string(),
        },
        TraceFusionError::ProofFailure {
            reason: "fail".to_string(),
        },
    ];
    let displays: BTreeSet<String> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_trace_fusion_error_clone_independence() {
    let original = TraceFusionError::DuplicateSegment {
        id: "original".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_trace_fusion_error_serde_all_variants() {
    let variants = vec![
        TraceFusionError::EmptyCandidate,
        TraceFusionError::DuplicateSegment {
            id: "dup".to_string(),
        },
        TraceFusionError::InvalidConfig {
            reason: "bad config".to_string(),
        },
        TraceFusionError::ProofFailure {
            reason: "proof fail".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: TraceFusionError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, v);
    }
}

// ===========================================================================
// TraceFusionConfig enrichment
// ===========================================================================

#[test]
fn enrichment_config_clone_independence() {
    let original = TraceFusionConfig::default_config();
    let mut cloned = original.clone();
    cloned.max_fused_instructions = 999;
    assert_eq!(original.max_fused_instructions, 128);
    assert_eq!(cloned.max_fused_instructions, 999);
}

#[test]
fn enrichment_config_json_field_names() {
    let config = TraceFusionConfig::default_config();
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("\"min_hotness_millionths\""));
    assert!(json.contains("\"max_fused_instructions\""));
    assert!(json.contains("\"max_side_exits\""));
    assert!(json.contains("\"require_proof\""));
    assert!(json.contains("\"allow_hostcall_fusion\""));
}

#[test]
fn enrichment_config_serde_roundtrip() {
    let config = TraceFusionConfig::default_config();
    let json = serde_json::to_string(&config).unwrap();
    let back: TraceFusionConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ===========================================================================
// SideExitDescriptor enrichment
// ===========================================================================

#[test]
fn enrichment_side_exit_descriptor_clone_independence() {
    let original = SideExitDescriptor {
        exit_id: "exit-1".to_string(),
        guard_index: 0,
        target_pc: 16,
        deopt_state_hash: ContentHash::compute(b"test"),
    };
    let mut cloned = original.clone();
    cloned.exit_id = "exit-mutated".to_string();
    assert_eq!(original.exit_id, "exit-1");
    assert_eq!(cloned.exit_id, "exit-mutated");
}

#[test]
fn enrichment_side_exit_descriptor_json_field_names() {
    let desc = SideExitDescriptor {
        exit_id: "exit-json".to_string(),
        guard_index: 2,
        target_pc: 32,
        deopt_state_hash: ContentHash::compute(b"json"),
    };
    let json = serde_json::to_string(&desc).unwrap();
    assert!(json.contains("\"exit_id\""));
    assert!(json.contains("\"guard_index\""));
    assert!(json.contains("\"target_pc\""));
    assert!(json.contains("\"deopt_state_hash\""));
}

// ===========================================================================
// Superinstruction enrichment
// ===========================================================================

#[test]
fn enrichment_superinstruction_clone_independence() {
    let cand = good_candidate();
    let proof = build_proof(&cand);
    let original = build_superinstruction(&cand, &proof);
    let mut cloned = original.clone();
    cloned.id = "mutated-id".to_string();
    assert_ne!(original.id, "mutated-id");
    assert_eq!(cloned.id, "mutated-id");
}

#[test]
fn enrichment_superinstruction_json_field_names() {
    let cand = good_candidate();
    let proof = build_proof(&cand);
    let si = build_superinstruction(&cand, &proof);
    let json = serde_json::to_string(&si).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"fused_segments\""));
    assert!(json.contains("\"side_exits\""));
    assert!(json.contains("\"proof_hash\""));
    assert!(json.contains("\"disable_token\""));
    assert!(json.contains("\"total_speedup_millionths\""));
}

#[test]
fn enrichment_superinstruction_side_exits_match_segments() {
    let cand = good_candidate();
    let proof = build_proof(&cand);
    let si = build_superinstruction(&cand, &proof);
    assert_eq!(si.side_exits.len(), cand.segments.len());
    assert_eq!(si.fused_segments.len(), cand.segments.len());
}

// ===========================================================================
// FusionProof enrichment
// ===========================================================================

#[test]
fn enrichment_fusion_proof_clone_independence() {
    let cand = good_candidate();
    let original = build_proof(&cand);
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_fusion_proof_json_field_names() {
    let cand = good_candidate();
    let proof = build_proof(&cand);
    let json = serde_json::to_string(&proof).unwrap();
    assert!(json.contains("\"candidate_hash\""));
    assert!(json.contains("\"policy_check_passed\""));
    assert!(json.contains("\"determinism_verified\""));
    assert!(json.contains("\"side_exit_coverage\""));
    assert!(json.contains("\"proof_hash\""));
}

// ===========================================================================
// FusionCertificate enrichment
// ===========================================================================

#[test]
fn enrichment_fusion_certificate_clone_independence() {
    let cand = good_candidate();
    let config = TraceFusionConfig::default_config();
    let original = certify_fusion(&cand, &config);
    let mut cloned = original.clone();
    cloned.schema_version = "mutated".to_string();
    assert_eq!(original.schema_version, TRACE_FUSION_SCHEMA_VERSION);
    assert_eq!(cloned.schema_version, "mutated");
}

#[test]
fn enrichment_fusion_certificate_json_field_names() {
    let cand = good_candidate();
    let config = TraceFusionConfig::default_config();
    let cert = certify_fusion(&cand, &config);
    let json = serde_json::to_string(&cert).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"candidate\""));
    assert!(json.contains("\"decision\""));
    assert!(json.contains("\"certificate_hash\""));
}

#[test]
fn enrichment_fusion_certificate_serde_roundtrip() {
    let cand = good_candidate();
    let config = TraceFusionConfig::default_config();
    let cert = certify_fusion(&cand, &config);
    let json = serde_json::to_string(&cert).unwrap();
    let back: FusionCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cert);
}

// ===========================================================================
// Cross-cutting: determinism
// ===========================================================================

#[test]
fn enrichment_certify_determinism_five_runs() {
    let cand = good_candidate();
    let config = TraceFusionConfig::default_config();
    let first = certify_fusion(&cand, &config);
    for _ in 0..4 {
        let again = certify_fusion(&cand, &config);
        assert_eq!(first.certificate_hash, again.certificate_hash);
        assert_eq!(first.decision, again.decision);
    }
}

#[test]
fn enrichment_evidence_manifest_determinism_five_runs() {
    let first = run_trace_fusion_evidence();
    for _ in 0..4 {
        let again = run_trace_fusion_evidence();
        assert_eq!(first.manifest_hash, again.manifest_hash);
        assert_eq!(first.fused_count, again.fused_count);
        assert_eq!(first.rejected_count, again.rejected_count);
        assert_eq!(first.deferred_count, again.deferred_count);
    }
}

// ===========================================================================
// Cross-cutting: evidence manifest structural invariants
// ===========================================================================

#[test]
fn enrichment_evidence_manifest_counts_sum() {
    let manifest = run_trace_fusion_evidence();
    assert_eq!(
        manifest.fused_count + manifest.rejected_count + manifest.deferred_count,
        manifest.candidates_evaluated
    );
}

#[test]
fn enrichment_evidence_manifest_no_error() {
    let manifest = run_trace_fusion_evidence();
    assert!(manifest.error.is_none());
}

#[test]
fn enrichment_evidence_manifest_schema_version() {
    let manifest = run_trace_fusion_evidence();
    assert_eq!(manifest.schema_version, TRACE_FUSION_SCHEMA_VERSION);
}

#[test]
fn enrichment_evidence_manifest_serde_roundtrip() {
    let manifest = run_trace_fusion_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: TraceFusionEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
}

// ===========================================================================
// Cross-cutting: constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stable() {
    assert_eq!(
        TRACE_FUSION_SCHEMA_VERSION,
        "franken-engine.trace-fusion-superinstruction.v1"
    );
    assert_eq!(TRACE_FUSION_COMPONENT, "trace_fusion_superinstruction");
    assert_eq!(TRACE_FUSION_POLICY_ID, "RGC-604B");
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ===========================================================================
// Cross-cutting: can_fuse_segments symmetry
// ===========================================================================

#[test]
fn enrichment_can_fuse_segments_no_effects_symmetric() {
    let a = arith_segment("sym-a", 800_000);
    let b = arith_segment("sym-b", 800_000);
    assert_eq!(can_fuse_segments(&a, &b), can_fuse_segments(&b, &a));
}

#[test]
fn enrichment_can_fuse_segments_memory_exception_conflict() {
    let a = TraceSegment {
        id: "mem".to_string(),
        motif: MotifKind::LoadStoreSequence,
        instruction_count: 3,
        hotness_millionths: 800_000,
        is_policy_legal: true,
        side_effects: vec![SideEffectKind::MemoryWrite],
    };
    let b = TraceSegment {
        id: "exc".to_string(),
        motif: MotifKind::BranchPattern,
        instruction_count: 2,
        hotness_millionths: 800_000,
        is_policy_legal: true,
        side_effects: vec![SideEffectKind::ExceptionThrow],
    };
    assert!(!can_fuse_segments(&a, &b));
    assert!(!can_fuse_segments(&b, &a)); // symmetric
}
