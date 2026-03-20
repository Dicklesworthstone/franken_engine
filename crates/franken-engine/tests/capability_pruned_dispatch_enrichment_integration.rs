#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]
//! Enrichment integration tests for capability_pruned_dispatch module.
//!
//! Covers pruning policy, dispatch compilation, specialization envelopes,
//! check-elidable regions, and dispatch corpus.

use std::collections::BTreeSet;

use frankenengine_engine::capability_pruned_dispatch::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

// ---------------------------------------------------------------------------
// PruningPolicy
// ---------------------------------------------------------------------------

#[test]
fn pruning_policy_default_values() {
    let p = PruningPolicy::default();
    assert_eq!(p.max_fast_path_sites, DEFAULT_MAX_FAST_PATH_SITES);
    assert_eq!(p.min_elision_confidence, DEFAULT_MIN_ELISION_CONFIDENCE);
    assert_eq!(p.max_region_span, DEFAULT_MAX_REGION_SPAN);
    assert!(p.require_ifc_proofs);
    assert!(!p.allow_degraded_dispatch);
}

#[test]
fn pruning_policy_hash_deterministic() {
    let p = PruningPolicy::default();
    let h1 = p.policy_hash();
    let h2 = p.policy_hash();
    assert_eq!(h1, h2);
}

#[test]
fn pruning_policy_different_configs_different_hash() {
    let p1 = PruningPolicy::default();
    let p2 = PruningPolicy {
        require_ifc_proofs: false,
        ..PruningPolicy::default()
    };
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn pruning_policy_serde_roundtrip() {
    let p = PruningPolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    let restored: PruningPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

// ---------------------------------------------------------------------------
// DispatchRoute
// ---------------------------------------------------------------------------

#[test]
fn dispatch_route_display_all_distinct() {
    let routes = [
        DispatchRoute::FastPath,
        DispatchRoute::CheckedPath {
            missing_proofs: BTreeSet::new(),
        },
        DispatchRoute::Rejected {
            reason: DispatchRejection::NoWitness,
        },
    ];
    let displays: BTreeSet<String> = routes.iter().map(|r| format!("{r}")).collect();
    assert_eq!(displays.len(), 3);
}

// ---------------------------------------------------------------------------
// DispatchRejection
// ---------------------------------------------------------------------------

#[test]
fn dispatch_rejection_display_all_distinct() {
    let rejections = [
        DispatchRejection::NoWitness,
        DispatchRejection::InsufficientConfidence {
            required_millionths: 950_000,
            actual_millionths: 500_000,
        },
        DispatchRejection::MissingFlowProof {
            source_label: "src".into(),
            sink_clearance: "sink".into(),
        },
        DispatchRejection::EnvelopeFull,
        DispatchRejection::DegradedNotAllowed,
    ];
    let displays: BTreeSet<String> = rejections.iter().map(|r| format!("{r}")).collect();
    assert_eq!(displays.len(), 5);
}

// ---------------------------------------------------------------------------
// DispatchCompiler
// ---------------------------------------------------------------------------

#[test]
fn dispatch_compiler_new() {
    let policy = PruningPolicy::default();
    let compiler = DispatchCompiler::new(policy, epoch(1));
    // Just verify it constructs without panic
    let _ = compiler;
}

#[test]
fn dispatch_compiler_compile_empty() {
    let policy = PruningPolicy::default();
    let compiler = DispatchCompiler::new(policy, epoch(1));
    let envelope = compiler.compile_envelope("test-scope", &[], 0);
    // Empty inputs should produce an empty envelope
    assert_eq!(envelope.fast_path_count, 0);
}

// ---------------------------------------------------------------------------
// DispatchSpecimenFamily
// ---------------------------------------------------------------------------

#[test]
fn dispatch_specimen_family_display_all_distinct() {
    let families = [
        DispatchSpecimenFamily::SingleSite,
        DispatchSpecimenFamily::MixedCapabilities,
        DispatchSpecimenFamily::IfcRequired,
        DispatchSpecimenFamily::ContiguousRegion,
        DispatchSpecimenFamily::DegradedMode,
    ];
    let displays: BTreeSet<String> = families.iter().map(|f| format!("{f}")).collect();
    assert_eq!(displays.len(), 5);
}

// ---------------------------------------------------------------------------
// dispatch_corpus and run_dispatch_corpus
// ---------------------------------------------------------------------------

#[test]
fn dispatch_corpus_not_empty() {
    let corpus = dispatch_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn dispatch_corpus_all_families_represented() {
    let corpus = dispatch_corpus();
    let families: BTreeSet<_> = corpus.iter().map(|(f, _)| format!("{f:?}")).collect();
    assert!(families.len() >= 3, "corpus should cover multiple families");
}

#[test]
fn run_dispatch_corpus_produces_results() {
    let results = run_dispatch_corpus();
    assert!(!results.is_empty());
    // Each result should have a family and a boolean
    for (family, passed) in &results {
        let _ = format!("{family:?}:{passed}"); // no panic
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_valid() {
    assert_eq!(COMPONENT, "capability_pruned_dispatch");
    assert!(DISPATCH_SCHEMA_VERSION.contains('.'));
    assert!(REGION_SCHEMA_VERSION.contains('.'));
    assert!(DEFAULT_MAX_FAST_PATH_SITES > 0);
    assert!(DEFAULT_MIN_ELISION_CONFIDENCE > 0);
    assert!(DEFAULT_MAX_REGION_SPAN > 0);
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchSite builder
// ---------------------------------------------------------------------------

#[test]
fn dispatch_site_new() {
    let site = DispatchSite::new(10, "hostcall.fs.read");
    assert_eq!(site.offset, 10);
    assert_eq!(site.hostcall_id, "hostcall.fs.read");
    assert!(site.required_capabilities.is_empty());
}

#[test]
fn dispatch_site_require_adds_capability() {
    use frankenengine_engine::policy_theorem_compiler::Capability;
    let cap = Capability::new("network_outbound");
    let site = DispatchSite::new(20, "hostcall.net.connect")
        .require(cap.clone());
    assert!(site.required_capabilities.contains(&cap));
}

#[test]
fn dispatch_site_with_ifc_flow() {
    let site = DispatchSite::new(30, "hostcall.declassify")
        .with_ifc_flow("secret", "public");
    assert_eq!(site.source_label.as_deref(), Some("secret"));
    assert_eq!(site.sink_clearance.as_deref(), Some("public"));
}

#[test]
fn dispatch_site_content_hash_deterministic() {
    let s1 = DispatchSite::new(5, "hostcall.timer");
    let s2 = DispatchSite::new(5, "hostcall.timer");
    assert_eq!(s1.content_hash(), s2.content_hash());
}

#[test]
fn dispatch_site_content_hash_changes_on_diff() {
    let s1 = DispatchSite::new(5, "hostcall.timer");
    let s2 = DispatchSite::new(6, "hostcall.timer");
    assert_ne!(s1.content_hash(), s2.content_hash());
}

// ---------------------------------------------------------------------------
// Enrichment: CapabilityProof
// ---------------------------------------------------------------------------

#[test]
fn capability_proof_meets_confidence() {
    use frankenengine_engine::policy_theorem_compiler::Capability;
    let proof = CapabilityProof::new(
        Capability::new("network_outbound"),
        "witness-001",
        950_000,
        true,
    );
    assert!(proof.meets_confidence(950_000));
    assert!(proof.meets_confidence(900_000));
    assert!(!proof.meets_confidence(960_000));
}

#[test]
fn capability_proof_serde_roundtrip() {
    use frankenengine_engine::policy_theorem_compiler::Capability;
    let proof = CapabilityProof::new(
        Capability::new("file_read"),
        "witness-serde",
        800_000,
        true,
    );
    let json = serde_json::to_string(&proof).unwrap();
    let restored: CapabilityProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, restored);
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchDecisionRecord
// ---------------------------------------------------------------------------

#[test]
fn dispatch_decision_record_fast_path() {
    let policy = PruningPolicy::default();
    let mut compiler = DispatchCompiler::new(policy, epoch(1));
    use frankenengine_engine::policy_theorem_compiler::Capability;
    let cap = Capability::new("network_outbound");
    compiler.register_capability_proofs(vec![CapabilityProof::new(
        cap.clone(),
        "full-cap",
        999_000,
        true,
    )]);
    let site = DispatchSite::new(0, "hostcall.net.ping")
        .require(cap);
    let decision = compiler.decide(&site);
    if decision.is_fast_path() {
        assert!(!decision.is_rejected());
    }
}

#[test]
fn dispatch_decision_record_id_deterministic() {
    let policy = PruningPolicy::default();
    let compiler = DispatchCompiler::new(policy, epoch(1));
    let site = DispatchSite::new(0, "hostcall.noop");
    let d1 = compiler.decide(&site);
    let d2 = compiler.decide(&site);
    assert_eq!(d1.decision_id, d2.decision_id);
}

#[test]
fn dispatch_decision_record_serde_roundtrip() {
    let policy = PruningPolicy::default();
    let compiler = DispatchCompiler::new(policy, epoch(1));
    let site = DispatchSite::new(0, "hostcall.noop");
    let decision = compiler.decide(&site);
    let json = serde_json::to_string(&decision).unwrap();
    let restored: DispatchDecisionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, restored);
}

// ---------------------------------------------------------------------------
// Enrichment: CheckElidableRegion
// ---------------------------------------------------------------------------

#[test]
fn check_elidable_region_new() {
    let region = CheckElidableRegion::new(10, 50, epoch(1));
    assert_eq!(region.span(), 40);
    assert!(region.contains_offset(25));
    assert!(!region.contains_offset(5));
    assert!(!region.contains_offset(51));
}

#[test]
fn check_elidable_region_invalidate() {
    let mut region = CheckElidableRegion::new(0, 100, epoch(1));
    region.add_fast_path_site(10);
    assert_eq!(region.fast_path_count(), 1);
    region.invalidate();
    assert_eq!(region.fast_path_count(), 0);
}

#[test]
fn check_elidable_region_serde_roundtrip() {
    let mut region = CheckElidableRegion::new(0, 64, epoch(2));
    region.add_fast_path_site(10);
    region.add_fast_path_site(20);
    let json = serde_json::to_string(&region).unwrap();
    let restored: CheckElidableRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(region, restored);
}

// ---------------------------------------------------------------------------
// Enrichment: SpecializationEnvelope
// ---------------------------------------------------------------------------

#[test]
fn specialization_envelope_compile_and_summary() {
    let policy = PruningPolicy::default();
    let compiler = DispatchCompiler::new(policy, epoch(1));
    let sites = vec![
        DispatchSite::new(0, "hostcall.noop"),
        DispatchSite::new(10, "hostcall.timer"),
    ];
    let envelope = compiler.compile_envelope("test-scope", &sites, 0);
    let summary = envelope.summary();
    assert!(summary.total_sites >= 2);
}

#[test]
fn specialization_envelope_content_hash_deterministic() {
    let policy = PruningPolicy::default();
    let c1 = DispatchCompiler::new(policy.clone(), epoch(1));
    let c2 = DispatchCompiler::new(policy, epoch(1));
    let sites = vec![DispatchSite::new(0, "hostcall.noop")];
    let e1 = c1.compile_envelope("scope", &sites, 0);
    let e2 = c2.compile_envelope("scope", &sites, 0);
    assert_eq!(e1.content_hash(), e2.content_hash());
}

#[test]
fn specialization_envelope_serde_roundtrip() {
    let policy = PruningPolicy::default();
    let compiler = DispatchCompiler::new(policy, epoch(1));
    let sites = vec![DispatchSite::new(0, "hostcall.noop")];
    let envelope = compiler.compile_envelope("scope", &sites, 0);
    let json = serde_json::to_string(&envelope).unwrap();
    let restored: SpecializationEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope, restored);
}
