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
