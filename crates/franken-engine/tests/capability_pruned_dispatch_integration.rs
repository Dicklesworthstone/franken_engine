//! Integration tests for capability-pruned dispatch module.

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

use frankenengine_engine::capability_pruned_dispatch::{
    COMPONENT, CapabilityProof, CheckElidableRegion, DEFAULT_MAX_FAST_PATH_SITES,
    DEFAULT_MAX_REGION_SPAN, DEFAULT_MIN_ELISION_CONFIDENCE, DISPATCH_SCHEMA_VERSION,
    DispatchCompiler, DispatchDecisionRecord, DispatchRejection, DispatchRoute, DispatchSite,
    DispatchSpecimenFamily, EnvelopeSummary, FlowProofRef, PruningPolicy, REGION_SCHEMA_VERSION,
    SpecializationEnvelope, dispatch_corpus, run_dispatch_corpus,
};
use frankenengine_engine::policy_theorem_compiler::Capability;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn simple_site(offset: u32, hostcall: &str) -> DispatchSite {
    DispatchSite::new(offset, hostcall)
}

fn simple_proof(cap: Capability) -> CapabilityProof {
    CapabilityProof::new(cap, "witness-001", 950_000, true)
}

fn simple_flow_proof(source: &str, sink: &str) -> FlowProofRef {
    FlowProofRef::new("fp-001", source, sink, "static-analysis", test_epoch())
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_non_empty() {
    assert!(!COMPONENT.is_empty());
    assert!(!DISPATCH_SCHEMA_VERSION.is_empty());
    assert!(!REGION_SCHEMA_VERSION.is_empty());
}

#[test]
fn default_limits_positive() {
    const {
        assert!(DEFAULT_MAX_FAST_PATH_SITES > 0);
        assert!(DEFAULT_MIN_ELISION_CONFIDENCE > 0);
        assert!(DEFAULT_MAX_REGION_SPAN > 0);
    }
}

// ---------------------------------------------------------------------------
// PruningPolicy
// ---------------------------------------------------------------------------

#[test]
fn policy_default_has_reasonable_values() {
    let p = PruningPolicy::default();
    assert!(p.max_fast_path_sites > 0);
    assert!(p.min_elision_confidence > 0);
    assert!(p.max_region_span > 0);
}

#[test]
fn policy_hash_deterministic() {
    let p1 = PruningPolicy::default();
    let p2 = PruningPolicy::default();
    assert_eq!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_differs_on_change() {
    let p1 = PruningPolicy::default();
    let mut p2 = PruningPolicy::default();
    p2.max_fast_path_sites = 1;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_display_non_empty() {
    let p = PruningPolicy::default();
    assert!(!format!("{p}").is_empty());
}

#[test]
fn policy_serde_round_trip() {
    let p = PruningPolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    let back: PruningPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// DispatchSite
// ---------------------------------------------------------------------------

#[test]
fn dispatch_site_construction() {
    let site = simple_site(10, "fs.read");
    assert_eq!(site.offset, 10);
    assert_eq!(site.hostcall_id, "fs.read");
    assert!(site.required_capabilities.is_empty());
}

#[test]
fn dispatch_site_with_capability() {
    let site = simple_site(10, "fs.read").require(Capability::new("file_read"));
    assert!(
        site.required_capabilities
            .contains(&Capability::new("file_read"))
    );
}

#[test]
fn dispatch_site_with_ifc_flow() {
    let site = simple_site(10, "db.query").with_ifc_flow("user-input", "sql-sink");
    assert!(site.requires_flow_proof);
    assert_eq!(site.source_label.as_deref(), Some("user-input"));
    assert_eq!(site.sink_clearance.as_deref(), Some("sql-sink"));
}

#[test]
fn dispatch_site_content_hash_deterministic() {
    let s1 = simple_site(10, "fs.read").require(Capability::new("file_read"));
    let s2 = simple_site(10, "fs.read").require(Capability::new("file_read"));
    assert_eq!(s1.content_hash(), s2.content_hash());
}

#[test]
fn dispatch_site_content_hash_differs() {
    let s1 = simple_site(10, "fs.read");
    let s2 = simple_site(20, "fs.read");
    assert_ne!(s1.content_hash(), s2.content_hash());
}

#[test]
fn dispatch_site_display() {
    let site = simple_site(10, "fs.read");
    assert!(!format!("{site}").is_empty());
}

#[test]
fn dispatch_site_serde_round_trip() {
    let site = simple_site(10, "fs.read")
        .require(Capability::new("file_read"))
        .with_ifc_flow("src", "sink");
    let json = serde_json::to_string(&site).unwrap();
    let back: DispatchSite = serde_json::from_str(&json).unwrap();
    assert_eq!(site, back);
}

// ---------------------------------------------------------------------------
// CapabilityProof
// ---------------------------------------------------------------------------

#[test]
fn capability_proof_meets_confidence() {
    let proof = simple_proof(Capability::new("file_read"));
    assert!(proof.meets_confidence(900_000));
    assert!(!proof.meets_confidence(1_000_000));
}

#[test]
fn capability_proof_display() {
    let proof = simple_proof(Capability::new("file_read"));
    assert!(!format!("{proof}").is_empty());
}

#[test]
fn capability_proof_serde_round_trip() {
    let proof = simple_proof(Capability::new("network_connect"));
    let json = serde_json::to_string(&proof).unwrap();
    let back: CapabilityProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, back);
}

// ---------------------------------------------------------------------------
// FlowProofRef
// ---------------------------------------------------------------------------

#[test]
fn flow_proof_construction() {
    let fp = simple_flow_proof("user-input", "sql-sink");
    assert_eq!(fp.source_label, "user-input");
    assert_eq!(fp.sink_clearance, "sql-sink");
}

#[test]
fn flow_proof_display() {
    let fp = simple_flow_proof("src", "sink");
    assert!(!format!("{fp}").is_empty());
}

#[test]
fn flow_proof_serde_round_trip() {
    let fp = simple_flow_proof("src", "sink");
    let json = serde_json::to_string(&fp).unwrap();
    let back: FlowProofRef = serde_json::from_str(&json).unwrap();
    assert_eq!(fp, back);
}

// ---------------------------------------------------------------------------
// DispatchRoute
// ---------------------------------------------------------------------------

#[test]
fn dispatch_route_fast_path_display() {
    let route = DispatchRoute::FastPath;
    let s = format!("{route}");
    assert!(!s.is_empty());
}

#[test]
fn dispatch_route_checked_path_display() {
    let mut missing = BTreeSet::new();
    missing.insert(Capability::new("file_read"));
    let route = DispatchRoute::CheckedPath {
        missing_proofs: missing,
    };
    let s = format!("{route}");
    assert!(!s.is_empty());
}

#[test]
fn dispatch_route_serde_round_trip() {
    let route = DispatchRoute::FastPath;
    let json = serde_json::to_string(&route).unwrap();
    let back: DispatchRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(route, back);
}

// ---------------------------------------------------------------------------
// CheckElidableRegion
// ---------------------------------------------------------------------------

#[test]
fn elidable_region_construction() {
    let region = CheckElidableRegion::new(0, 100, test_epoch());
    assert_eq!(region.span(), 100);
    assert!(region.valid);
    assert_eq!(region.fast_path_count(), 0);
}

#[test]
fn elidable_region_contains_offset() {
    let region = CheckElidableRegion::new(10, 50, test_epoch());
    assert!(region.contains_offset(10));
    assert!(region.contains_offset(25));
    assert!(region.contains_offset(49));
    assert!(!region.contains_offset(50)); // exclusive end
    assert!(!region.contains_offset(9));
}

#[test]
fn elidable_region_add_fast_path() {
    let mut region = CheckElidableRegion::new(0, 100, test_epoch());
    region.add_fast_path_site(10);
    region.add_fast_path_site(20);
    assert_eq!(region.fast_path_count(), 2);
}

#[test]
fn elidable_region_invalidate() {
    let mut region = CheckElidableRegion::new(0, 100, test_epoch());
    assert!(region.valid);
    region.invalidate();
    assert!(!region.valid);
}

#[test]
fn elidable_region_display() {
    let region = CheckElidableRegion::new(0, 100, test_epoch());
    assert!(!format!("{region}").is_empty());
}

#[test]
fn elidable_region_serde_round_trip() {
    let mut region = CheckElidableRegion::new(0, 100, test_epoch());
    region.add_fast_path_site(10);
    let json = serde_json::to_string(&region).unwrap();
    let back: CheckElidableRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(region, back);
}

// ---------------------------------------------------------------------------
// DispatchCompiler — decide
// ---------------------------------------------------------------------------

#[test]
fn compiler_decide_fast_path_with_proof() {
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_capability_proofs(vec![simple_proof(Capability::new("file_read"))]);

    let site = simple_site(0, "fs.read").require(Capability::new("file_read"));
    let decision = compiler.decide(&site);
    assert!(decision.is_fast_path());
    assert!(!decision.is_rejected());
}

#[test]
fn compiler_decide_checked_path_without_proof() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let site = simple_site(0, "fs.read").require(Capability::new("file_read"));
    let decision = compiler.decide(&site);
    assert!(!decision.is_fast_path());
}

#[test]
fn compiler_decide_no_capabilities_fast_path() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let site = simple_site(0, "noop");
    let decision = compiler.decide(&site);
    // No capabilities required → fast path
    assert!(decision.is_fast_path());
}

#[test]
fn compiler_decide_with_ifc_flow_proof() {
    let policy = PruningPolicy {
        require_ifc_proofs: true,
        ..PruningPolicy::default()
    };
    let mut compiler = DispatchCompiler::new(policy, test_epoch());
    compiler.register_flow_proofs(vec![simple_flow_proof("user-input", "sql-sink")]);

    let site = simple_site(0, "db.query").with_ifc_flow("user-input", "sql-sink");
    let decision = compiler.decide(&site);
    assert!(decision.is_fast_path());
}

#[test]
fn compiler_decide_missing_flow_proof_rejected() {
    let policy = PruningPolicy {
        require_ifc_proofs: true,
        ..PruningPolicy::default()
    };
    let compiler = DispatchCompiler::new(policy, test_epoch());
    let site = simple_site(0, "db.query").with_ifc_flow("user-input", "sql-sink");
    let decision = compiler.decide(&site);
    assert!(decision.is_rejected());
}

#[test]
fn decision_record_display() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let site = simple_site(0, "noop");
    let decision = compiler.decide(&site);
    assert!(!format!("{decision}").is_empty());
}

#[test]
fn decision_record_serde_round_trip() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let site = simple_site(0, "noop");
    let decision = compiler.decide(&site);
    let json = serde_json::to_string(&decision).unwrap();
    let back: DispatchDecisionRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

// ---------------------------------------------------------------------------
// DispatchCompiler — compile_envelope
// ---------------------------------------------------------------------------

#[test]
fn compile_envelope_empty_sites() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let envelope = compiler.compile_envelope("scope-1", &[], 1);
    assert_eq!(envelope.fast_path_count, 0);
    assert_eq!(envelope.checked_path_count, 0);
    assert_eq!(envelope.rejected_count, 0);
}

#[test]
fn compile_envelope_with_fast_path_sites() {
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_capability_proofs(vec![simple_proof(Capability::new("file_read"))]);

    let sites = vec![
        simple_site(0, "fs.read").require(Capability::new("file_read")),
        simple_site(4, "fs.stat").require(Capability::new("file_read")),
        simple_site(8, "noop"),
    ];
    let envelope = compiler.compile_envelope("scope-fs", &sites, 1);
    assert!(envelope.fast_path_count >= 2);
}

#[test]
fn compile_envelope_summary() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let sites = vec![simple_site(0, "noop"), simple_site(4, "noop2")];
    let envelope = compiler.compile_envelope("scope-sum", &sites, 1);
    let summary = envelope.summary();
    assert_eq!(summary.scope_id, "scope-sum");
    assert_eq!(summary.total_sites, 2);
}

#[test]
fn compile_envelope_content_hash_deterministic() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let sites = vec![simple_site(0, "noop")];
    let e1 = compiler.compile_envelope("scope-1", &sites, 1);
    let e2 = compiler.compile_envelope("scope-1", &sites, 1);
    assert_eq!(e1.content_hash(), e2.content_hash());
}

#[test]
fn compile_envelope_display() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let envelope = compiler.compile_envelope("scope-1", &[], 1);
    assert!(!format!("{envelope}").is_empty());
}

#[test]
fn compile_envelope_serde_round_trip() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let sites = vec![simple_site(0, "noop")];
    let envelope = compiler.compile_envelope("scope-serde", &sites, 1);
    let json = serde_json::to_string(&envelope).unwrap();
    let back: SpecializationEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope, back);
}

#[test]
fn envelope_summary_serde_round_trip() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let envelope = compiler.compile_envelope("scope-1", &[], 1);
    let summary = envelope.summary();
    let json = serde_json::to_string(&summary).unwrap();
    let back: EnvelopeSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

#[test]
fn dispatch_corpus_non_empty() {
    let corpus = dispatch_corpus();
    assert!(!corpus.is_empty());
}

#[test]
fn dispatch_corpus_families_covered() {
    let corpus = dispatch_corpus();
    let mut families: Vec<_> = corpus.iter().map(|(f, _)| format!("{f:?}")).collect();
    families.dedup();
    assert!(families.len() >= 3);
}

#[test]
fn run_dispatch_corpus_all_pass() {
    let results = run_dispatch_corpus();
    assert!(!results.is_empty());
    for (family, passed) in &results {
        assert!(passed, "corpus specimen for {:?} failed", family);
    }
}

// ---------------------------------------------------------------------------
// DispatchSpecimenFamily
// ---------------------------------------------------------------------------

#[test]
fn specimen_family_display() {
    let families = [
        DispatchSpecimenFamily::SingleSite,
        DispatchSpecimenFamily::MixedCapabilities,
        DispatchSpecimenFamily::IfcRequired,
        DispatchSpecimenFamily::ContiguousRegion,
        DispatchSpecimenFamily::DegradedMode,
    ];
    for f in &families {
        assert!(!format!("{f}").is_empty());
    }
}

#[test]
fn specimen_family_serde_round_trip() {
    let f = DispatchSpecimenFamily::SingleSite;
    let json = serde_json::to_string(&f).unwrap();
    let back: DispatchSpecimenFamily = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ---------------------------------------------------------------------------
// Enrichment: Constants — exact values
// ---------------------------------------------------------------------------

#[test]
fn component_exact_value() {
    assert_eq!(COMPONENT, "capability_pruned_dispatch");
}

#[test]
fn dispatch_schema_version_exact() {
    assert_eq!(DISPATCH_SCHEMA_VERSION, "1.0.0");
}

#[test]
fn region_schema_version_exact() {
    assert_eq!(REGION_SCHEMA_VERSION, "1.0.0");
}

#[test]
fn default_max_fast_path_sites_exact() {
    assert_eq!(DEFAULT_MAX_FAST_PATH_SITES, 256);
}

#[test]
fn default_min_elision_confidence_exact() {
    assert_eq!(DEFAULT_MIN_ELISION_CONFIDENCE, 950_000);
}

#[test]
fn default_max_region_span_exact() {
    assert_eq!(DEFAULT_MAX_REGION_SPAN, 512);
}

// ---------------------------------------------------------------------------
// Enrichment: PruningPolicy — field-level coverage
// ---------------------------------------------------------------------------

#[test]
fn policy_default_matches_constants() {
    let p = PruningPolicy::default();
    assert_eq!(p.max_fast_path_sites, DEFAULT_MAX_FAST_PATH_SITES);
    assert_eq!(p.min_elision_confidence, DEFAULT_MIN_ELISION_CONFIDENCE);
    assert_eq!(p.max_region_span, DEFAULT_MAX_REGION_SPAN);
    assert!(p.require_ifc_proofs);
    assert!(!p.allow_degraded_dispatch);
    assert_eq!(p.min_witness_count, 1);
    assert!(p.emit_rejection_details);
}

#[test]
fn policy_display_contains_fields() {
    let p = PruningPolicy::default();
    let s = format!("{p}");
    assert!(s.contains("pruning-policy"));
    assert!(s.contains("max-sites="));
    assert!(s.contains("min-conf="));
    assert!(s.contains("ifc="));
    assert!(s.contains("degraded="));
}

#[test]
fn policy_hash_starts_with_ph_prefix() {
    let p = PruningPolicy::default();
    assert!(p.policy_hash().starts_with("ph-"));
}

#[test]
fn policy_hash_length_consistent() {
    let p = PruningPolicy::default();
    let h = p.policy_hash();
    // "ph-" + 16 hex chars = 19
    assert_eq!(h.len(), 19);
}

#[test]
fn policy_hash_differs_on_min_elision_confidence() {
    let p1 = PruningPolicy::default();
    let mut p2 = PruningPolicy::default();
    p2.min_elision_confidence = 800_000;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_differs_on_max_region_span() {
    let p1 = PruningPolicy::default();
    let mut p2 = PruningPolicy::default();
    p2.max_region_span = 1024;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_differs_on_require_ifc_proofs() {
    let p1 = PruningPolicy::default();
    let mut p2 = PruningPolicy::default();
    p2.require_ifc_proofs = false;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_differs_on_allow_degraded() {
    let p1 = PruningPolicy::default();
    let mut p2 = PruningPolicy::default();
    p2.allow_degraded_dispatch = true;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_differs_on_min_witness_count() {
    let p1 = PruningPolicy::default();
    let mut p2 = PruningPolicy::default();
    p2.min_witness_count = 5;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_hash_differs_on_emit_rejection_details() {
    let p1 = PruningPolicy::default();
    let mut p2 = PruningPolicy::default();
    p2.emit_rejection_details = false;
    assert_ne!(p1.policy_hash(), p2.policy_hash());
}

#[test]
fn policy_clone_eq() {
    let p = PruningPolicy::default();
    let p2 = p.clone();
    assert_eq!(p, p2);
}

#[test]
fn policy_serde_custom_values() {
    let p = PruningPolicy {
        max_fast_path_sites: 128,
        min_elision_confidence: 800_000,
        max_region_span: 1024,
        require_ifc_proofs: false,
        allow_degraded_dispatch: true,
        min_witness_count: 3,
        emit_rejection_details: false,
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: PruningPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchSite — edge cases
// ---------------------------------------------------------------------------

#[test]
fn dispatch_site_multiple_capabilities() {
    let site = simple_site(0, "fs.copy")
        .require(Capability::new("file_read"))
        .require(Capability::new("file_write"));
    assert_eq!(site.required_capabilities.len(), 2);
}

#[test]
fn dispatch_site_duplicate_capability_deduplicated() {
    let site = simple_site(0, "fs.read")
        .require(Capability::new("file_read"))
        .require(Capability::new("file_read"));
    assert_eq!(site.required_capabilities.len(), 1);
}

#[test]
fn dispatch_site_display_contains_offset_and_hostcall() {
    let site = simple_site(42, "net.connect");
    let s = format!("{site}");
    assert!(s.contains("dispatch@42"));
    assert!(s.contains("net.connect"));
}

#[test]
fn dispatch_site_display_shows_cap_count() {
    let site = simple_site(0, "fs.read")
        .require(Capability::new("a"))
        .require(Capability::new("b"));
    let s = format!("{site}");
    assert!(s.contains("caps=2"));
}

#[test]
fn dispatch_site_display_shows_ifc_flag() {
    let site = simple_site(0, "db.query").with_ifc_flow("src", "sink");
    let s = format!("{site}");
    assert!(s.contains("ifc=true"));
}

#[test]
fn dispatch_site_content_hash_differs_by_hostcall() {
    let s1 = simple_site(0, "fs.read");
    let s2 = simple_site(0, "fs.write");
    assert_ne!(s1.content_hash(), s2.content_hash());
}

#[test]
fn dispatch_site_content_hash_differs_with_ifc_flow() {
    let s1 = simple_site(0, "db.query");
    let s2 = simple_site(0, "db.query").with_ifc_flow("src", "sink");
    assert_ne!(s1.content_hash(), s2.content_hash());
}

#[test]
fn dispatch_site_content_hash_differs_by_capability() {
    let s1 = simple_site(0, "fs.read").require(Capability::new("a"));
    let s2 = simple_site(0, "fs.read").require(Capability::new("b"));
    assert_ne!(s1.content_hash(), s2.content_hash());
}

#[test]
fn dispatch_site_clone_eq() {
    let site = simple_site(10, "fs.read")
        .require(Capability::new("file_read"))
        .with_ifc_flow("src", "sink");
    let site2 = site.clone();
    assert_eq!(site, site2);
}

// ---------------------------------------------------------------------------
// Enrichment: CapabilityProof — edge cases
// ---------------------------------------------------------------------------

#[test]
fn capability_proof_inactive_fails_all_thresholds() {
    let proof = CapabilityProof::new(Capability::new("file_read"), "w1", 1_000_000, false);
    assert!(!proof.meets_confidence(0));
    assert!(!proof.meets_confidence(500_000));
    assert!(!proof.meets_confidence(1_000_000));
}

#[test]
fn capability_proof_zero_confidence_meets_zero() {
    let proof = CapabilityProof::new(Capability::new("file_read"), "w1", 0, true);
    assert!(proof.meets_confidence(0));
    assert!(!proof.meets_confidence(1));
}

#[test]
fn capability_proof_exact_threshold_boundary() {
    let proof = CapabilityProof::new(Capability::new("file_read"), "w1", 950_000, true);
    assert!(proof.meets_confidence(950_000));
    assert!(!proof.meets_confidence(950_001));
}

#[test]
fn capability_proof_max_confidence() {
    let proof = CapabilityProof::new(Capability::new("file_read"), "w1", 1_000_000, true);
    assert!(proof.meets_confidence(1_000_000));
}

#[test]
fn capability_proof_display_contains_fields() {
    let proof = CapabilityProof::new(Capability::new("net_connect"), "w-abc", 800_000, true);
    let s = format!("{proof}");
    assert!(s.contains("cap-proof"));
    assert!(s.contains("w-abc"));
    assert!(s.contains("800000"));
    assert!(s.contains("true"));
}

#[test]
fn capability_proof_clone_eq() {
    let p1 = simple_proof(Capability::new("x"));
    let p2 = p1.clone();
    assert_eq!(p1, p2);
}

// ---------------------------------------------------------------------------
// Enrichment: FlowProofRef — edge cases
// ---------------------------------------------------------------------------

#[test]
fn flow_proof_ref_all_fields() {
    let fp = FlowProofRef::new("fp-100", "Secret", "Public", "taint-analysis", test_epoch());
    assert_eq!(fp.proof_id, "fp-100");
    assert_eq!(fp.source_label, "Secret");
    assert_eq!(fp.sink_clearance, "Public");
    assert_eq!(fp.proof_method, "taint-analysis");
    assert_eq!(fp.epoch, test_epoch());
}

#[test]
fn flow_proof_display_contains_fields() {
    let fp = simple_flow_proof("src-label", "sink-label");
    let s = format!("{fp}");
    assert!(s.contains("flow-proof"));
    assert!(s.contains("fp-001"));
    assert!(s.contains("static-analysis"));
}

#[test]
fn flow_proof_clone_eq() {
    let fp1 = simple_flow_proof("a", "b");
    let fp2 = fp1.clone();
    assert_eq!(fp1, fp2);
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchRejection — Display for every variant
// ---------------------------------------------------------------------------

#[test]
fn rejection_no_witness_display() {
    let r = DispatchRejection::NoWitness;
    assert_eq!(format!("{r}"), "no-witness");
}

#[test]
fn rejection_witness_inactive_display() {
    let r = DispatchRejection::WitnessInactive {
        witness_id: "w-42".into(),
    };
    let s = format!("{r}");
    assert!(s.contains("witness-inactive"));
    assert!(s.contains("w-42"));
}

#[test]
fn rejection_insufficient_confidence_display() {
    let r = DispatchRejection::InsufficientConfidence {
        required_millionths: 950_000,
        actual_millionths: 800_000,
    };
    let s = format!("{r}");
    assert!(s.contains("insufficient-confidence"));
    assert!(s.contains("950000"));
    assert!(s.contains("800000"));
}

#[test]
fn rejection_missing_flow_proof_display() {
    let r = DispatchRejection::MissingFlowProof {
        source_label: "Secret".into(),
        sink_clearance: "Public".into(),
    };
    let s = format!("{r}");
    assert!(s.contains("missing-flow-proof"));
}

#[test]
fn rejection_flow_proof_stale_display() {
    let r = DispatchRejection::FlowProofStale {
        proof_id: "fp-old".into(),
        proof_epoch: 3,
    };
    let s = format!("{r}");
    assert!(s.contains("flow-proof-stale"));
    assert!(s.contains("fp-old"));
    assert!(s.contains("epoch=3"));
}

#[test]
fn rejection_capability_denied_display() {
    let r = DispatchRejection::CapabilityDenied {
        capability: Capability::new("dangerous"),
    };
    let s = format!("{r}");
    assert!(s.contains("capability-denied"));
}

#[test]
fn rejection_envelope_full_display() {
    assert_eq!(
        format!("{}", DispatchRejection::EnvelopeFull),
        "envelope-full"
    );
}

#[test]
fn rejection_degraded_not_allowed_display() {
    assert_eq!(
        format!("{}", DispatchRejection::DegradedNotAllowed),
        "degraded-not-allowed"
    );
}

#[test]
fn rejection_epoch_mismatch_display() {
    let r = DispatchRejection::EpochMismatch {
        expected: SecurityEpoch::from_raw(1),
        actual: SecurityEpoch::from_raw(2),
    };
    let s = format!("{r}");
    assert!(s.contains("epoch-mismatch"));
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchRejection — serde for every variant
// ---------------------------------------------------------------------------

#[test]
fn rejection_no_witness_serde() {
    let r = DispatchRejection::NoWitness;
    let json = serde_json::to_string(&r).unwrap();
    let back: DispatchRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn rejection_witness_inactive_serde() {
    let r = DispatchRejection::WitnessInactive {
        witness_id: "w-99".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DispatchRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn rejection_insufficient_confidence_serde() {
    let r = DispatchRejection::InsufficientConfidence {
        required_millionths: 950_000,
        actual_millionths: 800_000,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DispatchRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn rejection_missing_flow_proof_serde() {
    let r = DispatchRejection::MissingFlowProof {
        source_label: "Secret".into(),
        sink_clearance: "Public".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DispatchRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn rejection_flow_proof_stale_serde() {
    let r = DispatchRejection::FlowProofStale {
        proof_id: "fp-stale".into(),
        proof_epoch: 7,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DispatchRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn rejection_capability_denied_serde() {
    let r = DispatchRejection::CapabilityDenied {
        capability: Capability::new("fs_admin"),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DispatchRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn rejection_envelope_full_serde() {
    let r = DispatchRejection::EnvelopeFull;
    let json = serde_json::to_string(&r).unwrap();
    let back: DispatchRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn rejection_degraded_not_allowed_serde() {
    let r = DispatchRejection::DegradedNotAllowed;
    let json = serde_json::to_string(&r).unwrap();
    let back: DispatchRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn rejection_epoch_mismatch_serde() {
    let r = DispatchRejection::EpochMismatch {
        expected: SecurityEpoch::from_raw(5),
        actual: SecurityEpoch::from_raw(10),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: DispatchRejection = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchRoute — serde for all variants
// ---------------------------------------------------------------------------

#[test]
fn dispatch_route_checked_path_serde() {
    let mut missing = BTreeSet::new();
    missing.insert(Capability::new("file_read"));
    missing.insert(Capability::new("net_connect"));
    let route = DispatchRoute::CheckedPath {
        missing_proofs: missing,
    };
    let json = serde_json::to_string(&route).unwrap();
    let back: DispatchRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(route, back);
}

#[test]
fn dispatch_route_rejected_serde() {
    let route = DispatchRoute::Rejected {
        reason: DispatchRejection::NoWitness,
    };
    let json = serde_json::to_string(&route).unwrap();
    let back: DispatchRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(route, back);
}

#[test]
fn dispatch_route_rejected_with_data_serde() {
    let route = DispatchRoute::Rejected {
        reason: DispatchRejection::InsufficientConfidence {
            required_millionths: 950_000,
            actual_millionths: 400_000,
        },
    };
    let json = serde_json::to_string(&route).unwrap();
    let back: DispatchRoute = serde_json::from_str(&json).unwrap();
    assert_eq!(route, back);
}

#[test]
fn dispatch_route_rejected_display() {
    let route = DispatchRoute::Rejected {
        reason: DispatchRejection::EnvelopeFull,
    };
    let s = format!("{route}");
    assert!(s.contains("rejected"));
    assert!(s.contains("envelope-full"));
}

#[test]
fn dispatch_route_fast_path_eq() {
    assert_eq!(DispatchRoute::FastPath, DispatchRoute::FastPath);
}

#[test]
fn dispatch_route_checked_path_display_with_count() {
    let mut missing = BTreeSet::new();
    missing.insert(Capability::new("a"));
    missing.insert(Capability::new("b"));
    missing.insert(Capability::new("c"));
    let route = DispatchRoute::CheckedPath {
        missing_proofs: missing,
    };
    let s = format!("{route}");
    assert!(s.contains("3 missing"));
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchDecisionRecord — deeper coverage
// ---------------------------------------------------------------------------

#[test]
fn decision_record_compute_id_prefix() {
    let id = DispatchDecisionRecord::compute_id(0, "noop", &DispatchRoute::FastPath, test_epoch());
    assert!(id.starts_with("dd-"));
    assert_eq!(id.len(), 19); // "dd-" + 16 hex
}

#[test]
fn decision_record_compute_id_differs_by_offset() {
    let id1 =
        DispatchDecisionRecord::compute_id(0, "fs.read", &DispatchRoute::FastPath, test_epoch());
    let id2 =
        DispatchDecisionRecord::compute_id(4, "fs.read", &DispatchRoute::FastPath, test_epoch());
    assert_ne!(id1, id2);
}

#[test]
fn decision_record_compute_id_differs_by_hostcall() {
    let id1 =
        DispatchDecisionRecord::compute_id(0, "fs.read", &DispatchRoute::FastPath, test_epoch());
    let id2 =
        DispatchDecisionRecord::compute_id(0, "net.send", &DispatchRoute::FastPath, test_epoch());
    assert_ne!(id1, id2);
}

#[test]
fn decision_record_compute_id_differs_by_route() {
    let id1 =
        DispatchDecisionRecord::compute_id(0, "fs.read", &DispatchRoute::FastPath, test_epoch());
    let id2 = DispatchDecisionRecord::compute_id(
        0,
        "fs.read",
        &DispatchRoute::CheckedPath {
            missing_proofs: BTreeSet::new(),
        },
        test_epoch(),
    );
    assert_ne!(id1, id2);
}

#[test]
fn decision_record_compute_id_differs_by_epoch() {
    let id1 = DispatchDecisionRecord::compute_id(
        0,
        "fs.read",
        &DispatchRoute::FastPath,
        SecurityEpoch::from_raw(1),
    );
    let id2 = DispatchDecisionRecord::compute_id(
        0,
        "fs.read",
        &DispatchRoute::FastPath,
        SecurityEpoch::from_raw(2),
    );
    assert_ne!(id1, id2);
}

#[test]
fn decision_record_is_rejected_true() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let site = simple_site(0, "fs.read").require(Capability::new("file_read"));
    let decision = compiler.decide(&site);
    assert!(decision.is_rejected());
    assert!(!decision.is_fast_path());
}

#[test]
fn decision_record_display_contains_hostcall() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let site = simple_site(0, "my_hostcall");
    let decision = compiler.decide(&site);
    let s = format!("{decision}");
    assert!(s.contains("dispatch-decision"));
    assert!(s.contains("my_hostcall"));
}

// ---------------------------------------------------------------------------
// Enrichment: CheckElidableRegion — edge cases
// ---------------------------------------------------------------------------

#[test]
fn elidable_region_zero_span() {
    let region = CheckElidableRegion::new(50, 50, test_epoch());
    assert_eq!(region.span(), 0);
    assert!(!region.contains_offset(50));
}

#[test]
fn elidable_region_single_offset_span() {
    let region = CheckElidableRegion::new(10, 11, test_epoch());
    assert_eq!(region.span(), 1);
    assert!(region.contains_offset(10));
    assert!(!region.contains_offset(11));
}

#[test]
fn elidable_region_add_site_outside_range_ignored() {
    let mut region = CheckElidableRegion::new(10, 20, test_epoch());
    region.add_fast_path_site(5);
    region.add_fast_path_site(20);
    region.add_fast_path_site(100);
    assert_eq!(region.fast_path_count(), 0);
}

#[test]
fn elidable_region_fast_path_sites_sorted() {
    let mut region = CheckElidableRegion::new(0, 100, test_epoch());
    region.add_fast_path_site(50);
    region.add_fast_path_site(10);
    region.add_fast_path_site(30);
    assert_eq!(region.fast_path_count(), 3);
    // sites should be sorted after each insertion
    let json = serde_json::to_string(&region).unwrap();
    let back: CheckElidableRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(back.fast_path_sites, vec![10, 30, 50]);
}

#[test]
fn elidable_region_id_prefix() {
    let region = CheckElidableRegion::new(0, 64, test_epoch());
    assert!(region.region_id.starts_with("cer-"));
}

#[test]
fn elidable_region_id_deterministic() {
    let r1 = CheckElidableRegion::new(10, 50, test_epoch());
    let r2 = CheckElidableRegion::new(10, 50, test_epoch());
    assert_eq!(r1.region_id, r2.region_id);
}

#[test]
fn elidable_region_id_differs_by_bounds() {
    let r1 = CheckElidableRegion::new(0, 64, test_epoch());
    let r2 = CheckElidableRegion::new(0, 128, test_epoch());
    assert_ne!(r1.region_id, r2.region_id);
}

#[test]
fn elidable_region_id_differs_by_epoch() {
    let r1 = CheckElidableRegion::new(0, 64, SecurityEpoch::from_raw(1));
    let r2 = CheckElidableRegion::new(0, 64, SecurityEpoch::from_raw(2));
    assert_ne!(r1.region_id, r2.region_id);
}

#[test]
fn elidable_region_schema_version_set() {
    let region = CheckElidableRegion::new(0, 100, test_epoch());
    assert_eq!(region.schema_version, REGION_SCHEMA_VERSION);
}

#[test]
fn elidable_region_display_shows_validity() {
    let mut region = CheckElidableRegion::new(0, 100, test_epoch());
    let s1 = format!("{region}");
    assert!(s1.contains("valid=true"));
    region.invalidate();
    let s2 = format!("{region}");
    assert!(s2.contains("valid=false"));
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchCompiler — more decision scenarios
// ---------------------------------------------------------------------------

#[test]
fn compiler_inactive_witness_rejection_includes_witness_id() {
    let mut proof = CapabilityProof::new(Capability::new("file_read"), "w-dead", 990_000, false);
    proof.witness_active = false;
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_capability_proofs(vec![proof]);

    let site = simple_site(0, "fs.read").require(Capability::new("file_read"));
    let decision = compiler.decide(&site);
    assert!(decision.is_rejected());
    if let DispatchRoute::Rejected { reason } = &decision.route {
        if let DispatchRejection::WitnessInactive { witness_id } = reason {
            assert_eq!(witness_id, "w-dead");
        } else {
            panic!("expected WitnessInactive");
        }
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn compiler_insufficient_confidence_rejection_values() {
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_capability_proofs(vec![CapabilityProof::new(
        Capability::new("file_read"),
        "w1",
        500_000,
        true,
    )]);

    let site = simple_site(0, "fs.read").require(Capability::new("file_read"));
    let decision = compiler.decide(&site);
    assert!(decision.is_rejected());
    if let DispatchRoute::Rejected { reason } = &decision.route {
        if let DispatchRejection::InsufficientConfidence {
            required_millionths,
            actual_millionths,
        } = reason
        {
            assert_eq!(*required_millionths, DEFAULT_MIN_ELISION_CONFIDENCE);
            assert_eq!(*actual_millionths, 500_000);
        } else {
            panic!("expected InsufficientConfidence, got {reason}");
        }
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn compiler_stale_flow_proof_rejection() {
    let old_epoch = SecurityEpoch::from_raw(0);
    let current_epoch = SecurityEpoch::from_raw(5);
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), current_epoch);
    compiler.register_flow_proofs(vec![FlowProofRef::new(
        "fp-old",
        "user-input",
        "sql-sink",
        "static-analysis",
        old_epoch,
    )]);

    let site = simple_site(0, "db.query").with_ifc_flow("user-input", "sql-sink");
    let decision = compiler.decide(&site);
    assert!(decision.is_rejected());
    if let DispatchRoute::Rejected { reason } = &decision.route {
        if let DispatchRejection::FlowProofStale {
            proof_id,
            proof_epoch,
        } = reason
        {
            assert_eq!(proof_id, "fp-old");
            assert_eq!(*proof_epoch, 0);
        } else {
            panic!("expected FlowProofStale, got {reason}");
        }
    } else {
        panic!("expected Rejected");
    }
}

#[test]
fn compiler_degraded_mode_with_missing_cap() {
    let policy = PruningPolicy {
        allow_degraded_dispatch: true,
        ..PruningPolicy::default()
    };
    let compiler = DispatchCompiler::new(policy, test_epoch());
    let site = simple_site(0, "fs.read").require(Capability::new("file_read"));
    let decision = compiler.decide(&site);
    assert!(!decision.is_fast_path());
    assert!(!decision.is_rejected());
    if let DispatchRoute::CheckedPath { missing_proofs } = &decision.route {
        assert!(missing_proofs.contains(&Capability::new("file_read")));
    } else {
        panic!("expected CheckedPath");
    }
}

#[test]
fn compiler_ifc_not_required_skips_proof_check() {
    let policy = PruningPolicy {
        require_ifc_proofs: false,
        ..PruningPolicy::default()
    };
    let compiler = DispatchCompiler::new(policy, test_epoch());
    let site = simple_site(0, "data.send").with_ifc_flow("Secret", "Public");
    let decision = compiler.decide(&site);
    assert!(decision.is_fast_path());
}

#[test]
fn compiler_multiple_proofs_best_confidence_selected() {
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_capability_proofs(vec![
        CapabilityProof::new(Capability::new("file_read"), "w-low", 960_000, true),
        CapabilityProof::new(Capability::new("file_read"), "w-high", 990_000, true),
    ]);

    let site = simple_site(0, "fs.read").require(Capability::new("file_read"));
    let decision = compiler.decide(&site);
    assert!(decision.is_fast_path());
    // Best proof should be included
    assert!(!decision.capability_proofs.is_empty());
}

#[test]
fn compiler_decision_sequence_zero_for_standalone() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let site = simple_site(0, "noop");
    let decision = compiler.decide(&site);
    assert_eq!(decision.decision_sequence, 0);
}

// ---------------------------------------------------------------------------
// Enrichment: compile_envelope — deeper scenarios
// ---------------------------------------------------------------------------

#[test]
fn compile_envelope_all_rejected() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let sites = vec![
        simple_site(0, "fs.read").require(Capability::new("a")),
        simple_site(4, "fs.write").require(Capability::new("b")),
    ];
    let envelope = compiler.compile_envelope("scope-rej", &sites, 1);
    assert_eq!(envelope.fast_path_count, 0);
    assert_eq!(envelope.rejected_count, 2);
    assert!(envelope.elidable_regions.is_empty());
}

#[test]
fn compile_envelope_envelope_full_rejection() {
    let policy = PruningPolicy {
        max_fast_path_sites: 1,
        ..PruningPolicy::default()
    };
    let compiler = DispatchCompiler::new(policy, test_epoch());
    let sites = vec![
        simple_site(0, "noop1"),
        simple_site(4, "noop2"),
        simple_site(8, "noop3"),
    ];
    let envelope = compiler.compile_envelope("scope-full", &sites, 1);
    assert_eq!(envelope.fast_path_count, 1);
    // Remaining 2 rejected as EnvelopeFull
    assert_eq!(envelope.rejected_count, 2);
}

#[test]
fn compile_envelope_decision_sequences_monotonic() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let sites = vec![
        simple_site(0, "noop1"),
        simple_site(4, "noop2"),
        simple_site(8, "noop3"),
    ];
    let envelope = compiler.compile_envelope("scope-seq", &sites, 1);
    for (i, d) in envelope.decisions.iter().enumerate() {
        assert_eq!(d.decision_sequence, i as u64);
    }
}

#[test]
fn compile_envelope_schema_version_set() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let envelope = compiler.compile_envelope("scope-sv", &[], 1);
    assert_eq!(envelope.schema_version, DISPATCH_SCHEMA_VERSION);
}

#[test]
fn compile_envelope_formation_sequence_preserved() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let envelope = compiler.compile_envelope("scope-fs", &[], 42);
    assert_eq!(envelope.formation_sequence, 42);
}

#[test]
fn compile_envelope_content_hash_differs_by_scope() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let sites = vec![simple_site(0, "noop")];
    let e1 = compiler.compile_envelope("scope-a", &sites, 1);
    let e2 = compiler.compile_envelope("scope-b", &sites, 1);
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn compile_envelope_content_hash_differs_by_formation_sequence() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let sites = vec![simple_site(0, "noop")];
    let e1 = compiler.compile_envelope("scope-same", &sites, 1);
    let e2 = compiler.compile_envelope("scope-same", &sites, 2);
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn compile_envelope_elidable_regions_split_by_span() {
    let policy = PruningPolicy {
        max_region_span: 10,
        ..PruningPolicy::default()
    };
    let mut compiler = DispatchCompiler::new(policy, test_epoch());
    compiler.register_capability_proofs(vec![simple_proof(Capability::new("file_read"))]);

    // Offsets 0, 4, 8 within span 10; offset 100 far away
    let sites = vec![
        simple_site(0, "fs.read").require(Capability::new("file_read")),
        simple_site(4, "fs.read").require(Capability::new("file_read")),
        simple_site(8, "fs.read").require(Capability::new("file_read")),
        simple_site(100, "fs.read").require(Capability::new("file_read")),
    ];
    let envelope = compiler.compile_envelope("scope-split", &sites, 1);
    assert_eq!(envelope.fast_path_count, 4);
    assert!(envelope.elidable_regions.len() >= 2);
}

#[test]
fn compile_envelope_elidable_region_has_covering_proofs() {
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_capability_proofs(vec![simple_proof(Capability::new("file_read"))]);

    let sites = vec![
        simple_site(0, "fs.read").require(Capability::new("file_read")),
        simple_site(4, "fs.read").require(Capability::new("file_read")),
    ];
    let envelope = compiler.compile_envelope("scope-cov", &sites, 1);
    assert_eq!(envelope.elidable_regions.len(), 1);
    let region = &envelope.elidable_regions[0];
    assert!(!region.covering_proofs.is_empty());
}

#[test]
fn compile_envelope_mixed_fast_and_rejected() {
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_capability_proofs(vec![simple_proof(Capability::new("file_read"))]);

    let sites = vec![
        simple_site(0, "fs.read").require(Capability::new("file_read")),
        simple_site(4, "net.send").require(Capability::new("net_connect")),
        simple_site(8, "noop"),
    ];
    let envelope = compiler.compile_envelope("scope-mix", &sites, 1);
    assert_eq!(envelope.fast_path_count, 2); // fs.read + noop
    assert_eq!(envelope.rejected_count, 1); // net.send
}

// ---------------------------------------------------------------------------
// Enrichment: SpecializationEnvelope — additional coverage
// ---------------------------------------------------------------------------

#[test]
fn envelope_id_prefix() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let envelope = compiler.compile_envelope("scope-pfx", &[], 1);
    assert!(envelope.envelope_id.starts_with("se-"));
}

#[test]
fn envelope_display_contains_scope_and_counts() {
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_capability_proofs(vec![simple_proof(Capability::new("file_read"))]);
    let sites = vec![
        simple_site(0, "fs.read").require(Capability::new("file_read")),
        simple_site(4, "noop"),
    ];
    let envelope = compiler.compile_envelope("my-scope", &sites, 1);
    let s = format!("{envelope}");
    assert!(s.contains("spec-envelope"));
    assert!(s.contains("my-scope"));
    assert!(s.contains("fast="));
    assert!(s.contains("checked="));
    assert!(s.contains("rejected="));
    assert!(s.contains("regions="));
}

#[test]
fn envelope_epoch_matches_compiler() {
    let epoch = SecurityEpoch::from_raw(42);
    let compiler = DispatchCompiler::new(PruningPolicy::default(), epoch);
    let envelope = compiler.compile_envelope("scope-ep", &[], 1);
    assert_eq!(envelope.epoch, epoch);
}

// ---------------------------------------------------------------------------
// Enrichment: EnvelopeSummary — deeper coverage
// ---------------------------------------------------------------------------

#[test]
fn envelope_summary_all_fields() {
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_capability_proofs(vec![simple_proof(Capability::new("file_read"))]);
    let sites = vec![
        simple_site(0, "fs.read").require(Capability::new("file_read")),
        simple_site(4, "net.send").require(Capability::new("net_connect")),
        simple_site(8, "noop"),
    ];
    let envelope = compiler.compile_envelope("scope-sum-all", &sites, 1);
    let summary = envelope.summary();
    assert_eq!(summary.envelope_id, envelope.envelope_id);
    assert_eq!(summary.scope_id, "scope-sum-all");
    assert_eq!(summary.total_sites, 3);
    assert_eq!(summary.fast_path_count, envelope.fast_path_count);
    assert_eq!(summary.checked_path_count, envelope.checked_path_count);
    assert_eq!(summary.rejected_count, envelope.rejected_count);
    assert_eq!(
        summary.elidable_region_count,
        envelope.elidable_regions.len() as u32
    );
    assert_eq!(summary.epoch, test_epoch());
}

#[test]
fn envelope_summary_empty_sites() {
    let compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    let envelope = compiler.compile_envelope("empty", &[], 1);
    let summary = envelope.summary();
    assert_eq!(summary.total_sites, 0);
    assert_eq!(summary.fast_path_count, 0);
    assert_eq!(summary.checked_path_count, 0);
    assert_eq!(summary.rejected_count, 0);
    assert_eq!(summary.elidable_region_count, 0);
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchSpecimenFamily — per-variant serde
// ---------------------------------------------------------------------------

#[test]
fn specimen_family_mixed_capabilities_serde() {
    let f = DispatchSpecimenFamily::MixedCapabilities;
    let json = serde_json::to_string(&f).unwrap();
    let back: DispatchSpecimenFamily = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn specimen_family_ifc_required_serde() {
    let f = DispatchSpecimenFamily::IfcRequired;
    let json = serde_json::to_string(&f).unwrap();
    let back: DispatchSpecimenFamily = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn specimen_family_contiguous_region_serde() {
    let f = DispatchSpecimenFamily::ContiguousRegion;
    let json = serde_json::to_string(&f).unwrap();
    let back: DispatchSpecimenFamily = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

#[test]
fn specimen_family_degraded_mode_serde() {
    let f = DispatchSpecimenFamily::DegradedMode;
    let json = serde_json::to_string(&f).unwrap();
    let back: DispatchSpecimenFamily = serde_json::from_str(&json).unwrap();
    assert_eq!(f, back);
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchSpecimenFamily — per-variant Display exact values
// ---------------------------------------------------------------------------

#[test]
fn specimen_family_single_site_display_exact() {
    assert_eq!(
        format!("{}", DispatchSpecimenFamily::SingleSite),
        "single-site"
    );
}

#[test]
fn specimen_family_mixed_capabilities_display_exact() {
    assert_eq!(
        format!("{}", DispatchSpecimenFamily::MixedCapabilities),
        "mixed-capabilities"
    );
}

#[test]
fn specimen_family_ifc_required_display_exact() {
    assert_eq!(
        format!("{}", DispatchSpecimenFamily::IfcRequired),
        "ifc-required"
    );
}

#[test]
fn specimen_family_contiguous_region_display_exact() {
    assert_eq!(
        format!("{}", DispatchSpecimenFamily::ContiguousRegion),
        "contiguous-region"
    );
}

#[test]
fn specimen_family_degraded_mode_display_exact() {
    assert_eq!(
        format!("{}", DispatchSpecimenFamily::DegradedMode),
        "degraded-mode"
    );
}

// ---------------------------------------------------------------------------
// Enrichment: Corpus — additional checks
// ---------------------------------------------------------------------------

#[test]
fn dispatch_corpus_has_five_families() {
    let corpus = dispatch_corpus();
    assert_eq!(corpus.len(), 5);
}

#[test]
fn dispatch_corpus_descriptions_non_empty() {
    let corpus = dispatch_corpus();
    for (_, desc) in &corpus {
        assert!(!desc.is_empty());
    }
}

#[test]
fn run_dispatch_corpus_returns_five_results() {
    let results = run_dispatch_corpus();
    assert_eq!(results.len(), 5);
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchCompiler — register proofs
// ---------------------------------------------------------------------------

#[test]
fn compiler_register_multiple_capability_proofs() {
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_capability_proofs(vec![
        CapabilityProof::new(Capability::new("file_read"), "w1", 990_000, true),
        CapabilityProof::new(Capability::new("file_write"), "w2", 980_000, true),
        CapabilityProof::new(Capability::new("net_connect"), "w3", 970_000, true),
    ]);

    let site = simple_site(0, "full_access")
        .require(Capability::new("file_read"))
        .require(Capability::new("file_write"))
        .require(Capability::new("net_connect"));
    let decision = compiler.decide(&site);
    assert!(decision.is_fast_path());
    assert_eq!(decision.capability_proofs.len(), 3);
}

#[test]
fn compiler_register_flow_proofs_extends() {
    let mut compiler = DispatchCompiler::new(PruningPolicy::default(), test_epoch());
    compiler.register_flow_proofs(vec![simple_flow_proof("src1", "sink1")]);
    compiler.register_flow_proofs(vec![simple_flow_proof("src2", "sink2")]);

    // First proof should match
    let site1 = simple_site(0, "data.send1").with_ifc_flow("src1", "sink1");
    let d1 = compiler.decide(&site1);
    // This should match because we have the flow proof for src1->sink1
    // But the site also needs no caps, so it should be fast path
    assert!(d1.is_fast_path());
}

// ---------------------------------------------------------------------------
// Enrichment: DispatchCompiler — min_witness_count
// ---------------------------------------------------------------------------

#[test]
fn compiler_min_witness_count_not_met_no_degraded() {
    let policy = PruningPolicy {
        min_witness_count: 3,
        allow_degraded_dispatch: false,
        ..PruningPolicy::default()
    };
    let mut compiler = DispatchCompiler::new(policy, test_epoch());
    compiler.register_capability_proofs(vec![CapabilityProof::new(
        Capability::new("file_read"),
        "w1",
        990_000,
        true,
    )]);

    let site = simple_site(0, "fs.read").require(Capability::new("file_read"));
    let decision = compiler.decide(&site);
    // Only 1 proof but needs 3, no degraded allowed -> rejected
    assert!(decision.is_rejected());
}

#[test]
fn compiler_min_witness_count_not_met_degraded_allowed() {
    let policy = PruningPolicy {
        min_witness_count: 3,
        allow_degraded_dispatch: true,
        ..PruningPolicy::default()
    };
    let mut compiler = DispatchCompiler::new(policy, test_epoch());
    compiler.register_capability_proofs(vec![CapabilityProof::new(
        Capability::new("file_read"),
        "w1",
        990_000,
        true,
    )]);

    let site = simple_site(0, "fs.read").require(Capability::new("file_read"));
    let decision = compiler.decide(&site);
    // Only 1 proof but needs 3, degraded allowed -> checked path
    assert!(!decision.is_fast_path());
    assert!(!decision.is_rejected());
}
