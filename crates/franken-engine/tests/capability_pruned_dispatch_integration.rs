//! Integration tests for capability-pruned dispatch module.

use std::collections::BTreeSet;

use frankenengine_engine::capability_pruned_dispatch::{
    COMPONENT, CapabilityProof, CheckElidableRegion, DEFAULT_MAX_FAST_PATH_SITES,
    DEFAULT_MAX_REGION_SPAN, DEFAULT_MIN_ELISION_CONFIDENCE, DISPATCH_SCHEMA_VERSION,
    DispatchCompiler, DispatchDecisionRecord, DispatchRoute, DispatchSite, DispatchSpecimenFamily,
    EnvelopeSummary, FlowProofRef, PruningPolicy, REGION_SCHEMA_VERSION, SpecializationEnvelope,
    dispatch_corpus, run_dispatch_corpus,
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
    assert!(DEFAULT_MAX_FAST_PATH_SITES > 0);
    assert!(DEFAULT_MIN_ELISION_CONFIDENCE > 0);
    assert!(DEFAULT_MAX_REGION_SPAN > 0);
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
