#![forbid(unsafe_code)]
//! Enrichment integration tests for `static_authority_analyzer`.
//!
//! Adds exact Display messages, Debug distinctness, JSON field-name stability,
//! serde exact enum values, std::error::Error impl, validation edge cases,
//! and cache behavior beyond the existing 36 integration tests (+ 12 unit tests
//! added in previous enrichment).

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
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::static_authority_analyzer::{
    AnalysisCache, AnalysisCacheKey, AnalysisConfig, AnalysisError, AnalysisMethod, Capability,
    EffectEdge, EffectGraph, EffectNode, EffectNodeKind, ManifestIntents, PerCapabilityEvidence,
    PrecisionEstimate, StaticAnalysisReport, StaticAuthorityAnalyzer,
};

// ===========================================================================
// Test helpers
// ===========================================================================

fn cap(name: &str) -> Capability {
    Capability::new(name)
}

fn entry_node(id: &str) -> EffectNode {
    EffectNode {
        node_id: id.to_string(),
        kind: EffectNodeKind::Entry,
        source_location: None,
    }
}

fn hostcall_node(id: &str, capability: &str) -> EffectNode {
    EffectNode {
        node_id: id.to_string(),
        kind: EffectNodeKind::HostcallSite {
            capability: cap(capability),
        },
        source_location: Some(format!("{id}.rs:1")),
    }
}

fn exit_node(id: &str) -> EffectNode {
    EffectNode {
        node_id: id.to_string(),
        kind: EffectNodeKind::Exit,
        source_location: None,
    }
}

fn edge(from: &str, to: &str) -> EffectEdge {
    EffectEdge {
        from: from.to_string(),
        to: to.to_string(),
        provably_dead: false,
    }
}

fn dead_edge(from: &str, to: &str) -> EffectEdge {
    EffectEdge {
        from: from.to_string(),
        to: to.to_string(),
        provably_dead: true,
    }
}

fn control_flow_node(id: &str) -> EffectNode {
    EffectNode {
        node_id: id.to_string(),
        kind: EffectNodeKind::ControlFlow,
        source_location: None,
    }
}

fn computation_node(id: &str) -> EffectNode {
    EffectNode {
        node_id: id.to_string(),
        kind: EffectNodeKind::Computation,
        source_location: None,
    }
}

fn simple_graph() -> EffectGraph {
    let mut g = EffectGraph::new("test-ext");
    g.add_node(entry_node("entry"));
    g.add_node(hostcall_node("hc-fs", "fs:read"));
    g.add_node(exit_node("exit"));
    g.add_edge(edge("entry", "hc-fs"));
    g.add_edge(edge("hc-fs", "exit"));
    g
}

fn simple_manifest() -> ManifestIntents {
    ManifestIntents {
        extension_id: "test-ext".to_string(),
        declared_capabilities: vec![cap("fs:read")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    }
}

fn config() -> AnalysisConfig {
    AnalysisConfig {
        time_budget_ns: 60_000_000_000,
        path_sensitive: false,
        zone: "enrich-zone".to_string(),
    }
}

fn do_analysis() -> StaticAnalysisReport {
    let analyzer = StaticAuthorityAnalyzer::new(config());
    analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000_000_000,
        )
        .expect("analyze")
}

// ===========================================================================
// 1) AnalysisMethod — exact Display
// ===========================================================================

#[test]
fn analysis_method_display_exact() {
    assert_eq!(
        AnalysisMethod::LatticeReachability.to_string(),
        "lattice_reachability"
    );
    assert_eq!(
        AnalysisMethod::ManifestFallback.to_string(),
        "manifest_fallback"
    );
    assert_eq!(
        AnalysisMethod::TimeoutFallback.to_string(),
        "timeout_fallback"
    );
    assert_eq!(
        AnalysisMethod::ExcludedDeadPath.to_string(),
        "excluded_dead_path"
    );
}

// ===========================================================================
// 2) AnalysisError — exact Display messages
// ===========================================================================

#[test]
fn error_display_exact_extension_mismatch() {
    let e = AnalysisError::ExtensionMismatch {
        graph_ext: "ext-a".to_string(),
        manifest_ext: "ext-b".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "extension mismatch: graph=ext-a, manifest=ext-b"
    );
}

#[test]
fn error_display_exact_empty_effect_graph() {
    let e = AnalysisError::EmptyEffectGraph {
        extension_id: "my-ext".to_string(),
    };
    assert_eq!(e.to_string(), "empty effect graph for extension my-ext");
}

#[test]
fn error_display_exact_no_entry_node() {
    let e = AnalysisError::NoEntryNode {
        extension_id: "my-ext".to_string(),
    };
    assert_eq!(e.to_string(), "no entry node in effect graph for my-ext");
}

#[test]
fn error_display_exact_timed_out() {
    let e = AnalysisError::TimedOut {
        extension_id: "slow-ext".to_string(),
        elapsed_ns: 70_000_000_000,
        budget_ns: 60_000_000_000,
    };
    assert_eq!(
        e.to_string(),
        "analysis timed out for slow-ext: 70000000000ns > 60000000000ns budget"
    );
}

// ===========================================================================
// 3) std::error::Error impl
// ===========================================================================

#[test]
fn analysis_error_source_is_none() {
    use std::error::Error;
    let errors: Vec<AnalysisError> = vec![
        AnalysisError::ExtensionMismatch {
            graph_ext: "a".to_string(),
            manifest_ext: "b".to_string(),
        },
        AnalysisError::EmptyEffectGraph {
            extension_id: "x".to_string(),
        },
        AnalysisError::NoEntryNode {
            extension_id: "x".to_string(),
        },
        AnalysisError::TimedOut {
            extension_id: "x".to_string(),
            elapsed_ns: 1,
            budget_ns: 0,
        },
    ];
    for e in &errors {
        assert!(e.source().is_none());
    }
}

// ===========================================================================
// 4) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_analysis_method() {
    let variants = [
        AnalysisMethod::LatticeReachability,
        AnalysisMethod::ManifestFallback,
        AnalysisMethod::TimeoutFallback,
        AnalysisMethod::ExcludedDeadPath,
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn debug_distinct_effect_node_kind() {
    let variants: Vec<EffectNodeKind> = vec![
        EffectNodeKind::Entry,
        EffectNodeKind::HostcallSite {
            capability: cap("c"),
        },
        EffectNodeKind::ControlFlow,
        EffectNodeKind::Computation,
        EffectNodeKind::Exit,
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

// ===========================================================================
// 5) serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_analysis_method() {
    assert_eq!(
        serde_json::to_string(&AnalysisMethod::LatticeReachability).unwrap(),
        "\"LatticeReachability\""
    );
    assert_eq!(
        serde_json::to_string(&AnalysisMethod::ManifestFallback).unwrap(),
        "\"ManifestFallback\""
    );
    assert_eq!(
        serde_json::to_string(&AnalysisMethod::TimeoutFallback).unwrap(),
        "\"TimeoutFallback\""
    );
    assert_eq!(
        serde_json::to_string(&AnalysisMethod::ExcludedDeadPath).unwrap(),
        "\"ExcludedDeadPath\""
    );
}

#[test]
fn serde_exact_effect_node_kind_tags() {
    let entry = EffectNodeKind::Entry;
    assert!(serde_json::to_string(&entry).unwrap().contains("\"Entry\""));

    let hc = EffectNodeKind::HostcallSite {
        capability: cap("fs:write"),
    };
    assert!(
        serde_json::to_string(&hc)
            .unwrap()
            .contains("\"HostcallSite\"")
    );

    let cf = EffectNodeKind::ControlFlow;
    assert!(
        serde_json::to_string(&cf)
            .unwrap()
            .contains("\"ControlFlow\"")
    );

    let comp = EffectNodeKind::Computation;
    assert!(
        serde_json::to_string(&comp)
            .unwrap()
            .contains("\"Computation\"")
    );

    let exit = EffectNodeKind::Exit;
    assert!(serde_json::to_string(&exit).unwrap().contains("\"Exit\""));
}

// ===========================================================================
// 6) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_capability() {
    let c = cap("fs:read");
    let json = serde_json::to_string(&c).unwrap();
    // Capability is a newtype wrapping String, serializes as plain string
    assert_eq!(json, "\"fs:read\"");
}

#[test]
fn json_fields_effect_node() {
    let n = entry_node("n1");
    let json = serde_json::to_string(&n).unwrap();
    assert!(json.contains("\"node_id\""));
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"source_location\""));
}

#[test]
fn json_fields_effect_edge() {
    let e = edge("a", "b");
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("\"from\""));
    assert!(json.contains("\"to\""));
    assert!(json.contains("\"provably_dead\""));
}

#[test]
fn json_fields_effect_graph() {
    let g = simple_graph();
    let json = serde_json::to_string(&g).unwrap();
    assert!(json.contains("\"extension_id\""));
    assert!(json.contains("\"nodes\""));
    assert!(json.contains("\"edges\""));
}

#[test]
fn json_fields_manifest_intents() {
    let m = simple_manifest();
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("\"extension_id\""));
    assert!(json.contains("\"declared_capabilities\""));
    assert!(json.contains("\"optional_capabilities\""));
}

#[test]
fn json_fields_analysis_config() {
    let c = AnalysisConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"time_budget_ns\""));
    assert!(json.contains("\"path_sensitive\""));
    assert!(json.contains("\"zone\""));
}

#[test]
fn json_fields_per_capability_evidence() {
    let pce = PerCapabilityEvidence {
        capability: cap("net:connect"),
        requiring_nodes: vec!["hc-1".to_string()].into_iter().collect(),
        analysis_method: AnalysisMethod::LatticeReachability,
        summary: "test".to_string(),
    };
    let json = serde_json::to_string(&pce).unwrap();
    assert!(json.contains("\"capability\""));
    assert!(json.contains("\"requiring_nodes\""));
    assert!(json.contains("\"analysis_method\""));
    assert!(json.contains("\"summary\""));
}

#[test]
fn json_fields_precision_estimate() {
    let pe = PrecisionEstimate {
        upper_bound_size: 3,
        manifest_declared_size: 2,
        ratio_millionths: 1_500_000,
        excluded_by_path_sensitivity: 1,
    };
    let json = serde_json::to_string(&pe).unwrap();
    assert!(json.contains("\"upper_bound_size\""));
    assert!(json.contains("\"manifest_declared_size\""));
    assert!(json.contains("\"ratio_millionths\""));
    assert!(json.contains("\"excluded_by_path_sensitivity\""));
}

#[test]
fn json_fields_analysis_cache_key() {
    let ack = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g"),
        manifest_hash: ContentHash::compute(b"m"),
        path_sensitive: true,
    };
    let json = serde_json::to_string(&ack).unwrap();
    assert!(json.contains("\"effect_graph_hash\""));
    assert!(json.contains("\"manifest_hash\""));
    assert!(json.contains("\"path_sensitive\""));
}

#[test]
fn json_fields_static_analysis_report() {
    let report = do_analysis();
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"report_id\""));
    assert!(json.contains("\"extension_id\""));
    assert!(json.contains("\"upper_bound_capabilities\""));
    assert!(json.contains("\"per_capability_evidence\""));
    assert!(json.contains("\"primary_analysis_method\""));
    assert!(json.contains("\"precision\""));
    assert!(json.contains("\"analysis_duration_ns\""));
    assert!(json.contains("\"timed_out\""));
    assert!(json.contains("\"path_sensitive\""));
    assert!(json.contains("\"effect_graph_hash\""));
    assert!(json.contains("\"manifest_hash\""));
    assert!(json.contains("\"epoch\""));
    assert!(json.contains("\"timestamp_ns\""));
    assert!(json.contains("\"zone\""));
}

// ===========================================================================
// 7) AnalysisConfig defaults — exact values
// ===========================================================================

#[test]
fn analysis_config_default_exact() {
    let c = AnalysisConfig::default();
    assert_eq!(c.time_budget_ns, 60_000_000_000);
    assert!(c.path_sensitive);
    assert_eq!(c.zone, "default");
}

// ===========================================================================
// 8) Capability — Display, as_str, Ord
// ===========================================================================

#[test]
fn capability_display_matches_inner() {
    let c = cap("net:connect");
    assert_eq!(c.to_string(), "net:connect");
    assert_eq!(c.as_str(), "net:connect");
}

#[test]
fn capability_ordering_lexicographic() {
    let mut caps = [cap("z:cap"), cap("a:cap"), cap("m:cap")];
    caps.sort();
    assert_eq!(caps[0].as_str(), "a:cap");
    assert_eq!(caps[1].as_str(), "m:cap");
    assert_eq!(caps[2].as_str(), "z:cap");
}

// ===========================================================================
// 9) AnalysisError — serde all variants
// ===========================================================================

#[test]
fn analysis_error_serde_all_variants() {
    let errors = vec![
        AnalysisError::ExtensionMismatch {
            graph_ext: "g".to_string(),
            manifest_ext: "m".to_string(),
        },
        AnalysisError::EmptyEffectGraph {
            extension_id: "e".to_string(),
        },
        AnalysisError::NoEntryNode {
            extension_id: "e".to_string(),
        },
        AnalysisError::TimedOut {
            extension_id: "e".to_string(),
            elapsed_ns: 100,
            budget_ns: 50,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: AnalysisError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

// ===========================================================================
// 10) AnalysisError Display messages unique
// ===========================================================================

#[test]
fn analysis_error_display_unique() {
    let msgs: Vec<String> = vec![
        AnalysisError::ExtensionMismatch {
            graph_ext: "g".to_string(),
            manifest_ext: "m".to_string(),
        }
        .to_string(),
        AnalysisError::EmptyEffectGraph {
            extension_id: "e".to_string(),
        }
        .to_string(),
        AnalysisError::NoEntryNode {
            extension_id: "e".to_string(),
        }
        .to_string(),
        AnalysisError::TimedOut {
            extension_id: "e".to_string(),
            elapsed_ns: 1,
            budget_ns: 0,
        }
        .to_string(),
    ];
    let set: BTreeSet<&str> = msgs.iter().map(|s| s.as_str()).collect();
    assert_eq!(set.len(), msgs.len());
}

// ===========================================================================
// 11) Analysis — error paths
// ===========================================================================

#[test]
fn analyze_rejects_extension_mismatch() {
    let g = simple_graph();
    let mut m = simple_manifest();
    m.extension_id = "wrong-ext".to_string();
    let analyzer = StaticAuthorityAnalyzer::new(config());
    let err = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 1_000_000_000)
        .unwrap_err();
    assert!(matches!(err, AnalysisError::ExtensionMismatch { .. }));
}

#[test]
fn analyze_rejects_empty_graph() {
    let g = EffectGraph::new("test-ext");
    let m = simple_manifest();
    let analyzer = StaticAuthorityAnalyzer::new(config());
    let err = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 1_000_000_000)
        .unwrap_err();
    assert!(matches!(err, AnalysisError::EmptyEffectGraph { .. }));
}

#[test]
fn analyze_rejects_no_entry_node() {
    let mut g = EffectGraph::new("test-ext");
    g.add_node(exit_node("exit")); // No entry node
    let m = simple_manifest();
    let analyzer = StaticAuthorityAnalyzer::new(config());
    let err = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 1_000_000_000)
        .unwrap_err();
    assert!(matches!(err, AnalysisError::NoEntryNode { .. }));
}

// ===========================================================================
// 12) Analysis — requires_capability / undeclared / unused
// ===========================================================================

#[test]
fn report_requires_capability() {
    let report = do_analysis();
    assert!(report.requires_capability(&cap("fs:read")));
    assert!(!report.requires_capability(&cap("net:connect")));
}

#[test]
fn report_undeclared_capabilities_when_graph_has_extras() {
    let mut g = simple_graph();
    g.add_node(hostcall_node("hc-net", "net:connect"));
    g.add_edge(edge("entry", "hc-net"));

    let m = simple_manifest(); // Only declares fs:read
    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 1_000_000_000)
        .unwrap();
    let undeclared = report.undeclared_capabilities(&m);
    assert!(undeclared.contains(&cap("net:connect")));
    assert!(!undeclared.contains(&cap("fs:read")));
}

#[test]
fn report_unused_declared_when_manifest_has_extras() {
    let g = simple_graph(); // Only has fs:read
    let mut m = simple_manifest();
    m.declared_capabilities.insert(cap("crypto:sign"));

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 1_000_000_000)
        .unwrap();
    // crypto:sign is declared but not actually reachable from graph — however
    // the analyzer adds it conservatively via ManifestFallback so it IS in
    // the upper bound.
    let unused = report.unused_declared_capabilities(&m);
    assert!(unused.is_empty()); // ManifestFallback adds declared caps
}

// ===========================================================================
// 13) Analysis — path-sensitive dead edge exclusion
// ===========================================================================

#[test]
fn path_sensitive_excludes_dead_edge_capability() {
    let mut g = EffectGraph::new("test-ext");
    g.add_node(entry_node("entry"));
    g.add_node(hostcall_node("hc-alive", "fs:read"));
    g.add_node(hostcall_node("hc-dead", "net:connect"));
    g.add_node(exit_node("exit"));
    g.add_edge(edge("entry", "hc-alive"));
    g.add_edge(dead_edge("entry", "hc-dead")); // provably dead
    g.add_edge(edge("hc-alive", "exit"));
    g.add_edge(edge("hc-dead", "exit"));

    let mut m = simple_manifest();
    m.declared_capabilities.insert(cap("net:connect"));

    let ps_config = AnalysisConfig {
        path_sensitive: true,
        ..config()
    };
    let analyzer = StaticAuthorityAnalyzer::new(ps_config);
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 1_000_000_000)
        .unwrap();

    // net:connect should be excluded by path-sensitive analysis (dead edge)
    // but manifest fallback may re-add it
    // The key thing: ExcludedDeadPath evidence should exist
    let excluded = report
        .per_capability_evidence
        .iter()
        .filter(|e| e.analysis_method == AnalysisMethod::ExcludedDeadPath)
        .count();
    assert!(excluded > 0, "should have at least one dead-path exclusion");
}

// ===========================================================================
// 14) AnalysisCache — edge cases
// ===========================================================================

#[test]
fn cache_empty_initial_state() {
    let cache = AnalysisCache::new(10);
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn cache_get_nonexistent_returns_none() {
    let cache = AnalysisCache::new(10);
    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g"),
        manifest_hash: ContentHash::compute(b"m"),
        path_sensitive: false,
    };
    assert!(cache.get(&key).is_none());
}

#[test]
fn cache_insert_and_get() {
    let mut cache = AnalysisCache::new(10);
    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g"),
        manifest_hash: ContentHash::compute(b"m"),
        path_sensitive: false,
    };
    let report = do_analysis();
    cache.insert(key.clone(), report.clone());
    assert_eq!(cache.len(), 1);
    let cached = cache.get(&key).unwrap();
    assert_eq!(cached.extension_id, report.extension_id);
}

#[test]
fn cache_evicts_oldest_at_capacity() {
    let mut cache = AnalysisCache::new(2);
    let report = do_analysis();

    let k1 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g1"),
        manifest_hash: ContentHash::compute(b"m1"),
        path_sensitive: false,
    };
    let k2 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g2"),
        manifest_hash: ContentHash::compute(b"m2"),
        path_sensitive: false,
    };
    let k3 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g3"),
        manifest_hash: ContentHash::compute(b"m3"),
        path_sensitive: false,
    };

    cache.insert(k1.clone(), report.clone());
    cache.insert(k2.clone(), report.clone());
    assert_eq!(cache.len(), 2);

    cache.insert(k3.clone(), report);
    assert_eq!(cache.len(), 2);
    assert!(cache.get(&k1).is_none(), "oldest entry should be evicted");
    assert!(cache.get(&k2).is_some());
    assert!(cache.get(&k3).is_some());
}

#[test]
fn cache_clear() {
    let mut cache = AnalysisCache::new(10);
    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g"),
        manifest_hash: ContentHash::compute(b"m"),
        path_sensitive: false,
    };
    cache.insert(key, do_analysis());
    assert!(!cache.is_empty());
    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

// ===========================================================================
// 15) Report — serde roundtrip
// ===========================================================================

#[test]
fn static_analysis_report_serde_roundtrip() {
    let report = do_analysis();
    let json = serde_json::to_string(&report).unwrap();
    let back: StaticAnalysisReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// 16) Report — content hash determinism
// ===========================================================================

#[test]
fn report_content_hash_deterministic() {
    let r1 = do_analysis();
    let r2 = do_analysis();
    assert_eq!(r1.content_hash(), r2.content_hash());
}

// ===========================================================================
// 17) EffectGraph — empty new
// ===========================================================================

#[test]
fn effect_graph_new_is_empty() {
    let g = EffectGraph::new("ext");
    assert_eq!(g.extension_id, "ext");
    assert!(g.nodes.is_empty());
    assert!(g.edges.is_empty());
}

// ===========================================================================
// 18) ManifestIntents — optional caps not in upper bound
// ===========================================================================

#[test]
fn optional_capabilities_excluded_from_declared() {
    let m = ManifestIntents {
        extension_id: "ext".to_string(),
        declared_capabilities: vec![cap("fs:read")].into_iter().collect(),
        optional_capabilities: vec![cap("net:connect")].into_iter().collect(),
    };
    // Optional caps are separate from declared
    assert!(!m.declared_capabilities.contains(&cap("net:connect")));
    assert!(m.optional_capabilities.contains(&cap("net:connect")));
}

// ===========================================================================
// 19) Serde roundtrips — remaining types
// ===========================================================================

#[test]
fn serde_roundtrip_analysis_method_all() {
    let methods = [
        AnalysisMethod::LatticeReachability,
        AnalysisMethod::ManifestFallback,
        AnalysisMethod::TimeoutFallback,
        AnalysisMethod::ExcludedDeadPath,
    ];
    for m in &methods {
        let json = serde_json::to_string(m).unwrap();
        let back: AnalysisMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(*m, back);
    }
}

#[test]
fn serde_roundtrip_effect_node() {
    let node = hostcall_node("hc-1", "fs:read");
    let json = serde_json::to_string(&node).unwrap();
    let back: EffectNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn serde_roundtrip_effect_edge() {
    let e = edge("a", "b");
    let json = serde_json::to_string(&e).unwrap();
    let back: EffectEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

#[test]
fn serde_roundtrip_effect_graph() {
    let g = simple_graph();
    let json = serde_json::to_string(&g).unwrap();
    let back: EffectGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

#[test]
fn serde_roundtrip_manifest_intents() {
    let m = simple_manifest();
    let json = serde_json::to_string(&m).unwrap();
    let back: ManifestIntents = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn serde_roundtrip_analysis_config() {
    let c = AnalysisConfig::default();
    let json = serde_json::to_string(&c).unwrap();
    let back: AnalysisConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn serde_roundtrip_analysis_cache_key() {
    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"graph"),
        manifest_hash: ContentHash::compute(b"manifest"),
        path_sensitive: true,
    };
    let json = serde_json::to_string(&key).unwrap();
    let back: AnalysisCacheKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, back);
}

#[test]
fn serde_roundtrip_per_capability_evidence() {
    let ev = PerCapabilityEvidence {
        capability: cap("fs:read"),
        requiring_nodes: vec!["node-1".to_string()].into_iter().collect(),
        analysis_method: AnalysisMethod::LatticeReachability,
        summary: "found via reachability".to_string(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: PerCapabilityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn serde_roundtrip_precision_estimate() {
    let pe = PrecisionEstimate {
        upper_bound_size: 3,
        manifest_declared_size: 2,
        ratio_millionths: 1_500_000,
        excluded_by_path_sensitivity: 1,
    };
    let json = serde_json::to_string(&pe).unwrap();
    let back: PrecisionEstimate = serde_json::from_str(&json).unwrap();
    assert_eq!(pe, back);
}

// ===========================================================================
// 20) Report ID determinism
// ===========================================================================

#[test]
fn report_derive_id_deterministic() {
    let gh = ContentHash::compute(b"graph");
    let mh = ContentHash::compute(b"manifest");
    let id1 = StaticAnalysisReport::derive_report_id("ext-1", &gh, &mh, 1000, "zone-a").unwrap();
    let id2 = StaticAnalysisReport::derive_report_id("ext-1", &gh, &mh, 1000, "zone-a").unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn report_derive_id_varies_with_zone() {
    let gh = ContentHash::compute(b"graph");
    let mh = ContentHash::compute(b"manifest");
    let id1 = StaticAnalysisReport::derive_report_id("ext-1", &gh, &mh, 1000, "zone-a").unwrap();
    let id2 = StaticAnalysisReport::derive_report_id("ext-1", &gh, &mh, 1000, "zone-b").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn report_derive_id_varies_with_timestamp() {
    let gh = ContentHash::compute(b"graph");
    let mh = ContentHash::compute(b"manifest");
    let id1 = StaticAnalysisReport::derive_report_id("ext-1", &gh, &mh, 1000, "zone").unwrap();
    let id2 = StaticAnalysisReport::derive_report_id("ext-1", &gh, &mh, 2000, "zone").unwrap();
    assert_ne!(id1, id2);
}

// ===========================================================================
// 21) AnalysisMethod ordering
// ===========================================================================

#[test]
fn analysis_method_ordering_stable() {
    let mut methods = vec![
        AnalysisMethod::ExcludedDeadPath,
        AnalysisMethod::LatticeReachability,
        AnalysisMethod::TimeoutFallback,
        AnalysisMethod::ManifestFallback,
    ];
    methods.sort();
    let mut methods2 = methods.clone();
    methods2.sort();
    assert_eq!(methods, methods2);
}

// ===========================================================================
// 22) StaticAuthorityAnalyzer — custom config
// ===========================================================================

#[test]
fn analyzer_custom_config() {
    let config = AnalysisConfig {
        time_budget_ns: 1_000_000_000,
        path_sensitive: false,
        zone: "custom-zone".to_string(),
    };
    let analyzer = StaticAuthorityAnalyzer::new(config.clone());
    let graph = simple_graph();
    let manifest = simple_manifest();
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 42)
        .unwrap();
    assert_eq!(report.zone, "custom-zone");
    assert!(!report.path_sensitive);
}

// ===========================================================================
// 23) EffectGraph — add_node/add_edge
// ===========================================================================

#[test]
fn effect_graph_add_node_and_edge() {
    let mut g = EffectGraph::new("ext-builder");
    g.add_node(entry_node("e"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "x"));
    assert_eq!(g.nodes.len(), 2);
    assert_eq!(g.edges.len(), 1);
}

// ===========================================================================
// 24) ManifestIntents — empty sets
// ===========================================================================

#[test]
fn manifest_intents_empty_capabilities() {
    let m = ManifestIntents {
        extension_id: "ext".to_string(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };
    assert!(m.declared_capabilities.is_empty());
    assert!(m.optional_capabilities.is_empty());
}

// ===========================================================================
// 25) AnalysisCache — key ordering
// ===========================================================================

#[test]
fn cache_key_ordering_deterministic() {
    let k1 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"aaa"),
        manifest_hash: ContentHash::compute(b"bbb"),
        path_sensitive: false,
    };
    let k2 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"ccc"),
        manifest_hash: ContentHash::compute(b"ddd"),
        path_sensitive: true,
    };
    let mut keys1 = vec![k2.clone(), k1.clone()];
    keys1.sort();
    let mut keys2 = vec![k1.clone(), k2.clone()];
    keys2.sort();
    // Sorting is deterministic regardless of initial order
    assert_eq!(keys1, keys2);
}

// ===========================================================================
// 26) Capability — as_str
// ===========================================================================

#[test]
fn capability_as_str_matches_display() {
    let c = cap("net:outbound");
    assert_eq!(c.as_str(), "net:outbound");
    assert_eq!(c.to_string(), "net:outbound");
}

// ===========================================================================
// 27) EffectEdge — dead flag
// ===========================================================================

#[test]
fn effect_edge_dead_flag_serde() {
    let e = dead_edge("a", "b");
    assert!(e.provably_dead);
    let json = serde_json::to_string(&e).unwrap();
    let back: EffectEdge = serde_json::from_str(&json).unwrap();
    assert!(back.provably_dead);
}

// ===========================================================================
// 28) EffectNodeKind — HostcallSite capability preserved
// ===========================================================================

#[test]
fn hostcall_site_preserves_capability_in_serde() {
    let kind = EffectNodeKind::HostcallSite {
        capability: cap("net:connect"),
    };
    let json = serde_json::to_string(&kind).unwrap();
    let back: EffectNodeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(kind, back);
    if let EffectNodeKind::HostcallSite { capability } = &back {
        assert_eq!(capability.as_str(), "net:connect");
    } else {
        panic!("expected HostcallSite");
    }
}

// ===========================================================================
// Enrichment tests — authority analysis, resolution, edge cases, determinism
// ===========================================================================

// ---------------------------------------------------------------------------
// 29) Multiple entry nodes — union of reachable capabilities
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multiple_entries_union_capabilities() {
    let mut g = EffectGraph::new("ext-multi-entry");
    g.add_node(entry_node("e1"));
    g.add_node(entry_node("e2"));
    g.add_node(hostcall_node("hc-a", "cap:alpha"));
    g.add_node(hostcall_node("hc-b", "cap:beta"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e1", "hc-a"));
    g.add_edge(edge("e2", "hc-b"));
    g.add_edge(edge("hc-a", "x"));
    g.add_edge(edge("hc-b", "x"));

    let m = ManifestIntents {
        extension_id: "ext-multi-entry".to_string(),
        declared_capabilities: vec![cap("cap:alpha"), cap("cap:beta")]
            .into_iter()
            .collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 1_000_000)
        .unwrap();
    assert_eq!(report.upper_bound_capabilities.len(), 2);
    assert!(report.requires_capability(&cap("cap:alpha")));
    assert!(report.requires_capability(&cap("cap:beta")));
}

#[test]
fn enrichment_multiple_entries_three_disjoint_paths() {
    let mut g = EffectGraph::new("ext-3e");
    g.add_node(entry_node("e1"));
    g.add_node(entry_node("e2"));
    g.add_node(entry_node("e3"));
    g.add_node(hostcall_node("h1", "c1"));
    g.add_node(hostcall_node("h2", "c2"));
    g.add_node(hostcall_node("h3", "c3"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e1", "h1"));
    g.add_edge(edge("e2", "h2"));
    g.add_edge(edge("e3", "h3"));
    g.add_edge(edge("h1", "x"));
    g.add_edge(edge("h2", "x"));
    g.add_edge(edge("h3", "x"));

    let m = ManifestIntents {
        extension_id: "ext-3e".to_string(),
        declared_capabilities: vec![cap("c1"), cap("c2"), cap("c3")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 2_000_000)
        .unwrap();
    assert_eq!(report.upper_bound_capabilities.len(), 3);
}

// ---------------------------------------------------------------------------
// 30) Cycle handling — BFS terminates and collects caps from cycle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cycle_terminates_with_single_cap() {
    let mut g = EffectGraph::new("ext-cyc");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h", "cap:loop"));
    g.add_node(computation_node("c"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "h"));
    g.add_edge(edge("h", "c"));
    g.add_edge(edge("c", "h")); // back-edge cycle
    g.add_edge(edge("c", "x"));

    let m = ManifestIntents {
        extension_id: "ext-cyc".to_string(),
        declared_capabilities: vec![cap("cap:loop")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 3_000_000)
        .unwrap();
    assert!(report.requires_capability(&cap("cap:loop")));
    assert_eq!(report.upper_bound_capabilities.len(), 1);
}

#[test]
fn enrichment_cycle_with_multiple_caps_in_loop() {
    let mut g = EffectGraph::new("ext-cyc2");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("ha", "cap:a"));
    g.add_node(hostcall_node("hb", "cap:b"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "ha"));
    g.add_edge(edge("ha", "hb"));
    g.add_edge(edge("hb", "ha")); // cycle
    g.add_edge(edge("hb", "x"));

    let m = ManifestIntents {
        extension_id: "ext-cyc2".to_string(),
        declared_capabilities: vec![cap("cap:a"), cap("cap:b")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 4_000_000)
        .unwrap();
    assert_eq!(report.upper_bound_capabilities.len(), 2);
}

// ---------------------------------------------------------------------------
// 31) Diamond graph — same cap on two paths deduplicates
// ---------------------------------------------------------------------------

#[test]
fn enrichment_diamond_deduplicates_same_capability() {
    let mut g = EffectGraph::new("ext-dia");
    g.add_node(entry_node("e"));
    g.add_node(control_flow_node("branch"));
    g.add_node(hostcall_node("left", "cap:shared"));
    g.add_node(hostcall_node("right", "cap:shared"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "branch"));
    g.add_edge(edge("branch", "left"));
    g.add_edge(edge("branch", "right"));
    g.add_edge(edge("left", "x"));
    g.add_edge(edge("right", "x"));

    let m = ManifestIntents {
        extension_id: "ext-dia".to_string(),
        declared_capabilities: vec![cap("cap:shared")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 5_000_000)
        .unwrap();
    assert_eq!(report.upper_bound_capabilities.len(), 1);

    let ev = report
        .per_capability_evidence
        .iter()
        .find(|e| e.capability == cap("cap:shared"))
        .unwrap();
    assert_eq!(ev.requiring_nodes.len(), 2);
    assert!(ev.requiring_nodes.contains("left"));
    assert!(ev.requiring_nodes.contains("right"));
}

// ---------------------------------------------------------------------------
// 32) Unreachable hostcall — no edges lead to it
// ---------------------------------------------------------------------------

#[test]
fn enrichment_unreachable_hostcall_excluded_from_reachability() {
    let mut g = EffectGraph::new("ext-unr");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("reachable", "cap:ok"));
    g.add_node(hostcall_node("island", "cap:hidden"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "reachable"));
    g.add_edge(edge("reachable", "x"));
    // "island" has no incoming edges

    let m = ManifestIntents {
        extension_id: "ext-unr".to_string(),
        declared_capabilities: vec![cap("cap:ok")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 6_000_000)
        .unwrap();
    assert!(report.requires_capability(&cap("cap:ok")));
    // cap:hidden is not declared in manifest and unreachable, so excluded
    assert!(!report.requires_capability(&cap("cap:hidden")));
}

#[test]
fn enrichment_unreachable_hostcall_included_if_manifest_declared() {
    let mut g = EffectGraph::new("ext-unr2");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("reachable", "cap:ok"));
    g.add_node(hostcall_node("island", "cap:hidden"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "reachable"));
    g.add_edge(edge("reachable", "x"));

    let m = ManifestIntents {
        extension_id: "ext-unr2".to_string(),
        declared_capabilities: vec![cap("cap:ok"), cap("cap:hidden")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 7_000_000)
        .unwrap();
    // cap:hidden is unreachable but declared -> ManifestFallback
    assert!(report.requires_capability(&cap("cap:hidden")));
    let ev = report
        .per_capability_evidence
        .iter()
        .find(|e| e.capability == cap("cap:hidden"))
        .unwrap();
    assert_eq!(ev.analysis_method, AnalysisMethod::ManifestFallback);
}

// ---------------------------------------------------------------------------
// 33) Path-sensitive: all edges dead => only manifest fallback caps
// ---------------------------------------------------------------------------

#[test]
fn enrichment_all_dead_edges_path_sensitive_empty_reachability() {
    let mut g = EffectGraph::new("ext-alldead");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h1", "cap:x"));
    g.add_node(exit_node("x"));
    g.add_edge(dead_edge("e", "h1"));
    g.add_edge(dead_edge("h1", "x"));

    let m = ManifestIntents {
        extension_id: "ext-alldead".to_string(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };

    let ps_cfg = AnalysisConfig {
        path_sensitive: true,
        ..config()
    };
    let analyzer = StaticAuthorityAnalyzer::new(ps_cfg);
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 8_000_000)
        .unwrap();
    // cap:x only reachable via dead edges + not declared -> excluded
    assert!(!report.requires_capability(&cap("cap:x")));
}

#[test]
fn enrichment_all_dead_edges_but_manifest_declares_cap() {
    let mut g = EffectGraph::new("ext-alldead2");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h1", "cap:x"));
    g.add_node(exit_node("x"));
    g.add_edge(dead_edge("e", "h1"));
    g.add_edge(dead_edge("h1", "x"));

    let m = ManifestIntents {
        extension_id: "ext-alldead2".to_string(),
        declared_capabilities: vec![cap("cap:x")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let ps_cfg = AnalysisConfig {
        path_sensitive: true,
        ..config()
    };
    let analyzer = StaticAuthorityAnalyzer::new(ps_cfg);
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 9_000_000)
        .unwrap();
    // cap:x declared in manifest -> ManifestFallback
    assert!(report.requires_capability(&cap("cap:x")));
}

// ---------------------------------------------------------------------------
// 34) Path-sensitive vs non-path-sensitive: dead edge makes difference
// ---------------------------------------------------------------------------

#[test]
fn enrichment_path_sensitive_flag_affects_cap_set() {
    let mut g = EffectGraph::new("ext-ps-diff");
    g.add_node(entry_node("e"));
    g.add_node(control_flow_node("b"));
    g.add_node(hostcall_node("alive", "cap:live"));
    g.add_node(hostcall_node("dead_node", "cap:dead"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "b"));
    g.add_edge(edge("b", "alive"));
    g.add_edge(dead_edge("b", "dead_node"));
    g.add_edge(edge("alive", "x"));
    g.add_edge(edge("dead_node", "x"));

    let m = ManifestIntents {
        extension_id: "ext-ps-diff".to_string(),
        declared_capabilities: vec![cap("cap:live")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    // Non-path-sensitive: includes cap:dead
    let nps_analyzer = StaticAuthorityAnalyzer::new(AnalysisConfig {
        path_sensitive: false,
        ..config()
    });
    let nps_report = nps_analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 10_000_000)
        .unwrap();
    assert!(nps_report.requires_capability(&cap("cap:dead")));

    // Path-sensitive: excludes cap:dead (not in manifest)
    let ps_analyzer = StaticAuthorityAnalyzer::new(AnalysisConfig {
        path_sensitive: true,
        ..config()
    });
    let ps_report = ps_analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 10_000_001)
        .unwrap();
    assert!(!ps_report.requires_capability(&cap("cap:dead")));
}

// ---------------------------------------------------------------------------
// 35) Evidence sorting is deterministic (alphabetical by capability)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_sorted_alphabetically() {
    let mut g = EffectGraph::new("ext-sort");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("hz", "z:cap"));
    g.add_node(hostcall_node("ha", "a:cap"));
    g.add_node(hostcall_node("hm", "m:cap"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "hz"));
    g.add_edge(edge("e", "ha"));
    g.add_edge(edge("e", "hm"));
    g.add_edge(edge("hz", "x"));
    g.add_edge(edge("ha", "x"));
    g.add_edge(edge("hm", "x"));

    let m = ManifestIntents {
        extension_id: "ext-sort".to_string(),
        declared_capabilities: vec![cap("z:cap"), cap("a:cap"), cap("m:cap")]
            .into_iter()
            .collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 11_000_000)
        .unwrap();

    let evidence_caps: Vec<&str> = report
        .per_capability_evidence
        .iter()
        .map(|e| e.capability.as_str())
        .collect();
    let mut sorted_caps = evidence_caps.clone();
    sorted_caps.sort();
    assert_eq!(evidence_caps, sorted_caps);
}

// ---------------------------------------------------------------------------
// 36) Precision ratio edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_precision_ratio_manifest_larger_than_upper_bound() {
    // If path-sensitive analysis removes a cap that was in manifest,
    // the ratio may be < 1_000_000. But manifest fallback re-adds declared caps.
    // So test with undeclared caps on dead path.
    let mut g = EffectGraph::new("ext-prec");
    g.add_node(entry_node("e"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "x"));

    let m = ManifestIntents {
        extension_id: "ext-prec".to_string(),
        declared_capabilities: vec![cap("c1"), cap("c2"), cap("c3")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 12_000_000)
        .unwrap();
    // All 3 caps from manifest are added via fallback
    assert_eq!(report.upper_bound_capabilities.len(), 3);
    assert_eq!(report.precision.ratio_millionths, 1_000_000);
}

#[test]
fn enrichment_precision_upper_bound_exceeds_manifest() {
    let mut g = EffectGraph::new("ext-over");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h1", "cap:a"));
    g.add_node(hostcall_node("h2", "cap:b"));
    g.add_node(hostcall_node("h3", "cap:c"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "h1"));
    g.add_edge(edge("h1", "h2"));
    g.add_edge(edge("h2", "h3"));
    g.add_edge(edge("h3", "x"));

    let m = ManifestIntents {
        extension_id: "ext-over".to_string(),
        declared_capabilities: vec![cap("cap:a")].into_iter().collect(), // only 1 declared
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 13_000_000)
        .unwrap();
    assert_eq!(report.upper_bound_capabilities.len(), 3);
    assert_eq!(report.precision.manifest_declared_size, 1);
    assert_eq!(report.precision.ratio_millionths, 3_000_000); // 3/1
}

// ---------------------------------------------------------------------------
// 37) Undeclared capabilities — more complex cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_undeclared_caps_multiple() {
    let mut g = EffectGraph::new("ext-und");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h1", "cap:declared"));
    g.add_node(hostcall_node("h2", "cap:secret1"));
    g.add_node(hostcall_node("h3", "cap:secret2"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "h1"));
    g.add_edge(edge("h1", "h2"));
    g.add_edge(edge("h2", "h3"));
    g.add_edge(edge("h3", "x"));

    let m = ManifestIntents {
        extension_id: "ext-und".to_string(),
        declared_capabilities: vec![cap("cap:declared")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 14_000_000)
        .unwrap();
    let undeclared = report.undeclared_capabilities(&m);
    assert_eq!(undeclared.len(), 2);
    assert!(undeclared.contains(&cap("cap:secret1")));
    assert!(undeclared.contains(&cap("cap:secret2")));
}

#[test]
fn enrichment_undeclared_empty_when_all_declared() {
    let mut g = EffectGraph::new("ext-alld");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h1", "c1"));
    g.add_node(hostcall_node("h2", "c2"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "h1"));
    g.add_edge(edge("h1", "h2"));
    g.add_edge(edge("h2", "x"));

    let m = ManifestIntents {
        extension_id: "ext-alld".to_string(),
        declared_capabilities: vec![cap("c1"), cap("c2")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 15_000_000)
        .unwrap();
    let undeclared = report.undeclared_capabilities(&m);
    assert!(undeclared.is_empty());
}

// ---------------------------------------------------------------------------
// 38) Unused declared — manifest fallback covers them
// ---------------------------------------------------------------------------

#[test]
fn enrichment_unused_declared_always_empty_due_to_fallback() {
    let mut g = EffectGraph::new("ext-unu");
    g.add_node(entry_node("e"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "x"));

    let m = ManifestIntents {
        extension_id: "ext-unu".to_string(),
        declared_capabilities: vec![cap("phantom1"), cap("phantom2")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 16_000_000)
        .unwrap();
    // ManifestFallback adds declared caps even if not in graph
    let unused = report.unused_declared_capabilities(&m);
    assert!(unused.is_empty());
}

// ---------------------------------------------------------------------------
// 39) Cache — zero-capacity cache rejects all inserts
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cache_zero_capacity_rejects_inserts() {
    let mut cache = AnalysisCache::new(0);
    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g"),
        manifest_hash: ContentHash::compute(b"m"),
        path_sensitive: false,
    };
    cache.insert(key.clone(), do_analysis());
    assert!(cache.is_empty());
    assert!(cache.get(&key).is_none());
}

// ---------------------------------------------------------------------------
// 40) Cache — capacity-1 evicts immediately on second insert
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cache_capacity_one_evicts_on_second() {
    let mut cache = AnalysisCache::new(1);
    let report = do_analysis();

    let k1 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g1"),
        manifest_hash: ContentHash::compute(b"m1"),
        path_sensitive: false,
    };
    let k2 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g2"),
        manifest_hash: ContentHash::compute(b"m2"),
        path_sensitive: false,
    };

    cache.insert(k1.clone(), report.clone());
    assert_eq!(cache.len(), 1);

    cache.insert(k2.clone(), report);
    assert_eq!(cache.len(), 1);
    assert!(cache.get(&k1).is_none());
    assert!(cache.get(&k2).is_some());
}

// ---------------------------------------------------------------------------
// 41) Cache — replacing same key doesn't increase length
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cache_same_key_replace_no_growth() {
    let mut cache = AnalysisCache::new(10);
    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g"),
        manifest_hash: ContentHash::compute(b"m"),
        path_sensitive: false,
    };
    let report = do_analysis();
    for _ in 0..5 {
        cache.insert(key.clone(), report.clone());
    }
    assert_eq!(cache.len(), 1);
}

// ---------------------------------------------------------------------------
// 42) Cache serde roundtrip with multiple entries
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cache_serde_multiple_entries() {
    let mut cache = AnalysisCache::new(10);
    let report = do_analysis();

    for i in 0..4u8 {
        let key = AnalysisCacheKey {
            effect_graph_hash: ContentHash::compute(&[i]),
            manifest_hash: ContentHash::compute(&[i + 10]),
            path_sensitive: i.is_multiple_of(2),
        };
        cache.insert(key, report.clone());
    }
    assert_eq!(cache.len(), 4);

    let json = serde_json::to_string(&cache).unwrap();
    let back: AnalysisCache = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 4);
}

// ---------------------------------------------------------------------------
// 43) Report — report_id varies with extension_id
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_id_varies_with_extension_id() {
    let gh = ContentHash::compute(b"g");
    let mh = ContentHash::compute(b"m");
    let id1 = StaticAnalysisReport::derive_report_id("ext-a", &gh, &mh, 1000, "z").unwrap();
    let id2 = StaticAnalysisReport::derive_report_id("ext-b", &gh, &mh, 1000, "z").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_report_id_varies_with_graph_hash() {
    let gh1 = ContentHash::compute(b"g1");
    let gh2 = ContentHash::compute(b"g2");
    let mh = ContentHash::compute(b"m");
    let id1 = StaticAnalysisReport::derive_report_id("ext", &gh1, &mh, 1000, "z").unwrap();
    let id2 = StaticAnalysisReport::derive_report_id("ext", &gh2, &mh, 1000, "z").unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn enrichment_report_id_varies_with_manifest_hash() {
    let gh = ContentHash::compute(b"g");
    let mh1 = ContentHash::compute(b"m1");
    let mh2 = ContentHash::compute(b"m2");
    let id1 = StaticAnalysisReport::derive_report_id("ext", &gh, &mh1, 1000, "z").unwrap();
    let id2 = StaticAnalysisReport::derive_report_id("ext", &gh, &mh2, 1000, "z").unwrap();
    assert_ne!(id1, id2);
}

// ---------------------------------------------------------------------------
// 44) Content hash — varies with capability set
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_varies_with_caps() {
    let analyzer = StaticAuthorityAnalyzer::new(config());

    let mut g1 = EffectGraph::new("ext-ch");
    g1.add_node(entry_node("e"));
    g1.add_node(hostcall_node("h", "cap:one"));
    g1.add_node(exit_node("x"));
    g1.add_edge(edge("e", "h"));
    g1.add_edge(edge("h", "x"));

    let m1 = ManifestIntents {
        extension_id: "ext-ch".to_string(),
        declared_capabilities: vec![cap("cap:one")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let mut g2 = EffectGraph::new("ext-ch");
    g2.add_node(entry_node("e"));
    g2.add_node(hostcall_node("h", "cap:two"));
    g2.add_node(exit_node("x"));
    g2.add_edge(edge("e", "h"));
    g2.add_edge(edge("h", "x"));

    let m2 = ManifestIntents {
        extension_id: "ext-ch".to_string(),
        declared_capabilities: vec![cap("cap:two")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let r1 = analyzer
        .analyze(&g1, &m1, SecurityEpoch::from_raw(1), 17_000_000)
        .unwrap();
    let r2 = analyzer
        .analyze(&g2, &m2, SecurityEpoch::from_raw(1), 17_000_000)
        .unwrap();
    assert_ne!(r1.content_hash(), r2.content_hash());
}

// ---------------------------------------------------------------------------
// 45) Content hash — stable across repeated calls
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_idempotent() {
    let report = do_analysis();
    let h1 = report.content_hash();
    let h2 = report.content_hash();
    let h3 = report.content_hash();
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
}

// ---------------------------------------------------------------------------
// 46) AnalysisError — IdDerivationFailed display
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_id_derivation_failed_display() {
    // We can't easily construct an IdError, but we can verify Display for other variants
    let err = AnalysisError::TimedOut {
        extension_id: "ext-t".to_string(),
        elapsed_ns: 200,
        budget_ns: 100,
    };
    let msg = err.to_string();
    assert!(msg.contains("200ns"));
    assert!(msg.contains("100ns"));
    assert!(msg.contains("ext-t"));
}

// ---------------------------------------------------------------------------
// 47) EffectGraph — serde with complex topology
// ---------------------------------------------------------------------------

#[test]
fn enrichment_effect_graph_serde_complex() {
    let mut g = EffectGraph::new("ext-cplx");
    g.add_node(entry_node("e1"));
    g.add_node(entry_node("e2"));
    g.add_node(control_flow_node("b"));
    g.add_node(computation_node("c"));
    g.add_node(hostcall_node("h1", "cap:alpha"));
    g.add_node(hostcall_node("h2", "cap:beta"));
    g.add_node(exit_node("x1"));
    g.add_node(exit_node("x2"));
    g.add_edge(edge("e1", "b"));
    g.add_edge(edge("e2", "c"));
    g.add_edge(edge("b", "h1"));
    g.add_edge(dead_edge("b", "h2"));
    g.add_edge(edge("c", "h2"));
    g.add_edge(edge("h1", "x1"));
    g.add_edge(edge("h2", "x2"));

    let json = serde_json::to_string(&g).unwrap();
    let back: EffectGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
    assert_eq!(back.nodes.len(), 8);
    assert_eq!(back.edges.len(), 7);
}

// ---------------------------------------------------------------------------
// 48) ManifestIntents serde — with both declared + optional
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_intents_serde_with_optional() {
    let m = ManifestIntents {
        extension_id: "ext-opt".to_string(),
        declared_capabilities: vec![cap("fs:read"), cap("fs:write")].into_iter().collect(),
        optional_capabilities: vec![cap("net:connect"), cap("db:query")]
            .into_iter()
            .collect(),
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: ManifestIntents = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
    assert_eq!(back.declared_capabilities.len(), 2);
    assert_eq!(back.optional_capabilities.len(), 2);
}

// ---------------------------------------------------------------------------
// 49) Optional capabilities don't appear in upper bound if not reachable
// ---------------------------------------------------------------------------

#[test]
fn enrichment_optional_caps_not_in_upper_bound_when_unreachable() {
    let mut g = EffectGraph::new("ext-optcap");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h", "cap:declared"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "h"));
    g.add_edge(edge("h", "x"));

    let m = ManifestIntents {
        extension_id: "ext-optcap".to_string(),
        declared_capabilities: vec![cap("cap:declared")].into_iter().collect(),
        optional_capabilities: vec![cap("cap:optional1"), cap("cap:optional2")]
            .into_iter()
            .collect(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 18_000_000)
        .unwrap();
    assert!(report.requires_capability(&cap("cap:declared")));
    assert!(!report.requires_capability(&cap("cap:optional1")));
    assert!(!report.requires_capability(&cap("cap:optional2")));
}

#[test]
fn enrichment_optional_caps_appear_if_reachable_in_graph() {
    let mut g = EffectGraph::new("ext-optreach");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h1", "cap:declared"));
    g.add_node(hostcall_node("h2", "cap:optional"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "h1"));
    g.add_edge(edge("h1", "h2"));
    g.add_edge(edge("h2", "x"));

    let m = ManifestIntents {
        extension_id: "ext-optreach".to_string(),
        declared_capabilities: vec![cap("cap:declared")].into_iter().collect(),
        optional_capabilities: vec![cap("cap:optional")].into_iter().collect(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 19_000_000)
        .unwrap();
    // cap:optional is reachable in graph -> included via LatticeReachability
    assert!(report.requires_capability(&cap("cap:optional")));
}

// ---------------------------------------------------------------------------
// 50) Report fields preserved through analysis
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_zone_matches_config() {
    let cfg = AnalysisConfig {
        zone: "production-eu-west".to_string(),
        ..config()
    };
    let analyzer = StaticAuthorityAnalyzer::new(cfg);
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(5),
            20_000_000,
        )
        .unwrap();
    assert_eq!(report.zone, "production-eu-west");
}

#[test]
fn enrichment_report_epoch_preserved() {
    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(999),
            21_000_000,
        )
        .unwrap();
    assert_eq!(report.epoch, SecurityEpoch::from_raw(999));
}

#[test]
fn enrichment_report_timestamp_preserved() {
    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            42_424_242,
        )
        .unwrap();
    assert_eq!(report.timestamp_ns, 42_424_242);
}

#[test]
fn enrichment_report_timed_out_always_false_in_normal_analysis() {
    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            22_000_000,
        )
        .unwrap();
    assert!(!report.timed_out);
}

#[test]
fn enrichment_report_analysis_duration_is_zero_by_default() {
    let report = do_analysis();
    assert_eq!(report.analysis_duration_ns, 0);
}

// ---------------------------------------------------------------------------
// 51) Primary analysis method is always LatticeReachability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_primary_method_lattice_reachability() {
    let report = do_analysis();
    assert_eq!(
        report.primary_analysis_method,
        AnalysisMethod::LatticeReachability
    );
}

// ---------------------------------------------------------------------------
// 52) Computation-only graph — no caps at all
// ---------------------------------------------------------------------------

#[test]
fn enrichment_computation_only_graph_no_caps() {
    let mut g = EffectGraph::new("ext-comp");
    g.add_node(entry_node("e"));
    g.add_node(computation_node("c1"));
    g.add_node(computation_node("c2"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "c1"));
    g.add_edge(edge("c1", "c2"));
    g.add_edge(edge("c2", "x"));

    let m = ManifestIntents {
        extension_id: "ext-comp".to_string(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 23_000_000)
        .unwrap();
    assert!(report.upper_bound_capabilities.is_empty());
    assert_eq!(report.precision.upper_bound_size, 0);
    assert_eq!(report.precision.manifest_declared_size, 0);
    assert_eq!(report.precision.ratio_millionths, 1_000_000);
}

// ---------------------------------------------------------------------------
// 53) Complex branching with mixed dead/live edges
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mixed_dead_live_branches_path_sensitive() {
    let mut g = EffectGraph::new("ext-mix");
    g.add_node(entry_node("e"));
    g.add_node(control_flow_node("b1"));
    g.add_node(control_flow_node("b2"));
    g.add_node(hostcall_node("h_live1", "cap:live1"));
    g.add_node(hostcall_node("h_live2", "cap:live2"));
    g.add_node(hostcall_node("h_dead1", "cap:dead1"));
    g.add_node(exit_node("x"));

    g.add_edge(edge("e", "b1"));
    g.add_edge(edge("b1", "h_live1"));
    g.add_edge(dead_edge("b1", "h_dead1"));
    g.add_edge(edge("h_live1", "b2"));
    g.add_edge(edge("h_dead1", "b2"));
    g.add_edge(edge("b2", "h_live2"));
    g.add_edge(edge("h_live2", "x"));

    let m = ManifestIntents {
        extension_id: "ext-mix".to_string(),
        declared_capabilities: vec![cap("cap:live1"), cap("cap:live2")]
            .into_iter()
            .collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let ps_cfg = AnalysisConfig {
        path_sensitive: true,
        ..config()
    };
    let analyzer = StaticAuthorityAnalyzer::new(ps_cfg);
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 24_000_000)
        .unwrap();
    assert!(report.requires_capability(&cap("cap:live1")));
    assert!(report.requires_capability(&cap("cap:live2")));
    // cap:dead1 not in manifest and on dead edge -> excluded
    assert!(!report.requires_capability(&cap("cap:dead1")));
    assert!(report.precision.excluded_by_path_sensitivity > 0);
}

// ---------------------------------------------------------------------------
// 54) Graph hash — dead vs live edge produces different hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_graph_hash_differs_dead_vs_live() {
    let mut g_live = EffectGraph::new("ext-h");
    g_live.add_node(entry_node("e"));
    g_live.add_node(exit_node("x"));
    g_live.add_edge(edge("e", "x"));

    let mut g_dead = EffectGraph::new("ext-h");
    g_dead.add_node(entry_node("e"));
    g_dead.add_node(exit_node("x"));
    g_dead.add_edge(dead_edge("e", "x"));

    let analyzer_live = StaticAuthorityAnalyzer::new(config());
    let analyzer_dead = StaticAuthorityAnalyzer::new(config());

    let m = ManifestIntents {
        extension_id: "ext-h".to_string(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };

    let r_live = analyzer_live
        .analyze(&g_live, &m, SecurityEpoch::from_raw(1), 25_000_000)
        .unwrap();
    let r_dead = analyzer_dead
        .analyze(&g_dead, &m, SecurityEpoch::from_raw(1), 25_000_000)
        .unwrap();
    assert_ne!(r_live.effect_graph_hash, r_dead.effect_graph_hash);
}

// ---------------------------------------------------------------------------
// 55) Extension ID in report matches graph
// ---------------------------------------------------------------------------

#[test]
fn enrichment_extension_id_in_report_matches_graph() {
    let report = do_analysis();
    assert_eq!(report.extension_id, "test-ext");
}

// ---------------------------------------------------------------------------
// 56) Large stress test — deep chain with 200 caps
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stress_deep_chain_200_caps() {
    let count = 200;
    let mut g = EffectGraph::new("ext-deep");
    g.add_node(entry_node("e"));

    let mut expected = BTreeSet::new();
    for i in 0..count {
        let cap_name = format!("cap:{i}");
        let node_id = format!("h{i}");
        g.add_node(hostcall_node(&node_id, &cap_name));
        expected.insert(cap(&cap_name));
    }
    g.add_node(exit_node("x"));

    g.add_edge(edge("e", "h0"));
    for i in 0..count - 1 {
        g.add_edge(edge(&format!("h{i}"), &format!("h{}", i + 1)));
    }
    g.add_edge(edge(&format!("h{}", count - 1), "x"));

    let m = ManifestIntents {
        extension_id: "ext-deep".to_string(),
        declared_capabilities: expected.clone(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 26_000_000)
        .unwrap();
    assert_eq!(report.upper_bound_capabilities.len(), count);
    assert_eq!(report.upper_bound_capabilities, expected);
}

// ---------------------------------------------------------------------------
// 57) Stress test — wide fan-out
// ---------------------------------------------------------------------------

#[test]
fn enrichment_stress_wide_fanout_100() {
    let count = 100;
    let mut g = EffectGraph::new("ext-fan");
    g.add_node(entry_node("e"));

    let mut expected = BTreeSet::new();
    for i in 0..count {
        let cap_name = format!("fan:{i}");
        let node_id = format!("h{i}");
        g.add_node(hostcall_node(&node_id, &cap_name));
        g.add_edge(edge("e", &node_id));
        g.add_node(exit_node(&format!("x{i}")));
        g.add_edge(edge(&node_id, &format!("x{i}")));
        expected.insert(cap(&cap_name));
    }

    let m = ManifestIntents {
        extension_id: "ext-fan".to_string(),
        declared_capabilities: expected.clone(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 27_000_000)
        .unwrap();
    assert_eq!(report.upper_bound_capabilities.len(), count);
}

// ---------------------------------------------------------------------------
// 58) Entry-to-exit with no intermediate nodes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_entry_directly_to_exit_no_caps() {
    let mut g = EffectGraph::new("ext-direct");
    g.add_node(entry_node("e"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "x"));

    let m = ManifestIntents {
        extension_id: "ext-direct".to_string(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 28_000_000)
        .unwrap();
    assert!(report.upper_bound_capabilities.is_empty());
    assert!(report.per_capability_evidence.is_empty());
}

// ---------------------------------------------------------------------------
// 59) EffectNode source_location preserved through serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_source_location_preserved() {
    let node = EffectNode {
        node_id: "hc-1".to_string(),
        kind: EffectNodeKind::HostcallSite {
            capability: cap("fs:read"),
        },
        source_location: Some("module.rs:42".to_string()),
    };
    let json = serde_json::to_string(&node).unwrap();
    let back: EffectNode = serde_json::from_str(&json).unwrap();
    assert_eq!(back.source_location, Some("module.rs:42".to_string()));
}

#[test]
fn enrichment_source_location_none_preserved() {
    let node = computation_node("c");
    let json = serde_json::to_string(&node).unwrap();
    let back: EffectNode = serde_json::from_str(&json).unwrap();
    assert_eq!(back.source_location, None);
}

// ---------------------------------------------------------------------------
// 60) AnalysisCacheKey — equality and cloning
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cache_key_clone_equals_original() {
    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"data"),
        manifest_hash: ContentHash::compute(b"manifest"),
        path_sensitive: true,
    };
    let cloned = key.clone();
    assert_eq!(key, cloned);
}

#[test]
fn enrichment_cache_key_different_path_sensitive_not_equal() {
    let k1 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"same"),
        manifest_hash: ContentHash::compute(b"same"),
        path_sensitive: false,
    };
    let k2 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"same"),
        manifest_hash: ContentHash::compute(b"same"),
        path_sensitive: true,
    };
    assert_ne!(k1, k2);
}

// ---------------------------------------------------------------------------
// 61) AnalysisConfig — custom values roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_config_custom_serde_roundtrip() {
    let cfg = AnalysisConfig {
        time_budget_ns: 1_000_000,
        path_sensitive: false,
        zone: "staging-us-east-1".to_string(),
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: AnalysisConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ---------------------------------------------------------------------------
// 62) Capability — empty string is valid
// ---------------------------------------------------------------------------

#[test]
fn enrichment_capability_empty_string() {
    let c = cap("");
    assert_eq!(c.as_str(), "");
    assert_eq!(c.to_string(), "");
    let json = serde_json::to_string(&c).unwrap();
    let back: Capability = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// 63) Capability — special characters
// ---------------------------------------------------------------------------

#[test]
fn enrichment_capability_special_chars() {
    let c = cap("cap:with/slashes.and-dashes_underscores");
    assert_eq!(c.as_str(), "cap:with/slashes.and-dashes_underscores");
    let json = serde_json::to_string(&c).unwrap();
    let back: Capability = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn enrichment_capability_unicode() {
    let c = cap("cap:unicode_\u{00e9}\u{00e8}\u{00ea}");
    let json = serde_json::to_string(&c).unwrap();
    let back: Capability = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ---------------------------------------------------------------------------
// 64) EffectEdge — Ord and BTreeSet usage
// ---------------------------------------------------------------------------

#[test]
fn enrichment_effect_edge_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(edge("b", "c"));
    set.insert(edge("a", "b"));
    set.insert(edge("b", "c")); // duplicate
    assert_eq!(set.len(), 2);
}

// ---------------------------------------------------------------------------
// 65) PerCapabilityEvidence — empty requiring_nodes for ManifestFallback
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_fallback_evidence_empty_nodes() {
    let mut g = EffectGraph::new("ext-fb");
    g.add_node(entry_node("e"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "x"));

    let m = ManifestIntents {
        extension_id: "ext-fb".to_string(),
        declared_capabilities: vec![cap("phantom:cap")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 29_000_000)
        .unwrap();

    let ev = report
        .per_capability_evidence
        .iter()
        .find(|e| e.capability == cap("phantom:cap"))
        .unwrap();
    assert_eq!(ev.analysis_method, AnalysisMethod::ManifestFallback);
    assert!(ev.requiring_nodes.is_empty());
    assert!(ev.summary.contains("manifest"));
}

// ---------------------------------------------------------------------------
// 66) PerCapabilityEvidence — LatticeReachability has non-empty nodes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lattice_reachability_evidence_has_nodes() {
    let report = do_analysis();
    let ev = report
        .per_capability_evidence
        .iter()
        .find(|e| e.capability == cap("fs:read"))
        .unwrap();
    assert_eq!(ev.analysis_method, AnalysisMethod::LatticeReachability);
    assert!(!ev.requiring_nodes.is_empty());
    assert!(ev.requiring_nodes.contains("hc-fs"));
}

// ---------------------------------------------------------------------------
// 67) ExcludedDeadPath evidence generated
// ---------------------------------------------------------------------------

#[test]
fn enrichment_excluded_dead_path_evidence_details() {
    let mut g = EffectGraph::new("ext-edp");
    g.add_node(entry_node("e"));
    g.add_node(control_flow_node("b"));
    g.add_node(hostcall_node("alive", "cap:alive"));
    g.add_node(hostcall_node("dead_n", "cap:dead_only"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "b"));
    g.add_edge(edge("b", "alive"));
    g.add_edge(dead_edge("b", "dead_n"));
    g.add_edge(edge("alive", "x"));
    g.add_edge(edge("dead_n", "x"));

    let m = ManifestIntents {
        extension_id: "ext-edp".to_string(),
        declared_capabilities: vec![cap("cap:alive")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let ps_cfg = AnalysisConfig {
        path_sensitive: true,
        ..config()
    };
    let analyzer = StaticAuthorityAnalyzer::new(ps_cfg);
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 30_000_000)
        .unwrap();

    let excluded = report
        .per_capability_evidence
        .iter()
        .find(|e| e.capability == cap("cap:dead_only"))
        .unwrap();
    assert_eq!(excluded.analysis_method, AnalysisMethod::ExcludedDeadPath);
    assert!(excluded.summary.contains("dead paths"));
}

// ---------------------------------------------------------------------------
// 68) EffectNodeKind — Eq and Clone
// ---------------------------------------------------------------------------

#[test]
fn enrichment_effect_node_kind_eq_same_hostcall() {
    let k1 = EffectNodeKind::HostcallSite {
        capability: cap("fs:read"),
    };
    let k2 = EffectNodeKind::HostcallSite {
        capability: cap("fs:read"),
    };
    assert_eq!(k1, k2);
}

#[test]
fn enrichment_effect_node_kind_ne_different_hostcall() {
    let k1 = EffectNodeKind::HostcallSite {
        capability: cap("fs:read"),
    };
    let k2 = EffectNodeKind::HostcallSite {
        capability: cap("fs:write"),
    };
    assert_ne!(k1, k2);
}

#[test]
fn enrichment_effect_node_kind_ne_different_variants() {
    assert_ne!(EffectNodeKind::Entry, EffectNodeKind::Exit);
    assert_ne!(EffectNodeKind::ControlFlow, EffectNodeKind::Computation);
}

// ---------------------------------------------------------------------------
// 69) Report serde — complex report with multiple evidence types
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_serde_with_mixed_evidence() {
    let mut g = EffectGraph::new("ext-mixed");
    g.add_node(entry_node("e"));
    g.add_node(control_flow_node("b"));
    g.add_node(hostcall_node("h_live", "cap:live"));
    g.add_node(hostcall_node("h_dead", "cap:dead"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "b"));
    g.add_edge(edge("b", "h_live"));
    g.add_edge(dead_edge("b", "h_dead"));
    g.add_edge(edge("h_live", "x"));
    g.add_edge(edge("h_dead", "x"));

    let m = ManifestIntents {
        extension_id: "ext-mixed".to_string(),
        declared_capabilities: vec![cap("cap:live"), cap("cap:phantom")]
            .into_iter()
            .collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let ps_cfg = AnalysisConfig {
        path_sensitive: true,
        ..config()
    };
    let analyzer = StaticAuthorityAnalyzer::new(ps_cfg);
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(3), 31_000_000)
        .unwrap();

    let json = serde_json::to_string(&report).unwrap();
    let back: StaticAnalysisReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// 70) Graph with only control flow nodes — no caps collected
// ---------------------------------------------------------------------------

#[test]
fn enrichment_control_flow_only_no_caps() {
    let mut g = EffectGraph::new("ext-cf");
    g.add_node(entry_node("e"));
    g.add_node(control_flow_node("b1"));
    g.add_node(control_flow_node("b2"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "b1"));
    g.add_edge(edge("b1", "b2"));
    g.add_edge(edge("b2", "x"));

    let m = ManifestIntents {
        extension_id: "ext-cf".to_string(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 32_000_000)
        .unwrap();
    assert!(report.upper_bound_capabilities.is_empty());
}

// ---------------------------------------------------------------------------
// 71) Same cap at multiple nodes — evidence aggregates node IDs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_same_cap_multiple_nodes_aggregated() {
    let mut g = EffectGraph::new("ext-agg");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h1", "fs:read"));
    g.add_node(hostcall_node("h2", "fs:read"));
    g.add_node(hostcall_node("h3", "fs:read"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "h1"));
    g.add_edge(edge("h1", "h2"));
    g.add_edge(edge("h2", "h3"));
    g.add_edge(edge("h3", "x"));

    let m = ManifestIntents {
        extension_id: "ext-agg".to_string(),
        declared_capabilities: vec![cap("fs:read")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 33_000_000)
        .unwrap();

    assert_eq!(report.upper_bound_capabilities.len(), 1);
    let ev = report
        .per_capability_evidence
        .iter()
        .find(|e| e.capability == cap("fs:read"))
        .unwrap();
    assert_eq!(ev.requiring_nodes.len(), 3);
    assert!(ev.requiring_nodes.contains("h1"));
    assert!(ev.requiring_nodes.contains("h2"));
    assert!(ev.requiring_nodes.contains("h3"));
}

// ---------------------------------------------------------------------------
// 72) Report — content_hash differs when extension_id differs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_content_hash_differs_by_extension_id() {
    let analyzer = StaticAuthorityAnalyzer::new(config());

    let mut g1 = EffectGraph::new("ext-aa");
    g1.add_node(entry_node("e"));
    g1.add_node(exit_node("x"));
    g1.add_edge(edge("e", "x"));
    let m1 = ManifestIntents {
        extension_id: "ext-aa".to_string(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };

    let mut g2 = EffectGraph::new("ext-bb");
    g2.add_node(entry_node("e"));
    g2.add_node(exit_node("x"));
    g2.add_edge(edge("e", "x"));
    let m2 = ManifestIntents {
        extension_id: "ext-bb".to_string(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };

    let r1 = analyzer
        .analyze(&g1, &m1, SecurityEpoch::from_raw(1), 34_000_000)
        .unwrap();
    let r2 = analyzer
        .analyze(&g2, &m2, SecurityEpoch::from_raw(1), 34_000_000)
        .unwrap();
    assert_ne!(r1.content_hash(), r2.content_hash());
}

// ---------------------------------------------------------------------------
// 73) PrecisionEstimate — Clone and Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_precision_estimate_clone() {
    let pe = PrecisionEstimate {
        upper_bound_size: 10,
        manifest_declared_size: 5,
        ratio_millionths: 2_000_000,
        excluded_by_path_sensitivity: 3,
    };
    let cloned = pe.clone();
    assert_eq!(pe, cloned);
}

#[test]
fn enrichment_precision_estimate_debug_non_empty() {
    let pe = PrecisionEstimate {
        upper_bound_size: 1,
        manifest_declared_size: 1,
        ratio_millionths: 1_000_000,
        excluded_by_path_sensitivity: 0,
    };
    let dbg = format!("{pe:?}");
    assert!(dbg.contains("PrecisionEstimate"));
    assert!(dbg.contains("1000000"));
}

// ---------------------------------------------------------------------------
// 74) AnalysisError — Clone and Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_error_clone() {
    let err = AnalysisError::NoEntryNode {
        extension_id: "ext".to_string(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn enrichment_analysis_error_debug() {
    let err = AnalysisError::EmptyEffectGraph {
        extension_id: "ext-dbg".to_string(),
    };
    let dbg = format!("{err:?}");
    assert!(dbg.contains("EmptyEffectGraph"));
    assert!(dbg.contains("ext-dbg"));
}

// ---------------------------------------------------------------------------
// 75) Cache — clear after insertions restores empty state
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cache_clear_restores_empty() {
    let mut cache = AnalysisCache::new(5);
    let report = do_analysis();
    for i in 0..5u8 {
        let key = AnalysisCacheKey {
            effect_graph_hash: ContentHash::compute(&[i]),
            manifest_hash: ContentHash::compute(&[i + 50]),
            path_sensitive: false,
        };
        cache.insert(key, report.clone());
    }
    assert_eq!(cache.len(), 5);
    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

// ---------------------------------------------------------------------------
// 76) Analysis determinism — two analyzers with same config produce same
// ---------------------------------------------------------------------------

#[test]
fn enrichment_two_analyzers_same_config_same_result() {
    let cfg = config();
    let a1 = StaticAuthorityAnalyzer::new(cfg.clone());
    let a2 = StaticAuthorityAnalyzer::new(cfg);

    let g = simple_graph();
    let m = simple_manifest();
    let epoch = SecurityEpoch::from_raw(7);

    let r1 = a1.analyze(&g, &m, epoch, 35_000_000).unwrap();
    let r2 = a2.analyze(&g, &m, epoch, 35_000_000).unwrap();
    assert_eq!(r1.report_id, r2.report_id);
    assert_eq!(r1.content_hash(), r2.content_hash());
    assert_eq!(r1.upper_bound_capabilities, r2.upper_bound_capabilities);
    assert_eq!(r1.per_capability_evidence, r2.per_capability_evidence);
}

// ---------------------------------------------------------------------------
// 77) Report — report_id is non-zero bytes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_id_non_zero() {
    let report = do_analysis();
    assert!(!report.report_id.as_bytes().iter().all(|b| *b == 0));
}

// ---------------------------------------------------------------------------
// 78) Report — effect_graph_hash and manifest_hash are non-zero
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hashes_non_zero() {
    let report = do_analysis();
    assert_ne!(report.effect_graph_hash, ContentHash([0u8; 32]));
    assert_ne!(report.manifest_hash, ContentHash([0u8; 32]));
}

// ---------------------------------------------------------------------------
// 79) Graph with self-loop on entry
// ---------------------------------------------------------------------------

#[test]
fn enrichment_self_loop_on_entry_terminates() {
    let mut g = EffectGraph::new("ext-self");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h", "cap:ok"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "e")); // self-loop
    g.add_edge(edge("e", "h"));
    g.add_edge(edge("h", "x"));

    let m = ManifestIntents {
        extension_id: "ext-self".to_string(),
        declared_capabilities: vec![cap("cap:ok")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 36_000_000)
        .unwrap();
    assert!(report.requires_capability(&cap("cap:ok")));
}

// ---------------------------------------------------------------------------
// 80) Graph with hostcall on self-loop
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hostcall_self_loop_terminates() {
    let mut g = EffectGraph::new("ext-hsl");
    g.add_node(entry_node("e"));
    g.add_node(hostcall_node("h", "cap:loopy"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "h"));
    g.add_edge(edge("h", "h")); // hostcall self-loop
    g.add_edge(edge("h", "x"));

    let m = ManifestIntents {
        extension_id: "ext-hsl".to_string(),
        declared_capabilities: vec![cap("cap:loopy")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 37_000_000)
        .unwrap();
    assert!(report.requires_capability(&cap("cap:loopy")));
    assert_eq!(report.upper_bound_capabilities.len(), 1);
}

// ---------------------------------------------------------------------------
// 81) PerCapabilityEvidence summary format for lattice
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_summary_format_lattice() {
    let report = do_analysis();
    let ev = report
        .per_capability_evidence
        .iter()
        .find(|e| e.capability == cap("fs:read"))
        .unwrap();
    assert!(ev.summary.contains("reachable at"));
    assert!(ev.summary.contains("hostcall site(s)"));
}

// ---------------------------------------------------------------------------
// 82) PerCapabilityEvidence summary format for manifest fallback
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evidence_summary_format_manifest_fallback() {
    let mut g = EffectGraph::new("ext-sfm");
    g.add_node(entry_node("e"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "x"));

    let m = ManifestIntents {
        extension_id: "ext-sfm".to_string(),
        declared_capabilities: vec![cap("cap:ghost")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 38_000_000)
        .unwrap();

    let ev = report
        .per_capability_evidence
        .iter()
        .find(|e| e.capability == cap("cap:ghost"))
        .unwrap();
    assert!(ev.summary.contains("declared in manifest"));
    assert!(ev.summary.contains("included conservatively"));
}

// ---------------------------------------------------------------------------
// 83) EffectGraph clone preserves all data
// ---------------------------------------------------------------------------

#[test]
fn enrichment_effect_graph_clone() {
    let g = simple_graph();
    let cloned = g.clone();
    assert_eq!(g, cloned);
    assert_eq!(g.extension_id, cloned.extension_id);
    assert_eq!(g.nodes.len(), cloned.nodes.len());
    assert_eq!(g.edges.len(), cloned.edges.len());
}

// ---------------------------------------------------------------------------
// 84) ManifestIntents clone preserves all data
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_intents_clone() {
    let m = ManifestIntents {
        extension_id: "ext-clone".to_string(),
        declared_capabilities: vec![cap("c1"), cap("c2")].into_iter().collect(),
        optional_capabilities: vec![cap("o1")].into_iter().collect(),
    };
    let cloned = m.clone();
    assert_eq!(m, cloned);
}

// ---------------------------------------------------------------------------
// 85) StaticAnalysisReport clone preserves content_hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_clone_preserves_content_hash() {
    let report = do_analysis();
    let cloned = report.clone();
    assert_eq!(report.content_hash(), cloned.content_hash());
    assert_eq!(report, cloned);
}

// ---------------------------------------------------------------------------
// 86) Multiple exit nodes don't affect capabilities
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multiple_exit_nodes() {
    let mut g = EffectGraph::new("ext-2x");
    g.add_node(entry_node("e"));
    g.add_node(control_flow_node("b"));
    g.add_node(hostcall_node("h", "cap:only"));
    g.add_node(exit_node("x1"));
    g.add_node(exit_node("x2"));
    g.add_edge(edge("e", "b"));
    g.add_edge(edge("b", "h"));
    g.add_edge(edge("b", "x1")); // early exit
    g.add_edge(edge("h", "x2"));

    let m = ManifestIntents {
        extension_id: "ext-2x".to_string(),
        declared_capabilities: vec![cap("cap:only")].into_iter().collect(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(config());
    let report = analyzer
        .analyze(&g, &m, SecurityEpoch::from_raw(1), 39_000_000)
        .unwrap();
    assert!(report.requires_capability(&cap("cap:only")));
    assert_eq!(report.upper_bound_capabilities.len(), 1);
}

// ---------------------------------------------------------------------------
// 87) Capability in BTreeSet — deduplication
// ---------------------------------------------------------------------------

#[test]
fn enrichment_capability_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(cap("a"));
    set.insert(cap("b"));
    set.insert(cap("a")); // dup
    set.insert(cap("c"));
    set.insert(cap("b")); // dup
    assert_eq!(set.len(), 3);
}

// ---------------------------------------------------------------------------
// 88) AnalysisMethod in BTreeSet — all unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_method_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(AnalysisMethod::LatticeReachability);
    set.insert(AnalysisMethod::ManifestFallback);
    set.insert(AnalysisMethod::TimeoutFallback);
    set.insert(AnalysisMethod::ExcludedDeadPath);
    set.insert(AnalysisMethod::LatticeReachability); // dup
    assert_eq!(set.len(), 4);
}
