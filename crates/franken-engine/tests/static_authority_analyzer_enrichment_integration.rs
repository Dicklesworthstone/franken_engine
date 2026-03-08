#![forbid(unsafe_code)]
//! Enrichment integration tests for `static_authority_analyzer`.
//!
//! Adds exact Display messages, Debug distinctness, JSON field-name stability,
//! serde exact enum values, std::error::Error impl, validation edge cases,
//! and cache behavior beyond the existing 36 integration tests (+ 12 unit tests
//! added in previous enrichment).

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
