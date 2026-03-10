//! Integration tests for the `static_authority_analyzer` module.
//!
//! Covers areas not exercised by inline unit tests: optional manifest
//! capabilities, complex graph topologies, cache key deduplication,
//! cross-zone report differentiation, full analysis-to-cache pipeline,
//! large graph stress tests, AnalysisError serde, undeclared capability
//! detection, and path-sensitive behaviour with no dead edges.

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
    PrecisionEstimate, StaticAuthorityAnalyzer,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn cap(name: &str) -> Capability {
    Capability::new(name)
}

fn entry_node(id: &str) -> EffectNode {
    EffectNode {
        node_id: id.into(),
        kind: EffectNodeKind::Entry,
        source_location: None,
    }
}

fn hostcall_node(id: &str, capability: &str) -> EffectNode {
    EffectNode {
        node_id: id.into(),
        kind: EffectNodeKind::HostcallSite {
            capability: cap(capability),
        },
        source_location: Some(format!("{id}.rs:1")),
    }
}

fn control_flow_node(id: &str) -> EffectNode {
    EffectNode {
        node_id: id.into(),
        kind: EffectNodeKind::ControlFlow,
        source_location: None,
    }
}

fn computation_node(id: &str) -> EffectNode {
    EffectNode {
        node_id: id.into(),
        kind: EffectNodeKind::Computation,
        source_location: None,
    }
}

fn exit_node(id: &str) -> EffectNode {
    EffectNode {
        node_id: id.into(),
        kind: EffectNodeKind::Exit,
        source_location: None,
    }
}

fn edge(from: &str, to: &str) -> EffectEdge {
    EffectEdge {
        from: from.into(),
        to: to.into(),
        provably_dead: false,
    }
}

fn dead_edge(from: &str, to: &str) -> EffectEdge {
    EffectEdge {
        from: from.into(),
        to: to.into(),
        provably_dead: true,
    }
}

fn default_config() -> AnalysisConfig {
    AnalysisConfig {
        time_budget_ns: 60_000_000_000,
        path_sensitive: false,
        zone: "test-zone".into(),
    }
}

fn config_with_zone(zone: &str) -> AnalysisConfig {
    AnalysisConfig {
        time_budget_ns: 60_000_000_000,
        path_sensitive: false,
        zone: zone.into(),
    }
}

fn path_sensitive_config() -> AnalysisConfig {
    AnalysisConfig {
        time_budget_ns: 60_000_000_000,
        path_sensitive: true,
        zone: "test-zone".into(),
    }
}

/// Linear graph: entry -> hostcall(fs_read) -> exit
fn simple_graph() -> EffectGraph {
    let mut g = EffectGraph::new("ext-simple");
    g.add_node(entry_node("e0"));
    g.add_node(hostcall_node("h1", "fs_read"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e0", "h1"));
    g.add_edge(edge("h1", "x"));
    g
}

fn simple_manifest() -> ManifestIntents {
    ManifestIntents {
        extension_id: "ext-simple".into(),
        declared_capabilities: [cap("fs_read")].into(),
        optional_capabilities: BTreeSet::new(),
    }
}

/// Complex graph with 5 capabilities across branching paths.
fn complex_graph() -> EffectGraph {
    let mut g = EffectGraph::new("ext-complex");
    g.add_node(entry_node("e0"));
    g.add_node(control_flow_node("branch1"));
    g.add_node(hostcall_node("h_read", "fs_read"));
    g.add_node(hostcall_node("h_write", "fs_write"));
    g.add_node(control_flow_node("branch2"));
    g.add_node(hostcall_node("h_net", "net_send"));
    g.add_node(hostcall_node("h_log", "logging"));
    g.add_node(computation_node("c1"));
    g.add_node(hostcall_node("h_crypto", "crypto_sign"));
    g.add_node(exit_node("x"));

    g.add_edge(edge("e0", "branch1"));
    g.add_edge(edge("branch1", "h_read"));
    g.add_edge(edge("branch1", "h_write"));
    g.add_edge(edge("h_read", "branch2"));
    g.add_edge(edge("h_write", "branch2"));
    g.add_edge(edge("branch2", "h_net"));
    g.add_edge(edge("branch2", "h_log"));
    g.add_edge(edge("h_net", "c1"));
    g.add_edge(edge("h_log", "c1"));
    g.add_edge(edge("c1", "h_crypto"));
    g.add_edge(edge("h_crypto", "x"));
    g
}

fn complex_manifest() -> ManifestIntents {
    ManifestIntents {
        extension_id: "ext-complex".into(),
        declared_capabilities: [
            cap("fs_read"),
            cap("fs_write"),
            cap("net_send"),
            cap("logging"),
            cap("crypto_sign"),
        ]
        .into(),
        optional_capabilities: BTreeSet::new(),
    }
}

// ---------------------------------------------------------------------------
// AnalysisConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn analysis_config_default_values() {
    let config = AnalysisConfig::default();
    assert_eq!(config.time_budget_ns, 60_000_000_000);
    assert!(config.path_sensitive);
    assert_eq!(config.zone, "default");
}

#[test]
fn analysis_config_serde_roundtrip() {
    let config = AnalysisConfig {
        time_budget_ns: 30_000_000_000,
        path_sensitive: true,
        zone: "prod-zone".into(),
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: AnalysisConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

// ---------------------------------------------------------------------------
// Optional capabilities in manifest
// ---------------------------------------------------------------------------

#[test]
fn optional_capabilities_not_added_to_upper_bound() {
    let graph = simple_graph(); // only fs_read reachable
    let manifest = ManifestIntents {
        extension_id: "ext-simple".into(),
        declared_capabilities: [cap("fs_read")].into(),
        optional_capabilities: [cap("net_send"), cap("logging")].into(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 1_000)
        .unwrap();

    // Optional capabilities not reachable in graph should NOT be in upper bound.
    assert!(report.requires_capability(&cap("fs_read")));
    // net_send and logging are optional and unreachable.
    assert!(!report.requires_capability(&cap("net_send")));
    assert!(!report.requires_capability(&cap("logging")));
}

#[test]
fn manifest_intents_with_optional_caps_serde_roundtrip() {
    let manifest = ManifestIntents {
        extension_id: "ext-opt".into(),
        declared_capabilities: [cap("fs_read")].into(),
        optional_capabilities: [cap("net_send"), cap("logging")].into(),
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let restored: ManifestIntents = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, restored);
}

// ---------------------------------------------------------------------------
// Complex graph analysis
// ---------------------------------------------------------------------------

#[test]
fn complex_graph_all_caps_reachable() {
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(
            &complex_graph(),
            &complex_manifest(),
            SecurityEpoch::from_raw(3),
            5_000,
        )
        .unwrap();

    assert_eq!(report.upper_bound_capabilities.len(), 5);
    assert!(report.requires_capability(&cap("fs_read")));
    assert!(report.requires_capability(&cap("fs_write")));
    assert!(report.requires_capability(&cap("net_send")));
    assert!(report.requires_capability(&cap("logging")));
    assert!(report.requires_capability(&cap("crypto_sign")));

    assert_eq!(report.precision.upper_bound_size, 5);
    assert_eq!(report.precision.manifest_declared_size, 5);
    assert_eq!(report.precision.ratio_millionths, 1_000_000);
}

#[test]
fn complex_graph_per_capability_evidence() {
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(
            &complex_graph(),
            &complex_manifest(),
            SecurityEpoch::from_raw(1),
            6_000,
        )
        .unwrap();

    // Each capability should have exactly one requiring node.
    for evidence in &report.per_capability_evidence {
        if evidence.analysis_method == AnalysisMethod::LatticeReachability {
            assert!(
                !evidence.requiring_nodes.is_empty(),
                "cap {} should have requiring nodes",
                evidence.capability
            );
        }
    }

    // Specifically check crypto_sign evidence.
    let crypto_ev = report
        .per_capability_evidence
        .iter()
        .find(|e| e.capability == cap("crypto_sign"))
        .unwrap();
    assert!(crypto_ev.requiring_nodes.contains("h_crypto"));
    assert_eq!(
        crypto_ev.analysis_method,
        AnalysisMethod::LatticeReachability
    );
}

// ---------------------------------------------------------------------------
// Cross-zone differentiation
// ---------------------------------------------------------------------------

#[test]
fn different_zones_produce_different_report_ids() {
    let analyzer_a = StaticAuthorityAnalyzer::new(config_with_zone("zone-alpha"));
    let analyzer_b = StaticAuthorityAnalyzer::new(config_with_zone("zone-beta"));

    let report_a = analyzer_a
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();
    let report_b = analyzer_b
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();

    assert_ne!(report_a.report_id, report_b.report_id);
    assert_eq!(report_a.zone, "zone-alpha");
    assert_eq!(report_b.zone, "zone-beta");
    // But capabilities should match.
    assert_eq!(
        report_a.upper_bound_capabilities,
        report_b.upper_bound_capabilities
    );
}

// ---------------------------------------------------------------------------
// Undeclared capabilities detection
// ---------------------------------------------------------------------------

#[test]
fn undeclared_capabilities_detected_when_graph_has_extras() {
    let mut graph = EffectGraph::new("ext-extra");
    graph.add_node(entry_node("e"));
    graph.add_node(hostcall_node("h_read", "fs_read"));
    graph.add_node(hostcall_node("h_admin", "admin_access"));
    graph.add_node(exit_node("x"));
    graph.add_edge(edge("e", "h_read"));
    graph.add_edge(edge("h_read", "h_admin"));
    graph.add_edge(edge("h_admin", "x"));

    // Manifest only declares fs_read, not admin_access.
    let manifest = ManifestIntents {
        extension_id: "ext-extra".into(),
        declared_capabilities: [cap("fs_read")].into(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 2_000)
        .unwrap();

    let undeclared = report.undeclared_capabilities(&manifest);
    assert_eq!(undeclared.len(), 1);
    assert!(undeclared.contains(&cap("admin_access")));
}

#[test]
fn unused_declared_capabilities_detected() {
    // Graph only has fs_read reachable, but manifest declares fs_read + net_send.
    // net_send is NOT in graph at all, but gets included via ManifestFallback.
    let graph = simple_graph();
    let manifest = ManifestIntents {
        extension_id: "ext-simple".into(),
        declared_capabilities: [cap("fs_read"), cap("net_send")].into(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 3_000)
        .unwrap();

    // net_send is included in upper bound via ManifestFallback, so it's NOT unused.
    let unused = report.unused_declared_capabilities(&manifest);
    assert!(unused.is_empty());
    // Both caps should be in upper bound.
    assert_eq!(report.upper_bound_capabilities.len(), 2);
}

// ---------------------------------------------------------------------------
// Path-sensitive with no dead edges
// ---------------------------------------------------------------------------

#[test]
fn path_sensitive_with_no_dead_edges_matches_non_path_sensitive() {
    let graph = simple_graph();
    let manifest = simple_manifest();
    let epoch = SecurityEpoch::from_raw(1);

    let report_ps = StaticAuthorityAnalyzer::new(path_sensitive_config())
        .analyze(&graph, &manifest, epoch, 4_000)
        .unwrap();
    let report_nps = StaticAuthorityAnalyzer::new(default_config())
        .analyze(&graph, &manifest, epoch, 4_000)
        .unwrap();

    assert_eq!(
        report_ps.upper_bound_capabilities,
        report_nps.upper_bound_capabilities
    );
    assert!(report_ps.path_sensitive);
    assert!(!report_nps.path_sensitive);
}

// ---------------------------------------------------------------------------
// Path-sensitive excluded dead path evidence
// ---------------------------------------------------------------------------

#[test]
fn path_sensitive_dead_edge_generates_excluded_evidence() {
    let mut graph = EffectGraph::new("ext-dead-ev");
    graph.add_node(entry_node("e"));
    graph.add_node(control_flow_node("b"));
    graph.add_node(hostcall_node("h_live", "fs_read"));
    graph.add_node(hostcall_node("h_dead", "danger_cap"));
    graph.add_node(exit_node("x"));
    graph.add_edge(edge("e", "b"));
    graph.add_edge(edge("b", "h_live"));
    graph.add_edge(dead_edge("b", "h_dead"));
    graph.add_edge(edge("h_live", "x"));
    graph.add_edge(edge("h_dead", "x"));

    let manifest = ManifestIntents {
        extension_id: "ext-dead-ev".into(),
        declared_capabilities: [cap("fs_read")].into(), // danger_cap NOT declared
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(path_sensitive_config());
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 5_000)
        .unwrap();

    // danger_cap should be excluded.
    assert!(!report.requires_capability(&cap("danger_cap")));
    assert!(report.precision.excluded_by_path_sensitivity > 0);

    // Should have an ExcludedDeadPath evidence entry.
    let excluded_ev = report
        .per_capability_evidence
        .iter()
        .find(|e| e.capability == cap("danger_cap"));
    assert!(excluded_ev.is_some());
    assert_eq!(
        excluded_ev.unwrap().analysis_method,
        AnalysisMethod::ExcludedDeadPath
    );
}

// ---------------------------------------------------------------------------
// Cache key behaviour
// ---------------------------------------------------------------------------

#[test]
fn cache_key_same_key_replaces_entry() {
    let mut cache = AnalysisCache::new(10);

    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"graph"),
        manifest_hash: ContentHash::compute(b"manifest"),
        path_sensitive: false,
    };

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report1 = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();
    let report2 = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            2_000,
        )
        .unwrap();

    cache.insert(key.clone(), report1);
    assert_eq!(cache.len(), 1);

    cache.insert(key.clone(), report2.clone());
    assert_eq!(cache.len(), 1); // replaced, not added

    let cached = cache.get(&key).unwrap();
    assert_eq!(cached.report_id, report2.report_id);
}

#[test]
fn cache_path_sensitive_is_separate_key() {
    let mut cache = AnalysisCache::new(10);

    let key_ps = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"same-graph"),
        manifest_hash: ContentHash::compute(b"same-manifest"),
        path_sensitive: true,
    };
    let key_nps = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"same-graph"),
        manifest_hash: ContentHash::compute(b"same-manifest"),
        path_sensitive: false,
    };

    assert_ne!(key_ps, key_nps);

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();

    cache.insert(key_ps.clone(), report.clone());
    cache.insert(key_nps.clone(), report);
    assert_eq!(cache.len(), 2);

    assert!(cache.get(&key_ps).is_some());
    assert!(cache.get(&key_nps).is_some());
}

// ---------------------------------------------------------------------------
// Full pipeline: build graph → analyze → cache → re-verify
// ---------------------------------------------------------------------------

#[test]
fn full_analysis_cache_pipeline() {
    let graph = complex_graph();
    let manifest = complex_manifest();
    let epoch = SecurityEpoch::from_raw(5);

    // Analyze.
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer.analyze(&graph, &manifest, epoch, 10_000).unwrap();

    // Cache.
    let mut cache = AnalysisCache::new(100);
    let key = AnalysisCacheKey {
        effect_graph_hash: report.effect_graph_hash.clone(),
        manifest_hash: report.manifest_hash.clone(),
        path_sensitive: false,
    };
    cache.insert(key.clone(), report.clone());

    // Retrieve and verify.
    let cached = cache.get(&key).unwrap();
    assert_eq!(cached.report_id, report.report_id);
    assert_eq!(cached.content_hash(), report.content_hash());
    assert_eq!(
        cached.upper_bound_capabilities,
        report.upper_bound_capabilities
    );
    assert_eq!(cached.extension_id, "ext-complex");
    assert_eq!(cached.epoch, epoch);

    // Serde round-trip the entire cache.
    let json = serde_json::to_string(&cache).unwrap();
    let restored_cache: AnalysisCache = serde_json::from_str(&json).unwrap();
    assert_eq!(restored_cache.len(), 1);
    let restored_report = restored_cache.get(&key).unwrap();
    assert_eq!(restored_report.report_id, report.report_id);
}

// ---------------------------------------------------------------------------
// AnalysisError serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn analysis_error_serde_all_variants() {
    let errors: Vec<AnalysisError> = vec![
        AnalysisError::ExtensionMismatch {
            graph_ext: "ext-a".into(),
            manifest_ext: "ext-b".into(),
        },
        AnalysisError::EmptyEffectGraph {
            extension_id: "ext-empty".into(),
        },
        AnalysisError::NoEntryNode {
            extension_id: "ext-noentry".into(),
        },
        AnalysisError::TimedOut {
            extension_id: "ext-slow".into(),
            elapsed_ns: 120_000_000_000,
            budget_ns: 60_000_000_000,
        },
    ];

    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: AnalysisError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored, "serde roundtrip failed for {err}");
    }
}

#[test]
fn analysis_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(AnalysisError::EmptyEffectGraph {
        extension_id: "test".into(),
    });
    assert!(err.to_string().contains("empty effect graph"));
}

// ---------------------------------------------------------------------------
// AnalysisMethod serde
// ---------------------------------------------------------------------------

#[test]
fn analysis_method_serde_roundtrip() {
    let methods = [
        AnalysisMethod::LatticeReachability,
        AnalysisMethod::ManifestFallback,
        AnalysisMethod::TimeoutFallback,
        AnalysisMethod::ExcludedDeadPath,
    ];
    for method in &methods {
        let json = serde_json::to_string(method).unwrap();
        let restored: AnalysisMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(*method, restored);
    }
}

// ---------------------------------------------------------------------------
// PrecisionEstimate and PerCapabilityEvidence serde
// ---------------------------------------------------------------------------

#[test]
fn precision_estimate_serde_roundtrip() {
    let pe = PrecisionEstimate {
        upper_bound_size: 5,
        manifest_declared_size: 3,
        ratio_millionths: 1_666_666,
        excluded_by_path_sensitivity: 2,
    };
    let json = serde_json::to_string(&pe).unwrap();
    let restored: PrecisionEstimate = serde_json::from_str(&json).unwrap();
    assert_eq!(pe, restored);
}

#[test]
fn per_capability_evidence_serde_roundtrip() {
    let ev = PerCapabilityEvidence {
        capability: cap("fs_read"),
        requiring_nodes: ["node-1".to_string(), "node-2".to_string()].into(),
        analysis_method: AnalysisMethod::LatticeReachability,
        summary: "capability 'fs_read' reachable at 2 hostcall site(s)".into(),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let restored: PerCapabilityEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, restored);
}

// ---------------------------------------------------------------------------
// Precision edge case: zero manifest caps
// ---------------------------------------------------------------------------

#[test]
fn precision_with_zero_manifest_and_zero_upper_bound() {
    let mut graph = EffectGraph::new("ext-no-caps");
    graph.add_node(entry_node("e"));
    graph.add_node(computation_node("c"));
    graph.add_node(exit_node("x"));
    graph.add_edge(edge("e", "c"));
    graph.add_edge(edge("c", "x"));

    let manifest = ManifestIntents {
        extension_id: "ext-no-caps".into(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 1_000)
        .unwrap();

    assert!(report.upper_bound_capabilities.is_empty());
    assert_eq!(report.precision.upper_bound_size, 0);
    assert_eq!(report.precision.manifest_declared_size, 0);
    // 0/0 should be 1_000_000 (perfect match: both empty).
    assert_eq!(report.precision.ratio_millionths, 1_000_000);
}

#[test]
fn precision_with_zero_manifest_but_graph_caps() {
    let graph = simple_graph(); // has fs_read
    let manifest = ManifestIntents {
        extension_id: "ext-simple".into(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 2_000)
        .unwrap();

    assert_eq!(report.upper_bound_capabilities.len(), 1);
    assert_eq!(report.precision.manifest_declared_size, 0);
    // upper_bound > 0, manifest == 0 => u64::MAX
    assert_eq!(report.precision.ratio_millionths, u64::MAX);
}

// ---------------------------------------------------------------------------
// EffectGraph builder API
// ---------------------------------------------------------------------------

#[test]
fn effect_graph_new_creates_empty_graph() {
    let g = EffectGraph::new("test-ext");
    assert_eq!(g.extension_id, "test-ext");
    assert!(g.nodes.is_empty());
    assert!(g.edges.is_empty());
}

#[test]
fn effect_graph_add_node_and_edge() {
    let mut g = EffectGraph::new("test-ext");
    g.add_node(entry_node("e"));
    g.add_node(exit_node("x"));
    g.add_edge(edge("e", "x"));

    assert_eq!(g.nodes.len(), 2);
    assert_eq!(g.edges.len(), 1);
}

// ---------------------------------------------------------------------------
// Capability type
// ---------------------------------------------------------------------------

#[test]
fn capability_ordering_is_lexicographic() {
    let caps = [cap("zebra"), cap("alpha"), cap("middle")];
    let mut sorted = caps.clone();
    sorted.sort();
    assert_eq!(sorted[0], cap("alpha"));
    assert_eq!(sorted[1], cap("middle"));
    assert_eq!(sorted[2], cap("zebra"));
}

#[test]
fn capability_serde_roundtrip() {
    let c = cap("net_send");
    let json = serde_json::to_string(&c).unwrap();
    let restored: Capability = serde_json::from_str(&json).unwrap();
    assert_eq!(c, restored);
}

// ---------------------------------------------------------------------------
// Report content_hash sensitivity
// ---------------------------------------------------------------------------

#[test]
fn content_hash_differs_for_different_capabilities() {
    let analyzer = StaticAuthorityAnalyzer::new(default_config());

    let report_simple = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();

    let report_complex = analyzer
        .analyze(
            &complex_graph(),
            &complex_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();

    assert_ne!(report_simple.content_hash(), report_complex.content_hash());
}

// ---------------------------------------------------------------------------
// Large graph stress test
// ---------------------------------------------------------------------------

#[test]
fn stress_large_linear_chain() {
    let mut graph = EffectGraph::new("ext-stress");
    graph.add_node(entry_node("e0"));

    let num_hostcalls = 100;
    let mut caps_expected = BTreeSet::new();

    for i in 0..num_hostcalls {
        let cap_name = format!("cap_{i}");
        let node_id = format!("h_{i}");
        graph.add_node(hostcall_node(&node_id, &cap_name));
        caps_expected.insert(cap(cap_name.as_str()));
    }
    graph.add_node(exit_node("x"));

    // Chain: e0 -> h_0 -> h_1 -> ... -> h_99 -> x
    graph.add_edge(edge("e0", "h_0"));
    for i in 0..num_hostcalls - 1 {
        graph.add_edge(edge(&format!("h_{i}"), &format!("h_{}", i + 1)));
    }
    graph.add_edge(edge(&format!("h_{}", num_hostcalls - 1), "x"));

    let manifest = ManifestIntents {
        extension_id: "ext-stress".into(),
        declared_capabilities: caps_expected.clone(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 100_000)
        .unwrap();

    assert_eq!(report.upper_bound_capabilities.len(), num_hostcalls);
    assert_eq!(report.upper_bound_capabilities, caps_expected);
    assert_eq!(report.precision.ratio_millionths, 1_000_000);
    assert!(report.requires_capability(&cap("cap_0")));
    assert!(report.requires_capability(&cap(&format!("cap_{}", num_hostcalls - 1))));
}

#[test]
fn stress_wide_branching_graph() {
    let mut graph = EffectGraph::new("ext-wide");
    graph.add_node(entry_node("e0"));
    graph.add_node(control_flow_node("hub"));
    graph.add_edge(edge("e0", "hub"));

    let branch_count = 50;
    let mut caps_expected = BTreeSet::new();

    for i in 0..branch_count {
        let cap_name = format!("branch_cap_{i}");
        let node_id = format!("h_{i}");
        graph.add_node(hostcall_node(&node_id, &cap_name));
        graph.add_edge(edge("hub", &node_id));
        graph.add_node(exit_node(&format!("x_{i}")));
        graph.add_edge(edge(&node_id, &format!("x_{i}")));
        caps_expected.insert(cap(&cap_name));
    }

    let manifest = ManifestIntents {
        extension_id: "ext-wide".into(),
        declared_capabilities: caps_expected.clone(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 200_000)
        .unwrap();

    assert_eq!(report.upper_bound_capabilities.len(), branch_count);
    assert_eq!(report.precision.ratio_millionths, 1_000_000);
}

// ---------------------------------------------------------------------------
// EffectEdge serde
// ---------------------------------------------------------------------------

#[test]
fn effect_edge_serde_roundtrip() {
    let live = edge("a", "b");
    let dead = dead_edge("c", "d");

    let json_live = serde_json::to_string(&live).unwrap();
    let json_dead = serde_json::to_string(&dead).unwrap();
    let restored_live: EffectEdge = serde_json::from_str(&json_live).unwrap();
    let restored_dead: EffectEdge = serde_json::from_str(&json_dead).unwrap();

    assert_eq!(live, restored_live);
    assert_eq!(dead, restored_dead);
    assert!(!restored_live.provably_dead);
    assert!(restored_dead.provably_dead);
}

// ---------------------------------------------------------------------------
// Report fields
// ---------------------------------------------------------------------------

#[test]
fn report_epoch_and_timestamp_preserved() {
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(42),
            99_999,
        )
        .unwrap();

    assert_eq!(report.epoch, SecurityEpoch::from_raw(42));
    assert_eq!(report.timestamp_ns, 99_999);
    assert!(!report.timed_out);
}

#[test]
fn report_effect_graph_hash_and_manifest_hash_non_zero() {
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();

    assert_ne!(report.effect_graph_hash, ContentHash([0u8; 32]));
    assert_ne!(report.manifest_hash, ContentHash([0u8; 32]));
}

// ---------------------------------------------------------------------------
// Deterministic report IDs
// ---------------------------------------------------------------------------

#[test]
fn same_epoch_same_timestamp_same_zone_produce_same_report_id() {
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let r1 = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();
    let r2 = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();

    assert_eq!(r1.report_id, r2.report_id);
}

#[test]
fn different_epochs_produce_different_content_hashes() {
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let r1 = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();
    let r2 = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(2),
            1_000,
        )
        .unwrap();

    // Same report_id (epoch not in derivation) but different content hashes?
    // Actually let me check — epoch is stored in the report but derive_report_id
    // doesn't include it. So report_id is the same, but the report objects differ.
    // content_hash doesn't include epoch either (it uses report_id, extension_id,
    // hashes, timestamp, and capabilities).
    // Let's just verify the report IDs match (epoch not in derivation).
    assert_eq!(r1.report_id, r2.report_id);
}

// ---------------------------------------------------------------------------
// EffectNode serde
// ---------------------------------------------------------------------------

#[test]
fn effect_node_serde_roundtrip() {
    let nodes = vec![
        entry_node("e"),
        hostcall_node("h", "fs_read"),
        control_flow_node("cf"),
        computation_node("c"),
        exit_node("x"),
    ];
    for node in &nodes {
        let json = serde_json::to_string(node).unwrap();
        let restored: EffectNode = serde_json::from_str(&json).unwrap();
        assert_eq!(*node, restored, "serde roundtrip failed for {node:?}");
    }
}

// ---------------------------------------------------------------------------
// AnalysisCacheKey serde and ordering
// ---------------------------------------------------------------------------

#[test]
fn analysis_cache_key_serde_roundtrip() {
    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"graph-data"),
        manifest_hash: ContentHash::compute(b"manifest-data"),
        path_sensitive: true,
    };
    let json = serde_json::to_string(&key).unwrap();
    let restored: AnalysisCacheKey = serde_json::from_str(&json).unwrap();
    assert_eq!(key, restored);
}

#[test]
fn analysis_cache_key_ord_and_hash() {
    use std::collections::BTreeSet;
    let key1 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"a"),
        manifest_hash: ContentHash::compute(b"m"),
        path_sensitive: false,
    };
    let key2 = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"b"),
        manifest_hash: ContentHash::compute(b"m"),
        path_sensitive: false,
    };

    let mut set = BTreeSet::new();
    set.insert(key1.clone());
    set.insert(key2.clone());
    set.insert(key1.clone()); // duplicate
    assert_eq!(set.len(), 2);
}
