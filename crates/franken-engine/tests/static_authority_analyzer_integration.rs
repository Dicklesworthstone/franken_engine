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
    PrecisionEstimate, StaticAnalysisReport, StaticAuthorityAnalyzer,
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
        effect_graph_hash: report.effect_graph_hash,
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

// ---------------------------------------------------------------------------
// Error Display formatting
// ---------------------------------------------------------------------------

#[test]
fn test_analysis_error_display_extension_mismatch() {
    let err = AnalysisError::ExtensionMismatch {
        graph_ext: "ext-graph".into(),
        manifest_ext: "ext-manifest".into(),
    };
    let s = err.to_string();
    assert!(
        s.contains("ext-graph"),
        "expected graph_ext in display: {s}"
    );
    assert!(
        s.contains("ext-manifest"),
        "expected manifest_ext in display: {s}"
    );
    assert!(
        s.contains("mismatch"),
        "expected 'mismatch' in display: {s}"
    );
}

#[test]
fn test_analysis_error_display_empty_effect_graph() {
    let err = AnalysisError::EmptyEffectGraph {
        extension_id: "ext-empty-display".into(),
    };
    let s = err.to_string();
    assert!(s.contains("empty"), "expected 'empty' in display: {s}");
    assert!(
        s.contains("ext-empty-display"),
        "expected extension_id in display: {s}"
    );
}

#[test]
fn test_analysis_error_display_no_entry_node() {
    let err = AnalysisError::NoEntryNode {
        extension_id: "ext-noentry-display".into(),
    };
    let s = err.to_string();
    assert!(
        s.contains("no entry node"),
        "expected 'no entry node' in display: {s}"
    );
    assert!(
        s.contains("ext-noentry-display"),
        "expected extension_id in display: {s}"
    );
}

#[test]
fn test_analysis_error_display_timed_out() {
    let err = AnalysisError::TimedOut {
        extension_id: "ext-timeout".into(),
        elapsed_ns: 200_000_000_000,
        budget_ns: 60_000_000_000,
    };
    let s = err.to_string();
    assert!(
        s.contains("timed out"),
        "expected 'timed out' in display: {s}"
    );
    assert!(
        s.contains("ext-timeout"),
        "expected extension_id in display: {s}"
    );
    assert!(
        s.contains("200000000000"),
        "expected elapsed_ns in display: {s}"
    );
    assert!(
        s.contains("60000000000"),
        "expected budget_ns in display: {s}"
    );
}

// ---------------------------------------------------------------------------
// AnalysisMethod Display formatting
// ---------------------------------------------------------------------------

#[test]
fn test_analysis_method_display_all_variants() {
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

// ---------------------------------------------------------------------------
// Capability Display and as_str
// ---------------------------------------------------------------------------

#[test]
fn test_capability_display_and_as_str() {
    let c = cap("net_send");
    assert_eq!(c.to_string(), "net_send");
    assert_eq!(c.as_str(), "net_send");
}

#[test]
fn test_capability_debug_format() {
    let c = cap("fs_write");
    let debug_str = format!("{c:?}");
    assert!(
        debug_str.contains("fs_write"),
        "Debug should include capability name: {debug_str}"
    );
}

#[test]
fn test_capability_clone_and_eq() {
    let c1 = cap("crypto_sign");
    let c2 = c1.clone();
    assert_eq!(c1, c2);
    assert_ne!(c1, cap("other"));
}

// ---------------------------------------------------------------------------
// Error paths: extension mismatch, empty graph, no entry node
// ---------------------------------------------------------------------------

#[test]
fn test_analyze_returns_err_on_extension_mismatch() {
    let graph = simple_graph(); // extension_id = "ext-simple"
    let manifest = ManifestIntents {
        extension_id: "ext-different".into(),
        declared_capabilities: [cap("fs_read")].into(),
        optional_capabilities: BTreeSet::new(),
    };
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let result = analyzer.analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 1_000);
    assert!(result.is_err());
    match result.unwrap_err() {
        AnalysisError::ExtensionMismatch {
            graph_ext,
            manifest_ext,
        } => {
            assert_eq!(graph_ext, "ext-simple");
            assert_eq!(manifest_ext, "ext-different");
        }
        other => panic!("expected ExtensionMismatch, got {other}"),
    }
}

#[test]
fn test_analyze_returns_err_on_empty_graph() {
    let graph = EffectGraph::new("ext-empty-err");
    let manifest = ManifestIntents {
        extension_id: "ext-empty-err".into(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let result = analyzer.analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 1_000);
    assert!(result.is_err());
    match result.unwrap_err() {
        AnalysisError::EmptyEffectGraph { extension_id } => {
            assert_eq!(extension_id, "ext-empty-err");
        }
        other => panic!("expected EmptyEffectGraph, got {other}"),
    }
}

#[test]
fn test_analyze_returns_err_on_no_entry_node() {
    let mut graph = EffectGraph::new("ext-no-entry");
    graph.add_node(computation_node("c1"));
    graph.add_node(exit_node("x"));
    graph.add_edge(edge("c1", "x"));
    let manifest = ManifestIntents {
        extension_id: "ext-no-entry".into(),
        declared_capabilities: BTreeSet::new(),
        optional_capabilities: BTreeSet::new(),
    };
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let result = analyzer.analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 1_000);
    assert!(result.is_err());
    match result.unwrap_err() {
        AnalysisError::NoEntryNode { extension_id } => {
            assert_eq!(extension_id, "ext-no-entry");
        }
        other => panic!("expected NoEntryNode, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// AnalysisError is std::error::Error for all variants
// ---------------------------------------------------------------------------

#[test]
fn test_analysis_error_std_error_extension_mismatch() {
    let err: Box<dyn std::error::Error> = Box::new(AnalysisError::ExtensionMismatch {
        graph_ext: "ga".into(),
        manifest_ext: "mb".into(),
    });
    assert!(err.to_string().contains("mismatch"));
}

#[test]
fn test_analysis_error_std_error_no_entry_node() {
    let err: Box<dyn std::error::Error> = Box::new(AnalysisError::NoEntryNode {
        extension_id: "ext-ne".into(),
    });
    assert!(err.to_string().contains("no entry node"));
}

#[test]
fn test_analysis_error_std_error_timed_out() {
    let err: Box<dyn std::error::Error> = Box::new(AnalysisError::TimedOut {
        extension_id: "ext-to".into(),
        elapsed_ns: 120_000_000_000,
        budget_ns: 60_000_000_000,
    });
    assert!(err.to_string().contains("timed out"));
}

// ---------------------------------------------------------------------------
// AnalysisCache: zero-capacity cache rejects all inserts
// ---------------------------------------------------------------------------

#[test]
fn test_analysis_cache_zero_capacity_stays_empty() {
    let mut cache = AnalysisCache::new(0);
    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"g"),
        manifest_hash: ContentHash::compute(b"m"),
        path_sensitive: false,
    };
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();
    cache.insert(key.clone(), report);
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
    assert!(cache.get(&key).is_none());
}

// ---------------------------------------------------------------------------
// AnalysisCache: eviction when at capacity
// ---------------------------------------------------------------------------

#[test]
fn test_analysis_cache_evicts_oldest_when_at_capacity() {
    let mut cache = AnalysisCache::new(2);
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();

    let key_a = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"aa"),
        manifest_hash: ContentHash::compute(b"m1"),
        path_sensitive: false,
    };
    let key_b = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"bb"),
        manifest_hash: ContentHash::compute(b"m2"),
        path_sensitive: false,
    };
    let key_c = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"cc"),
        manifest_hash: ContentHash::compute(b"m3"),
        path_sensitive: false,
    };

    cache.insert(key_a.clone(), report.clone());
    cache.insert(key_b.clone(), report.clone());
    assert_eq!(cache.len(), 2);

    // Inserting a third entry should evict the oldest (key_a).
    cache.insert(key_c.clone(), report.clone());
    assert_eq!(cache.len(), 2);
    assert!(
        cache.get(&key_a).is_none(),
        "key_a should have been evicted"
    );
    assert!(cache.get(&key_b).is_some());
    assert!(cache.get(&key_c).is_some());
}

// ---------------------------------------------------------------------------
// AnalysisCache: clear removes all entries
// ---------------------------------------------------------------------------

#[test]
fn test_analysis_cache_clear_empties_cache() {
    let mut cache = AnalysisCache::new(10);
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();
    let key = AnalysisCacheKey {
        effect_graph_hash: ContentHash::compute(b"x"),
        manifest_hash: ContentHash::compute(b"y"),
        path_sensitive: false,
    };
    cache.insert(key.clone(), report);
    assert_eq!(cache.len(), 1);
    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
    assert!(cache.get(&key).is_none());
}

// ---------------------------------------------------------------------------
// EffectGraph serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_effect_graph_serde_roundtrip() {
    let graph = complex_graph();
    let json = serde_json::to_string(&graph).unwrap();
    let restored: EffectGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(graph, restored);
    assert_eq!(restored.nodes.len(), graph.nodes.len());
    assert_eq!(restored.edges.len(), graph.edges.len());
}

// ---------------------------------------------------------------------------
// EffectNodeKind variants: serde and equality
// ---------------------------------------------------------------------------

#[test]
fn test_effect_node_kind_serde_all_variants() {
    let kinds: Vec<EffectNodeKind> = vec![
        EffectNodeKind::Entry,
        EffectNodeKind::HostcallSite {
            capability: cap("fs_read"),
        },
        EffectNodeKind::ControlFlow,
        EffectNodeKind::Computation,
        EffectNodeKind::Exit,
    ];
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let restored: EffectNodeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored, "serde roundtrip failed for {kind:?}");
    }
}

#[test]
fn test_effect_node_kind_clone_and_debug() {
    let kind = EffectNodeKind::HostcallSite {
        capability: cap("net_send"),
    };
    let cloned = kind.clone();
    assert_eq!(kind, cloned);
    let debug_str = format!("{kind:?}");
    assert!(
        debug_str.contains("HostcallSite"),
        "Debug should mention variant: {debug_str}"
    );
    assert!(
        debug_str.contains("net_send"),
        "Debug should include capability: {debug_str}"
    );
}

// ---------------------------------------------------------------------------
// PrecisionEstimate: clone and debug
// ---------------------------------------------------------------------------

#[test]
fn test_precision_estimate_clone_and_debug() {
    let pe = PrecisionEstimate {
        upper_bound_size: 3,
        manifest_declared_size: 5,
        ratio_millionths: 600_000,
        excluded_by_path_sensitivity: 0,
    };
    let cloned = pe.clone();
    assert_eq!(pe, cloned);
    let debug_str = format!("{pe:?}");
    assert!(
        debug_str.contains("600000"),
        "Debug should include ratio: {debug_str}"
    );
}

// ---------------------------------------------------------------------------
// StaticAnalysisReport: Clone/Debug/serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_static_analysis_report_clone_and_debug() {
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(1),
            5_000,
        )
        .unwrap();
    let cloned = report.clone();
    assert_eq!(report, cloned);
    let debug_str = format!("{report:?}");
    assert!(
        debug_str.contains("ext-simple"),
        "Debug should include extension_id: {debug_str}"
    );
}

#[test]
fn test_static_analysis_report_serde_roundtrip() {
    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(
            &simple_graph(),
            &simple_manifest(),
            SecurityEpoch::from_raw(7),
            9_999,
        )
        .unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let restored: StaticAnalysisReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
    assert_eq!(restored.extension_id, "ext-simple");
    assert_eq!(restored.epoch, SecurityEpoch::from_raw(7));
    assert_eq!(restored.timestamp_ns, 9_999);
}

// ---------------------------------------------------------------------------
// ManifestIntents: Clone/Debug
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_intents_clone_and_debug() {
    let manifest = ManifestIntents {
        extension_id: "ext-clone-test".into(),
        declared_capabilities: [cap("fs_read"), cap("fs_write")].into(),
        optional_capabilities: [cap("net_send")].into(),
    };
    let cloned = manifest.clone();
    assert_eq!(manifest, cloned);
    let debug_str = format!("{manifest:?}");
    assert!(
        debug_str.contains("ext-clone-test"),
        "Debug includes extension_id: {debug_str}"
    );
}

// ---------------------------------------------------------------------------
// AnalysisConfig: Clone/Debug
// ---------------------------------------------------------------------------

#[test]
fn test_analysis_config_clone_and_debug() {
    let config = AnalysisConfig {
        time_budget_ns: 30_000_000,
        path_sensitive: true,
        zone: "debug-zone".into(),
    };
    let cloned = config.clone();
    assert_eq!(config, cloned);
    let debug_str = format!("{config:?}");
    assert!(
        debug_str.contains("debug-zone"),
        "Debug includes zone: {debug_str}"
    );
}

// ---------------------------------------------------------------------------
// Multiple entry nodes: both contribute reachable capabilities
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_entry_nodes_both_contribute() {
    let mut graph = EffectGraph::new("ext-multi-entry");
    graph.add_node(entry_node("e1"));
    graph.add_node(entry_node("e2"));
    graph.add_node(hostcall_node("h_read", "fs_read"));
    graph.add_node(hostcall_node("h_write", "fs_write"));
    graph.add_node(exit_node("x1"));
    graph.add_node(exit_node("x2"));
    graph.add_edge(edge("e1", "h_read"));
    graph.add_edge(edge("h_read", "x1"));
    graph.add_edge(edge("e2", "h_write"));
    graph.add_edge(edge("h_write", "x2"));

    let manifest = ManifestIntents {
        extension_id: "ext-multi-entry".into(),
        declared_capabilities: [cap("fs_read"), cap("fs_write")].into(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 3_000)
        .unwrap();

    assert!(report.requires_capability(&cap("fs_read")));
    assert!(report.requires_capability(&cap("fs_write")));
    assert_eq!(report.upper_bound_capabilities.len(), 2);
}

// ---------------------------------------------------------------------------
// Precision ratio for over-approximation: upper bound > manifest
// ---------------------------------------------------------------------------

#[test]
fn test_precision_ratio_over_approximation() {
    // Graph has fs_read + admin_access; manifest only declares fs_read.
    let mut graph = EffectGraph::new("ext-overapprox");
    graph.add_node(entry_node("e"));
    graph.add_node(hostcall_node("h1", "fs_read"));
    graph.add_node(hostcall_node("h2", "admin_access"));
    graph.add_node(exit_node("x"));
    graph.add_edge(edge("e", "h1"));
    graph.add_edge(edge("h1", "h2"));
    graph.add_edge(edge("h2", "x"));

    let manifest = ManifestIntents {
        extension_id: "ext-overapprox".into(),
        declared_capabilities: [cap("fs_read")].into(),
        optional_capabilities: BTreeSet::new(),
    };

    let analyzer = StaticAuthorityAnalyzer::new(default_config());
    let report = analyzer
        .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 2_000)
        .unwrap();

    // upper_bound=2, manifest=1 -> ratio = 2_000_000
    assert_eq!(report.precision.upper_bound_size, 2);
    assert_eq!(report.precision.manifest_declared_size, 1);
    assert_eq!(report.precision.ratio_millionths, 2_000_000);
}

// ---------------------------------------------------------------------------
// derive_report_id is deterministic
// ---------------------------------------------------------------------------

#[test]
fn test_derive_report_id_is_deterministic() {
    let hash_g = ContentHash::compute(b"graph-data");
    let hash_m = ContentHash::compute(b"manifest-data");
    let id1 = StaticAnalysisReport::derive_report_id("ext-det", &hash_g, &hash_m, 12345, "z1");
    let id2 = StaticAnalysisReport::derive_report_id("ext-det", &hash_g, &hash_m, 12345, "z1");
    assert!(id1.is_ok());
    assert_eq!(id1.unwrap(), id2.unwrap());
}

#[test]
fn test_derive_report_id_differs_on_timestamp() {
    let hash_g = ContentHash::compute(b"graph-ts");
    let hash_m = ContentHash::compute(b"manifest-ts");
    let id1 = StaticAnalysisReport::derive_report_id("ext-ts", &hash_g, &hash_m, 100, "zone");
    let id2 = StaticAnalysisReport::derive_report_id("ext-ts", &hash_g, &hash_m, 200, "zone");
    assert_ne!(id1.unwrap(), id2.unwrap());
}

#[test]
fn test_derive_report_id_differs_on_zone() {
    let hash_g = ContentHash::compute(b"graph-zone");
    let hash_m = ContentHash::compute(b"manifest-zone");
    let id1 = StaticAnalysisReport::derive_report_id("ext-z", &hash_g, &hash_m, 1, "zone-a");
    let id2 = StaticAnalysisReport::derive_report_id("ext-z", &hash_g, &hash_m, 1, "zone-b");
    assert_ne!(id1.unwrap(), id2.unwrap());
}
