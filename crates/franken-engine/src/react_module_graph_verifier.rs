//! React module-graph verifier with deterministic receipts.
//!
//! Builds on [`react_package_cohort`] to model SSR and client-entry React
//! module graphs, detect cycles, orphans, and format mismatches, and
//! produce deterministic verification receipts and surface-coverage
//! reports.
//!
//! Plan references: Section 5.7 (RGC-405B), bead bd-1lsy.5.7.2.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::react_package_cohort::{ExportCondition, ModuleFormat, ReactPackage};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

/// Schema version for the react module graph verifier.
pub const REACT_MODULE_GRAPH_SCHEMA_VERSION: &str = "franken-engine.react-module-graph-verifier.v1";

/// Bead identifier originating this module.
pub const REACT_MODULE_GRAPH_BEAD_ID: &str = "bd-1lsy.5.7.2";

/// Policy ID binding.
pub const REACT_MODULE_GRAPH_POLICY_ID: &str = "RGC-405B";

/// Component name for evidence linkage.
pub const COMPONENT: &str = "react_module_graph_verifier";

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// RenderSurface
// ---------------------------------------------------------------------------

/// The React rendering surface targeted by a module graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenderSurface {
    /// Server-side rendering (full HTML generation).
    ServerSideRender,
    /// Client entry-point (browser hydration root).
    ClientEntry,
    /// Hydration bridge (selective hydration boundary).
    HydrationBridge,
    /// Static site generation (build-time rendering).
    StaticGeneration,
    /// Streaming SSR (chunked transfer encoding).
    StreamingSSR,
}

/// All render-surface variants for exhaustive iteration.
pub const ALL_SURFACES: &[RenderSurface] = &[
    RenderSurface::ServerSideRender,
    RenderSurface::ClientEntry,
    RenderSurface::HydrationBridge,
    RenderSurface::StaticGeneration,
    RenderSurface::StreamingSSR,
];

impl RenderSurface {
    /// Short identifier for hash derivation and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerSideRender => "server_side_render",
            Self::ClientEntry => "client_entry",
            Self::HydrationBridge => "hydration_bridge",
            Self::StaticGeneration => "static_generation",
            Self::StreamingSSR => "streaming_ssr",
        }
    }
}

impl fmt::Display for RenderSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ModuleRole
// ---------------------------------------------------------------------------

/// The role of a module node within a React module graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleRole {
    /// The top-level entry-point module.
    EntryPoint,
    /// Provides the React runtime (createElement, hooks, etc.).
    RuntimeProvider,
    /// Binds to a specific renderer (DOM, server, native).
    RendererBinding,
    /// Hooks into the scheduler for concurrent features.
    SchedulerHook,
    /// Internal shared module (e.g. reconciler internals).
    InternalShared,
    /// Module targets an unsupported surface.
    UnsupportedSurface,
}

impl ModuleRole {
    /// Short identifier for hash derivation and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntryPoint => "entry_point",
            Self::RuntimeProvider => "runtime_provider",
            Self::RendererBinding => "renderer_binding",
            Self::SchedulerHook => "scheduler_hook",
            Self::InternalShared => "internal_shared",
            Self::UnsupportedSurface => "unsupported_surface",
        }
    }
}

impl fmt::Display for ModuleRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GraphNodeId
// ---------------------------------------------------------------------------

/// Opaque, deterministic identifier for a node in the module graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GraphNodeId(pub String);

impl GraphNodeId {
    /// Create a new node id.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GraphNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// ModuleGraphNode
// ---------------------------------------------------------------------------

/// A single node in a React module graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleGraphNode {
    /// Unique node identifier within the graph.
    pub node_id: GraphNodeId,
    /// The React package this node belongs to.
    pub package: ReactPackage,
    /// Subpath within the package (e.g. `"."`, `"./server"`).
    pub subpath: String,
    /// The export condition used to resolve this node.
    pub condition: ExportCondition,
    /// The module format of the resolved file.
    pub format: ModuleFormat,
    /// The role this node plays in the graph.
    pub role: ModuleRole,
    /// The rendering surface this node targets.
    pub surface: RenderSurface,
    /// Content hash over the deterministic representation.
    pub content_hash: ContentHash,
}

impl ModuleGraphNode {
    /// Compute a deterministic content hash over all fields.
    pub fn compute_content_hash(
        node_id: &str,
        package: ReactPackage,
        subpath: &str,
        condition: ExportCondition,
        format: ModuleFormat,
        role: ModuleRole,
        surface: RenderSurface,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"ModuleGraphNode:");
        hasher.update(node_id.as_bytes());
        hasher.update(b":");
        hasher.update(package.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(subpath.as_bytes());
        hasher.update(b":");
        hasher.update(condition.condition_key().as_bytes());
        hasher.update(b":");
        hasher.update(format.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(role.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(surface.as_str().as_bytes());
        let result: [u8; 32] = hasher.finalize().into();
        ContentHash(result)
    }
}

impl fmt::Display for ModuleGraphNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GraphNode({}, {}, {}, {})",
            self.node_id, self.package, self.role, self.surface
        )
    }
}

// ---------------------------------------------------------------------------
// ModuleGraphEdge
// ---------------------------------------------------------------------------

/// A directed edge in a React module graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleGraphEdge {
    /// Source node.
    pub from_node: GraphNodeId,
    /// Target node.
    pub to_node: GraphNodeId,
    /// The kind of edge: `"imports"`, `"re-exports"`, or `"side-effect"`.
    pub edge_kind: String,
    /// Content hash over the deterministic representation.
    pub content_hash: ContentHash,
}

impl ModuleGraphEdge {
    /// Compute a deterministic content hash for an edge.
    pub fn compute_content_hash(from: &str, to: &str, kind: &str) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"ModuleGraphEdge:");
        hasher.update(from.as_bytes());
        hasher.update(b"->");
        hasher.update(to.as_bytes());
        hasher.update(b":");
        hasher.update(kind.as_bytes());
        let result: [u8; 32] = hasher.finalize().into();
        ContentHash(result)
    }
}

impl fmt::Display for ModuleGraphEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Edge({} -[{}]-> {})",
            self.from_node, self.edge_kind, self.to_node
        )
    }
}

// ---------------------------------------------------------------------------
// ModuleGraph
// ---------------------------------------------------------------------------

/// A directed graph of React module nodes and edges for a given rendering surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleGraph {
    /// Unique graph identifier.
    pub graph_id: String,
    /// The rendering surface this graph targets.
    pub surface: RenderSurface,
    /// All nodes in the graph.
    pub nodes: Vec<ModuleGraphNode>,
    /// All edges in the graph.
    pub edges: Vec<ModuleGraphEdge>,
    /// The security epoch under which this graph was built.
    pub epoch: SecurityEpoch,
    /// Content hash over the entire graph.
    pub content_hash: ContentHash,
}

impl ModuleGraph {
    /// Compute a deterministic content hash over the entire graph.
    pub fn compute_content_hash(
        graph_id: &str,
        surface: RenderSurface,
        nodes: &[ModuleGraphNode],
        edges: &[ModuleGraphEdge],
        epoch: SecurityEpoch,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"ModuleGraph:");
        hasher.update(graph_id.as_bytes());
        hasher.update(b":");
        hasher.update(surface.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(epoch.as_u64().to_le_bytes());
        for node in nodes {
            hasher.update(node.content_hash.as_bytes());
        }
        for edge in edges {
            hasher.update(edge.content_hash.as_bytes());
        }
        let result: [u8; 32] = hasher.finalize().into();
        ContentHash(result)
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

impl fmt::Display for ModuleGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ModuleGraph({}, {}, {} nodes, {} edges)",
            self.graph_id,
            self.surface,
            self.nodes.len(),
            self.edges.len()
        )
    }
}

// ---------------------------------------------------------------------------
// GraphVerificationVerdict
// ---------------------------------------------------------------------------

/// Outcome of verifying a React module graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphVerificationVerdict {
    /// The graph passed all verification checks.
    Valid,
    /// The graph targets a surface that is missing required nodes.
    MissingSurface,
    /// The graph contains one or more dependency cycles.
    CyclicDependency,
    /// Two connected nodes have incompatible module formats.
    FormatMismatch,
    /// The graph targets an unsupported rendering surface.
    UnsupportedSurface,
    /// The graph contains orphan nodes (no edges).
    OrphanNode,
}

impl GraphVerificationVerdict {
    /// Short identifier for hash derivation and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::MissingSurface => "missing_surface",
            Self::CyclicDependency => "cyclic_dependency",
            Self::FormatMismatch => "format_mismatch",
            Self::UnsupportedSurface => "unsupported_surface",
            Self::OrphanNode => "orphan_node",
        }
    }
}

impl fmt::Display for GraphVerificationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GraphVerificationReceipt
// ---------------------------------------------------------------------------

/// Deterministic receipt from verifying a React module graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphVerificationReceipt {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// The graph that was verified.
    pub graph_id: String,
    /// The surface the graph targets.
    pub surface: RenderSurface,
    /// The verification verdict.
    pub verdict: GraphVerificationVerdict,
    /// Number of nodes in the graph.
    pub node_count: u64,
    /// Number of edges in the graph.
    pub edge_count: u64,
    /// Diagnostic messages collected during verification.
    pub diagnostics: Vec<String>,
    /// Content hash over the receipt.
    pub content_hash: ContentHash,
}

impl GraphVerificationReceipt {
    /// Compute a deterministic content hash over the receipt.
    pub fn compute_content_hash(
        receipt_id: &str,
        graph_id: &str,
        surface: RenderSurface,
        verdict: GraphVerificationVerdict,
        node_count: u64,
        edge_count: u64,
        diagnostics: &[String],
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"GraphVerificationReceipt:");
        hasher.update(receipt_id.as_bytes());
        hasher.update(b":");
        hasher.update(graph_id.as_bytes());
        hasher.update(b":");
        hasher.update(surface.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(verdict.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(node_count.to_le_bytes());
        hasher.update(b":");
        hasher.update(edge_count.to_le_bytes());
        for diag in diagnostics {
            hasher.update(b"|");
            hasher.update(diag.as_bytes());
        }
        let result: [u8; 32] = hasher.finalize().into();
        ContentHash(result)
    }
}

impl fmt::Display for GraphVerificationReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Receipt({}, {}, {})",
            self.receipt_id, self.surface, self.verdict
        )
    }
}

// ---------------------------------------------------------------------------
// SurfaceCoverageReport
// ---------------------------------------------------------------------------

/// Aggregated surface-coverage report across multiple verified graphs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceCoverageReport {
    /// Unique report identifier.
    pub report_id: String,
    /// The security epoch under which this report was built.
    pub epoch: SecurityEpoch,
    /// All verification receipts included in the report.
    pub receipts: Vec<GraphVerificationReceipt>,
    /// The rendering surfaces covered by the receipts.
    pub surfaces_covered: Vec<RenderSurface>,
    /// Fixed-point coverage ratio in millionths.
    pub coverage_millionths: u64,
    /// Total node count across all verified graphs.
    pub total_nodes: u64,
    /// Total edge count across all verified graphs.
    pub total_edges: u64,
    /// Content hash over the report.
    pub content_hash: ContentHash,
}

impl SurfaceCoverageReport {
    /// Compute a deterministic content hash over the report.
    pub fn compute_content_hash(
        report_id: &str,
        epoch: SecurityEpoch,
        receipts: &[GraphVerificationReceipt],
        surfaces_covered: &[RenderSurface],
        coverage_millionths: u64,
        total_nodes: u64,
        total_edges: u64,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"SurfaceCoverageReport:");
        hasher.update(report_id.as_bytes());
        hasher.update(b":");
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(b":");
        hasher.update(coverage_millionths.to_le_bytes());
        hasher.update(b":");
        hasher.update(total_nodes.to_le_bytes());
        hasher.update(b":");
        hasher.update(total_edges.to_le_bytes());
        for receipt in receipts {
            hasher.update(receipt.content_hash.as_bytes());
        }
        for surface in surfaces_covered {
            hasher.update(surface.as_str().as_bytes());
        }
        let result: [u8; 32] = hasher.finalize().into();
        ContentHash(result)
    }
}

impl fmt::Display for SurfaceCoverageReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SurfaceCoverageReport({}, {} surfaces, coverage={})",
            self.report_id,
            self.surfaces_covered.len(),
            self.coverage_millionths
        )
    }
}

// ---------------------------------------------------------------------------
// Builder functions
// ---------------------------------------------------------------------------

/// Build a module graph node with computed content hash.
pub fn build_module_node(
    id: &str,
    package: ReactPackage,
    subpath: &str,
    condition: ExportCondition,
    format: ModuleFormat,
    role: ModuleRole,
    surface: RenderSurface,
) -> ModuleGraphNode {
    let content_hash = ModuleGraphNode::compute_content_hash(
        id, package, subpath, condition, format, role, surface,
    );
    ModuleGraphNode {
        node_id: GraphNodeId::new(id),
        package,
        subpath: subpath.to_owned(),
        condition,
        format,
        role,
        surface,
        content_hash,
    }
}

/// Build a module graph edge with computed content hash.
pub fn build_module_edge(from: &str, to: &str, kind: &str) -> ModuleGraphEdge {
    let content_hash = ModuleGraphEdge::compute_content_hash(from, to, kind);
    ModuleGraphEdge {
        from_node: GraphNodeId::new(from),
        to_node: GraphNodeId::new(to),
        edge_kind: kind.to_owned(),
        content_hash,
    }
}

/// Build a module graph with computed content hash.
pub fn build_module_graph(
    graph_id: &str,
    surface: RenderSurface,
    nodes: Vec<ModuleGraphNode>,
    edges: Vec<ModuleGraphEdge>,
    epoch: SecurityEpoch,
) -> ModuleGraph {
    let content_hash = ModuleGraph::compute_content_hash(graph_id, surface, &nodes, &edges, epoch);
    ModuleGraph {
        graph_id: graph_id.to_owned(),
        surface,
        nodes,
        edges,
        epoch,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Cycle detection (DFS-based)
// ---------------------------------------------------------------------------

/// Detect all cycles in the module graph using DFS.
pub fn detect_cycles(graph: &ModuleGraph) -> Vec<Vec<GraphNodeId>> {
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in &graph.nodes {
        adj.entry(node.node_id.as_str()).or_default();
    }
    for edge in &graph.edges {
        adj.entry(edge.from_node.as_str())
            .or_default()
            .push(edge.to_node.as_str());
    }

    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut on_stack: BTreeSet<&str> = BTreeSet::new();
    let mut stack: Vec<&str> = Vec::new();
    let mut cycles: Vec<Vec<GraphNodeId>> = Vec::new();

    fn dfs<'a>(
        node: &'a str,
        adj: &BTreeMap<&'a str, Vec<&'a str>>,
        visited: &mut BTreeSet<&'a str>,
        on_stack: &mut BTreeSet<&'a str>,
        stack: &mut Vec<&'a str>,
        cycles: &mut Vec<Vec<GraphNodeId>>,
    ) {
        visited.insert(node);
        on_stack.insert(node);
        stack.push(node);
        if let Some(neighbors) = adj.get(node) {
            for &neighbor in neighbors {
                if !visited.contains(neighbor) {
                    dfs(neighbor, adj, visited, on_stack, stack, cycles);
                } else if on_stack.contains(neighbor) {
                    let mut cycle = Vec::new();
                    let mut found = false;
                    for &s in stack.iter() {
                        if s == neighbor {
                            found = true;
                        }
                        if found {
                            cycle.push(GraphNodeId::new(s));
                        }
                    }
                    cycle.push(GraphNodeId::new(neighbor));
                    cycles.push(cycle);
                }
            }
        }
        stack.pop();
        on_stack.remove(node);
    }

    let node_ids: Vec<&str> = adj.keys().copied().collect();
    for node_id in node_ids {
        if !visited.contains(node_id) {
            dfs(
                node_id,
                &adj,
                &mut visited,
                &mut on_stack,
                &mut stack,
                &mut cycles,
            );
        }
    }
    cycles
}

// ---------------------------------------------------------------------------
// Orphan detection
// ---------------------------------------------------------------------------

/// Detect orphan nodes: nodes with no incoming and no outgoing edges.
pub fn detect_orphans(graph: &ModuleGraph) -> Vec<GraphNodeId> {
    let mut connected: BTreeSet<&str> = BTreeSet::new();
    for edge in &graph.edges {
        connected.insert(edge.from_node.as_str());
        connected.insert(edge.to_node.as_str());
    }
    graph
        .nodes
        .iter()
        .filter(|n| !connected.contains(n.node_id.as_str()))
        .map(|n| n.node_id.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Format-mismatch detection
// ---------------------------------------------------------------------------

/// Detect edges where CJS imports ESM (incompatible).
pub fn detect_format_mismatches(graph: &ModuleGraph) -> Vec<(GraphNodeId, GraphNodeId)> {
    let node_map: BTreeMap<&str, &ModuleGraphNode> = graph
        .nodes
        .iter()
        .map(|n| (n.node_id.as_str(), n))
        .collect();
    let mut mismatches = Vec::new();
    for edge in &graph.edges {
        if let Some(from_node) = node_map.get(edge.from_node.as_str()) {
            if let Some(to_node) = node_map.get(edge.to_node.as_str()) {
                if from_node.format == ModuleFormat::Cjs && to_node.format == ModuleFormat::Esm {
                    mismatches.push((edge.from_node.clone(), edge.to_node.clone()));
                }
            }
        }
    }
    mismatches
}

// ---------------------------------------------------------------------------
// Graph verification
// ---------------------------------------------------------------------------

/// Verify a React module graph, producing a deterministic receipt.
pub fn verify_module_graph(graph: &ModuleGraph) -> GraphVerificationReceipt {
    let mut diagnostics: Vec<String> = Vec::new();
    let mut verdict = GraphVerificationVerdict::Valid;

    // 1. Unsupported surface roles.
    let unsupported: Vec<&ModuleGraphNode> = graph
        .nodes
        .iter()
        .filter(|n| n.role == ModuleRole::UnsupportedSurface)
        .collect();
    if !unsupported.is_empty() {
        verdict = GraphVerificationVerdict::UnsupportedSurface;
        for node in &unsupported {
            diagnostics.push(format!(
                "node {} has unsupported surface role",
                node.node_id
            ));
        }
    }

    // 2. Cycles.
    if verdict == GraphVerificationVerdict::Valid {
        let cycles = detect_cycles(graph);
        if !cycles.is_empty() {
            verdict = GraphVerificationVerdict::CyclicDependency;
            for cycle in &cycles {
                let ids: Vec<&str> = cycle.iter().map(|id| id.as_str()).collect();
                diagnostics.push(format!("cycle detected: {}", ids.join(" -> ")));
            }
        }
    }

    // 3. Format mismatches.
    if verdict == GraphVerificationVerdict::Valid {
        let mismatches = detect_format_mismatches(graph);
        if !mismatches.is_empty() {
            verdict = GraphVerificationVerdict::FormatMismatch;
            for (from, to) in &mismatches {
                diagnostics.push(format!("format mismatch: {} -> {}", from, to));
            }
        }
    }

    // 4. Orphans.
    if verdict == GraphVerificationVerdict::Valid {
        let orphans = detect_orphans(graph);
        if !orphans.is_empty() {
            verdict = GraphVerificationVerdict::OrphanNode;
            for orphan in &orphans {
                diagnostics.push(format!("orphan node: {}", orphan));
            }
        }
    }

    // 5. Missing entry point.
    if verdict == GraphVerificationVerdict::Valid {
        let has_entry = graph
            .nodes
            .iter()
            .any(|n| n.role == ModuleRole::EntryPoint && n.surface == graph.surface);
        if !has_entry {
            verdict = GraphVerificationVerdict::MissingSurface;
            diagnostics.push(format!("no entry-point node for surface {}", graph.surface));
        }
    }

    let receipt_id = format!("receipt-{}-{}", graph.graph_id, graph.surface.as_str());
    let node_count = graph.nodes.len() as u64;
    let edge_count = graph.edges.len() as u64;
    let content_hash = GraphVerificationReceipt::compute_content_hash(
        &receipt_id,
        &graph.graph_id,
        graph.surface,
        verdict,
        node_count,
        edge_count,
        &diagnostics,
    );

    GraphVerificationReceipt {
        receipt_id,
        graph_id: graph.graph_id.clone(),
        surface: graph.surface,
        verdict,
        node_count,
        edge_count,
        diagnostics,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Canonical graph builders
// ---------------------------------------------------------------------------

/// Build the canonical SSR module graph.
pub fn build_ssr_graph(epoch: SecurityEpoch) -> ModuleGraph {
    let surface = RenderSurface::ServerSideRender;
    let nodes = vec![
        build_module_node(
            "ssr-entry",
            ReactPackage::ReactDomServer,
            "./server",
            ExportCondition::Node,
            ModuleFormat::Esm,
            ModuleRole::EntryPoint,
            surface,
        ),
        build_module_node(
            "ssr-react",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::RuntimeProvider,
            surface,
        ),
        build_module_node(
            "ssr-jsx-runtime",
            ReactPackage::ReactJsxRuntime,
            "./jsx-runtime",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::InternalShared,
            surface,
        ),
        build_module_node(
            "ssr-scheduler",
            ReactPackage::Scheduler,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::SchedulerHook,
            surface,
        ),
    ];
    let edges = vec![
        build_module_edge("ssr-entry", "ssr-react", "imports"),
        build_module_edge("ssr-entry", "ssr-jsx-runtime", "imports"),
        build_module_edge("ssr-react", "ssr-scheduler", "imports"),
        build_module_edge("ssr-jsx-runtime", "ssr-react", "imports"),
    ];
    build_module_graph("ssr-graph", surface, nodes, edges, epoch)
}

/// Build the canonical client-entry module graph.
pub fn build_client_entry_graph(epoch: SecurityEpoch) -> ModuleGraph {
    let surface = RenderSurface::ClientEntry;
    let nodes = vec![
        build_module_node(
            "client-entry",
            ReactPackage::ReactDom,
            ".",
            ExportCondition::Browser,
            ModuleFormat::Esm,
            ModuleRole::EntryPoint,
            surface,
        ),
        build_module_node(
            "client-react",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::RuntimeProvider,
            surface,
        ),
        build_module_node(
            "client-jsx-runtime",
            ReactPackage::ReactJsxRuntime,
            "./jsx-runtime",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::InternalShared,
            surface,
        ),
        build_module_node(
            "client-scheduler",
            ReactPackage::Scheduler,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::SchedulerHook,
            surface,
        ),
    ];
    let edges = vec![
        build_module_edge("client-entry", "client-react", "imports"),
        build_module_edge("client-entry", "client-jsx-runtime", "imports"),
        build_module_edge("client-react", "client-scheduler", "imports"),
        build_module_edge("client-jsx-runtime", "client-react", "imports"),
    ];
    build_module_graph("client-entry-graph", surface, nodes, edges, epoch)
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

/// Compute the fraction of ALL_SURFACES covered, in millionths.
pub fn surface_coverage_millionths(surfaces: &[RenderSurface]) -> u64 {
    let total = ALL_SURFACES.len() as u64;
    if total == 0 {
        return 0;
    }
    let unique: BTreeSet<RenderSurface> = surfaces.iter().copied().collect();
    let covered = unique.len() as u64;
    covered.saturating_mul(MILLIONTHS) / total
}

/// Build a surface-coverage report from verification receipts.
pub fn build_coverage_report(
    report_id: &str,
    epoch: SecurityEpoch,
    receipts: Vec<GraphVerificationReceipt>,
) -> SurfaceCoverageReport {
    let mut surfaces_set: BTreeSet<RenderSurface> = BTreeSet::new();
    let mut total_nodes: u64 = 0;
    let mut total_edges: u64 = 0;
    for receipt in &receipts {
        surfaces_set.insert(receipt.surface);
        total_nodes = total_nodes.saturating_add(receipt.node_count);
        total_edges = total_edges.saturating_add(receipt.edge_count);
    }
    let surfaces_covered: Vec<RenderSurface> = surfaces_set.into_iter().collect();
    let coverage = surface_coverage_millionths(&surfaces_covered);
    let content_hash = SurfaceCoverageReport::compute_content_hash(
        report_id,
        epoch,
        &receipts,
        &surfaces_covered,
        coverage,
        total_nodes,
        total_edges,
    );
    SurfaceCoverageReport {
        report_id: report_id.to_owned(),
        epoch,
        receipts,
        surfaces_covered,
        coverage_millionths: coverage,
        total_nodes,
        total_edges,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Canonical manifest
// ---------------------------------------------------------------------------

/// Produce the canonical react module graph manifest.
pub fn franken_engine_react_module_graph_manifest() -> SurfaceCoverageReport {
    let epoch = SecurityEpoch::from_raw(1);
    let ssr_graph = build_ssr_graph(epoch);
    let client_graph = build_client_entry_graph(epoch);
    let ssr_receipt = verify_module_graph(&ssr_graph);
    let client_receipt = verify_module_graph(&client_graph);
    build_coverage_report(
        "canonical-react-module-graph-manifest",
        epoch,
        vec![ssr_receipt, client_receipt],
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_surface_display_server_side_render() {
        assert_eq!(
            RenderSurface::ServerSideRender.to_string(),
            "server_side_render"
        );
    }

    #[test]
    fn render_surface_display_client_entry() {
        assert_eq!(RenderSurface::ClientEntry.to_string(), "client_entry");
    }

    #[test]
    fn render_surface_display_hydration_bridge() {
        assert_eq!(
            RenderSurface::HydrationBridge.to_string(),
            "hydration_bridge"
        );
    }

    #[test]
    fn render_surface_display_static_generation() {
        assert_eq!(
            RenderSurface::StaticGeneration.to_string(),
            "static_generation"
        );
    }

    #[test]
    fn render_surface_display_streaming_ssr() {
        assert_eq!(RenderSurface::StreamingSSR.to_string(), "streaming_ssr");
    }

    #[test]
    fn module_role_display_entry_point() {
        assert_eq!(ModuleRole::EntryPoint.to_string(), "entry_point");
    }

    #[test]
    fn module_role_display_runtime_provider() {
        assert_eq!(ModuleRole::RuntimeProvider.to_string(), "runtime_provider");
    }

    #[test]
    fn module_role_display_renderer_binding() {
        assert_eq!(ModuleRole::RendererBinding.to_string(), "renderer_binding");
    }

    #[test]
    fn module_role_display_scheduler_hook() {
        assert_eq!(ModuleRole::SchedulerHook.to_string(), "scheduler_hook");
    }

    #[test]
    fn module_role_display_internal_shared() {
        assert_eq!(ModuleRole::InternalShared.to_string(), "internal_shared");
    }

    #[test]
    fn module_role_display_unsupported_surface() {
        assert_eq!(
            ModuleRole::UnsupportedSurface.to_string(),
            "unsupported_surface"
        );
    }

    #[test]
    fn graph_node_id_creation() {
        let id = GraphNodeId::new("test-node");
        assert_eq!(id.as_str(), "test-node");
    }

    #[test]
    fn graph_node_id_display() {
        let id = GraphNodeId::new("my-node");
        assert_eq!(id.to_string(), "my-node");
    }

    #[test]
    fn graph_node_id_equality() {
        assert_eq!(GraphNodeId::new("same"), GraphNodeId::new("same"));
    }

    #[test]
    fn graph_node_id_ordering() {
        assert!(GraphNodeId::new("alpha") < GraphNodeId::new("beta"));
    }

    #[test]
    fn module_graph_node_creation() {
        let node = build_module_node(
            "n1",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::RuntimeProvider,
            RenderSurface::ClientEntry,
        );
        assert_eq!(node.node_id.as_str(), "n1");
        assert_eq!(node.package, ReactPackage::React);
        assert_eq!(node.subpath, ".");
    }

    #[test]
    fn module_graph_node_hash_determinism() {
        let a = build_module_node(
            "n1",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::RuntimeProvider,
            RenderSurface::ClientEntry,
        );
        let b = build_module_node(
            "n1",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::RuntimeProvider,
            RenderSurface::ClientEntry,
        );
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn module_graph_node_hash_differs_with_different_id() {
        let a = build_module_node(
            "n1",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::RuntimeProvider,
            RenderSurface::ClientEntry,
        );
        let b = build_module_node(
            "n2",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::RuntimeProvider,
            RenderSurface::ClientEntry,
        );
        assert_ne!(a.content_hash, b.content_hash);
    }

    #[test]
    fn module_graph_node_display() {
        let node = build_module_node(
            "x",
            ReactPackage::ReactDom,
            ".",
            ExportCondition::Browser,
            ModuleFormat::Esm,
            ModuleRole::RendererBinding,
            RenderSurface::ClientEntry,
        );
        let s = node.to_string();
        assert!(s.contains("x"));
        assert!(s.contains("react_dom"));
    }

    #[test]
    fn module_graph_edge_creation() {
        let edge = build_module_edge("a", "b", "imports");
        assert_eq!(edge.from_node.as_str(), "a");
        assert_eq!(edge.to_node.as_str(), "b");
        assert_eq!(edge.edge_kind, "imports");
    }

    #[test]
    fn module_graph_edge_hash_determinism() {
        let a = build_module_edge("x", "y", "imports");
        let b = build_module_edge("x", "y", "imports");
        assert_eq!(a.content_hash, b.content_hash);
    }

    #[test]
    fn module_graph_edge_hash_differs_with_kind() {
        let a = build_module_edge("x", "y", "imports");
        let b = build_module_edge("x", "y", "re-exports");
        assert_ne!(a.content_hash, b.content_hash);
    }

    #[test]
    fn module_graph_edge_display() {
        let edge = build_module_edge("from", "to", "side-effect");
        let s = edge.to_string();
        assert!(s.contains("from") && s.contains("to") && s.contains("side-effect"));
    }

    #[test]
    fn module_graph_building() {
        let nodes = vec![build_module_node(
            "entry",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::EntryPoint,
            RenderSurface::ClientEntry,
        )];
        let graph = build_module_graph(
            "test-graph",
            RenderSurface::ClientEntry,
            nodes,
            vec![],
            SecurityEpoch::GENESIS,
        );
        assert_eq!(graph.graph_id, "test-graph");
        assert_eq!(graph.node_count(), 1);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn module_graph_hash_determinism() {
        let mk = || {
            let nodes = vec![build_module_node(
                "e",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                RenderSurface::ClientEntry,
            )];
            build_module_graph(
                "g",
                RenderSurface::ClientEntry,
                nodes,
                vec![],
                SecurityEpoch::GENESIS,
            )
        };
        assert_eq!(mk().content_hash, mk().content_hash);
    }

    #[test]
    fn module_graph_display() {
        let graph = build_module_graph(
            "display-graph",
            RenderSurface::StreamingSSR,
            vec![],
            vec![],
            SecurityEpoch::GENESIS,
        );
        let s = graph.to_string();
        assert!(s.contains("display-graph") && s.contains("streaming_ssr"));
    }

    #[test]
    fn detect_cycles_no_cycle() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RendererBinding,
                s,
            ),
        ];
        let edges = vec![build_module_edge("a", "b", "imports")];
        let graph = build_module_graph("g", s, nodes, edges, SecurityEpoch::GENESIS);
        assert!(detect_cycles(&graph).is_empty());
    }

    #[test]
    fn detect_cycles_simple_cycle() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RendererBinding,
                s,
            ),
        ];
        let edges = vec![
            build_module_edge("a", "b", "imports"),
            build_module_edge("b", "a", "imports"),
        ];
        let graph = build_module_graph("g", s, nodes, edges, SecurityEpoch::GENESIS);
        assert!(!detect_cycles(&graph).is_empty());
    }

    #[test]
    fn detect_cycles_three_node_cycle() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RendererBinding,
                s,
            ),
            build_module_node(
                "c",
                ReactPackage::Scheduler,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::SchedulerHook,
                s,
            ),
        ];
        let edges = vec![
            build_module_edge("a", "b", "imports"),
            build_module_edge("b", "c", "imports"),
            build_module_edge("c", "a", "imports"),
        ];
        let graph = build_module_graph("g", s, nodes, edges, SecurityEpoch::GENESIS);
        assert!(!detect_cycles(&graph).is_empty());
    }

    #[test]
    fn detect_orphans_no_orphans() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RendererBinding,
                s,
            ),
        ];
        let edges = vec![build_module_edge("a", "b", "imports")];
        let graph = build_module_graph("g", s, nodes, edges, SecurityEpoch::GENESIS);
        assert!(detect_orphans(&graph).is_empty());
    }

    #[test]
    fn detect_orphans_with_orphan() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RendererBinding,
                s,
            ),
            build_module_node(
                "orphan",
                ReactPackage::Scheduler,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::SchedulerHook,
                s,
            ),
        ];
        let edges = vec![build_module_edge("a", "b", "imports")];
        let graph = build_module_graph("g", s, nodes, edges, SecurityEpoch::GENESIS);
        let orphans = detect_orphans(&graph);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].as_str(), "orphan");
    }

    #[test]
    fn detect_format_mismatches_compatible() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RendererBinding,
                s,
            ),
        ];
        let edges = vec![build_module_edge("a", "b", "imports")];
        let graph = build_module_graph("g", s, nodes, edges, SecurityEpoch::GENESIS);
        assert!(detect_format_mismatches(&graph).is_empty());
    }

    #[test]
    fn detect_format_mismatches_incompatible() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Require,
                ModuleFormat::Cjs,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RendererBinding,
                s,
            ),
        ];
        let edges = vec![build_module_edge("a", "b", "imports")];
        let graph = build_module_graph("g", s, nodes, edges, SecurityEpoch::GENESIS);
        let mismatches = detect_format_mismatches(&graph);
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].0.as_str(), "a");
        assert_eq!(mismatches[0].1.as_str(), "b");
    }

    #[test]
    fn detect_format_mismatches_esm_to_cjs_ok() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Require,
                ModuleFormat::Cjs,
                ModuleRole::RendererBinding,
                s,
            ),
        ];
        let edges = vec![build_module_edge("a", "b", "imports")];
        let graph = build_module_graph("g", s, nodes, edges, SecurityEpoch::GENESIS);
        assert!(detect_format_mismatches(&graph).is_empty());
    }

    #[test]
    fn verify_module_graph_valid() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "entry",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Browser,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "rt",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RuntimeProvider,
                s,
            ),
        ];
        let edges = vec![build_module_edge("entry", "rt", "imports")];
        let graph = build_module_graph("valid-g", s, nodes, edges, SecurityEpoch::GENESIS);
        let receipt = verify_module_graph(&graph);
        assert_eq!(receipt.verdict, GraphVerificationVerdict::Valid);
        assert!(receipt.diagnostics.is_empty());
    }

    #[test]
    fn verify_module_graph_cycle() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RendererBinding,
                s,
            ),
        ];
        let edges = vec![
            build_module_edge("a", "b", "imports"),
            build_module_edge("b", "a", "imports"),
        ];
        let graph = build_module_graph("cycle-g", s, nodes, edges, SecurityEpoch::GENESIS);
        let receipt = verify_module_graph(&graph);
        assert_eq!(receipt.verdict, GraphVerificationVerdict::CyclicDependency);
        assert!(!receipt.diagnostics.is_empty());
    }

    #[test]
    fn verify_module_graph_format_mismatch() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Require,
                ModuleFormat::Cjs,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RendererBinding,
                s,
            ),
        ];
        let edges = vec![build_module_edge("a", "b", "imports")];
        let graph = build_module_graph("fmt-g", s, nodes, edges, SecurityEpoch::GENESIS);
        assert_eq!(
            verify_module_graph(&graph).verdict,
            GraphVerificationVerdict::FormatMismatch
        );
    }

    #[test]
    fn verify_module_graph_orphan() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "entry",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Browser,
                ModuleFormat::Esm,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "rt",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RuntimeProvider,
                s,
            ),
            build_module_node(
                "orphan",
                ReactPackage::Scheduler,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::SchedulerHook,
                s,
            ),
        ];
        let edges = vec![build_module_edge("entry", "rt", "imports")];
        let graph = build_module_graph("orphan-g", s, nodes, edges, SecurityEpoch::GENESIS);
        assert_eq!(
            verify_module_graph(&graph).verdict,
            GraphVerificationVerdict::OrphanNode
        );
    }

    #[test]
    fn verify_module_graph_unsupported_surface() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![build_module_node(
            "bad",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::UnsupportedSurface,
            s,
        )];
        let graph = build_module_graph("unsup-g", s, nodes, vec![], SecurityEpoch::GENESIS);
        assert_eq!(
            verify_module_graph(&graph).verdict,
            GraphVerificationVerdict::UnsupportedSurface
        );
    }

    #[test]
    fn verify_module_graph_missing_surface() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "rt",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RuntimeProvider,
                s,
            ),
            build_module_node(
                "sched",
                ReactPackage::Scheduler,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::SchedulerHook,
                s,
            ),
        ];
        let edges = vec![build_module_edge("rt", "sched", "imports")];
        let graph = build_module_graph("miss-g", s, nodes, edges, SecurityEpoch::GENESIS);
        assert_eq!(
            verify_module_graph(&graph).verdict,
            GraphVerificationVerdict::MissingSurface
        );
    }

    #[test]
    fn build_ssr_graph_produces_valid_graph() {
        let graph = build_ssr_graph(SecurityEpoch::from_raw(1));
        assert_eq!(graph.surface, RenderSurface::ServerSideRender);
        assert_eq!(graph.node_count(), 4);
        assert_eq!(graph.edge_count(), 4);
    }

    #[test]
    fn build_ssr_graph_verifies_valid() {
        assert_eq!(
            verify_module_graph(&build_ssr_graph(SecurityEpoch::from_raw(1))).verdict,
            GraphVerificationVerdict::Valid
        );
    }

    #[test]
    fn build_client_entry_graph_produces_valid_graph() {
        let graph = build_client_entry_graph(SecurityEpoch::from_raw(1));
        assert_eq!(graph.surface, RenderSurface::ClientEntry);
        assert_eq!(graph.node_count(), 4);
        assert_eq!(graph.edge_count(), 4);
    }

    #[test]
    fn build_client_entry_graph_verifies_valid() {
        assert_eq!(
            verify_module_graph(&build_client_entry_graph(SecurityEpoch::from_raw(1))).verdict,
            GraphVerificationVerdict::Valid
        );
    }

    #[test]
    fn ssr_graph_hash_determinism() {
        assert_eq!(
            build_ssr_graph(SecurityEpoch::from_raw(1)).content_hash,
            build_ssr_graph(SecurityEpoch::from_raw(1)).content_hash
        );
    }

    #[test]
    fn client_graph_hash_determinism() {
        assert_eq!(
            build_client_entry_graph(SecurityEpoch::from_raw(1)).content_hash,
            build_client_entry_graph(SecurityEpoch::from_raw(1)).content_hash
        );
    }

    #[test]
    fn coverage_report_from_two_graphs() {
        let ssr = verify_module_graph(&build_ssr_graph(SecurityEpoch::from_raw(1)));
        let client = verify_module_graph(&build_client_entry_graph(SecurityEpoch::from_raw(1)));
        let report = build_coverage_report("rpt-1", SecurityEpoch::from_raw(1), vec![ssr, client]);
        assert_eq!(report.receipts.len(), 2);
        assert_eq!(report.surfaces_covered.len(), 2);
        assert!(report.coverage_millionths > 0);
        assert!(report.total_nodes > 0);
        assert!(report.total_edges > 0);
    }

    #[test]
    fn coverage_report_empty() {
        let report = build_coverage_report("rpt-empty", SecurityEpoch::GENESIS, vec![]);
        assert_eq!(report.receipts.len(), 0);
        assert_eq!(report.surfaces_covered.len(), 0);
        assert_eq!(report.coverage_millionths, 0);
    }

    #[test]
    fn surface_coverage_all() {
        assert_eq!(surface_coverage_millionths(ALL_SURFACES), MILLIONTHS);
    }

    #[test]
    fn surface_coverage_partial() {
        assert_eq!(
            surface_coverage_millionths(&[
                RenderSurface::ServerSideRender,
                RenderSurface::ClientEntry
            ]),
            400_000
        );
    }

    #[test]
    fn surface_coverage_none() {
        assert_eq!(surface_coverage_millionths(&[]), 0);
    }

    #[test]
    fn surface_coverage_deduplicates() {
        assert_eq!(
            surface_coverage_millionths(&[
                RenderSurface::ClientEntry,
                RenderSurface::ClientEntry,
                RenderSurface::ClientEntry
            ]),
            200_000
        );
    }

    #[test]
    fn canonical_manifest_produces_report() {
        let report = franken_engine_react_module_graph_manifest();
        assert_eq!(report.report_id, "canonical-react-module-graph-manifest");
        assert_eq!(report.receipts.len(), 2);
        assert_eq!(report.surfaces_covered.len(), 2);
    }

    #[test]
    fn canonical_manifest_all_valid() {
        let report = franken_engine_react_module_graph_manifest();
        for receipt in &report.receipts {
            assert_eq!(receipt.verdict, GraphVerificationVerdict::Valid);
        }
    }

    #[test]
    fn canonical_manifest_deterministic() {
        assert_eq!(
            franken_engine_react_module_graph_manifest().content_hash,
            franken_engine_react_module_graph_manifest().content_hash
        );
    }

    #[test]
    fn verdict_display_valid() {
        assert_eq!(GraphVerificationVerdict::Valid.to_string(), "valid");
    }
    #[test]
    fn verdict_display_missing_surface() {
        assert_eq!(
            GraphVerificationVerdict::MissingSurface.to_string(),
            "missing_surface"
        );
    }
    #[test]
    fn verdict_display_cyclic_dependency() {
        assert_eq!(
            GraphVerificationVerdict::CyclicDependency.to_string(),
            "cyclic_dependency"
        );
    }
    #[test]
    fn verdict_display_format_mismatch() {
        assert_eq!(
            GraphVerificationVerdict::FormatMismatch.to_string(),
            "format_mismatch"
        );
    }
    #[test]
    fn verdict_display_unsupported_surface() {
        assert_eq!(
            GraphVerificationVerdict::UnsupportedSurface.to_string(),
            "unsupported_surface"
        );
    }
    #[test]
    fn verdict_display_orphan_node() {
        assert_eq!(
            GraphVerificationVerdict::OrphanNode.to_string(),
            "orphan_node"
        );
    }

    #[test]
    fn serde_roundtrip_render_surface() {
        let val = RenderSurface::StreamingSSR;
        let json = serde_json::to_string(&val).unwrap();
        assert_eq!(val, serde_json::from_str::<RenderSurface>(&json).unwrap());
    }

    #[test]
    fn serde_roundtrip_module_role() {
        let val = ModuleRole::SchedulerHook;
        let json = serde_json::to_string(&val).unwrap();
        assert_eq!(val, serde_json::from_str::<ModuleRole>(&json).unwrap());
    }

    #[test]
    fn serde_roundtrip_graph_node_id() {
        let val = GraphNodeId::new("test-serde");
        let json = serde_json::to_string(&val).unwrap();
        assert_eq!(val, serde_json::from_str::<GraphNodeId>(&json).unwrap());
    }

    #[test]
    fn serde_roundtrip_verdict() {
        let val = GraphVerificationVerdict::CyclicDependency;
        let json = serde_json::to_string(&val).unwrap();
        assert_eq!(
            val,
            serde_json::from_str::<GraphVerificationVerdict>(&json).unwrap()
        );
    }

    #[test]
    fn serde_roundtrip_module_graph_node() {
        let node = build_module_node(
            "serde-n",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::RuntimeProvider,
            RenderSurface::ClientEntry,
        );
        let json = serde_json::to_string(&node).unwrap();
        let back: ModuleGraphNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node.node_id, back.node_id);
        assert_eq!(node.content_hash, back.content_hash);
    }

    #[test]
    fn serde_roundtrip_module_graph_edge() {
        let edge = build_module_edge("s-a", "s-b", "re-exports");
        let json = serde_json::to_string(&edge).unwrap();
        let back: ModuleGraphEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge.from_node, back.from_node);
        assert_eq!(edge.content_hash, back.content_hash);
    }

    #[test]
    fn serde_roundtrip_verification_receipt() {
        let receipt = verify_module_graph(&build_ssr_graph(SecurityEpoch::from_raw(1)));
        let json = serde_json::to_string(&receipt).unwrap();
        let back: GraphVerificationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.receipt_id, back.receipt_id);
        assert_eq!(receipt.content_hash, back.content_hash);
    }

    #[test]
    fn serde_roundtrip_coverage_report() {
        let report = franken_engine_react_module_graph_manifest();
        let json = serde_json::to_string(&report).unwrap();
        let back: SurfaceCoverageReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.report_id, back.report_id);
        assert_eq!(report.content_hash, back.content_hash);
    }

    #[test]
    fn schema_version_not_empty() {
        assert!(!REACT_MODULE_GRAPH_SCHEMA_VERSION.is_empty());
    }
    #[test]
    fn bead_id_correct() {
        assert_eq!(REACT_MODULE_GRAPH_BEAD_ID, "bd-1lsy.5.7.2");
    }
    #[test]
    fn policy_id_correct() {
        assert_eq!(REACT_MODULE_GRAPH_POLICY_ID, "RGC-405B");
    }
    #[test]
    fn component_correct() {
        assert_eq!(COMPONENT, "react_module_graph_verifier");
    }
    #[test]
    fn all_surfaces_has_five() {
        assert_eq!(ALL_SURFACES.len(), 5);
    }

    #[test]
    fn receipt_has_correct_node_edge_counts() {
        let receipt = verify_module_graph(&build_ssr_graph(SecurityEpoch::from_raw(1)));
        assert_eq!(receipt.node_count, 4);
        assert_eq!(receipt.edge_count, 4);
    }

    #[test]
    fn receipt_id_format() {
        let receipt = verify_module_graph(&build_ssr_graph(SecurityEpoch::from_raw(1)));
        assert!(receipt.receipt_id.starts_with("receipt-"));
        assert!(receipt.receipt_id.contains("ssr-graph"));
    }

    #[test]
    fn empty_graph_missing_surface() {
        let graph = build_module_graph(
            "empty",
            RenderSurface::HydrationBridge,
            vec![],
            vec![],
            SecurityEpoch::GENESIS,
        );
        assert_eq!(
            verify_module_graph(&graph).verdict,
            GraphVerificationVerdict::MissingSurface
        );
    }

    #[test]
    fn dual_format_not_flagged_as_mismatch() {
        let s = RenderSurface::ClientEntry;
        let nodes = vec![
            build_module_node(
                "a",
                ReactPackage::React,
                ".",
                ExportCondition::Import,
                ModuleFormat::Dual,
                ModuleRole::EntryPoint,
                s,
            ),
            build_module_node(
                "b",
                ReactPackage::ReactDom,
                ".",
                ExportCondition::Import,
                ModuleFormat::Esm,
                ModuleRole::RendererBinding,
                s,
            ),
        ];
        let edges = vec![build_module_edge("a", "b", "imports")];
        let graph = build_module_graph("dual-g", s, nodes, edges, SecurityEpoch::GENESIS);
        assert!(detect_format_mismatches(&graph).is_empty());
    }

    #[test]
    fn coverage_report_hash_determinism() {
        let a = franken_engine_react_module_graph_manifest();
        let b = franken_engine_react_module_graph_manifest();
        assert_eq!(a.content_hash, b.content_hash);
        assert_eq!(a.coverage_millionths, b.coverage_millionths);
    }

    #[test]
    fn serde_roundtrip_all_render_surfaces() {
        for surface in ALL_SURFACES {
            let json = serde_json::to_string(surface).unwrap();
            assert_eq!(
                *surface,
                serde_json::from_str::<RenderSurface>(&json).unwrap()
            );
        }
    }

    #[test]
    fn module_graph_node_hash_differs_with_surface() {
        let a = build_module_node(
            "n",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::RuntimeProvider,
            RenderSurface::ClientEntry,
        );
        let b = build_module_node(
            "n",
            ReactPackage::React,
            ".",
            ExportCondition::Import,
            ModuleFormat::Esm,
            ModuleRole::RuntimeProvider,
            RenderSurface::ServerSideRender,
        );
        assert_ne!(a.content_hash, b.content_hash);
    }

    #[test]
    fn coverage_report_display() {
        let report = franken_engine_react_module_graph_manifest();
        let s = report.to_string();
        assert!(s.contains("canonical-react-module-graph-manifest"));
        assert!(s.contains("2 surfaces"));
    }

    #[test]
    fn receipt_display() {
        let receipt = verify_module_graph(&build_ssr_graph(SecurityEpoch::from_raw(1)));
        let s = receipt.to_string();
        assert!(s.contains("receipt-") && s.contains("valid"));
    }
}
