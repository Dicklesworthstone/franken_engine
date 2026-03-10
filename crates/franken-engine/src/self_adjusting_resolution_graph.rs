//! Self-adjusting module-resolution dependency graph — RGC-406B
//!
//! Represents module-resolution dependencies as a self-adjusting graph so that
//! invalidation and recomputation cost scales with the changed package region
//! instead of the full dependency forest.  Each graph mutation produces an
//! explicit invalidation receipt that records precisely which modules were
//! affected and which were skipped, together with before/after content hashes.
//!
//! Rollback checkpoints capture a snapshot hash of the graph state at a given
//! security epoch, enabling deterministic undo without replaying every edge.
//!
//! Core invariants:
//!
//! 1. **Locality** — invalidation propagates only along reverse-dependency
//!    edges reachable from the trigger module, not the entire graph.
//! 2. **Determinism** — identical inputs always produce identical graphs,
//!    receipts, and checkpoints (BTreeMap ordering, fixed-point arithmetic).
//! 3. **Rollback truth** — every checkpoint can be verified against the
//!    current graph hash to detect silent drift.
//! 4. **Cycle safety** — the graph explicitly detects and reports cycles
//!    rather than diverging.
//!
//! Reference: [RGC-406B], bead bd-1lsy.5.8.2

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for self-adjusting resolution graph artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.self-adjusting-resolution-graph.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.5.8.2";

/// Component name.
pub const COMPONENT: &str = "self_adjusting_resolution_graph";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-406B";

/// Fixed-point unit: 1.0 represented as 1_000_000.
pub const MILLIONTHS: i64 = 1_000_000;

/// Maximum nodes allowed in a single graph (budget guard).
const MAX_NODES: usize = 500_000;

/// Maximum edges allowed in a single graph (budget guard).
const MAX_EDGES: usize = 2_000_000;

/// Maximum affected modules tracked in a single invalidation receipt.
const MAX_AFFECTED: usize = 100_000;

// ---------------------------------------------------------------------------
// EdgeKind
// ---------------------------------------------------------------------------

/// The kind of dependency relationship between two modules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// A compile-time `import` or `require`.
    StaticImport,
    /// A runtime `import()` expression.
    DynamicImport,
    /// A `export { ... } from "..."` re-export.
    Reexport,
    /// A type-only import (`import type`).
    TypeOnly,
    /// A bare side-effect import (`import "polyfill"`).
    SideEffect,
    /// A conditional import gated by export conditions / package.json `exports`.
    Conditional,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticImport => write!(f, "static-import"),
            Self::DynamicImport => write!(f, "dynamic-import"),
            Self::Reexport => write!(f, "reexport"),
            Self::TypeOnly => write!(f, "type-only"),
            Self::SideEffect => write!(f, "side-effect"),
            Self::Conditional => write!(f, "conditional"),
        }
    }
}

// ---------------------------------------------------------------------------
// ModuleNode
// ---------------------------------------------------------------------------

/// A single module within the resolution graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleNode {
    /// Unique identifier for this node within the graph.
    pub node_id: String,
    /// The import specifier as written in source (e.g. `"react"`, `"./utils"`).
    pub specifier: String,
    /// The fully resolved filesystem path.
    pub resolved_path: String,
    /// The package version string (semver or hash).
    pub version: String,
    /// Content hash of the module source at snapshot time.
    pub content_hash: ContentHash,
}

impl ModuleNode {
    /// Compute a deterministic hash covering all fields.
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"ModuleNode:");
        hasher.update(self.node_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.specifier.as_bytes());
        hasher.update(b"|");
        hasher.update(self.resolved_path.as_bytes());
        hasher.update(b"|");
        hasher.update(self.version.as_bytes());
        hasher.update(b"|");
        hasher.update(self.content_hash.as_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// DependencyEdge
// ---------------------------------------------------------------------------

/// A directed edge from a source module to a target module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdge {
    /// The node_id of the importing module.
    pub source: String,
    /// The node_id of the imported module.
    pub target: String,
    /// The kind of dependency.
    pub kind: EdgeKind,
    /// Optional conditions that gate this edge (e.g. `["import", "node"]`).
    pub conditions: Vec<String>,
}

impl DependencyEdge {
    /// Compute a deterministic hash of this edge.
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"DependencyEdge:");
        hasher.update(self.source.as_bytes());
        hasher.update(b"->");
        hasher.update(self.target.as_bytes());
        hasher.update(b"|");
        hasher.update(format!("{}", self.kind).as_bytes());
        for cond in &self.conditions {
            hasher.update(b"|cond:");
            hasher.update(cond.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// InvalidationScope
// ---------------------------------------------------------------------------

/// Describes the extent of invalidation triggered by a module change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationScope {
    /// Only the single changed module is invalidated.
    SingleModule,
    /// The subtree rooted at the changed module (all transitive dependents).
    SubtreeFromModule,
    /// The entire connected component containing the module.
    ConnectedComponent,
    /// The full graph is invalidated (catastrophic change).
    FullGraph,
}

impl fmt::Display for InvalidationScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleModule => write!(f, "single-module"),
            Self::SubtreeFromModule => write!(f, "subtree"),
            Self::ConnectedComponent => write!(f, "connected-component"),
            Self::FullGraph => write!(f, "full-graph"),
        }
    }
}

// ---------------------------------------------------------------------------
// ResolutionGraph
// ---------------------------------------------------------------------------

/// A self-adjusting module-resolution dependency graph.
///
/// Nodes represent resolved modules; edges represent dependency relationships.
/// The graph maintains a content hash covering all nodes, edges, and roots for
/// snapshot verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionGraph {
    /// Unique identifier for this graph instance.
    pub graph_id: String,
    /// The security epoch at which this graph was last modified.
    pub epoch: SecurityEpoch,
    /// Nodes keyed by node_id, ordered deterministically.
    pub nodes: BTreeMap<String, ModuleNode>,
    /// All dependency edges.
    pub edges: Vec<DependencyEdge>,
    /// Root modules (entry points).
    pub root_modules: Vec<String>,
    /// Content hash of the entire graph (nodes + edges + roots).
    pub content_hash: ContentHash,
}

impl ResolutionGraph {
    /// Recompute the content hash from current state.
    pub fn recompute_hash(&mut self) {
        self.content_hash = compute_graph_hash(&self.nodes, &self.edges, &self.root_modules);
    }

    /// Return the number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return the number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

// ---------------------------------------------------------------------------
// InvalidationReceipt
// ---------------------------------------------------------------------------

/// A receipt documenting the result of an invalidation pass.
///
/// Every invalidation produces a receipt that records what changed, what was
/// recomputed, and what was safely skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationReceipt {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// The scope of this invalidation.
    pub scope: InvalidationScope,
    /// Module IDs that were affected (invalidated).
    pub affected_modules: Vec<String>,
    /// The module that triggered the invalidation.
    pub trigger_module: String,
    /// Content hash of the graph before invalidation.
    pub old_hash: ContentHash,
    /// Content hash of the graph after invalidation.
    pub new_hash: ContentHash,
    /// Number of modules that were recomputed.
    pub recomputed_count: u64,
    /// Number of modules that were safely skipped.
    pub skipped_count: u64,
    /// Content hash of this receipt for integrity verification.
    pub content_hash: ContentHash,
}

impl InvalidationReceipt {
    /// Recompute the receipt content hash from its fields.
    pub fn recompute_hash(&mut self) {
        self.content_hash = compute_receipt_hash(self);
    }
}

// ---------------------------------------------------------------------------
// RollbackCheckpoint
// ---------------------------------------------------------------------------

/// A rollback checkpoint capturing graph state at a point in time.
///
/// Checkpoints allow reverting to a known-good state by comparing the stored
/// graph snapshot hash against the current graph hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackCheckpoint {
    /// Unique checkpoint identifier.
    pub checkpoint_id: String,
    /// Security epoch at checkpoint creation.
    pub epoch: SecurityEpoch,
    /// Hash of the graph at checkpoint time.
    pub graph_snapshot_hash: ContentHash,
    /// Receipt IDs applied since the previous checkpoint.
    pub invalidation_receipts: Vec<String>,
    /// Content hash of this checkpoint for integrity verification.
    pub content_hash: ContentHash,
}

impl RollbackCheckpoint {
    /// Recompute the checkpoint content hash.
    pub fn recompute_hash(&mut self) {
        self.content_hash = compute_checkpoint_hash(self);
    }
}

// ---------------------------------------------------------------------------
// ResolutionGraphError
// ---------------------------------------------------------------------------

/// Errors arising from resolution graph operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResolutionGraphError {
    /// A cycle was detected in the dependency graph.
    CycleDetected,
    /// A referenced module was not found in the graph.
    ModuleNotFound(String),
    /// A duplicate edge was detected.
    DuplicateEdge,
    /// An import specifier was invalid.
    InvalidSpecifier,
    /// A snapshot or checkpoint hash did not match expected state.
    SnapshotCorrupted,
    /// An internal invariant was violated.
    InternalError(String),
}

impl fmt::Display for ResolutionGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CycleDetected => write!(f, "cycle detected in resolution graph"),
            Self::ModuleNotFound(id) => write!(f, "module not found: {id}"),
            Self::DuplicateEdge => write!(f, "duplicate edge in resolution graph"),
            Self::InvalidSpecifier => write!(f, "invalid import specifier"),
            Self::SnapshotCorrupted => write!(f, "snapshot hash mismatch (corrupted)"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute a content hash covering all nodes, edges, and root modules.
fn compute_graph_hash(
    nodes: &BTreeMap<String, ModuleNode>,
    edges: &[DependencyEdge],
    roots: &[String],
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(b"ResolutionGraph:v1:");
    for (id, node) in nodes {
        hasher.update(b"node:");
        hasher.update(id.as_bytes());
        hasher.update(node.compute_hash().as_bytes());
    }
    for edge in edges {
        hasher.update(b"edge:");
        hasher.update(edge.compute_hash().as_bytes());
    }
    for root in roots {
        hasher.update(b"root:");
        hasher.update(root.as_bytes());
    }
    ContentHash::compute(&hasher.finalize())
}

/// Compute a content hash for an invalidation receipt (excluding the content_hash field itself).
fn compute_receipt_hash(receipt: &InvalidationReceipt) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(b"InvalidationReceipt:v1:");
    hasher.update(receipt.receipt_id.as_bytes());
    hasher.update(format!("{}", receipt.scope).as_bytes());
    for m in &receipt.affected_modules {
        hasher.update(b"affected:");
        hasher.update(m.as_bytes());
    }
    hasher.update(b"trigger:");
    hasher.update(receipt.trigger_module.as_bytes());
    hasher.update(receipt.old_hash.as_bytes());
    hasher.update(receipt.new_hash.as_bytes());
    hasher.update(receipt.recomputed_count.to_le_bytes());
    hasher.update(receipt.skipped_count.to_le_bytes());
    ContentHash::compute(&hasher.finalize())
}

/// Compute a content hash for a rollback checkpoint.
fn compute_checkpoint_hash(checkpoint: &RollbackCheckpoint) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(b"RollbackCheckpoint:v1:");
    hasher.update(checkpoint.checkpoint_id.as_bytes());
    hasher.update(checkpoint.epoch.as_u64().to_le_bytes());
    hasher.update(checkpoint.graph_snapshot_hash.as_bytes());
    for rid in &checkpoint.invalidation_receipts {
        hasher.update(b"receipt:");
        hasher.update(rid.as_bytes());
    }
    ContentHash::compute(&hasher.finalize())
}

/// Build a reverse-adjacency index: for each target, collect all sources.
fn build_reverse_index(edges: &[DependencyEdge]) -> BTreeMap<String, BTreeSet<String>> {
    let mut reverse: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for edge in edges {
        reverse
            .entry(edge.target.clone())
            .or_default()
            .insert(edge.source.clone());
    }
    reverse
}

/// Build a forward-adjacency index: for each source, collect all targets.
fn build_forward_index(edges: &[DependencyEdge]) -> BTreeMap<String, BTreeSet<String>> {
    let mut forward: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for edge in edges {
        forward
            .entry(edge.source.clone())
            .or_default()
            .insert(edge.target.clone());
    }
    forward
}

/// Generate a receipt ID from the trigger module and graph hash.
fn generate_receipt_id(trigger: &str, graph_hash: &ContentHash) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"receipt-id:");
    hasher.update(trigger.as_bytes());
    hasher.update(graph_hash.as_bytes());
    let digest = hasher.finalize();
    format!(
        "rcpt-{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

/// Generate a checkpoint ID from the graph hash and epoch.
fn generate_checkpoint_id(graph_hash: &ContentHash, epoch: SecurityEpoch) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"checkpoint-id:");
    hasher.update(graph_hash.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    let digest = hasher.finalize();
    format!(
        "ckpt-{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

/// Validate that an import specifier is non-empty and contains no null bytes.
fn validate_specifier(spec: &str) -> Result<(), ResolutionGraphError> {
    if spec.is_empty() || spec.contains('\0') {
        return Err(ResolutionGraphError::InvalidSpecifier);
    }
    Ok(())
}

/// Check edges for duplicate (source, target, kind) triples.
fn check_duplicate_edges(edges: &[DependencyEdge]) -> Result<(), ResolutionGraphError> {
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    for edge in edges {
        let key = (
            edge.source.clone(),
            edge.target.clone(),
            format!("{}", edge.kind),
        );
        if !seen.insert(key) {
            return Err(ResolutionGraphError::DuplicateEdge);
        }
    }
    Ok(())
}

/// Validate that all edge endpoints reference existing nodes.
fn validate_edge_endpoints(
    edges: &[DependencyEdge],
    nodes: &BTreeMap<String, ModuleNode>,
) -> Result<(), ResolutionGraphError> {
    for edge in edges {
        if !nodes.contains_key(&edge.source) {
            return Err(ResolutionGraphError::ModuleNotFound(edge.source.clone()));
        }
        if !nodes.contains_key(&edge.target) {
            return Err(ResolutionGraphError::ModuleNotFound(edge.target.clone()));
        }
    }
    Ok(())
}

/// Validate that all root modules reference existing nodes.
fn validate_roots(
    roots: &[String],
    nodes: &BTreeMap<String, ModuleNode>,
) -> Result<(), ResolutionGraphError> {
    for root in roots {
        if !nodes.contains_key(root) {
            return Err(ResolutionGraphError::ModuleNotFound(root.clone()));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Build a resolution graph from constituent parts.
///
/// Validates node specifiers, edge endpoints, root references, and checks
/// for duplicate edges.  Returns a fully hashed `ResolutionGraph`.
pub fn build_graph(
    nodes: Vec<ModuleNode>,
    edges: Vec<DependencyEdge>,
    roots: Vec<String>,
) -> Result<ResolutionGraph, ResolutionGraphError> {
    if nodes.len() > MAX_NODES {
        return Err(ResolutionGraphError::InternalError(format!(
            "node count {} exceeds budget {}",
            nodes.len(),
            MAX_NODES,
        )));
    }
    if edges.len() > MAX_EDGES {
        return Err(ResolutionGraphError::InternalError(format!(
            "edge count {} exceeds budget {}",
            edges.len(),
            MAX_EDGES,
        )));
    }

    // Validate specifiers.
    for node in &nodes {
        validate_specifier(&node.specifier)?;
    }

    // Insert into BTreeMap.
    let mut node_map = BTreeMap::new();
    for node in nodes {
        if node_map.contains_key(&node.node_id) {
            return Err(ResolutionGraphError::InternalError(format!(
                "duplicate node_id: {}",
                node.node_id,
            )));
        }
        node_map.insert(node.node_id.clone(), node);
    }

    // Validate edge endpoints.
    validate_edge_endpoints(&edges, &node_map)?;

    // Check for duplicate edges.
    check_duplicate_edges(&edges)?;

    // Validate roots.
    validate_roots(&roots, &node_map)?;

    let content_hash = compute_graph_hash(&node_map, &edges, &roots);

    // Generate a deterministic graph_id.
    let graph_id = {
        let mut hasher = Sha256::new();
        hasher.update(b"graph-id:");
        hasher.update(content_hash.as_bytes());
        let digest = hasher.finalize();
        format!(
            "rg-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        )
    };

    Ok(ResolutionGraph {
        graph_id,
        epoch: SecurityEpoch::GENESIS,
        nodes: node_map,
        edges,
        root_modules: roots,
        content_hash,
    })
}

/// Add a module to an existing graph.
///
/// Validates the specifier and checks for duplicate node IDs.
/// Recomputes the graph hash after insertion.
pub fn add_module(
    graph: &mut ResolutionGraph,
    node: ModuleNode,
) -> Result<(), ResolutionGraphError> {
    validate_specifier(&node.specifier)?;
    if graph.nodes.contains_key(&node.node_id) {
        return Err(ResolutionGraphError::InternalError(format!(
            "duplicate node_id: {}",
            node.node_id,
        )));
    }
    if graph.nodes.len() >= MAX_NODES {
        return Err(ResolutionGraphError::InternalError(
            "node budget exhausted".to_string(),
        ));
    }
    graph.nodes.insert(node.node_id.clone(), node);
    graph.recompute_hash();
    Ok(())
}

/// Remove a module and all its incident edges from the graph.
///
/// Returns an invalidation receipt documenting which modules were affected
/// by the removal.  Affected modules are those that transitively depended on
/// the removed module.
pub fn remove_module(
    graph: &mut ResolutionGraph,
    module_id: &str,
) -> Result<InvalidationReceipt, ResolutionGraphError> {
    if !graph.nodes.contains_key(module_id) {
        return Err(ResolutionGraphError::ModuleNotFound(module_id.to_string()));
    }

    let old_hash = graph.content_hash.clone();

    // Compute the affected set before removal (transitive reverse deps).
    let affected = compute_affected_set(graph, module_id);

    // Remove the node.
    graph.nodes.remove(module_id);

    // Remove all edges incident to this module.
    graph
        .edges
        .retain(|e| e.source != module_id && e.target != module_id);

    // Remove from root_modules if present.
    graph.root_modules.retain(|r| r != module_id);

    // Recompute hash.
    graph.recompute_hash();
    let new_hash = graph.content_hash.clone();

    let total_nodes = graph.nodes.len() as u64;
    let recomputed = affected.len() as u64;
    let skipped = total_nodes.saturating_sub(recomputed);

    let receipt_id = generate_receipt_id(module_id, &old_hash);

    let mut receipt = InvalidationReceipt {
        receipt_id,
        scope: InvalidationScope::SubtreeFromModule,
        affected_modules: affected.into_iter().collect(),
        trigger_module: module_id.to_string(),
        old_hash,
        new_hash,
        recomputed_count: recomputed,
        skipped_count: skipped,
        content_hash: ContentHash::default(),
    };
    receipt.recompute_hash();
    Ok(receipt)
}

/// Compute the invalidation receipt for a changed module without mutating the graph.
///
/// Walks the reverse-dependency edges to find all transitive dependents, then
/// reports them as the affected set.
pub fn invalidate_module(
    graph: &ResolutionGraph,
    module_id: &str,
) -> Result<InvalidationReceipt, ResolutionGraphError> {
    if !graph.nodes.contains_key(module_id) {
        return Err(ResolutionGraphError::ModuleNotFound(module_id.to_string()));
    }

    let old_hash = graph.content_hash.clone();
    let affected = compute_affected_set(graph, module_id);

    let total = graph.nodes.len() as u64;
    let recomputed = affected.len() as u64;
    let skipped = total.saturating_sub(recomputed);

    // Determine scope based on affected ratio.
    let scope = if recomputed <= 1 {
        InvalidationScope::SingleModule
    } else if recomputed == total {
        InvalidationScope::FullGraph
    } else {
        InvalidationScope::SubtreeFromModule
    };

    let receipt_id = generate_receipt_id(module_id, &old_hash);

    let mut receipt = InvalidationReceipt {
        receipt_id,
        scope,
        affected_modules: affected.into_iter().collect(),
        trigger_module: module_id.to_string(),
        old_hash: old_hash.clone(),
        new_hash: old_hash, // graph not mutated
        recomputed_count: recomputed,
        skipped_count: skipped,
        content_hash: ContentHash::default(),
    };
    receipt.recompute_hash();
    Ok(receipt)
}

/// Compute the set of all modules transitively affected by a change to `module_id`.
///
/// Uses BFS on the reverse-dependency graph starting from `module_id`.
/// The trigger module itself is included in the result set.
pub fn compute_affected_set(graph: &ResolutionGraph, module_id: &str) -> BTreeSet<String> {
    let reverse = build_reverse_index(&graph.edges);
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();

    visited.insert(module_id.to_string());
    queue.push_back(module_id.to_string());

    while let Some(current) = queue.pop_front() {
        if let Some(dependents) = reverse.get(&current) {
            for dep in dependents {
                if visited.insert(dep.clone()) && visited.len() <= MAX_AFFECTED {
                    queue.push_back(dep.clone());
                }
            }
        }
    }

    visited
}

/// Create a rollback checkpoint for the current graph state.
pub fn create_checkpoint(graph: &ResolutionGraph) -> RollbackCheckpoint {
    let checkpoint_id = generate_checkpoint_id(&graph.content_hash, graph.epoch);

    let mut checkpoint = RollbackCheckpoint {
        checkpoint_id,
        epoch: graph.epoch,
        graph_snapshot_hash: graph.content_hash.clone(),
        invalidation_receipts: Vec::new(),
        content_hash: ContentHash::default(),
    };
    checkpoint.recompute_hash();
    checkpoint
}

/// Detect all cycles in the graph.
///
/// Returns a list of cycles, where each cycle is a list of node IDs forming
/// a closed loop.  Uses iterative DFS with explicit state tracking.
pub fn detect_cycles(graph: &ResolutionGraph) -> Vec<Vec<String>> {
    let forward = build_forward_index(&graph.edges);
    let mut cycles = Vec::new();
    let mut visited = BTreeSet::new();
    let mut on_stack = BTreeSet::new();
    let mut path = Vec::new();

    for node_id in graph.nodes.keys() {
        if !visited.contains(node_id) {
            detect_cycles_dfs(
                node_id,
                &forward,
                &mut visited,
                &mut on_stack,
                &mut path,
                &mut cycles,
            );
        }
    }

    cycles
}

/// Recursive DFS helper for cycle detection.
fn detect_cycles_dfs(
    node: &str,
    forward: &BTreeMap<String, BTreeSet<String>>,
    visited: &mut BTreeSet<String>,
    on_stack: &mut BTreeSet<String>,
    path: &mut Vec<String>,
    cycles: &mut Vec<Vec<String>>,
) {
    visited.insert(node.to_string());
    on_stack.insert(node.to_string());
    path.push(node.to_string());

    if let Some(neighbors) = forward.get(node) {
        for neighbor in neighbors {
            if !visited.contains(neighbor) {
                detect_cycles_dfs(neighbor, forward, visited, on_stack, path, cycles);
            } else if on_stack.contains(neighbor) {
                // Found a cycle — extract it from the path.
                let cycle_start = path.iter().position(|n| n == neighbor).unwrap_or(0);
                let mut cycle: Vec<String> = path[cycle_start..].to_vec();
                cycle.push(neighbor.clone());
                cycles.push(cycle);
            }
        }
    }

    path.pop();
    on_stack.remove(node);
}

/// Compute a topological ordering of nodes in the graph.
///
/// Returns an error if the graph contains a cycle.  Uses Kahn's algorithm
/// for deterministic ordering (BTreeMap iteration order).
pub fn topological_order(graph: &ResolutionGraph) -> Result<Vec<String>, ResolutionGraphError> {
    let forward = build_forward_index(&graph.edges);

    // Compute in-degree for each node.
    let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();
    for node_id in graph.nodes.keys() {
        in_degree.insert(node_id.clone(), 0);
    }
    for edge in &graph.edges {
        *in_degree.entry(edge.target.clone()).or_insert(0) += 1;
    }

    // Seed queue with zero in-degree nodes (using BTreeSet for determinism).
    let mut queue: BTreeSet<String> = BTreeSet::new();
    for (id, &deg) in &in_degree {
        if deg == 0 {
            queue.insert(id.clone());
        }
    }

    let mut order = Vec::with_capacity(graph.nodes.len());

    while let Some(node) = queue.iter().next().cloned() {
        queue.remove(&node);
        order.push(node.clone());

        if let Some(neighbors) = forward.get(&node) {
            for neighbor in neighbors {
                if let Some(deg) = in_degree.get_mut(neighbor) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.insert(neighbor.clone());
                    }
                }
            }
        }
    }

    if order.len() != graph.nodes.len() {
        return Err(ResolutionGraphError::CycleDetected);
    }

    Ok(order)
}

/// Add a dependency edge to an existing graph.
///
/// Validates that both endpoints exist and the edge is not a duplicate,
/// then recomputes the graph hash.
pub fn add_edge(
    graph: &mut ResolutionGraph,
    edge: DependencyEdge,
) -> Result<(), ResolutionGraphError> {
    if !graph.nodes.contains_key(&edge.source) {
        return Err(ResolutionGraphError::ModuleNotFound(edge.source.clone()));
    }
    if !graph.nodes.contains_key(&edge.target) {
        return Err(ResolutionGraphError::ModuleNotFound(edge.target.clone()));
    }

    // Check for duplicate.
    let key = (
        edge.source.clone(),
        edge.target.clone(),
        format!("{}", edge.kind),
    );
    for existing in &graph.edges {
        let existing_key = (
            existing.source.clone(),
            existing.target.clone(),
            format!("{}", existing.kind),
        );
        if existing_key == key {
            return Err(ResolutionGraphError::DuplicateEdge);
        }
    }

    if graph.edges.len() >= MAX_EDGES {
        return Err(ResolutionGraphError::InternalError(
            "edge budget exhausted".to_string(),
        ));
    }

    graph.edges.push(edge);
    graph.recompute_hash();
    Ok(())
}

/// Compute the connected component containing the given module.
///
/// Uses BFS on the undirected version of the graph (both forward and
/// reverse edges).
pub fn connected_component(
    graph: &ResolutionGraph,
    module_id: &str,
) -> Result<BTreeSet<String>, ResolutionGraphError> {
    if !graph.nodes.contains_key(module_id) {
        return Err(ResolutionGraphError::ModuleNotFound(module_id.to_string()));
    }

    let forward = build_forward_index(&graph.edges);
    let reverse = build_reverse_index(&graph.edges);

    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();

    visited.insert(module_id.to_string());
    queue.push_back(module_id.to_string());

    while let Some(current) = queue.pop_front() {
        // Forward neighbors.
        if let Some(neighbors) = forward.get(&current) {
            for neighbor in neighbors {
                if visited.insert(neighbor.clone()) {
                    queue.push_back(neighbor.clone());
                }
            }
        }
        // Reverse neighbors.
        if let Some(neighbors) = reverse.get(&current) {
            for neighbor in neighbors {
                if visited.insert(neighbor.clone()) {
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }

    Ok(visited)
}

/// Verify that a checkpoint matches the current graph state.
///
/// Returns `Ok(true)` if the hashes match, `Ok(false)` if they diverge,
/// or an error if the checkpoint is structurally invalid.
pub fn verify_checkpoint(
    graph: &ResolutionGraph,
    checkpoint: &RollbackCheckpoint,
) -> Result<bool, ResolutionGraphError> {
    // Verify checkpoint self-integrity.
    let expected = compute_checkpoint_hash(checkpoint);
    if expected != checkpoint.content_hash {
        return Err(ResolutionGraphError::SnapshotCorrupted);
    }

    Ok(graph.content_hash == checkpoint.graph_snapshot_hash)
}

/// Compute graph depth: the longest path from any root module.
///
/// Returns 0 for an empty graph.  Returns an error if a cycle is detected.
pub fn graph_depth(graph: &ResolutionGraph) -> Result<u64, ResolutionGraphError> {
    let order = topological_order(graph)?;
    let forward = build_forward_index(&graph.edges);

    let mut depths: BTreeMap<String, u64> = BTreeMap::new();
    for node_id in &order {
        let current_depth = *depths.get(node_id).unwrap_or(&0);
        if let Some(neighbors) = forward.get(node_id) {
            for neighbor in neighbors {
                let neighbor_depth = depths.entry(neighbor.clone()).or_insert(0);
                if current_depth + 1 > *neighbor_depth {
                    *neighbor_depth = current_depth + 1;
                }
            }
        }
    }

    Ok(depths.values().copied().max().unwrap_or(0))
}

/// Produce the canonical reference resolution graph for the franken-engine.
///
/// This is a small, deterministic graph used for testing and manifest
/// verification.  It represents a minimal React-like application dependency
/// structure.
pub fn franken_engine_resolution_manifest() -> ResolutionGraph {
    let make_node = |id: &str, specifier: &str, path: &str, version: &str| ModuleNode {
        node_id: id.to_string(),
        specifier: specifier.to_string(),
        resolved_path: path.to_string(),
        version: version.to_string(),
        content_hash: ContentHash::compute(format!("{id}:{version}").as_bytes()),
    };

    let nodes = vec![
        make_node("app", "./src/App", "/src/App.tsx", "0.0.0"),
        make_node("react", "react", "/node_modules/react/index.js", "18.3.0"),
        make_node(
            "react-dom",
            "react-dom",
            "/node_modules/react-dom/index.js",
            "18.3.0",
        ),
        make_node("utils", "./src/utils", "/src/utils.ts", "0.0.0"),
        make_node(
            "scheduler",
            "scheduler",
            "/node_modules/scheduler/index.js",
            "0.23.0",
        ),
        make_node("types", "./src/types", "/src/types.ts", "0.0.0"),
    ];

    let edges = vec![
        DependencyEdge {
            source: "app".to_string(),
            target: "react".to_string(),
            kind: EdgeKind::StaticImport,
            conditions: vec![],
        },
        DependencyEdge {
            source: "app".to_string(),
            target: "react-dom".to_string(),
            kind: EdgeKind::StaticImport,
            conditions: vec![],
        },
        DependencyEdge {
            source: "app".to_string(),
            target: "utils".to_string(),
            kind: EdgeKind::StaticImport,
            conditions: vec![],
        },
        DependencyEdge {
            source: "react-dom".to_string(),
            target: "react".to_string(),
            kind: EdgeKind::StaticImport,
            conditions: vec![],
        },
        DependencyEdge {
            source: "react-dom".to_string(),
            target: "scheduler".to_string(),
            kind: EdgeKind::StaticImport,
            conditions: vec![],
        },
        DependencyEdge {
            source: "react".to_string(),
            target: "scheduler".to_string(),
            kind: EdgeKind::StaticImport,
            conditions: vec![],
        },
        DependencyEdge {
            source: "utils".to_string(),
            target: "types".to_string(),
            kind: EdgeKind::StaticImport,
            conditions: vec![],
        },
        DependencyEdge {
            source: "app".to_string(),
            target: "types".to_string(),
            kind: EdgeKind::TypeOnly,
            conditions: vec![],
        },
    ];

    let roots = vec!["app".to_string()];

    build_graph(nodes, edges, roots).expect("canonical manifest must build successfully")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers ---------------------------------------------------------------

    fn make_node(id: &str) -> ModuleNode {
        ModuleNode {
            node_id: id.to_string(),
            specifier: format!("./{id}"),
            resolved_path: format!("/src/{id}.ts"),
            version: "1.0.0".to_string(),
            content_hash: ContentHash::compute(id.as_bytes()),
        }
    }

    fn make_edge(source: &str, target: &str) -> DependencyEdge {
        DependencyEdge {
            source: source.to_string(),
            target: target.to_string(),
            kind: EdgeKind::StaticImport,
            conditions: vec![],
        }
    }

    fn make_edge_with_kind(source: &str, target: &str, kind: EdgeKind) -> DependencyEdge {
        DependencyEdge {
            source: source.to_string(),
            target: target.to_string(),
            kind,
            conditions: vec![],
        }
    }

    fn simple_graph() -> ResolutionGraph {
        // A -> B -> C
        let nodes = vec![make_node("a"), make_node("b"), make_node("c")];
        let edges = vec![make_edge("a", "b"), make_edge("b", "c")];
        build_graph(nodes, edges, vec!["a".to_string()]).unwrap()
    }

    fn diamond_graph() -> ResolutionGraph {
        // A -> B -> D
        // A -> C -> D
        let nodes = vec![
            make_node("a"),
            make_node("b"),
            make_node("c"),
            make_node("d"),
        ];
        let edges = vec![
            make_edge("a", "b"),
            make_edge("a", "c"),
            make_edge("b", "d"),
            make_edge("c", "d"),
        ];
        build_graph(nodes, edges, vec!["a".to_string()]).unwrap()
    }

    // Construction ----------------------------------------------------------

    #[test]
    fn test_build_empty_graph() {
        let graph = build_graph(vec![], vec![], vec![]).unwrap();
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
        assert!(graph.root_modules.is_empty());
    }

    #[test]
    fn test_build_single_node() {
        let graph = build_graph(vec![make_node("a")], vec![], vec!["a".to_string()]).unwrap();
        assert_eq!(graph.node_count(), 1);
        assert!(graph.nodes.contains_key("a"));
    }

    #[test]
    fn test_build_linear_chain() {
        let graph = simple_graph();
        assert_eq!(graph.node_count(), 3);
        assert_eq!(graph.edge_count(), 2);
        assert_eq!(graph.root_modules, vec!["a".to_string()]);
    }

    #[test]
    fn test_build_diamond_graph() {
        let graph = diamond_graph();
        assert_eq!(graph.node_count(), 4);
        assert_eq!(graph.edge_count(), 4);
    }

    #[test]
    fn test_build_graph_deterministic_hash() {
        let g1 = simple_graph();
        let g2 = simple_graph();
        assert_eq!(g1.content_hash, g2.content_hash);
    }

    #[test]
    fn test_build_graph_duplicate_node_id() {
        let nodes = vec![make_node("a"), make_node("a")];
        let result = build_graph(nodes, vec![], vec![]);
        assert!(result.is_err());
        if let Err(ResolutionGraphError::InternalError(msg)) = result {
            assert!(msg.contains("duplicate node_id"));
        }
    }

    #[test]
    fn test_build_graph_invalid_specifier_empty() {
        let mut node = make_node("a");
        node.specifier = String::new();
        let result = build_graph(vec![node], vec![], vec![]);
        assert!(matches!(
            result,
            Err(ResolutionGraphError::InvalidSpecifier)
        ));
    }

    #[test]
    fn test_build_graph_invalid_specifier_null() {
        let mut node = make_node("a");
        node.specifier = "foo\0bar".to_string();
        let result = build_graph(vec![node], vec![], vec![]);
        assert!(matches!(
            result,
            Err(ResolutionGraphError::InvalidSpecifier)
        ));
    }

    #[test]
    fn test_build_graph_missing_edge_source() {
        let nodes = vec![make_node("a")];
        let edges = vec![make_edge("b", "a")];
        let result = build_graph(nodes, edges, vec![]);
        assert!(matches!(result, Err(ResolutionGraphError::ModuleNotFound(ref id)) if id == "b"));
    }

    #[test]
    fn test_build_graph_missing_edge_target() {
        let nodes = vec![make_node("a")];
        let edges = vec![make_edge("a", "z")];
        let result = build_graph(nodes, edges, vec![]);
        assert!(matches!(result, Err(ResolutionGraphError::ModuleNotFound(ref id)) if id == "z"));
    }

    #[test]
    fn test_build_graph_duplicate_edge() {
        let nodes = vec![make_node("a"), make_node("b")];
        let edges = vec![make_edge("a", "b"), make_edge("a", "b")];
        let result = build_graph(nodes, edges, vec![]);
        assert!(matches!(result, Err(ResolutionGraphError::DuplicateEdge)));
    }

    #[test]
    fn test_build_graph_missing_root() {
        let nodes = vec![make_node("a")];
        let result = build_graph(nodes, vec![], vec!["missing".to_string()]);
        assert!(matches!(
            result,
            Err(ResolutionGraphError::ModuleNotFound(_))
        ));
    }

    // Add module ------------------------------------------------------------

    #[test]
    fn test_add_module_success() {
        let mut graph = simple_graph();
        let node = make_node("d");
        assert!(add_module(&mut graph, node).is_ok());
        assert_eq!(graph.node_count(), 4);
        assert!(graph.nodes.contains_key("d"));
    }

    #[test]
    fn test_add_module_duplicate() {
        let mut graph = simple_graph();
        let node = make_node("a");
        let result = add_module(&mut graph, node);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_module_recomputes_hash() {
        let mut graph = simple_graph();
        let old_hash = graph.content_hash.clone();
        add_module(&mut graph, make_node("new")).unwrap();
        assert_ne!(graph.content_hash, old_hash);
    }

    #[test]
    fn test_add_module_invalid_specifier() {
        let mut graph = simple_graph();
        let mut node = make_node("d");
        node.specifier = String::new();
        let result = add_module(&mut graph, node);
        assert!(matches!(
            result,
            Err(ResolutionGraphError::InvalidSpecifier)
        ));
    }

    // Remove module ---------------------------------------------------------

    #[test]
    fn test_remove_module_success() {
        let mut graph = simple_graph();
        let receipt = remove_module(&mut graph, "b").unwrap();
        assert!(!graph.nodes.contains_key("b"));
        assert_eq!(graph.node_count(), 2);
        assert_eq!(receipt.trigger_module, "b");
        assert!(!receipt.affected_modules.is_empty());
    }

    #[test]
    fn test_remove_module_cleans_edges() {
        let mut graph = simple_graph();
        remove_module(&mut graph, "b").unwrap();
        // No edges should reference "b".
        for edge in &graph.edges {
            assert_ne!(edge.source, "b");
            assert_ne!(edge.target, "b");
        }
    }

    #[test]
    fn test_remove_module_not_found() {
        let mut graph = simple_graph();
        let result = remove_module(&mut graph, "nonexistent");
        assert!(matches!(
            result,
            Err(ResolutionGraphError::ModuleNotFound(_))
        ));
    }

    #[test]
    fn test_remove_root_module() {
        let mut graph = simple_graph();
        assert!(graph.root_modules.contains(&"a".to_string()));
        remove_module(&mut graph, "a").unwrap();
        assert!(!graph.root_modules.contains(&"a".to_string()));
    }

    // Invalidation ----------------------------------------------------------

    #[test]
    fn test_invalidate_module_leaf() {
        let graph = simple_graph();
        let receipt = invalidate_module(&graph, "c").unwrap();
        // c is a leaf — affected set includes c, b (depends on c), a (depends on b).
        assert!(receipt.affected_modules.contains(&"c".to_string()));
        assert_eq!(receipt.scope, InvalidationScope::FullGraph);
    }

    #[test]
    fn test_invalidate_module_root() {
        let graph = simple_graph();
        let receipt = invalidate_module(&graph, "a").unwrap();
        // a is a root with no reverse deps — only a is affected.
        assert_eq!(receipt.affected_modules.len(), 1);
        assert_eq!(receipt.scope, InvalidationScope::SingleModule);
    }

    #[test]
    fn test_invalidate_module_middle() {
        let graph = diamond_graph();
        let receipt = invalidate_module(&graph, "b").unwrap();
        // b's reverse dep is a.
        assert!(receipt.affected_modules.contains(&"b".to_string()));
        assert!(receipt.affected_modules.contains(&"a".to_string()));
        assert_eq!(receipt.affected_modules.len(), 2);
    }

    #[test]
    fn test_invalidate_module_not_found() {
        let graph = simple_graph();
        let result = invalidate_module(&graph, "z");
        assert!(matches!(
            result,
            Err(ResolutionGraphError::ModuleNotFound(_))
        ));
    }

    #[test]
    fn test_invalidate_preserves_graph() {
        let graph = simple_graph();
        let hash_before = graph.content_hash.clone();
        let _receipt = invalidate_module(&graph, "b").unwrap();
        assert_eq!(graph.content_hash, hash_before);
    }

    // Affected set ----------------------------------------------------------

    #[test]
    fn test_affected_set_diamond_shared_dep() {
        let graph = diamond_graph();
        let affected = compute_affected_set(&graph, "d");
        // d is depended on by b and c; a depends on both.
        assert!(affected.contains("d"));
        assert!(affected.contains("b"));
        assert!(affected.contains("c"));
        assert!(affected.contains("a"));
        assert_eq!(affected.len(), 4);
    }

    #[test]
    fn test_affected_set_no_deps() {
        let graph = simple_graph();
        let affected = compute_affected_set(&graph, "a");
        assert_eq!(affected.len(), 1);
        assert!(affected.contains("a"));
    }

    #[test]
    fn test_affected_set_isolated_node() {
        let nodes = vec![make_node("x"), make_node("y")];
        let graph = build_graph(nodes, vec![], vec![]).unwrap();
        let affected = compute_affected_set(&graph, "x");
        assert_eq!(affected.len(), 1);
    }

    // Cycle detection -------------------------------------------------------

    #[test]
    fn test_detect_cycles_acyclic() {
        let graph = simple_graph();
        let cycles = detect_cycles(&graph);
        assert!(cycles.is_empty());
    }

    #[test]
    fn test_detect_cycles_simple_cycle() {
        let nodes = vec![make_node("a"), make_node("b")];
        let edges = vec![make_edge("a", "b"), make_edge("b", "a")];
        // build_graph doesn't reject cycles, it's a data structure.
        let mut graph = build_graph(nodes, vec![], vec![]).unwrap();
        graph.edges = edges;
        let cycles = detect_cycles(&graph);
        assert!(!cycles.is_empty());
    }

    #[test]
    fn test_detect_cycles_self_loop() {
        let nodes = vec![make_node("a")];
        let mut graph = build_graph(nodes, vec![], vec![]).unwrap();
        graph.edges = vec![make_edge("a", "a")];
        let cycles = detect_cycles(&graph);
        assert!(!cycles.is_empty());
    }

    // Topological ordering --------------------------------------------------

    #[test]
    fn test_topological_order_linear() {
        let graph = simple_graph();
        let order = topological_order(&graph).unwrap();
        assert_eq!(order.len(), 3);
        // a comes before b, b comes before c.
        let pos_a = order.iter().position(|n| n == "a").unwrap();
        let pos_b = order.iter().position(|n| n == "b").unwrap();
        let pos_c = order.iter().position(|n| n == "c").unwrap();
        assert!(pos_a < pos_b);
        assert!(pos_b < pos_c);
    }

    #[test]
    fn test_topological_order_diamond() {
        let graph = diamond_graph();
        let order = topological_order(&graph).unwrap();
        assert_eq!(order.len(), 4);
        let pos_a = order.iter().position(|n| n == "a").unwrap();
        let pos_d = order.iter().position(|n| n == "d").unwrap();
        assert!(pos_a < pos_d);
    }

    #[test]
    fn test_topological_order_with_cycle() {
        let nodes = vec![make_node("a"), make_node("b")];
        let mut graph = build_graph(nodes, vec![], vec![]).unwrap();
        graph.edges = vec![make_edge("a", "b"), make_edge("b", "a")];
        let result = topological_order(&graph);
        assert!(matches!(result, Err(ResolutionGraphError::CycleDetected)));
    }

    #[test]
    fn test_topological_order_empty() {
        let graph = build_graph(vec![], vec![], vec![]).unwrap();
        let order = topological_order(&graph).unwrap();
        assert!(order.is_empty());
    }

    #[test]
    fn test_topological_order_single_node() {
        let graph = build_graph(vec![make_node("x")], vec![], vec!["x".to_string()]).unwrap();
        let order = topological_order(&graph).unwrap();
        assert_eq!(order, vec!["x".to_string()]);
    }

    // Checkpoint ------------------------------------------------------------

    #[test]
    fn test_create_checkpoint() {
        let graph = simple_graph();
        let checkpoint = create_checkpoint(&graph);
        assert_eq!(checkpoint.epoch, SecurityEpoch::GENESIS);
        assert_eq!(checkpoint.graph_snapshot_hash, graph.content_hash);
        assert!(checkpoint.invalidation_receipts.is_empty());
    }

    #[test]
    fn test_checkpoint_deterministic() {
        let graph = simple_graph();
        let c1 = create_checkpoint(&graph);
        let c2 = create_checkpoint(&graph);
        assert_eq!(c1.content_hash, c2.content_hash);
        assert_eq!(c1.checkpoint_id, c2.checkpoint_id);
    }

    #[test]
    fn test_verify_checkpoint_matches() {
        let graph = simple_graph();
        let checkpoint = create_checkpoint(&graph);
        assert!(verify_checkpoint(&graph, &checkpoint).unwrap());
    }

    #[test]
    fn test_verify_checkpoint_diverged() {
        let mut graph = simple_graph();
        let checkpoint = create_checkpoint(&graph);
        add_module(&mut graph, make_node("d")).unwrap();
        assert!(!verify_checkpoint(&graph, &checkpoint).unwrap());
    }

    #[test]
    fn test_verify_checkpoint_corrupted() {
        let graph = simple_graph();
        let mut checkpoint = create_checkpoint(&graph);
        checkpoint.content_hash = ContentHash::default();
        let result = verify_checkpoint(&graph, &checkpoint);
        assert!(matches!(
            result,
            Err(ResolutionGraphError::SnapshotCorrupted)
        ));
    }

    // Add edge --------------------------------------------------------------

    #[test]
    fn test_add_edge_success() {
        let mut graph = diamond_graph();
        add_module(&mut graph, make_node("e")).unwrap();
        let edge = make_edge("a", "e");
        assert!(add_edge(&mut graph, edge).is_ok());
        assert_eq!(graph.edge_count(), 5);
    }

    #[test]
    fn test_add_edge_missing_source() {
        let mut graph = simple_graph();
        let edge = make_edge("z", "a");
        let result = add_edge(&mut graph, edge);
        assert!(matches!(
            result,
            Err(ResolutionGraphError::ModuleNotFound(_))
        ));
    }

    #[test]
    fn test_add_edge_duplicate() {
        let mut graph = simple_graph();
        let edge = make_edge("a", "b");
        let result = add_edge(&mut graph, edge);
        assert!(matches!(result, Err(ResolutionGraphError::DuplicateEdge)));
    }

    #[test]
    fn test_add_edge_same_endpoints_different_kind() {
        let mut graph = build_graph(
            vec![make_node("a"), make_node("b")],
            vec![make_edge("a", "b")],
            vec![],
        )
        .unwrap();
        let edge = make_edge_with_kind("a", "b", EdgeKind::TypeOnly);
        assert!(add_edge(&mut graph, edge).is_ok());
        assert_eq!(graph.edge_count(), 2);
    }

    // Connected component ---------------------------------------------------

    #[test]
    fn test_connected_component_full() {
        let graph = simple_graph();
        let component = connected_component(&graph, "c").unwrap();
        assert_eq!(component.len(), 3);
    }

    #[test]
    fn test_connected_component_isolated() {
        let nodes = vec![make_node("x"), make_node("y")];
        let graph = build_graph(nodes, vec![], vec![]).unwrap();
        let component = connected_component(&graph, "x").unwrap();
        assert_eq!(component.len(), 1);
    }

    #[test]
    fn test_connected_component_not_found() {
        let graph = simple_graph();
        let result = connected_component(&graph, "nope");
        assert!(matches!(
            result,
            Err(ResolutionGraphError::ModuleNotFound(_))
        ));
    }

    // Graph depth -----------------------------------------------------------

    #[test]
    fn test_graph_depth_linear() {
        let graph = simple_graph();
        assert_eq!(graph_depth(&graph).unwrap(), 2);
    }

    #[test]
    fn test_graph_depth_empty() {
        let graph = build_graph(vec![], vec![], vec![]).unwrap();
        assert_eq!(graph_depth(&graph).unwrap(), 0);
    }

    #[test]
    fn test_graph_depth_diamond() {
        let graph = diamond_graph();
        assert_eq!(graph_depth(&graph).unwrap(), 2);
    }

    // Serde roundtrips ------------------------------------------------------

    #[test]
    fn test_serde_roundtrip_module_node() {
        let node = make_node("test");
        let json = serde_json::to_string(&node).unwrap();
        let restored: ModuleNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, restored);
    }

    #[test]
    fn test_serde_roundtrip_dependency_edge() {
        let edge = DependencyEdge {
            source: "src".to_string(),
            target: "tgt".to_string(),
            kind: EdgeKind::DynamicImport,
            conditions: vec!["import".to_string(), "node".to_string()],
        };
        let json = serde_json::to_string(&edge).unwrap();
        let restored: DependencyEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, restored);
    }

    #[test]
    fn test_serde_roundtrip_edge_kind_all_variants() {
        let variants = vec![
            EdgeKind::StaticImport,
            EdgeKind::DynamicImport,
            EdgeKind::Reexport,
            EdgeKind::TypeOnly,
            EdgeKind::SideEffect,
            EdgeKind::Conditional,
        ];
        for kind in &variants {
            let json = serde_json::to_string(kind).unwrap();
            let restored: EdgeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, restored);
        }
    }

    #[test]
    fn test_serde_roundtrip_invalidation_scope() {
        let scopes = vec![
            InvalidationScope::SingleModule,
            InvalidationScope::SubtreeFromModule,
            InvalidationScope::ConnectedComponent,
            InvalidationScope::FullGraph,
        ];
        for scope in &scopes {
            let json = serde_json::to_string(scope).unwrap();
            let restored: InvalidationScope = serde_json::from_str(&json).unwrap();
            assert_eq!(*scope, restored);
        }
    }

    #[test]
    fn test_serde_roundtrip_resolution_graph() {
        let graph = simple_graph();
        let json = serde_json::to_string(&graph).unwrap();
        let restored: ResolutionGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(graph, restored);
    }

    #[test]
    fn test_serde_roundtrip_invalidation_receipt() {
        let graph = simple_graph();
        let receipt = invalidate_module(&graph, "b").unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: InvalidationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    #[test]
    fn test_serde_roundtrip_rollback_checkpoint() {
        let graph = simple_graph();
        let checkpoint = create_checkpoint(&graph);
        let json = serde_json::to_string(&checkpoint).unwrap();
        let restored: RollbackCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(checkpoint, restored);
    }

    #[test]
    fn test_serde_roundtrip_error() {
        let errors = vec![
            ResolutionGraphError::CycleDetected,
            ResolutionGraphError::ModuleNotFound("x".to_string()),
            ResolutionGraphError::DuplicateEdge,
            ResolutionGraphError::InvalidSpecifier,
            ResolutionGraphError::SnapshotCorrupted,
            ResolutionGraphError::InternalError("oops".to_string()),
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: ResolutionGraphError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // Manifest --------------------------------------------------------------

    #[test]
    fn test_manifest_builds_successfully() {
        let graph = franken_engine_resolution_manifest();
        assert!(graph.node_count() >= 4);
        assert!(graph.edge_count() >= 4);
        assert!(!graph.root_modules.is_empty());
    }

    #[test]
    fn test_manifest_is_acyclic() {
        let graph = franken_engine_resolution_manifest();
        let cycles = detect_cycles(&graph);
        assert!(cycles.is_empty());
    }

    #[test]
    fn test_manifest_deterministic() {
        let g1 = franken_engine_resolution_manifest();
        let g2 = franken_engine_resolution_manifest();
        assert_eq!(g1.content_hash, g2.content_hash);
        assert_eq!(g1.graph_id, g2.graph_id);
    }

    #[test]
    fn test_manifest_topological_order() {
        let graph = franken_engine_resolution_manifest();
        let order = topological_order(&graph).unwrap();
        assert_eq!(order.len(), graph.node_count());
    }

    #[test]
    fn test_manifest_invalidation() {
        let graph = franken_engine_resolution_manifest();
        let receipt = invalidate_module(&graph, "scheduler").unwrap();
        assert!(receipt.affected_modules.contains(&"scheduler".to_string()));
        // scheduler is depended on by react and react-dom, so those propagate to app.
        assert!(receipt.affected_modules.len() >= 2);
    }

    #[test]
    fn test_manifest_checkpoint_verifies() {
        let graph = franken_engine_resolution_manifest();
        let checkpoint = create_checkpoint(&graph);
        assert!(verify_checkpoint(&graph, &checkpoint).unwrap());
    }

    // Error display ---------------------------------------------------------

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", ResolutionGraphError::CycleDetected),
            "cycle detected in resolution graph",
        );
        assert_eq!(
            format!("{}", ResolutionGraphError::ModuleNotFound("foo".into())),
            "module not found: foo",
        );
        assert_eq!(
            format!("{}", ResolutionGraphError::DuplicateEdge),
            "duplicate edge in resolution graph",
        );
        assert_eq!(
            format!("{}", ResolutionGraphError::InvalidSpecifier),
            "invalid import specifier",
        );
        assert_eq!(
            format!("{}", ResolutionGraphError::SnapshotCorrupted),
            "snapshot hash mismatch (corrupted)",
        );
        assert_eq!(
            format!("{}", ResolutionGraphError::InternalError("x".into())),
            "internal error: x",
        );
    }

    // Edge kind display -----------------------------------------------------

    #[test]
    fn test_edge_kind_display() {
        assert_eq!(format!("{}", EdgeKind::StaticImport), "static-import");
        assert_eq!(format!("{}", EdgeKind::DynamicImport), "dynamic-import");
        assert_eq!(format!("{}", EdgeKind::Reexport), "reexport");
        assert_eq!(format!("{}", EdgeKind::TypeOnly), "type-only");
        assert_eq!(format!("{}", EdgeKind::SideEffect), "side-effect");
        assert_eq!(format!("{}", EdgeKind::Conditional), "conditional");
    }

    // InvalidationScope display ---------------------------------------------

    #[test]
    fn test_invalidation_scope_display() {
        assert_eq!(
            format!("{}", InvalidationScope::SingleModule),
            "single-module"
        );
        assert_eq!(
            format!("{}", InvalidationScope::SubtreeFromModule),
            "subtree"
        );
        assert_eq!(
            format!("{}", InvalidationScope::ConnectedComponent),
            "connected-component",
        );
        assert_eq!(format!("{}", InvalidationScope::FullGraph), "full-graph");
    }

    // Constants -------------------------------------------------------------

    #[test]
    fn test_constants() {
        assert_eq!(BEAD_ID, "bd-1lsy.5.8.2");
        assert_eq!(POLICY_ID, "RGC-406B");
        assert_eq!(COMPONENT, "self_adjusting_resolution_graph");
        assert_eq!(MILLIONTHS, 1_000_000);
        assert!(!SCHEMA_VERSION.is_empty());
    }

    // Node hashing ----------------------------------------------------------

    #[test]
    fn test_node_hash_deterministic() {
        let n1 = make_node("a");
        let n2 = make_node("a");
        assert_eq!(n1.compute_hash(), n2.compute_hash());
    }

    #[test]
    fn test_node_hash_varies_with_content() {
        let n1 = make_node("a");
        let mut n2 = make_node("a");
        n2.version = "2.0.0".to_string();
        assert_ne!(n1.compute_hash(), n2.compute_hash());
    }

    // Edge hashing ----------------------------------------------------------

    #[test]
    fn test_edge_hash_deterministic() {
        let e1 = make_edge("a", "b");
        let e2 = make_edge("a", "b");
        assert_eq!(e1.compute_hash(), e2.compute_hash());
    }

    #[test]
    fn test_edge_hash_varies_with_kind() {
        let e1 = make_edge_with_kind("a", "b", EdgeKind::StaticImport);
        let e2 = make_edge_with_kind("a", "b", EdgeKind::DynamicImport);
        assert_ne!(e1.compute_hash(), e2.compute_hash());
    }

    // Receipt integrity -----------------------------------------------------

    #[test]
    fn test_receipt_hash_self_consistent() {
        let graph = simple_graph();
        let receipt = invalidate_module(&graph, "b").unwrap();
        let expected = compute_receipt_hash(&receipt);
        assert_eq!(receipt.content_hash, expected);
    }

    // Multiple edge kinds ---------------------------------------------------

    #[test]
    fn test_graph_with_multiple_edge_kinds() {
        let nodes = vec![make_node("a"), make_node("b"), make_node("c")];
        let edges = vec![
            make_edge_with_kind("a", "b", EdgeKind::StaticImport),
            make_edge_with_kind("a", "b", EdgeKind::TypeOnly),
            make_edge_with_kind("a", "c", EdgeKind::DynamicImport),
            make_edge_with_kind("b", "c", EdgeKind::Reexport),
        ];
        let graph = build_graph(nodes, edges, vec!["a".to_string()]).unwrap();
        assert_eq!(graph.edge_count(), 4);
        let order = topological_order(&graph).unwrap();
        assert_eq!(order.len(), 3);
    }

    // Conditional edges -----------------------------------------------------

    #[test]
    fn test_conditional_edge() {
        let nodes = vec![make_node("a"), make_node("b")];
        let edges = vec![DependencyEdge {
            source: "a".to_string(),
            target: "b".to_string(),
            kind: EdgeKind::Conditional,
            conditions: vec!["import".to_string(), "node".to_string()],
        }];
        let graph = build_graph(nodes, edges, vec!["a".to_string()]).unwrap();
        assert_eq!(graph.edges[0].conditions.len(), 2);
    }

    // Large graph construction ----------------------------------------------

    #[test]
    fn test_large_linear_graph() {
        let count = 100;
        let nodes: Vec<ModuleNode> = (0..count).map(|i| make_node(&format!("n{i}"))).collect();
        let edges: Vec<DependencyEdge> = (0..count - 1)
            .map(|i| make_edge(&format!("n{i}"), &format!("n{}", i + 1)))
            .collect();
        let graph = build_graph(nodes, edges, vec!["n0".to_string()]).unwrap();
        assert_eq!(graph.node_count(), count);
        assert_eq!(graph.edge_count(), count - 1);

        let order = topological_order(&graph).unwrap();
        assert_eq!(order.len(), count);

        // Invalidating the last node should propagate to all nodes.
        let receipt = invalidate_module(&graph, &format!("n{}", count - 1)).unwrap();
        assert_eq!(receipt.affected_modules.len(), count);
    }

    // Epoch tracking --------------------------------------------------------

    #[test]
    fn test_graph_epoch_default() {
        let graph = simple_graph();
        assert_eq!(graph.epoch, SecurityEpoch::GENESIS);
    }

    #[test]
    fn test_checkpoint_epoch_propagation() {
        let mut graph = simple_graph();
        graph.epoch = SecurityEpoch::from_raw(42);
        let checkpoint = create_checkpoint(&graph);
        assert_eq!(checkpoint.epoch, SecurityEpoch::from_raw(42));
    }
}
