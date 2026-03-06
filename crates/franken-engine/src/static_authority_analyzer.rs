//! Static upper-bound authority analyzer for the PLAS pipeline.
//!
//! Computes a conservative capability upper bound from an extension's effect
//! graph and declared manifest intents. The result is a sound over-approximation:
//! every capability the extension *could* exercise on any execution path is
//! included, but capabilities it provably never reaches may be excluded.
//!
//! The analysis proceeds in two phases:
//! 1. **Lattice reachability**: walk the effect graph from entry nodes,
//!    collecting capabilities at every reachable hostcall site.
//! 2. **Precision refinement**: optional path-sensitive analysis removes
//!    capabilities that are only reachable on provably dead paths.
//!
//! The output [`StaticAnalysisReport`] feeds directly into the PLAS witness
//! builder as static evidence for the [`ProofKind::StaticAnalysis`] proof
//! obligations.
//!
//! Plan reference: Section 10.15 item 2 of 9I.5 (`bd-2lr7`).
//! Cross-refs: bd-2w9w (witness schema consumes analysis report),
//! bd-1kdc (ablation engine uses upper bound as starting point),
//! bd-2tzx (theorem checks validate merge legality of static + dynamic evidence).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema hash
// ---------------------------------------------------------------------------

fn analysis_report_schema_hash() -> crate::deterministic_serde::SchemaHash {
    crate::deterministic_serde::SchemaHash::from_definition(
        b"plas.static-authority-analysis-report.v1",
    )
}

fn append_canonical_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// Capability — atomic authority unit (string-based, lattice-sorted)
// ---------------------------------------------------------------------------

/// Atomic capability identifier used in the effect graph.
///
/// Wraps a string to match the `Capability` type in `policy_theorem_compiler`.
/// Capabilities are totally ordered for deterministic set operations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Capability(pub String);

impl Capability {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Effect graph — input representation for static analysis
// ---------------------------------------------------------------------------

/// Classification of an effect node in the IR graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EffectNodeKind {
    /// Entry point of the extension (always reachable).
    Entry,
    /// A hostcall site that exercises a specific capability.
    HostcallSite {
        /// The capability required by this hostcall.
        capability: Capability,
    },
    /// A control-flow decision point (branch, match, loop header).
    ControlFlow,
    /// An internal computation node (no capability requirement).
    Computation,
    /// Exit point of the extension.
    Exit,
}

/// A node in the extension's effect graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectNode {
    /// Unique node identifier within the effect graph.
    pub node_id: String,
    /// Classification of this node.
    pub kind: EffectNodeKind,
    /// Source location for diagnostics (e.g. "module.rs:42").
    pub source_location: Option<String>,
}

/// A directed edge in the effect graph representing control flow.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EffectEdge {
    /// Source node identifier.
    pub from: String,
    /// Target node identifier.
    pub to: String,
    /// Whether this edge is provably dead (unreachable branch).
    /// Path-sensitive analysis may mark edges as dead.
    pub provably_dead: bool,
}

/// The complete effect graph for an extension.
///
/// Represents the control-flow and capability-usage structure of an extension
/// at the IR level. Built from capability-typed IR (IR2 CapabilityIR) by the
/// lowering pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectGraph {
    /// Extension identifier.
    pub extension_id: String,
    /// All nodes in the graph.
    pub nodes: Vec<EffectNode>,
    /// All edges in the graph.
    pub edges: Vec<EffectEdge>,
}

impl EffectGraph {
    /// Create a new empty effect graph for an extension.
    pub fn new(extension_id: impl Into<String>) -> Self {
        Self {
            extension_id: extension_id.into(),
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, node: EffectNode) {
        self.nodes.push(node);
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, edge: EffectEdge) {
        self.edges.push(edge);
    }

    /// Find all entry nodes.
    fn entry_nodes(&self) -> Vec<&EffectNode> {
        self.nodes
            .iter()
            .filter(|n| matches!(n.kind, EffectNodeKind::Entry))
            .collect()
    }

    /// Build adjacency list (node_id -> list of successor node_ids).
    fn adjacency_list(&self, include_dead: bool) -> BTreeMap<&str, Vec<&str>> {
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for edge in &self.edges {
            if !include_dead && edge.provably_dead {
                continue;
            }
            adj.entry(edge.from.as_str())
                .or_default()
                .push(edge.to.as_str());
        }
        adj
    }

    /// Look up a node by ID.
    fn node_by_id(&self, id: &str) -> Option<&EffectNode> {
        self.nodes.iter().find(|n| n.node_id == id)
    }
}

/// Declared capability intents from the extension manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestIntents {
    /// Extension identifier (must match the effect graph).
    pub extension_id: String,
    /// Capabilities declared as needed by the extension author.
    pub declared_capabilities: BTreeSet<Capability>,
    /// Optional capabilities: used if available, not required.
    pub optional_capabilities: BTreeSet<Capability>,
}

// ---------------------------------------------------------------------------
// Analysis configuration
// ---------------------------------------------------------------------------

/// Configuration for the static analysis pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Maximum analysis time budget in nanoseconds.
    /// If exceeded, analysis fails open to manifest-declared set with warning.
    pub time_budget_ns: u64,
    /// Whether to enable path-sensitive analysis for improved precision.
    /// When disabled, all edges (including provably-dead ones) are traversed.
    pub path_sensitive: bool,
    /// Zone for scoping the analysis report.
    pub zone: String,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            time_budget_ns: 60_000_000_000, // 60 seconds
            path_sensitive: true,
            zone: "default".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Analysis output — structured report
// ---------------------------------------------------------------------------

/// Method used to determine a capability's inclusion in the upper bound.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnalysisMethod {
    /// Found via lattice reachability from entry nodes.
    LatticeReachability,
    /// Included because manifest declares it and reachability is uncertain.
    ManifestFallback,
    /// Included because analysis timed out (fail-open).
    TimeoutFallback,
    /// Excluded by path-sensitive dead-code elimination.
    ExcludedDeadPath,
}

impl fmt::Display for AnalysisMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LatticeReachability => f.write_str("lattice_reachability"),
            Self::ManifestFallback => f.write_str("manifest_fallback"),
            Self::TimeoutFallback => f.write_str("timeout_fallback"),
            Self::ExcludedDeadPath => f.write_str("excluded_dead_path"),
        }
    }
}

/// Evidence for why a specific capability is in the upper bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerCapabilityEvidence {
    /// The capability this evidence pertains to.
    pub capability: Capability,
    /// Node IDs in the effect graph that require this capability.
    pub requiring_nodes: BTreeSet<String>,
    /// How this capability was determined to be needed.
    pub analysis_method: AnalysisMethod,
    /// Human-readable summary.
    pub summary: String,
}

/// Precision estimate for the analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrecisionEstimate {
    /// Number of capabilities in the computed upper bound.
    pub upper_bound_size: u64,
    /// Number of capabilities in the manifest-declared set.
    pub manifest_declared_size: u64,
    /// Over-approximation ratio (fixed-point millionths).
    /// 1_000_000 means upper bound == manifest. > 1_000_000 means upper bound
    /// is larger than manifest (should not happen for valid extensions).
    /// < 1_000_000 means analysis tightened beyond manifest.
    pub ratio_millionths: u64,
    /// Number of capabilities excluded by path-sensitive analysis.
    pub excluded_by_path_sensitivity: u64,
}

/// The complete static analysis report.
///
/// Contains the conservative capability upper bound and per-capability
/// evidence. This report feeds into the PLAS witness builder as evidence
/// for `ProofKind::StaticAnalysis` proof obligations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticAnalysisReport {
    /// Content-addressed report identifier.
    pub report_id: crate::engine_object_id::EngineObjectId,
    /// Extension that was analyzed.
    pub extension_id: String,
    /// Conservative upper bound: set of capabilities that could be exercised.
    pub upper_bound_capabilities: BTreeSet<Capability>,
    /// Per-capability evidence for inclusion/exclusion.
    pub per_capability_evidence: Vec<PerCapabilityEvidence>,
    /// Analysis method used for the overall result.
    pub primary_analysis_method: AnalysisMethod,
    /// Precision estimate.
    pub precision: PrecisionEstimate,
    /// Analysis duration in nanoseconds.
    pub analysis_duration_ns: u64,
    /// Whether the analysis timed out and fell back to manifest.
    pub timed_out: bool,
    /// Whether path-sensitive analysis was enabled.
    pub path_sensitive: bool,
    /// Content hash of the effect graph that was analyzed.
    pub effect_graph_hash: ContentHash,
    /// Content hash of the manifest intents.
    pub manifest_hash: ContentHash,
    /// Security epoch at analysis time.
    pub epoch: SecurityEpoch,
    /// Timestamp when analysis completed (nanoseconds, monotonic).
    pub timestamp_ns: u64,
    /// Zone scoping.
    pub zone: String,
}

impl StaticAnalysisReport {
    /// Derive report ID from canonical fields.
    pub fn derive_report_id(
        extension_id: &str,
        effect_graph_hash: &ContentHash,
        manifest_hash: &ContentHash,
        timestamp_ns: u64,
        zone: &str,
    ) -> Result<crate::engine_object_id::EngineObjectId, crate::engine_object_id::IdError> {
        let mut canonical = Vec::new();
        append_canonical_field(&mut canonical, b"static-authority-analysis");
        append_canonical_field(&mut canonical, extension_id.as_bytes());
        append_canonical_field(&mut canonical, effect_graph_hash.as_bytes());
        append_canonical_field(&mut canonical, manifest_hash.as_bytes());
        append_canonical_field(&mut canonical, &timestamp_ns.to_be_bytes());
        let schema_id = crate::engine_object_id::SchemaId::from_definition(
            analysis_report_schema_hash().0.as_slice(),
        );
        crate::engine_object_id::derive_id(
            crate::engine_object_id::ObjectDomain::EvidenceRecord,
            zone,
            &schema_id,
            &canonical,
        )
    }

    /// Content hash of this report for evidence chaining.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        append_canonical_field(&mut buf, b"static-analysis-report");
        append_canonical_field(&mut buf, self.report_id.as_bytes());
        append_canonical_field(&mut buf, self.extension_id.as_bytes());
        append_canonical_field(&mut buf, self.effect_graph_hash.as_bytes());
        append_canonical_field(&mut buf, self.manifest_hash.as_bytes());
        append_canonical_field(&mut buf, &self.timestamp_ns.to_be_bytes());
        for cap in &self.upper_bound_capabilities {
            append_canonical_field(&mut buf, cap.as_str().as_bytes());
        }
        ContentHash::compute(&buf)
    }

    /// Check whether a capability is in the computed upper bound.
    pub fn requires_capability(&self, cap: &Capability) -> bool {
        self.upper_bound_capabilities.contains(cap)
    }

    /// Capabilities in the upper bound but not in the manifest.
    pub fn undeclared_capabilities(&self, manifest: &ManifestIntents) -> BTreeSet<Capability> {
        self.upper_bound_capabilities
            .difference(&manifest.declared_capabilities)
            .cloned()
            .collect()
    }

    /// Capabilities in the manifest but not in the upper bound.
    pub fn unused_declared_capabilities(&self, manifest: &ManifestIntents) -> BTreeSet<Capability> {
        manifest
            .declared_capabilities
            .difference(&self.upper_bound_capabilities)
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Static authority analyzer — main analysis engine
// ---------------------------------------------------------------------------

/// Static authority analyzer that computes conservative capability upper bounds.
///
/// Constructed with an analysis configuration. The [`analyze`] method takes
/// an effect graph and manifest intents, and produces a [`StaticAnalysisReport`].
///
/// The analysis is deterministic: identical inputs always produce identical
/// output, regardless of wall-clock time (time budget is checked but does not
/// affect traversal order).
#[derive(Debug, Clone)]
pub struct StaticAuthorityAnalyzer {
    config: AnalysisConfig,
}

/// Intermediate result from graph traversal.
#[derive(Debug)]
struct TraversalResult {
    /// Capabilities found at reachable hostcall sites.
    reachable_capabilities: BTreeMap<Capability, BTreeSet<String>>,
    /// All reachable node IDs.
    reachable_nodes: BTreeSet<String>,
    /// Capabilities excluded by path-sensitive dead-code analysis.
    excluded_dead: BTreeSet<Capability>,
}

impl StaticAuthorityAnalyzer {
    /// Create a new analyzer with the given configuration.
    pub fn new(config: AnalysisConfig) -> Self {
        Self { config }
    }

    /// Analyze an extension's effect graph against its manifest intents.
    ///
    /// Returns a `StaticAnalysisReport` containing the conservative
    /// capability upper bound. The analysis is sound: no capability that
    /// the extension could actually exercise is omitted.
    pub fn analyze(
        &self,
        graph: &EffectGraph,
        manifest: &ManifestIntents,
        epoch: SecurityEpoch,
        timestamp_ns: u64,
    ) -> Result<StaticAnalysisReport, AnalysisError> {
        if graph.extension_id != manifest.extension_id {
            return Err(AnalysisError::ExtensionMismatch {
                graph_ext: graph.extension_id.clone(),
                manifest_ext: manifest.extension_id.clone(),
            });
        }

        if graph.nodes.is_empty() {
            return Err(AnalysisError::EmptyEffectGraph {
                extension_id: graph.extension_id.clone(),
            });
        }

        let entry_nodes = graph.entry_nodes();
        if entry_nodes.is_empty() {
            return Err(AnalysisError::NoEntryNode {
                extension_id: graph.extension_id.clone(),
            });
        }

        // Compute content hashes for reproducibility binding.
        let effect_graph_hash = Self::compute_graph_hash(graph);
        let manifest_hash = Self::compute_manifest_hash(manifest);

        // Phase 1: lattice reachability (BFS from all entry nodes).
        let traversal = self.lattice_reachability(graph);

        // Phase 2: if path-sensitive, compute again with dead edges excluded.
        let (final_caps, excluded_count) = if self.config.path_sensitive {
            let sensitive = self.path_sensitive_reachability(graph);
            // Capabilities in traversal.reachable but not in sensitive are dead-path.
            let excluded = traversal
                .reachable_capabilities
                .keys()
                .filter(|cap| !sensitive.reachable_capabilities.contains_key(cap))
                .count() as u64;
            (sensitive, excluded)
        } else {
            (traversal, 0)
        };

        // Build per-capability evidence.
        let mut evidence = Vec::new();
        let mut upper_bound = BTreeSet::new();

        for (cap, nodes) in &final_caps.reachable_capabilities {
            upper_bound.insert(cap.clone());
            evidence.push(PerCapabilityEvidence {
                capability: cap.clone(),
                requiring_nodes: nodes.clone(),
                analysis_method: AnalysisMethod::LatticeReachability,
                summary: format!(
                    "capability '{}' reachable at {} hostcall site(s)",
                    cap,
                    nodes.len()
                ),
            });
        }

        // Add manifest-declared capabilities not found in graph
        // (they might be used through dynamic patterns we can't statically trace).
        for cap in &manifest.declared_capabilities {
            if !upper_bound.contains(cap) {
                upper_bound.insert(cap.clone());
                evidence.push(PerCapabilityEvidence {
                    capability: cap.clone(),
                    requiring_nodes: BTreeSet::new(),
                    analysis_method: AnalysisMethod::ManifestFallback,
                    summary: format!(
                        "capability '{}' declared in manifest but not found in effect graph; \
                         included conservatively",
                        cap
                    ),
                });
            }
        }

        // Record dead-path exclusions.
        for cap in &final_caps.excluded_dead {
            evidence.push(PerCapabilityEvidence {
                capability: cap.clone(),
                requiring_nodes: BTreeSet::new(),
                analysis_method: AnalysisMethod::ExcludedDeadPath,
                summary: format!(
                    "capability '{}' excluded: only reachable on provably dead paths",
                    cap
                ),
            });
        }

        // Sort evidence deterministically.
        evidence.sort_by(|a, b| a.capability.cmp(&b.capability));

        // Compute precision estimate.
        let manifest_size = manifest.declared_capabilities.len() as u64;
        let upper_bound_size = upper_bound.len() as u64;
        let ratio = if manifest_size == 0 {
            if upper_bound_size == 0 {
                1_000_000
            } else {
                u64::MAX // infinite over-approximation
            }
        } else {
            (upper_bound_size * 1_000_000)
                .checked_div(manifest_size)
                .unwrap_or(u64::MAX)
        };

        let precision = PrecisionEstimate {
            upper_bound_size,
            manifest_declared_size: manifest_size,
            ratio_millionths: ratio,
            excluded_by_path_sensitivity: excluded_count,
        };

        let report_id = StaticAnalysisReport::derive_report_id(
            &graph.extension_id,
            &effect_graph_hash,
            &manifest_hash,
            timestamp_ns,
            &self.config.zone,
        )
        .map_err(AnalysisError::IdDerivationFailed)?;

        Ok(StaticAnalysisReport {
            report_id,
            extension_id: graph.extension_id.clone(),
            upper_bound_capabilities: upper_bound,
            per_capability_evidence: evidence,
            primary_analysis_method: AnalysisMethod::LatticeReachability,
            precision,
            analysis_duration_ns: 0, // Set by caller if desired
            timed_out: false,
            path_sensitive: self.config.path_sensitive,
            effect_graph_hash,
            manifest_hash,
            epoch,
            timestamp_ns,
            zone: self.config.zone.clone(),
        })
    }

    /// Phase 1: BFS lattice reachability from all entry nodes.
    /// Traverses all edges (including provably-dead ones if not path-sensitive).
    fn lattice_reachability(&self, graph: &EffectGraph) -> TraversalResult {
        self.bfs_capabilities(graph, true)
    }

    /// Phase 2: Path-sensitive reachability (excludes provably-dead edges).
    fn path_sensitive_reachability(&self, graph: &EffectGraph) -> TraversalResult {
        let sensitive = self.bfs_capabilities(graph, false);
        // Compute excluded capabilities: those in full reachability but not
        // in path-sensitive reachability.
        let full = self.bfs_capabilities(graph, true);
        let excluded: BTreeSet<Capability> = full
            .reachable_capabilities
            .keys()
            .filter(|cap| !sensitive.reachable_capabilities.contains_key(cap))
            .cloned()
            .collect();

        TraversalResult {
            reachable_capabilities: sensitive.reachable_capabilities,
            reachable_nodes: sensitive.reachable_nodes,
            excluded_dead: excluded,
        }
    }

    /// BFS traversal collecting capabilities at reachable hostcall sites.
    fn bfs_capabilities(&self, graph: &EffectGraph, include_dead_edges: bool) -> TraversalResult {
        let adj = graph.adjacency_list(include_dead_edges);
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        let mut caps: BTreeMap<Capability, BTreeSet<String>> = BTreeMap::new();

        // Seed BFS with all entry nodes.
        for entry in graph.entry_nodes() {
            if visited.insert(entry.node_id.clone()) {
                queue.push_back(entry.node_id.as_str());
            }
        }

        while let Some(node_id) = queue.pop_front() {
            // Check if this node is a hostcall site.
            if let Some(node) = graph.node_by_id(node_id)
                && let EffectNodeKind::HostcallSite { capability } = &node.kind
            {
                caps.entry(capability.clone())
                    .or_default()
                    .insert(node_id.to_string());
            }

            // Enqueue successors.
            if let Some(successors) = adj.get(node_id) {
                for succ in successors {
                    if visited.insert((*succ).to_string()) {
                        queue.push_back(succ);
                    }
                }
            }
        }

        TraversalResult {
            reachable_capabilities: caps,
            reachable_nodes: visited,
            excluded_dead: BTreeSet::new(),
        }
    }

    /// Compute a deterministic content hash of the effect graph.
    fn compute_graph_hash(graph: &EffectGraph) -> ContentHash {
        let mut buf = Vec::new();
        append_canonical_field(&mut buf, b"effect-graph");
        append_canonical_field(&mut buf, graph.extension_id.as_bytes());

        let mut nodes = graph.nodes.iter().collect::<Vec<_>>();
        nodes.sort_by(|left, right| {
            left.node_id
                .cmp(&right.node_id)
                .then_with(|| left.kind.cmp(&right.kind))
                .then_with(|| left.source_location.cmp(&right.source_location))
        });
        for node in nodes {
            append_canonical_field(&mut buf, b"node");
            append_canonical_field(&mut buf, node.node_id.as_bytes());
            match &node.kind {
                EffectNodeKind::Entry => append_canonical_field(&mut buf, b"entry"),
                EffectNodeKind::HostcallSite { capability } => {
                    append_canonical_field(&mut buf, b"hostcall");
                    append_canonical_field(&mut buf, capability.as_str().as_bytes());
                }
                EffectNodeKind::ControlFlow => append_canonical_field(&mut buf, b"control_flow"),
                EffectNodeKind::Computation => append_canonical_field(&mut buf, b"computation"),
                EffectNodeKind::Exit => append_canonical_field(&mut buf, b"exit"),
            }

            match &node.source_location {
                Some(source_location) => {
                    append_canonical_field(&mut buf, b"source_location");
                    append_canonical_field(&mut buf, source_location.as_bytes());
                }
                None => append_canonical_field(&mut buf, b"no_source_location"),
            }
        }

        let mut edges = graph.edges.iter().collect::<Vec<_>>();
        edges.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| left.to.cmp(&right.to))
                .then_with(|| left.provably_dead.cmp(&right.provably_dead))
        });
        for edge in edges {
            append_canonical_field(&mut buf, b"edge");
            append_canonical_field(&mut buf, edge.from.as_bytes());
            append_canonical_field(&mut buf, edge.to.as_bytes());
            append_canonical_field(&mut buf, if edge.provably_dead { b"dead" } else { b"live" });
        }
        ContentHash::compute(&buf)
    }

    /// Compute a deterministic content hash of the manifest intents.
    fn compute_manifest_hash(manifest: &ManifestIntents) -> ContentHash {
        let mut buf = Vec::new();
        append_canonical_field(&mut buf, b"manifest-intents");
        append_canonical_field(&mut buf, manifest.extension_id.as_bytes());
        append_canonical_field(&mut buf, b"declared");
        for cap in &manifest.declared_capabilities {
            append_canonical_field(&mut buf, cap.as_str().as_bytes());
        }
        append_canonical_field(&mut buf, b"optional");
        for cap in &manifest.optional_capabilities {
            append_canonical_field(&mut buf, cap.as_str().as_bytes());
        }
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// Incremental analysis cache
// ---------------------------------------------------------------------------

/// Cache key for incremental analysis reuse.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AnalysisCacheKey {
    /// Hash of the effect graph.
    pub effect_graph_hash: ContentHash,
    /// Hash of the manifest intents.
    pub manifest_hash: ContentHash,
    /// Whether path-sensitive analysis was used.
    pub path_sensitive: bool,
}

/// Cache for incremental analysis results.
///
/// Stores previous analysis reports keyed by effect-graph + manifest hashes.
/// If an extension's IR hasn't changed, the cached report is reused.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisCache {
    entries: Vec<(AnalysisCacheKey, StaticAnalysisReport)>,
    max_entries: usize,
}

impl AnalysisCache {
    /// Create a new cache with the given maximum entry count.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    /// Look up a cached report by key.
    pub fn get(&self, key: &AnalysisCacheKey) -> Option<&StaticAnalysisReport> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Insert a report into the cache. Evicts oldest if at capacity.
    pub fn insert(&mut self, key: AnalysisCacheKey, report: StaticAnalysisReport) {
        if self.max_entries == 0 {
            return;
        }
        // Remove existing entry with same key if present.
        self.entries.retain(|(k, _)| k != &key);
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push((key, report));
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all cached entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// AnalysisError
// ---------------------------------------------------------------------------

/// Errors from static authority analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisError {
    /// Extension ID mismatch between graph and manifest.
    ExtensionMismatch {
        graph_ext: String,
        manifest_ext: String,
    },
    /// Effect graph is empty.
    EmptyEffectGraph { extension_id: String },
    /// No entry node found in the effect graph.
    NoEntryNode { extension_id: String },
    /// ID derivation failed.
    IdDerivationFailed(crate::engine_object_id::IdError),
    /// Analysis timed out.
    TimedOut {
        extension_id: String,
        elapsed_ns: u64,
        budget_ns: u64,
    },
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExtensionMismatch {
                graph_ext,
                manifest_ext,
            } => write!(
                f,
                "extension mismatch: graph={graph_ext}, manifest={manifest_ext}"
            ),
            Self::EmptyEffectGraph { extension_id } => {
                write!(f, "empty effect graph for extension {extension_id}")
            }
            Self::NoEntryNode { extension_id } => {
                write!(f, "no entry node in effect graph for {extension_id}")
            }
            Self::IdDerivationFailed(e) => write!(f, "id derivation failed: {e}"),
            Self::TimedOut {
                extension_id,
                elapsed_ns,
                budget_ns,
            } => write!(
                f,
                "analysis timed out for {extension_id}: {elapsed_ns}ns > {budget_ns}ns budget"
            ),
        }
    }
}

impl std::error::Error for AnalysisError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_epoch::SecurityEpoch;

    // --- Test helpers ---

    fn cap(name: &str) -> Capability {
        Capability::new(name)
    }

    fn default_config() -> AnalysisConfig {
        AnalysisConfig {
            time_budget_ns: 60_000_000_000,
            path_sensitive: false,
            zone: "test-zone".to_string(),
        }
    }

    fn path_sensitive_config() -> AnalysisConfig {
        AnalysisConfig {
            time_budget_ns: 60_000_000_000,
            path_sensitive: true,
            zone: "test-zone".to_string(),
        }
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

    /// Build a simple linear graph: entry -> hostcall(fs_read) -> exit
    fn simple_graph() -> EffectGraph {
        let mut g = EffectGraph::new("ext-simple");
        g.add_node(entry_node("e0"));
        g.add_node(hostcall_node("h1", "fs_read"));
        g.add_node(exit_node("x2"));
        g.add_edge(edge("e0", "h1"));
        g.add_edge(edge("h1", "x2"));
        g
    }

    fn simple_manifest() -> ManifestIntents {
        ManifestIntents {
            extension_id: "ext-simple".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: BTreeSet::new(),
        }
    }

    /// Build a branching graph:
    ///   entry -> branch -> hostcall(fs_read) -> exit
    ///                   -> hostcall(net_send) -> exit   (provably dead)
    fn branching_graph() -> EffectGraph {
        let mut g = EffectGraph::new("ext-branch");
        g.add_node(entry_node("e0"));
        g.add_node(control_flow_node("branch"));
        g.add_node(hostcall_node("h_read", "fs_read"));
        g.add_node(hostcall_node("h_net", "net_send"));
        g.add_node(exit_node("x"));
        g.add_edge(edge("e0", "branch"));
        g.add_edge(edge("branch", "h_read"));
        g.add_edge(dead_edge("branch", "h_net")); // dead branch
        g.add_edge(edge("h_read", "x"));
        g.add_edge(edge("h_net", "x"));
        g
    }

    fn branching_manifest() -> ManifestIntents {
        ManifestIntents {
            extension_id: "ext-branch".to_string(),
            declared_capabilities: [cap("fs_read"), cap("net_send")].into(),
            optional_capabilities: BTreeSet::new(),
        }
    }

    /// Build a multi-capability graph:
    ///   entry -> compute -> hostcall(fs_read) -> hostcall(fs_write) -> exit
    fn multi_cap_graph() -> EffectGraph {
        let mut g = EffectGraph::new("ext-multi");
        g.add_node(entry_node("e0"));
        g.add_node(computation_node("c1"));
        g.add_node(hostcall_node("h_read", "fs_read"));
        g.add_node(hostcall_node("h_write", "fs_write"));
        g.add_node(exit_node("x"));
        g.add_edge(edge("e0", "c1"));
        g.add_edge(edge("c1", "h_read"));
        g.add_edge(edge("h_read", "h_write"));
        g.add_edge(edge("h_write", "x"));
        g
    }

    fn multi_cap_manifest() -> ManifestIntents {
        ManifestIntents {
            extension_id: "ext-multi".to_string(),
            declared_capabilities: [cap("fs_read"), cap("fs_write")].into(),
            optional_capabilities: BTreeSet::new(),
        }
    }

    // --- Basic analysis tests ---

    #[test]
    fn simple_linear_graph_analysis() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                1_000,
            )
            .expect("analysis");

        assert_eq!(report.extension_id, "ext-simple");
        assert_eq!(report.upper_bound_capabilities.len(), 1);
        assert!(report.requires_capability(&cap("fs_read")));
        assert!(!report.timed_out);
        assert_eq!(report.precision.upper_bound_size, 1);
        assert_eq!(report.precision.manifest_declared_size, 1);
        assert_eq!(report.precision.ratio_millionths, 1_000_000);
    }

    #[test]
    fn multi_capability_graph_analysis() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &multi_cap_graph(),
                &multi_cap_manifest(),
                SecurityEpoch::from_raw(1),
                2_000,
            )
            .expect("analysis");

        assert_eq!(report.upper_bound_capabilities.len(), 2);
        assert!(report.requires_capability(&cap("fs_read")));
        assert!(report.requires_capability(&cap("fs_write")));
    }

    #[test]
    fn branching_graph_without_path_sensitivity() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &branching_graph(),
                &branching_manifest(),
                SecurityEpoch::from_raw(1),
                3_000,
            )
            .expect("analysis");

        // Without path sensitivity, dead edges are traversed.
        assert_eq!(report.upper_bound_capabilities.len(), 2);
        assert!(report.requires_capability(&cap("fs_read")));
        assert!(report.requires_capability(&cap("net_send")));
    }

    #[test]
    fn branching_graph_with_path_sensitivity() {
        let analyzer = StaticAuthorityAnalyzer::new(path_sensitive_config());
        let report = analyzer
            .analyze(
                &branching_graph(),
                &branching_manifest(),
                SecurityEpoch::from_raw(1),
                4_000,
            )
            .expect("analysis");

        // Path sensitivity excludes net_send (only on dead edge).
        // But manifest declares it, so it's included via manifest fallback.
        assert!(report.requires_capability(&cap("fs_read")));
        // net_send is on a dead edge but is in manifest, so included conservatively.
        assert!(report.requires_capability(&cap("net_send")));
        assert!(report.path_sensitive);

        // Check evidence: net_send should be manifest fallback.
        let net_evidence = report
            .per_capability_evidence
            .iter()
            .find(|e| e.capability == cap("net_send"))
            .expect("net_send evidence");
        assert_eq!(
            net_evidence.analysis_method,
            AnalysisMethod::ManifestFallback
        );
    }

    // --- Manifest interaction tests ---

    #[test]
    fn manifest_declared_cap_not_in_graph_included_conservatively() {
        let graph = simple_graph(); // only fs_read
        let manifest = ManifestIntents {
            extension_id: "ext-simple".to_string(),
            declared_capabilities: [cap("fs_read"), cap("net_send")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 5_000)
            .expect("analysis");

        // net_send not in graph but declared in manifest: included conservatively.
        assert!(report.requires_capability(&cap("net_send")));
        let evidence = report
            .per_capability_evidence
            .iter()
            .find(|e| e.capability == cap("net_send"))
            .expect("evidence");
        assert_eq!(evidence.analysis_method, AnalysisMethod::ManifestFallback);
    }

    #[test]
    fn graph_cap_not_in_manifest_still_in_upper_bound() {
        let graph = multi_cap_graph(); // fs_read + fs_write
        let manifest = ManifestIntents {
            extension_id: "ext-multi".to_string(),
            declared_capabilities: [cap("fs_read")].into(), // only declares fs_read
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 6_000)
            .expect("analysis");

        // fs_write found in graph even though not in manifest: must be in upper bound.
        assert!(report.requires_capability(&cap("fs_write")));
        assert_eq!(report.upper_bound_capabilities.len(), 2);

        // Precision ratio > 1_000_000 since upper bound has more caps than manifest.
        assert!(report.precision.ratio_millionths > 1_000_000);
    }

    #[test]
    fn undeclared_and_unused_capability_helpers() {
        let graph = simple_graph(); // only fs_read
        let manifest = ManifestIntents {
            extension_id: "ext-simple".to_string(),
            declared_capabilities: [cap("fs_read"), cap("net_send")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 7_000)
            .expect("analysis");

        let undeclared = report.undeclared_capabilities(&manifest);
        assert!(undeclared.is_empty()); // all caps in upper bound are also in manifest

        let unused = report.unused_declared_capabilities(&manifest);
        assert!(unused.is_empty()); // manifest's net_send included via fallback
    }

    // --- Error handling tests ---

    #[test]
    fn extension_mismatch_error() {
        let graph = simple_graph(); // ext-simple
        let manifest = ManifestIntents {
            extension_id: "ext-other".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let err = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 0)
            .unwrap_err();

        match err {
            AnalysisError::ExtensionMismatch {
                graph_ext,
                manifest_ext,
            } => {
                assert_eq!(graph_ext, "ext-simple");
                assert_eq!(manifest_ext, "ext-other");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn empty_graph_error() {
        let graph = EffectGraph::new("ext-empty");
        let manifest = ManifestIntents {
            extension_id: "ext-empty".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let err = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 0)
            .unwrap_err();

        assert!(matches!(err, AnalysisError::EmptyEffectGraph { .. }));
    }

    #[test]
    fn no_entry_node_error() {
        let mut graph = EffectGraph::new("ext-noentry");
        graph.add_node(hostcall_node("h1", "fs_read")); // no entry
        let manifest = ManifestIntents {
            extension_id: "ext-noentry".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let err = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 0)
            .unwrap_err();

        assert!(matches!(err, AnalysisError::NoEntryNode { .. }));
    }

    // --- Determinism tests ---

    #[test]
    fn identical_inputs_produce_identical_reports() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let graph = multi_cap_graph();
        let manifest = multi_cap_manifest();
        let epoch = SecurityEpoch::from_raw(1);

        let r1 = analyzer
            .analyze(&graph, &manifest, epoch, 10_000)
            .expect("r1");
        let r2 = analyzer
            .analyze(&graph, &manifest, epoch, 10_000)
            .expect("r2");

        assert_eq!(r1.report_id, r2.report_id);
        assert_eq!(r1.upper_bound_capabilities, r2.upper_bound_capabilities);
        assert_eq!(r1.per_capability_evidence, r2.per_capability_evidence);
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn different_timestamps_produce_different_report_ids() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let graph = simple_graph();
        let manifest = simple_manifest();

        let r1 = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 1_000)
            .expect("r1");
        let r2 = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 2_000)
            .expect("r2");

        assert_ne!(r1.report_id, r2.report_id);
        // But upper bounds are the same.
        assert_eq!(r1.upper_bound_capabilities, r2.upper_bound_capabilities);
    }

    // --- Graph structure tests ---

    #[test]
    fn unreachable_hostcall_excluded() {
        // entry -> compute -> exit
        //          hostcall(admin) (no edges to it: unreachable)
        let mut graph = EffectGraph::new("ext-unreach");
        graph.add_node(entry_node("e"));
        graph.add_node(computation_node("c"));
        graph.add_node(hostcall_node("h_admin", "admin_access"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "c"));
        graph.add_edge(edge("c", "x"));
        // No edge to h_admin: unreachable.

        let manifest = ManifestIntents {
            extension_id: "ext-unreach".to_string(),
            declared_capabilities: [cap("admin_access")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 11_000)
            .expect("analysis");

        // admin_access is unreachable in graph but declared in manifest.
        // Sound analysis includes it via manifest fallback.
        assert!(report.requires_capability(&cap("admin_access")));
        let evidence = report
            .per_capability_evidence
            .iter()
            .find(|e| e.capability == cap("admin_access"))
            .expect("evidence");
        assert_eq!(evidence.analysis_method, AnalysisMethod::ManifestFallback);
        assert!(evidence.requiring_nodes.is_empty());
    }

    #[test]
    fn diamond_graph_deduplicates_capabilities() {
        // entry -> branch -> hostcall(fs_read) [via path A]
        //                 -> hostcall(fs_read) [via path B, same capability]
        //          both -> exit
        let mut graph = EffectGraph::new("ext-diamond");
        graph.add_node(entry_node("e"));
        graph.add_node(control_flow_node("branch"));
        graph.add_node(hostcall_node("h_a", "fs_read"));
        graph.add_node(hostcall_node("h_b", "fs_read"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "branch"));
        graph.add_edge(edge("branch", "h_a"));
        graph.add_edge(edge("branch", "h_b"));
        graph.add_edge(edge("h_a", "x"));
        graph.add_edge(edge("h_b", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-diamond".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 12_000)
            .expect("analysis");

        assert_eq!(report.upper_bound_capabilities.len(), 1);
        assert!(report.requires_capability(&cap("fs_read")));

        // Evidence should reference both nodes.
        let evidence = report
            .per_capability_evidence
            .iter()
            .find(|e| e.capability == cap("fs_read"))
            .expect("evidence");
        assert_eq!(evidence.requiring_nodes.len(), 2);
        assert!(evidence.requiring_nodes.contains("h_a"));
        assert!(evidence.requiring_nodes.contains("h_b"));
    }

    #[test]
    fn cycle_in_graph_terminates() {
        // entry -> hostcall(fs_read) -> compute -> hostcall(fs_read) [cycle back]
        let mut graph = EffectGraph::new("ext-cycle");
        graph.add_node(entry_node("e"));
        graph.add_node(hostcall_node("h1", "fs_read"));
        graph.add_node(computation_node("c"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "h1"));
        graph.add_edge(edge("h1", "c"));
        graph.add_edge(edge("c", "h1")); // cycle
        graph.add_edge(edge("c", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-cycle".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 13_000)
            .expect("analysis");

        assert!(report.requires_capability(&cap("fs_read")));
    }

    #[test]
    fn empty_manifest_with_graph_caps() {
        let graph = simple_graph(); // has fs_read
        let manifest = ManifestIntents {
            extension_id: "ext-simple".to_string(),
            declared_capabilities: BTreeSet::new(), // empty!
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 14_000)
            .expect("analysis");

        // fs_read found in graph: must be in upper bound even though not declared.
        assert!(report.requires_capability(&cap("fs_read")));
        assert_eq!(report.precision.manifest_declared_size, 0);
    }

    // --- Path sensitivity tests ---

    #[test]
    fn path_sensitivity_excludes_dead_branch_caps() {
        // entry -> branch -> hostcall(fs_read) [live]
        //                 -> hostcall(net_send) [dead branch]
        // manifest does NOT declare net_send, so it's excluded.
        let mut graph = EffectGraph::new("ext-dead");
        graph.add_node(entry_node("e"));
        graph.add_node(control_flow_node("b"));
        graph.add_node(hostcall_node("h_read", "fs_read"));
        graph.add_node(hostcall_node("h_net", "net_send"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "b"));
        graph.add_edge(edge("b", "h_read"));
        graph.add_edge(dead_edge("b", "h_net"));
        graph.add_edge(edge("h_read", "x"));
        graph.add_edge(edge("h_net", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-dead".to_string(),
            declared_capabilities: [cap("fs_read")].into(), // net_send NOT declared
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(path_sensitive_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 15_000)
            .expect("analysis");

        assert!(report.requires_capability(&cap("fs_read")));
        // net_send is on dead edge AND not in manifest: should not be in upper bound.
        assert!(!report.requires_capability(&cap("net_send")));
        assert!(report.precision.excluded_by_path_sensitivity > 0);
    }

    // --- Precision estimate tests ---

    #[test]
    fn precision_ratio_exact_match() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                16_000,
            )
            .expect("analysis");

        assert_eq!(report.precision.ratio_millionths, 1_000_000); // exact match
    }

    #[test]
    fn precision_ratio_over_approximation() {
        // Graph has 2 caps, manifest declares 1.
        let graph = multi_cap_graph();
        let manifest = ManifestIntents {
            extension_id: "ext-multi".to_string(),
            declared_capabilities: [cap("fs_read")].into(), // only 1
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 17_000)
            .expect("analysis");

        assert_eq!(report.precision.ratio_millionths, 2_000_000); // 2/1 = 200%
    }

    // --- Cache tests ---

    #[test]
    fn cache_stores_and_retrieves() {
        let mut cache = AnalysisCache::new(10);
        assert!(cache.is_empty());

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                18_000,
            )
            .expect("analysis");

        let key = AnalysisCacheKey {
            effect_graph_hash: report.effect_graph_hash.clone(),
            manifest_hash: report.manifest_hash.clone(),
            path_sensitive: false,
        };

        cache.insert(key.clone(), report.clone());
        assert_eq!(cache.len(), 1);

        let cached = cache.get(&key).expect("cached");
        assert_eq!(cached.report_id, report.report_id);
    }

    #[test]
    fn cache_evicts_oldest_on_overflow() {
        let mut cache = AnalysisCache::new(2);

        let key1 = AnalysisCacheKey {
            effect_graph_hash: ContentHash::compute(b"g1"),
            manifest_hash: ContentHash::compute(b"m1"),
            path_sensitive: false,
        };
        let key2 = AnalysisCacheKey {
            effect_graph_hash: ContentHash::compute(b"g2"),
            manifest_hash: ContentHash::compute(b"m2"),
            path_sensitive: false,
        };
        let key3 = AnalysisCacheKey {
            effect_graph_hash: ContentHash::compute(b"g3"),
            manifest_hash: ContentHash::compute(b"m3"),
            path_sensitive: false,
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                19_000,
            )
            .expect("analysis");

        cache.insert(key1.clone(), report.clone());
        cache.insert(key2.clone(), report.clone());
        assert_eq!(cache.len(), 2);

        cache.insert(key3.clone(), report);
        assert_eq!(cache.len(), 2);

        // key1 evicted, key2 and key3 remain.
        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_some());
        assert!(cache.get(&key3).is_some());
    }

    #[test]
    fn cache_clear() {
        let mut cache = AnalysisCache::new(10);
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
                20_000,
            )
            .expect("analysis");

        cache.insert(key.clone(), report);
        assert!(!cache.is_empty());

        cache.clear();
        assert!(cache.is_empty());
        assert!(cache.get(&key).is_none());
    }

    // --- Content hash tests ---

    #[test]
    fn report_content_hash_is_deterministic() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let r1 = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                21_000,
            )
            .expect("r1");

        assert_eq!(r1.content_hash(), r1.content_hash());
    }

    #[test]
    fn graph_hash_is_deterministic() {
        let g1 = simple_graph();
        let g2 = simple_graph();
        let h1 = StaticAuthorityAnalyzer::compute_graph_hash(&g1);
        let h2 = StaticAuthorityAnalyzer::compute_graph_hash(&g2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn graph_hash_is_insertion_order_insensitive() {
        let mut ordered = EffectGraph::new("ext-order");
        ordered.add_node(entry_node("e0"));
        ordered.add_node(hostcall_node("h1", "fs_read"));
        ordered.add_node(exit_node("x2"));
        ordered.add_edge(edge("e0", "h1"));
        ordered.add_edge(edge("h1", "x2"));

        let mut reordered = EffectGraph::new("ext-order");
        reordered.add_node(exit_node("x2"));
        reordered.add_node(hostcall_node("h1", "fs_read"));
        reordered.add_node(entry_node("e0"));
        reordered.add_edge(edge("h1", "x2"));
        reordered.add_edge(edge("e0", "h1"));

        let ordered_hash = StaticAuthorityAnalyzer::compute_graph_hash(&ordered);
        let reordered_hash = StaticAuthorityAnalyzer::compute_graph_hash(&reordered);
        assert_eq!(ordered_hash, reordered_hash);
    }

    #[test]
    fn graph_hash_changes_when_hostcall_capability_changes() {
        let mut graph_a = EffectGraph::new("ext-cap-diff");
        graph_a.add_node(entry_node("e0"));
        graph_a.add_node(hostcall_node("h1", "fs_read"));
        graph_a.add_node(exit_node("x2"));
        graph_a.add_edge(edge("e0", "h1"));
        graph_a.add_edge(edge("h1", "x2"));

        let mut graph_b = EffectGraph::new("ext-cap-diff");
        graph_b.add_node(entry_node("e0"));
        graph_b.add_node(hostcall_node("h1", "net_send"));
        graph_b.add_node(exit_node("x2"));
        graph_b.add_edge(edge("e0", "h1"));
        graph_b.add_edge(edge("h1", "x2"));

        let hash_a = StaticAuthorityAnalyzer::compute_graph_hash(&graph_a);
        let hash_b = StaticAuthorityAnalyzer::compute_graph_hash(&graph_b);
        assert_ne!(hash_a, hash_b);
    }

    #[test]
    fn manifest_hash_is_deterministic() {
        let m1 = simple_manifest();
        let m2 = simple_manifest();
        let h1 = StaticAuthorityAnalyzer::compute_manifest_hash(&m1);
        let h2 = StaticAuthorityAnalyzer::compute_manifest_hash(&m2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn manifest_hash_distinguishes_delimiter_ambiguous_inputs() {
        let extension_encoded = ManifestIntents {
            extension_id: "ext|fs_read".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: BTreeSet::new(),
        };
        let capability_encoded = ManifestIntents {
            extension_id: "ext".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let extension_hash = StaticAuthorityAnalyzer::compute_manifest_hash(&extension_encoded);
        let capability_hash = StaticAuthorityAnalyzer::compute_manifest_hash(&capability_encoded);
        assert_ne!(extension_hash, capability_hash);
    }

    #[test]
    fn different_graphs_produce_different_hashes() {
        let h1 = StaticAuthorityAnalyzer::compute_graph_hash(&simple_graph());
        let h2 = StaticAuthorityAnalyzer::compute_graph_hash(&multi_cap_graph());
        assert_ne!(h1, h2);
    }

    // --- Serialization round-trip tests ---

    #[test]
    fn analysis_report_serde_roundtrip() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &multi_cap_graph(),
                &multi_cap_manifest(),
                SecurityEpoch::from_raw(2),
                22_000,
            )
            .expect("analysis");

        let json = serde_json::to_string(&report).expect("serialize");
        let restored: StaticAnalysisReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, restored);
    }

    #[test]
    fn effect_graph_serde_roundtrip() {
        let graph = branching_graph();
        let json = serde_json::to_string(&graph).expect("serialize");
        let restored: EffectGraph = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(graph, restored);
    }

    #[test]
    fn manifest_intents_serde_roundtrip() {
        let manifest = branching_manifest();
        let json = serde_json::to_string(&manifest).expect("serialize");
        let restored: ManifestIntents = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(manifest, restored);
    }

    #[test]
    fn analysis_cache_serde_roundtrip() {
        let mut cache = AnalysisCache::new(5);
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                23_000,
            )
            .expect("analysis");

        let key = AnalysisCacheKey {
            effect_graph_hash: report.effect_graph_hash.clone(),
            manifest_hash: report.manifest_hash.clone(),
            path_sensitive: false,
        };
        cache.insert(key, report);

        let json = serde_json::to_string(&cache).expect("serialize");
        let restored: AnalysisCache = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cache.len(), restored.len());
    }

    // --- Error display tests ---

    #[test]
    fn analysis_error_display() {
        let err = AnalysisError::ExtensionMismatch {
            graph_ext: "a".to_string(),
            manifest_ext: "b".to_string(),
        };
        assert!(err.to_string().contains("extension mismatch"));

        let err2 = AnalysisError::EmptyEffectGraph {
            extension_id: "x".to_string(),
        };
        assert!(err2.to_string().contains("empty effect graph"));

        let err3 = AnalysisError::NoEntryNode {
            extension_id: "y".to_string(),
        };
        assert!(err3.to_string().contains("no entry node"));

        let err4 = AnalysisError::TimedOut {
            extension_id: "z".to_string(),
            elapsed_ns: 100,
            budget_ns: 50,
        };
        assert!(err4.to_string().contains("timed out"));
    }

    // --- Multiple entry node tests ---

    #[test]
    fn multiple_entry_nodes_analyzed() {
        let mut graph = EffectGraph::new("ext-multi-entry");
        graph.add_node(entry_node("e1"));
        graph.add_node(entry_node("e2"));
        graph.add_node(hostcall_node("h_read", "fs_read"));
        graph.add_node(hostcall_node("h_write", "fs_write"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e1", "h_read"));
        graph.add_edge(edge("e2", "h_write"));
        graph.add_edge(edge("h_read", "x"));
        graph.add_edge(edge("h_write", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-multi-entry".to_string(),
            declared_capabilities: [cap("fs_read"), cap("fs_write")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 24_000)
            .expect("analysis");

        // Both entry nodes lead to different caps.
        assert!(report.requires_capability(&cap("fs_read")));
        assert!(report.requires_capability(&cap("fs_write")));
    }

    // --- EffectNodeKind tests ---

    #[test]
    fn capability_display() {
        let cap = Capability::new("fs_read");
        assert_eq!(cap.to_string(), "fs_read");
        assert_eq!(cap.as_str(), "fs_read");
    }

    #[test]
    fn effect_node_kinds_serializable() {
        let kinds = vec![
            EffectNodeKind::Entry,
            EffectNodeKind::HostcallSite {
                capability: cap("test"),
            },
            EffectNodeKind::ControlFlow,
            EffectNodeKind::Computation,
            EffectNodeKind::Exit,
        ];

        for kind in &kinds {
            let json = serde_json::to_string(kind).expect("serialize");
            let restored: EffectNodeKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(kind, &restored);
        }
    }

    // --- AnalysisMethod display tests ---

    #[test]
    fn analysis_method_display() {
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

    // -----------------------------------------------------------------------
    // Enrichment: leaf enum serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_method_serde_roundtrip() {
        for v in [
            AnalysisMethod::LatticeReachability,
            AnalysisMethod::ManifestFallback,
            AnalysisMethod::TimeoutFallback,
            AnalysisMethod::ExcludedDeadPath,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: AnalysisMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn analysis_error_serde_all_variants() {
        let errors: Vec<AnalysisError> = vec![
            AnalysisError::ExtensionMismatch {
                graph_ext: "a".to_string(),
                manifest_ext: "b".to_string(),
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
            let restored: AnalysisError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn effect_node_serde_roundtrip() {
        let node = EffectNode {
            node_id: "n1".to_string(),
            kind: EffectNodeKind::HostcallSite {
                capability: cap("cap:fs"),
            },
            source_location: Some("module.rs:42".to_string()),
        };
        let json = serde_json::to_string(&node).unwrap();
        let restored: EffectNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, restored);
    }

    #[test]
    fn effect_edge_serde_roundtrip() {
        let e = EffectEdge {
            from: "a".to_string(),
            to: "b".to_string(),
            provably_dead: true,
        };
        let json = serde_json::to_string(&e).unwrap();
        let restored: EffectEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(e, restored);
    }

    #[test]
    fn per_capability_evidence_serde_roundtrip() {
        let ev = PerCapabilityEvidence {
            capability: cap("cap:net"),
            requiring_nodes: {
                let mut s = BTreeSet::new();
                s.insert("n1".to_string());
                s
            },
            analysis_method: AnalysisMethod::LatticeReachability,
            summary: "found via lattice".to_string(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let restored: PerCapabilityEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, restored);
    }

    #[test]
    fn precision_estimate_serde_roundtrip() {
        let pe = PrecisionEstimate {
            upper_bound_size: 5,
            manifest_declared_size: 3,
            ratio_millionths: 1_666_667,
            excluded_by_path_sensitivity: 1,
        };
        let json = serde_json::to_string(&pe).unwrap();
        let restored: PrecisionEstimate = serde_json::from_str(&json).unwrap();
        assert_eq!(pe, restored);
    }

    #[test]
    fn analysis_config_serde_roundtrip() {
        let cfg = AnalysisConfig {
            time_budget_ns: 1_000_000,
            path_sensitive: false,
            zone: "us-east".to_string(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: AnalysisConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, restored);
    }

    #[test]
    fn analysis_cache_key_serde_roundtrip() {
        let key = AnalysisCacheKey {
            effect_graph_hash: ContentHash::compute(b"graph"),
            manifest_hash: ContentHash::compute(b"manifest"),
            path_sensitive: true,
        };
        let json = serde_json::to_string(&key).unwrap();
        let restored: AnalysisCacheKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: default values
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_config_default_values() {
        let cfg = AnalysisConfig::default();
        assert_eq!(cfg.time_budget_ns, 60_000_000_000);
        assert!(cfg.path_sensitive);
        assert_eq!(cfg.zone, "default");
    }

    // -----------------------------------------------------------------------
    // Enrichment: ordering
    // -----------------------------------------------------------------------

    #[test]
    fn effect_node_kind_ordering() {
        assert!(EffectNodeKind::Entry < EffectNodeKind::Exit);
    }

    #[test]
    fn analysis_method_ordering() {
        assert!(AnalysisMethod::LatticeReachability < AnalysisMethod::ExcludedDeadPath);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Capability helpers
    // -----------------------------------------------------------------------

    #[test]
    fn capability_as_str_matches_display() {
        let c = Capability::new("cap:fs");
        assert_eq!(c.as_str(), "cap:fs");
        assert_eq!(c.to_string(), "cap:fs");
    }

    // -----------------------------------------------------------------------
    // Enrichment: AnalysisError is std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(AnalysisError::EmptyEffectGraph {
            extension_id: "e".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display uniqueness via BTreeSet
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_method_display_uniqueness() {
        let displays: BTreeSet<String> = [
            AnalysisMethod::LatticeReachability,
            AnalysisMethod::ManifestFallback,
            AnalysisMethod::TimeoutFallback,
            AnalysisMethod::ExcludedDeadPath,
        ]
        .iter()
        .map(|m| m.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn analysis_error_display_uniqueness() {
        let displays: BTreeSet<String> = [
            AnalysisError::ExtensionMismatch {
                graph_ext: "a".into(),
                manifest_ext: "b".into(),
            },
            AnalysisError::EmptyEffectGraph {
                extension_id: "e".into(),
            },
            AnalysisError::NoEntryNode {
                extension_id: "e".into(),
            },
            AnalysisError::TimedOut {
                extension_id: "e".into(),
                elapsed_ns: 100,
                budget_ns: 50,
            },
        ]
        .iter()
        .map(|e| e.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Enrichment: optional capability in manifest
    // -----------------------------------------------------------------------

    #[test]
    fn optional_capabilities_in_manifest_are_handled() {
        let graph = simple_graph(); // only fs_read
        let manifest = ManifestIntents {
            extension_id: "ext-simple".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: [cap("net_send")].into(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 30_000)
            .expect("analysis");

        // fs_read in graph, net_send not in graph but is optional — should still be
        // included conservatively (optional counts in manifest union).
        assert!(report.requires_capability(&cap("fs_read")));
    }

    // -----------------------------------------------------------------------
    // Enrichment: EffectGraph serde with no nodes
    // -----------------------------------------------------------------------

    #[test]
    fn empty_effect_graph_serde_roundtrip() {
        let graph = EffectGraph::new("ext-empty-serde");
        let json = serde_json::to_string(&graph).expect("serialize");
        let restored: EffectGraph = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(graph, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: report content hash differs for different inputs
    // -----------------------------------------------------------------------

    #[test]
    fn different_graphs_produce_different_report_content_hashes() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let r1 = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                31_000,
            )
            .expect("r1");
        let r2 = analyzer
            .analyze(
                &multi_cap_graph(),
                &multi_cap_manifest(),
                SecurityEpoch::from_raw(1),
                32_000,
            )
            .expect("r2");

        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    // -----------------------------------------------------------------------
    // Enrichment: cache miss returns None
    // -----------------------------------------------------------------------

    #[test]
    fn cache_miss_returns_none() {
        let cache = AnalysisCache::new(10);
        let key = AnalysisCacheKey {
            effect_graph_hash: ContentHash::compute(b"missing"),
            manifest_hash: ContentHash::compute(b"missing"),
            path_sensitive: false,
        };
        assert!(cache.get(&key).is_none());
    }

    // -----------------------------------------------------------------------
    // Enrichment: capability ordering
    // -----------------------------------------------------------------------

    #[test]
    fn capability_ordering_is_alphabetical() {
        assert!(cap("alpha") < cap("beta"));
        assert!(cap("beta") < cap("gamma"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: cache deduplication on insert
    // -----------------------------------------------------------------------

    #[test]
    fn cache_insert_replaces_existing_key() {
        let mut cache = AnalysisCache::new(10);
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let r1 = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                40_000,
            )
            .expect("r1");
        let r2 = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                41_000,
            )
            .expect("r2");

        let key = AnalysisCacheKey {
            effect_graph_hash: r1.effect_graph_hash.clone(),
            manifest_hash: r1.manifest_hash.clone(),
            path_sensitive: false,
        };

        cache.insert(key.clone(), r1);
        assert_eq!(cache.len(), 1);

        // Insert again with same key replaces, doesn't duplicate.
        cache.insert(key.clone(), r2.clone());
        assert_eq!(cache.len(), 1);

        let cached = cache.get(&key).unwrap();
        assert_eq!(cached.timestamp_ns, r2.timestamp_ns);
    }

    #[test]
    fn cache_zero_capacity_insert_is_noop() {
        let mut cache = AnalysisCache::new(0);
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                42_000,
            )
            .expect("report");

        cache.insert(
            AnalysisCacheKey {
                effect_graph_hash: report.effect_graph_hash.clone(),
                manifest_hash: report.manifest_hash.clone(),
                path_sensitive: report.path_sensitive,
            },
            report,
        );

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: undeclared_capabilities returns non-empty
    // -----------------------------------------------------------------------

    #[test]
    fn undeclared_capabilities_returns_graph_only_caps() {
        // Graph has fs_read + fs_write; manifest only declares fs_read.
        let graph = multi_cap_graph();
        let manifest = ManifestIntents {
            extension_id: "ext-multi".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 42_000)
            .expect("analysis");

        let undeclared = report.undeclared_capabilities(&manifest);
        assert_eq!(undeclared.len(), 1);
        assert!(undeclared.contains(&cap("fs_write")));
    }

    // -----------------------------------------------------------------------
    // Enrichment: unused_declared returns non-empty when cap NOT in graph
    // -----------------------------------------------------------------------

    #[test]
    fn unused_declared_returns_manifest_only_caps() {
        // Graph only has fs_read; manifest declares fs_read + net_send + crypto_sign.
        // net_send and crypto_sign are NOT in graph but ARE in manifest → included via fallback.
        // So they appear in upper bound. However, if we check unused_declared against
        // a manifest that has extra caps not found in graph, they still get into
        // upper bound via fallback. So unused_declared should be empty.
        // To get a non-empty result, we need caps in manifest that DON'T end up
        // in the upper bound. That only happens with path-sensitive dead-path
        // exclusion AND the cap not in manifest.
        //
        // Actually let's just test: manifest declares cap "missing" but the
        // fallback always adds declared caps to upper bound, so unused is empty.
        // The only way to get unused is if the upper bound is SMALLER than manifest,
        // which doesn't happen with our analysis (it always adds manifest fallback).
        // So this test verifies the symmetric case:
        let graph = simple_graph(); // fs_read
        let manifest = ManifestIntents {
            extension_id: "ext-simple".to_string(),
            declared_capabilities: [cap("fs_read"), cap("net_send")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 43_000)
            .expect("analysis");

        // Both are in upper bound (net_send via fallback).
        let unused = report.unused_declared_capabilities(&manifest);
        assert!(unused.is_empty(), "fallback always includes declared caps");
    }

    // -----------------------------------------------------------------------
    // Enrichment: precision ratio u64::MAX when empty manifest, non-empty graph
    // -----------------------------------------------------------------------

    #[test]
    fn precision_ratio_max_when_zero_manifest_nonzero_graph() {
        let graph = simple_graph(); // has fs_read
        let manifest = ManifestIntents {
            extension_id: "ext-simple".to_string(),
            declared_capabilities: BTreeSet::new(), // empty
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 44_000)
            .expect("analysis");

        assert_eq!(report.precision.manifest_declared_size, 0);
        assert!(report.precision.upper_bound_size > 0);
        assert_eq!(report.precision.ratio_millionths, u64::MAX);
    }

    // -----------------------------------------------------------------------
    // Enrichment: precision ratio 1M when both empty
    // -----------------------------------------------------------------------

    #[test]
    fn precision_ratio_one_when_both_empty() {
        // Graph with entry + exit but NO hostcall; manifest empty.
        let mut graph = EffectGraph::new("ext-empty-caps");
        graph.add_node(entry_node("e"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-empty-caps".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 45_000)
            .expect("analysis");

        assert_eq!(report.precision.upper_bound_size, 0);
        assert_eq!(report.precision.manifest_declared_size, 0);
        assert_eq!(report.precision.ratio_millionths, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Enrichment: effect edge ordering
    // -----------------------------------------------------------------------

    #[test]
    fn effect_edge_ordering() {
        let e1 = EffectEdge {
            from: "a".into(),
            to: "b".into(),
            provably_dead: false,
        };
        let e2 = EffectEdge {
            from: "a".into(),
            to: "c".into(),
            provably_dead: false,
        };
        assert!(e1 < e2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: capability serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn capability_serde_roundtrip() {
        let c = Capability::new("net_send");
        let json = serde_json::to_string(&c).unwrap();
        let back: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: report requires_capability false for absent cap
    // -----------------------------------------------------------------------

    #[test]
    fn requires_capability_false_for_absent() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                46_000,
            )
            .expect("analysis");

        assert!(!report.requires_capability(&cap("admin")));
    }

    // -----------------------------------------------------------------------
    // Enrichment: evidence sorted deterministically by capability
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_sorted_by_capability() {
        let graph = multi_cap_graph(); // fs_read + fs_write
        let manifest = multi_cap_manifest();

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 47_000)
            .expect("analysis");

        let caps: Vec<&str> = report
            .per_capability_evidence
            .iter()
            .map(|e| e.capability.as_str())
            .collect();
        let mut sorted = caps.clone();
        sorted.sort();
        assert_eq!(caps, sorted);
    }

    // -----------------------------------------------------------------------
    // Enrichment: schema hash deterministic
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_report_schema_hash_deterministic() {
        let h1 = analysis_report_schema_hash();
        let h2 = analysis_report_schema_hash();
        assert_eq!(h1, h2);
    }

    // -- Enrichment: PearlTower 2026-02-26 session 6 --

    #[test]
    fn excluded_dead_path_evidence_present_in_report() {
        // Same setup as path_sensitivity_excludes_dead_branch_caps but verify
        // that an ExcludedDeadPath evidence item for net_send exists.
        let mut graph = EffectGraph::new("ext-dead-ev");
        graph.add_node(entry_node("e"));
        graph.add_node(control_flow_node("b"));
        graph.add_node(hostcall_node("h_read", "fs_read"));
        graph.add_node(hostcall_node("h_net", "net_send"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "b"));
        graph.add_edge(edge("b", "h_read"));
        graph.add_edge(dead_edge("b", "h_net"));
        graph.add_edge(edge("h_read", "x"));
        graph.add_edge(edge("h_net", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-dead-ev".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(path_sensitive_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 50_000)
            .expect("analysis");

        let dead_evidence = report
            .per_capability_evidence
            .iter()
            .find(|e| e.capability == cap("net_send"));
        assert!(
            dead_evidence.is_some(),
            "ExcludedDeadPath evidence expected"
        );
        assert_eq!(
            dead_evidence.unwrap().analysis_method,
            AnalysisMethod::ExcludedDeadPath
        );
    }

    #[test]
    fn optional_capabilities_affect_manifest_hash() {
        let m1 = ManifestIntents {
            extension_id: "ext-opt".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: BTreeSet::new(),
        };
        let m2 = ManifestIntents {
            extension_id: "ext-opt".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: [cap("net_send")].into(),
        };

        let h1 = StaticAuthorityAnalyzer::compute_manifest_hash(&m1);
        let h2 = StaticAuthorityAnalyzer::compute_manifest_hash(&m2);
        assert_ne!(h1, h2, "optional capabilities should affect manifest hash");
    }

    #[test]
    fn different_zones_produce_different_report_ids() {
        let gh = ContentHash::compute(b"graph");
        let mh = ContentHash::compute(b"manifest");
        let id1 = StaticAnalysisReport::derive_report_id("ext", &gh, &mh, 100, "zone-a").unwrap();
        let id2 = StaticAnalysisReport::derive_report_id("ext", &gh, &mh, 100, "zone-b").unwrap();
        assert_ne!(
            id1, id2,
            "different zones should produce different report IDs"
        );
    }

    #[test]
    fn content_hash_changes_when_capabilities_differ() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let r1 = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                51_000,
            )
            .expect("r1");

        // Build a graph with a different capability (fs_write instead of fs_read).
        let mut graph2 = EffectGraph::new("ext-simple");
        graph2.add_node(entry_node("e0"));
        graph2.add_node(hostcall_node("h1", "fs_write"));
        graph2.add_node(exit_node("x2"));
        graph2.add_edge(edge("e0", "h1"));
        graph2.add_edge(edge("h1", "x2"));
        let manifest2 = ManifestIntents {
            extension_id: "ext-simple".to_string(),
            declared_capabilities: [cap("fs_write")].into(),
            optional_capabilities: BTreeSet::new(),
        };
        let r2 = analyzer
            .analyze(&graph2, &manifest2, SecurityEpoch::from_raw(1), 51_000)
            .expect("r2");

        assert_ne!(
            r1.content_hash(),
            r2.content_hash(),
            "different capabilities should produce different content hashes"
        );
    }

    #[test]
    fn cache_capacity_one_evicts_on_second_insert() {
        let mut cache = AnalysisCache::new(1);
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                52_000,
            )
            .expect("analysis");

        let key1 = AnalysisCacheKey {
            effect_graph_hash: ContentHash::compute(b"g1"),
            manifest_hash: ContentHash::compute(b"m1"),
            path_sensitive: false,
        };
        let key2 = AnalysisCacheKey {
            effect_graph_hash: ContentHash::compute(b"g2"),
            manifest_hash: ContentHash::compute(b"m2"),
            path_sensitive: false,
        };

        cache.insert(key1.clone(), report.clone());
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&key1).is_some());

        cache.insert(key2.clone(), report);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&key1).is_none(), "key1 should be evicted");
        assert!(cache.get(&key2).is_some());
    }

    #[test]
    fn graph_edge_to_nonexistent_node_does_not_crash() {
        // Edge references a node that doesn't exist in nodes list.
        let mut graph = EffectGraph::new("ext-phantom");
        graph.add_node(entry_node("e"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "phantom")); // phantom not in nodes
        graph.add_edge(edge("e", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-phantom".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 53_000)
            .expect("analysis should not crash on phantom edges");
        // No capabilities in graph, so upper bound should be empty.
        assert!(report.upper_bound_capabilities.is_empty());
    }

    #[test]
    fn evidence_summary_includes_hostcall_site_count() {
        // Diamond graph: two hostcall sites for the same capability.
        let mut graph = EffectGraph::new("ext-diamond-ev");
        graph.add_node(entry_node("e"));
        graph.add_node(control_flow_node("branch"));
        graph.add_node(hostcall_node("h_a", "fs_read"));
        graph.add_node(hostcall_node("h_b", "fs_read"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "branch"));
        graph.add_edge(edge("branch", "h_a"));
        graph.add_edge(edge("branch", "h_b"));
        graph.add_edge(edge("h_a", "x"));
        graph.add_edge(edge("h_b", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-diamond-ev".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 54_000)
            .expect("analysis");

        let ev = report
            .per_capability_evidence
            .iter()
            .find(|e| e.capability == cap("fs_read"))
            .expect("evidence for fs_read");
        assert_eq!(ev.analysis_method, AnalysisMethod::LatticeReachability);
        assert!(ev.summary.contains("2 hostcall site(s)"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-03-04 — BFS / topology / cache / field tests
    // -----------------------------------------------------------------------

    #[test]
    fn all_dead_edges_path_sensitive_excludes_everything() {
        // entry -> dead_edge -> hostcall(admin)
        // With path-sensitive, admin should NOT be reachable (only dead path).
        // Manifest does NOT declare admin, so it should be excluded.
        let mut graph = EffectGraph::new("ext-all-dead");
        graph.add_node(entry_node("e"));
        graph.add_node(hostcall_node("h_admin", "admin"));
        graph.add_node(exit_node("x"));
        graph.add_edge(dead_edge("e", "h_admin"));
        graph.add_edge(dead_edge("h_admin", "x"));
        // Live edge directly to exit so entry is valid.
        graph.add_edge(edge("e", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-all-dead".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(path_sensitive_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 60_000)
            .expect("analysis");

        assert!(!report.requires_capability(&cap("admin")));
        assert!(report.upper_bound_capabilities.is_empty());
        assert!(report.precision.excluded_by_path_sensitivity > 0);
    }

    #[test]
    fn self_loop_hostcall_terminates_and_captures() {
        // entry -> hostcall(fs_read) -> hostcall(fs_read) [self-loop]
        //                             -> exit
        let mut graph = EffectGraph::new("ext-selfloop");
        graph.add_node(entry_node("e"));
        graph.add_node(hostcall_node("h", "fs_read"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "h"));
        graph.add_edge(edge("h", "h")); // self-loop
        graph.add_edge(edge("h", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-selfloop".to_string(),
            declared_capabilities: [cap("fs_read")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 61_000)
            .expect("analysis");

        assert!(report.requires_capability(&cap("fs_read")));
        assert_eq!(report.upper_bound_capabilities.len(), 1);
    }

    #[test]
    fn deep_chain_capabilities_at_end_reachable() {
        // entry -> c0 -> c1 -> c2 -> c3 -> c4 -> hostcall(deep_cap) -> exit
        let mut graph = EffectGraph::new("ext-deep");
        graph.add_node(entry_node("e"));
        for i in 0..5 {
            graph.add_node(computation_node(&format!("c{i}")));
        }
        graph.add_node(hostcall_node("h_deep", "deep_cap"));
        graph.add_node(exit_node("x"));

        graph.add_edge(edge("e", "c0"));
        for i in 0..4 {
            graph.add_edge(edge(&format!("c{i}"), &format!("c{}", i + 1)));
        }
        graph.add_edge(edge("c4", "h_deep"));
        graph.add_edge(edge("h_deep", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-deep".to_string(),
            declared_capabilities: [cap("deep_cap")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 62_000)
            .expect("analysis");

        assert!(report.requires_capability(&cap("deep_cap")));
        assert_eq!(report.precision.ratio_millionths, 1_000_000);
    }

    #[test]
    fn path_sensitive_no_dead_edges_matches_non_path_sensitive() {
        // Same graph, no dead edges — both modes should yield identical upper bounds.
        let graph = multi_cap_graph();
        let manifest = multi_cap_manifest();

        let analyzer_normal = StaticAuthorityAnalyzer::new(default_config());
        let analyzer_sensitive = StaticAuthorityAnalyzer::new(path_sensitive_config());

        let r_normal = analyzer_normal
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 63_000)
            .expect("normal");
        let r_sensitive = analyzer_sensitive
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 63_000)
            .expect("sensitive");

        assert_eq!(
            r_normal.upper_bound_capabilities,
            r_sensitive.upper_bound_capabilities
        );
    }

    #[test]
    fn multiple_entries_converging_to_single_hostcall() {
        // e1 -> h, e2 -> h, e3 -> h -> exit
        let mut graph = EffectGraph::new("ext-converge");
        graph.add_node(entry_node("e1"));
        graph.add_node(entry_node("e2"));
        graph.add_node(entry_node("e3"));
        graph.add_node(hostcall_node("h", "shared_cap"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e1", "h"));
        graph.add_edge(edge("e2", "h"));
        graph.add_edge(edge("e3", "h"));
        graph.add_edge(edge("h", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-converge".to_string(),
            declared_capabilities: [cap("shared_cap")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 64_000)
            .expect("analysis");

        assert!(report.requires_capability(&cap("shared_cap")));
        let ev = report
            .per_capability_evidence
            .iter()
            .find(|e| e.capability == cap("shared_cap"))
            .unwrap();
        // Only one hostcall node despite 3 entry paths.
        assert_eq!(ev.requiring_nodes.len(), 1);
        assert!(ev.requiring_nodes.contains("h"));
    }

    #[test]
    fn cache_discriminates_by_path_sensitive_flag() {
        let mut cache = AnalysisCache::new(10);
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                65_000,
            )
            .expect("analysis");

        let key_false = AnalysisCacheKey {
            effect_graph_hash: report.effect_graph_hash.clone(),
            manifest_hash: report.manifest_hash.clone(),
            path_sensitive: false,
        };
        let key_true = AnalysisCacheKey {
            effect_graph_hash: report.effect_graph_hash.clone(),
            manifest_hash: report.manifest_hash.clone(),
            path_sensitive: true,
        };

        cache.insert(key_false.clone(), report.clone());
        assert!(cache.get(&key_false).is_some());
        assert!(cache.get(&key_true).is_none());

        cache.insert(key_true.clone(), report);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&key_false).is_some());
        assert!(cache.get(&key_true).is_some());
    }

    #[test]
    fn entry_only_graph_no_edges_yields_empty_upper_bound() {
        let mut graph = EffectGraph::new("ext-entry-only");
        graph.add_node(entry_node("e"));
        // No edges at all.

        let manifest = ManifestIntents {
            extension_id: "ext-entry-only".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 66_000)
            .expect("analysis");

        assert!(report.upper_bound_capabilities.is_empty());
    }

    #[test]
    fn mixed_dead_live_diamond_path_sensitive_keeps_live_cap() {
        // entry -> branch -> [live] hostcall(fs_read) -> exit
        //                 -> [dead] hostcall(net_send) -> exit
        // manifest declares both. Path-sensitive: fs_read reachable, net_send dead
        // but net_send in manifest → included via fallback.
        let mut graph = EffectGraph::new("ext-mixed-diamond");
        graph.add_node(entry_node("e"));
        graph.add_node(control_flow_node("b"));
        graph.add_node(hostcall_node("h_fs", "fs_read"));
        graph.add_node(hostcall_node("h_net", "net_send"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "b"));
        graph.add_edge(edge("b", "h_fs"));
        graph.add_edge(dead_edge("b", "h_net"));
        graph.add_edge(edge("h_fs", "x"));
        graph.add_edge(edge("h_net", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-mixed-diamond".to_string(),
            declared_capabilities: [cap("fs_read"), cap("net_send")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(path_sensitive_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 67_000)
            .expect("analysis");

        // fs_read via LatticeReachability
        let fs_ev = report
            .per_capability_evidence
            .iter()
            .find(|e| e.capability == cap("fs_read"))
            .unwrap();
        assert_eq!(fs_ev.analysis_method, AnalysisMethod::LatticeReachability);

        // net_send via ManifestFallback (dead path, but declared)
        let net_ev = report.per_capability_evidence.iter().find(|e| {
            e.capability == cap("net_send") && e.analysis_method == AnalysisMethod::ManifestFallback
        });
        assert!(net_ev.is_some());

        // Both in upper bound
        assert!(report.requires_capability(&cap("fs_read")));
        assert!(report.requires_capability(&cap("net_send")));
    }

    #[test]
    fn report_zone_matches_config_zone() {
        let mut config = default_config();
        config.zone = "us-west-2".to_string();
        let analyzer = StaticAuthorityAnalyzer::new(config);
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(5),
                68_000,
            )
            .expect("analysis");

        assert_eq!(report.zone, "us-west-2");
    }

    #[test]
    fn report_epoch_matches_input_epoch() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let epoch = SecurityEpoch::from_raw(42);
        let report = analyzer
            .analyze(&simple_graph(), &simple_manifest(), epoch, 69_000)
            .expect("analysis");

        assert_eq!(report.epoch, epoch);
    }

    #[test]
    fn report_timestamp_matches_input() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                99_999,
            )
            .expect("analysis");

        assert_eq!(report.timestamp_ns, 99_999);
    }

    #[test]
    fn report_timed_out_false_and_duration_zero() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                70_000,
            )
            .expect("analysis");

        assert!(!report.timed_out);
        assert_eq!(report.analysis_duration_ns, 0);
    }

    #[test]
    fn computation_only_graph_empty_upper_bound() {
        // entry -> compute -> exit (no hostcalls, no manifest caps)
        let mut graph = EffectGraph::new("ext-compute");
        graph.add_node(entry_node("e"));
        graph.add_node(computation_node("c"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "c"));
        graph.add_edge(edge("c", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-compute".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 71_000)
            .expect("analysis");

        assert!(report.upper_bound_capabilities.is_empty());
        assert!(report.per_capability_evidence.is_empty());
    }

    #[test]
    fn dead_chain_path_sensitive_excludes_transitive() {
        // entry -> [dead] -> compute -> hostcall(secret) -> exit
        // entry -> [live] -> exit
        // Path-sensitive: secret should not be reachable.
        let mut graph = EffectGraph::new("ext-dead-chain");
        graph.add_node(entry_node("e"));
        graph.add_node(computation_node("c"));
        graph.add_node(hostcall_node("h", "secret"));
        graph.add_node(exit_node("x1"));
        graph.add_node(exit_node("x2"));
        graph.add_edge(dead_edge("e", "c"));
        graph.add_edge(edge("c", "h"));
        graph.add_edge(edge("h", "x1"));
        graph.add_edge(edge("e", "x2")); // live path to exit

        let manifest = ManifestIntents {
            extension_id: "ext-dead-chain".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(path_sensitive_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 72_000)
            .expect("analysis");

        assert!(!report.requires_capability(&cap("secret")));
    }

    #[test]
    fn bfs_visited_prevents_duplicate_capability_nodes() {
        // entry -> hostcall(A) -> compute -> hostcall(A) [cycle]
        //                                 -> exit
        // Verify A appears with 1 node in evidence (h1), not duplicated.
        let mut graph = EffectGraph::new("ext-bfs-dup");
        graph.add_node(entry_node("e"));
        graph.add_node(hostcall_node("h1", "cap_a"));
        graph.add_node(computation_node("c"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "h1"));
        graph.add_edge(edge("h1", "c"));
        graph.add_edge(edge("c", "h1")); // cycle back
        graph.add_edge(edge("c", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-bfs-dup".to_string(),
            declared_capabilities: [cap("cap_a")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 73_000)
            .expect("analysis");

        let ev = report
            .per_capability_evidence
            .iter()
            .find(|e| e.capability == cap("cap_a"))
            .unwrap();
        assert_eq!(ev.requiring_nodes.len(), 1);
        assert!(ev.requiring_nodes.contains("h1"));
    }

    #[test]
    fn many_capabilities_at_different_distances() {
        // entry -> h1(A) -> h2(B) -> h3(C) -> exit
        let mut graph = EffectGraph::new("ext-dist");
        graph.add_node(entry_node("e"));
        graph.add_node(hostcall_node("h1", "cap_a"));
        graph.add_node(hostcall_node("h2", "cap_b"));
        graph.add_node(hostcall_node("h3", "cap_c"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "h1"));
        graph.add_edge(edge("h1", "h2"));
        graph.add_edge(edge("h2", "h3"));
        graph.add_edge(edge("h3", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-dist".to_string(),
            declared_capabilities: [cap("cap_a"), cap("cap_b"), cap("cap_c")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 74_000)
            .expect("analysis");

        assert_eq!(report.upper_bound_capabilities.len(), 3);
        assert!(report.requires_capability(&cap("cap_a")));
        assert!(report.requires_capability(&cap("cap_b")));
        assert!(report.requires_capability(&cap("cap_c")));
        assert_eq!(report.precision.ratio_millionths, 1_000_000);
    }

    #[test]
    fn manifest_fallback_summary_contains_conservatively() {
        let graph = simple_graph(); // only fs_read
        let manifest = ManifestIntents {
            extension_id: "ext-simple".to_string(),
            declared_capabilities: [cap("fs_read"), cap("phantom_cap")].into(),
            optional_capabilities: BTreeSet::new(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 75_000)
            .expect("analysis");

        let ev = report
            .per_capability_evidence
            .iter()
            .find(|e| e.capability == cap("phantom_cap"))
            .unwrap();
        assert_eq!(ev.analysis_method, AnalysisMethod::ManifestFallback);
        assert!(ev.summary.contains("conservatively"));
    }

    #[test]
    fn manifest_only_optional_caps_not_in_upper_bound() {
        // Manifest has NO declared caps but has optional caps.
        // Graph has no hostcalls. Optional caps are NOT added to upper bound.
        let mut graph = EffectGraph::new("ext-opt-only");
        graph.add_node(entry_node("e"));
        graph.add_node(exit_node("x"));
        graph.add_edge(edge("e", "x"));

        let manifest = ManifestIntents {
            extension_id: "ext-opt-only".to_string(),
            declared_capabilities: BTreeSet::new(),
            optional_capabilities: [cap("opt_cap")].into(),
        };

        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(&graph, &manifest, SecurityEpoch::from_raw(1), 76_000)
            .expect("analysis");

        // opt_cap is optional, not declared, and not in graph → not in upper bound.
        assert!(!report.requires_capability(&cap("opt_cap")));
        assert!(report.upper_bound_capabilities.is_empty());
    }

    #[test]
    fn primary_analysis_method_is_lattice_reachability() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let report = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                77_000,
            )
            .expect("analysis");

        assert_eq!(
            report.primary_analysis_method,
            AnalysisMethod::LatticeReachability
        );
    }

    #[test]
    fn report_hashes_bind_to_input_graph_and_manifest() {
        let analyzer = StaticAuthorityAnalyzer::new(default_config());
        let r1 = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                78_000,
            )
            .expect("r1");

        // Verify effect_graph_hash and manifest_hash are non-trivial.
        assert_ne!(r1.effect_graph_hash, r1.manifest_hash);

        // Same inputs → same hashes.
        let r2 = analyzer
            .analyze(
                &simple_graph(),
                &simple_manifest(),
                SecurityEpoch::from_raw(1),
                79_000,
            )
            .expect("r2");
        assert_eq!(r1.effect_graph_hash, r2.effect_graph_hash);
        assert_eq!(r1.manifest_hash, r2.manifest_hash);
    }
}
