//! Static dependency, effect, and capability analysis graph.
//!
//! Provides deep static analysis as the primary semantic substrate for
//! no-VDOM lowering:
//! - Component dependency graph
//! - Hook slot graph
//! - Effect / dataflow graph
//! - Capability / effect boundary classification
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//! Collections use BTreeMap/BTreeSet for deterministic iteration.
//!
//! Plan references: FRX-03.2, FRX-03 (Compiler Architecture).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::ir_contract::{CapabilityTag, EffectBoundary};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLION: i64 = 1_000_000;

/// Schema version for static analysis artifacts.
pub const STATIC_ANALYSIS_SCHEMA_VERSION: &str = "franken-engine.static-analysis-graph.v1";

/// Maximum nodes allowed in a single analysis graph.
const MAX_NODES: usize = 100_000;

/// Maximum edges allowed in a single analysis graph.
const MAX_EDGES: usize = 500_000;

/// Maximum hook slots per component.
const MAX_HOOK_SLOTS: usize = 256;

// ---------------------------------------------------------------------------
// ComponentId — typed identifier for a React-like component
// ---------------------------------------------------------------------------

/// Unique identifier for a component in the analysis graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ComponentId(pub String);

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl ComponentId {
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

// ---------------------------------------------------------------------------
// AnalysisNodeId — node identity in the analysis graph
// ---------------------------------------------------------------------------

/// Unique node identifier in the analysis graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AnalysisNodeId(pub String);

impl fmt::Display for AnalysisNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AnalysisNodeId {
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

// ---------------------------------------------------------------------------
// AnalysisEdgeId — edge identity in the analysis graph
// ---------------------------------------------------------------------------

/// Unique edge identifier in the analysis graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AnalysisEdgeId(pub String);

impl fmt::Display for AnalysisEdgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AnalysisEdgeId {
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

// ---------------------------------------------------------------------------
// NodeKind — semantic classification of analysis nodes
// ---------------------------------------------------------------------------

/// Kind of node in the analysis graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    /// A React-like component (function or class).
    Component,
    /// A hook invocation site (useState, useEffect, etc.).
    HookSlot,
    /// An effect boundary (side-effect producing operation).
    EffectSite,
    /// A data source (props, context, external state).
    DataSource,
    /// A data sink (rendered output, state update, network call).
    DataSink,
    /// A module boundary (import/export).
    ModuleBoundary,
    /// A capability gate (requires a specific capability).
    CapabilityGate,
    /// A scope boundary (closure, block, function).
    ScopeBoundary,
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Component => "component",
            Self::HookSlot => "hook_slot",
            Self::EffectSite => "effect_site",
            Self::DataSource => "data_source",
            Self::DataSink => "data_sink",
            Self::ModuleBoundary => "module_boundary",
            Self::CapabilityGate => "capability_gate",
            Self::ScopeBoundary => "scope_boundary",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// EdgeKind — semantic classification of analysis edges
// ---------------------------------------------------------------------------

/// Kind of edge in the analysis graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// Component renders another component.
    RendersChild,
    /// Component passes props to child.
    PropFlow,
    /// Data flows through a hook (state/effect chain).
    HookDataFlow,
    /// Effect depends on a data source.
    EffectDependency,
    /// Import dependency between modules.
    ImportDependency,
    /// Context provider→consumer flow.
    ContextFlow,
    /// Callback / event handler flow.
    CallbackFlow,
    /// Capability requirement edge.
    CapabilityRequirement,
    /// Scope containment (parent→child).
    ScopeContainment,
    /// State update trigger (setState→re-render).
    StateUpdateTrigger,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RendersChild => "renders_child",
            Self::PropFlow => "prop_flow",
            Self::HookDataFlow => "hook_data_flow",
            Self::EffectDependency => "effect_dependency",
            Self::ImportDependency => "import_dependency",
            Self::ContextFlow => "context_flow",
            Self::CallbackFlow => "callback_flow",
            Self::CapabilityRequirement => "capability_requirement",
            Self::ScopeContainment => "scope_containment",
            Self::StateUpdateTrigger => "state_update_trigger",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// HookKind — classification of React hooks
// ---------------------------------------------------------------------------

/// Classification of a hook invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HookKind {
    /// useState or useReducer — state management.
    State,
    /// useEffect — side effect with cleanup.
    Effect,
    /// useLayoutEffect — synchronous layout effect.
    LayoutEffect,
    /// useMemo — memoized computation.
    Memo,
    /// useCallback — memoized callback.
    Callback,
    /// useRef — mutable ref container.
    Ref,
    /// useContext — context consumer.
    Context,
    /// useImperativeHandle — imperative API exposure.
    ImperativeHandle,
    /// Custom hook invocation.
    Custom,
}

impl fmt::Display for HookKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::State => "useState",
            Self::Effect => "useEffect",
            Self::LayoutEffect => "useLayoutEffect",
            Self::Memo => "useMemo",
            Self::Callback => "useCallback",
            Self::Ref => "useRef",
            Self::Context => "useContext",
            Self::ImperativeHandle => "useImperativeHandle",
            Self::Custom => "useCustom",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// HookSlot — a hook invocation site within a component
// ---------------------------------------------------------------------------

/// A single hook invocation site within a component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSlot {
    /// Position index within the component (0-based, call order).
    pub slot_index: u32,
    /// Kind of hook.
    pub kind: HookKind,
    /// Human-readable label (e.g. "count" for useState).
    pub label: String,
    /// Dependencies array length (for useEffect/useMemo/useCallback).
    /// None means no dependency array was provided.
    pub dependency_count: Option<u32>,
    /// Whether this hook has a cleanup function (useEffect/useLayoutEffect).
    pub has_cleanup: bool,
    /// Source location offset (start byte).
    pub source_offset: u64,
    /// Content hash of the hook's dependency expressions.
    pub dependency_hash: Option<ContentHash>,
}

impl HookSlot {
    /// Check if this is a stateful hook (produces state that triggers re-render).
    pub fn is_stateful(&self) -> bool {
        matches!(self.kind, HookKind::State)
    }

    /// Check if this hook has side effects.
    pub fn has_side_effects(&self) -> bool {
        matches!(
            self.kind,
            HookKind::Effect | HookKind::LayoutEffect | HookKind::ImperativeHandle
        )
    }

    /// Check if this is a memoization hook.
    pub fn is_memoized(&self) -> bool {
        matches!(self.kind, HookKind::Memo | HookKind::Callback)
    }
}

// ---------------------------------------------------------------------------
// EffectClassification — boundary classification for effects
// ---------------------------------------------------------------------------

/// Classification of an effect boundary with capability requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectClassification {
    /// The IR-level effect boundary type.
    pub boundary: EffectBoundary,
    /// Required capabilities for this effect.
    pub required_capabilities: BTreeSet<String>,
    /// Whether this effect is idempotent (safe to replay).
    pub idempotent: bool,
    /// Whether this effect is commutative with other effects.
    pub commutative: bool,
    /// Estimated cost in millionths (for budgeting).
    pub estimated_cost_millionths: i64,
}

impl EffectClassification {
    /// Create a pure (no-effect) classification.
    pub fn pure_effect() -> Self {
        Self {
            boundary: EffectBoundary::Pure,
            required_capabilities: BTreeSet::new(),
            idempotent: true,
            commutative: true,
            estimated_cost_millionths: 0,
        }
    }

    /// Check if this is a pure computation.
    pub fn is_pure(&self) -> bool {
        self.boundary == EffectBoundary::Pure
    }

    /// Check if this effect requires any capabilities.
    pub fn requires_capabilities(&self) -> bool {
        !self.required_capabilities.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CapabilityBoundary — capability/effect boundary for a component
// ---------------------------------------------------------------------------

/// Capability boundary classification for a component or scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityBoundary {
    /// Capabilities directly required by this component.
    pub direct_capabilities: BTreeSet<String>,
    /// Capabilities transitively required (from children).
    pub transitive_capabilities: BTreeSet<String>,
    /// Effect boundary for the component's render path.
    pub render_effect: EffectBoundary,
    /// Effect boundaries for the component's hooks.
    pub hook_effects: Vec<EffectClassification>,
    /// Whether this component is a capability boundary (restricts
    /// what children can access).
    pub is_boundary: bool,
    /// Capability tags for the boundary (from IR2 annotations).
    pub boundary_tags: Vec<CapabilityTag>,
}

impl CapabilityBoundary {
    /// Create a pure component boundary (no capabilities, no effects).
    pub fn pure_component() -> Self {
        Self {
            direct_capabilities: BTreeSet::new(),
            transitive_capabilities: BTreeSet::new(),
            render_effect: EffectBoundary::Pure,
            hook_effects: Vec::new(),
            is_boundary: false,
            boundary_tags: Vec::new(),
        }
    }

    /// Total capabilities (union of direct and transitive).
    pub fn all_capabilities(&self) -> BTreeSet<String> {
        let mut all = self.direct_capabilities.clone();
        for cap in &self.transitive_capabilities {
            all.insert(cap.clone());
        }
        all
    }

    /// Check if the render path is pure (no side effects during render).
    pub fn is_render_pure(&self) -> bool {
        self.render_effect == EffectBoundary::Pure
    }
}

// ---------------------------------------------------------------------------
// AnalysisNode — a node in the analysis graph
// ---------------------------------------------------------------------------

/// A node in the static analysis graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisNode {
    /// Unique node identifier.
    pub id: AnalysisNodeId,
    /// Semantic kind of this node.
    pub kind: NodeKind,
    /// Human-readable label.
    pub label: String,
    /// Component this node belongs to (if any).
    pub component_id: Option<ComponentId>,
    /// Source location offset (start byte).
    pub source_offset: u64,
    /// Content hash of the node's definition.
    pub content_hash: ContentHash,
    /// Hook slots (only for Component nodes).
    pub hook_slots: Vec<HookSlot>,
    /// Effect classification (only for EffectSite/HookSlot nodes).
    pub effect_classification: Option<EffectClassification>,
    /// Capability boundary (only for Component/CapabilityGate nodes).
    pub capability_boundary: Option<CapabilityBoundary>,
}

// ---------------------------------------------------------------------------
// AnalysisEdge — an edge in the analysis graph
// ---------------------------------------------------------------------------

/// An edge in the static analysis graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisEdge {
    /// Unique edge identifier.
    pub id: AnalysisEdgeId,
    /// Source node.
    pub source: AnalysisNodeId,
    /// Target node.
    pub target: AnalysisNodeId,
    /// Semantic kind of this edge.
    pub kind: EdgeKind,
    /// Data labels flowing along this edge (for IFC analysis).
    pub data_labels: Vec<String>,
    /// Weight/strength in millionths (for prioritization).
    pub weight_millionths: i64,
}

// ---------------------------------------------------------------------------
// ComponentDescriptor — full descriptor for a component
// ---------------------------------------------------------------------------

/// Full descriptor for a component in the analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentDescriptor {
    /// Component identity.
    pub id: ComponentId,
    /// Whether this is a function component (vs class).
    pub is_function_component: bool,
    /// Module where this component is defined.
    pub module_path: String,
    /// Export name (None for non-exported/anonymous).
    pub export_name: Option<String>,
    /// Hook slots in call order.
    pub hook_slots: Vec<HookSlot>,
    /// Props interface (prop name → type hint).
    pub props: BTreeMap<String, String>,
    /// Context types consumed.
    pub consumed_contexts: Vec<String>,
    /// Context types provided.
    pub provided_contexts: Vec<String>,
    /// Capability boundary for this component.
    pub capability_boundary: CapabilityBoundary,
    /// Whether this component is a pure component (no side effects in render).
    pub is_pure: bool,
    /// Content hash of the component definition.
    pub content_hash: ContentHash,
    /// Children component IDs (direct renders).
    pub children: Vec<ComponentId>,
}

impl ComponentDescriptor {
    /// Count of stateful hooks.
    pub fn stateful_hook_count(&self) -> usize {
        self.hook_slots.iter().filter(|h| h.is_stateful()).count()
    }

    /// Count of effect hooks.
    pub fn effect_hook_count(&self) -> usize {
        self.hook_slots
            .iter()
            .filter(|h| h.has_side_effects())
            .count()
    }

    /// Total hook count.
    pub fn total_hook_count(&self) -> usize {
        self.hook_slots.len()
    }

    /// Check if this component is a leaf (no children).
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}

// ---------------------------------------------------------------------------
// DependencyPath — a path through the dependency graph
// ---------------------------------------------------------------------------

/// A path through the component dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyPath {
    /// Ordered list of component IDs from root to leaf.
    pub components: Vec<ComponentId>,
    /// Total weight in millionths.
    pub total_weight_millionths: i64,
    /// Edge kinds along the path.
    pub edge_kinds: Vec<EdgeKind>,
}

impl DependencyPath {
    /// Length of the path (number of edges).
    pub fn depth(&self) -> usize {
        if self.components.is_empty() {
            0
        } else {
            self.components.len() - 1
        }
    }

    /// Check if a component appears in the path (cycle detection).
    pub fn contains(&self, id: &ComponentId) -> bool {
        self.components.contains(id)
    }
}

// ---------------------------------------------------------------------------
// CycleReport — detected cycle in the dependency graph
// ---------------------------------------------------------------------------

/// A cycle detected in the component dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleReport {
    /// Components forming the cycle (last element links back to first).
    pub cycle: Vec<ComponentId>,
    /// Edge kinds along the cycle.
    pub edge_kinds: Vec<EdgeKind>,
    /// Severity: true if the cycle involves data flow (dangerous),
    /// false if it's only render-tree structure (possibly intentional).
    pub is_data_cycle: bool,
}

// ---------------------------------------------------------------------------
// AnalysisSummary — high-level summary statistics
// ---------------------------------------------------------------------------

/// High-level summary of the analysis graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSummary {
    /// Total number of components.
    pub component_count: u64,
    /// Total number of hook slots.
    pub hook_slot_count: u64,
    /// Total number of effect sites.
    pub effect_site_count: u64,
    /// Total number of edges.
    pub edge_count: u64,
    /// Number of pure components (no side effects in render).
    pub pure_component_count: u64,
    /// Number of components with state hooks.
    pub stateful_component_count: u64,
    /// Number of detected cycles.
    pub cycle_count: u64,
    /// Maximum component tree depth.
    pub max_depth: u64,
    /// Number of distinct capability tags required.
    pub distinct_capability_count: u64,
    /// Fraction of components that are pure, in millionths.
    pub purity_ratio_millionths: i64,
    /// Content hash of the entire analysis snapshot.
    pub snapshot_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// AnalysisError — errors during analysis
// ---------------------------------------------------------------------------

/// Errors that can occur during static analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisError {
    /// Node limit exceeded.
    NodeLimitExceeded { count: usize, max: usize },
    /// Edge limit exceeded.
    EdgeLimitExceeded { count: usize, max: usize },
    /// Hook slot limit exceeded.
    HookSlotLimitExceeded {
        component: ComponentId,
        count: usize,
        max: usize,
    },
    /// Duplicate node ID.
    DuplicateNode(AnalysisNodeId),
    /// Duplicate edge ID.
    DuplicateEdge(AnalysisEdgeId),
    /// Reference to unknown node.
    UnknownNode(AnalysisNodeId),
    /// Duplicate component ID.
    DuplicateComponent(ComponentId),
    /// Reference to unknown component.
    UnknownComponent(ComponentId),
    /// Cycle detected in graph.
    CycleDetected(CycleReport),
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeLimitExceeded { count, max } => {
                write!(f, "node limit exceeded: {count} > {max}")
            }
            Self::EdgeLimitExceeded { count, max } => {
                write!(f, "edge limit exceeded: {count} > {max}")
            }
            Self::HookSlotLimitExceeded {
                component,
                count,
                max,
            } => {
                write!(
                    f,
                    "hook slot limit exceeded for {component}: {count} > {max}"
                )
            }
            Self::DuplicateNode(id) => write!(f, "duplicate node: {id}"),
            Self::DuplicateEdge(id) => write!(f, "duplicate edge: {id}"),
            Self::UnknownNode(id) => write!(f, "unknown node: {id}"),
            Self::DuplicateComponent(id) => write!(f, "duplicate component: {id}"),
            Self::UnknownComponent(id) => write!(f, "unknown component: {id}"),
            Self::CycleDetected(report) => {
                write!(f, "cycle detected: {} components", report.cycle.len())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// StaticAnalysisGraph — the main analysis graph
// ---------------------------------------------------------------------------

/// Static analysis graph for a module or application.
///
/// This is the primary semantic substrate for no-VDOM lowering.
/// It provides component dependency analysis, hook slot tracking,
/// effect/dataflow analysis, and capability boundary classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticAnalysisGraph {
    /// Schema version.
    pub schema_version: String,
    /// All nodes keyed by ID.
    nodes: BTreeMap<String, AnalysisNode>,
    /// All edges keyed by ID.
    edges: BTreeMap<String, AnalysisEdge>,
    /// Component descriptors keyed by component ID.
    components: BTreeMap<String, ComponentDescriptor>,
    /// Forward adjacency list: source → [edge_ids].
    forward_adj: BTreeMap<String, Vec<String>>,
    /// Reverse adjacency list: target → [edge_ids].
    reverse_adj: BTreeMap<String, Vec<String>>,
    /// Detected cycles.
    cycles: Vec<CycleReport>,
    /// Event log for auditing.
    events: Vec<AnalysisEvent>,
    /// Next event sequence number.
    next_event_seq: u64,
}

// ---------------------------------------------------------------------------
// AnalysisEventKind — event types for audit trail
// ---------------------------------------------------------------------------

/// Kind of analysis event for the audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisEventKind {
    /// A node was added.
    NodeAdded,
    /// An edge was added.
    EdgeAdded,
    /// A component was registered.
    ComponentRegistered,
    /// A cycle was detected.
    CycleDetected,
    /// Capability boundary was computed.
    CapabilityBoundaryComputed,
    /// Analysis was finalized.
    AnalysisFinalized,
}

impl fmt::Display for AnalysisEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::NodeAdded => "node_added",
            Self::EdgeAdded => "edge_added",
            Self::ComponentRegistered => "component_registered",
            Self::CycleDetected => "cycle_detected",
            Self::CapabilityBoundaryComputed => "capability_boundary_computed",
            Self::AnalysisFinalized => "analysis_finalized",
        };
        f.write_str(s)
    }
}

/// An event in the analysis audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisEvent {
    /// Sequence number.
    pub seq: u64,
    /// Event kind.
    pub kind: AnalysisEventKind,
    /// Associated entity ID (node, edge, or component).
    pub entity_id: String,
    /// Detail message.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// StaticAnalysisGraph — implementation
// ---------------------------------------------------------------------------

impl StaticAnalysisGraph {
    /// Create a new empty analysis graph.
    pub fn new() -> Self {
        Self::with_capacity(0, 0)
    }

    /// Create a new analysis graph with preallocated capacity for nodes and edges.
    /// This optimization removes repeated map growth during analysis graph assembly.
    pub fn with_capacity(expected_nodes: usize, expected_edges: usize) -> Self {
        Self {
            schema_version: STATIC_ANALYSIS_SCHEMA_VERSION.to_string(),
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            components: BTreeMap::new(),
            forward_adj: BTreeMap::new(),
            reverse_adj: BTreeMap::new(),
            cycles: Vec::with_capacity(expected_nodes.saturating_div(10)), // Estimate cycle capacity
            events: Vec::with_capacity(expected_nodes.saturating_add(expected_edges)), // Events = nodes + edges
            next_event_seq: 0,
        }
    }

    // -- Mutation --

    /// Add a node to the graph.
    pub fn add_node(&mut self, node: AnalysisNode) -> Result<(), AnalysisError> {
        if self.nodes.len() >= MAX_NODES {
            return Err(AnalysisError::NodeLimitExceeded {
                count: self.nodes.len() + 1,
                max: MAX_NODES,
            });
        }
        let key = node.id.0.clone();
        if self.nodes.contains_key(&key) {
            return Err(AnalysisError::DuplicateNode(node.id.clone()));
        }
        self.emit_event(AnalysisEventKind::NodeAdded, &key, "");

        // Preallocate adjacency list slots for this node to avoid Vec growth on first edge
        self.forward_adj
            .entry(key.clone())
            .or_insert_with(|| Vec::with_capacity(8));
        self.reverse_adj
            .entry(key.clone())
            .or_insert_with(|| Vec::with_capacity(8));

        self.nodes.insert(key, node);
        Ok(())
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, edge: AnalysisEdge) -> Result<(), AnalysisError> {
        if self.edges.len() >= MAX_EDGES {
            return Err(AnalysisError::EdgeLimitExceeded {
                count: self.edges.len() + 1,
                max: MAX_EDGES,
            });
        }
        let key = edge.id.0.clone();
        if self.edges.contains_key(&key) {
            return Err(AnalysisError::DuplicateEdge(edge.id.clone()));
        }
        if !self.nodes.contains_key(&edge.source.0) {
            return Err(AnalysisError::UnknownNode(edge.source.clone()));
        }
        if !self.nodes.contains_key(&edge.target.0) {
            return Err(AnalysisError::UnknownNode(edge.target.clone()));
        }
        let source_key = edge.source.0.clone();
        let target_key = edge.target.0.clone();
        self.emit_event(AnalysisEventKind::EdgeAdded, &key, "");

        // Preallocate adjacency list capacity based on graph density heuristics
        self.forward_adj
            .entry(source_key)
            .or_insert_with(|| Vec::with_capacity(8)) // Typical fanout: 2-8 edges per node
            .push(key.clone());
        self.reverse_adj
            .entry(target_key)
            .or_insert_with(|| Vec::with_capacity(8)) // Typical fanin: 2-8 edges per node
            .push(key.clone());
        self.edges.insert(key, edge);
        Ok(())
    }

    /// Register a component descriptor.
    pub fn register_component(
        &mut self,
        descriptor: ComponentDescriptor,
    ) -> Result<(), AnalysisError> {
        if descriptor.hook_slots.len() > MAX_HOOK_SLOTS {
            return Err(AnalysisError::HookSlotLimitExceeded {
                component: descriptor.id.clone(),
                count: descriptor.hook_slots.len(),
                max: MAX_HOOK_SLOTS,
            });
        }
        let key = descriptor.id.0.clone();
        if self.components.contains_key(&key) {
            return Err(AnalysisError::DuplicateComponent(descriptor.id.clone()));
        }
        self.emit_event(AnalysisEventKind::ComponentRegistered, &key, "");
        self.components.insert(key, descriptor);
        Ok(())
    }

    // -- Query --

    /// Get a node by ID.
    pub fn get_node(&self, id: &AnalysisNodeId) -> Option<&AnalysisNode> {
        self.nodes.get(&id.0)
    }

    /// Get an edge by ID.
    pub fn get_edge(&self, id: &AnalysisEdgeId) -> Option<&AnalysisEdge> {
        self.edges.get(&id.0)
    }

    /// Get a component descriptor by ID.
    pub fn get_component(&self, id: &ComponentId) -> Option<&ComponentDescriptor> {
        self.components.get(&id.0)
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Number of registered components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Get outgoing edge IDs for a node.
    ///
    /// Returns an error if the node ID is not registered in the graph.
    pub fn outgoing_edges(
        &self,
        node_id: &AnalysisNodeId,
    ) -> Result<Vec<AnalysisEdgeId>, AnalysisError> {
        self.forward_adj
            .get(&node_id.0)
            .map(|ids| ids.iter().map(|s| AnalysisEdgeId(s.clone())).collect())
            .ok_or_else(|| AnalysisError::UnknownNode(node_id.clone()))
    }

    /// Get incoming edge IDs for a node.
    ///
    /// Returns an error if the node ID is not registered in the graph.
    pub fn incoming_edges(
        &self,
        node_id: &AnalysisNodeId,
    ) -> Result<Vec<AnalysisEdgeId>, AnalysisError> {
        self.reverse_adj
            .get(&node_id.0)
            .map(|ids| ids.iter().map(|s| AnalysisEdgeId(s.clone())).collect())
            .ok_or_else(|| AnalysisError::UnknownNode(node_id.clone()))
    }

    /// Get direct dependencies for a node (nodes this node depends on).
    ///
    /// Returns an error if the node ID is not registered in the graph.
    pub fn dependencies(
        &self,
        node_id: &AnalysisNodeId,
    ) -> Result<Vec<AnalysisNodeId>, AnalysisError> {
        let edges = self.outgoing_edges(node_id)?;
        Ok(edges
            .iter()
            .filter_map(|eid| self.edges.get(&eid.0).map(|e| e.target.clone()))
            .collect())
    }

    /// Get direct dependents for a node (nodes that depend on this node).
    ///
    /// Returns an error if the node ID is not registered in the graph.
    pub fn dependents(
        &self,
        node_id: &AnalysisNodeId,
    ) -> Result<Vec<AnalysisNodeId>, AnalysisError> {
        let edges = self.incoming_edges(node_id)?;
        Ok(edges
            .iter()
            .filter_map(|eid| self.edges.get(&eid.0).map(|e| e.source.clone()))
            .collect())
    }

    /// Get all component IDs.
    pub fn component_ids(&self) -> Vec<ComponentId> {
        self.components
            .keys()
            .map(|k| ComponentId(k.clone()))
            .collect()
    }

    /// Get all node IDs of a specific kind.
    pub fn nodes_of_kind(&self, kind: NodeKind) -> Vec<AnalysisNodeId> {
        self.nodes
            .values()
            .filter(|n| n.kind == kind)
            .map(|n| n.id.clone())
            .collect()
    }

    /// Get all edges of a specific kind.
    pub fn edges_of_kind(&self, kind: EdgeKind) -> Vec<AnalysisEdgeId> {
        self.edges
            .values()
            .filter(|e| e.kind == kind)
            .map(|e| e.id.clone())
            .collect()
    }

    /// Get detected cycles.
    pub fn cycles(&self) -> &[CycleReport] {
        &self.cycles
    }

    /// Get all events.
    pub fn events(&self) -> &[AnalysisEvent] {
        &self.events
    }

    // -- Analysis --

    /// Detect cycles in the component dependency graph using DFS.
    pub fn detect_cycles(&mut self) -> Vec<CycleReport> {
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut in_stack: BTreeSet<String> = BTreeSet::new();
        let mut stack: Vec<String> = Vec::new();
        let mut new_cycles: Vec<CycleReport> = Vec::new();

        for component_key in self.components.keys().cloned().collect::<Vec<_>>() {
            if !visited.contains(&component_key) {
                self.dfs_cycle_detect(
                    &component_key,
                    &mut visited,
                    &mut in_stack,
                    &mut stack,
                    &mut new_cycles,
                );
            }
        }

        for cycle in &new_cycles {
            self.emit_event(
                AnalysisEventKind::CycleDetected,
                &cycle
                    .cycle
                    .first()
                    .map(|c| c.0.clone())
                    .expect("serde deserialization should succeed"),
                &format!("{} components in cycle", cycle.cycle.len()),
            );
        }
        self.cycles = new_cycles.clone();
        new_cycles
    }

    fn dfs_cycle_detect(
        &self,
        node: &str,
        visited: &mut BTreeSet<String>,
        in_stack: &mut BTreeSet<String>,
        stack: &mut Vec<String>,
        cycles: &mut Vec<CycleReport>,
    ) {
        visited.insert(node.to_string());
        in_stack.insert(node.to_string());
        stack.push(node.to_string());

        // Find children via component descriptors
        if let Some(desc) = self.components.get(node) {
            for child in &desc.children {
                if !visited.contains(&child.0) {
                    self.dfs_cycle_detect(&child.0, visited, in_stack, stack, cycles);
                } else if in_stack.contains(&child.0) {
                    // Found a cycle — extract it
                    let cycle_start = stack.iter().position(|s| s == &child.0).unwrap_or(0);
                    let cycle_components: Vec<ComponentId> = stack[cycle_start..]
                        .iter()
                        .map(|s| ComponentId(s.clone()))
                        .collect();
                    let has_data_edges = self.has_data_flow_between_any(&cycle_components);
                    cycles.push(CycleReport {
                        cycle: cycle_components,
                        edge_kinds: vec![EdgeKind::RendersChild],
                        is_data_cycle: has_data_edges,
                    });
                }
            }
        }

        stack.pop();
        in_stack.remove(node);
    }

    fn has_data_flow_between_any(&self, components: &[ComponentId]) -> bool {
        let id_set: BTreeSet<&str> = components.iter().map(|c| c.0.as_str()).collect();
        for edge in self.edges.values() {
            if matches!(
                edge.kind,
                EdgeKind::PropFlow
                    | EdgeKind::ContextFlow
                    | EdgeKind::HookDataFlow
                    | EdgeKind::StateUpdateTrigger
            ) && id_set.contains(edge.source.0.as_str())
                && id_set.contains(edge.target.0.as_str())
            {
                return true;
            }
        }
        false
    }

    /// Compute transitive capabilities for all components.
    ///
    /// For each component, computes the union of its direct capabilities
    /// and all capabilities of its children (transitively).
    pub fn compute_transitive_capabilities(&mut self) {
        // Topological sort: process leaves first
        let order = self.topological_sort_components();
        // Process in reverse topological order (leaves first)
        for comp_id in order.into_iter().rev() {
            let children_caps: BTreeSet<String> = {
                let desc = match self.components.get(&comp_id) {
                    Some(d) => d,
                    None => continue,
                };
                desc.children
                    .iter()
                    .flat_map(|child_id| {
                        self.components
                            .get(&child_id.0)
                            .map(|c| c.capability_boundary.all_capabilities())
                            .expect("serde deserialization should succeed")
                    })
                    .collect()
            };
            if let Some(desc) = self.components.get_mut(&comp_id) {
                desc.capability_boundary.transitive_capabilities = children_caps;
            }
            self.emit_event(AnalysisEventKind::CapabilityBoundaryComputed, &comp_id, "");
        }
    }

    /// Topological sort of component IDs (Kahn's algorithm).
    /// Returns IDs from roots to leaves.
    fn topological_sort_components(&self) -> Vec<String> {
        // Build in-degree map from children edges
        let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();
        let mut children_map: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for (key, desc) in &self.components {
            in_degree.entry(key.clone()).or_insert(0);
            for child in &desc.children {
                *in_degree.entry(child.0.clone()).or_insert(0) += 1;
                children_map
                    .entry(key.clone())
                    .or_default()
                    .push(child.0.clone());
            }
        }

        let mut queue: Vec<String> = in_degree
            .iter()
            .filter(|(_, deg)| **deg == 0)
            .map(|(k, _)| k.clone())
            .collect();
        queue.sort(); // deterministic
        let mut result = Vec::new();

        while let Some(node) = queue.first().cloned() {
            queue.remove(0);
            result.push(node.clone());
            if let Some(children) = children_map.get(&node) {
                for child in children {
                    if let Some(deg) = in_degree.get_mut(child) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push(child.clone());
                            queue.sort(); // maintain deterministic order
                        }
                    }
                }
            }
        }

        result
    }

    /// Compute a summary of the analysis graph.
    pub fn summary(&self) -> AnalysisSummary {
        let component_count = self.components.len() as u64;
        let hook_slot_count: u64 = self
            .components
            .values()
            .map(|c| c.hook_slots.len() as u64)
            .fold(0u64, |acc, x| acc.saturating_add(x));
        let effect_site_count = self
            .nodes
            .values()
            .filter(|n| n.kind == NodeKind::EffectSite)
            .count() as u64;
        let edge_count = self.edges.len() as u64;
        let pure_component_count = self.components.values().filter(|c| c.is_pure).count() as u64;
        let stateful_component_count = self
            .components
            .values()
            .filter(|c| c.stateful_hook_count() > 0)
            .count() as u64;
        let cycle_count = self.cycles.len() as u64;
        let max_depth = self.compute_max_depth();
        let distinct_caps: BTreeSet<String> = self
            .components
            .values()
            .flat_map(|c| c.capability_boundary.all_capabilities())
            .collect();
        let purity_ratio_millionths = if component_count == 0 {
            0
        } else {
            (pure_component_count as i64) * MILLION / (component_count as i64)
        };

        let snapshot_hash = self.compute_snapshot_hash();

        AnalysisSummary {
            component_count,
            hook_slot_count,
            effect_site_count,
            edge_count,
            pure_component_count,
            stateful_component_count,
            cycle_count,
            max_depth,
            distinct_capability_count: distinct_caps.len() as u64,
            purity_ratio_millionths,
            snapshot_hash,
        }
    }

    fn compute_snapshot_hash(&self) -> ContentHash {
        #[derive(Serialize)]
        struct SnapshotEnvelope<'a> {
            schema_version: &'a str,
            nodes: &'a BTreeMap<String, AnalysisNode>,
            edges: &'a BTreeMap<String, AnalysisEdge>,
            components: &'a BTreeMap<String, ComponentDescriptor>,
            cycles: &'a [CycleReport],
        }

        let canonical = serde_json::to_vec(&SnapshotEnvelope {
            schema_version: &self.schema_version,
            nodes: &self.nodes,
            edges: &self.edges,
            components: &self.components,
            cycles: &self.cycles,
        })
        .expect("serde deserialization should succeed");
        ContentHash::compute(&canonical)
    }

    fn compute_max_depth(&self) -> u64 {
        let mut max_depth: u64 = 0;
        // Use BFS from root components (no parents)
        let child_set: BTreeSet<String> = self
            .components
            .values()
            .flat_map(|c| c.children.iter().map(|ch| ch.0.clone()))
            .collect();
        let roots: Vec<String> = self
            .components
            .keys()
            .filter(|k| !child_set.contains(*k))
            .cloned()
            .collect();

        for root in &roots {
            let depth = self.bfs_depth(root);
            if depth > max_depth {
                max_depth = depth;
            }
        }
        max_depth
    }

    fn bfs_depth(&self, root: &str) -> u64 {
        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut queue: Vec<(String, u64)> = vec![(root.to_string(), 0)];
        let mut max_d: u64 = 0;
        visited.insert(root.to_string());

        while let Some((node, depth)) = queue.first().cloned() {
            queue.remove(0);
            if depth > max_d {
                max_d = depth;
            }
            if let Some(desc) = self.components.get(&node) {
                for child in &desc.children {
                    if !visited.contains(&child.0) {
                        visited.insert(child.0.clone());
                        queue.push((child.0.clone(), depth + 1));
                    }
                }
            }
        }
        max_d
    }

    /// Find all root components (components not rendered by any other component).
    pub fn root_components(&self) -> Vec<ComponentId> {
        let child_set: BTreeSet<&str> = self
            .components
            .values()
            .flat_map(|c| c.children.iter().map(|ch| ch.0.as_str()))
            .collect();
        self.components
            .keys()
            .filter(|k| !child_set.contains(k.as_str()))
            .map(|k| ComponentId(k.clone()))
            .collect()
    }

    /// Find all leaf components (components that don't render any children).
    pub fn leaf_components(&self) -> Vec<ComponentId> {
        self.components
            .values()
            .filter(|c| c.is_leaf())
            .map(|c| c.id.clone())
            .collect()
    }

    /// Get the hook slot map for a component.
    pub fn hook_slots_for(&self, component_id: &ComponentId) -> Option<&[HookSlot]> {
        self.components
            .get(&component_id.0)
            .map(|c| c.hook_slots.as_slice())
    }

    /// Get all components with a given capability requirement.
    pub fn components_requiring_capability(&self, capability: &str) -> Vec<ComponentId> {
        self.components
            .values()
            .filter(|c| {
                c.capability_boundary
                    .direct_capabilities
                    .contains(capability)
            })
            .map(|c| c.id.clone())
            .collect()
    }

    /// Get all edges between two nodes.
    pub fn edges_between(
        &self,
        source: &AnalysisNodeId,
        target: &AnalysisNodeId,
    ) -> Vec<&AnalysisEdge> {
        self.forward_adj
            .get(&source.0)
            .map(|ids| {
                ids.iter()
                    .filter_map(|eid| {
                        let edge = self.edges.get(eid)?;
                        if edge.target == *target {
                            Some(edge)
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .expect("serde deserialization should succeed")
    }

    /// Compute the subgraph reachable from a given node (forward).
    ///
    /// Returns an error if any node in the traversal is not registered in the graph.
    pub fn reachable_from(
        &self,
        start: &AnalysisNodeId,
    ) -> Result<BTreeSet<AnalysisNodeId>, AnalysisError> {
        let mut visited: BTreeSet<AnalysisNodeId> = BTreeSet::new();
        let mut queue: Vec<AnalysisNodeId> = vec![start.clone()];

        while let Some(current) = queue.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());
            for dep in self.dependencies(&current)? {
                if !visited.contains(&dep) {
                    queue.push(dep);
                }
            }
        }
        Ok(visited)
    }

    // -- Internal --

    fn emit_event(&mut self, kind: AnalysisEventKind, entity_id: &str, detail: &str) {
        let seq = self.next_event_seq;
        self.next_event_seq += 1;
        self.events.push(AnalysisEvent {
            seq,
            kind,
            entity_id: entity_id.to_string(),
            detail: detail.to_string(),
        });
    }
}

impl Default for StaticAnalysisGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_tiers::ContentHash;

    // -- Helpers --

    fn make_hash(data: &[u8]) -> ContentHash {
        ContentHash::compute(data)
    }

    fn make_node(id: &str, kind: NodeKind) -> AnalysisNode {
        AnalysisNode {
            id: AnalysisNodeId::new(id),
            kind,
            label: id.to_string(),
            component_id: None,
            source_offset: 0,
            content_hash: make_hash(id.as_bytes()),
            hook_slots: Vec::new(),
            effect_classification: None,
            capability_boundary: None,
        }
    }

    fn make_edge(id: &str, source: &str, target: &str, kind: EdgeKind) -> AnalysisEdge {
        AnalysisEdge {
            id: AnalysisEdgeId::new(id),
            source: AnalysisNodeId::new(source),
            target: AnalysisNodeId::new(target),
            kind,
            data_labels: Vec::new(),
            weight_millionths: MILLION,
        }
    }

    fn make_component(id: &str, children: &[&str]) -> ComponentDescriptor {
        ComponentDescriptor {
            id: ComponentId::new(id),
            is_function_component: true,
            module_path: format!("src/{id}.tsx"),
            export_name: Some(id.to_string()),
            hook_slots: Vec::new(),
            props: BTreeMap::new(),
            consumed_contexts: Vec::new(),
            provided_contexts: Vec::new(),
            capability_boundary: CapabilityBoundary::pure_component(),
            is_pure: true,
            content_hash: make_hash(id.as_bytes()),
            children: children.iter().map(|c| ComponentId::new(c)).collect(),
        }
    }

    fn make_hook_slot(index: u32, kind: HookKind) -> HookSlot {
        HookSlot {
            slot_index: index,
            kind,
            label: format!("hook_{index}"),
            dependency_count: None,
            has_cleanup: false,
            source_offset: 0,
            dependency_hash: None,
        }
    }

    // -- ComponentId tests --

    #[test]
    fn component_id_display() {
        let id = ComponentId::new("App");
        assert_eq!(format!("{id}"), "App");
    }

    #[test]
    fn component_id_ord() {
        let a = ComponentId::new("Alpha");
        let b = ComponentId::new("Beta");
        assert!(a < b);
    }

    #[test]
    fn component_id_serde_roundtrip() {
        let id = ComponentId::new("MyComponent");
        let json = serde_json::to_string(&id).expect("serde deserialization should succeed");
        let back: ComponentId =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(id, back);
    }

    // -- AnalysisNodeId tests --

    #[test]
    fn analysis_node_id_display() {
        let id = AnalysisNodeId::new("node_0");
        assert_eq!(format!("{id}"), "node_0");
    }

    #[test]
    fn analysis_node_id_serde_roundtrip() {
        let id = AnalysisNodeId::new("n1");
        let json = serde_json::to_string(&id).expect("serde deserialization should succeed");
        let back: AnalysisNodeId =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(id, back);
    }

    // -- AnalysisEdgeId tests --

    #[test]
    fn analysis_edge_id_display() {
        let id = AnalysisEdgeId::new("edge_0");
        assert_eq!(format!("{id}"), "edge_0");
    }

    // -- NodeKind tests --

    #[test]
    fn node_kind_display() {
        assert_eq!(format!("{}", NodeKind::Component), "component");
        assert_eq!(format!("{}", NodeKind::HookSlot), "hook_slot");
        assert_eq!(format!("{}", NodeKind::EffectSite), "effect_site");
        assert_eq!(format!("{}", NodeKind::DataSource), "data_source");
        assert_eq!(format!("{}", NodeKind::DataSink), "data_sink");
        assert_eq!(format!("{}", NodeKind::ModuleBoundary), "module_boundary");
        assert_eq!(format!("{}", NodeKind::CapabilityGate), "capability_gate");
        assert_eq!(format!("{}", NodeKind::ScopeBoundary), "scope_boundary");
    }

    #[test]
    fn node_kind_serde_roundtrip() {
        for kind in [
            NodeKind::Component,
            NodeKind::HookSlot,
            NodeKind::EffectSite,
            NodeKind::DataSource,
            NodeKind::DataSink,
            NodeKind::ModuleBoundary,
            NodeKind::CapabilityGate,
            NodeKind::ScopeBoundary,
        ] {
            let json = serde_json::to_string(&kind).expect("serde deserialization should succeed");
            let back: NodeKind =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(kind, back);
        }
    }

    // -- EdgeKind tests --

    #[test]
    fn edge_kind_display() {
        assert_eq!(format!("{}", EdgeKind::RendersChild), "renders_child");
        assert_eq!(format!("{}", EdgeKind::PropFlow), "prop_flow");
        assert_eq!(format!("{}", EdgeKind::HookDataFlow), "hook_data_flow");
        assert_eq!(
            format!("{}", EdgeKind::EffectDependency),
            "effect_dependency"
        );
        assert_eq!(
            format!("{}", EdgeKind::ImportDependency),
            "import_dependency"
        );
        assert_eq!(format!("{}", EdgeKind::ContextFlow), "context_flow");
        assert_eq!(format!("{}", EdgeKind::CallbackFlow), "callback_flow");
        assert_eq!(
            format!("{}", EdgeKind::CapabilityRequirement),
            "capability_requirement"
        );
        assert_eq!(
            format!("{}", EdgeKind::ScopeContainment),
            "scope_containment"
        );
        assert_eq!(
            format!("{}", EdgeKind::StateUpdateTrigger),
            "state_update_trigger"
        );
    }

    #[test]
    fn edge_kind_serde_roundtrip() {
        for kind in [
            EdgeKind::RendersChild,
            EdgeKind::PropFlow,
            EdgeKind::HookDataFlow,
            EdgeKind::EffectDependency,
            EdgeKind::ImportDependency,
            EdgeKind::ContextFlow,
            EdgeKind::CallbackFlow,
            EdgeKind::CapabilityRequirement,
            EdgeKind::ScopeContainment,
            EdgeKind::StateUpdateTrigger,
        ] {
            let json = serde_json::to_string(&kind).expect("serde deserialization should succeed");
            let back: EdgeKind =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(kind, back);
        }
    }

    // -- HookKind tests --

    #[test]
    fn hook_kind_display() {
        assert_eq!(format!("{}", HookKind::State), "useState");
        assert_eq!(format!("{}", HookKind::Effect), "useEffect");
        assert_eq!(format!("{}", HookKind::LayoutEffect), "useLayoutEffect");
        assert_eq!(format!("{}", HookKind::Memo), "useMemo");
        assert_eq!(format!("{}", HookKind::Callback), "useCallback");
        assert_eq!(format!("{}", HookKind::Ref), "useRef");
        assert_eq!(format!("{}", HookKind::Context), "useContext");
        assert_eq!(
            format!("{}", HookKind::ImperativeHandle),
            "useImperativeHandle"
        );
        assert_eq!(format!("{}", HookKind::Custom), "useCustom");
    }

    #[test]
    fn hook_kind_serde_roundtrip() {
        for kind in [
            HookKind::State,
            HookKind::Effect,
            HookKind::LayoutEffect,
            HookKind::Memo,
            HookKind::Callback,
            HookKind::Ref,
            HookKind::Context,
            HookKind::ImperativeHandle,
            HookKind::Custom,
        ] {
            let json = serde_json::to_string(&kind).expect("serde deserialization should succeed");
            let back: HookKind =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(kind, back);
        }
    }

    // -- HookSlot tests --

    #[test]
    fn hook_slot_stateful() {
        let slot = make_hook_slot(0, HookKind::State);
        assert!(slot.is_stateful());
        assert!(!slot.has_side_effects());
        assert!(!slot.is_memoized());
    }

    #[test]
    fn hook_slot_effect() {
        let slot = make_hook_slot(1, HookKind::Effect);
        assert!(!slot.is_stateful());
        assert!(slot.has_side_effects());
        assert!(!slot.is_memoized());
    }

    #[test]
    fn hook_slot_layout_effect() {
        let slot = make_hook_slot(2, HookKind::LayoutEffect);
        assert!(slot.has_side_effects());
    }

    #[test]
    fn hook_slot_memo() {
        let slot = make_hook_slot(3, HookKind::Memo);
        assert!(slot.is_memoized());
        assert!(!slot.is_stateful());
        assert!(!slot.has_side_effects());
    }

    #[test]
    fn hook_slot_callback() {
        let slot = make_hook_slot(4, HookKind::Callback);
        assert!(slot.is_memoized());
    }

    #[test]
    fn hook_slot_ref_is_neutral() {
        let slot = make_hook_slot(5, HookKind::Ref);
        assert!(!slot.is_stateful());
        assert!(!slot.has_side_effects());
        assert!(!slot.is_memoized());
    }

    #[test]
    fn hook_slot_imperative_handle_has_effects() {
        let slot = make_hook_slot(6, HookKind::ImperativeHandle);
        assert!(slot.has_side_effects());
    }

    #[test]
    fn hook_slot_serde_roundtrip() {
        let mut slot = make_hook_slot(0, HookKind::Effect);
        slot.dependency_count = Some(3);
        slot.has_cleanup = true;
        slot.dependency_hash = Some(make_hash(b"deps"));
        let json = serde_json::to_string(&slot).expect("serde deserialization should succeed");
        let back: HookSlot =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(slot, back);
    }

    // -- EffectClassification tests --

    #[test]
    fn effect_pure() {
        let eff = EffectClassification::pure_effect();
        assert!(eff.is_pure());
        assert!(!eff.requires_capabilities());
        assert!(eff.idempotent);
        assert!(eff.commutative);
        assert_eq!(eff.estimated_cost_millionths, 0);
    }

    #[test]
    fn effect_with_capabilities() {
        let mut caps = BTreeSet::new();
        caps.insert("network".to_string());
        let eff = EffectClassification {
            boundary: EffectBoundary::NetworkEffect,
            required_capabilities: caps,
            idempotent: false,
            commutative: false,
            estimated_cost_millionths: 500_000,
        };
        assert!(!eff.is_pure());
        assert!(eff.requires_capabilities());
    }

    #[test]
    fn effect_classification_serde_roundtrip() {
        let eff = EffectClassification::pure_effect();
        let json = serde_json::to_string(&eff).expect("serde deserialization should succeed");
        let back: EffectClassification =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(eff, back);
    }

    // -- CapabilityBoundary tests --

    #[test]
    fn capability_boundary_pure() {
        let cb = CapabilityBoundary::pure_component();
        assert!(cb.is_render_pure());
        assert!(cb.all_capabilities().is_empty());
        assert!(!cb.is_boundary);
    }

    #[test]
    fn capability_boundary_with_caps() {
        let mut cb = CapabilityBoundary::pure_component();
        cb.direct_capabilities.insert("fs_read".to_string());
        cb.transitive_capabilities.insert("network".to_string());
        let all = cb.all_capabilities();
        assert_eq!(all.len(), 2);
        assert!(all.contains("fs_read"));
        assert!(all.contains("network"));
    }

    #[test]
    fn capability_boundary_serde_roundtrip() {
        let mut cb = CapabilityBoundary::pure_component();
        cb.direct_capabilities.insert("vm_dispatch".to_string());
        cb.boundary_tags.push(CapabilityTag("test".to_string()));
        let json = serde_json::to_string(&cb).expect("serde deserialization should succeed");
        let back: CapabilityBoundary =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(cb, back);
    }

    // -- ComponentDescriptor tests --

    #[test]
    fn component_descriptor_leaf() {
        let desc = make_component("Leaf", &[]);
        assert!(desc.is_leaf());
        assert_eq!(desc.total_hook_count(), 0);
        assert_eq!(desc.stateful_hook_count(), 0);
        assert_eq!(desc.effect_hook_count(), 0);
    }

    #[test]
    fn component_descriptor_with_hooks() {
        let mut desc = make_component("Counter", &[]);
        desc.hook_slots.push(make_hook_slot(0, HookKind::State));
        desc.hook_slots.push(make_hook_slot(1, HookKind::Effect));
        desc.hook_slots.push(make_hook_slot(2, HookKind::Memo));
        assert_eq!(desc.total_hook_count(), 3);
        assert_eq!(desc.stateful_hook_count(), 1);
        assert_eq!(desc.effect_hook_count(), 1);
    }

    #[test]
    fn component_descriptor_with_children() {
        let desc = make_component("App", &["Header", "Body", "Footer"]);
        assert!(!desc.is_leaf());
        assert_eq!(desc.children.len(), 3);
    }

    #[test]
    fn component_descriptor_serde_roundtrip() {
        let mut desc = make_component("App", &["Child"]);
        desc.props.insert("title".to_string(), "string".to_string());
        desc.consumed_contexts.push("ThemeContext".to_string());
        let json = serde_json::to_string(&desc).expect("serde deserialization should succeed");
        let back: ComponentDescriptor =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(desc, back);
    }

    // -- DependencyPath tests --

    #[test]
    fn dependency_path_depth() {
        let path = DependencyPath {
            components: vec![
                ComponentId::new("A"),
                ComponentId::new("B"),
                ComponentId::new("C"),
            ],
            total_weight_millionths: 3 * MILLION,
            edge_kinds: vec![EdgeKind::RendersChild, EdgeKind::RendersChild],
        };
        assert_eq!(path.depth(), 2);
    }

    #[test]
    fn dependency_path_empty() {
        let path = DependencyPath {
            components: Vec::new(),
            total_weight_millionths: 0,
            edge_kinds: Vec::new(),
        };
        assert_eq!(path.depth(), 0);
    }

    #[test]
    fn dependency_path_contains() {
        let path = DependencyPath {
            components: vec![ComponentId::new("A"), ComponentId::new("B")],
            total_weight_millionths: MILLION,
            edge_kinds: vec![EdgeKind::RendersChild],
        };
        assert!(path.contains(&ComponentId::new("A")));
        assert!(!path.contains(&ComponentId::new("C")));
    }

    // -- CycleReport tests --

    #[test]
    fn cycle_report_serde_roundtrip() {
        let report = CycleReport {
            cycle: vec![
                ComponentId::new("A"),
                ComponentId::new("B"),
                ComponentId::new("A"),
            ],
            edge_kinds: vec![EdgeKind::RendersChild, EdgeKind::RendersChild],
            is_data_cycle: false,
        };
        let json = serde_json::to_string(&report).expect("serde deserialization should succeed");
        let back: CycleReport =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(report, back);
    }

    // -- AnalysisError tests --

    #[test]
    fn analysis_error_display() {
        let e = AnalysisError::NodeLimitExceeded {
            count: 100_001,
            max: 100_000,
        };
        assert_eq!(format!("{e}"), "node limit exceeded: 100001 > 100000");

        let e = AnalysisError::DuplicateNode(AnalysisNodeId::new("n1"));
        assert_eq!(format!("{e}"), "duplicate node: n1");

        let e = AnalysisError::UnknownNode(AnalysisNodeId::new("n99"));
        assert_eq!(format!("{e}"), "unknown node: n99");

        let e = AnalysisError::DuplicateComponent(ComponentId::new("App"));
        assert_eq!(format!("{e}"), "duplicate component: App");
    }

    #[test]
    fn analysis_error_serde_roundtrip() {
        let e = AnalysisError::HookSlotLimitExceeded {
            component: ComponentId::new("BigComp"),
            count: 300,
            max: 256,
        };
        let json = serde_json::to_string(&e).expect("serde deserialization should succeed");
        let back: AnalysisError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(e, back);
    }

    // -- AnalysisEventKind tests --

    #[test]
    fn analysis_event_kind_display() {
        assert_eq!(format!("{}", AnalysisEventKind::NodeAdded), "node_added");
        assert_eq!(format!("{}", AnalysisEventKind::EdgeAdded), "edge_added");
        assert_eq!(
            format!("{}", AnalysisEventKind::ComponentRegistered),
            "component_registered"
        );
        assert_eq!(
            format!("{}", AnalysisEventKind::CycleDetected),
            "cycle_detected"
        );
        assert_eq!(
            format!("{}", AnalysisEventKind::CapabilityBoundaryComputed),
            "capability_boundary_computed"
        );
        assert_eq!(
            format!("{}", AnalysisEventKind::AnalysisFinalized),
            "analysis_finalized"
        );
    }

    // -- StaticAnalysisGraph basic tests --

    #[test]
    fn graph_new_is_empty() {
        let g = StaticAnalysisGraph::new();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
        assert_eq!(g.component_count(), 0);
        assert_eq!(g.schema_version, STATIC_ANALYSIS_SCHEMA_VERSION);
    }

    #[test]
    fn graph_default_is_new() {
        let g = StaticAnalysisGraph::default();
        assert_eq!(g.node_count(), 0);
    }

    #[test]
    fn graph_add_node() {
        let mut g = StaticAnalysisGraph::new();
        let node = make_node("n1", NodeKind::Component);
        g.add_node(node)
            .expect("serde deserialization should succeed");
        assert_eq!(g.node_count(), 1);
        assert!(g.get_node(&AnalysisNodeId::new("n1")).is_some());
    }

    #[test]
    fn graph_add_duplicate_node_fails() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        let err = g.add_node(make_node("n1", NodeKind::HookSlot)).unwrap_err();
        assert!(matches!(err, AnalysisError::DuplicateNode(_)));
    }

    #[test]
    fn graph_add_edge() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        assert_eq!(g.edge_count(), 1);
        assert!(g.get_edge(&AnalysisEdgeId::new("e1")).is_some());
    }

    #[test]
    fn graph_add_edge_unknown_source_fails() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        let err = g
            .add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .unwrap_err();
        assert!(matches!(err, AnalysisError::UnknownNode(_)));
    }

    #[test]
    fn graph_add_edge_unknown_target_fails() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        let err = g
            .add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .unwrap_err();
        assert!(matches!(err, AnalysisError::UnknownNode(_)));
    }

    #[test]
    fn graph_add_duplicate_edge_fails() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        let err = g
            .add_edge(make_edge("e1", "n1", "n2", EdgeKind::PropFlow))
            .unwrap_err();
        assert!(matches!(err, AnalysisError::DuplicateEdge(_)));
    }

    // -- Component registration tests --

    #[test]
    fn graph_register_component() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("App", &[]))
            .expect("serde deserialization should succeed");
        assert_eq!(g.component_count(), 1);
        assert!(g.get_component(&ComponentId::new("App")).is_some());
    }

    #[test]
    fn graph_register_duplicate_component_fails() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("App", &[]))
            .expect("serde deserialization should succeed");
        let err = g
            .register_component(make_component("App", &[]))
            .unwrap_err();
        assert!(matches!(err, AnalysisError::DuplicateComponent(_)));
    }

    #[test]
    fn graph_register_component_too_many_hooks() {
        let mut g = StaticAnalysisGraph::new();
        let mut desc = make_component("BigComp", &[]);
        for i in 0..257 {
            desc.hook_slots.push(make_hook_slot(i, HookKind::State));
        }
        let err = g.register_component(desc).unwrap_err();
        assert!(matches!(err, AnalysisError::HookSlotLimitExceeded { .. }));
    }

    // -- Adjacency / dependency tests --

    #[test]
    fn graph_outgoing_edges() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n3", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e2", "n1", "n3", EdgeKind::PropFlow))
            .expect("serde deserialization should succeed");
        let out = g
            .outgoing_edges(&AnalysisNodeId::new("n1"))
            .expect("serde deserialization should succeed");
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn graph_incoming_edges() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n3", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e1", "n1", "n3", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e2", "n2", "n3", EdgeKind::PropFlow))
            .expect("serde deserialization should succeed");
        let inc = g
            .incoming_edges(&AnalysisNodeId::new("n3"))
            .expect("serde deserialization should succeed");
        assert_eq!(inc.len(), 2);
    }

    #[test]
    fn graph_dependencies() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        let deps = g
            .dependencies(&AnalysisNodeId::new("n1"))
            .expect("serde deserialization should succeed");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0], AnalysisNodeId::new("n2"));
    }

    #[test]
    fn graph_dependents() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        let deps = g
            .dependents(&AnalysisNodeId::new("n2"))
            .expect("serde deserialization should succeed");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0], AnalysisNodeId::new("n1"));
    }

    // -- Component tree tests --

    #[test]
    fn graph_root_components() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("App", &["Header", "Body"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Header", &[]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Body", &["Footer"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Footer", &[]))
            .expect("serde deserialization should succeed");
        let roots = g.root_components();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], ComponentId::new("App"));
    }

    #[test]
    fn graph_leaf_components() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("App", &["Header", "Body"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Header", &[]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Body", &["Footer"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Footer", &[]))
            .expect("serde deserialization should succeed");
        let leaves = g.leaf_components();
        assert_eq!(leaves.len(), 2);
        // BTreeMap ordering gives alphabetical
        assert!(leaves.contains(&ComponentId::new("Footer")));
        assert!(leaves.contains(&ComponentId::new("Header")));
    }

    #[test]
    fn graph_component_ids() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("B", &[]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("A", &[]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("C", &[]))
            .expect("serde deserialization should succeed");
        let ids = g.component_ids();
        assert_eq!(ids.len(), 3);
        // BTreeMap → sorted
        assert_eq!(ids[0], ComponentId::new("A"));
        assert_eq!(ids[1], ComponentId::new("B"));
        assert_eq!(ids[2], ComponentId::new("C"));
    }

    // -- Cycle detection tests --

    #[test]
    fn graph_no_cycles() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("App", &["Child"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Child", &[]))
            .expect("serde deserialization should succeed");
        let cycles = g.detect_cycles();
        assert!(cycles.is_empty());
    }

    #[test]
    fn graph_simple_cycle() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("A", &["B"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("B", &["A"]))
            .expect("serde deserialization should succeed");
        let cycles = g.detect_cycles();
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0].cycle.len(), 2);
    }

    #[test]
    fn graph_three_node_cycle() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("A", &["B"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("B", &["C"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("C", &["A"]))
            .expect("serde deserialization should succeed");
        let cycles = g.detect_cycles();
        assert!(!cycles.is_empty());
    }

    #[test]
    fn graph_data_cycle_detection() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("A", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("B", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("A", &["B"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("B", &["A"]))
            .expect("serde deserialization should succeed");
        // Add a data flow edge
        g.add_edge(make_edge("e1", "A", "B", EdgeKind::PropFlow))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e2", "B", "A", EdgeKind::StateUpdateTrigger))
            .expect("serde deserialization should succeed");
        let cycles = g.detect_cycles();
        assert!(!cycles.is_empty());
        assert!(cycles[0].is_data_cycle);
    }

    // -- Capability computation tests --

    #[test]
    fn graph_transitive_capabilities_leaf() {
        let mut g = StaticAnalysisGraph::new();
        let mut desc = make_component("Leaf", &[]);
        desc.capability_boundary
            .direct_capabilities
            .insert("fs_read".to_string());
        g.register_component(desc)
            .expect("serde deserialization should succeed");
        g.compute_transitive_capabilities();
        let comp = g
            .get_component(&ComponentId::new("Leaf"))
            .expect("serde deserialization should succeed");
        assert!(comp.capability_boundary.transitive_capabilities.is_empty());
        assert!(
            comp.capability_boundary
                .direct_capabilities
                .contains("fs_read")
        );
    }

    #[test]
    fn graph_transitive_capabilities_parent() {
        let mut g = StaticAnalysisGraph::new();
        let mut child = make_component("Child", &[]);
        child
            .capability_boundary
            .direct_capabilities
            .insert("network".to_string());
        g.register_component(child)
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Parent", &["Child"]))
            .expect("serde deserialization should succeed");
        g.compute_transitive_capabilities();
        let parent = g
            .get_component(&ComponentId::new("Parent"))
            .expect("serde deserialization should succeed");
        assert!(
            parent
                .capability_boundary
                .transitive_capabilities
                .contains("network")
        );
    }

    #[test]
    fn graph_transitive_capabilities_deep() {
        let mut g = StaticAnalysisGraph::new();
        let mut leaf = make_component("Leaf", &[]);
        leaf.capability_boundary
            .direct_capabilities
            .insert("fs_write".to_string());
        g.register_component(leaf)
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Mid", &["Leaf"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Root", &["Mid"]))
            .expect("serde deserialization should succeed");
        g.compute_transitive_capabilities();
        let root = g
            .get_component(&ComponentId::new("Root"))
            .expect("serde deserialization should succeed");
        assert!(
            root.capability_boundary
                .transitive_capabilities
                .contains("fs_write")
        );
    }

    // -- Nodes by kind tests --

    #[test]
    fn graph_nodes_of_kind() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("c1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("c2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("h1", NodeKind::HookSlot))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("e1", NodeKind::EffectSite))
            .expect("serde deserialization should succeed");
        let components = g.nodes_of_kind(NodeKind::Component);
        assert_eq!(components.len(), 2);
        let hooks = g.nodes_of_kind(NodeKind::HookSlot);
        assert_eq!(hooks.len(), 1);
    }

    // -- Edges by kind tests --

    #[test]
    fn graph_edges_of_kind() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n3", NodeKind::DataSource))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e2", "n1", "n3", EdgeKind::EffectDependency))
            .expect("serde deserialization should succeed");
        let render_edges = g.edges_of_kind(EdgeKind::RendersChild);
        assert_eq!(render_edges.len(), 1);
    }

    // -- Edges between tests --

    #[test]
    fn graph_edges_between() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e2", "n1", "n2", EdgeKind::PropFlow))
            .expect("serde deserialization should succeed");
        let between = g.edges_between(&AnalysisNodeId::new("n1"), &AnalysisNodeId::new("n2"));
        assert_eq!(between.len(), 2);
    }

    #[test]
    fn graph_edges_between_no_match() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        let between = g.edges_between(&AnalysisNodeId::new("n1"), &AnalysisNodeId::new("n2"));
        assert!(between.is_empty());
    }

    // -- Reachability tests --

    #[test]
    fn graph_reachable_from_single() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        let reachable = g
            .reachable_from(&AnalysisNodeId::new("n1"))
            .expect("serde deserialization should succeed");
        assert_eq!(reachable.len(), 1);
    }

    #[test]
    fn graph_reachable_from_chain() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n3", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e2", "n2", "n3", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        let reachable = g
            .reachable_from(&AnalysisNodeId::new("n1"))
            .expect("serde deserialization should succeed");
        assert_eq!(reachable.len(), 3);
    }

    // -- Hook slot query tests --

    #[test]
    fn graph_hook_slots_for() {
        let mut g = StaticAnalysisGraph::new();
        let mut desc = make_component("Counter", &[]);
        desc.hook_slots.push(make_hook_slot(0, HookKind::State));
        desc.hook_slots.push(make_hook_slot(1, HookKind::Effect));
        g.register_component(desc)
            .expect("serde deserialization should succeed");
        let slots = g
            .hook_slots_for(&ComponentId::new("Counter"))
            .expect("serde deserialization should succeed");
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].kind, HookKind::State);
        assert_eq!(slots[1].kind, HookKind::Effect);
    }

    #[test]
    fn graph_hook_slots_for_unknown() {
        let g = StaticAnalysisGraph::new();
        assert!(g.hook_slots_for(&ComponentId::new("Unknown")).is_none());
    }

    // -- Capability requirement query tests --

    #[test]
    fn graph_components_requiring_capability() {
        let mut g = StaticAnalysisGraph::new();
        let mut desc1 = make_component("NetComp", &[]);
        desc1
            .capability_boundary
            .direct_capabilities
            .insert("network".to_string());
        let mut desc2 = make_component("FsComp", &[]);
        desc2
            .capability_boundary
            .direct_capabilities
            .insert("fs_read".to_string());
        let desc3 = make_component("PureComp", &[]);
        g.register_component(desc1)
            .expect("serde deserialization should succeed");
        g.register_component(desc2)
            .expect("serde deserialization should succeed");
        g.register_component(desc3)
            .expect("serde deserialization should succeed");
        let net = g.components_requiring_capability("network");
        assert_eq!(net.len(), 1);
        assert_eq!(net[0], ComponentId::new("NetComp"));
        let pure = g.components_requiring_capability("nonexistent");
        assert!(pure.is_empty());
    }

    // -- Summary tests --

    #[test]
    fn graph_summary_empty() {
        let g = StaticAnalysisGraph::new();
        let s = g.summary();
        assert_eq!(s.component_count, 0);
        assert_eq!(s.hook_slot_count, 0);
        assert_eq!(s.edge_count, 0);
        assert_eq!(s.purity_ratio_millionths, 0);
    }

    #[test]
    fn graph_summary_with_data() {
        let mut g = StaticAnalysisGraph::new();
        let mut desc = make_component("Counter", &[]);
        desc.hook_slots.push(make_hook_slot(0, HookKind::State));
        desc.is_pure = false;
        g.register_component(desc)
            .expect("serde deserialization should succeed");
        g.register_component(make_component("PureLeaf", &[]))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("eff1", NodeKind::EffectSite))
            .expect("serde deserialization should succeed");
        let s = g.summary();
        assert_eq!(s.component_count, 2);
        assert_eq!(s.hook_slot_count, 1);
        assert_eq!(s.effect_site_count, 1);
        assert_eq!(s.pure_component_count, 1);
        assert_eq!(s.stateful_component_count, 1);
        assert_eq!(s.purity_ratio_millionths, 500_000); // 1/2 = 0.5
    }

    #[test]
    fn graph_summary_max_depth() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("Root", &["Mid"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Mid", &["Leaf"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Leaf", &[]))
            .expect("serde deserialization should succeed");
        let s = g.summary();
        assert_eq!(s.max_depth, 2);
    }

    // -- Event audit trail tests --

    #[test]
    fn graph_events_tracked() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("App", &[]))
            .expect("serde deserialization should succeed");
        let events = g.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, AnalysisEventKind::NodeAdded);
        assert_eq!(events[1].kind, AnalysisEventKind::ComponentRegistered);
        assert_eq!(events[0].seq, 0);
        assert_eq!(events[1].seq, 1);
    }

    #[test]
    fn graph_event_serde_roundtrip() {
        let event = AnalysisEvent {
            seq: 42,
            kind: AnalysisEventKind::CycleDetected,
            entity_id: "comp_a".to_string(),
            detail: "3 components in cycle".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let back: AnalysisEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, back);
    }

    // -- Full graph serde roundtrip --

    #[test]
    fn graph_serde_roundtrip() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("n1", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_node(make_node("n2", NodeKind::Component))
            .expect("serde deserialization should succeed");
        g.add_edge(make_edge("e1", "n1", "n2", EdgeKind::RendersChild))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("App", &["Child"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Child", &[]))
            .expect("serde deserialization should succeed");
        let json = serde_json::to_string(&g).expect("serde deserialization should succeed");
        let back: StaticAnalysisGraph =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(g, back);
    }

    // -- AnalysisSummary serde --

    #[test]
    fn summary_serde_roundtrip() {
        let s = AnalysisSummary {
            component_count: 10,
            hook_slot_count: 25,
            effect_site_count: 5,
            edge_count: 30,
            pure_component_count: 7,
            stateful_component_count: 3,
            cycle_count: 0,
            max_depth: 4,
            distinct_capability_count: 2,
            purity_ratio_millionths: 700_000,
            snapshot_hash: make_hash(b"snapshot"),
        };
        let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
        let back: AnalysisSummary =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(s, back);
    }

    // -- Topological sort tests --

    #[test]
    fn graph_topological_sort_linear() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("A", &["B"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("B", &["C"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("C", &[]))
            .expect("serde deserialization should succeed");
        let order = g.topological_sort_components();
        assert_eq!(order, vec!["A", "B", "C"]);
    }

    #[test]
    fn graph_topological_sort_diamond() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("A", &["B", "C"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("B", &["D"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("C", &["D"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("D", &[]))
            .expect("serde deserialization should succeed");
        let order = g.topological_sort_components();
        // A must come first, D must come last, B and C can be in either order
        assert_eq!(order[0], "A");
        assert_eq!(order[3], "D");
    }

    // -- Components requiring capability with transitive --

    #[test]
    fn graph_transitive_caps_union() {
        let mut g = StaticAnalysisGraph::new();
        let mut c1 = make_component("Child1", &[]);
        c1.capability_boundary
            .direct_capabilities
            .insert("network".to_string());
        let mut c2 = make_component("Child2", &[]);
        c2.capability_boundary
            .direct_capabilities
            .insert("fs_read".to_string());
        g.register_component(c1)
            .expect("serde deserialization should succeed");
        g.register_component(c2)
            .expect("serde deserialization should succeed");
        g.register_component(make_component("Parent", &["Child1", "Child2"]))
            .expect("serde deserialization should succeed");
        g.compute_transitive_capabilities();
        let parent = g
            .get_component(&ComponentId::new("Parent"))
            .expect("serde deserialization should succeed");
        let trans = &parent.capability_boundary.transitive_capabilities;
        assert!(trans.contains("network"));
        assert!(trans.contains("fs_read"));
        assert_eq!(trans.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: AnalysisError display — remaining variants
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_error_display_edge_limit() {
        let e = AnalysisError::EdgeLimitExceeded {
            count: 500_001,
            max: 500_000,
        };
        let s = format!("{e}");
        assert!(s.contains("edge limit"));
        assert!(s.contains("500001"));
        assert!(s.contains("500000"));
    }

    #[test]
    fn analysis_error_display_hook_slot_limit() {
        let e = AnalysisError::HookSlotLimitExceeded {
            component: ComponentId::new("BigComp"),
            count: 300,
            max: 256,
        };
        let s = format!("{e}");
        assert!(s.contains("BigComp"));
        assert!(s.contains("300"));
        assert!(s.contains("256"));
    }

    #[test]
    fn analysis_error_display_duplicate_edge() {
        let e = AnalysisError::DuplicateEdge(AnalysisEdgeId::new("e1"));
        assert_eq!(format!("{e}"), "duplicate edge: e1");
    }

    #[test]
    fn analysis_error_display_unknown_component() {
        let e = AnalysisError::UnknownComponent(ComponentId::new("Missing"));
        assert_eq!(format!("{e}"), "unknown component: Missing");
    }

    #[test]
    fn analysis_error_display_cycle_detected() {
        let report = CycleReport {
            cycle: vec![ComponentId::new("A"), ComponentId::new("B")],
            edge_kinds: vec![EdgeKind::RendersChild],
            is_data_cycle: false,
        };
        let e = AnalysisError::CycleDetected(report);
        let s = format!("{e}");
        assert!(s.contains("cycle detected"));
        assert!(s.contains("2 components"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: AnalysisEventKind serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_event_kind_serde_roundtrip() {
        let variants = [
            AnalysisEventKind::NodeAdded,
            AnalysisEventKind::EdgeAdded,
            AnalysisEventKind::ComponentRegistered,
            AnalysisEventKind::CycleDetected,
            AnalysisEventKind::CapabilityBoundaryComputed,
            AnalysisEventKind::AnalysisFinalized,
        ];
        for kind in &variants {
            let json = serde_json::to_string(kind).expect("serde deserialization should succeed");
            let back: AnalysisEventKind =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*kind, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: AnalysisError serde — more variants
    // -----------------------------------------------------------------------

    #[test]
    fn analysis_error_serde_all_variants() {
        let report = CycleReport {
            cycle: vec![ComponentId::new("X"), ComponentId::new("Y")],
            edge_kinds: vec![EdgeKind::RendersChild],
            is_data_cycle: true,
        };
        let variants: Vec<AnalysisError> = vec![
            AnalysisError::NodeLimitExceeded {
                count: 100_001,
                max: 100_000,
            },
            AnalysisError::EdgeLimitExceeded {
                count: 500_001,
                max: 500_000,
            },
            AnalysisError::DuplicateNode(AnalysisNodeId::new("dup_n")),
            AnalysisError::DuplicateEdge(AnalysisEdgeId::new("dup_e")),
            AnalysisError::UnknownNode(AnalysisNodeId::new("unk_n")),
            AnalysisError::DuplicateComponent(ComponentId::new("DupComp")),
            AnalysisError::UnknownComponent(ComponentId::new("UnkComp")),
            AnalysisError::CycleDetected(report),
        ];
        for err in &variants {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let back: AnalysisError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: DependencyPath serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn dependency_path_serde_roundtrip() {
        let path = DependencyPath {
            components: vec![ComponentId::new("A"), ComponentId::new("B")],
            total_weight_millionths: 2 * MILLION,
            edge_kinds: vec![EdgeKind::RendersChild],
        };
        let json = serde_json::to_string(&path).expect("serde deserialization should succeed");
        let back: DependencyPath =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(path, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display uniqueness for all enum variants
    // -----------------------------------------------------------------------

    #[test]
    fn node_kind_display_all_unique() {
        let variants = [
            NodeKind::Component,
            NodeKind::HookSlot,
            NodeKind::EffectSite,
            NodeKind::DataSource,
            NodeKind::DataSink,
            NodeKind::ModuleBoundary,
            NodeKind::CapabilityGate,
            NodeKind::ScopeBoundary,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn edge_kind_display_all_unique() {
        let variants = [
            EdgeKind::RendersChild,
            EdgeKind::PropFlow,
            EdgeKind::HookDataFlow,
            EdgeKind::EffectDependency,
            EdgeKind::ImportDependency,
            EdgeKind::ContextFlow,
            EdgeKind::CallbackFlow,
            EdgeKind::CapabilityRequirement,
            EdgeKind::ScopeContainment,
            EdgeKind::StateUpdateTrigger,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn hook_kind_display_all_unique() {
        let variants = [
            HookKind::State,
            HookKind::Effect,
            HookKind::LayoutEffect,
            HookKind::Memo,
            HookKind::Callback,
            HookKind::Ref,
            HookKind::Context,
            HookKind::ImperativeHandle,
            HookKind::Custom,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn analysis_event_kind_display_all_unique() {
        let variants = [
            AnalysisEventKind::NodeAdded,
            AnalysisEventKind::EdgeAdded,
            AnalysisEventKind::ComponentRegistered,
            AnalysisEventKind::CycleDetected,
            AnalysisEventKind::CapabilityBoundaryComputed,
            AnalysisEventKind::AnalysisFinalized,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(set.len(), variants.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: HookSlot Context and Custom kind classification
    // -----------------------------------------------------------------------

    #[test]
    fn hook_slot_context_is_neutral() {
        let slot = make_hook_slot(7, HookKind::Context);
        assert!(!slot.is_stateful());
        assert!(!slot.has_side_effects());
        assert!(!slot.is_memoized());
    }

    #[test]
    fn hook_slot_custom_is_neutral() {
        let slot = make_hook_slot(8, HookKind::Custom);
        assert!(!slot.is_stateful());
        assert!(!slot.has_side_effects());
        assert!(!slot.is_memoized());
    }

    // -----------------------------------------------------------------------
    // Enrichment: cycles() accessor after detect_cycles
    // -----------------------------------------------------------------------

    #[test]
    fn graph_cycles_accessor_after_detection() {
        let mut g = StaticAnalysisGraph::new();
        g.register_component(make_component("A", &["B"]))
            .expect("serde deserialization should succeed");
        g.register_component(make_component("B", &["A"]))
            .expect("serde deserialization should succeed");
        assert!(g.cycles().is_empty()); // before detection
        let detected = g.detect_cycles();
        assert!(!detected.is_empty());
        assert_eq!(g.cycles().len(), detected.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: outgoing/incoming edges for isolated node
    // -----------------------------------------------------------------------

    #[test]
    fn graph_outgoing_edges_isolated_node() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("isolated", NodeKind::Component))
            .expect("serde deserialization should succeed");
        let out = g
            .outgoing_edges(&AnalysisNodeId::new("isolated"))
            .expect("serde deserialization should succeed");
        assert!(out.is_empty());
    }

    #[test]
    fn graph_incoming_edges_isolated_node() {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(make_node("isolated", NodeKind::Component))
            .expect("serde deserialization should succeed");
        let inc = g
            .incoming_edges(&AnalysisNodeId::new("isolated"))
            .expect("serde deserialization should succeed");
        assert!(inc.is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: get_node/get_edge/get_component for nonexistent keys
    // -----------------------------------------------------------------------

    #[test]
    fn graph_get_nonexistent_returns_none() {
        let g = StaticAnalysisGraph::new();
        assert!(g.get_node(&AnalysisNodeId::new("nope")).is_none());
        assert!(g.get_edge(&AnalysisEdgeId::new("nope")).is_none());
        assert!(g.get_component(&ComponentId::new("nope")).is_none());
    }

    // -----------------------------------------------------------------------
    // Enrichment: EffectClassification serde with capabilities
    // -----------------------------------------------------------------------

    #[test]
    fn effect_classification_with_caps_serde_roundtrip() {
        let mut caps = BTreeSet::new();
        caps.insert("network".to_string());
        caps.insert("dom".to_string());
        let eff = EffectClassification {
            boundary: EffectBoundary::NetworkEffect,
            required_capabilities: caps,
            idempotent: false,
            commutative: false,
            estimated_cost_millionths: 750_000,
        };
        let json = serde_json::to_string(&eff).expect("serde deserialization should succeed");
        let back: EffectClassification =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(eff, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DependencyPath with single component has depth 0
    // -----------------------------------------------------------------------

    #[test]
    fn dependency_path_single_component() {
        let path = DependencyPath {
            components: vec![ComponentId::new("Solo")],
            total_weight_millionths: 0,
            edge_kinds: Vec::new(),
        };
        assert_eq!(path.depth(), 0);
        assert!(path.contains(&ComponentId::new("Solo")));
    }

    // -----------------------------------------------------------------------
    // Enrichment: graph summary distinct_capability_count
    // -----------------------------------------------------------------------

    #[test]
    fn graph_summary_distinct_capabilities() {
        let mut g = StaticAnalysisGraph::new();
        let mut c1 = make_component("Net", &[]);
        c1.capability_boundary
            .direct_capabilities
            .insert("network".to_string());
        let mut c2 = make_component("Fs", &[]);
        c2.capability_boundary
            .direct_capabilities
            .insert("fs_read".to_string());
        c2.capability_boundary
            .direct_capabilities
            .insert("network".to_string()); // duplicate
        g.register_component(c1)
            .expect("serde deserialization should succeed");
        g.register_component(c2)
            .expect("serde deserialization should succeed");
        let s = g.summary();
        assert_eq!(s.distinct_capability_count, 2); // network + fs_read
    }

    // -----------------------------------------------------------------------
    // Enrichment: CapabilityBoundary overlapping direct/transitive
    // -----------------------------------------------------------------------

    #[test]
    fn capability_boundary_all_deduplicates() {
        let mut cb = CapabilityBoundary::pure_component();
        cb.direct_capabilities.insert("network".to_string());
        cb.transitive_capabilities.insert("network".to_string()); // same
        cb.transitive_capabilities.insert("fs".to_string());
        let all = cb.all_capabilities();
        assert_eq!(all.len(), 2); // network + fs, no duplicates
    }
}
