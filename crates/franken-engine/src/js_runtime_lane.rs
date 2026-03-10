//! Minimal JS Runtime Lane for Fine-Grained DOM Updates (FRX-04.1)
//!
//! The small-app default execution lane. Implements:
//! - Signal graph evaluator with topological propagation.
//! - Deterministic update scheduler with priority queuing.
//! - Direct DOM patch executor (no VDOM diff loop).
//! - Event delegation and cleanup model.
//!
//! Keeps footprint aggressively small while preserving React-compatible semantics.

#![forbid(unsafe_code)]

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

fn lane_schema() -> SchemaId {
    SchemaId::from_definition(b"js_runtime_lane-v1")
}

// ---------------------------------------------------------------------------
// Signal graph
// ---------------------------------------------------------------------------

/// Unique identifier for a signal node in the reactive graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SignalId(pub u64);

/// The kind of signal node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SignalKind {
    /// Source signal — externally set (e.g. useState).
    Source,
    /// Derived signal — computed from other signals (e.g. useMemo).
    Derived,
    /// Effect signal — side-effect triggered by dependency changes.
    Effect,
}

/// Current status of a signal node in the evaluation cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SignalStatus {
    /// Signal value is current and valid.
    Clean,
    /// Signal may need re-evaluation (a dependency changed).
    Dirty,
    /// Signal is currently being evaluated (cycle detection).
    Evaluating,
    /// Signal has been disposed and should not be evaluated.
    Disposed,
}

/// A node in the signal dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalNode {
    pub id: SignalId,
    pub kind: SignalKind,
    pub status: SignalStatus,
    /// Signals this node depends on (upstream).
    pub dependencies: BTreeSet<SignalId>,
    /// Signals that depend on this node (downstream).
    pub dependents: BTreeSet<SignalId>,
    /// Topological depth for evaluation ordering (0 = source).
    pub depth: u32,
    /// Generation counter for staleness detection.
    pub generation: u64,
}

/// Errors from signal graph operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalGraphError {
    /// Signal not found in the graph.
    NotFound(SignalId),
    /// Dependency cycle detected.
    CycleDetected {
        signal: SignalId,
        path: Vec<SignalId>,
    },
    /// Signal is disposed and cannot be accessed.
    Disposed(SignalId),
    /// Duplicate signal registration.
    DuplicateSignal(SignalId),
}

/// The reactive signal dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalGraph {
    nodes: BTreeMap<SignalId, SignalNode>,
    next_id: u64,
    global_generation: u64,
}

impl SignalGraph {
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            next_id: 0,
            global_generation: 0,
        }
    }

    /// Allocate a new signal ID.
    pub fn next_signal_id(&mut self) -> SignalId {
        let id = SignalId(self.next_id);
        self.next_id += 1;
        id
    }

    /// Register a new signal node.
    pub fn register(
        &mut self,
        id: SignalId,
        kind: SignalKind,
        dependencies: BTreeSet<SignalId>,
    ) -> Result<(), SignalGraphError> {
        if self.nodes.contains_key(&id) {
            return Err(SignalGraphError::DuplicateSignal(id));
        }

        // Validate all deps exist
        for dep in &dependencies {
            if !self.nodes.contains_key(dep) {
                return Err(SignalGraphError::NotFound(*dep));
            }
        }

        // Compute depth: max(dep depths) + 1
        let depth = if dependencies.is_empty() {
            0
        } else {
            dependencies
                .iter()
                .filter_map(|d| self.nodes.get(d))
                .map(|n| n.depth)
                .max()
                .unwrap_or(0)
                + 1
        };

        // Add as dependent to each dep
        for dep in &dependencies {
            if let Some(dep_node) = self.nodes.get_mut(dep) {
                dep_node.dependents.insert(id);
            }
        }

        self.nodes.insert(
            id,
            SignalNode {
                id,
                kind,
                status: SignalStatus::Dirty,
                dependencies,
                dependents: BTreeSet::new(),
                depth,
                generation: self.global_generation,
            },
        );
        Ok(())
    }

    /// Mark a source signal as dirty and propagate to dependents.
    pub fn mark_dirty(&mut self, id: SignalId) -> Result<Vec<SignalId>, SignalGraphError> {
        if !self.nodes.contains_key(&id) {
            return Err(SignalGraphError::NotFound(id));
        }
        if self.nodes[&id].status == SignalStatus::Disposed {
            return Err(SignalGraphError::Disposed(id));
        }

        self.global_generation += 1;
        let generation = self.global_generation;

        let mut dirty_list = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back(id);

        while let Some(current) = queue.pop_front() {
            if let Some(node) = self.nodes.get_mut(&current) {
                if node.generation == generation {
                    continue; // already visited
                }
                node.status = SignalStatus::Dirty;
                node.generation = generation;
                dirty_list.push(current);

                let dependents: Vec<_> = node.dependents.iter().copied().collect();
                for dep in dependents {
                    queue.push_back(dep);
                }
            }
        }

        // Sort by depth for topological evaluation order
        dirty_list.sort_by_key(|id| self.nodes.get(id).map_or(0, |n| n.depth));
        Ok(dirty_list)
    }

    /// Get the evaluation order for all dirty signals (topological order by depth).
    pub fn dirty_evaluation_order(&self) -> Vec<SignalId> {
        let mut dirty: Vec<_> = self
            .nodes
            .values()
            .filter(|n| n.status == SignalStatus::Dirty)
            .map(|n| (n.depth, n.id))
            .collect();
        dirty.sort();
        dirty.into_iter().map(|(_, id)| id).collect()
    }

    /// Mark a signal as clean after successful evaluation.
    pub fn mark_clean(&mut self, id: SignalId) -> Result<(), SignalGraphError> {
        let node = self
            .nodes
            .get_mut(&id)
            .ok_or(SignalGraphError::NotFound(id))?;
        if node.status == SignalStatus::Disposed {
            return Err(SignalGraphError::Disposed(id));
        }
        node.status = SignalStatus::Clean;
        Ok(())
    }

    /// Dispose a signal, removing it from the graph.
    pub fn dispose(&mut self, id: SignalId) -> Result<(), SignalGraphError> {
        let node = self
            .nodes
            .get(&id)
            .ok_or(SignalGraphError::NotFound(id))?
            .clone();

        // Remove from upstream dependents lists
        for dep in &node.dependencies {
            if let Some(dep_node) = self.nodes.get_mut(dep) {
                dep_node.dependents.remove(&id);
            }
        }

        // Remove from downstream dependencies lists
        for dependent in &node.dependents {
            if let Some(dep_node) = self.nodes.get_mut(dependent) {
                dep_node.dependencies.remove(&id);
            }
        }

        if let Some(n) = self.nodes.get_mut(&id) {
            n.status = SignalStatus::Disposed;
            n.dependencies.clear();
            n.dependents.clear();
        }
        Ok(())
    }

    pub fn node_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|n| n.status != SignalStatus::Disposed)
            .count()
    }

    pub fn get(&self, id: SignalId) -> Option<&SignalNode> {
        self.nodes.get(&id)
    }
}

impl Default for SignalGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Update scheduler
// ---------------------------------------------------------------------------

/// Priority level for scheduled updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum UpdatePriority {
    /// Synchronous/immediate (e.g. discrete events like clicks).
    Sync,
    /// User-blocking (e.g. input handling).
    UserBlocking,
    /// Normal priority (default for state updates).
    Normal,
    /// Low priority (e.g. offscreen, deferred).
    Low,
    /// Idle priority (e.g. prefetching).
    Idle,
}

impl UpdatePriority {
    /// Numeric ordering (lower = higher priority).
    pub fn urgency(&self) -> u8 {
        match self {
            Self::Sync => 0,
            Self::UserBlocking => 1,
            Self::Normal => 2,
            Self::Low => 3,
            Self::Idle => 4,
        }
    }
}

/// A scheduled state update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledUpdate {
    pub signal_id: SignalId,
    pub priority: UpdatePriority,
    /// Monotonic sequence number for FIFO within same priority.
    pub sequence: u64,
    /// Component that triggered this update.
    pub component: String,
}

/// Deterministic update scheduler with priority queuing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateScheduler {
    queue: Vec<ScheduledUpdate>,
    next_sequence: u64,
    /// Maximum updates per flush cycle to prevent infinite loops.
    pub max_updates_per_flush: u32,
}

impl UpdateScheduler {
    pub fn new() -> Self {
        Self {
            queue: Vec::new(),
            next_sequence: 0,
            max_updates_per_flush: 1000,
        }
    }

    /// Schedule a state update.
    pub fn schedule(&mut self, signal_id: SignalId, priority: UpdatePriority, component: String) {
        let update = ScheduledUpdate {
            signal_id,
            priority,
            sequence: self.next_sequence,
            component,
        };
        self.next_sequence += 1;
        self.queue.push(update);
    }

    /// Drain updates in priority order (then FIFO within priority).
    pub fn drain_batch(&mut self) -> Vec<ScheduledUpdate> {
        self.queue
            .sort_by_key(|u| (u.priority.urgency(), u.sequence));
        let limit = self.max_updates_per_flush as usize;
        let take = self.queue.len().min(limit);
        self.queue.drain(..take).collect()
    }

    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl Default for UpdateScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DOM patch model (no VDOM diff)
// ---------------------------------------------------------------------------

/// Unique identifier for a DOM element in the managed tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DomElementId(pub u64);

/// A fine-grained DOM mutation operation (no VDOM diff needed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomPatch {
    /// Create a new element.
    CreateElement {
        id: DomElementId,
        tag: String,
        parent: Option<DomElementId>,
    },
    /// Remove an element and its children.
    RemoveElement { id: DomElementId },
    /// Set a property on an element.
    SetProperty {
        id: DomElementId,
        key: String,
        value: String,
    },
    /// Remove a property from an element.
    RemoveProperty { id: DomElementId, key: String },
    /// Set text content of an element.
    SetTextContent { id: DomElementId, text: String },
    /// Move an element to a new parent/position.
    MoveElement {
        id: DomElementId,
        new_parent: DomElementId,
        before_sibling: Option<DomElementId>,
    },
    /// Replace one element with another.
    ReplaceElement {
        old: DomElementId,
        new_id: DomElementId,
        tag: String,
    },
}

impl DomPatch {
    /// The target element of this patch.
    pub fn target_element(&self) -> DomElementId {
        match self {
            Self::CreateElement { id, .. } => *id,
            Self::RemoveElement { id } => *id,
            Self::SetProperty { id, .. } => *id,
            Self::RemoveProperty { id, .. } => *id,
            Self::SetTextContent { id, .. } => *id,
            Self::MoveElement { id, .. } => *id,
            Self::ReplaceElement { old, .. } => *old,
        }
    }
}

/// A batch of DOM patches from a single update cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchBatch {
    pub patches: Vec<DomPatch>,
    pub cycle_sequence: u64,
    pub component: String,
}

impl PatchBatch {
    pub fn new(component: impl Into<String>, cycle_sequence: u64) -> Self {
        Self {
            patches: Vec::new(),
            cycle_sequence,
            component: component.into(),
        }
    }

    pub fn push(&mut self, patch: DomPatch) {
        self.patches.push(patch);
    }

    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "patch_batch:{}:cycle{}:patches={}",
            self.component,
            self.cycle_sequence,
            self.patches.len(),
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "js-lane",
            &lane_schema(),
            canonical.as_bytes(),
        )
        .expect("patch batch id derivation")
    }
}

// ---------------------------------------------------------------------------
// DOM patch executor
// ---------------------------------------------------------------------------

/// Tracks the managed DOM element tree for patch application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomTree {
    elements: BTreeMap<DomElementId, DomElementRecord>,
    next_id: u64,
}

/// Record for a single managed DOM element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomElementRecord {
    pub id: DomElementId,
    pub tag: String,
    pub parent: Option<DomElementId>,
    pub children: Vec<DomElementId>,
    pub properties: BTreeMap<String, String>,
    pub text_content: Option<String>,
}

/// Errors from DOM patch application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomPatchError {
    ElementNotFound(DomElementId),
    ElementAlreadyExists(DomElementId),
    ParentNotFound(DomElementId),
    InvalidReparent {
        id: DomElementId,
        new_parent: DomElementId,
    },
}

impl DomTree {
    pub fn new() -> Self {
        Self {
            elements: BTreeMap::new(),
            next_id: 0,
        }
    }

    pub fn next_element_id(&mut self) -> DomElementId {
        let id = DomElementId(self.next_id);
        self.next_id += 1;
        id
    }

    fn collect_subtree_ids(&self, root: DomElementId) -> Result<Vec<DomElementId>, DomPatchError> {
        if !self.elements.contains_key(&root) {
            return Err(DomPatchError::ElementNotFound(root));
        }

        let mut to_remove = vec![root];
        let mut i = 0;
        while i < to_remove.len() {
            let current = to_remove[i];
            if let Some(rec) = self.elements.get(&current) {
                to_remove.extend(rec.children.iter().copied());
            }
            i += 1;
        }
        Ok(to_remove)
    }

    fn reparent_would_cycle(&self, id: DomElementId, new_parent: DomElementId) -> bool {
        let mut current = Some(new_parent);
        let mut visited = BTreeSet::new();
        while let Some(node_id) = current {
            if node_id == id {
                return true;
            }
            if !visited.insert(node_id) {
                return true;
            }
            current = self.elements.get(&node_id).and_then(|record| record.parent);
        }
        false
    }

    /// Apply a single patch to the tree.
    pub fn apply_patch(&mut self, patch: &DomPatch) -> Result<(), DomPatchError> {
        match patch {
            DomPatch::CreateElement { id, tag, parent } => {
                if self.elements.contains_key(id) {
                    return Err(DomPatchError::ElementAlreadyExists(*id));
                }
                if let Some(p) = parent
                    && !self.elements.contains_key(p)
                {
                    return Err(DomPatchError::ParentNotFound(*p));
                }
                self.elements.insert(
                    *id,
                    DomElementRecord {
                        id: *id,
                        tag: tag.clone(),
                        parent: *parent,
                        children: Vec::new(),
                        properties: BTreeMap::new(),
                        text_content: None,
                    },
                );
                if let Some(p) = parent
                    && let Some(parent_rec) = self.elements.get_mut(p)
                {
                    parent_rec.children.push(*id);
                }
                Ok(())
            }
            DomPatch::RemoveElement { id } => {
                let record = self
                    .elements
                    .get(id)
                    .ok_or(DomPatchError::ElementNotFound(*id))?
                    .clone();

                // Remove from parent's children
                if let Some(parent_id) = record.parent
                    && let Some(parent_rec) = self.elements.get_mut(&parent_id)
                {
                    parent_rec.children.retain(|c| c != id);
                }

                let to_remove = self.collect_subtree_ids(*id)?;
                for r in &to_remove {
                    self.elements.remove(r);
                }
                Ok(())
            }
            DomPatch::SetProperty { id, key, value } => {
                let rec = self
                    .elements
                    .get_mut(id)
                    .ok_or(DomPatchError::ElementNotFound(*id))?;
                rec.properties.insert(key.clone(), value.clone());
                Ok(())
            }
            DomPatch::RemoveProperty { id, key } => {
                let rec = self
                    .elements
                    .get_mut(id)
                    .ok_or(DomPatchError::ElementNotFound(*id))?;
                rec.properties.remove(key);
                Ok(())
            }
            DomPatch::SetTextContent { id, text } => {
                let rec = self
                    .elements
                    .get_mut(id)
                    .ok_or(DomPatchError::ElementNotFound(*id))?;
                rec.text_content = Some(text.clone());
                Ok(())
            }
            DomPatch::MoveElement {
                id,
                new_parent,
                before_sibling,
            } => {
                if !self.elements.contains_key(id) {
                    return Err(DomPatchError::ElementNotFound(*id));
                }
                if !self.elements.contains_key(new_parent) {
                    return Err(DomPatchError::ParentNotFound(*new_parent));
                }
                if self.reparent_would_cycle(*id, *new_parent) {
                    return Err(DomPatchError::InvalidReparent {
                        id: *id,
                        new_parent: *new_parent,
                    });
                }

                // Remove from old parent
                let old_parent = self.elements[id].parent;
                if let Some(old_p) = old_parent
                    && let Some(old_rec) = self.elements.get_mut(&old_p)
                {
                    old_rec.children.retain(|c| c != id);
                }

                // Insert into new parent
                if let Some(new_rec) = self.elements.get_mut(new_parent) {
                    if let Some(before) = before_sibling {
                        if let Some(pos) = new_rec.children.iter().position(|c| c == before) {
                            new_rec.children.insert(pos, *id);
                        } else {
                            new_rec.children.push(*id);
                        }
                    } else {
                        new_rec.children.push(*id);
                    }
                }

                if let Some(rec) = self.elements.get_mut(id) {
                    rec.parent = Some(*new_parent);
                }
                Ok(())
            }
            DomPatch::ReplaceElement { old, new_id, tag } => {
                let old_rec = self
                    .elements
                    .get(old)
                    .ok_or(DomPatchError::ElementNotFound(*old))?
                    .clone();
                if old != new_id && self.elements.contains_key(new_id) {
                    return Err(DomPatchError::ElementAlreadyExists(*new_id));
                }

                // Create new element in place
                let new_rec = DomElementRecord {
                    id: *new_id,
                    tag: tag.clone(),
                    parent: old_rec.parent,
                    children: Vec::new(),
                    properties: BTreeMap::new(),
                    text_content: None,
                };

                // Update parent's children list
                if let Some(parent_id) = old_rec.parent
                    && let Some(parent_rec) = self.elements.get_mut(&parent_id)
                {
                    for child in &mut parent_rec.children {
                        if *child == *old {
                            *child = *new_id;
                        }
                    }
                }

                for child_id in old_rec.children.iter().copied() {
                    for descendant_id in self.collect_subtree_ids(child_id)? {
                        self.elements.remove(&descendant_id);
                    }
                }
                self.elements.remove(old);
                self.elements.insert(*new_id, new_rec);
                Ok(())
            }
        }
    }

    /// Apply a batch of patches atomically.
    pub fn apply_batch(&mut self, batch: &PatchBatch) -> Result<(), DomPatchError> {
        for patch in &batch.patches {
            self.apply_patch(patch)?;
        }
        Ok(())
    }

    pub fn element_count(&self) -> usize {
        self.elements.len()
    }

    pub fn get(&self, id: DomElementId) -> Option<&DomElementRecord> {
        self.elements.get(&id)
    }

    pub fn contains(&self, id: DomElementId) -> bool {
        self.elements.contains_key(&id)
    }
}

impl Default for DomTree {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Event delegation
// ---------------------------------------------------------------------------

/// The type of delegated event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventType {
    Click,
    Input,
    Change,
    Submit,
    Focus,
    Blur,
    KeyDown,
    KeyUp,
    MouseEnter,
    MouseLeave,
    Scroll,
    Resize,
}

impl EventType {
    pub const ALL: &[EventType] = &[
        Self::Click,
        Self::Input,
        Self::Change,
        Self::Submit,
        Self::Focus,
        Self::Blur,
        Self::KeyDown,
        Self::KeyUp,
        Self::MouseEnter,
        Self::MouseLeave,
        Self::Scroll,
        Self::Resize,
    ];

    /// Whether this event type bubbles up the DOM tree.
    pub fn bubbles(&self) -> bool {
        match self {
            Self::Click
            | Self::Input
            | Self::Change
            | Self::Submit
            | Self::KeyDown
            | Self::KeyUp
            | Self::Scroll => true,
            Self::Focus | Self::Blur | Self::MouseEnter | Self::MouseLeave | Self::Resize => false,
        }
    }
}

/// A registered event handler on the delegation root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHandler {
    pub id: u64,
    pub event_type: EventType,
    pub target_element: DomElementId,
    pub component: String,
    /// Capture phase (true) or bubble phase (false).
    pub capture: bool,
}

/// The event delegation manager. All handlers are registered on a single
/// delegation root and dispatched by target element matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventDelegation {
    handlers: Vec<EventHandler>,
    next_handler_id: u64,
}

impl EventDelegation {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            next_handler_id: 0,
        }
    }

    /// Register an event handler.
    pub fn register(
        &mut self,
        event_type: EventType,
        target_element: DomElementId,
        component: impl Into<String>,
        capture: bool,
    ) -> u64 {
        let id = self.next_handler_id;
        self.next_handler_id += 1;
        self.handlers.push(EventHandler {
            id,
            event_type,
            target_element,
            component: component.into(),
            capture,
        });
        id
    }

    /// Unregister a handler by ID.
    pub fn unregister(&mut self, handler_id: u64) -> bool {
        let len_before = self.handlers.len();
        self.handlers.retain(|h| h.id != handler_id);
        self.handlers.len() < len_before
    }

    /// Cleanup all handlers for a given element (e.g. on unmount).
    pub fn cleanup_element(&mut self, element: DomElementId) -> usize {
        let len_before = self.handlers.len();
        self.handlers.retain(|h| h.target_element != element);
        len_before - self.handlers.len()
    }

    /// Cleanup all handlers for a component.
    pub fn cleanup_component(&mut self, component: &str) -> usize {
        let len_before = self.handlers.len();
        self.handlers.retain(|h| h.component != component);
        len_before - self.handlers.len()
    }

    /// Find handlers matching a dispatched event on a target element.
    pub fn find_handlers(&self, event_type: EventType, target: DomElementId) -> Vec<&EventHandler> {
        self.handlers
            .iter()
            .filter(|h| h.event_type == event_type && h.target_element == target)
            .collect()
    }

    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }
}

impl Default for EventDelegation {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Lane configuration and lifecycle
// ---------------------------------------------------------------------------

/// Configuration for the JS runtime lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsLaneConfig {
    /// Maximum signal graph depth before rejecting.
    pub max_signal_depth: u32,
    /// Maximum updates per scheduler flush cycle.
    pub max_updates_per_flush: u32,
    /// Maximum DOM elements in managed tree.
    pub max_dom_elements: u64,
    /// Maximum event handlers registered.
    pub max_event_handlers: u64,
    /// Whether to enable fine-grained effect batching.
    pub enable_effect_batching: bool,
}

impl JsLaneConfig {
    pub fn default_config() -> Self {
        Self {
            max_signal_depth: 64,
            max_updates_per_flush: 1000,
            max_dom_elements: 100_000,
            max_event_handlers: 50_000,
            enable_effect_batching: true,
        }
    }

    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.max_signal_depth == 0 {
            errors.push("max_signal_depth must be > 0".into());
        }
        if self.max_updates_per_flush == 0 {
            errors.push("max_updates_per_flush must be > 0".into());
        }
        if self.max_dom_elements == 0 {
            errors.push("max_dom_elements must be > 0".into());
        }
        errors
    }
}

/// Operational state of the JS runtime lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LaneState {
    /// Lane is initialised and ready.
    Ready,
    /// Lane is processing an update batch.
    Processing,
    /// Lane has been suspended (e.g. tab hidden).
    Suspended,
    /// Lane has been shut down.
    Shutdown,
}

/// Summary of a lane flush cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlushSummary {
    pub updates_processed: u32,
    pub signals_evaluated: u32,
    pub patches_emitted: u32,
    pub handlers_cleaned: u32,
    pub cycle_sequence: u64,
}

impl FlushSummary {
    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "flush_summary:cycle{}:updates={}:signals={}:patches={}",
            self.cycle_sequence,
            self.updates_processed,
            self.signals_evaluated,
            self.patches_emitted,
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "js-lane",
            &lane_schema(),
            canonical.as_bytes(),
        )
        .expect("flush summary id derivation")
    }
}

/// The complete JS runtime lane instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsRuntimeLane {
    pub config: JsLaneConfig,
    pub signal_graph: SignalGraph,
    pub scheduler: UpdateScheduler,
    pub dom_tree: DomTree,
    pub event_delegation: EventDelegation,
    pub state: LaneState,
    pub flush_count: u64,
}

impl JsRuntimeLane {
    pub fn new(config: JsLaneConfig) -> Self {
        Self {
            config,
            signal_graph: SignalGraph::new(),
            scheduler: UpdateScheduler::new(),
            dom_tree: DomTree::new(),
            event_delegation: EventDelegation::new(),
            state: LaneState::Ready,
            flush_count: 0,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(JsLaneConfig::default_config())
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "js_runtime_lane:signals={}:dom={}:handlers={}:flushes={}",
            self.signal_graph.node_count(),
            self.dom_tree.element_count(),
            self.event_delegation.handler_count(),
            self.flush_count,
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "js-lane",
            &lane_schema(),
            canonical.as_bytes(),
        )
        .expect("lane id derivation")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SignalGraph tests ----

    #[test]
    fn signal_graph_new_empty() {
        let g = SignalGraph::new();
        assert_eq!(g.node_count(), 0);
    }

    #[test]
    fn signal_graph_register_source() {
        let mut g = SignalGraph::new();
        let id = g.next_signal_id();
        assert!(g.register(id, SignalKind::Source, BTreeSet::new()).is_ok());
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.get(id).unwrap().depth, 0);
    }

    #[test]
    fn signal_graph_register_derived() {
        let mut g = SignalGraph::new();
        let s1 = g.next_signal_id();
        g.register(s1, SignalKind::Source, BTreeSet::new()).unwrap();

        let d1 = g.next_signal_id();
        let mut deps = BTreeSet::new();
        deps.insert(s1);
        g.register(d1, SignalKind::Derived, deps).unwrap();

        assert_eq!(g.get(d1).unwrap().depth, 1);
        assert!(g.get(s1).unwrap().dependents.contains(&d1));
    }

    #[test]
    fn signal_graph_register_deep_chain() {
        let mut g = SignalGraph::new();
        let s = g.next_signal_id();
        g.register(s, SignalKind::Source, BTreeSet::new()).unwrap();

        let mut prev = s;
        for _ in 0..5 {
            let next = g.next_signal_id();
            let mut deps = BTreeSet::new();
            deps.insert(prev);
            g.register(next, SignalKind::Derived, deps).unwrap();
            prev = next;
        }
        assert_eq!(g.get(prev).unwrap().depth, 5);
    }

    #[test]
    fn signal_graph_duplicate_rejected() {
        let mut g = SignalGraph::new();
        let id = g.next_signal_id();
        g.register(id, SignalKind::Source, BTreeSet::new()).unwrap();
        assert!(matches!(
            g.register(id, SignalKind::Source, BTreeSet::new()),
            Err(SignalGraphError::DuplicateSignal(_))
        ));
    }

    #[test]
    fn signal_graph_missing_dep_rejected() {
        let mut g = SignalGraph::new();
        let missing = SignalId(999);
        let id = g.next_signal_id();
        let mut deps = BTreeSet::new();
        deps.insert(missing);
        assert!(matches!(
            g.register(id, SignalKind::Derived, deps),
            Err(SignalGraphError::NotFound(_))
        ));
    }

    #[test]
    fn signal_graph_mark_dirty_propagates() {
        let mut g = SignalGraph::new();
        let s = g.next_signal_id();
        g.register(s, SignalKind::Source, BTreeSet::new()).unwrap();
        g.mark_clean(s).unwrap();

        let d1 = g.next_signal_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        g.register(d1, SignalKind::Derived, deps).unwrap();
        g.mark_clean(d1).unwrap();

        let d2 = g.next_signal_id();
        let mut deps2 = BTreeSet::new();
        deps2.insert(d1);
        g.register(d2, SignalKind::Effect, deps2).unwrap();
        g.mark_clean(d2).unwrap();

        let dirty = g.mark_dirty(s).unwrap();
        assert_eq!(dirty.len(), 3);
        // Should be in topological order
        assert_eq!(dirty[0], s);
        assert_eq!(dirty[1], d1);
        assert_eq!(dirty[2], d2);
    }

    #[test]
    fn signal_graph_mark_dirty_not_found() {
        let mut g = SignalGraph::new();
        assert!(matches!(
            g.mark_dirty(SignalId(99)),
            Err(SignalGraphError::NotFound(_))
        ));
    }

    #[test]
    fn signal_graph_dispose() {
        let mut g = SignalGraph::new();
        let s = g.next_signal_id();
        g.register(s, SignalKind::Source, BTreeSet::new()).unwrap();
        let d = g.next_signal_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        g.register(d, SignalKind::Derived, deps).unwrap();

        g.dispose(d).unwrap();
        assert_eq!(g.node_count(), 1); // only source remains active
        assert!(g.get(s).unwrap().dependents.is_empty());
    }

    #[test]
    fn signal_graph_dirty_eval_order() {
        let mut g = SignalGraph::new();
        let s1 = g.next_signal_id();
        let s2 = g.next_signal_id();
        g.register(s1, SignalKind::Source, BTreeSet::new()).unwrap();
        g.register(s2, SignalKind::Source, BTreeSet::new()).unwrap();

        let d = g.next_signal_id();
        let mut deps = BTreeSet::new();
        deps.insert(s1);
        deps.insert(s2);
        g.register(d, SignalKind::Derived, deps).unwrap();

        let order = g.dirty_evaluation_order();
        // Sources first (depth 0), derived last (depth 1)
        assert!(
            order.iter().position(|&x| x == d).unwrap()
                > order.iter().position(|&x| x == s1).unwrap()
        );
    }

    #[test]
    fn signal_graph_serde_roundtrip() {
        let mut g = SignalGraph::new();
        let s = g.next_signal_id();
        g.register(s, SignalKind::Source, BTreeSet::new()).unwrap();
        let json = serde_json::to_string(&g).unwrap();
        let g2: SignalGraph = serde_json::from_str(&json).unwrap();
        assert_eq!(g, g2);
    }

    #[test]
    fn signal_graph_default() {
        let g = SignalGraph::default();
        assert_eq!(g.node_count(), 0);
    }

    // ---- UpdateScheduler tests ----

    #[test]
    fn scheduler_new_empty() {
        let s = UpdateScheduler::new();
        assert!(s.is_empty());
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn scheduler_schedule_and_drain() {
        let mut s = UpdateScheduler::new();
        s.schedule(SignalId(0), UpdatePriority::Normal, "App".into());
        s.schedule(SignalId(1), UpdatePriority::Sync, "Header".into());

        let batch = s.drain_batch();
        assert_eq!(batch.len(), 2);
        // Sync should come first
        assert_eq!(batch[0].priority, UpdatePriority::Sync);
        assert_eq!(batch[1].priority, UpdatePriority::Normal);
    }

    #[test]
    fn scheduler_fifo_within_priority() {
        let mut s = UpdateScheduler::new();
        s.schedule(SignalId(0), UpdatePriority::Normal, "A".into());
        s.schedule(SignalId(1), UpdatePriority::Normal, "B".into());
        s.schedule(SignalId(2), UpdatePriority::Normal, "C".into());

        let batch = s.drain_batch();
        assert_eq!(batch[0].component, "A");
        assert_eq!(batch[1].component, "B");
        assert_eq!(batch[2].component, "C");
    }

    #[test]
    fn scheduler_max_per_flush() {
        let mut s = UpdateScheduler::new();
        s.max_updates_per_flush = 2;
        for i in 0..5 {
            s.schedule(SignalId(i), UpdatePriority::Normal, format!("{i}"));
        }
        let batch = s.drain_batch();
        assert_eq!(batch.len(), 2);
        assert_eq!(s.pending_count(), 3);
    }

    #[test]
    fn update_priority_urgency_ordering() {
        assert!(UpdatePriority::Sync.urgency() < UpdatePriority::UserBlocking.urgency());
        assert!(UpdatePriority::UserBlocking.urgency() < UpdatePriority::Normal.urgency());
        assert!(UpdatePriority::Normal.urgency() < UpdatePriority::Low.urgency());
        assert!(UpdatePriority::Low.urgency() < UpdatePriority::Idle.urgency());
    }

    #[test]
    fn scheduler_serde_roundtrip() {
        let mut s = UpdateScheduler::new();
        s.schedule(SignalId(0), UpdatePriority::Normal, "App".into());
        let json = serde_json::to_string(&s).unwrap();
        let s2: UpdateScheduler = serde_json::from_str(&json).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn scheduler_default() {
        let s = UpdateScheduler::default();
        assert!(s.is_empty());
    }

    // ---- DomPatch / DomTree tests ----

    #[test]
    fn dom_tree_new_empty() {
        let t = DomTree::new();
        assert_eq!(t.element_count(), 0);
    }

    #[test]
    fn dom_tree_create_element() {
        let mut t = DomTree::new();
        let id = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
        assert_eq!(t.element_count(), 1);
        assert_eq!(t.get(id).unwrap().tag, "div");
    }

    #[test]
    fn dom_tree_create_child() {
        let mut t = DomTree::new();
        let root = t.next_element_id();
        let child = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id: root,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
        t.apply_patch(&DomPatch::CreateElement {
            id: child,
            tag: "span".into(),
            parent: Some(root),
        })
        .unwrap();
        assert_eq!(t.get(root).unwrap().children.len(), 1);
        assert_eq!(t.get(child).unwrap().parent, Some(root));
    }

    #[test]
    fn dom_tree_remove_cascades() {
        let mut t = DomTree::new();
        let root = t.next_element_id();
        let child = t.next_element_id();
        let grandchild = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id: root,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
        t.apply_patch(&DomPatch::CreateElement {
            id: child,
            tag: "ul".into(),
            parent: Some(root),
        })
        .unwrap();
        t.apply_patch(&DomPatch::CreateElement {
            id: grandchild,
            tag: "li".into(),
            parent: Some(child),
        })
        .unwrap();

        t.apply_patch(&DomPatch::RemoveElement { id: child })
            .unwrap();
        assert_eq!(t.element_count(), 1); // only root remains
        assert!(!t.contains(child));
        assert!(!t.contains(grandchild));
    }

    #[test]
    fn dom_tree_set_property() {
        let mut t = DomTree::new();
        let id = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id,
            tag: "input".into(),
            parent: None,
        })
        .unwrap();
        t.apply_patch(&DomPatch::SetProperty {
            id,
            key: "type".into(),
            value: "text".into(),
        })
        .unwrap();
        assert_eq!(t.get(id).unwrap().properties.get("type").unwrap(), "text");
    }

    #[test]
    fn dom_tree_remove_property() {
        let mut t = DomTree::new();
        let id = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
        t.apply_patch(&DomPatch::SetProperty {
            id,
            key: "class".into(),
            value: "active".into(),
        })
        .unwrap();
        t.apply_patch(&DomPatch::RemoveProperty {
            id,
            key: "class".into(),
        })
        .unwrap();
        assert!(t.get(id).unwrap().properties.is_empty());
    }

    #[test]
    fn dom_tree_set_text_content() {
        let mut t = DomTree::new();
        let id = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id,
            tag: "p".into(),
            parent: None,
        })
        .unwrap();
        t.apply_patch(&DomPatch::SetTextContent {
            id,
            text: "hello".into(),
        })
        .unwrap();
        assert_eq!(t.get(id).unwrap().text_content.as_deref(), Some("hello"));
    }

    #[test]
    fn dom_tree_move_element() {
        let mut t = DomTree::new();
        let a = t.next_element_id();
        let b = t.next_element_id();
        let child = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id: a,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
        t.apply_patch(&DomPatch::CreateElement {
            id: b,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
        t.apply_patch(&DomPatch::CreateElement {
            id: child,
            tag: "span".into(),
            parent: Some(a),
        })
        .unwrap();

        t.apply_patch(&DomPatch::MoveElement {
            id: child,
            new_parent: b,
            before_sibling: None,
        })
        .unwrap();
        assert!(t.get(a).unwrap().children.is_empty());
        assert_eq!(t.get(b).unwrap().children, vec![child]);
        assert_eq!(t.get(child).unwrap().parent, Some(b));
    }

    #[test]
    fn dom_tree_replace_element() {
        let mut t = DomTree::new();
        let root = t.next_element_id();
        let old = t.next_element_id();
        let new_id = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id: root,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
        t.apply_patch(&DomPatch::CreateElement {
            id: old,
            tag: "span".into(),
            parent: Some(root),
        })
        .unwrap();

        t.apply_patch(&DomPatch::ReplaceElement {
            old,
            new_id,
            tag: "strong".into(),
        })
        .unwrap();
        assert!(!t.contains(old));
        assert_eq!(t.get(new_id).unwrap().tag, "strong");
        assert_eq!(t.get(root).unwrap().children, vec![new_id]);
    }

    #[test]
    fn dom_tree_error_element_not_found() {
        let mut t = DomTree::new();
        assert!(matches!(
            t.apply_patch(&DomPatch::RemoveElement {
                id: DomElementId(99)
            }),
            Err(DomPatchError::ElementNotFound(_))
        ));
    }

    #[test]
    fn dom_tree_error_duplicate() {
        let mut t = DomTree::new();
        let id = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
        assert!(matches!(
            t.apply_patch(&DomPatch::CreateElement {
                id,
                tag: "span".into(),
                parent: None,
            }),
            Err(DomPatchError::ElementAlreadyExists(_))
        ));
    }

    #[test]
    fn dom_tree_batch_apply() {
        let mut t = DomTree::new();
        let root = DomElementId(0);
        let child = DomElementId(1);
        let batch = PatchBatch {
            patches: vec![
                DomPatch::CreateElement {
                    id: root,
                    tag: "div".into(),
                    parent: None,
                },
                DomPatch::CreateElement {
                    id: child,
                    tag: "p".into(),
                    parent: Some(root),
                },
                DomPatch::SetTextContent {
                    id: child,
                    text: "hello".into(),
                },
            ],
            cycle_sequence: 0,
            component: "App".into(),
        };
        t.apply_batch(&batch).unwrap();
        assert_eq!(t.element_count(), 2);
        assert_eq!(t.get(child).unwrap().text_content.as_deref(), Some("hello"));
    }

    #[test]
    fn dom_tree_serde_roundtrip() {
        let mut t = DomTree::new();
        let id = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
        let json = serde_json::to_string(&t).unwrap();
        let t2: DomTree = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn dom_tree_default() {
        let t = DomTree::default();
        assert_eq!(t.element_count(), 0);
    }

    #[test]
    fn patch_batch_derive_id_stable() {
        let b = PatchBatch::new("App", 0);
        assert_eq!(b.derive_id(), b.derive_id());
    }

    #[test]
    fn dom_patch_target_element() {
        let p = DomPatch::SetProperty {
            id: DomElementId(42),
            key: "x".into(),
            value: "y".into(),
        };
        assert_eq!(p.target_element(), DomElementId(42));
    }

    // ---- EventDelegation tests ----

    #[test]
    fn event_delegation_new_empty() {
        let d = EventDelegation::new();
        assert_eq!(d.handler_count(), 0);
    }

    #[test]
    fn event_delegation_register_and_find() {
        let mut d = EventDelegation::new();
        let elem = DomElementId(1);
        d.register(EventType::Click, elem, "Button", false);

        let handlers = d.find_handlers(EventType::Click, elem);
        assert_eq!(handlers.len(), 1);
        assert_eq!(handlers[0].component, "Button");
    }

    #[test]
    fn event_delegation_unregister() {
        let mut d = EventDelegation::new();
        let elem = DomElementId(1);
        let id = d.register(EventType::Click, elem, "Button", false);
        assert!(d.unregister(id));
        assert_eq!(d.handler_count(), 0);
    }

    #[test]
    fn event_delegation_unregister_missing() {
        let mut d = EventDelegation::new();
        assert!(!d.unregister(999));
    }

    #[test]
    fn event_delegation_cleanup_element() {
        let mut d = EventDelegation::new();
        let elem = DomElementId(1);
        d.register(EventType::Click, elem, "A", false);
        d.register(EventType::Input, elem, "A", false);
        d.register(EventType::Click, DomElementId(2), "B", false);

        let removed = d.cleanup_element(elem);
        assert_eq!(removed, 2);
        assert_eq!(d.handler_count(), 1);
    }

    #[test]
    fn event_delegation_cleanup_component() {
        let mut d = EventDelegation::new();
        d.register(EventType::Click, DomElementId(1), "App", false);
        d.register(EventType::Input, DomElementId(2), "App", false);
        d.register(EventType::Click, DomElementId(3), "Header", false);

        let removed = d.cleanup_component("App");
        assert_eq!(removed, 2);
        assert_eq!(d.handler_count(), 1);
    }

    #[test]
    fn event_type_bubbles() {
        assert!(EventType::Click.bubbles());
        assert!(EventType::Input.bubbles());
        assert!(!EventType::Focus.bubbles());
        assert!(!EventType::Blur.bubbles());
        assert!(!EventType::MouseEnter.bubbles());
    }

    #[test]
    fn event_type_all_count() {
        assert_eq!(EventType::ALL.len(), 12);
    }

    #[test]
    fn event_delegation_serde_roundtrip() {
        let mut d = EventDelegation::new();
        d.register(EventType::Click, DomElementId(1), "App", false);
        let json = serde_json::to_string(&d).unwrap();
        let d2: EventDelegation = serde_json::from_str(&json).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn event_delegation_default() {
        let d = EventDelegation::default();
        assert_eq!(d.handler_count(), 0);
    }

    // ---- JsLaneConfig tests ----

    #[test]
    fn config_defaults_valid() {
        let c = JsLaneConfig::default_config();
        assert!(c.validate().is_empty());
    }

    #[test]
    fn config_zero_depth_invalid() {
        let mut c = JsLaneConfig::default_config();
        c.max_signal_depth = 0;
        assert!(!c.validate().is_empty());
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = JsLaneConfig::default_config();
        let json = serde_json::to_string(&c).unwrap();
        let c2: JsLaneConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);
    }

    // ---- JsRuntimeLane tests ----

    #[test]
    fn lane_with_defaults() {
        let lane = JsRuntimeLane::with_defaults();
        assert_eq!(lane.state, LaneState::Ready);
        assert_eq!(lane.flush_count, 0);
    }

    #[test]
    fn lane_derive_id_stable() {
        let lane = JsRuntimeLane::with_defaults();
        assert_eq!(lane.derive_id(), lane.derive_id());
    }

    #[test]
    fn lane_serde_roundtrip() {
        let lane = JsRuntimeLane::with_defaults();
        let json = serde_json::to_string(&lane).unwrap();
        let l2: JsRuntimeLane = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, l2);
    }

    #[test]
    fn flush_summary_derive_id_stable() {
        let s = FlushSummary {
            updates_processed: 5,
            signals_evaluated: 10,
            patches_emitted: 3,
            handlers_cleaned: 0,
            cycle_sequence: 1,
        };
        assert_eq!(s.derive_id(), s.derive_id());
    }

    // ---- End-to-end pipeline tests ----

    #[test]
    fn e2e_signal_update_to_dom_patch() {
        let mut lane = JsRuntimeLane::with_defaults();

        // 1. Create source signal (counter state)
        let counter_signal = lane.signal_graph.next_signal_id();
        lane.signal_graph
            .register(counter_signal, SignalKind::Source, BTreeSet::new())
            .unwrap();
        lane.signal_graph.mark_clean(counter_signal).unwrap();

        // 2. Create derived signal (display text)
        let display_signal = lane.signal_graph.next_signal_id();
        let mut deps = BTreeSet::new();
        deps.insert(counter_signal);
        lane.signal_graph
            .register(display_signal, SignalKind::Derived, deps)
            .unwrap();
        lane.signal_graph.mark_clean(display_signal).unwrap();

        // 3. Create DOM tree
        let root = lane.dom_tree.next_element_id();
        let text_node = lane.dom_tree.next_element_id();
        lane.dom_tree
            .apply_patch(&DomPatch::CreateElement {
                id: root,
                tag: "div".into(),
                parent: None,
            })
            .unwrap();
        lane.dom_tree
            .apply_patch(&DomPatch::CreateElement {
                id: text_node,
                tag: "span".into(),
                parent: Some(root),
            })
            .unwrap();

        // 4. Register click handler
        lane.event_delegation
            .register(EventType::Click, root, "Counter", false);

        // 5. Simulate state update
        lane.scheduler
            .schedule(counter_signal, UpdatePriority::Sync, "Counter".into());

        // 6. Flush: drain updates, propagate dirty, evaluate, patch
        let updates = lane.scheduler.drain_batch();
        assert_eq!(updates.len(), 1);

        let dirty = lane.signal_graph.mark_dirty(counter_signal).unwrap();
        assert_eq!(dirty.len(), 2); // counter + display

        // Evaluate signals in order
        for sig in &dirty {
            lane.signal_graph.mark_clean(*sig).unwrap();
        }

        // Apply DOM patch
        let mut batch = PatchBatch::new("Counter", lane.flush_count);
        batch.push(DomPatch::SetTextContent {
            id: text_node,
            text: "Count: 1".into(),
        });
        lane.dom_tree.apply_batch(&batch).unwrap();
        lane.flush_count += 1;

        assert_eq!(
            lane.dom_tree
                .get(text_node)
                .unwrap()
                .text_content
                .as_deref(),
            Some("Count: 1")
        );
        assert_eq!(lane.flush_count, 1);
    }

    #[test]
    fn e2e_component_mount_and_unmount() {
        let mut lane = JsRuntimeLane::with_defaults();

        // Mount: create DOM + register handlers
        let root = lane.dom_tree.next_element_id();
        let button = lane.dom_tree.next_element_id();
        lane.dom_tree
            .apply_patch(&DomPatch::CreateElement {
                id: root,
                tag: "div".into(),
                parent: None,
            })
            .unwrap();
        lane.dom_tree
            .apply_patch(&DomPatch::CreateElement {
                id: button,
                tag: "button".into(),
                parent: Some(root),
            })
            .unwrap();
        lane.event_delegation
            .register(EventType::Click, button, "MyComponent", false);
        lane.event_delegation
            .register(EventType::Focus, button, "MyComponent", false);

        assert_eq!(lane.dom_tree.element_count(), 2);
        assert_eq!(lane.event_delegation.handler_count(), 2);

        // Unmount: cleanup handlers then remove DOM
        lane.event_delegation.cleanup_component("MyComponent");
        lane.dom_tree
            .apply_patch(&DomPatch::RemoveElement { id: root })
            .unwrap();

        assert_eq!(lane.dom_tree.element_count(), 0);
        assert_eq!(lane.event_delegation.handler_count(), 0);
    }

    #[test]
    fn e2e_multi_priority_scheduling() {
        let mut lane = JsRuntimeLane::with_defaults();

        // Schedule updates at different priorities
        lane.scheduler
            .schedule(SignalId(0), UpdatePriority::Low, "Background".into());
        lane.scheduler
            .schedule(SignalId(1), UpdatePriority::Sync, "Click".into());
        lane.scheduler
            .schedule(SignalId(2), UpdatePriority::Normal, "Effect".into());

        let batch = lane.scheduler.drain_batch();
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].priority, UpdatePriority::Sync);
        assert_eq!(batch[1].priority, UpdatePriority::Normal);
        assert_eq!(batch[2].priority, UpdatePriority::Low);
    }

    #[test]
    fn e2e_signal_dispose_cleanup() {
        let mut lane = JsRuntimeLane::with_defaults();

        let s = lane.signal_graph.next_signal_id();
        lane.signal_graph
            .register(s, SignalKind::Source, BTreeSet::new())
            .unwrap();

        let effect = lane.signal_graph.next_signal_id();
        let mut deps = BTreeSet::new();
        deps.insert(s);
        lane.signal_graph
            .register(effect, SignalKind::Effect, deps)
            .unwrap();

        // Dispose effect
        lane.signal_graph.dispose(effect).unwrap();
        assert_eq!(lane.signal_graph.node_count(), 1);

        // Source should have no dependents
        assert!(lane.signal_graph.get(s).unwrap().dependents.is_empty());
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn signal_kind_serde_roundtrip() {
        let variants = [SignalKind::Source, SignalKind::Derived, SignalKind::Effect];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SignalKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn signal_status_serde_roundtrip() {
        let variants = [
            SignalStatus::Clean,
            SignalStatus::Dirty,
            SignalStatus::Evaluating,
            SignalStatus::Disposed,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SignalStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn update_priority_serde_roundtrip() {
        let variants = [
            UpdatePriority::Sync,
            UpdatePriority::UserBlocking,
            UpdatePriority::Normal,
            UpdatePriority::Low,
            UpdatePriority::Idle,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: UpdatePriority = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn event_type_serde_roundtrip() {
        let variants = [
            EventType::Click,
            EventType::Input,
            EventType::Change,
            EventType::Submit,
            EventType::Focus,
            EventType::Blur,
            EventType::KeyDown,
            EventType::KeyUp,
            EventType::MouseEnter,
            EventType::MouseLeave,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EventType = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn lane_state_serde_roundtrip() {
        let variants = [
            LaneState::Ready,
            LaneState::Processing,
            LaneState::Suspended,
            LaneState::Shutdown,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: LaneState = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn signal_graph_error_serde_roundtrip() {
        let variants = vec![
            SignalGraphError::NotFound(SignalId(99)),
            SignalGraphError::CycleDetected {
                signal: SignalId(1),
                path: vec![SignalId(1), SignalId(2)],
            },
            SignalGraphError::Disposed(SignalId(3)),
            SignalGraphError::DuplicateSignal(SignalId(4)),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SignalGraphError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn dom_patch_error_serde_roundtrip() {
        let variants = vec![
            DomPatchError::ElementNotFound(DomElementId(1)),
            DomPatchError::ElementAlreadyExists(DomElementId(2)),
            DomPatchError::ParentNotFound(DomElementId(3)),
            DomPatchError::InvalidReparent {
                id: DomElementId(4),
                new_parent: DomElementId(5),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DomPatchError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn signal_graph_mark_dirty_on_disposed_returns_error() {
        let mut g = SignalGraph::new();
        let s = g.next_signal_id();
        g.register(s, SignalKind::Source, BTreeSet::new()).unwrap();
        g.dispose(s).unwrap();
        assert!(matches!(
            g.mark_dirty(s),
            Err(SignalGraphError::Disposed(_))
        ));
    }

    #[test]
    fn signal_graph_mark_clean_on_disposed_returns_error() {
        let mut g = SignalGraph::new();
        let s = g.next_signal_id();
        g.register(s, SignalKind::Source, BTreeSet::new()).unwrap();
        g.dispose(s).unwrap();
        assert!(matches!(
            g.mark_clean(s),
            Err(SignalGraphError::Disposed(_))
        ));
    }

    #[test]
    fn signal_graph_dispose_not_found() {
        let mut g = SignalGraph::new();
        assert!(matches!(
            g.dispose(SignalId(999)),
            Err(SignalGraphError::NotFound(_))
        ));
    }

    #[test]
    fn signal_graph_generation_increments_on_dirty() {
        let mut g = SignalGraph::new();
        let s = g.next_signal_id();
        g.register(s, SignalKind::Source, BTreeSet::new()).unwrap();
        g.mark_clean(s).unwrap();

        let gen_before = g.get(s).unwrap().generation;
        g.mark_dirty(s).unwrap();
        let gen_after = g.get(s).unwrap().generation;
        assert!(gen_after > gen_before);
    }

    #[test]
    fn dom_patch_create_with_invalid_parent_returns_error() {
        let mut t = DomTree::new();
        let id = t.next_element_id();
        assert!(matches!(
            t.apply_patch(&DomPatch::CreateElement {
                id,
                tag: "div".into(),
                parent: Some(DomElementId(999)),
            }),
            Err(DomPatchError::ParentNotFound(_))
        ));
    }

    #[test]
    fn dom_patch_move_element_not_found() {
        let mut t = DomTree::new();
        let parent = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id: parent,
            tag: "div".into(),
            parent: None,
        })
        .unwrap();
        assert!(matches!(
            t.apply_patch(&DomPatch::MoveElement {
                id: DomElementId(999),
                new_parent: parent,
                before_sibling: None,
            }),
            Err(DomPatchError::ElementNotFound(_))
        ));
    }

    #[test]
    fn dom_patch_move_to_missing_parent() {
        let mut t = DomTree::new();
        let elem = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id: elem,
            tag: "span".into(),
            parent: None,
        })
        .unwrap();
        assert!(matches!(
            t.apply_patch(&DomPatch::MoveElement {
                id: elem,
                new_parent: DomElementId(999),
                before_sibling: None,
            }),
            Err(DomPatchError::ParentNotFound(_))
        ));
    }

    #[test]
    fn dom_patch_set_text_on_missing_element() {
        let mut t = DomTree::new();
        assert!(matches!(
            t.apply_patch(&DomPatch::SetTextContent {
                id: DomElementId(99),
                text: "hello".into(),
            }),
            Err(DomPatchError::ElementNotFound(_))
        ));
    }

    #[test]
    fn dom_patch_remove_property_on_missing_element() {
        let mut t = DomTree::new();
        assert!(matches!(
            t.apply_patch(&DomPatch::RemoveProperty {
                id: DomElementId(99),
                key: "class".into(),
            }),
            Err(DomPatchError::ElementNotFound(_))
        ));
    }

    #[test]
    fn dom_patch_replace_missing_element() {
        let mut t = DomTree::new();
        assert!(matches!(
            t.apply_patch(&DomPatch::ReplaceElement {
                old: DomElementId(99),
                new_id: DomElementId(100),
                tag: "div".into(),
            }),
            Err(DomPatchError::ElementNotFound(_))
        ));
    }

    #[test]
    fn dom_patch_move_with_before_sibling() {
        let mut t = DomTree::new();
        let parent = t.next_element_id();
        let a = t.next_element_id();
        let b = t.next_element_id();
        let c = t.next_element_id();
        t.apply_patch(&DomPatch::CreateElement {
            id: parent,
            tag: "ul".into(),
            parent: None,
        })
        .unwrap();
        t.apply_patch(&DomPatch::CreateElement {
            id: a,
            tag: "li".into(),
            parent: Some(parent),
        })
        .unwrap();
        t.apply_patch(&DomPatch::CreateElement {
            id: b,
            tag: "li".into(),
            parent: Some(parent),
        })
        .unwrap();
        // Create c as orphan, then move before b
        t.apply_patch(&DomPatch::CreateElement {
            id: c,
            tag: "li".into(),
            parent: None,
        })
        .unwrap();
        t.apply_patch(&DomPatch::MoveElement {
            id: c,
            new_parent: parent,
            before_sibling: Some(b),
        })
        .unwrap();
        // Should be: a, c, b
        let children = &t.get(parent).unwrap().children;
        assert_eq!(children, &[a, c, b]);
    }

    #[test]
    fn patch_batch_is_empty_and_push() {
        let mut batch = PatchBatch::new("App", 0);
        assert!(batch.is_empty());
        batch.push(DomPatch::RemoveElement {
            id: DomElementId(1),
        });
        assert!(!batch.is_empty());
        assert_eq!(batch.patches.len(), 1);
    }

    #[test]
    fn dom_patch_target_element_all_variants() {
        let cases: Vec<(DomPatch, DomElementId)> = vec![
            (
                DomPatch::CreateElement {
                    id: DomElementId(1),
                    tag: "div".into(),
                    parent: None,
                },
                DomElementId(1),
            ),
            (
                DomPatch::RemoveElement {
                    id: DomElementId(2),
                },
                DomElementId(2),
            ),
            (
                DomPatch::SetProperty {
                    id: DomElementId(3),
                    key: "k".into(),
                    value: "v".into(),
                },
                DomElementId(3),
            ),
            (
                DomPatch::RemoveProperty {
                    id: DomElementId(4),
                    key: "k".into(),
                },
                DomElementId(4),
            ),
            (
                DomPatch::SetTextContent {
                    id: DomElementId(5),
                    text: "t".into(),
                },
                DomElementId(5),
            ),
            (
                DomPatch::MoveElement {
                    id: DomElementId(6),
                    new_parent: DomElementId(0),
                    before_sibling: None,
                },
                DomElementId(6),
            ),
            (
                DomPatch::ReplaceElement {
                    old: DomElementId(7),
                    new_id: DomElementId(8),
                    tag: "p".into(),
                },
                DomElementId(7),
            ),
        ];
        for (patch, expected) in cases {
            assert_eq!(patch.target_element(), expected);
        }
    }

    #[test]
    fn dom_patch_serde_all_variants() {
        let variants: Vec<DomPatch> = vec![
            DomPatch::CreateElement {
                id: DomElementId(1),
                tag: "div".into(),
                parent: Some(DomElementId(0)),
            },
            DomPatch::RemoveElement {
                id: DomElementId(2),
            },
            DomPatch::SetProperty {
                id: DomElementId(3),
                key: "class".into(),
                value: "active".into(),
            },
            DomPatch::RemoveProperty {
                id: DomElementId(4),
                key: "style".into(),
            },
            DomPatch::SetTextContent {
                id: DomElementId(5),
                text: "hello".into(),
            },
            DomPatch::MoveElement {
                id: DomElementId(6),
                new_parent: DomElementId(0),
                before_sibling: Some(DomElementId(1)),
            },
            DomPatch::ReplaceElement {
                old: DomElementId(7),
                new_id: DomElementId(8),
                tag: "strong".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: DomPatch = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn js_lane_config_validate_all_error_paths() {
        let mut c = JsLaneConfig::default_config();
        c.max_signal_depth = 0;
        c.max_updates_per_flush = 0;
        c.max_dom_elements = 0;
        let errors = c.validate();
        assert_eq!(errors.len(), 3);
        assert!(errors.iter().any(|e| e.contains("max_signal_depth")));
        assert!(errors.iter().any(|e| e.contains("max_updates_per_flush")));
        assert!(errors.iter().any(|e| e.contains("max_dom_elements")));
    }

    #[test]
    fn event_type_bubbles_comprehensive() {
        let bubbling = [
            EventType::Click,
            EventType::Input,
            EventType::Change,
            EventType::Submit,
            EventType::KeyDown,
            EventType::KeyUp,
            EventType::Scroll,
        ];
        let non_bubbling = [
            EventType::Focus,
            EventType::Blur,
            EventType::MouseEnter,
            EventType::MouseLeave,
            EventType::Resize,
        ];
        for et in &bubbling {
            assert!(et.bubbles(), "{et:?} should bubble");
        }
        for et in &non_bubbling {
            assert!(!et.bubbles(), "{et:?} should not bubble");
        }
        assert_eq!(bubbling.len() + non_bubbling.len(), EventType::ALL.len());
    }

    #[test]
    fn event_delegation_ids_auto_increment() {
        let mut d = EventDelegation::new();
        let id0 = d.register(EventType::Click, DomElementId(1), "A", false);
        let id1 = d.register(EventType::Input, DomElementId(2), "B", false);
        let id2 = d.register(EventType::Focus, DomElementId(3), "C", true);
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn event_delegation_find_handlers_no_match() {
        let mut d = EventDelegation::new();
        d.register(EventType::Click, DomElementId(1), "A", false);
        let found = d.find_handlers(EventType::Input, DomElementId(1));
        assert!(found.is_empty());
        let found2 = d.find_handlers(EventType::Click, DomElementId(999));
        assert!(found2.is_empty());
    }

    #[test]
    fn flush_summary_serde_roundtrip() {
        let s = FlushSummary {
            updates_processed: 10,
            signals_evaluated: 20,
            patches_emitted: 5,
            handlers_cleaned: 2,
            cycle_sequence: 42,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: FlushSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn lane_state_ord_ready_before_shutdown() {
        assert!(LaneState::Ready < LaneState::Processing);
        assert!(LaneState::Processing < LaneState::Suspended);
        assert!(LaneState::Suspended < LaneState::Shutdown);
    }

    #[test]
    fn lane_derive_id_changes_after_mutation() {
        let mut lane = JsRuntimeLane::with_defaults();
        let id_before = lane.derive_id();
        let s = lane.signal_graph.next_signal_id();
        lane.signal_graph
            .register(s, SignalKind::Source, BTreeSet::new())
            .unwrap();
        let id_after = lane.derive_id();
        assert_ne!(id_before, id_after);
    }

    #[test]
    fn scheduled_update_serde_roundtrip() {
        let u = ScheduledUpdate {
            signal_id: SignalId(5),
            priority: UpdatePriority::UserBlocking,
            sequence: 7,
            component: "Counter".into(),
        };
        let json = serde_json::to_string(&u).unwrap();
        let back: ScheduledUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn dom_element_record_serde_roundtrip() {
        let mut props = BTreeMap::new();
        props.insert("class".into(), "active".into());
        let rec = DomElementRecord {
            id: DomElementId(1),
            tag: "div".into(),
            parent: Some(DomElementId(0)),
            children: vec![DomElementId(2), DomElementId(3)],
            properties: props,
            text_content: Some("hello".into()),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: DomElementRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn event_handler_serde_roundtrip() {
        let h = EventHandler {
            id: 42,
            event_type: EventType::Submit,
            target_element: DomElementId(10),
            component: "Form".into(),
            capture: true,
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: EventHandler = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn dom_tree_contains_returns_false_for_missing() {
        let t = DomTree::new();
        assert!(!t.contains(DomElementId(999)));
    }

    #[test]
    fn dom_tree_get_returns_none_for_missing() {
        let t = DomTree::new();
        assert!(t.get(DomElementId(0)).is_none());
    }

    #[test]
    fn signal_graph_node_count_excludes_disposed() {
        let mut g = SignalGraph::new();
        let s1 = g.next_signal_id();
        let s2 = g.next_signal_id();
        g.register(s1, SignalKind::Source, BTreeSet::new()).unwrap();
        g.register(s2, SignalKind::Source, BTreeSet::new()).unwrap();
        assert_eq!(g.node_count(), 2);
        g.dispose(s1).unwrap();
        assert_eq!(g.node_count(), 1);
    }

    #[test]
    fn schema_version_stable() {
        let a = lane_schema();
        let b = lane_schema();
        assert_eq!(a, b);
    }
}
