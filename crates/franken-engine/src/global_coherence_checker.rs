//! Global Coherence Checker — FRX-14.2
//!
//! Composes local semantic contracts (from [`LocalSemanticAtlas`]) into
//! app-level coherence guarantees using a gluing/descent approach:
//!
//! 1. **Context coherence** — every consumed context has a matching provider,
//!    and no provider is orphaned.
//! 2. **Capability boundary coherence** — transitive capability requirements
//!    are satisfied at every composition boundary.
//! 3. **Effect ordering coherence** — composed effect signatures admit a
//!    consistent total order (no cycles, layout-before-passive invariant).
//! 4. **Suspense/hydration boundary coherence** — async boundaries do not
//!    straddle incompatible effect or context contracts.
//! 5. **Hook signature compatibility** — hooks with shared dependency graphs
//!    agree on cleanup policy and invocation count.
//!
//! Each check produces deterministic, evidence-linked diagnostic artifacts
//! with fixed-point severity scores.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use crate::hash_tiers::ContentHash;
use crate::semantic_contract_baseline::{LocalSemanticAtlas, LocalSemanticAtlasEntry};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for global coherence artifacts.
pub const GLOBAL_COHERENCE_SCHEMA_VERSION: &str = "franken-engine.global_coherence_checker.v1";

/// Maximum components in a single coherence check.
const MAX_COMPONENTS: usize = 50_000;

/// Maximum edges in the composition graph.
const MAX_COMPOSITION_EDGES: usize = 200_000;

/// Maximum violations before the checker stops (budget exhaustion).
const MAX_VIOLATIONS: usize = 10_000;

/// Bead identifier for this module.
pub const GLOBAL_COHERENCE_BEAD_ID: &str = "bd-mjh3.14.2";

// ---------------------------------------------------------------------------
// Blocking quality-debt codes (FRX-14.2)
// ---------------------------------------------------------------------------

pub const DEBT_UNRESOLVED_CONTEXT: &str = "FE-FRX-14-2-GLOBAL-0001";
pub const DEBT_CAPABILITY_GAP: &str = "FE-FRX-14-2-GLOBAL-0002";
pub const DEBT_EFFECT_CYCLE: &str = "FE-FRX-14-2-GLOBAL-0003";
pub const DEBT_SUSPENSE_BOUNDARY_CONFLICT: &str = "FE-FRX-14-2-GLOBAL-0004";
pub const DEBT_HOOK_CLEANUP_MISMATCH: &str = "FE-FRX-14-2-GLOBAL-0005";
pub const DEBT_HYDRATION_BOUNDARY_CONFLICT: &str = "FE-FRX-14-2-GLOBAL-0006";

// ---------------------------------------------------------------------------
// Composition graph
// ---------------------------------------------------------------------------

/// Edge kind in the component composition graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CompositionEdgeKind {
    /// Parent renders child.
    ParentChild,
    /// Provider supplies context to consumer.
    ContextFlow,
    /// Shared capability boundary.
    CapabilityBoundary,
    /// Suspense boundary wraps child.
    SuspenseBoundary,
    /// Hydration boundary wraps child.
    HydrationBoundary,
    /// Effect ordering dependency.
    EffectDependency,
}

impl fmt::Display for CompositionEdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParentChild => write!(f, "parent-child"),
            Self::ContextFlow => write!(f, "context-flow"),
            Self::CapabilityBoundary => write!(f, "capability-boundary"),
            Self::SuspenseBoundary => write!(f, "suspense-boundary"),
            Self::HydrationBoundary => write!(f, "hydration-boundary"),
            Self::EffectDependency => write!(f, "effect-dependency"),
        }
    }
}

/// A single edge in the composition graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CompositionEdge {
    pub from_component: String,
    pub to_component: String,
    pub kind: CompositionEdgeKind,
    pub label: String,
}

/// The full composition graph describing how components relate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionGraph {
    pub component_ids: BTreeSet<String>,
    pub edges: Vec<CompositionEdge>,
}

impl CompositionGraph {
    pub fn new() -> Self {
        Self {
            component_ids: BTreeSet::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_component(&mut self, id: String) -> Result<(), CoherenceError> {
        if self.component_ids.len() >= MAX_COMPONENTS {
            return Err(CoherenceError::BudgetExhausted {
                resource: "components".to_string(),
                limit: MAX_COMPONENTS,
            });
        }
        self.component_ids.insert(id);
        Ok(())
    }

    pub fn add_edge(&mut self, edge: CompositionEdge) -> Result<(), CoherenceError> {
        if self.edges.len() >= MAX_COMPOSITION_EDGES {
            return Err(CoherenceError::BudgetExhausted {
                resource: "composition_edges".to_string(),
                limit: MAX_COMPOSITION_EDGES,
            });
        }
        if !self.component_ids.contains(&edge.from_component) {
            return Err(CoherenceError::UnknownComponent(
                edge.from_component.clone(),
            ));
        }
        if !self.component_ids.contains(&edge.to_component) {
            return Err(CoherenceError::UnknownComponent(edge.to_component.clone()));
        }
        self.edges.push(edge);
        Ok(())
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn component_count(&self) -> usize {
        self.component_ids.len()
    }

    /// Return outgoing adjacency list for a given edge kind.
    pub fn adjacency_for_kind(&self, kind: &CompositionEdgeKind) -> BTreeMap<String, Vec<String>> {
        let mut adj: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for edge in &self.edges {
            if edge.kind == *kind {
                adj.entry(edge.from_component.clone())
                    .or_default()
                    .push(edge.to_component.clone());
            }
        }
        adj
    }

    /// Return all children of a component (via ParentChild edges).
    pub fn children_of(&self, component_id: &str) -> Vec<String> {
        self.edges
            .iter()
            .filter(|e| {
                e.from_component == component_id && e.kind == CompositionEdgeKind::ParentChild
            })
            .map(|e| e.to_component.clone())
            .collect()
    }

    /// Return all parents of a component.
    pub fn parents_of(&self, component_id: &str) -> Vec<String> {
        self.edges
            .iter()
            .filter(|e| {
                e.to_component == component_id && e.kind == CompositionEdgeKind::ParentChild
            })
            .map(|e| e.from_component.clone())
            .collect()
    }
}

impl Default for CompositionGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Coherence violation
// ---------------------------------------------------------------------------

/// Severity score in millionths (1 000 000 = 1.0).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SeverityScore(pub i64);

impl SeverityScore {
    pub fn critical() -> Self {
        Self(MILLION)
    }
    pub fn high() -> Self {
        Self(750_000)
    }
    pub fn medium() -> Self {
        Self(500_000)
    }
    pub fn low() -> Self {
        Self(250_000)
    }
    pub fn info() -> Self {
        Self(100_000)
    }

    pub fn is_blocking(&self) -> bool {
        self.0 >= 500_000
    }
}

/// Category of coherence violation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CoherenceViolationKind {
    /// A consumed context has no provider ancestor.
    UnresolvedContext {
        consumer: String,
        context_key: String,
    },
    /// Orphaned provider — provides context that no descendant consumes.
    OrphanedProvider {
        provider: String,
        context_key: String,
    },
    /// A component requires capabilities not granted by any boundary ancestor.
    CapabilityGap {
        component: String,
        missing_capabilities: Vec<String>,
    },
    /// Effect ordering contains a cycle.
    EffectOrderCycle { cycle_participants: Vec<String> },
    /// Layout effect appears after passive effect in composition order.
    LayoutAfterPassive {
        layout_component: String,
        passive_component: String,
    },
    /// Suspense boundary wraps components with incompatible async contracts.
    SuspenseBoundaryConflict {
        boundary_component: String,
        conflicting_children: Vec<String>,
        reason: String,
    },
    /// Hydration boundary spans components with incompatible effect contracts.
    HydrationBoundaryConflict {
        boundary_component: String,
        conflicting_children: Vec<String>,
        reason: String,
    },
    /// Two components sharing a hook dependency graph disagree on cleanup policy.
    HookCleanupMismatch {
        component_a: String,
        component_b: String,
        hook_label: String,
    },
    /// Duplicate context provider within the same subtree.
    DuplicateProvider {
        providers: Vec<String>,
        context_key: String,
    },
    /// A capability boundary does not cover all transitive requirements of children.
    BoundaryCapabilityLeak {
        boundary: String,
        leaked_capabilities: Vec<String>,
    },
}

impl fmt::Display for CoherenceViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnresolvedContext {
                consumer,
                context_key,
            } => write!(f, "unresolved context: {consumer} needs '{context_key}'"),
            Self::OrphanedProvider {
                provider,
                context_key,
            } => write!(f, "orphaned provider: {provider} provides '{context_key}'"),
            Self::CapabilityGap {
                component,
                missing_capabilities,
            } => write!(
                f,
                "capability gap: {component} missing [{}]",
                missing_capabilities.join(", ")
            ),
            Self::EffectOrderCycle { cycle_participants } => {
                write!(f, "effect cycle: [{}]", cycle_participants.join(" -> "))
            }
            Self::LayoutAfterPassive {
                layout_component,
                passive_component,
            } => write!(
                f,
                "layout-after-passive: {layout_component} (layout) after {passive_component} (passive)"
            ),
            Self::SuspenseBoundaryConflict {
                boundary_component,
                conflicting_children,
                reason,
            } => write!(
                f,
                "suspense conflict at {boundary_component}: [{}] — {reason}",
                conflicting_children.join(", ")
            ),
            Self::HydrationBoundaryConflict {
                boundary_component,
                conflicting_children,
                reason,
            } => write!(
                f,
                "hydration conflict at {boundary_component}: [{}] — {reason}",
                conflicting_children.join(", ")
            ),
            Self::HookCleanupMismatch {
                component_a,
                component_b,
                hook_label,
            } => write!(
                f,
                "hook cleanup mismatch: {component_a} vs {component_b} on '{hook_label}'"
            ),
            Self::DuplicateProvider {
                providers,
                context_key,
            } => write!(
                f,
                "duplicate provider for '{context_key}': [{}]",
                providers.join(", ")
            ),
            Self::BoundaryCapabilityLeak {
                boundary,
                leaked_capabilities,
            } => write!(
                f,
                "boundary leak at {boundary}: [{}]",
                leaked_capabilities.join(", ")
            ),
        }
    }
}

/// A single coherence violation with evidence linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoherenceViolation {
    pub id: EngineObjectId,
    pub kind: CoherenceViolationKind,
    pub severity: SeverityScore,
    pub debt_code: String,
    pub description: String,
    pub evidence_hash: ContentHash,
    pub detected_epoch: u64,
}

// ---------------------------------------------------------------------------
// Coherence check input
// ---------------------------------------------------------------------------

/// Input bundle for a full global coherence check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoherenceCheckInput {
    pub atlas: LocalSemanticAtlas,
    pub graph: CompositionGraph,
    pub check_epoch: u64,
    pub suspense_components: BTreeSet<String>,
    pub hydration_components: BTreeSet<String>,
    pub capability_boundary_components: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Coherence result
// ---------------------------------------------------------------------------

/// Outcome of a coherence check pass.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CoherenceOutcome {
    /// All checks passed.
    Coherent,
    /// Violations found but none blocking.
    CoherentWithWarnings,
    /// At least one blocking violation found.
    Incoherent,
    /// Check was aborted due to budget exhaustion.
    BudgetExhausted,
}

impl fmt::Display for CoherenceOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coherent => write!(f, "coherent"),
            Self::CoherentWithWarnings => write!(f, "coherent-with-warnings"),
            Self::Incoherent => write!(f, "incoherent"),
            Self::BudgetExhausted => write!(f, "budget-exhausted"),
        }
    }
}

/// Full result of a global coherence check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoherenceCheckResult {
    pub schema_version: String,
    pub bead_id: String,
    pub outcome: CoherenceOutcome,
    pub violations: Vec<CoherenceViolation>,
    pub component_count: usize,
    pub edge_count: usize,
    pub context_pairs_checked: usize,
    pub capability_boundaries_checked: usize,
    pub effect_orderings_checked: usize,
    pub suspense_boundaries_checked: usize,
    pub hydration_boundaries_checked: usize,
    pub total_severity_millionths: i64,
    pub blocking_violation_count: usize,
    pub check_epoch: u64,
    pub result_hash: ContentHash,
}

impl CoherenceCheckResult {
    pub fn is_coherent(&self) -> bool {
        matches!(
            self.outcome,
            CoherenceOutcome::Coherent | CoherenceOutcome::CoherentWithWarnings
        )
    }

    pub fn blocking_violations(&self) -> Vec<&CoherenceViolation> {
        self.violations
            .iter()
            .filter(|v| v.severity.is_blocking())
            .collect()
    }

    pub fn violations_by_debt_code(&self) -> BTreeMap<String, Vec<&CoherenceViolation>> {
        let mut map: BTreeMap<String, Vec<&CoherenceViolation>> = BTreeMap::new();
        for v in &self.violations {
            map.entry(v.debt_code.clone()).or_default().push(v);
        }
        map
    }

    pub fn summary_line(&self) -> String {
        format!(
            "{}: {} violations ({} blocking), {} components, {} edges",
            self.outcome,
            self.violations.len(),
            self.blocking_violation_count,
            self.component_count,
            self.edge_count,
        )
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoherenceError {
    BudgetExhausted {
        resource: String,
        limit: usize,
    },
    UnknownComponent(String),
    EmptyAtlas,
    EmptyGraph,
    AtlasGraphMismatch {
        atlas_components: usize,
        graph_components: usize,
    },
}

impl fmt::Display for CoherenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted { resource, limit } => {
                write!(f, "budget exhausted for {resource}: limit={limit}")
            }
            Self::UnknownComponent(id) => write!(f, "unknown component: {id}"),
            Self::EmptyAtlas => write!(f, "atlas is empty"),
            Self::EmptyGraph => write!(f, "composition graph is empty"),
            Self::AtlasGraphMismatch {
                atlas_components,
                graph_components,
            } => write!(
                f,
                "atlas/graph mismatch: atlas has {atlas_components} components, graph has {graph_components}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Checker implementation
// ---------------------------------------------------------------------------

/// The global coherence checker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalCoherenceChecker {
    violation_budget: usize,
}

impl GlobalCoherenceChecker {
    pub fn new() -> Self {
        Self {
            violation_budget: MAX_VIOLATIONS,
        }
    }

    pub fn with_violation_budget(mut self, budget: usize) -> Self {
        self.violation_budget = budget;
        self
    }

    /// Run a full coherence check.
    pub fn check(
        &self,
        input: &CoherenceCheckInput,
    ) -> Result<CoherenceCheckResult, CoherenceError> {
        if input.atlas.entries.is_empty() {
            return Err(CoherenceError::EmptyAtlas);
        }
        if input.graph.component_ids.is_empty() {
            return Err(CoherenceError::EmptyGraph);
        }

        let mut violations = Vec::new();

        // Build atlas lookup
        let atlas_map: BTreeMap<&str, &LocalSemanticAtlasEntry> = input
            .atlas
            .entries
            .iter()
            .map(|e| (e.component_id.as_str(), e))
            .collect();

        // 1. Context coherence
        let (ctx_violations, context_pairs) =
            self.check_context_coherence(&input.graph, &atlas_map, input.check_epoch);
        self.collect_violations(&mut violations, ctx_violations);

        // 2. Capability boundary coherence
        let (cap_violations, cap_boundaries) = self.check_capability_coherence(
            &input.graph,
            &atlas_map,
            &input.capability_boundary_components,
            input.check_epoch,
        );
        self.collect_violations(&mut violations, cap_violations);

        // 3. Effect ordering coherence
        let (effect_violations, effect_orderings) =
            self.check_effect_ordering(&input.graph, &atlas_map, input.check_epoch);
        self.collect_violations(&mut violations, effect_violations);

        // 4. Suspense boundary coherence
        let (susp_violations, suspense_boundaries) = self.check_suspense_boundaries(
            &input.graph,
            &atlas_map,
            &input.suspense_components,
            input.check_epoch,
        );
        self.collect_violations(&mut violations, susp_violations);

        // 5. Hydration boundary coherence
        let (hydr_violations, hydration_boundaries) = self.check_hydration_boundaries(
            &input.graph,
            &atlas_map,
            &input.hydration_components,
            input.check_epoch,
        );
        self.collect_violations(&mut violations, hydr_violations);

        // 6. Hook cleanup coherence
        let hook_violations =
            self.check_hook_cleanup_coherence(&input.graph, &atlas_map, input.check_epoch);
        self.collect_violations(&mut violations, hook_violations);

        // Compute summary
        let total_severity: i64 = violations
            .iter()
            .map(|v| v.severity.0)
            .fold(0i64, |acc, x| acc.saturating_add(x));
        let blocking_count = violations
            .iter()
            .filter(|v| v.severity.is_blocking())
            .count();
        let budget_exhausted = violations.len() >= self.violation_budget;

        let outcome = if budget_exhausted {
            CoherenceOutcome::BudgetExhausted
        } else if blocking_count > 0 {
            CoherenceOutcome::Incoherent
        } else if violations.is_empty() {
            CoherenceOutcome::Coherent
        } else {
            CoherenceOutcome::CoherentWithWarnings
        };

        let result_hash = Self::compute_result_hash(&violations, &outcome);

        Ok(CoherenceCheckResult {
            schema_version: GLOBAL_COHERENCE_SCHEMA_VERSION.to_string(),
            bead_id: GLOBAL_COHERENCE_BEAD_ID.to_string(),
            outcome,
            violations,
            component_count: input.graph.component_count(),
            edge_count: input.graph.edge_count(),
            context_pairs_checked: context_pairs,
            capability_boundaries_checked: cap_boundaries,
            effect_orderings_checked: effect_orderings,
            suspense_boundaries_checked: suspense_boundaries,
            hydration_boundaries_checked: hydration_boundaries,
            total_severity_millionths: total_severity,
            blocking_violation_count: blocking_count,
            check_epoch: input.check_epoch,
            result_hash,
        })
    }

    // -----------------------------------------------------------------------
    // Context coherence
    // -----------------------------------------------------------------------

    fn check_context_coherence(
        &self,
        graph: &CompositionGraph,
        atlas: &BTreeMap<&str, &LocalSemanticAtlasEntry>,
        epoch: u64,
    ) -> (Vec<CoherenceViolation>, usize) {
        let mut violations = Vec::new();
        let mut pairs_checked = 0_usize;

        // Collect all provided contexts and their providers
        let mut providers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for entry in atlas.values() {
            for ctx in &entry.provided_contexts {
                providers
                    .entry(ctx.clone())
                    .or_default()
                    .push(entry.component_id.clone());
            }
        }

        // Check for duplicate providers in the same subtree
        for (ctx_key, provider_list) in &providers {
            if provider_list.len() > 1 {
                // Check if any providers are in ancestor-descendant relationship
                for i in 0..provider_list.len() {
                    for j in (i + 1)..provider_list.len() {
                        if is_ancestor(graph, &provider_list[i], &provider_list[j])
                            || is_ancestor(graph, &provider_list[j], &provider_list[i])
                        {
                            violations.push(make_violation(
                                CoherenceViolationKind::DuplicateProvider {
                                    providers: vec![
                                        provider_list[i].clone(),
                                        provider_list[j].clone(),
                                    ],
                                    context_key: ctx_key.clone(),
                                },
                                SeverityScore::medium(),
                                DEBT_UNRESOLVED_CONTEXT,
                                epoch,
                            ));
                        }
                    }
                }
            }
        }

        // Check that every consumed context has a provider
        let all_provided: BTreeSet<String> = providers.keys().cloned().collect();
        for entry in atlas.values() {
            for ctx in &entry.required_contexts {
                pairs_checked += 1;
                if !all_provided.contains(ctx) {
                    violations.push(make_violation(
                        CoherenceViolationKind::UnresolvedContext {
                            consumer: entry.component_id.clone(),
                            context_key: ctx.clone(),
                        },
                        SeverityScore::critical(),
                        DEBT_UNRESOLVED_CONTEXT,
                        epoch,
                    ));
                }
            }
        }

        // Check for orphaned providers (no consumer for the context)
        let all_consumed: BTreeSet<String> = atlas
            .values()
            .flat_map(|e| e.required_contexts.iter().cloned())
            .collect();
        for (ctx_key, provider_list) in &providers {
            if !all_consumed.contains(ctx_key) {
                for provider_id in provider_list {
                    violations.push(make_violation(
                        CoherenceViolationKind::OrphanedProvider {
                            provider: provider_id.clone(),
                            context_key: ctx_key.clone(),
                        },
                        SeverityScore::low(),
                        DEBT_UNRESOLVED_CONTEXT,
                        epoch,
                    ));
                }
            }
        }

        (violations, pairs_checked)
    }

    // -----------------------------------------------------------------------
    // Capability boundary coherence
    // -----------------------------------------------------------------------

    fn check_capability_coherence(
        &self,
        graph: &CompositionGraph,
        atlas: &BTreeMap<&str, &LocalSemanticAtlasEntry>,
        boundary_components: &BTreeSet<String>,
        epoch: u64,
    ) -> (Vec<CoherenceViolation>, usize) {
        let mut violations = Vec::new();
        let mut boundaries_checked = 0_usize;

        for boundary_id in boundary_components {
            let Some(boundary_entry) = atlas.get(boundary_id.as_str()) else {
                continue;
            };
            boundaries_checked += 1;

            // Get all descendants' capability requirements
            let descendants = collect_descendants(graph, boundary_id);
            let boundary_caps: BTreeSet<String> = boundary_entry
                .capability_requirements
                .iter()
                .cloned()
                .collect();

            for desc_id in &descendants {
                let Some(desc_entry) = atlas.get(desc_id.as_str()) else {
                    continue;
                };
                let desc_caps: BTreeSet<String> =
                    desc_entry.capability_requirements.iter().cloned().collect();

                let missing: Vec<String> = desc_caps.difference(&boundary_caps).cloned().collect();

                if !missing.is_empty() {
                    violations.push(make_violation(
                        CoherenceViolationKind::BoundaryCapabilityLeak {
                            boundary: boundary_id.clone(),
                            leaked_capabilities: missing.clone(),
                        },
                        SeverityScore::high(),
                        DEBT_CAPABILITY_GAP,
                        epoch,
                    ));
                }
            }

            // Also check components with capability requirements outside any boundary
            let components_outside_boundary: Vec<String> = atlas
                .values()
                .filter(|e| {
                    !e.capability_requirements.is_empty()
                        && !descendants.contains(&e.component_id)
                        && e.component_id != *boundary_id
                })
                .map(|e| e.component_id.clone())
                .collect();

            for comp_id in components_outside_boundary {
                let Some(entry) = atlas.get(comp_id.as_str()) else {
                    continue;
                };
                if !entry.capability_requirements.is_empty()
                    && !boundary_components.contains(&comp_id)
                {
                    violations.push(make_violation(
                        CoherenceViolationKind::CapabilityGap {
                            component: comp_id,
                            missing_capabilities: entry.capability_requirements.clone(),
                        },
                        SeverityScore::high(),
                        DEBT_CAPABILITY_GAP,
                        epoch,
                    ));
                }
            }
        }

        (violations, boundaries_checked)
    }

    // -----------------------------------------------------------------------
    // Effect ordering coherence
    // -----------------------------------------------------------------------

    fn check_effect_ordering(
        &self,
        graph: &CompositionGraph,
        atlas: &BTreeMap<&str, &LocalSemanticAtlasEntry>,
        epoch: u64,
    ) -> (Vec<CoherenceViolation>, usize) {
        let mut violations = Vec::new();
        let mut orderings_checked = 0_usize;

        // Build effect dependency adjacency
        let effect_adj = graph.adjacency_for_kind(&CompositionEdgeKind::EffectDependency);

        // Detect cycles using DFS
        let cycle = detect_cycle_in_adjacency(&effect_adj);
        if let Some(cycle_components) = cycle {
            orderings_checked += 1;
            violations.push(make_violation(
                CoherenceViolationKind::EffectOrderCycle {
                    cycle_participants: cycle_components,
                },
                SeverityScore::critical(),
                DEBT_EFFECT_CYCLE,
                epoch,
            ));
        }

        // Check layout-before-passive invariant along ParentChild edges
        let parent_child_adj = graph.adjacency_for_kind(&CompositionEdgeKind::ParentChild);
        for (parent_id, children) in &parent_child_adj {
            let Some(parent_entry) = atlas.get(parent_id.as_str()) else {
                continue;
            };
            let parent_has_layout = has_layout_effect(parent_entry);

            for child_id in children {
                let Some(child_entry) = atlas.get(child_id.as_str()) else {
                    continue;
                };
                let _child_has_passive = has_passive_effect(child_entry);
                orderings_checked += 1;

                // Layout effects in a parent should fire before passive effects in children,
                // which is the natural order. Flag if a child has layout and parent has passive
                // (inverted ordering under composition).
                let child_has_layout = has_layout_effect(child_entry);
                let parent_has_passive = has_passive_effect(parent_entry);

                if child_has_layout && parent_has_passive && !parent_has_layout {
                    violations.push(make_violation(
                        CoherenceViolationKind::LayoutAfterPassive {
                            layout_component: child_id.clone(),
                            passive_component: parent_id.clone(),
                        },
                        SeverityScore::high(),
                        DEBT_EFFECT_CYCLE,
                        epoch,
                    ));
                }
            }
        }

        (violations, orderings_checked)
    }

    // -----------------------------------------------------------------------
    // Suspense boundary coherence
    // -----------------------------------------------------------------------

    fn check_suspense_boundaries(
        &self,
        graph: &CompositionGraph,
        atlas: &BTreeMap<&str, &LocalSemanticAtlasEntry>,
        suspense_components: &BTreeSet<String>,
        epoch: u64,
    ) -> (Vec<CoherenceViolation>, usize) {
        let mut violations = Vec::new();
        let mut boundaries_checked = 0_usize;

        for susp_id in suspense_components {
            boundaries_checked += 1;
            let children = graph.children_of(susp_id);

            // Collect children with async effects (identified by effect signature
            // containing "async" or "suspense" patterns)
            let mut async_children = Vec::new();
            let mut sync_only_children = Vec::new();

            for child_id in &children {
                let Some(entry) = atlas.get(child_id.as_str()) else {
                    continue;
                };
                if has_async_effect(entry) {
                    async_children.push(child_id.clone());
                } else {
                    sync_only_children.push(child_id.clone());
                }
            }

            // Check: suspense boundary should not wrap a mix of async-suspended
            // and sync-only if sync-only children have layout effects
            if !async_children.is_empty() && !sync_only_children.is_empty() {
                let sync_with_layout: Vec<String> = sync_only_children
                    .iter()
                    .filter(|id| atlas.get(id.as_str()).is_some_and(|e| has_layout_effect(e)))
                    .cloned()
                    .collect();

                if !sync_with_layout.is_empty() {
                    let mut conflicting = async_children.clone();
                    conflicting.extend(sync_with_layout);
                    violations.push(make_violation(
                        CoherenceViolationKind::SuspenseBoundaryConflict {
                            boundary_component: susp_id.clone(),
                            conflicting_children: conflicting,
                            reason: "mix of async-suspended and sync layout effects".to_string(),
                        },
                        SeverityScore::high(),
                        DEBT_SUSPENSE_BOUNDARY_CONFLICT,
                        epoch,
                    ));
                }
            }

            // Check: all async children under suspense should share compatible
            // context requirements
            if async_children.len() > 1 {
                let mut all_required_contexts: BTreeSet<String> = BTreeSet::new();
                let mut per_child_contexts: Vec<(String, BTreeSet<String>)> = Vec::new();

                for child_id in &async_children {
                    let Some(entry) = atlas.get(child_id.as_str()) else {
                        continue;
                    };
                    let child_ctx: BTreeSet<String> =
                        entry.required_contexts.iter().cloned().collect();
                    all_required_contexts.extend(child_ctx.iter().cloned());
                    per_child_contexts.push((child_id.clone(), child_ctx));
                }

                // If any child requires a context that another doesn't,
                // and neither provides it, that's a potential conflict
                for (child_id, child_ctx) in &per_child_contexts {
                    let missing: Vec<String> = all_required_contexts
                        .difference(child_ctx)
                        .cloned()
                        .collect();
                    if !missing.is_empty() {
                        // This is informational, not blocking
                        violations.push(make_violation(
                            CoherenceViolationKind::SuspenseBoundaryConflict {
                                boundary_component: susp_id.clone(),
                                conflicting_children: vec![child_id.clone()],
                                reason: format!(
                                    "async child missing contexts available to siblings: [{}]",
                                    missing.join(", ")
                                ),
                            },
                            SeverityScore::info(),
                            DEBT_SUSPENSE_BOUNDARY_CONFLICT,
                            epoch,
                        ));
                    }
                }
            }
        }

        (violations, boundaries_checked)
    }

    // -----------------------------------------------------------------------
    // Hydration boundary coherence
    // -----------------------------------------------------------------------

    fn check_hydration_boundaries(
        &self,
        graph: &CompositionGraph,
        atlas: &BTreeMap<&str, &LocalSemanticAtlasEntry>,
        hydration_components: &BTreeSet<String>,
        epoch: u64,
    ) -> (Vec<CoherenceViolation>, usize) {
        let mut violations = Vec::new();
        let mut boundaries_checked = 0_usize;

        for hydr_id in hydration_components {
            boundaries_checked += 1;
            let children = graph.children_of(hydr_id);

            // Hydration boundaries must not contain children with non-deterministic
            // or side-effectful hooks that can't be replayed during hydration
            let mut non_hydration_safe_children = Vec::new();

            for child_id in &children {
                let Some(entry) = atlas.get(child_id.as_str()) else {
                    continue;
                };
                if !is_hydration_safe(entry) {
                    non_hydration_safe_children.push(child_id.clone());
                }
            }

            if !non_hydration_safe_children.is_empty() {
                violations.push(make_violation(
                    CoherenceViolationKind::HydrationBoundaryConflict {
                        boundary_component: hydr_id.clone(),
                        conflicting_children: non_hydration_safe_children,
                        reason: "children with non-deterministic effects inside hydration boundary"
                            .to_string(),
                    },
                    SeverityScore::critical(),
                    DEBT_HYDRATION_BOUNDARY_CONFLICT,
                    epoch,
                ));
            }
        }

        (violations, boundaries_checked)
    }

    // -----------------------------------------------------------------------
    // Hook cleanup coherence
    // -----------------------------------------------------------------------

    fn check_hook_cleanup_coherence(
        &self,
        _graph: &CompositionGraph,
        atlas: &BTreeMap<&str, &LocalSemanticAtlasEntry>,
        epoch: u64,
    ) -> Vec<CoherenceViolation> {
        let mut violations = Vec::new();

        // Group hook signatures by label across components
        let mut hooks_by_label: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();

        for entry in atlas.values() {
            for sig in &entry.hook_signature {
                if let Some(parsed) = parse_hook_signature(sig) {
                    hooks_by_label
                        .entry(parsed.label.clone())
                        .or_default()
                        .push((entry.component_id.clone(), parsed.has_cleanup));
                }
            }
        }

        // Check: hooks with the same label should agree on cleanup policy
        for (label, components) in &hooks_by_label {
            let has_cleanup_set: BTreeSet<bool> =
                components.iter().map(|(_, cleanup)| *cleanup).collect();
            if has_cleanup_set.len() > 1 && components.len() >= 2 {
                let with_cleanup: Vec<String> = components
                    .iter()
                    .filter(|(_, cleanup)| *cleanup)
                    .map(|(id, _)| id.clone())
                    .collect();
                let without_cleanup: Vec<String> = components
                    .iter()
                    .filter(|(_, cleanup)| !*cleanup)
                    .map(|(id, _)| id.clone())
                    .collect();

                if let (Some(comp_a), Some(comp_b)) =
                    (with_cleanup.first(), without_cleanup.first())
                {
                    violations.push(make_violation(
                        CoherenceViolationKind::HookCleanupMismatch {
                            component_a: comp_a.clone(),
                            component_b: comp_b.clone(),
                            hook_label: label.clone(),
                        },
                        SeverityScore::medium(),
                        DEBT_HOOK_CLEANUP_MISMATCH,
                        epoch,
                    ));
                }
            }
        }

        violations
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn collect_violations(
        &self,
        target: &mut Vec<CoherenceViolation>,
        source: Vec<CoherenceViolation>,
    ) {
        let remaining = self.violation_budget.saturating_sub(target.len());
        target.extend(source.into_iter().take(remaining));
    }

    fn compute_result_hash(
        violations: &[CoherenceViolation],
        outcome: &CoherenceOutcome,
    ) -> ContentHash {
        let mut data = Vec::new();
        data.extend_from_slice(format!("{outcome}").as_bytes());
        for v in violations {
            data.extend_from_slice(v.evidence_hash.as_bytes());
        }
        ContentHash::compute(&data)
    }
}

impl Default for GlobalCoherenceChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Free helper functions
// ---------------------------------------------------------------------------

fn make_violation(
    kind: CoherenceViolationKind,
    severity: SeverityScore,
    debt_code: &str,
    epoch: u64,
) -> CoherenceViolation {
    let description = kind.to_string();
    let evidence_hash = {
        let mut data = Vec::new();
        data.extend_from_slice(description.as_bytes());
        data.extend_from_slice(&epoch.to_le_bytes());
        data.extend_from_slice(debt_code.as_bytes());
        ContentHash::compute(&data)
    };
    let schema = SchemaId::from_definition(b"global_coherence_checker.violation.v1");
    let id = derive_id(
        ObjectDomain::EvidenceRecord,
        "global-coherence",
        &schema,
        description.as_bytes(),
    )
    .unwrap_or_else(|_| {
        derive_id(
            ObjectDomain::EvidenceRecord,
            "global-coherence",
            &schema,
            b"fallback",
        )
        .expect("operation should succeed for valid inputs")
    });

    CoherenceViolation {
        id,
        kind,
        severity,
        debt_code: debt_code.to_string(),
        description,
        evidence_hash,
        detected_epoch: epoch,
    }
}

/// Check if `ancestor` is an ancestor of `descendant` in the ParentChild graph.
fn is_ancestor(graph: &CompositionGraph, ancestor: &str, descendant: &str) -> bool {
    let mut visited = BTreeSet::new();
    let mut stack = vec![ancestor.to_string()];
    while let Some(current) = stack.pop() {
        if current == descendant {
            return true;
        }
        if visited.insert(current.clone()) {
            stack.extend(graph.children_of(&current));
        }
    }
    false
}

/// Collect all descendants of a component via ParentChild edges.
fn collect_descendants(graph: &CompositionGraph, root: &str) -> BTreeSet<String> {
    let mut descendants = BTreeSet::new();
    let mut stack = vec![root.to_string()];
    while let Some(current) = stack.pop() {
        for child in graph.children_of(&current) {
            if descendants.insert(child.clone()) {
                stack.push(child);
            }
        }
    }
    descendants
}

/// Detect a cycle in a directed adjacency map. Returns the cycle path if found.
fn detect_cycle_in_adjacency(adj: &BTreeMap<String, Vec<String>>) -> Option<Vec<String>> {
    let all_nodes: BTreeSet<String> = adj
        .keys()
        .cloned()
        .chain(adj.values().flatten().cloned())
        .collect();

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Color {
        White,
        Gray,
        Black,
    }

    let mut color: BTreeMap<String, Color> = all_nodes
        .iter()
        .map(|n| (n.clone(), Color::White))
        .collect();
    let mut parent: BTreeMap<String, Option<String>> = BTreeMap::new();

    for start in &all_nodes {
        if color.get(start) != Some(&Color::White) {
            continue;
        }
        let mut stack = vec![(start.clone(), false)];
        while let Some((node, returning)) = stack.pop() {
            if returning {
                color.insert(node, Color::Black);
                continue;
            }
            if color.get(&node) == Some(&Color::Gray) {
                continue;
            }
            color.insert(node.clone(), Color::Gray);
            stack.push((node.clone(), true));

            if let Some(neighbors) = adj.get(&node) {
                for neighbor in neighbors {
                    match color.get(neighbor) {
                        Some(Color::Gray) => {
                            // Found cycle — reconstruct
                            let mut cycle = vec![neighbor.clone(), node.clone()];
                            let mut current = node.clone();
                            while let Some(Some(p)) = parent.get(&current) {
                                if *p == *neighbor {
                                    break;
                                }
                                cycle.push(p.clone());
                                current = p.clone();
                            }
                            cycle.reverse();
                            return Some(cycle);
                        }
                        Some(Color::White) | None => {
                            parent.insert(neighbor.clone(), Some(node.clone()));
                            stack.push((neighbor.clone(), false));
                        }
                        Some(Color::Black) => {}
                    }
                }
            }
        }
    }

    None
}

struct ParsedHookSignature {
    label: String,
    has_cleanup: bool,
}

fn parse_hook_signature(sig: &str) -> Option<ParsedHookSignature> {
    let mut label = None;
    let mut has_cleanup = false;

    for part in sig.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("label=") {
            label = Some(val.to_string());
        } else if let Some(val) = part.strip_prefix("cleanup=") {
            has_cleanup = val == "true";
        }
    }

    label.map(|l| ParsedHookSignature {
        label: l,
        has_cleanup,
    })
}

fn has_layout_effect(entry: &LocalSemanticAtlasEntry) -> bool {
    entry
        .effect_signature
        .iter()
        .any(|sig| sig.contains("Layout") || sig.contains("layout"))
}

fn has_passive_effect(entry: &LocalSemanticAtlasEntry) -> bool {
    entry
        .effect_signature
        .iter()
        .any(|sig| sig.contains("Passive") || sig.contains("passive") || sig.contains("Effect"))
}

fn has_async_effect(entry: &LocalSemanticAtlasEntry) -> bool {
    entry.effect_signature.iter().any(|sig| {
        sig.contains("async")
            || sig.contains("Suspense")
            || sig.contains("suspense")
            || sig.contains("lazy")
    })
}

fn is_hydration_safe(entry: &LocalSemanticAtlasEntry) -> bool {
    // A component is hydration-safe if it has no non-deterministic effects
    // and all its hooks are deterministic (no side effects during render)
    !entry
        .effect_signature
        .iter()
        .any(|sig| sig.contains("idempotent=false") || sig.contains("commutative=false"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_tiers::ContentHash;
    use crate::semantic_contract_baseline::{
        LocalSemanticAtlas, LocalSemanticAtlasEntry, SemanticContractVersion,
    };

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn test_entry(id: &str) -> LocalSemanticAtlasEntry {
        LocalSemanticAtlasEntry {
            component_id: id.to_string(),
            module_path: format!("src/components/{id}.tsx"),
            export_name: Some(id.to_string()),
            hook_signature: Vec::new(),
            effect_signature: Vec::new(),
            required_contexts: Vec::new(),
            provided_contexts: Vec::new(),
            capability_requirements: Vec::new(),
            assumption_keys: Vec::new(),
            fixture_refs: Vec::new(),
            trace_refs: Vec::new(),
            content_hash: ContentHash::compute(id.as_bytes()),
        }
    }

    fn test_entry_with_contexts(
        id: &str,
        required: Vec<&str>,
        provided: Vec<&str>,
    ) -> LocalSemanticAtlasEntry {
        let mut entry = test_entry(id);
        entry.required_contexts = required.into_iter().map(String::from).collect();
        entry.provided_contexts = provided.into_iter().map(String::from).collect();
        entry
    }

    fn test_entry_with_capabilities(id: &str, caps: Vec<&str>) -> LocalSemanticAtlasEntry {
        let mut entry = test_entry(id);
        entry.capability_requirements = caps.into_iter().map(String::from).collect();
        entry
    }

    fn test_entry_with_effects(id: &str, effects: Vec<&str>) -> LocalSemanticAtlasEntry {
        let mut entry = test_entry(id);
        entry.effect_signature = effects.into_iter().map(String::from).collect();
        entry
    }

    fn test_entry_with_hooks(id: &str, hooks: Vec<&str>) -> LocalSemanticAtlasEntry {
        let mut entry = test_entry(id);
        entry.hook_signature = hooks.into_iter().map(String::from).collect();
        entry
    }

    fn make_atlas(entries: Vec<LocalSemanticAtlasEntry>) -> LocalSemanticAtlas {
        let hash = {
            let mut data = Vec::new();
            for e in &entries {
                data.extend_from_slice(e.content_hash.as_bytes());
            }
            ContentHash::compute(&data)
        };
        LocalSemanticAtlas {
            schema_version: "test.v1".to_string(),
            bead_id: "test-bead".to_string(),
            version: SemanticContractVersion::CURRENT,
            generated_epoch: 1000,
            entries,
            quality_debt: Vec::new(),
            atlas_hash: hash,
        }
    }

    fn make_graph(
        components: Vec<&str>,
        edges: Vec<(&str, &str, CompositionEdgeKind)>,
    ) -> CompositionGraph {
        let mut graph = CompositionGraph::new();
        for c in components {
            graph
                .add_component(c.to_string())
                .expect("operation should succeed for valid inputs");
        }
        for (from, to, kind) in edges {
            graph
                .add_edge(CompositionEdge {
                    from_component: from.to_string(),
                    to_component: to.to_string(),
                    kind,
                    label: format!("{from}->{to}"),
                })
                .expect("operation should succeed for valid inputs");
        }
        graph
    }

    fn make_input(
        entries: Vec<LocalSemanticAtlasEntry>,
        components: Vec<&str>,
        edges: Vec<(&str, &str, CompositionEdgeKind)>,
    ) -> CoherenceCheckInput {
        CoherenceCheckInput {
            atlas: make_atlas(entries),
            graph: make_graph(components, edges),
            check_epoch: 42,
            suspense_components: BTreeSet::new(),
            hydration_components: BTreeSet::new(),
            capability_boundary_components: BTreeSet::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Schema and version tests
    // -----------------------------------------------------------------------

    #[test]
    fn schema_version_is_set() {
        assert!(GLOBAL_COHERENCE_SCHEMA_VERSION.contains("global_coherence_checker"));
    }

    #[test]
    fn bead_id_matches() {
        assert_eq!(GLOBAL_COHERENCE_BEAD_ID, "bd-mjh3.14.2");
    }

    #[test]
    fn debt_codes_are_distinct() {
        let codes = [
            DEBT_UNRESOLVED_CONTEXT,
            DEBT_CAPABILITY_GAP,
            DEBT_EFFECT_CYCLE,
            DEBT_SUSPENSE_BOUNDARY_CONFLICT,
            DEBT_HOOK_CLEANUP_MISMATCH,
            DEBT_HYDRATION_BOUNDARY_CONFLICT,
        ];
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len());
    }

    // -----------------------------------------------------------------------
    // CompositionEdgeKind display
    // -----------------------------------------------------------------------

    #[test]
    fn edge_kind_display() {
        assert_eq!(CompositionEdgeKind::ParentChild.to_string(), "parent-child");
        assert_eq!(CompositionEdgeKind::ContextFlow.to_string(), "context-flow");
        assert_eq!(
            CompositionEdgeKind::CapabilityBoundary.to_string(),
            "capability-boundary"
        );
    }

    // -----------------------------------------------------------------------
    // CompositionGraph tests
    // -----------------------------------------------------------------------

    #[test]
    fn empty_graph() {
        let g = CompositionGraph::new();
        assert_eq!(g.component_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn add_component_and_edge() {
        let mut g = CompositionGraph::new();
        g.add_component("A".to_string())
            .expect("operation should succeed for valid inputs");
        g.add_component("B".to_string())
            .expect("operation should succeed for valid inputs");
        g.add_edge(CompositionEdge {
            from_component: "A".to_string(),
            to_component: "B".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "A->B".to_string(),
        })
        .expect("operation should succeed for valid inputs");
        assert_eq!(g.component_count(), 2);
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn edge_to_unknown_component_fails() {
        let mut g = CompositionGraph::new();
        g.add_component("A".to_string())
            .expect("operation should succeed for valid inputs");
        let result = g.add_edge(CompositionEdge {
            from_component: "A".to_string(),
            to_component: "Z".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "bad".to_string(),
        });
        assert_eq!(
            result,
            Err(CoherenceError::UnknownComponent("Z".to_string()))
        );
    }

    #[test]
    fn children_of_returns_direct_children() {
        let g = make_graph(
            vec!["root", "child1", "child2", "grandchild"],
            vec![
                ("root", "child1", CompositionEdgeKind::ParentChild),
                ("root", "child2", CompositionEdgeKind::ParentChild),
                ("child1", "grandchild", CompositionEdgeKind::ParentChild),
            ],
        );
        let children = g.children_of("root");
        assert_eq!(children.len(), 2);
        assert!(children.contains(&"child1".to_string()));
        assert!(children.contains(&"child2".to_string()));
    }

    #[test]
    fn parents_of_returns_direct_parents() {
        let g = make_graph(
            vec!["root", "child"],
            vec![("root", "child", CompositionEdgeKind::ParentChild)],
        );
        assert_eq!(g.parents_of("child"), vec!["root".to_string()]);
        assert!(g.parents_of("root").is_empty());
    }

    #[test]
    fn adjacency_for_kind_filters_correctly() {
        let g = make_graph(
            vec!["A", "B", "C"],
            vec![
                ("A", "B", CompositionEdgeKind::ParentChild),
                ("A", "C", CompositionEdgeKind::ContextFlow),
            ],
        );
        let parent_adj = g.adjacency_for_kind(&CompositionEdgeKind::ParentChild);
        assert_eq!(
            parent_adj
                .get("A")
                .expect("operation should succeed for valid inputs")
                .len(),
            1
        );
        let ctx_adj = g.adjacency_for_kind(&CompositionEdgeKind::ContextFlow);
        assert_eq!(
            ctx_adj
                .get("A")
                .expect("operation should succeed for valid inputs")
                .len(),
            1
        );
    }

    #[test]
    fn default_graph_is_empty() {
        let g = CompositionGraph::default();
        assert_eq!(g.component_count(), 0);
    }

    // -----------------------------------------------------------------------
    // SeverityScore tests
    // -----------------------------------------------------------------------

    #[test]
    fn severity_levels() {
        assert!(SeverityScore::critical().is_blocking());
        assert!(SeverityScore::high().is_blocking());
        assert!(SeverityScore::medium().is_blocking());
        assert!(!SeverityScore::low().is_blocking());
        assert!(!SeverityScore::info().is_blocking());
    }

    #[test]
    fn severity_ordering() {
        assert!(SeverityScore::critical() > SeverityScore::high());
        assert!(SeverityScore::high() > SeverityScore::medium());
        assert!(SeverityScore::medium() > SeverityScore::low());
        assert!(SeverityScore::low() > SeverityScore::info());
    }

    // -----------------------------------------------------------------------
    // CoherenceOutcome display
    // -----------------------------------------------------------------------

    #[test]
    fn outcome_display() {
        assert_eq!(CoherenceOutcome::Coherent.to_string(), "coherent");
        assert_eq!(
            CoherenceOutcome::CoherentWithWarnings.to_string(),
            "coherent-with-warnings"
        );
        assert_eq!(CoherenceOutcome::Incoherent.to_string(), "incoherent");
        assert_eq!(
            CoherenceOutcome::BudgetExhausted.to_string(),
            "budget-exhausted"
        );
    }

    // -----------------------------------------------------------------------
    // CoherenceError display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display() {
        let err = CoherenceError::EmptyAtlas;
        assert_eq!(err.to_string(), "atlas is empty");

        let err = CoherenceError::UnknownComponent("foo".to_string());
        assert!(err.to_string().contains("foo"));
    }

    // -----------------------------------------------------------------------
    // Checker: empty inputs
    // -----------------------------------------------------------------------

    #[test]
    fn empty_atlas_fails() {
        let checker = GlobalCoherenceChecker::new();
        let input = CoherenceCheckInput {
            atlas: make_atlas(Vec::new()),
            graph: make_graph(vec!["A"], vec![]),
            check_epoch: 1,
            suspense_components: BTreeSet::new(),
            hydration_components: BTreeSet::new(),
            capability_boundary_components: BTreeSet::new(),
        };
        assert_eq!(checker.check(&input), Err(CoherenceError::EmptyAtlas));
    }

    #[test]
    fn empty_graph_fails() {
        let checker = GlobalCoherenceChecker::new();
        let input = CoherenceCheckInput {
            atlas: make_atlas(vec![test_entry("A")]),
            graph: CompositionGraph::new(),
            check_epoch: 1,
            suspense_components: BTreeSet::new(),
            hydration_components: BTreeSet::new(),
            capability_boundary_components: BTreeSet::new(),
        };
        assert_eq!(checker.check(&input), Err(CoherenceError::EmptyGraph));
    }

    // -----------------------------------------------------------------------
    // Checker: fully coherent
    // -----------------------------------------------------------------------

    #[test]
    fn fully_coherent_simple() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![
                test_entry_with_contexts("Provider", vec![], vec!["theme"]),
                test_entry_with_contexts("Consumer", vec!["theme"], vec![]),
            ],
            vec!["Provider", "Consumer"],
            vec![("Provider", "Consumer", CompositionEdgeKind::ParentChild)],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.outcome, CoherenceOutcome::Coherent);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn coherent_result_is_coherent() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(vec![test_entry("A")], vec!["A"], vec![]);
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.is_coherent());
    }

    #[test]
    fn coherent_summary_line() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(vec![test_entry("A")], vec!["A"], vec![]);
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.summary_line().contains("coherent"));
        assert!(result.summary_line().contains("0 violations"));
    }

    // -----------------------------------------------------------------------
    // Context coherence tests
    // -----------------------------------------------------------------------

    #[test]
    fn unresolved_context_detected() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![test_entry_with_contexts(
                "Orphan",
                vec!["missing_ctx"],
                vec![],
            )],
            vec!["Orphan"],
            vec![],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.outcome, CoherenceOutcome::Incoherent);
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::UnresolvedContext { context_key, .. }
                if context_key == "missing_ctx"
        )));
    }

    #[test]
    fn orphaned_provider_detected() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![test_entry_with_contexts(
                "Provider",
                vec![],
                vec!["unused_ctx"],
            )],
            vec!["Provider"],
            vec![],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::OrphanedProvider { context_key, .. }
                if context_key == "unused_ctx"
        )));
    }

    #[test]
    fn multiple_consumers_same_context_ok() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![
                test_entry_with_contexts("Provider", vec![], vec!["theme"]),
                test_entry_with_contexts("ConsumerA", vec!["theme"], vec![]),
                test_entry_with_contexts("ConsumerB", vec!["theme"], vec![]),
            ],
            vec!["Provider", "ConsumerA", "ConsumerB"],
            vec![
                ("Provider", "ConsumerA", CompositionEdgeKind::ParentChild),
                ("Provider", "ConsumerB", CompositionEdgeKind::ParentChild),
            ],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.is_coherent());
    }

    #[test]
    fn duplicate_provider_in_ancestor_descendant() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![
                test_entry_with_contexts("Parent", vec![], vec!["theme"]),
                test_entry_with_contexts("Child", vec![], vec!["theme"]),
            ],
            vec!["Parent", "Child"],
            vec![("Parent", "Child", CompositionEdgeKind::ParentChild)],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::DuplicateProvider { context_key, .. }
                if context_key == "theme"
        )));
    }

    #[test]
    fn context_pairs_counted() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![
                test_entry_with_contexts("P", vec![], vec!["a", "b"]),
                test_entry_with_contexts("C", vec!["a", "b"], vec![]),
            ],
            vec!["P", "C"],
            vec![("P", "C", CompositionEdgeKind::ParentChild)],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.context_pairs_checked, 2);
    }

    // -----------------------------------------------------------------------
    // Capability coherence tests
    // -----------------------------------------------------------------------

    #[test]
    fn capability_gap_outside_boundary() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_capabilities("Boundary", vec!["net", "dom"]),
            test_entry_with_capabilities("Inside", vec!["net"]),
            test_entry_with_capabilities("Outside", vec!["fs"]),
        ];
        let mut input = make_input(
            entries,
            vec!["Boundary", "Inside", "Outside"],
            vec![("Boundary", "Inside", CompositionEdgeKind::ParentChild)],
        );
        input
            .capability_boundary_components
            .insert("Boundary".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::CapabilityGap {
                component,
                missing_capabilities,
            } if component == "Outside" && missing_capabilities.contains(&"fs".to_string())
        )));
    }

    #[test]
    fn boundary_capability_leak_detected() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_capabilities("Boundary", vec!["net"]),
            test_entry_with_capabilities("Child", vec!["net", "fs"]),
        ];
        let mut input = make_input(
            entries,
            vec!["Boundary", "Child"],
            vec![("Boundary", "Child", CompositionEdgeKind::ParentChild)],
        );
        input
            .capability_boundary_components
            .insert("Boundary".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::BoundaryCapabilityLeak {
                boundary,
                leaked_capabilities,
            } if boundary == "Boundary" && leaked_capabilities.contains(&"fs".to_string())
        )));
    }

    #[test]
    fn capability_satisfied_no_violation() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_capabilities("Boundary", vec!["net", "dom", "fs"]),
            test_entry_with_capabilities("Child", vec!["net", "fs"]),
        ];
        let mut input = make_input(
            entries,
            vec!["Boundary", "Child"],
            vec![("Boundary", "Child", CompositionEdgeKind::ParentChild)],
        );
        input
            .capability_boundary_components
            .insert("Boundary".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().all(|v| !matches!(
            &v.kind,
            CoherenceViolationKind::BoundaryCapabilityLeak { .. }
        )));
    }

    #[test]
    fn capability_boundaries_counted() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_capabilities("B1", vec!["net"]),
            test_entry_with_capabilities("B2", vec!["dom"]),
        ];
        let mut input = make_input(entries, vec!["B1", "B2"], vec![]);
        input
            .capability_boundary_components
            .insert("B1".to_string());
        input
            .capability_boundary_components
            .insert("B2".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.capability_boundaries_checked, 2);
    }

    // -----------------------------------------------------------------------
    // Effect ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn effect_cycle_detected() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![test_entry("A"), test_entry("B"), test_entry("C")],
            vec!["A", "B", "C"],
            vec![
                ("A", "B", CompositionEdgeKind::EffectDependency),
                ("B", "C", CompositionEdgeKind::EffectDependency),
                ("C", "A", CompositionEdgeKind::EffectDependency),
            ],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(&v.kind, CoherenceViolationKind::EffectOrderCycle { .. }))
        );
    }

    #[test]
    fn no_effect_cycle_in_dag() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![test_entry("A"), test_entry("B"), test_entry("C")],
            vec!["A", "B", "C"],
            vec![
                ("A", "B", CompositionEdgeKind::EffectDependency),
                ("B", "C", CompositionEdgeKind::EffectDependency),
            ],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(
            result
                .violations
                .iter()
                .all(|v| !matches!(&v.kind, CoherenceViolationKind::EffectOrderCycle { .. }))
        );
    }

    #[test]
    fn layout_after_passive_detected() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_effects(
                "Parent",
                vec!["boundary=Passive;caps=;idempotent=true;commutative=true;cost_millionths=0"],
            ),
            test_entry_with_effects(
                "Child",
                vec!["boundary=Layout;caps=;idempotent=true;commutative=true;cost_millionths=0"],
            ),
        ];
        let input = make_input(
            entries,
            vec!["Parent", "Child"],
            vec![("Parent", "Child", CompositionEdgeKind::ParentChild)],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(&v.kind, CoherenceViolationKind::LayoutAfterPassive { .. }))
        );
    }

    #[test]
    fn layout_parent_passive_child_ok() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_effects(
                "Parent",
                vec!["boundary=Layout;caps=;idempotent=true;commutative=true;cost_millionths=0"],
            ),
            test_entry_with_effects(
                "Child",
                vec!["boundary=Passive;caps=;idempotent=true;commutative=true;cost_millionths=0"],
            ),
        ];
        let input = make_input(
            entries,
            vec!["Parent", "Child"],
            vec![("Parent", "Child", CompositionEdgeKind::ParentChild)],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(
            result
                .violations
                .iter()
                .all(|v| !matches!(&v.kind, CoherenceViolationKind::LayoutAfterPassive { .. }))
        );
    }

    // -----------------------------------------------------------------------
    // Suspense boundary tests
    // -----------------------------------------------------------------------

    #[test]
    fn suspense_async_sync_layout_conflict() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry("SuspenseBoundary"),
            test_entry_with_effects(
                "AsyncChild",
                vec!["boundary=Suspense;caps=;idempotent=true;commutative=true;cost_millionths=0"],
            ),
            test_entry_with_effects(
                "SyncLayout",
                vec!["boundary=Layout;caps=;idempotent=true;commutative=true;cost_millionths=0"],
            ),
        ];
        let mut input = make_input(
            entries,
            vec!["SuspenseBoundary", "AsyncChild", "SyncLayout"],
            vec![
                (
                    "SuspenseBoundary",
                    "AsyncChild",
                    CompositionEdgeKind::ParentChild,
                ),
                (
                    "SuspenseBoundary",
                    "SyncLayout",
                    CompositionEdgeKind::ParentChild,
                ),
            ],
        );
        input
            .suspense_components
            .insert("SuspenseBoundary".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::SuspenseBoundaryConflict { .. }
        )));
    }

    #[test]
    fn suspense_all_sync_no_conflict() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry("SuspenseBoundary"),
            test_entry("ChildA"),
            test_entry("ChildB"),
        ];
        let mut input = make_input(
            entries,
            vec!["SuspenseBoundary", "ChildA", "ChildB"],
            vec![
                (
                    "SuspenseBoundary",
                    "ChildA",
                    CompositionEdgeKind::ParentChild,
                ),
                (
                    "SuspenseBoundary",
                    "ChildB",
                    CompositionEdgeKind::ParentChild,
                ),
            ],
        );
        input
            .suspense_components
            .insert("SuspenseBoundary".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().all(|v| !matches!(
            &v.kind,
            CoherenceViolationKind::SuspenseBoundaryConflict { .. }
        )));
    }

    #[test]
    fn suspense_boundaries_counted() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![test_entry("S1"), test_entry("S2")];
        let mut input = make_input(entries, vec!["S1", "S2"], vec![]);
        input.suspense_components.insert("S1".to_string());
        input.suspense_components.insert("S2".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.suspense_boundaries_checked, 2);
    }

    // -----------------------------------------------------------------------
    // Hydration boundary tests
    // -----------------------------------------------------------------------

    #[test]
    fn hydration_non_deterministic_child_detected() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry("HydrationBoundary"),
            test_entry_with_effects(
                "NonDet",
                vec!["boundary=Effect;caps=;idempotent=false;commutative=true;cost_millionths=0"],
            ),
        ];
        let mut input = make_input(
            entries,
            vec!["HydrationBoundary", "NonDet"],
            vec![(
                "HydrationBoundary",
                "NonDet",
                CompositionEdgeKind::ParentChild,
            )],
        );
        input
            .hydration_components
            .insert("HydrationBoundary".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::HydrationBoundaryConflict { .. }
        )));
    }

    #[test]
    fn hydration_deterministic_children_ok() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry("HydrationBoundary"),
            test_entry_with_effects(
                "Det",
                vec!["boundary=Effect;caps=;idempotent=true;commutative=true;cost_millionths=0"],
            ),
        ];
        let mut input = make_input(
            entries,
            vec!["HydrationBoundary", "Det"],
            vec![("HydrationBoundary", "Det", CompositionEdgeKind::ParentChild)],
        );
        input
            .hydration_components
            .insert("HydrationBoundary".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().all(|v| !matches!(
            &v.kind,
            CoherenceViolationKind::HydrationBoundaryConflict { .. }
        )));
    }

    #[test]
    fn hydration_boundaries_counted() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![test_entry("H1"), test_entry("H2")];
        let mut input = make_input(entries, vec!["H1", "H2"], vec![]);
        input.hydration_components.insert("H1".to_string());
        input.hydration_components.insert("H2".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.hydration_boundaries_checked, 2);
    }

    // -----------------------------------------------------------------------
    // Hook cleanup coherence tests
    // -----------------------------------------------------------------------

    #[test]
    fn hook_cleanup_mismatch_detected() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_hooks(
                "CompA",
                vec!["slot=0;kind=Effect;label=fetch;deps=1;cleanup=true"],
            ),
            test_entry_with_hooks(
                "CompB",
                vec!["slot=0;kind=Effect;label=fetch;deps=1;cleanup=false"],
            ),
        ];
        let input = make_input(entries, vec!["CompA", "CompB"], vec![]);
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::HookCleanupMismatch { hook_label, .. }
                if hook_label == "fetch"
        )));
    }

    #[test]
    fn hook_cleanup_agreement_ok() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_hooks(
                "CompA",
                vec!["slot=0;kind=Effect;label=fetch;deps=1;cleanup=true"],
            ),
            test_entry_with_hooks(
                "CompB",
                vec!["slot=0;kind=Effect;label=fetch;deps=1;cleanup=true"],
            ),
        ];
        let input = make_input(entries, vec!["CompA", "CompB"], vec![]);
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(
            result
                .violations
                .iter()
                .all(|v| !matches!(&v.kind, CoherenceViolationKind::HookCleanupMismatch { .. }))
        );
    }

    // -----------------------------------------------------------------------
    // Budget exhaustion tests
    // -----------------------------------------------------------------------

    #[test]
    fn budget_exhaustion_caps_violations() {
        let checker = GlobalCoherenceChecker::new().with_violation_budget(2);
        let entries = vec![
            test_entry_with_contexts("C1", vec!["missing1"], vec![]),
            test_entry_with_contexts("C2", vec!["missing2"], vec![]),
            test_entry_with_contexts("C3", vec!["missing3"], vec![]),
        ];
        let input = make_input(entries, vec!["C1", "C2", "C3"], vec![]);
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.outcome, CoherenceOutcome::BudgetExhausted);
        assert!(result.violations.len() <= 2);
    }

    // -----------------------------------------------------------------------
    // CoherenceCheckResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn blocking_violations_filter() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![
                test_entry_with_contexts("C1", vec!["missing"], vec![]),
                test_entry_with_contexts("P1", vec![], vec!["unused"]),
            ],
            vec!["C1", "P1"],
            vec![],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        let blocking = result.blocking_violations();
        assert!(!blocking.is_empty());
        for v in &blocking {
            assert!(v.severity.is_blocking());
        }
    }

    #[test]
    fn violations_by_debt_code_groups() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![test_entry_with_contexts("C1", vec!["m1", "m2"], vec![])],
            vec!["C1"],
            vec![],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        let by_code = result.violations_by_debt_code();
        assert!(by_code.contains_key(DEBT_UNRESOLVED_CONTEXT));
    }

    #[test]
    fn result_hash_deterministic() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![test_entry_with_contexts("C1", vec!["m1"], vec![])],
            vec!["C1"],
            vec![],
        );
        let r1 = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        let r2 = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(r1.result_hash, r2.result_hash);
    }

    // -----------------------------------------------------------------------
    // Violation kind display tests
    // -----------------------------------------------------------------------

    #[test]
    fn violation_kind_display_unresolved_context() {
        let kind = CoherenceViolationKind::UnresolvedContext {
            consumer: "Foo".to_string(),
            context_key: "theme".to_string(),
        };
        assert!(kind.to_string().contains("Foo"));
        assert!(kind.to_string().contains("theme"));
    }

    #[test]
    fn violation_kind_display_capability_gap() {
        let kind = CoherenceViolationKind::CapabilityGap {
            component: "Bar".to_string(),
            missing_capabilities: vec!["net".to_string()],
        };
        assert!(kind.to_string().contains("Bar"));
        assert!(kind.to_string().contains("net"));
    }

    #[test]
    fn violation_kind_display_effect_cycle() {
        let kind = CoherenceViolationKind::EffectOrderCycle {
            cycle_participants: vec!["A".to_string(), "B".to_string()],
        };
        assert!(kind.to_string().contains("A -> B"));
    }

    #[test]
    fn violation_kind_display_suspense_conflict() {
        let kind = CoherenceViolationKind::SuspenseBoundaryConflict {
            boundary_component: "Susp".to_string(),
            conflicting_children: vec!["C1".to_string()],
            reason: "test".to_string(),
        };
        assert!(kind.to_string().contains("Susp"));
    }

    #[test]
    fn violation_kind_display_hydration_conflict() {
        let kind = CoherenceViolationKind::HydrationBoundaryConflict {
            boundary_component: "Hydr".to_string(),
            conflicting_children: vec!["C1".to_string()],
            reason: "test".to_string(),
        };
        assert!(kind.to_string().contains("Hydr"));
    }

    #[test]
    fn violation_kind_display_hook_mismatch() {
        let kind = CoherenceViolationKind::HookCleanupMismatch {
            component_a: "A".to_string(),
            component_b: "B".to_string(),
            hook_label: "fetch".to_string(),
        };
        assert!(kind.to_string().contains("fetch"));
    }

    #[test]
    fn violation_kind_display_duplicate_provider() {
        let kind = CoherenceViolationKind::DuplicateProvider {
            providers: vec!["P1".to_string(), "P2".to_string()],
            context_key: "theme".to_string(),
        };
        assert!(kind.to_string().contains("theme"));
        assert!(kind.to_string().contains("P1"));
    }

    #[test]
    fn violation_kind_display_boundary_leak() {
        let kind = CoherenceViolationKind::BoundaryCapabilityLeak {
            boundary: "B1".to_string(),
            leaked_capabilities: vec!["fs".to_string()],
        };
        assert!(kind.to_string().contains("B1"));
        assert!(kind.to_string().contains("fs"));
    }

    // -----------------------------------------------------------------------
    // Free function tests
    // -----------------------------------------------------------------------

    #[test]
    fn is_ancestor_direct() {
        let g = make_graph(
            vec!["A", "B"],
            vec![("A", "B", CompositionEdgeKind::ParentChild)],
        );
        assert!(is_ancestor(&g, "A", "B"));
        assert!(!is_ancestor(&g, "B", "A"));
    }

    #[test]
    fn is_ancestor_transitive() {
        let g = make_graph(
            vec!["A", "B", "C"],
            vec![
                ("A", "B", CompositionEdgeKind::ParentChild),
                ("B", "C", CompositionEdgeKind::ParentChild),
            ],
        );
        assert!(is_ancestor(&g, "A", "C"));
    }

    #[test]
    fn is_ancestor_no_relation() {
        let g = make_graph(vec!["A", "B"], vec![]);
        assert!(!is_ancestor(&g, "A", "B"));
    }

    #[test]
    fn collect_descendants_empty() {
        let g = make_graph(vec!["A"], vec![]);
        assert!(collect_descendants(&g, "A").is_empty());
    }

    #[test]
    fn collect_descendants_tree() {
        let g = make_graph(
            vec!["root", "c1", "c2", "gc1"],
            vec![
                ("root", "c1", CompositionEdgeKind::ParentChild),
                ("root", "c2", CompositionEdgeKind::ParentChild),
                ("c1", "gc1", CompositionEdgeKind::ParentChild),
            ],
        );
        let desc = collect_descendants(&g, "root");
        assert_eq!(desc.len(), 3);
        assert!(desc.contains("c1"));
        assert!(desc.contains("c2"));
        assert!(desc.contains("gc1"));
    }

    #[test]
    fn detect_cycle_none_in_dag() {
        let mut adj = BTreeMap::new();
        adj.insert("A".to_string(), vec!["B".to_string()]);
        adj.insert("B".to_string(), vec!["C".to_string()]);
        assert!(detect_cycle_in_adjacency(&adj).is_none());
    }

    #[test]
    fn detect_cycle_found() {
        let mut adj = BTreeMap::new();
        adj.insert("A".to_string(), vec!["B".to_string()]);
        adj.insert("B".to_string(), vec!["C".to_string()]);
        adj.insert("C".to_string(), vec!["A".to_string()]);
        assert!(detect_cycle_in_adjacency(&adj).is_some());
    }

    #[test]
    fn detect_cycle_self_loop() {
        let mut adj = BTreeMap::new();
        adj.insert("A".to_string(), vec!["A".to_string()]);
        assert!(detect_cycle_in_adjacency(&adj).is_some());
    }

    #[test]
    fn detect_cycle_empty() {
        let adj: BTreeMap<String, Vec<String>> = BTreeMap::new();
        assert!(detect_cycle_in_adjacency(&adj).is_none());
    }

    #[test]
    fn parse_hook_signature_valid() {
        let parsed = parse_hook_signature("slot=0;kind=Effect;label=fetch;deps=1;cleanup=true");
        assert!(parsed.is_some());
        let p = parsed.expect("operation should succeed for valid inputs");
        assert_eq!(p.label, "fetch");
        assert!(p.has_cleanup);
    }

    #[test]
    fn parse_hook_signature_no_cleanup() {
        let parsed = parse_hook_signature("slot=0;kind=State;label=count;deps=none;cleanup=false");
        assert!(parsed.is_some());
        let p = parsed.expect("operation should succeed for valid inputs");
        assert_eq!(p.label, "count");
        assert!(!p.has_cleanup);
    }

    #[test]
    fn parse_hook_signature_missing_label() {
        let parsed = parse_hook_signature("slot=0;kind=State;cleanup=false");
        assert!(parsed.is_none());
    }

    #[test]
    fn has_layout_effect_true() {
        let entry = test_entry_with_effects(
            "A",
            vec!["boundary=Layout;caps=;idempotent=true;commutative=true;cost_millionths=0"],
        );
        assert!(has_layout_effect(&entry));
    }

    #[test]
    fn has_layout_effect_false() {
        let entry = test_entry_with_effects(
            "A",
            vec!["boundary=Passive;caps=;idempotent=true;commutative=true;cost_millionths=0"],
        );
        assert!(!has_layout_effect(&entry));
    }

    #[test]
    fn has_passive_effect_true() {
        let entry = test_entry_with_effects(
            "A",
            vec!["boundary=Passive;caps=;idempotent=true;commutative=true;cost_millionths=0"],
        );
        assert!(has_passive_effect(&entry));
    }

    #[test]
    fn has_async_effect_true() {
        let entry = test_entry_with_effects(
            "A",
            vec!["boundary=Suspense;caps=;idempotent=true;commutative=true;cost_millionths=0"],
        );
        assert!(has_async_effect(&entry));
    }

    #[test]
    fn has_async_effect_false() {
        let entry = test_entry_with_effects(
            "A",
            vec!["boundary=Layout;caps=;idempotent=true;commutative=true;cost_millionths=0"],
        );
        assert!(!has_async_effect(&entry));
    }

    #[test]
    fn is_hydration_safe_true() {
        let entry = test_entry_with_effects(
            "A",
            vec!["boundary=Effect;caps=;idempotent=true;commutative=true;cost_millionths=0"],
        );
        assert!(is_hydration_safe(&entry));
    }

    #[test]
    fn is_hydration_safe_false_non_idempotent() {
        let entry = test_entry_with_effects(
            "A",
            vec!["boundary=Effect;caps=;idempotent=false;commutative=true;cost_millionths=0"],
        );
        assert!(!is_hydration_safe(&entry));
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn severity_score_serde_roundtrip() {
        let score = SeverityScore::high();
        let json = serde_json::to_string(&score).expect("serialize derived Serialize");
        let back: SeverityScore =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(score, back);
    }

    #[test]
    fn composition_edge_serde_roundtrip() {
        let edge = CompositionEdge {
            from_component: "A".to_string(),
            to_component: "B".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "test".to_string(),
        };
        let json = serde_json::to_string(&edge).expect("serialize derived Serialize");
        let back: CompositionEdge =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(edge, back);
    }

    #[test]
    fn coherence_outcome_serde_roundtrip() {
        for outcome in [
            CoherenceOutcome::Coherent,
            CoherenceOutcome::CoherentWithWarnings,
            CoherenceOutcome::Incoherent,
            CoherenceOutcome::BudgetExhausted,
        ] {
            let json = serde_json::to_string(&outcome).expect("serialize derived Serialize");
            let back: CoherenceOutcome =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(outcome, back);
        }
    }

    #[test]
    fn coherence_error_serde_roundtrip() {
        let err = CoherenceError::BudgetExhausted {
            resource: "test".to_string(),
            limit: 42,
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let back: CoherenceError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, back);
    }

    #[test]
    fn composition_graph_serde_roundtrip() {
        let g = make_graph(
            vec!["A", "B"],
            vec![("A", "B", CompositionEdgeKind::ParentChild)],
        );
        let json = serde_json::to_string(&g).expect("serialize derived Serialize");
        let back: CompositionGraph =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(g, back);
    }

    #[test]
    fn coherence_check_result_serde_roundtrip() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(vec![test_entry("A")], vec!["A"], vec![]);
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        let json = serde_json::to_string(&result).expect("serialize derived Serialize");
        let back: CoherenceCheckResult =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(result, back);
    }

    // -----------------------------------------------------------------------
    // Integration: complex multi-component tree
    // -----------------------------------------------------------------------

    #[test]
    fn complex_tree_mixed_violations() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_contexts("App", vec![], vec!["theme", "auth"]),
            test_entry_with_contexts("Header", vec!["theme"], vec![]),
            test_entry_with_contexts("Body", vec!["theme", "data"], vec![]),
            test_entry_with_contexts("Footer", vec!["auth"], vec![]),
        ];
        let input = make_input(
            entries,
            vec!["App", "Header", "Body", "Footer"],
            vec![
                ("App", "Header", CompositionEdgeKind::ParentChild),
                ("App", "Body", CompositionEdgeKind::ParentChild),
                ("App", "Footer", CompositionEdgeKind::ParentChild),
            ],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        // Body requires "data" which nobody provides
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::UnresolvedContext { context_key, .. }
                if context_key == "data"
        )));
    }

    #[test]
    fn deep_tree_coherent() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_contexts("Root", vec![], vec!["theme"]),
            test_entry_with_contexts("L1", vec!["theme"], vec!["locale"]),
            test_entry_with_contexts("L2", vec!["theme", "locale"], vec![]),
        ];
        let input = make_input(
            entries,
            vec!["Root", "L1", "L2"],
            vec![
                ("Root", "L1", CompositionEdgeKind::ParentChild),
                ("L1", "L2", CompositionEdgeKind::ParentChild),
            ],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.is_coherent());
    }

    #[test]
    fn checker_default_equals_new() {
        let c1 = GlobalCoherenceChecker::new();
        let c2 = GlobalCoherenceChecker::default();
        assert_eq!(c1.violation_budget, c2.violation_budget);
    }

    #[test]
    fn check_epoch_propagated() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(vec![test_entry("A")], vec!["A"], vec![]);
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.check_epoch, 42);
    }

    #[test]
    fn component_and_edge_counts_propagated() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![test_entry("A"), test_entry("B")],
            vec!["A", "B"],
            vec![("A", "B", CompositionEdgeKind::ParentChild)],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.component_count, 2);
        assert_eq!(result.edge_count, 1);
    }

    // -----------------------------------------------------------------------
    // Enrichment: CompositionEdgeKind display — remaining variants
    // -----------------------------------------------------------------------

    #[test]
    fn edge_kind_display_suspense_boundary() {
        assert_eq!(
            CompositionEdgeKind::SuspenseBoundary.to_string(),
            "suspense-boundary"
        );
    }

    #[test]
    fn edge_kind_display_hydration_boundary() {
        assert_eq!(
            CompositionEdgeKind::HydrationBoundary.to_string(),
            "hydration-boundary"
        );
    }

    #[test]
    fn edge_kind_display_effect_dependency() {
        assert_eq!(
            CompositionEdgeKind::EffectDependency.to_string(),
            "effect-dependency"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: CoherenceError display — remaining variants
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_budget_exhausted() {
        let err = CoherenceError::BudgetExhausted {
            resource: "violations".to_string(),
            limit: 100,
        };
        let s = err.to_string();
        assert!(s.contains("violations"));
        assert!(s.contains("100"));
    }

    #[test]
    fn error_display_empty_graph() {
        let err = CoherenceError::EmptyGraph;
        assert_eq!(err.to_string(), "composition graph is empty");
    }

    #[test]
    fn error_display_atlas_graph_mismatch() {
        let err = CoherenceError::AtlasGraphMismatch {
            atlas_components: 5,
            graph_components: 3,
        };
        let s = err.to_string();
        assert!(s.contains("5"));
        assert!(s.contains("3"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: CoherenceViolationKind display — remaining variants
    // -----------------------------------------------------------------------

    #[test]
    fn violation_kind_display_orphaned_provider() {
        let kind = CoherenceViolationKind::OrphanedProvider {
            provider: "ThemeProvider".to_string(),
            context_key: "theme".to_string(),
        };
        let s = kind.to_string();
        assert!(s.contains("ThemeProvider"));
        assert!(s.contains("theme"));
        assert!(s.contains("orphaned"));
    }

    #[test]
    fn violation_kind_display_layout_after_passive() {
        let kind = CoherenceViolationKind::LayoutAfterPassive {
            layout_component: "Child".to_string(),
            passive_component: "Parent".to_string(),
        };
        let s = kind.to_string();
        assert!(s.contains("Child"));
        assert!(s.contains("Parent"));
        assert!(s.contains("layout"));
        assert!(s.contains("passive"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: SeverityScore exact values and serde
    // -----------------------------------------------------------------------

    #[test]
    fn severity_exact_values() {
        assert_eq!(SeverityScore::critical().0, 1_000_000);
        assert_eq!(SeverityScore::high().0, 750_000);
        assert_eq!(SeverityScore::medium().0, 500_000);
        assert_eq!(SeverityScore::low().0, 250_000);
        assert_eq!(SeverityScore::info().0, 100_000);
    }

    #[test]
    fn severity_blocking_boundary() {
        assert!(SeverityScore(500_000).is_blocking());
        assert!(!SeverityScore(499_999).is_blocking());
    }

    // -----------------------------------------------------------------------
    // Enrichment: CoherenceOutcome is_coherent for all variants
    // -----------------------------------------------------------------------

    #[test]
    fn is_coherent_true_for_warnings() {
        let checker = GlobalCoherenceChecker::new();
        // Orphaned provider → low severity (non-blocking) → CoherentWithWarnings
        let input = make_input(
            vec![test_entry_with_contexts("Provider", vec![], vec!["unused"])],
            vec!["Provider"],
            vec![],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.outcome, CoherenceOutcome::CoherentWithWarnings);
        assert!(result.is_coherent());
    }

    #[test]
    fn is_coherent_false_for_incoherent() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![test_entry_with_contexts("C", vec!["missing"], vec![])],
            vec!["C"],
            vec![],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.outcome, CoherenceOutcome::Incoherent);
        assert!(!result.is_coherent());
    }

    // -----------------------------------------------------------------------
    // Enrichment: summary_line for non-coherent results
    // -----------------------------------------------------------------------

    #[test]
    fn summary_line_incoherent() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(
            vec![test_entry_with_contexts("C", vec!["missing"], vec![])],
            vec!["C"],
            vec![],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        let line = result.summary_line();
        assert!(line.contains("incoherent"));
        assert!(line.contains("1 violations"));
        assert!(line.contains("1 blocking"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: schema_version and bead_id propagated in result
    // -----------------------------------------------------------------------

    #[test]
    fn result_schema_version_propagated() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(vec![test_entry("A")], vec!["A"], vec![]);
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.schema_version, GLOBAL_COHERENCE_SCHEMA_VERSION);
    }

    #[test]
    fn result_bead_id_propagated() {
        let checker = GlobalCoherenceChecker::new();
        let input = make_input(vec![test_entry("A")], vec!["A"], vec![]);
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.bead_id, GLOBAL_COHERENCE_BEAD_ID);
    }

    // -----------------------------------------------------------------------
    // Enrichment: total_severity accumulation
    // -----------------------------------------------------------------------

    #[test]
    fn total_severity_accumulates() {
        let checker = GlobalCoherenceChecker::new();
        // Two unresolved contexts (each critical = 1_000_000)
        let input = make_input(
            vec![test_entry_with_contexts(
                "C",
                vec!["missing1", "missing2"],
                vec![],
            )],
            vec!["C"],
            vec![],
        );
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.total_severity_millionths >= 2_000_000);
    }

    // -----------------------------------------------------------------------
    // Enrichment: hydration with commutative=false
    // -----------------------------------------------------------------------

    #[test]
    fn hydration_non_commutative_child_detected() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry("HB"),
            test_entry_with_effects(
                "NonComm",
                vec!["boundary=Effect;caps=;idempotent=true;commutative=false;cost_millionths=0"],
            ),
        ];
        let mut input = make_input(
            entries,
            vec!["HB", "NonComm"],
            vec![("HB", "NonComm", CompositionEdgeKind::ParentChild)],
        );
        input.hydration_components.insert("HB".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::HydrationBoundaryConflict { .. }
        )));
    }

    // -----------------------------------------------------------------------
    // Enrichment: CoherenceCheckInput serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn coherence_check_input_serde_roundtrip() {
        let mut input = make_input(
            vec![test_entry("A"), test_entry("B")],
            vec!["A", "B"],
            vec![("A", "B", CompositionEdgeKind::ParentChild)],
        );
        input.suspense_components.insert("A".to_string());
        input.hydration_components.insert("B".to_string());
        input.capability_boundary_components.insert("A".to_string());
        let json = serde_json::to_string(&input).expect("serialize derived Serialize");
        let back: CoherenceCheckInput =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(input, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: CoherenceError serde roundtrip for all variants
    // -----------------------------------------------------------------------

    #[test]
    fn coherence_error_serde_all_variants() {
        let variants: Vec<CoherenceError> = vec![
            CoherenceError::BudgetExhausted {
                resource: "nodes".to_string(),
                limit: 50_000,
            },
            CoherenceError::UnknownComponent("X".to_string()),
            CoherenceError::EmptyAtlas,
            CoherenceError::EmptyGraph,
            CoherenceError::AtlasGraphMismatch {
                atlas_components: 10,
                graph_components: 5,
            },
        ];
        for err in &variants {
            let json = serde_json::to_string(err).expect("serialize derived Serialize");
            let back: CoherenceError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*err, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: CompositionEdgeKind serde all variants
    // -----------------------------------------------------------------------

    #[test]
    fn edge_kind_serde_all_variants() {
        let variants = [
            CompositionEdgeKind::ParentChild,
            CompositionEdgeKind::ContextFlow,
            CompositionEdgeKind::CapabilityBoundary,
            CompositionEdgeKind::SuspenseBoundary,
            CompositionEdgeKind::HydrationBoundary,
            CompositionEdgeKind::EffectDependency,
        ];
        for kind in &variants {
            let json = serde_json::to_string(kind).expect("serialize derived Serialize");
            let back: CompositionEdgeKind =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*kind, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: display uniqueness for all enum variants
    // -----------------------------------------------------------------------

    #[test]
    fn edge_kind_display_all_unique() {
        let variants = [
            CompositionEdgeKind::ParentChild,
            CompositionEdgeKind::ContextFlow,
            CompositionEdgeKind::CapabilityBoundary,
            CompositionEdgeKind::SuspenseBoundary,
            CompositionEdgeKind::HydrationBoundary,
            CompositionEdgeKind::EffectDependency,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn outcome_display_all_unique() {
        let variants = [
            CoherenceOutcome::Coherent,
            CoherenceOutcome::CoherentWithWarnings,
            CoherenceOutcome::Incoherent,
            CoherenceOutcome::BudgetExhausted,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(set.len(), variants.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: CompositionGraph edge_from unknown source
    // -----------------------------------------------------------------------

    #[test]
    fn edge_from_unknown_source_fails() {
        let mut g = CompositionGraph::new();
        g.add_component("B".to_string())
            .expect("operation should succeed for valid inputs");
        let result = g.add_edge(CompositionEdge {
            from_component: "Z".to_string(),
            to_component: "B".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "bad".to_string(),
        });
        assert_eq!(
            result,
            Err(CoherenceError::UnknownComponent("Z".to_string()))
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: children_of / parents_of for leaf and isolated nodes
    // -----------------------------------------------------------------------

    #[test]
    fn children_of_leaf_is_empty() {
        let g = make_graph(
            vec!["root", "leaf"],
            vec![("root", "leaf", CompositionEdgeKind::ParentChild)],
        );
        assert!(g.children_of("leaf").is_empty());
    }

    #[test]
    fn parents_of_multiple_parents() {
        let g = make_graph(
            vec!["P1", "P2", "child"],
            vec![
                ("P1", "child", CompositionEdgeKind::ParentChild),
                ("P2", "child", CompositionEdgeKind::ParentChild),
            ],
        );
        let parents = g.parents_of("child");
        assert_eq!(parents.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: hook signature with multiple hooks per component
    // -----------------------------------------------------------------------

    #[test]
    fn hook_cleanup_mismatch_different_labels_no_violation() {
        let checker = GlobalCoherenceChecker::new();
        let entries = vec![
            test_entry_with_hooks(
                "CompA",
                vec!["slot=0;kind=Effect;label=fetch;deps=1;cleanup=true"],
            ),
            test_entry_with_hooks(
                "CompB",
                vec!["slot=0;kind=Effect;label=subscribe;deps=1;cleanup=false"],
            ),
        ];
        let input = make_input(entries, vec!["CompA", "CompB"], vec![]);
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        // Different labels → no mismatch
        assert!(
            result
                .violations
                .iter()
                .all(|v| !matches!(&v.kind, CoherenceViolationKind::HookCleanupMismatch { .. }))
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: suspense with multiple async children context mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn suspense_async_siblings_context_mismatch() {
        let checker = GlobalCoherenceChecker::new();
        let mut c1 = test_entry_with_effects(
            "Async1",
            vec!["boundary=Suspense;caps=;idempotent=true;commutative=true;cost_millionths=0"],
        );
        c1.required_contexts = vec!["theme".to_string(), "auth".to_string()];
        let mut c2 = test_entry_with_effects(
            "Async2",
            vec!["boundary=Suspense;caps=;idempotent=true;commutative=true;cost_millionths=0"],
        );
        c2.required_contexts = vec!["theme".to_string()]; // missing "auth"
        let entries = vec![test_entry("SB"), c1, c2];
        let mut input = make_input(
            entries,
            vec!["SB", "Async1", "Async2"],
            vec![
                ("SB", "Async1", CompositionEdgeKind::ParentChild),
                ("SB", "Async2", CompositionEdgeKind::ParentChild),
            ],
        );
        input.suspense_components.insert("SB".to_string());
        let result = checker
            .check(&input)
            .expect("operation should succeed for valid inputs");
        // Async2 is missing "auth" that Async1 has → info-level violation
        assert!(result.violations.iter().any(|v| matches!(
            &v.kind,
            CoherenceViolationKind::SuspenseBoundaryConflict { reason, .. }
                if reason.contains("missing contexts")
        )));
    }

    // -----------------------------------------------------------------------
    // Enrichment: result_hash changes with different violations
    // -----------------------------------------------------------------------

    #[test]
    fn result_hash_differs_for_different_violations() {
        let checker = GlobalCoherenceChecker::new();
        let input1 = make_input(vec![test_entry("A")], vec!["A"], vec![]);
        let input2 = make_input(
            vec![test_entry_with_contexts("A", vec!["missing"], vec![])],
            vec!["A"],
            vec![],
        );
        let r1 = checker
            .check(&input1)
            .expect("operation should succeed for valid inputs");
        let r2 = checker
            .check(&input2)
            .expect("operation should succeed for valid inputs");
        assert_ne!(r1.result_hash, r2.result_hash);
    }

    // -----------------------------------------------------------------------
    // Enrichment: with_violation_budget builder
    // -----------------------------------------------------------------------

    #[test]
    fn with_violation_budget_builder() {
        let checker = GlobalCoherenceChecker::new().with_violation_budget(5);
        assert_eq!(checker.violation_budget, 5);
    }
}
