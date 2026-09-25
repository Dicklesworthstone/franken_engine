//! ES module loader with deterministic cache, cycle handling, and resolution
//! tracing.
//!
//! Implements the ES2020 module loading pipeline:
//! 1. **Resolve** — map specifier to canonical module id
//! 2. **Fetch** — retrieve source text (from registry or filesystem)
//! 3. **Parse** — produce AST (via the parser module)
//! 4. **Link** — bind import/export bindings across the module graph
//! 5. **Evaluate** — execute module body in topological order
//!
//! Key design decisions:
//! - Cycle-safe: uses DFS with `Linking` sentinel to detect cycles and return
//!   live-binding stubs per ES2020 §15.2.1.16.4.
//! - Deterministic: module graph ordering is stable via `BTreeMap` keying.
//! - Traced: every resolution, link, and evaluate step emits tracing events
//!   for the evidence ledger.
//! - Cache-aware: integrates with `module_cache` for fingerprint-based
//!   invalidation.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.4, bd-1lsy.5.1.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::module_resolver::ModuleSyntax;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum module graph depth before aborting (prevents stack overflow on
/// pathological circular imports).
const MAX_MODULE_DEPTH: usize = 512;

/// Maximum number of modules in a single graph (prevents runaway resolution).
const MAX_MODULE_GRAPH_SIZE: usize = 10_000;

// ---------------------------------------------------------------------------
// Module status (ES2020 §15.2.1.16 Module Record status field)
// ---------------------------------------------------------------------------

/// Status of a module in the loading pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ModuleStatus {
    /// Module has been resolved but not yet fetched/parsed.
    Unlinked,
    /// Module is currently being linked (cycle detection sentinel).
    Linking,
    /// Module has been linked — all import bindings are wired.
    Linked,
    /// Module is currently being evaluated (cycle detection sentinel).
    Evaluating,
    /// Module has been evaluated — its body has executed.
    Evaluated,
    /// Module evaluation threw an error.
    EvaluationError,
}

impl fmt::Display for ModuleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlinked => write!(f, "unlinked"),
            Self::Linking => write!(f, "linking"),
            Self::Linked => write!(f, "linked"),
            Self::Evaluating => write!(f, "evaluating"),
            Self::Evaluated => write!(f, "evaluated"),
            Self::EvaluationError => write!(f, "evaluation_error"),
        }
    }
}

// ---------------------------------------------------------------------------
// Export / Import binding descriptors
// ---------------------------------------------------------------------------

/// A single export from a module.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExportEntry {
    /// The local name in the exporting module (None for re-exports).
    pub local_name: Option<String>,
    /// The export name visible to importers.
    pub export_name: String,
    /// For re-exports: the source module specifier.
    pub module_request: Option<String>,
    /// For re-exports: the import name from the source module.
    pub import_name: Option<String>,
}

impl ExportEntry {
    /// Direct export: `export { foo }` or `export const foo = ...`.
    pub fn direct(local_name: impl Into<String>, export_name: impl Into<String>) -> Self {
        Self {
            local_name: Some(local_name.into()),
            export_name: export_name.into(),
            module_request: None,
            import_name: None,
        }
    }

    /// Re-export: `export { foo } from "mod"`.
    pub fn re_export(
        export_name: impl Into<String>,
        module_request: impl Into<String>,
        import_name: impl Into<String>,
    ) -> Self {
        Self {
            local_name: None,
            export_name: export_name.into(),
            module_request: Some(module_request.into()),
            import_name: Some(import_name.into()),
        }
    }

    /// Star re-export: `export * from "mod"`.
    pub fn star_re_export(module_request: impl Into<String>) -> Self {
        Self {
            local_name: None,
            export_name: "*".into(),
            module_request: Some(module_request.into()),
            import_name: None,
        }
    }
}

/// A single import binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ImportEntry {
    /// The module specifier being imported from.
    pub module_request: String,
    /// The name exported by the source module.
    pub import_name: String,
    /// The local binding name in the importing module.
    pub local_name: String,
}

impl ImportEntry {
    pub fn new(
        module_request: impl Into<String>,
        import_name: impl Into<String>,
        local_name: impl Into<String>,
    ) -> Self {
        Self {
            module_request: module_request.into(),
            import_name: import_name.into(),
            local_name: local_name.into(),
        }
    }

    /// Namespace import: `import * as ns from "mod"`.
    pub fn namespace(module_request: impl Into<String>, local_name: impl Into<String>) -> Self {
        Self {
            module_request: module_request.into(),
            import_name: "*".into(),
            local_name: local_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// EsmModule — a single module in the graph
// ---------------------------------------------------------------------------

/// A module record in the ESM loader graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsmModule {
    /// Canonical module specifier (unique within a graph).
    pub specifier: String,
    /// Module syntax (ESM or CJS).
    pub syntax: ModuleSyntax,
    /// Module source text.
    pub source: String,
    /// Content hash of the source.
    pub content_hash: ContentHash,
    /// Import bindings declared by this module.
    pub imports: Vec<ImportEntry>,
    /// Export bindings declared by this module.
    pub exports: Vec<ExportEntry>,
    /// Dependencies (specifiers this module imports from).
    pub dependencies: BTreeSet<String>,
    /// Current status in the loading pipeline.
    pub status: ModuleStatus,
    /// DFS index for cycle detection (assigned during link phase).
    pub dfs_index: Option<u32>,
    /// DFS ancestor index for cycle detection.
    pub dfs_ancestor_index: Option<u32>,
    /// Has a default export?
    pub has_default_export: bool,
    /// Evaluation order index (topological sort rank).
    pub eval_order: Option<u32>,
}

impl EsmModule {
    /// Create a new unlinked ESM module.
    pub fn new(
        specifier: impl Into<String>,
        source: impl Into<String>,
        syntax: ModuleSyntax,
    ) -> Self {
        let source = source.into();
        let content_hash = ContentHash::compute(source.as_bytes());
        Self {
            specifier: specifier.into(),
            syntax,
            source,
            content_hash,
            imports: Vec::new(),
            exports: Vec::new(),
            dependencies: BTreeSet::new(),
            status: ModuleStatus::Unlinked,
            dfs_index: None,
            dfs_ancestor_index: None,
            has_default_export: false,
            eval_order: None,
        }
    }

    /// Create a WebAssembly module record for the ESM loader graph.
    pub fn wasm(specifier: impl Into<String>, source: impl Into<String>) -> Self {
        Self::new(specifier, source, ModuleSyntax::Wasm)
    }

    /// Add an import entry.
    pub fn add_import(&mut self, entry: ImportEntry) {
        self.dependencies.insert(entry.module_request.clone());
        // Export declarations may precede their imports in source order.
        for export in &mut self.exports {
            Self::normalize_imported_export(export, &entry);
        }
        self.imports.push(entry);
    }

    /// Add an export entry.
    pub fn add_export(&mut self, mut entry: ExportEntry) {
        if let Some(import) = self
            .imports
            .iter()
            .find(|import| entry.local_name.as_deref() == Some(import.local_name.as_str()))
        {
            Self::normalize_imported_export(&mut entry, import);
        }
        if entry.export_name == "default" {
            self.has_default_export = true;
        }
        if let Some(req) = &entry.module_request {
            self.dependencies.insert(req.clone());
        }
        self.exports.push(entry);
    }

    /// ParseModule classifies an exported named import as an indirect export:
    /// it aliases the source binding rather than allocating a new local cell.
    /// Namespace imports remain local bindings to their namespace objects.
    fn normalize_imported_export(export: &mut ExportEntry, import: &ImportEntry) {
        if export.module_request.is_none()
            && export.local_name.as_deref() == Some(import.local_name.as_str())
            && import.import_name != "*"
        {
            export.module_request = Some(import.module_request.clone());
            export.import_name = Some(import.import_name.clone());
            export.local_name = None;
        }
    }
}

// ---------------------------------------------------------------------------
// ModuleGraph — the full dependency graph
// ---------------------------------------------------------------------------

/// The module dependency graph, keyed by canonical specifier.
///
/// Uses `BTreeMap` for deterministic iteration order, which is critical for
/// reproducible evaluation ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleGraph {
    /// All modules in the graph, keyed by canonical specifier.
    modules: BTreeMap<String, EsmModule>,
    /// The entry point specifier.
    entry_point: Option<String>,
    /// Resolution trace events.
    trace_events: Vec<TraceEvent>,
}

/// State owned by one evaluation-scheduling attempt. No module body executes
/// here, so a failed attempt must roll back its entire unpublished schedule.
#[derive(Default)]
struct EvaluationTraversal {
    order: Vec<String>,
    active: BTreeSet<String>,
    previous_orders: Vec<(String, Option<u32>)>,
}

/// A trace event for the evidence ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub phase: TracePhase,
    pub specifier: String,
    pub detail: String,
    pub seq: u64,
}

/// Which loading phase generated this trace event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TracePhase {
    Resolve,
    Link,
    Evaluate,
    CycleDetected,
}

impl fmt::Display for TracePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve => write!(f, "resolve"),
            Self::Link => write!(f, "link"),
            Self::Evaluate => write!(f, "evaluate"),
            Self::CycleDetected => write!(f, "cycle_detected"),
        }
    }
}

impl ModuleGraph {
    /// Create an empty module graph.
    pub fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
            entry_point: None,
            trace_events: Vec::new(),
        }
    }

    /// Number of modules in the graph.
    pub fn len(&self) -> usize {
        self.modules.len()
    }

    /// Is the graph empty?
    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Get the entry point specifier.
    pub fn entry_point(&self) -> Option<&str> {
        self.entry_point.as_deref()
    }

    /// Get a module by specifier.
    pub fn get_module(&self, specifier: &str) -> Option<&EsmModule> {
        self.modules.get(specifier)
    }

    /// Get a mutable module by specifier.
    pub fn get_module_mut(&mut self, specifier: &str) -> Option<&mut EsmModule> {
        self.modules.get_mut(specifier)
    }

    /// All module specifiers in deterministic order.
    pub fn specifiers(&self) -> impl Iterator<Item = &str> {
        self.modules.keys().map(|s| s.as_str())
    }

    /// All modules in deterministic order.
    pub fn modules(&self) -> impl Iterator<Item = &EsmModule> {
        self.modules.values()
    }

    /// All trace events.
    pub fn trace_events(&self) -> &[TraceEvent] {
        &self.trace_events
    }

    /// Add a module to the graph. Returns error if graph is full.
    pub fn add_module(&mut self, mut module: EsmModule) -> Result<(), EsmLoaderError> {
        if self.modules.len() >= MAX_MODULE_GRAPH_SIZE {
            return Err(EsmLoaderError::GraphTooLarge {
                limit: MAX_MODULE_GRAPH_SIZE,
            });
        }
        // Normalize records assembled through public fields or serde too.
        // Use the incremental path once, not a full import/export cross-product
        // after every addition to a growing module.
        let exports = std::mem::take(&mut module.exports);
        module.exports.reserve(exports.len());
        for export in exports {
            module.add_export(export);
        }
        let specifier = module.specifier.clone();
        if self.entry_point.is_none() {
            self.entry_point = Some(specifier.clone());
        }
        self.modules.insert(specifier, module);
        Ok(())
    }

    /// Record a trace event.
    fn trace(&mut self, phase: TracePhase, specifier: &str, detail: impl Into<String>) {
        let seq = self.trace_events.len() as u64;
        self.trace_events.push(TraceEvent {
            phase,
            specifier: specifier.to_string(),
            detail: detail.into(),
            seq,
        });
    }

    // -----------------------------------------------------------------------
    // Link phase — DFS-based module linking with cycle detection
    // -----------------------------------------------------------------------

    /// Link all modules in the graph starting from the entry point.
    ///
    /// This implements the ES2020 Link phase (§15.2.1.16.4):
    /// - DFS traversal of the dependency graph
    /// - Cycle detection via `Linking` sentinel status
    /// - Export binding resolution across the graph
    pub fn link(&mut self) -> Result<LinkResult, EsmLoaderError> {
        let entry = self
            .entry_point
            .clone()
            .ok_or(EsmLoaderError::NoEntryPoint)?;

        let mut dfs_counter: u32 = 0;
        let mut stack: Vec<String> = Vec::new();
        let mut cycles: Vec<CycleInfo> = Vec::new();

        if let Err(error) = self.link_module(&entry, &mut dfs_counter, &mut stack, &mut cycles, 0) {
            // Only unfinished SCCs remain on this traversal's stack. Completed
            // dependency components stay linked and can be reused on a retry.
            // In particular, an abandoned Linking marker must not turn the
            // next attempt into a spurious successful cycle detection.
            let pending_count = stack.len();
            for specifier in stack {
                if let Some(module) = self.modules.get_mut(&specifier) {
                    module.status = ModuleStatus::Unlinked;
                    module.dfs_index = None;
                    module.dfs_ancestor_index = None;
                }
            }
            self.trace(
                TracePhase::Link,
                &entry,
                format!("link failed; reset {pending_count} unfinished modules: {error}"),
            );
            return Err(error);
        }

        Ok(LinkResult {
            linked_count: self
                .modules
                .values()
                .filter(|m| m.status == ModuleStatus::Linked)
                .count(),
            cycle_count: cycles.len(),
            cycles,
        })
    }

    fn link_module(
        &mut self,
        specifier: &str,
        dfs_counter: &mut u32,
        stack: &mut Vec<String>,
        cycles: &mut Vec<CycleInfo>,
        depth: usize,
    ) -> Result<u32, EsmLoaderError> {
        // Check status before the depth bound: an already visited back-edge
        // does not allocate another linking activation.
        // Check current status.
        let status = self
            .modules
            .get(specifier)
            .ok_or_else(|| EsmLoaderError::ModuleNotFound(specifier.to_string()))?
            .status;

        match status {
            ModuleStatus::Linked
            | ModuleStatus::Evaluating
            | ModuleStatus::Evaluated
            | ModuleStatus::EvaluationError => {
                // A completed SCC (including one whose later evaluation
                // failed) is not on our DFS stack. Its old traversal index
                // must never lower this traversal's SCC root.
                return Ok(u32::MAX);
            }
            ModuleStatus::Linking => {
                if !stack.iter().any(|pending| pending == specifier)
                    || self.modules[specifier].dfs_index.is_none()
                {
                    return Err(EsmLoaderError::InvalidStatus {
                        specifier: specifier.to_string(),
                        expected: "linking module owned by the current traversal",
                        actual: "orphan linking state".into(),
                    });
                }
                // Cycle detected in this traversal, not a stale marker.
                self.trace(
                    TracePhase::CycleDetected,
                    specifier,
                    format!("cycle detected at depth {depth}"),
                );
                cycles.push(CycleInfo {
                    specifier: specifier.to_string(),
                    stack_snapshot: stack.clone(),
                });
                // Return this module's DFS index as the ancestor index.
                return Ok(self.modules[specifier].dfs_index.unwrap_or(0));
            }
            ModuleStatus::Unlinked => {}
        }

        if depth >= MAX_MODULE_DEPTH {
            return Err(EsmLoaderError::DepthExceeded {
                specifier: specifier.to_string(),
                depth,
                limit: MAX_MODULE_DEPTH,
            });
        }

        // Set status to Linking and assign DFS index.
        let index = *dfs_counter;
        *dfs_counter += 1;

        {
            let Some(module) = self.modules.get_mut(specifier) else {
                return Err(EsmLoaderError::ModuleNotFound(specifier.to_string()));
            };
            module.status = ModuleStatus::Linking;
            module.dfs_index = Some(index);
            module.dfs_ancestor_index = Some(index);
        }

        stack.push(specifier.to_string());
        self.trace(
            TracePhase::Link,
            specifier,
            format!("linking (dfs_index={index})"),
        );

        // Collect dependencies (need to clone to avoid borrow issues).
        let deps: Vec<String> = self.modules[specifier]
            .dependencies
            .iter()
            .cloned()
            .collect();

        let mut ancestor = index;
        for dep in &deps {
            if !self.modules.contains_key(dep.as_str()) {
                // Dependency not in graph — this is a resolution error.
                return Err(EsmLoaderError::UnresolvedDependency {
                    specifier: specifier.to_string(),
                    dependency: dep.clone(),
                });
            }
            let dep_ancestor = self.link_module(dep, dfs_counter, stack, cycles, depth + 1)?;
            if self.modules[dep.as_str()].status == ModuleStatus::Linking {
                ancestor = ancestor.min(dep_ancestor);
            }
        }

        // Update ancestor index.
        if let Some(module) = self.modules.get_mut(specifier) {
            module.dfs_ancestor_index = Some(ancestor);
        }

        // If this is a root of an SCC (ancestor == index), mark all modules
        // in this SCC as Linked.
        if ancestor == index {
            while let Some(top) = stack.pop() {
                if let Some(m) = self.modules.get_mut(&top) {
                    m.status = ModuleStatus::Linked;
                    m.dfs_ancestor_index = Some(index);
                }
                if top == specifier {
                    break;
                }
            }
        }

        Ok(ancestor)
    }

    // -----------------------------------------------------------------------
    // Evaluate phase — topological execution
    // -----------------------------------------------------------------------

    /// Schedule linked modules in deterministic dependency-first order.
    ///
    /// This graph operation does not execute JavaScript bodies. A successful
    /// call publishes the schedule and updates module statuses; a failed call
    /// restores every status/order it changed so a retry cannot skip work.
    /// Previously evaluated modules and failure records are left untouched.
    pub fn evaluate(&mut self) -> Result<EvalResult, EsmLoaderError> {
        let entry = self
            .entry_point
            .clone()
            .ok_or(EsmLoaderError::NoEntryPoint)?;
        let mut traversal = EvaluationTraversal::default();

        if let Err(error) = self.evaluate_module(&entry, &mut traversal, 0) {
            let restored_count = traversal.previous_orders.len();
            for (specifier, previous_order) in traversal.previous_orders {
                if let Some(module) = self.modules.get_mut(&specifier) {
                    module.status = ModuleStatus::Linked;
                    module.eval_order = previous_order;
                }
            }
            self.trace(
                TracePhase::Evaluate,
                &entry,
                format!("evaluation scheduling failed; restored {restored_count} modules: {error}"),
            );
            return Err(error);
        }

        Ok(EvalResult {
            evaluated_count: traversal.order.len(),
            eval_order: traversal.order,
        })
    }

    fn evaluate_module(
        &mut self,
        specifier: &str,
        traversal: &mut EvaluationTraversal,
        depth: usize,
    ) -> Result<(), EsmLoaderError> {
        let status = self
            .modules
            .get(specifier)
            .ok_or_else(|| EsmLoaderError::ModuleNotFound(specifier.to_string()))?
            .status;

        match status {
            ModuleStatus::Evaluated => return Ok(()),
            ModuleStatus::Evaluating => {
                if !traversal.active.contains(specifier) {
                    return Err(EsmLoaderError::InvalidStatus {
                        specifier: specifier.to_string(),
                        expected: "evaluating module owned by the current traversal",
                        actual: "orphan evaluating state".into(),
                    });
                }
                // Only a back-edge owned by this attempt is a real cycle.
                return Ok(());
            }
            ModuleStatus::EvaluationError => {
                return Err(EsmLoaderError::EvaluationFailed {
                    specifier: specifier.to_string(),
                    reason: "previous evaluation failed".into(),
                });
            }
            ModuleStatus::Linked => {}
            _ => {
                return Err(EsmLoaderError::InvalidStatus {
                    specifier: specifier.to_string(),
                    expected: "linked",
                    actual: status.to_string(),
                });
            }
        }

        // A completed dependency or an owned cycle does not need another
        // activation, including a back-edge at the maximum permitted depth.
        if depth >= MAX_MODULE_DEPTH {
            return Err(EsmLoaderError::DepthExceeded {
                specifier: specifier.to_string(),
                depth,
                limit: MAX_MODULE_DEPTH,
            });
        }

        if let Some(module) = self.modules.get_mut(specifier) {
            traversal
                .previous_orders
                .push((specifier.to_string(), module.eval_order));
            module.status = ModuleStatus::Evaluating;
        }
        traversal.active.insert(specifier.to_string());

        self.trace(
            TracePhase::Evaluate,
            specifier,
            format!("evaluating at depth {depth}"),
        );

        let deps: Vec<String> = self.modules[specifier]
            .dependencies
            .iter()
            .cloned()
            .collect();
        for dep in &deps {
            self.evaluate_module(dep, traversal, depth + 1)?;
        }

        let order = traversal.order.len() as u32;
        if let Some(module) = self.modules.get_mut(specifier) {
            module.status = ModuleStatus::Evaluated;
            module.eval_order = Some(order);
        }
        traversal.order.push(specifier.to_string());
        traversal.active.remove(specifier);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Export resolution
    // -----------------------------------------------------------------------

    /// Resolve an export binding by walking the module graph.
    ///
    /// Handles:
    /// - Direct exports
    /// - Re-exports (`export { x } from "mod"`)
    /// - Star re-exports (`export * from "mod"`)
    /// - Default exports
    pub fn resolve_export(
        &self,
        specifier: &str,
        export_name: &str,
    ) -> Result<ResolvedBinding, EsmLoaderError> {
        let mut visited = BTreeSet::new();
        self.resolve_export_inner(specifier, export_name, &mut visited)
    }

    fn resolve_export_inner(
        &self,
        specifier: &str,
        export_name: &str,
        visited: &mut BTreeSet<(String, String)>,
    ) -> Result<ResolvedBinding, EsmLoaderError> {
        let key = (specifier.to_string(), export_name.to_string());
        if !visited.insert(key.clone()) {
            // Circular re-export paths do not themselves establish a binding.
            // Treat them as an unresolved branch so sibling star paths can
            // still contribute a real export.
            return Err(EsmLoaderError::ExportNotFound {
                specifier: specifier.to_string(),
                export_name: export_name.to_string(),
            });
        }

        let result = (|| {
            let module = self
                .modules
                .get(specifier)
                .ok_or_else(|| EsmLoaderError::ModuleNotFound(specifier.to_string()))?;

            let explicit_export_matches = module
                .exports
                .iter()
                .filter(|entry| entry.export_name == export_name)
                .count();
            if explicit_export_matches > 1 {
                return Err(EsmLoaderError::DuplicateExport {
                    specifier: specifier.to_string(),
                    export_name: export_name.to_string(),
                });
            }

            // Check direct exports first.
            for entry in &module.exports {
                if entry.export_name == export_name {
                    if let Some(local) = &entry.local_name {
                        return Ok(ResolvedBinding {
                            module_specifier: specifier.to_string(),
                            local_name: local.clone(),
                            binding_type: BindingType::Direct,
                        });
                    }

                    if let (Some(req), Some(imp)) = (&entry.module_request, &entry.import_name) {
                        match self.resolve_export_inner(req, imp, visited) {
                            Ok(mut binding) => {
                                binding.binding_type = BindingType::ReExport;
                                return Ok(binding);
                            }
                            Err(EsmLoaderError::ExportNotFound { .. }) => {
                                return Err(EsmLoaderError::ExportNotFound {
                                    specifier: specifier.to_string(),
                                    export_name: export_name.to_string(),
                                });
                            }
                            Err(EsmLoaderError::AmbiguousExport { .. }) => {
                                return Err(EsmLoaderError::AmbiguousExport {
                                    specifier: specifier.to_string(),
                                    export_name: export_name.to_string(),
                                });
                            }
                            Err(EsmLoaderError::DuplicateExport { .. }) => {
                                return Err(EsmLoaderError::DuplicateExport {
                                    specifier: specifier.to_string(),
                                    export_name: export_name.to_string(),
                                });
                            }
                            Err(err) => return Err(err),
                        }
                    }
                }
            }

            // `export *` never re-exports `default`.
            if export_name == "default" {
                return Err(EsmLoaderError::ExportNotFound {
                    specifier: specifier.to_string(),
                    export_name: export_name.to_string(),
                });
            }

            let mut found: Option<ResolvedBinding> = None;
            for entry in &module.exports {
                if entry.export_name != "*" {
                    continue;
                }
                let Some(req) = &entry.module_request else {
                    continue;
                };

                match self.resolve_export_inner(req, export_name, visited) {
                    Ok(mut binding) => {
                        binding.binding_type = BindingType::StarReExport;
                        if let Some(existing) = &found {
                            if existing != &binding {
                                return Err(EsmLoaderError::AmbiguousExport {
                                    specifier: specifier.to_string(),
                                    export_name: export_name.to_string(),
                                });
                            }
                        } else {
                            found = Some(binding);
                        }
                    }
                    Err(EsmLoaderError::ExportNotFound { .. }) => {}
                    Err(EsmLoaderError::AmbiguousExport { .. }) => {
                        return Err(EsmLoaderError::AmbiguousExport {
                            specifier: specifier.to_string(),
                            export_name: export_name.to_string(),
                        });
                    }
                    Err(EsmLoaderError::DuplicateExport { .. }) => {
                        return Err(EsmLoaderError::DuplicateExport {
                            specifier: specifier.to_string(),
                            export_name: export_name.to_string(),
                        });
                    }
                    Err(err) => return Err(err),
                }
            }

            found.ok_or_else(|| EsmLoaderError::ExportNotFound {
                specifier: specifier.to_string(),
                export_name: export_name.to_string(),
            })
        })();

        visited.remove(&key);
        result
    }

    // -----------------------------------------------------------------------
    // Cycle detection utilities
    // -----------------------------------------------------------------------

    /// Get all strongly connected components (cycles) in the graph.
    pub fn find_cycles(&self) -> Vec<Vec<String>> {
        let mut visited = BTreeSet::new();
        let mut stack = Vec::new();
        let mut on_stack = BTreeSet::new();
        let mut sccs = Vec::new();
        let mut index_map: BTreeMap<String, u32> = BTreeMap::new();
        let mut lowlink_map: BTreeMap<String, u32> = BTreeMap::new();
        let mut counter: u32 = 0;

        for specifier in self.modules.keys() {
            if !visited.contains(specifier.as_str()) {
                self.tarjan_dfs(
                    specifier,
                    &mut visited,
                    &mut stack,
                    &mut on_stack,
                    &mut sccs,
                    &mut index_map,
                    &mut lowlink_map,
                    &mut counter,
                );
            }
        }

        sccs.into_iter()
            .filter(|scc| {
                scc.len() > 1
                    || scc.first().is_some_and(|specifier| {
                        self.modules
                            .get(specifier)
                            .is_some_and(|module| module.dependencies.contains(specifier))
                    })
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn tarjan_dfs(
        &self,
        specifier: &str,
        visited: &mut BTreeSet<String>,
        stack: &mut Vec<String>,
        on_stack: &mut BTreeSet<String>,
        sccs: &mut Vec<Vec<String>>,
        index_map: &mut BTreeMap<String, u32>,
        lowlink_map: &mut BTreeMap<String, u32>,
        counter: &mut u32,
    ) {
        let index = *counter;
        *counter += 1;
        visited.insert(specifier.to_string());
        index_map.insert(specifier.to_string(), index);
        lowlink_map.insert(specifier.to_string(), index);
        stack.push(specifier.to_string());
        on_stack.insert(specifier.to_string());

        if let Some(module) = self.modules.get(specifier) {
            for dep in &module.dependencies {
                if !visited.contains(dep.as_str()) {
                    self.tarjan_dfs(
                        dep,
                        visited,
                        stack,
                        on_stack,
                        sccs,
                        index_map,
                        lowlink_map,
                        counter,
                    );
                    let dep_ll = lowlink_map.get(dep.as_str()).copied().unwrap_or(u32::MAX);
                    let cur_ll = lowlink_map.get(specifier).copied().unwrap_or(u32::MAX);
                    if dep_ll < cur_ll {
                        lowlink_map.insert(specifier.to_string(), dep_ll);
                    }
                } else if on_stack.contains(dep.as_str()) {
                    let dep_idx = index_map.get(dep.as_str()).copied().unwrap_or(u32::MAX);
                    let cur_ll = lowlink_map.get(specifier).copied().unwrap_or(u32::MAX);
                    if dep_idx < cur_ll {
                        lowlink_map.insert(specifier.to_string(), dep_idx);
                    }
                }
            }
        }

        let lowlink = lowlink_map.get(specifier).copied().unwrap_or(0);
        if lowlink == index {
            let mut scc = Vec::new();
            while let Some(top) = stack.pop() {
                on_stack.remove(&top);
                scc.push(top.clone());
                if top == specifier {
                    break;
                }
            }
            scc.reverse();
            sccs.push(scc);
        }
    }

    // -----------------------------------------------------------------------
    // Graph analysis
    // -----------------------------------------------------------------------

    /// Get the topological sort order of the module graph.
    ///
    /// Returns specifiers in evaluation order (dependencies first).
    /// Cycles are handled by treating the first-visited module in a cycle
    /// as the cycle root.
    pub fn topological_order(&self) -> Vec<String> {
        let mut visited = BTreeSet::new();
        let mut order = Vec::new();

        for specifier in self.modules.keys() {
            self.topo_dfs(specifier, &mut visited, &mut order);
        }

        order
    }

    fn topo_dfs(&self, specifier: &str, visited: &mut BTreeSet<String>, order: &mut Vec<String>) {
        if visited.contains(specifier) {
            return;
        }
        visited.insert(specifier.to_string());

        if let Some(module) = self.modules.get(specifier) {
            for dep in &module.dependencies {
                self.topo_dfs(dep, visited, order);
            }
        }

        order.push(specifier.to_string());
    }

    /// Get all modules that export a given name.
    pub fn find_exporters(&self, export_name: &str) -> Vec<String> {
        self.modules
            .iter()
            .filter(|(_, m)| m.exports.iter().any(|e| e.export_name == export_name))
            .map(|(s, _)| s.clone())
            .collect()
    }

    /// Get the set of modules reachable from a given specifier.
    pub fn transitive_dependencies(&self, specifier: &str) -> BTreeSet<String> {
        let mut reachable = BTreeSet::new();
        self.reachable_dfs(specifier, &mut reachable);
        reachable.remove(specifier);
        reachable
    }

    fn reachable_dfs(&self, specifier: &str, reachable: &mut BTreeSet<String>) {
        if reachable.contains(specifier) {
            return;
        }
        reachable.insert(specifier.to_string());
        if let Some(module) = self.modules.get(specifier) {
            for dep in &module.dependencies {
                self.reachable_dfs(dep, reachable);
            }
        }
    }
}

impl Default for ModuleGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Result of the link phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkResult {
    pub linked_count: usize,
    pub cycle_count: usize,
    pub cycles: Vec<CycleInfo>,
}

/// Information about a detected cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleInfo {
    pub specifier: String,
    pub stack_snapshot: Vec<String>,
}

/// Result of the evaluate phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResult {
    pub eval_order: Vec<String>,
    pub evaluated_count: usize,
}

/// A resolved export binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedBinding {
    pub module_specifier: String,
    pub local_name: String,
    pub binding_type: BindingType,
}

/// Type of export binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BindingType {
    /// Direct local export.
    Direct,
    /// Re-exported from another module.
    ReExport,
    /// Star re-export.
    StarReExport,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the ESM loader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EsmLoaderError {
    NoEntryPoint,
    ModuleNotFound(String),
    GraphTooLarge {
        limit: usize,
    },
    DepthExceeded {
        specifier: String,
        depth: usize,
        limit: usize,
    },
    UnresolvedDependency {
        specifier: String,
        dependency: String,
    },
    ExportNotFound {
        specifier: String,
        export_name: String,
    },
    DuplicateExport {
        specifier: String,
        export_name: String,
    },
    AmbiguousExport {
        specifier: String,
        export_name: String,
    },
    EvaluationFailed {
        specifier: String,
        reason: String,
    },
    InvalidStatus {
        specifier: String,
        expected: &'static str,
        actual: String,
    },
}

impl fmt::Display for EsmLoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEntryPoint => write!(f, "no entry point set"),
            Self::ModuleNotFound(s) => write!(f, "module not found: {s}"),
            Self::GraphTooLarge { limit } => {
                write!(f, "module graph exceeds limit of {limit} modules")
            }
            Self::DepthExceeded {
                specifier,
                depth,
                limit,
            } => write!(
                f,
                "module depth {depth} exceeds limit {limit} at {specifier}"
            ),
            Self::UnresolvedDependency {
                specifier,
                dependency,
            } => write!(f, "unresolved dependency: {specifier} imports {dependency}"),
            Self::ExportNotFound {
                specifier,
                export_name,
            } => write!(f, "export '{export_name}' not found in {specifier}"),
            Self::DuplicateExport {
                specifier,
                export_name,
            } => write!(f, "duplicate export '{export_name}' in {specifier}"),
            Self::AmbiguousExport {
                specifier,
                export_name,
            } => write!(
                f,
                "ambiguous star re-export of '{export_name}' in {specifier}"
            ),
            Self::EvaluationFailed { specifier, reason } => {
                write!(f, "evaluation failed for {specifier}: {reason}")
            }
            Self::InvalidStatus {
                specifier,
                expected,
                actual,
            } => write!(
                f,
                "invalid status for {specifier}: expected {expected}, got {actual}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

include!("esm_loader/tests.rs");
