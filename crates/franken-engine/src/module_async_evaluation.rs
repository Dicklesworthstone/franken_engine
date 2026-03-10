#![forbid(unsafe_code)]

//! Async module evaluation, suspension, and rejection-linkage semantics.
//!
//! Implements ES2020 §15.2.1.16 async evaluation ordering:
//! - Modules with top-level `await` produce a Promise for their evaluation
//! - Modules importing from an async module are themselves async
//! - Rejection in an async module propagates through the module graph
//! - Live bindings from rejected modules enter the `Dead` state
//!
//! This module builds on the foundations of:
//! - `esm_loader`: module graph, `ModuleStatus`, `EsmModule`
//! - `module_live_binding`: `LiveBindingMap`, `BindingCell`, `BindingCellState`
//! - `promise_model`: `PromiseHandle`, `PromiseState`, `PromiseStore`
//! - `object_model`: `JsValue`

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::module_live_binding::{BindingCellState, BindingId, LiveBindingMap};
use crate::object_model::JsValue;
use crate::promise_model::PromiseHandle;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const MODULE_ASYNC_EVAL_SCHEMA_VERSION: &str = "franken-engine.module_async_evaluation.v1";
pub const MODULE_ASYNC_EVAL_COMPONENT: &str = "module_async_evaluation";

// ---------------------------------------------------------------------------
// Async module status
// ---------------------------------------------------------------------------

/// Extended module status for async evaluation.
///
/// Complements `ModuleStatus` with additional states tracking
/// suspension and asynchronous settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsyncModulePhase {
    /// Module does not use top-level await — evaluation is synchronous.
    Synchronous,
    /// Module evaluation has started and is suspended at a top-level await.
    Suspended,
    /// Module is waiting for async dependencies to settle before resuming.
    AwaitingDependencies,
    /// Module evaluation resumed and completed successfully.
    Settled,
    /// Module evaluation was rejected (threw or an awaited promise rejected).
    Rejected,
}

impl AsyncModulePhase {
    pub const ALL: &'static [Self] = &[
        Self::Synchronous,
        Self::Suspended,
        Self::AwaitingDependencies,
        Self::Settled,
        Self::Rejected,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Synchronous => "synchronous",
            Self::Suspended => "suspended",
            Self::AwaitingDependencies => "awaiting_dependencies",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Synchronous | Self::Settled | Self::Rejected)
    }
}

impl fmt::Display for AsyncModulePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Suspension record
// ---------------------------------------------------------------------------

/// Why a module evaluation is suspended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuspensionContext {
    /// Suspended at a top-level `await` expression.
    TopLevelAwait,
    /// Suspended because an imported module is still evaluating asynchronously.
    AwaitingDependency { module_specifier: String },
    /// Suspended awaiting a specific binding initialization.
    AwaitingBinding { binding_id: BindingId },
}

/// Records a single suspension event during module evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspensionRecord {
    /// The module whose evaluation is suspended.
    pub module_specifier: String,
    /// Monotonic sequence number at suspension.
    pub suspension_seq: u64,
    /// Monotonic sequence number at resumption (0 if still suspended).
    pub resume_seq: u64,
    /// The Promise being awaited.
    pub awaiting_promise: PromiseHandle,
    /// Why this suspension occurred.
    pub context: SuspensionContext,
    /// Whether the suspension has been resolved.
    pub resolved: bool,
}

impl SuspensionRecord {
    pub fn new(
        module_specifier: String,
        suspension_seq: u64,
        awaiting_promise: PromiseHandle,
        context: SuspensionContext,
    ) -> Self {
        Self {
            module_specifier,
            suspension_seq,
            resume_seq: 0,
            awaiting_promise,
            context,
            resolved: false,
        }
    }

    pub fn resolve(&mut self, resume_seq: u64) {
        self.resume_seq = resume_seq;
        self.resolved = true;
    }
}

// ---------------------------------------------------------------------------
// Rejection linkage
// ---------------------------------------------------------------------------

/// How a module is linked to a rejected dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkageKind {
    /// Direct named import from the rejected module.
    DirectImport,
    /// Re-export from the rejected module.
    ReExport,
    /// Namespace import (import * as ns).
    NamespaceImport,
    /// Default import from the rejected module.
    DefaultImport,
}

impl LinkageKind {
    pub const ALL: &'static [Self] = &[
        Self::DirectImport,
        Self::ReExport,
        Self::NamespaceImport,
        Self::DefaultImport,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectImport => "direct_import",
            Self::ReExport => "re_export",
            Self::NamespaceImport => "namespace_import",
            Self::DefaultImport => "default_import",
        }
    }
}

impl fmt::Display for LinkageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A module linked to a rejected dependency.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LinkedModule {
    pub module_specifier: String,
    pub import_bindings: Vec<BindingId>,
    pub linkage_kind: LinkageKind,
}

/// Rejection linkage record — tracks how a rejection propagates through
/// the module graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectionLinkage {
    /// The module that was originally rejected.
    pub rejected_module: String,
    /// The rejection reason (error value).
    pub rejection_reason_hash: String,
    /// Modules directly linked to the rejected module.
    pub linked_modules: Vec<LinkedModule>,
    /// Transitive closure of all modules affected by this rejection.
    pub transitive_closure: BTreeSet<String>,
    /// Bindings marked dead due to this rejection.
    pub dead_bindings: Vec<BindingId>,
}

// ---------------------------------------------------------------------------
// Async module state
// ---------------------------------------------------------------------------

/// Per-module async evaluation state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncModuleState {
    /// Module specifier.
    pub module_specifier: String,
    /// Current async phase.
    pub phase: AsyncModulePhase,
    /// The Promise representing this module's evaluation (None if synchronous).
    pub evaluation_promise: Option<PromiseHandle>,
    /// Suspension records (may be empty for synchronous modules).
    pub suspensions: Vec<SuspensionRecord>,
    /// If rejected, the hash of the rejection reason.
    pub rejection_reason_hash: Option<String>,
    /// Modules that this module is waiting on.
    pub pending_dependencies: BTreeSet<String>,
    /// Whether this module has top-level await.
    pub has_top_level_await: bool,
    /// Monotonic sequence counter for events in this module.
    pub event_seq: u64,
}

impl AsyncModuleState {
    pub fn synchronous(module_specifier: String) -> Self {
        Self {
            module_specifier,
            phase: AsyncModulePhase::Synchronous,
            evaluation_promise: None,
            suspensions: Vec::new(),
            rejection_reason_hash: None,
            pending_dependencies: BTreeSet::new(),
            has_top_level_await: false,
            event_seq: 0,
        }
    }

    pub fn async_pending(module_specifier: String, promise: PromiseHandle) -> Self {
        Self {
            module_specifier,
            phase: AsyncModulePhase::Suspended,
            evaluation_promise: Some(promise),
            suspensions: Vec::new(),
            rejection_reason_hash: None,
            pending_dependencies: BTreeSet::new(),
            has_top_level_await: true,
            event_seq: 0,
        }
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.event_seq;
        self.event_seq += 1;
        seq
    }

    pub fn record_suspension(
        &mut self,
        awaiting_promise: PromiseHandle,
        context: SuspensionContext,
    ) {
        let seq = self.next_seq();
        self.suspensions.push(SuspensionRecord::new(
            self.module_specifier.clone(),
            seq,
            awaiting_promise,
            context,
        ));
        self.phase = AsyncModulePhase::Suspended;
    }

    pub fn record_resumption(&mut self) {
        let seq = self.next_seq();
        if let Some(last) = self.suspensions.last_mut()
            && !last.resolved
        {
            last.resolve(seq);
        }
    }

    pub fn settle(&mut self) {
        self.phase = AsyncModulePhase::Settled;
        self.pending_dependencies.clear();
    }

    pub fn reject(&mut self, reason_hash: String) {
        self.phase = AsyncModulePhase::Rejected;
        self.rejection_reason_hash = Some(reason_hash);
    }

    pub fn add_pending_dependency(&mut self, dep: String) {
        self.pending_dependencies.insert(dep);
        if self.phase == AsyncModulePhase::Suspended {
            self.phase = AsyncModulePhase::AwaitingDependencies;
        }
    }

    pub fn resolve_dependency(&mut self, dep: &str) {
        self.pending_dependencies.remove(dep);
    }

    pub fn all_dependencies_settled(&self) -> bool {
        self.pending_dependencies.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Evaluation witness events
// ---------------------------------------------------------------------------

/// Witness event for deterministic replay of async module evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncEvalWitnessEvent {
    pub module_specifier: String,
    pub event_type: AsyncEvalEventType,
    pub seq: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsyncEvalEventType {
    EvaluationStarted,
    TopLevelAwaitSuspended,
    DependencySuspended,
    DependencySettled,
    DependencyRejected,
    EvaluationResumed,
    EvaluationSettled,
    EvaluationRejected,
    BindingMarkedDead,
    RejectionPropagated,
}

impl AsyncEvalEventType {
    pub const ALL: &'static [Self] = &[
        Self::EvaluationStarted,
        Self::TopLevelAwaitSuspended,
        Self::DependencySuspended,
        Self::DependencySettled,
        Self::DependencyRejected,
        Self::EvaluationResumed,
        Self::EvaluationSettled,
        Self::EvaluationRejected,
        Self::BindingMarkedDead,
        Self::RejectionPropagated,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EvaluationStarted => "evaluation_started",
            Self::TopLevelAwaitSuspended => "top_level_await_suspended",
            Self::DependencySuspended => "dependency_suspended",
            Self::DependencySettled => "dependency_settled",
            Self::DependencyRejected => "dependency_rejected",
            Self::EvaluationResumed => "evaluation_resumed",
            Self::EvaluationSettled => "evaluation_settled",
            Self::EvaluationRejected => "evaluation_rejected",
            Self::BindingMarkedDead => "binding_marked_dead",
            Self::RejectionPropagated => "rejection_propagated",
        }
    }
}

// ---------------------------------------------------------------------------
// Async evaluation error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsyncEvalError {
    /// Module not found in the evaluation graph.
    ModuleNotFound { specifier: String },
    /// Module is not in a valid state for the requested operation.
    InvalidPhaseTransition {
        specifier: String,
        from: AsyncModulePhase,
        to: AsyncModulePhase,
    },
    /// Cycle detected during async evaluation ordering.
    CycleDetected { modules: Vec<String> },
    /// Maximum suspension depth exceeded.
    SuspensionLimitExceeded { specifier: String, limit: u64 },
    /// Rejection propagation failed.
    RejectionPropagationFailed { specifier: String, detail: String },
}

impl fmt::Display for AsyncEvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleNotFound { specifier } => {
                write!(f, "module not found: {specifier}")
            }
            Self::InvalidPhaseTransition {
                specifier,
                from,
                to,
            } => {
                write!(
                    f,
                    "invalid phase transition for {specifier}: {from} -> {to}"
                )
            }
            Self::CycleDetected { modules } => {
                write!(f, "cycle detected: {}", modules.join(" -> "))
            }
            Self::SuspensionLimitExceeded { specifier, limit } => {
                write!(f, "suspension limit {limit} exceeded for {specifier}")
            }
            Self::RejectionPropagationFailed { specifier, detail } => {
                write!(f, "rejection propagation failed for {specifier}: {detail}")
            }
        }
    }
}

impl std::error::Error for AsyncEvalError {}

// ---------------------------------------------------------------------------
// Async evaluation result
// ---------------------------------------------------------------------------

/// Result of evaluating a module graph with async semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncEvalResult {
    /// Per-module states after evaluation.
    pub module_states: BTreeMap<String, AsyncModuleState>,
    /// Rejection linkages computed during evaluation.
    pub rejection_linkages: Vec<RejectionLinkage>,
    /// Witness events for replay.
    pub witness_events: Vec<AsyncEvalWitnessEvent>,
    /// Total number of suspensions across all modules.
    pub total_suspensions: u64,
    /// Total number of rejections across all modules.
    pub total_rejections: u64,
    /// Whether all modules settled successfully.
    pub all_settled: bool,
    /// Content hash of the result for integrity verification.
    pub result_hash: String,
}

impl AsyncEvalResult {
    pub fn settled_count(&self) -> usize {
        self.module_states
            .values()
            .filter(|s| {
                s.phase == AsyncModulePhase::Settled || s.phase == AsyncModulePhase::Synchronous
            })
            .count()
    }

    pub fn rejected_count(&self) -> usize {
        self.module_states
            .values()
            .filter(|s| s.phase == AsyncModulePhase::Rejected)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Async module evaluator
// ---------------------------------------------------------------------------

/// Configuration for the async module evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncEvalConfig {
    /// Maximum number of suspensions per module.
    pub max_suspensions_per_module: u64,
    /// Maximum total suspension records.
    pub max_total_suspensions: u64,
    /// Whether to propagate rejections transitively.
    pub transitive_rejection_propagation: bool,
}

impl Default for AsyncEvalConfig {
    fn default() -> Self {
        Self {
            max_suspensions_per_module: 256,
            max_total_suspensions: 4096,
            transitive_rejection_propagation: true,
        }
    }
}

/// Evaluates a set of modules with async evaluation semantics.
///
/// The evaluator walks the module graph in topological order, tracking
/// which modules have top-level await and managing suspension/resumption
/// of their evaluation.
pub struct AsyncModuleEvaluator {
    /// Per-module async state.
    states: BTreeMap<String, AsyncModuleState>,
    /// Rejection linkages computed during evaluation.
    rejection_linkages: Vec<RejectionLinkage>,
    /// Witness events for deterministic replay.
    witness_events: Vec<AsyncEvalWitnessEvent>,
    /// Global sequence counter.
    global_seq: u64,
    /// Configuration.
    config: AsyncEvalConfig,
}

impl AsyncModuleEvaluator {
    pub fn new(config: AsyncEvalConfig) -> Self {
        Self {
            states: BTreeMap::new(),
            rejection_linkages: Vec::new(),
            witness_events: Vec::new(),
            global_seq: 0,
            config,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(AsyncEvalConfig::default())
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.global_seq;
        self.global_seq += 1;
        seq
    }

    fn emit_event(&mut self, specifier: &str, event_type: AsyncEvalEventType, detail: String) {
        let seq = self.next_seq();
        self.witness_events.push(AsyncEvalWitnessEvent {
            module_specifier: specifier.to_string(),
            event_type,
            seq,
            detail,
        });
    }

    /// Register a module for async evaluation.
    pub fn register_module(
        &mut self,
        specifier: &str,
        has_top_level_await: bool,
        dependencies: &[String],
        evaluation_promise: Option<PromiseHandle>,
    ) {
        let mut state = if has_top_level_await {
            AsyncModuleState::async_pending(
                specifier.to_string(),
                evaluation_promise.unwrap_or(PromiseHandle(0)),
            )
        } else {
            AsyncModuleState::synchronous(specifier.to_string())
        };

        // Track which dependencies are async (need to wait).
        for dep in dependencies {
            if let Some(dep_state) = self.states.get(dep)
                && (!dep_state.phase.is_terminal() || dep_state.phase == AsyncModulePhase::Rejected)
            {
                state.add_pending_dependency(dep.clone());
            }
        }

        self.emit_event(
            specifier,
            AsyncEvalEventType::EvaluationStarted,
            format!("has_tla={has_top_level_await} deps={}", dependencies.len()),
        );
        self.states.insert(specifier.to_string(), state);
    }

    /// Record a top-level await suspension for a module.
    pub fn suspend_at_top_level_await(
        &mut self,
        specifier: &str,
        awaiting_promise: PromiseHandle,
    ) -> Result<(), AsyncEvalError> {
        let detail = format!("promise={awaiting_promise}");
        {
            let state =
                self.states
                    .get_mut(specifier)
                    .ok_or_else(|| AsyncEvalError::ModuleNotFound {
                        specifier: specifier.to_string(),
                    })?;

            if state.suspensions.len() as u64 >= self.config.max_suspensions_per_module {
                return Err(AsyncEvalError::SuspensionLimitExceeded {
                    specifier: specifier.to_string(),
                    limit: self.config.max_suspensions_per_module,
                });
            }

            state.record_suspension(awaiting_promise, SuspensionContext::TopLevelAwait);
        }
        self.emit_event(
            specifier,
            AsyncEvalEventType::TopLevelAwaitSuspended,
            detail,
        );
        Ok(())
    }

    /// Record that a module is waiting on a dependency.
    pub fn suspend_on_dependency(
        &mut self,
        specifier: &str,
        dependency: &str,
        awaiting_promise: PromiseHandle,
    ) -> Result<(), AsyncEvalError> {
        let detail = format!("awaiting={dependency}");
        {
            let state =
                self.states
                    .get_mut(specifier)
                    .ok_or_else(|| AsyncEvalError::ModuleNotFound {
                        specifier: specifier.to_string(),
                    })?;

            state.record_suspension(
                awaiting_promise,
                SuspensionContext::AwaitingDependency {
                    module_specifier: dependency.to_string(),
                },
            );
            state.add_pending_dependency(dependency.to_string());
        }
        self.emit_event(specifier, AsyncEvalEventType::DependencySuspended, detail);
        Ok(())
    }

    /// Notify that a dependency has settled, potentially allowing
    /// dependent modules to resume.
    pub fn notify_dependency_settled(
        &mut self,
        settled_module: &str,
    ) -> Result<Vec<String>, AsyncEvalError> {
        let mut resumable = Vec::new();

        // Collect modules that were waiting on this dependency.
        let waiting_modules: Vec<String> = self
            .states
            .iter()
            .filter(|(_, s)| s.pending_dependencies.contains(settled_module))
            .map(|(k, _)| k.clone())
            .collect();

        for module_spec in &waiting_modules {
            let all_settled = if let Some(state) = self.states.get_mut(module_spec) {
                state.resolve_dependency(settled_module);
                state.all_dependencies_settled()
            } else {
                continue;
            };

            self.emit_event(
                module_spec,
                AsyncEvalEventType::DependencySettled,
                format!("settled={settled_module}"),
            );
            if all_settled {
                resumable.push(module_spec.clone());
            }
        }

        Ok(resumable)
    }

    /// Resume evaluation of a module after all dependencies have settled.
    pub fn resume_evaluation(&mut self, specifier: &str) -> Result<(), AsyncEvalError> {
        {
            let state =
                self.states
                    .get_mut(specifier)
                    .ok_or_else(|| AsyncEvalError::ModuleNotFound {
                        specifier: specifier.to_string(),
                    })?;

            state.record_resumption();
        }
        self.emit_event(
            specifier,
            AsyncEvalEventType::EvaluationResumed,
            "dependencies_settled".to_string(),
        );
        Ok(())
    }

    /// Mark a module's evaluation as successfully settled.
    pub fn settle_module(&mut self, specifier: &str) -> Result<Vec<String>, AsyncEvalError> {
        let suspension_count = {
            let state =
                self.states
                    .get_mut(specifier)
                    .ok_or_else(|| AsyncEvalError::ModuleNotFound {
                        specifier: specifier.to_string(),
                    })?;

            state.settle();
            state.suspensions.len()
        };
        self.emit_event(
            specifier,
            AsyncEvalEventType::EvaluationSettled,
            format!("suspensions={suspension_count}"),
        );

        // Notify dependents.
        self.notify_dependency_settled(specifier)
    }

    /// Reject a module's evaluation and propagate through the graph.
    pub fn reject_module(
        &mut self,
        specifier: &str,
        reason: &JsValue,
        live_bindings: &mut LiveBindingMap,
    ) -> Result<RejectionLinkage, AsyncEvalError> {
        let reason_hash = ContentHash::compute(format!("{reason:?}").as_bytes())
            .as_bytes()
            .iter()
            .fold(String::new(), |mut acc, b| {
                use fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });

        // Mark the module as rejected.
        {
            let state =
                self.states
                    .get_mut(specifier)
                    .ok_or_else(|| AsyncEvalError::ModuleNotFound {
                        specifier: specifier.to_string(),
                    })?;
            state.reject(reason_hash.clone());
        }

        self.emit_event(
            specifier,
            AsyncEvalEventType::EvaluationRejected,
            format!("reason_hash={}", &reason_hash[..8.min(reason_hash.len())]),
        );

        // Find all bindings from the rejected module and mark them dead.
        let dead_bindings = Self::mark_bindings_dead(specifier, live_bindings);

        for binding_id in &dead_bindings {
            self.emit_event(
                specifier,
                AsyncEvalEventType::BindingMarkedDead,
                format!(
                    "binding={}:{}",
                    binding_id.module_specifier, binding_id.export_name
                ),
            );
        }

        // Find modules that import from the rejected module.
        let linked_modules = self.find_linked_modules(specifier);

        // Compute transitive closure if configured.
        let transitive_closure = if self.config.transitive_rejection_propagation {
            self.compute_rejection_transitive_closure(specifier)
        } else {
            let mut set = BTreeSet::new();
            for lm in &linked_modules {
                set.insert(lm.module_specifier.clone());
            }
            set
        };

        // Propagate rejection to waiting modules.
        for module_spec in &transitive_closure {
            let additional_dead = if let Some(dep_state) = self.states.get_mut(module_spec)
                && !dep_state.phase.is_terminal()
            {
                dep_state.reject(reason_hash.clone());
                Some(Self::mark_bindings_dead(module_spec, live_bindings))
            } else {
                None
            };
            if let Some(additional_dead) = additional_dead {
                for bid in &additional_dead {
                    self.emit_event(
                        module_spec,
                        AsyncEvalEventType::BindingMarkedDead,
                        format!("binding={}:{}", bid.module_specifier, bid.export_name),
                    );
                }
            }
            self.emit_event(
                module_spec,
                AsyncEvalEventType::RejectionPropagated,
                format!("from={specifier}"),
            );
        }

        let linkage = RejectionLinkage {
            rejected_module: specifier.to_string(),
            rejection_reason_hash: reason_hash,
            linked_modules,
            transitive_closure,
            dead_bindings,
        };
        self.rejection_linkages.push(linkage.clone());
        Ok(linkage)
    }

    /// Produce the final evaluation result.
    pub fn finalize(self) -> AsyncEvalResult {
        let total_suspensions: u64 = self
            .states
            .values()
            .map(|s| s.suspensions.len() as u64)
            .sum();
        let total_rejections = self
            .states
            .values()
            .filter(|s| s.phase == AsyncModulePhase::Rejected)
            .count() as u64;
        let all_settled = self
            .states
            .values()
            .all(|s| s.phase.is_terminal() && s.phase != AsyncModulePhase::Rejected);

        let hash_input = format!(
            "async_eval:modules={}:suspensions={total_suspensions}:rejections={total_rejections}",
            self.states.len()
        );
        let result_hash = ContentHash::compute(hash_input.as_bytes())
            .as_bytes()
            .iter()
            .fold(String::new(), |mut acc, b| {
                use fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });

        AsyncEvalResult {
            module_states: self.states,
            rejection_linkages: self.rejection_linkages,
            witness_events: self.witness_events,
            total_suspensions,
            total_rejections,
            all_settled,
            result_hash,
        }
    }

    // -- Private helpers --

    fn mark_bindings_dead(
        module_specifier: &str,
        live_bindings: &mut LiveBindingMap,
    ) -> Vec<BindingId> {
        let mut dead = Vec::new();
        let binding_ids: Vec<BindingId> = live_bindings
            .cells
            .keys()
            .filter(|id| id.module_specifier == module_specifier)
            .cloned()
            .collect();
        for id in binding_ids {
            let should_mark_dead = live_bindings
                .get_cell(&id)
                .is_some_and(|cell| cell.state != BindingCellState::Dead);
            if should_mark_dead && live_bindings.mark_dead(&id).is_ok() {
                dead.push(id);
            }
        }
        dead
    }

    fn find_linked_modules(&self, rejected_module: &str) -> Vec<LinkedModule> {
        let mut linked = Vec::new();
        for (specifier, state) in &self.states {
            if specifier == rejected_module {
                continue;
            }
            if state.pending_dependencies.contains(rejected_module) {
                linked.push(LinkedModule {
                    module_specifier: specifier.clone(),
                    import_bindings: Vec::new(),
                    linkage_kind: LinkageKind::DirectImport,
                });
            }
        }
        linked
    }

    fn compute_rejection_transitive_closure(&self, rejected_module: &str) -> BTreeSet<String> {
        let mut closure = BTreeSet::new();
        let mut worklist = vec![rejected_module.to_string()];
        while let Some(current) = worklist.pop() {
            for (specifier, state) in &self.states {
                if closure.contains(specifier.as_str()) || specifier == &current {
                    continue;
                }
                if state.pending_dependencies.contains(&current) {
                    closure.insert(specifier.clone());
                    worklist.push(specifier.clone());
                }
            }
        }
        closure
    }

    /// Access the current states.
    pub fn states(&self) -> &BTreeMap<String, AsyncModuleState> {
        &self.states
    }

    /// Access the witness events.
    pub fn witness_events(&self) -> &[AsyncEvalWitnessEvent] {
        &self.witness_events
    }
}

// ---------------------------------------------------------------------------
// Topological async evaluation ordering
// ---------------------------------------------------------------------------

/// Compute the topological evaluation order for modules, considering
/// async dependencies. Returns an ordered list of module specifiers.
pub fn compute_async_evaluation_order(
    module_specifiers: &[String],
    dependencies: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<String>, AsyncEvalError> {
    let mut in_degree: BTreeMap<&str, usize> = BTreeMap::new();
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

    for spec in module_specifiers {
        in_degree.entry(spec.as_str()).or_insert(0);
        adjacency.entry(spec.as_str()).or_default();
    }

    for (module, deps) in dependencies {
        for dep in deps {
            if module_specifiers.iter().any(|s| s == dep) {
                adjacency
                    .entry(dep.as_str())
                    .or_default()
                    .push(module.as_str());
                *in_degree.entry(module.as_str()).or_insert(0) += 1;
            }
        }
    }

    let mut queue: Vec<&str> = in_degree
        .iter()
        .filter(|(_, deg)| **deg == 0)
        .map(|(spec, _)| *spec)
        .collect();
    queue.sort(); // deterministic ordering

    let mut order = Vec::new();
    while let Some(spec) = queue.pop() {
        order.push(spec.to_string());
        let successors: Vec<&str> = adjacency.get(spec).cloned().unwrap_or_default();
        for succ in successors {
            if let Some(deg) = in_degree.get_mut(succ) {
                *deg = deg.saturating_sub(1);
                if *deg == 0 {
                    queue.push(succ);
                    queue.sort(); // maintain deterministic ordering
                }
            }
        }
    }

    if order.len() != module_specifiers.len() {
        let remaining: Vec<String> = module_specifiers
            .iter()
            .filter(|s| !order.contains(s))
            .cloned()
            .collect();
        return Err(AsyncEvalError::CycleDetected { modules: remaining });
    }

    Ok(order)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esm_loader::BindingType;
    use crate::module_live_binding::{BindingCell, BindingEvent};

    fn js_error(msg: &str) -> JsValue {
        JsValue::Str(msg.to_string())
    }

    fn empty_live_bindings() -> LiveBindingMap {
        LiveBindingMap {
            cells: BTreeMap::new(),
            namespaces: BTreeMap::new(),
            imports: Vec::new(),
            events: Vec::new(),
            schema_version: "test".to_string(),
        }
    }

    // -- AsyncModulePhase --

    #[test]
    fn phase_all_variants_count() {
        assert_eq!(AsyncModulePhase::ALL.len(), 5);
    }

    #[test]
    fn phase_as_str_distinct() {
        let strs: BTreeSet<&str> = AsyncModulePhase::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(strs.len(), AsyncModulePhase::ALL.len());
    }

    #[test]
    fn phase_terminal_check() {
        assert!(AsyncModulePhase::Synchronous.is_terminal());
        assert!(!AsyncModulePhase::Suspended.is_terminal());
        assert!(!AsyncModulePhase::AwaitingDependencies.is_terminal());
        assert!(AsyncModulePhase::Settled.is_terminal());
        assert!(AsyncModulePhase::Rejected.is_terminal());
    }

    #[test]
    fn phase_serde_roundtrip() {
        for p in AsyncModulePhase::ALL {
            let json = serde_json::to_string(p).unwrap();
            let back: AsyncModulePhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, back);
        }
    }

    // -- SuspensionRecord --

    #[test]
    fn suspension_record_new_unresolved() {
        let sr = SuspensionRecord::new(
            "mod.js".into(),
            0,
            PromiseHandle(1),
            SuspensionContext::TopLevelAwait,
        );
        assert!(!sr.resolved);
        assert_eq!(sr.resume_seq, 0);
    }

    #[test]
    fn suspension_record_resolve() {
        let mut sr = SuspensionRecord::new(
            "mod.js".into(),
            0,
            PromiseHandle(1),
            SuspensionContext::TopLevelAwait,
        );
        sr.resolve(5);
        assert!(sr.resolved);
        assert_eq!(sr.resume_seq, 5);
    }

    // -- LinkageKind --

    #[test]
    fn linkage_kind_all_count() {
        assert_eq!(LinkageKind::ALL.len(), 4);
    }

    #[test]
    fn linkage_kind_serde_roundtrip() {
        for k in LinkageKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: LinkageKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // -- AsyncModuleState --

    #[test]
    fn sync_state_is_synchronous() {
        let s = AsyncModuleState::synchronous("a.js".into());
        assert_eq!(s.phase, AsyncModulePhase::Synchronous);
        assert!(!s.has_top_level_await);
        assert!(s.evaluation_promise.is_none());
    }

    #[test]
    fn async_state_is_suspended() {
        let s = AsyncModuleState::async_pending("b.js".into(), PromiseHandle(1));
        assert_eq!(s.phase, AsyncModulePhase::Suspended);
        assert!(s.has_top_level_await);
        assert_eq!(s.evaluation_promise, Some(PromiseHandle(1)));
    }

    #[test]
    fn state_settle() {
        let mut s = AsyncModuleState::async_pending("c.js".into(), PromiseHandle(2));
        s.settle();
        assert_eq!(s.phase, AsyncModulePhase::Settled);
    }

    #[test]
    fn state_reject() {
        let mut s = AsyncModuleState::async_pending("d.js".into(), PromiseHandle(3));
        s.reject("hash123".into());
        assert_eq!(s.phase, AsyncModulePhase::Rejected);
        assert_eq!(s.rejection_reason_hash, Some("hash123".to_string()));
    }

    #[test]
    fn state_dependency_tracking() {
        let mut s = AsyncModuleState::async_pending("e.js".into(), PromiseHandle(4));
        s.add_pending_dependency("dep1".into());
        s.add_pending_dependency("dep2".into());
        assert!(!s.all_dependencies_settled());
        s.resolve_dependency("dep1");
        assert!(!s.all_dependencies_settled());
        s.resolve_dependency("dep2");
        assert!(s.all_dependencies_settled());
    }

    // -- AsyncModuleEvaluator --

    #[test]
    fn evaluator_register_sync_module() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("sync.js", false, &[], None);
        let states = eval.states();
        assert_eq!(states.len(), 1);
        assert_eq!(states["sync.js"].phase, AsyncModulePhase::Synchronous);
    }

    #[test]
    fn evaluator_register_async_module() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("async.js", true, &[], Some(PromiseHandle(10)));
        assert_eq!(eval.states()["async.js"].phase, AsyncModulePhase::Suspended);
    }

    #[test]
    fn evaluator_suspend_and_resume() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("tla.js", true, &[], Some(PromiseHandle(10)));
        eval.suspend_at_top_level_await("tla.js", PromiseHandle(20))
            .unwrap();
        assert_eq!(eval.states()["tla.js"].suspensions.len(), 1);
        eval.resume_evaluation("tla.js").unwrap();
        assert!(eval.states()["tla.js"].suspensions[0].resolved);
    }

    #[test]
    fn evaluator_settle_module() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("m.js", true, &[], Some(PromiseHandle(10)));
        let resumable = eval.settle_module("m.js").unwrap();
        assert!(resumable.is_empty());
        assert_eq!(eval.states()["m.js"].phase, AsyncModulePhase::Settled);
    }

    #[test]
    fn evaluator_reject_module() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("bad.js", true, &[], Some(PromiseHandle(10)));
        let mut bindings = empty_live_bindings();
        let linkage = eval
            .reject_module("bad.js", &js_error("oops"), &mut bindings)
            .unwrap();
        assert_eq!(linkage.rejected_module, "bad.js");
        assert_eq!(eval.states()["bad.js"].phase, AsyncModulePhase::Rejected);
    }

    #[test]
    fn evaluator_dependency_notification() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("dep.js", true, &[], Some(PromiseHandle(1)));
        eval.register_module(
            "consumer.js",
            true,
            &["dep.js".to_string()],
            Some(PromiseHandle(2)),
        );
        eval.suspend_on_dependency("consumer.js", "dep.js", PromiseHandle(1))
            .unwrap();
        assert!(!eval.states()["consumer.js"].all_dependencies_settled());

        let resumable = eval.notify_dependency_settled("dep.js").unwrap();
        assert!(resumable.contains(&"consumer.js".to_string()));
        assert!(eval.states()["consumer.js"].all_dependencies_settled());
    }

    #[test]
    fn evaluator_rejection_propagation() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("root.js", true, &[], Some(PromiseHandle(1)));
        eval.register_module(
            "child.js",
            true,
            &["root.js".to_string()],
            Some(PromiseHandle(2)),
        );
        eval.suspend_on_dependency("child.js", "root.js", PromiseHandle(1))
            .unwrap();

        let mut bindings = empty_live_bindings();
        let linkage = eval
            .reject_module("root.js", &js_error("fail"), &mut bindings)
            .unwrap();

        assert!(linkage.transitive_closure.contains("child.js"));
        assert_eq!(eval.states()["child.js"].phase, AsyncModulePhase::Rejected);
    }

    #[test]
    fn evaluator_reject_records_live_binding_cell_died_event() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));

        let mut bindings = empty_live_bindings();
        let binding_id = bindings.register_cell(BindingCell::new(
            "bad.js",
            "value",
            "value",
            BindingType::Direct,
        ));

        let linkage = eval
            .reject_module("bad.js", &js_error("fail"), &mut bindings)
            .unwrap();

        assert_eq!(linkage.dead_bindings, vec![binding_id.clone()]);
        assert_eq!(
            bindings.get_cell(&binding_id).map(|cell| cell.state),
            Some(BindingCellState::Dead)
        );
        assert!(bindings.events.iter().any(|event| matches!(
            event,
            BindingEvent::CellDied { binding_id: event_id } if event_id == &binding_id
        )));
    }

    #[test]
    fn evaluator_finalize() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("a.js", false, &[], None);
        eval.register_module("b.js", true, &[], Some(PromiseHandle(1)));
        eval.settle_module("b.js").unwrap();
        let result = eval.finalize();
        assert!(result.all_settled);
        assert_eq!(result.total_rejections, 0);
        assert!(!result.result_hash.is_empty());
    }

    #[test]
    fn evaluator_finalize_with_rejection() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));
        let mut bindings = empty_live_bindings();
        eval.reject_module("bad.js", &js_error("err"), &mut bindings)
            .unwrap();
        let result = eval.finalize();
        assert!(!result.all_settled);
        assert_eq!(result.total_rejections, 1);
    }

    #[test]
    fn evaluator_witness_events_emitted() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
        eval.suspend_at_top_level_await("m.js", PromiseHandle(2))
            .unwrap();
        eval.resume_evaluation("m.js").unwrap();
        eval.settle_module("m.js").unwrap();
        assert!(eval.witness_events().len() >= 4);
    }

    #[test]
    fn evaluator_suspension_limit() {
        let config = AsyncEvalConfig {
            max_suspensions_per_module: 2,
            ..Default::default()
        };
        let mut eval = AsyncModuleEvaluator::new(config);
        eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
        eval.suspend_at_top_level_await("m.js", PromiseHandle(2))
            .unwrap();
        eval.suspend_at_top_level_await("m.js", PromiseHandle(3))
            .unwrap();
        let err = eval
            .suspend_at_top_level_await("m.js", PromiseHandle(4))
            .unwrap_err();
        assert!(matches!(
            err,
            AsyncEvalError::SuspensionLimitExceeded { .. }
        ));
    }

    #[test]
    fn evaluator_module_not_found_error() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        let err = eval
            .suspend_at_top_level_await("nonexistent.js", PromiseHandle(1))
            .unwrap_err();
        assert!(matches!(err, AsyncEvalError::ModuleNotFound { .. }));
    }

    // -- Topological ordering --

    #[test]
    fn topological_order_simple() {
        let modules = vec!["a.js".into(), "b.js".into(), "c.js".into()];
        let deps = {
            let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
            m.insert("b.js".into(), vec!["a.js".into()]);
            m.insert("c.js".into(), vec!["b.js".into()]);
            m
        };
        let order = compute_async_evaluation_order(&modules, &deps).unwrap();
        let pos_a = order.iter().position(|s| s == "a.js").unwrap();
        let pos_b = order.iter().position(|s| s == "b.js").unwrap();
        let pos_c = order.iter().position(|s| s == "c.js").unwrap();
        assert!(pos_a < pos_b);
        assert!(pos_b < pos_c);
    }

    #[test]
    fn topological_order_no_deps() {
        let modules = vec!["x.js".into(), "y.js".into()];
        let deps = BTreeMap::new();
        let order = compute_async_evaluation_order(&modules, &deps).unwrap();
        assert_eq!(order.len(), 2);
    }

    #[test]
    fn topological_order_cycle_detected() {
        let modules = vec!["a.js".into(), "b.js".into()];
        let deps = {
            let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
            m.insert("a.js".into(), vec!["b.js".into()]);
            m.insert("b.js".into(), vec!["a.js".into()]);
            m
        };
        let err = compute_async_evaluation_order(&modules, &deps).unwrap_err();
        assert!(matches!(err, AsyncEvalError::CycleDetected { .. }));
    }

    // -- Serde roundtrips --

    #[test]
    fn async_eval_result_serde_roundtrip() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("a.js", false, &[], None);
        eval.register_module("b.js", true, &[], Some(PromiseHandle(1)));
        eval.settle_module("b.js").unwrap();
        let result = eval.finalize();
        let json = serde_json::to_string(&result).unwrap();
        let back: AsyncEvalResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn suspension_record_serde_roundtrip() {
        let sr = SuspensionRecord::new(
            "m.js".into(),
            0,
            PromiseHandle(1),
            SuspensionContext::TopLevelAwait,
        );
        let json = serde_json::to_string(&sr).unwrap();
        let back: SuspensionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(sr, back);
    }

    #[test]
    fn rejection_linkage_serde_roundtrip() {
        let rl = RejectionLinkage {
            rejected_module: "bad.js".into(),
            rejection_reason_hash: "abc".into(),
            linked_modules: vec![LinkedModule {
                module_specifier: "consumer.js".into(),
                import_bindings: vec![],
                linkage_kind: LinkageKind::DirectImport,
            }],
            transitive_closure: {
                let mut s = BTreeSet::new();
                s.insert("consumer.js".into());
                s
            },
            dead_bindings: vec![],
        };
        let json = serde_json::to_string(&rl).unwrap();
        let back: RejectionLinkage = serde_json::from_str(&json).unwrap();
        assert_eq!(rl, back);
    }

    #[test]
    fn async_eval_event_type_all_count() {
        assert_eq!(AsyncEvalEventType::ALL.len(), 10);
    }

    #[test]
    fn async_eval_event_type_serde_roundtrip() {
        for t in AsyncEvalEventType::ALL {
            let json = serde_json::to_string(t).unwrap();
            let back: AsyncEvalEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    #[test]
    fn async_eval_error_display() {
        let err = AsyncEvalError::ModuleNotFound {
            specifier: "x.js".into(),
        };
        assert!(err.to_string().contains("x.js"));
    }

    #[test]
    fn async_eval_config_default() {
        let cfg = AsyncEvalConfig::default();
        assert_eq!(cfg.max_suspensions_per_module, 256);
        assert_eq!(cfg.max_total_suspensions, 4096);
        assert!(cfg.transitive_rejection_propagation);
    }

    #[test]
    fn suspension_context_serde_roundtrip() {
        for ctx in [
            SuspensionContext::TopLevelAwait,
            SuspensionContext::AwaitingDependency {
                module_specifier: "dep.js".into(),
            },
            SuspensionContext::AwaitingBinding {
                binding_id: BindingId {
                    module_specifier: "m.js".into(),
                    export_name: "x".into(),
                },
            },
        ] {
            let json = serde_json::to_string(&ctx).unwrap();
            let back: SuspensionContext = serde_json::from_str(&json).unwrap();
            assert_eq!(ctx, back);
        }
    }

    #[test]
    fn schema_constants_non_empty() {
        assert!(!MODULE_ASYNC_EVAL_SCHEMA_VERSION.is_empty());
        assert!(!MODULE_ASYNC_EVAL_COMPONENT.is_empty());
    }

    #[test]
    fn schema_version_prefixed() {
        assert!(MODULE_ASYNC_EVAL_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn async_eval_result_counts() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("ok.js", false, &[], None);
        eval.register_module("bad.js", true, &[], Some(PromiseHandle(1)));
        let mut bindings = empty_live_bindings();
        eval.reject_module("bad.js", &js_error("err"), &mut bindings)
            .unwrap();
        let result = eval.finalize();
        assert_eq!(result.settled_count(), 1); // ok.js is Synchronous
        assert_eq!(result.rejected_count(), 1); // bad.js
    }
}
