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
    /// The rejection reason (error value hash).
    pub rejection_reason_hash: String,
    /// Human-readable description of the exception that caused rejection.
    pub rejection_reason_description: Option<String>,
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
    /// If rejected, a human-readable description of the exception that caused
    /// rejection.  Preserved for downstream failure hooks and diagnostics.
    pub rejection_reason_description: Option<String>,
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
            rejection_reason_description: None,
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
            rejection_reason_description: None,
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

    pub fn reject(&mut self, reason_hash: String, reason_description: Option<String>) {
        self.phase = AsyncModulePhase::Rejected;
        self.rejection_reason_hash = Some(reason_hash);
        self.rejection_reason_description = reason_description;
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
    /// Declared dependency graph, distinct from the mutable pending set used
    /// for wake-up bookkeeping.
    declared_dependencies: BTreeMap<String, BTreeSet<String>>,
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
            declared_dependencies: BTreeMap::new(),
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
        self.declared_dependencies.insert(
            specifier.to_string(),
            dependencies.iter().cloned().collect(),
        );

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

        // Derive a human-readable description from the rejection reason.
        let reason_description = Some(format!("{reason:?}"));

        // Mark the module as rejected.
        {
            let state =
                self.states
                    .get_mut(specifier)
                    .ok_or_else(|| AsyncEvalError::ModuleNotFound {
                        specifier: specifier.to_string(),
                    })?;
            state.reject(reason_hash.clone(), reason_description.clone());
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
                dep_state.reject(reason_hash.clone(), reason_description.clone());
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
            rejection_reason_description: reason_description,
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
        for specifier in self.states.keys() {
            if specifier == rejected_module {
                continue;
            }
            if self
                .declared_dependencies
                .get(specifier)
                .is_some_and(|deps| deps.contains(rejected_module))
            {
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
            for specifier in self.states.keys() {
                if closure.contains(specifier.as_str()) || specifier == &current {
                    continue;
                }
                if self
                    .declared_dependencies
                    .get(specifier)
                    .is_some_and(|deps| deps.contains(&current))
                {
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
        s.reject("hash123".into(), Some("test rejection".into()));
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
    fn evaluator_rejection_uses_declared_dependencies_even_when_not_pending() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("provider.js", false, &[], None);
        eval.register_module(
            "consumer.js",
            true,
            &["provider.js".to_string()],
            Some(PromiseHandle(1)),
        );

        assert!(
            !eval.states()["consumer.js"]
                .pending_dependencies
                .contains("provider.js")
        );

        let mut bindings = empty_live_bindings();
        let linkage = eval
            .reject_module("provider.js", &js_error("fail"), &mut bindings)
            .unwrap();

        assert!(
            linkage
                .linked_modules
                .iter()
                .any(|module| module.module_specifier == "consumer.js")
        );
        assert!(linkage.transitive_closure.contains("consumer.js"));
        assert_eq!(
            eval.states()["consumer.js"].phase,
            AsyncModulePhase::Rejected
        );
    }

    #[test]
    fn evaluator_suspend_on_dependency_keeps_declared_graph_static() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("provider.js", false, &[], None);
        eval.register_module("consumer.js", true, &[], Some(PromiseHandle(1)));

        eval.suspend_on_dependency("consumer.js", "provider.js", PromiseHandle(2))
            .unwrap();

        assert!(
            eval.declared_dependencies["consumer.js"].is_empty(),
            "runtime suspension bookkeeping must not rewrite the static import graph"
        );

        let mut bindings = empty_live_bindings();
        let linkage = eval
            .reject_module("provider.js", &js_error("fail"), &mut bindings)
            .unwrap();

        assert!(
            linkage
                .linked_modules
                .iter()
                .all(|module| module.module_specifier != "consumer.js")
        );
        assert!(!linkage.transitive_closure.contains("consumer.js"));
        assert_eq!(
            eval.states()["consumer.js"].phase,
            AsyncModulePhase::AwaitingDependencies
        );
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
            rejection_reason_description: Some("Error: oops".into()),
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

    // -----------------------------------------------------------------------
    // Additional tests (edge cases, Display, Hash, serde, error paths, etc.)
    // -----------------------------------------------------------------------

    // -- AsyncModulePhase Display --

    #[test]
    fn phase_display_matches_as_str() {
        for p in AsyncModulePhase::ALL {
            assert_eq!(p.to_string(), p.as_str());
        }
    }

    #[test]
    fn phase_ordering_is_defined() {
        // Enum derives Ord; verify the ordering is consistent with variant declaration order.
        assert!(AsyncModulePhase::Synchronous < AsyncModulePhase::Suspended);
        assert!(AsyncModulePhase::Suspended < AsyncModulePhase::AwaitingDependencies);
        assert!(AsyncModulePhase::AwaitingDependencies < AsyncModulePhase::Settled);
        assert!(AsyncModulePhase::Settled < AsyncModulePhase::Rejected);
    }

    #[test]
    fn phase_clone_eq() {
        let p = AsyncModulePhase::Settled;
        let p2 = p;
        assert_eq!(p, p2);
    }

    // -- LinkageKind Display --

    #[test]
    fn linkage_kind_display_matches_as_str() {
        for k in LinkageKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn linkage_kind_ordering_is_defined() {
        assert!(LinkageKind::DirectImport < LinkageKind::ReExport);
        assert!(LinkageKind::ReExport < LinkageKind::NamespaceImport);
        assert!(LinkageKind::NamespaceImport < LinkageKind::DefaultImport);
    }

    // -- AsyncEvalEventType --

    #[test]
    fn event_type_as_str_all_distinct() {
        let strs: BTreeSet<&str> = AsyncEvalEventType::ALL.iter().map(|e| e.as_str()).collect();
        assert_eq!(strs.len(), AsyncEvalEventType::ALL.len());
    }

    #[test]
    fn event_type_ordering() {
        assert!(AsyncEvalEventType::EvaluationStarted < AsyncEvalEventType::EvaluationRejected);
        assert!(AsyncEvalEventType::BindingMarkedDead < AsyncEvalEventType::RejectionPropagated);
    }

    // -- AsyncEvalError Display coverage --

    #[test]
    fn error_display_invalid_phase_transition() {
        let err = AsyncEvalError::InvalidPhaseTransition {
            specifier: "mod.js".into(),
            from: AsyncModulePhase::Synchronous,
            to: AsyncModulePhase::Rejected,
        };
        let msg = err.to_string();
        assert!(msg.contains("mod.js"));
        assert!(msg.contains("synchronous"));
        assert!(msg.contains("rejected"));
    }

    #[test]
    fn error_display_cycle_detected() {
        let err = AsyncEvalError::CycleDetected {
            modules: vec!["a.js".into(), "b.js".into(), "c.js".into()],
        };
        let msg = err.to_string();
        assert!(msg.contains("a.js -> b.js -> c.js"));
    }

    #[test]
    fn error_display_suspension_limit_exceeded() {
        let err = AsyncEvalError::SuspensionLimitExceeded {
            specifier: "heavy.js".into(),
            limit: 42,
        };
        let msg = err.to_string();
        assert!(msg.contains("heavy.js"));
        assert!(msg.contains("42"));
    }

    #[test]
    fn error_display_rejection_propagation_failed() {
        let err = AsyncEvalError::RejectionPropagationFailed {
            specifier: "src.js".into(),
            detail: "network timeout".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("src.js"));
        assert!(msg.contains("network timeout"));
    }

    #[test]
    fn error_implements_std_error() {
        let err = AsyncEvalError::ModuleNotFound {
            specifier: "x.js".into(),
        };
        // std::error::Error is implemented; verify source() returns None (no chained cause).
        let as_error: &dyn std::error::Error = &err;
        assert!(as_error.source().is_none());
    }

    #[test]
    fn error_serde_roundtrip_all_variants() {
        let variants: Vec<AsyncEvalError> = vec![
            AsyncEvalError::ModuleNotFound {
                specifier: "a.js".into(),
            },
            AsyncEvalError::InvalidPhaseTransition {
                specifier: "b.js".into(),
                from: AsyncModulePhase::Suspended,
                to: AsyncModulePhase::Synchronous,
            },
            AsyncEvalError::CycleDetected {
                modules: vec!["c.js".into(), "d.js".into()],
            },
            AsyncEvalError::SuspensionLimitExceeded {
                specifier: "e.js".into(),
                limit: 100,
            },
            AsyncEvalError::RejectionPropagationFailed {
                specifier: "f.js".into(),
                detail: "internal".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: AsyncEvalError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -- SuspensionRecord edge cases --

    #[test]
    fn suspension_record_resolve_twice_overwrites() {
        let mut sr = SuspensionRecord::new(
            "mod.js".into(),
            0,
            PromiseHandle(5),
            SuspensionContext::TopLevelAwait,
        );
        sr.resolve(10);
        assert_eq!(sr.resume_seq, 10);
        sr.resolve(20);
        assert_eq!(sr.resume_seq, 20);
        assert!(sr.resolved);
    }

    #[test]
    fn suspension_record_awaiting_dependency_context() {
        let sr = SuspensionRecord::new(
            "consumer.js".into(),
            3,
            PromiseHandle(7),
            SuspensionContext::AwaitingDependency {
                module_specifier: "dep.js".into(),
            },
        );
        assert_eq!(sr.suspension_seq, 3);
        assert!(matches!(
            sr.context,
            SuspensionContext::AwaitingDependency { ref module_specifier } if module_specifier == "dep.js"
        ));
    }

    #[test]
    fn suspension_record_awaiting_binding_context() {
        let bid = BindingId::new("m.js", "count");
        let sr = SuspensionRecord::new(
            "m.js".into(),
            0,
            PromiseHandle(1),
            SuspensionContext::AwaitingBinding {
                binding_id: bid.clone(),
            },
        );
        assert!(matches!(
            sr.context,
            SuspensionContext::AwaitingBinding { ref binding_id } if binding_id == &bid
        ));
    }

    // -- AsyncModuleState edge cases --

    #[test]
    fn state_next_seq_increments() {
        let mut s = AsyncModuleState::synchronous("s.js".into());
        assert_eq!(s.event_seq, 0);
        s.record_suspension(PromiseHandle(1), SuspensionContext::TopLevelAwait);
        assert_eq!(s.event_seq, 1);
        s.record_suspension(PromiseHandle(2), SuspensionContext::TopLevelAwait);
        assert_eq!(s.event_seq, 2);
    }

    #[test]
    fn state_record_resumption_no_suspensions_is_noop() {
        let mut s = AsyncModuleState::async_pending("r.js".into(), PromiseHandle(1));
        // record_resumption with no suspensions should not panic.
        s.record_resumption();
        assert!(s.suspensions.is_empty());
    }

    #[test]
    fn state_record_resumption_already_resolved_is_noop() {
        let mut s = AsyncModuleState::async_pending("r.js".into(), PromiseHandle(1));
        s.record_suspension(PromiseHandle(2), SuspensionContext::TopLevelAwait);
        s.record_resumption();
        assert!(s.suspensions[0].resolved);
        let old_seq = s.suspensions[0].resume_seq;
        // A second resumption should not modify the already-resolved record.
        s.record_resumption();
        assert_eq!(s.suspensions[0].resume_seq, old_seq);
    }

    #[test]
    fn state_add_pending_dependency_transitions_to_awaiting() {
        let mut s = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
        assert_eq!(s.phase, AsyncModulePhase::Suspended);
        s.add_pending_dependency("dep.js".into());
        assert_eq!(s.phase, AsyncModulePhase::AwaitingDependencies);
    }

    #[test]
    fn state_add_pending_dependency_when_not_suspended_preserves_phase() {
        let mut s = AsyncModuleState::synchronous("m.js".into());
        assert_eq!(s.phase, AsyncModulePhase::Synchronous);
        s.add_pending_dependency("dep.js".into());
        // Phase transition only happens from Suspended -> AwaitingDependencies.
        assert_eq!(s.phase, AsyncModulePhase::Synchronous);
        assert!(!s.all_dependencies_settled());
    }

    #[test]
    fn state_resolve_nonexistent_dependency_is_noop() {
        let mut s = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
        s.add_pending_dependency("real.js".into());
        s.resolve_dependency("nonexistent.js");
        assert!(!s.all_dependencies_settled());
    }

    #[test]
    fn state_settle_clears_pending_dependencies() {
        let mut s = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(1));
        s.add_pending_dependency("a.js".into());
        s.add_pending_dependency("b.js".into());
        assert!(!s.all_dependencies_settled());
        s.settle();
        assert!(s.all_dependencies_settled());
        assert_eq!(s.phase, AsyncModulePhase::Settled);
    }

    #[test]
    fn state_serde_roundtrip_async_with_suspensions() {
        let mut s = AsyncModuleState::async_pending("m.js".into(), PromiseHandle(42));
        s.record_suspension(PromiseHandle(100), SuspensionContext::TopLevelAwait);
        s.record_resumption();
        s.add_pending_dependency("dep.js".into());
        let json = serde_json::to_string(&s).unwrap();
        let back: AsyncModuleState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -- Evaluator: module_not_found on various operations --

    #[test]
    fn evaluator_suspend_on_dependency_module_not_found() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        let err = eval
            .suspend_on_dependency("ghost.js", "dep.js", PromiseHandle(1))
            .unwrap_err();
        assert!(
            matches!(err, AsyncEvalError::ModuleNotFound { ref specifier } if specifier == "ghost.js")
        );
        assert!(!eval.declared_dependencies.contains_key("ghost.js"));
    }

    #[test]
    fn evaluator_resume_evaluation_module_not_found() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        let err = eval.resume_evaluation("ghost.js").unwrap_err();
        assert!(
            matches!(err, AsyncEvalError::ModuleNotFound { ref specifier } if specifier == "ghost.js")
        );
    }

    #[test]
    fn evaluator_settle_module_not_found() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        let err = eval.settle_module("ghost.js").unwrap_err();
        assert!(
            matches!(err, AsyncEvalError::ModuleNotFound { ref specifier } if specifier == "ghost.js")
        );
    }

    #[test]
    fn evaluator_reject_module_not_found() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        let mut bindings = empty_live_bindings();
        let err = eval
            .reject_module("ghost.js", &js_error("err"), &mut bindings)
            .unwrap_err();
        assert!(
            matches!(err, AsyncEvalError::ModuleNotFound { ref specifier } if specifier == "ghost.js")
        );
    }

    // -- Evaluator: complex graph scenarios --

    #[test]
    fn evaluator_diamond_dependency_graph() {
        // A -> B, A -> C, B -> D, C -> D (D is the leaf)
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("d.js", true, &[], Some(PromiseHandle(1)));
        eval.register_module("b.js", true, &["d.js".into()], Some(PromiseHandle(2)));
        eval.register_module("c.js", true, &["d.js".into()], Some(PromiseHandle(3)));
        eval.register_module(
            "a.js",
            true,
            &["b.js".into(), "c.js".into()],
            Some(PromiseHandle(4)),
        );

        // d.js settles -> b.js and c.js should become resumable
        let resumable = eval.settle_module("d.js").unwrap();
        assert!(resumable.contains(&"b.js".to_string()));
        assert!(resumable.contains(&"c.js".to_string()));
        // a.js is still waiting on b.js and c.js
        assert!(!resumable.contains(&"a.js".to_string()));

        // Settle b.js
        let resumable2 = eval.settle_module("b.js").unwrap();
        // a.js still waiting on c.js
        assert!(!resumable2.contains(&"a.js".to_string()));

        // Settle c.js -> a.js should become resumable
        let resumable3 = eval.settle_module("c.js").unwrap();
        assert!(resumable3.contains(&"a.js".to_string()));
    }

    #[test]
    fn evaluator_rejection_transitive_cascade() {
        // chain: root -> mid -> leaf
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("root.js", true, &[], Some(PromiseHandle(1)));
        eval.register_module("mid.js", true, &["root.js".into()], Some(PromiseHandle(2)));
        eval.suspend_on_dependency("mid.js", "root.js", PromiseHandle(1))
            .unwrap();
        eval.register_module("leaf.js", true, &["mid.js".into()], Some(PromiseHandle(3)));
        eval.suspend_on_dependency("leaf.js", "mid.js", PromiseHandle(2))
            .unwrap();

        let mut bindings = empty_live_bindings();
        let linkage = eval
            .reject_module("root.js", &js_error("cascade"), &mut bindings)
            .unwrap();

        // mid.js depends on root.js, leaf.js depends on mid.js
        assert!(linkage.transitive_closure.contains("mid.js"));
        assert!(linkage.transitive_closure.contains("leaf.js"));
        assert_eq!(eval.states()["mid.js"].phase, AsyncModulePhase::Rejected);
        assert_eq!(eval.states()["leaf.js"].phase, AsyncModulePhase::Rejected);
    }

    #[test]
    fn evaluator_transitive_rejection_uses_declared_dependency_graph() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("root.js", false, &[], None);
        eval.register_module("mid.js", true, &["root.js".into()], Some(PromiseHandle(1)));
        eval.register_module("leaf.js", true, &["mid.js".into()], Some(PromiseHandle(2)));
        eval.suspend_on_dependency("leaf.js", "mid.js", PromiseHandle(1))
            .unwrap();

        let mut bindings = empty_live_bindings();
        let linkage = eval
            .reject_module("root.js", &js_error("cascade"), &mut bindings)
            .unwrap();

        assert!(linkage.transitive_closure.contains("mid.js"));
        assert!(linkage.transitive_closure.contains("leaf.js"));
        assert_eq!(eval.states()["mid.js"].phase, AsyncModulePhase::Rejected);
        assert_eq!(eval.states()["leaf.js"].phase, AsyncModulePhase::Rejected);
    }

    #[test]
    fn evaluator_rejection_no_transitive_when_disabled() {
        let config = AsyncEvalConfig {
            transitive_rejection_propagation: false,
            ..Default::default()
        };
        let mut eval = AsyncModuleEvaluator::new(config);
        eval.register_module("root.js", true, &[], Some(PromiseHandle(1)));
        eval.register_module("mid.js", true, &["root.js".into()], Some(PromiseHandle(2)));
        eval.suspend_on_dependency("mid.js", "root.js", PromiseHandle(1))
            .unwrap();
        eval.register_module("leaf.js", true, &["mid.js".into()], Some(PromiseHandle(3)));
        eval.suspend_on_dependency("leaf.js", "mid.js", PromiseHandle(2))
            .unwrap();

        let mut bindings = empty_live_bindings();
        let linkage = eval
            .reject_module("root.js", &js_error("no-cascade"), &mut bindings)
            .unwrap();

        // Without transitive propagation, only direct dependents are in the closure.
        assert!(linkage.transitive_closure.contains("mid.js"));
        // leaf.js is NOT a direct dependent of root.js.
        assert!(!linkage.transitive_closure.contains("leaf.js"));
    }

    #[test]
    fn evaluator_multiple_suspensions_tracked() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
        eval.suspend_at_top_level_await("m.js", PromiseHandle(10))
            .unwrap();
        eval.resume_evaluation("m.js").unwrap();
        eval.suspend_at_top_level_await("m.js", PromiseHandle(11))
            .unwrap();
        eval.resume_evaluation("m.js").unwrap();
        eval.suspend_at_top_level_await("m.js", PromiseHandle(12))
            .unwrap();

        let state = &eval.states()["m.js"];
        assert_eq!(state.suspensions.len(), 3);
        assert!(state.suspensions[0].resolved);
        assert!(state.suspensions[1].resolved);
        assert!(!state.suspensions[2].resolved);
    }

    #[test]
    fn evaluator_register_module_with_rejected_dependency_tracks_pending() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("dep.js", true, &[], Some(PromiseHandle(1)));
        let mut bindings = empty_live_bindings();
        eval.reject_module("dep.js", &js_error("fail"), &mut bindings)
            .unwrap();

        // Now register a consumer that depends on the rejected module.
        eval.register_module("consumer.js", false, &["dep.js".into()], None);
        // rejected module has is_terminal() == true AND phase == Rejected,
        // so dep.js should be added as pending.
        assert!(
            eval.states()["consumer.js"]
                .pending_dependencies
                .contains("dep.js")
        );
    }

    #[test]
    fn evaluator_notify_dependency_settled_unknown_module_returns_empty() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
        let resumable = eval.notify_dependency_settled("unknown.js").unwrap();
        assert!(resumable.is_empty());
    }

    #[test]
    fn evaluator_reject_marks_multiple_bindings_dead() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("lib.js", true, &[], Some(PromiseHandle(1)));

        let mut bindings = empty_live_bindings();
        let id1 = bindings.register_cell(BindingCell::new(
            "lib.js",
            "alpha",
            "alpha",
            BindingType::Direct,
        ));
        let id2 = bindings.register_cell(BindingCell::new(
            "lib.js",
            "beta",
            "beta",
            BindingType::Direct,
        ));
        // Register a binding from a different module — should NOT be marked dead.
        let id_other = bindings.register_cell(BindingCell::new(
            "other.js",
            "gamma",
            "gamma",
            BindingType::Direct,
        ));

        let linkage = eval
            .reject_module("lib.js", &js_error("err"), &mut bindings)
            .unwrap();

        assert!(linkage.dead_bindings.contains(&id1));
        assert!(linkage.dead_bindings.contains(&id2));
        assert!(!linkage.dead_bindings.contains(&id_other));
        assert_eq!(
            bindings.get_cell(&id1).unwrap().state,
            BindingCellState::Dead
        );
        assert_eq!(
            bindings.get_cell(&id2).unwrap().state,
            BindingCellState::Dead
        );
        assert_ne!(
            bindings.get_cell(&id_other).unwrap().state,
            BindingCellState::Dead
        );
    }

    #[test]
    fn evaluator_reject_already_dead_binding_not_double_counted() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("lib.js", true, &[], Some(PromiseHandle(1)));

        let mut bindings = empty_live_bindings();
        let id = bindings.register_cell(BindingCell::new(
            "lib.js",
            "val",
            "val",
            BindingType::Direct,
        ));
        // Pre-mark the binding as dead.
        bindings.mark_dead(&id).unwrap();

        let linkage = eval
            .reject_module("lib.js", &js_error("err"), &mut bindings)
            .unwrap();
        // Already-dead binding should not appear in dead_bindings.
        assert!(linkage.dead_bindings.is_empty());
    }

    // -- Finalize hash determinism --

    #[test]
    fn finalize_hash_deterministic_same_input() {
        let build = || {
            let mut eval = AsyncModuleEvaluator::with_defaults();
            eval.register_module("a.js", false, &[], None);
            eval.register_module("b.js", true, &[], Some(PromiseHandle(1)));
            eval.settle_module("b.js").unwrap();
            eval.finalize()
        };
        let r1 = build();
        let r2 = build();
        assert_eq!(r1.result_hash, r2.result_hash);
    }

    #[test]
    fn finalize_hash_different_for_different_inputs() {
        let mut eval1 = AsyncModuleEvaluator::with_defaults();
        eval1.register_module("a.js", false, &[], None);
        let r1 = eval1.finalize();

        let mut eval2 = AsyncModuleEvaluator::with_defaults();
        eval2.register_module("a.js", false, &[], None);
        eval2.register_module("b.js", false, &[], None);
        let r2 = eval2.finalize();

        assert_ne!(r1.result_hash, r2.result_hash);
    }

    // -- Topological ordering edge cases --

    #[test]
    fn topological_order_single_module() {
        let modules = vec!["only.js".into()];
        let deps = BTreeMap::new();
        let order = compute_async_evaluation_order(&modules, &deps).unwrap();
        assert_eq!(order, vec!["only.js".to_string()]);
    }

    #[test]
    fn topological_order_diamond() {
        // d depends on b and c, b depends on a, c depends on a
        let modules: Vec<String> = vec!["a.js".into(), "b.js".into(), "c.js".into(), "d.js".into()];
        let mut deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
        deps.insert("b.js".into(), vec!["a.js".into()]);
        deps.insert("c.js".into(), vec!["a.js".into()]);
        deps.insert("d.js".into(), vec!["b.js".into(), "c.js".into()]);
        let order = compute_async_evaluation_order(&modules, &deps).unwrap();
        let pos = |name: &str| order.iter().position(|s| s == name).unwrap();
        assert!(pos("a.js") < pos("b.js"));
        assert!(pos("a.js") < pos("c.js"));
        assert!(pos("b.js") < pos("d.js"));
        assert!(pos("c.js") < pos("d.js"));
    }

    #[test]
    fn topological_order_deterministic_across_runs() {
        let modules: Vec<String> = vec!["z.js".into(), "y.js".into(), "x.js".into(), "w.js".into()];
        let deps = BTreeMap::new();
        let order1 = compute_async_evaluation_order(&modules, &deps).unwrap();
        let order2 = compute_async_evaluation_order(&modules, &deps).unwrap();
        assert_eq!(order1, order2);
    }

    #[test]
    fn topological_order_external_dep_ignored() {
        // If a dependency is not in the module_specifiers list, it should be ignored.
        let modules = vec!["a.js".into(), "b.js".into()];
        let mut deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
        deps.insert("b.js".into(), vec!["external.js".into()]);
        let order = compute_async_evaluation_order(&modules, &deps).unwrap();
        assert_eq!(order.len(), 2);
    }

    #[test]
    fn topological_order_three_way_cycle() {
        let modules = vec!["a.js".into(), "b.js".into(), "c.js".into()];
        let mut deps: BTreeMap<String, Vec<String>> = BTreeMap::new();
        deps.insert("a.js".into(), vec!["b.js".into()]);
        deps.insert("b.js".into(), vec!["c.js".into()]);
        deps.insert("c.js".into(), vec!["a.js".into()]);
        let err = compute_async_evaluation_order(&modules, &deps).unwrap_err();
        if let AsyncEvalError::CycleDetected { modules } = &err {
            assert_eq!(modules.len(), 3);
        } else {
            panic!("expected CycleDetected");
        }
    }

    #[test]
    fn topological_order_empty_input() {
        let modules: Vec<String> = vec![];
        let deps = BTreeMap::new();
        let order = compute_async_evaluation_order(&modules, &deps).unwrap();
        assert!(order.is_empty());
    }

    // -- Evaluator: witness events content --

    #[test]
    fn witness_events_contain_correct_event_types() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("m.js", true, &[], Some(PromiseHandle(1)));
        eval.suspend_at_top_level_await("m.js", PromiseHandle(2))
            .unwrap();
        eval.resume_evaluation("m.js").unwrap();
        eval.settle_module("m.js").unwrap();

        let events = eval.witness_events();
        let types: Vec<AsyncEvalEventType> = events.iter().map(|e| e.event_type).collect();
        assert!(types.contains(&AsyncEvalEventType::EvaluationStarted));
        assert!(types.contains(&AsyncEvalEventType::TopLevelAwaitSuspended));
        assert!(types.contains(&AsyncEvalEventType::EvaluationResumed));
        assert!(types.contains(&AsyncEvalEventType::EvaluationSettled));
    }

    #[test]
    fn witness_events_seq_monotonically_increasing() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("a.js", true, &[], Some(PromiseHandle(1)));
        eval.register_module("b.js", true, &[], Some(PromiseHandle(2)));
        eval.suspend_at_top_level_await("a.js", PromiseHandle(10))
            .unwrap();
        eval.resume_evaluation("a.js").unwrap();
        eval.settle_module("a.js").unwrap();
        eval.settle_module("b.js").unwrap();

        let events = eval.witness_events();
        for window in events.windows(2) {
            assert!(
                window[0].seq < window[1].seq,
                "seq {} should be < {}",
                window[0].seq,
                window[1].seq
            );
        }
    }

    // -- AsyncEvalConfig serde --

    #[test]
    fn config_serde_roundtrip() {
        let cfg = AsyncEvalConfig {
            max_suspensions_per_module: 10,
            max_total_suspensions: 50,
            transitive_rejection_propagation: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: AsyncEvalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // -- LinkedModule serde --

    #[test]
    fn linked_module_serde_roundtrip_with_bindings() {
        let lm = LinkedModule {
            module_specifier: "consumer.js".into(),
            import_bindings: vec![
                BindingId::new("lib.js", "foo"),
                BindingId::new("lib.js", "bar"),
            ],
            linkage_kind: LinkageKind::NamespaceImport,
        };
        let json = serde_json::to_string(&lm).unwrap();
        let back: LinkedModule = serde_json::from_str(&json).unwrap();
        assert_eq!(lm, back);
    }

    // -- AsyncEvalWitnessEvent serde --

    #[test]
    fn witness_event_serde_roundtrip() {
        let ev = AsyncEvalWitnessEvent {
            module_specifier: "test.js".into(),
            event_type: AsyncEvalEventType::BindingMarkedDead,
            seq: 42,
            detail: "binding=m.js:x".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: AsyncEvalWitnessEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    // -- Evaluator: full lifecycle --

    #[test]
    fn evaluator_full_lifecycle_suspend_depend_settle() {
        let mut eval = AsyncModuleEvaluator::with_defaults();

        // Register a dep and a consumer with TLA.
        eval.register_module("dep.js", true, &[], Some(PromiseHandle(1)));
        eval.register_module("app.js", true, &["dep.js".into()], Some(PromiseHandle(2)));

        // app.js suspends on TLA, then suspends on dep.js
        eval.suspend_at_top_level_await("app.js", PromiseHandle(10))
            .unwrap();
        eval.suspend_on_dependency("app.js", "dep.js", PromiseHandle(1))
            .unwrap();

        // dep.js settles
        eval.settle_module("dep.js").unwrap();

        // app.js should now be resumable
        assert!(eval.states()["app.js"].all_dependencies_settled());

        eval.resume_evaluation("app.js").unwrap();
        eval.settle_module("app.js").unwrap();

        let result = eval.finalize();
        assert!(result.all_settled);
        assert_eq!(result.settled_count(), 2);
        assert_eq!(result.rejected_count(), 0);
        assert!(result.total_suspensions >= 2);
    }

    // -- Evaluator: register_module with sync dep does not add pending --

    #[test]
    fn evaluator_register_with_settled_dep_no_pending() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("dep.js", true, &[], Some(PromiseHandle(1)));
        eval.settle_module("dep.js").unwrap();

        // Now register consumer — dep.js is Settled (terminal, not Rejected)
        // so it should NOT be added as pending.
        eval.register_module("app.js", false, &["dep.js".into()], None);
        assert!(eval.states()["app.js"].all_dependencies_settled());
    }

    #[test]
    fn evaluator_register_with_sync_dep_no_pending() {
        let mut eval = AsyncModuleEvaluator::with_defaults();
        eval.register_module("dep.js", false, &[], None);

        // Synchronous dep is terminal and not Rejected — not added as pending.
        eval.register_module("app.js", false, &["dep.js".into()], None);
        assert!(eval.states()["app.js"].all_dependencies_settled());
    }
}
