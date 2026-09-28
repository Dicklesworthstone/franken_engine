//! Reclaiming collector for the baseline interpreter heap (bd-9vouw.57).
//!
//! Before this collector every allocation was permanent. A program died at its
//! 100,001st object however small its live set was:
//! `for (...) { const o = { a: i } }` failed with "memory budget exceeded".
//!
//! Design:
//! - Precise, stop-the-world mark from an enumerated root set, then a sweep
//!   that empties the slot of every unmarked object (`Heap::reclaim`).
//! - Slot ids are never reused. A missed root therefore surfaces as a missing
//!   object, never as another object's identity.
//! - Collection runs only at a safe point, where every live value sits in
//!   interpreter state. The first safe point is the top of the dispatch loop
//!   of the top-level script's own run loop.
//! - The second safe point is between event-loop jobs (turns, microtasks,
//!   nextTick callbacks) after the script, while no run loop is active. The
//!   script's completion value, held by the caller across that phase, is
//!   pinned.
//! - Nested run loops (callbacks, generator bodies, isolated calls) hold
//!   caller state in Rust locals, so no collection runs while one is active.
//!   A single callback that allocates past the budget still fails.
//! - Collection is also skipped while host I/O subsystems (streams, sockets,
//!   http, child processes, URL/crypto objects) hold state. The allocation
//!   budget then fails exactly as before.
//! - Triggers are deterministic: live-object and live-byte thresholds derived
//!   from the configured budgets, so replay reproduces every collection.
//! - `roots` destructures `InterpreterCore` exhaustively. Adding a field does
//!   not compile until the field is registered here as a root, a weak table,
//!   or non-referencing state.
//!
//! Closures are traced from the values that reference them: an unreachable
//! closure's captured environment is released and its function index is
//! poisoned (`ClosureTable::reclaim`); its id is never reused. Generators,
//! iterators, async objects and promises live in their own tables and are not
//! reclaimed yet, so they are roots. WeakMap entries are ephemerons: a value is
//! kept only while its key is reachable.

use std::collections::HashSet;

use super::*;
use crate::object_model::JsValue;

/// Collection totals over one interpreter's lifetime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcStats {
    /// Completed collections.
    pub collections: u64,
    /// Safe points where a collection was due but host state blocked it.
    pub skipped_collections: u64,
    /// Objects reclaimed over all collections.
    pub reclaimed_objects: u64,
    /// Estimated bytes released over all collections.
    pub reclaimed_bytes: u64,
    /// Closures whose captured environments were released.
    pub reclaimed_closures: u64,
}

/// Collector state carried by `InterpreterCore`.
#[derive(Debug, Clone, Default)]
pub(super) struct GcState {
    /// Nesting depth of `run_loop_labeled_with_trampoline`.
    run_loop_depth: u32,
    /// The run-loop depth whose dispatch loop may collect: the top-level
    /// script's own loop. `None` outside top-level execution.
    safe_depth: Option<u32>,
    /// Collect when the live object count reaches this.
    trigger_objects: usize,
    /// Collect when the estimated live bytes reach this.
    trigger_bytes: u64,
    /// Diagnostic stress mode: collect at every `n`th due safe point.
    stress_interval: Option<u64>,
    stress_safe_points: u64,
    stats: GcStats,
    /// Set while a top-level CommonJS entry is being evaluated, until
    /// `evaluate_cjs_ir3` arms its run loop.
    cjs_entry_pending: bool,
    /// Objects referenced by state that a Rust caller holds across the armed
    /// run loop (the CommonJS entry's saved caller execution). Roots.
    pinned: Vec<ObjectId>,
    /// Set while the event loop runs after the top-level script: collection
    /// may run between jobs whenever no run loop is active.
    event_loop_armed: bool,
    /// Values a Rust caller holds across the event-loop phase (the script's
    /// completion value). Roots.
    pinned_values: Vec<Value>,
    /// Planted negative for the root-coverage tests: skip the registers,
    /// call frames, scope chain and realm globals.
    #[cfg(test)]
    drop_execution_roots: bool,
}

/// Why a due collection did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GcSkip {
    /// Host I/O state (streams, sockets, http, ...) is live and not traced.
    HostState,
}

/// Mark state for one collection.
struct GcMarker {
    marked: Vec<bool>,
    stack: Vec<u32>,
    closures_marked: Vec<bool>,
    closure_stack: Vec<u32>,
    visited_frames: HashSet<usize>,
    visited_cells: HashSet<usize>,
}

impl GcMarker {
    fn new(heap_len: usize, closures_len: usize) -> Self {
        Self {
            marked: vec![false; heap_len],
            stack: Vec::new(),
            closures_marked: vec![false; closures_len],
            closure_stack: Vec::new(),
            visited_frames: HashSet::new(),
            visited_cells: HashSet::new(),
        }
    }

    /// Closure-table ids: `Value::Closure` and the generator/async function
    /// values index the closure table.
    fn closure(&mut self, id: u32) {
        if let Some(mark) = self.closures_marked.get_mut(id as usize)
            && !*mark
        {
            *mark = true;
            self.closure_stack.push(id);
        }
    }

    /// A promise/timer handler handle: a closure id, or (at or above
    /// `PROMISE_REACTION_CALLABLE_BASE`) a key of
    /// `promise_reaction_callables`, which is traced as a root.
    fn handler(&mut self, handle: crate::closure_model::ClosureHandle) {
        if handle.0 < PROMISE_REACTION_CALLABLE_BASE {
            self.closure(handle.0);
        }
    }

    fn is_marked(&self, id: u32) -> bool {
        self.marked.get(id as usize).copied().unwrap_or(false)
    }

    fn object(&mut self, id: ObjectId) {
        if let Some(mark) = self.marked.get_mut(id.0 as usize)
            && !*mark
        {
            *mark = true;
            self.stack.push(id.0);
        }
    }

    fn value(&mut self, value: &Value) {
        match value {
            Value::Object(id) => self.object(*id),
            Value::BuiltinFunction(builtin) => {
                if let Some(bound) = builtin.bound_object {
                    self.object(ObjectId(bound));
                }
            }
            Value::Accessor { get, set } => {
                if let Some(get) = get {
                    self.value(get);
                }
                if let Some(set) = set {
                    self.value(set);
                }
            }
            Value::Closure(id)
            | Value::GeneratorFunction(id)
            | Value::AsyncFunction(id)
            | Value::AsyncGeneratorFunction(id) => self.closure(*id),
            // Generators, iterators, async objects and promises index tables
            // whose entries are all roots.
            Value::Undefined
            | Value::Null
            | Value::Bool(_)
            | Value::Int(_)
            | Value::BigInt(_)
            | Value::Float(_)
            | Value::Str(_)
            | Value::Function(_)
            | Value::Iterator(_)
            | Value::Generator(_)
            | Value::AsyncFunctionObject(_)
            | Value::AsyncGeneratorObject(_)
            | Value::Promise(_)
            | Value::Symbol(_) => {}
        }
    }

    fn js_value(&mut self, value: &JsValue) {
        if let JsValue::Object(handle) = value {
            self.object(ObjectId(handle.0));
        }
    }

    fn labeled_return(&mut self, completion: &LabeledReturn) {
        self.value(&completion.value);
    }

    fn abrupt(&mut self, completion: &AbruptCompletion) {
        match completion {
            AbruptCompletion::Exception(value, _) => self.value(value),
            AbruptCompletion::Return(completion) => self.labeled_return(completion),
        }
    }

    fn cell(&mut self, cell: &Rc<RefCell<ScopeBindingState>>) {
        if self.visited_cells.insert(Rc::as_ptr(cell) as usize) {
            let state = cell.borrow();
            self.value(&state.value);
        }
    }

    fn binding(&mut self, binding: &ScopeBinding) {
        self.cell(&binding.state);
    }

    fn scope_frame(&mut self, frame: &ScopeFrame) {
        if self
            .visited_frames
            .insert(Rc::as_ptr(&frame.bindings) as usize)
        {
            for binding in frame.bindings.values() {
                self.binding(binding);
            }
        }
    }

    fn scope_frames(&mut self, frames: &[ScopeFrame]) {
        for frame in frames {
            self.scope_frame(frame);
        }
    }

    fn call_frame(&mut self, frame: &CallFrame) {
        let CallFrame {
            return_ip: _,
            return_reg: _,
            register_base: _,
            function_index: _,
            this_value,
            this_label: _,
            new_target_value,
            new_target_label: _,
            super_value,
            super_label: _,
            super_home_object,
            construct_this,
            derived_constructor: _,
            this_initialized: _,
            initialize_derived_this_on_return: _,
            saved_pending_exception,
            saved_pending_exception_label: _,
            saved_pending_return,
            saved_suspended_abrupt_depth: _,
            saved_finally_mode_depth: _,
            saved_scope_depth: _,
            saved_scope_chain,
            scope_inert_virtual_scope_bytes: _,
            async_function_id: _,
            native_boundary: _,
        } = frame;
        self.value(this_value);
        self.value(new_target_value);
        self.value(super_value);
        if let Some(home) = super_home_object {
            self.object(*home);
        }
        if let Some(value) = construct_this {
            self.value(value);
        }
        if let Some(value) = saved_pending_exception {
            self.value(value);
        }
        if let Some(completion) = saved_pending_return {
            self.labeled_return(completion);
        }
        if let Some(frames) = saved_scope_chain {
            self.scope_frames(frames);
        }
    }

    fn finally_frame(&mut self, frame: &FinallyFrame) {
        if let Some(completion) = &frame.completion {
            self.abrupt(completion);
        }
    }

    fn generator_execution(&mut self, execution: &GeneratorExecutionSnapshot) {
        let GeneratorExecutionSnapshot {
            registers,
            register_labels: _,
            delegation: _,
            active_inline_callback_context_label: _,
            call_stack,
            ip: _,
            register_base: _,
            catch_frames: _,
            pending_exception,
            pending_exception_label: _,
            pending_hostcall_result_label: _,
            pending_return,
            suspended_abrupt_completions,
            finally_frames,
            pending_finally_entry: _,
            scope_chain,
            pending_captures: _,
            current_module_specifier: _,
            active_generated_function_artifact: _,
            contained_codegen_grant: _,
        } = execution;
        registers.iter().for_each(|value| self.value(value));
        call_stack.iter().for_each(|frame| self.call_frame(frame));
        if let Some(value) = pending_exception {
            self.value(value);
        }
        if let Some(completion) = pending_return {
            self.labeled_return(completion);
        }
        suspended_abrupt_completions
            .iter()
            .for_each(|completion| self.abrupt(completion));
        finally_frames
            .iter()
            .for_each(|frame| self.finally_frame(frame));
        self.scope_frames(&scope_chain.frames);
    }

    fn module_execution(&mut self, execution: &ModuleExecutionSnapshot) {
        let ModuleExecutionSnapshot {
            accounted_bytes: _,
            registers,
            generator_delegation: _,
            register_labels: _,
            active_inline_callback_context_label: _,
            call_stack,
            ip: _,
            register_base: _,
            catch_frames: _,
            pending_exception,
            pending_exception_label: _,
            pending_hostcall_result_label: _,
            pending_return,
            suspended_abrupt_completions,
            finally_frames,
            pending_finally_entry: _,
            scope_chain,
            pending_captures: _,
            current_module_specifier: _,
            active_generated_function_artifact: _,
        } = execution;
        registers.iter().for_each(|value| self.value(value));
        call_stack.iter().for_each(|frame| self.call_frame(frame));
        if let Some(value) = pending_exception {
            self.value(value);
        }
        if let Some(completion) = pending_return {
            self.labeled_return(completion);
        }
        suspended_abrupt_completions
            .iter()
            .for_each(|completion| self.abrupt(completion));
        finally_frames
            .iter()
            .for_each(|frame| self.finally_frame(frame));
        self.scope_frames(&scope_chain.frames);
    }

    fn iterator(&mut self, iterator: &RuntimeIteratorState) {
        match iterator {
            RuntimeIteratorState::ForIn(state) => self.object(state.object_id),
            RuntimeIteratorState::ForOf(state) => {
                let RuntimeForOfState {
                    values,
                    next_index: _,
                    array,
                    typed_array,
                    iterator_receiver,
                    next_method,
                    timers_interval,
                    done: _,
                    closed: _,
                    return_called: _,
                    trace_index: _,
                } = state;
                values.iter().for_each(|value| self.value(value));
                if let Some(array) = array {
                    self.object(array.object_id);
                }
                if let Some(typed_array) = typed_array {
                    self.object(typed_array.view.buffer);
                }
                if let Some(value) = iterator_receiver {
                    self.value(value);
                }
                if let Some(value) = next_method {
                    self.value(value);
                }
                if let Some((_, value)) = timers_interval {
                    self.value(value);
                }
            }
        }
    }

    fn generator(&mut self, generator: &GeneratorObject) {
        let GeneratorObject {
            owner_module: _,
            invocation,
            execution,
            resume_dst: _,
            phase: _,
        } = generator;
        if let Some(invocation) = invocation {
            invocation
                .arguments
                .iter()
                .for_each(|value| self.value(value));
            self.value(&invocation.this_value);
            if let Some(closure) = invocation.closure_index {
                self.closure(closure);
            }
        }
        if let Some(execution) = execution {
            self.generator_execution(execution);
        }
    }

    fn async_function(&mut self, function: &AsyncFunctionObject) {
        let AsyncFunctionObject {
            owner_module: _,
            isolated_execution,
            function_index: _,
            closure_index,
            saved_ip: _,
            saved_registers,
            saved_register_labels: _,
            saved_register_base: _,
            phase: _,
            result_promise: _,
        } = function;
        if let Some(execution) = isolated_execution {
            self.generator_execution(execution);
        }
        if let Some(closure) = closure_index {
            self.closure(*closure);
        }
        saved_registers.iter().for_each(|value| self.value(value));
    }

    fn combinator(&mut self, state: &PromiseCombinatorState) {
        match state {
            PromiseCombinatorState::All(tracker) => {
                tracker
                    .values
                    .values()
                    .for_each(|value| self.js_value(value));
            }
            PromiseCombinatorState::AllSettled(tracker) => {
                tracker
                    .outcomes
                    .values()
                    .for_each(|outcome| self.js_value(&outcome.value));
            }
            PromiseCombinatorState::Race(_) => {}
            PromiseCombinatorState::Any(tracker) => {
                tracker
                    .errors
                    .values()
                    .for_each(|value| self.js_value(value));
            }
        }
    }
}

impl InterpreterCore {
    /// Collector totals for this interpreter.
    pub fn gc_stats(&self) -> GcStats {
        self.gc.stats
    }

    /// Diagnostic stress mode: when `Some(n)`, collect at every `n`th safe
    /// point regardless of heap pressure. Used by the root-coverage
    /// differential (a missed root changes the program's output).
    pub fn set_gc_stress_interval(&mut self, interval: Option<u64>) {
        self.gc.stress_interval = interval.filter(|n| *n > 0);
        self.gc.stress_safe_points = 0;
    }

    /// Enter a run loop (tracks the depth that `safe_depth` refers to).
    pub(super) fn gc_enter_run_loop(&mut self) {
        self.gc.run_loop_depth = self.gc.run_loop_depth.saturating_add(1);
    }

    pub(super) fn gc_exit_run_loop(&mut self) {
        self.gc.run_loop_depth = self.gc.run_loop_depth.saturating_sub(1);
    }

    /// Allow collection in the next run loop entered (the top-level script's
    /// own loop). Returns the previous setting for `gc_restore_safe_depth`.
    pub(super) fn gc_arm_top_level(&mut self) -> Option<u32> {
        self.gc_reset_triggers();
        self.gc
            .safe_depth
            .replace(self.gc.run_loop_depth.saturating_add(1))
    }

    pub(super) fn gc_restore_safe_depth(&mut self, previous: Option<u32>) {
        self.gc.safe_depth = previous;
        self.gc.pinned.clear();
    }

    /// Allow collection between event-loop jobs, pinning the values the
    /// caller holds until `gc_disarm_event_loop`.
    pub(super) fn gc_arm_event_loop(&mut self, pinned: Option<Value>) {
        self.gc.event_loop_armed = true;
        self.gc.pinned_values = pinned.into_iter().collect();
    }

    pub(super) fn gc_disarm_event_loop(&mut self) {
        self.gc.event_loop_armed = false;
        self.gc.pinned_values.clear();
    }

    /// Safe point between event-loop jobs (turns, microtasks, nextTick
    /// callbacks). Valid only with no run loop active: every job's state is
    /// then in interpreter tables, and the drivers hold only counters.
    pub(super) fn gc_event_loop_safe_point(&mut self) {
        if self.gc.event_loop_armed
            && self.gc.run_loop_depth == 0
            && (self.heap.live_len() >= self.gc.trigger_objects
                || self.estimated_memory_bytes >= self.gc.trigger_bytes
                || self.gc.stress_interval.is_some())
        {
            self.gc_safe_point();
        }
    }

    /// Mark the next `evaluate_cjs_ir3` as the top-level CommonJS entry.
    pub(super) fn gc_set_cjs_entry_pending(&mut self, pending: bool) {
        self.gc.cjs_entry_pending = pending;
    }

    /// Arm collection for the top-level CommonJS entry's run loop. The saved
    /// caller execution stays in a Rust local across that loop, so every
    /// object it references is pinned as a root. Returns the previous safe
    /// depth for `gc_restore_safe_depth`, or `None` when this evaluation is
    /// not the top-level entry.
    pub(super) fn gc_arm_cjs_entry(
        &mut self,
        caller: &ModuleExecutionSnapshot,
    ) -> Option<Option<u32>> {
        if !std::mem::take(&mut self.gc.cjs_entry_pending) {
            return None;
        }
        let mut marker = GcMarker::new(self.heap.len(), self.closures.len());
        marker.module_execution(caller);
        let pinned: Vec<ObjectId> = marker.stack.iter().map(|id| ObjectId(*id)).collect();
        let previous = self.gc_arm_top_level();
        self.gc.pinned = pinned;
        Some(previous)
    }

    fn gc_reset_triggers(&mut self) {
        let max_objects = self.config.max_heap_objects as usize;
        self.gc.trigger_objects = (max_objects / 4).saturating_mul(3).max(1);
        self.gc.trigger_bytes = (self.config.max_total_memory_bytes / 4)
            .saturating_mul(3)
            .max(1);
    }

    /// Checked at the top of every dispatch-loop iteration.
    #[inline]
    pub(super) fn gc_safe_point_due(&self) -> bool {
        self.gc.safe_depth == Some(self.gc.run_loop_depth)
            && (self.heap.live_len() >= self.gc.trigger_objects
                || self.estimated_memory_bytes >= self.gc.trigger_bytes
                || self.gc.stress_interval.is_some())
    }

    /// Collect at a safe point if a threshold (or stress mode) says so.
    pub(super) fn gc_safe_point(&mut self) {
        if let Some(interval) = self.gc.stress_interval {
            let under_pressure = self.heap.live_len() >= self.gc.trigger_objects
                || self.estimated_memory_bytes >= self.gc.trigger_bytes;
            self.gc.stress_safe_points = self.gc.stress_safe_points.wrapping_add(1);
            if !under_pressure && !self.gc.stress_safe_points.is_multiple_of(interval) {
                return;
            }
        }
        match self.collect_garbage() {
            Ok(()) => {}
            Err(GcSkip::HostState) => {
                self.gc.stats.skipped_collections =
                    self.gc.stats.skipped_collections.saturating_add(1);
                // Nothing can change until host state drains; stop checking
                // on every instruction. The allocation budget still applies.
                self.gc.trigger_objects = usize::MAX;
                self.gc.trigger_bytes = u64::MAX;
            }
        }
    }

    /// One stop-the-world mark-sweep over the heap.
    fn collect_garbage(&mut self) -> Result<(), GcSkip> {
        let mut marker = GcMarker::new(self.heap.len(), self.closures.len());
        self.gc_mark_roots(&mut marker)?;
        self.gc_drain(&mut marker);
        self.gc_mark_ephemerons(&mut marker);

        #[cfg(debug_assertions)]
        let drift_before = self
            .estimated_memory_bytes
            .wrapping_sub(self.recompute_base_estimated_memory_bytes());

        let GcMarker {
            marked,
            closures_marked,
            ..
        } = marker;
        let mut reclaimed_objects = 0u64;
        let mut reclaimed_bytes = 0u64;
        self.mutate_heap(|heap| {
            for (index, live) in marked.iter().enumerate() {
                if !*live && let Some(object) = heap.reclaim(index) {
                    reclaimed_objects += 1;
                    reclaimed_bytes =
                        reclaimed_bytes.saturating_add(Self::estimate_heap_object_bytes(&object));
                }
            }
        });
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(reclaimed_bytes);

        // Closures: release unreachable captured environments. The closure,
        // cold-cell and scope components move together, so charge the exact
        // difference of the recomputed estimate.
        let dead_closures: Vec<usize> = closures_marked
            .iter()
            .enumerate()
            .filter(|(index, live)| {
                !**live && self.closures[*index].function_index != RECLAIMED_CLOSURE_FUNCTION_INDEX
            })
            .map(|(index, _)| index)
            .collect();
        let mut reclaimed_closures = 0u64;
        if !dead_closures.is_empty() {
            let before = self.recompute_base_estimated_memory_bytes();
            for index in dead_closures {
                if self.closures.reclaim(index) {
                    reclaimed_closures += 1;
                }
            }
            let released = before.saturating_sub(self.recompute_base_estimated_memory_bytes());
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
            reclaimed_bytes = reclaimed_bytes.saturating_add(released);
        }

        #[cfg(debug_assertions)]
        debug_assert_eq!(
            self.estimated_memory_bytes
                .wrapping_sub(self.recompute_base_estimated_memory_bytes()),
            drift_before,
            "collection changed memory-accounting drift"
        );

        let stats = &mut self.gc.stats;
        stats.collections = stats.collections.saturating_add(1);
        stats.reclaimed_objects = stats.reclaimed_objects.saturating_add(reclaimed_objects);
        stats.reclaimed_bytes = stats.reclaimed_bytes.saturating_add(reclaimed_bytes);
        stats.reclaimed_closures = stats.reclaimed_closures.saturating_add(reclaimed_closures);

        // Next trigger: halfway between the surviving live set and the
        // budget, so collection cost stays proportional to allocation.
        let max_objects = self.config.max_heap_objects as usize;
        let live = self.heap.live_len();
        self.gc.trigger_objects =
            live.saturating_add((max_objects.saturating_sub(live) / 2).max(1));
        let max_bytes = self.config.max_total_memory_bytes;
        let bytes = self.estimated_memory_bytes;
        self.gc.trigger_bytes = bytes.saturating_add((max_bytes.saturating_sub(bytes) / 2).max(1));
        Ok(())
    }

    fn gc_drain(&self, marker: &mut GcMarker) {
        loop {
            if let Some(closure) = marker.closure_stack.pop() {
                self.gc_trace_closure(marker, closure);
                continue;
            }
            let Some(index) = marker.stack.pop() else {
                break;
            };
            let Some(object) = self.heap.get(index as usize) else {
                continue;
            };
            let HeapObject {
                properties,
                property_labels: _,
                property_attributes: _,
                prototype,
                constructor_function: _,
                derived_constructor_parent,
                derived_constructor_parent_label: _,
                is_derived_constructor: _,
                is_default_derived_constructor: _,
                is_array: _,
                cached_dense_length: _,
                array_buffer: _,
                typed_array,
                data_view,
                is_frozen: _,
                is_non_extensible: _,
                is_import_meta: _,
                is_null_prototype: _,
            } = object;
            // Every value store of the property map: well-formed and
            // exact-only string keys, and Symbol-keyed data and accessors
            // (kept in a separate sidecar that `values()` does not visit).
            for value in properties.all_data_values() {
                marker.value(value);
            }
            for (_, property) in properties.baseline_symbol_properties() {
                match property {
                    BaselineSymbolProperty::Data(value) => marker.value(value),
                    BaselineSymbolProperty::Accessor { get, set } => {
                        if let Some(get) = get {
                            marker.value(get);
                        }
                        if let Some(set) = set {
                            marker.value(set);
                        }
                    }
                }
            }
            if let Some(prototype) = prototype {
                marker.object(*prototype);
            }
            if let Some(parent) = derived_constructor_parent {
                marker.value(parent);
            }
            if let Some(view) = typed_array {
                marker.object(view.buffer);
            }
            if let Some(view) = data_view {
                marker.object(view.buffer);
            }
            // Map keys live in the storage object's property names (see
            // `collection_key_repr`); an object key is reachable through them.
            if let Some(storage_id) =
                self.collection_storage_id(ObjectId(index), "Map", "__entries")
                && let Some(storage) = self.heap.get(storage_id.0 as usize)
            {
                for repr in storage.properties.keys() {
                    marker.value(&Self::collection_key_from_repr(repr));
                }
            }
        }
    }

    /// A live closure keeps its captured environment and its per-closure
    /// metadata (home object, lexical `this`) alive.
    fn gc_trace_closure(&self, marker: &mut GcMarker, closure: u32) {
        if let Some(entry) = self.closures.get(closure as usize) {
            marker.scope_frames(&entry.captured_env);
        }
        if let Some(metadata) = self.closure_method_metadata.get(&closure) {
            marker.object(metadata.home_object);
        }
        if let Some(metadata) = self.closure_lexical_super_metadata.get(&closure) {
            marker.object(metadata.home_object);
            marker.value(&metadata.this_value);
        }
        if let Some((value, _)) = self.arrow_lexical_this.get(&closure) {
            marker.value(value);
        }
    }

    /// WeakMap side-table entries keep their value only while both the map
    /// and the key are reachable. Iterate to a fixpoint.
    fn gc_mark_ephemerons(&self, marker: &mut GcMarker) {
        loop {
            let before = marker.stack.len();
            let mut added = false;
            for (map_id, storage) in &self.weakmap_storage {
                if !marker.is_marked(map_id.0) {
                    continue;
                }
                for (key, value) in &storage.entries {
                    if marker.is_marked(*key) {
                        marker.value(value);
                    }
                }
            }
            if marker.stack.len() > before {
                added = true;
                self.gc_drain(marker);
            }
            if !added {
                break;
            }
        }
    }

    /// Enumerate every root. The exhaustive destructuring is the registration
    /// guard: a new field must be classified here before the crate compiles.
    fn gc_mark_roots(&self, m: &mut GcMarker) -> Result<(), GcSkip> {
        let InterpreterCore {
            // Configuration, providers and hooks hold no heap references.
            config: _,
            hook: _,
            pruned_hostcall_dispatch: _,
            preparing_execution: _,
            state_capture_tick: _,
            // A capture is a self-contained copy returned to the caller.
            state_capture_result: _,
            host_io: _,
            host_io_recorder: _,
            process_spawn: _,
            host_effect_journal: _,
            timer_effect_authority: _,
            registers,
            call_stack,
            heap: _,
            estimated_memory_bytes: _,
            simple_callback_temporary_bytes: _,
            json_parse_temporary_bytes: _,
            module_snapshot_in_flight_bytes: _,
            temporarily_suspended_execution_bytes: _,
            iterators,
            iteration_traces: _,
            function_prototypes,
            builtin_prototypes,
            seed_epoch: _,
            // Seeds hold their own heap copies; restoring one replaces the
            // whole heap.
            pending_lazy_seeds: _,
            pending_arguments_object,
            execution_seed_reservation_ledger: _,
            ip: _,
            instructions_executed: _,
            // Instruction count at the last virtual-clock advance (bd-9vouw.59).
            virtual_clock_instruction_mark: _,
            tier_i_instructions_executed: _,
            tier_i_specialized_instructions_executed: _,
            // Evidence and telemetry records name ids but never dereference
            // them.
            witness_events: _,
            hostcall_decisions: _,
            security_observability: _,
            telemetry_recorder: _,
            events: _,
            general_event_bytes: _,
            dropped_event_count: _,
            generated_code_audit: _,
            generated_code_observability_bytes: _,
            generated_code_observability_reservation_bytes: _,
            witness_seq: _,
            trace_id: _,
            register_base: _,
            stacked_register_frame_clear_width_high_water: _,
            top_level_compact_tier1: _,
            catch_frames: _,
            pending_exception,
            pending_exception_label: _,
            pending_hostcall_result_label: _,
            pending_return,
            suspended_abrupt_completions,
            finally_frames,
            pending_finally_entry: _,
            last_pre_run_seed: _,
            last_post_run_epoch: _,
            scope_chain,
            realm_dynamic_globals,
            generated_function_realm_globals,
            generated_function_realm_generation: _,
            runtime_name_references,
            // Traced per live closure by `gc_trace_closure`.
            closures: _,
            closure_method_metadata: _,
            closure_lexical_super_metadata: _,
            arrow_lexical_this: _,
            closure_module_origins: _,
            closure_generated_function_artifacts: _,
            module_reentrant_call_depth: _,
            active_foreign_module_call_depth: _,
            isolated_async_entry_pending: _,
            pending_captures: _,
            generators,
            generator_yielded: _,
            generator_resume_dst: _,
            generator_result_label: _,
            generator_delegation: _,
            async_functions,
            async_resumption_contexts: _,
            top_level_await_resumption_contexts: _,
            top_level_await_outcome,
            async_generators,
            async_generator_runtime,
            promise_store,
            event_loop,
            promise_in_flight_task_bytes: _,
            promise_reaction_callables,
            next_tick_queue,
            next_promise_reaction_callable_id: _,
            builtin_dispatch_hit_unknown_member: _,
            pending_io_callbacks,
            pending_child_process_tasks,
            child_process_task_in_flight_bytes: _,
            event_listeners,
            event_once_wrappers,
            event_promise_waiters,
            next_event_promise_waiter_id: _,
            completed_child_processes,
            child_process_streams,
            child_process_handles,
            url_objects,
            url_search_params,
            cluster_facades,
            crypto_objects,
            stream_pipelines,
            next_stream_pipeline_token: _,
            pending_stream_emissions,
            readable_from_streams,
            readable_terminal_states,
            pending_readable_from_pumps,
            readable_pump_reservations,
            active_readable_listener_target,
            readable_pipe_links,
            readable_pipe_sources,
            next_readable_pipe_token: _,
            loopback_servers,
            loopback_sockets,
            loopback_ports,
            pending_loopback_tasks,
            loopback_task_in_flight_bytes: _,
            next_loopback_port: _,
            next_loopback_listener_generation: _,
            http_servers,
            http_client_requests,
            http_incoming_messages,
            http_server_responses,
            http_agents,
            pending_http_tasks,
            http_task_in_flight_bytes: _,
            writable_streams,
            writable_terminal_states,
            writable_in_flight_callback_bytes: _,
            pending_writable_terminal_ticks,
            next_writable_tick_sequence: _,
            next_writable_completion_token: _,
            promise_combinators,
            // Watchers name combinator ids and indices only.
            promise_combinator_watchers: _,
            next_promise_combinator_id: _,
            module_state,
            pending_async_module_import: _,
            pending_cyclic_import_binding: _,
            active_cjs_context,
            current_module_specifier: _,
            active_generated_function_artifact: _,
            entry_module_specifier: _,
            console_output: _,
            console_output_bytes: _,
            process_exit_code: _,
            profiling_data: _,
            next_timer_id: _,
            active_timers,
            pending_timer_tasks,
            unref_timer_ids: _,
            suspended: _,
            sandboxed: _,
            quarantined: _,
            pending_challenges: _,
            containment_evidence: _,
            decision_receipts: _,
            nondeterminism_trace: _,
            register_labels: _,
            // Weak side tables: entries for reclaimed ids are unreachable
            // and ids are never reused.
            object_mutation_labels: _,
            active_inline_callback_context_label: _,
            inline_callback_start_probes: _,
            proxy_trap_lookup_depth: _,
            weakmap_storage: _,
            symbol_state: _,
            gc_remembered_set: _,
            jit_function_call_counts: _,
            jit_loop_iteration_counts: _,
            jit_hot_threshold: _,
            jit_eviction_counter: _,
            gc: _,
        } = self;

        // Host I/O state is not traced yet: refuse to collect while any of it
        // is live.
        let host_state: [(&'static str, bool); 30] = [
            (
                "pending_child_process_tasks",
                pending_child_process_tasks.is_empty(),
            ),
            (
                "completed_child_processes",
                completed_child_processes.is_empty(),
            ),
            ("child_process_streams", child_process_streams.is_empty()),
            ("child_process_handles", child_process_handles.is_empty()),
            ("url_objects", url_objects.is_empty()),
            ("url_search_params", url_search_params.is_empty()),
            ("cluster_facades", cluster_facades.is_empty()),
            ("crypto_objects", crypto_objects.is_empty()),
            ("stream_pipelines", stream_pipelines.is_empty()),
            (
                "pending_stream_emissions",
                pending_stream_emissions.is_empty(),
            ),
            ("readable_from_streams", readable_from_streams.is_empty()),
            (
                "readable_terminal_states",
                readable_terminal_states.is_empty(),
            ),
            (
                "pending_readable_from_pumps",
                pending_readable_from_pumps.is_empty(),
            ),
            (
                "readable_pump_reservations",
                readable_pump_reservations.is_empty(),
            ),
            (
                "active_readable_listener_target",
                active_readable_listener_target.is_none(),
            ),
            ("readable_pipe_links", readable_pipe_links.is_empty()),
            ("readable_pipe_sources", readable_pipe_sources.is_empty()),
            ("loopback_servers", loopback_servers.is_empty()),
            ("loopback_sockets", loopback_sockets.is_empty()),
            ("loopback_ports", loopback_ports.is_empty()),
            ("pending_loopback_tasks", pending_loopback_tasks.is_empty()),
            ("http_servers", http_servers.is_empty()),
            ("http_client_requests", http_client_requests.is_empty()),
            ("http_incoming_messages", http_incoming_messages.is_empty()),
            ("http_server_responses", http_server_responses.is_empty()),
            ("http_agents", http_agents.is_empty()),
            ("pending_http_tasks", pending_http_tasks.is_empty()),
            ("writable_streams", writable_streams.is_empty()),
            (
                "writable_terminal_states",
                writable_terminal_states.is_empty(),
            ),
            (
                "pending_writable_terminal_ticks",
                *pending_writable_terminal_ticks == 0,
            ),
        ];
        if host_state.iter().any(|(_, idle)| !idle) {
            return Err(GcSkip::HostState);
        }

        // Execution state.
        #[cfg(test)]
        let drop_execution_roots = self.gc.drop_execution_roots;
        #[cfg(not(test))]
        let drop_execution_roots = false;
        if !drop_execution_roots {
            registers.iter().for_each(|value| m.value(value));
            call_stack.iter().for_each(|frame| m.call_frame(frame));
            m.scope_frames(&scope_chain.frames);
            realm_dynamic_globals
                .values()
                .for_each(|binding| m.binding(binding));
        }
        if let Some((_, value, _)) = pending_arguments_object {
            m.value(value);
        }
        if let Some(value) = pending_exception {
            m.value(value);
        }
        if let Some(completion) = pending_return {
            m.labeled_return(completion);
        }
        suspended_abrupt_completions
            .iter()
            .for_each(|completion| m.abrupt(completion));
        finally_frames
            .iter()
            .for_each(|frame| m.finally_frame(frame));
        if let Some(globals) = generated_function_realm_globals {
            globals.values().for_each(|binding| m.binding(binding));
        }
        for reference in runtime_name_references {
            if let RuntimeNameReference::Resolved(binding) = reference {
                m.binding(binding);
            }
        }

        // Objects and values a Rust caller holds across an armed phase.
        self.gc.pinned.iter().for_each(|id| m.object(*id));
        self.gc
            .pinned_values
            .iter()
            .for_each(|value| m.value(value));

        // Intrinsics.
        function_prototypes.values().for_each(|id| m.object(*id));
        builtin_prototypes.values().for_each(|id| m.object(*id));

        // Tables whose entries are never reclaimed. Closures are traced from
        // the values that reference them (`gc_trace_closure`).
        iterators.iter().for_each(|iterator| m.iterator(iterator));
        generators
            .iter()
            .for_each(|generator| m.generator(generator));
        async_functions
            .iter()
            .for_each(|function| m.async_function(function));
        if let Some(Ok(completion)) = top_level_await_outcome {
            m.labeled_return(completion);
        }
        for generator in async_generators {
            generator.for_each_value(|value| m.value(value));
        }
        async_generator_runtime.for_each_value(|value| m.value(value));

        // Promises and queued work, including the handlers they will call.
        promise_store.for_each_value(|value| m.js_value(value));
        promise_store.for_each_handler(|handler| m.handler(handler));
        event_loop
            .microtasks
            .for_each_value(|value| m.js_value(value));
        event_loop
            .microtasks
            .for_each_handler(|handler| m.handler(handler));
        for task in event_loop.macrotasks.iter_pending() {
            m.handler(task.handler);
        }
        for timer in active_timers.values() {
            if let Some(handler) = timer.handler {
                m.handler(crate::closure_model::ClosureHandle(handler));
            }
        }
        promise_reaction_callables
            .values()
            .for_each(|value| m.value(value));
        for task in next_tick_queue {
            m.value(&task.callback);
            task.args.iter().for_each(|value| m.value(value));
        }
        pending_io_callbacks
            .values()
            .flatten()
            .for_each(|value| m.value(value));
        promise_combinators
            .values()
            .for_each(|state| m.combinator(state));
        for task in pending_timer_tasks.values() {
            match &task.kind {
                PendingTimerTaskKind::Callback { callback, args, .. } => {
                    m.value(callback);
                    args.iter().for_each(|value| m.value(value));
                }
                PendingTimerTaskKind::PromiseResolve { value, .. } => m.js_value(value),
            }
        }

        // Event emitters.
        for (emitter, events) in event_listeners {
            m.object(*emitter);
            for record in events.values().flatten() {
                m.value(&record.listener);
            }
        }
        for (wrapper, state) in event_once_wrappers {
            m.object(*wrapper);
            m.object(state.target);
            m.value(&state.original_listener);
        }
        event_promise_waiters
            .keys()
            .for_each(|emitter| m.object(*emitter));

        // Modules.
        for record in module_state.modules.values() {
            m.object(record.namespace_object);
            record.exports.values().for_each(|value| m.value(value));
            if let Some(id) = record.cjs_module_object {
                m.object(id);
            }
            if let Some(execution) = &record.async_execution {
                m.module_execution(execution);
            }
        }
        if let Some(context) = active_cjs_context {
            m.object(context.module_object);
            m.object(context.exports_object);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::ParseGoal;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    fn execute(source: &str, drop_execution_roots: bool) -> String {
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "gc-unit.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("parse");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "gc-unit.js"),
            &LoweringContext::new("gc-trace", "gc-decision", "gc-policy"),
        )
        .expect("lower")
        .ir3;
        let mut config = InterpreterConfig::quickjs_defaults();
        config.instruction_budget = 1_000_000_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "gc-unit");
        core.set_gc_stress_interval(Some(1));
        core.gc.drop_execution_roots = drop_execution_roots;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| core.execute(&module))) {
            Ok(Ok(result)) => format!("{:?}", result.value),
            Ok(Err(error)) => format!("error: {error:?}"),
            Err(_) => "panic".to_string(),
        }
    }

    /// The differential must not be vacuous: dropping one root class changes
    /// the outcome of a program whose object lives only in execution state.
    #[test]
    fn dropping_execution_roots_is_detected() {
        let source =
            "var keep = { v: 7 }; for (let i = 0; i < 50; i++) { const g = { i }; } keep.v";
        assert_eq!(execute(source, false), format!("{:?}", Value::Int(7)));
        assert_ne!(execute(source, true), format!("{:?}", Value::Int(7)));
    }

    /// Symbol-keyed properties and exact-only (lone-surrogate) string keys
    /// live in sidecars of the property map that `values()` skips. Objects
    /// reachable only through them must survive; unreferenced ones must not.
    /// The heap is built directly so no stale register can keep them alive.
    #[test]
    fn symbol_and_exact_key_property_values_are_traced() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [RuntimeCapability::HeapAllocate].into_iter().collect();
        let mut core = InterpreterCore::new(config, "gc-unit");
        let holder = core.alloc_object_with_prototype(None).expect("holder");
        let via_symbol = core
            .alloc_object_with_prototype(None)
            .expect("symbol target");
        let via_symbol_getter = core
            .alloc_object_with_prototype(None)
            .expect("getter target");
        let via_exact_key = core
            .alloc_object_with_prototype(None)
            .expect("exact target");
        let garbage = core.alloc_object_with_prototype(None).expect("garbage");
        core.mutate_heap(|heap| {
            let properties = &mut heap[holder.0 as usize].properties;
            properties.insert_baseline_symbol_property(
                CoreSymbolId(7),
                BaselineSymbolProperty::Data(Value::Object(via_symbol)),
            );
            properties.insert_baseline_symbol_property(
                CoreSymbolId(8),
                BaselineSymbolProperty::Accessor {
                    get: Some(Value::Object(via_symbol_getter)),
                    set: None,
                },
            );
            properties.insert_exact(
                JsString::from_code_units(&[0xD800]),
                Value::Object(via_exact_key),
            );
        });
        core.set_reg(0, Value::Object(holder));
        core.collect_garbage().expect("collection runs");
        for (name, id) in [
            ("holder", holder),
            ("symbol data", via_symbol),
            ("symbol accessor", via_symbol_getter),
            ("exact-only key", via_exact_key),
        ] {
            assert!(
                core.heap.get(id.0 as usize).is_some(),
                "{name} was reclaimed"
            );
        }
        assert!(
            core.heap.is_reclaimed(garbage.0 as usize),
            "garbage survived"
        );
    }

    /// The script's completion value is held by the caller across the
    /// event-loop phase. 300 timer callbacks allocate 300,000 objects in
    /// total (collections run between them) and reuse register windows, so
    /// the pin is what keeps the completion alive.
    #[test]
    fn completion_value_survives_event_loop_collection() {
        let source = "let n = 300; function tick() { for (let i = 0; i < 1000; i++) { const g = { i }; } \
                      n = n - 1; if (n > 0) { setTimeout(tick, 0); } } setTimeout(tick, 0); \
                      ({ v: 9 })";
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "gc-unit.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("parse");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "gc-unit.js"),
            &LoweringContext::new("gc-trace", "gc-decision", "gc-policy"),
        )
        .expect("lower")
        .ir3;
        let mut config = InterpreterConfig::quickjs_defaults();
        config.instruction_budget = 1_000_000_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Timer,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "gc-unit");
        let result = core.execute(&module).expect("execute");
        assert!(
            core.gc_stats().collections > 0,
            "no event-loop collection ran"
        );
        let Value::Object(id) = result.value else {
            panic!("completion is not an object: {:?}", result.value);
        };
        let object = core
            .heap
            .get(id.0 as usize)
            .expect("completion value was reclaimed");
        assert_eq!(object.properties.get("v"), Some(&Value::Int(9)));
    }

    /// Reclaimed slots cost one pointer, not a whole object.
    #[test]
    fn reclaimed_slot_is_pointer_sized() {
        assert_eq!(
            std::mem::size_of::<Option<Box<HeapObject>>>(),
            std::mem::size_of::<usize>()
        );
    }
}
