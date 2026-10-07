//! Reclaiming collector for the baseline interpreter heap (bd-9vouw.57).
//!
//! Before this collector every allocation was permanent. A program died at its
//! 100,001st object however small its live set was:
//! `for (...) { const o = { a: i } }` failed with "memory budget exceeded".
//!
//! Design:
//! - Precise, stop-the-world mark from an enumerated root set, then a sweep
//!   that empties the slot of every unmarked object (`Heap::sweep`).
//! - Slot ids are never reused. A missed root therefore surfaces as a missing
//!   object, never as another object's identity. Memory is released by chunk:
//!   a full chunk of slots whose objects are all reclaimed is dropped, and
//!   mark and sweep visit only resident chunks.
//! - Collection runs only at a safe point, where every live value sits in
//!   interpreter state. The first safe point is the top of the dispatch loop
//!   of the top-level script's own run loop.
//! - The second safe point is between event-loop jobs (turns, microtasks,
//!   nextTick callbacks) after the script, while no run loop is active. The
//!   script's completion value, held by the caller across that phase, is
//!   pinned.
//! - Nested run loops (callbacks, generator bodies, isolated calls) hold
//!   caller state in Rust locals, so by default no collection runs while one
//!   is active. A call site that knows what its Rust frames hold may arm the
//!   nested loop it enters (bd-9vouw.77): async function calls, timer
//!   callbacks, Promise reaction handlers and async resumption. The caller's
//!   saved execution and the values the dispatching frames hold are pinned
//!   on a stack for the duration. Builtins that call guest callbacks while
//!   holding values only in Rust locals (map's result array, sort's element
//!   vector) never arm, so no collection runs inside those callbacks.
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
//! closure's captured environment is released, its function index is
//! poisoned (`ClosureTable::reclaim`) and its per-closure side-table entries
//! are purged; its id is never reused. The closure table releases fully dead
//! chunks like the heap. Weak side tables keyed by object id drop the entries
//! of reclaimed objects (mutation labels), and the write-barrier remembered
//! set restarts empty after each collection.
//!
//! Promises, iterators, generators and async-function records live in id
//! tables that are traced too:
//! - A settled promise, or an iterator, survives only while a reachable value
//!   or engine table names it.
//! - Pending promises are roots.
//! - A completed async-function record survives only while a call frame or
//!   an await continuation names it.
//! - Ids are never reused, so a stale id fails loudly.
//!
//! Generators are traced the same way: an unreachable generator, suspended
//! or not, can never resume. An async generator is kept while a value names
//! it, while it runs or awaits, or while requests are queued on it; its
//! backing generator follows it. WeakMap entries are ephemerons: a value is
//! kept only while its key is reachable.

use std::collections::HashSet;

use super::*;
use crate::object_model::JsValue;
use crate::promise_model::PromiseEdge;

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
    /// Settled promises whose records were vacated.
    pub reclaimed_promises: u64,
    /// Completed async-function records released.
    pub reclaimed_async_functions: u64,
    /// Iterator-table entries released.
    pub reclaimed_iterators: u64,
    /// Generators released with their suspended executions.
    pub reclaimed_generators: u64,
    /// Async-generator records released.
    #[serde(default)]
    pub reclaimed_async_generators: u64,
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
    /// Objects, closures and promises referenced by state that a Rust caller
    /// holds across the armed run loop (the CommonJS entry's saved caller
    /// execution). Roots.
    pinned: Vec<Value>,
    /// Set while the event loop runs after the top-level script: collection
    /// may run between jobs whenever no run loop is active.
    event_loop_armed: bool,
    /// Values a Rust caller holds across the event-loop phase (the script's
    /// completion value). Roots.
    pinned_values: Vec<Value>,
    /// One entry per armed nested run loop (bd-9vouw.77): what its callers
    /// hold in Rust locals. Roots.
    nested_pins: Vec<NestedPins>,
    /// Builtin dispatches active in the current run loop. A builtin whose
    /// Rust frame calls another builtin's dispatch holds its own locals
    /// across it, so only the outermost one may arm a nested loop.
    builtin_depth: u32,
    /// `builtin_depth` of each enclosing run loop, restored on exit.
    builtin_depth_stack: Vec<u32>,
    /// Planted negative for the root-coverage tests: skip the registers,
    /// call frames, scope chain and realm globals.
    #[cfg(test)]
    drop_execution_roots: bool,
}

/// State a Rust frame holds outside the interpreter while a nested run loop
/// it armed for collection runs (bd-9vouw.77).
pub(super) enum GcPin<'a> {
    Value(&'a Value),
    /// Async-function records created from this id on.
    AsyncFunctionsFrom(usize),
    ModuleExecution(&'a ModuleExecutionSnapshot),
    GeneratorExecution(&'a GeneratorExecutionSnapshot),
}

/// What the Rust frames around one armed nested run loop hold.
#[derive(Debug, Clone, Default)]
struct NestedPins {
    values: Vec<Value>,
    /// Async-function records with at least this id, which the caller reads
    /// once the loop returns (the record its isolated call created, and any
    /// it must reject if the call fails), completed or not.
    async_functions_from: Option<usize>,
}

/// Proof that `gc_arm_nested` armed a run loop; `gc_disarm_nested` undoes it.
#[must_use]
pub(super) struct NestedGcArm {
    previous: Option<u32>,
}

/// Why a due collection did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GcSkip {
    /// Host I/O state (streams, sockets, http, ...) is live and not traced.
    HostState,
}

/// Mark bits for ids stored in fixed chunks (heap slots, closure-table
/// entries). A chunk's bits are allocated on its first mark, so marking costs
/// follow the live set rather than every id ever allocated.
struct ChunkedMarks {
    chunks: Vec<Option<Box<[u64; HEAP_CHUNK_SLOTS / 64]>>>,
    len: usize,
}

impl ChunkedMarks {
    fn new(len: usize) -> Self {
        Self {
            chunks: vec![None; len.div_ceil(HEAP_CHUNK_SLOTS)],
            len,
        }
    }

    fn is_marked(&self, index: usize) -> bool {
        let offset = index % HEAP_CHUNK_SLOTS;
        self.chunks
            .get(index / HEAP_CHUNK_SLOTS)
            .and_then(Option::as_ref)
            .is_some_and(|bits| bits[offset / 64] & (1 << (offset % 64)) != 0)
    }

    /// Mark `index`; true when it was not marked before. Ids at or past the
    /// table length are ignored.
    fn mark(&mut self, index: usize) -> bool {
        if index >= self.len {
            return false;
        }
        let offset = index % HEAP_CHUNK_SLOTS;
        let bits = self.chunks[index / HEAP_CHUNK_SLOTS]
            .get_or_insert_with(|| Box::new([0; HEAP_CHUNK_SLOTS / 64]));
        let bit = 1u64 << (offset % 64);
        let unmarked = bits[offset / 64] & bit == 0;
        bits[offset / 64] |= bit;
        unmarked
    }
}

/// Mark state for one collection.
struct GcMarker {
    objects: ChunkedMarks,
    stack: Vec<u32>,
    closures: ChunkedMarks,
    closure_stack: Vec<u32>,
    promises: ChunkedMarks,
    promise_stack: Vec<u32>,
    /// Promise-value carriers (bd-9vouw.69) named by a traced `JsValue`.
    carriers: HashSet<u32>,
    carrier_stack: Vec<u32>,
    /// Async-function records named by a call frame or an await
    /// continuation. Records that have not completed are always kept.
    async_functions: ChunkedMarks,
    iterators: ChunkedMarks,
    iterator_stack: Vec<u32>,
    generators: ChunkedMarks,
    generator_stack: Vec<u32>,
    async_generators: ChunkedMarks,
    async_generator_stack: Vec<u32>,
    visited_frames: HashSet<usize>,
    visited_cells: HashSet<usize>,
}

impl GcMarker {
    fn new(
        heap_len: usize,
        closures_len: usize,
        promises_len: usize,
        async_functions_len: usize,
        iterators_len: usize,
        generators_len: usize,
        async_generators_len: usize,
    ) -> Self {
        Self {
            objects: ChunkedMarks::new(heap_len),
            stack: Vec::new(),
            closures: ChunkedMarks::new(closures_len),
            closure_stack: Vec::new(),
            promises: ChunkedMarks::new(promises_len),
            promise_stack: Vec::new(),
            carriers: HashSet::new(),
            carrier_stack: Vec::new(),
            async_functions: ChunkedMarks::new(async_functions_len),
            iterators: ChunkedMarks::new(iterators_len),
            iterator_stack: Vec::new(),
            generators: ChunkedMarks::new(generators_len),
            generator_stack: Vec::new(),
            async_generators: ChunkedMarks::new(async_generators_len),
            async_generator_stack: Vec::new(),
            visited_frames: HashSet::new(),
            visited_cells: HashSet::new(),
        }
    }

    /// Closure-table ids: `Value::Closure` and the generator/async function
    /// values index the closure table.
    fn closure(&mut self, id: u32) {
        if self.closures.mark(id as usize) {
            self.closure_stack.push(id);
        }
    }

    /// Promise-store handles: `Value::Promise` and the engine tables that
    /// name a promise.
    fn promise(&mut self, handle: u32) {
        if self.promises.mark(handle as usize) {
            self.promise_stack.push(handle);
        }
    }

    /// Iterator-table handles: `Value::Iterator`, the iterator methods bound
    /// to one, and `yield*` delegations.
    fn iterator_handle(&mut self, handle: u32) {
        if self.iterators.mark(handle as usize) {
            self.iterator_stack.push(handle);
        }
    }

    /// Generator-table ids: `Value::Generator` and the generator behind
    /// each async generator.
    fn generator_id(&mut self, id: u32) {
        if self.generators.mark(id as usize) {
            self.generator_stack.push(id);
        }
    }

    /// Async-generator table ids: `Value::AsyncGeneratorObject` and the
    /// running or awaiting async generator.
    fn async_generator(&mut self, id: u32) {
        if self.async_generators.mark(id as usize) {
            self.async_generator_stack.push(id);
        }
    }

    fn delegation(&mut self, delegation: &Option<GeneratorDelegation>) {
        if let Some(delegation) = delegation {
            self.iterator_handle(delegation.iterator);
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
        self.objects.is_marked(id as usize)
    }

    fn object(&mut self, id: ObjectId) {
        if self.objects.mark(id.0 as usize) {
            self.stack.push(id.0);
        }
    }

    fn value(&mut self, value: &Value) {
        match value {
            Value::Object(id) => self.object(*id),
            Value::BuiltinFunction(builtin) => {
                if let Some(bound) = builtin.bound_object {
                    // A resolve/reject capability binds its promise handle
                    // (`make_promise_capability`); every other kind binds an
                    // object.
                    if matches!(
                        builtin.kind,
                        BuiltinFunctionKind::PromiseResolve | BuiltinFunctionKind::PromiseReject
                    ) {
                        self.promise(bound);
                    } else {
                        self.object(ObjectId(bound));
                    }
                }
                // Iterator methods bind an iterator handle; other kinds use
                // the field as a stream token.
                if let Some(handle) = builtin.iterator_handle
                    && matches!(
                        builtin.kind,
                        BuiltinFunctionKind::IteratorNext | BuiltinFunctionKind::IteratorSelf
                    )
                {
                    self.iterator_handle(handle);
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
            Value::Promise(handle) => self.promise(*handle),
            Value::Iterator(handle) => self.iterator_handle(*handle),
            Value::Generator(id) => self.generator_id(*id),
            Value::AsyncGeneratorObject(id) => self.async_generator(*id),
            // Async-function objects index a table whose entries are roots.
            Value::Undefined
            | Value::Null
            | Value::Bool(_)
            | Value::Int(_)
            | Value::BigInt(_)
            | Value::Float(_)
            | Value::Str(_)
            | Value::Function(_)
            | Value::AsyncFunctionObject(_)
            | Value::Symbol(_) => {}
        }
    }

    fn js_value(&mut self, value: &JsValue) {
        match value {
            JsValue::Object(handle) => self.object(ObjectId(handle.0)),
            JsValue::Function(id) if *id >= PROMISE_VALUE_CARRIER_BASE => {
                if self.carriers.insert(*id) {
                    self.carrier_stack.push(*id);
                }
            }
            _ => {}
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
            register_width: _,
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
            class_instance_fields,
            saved_pending_exception,
            saved_pending_exception_label: _,
            saved_pending_return,
            saved_suspended_abrupt_depth: _,
            saved_finally_mode_depth: _,
            saved_scope_depth: _,
            saved_scope_chain,
            scope_inert_virtual_scope_bytes: _,
            async_function_id,
            native_boundary: _,
        } = frame;
        if let Some(id) = async_function_id {
            self.async_functions.mark(*id as usize);
        }
        self.value(this_value);
        self.value(new_target_value);
        self.value(super_value);
        if let Some(home) = super_home_object {
            self.object(*home);
        }
        if let Some(value) = construct_this {
            self.value(value);
        }
        if let Some(fields) = class_instance_fields {
            self.value(fields);
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
            register_len: _,
            register_label_len: _,
            delegation,
            active_inline_callback_context_label: _,
            call_stack,
            ip: _,
            register_base: _,
            register_width: _,
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
        self.delegation(delegation);
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
            generator_delegation,
            register_labels: _,
            active_inline_callback_context_label: _,
            call_stack,
            ip: _,
            register_base: _,
            register_width: _,
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
        self.delegation(generator_delegation);
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
                    collection,
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
                if let Some(collection) = collection {
                    self.object(collection.collection);
                    self.object(collection.storage);
                }
                if let Some(typed_array) = typed_array {
                    self.object(typed_array.view.buffer);
                    self.object(typed_array.object);
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
            prototype,
        } = generator;
        if let Some(prototype) = prototype {
            self.object(*prototype);
        }
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

    fn writable_callback(&mut self, record: &WritableCallbackRecord) {
        let WritableCallbackRecord {
            value,
            label: _,
            module_specifier: _,
        } = record;
        self.value(value);
    }

    /// A live Writable's guest values: its write/final callbacks, queued
    /// chunks and their callbacks, end callbacks and terminal error.
    fn writable_state(&mut self, state: &WritableState) {
        let WritableState {
            flavor: _,
            object_mode: _,
            high_water_mark: _,
            write_callback,
            final_callback,
            writes,
            buffered_length: _,
            need_drain: _,
            cork_depth: _,
            end_requested: _,
            destroy_requested: _,
            end_callbacks,
            end_callback_batch_remaining: _,
            finished_end_callback_batch_remaining: _,
            final_status: _,
            prefinish_emitted: _,
            finished: _,
            terminal_error,
            terminal_error_origin: _,
            terminal_error_emitted: _,
            tick_phase: _,
            tick_sequence: _,
            deferred_final_tick_sequence: _,
            inside_write_invocation: _,
            lifecycle_label: _,
        } = state;
        write_callback
            .iter()
            .chain(final_callback.iter())
            .for_each(|value| self.value(value));
        // The other WritableWriteQueue fields are byte counts.
        let WritableWriteQueue {
            completed, ready, ..
        } = writes;
        for record in completed.iter().chain(ready.iter()) {
            let WritableWriteRecord {
                value,
                label: _,
                units: _,
                callback,
                status: _,
                completion_failed: _,
            } = record;
            self.value(value);
            if let Some(callback) = callback {
                self.writable_callback(callback);
            }
        }
        for record in end_callbacks {
            let WritableEndCallbackRecord {
                callback,
                registered_after_end: _,
            } = record;
            self.writable_callback(callback);
        }
        if let Some((value, _)) = terminal_error {
            self.value(value);
        }
    }

    fn writable_terminal_state(&mut self, state: &WritableTerminalState) {
        let WritableTerminalState {
            object_mode: _,
            high_water_mark: _,
            end_requested: _,
            finished: _,
            buffered_length: _,
            cork_depth: _,
            accepts_late_end_callback: _,
            callbacks,
            tick_sequence: _,
            lifecycle_label: _,
        } = state;
        for record in callbacks {
            let WritableTerminalCallbackRecord { callback, error: _ } = record;
            self.writable_callback(callback);
        }
    }

    /// A live Readable's source, read callback, buffered chunks, destroy
    /// error and toArray waiter.
    fn readable_from_state(&mut self, state: &ReadableFromState) {
        let ReadableFromState {
            source,
            push_only: _,
            object_mode: _,
            high_water_mark: _,
            read_callback,
            buffer,
            buffered_length: _,
            eof_requested: _,
            data_readable_pending: _,
            eof_readable_pending: _,
            read_callback_active: _,
            decode_utf8: _,
            utf8_pending: _,
            destroy_requested: _,
            destroy_error,
            next_index: _,
            phase: _,
            flowing: _,
            paused: _,
            nonflowing_read_consumed: _,
            lifecycle_label: _,
            to_array_waiter,
        } = state;
        self.value(source);
        read_callback
            .iter()
            .chain(destroy_error.iter())
            .for_each(|value| self.value(value));
        for chunk in buffer {
            let ReadableBufferedChunk {
                value,
                label: _,
                units: _,
            } = chunk;
            self.value(value);
        }
        if let Some(ReadableToArrayWaiter {
            promise,
            result,
            label: _,
        }) = to_array_waiter
        {
            self.promise(promise.0);
            self.object(*result);
        }
    }

    fn stream_pipeline(&mut self, state: &StreamPipelineState) {
        let StreamPipelineState {
            stages,
            pending_close,
            completion,
            registration_label: _,
            first_error,
            phase: _,
        } = state;
        stages
            .iter()
            .chain(pending_close.iter())
            .for_each(|id| self.object(*id));
        match completion {
            StreamPipelineCompletion::Callback(value) => self.value(value),
            StreamPipelineCompletion::Promise(promise) => self.promise(promise.0),
        }
        if let Some((value, _)) = first_error {
            self.value(value);
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
            phase,
            result_promise,
        } = function;
        // A running or suspended async function still settles its result
        // promise; a completed one never reads it again.
        if !matches!(phase, AsyncFunctionPhase::Completed) {
            self.promise(*result_promise);
        }
        if let Some(execution) = isolated_execution {
            self.generator_execution(execution);
        }
        if let Some(closure) = closure_index {
            self.closure(*closure);
        }
        saved_registers.iter().for_each(|value| self.value(value));
    }

    fn combinator(&mut self, state: &PromiseCombinatorState) {
        let result_promise = match state {
            PromiseCombinatorState::All(tracker) => tracker.result_promise,
            PromiseCombinatorState::AllSettled(tracker) => tracker.result_promise,
            PromiseCombinatorState::Race(tracker) => tracker.result_promise,
            PromiseCombinatorState::Any(tracker) => tracker.result_promise,
        };
        self.promise(result_promise.0);
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
        self.gc.builtin_depth_stack.push(self.gc.builtin_depth);
        self.gc.builtin_depth = 0;
    }

    pub(super) fn gc_exit_run_loop(&mut self) {
        self.gc.run_loop_depth = self.gc.run_loop_depth.saturating_sub(1);
        self.gc.builtin_depth = self.gc.builtin_depth_stack.pop().unwrap_or(0);
    }

    /// A builtin dispatch begins in the current run loop (bd-9vouw.77).
    pub(super) fn gc_enter_builtin(&mut self) {
        self.gc.builtin_depth = self.gc.builtin_depth.saturating_add(1);
    }

    pub(super) fn gc_exit_builtin(&mut self) {
        self.gc.builtin_depth = self.gc.builtin_depth.saturating_sub(1);
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

    /// Whether the event loop is between jobs after the script, with no run
    /// loop active: a job dispatched now is held only by its queue entry.
    pub(super) fn gc_in_event_loop_phase(&self) -> bool {
        self.gc.event_loop_armed && self.gc.run_loop_depth == 0
    }

    /// Whether the code running now is at a safe point context: the armed run
    /// loop itself, or the event loop between jobs.
    fn gc_context_is_safe(&self) -> bool {
        self.gc.safe_depth == Some(self.gc.run_loop_depth)
            || (self.gc.event_loop_armed && self.gc.run_loop_depth == 0)
    }

    /// Arm the next run loop entered for collection while the current one is
    /// suspended in a Rust frame (bd-9vouw.77). `pins` is everything that
    /// frame and its callers hold outside interpreter state; it stays rooted
    /// until `gc_disarm_nested`. Returns `None`, arming nothing, unless the
    /// current context is itself safe: a caller that is not at a safe point
    /// may hold unpinned values of its own.
    pub(super) fn gc_arm_nested(&mut self, pins: &[GcPin<'_>]) -> Option<NestedGcArm> {
        // A builtin dispatched from inside another builtin's Rust frame may
        // not arm: the outer builtin's locals are pinned by nobody.
        if !self.gc_context_is_safe() || self.gc.builtin_depth > 1 {
            return None;
        }
        let mut marker = self.gc_new_marker();
        let mut async_functions_from: Option<usize> = None;
        for pin in pins {
            match pin {
                GcPin::Value(value) => marker.value(value),
                GcPin::AsyncFunctionsFrom(id) => {
                    async_functions_from =
                        Some(async_functions_from.map_or(*id, |from| from.min(*id)));
                }
                GcPin::ModuleExecution(execution) => marker.module_execution(execution),
                GcPin::GeneratorExecution(execution) => marker.generator_execution(execution),
            }
        }
        self.gc.nested_pins.push(NestedPins {
            values: Self::gc_marked_values(&marker),
            async_functions_from,
        });
        let previous = self
            .gc
            .safe_depth
            .replace(self.gc.run_loop_depth.saturating_add(1));
        Some(NestedGcArm { previous })
    }

    /// Undo `gc_arm_nested` once the armed loop has returned.
    pub(super) fn gc_disarm_nested(&mut self, arm: Option<NestedGcArm>) {
        if let Some(NestedGcArm { previous }) = arm {
            self.gc.safe_depth = previous;
            self.gc.nested_pins.pop();
        }
    }

    fn gc_new_marker(&self) -> GcMarker {
        GcMarker::new(
            self.heap.len(),
            self.closures.len(),
            self.promise_store.slot_count(),
            self.async_functions.len(),
            self.iterators.len(),
            self.generators.len(),
            self.async_generators.len(),
        )
    }

    /// The values a marker marked directly, before draining: roots that pin
    /// everything reachable from them.
    fn gc_marked_values(marker: &GcMarker) -> Vec<Value> {
        marker
            .stack
            .iter()
            .map(|id| Value::Object(ObjectId(*id)))
            .chain(marker.closure_stack.iter().map(|id| Value::Closure(*id)))
            .chain(marker.promise_stack.iter().map(|id| Value::Promise(*id)))
            .chain(marker.iterator_stack.iter().map(|id| Value::Iterator(*id)))
            .chain(
                marker
                    .generator_stack
                    .iter()
                    .map(|id| Value::Generator(*id)),
            )
            .chain(
                marker
                    .async_generator_stack
                    .iter()
                    .map(|id| Value::AsyncGeneratorObject(*id)),
            )
            .collect()
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
        let mut marker = self.gc_new_marker();
        marker.module_execution(caller);
        let pinned = Self::gc_marked_values(&marker);
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
        let mut marker = GcMarker::new(
            self.heap.len(),
            self.closures.len(),
            self.promise_store.slot_count(),
            self.async_functions.len(),
            self.iterators.len(),
            self.generators.len(),
            self.async_generators.len(),
        );
        self.gc_mark_roots(&mut marker)?;
        self.gc_drain(&mut marker);
        self.gc_mark_ephemerons(&mut marker);

        #[cfg(debug_assertions)]
        let drift_before = self
            .estimated_memory_bytes
            .wrapping_sub(self.recompute_base_estimated_memory_bytes());

        let mut reclaimed_objects = 0u64;
        let mut reclaimed_bytes = 0u64;
        self.mutate_heap(|heap| {
            heap.sweep(
                |index| marker.objects.is_marked(index),
                |object| {
                    reclaimed_objects += 1;
                    reclaimed_bytes =
                        reclaimed_bytes.saturating_add(Self::estimate_heap_object_bytes(object));
                },
            );
        });
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(reclaimed_bytes);

        // Mutation labels of reclaimed objects can never be read again, but
        // they stay charged against the memory budget until purged.
        let heap = &self.heap;
        let mut released_label_bytes = 0u64;
        self.object_mutation_labels.retain(|id, label| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released_label_bytes = released_label_bytes
                    .saturating_add(Self::estimate_object_mutation_label_entry_bytes(label));
            }
            live
        });
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(released_label_bytes);
        reclaimed_bytes = reclaimed_bytes.saturating_add(released_label_bytes);

        // The state of reclaimed URL and URLSearchParams objects can never be
        // read again (bd-9vouw.163): drop it with its charge.
        let mut released_state_bytes = 0u64;
        self.url_objects.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released_state_bytes =
                    released_state_bytes.saturating_add(Self::estimate_url_state_bytes(state));
            }
            live
        });
        self.url_search_params.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released_state_bytes = released_state_bytes
                    .saturating_add(Self::estimate_url_search_params_state_bytes(state));
            }
            live
        });
        // So can a reclaimed crypto Hash, Hmac, Cipher or key pair's
        // (bytes and a label, no heap references).
        self.crypto_objects.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released_state_bytes = released_state_bytes
                    .saturating_add(Self::estimate_crypto_object_state_bytes(state));
            }
            live
        });
        // A reclaimed stream's terminal state had nothing pending (pending
        // ones are roots, bd-9vouw.164).
        self.writable_terminal_states.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released_state_bytes = released_state_bytes
                    .saturating_add(Self::estimate_writable_terminal_state_bytes(state));
            }
            live
        });
        self.readable_terminal_states.retain(|id, state| {
            let live = !heap.is_reclaimed(id.0 as usize);
            if !live {
                released_state_bytes = released_state_bytes
                    .saturating_add(Self::estimate_readable_terminal_state_bytes(state));
            }
            live
        });
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(released_state_bytes);
        reclaimed_bytes = reclaimed_bytes.saturating_add(released_state_bytes);

        // The write-barrier remembered set records objects written since the
        // last collection. A full collection leaves no younger generation, so
        // it restarts empty, as its contract states; nothing else clears it.
        self.gc_remembered_set.clear();

        // Closures: release unreachable captured environments and the
        // per-closure side-table entries, which no live value can reach
        // again. The closure, cold-cell and scope components move together,
        // so charge the exact difference of the recomputed estimate.
        let dead_closures = self
            .closures
            .live_indices()
            .filter(|index| !marker.closures.is_marked(*index))
            .collect::<Vec<_>>();
        let mut reclaimed_closures = 0u64;
        if !dead_closures.is_empty() {
            let before = self.recompute_base_estimated_memory_bytes();
            for index in dead_closures {
                if self.closures.reclaim(index) {
                    reclaimed_closures += 1;
                }
                let id = index as u32;
                self.closure_method_metadata.remove(&id);
                self.closure_lexical_super_metadata.remove(&id);
                self.arrow_lexical_this.remove(&id);
                self.closure_module_origins.remove(&id);
                self.closure_generated_function_artifacts.remove(&id);
            }
            let released = before.saturating_sub(self.recompute_base_estimated_memory_bytes());
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
            reclaimed_bytes = reclaimed_bytes.saturating_add(released);
        }

        // Generators nothing names can never be resumed: release their
        // retained invocation and suspended execution.
        let dead_generators = self
            .generators
            .iter_live()
            .filter(|(id, _)| !marker.generators.is_marked(*id))
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        let mut reclaimed_generators = 0u64;
        if !dead_generators.is_empty() {
            let before = self.recompute_base_estimated_memory_bytes();
            for id in dead_generators {
                if let Some(mut generator) = self.generators.reclaim(id) {
                    self.closures
                        .replace_activation(&mut generator.execution, None);
                    reclaimed_generators += 1;
                }
            }
            let released = before.saturating_sub(self.recompute_base_estimated_memory_bytes());
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
            reclaimed_bytes = reclaimed_bytes.saturating_add(released);
        }

        // Async generators nothing names that neither run, await nor hold
        // requests can never be resumed again.
        let dead_async_generators = self
            .async_generators
            .iter_live()
            .filter(|(id, _)| !marker.async_generators.is_marked(*id))
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        let mut reclaimed_async_generators = 0u64;
        if !dead_async_generators.is_empty() {
            let before = self.recompute_base_estimated_memory_bytes();
            for id in dead_async_generators {
                if self.async_generators.reclaim(id).is_some() {
                    reclaimed_async_generators += 1;
                }
            }
            let released = before.saturating_sub(self.recompute_base_estimated_memory_bytes());
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
            reclaimed_bytes = reclaimed_bytes.saturating_add(released);
        }

        // Iterators nothing names: their state (source array, captured
        // values, next method) is released.
        let dead_iterators = self
            .iterators
            .iter_live()
            .filter(|(id, _)| !marker.iterators.is_marked(*id))
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        let mut reclaimed_iterators = 0u64;
        if !dead_iterators.is_empty() {
            let before = self.recompute_base_estimated_memory_bytes();
            for id in dead_iterators {
                if self.iterators.reclaim(id).is_some() {
                    reclaimed_iterators += 1;
                }
            }
            let released = before.saturating_sub(self.recompute_base_estimated_memory_bytes());
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
            reclaimed_bytes = reclaimed_bytes.saturating_add(released);
        }

        // Completed async-function records no frame or continuation names:
        // nothing resumes or settles through them again.
        let dead_async_functions = self
            .async_functions
            .iter_live()
            .filter(|(id, function)| {
                matches!(function.phase, AsyncFunctionPhase::Completed)
                    && !marker.async_functions.is_marked(*id)
            })
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        let mut reclaimed_async_functions = 0u64;
        if !dead_async_functions.is_empty() {
            let before = self.recompute_base_estimated_memory_bytes();
            for id in dead_async_functions {
                if let Some(mut function) = self.async_functions.reclaim(id) {
                    self.closures
                        .replace_activation(&mut function.isolated_execution, None);
                    reclaimed_async_functions += 1;
                }
            }
            let released = before.saturating_sub(self.recompute_base_estimated_memory_bytes());
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
            reclaimed_bytes = reclaimed_bytes.saturating_add(released);
        }

        // Promise-value carriers no traced value names.
        let marked_carriers = std::mem::take(&mut marker.carriers);
        let mut released_carrier_bytes = 0u64;
        self.promise_value_carriers.retain(|id, value| {
            let live = marked_carriers.contains(id);
            if !live {
                released_carrier_bytes = released_carrier_bytes
                    .saturating_add(Self::estimate_promise_value_carrier_bytes(value));
            }
            live
        });
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(released_carrier_bytes);
        reclaimed_bytes = reclaimed_bytes.saturating_add(released_carrier_bytes);

        // Settled promises nothing reachable names: vacate their records
        // (values and reactions). Pending promises are roots.
        let before = self.promise_runtime_memory_bytes();
        let reclaimed_promises = self
            .promise_store
            .reclaim_settled(|handle| marker.promises.is_marked(handle.0 as usize));
        let released = before.saturating_sub(self.promise_runtime_memory_bytes());
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
        reclaimed_bytes = reclaimed_bytes.saturating_add(released);

        // Drain the running totals' dirty lists. They name every entry
        // borrowed mutably since the last re-derivation, and a loop that
        // never re-derives (no closure, promise or iterator to reclaim) grew
        // them by one id per object it wrote after allocating.
        self.heap.estimated_bytes();
        self.async_functions.estimated_bytes();
        self.iterators.estimated_bytes();
        self.generators.estimated_bytes();
        self.async_generators.estimated_bytes();

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
        stats.reclaimed_promises = stats.reclaimed_promises.saturating_add(reclaimed_promises);
        stats.reclaimed_async_functions = stats
            .reclaimed_async_functions
            .saturating_add(reclaimed_async_functions);
        stats.reclaimed_iterators = stats
            .reclaimed_iterators
            .saturating_add(reclaimed_iterators);
        stats.reclaimed_generators = stats
            .reclaimed_generators
            .saturating_add(reclaimed_generators);
        stats.reclaimed_async_generators = stats
            .reclaimed_async_generators
            .saturating_add(reclaimed_async_generators);

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
            if let Some(generator) = marker.generator_stack.pop() {
                if let Some(object) = self.generators.get(generator as usize) {
                    marker.generator(object);
                }
                continue;
            }
            if let Some(id) = marker.async_generator_stack.pop() {
                if let Some(generator) = self.async_generators.get(id as usize) {
                    marker.generator_id(generator.generator_id);
                    generator.for_each_value(|value| marker.value(value));
                    generator.for_each_promise(|handle| marker.promise(handle.0));
                }
                continue;
            }
            if let Some(iterator) = marker.iterator_stack.pop() {
                if let Some(state) = self.iterators.get(iterator as usize) {
                    marker.iterator(state);
                }
                continue;
            }
            if let Some(carrier) = marker.carrier_stack.pop() {
                if let Some(value) = self.promise_value_carriers.get(&carrier) {
                    marker.value(value);
                }
                continue;
            }
            if let Some(promise) = marker.promise_stack.pop() {
                self.promise_store.for_each_edge(
                    crate::promise_model::PromiseHandle(promise),
                    |edge| match edge {
                        PromiseEdge::Value(value) => marker.js_value(value),
                        PromiseEdge::Handler(handler) => marker.handler(handler),
                        PromiseEdge::Promise(derived) => marker.promise(derived.0),
                    },
                );
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
                class_fields,
                primitive_value,
                // A brand name: no references.
                brand: _,
                is_array: _,
                cached_dense_length: _,
                array_buffer: _,
                typed_array,
                data_view,
                is_frozen: _,
                is_non_extensible: _,
                is_import_meta: _,
                is_null_prototype: _,
                private_elements,
                // String keys and well-known Symbols: no references.
                deleted_virtual_keys: _,
                // Bytes and a type: no references.
                blob: _,
                // A pattern and flags: no references.
                regexp: _,
            } = object;
            for value in private_elements.values().flat_map(PrivateElement::values) {
                marker.value(value);
            }
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
            if let Some(fields) = class_fields {
                marker.value(fields);
            }
            if let Some(value) = primitive_value {
                marker.value(value);
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
            // A reachable URL keeps its searchParams object, and a reachable
            // URLSearchParams the URL it updates (bd-9vouw.163). Their state
            // holds no other heap reference.
            for (url, state) in &self.url_objects {
                if marker.is_marked(url.0) {
                    marker.object(state.search_params);
                }
            }
            for (params, state) in &self.url_search_params {
                if marker.is_marked(params.0)
                    && let Some(owner) = state.owner_url
                {
                    marker.object(owner);
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
            codegen_caller_grants: _,
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
            // Traced from the values and delegations that name them.
            iterators: _,
            // Weak: a reclaimed iterator or storage is pruned on the next
            // visit (bd-9vouw.131).
            collection_iterators: _,
            collection_for_each_cursors,
            iteration_traces: _,
            function_prototypes,
            // Digests of module headers: no references (bd-9vouw.124).
            prototype_owner_ids: _,
            builtin_function_backings: _,
            // A call counter; it holds no heap reference.
            promise_capability_executor_calls: _,
            virtual_property_deletions: _,
            builtin_prototypes,
            seed_epoch: _,
            // Seeds hold their own heap copies; restoring one replaces the
            // whole heap.
            pending_lazy_seeds: _,
            pending_arguments_object,
            argument_overflow,
            argument_overflow_bytes: _,
            execution_seed_reservation_ledger: _,
            ip: _,
            instructions_executed: _,
            native_hole_reads: _,
            // Instruction count at the last virtual-clock advance (bd-9vouw.59).
            virtual_clock_instruction_mark: _,
            tier_i_instructions_executed: _,
            tier_i_specialized_instructions_executed: _,
            // Evidence and telemetry records name ids but never dereference
            // them.
            witness_events: _,
            hostcall_decisions: _,
            folded_hostcall_decisions: _,
            recorded_effect_free_grants: _,
            // Compiled patterns hold no guest values.
            regexp_cache: _,
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
            register_width: _,
            native_run_loop_depth: _,
            stacked_register_frame_clear_width_high_water: _,
            top_level_compact_tier1: _,
            entry_frame_widths: _,
            catch_frames: _,
            pending_exception,
            pending_exception_label: _,
            pending_hostcall_result_label: _,
            // bd-9vouw.113: the last RegExp match is a copied string, spans
            // and a label; no heap references.
            legacy_regexp_match: _,
            legacy_regexp_generation: _,
            legacy_regexp_read_label: _,
            pending_return,
            suspended_abrupt_completions,
            finally_frames,
            pending_finally_entry: _,
            last_pre_run_seed: _,
            last_post_run_epoch: _,
            scope_chain,
            realm_dynamic_globals,
            realm_global_object,
            generated_function_realm_globals,
            generated_function_realm_generation: _,
            runtime_name_references,
            // Traced per live closure by `gc_trace_closure`.
            closures: _,
            closure_method_metadata: _,
            closure_lexical_super_metadata: _,
            // Per-module memo of IR headers and booleans (bd-9vouw.159).
            lexical_super_functions: _,
            arrow_lexical_this: _,
            closure_module_origins: _,
            closure_generated_function_artifacts: _,
            module_reentrant_call_depth: _,
            active_foreign_module_call_depth: _,
            isolated_async_entry_pending: _,
            gc_nested_request,
            pending_captures: _,
            // Traced from the values that name them.
            generators: _,
            generator_yielded: _,
            generator_resume_dst: _,
            generator_result_label: _,
            // A generator id (the object is traced from its value) and a flag.
            generator_prologue_pending: _,
            suspend_at_generator_prologue: _,
            generator_delegation,
            async_functions,
            async_resumption_contexts,
            top_level_await_resumption_contexts,
            top_level_await_outcome,
            async_generators,
            async_generator_runtime,
            promise_store,
            event_loop,
            promise_in_flight_task_bytes: _,
            promise_reaction_callables,
            // Traced from the promise values and jobs that name each carrier.
            promise_value_carriers: _,
            next_promise_value_carrier: _,
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
            // Weak: traced in gc_mark_ephemerons, purged after the sweep.
            url_objects: _,
            url_search_params: _,
            cluster_facades,
            // Weak: no heap references, purged after the sweep.
            crypto_objects: _,
            stream_pipelines,
            next_stream_pipeline_token: _,
            pending_stream_emissions,
            readable_from_streams,
            // Labels only; weak, purged after the sweep (bd-9vouw.164).
            readable_terminal_states: _,
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
            // A count; the ticks it counts are the terminal states'
            // tick_sequence, traced with them (bd-9vouw.164).
            pending_writable_terminal_ticks: _,
            next_writable_tick_sequence: _,
            next_writable_completion_token: _,
            promise_combinators,
            // Keyed by the promises they watch.
            promise_combinator_watchers,
            next_promise_combinator_id: _,
            module_state,
            pending_async_module_import,
            pending_cyclic_import_binding: _,
            active_cjs_context,
            current_module_specifier: _,
            active_generated_function_artifact: _,
            entry_module_specifier: _,
            console_output: _,
            console_output_bytes: _,
            // Labels, counts and timer ticks: no heap references.
            console_group_depth: _,
            console_counts: _,
            console_timers: _,
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
            // and ids are never reused. `collect_garbage` purges the
            // mutation labels of reclaimed objects.
            object_mutation_labels: _,
            active_inline_callback_context_label: _,
            inline_callback_start_probes: _,
            proxy_trap_lookup_depth: _,
            weakmap_storage: _,
            symbol_state: _,
            // Ids only; cleared by `collect_garbage`.
            gc_remembered_set: _,
            jit_function_call_counts: _,
            jit_loop_iteration_counts: _,
            jit_hot_threshold: _,
            jit_eviction_counter: _,
            gc: _,
        } = self;

        // Host I/O state is not traced yet: refuse to collect while any of it
        // is live.
        let host_state: [(&'static str, bool); 14] = [
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
            if let Some(global) = realm_global_object {
                m.object(*global);
            }
        }
        if let Some((_, value, _)) = pending_arguments_object {
            m.value(value);
        }
        // Every active call site's out-of-band arguments (bd-9vouw.50): an
        // outer builtin may read its list again after a nested call returns.
        argument_overflow
            .iter()
            .flat_map(|overflow| overflow.values.iter())
            .for_each(|value| m.value(value));
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
        self.gc.pinned.iter().for_each(|value| m.value(value));
        self.gc
            .pinned_values
            .iter()
            .for_each(|value| m.value(value));
        self.gc
            .nested_pins
            .iter()
            .flat_map(|pins| pins.values.iter())
            .chain(gc_nested_request.iter().flatten())
            .for_each(|value| m.value(value));
        if let Some(from) = self
            .gc
            .nested_pins
            .iter()
            .filter_map(|pins| pins.async_functions_from)
            .min()
        {
            for (id, function) in async_functions.iter_live() {
                if id >= from {
                    m.async_functions.mark(id);
                    m.async_function(function);
                }
            }
        }

        // Intrinsics.
        function_prototypes.values().for_each(|id| m.object(*id));
        builtin_prototypes.values().for_each(|id| m.object(*id));
        // A forEach in progress keeps its collection's storage.
        collection_for_each_cursors
            .iter()
            .for_each(|(storage, _)| m.object(*storage));

        // Tables whose entries are never reclaimed. Closures are traced from
        // the values that reference them (`gc_trace_closure`).
        m.delegation(generator_delegation);
        async_functions
            .iter()
            .for_each(|function| m.async_function(function));
        if let Some(Ok(completion)) = top_level_await_outcome {
            m.labeled_return(completion);
        }
        // An async generator that runs, awaits or has queued requests will
        // resume. Otherwise only a value naming it keeps it.
        for (id, generator) in async_generators.iter_live() {
            if generator.pending() {
                m.async_generator(id as u32);
            }
        }
        if let Some(id) = async_generator_runtime.active {
            m.async_generator(id);
        }
        async_generator_runtime.for_each_generator(|id| m.async_generator(id));
        async_generator_runtime.for_each_value(|value| m.value(value));

        // Promises and queued work, including the handlers they will call.
        // A settled promise is kept only when something reachable names it;
        // its value is traced from the promise.
        promise_store.for_each_root(|handle| m.promise(handle.0));
        event_loop
            .microtasks
            .for_each_promise(|handle| m.promise(handle.0));
        async_resumption_contexts
            .keys()
            .chain(top_level_await_resumption_contexts.keys())
            .for_each(|handle| m.promise(*handle));
        for context in async_resumption_contexts.values() {
            m.async_functions.mark(context.async_function_id as usize);
        }
        promise_combinator_watchers
            .keys()
            .for_each(|handle| m.promise(handle.0));
        if let Some((_, handle)) = pending_async_module_import {
            m.promise(handle.0);
        }
        async_generator_runtime.for_each_promise(|handle| m.promise(handle.0));
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
                PendingTimerTaskKind::PromiseResolve { promise, value, .. } => {
                    m.promise(promise.0);
                    m.js_value(value);
                }
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
        for (emitter, waiters) in event_promise_waiters {
            m.object(*emitter);
            for record in waiters.values().flatten() {
                m.promise(record.promise.0);
            }
        }

        // Streams, pipelines and the cluster facade (bd-9vouw.164): live
        // state is a root while its entry exists (pending callbacks, queued
        // chunks, scheduled ticks and emissions run against these objects).
        // A terminal state with nothing pending is weak: purged with its
        // charge once its stream is reclaimed.
        for (stream, state) in writable_streams {
            m.object(*stream);
            m.writable_state(state);
        }
        for (stream, state) in writable_terminal_states {
            if state.tick_sequence.is_some() || !state.callbacks.is_empty() {
                m.object(*stream);
                m.writable_terminal_state(state);
            }
        }
        for state in stream_pipelines.values() {
            m.stream_pipeline(state);
        }
        for emission in pending_stream_emissions.values() {
            let PendingStreamEmission {
                object_id,
                phase: _,
            } = emission;
            m.object(*object_id);
        }
        for (stream, state) in readable_from_streams {
            m.object(*stream);
            m.readable_from_state(state);
        }
        pending_readable_from_pumps
            .values()
            .for_each(|stream| m.object(*stream));
        readable_pump_reservations
            .keys()
            .for_each(|stream| m.object(*stream));
        if let Some(target) = active_readable_listener_target {
            m.object(*target);
        }
        for (source, link) in readable_pipe_links {
            let ReadablePipeLink {
                destination,
                token: _,
            } = link;
            m.object(*source);
            m.object(*destination);
        }
        for (destination, source) in readable_pipe_sources {
            m.object(*destination);
            m.object(*source);
        }
        for (facade, state) in cluster_facades {
            let ClusterRuntimeState {
                settings,
                lifecycle_label: _,
            } = state;
            m.object(*facade);
            m.object(*settings);
        }

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
            if let Some(handle) = record.evaluation_promise {
                m.promise(handle.0);
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

    /// Only the outermost builtin at a run-loop level may arm a nested loop
    /// (bd-9vouw.77). A builtin dispatched from inside another builtin's Rust
    /// frame would leave the outer builtin's locals unpinned. A nested run
    /// loop starts with no active builtins of its own.
    #[test]
    fn only_the_outermost_builtin_of_a_run_loop_arms() {
        let mut core = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "gc-unit");
        core.gc_enter_run_loop();
        core.gc.safe_depth = Some(1);
        core.gc_enter_builtin();
        let arm = core.gc_arm_nested(&[]);
        assert!(arm.is_some(), "the outermost builtin arms");
        core.gc_disarm_nested(arm);
        core.gc_enter_builtin();
        assert!(
            core.gc_arm_nested(&[]).is_none(),
            "a nested builtin must not arm"
        );
        core.gc_exit_builtin();

        core.gc_enter_run_loop();
        core.gc.safe_depth = Some(2);
        core.gc_enter_builtin();
        let arm = core.gc_arm_nested(&[]);
        assert!(arm.is_some(), "the armed nested loop's own builtin arms");
        core.gc_disarm_nested(arm);
        core.gc_exit_builtin();
        core.gc_exit_run_loop();
        assert_eq!(
            core.gc.builtin_depth, 1,
            "the outer loop's count is restored"
        );
        core.gc_exit_builtin();
        core.gc_exit_run_loop();
        assert_eq!(core.gc.builtin_depth, 0);
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

    /// Memory follows the live set: every full chunk whose objects were all
    /// reclaimed is released, and the heap stays usable (ids keep counting,
    /// rollback truncation still crosses released chunks).
    #[test]
    fn fully_reclaimed_chunks_are_released() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [RuntimeCapability::HeapAllocate].into_iter().collect();
        let mut core = InterpreterCore::new(config, "gc-unit");
        let holder = core.alloc_object_with_prototype(None).expect("holder");
        let first_garbage = core.heap.len();
        for _ in 0..10 * HEAP_CHUNK_SLOTS {
            core.alloc_object_with_prototype(None).expect("garbage");
        }
        let end = core.heap.len();
        let full_garbage_chunks: Vec<usize> =
            (first_garbage.div_ceil(HEAP_CHUNK_SLOTS)..end / HEAP_CHUNK_SLOTS).collect();
        assert!(full_garbage_chunks.len() >= 9);
        let resident_before = core.heap.resident_chunks();

        core.set_reg(0, Value::Object(holder));
        core.collect_garbage().expect("collection runs");

        for chunk in &full_garbage_chunks {
            assert!(core.heap.chunks[*chunk].is_none(), "chunk {chunk} kept");
        }
        assert_eq!(
            core.heap.resident_chunks(),
            resident_before - full_garbage_chunks.len()
        );
        assert!(
            core.heap.get(holder.0 as usize).is_some(),
            "holder reclaimed"
        );
        let dead = full_garbage_chunks[0] * HEAP_CHUNK_SLOTS;
        assert!(core.heap.is_reclaimed(dead));
        assert_eq!(core.heap.len(), end, "ids are never reused");

        let fresh = core.alloc_object_with_prototype(None).expect("fresh");
        assert_eq!(fresh.0 as usize, end);
        assert!(core.heap.get(end).is_some());

        // A transactional rollback truncates back into a released chunk.
        let mut heap = core.heap.clone();
        let rollback_len = dead + 7;
        heap.truncate(rollback_len);
        assert_eq!(heap.len(), rollback_len);
        assert!(heap.is_reclaimed(dead));
        heap.push(heap[holder.0 as usize].clone());
        assert!(heap.get(rollback_len).is_some());
        assert_eq!(heap.len(), rollback_len + 1);
    }

    /// A reclaimed object's IFC mutation label is purged and its charge
    /// released; a live object keeps its label.
    #[test]
    fn mutation_labels_of_reclaimed_objects_are_purged() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [RuntimeCapability::HeapAllocate].into_iter().collect();
        let mut core = InterpreterCore::new(config, "gc-unit");
        let holder = core.alloc_object_with_prototype(None).expect("holder");
        let garbage = core.alloc_object_with_prototype(None).expect("garbage");
        for id in [holder, garbage] {
            core.join_direct_object_mutation_label(id, &Label::Secret)
                .expect("label charge");
        }
        let charged = core.object_mutation_labels_memory_bytes();
        assert!(charged > 0);
        core.set_reg(0, Value::Object(holder));
        core.collect_garbage().expect("collection runs");
        assert_eq!(
            core.object_mutation_labels.get(&holder),
            Some(&Label::Secret)
        );
        assert!(!core.object_mutation_labels.contains_key(&garbage));
        assert_eq!(core.object_mutation_labels_memory_bytes(), charged / 2);
    }

    /// Before collections existed the write-barrier remembered set only
    /// grew: one entry per object ever written. A collection clears it.
    #[test]
    fn collection_clears_the_remembered_set() {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [RuntimeCapability::HeapAllocate].into_iter().collect();
        let mut core = InterpreterCore::new(config, "gc-unit");
        let holder = core.alloc_object_with_prototype(None).expect("holder");
        let garbage = core.alloc_object_with_prototype(None).expect("garbage");
        core.gc_write_barrier(holder);
        core.gc_write_barrier(garbage);
        assert_eq!(core.gc_remembered_set_size(), 2);
        core.set_reg(0, Value::Object(holder));
        core.collect_garbage().expect("collection runs");
        assert_eq!(core.gc_remembered_set_size(), 0);
        assert!(
            core.heap.get(holder.0 as usize).is_some(),
            "holder reclaimed"
        );
    }

    /// A dead arrow closure used to stay charged forever: its 32-byte entry
    /// plus its lexical-`this` side-table entry (48+ bytes), so 8,000 of them
    /// (at least 640 KB) could not fit a 256 KiB budget with nothing live. Now
    /// the loop completes, the side table holds only live closures, and fully
    /// dead closure chunks are released.
    #[test]
    fn dead_closures_release_their_charge_side_tables_and_chunks() {
        let source =
            "let s = 0; for (let i = 0; i < 8000; i++) { const f = () => i; s += f() & 1; } s";
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
        config.max_total_memory_bytes = 256 * 1024;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "gc-unit");
        let result = core.execute(&module).expect("execute");
        assert_eq!(result.value, Value::Int(4000));
        let stats = core.gc_stats();
        assert!(stats.reclaimed_closures >= 6_000, "{stats:?}");
        assert!(core.closures.len() >= 8_000);
        assert!(
            core.arrow_lexical_this.len() < 2 * CLOSURE_CHUNK_SLOTS,
            "lexical-this entries of dead closures kept: {}",
            core.arrow_lexical_this.len()
        );
        let resident = core.closures.chunks.iter().flatten().count();
        assert!(
            resident <= 3 && core.closures.chunks.len() >= 8,
            "{resident} of {} closure chunks resident",
            core.closures.chunks.len()
        );
    }

    /// `ReclaimableTable`: ids are never reused, a reclaimed id reads as
    /// `None`, a fully reclaimed chunk is released, popping back into a
    /// released chunk works, and the running byte total re-measures entries
    /// borrowed mutably since the last read.
    #[test]
    fn reclaimable_table_releases_chunks_and_tracks_bytes() {
        // An entry's "size" is its value.
        fn measure(value: &u64) -> u64 {
            *value
        }
        let mut table: ReclaimableTable<u64> = ReclaimableTable::new("entry", measure);
        for _ in 0..3 * TABLE_CHUNK_SLOTS {
            table.push(2);
        }
        assert_eq!(table.estimated_bytes(), 6 * TABLE_CHUNK_SLOTS as u64);
        table[5] += 1;
        assert_eq!(table.estimated_bytes(), 6 * TABLE_CHUNK_SLOTS as u64 + 1);
        for id in TABLE_CHUNK_SLOTS..2 * TABLE_CHUNK_SLOTS {
            assert!(table.reclaim(id).is_some());
        }
        assert!(table.chunks[1].is_none(), "fully reclaimed chunk kept");
        assert!(table.get(TABLE_CHUNK_SLOTS).is_none());
        assert_eq!(table.len(), 3 * TABLE_CHUNK_SLOTS);
        assert_eq!(table.estimated_bytes(), 4 * TABLE_CHUNK_SLOTS as u64 + 1);
        assert_eq!(table.iter().count(), 2 * TABLE_CHUNK_SLOTS);
        // Roll back into the released chunk, then keep allocating.
        while table.len() > TABLE_CHUNK_SLOTS + 3 {
            table.pop();
        }
        assert!(table.get(TABLE_CHUNK_SLOTS + 1).is_none());
        table.push(7);
        assert_eq!(table[TABLE_CHUNK_SLOTS + 3], 7);
        assert_eq!(table.estimated_bytes(), 2 * TABLE_CHUNK_SLOTS as u64 + 8);
    }

    /// Completed async-function records are reclaimed: an await loop keeps
    /// only the records still running or suspended.
    #[test]
    fn completed_async_function_records_are_reclaimed() {
        let source = "let s = 0; async function f(i) { return i; } \
                      (async () => { for (let i = 0; i < 3000; i++) { s += await f(i); } })(); s";
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
        core.set_gc_stress_interval(Some(64));
        core.execute(&module).expect("execute");
        let stats = core.gc_stats();
        assert!(core.async_functions.len() >= 3000);
        assert!(
            stats.reclaimed_async_functions >= 2000,
            "reclaimed only {} async records",
            stats.reclaimed_async_functions
        );
        assert!(core.async_functions.live < core.async_functions.len() / 2);
    }

    /// Every object written after allocation is listed as dirty for the
    /// running heap byte total. A loop that never re-derives memory used to
    /// grow that list by one id per iteration forever; each collection now
    /// drains it.
    #[test]
    fn collections_drain_the_heap_dirty_list() {
        let source = "let s = 0; for (let i = 0; i < 20000; i++) { \
                      const o = { p: { i } }; s += o.p.i & 1; } s";
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
        config.max_heap_objects = 2_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "gc-unit");
        let result = core.execute(&module).expect("execute");
        assert_eq!(result.value, Value::Int(10000));
        assert!(core.gc_stats().collections >= 10);
        // Bounded by what was written since the last collection, not by the
        // 40,000 objects allocated.
        let dirty = core.heap.dirty.borrow().len();
        assert!(dirty < 2_000, "{dirty} dirty heap ids retained");
    }

    /// Each `await` registered an internal reaction promise as the key of
    /// its resumption context and never settled it, so it stayed a root:
    /// one promise record per await, retained after every collection. Once
    /// the awaiting code resumes, the carrier is removed.
    #[test]
    fn resumed_awaits_leave_no_promise_records_behind() {
        let source = "async function f(i) { return i; } (async () => { let s = 0; \
                      for (let i = 0; i < 3000; i++) { s += await f(i); } })(); 0";
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
        core.execute(&module).expect("execute");
        assert!(core.promise_store.slot_count() >= 6_000);
        core.collect_garbage().expect("collection runs");
        let retained = core.promise_store.len();
        assert!(retained < 16, "{retained} promise records retained");
        assert!(core.async_resumption_contexts.is_empty());
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
