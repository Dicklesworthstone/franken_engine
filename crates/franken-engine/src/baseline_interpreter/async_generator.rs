//! Executable async generators over the engine's ordinary generator activations.
//!
//! The activation owns language state; this module owns the FIFO request queue
//! and connects each suspension to the existing Promise job queue. No second
//! interpreter, event loop, or unaccounted saved-register representation exists.

use super::*;
use crate::object_model::JsValue;
use crate::promise_model::PromiseHandle;

mod delegation;
use delegation::{AsyncDelegateStage, AsyncDelegateState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AsyncGeneratorPhase {
    SuspendedStart,
    SuspendedYield,
    SuspendedAwait,
    Executing,
    Completed,
}

#[derive(Debug, Clone)]
pub(super) struct AsyncGeneratorRequest {
    kind: GeneratorResumeKind,
    argument: Value,
    label: Label,
    promise: PromiseHandle,
}

#[derive(Debug, Clone)]
pub(super) struct AsyncGeneratorObject {
    /// Index into the canonical generator activation store. Never guest-visible.
    pub(super) generator_id: u32,
    pub(super) phase: AsyncGeneratorPhase,
    pub(super) requests: VecDeque<AsyncGeneratorRequest>,
    /// Body-level `await` transfers its operand here before saving the frame.
    pub(super) awaited: Option<LabeledReturn>,
    pub(super) awaited_kind: AwaitKind,
    pub(super) delegation: Option<AsyncDelegateState>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum AwaitKind {
    Body,
    Yield,
    ReturnArgument,
    ReturnResult,
    DelegateResult,
    DelegateSyncValue,
    DelegateYield,
    DelegateClose,
    DelegateMissingReturn,
}

#[derive(Debug, Clone)]
pub(super) struct AsyncGeneratorContinuation {
    generator_id: u32,
    kind: AwaitKind,
    /// Set before publication. Retain the ticket after the dispatcher removes
    /// this context from the index so cancellation can close that Promise too.
    ticket: Option<PromiseHandle>,
    /// Internal PromiseResolve/primitive wrapper owned by this await. A caller's
    /// existing Promise is borrowed and must never be cancelled with its waiter.
    owned_source: Option<PromiseHandle>,
    /// A non-Promise primitive need not travel through the narrower JsValue
    /// carrier. Preserve exact UTF-16, callable identity and BigInt while the
    /// internal Promise reaction supplies the mandatory asynchronous boundary.
    exact_value: Option<Value>,
}

#[derive(Debug, Default)]
pub(super) struct AsyncGeneratorRuntime {
    pub(super) active: Option<u32>,
    pub(super) continuations: BTreeMap<u32, AsyncGeneratorContinuation>,
}

impl InterpreterCore {
    pub(super) fn create_async_generator(
        &mut self,
        owner_module: Arc<Ir3Module>,
        invocation: GeneratorInvocation,
    ) -> Result<u32, InterpreterError> {
        let generator_id = self.push_generator_object(GeneratorObject {
            owner_module,
            invocation: Some(invocation),
            execution: None,
            resume_dst: None,
            phase: GeneratorPhase::SuspendedStart,
        })?;
        match self.push_async_generator_object(AsyncGeneratorObject {
            generator_id,
            phase: AsyncGeneratorPhase::SuspendedStart,
            requests: VecDeque::new(),
            awaited: None,
            awaited_kind: AwaitKind::Body,
            delegation: None,
        }) {
            Ok(id) => Ok(id),
            Err(error) => {
                self.pop_generator_object_and_release();
                Err(error)
            }
        }
    }

    pub(super) fn dispatch_async_generator_resume(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let receiver = receiver.unwrap_or(Value::Undefined);
        let mut label = self.join_arg_range_label(args)?;
        if let Some(reg) = receiver_register {
            label =
                self.join_owned_label_with_temporary_budget(label, self.get_register_label(reg)?)?;
        }
        let Value::AsyncGeneratorObject(id) = receiver else {
            // Unlike synchronous generator methods, async methods reject their
            // returned Promise for a receiver-brand failure.
            let error = InterpreterError::TypeError {
                expected: "async generator receiver".into(),
                got: receiver.type_name().into(),
            };
            let reason = self.native_error_to_thrown_value(&error)?;
            let promise =
                self.create_rejected_promise(Self::value_to_js_value(&reason), label.clone())?;
            self.replace_pending_hostcall_result_label(Some(label))?;
            return Ok(Value::Promise(promise.0));
        };
        let argument = if args.count == 0 {
            Value::Undefined
        } else {
            self.read_reg(args.start)?
        };
        let resume = match kind {
            BuiltinFunctionKind::AsyncGeneratorNext => GeneratorResumeKind::Next,
            BuiltinFunctionKind::AsyncGeneratorReturn => GeneratorResumeKind::Return,
            BuiltinFunctionKind::AsyncGeneratorThrow => GeneratorResumeKind::Throw,
            _ => unreachable!("finite async generator method dispatcher"),
        };
        let promise =
            self.enqueue_async_generator_request(module, id, resume, argument, label.clone())?;
        self.replace_pending_hostcall_result_label(Some(label))?;
        Ok(promise)
    }

    pub(super) fn enqueue_async_generator_request(
        &mut self,
        module: &Ir3Module,
        id: u32,
        kind: GeneratorResumeKind,
        argument: Value,
        label: Label,
    ) -> Result<Value, InterpreterError> {
        if self.async_generators.get(id as usize).is_none() {
            return Err(InterpreterError::InternalError {
                details: format!("missing async generator {id}"),
            });
        }
        self.check_async_generator_cancellation(id)?;
        let promise = self.create_promise()?;
        let previous = self.async_generators_memory_bytes();
        self.async_generators[id as usize]
            .requests
            .push_back(AsyncGeneratorRequest {
                kind,
                argument,
                label,
                promise,
            });
        let next = self.async_generators_memory_bytes();
        if let Err(error) = self.apply_memory_component_delta(previous, next) {
            self.async_generators[id as usize].requests.pop_back();
            self.rollback_fresh_promise(promise);
            return Err(error);
        }
        if let Err(error) = self.drain_async_generator_requests(module, id) {
            self.abort_async_generator(id);
            return Err(error);
        }
        Ok(Value::Promise(promise.0))
    }

    fn drain_async_generator_requests(
        &mut self,
        module: &Ir3Module,
        id: u32,
    ) -> Result<(), InterpreterError> {
        loop {
            self.check_async_generator_cancellation(id)?;
            let generator = &self.async_generators[id as usize];
            if matches!(
                generator.phase,
                AsyncGeneratorPhase::Executing | AsyncGeneratorPhase::SuspendedAwait
            ) || generator.requests.is_empty()
            {
                return Ok(());
            }
            let request = generator.requests.front().expect("nonempty request queue");
            self.check_temporary_memory_budget(Self::async_generator_request_bytes(request))?;
            let request = request.clone();
            let phase = generator.phase;
            let backing = generator.generator_id;
            self.async_generators[id as usize].phase = AsyncGeneratorPhase::Executing;
            if phase == AsyncGeneratorPhase::Completed
                || (phase == AsyncGeneratorPhase::SuspendedStart
                    && request.kind != GeneratorResumeKind::Next)
            {
                self.complete_async_generator_activation(id);
                if request.kind == GeneratorResumeKind::Return {
                    return self.await_async_generator_value(
                        id,
                        AwaitKind::ReturnResult,
                        request.argument,
                        request.label,
                    );
                }
                self.settle_async_generator_request(
                    id,
                    if request.kind == GeneratorResumeKind::Throw {
                        Err(request.argument)
                    } else {
                        Ok(Value::Undefined)
                    },
                    true,
                    request.label,
                )?;
                continue;
            }
            if request.kind == GeneratorResumeKind::Return {
                // AsyncGeneratorYield awaits a return completion's value before
                // injecting it. Rejection is thrown at the suspended yield, so
                // the body's catch/finally machinery remains authoritative.
                return self.await_async_generator_value(
                    id,
                    AwaitKind::ReturnArgument,
                    request.argument,
                    request.label,
                );
            }
            debug_assert_ne!(
                self.generators[backing as usize].phase,
                GeneratorPhase::Completed
            );
            self.step_async_generator(module, id, request.kind, request.argument, request.label)?;
        }
    }

    fn step_async_generator(
        &mut self,
        module: &Ir3Module,
        id: u32,
        kind: GeneratorResumeKind,
        argument: Value,
        label: Label,
    ) -> Result<(), InterpreterError> {
        self.async_generators[id as usize].phase = AsyncGeneratorPhase::Executing;
        let backing = self.async_generators[id as usize].generator_id;
        // Keep the resumption's security floor alive across frame restoration.
        // A native language error has no value register from which to recover it.
        let saved_label_bytes = Self::estimate_label_bytes(&label);
        self.json_reserve_temporary(saved_label_bytes)?;
        let outcome = self.generator_resume_with_async(
            module,
            backing,
            kind,
            argument,
            label.clone(),
            Some(id),
        );
        self.json_release_temporary(saved_label_bytes);
        match outcome {
            Ok((result, result_label)) => {
                if let Some(awaited) = self.async_generators[id as usize].awaited.take() {
                    if matches!(
                        self.async_generators[id as usize].awaited_kind,
                        AwaitKind::DelegateYield
                    ) {
                        // Async yield* forwards IteratorValue unchanged. Unlike
                        // ordinary `yield`, it does not implicitly Await it;
                        // the AsyncFromSync adapter already unwraps sync values.
                        return self.settle_async_generator_request(
                            id,
                            Ok(awaited.value),
                            false,
                            awaited.label,
                        );
                    }
                    return self.await_async_generator_value(
                        id,
                        self.async_generators[id as usize].awaited_kind,
                        awaited.value,
                        awaited.label,
                    );
                }
                let Value::Object(result_id) = result else {
                    return Err(InterpreterError::InternalError {
                        details: "generator continuation returned no iterator result".into(),
                    });
                };
                let value = self.heap[result_id.0 as usize]
                    .properties
                    .get("value")
                    .cloned()
                    .unwrap_or(Value::Undefined);
                let done = self.generators[backing as usize].phase == GeneratorPhase::Completed;
                self.await_async_generator_value(
                    id,
                    if done {
                        AwaitKind::ReturnResult
                    } else {
                        AwaitKind::Yield
                    },
                    value,
                    result_label,
                )
            }
            Err(error)
                if matches!(error, InterpreterError::UncaughtException { .. })
                    || Self::js_catchable_error_name(&error).is_some() =>
            {
                let rejection = self.async_generator_exception(error, &label)?;
                self.complete_async_generator_activation(id);
                self.settle_async_generator_request(
                    id,
                    Err(rejection.value),
                    true,
                    rejection.label,
                )
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn suspend_async_generator_await(
        &mut self,
        id: u32,
        register: u32,
    ) -> Result<(), InterpreterError> {
        let value = self.read_reg(register)?;
        let mut label = self.clone_register_label_with_temporary_budget(register)?;
        if let Some(context) = &self.active_inline_callback_context_label {
            label = self.join_owned_label_with_temporary_budget(label, context)?;
        }
        let previous = self.async_generators_memory_bytes();
        self.async_generators[id as usize].awaited_kind = AwaitKind::Body;
        self.async_generators[id as usize].awaited = Some(LabeledReturn {
            value,
            label: label.clone(),
        });
        let next = self.async_generators_memory_bytes();
        if let Err(error) = self.apply_memory_component_delta(previous, next) {
            self.async_generators[id as usize].awaited = None;
            return Err(error);
        }
        self.generator_yielded = true;
        self.generator_resume_dst = Some(register);
        self.generator_result_label = label;
        self.ip += 1;
        Ok(())
    }

    fn await_async_generator_value(
        &mut self,
        id: u32,
        kind: AwaitKind,
        value: Value,
        mut label: Label,
    ) -> Result<(), InterpreterError> {
        self.check_async_generator_cancellation(id)?;
        // Await argument conversion is observable. In particular, a completed
        // generator's .return(thenable) must not let a reentrant .next() drain
        // the still-active return request while its then getter is executing.
        self.async_generators[id as usize].phase = AsyncGeneratorPhase::Executing;
        let mut owned_source = None;
        let outcome = (|| {
            let exact_value;
            let source = match value {
                Value::Promise(handle) => {
                    exact_value = None;
                    PromiseHandle(handle)
                }
                Value::Object(object) => {
                    exact_value = None;
                    let (promise, observed_label) =
                        self.async_generator_thenable_source(id, object, &label)?;
                    label = observed_label;
                    owned_source = Some(promise);
                    promise
                }
                other => {
                    exact_value = Some(other);
                    let promise =
                        self.create_fulfilled_promise(JsValue::Undefined, label.clone())?;
                    owned_source = Some(promise);
                    promise
                }
            };
            // A getter may have run since the entry check. Its effects remain
            // real, but a now-cancelled evaluation must not install a new await.
            self.check_async_generator_cancellation(id)?;
            let mut context = AsyncGeneratorContinuation {
                generator_id: id,
                kind,
                ticket: None,
                owned_source,
                exact_value,
            };
            let context_bytes = Self::async_generator_continuation_bytes(&context);
            // A mere temporary check lets the Promise reaction consume the
            // same headroom before the context is installed. Reserve ownership
            // first, so the reaction preflight sees their combined footprint.
            self.apply_memory_component_delta(0, context_bytes)?;
            let ticket = match self.register_promise_then_for_await(source, label) {
                Ok(ticket) => ticket,
                Err(error) => {
                    self.estimated_memory_bytes =
                        self.estimated_memory_bytes.saturating_sub(context_bytes);
                    return Err(error);
                }
            };
            context.ticket = Some(ticket);
            self.async_generator_runtime
                .continuations
                .insert(ticket.0, context);
            self.async_generators[id as usize].phase = AsyncGeneratorPhase::SuspendedAwait;
            // The reserved bytes now belong to the published continuation.
            // Reconcile any operand ownership transferred out of the activation.
            self.sync_estimated_memory_bytes()?;
            Ok(())
        })();
        if outcome.is_err() {
            // PromiseResolve can succeed before continuation admission fails.
            // Do not roll back the heap or newer getter-created Promises; close
            // only our internal source, then retire the failed activation.
            if let Some(source) = owned_source
                && let Ok(epoch) = self
                    .promise_store
                    .terminally_reject_without_jobs(source, &Label::Public)
            {
                self.close_terminal_async_promise_dependencies(epoch, &Label::Public);
            }
            self.abort_async_generator(id);
        }
        outcome
    }

    /// PromiseResolve's Get(then) must use the native property machinery, not
    /// the own-data-only helper used by the legacy Promise callback subset.
    /// Read it exactly once under the await context, including prototype and
    /// getter provenance, and feed closure thenables to the existing job queue.
    /// Return the observation label separately: the await reaction must retain
    /// it even when a resolving capability later supplies a public value.
    fn async_generator_thenable_source(
        &mut self,
        id: u32,
        object: ObjectId,
        floor: &Label,
    ) -> Result<(PromiseHandle, Label), InterpreterError> {
        let backing = self.async_generators[id as usize].generator_id;
        let owner = Arc::clone(&self.generators[backing as usize].owner_module);
        let context = self.json_parse_context_label()?;
        let context = self.join_owned_label_with_temporary_budget(context, floor)?;
        let saved_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        self.json_reserve_temporary(saved_bytes)?;
        if let Err(error) =
            self.apply_memory_component_delta(saved_bytes, Self::estimate_label_bytes(&context))
        {
            self.json_release_temporary(saved_bytes);
            return Err(error);
        }
        let saved_context = self.active_inline_callback_context_label.replace(context);
        let outcome = (|| {
            self.json_charge_work()?;
            let promise = self.create_promise()?;
            let resolution = (|| {
                let key = self.executable_property_key_from_value(&Value::str("then"));
                self.reflect_observe_selected_property(object, &key)?;
                let then = self.iterator_protocol_property(
                    Some(owner.as_ref()),
                    object,
                    &key,
                    Value::Object(object),
                )?;
                let then_bytes = Self::estimate_value_bytes(&then);
                self.json_reserve_temporary(then_bytes)?;
                let resolution = (|| {
                    self.observe_scoped_callback_result()?;
                    let label = self.json_parse_context_label()?;
                    if let Value::Closure(then_id) = then {
                        self.enqueue_resolve_thenable(
                            promise,
                            crate::closure_model::ClosureHandle(then_id),
                            Value::Object(object),
                            label.clone(),
                        )?;
                    } else {
                        // Preserve the shared Promise lane's callable coverage.
                        // Never look up then twice: a getter can replace itself.
                        self.fulfill_promise(
                            promise,
                            Self::value_to_js_value(&Value::Object(object)),
                            label.clone(),
                        )?;
                    }
                    Ok(label)
                })();
                self.json_release_temporary(then_bytes);
                resolution
            })();
            let resolution = match resolution {
                Ok(label) => Ok(label),
                Err(error) => match self.async_generator_exception(error, floor) {
                    Ok(rejection) => self
                        .reject_promise(
                            promise,
                            Self::value_to_js_value(&rejection.value),
                            rejection.label.clone(),
                        )
                        .map(|()| rejection.label),
                    Err(error) => Err(error),
                },
            };
            match resolution {
                Ok(label) => Ok((promise, label)),
                Err(error) => {
                    // This internal Promise is not yet owned by an await
                    // continuation. Close it explicitly on resource failure.
                    if let Ok(epoch) = self
                        .promise_store
                        .terminally_reject_without_jobs(promise, floor)
                    {
                        self.close_terminal_async_promise_dependencies(epoch, floor);
                    }
                    Err(error)
                }
            }
        })();
        let context = self
            .active_inline_callback_context_label
            .take()
            .expect("nested then getters restore the await context");
        self.active_inline_callback_context_label = saved_context;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context))
            .saturating_add(saved_bytes);
        self.json_release_temporary(saved_bytes);
        outcome
    }

    pub(super) fn resume_async_generator_task(
        &mut self,
        context: AsyncGeneratorContinuation,
        result: Result<JsValue, JsValue>,
        label: Label,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let id = context.generator_id;
        if let Err(error) = self.check_async_generator_cancellation(id) {
            // The dispatcher already removed this context from its map. It
            // cannot be found by abort_async_generator's parked-ticket scan.
            let mut epoch = None;
            for promise in [context.ticket, context.owned_source].into_iter().flatten() {
                match epoch {
                    Some(epoch) => {
                        let _ = self.promise_store.extend_terminal_rejection_without_jobs(
                            promise, &label, epoch,
                        );
                    }
                    None => {
                        epoch = self.promise_store
                            .terminally_reject_without_jobs(promise, &label)
                            .ok();
                    }
                }
            }
            if let Some(epoch) = epoch {
                self.close_terminal_async_promise_dependencies(epoch, &label);
            }
            self.estimated_memory_bytes = self.recompute_base_estimated_memory_bytes();
            return Err(error);
        }
        let backing = self.async_generators[id as usize].generator_id;
        let owner = Arc::clone(&self.generators[backing as usize].owner_module);
        let module = module.unwrap_or(owner.as_ref());
        let result = result
            .map(|value| {
                context
                    .exact_value
                    .unwrap_or_else(|| Self::js_value_to_value(&value))
            })
            .map_err(|reason| Self::js_value_to_value(&reason));
        let outcome = (|| {
            if self.async_generators[id as usize].phase != AsyncGeneratorPhase::SuspendedAwait {
                return Err(InterpreterError::InternalError {
                    details: "async generator resumed without an await".into(),
                });
            }
            self.async_generators[id as usize].phase = AsyncGeneratorPhase::Executing;
            match (context.kind, result) {
                (AwaitKind::DelegateSyncValue, Ok(value)) => {
                    let done = self.async_generators[id as usize]
                        .delegation
                        .expect("awaited sync delegate")
                        .done;
                    let result = self.async_generator_result_object(value, done, &label)?;
                    self.await_async_generator_value(id, AwaitKind::DelegateResult, result, label)?;
                }
                (
                    AwaitKind::DelegateResult
                    | AwaitKind::DelegateClose
                    | AwaitKind::DelegateMissingReturn,
                    Ok(value),
                ) => {
                    self.async_generators[id as usize]
                        .delegation
                        .as_mut()
                        .expect("awaited delegate")
                        .stage = match context.kind {
                        AwaitKind::DelegateClose => AsyncDelegateStage::CloseResult,
                        AwaitKind::DelegateMissingReturn => AsyncDelegateStage::MissingReturn,
                        _ => AsyncDelegateStage::Result,
                    };
                    self.step_async_generator(module, id, GeneratorResumeKind::Next, value, label)?;
                }
                (AwaitKind::DelegateYield, _) => {
                    return Err(InterpreterError::InternalError {
                        details: "raw delegated yield must not enter an await reaction".into(),
                    });
                }
                (
                    AwaitKind::DelegateResult
                    | AwaitKind::DelegateSyncValue
                    | AwaitKind::DelegateClose
                    | AwaitKind::DelegateMissingReturn,
                    Err(reason),
                ) => {
                    // Await failure belongs to this yield* expression, not a
                    // caller-issued .throw. Do not forward it to the delegate.
                    self.abandon_suspended_async_delegation(id)?;
                    self.step_async_generator(
                        module,
                        id,
                        GeneratorResumeKind::Throw,
                        reason,
                        label,
                    )?;
                }
                (AwaitKind::Body, Ok(value)) => {
                    self.step_async_generator(module, id, GeneratorResumeKind::Next, value, label)?
                }
                (AwaitKind::Body | AwaitKind::Yield | AwaitKind::ReturnArgument, Err(reason)) => {
                    self.step_async_generator(
                        module,
                        id,
                        GeneratorResumeKind::Throw,
                        reason,
                        label,
                    )?
                }
                (AwaitKind::ReturnArgument, Ok(value)) => self.step_async_generator(
                    module,
                    id,
                    GeneratorResumeKind::Return,
                    value,
                    label,
                )?,
                (AwaitKind::Yield, Ok(value)) => {
                    self.settle_async_generator_request(id, Ok(value), false, label)?
                }
                (AwaitKind::ReturnResult, result) => {
                    self.complete_async_generator_activation(id);
                    self.settle_async_generator_request(id, result, true, label)?;
                }
            }
            self.drain_async_generator_requests(module, id)
        })();
        if outcome.is_err() {
            self.abort_async_generator(id);
        }
        outcome
    }

    fn settle_async_generator_request(
        &mut self,
        id: u32,
        result: Result<Value, Value>,
        done: bool,
        label: Label,
    ) -> Result<(), InterpreterError> {
        self.check_async_generator_cancellation(id)?;
        let request = self.async_generators[id as usize]
            .requests
            .front()
            .ok_or_else(|| InterpreterError::InternalError {
                details: "async generator has no request to settle".into(),
            })?;
        let promise = request.promise;
        // Neither fulfillment nor rejection can discard the caller's label,
        // even if the continuation produces a public constant or native error.
        let label = self.join_owned_label_with_temporary_budget(label, &request.label)?;
        match result {
            Ok(value) => {
                let result = self.async_generator_result_object(value, done, &label)?;
                self.fulfill_promise(promise, Self::value_to_js_value(&result), label)?;
            }
            Err(reason) => self.reject_promise(promise, Self::value_to_js_value(&reason), label)?,
        }
        self.async_generators[id as usize].requests.pop_front();
        self.async_generators[id as usize].phase = if done {
            AsyncGeneratorPhase::Completed
        } else {
            AsyncGeneratorPhase::SuspendedYield
        };
        self.sync_estimated_memory_bytes()?;
        Ok(())
    }

    /// Convert only catchable language failures. A rejection keeps the exact
    /// thrown identity and joins its provenance with the observed callback and
    /// resumption context. Admission failures are deliberately not converted.
    fn async_generator_exception(
        &mut self,
        error: InterpreterError,
        floor: &Label,
    ) -> Result<LabeledReturn, InterpreterError> {
        let is_thrown = matches!(error, InterpreterError::UncaughtException { .. });
        if !is_thrown && Self::js_catchable_error_name(&error).is_none() {
            return Err(error);
        }
        let context = self.json_parse_context_label()?;
        let label = self.join_owned_label_with_temporary_budget(context, floor)?;
        let (value, thrown_label) = if is_thrown {
            self.take_pending_exception_slot().ok_or_else(|| InterpreterError::InternalError {
                details: "async generator lost its thrown value".into(),
            })?
        } else {
            (self.native_error_to_thrown_value(&error)?, Label::Public)
        };
        let label = self.join_owned_label_with_temporary_budget(label, &thrown_label)?;
        Ok(LabeledReturn { value, label })
    }

    /// The Promise label is not a substitute for labeling the result object:
    /// its value/done properties remain observable through aliases and Reflect.
    /// Use the existing budgeted object provenance store, including for the
    /// internal AsyncFromSync result that crosses a second Promise boundary.
    fn async_generator_result_object(
        &mut self,
        value: Value,
        done: bool,
        label: &Label,
    ) -> Result<Value, InterpreterError> {
        let result = self.generator_result_object(value, done)?;
        let Value::Object(object) = result else {
            return Err(InterpreterError::InternalError {
                details: "async generator result is not an object".into(),
            });
        };
        self.join_direct_object_mutation_label(object, label)?;
        Ok(Value::Object(object))
    }

    fn complete_async_generator_activation(&mut self, id: u32) {
        let generator = &mut self.async_generators[id as usize];
        generator.phase = AsyncGeneratorPhase::Completed;
        generator.awaited = None;
        generator.delegation = None;
        let backing = &mut self.generators[generator.generator_id as usize];
        backing.phase = GeneratorPhase::Completed;
        backing.invocation = None;
        backing.execution = None;
        backing.resume_dst = None;
    }

    /// Async requests may finish or suspend without executing enough bytecode
    /// to reach the dispatch checkpoint density. Honor the same host token at
    /// those boundaries, before argument getters, body resumption, or settlement.
    /// Cancellation remains an uncatchable interpreter failure, not .return().
    fn check_async_generator_cancellation(&mut self, id: u32) -> Result<(), InterpreterError> {
        if self
            .config
            .cancellation_token
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            self.abort_async_generator(id);
            return Err(InterpreterError::Cancelled);
        }
        Ok(())
    }

    fn abort_async_generator(&mut self, id: u32) {
        self.complete_async_generator_activation(id);
        let mut epoch = None;
        for request in self.async_generators[id as usize].requests.drain(..) {
            match epoch {
                Some(epoch) => {
                    let _ = self.promise_store.extend_terminal_rejection_without_jobs(
                        request.promise,
                        &request.label,
                        epoch,
                    );
                }
                None => {
                    epoch = self
                        .promise_store
                        .terminally_reject_without_jobs(request.promise, &request.label)
                        .ok();
                }
            }
        }
        // Removing a saved continuation alone strands its internal Promise.
        // Close only this generator's child tickets, not their awaited sources:
        // another generator or ordinary Promise reaction may share a source.
        let promise_store = &mut self.promise_store;
        self.async_generator_runtime.continuations.retain(|ticket, context| {
            if context.generator_id != id {
                return true;
            }
            for promise in [Some(PromiseHandle(*ticket)), context.owned_source]
                .into_iter()
                .flatten()
            {
                match epoch {
                    Some(epoch) => {
                        let _ = promise_store.extend_terminal_rejection_without_jobs(
                            promise,
                            &Label::Public,
                            epoch,
                        );
                    }
                    None => {
                        epoch = promise_store
                            .terminally_reject_without_jobs(promise, &Label::Public)
                            .ok();
                    }
                }
            }
            false
        });
        if let Some(epoch) = epoch {
            self.close_terminal_async_promise_dependencies(epoch, &Label::Public);
        }
        self.estimated_memory_bytes = self.recompute_base_estimated_memory_bytes();
    }

    fn async_generator_request_bytes(request: &AsyncGeneratorRequest) -> u64 {
        (std::mem::size_of::<AsyncGeneratorRequest>() as u64)
            .saturating_add(Self::estimate_value_bytes(&request.argument))
            .saturating_add(Self::estimate_label_bytes(&request.label))
    }

    fn async_generator_continuation_bytes(context: &AsyncGeneratorContinuation) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<AsyncGeneratorContinuation>() as u64)
            .saturating_add(
                context
                    .exact_value
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
    }

    pub(super) fn estimate_async_generator_bytes(generator: &AsyncGeneratorObject) -> u64 {
        MEMORY_ESTIMATE_GENERATOR_BASE_BYTES
            .saturating_add(std::mem::size_of::<AwaitKind>() as u64)
            .saturating_add(if generator.delegation.is_some() {
                std::mem::size_of::<AsyncDelegateState>() as u64
            } else {
                0
            })
            .saturating_add(Self::saturating_sum(
                generator
                    .requests
                    .iter()
                    .map(Self::async_generator_request_bytes),
            ))
            .saturating_add(
                generator
                    .awaited
                    .as_ref()
                    .map(Self::estimate_labeled_return_bytes)
                    .unwrap_or(0),
            )
    }

    pub(super) fn async_generators_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.async_generators
                .iter()
                .map(Self::estimate_async_generator_bytes),
        )
        .saturating_add(Self::saturating_sum(
            self.async_generator_runtime
                .continuations
                .values()
                .map(Self::async_generator_continuation_bytes),
        ))
    }

    pub(super) fn generator_resume(
        &mut self,
        module: &Ir3Module,
        id: u32,
        kind: GeneratorResumeKind,
        argument: Value,
        label: Label,
    ) -> Result<(Value, Label), InterpreterError> {
        self.generator_resume_with_async(module, id, kind, argument, label, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::promise_model::PromiseState;

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "async-generator-provenance")
    }

    // Allocate the activation through real parsing, lowering and execution.
    // The tests then isolate the request-settlement boundary with labeled input.
    fn request_core(label: Label) -> (InterpreterCore, u32, PromiseHandle) {
        request_core_with_source(
            label,
            "async function* values() { yield 1; } const it = values();",
        )
    }

    fn request_core_with_source(
        label: Label,
        source: &str,
    ) -> (InterpreterCore, u32, PromiseHandle) {
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "async-generator-provenance.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .unwrap();
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "async-generator-provenance.js"),
            &LoweringContext::new("provenance", "provenance", "provenance"),
        )
        .unwrap()
        .ir3;
        let mut core = core();
        core.execute(&module).unwrap();
        assert_eq!(core.async_generators.len(), 1);
        let promise = core.create_promise().unwrap();
        core.async_generators[0].requests.push_back(AsyncGeneratorRequest {
            kind: GeneratorResumeKind::Next,
            argument: Value::Undefined,
            label,
            promise,
        });
        core.sync_estimated_memory_bytes().unwrap();
        (core, 0, promise)
    }

    fn assert_accounting(core: &InterpreterCore) {
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn thrown_rejection_keeps_exact_identity_and_secret_provenance() {
        let mut core = core();
        let value = core.generator_result_object(Value::Int(17), false).unwrap();
        core.replace_pending_abrupt_slots(Some((value.clone(), Label::Secret)), None)
            .unwrap();
        let rejection = core
            .async_generator_exception(
                InterpreterError::UncaughtException { value: "classified".into() },
                &Label::Public,
            )
            .unwrap();
        assert_eq!(rejection.value, value);
        assert_eq!(rejection.label, Label::Secret);
        assert!(core.take_pending_exception_slot().is_none());
        assert_accounting(&core);
    }

    #[test]
    fn exception_join_retains_custom_label_order_and_observed_context() {
        let labels = [
            Label::Public,
            Label::Secret,
            Label::Custom { name: "a".into(), level: 3 },
            Label::Custom { name: "z".repeat(256), level: 3 },
            Label::Custom { name: "low".into(), level: 1 },
        ];
        for floor in &labels {
            for thrown in &labels {
                let mut core = core();
                core.replace_pending_hostcall_result_label(Some(Label::Internal)).unwrap();
                core.replace_pending_abrupt_slots(Some((Value::Int(9), thrown.clone())), None)
                    .unwrap();
                let rejection = core.async_generator_exception(
                    InterpreterError::UncaughtException { value: "9".into() },
                    floor,
                ).unwrap();
                assert_eq!(rejection.value, Value::Int(9));
                assert_eq!(rejection.label, floor.join(thrown).join(&Label::Internal));
                assert_accounting(&core);
            }
        }
    }

    #[test]
    fn native_type_error_keeps_the_callback_and_resumption_security_floor() {
        let mut core = core();
        core.replace_pending_hostcall_result_label(Some(Label::Secret)).unwrap();
        let rejection = core.async_generator_exception(
            InterpreterError::TypeError { expected: "object".into(), got: "number".into() },
            &Label::Confidential,
        ).unwrap();
        assert!(matches!(rejection.value, Value::Object(_)));
        assert_eq!(rejection.label, Label::Secret);
        assert_accounting(&core);
    }

    #[test]
    fn resource_failure_is_not_converted_or_allowed_to_consume_a_guest_exception() {
        let mut core = core();
        core.replace_pending_abrupt_slots(Some((Value::Int(7), Label::Secret)), None).unwrap();
        let error = InterpreterError::MemoryBudgetExceeded {
            requested_bytes: 2,
            max_bytes: 1,
            requested_heap_objects: 0,
            max_heap_objects: 1,
        };
        assert!(matches!(
            core.async_generator_exception(error, &Label::Public),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.take_pending_exception_slot(), Some((Value::Int(7), Label::Secret)));
        assert_accounting(&core);
    }

    #[test]
    fn fulfillment_and_rejection_both_join_the_request_security_floor() {
        for reject in [false, true] {
            for (request, body) in [
                (Label::Secret, Label::Public),
                (Label::Public, Label::Secret),
                (Label::Internal, Label::Confidential),
            ] {
                let expected = request.join(&body);
                let (mut core, id, promise) = request_core(request);
                core.settle_async_generator_request(
                    id,
                    if reject { Err(Value::Int(42)) } else { Ok(Value::Int(42)) },
                    true,
                    body,
                ).unwrap();
                let record = core.promise_store.get(promise).unwrap();
                assert_eq!(record.label, expected);
                assert_eq!(record.state.is_rejected(), reject);
                assert!(core.async_generators[id as usize].requests.is_empty());
                assert_eq!(core.async_generators[id as usize].phase, AsyncGeneratorPhase::Completed);
                assert_accounting(&core);
            }
        }
    }

    #[test]
    fn result_value_and_done_keep_provenance_through_a_public_alias() {
        for done in [false, true] {
            let (mut core, id, promise) = request_core(Label::Public);
            core.settle_async_generator_request(id, Ok(Value::Int(42)), done, Label::Secret).unwrap();
            let result = match &core.promise_store.get(promise).unwrap().state {
                PromiseState::Fulfilled(value) => InterpreterCore::js_value_to_value(value),
                _ => panic!("request must be fulfilled"),
            };
            for (key, expected) in [("value", Value::Int(42)), ("done", Value::Bool(done))] {
                // Deliberately discard the reference label: object provenance,
                // not the incoming register, must protect both stored fields.
                core.write_reg_with_label(0, result.clone(), Label::Public).unwrap();
                core.write_reg_with_label(1, Value::Str(key.into()), Label::Public).unwrap();
                core.replace_pending_hostcall_result_label(None).unwrap();
                let actual = core.reflect_property_builtin(
                    None,
                    RegRange { start: 0, count: 2 },
                    ReflectPropertyOperation::Get,
                ).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
                assert_accounting(&core);
            }
        }
    }

    #[test]
    fn sensitive_settlement_does_not_taint_a_separate_public_generator() {
        let mut core = core();
        let secret = core.async_generator_result_object(Value::Int(1), false, &Label::Secret).unwrap();
        let public = core.async_generator_result_object(Value::Int(2), false, &Label::Public).unwrap();
        let Value::Object(secret_id) = secret else { panic!("object"); };
        let Value::Object(public_id) = public else { panic!("object"); };
        assert_eq!(core.object_mutation_labels.get(&secret_id), Some(&Label::Secret));
        assert!(core.object_mutation_labels.get(&public_id).is_none_or(|label| *label == Label::Public));
        assert_accounting(&core);
    }

    #[test]
    fn thenable_source_keeps_observed_object_provenance_after_context_restoration() {
        let (mut core, id, _) = request_core(Label::Public);
        let value = core.generator_result_object(Value::Int(42), false).unwrap();
        let Value::Object(object) = value else {
            panic!("ordinary source object");
        };
        core.join_direct_object_mutation_label(object, &Label::Secret)
            .unwrap();
        assert!(core.active_inline_callback_context_label.is_none());
        let (promise, label) = core
            .async_generator_thenable_source(id, object, &Label::Public)
            .unwrap();
        assert_eq!(label, Label::Secret);
        let record = core.promise_store.get(promise).unwrap();
        assert_eq!(record.label, Label::Secret);
        assert_eq!(
            InterpreterCore::js_value_to_value(match &record.state {
                PromiseState::Fulfilled(value) => value,
                _ => panic!("non-thenable source must fulfill with its exact identity"),
            }),
            Value::Object(object)
        );
        assert!(core.active_inline_callback_context_label.is_none());
        assert_accounting(&core);
    }

    #[test]
    fn thenable_admission_failure_restores_context_and_keeps_the_request_pending() {
        let (mut core, id, request) = request_core(Label::Public);
        let value = core.generator_result_object(Value::Int(42), false).unwrap();
        let Value::Object(object) = value else {
            panic!("ordinary source object");
        };
        core.replace_pending_abrupt_slots(Some((Value::Int(9), Label::Secret)), None)
            .unwrap();
        let before = core.promise_store.estimated_memory_bytes();
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        assert!(matches!(
            core.async_generator_thenable_source(id, object, &Label::Public),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(core.promise_store.estimated_memory_bytes(), before);
        assert_eq!(core.promise_store.get(request).unwrap().state, PromiseState::Pending);
        assert_eq!(core.async_generators[id as usize].requests.len(), 1);
        assert_eq!(core.take_pending_exception_slot(), Some((Value::Int(9), Label::Secret)));
        assert_accounting(&core);
    }

    fn cancel_token(core: &mut InterpreterCore) {
        let token = CancellationToken::new();
        core.config.cancellation_token = Some(token.clone());
        // No dependence on wall time, threads, or bytecode checkpoint density.
        core.config.checkpoint_density = u64::MAX;
        token.cancel();
    }

    fn assert_aborted(core: &InterpreterCore, id: u32, request: PromiseHandle) {
        let generator = &core.async_generators[id as usize];
        assert_eq!(generator.phase, AsyncGeneratorPhase::Completed);
        assert!(generator.requests.is_empty());
        assert!(generator.awaited.is_none());
        assert!(generator.delegation.is_none());
        assert!(core.async_generator_runtime.continuations.values().all(|entry| {
            entry.generator_id != id
        }));
        let backing = &core.generators[generator.generator_id as usize];
        assert_eq!(backing.phase, GeneratorPhase::Completed);
        assert!(backing.invocation.is_none());
        assert!(backing.execution.is_none());
        assert!(backing.resume_dst.is_none());
        assert!(core.promise_store.get(request).unwrap().state.is_rejected());
        assert_accounting(core);
    }

    #[test]
    fn cancelled_native_request_allocates_no_new_promise_or_result_object() {
        for kind in [GeneratorResumeKind::Next, GeneratorResumeKind::Return, GeneratorResumeKind::Throw] {
            let (mut core, id, request) = request_core(Label::Secret);
            let backing = core.async_generators[id as usize].generator_id;
            let owner = Arc::clone(&core.generators[backing as usize].owner_module);
            let marker = core.create_promise().unwrap();
            let heap_len = core.heap.len();
            cancel_token(&mut core);
            assert!(matches!(
                core.enqueue_async_generator_request(
                    owner.as_ref(), id, kind, Value::Int(42), Label::Public,
                ),
                Err(InterpreterError::Cancelled)
            ));
            assert_aborted(&core, id, request);
            assert_eq!(core.heap.len(), heap_len);
            assert_eq!(core.promise_store.get(request).unwrap().label, Label::Secret);
            assert_eq!(core.promise_store.get(marker).unwrap().state, PromiseState::Pending);
            assert_eq!(core.create_promise().unwrap().0, marker.0 + 1);
        }
    }

    #[test]
    fn cancellation_closes_parked_await_tickets_but_preserves_shared_sources() {
        let (mut core, id, request) = request_core(Label::Secret);
        let source = core.create_promise().unwrap();
        core.await_async_generator_value(
            id, AwaitKind::ReturnResult, Value::Promise(source.0), Label::Secret,
        ).unwrap();
        let ticket = *core.async_generator_runtime.continuations.keys().next().unwrap();
        // A second, independent consumer of precisely the same source.
        let other = core.register_promise_then_for_await(source, Label::Public).unwrap();
        let backing = core.async_generators[id as usize].generator_id;
        let owner = Arc::clone(&core.generators[backing as usize].owner_module);
        cancel_token(&mut core);
        let limit = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = limit;
        assert!(matches!(
            core.drain_async_generator_requests(owner.as_ref(), id),
            Err(InterpreterError::Cancelled)
        ));
        assert_aborted(&core, id, request);
        assert!(core.promise_store.get(PromiseHandle(ticket)).unwrap().state.is_rejected());
        assert_eq!(core.promise_store.get(source).unwrap().state, PromiseState::Pending);
        assert_eq!(core.promise_store.get(other).unwrap().state, PromiseState::Pending);
        assert_eq!(core.config.max_total_memory_bytes, limit);
    }

    #[test]
    fn cancelled_dequeued_continuation_closes_its_ticket_before_resumption() {
        for rejected in [false, true] {
            let (mut core, id, request) = request_core(Label::Public);
            let source = core.create_promise().unwrap();
            core.await_async_generator_value(
                id, AwaitKind::ReturnResult, Value::Promise(source.0), Label::Secret,
            ).unwrap();
            let ticket = *core.async_generator_runtime.continuations.keys().next().unwrap();
            // Mirror the dispatcher's ownership transfer before it invokes
            // resume_async_generator_task, including the no-longer-indexed ticket.
            let context = core.async_generator_runtime.continuations.remove(&ticket).unwrap();
            core.sync_estimated_memory_bytes().unwrap();
            cancel_token(&mut core);
            assert!(matches!(
                core.resume_async_generator_task(
                    context,
                    if rejected { Err(JsValue::Int(42)) } else { Ok(JsValue::Int(42)) },
                    Label::Secret,
                    None,
                ),
                Err(InterpreterError::Cancelled)
            ));
            assert_aborted(&core, id, request);
            let record = core.promise_store.get(PromiseHandle(ticket)).unwrap();
            assert!(record.state.is_rejected());
            assert_eq!(record.label, Label::Secret);
            assert_eq!(core.promise_store.get(source).unwrap().state, PromiseState::Pending);
        }
    }

    #[test]
    fn cancellation_before_await_conversion_preserves_guest_exception_and_heap() {
        let (mut core, id, request) = request_core(Label::Secret);
        let object = core.generator_result_object(Value::Int(42), false).unwrap();
        core.replace_pending_abrupt_slots(Some((Value::Int(9), Label::Secret)), None).unwrap();
        let marker = core.create_promise().unwrap();
        let heap_len = core.heap.len();
        cancel_token(&mut core);
        assert!(matches!(
            core.await_async_generator_value(id, AwaitKind::ReturnResult, object, Label::Public),
            Err(InterpreterError::Cancelled)
        ));
        assert_aborted(&core, id, request);
        assert_eq!(core.heap.len(), heap_len);
        assert_eq!(core.take_pending_exception_slot(), Some((Value::Int(9), Label::Secret)));
        assert_eq!(core.create_promise().unwrap().0, marker.0 + 1);
    }

    #[test]
    fn cancellation_prevents_fulfillment_even_without_a_bytecode_dispatch() {
        for done in [false, true] {
            let (mut core, id, request) = request_core(Label::Secret);
            let heap_len = core.heap.len();
            cancel_token(&mut core);
            assert!(matches!(
                core.settle_async_generator_request(id, Ok(Value::Int(42)), done, Label::Public),
                Err(InterpreterError::Cancelled)
            ));
            assert_aborted(&core, id, request);
            assert_eq!(core.heap.len(), heap_len);
            assert_eq!(core.promise_store.get(request).unwrap().label, Label::Secret);
        }
    }

    #[test]
    fn live_cancellation_token_preserves_successful_native_settlement() {
        let (mut core, id, request) = request_core(Label::Public);
        core.config.cancellation_token = Some(CancellationToken::new());
        core.settle_async_generator_request(id, Ok(Value::Int(42)), true, Label::Secret).unwrap();
        let record = core.promise_store.get(request).unwrap();
        let PromiseState::Fulfilled(value) = &record.state else {
            panic!("a live token must not cancel execution");
        };
        let Value::Object(object) = InterpreterCore::js_value_to_value(value) else {
            panic!("native iterator result object");
        };
        assert_eq!(core.heap[object.0 as usize].properties.get("value"), Some(&Value::Int(42)));
        assert_eq!(record.label, Label::Secret);
        assert_accounting(&core);
    }

    fn await_registration_costs() -> (u64, u64) {
        let (mut probe, id, _) = request_core(Label::Public);
        let source = probe.create_promise().unwrap();
        let context = AsyncGeneratorContinuation {
            generator_id: id,
            kind: AwaitKind::ReturnResult,
            ticket: None,
            owned_source: None,
            exact_value: None,
        };
        let before = probe.estimated_memory_bytes();
        probe.register_promise_then_for_await(source, Label::Public).unwrap();
        (
            InterpreterCore::async_generator_continuation_bytes(&context),
            probe.estimated_memory_bytes() - before,
        )
    }

    #[test]
    fn await_admission_reserves_context_and_reaction_together() {
        let (context_bytes, reaction_bytes) = await_registration_costs();
        assert!(context_bytes > 0 && reaction_bytes > 0);
        let (mut core, id, request) = request_core(Label::Public);
        let source = core.create_promise().unwrap();
        let source_before = core.promise_store.get(source).unwrap().clone();
        let count = core.promise_store.len();
        let queue = serde_json::to_value(&core.event_loop.microtasks).unwrap();
        // Either allocation fits alone, but the two cannot share one reserve.
        let limit = core.estimated_memory_bytes() + context_bytes.max(reaction_bytes);
        core.config.max_total_memory_bytes = limit;
        assert!(matches!(
            core.await_async_generator_value(
                id, AwaitKind::ReturnResult, Value::Promise(source.0), Label::Public,
            ),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_aborted(&core, id, request);
        assert_eq!(core.promise_store.len(), count, "no orphan await ticket");
        assert_eq!(core.promise_store.get(source).unwrap(), &source_before);
        assert_eq!(serde_json::to_value(&core.event_loop.microtasks).unwrap(), queue);
        assert_eq!(core.config.max_total_memory_bytes, limit);
        assert!(core.estimated_memory_bytes() <= limit);
    }

    #[test]
    fn exact_combined_await_budget_admits_a_fully_owned_continuation() {
        let (context_bytes, reaction_bytes) = await_registration_costs();
        let (mut core, id, _) = request_core(Label::Public);
        let source = core.create_promise().unwrap();
        let limit = core.estimated_memory_bytes() + context_bytes + reaction_bytes;
        core.config.max_total_memory_bytes = limit;
        core.await_async_generator_value(
            id, AwaitKind::ReturnResult, Value::Promise(source.0), Label::Public,
        ).unwrap();
        assert_eq!(core.estimated_memory_bytes(), limit);
        assert_eq!(core.async_generators[id as usize].phase, AsyncGeneratorPhase::SuspendedAwait);
        let (&ticket, context) = core.async_generator_runtime.continuations.iter().next().unwrap();
        assert_eq!(context.ticket, Some(PromiseHandle(ticket)));
        assert_eq!(context.owned_source, None);
        assert_eq!(context.generator_id, id);
        assert_eq!(core.promise_store.get(source).unwrap().state, PromiseState::Pending);
        assert_accounting(&core);
    }

    fn thenable_request_core() -> (InterpreterCore, u32, PromiseHandle, ObjectId) {
        let (core, id, request) = request_core_with_source(
            Label::Public,
            "async function* values() { yield 1; } const it = values();
             const input = { marker: 991, then: function(resolve) {} };",
        );
        let object = core.heap.iter().position(|object| {
            object.properties.get("marker") == Some(&Value::Int(991))
        }).expect("thenable allocated by native execution");
        assert!(matches!(core.heap[object].properties.get("then"), Some(Value::Closure(_))));
        (core, id, request, ObjectId(object as u32))
    }

    #[test]
    fn failed_await_registration_closes_the_fresh_thenable_source() {
        let (context_bytes, reaction_bytes) = await_registration_costs();
        let (mut probe, probe_id, _, object) = thenable_request_core();
        let before = probe.estimated_memory_bytes();
        let (source, _) = probe.async_generator_thenable_source(probe_id, object, &Label::Public).unwrap();
        assert_eq!(probe.promise_store.get(source).unwrap().state, PromiseState::Pending);
        let source_bytes = probe.estimated_memory_bytes() - before;

        let (mut core, id, request, object) = thenable_request_core();
        let before_count = core.promise_store.len();
        let limit = core.estimated_memory_bytes() + source_bytes + context_bytes.max(reaction_bytes);
        core.config.max_total_memory_bytes = limit;
        assert!(matches!(
            core.await_async_generator_value(id, AwaitKind::ReturnResult, Value::Object(object), Label::Public),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.promise_store.len(), before_count + 1, "source exists, ticket was refused");
        assert!(core.promise_store.get(source).unwrap().state.is_rejected());
        assert_aborted(&core, id, request);
        assert_eq!(core.config.max_total_memory_bytes, limit);
        assert!(core.estimated_memory_bytes() <= limit);
    }

    #[test]
    fn abort_retires_owned_thenable_source_as_well_as_its_ticket() {
        let (mut core, id, request, object) = thenable_request_core();
        let unrelated = core.create_promise().unwrap();
        core.await_async_generator_value(id, AwaitKind::ReturnResult, Value::Object(object), Label::Public).unwrap();
        let context = core.async_generator_runtime.continuations.values().next().unwrap();
        let ticket = context.ticket.unwrap();
        let source = context.owned_source.expect("internal PromiseResolve source");
        assert_eq!(core.promise_store.get(source).unwrap().state, PromiseState::Pending);
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        core.abort_async_generator(id);
        assert_aborted(&core, id, request);
        for handle in [ticket, source] {
            assert!(core.promise_store.get(handle).unwrap().state.is_rejected());
        }
        assert_eq!(core.promise_store.get(unrelated).unwrap().state, PromiseState::Pending);
    }

    #[test]
    fn invalid_await_source_releases_reservation_and_terminates_the_request() {
        let (mut core, id, request) = request_core(Label::Secret);
        let count = core.promise_store.len();
        let queue = serde_json::to_value(&core.event_loop.microtasks).unwrap();
        assert!(core.await_async_generator_value(
            id, AwaitKind::ReturnResult, Value::Promise(u32::MAX), Label::Public,
        ).is_err());
        assert_aborted(&core, id, request);
        assert_eq!(core.promise_store.len(), count);
        assert_eq!(serde_json::to_value(&core.event_loop.microtasks).unwrap(), queue);
        assert_eq!(core.promise_store.get(request).unwrap().label, Label::Secret);
    }
}
