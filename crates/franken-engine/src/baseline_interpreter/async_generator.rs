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
        let outcome =
            self.generator_resume_with_async(module, backing, kind, argument, label, Some(id));
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
                let (reason, label) = if matches!(error, InterpreterError::UncaughtException { .. })
                {
                    self.take_pending_exception_slot().ok_or_else(|| {
                        InterpreterError::InternalError {
                            details: "async generator lost its thrown value".into(),
                        }
                    })?
                } else {
                    (self.native_error_to_thrown_value(&error)?, Label::Public)
                };
                self.complete_async_generator_activation(id);
                self.settle_async_generator_request(id, Err(reason), true, label)
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
        label: Label,
    ) -> Result<(), InterpreterError> {
        let exact_value;
        let source = match value {
            Value::Promise(handle) => {
                exact_value = None;
                PromiseHandle(handle)
            }
            Value::Object(_) => {
                exact_value = None;
                let promise = self.create_promise()?;
                if let Err(error) = self.resolve_promise_with_value(promise, value, label.clone()) {
                    if matches!(error, InterpreterError::UncaughtException { .. })
                        || Self::js_catchable_error_name(&error).is_some()
                    {
                        let reason = if matches!(error, InterpreterError::UncaughtException { .. })
                        {
                            self.take_pending_exception_slot()
                                .map(|(value, _)| value)
                                .ok_or_else(|| InterpreterError::InternalError {
                                    details: "thenable getter lost its exception".into(),
                                })?
                        } else {
                            self.native_error_to_thrown_value(&error)?
                        };
                        self.reject_promise(
                            promise,
                            Self::value_to_js_value(&reason),
                            label.clone(),
                        )?;
                    } else {
                        return Err(error);
                    }
                }
                promise
            }
            other => {
                exact_value = Some(other);
                self.create_fulfilled_promise(JsValue::Undefined, label.clone())?
            }
        };
        let context = AsyncGeneratorContinuation {
            generator_id: id,
            kind,
            exact_value,
        };
        self.check_temporary_memory_budget(Self::async_generator_continuation_bytes(&context))?;
        let ticket = self.register_promise_then_for_await(source, label)?;
        self.async_generator_runtime
            .continuations
            .insert(ticket.0, context);
        self.async_generators[id as usize].phase = AsyncGeneratorPhase::SuspendedAwait;
        self.sync_estimated_memory_bytes()?;
        Ok(())
    }

    pub(super) fn resume_async_generator_task(
        &mut self,
        context: AsyncGeneratorContinuation,
        result: Result<JsValue, JsValue>,
        label: Label,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let id = context.generator_id;
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
                    let result = self.generator_result_object(value, done)?;
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
        let promise = self.async_generators[id as usize]
            .requests
            .front()
            .ok_or_else(|| InterpreterError::InternalError {
                details: "async generator has no request to settle".into(),
            })?
            .promise;
        match result {
            Ok(value) => {
                let result = self.generator_result_object(value, done)?;
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

    fn abort_async_generator(&mut self, id: u32) {
        self.complete_async_generator_activation(id);
        self.async_generator_runtime
            .continuations
            .retain(|_, context| context.generator_id != id);
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
