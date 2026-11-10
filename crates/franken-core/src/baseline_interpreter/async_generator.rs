//! Isolated async-generator activations and ordered Promise-backed requests.
//!
//! Await and yield park the complete execution context. The front request keeps
//! ownership until its result settles, so reentrant calls and pending awaits
//! cannot install a second activation for the same generator.

use std::collections::VecDeque;

use super::*;
use crate::ifc_artifacts::Label;
use crate::object_model::JsValue;
use crate::promise_model::PromiseHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AsyncGeneratorResumeKind {
    Next,
    Return,
    Throw,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum AsyncGeneratorAwaitKind {
    Body { register: u32 },
    Yield { resume_dst: u32 },
    ReturnArgument,
    CompletedReturn,
}

#[derive(Debug, Clone)]
struct AsyncGeneratorRequest {
    kind: AsyncGeneratorResumeKind,
    argument: Value,
    label: Label,
    promise: PromiseHandle,
}

#[derive(Debug, Clone)]
pub(super) struct AsyncGeneratorContinuation {
    generator_id: u32,
    kind: AsyncGeneratorAwaitKind,
}

#[derive(Debug, Clone)]
pub(super) struct AsyncGeneratorObject {
    pub(super) execution: Option<ModuleExecutionSnapshot>,
    pub(super) resume_dst: Option<u32>,
    pub(super) phase: AsyncGeneratorPhase,
    owner_module: Option<Rc<Ir3Module>>,
    retained_program_bytes: u64,
    register_storage_bytes: u64,
    requests: VecDeque<AsyncGeneratorRequest>,
    /// Provenance accumulated while processing the current request.
    label: Label,
}

impl AsyncGeneratorObject {
    #[cfg(test)]
    pub(super) fn completed() -> Self {
        Self {
            execution: None,
            resume_dst: None,
            phase: AsyncGeneratorPhase::Completed,
            owner_module: None,
            retained_program_bytes: 0,
            register_storage_bytes: 0,
            requests: VecDeque::new(),
            label: Label::Public,
        }
    }
}

impl InterpreterCore {
    pub(super) fn prepare_async_generator_activation(
        &mut self,
        module: &Ir3Module,
        setup: GeneratorCallSetup,
        rollback: Option<CallSetupSnapshot>,
    ) -> Result<AsyncGeneratorObject, InterpreterError> {
        let retained_owner = self
            .module_state
            .modules
            .get(&module.header.source_label)
            .and_then(|record| record.compiled_module.clone());
        let retained_program_bytes = if retained_owner.is_some() {
            0
        } else {
            Self::retained_module_program_bytes(module)
        };
        let register_storage_bytes = u64::from(self.config.max_registers).saturating_mul(
            (std::mem::size_of::<Value>() + std::mem::size_of::<Label>()) as u64,
        );
        let overhead = (std::mem::size_of::<AsyncGeneratorObject>() as u64)
            .saturating_add(retained_program_bytes)
            .saturating_add(register_storage_bytes);
        if let Err(error) = self.check_temporary_memory_budget(overhead) {
            if let Some(snapshot) = rollback {
                self.restore_call_setup(snapshot);
            }
            return Err(error);
        }
        // Reserve the fixed arena before the shared prologue helper allocates
        // it. The helper independently accounts the dynamic execution payload.
        let previous_bytes = self.temporarily_suspended_execution_bytes;
        self.temporarily_suspended_execution_bytes =
            previous_bytes.saturating_add(overhead);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(overhead);
        let saved_cjs_context = self.active_cjs_context.take();
        let prepared = self.prepare_generator_activation_inner(module, setup, rollback);
        self.active_cjs_context = saved_cjs_context;
        self.temporarily_suspended_execution_bytes = previous_bytes;
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        let generator = prepared?;
        let activation_bytes = generator
            .execution
            .as_ref()
            .map(Self::estimate_module_execution_bytes)
            .unwrap_or(0);
        self.check_temporary_memory_budget(overhead.saturating_add(activation_bytes))?;
        Ok(AsyncGeneratorObject {
            execution: generator.execution,
            resume_dst: None,
            phase: AsyncGeneratorPhase::SuspendedStart,
            owner_module: Some(retained_owner.unwrap_or_else(|| Rc::new(module.clone()))),
            retained_program_bytes,
            register_storage_bytes,
            requests: VecDeque::new(),
            label: Label::Public,
        })
    }

    pub(super) fn async_generator_next(
        &mut self,
        _module: &Ir3Module,
        generator_id: u32,
        argument: Value,
        label: Label,
    ) -> Result<Value, InterpreterError> {
        self.enqueue_async_generator_request(
            generator_id,
            AsyncGeneratorResumeKind::Next,
            argument,
            label,
        )
    }

    fn check_async_generator_cancellation(&self) -> Result<(), InterpreterError> {
        if self
            .config
            .cancellation_token
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            Err(InterpreterError::Cancelled)
        } else {
            Ok(())
        }
    }

    pub(super) fn enqueue_async_generator_request(
        &mut self,
        generator_id: u32,
        kind: AsyncGeneratorResumeKind,
        argument: Value,
        label: Label,
    ) -> Result<Value, InterpreterError> {
        let generator = self.async_generators.get(generator_id as usize).ok_or_else(|| {
            InterpreterError::TypeError {
                expected: "valid async generator".into(),
                got: format!("async generator #{generator_id} not found"),
            }
        })?;
        if let Some(execution) = &generator.execution
            && execution.registers.len() != execution.register_labels.len()
        {
            return Err(InterpreterError::TypeError {
                expected: "one IFC label per register in async generator snapshot".into(),
                got: format!(
                    "values={}, labels={}",
                    execution.registers.len(),
                    execution.register_labels.len(),
                ),
            });
        }
        if let Err(error) = self.check_async_generator_cancellation() {
            self.abort_async_generator(generator_id);
            return Err(error);
        }
        let request_bytes = Self::async_generator_request_bytes(&argument, &label);
        let promise = self.with_async_generator_temporary(request_bytes, |core| {
            let promise = core.create_promise_accounted()?;
            core.async_generators[generator_id as usize]
                .requests
                .push_back(AsyncGeneratorRequest {
                    kind,
                    argument,
                    label,
                    promise,
                });
            Ok(promise)
        })?;
        if let Err(error) = self.drain_async_generator_requests(generator_id) {
            self.abort_async_generator(generator_id);
            return Err(error);
        }
        Ok(Value::Promise(promise.0))
    }

    fn drain_async_generator_requests(&mut self, generator_id: u32) -> Result<(), InterpreterError> {
        loop {
            self.check_async_generator_cancellation()?;
            let generator = &self.async_generators[generator_id as usize];
            if matches!(
                generator.phase,
                AsyncGeneratorPhase::Executing | AsyncGeneratorPhase::SuspendedAwait
            ) || generator.requests.is_empty()
            {
                return Ok(());
            }
            let request = generator.requests.front().expect("nonempty request queue");
            let clone_bytes = Self::async_generator_request_bytes(&request.argument, &request.label);
            self.with_async_generator_temporary(clone_bytes, |core| {
                let generator = &mut core.async_generators[generator_id as usize];
                let phase = generator.phase;
                let request = generator.requests.front().expect("nonempty request queue").clone();
                // PromiseResolve can execute a getter which queues another
                // request. Mark busy before any such call.
                generator.phase = AsyncGeneratorPhase::Executing;
                if phase == AsyncGeneratorPhase::Completed
                    || (phase == AsyncGeneratorPhase::SuspendedStart
                        && request.kind != AsyncGeneratorResumeKind::Next)
                {
                    core.complete_async_generator_activation(generator_id);
                    match request.kind {
                        AsyncGeneratorResumeKind::Return => core.await_async_generator_value(
                            generator_id,
                            AsyncGeneratorAwaitKind::CompletedReturn,
                            request.argument,
                            request.label,
                        ),
                        AsyncGeneratorResumeKind::Throw => core.settle_async_generator_request(
                            generator_id,
                            Err(request.argument),
                            true,
                            request.label,
                        ),
                        AsyncGeneratorResumeKind::Next => core.settle_async_generator_request(
                            generator_id,
                            Ok(Value::Undefined),
                            true,
                            request.label,
                        ),
                    }
                } else if request.kind == AsyncGeneratorResumeKind::Return {
                    core.await_async_generator_value(
                        generator_id,
                        AsyncGeneratorAwaitKind::ReturnArgument,
                        request.argument,
                        request.label,
                    )
                } else {
                    core.step_async_generator(
                        generator_id,
                        request.kind,
                        request.argument,
                        request.label,
                        None,
                    )
                }
            })?;
        }
    }

    fn step_async_generator(
        &mut self,
        generator_id: u32,
        kind: AsyncGeneratorResumeKind,
        argument: Value,
        label: Label,
        register_override: Option<u32>,
    ) -> Result<(), InterpreterError> {
        self.check_async_generator_cancellation()?;
        self.ensure_call_depth_available()?;
        let (owner, execution, resume_dst) = {
            let generator = &mut self.async_generators[generator_id as usize];
            let owner = generator.owner_module.clone().ok_or_else(|| InterpreterError::TypeError {
                expected: "retained async generator owner".into(),
                got: "missing async generator owner".into(),
            })?;
            let execution = generator.execution.take().ok_or_else(|| InterpreterError::TypeError {
                expected: "saved async generator activation".into(),
                got: "missing async generator activation".into(),
            })?;
            generator.phase = AsyncGeneratorPhase::Executing;
            (owner, execution, register_override.or(generator.resume_dst.take()))
        };
        let caller = self.take_module_execution();
        let previous_bytes = self.temporarily_suspended_execution_bytes;
        let previous_depth = self.temporarily_suspended_call_depth;
        self.temporarily_suspended_execution_bytes = previous_bytes
            .saturating_add(Self::estimate_module_execution_bytes(&caller));
        self.temporarily_suspended_call_depth =
            previous_depth.saturating_add(caller.call_stack.len());
        let saved_cjs_context = self.active_cjs_context.take();
        self.install_module_execution(execution);
        let outcome = (|| {
            self.sync_estimated_memory_bytes()?;
            match kind {
                AsyncGeneratorResumeKind::Next => {
                    if let Some(register) = resume_dst {
                        self.write_reg_with_label(register, argument, label)?;
                    }
                }
                AsyncGeneratorResumeKind::Throw => {
                    let exception = LabeledException { value: argument, label };
                    self.suspend_current_abrupt_completion();
                    self.pending_return = None;
                    self.pending_exception = Some(exception.clone());
                    if let Some(frame) = self.pop_exception_target_frame() {
                        self.pending_finally_entry =
                            frame.catch_is_finally.then_some(PendingFinallyEntry {
                                target: frame.catch_target,
                                mode: FinallyMode::Exception,
                            });
                        self.ip = frame.catch_target;
                    } else {
                        let description = format!("{:?}", exception.value);
                        return Ok(RunLoopExit::GeneratorThrow { exception, description });
                    }
                }
                AsyncGeneratorResumeKind::Return => {
                    self.suspend_current_abrupt_completion();
                    self.pending_exception = None;
                    self.pending_return = Some(LabeledReturn {
                        value: argument.clone(),
                        label: label.clone(),
                    });
                    if let Some(target) = self.pop_current_finally_target() {
                        self.pending_finally_entry = Some(PendingFinallyEntry {
                            target,
                            mode: FinallyMode::Return,
                        });
                        self.ip = target;
                    } else {
                        self.pending_return = None;
                        let _ = self.complete_return(argument.clone(), label.clone())?;
                        return Ok(RunLoopExit::GeneratorReturn { value: argument, label });
                    }
                }
            }
            loop {
                match self.run_loop_with_mode(&owner, RunLoopMode::AsyncGenerator) {
                    Err(error) if Self::is_js_catchable_error(&error) && self.has_exception_target_frame() => {
                        match self.route_run_loop_javascript_error(
                            &owner,
                            error,
                            RunLoopMode::AsyncGenerator,
                        )? {
                            None => continue,
                            Some(error) => return Err(error),
                        }
                    }
                    outcome => return outcome,
                }
            }
        })();
        let mut execution = self.take_module_execution();
        let escaped_exception = execution.pending_exception.take();
        self.active_cjs_context = saved_cjs_context;
        self.temporarily_suspended_execution_bytes = previous_bytes;
        self.temporarily_suspended_call_depth = previous_depth;
        self.restore_module_execution(caller);
        drop(owner);
        if let Ok(RunLoopExit::AsyncGeneratorAwait { completion, kind }) = outcome {
            execution.pending_exception = escaped_exception;
            let generator = &mut self.async_generators[generator_id as usize];
            generator.execution = Some(execution);
            if let AsyncGeneratorAwaitKind::Yield { resume_dst } = kind {
                generator.resume_dst = Some(resume_dst);
            }
            self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
            let completion_bytes = Self::async_generator_value_bytes(&completion.value)
                .saturating_add(Self::estimate_label_bytes(&completion.label));
            return self.with_async_generator_temporary(completion_bytes, |core| {
                core.await_async_generator_value(
                    generator_id,
                    kind,
                    completion.value,
                    completion.label,
                )
            });
        }
        drop(execution);
        let context_label = self.async_generators[generator_id as usize].label.clone();
        self.complete_async_generator_activation(generator_id);
        let completion_bytes = match &outcome {
            Ok(RunLoopExit::Value(completion)) => Self::async_generator_value_bytes(&completion.value)
                .saturating_add(Self::estimate_label_bytes(&completion.label)),
            Ok(RunLoopExit::GeneratorReturn { value, label }) => Self::async_generator_value_bytes(value)
                .saturating_add(Self::estimate_label_bytes(label)),
            Ok(RunLoopExit::GeneratorThrow { exception, .. }) => Self::async_generator_value_bytes(&exception.value)
                .saturating_add(Self::estimate_label_bytes(&exception.label)),
            _ => 0,
        }
        .saturating_add(Self::estimate_label_bytes(&context_label))
        .saturating_add(escaped_exception.as_ref().map(Self::estimate_labeled_exception_bytes).unwrap_or(0));
        self.with_async_generator_temporary(completion_bytes, |core| {
            match outcome {
                Ok(RunLoopExit::Value(completion)) => core.settle_async_generator_request(
                    generator_id, Ok(completion.value), true, context_label.join(&completion.label),
                ),
                Ok(RunLoopExit::GeneratorReturn { value, label }) => core.settle_async_generator_request(
                    generator_id, Ok(value), true, context_label.join(&label),
                ),
                Ok(RunLoopExit::GeneratorThrow { exception, .. }) => core.settle_async_generator_request(
                    generator_id, Err(exception.value), true, context_label.join(&exception.label),
                ),
                Err(InterpreterError::Halted) => core.settle_async_generator_request(
                    generator_id, Ok(Value::Undefined), true, context_label,
                ),
                Err(error) if Self::is_js_catchable_error(&error) => {
                    let (reason, label) = match escaped_exception {
                        Some(exception) if matches!(error, InterpreterError::UncaughtException { .. }) =>
                            (exception.value, context_label.join(&exception.label)),
                        _ => (core.promise_error_value(&error)?, context_label),
                    };
                    core.settle_async_generator_request(generator_id, Err(reason), true, label)
                }
                Err(error) => Err(error),
                Ok(_) => Err(InterpreterError::TypeError {
                    expected: "async generator await, yield, return, or throw".into(),
                    got: "unexpected async generator execution boundary".into(),
                }),
            }
        })
    }

    fn await_async_generator_value(
        &mut self,
        generator_id: u32,
        kind: AsyncGeneratorAwaitKind,
        value: Value,
        label: Label,
    ) -> Result<(), InterpreterError> {
        self.async_generators[generator_id as usize].phase = AsyncGeneratorPhase::Executing;
        let label = self.async_generators[generator_id as usize].label.join(&label);
        let promise = if let Value::Promise(handle) = value {
            PromiseHandle(handle)
        } else {
            let promise = self.create_promise_accounted()?;
            self.resolve_promise_with_value(promise, value, label.clone())?;
            promise
        };
        self.check_async_generator_cancellation()?;
        let context_bytes = Self::async_generator_continuation_bytes();
        self.with_async_generator_temporary(context_bytes, |core| {
            let rollback_bytes = core.promise_store.estimated_memory_bytes()
                .saturating_add(core.event_loop.microtasks.estimated_memory_bytes());
            let continuation = core.with_async_generator_temporary(rollback_bytes, |core| {
                let previous_runtime = core.promise_runtime_memory_bytes();
                let store = core.promise_store.clone();
                let queue = core.event_loop.microtasks.clone();
                let registered = match core.promise_store.then_for_await(
                    promise, label, &mut core.event_loop.microtasks,
                ) {
                    Ok(continuation) => core
                        .apply_promise_runtime_memory_delta(previous_runtime)
                        .map(|()| continuation),
                    Err(error) => Err(InterpreterError::TypeError {
                        expected: "valid awaited async generator value".into(),
                        got: error.to_string(),
                    }),
                };
                if registered.is_err() {
                    core.promise_store = store;
                    core.event_loop.microtasks = queue;
                }
                registered
            })?;
            core.async_generator_continuations.insert(
                continuation.0,
                AsyncGeneratorContinuation { generator_id, kind },
            );
            core.async_generators[generator_id as usize].phase = AsyncGeneratorPhase::SuspendedAwait;
            Ok(())
        })
    }

    pub(super) fn take_async_generator_continuation(
        &mut self,
        promise: u32,
    ) -> Option<AsyncGeneratorContinuation> {
        let context = self.async_generator_continuations.remove(&promise)?;
        self.estimated_memory_bytes = self.estimated_memory_bytes
            .saturating_sub(Self::async_generator_continuation_bytes());
        Some(context)
    }

    pub(super) fn resume_async_generator_task(
        &mut self,
        context: AsyncGeneratorContinuation,
        settlement: Result<JsValue, JsValue>,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let generator_id = context.generator_id;
        let outcome = (|| {
            self.check_async_generator_cancellation()?;
            let generator = self.async_generators.get(generator_id as usize).ok_or_else(|| InterpreterError::TypeError {
                expected: "valid async generator continuation".into(),
                got: "missing async generator".into(),
            })?;
            if generator.phase != AsyncGeneratorPhase::SuspendedAwait {
                return Err(InterpreterError::TypeError {
                    expected: "suspended async generator await".into(),
                    got: format!("async generator phase {:?}", generator.phase),
                });
            }
            let joined = generator.label.join(&label);
            self.check_temporary_memory_budget(Self::estimate_label_bytes(&joined))?;
            self.async_generators[generator_id as usize].label = joined.clone();
            self.async_generators[generator_id as usize].phase = AsyncGeneratorPhase::Executing;
            self.sync_estimated_memory_bytes()?;
            match (context.kind, settlement) {
                (AsyncGeneratorAwaitKind::Body { register }, Ok(value)) => self.step_async_generator(
                    generator_id, AsyncGeneratorResumeKind::Next, Self::js_value_to_value(&value), joined, Some(register),
                )?,
                (AsyncGeneratorAwaitKind::Yield { .. }, Ok(value)) => self.settle_async_generator_request(
                    generator_id, Ok(Self::js_value_to_value(&value)), false, joined,
                )?,
                (AsyncGeneratorAwaitKind::ReturnArgument, Ok(value)) => self.step_async_generator(
                    generator_id, AsyncGeneratorResumeKind::Return, Self::js_value_to_value(&value), joined, None,
                )?,
                (AsyncGeneratorAwaitKind::CompletedReturn, settlement) => {
                    self.complete_async_generator_activation(generator_id);
                    self.settle_async_generator_request(
                        generator_id,
                        settlement.map(|value| Self::js_value_to_value(&value))
                            .map_err(|reason| Self::js_value_to_value(&reason)),
                        true,
                        joined,
                    )?;
                }
                (_, Err(reason)) => self.step_async_generator(
                    generator_id, AsyncGeneratorResumeKind::Throw, Self::js_value_to_value(&reason), joined, None,
                )?,
            }
            self.drain_async_generator_requests(generator_id)
        })();
        if outcome.is_err() {
            self.abort_async_generator(generator_id);
        }
        outcome
    }

    fn settle_async_generator_request(
        &mut self,
        generator_id: u32,
        result: Result<Value, Value>,
        done: bool,
        label: Label,
    ) -> Result<(), InterpreterError> {
        self.check_async_generator_cancellation()?;
        let request = self.async_generators[generator_id as usize]
            .requests.front().ok_or_else(|| InterpreterError::TypeError {
                expected: "active async generator request".into(),
                got: "empty async generator request queue".into(),
            })?;
        let promise = request.promise;
        let label = request.label.join(&label);
        match result {
            Ok(value) => {
                let object = self.generator_result_object(value, done)?;
                let Value::Object(object_id) = object else { unreachable!("iterator result is an object") };
                self.set_own_runtime_property_label(object_id, &RuntimePropertyKey::String("value".into()), &label)?;
                self.set_own_runtime_property_label(object_id, &RuntimePropertyKey::String("done".into()), &label)?;
                self.fulfill_promise(promise, Self::value_to_js_value(&Value::Object(object_id)), label)?;
            }
            Err(reason) => self.reject_promise(promise, Self::value_to_js_value(&reason), label)?,
        }
        let generator = &mut self.async_generators[generator_id as usize];
        generator.requests.pop_front();
        generator.label = Label::Public;
        generator.phase = if done {
            AsyncGeneratorPhase::Completed
        } else {
            AsyncGeneratorPhase::SuspendedYield
        };
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        Ok(())
    }

    fn complete_async_generator_activation(&mut self, generator_id: u32) {
        if let Some(generator) = self.async_generators.get_mut(generator_id as usize) {
            generator.execution = None;
            generator.resume_dst = None;
            generator.owner_module = None;
            generator.retained_program_bytes = 0;
            generator.register_storage_bytes = 0;
            generator.phase = AsyncGeneratorPhase::Completed;
            generator.label = Label::Public;
        }
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
    }

    fn abort_async_generator(&mut self, generator_id: u32) {
        self.complete_async_generator_activation(generator_id);
        if let Some(generator) = self.async_generators.get_mut(generator_id as usize) {
            generator.requests.clear();
        }
        self.async_generator_continuations.retain(|_, context| context.generator_id != generator_id);
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
    }

    pub(super) fn reset_async_generator_requests(&mut self) {
        for generator_id in 0..self.async_generators.len() {
            self.abort_async_generator(generator_id as u32);
        }
        self.async_generator_continuations.clear();
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
    }

    fn with_async_generator_temporary<T>(
        &mut self,
        bytes: u64,
        action: impl FnOnce(&mut Self) -> Result<T, InterpreterError>,
    ) -> Result<T, InterpreterError> {
        self.check_temporary_memory_budget(bytes)?;
        self.promise_in_flight_task_bytes = self.promise_in_flight_task_bytes.saturating_add(bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_add(bytes);
        let outcome = action(self);
        self.promise_in_flight_task_bytes = self.promise_in_flight_task_bytes.saturating_sub(bytes);
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
        outcome
    }

    fn async_generator_value_bytes(value: &Value) -> u64 {
        Self::estimate_value_bytes(value).saturating_add(match value {
            Value::BuiltinFunction(builtin) => builtin.module_specifier.len() as u64,
            _ => 0,
        })
    }

    fn async_generator_request_bytes(value: &Value, label: &Label) -> u64 {
        (std::mem::size_of::<AsyncGeneratorRequest>() as u64)
            .saturating_add(Self::async_generator_value_bytes(value))
            .saturating_add(Self::estimate_label_bytes(label))
    }

    pub(super) fn async_generator_continuation_bytes() -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<AsyncGeneratorContinuation>() as u64)
    }

    pub(super) fn estimate_async_generator_bytes(generator: &AsyncGeneratorObject) -> u64 {
        (std::mem::size_of::<AsyncGeneratorObject>() as u64)
            .saturating_add(generator.retained_program_bytes)
            .saturating_add(generator.register_storage_bytes)
            .saturating_add(Self::estimate_label_bytes(&generator.label))
            .saturating_add(generator.execution.as_ref().map(Self::estimate_module_execution_bytes).unwrap_or(0))
            .saturating_add(generator.requests.iter().map(|request| {
                Self::async_generator_request_bytes(&request.argument, &request.label)
            }).fold(0u64, u64::saturating_add))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir_contract::{IrHeader, IrLevel, IrSchemaVersion};

    fn pending_module() -> Ir3Module {
        Ir3Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: None,
                source_label: "async-generator-private-test".into(),
            },
            instructions: vec![
                Ir3Instruction::GeneratorBodyStart,
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::Yield { value: 0, delegate: false, resume_dst: 1 },
                Ir3Instruction::Return { value: 1 },
            ],
            constant_pool: Vec::new(),
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
        }
    }

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        InterpreterCore::new(config, "async-generator-private-test")
    }

    fn prepare(core: &mut InterpreterCore, module: &Ir3Module, awaited: PromiseHandle) -> u32 {
        let generator = core.prepare_async_generator_activation(
            module,
            GeneratorCallSetup {
                function_index: 0,
                function_entry: 0,
                captured_env: core.scope_chain.snapshot(),
                arguments: vec![(Value::Promise(awaited.0), Label::Confidential)],
                this_value: Value::Undefined,
                this_label: Label::Public,
                super_value: Value::Undefined,
                super_label: Label::Public,
            },
            None,
        ).unwrap();
        let id = core.async_generators.len() as u32;
        core.async_generators.push(generator);
        core.sync_estimated_memory_bytes().unwrap();
        id
    }

    fn promise(value: Value) -> PromiseHandle {
        let Value::Promise(handle) = value else { panic!("async request must return Promise") };
        PromiseHandle(handle)
    }

    #[test]
    fn pending_requests_preserve_caller_state_and_per_request_ifc() {
        let module = pending_module();
        let mut core = core();
        let awaited = core.create_promise_accounted().unwrap();
        let id = prepare(&mut core, &module, awaited);
        core.write_reg_with_label(5, Value::Int(81), Label::TopSecret).unwrap();
        let first = promise(core.async_generator_next(&module, id, Value::Undefined, Label::Public).unwrap());
        let second = promise(core.async_generator_next(&module, id, Value::Int(99), Label::Internal).unwrap());
        assert!(!core.promise_store.get(first).unwrap().state.is_settled());
        assert!(!core.promise_store.get(second).unwrap().state.is_settled());
        assert_eq!(core.async_generators[id as usize].requests.len(), 2);
        assert_eq!(core.async_generators[id as usize].phase, AsyncGeneratorPhase::SuspendedAwait);
        core.fulfill_promise(awaited, JsValue::Int(7), Label::Secret).unwrap();
        core.drain_microtasks(Some(&module)).unwrap();
        for (handle, expected_value, expected_done, expected_label) in [
            (first, 7, false, Label::Secret),
            (second, 99, true, Label::Internal),
        ] {
            let record = core.promise_store.get(handle).unwrap();
            assert_eq!(record.label, expected_label);
            let crate::promise_model::PromiseState::Fulfilled(payload) = &record.state else {
                panic!("request should fulfill");
            };
            let Value::Object(object_id) = InterpreterCore::js_value_to_value(payload) else {
                panic!("iterator result should be an object");
            };
            assert_eq!(core.prototype_chain_get(object_id, "value").unwrap(), Value::Int(expected_value));
            assert_eq!(core.prototype_chain_get(object_id, "done").unwrap(), Value::Bool(expected_done));
            assert_eq!(core.runtime_property_label(object_id, &RuntimePropertyKey::String("value".into())), expected_label);
        }
        assert_eq!(core.read_reg(5).unwrap(), Value::Int(81));
        assert_eq!(core.read_reg_label(5).unwrap(), Label::TopSecret);
        assert!(core.call_stack.is_empty());
        assert!(core.async_generator_continuations.is_empty());
        assert!(core.async_generators[id as usize].execution.is_none());
        assert_eq!(core.async_generators[id as usize].register_storage_bytes, 0);
        assert_eq!(core.promise_in_flight_task_bytes, 0);
        assert_eq!(core.estimated_memory_bytes, core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn fixed_register_arena_is_admitted_before_activation_preparation() {
        let module = pending_module();
        let mut core = core();
        let baseline = core.estimated_memory_bytes;
        let arena_bytes = u64::from(core.config.max_registers)
            * (std::mem::size_of::<Value>() + std::mem::size_of::<Label>()) as u64;
        core.config.max_total_memory_bytes = baseline + arena_bytes - 1;
        let error = core.prepare_async_generator_activation(
            &module,
            GeneratorCallSetup {
                function_index: 0,
                function_entry: 0,
                captured_env: core.scope_chain.snapshot(),
                arguments: Vec::new(),
                this_value: Value::Undefined,
                this_label: Label::Public,
                super_value: Value::Undefined,
                super_label: Label::Public,
            },
            None,
        ).unwrap_err();
        assert!(matches!(error, InterpreterError::MemoryBudgetExceeded { .. }));
        assert!(core.async_generators.is_empty());
        assert!(core.call_stack.is_empty());
        assert_eq!(core.promise_store.len(), 0);
        assert_eq!(core.estimated_memory_bytes, baseline);
    }

    #[test]
    fn cancellation_drops_queued_arguments_and_suspended_execution() {
        let module = pending_module();
        let mut core = core();
        let token = CancellationToken::new();
        core.config.cancellation_token = Some(token.clone());
        let awaited = core.create_promise_accounted().unwrap();
        let id = prepare(&mut core, &module, awaited);
        let first = promise(core.async_generator_next(&module, id, Value::Undefined, Label::Public).unwrap());
        core.enqueue_async_generator_request(
            id,
            AsyncGeneratorResumeKind::Return,
            Value::str("queued argument".repeat(32)),
            Label::Secret,
        ).unwrap();
        assert_eq!(core.async_generators[id as usize].requests.len(), 2);
        token.cancel();
        assert_eq!(
            core.async_generator_next(&module, id, Value::Undefined, Label::Public),
            Err(InterpreterError::Cancelled),
        );
        let generator = &core.async_generators[id as usize];
        assert!(generator.execution.is_none());
        assert!(generator.owner_module.is_none());
        assert!(generator.requests.is_empty());
        assert_eq!(generator.register_storage_bytes, 0);
        assert_eq!(generator.retained_program_bytes, 0);
        assert!(core.async_generator_continuations.is_empty());
        assert!(!core.promise_store.get(first).unwrap().state.is_settled());
        assert_eq!(core.promise_in_flight_task_bytes, 0);
        assert_eq!(core.estimated_memory_bytes, core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn resumed_execution_limits_stay_fatal_and_release_owners() {
        let module = pending_module();
        let mut core = core();
        let awaited = core.create_promise_accounted().unwrap();
        let id = prepare(&mut core, &module, awaited);
        let first = promise(core.async_generator_next(&module, id, Value::Undefined, Label::Public).unwrap());
        core.config.instruction_budget = core.instructions_executed;
        core.fulfill_promise(awaited, JsValue::Int(7), Label::Public).unwrap();
        assert!(matches!(
            core.drain_microtasks(Some(&module)),
            Err(InterpreterError::BudgetExhausted { .. }),
        ));
        let generator = &core.async_generators[id as usize];
        assert!(generator.execution.is_none());
        assert!(generator.owner_module.is_none());
        assert!(generator.requests.is_empty());
        assert_eq!(generator.register_storage_bytes, 0);
        assert!(core.async_generator_continuations.is_empty());
        assert!(!core.promise_store.get(first).unwrap().state.is_settled());
        assert!(core.call_stack.is_empty());
        assert_eq!(core.promise_in_flight_task_bytes, 0);
        assert_eq!(core.estimated_memory_bytes, core.recompute_estimated_memory_bytes());
    }
}
