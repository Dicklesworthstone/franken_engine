//! Async yield* resumes the same bytecode instruction after each awaited step.
//!
//! Receiver/next ownership stays in the canonical iterator table. Awaited
//! values travel through the ordinary saved resume register and Promise jobs;
//! this state carries only fixed-size protocol coordinates, never guest data.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AsyncDelegateStage {
    Ready,
    Result,
    CloseResult,
    MissingReturn,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::baseline_interpreter) struct AsyncDelegateState {
    pub(super) synchronous: bool,
    pub(super) stage: AsyncDelegateStage,
    pub(super) method: GeneratorResumeKind,
    pub(super) done: bool,
}

impl InterpreterCore {
    pub(in crate::baseline_interpreter) fn finish_async_generator_delegate_dispatch(
        &mut self,
        module: &Ir3Module,
        id: u32,
        source: u32,
        resume_dst: u32,
    ) -> Result<Option<LabeledReturn>, InterpreterError> {
        let result = self.step_async_generator_delegation(module, id, source, resume_dst);
        if result.is_err() {
            self.async_generators[id as usize].delegation = None;
            if let Some(delegation) = self.take_generator_delegation() {
                let label = delegation.label.join(
                    self.pending_hostcall_result_label
                        .as_ref()
                        .unwrap_or(&Label::Public),
                );
                if self.pending_exception.is_some() {
                    self.join_pending_exception_label(&label)?;
                }
                self.replace_pending_hostcall_result_label(Some(label))?;
            }
            self.sync_estimated_memory_bytes()?;
        }
        result
    }

    fn prepare_async_delegate(
        &mut self,
        module: &Ir3Module,
        source: &Value,
    ) -> Result<(RuntimeForOfInit, bool), InterpreterError> {
        // GetMethod uses GetV: primitives consult their realm's intrinsic
        // prototype too, and native generator values retain their ordinary
        // own properties. Preserve the original receiver and property labels;
        // recognizing a native carrier never authorizes bypassing its hooks.
        if let Some(method) = self.iterator_protocol_method(
            module,
            source.clone(),
            &RuntimePropertyKey::Symbol(WellKnownSymbol::AsyncIterator.id()),
        )? {
            let (receiver, label) = self.invoke_inline_method_call_with_argument_label(
                Some(module),
                method,
                source.clone(),
                Vec::new(),
                self.pending_hostcall_result_label.clone(),
            )?;
            let label = label.join(
                self.pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public),
            );
            self.replace_pending_hostcall_result_label(Some(label))?;
            // Get(iterator, "next") is captured exactly once even when the
            // iterator returned by the hook is itself a native generator.
            return self
                .prepare_custom_iterator_result(module, receiver)
                .map(|init| (init, false));
        }
        // GetMethod(Symbol.asyncIterator) must succeed before trying the
        // synchronous fallback. A present non-callable method never falls back.
        Ok((self.prepare_for_of_state(Some(module), source)?, true))
    }

    fn step_async_generator_delegation(
        &mut self,
        module: &Ir3Module,
        id: u32,
        source: u32,
        resume_dst: u32,
    ) -> Result<Option<LabeledReturn>, InterpreterError> {
        if self.async_generators[id as usize].delegation.is_none() {
            let value = self.read_reg(source)?;
            let mut label = self.unary_operation_label(source)?;
            self.replace_pending_hostcall_result_label(Some(label.clone()))?;
            let (init, synchronous) = self.prepare_async_delegate(module, &value)?;
            let iterator = self.init_iterator_from_state_with_symbol(
                value,
                init,
                IterationKind::YieldDelegate,
                if synchronous {
                    IteratorSymbolKind::Iterator
                } else {
                    IteratorSymbolKind::AsyncIterator
                },
            )?;
            label = label.join(
                &self
                    .take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
            );
            self.replace_generator_delegation(GeneratorDelegation {
                iterator: self.expect_iterator_handle(iterator)?,
                label,
                resume_kind: GeneratorResumeKind::Next,
                started: false,
            })?;
            self.async_generators[id as usize].delegation = Some(AsyncDelegateState {
                synchronous,
                stage: AsyncDelegateStage::Ready,
                method: GeneratorResumeKind::Next,
                done: false,
            });
            self.sync_estimated_memory_bytes()?;
        }
        let state = self.async_generators[id as usize]
            .delegation
            .expect("delegation initialized");
        self.check_temporary_memory_budget(self.generator_delegation_memory_bytes())?;
        let marker = self
            .generator_delegation
            .as_ref()
            .expect("saved delegation marker");
        let (iterator, kind, started, mut label) = (
            marker.iterator,
            marker.resume_kind,
            marker.started,
            marker.label.clone(),
        );
        if started || state.stage != AsyncDelegateStage::Ready {
            label = label.join(&self.unary_operation_label(resume_dst)?);
        }
        self.replace_pending_hostcall_result_label(Some(label.clone()))?;

        if state.stage == AsyncDelegateStage::CloseResult {
            let result = self.read_reg(resume_dst)?;
            // AsyncIteratorClose validates object-ness, but does not Get done
            // or value. Cleanup rejection/primitive results replace TypeError.
            self.iterator_carrier_backing_id(&result, "iterator return result object")?;
            self.mark_async_delegate_done(iterator)?;
            return Err(Self::missing_async_delegate_throw());
        }
        if state.stage == AsyncDelegateStage::MissingReturn {
            let value = self.read_reg(resume_dst)?;
            self.mark_async_delegate_done(iterator)?;
            self.clear_active_async_delegation(id)?;
            return self.inject_generator_return(LabeledReturn { value, label });
        }
        if state.stage == AsyncDelegateStage::Result {
            let result = self.read_reg(resume_dst)?;
            let done = self.iterator_result_done(module, &result)?;
            let value = self.iterator_result_value(module, &result)?;
            label = label.join(
                &self
                    .take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
            );
            if !state.synchronous {
                let trace_index = match self.iterator_state_mut(iterator)? {
                    RuntimeIteratorState::ForOf(record) => record.trace_index,
                    RuntimeIteratorState::ForIn(_) => unreachable!("yield* has a for-of record"),
                };
                self.record_iteration_next_result_impl(
                    trace_index,
                    (!done).then_some(value.clone()),
                    false,
                    false,
                );
            }
            if done {
                self.mark_async_delegate_done(iterator)?;
                self.clear_active_async_delegation(id)?;
                if state.method == GeneratorResumeKind::Return {
                    return self.inject_generator_return(LabeledReturn { value, label });
                }
                self.write_reg_with_label(resume_dst, value, label)?;
                self.ip += 1;
                return Ok(None);
            }
            self.async_generators[id as usize]
                .delegation
                .as_mut()
                .expect("delegate")
                .stage = AsyncDelegateStage::Ready;
            self.replace_generator_delegation(GeneratorDelegation {
                iterator,
                label: label.clone(),
                resume_kind: GeneratorResumeKind::Next,
                started: true,
            })?;
            return self.suspend_async_delegate(
                id,
                resume_dst,
                AwaitKind::DelegateYield,
                value,
                label,
            );
        }

        self.async_generators[id as usize]
            .delegation
            .as_mut()
            .expect("delegate")
            .method = kind;
        if state.synchronous {
            // The existing sync protocol handles native iterators, cached next,
            // abrupt forwarding and cleanup. AsyncFromSync then awaits VALUE
            // (even when done), before the outer yield* awaits the result object.
            let stepped = (|| match self.step_generator_delegation(module, source, resume_dst)? {
                GeneratorDelegationStep::Yield(result) => {
                    let value = self.iterator_result_value(module, &result.value)?;
                    let label = result.label.join(
                        &self
                            .take_pending_hostcall_result_label()
                            .unwrap_or(Label::Public),
                    );
                    Ok((value, false, label))
                }
                GeneratorDelegationStep::Complete(result)
                | GeneratorDelegationStep::Return(result) => Ok((result.value, true, result.label)),
            })();
            let (value, done, label) = match stepped {
                Ok(result) => result,
                Err(error)
                    if matches!(error, InterpreterError::UncaughtException { .. })
                        || Self::js_catchable_error_name(&error).is_some() =>
                {
                    let (reason, thrown_label) =
                        if matches!(error, InterpreterError::UncaughtException { .. }) {
                            self.take_pending_exception_slot().ok_or_else(|| {
                                InterpreterError::InternalError {
                                    details: "sync delegate lost its exception".into(),
                                }
                            })?
                        } else {
                            (self.native_error_to_thrown_value(&error)?, Label::Public)
                        };
                    let label = label.join(&thrown_label).join(
                        &self
                            .take_pending_hostcall_result_label()
                            .unwrap_or(Label::Public),
                    );
                    let promise = self
                        .create_rejected_promise(Self::value_to_js_value(&reason), label.clone())?;
                    return self.suspend_async_delegate(
                        id,
                        resume_dst,
                        AwaitKind::DelegateResult,
                        Value::Promise(promise.0),
                        label,
                    );
                }
                Err(error) => return Err(error),
            };
            self.async_generators[id as usize]
                .delegation
                .as_mut()
                .expect("delegate")
                .done = done;
            return self.suspend_async_delegate(
                id,
                resume_dst,
                AwaitKind::DelegateSyncValue,
                value,
                label,
            );
        }

        let argument = if started {
            self.read_reg(resume_dst)?
        } else {
            Value::Undefined
        };
        let (receiver, next) = match self.iterator_state_mut(iterator)? {
            RuntimeIteratorState::ForOf(record) => {
                (record.iterator_receiver.clone(), record.next_method.clone())
            }
            RuntimeIteratorState::ForIn(_) => unreachable!("yield* has a for-of record"),
        };
        let receiver = receiver.unwrap_or(Value::Undefined);
        let method = if kind == GeneratorResumeKind::Next {
            next
        } else {
            self.async_delegate_method(module, &receiver, kind)?
        };
        label = label.join(
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
        );
        let (method, arguments, await_kind) = if let Some(method) = method {
            (method, vec![argument], AwaitKind::DelegateResult)
        } else if kind == GeneratorResumeKind::Return {
            return self.suspend_async_delegate(
                id,
                resume_dst,
                AwaitKind::DelegateMissingReturn,
                argument,
                label,
            );
        } else if kind == GeneratorResumeKind::Throw {
            let close =
                self.async_delegate_method(module, &receiver, GeneratorResumeKind::Return)?;
            let Some(close) = close else {
                return Err(Self::missing_async_delegate_throw());
            };
            (close, Vec::new(), AwaitKind::DelegateClose)
        } else {
            return Err(InterpreterError::TypeError {
                expected: "callable iterator.next".into(),
                got: "undefined".into(),
            });
        };
        label = label.join(
            &self
                .take_pending_hostcall_result_label()
                .unwrap_or(Label::Public),
        );
        let (result, callback_label) = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            method,
            receiver,
            arguments,
            Some(label.clone()),
        )?;
        label = label.join(&callback_label);
        self.replace_generator_delegation(GeneratorDelegation {
            iterator,
            label: label.clone(),
            resume_kind: GeneratorResumeKind::Next,
            started: true,
        })?;
        self.suspend_async_delegate(id, resume_dst, await_kind, result, label)
    }

    fn async_delegate_method(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        kind: GeneratorResumeKind,
    ) -> Result<Option<Value>, InterpreterError> {
        let key =
            RuntimePropertyKey::String(JsString::from(if kind == GeneratorResumeKind::Return {
                "return"
            } else {
                "throw"
            }));
        self.iterator_protocol_method(module, receiver.clone(), &key)
    }

    fn missing_async_delegate_throw() -> InterpreterError {
        InterpreterError::TypeError {
            expected: "callable iterator.throw method for async yield*".into(),
            got: "null or undefined iterator.throw".into(),
        }
    }

    fn mark_async_delegate_done(&mut self, iterator: u32) -> Result<(), InterpreterError> {
        if let RuntimeIteratorState::ForOf(record) = self.iterator_state_mut(iterator)? {
            record.done = true;
        }
        Ok(())
    }

    fn clear_active_async_delegation(&mut self, id: u32) -> Result<(), InterpreterError> {
        self.take_generator_delegation();
        self.async_generators[id as usize].delegation = None;
        self.sync_estimated_memory_bytes().map(|_| ())
    }

    pub(super) fn abandon_suspended_async_delegation(
        &mut self,
        id: u32,
    ) -> Result<(), InterpreterError> {
        let generator = &mut self.async_generators[id as usize];
        generator.delegation = None;
        if let Some(execution) = self.generators[generator.generator_id as usize]
            .execution
            .as_mut()
        {
            execution.delegation = None;
        }
        // This runs in the resumer, not inside the generator. Never clear the
        // caller's own delegation or its saved abrupt-completion state.
        self.sync_estimated_memory_bytes().map(|_| ())
    }

    fn suspend_async_delegate(
        &mut self,
        id: u32,
        resume_dst: u32,
        kind: AwaitKind,
        value: Value,
        label: Label,
    ) -> Result<Option<LabeledReturn>, InterpreterError> {
        let previous = self.async_generators_memory_bytes();
        self.async_generators[id as usize].awaited = Some(LabeledReturn {
            value,
            label: label.clone(),
        });
        self.async_generators[id as usize].awaited_kind = kind;
        let next = self.async_generators_memory_bytes();
        if let Err(error) = self.apply_memory_component_delta(previous, next) {
            self.async_generators[id as usize].awaited = None;
            return Err(error);
        }
        self.generator_yielded = true;
        self.generator_resume_dst = Some(resume_dst);
        self.generator_result_label = label.clone();
        // Keep IP at yield*: the saved register receives the awaited outcome
        // and the stage determines whether to call a method or read its result.
        Ok(Some(LabeledReturn {
            value: Value::Undefined,
            label,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(source: &str, throughput: bool) -> (InterpreterCore, Ir3Module, Value) {
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "async-delegate-protocol-labels.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .unwrap();
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "async-delegate-protocol-labels.js"),
            &LoweringContext::new("async-delegate", "protocol-labels", "builtin-only"),
        )
        .unwrap()
        .ir3;
        let mut config = if throughput {
            InterpreterConfig::v8_defaults()
        } else {
            InterpreterConfig::quickjs_defaults()
        };
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "async-delegate-protocol-labels");
        core.execute(&module).unwrap();
        assert_eq!(core.async_generators.len(), 1);
        (core, module, Value::AsyncGeneratorObject(0))
    }

    fn assert_accounting(core: &InterpreterCore) {
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn async_delegate_acquisition_keeps_own_and_inherited_protocol_labels() {
        for throughput in [false, true] {
            for own in [false, true] {
                for key in [
                    RuntimePropertyKey::Symbol(WellKnownSymbol::AsyncIterator.id()),
                    RuntimePropertyKey::String(JsString::from("next")),
                ] {
                    let (mut core, module, receiver) = fixture(
                        "async function* original() { yield 1; } const source = original();",
                        throughput,
                    );
                    let method = core
                        .iterator_protocol_value_property(Some(&module), receiver.clone(), &key)
                        .unwrap();
                    assert!(method.is_callable());
                    let holder = if own {
                        core.own_property_holder(Some(&module), &receiver, true)
                            .unwrap()
                            .unwrap()
                    } else {
                        core.exotic_prototype_link(Some(&module), &receiver)
                            .unwrap()
                            .unwrap()
                    };
                    core.set_object_runtime_property(holder, key.clone(), method)
                        .unwrap();
                    core.set_own_runtime_property_label(holder, &key, &Label::Secret)
                        .unwrap();
                    core.replace_pending_hostcall_result_label(None).unwrap();

                    let (init, synchronous) =
                        core.prepare_async_delegate(&module, &receiver).unwrap();
                    assert!(!synchronous);
                    assert_eq!(init.iterator_receiver, Some(receiver));
                    assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
                    assert_accounting(&core);
                }
            }
        }
    }

    #[test]
    fn async_delegate_noncallable_hooks_keep_secret_error_provenance() {
        for throughput in [false, true] {
            for (key, kind) in [
                (
                    RuntimePropertyKey::Symbol(WellKnownSymbol::AsyncIterator.id()),
                    None,
                ),
                (
                    RuntimePropertyKey::String(JsString::from("return")),
                    Some(GeneratorResumeKind::Return),
                ),
                (
                    RuntimePropertyKey::String(JsString::from("throw")),
                    Some(GeneratorResumeKind::Throw),
                ),
            ] {
                let (mut core, module, receiver) = fixture(
                    "async function* original() { yield 1; } const source = original();",
                    throughput,
                );
                let holder = core
                    .own_property_holder(Some(&module), &receiver, true)
                    .unwrap()
                    .unwrap();
                core.set_object_runtime_property(holder, key.clone(), Value::Int(1))
                    .unwrap();
                core.set_own_runtime_property_label(holder, &key, &Label::Secret)
                    .unwrap();
                core.replace_pending_hostcall_result_label(None).unwrap();
                let error = match kind {
                    Some(kind) => core
                        .async_delegate_method(&module, &receiver, kind)
                        .unwrap_err(),
                    None => core.prepare_async_delegate(&module, &receiver).unwrap_err(),
                };
                assert!(matches!(error, InterpreterError::TypeError { .. }));
                let rejection = core
                    .async_generator_exception(error, &Label::Public)
                    .unwrap();
                assert_eq!(rejection.label, Label::Secret);
                assert!(rejection.value.is_object_like());
                assert_accounting(&core);
            }
        }
    }

    #[test]
    fn async_delegate_throwing_getter_keeps_exact_value_and_selection_label() {
        for throughput in [false, true] {
            for property in ["Symbol.asyncIterator", "'next'"] {
                let source = format!(
                    "async function* original() {{ yield 1; }} const source = original(); \
                     Object.defineProperty(source, {property}, {{ get() {{ throw 17; }} }});"
                );
                let (mut core, module, receiver) = fixture(&source, throughput);
                let key = if property == "Symbol.asyncIterator" {
                    RuntimePropertyKey::Symbol(WellKnownSymbol::AsyncIterator.id())
                } else {
                    RuntimePropertyKey::String(JsString::from("next"))
                };
                let holder = core
                    .own_property_holder(Some(&module), &receiver, false)
                    .unwrap()
                    .unwrap();
                core.set_own_runtime_property_label(holder, &key, &Label::Secret)
                    .unwrap();
                core.replace_pending_hostcall_result_label(None).unwrap();

                let error = core.prepare_async_delegate(&module, &receiver).unwrap_err();
                assert!(matches!(error, InterpreterError::UncaughtException { .. }));
                let rejection = core
                    .async_generator_exception(error, &Label::Public)
                    .unwrap();
                assert_eq!(rejection.value, Value::Int(17));
                assert_eq!(rejection.label, Label::Secret);
                assert!(core.pending_exception.is_none());
                assert_accounting(&core);
            }
        }
    }
}
