//! Synchronous generator resume and delegated iterator protocols.

use super::*;
use crate::ifc_artifacts::Label;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GeneratorResumeKind {
    Next,
    Return,
    Throw,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct GeneratorDelegation {
    iterator: u32,
    resume_dst: u32,
}

enum DelegateCompletion {
    Yield {
        result: Value,
        label: Label,
    },
    Complete {
        kind: GeneratorResumeKind,
        value: Value,
        label: Label,
    },
}

impl InterpreterCore {
    pub(super) fn generator_property(key: &RuntimePropertyKey) -> Option<Value> {
        let kind = match key {
            RuntimePropertyKey::String(name) => match name.as_str()? {
                "next" => BuiltinFunctionKind::GeneratorPrototypeNext,
                "return" => BuiltinFunctionKind::GeneratorPrototypeReturn,
                "throw" => BuiltinFunctionKind::GeneratorPrototypeThrow,
                _ => return None,
            },
            RuntimePropertyKey::Symbol(symbol) if *symbol == WellKnownSymbol::Iterator.id() => {
                BuiltinFunctionKind::IteratorPrototypeIterator
            }
            RuntimePropertyKey::Symbol(_) => return None,
        };
        Some(Value::BuiltinFunction(match kind {
            BuiltinFunctionKind::GeneratorPrototypeNext => BuiltinFunction::generator_next(),
            BuiltinFunctionKind::GeneratorPrototypeReturn => BuiltinFunction::generator_return(),
            kind => BuiltinFunction::promise_method(kind),
        }))
    }

    pub(super) fn complete_sync_generator(&mut self, id: u32) {
        let generator = &mut self.generators[id as usize];
        generator.execution = None;
        generator.resume_dst = None;
        generator.delegation = None;
        generator.owner_module = None;
        generator.retained_program_bytes = 0;
        generator.phase = GeneratorPhase::Completed;
        self.estimated_memory_bytes = self.recompute_estimated_memory_bytes();
    }

    fn mark_generator_delegate_done(&mut self, iterator: u32) -> Result<(), InterpreterError> {
        match self.iterator_state_mut(iterator)? {
            RuntimeIteratorState::ForOf(state) => {
                state.done = true;
                Ok(())
            }
            RuntimeIteratorState::ForIn(_) => Err(InterpreterError::TypeError {
                expected: "yield-star iterator".into(),
                got: "for-in iterator".into(),
            }),
        }
    }

    fn resume_generator_delegate(
        &mut self,
        module: &Ir3Module,
        delegation: GeneratorDelegation,
        kind: GeneratorResumeKind,
        argument: Value,
        argument_label: Label,
    ) -> Result<DelegateCompletion, InterpreterError> {
        let state = match self.iterators.get(delegation.iterator as usize) {
            Some(RuntimeIteratorState::ForOf(state)) => state,
            _ => {
                return Err(InterpreterError::IteratorNotFound {
                    handle: delegation.iterator,
                });
            }
        };
        // Joining labels is their lattice maximum. Move the owned winner when
        // possible, and admit a retained iterator label before cloning it.
        let mut label = if state.label > argument_label {
            self.check_temporary_memory_budget(Self::estimate_label_bytes(&state.label))?;
            state.label.clone()
        } else {
            argument_label
        };
        let clone_bytes = state
            .iterator_receiver
            .as_ref()
            .map(Self::estimate_timer_value_bytes)
            .unwrap_or(0)
            .saturating_add(
                state
                    .next_method
                    .as_ref()
                    .map(Self::estimate_timer_value_bytes)
                    .unwrap_or(0),
            );
        let retained_bytes = clone_bytes
            .saturating_add(Self::estimate_timer_value_bytes(&argument))
            .saturating_add(Self::estimate_label_bytes(&label));
        let outcome = self.with_array_method_temporary(retained_bytes, |core| {
            let (receiver, next) = match &core.iterators[delegation.iterator as usize] {
                RuntimeIteratorState::ForOf(state) => {
                    (state.iterator_receiver.clone(), state.next_method.clone())
                }
                RuntimeIteratorState::ForIn(_) => unreachable!("validated delegated iterator"),
            };
            let result = if let Some(receiver) = receiver {
                let method = if kind == GeneratorResumeKind::Next {
                    next.unwrap_or(Value::Undefined)
                } else {
                    let name = if kind == GeneratorResumeKind::Return {
                        "return"
                    } else {
                        "throw"
                    };
                    core.read_iterator_property(
                        module,
                        &receiver,
                        &RuntimePropertyKey::String(JsString::from(name)),
                        &mut label,
                    )?
                };
                if method.is_nullish() && kind != GeneratorResumeKind::Next {
                    if kind == GeneratorResumeKind::Throw {
                        // Missing throw closes the delegate with no arguments,
                        // then throws TypeError. A failing close takes precedence.
                        core.close_iterator_with_label(
                            module,
                            Value::Iterator(delegation.iterator),
                            IteratorCloseReason::Break,
                            &mut label,
                        )?;
                        return Err(Self::missing_generator_delegate_throw());
                    }
                    core.mark_generator_delegate_done(delegation.iterator)?;
                    return core.generator_delegate_completion(kind, argument, &label);
                }
                if !Self::is_sync_callable(&method) {
                    return Err(InterpreterError::TypeError {
                        expected: "callable delegated iterator method".into(),
                        got: method.type_name().into(),
                    });
                }
                let bytes = Self::estimate_timer_value_bytes(&argument)
                    .saturating_add(Self::estimate_label_bytes(&label))
                    .saturating_mul(2);
                let (completion, result_label) =
                    core.with_array_method_temporary(bytes, |core| {
                        core.invoke_inline_method_call_with_receiver_label(
                            module,
                            method,
                            receiver,
                            label.clone(),
                            &[(argument, label.clone())],
                        )
                    })?;
                label = label.join(&result_label);
                core.complete_inline_call(completion)?
            } else {
                match kind {
                    GeneratorResumeKind::Throw => {
                        core.mark_generator_delegate_done(delegation.iterator)?;
                        return Err(Self::missing_generator_delegate_throw());
                    }
                    GeneratorResumeKind::Return => {
                        core.mark_generator_delegate_done(delegation.iterator)?;
                        return core.generator_delegate_completion(kind, argument, &label);
                    }
                    GeneratorResumeKind::Next => match core.advance_for_of_iterator(
                        module,
                        Value::Iterator(delegation.iterator),
                        &mut label,
                    )? {
                        Some(value) => core.generator_result_object(value, false)?,
                        None => {
                            return core.generator_delegate_completion(
                                kind,
                                Value::Undefined,
                                &label,
                            );
                        }
                    },
                }
            };
            core.iterator_carrier_backing_id(&result, "delegated iterator result object")?;
            let done = core.read_iterator_property(
                module,
                &result,
                &RuntimePropertyKey::String(JsString::from("done")),
                &mut label,
            )?;
            if done.is_truthy() {
                core.mark_generator_delegate_done(delegation.iterator)?;
                let value = core.read_iterator_property(
                    module,
                    &result,
                    &RuntimePropertyKey::String(JsString::from("value")),
                    &mut label,
                )?;
                core.generator_delegate_completion(
                    if kind == GeneratorResumeKind::Return {
                        kind
                    } else {
                        GeneratorResumeKind::Next
                    },
                    value,
                    &label,
                )
            } else {
                // Yield the exact result object. Reading value here would
                // spuriously invoke a getter before the consumer observes it.
                core.check_temporary_memory_budget(
                    Self::estimate_label_bytes(&label).saturating_mul(2),
                )?;
                core.set_for_of_iterator_label(delegation.iterator, label.clone())?;
                Ok(DelegateCompletion::Yield {
                    result,
                    label: label.clone(),
                })
            }
        });
        self.finish_generator_protocol(outcome, label)
    }

    fn missing_generator_delegate_throw() -> InterpreterError {
        InterpreterError::TypeError {
            expected: "delegated iterator with a throw method".into(),
            got: "missing iterator.throw".into(),
        }
    }

    fn generator_delegate_completion(
        &self,
        kind: GeneratorResumeKind,
        value: Value,
        label: &Label,
    ) -> Result<DelegateCompletion, InterpreterError> {
        self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
        Ok(DelegateCompletion::Complete {
            kind,
            value,
            label: label.clone(),
        })
    }

    fn finish_generator_protocol<T>(
        &mut self,
        outcome: Result<T, InterpreterError>,
        label: Label,
    ) -> Result<T, InterpreterError> {
        match outcome {
            Ok(value) => Ok(value),
            Err(error) => match self.finish_native_builtin_call(Err(error), label) {
                Err(error) => Err(error),
                Ok(_) => unreachable!("an error cannot become a completion"),
            },
        }
    }

    fn inject_generator_completion(
        &mut self,
        kind: GeneratorResumeKind,
        argument: Value,
        label: Label,
        resume_dst: Option<u32>,
    ) -> Result<Option<RunLoopExit>, InterpreterError> {
        match kind {
            GeneratorResumeKind::Next => {
                if let Some(register) = resume_dst {
                    self.write_reg_with_label(register, argument, label)?;
                }
            }
            GeneratorResumeKind::Throw => {
                let exception = LabeledException {
                    value: argument,
                    label,
                };
                self.suspend_current_abrupt_completion();
                self.pending_return = None;
                if let Some(frame) = self.pop_exception_target_frame() {
                    self.pending_exception = Some(exception);
                    self.pending_finally_entry =
                        frame.catch_is_finally.then_some(PendingFinallyEntry {
                            target: frame.catch_target,
                            mode: FinallyMode::Exception,
                        });
                    self.ip = frame.catch_target;
                } else {
                    let description = Self::exception_description(&exception.value);
                    return Ok(Some(RunLoopExit::GeneratorThrow {
                        exception,
                        description,
                    }));
                }
            }
            GeneratorResumeKind::Return => {
                self.suspend_current_abrupt_completion();
                self.pending_exception = None;
                if let Some(target) = self.pop_current_finally_target() {
                    self.pending_return = Some(LabeledReturn {
                        value: argument,
                        label,
                    });
                    self.pending_finally_entry = Some(PendingFinallyEntry {
                        target,
                        mode: FinallyMode::Return,
                    });
                    self.ip = target;
                } else {
                    return Ok(Some(RunLoopExit::GeneratorReturn {
                        value: argument,
                        label,
                    }));
                }
            }
        }
        self.sync_estimated_memory_bytes()?;
        Ok(None)
    }

    pub(super) fn run_generator_resume(
        &mut self,
        module: &Ir3Module,
        generator: u32,
        kind: GeneratorResumeKind,
        argument: Value,
        label: Label,
        resume_dst: Option<u32>,
    ) -> Result<RunLoopExit, InterpreterError> {
        let delegation = self.generators[generator as usize].delegation.take();
        let initial = if let Some(delegation) = delegation {
            self.resume_generator_delegate(module, delegation, kind, argument, label)
                .and_then(|completion| {
                    self.apply_delegate_completion(generator, delegation, completion)
                })
        } else {
            self.inject_generator_completion(kind, argument, label, resume_dst)
        };
        if let Some(outcome) = self.route_generator_resume_outcome(module, initial)? {
            return Ok(outcome);
        }
        loop {
            let outcome = match self.run_loop_with_mode(module, RunLoopMode::Generator) {
                Ok(RunLoopExit::GeneratorDelegate {
                    value,
                    mut label,
                    resume_dst,
                }) => {
                    let outcome = (|| {
                        let iterator = self.init_for_of_iterator(module, value, &mut label);
                        let iterator = match iterator {
                            Ok(iterator) => iterator,
                            Err(error) => return self.finish_generator_protocol(Err(error), label),
                        };
                        let delegation = GeneratorDelegation {
                            iterator: self.expect_iterator_handle(iterator)?,
                            resume_dst,
                        };
                        let completion = self.resume_generator_delegate(
                            module,
                            delegation,
                            GeneratorResumeKind::Next,
                            Value::Undefined,
                            label,
                        )?;
                        self.apply_delegate_completion(generator, delegation, completion)
                    })();
                    self.route_generator_resume_outcome(module, outcome)?
                }
                Ok(outcome) => Some(outcome),
                Err(error) => self.route_generator_resume_outcome(module, Err(error))?,
            };
            if let Some(outcome) = outcome {
                return Ok(outcome);
            }
        }
    }

    fn apply_delegate_completion(
        &mut self,
        generator: u32,
        delegation: GeneratorDelegation,
        completion: DelegateCompletion,
    ) -> Result<Option<RunLoopExit>, InterpreterError> {
        match completion {
            DelegateCompletion::Yield { result, label } => {
                self.generators[generator as usize].delegation = Some(delegation);
                Ok(Some(RunLoopExit::GeneratorYield {
                    result,
                    label,
                    resume_dst: delegation.resume_dst,
                }))
            }
            DelegateCompletion::Complete { kind, value, label } => {
                self.inject_generator_completion(kind, value, label, Some(delegation.resume_dst))
            }
        }
    }

    fn route_generator_resume_outcome(
        &mut self,
        module: &Ir3Module,
        outcome: Result<Option<RunLoopExit>, InterpreterError>,
    ) -> Result<Option<RunLoopExit>, InterpreterError> {
        match outcome {
            Err(error)
                if Self::is_js_catchable_error(&error) && self.has_exception_target_frame() =>
            {
                match self.route_run_loop_javascript_error(module, error, RunLoopMode::Generator)? {
                    None => Ok(None),
                    Some(error) => Err(error),
                }
            }
            outcome => outcome,
        }
    }
}
