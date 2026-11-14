use super::*;

impl InterpreterCore {
    pub(super) fn execute_pending_dynamic_import(
        &mut self,
        sequence: u64,
    ) -> Option<Result<(), InterpreterError>> {
        // Keep the map entry until completion. Nested module evaluation can
        // collect, and both the Promise and the CJS context must stay rooted.
        let task = Arc::clone(self.pending_dynamic_imports.get(&sequence)?);
        let retained_bytes = Self::pending_dynamic_import_task_bytes(&task);
        let frame_bytes = Self::estimate_string_bytes(&task.referrer).saturating_add(
            task.cjs_context
                .as_ref()
                .map(|context| Self::estimate_string_bytes(&context.module_specifier))
                .unwrap_or(0),
        );
        let next_context_bytes = task
            .inline_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        let additional_bytes = frame_bytes.saturating_add(next_context_bytes);
        if let Err(error) = self.apply_memory_component_delta(0, additional_bytes) {
            self.pending_dynamic_imports.remove(&sequence);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(retained_bytes);
            return Some(Err(error));
        }
        let previous_context_bytes = self.active_inline_callback_context_memory_bytes();
        // The old label remains owned by this frame while the captured one
        // occupies the accounted interpreter slot. Keep both live in the oracle.
        let suspended_bytes = frame_bytes.saturating_add(previous_context_bytes);
        self.module_snapshot_in_flight_bytes = self
            .module_snapshot_in_flight_bytes
            .saturating_add(suspended_bytes);
        let previous_referrer = self.current_module_specifier.replace(task.referrer.clone());
        let previous_cjs =
            std::mem::replace(&mut self.active_cjs_context, task.cjs_context.clone());
        let previous_context = std::mem::replace(
            &mut self.active_inline_callback_context_label,
            task.inline_context_label.clone(),
        );
        let previous_ip = std::mem::replace(&mut self.ip, task.source_ip);
        let result = self.complete_dynamic_import(&task);
        self.current_module_specifier = previous_referrer;
        self.active_cjs_context = previous_cjs;
        self.active_inline_callback_context_label = previous_context;
        self.ip = previous_ip;
        self.module_snapshot_in_flight_bytes = self
            .module_snapshot_in_flight_bytes
            .saturating_sub(suspended_bytes);
        self.pending_dynamic_imports.remove(&sequence);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(retained_bytes.saturating_add(additional_bytes));
        Some(result)
    }

    pub(super) fn complete_dynamic_import(
        &mut self,
        task: &PendingDynamicImportTask,
    ) -> Result<(), InterpreterError> {
        // Admission at import() time does not authorize a later host effect
        // after revocation. Do this before hooks, resolution or cache access.
        if !live_hostcall_decision(
            crate::capability::DYNAMIC_IMPORT_CAPABILITY,
            &self.config.granted_capabilities,
        ) {
            return Err(InterpreterError::CapabilityDenied {
                capability: RuntimeCapability::ModuleLoad.to_string(),
            });
        }
        check_hostcall_capability_gate(
            self,
            crate::capability::DYNAMIC_IMPORT_CAPABILITY,
            u32::try_from(task.source_ip).unwrap_or(u32::MAX),
        )?;
        self.pending_async_module_import = None;
        let module = task.owner_module.as_ref();
        // This host job starts a fresh observation. The initiating specifier
        // and execution context are retained by the task, independently of a
        // preceding job's temporary hostcall-result publication.
        self.clear_pending_hostcall_result_label();
        let mut native_effect = false;
        let outcome = self
            .dynamic_import_namespace(module, &task.specifier, &mut native_effect)
            .and_then(|namespace| {
                let label = if native_effect && let Value::Object(object) = &namespace {
                    // As for static imports and require, authenticated native
                    // factories read no host source bytes. Keep selection,
                    // cached mutations and accessor observations; source
                    // re-exports still take the ordinary Internal floor.
                    let state =
                        self.native_builtin_state_label_with_floor(module, *object, Label::Public)?;
                    let label = self.join_owned_label_with_temporary_budget(state, &task.label)?;
                    let observed = self
                        .take_pending_hostcall_result_label()
                        .unwrap_or(Label::Public);
                    self.join_owned_label_with_temporary_budget(label, &observed)?
                } else {
                    hostcall_result_contract(crate::capability::DYNAMIC_IMPORT_CAPABILITY)
                        .result_label(&task.label, None)
                };
                Ok((namespace, label))
            });
        let async_evaluation = self.pending_async_module_import.take();
        match outcome {
            Ok((namespace, label)) => {
                // A module still suspended at a top-level await fulfills its
                // evaluation promise with its namespace (or rejects it), so
                // following that promise settles this one when it finishes.
                let value = match async_evaluation {
                    Some((_, evaluation_promise)) => Value::Promise(evaluation_promise.0),
                    None => namespace,
                };
                self.resolve_promise_with_value(Some(module), task.promise, value, label)?;
            }
            Err(error) => {
                let (reason, label) = self.dynamic_import_rejection(error, &task.label)?;
                self.reject_promise(task.promise, reason, label)?;
            }
        }
        Ok(())
    }

    /// Load the module an ImportCall names and return its namespace. The
    /// format is Node's: `.mjs` is an ES module, `.cjs` (and `.json`)
    /// CommonJS, and any other file follows its package.json `"type"` or its
    /// syntax, so a CommonJS module's namespace holds `default:
    /// module.exports` beside its own properties.
    pub(super) fn dynamic_import_namespace(
        &mut self,
        module: &Ir3Module,
        specifier: &str,
        native_effect: &mut bool,
    ) -> Result<Value, InterpreterError> {
        *native_effect = false;
        self.run_pre_import_hook(module, specifier)?;
        // bd-j8f7q: a unit lowered under the bounded-imports contract assumed
        // every ImportCall yields at most IFC_BOUNDED_IMPORT_LABEL, whatever
        // its specifier. Native providers check their live export state, and
        // source modules check their lowered flow ceiling before evaluation.
        let import_bound = Self::unit_declares_bounded_imports(module)
            .then_some(crate::lowering_pipeline::IFC_BOUNDED_IMPORT_LABEL);
        if self.module_resolver.is_some() {
            let delivered = self.resolve_installed_module(
                specifier,
                ImportStyle::Import,
                &ImportAttributes::default(),
            )?;
            let resolved = delivered.module.record.id.clone();
            if let Some(native) = NativeBuiltinModule::from_record(&delivered.module.record) {
                let namespace = self.load_native_builtin_namespace(
                    module,
                    &delivered,
                    native,
                    import_bound.as_ref(),
                )?;
                *native_effect = matches!(
                    native,
                    NativeBuiltinModule::Http
                        | NativeBuiltinModule::Https
                        | NativeBuiltinModule::ChildProcess
                );
                return Ok(namespace);
            }
            return self.load_module_resolved(
                module,
                &resolved,
                ModuleLoadKind::DynamicImport,
                import_bound.as_ref(),
                Some(delivered.module),
            );
        }
        if let Some(native) = NativeBuiltinModule::from_specifier(specifier) {
            let namespace = self.load_ordinary_native_builtin_namespace(
                module,
                specifier,
                native,
                import_bound.as_ref(),
            )?;
            *native_effect = matches!(
                native,
                NativeBuiltinModule::Http
                    | NativeBuiltinModule::Https
                    | NativeBuiltinModule::ChildProcess
            );
            return Ok(namespace);
        }
        if import_bound.is_some()
            && !crate::lowering_pipeline::is_bounded_import_specifier(specifier)
        {
            return Err(InterpreterError::ModuleResolutionFailed {
                specifier: specifier.to_string(),
                reason: ModuleResolutionFailureReason::Other(
                    "a core module is opaque to the bounded-imports contract".to_string(),
                ),
            });
        }
        let resolved = self.resolve_module_specifier(specifier)?;
        self.load_module_resolved(
            module,
            &resolved,
            ModuleLoadKind::DynamicImport,
            import_bound.as_ref(),
            None,
        )
    }

    /// The rejection reason of a failed ImportCall: the value a guest throw
    /// left in the pending-exception slot, a JS error for a catchable native
    /// fault, or an `Error` for a module that cannot be found (code
    /// `ERR_MODULE_NOT_FOUND`, as Node's loader reports), read or evaluated.
    /// Any other failure is not the guest's to catch and is returned as is.
    pub(super) fn dynamic_import_rejection(
        &mut self,
        error: InterpreterError,
        specifier_label: &Label,
    ) -> Result<(crate::object_model::JsValue, Label), InterpreterError> {
        let thrown = match error {
            InterpreterError::UncaughtException { .. } => {
                return match self.take_pending_exception_slot() {
                    Some((thrown, thrown_label)) => Ok((
                        self.promise_value(&thrown)?,
                        thrown_label.join(specifier_label),
                    )),
                    None => Ok((
                        Self::promise_rejection_from_error(&error),
                        specifier_label.clone(),
                    )),
                };
            }
            InterpreterError::ModuleResolutionFailed { specifier, reason } => {
                let failure =
                    self.throw_module_resolution_failure(&specifier, &reason, ImportStyle::Import);
                // Allocating the error or its code may exhaust a runtime
                // budget. A partially constructed pending exception cannot
                // turn that engine failure into a guest-catchable rejection.
                if !matches!(failure, InterpreterError::UncaughtException { .. }) {
                    return Err(failure);
                }
                let Some((thrown, _)) = self.take_pending_exception_slot() else {
                    return Err(failure);
                };
                thrown
            }
            native @ (InterpreterError::ModuleReadFailed { .. }
            | InterpreterError::ModuleEvaluationFailed { .. }) => {
                self.native_error_to_thrown_value(&native)?
            }
            native if Self::js_catchable_error_name(&native).is_some() => {
                self.native_error_to_thrown_value(&native)?
            }
            other => return Err(other),
        };
        Ok((self.promise_value(&thrown)?, specifier_label.clone()))
    }

    pub(super) fn dispatch_promise_hostcall_inner(
        &mut self,
        cap: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        let label = self.join_arg_range_with_object_mutation_label(args)?;
        match cap {
            "promise:constructor" => {
                // Create a new pending promise and return its handle.
                let handle = self.create_promise()?;
                Ok(Value::Promise(handle.0))
            }
            "promise:resolve" => {
                // ES2020 25.6.4.5 Promise.resolve(x) (PromiseResolve with
                // %Promise%): a promise is returned as it is, any other value
                // settles a new promise. Extra arguments are ignored. This
                // never settles an existing promise: only that promise's own
                // resolving functions may, so `Promise.resolve(p, v)` cannot
                // settle someone else's pending `p`, and `Promise.resolve(p)`
                // no longer tries to fulfill `p` with undefined (a TypeError
                // once `p` had settled, e.g. `Promise.resolve(asyncFn())`).
                let arg0 = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                match arg0 {
                    Value::Promise(h) => Ok(Value::Promise(h)),
                    _ => {
                        // Promise.resolve(value): a pending promise resolved
                        // with `value`. Thenable assimilation (ES 25.6.4.5.1)
                        // is applied — a thenable adopts its eventual state
                        // through a PromiseResolveThenableJob rather than
                        // fulfilling with the object itself (bd-iio0f). A
                        // non-thenable fulfills synchronously here, so the
                        // observable result for ordinary values is unchanged.
                        let handle = self.create_promise()?;
                        self.resolve_promise_with_value(module, handle, arg0, label.clone())?;
                        Ok(Value::Promise(handle.0))
                    }
                }
            }
            "promise:reject" => {
                // ES2020 25.6.4.4 Promise.reject(r): always a new promise
                // rejected with `r`, even when `r` is itself a promise; extra
                // arguments are ignored (see promise:resolve).
                let arg0 = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let js_reason = self.promise_value(&arg0)?;
                let handle = self.create_rejected_promise(js_reason, label.clone())?;
                Ok(Value::Promise(handle.0))
            }
            "promise:then" => {
                // arg0 = promise handle, arg1 = onFulfilled (optional),
                // arg2 = onRejected (optional).
                let arg0 = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    return Err(InterpreterError::TypeError {
                        expected: "promise".to_string(),
                        got: "undefined".to_string(),
                    });
                };
                let handle = match arg0 {
                    Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "promise".to_string(),
                            got: arg0.type_name().to_string(),
                        });
                    }
                };
                let on_fulfilled = match self.promise_reaction_arg(args, 1)? {
                    Some(value) => {
                        self.promise_reaction_handler_from_value(value, "onFulfilled")?
                    }
                    None => None,
                };
                let on_rejected = match self.promise_reaction_arg(args, 2)? {
                    Some(value) => self.promise_reaction_handler_from_value(value, "onRejected")?,
                    None => None,
                };
                let result =
                    self.register_promise_then(handle, on_fulfilled, on_rejected, label)?;
                Ok(Value::Promise(result.0))
            }
            "promise:catch" => {
                // Sugar for .then(undefined, onRejected).
                let arg0 = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    return Err(InterpreterError::TypeError {
                        expected: "promise".to_string(),
                        got: "undefined".to_string(),
                    });
                };
                let handle = match arg0 {
                    Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "promise".to_string(),
                            got: arg0.type_name().to_string(),
                        });
                    }
                };
                let on_rejected = match self.promise_reaction_arg(args, 1)? {
                    Some(value) => self.promise_reaction_handler_from_value(value, "onRejected")?,
                    None => None,
                };
                let result = self.register_promise_then(handle, None, on_rejected, label)?;
                Ok(Value::Promise(result.0))
            }
            "promise:finally" => {
                let arg0 = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    return Err(InterpreterError::TypeError {
                        expected: "promise".to_string(),
                        got: "undefined".to_string(),
                    });
                };
                let handle = match arg0 {
                    Value::Promise(h) => crate::promise_model::PromiseHandle(h),
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "promise".to_string(),
                            got: arg0.type_name().to_string(),
                        });
                    }
                };
                let on_finally = self.promise_reaction_arg(args, 1)?;
                // The internal hostcall has no observable species: %Promise%.
                let (then_finally, catch_finally) = self.promise_finally_handlers(
                    on_finally,
                    Value::BuiltinFunction(BuiltinFunction::standard_constructor("Promise")),
                )?;
                let result =
                    self.register_promise_then(handle, then_finally, catch_finally, label)?;
                Ok(Value::Promise(result.0))
            }
            "promise:all" => {
                self.dispatch_promise_combinator(PromiseCombinatorKind::All, args, module)
            }
            "promise:race" => {
                self.dispatch_promise_combinator(PromiseCombinatorKind::Race, args, module)
            }
            "promise:allSettled" => {
                self.dispatch_promise_combinator(PromiseCombinatorKind::AllSettled, args, module)
            }
            "promise:any" => {
                self.dispatch_promise_combinator(PromiseCombinatorKind::Any, args, module)
            }
            _ => {
                // Unknown promise sub-capability — return undefined.
                Ok(Value::Undefined)
            }
        }
    }

    /// Run the event loop until no pending work remains.
    ///
    /// Executes the standard event loop cycle:
    /// 1. Select and execute a macrotask (if any)
    /// 2. Drain all microtasks
    /// 3. Repeat until no pending macrotasks or microtasks
    ///
    /// This is called after top-level script evaluation to handle any
    /// pending timers or other async work before the interpreter exits.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn run_event_loop_until_idle(&mut self) {
        let _ = self.run_event_loop_until_idle_with_module(None);
    }

    pub(super) fn run_event_loop_until_idle_with_module(
        &mut self,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        // bd-9vouw.58: a run gets as many event-loop turns as instructions
        // (at least the historical 10,000), so the operator's
        // --instruction-budget bounds timer-driven work as it bounds straight
        // code. A turn can run no IR instruction (a builtin interval callback),
        // so turns keep their own bound. A fixed 10,000 failed 10,001
        // setTimeout callbacks that Node runs, as an internal invariant
        // violation.
        let max_turns = self.config.instruction_budget.max(10_000);
        let mut turns: u64 = 0;

        while (self.event_loop.has_pending_work() || !self.next_tick_queue.is_empty())
            && turns < max_turns
        {
            if self
                .config
                .cancellation_token
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                self.cancel_all_pending_timer_tasks();
                return Err(InterpreterError::Cancelled);
            }
            // bd-suwvw: unref'd timers do not keep the loop alive. When every
            // remaining macrotask is an unref'd (or cancelled) timer and no
            // microtasks are queued, the program is done — exactly Node's
            // process-exit rule (an unref'd timer may simply never fire).
            if self.event_loop.microtasks.is_empty()
                && self.next_tick_queue.is_empty()
                && self.only_unref_or_cancelled_timers_pending()
            {
                break;
            }

            // Collector safe point between event-loop turns (bd-9vouw.57).
            self.gc_event_loop_safe_point();
            turns += 1;

            // Phase 1: Execute one macrotask (if ready)
            let previous_promise_bytes = self.promise_runtime_memory_bytes();
            let turn_result = self.event_loop.turn();
            let transferred_bytes = self.begin_promise_task_transfer(previous_promise_bytes);
            let mut macrotask_error = None;
            let mut failed_readable = None;
            if let Some(macrotask) = turn_result.macrotask {
                let readable_listener_target = (macrotask.source
                    == crate::promise_model::MacrotaskSource::IoCompletion)
                    .then(|| {
                        self.pending_readable_from_pumps
                            .get(&macrotask.registration_seq)
                            .copied()
                    })
                    .flatten()
                    .filter(|object_id| {
                        self.readable_from_streams
                            .get(object_id)
                            .is_some_and(|state| {
                                matches!(
                                    state.phase,
                                    ReadableFromPumpPhase::Data | ReadableFromPumpPhase::End
                                )
                            })
                    });
                // Execute the macrotask's handler closure. An error escaping a
                // timer, immediate or I/O callback is an uncaught exception
                // that ends the program, as in Node (bd-xzemw, bd-7qwej): it
                // used to be printed and dropped for timers and immediates,
                // and the run exited 0.
                if let Err(err) = self.execute_macrotask_callback(&macrotask, module) {
                    failed_readable = readable_listener_target;
                    macrotask_error = Some(err);
                }
            }
            self.finish_promise_task_transfer(transferred_bytes);
            if let Some(error) = macrotask_error {
                if let Some(object_id) = failed_readable {
                    self.abort_readable_after_async_failure(object_id);
                }
                return Err(error);
            }

            // Phase 2: settle internal Writable work, then drain microtasks.
            self.drain_runtime_checkpoint(module)?;
            self.raise_unhandled_rejection()?;
        }
        if turns >= max_turns
            && self.event_loop.has_pending_work()
            && !(self.event_loop.microtasks.is_empty()
                && self.only_unref_or_cancelled_timers_pending())
        {
            return Err(InterpreterError::BudgetExhausted {
                executed: turns,
                budget: max_turns,
            });
        }
        Ok(())
    }

    /// Node's default `--unhandled-rejections=throw` (bd-xzemw): a Promise
    /// rejected with no handler attached by the end of a microtask checkpoint
    /// is an uncaught exception that ends the program. Before this check an
    /// async failure (`Promise.reject(e)`, a throwing async function nobody
    /// awaited) was dropped and the run exited 0.
    pub(super) fn raise_unhandled_rejection(&mut self) -> Result<(), InterpreterError> {
        let Some(handle) = self
            .promise_store
            .take_unhandled_rejections()
            .into_iter()
            .next()
        else {
            return Ok(());
        };
        let Ok(crate::promise_model::PromiseState::Rejected(reason)) = self
            .promise_store
            .get(handle)
            .map(|record| record.state.clone())
        else {
            return Ok(());
        };
        let reason = self.js_value_to_value(&reason);
        Err(InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&reason),
        })
    }

    /// Drain engine-internal stream lifecycle work before the ordinary
    /// microtask checkpoint. Writable readiness and its monotonic FIFO sequence
    /// live in each accounted state, so selecting the minimum sequence retains
    /// no separate queue allocation or capacity. A microtask may complete a
    /// delayed `_write`, so repeat until both phases reach a fixed point
    /// (bounded like the surrounding event loop).
    pub(super) fn drain_runtime_checkpoint(
        &mut self,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        const MAX_CHECKPOINT_ROUNDS: u32 = 10_000;
        let mut first_error = None;
        for _ in 0..MAX_CHECKPOINT_ROUNDS {
            while let Some(object_id) = self.next_scheduled_writable_tick()? {
                if let Some(state) = self.writable_streams.get_mut(&object_id) {
                    state.tick_sequence = None;
                    let emitting_terminal_error =
                        self.writable_streams.get(&object_id).is_some_and(|state| {
                            state.tick_phase == WritableTickPhase::Error
                                && state.finished_end_callback_batch_remaining == 0
                                && !(matches!(
                                    state.terminal_error_origin,
                                    Some(WritableErrorOrigin::Write | WritableErrorOrigin::Destroy)
                                ) && state.end_callback_batch_remaining > 0)
                        });
                    if let Err(error) = self.drive_writable_tick(object_id, module) {
                        if emitting_terminal_error || Self::stops_guest_execution(&error) {
                            // An unhandled stream `error` is process-fatal in
                            // the reference runtime. Do not run close handlers,
                            // other Writable ticks, or the ordinary microtask
                            // queue. Runtime/security failures have the same
                            // stop boundary even outside the stream-error phase.
                            return Err(error);
                        }
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                    continue;
                }

                if let Some(state) = self.writable_terminal_states.get_mut(&object_id) {
                    if state.tick_sequence.take().is_some() {
                        self.pending_writable_terminal_ticks =
                            self.pending_writable_terminal_ticks.saturating_sub(1);
                    }
                    if let Err(error) = self.drive_writable_terminal_tick(object_id, module) {
                        if Self::stops_guest_execution(&error) {
                            return Err(error);
                        }
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                } else {
                    return Err(InterpreterError::InternalError {
                        details: "scheduled Writable tick lost both live and terminal state"
                            .to_string(),
                    });
                }
            }
            self.drain_microtasks(module)?;
            if self.pending_writable_terminal_ticks == 0
                && !self
                    .writable_streams
                    .values()
                    .any(|state| state.tick_sequence.is_some())
            {
                return match first_error {
                    Some(error) => Err(error),
                    None => Ok(()),
                };
            }
        }
        Err(
            first_error.unwrap_or_else(|| InterpreterError::InternalError {
                details: "Writable runtime checkpoint round limit exhausted".to_string(),
            }),
        )
    }

    /// The callable a Promise reaction or thenable-job handle names.
    /// Synthetic handles at/above the base name a retained non-closure
    /// callable (builtin, async/generator function object); everything
    /// below is a real closure-table id.
    pub(super) fn promise_reaction_callee(
        &self,
        handler: crate::closure_model::ClosureHandle,
    ) -> Result<Value, InterpreterError> {
        if handler.0 >= PROMISE_REACTION_CALLABLE_BASE {
            self.promise_reaction_callables
                .get(&handler.0)
                .cloned()
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "registered Promise reaction callable handler".to_string(),
                    got: format!("unknown reaction callable #{}", handler.0),
                })
        } else {
            Ok(Value::Closure(handler.0))
        }
    }

    pub(super) fn execute_promise_reaction_handler(
        &mut self,
        module: Option<&Ir3Module>,
        handler: crate::closure_model::ClosureHandle,
        arguments: Vec<Value>,
        task_label: Label,
    ) -> Result<(Value, Label), InterpreterError> {
        let module = module.ok_or_else(|| InterpreterError::TypeError {
            expected: "module-backed Promise reaction handler dispatch".to_string(),
            got: "missing module context".to_string(),
        })?;
        let callee = self.promise_reaction_callee(handler)?;
        // Promise reactions are control-dependent on settlement as well as
        // value-dependent on the delivered argument. Run the whole isolated
        // callback under the queued task label so ignored arguments cannot
        // make side effects, hostcalls, or nested Promise work appear Public.
        let result = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            callee,
            Value::Undefined,
            arguments,
            Some(task_label),
        );
        match &result {
            Ok(_) => self.push_component_event(
                "promise_reaction",
                "reaction_handler_executed",
                "ok",
                None,
            ),
            Err(error) => {
                let detail = error.to_string();
                self.push_component_event(
                    "promise_reaction",
                    "reaction_handler_executed",
                    "error",
                    Some(&detail),
                );
            }
        }
        // The callback can read classified captures independently of the
        // queued task's label. Keep its returned provenance with the Value
        // through the derived promise's resolution and thenable observations.
        result
    }

    /// Whether a promise handle has left the pending state.
    pub(super) fn promise_is_settled(&self, handle: crate::promise_model::PromiseHandle) -> bool {
        self.promise_store
            .get(handle)
            .map(|record| record.state.is_settled())
            .unwrap_or(false)
    }

    /// Resolve `target` to a native promise `source` (ES2020 25.6.3.2 promise
    /// resolution specialized to internal promises): a settled source copies
    /// its state directly, a pending source registers identity-forwarding
    /// reactions via [`crate::promise_model::PromiseStore::register_native_adoption`],
    /// and self-resolution rejects with a TypeError per spec.
    pub(super) fn resolve_promise_to_native(
        &mut self,
        target: crate::promise_model::PromiseHandle,
        source: crate::promise_model::PromiseHandle,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        if target == source {
            // ES2020 25.6.1.3.2 step 6: a TypeError object, as V8 reports it.
            let prototype = self.ensure_builtin_prototype("TypeError")?;
            let error_id = self.alloc_object_with_prototype(Some(prototype))?;
            self.initialize_error_like_object(
                error_id,
                "TypeError",
                "Chaining cycle detected for promise #<Promise>".to_string(),
            )?;
            let reason = self.promise_value(&Value::Object(error_id))?;
            return self.reject_promise(target, reason, label);
        }
        let (source_state, label) = self
            .promise_store
            .get(source)
            .map(|record| (record.state.clone(), label.join(&record.label)))
            .map_err(|_| InterpreterError::TypeError {
                expected: "valid promise handle".to_string(),
                got: "invalid promise resolution source".to_string(),
            })?;
        match source_state {
            crate::promise_model::PromiseState::Fulfilled(value) => {
                self.fulfill_promise(target, value, label)
            }
            crate::promise_model::PromiseState::Rejected(reason) => {
                // Adopting a settled source handles its rejection, as the
                // pending-source path does through its forwarding reaction.
                self.promise_store
                    .mark_rejection_handled(source)
                    .map_err(|error| InterpreterError::TypeError {
                        expected: "valid promise handle".to_string(),
                        got: error.to_string(),
                    })?;
                self.reject_promise(target, reason, label)
            }
            crate::promise_model::PromiseState::Pending => {
                let previous_promise_bytes = self.promise_runtime_memory_bytes();
                let next_store_bytes = self
                    .promise_store
                    .projected_native_adoption_memory_bytes(source, &label)
                    .map_err(|error| InterpreterError::TypeError {
                        expected: "pending native promise adoption source".to_string(),
                        got: error.to_string(),
                    })?;
                // Registration enqueues nothing; the queue term is carried
                // through unchanged so the composition mirrors
                // [`Self::register_promise_then`].
                let next_queue_bytes = self.event_loop.microtasks.estimated_memory_bytes();
                let next_promise_bytes = next_store_bytes
                    .saturating_add(
                        self.event_loop
                            .estimated_memory_bytes()
                            .saturating_sub(self.event_loop.microtasks.estimated_memory_bytes())
                            .saturating_add(next_queue_bytes),
                    )
                    .saturating_add(self.promise_combinators_memory_bytes())
                    .saturating_add(self.promise_combinator_watchers_memory_bytes())
                    .saturating_add(self.promise_in_flight_task_bytes);
                self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
                self.promise_store
                    .register_native_adoption(source, target, label)
                    .expect("preflighted native promise adoption must remain valid");
                self.settle_projected_promise_bytes(next_promise_bytes)?;
                // `target` now follows `source`: the resolving functions that
                // chose it are already resolved (bd-9vouw.174).
                self.retire_promise_resolvers(target)
            }
        }
    }

    /// ES2020 25.6.1.3.2 Promise Resolve Function: resolve `promise` with
    /// `value`. If `value` is a thenable (an object exposing a callable `then`),
    /// adopt its eventual state by enqueuing a PromiseResolveThenableJob rather
    /// than fulfilling with the object itself; otherwise fulfill directly.
    ///
    /// `then` is read once with the full [[Get]] (bd-9vouw.174): a method a
    /// class or prototype defines, a getter and a Proxy trap all count, and
    /// any callable qualifies. A Get that throws rejects `promise` with the
    /// thrown value (step 10).
    pub(super) fn resolve_promise_with_value(
        &mut self,
        module: Option<&Ir3Module>,
        promise: crate::promise_model::PromiseHandle,
        value: Value,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        if let Value::Promise(source_handle) = value {
            return self.resolve_promise_with_native(module, promise, source_handle, label);
        }
        if !value.is_object_like() {
            let value = self.promise_value(&value)?;
            return self.fulfill_promise(promise, value, label);
        }
        self.resolve_promise_with_observable_then(module, promise, value, label)
    }

    /// The observable part of Promise Resolve Functions, also used when
    /// PromiseResolve must wrap a native promise with a different constructor.
    pub(super) fn resolve_promise_with_observable_then(
        &mut self,
        module: Option<&Ir3Module>,
        promise: crate::promise_model::PromiseHandle,
        value: Value,
        label: Label,
    ) -> Result<(), InterpreterError> {
        // Resolve functions claim their once-only pair before Get(then): an
        // own getter can re-enter a saved resolver while the promise is still
        // pending. The eventual thenable job gets a fresh pair for this epoch.
        self.retire_promise_resolvers(promise)?;
        // The Get may run a getter or a trap; what it reads labels the
        // resolution. The enclosing HostCall's pending result label is set
        // aside so this read neither joins into nor clears it.
        let saved_result_label = self.take_pending_hostcall_result_label();
        let key = RuntimePropertyKey::String(JsString::from("then"));
        // Resolution can resume after a reaction's callback context has been
        // restored. The value's label must govern the Get itself, including
        // getters that ignore their receiver and perform zero-argument effects.
        let then = self.in_promise_resolution_context(&label, |core| match &value {
            Value::Object(object) => {
                core.iterator_protocol_property(module, *object, &key, value.clone())
            }
            _ => match module {
                Some(module) => core.get_v(module, &value, &key),
                None => Err(InterpreterError::TypeError {
                    expected: "module-backed PromiseResolve property read".to_string(),
                    got: "missing module context".to_string(),
                }),
            },
        });
        let observed = self.take_pending_hostcall_result_label();
        if let Some(saved) = saved_result_label {
            self.replace_pending_hostcall_result_label(Some(saved))?;
        }
        let label = match observed {
            Some(observed) => label.join(&observed),
            None => label,
        };
        let then = match then {
            Ok(then) => then,
            Err(error) => {
                let (reason, reason_label) = self.thrown_completion_value(error, &label)?;
                let reason = self.promise_value(&reason)?;
                return self.reject_promise(promise, reason, reason_label);
            }
        };
        match self.promise_reaction_handler_from_value(then, "thenable then")? {
            Some(handler) => self.enqueue_resolve_thenable(promise, handler, value, label),
            None => {
                let value = self.promise_value(&value)?;
                self.fulfill_promise(promise, value, label)
            }
        }
    }

    /// The Promise Resolve Function with a native promise (ES2020 25.6.1.3.2
    /// steps 6-12). Resolving with itself is a TypeError at once. Otherwise
    /// `then` is read now: the intrinsic %Promise.prototype.then% makes the
    /// PromiseResolveThenableJob an adoption of the native promise, which
    /// settles `promise` two jobs later, as in Node; adopting at once settled
    /// it two ticks early (an async function returning a promise, `resolve(p)`
    /// in an executor, a `then` callback returning a promise). An own or
    /// patched `then` runs as any thenable's, and a non-callable one
    /// fulfills `promise` with the source itself (bd-9vouw.323).
    pub(super) fn resolve_promise_with_native(
        &mut self,
        module: Option<&Ir3Module>,
        promise: crate::promise_model::PromiseHandle,
        source_handle: u32,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let source = crate::promise_model::PromiseHandle(source_handle);
        let Some(module) = module.filter(|_| source != promise) else {
            return self.resolve_promise_to_native(promise, source, label);
        };
        // Claim the resolving pair before the observable Get, just as for
        // other thenables. A native promise's own getter can call the saved
        // resolve/reject functions while the target is still pending.
        self.retire_promise_resolvers(promise)?;
        // As for any thenable, what the Get reads labels the resolution, and
        // the enclosing HostCall's pending result label is set aside.
        let saved_result_label = self.take_pending_hostcall_result_label();
        let then = self.in_promise_resolution_context(&label, |core| {
            core.get_v(
                module,
                &Value::Promise(source_handle),
                &RuntimePropertyKey::String(JsString::from("then")),
            )
        });
        let observed = self.take_pending_hostcall_result_label();
        if let Some(saved) = saved_result_label {
            self.replace_pending_hostcall_result_label(Some(saved))?;
        }
        let label = match observed {
            Some(observed) => label.join(&observed),
            None => label,
        };
        let then = match then {
            Ok(then) => then,
            Err(error) => {
                let (reason, reason_label) = self.thrown_completion_value(error, &label)?;
                let reason = self.promise_value(&reason)?;
                return self.reject_promise(promise, reason, reason_label);
            }
        };
        // The adoption stands in for the job's `then` call only when that
        // call is unobservable: a subclass instance's `then` constructs the
        // subclass, so it runs as any thenable's (bd-9vouw.349).
        if matches!(&then, Value::BuiltinFunction(builtin)
            if builtin.kind == BuiltinFunctionKind::PromiseThen && builtin.bound_object.is_none())
            && self.native_then_is_inert(module, &Value::Promise(source_handle))?
        {
            return self.enqueue_adopt_native(promise, source, false, label);
        }
        match self.promise_reaction_handler_from_value(then, "thenable then")? {
            Some(handler) => self.enqueue_resolve_thenable(
                promise,
                handler,
                Value::Promise(source_handle),
                label,
            ),
            None => {
                let value = self.promise_value(&Value::Promise(source_handle))?;
                self.fulfill_promise(promise, value, label)
            }
        }
    }

    /// Enqueue an [`crate::promise_model::Microtask::AdoptNative`] job
    /// (memory-preflighted, as [`Self::enqueue_resolve_thenable`]). The
    /// first (`settle` false) is the resolving functions' resolution: the
    /// caller has already claimed the pair before its observable Get(then).
    pub(super) fn enqueue_adopt_native(
        &mut self,
        promise: crate::promise_model::PromiseHandle,
        source: crate::promise_model::PromiseHandle,
        settle: bool,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let task = crate::promise_model::Microtask::AdoptNative {
            promise,
            source,
            settle,
            label,
        };
        let next_queue_bytes = self
            .event_loop
            .microtasks
            .projected_enqueue_memory_bytes(&task);
        let next_promise_bytes = self
            .promise_store
            .estimated_memory_bytes()
            .saturating_add(
                self.event_loop
                    .estimated_memory_bytes()
                    .saturating_sub(self.event_loop.microtasks.estimated_memory_bytes())
                    .saturating_add(next_queue_bytes),
            )
            .saturating_add(self.promise_combinators_memory_bytes())
            .saturating_add(self.promise_combinator_watchers_memory_bytes())
            .saturating_add(self.promise_in_flight_task_bytes);
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
        self.event_loop.microtasks.enqueue(task);
        self.settle_projected_promise_bytes(next_promise_bytes)
    }

    /// Enqueue a PromiseResolveThenableJob (memory-preflighted, mirroring
    /// [`Self::queue_microtask_from_value`]).
    pub(super) fn enqueue_resolve_thenable(
        &mut self,
        promise: crate::promise_model::PromiseHandle,
        then_handler: crate::closure_model::ClosureHandle,
        thenable: Value,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let thenable = self.promise_value(&thenable)?;
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let task = crate::promise_model::Microtask::ResolveThenable {
            promise,
            then_handler,
            thenable,
            label,
        };
        let next_queue_bytes = self
            .event_loop
            .microtasks
            .projected_enqueue_memory_bytes(&task);
        let next_promise_bytes = self
            .promise_store
            .estimated_memory_bytes()
            .saturating_add(
                self.event_loop
                    .estimated_memory_bytes()
                    .saturating_sub(self.event_loop.microtasks.estimated_memory_bytes())
                    .saturating_add(next_queue_bytes),
            )
            .saturating_add(self.promise_combinators_memory_bytes())
            .saturating_add(self.promise_combinator_watchers_memory_bytes())
            .saturating_add(self.promise_in_flight_task_bytes);
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
        self.event_loop.microtasks.enqueue(task);
        self.settle_projected_promise_bytes(next_promise_bytes)
    }

    /// Build a single-use resolve/reject capability function bound to
    /// `promise` (ES CreateResolvingFunctions). The bound promise handle rides
    /// in `bound_object`; the [`BuiltinFunctionKind::PromiseResolve`] /
    /// `PromiseReject` apply arms interpret a bound handle as a capability call
    /// rather than the static `Promise.resolve`/`Promise.reject` constructor
    /// methods. `iterator_handle` (a per-kind slot) carries the pair's
    /// resolver epoch (bd-9vouw.174).
    pub(super) fn make_promise_capability(
        &self,
        kind: BuiltinFunctionKind,
        promise: crate::promise_model::PromiseHandle,
    ) -> Value {
        let mut builtin = BuiltinFunction::new_kind(kind);
        builtin.bound_object = Some(promise.0);
        builtin.iterator_handle = Some(u32::from(self.promise_resolver_epoch(promise)));
        Value::BuiltinFunction(builtin)
    }

    pub(super) fn promise_resolver_epoch(
        &self,
        promise: crate::promise_model::PromiseHandle,
    ) -> u16 {
        self.promise_store.resolver_epoch(promise).unwrap_or(0)
    }

    /// Whether the resolving-function pair of `epoch` may still settle
    /// `promise`: it is pending and the pair has not resolved it already
    /// (ES2020 25.6.1.3 `alreadyResolved`).
    pub(super) fn promise_resolvers_live(
        &self,
        promise: crate::promise_model::PromiseHandle,
        epoch: u16,
    ) -> bool {
        !self.promise_is_settled(promise) && self.promise_resolver_epoch(promise) == epoch
    }

    /// The pair of `promise`'s current resolving functions has resolved it to
    /// a promise or thenable it now follows: their later calls do nothing.
    pub(super) fn retire_promise_resolvers(
        &mut self,
        promise: crate::promise_model::PromiseHandle,
    ) -> Result<(), InterpreterError> {
        self.promise_store
            .retire_resolving_functions(promise)
            .map_err(|error| InterpreterError::TypeError {
                expected: "valid promise handle".to_string(),
                got: error.to_string(),
            })
    }

    /// Apply a resolve/reject capability bound to `promise`. Settling is
    /// once-only (ES `alreadyResolved`): a call after the promise has left the
    /// pending state, or after this pair resolved it to a promise or thenable
    /// it now follows, is a silent no-op returning `undefined`. `epoch` is the
    /// pair's (None for an engine-internal application).
    pub(super) fn apply_promise_capability(
        &mut self,
        module: Option<&Ir3Module>,
        promise: crate::promise_model::PromiseHandle,
        epoch: Option<u32>,
        args: RegRange,
        is_resolve: bool,
    ) -> Result<Value, InterpreterError> {
        let argument = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };
        if self.promise_is_settled(promise)
            || epoch.is_some_and(|epoch| epoch != u32::from(self.promise_resolver_epoch(promise)))
        {
            return Ok(Value::Undefined);
        }
        let label = self.join_arg_range_with_object_mutation_label(args)?;
        if is_resolve {
            self.resolve_promise_with_value(module, promise, argument, label)?;
        } else {
            let reason = self.promise_value(&argument)?;
            self.reject_promise(promise, reason, label)?;
        }
        Ok(Value::Undefined)
    }

    /// `new Promise(executor)` (ES2020 25.6.3.1, bd-auy04): create a pending
    /// promise, call `executor(resolve, reject)` synchronously with its
    /// one-shot resolving functions, and reject the promise when the executor
    /// throws. Only guest-catchable errors become rejections; engine faults
    /// and resource limits (budget, memory, containment) keep propagating.
    pub(super) fn construct_promise(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let executor = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };
        if !executor.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "Promise resolver function".to_string(),
                got: executor.type_name().to_string(),
            });
        }
        let executor_label = self.join_arg_range_label(args)?;
        let promise = self.create_promise()?;
        let executor_epoch = self.promise_resolver_epoch(promise);
        let resolve = self.make_promise_capability(BuiltinFunctionKind::PromiseResolve, promise);
        let reject = self.make_promise_capability(BuiltinFunctionKind::PromiseReject, promise);
        if let Err(error) = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            executor,
            Value::Undefined,
            vec![resolve, reject],
            Some(executor_label.clone()),
        ) {
            // The rejection reason is the thrown value itself (an explicit
            // `throw`, taken from the isolated run's pending slot so the slot
            // never stays armed) or the JS error object for a catchable native
            // fault.
            let (reason, reason_label) = match &error {
                InterpreterError::UncaughtException { .. } => {
                    match self.take_pending_exception_slot() {
                        Some((thrown, thrown_label)) => (
                            self.promise_value(&thrown)?,
                            thrown_label.join(&executor_label),
                        ),
                        None => (
                            Self::promise_rejection_from_error(&error),
                            executor_label.clone(),
                        ),
                    }
                }
                native if Self::js_catchable_error_name(native).is_some() => {
                    let thrown = self.native_error_to_thrown_value(native)?;
                    (self.promise_value(&thrown)?, executor_label.clone())
                }
                _ => return Err(error),
            };
            // A resolving function already called by the executor wins: a
            // later throw is inert (ES `alreadyResolved`), also when it
            // resolved the promise to one it now follows.
            if self.promise_resolvers_live(promise, executor_epoch) {
                self.reject_promise(promise, reason, reason_label)?;
            }
        }
        Ok(Value::Promise(promise.0))
    }

    pub(super) fn promise_rejection_from_error(
        error: &InterpreterError,
    ) -> crate::object_model::JsValue {
        match error {
            InterpreterError::UncaughtException { value } => {
                crate::object_model::JsValue::Str(value.clone())
            }
            other => crate::object_model::JsValue::Str(other.to_string()),
        }
    }

    /// Drain all pending microtasks from the queue.
    ///
    /// Each microtask may enqueue additional microtasks; the drain continues
    /// until the queue is empty, matching ES2020 semantics (microtask checkpoint).
    /// A safety bound prevents infinite loops from pathological promise chains.
    /// Drain the `process.nextTick` job queue until it is empty (bd-8nrud).
    ///
    /// Node semantics: the tick queue runs to exhaustion — including ticks
    /// enqueued by tick callbacks — before any Promise microtask. Each
    /// executed tick counts in the caller's `drained`. An uncaught exception
    /// in a tick callback aborts the drain fail-closed (Node's equivalent
    /// crashes the process).
    pub(super) fn drain_next_tick_queue(
        &mut self,
        module: Option<&Ir3Module>,
        drained: &mut u64,
    ) -> Result<(), InterpreterError> {
        loop {
            // Collector safe point between nextTick callbacks (bd-9vouw.57).
            self.gc_event_loop_safe_point();
            let previous_bytes = self.next_tick_queue_memory_bytes();
            let Some(task) = self.next_tick_queue.pop_front() else {
                break;
            };
            self.apply_memory_component_delta(previous_bytes, self.next_tick_queue_memory_bytes())?;
            *drained += 1;
            let module = module.ok_or_else(|| InterpreterError::TypeError {
                expected: "module-backed process.nextTick dispatch".to_string(),
                got: "missing module context".to_string(),
            })?;
            self.invoke_inline_method_call_with_argument_label(
                Some(module),
                task.callback,
                Value::Undefined,
                task.args,
                Some(task.label),
            )?;
        }
        Ok(())
    }

    pub(super) fn drain_microtasks(
        &mut self,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        // The checkpoint runs until both queues are empty, as Node's does: it
        // used to stop after 10,000 jobs and let a timer run ahead of the
        // jobs still queued (bd-9vouw.478: 20,000 reactions on one promise
        // printed "many 10000" from a setTimeout). It ends: a job that queues
        // another runs guest code, which the instruction budget bounds, and a
        // native job (a resolve function, a combinator element) only settles
        // promises that guest code created and registered reactions on.
        let mut drained = 0u64;
        #[cfg(test)]
        let entry_drift = self.memory_walk_drift();
        let mut dequeued_since_compaction = 0u32;
        // Node's processTicksAndRejections: drain the whole next-tick queue,
        // then let the microtask checkpoint run every queued job (jobs those
        // jobs queue included), and only then the ticks queued meanwhile;
        // repeat until both are empty. Draining the ticks before every job
        // ran a tick that a job queued ahead of the jobs already waiting
        // (bd-9vouw.319).
        let mut tick_round = true;

        loop {
            // Collector safe point between microtasks (bd-9vouw.57).
            self.gc_event_loop_safe_point();
            // bd-9vouw.71: a consumed queue slot stays charged until the
            // queue compacts. A drain of thousands of chained jobs (an await
            // loop) releases them every MICROTASK_COMPACTION_INTERVAL jobs
            // rather than only when the drain returns.
            if dequeued_since_compaction >= MICROTASK_COMPACTION_INTERVAL {
                dequeued_since_compaction = 0;
                let previous_promise_bytes = self.promise_runtime_memory_bytes();
                self.event_loop.microtasks.compact();
                self.apply_promise_runtime_memory_delta(previous_promise_bytes)?;
            }
            // bd-8nrud: the next-tick queue drains completely before the
            // round's Promise microtasks.
            if tick_round {
                self.drain_next_tick_queue(module, &mut drained)?;
                tick_round = false;
            }
            let previous_promise_bytes = self.promise_runtime_memory_bytes();
            let Some(task) = self.event_loop.microtasks.dequeue() else {
                if self.next_tick_queue.is_empty() {
                    break;
                }
                // Ticks the round's jobs queued run now, then their jobs.
                tick_round = true;
                continue;
            };
            let transferred_bytes = self.begin_promise_task_transfer(previous_promise_bytes);
            drained += 1;
            dequeued_since_compaction += 1;
            let task_result = (|| -> Result<(), InterpreterError> {
                match &task {
                    crate::promise_model::Microtask::PromiseCombinator {
                        combinator,
                        kind,
                        argument,
                        result_promise,
                        label,
                    } => {
                        let result = match kind {
                            crate::promise_model::ReactionKind::Fulfill => self
                                .update_combinator_fulfillment(
                                    module,
                                    combinator.combinator_id,
                                    combinator.index,
                                    argument,
                                    label,
                                ),
                            crate::promise_model::ReactionKind::Reject => self
                                .update_combinator_rejection(
                                    module,
                                    combinator.combinator_id,
                                    combinator.index,
                                    argument,
                                    label,
                                ),
                        };
                        if let Err(error) = result {
                            self.terminally_reject_native_combinator(*result_promise, label);
                            return Err(error);
                        }
                    }
                    crate::promise_model::Microtask::PromiseReaction {
                        handler,
                        argument,
                        result_promise,
                        label: task_label,
                    } => {
                        // Check if this is an async function resumption
                        if handler.is_none() {
                            if let Some(context) = self
                                .async_generator_runtime
                                .continuations
                                .remove(&result_promise.0)
                            {
                                self.resume_async_generator_task(
                                    context,
                                    Ok(argument.clone()),
                                    task_label.clone(),
                                    module,
                                )?;
                                self.release_await_carrier(*result_promise);
                                return Ok(());
                            }
                            // Check if there's an async resumption context for this promise
                            if let Some(resumption_context) =
                                self.async_resumption_contexts.remove(&result_promise.0)
                            {
                                // Resume the async function. This loop holds the
                                // await carrier and the settled value
                                // (bd-9vouw.77).
                                let held = vec![
                                    Value::Promise(result_promise.0),
                                    self.js_value_to_value(argument),
                                ];
                                if let Err(err) = self.with_event_job_gc_request(held, |this| {
                                    this.resume_async_function_task(
                                        resumption_context,
                                        Ok(argument.clone()),
                                        task_label.clone(),
                                        module,
                                    )
                                }) {
                                    let reason = Self::promise_rejection_from_error(&err);
                                    let _ = self.reject_promise(
                                        *result_promise,
                                        reason,
                                        task_label.clone(),
                                    );
                                    return Err(err);
                                }
                                self.release_await_carrier(*result_promise);
                            } else if let Some(resumption_context) = self
                                .top_level_await_resumption_contexts
                                .remove(&result_promise.0)
                            {
                                self.resume_module_evaluation_task(
                                    resumption_context,
                                    Ok(argument.clone()),
                                    task_label.clone(),
                                    module,
                                )?;
                                self.release_await_carrier(*result_promise);
                            } else {
                                // With no closure handler, the identity transform propagates
                                // the argument to the result promise as a fulfillment value.
                                self.fulfill_promise(
                                    *result_promise,
                                    argument.clone(),
                                    task_label.clone(),
                                )?;
                            }
                        } else {
                            let Some(handler) = *handler else {
                                unreachable!("handler.is_some() checked above");
                            };
                            // This loop holds the derived promise it settles
                            // with the handler's result (bd-9vouw.77).
                            let held = vec![Value::Promise(result_promise.0)];
                            match self.with_event_job_gc_request(held, |this| {
                                let argument = this.js_value_to_value(argument);
                                this.execute_promise_reaction_handler(
                                    module,
                                    handler,
                                    vec![argument],
                                    task_label.clone(),
                                )
                            }) {
                                // The chain result is resolved with the
                                // handler's result (ES2020 PromiseReactionJob):
                                // a native promise or a thenable is adopted,
                                // never used as the fulfillment value.
                                Ok((result, result_label)) => {
                                    self.resolve_promise_with_value(
                                        module,
                                        *result_promise,
                                        result,
                                        task_label.join(&result_label),
                                    )?;
                                }
                                Err(err) => {
                                    // Budgets, containment and `process.exit`
                                    // (bd-my9hk) are not JS exceptions: they end
                                    // the run instead of rejecting the chain,
                                    // exactly as in the executor path.
                                    if !matches!(err, InterpreterError::UncaughtException { .. })
                                        && Self::js_catchable_error_name(&err).is_none()
                                    {
                                        return Err(err);
                                    }
                                    // A guest throw re-arms the thrown value in
                                    // the pending-exception slot; reject with it
                                    // (an Error object stays an object) instead
                                    // of its stringified message (bd-9vouw.38).
                                    let (reason, reason_label) =
                                        match self.take_pending_exception_slot() {
                                            Some((thrown, thrown_label)) => (
                                                self.promise_value(&thrown)?,
                                                thrown_label.join(task_label),
                                            ),
                                            None => (
                                                Self::promise_rejection_from_error(&err),
                                                task_label.clone(),
                                            ),
                                        };
                                    self.reject_promise(*result_promise, reason, reason_label)?;
                                }
                            }
                        }
                    }
                    // queueMicrotask(callback) (bd-9vouw.478): the callback
                    // gets no arguments, its value is dropped, and a throw is
                    // an uncaught exception that ends the run here, as in
                    // Node. It used to reject a promise nobody held, and the
                    // jobs after it still ran before that was reported.
                    crate::promise_model::Microtask::QueuedCallback {
                        handler,
                        label: task_label,
                    } => {
                        let held = vec![self.promise_reaction_callee(*handler)?];
                        self.with_event_job_gc_request(held, |this| {
                            this.execute_promise_reaction_handler(
                                module,
                                *handler,
                                Vec::new(),
                                task_label.clone(),
                            )
                        })?;
                    }
                    crate::promise_model::Microtask::PromiseRejection {
                        reason,
                        result_promise,
                        label: task_label,
                    } => {
                        if let Some(context) = self
                            .async_generator_runtime
                            .continuations
                            .remove(&result_promise.0)
                        {
                            self.resume_async_generator_task(
                                context,
                                Err(reason.clone()),
                                task_label.clone(),
                                module,
                            )?;
                            self.release_await_carrier(*result_promise);
                            return Ok(());
                        }
                        if let Some(resumption_context) =
                            self.async_resumption_contexts.remove(&result_promise.0)
                        {
                            let held = vec![
                                Value::Promise(result_promise.0),
                                self.js_value_to_value(reason),
                            ];
                            if let Err(err) = self.with_event_job_gc_request(held, |this| {
                                this.resume_async_function_task(
                                    resumption_context,
                                    Err(reason.clone()),
                                    task_label.clone(),
                                    module,
                                )
                            }) {
                                let reason = Self::promise_rejection_from_error(&err);
                                let _ = self.reject_promise(
                                    *result_promise,
                                    reason,
                                    task_label.clone(),
                                );
                                return Err(err);
                            }
                            self.release_await_carrier(*result_promise);
                        } else if let Some(resumption_context) = self
                            .top_level_await_resumption_contexts
                            .remove(&result_promise.0)
                        {
                            self.resume_module_evaluation_task(
                                resumption_context,
                                Err(reason.clone()),
                                task_label.clone(),
                                module,
                            )?;
                            self.release_await_carrier(*result_promise);
                        } else {
                            self.reject_promise(
                                *result_promise,
                                reason.clone(),
                                task_label.clone(),
                            )?;
                        }
                    }
                    crate::promise_model::Microtask::AdoptNative {
                        promise,
                        source,
                        settle,
                        label: task_label,
                    } => {
                        // The PromiseResolveThenableJob's `then(resolve,
                        // reject)` on a native promise (bd-9vouw.323): a
                        // pending source gets the forwarding reaction, which
                        // settles `promise` when it settles; a settled one
                        // queues the reaction job, which settles it next.
                        let pending = matches!(
                            self.promise_store.get(*source).map(|record| &record.state),
                            Ok(crate::promise_model::PromiseState::Pending)
                        );
                        if *settle || pending {
                            self.resolve_promise_to_native(*promise, *source, task_label.clone())?;
                        } else {
                            self.enqueue_adopt_native(*promise, *source, true, task_label.clone())?;
                        }
                    }
                    crate::promise_model::Microtask::ResolveThenable {
                        promise,
                        then_handler,
                        thenable,
                        label: task_label,
                    } => {
                        // PromiseResolveThenableJob (ES2020 25.6.1.3.1): call
                        // `thenable.then(resolve, reject)` with resolve/reject
                        // capabilities bound to `promise`. The user `then` runs
                        // synchronously within this job; any microtasks it
                        // schedules (and the settle it performs) are enqueued in
                        // program order, preserving nested-microtask ordering.
                        let thenable_value = self.js_value_to_value(thenable);
                        let job_epoch = self.promise_resolver_epoch(*promise);
                        let resolve_fn = self
                            .make_promise_capability(BuiltinFunctionKind::PromiseResolve, *promise);
                        let reject_fn = self
                            .make_promise_capability(BuiltinFunctionKind::PromiseReject, *promise);
                        let then_callee = self.promise_reaction_callee(*then_handler)?;
                        let invocation = self.invoke_inline_method_call_with_argument_label(
                            module,
                            then_callee,
                            thenable_value,
                            vec![resolve_fn, reject_fn],
                            Some(task_label.clone()),
                        );
                        if let Err(err) = invocation {
                            // ES 25.6.1.3.1 step 3: if calling `then` throws,
                            // reject the promise with the thrown value — unless
                            // the thenable already settled it via its resolve
                            // capability, in which case the throw is inert (the
                            // capability's once-guard has already fired). As in
                            // the PromiseReaction arm, a budget, containment or
                            // exit error ends the run instead.
                            let (reason, reason_label) =
                                self.thrown_completion_value(err, task_label)?;
                            if self.promise_resolvers_live(*promise, job_epoch) {
                                let reason = self.promise_value(&reason)?;
                                self.reject_promise(*promise, reason, reason_label)?;
                            }
                        }
                    }
                }
                Ok(())
            })();
            self.finish_promise_task_transfer(transferred_bytes);
            task_result?;
        }
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        self.event_loop.microtasks.compact();
        self.apply_promise_runtime_memory_delta(previous_promise_bytes)?;
        if drained == 0 {
            // No next-tick callback or reaction ran, so only the compaction
            // above changed state and its delta is exact. The event loop
            // checkpoints after every macrotask; a whole-state reconcile
            // here walked the heap once per timer (bd-j9r60).
            #[cfg(test)]
            debug_assert_eq!(
                self.memory_walk_drift(),
                entry_drift,
                "an empty microtask checkpoint drifted from the full walk (bd-j9r60)"
            );
            return Ok(());
        }
        // A reaction can mutate both Promise-owned queues and arbitrary
        // interpreter state (registers, heap, scopes, async continuations).
        // Reconcile the checkpoint from every resident owner instead of
        // combining the final Promise estimate with a stale pre-drain
        // non-Promise subtotal.
        let requested_bytes = self.recompute_base_estimated_memory_bytes();
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.estimated_memory_bytes = requested_bytes;
        Ok(())
    }

    pub(super) fn execute_pending_deferred_callback(
        &mut self,
        macrotask: &crate::promise_model::Macrotask,
        module: Option<&Ir3Module>,
    ) -> Option<Result<(), InterpreterError>> {
        let callback_args = self
            .pending_io_callbacks
            .remove(&macrotask.registration_seq)?;
        let retained_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(Self::estimate_value_vec_bytes(&callback_args));
        let closure_id = macrotask.handler.0;
        if self.closures.get(closure_id as usize).is_none() {
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(retained_bytes);
            return Some(Err(InterpreterError::TypeError {
                expected: "valid closure".to_string(),
                got: format!("closure#{closure_id} not found"),
            }));
        }
        self.deferred_callback_in_flight_bytes = self
            .deferred_callback_in_flight_bytes
            .saturating_add(retained_bytes);
        let result = match module {
            // The invocation pins its callee and full argument vector. No
            // other values are held by this dispatch frame after transfer.
            Some(module) => self.with_event_job_gc_request(Vec::new(), |core| {
                core.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    Value::Closure(closure_id),
                    Value::Undefined,
                    callback_args,
                    Some(macrotask.label.clone()),
                )
                .map(|_| ())
            }),
            None => Ok(()),
        };
        self.deferred_callback_in_flight_bytes = self
            .deferred_callback_in_flight_bytes
            .saturating_sub(retained_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(retained_bytes);
        Some(result)
    }

    /// Execute a macrotask callback (e.g., timer callbacks).
    ///
    /// This handles timer callbacks by invoking the associated closure.
    /// For setInterval timers, it also re-schedules the next execution.
    pub(super) fn execute_macrotask_callback(
        &mut self,
        macrotask: &crate::promise_model::Macrotask,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        match macrotask.source {
            crate::promise_model::MacrotaskSource::Timer
            | crate::promise_model::MacrotaskSource::Immediate => {
                if let Some(task) = self.pending_http_tasks.remove(&macrotask.registration_seq) {
                    return self.execute_pending_http_task(task, module);
                }
                if let Some(result) = self.execute_pending_deferred_callback(macrotask, module) {
                    return result;
                }
                // bd-suwvw: a builtin-scheduled timer/immediate carries its
                // action in `pending_timer_tasks` (keyed by registration
                // seq) — cancellation, extra callback args, interval
                // re-scheduling, and timers/promises fulfillment all live
                // there. Dispatched BEFORE the raw-closure path so the
                // sentinel handler of a promise timer is never invoked.
                if let Some(task) = self.pending_timer_tasks.remove(&macrotask.registration_seq) {
                    return self.execute_pending_timer_task(task, module);
                }

                // Legacy path: a closure scheduled directly on the event loop
                // (`event_loop.set_timeout(...)` in tests) with no side-table
                // entry. Preserve the original behavior.
                let closure_id = macrotask.handler.0;
                // Validate the handler refers to a live closure before running
                // (preserves the clear diagnostic; the invocation path would
                // otherwise surface a less specific error).
                if self.closures.get(closure_id as usize).is_none() {
                    return Err(InterpreterError::TypeError {
                        expected: "valid closure".to_string(),
                        got: format!("closure#{closure_id} not found"),
                    });
                }

                // Execute the timer callback body (no arguments, undefined this).
                let result = self.execute_timer_callback(
                    Value::Closure(closure_id),
                    module,
                    Vec::new(),
                    macrotask.label.clone(),
                );

                if let Err(ref err) = result {
                    eprintln!("Timer callback execution error: {err:?}");
                }

                result.map(|_| ())
            }
            crate::promise_model::MacrotaskSource::IoCompletion => {
                if let Some(result) = self.execute_pending_fs_promise_read(macrotask, module) {
                    return result;
                }
                if let Some(result) =
                    self.execute_pending_dynamic_import(macrotask.registration_seq)
                {
                    return result;
                }
                if let Some(task) = self
                    .pending_child_process_tasks
                    .remove(&macrotask.registration_seq)
                {
                    let retained_bytes = Self::pending_child_process_task_bytes(&task);
                    self.child_process_task_in_flight_bytes = self
                        .child_process_task_in_flight_bytes
                        .saturating_add(retained_bytes);
                    let gc_checkpoint = self.gc_pin_child_process_task(&task);
                    let result = self.execute_pending_child_process_task(task, module);
                    self.gc_unpin_network_values(gc_checkpoint);
                    self.child_process_task_in_flight_bytes = self
                        .child_process_task_in_flight_bytes
                        .saturating_sub(retained_bytes);
                    self.estimated_memory_bytes =
                        self.estimated_memory_bytes.saturating_sub(retained_bytes);
                    return result;
                }
                if let Some(task) = self.pending_http_tasks.remove(&macrotask.registration_seq) {
                    return self.execute_pending_http_task(task, module);
                }
                // bd-7qwej: interpreter-local `net` lifecycle/data actions use
                // the deterministic I/O lane with a sentinel handler. Dispatch
                // their engine-owned side-table entry before any raw closure
                // path can observe that sentinel.
                if let Some(task) = self
                    .pending_loopback_tasks
                    .remove(&macrotask.registration_seq)
                {
                    return self.execute_pending_loopback_task(task, module);
                }
                // bd-fw7zd: finite `Readable.from` pumps share the deterministic
                // I/O-completion lane but carry their state in an engine-owned
                // table, so the sentinel handler is never invoked as a closure.
                if let Some(object_id) =
                    self.remove_pending_readable_pump(macrotask.registration_seq)
                {
                    return self.drive_readable_from_pump(object_id, module);
                }
                // bd-3894s slice (2d): a deferred readable-stream emission
                // (`'data'`/`'end'` on an `IncomingMessage`) carries no real handler
                // closure — it is identified by its registration sequence and
                // dispatched here BEFORE the closure-callback path, so the sentinel
                // `ClosureHandle(0)` it stored is never invoked as a closure.
                if let Some(emission) =
                    self.remove_pending_stream_emission(macrotask.registration_seq)
                {
                    return self.drive_stream_emission(emission, module, macrotask.label.clone());
                }
                // bd-201vt / bd-3894s slice (2c): an async host-I/O callback — a fs
                // callback (`fs.readFile`/`fs.writeFile`, err-first `cb(err[, data])`)
                // or an http response callback (`http.get`/`http.request`'s
                // `cb(res)`). The host effect already ran and was recorded at
                // dispatch; here we invoke the JS callback with the arguments stashed
                // by `schedule_io_callback`, keyed by this macrotask's registration
                // sequence. Draining the entry keeps the side-table bounded to
                // in-flight callbacks.
                self.execute_pending_deferred_callback(macrotask, module)
                    .unwrap_or_else(|| {
                        let closure_id = macrotask.handler.0;
                        if self.closures.get(closure_id as usize).is_none() {
                            return Err(InterpreterError::TypeError {
                                expected: "valid closure".to_string(),
                                got: format!("closure#{closure_id} not found"),
                            });
                        }
                        match module {
                            Some(module) => self
                                .invoke_inline_method_call_with_argument_label(
                                    Some(module),
                                    Value::Closure(closure_id),
                                    Value::Undefined,
                                    Vec::new(),
                                    Some(macrotask.label.clone()),
                                )
                                .map(|_| ()),
                            None => Ok(()),
                        }
                    })
            }
            _ => {
                // Remaining sources (e.g. MessageChannel) are not yet scheduled.
                Ok(())
            }
        }
    }

    /// Execute a timer closure callback.
    ///
    /// This creates a minimal execution context to run the timer callback function.
    /// `args` carries the extra trailing `setTimeout(cb, ms, ...args)` arguments
    /// (empty for the legacy direct-scheduled path) (bd-suwvw).
    /// Run `call`, letting the collector run inside the inline call it makes
    /// (bd-9vouw.77). `held` are the values this frame and its callers keep in
    /// Rust locals across that call; the callee, receiver and arguments are
    /// pinned by the call itself. The request never outlives `call`.
    pub(super) fn with_gc_nested_request<T>(
        &mut self,
        held: Vec<Value>,
        call: impl FnOnce(&mut Self) -> T,
    ) -> T {
        self.gc_nested_request = Some(held);
        let result = call(self);
        self.gc_nested_request = None;
        result
    }

    /// `with_gc_nested_request` for an event-loop job dispatched between jobs;
    /// anywhere else `call` runs without one (bd-9vouw.77).
    pub(super) fn with_event_job_gc_request<T>(
        &mut self,
        held: Vec<Value>,
        call: impl FnOnce(&mut Self) -> T,
    ) -> T {
        if self.gc_in_event_loop_phase() {
            self.with_gc_nested_request(held, call)
        } else {
            call(self)
        }
    }

    pub(super) fn execute_timer_callback(
        &mut self,
        callback: Value,
        module: Option<&Ir3Module>,
        args: Vec<Value>,
        label: Label,
    ) -> Result<Value, InterpreterError> {
        // Bind every fired callback to the replay witness without retaining
        // an event per interval tick (bd-9vouw.76). Host effects performed by
        // the callback still emit their complete individual records.
        self.record_timer_callback_witness(&callback)?;

        // Run the callback body for real (bd-zqb1x): `setTimeout(() => { ... })`
        // must execute its closure, not merely emit a witness. Timer callbacks
        // receive the stashed extra arguments and an undefined `this`. Reuse
        // the audited synchronous closure-invocation path (the same one
        // Array.prototype callbacks use), which snapshots/restores execution
        // state around the call and runs the closure's IR3 body to completion
        // against its captured environment.
        match module {
            // Between event-loop jobs the timer queue owns nothing else the
            // callback could need; its callee and arguments are pinned by the
            // call (bd-9vouw.77). Elsewhere a caller may hold unpinned values.
            Some(module) if self.gc_in_event_loop_phase() => self
                .with_gc_nested_request(Vec::new(), |this| {
                    this.invoke_inline_method_call_with_argument_label(
                        Some(module),
                        callback,
                        Value::Undefined,
                        args,
                        Some(label),
                    )
                })
                .map(|(value, _)| value),
            Some(module) => self
                .invoke_inline_method_call_with_argument_label(
                    Some(module),
                    callback,
                    Value::Undefined,
                    args,
                    Some(label),
                )
                .map(|(value, _)| value),
            None => {
                // No module context is available only on the test-only
                // `run_event_loop_until_idle()` path (the production eval flow
                // always threads `Some(module)`). Without the module the
                // closure body cannot be run; preserve the prior witness-only
                // behaviour rather than fail the drain.
                Ok(Value::Undefined)
            }
        }
    }

    /// bd-suwvw: run one builtin-scheduled timer/immediate macrotask action.
    /// Skips cancelled timers, forwards stashed extra callback arguments,
    /// re-schedules still-active intervals after a successful fire, and
    /// fulfills timers/promises timers.
    pub(super) fn execute_pending_timer_task(
        &mut self,
        task: PendingTimerTask,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let retained_bytes = Self::estimate_pending_timer_task_bytes(&task);
        if !self.active_timers.contains_key(&task.timer_id) {
            // Cancelled (clearTimeout/clearInterval/clearImmediate) between
            // scheduling and firing: the macrotask is inert.
            self.unref_timer_ids.remove(&task.timer_id);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(retained_bytes);
            return Ok(());
        }
        match task.kind {
            PendingTimerTaskKind::Callback {
                callback,
                args,
                repeating,
                delay_ms,
                label,
            } => {
                let (result, reschedule_args) = if repeating {
                    let clone_bytes = Self::estimate_value_vec_bytes(&args);
                    if let Err(error) = self.apply_memory_component_delta(0, clone_bytes) {
                        self.active_timers.remove(&task.timer_id);
                        self.unref_timer_ids.remove(&task.timer_id);
                        self.estimated_memory_bytes =
                            self.estimated_memory_bytes.saturating_sub(retained_bytes);
                        return Err(error);
                    }
                    let callback_args = args.clone();
                    let result = self
                        .execute_timer_callback(
                            callback.clone(),
                            module,
                            callback_args,
                            label.clone(),
                        )
                        .map(|_| ());
                    self.estimated_memory_bytes =
                        self.estimated_memory_bytes.saturating_sub(clone_bytes);
                    (result, Some(args))
                } else {
                    (
                        self.execute_timer_callback(callback.clone(), module, args, label.clone())
                            .map(|_| ()),
                        None,
                    )
                };
                if let Err(ref err) = result {
                    eprintln!("Timer callback execution error: {err:?}");
                }
                if repeating && result.is_ok() {
                    // Re-schedule the next tick unless the callback (or
                    // anything it ran) cleared the interval.
                    if self.active_timers.contains_key(&task.timer_id) {
                        let previous_promise_bytes = self.promise_runtime_memory_bytes();
                        let handler_id = match &callback {
                            Value::Closure(id) | Value::Function(id) => *id,
                            _ => u32::MAX,
                        };
                        let seq = self.event_loop.set_timeout(
                            crate::closure_model::ClosureHandle(handler_id),
                            delay_ms,
                            label.clone(),
                        );
                        if let Err(error) =
                            self.apply_promise_runtime_memory_delta(previous_promise_bytes)
                        {
                            self.event_loop.rollback_last_scheduled(seq);
                            self.active_timers.remove(&task.timer_id);
                            self.unref_timer_ids.remove(&task.timer_id);
                            self.estimated_memory_bytes =
                                self.estimated_memory_bytes.saturating_sub(retained_bytes);
                            return Err(error);
                        }
                        self.pending_timer_tasks.insert(
                            seq,
                            PendingTimerTask {
                                timer_id: task.timer_id,
                                kind: PendingTimerTaskKind::Callback {
                                    callback,
                                    args: reschedule_args
                                        .expect("repeating timer retained its owned arguments"),
                                    repeating: true,
                                    delay_ms,
                                    label,
                                },
                            },
                        );
                    } else {
                        self.unref_timer_ids.remove(&task.timer_id);
                        self.estimated_memory_bytes =
                            self.estimated_memory_bytes.saturating_sub(retained_bytes);
                    }
                } else {
                    // One-shot timers/immediates (and errored intervals) are
                    // finished: drop the active entry so `hasRef()` reports
                    // false and cancellation state stays bounded.
                    self.active_timers.remove(&task.timer_id);
                    self.unref_timer_ids.remove(&task.timer_id);
                    self.estimated_memory_bytes =
                        self.estimated_memory_bytes.saturating_sub(retained_bytes);
                }
                result
            }
            PendingTimerTaskKind::PromiseResolve { promise, value } => {
                self.active_timers.remove(&task.timer_id);
                self.unref_timer_ids.remove(&task.timer_id);
                let result =
                    self.fulfill_promise(promise, value, crate::ifc_artifacts::Label::Public);
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(retained_bytes);
                result
            }
        }
    }

    /// bd-suwvw: Node's timer-delay coercion + clamp. `ToNumber`-style
    /// coercion of the delay argument; NaN, non-finite, negative, sub-1ms
    /// and over-`TIMEOUT_MAX_MS` delays all clamp to 1ms (Node prints a
    /// warning for the negative/NaN cases — see the corpus notes; the engine
    /// stays silent on stderr and matches the firing behavior).
    pub(super) fn timer_delay_ms_from_value(value: &Value) -> u64 {
        let ms = match value {
            Value::Int(n) => *n as f64,
            Value::Float(f) => f.inner(),
            Value::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            Value::Null => 0.0,
            Value::Str(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    0.0
                } else {
                    trimmed.parse::<f64>().unwrap_or(f64::NAN)
                }
            }
            _ => f64::NAN,
        };
        const TIMEOUT_MAX_MS: f64 = 2_147_483_647.0;
        if !ms.is_finite() || ms < 1.0 || ms > TIMEOUT_MAX_MS {
            1
        } else {
            ms as u64
        }
    }

    pub(super) fn timer_effect_error(error: EffectError) -> InterpreterError {
        match error {
            EffectError::CapabilityDenied { .. } => InterpreterError::CapabilityDenied {
                capability: RuntimeCapability::Timer.to_string(),
            },
            EffectError::HandlerError {
                message: _,
                code: Some(code),
                ..
            } if code == "TIMER_CELL_CANCELLED" => InterpreterError::Cancelled,
            EffectError::HandlerError {
                message: _,
                code: Some(code),
                ..
            } if code == "TIMER_CELL_CAPABILITY_DENIED" => InterpreterError::CapabilityDenied {
                capability: RuntimeCapability::Timer.to_string(),
            },
            other => InterpreterError::InternalError {
                details: format!("interpreter timer effect dispatch failed: {other}"),
            },
        }
    }

    pub(super) fn begin_interpreter_timer_effect(
        &self,
        request: InterpreterTimerRequest,
    ) -> Result<TimerEffectPermit, InterpreterError> {
        let capability_granted = self
            .config
            .granted_capabilities
            .contains(&RuntimeCapability::Timer);
        let mut stack = create_interpreter_timer_handler_stack(
            self.timer_effect_authority.clone(),
            capability_granted,
        );
        let effect = create_interpreter_timer_effect(request);
        stack
            .handle_effect(effect.as_ref())
            .map_err(Self::timer_effect_error)?
            .downcast::<TimerEffectPermit>()
            .map_err(Self::timer_effect_error)
    }

    pub(super) fn complete_interpreter_timer_effect(
        permit: TimerEffectPermit,
        outcome: &InterpreterTimerOutcome,
    ) -> Result<(), InterpreterError> {
        permit
            .complete(outcome)
            .map_err(|error| InterpreterError::InternalError {
                details: format!("interpreter timer evidence commit failed: {error}"),
            })
    }

    /// bd-suwvw: allocate a Timeout/Immediate handle object carrying the timer
    /// id plus bound `hasRef`/`ref`/`unref` methods. `typeof handle` is
    /// "object" and `clearTimeout(handle)` resolves the id via `__timerId`,
    /// matching bun's observable handle shape for the compat corpus.
    pub(super) fn alloc_timer_handle_object(
        &mut self,
        timer_id: u32,
        marker: &str,
    ) -> Result<Value, InterpreterError> {
        self.ensure_heap_allocation_allowed()?;
        let requested_heap_objects = self.heap_object_count_u32().saturating_add(1);
        if requested_heap_objects > self.config.max_heap_objects {
            return Err(
                self.memory_budget_error(self.estimated_memory_bytes, requested_heap_objects)
            );
        }
        let object_id =
            ObjectId(
                u32::try_from(self.heap.len()).map_err(|_| InterpreterError::TypeError {
                    expected: "heap capacity".into(),
                    got: format!("exceeded u32::MAX ({})", self.heap.len()),
                })?,
            );
        let mut object = HeapObject::new();
        object.brand = Some(Box::new(JsString::from(marker)));
        object
            .properties
            .insert("__timerId".to_string(), Value::Int(timer_id as i64));
        for (name, kind) in [
            ("hasRef", BuiltinFunctionKind::TimerHasRef),
            ("ref", BuiltinFunctionKind::TimerRef),
            ("unref", BuiltinFunctionKind::TimerUnref),
        ] {
            object.properties.insert(
                name.to_string(),
                Value::BuiltinFunction(BuiltinFunction::timer_handle_method(kind, object_id)),
            );
        }
        let object_size = Self::estimate_heap_object_bytes(&object);
        let requested_bytes = self.estimated_memory_bytes.saturating_add(object_size);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, requested_heap_objects));
        }
        self.mutate_heap(|heap| heap.push(object));
        self.estimated_memory_bytes = requested_bytes;
        if let Some(profiler) = &mut self.profiling_data {
            profiler.record_object_allocation(object_size);
        }
        Ok(Value::Object(object_id))
    }

    /// bd-suwvw: shared setTimeout/setInterval/setImmediate scheduling core.
    /// Value-based so both the lowering hostcall arms and first-class
    /// `BuiltinFunction` dispatch reuse it.
    pub(super) fn timer_schedule_from_values(
        &mut self,
        callback: Value,
        delay: Option<Value>,
        extra_args: Vec<Value>,
        repeating: bool,
        immediate: bool,
        registration_label: Label,
    ) -> Result<Value, InterpreterError> {
        if !callback.is_callable() {
            // Preserved lenient legacy contract: a non-callable callback
            // yields the invalid timer id instead of throwing.
            return Ok(Value::Int(0));
        }
        let delay_ms = if immediate {
            0
        } else {
            match &delay {
                Some(value) => Self::timer_delay_ms_from_value(value),
                None => 1,
            }
        };

        let timer_id = self.next_timer_id;
        // Async, generator and builtin callables (`setTimeout(resolve, ms)`,
        // `setTimeout(async () => ...)`) are ordinary callbacks too; the
        // stored `callback` is what runs. Non-closure callables record the
        // same sentinel handle `schedule_pending_timer_task` uses
        // (bd-9vouw.30).
        let callback_id = match &callback {
            Value::Closure(id) | Value::Function(id) => *id,
            _ => u32::MAX,
        };
        let effect_permit = if immediate {
            None
        } else {
            Some(
                self.begin_interpreter_timer_effect(InterpreterTimerRequest {
                    operation: if repeating {
                        TimerOperation::SetInterval
                    } else {
                        TimerOperation::SetTimeout
                    },
                    duration_ms: Some(delay_ms),
                    timer_id: None,
                    callback_id: Some(callback_id),
                    ifc_label: registration_label.clone(),
                })?,
            )
        };

        let pending_task = PendingTimerTask {
            timer_id,
            kind: PendingTimerTaskKind::Callback {
                callback,
                args: extra_args,
                repeating,
                delay_ms,
                label: registration_label,
            },
        };
        self.active_timers.insert(
            timer_id,
            ActiveTimer {
                handler: Some(callback_id),
                delay_ms,
                repeating,
            },
        );

        let scheduled_seq =
            match self.schedule_pending_timer_task(pending_task, immediate, delay_ms) {
                Ok(sequence) => sequence,
                Err(error) => {
                    self.active_timers.remove(&timer_id);
                    return Err(error);
                }
            };

        let (witness_tag, marker) = if immediate {
            ("builtin:setImmediate", TIMER_HANDLE_IMMEDIATE_TYPE)
        } else if repeating {
            ("builtin:setInterval", TIMER_HANDLE_TIMEOUT_TYPE)
        } else {
            ("builtin:setTimeout", TIMER_HANDLE_TIMEOUT_TYPE)
        };
        let handle = match self.alloc_timer_handle_object(timer_id, marker) {
            Ok(handle) => handle,
            Err(error) => {
                self.active_timers.remove(&timer_id);
                self.cancel_pending_timer_registration(scheduled_seq);
                return Err(error);
            }
        };
        if let Some(permit) = effect_permit
            && let Err(error) = Self::complete_interpreter_timer_effect(
                permit,
                &InterpreterTimerOutcome::Scheduled {
                    timer_id: u64::from(timer_id),
                    registration_sequence: scheduled_seq,
                },
            )
        {
            self.active_timers.remove(&timer_id);
            self.cancel_pending_timer_registration(scheduled_seq);
            self.rollback_timer_handle_object(&handle);
            return Err(error);
        }
        self.next_timer_id = self.next_timer_id.wrapping_add(1);
        self.emit_witness(
            WitnessEventKind::HostcallDispatched,
            Some(&format!("{witness_tag}:{timer_id}")),
        );

        Ok(handle)
    }

    pub(super) fn rollback_timer_handle_object(&mut self, handle: &Value) {
        let Value::Object(object_id) = handle else {
            return;
        };
        let is_last = object_id.0 as usize + 1 == self.heap.len();
        if !is_last {
            return;
        }
        if let Some(object) = self.mutate_heap(Heap::pop) {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(Self::estimate_heap_object_bytes(&object));
        }
    }

    /// bd-suwvw: shared clearTimeout/clearInterval/clearImmediate core.
    /// Resolves the timer id from a handle object (`__timerId`) or a legacy
    /// integer id; every other value is a no-op (Node semantics).
    pub(super) fn timer_clear_from_value(
        &mut self,
        handle: &Value,
        witness_tag: &str,
        operation: Option<TimerOperation>,
        ifc_label: Label,
    ) -> Result<Value, InterpreterError> {
        let timer_id = match handle {
            Value::Int(id) => Some(*id as u32),
            Value::Object(object_id) => match self
                .heap
                .get(object_id.0 as usize)
                .and_then(|object| object.properties.get("__timerId"))
            {
                Some(Value::Int(id)) => Some(*id as u32),
                _ => None,
            },
            _ => None,
        };
        let Some(timer_id) = timer_id else {
            return Ok(Value::Undefined);
        };

        let effect_permit = match operation {
            Some(operation) => Some(self.begin_interpreter_timer_effect(
                InterpreterTimerRequest {
                    operation,
                    duration_ms: None,
                    timer_id: Some(u64::from(timer_id)),
                    callback_id: None,
                    ifc_label,
                },
            )?),
            None => None,
        };

        let was_active = self.active_timers.remove(&timer_id).is_some();
        self.unref_timer_ids.remove(&timer_id);
        let pending_sequences: Vec<u64> = self
            .pending_timer_tasks
            .iter()
            .filter_map(|(sequence, task)| (task.timer_id == timer_id).then_some(*sequence))
            .collect();
        for sequence in pending_sequences {
            self.cancel_pending_timer_registration(sequence);
        }
        if let Some(permit) = effect_permit {
            Self::complete_interpreter_timer_effect(
                permit,
                &InterpreterTimerOutcome::Cleared {
                    timer_id: u64::from(timer_id),
                    was_active,
                },
            )?;
        }
        if was_active {
            self.emit_witness(
                WitnessEventKind::HostcallDispatched,
                Some(&format!("{witness_tag}:{timer_id}")),
            );
        }
        Ok(Value::Undefined)
    }

    /// bd-suwvw: queueMicrotask(cb) core — enqueue a plain microtask that
    /// invokes `cb` with no arguments at the next microtask checkpoint.
    /// Implemented as a `PromiseReaction` against a fresh (unobservable)
    /// promise so it reuses the audited reaction-drain path.
    pub(super) fn queue_microtask_from_value(
        &mut self,
        callback: &Value,
    ) -> Result<Value, InterpreterError> {
        // Any callable, as Promise reactions take: a builtin (a promise's
        // resolve function, `console.log`, a bound function) or an async or
        // generator function object, not only a closure. Those were refused
        // with "expected function, got function" (bd-9vouw.478).
        let handler = if callback.is_callable() {
            self.promise_reaction_handler_from_value(callback.clone(), "queueMicrotask callback")?
        } else {
            None
        };
        let Some(handler) = handler else {
            return Err(InterpreterError::TypeError {
                expected: "function".to_string(),
                got: callback.type_name().to_string(),
            });
        };
        // Hash only the callable identity (closure/function handle or typed
        // builtin binding), never its captured heap graph. Prepare the next
        // commitment before changing queue ownership and publish it only when
        // the enqueue succeeds, so rejected attempts do not claim delivery.
        let next_witness = self.callback_witness_step(
            callback,
            self.microtask_enqueue_witness,
            b"franken-engine.microtask-enqueue-chain.v1\0",
        )?;
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let task = crate::promise_model::Microtask::QueuedCallback {
            handler,
            label: crate::ifc_artifacts::Label::Public,
        };
        let next_queue_bytes = self
            .event_loop
            .microtasks
            .projected_enqueue_memory_bytes(&task);
        let next_promise_bytes = self
            .promise_store
            .estimated_memory_bytes()
            .saturating_add(
                self.event_loop
                    .estimated_memory_bytes()
                    .saturating_sub(self.event_loop.microtasks.estimated_memory_bytes())
                    .saturating_add(next_queue_bytes),
            )
            .saturating_add(self.promise_combinators_memory_bytes())
            .saturating_add(self.promise_combinator_watchers_memory_bytes())
            .saturating_add(self.promise_in_flight_task_bytes);
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
        self.event_loop.microtasks.enqueue(task);
        self.settle_projected_promise_bytes(next_promise_bytes)?;
        self.microtask_enqueue_witness = Some(next_witness);
        Ok(Value::Undefined)
    }

    /// bd-suwvw: timers/promises setTimeout/setImmediate core — a pending
    /// promise fulfilled with `value` when the scheduled task fires. The
    /// macrotask handler is an inert sentinel; `execute_pending_timer_task`
    /// intercepts by registration seq before any closure dispatch.
    pub(super) fn timers_promises_schedule_from_values(
        &mut self,
        delay: Option<Value>,
        value: &Value,
        immediate: bool,
    ) -> Result<Value, InterpreterError> {
        let delay_ms = if immediate {
            0
        } else {
            match &delay {
                Some(value) => Self::timer_delay_ms_from_value(value),
                None => 1,
            }
        };
        let timer_id = self.next_timer_id;
        let promise = self.create_promise()?;
        let task = PendingTimerTask {
            timer_id,
            kind: PendingTimerTaskKind::PromiseResolve {
                promise,
                value: Self::value_to_js_value(value),
            },
        };
        self.active_timers.insert(
            timer_id,
            ActiveTimer {
                handler: None,
                delay_ms,
                repeating: false,
            },
        );
        if let Err(error) = self.schedule_pending_timer_task(task, immediate, delay_ms) {
            self.active_timers.remove(&timer_id);
            self.rollback_fresh_promise(promise);
            return Err(error);
        }
        self.next_timer_id = self.next_timer_id.wrapping_add(1);
        self.emit_witness(
            WitnessEventKind::HostcallDispatched,
            Some(&format!("builtin:timersPromises:{timer_id}")),
        );
        Ok(Value::Promise(promise.0))
    }

    /// bd-suwvw: `next()` / `return()` of a `timers/promises` setInterval
    /// iterator. `next` advances the deterministic virtual clock by the
    /// interval delay and resolves `{ value, done: false }`; `return` ends the
    /// iteration, after which `next` resolves `{ value: undefined, done: true }`.
    /// The promise carries the receiver's and arguments' labels, since it
    /// hands out the value the interval was created with.
    pub(super) fn timers_promises_interval_step(
        &mut self,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
        args: RegRange,
        finish: bool,
    ) -> Result<Value, InterpreterError> {
        let interval = match receiver {
            Some(Value::Object(object_id))
                if self.heap.get(object_id.0 as usize).is_some_and(|object| {
                    object.brand() == Some(TIMERS_PROMISES_INTERVAL_TYPE)
                }) =>
            {
                object_id
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "timers/promises setInterval iterator receiver".to_string(),
                    got: other
                        .as_ref()
                        .map_or("undefined", Value::type_name)
                        .to_string(),
                });
            }
        };
        let (delay_ms, value, done) = {
            let properties = &self.heap[interval.0 as usize].properties;
            let delay_ms = match properties.get("__delayMs") {
                Some(Value::Int(ms)) => (*ms).max(1) as u64,
                _ => 1,
            };
            let value = properties
                .get("__value")
                .cloned()
                .unwrap_or(Value::Undefined);
            let done = matches!(properties.get("__done"), Some(Value::Bool(true)));
            (delay_ms, value, done)
        };
        let mut label = self.join_arg_range_label(args)?;
        if let Some(register) = receiver_register {
            let receiver_label = self.get_register_label(register)?;
            if *receiver_label > label {
                label = receiver_label.clone();
            }
        }
        let next_value = if finish || done {
            if !done {
                self.set_object_property(interval, "__done".to_string(), Value::Bool(true))?;
            }
            None
        } else {
            let now = self.event_loop.clock.now_ms();
            self.event_loop
                .clock
                .advance_to(now.saturating_add(delay_ms));
            Some(value)
        };
        let result = self.alloc_iterator_result_object(next_value)?;
        let promise = self.create_fulfilled_promise(Self::value_to_js_value(&result), label)?;
        Ok(Value::Promise(promise.0))
    }

    /// bd-suwvw: true when every pending macrotask is a timer whose handle was
    /// unref'd (or that was already cancelled) — the idle drain exits instead
    /// of firing them, matching Node's "unref'd timers don't keep the event
    /// loop alive" semantics. Non-timer macrotasks (I/O completions, stream
    /// emissions, directly-scheduled closures) always keep the loop alive.
    pub(super) fn only_unref_or_cancelled_timers_pending(&self) -> bool {
        let mut saw_any = false;
        for task in self.event_loop.macrotasks.iter_pending() {
            saw_any = true;
            match self.pending_timer_tasks.get(&task.registration_seq) {
                Some(pending) => {
                    let cancelled = !self.active_timers.contains_key(&pending.timer_id);
                    let unrefd = self.unref_timer_ids.contains(&pending.timer_id);
                    if !cancelled && !unrefd {
                        return false;
                    }
                }
                None => return false,
            }
        }
        saw_any
    }

    pub(super) fn property_key(value: &Value) -> String {
        match value {
            Value::Str(s) => s.to_string(),
            Value::Int(n) => n.to_string(),
            _ => value.to_string(),
        }
    }

    pub(super) fn symbol_description_argument(
        &self,
        value: Option<Value>,
    ) -> Result<Option<JsString>, InterpreterError> {
        match value {
            None | Some(Value::Undefined) => Ok(None),
            Some(Value::Str(text)) => Ok(Some(text)),
            Some(Value::Symbol(_)) => Err(InterpreterError::TypeError {
                expected: "Symbol description coercible to string".to_string(),
                got: "symbol".to_string(),
            }),
            Some(value) => Ok(Some(JsString::from(self.value_to_string(&value)))),
        }
    }

    pub(super) fn symbol_registry_key_argument(
        &self,
        value: Value,
    ) -> Result<JsString, InterpreterError> {
        match value {
            Value::Str(text) => Ok(text),
            Value::Symbol(_) => Err(InterpreterError::TypeError {
                expected: "Symbol.for key coercible to string".to_string(),
                got: "symbol".to_string(),
            }),
            value => Ok(JsString::from(self.value_to_string(&value))),
        }
    }

    pub(super) fn allocate_private_symbol(
        &mut self,
        description: Option<JsString>,
    ) -> Result<SymbolId, InterpreterError> {
        self.allocate_charged_symbol(RuntimeSymbolKind::Private, description, None)
    }

    /// A class evaluation's Private Name `#x`, charged like any symbol.
    pub(super) fn allocate_class_private_name_symbol(
        &mut self,
        description: JsString,
    ) -> Result<SymbolId, InterpreterError> {
        self.allocate_charged_symbol(RuntimeSymbolKind::ClassPrivateName, Some(description), None)
    }

    /// Adds one symbol record within the memory budget and charges it. The
    /// record's bytes are known before it exists, so the budget is checked
    /// and charged first and the state changes only on success. This used to
    /// copy the whole symbol state and estimate it twice per allocation:
    /// O(symbols) for every Symbol(), Symbol.for and class private name, so
    /// a class with N private fields took O(N^2) to define (bd-9vouw.332).
    pub(super) fn allocate_charged_symbol(
        &mut self,
        kind: RuntimeSymbolKind,
        description: Option<JsString>,
        registry_key: Option<JsString>,
    ) -> Result<SymbolId, InterpreterError> {
        let record_bytes =
            Self::estimate_symbol_record_bytes(description.as_ref(), registry_key.as_ref());
        self.apply_memory_component_delta(0, record_bytes)?;
        match self.mutate_symbol_state(|state| state.allocate(kind, description, registry_key)) {
            Ok(symbol) => Ok(symbol),
            Err(error) => {
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(record_bytes);
                Err(error)
            }
        }
    }

    pub(super) fn intern_global_symbol(
        &mut self,
        key: JsString,
    ) -> Result<SymbolId, InterpreterError> {
        if let Some(symbol) = self.symbol_state.global_symbol(&key) {
            return Ok(symbol);
        }
        self.allocate_charged_symbol(RuntimeSymbolKind::Global, Some(key.clone()), Some(key))
    }

    pub(super) fn symbol_description(&self, id: SymbolId) -> Option<JsString> {
        well_known_symbol_description(id)
            .map(JsString::from)
            .or_else(|| self.symbol_state.description(id).cloned())
    }

    /// The `got` of the TypeError for a property access on `value`: for
    /// `null` and `undefined` it carries the access as V8 words it,
    /// `null (reading 'x')` / `undefined (setting 'x')`, which
    /// `native_error_to_thrown_value` turns into Node's message (bd-9vouw.108);
    /// any other value is its type name.
    pub(super) fn nullish_access_subject(
        &self,
        value: &Value,
        key: &RuntimePropertyKey,
        verb: &str,
    ) -> String {
        if !matches!(value, Value::Null | Value::Undefined) {
            return value.type_name().to_string();
        }
        let key = match key {
            RuntimePropertyKey::String(text) => text.to_string(),
            RuntimePropertyKey::Symbol(id) => self.symbol_display_string(*id),
        };
        format!("{} ({verb} '{key}')", value.type_name())
    }

    pub(super) fn symbol_display_string(&self, id: SymbolId) -> String {
        self.symbol_description(id).map_or_else(
            || "Symbol()".to_string(),
            |description| format!("Symbol({description})"),
        )
    }

    pub(super) fn symbol_to_string(&self, id: SymbolId) -> JsString {
        let prefix = JsString::from("Symbol(");
        let suffix = JsString::from(")");
        self.symbol_description(id).map_or_else(
            || prefix.concat(&suffix),
            |description| prefix.concat(&description).concat(&suffix),
        )
    }

    /// Convert a dynamic IR value to the private exact string-key carrier.
    /// This is the executable key path for dynamic and builtin consumers.
    /// ToPropertyKey (ES2020 7.1.19) of a computed member key: an object is
    /// ToPrimitive'd with the string hint (its toString runs), so `o[k]`
    /// with `k = { toString() { return 'key' } }` reads "key"; it read
    /// "[object#13]" (the object's heap id). A primitive is returned as is.
    /// ToPropertyKey of a computed member's key after RequireObjectCoercible
    /// of its base (ES2020 12.3.2.1 EvaluatePropertyAccessWithExpressionKey
    /// steps 2-4): `null[key]` throws its TypeError before an object key's
    /// toString runs.
    pub(super) fn member_key_primitive(
        &mut self,
        module: &Ir3Module,
        base: &Value,
        key: Value,
    ) -> Result<Value, InterpreterError> {
        if key.is_object_like() && matches!(base, Value::Undefined | Value::Null) {
            return Err(InterpreterError::TypeError {
                expected: "object-coercible base of a computed member".to_string(),
                got: base.type_name().to_string(),
            });
        }
        self.property_key_primitive(module, key)
    }

    pub(super) fn property_key_primitive(
        &mut self,
        module: &Ir3Module,
        key: Value,
    ) -> Result<Value, InterpreterError> {
        if !key.is_object_like() {
            return Ok(key);
        }
        // Guest code may run: no collection while native locals hold values.
        self.gc_nested_request = None;
        self.coerce_runtime_primitive(Some(module), key, true)
    }

    pub(super) fn executable_property_key_from_value(&self, value: &Value) -> RuntimePropertyKey {
        if let Value::Symbol(symbol) = value {
            return RuntimePropertyKey::Symbol(*symbol);
        }

        let key = match value {
            Value::Str(key) => key.clone(),
            Value::Int(number) => {
                small_index_key(*number).unwrap_or_else(|| JsString::from(number.to_string()))
            }
            _ => JsString::from(Self::property_key(value)),
        };
        RuntimePropertyKey::String(key)
    }

    pub(super) fn validate_executable_property_key(
        &self,
        key: &RuntimePropertyKey,
    ) -> Result<(), InterpreterError> {
        if let RuntimePropertyKey::Symbol(symbol) = key
            && !self.symbol_state.contains(*symbol)
        {
            return Err(InterpreterError::TypeError {
                expected: "resolved Symbol property key".to_string(),
                got: format!("unresolved Symbol id {}", symbol.0),
            });
        }
        Ok(())
    }

    /// Node's `process.exit(code)` / `process.exitCode` validation: an integer
    /// or a string holding one; `undefined`/`null` mean "not set".
    pub(super) fn process_exit_code_from_value(
        value: &Value,
    ) -> Result<Option<i32>, InterpreterError> {
        let integer = match value {
            Value::Undefined | Value::Null => return Ok(None),
            Value::Int(n) => Some(*n),
            Value::Float(f) if f.inner().fract() == 0.0 && f.inner().is_finite() => {
                Some(f.inner() as i64)
            }
            Value::Str(s) => s.as_str().and_then(|text| text.trim().parse::<i64>().ok()),
            _ => None,
        };
        let Some(integer) = integer else {
            return Err(InterpreterError::TypeError {
                expected: "process exit code as an integer or integer string".to_string(),
                got: value.type_name().to_string(),
            });
        };
        i32::try_from(integer)
            .map(Some)
            .map_err(|_| InterpreterError::RangeError {
                message: format!("process exit code {integer} is out of the 32-bit range"),
            })
    }

    #[allow(dead_code)] // Kept for potential integer-only operations; tested below
    pub(super) fn coerce_to_number(value: &Value) -> Option<i64> {
        match value {
            Value::Int(n) => Some(*n),
            Value::BigInt(_) | Value::Symbol(_) => None,
            Value::Float(f) => {
                let v = f.inner();
                if v.is_nan() || v.is_infinite() {
                    None
                } else if v.fract() == 0.0 && v >= i64::MIN as f64 && v <= i64::MAX as f64 {
                    Some(v as i64)
                } else {
                    None
                }
            }
            Value::Bool(b) => Some(i64::from(*b)),
            Value::Null => Some(0),
            Value::Str(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    Some(0)
                } else {
                    trimmed.parse::<i64>().ok()
                }
            }
            Value::Undefined
            | Value::Object(_)
            | Value::Function(_)
            | Value::Closure(_)
            | Value::Iterator(_)
            | Value::GeneratorFunction(_)
            | Value::Generator(_)
            | Value::Promise(_)
            | Value::BuiltinFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncFunctionObject(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::AsyncGeneratorObject(_)
            | Value::Accessor { .. } => None,
        }
    }

    pub(super) fn array_buffer_byte_length_from_args(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<usize, InterpreterError> {
        let raw_length = if args.count == 0 {
            Value::Undefined
        } else {
            self.read_reg(args.start)?
        };

        if matches!(raw_length, Value::Undefined) {
            return Ok(0);
        }
        let raw_length = self.object_to_number_primitive(module, raw_length)?;

        let Some(length) = Self::to_index_value(&raw_length)? else {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "invalid ArrayBuffer byteLength {}; requested value must be an integer from 0 to 2^53 - 1, per-buffer cap is {} bytes, total cap is {} bytes, committed bytes are {}",
                    self.value_to_string(&raw_length),
                    MAX_ARRAY_BUFFER_BYTE_LENGTH,
                    self.config.max_total_memory_bytes,
                    self.estimated_memory_bytes(),
                ),
            });
        };

        if length > MAX_ARRAY_BUFFER_BYTE_LENGTH {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "ArrayBuffer byteLength {length} exceeds per-buffer cap of {} bytes; total cap is {} bytes, committed bytes are {}",
                    MAX_ARRAY_BUFFER_BYTE_LENGTH,
                    self.config.max_total_memory_bytes,
                    self.estimated_memory_bytes(),
                ),
            });
        }

        usize::try_from(length).map_err(|_| InterpreterError::RangeError {
            message: format!(
                "ArrayBuffer byteLength {length} exceeds host addressable size; per-buffer cap is {} bytes, total cap is {} bytes, committed bytes are {}",
                MAX_ARRAY_BUFFER_BYTE_LENGTH,
                self.config.max_total_memory_bytes,
                self.estimated_memory_bytes(),
            ),
        })
    }

    pub(super) fn typed_array_index_from_value(
        &self,
        kind: TypedArrayKind,
        field: &str,
        value: &Value,
    ) -> Result<usize, InterpreterError> {
        let Some(index) = Self::to_index_value(value)? else {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "invalid {} {field} {}; requested value must be an integer from 0 to 2^53 - 1",
                    kind.type_name(),
                    self.value_to_string(value),
                ),
            });
        };
        usize::try_from(index).map_err(|_| InterpreterError::RangeError {
            message: format!(
                "{} {field} {index} exceeds host addressable size",
                kind.type_name(),
            ),
        })
    }

    pub(super) fn typed_array_optional_index_arg(
        &mut self,
        module: Option<&Ir3Module>,
        kind: TypedArrayKind,
        args: RegRange,
        offset: u32,
        field: &str,
    ) -> Result<Option<usize>, InterpreterError> {
        if offset >= args.count {
            return Ok(None);
        }
        let value = self.read_reg(args.start + offset)?;
        if matches!(value, Value::Undefined) {
            return Ok(None);
        }
        let value = self.object_to_number_primitive(module, value)?;
        self.typed_array_index_from_value(kind, field, &value)
            .map(Some)
    }

    pub(super) fn checked_typed_array_byte_length(
        &self,
        kind: TypedArrayKind,
        length: usize,
    ) -> Result<usize, InterpreterError> {
        length
            .checked_mul(kind.element_size())
            .filter(|byte_length| (*byte_length as u64) <= MAX_ARRAY_BUFFER_BYTE_LENGTH)
            .ok_or_else(|| InterpreterError::RangeError {
                message: format!(
                    "{} length {length} exceeds per-buffer cap of {} bytes",
                    kind.type_name(),
                    MAX_ARRAY_BUFFER_BYTE_LENGTH,
                ),
            })
    }

    pub(super) fn array_buffer_byte_length(
        &self,
        object_id: ObjectId,
    ) -> Result<usize, InterpreterError> {
        self.with_array_buffer_bytes(object_id, |bytes| bytes.len())
    }

    /// ES2024 23.2.5.1.3 InitializeTypedArrayFromArrayBuffer's checks, in
    /// order: byteOffset, its alignment, length, a detached buffer, then
    /// the bounds against the buffer's byte length after those coercions
    /// (which may have resized it). Over a resizable buffer the view also
    /// takes bounds: without a length it tracks the buffer (bd-9vouw.256).
    pub(super) fn typed_array_buffer_view_shape(
        &mut self,
        module: Option<&Ir3Module>,
        kind: TypedArrayKind,
        buffer_id: ObjectId,
        args: RegRange,
    ) -> Result<(usize, usize, usize, Option<ViewBounds>), InterpreterError> {
        let byte_offset = self
            .typed_array_optional_index_arg(module, kind, args, 1, "byteOffset")?
            .unwrap_or(0);
        let element_size = kind.element_size();

        if byte_offset % element_size != 0 {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "{} byteOffset {byte_offset} is misaligned for element size {element_size}",
                    kind.type_name(),
                ),
            });
        }
        let explicit_length =
            self.typed_array_optional_index_arg(module, kind, args, 2, "length")?;
        self.typed_array_view_shape_over(kind, buffer_id, byte_offset, explicit_length)
    }

    /// The shape of a `kind` view at `byte_offset` over `buffer_id`, with an
    /// explicit element count or none (the rest of the buffer, or tracking
    /// it when the buffer is resizable): the coercion-free tail of
    /// InitializeTypedArrayFromArrayBuffer, also used by `subarray`.
    pub(super) fn typed_array_view_shape_over(
        &self,
        kind: TypedArrayKind,
        buffer_id: ObjectId,
        byte_offset: usize,
        explicit_length: Option<usize>,
    ) -> Result<(usize, usize, usize, Option<ViewBounds>), InterpreterError> {
        let element_size = kind.element_size();
        let (resizable, detached) = self.buffer_resizability(buffer_id)?;
        if detached {
            return Err(InterpreterError::TypeError {
                expected: format!("an attached ArrayBuffer for a {}", kind.type_name()),
                got: "a detached ArrayBuffer".to_string(),
            });
        }
        let buffer_len = self.array_buffer_byte_length(buffer_id)?;
        if byte_offset > buffer_len {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "{} byteOffset {byte_offset} exceeds ArrayBuffer byteLength {buffer_len}",
                    kind.type_name(),
                ),
            });
        }

        let remaining = buffer_len - byte_offset;
        let length = match explicit_length {
            Some(length) => length,
            None if resizable => remaining / element_size,
            None => {
                if !remaining.is_multiple_of(element_size) {
                    return Err(InterpreterError::RangeError {
                        message: format!(
                            "{} view byteLength {remaining} is not a multiple of element size {element_size}",
                            kind.type_name(),
                        ),
                    });
                }
                remaining / element_size
            }
        };
        let byte_length = self.checked_typed_array_byte_length(kind, length)?;
        let end =
            byte_offset
                .checked_add(byte_length)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: format!(
                        "{} byteOffset {byte_offset} plus byteLength {byte_length} overflows",
                        kind.type_name(),
                    ),
                })?;
        if end > buffer_len {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "{} view range byteOffset {byte_offset} + byteLength {byte_length} exceeds ArrayBuffer byteLength {buffer_len}",
                    kind.type_name(),
                ),
            });
        }

        let bounds = self.new_view_bounds(buffer_id, explicit_length)?;
        Ok((byte_offset, byte_length, length, bounds))
    }

    /// ES2020 7.1.21 CanonicalNumericIndexString: "-0", or a string that
    /// ToNumber and Number::toString return unchanged ("1.1", "Infinity",
    /// "NaN"; not "01" or "1.0").
    pub(super) fn canonical_numeric_index_string(key: &str) -> bool {
        let number = primitive_conversion::string_number(&JsString::from(key));
        key == "-0" || ryu_js::Buffer::new().format(number) == key
    }

    pub(super) fn typed_array_integer_index_key(key: &str) -> Option<usize> {
        if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        if key.len() > 1 && key.starts_with('0') {
            return None;
        }
        key.parse::<usize>().ok()
    }

    pub(super) fn typed_array_element_range(
        kind: TypedArrayKind,
        byte_offset: usize,
        index: usize,
    ) -> Result<(usize, usize), InterpreterError> {
        let element_size = kind.element_size();
        let relative_start =
            index
                .checked_mul(element_size)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: format!("{} element index {index} overflows", kind.type_name()),
                })?;
        let start = byte_offset.checked_add(relative_start).ok_or_else(|| {
            InterpreterError::RangeError {
                message: format!("{} element index {index} overflows", kind.type_name()),
            }
        })?;
        let end = start
            .checked_add(element_size)
            .ok_or_else(|| InterpreterError::RangeError {
                message: format!("{} element index {index} overflows", kind.type_name()),
            })?;
        Ok((start, end))
    }

    pub(super) fn typed_array_unsigned_mod_i64(value: i64, modulus: u64) -> u64 {
        i128::from(value).rem_euclid(i128::from(modulus)) as u64
    }

    pub(super) fn typed_array_unsigned_mod_f64(value: f64, modulus: u64) -> u64 {
        if !value.is_finite() || value == 0.0 {
            return 0;
        }
        value.trunc().rem_euclid(modulus as f64) as u64
    }

    pub(super) fn typed_array_unsigned_mod(value: &Value, modulus: u64) -> u64 {
        match value {
            Value::Int(n) => Self::typed_array_unsigned_mod_i64(*n, modulus),
            Value::Bool(true) => 1 % modulus,
            Value::Bool(false) | Value::Null => 0,
            _ => Self::coerce_to_float(value)
                .map(|number| Self::typed_array_unsigned_mod_f64(number, modulus))
                .unwrap_or(0),
        }
    }

    pub(super) fn typed_array_u8_value(value: &Value) -> u8 {
        Self::typed_array_unsigned_mod(value, 256) as u8
    }

    pub(super) fn typed_array_i32_value(value: &Value) -> i32 {
        (Self::typed_array_unsigned_mod(value, 1u64 << 32) as u32) as i32
    }

    pub(super) fn typed_array_u32_value(value: &Value) -> u32 {
        Self::typed_array_unsigned_mod(value, 1u64 << 32) as u32
    }

    /// ES2020 7.1.4 ToNumber for a typed-array element store (primitives only;
    /// anything else stores NaN).
    pub(super) fn typed_array_number(value: &Value) -> f64 {
        match value {
            Value::Int(n) => *n as f64,
            Value::Bool(true) => 1.0,
            Value::Bool(false) | Value::Null => 0.0,
            Value::Undefined => f64::NAN,
            _ => Self::coerce_to_float(value).unwrap_or(f64::NAN),
        }
    }

    /// ES2020 7.1.12 ToUint8Clamp: clamp to [0, 255], ties to even.
    pub(super) fn typed_array_u8_clamped_value(value: &Value) -> u8 {
        let number = Self::typed_array_number(value);
        if number.is_nan() || number <= 0.0 {
            return 0;
        }
        if number >= 255.0 {
            return 255;
        }
        let floor = number.floor();
        let rounded = if number - floor > 0.5 {
            floor + 1.0
        } else if number - floor < 0.5 {
            floor
        } else if floor % 2.0 == 0.0 {
            floor
        } else {
            floor + 1.0
        };
        rounded as u8
    }

    pub(super) fn read_typed_array_element_bytes(
        view: &TypedArrayView,
        bytes: &[u8],
        index: usize,
    ) -> Result<Value, InterpreterError> {
        let (start, end) = Self::typed_array_element_range(view.kind, view.byte_offset, index)?;
        let Some(slot) = bytes.get(start..end) else {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "{} element index {index} is out of bounds",
                    view.kind.type_name()
                ),
            });
        };
        match view.kind {
            TypedArrayKind::Uint8 => Ok(Value::Int(i64::from(slot[0]))),
            TypedArrayKind::Int32 => {
                let mut raw = [0u8; 4];
                raw.copy_from_slice(slot);
                Ok(Value::Int(i64::from(i32::from_le_bytes(raw))))
            }
            TypedArrayKind::Uint32 => {
                let mut raw = [0u8; 4];
                raw.copy_from_slice(slot);
                Ok(Value::Int(i64::from(u32::from_le_bytes(raw))))
            }
            TypedArrayKind::Int8 => Ok(Value::Int(i64::from(slot[0] as i8))),
            TypedArrayKind::Uint8Clamped => Ok(Value::Int(i64::from(slot[0]))),
            TypedArrayKind::Int16 => Ok(Value::Int(i64::from(i16::from_le_bytes([
                slot[0], slot[1],
            ])))),
            TypedArrayKind::Uint16 => Ok(Value::Int(i64::from(u16::from_le_bytes([
                slot[0], slot[1],
            ])))),
            TypedArrayKind::Float32 => {
                let mut raw = [0u8; 4];
                raw.copy_from_slice(slot);
                Ok(js_number_to_value(f64::from(f32::from_le_bytes(raw))))
            }
            TypedArrayKind::Float64 => {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(slot);
                Ok(js_number_to_value(f64::from_le_bytes(raw)))
            }
            TypedArrayKind::BigInt64 | TypedArrayKind::BigUint64 => {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(slot);
                let digits = if view.kind == TypedArrayKind::BigInt64 {
                    i64::from_le_bytes(raw).to_string()
                } else {
                    u64::from_le_bytes(raw).to_string()
                };
                Ok(Value::BigInt(Arc::from(digits.as_str())))
            }
        }
    }

    pub(super) fn write_typed_array_element_bytes_at_offset(
        kind: TypedArrayKind,
        byte_offset: usize,
        bytes: &mut [u8],
        index: usize,
        value: &Value,
    ) -> Result<(), InterpreterError> {
        let (start, end) = Self::typed_array_element_range(kind, byte_offset, index)?;
        let Some(slot) = bytes.get_mut(start..end) else {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "{} element index {index} is out of bounds",
                    kind.type_name()
                ),
            });
        };
        match kind {
            TypedArrayKind::Uint8 => {
                slot[0] = Self::typed_array_u8_value(value);
            }
            TypedArrayKind::Int32 => {
                slot.copy_from_slice(&Self::typed_array_i32_value(value).to_le_bytes());
            }
            TypedArrayKind::Uint32 => {
                slot.copy_from_slice(&Self::typed_array_u32_value(value).to_le_bytes());
            }
            TypedArrayKind::Int8 => {
                slot[0] = Self::typed_array_unsigned_mod(value, 1 << 8) as u8;
            }
            TypedArrayKind::Uint8Clamped => {
                slot[0] = Self::typed_array_u8_clamped_value(value);
            }
            TypedArrayKind::Int16 | TypedArrayKind::Uint16 => {
                let bits = Self::typed_array_unsigned_mod(value, 1 << 16) as u16;
                slot.copy_from_slice(&bits.to_le_bytes());
            }
            TypedArrayKind::Float32 => {
                let number = Self::typed_array_number(value) as f32;
                slot.copy_from_slice(&number.to_le_bytes());
            }
            TypedArrayKind::Float64 => {
                slot.copy_from_slice(&Self::typed_array_number(value).to_le_bytes());
            }
            TypedArrayKind::BigInt64 | TypedArrayKind::BigUint64 => {
                slot.copy_from_slice(&Self::typed_array_bigint_bits(value)?.to_le_bytes());
            }
        }
        Ok(())
    }

    /// The low 64 bits of a BigInt element value (ToBigInt64 and ToBigUint64
    /// store the same bits). Values reach the byte writer already converted
    /// by `typed_array_prepare_value`; anything else is the TypeError ToBigInt
    /// raises for a Number.
    pub(super) fn typed_array_bigint_bits(value: &Value) -> Result<u64, InterpreterError> {
        let Value::BigInt(digits) = value else {
            return Err(InterpreterError::TypeError {
                expected: "BigInt typed-array element".to_string(),
                got: format!("{} (Cannot convert it to a BigInt)", value.type_name()),
            });
        };
        let wrapped = bigint_ops::as_uint_n(64, digits.as_ref()).map_err(|error| {
            InterpreterError::RangeError {
                message: error.message().to_string(),
            }
        })?;
        wrapped
            .parse::<u64>()
            .map_err(|_| InterpreterError::RangeError {
                message: "BigInt typed-array element does not fit 64 bits".to_string(),
            })
    }

    /// ES2020 22.2 IntegerIndexedElementSet: a BigInt array converts the
    /// value with ToBigInt (a TypeError for a Number, a SyntaxError for a
    /// string that is not a BigInt literal) before anything is written; a
    /// Number array converts in the byte writer, after ToNumber's TypeError
    /// for a BigInt or a Symbol (`new Int8Array(1).set([1n])` wrote 1,
    /// bd-9vouw.269).
    pub(super) fn typed_array_prepare_value(
        &mut self,
        kind: TypedArrayKind,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        if kind.is_bigint() && !matches!(value, Value::BigInt(_)) {
            let digits = self.bigint_digits_of(value)?;
            return Ok(Value::BigInt(Arc::from(digits.as_str())));
        }
        if !kind.is_bigint() && matches!(value, Value::BigInt(_) | Value::Symbol(_)) {
            return Err(InterpreterError::TypeError {
                expected: format!("value convertible to a Number for {}", kind.type_name()),
                got: value.type_name().to_string(),
            });
        }
        Ok(value)
    }

    /// `typed_array_prepare_value` for every element, in order.
    pub(super) fn typed_array_prepare_values(
        &mut self,
        kind: TypedArrayKind,
        values: Vec<Value>,
    ) -> Result<Vec<Value>, InterpreterError> {
        values
            .into_iter()
            .map(|value| self.typed_array_prepare_value(kind, value))
            .collect()
    }

    /// The TypeError for copying between a BigInt and a Number typed array
    /// (ES2020 22.2.3.23.2 step 21, 22.2.4.3 step 16).
    pub(super) fn typed_array_content_type_check(
        &self,
        target: TypedArrayKind,
        source: &Value,
    ) -> Result<(), InterpreterError> {
        let Value::Object(source_id) = source else {
            return Ok(());
        };
        let source_kind = self
            .heap
            .get(source_id.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            .map(|view| view.kind);
        match source_kind {
            Some(kind) if kind.is_bigint() != target.is_bigint() => {
                Err(InterpreterError::TypeError {
                    expected: format!(
                        "{} source for a {}",
                        if target.is_bigint() {
                            "BigInt"
                        } else {
                            "Number"
                        },
                        target.type_name()
                    ),
                    got: "Cannot mix BigInt and other types, use explicit conversions".to_string(),
                })
            }
            _ => Ok(()),
        }
    }

    pub(super) fn write_typed_array_element_bytes(
        kind: TypedArrayKind,
        bytes: &mut [u8],
        index: usize,
        value: &Value,
    ) -> Result<(), InterpreterError> {
        Self::write_typed_array_element_bytes_at_offset(kind, 0, bytes, index, value)
    }

    pub(super) fn typed_array_indexed_get_property(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<Option<Value>, InterpreterError> {
        // Only a typed array has integer-indexed elements; look at the
        // object before parsing the key, which every property read reaches.
        let Some(object) = self.heap.get(object_id.0 as usize) else {
            return match Self::typed_array_integer_index_key(key) {
                Some(_) => Err(InterpreterError::ObjectNotFound { id: object_id.0 }),
                None => Ok(None),
            };
        };
        let Some(view) = object.typed_array.as_deref().cloned() else {
            return Ok(None);
        };
        let Some(index) = Self::typed_array_integer_index_key(key) else {
            // Any other canonical numeric string ("1.1", "-0", "Infinity")
            // names no element and is not looked up on the prototype
            // (ES2020 9.4.5.2 and 9.4.5.4, integer-indexed [[HasProperty]]
            // and [[Get]]); "01" is an ordinary key.
            if Self::canonical_numeric_index_string(key) {
                return Ok(Some(Value::Undefined));
            }
            return Ok(None);
        };
        if index >= view.length {
            return Ok(Some(Value::Undefined));
        }
        let value = self.with_array_buffer_bytes(view.buffer, |bytes| {
            Self::read_typed_array_element_bytes(&view, bytes, index)
        })??;
        Ok(Some(value))
    }

    pub(super) fn typed_array_indexed_set_property(
        &mut self,
        object_id: ObjectId,
        key: &str,
        value: &Value,
    ) -> Result<Option<bool>, InterpreterError> {
        let Some(index) = Self::typed_array_integer_index_key(key) else {
            return Ok(None);
        };
        let Some(view) = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
            .typed_array
            .as_deref()
            .cloned()
        else {
            return Ok(None);
        };
        let value = self.typed_array_prepare_value(view.kind, value.clone())?;
        if index >= view.length {
            return Ok(Some(true));
        }
        self.with_array_buffer_bytes_mut(view.buffer, |bytes| {
            Self::write_typed_array_element_bytes_at_offset(
                view.kind,
                view.byte_offset,
                bytes,
                index,
                &value,
            )
        })??;
        Ok(Some(true))
    }

    /// %TypedArray%.prototype.join (ES2024 23.2.3.18): ValidateTypedArray,
    /// the length taken before the separator's ToString (which runs a
    /// separator object's toString or valueOf, may resize the buffer, and
    /// makes a Symbol a TypeError), then each element read again: one past a
    /// shrink is undefined and joins as "". The separator was rendered
    /// without its conversion ("[object Object]").
    pub(super) fn typed_array_join(
        &mut self,
        module: &Ir3Module,
        array_id: ObjectId,
        view: &TypedArrayView,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        Self::reject_out_of_bounds_typed_array(view, "join")?;
        let length = view.length;
        let separator = match self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined) {
            Value::Undefined => vec![u16::from(b',')],
            value => {
                // Guest code runs while native locals hold values: no
                // collection until this returns.
                self.gc_nested_request = None;
                match self.object_to_string_primitive(Some(module), value)? {
                    Value::Symbol(_) => return Err(Self::symbol_to_string_error()),
                    Value::Str(text) => text.code_units_vec(),
                    other => self.value_to_string(&other).encode_utf16().collect(),
                }
            }
        };
        let mut joined: Vec<u16> = Vec::new();
        for index in 0..length {
            if index > 0 {
                joined.extend_from_slice(&separator);
            }
            if let Some(element) =
                self.typed_array_indexed_get_property(array_id, &index.to_string())?
                && !matches!(element, Value::Undefined)
            {
                joined.extend(self.value_to_string(&element).encode_utf16());
            }
            self.check_string_limit(joined.len())?;
        }
        Ok(Value::Str(JsString::from_code_units(&joined)))
    }

    /// TypedArraySetElement steps 1-2 (ES2024 10.4.5.16): ToBigInt for a
    /// BigInt array, ToNumber otherwise, running an object's @@toPrimitive,
    /// valueOf or toString. A BigInt for a Number array and a Symbol are
    /// TypeErrors. The conversion happens even when the index is invalid.
    pub(super) fn typed_array_element_value(
        &mut self,
        module: Option<&Ir3Module>,
        kind: TypedArrayKind,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        let primitive = self.object_to_number_primitive(module, value)?;
        if kind.is_bigint() {
            return self.typed_array_prepare_value(kind, primitive);
        }
        match primitive {
            Value::BigInt(_) | Value::Symbol(_) => Err(InterpreterError::TypeError {
                expected: format!("value convertible to a Number for {}", kind.type_name()),
                got: primitive.type_name().to_string(),
            }),
            primitive => Ok(primitive),
        }
    }

    /// `typed_array_element_value` for each value, in order.
    pub(super) fn typed_array_element_values(
        &mut self,
        module: Option<&Ir3Module>,
        kind: TypedArrayKind,
        values: Vec<Value>,
    ) -> Result<Vec<Value>, InterpreterError> {
        // Guest code runs while native locals hold values: no collection
        // until this returns.
        self.gc_nested_request = None;
        values
            .into_iter()
            .map(|value| self.typed_array_element_value(module, kind, value))
            .collect()
    }

    /// [[Set]] of a typed array (ES2024 10.4.5.5) for a key that is a
    /// CanonicalNumericIndexString ("0", "-0", "1.1", "-1", "Infinity").
    /// On the typed array itself it is TypedArraySetElement: the value is
    /// converted, then written when the index is a valid integer index;
    /// any other numeric key writes nothing and creates no property. Through
    /// another receiver an invalid index does nothing, and a valid one is
    /// OrdinarySet with the element's writable data descriptor, which
    /// defines the property on the receiver. `None` for any other key or
    /// object.
    pub(super) fn typed_array_set_runtime_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &str,
        value: &Value,
        receiver: &Value,
    ) -> Result<Option<TypedArraySetOutcome>, InterpreterError> {
        let Some(view) = self.typed_array_view_for_object(object_id)? else {
            return Ok(None);
        };
        let index = Self::typed_array_integer_index_key(key);
        if index.is_none() && !Self::canonical_numeric_index_string(key) {
            return Ok(None);
        }
        if !matches!(receiver, Value::Object(receiver_id) if *receiver_id == object_id) {
            let valid = index.is_some_and(|index| index < view.length);
            return Ok(Some(if valid {
                TypedArraySetOutcome::DefineOnReceiver
            } else {
                TypedArraySetOutcome::Done(true)
            }));
        }
        let converted = self.typed_array_element_value(module, view.kind, value.clone())?;
        if index.is_some() {
            // The conversion can run guest code that shrank the buffer; the
            // write re-reads the view and skips an index now out of range.
            self.typed_array_indexed_set_property(object_id, key, &converted)?;
        }
        Ok(Some(TypedArraySetOutcome::Done(true)))
    }

    /// For a typed array and a CanonicalNumericIndexString key, whether
    /// the key is a valid integer index (IsValidIntegerIndex); `None` for
    /// any other key or object.
    pub(super) fn typed_array_numeric_key_is_valid(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<Option<bool>, InterpreterError> {
        let Some(view) = self.typed_array_view_for_object(object_id)? else {
            return Ok(None);
        };
        Ok(match Self::typed_array_integer_index_key(key) {
            Some(index) => Some(index < view.length),
            None => Self::canonical_numeric_index_string(key).then_some(false),
        })
    }

    /// [[GetOwnProperty]] of a typed array (ES2024 10.4.5.1) for a
    /// CanonicalNumericIndexString key: the element as a writable,
    /// enumerable, configurable data property, or undefined when the index
    /// is not valid. `None` for any other key or object.
    pub(super) fn typed_array_own_property_descriptor(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<Option<Value>, InterpreterError> {
        let Some(name) = key.as_str() else {
            return Ok(None);
        };
        match self.typed_array_numeric_key_is_valid(object_id, name)? {
            None => Ok(None),
            Some(false) => Ok(Some(Value::Undefined)),
            Some(true) => {
                let value = self
                    .typed_array_indexed_get_property(object_id, name)?
                    .unwrap_or(Value::Undefined);
                let descriptor = self.alloc_object_with_properties(&[
                    ("value", value),
                    ("writable", Value::Bool(true)),
                    ("enumerable", Value::Bool(true)),
                    ("configurable", Value::Bool(true)),
                ])?;
                Ok(Some(Value::Object(descriptor)))
            }
        }
    }

    /// [[DefineOwnProperty]] of a typed array (ES2024 10.4.5.3) for a
    /// CanonicalNumericIndexString key: false for an index that is not a
    /// valid integer index, a descriptor that is non-configurable,
    /// non-enumerable, non-writable or an accessor; otherwise a given value
    /// is written with TypedArraySetElement. `None` for any other key or
    /// object.
    pub(super) fn typed_array_define_own_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        fields: &PropertyDescriptorFields,
    ) -> Result<Option<bool>, InterpreterError> {
        let Some(key) = key.as_str() else {
            return Ok(None);
        };
        let Some(view) = self.typed_array_view_for_object(object_id)? else {
            return Ok(None);
        };
        let index = Self::typed_array_integer_index_key(key);
        if index.is_none() && !Self::canonical_numeric_index_string(key) {
            return Ok(None);
        }
        if !index.is_some_and(|index| index < view.length)
            || fields.configurable == Some(false)
            || fields.enumerable == Some(false)
            || fields.is_accessor()
            || fields.writable == Some(false)
        {
            return Ok(Some(false));
        }
        if let Some(value) = fields.value.clone() {
            let converted = self.typed_array_element_value(module, view.kind, value)?;
            self.typed_array_indexed_set_property(object_id, key, &converted)?;
        }
        Ok(Some(true))
    }

    pub(super) fn typed_array_view_for_object(
        &self,
        object_id: ObjectId,
    ) -> Result<Option<TypedArrayView>, InterpreterError> {
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        Ok(object.typed_array.as_deref().cloned())
    }

    pub(super) fn typed_array_receiver_view(
        &self,
        receiver: Value,
        method_name: &str,
    ) -> Result<(ObjectId, TypedArrayView), InterpreterError> {
        let Value::Object(object_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: format!("TypedArray receiver for TypedArray.prototype.{method_name}"),
                got: receiver.type_name().to_string(),
            });
        };
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let view = object.typed_array.as_deref().cloned().ok_or_else(|| {
            let got = object.brand().unwrap_or("object").to_string();
            InterpreterError::TypeError {
                expected: format!("TypedArray receiver for TypedArray.prototype.{method_name}"),
                got,
            }
        })?;
        // ValidateTypedArray (bd-9vouw.256); subarray takes an
        // out-of-bounds receiver as one of length 0.
        if method_name != "subarray" {
            Self::reject_out_of_bounds_typed_array(&view, method_name)?;
        }
        Ok((object_id, view))
    }

    pub(super) fn typed_array_values_in_range(
        &self,
        view: &TypedArrayView,
        start: usize,
        end: usize,
    ) -> Result<Vec<Value>, InterpreterError> {
        if start > end || end > view.length {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "{} value range {start}..{end} exceeds length {}",
                    view.kind.type_name(),
                    view.length,
                ),
            });
        }
        self.with_array_buffer_bytes(view.buffer, |bytes| {
            let mut values = Vec::with_capacity(end - start);
            for index in start..end {
                values.push(Self::read_typed_array_element_bytes(view, bytes, index)?);
            }
            Ok(values)
        })?
    }

    pub(super) fn array_like_values(
        &self,
        obj_id: ObjectId,
    ) -> Result<Vec<Value>, InterpreterError> {
        if let Some(view) = self.typed_array_view_for_object(obj_id)? {
            return self.typed_array_values_in_range(&view, 0, view.length);
        }
        let length = self.array_like_length(obj_id)?;
        let mut values = self.element_buffer(length)?;
        for index in 0..length {
            values.push(
                self.array_index_value(obj_id, index)?
                    .unwrap_or(Value::Undefined),
            );
        }
        Ok(values)
    }

    /// The values of an array-like source as the typed array constructor
    /// (ES2020 22.2.4.4 steps 8-12) and set() (22.2.3.23.1 steps 16-22)
    /// read them: LengthOfArrayLike, which runs a `length` getter and
    /// valueOf and makes a Symbol length a TypeError, then Get for each
    /// index, getters included. A typed array source is read directly. The
    /// non-observable read took a missing or Symbol length as 0.
    pub(super) fn observable_array_like_values(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
    ) -> Result<Vec<Value>, InterpreterError> {
        if let Some(view) = self.typed_array_view_for_object(object_id)? {
            return self.typed_array_values_in_range(&view, 0, view.length);
        }
        let length = self.generic_length(module, object_id)?;
        let length = usize::try_from(length).map_err(|_| InterpreterError::RangeError {
            message: format!("array-like length {length} exceeds host addressable size"),
        })?;
        let mut values = self.element_buffer(length)?;
        for index in 0..length {
            values.push(self.generic_get(
                module,
                object_id,
                &Self::generic_index_key(index as u64),
            )?);
        }
        Ok(values)
    }

    pub(super) fn typed_array_source_values(
        &mut self,
        module: &Ir3Module,
        source: Value,
    ) -> Result<Vec<Value>, InterpreterError> {
        match source {
            Value::Object(object_id) => self.observable_array_like_values(Some(module), object_id),
            other => Err(InterpreterError::TypeError {
                expected: "array-like or TypedArray source for TypedArray.prototype.set"
                    .to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn typed_array_offset_arg(
        &mut self,
        module: &Ir3Module,
        kind: TypedArrayKind,
        args: RegRange,
        offset: u32,
        field: &str,
    ) -> Result<usize, InterpreterError> {
        let Some(value) = self.builtin_arg(args, offset)? else {
            return Ok(0);
        };
        if matches!(value, Value::Undefined) {
            return Ok(0);
        }
        let value = self.object_to_number_primitive(Some(module), value)?;
        self.typed_array_index_from_value(kind, field, &value)
    }

    pub(super) fn typed_array_relative_index_arg(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        offset: u32,
        len: usize,
        default: usize,
    ) -> Result<usize, InterpreterError> {
        match self.builtin_number_arg(module, args, offset)? {
            Some(Value::Undefined) | None => Ok(default),
            Some(value) => Ok(Self::clamp_relative_index(
                Self::value_as_integer(&value),
                len,
            )),
        }
    }

    pub(super) fn typed_array_method_range(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        start_offset: u32,
        end_offset: u32,
        len: usize,
    ) -> Result<(usize, usize), InterpreterError> {
        let start = self.typed_array_relative_index_arg(module, args, start_offset, len, 0)?;
        let end = self.typed_array_relative_index_arg(module, args, end_offset, len, len)?;
        Ok((start, end))
    }

    pub(super) fn typed_array_set(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (target_id, target_view) = self.typed_array_receiver_view(receiver, "set")?;
        let offset = self.typed_array_offset_arg(module, target_view.kind, args, 1, "offset")?;
        let source = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        self.typed_array_content_type_check(target_view.kind, &source)?;
        if let Some(source_id) = self.typed_array_set_array_like_source(&source)? {
            return self.typed_array_set_from_array_like(
                module,
                target_id,
                &target_view,
                offset,
                source_id,
            );
        }
        let values = self.typed_array_source_values(module, source)?;
        let values = self.typed_array_prepare_values(target_view.kind, values)?;
        let end = offset
            .checked_add(values.len())
            .ok_or_else(|| InterpreterError::RangeError {
                message: format!(
                    "{}.prototype.set offset {offset} plus source length {} overflows",
                    target_view.kind.type_name(),
                    values.len(),
                ),
            })?;
        if end > target_view.length {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "{}.prototype.set source length {} at offset {offset} exceeds target length {}",
                    target_view.kind.type_name(),
                    values.len(),
                    target_view.length,
                ),
            });
        }
        self.with_array_buffer_bytes_mut(target_view.buffer, |bytes| {
            for (relative, value) in values.iter().enumerate() {
                Self::write_typed_array_element_bytes_at_offset(
                    target_view.kind,
                    target_view.byte_offset,
                    bytes,
                    offset + relative,
                    value,
                )?;
            }
            Ok(())
        })??;
        Ok(Value::Undefined)
    }

    /// The array-like source `set` reads with Get and converts element by
    /// element (ES2024 23.2.3.26.2 SetTypedArrayFromArrayLike): ToObject of
    /// a primitive source (a string's characters, a number's nothing), or
    /// an object that is not a typed array and not an Array whose elements
    /// are all plain primitives (those keep the bulk read, which observes
    /// nothing). `None` for those, and for undefined and null, which keep
    /// their TypeError.
    pub(super) fn typed_array_set_array_like_source(
        &mut self,
        source: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        Ok(match source {
            Value::Object(source_id) => {
                let bulk = self.heap.get(source_id.0 as usize).is_some_and(|object| {
                    object.typed_array.is_some()
                        || (object.is_array && self.array_holds_plain_primitives(*source_id))
                });
                (!bulk).then_some(*source_id)
            }
            Value::Bool(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::Str(_)
            | Value::Symbol(_)
            | Value::BigInt(_) => Some(self.alloc_primitive_wrapper(source.clone())?),
            _ => None,
        })
    }

    /// Whether every index below the Array `array_id`'s length is an own
    /// data property holding a primitive other than a Symbol, so reading and
    /// converting its elements runs no guest code.
    pub(super) fn array_holds_plain_primitives(&self, array_id: ObjectId) -> bool {
        let Some(object) = self.heap.get(array_id.0 as usize) else {
            return false;
        };
        let Some(Value::Int(length)) = object.properties.get("length") else {
            return false;
        };
        (0..*length).all(|index| {
            matches!(
                object.own_runtime_property_value(&RuntimePropertyKey::String(JsString::from(
                    index.to_string()
                ))),
                Some(
                    Value::Undefined
                        | Value::Null
                        | Value::Bool(_)
                        | Value::Int(_)
                        | Value::Float(_)
                        | Value::Str(_)
                        | Value::BigInt(_)
                )
            )
        })
    }

    /// SetTypedArrayFromArrayLike (ES2024 23.2.3.26.2): LengthOfArrayLike
    /// of the source, the range check against the target's length, then for
    /// each index Get, conversion (ToNumber/ToBigInt, running valueOf) and
    /// TypedArraySetElement in order, so an abrupt Get or conversion leaves
    /// the earlier elements written, and an element past a shrink the
    /// conversions caused is skipped. All values were read first and
    /// converted without running guest code.
    pub(super) fn typed_array_set_from_array_like(
        &mut self,
        module: &Ir3Module,
        target_id: ObjectId,
        target_view: &TypedArrayView,
        offset: usize,
        source_id: ObjectId,
    ) -> Result<Value, InterpreterError> {
        // Guest code runs while native locals hold values: no collection
        // until this returns.
        self.gc_nested_request = None;
        let source_length = self.generic_length(Some(module), source_id)?;
        let source_length =
            usize::try_from(source_length).map_err(|_| InterpreterError::RangeError {
                message: format!("array-like length {source_length} exceeds host addressable size"),
            })?;
        if offset
            .checked_add(source_length)
            .is_none_or(|end| end > target_view.length)
        {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "{}.prototype.set source length {source_length} at offset {offset} exceeds target length {}",
                    target_view.kind.type_name(),
                    target_view.length,
                ),
            });
        }
        for index in 0..source_length {
            let value = self.generic_get(
                Some(module),
                source_id,
                &Self::generic_index_key(index as u64),
            )?;
            let converted =
                self.typed_array_element_value(Some(module), target_view.kind, value)?;
            self.typed_array_indexed_set_property(
                target_id,
                &(offset + index).to_string(),
                &converted,
            )?;
        }
        Ok(Value::Undefined)
    }

    pub(super) fn typed_array_subarray(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (target_id, view) = self.typed_array_receiver_view(receiver, "subarray")?;
        let (start, end) = self.typed_array_method_range(module, args, 0, 1, view.length)?;
        let length = end.saturating_sub(start);
        let element_size = view.kind.element_size();
        let relative_byte_offset =
            start
                .checked_mul(element_size)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: format!(
                        "{}.prototype.subarray byteOffset overflows",
                        view.kind.type_name()
                    ),
                })?;
        let byte_offset = view
            .byte_offset
            .checked_add(relative_byte_offset)
            .ok_or_else(|| InterpreterError::RangeError {
                message: format!(
                    "{}.prototype.subarray absolute byteOffset overflows",
                    view.kind.type_name()
                ),
            })?;
        // ES2024 23.2.3.29 steps 14-16: TypedArraySpeciesCreate(O, «buffer,
        // beginByteOffset, newLength»), without newLength when O tracks its
        // buffer's length and `end` is undefined, so the result tracks it
        // too (bd-9vouw.256).
        let tracking = view
            .bounds
            .is_some_and(|bounds| bounds.fixed_length.is_none())
            && matches!(self.builtin_arg(args, 1)?, None | Some(Value::Undefined));
        let mut species_args = vec![
            Value::Object(view.buffer),
            Value::Int(i64::try_from(byte_offset).unwrap_or(i64::MAX)),
        ];
        if !tracking {
            species_args.push(Value::Int(i64::try_from(length).unwrap_or(i64::MAX)));
        }
        if let Some(created) =
            self.typed_array_species_result(module, target_id, view.kind, species_args)?
        {
            return Ok(Value::Object(created));
        }
        let explicit_length = (!tracking).then_some(length);
        let (byte_offset, byte_length, length, bounds) =
            self.typed_array_view_shape_over(view.kind, view.buffer, byte_offset, explicit_length)?;
        let result = self.alloc_typed_array_view_object(
            view.kind,
            view.buffer,
            byte_offset,
            byte_length,
            length,
        )?;
        self.register_buffer_view(result, bounds)?;
        Ok(Value::Object(result))
    }

    /// bd-9vouw.94: ES2020 22.2.4.7 TypedArraySpeciesCreate(exemplar, args).
    /// `None` when the species is the exemplar's own intrinsic constructor
    /// (the caller allocates as before): `constructor` undefined, or its
    /// @@species undefined, null or that intrinsic. Otherwise the species
    /// is constructed with `args` and validated (22.2.4.6
    /// TypedArrayCreate): a TypeError when `constructor` is not an object,
    /// the species is not a constructor, the result is not a typed array,
    /// is shorter than a single numeric argument asks, or holds BigInts
    /// where the exemplar holds Numbers (or the reverse).
    pub(super) fn typed_array_species_result(
        &mut self,
        module: &Ir3Module,
        exemplar: ObjectId,
        kind: TypedArrayKind,
        args: Vec<Value>,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let constructor_key = RuntimePropertyKey::String(JsString::from("constructor"));
        let constructor = self.proxy_aware_get_runtime_property(
            Some(module),
            exemplar,
            &constructor_key,
            Value::Object(exemplar),
            0,
        )?;
        let is_own_intrinsic = |value: &Value| {
            matches!(value, Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::StandardConstructor
                    && Self::standard_constructor_name(builtin)
                        .is_ok_and(|name| name == kind.type_name()))
        };
        if matches!(constructor, Value::Undefined) || is_own_intrinsic(&constructor) {
            return Ok(None);
        }
        if !constructor.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "object or undefined constructor for TypedArraySpeciesCreate".to_string(),
                got: constructor.type_name().to_string(),
            });
        }
        let species = self.species_of_constructor(module, &constructor)?;
        if matches!(species, Value::Undefined | Value::Null) || is_own_intrinsic(&species) {
            return Ok(None);
        }
        if !self.is_constructible_value(&species) {
            return Err(InterpreterError::TypeError {
                expected: "constructor @@species for TypedArraySpeciesCreate".to_string(),
                got: species.type_name().to_string(),
            });
        }
        let requested_length = match args.as_slice() {
            [Value::Int(length)] => usize::try_from(*length).ok(),
            _ => None,
        };
        let (result, label) =
            self.with_gc_nested_request(vec![Value::Object(exemplar)], |core| {
                core.invoke_inline_construct_with_labels(Some(module), species, args, None, None)
            })?;
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        let created_view = match &result {
            Value::Object(object_id) => self
                .heap
                .get(object_id.0 as usize)
                .and_then(|object| object.typed_array.as_deref().cloned()),
            _ => None,
        };
        let (Value::Object(created), Some(created_view)) = (result.clone(), created_view) else {
            return Err(InterpreterError::TypeError {
                expected: "typed array from the @@species constructor".to_string(),
                got: result.type_name().to_string(),
            });
        };
        if requested_length.is_some_and(|length| created_view.length < length) {
            return Err(InterpreterError::TypeError {
                expected: format!(
                    "typed array of length {} or more from the @@species constructor",
                    requested_length.unwrap_or_default()
                ),
                got: format!("length {}", created_view.length),
            });
        }
        if created_view.kind.is_bigint() != kind.is_bigint() {
            return Err(InterpreterError::TypeError {
                expected: format!(
                    "{} content from the @@species constructor",
                    if kind.is_bigint() { "BigInt" } else { "Number" }
                ),
                got: created_view.kind.type_name().to_string(),
            });
        }
        Ok(Some(created))
    }

    /// Set(A, index, value) for each value, in order: the elements of a
    /// typed array a @@species constructor returned. The target's bytes
    /// also take the source bytes' IFC label (conservatively, whatever was
    /// copied).
    pub(super) fn typed_array_write_values(
        &mut self,
        target: ObjectId,
        source: ObjectId,
        values: &[Value],
    ) -> Result<(), InterpreterError> {
        for (index, value) in values.iter().enumerate() {
            self.typed_array_indexed_set_property(target, &index.to_string(), value)?;
        }
        self.join_typed_array_source_label(target, source)
    }

    /// `target`'s storage joins the label of `source`'s backing buffer, whose
    /// elements were written to it.
    pub(super) fn join_typed_array_source_label(
        &mut self,
        target: ObjectId,
        source: ObjectId,
    ) -> Result<(), InterpreterError> {
        let label = self
            .array_buffer_id_for_object(source)
            .and_then(|buffer| self.heap.get(buffer.0 as usize))
            .and_then(|object| object.array_buffer.as_deref())
            .map(|backing| backing.label.clone())
            .unwrap_or(Label::Public);
        self.join_binary_storage_label(target, &label)
    }

    pub(super) fn typed_array_slice(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (target_id, view) = self.typed_array_receiver_view(receiver, "slice")?;
        let (start, end) = self.typed_array_method_range(module, args, 0, 1, view.length)?;
        // ES2020 22.2.3.24 step 9: the result exists before any element is
        // read.
        let count = Value::Int(i64::try_from(end.saturating_sub(start)).unwrap_or(i64::MAX));
        let species = self.typed_array_species_result(module, target_id, view.kind, vec![count])?;
        let values = self.typed_array_values_in_range(&view, start, end.max(start))?;
        let result = match species {
            Some(created) => {
                self.typed_array_write_values(created, target_id, &values)?;
                created
            }
            None => self.alloc_typed_array_from_values(view.kind, &values)?,
        };
        Ok(Value::Object(result))
    }

    /// ES2020 24.1.4.3 ArrayBuffer.prototype.slice(start, end): a new
    /// ArrayBuffer holding a copy of the bytes from `start` to `end`
    /// (relative indices clamped to byteLength, as for typed arrays). The new
    /// buffer is charged like the constructor's, and its bytes keep the
    /// source bytes' IFC label.
    /// bd-9vouw.94: the result buffer of ArrayBuffer.prototype.slice through
    /// SpeciesConstructor(O, %ArrayBuffer%) (ES2020 24.1.4.3 steps 15-22).
    /// `None` for %ArrayBuffer% itself. Another species is constructed with
    /// the new length. A TypeError results when that is not an ArrayBuffer,
    /// is the receiver itself, or is shorter than the new length.
    pub(super) fn array_buffer_species_result(
        &mut self,
        module: &Ir3Module,
        source: ObjectId,
        new_length: usize,
        shared: bool,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let intrinsic = if shared {
            "SharedArrayBuffer"
        } else {
            "ArrayBuffer"
        };
        let constructor_key = RuntimePropertyKey::String(JsString::from("constructor"));
        let constructor = self.proxy_aware_get_runtime_property(
            Some(module),
            source,
            &constructor_key,
            Value::Object(source),
            0,
        )?;
        let is_intrinsic = |value: &Value| {
            matches!(value, Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::StandardConstructor
                    && Self::standard_constructor_name(builtin)
                        .is_ok_and(|name| name == intrinsic))
        };
        if matches!(constructor, Value::Undefined) || is_intrinsic(&constructor) {
            return Ok(None);
        }
        if !constructor.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "object or undefined constructor for ArrayBuffer.prototype.slice"
                    .to_string(),
                got: constructor.type_name().to_string(),
            });
        }
        let species = self.species_of_constructor(module, &constructor)?;
        if matches!(species, Value::Undefined | Value::Null) || is_intrinsic(&species) {
            return Ok(None);
        }
        if !self.is_constructible_value(&species) {
            return Err(InterpreterError::TypeError {
                expected: "constructor @@species for ArrayBuffer.prototype.slice".to_string(),
                got: species.type_name().to_string(),
            });
        }
        let length = Value::Int(i64::try_from(new_length).unwrap_or(i64::MAX));
        let (result, label) = self.with_gc_nested_request(vec![Value::Object(source)], |core| {
            core.invoke_inline_construct_with_labels(
                Some(module),
                species,
                vec![length],
                None,
                None,
            )
        })?;
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        let created = match result {
            Value::Object(object_id)
                if self
                    .heap
                    .get(object_id.0 as usize)
                    .is_some_and(|object| Self::is_plain_buffer(object, shared)) =>
            {
                object_id
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: format!("{intrinsic} from the @@species constructor"),
                    got: other.type_name().to_string(),
                });
            }
        };
        if created == source {
            return Err(InterpreterError::TypeError {
                expected: "a new ArrayBuffer from the @@species constructor".to_string(),
                got: "the receiver itself".to_string(),
            });
        }
        if self.array_buffer_byte_length(created)? < new_length {
            return Err(InterpreterError::TypeError {
                expected: format!("ArrayBuffer of byteLength {new_length} or more"),
                got: format!("byteLength {}", self.array_buffer_byte_length(created)?),
            });
        }
        Ok(Some(created))
    }

    pub(super) fn array_buffer_slice(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
        shared: bool,
    ) -> Result<Value, InterpreterError> {
        let source = self.plain_buffer_receiver(&receiver, shared, "slice")?;
        // ES2024 25.1.6.7 step 4 (bd-9vouw.256).
        if self.buffer_resizability(source)?.1 {
            return Err(InterpreterError::TypeError {
                expected: "an attached ArrayBuffer for ArrayBuffer.prototype.slice".to_string(),
                got: "a detached ArrayBuffer".to_string(),
            });
        }
        let length = self.with_array_buffer_bytes(source, <[u8]>::len)?;
        let (first, last) = self.typed_array_method_range(module, args, 0, 1, length)?;
        let species =
            self.array_buffer_species_result(module, source, last.saturating_sub(first), shared)?;
        // ES2024 25.1.6.7 steps 20-23: the species constructor may have
        // detached or shrunk the source; copy what is still there
        // (bd-9vouw.256).
        if self.buffer_resizability(source)?.1 {
            return Err(InterpreterError::TypeError {
                expected: "an attached ArrayBuffer for ArrayBuffer.prototype.slice".to_string(),
                got: "a detached ArrayBuffer".to_string(),
            });
        }
        let copied = self.with_array_buffer_bytes(source, |bytes| {
            let end = last.min(bytes.len());
            bytes[first.min(end)..end].to_vec()
        })?;
        if let Some(created) = species {
            self.with_array_buffer_bytes_mut(created, |bytes| {
                bytes[..copied.len()].copy_from_slice(&copied);
            })?;
            // The copied bytes keep the source bytes' IFC label, as on the
            // %ArrayBuffer% path below.
            let label = self
                .heap
                .get(source.0 as usize)
                .and_then(|object| object.array_buffer.as_deref())
                .map(|backing| backing.label.clone())
                .unwrap_or(Label::Public);
            self.join_binary_storage_label(created, &label)?;
            return Ok(Value::Object(created));
        }
        let label = self
            .heap
            .get(source.0 as usize)
            .and_then(|object| object.array_buffer.as_deref())
            .map(|backing| backing.label.clone())
            .unwrap_or(Label::Public);
        let created = self.alloc_buffer_object(last.saturating_sub(first), shared)?;
        self.with_array_buffer_bytes_mut(created, |bytes| {
            bytes[..copied.len()].copy_from_slice(&copied);
        })?;
        self.join_binary_storage_label(created, &label)?;
        Ok(Value::Object(created))
    }

    /// The receiver of an ArrayBuffer (`shared` false) or SharedArrayBuffer
    /// (`shared` true) prototype method: a buffer of that kind, not a view.
    /// Each kind's methods refuse the other's buffers (ES2020 24.1.4.3 step
    /// 3, 24.2.4.3 step 3).
    pub(super) fn plain_buffer_receiver(
        &self,
        receiver: &Value,
        shared: bool,
        method: &str,
    ) -> Result<ObjectId, InterpreterError> {
        let constructor = if shared {
            "SharedArrayBuffer"
        } else {
            "ArrayBuffer"
        };
        match receiver {
            Value::Object(object_id)
                if self
                    .heap
                    .get(object_id.0 as usize)
                    .is_some_and(|object| Self::is_plain_buffer(object, shared)) =>
            {
                Ok(*object_id)
            }
            other => Err(InterpreterError::TypeError {
                expected: format!("{constructor} receiver for {constructor}.prototype.{method}"),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// An ArrayBuffer (`shared` false) or a SharedArrayBuffer (`shared`
    /// true), not a typed array or DataView over one.
    pub(super) fn is_plain_buffer(object: &HeapObject, shared: bool) -> bool {
        object.array_buffer.is_some()
            && object.typed_array.is_none()
            && object.data_view.is_none()
            && (object.brand() == Some("SharedArrayBuffer")) == shared
    }

    pub(super) fn typed_array_fill(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (target_id, view) = self.typed_array_receiver_view(receiver, "fill")?;
        // ES2020 22.2.3.8 step 4: ToBigInt or ToNumber of the value, before
        // start and end convert.
        let value = if view.kind.is_bigint() {
            let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
            self.object_to_number_primitive(Some(module), value)?
        } else {
            self.builtin_number_arg(module, args, 0)?
                .unwrap_or(Value::Undefined)
        };
        let value = self.typed_array_prepare_value(view.kind, value)?;
        let start = self.typed_array_relative_index_arg(module, args, 1, view.length, 0)?;
        let end = self.typed_array_relative_index_arg(module, args, 2, view.length, view.length)?;
        // ES2024 23.2.3.9 steps 15-17: the coercions may have resized or
        // detached the buffer (bd-9vouw.256).
        let view = self.typed_array_view_for_object(target_id)?.unwrap_or(view);
        Self::reject_out_of_bounds_typed_array(&view, "fill")?;
        let end = end.min(view.length);
        if start < end {
            self.with_array_buffer_bytes_mut(view.buffer, |bytes| {
                for index in start..end {
                    Self::write_typed_array_element_bytes_at_offset(
                        view.kind,
                        view.byte_offset,
                        bytes,
                        index,
                        &value,
                    )?;
                }
                Ok(())
            })??;
        }
        Ok(Value::Object(target_id))
    }

    /// ES2020 22.2.3.19 map / 22.2.3.9 filter: a new typed array of the
    /// receiver's kind holding the callback results (map) or the elements the
    /// callback accepts (filter); the callback sees (element, index, typed
    /// array). 22.2.3.22 reverse and 22.2.3.26 sort reorder the elements in
    /// place and return the receiver. Without a comparator, sort orders
    /// numerically (BigInts by value, -0 before +0, NaN last), not by the
    /// string order Array.prototype.sort uses; a comparator runs over a copy
    /// that is written back, so an abrupt comparator leaves the array intact.
    pub(super) fn typed_array_method(
        &mut self,
        module: &Ir3Module,
        method: &str,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (target_id, view) = self.typed_array_receiver_view(receiver, method)?;
        let values = self.typed_array_values_in_range(&view, 0, view.length)?;
        let reordered = match method {
            "map" | "filter" => {
                let callback = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                if !callback.is_callable() {
                    return Err(InterpreterError::TypeError {
                        expected: format!("callable callback for TypedArray.prototype.{method}"),
                        got: callback.type_name().to_string(),
                    });
                }
                let this_arg = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let len = view.length;
                if method == "map" {
                    // ES2024 23.2.3.22: the result exists before the
                    // callbacks run (step 4). Each step reads O[k] when it
                    // runs (undefined once a resize left k out of bounds)
                    // and Sets the result's element, converting the mapped
                    // value then (steps 6.b-6.d).
                    let length = Value::Int(i64::try_from(len).unwrap_or(i64::MAX));
                    let species = self.typed_array_species_result(
                        module,
                        target_id,
                        view.kind,
                        vec![length],
                    )?;
                    let created = match species {
                        Some(created) => created,
                        None => self.alloc_typed_array_with_fresh_buffer(view.kind, len)?,
                    };
                    // A species constructor may return another element type.
                    let created_kind = self
                        .typed_array_view_for_object(created)?
                        .map_or(view.kind, |created_view| created_view.kind);
                    for index in 0..len {
                        let element = self
                            .array_loop_element(Some(module), target_id, index, true)?
                            .unwrap_or(Value::Undefined);
                        // Set converts the mapped value (its valueOf runs)
                        // before the next callback.
                        let converted =
                            self.with_gc_nested_request(vec![Value::Object(created)], |core| {
                                let mapped = core.invoke_array_callback(
                                    Some(module),
                                    &callback,
                                    this_arg.clone(),
                                    element,
                                    index,
                                    target_id,
                                )?;
                                core.typed_array_element_value(Some(module), created_kind, mapped)
                            })?;
                        self.typed_array_indexed_set_property(
                            created,
                            &index.to_string(),
                            &converted,
                        )?;
                    }
                    // As before: a species result joins the receiver's
                    // storage label (typed_array_write_values); the
                    // default result is a fresh array of the mapped values.
                    if species.is_some() {
                        self.join_typed_array_source_label(created, target_id)?;
                    }
                    return Ok(Value::Object(created));
                }
                // ES2024 23.2.3.10: each step reads O[k] when it runs; the
                // kept values go to a result created after the callbacks
                // (step 9).
                let mut kept = Vec::new();
                for index in 0..len {
                    let element = self
                        .array_loop_element(Some(module), target_id, index, true)?
                        .unwrap_or(Value::Undefined);
                    let selected = self.invoke_array_callback(
                        Some(module),
                        &callback,
                        this_arg.clone(),
                        element.clone(),
                        index,
                        target_id,
                    )?;
                    if selected.is_truthy() {
                        kept.push(element);
                    }
                }
                let length = Value::Int(i64::try_from(kept.len()).unwrap_or(i64::MAX));
                let created = match self.typed_array_species_result(
                    module,
                    target_id,
                    view.kind,
                    vec![length],
                )? {
                    Some(created) => {
                        self.typed_array_write_values(created, target_id, &kept)?;
                        created
                    }
                    None => self.alloc_typed_array_from_values(view.kind, &kept)?,
                };
                return Ok(Value::Object(created));
            }
            "reverse" => {
                let mut values = values;
                values.reverse();
                values
            }
            "sort" => self.typed_array_sorted_values(module, args, values, method)?,
            // ES2023 23.2.3.32 toReversed and 23.2.3.33 toSorted: the
            // reordered elements in a new array of the receiver's type
            // (TypedArrayCreateSameType, never the species), the receiver
            // unchanged (bd-9vouw.258).
            "toReversed" | "toSorted" => {
                let values = if method == "toSorted" {
                    self.typed_array_sorted_values(module, args, values, method)?
                } else {
                    values.into_iter().rev().collect()
                };
                return Ok(Value::Object(
                    self.alloc_typed_array_from_values(view.kind, &values)?,
                ));
            }
            "with" => return self.typed_array_with(module, target_id, &view, args),
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "TypedArray.prototype method".to_string(),
                    got: other.to_string(),
                });
            }
        };
        // A comparator may have shrunk the buffer: a write past the current
        // length is a no-op Set (bd-9vouw.256).
        let view = self.typed_array_view_for_object(target_id)?.unwrap_or(view);
        let reordered = &reordered[..reordered.len().min(view.length)];
        self.with_array_buffer_bytes_mut(view.buffer, |bytes| {
            for (index, value) in reordered.iter().enumerate() {
                Self::write_typed_array_element_bytes_at_offset(
                    view.kind,
                    view.byte_offset,
                    bytes,
                    index,
                    value,
                )?;
            }
            Ok(())
        })??;
        Ok(Value::Object(target_id))
    }

    /// `values` sorted for %TypedArray%.prototype.sort / toSorted: by the
    /// comparator argument, or numerically without one.
    pub(super) fn typed_array_sorted_values(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        mut values: Vec<Value>,
        method: &str,
    ) -> Result<Vec<Value>, InterpreterError> {
        let comparator = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        if matches!(comparator, Value::Undefined) {
            values.sort_by(Self::typed_array_default_order);
            Ok(values)
        } else if comparator.is_callable() {
            self.merge_sort_with_comparator(module, &comparator, values)
        } else {
            Err(InterpreterError::TypeError {
                expected: format!(
                    "comparator function or undefined for TypedArray.prototype.{method}"
                ),
                got: comparator.type_name().to_string(),
            })
        }
    }

    /// ES2023 23.2.3.36 %TypedArray%.prototype.with(index, value): a copy
    /// with one element replaced. The index is relative to the end when
    /// negative, the value converts (ToNumber or ToBigInt) before the
    /// index is checked against the current length (a RangeError past it),
    /// and the other elements are read after that conversion
    /// (bd-9vouw.258).
    pub(super) fn typed_array_with(
        &mut self,
        module: &Ir3Module,
        target_id: ObjectId,
        view: &TypedArrayView,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let len = view.length;
        let relative = match self.builtin_number_arg(module, args, 0)? {
            Some(index) => Self::value_as_integer(&index) as f64,
            None => 0.0,
        };
        let actual = if relative < 0.0 {
            len as f64 + relative
        } else {
            relative
        };
        let value = if view.kind.is_bigint() {
            let value = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
            self.object_to_number_primitive(Some(module), value)?
        } else {
            self.builtin_number_arg(module, args, 1)?
                .unwrap_or(Value::Undefined)
        };
        let value = self.typed_array_prepare_value(view.kind, value)?;
        let current = self
            .typed_array_view_for_object(target_id)?
            .unwrap_or_else(|| view.clone());
        let in_bounds = !current.bounds.is_some_and(|bounds| bounds.out_of_bounds);
        if !in_bounds || actual < 0.0 || actual >= current.length as f64 {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "{}.prototype.with: index {relative} is out of range for length {}",
                    view.kind.type_name(),
                    current.length
                ),
            });
        }
        let actual = actual as usize;
        let mut values = Vec::with_capacity(len);
        for index in 0..len {
            values.push(if index == actual {
                value.clone()
            } else if index < current.length {
                self.with_array_buffer_bytes(current.buffer, |bytes| {
                    Self::read_typed_array_element_bytes(&current, bytes, index)
                })??
            } else {
                Value::Undefined
            });
        }
        Ok(Value::Object(
            self.alloc_typed_array_from_values(view.kind, &values)?,
        ))
    }

    /// ES2020 22.2.3.26 step 2 (TypedArray SortCompare without a comparator).
    pub(super) fn typed_array_default_order(left: &Value, right: &Value) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        if let (Value::BigInt(x), Value::BigInt(y)) = (left, right) {
            return bigint_ops::compare(x, y);
        }
        let number = |value: &Value| Self::coerce_to_float(value).unwrap_or(f64::NAN);
        let (x, y) = (number(left), number(right));
        match (x.is_nan(), y.is_nan()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => x.total_cmp(&y),
        }
    }

    pub(super) fn typed_array_copy_within(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (target_id, view) = self.typed_array_receiver_view(receiver, "copyWithin")?;
        let to = self.typed_array_relative_index_arg(module, args, 0, view.length, 0)?;
        let from = self.typed_array_relative_index_arg(module, args, 1, view.length, 0)?;
        let end = self.typed_array_relative_index_arg(module, args, 2, view.length, view.length)?;
        let mut count = end.saturating_sub(from).min(view.length.saturating_sub(to));
        if count > 0 {
            // ES2024 23.2.3.6 step 17: after the coercions, the current
            // length bounds the copy (bd-9vouw.256).
            let view = self
                .typed_array_view_for_object(target_id)?
                .unwrap_or_else(|| view.clone());
            Self::reject_out_of_bounds_typed_array(&view, "copyWithin")?;
            count = count
                .min(view.length.saturating_sub(from))
                .min(view.length.saturating_sub(to));
        }
        if count > 0 {
            let values = self.typed_array_values_in_range(&view, from, from + count)?;
            self.with_array_buffer_bytes_mut(view.buffer, |bytes| {
                for (relative, value) in values.iter().enumerate() {
                    Self::write_typed_array_element_bytes_at_offset(
                        view.kind,
                        view.byte_offset,
                        bytes,
                        to + relative,
                        value,
                    )?;
                }
                Ok(())
            })??;
        }
        Ok(Value::Object(target_id))
    }

    pub(super) fn typed_array_iterator_for_receiver(
        &mut self,
        receiver: Value,
        kind: &'static str,
    ) -> Result<Value, InterpreterError> {
        let (object_id, view) = self.typed_array_receiver_view(receiver, kind)?;
        let kind_name = kind;
        let kind = match kind {
            "entries" => RuntimeTypedArrayIteratorKind::Entries,
            "keys" => RuntimeTypedArrayIteratorKind::Keys,
            "values" => RuntimeTypedArrayIteratorKind::Values,
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "typed-array iterator kind".to_string(),
                    got: kind.to_string(),
                });
            }
        };
        let trace_index = self.start_iteration_trace(IterationKind::ForOf, || {
            format!("typed_array_iterator:{kind_name}|{}", object_id.0)
        });
        if self.iteration_traced(trace_index) {
            let iterable_ref = self.iteration_ref_for_object(object_id);
            self.record_iteration_event(trace_index, |record_id, step_index| {
                make_get_iterator_event(
                    record_id,
                    step_index,
                    IteratorSymbolKind::Iterator,
                    iterable_ref,
                )
            });
        }
        let handle = self.alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
            values: Vec::new(),
            next_index: 0,
            array: None,
            typed_array: Some(RuntimeTypedArrayIterator {
                view,
                kind,
                object: object_id,
            }),
            collection: None,
            iterator_receiver: None,
            next_method: None,
            timers_interval: None,
            done: false,
            closed: false,
            return_called: false,
            trace_index,
        }))?;
        Ok(Value::Iterator(handle))
    }

    pub(super) fn is_buffer_object(&self, object_id: ObjectId) -> bool {
        self.heap.get(object_id.0 as usize).is_some_and(|object| {
            object
                .typed_array
                .as_ref()
                .is_some_and(|view| view.kind == TypedArrayKind::Uint8 && view.is_buffer)
        })
    }

    pub(super) fn buffer_receiver_view(
        &self,
        receiver: Value,
        method_name: &str,
    ) -> Result<(ObjectId, TypedArrayView), InterpreterError> {
        let (object_id, view) = self.typed_array_receiver_view(receiver, method_name)?;
        if view.kind != TypedArrayKind::Uint8 || !self.is_buffer_object(object_id) {
            return Err(InterpreterError::TypeError {
                expected: format!("Buffer receiver for Buffer.prototype.{method_name}"),
                got: view.kind.type_name().to_string(),
            });
        }
        Ok((object_id, view))
    }

    pub(super) fn authenticated_buffer_backing_label(
        &self,
        object_id: ObjectId,
        simultaneous_clones: u64,
    ) -> Result<Label, InterpreterError> {
        let label = self.binary_storage_label_ref(object_id).ok_or_else(|| {
            InterpreterError::InternalError {
                details: format!(
                    "private-branded Buffer object {} has no live ArrayBuffer backing",
                    object_id.0
                ),
            }
        })?;
        self.check_temporary_memory_budget(
            Self::estimate_label_bytes(label).saturating_mul(simultaneous_clones),
        )?;
        Ok(label.clone())
    }

    pub(super) fn rollback_buffer_object_error_publication(
        &mut self,
        heap_checkpoint: usize,
        memory_checkpoint: u64,
        error_prototype_existed: bool,
        type_error_prototype_existed: bool,
        range_error_prototype_existed: bool,
    ) {
        self.pending_exception = None;
        self.pending_exception_label = Label::Public;
        self.rollback_heap_to_len(heap_checkpoint);
        let remove_error =
            !error_prototype_existed && self.builtin_prototypes.contains_key("Error");
        let remove_type_error =
            !type_error_prototype_existed && self.builtin_prototypes.contains_key("TypeError");
        let remove_range_error =
            !range_error_prototype_existed && self.builtin_prototypes.contains_key("RangeError");
        if remove_error || remove_type_error || remove_range_error {
            self.mutate_builtin_prototypes(|prototypes| {
                if remove_error {
                    prototypes.remove("Error");
                }
                if remove_type_error {
                    prototypes.remove("TypeError");
                }
                if remove_range_error {
                    prototypes.remove("RangeError");
                }
            });
        }
        self.estimated_memory_bytes = memory_checkpoint;
    }

    /// Dispatch one source-authenticated Buffer instance observation.
    ///
    /// Lowering's finite-use proof is not trusted here: slot zero must still
    /// resolve to the interpreter's private Buffer brand and a live backing
    /// store. The backing label is published separately because ordinary
    /// HostCall execution joins register labels but cannot see hidden binary
    /// storage provenance.
    pub(super) fn buffer_object_hostcall(
        &mut self,
        capability: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if self.pending_exception.is_some() || self.pending_exception_label != Label::Public {
            return Err(InterpreterError::InternalError {
                details: "Buffer object HostCall entered with a stale pending exception"
                    .to_string(),
            });
        }
        if args.count == 0 {
            return Err(InterpreterError::TypeError {
                expected: "authenticated Buffer receiver in argument slot zero".to_string(),
                got: "missing receiver".to_string(),
            });
        }
        let receiver = self.read_reg(args.start)?;
        let method_name = match capability {
            "builtin:BufferObjectToString" => "toString",
            "builtin:BufferObjectReadUInt32LE" => "readUInt32LE",
            // bd-dign3 follow-up: the runtime equals implementation predates
            // this route; only the static capability string was missing.
            "builtin:BufferObjectEquals" => "equals",
            _ => {
                return Err(InterpreterError::InternalError {
                    details: format!(
                        "unsupported authenticated Buffer object capability {capability}"
                    ),
                });
            }
        };
        let (object_id, _) = self.buffer_receiver_view(receiver.clone(), method_name)?;
        if self.binary_storage_label_ref(object_id).is_none() {
            return Err(InterpreterError::InternalError {
                details: format!(
                    "private-branded Buffer object {} has no live ArrayBuffer backing",
                    object_id.0
                ),
            });
        }
        let method_start =
            args.start
                .checked_add(1)
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "Buffer object method argument range overflows register space"
                        .to_string(),
                })?;
        let method_args = RegRange {
            start: method_start,
            count: args.count - 1,
        };
        let heap_checkpoint = self.heap.len();
        let memory_checkpoint = self.estimated_memory_bytes;
        let error_prototype_existed = self.builtin_prototypes.contains_key("Error");
        let type_error_prototype_existed = self.builtin_prototypes.contains_key("TypeError");
        let range_error_prototype_existed = self.builtin_prototypes.contains_key("RangeError");
        let outcome = match capability {
            "builtin:BufferObjectToString" => self.buffer_to_string(receiver, method_args),
            "builtin:BufferObjectReadUInt32LE" => {
                self.buffer_read_integer(receiver, method_args, BufferIntegerKind::UInt32, true)
            }
            "builtin:BufferObjectEquals" => self.buffer_equals(receiver, method_args),
            _ => unreachable!("authenticated Buffer capability matched above"),
        };
        match outcome {
            Ok(value) => {
                let backing_label = match self.authenticated_buffer_backing_label(object_id, 1) {
                    Ok(label) => label,
                    Err(resource_error) => {
                        self.rollback_buffer_object_error_publication(
                            heap_checkpoint,
                            memory_checkpoint,
                            error_prototype_existed,
                            type_error_prototype_existed,
                            range_error_prototype_existed,
                        );
                        return Err(resource_error);
                    }
                };
                if let Err(resource_error) =
                    self.replace_pending_hostcall_result_label(Some(backing_label))
                {
                    self.rollback_buffer_object_error_publication(
                        heap_checkpoint,
                        memory_checkpoint,
                        error_prototype_existed,
                        type_error_prototype_existed,
                        range_error_prototype_existed,
                    );
                    return Err(resource_error);
                }
                Ok(value)
            }
            Err(error @ InterpreterError::UncaughtException { .. }) => {
                let backing_label = match self.authenticated_buffer_backing_label(object_id, 2) {
                    Ok(label) => label,
                    Err(resource_error) => {
                        self.rollback_buffer_object_error_publication(
                            heap_checkpoint,
                            memory_checkpoint,
                            error_prototype_existed,
                            type_error_prototype_existed,
                            range_error_prototype_existed,
                        );
                        return Err(resource_error);
                    }
                };
                if let Err(resource_error) = self.join_pending_exception_label(&backing_label) {
                    self.rollback_buffer_object_error_publication(
                        heap_checkpoint,
                        memory_checkpoint,
                        error_prototype_existed,
                        type_error_prototype_existed,
                        range_error_prototype_existed,
                    );
                    return Err(resource_error);
                }
                Err(error)
            }
            Err(error) if Self::js_catchable_error_name(&error).is_some() => {
                let backing_label = match self.authenticated_buffer_backing_label(object_id, 1) {
                    Ok(label) => label,
                    Err(resource_error) => {
                        self.rollback_buffer_object_error_publication(
                            heap_checkpoint,
                            memory_checkpoint,
                            error_prototype_existed,
                            type_error_prototype_existed,
                            range_error_prototype_existed,
                        );
                        return Err(resource_error);
                    }
                };
                if let Err(resource_error) =
                    self.replace_pending_hostcall_result_label(Some(backing_label))
                {
                    self.rollback_buffer_object_error_publication(
                        heap_checkpoint,
                        memory_checkpoint,
                        error_prototype_existed,
                        type_error_prototype_existed,
                        range_error_prototype_existed,
                    );
                    return Err(resource_error);
                }
                Err(error)
            }
            Err(error) => {
                self.rollback_buffer_object_error_publication(
                    heap_checkpoint,
                    memory_checkpoint,
                    error_prototype_existed,
                    type_error_prototype_existed,
                    range_error_prototype_existed,
                );
                Err(error)
            }
        }
    }

    pub(super) fn typed_array_view_bytes<'a>(
        &'a self,
        view: &TypedArrayView,
    ) -> Result<&'a [u8], InterpreterError> {
        if view.kind != TypedArrayKind::Uint8 {
            return Err(InterpreterError::TypeError {
                expected: "Uint8Array-backed byte view".to_string(),
                got: view.kind.type_name().to_string(),
            });
        }
        let end = view
            .byte_offset
            .checked_add(view.byte_length)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "Buffer byte range overflows host address space".to_string(),
            })?;
        let object = self
            .heap
            .get(view.buffer.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: view.buffer.0 })?;
        let backing = object
            .array_buffer
            .as_ref()
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "ArrayBuffer backing".to_string(),
                got: "ordinary object".to_string(),
            })?;
        backing
            .bytes
            .get(view.byte_offset..end)
            .ok_or_else(|| InterpreterError::RangeError {
                message: format!(
                    "Buffer byte range {}..{end} exceeds backing length",
                    view.byte_offset
                ),
            })
    }

    pub(super) fn buffer_like_view(
        &self,
        value: &Value,
    ) -> Result<TypedArrayView, InterpreterError> {
        let Value::Object(object_id) = value else {
            return Err(InterpreterError::TypeError {
                expected: "Buffer or Uint8Array".to_string(),
                got: value.type_name().to_string(),
            });
        };
        let view = self
            .typed_array_view_for_object(*object_id)?
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "Buffer or Uint8Array".to_string(),
                got: "ordinary object".to_string(),
            })?;
        if view.kind != TypedArrayKind::Uint8 {
            return Err(InterpreterError::TypeError {
                expected: "Buffer or Uint8Array".to_string(),
                got: view.kind.type_name().to_string(),
            });
        }
        Ok(view)
    }

    pub(super) fn bytes_for_typed_array_view(
        &self,
        view: &TypedArrayView,
    ) -> Result<Vec<u8>, InterpreterError> {
        let bytes = self.typed_array_view_bytes(view)?;
        let temporary_bytes =
            u64::try_from(bytes.len()).map_err(|_| InterpreterError::RangeError {
                message: "Buffer temporary copy exceeds memory accounting range".to_string(),
            })?;
        self.check_temporary_memory_budget(temporary_bytes)?;
        Ok(bytes.to_vec())
    }

    pub(super) fn bytes_for_buffer_like(&self, value: &Value) -> Result<Vec<u8>, InterpreterError> {
        let view = self.buffer_like_view(value)?;
        self.bytes_for_typed_array_view(&view)
    }

    pub(super) fn crypto_binary_view_range(
        &self,
        value: &Value,
        allow_array_buffer: bool,
    ) -> Result<(ObjectId, usize, usize), InterpreterError> {
        let Value::Object(object_id) = value else {
            return Err(InterpreterError::TypeError {
                expected: "ArrayBuffer or an ArrayBuffer view".to_string(),
                got: value.type_name().to_string(),
            });
        };
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let (buffer, byte_offset, byte_length) = if let Some(view) = &object.typed_array {
            (view.buffer, view.byte_offset, view.byte_length)
        } else if let Some(view) = &object.data_view {
            (view.buffer, view.byte_offset, view.byte_length)
        } else if allow_array_buffer && let Some(backing) = &object.array_buffer {
            (*object_id, 0, backing.bytes.len())
        } else {
            return Err(InterpreterError::TypeError {
                expected: if allow_array_buffer {
                    "ArrayBuffer or an ArrayBuffer view".to_string()
                } else {
                    "ArrayBuffer view".to_string()
                },
                got: "ordinary object".to_string(),
            });
        };
        let end =
            byte_offset
                .checked_add(byte_length)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "crypto binary view range overflows host address space".to_string(),
                })?;
        self.with_array_buffer_bytes(buffer, |bytes| {
            if end <= bytes.len() {
                Ok(())
            } else {
                Err(InterpreterError::RangeError {
                    message: format!(
                        "crypto binary view range {byte_offset}..{end} exceeds backing length {}",
                        bytes.len()
                    ),
                })
            }
        })??;
        Ok((buffer, byte_offset, byte_length))
    }

    pub(super) fn copy_crypto_binary_view_range(
        &self,
        buffer: ObjectId,
        byte_offset: usize,
        byte_length: usize,
    ) -> Result<Vec<u8>, InterpreterError> {
        let end =
            byte_offset
                .checked_add(byte_length)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "crypto binary view range overflows host address space".to_string(),
                })?;
        self.with_array_buffer_bytes(buffer, |bytes| {
            bytes
                .get(byte_offset..end)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: format!(
                        "crypto binary view range {byte_offset}..{end} exceeds backing length {}",
                        bytes.len()
                    ),
                })
        })?
    }

    pub(super) fn crypto_binary_view_bytes_with_mode(
        &self,
        value: &Value,
        allow_array_buffer: bool,
    ) -> Result<Vec<u8>, InterpreterError> {
        let (buffer, byte_offset, byte_length) =
            self.crypto_binary_view_range(value, allow_array_buffer)?;
        self.check_temporary_memory_budget(u64::try_from(byte_length).unwrap_or(u64::MAX))?;
        self.copy_crypto_binary_view_range(buffer, byte_offset, byte_length)
    }

    pub(super) fn buffer_encoding(
        &self,
        value: Option<Value>,
        default: &str,
    ) -> Result<String, InterpreterError> {
        match value {
            None | Some(Value::Undefined) => Ok(default.to_string()),
            Some(Value::Str(encoding)) => Ok(encoding.to_ascii_lowercase()),
            Some(other) => Err(InterpreterError::TypeError {
                expected: "a recognized Node BufferEncoding".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// Build and arm a catchable Node-style Buffer error carrying an own
    /// `code` property. Buffer's public API distinguishes several validation
    /// failures by code even when they share the same JavaScript error class.
    pub(super) fn throw_buffer_node_error(
        &mut self,
        name: &str,
        code: &str,
        message: String,
    ) -> InterpreterError {
        let thrown = match self.construct_buffer_node_error(name, code, message) {
            Ok(value) => value,
            Err(err) => return err,
        };
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = Label::Public;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    pub(super) fn construct_buffer_node_error(
        &mut self,
        name: &str,
        code: &str,
        message: String,
    ) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype(name)?;
        let error_id = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_like_object(error_id, name, message)?;
        self.set_object_property(error_id, "code".to_string(), Value::str(code))?;
        Ok(Value::Object(error_id))
    }

    /// bd-9vouw.96: `btoa`/`atob` (the HTML Standard's base64 pair, Node
    /// globals) and ES2020 B.2.1 `escape`/`unescape`, over the argument's
    /// UTF-16 code units. The argument converts as a template substitution
    /// does in Node (`${input}`), so a Symbol is a TypeError, and btoa/atob
    /// without one throw Node's ERR_MISSING_ARGS TypeError.
    pub(super) fn string_codec_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        capability: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count == 0 && matches!(capability, "builtin:Btoa" | "builtin:Atob") {
            return Err(self.throw_buffer_node_error(
                "TypeError",
                "ERR_MISSING_ARGS",
                "The \"input\" argument must be specified".to_string(),
            ));
        }
        if matches!(self.builtin_arg(args, 0)?, Some(Value::Symbol(_))) {
            return Err(InterpreterError::TypeError {
                expected: "a value convertible to a string".to_string(),
                got: "Symbol".to_string(),
            });
        }
        let units: Vec<u16> = if args.count == 0 {
            "undefined".encode_utf16().collect()
        } else {
            match self.primitive_conversion_builtin(module, args, PrimitiveConversion::String)? {
                Value::Str(text) => text.code_units_vec(),
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "string conversion result".to_string(),
                        got: other.type_name().to_string(),
                    });
                }
            }
        };
        let result = match capability {
            "builtin:Btoa" => match base64_encode_latin1(&units) {
                Some(encoded) => encoded,
                None => return Err(self.throw_invalid_character_error("Invalid character")),
            },
            "builtin:Atob" => match forgiving_base64_decode(&units) {
                Ok(decoded) => decoded,
                Err(message) => return Err(self.throw_invalid_character_error(message)),
            },
            "builtin:Escape" => escape_code_units(&units),
            _ => unescape_code_units(&units),
        };
        Ok(Value::Str(JsString::from_code_units(&result)))
    }

    /// Node throws a DOMException named InvalidCharacterError (legacy code
    /// 5) from btoa/atob. This engine has no DOMException, so the thrown
    /// value is an Error with that `name`, Node's message and `code` 5.
    pub(super) fn throw_invalid_character_error(&mut self, message: &str) -> InterpreterError {
        let thrown = (|| -> Result<Value, InterpreterError> {
            let prototype = self.ensure_builtin_prototype("Error")?;
            let error_id = self.alloc_object_with_prototype(Some(prototype))?;
            self.initialize_error_like_object(
                error_id,
                "InvalidCharacterError",
                message.to_string(),
            )?;
            self.set_object_property(error_id, "code".to_string(), Value::Int(5))?;
            Ok(Value::Object(error_id))
        })();
        let thrown = match thrown {
            Ok(value) => value,
            Err(err) => return err,
        };
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = Label::Public;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    pub(super) fn check_buffer_temporary_bytes(
        &self,
        bytes: usize,
    ) -> Result<(), InterpreterError> {
        let bytes = u64::try_from(bytes).map_err(|_| InterpreterError::RangeError {
            message: "Buffer temporary allocation exceeds memory accounting range".to_string(),
        })?;
        self.check_temporary_memory_budget(bytes)
    }

    pub(super) fn decode_buffer_string(
        &self,
        text: &JsString,
        encoding: &str,
    ) -> Result<Vec<u8>, InterpreterError> {
        use base64::Engine as _;

        match encoding {
            "utf8" | "utf-8" => {
                self.check_buffer_temporary_bytes(text.len())?;
                Ok(text.as_bytes().to_vec())
            }
            "ascii" | "latin1" | "binary" => {
                let code_units = text.utf16_len();
                self.check_buffer_temporary_bytes(code_units)?;
                Ok(text
                    .encode_utf16()
                    .map(|unit| unit.to_le_bytes()[0])
                    .collect())
            }
            "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => {
                let byte_length = text.utf16_len().checked_mul(2).ok_or_else(|| {
                    InterpreterError::RangeError {
                        message: "UTF-16LE Buffer input size overflows host address space"
                            .to_string(),
                    }
                })?;
                self.check_buffer_temporary_bytes(byte_length)?;
                let mut decoded = Vec::with_capacity(byte_length);
                for unit in text.encode_utf16() {
                    decoded.extend_from_slice(&unit.to_le_bytes());
                }
                Ok(decoded)
            }
            "hex" => {
                let raw = text.as_bytes();
                self.check_buffer_temporary_bytes(raw.len() / 2)?;
                let mut decoded = Vec::with_capacity(raw.len() / 2);
                for pair in raw.as_chunks::<2>().0 {
                    let Some(high) = qs_hex_digit_value(pair[0]) else {
                        break;
                    };
                    let Some(low) = qs_hex_digit_value(pair[1]) else {
                        break;
                    };
                    decoded.push((high << 4) | low);
                }
                Ok(decoded)
            }
            "base64" | "base64url" => {
                // Node accepts both standard and URL-safe alphabet characters
                // for both names, ignores whitespace/non-alphabet bytes, and
                // tolerates missing padding. Canonicalize to the standard
                // alphabet before using the strict Rust decoder.
                let maximum_temporary = text
                    .len()
                    .checked_mul(2)
                    .and_then(|bytes| bytes.checked_add(3))
                    .ok_or_else(|| InterpreterError::RangeError {
                        message: "base64 Buffer temporary size overflows".to_string(),
                    })?;
                self.check_buffer_temporary_bytes(maximum_temporary)?;
                let mut normalized = Vec::with_capacity(text.len().saturating_add(3));
                for byte in text.bytes() {
                    match byte {
                        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                            normalized.push(byte);
                        }
                        b'-' => normalized.push(b'+'),
                        b'_' => normalized.push(b'/'),
                        b'=' => break,
                        b' ' | b'\t' | b'\r' | b'\n' => {}
                        _ => {}
                    }
                }
                while normalized.len() % 4 == 1 {
                    normalized.pop();
                }
                while normalized.len() % 4 != 0 {
                    normalized.push(b'=');
                }
                let decoded = base64::engine::general_purpose::STANDARD.decode(&normalized);
                decoded.map_err(|_| InterpreterError::TypeError {
                    expected: format!("valid {encoding} Buffer input"),
                    got: Self::crypto_diagnostic_fragment(text),
                })
            }
            _ => Err(InterpreterError::TypeError {
                expected: "a recognized Node BufferEncoding".to_string(),
                got: Self::crypto_diagnostic_fragment(encoding),
            }),
        }
    }

    pub(super) fn encode_buffer_bytes(
        &self,
        bytes: &[u8],
        encoding: &str,
    ) -> Result<JsString, InterpreterError> {
        use base64::Engine as _;

        let may_retain_exact_units = matches!(encoding, "ucs2" | "ucs-2" | "utf16le" | "utf-16le");
        let maximum_output = match encoding {
            "utf8" | "utf-8" => bytes.len().checked_mul(3),
            "ascii" => Some(bytes.len()),
            "latin1" | "binary" | "hex" => bytes.len().checked_mul(2),
            "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => {
                // Decoding may briefly retain the u16 scratch vector, its
                // exact-unit copy, and the lossy UTF-8 projection together.
                bytes.len().checked_mul(4)
            }
            "base64" | "base64url" => bytes
                .len()
                .checked_add(2)
                .map(|length| (length / 3).saturating_mul(4)),
            _ => None,
        }
        .ok_or_else(|| InterpreterError::TypeError {
            expected: "a recognized Node BufferEncoding with bounded output".to_string(),
            got: encoding.to_string(),
        })?;
        let maximum_output = u64::try_from(maximum_output)
            .unwrap_or(u64::MAX)
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(if may_retain_exact_units {
                // A malformed JsString owns a second Arc allocation for its
                // exact UTF-16 units in addition to the UTF-8 projection.
                MEMORY_ESTIMATE_STRING_BASE_BYTES
            } else {
                0
            });
        self.check_temporary_memory_budget(maximum_output)?;

        match encoding {
            "utf8" | "utf-8" => Ok(String::from_utf8_lossy(bytes).into_owned().into()),
            "ascii" => Ok(bytes
                .iter()
                .map(|byte| char::from(*byte & 0x7f))
                .collect::<String>()
                .into()),
            "latin1" | "binary" => Ok(bytes
                .iter()
                .map(|byte| char::from(*byte))
                .collect::<String>()
                .into()),
            "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => {
                let units = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes(*pair))
                    .collect::<Vec<_>>();
                Ok(JsString::from_code_units(&units))
            }
            "hex" => Ok(hex::encode(bytes).into()),
            "base64" => Ok(base64::engine::general_purpose::STANDARD
                .encode(bytes)
                .into()),
            "base64url" => Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(bytes)
                .into()),
            _ => Err(InterpreterError::TypeError {
                expected: "a recognized Node BufferEncoding".to_string(),
                got: encoding.to_string(),
            }),
        }
    }

    pub(super) fn alloc_zeroed_buffer(
        &mut self,
        length: usize,
        live_temporary_bytes: usize,
    ) -> Result<ObjectId, InterpreterError> {
        self.alloc_fresh_buffer_object(length, None, live_temporary_bytes)
    }

    pub(super) fn buffer_numeric_length(
        &self,
        value: &Value,
        argument: &str,
        nan_is_zero: bool,
    ) -> Result<usize, InterpreterError> {
        let number = match value {
            Value::Int(value) => *value as f64,
            Value::Float(value) => value.inner(),
            other => {
                return Err(InterpreterError::TypeError {
                    expected: format!("Buffer {argument} argument of type number"),
                    got: other.type_name().to_string(),
                });
            }
        };
        let number = if number.is_nan() && nan_is_zero {
            0.0
        } else {
            number
        };
        if !number.is_finite() || number < 0.0 {
            return Err(InterpreterError::RangeError {
                message: format!("Buffer {argument} must be a finite non-negative number"),
            });
        }
        let truncated = number.trunc();
        if truncated > MAX_ARRAY_BUFFER_BYTE_LENGTH as f64 {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Buffer {argument} {truncated} exceeds per-buffer cap of {} bytes",
                    MAX_ARRAY_BUFFER_BYTE_LENGTH
                ),
            });
        }
        Ok(truncated as usize)
    }

    pub(super) fn required_buffer_size_arg(
        &self,
        args: RegRange,
    ) -> Result<usize, InterpreterError> {
        let Some(value) = self.builtin_arg(args, 0)? else {
            return Err(InterpreterError::TypeError {
                expected: "Buffer size argument of type number".to_string(),
                got: "undefined".to_string(),
            });
        };
        self.buffer_numeric_length(&value, "size", false)
    }

    pub(super) fn buffer_from(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let source = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        match source {
            Value::Str(text) => {
                let encoding = self.buffer_encoding(self.builtin_arg(args, 1)?, "utf8")?;
                let bytes = self.decode_buffer_string(&text, &encoding)?;
                Ok(Value::Object(self.alloc_buffer_from_bytes(&bytes)?))
            }
            Value::Object(object_id)
                if self
                    .heap
                    .get(object_id.0 as usize)
                    .is_some_and(|object| object.array_buffer.is_some()) =>
            {
                let (byte_offset, byte_length, _, _) = self.typed_array_buffer_view_shape(
                    None,
                    TypedArrayKind::Uint8,
                    object_id,
                    args,
                )?;
                // Node gives the view an explicit length, so over a
                // resizable buffer it is fixed-length (bd-9vouw.256).
                let bounds = self.new_view_bounds(object_id, Some(byte_length))?;
                let view = self.alloc_buffer_view_object(object_id, byte_offset, byte_length)?;
                self.register_buffer_view(view, bounds)?;
                Ok(Value::Object(view))
            }
            Value::Object(object_id) => {
                let bytes = if let Some(view) = self.typed_array_view_for_object(object_id)? {
                    if view.kind == TypedArrayKind::Uint8 {
                        self.bytes_for_typed_array_view(&view)?
                    } else {
                        let values_bytes = view
                            .length
                            .checked_mul(std::mem::size_of::<Value>())
                            .and_then(|bytes| bytes.checked_add(view.length))
                            .ok_or_else(|| InterpreterError::RangeError {
                                message: "Buffer.from typed-array temporary size overflows"
                                    .to_string(),
                            })?;
                        self.check_buffer_temporary_bytes(values_bytes)?;
                        let values = self.typed_array_values_in_range(&view, 0, view.length)?;
                        let bytes = values
                            .iter()
                            .map(|value| {
                                if matches!(value, Value::BigInt(_)) {
                                    Err(InterpreterError::TypeError {
                                        expected: "Buffer element convertible to number"
                                            .to_string(),
                                        got: "bigint".to_string(),
                                    })
                                } else {
                                    Ok(Self::typed_array_u8_value(value))
                                }
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        drop(values);
                        bytes
                    }
                } else {
                    let length = self.array_like_length(object_id)?;
                    self.checked_typed_array_byte_length(TypedArrayKind::Uint8, length)?;
                    self.check_buffer_temporary_bytes(length)?;
                    let mut bytes = Vec::with_capacity(length);
                    for index in 0..length {
                        let value = self
                            .array_index_value(object_id, index)?
                            .unwrap_or(Value::Undefined);
                        if matches!(value, Value::BigInt(_)) {
                            return Err(InterpreterError::TypeError {
                                expected: "Buffer element convertible to number".to_string(),
                                got: "bigint".to_string(),
                            });
                        }
                        bytes.push(Self::typed_array_u8_value(&value));
                    }
                    bytes
                };
                Ok(Value::Object(self.alloc_buffer_from_bytes(&bytes)?))
            }
            other => Err(InterpreterError::TypeError {
                expected: "string, ArrayBuffer, Buffer, Uint8Array, or array-like Buffer source"
                    .to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn buffer_alloc(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let length = match self.required_buffer_size_arg(args) {
            Ok(length) => length,
            Err(InterpreterError::RangeError { message }) => {
                return Err(self.throw_buffer_node_error(
                    "RangeError",
                    "ERR_OUT_OF_RANGE",
                    message,
                ));
            }
            Err(err) => return Err(err),
        };
        let fill = self.builtin_arg(args, 1)?;
        let pattern = if length == 0 {
            None
        } else {
            match fill {
                None | Some(Value::Undefined) => None,
                Some(Value::Str(text)) => {
                    let encoding = self.buffer_encoding(self.builtin_arg(args, 2)?, "utf8")?;
                    Some(self.decode_buffer_string(&text, &encoding)?)
                }
                Some(fill @ Value::Object(_)) => Some(self.bytes_for_buffer_like(&fill)?),
                Some(Value::BigInt(_)) => {
                    return Err(InterpreterError::TypeError {
                        expected: "Buffer fill value convertible to number".to_string(),
                        got: "bigint".to_string(),
                    });
                }
                Some(other) => {
                    self.check_buffer_temporary_bytes(1)?;
                    Some(vec![Self::typed_array_u8_value(&other)])
                }
            }
        };
        let temporary_bytes = pattern.as_ref().map_or(0, Vec::len);
        let view_id = self.alloc_zeroed_buffer(length, temporary_bytes)?;
        let Some(pattern) = pattern.filter(|pattern| !pattern.is_empty()) else {
            return Ok(Value::Object(view_id));
        };
        let view = self.typed_array_view_for_object(view_id)?.ok_or_else(|| {
            InterpreterError::TypeError {
                expected: "newly allocated Buffer".to_string(),
                got: "ordinary object".to_string(),
            }
        })?;
        self.with_array_buffer_bytes_mut(view.buffer, |bytes| {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = pattern[index % pattern.len()];
            }
        })?;
        Ok(Value::Object(view_id))
    }

    pub(super) fn buffer_byte_length(&self, args: RegRange) -> Result<Value, InterpreterError> {
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let length = match value {
            Value::Str(text) => {
                let encoding = match self.builtin_arg(args, 1)? {
                    Some(Value::Str(encoding)) => encoding.to_ascii_lowercase(),
                    _ => "utf8".to_string(),
                };
                match encoding.as_str() {
                    "utf8" | "utf-8" => text.len(),
                    "ascii" | "latin1" | "binary" => text.utf16_len(),
                    "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => text
                        .utf16_len()
                        .checked_mul(2)
                        .ok_or_else(|| InterpreterError::RangeError {
                            message: "UTF-16LE Buffer byte length overflows host address space"
                                .to_string(),
                        })?,
                    "hex" => text.len() / 2,
                    "base64" | "base64url" => {
                        // Node intentionally returns an encoded-length estimate
                        // here instead of fully decoding/validating the input.
                        // Strip only terminal padding; embedded padding and
                        // ignored characters still contribute to the estimate.
                        let mut encoded_len = text.len();
                        if text.as_bytes().get(encoded_len.wrapping_sub(1)) == Some(&b'=') {
                            encoded_len -= 1;
                        }
                        if text.as_bytes().get(encoded_len.wrapping_sub(1)) == Some(&b'=') {
                            encoded_len -= 1;
                        }
                        encoded_len.saturating_mul(3) / 4
                    }
                    _ => text.len(),
                }
            }
            Value::Object(object_id) => {
                let object = self
                    .heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                if let Some(backing) = &object.array_buffer {
                    backing.byte_length()
                } else if let Some(view) = &object.typed_array {
                    view.byte_length
                } else if let Some(view) = &object.data_view {
                    view.byte_length
                } else {
                    return Err(InterpreterError::TypeError {
                        expected: "string, Buffer, ArrayBuffer, TypedArray, or DataView"
                            .to_string(),
                        got: "ordinary object".to_string(),
                    });
                }
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "string, Buffer, ArrayBuffer, TypedArray, or DataView".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        Ok(Value::Int(i64::try_from(length).unwrap_or(i64::MAX)))
    }

    pub(super) fn buffer_concat(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let list = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let Value::Object(list_id) = list else {
            return Err(InterpreterError::TypeError {
                expected: "array-like list of Buffer or Uint8Array values".to_string(),
                got: list.type_name().to_string(),
            });
        };
        let list_length = self.array_like_length(list_id)?;
        let mut natural_length = 0usize;
        for index in 0..list_length {
            let value = self
                .array_index_value(list_id, index)?
                .unwrap_or(Value::Undefined);
            let view = self.buffer_like_view(&value)?;
            natural_length = natural_length
                .checked_add(view.byte_length)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Buffer.concat total length overflows host address space".to_string(),
                })?;
        }
        let output_length = match self.builtin_arg(args, 1)? {
            None | Some(Value::Undefined) => natural_length,
            Some(value) => self.buffer_numeric_length(&value, "totalLength", true)?,
        };
        self.checked_typed_array_byte_length(TypedArrayKind::Uint8, output_length)?;
        self.check_buffer_temporary_bytes(output_length)?;
        let mut output = Vec::with_capacity(output_length);
        for index in 0..list_length {
            let value = self
                .array_index_value(list_id, index)?
                .unwrap_or(Value::Undefined);
            let view = self.buffer_like_view(&value)?;
            let chunk = self.typed_array_view_bytes(&view)?;
            let remaining = output_length.saturating_sub(output.len());
            output.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
            if output.len() == output_length {
                break;
            }
        }
        output.resize(output_length, 0);
        Ok(Value::Object(self.alloc_buffer_from_bytes(&output)?))
    }

    pub(super) fn compare_buffer_bytes(left: &[u8], right: &[u8]) -> i64 {
        match left.cmp(right) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    pub(super) fn buffer_static_compare(&self, args: RegRange) -> Result<Value, InterpreterError> {
        let left = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let right = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let left_view = self.buffer_like_view(&left)?;
        let right_view = self.buffer_like_view(&right)?;
        let left = self.typed_array_view_bytes(&left_view)?;
        let right = self.typed_array_view_bytes(&right_view)?;
        Ok(Value::Int(Self::compare_buffer_bytes(left, right)))
    }

    pub(super) fn buffer_is_buffer_builtin(
        &self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        Ok(Value::Bool(
            matches!(value, Value::Object(id) if self.is_buffer_object(id)),
        ))
    }

    /// Node's `Buffer.isEncoding(encoding)` (bd-9vouw.308): whether
    /// `encoding` is a string naming one of Buffer's encodings, ignoring case.
    pub(super) fn buffer_is_encoding_builtin(
        &self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let Value::Str(name) = value else {
            return Ok(Value::Bool(false));
        };
        let known = name.as_str().is_some_and(|name| {
            [
                "utf8",
                "utf-8",
                "ucs2",
                "ucs-2",
                "utf16le",
                "utf-16le",
                "latin1",
                "binary",
                "base64",
                "base64url",
                "hex",
                "ascii",
            ]
            .iter()
            .any(|encoding| encoding.eq_ignore_ascii_case(name))
        });
        Ok(Value::Bool(known))
    }

    pub(super) fn buffer_to_string(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (_, view) = self.buffer_receiver_view(receiver, "toString")?;
        let start = self.buffer_clamped_bound_arg(args, 1, view.length, 0)?;
        let end = self.buffer_clamped_bound_arg(args, 2, view.length, view.length)?;
        if start >= end {
            return Ok(Value::str(""));
        }
        let encoding = match self.builtin_arg(args, 0)? {
            None | Some(Value::Undefined) => "utf8".to_string(),
            Some(value) => self.value_to_string(&value).to_ascii_lowercase(),
        };
        let bytes = self.typed_array_view_bytes(&view)?;
        let text = match self.encode_buffer_bytes(&bytes[start..end], &encoding) {
            Ok(text) => text,
            Err(InterpreterError::TypeError { .. }) => {
                return Err(self.throw_buffer_node_error(
                    "TypeError",
                    "ERR_UNKNOWN_ENCODING",
                    format!("Unknown encoding: {encoding}"),
                ));
            }
            Err(err) => return Err(err),
        };
        Ok(Value::str(text))
    }

    pub(super) fn buffer_clamped_bound_arg(
        &self,
        args: RegRange,
        offset: u32,
        length: usize,
        default: usize,
    ) -> Result<usize, InterpreterError> {
        let Some(value) = self.builtin_arg(args, offset)? else {
            return Ok(default);
        };
        if matches!(value, Value::Undefined) {
            return Ok(default);
        }
        let bound = Self::value_as_integer(&value);
        if bound <= 0 {
            return Ok(0);
        }
        Ok(usize::try_from(bound).unwrap_or(usize::MAX).min(length))
    }

    pub(super) fn buffer_shared_slice(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (_, view) = self.buffer_receiver_view(receiver, "slice")?;
        let (start, end) = self.typed_array_method_range(module, args, 0, 1, view.length)?;
        let length = end.saturating_sub(start);
        let byte_offset =
            view.byte_offset
                .checked_add(start)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Buffer slice byteOffset overflows host address space".to_string(),
                })?;
        Ok(Value::Object(self.alloc_buffer_view_object(
            view.buffer,
            byte_offset,
            length,
        )?))
    }

    pub(super) fn buffer_search_needle(
        &self,
        value: Value,
        encoding: Option<Value>,
    ) -> Result<(Vec<u8>, bool), InterpreterError> {
        match value {
            Value::Str(text) => {
                let encoding = self.buffer_encoding(encoding, "utf8")?;
                let is_utf16le =
                    matches!(encoding.as_str(), "ucs2" | "ucs-2" | "utf16le" | "utf-16le");
                self.decode_buffer_string(&text, &encoding)
                    .map(|needle| (needle, is_utf16le))
            }
            Value::Int(_) | Value::Float(_) => {
                self.check_buffer_temporary_bytes(1)?;
                Ok((vec![Self::typed_array_u8_value(&value)], false))
            }
            Value::Object(_) => self
                .bytes_for_buffer_like(&value)
                .map(|needle| (needle, false)),
            other => Err(InterpreterError::TypeError {
                expected: "string, number, Buffer, or Uint8Array search value".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn buffer_index_of(
        &self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (_, view) = self.buffer_receiver_view(receiver, "indexOf")?;
        let needle_value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let second = self.builtin_arg(args, 1)?;
        let (offset, encoding) = match second {
            Some(encoding @ Value::Str(_)) => (None, Some(encoding)),
            offset => (offset, self.builtin_arg(args, 2)?),
        };
        let (needle, is_utf16le_string) = self.buffer_search_needle(needle_value, encoding)?;
        // Node's string-search binding rounds an odd UCS-2 haystack length
        // down before normalizing byteOffset and then searches u16 units from
        // floor(byteOffset / 2). Buffer needles use a separate binding and do
        // not take this path.
        let search_length = if is_utf16le_string {
            view.length & !1
        } else {
            view.length
        };
        let start = match offset {
            None | Some(Value::Undefined) => 0,
            Some(value) => {
                Self::clamp_relative_index(Self::value_as_integer(&value), search_length)
            }
        };
        let bytes = self.typed_array_view_bytes(&view)?;
        if needle.is_empty() {
            return Ok(Value::Int(i64::try_from(start).unwrap_or(i64::MAX)));
        }
        let found = if is_utf16le_string {
            start
                .checked_add(needle.len())
                .filter(|end| *end <= search_length)
                .and_then(|_| {
                    let haystack_units = bytes[..search_length].as_chunks::<2>().0;
                    let needle_units = needle.as_chunks::<2>().0;
                    let unit_start = start / 2;
                    haystack_units
                        .get(unit_start..)
                        .and_then(|remaining| {
                            remaining
                                .windows(needle_units.len())
                                .position(|window| window == needle_units)
                        })
                        .and_then(|relative| unit_start.checked_add(relative))
                        .and_then(|unit_index| unit_index.checked_mul(2))
                })
        } else {
            bytes
                .get(start..)
                .and_then(|remaining| {
                    remaining
                        .windows(needle.len())
                        .position(|window| window == needle)
                })
                .and_then(|relative| start.checked_add(relative))
        }
        .and_then(|index| i64::try_from(index).ok())
        .unwrap_or(-1);
        Ok(Value::Int(found))
    }

    pub(super) fn buffer_includes(
        &self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let result = self.buffer_index_of(receiver, args)?;
        Ok(Value::Bool(
            matches!(result, Value::Int(index) if index >= 0),
        ))
    }

    pub(super) fn buffer_equals(
        &self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (_, view) = self.buffer_receiver_view(receiver, "equals")?;
        let target = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let target_view = self.buffer_like_view(&target)?;
        let left = self.typed_array_view_bytes(&view)?;
        let right = self.typed_array_view_bytes(&target_view)?;
        Ok(Value::Bool(left == right))
    }

    pub(super) fn buffer_compare_method(
        &self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (_, view) = self.buffer_receiver_view(receiver, "compare")?;
        let target = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let target_view = self.buffer_like_view(&target)?;
        let target_start =
            self.buffer_compare_bound_arg(args, 1, target_view.length, 0, "targetStart")?;
        let target_end = self.buffer_compare_bound_arg(
            args,
            2,
            target_view.length,
            target_view.length,
            "targetEnd",
        )?;
        let source_start = self.buffer_compare_bound_arg(args, 3, view.length, 0, "sourceStart")?;
        let source_end =
            self.buffer_compare_bound_arg(args, 4, view.length, view.length, "sourceEnd")?;
        let source = self.typed_array_view_bytes(&view)?;
        let target = self.typed_array_view_bytes(&target_view)?;
        Ok(Value::Int(Self::compare_buffer_bytes(
            &source[source_start..source_end.max(source_start)],
            &target[target_start..target_end.max(target_start)],
        )))
    }

    pub(super) fn buffer_compare_bound_arg(
        &self,
        args: RegRange,
        offset: u32,
        length: usize,
        default: usize,
        field: &str,
    ) -> Result<usize, InterpreterError> {
        let Some(value) = self.builtin_arg(args, offset)? else {
            return Ok(default);
        };
        if matches!(value, Value::Undefined) {
            return Ok(default);
        }
        let bound = self.buffer_numeric_length(&value, field, true)?;
        if bound > length {
            return Err(InterpreterError::RangeError {
                message: format!("Buffer.compare {field} {bound} exceeds length {length}"),
            });
        }
        Ok(bound)
    }

    pub(super) fn buffer_integer_offset(
        &self,
        args: RegRange,
        offset: u32,
    ) -> Result<usize, InterpreterError> {
        let value = match self.builtin_arg(args, offset)? {
            None | Some(Value::Undefined) => Value::Int(0),
            Some(value) => value,
        };
        self.typed_array_index_from_value(TypedArrayKind::Uint8, "offset", &value)
    }

    pub(super) fn buffer_read_integer_offset(
        &mut self,
        args: RegRange,
        view: &TypedArrayView,
        width: usize,
    ) -> Result<usize, InterpreterError> {
        self.buffer_offset_arg(args, 0, view, width)
    }

    /// Node's `offset` argument at `index` of a `width`-byte access: an
    /// integer from 0 to the view's length minus `width` (undefined is 0).
    pub(super) fn buffer_offset_arg(
        &mut self,
        args: RegRange,
        index: u32,
        view: &TypedArrayView,
        width: usize,
    ) -> Result<usize, InterpreterError> {
        let value = match self.builtin_arg(args, index)? {
            None | Some(Value::Undefined) => Value::Int(0),
            Some(value) => value,
        };
        let number = match &value {
            Value::Int(value) => *value as f64,
            Value::Float(value) => value.inner(),
            other => {
                return Err(self.throw_buffer_node_error(
                    "TypeError",
                    "ERR_INVALID_ARG_TYPE",
                    format!(
                        "The \"offset\" argument must be of type number. Received type {}",
                        other.type_name()
                    ),
                ));
            }
        };
        if number.is_nan() || (number.is_finite() && number.fract() != 0.0) {
            return Err(self.throw_buffer_node_error(
                "RangeError",
                "ERR_OUT_OF_RANGE",
                format!("The value of \"offset\" is out of range. Received {number}"),
            ));
        }
        if view.byte_length < width {
            return Err(self.throw_buffer_node_error(
                "RangeError",
                "ERR_BUFFER_OUT_OF_BOUNDS",
                "Attempt to access memory outside buffer bounds".to_string(),
            ));
        }
        let maximum = view.byte_length - width;
        if !number.is_finite() || number < 0.0 || number > maximum as f64 {
            return Err(self.throw_buffer_node_error(
                "RangeError",
                "ERR_OUT_OF_RANGE",
                format!(
                    "The value of \"offset\" is out of range. It must be >= 0 and <= {maximum}. Received {number}"
                ),
            ));
        }
        Ok(number as usize)
    }

    pub(super) fn buffer_integer_range(
        &self,
        view: &TypedArrayView,
        offset: usize,
        width: usize,
    ) -> Result<std::ops::Range<usize>, InterpreterError> {
        let relative_end =
            offset
                .checked_add(width)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Buffer integer access range overflows host address space".to_string(),
                })?;
        if relative_end > view.byte_length {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Buffer integer access at offset {offset} with width {width} exceeds length {}",
                    view.byte_length
                ),
            });
        }
        let start =
            view.byte_offset
                .checked_add(offset)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Buffer integer access absolute offset overflows host address space"
                        .to_string(),
                })?;
        let end = start
            .checked_add(width)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "Buffer integer access absolute range overflows host address space"
                    .to_string(),
            })?;
        Ok(start..end)
    }

    pub(super) fn buffer_read_integer(
        &mut self,
        receiver: Value,
        args: RegRange,
        kind: BufferIntegerKind,
        little_endian: bool,
    ) -> Result<Value, InterpreterError> {
        let (_, view) = self.buffer_receiver_view(receiver, "read integer")?;
        let width = kind.byte_width();
        let offset = self.buffer_read_integer_offset(args, &view, width)?;
        let range = self.buffer_integer_range(&view, offset, width)?;
        self.with_array_buffer_bytes(view.buffer, |bytes| {
            let slot = bytes
                .get(range)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Buffer integer read exceeds backing storage".to_string(),
                })?;
            let value = match kind {
                BufferIntegerKind::UInt8 => i64::from(slot[0]),
                BufferIntegerKind::UInt16 => {
                    let raw = [slot[0], slot[1]];
                    i64::from(if little_endian {
                        u16::from_le_bytes(raw)
                    } else {
                        u16::from_be_bytes(raw)
                    })
                }
                BufferIntegerKind::Int32 => {
                    let raw = [slot[0], slot[1], slot[2], slot[3]];
                    i64::from(if little_endian {
                        i32::from_le_bytes(raw)
                    } else {
                        i32::from_be_bytes(raw)
                    })
                }
                BufferIntegerKind::UInt32 => {
                    let raw = [slot[0], slot[1], slot[2], slot[3]];
                    i64::from(if little_endian {
                        u32::from_le_bytes(raw)
                    } else {
                        u32::from_be_bytes(raw)
                    })
                }
            };
            Ok(Value::Int(value))
        })?
    }

    pub(super) fn buffer_write_integer(
        &mut self,
        receiver: Value,
        args: RegRange,
        kind: BufferIntegerKind,
        little_endian: bool,
    ) -> Result<Value, InterpreterError> {
        let (_, view) = self.buffer_receiver_view(receiver, "write integer")?;
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        if matches!(value, Value::BigInt(_)) {
            return Err(InterpreterError::TypeError {
                expected: "Buffer integer write value convertible to number".to_string(),
                got: "bigint".to_string(),
            });
        }
        let numeric = Self::coerce_to_float(&value).unwrap_or(f64::NAN);
        if numeric.is_infinite() {
            return Err(InterpreterError::RangeError {
                message: "Buffer integer write value is outside the method range".to_string(),
            });
        }
        // Node applies ToNumber followed by integer truncation before the
        // method-specific range check. NaN (including undefined) becomes 0.
        let number = Self::f64_as_integer(numeric);
        let (encoded, width) = match kind {
            BufferIntegerKind::UInt8 => {
                let number = u8::try_from(number).map_err(|_| InterpreterError::RangeError {
                    message: "Buffer writeUInt8 value must be between 0 and 255".to_string(),
                })?;
                ([number, 0, 0, 0], 1)
            }
            BufferIntegerKind::UInt16 => {
                let number = u16::try_from(number).map_err(|_| InterpreterError::RangeError {
                    message: "Buffer writeUInt16 value must be between 0 and 65535".to_string(),
                })?;
                let raw = if little_endian {
                    number.to_le_bytes()
                } else {
                    number.to_be_bytes()
                };
                ([raw[0], raw[1], 0, 0], 2)
            }
            BufferIntegerKind::Int32 => {
                let number = i32::try_from(number).map_err(|_| InterpreterError::RangeError {
                    message: "Buffer writeInt32 value is outside the signed 32-bit range"
                        .to_string(),
                })?;
                let raw = if little_endian {
                    number.to_le_bytes()
                } else {
                    number.to_be_bytes()
                };
                (raw, 4)
            }
            BufferIntegerKind::UInt32 => {
                let number = u32::try_from(number).map_err(|_| InterpreterError::RangeError {
                    message: "Buffer writeUInt32 value is outside the unsigned 32-bit range"
                        .to_string(),
                })?;
                let raw = if little_endian {
                    number.to_le_bytes()
                } else {
                    number.to_be_bytes()
                };
                (raw, 4)
            }
        };
        let offset = self.buffer_integer_offset(args, 1)?;
        let range = self.buffer_integer_range(&view, offset, width)?;
        self.with_array_buffer_bytes_mut(view.buffer, |bytes| {
            let slot = bytes
                .get_mut(range)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Buffer integer write exceeds backing storage".to_string(),
                })?;
            slot.copy_from_slice(&encoded[..width]);
            Ok(())
        })??;
        let next_offset = offset.saturating_add(width);
        Ok(Value::Int(i64::try_from(next_offset).unwrap_or(i64::MAX)))
    }

    /// Node's `Buffer.prototype` numeric accessors that the dedicated kinds
    /// do not serve, and `write(string)` (bd-9vouw.437). A read takes
    /// `(offset)` (`(offset, byteLength)` for the variable-width family) and
    /// returns the value; a write takes `(value, offset)` (`(value, offset,
    /// byteLength)`) and returns the offset after the bytes it wrote.
    pub(super) fn buffer_numeric_method(
        &mut self,
        receiver: Value,
        args: RegRange,
        name: &str,
    ) -> Result<Value, InterpreterError> {
        if name == "write" {
            return self.buffer_write_string(receiver, args);
        }
        let Some((write, format, little_endian)) = BufferNumberFormat::parse(name) else {
            return Err(InterpreterError::TypeError {
                expected: "Buffer numeric accessor".to_string(),
                got: name.to_string(),
            });
        };
        let (_, view) = self.buffer_receiver_view(receiver, name)?;
        let width = match format {
            BufferNumberFormat::Int { width, .. } => width,
            BufferNumberFormat::Variable { .. } => {
                self.buffer_byte_length_arg(args, if write { 2 } else { 1 })?
            }
            BufferNumberFormat::Float32 => 4,
            BufferNumberFormat::Float64 | BufferNumberFormat::BigInt64 { .. } => 8,
        };
        if write {
            let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
            let mut bytes = self.buffer_numeric_bytes(format, width, value)?;
            if !little_endian {
                bytes[..width].reverse();
            }
            let offset = self.buffer_offset_arg(args, 1, &view, width)?;
            let range = self.buffer_integer_range(&view, offset, width)?;
            self.with_array_buffer_bytes_mut(view.buffer, |storage| {
                let slot = storage
                    .get_mut(range)
                    .ok_or_else(|| InterpreterError::RangeError {
                        message: "Buffer write exceeds backing storage".to_string(),
                    })?;
                slot.copy_from_slice(&bytes[..width]);
                Ok(())
            })??;
            return Ok(Value::Int(
                i64::try_from(offset.saturating_add(width)).unwrap_or(i64::MAX),
            ));
        }
        let offset = self.buffer_offset_arg(args, 0, &view, width)?;
        let range = self.buffer_integer_range(&view, offset, width)?;
        let mut bytes = self.with_array_buffer_bytes(view.buffer, |storage| {
            let slot = storage
                .get(range)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Buffer read exceeds backing storage".to_string(),
                })?;
            let mut bytes = [0u8; 8];
            bytes[..width].copy_from_slice(slot);
            Ok::<[u8; 8], InterpreterError>(bytes)
        })??;
        if !little_endian {
            bytes[..width].reverse();
        }
        Ok(format.decode(bytes, width))
    }

    /// The `byteLength` argument of the variable-width accessors: an integer
    /// from 1 to 6.
    pub(super) fn buffer_byte_length_arg(
        &mut self,
        args: RegRange,
        index: u32,
    ) -> Result<usize, InterpreterError> {
        let value = self.builtin_arg(args, index)?.unwrap_or(Value::Undefined);
        let number = match &value {
            Value::Int(value) => *value as f64,
            Value::Float(value) => value.inner(),
            other => {
                return Err(self.throw_buffer_node_error(
                    "TypeError",
                    "ERR_INVALID_ARG_TYPE",
                    format!(
                        "The \"byteLength\" argument must be of type number. Received {}",
                        if matches!(other, Value::Undefined) {
                            "undefined".to_string()
                        } else {
                            format!("type {}", other.type_name())
                        }
                    ),
                ));
            }
        };
        if number.fract() != 0.0 || !(1.0..=6.0).contains(&number) {
            return Err(self.throw_buffer_node_error(
                "RangeError",
                "ERR_OUT_OF_RANGE",
                format!(
                    "The value of \"byteLength\" is out of range. It must be >= 1 and <= 6. Received {}",
                    node_out_of_range_received(number)
                ),
            ));
        }
        Ok(number as usize)
    }

    /// The `width` little-endian bytes a numeric write stores for `value`,
    /// after Node's range check (an integer format takes a Number, a
    /// BigInt64 format a BigInt).
    pub(super) fn buffer_numeric_bytes(
        &mut self,
        format: BufferNumberFormat,
        width: usize,
        value: Value,
    ) -> Result<[u8; 8], InterpreterError> {
        match format {
            BufferNumberFormat::Int { signed, .. } | BufferNumberFormat::Variable { signed } => {
                if matches!(value, Value::BigInt(_)) {
                    return Err(self.throw_js_error(
                        "TypeError",
                        "Cannot mix BigInt and other types, use explicit conversions".to_string(),
                    ));
                }
                let number = Self::coerce_to_float(&value).unwrap_or(f64::NAN);
                let bits = (width * 8) as i32;
                let (minimum, maximum) = if signed {
                    (-(2f64.powi(bits - 1)), 2f64.powi(bits - 1) - 1.0)
                } else {
                    (0.0, 2f64.powi(bits) - 1.0)
                };
                if number < minimum || number > maximum {
                    let bounds = if width > 4 {
                        if signed {
                            format!(">= -(2 ** {}) and < 2 ** {}", bits - 1, bits - 1)
                        } else {
                            format!(">= 0 and < 2 ** {bits}")
                        }
                    } else {
                        format!(">= {minimum} and <= {maximum}")
                    };
                    return Err(self.throw_buffer_node_error(
                        "RangeError",
                        "ERR_OUT_OF_RANGE",
                        format!(
                            "The value of \"value\" is out of range. It must be {bounds}. Received {}",
                            node_out_of_range_received(number)
                        ),
                    ));
                }
                let integer = if number.is_nan() {
                    0
                } else {
                    number.trunc() as i64
                };
                Ok((integer as u64).to_le_bytes())
            }
            BufferNumberFormat::Float32 => {
                Ok(u64::from((Self::typed_array_number(&value) as f32).to_bits()).to_le_bytes())
            }
            BufferNumberFormat::Float64 => {
                Ok(Self::typed_array_number(&value).to_bits().to_le_bytes())
            }
            BufferNumberFormat::BigInt64 { signed } => {
                // Node mixes the value into BigInt arithmetic.
                let Value::BigInt(digits) = &value else {
                    return Err(self.throw_js_error(
                        "TypeError",
                        "Cannot mix BigInt and other types, use explicit conversions".to_string(),
                    ));
                };
                let parsed = digits.parse::<i128>().ok();
                let in_range = parsed.is_some_and(|parsed| {
                    if signed {
                        i64::try_from(parsed).is_ok()
                    } else {
                        u64::try_from(parsed).is_ok()
                    }
                });
                let Some(parsed) = parsed.filter(|_| in_range) else {
                    let bounds = if signed {
                        ">= -(2n ** 63n) and < 2n ** 63n"
                    } else {
                        ">= 0n and < 2n ** 64n"
                    };
                    let large = parsed.is_none_or(|parsed| parsed.unsigned_abs() > 1u128 << 32);
                    let received = if large {
                        group_decimal_digits(digits)
                    } else {
                        digits.to_string()
                    };
                    return Err(self.throw_buffer_node_error(
                        "RangeError",
                        "ERR_OUT_OF_RANGE",
                        format!(
                            "The value of \"value\" is out of range. It must be {bounds}. Received {received}n"
                        ),
                    ));
                };
                Ok((parsed as u64).to_le_bytes())
            }
        }
    }

    /// `buf.write(string[, offset[, length]][, encoding])`: the string's
    /// bytes in `encoding` (utf8 by default) copied in at `offset`, at most
    /// `length` of them and never a partial character; returns the count.
    pub(super) fn buffer_write_string(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (_, view) = self.buffer_receiver_view(receiver, "write")?;
        let Some(Value::Str(text)) = self.builtin_arg(args, 0)? else {
            return Err(self.throw_buffer_node_error(
                "TypeError",
                "ERR_INVALID_ARG_TYPE",
                "The \"string\" argument must be of type string".to_string(),
            ));
        };
        let length = view.byte_length;
        let mut encoding = "utf8".to_string();
        let mut offset = 0usize;
        let mut count = length;
        match self.builtin_arg(args, 1)? {
            None | Some(Value::Undefined) => {}
            Some(Value::Str(name)) => encoding = name.to_string(),
            Some(_) => {
                offset = self.buffer_integer_offset(args, 1)?;
                if offset > length {
                    return Err(self.throw_buffer_node_error(
                        "RangeError",
                        "ERR_OUT_OF_RANGE",
                        format!(
                            "The value of \"offset\" is out of range. It must be >= 0 && <= {length}. Received {offset}"
                        ),
                    ));
                }
                count = length - offset;
                match self.builtin_arg(args, 2)? {
                    None | Some(Value::Undefined) => {}
                    Some(Value::Str(name)) => encoding = name.to_string(),
                    Some(_) => {
                        count = count.min(self.buffer_integer_offset(args, 2)?);
                        if let Some(Value::Str(name)) = self.builtin_arg(args, 3)? {
                            encoding = name.to_string();
                        }
                    }
                }
            }
        }
        let encoding = encoding.to_ascii_lowercase();
        let bytes = self.decode_buffer_string(&text, &encoding)?;
        let mut written = bytes.len().min(count);
        // Node writes whole characters only.
        if written < bytes.len() {
            match encoding.as_str() {
                "utf8" | "utf-8" => {
                    while written > 0 && bytes[written] & 0xc0 == 0x80 {
                        written -= 1;
                    }
                }
                "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => written -= written % 2,
                _ => {}
            }
        }
        let start =
            view.byte_offset
                .checked_add(offset)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Buffer write offset overflows host address space".to_string(),
                })?;
        self.with_array_buffer_bytes_mut(view.buffer, |storage| {
            let slot = storage.get_mut(start..start + written).ok_or_else(|| {
                InterpreterError::RangeError {
                    message: "Buffer write exceeds backing storage".to_string(),
                }
            })?;
            slot.copy_from_slice(&bytes[..written]);
            Ok(())
        })??;
        Ok(Value::Int(i64::try_from(written).unwrap_or(i64::MAX)))
    }

    pub(super) fn buffer_copy(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (_, source_view) = self.buffer_receiver_view(receiver, "copy")?;
        let target = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let Value::Object(target_id) = target else {
            return Err(InterpreterError::TypeError {
                expected: "Buffer or Uint8Array copy target".to_string(),
                got: target.type_name().to_string(),
            });
        };
        let target_view = self
            .typed_array_view_for_object(target_id)?
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "Buffer or Uint8Array copy target".to_string(),
                got: "ordinary object".to_string(),
            })?;
        if target_view.kind != TypedArrayKind::Uint8 {
            return Err(InterpreterError::TypeError {
                expected: "Buffer or Uint8Array copy target".to_string(),
                got: target_view.kind.type_name().to_string(),
            });
        }
        let target_start = self.buffer_copy_bound_arg(args, 1, target_view.length, 0)?;
        let source_start = self.buffer_copy_source_start_arg(args, 2, source_view.length)?;
        let source_end =
            self.buffer_copy_bound_arg(args, 3, source_view.length, source_view.length)?;
        let count = source_end
            .saturating_sub(source_start)
            .min(target_view.length.saturating_sub(target_start));
        self.check_buffer_temporary_bytes(count)?;
        let copy =
            self.typed_array_view_bytes(&source_view)?[source_start..source_start + count].to_vec();
        let target_offset = target_view
            .byte_offset
            .checked_add(target_start)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "Buffer copy target offset overflows host address space".to_string(),
            })?;
        self.with_array_buffer_bytes_mut(target_view.buffer, |bytes| {
            let end = target_offset.checked_add(copy.len()).ok_or_else(|| {
                InterpreterError::RangeError {
                    message: "Buffer copy target range overflows host address space".to_string(),
                }
            })?;
            let target =
                bytes
                    .get_mut(target_offset..end)
                    .ok_or_else(|| InterpreterError::RangeError {
                        message: "Buffer copy target range exceeds backing storage".to_string(),
                    })?;
            target.copy_from_slice(&copy);
            Ok(())
        })??;
        Ok(Value::Int(i64::try_from(count).unwrap_or(i64::MAX)))
    }

    pub(super) fn buffer_copy_bound_arg(
        &self,
        args: RegRange,
        offset: u32,
        length: usize,
        default: usize,
    ) -> Result<usize, InterpreterError> {
        let Some(value) = self.builtin_arg(args, offset)? else {
            return Ok(default);
        };
        if matches!(value, Value::Undefined) {
            return Ok(default);
        }
        if Self::coerce_to_float(&value).is_some_and(f64::is_infinite) {
            return Ok(0);
        }
        let bound = Self::value_as_integer(&value);
        if bound < 0 {
            return Err(InterpreterError::RangeError {
                message: "Buffer.copy bounds must be non-negative".to_string(),
            });
        }
        Ok(usize::try_from(bound).unwrap_or(usize::MAX).min(length))
    }

    pub(super) fn buffer_copy_source_start_arg(
        &self,
        args: RegRange,
        offset: u32,
        length: usize,
    ) -> Result<usize, InterpreterError> {
        let Some(value) = self.builtin_arg(args, offset)? else {
            return Ok(0);
        };
        if matches!(value, Value::Undefined) {
            return Ok(0);
        }
        if Self::coerce_to_float(&value).is_some_and(f64::is_infinite) {
            return Ok(0);
        }
        let bound = Self::value_as_integer(&value);
        if bound < 0 || usize::try_from(bound).map_or(true, |bound| bound > length) {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Buffer.copy sourceStart must be between 0 and {length}, received {bound}"
                ),
            });
        }
        Ok(bound as usize)
    }

    pub(super) fn buffer_to_json(&mut self, receiver: Value) -> Result<Value, InterpreterError> {
        let (_, view) = self.buffer_receiver_view(receiver, "toJSON")?;
        let bytes = self.typed_array_view_bytes(&view)?;
        let values_temporary = bytes
            .len()
            .checked_mul(std::mem::size_of::<Value>())
            .ok_or_else(|| InterpreterError::RangeError {
                message: "Buffer.toJSON temporary size overflows".to_string(),
            })?;
        let mut data_object_bytes = MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES.saturating_add(
            Self::estimate_property_entry_bytes(
                "length",
                &Value::Int(i64::try_from(bytes.len()).unwrap_or(i64::MAX)),
            ),
        );
        for index in 0..bytes.len() {
            data_object_bytes = data_object_bytes.saturating_add(
                Self::estimate_property_entry_bytes(&index.to_string(), &Value::Int(0)),
            );
        }
        let wrapper_object_bytes = MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES
            .saturating_add(Self::estimate_property_entry_bytes(
                "type",
                &Value::str("Buffer"),
            ))
            .saturating_add(Self::estimate_property_entry_bytes(
                "data",
                &Value::Object(ObjectId(0)),
            ));
        let temporary_and_heap = u64::try_from(values_temporary)
            .unwrap_or(u64::MAX)
            .saturating_add(data_object_bytes)
            .saturating_add(wrapper_object_bytes);
        self.check_temporary_memory_budget(temporary_and_heap)?;
        let requested_heap_objects = self.heap_object_count_u32().saturating_add(2);
        if requested_heap_objects > self.config.max_heap_objects {
            return Err(
                self.memory_budget_error(self.estimated_memory_bytes, requested_heap_objects)
            );
        }
        let values = bytes
            .iter()
            .copied()
            .map(|byte| Value::Int(i64::from(byte)))
            .collect::<Vec<_>>();
        let data = self.alloc_array_from_values(&values)?;
        let object = self.alloc_object_with_properties(&[
            ("type", Value::str("Buffer")),
            ("data", Value::Object(data)),
        ])?;
        Ok(Value::Object(object))
    }

    pub(super) fn buffer_swap(
        &mut self,
        receiver: Value,
        width: usize,
    ) -> Result<Value, InterpreterError> {
        let (object_id, view) = self.buffer_receiver_view(receiver, "swap")?;
        if view.byte_length % width != 0 {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Buffer size {} must be a multiple of {width} bytes",
                    view.byte_length
                ),
            });
        }
        let start = view.byte_offset;
        let end =
            start
                .checked_add(view.byte_length)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Buffer swap range overflows host address space".to_string(),
                })?;
        self.with_array_buffer_bytes_mut(view.buffer, |bytes| {
            let range = bytes
                .get_mut(start..end)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Buffer swap range exceeds backing storage".to_string(),
                })?;
            for chunk in range.chunks_exact_mut(width) {
                chunk.reverse();
            }
            Ok(())
        })??;
        Ok(Value::Object(object_id))
    }

    pub(super) fn data_view_index_from_value(
        &self,
        field: &str,
        value: &Value,
    ) -> Result<usize, InterpreterError> {
        let Some(index) = Self::to_index_value(value)? else {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "invalid DataView {field} {}; requested value must be an integer from 0 to 2^53 - 1",
                    self.value_to_string(value),
                ),
            });
        };
        usize::try_from(index).map_err(|_| InterpreterError::RangeError {
            message: format!("DataView {field} {index} exceeds host addressable size"),
        })
    }

    pub(super) fn data_view_optional_index_arg(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
        offset: u32,
        field: &str,
    ) -> Result<Option<usize>, InterpreterError> {
        if offset >= args.count {
            return Ok(None);
        }
        let value = self.read_reg(args.start + offset)?;
        if matches!(value, Value::Undefined) {
            return Ok(None);
        }
        let value = self.object_to_number_primitive(module, value)?;
        self.data_view_index_from_value(field, &value).map(Some)
    }

    pub(super) fn data_view_buffer_view_shape(
        &mut self,
        module: Option<&Ir3Module>,
        buffer_id: ObjectId,
        args: RegRange,
    ) -> Result<(usize, usize, Option<ViewBounds>), InterpreterError> {
        // ES2024 25.3.2.1 steps 3-9: byteOffset, a detached buffer, the
        // offset against the buffer's length, then byteLength. Over a
        // resizable buffer a view without byteLength tracks the buffer
        // (bd-9vouw.256).
        let byte_offset = self
            .data_view_optional_index_arg(module, args, 1, "byteOffset")?
            .unwrap_or(0);
        let (_, detached) = self.buffer_resizability(buffer_id)?;
        if detached {
            return Err(InterpreterError::TypeError {
                expected: "an attached ArrayBuffer for DataView".to_string(),
                got: "a detached ArrayBuffer".to_string(),
            });
        }
        let buffer_len = self.array_buffer_byte_length(buffer_id)?;
        if byte_offset > buffer_len {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "DataView byteOffset {byte_offset} exceeds ArrayBuffer byteLength {buffer_len}"
                ),
            });
        }

        let remaining = buffer_len - byte_offset;
        let explicit_length = self.data_view_optional_index_arg(module, args, 2, "byteLength")?;
        let bounds = self.new_view_bounds(buffer_id, explicit_length)?;
        let byte_length = explicit_length.unwrap_or(remaining);
        let end =
            byte_offset
                .checked_add(byte_length)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: format!(
                        "DataView byteOffset {byte_offset} plus byteLength {byte_length} overflows"
                    ),
                })?;
        if end > buffer_len {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "DataView view range byteOffset {byte_offset} + byteLength {byte_length} exceeds ArrayBuffer byteLength {buffer_len}"
                ),
            });
        }

        Ok((byte_offset, byte_length, bounds))
    }

    pub(super) fn data_view_byte_offset_arg(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        method_name: &str,
    ) -> Result<usize, InterpreterError> {
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Int(0));
        let value = self.object_to_number_primitive(Some(module), value)?;
        self.data_view_index_from_value(
            &format!("byteOffset for DataView.prototype.{method_name}"),
            &value,
        )
    }

    pub(super) fn data_view_little_endian_arg(
        &self,
        args: RegRange,
        offset: u32,
    ) -> Result<bool, InterpreterError> {
        Ok(self
            .builtin_arg(args, offset)?
            .map(|value| value.is_truthy())
            .unwrap_or(false))
    }

    pub(super) fn data_view_receiver_view(
        &self,
        receiver: Value,
        method_name: &str,
    ) -> Result<DataViewView, InterpreterError> {
        let Value::Object(object_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: format!("DataView receiver for DataView.prototype.{method_name}"),
                got: receiver.type_name().to_string(),
            });
        };
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        object.data_view.as_deref().cloned().ok_or_else(|| {
            let got = object.brand().unwrap_or("object").to_string();
            InterpreterError::TypeError {
                expected: format!("DataView receiver for DataView.prototype.{method_name}"),
                got,
            }
        })
    }

    pub(super) fn data_view_absolute_range(
        view: &DataViewView,
        method_name: &str,
        byte_offset: usize,
        byte_width: usize,
    ) -> Result<(usize, usize), InterpreterError> {
        let relative_end =
            byte_offset
                .checked_add(byte_width)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: format!(
                        "DataView.prototype.{method_name} byteOffset {byte_offset} plus {byte_width} bytes overflows"
                    ),
                })?;
        if relative_end > view.byte_length {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "DataView.prototype.{method_name} byteOffset {byte_offset} plus {byte_width} bytes is out of bounds for DataView byteLength {}",
                    view.byte_length,
                ),
            });
        }
        let start = view.byte_offset.checked_add(byte_offset).ok_or_else(|| {
            InterpreterError::RangeError {
                message: format!("DataView.prototype.{method_name} absolute byteOffset overflows"),
            }
        })?;
        let end = start
            .checked_add(byte_width)
            .ok_or_else(|| InterpreterError::RangeError {
                message: format!("DataView.prototype.{method_name} byte range overflows"),
            })?;
        Ok((start, end))
    }

    pub(super) fn data_view_get_integer(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
        kind: DataViewIntegerKind,
    ) -> Result<Value, InterpreterError> {
        let method_name = kind.method_name(false);
        // RequireInternalSlot before the arguments are coerced.
        self.data_view_receiver_view(receiver.clone(), method_name)?;
        let byte_offset = self.data_view_byte_offset_arg(module, args, method_name)?;
        let little_endian = if kind.byte_width() == 1 {
            false
        } else {
            self.data_view_little_endian_arg(args, 1)?
        };
        // ES2024 25.3.1.5-6 steps 7-8: the view's bounds after the coercions,
        // which may have resized or detached its buffer (bd-9vouw.256).
        let view = self.data_view_receiver_view(receiver, method_name)?;
        Self::reject_out_of_bounds_data_view(&view, method_name)?;
        let (start, end) =
            Self::data_view_absolute_range(&view, method_name, byte_offset, kind.byte_width())?;
        self.with_array_buffer_bytes(view.buffer, |bytes| {
            let slot = bytes
                .get(start..end)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: format!(
                        "DataView.prototype.{method_name} absolute byte range is out of bounds"
                    ),
                })?;
            let mut raw = [0u8; 8];
            raw[..slot.len()].copy_from_slice(slot);
            let ordered = |width: usize| -> [u8; 8] {
                let mut bytes = [0u8; 8];
                bytes[..width].copy_from_slice(&raw[..width]);
                if !little_endian {
                    bytes[..width].reverse();
                }
                bytes
            };
            // `ordered` yields little-endian bytes for every width.
            Ok(match kind {
                DataViewIntegerKind::Uint8 => Value::Int(i64::from(raw[0])),
                DataViewIntegerKind::Int8 => Value::Int(i64::from(raw[0] as i8)),
                DataViewIntegerKind::Int16 => {
                    let bytes = ordered(2);
                    Value::Int(i64::from(i16::from_le_bytes([bytes[0], bytes[1]])))
                }
                DataViewIntegerKind::Uint16 => {
                    let bytes = ordered(2);
                    Value::Int(i64::from(u16::from_le_bytes([bytes[0], bytes[1]])))
                }
                DataViewIntegerKind::Int32 => {
                    let bytes = ordered(4);
                    Value::Int(i64::from(i32::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3],
                    ])))
                }
                DataViewIntegerKind::Uint32 => {
                    let bytes = ordered(4);
                    Value::Int(i64::from(u32::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3],
                    ])))
                }
                DataViewIntegerKind::Float32 => {
                    let bytes = ordered(4);
                    js_number_to_value(f64::from(f32::from_le_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3],
                    ])))
                }
                DataViewIntegerKind::Float64 => js_number_to_value(f64::from_le_bytes(ordered(8))),
                DataViewIntegerKind::BigInt64 => Value::BigInt(Arc::from(
                    i64::from_le_bytes(ordered(8)).to_string().as_str(),
                )),
                DataViewIntegerKind::BigUint64 => Value::BigInt(Arc::from(
                    u64::from_le_bytes(ordered(8)).to_string().as_str(),
                )),
            })
        })?
    }

    pub(super) fn data_view_set_integer(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
        kind: DataViewIntegerKind,
    ) -> Result<Value, InterpreterError> {
        let method_name = kind.method_name(true);
        // RequireInternalSlot before the arguments are coerced.
        self.data_view_receiver_view(receiver.clone(), method_name)?;
        let byte_offset = self.data_view_byte_offset_arg(module, args, method_name)?;
        let value = match kind {
            DataViewIntegerKind::BigInt64 | DataViewIntegerKind::BigUint64 => {
                let value = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                self.object_to_number_primitive(Some(module), value)?
            }
            _ => self
                .builtin_number_arg(module, args, 1)?
                .unwrap_or(Value::Undefined),
        };
        let little_endian = if kind.byte_width() == 1 {
            false
        } else {
            self.data_view_little_endian_arg(args, 2)?
        };
        // ES2020 24.3.1.2 SetViewValue converts the value (ToNumber, or
        // ToBigInt for the BigInt kinds) before the range check.
        let mut bytes: [u8; 8] = match kind {
            DataViewIntegerKind::Uint8 => {
                u64::from(Self::typed_array_u8_value(&value)).to_le_bytes()
            }
            DataViewIntegerKind::Int8 => {
                Self::typed_array_unsigned_mod(&value, 1 << 8).to_le_bytes()
            }
            DataViewIntegerKind::Int16 | DataViewIntegerKind::Uint16 => {
                Self::typed_array_unsigned_mod(&value, 1 << 16).to_le_bytes()
            }
            DataViewIntegerKind::Int32 => {
                u64::from(Self::typed_array_i32_value(&value) as u32).to_le_bytes()
            }
            DataViewIntegerKind::Uint32 => {
                u64::from(Self::typed_array_u32_value(&value)).to_le_bytes()
            }
            DataViewIntegerKind::Float32 => {
                u64::from((Self::typed_array_number(&value) as f32).to_bits()).to_le_bytes()
            }
            DataViewIntegerKind::Float64 => {
                Self::typed_array_number(&value).to_bits().to_le_bytes()
            }
            DataViewIntegerKind::BigInt64 | DataViewIntegerKind::BigUint64 => {
                let digits = self.bigint_digits_of(value)?;
                let wrapped = bigint_ops::as_uint_n(64, &digits).map_err(|error| {
                    InterpreterError::RangeError {
                        message: error.message().to_string(),
                    }
                })?;
                wrapped
                    .parse::<u64>()
                    .map_err(|_| InterpreterError::RangeError {
                        message: format!("DataView.prototype.{method_name} value out of range"),
                    })?
                    .to_le_bytes()
            }
        };
        let width = kind.byte_width();
        if !little_endian {
            bytes[..width].reverse();
        }
        // ES2024 25.3.1.5-6 steps 7-8: the view's bounds after the coercions,
        // which may have resized or detached its buffer (bd-9vouw.256).
        let view = self.data_view_receiver_view(receiver, method_name)?;
        Self::reject_out_of_bounds_data_view(&view, method_name)?;
        let (start, end) = Self::data_view_absolute_range(&view, method_name, byte_offset, width)?;
        self.with_array_buffer_bytes_mut(view.buffer, |buffer| {
            let slot = buffer
                .get_mut(start..end)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: format!(
                        "DataView.prototype.{method_name} absolute byte range is out of bounds"
                    ),
                })?;
            slot.copy_from_slice(&bytes[..width]);
            Ok(())
        })??;
        Ok(Value::Undefined)
    }

    /// ES2020 7.1.13 ToBigInt as decimal digits: a BigInt, a boolean (0n/1n)
    /// or a string that parses as one; a Number, undefined, null or Symbol is
    /// a TypeError and an unparsable string a SyntaxError.
    pub(super) fn bigint_digits_of(&mut self, value: Value) -> Result<String, InterpreterError> {
        match value {
            Value::BigInt(digits) => Ok(digits.to_string()),
            Value::Bool(flag) => Ok(i64::from(flag).to_string()),
            Value::Str(text) => {
                let text = text.to_string();
                bigint_ops::from_string(&text).ok_or_else(|| {
                    self.throw_js_error("SyntaxError", format!("Cannot convert {text} to a BigInt"))
                })
            }
            other => Err(InterpreterError::TypeError {
                expected: "value convertible to BigInt".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// Coerce a value to f64 for floating-point operations.
    /// ES2020 ToNumber for a `Math.*` argument (bd-9vouw.63). Numbers pass
    /// through unchanged (so integer fast paths keep their `Int`); other
    /// primitives convert (`'5'` -> 5, `true` -> 1, `null` -> 0, `undefined`
    /// -> NaN); objects convert through ToPrimitive with hint "number" when a
    /// module is available for the reentrant call (NaN otherwise); Symbol and
    /// BigInt throw TypeError. Arms read their arguments through this in
    /// argument order, so observable `valueOf` calls happen left to right.
    pub(super) fn math_argument_value(
        &mut self,
        register: u32,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        let value = self.read_reg(register)?;
        if matches!(value, Value::Int(_) | Value::Float(_)) {
            return Ok(value);
        }
        let primitive = if value.is_object_like() && module.is_some() {
            self.coerce_runtime_primitive_with_hint(module, value, "number")?
        } else {
            value
        };
        match primitive {
            Value::Int(_) | Value::Float(_) => Ok(primitive),
            Value::Symbol(_) => Err(InterpreterError::TypeError {
                expected: "value convertible to a number".to_string(),
                got: "Symbol (Cannot convert a Symbol value to a number)".to_string(),
            }),
            Value::BigInt(_) => Err(InterpreterError::TypeError {
                expected: "value convertible to a number".to_string(),
                got: "BigInt (Cannot convert a BigInt value to a number)".to_string(),
            }),
            other => Ok(Value::Float(Float64::new(
                Self::coerce_to_float(&other).unwrap_or(f64::NAN),
            ))),
        }
    }

    pub(super) fn coerce_to_float(value: &Value) -> Option<f64> {
        match value {
            Value::Int(n) => Some(*n as f64),
            Value::BigInt(_) | Value::Symbol(_) => None,
            Value::Float(f) => Some(f.inner()),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Null => Some(0.0),
            // ES2020 7.1.4.1.1 StringToNumber: JS whitespace, 0x/0o/0b
            // literals, and NaN (not a refusal) for anything else.
            Value::Str(s) => Some(primitive_conversion::string_number(s)),
            Value::Undefined => Some(f64::NAN),
            Value::Object(_)
            | Value::Function(_)
            | Value::Closure(_)
            | Value::Iterator(_)
            | Value::GeneratorFunction(_)
            | Value::Generator(_)
            | Value::Promise(_)
            | Value::BuiltinFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncFunctionObject(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::AsyncGeneratorObject(_)
            | Value::Accessor { .. } => Some(f64::NAN),
        }
    }

    /// Convert a Value to its string representation using JavaScript toString semantics.
    /// This unified implementation ensures all string case-conversion builtin paths
    /// have consistent behavior across all Value enum variants.
    pub(super) fn value_to_primitive_string(value: &Value) -> String {
        match value {
            Value::Str(s) => s.to_string(),
            Value::Null => "null".to_string(),
            Value::Undefined => "undefined".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Int(n) => n.to_string(),
            Value::BigInt(n) => n.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Object(_) => "[object Object]".to_string(),
            Value::Accessor { .. } => "[object Object]".to_string(),
            Value::Function(_) => "[object Function]".to_string(),
            Value::Closure(_) => "[object Function]".to_string(),
            Value::Iterator(_) => "[object Array Iterator]".to_string(),
            Value::GeneratorFunction(_) => "[object GeneratorFunction]".to_string(),
            Value::Generator(_) => "[object Generator]".to_string(),
            Value::AsyncFunction(_) => "[object AsyncFunction]".to_string(),
            Value::AsyncFunctionObject(_) => "[object AsyncFunction]".to_string(),
            Value::AsyncGeneratorFunction(_) => "[object AsyncGeneratorFunction]".to_string(),
            Value::AsyncGeneratorObject(_) => "[object AsyncGenerator]".to_string(),
            Value::Promise(_) => "[object Promise]".to_string(),
            Value::BuiltinFunction(_) => "[object Function]".to_string(),
            Value::Symbol(symbol) => format!("Symbol({})", symbol.0),
        }
    }

    pub(super) fn value_to_object_to_string_tag(value: &Value) -> String {
        match value {
            Value::Undefined => "[object Undefined]".to_string(),
            Value::Null => "[object Null]".to_string(),
            Value::Bool(_) => "[object Boolean]".to_string(),
            Value::Int(_) | Value::Float(_) => "[object Number]".to_string(),
            Value::BigInt(_) => "[object BigInt]".to_string(),
            Value::Symbol(_) => "[object Symbol]".to_string(),
            Value::Str(_) => "[object String]".to_string(),
            Value::Object(_) => "[object Object]".to_string(),
            Value::Accessor { .. } => "[object Object]".to_string(),
            Value::Function(_) | Value::Closure(_) | Value::BuiltinFunction(_) => {
                "[object Function]".to_string()
            }
            Value::GeneratorFunction(_) => "[object GeneratorFunction]".to_string(),
            Value::Generator(_) => "[object Generator]".to_string(),
            Value::AsyncFunction(_) => "[object AsyncFunction]".to_string(),
            Value::AsyncFunctionObject(_) => "[object AsyncFunction]".to_string(),
            Value::AsyncGeneratorFunction(_) => "[object AsyncGeneratorFunction]".to_string(),
            Value::AsyncGeneratorObject(_) => "[object AsyncGenerator]".to_string(),
            Value::Iterator(_) => "[object Array Iterator]".to_string(),
            Value::Promise(_) => "[object Promise]".to_string(),
        }
    }

    /// String.prototype receiver coercion with RequireObjectCoercible semantics.
    /// Throws TypeError for null/undefined as per ECMAScript specification.
    /// All String.prototype methods should use this for consistent behavior.
    /// Shared padStart/padEnd core (bd-9a8cz.1, bd-3kvat). Pads `value` to
    /// `target_length` UTF-16 code units using the optional pad string
    /// (default `" "`), prepending when `pad_start` else appending. Returns
    /// `value` unchanged when it is already at least `target_length` long or
    /// the pad string is empty (per ES2020 21.1.3.13/21.1.3.14).
    pub(super) fn string_pad_value(
        &mut self,
        module: &Ir3Module,
        value: &JsString,
        args: RegRange,
        pad_start: bool,
    ) -> Result<JsString, InterpreterError> {
        // ES2020 21.1.3.13/14: `targetLength` and the fill are measured in
        // UTF-16 code units over exact units; a fill truncated inside a
        // surrogate pair keeps the lone half losslessly (bd-3kvat;
        // previously scalar-counted over the projection).
        let units = value.code_units_vec();
        let cur_len = units.len();
        let target = match self.builtin_number_arg(module, args, 0)? {
            Some(arg) => Self::value_as_integer(&arg).max(0) as usize,
            None => 0,
        };
        let pad = match self.builtin_string_arg(module, args, 1)? {
            Some(Value::Undefined) | None => JsString::from(" "),
            Some(Value::Str(s)) => s,
            Some(Value::Symbol(_)) => return Err(Self::symbol_to_string_error()),
            Some(arg) => JsString::from(self.value_to_string(&arg)),
        };
        let pad_units = pad.code_units_vec();
        if target <= cur_len || pad_units.is_empty() {
            return Ok(value.clone());
        }
        // Guard before allocating the filler: a code unit re-encodes to at
        // most 3 UTF-8 bytes, so this bounds the projected byte length.
        self.check_string_limit(target.saturating_mul(3))?;
        let fill_needed = target - cur_len;
        let filler_units: Vec<u16> = (0..fill_needed)
            .map(|i| pad_units[i % pad_units.len()])
            .collect();
        let mut result_units = Vec::with_capacity(target);
        if pad_start {
            result_units.extend_from_slice(&filler_units);
            result_units.extend_from_slice(&units);
        } else {
            result_units.extend_from_slice(&units);
            result_units.extend_from_slice(&filler_units);
        }
        Ok(JsString::from_code_units(&result_units))
    }

    /// RequireObjectCoercible for primitive String.prototype receiver paths.
    /// String receivers keep their real UTF-16 code units (including lone
    /// surrogates, bd-neika); non-string receivers coerce through the
    /// primitive-string path, which is always well-formed.
    pub(super) fn require_object_coercible_to_js_string(
        value: &Value,
    ) -> Result<JsString, InterpreterError> {
        match value {
            Value::Null => Err(InterpreterError::TypeError {
                expected: "object-coercible String.prototype receiver".to_string(),
                got: "null".to_string(),
            }),
            Value::Undefined => Err(InterpreterError::TypeError {
                expected: "object-coercible String.prototype receiver".to_string(),
                got: "undefined".to_string(),
            }),
            Value::Str(s) => Ok(s.clone()),
            _ => Ok(JsString::from(Self::value_to_primitive_string(value))),
        }
    }

    /// Annex B CreateHTML (B.2.2.2.1): `<tag attribute="value">S</tag>`, the
    /// value's `"` written as `&quot;`. The receiver converts before the
    /// value, each with ToString.
    pub(super) fn string_html_method(
        &mut self,
        module: &Ir3Module,
        method: &str,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let Some(&(_, tag, attribute)) = STRING_HTML_METHODS
            .iter()
            .find(|(name, _, _)| *name == method)
        else {
            return Err(InterpreterError::InternalError {
                details: format!("unknown String HTML method {method}"),
            });
        };
        if matches!(receiver, Value::Undefined | Value::Null) {
            return Err(self.throw_js_error(
                "TypeError",
                format!(
                    "String.prototype.{method} called on {}",
                    if matches!(receiver, Value::Null) {
                        "null"
                    } else {
                        "undefined"
                    }
                ),
            ));
        }
        let text =
            self.scoped_conversion(|this| this.conversion_to_string(Some(module), receiver))?;
        let mut units: Vec<u16> = format!("<{tag}").encode_utf16().collect();
        if let Some(attribute) = attribute {
            let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
            let value =
                self.scoped_conversion(|this| this.conversion_to_string(Some(module), value))?;
            units.extend(format!(" {attribute}=\"").encode_utf16());
            for unit in value.encode_utf16() {
                if unit == u16::from(b'"') {
                    units.extend("&quot;".encode_utf16());
                } else {
                    units.push(unit);
                }
            }
            units.push(u16::from(b'"'));
        }
        units.push(u16::from(b'>'));
        units.extend(text.encode_utf16());
        units.extend(format!("</{tag}>").encode_utf16());
        self.check_string_limit(units.len())?;
        Ok(Value::Str(JsString::from_code_units(&units)))
    }

    pub(super) fn string_prototype_char_at_value(
        receiver: Value,
        index: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        let string_val = Self::require_object_coercible_to_js_string(&receiver)?;
        let index = index.as_ref().map(Self::value_as_integer).unwrap_or(0);
        if index < 0 {
            return Ok(Value::str(""));
        }

        let Some(unit) = string_val.code_unit_at(index as usize) else {
            return Ok(Value::str(""));
        };
        // A surrogate half stays a real lone-surrogate string value
        // (bd-neika); a BMP unit normalizes to the well-formed fast path.
        Ok(Value::Str(JsString::from_code_units(&[unit])))
    }

    pub(super) fn string_prototype_char_code_at_value(
        receiver: Value,
        index: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        let string_val = Self::require_object_coercible_to_js_string(&receiver)?;
        let index = index.as_ref().map(Self::value_as_integer).unwrap_or(0);
        if index < 0 {
            return Ok(Value::Float(Float64::new(f64::NAN)));
        }

        match string_val.code_unit_at(index as usize) {
            Some(unit) => Ok(Value::Int(i64::from(unit))),
            None => Ok(Value::Float(Float64::new(f64::NAN))),
        }
    }

    pub(super) fn string_prototype_at_value(
        receiver: Value,
        index: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        let string_val = Self::require_object_coercible_to_js_string(&receiver)?;
        let len = string_val.utf16_len() as i64;
        let raw = index.as_ref().map(Self::value_as_integer).unwrap_or(0);
        let idx = if raw < 0 { raw + len } else { raw };
        if idx < 0 || idx >= len {
            return Ok(Value::Undefined);
        }
        Ok(string_val
            .code_unit_at(idx as usize)
            .map_or(Value::Undefined, |unit| {
                Value::Str(JsString::from_code_units(&[unit]))
            }))
    }

    /// Validates Array method callback arguments for fail-closed implementations.
    /// Hostcall-based tests pass the receiver as the first argument, while
    /// lowered method wrappers keep the receiver in the active frame's `this`
    /// value and pass only user arguments.
    pub(super) fn validate_array_callback_args(
        &self,
        args: RegRange,
        method_name: &str,
    ) -> Result<(), InterpreterError> {
        self.validate_array_callback_structure(args, method_name)
            .map(|_| ())
    }

    pub(super) fn validate_array_callback_structure(
        &self,
        args: RegRange,
        method_name: &str,
    ) -> Result<(ObjectId, Value, Value, usize), InterpreterError> {
        if args.count == 0 {
            return Err(InterpreterError::TypeError {
                expected: "callback function".to_string(),
                got: "missing callback argument".to_string(),
            });
        }

        let first = self.read_reg(args.start)?;
        let frame_this = self
            .call_stack
            .last()
            .map_or(Value::Undefined, |frame| frame.this_value.clone());

        let use_frame_receiver = matches!(frame_this, Value::Object(_))
            && (args.count == 1 || !matches!(first, Value::Object(_)));
        let (this_val, callback, this_arg) = if use_frame_receiver {
            (
                frame_this,
                first,
                if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                },
            )
        } else if args.count >= 2 {
            (
                first,
                self.read_reg(args.start + 1)?,
                if args.count > 2 {
                    self.read_reg(args.start + 2)?
                } else {
                    Value::Undefined
                },
            )
        } else {
            return Err(InterpreterError::TypeError {
                expected: "callback function".to_string(),
                got: "missing callback argument".to_string(),
            });
        };

        let array_id = match this_val {
            Value::Object(object_id) => object_id,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "array object".to_string(),
                    got: format!("{} receiver for {method_name}", other.type_name()),
                });
            }
        };

        if !callback.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "function".to_string(),
                got: callback.type_name().to_string(),
            });
        }

        let array_length = self.array_like_length(array_id)?;
        Ok((array_id, callback, this_arg, array_length))
    }

    /// Call an array builtin's callback with `(element, index, array)`. The
    /// callback may collect (bd-9vouw.77): the call pins the callback, its
    /// `this` and its arguments, which include the array being iterated. A
    /// builtin that also holds an array it fills across calls sets a request
    /// holding it first; that request carries over. The builtin holds nothing
    /// else across the call.
    pub(super) fn invoke_array_callback(
        &mut self,
        module: Option<&Ir3Module>,
        callback: &Value,
        this_arg: Value,
        element: Value,
        element_index: usize,
        array_id: ObjectId,
    ) -> Result<Value, InterpreterError> {
        self.invoke_labeled_array_callback(
            module,
            callback,
            this_arg,
            element,
            element_index,
            array_id,
        )
        .map(|(value, _label)| value)
    }

    /// Preserve callback return provenance both for the enclosing builtin's
    /// result and for callers that copy the value into a new array. Predicates
    /// also contribute: their result decides which value/index/length escapes.
    pub(super) fn invoke_labeled_array_callback(
        &mut self,
        module: Option<&Ir3Module>,
        callback: &Value,
        this_arg: Value,
        element: Value,
        element_index: usize,
        array_id: ObjectId,
    ) -> Result<(Value, Label), InterpreterError> {
        let index = i64::try_from(element_index).map_err(|_| InterpreterError::TypeError {
            expected: "array callback index within i64".to_string(),
            got: element_index.to_string(),
        })?;
        // The element's stored label (and the array's own) is the callback's
        // context label, so an aliased sink inside the callback sees it.
        let element_key = RuntimePropertyKey::String(JsString::from(element_index.to_string()));
        let element_label = self.runtime_property_label(array_id, &element_key).join(
            self.object_mutation_labels
                .get(&array_id)
                .unwrap_or(&Label::Public),
        );
        let argument_label = (element_label != Label::Public).then_some(element_label);
        let held = self.gc_nested_request.take().unwrap_or_default();
        let result = self.with_gc_nested_request(held, |core| {
            core.invoke_inline_method_call_with_argument_label(
                module,
                callback.clone(),
                this_arg,
                vec![element, Value::Int(index), Value::Object(array_id)],
                argument_label,
            )
        })?;
        // The inline-call boundary preserves a nonempty pending label in its
        // caller snapshot. Join instead of replacing it so a later Public
        // callback cannot erase an earlier Secret return.
        self.join_pending_array_result_label(&result.1)?;
        Ok(result)
    }

    pub(super) fn join_pending_array_result_label(
        &mut self,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        if label == &Label::Public {
            return Ok(());
        }
        let joined = self.clone_dominant_label_with_temporary_budget(
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
            label,
            Self::estimate_label_bytes(label),
        )?;
        self.replace_pending_hostcall_result_label(Some(joined))
    }

    pub(super) fn array_prototype_reduce(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        self.with_array_reduction_observation(args, None, |core| {
            core.array_prototype_reduce_inner(args, module)
        })
    }

    pub(super) fn array_prototype_reduce_inner(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        self.validate_array_callback_args(args, "Array.prototype.reduce")?;

        let array_id = match self.read_reg(args.start)? {
            Value::Object(object_id) => object_id,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "array object".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let callback = self.read_reg(args.start + 1)?;
        self.observe_array_reduction_length(array_id, false)?;
        let length = self.array_like_length(array_id)?;
        let mut next_index = 0usize;
        let mut accumulator = if args.count > 2 {
            self.read_reg(args.start + 2)?
        } else {
            let mut first_present = None;
            for element_index in 0..length {
                if let Some(value) =
                    self.array_reduction_element(module, array_id, element_index, false)?
                {
                    first_present = Some((element_index, value));
                    break;
                }
            }
            let Some((element_index, value)) = first_present else {
                return Err(InterpreterError::TypeError {
                    expected: "non-empty array or initialValue".to_string(),
                    got: "empty Array.prototype.reduce without initialValue".to_string(),
                });
            };
            next_index = element_index.saturating_add(1);
            value
        };

        for element_index in next_index..length {
            let Some(current_value) =
                self.array_reduction_element(module, array_id, element_index, false)?
            else {
                continue;
            };
            accumulator = self.invoke_simple_reduce_callback(
                module,
                &callback,
                accumulator,
                current_value,
                element_index,
                array_id,
            )?;
        }

        Ok(accumulator)
    }

    pub(super) fn array_prototype_reduce_right(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        self.with_array_reduction_observation(args, None, |core| {
            core.array_prototype_reduce_right_inner(args, module)
        })
    }

    pub(super) fn array_prototype_reduce_right_inner(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        self.validate_array_callback_args(args, "Array.prototype.reduceRight")?;

        let array_id = match self.read_reg(args.start)? {
            Value::Object(object_id) => object_id,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "array object".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let callback = self.read_reg(args.start + 1)?;
        self.observe_array_reduction_length(array_id, false)?;
        let length = self.array_like_length(array_id)?;
        let mut next_index_exclusive = length;
        let mut accumulator = if args.count > 2 {
            self.read_reg(args.start + 2)?
        } else {
            let mut first_present = None;
            for element_index in (0..length).rev() {
                if let Some(value) =
                    self.array_reduction_element(module, array_id, element_index, false)?
                {
                    first_present = Some((element_index, value));
                    break;
                }
            }
            let Some((element_index, value)) = first_present else {
                return Err(InterpreterError::TypeError {
                    expected: "non-empty array or initialValue".to_string(),
                    got: "empty Array.prototype.reduceRight without initialValue".to_string(),
                });
            };
            next_index_exclusive = element_index;
            value
        };

        for element_index in (0..next_index_exclusive).rev() {
            let Some(current_value) =
                self.array_reduction_element(module, array_id, element_index, false)?
            else {
                continue;
            };
            accumulator = self.invoke_simple_reduce_callback(
                module,
                &callback,
                accumulator,
                current_value,
                element_index,
                array_id,
            )?;
        }

        Ok(accumulator)
    }

    /// `length` of an array-like receiver, read through its prototype chain
    /// like [[Get]] (`Object.create(['x', 'y'])` has no own `length`).
    /// An empty buffer for `len` elements of an array-like, charged to the
    /// temporary budget first: the length is guest-chosen (up to 2^53 - 1,
    /// `{ length: 2 ** 53 - 1 }`), and an unchecked `with_capacity` of it
    /// aborted the process ("memory allocation of ... bytes failed").
    pub(super) fn element_buffer<T>(&self, len: usize) -> Result<Vec<T>, InterpreterError> {
        self.check_temporary_memory_budget(
            (len as u64).saturating_mul(std::mem::size_of::<T>() as u64),
        )?;
        Ok(Vec::with_capacity(len))
    }

    /// The length an Array-kind method iterates. A %TypedArray%.prototype
    /// method reads the view's [[ArrayLength]] (ES2024 23.2.4.4
    /// TypedArrayLength), never a `length` property: a typed array whose
    /// own or inherited `length` the program redefined still iterates every
    /// element, and that getter is not called (bd-9vouw.287). An
    /// Array.prototype method reads LengthOfArrayLike.
    pub(super) fn array_method_length(
        &self,
        array_id: ObjectId,
        typed_array_method: bool,
    ) -> Result<usize, InterpreterError> {
        if typed_array_method
            && let Some(view) = self
                .heap
                .get(array_id.0 as usize)
                .and_then(|object| object.typed_array.as_deref())
        {
            return Ok(view.length);
        }
        self.array_like_length(array_id)
    }

    pub(super) fn array_like_length(&self, array_id: ObjectId) -> Result<usize, InterpreterError> {
        if self.heap.get(array_id.0 as usize).is_none() {
            return Err(InterpreterError::ObjectNotFound { id: array_id.0 });
        }
        // ToLength(Get(O, "length")) (ES2020 7.1.20) of a primitive length:
        // a string is StringToNumber (`"2.3E2"`, `"0x0002"`), a boolean 0 or
        // 1, and the number is truncated into [0, 2^53 - 1]. A string length
        // counted as 0, so `Array.prototype.map.call({ length: '2' }, f)`
        // saw no elements.
        Ok(match self.chain_data_property(array_id, "length") {
            Some(Value::Int(length)) if *length > 0 => {
                usize::try_from(*length).unwrap_or(usize::MAX)
            }
            Some(length) => {
                let number = Self::coerce_to_float(length).unwrap_or(0.0);
                if number > 0.0 {
                    number.trunc().min(9_007_199_254_740_991.0) as usize
                } else {
                    0
                }
            }
            None => 0,
        })
    }

    pub(super) fn array_index_value(
        &self,
        array_id: ObjectId,
        element_index: usize,
    ) -> Result<Option<Value>, InterpreterError> {
        let key = element_index.to_string();
        if let Some(value) = self.typed_array_indexed_get_property(array_id, &key)? {
            // A typed array element is never undefined: undefined is an index
            // past its current length (its resizable buffer shrank, or was
            // detached, while the loop ran). HasProperty is false there, so
            // the loop skips it (bd-9vouw.256).
            return Ok((!matches!(value, Value::Undefined)).then_some(value));
        }
        if self.heap.get(array_id.0 as usize).is_none() {
            return Err(InterpreterError::ObjectNotFound { id: array_id.0 });
        }
        // Inherited elements count, as for [[Get]]/HasProperty: an object
        // whose prototype is an array sees that array's elements.
        let value = self.chain_data_property(array_id, &key).cloned();
        if value.is_none() {
            self.charge_native_hole_read()?;
        }
        Ok(value)
    }

    /// [[Get]] of an element a native Array.prototype loop visits: its
    /// value, the result of its getter when it is an accessor (the
    /// accessor itself leaked as the element), or `None` for a hole.
    pub(super) fn array_index_get(
        &mut self,
        module: Option<&Ir3Module>,
        array_id: ObjectId,
        element_index: usize,
    ) -> Result<Option<Value>, InterpreterError> {
        match self.array_index_value(array_id, element_index)? {
            Some(accessor @ Value::Accessor { .. }) => self
                .resolve_accessor_get(module, accessor, Value::Object(array_id))
                .map(Some),
            element => Ok(element),
        }
    }

    /// Write `element` at `index` of an in-place Array method's receiver, or
    /// delete that index when `element` is `None` (a hole moved there): the
    /// Set / DeletePropertyOrThrow pair the in-place methods' moves make.
    pub(super) fn array_store_or_delete(
        &mut self,
        array_id: ObjectId,
        index: usize,
        element: Option<Value>,
    ) -> Result<(), InterpreterError> {
        match element {
            Some(element) => self.set_object_property(array_id, index.to_string(), element),
            None => self
                .array_delete_or_throw(array_id, &index.to_string())
                .map(|_| ()),
        }
    }

    /// Move the element at `from` to `to` as shift and unshift do: a present
    /// element is read with [[Get]] and written; a hole deletes `to` and sets
    /// `moved_hole`.
    pub(super) fn array_move_element(
        &mut self,
        module: &Ir3Module,
        array_id: ObjectId,
        from: usize,
        to: usize,
        moved_hole: &mut bool,
    ) -> Result<(), InterpreterError> {
        let element = self.array_index_get(Some(module), array_id, from)?;
        *moved_hole |= element.is_none();
        self.array_store_or_delete(array_id, to, element)
    }

    /// The element a native callback loop visits at `index`, or `None` to
    /// skip a hole. A %TypedArray%.prototype method sharing the Array loop
    /// reads with Get alone (ES2024 23.2.3.12 every, .15 forEach, .23
    /// reduce, .24 reduceRight, .28 some: no HasProperty), so an index a
    /// buffer shrink removed during the loop is visited as undefined, where
    /// the Array.prototype method skips it (bd-9vouw.256 made both skip).
    pub(super) fn array_loop_element(
        &mut self,
        module: Option<&Ir3Module>,
        array_id: ObjectId,
        index: usize,
        typed_array_method: bool,
    ) -> Result<Option<Value>, InterpreterError> {
        let element = self.array_index_get(module, array_id, index)?;
        Ok(if typed_array_method {
            Some(element.unwrap_or(Value::Undefined))
        } else {
            element
        })
    }

    /// Whether `builtin` is a %TypedArray%.prototype method that shares an
    /// Array.prototype algorithm (`typed_array_prototype_method`).
    pub(super) fn is_typed_array_prototype_builtin(builtin: &BuiltinFunction) -> bool {
        &*builtin.module_specifier == TYPED_ARRAY_PROTOTYPE_SPECIFIER
    }

    /// One hole visited by a native element loop (bd-9vouw.112).
    pub(super) fn charge_native_hole_read(&self) -> Result<(), InterpreterError> {
        let reads = self.native_hole_reads.get().saturating_add(1);
        self.native_hole_reads.set(reads);
        if self.instructions_executed.saturating_add(reads) > self.config.instruction_budget {
            return Err(InterpreterError::BudgetExhausted {
                executed: self.instructions_executed,
                budget: self.config.instruction_budget,
            });
        }
        Ok(())
    }

    /// One step of AddEntriesFromIterable (ES2020 19.1.2.7 / 23.1.1.2): an
    /// entry that is not an object is a TypeError; its key and value are
    /// Get(entry, "0") and Get(entry, "1") (getters run; a String object is
    /// an entry), then the key goes through ToPropertyKey (its toString
    /// runs). They were read as array elements, so a String object entry or
    /// an accessor entry gave undefined, and an object key read
    /// "[object Object]".
    pub(super) fn set_object_from_entry_pair(
        &mut self,
        module: Option<&Ir3Module>,
        target_id: ObjectId,
        entry: Value,
    ) -> Result<(), InterpreterError> {
        if !entry.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "Object.fromEntries entry object".to_string(),
                got: format!(
                    "Iterator value {} is not an entry object",
                    entry.type_name()
                ),
            });
        }
        let (key_value, value) = match (module, &entry) {
            (Some(module), _) => {
                let key = self.get_v(
                    module,
                    &entry,
                    &RuntimePropertyKey::String(JsString::from("0")),
                )?;
                let value = self.get_v(
                    module,
                    &entry,
                    &RuntimePropertyKey::String(JsString::from("1")),
                )?;
                (self.property_key_primitive(module, key)?, value)
            }
            (None, Value::Object(entry_id)) => (
                self.array_index_value(*entry_id, 0)?
                    .unwrap_or(Value::Undefined),
                self.array_index_value(*entry_id, 1)?
                    .unwrap_or(Value::Undefined),
            ),
            (None, _) => (Value::Undefined, Value::Undefined),
        };
        let key = self.executable_property_key_from_value(&key_value);
        self.set_object_runtime_property(target_id, key, value)
    }

    pub(super) fn object_from_entries_value(
        &mut self,
        module: Option<&Ir3Module>,
        source: Value,
    ) -> Result<Value, InterpreterError> {
        // ES2020 19.1.2.7: `iterable` goes through the iteration protocol
        // (arrays, Map, Set, generators, user iterables). An object used to be
        // read as array-like, so `Object.fromEntries(new Map(...))` gave `{}`
        // (a Map has no `length`).
        let type_name = source.type_name();
        let iterator = match source {
            Value::Iterator(_) => source,
            Value::Undefined | Value::Null => {
                return Err(InterpreterError::TypeError {
                    expected: "iterable entries object".to_string(),
                    got: type_name.to_string(),
                });
            }
            other => self.init_for_of_iterator(module, other)?,
        };
        let target_id = self.alloc_object_with_prototype(None)?;
        while let Some(entry) = self.advance_for_of_iterator(module, iterator.clone())? {
            // IfAbruptCloseIterator: a bad entry, a throwing getter or key
            // conversion closes the iterator (its error wins over return's).
            if let Err(error) = self.set_object_from_entry_pair(module, target_id, entry) {
                return self.array_from_close_after_error(module, iterator, error);
            }
        }
        Ok(Value::Object(target_id))
    }

    /// Append the elements of `src_id` into `result` (an already-allocated
    /// array), recursively flattening any element that is itself an array up to
    /// `depth` further levels (ES2019 `FlattenIntoArray`). `out` tracks the next
    /// write index. Mirrors `Array.prototype.concat`'s one-level spread but
    /// recurses while `depth > 0`.
    /// ES2020 7.3.6 CreateDataPropertyOrThrow for the result objects the
    /// Array methods fill (bd-9vouw.94): the property becomes a writable,
    /// enumerable, configurable data property, replacing a configurable one
    /// whatever its attributes (an @@species constructor may have defined
    /// it non-writable); a non-configurable one, or a new key on a
    /// non-extensible object, is a TypeError. A fresh key takes the plain
    /// store, as before.
    pub(super) fn create_data_property_or_throw(
        &mut self,
        object_id: ObjectId,
        key: String,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let runtime_key = RuntimePropertyKey::String(JsString::from(key.as_str()));
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let Some(property) = object.own_runtime_property_descriptor(&runtime_key) else {
            if !object.extensible() {
                return Err(InterpreterError::TypeError {
                    expected: "extensible object for CreateDataPropertyOrThrow".to_string(),
                    got: format!("non-extensible object without property {key}"),
                });
            }
            return self.set_object_property(object_id, key, value);
        };
        let attributes = object.own_property_attributes(&runtime_key);
        let plain_data = matches!(property, BaselineSymbolProperty::Data(_))
            && attributes.writable
            && attributes.enumerable
            && attributes.configurable;
        if plain_data {
            return self.set_object_property(object_id, key, value);
        }
        if !attributes.configurable {
            return Err(InterpreterError::TypeError {
                expected: "configurable property for CreateDataPropertyOrThrow".to_string(),
                got: format!("non-configurable property {key}"),
            });
        }
        self.set_object_property(object_id, key, value)?;
        self.set_own_property_attributes(
            object_id,
            &runtime_key,
            PropertyAttributes {
                writable: true,
                enumerable: true,
                configurable: true,
            },
        )
    }

    /// Prepare and reserve the label map before writing an indexed array
    /// result. The value writer invokes no guest code and its trailing
    /// descriptor reset only releases memory, so success can publish the
    /// preallocated labels without another fallible operation. On refusal the
    /// original labels remain intact; rollback never allocates.
    pub(super) fn create_labeled_data_property_or_throw(
        &mut self,
        object_id: ObjectId,
        key: String,
        value: Value,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let heap_index = object_id.0 as usize;
        let object = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if label == &Label::Public && object.property_labels.is_empty() {
            return self.create_data_property_or_throw(object_id, key, value);
        }
        let previous_label_bytes =
            Self::estimate_execution_seed_ordered_label_map_bytes(&object.property_labels);
        self.check_temporary_memory_budget(previous_label_bytes)?;
        let mut projected_labels = object.property_labels.clone();
        let property_key = JsString::from(key.as_str());
        if label == &Label::Public {
            projected_labels.remove_exact(&property_key);
        } else {
            projected_labels.insert_exact(property_key, label.clone());
        }
        let projected_label_bytes =
            Self::estimate_execution_seed_ordered_label_map_bytes(&projected_labels);
        // Both maps stay live until the value write either commits or refuses.
        // Include the staged map in every budget check made by that writer.
        self.apply_memory_component_delta(0, projected_label_bytes)?;
        match self.create_data_property_or_throw(object_id, key, value) {
            Ok(()) => {
                self.mutate_heap(|heap| heap[heap_index].property_labels = projected_labels);
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(previous_label_bytes);
                Ok(())
            }
            Err(error) => {
                drop(projected_labels);
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(projected_label_bytes);
                Err(error)
            }
        }
    }

    /// Borrow the first owning string property's label with the same shadowing
    /// and traversal bounds as runtime_property_label, without cloning its name.
    pub(super) fn array_string_property_label_ref(
        &self,
        object_id: ObjectId,
        key: &JsString,
    ) -> Option<&Label> {
        let runtime_key = RuntimePropertyKey::String(key.clone());
        let mut current = Some(object_id);
        let mut depth = 0u32;
        let mut visited = ChainGuard::default();
        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                break;
            }
            let object = self.heap.get(id.0 as usize)?;
            if object.contains_own_runtime_property(&runtime_key) {
                return object.property_labels.get_exact(key);
            }
            current = self.observable_prototype_link(object, id);
            depth += 1;
        }
        None
    }

    /// Join provenance already observed while compacting an array result.
    /// The source length and mutation state matter even when it has no elements.
    pub(super) fn array_result_prefix_label(
        &self,
        source: ObjectId,
        result: ObjectId,
        input_label: &Label,
    ) -> Result<Label, InterpreterError> {
        let length_key = JsString::from("length");
        let mut winner = input_label;
        for candidate in [
            self.array_string_property_label_ref(source, &length_key),
            self.object_mutation_labels.get(&source),
            self.object_mutation_labels.get(&result),
            self.pending_hostcall_result_label.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if candidate > winner {
                winner = candidate;
            }
        }
        // A Custom name can be large. Scan borrowed labels, then preflight
        // both the caller's input temporary and the single winning clone.
        self.clone_dominant_label_with_temporary_budget(
            winner,
            &Label::Public,
            Self::estimate_label_bytes(input_label),
        )
    }

    /// Preserve length provenance on an ordinary Array species result before
    /// writing an element. Its reference may already be held by a Public alias.
    /// Missing-index and HasProperty observations need separate shape tracking.
    pub(super) fn record_array_result_prefix_label(
        &mut self,
        result: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        if label == &Label::Public {
            return Ok(());
        }
        self.join_pending_array_result_label(label)?;
        self.join_object_mutation_label(result, label)?;
        if let Some(object) = self.heap.get(result.0 as usize)
            && object.is_array
        {
            let length_key = JsString::from("length");
            let previous_label = object
                .property_labels
                .get_exact(&length_key)
                .unwrap_or(&Label::Public);
            // The labels form a total order. Keep an already dominant stored
            // label without cloning its name; otherwise the input is the join.
            if previous_label < label {
                self.set_own_runtime_property_label(
                    result,
                    &RuntimePropertyKey::String(length_key),
                    label,
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn array_flatten_into(
        &mut self,
        module: &Ir3Module,
        src_id: ObjectId,
        depth: i64,
        result: ObjectId,
        out: &mut usize,
        source_label: &Label,
    ) -> Result<(), InterpreterError> {
        let mut prefix_label = self.array_result_prefix_label(src_id, result, source_label)?;
        self.record_array_result_prefix_label(result, &prefix_label)?;
        let len = self.array_like_length(src_id)?;
        for i in 0..len {
            // FlattenIntoArray (ES2020 23.1.3.10.1): a hole is skipped and
            // takes no target index, and an element is read with [[Get]], so
            // an accessor element's getter runs (its accessor leaked before).
            let Some(element) = self.array_index_get(Some(module), src_id, i)? else {
                continue;
            };
            let element_key = JsString::from(i.to_string());
            if let Some(element_label) = self.array_string_property_label_ref(src_id, &element_key)
            {
                prefix_label =
                    self.join_owned_label_with_temporary_budget(prefix_label, element_label)?;
            }
            // A recursive empty array may have contributed a length label.
            // Getter returns and earlier callback results also join this prefix.
            prefix_label = self.array_result_prefix_label(src_id, result, &prefix_label)?;
            self.record_array_result_prefix_label(result, &prefix_label)?;
            let nested = if let Value::Object(eid) = &element {
                self.heap
                    .get(eid.0 as usize)
                    .map(|object| object.is_array)
                    .unwrap_or(false)
            } else {
                false
            };
            if depth > 0 && nested {
                if let Value::Object(eid) = element {
                    self.array_flatten_into(module, eid, depth - 1, result, out, &prefix_label)?;
                }
            } else {
                self.create_labeled_data_property_or_throw(
                    result,
                    out.to_string(),
                    element,
                    &prefix_label,
                )?;
                *out += 1;
            }
        }
        Ok(())
    }

    /// Whether the array's dense-length fast-path cache is currently populated.
    /// Captured *before* an in-place mutation so the cache can be re-established
    /// afterwards (the property set/remove helpers conservatively clear it).
    pub(super) fn array_cache_is_dense(&self, array_id: ObjectId) -> bool {
        self.heap
            .get(array_id.0 as usize)
            .map(|object| object.cached_dense_length.is_some())
            .unwrap_or(false)
    }

    /// Whether the runtime-maintained dense cache agrees with the visible
    /// integral Array length. A populated but stale low-level cache is not
    /// authority for a mutation shortcut.
    pub(super) fn array_cache_matches_visible_length(
        &self,
        array_id: ObjectId,
        length: usize,
    ) -> bool {
        let Ok(cached_length) = u32::try_from(length) else {
            return false;
        };
        self.heap.get(array_id.0 as usize).is_some_and(|object| {
            object.is_array
                && object.cached_dense_length == Some(cached_length)
                && matches!(
                    object.properties.get("length"),
                    Some(Value::Int(visible_length))
                        if usize::try_from(*visible_length)
                            .is_ok_and(|visible_length| visible_length == length)
                )
        })
    }

    /// Finish receiver-aware `Array.prototype.pop` after a trusted dense tail
    /// was removed. The general Array `length` setter must enumerate every own
    /// property on shrink because arbitrary sparse indices may need deletion.
    /// Here the dense cache matched `old_length`, the exact tail removal
    /// succeeded, and this helper rechecks that the visible state still has the
    /// expected shape. Updating the remaining `length` entry therefore cannot
    /// truncate another index and needs no carrier scan. Any failed recheck
    /// returns `false` so the caller preserves the conservative setter path.
    pub(super) fn set_array_length_after_dense_tail_removal(
        &mut self,
        array_id: ObjectId,
        old_length: usize,
        new_length: usize,
        removed_tail_key: &str,
    ) -> Result<bool, InterpreterError> {
        let heap_index = array_id.0 as usize;
        let Some(object) = self.heap.get(heap_index) else {
            return Err(InterpreterError::ObjectNotFound { id: array_id.0 });
        };
        // A low-level write at exactly the visible length does not invalidate
        // the cache, yet a subsequent shrink must delete that boundary index.
        // Larger out-of-bounds writes do invalidate the cache, so this single
        // lookup closes the only trusted-cache escape without restoring a scan.
        let boundary_index_key = u32::try_from(old_length)
            .ok()
            .filter(|index| *index != u32::MAX)
            .map(|index| index.to_string());
        if !object.is_array
            || object.is_frozen
            || old_length.checked_sub(1) != Some(new_length)
            || object.properties.exact_len() != object.properties.len()
            || object.properties.get(removed_tail_key).is_some()
            || boundary_index_key
                .as_ref()
                .is_some_and(|key| object.properties.get(key).is_some())
            || !matches!(
                object.properties.get("length"),
                Some(Value::Int(visible_length))
                    if usize::try_from(*visible_length)
                        .is_ok_and(|visible_length| visible_length == old_length)
            )
        {
            return Ok(false);
        }

        let Ok(cached_length) = u32::try_from(new_length) else {
            return Ok(false);
        };
        let new_length_value = Value::Int(i64::from(cached_length));
        let previous_bytes = object.properties.get("length").map_or(0, |previous| {
            Self::estimate_property_entry_bytes("length", previous)
        });
        let new_bytes = Self::estimate_property_entry_bytes("length", &new_length_value);
        self.apply_memory_component_delta(previous_bytes, new_bytes)?;
        self.mutate_heap(|heap| {
            let object = &mut heap[heap_index];
            let length = object
                .properties
                .get_mut("length")
                .expect("visible length was checked immediately before mutation");
            *length = new_length_value;
            object.cached_dense_length = Some(cached_length);
        });
        self.gc_write_barrier(array_id);
        Ok(true)
    }

    /// Whether shift and unshift may move this array's elements inside its
    /// property carrier: the generic algorithm's per-element steps observe
    /// nothing. No hole (the dense cache matches the visible length, so no
    /// lookup reaches the prototype chain), no accessor element, no attribute
    /// on an index or on `length`, no IFC label on an index, not frozen, not
    /// a typed array, no exact-only key. Then each [[Get]] is a plain own
    /// data read and each [[Set]] replaces a data value whose label and
    /// attributes stay with the position (bd-9vouw.472).
    pub(super) fn dense_array_moves_are_plain(
        &self,
        array_id: ObjectId,
        len: usize,
    ) -> Result<bool, InterpreterError> {
        if !self.array_cache_matches_visible_length(array_id, len) {
            return Ok(false);
        }
        let Some(slot) = self.heap.slot(array_id.0 as usize) else {
            return Err(InterpreterError::ObjectNotFound { id: array_id.0 });
        };
        if let Some(plain) = slot.dense_moves_plain.get() {
            return Ok(plain);
        }
        let object = &slot.object;
        let attributed = object.property_attributes.keys().any(|key| match key {
            RuntimePropertyKey::String(name) => name.as_str().is_some_and(|name| {
                name == "length" || Self::canonical_array_index_key(name).is_some()
            }),
            RuntimePropertyKey::Symbol(_) => false,
        });
        let plain = !(attributed
            || object.is_frozen
            || object.typed_array.is_some()
            || object.properties.exact_len() != object.properties.len()
            || object.property_labels.has_index_keys()
            || object
                .properties
                .index_values()
                .any(|value| matches!(value, Value::Accessor { .. })));
        slot.dense_moves_plain.set(Some(plain));
        Ok(plain)
    }

    /// `Array.prototype.shift` on an array `dense_array_moves_are_plain`
    /// admits: the values move down one index inside the property carrier,
    /// the last index entry goes with its exact estimate and `length` is
    /// written without the shrink scan. Returns the shifted value, or `None`
    /// with nothing changed when the array does not qualify (bd-9vouw.472).
    pub(super) fn shift_dense_array_in_place(
        &mut self,
        array_id: ObjectId,
        len: usize,
    ) -> Result<Option<Value>, InterpreterError> {
        let (Ok(len_u32), Some(last)) = (u32::try_from(len), len.checked_sub(1)) else {
            return Ok(None);
        };
        if !self.dense_array_moves_are_plain(array_id, len)? {
            return Ok(None);
        }
        let heap_index = array_id.0 as usize;
        let Some(first) = self.heap[heap_index].properties.get_index(0) else {
            return Ok(None);
        };
        let last_key = last.to_string();
        // Moved, the carrier has lost exactly the entry `last_key` holding
        // the first value: the estimate is a sum over entries.
        let removed_bytes = Self::estimate_property_entry_bytes(&last_key, first);
        let mut shifted = None;
        self.mutate_heap(|heap| {
            shifted = heap[heap_index]
                .properties
                .shift_dense_index_values(len_u32);
        });
        let Some(shifted) = shifted else {
            return Ok(None);
        };
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(removed_bytes);
        if !self.set_array_length_after_dense_tail_removal(array_id, len, last, &last_key)? {
            let new_len = i64::try_from(last).unwrap_or(i64::MAX);
            self.set_object_property(array_id, "length".to_string(), Value::Int(new_len))?;
            self.refresh_dense_length_cache(array_id, last, true);
        }
        // The guarded move only removes a plain own element. All mutable
        // borrows above invalidated the cache; re-establish its proof after
        // the final length write, without rescanning every surviving value.
        self.heap
            .slot(heap_index)
            .expect("shifted array remains live")
            .dense_moves_plain
            .set(Some(true));
        Ok(Some(shifted))
    }

    /// `Array.prototype.unshift` of `items` onto an extensible array that
    /// `dense_array_moves_are_plain` admits: the items take the first indices
    /// and the existing values move up inside the property carrier, so only
    /// the new top entries are added. Their estimate is checked against the
    /// memory budget before anything changes. Returns the new length, or the
    /// items back with nothing changed when the array does not qualify
    /// (bd-9vouw.472).
    pub(super) fn unshift_dense_array_in_place(
        &mut self,
        array_id: ObjectId,
        len: usize,
        items: Vec<Value>,
    ) -> Result<Result<usize, Vec<Value>>, InterpreterError> {
        let fits = |length: usize| u32::try_from(length).is_ok();
        let Some(new_len) = len
            .checked_add(items.len())
            .filter(|new_len| fits(*new_len))
        else {
            return Ok(Err(items));
        };
        let Ok(len_u32) = u32::try_from(len) else {
            return Ok(Err(items));
        };
        if !self.dense_array_moves_are_plain(array_id, len)?
            || !self.heap[array_id.0 as usize].extensible()
        {
            return Ok(Err(items));
        }
        let inserted_are_plain = items
            .iter()
            .all(|item| !matches!(item, Value::Accessor { .. }));
        for item in &items {
            validate_symbol_value(&self.symbol_state, item).map_err(|got| {
                InterpreterError::TypeError {
                    expected: "resolved Symbol value".to_string(),
                    got,
                }
            })?;
        }
        // The carrier gains exactly the entries `len..new_len`; the estimate
        // is a sum over entries, and the values only move, so the gain is
        // those keys' entries holding the items.
        let added_bytes =
            Self::saturating_sum((len..new_len).zip(&items).map(|(index, item)| {
                Self::estimate_property_entry_bytes(&index.to_string(), item)
            }));
        let requested_bytes = self.estimated_memory_bytes.saturating_add(added_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        let heap_index = array_id.0 as usize;
        let refused = self.mutate_heap(|heap| {
            heap[heap_index]
                .properties
                .unshift_dense_index_values(len_u32, items)
                .err()
        });
        if let Some(items) = refused {
            return Ok(Err(items));
        }
        self.estimated_memory_bytes = requested_bytes;
        let new_len_int = i64::try_from(new_len).unwrap_or(i64::MAX);
        self.set_object_property(array_id, "length".to_string(), Value::Int(new_len_int))?;
        self.refresh_dense_length_cache(array_id, new_len, true);
        self.gc_write_barrier(array_id);
        self.heap
            .slot(heap_index)
            .expect("unshifted array remains live")
            .dense_moves_plain
            .set(Some(inserted_are_plain));
        Ok(Ok(new_len))
    }

    /// `Array.prototype.splice` on an array `dense_array_moves_are_plain`
    /// admits (and that is extensible when it grows): the deleted values
    /// leave, the items take their place and the values after them move
    /// inside the property carrier, entries changing only at the top. The
    /// estimate changes by exactly the top keys added or removed and the
    /// values exchanged, checked against the memory budget before anything
    /// changes. Returns the deleted values in order, or the items back with
    /// nothing changed when the array does not qualify (bd-9vouw.472).
    pub(super) fn splice_dense_array_in_place(
        &mut self,
        array_id: ObjectId,
        len: usize,
        start: usize,
        delete_count: usize,
        items: Vec<Value>,
    ) -> Result<Result<Vec<Value>, Vec<Value>>, InterpreterError> {
        let as_u32 = |count: usize| u32::try_from(count).ok();
        let (Some(len_u32), Some(start_u32), Some(delete_u32)) =
            (as_u32(len), as_u32(start), as_u32(delete_count))
        else {
            return Ok(Err(items));
        };
        let Some(new_len) = len
            .checked_sub(delete_count)
            .and_then(|kept| kept.checked_add(items.len()))
            .filter(|new_len| as_u32(*new_len).is_some())
        else {
            return Ok(Err(items));
        };
        if start.checked_add(delete_count).is_none_or(|end| end > len)
            || !self.dense_array_moves_are_plain(array_id, len)?
            || (new_len > len && !self.heap[array_id.0 as usize].extensible())
        {
            return Ok(Err(items));
        }
        let inserted_are_plain = items
            .iter()
            .all(|item| !matches!(item, Value::Accessor { .. }));
        for item in &items {
            validate_symbol_value(&self.symbol_state, item).map_err(|got| {
                InterpreterError::TypeError {
                    expected: "resolved Symbol value".to_string(),
                    got,
                }
            })?;
        }
        // The estimate is a sum over entries: an entry is its key's part
        // (the entry with an undefined value, which costs nothing) plus its
        // value's bytes. Keys change only at the top; values are exchanged.
        let heap_index = array_id.0 as usize;
        let key_bytes = |index: usize| {
            Self::estimate_property_entry_bytes(&index.to_string(), &Value::Undefined)
        };
        let properties = &self.heap[heap_index].properties;
        let deleted_value_bytes =
            Self::saturating_sum((start..start + delete_count).map(|index| {
                u32::try_from(index)
                    .ok()
                    .and_then(|index| properties.get_index(index))
                    .map_or(0, Self::estimate_value_bytes)
            }));
        let added_bytes = Self::saturating_sum((len..new_len).map(key_bytes)).saturating_add(
            Self::saturating_sum(items.iter().map(Self::estimate_value_bytes)),
        );
        let removed_bytes =
            Self::saturating_sum((new_len..len).map(key_bytes)).saturating_add(deleted_value_bytes);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_add(added_bytes)
            .saturating_sub(removed_bytes);
        if added_bytes > removed_bytes
            && self
                .memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes)
        {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        let outcome = self.mutate_heap(|heap| {
            heap[heap_index]
                .properties
                .splice_dense_index_values(len_u32, start_u32, delete_u32, items)
        });
        let removed = match outcome {
            Ok(removed) => removed,
            Err(items) => return Ok(Err(items)),
        };
        self.estimated_memory_bytes = requested_bytes;
        if new_len != len {
            // Admission proved a writable own Int length, and successful
            // carrier mutation proves exactly the new dense prefix. No guest
            // callback occurs between those steps, so no further index can
            // need truncation. Preserve the length's label/attributes while
            // avoiding the generic setter's full scan on a batch shrink.
            let new_len_u32 = as_u32(new_len).expect("new array length was checked");
            let new_length = Value::Int(i64::from(new_len_u32));
            let previous_bytes = self.heap[heap_index]
                .properties
                .get("length")
                .map_or(0, |previous| {
                    Self::estimate_property_entry_bytes("length", previous)
                });
            let next_bytes = Self::estimate_property_entry_bytes("length", &new_length);
            self.apply_memory_component_delta(previous_bytes, next_bytes)?;
            self.mutate_heap(|heap| {
                let object = &mut heap[heap_index];
                *object
                    .properties
                    .get_mut("length")
                    .expect("dense splice preserves the admitted length property") = new_length;
                object.cached_dense_length = Some(new_len_u32);
            });
        }
        self.gc_write_barrier(array_id);
        // The admission guard proved every surviving element plain. Only
        // inserted values can change that fact; retain it after the length
        // write so repeated prefix splices do not rescan the whole suffix.
        self.heap
            .slot(heap_index)
            .expect("spliced array remains live")
            .dense_moves_plain
            .set(Some(inserted_are_plain));
        Ok(Ok(removed))
    }

    /// Re-establish the dense-length cache after a contiguous in-place array
    /// mutation (pop/shift/unshift keep the array dense). `set_object_property`
    /// and `remove_object_property` clear the cache defensively; this restores
    /// it to `new_len` only when the array was dense beforehand, mirroring the
    /// coherence the IR `ArrayPush` fast path expects (see `ArrayPush` dispatch).
    pub(super) fn refresh_dense_length_cache(
        &mut self,
        array_id: ObjectId,
        new_len: usize,
        was_dense: bool,
    ) {
        if !was_dense {
            return;
        }
        let arr_index = array_id.0 as usize;
        let cached_len = u32::try_from(new_len).ok();
        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(arr_index)
                && object.is_array
            {
                object.cached_dense_length = cached_len;
            }
        });
    }

    /// Maintain the array invariants after a user-level `arr[i] = x` index
    /// assignment (the IR3 `SetProperty` path). The array builtins manage
    /// these themselves around their `set_object_property` calls; plain index
    /// assignment is the one path that previously left both stale, so
    /// `a[a.length] = x; a.push(y)` overwrote `x` and lost a slot (a sibling
    /// of the splice dense-length-cache bug):
    ///
    /// 1. **ES2020 array length** (23.1 array exotic `[[Set]]`): when `index`
    ///    is at or past the current `length`, grow `length` to `index + 1`.
    /// 2. **Dense-length cache** that the `ArrayPush` fast path trusts as the
    ///    next write index: grow by one on a dense append (`index == dense`),
    ///    invalidate on a sparse gap (`index > dense`), and leave it untouched
    ///    on an in-bounds overwrite (`index < dense`). `set_object_property`
    ///    has already invalidated on the gap case before this runs, so the
    ///    `Some` branch here only needs the dense-append growth.
    pub(super) fn maintain_array_index_assignment(
        &mut self,
        array_id: ObjectId,
        index: u32,
    ) -> Result<(), InterpreterError> {
        let arr_index = array_id.0 as usize;

        // Compute the grown length before mutating the heap. The first index
        // assignment on an array without a `length` entry creates one here.
        // Route that insertion through the ordinary property setter so an
        // exact-active carrier accounts both hidden order sidecars as well as
        // the visible entry (bd-b12xs.5).
        let grown_length = match self.heap.get(arr_index) {
            Some(object) if object.is_array => {
                let current_len = match object.properties.get("length") {
                    Some(Value::Int(n)) if *n >= 0 => *n as u64,
                    _ => 0,
                };
                if u64::from(index) >= current_len {
                    let grown =
                        i64::try_from(u64::from(index).saturating_add(1)).unwrap_or(i64::MAX);
                    Some(grown)
                } else {
                    None
                }
            }
            _ => return Ok(()),
        };

        if let Some(grown) = grown_length {
            // Setting `length` normally refreshes the dense cache. Preserve
            // the state established by the preceding index write so a sparse
            // gap stays sparse; the update below then advances a dense append.
            let cached_dense_length = self.heap[arr_index].cached_dense_length;
            self.set_object_property(array_id, "length".to_string(), Value::Int(grown))?;
            self.mutate_heap(|heap| {
                heap[arr_index].cached_dense_length = cached_dense_length;
            });
        }

        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(arr_index)
                && object.is_array
                && let Some(dense_len) = object.cached_dense_length
            {
                if index == dense_len {
                    object.cached_dense_length = Some(dense_len.saturating_add(1));
                } else if index > dense_len {
                    object.cached_dense_length = None;
                }
            }
        });
        Ok(())
    }

    /// Read the `index`th positional argument of a builtin call, or `None` when
    /// fewer arguments were supplied. Shared by the non-callback
    /// `Array.prototype` methods (bd-962ev.1) for their optional parameters.
    /// Every argument of a register-staged builtin call, in order.
    pub(super) fn builtin_argument_values(
        &self,
        args: RegRange,
    ) -> Result<Vec<Value>, InterpreterError> {
        (0..args.count)
            .map(|offset| {
                let register = args.start.checked_add(offset).ok_or(
                    InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    },
                )?;
                self.read_reg(register)
            })
            .collect()
    }

    /// ES2020 7.1.4 ToNumber for a numeric builtin argument. Objects go
    /// through ToPrimitive (hint Number), which may run guest
    /// valueOf/toString; strings use StringToNumber; BigInt and Symbol are
    /// TypeErrors. A coercion's result label joins `label`.
    pub(super) fn builtin_argument_to_number(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
        label: &mut Option<Label>,
    ) -> Result<f64, InterpreterError> {
        let primitive = if value.is_object_like() {
            let primitive = self.coerce_runtime_primitive(module, value, false)?;
            if let Some(pending) = self.take_pending_hostcall_result_label() {
                *label = Some(match label.take() {
                    Some(existing) => {
                        self.join_owned_label_with_temporary_budget(existing, &pending)?
                    }
                    None => pending,
                });
            }
            primitive
        } else {
            value
        };
        match &primitive {
            Value::Str(text) => Ok(primitive_conversion::string_number(text)),
            Value::BigInt(_) | Value::Symbol(_) => Err(InterpreterError::TypeError {
                expected: "Number-convertible builtin argument".to_string(),
                got: primitive.type_name().to_string(),
            }),
            other => Ok(Self::coerce_to_float(other).unwrap_or(f64::NAN)),
        }
    }

    /// Join a label collected while converting builtin arguments into the
    /// pending hostcall result label.
    pub(super) fn join_into_pending_hostcall_result_label(
        &mut self,
        label: Option<Label>,
    ) -> Result<(), InterpreterError> {
        let Some(label) = label else {
            return Ok(());
        };
        let merged = match self.take_pending_hostcall_result_label() {
            Some(pending) => self.join_owned_label_with_temporary_budget(pending, &label)?,
            None => label,
        };
        self.replace_pending_hostcall_result_label(Some(merged))
    }

    /// `Math.max` (`is_max`) / `Math.min`, ES2020 20.2.2.24/.25. Every
    /// argument is converted first, in order. Any NaN makes the result NaN.
    /// +0 beats -0 for max and -0 beats +0 for min. An all-integer list keeps
    /// an Int result.
    pub(super) fn math_extremum(
        &mut self,
        module: Option<&Ir3Module>,
        values: Vec<Value>,
        is_max: bool,
    ) -> Result<Value, InterpreterError> {
        let mut label = None;
        let mut numbers = Vec::with_capacity(values.len());
        let mut integers = Vec::with_capacity(values.len());
        for value in values {
            match value {
                Value::Int(integer) => {
                    integers.push(integer);
                    numbers.push(integer as f64);
                }
                other => numbers.push(self.builtin_argument_to_number(module, other, &mut label)?),
            }
        }
        self.join_into_pending_hostcall_result_label(label)?;
        if !numbers.is_empty() && integers.len() == numbers.len() {
            let extremum = if is_max {
                integers.iter().copied().max()
            } else {
                integers.iter().copied().min()
            };
            return Ok(Value::Int(extremum.expect("non-empty integer list")));
        }
        let mut result = if is_max {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
        for number in numbers {
            if number.is_nan() {
                return Ok(Value::Float(Float64::new(f64::NAN)));
            }
            let better = if is_max {
                number > result || (number == 0.0 && result == 0.0 && result.is_sign_negative())
            } else {
                number < result || (number == 0.0 && result == 0.0 && number.is_sign_negative())
            };
            if better {
                result = number;
            }
        }
        Ok(Value::Float(Float64::new(result)))
    }

    /// `String.fromCharCode`, ES2020 21.1.2.1: ToUint16(ToNumber(code)) per
    /// argument. Surrogate units stay lone units (bd-neika) and heal into a
    /// supplementary code point when a pair is adjacent.
    pub(super) fn string_from_char_code(
        &mut self,
        module: Option<&Ir3Module>,
        values: Vec<Value>,
    ) -> Result<Value, InterpreterError> {
        self.check_string_limit(values.len())?;
        let mut label = None;
        let mut units: Vec<u16> = Vec::with_capacity(values.len());
        for value in values {
            let code = match value {
                // Modular ToUint32 then ToUint16, as `js_to_uint32` does for
                // floats (`fromCharCode(-1.5)` is 0xFFFF).
                Value::Int(integer) => integer as u32,
                other => {
                    Self::js_to_uint32(self.builtin_argument_to_number(module, other, &mut label)?)
                }
            };
            units.push((code & 0xFFFF) as u16);
        }
        self.join_into_pending_hostcall_result_label(label)?;
        Ok(Value::Str(JsString::from_code_units(&units)))
    }

    /// `String.fromCodePoint`, ES2020 21.1.2.2: each ToNumber(argument) must
    /// be an integral code point in 0..=0x10FFFF (surrogates included), else
    /// RangeError.
    pub(super) fn string_from_code_point(
        &mut self,
        module: Option<&Ir3Module>,
        values: Vec<Value>,
    ) -> Result<Value, InterpreterError> {
        self.check_string_limit(values.len())?;
        let mut label = None;
        let mut units: Vec<u16> = Vec::with_capacity(values.len());
        for value in values {
            let number = match value {
                Value::Int(integer) => integer as f64,
                other => self.builtin_argument_to_number(module, other, &mut label)?,
            };
            if !number.is_finite()
                || number.fract() != 0.0
                || !(0.0..=0x10FFFF as f64).contains(&number)
            {
                return Err(InterpreterError::RangeError {
                    message: format!("String.fromCodePoint invalid code point: {number}"),
                });
            }
            let code_point = number as u32;
            if code_point < 0x10000 {
                units.push(code_point as u16);
            } else {
                let offset = code_point - 0x10000;
                units.push(0xD800 + (offset >> 10) as u16);
                units.push(0xDC00 + (offset & 0x3FF) as u16);
            }
        }
        self.check_string_limit(units.len())?;
        self.join_into_pending_hostcall_result_label(label)?;
        Ok(Value::Str(JsString::from_code_units(&units)))
    }

    /// Hostcall tags of the variadic builtins that can consume an argument
    /// list longer than a register frame (bd-9vouw.50).
    pub(super) fn is_vector_variadic_tag(tag: &str) -> bool {
        matches!(
            tag,
            "builtin:MathMax"
                | "builtin:MathMin"
                | "builtin:StringFromCharCode"
                | "builtin:StringFromCodePoint"
        )
    }

    /// The vector-variadic hostcall tag a callable builtin value runs, and
    /// whether calling it checks the capability gate (static hostcall
    /// values do).
    pub(super) fn vector_variadic_builtin_tag(value: &Value) -> Option<(&'static str, bool)> {
        let Value::BuiltinFunction(builtin) = value else {
            return None;
        };
        match builtin.kind {
            BuiltinFunctionKind::MathMax => Some(("builtin:MathMax", false)),
            BuiltinFunctionKind::MathMin => Some(("builtin:MathMin", false)),
            BuiltinFunctionKind::StaticHostcall => match &*builtin.module_specifier {
                "builtin:StringFromCharCode" => Some(("builtin:StringFromCharCode", true)),
                "builtin:StringFromCodePoint" => Some(("builtin:StringFromCodePoint", true)),
                _ => None,
            },
            _ => None,
        }
    }

    /// Run a vector-variadic builtin over an argument vector.
    pub(super) fn dispatch_vector_variadic_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        tag: &str,
        values: Vec<Value>,
    ) -> Result<Value, InterpreterError> {
        match tag {
            "builtin:MathMax" => self.math_extremum(module, values, true),
            "builtin:MathMin" => self.math_extremum(module, values, false),
            "builtin:StringFromCharCode" => self.string_from_char_code(module, values),
            "builtin:StringFromCodePoint" => self.string_from_code_point(module, values),
            other => Err(InterpreterError::InternalError {
                details: format!("{other} is not a vector-variadic builtin"),
            }),
        }
    }

    /// An `apply` of a vector-variadic builtin whose list does not fit a
    /// register frame. The result label joins `context` and every argument
    /// label.
    pub(super) fn apply_vector_variadic_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        (tag, gated): (&'static str, bool),
        values: Vec<Value>,
        argument_labels: &IsolatedArgumentLabels,
        context: Label,
    ) -> Result<(Value, Label), InterpreterError> {
        if gated {
            let instruction_index = u32::try_from(self.ip).unwrap_or(u32::MAX);
            check_hostcall_capability_gate(self, tag, instruction_index)?;
        }
        let mut label = context;
        match argument_labels {
            IsolatedArgumentLabels::Public => {}
            IsolatedArgumentLabels::Exact(labels) => {
                for argument_label in labels {
                    label = self.join_owned_label_with_temporary_budget(label, argument_label)?;
                }
            }
            IsolatedArgumentLabels::Uniform(argument_label) => {
                label = self.join_owned_label_with_temporary_budget(label, argument_label)?;
            }
        }
        self.clear_pending_hostcall_result_label();
        let value = self.dispatch_vector_variadic_builtin(module, tag, values)?;
        if let Some(pending) = self.take_pending_hostcall_result_label() {
            label = self.join_owned_label_with_temporary_budget(label, &pending)?;
        }
        Ok((value, label))
    }

    pub(super) fn builtin_arg(
        &self,
        args: RegRange,
        index: u32,
    ) -> Result<Option<Value>, InterpreterError> {
        if index >= args.count {
            return Ok(None);
        }
        let reg = args
            .start
            .checked_add(index)
            .ok_or(InterpreterError::RegisterOutOfBounds {
                register: args.start,
                max: self.config.max_registers,
            })?;
        Ok(Some(self.read_reg(reg)?))
    }

    pub(super) fn f64_as_integer(value: f64) -> i64 {
        if value.is_nan() {
            0
        } else {
            value.trunc() as i64
        }
    }

    /// `ToIntegerOrInfinity`-style coercion for integer index/count arguments:
    /// numbers and numeric strings truncate toward zero, `NaN` contributes 0,
    /// and non-numeric values fall back to the existing primitive defaults.
    pub(super) fn value_as_integer(value: &Value) -> i64 {
        match value {
            Value::Int(n) => *n,
            Value::Float(f) => Self::f64_as_integer(f.inner()),
            Value::Bool(true) => 1,
            // StringToNumber (ES2020 7.1.4.1.1): "0x0003" is 3, "Infinity"
            // saturates, "inf" is NaN (0). Rust's float parser read "0x0003"
            // as 0 and accepted spellings JavaScript does not.
            Value::Str(s) => Self::f64_as_integer(primitive_conversion::string_number(s)),
            _ => 0,
        }
    }

    /// ToIntegerOrInfinity's ToNumber step (ES2020 7.1.5, 7.1.4) for a
    /// `fromIndex` argument: a Symbol or BigInt throws a TypeError. They were
    /// read as 0, so `[1].indexOf(7, Symbol())` searched instead of throwing.
    pub(super) fn require_number_coercible_index(
        value: &Value,
        method: &str,
    ) -> Result<(), InterpreterError> {
        if matches!(value, Value::Symbol(_) | Value::BigInt(_)) {
            return Err(InterpreterError::TypeError {
                expected: format!("a fromIndex convertible to a Number for {method}"),
                got: value.type_name().to_string(),
            });
        }
        Ok(())
    }

    /// Clamp a possibly-negative relative array index into `[0, len]`, per the
    /// `Array.prototype` convention where a negative index counts from the end.
    pub(super) fn clamp_relative_index(raw: i64, len: usize) -> usize {
        let len_i = len as i64;
        let idx = if raw < 0 {
            (len_i + raw).max(0)
        } else {
            raw.min(len_i)
        };
        idx as usize
    }

    /// `SameValueZero` only differs from strict equality (`values_equal`) in
    /// treating `NaN` as equal to `NaN`; `Array.prototype.includes` needs that.
    pub(super) fn both_nan(a: &Value, b: &Value) -> bool {
        matches!(
            (a, b),
            (Value::Float(x), Value::Float(y)) if x.inner().is_nan() && y.inner().is_nan()
        )
    }

    /// Extract `(array, callback, thisArg, length)` for a receiver-aware
    /// `Array.prototype` callback method (`arr.map(fn, thisArg)`): the array is
    /// the `this` receiver, the callback is the first argument, the optional
    /// `thisArg` is the second (bd-962ev.2). A non-array receiver is a TypeError.
    pub(super) fn array_callback_receiver(
        &self,
        receiver: Option<Value>,
        args: RegRange,
        typed_array_method: bool,
        method: &str,
    ) -> Result<(ObjectId, Value, Value, usize), InterpreterError> {
        let receiver = receiver.unwrap_or(Value::Undefined);
        let Value::Object(arr_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: format!("array receiver for {method}"),
                got: receiver.type_name().to_string(),
            });
        };
        let callback = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let this_arg = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let len = self.array_method_length(arr_id, typed_array_method)?;
        // IsCallable(callbackfn) before the first element, so an empty or
        // all-holes array still throws.
        if !callback.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: format!("a callable callback for {method}"),
                got: format!("{} is not a function", callback.type_name()),
            });
        }
        Ok((arr_id, callback, this_arg, len))
    }

    /// Receiver-aware `Array.prototype.reduce`/`reduceRight` (bd-962ev.2): the
    /// array is the `this` receiver, the callback is arg0, and the optional
    /// initial value is arg1. `reverse` selects the fold direction. Reuses the
    /// existing `invoke_simple_reduce_callback` accumulator machinery.
    pub(super) fn array_reduce_receiver(
        &mut self,
        module: &Ir3Module,
        receiver: Option<Value>,
        args: RegRange,
        reverse: bool,
        typed_array_method: bool,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let method = if reverse {
            "Array.prototype.reduceRight"
        } else {
            "Array.prototype.reduce"
        };
        self.with_array_reduction_observation(args, receiver_register, |core| {
            core.array_reduce_receiver_inner(
                module,
                receiver,
                args,
                reverse,
                typed_array_method,
                method,
            )
        })
    }

    pub(super) fn array_reduce_receiver_inner(
        &mut self,
        module: &Ir3Module,
        receiver: Option<Value>,
        args: RegRange,
        reverse: bool,
        typed_array_method: bool,
        method: &str,
    ) -> Result<Value, InterpreterError> {
        let receiver = receiver.unwrap_or(Value::Undefined);
        let Value::Object(arr_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: format!("array receiver for {method}"),
                got: receiver.type_name().to_string(),
            });
        };
        let callback = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        self.observe_array_reduction_length(arr_id, typed_array_method)?;
        let length = self.array_method_length(arr_id, typed_array_method)?;
        if !callback.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: format!("a callable callback for {method}"),
                got: format!("{} is not a function", callback.type_name()),
            });
        }
        let has_initial = args.count > 1;
        // Guest-selected sparse lengths must not allocate an index vector
        // before the first bounded property observation.
        let mut iter = (0..length).map(|offset| if reverse { length - 1 - offset } else { offset });
        let mut accumulator = if has_initial {
            self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined)
        } else {
            let mut seed = None;
            for idx in iter.by_ref() {
                if let Some(value) =
                    self.array_reduction_element(Some(module), arr_id, idx, typed_array_method)?
                {
                    seed = Some(value);
                    break;
                }
            }
            match seed {
                Some(value) => value,
                None => {
                    return Err(InterpreterError::TypeError {
                        expected: "non-empty array or initialValue".to_string(),
                        got: format!("empty {method} without initialValue"),
                    });
                }
            }
        };
        for idx in iter {
            let Some(current) =
                self.array_reduction_element(Some(module), arr_id, idx, typed_array_method)?
            else {
                continue;
            };
            accumulator = self.invoke_simple_reduce_callback(
                Some(module),
                &callback,
                accumulator,
                current,
                idx,
                arr_id,
            )?;
        }
        Ok(accumulator)
    }

    /// Default `Array.prototype.sort` ordering key: the element's string form
    /// (ES sorts by `ToString` when no comparator is given).
    /// The UTF-16 code units of a primitive's ToString, which SortCompare
    /// orders (ES2020 22.1.3.27.1); code point order differs once a string
    /// holds both astral and U+E000..U+FFFF characters.
    pub(super) fn sort_utf16_key(value: &Value) -> Vec<u16> {
        match value {
            Value::Str(text) => text.encode_utf16().collect(),
            other => Self::sort_string_key(other).encode_utf16().collect(),
        }
    }

    pub(super) fn sort_string_key(value: &Value) -> String {
        match value {
            Value::Str(s) => s.to_string(),
            Value::BigInt(digits) => digits.to_string(),
            Value::Int(n) => n.to_string(),
            Value::Float(f) => f.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "null".to_string(),
            Value::Undefined => "undefined".to_string(),
            _ => String::new(),
        }
    }

    /// Stable bottom-up merge sort by a comparator (ES2019+ requires a stable
    /// sort): O(n log n) comparator calls, where the insertion sort this
    /// replaces made O(n^2) (5,000 elements took minutes). The comparator
    /// re-enters the interpreter, so no closure borrows `self`; an abrupt
    /// comparator leaves the caller's array untouched.
    pub(super) fn merge_sort_with_comparator(
        &mut self,
        module: &Ir3Module,
        comparator: &Value,
        elements: Vec<Value>,
    ) -> Result<Vec<Value>, InterpreterError> {
        let len = elements.len();
        let mut source = elements;
        let mut merged: Vec<Value> = Vec::with_capacity(len);
        let mut width = 1usize;
        while width < len {
            merged.clear();
            let mut start = 0usize;
            while start < len {
                let middle = start.saturating_add(width).min(len);
                let end = start.saturating_add(width.saturating_mul(2)).min(len);
                let (mut left, mut right) = (start, middle);
                while left < middle && right < end {
                    // Take the right run's element only when it orders strictly
                    // before the left one, which keeps equal elements stable.
                    let ordering =
                        self.sort_compare(module, comparator, &source[left], &source[right])?;
                    if ordering == std::cmp::Ordering::Greater {
                        merged.push(source[right].clone());
                        right += 1;
                    } else {
                        merged.push(source[left].clone());
                        left += 1;
                    }
                }
                merged.extend_from_slice(&source[left..middle]);
                merged.extend_from_slice(&source[right..end]);
                start = end;
            }
            std::mem::swap(&mut source, &mut merged);
            width = width.saturating_mul(2);
        }
        Ok(source)
    }

    /// Compare two elements via a user `Array.prototype.sort` comparator: the
    /// sign of `ToNumber(comparator(a, b))` gives the order (negative → a
    /// first); NaN is treated as equal.
    pub(super) fn sort_compare(
        &mut self,
        module: &Ir3Module,
        comparator: &Value,
        a: &Value,
        b: &Value,
    ) -> Result<std::cmp::Ordering, InterpreterError> {
        let result = self.invoke_inline_method_call(
            Some(module),
            comparator.clone(),
            Value::Undefined,
            vec![a.clone(), b.clone()],
        )?;
        // ToNumber of the result: a boolean comparator (`(a, b) => a > b`)
        // orders by 1 / 0, and NaN is +0.
        let n = match result {
            Value::Int(i) => i as f64,
            Value::Float(f) => f.inner(),
            other => Self::coerce_to_float(&other).unwrap_or(0.0),
        };
        Ok(if n < 0.0 {
            std::cmp::Ordering::Less
        } else if n > 0.0 {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        })
    }

    /// One invocation path for property-resolved and intrinsic call/apply.
    /// `args` starts at thisArg; the target itself is never an argument.
    /// `Map.prototype.forEach` / `Set.prototype.forEach` (ES2020 23.1.3.5,
    /// 23.2.3.6) over the live entry list (bd-9vouw.131): an entry added by
    /// a callback is visited, a deleted one is not (it was a snapshot, so
    /// additions were missed).
    pub(super) fn collection_for_each(
        &mut self,
        module: &Ir3Module,
        is_map: bool,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let tag = if is_map { "Map" } else { "Set" };
        let (collection_id, storage_id) = match &receiver {
            Value::Object(id) => match self.collection_storage_id(*id, tag) {
                Some(storage_id) => (*id, storage_id),
                None => {
                    return Err(InterpreterError::TypeError {
                        expected: format!("{tag} receiver for forEach"),
                        got: receiver.type_name().to_string(),
                    });
                }
            },
            other => {
                return Err(InterpreterError::TypeError {
                    expected: format!("{tag} receiver for forEach"),
                    got: other.type_name().to_string(),
                });
            }
        };
        let callback = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        if !callback.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: format!("callable {tag}.prototype.forEach callback"),
                got: callback.type_name().to_string(),
            });
        }
        let this_arg = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let mut label = self.join_arg_range_label(args)?;
        if let Some(collection_label) = self.object_mutation_labels.get(&collection_id) {
            label = label.join(collection_label);
        }
        // The cursor is popped on every exit, a throwing callback included.
        let depth = self.collection_for_each_cursors.len();
        self.collection_for_each_cursors.push((storage_id, 0));
        let walked = loop {
            let index = self.collection_for_each_cursors[depth].1;
            let Some((repr, stored)) = self.collection_entry_at(storage_id, index) else {
                break Ok(());
            };
            self.collection_for_each_cursors[depth].1 = index.saturating_add(1);
            let (value, key) = if is_map {
                (stored, Self::collection_key_from_repr(&repr))
            } else {
                (stored.clone(), stored)
            };
            if let Err(error) = self.preflight_inline_method_call_with_argument_label(
                Some(module),
                &callback,
                3,
                Some(&label),
            ) {
                break Err(error);
            }
            // The live cursor keeps its storage in this Rust frame. Pin it
            // and its owner while the callback allocates or changes entries;
            // the inline call also pins the current value, key and thisArg.
            if let Err(error) = self.with_gc_nested_request(
                vec![receiver.clone(), Value::Object(storage_id)],
                |core| {
                    core.invoke_inline_method_call_with_argument_label_preflighted(
                        Some(module),
                        callback.clone(),
                        this_arg.clone(),
                        vec![value, key, receiver.clone()],
                        Some(label.clone()),
                    )
                },
            ) {
                break Err(error);
            }
        };
        self.collection_for_each_cursors.truncate(depth);
        walked?;
        self.replace_pending_hostcall_result_label(Some(label))?;
        Ok(Value::Undefined)
    }

    /// URLSearchParams.prototype.keys/values/entries (bd-9vouw.126): an
    /// iterator over the pairs present at the call, `[name, value]` arrays
    /// for entries. The values carry the params' lifecycle label.
    pub(super) fn url_search_params_iterator(
        &mut self,
        kind: BuiltinFunctionKind,
        receiver: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        let method = match kind {
            BuiltinFunctionKind::UrlSearchParamsKeys => "keys",
            BuiltinFunctionKind::UrlSearchParamsValues => "values",
            _ => "entries",
        };
        let object_id = self.url_search_params_receiver_id(receiver, method)?;
        let state = &self.url_search_params[&object_id];
        self.check_temporary_memory_budget(
            Self::estimate_url_search_params_state_bytes(state).saturating_mul(2),
        )?;
        let (pairs, label) = (state.pairs.clone(), state.lifecycle_label.clone());
        let mut projected = Vec::with_capacity(pairs.len());
        for (name, value) in pairs {
            projected.push(match kind {
                BuiltinFunctionKind::UrlSearchParamsKeys => Value::str(name),
                BuiltinFunctionKind::UrlSearchParamsValues => Value::str(value),
                _ => Value::Object(
                    self.alloc_array_from_values(&[Value::str(name), Value::str(value)])?,
                ),
            });
        }
        let array = self.alloc_array_from_values(&projected)?;
        self.join_object_mutation_label(array, &label)?;
        self.replace_pending_hostcall_result_label(Some(label))?;
        self.array_prototype_iterator_for_receiver(Value::Object(array), "values")
    }

    /// URLSearchParams.prototype.forEach(callback, thisArg): calls
    /// `callback(value, name, params)` for each pair, reading the list live
    /// by index as Node does, so pairs a callback appends are visited.
    pub(super) fn url_search_params_for_each(
        &mut self,
        module: &Ir3Module,
        receiver: Option<Value>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let params = receiver.clone().unwrap_or(Value::Undefined);
        let object_id = self.url_search_params_receiver_id(receiver, "forEach")?;
        let callback = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        if !callback.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable URLSearchParams.prototype.forEach callback".to_string(),
                got: callback.type_name().to_string(),
            });
        }
        let this_arg = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let mut index = 0;
        while let Some((name, value, params_label)) =
            self.url_search_params.get(&object_id).and_then(|state| {
                let (name, value) = state.pairs.get(index)?.clone();
                Some((name, value, state.lifecycle_label.clone()))
            })
        {
            let label = self.join_arg_range_label(args)?.join(&params_label);
            self.preflight_inline_method_call_with_argument_label(
                Some(module),
                &callback,
                3,
                Some(&label),
            )?;
            // Keep the live params state (and its linked URL, if any) rooted
            // while a callback allocates. Its argument strings and thisArg
            // are pinned by the inline call itself.
            self.with_gc_nested_request(vec![params.clone()], |core| {
                core.invoke_inline_method_call_with_argument_label_preflighted(
                    Some(module),
                    callback.clone(),
                    this_arg.clone(),
                    vec![Value::str(value), Value::str(name), params.clone()],
                    Some(label),
                )
            })?;
            index += 1;
        }
        Ok(Value::Undefined)
    }

    /// `Map.prototype.keys/values/entries` and `Set.prototype.values/entries`
    /// (ES2020 23.1.3.8, 23.1.3.11, 23.1.3.4, 23.2.3.10, 23.2.3.5): an
    /// iterator over the live entry list (bd-9vouw.131). It was an array
    /// iterator over the entries present at the call, so entries added while
    /// iterating (`for (x of set) set.add(...)` worklists) were never visited
    /// and deleted ones still were. Each `next` reads the entry at its
    /// position in the storage's insertion order; `collection_delete` and
    /// `collection_clear` move registered iterators back.
    pub(super) fn collection_iterator(
        &mut self,
        kind: BuiltinFunctionKind,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let is_map = matches!(
            kind,
            BuiltinFunctionKind::MapKeys
                | BuiltinFunctionKind::MapValues
                | BuiltinFunctionKind::MapEntries
        );
        let tag = if is_map { "Map" } else { "Set" };
        let (collection_id, storage_id) = match &receiver {
            Value::Object(id) => match self.collection_storage_id(*id, tag) {
                Some(storage_id) => (*id, storage_id),
                None => {
                    return Err(InterpreterError::TypeError {
                        expected: format!("{tag} receiver"),
                        got: receiver.type_name().to_string(),
                    });
                }
            },
            other => {
                return Err(InterpreterError::TypeError {
                    expected: format!("{tag} receiver"),
                    got: other.type_name().to_string(),
                });
            }
        };
        let projection = match kind {
            BuiltinFunctionKind::MapKeys => RuntimeTypedArrayIteratorKind::Keys,
            BuiltinFunctionKind::MapEntries | BuiltinFunctionKind::SetEntries => {
                RuntimeTypedArrayIteratorKind::Entries
            }
            _ => RuntimeTypedArrayIteratorKind::Values,
        };
        let trace_index = self.start_iteration_trace(IterationKind::ForOf, || {
            format!("collection_iterator:{tag}|{}", collection_id.0)
        });
        if self.iteration_traced(trace_index) {
            let iterable_ref = self.iteration_ref_for_object(collection_id);
            self.record_iteration_event(trace_index, |record_id, step_index| {
                make_get_iterator_event(
                    record_id,
                    step_index,
                    IteratorSymbolKind::Iterator,
                    iterable_ref,
                )
            });
        }
        let handle = self.alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
            values: Vec::new(),
            next_index: 0,
            array: None,
            typed_array: None,
            collection: Some(RuntimeCollectionIterator {
                collection: collection_id,
                storage: storage_id,
                is_map,
                kind: projection,
            }),
            iterator_receiver: None,
            next_method: None,
            timers_interval: None,
            done: false,
            closed: false,
            return_called: false,
            trace_index,
        }))?;
        self.collection_iterators
            .entry(storage_id)
            .or_default()
            .insert(handle);
        if let Some(collection_label) = self.object_mutation_labels.get(&collection_id).cloned() {
            self.replace_pending_hostcall_result_label(Some(collection_label))?;
        }
        Ok(Value::Iterator(handle))
    }

    /// The key representation and stored value of the entry at `position` in
    /// the collection storage's insertion order (bd-9vouw.131).
    pub(super) fn collection_entry_at(
        &self,
        storage: ObjectId,
        position: usize,
    ) -> Option<(String, Value)> {
        let storage = self.heap.get(storage.0 as usize)?;
        let repr = storage.properties.insertion_key_at(position)?;
        let stored = storage
            .properties
            .get(repr)
            .cloned()
            .unwrap_or(Value::Undefined);
        Some((repr.clone(), stored))
    }

    /// The live Map/Set iterators of the collection storage `storage`, after
    /// pruning handles that were reclaimed, finished, or are not its
    /// iterators (bd-9vouw.131).
    pub(super) fn live_collection_iterators(&mut self, storage: ObjectId) -> Vec<u32> {
        let Some(handles) = self.collection_iterators.get(&storage) else {
            return Vec::new();
        };
        let live: BTreeSet<u32> = handles
            .iter()
            .copied()
            .filter(|handle| {
                matches!(
                    self.iterators.get(*handle as usize),
                    Some(RuntimeIteratorState::ForOf(state))
                        if !state.done
                            && !state.closed
                            && state
                                .collection
                                .as_ref()
                                .is_some_and(|iterator| iterator.storage == storage)
                )
            })
            .collect();
        if live.is_empty() {
            self.collection_iterators.remove(&storage);
            return Vec::new();
        }
        let handles = live.iter().copied().collect();
        self.collection_iterators.insert(storage, live);
        handles
    }

    /// The entry at `position` of the collection storage was removed: every
    /// live iterator past it moves back one, so it neither skips the next
    /// entry nor revisits one (bd-9vouw.131).
    pub(super) fn collection_entry_removed(&mut self, storage: ObjectId, position: usize) {
        for (cursor_storage, next) in &mut self.collection_for_each_cursors {
            if *cursor_storage == storage && *next > position {
                *next -= 1;
            }
        }
        for handle in self.live_collection_iterators(storage) {
            if let Some(RuntimeIteratorState::ForOf(state)) =
                self.iterators.get_mut(handle as usize)
                && state.next_index > position
            {
                state.next_index -= 1;
            }
        }
    }

    /// The collection storage was emptied: its live iterators continue with
    /// the entries added from now on (ES2020 23.1.3.1 keeps the list and
    /// its iterators' positions; entries added later follow them).
    pub(super) fn collection_storage_cleared(&mut self, storage: ObjectId) {
        for (cursor_storage, next) in &mut self.collection_for_each_cursors {
            if *cursor_storage == storage {
                *next = 0;
            }
        }
        for handle in self.live_collection_iterators(storage) {
            if let Some(RuntimeIteratorState::ForOf(state)) =
                self.iterators.get_mut(handle as usize)
            {
                state.next_index = 0;
            }
        }
    }

    /// ES2020 20.1.3 thisNumberValue: a Number or a Number wrapper object.
    pub(super) fn this_number_value(&self, receiver: &Value) -> Result<f64, InterpreterError> {
        match receiver {
            Value::Int(value) => Ok(*value as f64),
            Value::Float(value) => Ok(value.inner()),
            // A Number wrapper's [[NumberData]] (bd-9vouw.73); a guest
            // object is never one, whatever its properties (bd-9vouw.150).
            Value::Object(id) => match self.primitive_wrapper_value(*id) {
                Some(Value::Int(value)) => Ok(*value as f64),
                Some(Value::Float(value)) => Ok(value.inner()),
                _ => Err(InterpreterError::TypeError {
                    expected: "Number receiver".to_string(),
                    got: "object".to_string(),
                }),
            },
            other => Err(InterpreterError::TypeError {
                expected: "Number receiver".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// Date.prototype getters, setters and formatters (ES2020 20.4.4) over the
    /// receiver's [[DateValue]]. Local time is UTC in this hermetic engine.
    /// The locale tag and options of a Date toLocale*String call. Local
    /// time is UTC, so a `timeZone` option must name UTC; component and
    /// style options (`month: 'long'`, `dateStyle`, `hour12`, ...) are not
    /// formatted and are refused by name.
    pub(super) fn date_locale_request(
        &self,
        method: &str,
        locales: &Value,
        options: &Value,
    ) -> Result<Option<String>, InterpreterError> {
        let refuse = |what: String| InterpreterError::TypeError {
            expected: format!("a locale and options Date.prototype.{method} formats"),
            got: what,
        };
        let locale = match locales {
            Value::Undefined => None,
            Value::Str(tag) => Some(tag.to_string()),
            Value::Object(list)
                if self
                    .heap
                    .get(list.0 as usize)
                    .is_some_and(|object| object.is_array) =>
            {
                match self.array_like_values(*list)?.into_iter().next() {
                    None => None,
                    Some(Value::Str(tag)) => Some(tag.to_string()),
                    Some(other) => return Err(refuse(format!("locale {}", other.type_name()))),
                }
            }
            other => return Err(refuse(format!("locales {}", other.type_name()))),
        };
        match options {
            Value::Undefined => {}
            Value::Object(options_id) => {
                let object = self
                    .heap
                    .get(options_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: options_id.0 })?;
                for (key, value) in &object.properties {
                    if key.starts_with("__") || matches!(value, Value::Undefined) {
                        continue;
                    }
                    let utc = match value {
                        Value::Str(zone) => zone.as_str().is_some_and(|zone| {
                            ["utc", "etc/utc", "gmt", "etc/gmt"]
                                .contains(&zone.to_ascii_lowercase().as_str())
                        }),
                        _ => false,
                    };
                    match key.as_str() {
                        "timeZone" if utc => {}
                        "localeMatcher" => {}
                        other => return Err(refuse(format!("option {other}"))),
                    }
                }
            }
            other => return Err(refuse(format!("options {}", other.type_name()))),
        }
        Ok(locale)
    }

    /// Date.prototype.toJSON (ES2020 20.4.4.37) is generic: ToObject(this),
    /// ToPrimitive with hint "number" (null for a non-finite Number), then
    /// Invoke(O, "toISOString"). It demanded a Date receiver and formatted
    /// it directly, so a user `toISOString`, a throwing valueOf and a
    /// primitive `this` were never seen.
    pub(super) fn date_prototype_to_json(
        &mut self,
        module: Option<&Ir3Module>,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let object = match receiver {
            Value::Undefined | Value::Null => {
                return Err(InterpreterError::TypeError {
                    expected: "object-coercible this for Date.prototype.toJSON".to_string(),
                    got: receiver.type_name().to_string(),
                });
            }
            Value::Bool(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::Str(_)
            | Value::Symbol(_)
            | Value::BigInt(_) => Value::Object(self.alloc_primitive_wrapper(receiver)?),
            other => other,
        };
        let Some(module) = module else {
            return Err(InterpreterError::TypeError {
                expected: "module-backed Date.prototype.toJSON".to_string(),
                got: "missing module context".to_string(),
            });
        };
        // Guest code runs while native locals hold values: no collection
        // until this returns.
        self.gc_nested_request = None;
        match self.coerce_runtime_primitive_with_hint(Some(module), object.clone(), "number")? {
            Value::Float(number) if !number.inner().is_finite() => return Ok(Value::Null),
            _ => {}
        }
        let to_iso_string = self.get_v(
            module,
            &object,
            &RuntimePropertyKey::String(JsString::from("toISOString")),
        )?;
        if !to_iso_string.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable toISOString for Date.prototype.toJSON".to_string(),
                got: to_iso_string.type_name().to_string(),
            });
        }
        self.invoke_inline_method_call(Some(module), to_iso_string, object, Vec::new())
    }

    /// Store [[DateValue]] without invoking a guest property, setter, Proxy
    /// trap, or the receiver's integrity checks. The Number has no heap
    /// references to trace; its allocation is charged before publication.
    pub(super) fn set_date_value(
        &mut self,
        date_id: ObjectId,
        time: f64,
    ) -> Result<(), InterpreterError> {
        let index = date_id.0 as usize;
        let object = self
            .heap
            .get(index)
            .ok_or(InterpreterError::ObjectNotFound { id: date_id.0 })?;
        let previous_bytes = if object.date_value.is_some() {
            std::mem::size_of::<Float64>() as u64
        } else {
            0
        };
        self.apply_memory_component_delta(previous_bytes, std::mem::size_of::<Float64>() as u64)?;
        let time = Float64::new(time);
        self.mutate_heap(|heap| match heap[index].date_value.as_deref_mut() {
            Some(stored) => *stored = time,
            None => heap[index].date_value = Some(Box::new(time)),
        });
        Ok(())
    }

    pub(super) fn observe_date_value_label(
        &mut self,
        value: &Value,
    ) -> Result<(), InterpreterError> {
        let Value::Object(date_id) = value else {
            return Ok(());
        };
        if self
            .heap
            .get(date_id.0 as usize)
            .and_then(HeapObject::date_time)
            .is_none()
        {
            return Ok(());
        }
        let Some(label) = self.object_mutation_labels.get(date_id) else {
            return Ok(());
        };
        self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
        let label = label.clone();
        self.join_into_pending_hostcall_result_label(Some(label))?;
        self.observe_scoped_callback_result()
    }

    pub(super) fn date_prototype_method(
        &mut self,
        module: Option<&Ir3Module>,
        method: &str,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        use date_math::*;
        if method == "toJSON" {
            return self.date_prototype_to_json(module, receiver);
        }
        let date_id = match &receiver {
            Value::Object(id)
                if self
                    .heap
                    .get(id.0 as usize)
                    .is_some_and(|object| object.date_value.is_some()) =>
            {
                *id
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: format!("Date receiver for Date.prototype.{method}"),
                    got: other.type_name().to_string(),
                });
            }
        };
        let t = self
            .heap
            .get(date_id.0 as usize)
            .and_then(HeapObject::date_time)
            .expect("Date receiver was validated above");
        let number = js_number_to_value;
        let getter = |part: fn(f64) -> f64| {
            if t.is_nan() { f64::NAN } else { part(t) }
        };
        let result = match method {
            "valueOf" => return Ok(number(t)),
            "getFullYear" | "getUTCFullYear" => return Ok(number(getter(year_from_time))),
            // Annex B B.2.4.1: the year minus 1900.
            "getYear" => return Ok(number(getter(year_from_time) - 1900.0)),
            "getMonth" | "getUTCMonth" => return Ok(number(getter(month_from_time))),
            "getDate" | "getUTCDate" => return Ok(number(getter(date_from_time))),
            "getDay" | "getUTCDay" => return Ok(number(getter(week_day))),
            "getHours" | "getUTCHours" => return Ok(number(getter(hour))),
            "getMinutes" | "getUTCMinutes" => return Ok(number(getter(minute))),
            "getSeconds" | "getUTCSeconds" => return Ok(number(getter(second))),
            "getMilliseconds" | "getUTCMilliseconds" => {
                return Ok(number(getter(millisecond)));
            }
            "getTimezoneOffset" => return Ok(number(if t.is_nan() { f64::NAN } else { 0.0 })),
            "toISOString" | "toJSON" => {
                if !t.is_finite() {
                    if method == "toJSON" {
                        return Ok(Value::Null);
                    }
                    return Err(InterpreterError::RangeError {
                        message: "Invalid time value".to_string(),
                    });
                }
                let year = year_from_time(t);
                let year_text = if (0.0..=9999.0).contains(&year) {
                    format!("{:04}", year as i64)
                } else {
                    format!(
                        "{}{:06}",
                        if year < 0.0 { '-' } else { '+' },
                        year.abs() as i64
                    )
                };
                return Ok(Value::str(format!(
                    "{year_text}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                    month_from_time(t) as i64 + 1,
                    date_from_time(t) as i64,
                    hour(t) as i64,
                    minute(t) as i64,
                    second(t) as i64,
                    millisecond(t) as i64
                )));
            }
            "toString" => return Ok(Value::str(to_date_string(t))),
            "toLocaleString" | "toLocaleDateString" | "toLocaleTimeString" => {
                let kind = match method {
                    "toLocaleDateString" => date_locale::DateLocaleKind::Date,
                    "toLocaleTimeString" => date_locale::DateLocaleKind::Time,
                    _ => date_locale::DateLocaleKind::DateTime,
                };
                if !t.is_finite() {
                    return Ok(Value::str("Invalid Date"));
                }
                let locales = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let options = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let locale = self.date_locale_request(method, &locales, &options)?;
                let fields = date_locale::DateFields {
                    year: year_from_time(t) as i64,
                    month: month_from_time(t) as u32,
                    day: date_from_time(t) as u32,
                    hour: hour(t) as u32,
                    minute: minute(t) as u32,
                    second: second(t) as u32,
                };
                return date_locale::format_date_locale(fields, locale.as_deref(), kind)
                    .map(Value::str)
                    .map_err(|what| InterpreterError::TypeError {
                        expected: format!("a locale Date.prototype.{method} formats"),
                        got: what,
                    });
            }
            "toDateString" | "toTimeString" => {
                if t.is_nan() {
                    return Ok(Value::str("Invalid Date"));
                }
                return Ok(Value::str(if method == "toDateString" {
                    date_string(t)
                } else {
                    time_zone_string(t)
                }));
            }
            "toUTCString" | "toGMTString" => {
                if !t.is_finite() {
                    return Ok(Value::str("Invalid Date"));
                }
                let year = year_from_time(t) as i64;
                let year_text = if year < 0 {
                    format!("-{:04}", -year)
                } else {
                    format!("{year:04}")
                };
                return Ok(Value::str(format!(
                    "{}, {:02} {} {year_text} {:02}:{:02}:{:02} GMT",
                    WEEK_DAY_NAMES[week_day(t) as usize],
                    date_from_time(t) as i64,
                    MONTH_NAMES[month_from_time(t) as usize],
                    hour(t) as i64,
                    minute(t) as i64,
                    second(t) as i64
                )));
            }
            _ => {
                // Each argument the setter takes is ToNumber'd, in order,
                // after the time value is read and even when it is NaN
                // (ES2020 20.4.4.20-28): an object's valueOf runs exactly
                // once, a Symbol or BigInt throws. Arguments were read as
                // primitives only, so `setHours(0, { valueOf })` saw NaN.
                let arity = match method {
                    "setHours" | "setUTCHours" => 4,
                    "setMinutes" | "setUTCMinutes" | "setFullYear" | "setUTCFullYear" => 3,
                    "setSeconds" | "setUTCSeconds" | "setMonth" | "setUTCMonth" => 2,
                    _ => 1,
                };
                // Guest valueOf may run; no collection while native locals
                // hold the receiver.
                self.gc_nested_request = None;
                let mut values = Vec::with_capacity(args.count.min(arity) as usize);
                for index in 0..args.count.min(arity) {
                    let value = self.builtin_arg(args, index)?.unwrap_or(Value::Undefined);
                    let value = if value.is_object_like() {
                        self.coerce_runtime_primitive(module, value, false)?
                    } else {
                        value
                    };
                    if matches!(value, Value::Symbol(_) | Value::BigInt(_)) {
                        return Err(InterpreterError::TypeError {
                            expected: format!("number argument for Date.prototype.{method}"),
                            got: value.type_name().to_string(),
                        });
                    }
                    values.push(Self::coerce_to_float(&value).unwrap_or(f64::NAN));
                }
                let arg =
                    |index: usize, fallback: f64| values.get(index).copied().unwrap_or(fallback);
                let first = arg(0, f64::NAN);
                let time_part = |t: f64| t.rem_euclid(MS_PER_DAY);
                match method {
                    "setTime" => time_clip(first),
                    "setMilliseconds" | "setUTCMilliseconds" => time_clip(make_date(
                        day(t),
                        make_time(hour(t), minute(t), second(t), first),
                    )),
                    "setSeconds" | "setUTCSeconds" => time_clip(make_date(
                        day(t),
                        make_time(hour(t), minute(t), first, arg(1, millisecond(t))),
                    )),
                    "setMinutes" | "setUTCMinutes" => time_clip(make_date(
                        day(t),
                        make_time(hour(t), first, arg(1, second(t)), arg(2, millisecond(t))),
                    )),
                    "setHours" | "setUTCHours" => time_clip(make_date(
                        day(t),
                        make_time(
                            first,
                            arg(1, minute(t)),
                            arg(2, second(t)),
                            arg(3, millisecond(t)),
                        ),
                    )),
                    "setDate" | "setUTCDate" => time_clip(make_date(
                        make_day(year_from_time(t), month_from_time(t), first),
                        time_part(t),
                    )),
                    "setMonth" | "setUTCMonth" => time_clip(make_date(
                        make_day(year_from_time(t), first, arg(1, date_from_time(t))),
                        time_part(t),
                    )),
                    // Annex B B.2.4.2: MakeFullYear (a NaN year makes the
                    // date NaN, 0..=99 is 1900 plus it) over the local date,
                    // a NaN date starting from +0; local time is UTC here.
                    "setYear" if first.is_nan() => f64::NAN,
                    "setYear" => {
                        let year = first.trunc();
                        let full_year = if (0.0..=99.0).contains(&year) {
                            1900.0 + year
                        } else {
                            year
                        };
                        let base = if t.is_nan() { 0.0 } else { t };
                        time_clip(make_date(
                            make_day(full_year, month_from_time(base), date_from_time(base)),
                            time_part(base),
                        ))
                    }
                    "setFullYear" | "setUTCFullYear" => {
                        // A NaN date starts from +0 (20.4.4.21 step 1).
                        let base = if t.is_nan() { 0.0 } else { t };
                        time_clip(make_date(
                            make_day(
                                first,
                                arg(1, month_from_time(base)),
                                arg(2, date_from_time(base)),
                            ),
                            time_part(base),
                        ))
                    }
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "Date.prototype method".to_string(),
                            got: method.to_string(),
                        });
                    }
                }
            }
        };
        let stored = if result.is_nan() {
            Value::Float(Float64::new(f64::NAN))
        } else {
            js_number_to_value(result)
        };
        // Admit the persistent provenance before publishing a new time. A
        // failing label allocation must not leave an unlabelled classified
        // value available through another reference to this Date.
        let label = self.json_parse_context_label()?;
        self.join_object_mutation_label(date_id, &label)?;
        self.set_date_value(date_id, result)?;
        Ok(stored)
    }

    /// ES2020 20.4.2.2 `new Date(value)`: another Date's time value; else
    /// ToPrimitive(value), and a string is parsed like Date.parse (it used to
    /// give NaN for every string, `new Date('2020-03-04')` included) while
    /// anything else goes through ToNumber (Symbol and BigInt throw); then
    /// TimeClip.
    pub(super) fn date_single_argument_time_value(
        &mut self,
        register: u32,
        module: Option<&Ir3Module>,
    ) -> Result<f64, InterpreterError> {
        let value = self.read_reg(register)?;
        if let Value::Object(date_id) = &value
            && let Some(time) = self
                .heap
                .get(date_id.0 as usize)
                .and_then(HeapObject::date_time)
        {
            self.observe_date_value_label(&value)?;
            return Ok(date_math::time_clip(time));
        }
        let primitive = if value.is_object_like() && module.is_some() {
            self.coerce_runtime_primitive_with_hint(module, value, "default")?
        } else {
            value
        };
        let type_name = primitive.type_name();
        let time = match primitive {
            Value::Str(text) => return Ok(Self::parse_date_string(text.as_utf8_projection())),
            Value::Int(millis) => millis as f64,
            Value::Float(millis) => millis.inner(),
            Value::Bool(flag) => f64::from(u8::from(flag)),
            Value::Null => 0.0,
            Value::Symbol(_) | Value::BigInt(_) => {
                return Err(InterpreterError::TypeError {
                    expected: "value convertible to a number".to_string(),
                    got: format!("{type_name} (Date time value)"),
                });
            }
            _ => f64::NAN,
        };
        Ok(date_math::time_clip(time))
    }

    /// ES2020 20.4.2.1 `new Date(year, month[, date[, hours[, minutes[,
    /// seconds[, ms]]]]])`: each component through ToNumber (left to right),
    /// years 0-99 mean 1900-1999, local time is UTC here; then TimeClip. The
    /// components used to be ignored (NaN).
    pub(super) fn date_components_time_value(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<f64, InterpreterError> {
        let mut parts = [f64::NAN, f64::NAN, 1.0, 0.0, 0.0, 0.0, 0.0];
        for (index, part) in parts.iter_mut().enumerate().take(args.count as usize) {
            let register = args.start.checked_add(index as u32).ok_or(
                InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                },
            )?;
            *part = match self.math_argument_value(register, module)? {
                Value::Int(value) => value as f64,
                Value::Float(value) => value.inner(),
                _ => f64::NAN,
            };
        }
        let [year, month, date, hours, minutes, seconds, millis] = parts;
        let year = if !year.is_nan() && (0.0..=99.0).contains(&year.trunc()) {
            1900.0 + year.trunc()
        } else {
            year
        };
        Ok(date_math::time_clip(date_math::make_date(
            date_math::make_day(year, month, date),
            date_math::make_time(hours, minutes, seconds, millis),
        )))
    }

    /// Date.parse (ES2020 20.4.3.2): the date-time string format and the
    /// toUTCString form, then V8's legacy formats (bd-9vouw.443), as Node
    /// parses them.
    pub(super) fn parse_date_string(text: &str) -> f64 {
        let iso = Self::parse_iso_date_string(text);
        if iso.is_nan() {
            Self::parse_legacy_date_string(text)
        } else {
            iso
        }
    }

    /// The date-time string format (ES2020 20.4.1.15):
    /// `YYYY[-MM[-DD]][THH:mm[:ss[.sss]]][Z|±HH:mm]` with extended
    /// `±YYYYYY` years, plus the `toUTCString` form
    /// `Www, DD Mmm YYYY HH:mm:ss GMT`. Date-only forms are UTC; date-time
    /// forms without an offset are local time, which is UTC here. Anything
    /// else is NaN.
    pub(super) fn parse_iso_date_string(text: &str) -> f64 {
        use date_math::{make_date, make_day, make_time, time_clip};
        let text = text.trim();
        let digits = |slice: &str, count: usize| -> Option<f64> {
            (slice.len() == count && slice.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| slice.parse::<f64>().ok())
                .flatten()
        };
        // `Thu, 01 Jan 1970 00:00:00 GMT`
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.len() == 6 && words[5] == "GMT" && words[0].ends_with(',') {
            let day = digits(words[1], 2).or_else(|| digits(words[1], 1));
            let month = MONTHS.iter().position(|name| *name == words[2]);
            let year = words[3].parse::<f64>().ok();
            let clock: Vec<&str> = words[4].split(':').collect();
            if let (Some(day), Some(month), Some(year), [h, m, sec]) =
                (day, month, year, clock.as_slice())
                && let (Some(h), Some(m), Some(sec)) = (digits(h, 2), digits(m, 2), digits(sec, 2))
            {
                return time_clip(make_date(
                    make_day(year, month as f64, day),
                    make_time(h, m, sec, 0.0),
                ));
            }
            return f64::NAN;
        }
        let (date_part, time_part) = match text.split_once('T') {
            Some((date, time)) => (date, Some(time)),
            None => (text, None),
        };
        let (year, rest) = if let Some(extended) = date_part.strip_prefix(['+', '-']) {
            let Some(year) = extended.get(..6).and_then(|year| digits(year, 6)) else {
                return f64::NAN;
            };
            let year = if date_part.starts_with('-') {
                if year == 0.0 {
                    return f64::NAN;
                }
                -year
            } else {
                year
            };
            (year, &extended[6..])
        } else {
            let Some(year) = date_part.get(..4).and_then(|year| digits(year, 4)) else {
                return f64::NAN;
            };
            (year, &date_part[4..])
        };
        let mut fields = rest.split('-').skip(1);
        let month = match rest {
            "" => 1.0,
            _ => match fields.next().and_then(|month| digits(month, 2)) {
                Some(month) if (1.0..=12.0).contains(&month) => month,
                _ => return f64::NAN,
            },
        };
        let day = match fields.next() {
            None => 1.0,
            Some(day) => match digits(day, 2) {
                Some(day) if (1.0..=31.0).contains(&day) => day,
                _ => return f64::NAN,
            },
        };
        if fields.next().is_some() {
            return f64::NAN;
        }
        let mut offset_minutes = 0.0;
        let (mut hours, mut minutes, mut seconds, mut millis) = (0.0, 0.0, 0.0, 0.0);
        if let Some(time) = time_part {
            let (clock, offset) = if let Some(clock) = time.strip_suffix('Z') {
                (clock, None)
            } else if let Some(index) = time.rfind(['+', '-']) {
                (&time[..index], Some(&time[index..]))
            } else {
                (time, None)
            };
            if let Some(offset) = offset {
                let sign = if offset.starts_with('-') { -1.0 } else { 1.0 };
                let Some((oh, om)) = offset[1..].split_once(':') else {
                    return f64::NAN;
                };
                let (Some(oh), Some(om)) = (digits(oh, 2), digits(om, 2)) else {
                    return f64::NAN;
                };
                offset_minutes = sign * (oh * 60.0 + om);
            }
            let (clock, fraction) = match clock.split_once('.') {
                Some((clock, fraction)) => (clock, Some(fraction)),
                None => (clock, None),
            };
            let pieces: Vec<&str> = clock.split(':').collect();
            let parsed: Option<Vec<f64>> = pieces.iter().map(|piece| digits(piece, 2)).collect();
            let Some(parsed) = parsed else {
                return f64::NAN;
            };
            match parsed.as_slice() {
                [h, m] => {
                    (hours, minutes) = (*h, *m);
                }
                [h, m, sec] => {
                    (hours, minutes, seconds) = (*h, *m, *sec);
                }
                _ => return f64::NAN,
            }
            if let Some(fraction) = fraction {
                if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                    return f64::NAN;
                }
                let padded = format!("{fraction:0<3}");
                millis = padded[..3].parse::<f64>().unwrap_or(0.0);
            }
            if hours > 24.0 || minutes > 59.0 || seconds > 59.0 {
                return f64::NAN;
            }
        }
        time_clip(
            make_date(
                make_day(year, month - 1.0, day),
                make_time(hours, minutes, seconds, millis),
            ) - offset_minutes * 60_000.0,
        )
    }

    /// V8's legacy Date.parse fallback (dateparser-inl.h), for a string that
    /// is neither the ES date-time format nor the toUTCString form
    /// (bd-9vouw.443): month names (`Feb 29, 2024`, `29 February 2024`),
    /// `M/D/Y` and `Y/M/D` numbers, `h:m[:s[.ms]]` times with AM/PM, the
    /// toString form (`Thu Feb 29 2024 13:05:09 GMT+0000 (...)`), and the
    /// zones UT/UTC/GMT/Z, the US abbreviations and a `±hh[mm]` / `±hh:mm`
    /// offset after a zone or a time. Parenthesized text is skipped. A
    /// string without a zone is local time, which is UTC here. V8's rules
    /// are kept, quirks included: a missing year is 2001 and a two-digit
    /// year is 19xx/20xx. Anything else is NaN.
    pub(super) fn parse_legacy_date_string(text: &str) -> f64 {
        use date_math::{make_date, make_day, make_time, time_clip};

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Token<'a> {
            Number { value: i64, length: usize },
            Word(&'a str),
            Symbol(char),
            Space,
        }
        enum Keyword {
            Month(i64),
            AmPm(i64),
            Zone(i64),
        }
        static KEYWORDS: [(&str, Keyword); 27] = [
            ("jan", Keyword::Month(1)),
            ("feb", Keyword::Month(2)),
            ("mar", Keyword::Month(3)),
            ("apr", Keyword::Month(4)),
            ("may", Keyword::Month(5)),
            ("jun", Keyword::Month(6)),
            ("jul", Keyword::Month(7)),
            ("aug", Keyword::Month(8)),
            ("sep", Keyword::Month(9)),
            ("oct", Keyword::Month(10)),
            ("nov", Keyword::Month(11)),
            ("dec", Keyword::Month(12)),
            ("am", Keyword::AmPm(0)),
            ("pm", Keyword::AmPm(12)),
            ("ut", Keyword::Zone(0)),
            ("utc", Keyword::Zone(0)),
            ("z", Keyword::Zone(0)),
            ("gmt", Keyword::Zone(0)),
            ("cdt", Keyword::Zone(-5)),
            ("cst", Keyword::Zone(-6)),
            ("edt", Keyword::Zone(-4)),
            ("est", Keyword::Zone(-5)),
            ("mdt", Keyword::Zone(-6)),
            ("mst", Keyword::Zone(-7)),
            ("pdt", Keyword::Zone(-7)),
            ("pst", Keyword::Zone(-8)),
            // V8's time separator keyword: a garbage word in this parser.
            ("t", Keyword::AmPm(-1)),
        ];
        // V8 compares a word's first three letters with each keyword; only a
        // month name may be longer than its keyword.
        fn keyword(word: &str) -> Option<&'static Keyword> {
            let lower = word.to_lowercase();
            let prefix: String = lower.chars().take(3).collect();
            KEYWORDS
                .iter()
                .find(|(name, kind)| {
                    *name == prefix
                        && (lower.chars().count() <= 3 || matches!(kind, Keyword::Month(_)))
                })
                .map(|(_, kind)| kind)
                .filter(|kind| !matches!(kind, Keyword::AmPm(-1)))
        }

        let mut tokens = Vec::new();
        let mut chars = text.char_indices().peekable();
        while let Some((start, ch)) = chars.next() {
            if ch.is_ascii_digit() {
                let mut value: i64 = i64::from(ch as u8 - b'0');
                let mut length = 1;
                while let Some(&(_, next)) = chars.peek() {
                    if !next.is_ascii_digit() {
                        break;
                    }
                    chars.next();
                    length += 1;
                    if value < i64::from(i32::MAX) / 10 - 10 {
                        value = value * 10 + i64::from(next as u8 - b'0');
                    }
                }
                tokens.push(Token::Number { value, length });
            } else if ch.is_alphabetic() || !ch.is_ascii() {
                let mut end = start + ch.len_utf8();
                while let Some(&(index, next)) = chars.peek() {
                    if !(next.is_alphabetic() || (!next.is_ascii() && !next.is_whitespace())) {
                        break;
                    }
                    chars.next();
                    end = index + next.len_utf8();
                }
                tokens.push(Token::Word(&text[start..end]));
            } else if ch.is_whitespace() {
                while chars.peek().is_some_and(|&(_, next)| next.is_whitespace()) {
                    chars.next();
                }
                tokens.push(Token::Space);
            } else if ch == '(' {
                let mut depth = 1;
                for (_, next) in chars.by_ref() {
                    match next {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            } else {
                tokens.push(Token::Symbol(ch));
            }
        }

        let is_day = |n: i64| (1..=31).contains(&n);
        let is_minute = |n: i64| (0..=59).contains(&n);
        let is_millisecond = |n: i64| (0..=999).contains(&n);
        let mut day = ([0i64; 3], 0usize);
        let mut named_month: Option<i64> = None;
        let mut time = ([0i64; 4], 0usize);
        let mut hour_offset: Option<i64> = None;
        let (mut tz_sign, mut tz_hour, mut tz_minute): (Option<i64>, Option<i64>, Option<i64>) =
            (None, None, None);
        let time_expecting = |time: &([i64; 4], usize), n: i64| {
            (time.1 == 1 && is_minute(n))
                || (time.1 == 2 && is_minute(n))
                || (time.1 == 3 && is_millisecond(n))
        };
        let mut has_read_number = false;
        let mut index = 0;
        while index < tokens.len() {
            let token = tokens[index];
            index += 1;
            let peek = tokens.get(index).copied();
            match token {
                Token::Number { value: n, .. } => {
                    has_read_number = true;
                    // V8 skips a dot after a number before asking whether a
                    // time component is expected.
                    let dot = peek == Some(Token::Symbol('.'));
                    if dot {
                        index += 1;
                    }
                    if peek == Some(Token::Symbol(':')) {
                        index += 1;
                        if tokens.get(index) == Some(&Token::Symbol(':')) {
                            index += 1;
                            if time.1 != 0 {
                                return f64::NAN;
                            }
                            time.0[0] = n;
                            time.0[1] = 0;
                            time.1 = 2;
                        } else {
                            if time.1 >= 4 {
                                return f64::NAN;
                            }
                            time.0[time.1] = n;
                            time.1 += 1;
                            if tokens.get(index) == Some(&Token::Symbol('.')) {
                                index += 1;
                            }
                        }
                    } else if dot && time_expecting(&time, n) {
                        time.0[time.1] = n;
                        time.1 += 1;
                        let Some(Token::Number { value, length }) = tokens.get(index).copied()
                        else {
                            return f64::NAN;
                        };
                        index += 1;
                        // The first three significant digits (ReadMilliseconds).
                        let millis = match length {
                            1 => value * 100,
                            2 => value * 10,
                            3 => value,
                            _ => value / 10i64.pow((length.min(9) - 3) as u32),
                        };
                        if time.1 >= 4 {
                            return f64::NAN;
                        }
                        time.0[time.1] = millis;
                        time.1 = 4;
                    } else if tz_hour.is_some() && tz_minute.is_none() && is_minute(n) {
                        tz_minute = Some(n);
                    } else if time_expecting(&time, n) {
                        time.0[time.1] = n;
                        time.1 = 4;
                        let peek = tokens.get(index).copied();
                        if !matches!(
                            peek,
                            None | Some(Token::Space) | Some(Token::Symbol('+' | '-'))
                        ) && !matches!(peek, Some(Token::Word(word)) if word.eq_ignore_ascii_case("z"))
                        {
                            return f64::NAN;
                        }
                    } else {
                        if day.1 >= 3 {
                            return f64::NAN;
                        }
                        day.0[day.1] = n;
                        day.1 += 1;
                        if tokens.get(index) == Some(&Token::Symbol('-')) {
                            index += 1;
                        }
                    }
                }
                Token::Word(word) => match keyword(word) {
                    Some(Keyword::AmPm(offset)) if time.1 != 0 => hour_offset = Some(*offset),
                    Some(Keyword::Month(month)) => {
                        named_month = Some(*month);
                        if peek == Some(Token::Symbol('-')) {
                            index += 1;
                        }
                    }
                    Some(Keyword::Zone(hours)) if has_read_number => {
                        tz_sign = Some(if *hours < 0 { -1 } else { 1 });
                        tz_hour = Some(hours.abs());
                        tz_minute = Some(0);
                    }
                    _ => {
                        // A word that is not a keyword (a weekday name) may
                        // only come before the first number, apart from it.
                        if has_read_number || matches!(peek, Some(Token::Number { .. })) {
                            return f64::NAN;
                        }
                    }
                },
                Token::Symbol(sign @ ('+' | '-'))
                    if (tz_hour == Some(0) && tz_minute == Some(0)) || time.1 != 0 =>
                {
                    tz_sign = Some(if sign == '-' { -1 } else { 1 });
                    let (mut n, mut length) = (0, 0);
                    if let Some(Token::Number {
                        value,
                        length: digits,
                    }) = tokens.get(index).copied()
                    {
                        index += 1;
                        (n, length) = (value, digits);
                    }
                    has_read_number = true;
                    if tokens.get(index) == Some(&Token::Symbol(':')) {
                        tz_hour = Some(n);
                        tz_minute = None;
                    } else if length == 1 || length == 2 {
                        tz_hour = Some(n);
                        tz_minute = Some(0);
                    } else if length == 3 || length == 4 {
                        tz_hour = Some(n / 100);
                        tz_minute = Some(n % 100);
                    } else {
                        return f64::NAN;
                    }
                }
                Token::Symbol('+' | '-' | ')') if has_read_number => return f64::NAN,
                _ => {}
            }
        }

        // DayComposer::Write: empty slots are 1 (so a missing year is 2001).
        if day.1 == 0 {
            return f64::NAN;
        }
        let comps = [
            day.0[0],
            if day.1 > 1 { day.0[1] } else { 1 },
            if day.1 > 2 { day.0[2] } else { 1 },
        ];
        let (mut year, month, date) = match named_month {
            None if !is_day(comps[0]) => (comps[0], comps[1], comps[2]),
            None => (comps[2], comps[0], comps[1]),
            Some(month) if !is_day(comps[0]) => (comps[0], month, comps[1]),
            Some(month) => (comps[1], month, comps[0]),
        };
        if (0..=49).contains(&year) {
            year += 2000;
        } else if (50..=99).contains(&year) {
            year += 1900;
        }
        if !(1..=12).contains(&month) || !is_day(date) {
            return f64::NAN;
        }
        // TimeComposer::Write.
        // Unfilled time slots are 0.
        let [mut hour, minute, second, millisecond] = time.0;
        if let Some(offset) = hour_offset {
            if !(0..=12).contains(&hour) {
                return f64::NAN;
            }
            hour = hour % 12 + offset;
        }
        if !((0..=23).contains(&hour)
            && is_minute(minute)
            && is_minute(second)
            && is_millisecond(millisecond))
            && !(hour == 24 && minute == 0 && second == 0 && millisecond == 0)
        {
            return f64::NAN;
        }
        // TimeZoneComposer::Write: no zone is local time (UTC here).
        let offset_ms = tz_sign.map_or(0, |sign| {
            sign * (tz_hour.unwrap_or(0) * 3600 + tz_minute.unwrap_or(0) * 60) * 1000
        });
        time_clip(
            make_date(
                make_day(year as f64, (month - 1) as f64, date as f64),
                make_time(
                    hour as f64,
                    minute as f64,
                    second as f64,
                    millisecond as f64,
                ),
            ) - offset_ms as f64,
        )
    }

    /// RegExpBuiltinExec's result (ES2020 21.2.5.2.2) for the first match at
    /// or after UTF-16 offset `start` (exactly at `start` when `sticky`): the
    /// match array with every capture, `index` (UTF-16), `input` and
    /// `groups`, and with the `d` flag `indices` (ES2022 MakeIndicesArray:
    /// each capture's UTF-16 `[start, end]` or undefined, and `groups`),
    /// plus the match's end UTF-16 offset.
    /// An ASCII subject's byte
    /// offsets are its UTF-16 offsets, and the subject is the result's
    /// `input` and the legacy statics' input as it is, shared, not copied:
    /// an exec loop over a long string decoded and copied the whole string
    /// per match (bd-9vouw.475).
    pub(super) fn regexp_exec_at(
        &mut self,
        regex: &CompiledRegExp,
        subject: &JsString,
        start: usize,
        sticky: bool,
        has_indices: bool,
        full_unicode: bool,
    ) -> Result<Option<(Value, usize)>, InterpreterError> {
        let input = self.prepare_regexp_input(subject, full_unicode)?;
        let Some(spans) = regex.captures_at(input.text(), input.byte_index(start), sticky)? else {
            return Ok(None);
        };
        let Some((whole_start, whole_end)) = spans[0] else {
            return Ok(None);
        };
        self.record_legacy_regexp_input_match(subject, &input, &spans);
        let values: Vec<Value> = spans
            .iter()
            .map(|span| {
                Ok(match span {
                    Some((from, to)) => {
                        Value::Str(self.decode_regexp_text(&input, &input.text()[*from..*to])?)
                    }
                    None => Value::Undefined,
                })
            })
            .collect::<Result<_, InterpreterError>>()?;
        let result = self.alloc_array_from_values(&values)?;
        let utf16_offset = |offset: usize| input.unit_index(offset);
        let index = utf16_offset(whole_start);
        self.set_object_property(
            result,
            "index".to_string(),
            Value::Int(i64::try_from(index).unwrap_or(i64::MAX)),
        )?;
        // `input` is the subject itself (ES2020 21.2.5.2.2 step 22), lone
        // surrogates included; it was the U+FFFD projection.
        self.set_object_property(result, "input".to_string(), Value::Str(subject.clone()))?;
        let named: Vec<(String, Value)> = regex
            .group_names()
            .into_iter()
            .enumerate()
            .filter_map(|(slot, name)| name.map(|name| (name, values[slot].clone())))
            .collect();
        // A match's `groups` is OrdinaryObjectCreate(null) (ES2020 21.2.5.2.2
        // step 25): no inherited members, and a group named `__proto__` is
        // an ordinary own property (bd-9vouw.365).
        let groups = if named.is_empty() {
            Value::Undefined
        } else {
            let groups = self.alloc_object_with_prototype(None)?;
            self.store_prototype_link(groups, None);
            for (name, value) in named {
                self.set_object_property(groups, name, value)?;
            }
            Value::Object(groups)
        };
        self.set_object_property(result, "groups".to_string(), groups)?;
        if has_indices {
            let utf16 =
                |offset: usize| Value::Int(i64::try_from(utf16_offset(offset)).unwrap_or(i64::MAX));
            let mut pairs = Vec::with_capacity(spans.len());
            for span in &spans {
                pairs.push(match span {
                    Some((from, to)) => {
                        Value::Object(self.alloc_array_from_values(&[utf16(*from), utf16(*to)])?)
                    }
                    None => Value::Undefined,
                });
            }
            let indices = self.alloc_array_from_values(&pairs)?;
            let named: Vec<(String, Value)> = regex
                .group_names()
                .into_iter()
                .enumerate()
                .filter_map(|(slot, name)| name.map(|name| (name, pairs[slot].clone())))
                .collect();
            let index_groups = if named.is_empty() {
                Value::Undefined
            } else {
                let groups = self.alloc_object_with_prototype(None)?;
                self.store_prototype_link(groups, None);
                for (name, value) in named {
                    self.set_object_property(groups, name, value)?;
                }
                Value::Object(groups)
            };
            self.set_object_property(indices, "groups".to_string(), index_groups)?;
            self.set_object_property(result, "indices".to_string(), Value::Object(indices))?;
        }
        Ok(Some((Value::Object(result), utf16_offset(whole_end))))
    }

    /// RegExp.prototype[@@match], [@@matchAll], [@@replace], [@@search] and
    /// [@@split] (ES2020 21.2.5.6-11) on a RegExp receiver: the algorithms
    /// String.prototype.match and its siblings run for a RegExp argument, so
    /// `re[Symbol.split](s, n)` and `s.split(re, n)` agree.
    pub(super) fn regexp_symbol_method_call(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let method = builtin.display_name();
        // bd-9vouw.257: a receiver whose reads are observable (a user exec,
        // an overridden flags getter, a subclass, a plain object) runs the
        // ES2024 22.2.6 algorithms instead of the matcher.
        // A direct @@matchAll of a non-global RegExp yields its one match
        // (only String.prototype.matchAll requires the g flag); the
        // matcher path refused it.
        let non_global_match_all = method == "@@matchAll"
            && self
                .regexp_source_flags_from_value(&receiver)
                .is_some_and(|(_, flags)| !flags.contains('g'));
        if non_global_match_all || !self.regexp_is_pristine(&receiver) {
            let string = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
            let extra = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
            let label = self.join_arg_range_label(args)?;
            if let Some(result) =
                self.regexp_symbol_method_generic(module, method, &receiver, string, extra, &label)?
            {
                return Ok(result);
            }
        }
        let Some((source, flags)) = self.regexp_source_flags_from_value(&receiver) else {
            return Err(InterpreterError::TypeError {
                expected: format!(
                    "RegExp receiver for RegExp.prototype.{}",
                    builtin.spec_name()
                ),
                got: receiver.type_name().to_string(),
            });
        };
        // ToString(string) (21.2.5.6-11 step 3): an object argument's
        // toString runs (it read "[object Object]"), a Symbol throws. Guest
        // code may run: no collection while native locals hold the receiver.
        let input = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let input = if input.is_object_like() {
            self.gc_nested_request = None;
            self.coerce_runtime_primitive(Some(module), input, true)?
        } else {
            input
        };
        if matches!(input, Value::Symbol(_)) {
            return Err(InterpreterError::TypeError {
                expected: format!(
                    "string argument for RegExp.prototype.{}",
                    builtin.spec_name()
                ),
                got: "symbol".to_string(),
            });
        }
        let input = match input {
            Value::Str(text) => text,
            other => JsString::from(self.value_to_string(&other)),
        };
        match method {
            "@@match" => self.string_match_value(&input, &receiver),
            "@@matchAll" => {
                let label = self.join_arg_range_label(args)?;
                self.string_match_all_value(&input, &receiver, &label)
            }
            "@@search" => self.string_search_value(&input, &receiver),
            "@@split" => {
                let limit =
                    Self::split_limit(self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined));
                let mut pieces = if limit == 0 {
                    Vec::new()
                } else {
                    self.regexp_split_pieces(&input, &source, &flags)?
                };
                pieces.truncate(limit);
                Ok(Value::Object(self.alloc_array_from_values(&pieces)?))
            }
            "@@replace" => {
                let replacement = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let label = self.join_arg_range_label(args)?;
                self.string_replace_js(Some(module), &input, &receiver, &replacement, false, label)
            }
            _ => Err(InterpreterError::TypeError {
                expected: "RegExp.prototype symbol method".to_string(),
                got: method.to_string(),
            }),
        }
    }

    /// `%TypedArray%.from(source[, mapFn[, thisArg]])` and
    /// `%TypedArray%.of(...items)` (ES2020 22.2.2.1-2). `this` is the
    /// constructor: an intrinsic typed array constructor (`Uint8Array.from`)
    /// allocates directly; any other constructor (a subclass, or a function
    /// returning a typed array) goes through TypedArrayCreate (bd-9vouw.344).
    /// A non-constructor `this`, an unbound call included, is a TypeError.
    /// `from` collects its source as `Array.from` does (iterables,
    /// array-likes), then maps and converts each value in order, so a
    /// throwing conversion stops the mapper there. No-claim: an array-like
    /// source's elements are all read before the first mapper call (the
    /// specification interleaves each read with its mapping).
    pub(super) fn typed_array_static_call(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let intrinsic_kind = match &receiver {
            Value::BuiltinFunction(constructor)
                if constructor.kind == BuiltinFunctionKind::StandardConstructor =>
            {
                Self::standard_constructor_name(constructor)
                    .ok()
                    .and_then(TypedArrayKind::from_type_name)
            }
            _ => None,
        };
        if intrinsic_kind.is_none() && !self.is_constructible_value(&receiver) {
            return Err(InterpreterError::TypeError {
                expected: format!(
                    "typed array constructor as this of %TypedArray%.{}",
                    builtin.display_name()
                ),
                got: receiver.type_name().to_string(),
            });
        }
        let (values, mapper, this_arg) = if builtin.display_name() == "of" {
            let mut items = Vec::with_capacity(args.count as usize);
            for index in 0..args.count {
                items.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
            }
            (items, Value::Undefined, Value::Undefined)
        } else {
            let mapper = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
            if !matches!(mapper, Value::Undefined) && !mapper.is_callable() {
                return Err(InterpreterError::TypeError {
                    expected: "callable %TypedArray%.from mapper".to_string(),
                    got: mapper.type_name().to_string(),
                });
            }
            let this_arg = self.builtin_arg(args, 2)?.unwrap_or(Value::Undefined);
            let source_only = RegRange {
                start: args.start,
                count: args.count.min(1),
            };
            let Value::Object(list) = self.array_from_builtin(Some(module), source_only)? else {
                return Err(InterpreterError::TypeError {
                    expected: "array from %TypedArray%.from source".to_string(),
                    got: "non-array".to_string(),
                });
            };
            (self.array_like_values(list)?, mapper, this_arg)
        };
        // Guest code (the constructor, the mapper, valueOf) runs while
        // native locals hold values: no collection until this returns.
        self.gc_nested_request = None;
        let target = match intrinsic_kind {
            Some(_) => None,
            None => Some(self.typed_array_create(module, receiver, values.len())?),
        };
        let kind = match (intrinsic_kind, target) {
            (Some(kind), _) => kind,
            (None, Some(target)) => self
                .typed_array_view_for_object(target)?
                .map(|view| view.kind)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "typed array from the %TypedArray%.from constructor".to_string(),
                    got: "object".to_string(),
                })?,
            (None, None) => unreachable!("a non-intrinsic constructor creates its target"),
        };
        let argument_label = self.join_arg_range_label(args)?;
        let mut converted = Vec::with_capacity(values.len());
        for (index, value) in values.into_iter().enumerate() {
            let mapped = if matches!(mapper, Value::Undefined) {
                value
            } else {
                let (mapped, label) = self.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    mapper.clone(),
                    this_arg.clone(),
                    vec![value, Value::Int(index as i64)],
                    Some(argument_label.clone()),
                )?;
                let joined = self
                    .pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public)
                    .join(&label);
                self.replace_pending_hostcall_result_label(Some(joined))?;
                mapped
            };
            // ToNumber/ToBigInt runs the value's valueOf (bd-9vouw.273).
            let element = self
                .typed_array_element_values(Some(module), kind, vec![mapped])?
                .pop()
                .unwrap_or(Value::Undefined);
            match target {
                Some(target) => {
                    self.typed_array_indexed_set_property(target, &index.to_string(), &element)?;
                }
                None => converted.push(element),
            }
        }
        match target {
            Some(target) => {
                // The constructed target's bytes take what was written into
                // them: the source's and the mapper's labels.
                let label = self
                    .pending_hostcall_result_label
                    .clone()
                    .unwrap_or(Label::Public);
                self.join_binary_storage_label(target, &label)?;
                Ok(Value::Object(target))
            }
            None => Ok(Value::Object(
                self.alloc_typed_array_from_values(kind, &converted)?,
            )),
        }
    }

    /// ES2020 22.2.4.6 TypedArrayCreate(constructor, «length»): construct
    /// it with the length and require a typed array of at least that length
    /// (22.2.3.5.1 ValidateTypedArray), whatever its element type.
    pub(super) fn typed_array_create(
        &mut self,
        module: &Ir3Module,
        constructor: Value,
        length: usize,
    ) -> Result<ObjectId, InterpreterError> {
        let (result, label) = self.invoke_inline_construct_with_labels(
            Some(module),
            constructor,
            vec![Value::Int(i64::try_from(length).unwrap_or(i64::MAX))],
            None,
            None,
        )?;
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        let created_length = match &result {
            Value::Object(object_id) => self
                .heap
                .get(object_id.0 as usize)
                .and_then(|object| object.typed_array.as_deref())
                .map(|view| view.length),
            _ => None,
        };
        let (Value::Object(created), Some(created_length)) = (&result, created_length) else {
            return Err(InterpreterError::TypeError {
                expected: "typed array from the %TypedArray% constructor".to_string(),
                got: result.type_name().to_string(),
            });
        };
        if created_length < length {
            return Err(InterpreterError::TypeError {
                expected: format!("typed array of length {length} or more from the constructor"),
                got: format!("length {created_length}"),
            });
        }
        Ok(*created)
    }

    /// ToString(this) for a String.prototype method that takes a pattern
    /// (replace, replaceAll, split, match, matchAll, search; ES2020
    /// 21.1.3.11, 21.1.3.19, 21.1.3.10 ...): RequireObjectCoercible, then
    /// ToString running an object's @@toPrimitive/toString, after the
    /// pattern's own method was looked up and the replaceAll/matchAll
    /// flags check ran. An object `this` was converted before both, so
    /// `''.replaceAll.call(obj, /./, x)` ran obj.toString before the flags
    /// TypeError (bd-9vouw.275).
    pub(super) fn string_pattern_this(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
    ) -> Result<JsString, InterpreterError> {
        if receiver.is_object_like() {
            // Guest code runs while native locals hold values: no
            // collection until this returns.
            self.gc_nested_request = None;
            let primitive = self.coerce_runtime_primitive(Some(module), receiver.clone(), true)?;
            if matches!(primitive, Value::Symbol(_)) {
                return Err(Self::symbol_to_string_error());
            }
            return Self::require_object_coercible_to_js_string(&primitive);
        }
        Self::require_object_coercible_to_js_string(receiver)
    }

    /// ES2020 21.1.3.11/.12/.17/.18/.19 step 2: a String method whose pattern
    /// argument is an object calls that object's `@@match` / `@@matchAll` /
    /// `@@replace` / `@@search` / `@@split` method with the receiver and the
    /// remaining arguments. `None` means the ordinary algorithm runs: the
    /// argument is not an object, has no such method, or its method is this
    /// realm's RegExp.prototype builtin (whose algorithm the caller runs
    /// directly). The method's result carries the join of its inputs' labels
    /// and its own.
    pub(super) fn string_pattern_protocol_call(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        args: RegRange,
        symbol: WellKnownSymbol,
    ) -> Result<Option<Value>, InterpreterError> {
        if matches!(receiver, Value::Undefined | Value::Null) {
            return Ok(None);
        }
        let Some(pattern @ Value::Object(pattern_id)) = self.builtin_arg(args, 0)? else {
            return Ok(None);
        };
        let key = RuntimePropertyKey::Symbol(symbol.id());
        if self.regexp_uses_builtin_symbol_method(pattern_id, &key) {
            return self
                .string_pattern_builtin_symbol_call(module, receiver, args, symbol, &pattern);
        }
        let method = self.prototype_chain_get_with_receiver_runtime(
            Some(module),
            pattern_id,
            &key,
            pattern.clone(),
        )?;
        match &method {
            Value::Undefined | Value::Null => return Ok(None),
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::RegExpSymbolMethod
                    && regexp_symbol_method_key(symbol.id()) == Some(builtin.display_name()) =>
            {
                return self
                    .string_pattern_builtin_symbol_call(module, receiver, args, symbol, &pattern);
            }
            callable if callable.is_callable() => {}
            other => {
                return Err(InterpreterError::TypeError {
                    expected: format!("callable {} method", symbol.name()),
                    got: other.type_name().to_string(),
                });
            }
        }
        let mut arguments = vec![receiver.clone()];
        for index in 1..args.count {
            arguments.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
        }
        let label = self.join_arg_range_label(args)?;
        let (result, result_label) = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            method,
            pattern,
            arguments,
            Some(label.clone()),
        )?;
        self.replace_pending_hostcall_result_label(Some(label.join(&result_label)))?;
        Ok(Some(result))
    }

    /// A String method's pattern whose `symbol` method is this realm's
    /// RegExp.prototype builtin: `None` (the caller's matcher algorithm)
    /// for a pristine RegExp, otherwise the builtin's specification
    /// algorithm with `this` the pattern (bd-9vouw.257).
    pub(super) fn string_pattern_builtin_symbol_call(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        args: RegRange,
        symbol: WellKnownSymbol,
        pattern: &Value,
    ) -> Result<Option<Value>, InterpreterError> {
        let Some(method) = regexp_symbol_method_key(symbol.id()) else {
            return Ok(None);
        };
        if self.regexp_is_pristine(pattern) {
            return Ok(None);
        }
        let extra = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let label = self.join_arg_range_label(args)?;
        self.regexp_symbol_method_generic(module, method, pattern, receiver.clone(), extra, &label)
    }

    /// Whether `object_id` is a RegExp whose `key` method is certainly the
    /// builtin: no own property shadows it, its prototype is
    /// %RegExp.prototype% (or none), and %RegExp.prototype% neither stores
    /// its own `key` property nor had the intrinsic one deleted. The common
    /// `s.split(/,/)` then skips the property walk.
    pub(super) fn regexp_uses_builtin_symbol_method(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> bool {
        if self.regexp_source_flags_from_object(object_id).is_none() {
            return false;
        }
        let Some(object) = self.heap.get(object_id.0 as usize) else {
            return false;
        };
        if object.own_runtime_property_value(key).is_some() {
            return false;
        }
        let regexp_prototype = self.builtin_prototypes.get("RegExp").copied();
        match object.prototype {
            None => true,
            // A deleted intrinsic method is absent too (bd-9vouw.498).
            Some(prototype) if Some(prototype) == regexp_prototype => self
                .heap
                .get(prototype.0 as usize)
                .is_some_and(|prototype| {
                    prototype.own_runtime_property_value(key).is_none()
                        && !prototype.deleted_virtual_keys.contains(key)
                }),
            Some(_) => false,
        }
    }

    /// ES2020 21.2.5.2 RegExp.prototype.exec: a global or sticky RegExp
    /// starts at and updates `lastIndex` (UTF-16); others search from 0.
    pub(super) fn regexp_prototype_exec(
        &mut self,
        receiver: Value,
        input: &Value,
    ) -> Result<Value, InterpreterError> {
        self.regexp_prototype_exec_from(receiver, input, None)
    }

    /// RegExpBuiltinExec (ES2020 21.2.5.2.2), with `last_index` the
    /// already-coerced ToNumber(lastIndex) when it was an object
    /// (`regexp_coerced_last_index`); `None` reads the stored number.
    pub(super) fn regexp_prototype_exec_from(
        &mut self,
        receiver: Value,
        input: &Value,
        last_index: Option<f64>,
    ) -> Result<Value, InterpreterError> {
        let Some((source, flags)) = self.regexp_source_flags_from_value(&receiver) else {
            return Err(InterpreterError::TypeError {
                expected: "RegExp receiver for RegExp.prototype.exec".to_string(),
                got: receiver.type_name().to_string(),
            });
        };
        let Value::Object(regexp_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: "RegExp receiver for RegExp.prototype.exec".to_string(),
                got: receiver.type_name().to_string(),
            });
        };
        // A string subject is used as it is (shared); copying it, counting
        // its units and mapping lastIndex from its start made each exec of
        // a loop over a long string cost the whole string (bd-9vouw.475).
        let subject = match input {
            Value::Str(text) => text.clone(),
            other => JsString::from(self.value_to_string(other)),
        };
        let regex = self.compile_regexp_pattern(&source, &flags)?;
        let sticky = flags.contains('y');
        let tracks_last_index = sticky || flags.contains('g');
        let last_index = match (tracks_last_index, last_index) {
            (false, _) => 0,
            (true, Some(number)) => Self::to_length_index(number),
            (true, None) => self.regexp_last_index_start(regexp_id),
        };
        let found = if last_index > subject.utf16_len() {
            None
        } else {
            self.regexp_exec_at(
                &regex,
                &subject,
                last_index,
                sticky,
                flags.contains('d'),
                flags.contains('u') || flags.contains('v'),
            )?
        };
        match found {
            None => {
                if tracks_last_index {
                    self.set_regexp_last_index(regexp_id, 0)?;
                }
                Ok(Value::Null)
            }
            Some((result, end)) => {
                if tracks_last_index {
                    self.set_regexp_last_index(regexp_id, end)?;
                }
                Ok(result)
            }
        }
    }

    /// ToLength(R.lastIndex) (ES2020 21.2.5.2.2 step 4) as a UTF-16 index:
    /// NaN and negatives are 0, and a huge value (Infinity) is past any
    /// input, so the match fails.
    pub(super) fn regexp_last_index_start(&self, regexp_id: ObjectId) -> usize {
        let value = self
            .heap
            .get(regexp_id.0 as usize)
            .and_then(|object| object.properties.get("lastIndex").cloned())
            .unwrap_or(Value::Int(0));
        Self::to_length_index(Self::coerce_to_float(&value).unwrap_or(0.0))
    }

    /// ToLength of an already-numeric lastIndex, as a UTF-16 index.
    pub(super) fn to_length_index(number: f64) -> usize {
        if number > 0.0 {
            number.trunc() as usize
        } else {
            0
        }
    }

    /// ES2020 21.2.5.2.2 step 4: ToLength(? Get(R, "lastIndex")) runs for
    /// every RegExpBuiltinExec, global or not, so an object lastIndex's
    /// valueOf is called (and may throw) exactly once; the property keeps
    /// the object. `Some` is the coerced number for an object lastIndex,
    /// `None` when the stored value needs no guest code (bd-9vouw.257).
    pub(super) fn regexp_coerced_last_index(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
    ) -> Result<Option<f64>, InterpreterError> {
        let Value::Object(regexp_id) = receiver else {
            return Ok(None);
        };
        let stored = self
            .heap
            .get(regexp_id.0 as usize)
            .and_then(|object| object.properties.get("lastIndex").cloned());
        let Some(value) = stored.filter(Value::is_object_like) else {
            return Ok(None);
        };
        let number = self.object_to_number_primitive(Some(module), value)?;
        if matches!(number, Value::Symbol(_) | Value::BigInt(_)) {
            return Err(InterpreterError::TypeError {
                expected: "lastIndex convertible to a number".to_string(),
                got: number.type_name().to_string(),
            });
        }
        Ok(Some(Self::coerce_to_float(&number).unwrap_or(f64::NAN)))
    }

    /// RegExpExec's `exec` (ES2020 21.2.5.2.1 steps 3-4): a callable
    /// `exec` other than the intrinsic RegExp.prototype.exec, which runs
    /// instead of the matcher; `None` when the intrinsic (or no callable)
    /// `exec` leaves the builtin path (bd-9vouw.257).
    pub(super) fn regexp_user_exec(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
    ) -> Result<Option<Value>, InterpreterError> {
        let exec = self.get_v(
            module,
            receiver,
            &RuntimePropertyKey::String(JsString::from("exec")),
        )?;
        let intrinsic = matches!(&exec, Value::BuiltinFunction(builtin)
            if builtin.kind == BuiltinFunctionKind::RegExpPrototypeExec);
        Ok((!intrinsic && exec.is_callable()).then_some(exec))
    }

    /// Call a user `exec` with `receiver` as `this` and `input` (carrying
    /// `argument_label`); its result must be an object or null (ES2020
    /// 21.2.5.2.1 step 4.b).
    pub(super) fn regexp_call_user_exec(
        &mut self,
        module: &Ir3Module,
        exec: Value,
        receiver: &Value,
        input: &Value,
        argument_label: Option<Label>,
    ) -> Result<Value, InterpreterError> {
        let (result, label) = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            exec,
            receiver.clone(),
            vec![input.clone()],
            argument_label,
        )?;
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        self.observe_scoped_callback_result()?;
        if !matches!(result, Value::Null) && !result.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "object or null from a RegExp exec method".to_string(),
                got: result.type_name().to_string(),
            });
        }
        Ok(result)
    }

    /// `Set(R, "lastIndex", index, true)` (ES2020 21.2.5.2.2): a RegExp
    /// whose `lastIndex` was made read-only turns the write into a
    /// TypeError instead of ignoring it.
    pub(super) fn set_regexp_last_index(
        &mut self,
        regexp_id: ObjectId,
        index: usize,
    ) -> Result<(), InterpreterError> {
        let key = RuntimePropertyKey::String(JsString::from("lastIndex"));
        let read_only = self.heap.get(regexp_id.0 as usize).is_some_and(|regexp| {
            regexp.own_runtime_property_value(&key).is_some()
                && !regexp.own_property_attributes(&key).writable
        });
        if read_only {
            return Err(InterpreterError::TypeError {
                expected: "writable RegExp lastIndex".to_string(),
                got: "read-only lastIndex".to_string(),
            });
        }
        self.set_object_property(
            regexp_id,
            "lastIndex".to_string(),
            Value::Int(i64::try_from(index).unwrap_or(i64::MAX)),
        )
    }

    /// RegExpBuiltinExec for a sticky, non-global pattern: it matches only
    /// at `lastIndex`, which then holds the match end (or 0 on failure).
    pub(super) fn sticky_regexp_captures(
        &mut self,
        regexp_id: ObjectId,
        regex: &CompiledRegExp,
        input: &RegExpInput<'_>,
    ) -> Result<Option<Captures>, InterpreterError> {
        let start = self.regexp_last_index_start(regexp_id);
        let found = if start > input.unit_index(input.text().len()) {
            None
        } else {
            regex.captures_at(input.text(), input.byte_index(start), true)?
        };
        let next = found
            .as_ref()
            .and_then(|spans| spans[0])
            .map_or(0, |(_, end)| input.unit_index(end));
        self.set_regexp_last_index(regexp_id, next)?;
        Ok(found)
    }

    /// `WeakMap.prototype.get/set/has/delete` over the WeakMap side storage
    /// (object keys only; entries are charged like the constructor's seeding).
    /// `WeakSet.prototype.add/has/delete` (ES2020 23.4.3) over the
    /// constructor's `__values` storage, keyed by object identity. A
    /// non-object value cannot be a member: `add` throws, `has` and `delete`
    /// report false.
    /// HasOwnProperty(O, P) for `hasOwnProperty` and `Object.hasOwn`. A
    /// function's own properties live on its backing object; once that
    /// exists it decides, so a deleted `name` is gone (bd-9vouw.17).
    pub(super) fn value_has_own_property(
        &mut self,
        module: Option<&Ir3Module>,
        receiver: &Value,
        property: &Value,
    ) -> Result<bool, InterpreterError> {
        if let Value::Object(object_id) = receiver {
            self.join_pending_hostcall_stream_label(*object_id)?;
            // A typed array owns exactly its valid integer indices among
            // the numeric keys (ES2024 10.4.5.1).
            let key = self.executable_property_key_from_value(property);
            if let Some(name) = key.as_str()
                && let Some(valid) = self.typed_array_numeric_key_is_valid(*object_id, name)?
            {
                return Ok(valid);
            }
            // A Proxy answers through [[GetOwnProperty]]: its
            // getOwnPropertyDescriptor trap, else its target's (ES2020
            // 9.5.5). Its own record has none of the target's keys, so every
            // key read false; mobx's `hasOwnProperty.call(proxy, $mobx)`
            // then made a second administration and recursed (bd-9vouw.236).
            if self.active_proxy_record(*object_id)?.is_some() {
                let key = self.executable_property_key_from_value(property);
                let descriptor =
                    self.proxy_aware_own_property_descriptor(module, *object_id, &key, 0)?;
                return Ok(!matches!(descriptor, Value::Undefined));
            }
        }
        let Some(module) = module else {
            return Ok(self.object_own_property_contains(receiver, property));
        };
        let key = self.executable_property_key_from_value(property);
        // A callable proxy answers through its getOwnPropertyDescriptor
        // trap or its target, as an object proxy does (bd-9vouw.263:
        // Function.prototype.bind's HasOwnProperty(Target, "length")).
        if let Value::BuiltinFunction(builtin) = receiver
            && builtin.kind == BuiltinFunctionKind::CallableProxy
        {
            let proxy = Self::callable_proxy_record_id(builtin)?;
            let descriptor =
                self.proxy_aware_own_property_descriptor(Some(module), proxy, &key, 0)?;
            return Ok(!matches!(descriptor, Value::Undefined));
        }
        if let Value::BuiltinFunction(builtin) = receiver
            && builtin.kind == BuiltinFunctionKind::StandardConstructor
            && let Some(name) = key.as_str()
            && self
                .function_own_property_object(module, receiver)?
                .is_none()
            && self
                .standard_constructor_own_static(builtin, name)?
                .is_some()
        {
            return Ok(true);
        }
        if let Some(own) = self.function_own_property_exists(module, receiver, &key)? {
            return Ok(own);
        }
        if self.object_own_property_contains(receiver, property) {
            return Ok(true);
        }
        let backing = self.own_property_holder(Some(module), receiver, false)?;
        Ok(backing.is_some_and(|backing| {
            self.object_own_property_contains(&Value::Object(backing), property)
        }))
    }

    /// WeakSet membership is private and weak, including objects represented
    /// by function, promise, generator and iterator carriers.
    pub(super) fn weakset_method(
        &mut self,
        module: Option<&Ir3Module>,
        method: &str,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let set_id = self.validate_weak_collection_receiver(&receiver, "WeakSet")?;
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let key = self.weak_collection_key(module, &value, method == "add")?;
        let label = self.join_arg_range_label(args)?;
        let label = self.join_owned_label_with_temporary_budget(
            label,
            self.object_mutation_labels
                .get(&set_id)
                .unwrap_or(&Label::Public),
        )?;
        let label = self.join_owned_label_with_temporary_budget(
            label,
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
        )?;
        match method {
            "add" => {
                let Some(key) = key else {
                    return Err(InterpreterError::TypeError {
                        expected: "object WeakSet value".to_string(),
                        got: value.type_name().to_string(),
                    });
                };
                self.update_weakset_membership(set_id, key, true, label)?;
                Ok(receiver)
            }
            "has" => {
                let storage = &self.weakmap_storage[&set_id];
                let present = match key {
                    Some(WeakMapKey::Object(id)) => storage.has(id),
                    Some(WeakMapKey::Symbol(id)) => storage.get_symbol(id).is_some(),
                    None => false,
                };
                self.replace_pending_hostcall_result_label(Some(label))?;
                Ok(Value::Bool(present))
            }
            "delete" => {
                let Some(key) = key else {
                    self.replace_pending_hostcall_result_label(Some(label))?;
                    return Ok(Value::Bool(false));
                };
                let present = self.update_weakset_membership(set_id, key, false, label)?;
                Ok(Value::Bool(present))
            }
            other => Err(InterpreterError::TypeError {
                expected: "WeakSet method".to_string(),
                got: other.to_string(),
            }),
        }
    }

    /// Publish membership and its control provenance together. Reserve all
    /// retained bytes before changing either the private table or its label;
    /// a memory refusal must not add/delete a key or expose a public result.
    pub(super) fn update_weakset_membership(
        &mut self,
        set_id: ObjectId,
        key: WeakMapKey,
        insert: bool,
        label: Label,
    ) -> Result<bool, InterpreterError> {
        let storage = &self.weakmap_storage[&set_id];
        let present = match key {
            WeakMapKey::Object(id) => storage.has(id),
            WeakMapKey::Symbol(id) => storage.get_symbol(id).is_some(),
        };
        let entry_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_mul(2)
            .saturating_add(Self::estimate_value_bytes(&Value::Bool(true)));
        let label = self.join_owned_label_with_temporary_budget(
            label,
            self.object_mutation_labels
                .get(&set_id)
                .unwrap_or(&Label::Public),
        )?;
        let label = self.join_owned_label_with_temporary_budget(
            label,
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
        )?;
        let previous_label_bytes = self
            .object_mutation_labels
            .get(&set_id)
            .map_or(0, Self::estimate_object_mutation_label_entry_bytes);
        let next_label_bytes = if label == Label::Public {
            0
        } else {
            Self::estimate_object_mutation_label_entry_bytes(&label)
        };
        let previous_result_bytes = self
            .pending_hostcall_result_label
            .as_ref()
            .map_or(0, Self::estimate_label_bytes);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(if present { entry_bytes } else { 0 })
            .saturating_add(if insert { entry_bytes } else { 0 })
            .saturating_sub(previous_label_bytes)
            .saturating_add(next_label_bytes)
            .saturating_sub(previous_result_bytes)
            .saturating_add(Self::estimate_label_bytes(&label));
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        // Keep the incoming owned label for the owner, and clone only the
        // result label after both retained and temporary bytes are admitted.
        self.check_temporary_memory_budget(Self::estimate_label_bytes(&label).saturating_mul(2))?;
        let result_label = label.clone();
        self.before_seed_surface_write();
        let storage = self
            .weakmap_storage
            .get_mut(&set_id)
            .expect("validated WeakSet");
        match (key, insert) {
            (WeakMapKey::Object(id), true) => storage.set(id, Value::Bool(true)),
            (WeakMapKey::Symbol(id), true) => storage.set_symbol(id, Value::Bool(true)),
            (WeakMapKey::Object(id), false) => {
                storage.delete(id);
            }
            (WeakMapKey::Symbol(id), false) => {
                storage.delete_symbol(id);
            }
        }
        if label == Label::Public {
            self.object_mutation_labels.remove(&set_id);
        } else {
            self.object_mutation_labels.insert(set_id, label);
        }
        self.pending_hostcall_result_label = Some(result_label);
        self.estimated_memory_bytes = requested_bytes;
        Ok(present)
    }

    /// ES2021 CanBeHeldWeakly: an object, or a Symbol outside the global
    /// registry (`Symbol.for`).
    pub(super) fn can_be_held_weakly(&self, value: &Value) -> bool {
        match value {
            Value::Symbol(symbol) => self.symbol_state.key_for(*symbol).is_none(),
            other => other.is_object_like(),
        }
    }

    /// `new WeakRef(target)` (ES2021 26.1.1.1). The target is held strongly:
    /// when a target is collected is not observable, and holding it keeps
    /// replay deterministic, so `deref()` always returns it. The slot keeps
    /// the target register's IFC label.
    pub(super) fn construct_weak_ref(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let target = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };
        if !self.can_be_held_weakly(&target) {
            return Err(InterpreterError::TypeError {
                expected: "WeakRef target that is an object or a non-registered symbol".to_string(),
                got: target.type_name().to_string(),
            });
        }
        let label = if args.count > 0 {
            self.get_register_label(args.start)?.clone()
        } else {
            Label::Public
        };
        let prototype = self.ensure_builtin_prototype("WeakRef")?;
        let weak_ref = self.alloc_object_with_prototype(Some(prototype))?;
        self.set_object_brand(weak_ref, "WeakRef")?;
        self.set_weak_ref_target(weak_ref, target, label)?;
        Ok(Value::Object(weak_ref))
    }

    /// Install [[WeakRefTarget]] only after its full value/label ownership
    /// fits the memory budget. Ordinary properties and integrity levels do
    /// not participate in this engine-private edge.
    pub(super) fn set_weak_ref_target(
        &mut self,
        weak_ref: ObjectId,
        value: Value,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let object = self
            .heap
            .get(weak_ref.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: weak_ref.0 })?;
        if object.brand() != Some("WeakRef") || !self.can_be_held_weakly(&value) {
            return Err(InterpreterError::TypeError {
                expected: "WeakRef receiver and weakly holdable target".to_string(),
                got: value.type_name().to_string(),
            });
        }
        let previous_bytes = object
            .weak_ref_target
            .as_deref()
            .map_or(0, Self::estimate_weak_ref_target_bytes);
        let target = WeakRefTarget { value, label };
        self.apply_memory_component_delta(
            previous_bytes,
            Self::estimate_weak_ref_target_bytes(&target),
        )?;
        self.mutate_heap(|heap| {
            let slot = &mut heap[weak_ref.0 as usize].weak_ref_target;
            match slot.as_deref_mut() {
                Some(current) => *current = target,
                None => *slot = Some(Box::new(target)),
            }
        });
        self.gc_write_barrier(weak_ref);
        Ok(())
    }

    /// `WeakRef.prototype.deref()` (ES2021 26.1.3.2).
    pub(super) fn weak_ref_deref(&mut self, receiver: &Value) -> Result<Value, InterpreterError> {
        let target = match receiver {
            Value::Object(weak_ref) => self
                .heap
                .get(weak_ref.0 as usize)
                .filter(|object| object.brand() == Some("WeakRef"))
                .and_then(|object| object.weak_ref_target.as_deref()),
            _ => None,
        }
        .ok_or_else(|| InterpreterError::TypeError {
            expected: "WeakRef receiver for WeakRef.prototype.deref".to_string(),
            got: receiver.type_name().to_string(),
        })?;
        self.check_temporary_memory_budget(
            Self::estimate_value_bytes(&target.value)
                .saturating_add(Self::estimate_label_bytes(&target.label)),
        )?;
        let value = target.value.clone();
        let label = target.label.clone();
        self.join_into_pending_hostcall_result_label(Some(label))?;
        self.observe_scoped_callback_result()?;
        Ok(value)
    }

    /// `new FinalizationRegistry(cleanup)` (ES2021 26.2.1.1). Cleanup
    /// callbacks never run: collection is not observable, and a registry that
    /// never calls back is conformant and replay-deterministic. It keeps only
    /// the unregister tokens, for `unregister`'s result.
    pub(super) fn construct_finalization_registry(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let cleanup = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };
        if !cleanup.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable FinalizationRegistry cleanup".to_string(),
                got: cleanup.type_name().to_string(),
            });
        }
        let prototype = self.ensure_builtin_prototype("FinalizationRegistry")?;
        let registry = self.alloc_object_with_prototype(Some(prototype))?;
        let tokens = self.alloc_object_with_prototype(None)?;
        self.set_object_brand(registry, "FinalizationRegistry")?;
        self.set_collection_storage(registry, tokens)?;
        Ok(Value::Object(registry))
    }

    /// `register(target, holdings[, token])` and `unregister(token)` (ES2021
    /// 26.2.3.2-3).
    pub(super) fn finalization_registry_method(
        &mut self,
        method: &str,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let tokens = match &receiver {
            Value::Object(registry) => {
                self.collection_storage_id(*registry, "FinalizationRegistry")
            }
            _ => None,
        }
        .ok_or_else(|| InterpreterError::TypeError {
            expected: format!(
                "FinalizationRegistry receiver for FinalizationRegistry.prototype.{method}"
            ),
            got: receiver.type_name().to_string(),
        })?;
        let invalid_token = |token: &Value| InterpreterError::TypeError {
            expected: "unregister token that is an object or a non-registered symbol".to_string(),
            got: token.type_name().to_string(),
        };
        match method {
            "register" => {
                let target = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let holdings = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let token = self.builtin_arg(args, 2)?.unwrap_or(Value::Undefined);
                if !self.can_be_held_weakly(&target) {
                    return Err(InterpreterError::TypeError {
                        expected: "FinalizationRegistry target that is an object or a \
                                   non-registered symbol"
                            .to_string(),
                        got: target.type_name().to_string(),
                    });
                }
                if Self::collection_key_repr(&target) == Self::collection_key_repr(&holdings) {
                    return Err(InterpreterError::TypeError {
                        expected: "FinalizationRegistry holdings that are not the target"
                            .to_string(),
                        got: "the target itself".to_string(),
                    });
                }
                match &token {
                    Value::Undefined => {}
                    token if self.can_be_held_weakly(token) => {
                        self.set_object_property(
                            tokens,
                            Self::collection_key_repr(token),
                            token.clone(),
                        )?;
                    }
                    token => return Err(invalid_token(token)),
                }
                Ok(Value::Undefined)
            }
            "unregister" => {
                let token = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                if !self.can_be_held_weakly(&token) {
                    return Err(invalid_token(&token));
                }
                let key =
                    RuntimePropertyKey::String(JsString::from(Self::collection_key_repr(&token)));
                Ok(Value::Bool(
                    self.remove_object_runtime_property(tokens, &key)?,
                ))
            }
            other => Err(InterpreterError::TypeError {
                expected: "FinalizationRegistry method".to_string(),
                got: other.to_string(),
            }),
        }
    }

    pub(super) fn weakmap_method(
        &mut self,
        module: &Ir3Module,
        method: &str,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let weakmap_id = self.validate_weakmap_receiver(receiver.clone())?;
        let key = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        // Any object is a valid key: immer and memoizers key WeakMaps by
        // function, delay by promise (bd-9vouw.220). Its identity is its
        // own-property holder (a function, promise, generator or iterator
        // uses its backing object), created for `set` and only looked up
        // otherwise.
        let key_id = if key.is_object_like() {
            self.own_property_holder(Some(module), &key, method == "set")?
                .map(|id| id.0)
        } else {
            None
        };
        // A symbol outside the global registry is a key too (ES2023
        // CanBeHeldWeakly); `Symbol.for` symbols are refused like primitives.
        let symbol_key = match &key {
            Value::Symbol(symbol) if self.can_be_held_weakly(&key) => Some(symbol.0),
            _ => None,
        };
        let Some(storage) = self.weakmap_storage.get(&weakmap_id) else {
            return Err(InterpreterError::TypeError {
                expected: "live WeakMap storage".to_string(),
                got: "missing storage".to_string(),
            });
        };
        let entry_bytes = |value: &Value| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_mul(2)
                .saturating_add(Self::estimate_value_bytes(value))
        };
        if let Some(symbol) = symbol_key {
            return match method {
                "get" => Ok(storage
                    .get_symbol(symbol)
                    .cloned()
                    .unwrap_or(Value::Undefined)),
                "has" => Ok(Value::Bool(storage.get_symbol(symbol).is_some())),
                "delete" => {
                    let released = storage.get_symbol(symbol).map(entry_bytes).unwrap_or(0);
                    self.before_seed_surface_write();
                    let deleted = self
                        .weakmap_storage
                        .get_mut(&weakmap_id)
                        .expect("WeakMap storage was checked above")
                        .delete_symbol(symbol);
                    if deleted {
                        self.estimated_memory_bytes =
                            self.estimated_memory_bytes.saturating_sub(released);
                    }
                    Ok(Value::Bool(deleted))
                }
                "set" => {
                    let value = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                    let previous = storage.get_symbol(symbol).map(entry_bytes).unwrap_or(0);
                    self.apply_memory_component_delta(previous, entry_bytes(&value))?;
                    self.before_seed_surface_write();
                    self.weakmap_storage
                        .get_mut(&weakmap_id)
                        .expect("WeakMap storage was checked above")
                        .set_symbol(symbol, value);
                    Ok(receiver)
                }
                _ => Err(InterpreterError::TypeError {
                    expected: "WeakMap method".to_string(),
                    got: method.to_string(),
                }),
            };
        }
        match method {
            "get" => Ok(key_id
                .and_then(|key| storage.get(key).cloned())
                .unwrap_or(Value::Undefined)),
            "has" => Ok(Value::Bool(key_id.is_some_and(|key| storage.has(key)))),
            "delete" => {
                let Some(key) = key_id else {
                    return Ok(Value::Bool(false));
                };
                let released = storage.get(key).map(entry_bytes).unwrap_or(0);
                self.before_seed_surface_write();
                let storage = self
                    .weakmap_storage
                    .get_mut(&weakmap_id)
                    .expect("WeakMap storage was checked above");
                let deleted = storage.delete(key);
                if deleted {
                    self.estimated_memory_bytes =
                        self.estimated_memory_bytes.saturating_sub(released);
                }
                Ok(Value::Bool(deleted))
            }
            "set" => {
                let Some(key) = key_id else {
                    return Err(InterpreterError::TypeError {
                        expected: "object WeakMap key".to_string(),
                        got: key.type_name().to_string(),
                    });
                };
                let value = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let previous = storage.get(key).map(entry_bytes).unwrap_or(0);
                self.apply_memory_component_delta(previous, entry_bytes(&value))?;
                self.before_seed_surface_write();
                self.weakmap_storage
                    .get_mut(&weakmap_id)
                    .expect("WeakMap storage was checked above")
                    .set(key, value);
                Ok(receiver)
            }
            _ => Err(InterpreterError::TypeError {
                expected: "WeakMap method".to_string(),
                got: method.to_string(),
            }),
        }
    }

    /// Number.prototype.toPrecision (ES2020 20.1.3.5) and toExponential
    /// (20.1.3.2) for a finite `number`. `significant` counts significant
    /// digits (`None`: as many as needed to round-trip, toExponential only).
    /// Rounding is round-half-up on the exact decimal value of the double,
    /// as the spec's "pick the larger n" tie rule requires.
    pub(super) fn format_number_significant(
        number: f64,
        significant: Option<usize>,
        exponential: bool,
    ) -> String {
        let sign = if number < 0.0 { "-" } else { "" };
        let magnitude = number.abs();
        let (digits, exponent) = if magnitude == 0.0 {
            let count = significant.unwrap_or(1).max(1);
            ("0".repeat(count), 0i32)
        } else {
            match significant {
                None => {
                    let shortest = format!("{magnitude:e}");
                    let (mantissa, exponent) =
                        shortest.split_once('e').unwrap_or((shortest.as_str(), "0"));
                    (
                        mantissa.replace('.', ""),
                        exponent.parse::<i32>().unwrap_or(0),
                    )
                }
                Some(count) => {
                    // The exact expansion of any finite double has at most
                    // 767 significant digits.
                    let exact = format!("{magnitude:.800e}");
                    let (mantissa, exponent) =
                        exact.split_once('e').unwrap_or((exact.as_str(), "0"));
                    let mut exponent = exponent.parse::<i32>().unwrap_or(0);
                    let all: Vec<u8> = mantissa.bytes().filter(|byte| *byte != b'.').collect();
                    let mut kept: Vec<u8> = all[..count.min(all.len())].to_vec();
                    while kept.len() < count {
                        kept.push(b'0');
                    }
                    if all.get(count).is_some_and(|digit| *digit >= b'5') {
                        let mut index = kept.len();
                        loop {
                            if index == 0 {
                                kept.insert(0, b'1');
                                kept.pop();
                                exponent += 1;
                                break;
                            }
                            index -= 1;
                            if kept[index] == b'9' {
                                kept[index] = b'0';
                            } else {
                                kept[index] += 1;
                                break;
                            }
                        }
                    }
                    (String::from_utf8(kept).unwrap_or_default(), exponent)
                }
            }
        };
        let precision = i32::try_from(digits.len()).unwrap_or(i32::MAX);
        if exponential || exponent < -6 || exponent >= precision {
            let (first, rest) = digits.split_at(1);
            let fraction = if rest.is_empty() {
                String::new()
            } else {
                format!(".{rest}")
            };
            let exponent_sign = if exponent >= 0 { '+' } else { '-' };
            return format!("{sign}{first}{fraction}e{exponent_sign}{}", exponent.abs());
        }
        if exponent >= 0 {
            let split = usize::try_from(exponent).unwrap_or(0) + 1;
            let (integer, fraction) = digits.split_at(split.min(digits.len()));
            if fraction.is_empty() {
                format!("{sign}{integer}")
            } else {
                format!("{sign}{integer}.{fraction}")
            }
        } else {
            let zeros = usize::try_from(-exponent - 1).unwrap_or(0);
            format!("{sign}0.{}{digits}", "0".repeat(zeros))
        }
    }

    /// ES2020 19.2.3.2 Function.prototype.bind. The bound function's private
    /// state object holds the target, the bound `this`, the bound arguments
    /// and the `name` and `length` read from the target at bind time; its
    /// mutation label carries every input's label, and every call through
    /// the bound function joins that label into its arguments.
    pub(super) fn function_prototype_bind(
        &mut self,
        module: &Ir3Module,
        target: Value,
        target_register: Option<u32>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if !target.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable Function.prototype.bind receiver".to_string(),
                got: target.type_name().to_string(),
            });
        }
        let bound_this = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let mut bound_arguments = Vec::with_capacity(args.count.saturating_sub(1) as usize);
        for index in 1..args.count {
            bound_arguments.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
        }
        let mut label = self.join_arg_range_label(args)?;
        if let Some(register) = target_register {
            label = label.join(self.get_register_label(register)?);
        }
        // Steps 4-8 (ES2024 20.2.3.2): HasOwnProperty(Target, "length"),
        // then Get(Target, "length") and Get(Target, "name"). A getter or a
        // proxy trap runs (and may throw) now; later changes to the target
        // do not reach the bound function. Guest code runs while native
        // locals hold values: no collection until this returns.
        self.gc_nested_request = None;
        let mut length = Value::Int(0);
        if self.value_has_own_property(Some(module), &target, &Value::str("length"))? {
            let bound_count = i64::try_from(bound_arguments.len()).unwrap_or(i64::MAX);
            length = match self.get_v(
                module,
                &target,
                &RuntimePropertyKey::String(JsString::from("length")),
            )? {
                Value::Int(target_length) => {
                    Value::Int(target_length.saturating_sub(bound_count).max(0))
                }
                Value::Float(target_length) if target_length.inner() == f64::INFINITY => {
                    Value::Float(Float64::new(f64::INFINITY))
                }
                Value::Float(target_length) if target_length.inner().is_finite() => {
                    let remaining = target_length.inner().trunc() - bound_count as f64;
                    if remaining > 0.0 {
                        js_number_to_value(remaining)
                    } else {
                        Value::Int(0)
                    }
                }
                _ => Value::Int(0),
            };
        }
        let name = match self.get_v(
            module,
            &target,
            &RuntimePropertyKey::String(JsString::from("name")),
        )? {
            Value::Str(target_name) => format!("bound {target_name}"),
            _ => "bound ".to_string(),
        };
        if let Some(getter_label) = self.take_pending_hostcall_result_label() {
            label = label.join(&getter_label);
        }
        let arguments_id = self.alloc_array_from_values(&bound_arguments)?;
        let state = self.alloc_object_with_prototype(None)?;
        self.set_object_property(state, "target".to_string(), target)?;
        self.set_object_property(state, "this".to_string(), bound_this)?;
        self.set_object_property(state, "arguments".to_string(), Value::Object(arguments_id))?;
        self.set_object_property(state, "name".to_string(), Value::str(name))?;
        self.set_object_property(state, "length".to_string(), length)?;
        self.join_object_mutation_label(state, &label)?;
        self.join_object_mutation_label(arguments_id, &label)?;
        let mut bound = BuiltinFunction::new_kind(BuiltinFunctionKind::BoundFunction);
        bound.bound_object = Some(state.0);
        self.replace_pending_hostcall_result_label(Some(label))?;
        Ok(Value::BuiltinFunction(bound))
    }

    /// A bound function's [[BoundTargetFunction]], [[BoundThis]] and
    /// [[BoundArguments]] (ES2020 9.4.1), plus the private state object that
    /// carries their label.
    pub(super) fn bound_function_parts(
        &self,
        builtin: &BuiltinFunction,
    ) -> Result<(Value, Value, Vec<Value>, ObjectId), InterpreterError> {
        let state =
            builtin
                .bound_object
                .map(ObjectId)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "bound function state".to_string(),
                    got: "bound function without state".to_string(),
                })?;
        let object = self
            .heap
            .get(state.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: state.0 })?;
        let field = |name: &str| {
            object
                .properties
                .get(name)
                .cloned()
                .unwrap_or(Value::Undefined)
        };
        let target = field("target");
        let bound_this = field("this");
        let Value::Object(arguments_id) = field("arguments") else {
            return Err(InterpreterError::TypeError {
                expected: "bound function arguments".to_string(),
                got: "missing bound arguments".to_string(),
            });
        };
        let arguments_object = self
            .heap
            .get(arguments_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: arguments_id.0 })?;
        let bound_count = match arguments_object.properties.get("length") {
            Some(Value::Int(length)) => usize::try_from(*length).unwrap_or(0),
            _ => 0,
        };
        let bound_arguments = (0..bound_count)
            .map(|index| {
                arguments_object
                    .properties
                    .get(&index.to_string())
                    .cloned()
                    .unwrap_or(Value::Undefined)
            })
            .collect();
        Ok((target, bound_this, bound_arguments, state))
    }

    /// The target of a bound function, else the value itself.
    pub(super) fn bound_function_target(
        &self,
        value: &Value,
    ) -> Result<Option<Value>, InterpreterError> {
        match value {
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::BoundFunction =>
            {
                Ok(Some(self.bound_function_parts(builtin)?.0))
            }
            _ => Ok(None),
        }
    }

    /// ES2020 9.4.1.2 [[Construct]] of a bound function: construct the target
    /// with the bound arguments followed by the call's own. `new.target` is
    /// the target unless an explicit one other than the bound function
    /// itself is given (`Reflect.construct(bound, args, F)`), which passes
    /// through. Every argument carries the call's and the bound state's
    /// labels.
    pub(super) fn construct_bound_function(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        new_target: Option<(Value, Label)>,
    ) -> Result<(Value, Label), InterpreterError> {
        let bound = Value::BuiltinFunction(builtin.clone());
        let new_target = new_target.filter(|(value, _)| !Self::same_value(value, &bound));
        let (target, _bound_this, mut arguments, state) = self.bound_function_parts(builtin)?;
        if !self.is_constructible_value(&target) {
            return Err(InterpreterError::TypeError {
                expected: "bound function with a constructible target".to_string(),
                got: target.type_name().to_string(),
            });
        }
        for index in 0..args.count {
            arguments.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
        }
        let mut label = self.join_arg_range_label(args)?;
        if let Some(state_label) = self.object_mutation_labels.get(&state) {
            label = label.join(state_label);
        }
        let (value, result_label) = self.invoke_inline_construct_with_labels(
            Some(module),
            target,
            arguments,
            Some(IsolatedCallLabels {
                receiver: Label::Public,
                arguments: IsolatedArgumentLabels::Uniform(label.clone()),
            }),
            new_target,
        )?;
        Ok((value, result_label.join(&label)))
    }

    /// `name` ("bound " + the target's name) and `length` (the target's
    /// length less the bound arguments, at least 0) of a bound function, as
    /// `Function.prototype.bind` read them from the target (ES2020 19.2.3.2
    /// steps 5-11).
    pub(super) fn bound_function_property(
        &self,
        builtin: &BuiltinFunction,
        key: &str,
    ) -> Result<Option<Value>, InterpreterError> {
        if !matches!(key, "name" | "length") {
            return Ok(None);
        }
        let state = builtin
            .bound_object
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "bound function state".to_string(),
                got: "bound function without state".to_string(),
            })?;
        Ok(self
            .heap
            .get(state as usize)
            .and_then(|object| object.properties.get(key).cloned()))
    }

    /// ES2020 9.4.1.1 [[Call]] of a bound function: call the target with the
    /// bound `this` and the bound arguments followed by the call's own.
    pub(super) fn invoke_bound_function(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (target, bound_this, bound_arguments, state) = self.bound_function_parts(builtin)?;
        let mut arguments =
            Vec::with_capacity(bound_arguments.len().saturating_add(args.count as usize));
        arguments.extend(bound_arguments);
        for index in 0..args.count {
            arguments.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
        }
        let mut label = self.join_arg_range_label(args)?;
        if let Some(state_label) = self.object_mutation_labels.get(&state) {
            label = label.join(state_label);
        }
        self.preflight_inline_method_call_with_argument_label(
            Some(module),
            &target,
            arguments.len(),
            Some(&label),
        )?;
        let (result, result_label) = self
            .invoke_inline_method_call_with_argument_label_preflighted(
                Some(module),
                target,
                bound_this,
                arguments,
                Some(label),
            )?;
        self.replace_pending_hostcall_result_label(Some(result_label))?;
        Ok(result)
    }

    /// ES2020 25.6.3.1 step 1: Promise's [[Call]] (NewTarget undefined)
    /// throws. The Call instruction refused it (bd-auy04), but
    /// `Promise.call(...)`, `Promise.apply(...)` and `Reflect.apply(Promise,
    /// ...)` reach the builtin dispatcher, which constructs (bd-9vouw.377).
    pub(super) fn reject_promise_constructor_call(
        function: &Value,
    ) -> Result<(), InterpreterError> {
        if matches!(function, Value::BuiltinFunction(builtin)
            if builtin.kind == BuiltinFunctionKind::PromiseConstructor)
        {
            return Err(InterpreterError::TypeError {
                expected: "new Promise(executor)".to_string(),
                got: "Promise constructor called without new".to_string(),
            });
        }
        Ok(())
    }

    pub(super) fn forward_function_invocation(
        &mut self,
        module: Option<&Ir3Module>,
        function: Value,
        function_register: Option<u32>,
        args: RegRange,
        apply: bool,
    ) -> Result<Value, InterpreterError> {
        if !function.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable Function.prototype receiver".to_string(),
                got: function.type_name().to_string(),
            });
        }
        let this_arg = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let mut context_label = function_register
            .map(|register| self.clone_register_label_with_temporary_budget(register))
            .transpose()?
            .unwrap_or(Label::Public);
        let first_argument = args.start.checked_add(u32::from(args.count > 0)).ok_or(
            InterpreterError::RegisterOutOfBounds {
                register: args.start,
                max: self.config.max_registers,
            },
        )?;
        let argument_range = RegRange {
            start: first_argument,
            count: if apply {
                0
            } else {
                args.count.saturating_sub(1)
            },
        };
        let mut labels = self.clone_isolated_call_labels_from_registers(
            (args.count > 0).then_some(args.start),
            argument_range,
        )?;
        let mut reserved = 0u64;
        let result = (|| {
            let values = if apply {
                let source = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let source_label = if args.count > 1 {
                    self.join_arg_range_with_object_mutation_label(RegRange {
                        start: first_argument,
                        count: 1,
                    })?
                } else {
                    Label::Public
                };
                let (values, value_labels, selection_label) = self.observable_apply_arguments(
                    module,
                    source,
                    source_label,
                    &mut reserved,
                    false,
                    MAX_CALL_ARGUMENTS,
                )?;
                context_label =
                    self.join_owned_label_with_temporary_budget(context_label, &selection_label)?;
                labels.arguments = IsolatedArgumentLabels::Exact(value_labels);
                values
            } else {
                self.preflight_inline_method_call_with_labels(
                    module,
                    &function,
                    argument_range.count as usize,
                    Some(&context_label),
                    Some(&labels),
                    u64::from(argument_range.count)
                        .saturating_mul(std::mem::size_of::<Value>() as u64),
                )?;
                let mut values = Vec::with_capacity(argument_range.count as usize);
                for offset in 0..argument_range.count {
                    values.push(self.read_reg(argument_range.start + offset)?);
                }
                values
            };
            // Call(F, thisArgument, argList) after the list is built.
            Self::reject_promise_constructor_call(&function)?;
            // bd-9vouw.50: a list that does not fit a register frame goes to
            // the builtin as a vector.
            let vector_tag = Self::vector_variadic_builtin_tag(&function)
                .filter(|_| values.len() > self.config.max_registers.saturating_sub(2) as usize);
            let (value, label) = if let Some(vector_tag) = vector_tag {
                self.apply_vector_variadic_builtin(
                    module,
                    vector_tag,
                    values,
                    &labels.arguments,
                    context_label,
                )?
            } else {
                // bd-9vouw.77: this frame holds nothing the call does not pin
                // (callee, receiver, arguments), so the callee may collect.
                self.with_gc_nested_request(Vec::new(), |core| {
                    core.invoke_inline_method_call_with_labels(
                        module,
                        function,
                        this_arg,
                        values,
                        Some(context_label),
                        labels,
                    )
                })?
            };
            self.replace_pending_hostcall_result_label(Some(label))?;
            Ok(value)
        })();
        self.simple_callback_temporary_bytes = self
            .simple_callback_temporary_bytes
            .saturating_sub(reserved);
        result
    }

    /// bd-9vouw.501: the argument list of `f.apply(t, list)`,
    /// `Reflect.apply(f, t, list)` or a spread call `f(...list)` (the
    /// Reflect.apply hostcall over a fresh array) when `f` can run as an
    /// ordinary frame of this run loop, with the list as its arguments,
    /// exactly as the isolated activation of `forward_function_invocation`
    /// would run it: `f` (in `function_register`) is a same-module closure
    /// or function; no embedder hook and no execution context label is
    /// active; `labelled_registers` (the call's own operands) and the
    /// function, receiver and list registers are Public, as are the list's
    /// mutation label and property labels, so the isolated call's context
    /// label would be Public; and the list is an ordinary Array whose
    /// `length` is an Int within MAX_CALL_ARGUMENTS and whose elements
    /// 0..length are own data properties, so CreateListFromArrayLike's
    /// [[Get]]s run no getter. Charges the instruction budget as
    /// `observable_apply_arguments` does: one unit, then one per element.
    pub(super) fn unobservable_apply_arguments(
        &mut self,
        module: &Ir3Module,
        labelled_registers: &[u32],
        function_register: u32,
        receiver_register: u32,
        list_register: u32,
    ) -> Result<Option<Vec<Value>>, InterpreterError> {
        if self.hook.is_some()
            || self
                .active_execution_context_label()
                .is_some_and(|label| *label != Label::Public)
        {
            return Ok(None);
        }
        let operands = [function_register, receiver_register, list_register];
        for &register in labelled_registers.iter().chain(&operands) {
            if *self.get_register_label(register)? != Label::Public {
                return Ok(None);
            }
        }
        let function = self.read_reg(function_register)?;
        if !matches!(function, Value::Closure(_) | Value::Function(_))
            || self.foreign_closure_module(&function, module)?.is_some()
        {
            return Ok(None);
        }
        let Value::Object(list) = self.read_reg(list_register)? else {
            return Ok(None);
        };
        if self
            .object_mutation_labels
            .get(&list)
            .is_some_and(|label| *label != Label::Public)
            || self.active_proxy_record(list)?.is_some()
        {
            return Ok(None);
        }
        let Some(object) = self.heap.get(list.0 as usize) else {
            return Ok(None);
        };
        if !object.is_array || object.typed_array.is_some() || !object.property_labels.is_empty() {
            return Ok(None);
        }
        let length = match object.properties.get("length") {
            Some(Value::Int(length)) if (0..=i64::from(MAX_CALL_ARGUMENTS)).contains(length) => {
                *length as u32
            }
            _ => return Ok(None),
        };
        let mut values = Vec::with_capacity(length as usize);
        for index in 0..length {
            match object.properties.get_index(index) {
                None | Some(Value::Accessor { .. }) => return Ok(None),
                Some(value) => values.push(value.clone()),
            }
        }
        for _ in 0..=length {
            self.json_charge_work()?;
        }
        Ok(Some(values))
    }

    /// The CallMethod a spread call's Reflect.apply hostcall runs as, with
    /// its argument list, when `unobservable_apply_arguments` allows it
    /// (bd-9vouw.501); `None` for any other instruction, and while the
    /// profiler observes instructions.
    pub(super) fn spread_call_as_method_call(
        &mut self,
        module: &Ir3Module,
        instruction: &Ir3Instruction,
    ) -> Result<Option<(Ir3Instruction, Vec<Value>)>, InterpreterError> {
        let Ir3Instruction::HostCall {
            capability,
            args,
            dst,
        } = instruction
        else {
            return Ok(None);
        };
        if self.profiling_data.is_some()
            || args.count != 3
            || capability.0 != "builtin:ReflectApply"
        {
            return Ok(None);
        }
        let Some(values) = self.unobservable_apply_arguments(
            module,
            &[],
            args.start,
            args.start + 1,
            args.start + 2,
        )?
        else {
            return Ok(None);
        };
        let call = Ir3Instruction::CallMethod {
            receiver: args.start + 1,
            callee: args.start,
            args: RegRange {
                start: self.config.max_registers,
                count: values.len() as u32,
            },
            dst: *dst,
        };
        Ok(Some((call, values)))
    }

    /// Make `values` (Public) registers `max_registers..` of the active frame
    /// for the call that binds them, as `stage_argument_overflow` does for a
    /// synthetic call site (bd-9vouw.501).
    pub(super) fn install_apply_argument_overflow(
        &mut self,
        values: Vec<Value>,
    ) -> Result<usize, InterpreterError> {
        let labels = vec![Label::Public; values.len()];
        let bytes = Self::estimate_value_vec_bytes(&values).saturating_add(
            u64::try_from(labels.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(std::mem::size_of::<Label>() as u64),
        );
        self.check_temporary_memory_budget(bytes)?;
        Ok(self.install_argument_overflow(values, labels, bytes))
    }

    /// CreateListFromArrayLike for apply, not iterable spread. Read length
    /// once, then use observable Get (including inherited values) in order.
    pub(super) fn observable_apply_arguments(
        &mut self,
        module: Option<&Ir3Module>,
        source: Value,
        mut source_label: Label,
        reserved: &mut u64,
        property_keys_only: bool,
        max_length: u32,
    ) -> Result<(Vec<Value>, Vec<Label>, Label), InterpreterError> {
        self.json_charge_work()?;
        if matches!(source, Value::Null | Value::Undefined) {
            return Ok((Vec::new(), Vec::new(), source_label));
        }
        let backing = self.iterator_carrier_backing_id(&source, "array-like object")?;
        let raw_length = if let Some(object_id) = backing {
            let key = RuntimePropertyKey::String("length".into());
            if let Some(module) = module {
                self.run_pre_runtime_property_access_hook(module, object_id, &key)?;
            }
            source_label = self.join_owned_label_with_temporary_budget(
                source_label,
                &self.runtime_property_label(object_id, &key),
            )?;
            self.proxy_aware_get_runtime_property(module, object_id, &key, source.clone(), 0)?
        } else {
            Value::Undefined
        };
        let primitive = self.coerce_runtime_primitive(module, raw_length, false)?;
        if let Some(label) = self.take_pending_hostcall_result_label() {
            source_label = self.join_owned_label_with_temporary_budget(source_label, &label)?;
        }
        let numeric = match &primitive {
            Value::BigInt(_) | Value::Symbol(_) => {
                return Err(InterpreterError::TypeError {
                    expected: "Number-convertible array-like length".to_string(),
                    got: primitive.type_name().to_string(),
                });
            }
            Value::Str(text) => {
                self.check_string_limit(text.len())?;
                for _ in 0..text.len().div_ceil(64) {
                    self.json_charge_work()?;
                }
                Self::array_like_length_string_number(text)
            }
            _ => Self::coerce_to_float(&primitive).unwrap_or(f64::NAN),
        };
        let length = if numeric.is_nan() || numeric <= 0.0 {
            0.0
        } else {
            numeric.floor().min(9_007_199_254_740_991.0)
        };
        // Refuse before indexed getters or allocation. Untrusted length is
        // not permitted to reserve an unbounded Rust Vec or evade VM limits.
        if length > f64::from(max_length) {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: u32::MAX,
                max: self.config.max_registers,
            });
        }
        let length = length as usize;
        let bytes = (length as u64)
            .saturating_mul((std::mem::size_of::<Value>() + std::mem::size_of::<Label>()) as u64);
        self.check_temporary_memory_budget(bytes)?;
        *reserved = reserved.saturating_add(bytes);
        // Keep the carrier in the existing scratch-memory component so a
        // getter's heap mutation/recompute cannot erase this reservation.
        self.simple_callback_temporary_bytes =
            self.simple_callback_temporary_bytes.saturating_add(bytes);
        let mut values = Vec::new();
        let mut labels = Vec::new();
        values
            .try_reserve_exact(length)
            .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        labels
            .try_reserve_exact(length)
            .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
        for index in 0..length {
            self.json_charge_work()?;
            let key = RuntimePropertyKey::String(index.to_string().into());
            let mut label = source_label.clone();
            let value = if let Some(object_id) = backing {
                if let Some(module) = module {
                    self.run_pre_runtime_property_access_hook(module, object_id, &key)?;
                }
                label = self.join_owned_label_with_temporary_budget(
                    label,
                    &self.runtime_property_label(object_id, &key),
                )?;
                self.proxy_aware_get_runtime_property(module, object_id, &key, source.clone(), 0)?
            } else {
                Value::Undefined
            };
            if let Some(callback_label) = self.take_pending_hostcall_result_label() {
                label = self.join_owned_label_with_temporary_budget(label, &callback_label)?;
            }
            // CreateListFromArrayLike's elementTypes check precedes Get of
            // the next index. Proxy ownKeys may not read past an invalid key.
            if property_keys_only && !matches!(value, Value::Str(_) | Value::Symbol(_)) {
                return Err(InterpreterError::TypeError {
                    expected: "string or Symbol Proxy.ownKeys result key".into(),
                    got: value.type_name().into(),
                });
            }
            let bytes = Self::estimate_value_bytes(&value)
                .saturating_add(Self::estimate_label_bytes(&label));
            self.check_temporary_memory_budget(bytes)?;
            *reserved = reserved.saturating_add(bytes);
            self.simple_callback_temporary_bytes =
                self.simple_callback_temporary_bytes.saturating_add(bytes);
            values.push(value);
            labels.push(label);
        }
        Ok((values, labels, source_label))
    }

    pub(super) fn array_like_length_string_number(text: &JsString) -> f64 {
        primitive_conversion::string_number(text)
    }

    /// Clone an `ApplyHostCall` arguments list only after reserving the full
    /// physical value+label carrier. Each scratch label preserves that exact
    /// element's property, backing-store, and reachable-value provenance. The
    /// separate active callback context carries whole-invocation control
    /// dependence for deferred work without smearing one element's label onto
    /// every other scratch register.
    #[cfg(test)]
    pub(super) fn prepare_delegated_hostcall_arguments(
        &mut self,
        value: Value,
    ) -> Result<DelegatedHostcallArguments, InterpreterError> {
        let max_count = self.config.max_registers;
        self.prepare_delegated_hostcall_arguments_up_to(value, max_count)
    }

    /// As [`Self::prepare_delegated_hostcall_arguments`], refusing lists
    /// longer than `max_count` before any indexed read or allocation.
    pub(super) fn prepare_delegated_hostcall_arguments_up_to(
        &mut self,
        value: Value,
        max_count: u32,
    ) -> Result<DelegatedHostcallArguments, InterpreterError> {
        let (length, dynamic_value_bytes, dynamic_label_bytes) = match &value {
            Value::Undefined | Value::Null => (0usize, 0u64, 0u64),
            Value::Object(object_id) => {
                let length = self.array_like_length(*object_id)?;
                let count =
                    u32::try_from(length).map_err(|_| InterpreterError::RegisterOutOfBounds {
                        register: u32::MAX,
                        max: self.config.max_registers,
                    })?;
                if count > max_count {
                    return Err(InterpreterError::RegisterOutOfBounds {
                        register: count,
                        max: self.config.max_registers,
                    });
                }
                let object = self
                    .heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                let typed_array = object.typed_array.is_some();
                let dynamic_value_bytes = if typed_array {
                    // Every currently supported typed-array element materializes
                    // as an allocation-free Int/Undefined value.
                    0
                } else {
                    Self::saturating_sum((0..length).map(|index| {
                        object
                            .properties
                            .get(&index.to_string())
                            .map(Self::estimate_value_bytes)
                            .unwrap_or(0)
                    }))
                };
                let dynamic_label_bytes = Self::saturating_sum((0..length).map(|index| {
                    let value = if typed_array {
                        None
                    } else {
                        object.properties.get(&index.to_string())
                    };
                    self.delegated_argument_label_ref(*object_id, index, value)
                        .map(Self::estimate_label_bytes)
                        .unwrap_or(0)
                }));
                (length, dynamic_value_bytes, dynamic_label_bytes)
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "array-like object or null/undefined".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };

        let carrier_bytes = u64::try_from(length)
            .unwrap_or(u64::MAX)
            .saturating_mul((std::mem::size_of::<Value>() + std::mem::size_of::<Label>()) as u64)
            .saturating_add(dynamic_value_bytes)
            .saturating_add(dynamic_label_bytes);
        self.apply_memory_component_delta(0, carrier_bytes)?;

        let extracted = (|| {
            let mut values = Vec::with_capacity(length);
            let mut labels = Vec::with_capacity(length);
            match value {
                Value::Undefined | Value::Null => {}
                Value::Object(object_id) => {
                    for element_index in 0..length {
                        let value = self
                            .array_index_value(object_id, element_index)?
                            .unwrap_or(Value::Undefined);
                        labels.push(
                            self.delegated_argument_label_ref(
                                object_id,
                                element_index,
                                Some(&value),
                            )
                            .cloned()
                            .unwrap_or(Label::Public),
                        );
                        values.push(value);
                    }
                }
                other => {
                    return Err(InterpreterError::InternalError {
                        details: format!(
                            "delegated argument-list shape changed after validation: {}",
                            other.type_name()
                        ),
                    });
                }
            }
            Ok::<_, InterpreterError>((values, labels))
        })();

        match extracted {
            Ok((values, labels)) => {
                let actual_carrier_bytes = Self::estimate_value_vec_bytes(&values)
                    .saturating_add(Self::estimate_label_vec_bytes(&labels));
                if actual_carrier_bytes != carrier_bytes {
                    drop(values);
                    drop(labels);
                    self.estimated_memory_bytes =
                        self.estimated_memory_bytes.saturating_sub(carrier_bytes);
                    return Err(InterpreterError::InternalError {
                        details: format!(
                            "delegated argument carrier estimate drifted: reserved {carrier_bytes}, actual {actual_carrier_bytes}"
                        ),
                    });
                }
                Ok(DelegatedHostcallArguments {
                    values,
                    labels,
                    carrier_bytes,
                })
            }
            Err(error) => {
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(carrier_bytes);
                Err(error)
            }
        }
    }

    pub(super) fn delegated_argument_label_ref<'a>(
        &'a self,
        arguments_list: ObjectId,
        element_index: usize,
        value: Option<&Value>,
    ) -> Option<&'a Label> {
        let property_key = JsString::from(element_index.to_string());
        let mut winner = self
            .heap
            .get(arguments_list.0 as usize)
            .and_then(|object| object.property_labels.get_exact(&property_key));
        if let Some(candidate) = self.binary_storage_label_ref(arguments_list)
            && winner.is_none_or(|current| candidate > current)
        {
            winner = Some(candidate);
        }
        if let Some(candidate) = value
            .and_then(|value| self.process_dynamic_value_label_ref(value, &mut BTreeSet::new()))
            && winner.is_none_or(|current| candidate > current)
        {
            winner = Some(candidate);
        }
        winner
    }

    /// Borrow the dominant label reachable through a value without allocating
    /// a temporary `Custom` label. Delegation preflight uses this to reserve
    /// the exact carrier before the one clone retained in the scratch frame.
    pub(super) fn process_dynamic_value_label_ref<'a>(
        &'a self,
        value: &Value,
        visited: &mut BTreeSet<ObjectId>,
    ) -> Option<&'a Label> {
        let Value::Object(object_id) = value else {
            return None;
        };
        if !visited.insert(*object_id) {
            return None;
        }
        let mut winner = self.object_mutation_labels.get(object_id);
        if let Some(candidate) = self.binary_storage_label_ref(*object_id)
            && winner.is_none_or(|current| candidate > current)
        {
            winner = Some(candidate);
        }
        if let Some(object) = self.heap.get(object_id.0 as usize) {
            // The largest label wins whatever the order (bd-9vouw.333).
            for property in object.properties.values_unordered() {
                if let Some(candidate) = self.process_dynamic_value_label_ref(property, visited)
                    && winner.is_none_or(|current| candidate > current)
                {
                    winner = Some(candidate);
                }
            }
        }
        winner
    }

    pub(super) fn release_delegated_hostcall_arguments(
        &mut self,
        arguments: DelegatedHostcallArguments,
    ) {
        let carrier_bytes = arguments.carrier_bytes;
        drop(arguments);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(carrier_bytes);
    }

    /// Collect an IR rest/slice suffix without first materializing the whole
    /// source. Every indexed Get observes accessors/prototypes, and every
    /// append goes through the same bounded allocation path as spread.
    pub(super) fn slice_array_suffix(
        &mut self,
        module: Option<&Ir3Module>,
        array: Value,
        start: Value,
    ) -> Result<Value, InterpreterError> {
        let Value::Object(array_id) = array else {
            return Err(InterpreterError::TypeError {
                expected: "array object".to_string(),
                got: array.type_name().to_string(),
            });
        };
        let length = self.array_like_length(array_id)?;
        let start = match start {
            Value::Undefined | Value::Null | Value::Bool(false) => 0,
            Value::Bool(true) => 1usize.min(length),
            Value::Int(index) if index < 0 => {
                usize::try_from((length as i64).saturating_add(index).max(0)).unwrap_or(0)
            }
            Value::Int(index) => usize::try_from(index).unwrap_or(usize::MAX).min(length),
            Value::Float(value) => {
                let index = value.inner().trunc();
                if index.is_nan() {
                    0
                } else if index < 0.0 {
                    ((length as f64) + index).max(0.0) as usize
                } else {
                    (index as usize).min(length)
                }
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "integer-compatible array slice start".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let result = self.alloc_array_from_values(&[])?;
        let mut next_index = 0;
        for index in start..length {
            let value = self.proxy_aware_get_property(
                module,
                array_id,
                &index.to_string(),
                Value::Object(array_id),
                0,
            )?;
            self.append_spread_array_element(result, &mut next_index, value)?;
        }
        self.set_object_property(
            result,
            "length".to_string(),
            Value::Int(i64::from(next_index)),
        )?;
        Ok(Value::Object(result))
    }

    pub(super) fn array_prototype_iterator(
        &mut self,
        args: RegRange,
        kind: &'static str,
    ) -> Result<Value, InterpreterError> {
        let receiver = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };
        self.array_prototype_iterator_for_receiver(receiver, kind)
    }

    /// The IFC label that calling the intrinsic `Array.prototype[Symbol.iterator]`
    /// (`ArrayValues`) on `object_id` through
    /// `invoke_inline_method_call_with_argument_label` returns (bd-9vouw.70).
    ///
    /// That isolated call runs under one context label: the inherited callback
    /// context where it dominates `argument_label`, else `argument_label`.
    /// Register writes take the context where it dominates, and
    /// `finish_builtin_dispatch` labels the result with the receiver register's
    /// label joined with the receiver's state labels and the builtin's own
    /// result label, which `array_prototype_iterator_for_receiver` never sets.
    /// Labels are totally ordered and join is their maximum, so the isolated
    /// call's label is the join of those.
    pub(super) fn intrinsic_array_values_label(
        &mut self,
        object_id: ObjectId,
        argument_label: Option<Label>,
    ) -> Label {
        let context = match (
            self.active_inline_callback_context_label.as_ref(),
            argument_label,
        ) {
            (Some(inherited), Some(argument)) if *inherited < argument => argument,
            (Some(inherited), _) => inherited.clone(),
            (None, argument) => argument.unwrap_or(Label::Public),
        };
        self.mark_inline_callback_started();
        context
            .join(&self.binary_storage_label(object_id))
            .join(&self.stream_state_label(object_id))
            .join(&self.url_state_label(object_id))
            .join(&self.cluster_state_label(object_id))
    }

    pub(super) fn array_prototype_iterator_for_receiver(
        &mut self,
        receiver: Value,
        kind: &'static str,
    ) -> Result<Value, InterpreterError> {
        // ToObject(this value) (ES2020 22.1.3.4, 22.1.3.14, 22.1.3.30 step
        // 1): an undefined or null receiver is a TypeError, not an empty
        // iterator.
        if matches!(receiver, Value::Undefined | Value::Null) {
            return Err(self.throw_js_error(
                "TypeError",
                format!("Array.prototype.{kind} called on null or undefined"),
            ));
        }
        let array_id = match receiver {
            Value::Object(object_id) => Some(object_id),
            _ => None,
        };
        let projection = match kind {
            "entries" => RuntimeTypedArrayIteratorKind::Entries,
            "keys" => RuntimeTypedArrayIteratorKind::Keys,
            "values" => RuntimeTypedArrayIteratorKind::Values,
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "array iterator kind".to_string(),
                    got: kind.to_string(),
                });
            }
        };

        let trace_index = self.start_iteration_trace(IterationKind::ForOf, || {
            format!(
                "array_iterator:{kind}|{}",
                array_id
                    .map(|id| id.0.to_string())
                    .unwrap_or_else(|| "non_object".to_string())
            )
        });
        if self.iteration_traced(trace_index) {
            let iterable_ref = array_id
                .map(|object_id| self.iteration_ref_for_object(object_id))
                .unwrap_or_else(|| {
                    self.derive_iteration_engine_id(
                        "array_iterator_receiver",
                        "non_object".to_string(),
                    )
                });
            self.record_iteration_event(trace_index, |record_id, step_index| {
                make_get_iterator_event(
                    record_id,
                    step_index,
                    IteratorSymbolKind::Iterator,
                    iterable_ref,
                )
            });
        }
        let handle = self.alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
            values: Vec::new(),
            next_index: 0,
            array: array_id.map(|object_id| RuntimeArrayIterator {
                object_id,
                kind: projection,
            }),
            typed_array: None,
            collection: None,
            iterator_receiver: None,
            next_method: None,
            timers_interval: None,
            done: false,
            closed: false,
            return_called: false,
            trace_index,
        }))?;
        Ok(Value::Iterator(handle))
    }

    pub(super) fn canonical_array_index_key(key: &str) -> Option<u32> {
        canonical_array_index(key)
    }

    pub(super) fn canonical_array_index_property(key: &str, length: usize) -> Option<usize> {
        let index = Self::canonical_array_index_key(key)?;
        let index = usize::try_from(index).ok()?;
        (index < length).then_some(index)
    }

    pub(super) fn normalize_array_length_assignment(
        value: &Value,
    ) -> Result<i64, InterpreterError> {
        let number = match value {
            Value::Int(n) => Some(*n as f64),
            Value::Float(f) => Some(f.inner()),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Null => Some(0.0),
            // StringToNumber: "0x0B" is 11, "1e1" 10, "" 0 (bd-9vouw.279).
            Value::Str(s) => Some(primitive_conversion::string_number(s)),
            _ => None,
        };

        let Some(number) = number else {
            return Err(InterpreterError::RangeError {
                message: format!("invalid array length {}", value.type_name()),
            });
        };
        if !number.is_finite() || number < 0.0 || number > u32::MAX as f64 || number.fract() != 0.0
        {
            return Err(InterpreterError::RangeError {
                message: format!("invalid array length {value}"),
            });
        }

        Ok(number as u32 as i64)
    }

    /// Return the indexed own-property keys that an Array `length` write must
    /// delete. A valid write that strictly grows a *trusted dense* length cannot
    /// truncate an index, so avoid enumerating the entire property carrier on
    /// that common path. The dense-length cache is invalidated by public sparse
    /// or named writes; requiring it to agree with the visible length keeps a
    /// low-level caller from using the shortcut after constructing an index
    /// above that length. Equality remains conservative because the low-level
    /// public setter may place an index exactly at the recorded length without
    /// growing it. If either value is missing, malformed, sparse, disagrees
    /// with the runtime-maintained cache, or is unchanged, keep the scan used
    /// before this fast path. This trust rule covers states reachable through
    /// the runtime mutation protocol; it is not a validator for an arbitrarily
    /// assembled `HeapObject`.
    pub(super) fn array_length_truncation_keys(
        object: &HeapObject,
        new_length: i64,
    ) -> Option<Vec<String>> {
        if let Some(Value::Int(current_length)) = object.properties.get("length")
            && *current_length >= 0
            && new_length > *current_length
            && u32::try_from(*current_length)
                .is_ok_and(|length| object.cached_dense_length == Some(length))
        {
            return None;
        }

        let new_length = new_length as u64;
        Some(
            object
                .properties
                .keys()
                .filter(|candidate| {
                    Self::canonical_array_index_key(candidate)
                        .is_some_and(|index| u64::from(index) >= new_length)
                })
                .cloned()
                .collect(),
        )
    }

    /// A class private name reaches a function only through its captured
    /// `#x` binding, which the callback mini-interpreters never load, so a
    /// private member access there is an engine fault, not guest behavior.
    pub(super) fn reject_private_name_in_simple_callback(
        &self,
        key: &Value,
    ) -> Result<(), InterpreterError> {
        match self.class_private_name_key(key) {
            Some(_) => Err(InterpreterError::InternalError {
                details: "private member access in a callback mini-interpreter".to_string(),
            }),
            None => Ok(()),
        }
    }

    /// A property read in the reducer mini-interpreter, keeping dynamic
    /// string identity exact and honoring the legacy-hook boundary.
    ///
    /// An object is read with the GetProperty instruction's [[Get]]
    /// (bd-9vouw.175): an inherited member, a getter (called with the object
    /// as its receiver) and a Proxy trap, not only an own data property, which
    /// used to give `undefined` or the accessor itself. The stored property
    /// label joins the enclosing HostCall's result label.
    pub(super) fn simple_callback_get_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_value: Value,
        key_value: &Value,
    ) -> Result<Value, InterpreterError> {
        self.reject_private_name_in_simple_callback(key_value)?;
        let key = self.executable_property_key_from_value(key_value);
        self.preflight_legacy_property_key_for_hook(&key)?;
        match object_value {
            Value::Object(object_id) => {
                if key.as_str() == Some("__proto__") && self.proto_key_reaches_accessor(object_id) {
                    let link = self.ordinary_get_prototype_of(object_id)?;
                    return Ok(self.prototype_value_for_link(module, link));
                }
                self.iterator_protocol_property(module, object_id, &key, Value::Object(object_id))
            }
            Value::Iterator(iterator_handle) => Ok(key.as_str().map_or(Value::Undefined, |key| {
                self.iterator_property_value(iterator_handle, key)
            })),
            Value::Str(text) => Ok(key.as_str().map_or(Value::Undefined, |key| {
                Self::string_property_value(&text, key)
            })),
            Value::Int(_) | Value::Float(_) => Ok(key
                .as_str()
                .map_or(Value::Undefined, Self::number_property_value)),
            Value::BigInt(_) => Ok(key
                .as_str()
                .map_or(Value::Undefined, Self::bigint_property_value)),
            Value::Bool(_) => Ok(key
                .as_str()
                .and_then(Self::boolean_prototype_method)
                .unwrap_or(Value::Undefined)),
            Value::BuiltinFunction(builtin) => {
                let Some(property_object) = Self::builtin_function_property_object(&builtin) else {
                    return Ok(Value::Undefined);
                };
                self.iterator_protocol_property(
                    module,
                    property_object,
                    &key,
                    Value::BuiltinFunction(builtin),
                )
            }
            other => Err(InterpreterError::TypeError {
                expected: "object".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn invoke_simple_reduce_callback(
        &mut self,
        module: Option<&Ir3Module>,
        callback: &Value,
        accumulator: Value,
        current_value: Value,
        element_index: usize,
        array_id: ObjectId,
    ) -> Result<Value, InterpreterError> {
        let previous_callback_temporary_bytes = self.simple_callback_temporary_bytes;
        let result = self.invoke_simple_reduce_callback_inner(
            module,
            callback,
            accumulator,
            current_value,
            element_index,
            array_id,
        );
        self.simple_callback_temporary_bytes = previous_callback_temporary_bytes;
        result
    }

    /// Whether every instruction reachable from `entry` (following jumps to a
    /// return, throw or halt) is one the reducer mini-lane below executes.
    pub(super) fn simple_reduce_lane_supports(module: &Ir3Module, entry: usize) -> bool {
        const MAX_SCANNED_INSTRUCTIONS: usize = 4096;
        let mut pending = vec![entry];
        let mut visited = BTreeSet::new();
        while let Some(ip) = pending.pop() {
            if !visited.insert(ip) {
                continue;
            }
            if visited.len() > MAX_SCANNED_INSTRUCTIONS {
                return false;
            }
            let Some(instruction) = module.instructions.get(ip) else {
                return false;
            };
            // The fourth reducer argument is always an object. Its reads
            // require canonical coercion and identity/label transport even
            // when the accumulator and current element are primitives.
            // Reject reads conservatively, including after an overwrite;
            // checking before execution avoids replaying callback work.
            let reads_array_argument = match instruction {
                Ir3Instruction::Move { src, .. }
                | Ir3Instruction::Inc { src, .. }
                | Ir3Instruction::Dec { src, .. } => *src == 3,
                Ir3Instruction::Add { lhs, rhs, .. }
                | Ir3Instruction::Sub { lhs, rhs, .. }
                | Ir3Instruction::Mul { lhs, rhs, .. }
                | Ir3Instruction::Div { lhs, rhs, .. } => *lhs == 3 || *rhs == 3,
                Ir3Instruction::JumpIf { cond, .. } => *cond == 3,
                Ir3Instruction::Return { value } | Ir3Instruction::Throw { value } => *value == 3,
                _ => false,
            };
            if reads_array_argument {
                return false;
            }
            match instruction {
                Ir3Instruction::Return { .. }
                | Ir3Instruction::Halt
                | Ir3Instruction::Throw { .. } => {}
                Ir3Instruction::Jump { target } => pending.push(*target as usize),
                Ir3Instruction::JumpIf { target, .. } => {
                    pending.push(*target as usize);
                    pending.push(ip + 1);
                }
                Ir3Instruction::LoadInt { .. }
                | Ir3Instruction::LoadFloat { .. }
                | Ir3Instruction::LoadStr { .. }
                | Ir3Instruction::LoadBool { .. }
                | Ir3Instruction::LoadNull { .. }
                | Ir3Instruction::LoadUndefined { .. }
                | Ir3Instruction::LoadBigInt { .. }
                | Ir3Instruction::LoadNewTarget { .. }
                | Ir3Instruction::Move { .. }
                | Ir3Instruction::Add { .. }
                | Ir3Instruction::Sub { .. }
                | Ir3Instruction::Inc { .. }
                | Ir3Instruction::Dec { .. }
                | Ir3Instruction::Mul { .. }
                | Ir3Instruction::Div { .. } => pending.push(ip + 1),
                // Heap/name access needs canonical live property, cell,
                // callback and abrupt-label transport.
                // A property write takes the ordinary path (bd-9vouw.175):
                // [[Set]] calls setters and Proxy traps, refuses read-only and
                // non-extensible targets per the write's strictness, and joins
                // the object's mutation label. The mini-lane wrote raw data.
                _ => return false,
            }
        }
        true
    }

    pub(super) fn invoke_simple_reduce_callback_inner(
        &mut self,
        module: Option<&Ir3Module>,
        callback: &Value,
        accumulator: Value,
        current_value: Value,
        element_index: usize,
        array_id: ObjectId,
    ) -> Result<Value, InterpreterError> {
        let module = module.ok_or_else(|| InterpreterError::TypeError {
            expected: "module-backed reducer callback".to_string(),
            got: "Array.prototype.reduce called without module context".to_string(),
        })?;
        let element_index =
            i64::try_from(element_index).map_err(|_| InterpreterError::TypeError {
                expected: "array reducer callback index within i64".to_string(),
                got: element_index.to_string(),
            })?;
        let function_index = match callback {
            Value::Function(index) => *index,
            Value::Closure(_)
            | Value::GeneratorFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::BuiltinFunction(_) => {
                // A closure's function index belongs to its defining module,
                // and its captures/realm may differ from the reducer caller.
                // The canonical boundary restores that execution provenance
                // and the activation semantics of generators/async functions.
                return self.invoke_labeled_reduce_callback(
                    Some(module),
                    callback.clone(),
                    Value::Undefined,
                    vec![
                        accumulator,
                        current_value,
                        Value::Int(element_index),
                        Value::Object(array_id),
                    ],
                );
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "function".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let function = module.function_table.get(function_index as usize).ok_or(
            InterpreterError::FunctionNotFound {
                index: function_index,
                table_size: module.function_table.len() as u32,
            },
        )?;
        if function.is_generator
            || function.rest_param_index.is_some()
            || accumulator.is_object_like()
            || current_value.is_object_like()
            || !Self::simple_reduce_lane_supports(module, function.entry as usize)
        {
            // Select the canonical callback before execution, so heap/name
            // access, coercion and user effects are never replayed.
            return self.invoke_labeled_reduce_callback(
                Some(module),
                callback.clone(),
                Value::Undefined,
                vec![
                    accumulator,
                    current_value,
                    Value::Int(element_index),
                    Value::Object(array_id),
                ],
            );
        }
        let previous_callback_temporary_bytes = self.simple_callback_temporary_bytes;
        let register_count = self.config.max_registers as usize;
        let register_carrier_bytes = u64::try_from(register_count)
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(std::mem::size_of::<Value>()).unwrap_or(u64::MAX));
        self.check_temporary_memory_budget(register_carrier_bytes)?;
        self.simple_callback_temporary_bytes = self
            .simple_callback_temporary_bytes
            .saturating_add(register_carrier_bytes);
        let mut local_registers = self.take_simple_callback_registers(register_count);
        let outcome = (|| -> Result<Value, InterpreterError> {
            Self::write_local_register(&mut local_registers, 0, accumulator)?;
            Self::write_local_register(&mut local_registers, 1, current_value)?;
            Self::write_local_register(&mut local_registers, 2, Value::Int(element_index))?;
            Self::write_local_register(&mut local_registers, 3, Value::Object(array_id))?;

            let mut instruction_pointer = function.entry as usize;
            for _step in 0..self.config.instruction_budget {
                // Share the run's remaining budget and cancellation boundary;
                // a reducer must not receive a fresh allowance per element.
                self.json_charge_work()?;
                self.simple_callback_temporary_bytes = previous_callback_temporary_bytes
                    .saturating_add(Self::simple_callback_register_bytes(&local_registers));
                let instruction_ref = module.instructions.get(instruction_pointer).ok_or(
                    InterpreterError::InstructionOutOfBounds {
                        ip: instruction_pointer,
                        count: module.instructions.len(),
                    },
                )?;
                if let Ir3Instruction::LoadBigInt { value, .. } = instruction_ref {
                    self.check_temporary_memory_budget(
                        Self::bigint_literal_construction_peak_bytes(value),
                    )?;
                }
                let instruction = instruction_ref.clone();
                match instruction {
                    Ir3Instruction::LoadInt { dst, value } => {
                        Self::write_local_register(&mut local_registers, dst, Value::Int(value))?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::LoadBigInt { dst, value } => {
                        Self::write_local_register(
                            &mut local_registers,
                            dst,
                            Value::BigInt(Arc::from(value)),
                        )?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::LoadFloat { dst, bits } => {
                        Self::write_local_register(
                            &mut local_registers,
                            dst,
                            Value::Float(Float64::new(f64::from_bits(bits))),
                        )?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::LoadStr { dst, pool_index } => {
                        let value = module
                            .constant_pool
                            .get(pool_index as usize)
                            .cloned()
                            .ok_or(InterpreterError::StringPoolOutOfBounds {
                                index: pool_index,
                                pool_size: module.constant_pool.len() as u32,
                            })?;
                        Self::write_local_register(&mut local_registers, dst, Value::str(value))?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::LoadBool { dst, value } => {
                        Self::write_local_register(&mut local_registers, dst, Value::Bool(value))?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::LoadNull { dst } => {
                        Self::write_local_register(&mut local_registers, dst, Value::Null)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::LoadUndefined { dst } => {
                        Self::write_local_register(&mut local_registers, dst, Value::Undefined)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::LoadName {
                        dst,
                        name_pool_index,
                        allow_missing,
                    } => {
                        let name = Self::scoped_constant_name(module, name_pool_index);
                        let value = match self.load_runtime_name(name.as_ref(), false) {
                            // This lane runs no guest code: a data property of the
                            // global object only, as its GetProperty reads.
                            Err(InterpreterError::UndefinedBinding { .. }) => {
                                match self.global_object_data_property(name.as_ref()) {
                                    Some(value) => value,
                                    None if allow_missing => Value::Undefined,
                                    None => {
                                        return Err(InterpreterError::UndefinedBinding {
                                            name: name.into_owned(),
                                        });
                                    }
                                }
                            }
                            loaded => loaded?,
                        };
                        Self::write_local_register(&mut local_registers, dst, value)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::ResolveNameStatus {
                        dst,
                        name_pool_index,
                    } => {
                        let name = Self::scoped_constant_name(module, name_pool_index);
                        let reference_token = self.capture_runtime_name_reference(name.as_ref())?;
                        Self::write_local_register(
                            &mut local_registers,
                            dst,
                            Value::Int(i64::from(reference_token)),
                        )?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::PutName {
                        src,
                        name_pool_index,
                        strict,
                    } => {
                        let name = Self::scoped_constant_name(module, name_pool_index);
                        let value = Self::read_local_register(&local_registers, src)?;
                        self.put_runtime_name(name.as_ref(), value, strict)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::PutNameWithStatus {
                        src,
                        status,
                        name_pool_index,
                        strict,
                    } => {
                        let name = Self::scoped_constant_name(module, name_pool_index);
                        let value = Self::read_local_register(&local_registers, src)?;
                        let reference_token = Self::runtime_name_reference_token(
                            Self::read_local_register(&local_registers, status)?,
                        )?;
                        self.put_runtime_name_with_status(
                            name.as_ref(),
                            value,
                            strict,
                            reference_token,
                        )?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::LoadNewTarget { dst } => {
                        Self::write_local_register(&mut local_registers, dst, Value::Undefined)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::Move { dst, src } => {
                        let value = Self::read_local_register(&local_registers, src)?;
                        Self::write_local_register(&mut local_registers, dst, value)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::Add { dst, lhs, rhs } => {
                        let left = Self::read_local_register(&local_registers, lhs)?;
                        let right = Self::read_local_register(&local_registers, rhs)?;
                        let value = self.eval_add_values(Some(module), &left, &right)?;
                        Self::write_local_register(&mut local_registers, dst, value)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::Sub { dst, lhs, rhs } => {
                        let left = Self::read_local_register(&local_registers, lhs)?;
                        let right = Self::read_local_register(&local_registers, rhs)?;
                        let value = Self::eval_arith_values(&left, &right, "sub")?;
                        Self::write_local_register(&mut local_registers, dst, value)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::Inc { dst, src } | Ir3Instruction::Dec { dst, src } => {
                        let delta = if matches!(instruction_ref, Ir3Instruction::Inc { .. }) {
                            1
                        } else {
                            -1
                        };
                        let value = Self::read_local_register(&local_registers, src)?;
                        let value = Self::step_numeric(&value, delta)?;
                        Self::write_local_register(&mut local_registers, dst, value)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::Mul { dst, lhs, rhs } => {
                        let left = Self::read_local_register(&local_registers, lhs)?;
                        let right = Self::read_local_register(&local_registers, rhs)?;
                        let value = Self::eval_arith_values(&left, &right, "mul")?;
                        Self::write_local_register(&mut local_registers, dst, value)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::Div { dst, lhs, rhs } => {
                        let left = Self::read_local_register(&local_registers, lhs)?;
                        let right = Self::read_local_register(&local_registers, rhs)?;
                        let value = Self::eval_div_values(&left, &right)?;
                        Self::write_local_register(&mut local_registers, dst, value)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::GetProperty { obj, key, dst } => {
                        let object_value = Self::read_local_register(&local_registers, obj)?;
                        let key_value = Self::read_local_register(&local_registers, key)?;
                        let value = self.simple_callback_get_property(
                            Some(module),
                            object_value,
                            &key_value,
                        )?;
                        Self::write_local_register(&mut local_registers, dst, value)?;
                        instruction_pointer += 1;
                    }
                    Ir3Instruction::Jump { target } => {
                        instruction_pointer = target as usize;
                    }
                    Ir3Instruction::JumpIf { cond, target } => {
                        let value = Self::read_local_register(&local_registers, cond)?;
                        if value.is_truthy() {
                            instruction_pointer = target as usize;
                        } else {
                            instruction_pointer += 1;
                        }
                    }
                    Ir3Instruction::Return { value } => {
                        return Self::read_local_register(&local_registers, value);
                    }
                    Ir3Instruction::Halt => {
                        return Ok(Value::Undefined);
                    }
                    Ir3Instruction::Throw { value } => {
                        // bd-8enww.4.8: preserve the callback's explicitly-thrown
                        // value so an enclosing `try`/`catch` binds the ORIGINAL
                        // value verbatim, instead of the wrapped "unsupported
                        // instruction" TypeError this `match` used to surface via its
                        // `other` arm (which the caller then re-boxed into a generic
                        // Error object — the `[object …]` symptom of this bug).
                        //
                        // Mirror the modern `Throw` arm: arm `pending_exception` with
                        // the value and surface an `UncaughtException`. The `Call` /
                        // `CallMethod` builtin dispatch that ran this reducer then
                        // routes it through `route_isolated_explicit_throw` into the
                        // caller's catch frames, re-raising the preserved value. This
                        // pure mini-lane's inputs are bounded by the reduction's
                        // live observation context, including earlier accumulator
                        // and element observations.
                        let thrown = Self::read_local_register(&local_registers, value)?;
                        let label = self.json_parse_context_label()?;
                        self.replace_pending_abrupt_slots(Some((thrown.clone(), label)), None)?;
                        return Err(InterpreterError::UncaughtException {
                            value: self.uncaught_exception_description(&thrown),
                        });
                    }
                    other => {
                        return Err(InterpreterError::TypeError {
                            expected: "simple synchronous reducer callback".to_string(),
                            got: format!("unsupported reducer instruction {other:?}"),
                        });
                    }
                }
            }

            Err(InterpreterError::BudgetExhausted {
                executed: self.config.instruction_budget,
                budget: self.config.instruction_budget,
            })
        })();
        self.return_simple_callback_registers(local_registers);
        outcome
    }

    /// The reducer lane's register file: the pooled one when it has
    /// `register_count` slots (all `Undefined`), else a new one.
    pub(super) fn take_simple_callback_registers(
        &mut self,
        register_count: usize,
    ) -> SimpleCallbackRegisters {
        let mut values = std::mem::take(&mut self.simple_callback_register_pool);
        if values.len() != register_count {
            values = vec![Value::Undefined; register_count];
        }
        SimpleCallbackRegisters {
            values,
            value_bytes: 0,
            high_water: 0,
        }
    }

    /// Reset the written prefix and keep the file for the next callback.
    pub(super) fn return_simple_callback_registers(
        &mut self,
        mut registers: SimpleCallbackRegisters,
    ) {
        for value in &mut registers.values[..registers.high_water] {
            *value = Value::Undefined;
        }
        self.simple_callback_register_pool = registers.values;
    }

    pub(super) fn invoke_inline_method_call(
        &mut self,
        module: Option<&Ir3Module>,
        callee: Value,
        receiver: Value,
        arguments: Vec<Value>,
    ) -> Result<Value, InterpreterError> {
        let (value, label) = self.invoke_inline_method_call_with_argument_label(
            module, callee, receiver, arguments, None,
        )?;
        self.join_pending_array_result_label(&label)?;
        Ok(value)
    }

    pub(super) fn mark_inline_callback_started(&mut self) {
        if let Some(started) = self.inline_callback_start_probes.last_mut() {
            *started = true;
        }
    }

    pub(super) fn invoke_inline_method_call_tracking_callback_start(
        &mut self,
        module: Option<&Ir3Module>,
        callee: Value,
        receiver: Value,
        arguments: Vec<Value>,
        argument_label: Option<Label>,
    ) -> (Result<(Value, Label), InterpreterError>, bool) {
        self.inline_callback_start_probes.push(false);
        let result = self.invoke_inline_method_call_with_argument_label(
            module,
            callee,
            receiver,
            arguments,
            argument_label,
        );
        let callback_started = self
            .inline_callback_start_probes
            .pop()
            .expect("isolated callback start probe remained balanced");
        if self.inline_callback_start_probes.is_empty() {
            // The probe stack is execution-transient. Drop its allocation at
            // the outer boundary so repeated callbacks do not create hidden
            // resident memory outside the interpreter accounting model.
            self.inline_callback_start_probes = Vec::new();
        }
        (result, callback_started)
    }

    /// Validate every fallible, tracked allocation needed to enter an isolated
    /// inline callback without cloning or mutating interpreter state. Callers
    /// that publish an externally visible in-flight state can use this before
    /// committing that transition, then invoke through the checked path below.
    pub(super) fn preflight_inline_method_call_with_argument_label(
        &self,
        module: Option<&Ir3Module>,
        callee: &Value,
        argument_count: usize,
        argument_label: Option<&Label>,
    ) -> Result<(), InterpreterError> {
        self.preflight_inline_method_call_with_labels(
            module,
            callee,
            argument_count,
            argument_label,
            None,
            0,
        )
    }

    pub(super) fn preflight_inline_method_call_with_argument_label_and_temporary(
        &self,
        module: Option<&Ir3Module>,
        callee: &Value,
        argument_count: usize,
        argument_label: Option<&Label>,
        additional_temporary_bytes: u64,
    ) -> Result<(), InterpreterError> {
        self.preflight_inline_method_call_with_labels(
            module,
            callee,
            argument_count,
            argument_label,
            None,
            additional_temporary_bytes,
        )
    }

    pub(super) fn preflight_inline_method_call_with_labels(
        &self,
        module: Option<&Ir3Module>,
        callee: &Value,
        argument_count: usize,
        argument_label: Option<&Label>,
        call_labels: Option<&IsolatedCallLabels>,
        additional_temporary_bytes: u64,
    ) -> Result<(), InterpreterError> {
        let caller_module = module.ok_or_else(|| InterpreterError::TypeError {
            expected: "module-backed Function.prototype.call/apply dispatch".to_string(),
            got: "missing module context".to_string(),
        })?;
        // Preserve owner validation before admitting callback state even
        // though the borrowed call site no longer depends on program size.
        self.foreign_closure_module(callee, caller_module)?;
        self.check_module_reentrant_call_depth()?;
        let arg_count = u32::try_from(argument_count).map_err(|_| InterpreterError::TypeError {
            expected: "u32-bounded Function.prototype.call/apply argument count".to_string(),
            got: format!("{argument_count} arguments"),
        })?;
        // bd-9vouw.50: arguments past the register frame are staged out of
        // band, so only the list length is bounded.
        if arg_count > MAX_CALL_ARGUMENTS {
            return Err(InterpreterError::TypeError {
                expected: "Function.prototype.call/apply argument list within MAX_CALL_ARGUMENTS"
                    .to_string(),
                got: format!("{arg_count} arguments"),
            });
        }
        if let Some(IsolatedCallLabels {
            arguments: IsolatedArgumentLabels::Exact(argument_labels),
            ..
        }) = call_labels
            && argument_labels.len() != argument_count
        {
            return Err(InterpreterError::TypeError {
                expected: "one IFC label per isolated callback argument".to_string(),
                got: format!(
                    "{} labels for {argument_count} arguments",
                    argument_labels.len()
                ),
            });
        }

        let transient_execution_bytes = Self::isolated_call_site_bytes()
            .saturating_add(self.module_execution_snapshot_memory_bytes());
        let callback_context_label = match (
            self.active_inline_callback_context_label.as_ref(),
            argument_label,
        ) {
            (Some(inherited), Some(argument)) => Some(if inherited >= argument {
                inherited
            } else {
                argument
            }),
            (Some(inherited), None) => Some(inherited),
            (None, argument) => argument,
        };
        let callback_context_bytes = callback_context_label
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        let label_transport_bytes = call_labels
            .map(|labels| Self::isolated_call_label_transport_bytes(labels, argument_count))
            .unwrap_or(0);
        self.check_temporary_memory_budget(
            transient_execution_bytes
                .saturating_add(callback_context_bytes)
                .saturating_add(label_transport_bytes)
                .saturating_add(additional_temporary_bytes),
        )
    }

    /// Invoke an isolated inline callback under one aggregate IFC context.
    /// EventEmitter supplies its emission label here; ordinary inline calls use
    /// `None` and retain their existing value-only behavior. The context is
    /// joined by register writes even after callee frame clearing, while the
    /// single snapshotted label avoids max-register Custom-label amplification.
    pub(super) fn invoke_inline_method_call_with_argument_label(
        &mut self,
        module: Option<&Ir3Module>,
        callee: Value,
        receiver: Value,
        arguments: Vec<Value>,
        argument_label: Option<Label>,
    ) -> Result<(Value, Label), InterpreterError> {
        self.preflight_inline_method_call_with_argument_label(
            module,
            &callee,
            arguments.len(),
            argument_label.as_ref(),
        )?;
        self.invoke_inline_method_call_with_argument_label_preflighted(
            module,
            callee,
            receiver,
            arguments,
            argument_label,
        )
    }

    pub(super) fn invoke_inline_method_call_with_labels(
        &mut self,
        module: Option<&Ir3Module>,
        callee: Value,
        receiver: Value,
        arguments: Vec<Value>,
        argument_label: Option<Label>,
        call_labels: IsolatedCallLabels,
    ) -> Result<(Value, Label), InterpreterError> {
        self.preflight_inline_method_call_with_labels(
            module,
            &callee,
            arguments.len(),
            argument_label.as_ref(),
            Some(&call_labels),
            0,
        )?;
        self.invoke_inline_method_call_with_labels_preflighted(
            module,
            callee,
            receiver,
            arguments,
            argument_label,
            Some(call_labels),
        )
    }

    pub(super) fn invoke_inline_method_call_with_argument_label_preflighted(
        &mut self,
        module: Option<&Ir3Module>,
        callee: Value,
        receiver: Value,
        arguments: Vec<Value>,
        argument_label: Option<Label>,
    ) -> Result<(Value, Label), InterpreterError> {
        self.invoke_inline_method_call_with_labels_preflighted(
            module,
            callee,
            receiver,
            arguments,
            argument_label,
            None,
        )
    }

    pub(super) fn invoke_inline_method_call_with_labels_preflighted(
        &mut self,
        module: Option<&Ir3Module>,
        callee: Value,
        receiver: Value,
        arguments: Vec<Value>,
        argument_label: Option<Label>,
        call_labels: Option<IsolatedCallLabels>,
    ) -> Result<(Value, Label), InterpreterError> {
        // A request applies to this call only, whatever path it takes.
        let gc_request = self.gc_nested_request.take();
        let caller_module = module.ok_or_else(|| InterpreterError::TypeError {
            expected: "module-backed Function.prototype.call/apply dispatch".to_string(),
            got: "missing module context".to_string(),
        })?;
        let (callee_module_specifier, callee_generated_artifact) =
            self.closure_execution_provenance(&callee, caller_module)?;
        let contained_codegen_grant = callee_generated_artifact
            .map(|handle| self.contained_codegen_grant_for_artifact(handle))
            .transpose()?;
        // Deferred callbacks (timers, EventEmitter, streams, Promise jobs) are
        // commonly invoked while the entry module is active. Select the
        // closure's retained owner program here as well as in direct Call/
        // CallMethod, otherwise the callback path can reintroduce the same
        // cross-module function-index collision.
        let foreign_module = self.foreign_closure_module(&callee, caller_module)?;
        let is_foreign_call = foreign_module.is_some();
        // bd-9vouw.26: every async callee (not only foreign ones) keeps its
        // activation parked at a pending `await`, so the caller resumes now.
        let isolated_async_call = matches!(&callee, Value::AsyncFunction(_));
        let foreign_async_index = isolated_async_call.then_some(self.async_functions.len());
        self.check_module_reentrant_call_depth()?;
        // Isolating a same-module callback hides caller frames just as surely
        // as entering a foreign module. Preserve them in the shared depth
        // budget before clearing the visible call stack.
        let hidden_call_depth = self.effective_call_depth();
        let module = foreign_module.as_deref().unwrap_or(caller_module);
        let arg_count =
            u32::try_from(arguments.len()).map_err(|_| InterpreterError::TypeError {
                expected: "u32-bounded Function.prototype.call/apply argument count".to_string(),
                got: format!("{} arguments", arguments.len()),
            })?;
        // bd-9vouw.50: arguments past the register frame are staged out of
        // band, so only the list length is bounded.
        if arg_count > MAX_CALL_ARGUMENTS {
            return Err(InterpreterError::TypeError {
                expected: "Function.prototype.call/apply argument list within MAX_CALL_ARGUMENTS"
                    .to_string(),
                got: format!("{arg_count} arguments"),
            });
        }

        let transient_wrapper_bytes = Self::isolated_call_site_bytes();
        let transient_execution_bytes = transient_wrapper_bytes;
        let mut remaining_label_transport_bytes = call_labels
            .as_ref()
            .map(|labels| Self::isolated_call_label_transport_bytes(labels, arguments.len()))
            .unwrap_or(0);
        let inherited_context_dominates = match (
            self.active_inline_callback_context_label.as_ref(),
            argument_label.as_ref(),
        ) {
            (Some(inherited), Some(argument)) => inherited >= argument,
            (Some(_), None) => true,
            (None, _) => false,
        };
        // The wrapper and caller snapshot coexist with the isolated callee
        // state. Charge both before either clone so a near-budget guest cannot
        // make the re-entrant module seam temporarily exceed containment.
        let callback_context_label = if inherited_context_dominates {
            // The lower owned argument aggregate is dead. Release it before
            // cloning the inherited winner so the strict physical peak
            // contains exactly one temporary context name, not both.
            drop(argument_label);
            let inherited = self
                .active_inline_callback_context_label
                .as_ref()
                .expect("dominant inherited callback context was checked");
            Some(inherited.clone())
        } else {
            // Move the argument aggregate directly into the isolated context;
            // no second attacker-sized String allocation is needed.
            argument_label
        };
        self.apply_memory_component_delta(
            0,
            transient_execution_bytes.saturating_add(remaining_label_transport_bytes),
        )?;
        if Self::callee_runs_nested(&callee)
            && !is_foreign_call
            && contained_codegen_grant.is_none()
            && callee_generated_artifact.is_none()
            && self.active_generated_function_artifact.is_none()
            && self.pending_exception.is_none()
            && self.pending_return.is_none()
            && self.pending_finally_entry.is_none()
            && self.pending_hostcall_result_label.is_none()
            && self.generator_delegation.is_none()
        {
            let saved_module_specifier = self
                .current_module_specifier
                .replace(callee_module_specifier);
            // The caller's registers stay live under the callback's frame, so
            // only what the requesting Rust frames hold needs pinning.
            let gc_arm = gc_request.as_ref().and_then(|held| {
                self.gc_arm_nested_values(
                    held.iter()
                        .chain([&callee, &receiver])
                        .chain(arguments.iter()),
                )
            });
            let outcome = self.invoke_nested_callback(
                module,
                callee,
                receiver,
                arguments,
                callback_context_label,
                call_labels,
                &mut remaining_label_transport_bytes,
            );
            self.gc_disarm_nested(gc_arm);
            self.current_module_specifier = saved_module_specifier;
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
                transient_execution_bytes.saturating_add(remaining_label_transport_bytes),
            );
            return outcome;
        }
        // The synthetic call site runs past the end of the immutable owner
        // program. This applies to async callees too: suspension retains the
        // activation and the owner's Arc, not this borrowed trampoline. On
        // resumption the async frame returns past the owner's instruction
        // stream, whose normal end-of-stream completion releases the wrapper.
        // Copying the whole program here made every async call O(module size).
        let wrapper_instructions = [
            Ir3Instruction::CallMethod {
                receiver: 0,
                callee: 1,
                args: RegRange {
                    start: 2,
                    count: arg_count,
                },
                dst: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ];
        let wrapper_start = module.instructions.len();

        let setup_previous_register_bytes = self.registers_memory_bytes();
        let setup_previous_register_context_label_bytes =
            self.register_context_labels_memory_bytes();
        // The snapshot takes the caller's registers and labels, leaving the
        // fresh files the callback starts on.
        let snapshot = match self.isolate_module_execution() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
                    transient_execution_bytes.saturating_add(remaining_label_transport_bytes),
                );
                return Err(error);
            }
        };
        let (receiver_label, argument_labels) = match call_labels {
            Some(labels) => (Some(labels.receiver), labels.arguments),
            None => (None, IsolatedArgumentLabels::Public),
        };
        let saved_active_cjs_context = self.active_cjs_context.clone();
        let setup_previous_scope_bytes = self.scope_chain_memory_bytes();
        let setup_previous_call_stack_bytes = self.call_stack_memory_bytes();
        let mut wrapper_memory_committed = false;
        let previous_granted_capabilities =
            self.replace_with_contained_codegen_grant(contained_codegen_grant);
        // The caller's execution now lives only in `snapshot`, a Rust local:
        // pin it with what the requesting frames hold (bd-9vouw.77).
        let gc_arm = gc_request.as_ref().and_then(|held| {
            let pins = held
                .iter()
                .chain([&callee, &receiver])
                .chain(arguments.iter())
                .map(GcPin::Value)
                .chain(std::iter::once(GcPin::ModuleExecution(&snapshot)))
                .chain(foreign_async_index.map(GcPin::AsyncFunctionsFrom))
                .collect::<Vec<_>>();
            self.gc_arm_nested(&pins)
        });
        let mut overflow_depth = None;
        let mut result = (|| -> Result<Value, InterpreterError> {
            // An isolated callback is not the suspended delegating generator.
            // In particular, a foreign async callback must not retain its
            // caller's yield* record in the callback's own activation.
            self.take_generator_delegation();
            self.active_inline_callback_context_label = callback_context_label;
            self.call_stack.clear(&mut self.closures.cold_cells);
            self.ip = wrapper_start;
            self.register_base = 0;
            self.register_width = self.config.max_registers as usize;
            self.catch_frames.clear();
            self.pending_exception = None;
            self.pending_exception_label = Label::Public;
            self.pending_hostcall_result_label = None;
            self.pending_return = None;
            self.suspended_abrupt_completions.clear();
            self.finally_frames.clear();
            self.pending_finally_entry = None;
            self.current_module_specifier = Some(callee_module_specifier);
            self.active_generated_function_artifact = callee_generated_artifact;
            if let Some(artifact_label) = self.active_generated_artifact_source_label() {
                self.active_inline_callback_context_label =
                    match self.active_inline_callback_context_label.take() {
                        Some(existing) => Some(
                            self.join_owned_label_with_temporary_budget(existing, &artifact_label)?,
                        ),
                        None => Some(artifact_label),
                    };
            }
            self.apply_register_context_scope_call_stack_memory_delta(
                setup_previous_register_bytes,
                setup_previous_register_context_label_bytes,
                setup_previous_scope_bytes,
                setup_previous_call_stack_bytes,
            )?;
            wrapper_memory_committed = true;
            self.seed_isolated_receiver(
                0,
                receiver,
                receiver_label,
                &mut remaining_label_transport_bytes,
            )?;
            self.write_reg(1, callee)?;
            let (mut arguments, mut argument_labels) = (arguments, argument_labels);
            overflow_depth =
                Some(self.stage_argument_overflow(2, &mut arguments, &mut argument_labels)?);
            let wrapper_width = 2usize.saturating_add(arguments.len());
            self.seed_isolated_arguments(
                2,
                arguments,
                argument_labels,
                &mut remaining_label_transport_bytes,
                "Function.prototype.call/apply argument register",
            )?;
            // The wrapper frame uses r0 (receiver and destination), r1 (the
            // callee) and the argument registers; the callee's window starts
            // right above them, not a whole window up, so a parked async
            // activation holds one window, not two (bd-9vouw.167).
            self.register_width = wrapper_width.min(self.config.max_registers as usize);
            let previous_reentrant_depth = self.module_reentrant_call_depth;
            let previous_foreign_call_depth = self.active_foreign_module_call_depth;
            self.module_reentrant_call_depth = hidden_call_depth;
            if is_foreign_call {
                self.active_foreign_module_call_depth =
                    previous_foreign_call_depth.saturating_add(1);
            }
            self.isolated_async_entry_pending = isolated_async_call;
            let result = self.run_loop_with_trampoline(module, &wrapper_instructions);
            self.isolated_async_entry_pending = false;
            self.module_reentrant_call_depth = previous_reentrant_depth;
            self.active_foreign_module_call_depth = previous_foreign_call_depth;
            result
        })();
        self.gc_disarm_nested(gc_arm);
        if let Some(depth) = overflow_depth {
            self.restore_argument_overflow(depth);
        }
        let mut isolated_async_result_label = None;
        let mut isolated_async_execution_rehomed = false;
        let mut isolated_async_execution_owner = None;
        let mut abandoned_async_ids = Vec::new();
        let mut abandoned_async_label = Label::Public;
        // bd-j9r60: a parked async callee's activation moves into its async
        // function object and the caller is restored without accounting. That
        // transfer is charged below as one delta over the live activation and
        // the one receiving async object, not by re-deriving the estimate.
        let rehome_async_id =
            foreign_async_index
                .filter(|_| result.is_ok())
                .and_then(|async_index| {
                    self.suspended_async_function_id_in_call_stack(&self.call_stack, async_index)
                });
        let rehome_previous_bytes = self.active_module_execution_memory_bytes().saturating_add(
            rehome_async_id.map_or(0, |id| self.async_function_memory_bytes_at(id)),
        );
        #[cfg(test)]
        let rehome_drift = self.memory_walk_drift();
        if let Some(async_index) = foreign_async_index {
            if result.is_ok() {
                // A pending `await` exits with the async callee's register base
                // still active. The synthetic caller's destination is absolute
                // register zero, not `read_reg(0)` in that callee frame.
                match self.retain_isolated_async_execution(async_index, contained_codegen_grant) {
                    Ok(Some((result_promise, result_label, suspended_async_id))) => {
                        isolated_async_result_label = Some(result_label);
                        isolated_async_execution_rehomed = true;
                        isolated_async_execution_owner = Some(suspended_async_id);
                        result = Ok(Value::Promise(result_promise));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        abandoned_async_ids = self.async_function_ids_created_since(async_index);
                        abandoned_async_label = self
                            .active_inline_callback_context_label
                            .as_ref()
                            .map_or(Label::Public, Self::terminal_async_failure_label);
                        result = Err(error);
                    }
                }
            } else {
                abandoned_async_ids = self.async_function_ids_created_since(async_index);
                abandoned_async_label = self
                    .active_inline_callback_context_label
                    .as_ref()
                    .map_or(Label::Public, Self::terminal_async_failure_label);
            }
        }
        let result_label = if result.is_ok() {
            match isolated_async_result_label {
                Some(label) => Ok(label),
                None => self.clone_register_label_with_temporary_budget(0),
            }
        } else {
            Ok(Label::Public)
        };
        // If the callee threw and nothing inside it caught the exception, the
        // isolated run cleared `catch_frames` so an *enclosing* try/catch was
        // invisible here. Capture the thrown VALUE before the snapshot restore
        // discards it, then re-arm `pending_exception` in the restored (caller)
        // context so the caller can re-route the throw through its own unwinding
        // (e.g. `ForOfNext` for `for (… of …)`). (bd-bg9l1.27.7)
        let thrown_value = match &result {
            Err(InterpreterError::UncaughtException { .. }) => self
                .pending_exception
                .clone()
                .map(|v| (v, self.pending_exception_label.clone())),
            _ => None,
        };
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
            transient_execution_bytes.saturating_add(remaining_label_transport_bytes),
        );
        self.restore_module_execution(
            snapshot,
            wrapper_memory_committed && !isolated_async_execution_rehomed,
        );
        self.active_cjs_context = saved_active_cjs_context;
        self.restore_replaced_codegen_grants(previous_granted_capabilities);
        if result.is_err() && !abandoned_async_ids.is_empty() {
            self.terminally_reject_abandoned_async_functions(
                &abandoned_async_ids,
                abandoned_async_label,
            );
        }
        let rehome_result = if isolated_async_execution_rehomed {
            let rehome_next_bytes = self.active_module_execution_memory_bytes().saturating_add(
                rehome_async_id.map_or(0, |id| self.async_function_memory_bytes_at(id)),
            );
            let applied =
                self.apply_memory_component_delta(rehome_previous_bytes, rehome_next_bytes);
            // The wrapper reservation released above is the only unwalked
            // charge that changed since `rehome_drift`.
            #[cfg(test)]
            if applied.is_ok() {
                debug_assert_eq!(
                    self.memory_walk_drift(),
                    rehome_drift
                        - i128::from(
                            transient_execution_bytes
                                .saturating_add(remaining_label_transport_bytes)
                        ),
                    "async rehome transfer drifted from the full walk (bd-j9r60)"
                );
            }
            applied
        } else {
            Ok(0)
        };
        if let Err(error) = rehome_result {
            let mut abandoned_async_ids = self.async_function_ids_created_since(
                foreign_async_index
                    .expect("rehomed foreign async execution has a published object"),
            );
            let retained_async_ids = isolated_async_execution_owner
                .and_then(|owner_id| {
                    self.closures.replace_activation(
                        &mut self.async_functions[owner_id as usize].isolated_execution,
                        None,
                    )
                })
                .map(|execution| {
                    Self::async_function_ids_in_call_stack(
                        &execution.call_stack,
                        foreign_async_index
                            .expect("rehomed foreign async execution has a published object"),
                    )
                })
                .unwrap_or_default();
            Self::extend_unique_async_function_ids(&mut abandoned_async_ids, retained_async_ids);
            let failure_label = result_label.as_ref().map_or(Label::Public, |label| {
                Self::terminal_async_failure_label(label)
            });
            self.terminally_reject_abandoned_async_functions(&abandoned_async_ids, failure_label);
            result = Err(error);
        }
        if let Some((value, label)) = thrown_value {
            self.replace_pending_abrupt_slots(Some((value, label)), None)?;
        }
        let result_label = result_label?;
        result.map(|value| (value, result_label))
    }

    /// Run a same-module synchronous callback as a nested call on the live
    /// stack. A native boundary frame is pushed for the builtin caller, the
    /// receiver, callee and arguments are staged in a scratch register frame,
    /// and the dispatch loop runs the `CallMethod` + `Halt` trampoline until
    /// the callee returns. Exception routing, async rejection and completion
    /// clearing stop at the boundary, so the callback is as isolated from its
    /// caller's handlers as the snapshotting path, without cloning the
    /// execution state or reallocating the register file per call.
    ///
    /// The caller guarantees no pending exception, return, finally entry,
    /// hostcall result label or generator delegation, so none needs parking.
    /// Identity of a module for the lifetime of a run: the top-level module
    /// reference outlives every nested dispatch, so an equal address is the
    /// same module.
    pub(super) fn module_address(module: &Ir3Module) -> usize {
        std::ptr::from_ref(module) as usize
    }

    /// The top-level compact plan when `module` is the module it was compiled
    /// for (O(1): the plan's tables are shared).
    pub(super) fn top_level_compact_tier1_for(
        &self,
        module: &Ir3Module,
    ) -> Option<CompactTier1Program> {
        self.top_level_compact_tier1
            .as_ref()
            .filter(|(address, _)| *address == Self::module_address(module))
            .map(|(_, program)| program.clone())
    }

    /// Callees an inline method call runs on the live stack through
    /// [`Self::invoke_nested_callback`] (when nothing else needs isolation):
    /// same-module closures, and builtins other than a Function-constructor
    /// generated function, whose contained codegen grant needs the isolated
    /// run. The nested trampoline runs the same CallMethod as the isolated
    /// wrapper. A builtin reached by `fn.call(...)`, `fn.apply(...)` or
    /// through a bound function used to snapshot and restore the whole
    /// module execution around one builtin dispatch: 7-9x a closure call
    /// (bd-9vouw.312).
    pub(super) fn callee_runs_nested(callee: &Value) -> bool {
        match callee {
            Value::Closure(_) | Value::Function(_) => true,
            Value::BuiltinFunction(builtin) => {
                builtin.kind != BuiltinFunctionKind::GeneratedFunction
            }
            _ => false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn invoke_nested_callback(
        &mut self,
        module: &Ir3Module,
        callee: Value,
        receiver: Value,
        arguments: Vec<Value>,
        callback_context_label: Option<Label>,
        call_labels: Option<IsolatedCallLabels>,
        remaining_label_transport_bytes: &mut u64,
    ) -> Result<(Value, Label), InterpreterError> {
        let arg_count = u32::try_from(arguments.len()).unwrap_or(u32::MAX);
        let saved_ip = self.ip;
        let saved_register_base = self.register_base;
        let saved_register_width = self.register_width;

        let previous_context_bytes = self.active_inline_callback_context_memory_bytes();
        let saved_context = std::mem::replace(
            &mut self.active_inline_callback_context_label,
            callback_context_label,
        );
        let context_bytes = self.active_inline_callback_context_memory_bytes();
        if let Err(error) = self.apply_memory_component_delta(previous_context_bytes, context_bytes)
        {
            self.active_inline_callback_context_label = saved_context;
            return Err(error);
        }

        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        let boundary_index = self.call_stack.len();
        let pushed_frame = CallFrame {
            return_ip: saved_ip,
            return_reg: 0,
            register_base: saved_register_base,
            register_width: saved_register_width,
            function_index: None,
            this_value: Value::Undefined,
            this_label: Label::Public,
            new_target_value: Value::Undefined,
            new_target_label: Label::Public,
            super_value: Value::Undefined,
            super_label: Label::Public,
            super_home_object: None,
            construct_this: None,
            derived_constructor: false,
            this_initialized: true,
            initialize_derived_this_on_return: false,
            class_instance_fields: None,
            saved_pending_exception: None,
            saved_pending_exception_label: Label::Public,
            saved_pending_return: None,
            saved_suspended_abrupt_depth: self.suspended_abrupt_completions.len(),
            saved_finally_mode_depth: self.finally_frames.len(),
            saved_scope_depth: self.scope_chain.depth(),
            saved_scope_chain: None,
            scope_inert_virtual_scope_bytes: 0,
            async_function_id: None,
            native_boundary: true,
        };
        self.call_stack
            .push(pushed_frame, &mut self.closures.cold_cells);
        let catch_frames_before = self.catch_frames.len();
        let mut overflow_depth = None;

        let run = (|| -> Result<(Value, Label), InterpreterError> {
            self.apply_call_stack_memory_delta(previous_call_stack_bytes)?;
            // The trampoline reads only the receiver, callee and arguments.
            // A full-width request would pin the shared clear high-water mark
            // at max_registers, so every later call would clear the whole
            // window.
            self.enter_stacked_register_frame_width(
                usize::try_from(arg_count)
                    .unwrap_or(usize::MAX)
                    .saturating_add(2)
                    .min(self.config.max_registers as usize),
            )?;
            let (receiver_label, mut argument_labels) = match call_labels {
                Some(labels) => (Some(labels.receiver), labels.arguments),
                None => (None, IsolatedArgumentLabels::Public),
            };
            let mut arguments = arguments;
            overflow_depth =
                Some(self.stage_argument_overflow(2, &mut arguments, &mut argument_labels)?);
            self.seed_isolated_receiver(
                0,
                receiver,
                receiver_label,
                remaining_label_transport_bytes,
            )?;
            self.write_reg(1, callee)?;
            self.seed_isolated_arguments(
                2,
                arguments,
                argument_labels,
                remaining_label_transport_bytes,
                "nested callback argument register",
            )?;
            let trampoline = [
                Ir3Instruction::CallMethod {
                    receiver: 0,
                    callee: 1,
                    args: RegRange {
                        start: 2,
                        count: arg_count,
                    },
                    dst: 0,
                },
                Ir3Instruction::Halt,
            ];
            self.ip = module.instructions.len();
            let compact_tier1 = self.top_level_compact_tier1_for(module);
            match self.run_loop_labeled_with_trampoline(module, compact_tier1.as_ref(), &trampoline)
            {
                Err(InterpreterError::Halted) if self.call_stack.len() == boundary_index + 1 => {
                    let value = self.read_reg(0)?;
                    let label = self.clone_register_label_with_temporary_budget(0)?;
                    Ok((value, label))
                }
                Ok(completion) => Ok((completion.value, completion.label)),
                Err(InterpreterError::Halted) => Err(InterpreterError::InternalError {
                    details: "nested callback halted above its native boundary".to_string(),
                }),
                Err(error) => Err(error),
            }
        })();
        if let Some(depth) = overflow_depth {
            self.restore_argument_overflow(depth);
        }

        // Unwind whatever the callee left above the boundary (an escaping
        // throw or a native fault), then drop the boundary frame itself.
        let unwound = if self.call_stack.len() > boundary_index + 1 {
            self.unwind_call_stack_to(boundary_index + 1).map(|_| ())
        } else {
            Ok(())
        };
        self.catch_frames.truncate(catch_frames_before);
        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        if let Some(boundary) = self.call_stack.pop(&mut self.closures.cold_cells) {
            debug_assert!(
                boundary.native_boundary,
                "nested callback lost its boundary frame"
            );
            self.truncate_finally_frames(boundary.saved_finally_mode_depth);
            self.restore_scope_chain_for_frame(&boundary);
        }
        let popped = self.apply_call_stack_memory_delta(previous_call_stack_bytes);
        self.register_base = saved_register_base;
        self.register_width = saved_register_width;
        self.ip = saved_ip;

        let previous_context_bytes = self.active_inline_callback_context_memory_bytes();
        self.active_inline_callback_context_label = saved_context;
        let context_bytes = self.active_inline_callback_context_memory_bytes();
        let restored = self.apply_memory_component_delta(previous_context_bytes, context_bytes);
        unwound?;
        popped?;
        restored?;
        run
    }

    #[cfg(test)]
    pub(super) fn invoke_inline_construct(
        &mut self,
        module: Option<&Ir3Module>,
        constructor: Value,
        arguments: Vec<Value>,
    ) -> Result<Value, InterpreterError> {
        self.invoke_inline_construct_with_labels(module, constructor, arguments, None, None)
            .map(|(value, _label)| value)
    }

    pub(super) fn invoke_inline_construct_with_labels(
        &mut self,
        module: Option<&Ir3Module>,
        constructor: Value,
        arguments: Vec<Value>,
        call_labels: Option<IsolatedCallLabels>,
        explicit_new_target: Option<(Value, Label)>,
    ) -> Result<(Value, Label), InterpreterError> {
        // A request applies to this construction only, whatever path it takes.
        let gc_request = self.gc_nested_request.take();
        let caller_module = module.ok_or_else(|| InterpreterError::TypeError {
            expected: "module-backed Reflect.construct dispatch".to_string(),
            got: "missing module context".to_string(),
        })?;
        let (constructor_module_specifier, constructor_generated_artifact) =
            self.closure_execution_provenance(&constructor, caller_module)?;
        let contained_codegen_grant = constructor_generated_artifact
            .map(|handle| self.contained_codegen_grant_for_artifact(handle))
            .transpose()?;
        let foreign_module = self.foreign_closure_module(&constructor, caller_module)?;
        if let Some((new_target, _)) = explicit_new_target.as_ref() {
            // Resolve independently from the target: function indices are
            // module-local, and equal indices from two retained modules must
            // never alias their prototype owners.
            let _ = self.foreign_closure_module(new_target, caller_module)?;
        }
        let is_foreign_construct = foreign_module.is_some();
        self.check_module_reentrant_call_depth()?;
        // Isolating a same-module callback hides caller frames just as surely
        // as entering a foreign module. Preserve them in the shared depth
        // budget before clearing the visible call stack.
        let hidden_call_depth = self.effective_call_depth();
        let module = foreign_module.as_deref().unwrap_or(caller_module);
        let arg_count =
            u32::try_from(arguments.len()).map_err(|_| InterpreterError::TypeError {
                expected: "u32-bounded Reflect.construct argument count".to_string(),
                got: format!("{} arguments", arguments.len()),
            })?;
        let argument_start: u32 = if explicit_new_target.is_some() { 2 } else { 1 };
        // bd-9vouw.50: arguments past the register frame are staged out of
        // band, so only the list length is bounded.
        if arg_count > MAX_CALL_ARGUMENTS {
            return Err(InterpreterError::TypeError {
                expected: "Reflect.construct argument list within MAX_CALL_ARGUMENTS".to_string(),
                got: format!("{arg_count} arguments"),
            });
        }
        if let Some(IsolatedCallLabels {
            arguments: IsolatedArgumentLabels::Exact(argument_labels),
            ..
        }) = call_labels.as_ref()
            && argument_labels.len() != arguments.len()
        {
            return Err(InterpreterError::TypeError {
                expected: "one IFC label per isolated constructor argument".to_string(),
                got: format!(
                    "{} labels for {} arguments",
                    argument_labels.len(),
                    arguments.len()
                ),
            });
        }

        let transient_wrapper_bytes = Self::isolated_call_site_bytes();
        let transient_execution_bytes = transient_wrapper_bytes;
        let mut remaining_label_transport_bytes = call_labels
            .as_ref()
            .map(|labels| Self::isolated_call_label_transport_bytes(labels, arguments.len()))
            .unwrap_or(0)
            .saturating_add(
                explicit_new_target
                    .as_ref()
                    .map(|(_, label)| Self::estimate_label_bytes(label))
                    .unwrap_or(0),
            );
        self.check_temporary_memory_budget(
            transient_execution_bytes
                .saturating_add(self.module_execution_snapshot_memory_bytes())
                .saturating_add(remaining_label_transport_bytes),
        )?;
        self.apply_memory_component_delta(
            0,
            transient_execution_bytes.saturating_add(remaining_label_transport_bytes),
        )?;
        // Trampoline past the end of the module, as for isolated calls.
        let wrapper_instructions = [
            if explicit_new_target.is_some() {
                Ir3Instruction::ConstructWithNewTarget {
                    callee: 0,
                    new_target: 1,
                    args: RegRange {
                        start: argument_start,
                        count: arg_count,
                    },
                    dst: 0,
                }
            } else {
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange {
                        start: argument_start,
                        count: arg_count,
                    },
                    dst: 0,
                }
            },
            Ir3Instruction::Return { value: 0 },
        ];
        let wrapper_start = module.instructions.len();

        let setup_previous_register_bytes = self.registers_memory_bytes();
        let setup_previous_register_context_label_bytes =
            self.register_context_labels_memory_bytes();
        // The snapshot takes the caller's registers and labels, leaving the
        // fresh files the constructor starts on.
        let snapshot = match self.isolate_module_execution() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
                    transient_execution_bytes.saturating_add(remaining_label_transport_bytes),
                );
                return Err(error);
            }
        };
        let (constructor_label, argument_labels) = match call_labels {
            Some(labels) => (Some(labels.receiver), labels.arguments),
            None => (None, IsolatedArgumentLabels::Public),
        };
        let saved_active_cjs_context = self.active_cjs_context.clone();
        let setup_previous_scope_bytes = self.scope_chain_memory_bytes();
        let setup_previous_call_stack_bytes = self.call_stack_memory_bytes();
        let mut wrapper_memory_committed = false;
        let previous_granted_capabilities =
            self.replace_with_contained_codegen_grant(contained_codegen_grant);
        let mut overflow_depth = None;
        let result = (|| -> Result<Value, InterpreterError> {
            self.call_stack.clear(&mut self.closures.cold_cells);
            self.ip = wrapper_start;
            self.register_base = 0;
            self.register_width = self.config.max_registers as usize;
            self.catch_frames.clear();
            self.pending_exception = None;
            self.pending_exception_label = Label::Public;
            self.pending_hostcall_result_label = None;
            self.pending_return = None;
            self.suspended_abrupt_completions.clear();
            self.finally_frames.clear();
            self.pending_finally_entry = None;
            self.current_module_specifier = Some(constructor_module_specifier);
            self.active_generated_function_artifact = constructor_generated_artifact;
            if let Some(artifact_label) = self.active_generated_artifact_source_label() {
                self.active_inline_callback_context_label =
                    match self.active_inline_callback_context_label.take() {
                        Some(existing) => Some(
                            self.join_owned_label_with_temporary_budget(existing, &artifact_label)?,
                        ),
                        None => Some(artifact_label),
                    };
            }
            self.apply_register_context_scope_call_stack_memory_delta(
                setup_previous_register_bytes,
                setup_previous_register_context_label_bytes,
                setup_previous_scope_bytes,
                setup_previous_call_stack_bytes,
            )?;
            wrapper_memory_committed = true;
            self.seed_isolated_receiver(
                0,
                constructor,
                constructor_label,
                &mut remaining_label_transport_bytes,
            )?;
            if let Some((new_target, new_target_label)) = explicit_new_target {
                self.seed_isolated_receiver(
                    1,
                    new_target,
                    Some(new_target_label),
                    &mut remaining_label_transport_bytes,
                )?;
            }
            let (mut arguments, mut argument_labels) = (arguments, argument_labels);
            overflow_depth = Some(self.stage_argument_overflow(
                argument_start,
                &mut arguments,
                &mut argument_labels,
            )?);
            self.seed_isolated_arguments(
                argument_start,
                arguments,
                argument_labels,
                &mut remaining_label_transport_bytes,
                "Reflect.construct argument register",
            )?;
            let previous_reentrant_depth = self.module_reentrant_call_depth;
            let previous_foreign_call_depth = self.active_foreign_module_call_depth;
            self.module_reentrant_call_depth = hidden_call_depth;
            if is_foreign_construct {
                self.active_foreign_module_call_depth =
                    previous_foreign_call_depth.saturating_add(1);
            }
            // bd-9vouw.77: the constructor, new target and arguments are in
            // the wrapper's registers; the caller's execution is in
            // `snapshot`.
            let gc_arm = gc_request.as_ref().and_then(|held| {
                let pins = held
                    .iter()
                    .map(GcPin::Value)
                    .chain(std::iter::once(GcPin::ModuleExecution(&snapshot)))
                    .collect::<Vec<_>>();
                self.gc_arm_nested(&pins)
            });
            let result = self.run_loop_with_trampoline(module, &wrapper_instructions);
            self.gc_disarm_nested(gc_arm);
            self.module_reentrant_call_depth = previous_reentrant_depth;
            self.active_foreign_module_call_depth = previous_foreign_call_depth;
            result
        })();
        if let Some(depth) = overflow_depth {
            self.restore_argument_overflow(depth);
        }
        let result_label = if result.is_ok() {
            self.clone_register_label_with_temporary_budget(0)
        } else {
            Ok(Label::Public)
        };
        let thrown_value = match &result {
            Err(InterpreterError::UncaughtException { .. }) => self
                .pending_exception
                .clone()
                .map(|value| (value, self.pending_exception_label.clone())),
            _ => None,
        };
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
            transient_execution_bytes.saturating_add(remaining_label_transport_bytes),
        );
        self.restore_module_execution(snapshot, wrapper_memory_committed);
        self.active_cjs_context = saved_active_cjs_context;
        self.restore_replaced_codegen_grants(previous_granted_capabilities);
        if let Some((value, label)) = thrown_value {
            self.replace_pending_abrupt_slots(Some((value, label)), None)?;
        }
        let result_label = result_label?;
        result.map(|value| (value, result_label))
    }

    pub(super) fn read_local_register(
        registers: &SimpleCallbackRegisters,
        register: u32,
    ) -> Result<Value, InterpreterError> {
        registers.values.get(register as usize).cloned().ok_or(
            InterpreterError::RegisterOutOfBounds {
                register,
                max: registers.values.len() as u32,
            },
        )
    }

    pub(super) fn write_local_register(
        registers: &mut SimpleCallbackRegisters,
        register: u32,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let max_registers = registers.values.len() as u32;
        let register_index = register as usize;
        let Some(slot) = registers.values.get_mut(register_index) else {
            return Err(InterpreterError::RegisterOutOfBounds {
                register,
                max: max_registers,
            });
        };
        let released = Self::estimate_execution_seed_value_bytes(slot);
        let added = Self::estimate_execution_seed_value_bytes(&value);
        *slot = value;
        registers.value_bytes = registers
            .value_bytes
            .saturating_sub(released)
            .saturating_add(added);
        registers.high_water = registers.high_water.max(register_index + 1);
        Ok(())
    }

    pub(super) fn simple_callback_register_bytes(registers: &SimpleCallbackRegisters) -> u64 {
        u64::try_from(registers.values.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(std::mem::size_of::<Value>()).unwrap_or(u64::MAX))
            .saturating_add(registers.value_bytes)
    }

    pub(super) fn eval_add_values(
        &self,
        module: Option<&Ir3Module>,
        left: &Value,
        right: &Value,
    ) -> Result<Value, InterpreterError> {
        match (left, right) {
            // bd-9vouw.2: the callback mini-lanes (reduce, Array.from) share
            // the main evaluator's Number semantics instead of wrapping i64.
            (Value::Int(left_int), Value::Int(right_int)) => Ok(js_int_add(*left_int, *right_int)),
            (Value::BigInt(left_bigint), Value::BigInt(right_bigint)) => {
                self.check_temporary_memory_budget(Self::bigint_add_construction_peak_bytes(
                    left_bigint,
                    right_bigint,
                ))?;
                Ok(Value::BigInt(Arc::from(Self::add_bigint_decimal(
                    left_bigint,
                    right_bigint,
                ))))
            }
            (Value::Float(left_float), Value::Float(right_float)) => {
                Ok(js_number_to_value(left_float.inner() + right_float.inner()))
            }
            (Value::Int(left_int), Value::Float(right_float)) => {
                Ok(js_number_to_value(*left_int as f64 + right_float.inner()))
            }
            (Value::Float(left_float), Value::Int(right_int)) => {
                Ok(js_number_to_value(left_float.inner() + *right_int as f64))
            }
            (Value::Str(left_string), Value::Str(right_string)) => {
                self.check_string_limit(left_string.len().saturating_add(right_string.len()))?;
                // Exact-code-unit concat heals split surrogate pairs (bd-neika).
                Ok(Value::Str(left_string.concat(right_string)))
            }
            (Value::Str(_), Value::Symbol(_)) | (Value::Symbol(_), Value::Str(_)) => {
                Err(InterpreterError::TypeError {
                    expected: "string-concatenable value".to_string(),
                    got: "symbol".to_string(),
                })
            }
            (Value::Str(left_string), other) => {
                let other_string = if other.is_callable() {
                    self.function_native_source_text(module, other)
                } else {
                    self.value_to_string(other)
                };
                self.check_string_limit(left_string.len().saturating_add(other_string.len()))?;
                Ok(Value::Str(
                    left_string.concat(&JsString::from(other_string)),
                ))
            }
            (other, Value::Str(right_string)) => {
                let other_string = if other.is_callable() {
                    self.function_native_source_text(module, other)
                } else {
                    self.value_to_string(other)
                };
                self.check_string_limit(other_string.len().saturating_add(right_string.len()))?;
                Ok(Value::Str(
                    JsString::from(other_string).concat(right_string),
                ))
            }
            _ => {
                let left_number =
                    Self::coerce_to_float(left).ok_or_else(|| InterpreterError::TypeError {
                        expected: "number or string".to_string(),
                        got: format!("{} + {}", left.type_name(), right.type_name()),
                    })?;
                let right_number =
                    Self::coerce_to_float(right).ok_or_else(|| InterpreterError::TypeError {
                        expected: "number or string".to_string(),
                        got: format!("{} + {}", left.type_name(), right.type_name()),
                    })?;
                Self::number_value(left_number + right_number)
            }
        }
    }
}
