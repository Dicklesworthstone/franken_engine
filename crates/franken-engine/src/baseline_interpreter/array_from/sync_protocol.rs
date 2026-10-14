//! Array.fromAsync's Async-from-Sync protocol, on the native Promise scheduler.
//! Keep the original result objects: the for-of adapter intentionally omits
//! terminal values and does not await return(). No guest-facing wrapper or
//! external runtime implements these steps.

use super::*;

impl InterpreterCore {
    pub(super) fn array_from_async_capture_sync(
        &mut self,
        module: &Ir3Module,
        iterator: Value,
    ) -> Result<FromAsyncSyncIterator, InterpreterError> {
        if !iterator.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "object returned by @@iterator".to_string(),
                got: iterator.type_name().to_string(),
            });
        }
        // GetIteratorFromMethod captures next, without testing IsCallable.
        // The actual call, after initialization, owns that possible failure.
        let next = self.get_v(module, &iterator, &Self::from_async_sync_key("next"))?;
        Ok(FromAsyncSyncIterator::Protocol { iterator, next })
    }

    fn from_async_sync_key(name: &str) -> RuntimePropertyKey {
        RuntimePropertyKey::String(JsString::from(name))
    }

    /// Isolate only these protocol observations; do not leave an observation
    /// floor installed on unrelated code after a suspended or failed step.
    fn from_async_sync_scope<T>(
        &mut self,
        label: &Label,
        step: impl FnOnce(&mut Self) -> Result<T, InterpreterError>,
    ) -> Result<T, InterpreterError> {
        self.scoped_conversion(|core| {
            core.json_observe_label(label.clone())?;
            let mut outcome = step(core);
            if let Err(error) = core.observe_scoped_callback_result() {
                outcome = Err(error);
            }
            match outcome {
                Err(error) if Self::js_catchable_error_name(&error).is_some() => {
                    Err(core.scoped_native_error(&error)?)
                }
                Err(error @ InterpreterError::UncaughtException { .. }) => {
                    let label = core.json_parse_context_label()?;
                    core.join_pending_exception_label(&label)?;
                    Err(error)
                }
                other => other,
            }
        })
    }

    fn from_async_sync_get(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        name: &str,
    ) -> Result<Value, InterpreterError> {
        let key = Self::from_async_sync_key(name);
        let value = match self.iterator_carrier_backing_id(value, "sync iterator protocol")? {
            Some(backing) => {
                self.iterator_protocol_property(Some(module), backing, &key, value.clone())?
            }
            None => self.get_v(module, value, &key)?,
        };
        self.observe_scoped_callback_result()?;
        Ok(value)
    }

    fn from_async_sync_call(
        &mut self,
        module: &Ir3Module,
        method: Value,
        iterator: Value,
    ) -> Result<Value, InterpreterError> {
        let label = self.json_parse_context_label()?;
        let (value, observed) = self.invoke_inline_method_call_with_argument_label(
            Some(module), method, iterator, Vec::new(), Some(label),
        )?;
        self.json_observe_label(observed)?;
        self.observe_scoped_callback_result()?;
        Ok(value)
    }

    /// AsyncFromSyncIteratorContinuation always reads done then value, even
    /// when done is true. Getter failures reject the wrapper before the outer
    /// await, without IteratorClose. A terminal rejected value also never closes.
    pub(super) fn array_from_async_sync_protocol_next(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        self.from_async_sync_scope(label, |core| {
            let step = (|| {
                let iterator = core.array_from_async_slot(holder, "__iterator")?;
                let next = core.array_from_async_slot(holder, "__next")?;
                let result = core.from_async_sync_call(module, next, iterator)?;
                if !result.is_object_like() {
                    return Err(InterpreterError::TypeError {
                        expected: "sync iterator result object".to_string(),
                        got: result.type_name().to_string(),
                    });
                }
                let done = core.from_async_sync_get(module, &result, "done")?.is_truthy();
                let value = core.from_async_sync_get(module, &result, "value")?;
                core.array_from_async_set(holder, "__done", Value::Bool(done))?;
                Ok(value)
            })();
            let observed = core.json_parse_context_label()?;
            match step {
                Ok(value) => core.array_from_async_await(
                    module, holder, value, FromAsyncAwait::SyncValue, &observed,
                ),
                Err(error) => {
                    // Only language errors reject the wrapper. Budget and
                    // cancellation faults propagate out of the native run.
                    let (reason, label) = core.thrown_completion_value(error, &observed)?;
                    core.from_async_sync_rejected_step(module, holder, reason, label)
                }
            }
        })
    }

    fn from_async_sync_rejected_step(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        reason: Value,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let reason = self.promise_value(&reason)?;
        let promise = self.create_rejected_promise(reason, label.clone())?;
        self.array_from_async_await(
            module, holder, Value::Promise(promise.0), FromAsyncAwait::SyncStep, &label,
        )
    }

    /// Return lookup/call is shared, but its consumers differ: a yielded
    /// rejection performs synchronous IteratorClose and ignores the result;
    /// a mapper failure awaits the value of the return result instead.
    fn from_async_sync_return(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
    ) -> Result<Option<Value>, InterpreterError> {
        let iterator = self.array_from_async_slot(holder, "__iterator")?;
        let method = self.from_async_sync_get(module, &iterator, "return")?;
        if matches!(method, Value::Undefined | Value::Null) {
            return Ok(None);
        }
        self.from_async_sync_call(module, method, iterator).map(Some)
    }

    pub(super) fn array_from_async_sync_value_rejected(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        reason: Value,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        // Publish the exact reason in the charged, traced holder before any
        // cleanup callback can allocate, reenter, or overwrite exception slots.
        self.array_from_async_keep_close_reason(holder, reason, label)?;
        self.from_async_sync_scope(label, |core| {
            let closed = core.from_async_sync_return(module, holder).map(|_| ());
            core.array_from_async_discard_close_error(closed)?;
            let reason = core.array_from_async_slot(holder, "__error")?;
            let observed = core.json_parse_context_label()?;
            core.from_async_sync_rejected_step(module, holder, reason, observed)
        })
    }

    pub(super) fn array_from_async_sync_protocol_close(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        self.from_async_sync_scope(label, |core| {
            let result = (|| {
                let Some(result) = core.from_async_sync_return(module, holder)? else {
                    return Ok(None);
                };
                if !result.is_object_like() {
                    return Err(InterpreterError::TypeError {
                        expected: "sync iterator return result object".to_string(),
                        got: result.type_name().to_string(),
                    });
                }
                // Both getters are observable, even though the original throw
                // wins and the return result cannot add another output element.
                let _done = core.from_async_sync_get(module, &result, "done")?.is_truthy();
                core.from_async_sync_get(module, &result, "value").map(Some)
            })();
            let observed = core.json_parse_context_label()?;
            match result {
                Ok(Some(value)) => core.array_from_async_await(
                    module, holder, value, FromAsyncAwait::SyncCloseValue, &observed,
                ),
                Ok(None) => core.array_from_async_sync_close_settled(module, holder, &observed),
                Err(error) => {
                    core.array_from_async_discard_close_error(Err(error))?;
                    core.array_from_async_sync_close_settled(module, holder, &observed)
                }
            }
        })
    }

    /// The close value's fulfillment OR rejection settles the wrapper; the
    /// outer AsyncIteratorClose awaits that wrapper before rejecting with the
    /// original completion. A rejection here must not call return a second time.
    pub(super) fn array_from_async_sync_close_settled(
        &mut self,
        module: &Ir3Module,
        holder: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let key = Self::from_async_sync_key("__error");
        let original_label = self.runtime_property_label(holder, &key);
        let observed = original_label.join(label);
        let original = self.array_from_async_slot(holder, "__error")?;
        self.array_from_async_keep_close_reason(holder, original, &observed)?;
        self.array_from_async_await(
            module, holder, Value::Undefined, FromAsyncAwait::Close, &observed,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::promise_model::PromiseState;

    fn fixture(source: &str) -> (InterpreterCore, Ir3Module, ObjectId) {
        let tree = crate::parser_api_stability::parse_script(source).unwrap();
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "sync-protocol-state.js"),
            &LoweringContext::new("sync-protocol", "state", "builtin-only"),
        ).unwrap().ir3;
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ].into_iter().collect();
        let mut core = InterpreterCore::new(config, "sync-protocol-state");
        let Value::Object(state) = core.execute(&module).unwrap().value else {
            panic!("fixture must return its state");
        };
        core.seed_register(0, Value::Object(state)).unwrap();
        core.replace_pending_hostcall_result_label(None).unwrap();
        (core, module, state)
    }

    fn prop(core: &InterpreterCore, state: ObjectId, name: &str) -> Value {
        core.heap[state.0 as usize].properties.get(name).unwrap().clone()
    }

    fn holder(core: &mut InterpreterCore, iterator: Value) -> ObjectId {
        let promise = core.create_promise().unwrap();
        let holder = core.alloc_object_with_properties(&[
            ("__promise", Value::Promise(promise.0)),
            ("__iterator", iterator),
        ]).unwrap();
        core.seed_register(1, Value::Object(holder)).unwrap();
        for (name, kind) in [
            ("__onFulfilled", BuiltinFunctionKind::ArrayFromAsyncFulfilled),
            ("__onRejected", BuiltinFunctionKind::ArrayFromAsyncRejected),
        ] {
            let handler = core.promise_reaction_handler_from_value(
                Value::BuiltinFunction(BuiltinFunction::bound_to(kind, holder)),
                "sync protocol test",
            ).unwrap().unwrap();
            core.array_from_async_set(holder, name, Value::Int(i64::from(handler.0))).unwrap();
        }
        core.array_from_async_set_source(holder, FromAsyncSource::SyncProtocol).unwrap();
        holder
    }

    #[test]
    fn capture_preserves_original_iterator_and_reads_next_once() {
        let (mut core, module, state) = fixture(r#"
            const state = { reads: 0 };
            state.iterator = { get next() { state.reads++; return function () { return {done:true}; }; } };
            state;
        "#);
        let original = prop(&core, state, "iterator");
        let FromAsyncSyncIterator::Protocol { iterator, next } =
            core.array_from_async_capture_sync(&module, original.clone()).unwrap()
        else { panic!("explicit protocol record required"); };
        assert_eq!(iterator, original);
        assert!(next.is_callable());
        assert_eq!(prop(&core, state, "reads"), Value::Int(1));
    }

    #[test]
    fn pending_close_value_keeps_original_reason_and_await_phase() {
        let (mut core, module, state) = fixture(r#"
            const state = { closes: 0, reason: {} };
            state.pending = new Promise(function () {});
            state.iterator = { return() { state.closes++; return {done:true,value:state.pending}; } };
            state;
        "#);
        let iterator = prop(&core, state, "iterator");
        let original = prop(&core, state, "reason");
        let holder = holder(&mut core, iterator);
        core.array_from_async_keep_close_reason(holder, original.clone(), &Label::Secret).unwrap();
        core.array_from_async_sync_protocol_close(&module, holder, &Label::Secret).unwrap();
        let phase = core.array_from_async_index(holder, "__await").unwrap() as usize;
        assert_eq!(FROM_ASYNC_AWAITS[phase], FromAsyncAwait::SyncCloseValue);
        assert_eq!(prop(&core, holder, "__error"), original);
        assert_eq!(prop(&core, state, "closes"), Value::Int(1));
        let promise = core.array_from_async_promise(holder).unwrap();
        assert!(matches!(core.promise_store.get(promise).unwrap().state, PromiseState::Pending));
        assert_eq!(core.runtime_property_label(holder, &InterpreterCore::from_async_sync_key("__error")), Label::Secret);
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn close_value_rejection_queues_outer_await_without_reentering_return() {
        let (mut core, module, state) = fixture("({iterator:{},reason:undefined});");
        let iterator = prop(&core, state, "iterator");
        let holder = holder(&mut core, iterator);
        core.array_from_async_keep_close_reason(holder, Value::Undefined, &Label::Secret).unwrap();
        core.array_from_async_sync_close_settled(&module, holder, &Label::Public).unwrap();
        let phase = core.array_from_async_index(holder, "__await").unwrap() as usize;
        assert_eq!(FROM_ASYNC_AWAITS[phase], FromAsyncAwait::Close);
        assert_eq!(prop(&core, holder, "__error"), Value::Undefined);
        assert_eq!(core.runtime_property_label(holder, &InterpreterCore::from_async_sync_key("__error")), Label::Secret);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn memory_refusal_precedes_cleanup_and_remains_a_host_error() {
        let (mut core, module, state) = fixture(r#"
            const state={closes:0};
            state.iterator={return(){state.closes++;return {};}};
            state;
        "#);
        let iterator = prop(&core, state, "iterator");
        let holder = holder(&mut core, iterator);
        core.array_from_async_keep_close_reason(holder, Value::Bool(false), &Label::Public).unwrap();
        let limit = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = limit;
        let label = Label::Custom { name: "sync-close-label".repeat(128), level: 3 };
        assert!(matches!(
            core.array_from_async_sync_protocol_close(&module, holder, &label),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(prop(&core, state, "closes"), Value::Int(0));
        assert!(core.pending_exception.is_none());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(core.json_parse_temporary_bytes, 0);
    }
}
