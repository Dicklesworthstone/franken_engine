//! NewPromiseCapability for any constructor, and the Promise combinators'
//! spec algorithm (bd-9vouw.282).
//!
//! A capability is a promise with its resolve and reject functions (ES2020
//! 25.6.1.1). For %Promise% it is an engine promise and its own resolving
//! functions. For any other constructor C it is whatever `new C(executor)`
//! returns, with the functions C passed to the GetCapabilitiesExecutor
//! (25.6.1.5.1), a built-in bound to a holder object that records them, so
//! a constructor that calls the executor itself and returns any object
//! works. A Promise subclass reaches %Promise% through `super(executor)`,
//! and its capability is again an engine promise with its own functions.
//!
//! The combinators (25.6.4.1-3, ES2021 Promise.any) run the spec algorithm
//! when C is not %Promise%, when Get(C, "resolve") is not the intrinsic
//! Promise.resolve, or when %Promise.prototype%.then was replaced:
//! Get(C, "resolve") once, then per element Call(resolve, C, « value ») and
//! Invoke(nextPromise, "then", « onFulfilled, onRejected »), with element
//! functions bound to per-element holders that share the values, the
//! remaining count and the capability. Any other call keeps the native
//! combinator, with its IFC label accumulation and memory accounting.

use super::*;

/// ES2020 25.6.1.1 PromiseCapability Record.
#[derive(Clone, Debug)]
pub(super) struct PromiseCapabilityRecord {
    pub(super) promise: Value,
    pub(super) resolve: Value,
    pub(super) reject: Value,
}

/// What every iteration of a combinator's spec algorithm uses: C, the
/// resolve read from it once, the capability and the shared holder.
struct CombinatorRun {
    constructor: Value,
    promise_resolve: Value,
    capability: PromiseCapabilityRecord,
    shared: ObjectId,
}

// Slots of the engine-owned holder objects (never reachable from guest code).
const CAPABILITY_RESOLVE: &str = "resolve";
const CAPABILITY_REJECT: &str = "reject";
const ELEMENT_INDEX: &str = "index";
const ELEMENT_ALREADY_CALLED: &str = "alreadyCalled";
const ELEMENT_SHARED: &str = "shared";
const SHARED_VALUES: &str = "values";
const SHARED_LENGTH: &str = "length";
const SHARED_REMAINING: &str = "remaining";

impl InterpreterCore {
    /// Whether `value` is this realm's %Promise%.
    pub(super) fn is_intrinsic_promise_constructor(value: &Value) -> bool {
        matches!(value, Value::BuiltinFunction(builtin)
            if Self::materialized_global_prototype_name(builtin) == Some("Promise")
                || (builtin.kind == BuiltinFunctionKind::StandardConstructor
                    && Self::standard_constructor_name(builtin)
                        .is_ok_and(|name| name == "Promise")))
    }

    /// The engine promise of `record` when its resolve and reject are that
    /// promise's own resolving functions (%Promise%, or a subclass that
    /// reached it through `super(executor)`): reactions can settle it
    /// directly.
    pub(super) fn capability_native_promise(
        record: &PromiseCapabilityRecord,
    ) -> Option<crate::promise_model::PromiseHandle> {
        match (&record.promise, &record.resolve, &record.reject) {
            (
                Value::Promise(handle),
                Value::BuiltinFunction(resolve),
                Value::BuiltinFunction(reject),
            ) if resolve.kind == BuiltinFunctionKind::PromiseResolve
                && reject.kind == BuiltinFunctionKind::PromiseReject
                && resolve.bound_object == Some(*handle)
                && reject.bound_object == Some(*handle) =>
            {
                Some(crate::promise_model::PromiseHandle(*handle))
            }
            _ => None,
        }
    }

    /// The `this` of a Promise static: NewPromiseCapability(C) and
    /// PromiseResolve(C, x) need an object (ES2020 25.6.4), so a detached
    /// `const r = Promise.resolve; r(1)` is a TypeError, as in Node.
    pub(super) fn promise_static_this(
        receiver: Option<&Value>,
        name: &str,
    ) -> Result<Value, InterpreterError> {
        match receiver {
            Some(value) if value.is_object_like() => Ok(value.clone()),
            other => Err(InterpreterError::TypeError {
                expected: format!("object receiver for Promise.{name}"),
                got: other.map_or("undefined", Value::type_name).to_string(),
            }),
        }
    }

    /// ES2020 25.6.1.5 NewPromiseCapability(C). `roots` stay reachable
    /// while C runs.
    pub(super) fn new_promise_capability_record(
        &mut self,
        module: &Ir3Module,
        constructor: Value,
        roots: Vec<Value>,
    ) -> Result<PromiseCapabilityRecord, InterpreterError> {
        if Self::is_intrinsic_promise_constructor(&constructor) {
            let promise = self.create_promise()?;
            return Ok(PromiseCapabilityRecord {
                promise: Value::Promise(promise.0),
                resolve: self.make_promise_capability(BuiltinFunctionKind::PromiseResolve, promise),
                reject: self.make_promise_capability(BuiltinFunctionKind::PromiseReject, promise),
            });
        }
        if !self.is_constructible_value(&constructor) {
            return Err(InterpreterError::TypeError {
                expected: "constructor for NewPromiseCapability".to_string(),
                got: constructor.type_name().to_string(),
            });
        }
        let holder = self.alloc_object_with_properties(&[
            (CAPABILITY_RESOLVE, Value::Undefined),
            (CAPABILITY_REJECT, Value::Undefined),
        ])?;
        let executor = Value::BuiltinFunction(BuiltinFunction::bound_to(
            BuiltinFunctionKind::PromiseCapabilityExecutor,
            holder,
        ));
        let mut held = roots;
        held.push(Value::Object(holder));
        let (promise, label) = self.with_gc_nested_request(held, |core| {
            core.invoke_inline_construct_with_labels(
                Some(module),
                constructor,
                vec![executor],
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
        let resolve = self.capability_holder_slot(holder, CAPABILITY_RESOLVE);
        let reject = self.capability_holder_slot(holder, CAPABILITY_REJECT);
        if !resolve.is_callable() || !reject.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable resolve and reject from a promise capability executor"
                    .to_string(),
                got: format!("{}, {}", resolve.type_name(), reject.type_name()),
            });
        }
        Ok(PromiseCapabilityRecord {
            promise,
            resolve,
            reject,
        })
    }

    fn capability_holder_slot(&self, holder: ObjectId, key: &str) -> Value {
        self.heap
            .get(holder.0 as usize)
            .and_then(|object| {
                object.own_runtime_property_value(&RuntimePropertyKey::String(JsString::from(key)))
            })
            .unwrap_or(Value::Undefined)
    }

    /// ES2020 25.6.1.5.1 GetCapabilitiesExecutor Functions: records resolve
    /// and reject once; a second call after either was set to something
    /// other than undefined is a TypeError.
    pub(super) fn promise_capability_executor_call(
        &mut self,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let Some(holder) = builtin.bound_object.map(ObjectId) else {
            return Ok(Value::Undefined);
        };
        for key in [CAPABILITY_RESOLVE, CAPABILITY_REJECT] {
            if !matches!(self.capability_holder_slot(holder, key), Value::Undefined) {
                return Err(InterpreterError::TypeError {
                    expected: "a promise capability executor whose resolve and reject are unset"
                        .to_string(),
                    got: format!("{key} already set"),
                });
            }
        }
        let resolve = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let reject = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        self.set_object_property(holder, CAPABILITY_RESOLVE.to_string(), resolve)?;
        self.set_object_property(holder, CAPABILITY_REJECT.to_string(), reject)?;
        Ok(Value::Undefined)
    }

    /// ES2020 25.6.4.5.1 PromiseResolve(C, x) for a C other than %Promise%:
    /// a promise whose `constructor` is C is returned as is; anything else
    /// resolves a new capability of C.
    pub(super) fn promise_resolve_with_constructor(
        &mut self,
        module: &Ir3Module,
        constructor: Value,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        if matches!(value, Value::Promise(_)) {
            let value_constructor = self.get_v(
                module,
                &value,
                &RuntimePropertyKey::String(JsString::from("constructor")),
            )?;
            if Self::values_equal(&value_constructor, &constructor) {
                return Ok(value);
            }
        }
        let capability =
            self.new_promise_capability_record(module, constructor, vec![value.clone()])?;
        self.invoke_inline_method_call(
            Some(module),
            capability.resolve.clone(),
            Value::Undefined,
            vec![value],
        )?;
        Ok(capability.promise)
    }

    /// Promise.reject(r) for a C other than %Promise% (ES2020 25.6.4.4).
    pub(super) fn promise_reject_with_constructor(
        &mut self,
        module: &Ir3Module,
        constructor: Value,
        reason: Value,
    ) -> Result<Value, InterpreterError> {
        let capability =
            self.new_promise_capability_record(module, constructor, vec![reason.clone()])?;
        self.invoke_inline_method_call(
            Some(module),
            capability.reject.clone(),
            Value::Undefined,
            vec![reason],
        )?;
        Ok(capability.promise)
    }

    /// A guest-visible error as the value a `catch` would see, with its
    /// label; a resource refusal or host fault stays an interpreter error.
    pub(super) fn catchable_thrown_value(
        &mut self,
        error: InterpreterError,
    ) -> Result<(Value, Label), InterpreterError> {
        if matches!(error, InterpreterError::UncaughtException { .. }) {
            return self.take_pending_exception_slot().ok_or(error);
        }
        if Self::js_catchable_error_name(&error).is_some() {
            return Ok((self.native_error_to_thrown_value(&error)?, Label::Public));
        }
        Err(error)
    }

    /// IfAbruptRejectPromise: a catchable error rejects the capability's
    /// promise, which is returned.
    fn reject_capability_with_error(
        &mut self,
        module: &Ir3Module,
        capability: &PromiseCapabilityRecord,
        error: InterpreterError,
    ) -> Result<Value, InterpreterError> {
        let (thrown, _) = self.catchable_thrown_value(error)?;
        self.invoke_inline_method_call(
            Some(module),
            capability.reject.clone(),
            Value::Undefined,
            vec![thrown],
        )?;
        Ok(capability.promise.clone())
    }

    /// Whether %Promise.prototype%.then is still the intrinsic one (an
    /// accessor or any other value is a replacement). Reads no guest code.
    fn promise_prototype_then_is_intrinsic(&self) -> bool {
        let Some(&prototype) = self.builtin_prototypes.get("Promise") else {
            return true;
        };
        match self.heap.get(prototype.0 as usize).and_then(|object| {
            object.own_runtime_property_value(&RuntimePropertyKey::String(JsString::from("then")))
        }) {
            None => !self.virtual_own_property_deleted(
                prototype,
                &RuntimePropertyKey::String(JsString::from("then")),
            ),
            Some(Value::BuiltinFunction(builtin)) => {
                builtin.kind == BuiltinFunctionKind::PromiseThen
            }
            Some(_) => false,
        }
    }

    /// Promise.all / allSettled / any / race with `this` (ES2020 25.6.4.1-3,
    /// ES2021 27.2.4.3). `capability_tag` is the native combinator's.
    pub(super) fn promise_combinator_call(
        &mut self,
        module: &Ir3Module,
        kind: PromiseCombinatorKind,
        capability_tag: &str,
        name: &str,
        args: RegRange,
        receiver: Option<&Value>,
    ) -> Result<Value, InterpreterError> {
        let constructor = Self::promise_static_this(receiver, name)?;
        let iterable = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        // Guest code (C, its `resolve` getter, iterators, `then`) runs while
        // native locals hold values: no collection until this returns.
        self.gc_nested_request = None;
        // Step 2: NewPromiseCapability(C), observable only for a C other
        // than %Promise%, before step 3's GetPromiseResolve(C).
        let intrinsic = Self::is_intrinsic_promise_constructor(&constructor);
        let capability = if intrinsic {
            None
        } else {
            Some(self.new_promise_capability_record(
                module,
                constructor.clone(),
                vec![iterable.clone()],
            )?)
        };
        let resolve_key = RuntimePropertyKey::String(JsString::from("resolve"));
        let promise_resolve = self.get_v(module, &constructor, &resolve_key);
        if intrinsic
            && matches!(&promise_resolve, Ok(Value::BuiltinFunction(builtin))
                if builtin.kind == BuiltinFunctionKind::PromiseResolve
                    && builtin.bound_object.is_none())
            && self.promise_prototype_then_is_intrinsic()
        {
            return self.dispatch_promise_hostcall(capability_tag, args, Some(module));
        }
        let capability = match capability {
            Some(capability) => capability,
            None => self.new_promise_capability_record(
                module,
                constructor.clone(),
                vec![iterable.clone()],
            )?,
        };
        let promise_resolve = match promise_resolve {
            Ok(value) if value.is_callable() => value,
            Ok(value) => {
                let error = InterpreterError::TypeError {
                    expected: format!("callable resolve of the Promise.{name} constructor"),
                    got: value.type_name().to_string(),
                };
                return self.reject_capability_with_error(module, &capability, error);
            }
            Err(error) => return self.reject_capability_with_error(module, &capability, error),
        };
        let iterator = match self.init_for_of_iterator(Some(module), iterable) {
            Ok(iterator) => iterator,
            Err(error) => return self.reject_capability_with_error(module, &capability, error),
        };
        let shared = self.alloc_object_with_properties(&[
            (SHARED_LENGTH, Value::Int(0)),
            (SHARED_REMAINING, Value::Int(1)),
            (CAPABILITY_RESOLVE, capability.resolve.clone()),
            (CAPABILITY_REJECT, capability.reject.clone()),
        ])?;
        let values = self.alloc_object_with_prototype(None)?;
        self.set_object_property(shared, SHARED_VALUES.to_string(), Value::Object(values))?;
        let run = CombinatorRun {
            constructor,
            promise_resolve,
            capability,
            shared,
        };
        let mut index = 0_i64;
        loop {
            // An error of the iterator itself leaves it done: no close.
            let value = match self.advance_for_of_iterator(Some(module), iterator.clone()) {
                Ok(Some(value)) => value,
                Ok(None) => break,
                Err(error) => {
                    return self.reject_capability_with_error(module, &run.capability, error);
                }
            };
            if let Err(error) = self.promise_combinator_step(module, kind, &run, index, value) {
                // IteratorClose with a throw completion: the original error
                // wins over one from `return`.
                if let Err(close_error) =
                    self.close_iterator(module, iterator.clone(), IteratorCloseReason::Throw)
                {
                    self.catchable_thrown_value(close_error)?;
                }
                return self.reject_capability_with_error(module, &run.capability, error);
            }
            index += 1;
        }
        if kind != PromiseCombinatorKind::Race
            && let Err(error) = self.promise_combinator_element_done(module, kind, run.shared)
        {
            return self.reject_capability_with_error(module, &run.capability, error);
        }
        Ok(run.capability.promise)
    }

    /// One iteration of PerformPromiseAll / AllSettled / Any / Race: the
    /// values slot, Call(promiseResolve, C, « value »), the element
    /// functions, and Invoke(nextPromise, "then", « onFulfilled, onRejected »).
    fn promise_combinator_step(
        &mut self,
        module: &Ir3Module,
        kind: PromiseCombinatorKind,
        run: &CombinatorRun,
        index: i64,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let CombinatorRun {
            constructor,
            promise_resolve,
            capability,
            shared,
        } = run;
        let shared = *shared;
        if kind != PromiseCombinatorKind::Race {
            let Value::Object(values) = self.capability_holder_slot(shared, SHARED_VALUES) else {
                return Err(InterpreterError::TypeError {
                    expected: "combinator values list".to_string(),
                    got: "missing".to_string(),
                });
            };
            self.set_object_property(values, index.to_string(), Value::Undefined)?;
            self.set_object_property(shared, SHARED_LENGTH.to_string(), Value::Int(index + 1))?;
        }
        let next_promise = self.invoke_inline_method_call(
            Some(module),
            promise_resolve.clone(),
            constructor.clone(),
            vec![value],
        )?;
        let element = |element_kind: BuiltinFunctionKind, holder: ObjectId| {
            Value::BuiltinFunction(BuiltinFunction::bound_to(element_kind, holder))
        };
        let (on_fulfilled, on_rejected) = if kind == PromiseCombinatorKind::Race {
            (capability.resolve.clone(), capability.reject.clone())
        } else {
            let holder = self.alloc_object_with_properties(&[
                (ELEMENT_INDEX, Value::Int(index)),
                (ELEMENT_ALREADY_CALLED, Value::Bool(false)),
                (ELEMENT_SHARED, Value::Object(shared)),
            ])?;
            let remaining = self.combinator_remaining(shared)?;
            self.set_object_property(
                shared,
                SHARED_REMAINING.to_string(),
                Value::Int(remaining + 1),
            )?;
            match kind {
                PromiseCombinatorKind::All => (
                    element(BuiltinFunctionKind::PromiseAllResolveElement, holder),
                    capability.reject.clone(),
                ),
                PromiseCombinatorKind::AllSettled => (
                    element(BuiltinFunctionKind::PromiseAllSettledResolveElement, holder),
                    element(BuiltinFunctionKind::PromiseAllSettledRejectElement, holder),
                ),
                _ => (
                    capability.resolve.clone(),
                    element(BuiltinFunctionKind::PromiseAnyRejectElement, holder),
                ),
            }
        };
        let then = self.get_v(
            module,
            &next_promise,
            &RuntimePropertyKey::String(JsString::from("then")),
        )?;
        self.invoke_inline_method_call(
            Some(module),
            then,
            next_promise,
            vec![on_fulfilled, on_rejected],
        )?;
        Ok(())
    }

    fn combinator_remaining(&self, shared: ObjectId) -> Result<i64, InterpreterError> {
        match self.capability_holder_slot(shared, SHARED_REMAINING) {
            Value::Int(remaining) => Ok(remaining),
            other => Err(InterpreterError::TypeError {
                expected: "combinator remaining count".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// remainingElementsCount - 1; at zero, the capability settles with the
    /// gathered values (all, allSettled) or an AggregateError of the
    /// reasons (any).
    fn promise_combinator_element_done(
        &mut self,
        module: &Ir3Module,
        kind: PromiseCombinatorKind,
        shared: ObjectId,
    ) -> Result<(), InterpreterError> {
        let remaining = self.combinator_remaining(shared)? - 1;
        self.set_object_property(shared, SHARED_REMAINING.to_string(), Value::Int(remaining))?;
        if remaining != 0 {
            return Ok(());
        }
        let Value::Object(values) = self.capability_holder_slot(shared, SHARED_VALUES) else {
            return Ok(());
        };
        let length = match self.capability_holder_slot(shared, SHARED_LENGTH) {
            Value::Int(length) => length,
            _ => 0,
        };
        let gathered: Vec<Value> = (0..length)
            .map(|index| self.capability_holder_slot(values, &index.to_string()))
            .collect();
        if kind == PromiseCombinatorKind::Any {
            let errors = gathered.iter().map(Self::value_to_js_value).collect();
            let error = self.build_aggregate_error(errors)?;
            let error = self.js_value_to_value(&error);
            let reject = self.capability_holder_slot(shared, CAPABILITY_REJECT);
            self.invoke_inline_method_call(Some(module), reject, Value::Undefined, vec![error])?;
        } else {
            let array = self.alloc_array_from_values(&gathered)?;
            let resolve = self.capability_holder_slot(shared, CAPABILITY_RESOLVE);
            self.invoke_inline_method_call(
                Some(module),
                resolve,
                Value::Undefined,
                vec![Value::Object(array)],
            )?;
        }
        Ok(())
    }

    /// Promise.all Resolve Element, Promise.allSettled Resolve / Reject
    /// Element and Promise.any Reject Element Functions (ES2020 25.6.4.1.2,
    /// 25.6.4.2.2-3, ES2021 27.2.4.3.2): the first call of an element's
    /// pair records its value (a `{ status, value | reason }` object for
    /// allSettled) and counts the element as done; later calls do nothing.
    pub(super) fn promise_combinator_element_call(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let Some(holder) = builtin.bound_object.map(ObjectId) else {
            return Ok(Value::Undefined);
        };
        if matches!(
            self.capability_holder_slot(holder, ELEMENT_ALREADY_CALLED),
            Value::Bool(true)
        ) {
            return Ok(Value::Undefined);
        }
        self.set_object_property(
            holder,
            ELEMENT_ALREADY_CALLED.to_string(),
            Value::Bool(true),
        )?;
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let (Value::Int(index), Value::Object(shared)) = (
            self.capability_holder_slot(holder, ELEMENT_INDEX),
            self.capability_holder_slot(holder, ELEMENT_SHARED),
        ) else {
            return Ok(Value::Undefined);
        };
        let (kind, element) = match builtin.kind {
            BuiltinFunctionKind::PromiseAllSettledResolveElement => {
                let entry = self.alloc_object_with_properties(&[
                    ("status", Value::str("fulfilled")),
                    ("value", value),
                ])?;
                (PromiseCombinatorKind::AllSettled, Value::Object(entry))
            }
            BuiltinFunctionKind::PromiseAllSettledRejectElement => {
                let entry = self.alloc_object_with_properties(&[
                    ("status", Value::str("rejected")),
                    ("reason", value),
                ])?;
                (PromiseCombinatorKind::AllSettled, Value::Object(entry))
            }
            BuiltinFunctionKind::PromiseAnyRejectElement => (PromiseCombinatorKind::Any, value),
            _ => (PromiseCombinatorKind::All, value),
        };
        if let Value::Object(values) = self.capability_holder_slot(shared, SHARED_VALUES) {
            self.set_object_property(values, index.to_string(), element)?;
        }
        self.promise_combinator_element_done(module, kind, shared)?;
        Ok(Value::Undefined)
    }
}
