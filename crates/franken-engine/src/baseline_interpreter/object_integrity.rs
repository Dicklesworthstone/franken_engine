//! Object identity operations and the private [[Extensible]] slot.
//!
//! Proxy invariants are checked against the target AFTER the trap runs. A
//! successful trap is not permission to fabricate a new target state. Ordinary
//! prototype-cycle checks inspect private links and stop at exotic boundaries;
//! they must not invoke a proposed prototype's getPrototypeOf trap.

use super::*;

/// Annex B.2.2.2-5 (bd-9vouw.172).
pub(super) const LEGACY_ACCESSOR_METHODS: [&str; 4] = [
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
];

#[derive(Clone, Copy)]
pub(super) enum ObjectIntegrityOperation {
    GetPrototype,
    SetPrototype,
    IsExtensible,
    PreventExtensions,
}

impl InterpreterCore {
    /// Annex B.2.2.2-5: `o.__defineGetter__(P, getter)` (and the setter
    /// form) is `Object.defineProperty(o, P, { get: getter, enumerable:
    /// true, configurable: true })` after a callable check;
    /// `o.__lookupGetter__(P)` (and the setter form) returns the getter of the
    /// first own property named P up the prototype chain, undefined for a
    /// data property or none. `this` is ToObject'd: a primitive acts on a
    /// fresh wrapper, undefined and null throw.
    pub(super) fn legacy_accessor_method(
        &mut self,
        module: &Ir3Module,
        method: &str,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if matches!(receiver, Value::Undefined | Value::Null) {
            return Err(Self::integrity_type_error(
                "object-coercible this",
                receiver.type_name(),
            ));
        }
        let object_id = match self.own_property_holder(Some(module), &receiver, true)? {
            Some(id) => id,
            None => self.alloc_primitive_wrapper(receiver)?,
        };
        let key_value = self.arg_or_undefined(args, 0)?;
        let key_value = self.property_key_primitive(module, key_value)?;
        let key = self.executable_property_key_from_value(&key_value);
        let getter = method.ends_with("Getter__");
        if method.starts_with("__define") {
            let function = self.arg_or_undefined(args, 1)?;
            if !function.is_callable() {
                return Err(InterpreterError::TypeError {
                    expected: format!("callable argument for Object.prototype.{method}"),
                    got: function.type_name().to_string(),
                });
            }
            let fields = PropertyDescriptorFields {
                value: None,
                writable: None,
                get: getter.then(|| function.clone()),
                set: (!getter).then_some(function),
                enumerable: Some(true),
                configurable: Some(true),
            };
            if !self.proxy_aware_define_own_property(Some(module), object_id, key, fields, 0)? {
                return Err(InterpreterError::TypeError {
                    expected: DEFINE_PROPERTY_REJECTED.to_string(),
                    got: format!("Object.prototype.{method} on a non-configurable property"),
                });
            }
            let label = self.join_arg_range_with_object_mutation_label(args)?;
            self.join_object_mutation_label(object_id, &label)?;
            return Ok(Value::Undefined);
        }
        let field = RuntimePropertyKey::String((if getter { "get" } else { "set" }).into());
        let mut current = Some(object_id);
        let mut depth = 0u32;
        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                break;
            }
            self.join_pending_hostcall_stream_label(id)?;
            let descriptor = self.proxy_aware_own_property_descriptor(Some(module), id, &key, 0)?;
            if let Value::Object(descriptor_id) = descriptor {
                return self.proxy_aware_get_runtime_property(
                    Some(module),
                    descriptor_id,
                    &field,
                    descriptor,
                    0,
                );
            }
            current = match self.object_get_prototype(Some(module), id, 0)? {
                Value::Object(parent) => Some(parent),
                _ => None,
            };
            depth += 1;
        }
        Ok(Value::Undefined)
    }

    /// Use the same private property object as ordinary builtin member access.
    /// A callable value is not a primitive, but accepting it must not invent
    /// a second object whose prototype/extensibility diverges from its storage.
    pub(super) fn reflection_target_object(
        &self,
        target: &Value,
    ) -> Result<ObjectId, InterpreterError> {
        self.iterator_carrier_backing_id(target, "object target")?
            .ok_or_else(|| {
                Self::integrity_type_error("object with property storage", target.type_name())
            })
    }

    pub(super) fn object_integrity_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
        operation: ObjectIntegrityOperation,
        reflect: bool,
    ) -> Result<Value, InterpreterError> {
        let target = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let proposed = if matches!(operation, ObjectIntegrityOperation::SetPrototype) {
            self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined)
        } else {
            Value::Undefined
        };
        let context = self.join_arg_range_label(args)?;
        let saved_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        let scratch = saved_bytes
            .saturating_add(Self::estimate_value_bytes(&target))
            .saturating_add(Self::estimate_value_bytes(&proposed));
        self.json_reserve_temporary(scratch)?;
        if let Err(error) =
            self.apply_memory_component_delta(saved_bytes, Self::estimate_label_bytes(&context))
        {
            self.json_release_temporary(scratch);
            return Err(error);
        }
        let previous = self.active_inline_callback_context_label.replace(context);
        let mut outcome = (|| {
            self.json_charge_work()?;
            // These walks perform no guest Get and do not test Proxy revocation.
            // The internal operation retains its required validation order.
            self.json_observe_reachable_value(&target)?;
            self.json_observe_reachable_value(&proposed)?;
            // A function value without ordinary property storage: its
            // [[Prototype]] lives on its own-property backing object.
            if target.is_callable()
                && self
                    .iterator_carrier_backing_id(&target, "object target")?
                    .is_none()
            {
                return match operation {
                    ObjectIntegrityOperation::GetPrototype => {
                        self.function_value_prototype(module, &target)
                    }
                    ObjectIntegrityOperation::SetPrototype => {
                        let accepted =
                            self.set_function_value_prototype(module, &target, &proposed)?;
                        if reflect {
                            Ok(Value::Bool(accepted))
                        } else if accepted {
                            Ok(target.clone())
                        } else {
                            Err(Self::integrity_type_error(
                                "permitted prototype change",
                                "rejected prototype",
                            ))
                        }
                    }
                    // [[Extensible]] is its backing object's (bd-9vouw.149).
                    ObjectIntegrityOperation::IsExtensible => {
                        Ok(Value::Bool(self.backing_is_extensible(module, &target)?))
                    }
                    ObjectIntegrityOperation::PreventExtensions => {
                        self.prevent_backing_extensions(module, &target, reflect)
                    }
                };
            }
            // A promise, generator, async generator or iterator value has no
            // ordinary property storage; it inherits from its intrinsic
            // prototype (%Promise.prototype%, bd-9vouw.34; %GeneratorPrototype%,
            // %AsyncGeneratorPrototype%, %ArrayIteratorPrototype%), which
            // core-js and regenerator-runtime read at load
            // (`getProto(getProto([].keys()))`). Its [[Extensible]] is its
            // backing object's, true until one exists (bd-9vouw.149).
            if let Some(name) = self.exotic_intrinsic_prototype_name(&target) {
                match operation {
                    ObjectIntegrityOperation::GetPrototype => {
                        // bd-9vouw.137: a Promise subclass instance reports
                        // the prototype its backing object records; a
                        // generator its function's `prototype` (bd-9vouw.120).
                        if let Some(module) = module
                            && let Some(prototype) =
                                self.exotic_prototype_override(module, &target)?
                        {
                            return Ok(Value::Object(prototype));
                        }
                        return Ok(Value::Object(self.ensure_builtin_prototype(name)?));
                    }
                    ObjectIntegrityOperation::IsExtensible => {
                        return Ok(Value::Bool(self.backing_is_extensible(module, &target)?));
                    }
                    ObjectIntegrityOperation::PreventExtensions => {
                        return self.prevent_backing_extensions(module, &target, reflect);
                    }
                    ObjectIntegrityOperation::SetPrototype => {}
                }
            }
            let target_id = match &target {
                value if value.is_object_like() => Some(self.reflection_target_object(value)?),
                value if reflect => {
                    return Err(Self::integrity_type_error(
                        "object target",
                        value.type_name(),
                    ));
                }
                _ => None,
            };
            match operation {
                ObjectIntegrityOperation::GetPrototype => {
                    if let Some(id) = target_id {
                        return self.object_get_prototype(module, id, 0);
                    }
                    // ToObject of a primitive has this realm's intrinsic
                    // prototype. No guest-visible wrapper allocation is needed.
                    let name = match target {
                        Value::Str(_) => "String",
                        Value::Int(_) | Value::Float(_) => "Number",
                        Value::Bool(_) => "Boolean",
                        Value::BigInt(_) => "BigInt",
                        Value::Symbol(_) => "Symbol",
                        _ => {
                            return Err(Self::integrity_type_error(
                                "object-coercible target",
                                target.type_name(),
                            ));
                        }
                    };
                    Ok(Value::Object(self.ensure_builtin_prototype(name)?))
                }
                ObjectIntegrityOperation::SetPrototype => {
                    // Object.setPrototypeOf requires coercibility before
                    // validating V, but does not box a non-nullish primitive.
                    if matches!(target, Value::Undefined | Value::Null) {
                        return Err(Self::integrity_type_error(
                            "object-coercible target",
                            target.type_name(),
                        ));
                    }
                    let prototype = Self::integrity_prototype(&proposed)?;
                    let Some(id) = target_id else {
                        return Ok(target);
                    };
                    let success = self.object_set_prototype(module, id, prototype, 0)?;
                    if reflect {
                        Ok(Value::Bool(success))
                    } else if success {
                        Ok(target)
                    } else {
                        Err(Self::integrity_type_error(
                            "permitted prototype change",
                            "rejected prototype",
                        ))
                    }
                }
                ObjectIntegrityOperation::IsExtensible => Ok(Value::Bool(match target_id {
                    Some(id) => self.object_is_extensible(module, id, 0)?,
                    None => false,
                })),
                ObjectIntegrityOperation::PreventExtensions => {
                    let Some(id) = target_id else {
                        return Ok(target);
                    };
                    let success = self.object_prevent_extensions(module, id, 0)?;
                    if reflect {
                        Ok(Value::Bool(success))
                    } else if success {
                        Ok(target)
                    } else {
                        Err(Self::integrity_type_error(
                            "successful preventExtensions",
                            "falsy Proxy trap result",
                        ))
                    }
                }
            }
        })();
        if let Err(error) = self.observe_scoped_callback_result() {
            outcome = Err(error);
        }
        if let Err(error) = &outcome
            && Self::js_catchable_error_name(error).is_some()
        {
            outcome = match self.scoped_native_error(error) {
                Ok(error) | Err(error) => Err(error),
            };
        }
        let context = self
            .active_inline_callback_context_label
            .take()
            .expect("nested identity operations restore their caller's context");
        if outcome.is_ok() {
            if let Err(error) = self
                .clone_dominant_label_with_temporary_budget(
                    &context,
                    self.pending_hostcall_result_label
                        .as_ref()
                        .unwrap_or(&Label::Public),
                    0,
                )
                .and_then(|label| self.replace_pending_hostcall_result_label(Some(label)))
            {
                outcome = Err(error);
            }
        } else if matches!(outcome, Err(InterpreterError::UncaughtException { .. }))
            && let Err(error) = self.join_pending_exception_label(&context)
        {
            outcome = Err(error);
        }
        self.active_inline_callback_context_label = previous;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_label_bytes(&context))
            .saturating_add(saved_bytes);
        self.json_release_temporary(scratch);
        outcome
    }

    /// The record of a Proxy (an object one or a callable one) whose
    /// integrity operations run through its traps; `None` for anything else.
    pub(super) fn integrity_proxy_id(
        &self,
        value: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        Ok(match value {
            Value::Object(id) if self.active_proxy_record(*id)?.is_some() => Some(*id),
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::CallableProxy =>
            {
                Some(Self::callable_proxy_record_id(builtin)?)
            }
            _ => None,
        })
    }

    /// ES2020 7.3.14 SetIntegrityLevel of a Proxy: [[PreventExtensions]],
    /// then DefinePropertyOrThrow of every key [[OwnPropertyKeys]] lists, all
    /// through its traps (bd-9vouw.149). `false` when preventExtensions is
    /// refused.
    pub(super) fn proxy_set_integrity_level(
        &mut self,
        module: Option<&Ir3Module>,
        proxy_id: ObjectId,
        frozen: bool,
    ) -> Result<bool, InterpreterError> {
        if !self.object_prevent_extensions(module, proxy_id, 0)? {
            return Ok(false);
        }
        for key_value in self.proxy_aware_own_property_keys(module, proxy_id, 0)? {
            let key = self.executable_property_key_from_value(&key_value);
            let mut fields = PropertyDescriptorFields {
                configurable: Some(false),
                ..PropertyDescriptorFields::default()
            };
            if frozen {
                match self.proxy_target_descriptor_fields(module, proxy_id, &key, 0)? {
                    None => continue,
                    Some(current) if current.is_accessor() => {}
                    Some(_) => fields.writable = Some(false),
                }
            }
            if !self.proxy_aware_define_own_property(module, proxy_id, key, fields, 0)? {
                return Err(InterpreterError::TypeError {
                    expected: DEFINE_PROPERTY_REJECTED.to_string(),
                    got: "a defineProperty trap that refused the integrity level".to_string(),
                });
            }
        }
        Ok(true)
    }

    /// ES2020 7.3.15 TestIntegrityLevel of a Proxy, through its
    /// isExtensible, ownKeys and getOwnPropertyDescriptor traps.
    pub(super) fn proxy_test_integrity_level(
        &mut self,
        module: Option<&Ir3Module>,
        proxy_id: ObjectId,
        frozen: bool,
    ) -> Result<bool, InterpreterError> {
        if self.object_is_extensible(module, proxy_id, 0)? {
            return Ok(false);
        }
        for key_value in self.proxy_aware_own_property_keys(module, proxy_id, 0)? {
            let key = self.executable_property_key_from_value(&key_value);
            if let Some(current) = self.proxy_target_descriptor_fields(module, proxy_id, &key, 0)? {
                if current.configurable == Some(true)
                    || (frozen && current.is_data() && current.writable == Some(true))
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// [[IsExtensible]] of a function, promise, generator or iterator value:
    /// its backing object's, and true before one exists (bd-9vouw.149).
    fn backing_is_extensible(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
    ) -> Result<bool, InterpreterError> {
        match self.own_property_holder(module, value, false)? {
            Some(backing) => self.object_is_extensible(module, backing, 0),
            None => Ok(true),
        }
    }

    /// [[PreventExtensions]] of a function, promise, generator or iterator
    /// value, on its backing object (created for it): Reflect's result is
    /// `true`, Object.preventExtensions returns the value.
    fn prevent_backing_extensions(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
        reflect: bool,
    ) -> Result<Value, InterpreterError> {
        let Some(backing) = self.own_property_holder(module, value, true)? else {
            return Err(Self::integrity_type_error(
                "object with property storage",
                value.type_name(),
            ));
        };
        let success = self.object_prevent_extensions(module, backing, 0)?;
        Ok(if reflect {
            Value::Bool(success)
        } else {
            value.clone()
        })
    }

    /// [[GetPrototypeOf]] of a function value: a derived class's parent, the
    /// link recorded by `Object.setPrototypeOf`, else `Function.prototype`.
    pub(super) fn function_value_prototype(
        &mut self,
        module: Option<&Ir3Module>,
        function: &Value,
    ) -> Result<Value, InterpreterError> {
        if let Some(module) = module {
            let is_constructor_candidate = match function {
                Value::Function(_) => true,
                Value::Closure(id) => !self.closure_method_metadata.contains_key(id),
                _ => false,
            };
            if is_constructor_candidate
                && let Ok((true, _, parent, _)) =
                    self.derived_constructor_metadata(module, function)
            {
                return Ok(parent);
            }
            if let Some(backing) = self.function_own_property_object(module, function)?
                && let Some(prototype) = self
                    .heap
                    .get(backing.0 as usize)
                    .and_then(|object| object.prototype)
            {
                return Ok(self
                    .function_value_for_backing(module, prototype)
                    .unwrap_or(Value::Object(prototype)));
            }
        }
        // ES2020 22.2.5: every concrete typed array constructor's
        // [[Prototype]] is %TypedArray%.
        if let Value::BuiltinFunction(builtin) = function
            && builtin.kind == BuiltinFunctionKind::StandardConstructor
            && Self::standard_constructor_name(builtin)
                .ok()
                .and_then(TypedArrayKind::from_type_name)
                .is_some()
        {
            return Ok(Value::BuiltinFunction(
                BuiltinFunction::standard_constructor(TYPED_ARRAY_INTRINSIC),
            ));
        }
        // ES2020 25.2.2, 25.7.2; ES2018 25.3.2: %GeneratorFunction%,
        // %AsyncFunction% and %AsyncGeneratorFunction% inherit from %Function%.
        if let Value::BuiltinFunction(builtin) = function
            && builtin.kind == BuiltinFunctionKind::StandardConstructor
            && FUNCTION_KIND_INTRINSICS.contains(&&*builtin.module_specifier)
        {
            return Ok(Value::BuiltinFunction(
                BuiltinFunction::function_constructor(),
            ));
        }
        Ok(Value::Object(self.ensure_builtin_prototype(
            Self::function_intrinsic_prototype_name(function).unwrap_or("Function"),
        )?))
    }

    /// [[SetPrototypeOf]] of a user function value (`Object.setPrototypeOf(D,
    /// B)` in compiled `extends`). The link lives on the backing objects, so
    /// `D`'s own-property lookups inherit `B`'s statics. A builtin parent
    /// (`Error`) has no backing object to link to; the change is accepted but
    /// only `Function.prototype` remains observable, a documented gap.
    pub(super) fn set_function_value_prototype(
        &mut self,
        module: Option<&Ir3Module>,
        function: &Value,
        proposed: &Value,
    ) -> Result<bool, InterpreterError> {
        let Some(module) = module else {
            return Ok(false);
        };
        let Some(backing) = self.ensure_function_own_property_object(module, function)? else {
            return Ok(false);
        };
        let prototype = match proposed {
            Value::Null => None,
            Value::Object(id) => Some(*id),
            callable if callable.is_callable() => {
                match self.ensure_function_own_property_object(module, callable)? {
                    Some(parent_backing) => Some(parent_backing),
                    None => return Ok(true),
                }
            }
            other => {
                return Err(Self::integrity_type_error(
                    "object or null prototype",
                    other.type_name(),
                ));
            }
        };
        let mut current = prototype;
        let mut depth = 0u32;
        while let Some(candidate) = current {
            if candidate == backing {
                return Ok(false);
            }
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                return Ok(false);
            }
            current = self
                .heap
                .get(candidate.0 as usize)
                .and_then(|object| object.prototype);
            depth += 1;
        }
        self.store_prototype_link(backing, prototype);
        self.gc_write_barrier(backing);
        Ok(true)
    }

    fn integrity_type_error(expected: &str, got: &str) -> InterpreterError {
        InterpreterError::TypeError {
            expected: expected.into(),
            got: got.into(),
        }
    }

    fn integrity_prototype(value: &Value) -> Result<Option<ObjectId>, InterpreterError> {
        match value {
            Value::Object(id) => Ok(Some(*id)),
            Value::Null => Ok(None),
            other => Err(Self::integrity_type_error(
                "object or null prototype",
                other.type_name(),
            )),
        }
    }

    fn integrity_step(&mut self, id: ObjectId, depth: u32) -> Result<(), InterpreterError> {
        self.json_charge_work()?;
        if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
            return Err(InterpreterError::StackOverflow {
                depth: depth as usize,
                max: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
            });
        }
        self.heap
            .get(id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
        self.observe_scoped_callback_result()?;
        if self.active_inline_callback_context_label.is_some()
            && let Some(label) = self.object_mutation_labels.get(&id)
        {
            self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
            let label = label.clone();
            self.json_observe_label(label)?;
        }
        Ok(())
    }

    pub(super) fn object_get_prototype(
        &mut self,
        module: Option<&Ir3Module>,
        id: ObjectId,
        depth: u32,
    ) -> Result<Value, InterpreterError> {
        self.integrity_step(id, depth)?;
        let Some((target, handler)) = self.active_proxy_record(id)? else {
            return Ok(self
                .ordinary_get_prototype_of(id)?
                .map_or(Value::Null, Value::Object));
        };
        let Some(result) = self.invoke_proxy_trap(
            module,
            handler,
            "getPrototypeOf",
            vec![self.proxy_trap_target(id, target)],
        )?
        else {
            return self.object_get_prototype(module, target, depth + 1);
        };
        self.observe_scoped_callback_result()?;
        let reported = Self::integrity_prototype(&result)?;
        if self.object_is_extensible(module, target, depth + 1)? {
            return Ok(result);
        }
        let actual = self.object_get_prototype(module, target, depth + 1)?;
        if reported != Self::integrity_prototype(&actual)? {
            return Err(Self::integrity_type_error(
                "non-extensible target's actual prototype",
                "inconsistent getPrototypeOf trap",
            ));
        }
        Ok(result)
    }

    fn object_set_prototype(
        &mut self,
        module: Option<&Ir3Module>,
        id: ObjectId,
        prototype: Option<ObjectId>,
        depth: u32,
    ) -> Result<bool, InterpreterError> {
        self.integrity_step(id, depth)?;
        if let Some((target, handler)) = self.active_proxy_record(id)? {
            let Some(result) = self.invoke_proxy_trap(
                module,
                handler,
                "setPrototypeOf",
                vec![
                    self.proxy_trap_target(id, target),
                    prototype.map_or(Value::Null, Value::Object),
                ],
            )?
            else {
                return self.object_set_prototype(module, target, prototype, depth + 1);
            };
            self.observe_scoped_callback_result()?;
            if !result.is_truthy() {
                return Ok(false);
            }
            if self.object_is_extensible(module, target, depth + 1)? {
                return Ok(true);
            }
            let actual = self.object_get_prototype(module, target, depth + 1)?;
            if prototype != Self::integrity_prototype(&actual)? {
                return Err(Self::integrity_type_error(
                    "non-extensible target's actual prototype",
                    "inconsistent setPrototypeOf trap",
                ));
            }
            return Ok(true);
        }
        let object = &self.heap[id.0 as usize];
        let unchanged = match prototype {
            Some(_) => self.observable_prototype_link(object, id) == prototype,
            None => {
                object.prototype.is_none()
                    && (object.is_null_prototype
                        || self.builtin_prototypes.get("Object") == Some(&id))
            }
        };
        if unchanged {
            return Ok(true);
        }
        if !self.heap[id.0 as usize].extensible()
            || self.builtin_prototypes.get("Object") == Some(&id)
        {
            return Ok(false);
        }
        let mut current = prototype;
        let mut walked = depth;
        while let Some(candidate) = current {
            self.integrity_step(candidate, walked)?;
            if candidate == id {
                return Ok(false);
            }
            // ES2020 OrdinarySetPrototypeOf stops at an exotic internal
            // method. Do not run a trap (or reject a revoked Proxy) here.
            if self.proxy_record(candidate)?.is_some() {
                break;
            }
            current = self.observable_prototype_of(candidate);
            walked += 1;
        }
        if self.active_inline_callback_context_label.is_some() {
            self.reflect_admit_mutation_label(id)?;
        }
        self.store_prototype_link(id, prototype);
        self.gc_write_barrier(id);
        Ok(true)
    }

    pub(super) fn object_is_extensible(
        &mut self,
        module: Option<&Ir3Module>,
        id: ObjectId,
        depth: u32,
    ) -> Result<bool, InterpreterError> {
        self.integrity_step(id, depth)?;
        let Some((target, handler)) = self.active_proxy_record(id)? else {
            return Ok(self.heap[id.0 as usize].extensible());
        };
        let Some(result) = self.invoke_proxy_trap(
            module,
            handler,
            "isExtensible",
            vec![self.proxy_trap_target(id, target)],
        )?
        else {
            return self.object_is_extensible(module, target, depth + 1);
        };
        self.observe_scoped_callback_result()?;
        let actual = self.object_is_extensible(module, target, depth + 1)?;
        if result.is_truthy() != actual {
            return Err(Self::integrity_type_error(
                "target's actual extensibility",
                "inconsistent isExtensible trap",
            ));
        }
        Ok(actual)
    }

    fn object_prevent_extensions(
        &mut self,
        module: Option<&Ir3Module>,
        id: ObjectId,
        depth: u32,
    ) -> Result<bool, InterpreterError> {
        self.integrity_step(id, depth)?;
        let Some((target, handler)) = self.active_proxy_record(id)? else {
            if self.active_inline_callback_context_label.is_some() {
                self.reflect_admit_mutation_label(id)?;
            }
            self.mutate_heap(|heap| heap[id.0 as usize].is_non_extensible = true);
            return Ok(true);
        };
        let Some(result) = self.invoke_proxy_trap(
            module,
            handler,
            "preventExtensions",
            vec![self.proxy_trap_target(id, target)],
        )?
        else {
            return self.object_prevent_extensions(module, target, depth + 1);
        };
        self.observe_scoped_callback_result()?;
        if !result.is_truthy() {
            return Ok(false);
        }
        if self.object_is_extensible(module, target, depth + 1)? {
            return Err(Self::integrity_type_error(
                "non-extensible target after success",
                "inconsistent preventExtensions trap",
            ));
        }
        Ok(true)
    }
}

/// Proxy [[GetOwnProperty]] and [[DefineOwnProperty]] (ES2020 9.5.5, 9.5.6;
/// bd-9vouw.147): `Object.getOwnPropertyDescriptor(proxy, k)` answered
/// undefined and `Object.defineProperty(proxy, ...)` neither called the trap
/// nor reached the target.
impl InterpreterCore {
    /// ES2020 6.2.5.4 FromPropertyDescriptor, after CompletePropertyDescriptor
    /// (6.2.5.6) when `complete`: the descriptor object a trap receives or a
    /// getOwnPropertyDescriptor call returns.
    fn descriptor_object_from_fields(
        &mut self,
        fields: &PropertyDescriptorFields,
        complete: bool,
    ) -> Result<Value, InterpreterError> {
        let object = self.alloc_object_with_prototype(None)?;
        let accessor = fields.is_accessor();
        if !accessor && (complete || fields.value.is_some()) {
            let value = fields.value.clone().unwrap_or(Value::Undefined);
            self.set_object_property(object, "value".to_string(), value)?;
        }
        if !accessor && (complete || fields.writable.is_some()) {
            let writable = fields.writable.unwrap_or(false);
            self.set_object_property(object, "writable".to_string(), Value::Bool(writable))?;
        }
        if accessor && (complete || fields.get.is_some()) {
            let get = fields.get.clone().unwrap_or(Value::Undefined);
            self.set_object_property(object, "get".to_string(), get)?;
        }
        if accessor && (complete || fields.set.is_some()) {
            let set = fields.set.clone().unwrap_or(Value::Undefined);
            self.set_object_property(object, "set".to_string(), set)?;
        }
        for (name, field) in [
            ("enumerable", fields.enumerable),
            ("configurable", fields.configurable),
        ] {
            if complete || field.is_some() {
                self.set_object_property(
                    object,
                    name.to_string(),
                    Value::Bool(field.unwrap_or(false)),
                )?;
            }
        }
        Ok(Value::Object(object))
    }

    /// ES2020 9.1.6.2 IsCompatiblePropertyDescriptor(Extensible, Desc,
    /// Current): whether an ordinary object could hold `desc` given
    /// `current`.
    fn descriptor_is_compatible(
        extensible: bool,
        desc: &PropertyDescriptorFields,
        current: Option<&PropertyDescriptorFields>,
    ) -> bool {
        let Some(current) = current else {
            return extensible;
        };
        if current.configurable != Some(true) {
            if desc.configurable == Some(true) {
                return false;
            }
            if desc.enumerable.is_some() && desc.enumerable != current.enumerable {
                return false;
            }
        }
        if !desc.is_accessor() && !desc.is_data() {
            return true;
        }
        if current.is_data() != desc.is_data() {
            return current.configurable == Some(true);
        }
        if current.configurable == Some(true) {
            return true;
        }
        if current.is_data() {
            if current.writable != Some(true) {
                if desc.writable == Some(true) {
                    return false;
                }
                if let (Some(value), Some(existing)) = (&desc.value, &current.value)
                    && !Self::same_value(value, existing)
                {
                    return false;
                }
            }
            return true;
        }
        for (wanted, existing) in [(&desc.get, &current.get), (&desc.set, &current.set)] {
            if let Some(wanted) = wanted
                && !Self::same_value(wanted, existing.as_ref().unwrap_or(&Value::Undefined))
            {
                return false;
            }
        }
        true
    }

    /// The target's own descriptor as fields, for the invariant checks.
    fn proxy_target_descriptor_fields(
        &mut self,
        module: Option<&Ir3Module>,
        target: ObjectId,
        key: &RuntimePropertyKey,
        depth: u32,
    ) -> Result<Option<PropertyDescriptorFields>, InterpreterError> {
        match self.proxy_aware_own_property_descriptor(module, target, key, depth)? {
            descriptor @ Value::Object(_) => {
                Ok(Some(self.read_property_descriptor(module, &descriptor)?))
            }
            _ => Ok(None),
        }
    }

    /// [[GetOwnProperty]] of `object_id` as a descriptor object or undefined,
    /// through a Proxy's `getOwnPropertyDescriptor` trap (ES2020 9.5.5).
    pub(super) fn proxy_aware_own_property_descriptor(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        depth: u32,
    ) -> Result<Value, InterpreterError> {
        self.integrity_step(object_id, depth)?;
        let Some((target, handler)) = self.active_proxy_record(object_id)? else {
            if let Some(descriptor) = self.prototype_getter_descriptor(object_id, key)? {
                return Ok(descriptor);
            }
            return self.own_property_descriptor_value(object_id, key);
        };
        let Some(trap) = self.proxy_trap_value(module, handler, "getOwnPropertyDescriptor")? else {
            return self.proxy_aware_own_property_descriptor(module, target, key, depth + 1);
        };
        let trap_target = self.proxy_trap_target(object_id, target);
        let result = self.call_proxy_trap(
            module,
            handler,
            "getOwnPropertyDescriptor",
            trap,
            vec![trap_target, key.value()],
        )?;
        let invariant = |what: &str| {
            Self::integrity_type_error(
                "a getOwnPropertyDescriptor trap result the target allows",
                what,
            )
        };
        if !matches!(result, Value::Undefined | Value::Object(_)) {
            return Err(invariant(&format!("{} result", result.type_name())));
        }
        let target_fields = self.proxy_target_descriptor_fields(module, target, key, depth + 1)?;
        if matches!(result, Value::Undefined) {
            if let Some(target_fields) = &target_fields {
                if target_fields.configurable != Some(true) {
                    return Err(invariant("a non-configurable property reported missing"));
                }
                if !self.object_is_extensible(module, target, depth + 1)? {
                    return Err(invariant(
                        "a non-extensible target's property reported missing",
                    ));
                }
            }
            return Ok(Value::Undefined);
        }
        let extensible = self.object_is_extensible(module, target, depth + 1)?;
        let fields = self.read_property_descriptor(module, &result)?;
        if !Self::descriptor_is_compatible(extensible, &fields, target_fields.as_ref()) {
            return Err(invariant("a descriptor incompatible with the target's"));
        }
        if fields.configurable != Some(true) {
            match &target_fields {
                None => return Err(invariant("a missing property reported non-configurable")),
                Some(target_fields) if target_fields.configurable == Some(true) => {
                    return Err(invariant(
                        "a configurable property reported non-configurable",
                    ));
                }
                Some(target_fields)
                    if fields.writable == Some(false) && target_fields.writable == Some(true) =>
                {
                    return Err(invariant("a writable property reported non-writable"));
                }
                _ => {}
            }
        }
        self.descriptor_object_from_fields(&fields, true)
    }

    /// [[DefineOwnProperty]] of `object_id`, through a Proxy's
    /// `defineProperty` trap (ES2020 9.5.6); `Ok(false)` is a rejected
    /// definition (Object.defineProperty throws, Reflect answers false).
    pub(super) fn proxy_aware_define_own_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: RuntimePropertyKey,
        fields: PropertyDescriptorFields,
        depth: u32,
    ) -> Result<bool, InterpreterError> {
        self.integrity_step(object_id, depth)?;
        let Some((target, handler)) = self.active_proxy_record(object_id)? else {
            return self.define_own_property_from_descriptor(object_id, key, fields);
        };
        let Some(trap) = self.proxy_trap_value(module, handler, "defineProperty")? else {
            return self.proxy_aware_define_own_property(module, target, key, fields, depth + 1);
        };
        let descriptor = self.descriptor_object_from_fields(&fields, false)?;
        let trap_target = self.proxy_trap_target(object_id, target);
        let result = self.call_proxy_trap(
            module,
            handler,
            "defineProperty",
            trap,
            vec![trap_target, key.value(), descriptor],
        )?;
        if !result.is_truthy() {
            return Ok(false);
        }
        let invariant = |what: &str| {
            Self::integrity_type_error("a defineProperty trap result the target allows", what)
        };
        let target_fields = self.proxy_target_descriptor_fields(module, target, &key, depth + 1)?;
        let extensible = self.object_is_extensible(module, target, depth + 1)?;
        let setting_config_false = fields.configurable == Some(false);
        match &target_fields {
            None => {
                if !extensible {
                    return Err(invariant("a new property on a non-extensible target"));
                }
                if setting_config_false {
                    return Err(invariant("a non-configurable property the target lacks"));
                }
            }
            Some(target_fields) => {
                if !Self::descriptor_is_compatible(extensible, &fields, Some(target_fields)) {
                    return Err(invariant("a descriptor incompatible with the target's"));
                }
                if setting_config_false && target_fields.configurable == Some(true) {
                    return Err(invariant(
                        "a configurable property defined non-configurable",
                    ));
                }
                if target_fields.is_data()
                    && target_fields.configurable != Some(true)
                    && target_fields.writable == Some(true)
                    && fields.writable == Some(false)
                {
                    return Err(invariant(
                        "a non-configurable writable property made non-writable",
                    ));
                }
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::ParseGoal;
    use crate::capability::RuntimeCapability;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    fn assert_native_true(source: &str) {
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "constructor-integrity.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("constructor integrity source must parse");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "constructor-integrity.js"),
            &LoweringContext::new("integrity-trace", "integrity-decision", "integrity-policy"),
        )
        .expect("constructor integrity source must lower")
        .ir3;
        for mut config in [
            InterpreterConfig::quickjs_defaults(),
            InterpreterConfig::v8_defaults(),
        ] {
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "constructor-integrity");
            let result = core
                .execute(&module)
                .expect("constructor integrity must execute");
            assert_eq!(result.value, Value::Bool(true), "{source}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "constructor reflection must release all temporary charges"
            );
        }
    }

    #[test]
    fn constructor_prototype_changes_preserve_callable_identity() {
        assert_native_true(
            r#"
            const original = Object.getPrototypeOf(Date);
            const same = original === Reflect.getPrototypeOf(Date);
            const parent = { inherited: 17 };
            const changed = Object.setPrototypeOf(Date, parent) === Date;
            const observed = Object.getPrototypeOf(Date) === parent &&
                Reflect.getPrototypeOf(Date) === parent;
            const restored = Reflect.setPrototypeOf(Date, original);
            same && changed && observed && restored &&
                Object.getPrototypeOf(Date) === original && typeof Date === 'function';
            "#,
        );
    }

    #[test]
    fn constructor_extensibility_uses_persistent_property_storage() {
        assert_native_true(
            r#"
            const before = Object.isExtensible(Date) && Reflect.isExtensible(Date);
            const prototype = Object.getPrototypeOf(Date);
            const identity = Object.preventExtensions(Date) === Date;
            const closed = !Object.isExtensible(Date) && !Reflect.isExtensible(Date);
            const unchanged = Reflect.setPrototypeOf(Date, prototype);
            const rejected = !Reflect.setPrototypeOf(Date, {});
            let threw = false;
            try { Object.setPrototypeOf(Date, {}); }
            catch (error) { threw = error.name === 'TypeError'; }
            before && identity && closed && unchanged && rejected && threw &&
                Reflect.preventExtensions(Date) && typeof Date.now === 'function';
            "#,
        );
    }

    #[test]
    fn promise_constructor_integrity_does_not_replace_the_callable() {
        assert_native_true(
            r#"
            const extensible = Reflect.isExtensible(Promise);
            const original = Reflect.getPrototypeOf(Promise);
            const parent = {};
            const changed = Reflect.setPrototypeOf(Promise, parent);
            const observed = Object.getPrototypeOf(Promise) === parent;
            const restored = Reflect.setPrototypeOf(Promise, original);
            const identity = Object.preventExtensions(Promise) === Promise;
            extensible && changed && observed && restored && identity &&
                !Reflect.isExtensible(Promise) && typeof Promise === 'function' &&
                typeof Promise.resolve === 'function';
            "#,
        );
    }

    #[test]
    fn primitive_object_and_reflect_contracts_remain_distinct() {
        assert_native_true(
            r#"
            let rejected = 0;
            try { Reflect.getPrototypeOf(1); } catch (e) { rejected += e.name === 'TypeError'; }
            try { Reflect.setPrototypeOf(1, null); } catch (e) { rejected += e.name === 'TypeError'; }
            try { Reflect.isExtensible(1); } catch (e) { rejected += e.name === 'TypeError'; }
            try { Reflect.preventExtensions(1); } catch (e) { rejected += e.name === 'TypeError'; }
            rejected === 4 && Object.preventExtensions(1) === 1 &&
                Object.setPrototypeOf(1, null) === 1 && !Object.isExtensible(1) &&
                Object.getPrototypeOf(1) === Number.prototype;
            "#,
        );
    }
}
