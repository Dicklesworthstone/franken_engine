use super::*;

impl InterpreterCore {
    pub(super) fn scoped_constant_name(module: &Ir3Module, name_pool_index: u32) -> Cow<'_, str> {
        module
            .constant_pool
            .get(name_pool_index as usize)
            .map(|name| {
                name.as_str()
                    .map(Cow::Borrowed)
                    .unwrap_or_else(|| Cow::Owned(name.to_string()))
            })
            .unwrap_or_else(|| Cow::Owned(format!("__binding_{name_pool_index}")))
    }

    /// Resolve a runtime name without manufacturing a lexical binding.
    ///
    /// Snapshot-backed execution modes can structurally replace the active
    /// scope chain. Realm-created sloppy globals therefore live in a separate
    /// shared map, while ordinary lexical resolution always retains priority.
    pub(super) fn resolve_runtime_name_binding(&self, name: &str) -> Option<ScopeBinding> {
        self.scope_chain
            .resolve(name)
            .map(|(_, binding)| binding.clone())
            .or_else(|| {
                if self.active_generated_function_artifact.is_some() {
                    self.generated_function_realm_globals
                        .as_ref()
                        .and_then(|globals| globals.get(name))
                        .cloned()
                } else {
                    self.realm_dynamic_globals.get(name).cloned()
                }
            })
    }

    /// Validate the complete Script declaration list before mutating the global
    /// object. A later forbidden function declaration must not leave the earlier
    /// var/function names partially instantiated.
    pub(super) fn validate_script_global_declarations(
        &mut self,
        module: &Ir3Module,
    ) -> Result<(), InterpreterError> {
        let object_id =
            self.realm_global_object
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "script global declarations require a realm global object".to_string(),
                })?;
        for instruction in &module.instructions {
            let Ir3Instruction::DeclareBinding {
                name_pool_index,
                kind,
            } = instruction
            else {
                break;
            };
            if !matches!(
                *kind,
                GLOBAL_VAR_BINDING_KIND | GLOBAL_FUNCTION_BINDING_KIND
            ) {
                break;
            }
            let name = Self::scoped_constant_name(module, *name_pool_index);
            let key = RuntimePropertyKey::String(name.as_ref().into());
            let object = self
                .heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            let permitted = match object.own_runtime_property_descriptor(&key) {
                None => object.extensible(),
                Some(_) if *kind == GLOBAL_VAR_BINDING_KIND => true,
                Some(descriptor) => {
                    let attributes = object.own_property_attributes(&key);
                    attributes.configurable
                        || (attributes.writable
                            && attributes.enumerable
                            && matches!(descriptor, BaselineSymbolProperty::Data(_)))
                }
            };
            if !permitted {
                return Err(self.throw_js_error(
                    "TypeError",
                    format!(
                        "cannot declare global {} {name}",
                        if *kind == GLOBAL_FUNCTION_BINDING_KIND {
                            "function"
                        } else {
                            "variable"
                        },
                    ),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn instantiate_script_global_binding(
        &mut self,
        name: &str,
        kind: u8,
    ) -> Result<(), InterpreterError> {
        let object_id =
            self.realm_global_object
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "script global declarations require a realm global object".to_string(),
                })?;
        let key = RuntimePropertyKey::String(name.into());
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let exists = object.contains_own_runtime_property(&key);
        let redefine = !exists
            || (kind == GLOBAL_FUNCTION_BINDING_KIND
                && object.own_property_attributes(&key).configurable);
        if redefine {
            // Global function declarations replace a configurable accessor
            // with a data property; the declaration never calls its setter.
            let accepted = self.define_own_property_from_descriptor(
                object_id,
                key,
                PropertyDescriptorFields {
                    value: Some(Value::Undefined),
                    writable: Some(true),
                    enumerable: Some(true),
                    configurable: Some(false),
                    ..PropertyDescriptorFields::default()
                },
            )?;
            if !accepted {
                return Err(
                    self.throw_js_error("TypeError", format!("cannot declare global {name}"))
                );
            }
        }
        // The injected globals historically also had private scope cells.
        // A source declaration must resolve through the object record, so a
        // stale injected cell cannot hide a later globalThis property write.
        let previous_scope_bytes = self.scope_chain_memory_bytes();
        let previous_closure_bytes = self.closures_memory_bytes();
        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        let previous_realm_global_bytes = self.realm_dynamic_globals_memory_bytes();
        let previous_generated_realm_global_bytes =
            self.generated_function_realm_globals_memory_bytes();
        self.scope_chain.current_mut()?.remove_binding(name);
        self.realm_dynamic_globals.remove(name);
        self.apply_scope_closure_call_stack_realm_memory_delta(
            previous_scope_bytes,
            previous_closure_bytes,
            previous_call_stack_bytes,
            previous_realm_global_bytes,
            previous_generated_realm_global_bytes,
        )?;
        Ok(())
    }

    pub(super) fn capture_runtime_name_reference(
        &mut self,
        name: &str,
    ) -> Result<u32, InterpreterError> {
        let reference = if let Some((_, binding)) = self.scope_chain.resolve(name) {
            RuntimeNameReference::Resolved(binding.clone())
        } else if self.active_generated_function_artifact.is_some() {
            self.generated_function_realm_globals
                .as_ref()
                .and_then(|globals| globals.get(name))
                .cloned()
                .map(RuntimeNameReference::Resolved)
                .unwrap_or(RuntimeNameReference::Unresolvable)
        } else if self.realm_dynamic_globals.contains_key(name)
            || self.global_object_binding(None, name)?.is_some()
        {
            // A global-object Reference retains the realm object and property
            // name, not the current property cell. If RHS code replaces that
            // property, PutValue must target the replacement.
            RuntimeNameReference::RealmGlobal
        } else {
            RuntimeNameReference::Unresolvable
        };
        if let Some(index) = self
            .runtime_name_references
            .iter()
            .position(|existing| existing.same_identity(&reference))
        {
            return u32::try_from(index).map_err(|_| InterpreterError::InternalError {
                details: "runtime name reference index exceeds u32".to_string(),
            });
        }

        let token = u32::try_from(self.runtime_name_references.len()).map_err(|_| {
            InterpreterError::MemoryBudgetExceeded {
                requested_bytes: u64::MAX,
                max_bytes: self.config.max_total_memory_bytes,
                requested_heap_objects: self.heap_object_count_u32(),
                max_heap_objects: self.config.max_heap_objects,
            }
        })?;
        let previous_bytes = self.runtime_name_references_memory_bytes();
        self.runtime_name_references.push(reference);
        let next_bytes = self.runtime_name_references_memory_bytes();
        if let Err(error) = self.apply_memory_component_delta(previous_bytes, next_bytes) {
            self.runtime_name_references.pop();
            return Err(error);
        }
        Ok(token)
    }

    pub(super) fn runtime_name_reference_token(value: Value) -> Result<u32, InterpreterError> {
        let Value::Int(token) = value else {
            return Err(InterpreterError::InternalError {
                details: "dynamic name resolution status register is not an integer token"
                    .to_string(),
            });
        };
        u32::try_from(token).map_err(|_| InterpreterError::InternalError {
            details: "dynamic name resolution status token is outside u32 range".to_string(),
        })
    }

    pub(super) fn load_runtime_name(
        &self,
        name: &str,
        allow_missing: bool,
    ) -> Result<Value, InterpreterError> {
        self.load_runtime_name_labeled(name, allow_missing)
            .map(|(value, _label)| value)
    }

    /// [`Self::load_runtime_name`] with the label the binding's cell holds
    /// alongside its value (the label LoadScoped reads); the CommonJS path
    /// names and an allowed missing name are Public (bd-9vouw.487).
    pub(super) fn load_runtime_name_labeled(
        &self,
        name: &str,
        allow_missing: bool,
    ) -> Result<(Value, Label), InterpreterError> {
        if let Some(binding) = self.resolve_runtime_name_binding(name) {
            let state = binding.state()?;
            if !state.initialized {
                return Err(InterpreterError::UninitializedBinding {
                    name: name.to_string(),
                });
            }
            return Ok((state.value.clone(), state.label.clone()));
        }

        // These are immutable global-object value properties, not mutable
        // scope cells. A real local binding (including its TDZ) wins above.
        if let Some(value) = Self::read_only_global_value(name) {
            return Ok((value, Label::Public));
        }

        if self.active_generated_function_artifact.is_none()
            && let Some(context) = self.active_cjs_context.as_ref()
        {
            let (filename, dirname) = self.cjs_filename_dirname(Some(&context.module_specifier));
            match name {
                "__filename" => return Ok((filename, Label::Public)),
                "__dirname" => return Ok((dirname, Label::Public)),
                _ => {}
            }
        }

        if allow_missing {
            Ok((Value::Undefined, Label::Public))
        } else {
            Err(InterpreterError::UndefinedBinding {
                name: name.to_string(),
            })
        }
    }

    /// The realm global object and the key of its property `name`, when a
    /// free identifier no binding resolves names one (ES2020 8.1.1.4.1
    /// HasBinding of the global object record): an own property
    /// (`globalThis.x = 1; x`), an accessor defined on it, or one it
    /// inherits from Object.prototype (`toString`).
    /// The global object free names resolve through, except while a
    /// Function-constructor body runs: generated code resolves in its own
    /// canonical realm (generated_function_realm_globals, bd-fw7zd.8.3), so
    /// the owner's global writes (`Function = 3`, `console = 1`) must not
    /// reach it through the main realm's global object.
    pub(super) fn name_resolving_global_object(&self) -> Option<ObjectId> {
        if self.active_generated_function_artifact.is_some() {
            None
        } else {
            self.realm_global_object
        }
    }

    pub(super) fn global_object_binding(
        &mut self,
        module: Option<&Ir3Module>,
        name: &str,
    ) -> Result<Option<(ObjectId, RuntimePropertyKey)>, InterpreterError> {
        let Some(global) = self.name_resolving_global_object() else {
            return Ok(None);
        };
        let key = RuntimePropertyKey::String(JsString::from(name));
        if self.heap.get(global.0 as usize).is_none()
            || !self.proxy_aware_has_runtime_property(module, global, &key, 0)?
        {
            return Ok(None);
        }
        Ok(Some((global, key)))
    }

    /// An own data property of the global object, read without running
    /// guest code.
    pub(super) fn global_object_data_property(&self, name: &str) -> Option<Value> {
        let key = RuntimePropertyKey::String(JsString::from(name));
        match self
            .heap
            .get(self.name_resolving_global_object()?.0 as usize)?
            .own_runtime_property_descriptor(&key)?
        {
            BaselineSymbolProperty::Data(value) => Some(value),
            BaselineSymbolProperty::Accessor { .. } => None,
        }
    }

    /// GetBindingValue of a global-object binding: an ordinary [[Get]]
    /// (getters run), with the label stored on the property it read.
    pub(super) fn load_global_object_name(
        &mut self,
        module: Option<&Ir3Module>,
        name: &str,
    ) -> Result<Option<(Value, Label)>, InterpreterError> {
        let Some((global, key)) = self.global_object_binding(module, name)? else {
            return Ok(None);
        };
        if let Some(module) = module {
            self.run_pre_runtime_property_access_hook(module, global, &key)?;
        }
        let value =
            self.proxy_aware_get_runtime_property(module, global, &key, Value::Object(global), 0)?;
        let label = self.runtime_property_label(global, &key);
        Ok(Some((value, label)))
    }

    /// SetMutableBinding of a global-object binding, and the property a
    /// sloppy write to an unresolvable name creates: an ordinary [[Set]] that
    /// stores the written value's label on the property, as SetProperty does.
    /// In strict code a binding the right-hand side deleted is a
    /// ReferenceError and a [[Set]] that fails (a non-writable property, a
    /// getter without a setter) a TypeError (ES2020 8.1.1.2.5 steps 1-5,
    /// bd-9vouw.466).
    pub(super) fn put_global_object_name(
        &mut self,
        module: Option<&Ir3Module>,
        global: ObjectId,
        name: &str,
        value: Value,
        label: &Label,
        strict: bool,
    ) -> Result<(), InterpreterError> {
        let key = RuntimePropertyKey::String(JsString::from(name));
        if strict && !self.proxy_aware_has_runtime_property(module, global, &key, 0)? {
            return Err(InterpreterError::UndefinedBinding {
                name: name.to_string(),
            });
        }
        if let Some(module) = module {
            self.run_pre_runtime_property_access_hook(module, global, &key)?;
        }
        self.join_object_mutation_label(global, label)?;
        let previous_label = self.own_stored_runtime_property_label(global, &key);
        self.set_own_runtime_property_label(global, &key, label)?;
        let committed = match self.proxy_aware_set_runtime_property(
            module,
            global,
            &key,
            value,
            Value::Object(global),
            0,
        ) {
            Ok(committed) => committed,
            Err(error) => {
                self.set_own_runtime_property_label(global, &key, &previous_label)?;
                return Err(error);
            }
        };
        let owns_property = self
            .heap
            .get(global.0 as usize)
            .is_some_and(|object| object.contains_own_runtime_property(&key));
        if !committed || !owns_property {
            // A non-writable property or an inherited setter keeps no own value.
            self.set_own_runtime_property_label(global, &key, &previous_label)?;
        }
        if strict && !committed {
            return Err(InterpreterError::TypeError {
                expected: "writable global property".to_string(),
                got: format!("the global object's read-only `{name}`"),
            });
        }
        Ok(())
    }

    pub(super) fn put_resolved_runtime_name_binding(
        &mut self,
        name: &str,
        binding: ScopeBinding,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let previous_scope_bytes = self.scope_chain_memory_bytes();
        let previous_closure_bytes = self.closures_memory_bytes();
        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        let previous_realm_global_bytes = self.realm_dynamic_globals_memory_bytes();
        let previous_generated_realm_global_bytes =
            self.generated_function_realm_globals_memory_bytes();
        let previous_state = binding.snapshot_state()?;
        if !previous_state.initialized {
            return Err(InterpreterError::UninitializedBinding {
                name: name.to_string(),
            });
        }
        if binding.kind.is_immutable() {
            return Err(InterpreterError::ConstAssignment {
                name: name.to_string(),
            });
        }
        if self
            .mapped_argument_aliases
            .contains_key(&ColdBindingCells::key(&binding.state))
        {
            return self.set_mapped_argument_value(binding, Some(value), None);
        }
        binding.state_mut()?.value = value;
        self.closures.refresh_cell(&binding.state);
        if let Err(error) = self.apply_scope_closure_call_stack_realm_memory_delta(
            previous_scope_bytes,
            previous_closure_bytes,
            previous_call_stack_bytes,
            previous_realm_global_bytes,
            previous_generated_realm_global_bytes,
        ) {
            binding.restore_state(previous_state)?;
            self.closures.refresh_cell(&binding.state);
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn put_unresolvable_runtime_name(
        &mut self,
        module: Option<&Ir3Module>,
        name: &str,
        value: Value,
        label: &Label,
        strict: bool,
    ) -> Result<(), InterpreterError> {
        if strict {
            return Err(InterpreterError::UndefinedBinding {
                name: name.to_string(),
            });
        }

        if self.active_generated_function_artifact.is_some() {
            if let Some(binding) = self
                .scope_chain
                .frames
                .first()
                .and_then(|frame| frame.get(name))
                .cloned()
            {
                let canonical_binding = self
                    .generated_function_realm_globals
                    .as_ref()
                    .and_then(|globals| globals.get(name))
                    .ok_or_else(|| InterpreterError::InternalError {
                        details: format!(
                            "generated Function realm frame contains non-canonical global `{name}`"
                        ),
                    })?;
                if !Rc::ptr_eq(&binding.state, &canonical_binding.state) {
                    return Err(InterpreterError::InternalError {
                        details: format!(
                            "generated Function realm binding identity drifted for `{name}`"
                        ),
                    });
                }
                return self.put_resolved_runtime_name_binding(name, binding, value);
            }
            if self.scope_chain.frames.is_empty() {
                return Err(InterpreterError::InternalError {
                    details: "generated Function scope chain unexpectedly empty".to_string(),
                });
            }
            let canonical_binding = self
                .generated_function_realm_globals
                .as_ref()
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "generated Function realm globals are not initialized".to_string(),
                })?
                .get(name)
                .cloned();
            if let Some(canonical_binding) = canonical_binding {
                // A closure can retain frame structure created before another
                // generated call adds this realm-global name. The canonical
                // environment record remains authoritative even when that
                // older structural view has no map entry for it.
                return self.put_resolved_runtime_name_binding(name, canonical_binding, value);
            }
            let previous_scope_bytes = self.scope_chain_memory_bytes();
            let previous_closure_bytes = self.closures_memory_bytes();
            let previous_call_stack_bytes = self.call_stack_memory_bytes();
            let previous_realm_global_bytes = self.realm_dynamic_globals_memory_bytes();
            let previous_generated_realm_global_bytes =
                self.generated_function_realm_globals_memory_bytes();
            let binding = ScopeBinding::with_state(BindingKind::Var, value, true);
            let canonical_replaced = self
                .generated_function_realm_globals
                .as_mut()
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "generated Function realm globals are not initialized".to_string(),
                })?
                .insert(name.to_string(), binding.clone());
            let frame_replaced = self
                .scope_chain
                .frames
                .first_mut()
                .expect("generated Function frame existence was checked")
                .insert_binding(name.to_string(), binding);
            debug_assert!(
                canonical_replaced.is_none(),
                "canonical binding was unresolved"
            );
            debug_assert!(frame_replaced.is_none(), "active binding was unresolved");
            if let Err(error) = self.apply_scope_closure_call_stack_realm_memory_delta(
                previous_scope_bytes,
                previous_closure_bytes,
                previous_call_stack_bytes,
                previous_realm_global_bytes,
                previous_generated_realm_global_bytes,
            ) {
                if let Some(globals) = self.generated_function_realm_globals.as_mut() {
                    if let Some(replaced) = canonical_replaced {
                        globals.insert(name.to_string(), replaced);
                    } else {
                        globals.remove(name);
                    }
                }
                if let Some(global_frame) = self.scope_chain.frames.first_mut() {
                    if let Some(replaced) = frame_replaced {
                        global_frame.insert_binding(name.to_string(), replaced);
                    } else {
                        global_frame.remove_binding(name);
                    }
                }
                return Err(error);
            }
            return Ok(());
        }

        // Sloppy code: the write creates the global property.
        self.put_realm_runtime_name_labeled(module, name, value, label, false)
    }

    /// Execute `delete name` for an identifier without a source lexical
    /// binding. Sloppy-created realm globals are configurable, so removing one
    /// succeeds and returns `true`; a genuinely missing name also returns
    /// `true` without any GetValue. A name that resolves to an environment
    /// (scope-chain) binding is not a deletable property, so it returns
    /// `false`, matching `delete` of an environment Reference.
    pub(super) fn delete_runtime_name(&mut self, name: &str) -> Result<bool, InterpreterError> {
        if self.scope_chain.resolve(name).is_some() {
            return Ok(false);
        }
        // The global object's NaN, Infinity and undefined are
        // non-configurable (ES2020 18.1): `delete NaN` is false. A function's
        // `arguments` is a binding of its own scope even when nothing else
        // reads it (and no runtime binding was declared): false inside a call.
        if matches!(name, "NaN" | "Infinity" | "undefined")
            || (name == "arguments" && !self.call_stack.is_empty())
        {
            return Ok(false);
        }

        let in_generated_artifact = self.active_generated_function_artifact.is_some();
        let present = if in_generated_artifact {
            self.generated_function_realm_globals
                .as_ref()
                .is_some_and(|globals| globals.contains_key(name))
        } else {
            self.realm_dynamic_globals.contains_key(name)
        };
        if !present {
            // A global-object binding deletes the property ([[Delete]]: an
            // inherited one is `true` without effect, a non-configurable one
            // `false`).
            if !in_generated_artifact
                && let Some((global, key)) = self.global_object_binding(None, name)?
            {
                return self.proxy_aware_delete_runtime_property(None, global, &key, 0);
            }
            // Genuinely missing name: `delete` of an unresolvable Reference is
            // `true` with no side effect.
            return Ok(true);
        }

        let previous_scope_bytes = self.scope_chain_memory_bytes();
        let previous_closure_bytes = self.closures_memory_bytes();
        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        let previous_realm_global_bytes = self.realm_dynamic_globals_memory_bytes();
        let previous_generated_realm_global_bytes =
            self.generated_function_realm_globals_memory_bytes();

        if in_generated_artifact {
            if let Some(globals) = self.generated_function_realm_globals.as_mut() {
                globals.remove(name);
            }
        } else {
            self.realm_dynamic_globals.remove(name);
        }

        self.apply_scope_closure_call_stack_realm_memory_delta(
            previous_scope_bytes,
            previous_closure_bytes,
            previous_call_stack_bytes,
            previous_realm_global_bytes,
            previous_generated_realm_global_bytes,
        )?;
        Ok(true)
    }

    pub(super) fn put_realm_runtime_name(
        &mut self,
        name: &str,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.put_realm_runtime_name_labeled(None, name, value, &Label::Public, false)
    }

    pub(super) fn put_realm_runtime_name_labeled(
        &mut self,
        module: Option<&Ir3Module>,
        name: &str,
        value: Value,
        label: &Label,
        strict: bool,
    ) -> Result<(), InterpreterError> {
        // Write the realm global object directly. If RHS code created or
        // replaced this property after the Reference was captured, it is still
        // the property this PutValue updates; a newly appearing lexical binding
        // must not steal the write.
        if let Some(binding) = self.realm_dynamic_globals.get(name).cloned() {
            return self.put_resolved_runtime_name_binding(name, binding, value);
        }
        // Once the realm has its global object, a sloppy global is a property
        // of it (`x = 1; globalThis.x`), readable through the fallback in
        // LoadName.
        if let Some(global) = self.name_resolving_global_object() {
            return self.put_global_object_name(module, global, name, value, label, strict);
        }

        let previous_scope_bytes = self.scope_chain_memory_bytes();
        let previous_closure_bytes = self.closures_memory_bytes();
        let previous_call_stack_bytes = self.call_stack_memory_bytes();
        let previous_realm_global_bytes = self.realm_dynamic_globals_memory_bytes();
        let previous_generated_realm_global_bytes =
            self.generated_function_realm_globals_memory_bytes();
        let binding = ScopeBinding::with_state(BindingKind::Var, value, true);
        debug_assert!(!self.realm_dynamic_globals.contains_key(name));
        self.realm_dynamic_globals.insert(name.to_string(), binding);

        if let Err(error) = self.apply_scope_closure_call_stack_realm_memory_delta(
            previous_scope_bytes,
            previous_closure_bytes,
            previous_call_stack_bytes,
            previous_realm_global_bytes,
            previous_generated_realm_global_bytes,
        ) {
            self.realm_dynamic_globals.remove(name);
            return Err(error);
        }

        Ok(())
    }

    /// Implement ECMAScript PutValue when target resolution and the write are
    /// adjacent (loop/destructuring leaves and direct IR clients).
    pub(super) fn put_runtime_name(
        &mut self,
        name: &str,
        value: Value,
        strict: bool,
    ) -> Result<(), InterpreterError> {
        self.put_runtime_name_labeled(None, name, value, &Label::Public, strict)
    }

    /// [`Self::put_runtime_name`] with the written value's label, which a
    /// global-object property stores.
    pub(super) fn put_runtime_name_labeled(
        &mut self,
        module: Option<&Ir3Module>,
        name: &str,
        value: Value,
        label: &Label,
        strict: bool,
    ) -> Result<(), InterpreterError> {
        if let Some(binding) = self.resolve_runtime_name_binding(name) {
            if self
                .mapped_argument_aliases
                .contains_key(&ColdBindingCells::key(&binding.state))
            {
                return self.set_mapped_argument_value(binding, Some(value), Some(label));
            }
            self.put_resolved_runtime_name_binding(name, binding, value)
        } else if let Some(outcome) = Self::put_read_only_global_value(name, strict) {
            outcome
        } else if self.active_generated_function_artifact.is_none()
            && self.global_object_binding(module, name)?.is_some()
        {
            // A property of the global object is a binding, in strict code
            // too (`globalThis.x = 1; x = 2`).
            self.put_realm_runtime_name_labeled(module, name, value, label, strict)
        } else {
            self.put_unresolvable_runtime_name(module, name, value, label, strict)
        }
    }

    /// Complete a dynamic PutValue using the exact Reference captured before
    /// RHS evaluation. The token remains stable when execution temporarily
    /// replaces the active scope chain or resumes under a same-named binding.
    pub(super) fn put_runtime_name_with_status(
        &mut self,
        name: &str,
        value: Value,
        strict: bool,
        reference_token: u32,
    ) -> Result<(), InterpreterError> {
        self.put_runtime_name_with_status_labeled(
            None,
            name,
            value,
            &Label::Public,
            strict,
            reference_token,
        )
    }

    pub(super) fn read_only_global_value(name: &str) -> Option<Value> {
        match name {
            "undefined" => Some(Value::Undefined),
            "NaN" => Some(Value::Float(Float64::new(f64::NAN))),
            "Infinity" => Some(Value::Float(Float64::new(f64::INFINITY))),
            _ => None,
        }
    }

    /// Install the immutable global value properties without creating Var
    /// cells, which would let name assignments bypass their descriptors.
    pub(super) fn seed_read_only_global_values(
        &mut self,
        global: ObjectId,
    ) -> Result<(), InterpreterError> {
        for name in ["undefined", "NaN", "Infinity"] {
            let value = Self::read_only_global_value(name)
                .expect("the immutable global value names are exhaustive");
            self.set_object_property(global, name.to_string(), value)?;
            self.set_own_property_attributes(
                global,
                &RuntimePropertyKey::String(JsString::from(name)),
                READ_ONLY_VALUE_ATTRIBUTES,
            )?;
        }
        Ok(())
    }

    /// The global object's NaN, Infinity and undefined are non-writable data
    /// properties (ES2020 18.1): assigning one through an identifier that no
    /// binding shadows changes nothing, and in strict code is a TypeError
    /// (PutValue step 6's [[Set]] returns false). `None` for any other name.
    pub(super) fn put_read_only_global_value(
        name: &str,
        strict: bool,
    ) -> Option<Result<(), InterpreterError>> {
        if !matches!(name, "NaN" | "Infinity" | "undefined") {
            return None;
        }
        Some(if strict {
            Err(InterpreterError::TypeError {
                expected: "writable global property".to_string(),
                got: format!("the global object's read-only `{name}`"),
            })
        } else {
            Ok(())
        })
    }

    pub(super) fn put_runtime_name_with_status_labeled(
        &mut self,
        module: Option<&Ir3Module>,
        name: &str,
        value: Value,
        label: &Label,
        strict: bool,
        reference_token: u32,
    ) -> Result<(), InterpreterError> {
        let reference = self
            .runtime_name_references
            .get(reference_token as usize)
            .cloned()
            .ok_or_else(|| InterpreterError::InternalError {
                details: format!("unknown runtime name reference token {reference_token}"),
            })?;
        if !matches!(reference, RuntimeNameReference::Resolved(_))
            && let Some(outcome) = Self::put_read_only_global_value(name, strict)
        {
            return outcome;
        }
        match reference {
            RuntimeNameReference::Resolved(binding) => {
                if self
                    .mapped_argument_aliases
                    .contains_key(&ColdBindingCells::key(&binding.state))
                {
                    return self.set_mapped_argument_value(binding, Some(value), Some(label));
                }
                self.put_resolved_runtime_name_binding(name, binding, value)
            }
            RuntimeNameReference::RealmGlobal => {
                if self.active_generated_function_artifact.is_some() {
                    return Err(InterpreterError::InternalError {
                        details:
                            "realm-global Reference crossed into a generated Function activation"
                                .to_string(),
                    });
                }
                self.put_realm_runtime_name_labeled(module, name, value, label, strict)
            }
            RuntimeNameReference::Unresolvable => {
                self.put_unresolvable_runtime_name(module, name, value, label, strict)
            }
        }
    }

    /// Create a new interpreter core with the given configuration.
    pub fn new(config: InterpreterConfig, trace_id: impl Into<String>) -> Self {
        let max_regs = config.max_registers as usize;
        let trace_id = trace_id.into();
        // perf: hot path - avoid clone by reusing trace_id for nondeterminism_trace
        let nondeterminism_trace = NondeterminismTrace::new(&trace_id);
        let scope_chain = ScopeChain::new();
        // Seed exactly what recompute reports for a fresh core: shallow chain
        // structure plus each (necessarily unaliased) cell payload once.
        let estimated_memory_bytes = Self::estimate_scope_chain_bytes(&scope_chain.frames)
            .saturating_add(Self::accumulate_scope_frame_cell_payload_bytes(
                &scope_chain.frames,
                &mut BTreeSet::new(),
                &mut BTreeSet::new(),
            ));
        Self {
            config,
            hook: None,
            pruned_hostcall_dispatch: None,
            codegen_caller_grants: Vec::new(),
            preparing_execution: false,
            state_capture_tick: None,
            state_capture_result: None,
            host_io: None,
            host_io_recorder: None,
            process_spawn: None,
            host_effect_journal: None,
            timer_effect_authority: None,
            entry_flow_label_ceiling: None,
            registers: SeedTrackedField::new(vec![Value::Undefined; max_regs]),
            registers_value_bytes: std::cell::Cell::new(None),
            register_labels_bytes: std::cell::Cell::new(None),
            template_objects: BTreeMap::new(),
            call_stack: CallStack::default(),
            heap: SeedTrackedField::new(Heap::new()),
            estimated_memory_bytes,
            simple_callback_temporary_bytes: 0,
            simple_callback_register_pool: Vec::new(),
            spare_register_files: Vec::new(),
            property_witness_scratch: Vec::new(),
            call_argument_value_scratch: Vec::new(),
            call_argument_label_scratch: Vec::new(),
            json_parse_temporary_bytes: 0,
            regexp_temporary_bytes: Rc::new(Cell::new(0)),
            module_snapshot_in_flight_bytes: 0,
            temporarily_suspended_execution_bytes: 0,
            iterators: ReclaimableTable::new("iterator", Self::estimate_iterator_bytes),
            collection_iterators: BTreeMap::new(),
            collection_for_each_cursors: Vec::new(),
            iteration_traces: Vec::new(),
            function_prototypes: SeedTrackedField::new(BTreeMap::new()),
            prototype_owner_ids: std::cell::RefCell::new(Vec::new()),
            lexical_super_functions: std::cell::RefCell::new(Vec::new()),
            builtin_function_backings: false,
            virtual_property_deletions: false,
            builtin_prototypes: SeedTrackedField::new(BTreeMap::new()),
            seed_epoch: 0,
            pending_lazy_seeds: Vec::new(),
            pending_arguments_object: None,
            mapped_argument_bindings: BTreeMap::new(),
            mapped_argument_aliases: BTreeMap::new(),
            argument_overflow: Vec::new(),
            argument_overflow_bytes: 0,
            execution_seed_reservation_ledger: std::rc::Rc::new(
                ExecutionSeedReservationLedger::default(),
            ),
            ip: 0,
            instructions_executed: 0,
            native_hole_reads: Cell::new(0),
            tier_i_instructions_executed: 0,
            tier_i_specialized_instructions_executed: 0,
            witness_events: Vec::new(),
            timer_callback_witness: None,
            microtask_enqueue_witness: None,
            hostcall_decisions: Vec::new(),
            folded_hostcall_decisions: 0,
            recorded_effect_free_grants: BTreeSet::new(),
            regexp_cache: RefCell::new(VecDeque::new()),
            security_observability: RuntimeSecurityObservability::new(),
            telemetry_recorder: TelemetryRecorder::new(RecorderConfig::default()),
            events: Vec::new(),
            general_event_bytes: 0,
            dropped_event_count: 0,
            generated_code_audit: Vec::new(),
            generated_code_observability_bytes: 0,
            generated_code_observability_reservation_bytes: 0,
            witness_seq: 0,
            trace_id,
            register_base: 0,
            register_width: max_regs,
            native_run_loop_depth: 0,
            register_dirty_end: 0,
            top_level_compact_tier1: None,
            entry_frame_widths: None,
            catch_frames: Vec::new(),
            pending_exception: None,
            pending_exception_label: Label::Public,
            pending_hostcall_result_label: None,
            legacy_regexp_match: None,
            legacy_regexp_generation: 0,
            legacy_regexp_read_label: None,
            pending_return: None,
            suspended_abrupt_completions: Vec::new(),
            finally_frames: Vec::new(),
            pending_finally_entry: None,
            last_pre_run_seed: None,
            last_post_run_epoch: None,
            scope_chain,
            realm_dynamic_globals: BTreeMap::new(),
            realm_global_object: None,
            process_global_object: None,
            generated_function_realm_globals: None,
            generated_function_realm_generation: 0,
            runtime_name_references: Vec::new(),
            closures: ClosureTable::default(),
            closure_method_metadata: ClosureSideTable::new(
                Self::estimate_closure_method_metadata_entry_bytes,
            ),
            closure_lexical_super_metadata: ClosureSideTable::new(
                Self::estimate_closure_lexical_super_metadata_entry_bytes,
            ),
            arrow_lexical_this: ClosureSideTable::new(
                Self::estimate_arrow_lexical_this_entry_bytes,
            ),
            closure_module_origins: ClosureSideTable::new(|origin| {
                Self::estimate_closure_module_origin_entry_bytes(origin)
            }),
            closure_generated_function_artifacts: ClosureSideTable::new(|_| {
                Self::estimate_closure_generated_function_artifact_entry_bytes()
            }),
            module_reentrant_call_depth: 0,
            active_foreign_module_call_depth: 0,
            isolated_async_entry_pending: false,
            gc_nested_request: None,
            generic_function_receiver: None,
            pending_captures: Vec::new(),
            generators: ReclaimableTable::new("generator", Self::estimate_generator_bytes),
            generator_yielded: false,
            generator_resume_dst: None,
            generator_result_label: Label::Public,
            generator_prologue_pending: None,
            suspend_at_generator_prologue: false,
            generator_delegation: None,
            async_functions: ReclaimableTable::new(
                "async function",
                Self::estimate_async_function_bytes,
            ),
            async_resumption_contexts: BTreeMap::new(),
            top_level_await_resumption_contexts: BTreeMap::new(),
            top_level_await_outcome: None,
            async_generators: ReclaimableTable::new(
                "async generator",
                Self::estimate_async_generator_bytes,
            ),
            async_generator_runtime: AsyncGeneratorRuntime::default(),
            promise_store: crate::promise_model::PromiseStore::new(),
            event_loop: crate::promise_model::EventLoop::new(),
            promise_in_flight_task_bytes: 0,
            promise_reaction_callables: BTreeMap::new(),
            promise_value_carriers: BTreeMap::new(),
            next_promise_value_carrier: PROMISE_VALUE_CARRIER_BASE,
            next_promise_reaction_callable_id: PROMISE_REACTION_CALLABLE_BASE,
            builtin_dispatch_hit_unknown_member: false,
            next_tick_queue: std::collections::VecDeque::new(),
            pending_io_callbacks: BTreeMap::new(),
            pending_fs_promise_reads: BTreeMap::new(),
            pending_dynamic_imports: BTreeMap::new(),
            deferred_callback_in_flight_bytes: 0,
            pending_child_process_tasks: BTreeMap::new(),
            child_process_task_in_flight_bytes: 0,
            event_listeners: BTreeMap::new(),
            event_once_wrappers: BTreeMap::new(),
            event_promise_waiters: BTreeMap::new(),
            next_event_promise_waiter_id: 0,
            completed_child_processes: BTreeMap::new(),
            child_process_streams: BTreeMap::new(),
            child_process_handles: BTreeMap::new(),
            url_objects: BTreeMap::new(),
            url_search_params: BTreeMap::new(),
            cluster_facades: BTreeMap::new(),
            crypto_objects: BTreeMap::new(),
            stream_pipelines: BTreeMap::new(),
            next_stream_pipeline_token: 0,
            pending_stream_emissions: BTreeMap::new(),
            readable_from_streams: BTreeMap::new(),
            readable_terminal_states: BTreeMap::new(),
            pending_readable_from_pumps: BTreeMap::new(),
            readable_pump_reservations: BTreeMap::new(),
            active_readable_listener_target: None,
            readable_pipe_links: BTreeMap::new(),
            readable_pipe_sources: BTreeMap::new(),
            next_readable_pipe_token: 0,
            loopback_servers: BTreeMap::new(),
            loopback_sockets: BTreeMap::new(),
            loopback_ports: BTreeMap::new(),
            pending_loopback_tasks: BTreeMap::new(),
            loopback_task_in_flight_bytes: 0,
            next_loopback_port: 41_000,
            next_loopback_listener_generation: 1,
            http_servers: BTreeMap::new(),
            http_client_requests: BTreeMap::new(),
            http_incoming_messages: BTreeMap::new(),
            http_server_responses: BTreeMap::new(),
            http_agents: BTreeSet::new(),
            pending_http_tasks: BTreeMap::new(),
            http_task_in_flight_bytes: 0,
            writable_streams: BTreeMap::new(),
            writable_terminal_states: BTreeMap::new(),
            writable_in_flight_callback_bytes: 0,
            pending_writable_terminal_ticks: 0,
            next_writable_tick_sequence: 0,
            next_writable_completion_token: 0,
            promise_combinators: BTreeMap::new(),
            promise_combinator_watchers: BTreeMap::new(),
            promise_combinators_bytes: 0,
            promise_combinator_watchers_bytes: 0,
            array_join_stack: BTreeSet::new(),
            next_promise_combinator_id: 0,
            module_state: ModuleState::new(),
            module_resolver: None,
            pending_async_module_import: None,
            active_cjs_context: None,
            current_module_specifier: None,
            active_generated_function_artifact: None,
            entry_module_specifier: None,
            console_output: Vec::new(),
            console_output_bytes: 0,
            console_group_depth: 0,
            console_counts: BTreeMap::new(),
            console_timers: BTreeMap::new(),
            process_exit_code: None,
            virtual_clock_instruction_mark: 0,
            profiling_data: None,
            next_timer_id: 0,
            active_timers: BTreeMap::new(),
            pending_timer_tasks: BTreeMap::new(),
            unref_timer_ids: BTreeSet::new(),
            atomics_async_waiters: Vec::new(),
            suspended: false,
            sandboxed: false,
            quarantined: false,
            pending_challenges: Vec::new(),
            containment_evidence: Vec::new(),
            decision_receipts: EvidenceLog::new(),
            nondeterminism_trace,
            register_labels: vec![Label::Public; max_regs],
            seeded_register_labels: BTreeSet::new(),
            all_register_labels_public: true,
            object_mutation_labels: BTreeMap::new(),
            active_inline_callback_context_label: None,
            pc_label_stack: Vec::new(),
            ipdom_cache: BTreeMap::new(),
            ifc_runtime_flow_audit: Vec::new(),
            inline_callback_start_probes: Vec::new(),
            proxy_trap_lookup_depth: 0,
            weakmap_storage: BTreeMap::new(),
            symbol_state: SeedTrackedField::new(RuntimeSymbolState::default()),
            gc_remembered_set: RememberedSet::default(),
            jit_function_call_counts: BTreeMap::new(),
            jit_loop_iteration_counts: LoopIterationCounters::default(),
            jit_hot_threshold: 10_000, // Default threshold
            jit_eviction_counter: 0,
            gc: collector::GcState::default(),
        }
    }

    pub fn set_hook(&mut self, hook: Arc<dyn InterpreterHook>) {
        self.hook = Some(hook);
    }

    pub fn clear_hook(&mut self) {
        self.hook = None;
    }

    /// Install capability-pruned hostcall dispatch metadata (E9.T4,
    /// bd-fqlfw.9.4). Only the E9 activation gate should call this, after
    /// its receipt/epoch/replay gates approve. The table decides only the
    /// allow/deny bit; witness and decision-record emission is unchanged.
    pub fn set_pruned_hostcall_dispatch(&mut self, table: PrunedHostcallDispatch) {
        self.pruned_hostcall_dispatch = Some(table);
    }

    /// Remove the pruned-dispatch table: every subsequent hostcall uses the
    /// live classification path (the safe-mode fallback surface).
    pub fn clear_pruned_hostcall_dispatch(&mut self) {
        self.pruned_hostcall_dispatch = None;
    }

    /// Whether a pruned-dispatch table is currently installed.
    pub fn has_pruned_hostcall_dispatch(&self) -> bool {
        self.pruned_hostcall_dispatch.is_some()
    }

    /// Install a sandboxed host-I/O provider (and an optional replay recorder) so
    /// authorized `fs:` hostcalls perform and record real host effects
    /// (bd-f5b04.2.7). Mirrors [`InterpreterCore::set_hook`]; with no provider the
    /// interpreter keeps its fail-closed baseline (fs hostcalls return undefined).
    pub fn set_host_io(
        &mut self,
        provider: Arc<dyn HostIoProvider>,
        recorder: Option<Arc<dyn HostIoRecorder>>,
    ) {
        self.host_io = Some(provider);
        self.host_io_recorder = recorder;
    }

    /// Bind compilation and execution to the same live/replay exception
    /// contract. A module loaded later in the execution must not lose the
    /// provider's authenticated provenance, or trust an unknown replay source.
    pub(super) fn filesystem_exception_provenance(&self) -> HostIoExceptionProvenance {
        let Some(provider) = self.host_io.as_ref() else {
            return if self.host_io_recorder.is_none()
                && self.process_spawn.is_none()
                && self.host_effect_journal.is_none()
            {
                HostIoExceptionProvenance::ProviderInternal
            } else {
                HostIoExceptionProvenance::Unknown
            };
        };
        let effect_source_provenance = self.host_effect_journal.as_ref().map_or_else(
            || {
                self.host_io_recorder
                    .as_ref()
                    .map_or(HostIoExceptionProvenance::ProviderInternal, |recorder| {
                        recorder.filesystem_exception_provenance()
                    })
            },
            |journal| journal.filesystem_exception_provenance(),
        );
        provider
            .filesystem_exception_provenance()
            .combine(effect_source_provenance)
    }

    /// Install the separately admitted process provider and the global journal
    /// that also records any host-I/O crossings in this execution.
    pub fn set_process_spawn(
        &mut self,
        provider: Arc<dyn ProcessSpawnProvider>,
        journal: Arc<InMemoryHostEffectJournal>,
    ) {
        self.process_spawn = Some(provider);
        self.host_effect_journal = Some(journal);
    }

    /// Attach the sealed product-cell authority used by interpreter timer
    /// effects. The actual scheduling provider remains this core's event loop.
    pub fn set_timer_effect_authority(&mut self, authority: Arc<dyn TimerEffectAuthority>) {
        self.timer_effect_authority = Some(authority);
    }

    /// Record the entry module's flow label ceiling (bd-j8f7q), computed by
    /// the embedder from the entry's lowering.
    pub fn set_entry_flow_label_ceiling(&mut self, ceiling: Label) {
        self.entry_flow_label_ceiling = Some(ceiling);
    }

    pub(super) fn join_object_mutation_label(
        &mut self,
        object_id: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let mut current = Some(object_id);
        // The cycle guard of a Proxy chain; a store into an ordinary object
        // ends after one step, so the set (one node allocation per store)
        // starts only when the chain goes on (bd-9vouw.504).
        let mut visited: Option<BTreeSet<ObjectId>> = None;
        let mut first = true;
        while let Some(target) = current {
            if first {
                first = false;
            } else if !visited
                .get_or_insert_with(|| BTreeSet::from([object_id]))
                .insert(target)
            {
                break;
            }
            self.join_direct_object_mutation_label(target, label)?;
            current = self.heap.get(target.0 as usize).and_then(|object| {
                let active_proxy = object.brand() == Some(PROXY_TYPE_TAG)
                    && !matches!(
                        object.properties.get(PROXY_REVOKED_SLOT),
                        Some(Value::Bool(true))
                    );
                active_proxy
                    .then(|| object.properties.get(PROXY_TARGET_SLOT))?
                    .and_then(|value| match value {
                        Value::Object(target) => Some(*target),
                        _ => None,
                    })
            });
        }
        Ok(())
    }

    pub(super) fn join_direct_object_mutation_label(
        &mut self,
        object_id: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let previous_bytes = self
            .object_mutation_labels
            .get(&object_id)
            .map_or(0, Self::estimate_object_mutation_label_entry_bytes);
        let next = self
            .object_mutation_labels
            .get(&object_id)
            .map_or_else(|| label.clone(), |current| current.join(label));
        let next_bytes = if next == Label::Public {
            0
        } else {
            Self::estimate_object_mutation_label_entry_bytes(&next)
        };
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        if next == Label::Public {
            self.object_mutation_labels.remove(&object_id);
        } else {
            self.object_mutation_labels.insert(object_id, next);
        }
        Ok(())
    }

    pub(super) fn process_dynamic_value_label(
        &self,
        value: &Value,
        visited: &mut BTreeSet<ObjectId>,
    ) -> Label {
        let Value::Object(object_id) = value else {
            return Label::Public;
        };
        if !visited.insert(*object_id) {
            return Label::Public;
        }
        let mut label = self
            .object_mutation_labels
            .get(object_id)
            .cloned()
            .unwrap_or(Label::Public)
            .join(&self.binary_storage_label(*object_id));
        if let Some(object) = self.heap.get(object_id.0 as usize) {
            // A join is order-insensitive: no per-key lookup for creation
            // order (bd-9vouw.333).
            for property in object.properties.values_unordered() {
                label = label.join(&self.process_dynamic_value_label(property, visited));
            }
        }
        label
    }

    pub(super) fn join_arg_range_with_object_mutation_label(
        &self,
        args: RegRange,
    ) -> Result<Label, InterpreterError> {
        let mut label = self.clone_active_execution_context_label()?;
        for offset in 0..args.count {
            let register =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            let value = self.read_reg(register)?;
            label = label
                .join(self.get_register_label(register)?)
                .join(&self.process_dynamic_value_label(&value, &mut BTreeSet::new()));
        }
        Ok(label)
    }

    pub(super) fn process_string_argument(
        &self,
        value: Option<&Value>,
        field: &str,
    ) -> Result<String, InterpreterError> {
        match value {
            Some(Value::Str(value)) => Ok(value.to_string()),
            Some(value) => Err(InterpreterError::TypeError {
                expected: format!("string child_process {field}"),
                got: value.type_name().to_string(),
            }),
            None => Err(InterpreterError::TypeError {
                expected: format!("string child_process {field}"),
                got: "missing argument".to_string(),
            }),
        }
    }

    pub(super) fn process_unsigned_option(
        value: &Value,
        field: &str,
    ) -> Result<u64, InterpreterError> {
        let number = match value {
            Value::Int(value) if *value >= 0 => u64::try_from(*value).unwrap_or(u64::MAX),
            Value::Float(value)
                if value.inner().is_finite()
                    && value.inner() >= 0.0
                    && value.inner().fract() == 0.0 =>
            {
                value.inner() as u64
            }
            value => {
                return Err(InterpreterError::TypeError {
                    expected: format!("non-negative integer child_process {field}"),
                    got: value.type_name().to_string(),
                });
            }
        };
        Ok(number)
    }

    pub(super) fn process_argv(
        &self,
        value: Option<&Value>,
    ) -> Result<Vec<String>, InterpreterError> {
        match value {
            None | Some(Value::Undefined | Value::Null) => Ok(Vec::new()),
            Some(Value::Object(object_id)) => self
                .array_like_values(*object_id)?
                .iter()
                .map(|value| match value {
                    Value::Str(value) => Ok(value.to_string()),
                    value => Err(InterpreterError::TypeError {
                        expected: "string child_process argv element".to_string(),
                        got: value.type_name().to_string(),
                    }),
                })
                .collect(),
            Some(value) => Err(InterpreterError::TypeError {
                expected: "child_process argv array".to_string(),
                got: value.type_name().to_string(),
            }),
        }
    }

    pub(super) fn process_is_array(&self, value: Option<&Value>) -> bool {
        matches!(
            value,
            Some(Value::Object(object_id))
                if self
                    .heap
                    .get(object_id.0 as usize)
                    .is_some_and(|object| object.is_array)
        )
    }

    pub(super) fn process_env(
        &self,
        value: &Value,
    ) -> Result<BTreeMap<String, String>, InterpreterError> {
        let Value::Object(object_id) = value else {
            return Err(InterpreterError::TypeError {
                expected: "child_process env object".to_string(),
                got: value.type_name().to_string(),
            });
        };
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        object
            .properties
            .iter()
            .map(|(key, value)| match value {
                Value::Str(value) => Ok((key.clone(), value.to_string())),
                value => Err(InterpreterError::TypeError {
                    expected: format!("string value for child_process env.{key}"),
                    got: value.type_name().to_string(),
                }),
            })
            .collect()
    }

    pub(super) fn process_call_options(
        &self,
        value: Option<&Value>,
    ) -> Result<ProcessCallOptions, InterpreterError> {
        let Some(value) = value else {
            return Ok(ProcessCallOptions::default());
        };
        if matches!(value, Value::Undefined | Value::Null) {
            return Ok(ProcessCallOptions::default());
        }
        let Value::Object(object_id) = value else {
            return Err(InterpreterError::TypeError {
                expected: "child_process options object".to_string(),
                got: value.type_name().to_string(),
            });
        };
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let mut options = ProcessCallOptions::default();
        if let Some(value) = object.properties.get("cwd") {
            options.cwd = Some(self.process_string_argument(Some(value), "cwd")?);
        }
        if let Some(value) = object.properties.get("env") {
            options.env = self.process_env(value)?;
        }
        if let Some(value) = object.properties.get("input") {
            options.input = self.fs_value_bytes(value)?;
        }
        if let Some(value) = object.properties.get("encoding") {
            options.encoding = Some(self.process_string_argument(Some(value), "encoding")?);
        }
        if let Some(value) = object.properties.get("shell") {
            options.shell = value.is_truthy();
        }
        if let Some(value) = object.properties.get("stdio") {
            let mode = self.process_string_argument(Some(value), "stdio")?;
            options.stdio = match mode.as_str() {
                "pipe" => ProcessStdio::default(),
                "ignore" => ProcessStdio {
                    stdin: ProcessStdioMode::Null,
                    stdout: ProcessStdioMode::Null,
                    stderr: ProcessStdioMode::Null,
                },
                _ => {
                    return Err(InterpreterError::TypeError {
                        expected: "child_process stdio value 'pipe' or 'ignore'".to_string(),
                        got: mode,
                    });
                }
            };
        }
        if let Some(value) = object.properties.get("timeout") {
            options.timeout_millis = Some(Self::process_unsigned_option(value, "timeout")?);
        }
        if let Some(value) = object.properties.get("maxBuffer") {
            options.max_buffer = Some(
                usize::try_from(Self::process_unsigned_option(value, "maxBuffer")?)
                    .unwrap_or(usize::MAX),
            );
        }
        Ok(options)
    }

    pub(super) fn process_launch(
        command: String,
        argv: Vec<String>,
        options: &ProcessCallOptions,
        force_shell: bool,
    ) -> ProcessLaunch {
        let shell = force_shell || options.shell;
        let (executable, argv) = if shell {
            (String::new(), vec![command])
        } else {
            (command, argv)
        };
        ProcessLaunch {
            executable,
            argv,
            env: options.env.clone(),
            cwd: options.cwd.clone(),
            shell,
            stdio: options.stdio,
        }
    }

    pub(super) fn process_error_from_effect(error: EffectError) -> InterpreterError {
        match error {
            EffectError::HandlerError {
                message,
                code: Some(code),
                ..
            } => InterpreterError::HostProcess {
                code: Self::node_code_for_process_spawn(&code).to_string(),
                message,
                status: None,
                signal: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            EffectError::HandlerStructuredFailure {
                message,
                code,
                payload,
                ..
            } => {
                let HandlerFailurePayload {
                    signal,
                    partial_stdout,
                    partial_stderr,
                } = payload.as_ref();
                InterpreterError::HostProcess {
                    code: Self::node_code_for_process_spawn(&code).to_string(),
                    message,
                    status: None,
                    signal: *signal,
                    stdout: partial_stdout.clone(),
                    stderr: partial_stderr.clone(),
                }
            }
            error => InterpreterError::InternalError {
                details: format!("process effect dispatch failed: {error}"),
            },
        }
    }

    /// Map a stable process-spawn domain code onto Node's guest-visible
    /// `err.code` spelling. Shared by the plain and structured handler
    /// failure arms so both shapes stay in lockstep (bd-k709s).
    pub(super) fn node_code_for_process_spawn(code: &str) -> &str {
        match code {
            PROCESS_SPAWN_EXECUTABLE_NOT_FOUND_CODE => "ENOENT",
            "PROCESS_SPAWN_TIMED_OUT" => "ETIMEDOUT",
            "PROCESS_SPAWN_LIMIT_EXCEEDED" => "ENOBUFS",
            "PROCESS_SPAWN_POLICY_VIOLATION"
            | "PROCESS_SPAWN_DENIED"
            | "PROCESS_SPAWN_CAPABILITY_MISSING" => "EACCES",
            other => other,
        }
    }

    pub(super) fn perform_process_request(
        &mut self,
        request: ProcessSpawnRequest,
        args_label: &Label,
    ) -> Result<ProcessSpawnResponse, InterpreterError> {
        let Some(provider) = self.process_spawn.clone() else {
            return Err(InterpreterError::CapabilityDenied {
                capability: "process_spawn provider admission".to_string(),
            });
        };
        let Some(journal) = self.host_effect_journal.clone() else {
            return Err(InterpreterError::InternalError {
                details: "process provider installed without host-effect journal".to_string(),
            });
        };
        if args_label != &Label::Public {
            let failure = ProcessSpawnError::FlowPolicyBlocked;
            // The current IFC refusal remains authoritative during replay.
            // Consume its exact recorded request and denial before returning;
            // a replay journal cannot append or dispatch a live provider call.
            match journal.replay_process_spawn_preparation_failure(&request, &failure) {
                Some(Err(ProcessSpawnError::FlowPolicyBlocked)) => {}
                Some(_) => {
                    return Err(InterpreterError::InternalError {
                        details: "recorded process IFC denial differs from the current refusal"
                            .to_string(),
                    });
                }
                None => {
                    let outcome = Err(failure);
                    journal
                        .record_process_spawn(&request, &outcome)
                        .map_err(|error| InterpreterError::InternalError {
                            details: format!("failed to journal process IFC denial: {error}"),
                        })?;
                }
            }
            return Err(InterpreterError::HostProcess {
                code: "EACCES".to_string(),
                message: "process spawn denied: FLOW_POLICY_BLOCKED".to_string(),
                status: None,
                signal: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
        }
        let effect = create_process_spawn_effect(request);
        let mut stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(provider),
            None,
            Some(journal),
        );
        stack
            .handle_effect(effect.as_ref())
            .map_err(Self::process_error_from_effect)?
            .downcast::<ProcessSpawnResponse>()
            .map_err(|_| InterpreterError::InternalError {
                details: "process effect returned an invalid response type".to_string(),
            })
    }

    pub(super) fn cleanup_process_handle(&self, handle: &str) -> Result<(), InterpreterError> {
        let Some(provider) = self.process_spawn.as_ref() else {
            return Err(InterpreterError::InternalError {
                details: "process cleanup requested without an admitted provider".to_string(),
            });
        };
        let Some(journal) = self.host_effect_journal.as_ref() else {
            return Err(InterpreterError::InternalError {
                details: "process cleanup requested without a host-effect journal".to_string(),
            });
        };
        let request = ProcessSpawnRequest::Cleanup {
            handle: handle.to_string(),
        };
        let outcome = if let Some(recorded) = journal.replay_process_spawn(&request) {
            recorded
        } else {
            let reservation = journal.reserve_process_spawn(&request).map_err(|error| {
                InterpreterError::InternalError {
                    details: format!("failed to reserve process cleanup: {error}"),
                }
            })?;
            let outcome = provider.cleanup_handle(handle);
            journal
                .complete_process_spawn(reservation, &request, &outcome)
                .map_err(|error| InterpreterError::InternalError {
                    details: format!("failed to journal process cleanup outcome: {error}"),
                })?;
            outcome
        };
        match outcome {
            Ok(ProcessSpawnResponse::Cleaned { .. }) => Ok(()),
            Ok(_) => Err(InterpreterError::InternalError {
                details: "process cleanup returned a non-cleanup response".to_string(),
            }),
            Err(error) => Err(InterpreterError::InternalError {
                details: format!("process cleanup failed: {error}"),
            }),
        }
    }

    pub(super) fn cleanup_process_handle_after_error(
        &self,
        handle: &str,
        primary: InterpreterError,
    ) -> InterpreterError {
        match self.cleanup_process_handle(handle) {
            Ok(()) => primary,
            Err(cleanup) => InterpreterError::InternalError {
                details: format!("{primary}; compensating process cleanup also failed: {cleanup}"),
            },
        }
    }

    pub(super) fn process_output_value(
        &mut self,
        bytes: &[u8],
        encoding: Option<&str>,
    ) -> Result<Value, InterpreterError> {
        let value = self.decode_fs_read_result(bytes, encoding)?;
        if let Value::Object(object_id) = &value {
            let output_label =
                hostcall_result_contract("process_spawn").result_label(&Label::Public, None);
            self.join_binary_storage_label(*object_id, &output_label)?;
        }
        Ok(value)
    }

    pub(super) fn process_run_error(
        exit: ProcessExit,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> InterpreterError {
        InterpreterError::HostProcess {
            code: "CHILD_PROCESS_EXIT".to_string(),
            message: format!("command failed with exit status {:?}", exit.code),
            status: exit.code,
            signal: exit.signal,
            stdout,
            stderr,
        }
    }

    pub(super) fn process_max_buffer_error(
        exit: ProcessExit,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> InterpreterError {
        InterpreterError::HostProcess {
            code: "ENOBUFS".to_string(),
            message: "child_process maxBuffer exceeded".to_string(),
            status: exit.code,
            signal: exit.signal,
            stdout,
            stderr,
        }
    }

    pub(super) fn process_sync_result(
        &mut self,
        response: ProcessSpawnResponse,
        options: &ProcessCallOptions,
    ) -> Result<Value, InterpreterError> {
        let ProcessSpawnResponse::Run {
            exit,
            stdout,
            stderr,
        } = response
        else {
            return Err(InterpreterError::InternalError {
                details: "process run returned a lifecycle response".to_string(),
            });
        };
        let ignored = options.stdio.stdout == ProcessStdioMode::Null;
        let stdout_value = if ignored {
            Value::Null
        } else {
            self.process_output_value(&stdout, options.encoding.as_deref())?
        };
        let stderr_value = if options.stdio.stderr == ProcessStdioMode::Null {
            Value::Null
        } else {
            self.process_output_value(&stderr, options.encoding.as_deref())?
        };
        let output = self.alloc_array_from_values(&[
            Value::Null,
            stdout_value.clone(),
            stderr_value.clone(),
        ])?;
        let result = self.alloc_object_with_properties(&[
            ("pid", Value::Int(1)),
            (
                "status",
                exit.code
                    .map_or(Value::Null, |code| Value::Int(i64::from(code))),
            ),
            (
                "signal",
                exit.signal
                    .map_or(Value::Null, |signal| Value::Int(i64::from(signal))),
            ),
            ("stdout", stdout_value),
            ("stderr", stderr_value),
            ("output", Value::Object(output)),
            ("error", Value::Undefined),
        ])?;
        Ok(Value::Object(result))
    }

    pub(super) fn process_spawn_sync_failure(
        &mut self,
        error: InterpreterError,
        encoding: Option<&str>,
    ) -> Result<Value, InterpreterError> {
        let thrown = self.native_error_to_thrown_value(&error)?;
        // bd-k709s: when the failure carries bounded partial stream output
        // (timeout, containment capture cap, or provider I/O), the sync
        // result exposes it Node-style instead of reporting null streams.
        let fields = match &error {
            InterpreterError::HostProcess {
                status,
                signal,
                stdout,
                stderr,
                ..
            } => Some((status, signal, stdout, stderr)),
            _ => None,
        };
        let (status_value, signal_value, stdout_value, stderr_value) = match fields {
            Some((status, signal, stdout, stderr)) => (
                status.map_or(Value::Null, |code| Value::Int(i64::from(code))),
                signal.map_or(Value::Null, |sig| Value::Int(i64::from(sig))),
                if stdout.is_empty() {
                    Value::Null
                } else {
                    self.process_output_value(stdout, encoding)?
                },
                if stderr.is_empty() {
                    Value::Null
                } else {
                    self.process_output_value(stderr, encoding)?
                },
            ),
            None => (Value::Null, Value::Null, Value::Null, Value::Null),
        };
        let result = self.alloc_object_with_properties(&[
            ("pid", Value::Int(0)),
            ("status", status_value),
            ("signal", signal_value),
            ("stdout", stdout_value),
            ("stderr", stderr_value),
            ("output", Value::Null),
            ("error", thrown),
        ])?;
        Ok(Value::Object(result))
    }

    /// Decode the bounded partial stream output carried by a child-process
    /// failure into Node's exec-callback `(error, stdout, stderr)` argument
    /// pair (bd-k709s). Failures without captured output keep the historic
    /// empty-string arguments.
    pub(super) fn process_failure_callback_args(
        &mut self,
        error: &InterpreterError,
        options: &ProcessCallOptions,
    ) -> Result<(Value, Value), InterpreterError> {
        match error {
            InterpreterError::HostProcess { stdout, stderr, .. } => {
                let stdout_value = if stdout.is_empty() {
                    Value::str("")
                } else {
                    self.process_output_value(stdout, options.encoding.as_deref())?
                };
                let stderr_value = if stderr.is_empty() {
                    Value::str("")
                } else {
                    self.process_output_value(stderr, options.encoding.as_deref())?
                };
                Ok((stdout_value, stderr_value))
            }
            _ => Ok((Value::str(""), Value::str(""))),
        }
    }
    pub(super) fn allocate_child_process_facade(
        &mut self,
        options: &ProcessCallOptions,
    ) -> Result<ObjectId, InterpreterError> {
        let stdout_stream = if options.stdio.stdout == ProcessStdioMode::Null {
            None
        } else {
            Some(self.alloc_branded_object("ChildProcessStream", &[])?)
        };
        let stderr_stream = if options.stdio.stderr == ProcessStdioMode::Null {
            None
        } else {
            Some(self.alloc_branded_object("ChildProcessStream", &[])?)
        };
        // bd-m42c2: a piped stdin gets a guest-writable facade backed by the
        // provider's bounded writer; `write`/`end` resolve through this
        // object to the owning child's opaque handle.
        let stdin_stream = if options.stdio.stdin == ProcessStdioMode::Null {
            None
        } else {
            Some(self.alloc_branded_object("ChildProcessStdin", &[])?)
        };
        let child = self.alloc_branded_object(
            "ChildProcess",
            &[
                ("pid", Value::Int(1)),
                ("killed", Value::Bool(false)),
                ("stdout", stdout_stream.map_or(Value::Null, Value::Object)),
                ("stderr", stderr_stream.map_or(Value::Null, Value::Object)),
                (
                    "stdin",
                    stdin_stream.map_or(Value::Undefined, Value::Object),
                ),
            ],
        )?;
        let stream_entries = u64::from(stdout_stream.is_some())
            + u64::from(stderr_stream.is_some())
            + u64::from(stdin_stream.is_some());
        let retained_stream_bytes =
            stream_entries.saturating_mul(MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(
                std::mem::size_of::<(ObjectId, (ObjectId, ChildProcessStreamKind))>() as u64,
            ));
        self.apply_memory_component_delta(0, retained_stream_bytes)?;
        if let Some(stream) = stdout_stream {
            self.child_process_streams
                .insert(stream, (child, ChildProcessStreamKind::Stdout));
        }
        if let Some(stream) = stderr_stream {
            self.child_process_streams
                .insert(stream, (child, ChildProcessStreamKind::Stderr));
        }
        if let Some(stream) = stdin_stream {
            self.child_process_streams
                .insert(stream, (child, ChildProcessStreamKind::Stdin));
        }
        Ok(child)
    }

    pub(super) fn pending_child_process_state() -> CompletedChildProcessState {
        CompletedChildProcessState {
            settled: false,
            stdout: Value::Null,
            stdout_has_data: false,
            stderr: Value::Null,
            stderr_has_data: false,
            exit_code: Value::Null,
            signal: Value::Null,
            error: None,
            scheduled_events: BTreeSet::new(),
        }
    }

    pub(super) fn replace_child_process_state(
        &mut self,
        child: ObjectId,
        state: CompletedChildProcessState,
    ) -> Result<(), InterpreterError> {
        let previous_bytes = self
            .completed_child_processes
            .get(&child)
            .map(Self::estimate_completed_child_process_state_bytes)
            .unwrap_or(0);
        let next_bytes = Self::estimate_completed_child_process_state_bytes(&state);
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.completed_child_processes.insert(child, state);
        Ok(())
    }

    pub(super) fn remove_child_process_state(&mut self, child: ObjectId) {
        if let Some(state) = self.completed_child_processes.remove(&child) {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(Self::estimate_completed_child_process_state_bytes(&state));
        }
        // bd-m42c2: the opaque provider handle dies with the facade's
        // lifecycle state, so post-settle kill()/stdin.write fail closed.
        if let Some(handle) = self.child_process_handles.remove(&child) {
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(Self::estimate_string_bytes(&handle)),
            );
        }
    }

    pub(super) fn settle_child_process(
        &mut self,
        child: ObjectId,
        outcome: Result<(ProcessExit, Vec<u8>, Vec<u8>), InterpreterError>,
    ) -> Result<(), InterpreterError> {
        let (exit_code, signal, stdout, stdout_has_data, stderr, stderr_has_data, error) =
            match outcome {
                Ok((exit, stdout, stderr)) => {
                    let stdout_has_data = !stdout.is_empty();
                    let stderr_has_data = !stderr.is_empty();
                    let stdout = self.process_output_value(&stdout, None)?;
                    let stderr = self.process_output_value(&stderr, None)?;
                    (
                        exit.code
                            .map_or(Value::Null, |code| Value::Int(i64::from(code))),
                        exit.signal
                            .map_or(Value::Null, |signal| Value::Int(i64::from(signal))),
                        stdout,
                        stdout_has_data,
                        stderr,
                        stderr_has_data,
                        None,
                    )
                }
                Err(error) => (
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    false,
                    Value::Null,
                    false,
                    Some(self.native_error_to_thrown_value(&error)?),
                ),
            };
        let scheduled_events = self
            .completed_child_processes
            .get(&child)
            .map(|state| state.scheduled_events.clone())
            .unwrap_or_default();
        self.replace_child_process_state(
            child,
            CompletedChildProcessState {
                settled: true,
                stdout,
                stdout_has_data,
                stderr,
                stderr_has_data,
                exit_code,
                signal,
                error,
                scheduled_events,
            },
        )
    }

    pub(super) fn activate_completed_child_process_event(
        &mut self,
        target: ObjectId,
        event: &str,
    ) -> Result<Option<u64>, InterpreterError> {
        let (child, stream_kind) = self
            .child_process_streams
            .get(&target)
            .copied()
            .map_or((target, None), |(child, kind)| (child, Some(kind)));
        let Some(state) = self.completed_child_processes.get_mut(&child) else {
            return Ok(None);
        };
        let event_key =
            stream_kind.map_or_else(|| event.to_string(), |kind| format!("{kind:?}:{event}"));
        if state.scheduled_events.contains(&event_key) {
            return Ok(None);
        }
        if event != "spawn" && !state.settled {
            return Ok(None);
        }
        let arguments = match (stream_kind, event) {
            (Some(ChildProcessStreamKind::Stdout), "data") if state.stdout_has_data => {
                vec![state.stdout.clone()]
            }
            (Some(ChildProcessStreamKind::Stderr), "data") if state.stderr_has_data => {
                vec![state.stderr.clone()]
            }
            (None, "error") => state
                .error
                .clone()
                .map_or_else(Vec::new, |error| vec![error]),
            (None, "spawn") if state.error.is_none() => Vec::new(),
            (None, "exit") if state.error.is_none() => {
                vec![
                    state.exit_code.clone(),
                    Self::child_signal_event_value(&state.signal),
                ]
            }
            (None, "close") => vec![
                state.exit_code.clone(),
                Self::child_signal_event_value(&state.signal),
            ],
            _ => return Ok(None),
        };
        let event_key_bytes =
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(Self::estimate_string_bytes(&event_key));
        self.apply_memory_component_delta(0, event_key_bytes)?;
        let Some(state) = self.completed_child_processes.get_mut(&child) else {
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(event_key_bytes);
            return Ok(None);
        };
        state.scheduled_events.insert(event_key.clone());
        match self.schedule_child_process_event_task(PendingHttpTask::EmitLegacyEvent {
            target,
            event: event.to_string(),
            arguments,
            leading_callback: None,
            label: hostcall_result_contract("process_spawn").result_label(&Label::Public, None),
        }) {
            Ok(sequence) => Ok(Some(sequence)),
            Err(error) => {
                if let Some(state) = self.completed_child_processes.get_mut(&child) {
                    state.scheduled_events.remove(&event_key);
                }
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(event_key_bytes);
                Err(error)
            }
        }
    }

    pub(super) fn execute_pending_child_process_task(
        &mut self,
        task: PendingChildProcessTask,
        _module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let response = self.perform_process_request(
            ProcessSpawnRequest::Wait {
                handle: task.handle.clone(),
                timeout_millis: task.options.timeout_millis,
            },
            &Label::Public,
        );
        let (settlement, callback_arguments) = match response {
            Ok(ProcessSpawnResponse::Waited {
                exit,
                stdout,
                stderr,
            }) if task
                .options
                .max_buffer
                .is_some_and(|maximum| stdout.len() > maximum || stderr.len() > maximum) =>
            {
                let error = Self::process_max_buffer_error(exit, stdout, stderr);
                let thrown = self.native_error_to_thrown_value(&error)?;
                (Err(error), vec![thrown, Value::str(""), Value::str("")])
            }
            // bd-m42c2: a lifecycle kill is a final outcome; the provider
            // reports it as `Killed` with the same exit/output payload shape
            // as a natural `Waited` completion.
            Ok(
                response @ (ProcessSpawnResponse::Waited { .. }
                | ProcessSpawnResponse::Killed { .. }),
            ) => {
                let (exit, stdout, stderr) = match response {
                    ProcessSpawnResponse::Waited {
                        exit,
                        stdout,
                        stderr,
                    }
                    | ProcessSpawnResponse::Killed {
                        exit,
                        stdout,
                        stderr,
                        ..
                    } => (exit, stdout, stderr),
                    _ => unreachable!("arm pattern above"),
                };
                let (stdout_value, stderr_value) =
                    if let Some(encoding) = task.callback_encoding.as_deref() {
                        (
                            self.process_output_value(&stdout, Some(encoding))?,
                            self.process_output_value(&stderr, Some(encoding))?,
                        )
                    } else {
                        (Value::Undefined, Value::Undefined)
                    };
                let error_value = if exit.success {
                    Value::Null
                } else {
                    let error = Self::process_run_error(exit, stdout.clone(), stderr.clone());
                    self.native_error_to_thrown_value(&error)?
                };
                (
                    Ok((exit, stdout, stderr)),
                    vec![error_value, stdout_value, stderr_value],
                )
            }
            Ok(response) => {
                let error = InterpreterError::InternalError {
                    // ProcessSpawnResponse's custom Debug prints byte
                    // lengths only, so this stays redaction-safe.
                    details: format!("process wait returned a non-wait response: {response:?}"),
                };
                return Err(self.cleanup_process_handle_after_error(&task.handle, error));
            }
            Err(error) => {
                self.cleanup_process_handle(&task.handle)?;
                let thrown = self.native_error_to_thrown_value(&error)?;
                (Err(error), vec![thrown, Value::str(""), Value::str("")])
            }
        };
        self.settle_child_process(task.child, settlement)?;
        // bd-m42c2: the native lifecycle is over; drop the opaque handle so
        // later kill()/stdin.write from guest code fail closed.
        if let Some(handle) = self.child_process_handles.remove(&task.child) {
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(Self::estimate_string_bytes(&handle)),
            );
        }
        let streams = self
            .child_process_streams
            .iter()
            .filter_map(|(stream, (child, _))| (*child == task.child).then_some(*stream))
            .collect::<Vec<_>>();
        for stream in streams {
            self.activate_completed_child_process_event(stream, "data")?;
        }
        let failed = self
            .completed_child_processes
            .get(&task.child)
            .is_some_and(|state| state.error.is_some());
        if failed {
            if let Some(callback) = task.callback {
                self.schedule_child_process_callback(
                    callback,
                    callback_arguments,
                    &task.callback_label,
                )?;
            }
            self.activate_completed_child_process_event(task.child, "error")?;
        } else {
            self.activate_completed_child_process_event(task.child, "exit")?;
            if let Some(callback) = task.callback {
                self.schedule_child_process_callback(
                    callback,
                    callback_arguments,
                    &task.callback_label,
                )?;
            }
        }
        self.activate_completed_child_process_event(task.child, "close")?;
        Ok(())
    }

    /// Resolve the owning child facade and its opaque provider handle for a
    /// `ChildProcess` or `ChildProcessStdin` receiver (bd-m42c2). Fails
    /// closed when no live lifecycle is registered.
    pub(super) fn child_process_receiver(
        &self,
        receiver: &Value,
    ) -> Result<(ObjectId, String), InterpreterError> {
        let Value::Object(object_id) = receiver else {
            return Err(InterpreterError::InternalError {
                details: "child process method called without an object receiver".to_string(),
            });
        };
        let child = self
            .child_process_streams
            .get(object_id)
            .map(|(child, _)| *child)
            .unwrap_or(*object_id);
        let Some(handle) = self.child_process_handles.get(&child) else {
            return Err(InterpreterError::ObjectNotFound { id: child.0 });
        };
        Ok((child, handle.clone()))
    }

    /// Node-compatible signal spelling for child-process exit/close events
    /// (bd-m42c2): known unix signals report their `SIG*` name; unknown or
    /// absent values pass through unchanged.
    pub(super) fn child_signal_event_value(signal: &Value) -> Value {
        match signal {
            Value::Int(code) => match code {
                1 => Value::str("SIGHUP"),
                2 => Value::str("SIGINT"),
                3 => Value::str("SIGQUIT"),
                6 => Value::str("SIGABRT"),
                9 => Value::str("SIGKILL"),
                15 => Value::str("SIGTERM"),
                _ => signal.clone(),
            },
            other => other.clone(),
        }
    }

    /// Provider-backed `child.kill([signal])` (bd-m42c2). The default signal
    /// is SIGTERM like Node. Denials and capability failures surface as
    /// typed errors; a dead or unknown lifecycle reports `false` instead of
    /// throwing, matching kill-after-exit semantics.
    pub(super) fn child_process_kill(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (_child, handle) = self.child_process_receiver(&receiver)?;
        // Possession of a previously authorized handle does not authorize a
        // later effect. Keep this outside the provider-error-to-false adapter:
        // a containment request must stop execution, not become a false result.
        check_hostcall_capability_gate(self, "process_spawn", self.ip as u32)?;
        let signal = match self.builtin_arg(args, 0)? {
            None | Some(Value::Null) | Some(Value::Undefined) => ProcessSignal::Terminate,
            Some(value @ Value::Str(_)) => {
                let upper = self.value_to_string(&value).to_ascii_uppercase();
                match upper.as_str() {
                    "SIGTERM" | "TERM" => ProcessSignal::Terminate,
                    "SIGKILL" | "KILL" => ProcessSignal::Kill,
                    "SIGINT" | "INT" => ProcessSignal::Interrupt,
                    other => {
                        return Err(InterpreterError::TypeError {
                            expected: format!("a known child-process signal, got {other}"),
                            got: self.value_to_string(&value),
                        });
                    }
                }
            }
            Some(other) => {
                return Err(InterpreterError::TypeError {
                    expected: "a signal name string".to_string(),
                    got: self.value_to_string(&other),
                });
            }
        };
        let killed = self
            .perform_process_request(ProcessSpawnRequest::Kill { handle, signal }, &Label::Public);
        // bd-m42c2: denials stay typed refusals; a dead or unknown lifecycle
        // reports `false` like Node's kill-after-exit.
        let denial = matches!(
            &killed,
            Err(InterpreterError::HostProcess { code, .. })
                if code == "EACCES" || code == "FLOW_POLICY_BLOCKED"
        ) || matches!(
            killed,
            Err(InterpreterError::CapabilityDenied { .. })
                | Err(InterpreterError::InternalError { .. })
        );
        if denial {
            return Err(killed.unwrap_err());
        }
        if killed.is_ok()
            && let Value::Object(child) = receiver
            && self.completed_child_processes.contains_key(&child)
        {
            self.set_object_property(child, "killed".to_string(), Value::Bool(true))?;
        }
        Ok(Value::Bool(killed.is_ok()))
    }

    /// Bounded `child.stdin.write(chunk)` (bd-m42c2). Bytes are accepted
    /// against the cumulative `max_stdin_bytes` bound and drained by the
    /// provider's dedicated writer thread; the interpreter never blocks on
    /// pipe backpressure.
    pub(super) fn child_process_stdin_write(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (_child, handle) = self.child_process_receiver(&receiver)?;
        check_hostcall_capability_gate(self, "process_spawn", self.ip as u32)?;
        let chunk = self.builtin_arg(args, 0)?.unwrap_or(Value::str(""));
        // The child handle is an engine-owned lifecycle identity, not bytes
        // sent to the process. Preserve the actual payload's register and
        // backing-storage provenance, including the active callback context.
        // A Public alias of a Secret Buffer must not launder its stored bytes.
        let request_label = self
            .writable_invocation_label(args)?
            .join(&self.process_dynamic_value_label(&chunk, &mut BTreeSet::new()));
        let data = self.fs_value_bytes(&chunk)?;
        match self.perform_process_request(
            ProcessSpawnRequest::WriteStdin { handle, data },
            &request_label,
        ) {
            Ok(_) => Ok(Value::Bool(true)),
            Err(error) => Err(error),
        }
    }

    /// `child.stdin.end()` (bd-m42c2): closes the pipe through the writer
    /// thread, delivering EOF to the child.
    pub(super) fn child_process_stdin_end(
        &mut self,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let (_child, handle) = self.child_process_receiver(&receiver)?;
        check_hostcall_capability_gate(self, "process_spawn", self.ip as u32)?;
        match self
            .perform_process_request(ProcessSpawnRequest::CloseStdin { handle }, &Label::Public)
        {
            Ok(_) => Ok(Value::Undefined),
            Err(error) => Err(error),
        }
    }

    pub(super) fn dispatch_process_spawn_hostcall(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let operation = self.builtin_arg(args, 0)?;
        let discriminator = self.process_string_argument(operation.as_ref(), "operation")?;
        let logical_args = RegRange {
            start: args
                .start
                .checked_add(1)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?,
            count: args.count.saturating_sub(1),
        };
        self.dispatch_process_spawn_operation(&discriminator, logical_args)
    }

    /// The raw authenticated hostcall and first-class module exports share
    /// exactly one request parser, IFC check, provider and journal path.
    /// Arguments keep their original registers and labels; no synthetic
    /// prefix can clobber a caller register or relabel a callback.
    pub(super) fn dispatch_process_spawn_operation(
        &mut self,
        discriminator: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let mut values = Vec::with_capacity(args.count as usize);
        let mut labels = Vec::with_capacity(args.count as usize);
        for offset in 0..args.count {
            let register =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            labels.push(self.get_register_label(register)?.clone());
            values.push(self.read_reg(register)?);
        }
        let logical = values.as_slice();
        let command = self.process_string_argument(logical.first(), "command")?;
        let (argv, options_value, callback, callback_argument_index, request_argument_count) =
            match discriminator {
                "\0processop:spawn_sync" | "\0processop:spawn" | "\0processop:exec_file_sync" => {
                    if self.process_is_array(logical.get(1)) {
                        (
                            self.process_argv(logical.get(1))?,
                            logical.get(2),
                            None,
                            None,
                            logical.len().min(3),
                        )
                    } else {
                        (Vec::new(), logical.get(1), None, None, logical.len().min(2))
                    }
                }
                "\0processop:exec_sync" => (Vec::new(), logical.get(1), None, None, 2),
                "\0processop:exec" => {
                    let (options, callback_value, callback_argument_index) =
                        if logical.get(1).is_some_and(Value::is_callable) {
                            (None, logical.get(1), Some(1))
                        } else {
                            (logical.get(1), logical.get(2), Some(2))
                        };
                    let request_argument_count = if options.is_some() { 2 } else { 1 };
                    (
                        Vec::new(),
                        options,
                        callback_value,
                        callback_argument_index,
                        request_argument_count,
                    )
                }
                "\0processop:exec_file" => {
                    if self.process_is_array(logical.get(1)) {
                        let (callback_value, callback_argument_index) =
                            if logical.get(2).is_some_and(Value::is_callable) {
                                (logical.get(2), Some(2))
                            } else {
                                (logical.get(3), Some(3))
                            };
                        let options = if logical.get(2).is_some_and(Value::is_callable) {
                            None
                        } else {
                            logical.get(2)
                        };
                        let request_argument_count = if options.is_some() { 3 } else { 2 };
                        (
                            self.process_argv(logical.get(1))?,
                            options,
                            callback_value,
                            callback_argument_index,
                            request_argument_count,
                        )
                    } else {
                        let (callback_value, callback_argument_index) =
                            if logical.get(1).is_some_and(Value::is_callable) {
                                (logical.get(1), Some(1))
                            } else {
                                (logical.get(2), Some(2))
                            };
                        let options = if logical.get(1).is_some_and(Value::is_callable) {
                            None
                        } else {
                            logical.get(1)
                        };
                        let request_argument_count = if options.is_some() { 2 } else { 1 };
                        (
                            Vec::new(),
                            options,
                            callback_value,
                            callback_argument_index,
                            request_argument_count,
                        )
                    }
                }
                _ => {
                    return Err(InterpreterError::InternalError {
                        details: "unrecognized authenticated child_process operation".to_string(),
                    });
                }
            };
        let request_label_seed = self.clone_active_execution_context_label()?;
        let request_label = labels
            .iter()
            .zip(logical.iter())
            .take(request_argument_count)
            .fold(request_label_seed, |joined, (label, value)| {
                joined
                    .join(label)
                    .join(&self.process_dynamic_value_label(value, &mut BTreeSet::new()))
            });
        let options = self.process_call_options(options_value)?;
        let force_shell = matches!(discriminator, "\0processop:exec_sync" | "\0processop:exec");
        let launch = Self::process_launch(command, argv, &options, force_shell);
        let async_operation = matches!(
            discriminator,
            "\0processop:spawn" | "\0processop:exec" | "\0processop:exec_file"
        );
        let callback_id = match callback {
            Some(Value::Closure(callback)) => Some(*callback),
            None | Some(Value::Undefined) => None,
            Some(value) => {
                return Err(InterpreterError::TypeError {
                    expected: "closure-backed child_process callback".to_string(),
                    got: value.type_name().to_string(),
                });
            }
        };
        let callback_label = callback_id
            .and(callback_argument_index)
            .and_then(|index| labels.get(index))
            .cloned()
            .unwrap_or(Label::Public);
        if async_operation {
            if !options.input.is_empty() {
                return Err(InterpreterError::TypeError {
                    expected: "async child_process input through bounded stdin lifecycle"
                        .to_string(),
                    got: "non-empty input option".to_string(),
                });
            }
            let child = self.allocate_child_process_facade(&options)?;
            match self
                .perform_process_request(ProcessSpawnRequest::Spawn { launch }, &request_label)
            {
                Ok(ProcessSpawnResponse::Spawned { handle }) => {
                    // bd-m42c2: keep the opaque handle reachable for
                    // kill/stdin while the lifecycle is pending. Charged here,
                    // released with the facade state.
                    let handle_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add(Self::estimate_string_bytes(&handle));
                    self.apply_memory_component_delta(0, handle_bytes)?;
                    self.child_process_handles.insert(child, handle.clone());
                    if let Err(error) =
                        self.replace_child_process_state(child, Self::pending_child_process_state())
                    {
                        return Err(self.cleanup_process_handle_after_error(&handle, error));
                    }
                    let spawn_sequence =
                        match self.activate_completed_child_process_event(child, "spawn") {
                            Ok(Some(sequence)) => sequence,
                            Ok(None) => {
                                self.remove_child_process_state(child);
                                let error = InterpreterError::InternalError {
                                    details: "spawn event was not scheduled for a live process"
                                        .to_string(),
                                };
                                return Err(self.cleanup_process_handle_after_error(&handle, error));
                            }
                            Err(error) => {
                                self.remove_child_process_state(child);
                                return Err(self.cleanup_process_handle_after_error(&handle, error));
                            }
                        };
                    if let Err(error) = self.schedule_child_process_wait(PendingChildProcessTask {
                        child,
                        handle: handle.clone(),
                        callback: callback_id,
                        callback_label: callback_label.clone(),
                        callback_encoding: callback_id.map(|_| {
                            options
                                .encoding
                                .clone()
                                .unwrap_or_else(|| "utf8".to_string())
                        }),
                        options,
                    }) {
                        self.cancel_http_task_registration(spawn_sequence);
                        self.remove_child_process_state(child);
                        return Err(self.cleanup_process_handle_after_error(&handle, error));
                    }
                }
                Ok(_) => {
                    return Err(InterpreterError::InternalError {
                        details: "process spawn returned a non-lifecycle response".to_string(),
                    });
                }
                Err(error @ InterpreterError::CapabilityDenied { .. })
                | Err(error @ InterpreterError::InternalError { .. }) => return Err(error),
                Err(error)
                    if matches!(
                        &error,
                        InterpreterError::HostProcess { message, .. }
                            if message.contains("FLOW_POLICY_BLOCKED")
                    ) =>
                {
                    return Err(error);
                }
                Err(error) => {
                    self.settle_child_process(child, Err(error.clone()))?;
                    if let Some(callback) = callback_id {
                        let thrown = self.native_error_to_thrown_value(&error)?;
                        self.schedule_child_process_callback(
                            callback,
                            vec![thrown, Value::str(""), Value::str("")],
                            &callback_label,
                        )?;
                    }
                    // Spawn failures are lifecycle events in their own right.
                    // Queue them even when no listener exists yet so a bare
                    // unhandled `error` reaches the eval boundary; synchronous
                    // listener registration can still observe the deferred
                    // emission before this Immediate turn executes.
                    self.activate_completed_child_process_event(child, "error")?;
                    self.activate_completed_child_process_event(child, "close")?;
                }
            }
            return Ok(Value::Object(child));
        }
        let request = ProcessSpawnRequest::Run {
            launch,
            stdin: options.input.clone(),
            timeout_millis: options.timeout_millis,
        };
        let response = match self.perform_process_request(request, &request_label) {
            Ok(response) => response,
            Err(error) if discriminator == "\0processop:spawn_sync" => {
                return self.process_spawn_sync_failure(error, options.encoding.as_deref());
            }
            Err(error) => {
                if let Some(Value::Closure(callback)) = callback {
                    // Node's exec callback receives (error, stdout, stderr);
                    // bd-k709s retains the bounded partial bytes captured
                    // before containment so they reach the callback args and
                    // the thrown error's stdout/stderr properties alike.
                    let callback_args = self.process_failure_callback_args(&error, &options)?;
                    let thrown = self.native_error_to_thrown_value(&error)?;
                    self.schedule_io_callback_with_label(
                        *callback,
                        vec![thrown, callback_args.0, callback_args.1],
                        hostcall_result_contract("process_spawn")
                            .result_label(&callback_label, None),
                    )?;
                    return Ok(Value::Undefined);
                }
                return Err(error);
            }
        };
        let ProcessSpawnResponse::Run {
            exit,
            stdout,
            stderr,
        } = response
        else {
            return Err(InterpreterError::InternalError {
                details: "process run returned a lifecycle response".to_string(),
            });
        };
        if options
            .max_buffer
            .is_some_and(|maximum| stdout.len() > maximum || stderr.len() > maximum)
        {
            let error = Self::process_max_buffer_error(exit, stdout, stderr);
            if discriminator == "\0processop:spawn_sync" {
                return self.process_spawn_sync_failure(error, options.encoding.as_deref());
            }
            if let Some(Value::Closure(callback)) = callback {
                let callback_args = self.process_failure_callback_args(&error, &options)?;
                let thrown = self.native_error_to_thrown_value(&error)?;
                self.schedule_io_callback_with_label(
                    *callback,
                    vec![thrown, callback_args.0, callback_args.1],
                    hostcall_result_contract("process_spawn").result_label(&callback_label, None),
                )?;
            }
            return Err(error);
        }
        match discriminator {
            "\0processop:spawn_sync" => self.process_sync_result(
                ProcessSpawnResponse::Run {
                    exit,
                    stdout,
                    stderr,
                },
                &options,
            ),
            "\0processop:exec_sync" | "\0processop:exec_file_sync" => {
                if !exit.success {
                    return Err(Self::process_run_error(exit, stdout, stderr));
                }
                self.process_output_value(&stdout, options.encoding.as_deref())
            }
            "\0processop:exec" | "\0processop:exec_file" | "\0processop:spawn" => {
                unreachable!("async operations return after scheduling their lifecycle wait")
            }
            _ => unreachable!("discriminator validated above"),
        }
    }

    pub(super) fn fs_object_property(&self, value: &Value, key: &str) -> Option<Value> {
        let Value::Object(object_id) = value else {
            return None;
        };
        self.heap
            .get(object_id.0 as usize)
            .and_then(|object| object.properties.get(key))
            .cloned()
    }

    pub(super) fn fs_value_bytes(&self, value: &Value) -> Result<Vec<u8>, InterpreterError> {
        match value {
            Value::Str(value) => Ok(value.as_bytes().to_vec()),
            Value::Object(object_id) => {
                let Some(view) = self.typed_array_view_for_object(*object_id)? else {
                    return Ok(self.value_to_string(value).into_bytes());
                };
                let values = self.typed_array_values_in_range(&view, 0, view.length)?;
                Ok(values.iter().map(Self::typed_array_u8_value).collect())
            }
            other => Ok(self.value_to_string(other).into_bytes()),
        }
    }

    /// Filesystem arguments are not arbitrary string-coercion sites. In
    /// particular, an omitted write payload must fail before an existing
    /// file can be truncated, and a view denotes its bytes, not its numeric
    /// elements or its public `buffer`/`byteOffset` properties.
    pub(super) fn fs_write_data_bytes(
        &self,
        value: Option<&Value>,
    ) -> Result<Vec<u8>, InterpreterError> {
        match value {
            Some(Value::Str(text)) => {
                self.check_temporary_memory_budget(u64::try_from(text.len()).unwrap_or(u64::MAX))?;
                Ok(text.as_bytes().to_vec())
            }
            Some(value @ Value::Object(object_id)) => {
                let object = self
                    .heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                if let Some(view) = &object.typed_array {
                    Self::reject_out_of_bounds_typed_array(view, "filesystem write")?;
                } else if let Some(view) = &object.data_view {
                    Self::reject_out_of_bounds_data_view(view, "filesystem write")?;
                } else {
                    return Err(InterpreterError::TypeError {
                        expected: "filesystem data of type string or ArrayBufferView".to_string(),
                        got: "ordinary object".to_string(),
                    });
                }
                // This shared native helper authenticates the backing store,
                // checks its byte range and admits the copy before allocating.
                self.crypto_binary_view_bytes_with_mode(value, false)
            }
            other => Err(InterpreterError::TypeError {
                expected: "filesystem data of type string or ArrayBufferView".to_string(),
                got: other.map_or("undefined", Value::type_name).to_string(),
            }),
        }
    }

    pub(super) fn fs_path_argument(
        &self,
        value: Option<&Value>,
    ) -> Result<String, InterpreterError> {
        let path = match value {
            Some(Value::Str(text)) => {
                self.check_temporary_memory_budget(u64::try_from(text.len()).unwrap_or(u64::MAX))?;
                text.to_string()
            }
            Some(value @ Value::Object(_)) => {
                let view = self.buffer_like_view(value)?;
                Self::reject_out_of_bounds_typed_array(&view, "filesystem path")?;
                String::from_utf8(self.bytes_for_typed_array_view(&view)?).map_err(|_| {
                    InterpreterError::TypeError {
                        expected: "a UTF-8 filesystem path".to_string(),
                        got: "non-UTF-8 path bytes".to_string(),
                    }
                })?
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "filesystem path of type string, Buffer or Uint8Array".to_string(),
                    got: other.map_or("undefined", Value::type_name).to_string(),
                });
            }
        };
        if path.contains('\0') {
            return Err(InterpreterError::TypeError {
                expected: "filesystem path without NUL bytes".to_string(),
                got: "path containing a NUL byte".to_string(),
            });
        }
        Ok(path)
    }

    pub(super) fn fs_value_argument(&self, value: &Value) -> String {
        match value {
            Value::Str(value) => value.to_string(),
            Value::Int(value) => value.to_string(),
            Value::Float(value) => value.to_string(),
            Value::Bool(value) => value.to_string(),
            Value::Null | Value::Undefined => String::new(),
            Value::Object(object_id) => self
                .heap
                .get(object_id.0 as usize)
                .and_then(HeapObject::date_time)
                .map_or_else(
                    || self.value_to_string(value),
                    |timestamp| self.value_to_string(&Value::Float(Float64::new(timestamp))),
                ),
            other => self.value_to_string(other),
        }
    }

    pub(super) fn fs_option_is_true(&self, value: Option<&Value>, key: &str) -> bool {
        value
            .and_then(|options| self.fs_object_property(options, key))
            .is_some_and(|value| matches!(value, Value::Bool(true)))
    }

    pub(super) fn fs_operation_arguments(
        &self,
        operation: FsOperation,
        args: &[Value],
    ) -> Result<Vec<String>, InterpreterError> {
        Ok(match operation {
            FsOperation::Mkdir => vec![format!(
                "recursive={}",
                self.fs_option_is_true(args.get(1), "recursive")
            )],
            FsOperation::ReadDir => vec![format!(
                "with_file_types={}",
                self.fs_option_is_true(args.get(1), "withFileTypes")
            )],
            FsOperation::Remove => vec![
                format!(
                    "recursive={}",
                    self.fs_option_is_true(args.get(1), "recursive")
                ),
                format!("force={}", self.fs_option_is_true(args.get(1), "force")),
            ],
            FsOperation::Symlink | FsOperation::Rename | FsOperation::CopyFile => {
                vec![self.fs_path_argument(args.get(1))?]
            }
            FsOperation::Truncate | FsOperation::Chmod => args
                .get(1)
                .map_or_else(Vec::new, |value| vec![self.fs_value_argument(value)]),
            FsOperation::Utimes => args
                .iter()
                .skip(1)
                .take(2)
                .map(|value| self.fs_value_argument(value))
                .collect(),
            // Numeric fd lifecycle (bd-zco6t). Open's arg0 is the path (kept
            // as the effect path); every other fd op identifies its target by
            // the `fd=` argument, never a path.
            FsOperation::Open => vec![format!(
                "flags={}",
                args.get(1)
                    .map_or_else(|| "r".to_string(), |value| self.fs_value_argument(value))
            )],
            FsOperation::WriteFd | FsOperation::Fsync | FsOperation::CloseFd => vec![format!(
                "fd={}",
                args.first()
                    .map_or_else(String::new, |value| self.fs_value_argument(value))
            )],
            FsOperation::ReadFd => {
                // readSync(fd, buffer, offset, length, position): length
                // defaults to the target buffer's element length; position
                // omitted/null means "read at the cursor".
                let fd = args
                    .first()
                    .map_or_else(String::new, |value| self.fs_value_argument(value));
                let length = match args.get(3) {
                    Some(Value::Int(length)) => *length,
                    _ => match args.get(1) {
                        Some(Value::Object(buffer_id)) => self
                            .typed_array_view_for_object(*buffer_id)
                            .ok()
                            .flatten()
                            .map_or(0, |view| i64::try_from(view.length).unwrap_or(0)),
                        _ => 0,
                    },
                };
                let mut arguments = vec![format!("fd={fd}"), format!("length={length}")];
                if let Some(Value::Int(position)) = args.get(4) {
                    arguments.push(format!("position={position}"));
                }
                arguments
            }
            FsOperation::Read
            | FsOperation::Write
            | FsOperation::Append
            | FsOperation::Exists
            | FsOperation::Stat
            | FsOperation::Lstat
            | FsOperation::ReadLink
            | FsOperation::Unlink
            | FsOperation::RemoveDir
            | FsOperation::Access
            | FsOperation::Realpath
            | FsOperation::Mkdtemp => Vec::new(),
        })
    }

    pub(super) fn alloc_fs_date(
        &mut self,
        modified_millis: i64,
    ) -> Result<Value, InterpreterError> {
        let date_prototype = self.ensure_builtin_prototype("Date")?;
        let date_id = self.alloc_object_with_prototype(Some(date_prototype))?;
        self.set_object_brand(date_id, "Date")?;
        self.set_date_value(date_id, modified_millis as f64)?;
        Ok(Value::Object(date_id))
    }

    /// Engine-internal slots still stored as own properties (collection
    /// storage, a Map/Set's cached size) stay out of
    /// Object.keys, for-in, JSON.stringify, spread and Object.assign, like the
    /// internal slots they stand in for.
    pub(super) fn hide_internal_slots(
        &mut self,
        object_id: ObjectId,
        keys: &[&str],
    ) -> Result<(), InterpreterError> {
        for key in keys {
            self.set_own_property_attributes(
                object_id,
                &RuntimePropertyKey::String(JsString::from(*key)),
                NON_ENUMERABLE_DATA_ATTRIBUTES,
            )?;
        }
        Ok(())
    }

    pub(super) fn fs_metadata_value(
        &mut self,
        metadata: FsMetadata,
    ) -> Result<Value, InterpreterError> {
        let modified = self.alloc_fs_date(metadata.modified_millis)?;
        let object_id = self.alloc_object_with_prototype(None)?;
        self.set_object_brand(object_id, "FsStats")?;
        self.set_object_property(
            object_id,
            "size".to_string(),
            Value::Int(i64::try_from(metadata.size).unwrap_or(i64::MAX)),
        )?;
        self.set_object_property(
            object_id,
            "mode".to_string(),
            Value::Int(i64::from(metadata.mode)),
        )?;
        self.set_object_property(object_id, "mtime".to_string(), modified)?;
        self.set_object_property(
            object_id,
            "__isFile".to_string(),
            Value::Bool(metadata.is_file),
        )?;
        self.set_object_property(
            object_id,
            "__isDirectory".to_string(),
            Value::Bool(metadata.is_directory),
        )?;
        self.set_object_property(
            object_id,
            "__isSymbolicLink".to_string(),
            Value::Bool(metadata.is_symbolic_link),
        )?;
        Ok(Value::Object(object_id))
    }

    pub(super) fn fs_dir_entry_value(
        &mut self,
        entry: FsDirEntry,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.alloc_object_with_prototype(None)?;
        self.set_object_brand(object_id, "FsDirent")?;
        self.set_object_property(object_id, "name".to_string(), Value::str(entry.name))?;
        self.set_object_property(
            object_id,
            "__isFile".to_string(),
            Value::Bool(entry.is_file),
        )?;
        self.set_object_property(
            object_id,
            "__isDirectory".to_string(),
            Value::Bool(entry.is_directory),
        )?;
        self.set_object_property(
            object_id,
            "__isSymbolicLink".to_string(),
            Value::Bool(entry.is_symbolic_link),
        )?;
        Ok(Value::Object(object_id))
    }

    pub(super) fn fs_meta_result_value(
        &mut self,
        result: FsMetaResult,
    ) -> Result<Value, InterpreterError> {
        match result {
            FsMetaResult::Unit | FsMetaResult::Unsigned(_) => Ok(Value::Undefined),
            FsMetaResult::Bool(value) => Ok(Value::Bool(value)),
            FsMetaResult::String(value) => Ok(Value::str(value)),
            FsMetaResult::Strings(values) => {
                let values: Vec<Value> = values.into_iter().map(Value::str).collect();
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            FsMetaResult::DirEntries(entries) => {
                let mut values = Vec::with_capacity(entries.len());
                for entry in entries {
                    values.push(self.fs_dir_entry_value(entry)?);
                }
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            FsMetaResult::Metadata(metadata) => self.fs_metadata_value(metadata),
            // fd reads are consumed by the ReadFd conversion arm (positional
            // Buffer mutation + count); a stray Bytes result surfaced here
            // still materializes as a real Buffer rather than vanishing.
            FsMetaResult::Bytes(bytes) => Ok(Value::Object(self.alloc_buffer_from_bytes(&bytes)?)),
        }
    }

    /// Dispatch an `fs:` or `net:request` hostcall through the installed sandboxed
    /// host-I/O provider, performing (and recording) a real host effect and mapping
    /// the result back into a JS [`Value`]. The `net:request` egress is split off up
    /// front to the shared [`Self::perform_net_request_effect`] seam (also used by
    /// the deferred `ClientRequest.end()` egress); `fs:` capabilities take the
    /// string-args builder path below. Returns [`Value::Undefined`] when no provider
    /// is installed, preserving the fail-closed baseline. The capability gate has
    /// already authorized the call before this point; the provider re-checks the
    /// single required capability and performs the real I/O.
    /// bd-9vouw.8: a host I/O HostCall's operands, and everything reachable
    /// from them, must fit the clearance the static flow check gives its sink
    /// (Public for `net:*`, Internal for `fs:*`). Checked before dispatch on
    /// every path guest code reaches it by, so a flow the static inference
    /// missed stops before any effect.
    pub(super) fn check_host_io_confidentiality(
        &mut self,
        capability: &str,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        self.check_sink_confidentiality(
            args,
            capability,
            &crate::lowering_pipeline::sink_clearance_from_capability(capability),
        )
    }

    pub(super) fn dispatch_host_io_hostcall(
        &mut self,
        capability: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if matches!(capability, "env:read" | "env:has" | "env.read" | "env.has") {
            let canonical = if matches!(capability, "env:has" | "env.has") {
                "env:has"
            } else {
                "env:read"
            };
            return self.dispatch_environment_hostcall(canonical, args);
        }
        // bd-3894s slice (2b): the `net:request` egress is handled by a single
        // shared seam — [`Self::perform_net_request_effect`] — used by BOTH the
        // immediate `http.get`/`fetch` forms (which reach here as a `net:request`
        // HostCall) AND the deferred `ClientRequest.end()` egress (which calls the
        // helper directly from the builtin). Resolving the request options off the
        // heap and performing the round trip here, separate from the fs string-args
        // path below, keeps the wire egress and the signed EffectReceipt faithful
        // to the real method/headers/body. (`net:client_request`, the
        // ClientRequest-CREATION tag, is intercepted earlier in the IR3 HostCall
        // dispatch and never reaches this function.)
        if capability.starts_with("net:") || capability.starts_with("net.") {
            self.check_host_io_confidentiality(capability, args)?;
            let args_label = self.join_arg_range_label(args)?;
            let response_label =
                hostcall_result_contract(capability).result_label(&args_label, None);
            let url = if args.count >= 1 {
                match self.read_reg(args.start)? {
                    Value::Str(s) => s.to_string(),
                    Value::Int(i) => i.to_string(),
                    _ => String::new(),
                }
            } else {
                String::new()
            };
            let options = if args.count >= 2 {
                Some(self.read_reg(args.start + 1)?)
            } else {
                None
            };
            // bd-3894s slice (2c): a trailing closure is the Node response callback —
            // `http.get(url[, options], cb)`. It can sit at arg[1] (no options) or
            // arg[2] (with options); either way it is the LAST argument, so detect a
            // `Value::Closure` in the final slot. (A non-closure last arg — the bare
            // URL, an options object, or a `fetch` init — is not a callback.) When
            // present the egress runs as usual and `cb(res)` is delivered on the next
            // event-loop turn (mirroring the fs async callback form), and the call
            // itself evaluates to `undefined`. The `options` read above already
            // resolves a callback-at-arg[1] to the bodyless-GET defaults, so the
            // framed request is unaffected.
            let response_callback = if args.count >= 2 {
                match self.read_reg(args.start + args.count - 1)? {
                    Value::Closure(cid) => Some(cid),
                    _ => None,
                }
            } else {
                None
            };
            let (method, headers, body) = self.resolve_net_request_options(options.as_ref());
            let response = self.perform_net_request_effect(url, method, headers, body)?;
            // The egress produced a real `IncomingMessage` (`Value::Object`) on
            // success, or `Value::Undefined` on a denied/failed egress (the signed
            // DENIED receipt is already recorded).
            let response_obj = match &response {
                Value::Object(rid) => Some(*rid),
                _ => None,
            };
            // Only deliver `cb(res)` for a real response. Firing the response callback
            // on a denied egress would be a false success — Node raises an `'error'`
            // event instead (surfaced on the `ClientRequest` `.on('error')` path), so
            // here (the bare `http.get(url, cb)` form, which exposes no request object)
            // we simply do not invoke the callback.
            let result = match response_callback {
                Some(cid) if response_obj.is_some() => {
                    self.schedule_io_callback_with_label(
                        cid,
                        vec![response],
                        response_label.clone(),
                    )?;
                    Value::Undefined
                }
                _ => response,
            };
            // bd-3894s slice (2d): when a real response was produced, drive its
            // readable stream (`'data'` then `'end'`) on later turns so
            // `res.on('data'|'end', …)` listeners fire — whether registered inside the
            // response callback above OR after a synchronous `const res =
            // http.get(url)`. The emission is scheduled after the callback (higher
            // registration seq), so it lands on a turn where the listeners exist.
            if let Some(rid) = response_obj {
                self.schedule_stream_emission(rid, StreamEventPhase::Data, response_label)?;
            }
            return Ok(result);
        }
        let args_label = self.join_arg_range_label(args)?;
        let filesystem_result_label =
            hostcall_result_contract(capability).result_label(&args_label, None);
        let filesystem_exception_label = match self.filesystem_exception_provenance() {
            HostIoExceptionProvenance::ProviderInternal => Label::Internal,
            HostIoExceptionProvenance::Unknown => Label::TopSecret,
        }
        .join(&args_label);
        let mut raw_args = Vec::with_capacity(args.count as usize);
        for offset in 0..args.count {
            raw_args.push(self.read_reg(args.start + offset)?);
        }
        // New breadth operations carry an internal leading discriminator while
        // retaining the existing `fs:read` / `fs:write` capability tag. Keeping
        // it in the typed effect/request makes transcripts and receipts commit to
        // the concrete action without adding capability aliases.
        let declared_operation = match capability {
            "fs:read" | "fs.read" => FsOperation::Read,
            "fs:write" | "fs.write" => FsOperation::Write,
            _ => {
                return Err(InterpreterError::CapabilityDenied {
                    capability: recordable_capability_tag(capability).into_owned(),
                });
            }
        };
        let (mut operation, logical_args) = if let Some(Value::Str(value)) = raw_args.first()
            && let Some(name) = value.strip_prefix("\0fsop:")
        {
            let operation = FsOperation::parse_name(name).ok_or_else(|| {
                InterpreterError::CapabilityDenied {
                    capability: "fs:unknown_operation".to_string(),
                }
            })?;
            (operation, &raw_args[1..])
        } else {
            (declared_operation, raw_args.as_slice())
        };
        // The discriminator is internal metadata, not a second source of
        // authority. Even forged IR cannot smuggle a mutation through a read
        // tag (or mislabel a read as a write) into the Full handler stack.
        if operation.required_capability() != declared_operation.required_capability() {
            return Err(InterpreterError::CapabilityDenied {
                capability: if operation.required_capability()
                    == FsOperation::Read.required_capability()
                {
                    "fs:read".to_string()
                } else {
                    "fs:write".to_string()
                },
            });
        }
        let callback_closure = logical_args.last().and_then(|value| match value {
            Value::Closure(closure_id) => Some(*closure_id),
            _ => None,
        });
        let path = if matches!(
            operation,
            FsOperation::ReadFd | FsOperation::WriteFd | FsOperation::Fsync | FsOperation::CloseFd
        ) {
            logical_args
                .first()
                .map_or_else(String::new, |value| self.fs_value_argument(value))
        } else {
            match self.fs_path_argument(logical_args.first()) {
                Ok(path) => path,
                // existsSync is the non-throwing predicate. Invalid paths
                // return false without crossing the host boundary; resource
                // and engine faults still propagate.
                Err(InterpreterError::TypeError { .. }) if operation == FsOperation::Exists => {
                    return Ok(Value::Bool(false));
                }
                Err(error) => return Err(error),
            }
        };
        let second_arg_value = logical_args.get(1).cloned();

        // `writeFile[Sync](path, data, {flag:'a'})` is append-class I/O even
        // though it shares Node's writeFile API entrypoint.
        if operation == FsOperation::Write
            && logical_args
                .get(2)
                .and_then(|options| self.fs_object_property(options, "flag"))
                .is_some_and(|value| matches!(value, Value::Str(flag) if flag.as_ref() == "a"))
        {
            operation = FsOperation::Append;
        }
        // bd-rul7k item 3: validate an explicit `fs:read` encoding BEFORE performing
        // the read. Node's `readFileSync`/`readFile` throw `TypeError('Unknown
        // encoding')` synchronously for an unrecognized encoding — no read is
        // performed and (for the callback form) the callback is never scheduled. We
        // return a JS-catchable `TypeError` here, before the effect is built/run, so
        // no spurious read effect is recorded in the host-effect transcript. The
        // resolved encoding is reused below for the return-shape decode.
        let fs_read_encoding = if operation == FsOperation::Read {
            let encoding = self.resolve_fs_read_encoding(second_arg_value.as_ref());
            if let Some(ref enc) = encoding
                && !Self::is_recognized_fs_encoding(enc)
            {
                return Err(InterpreterError::TypeError {
                    expected: "a recognized Node BufferEncoding".to_string(),
                    got: format!("Unknown encoding: {enc}"),
                });
            }
            encoding
        } else {
            None
        };
        let operation_arguments = self.fs_operation_arguments(operation, logical_args)?;
        let content = if matches!(
            operation,
            FsOperation::Write | FsOperation::Append | FsOperation::WriteFd
        ) {
            Some(self.fs_write_data_bytes(logical_args.get(1))?)
        } else {
            None
        };
        let Some(provider) = self.host_io.clone() else {
            return Ok(Value::Undefined);
        };
        let effect = create_fs_effect(operation, path, operation_arguments, content);
        // A host boundary is also a cancellation checkpoint. Check before
        // replay/recording or provider entry, so revocation preserves exactly
        // the completed effect prefix rather than recording another attempt.
        if self
            .config
            .cancellation_token
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(InterpreterError::Cancelled);
        }
        // Build a Full handler stack backed by the provider (+ recorder) for this
        // dispatch. Full grants all capabilities so the stack's gate never
        // re-denies what the interpreter already authorized; the provider performs
        // the real, capability-checked effect and the recorder logs it.
        let mut stack = if self.host_effect_journal.is_some() {
            create_handler_stack_from_profile_with_effect_providers(
                &CapabilityProfile::full(),
                Some(provider),
                self.host_io_recorder.clone(),
                self.process_spawn.clone(),
                None,
                self.host_effect_journal.clone(),
            )
        } else {
            create_handler_stack_from_profile_with_host_io(
                &CapabilityProfile::full(),
                provider,
                self.host_io_recorder.clone(),
            )
        };
        let outcome = stack.handle_effect(effect.as_ref());
        // The provider and journal have already settled the irreversible effect
        // prefix. Cancellation is a host fault, not a catchable filesystem error
        // or a callback result; observe it before translating any outcome.
        if self
            .config
            .cancellation_token
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(InterpreterError::Cancelled);
        }
        let result = match outcome {
            Ok(result) => result,
            Err(EffectError::HandlerError {
                message,
                code: Some(code),
                ..
            }) => {
                let error = InterpreterError::HostFilesystem { code, message };
                if let Some(closure_id) = callback_closure {
                    let thrown = self.native_error_to_thrown_value(&error)?;
                    self.schedule_io_callback_with_label(
                        closure_id,
                        vec![thrown],
                        filesystem_exception_label,
                    )?;
                    return Ok(Value::Undefined);
                }
                self.replace_pending_hostcall_result_label(Some(filesystem_exception_label))?;
                return Err(error);
            }
            Err(EffectError::CapabilityDenied { .. })
                if self
                    .config
                    .cancellation_token
                    .as_ref()
                    .is_some_and(CancellationToken::is_cancelled) =>
            {
                // Cell-authorized providers report revoked dispatch as a host
                // denial. Preserve the live cancellation at the interpreter
                // boundary instead of turning it into an internal VM fault.
                // Completed effects and their recorder entries remain intact;
                // unrelated provider failures keep their original error path.
                return Err(InterpreterError::Cancelled);
            }
            Err(err) => {
                return Err(InterpreterError::InternalError {
                    details: format!("host effect dispatch failed for {capability}: {err}"),
                });
            }
        };
        Ok(match operation {
            FsOperation::Read => {
                // bd-1xl17.d / bd-rul7k: Node parity for `readFileSync`'s return
                // shape. The optional second arg selects the character encoding,
                // either as a bare string (`readFileSync(p, 'utf8')`) or an options
                // object (`readFileSync(p, { encoding: 'utf8' })`); without a
                // recognized encoding the call yields a `Buffer`. The encoding was
                // resolved and validated up front (`fs_read_encoding`) so it only
                // steers the value here; it is inert to the host effect itself
                // (the typed effect consumes only the path for reads).
                let value = match result.downcast::<Vec<u8>>() {
                    Ok(bytes) => self.decode_fs_read_result(&bytes, fs_read_encoding.as_deref())?,
                    Err(_) => Value::Undefined,
                };
                if let Value::Object(object_id) = &value {
                    self.join_binary_storage_label(*object_id, &filesystem_result_label)?;
                }
                if let Some(closure_id) = callback_closure {
                    // bd-201vt: async `fs.readFile(path[, enc], cb)`. The read effect
                    // already ran and was recorded above; defer the err-first
                    // `cb(null, data)` to the next event-loop turn (Node runs fs
                    // callbacks off the current call stack), and the call itself
                    // evaluates to `undefined`. The encoding still steers `data`'s
                    // Buffer-vs-string shape via the resolver above.
                    self.schedule_io_callback_with_label(
                        closure_id,
                        vec![Value::Null, value],
                        filesystem_result_label.clone(),
                    )?;
                    Value::Undefined
                } else {
                    value
                }
            }
            // bd-1xl17.d: Node's `writeFileSync` returns `undefined`. The real
            // write still happened and was recorded in the host-effect transcript
            // (the ledger source for bd-5r99w.12); only the JS-visible value
            // changes to match Node, not the recorded effect.
            FsOperation::Write | FsOperation::Append => {
                if let Some(closure_id) = callback_closure {
                    // bd-201vt: async `fs.writeFile(path, data, cb)`. The write ran
                    // and was recorded above; defer the err-first `cb(null)` to the
                    // next event-loop turn. (Node's writeFile callback takes only the
                    // error argument.)
                    self.schedule_io_callback_with_label(
                        closure_id,
                        vec![Value::Null],
                        filesystem_result_label.clone(),
                    )?;
                }
                Value::Undefined
            }
            // Numeric fd lifecycle result shapes (bd-zco6t): openSync yields
            // the fd number, writeSync the byte count — both ride the
            // FsMetaResult::Unsigned carrier the generic arm would collapse
            // to `undefined`.
            FsOperation::Open | FsOperation::WriteFd => match result.downcast::<FsMetaResult>() {
                Ok(FsMetaResult::Unsigned(value)) => {
                    Value::Int(i64::try_from(value).unwrap_or(i64::MAX))
                }
                _ => Value::Undefined,
            },
            // readSync mutates the guest Buffer POSITIONALLY (bytes copied in
            // at `offset`) and evaluates to the byte count actually read.
            FsOperation::ReadFd => match result.downcast::<FsMetaResult>() {
                Ok(FsMetaResult::Bytes(bytes)) => {
                    let offset = match logical_args.get(2) {
                        Some(Value::Int(offset)) => usize::try_from(*offset).unwrap_or(0),
                        _ => 0,
                    };
                    if let Some(Value::Object(buffer_id)) = logical_args.get(1) {
                        for (index, byte) in bytes.iter().enumerate() {
                            self.typed_array_indexed_set_property(
                                *buffer_id,
                                &(offset + index).to_string(),
                                &Value::Int(i64::from(*byte)),
                            )?;
                        }
                        self.join_binary_storage_label(*buffer_id, &filesystem_result_label)?;
                    }
                    Value::Int(i64::try_from(bytes.len()).unwrap_or(i64::MAX))
                }
                _ => Value::Undefined,
            },
            _ => match result.downcast::<FsMetaResult>() {
                Ok(result) => self.fs_meta_result_value(result)?,
                Err(_) => Value::Undefined,
            },
        })
    }

    /// bd-3894s slice (4)+(2b): perform a `net:request` host effect from already-
    /// resolved request fields and return the JS value the call evaluates to.
    ///
    /// This is the single shared seam for ALL http egress:
    /// - the immediate `http.get(url)` / `fetch(url)` forms, which reach it via the
    ///   `net:request` arm of [`Self::dispatch_host_io_hostcall`], and
    /// - the deferred `ClientRequest.end()` egress (slice 2b), which calls it
    ///   directly from the [`BuiltinFunctionKind::ClientRequestEnd`] dispatch once
    ///   the writable-stream body has been accumulated via `req.write`/`req.end`.
    ///
    /// Both routes therefore frame the identical wire request, run it through the
    /// same `CapabilityProfile::full()` handler stack backed by the sandboxed
    /// provider (the franken_node SSRF gate, when installed) and the recorder, and
    /// record the same signed `EffectReceipt` in the host-effect transcript — so a
    /// POST-with-body sent via `req.write` is recorded with byte-for-byte the same
    /// fidelity as one sent via `fetch(url, { body })`. The single-socket
    /// `NetworkRequest` round trip both sends the egress and reads the peer's reply;
    /// the raw HTTP/1.1 response bytes are parsed into the JS response object
    /// `{ status, statusText, ok, headers, body }` ([`Self::build_net_response_value`]).
    ///
    /// A product-layer network-policy denial (the SSRF gate) surfaces as a handler
    /// `CapabilityDenied`. The denial was ALREADY recorded in the host-effect
    /// transcript by the recorder inside the handler stack (`route_host_io` records
    /// every request/outcome, including the Err) — that recorded entry IS the
    /// fail-closed DENIED receipt the run --json effect ledger renders. So it must
    /// NOT abort the run as a fatal interpreter error (which would discard the whole
    /// transcript before harvest): it is a fail-closed no-op — the egress did not
    /// reach the network, the call evaluates to `undefined`, and the run completes
    /// so the signed denied receipt is surfaced. When no sandboxed provider is
    /// installed the call also evaluates to `undefined` (no effect performed).
    pub(super) fn perform_net_request_effect(
        &mut self,
        url: String,
        method: String,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<Value, InterpreterError> {
        let Some(provider) = self.host_io.clone() else {
            return Ok(Value::Undefined);
        };
        // Only these methods change response framing. Retain the semantic
        // context without cloning the already-owned request payload.
        let response_method = match method.as_str() {
            "HEAD" => "HEAD",
            "CONNECT" => "CONNECT",
            _ => "GET",
        };
        let effect = create_network_effect(url, method, headers, body);
        // Build a Full handler stack backed by the provider (+ recorder) for this
        // dispatch. Full grants all capabilities so the stack's gate never
        // re-denies what the interpreter already authorized; the provider performs
        // the real, capability-checked effect and the recorder logs it.
        let mut stack = if self.host_effect_journal.is_some() {
            create_handler_stack_from_profile_with_effect_providers(
                &CapabilityProfile::full(),
                Some(provider),
                self.host_io_recorder.clone(),
                self.process_spawn.clone(),
                None,
                self.host_effect_journal.clone(),
            )
        } else {
            create_handler_stack_from_profile_with_host_io(
                &CapabilityProfile::full(),
                provider,
                self.host_io_recorder.clone(),
            )
        };
        let outcome = stack.handle_effect(effect.as_ref());
        // A supervisor cancellation must not become the ordinary policy-denial
        // `undefined` value below. The failed effect remains journaled, but no
        // response callback or following guest instruction may run.
        if self
            .config
            .cancellation_token
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
        {
            return Err(InterpreterError::Cancelled);
        }
        let result = match outcome {
            Ok(result) => result,
            Err(EffectError::CapabilityDenied { .. }) => {
                return Ok(Value::Undefined);
            }
            // bd-3894s slice (5): an I/O failure inside the network mechanism
            // (TLS handshake/certificate rejection, connect refused, timeout)
            // surfaces as the provider's `HostIoError::Io` -> `HandlerError`.
            // Exactly like the policy-deny arm above, the failed outcome was
            // ALREADY recorded in the host-effect transcript by `route_host_io`,
            // so aborting the run here would discard the signed fail-closed
            // evidence. Node parity is an 'error' event, not a process abort:
            // the call evaluates to `undefined`, no response value is fabricated,
            // and the run completes so the recorded failure is surfaced. This arm
            // is net-only (this fn dispatches only net effects); fs keeps its
            // fatal-on-error semantics.
            Err(EffectError::HandlerError { .. }) => {
                return Ok(Value::Undefined);
            }
            Err(err) => {
                return Err(InterpreterError::InternalError {
                    details: format!("host effect dispatch failed for net:request: {err}"),
                });
            }
        };
        match result.downcast::<Vec<u8>>() {
            Ok(bytes) => self.build_net_response_value(&bytes, response_method),
            Err(_) => Ok(Value::Undefined),
        }
    }

    /// Record a runtime IFC refusal for a deferred HTTP request without entering
    /// the live provider. The request bytes come from the same typed conversion
    /// used by the ordinary effect handler, so recording and replay bind the exact
    /// endpoint, TLS mode, headers, and body that were refused.
    pub(super) fn record_deferred_network_ifc_denial(
        &self,
        url: &str,
        method: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<(), InterpreterError> {
        let request = create_network_host_io_request(url, method, headers, body);
        let denial: HostIoOutcome = Err(HostIoError::Denied {
            reason: DEFERRED_NETWORK_FLOW_POLICY_DENIAL.to_string(),
        });

        if let Some(journal) = self.host_effect_journal.as_deref() {
            if let Some(recorded) = journal.replay_host_io(&request) {
                if recorded != denial {
                    return Err(InterpreterError::InternalError {
                        details: format!(
                            "deferred network IFC replay mismatch: expected {denial:?}, got {recorded:?}"
                        ),
                    });
                }
                return Ok(());
            }
            journal.record_host_io(&request, &denial).map_err(|error| {
                InterpreterError::InternalError {
                    details: format!("failed to journal deferred network IFC denial: {error}"),
                }
            })?;
            return Ok(());
        }

        if let Some(recorder) = self.host_io_recorder.as_deref() {
            if let Some(recorded) = recorder.replay(&request) {
                if recorded != denial {
                    return Err(InterpreterError::InternalError {
                        details: format!(
                            "deferred network IFC transcript mismatch: expected {denial:?}, got {recorded:?}"
                        ),
                    });
                }
            } else {
                recorder.record(&request, &denial);
            }
            return Ok(());
        }
        Err(InterpreterError::InternalError {
            details: "deferred network IFC denial has no host-effect evidence sink".to_string(),
        })
    }

    /// bd-3894s slice (2b): build the writable `ClientRequest` object returned by
    /// `http.request(url[, opts])`. This does NOT egress — it captures the request
    /// target (`__url`), method (`__method`), and headers (`__headers`, a child
    /// object of lower-`net_header_value`-coerced pairs) from the options object,
    /// and seeds the writable body buffer (`__body`) from any `opts.body`. The
    /// returned object carries the `__type: "ClientRequest"` tag so member access
    /// resolves `.write`/`.end` to their receiver-aware builtins
    /// ([`Self::collection_prototype_method`]); `.end()` performs the deferred
    /// egress via [`Self::perform_net_request_effect`]. The hostcall capability gate
    /// authorizes construction through `net:client_request`. The later `.end()`
    /// checks `net:request` again before changing request state or dispatching,
    /// so a live containment decision can stop the deferred effect.
    pub(super) fn dispatch_client_request_create(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let lifecycle_label = self.join_arg_range_with_object_mutation_label(args)?;
        let url = if args.count >= 1 {
            match self.read_reg(args.start)? {
                Value::Str(s) => s.to_string(),
                Value::Int(i) => i.to_string(),
                _ => String::new(),
            }
        } else {
            String::new()
        };
        let options = if args.count >= 2 {
            Some(self.read_reg(args.start + 1)?)
        } else {
            None
        };
        // bd-3894s slice (2c): a trailing closure is the Node response callback —
        // `http.request(url[, options], cb)`. Unlike the immediate `http.get` form,
        // the response does not exist until `.end()` performs the deferred egress, so
        // the callback is CAPTURED on the ClientRequest now (as `__response_cb`) and
        // delivered `cb(res)` from `.end()`. It is the LAST argument (arg[1] with no
        // options, arg[2] with), so detect a `Value::Closure` in the final slot; a
        // non-closure last arg (URL / options object) is not a callback. The
        // `options` read above already resolves a callback-at-arg[1] to the GET
        // defaults, so the framed request is unaffected.
        let response_callback = if args.count >= 2 {
            match self.read_reg(args.start + args.count - 1)? {
                Value::Closure(cid) => Value::Closure(cid),
                _ => Value::Undefined,
            }
        } else {
            Value::Undefined
        };
        let initial_body_len = options
            .as_ref()
            .and_then(|value| match value {
                Value::Object(id) => self.heap.get(id.0 as usize),
                _ => None,
            })
            .and_then(|options| options.properties.get("body"))
            .and_then(Self::client_request_chunk_len)
            .unwrap_or(0);
        if initial_body_len > MAX_HTTP_BODY_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!("HTTP request body exceeds {MAX_HTTP_BODY_BYTES} bytes"),
            });
        }
        self.check_temporary_memory_budget(
            u64::try_from(initial_body_len)
                .unwrap_or(u64::MAX)
                // `resolve_net_request_options` first owns a byte vector, then
                // request construction owns a String and the final JsString
                // backing at the conversion peak.
                .saturating_mul(3)
                .saturating_add(64 * 1024),
        )?;
        let (method, headers, body) = self.resolve_net_request_options(options.as_ref());
        // Persist the resolved headers as a child object so `.end()` can re-read
        // them (the headers are captured at request-construction time, matching
        // Node — a later mutation of the original options object does not change
        // the framed request).
        let header_props: Vec<(&str, Value)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), Value::str(value.as_str())))
            .collect();
        let headers_id = self.alloc_object_with_properties(&header_props)?;
        // Seed the writable body buffer from any `opts.body`. `req.write`/`req.end`
        // append to this buffer; the bytes are sent on `.end()`.
        let initial_body = body
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        let request_id = self.alloc_branded_object(
            "ClientRequest",
            &[
                ("__url", Value::str(url.as_str())),
                ("__method", Value::str(method.as_str())),
                ("__headers", Value::Object(headers_id)),
                ("__body", Value::str(initial_body.as_str())),
                ("__ended", Value::Bool(false)),
                ("__response_cb", response_callback),
            ],
        )?;
        self.join_object_mutation_label(request_id, &lifecycle_label)?;
        Ok(Value::Object(request_id))
    }

    /// The compiler emits this exact route only for proven call-only literal
    /// paths and primitive encodings. The ordinary fs:read dispatcher still
    /// validates paths, records the effect, checks cancellation and labels its
    /// result/error. Native completion replaces only the facade's Promise
    /// executor and callback; it neither grants authority nor changes I/O.
    pub(super) fn dispatch_fs_promise_read(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // Like Node's fs/promises, this protected operation uses the realm's
        // intrinsic Promise, independent of a replaceable global constructor.
        // Never let this read-only entrypoint smuggle another FsOperation or
        // a trailing guest callback into the shared dispatcher, even in IR
        // supplied directly by an embedder.
        if args.count != 3
            || !matches!(self.read_reg(args.start)?, Value::Str(ref value)
                if value.as_ref() == "\0fsop:read")
        {
            return Err(InterpreterError::CapabilityDenied {
                capability: "fs:read:promise:operation".to_string(),
            });
        }
        self.check_host_io_confidentiality("fs:read", args)?;
        let inputs_label = self.join_arg_range_label(args)?;
        let result_label = hostcall_result_contract("fs:read").result_label(&inputs_label, None);
        let promise = self.create_promise()?;
        // Provider result/error allocation can collect. The returned Promise
        // does not yet have a guest register or pending-task owner.
        let pins = self.gc_pin_network_values([Value::Promise(promise.0)]);
        let result = (|| {
            let path = self.read_reg(args.start + 1)?;
            let options = self.read_reg(args.start + 2)?;
            let outcome = if !matches!(path, Value::Str(_))
                || !matches!(options, Value::Str(_) | Value::Undefined | Value::Null)
            {
                Err(InterpreterError::TypeError {
                    expected: "a filesystem Promise read with a string path and primitive encoding"
                        .to_string(),
                    got: format!(
                        "{} path and {} options",
                        path.type_name(),
                        options.type_name()
                    ),
                })
            } else {
                self.dispatch_host_io_hostcall("fs:read", args)
            };
            let provider_label = self.take_pending_hostcall_result_label();
            match outcome {
                Ok(value) => {
                    // The existing facade's callback is never called when no
                    // provider is installed. Preserve its pending Promise.
                    let settlement_label = provider_label
                        .as_ref()
                        .map_or_else(|| result_label.clone(), |label| result_label.join(label));
                    // Publish the return label before committing a queued task:
                    // a failed label admission must leave no job referring to
                    // the fresh Promise that the error path rolls back.
                    let value_pins = self.gc_pin_network_values([value.clone()]);
                    let scheduled: Result<(), InterpreterError> = (|| {
                        self.replace_pending_hostcall_result_label(Some(settlement_label.clone()))?;
                        if self.host_io.is_some() {
                            self.schedule_fs_promise_read(
                                PendingFsPromiseRead {
                                    promise,
                                    outcome: Ok(value),
                                },
                                settlement_label,
                            )?;
                        }
                        Ok(())
                    })();
                    self.gc_unpin_network_values(value_pins);
                    scheduled?;
                }
                Err(error) if matches!(error, InterpreterError::HostFilesystem { .. }) => {
                    let exception_floor = match self.filesystem_exception_provenance() {
                        HostIoExceptionProvenance::ProviderInternal => Label::Internal,
                        HostIoExceptionProvenance::Unknown => Label::TopSecret,
                    };
                    let label = provider_label
                        .unwrap_or(exception_floor)
                        .join(&inputs_label);
                    let thrown = self.native_error_to_thrown_value(&error)?;
                    let error_pins = self.gc_pin_network_values([thrown.clone()]);
                    let scheduled = (|| {
                        self.replace_pending_hostcall_result_label(Some(label.clone()))?;
                        self.schedule_fs_promise_read(
                            PendingFsPromiseRead {
                                promise,
                                outcome: Err(thrown),
                            },
                            label,
                        )
                    })();
                    self.gc_unpin_network_values(error_pins);
                    scheduled?;
                }
                Err(error) if Self::js_catchable_error_name(&error).is_some() => {
                    // Validation throws happen inside the Promise executor;
                    // they reject immediately, before any I/O-completion job.
                    let mut label = Label::Internal.join(&inputs_label);
                    if let Some(provider_label) = provider_label {
                        label = label.join(&provider_label);
                    }
                    let thrown = self.native_error_to_thrown_value(&error)?;
                    let error_pins = self.gc_pin_network_values([thrown.clone()]);
                    let rejected = (|| {
                        self.replace_pending_hostcall_result_label(Some(label.clone()))?;
                        let reason = self.promise_value(&thrown)?;
                        self.reject_promise(promise, reason, label)
                    })();
                    self.gc_unpin_network_values(error_pins);
                    rejected?;
                }
                Err(error) => return Err(error),
            }
            Ok(Value::Promise(promise.0))
        })();
        self.gc_unpin_network_values(pins);
        if result.is_err() {
            self.rollback_fresh_promise(promise);
        }
        result
    }

    pub(super) fn schedule_fs_promise_read(
        &mut self,
        task: PendingFsPromiseRead,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let value = match &task.outcome {
            Ok(value) | Err(value) => value.clone(),
        };
        // Both the Promise and payload are unowned by the task map until
        // admission succeeds; protect them across any allocation safe point.
        let pins = self.gc_pin_network_values([Value::Promise(task.promise.0), value]);
        let admitted = (|| {
            let retained_bytes = Self::pending_fs_promise_read_bytes(&task);
            self.apply_memory_component_delta(0, retained_bytes)?;
            let previous_promise_bytes = self.promise_runtime_memory_bytes();
            let registration = self
                .event_loop
                .schedule_io_completion(crate::closure_model::ClosureHandle(u32::MAX), label);
            if let Err(error) = self.apply_promise_runtime_memory_delta(previous_promise_bytes) {
                self.event_loop.rollback_last_scheduled(registration);
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(retained_bytes);
                return Err(error);
            }
            self.pending_fs_promise_reads
                .insert(registration, Arc::new(task));
            Ok(())
        })();
        self.gc_unpin_network_values(pins);
        admitted
    }

    pub(super) fn execute_pending_fs_promise_read(
        &mut self,
        macrotask: &crate::promise_model::Macrotask,
        module: Option<&Ir3Module>,
    ) -> Option<Result<(), InterpreterError>> {
        // Keep the task in its GC root map until adoption finishes. A Buffer's
        // then getter can run guest code, allocate or request collection.
        let task = Arc::clone(
            self.pending_fs_promise_reads
                .get(&macrotask.registration_seq)?,
        );
        let retained_bytes = Self::pending_fs_promise_read_bytes(&task);
        let result = match &task.outcome {
            Ok(value) => self.resolve_promise_with_value(
                module,
                task.promise,
                value.clone(),
                macrotask.label.clone(),
            ),
            Err(value) => self.promise_value(value).and_then(|reason| {
                self.reject_promise(task.promise, reason, macrotask.label.clone())
            }),
        };
        self.pending_fs_promise_reads
            .remove(&macrotask.registration_seq);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(retained_bytes);
        Some(result)
    }

    /// bd-201vt / bd-3894s slice (2c): schedule an async host-I/O callback to run on
    /// the next event-loop turn. Shared by the fs async callback forms
    /// (`fs.readFile`/`fs.writeFile`, err-first `[null]` / `[null, data]`) AND the
    /// http response-callback forms (`http.get`/`http.request`'s `cb(res)`, a single
    /// response argument). The host effect has already been performed and recorded
    /// synchronously by the caller; this only defers the JS callback invocation so it
    /// runs off the current call stack, matching Node's `IoCompletion`-phase
    /// scheduling. `callback_args` is whatever the caller delivers to the closure; it
    /// is stashed by the macrotask's registration sequence and drained when the
    /// macrotask fires in `execute_macrotask_callback`.
    /// Schedule an I/O-lane callback under the aggregate label of the data
    /// delivered to it. Callers must provide the exact result/source or error
    /// provenance for the deferred payload so callback execution cannot launder
    /// classified state.
    pub(super) fn schedule_io_callback_with_label(
        &mut self,
        closure_id: u32,
        callback_args: Vec<Value>,
        callback_label: Label,
    ) -> Result<(), InterpreterError> {
        self.schedule_callback_in_lane(closure_id, callback_args, callback_label, false)
    }

    pub(super) fn schedule_child_process_callback(
        &mut self,
        closure_id: u32,
        callback_args: Vec<Value>,
        callback_label: &Label,
    ) -> Result<(), InterpreterError> {
        let output_label =
            hostcall_result_contract("process_spawn").result_label(callback_label, None);
        self.schedule_callback_in_lane(closure_id, callback_args, output_label, true)
    }

    pub(super) fn schedule_callback_in_lane(
        &mut self,
        closure_id: u32,
        callback_args: Vec<Value>,
        callback_label: Label,
        immediate: bool,
    ) -> Result<(), InterpreterError> {
        let retained_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(Self::estimate_value_vec_bytes(&callback_args));
        self.apply_memory_component_delta(0, retained_bytes)?;
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let handler = crate::closure_model::ClosureHandle(closure_id);
        let seq = if immediate {
            self.event_loop.set_immediate(handler, callback_label)
        } else {
            self.event_loop
                .schedule_io_completion(handler, callback_label)
        };
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_promise_bytes) {
            self.event_loop.rollback_last_scheduled(seq);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(retained_bytes);
            return Err(error);
        }
        self.pending_io_callbacks.insert(seq, callback_args);
        Ok(())
    }

    pub(super) fn pending_child_process_task_bytes(task: &PendingChildProcessTask) -> u64 {
        let options = &task.options;
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<PendingChildProcessTask>() as u64)
            .saturating_add(Self::estimate_string_bytes(&task.handle))
            .saturating_add(
                options
                    .cwd
                    .as_deref()
                    .map(Self::estimate_string_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                options
                    .encoding
                    .as_deref()
                    .map(Self::estimate_string_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(
                task.callback_encoding
                    .as_deref()
                    .map(Self::estimate_string_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::estimate_label_bytes(&task.callback_label))
            .saturating_add(options.input.len() as u64)
            .saturating_add(Self::saturating_sum(options.env.iter().map(
                |(key, value)| {
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add(Self::estimate_string_bytes(key))
                        .saturating_add(Self::estimate_string_bytes(value))
                },
            )))
    }

    pub(super) fn estimate_completed_child_process_state_bytes(
        state: &CompletedChildProcessState,
    ) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<CompletedChildProcessState>() as u64)
            .saturating_add(Self::estimate_value_bytes(&state.stdout))
            .saturating_add(Self::estimate_value_bytes(&state.stderr))
            .saturating_add(Self::estimate_value_bytes(&state.exit_code))
            .saturating_add(Self::estimate_value_bytes(&state.signal))
            .saturating_add(
                state
                    .error
                    .as_ref()
                    .map(Self::estimate_value_bytes)
                    .unwrap_or(0),
            )
            .saturating_add(Self::saturating_sum(state.scheduled_events.iter().map(
                |event| {
                    MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add(Self::estimate_string_bytes(event))
                },
            )))
    }

    pub(super) fn completed_child_processes_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.completed_child_processes
                .values()
                .map(Self::estimate_completed_child_process_state_bytes),
        )
    }

    pub(super) fn child_process_streams_memory_bytes(&self) -> u64 {
        u64::try_from(self.child_process_streams.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(std::mem::size_of::<(
                    ObjectId,
                    (ObjectId, ChildProcessStreamKind),
                )>() as u64),
            )
    }

    pub(super) fn child_process_handles_memory_bytes(&self) -> u64 {
        Self::saturating_sum(self.child_process_handles.values().map(|handle| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(Self::estimate_string_bytes(handle))
        }))
    }

    pub(super) fn schedule_child_process_wait(
        &mut self,
        task: PendingChildProcessTask,
    ) -> Result<(), InterpreterError> {
        let retained_bytes = Self::pending_child_process_task_bytes(&task);
        self.apply_memory_component_delta(0, retained_bytes)?;
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let sequence = self
            .event_loop
            .schedule_io_completion(crate::closure_model::ClosureHandle(0), Label::Public);
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_promise_bytes) {
            self.event_loop.rollback_last_scheduled(sequence);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(retained_bytes);
            return Err(error);
        }
        self.pending_child_process_tasks.insert(sequence, task);
        Ok(())
    }

    pub(super) fn estimate_tls_server_state_bytes(tls: &HermeticTlsServerState) -> u64 {
        (tls.certificate_der.len() as u64).saturating_add(Self::saturating_sum(
            tls.alpn_protocols.iter().map(|protocol| {
                MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(protocol.len() as u64)
            }),
        ))
    }

    pub(super) fn estimate_tls_socket_state_bytes(tls: &HermeticTlsSocketState) -> u64 {
        tls.servername
            .as_ref()
            .map_or(0, |name| {
                MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(name.len() as u64)
            })
            .saturating_add(tls.authorization_error.as_ref().map_or(0, |error| {
                MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(error.len() as u64)
            }))
            .saturating_add(tls.negotiated_alpn.as_ref().map_or(0, |protocol| {
                MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(protocol.len() as u64)
            }))
            .saturating_add(tls.peer_certificate_der.len() as u64)
            .saturating_add(Self::saturating_sum(tls.alpn_protocols.iter().map(
                |protocol| MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(protocol.len() as u64),
            )))
    }

    pub(super) fn estimate_loopback_server_state_bytes(state: &LoopbackServerState) -> u64 {
        let tls_bytes = state
            .tls
            .as_ref()
            .map_or(0, Self::estimate_tls_server_state_bytes);
        MEMORY_ESTIMATE_LOOPBACK_SERVER_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(state.address.len() as u64)
            .saturating_add(
                (state.active_connections.len() as u64)
                    .saturating_mul(MEMORY_ESTIMATE_MAP_ENTRY_BYTES),
            )
            .saturating_add(tls_bytes)
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
    }

    pub(super) fn estimate_loopback_socket_state_bytes(state: &LoopbackSocketState) -> u64 {
        let queued_data = |queue: &VecDeque<LoopbackBufferedData>| {
            Self::saturating_sum(queue.iter().map(|data| {
                MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(data.bytes.len() as u64)
                    .saturating_add(Self::estimate_label_bytes(&data.label))
            }))
        };
        let tls_bytes = state
            .tls
            .as_ref()
            .map_or(0, Self::estimate_tls_socket_state_bytes);
        MEMORY_ESTIMATE_LOOPBACK_SOCKET_BASE_BYTES
            .saturating_add(queued_data(&state.pending_data))
            .saturating_add(queued_data(&state.pending_outbound))
            .saturating_add(tls_bytes)
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
            .saturating_add(
                state
                    .end_completion_callback
                    .as_ref()
                    .map_or(0, Self::estimate_value_bytes),
            )
    }

    pub(super) fn estimate_pending_loopback_task_bytes(task: &PendingLoopbackTask) -> u64 {
        let payload = match task {
            PendingLoopbackTask::Data { bytes, label, .. } => {
                (bytes.len() as u64).saturating_add(Self::estimate_label_bytes(label))
            }
            PendingLoopbackTask::End { label, .. }
            | PendingLoopbackTask::Close { label, .. }
            | PendingLoopbackTask::ServerClose { label, .. } => Self::estimate_label_bytes(label),
            PendingLoopbackTask::Error { code, label, .. } => MEMORY_ESTIMATE_STRING_BASE_BYTES
                .saturating_add(code.len() as u64)
                .saturating_add(Self::estimate_label_bytes(label)),
            PendingLoopbackTask::Listening { .. } | PendingLoopbackTask::Connect { .. } => 0,
        };
        MEMORY_ESTIMATE_LOOPBACK_TASK_BASE_BYTES.saturating_add(payload)
    }

    pub(super) fn loopback_servers_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.loopback_servers
                .values()
                .map(Self::estimate_loopback_server_state_bytes),
        )
    }

    pub(super) fn loopback_sockets_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.loopback_sockets
                .values()
                .map(Self::estimate_loopback_socket_state_bytes),
        )
    }

    pub(super) fn pending_loopback_tasks_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.pending_loopback_tasks
                .values()
                .map(Self::estimate_pending_loopback_task_bytes),
        )
    }

    pub(super) fn loopback_ports_memory_bytes(&self) -> u64 {
        (self.loopback_ports.len() as u64).saturating_mul(MEMORY_ESTIMATE_LOOPBACK_PORT_BASE_BYTES)
    }

    pub(super) fn estimate_http_headers_bytes(headers: &HttpHeaders) -> u64 {
        Self::saturating_sum(
            headers
                .iter()
                .map(|(lower_name, header)| Self::estimate_http_header_bytes(lower_name, header)),
        )
    }

    pub(super) fn estimate_http_header_bytes(lower_name: &str, header: &HttpHeaderValue) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(lower_name.len() as u64)
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(header.original_name.len() as u64)
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(header.value.len() as u64)
            .saturating_add(header.array_values.as_ref().map_or(0, |values| {
                MEMORY_ESTIMATE_HTTP_HEADER_ARRAY_BASE_BYTES.saturating_add(Self::saturating_sum(
                    values.iter().map(|value| {
                        MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(value.len() as u64)
                    }),
                ))
            }))
    }

    pub(super) fn estimate_http_client_request_state_bytes(state: &HttpClientRequestState) -> u64 {
        MEMORY_ESTIMATE_HTTP_CLIENT_REQUEST_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(state.host.len() as u64)
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(state.path.len() as u64)
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(state.method.len() as u64)
            .saturating_add(Self::estimate_http_headers_bytes(&state.headers))
            .saturating_add(state.body.len() as u64)
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
            .saturating_add(Self::estimate_label_bytes(&state.egress_label))
    }

    pub(super) fn estimate_http_incoming_message_state_bytes(
        state: &HttpIncomingMessageState,
    ) -> u64 {
        MEMORY_ESTIMATE_HTTP_INCOMING_MESSAGE_BASE_BYTES
            .saturating_add(state.body.len() as u64)
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
    }

    pub(super) fn estimate_http_server_response_state_bytes(
        state: &HttpServerResponseState,
    ) -> u64 {
        MEMORY_ESTIMATE_HTTP_SERVER_RESPONSE_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(state.request_method.len() as u64)
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(state.status_message.len() as u64)
            .saturating_add(Self::estimate_http_headers_bytes(&state.headers))
            .saturating_add(state.body.len() as u64)
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label))
    }

    pub(super) fn estimate_pending_http_task_bytes(task: &PendingHttpTask) -> u64 {
        let payload = match task {
            PendingHttpTask::ClientError { code, label, .. } => MEMORY_ESTIMATE_STRING_BASE_BYTES
                .saturating_add(code.len() as u64)
                .saturating_add(Self::estimate_label_bytes(label)),
            PendingHttpTask::EmitLegacyEvent {
                event,
                arguments,
                label,
                ..
            } => MEMORY_ESTIMATE_STRING_BASE_BYTES
                .saturating_add(event.len() as u64)
                .saturating_add(Self::estimate_value_vec_bytes(arguments))
                .saturating_add(Self::estimate_label_bytes(label)),
            _ => 0,
        };
        MEMORY_ESTIMATE_HTTP_TASK_BASE_BYTES.saturating_add(payload)
    }

    pub(super) fn http_runtime_memory_bytes(&self) -> u64 {
        (self.http_servers.len() as u64)
            .saturating_mul(MEMORY_ESTIMATE_HTTP_SERVER_BASE_BYTES)
            .saturating_add(Self::saturating_sum(
                self.http_servers
                    .values()
                    .map(|state| Self::estimate_label_bytes(&state.lifecycle_label)),
            ))
            .saturating_add(Self::saturating_sum(
                self.http_client_requests
                    .values()
                    .map(Self::estimate_http_client_request_state_bytes),
            ))
            .saturating_add(Self::saturating_sum(
                self.http_incoming_messages
                    .values()
                    .map(Self::estimate_http_incoming_message_state_bytes),
            ))
            .saturating_add(Self::saturating_sum(
                self.http_server_responses
                    .values()
                    .map(Self::estimate_http_server_response_state_bytes),
            ))
            .saturating_add(
                (self.http_agents.len() as u64)
                    .saturating_mul(MEMORY_ESTIMATE_HTTP_AGENT_BASE_BYTES),
            )
            .saturating_add(Self::saturating_sum(
                self.pending_http_tasks
                    .values()
                    .map(Self::estimate_pending_http_task_bytes),
            ))
            .saturating_add(self.pending_stream_emissions_memory_bytes())
            .saturating_add(self.http_task_in_flight_bytes)
    }

    pub(super) fn schedule_http_task(
        &mut self,
        task: PendingHttpTask,
    ) -> Result<u64, InterpreterError> {
        self.schedule_http_task_in_lane(task, false)
    }

    pub(super) fn schedule_child_process_event_task(
        &mut self,
        task: PendingHttpTask,
    ) -> Result<u64, InterpreterError> {
        self.schedule_http_task_in_lane(task, true)
    }

    pub(super) fn schedule_http_task_in_lane(
        &mut self,
        task: PendingHttpTask,
        immediate: bool,
    ) -> Result<u64, InterpreterError> {
        let retained_bytes = Self::estimate_pending_http_task_bytes(&task);
        let task_label = match &task {
            PendingHttpTask::DispatchRequest { request, .. } => self
                .http_client_requests
                .get(request)
                .map(|state| state.lifecycle_label.clone())
                .unwrap_or(Label::Public),
            PendingHttpTask::DeliverResponse { request, message } => self
                .http_client_requests
                .get(request)
                .map(|state| state.lifecycle_label.clone())
                .unwrap_or(Label::Public)
                .join(
                    &self
                        .http_incoming_messages
                        .get(message)
                        .map(|state| state.lifecycle_label.clone())
                        .unwrap_or(Label::Public),
                ),
            PendingHttpTask::DeliverExternalResponse { request, .. } => self
                .http_client_requests
                .get(request)
                .map(|state| {
                    hostcall_result_contract("net:request")
                        .result_label(&state.lifecycle_label, None)
                })
                .unwrap_or(Label::TopSecret),
            PendingHttpTask::MessageData { message }
            | PendingHttpTask::MessageEnd { message }
            | PendingHttpTask::MessageClose { message } => self
                .http_incoming_messages
                .get(message)
                .map(|state| state.lifecycle_label.clone())
                .unwrap_or(Label::Public),
            PendingHttpTask::ClientError { label, .. } => label.clone(),
            PendingHttpTask::EmitLegacyEvent { label, .. } => label.clone(),
        };
        self.apply_memory_component_delta(0, retained_bytes)?;
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let handler = crate::closure_model::ClosureHandle(u32::MAX);
        let sequence = if immediate {
            self.event_loop.set_immediate(handler, task_label)
        } else {
            self.event_loop.schedule_io_completion(handler, task_label)
        };
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_promise_bytes) {
            self.event_loop.rollback_last_scheduled(sequence);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(retained_bytes);
            return Err(error);
        }
        self.pending_http_tasks.insert(sequence, task);
        Ok(sequence)
    }

    pub(super) fn cancel_http_task_registration(&mut self, sequence: u64) {
        if let Some(task) = self.pending_http_tasks.remove(&sequence) {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(Self::estimate_pending_http_task_bytes(&task));
        }
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        self.event_loop.cancel_registration(sequence);
        let released_promise_bytes =
            previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(released_promise_bytes);
    }

    pub(super) fn schedule_loopback_task(
        &mut self,
        task: PendingLoopbackTask,
    ) -> Result<u64, InterpreterError> {
        let retained_bytes = Self::estimate_pending_loopback_task_bytes(&task);
        self.apply_memory_component_delta(0, retained_bytes)?;
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let sequence = self
            .event_loop
            .schedule_io_completion(crate::closure_model::ClosureHandle(u32::MAX), Label::Public);
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_promise_bytes) {
            self.event_loop.rollback_last_scheduled(sequence);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(retained_bytes);
            return Err(error);
        }
        self.pending_loopback_tasks.insert(sequence, task);
        Ok(sequence)
    }

    /// Undo a loopback task admitted by the current transaction before any
    /// intervening schedule. Restoring the registration sequence is part of
    /// failure atomicity: a refused `listen`/`write` must not perturb replay.
    pub(super) fn rollback_loopback_task_registration(&mut self, sequence: u64) {
        let retained_bytes = self
            .pending_loopback_tasks
            .remove(&sequence)
            .as_ref()
            .map(Self::estimate_pending_loopback_task_bytes)
            .unwrap_or(0);
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let rolled_back = self.event_loop.rollback_last_scheduled(sequence);
        debug_assert!(rolled_back.is_some());
        let released_promise_bytes =
            previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(retained_bytes)
            .saturating_sub(released_promise_bytes);
    }

    pub(super) fn projected_loopback_task_registration_bytes(
        &self,
        task: &PendingLoopbackTask,
    ) -> u64 {
        Self::estimate_pending_loopback_task_bytes(task).saturating_add(
            self.event_loop
                .projected_io_completion_memory_bytes(&Label::Public)
                .saturating_sub(self.event_loop.estimated_memory_bytes()),
        )
    }

    pub(super) fn add_loopback_listener(
        &mut self,
        target: ObjectId,
        event: &str,
        listener: Value,
        once: bool,
    ) -> Result<(), InterpreterError> {
        if !listener.is_callable() {
            return Ok(());
        }
        self.insert_event_listener(target, event, EventListenerRecord { listener, once }, false)
    }

    pub(super) fn last_callable_arg(
        &self,
        args: RegRange,
    ) -> Result<Option<Value>, InterpreterError> {
        if args.count == 0 {
            return Ok(None);
        }
        let value = self.read_reg(args.start + args.count - 1)?;
        Ok(value.is_callable().then_some(value))
    }

    pub(super) fn construct_loopback_server(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.construct_loopback_server_with_tls(args, None)
    }

    pub(super) fn construct_loopback_server_with_tls(
        &mut self,
        args: RegRange,
        tls: Option<HermeticTlsServerState>,
    ) -> Result<Value, InterpreterError> {
        let lifecycle_label = self.join_arg_range_with_object_mutation_label(args)?;
        let is_tls = tls.is_some();
        let object_id = self.alloc_branded_object(
            if is_tls { "TlsServer" } else { "NetServer" },
            &[
                ("__maxListeners", Value::Int(10)),
                ("listening", Value::Bool(false)),
            ],
        )?;
        let state = LoopbackServerState {
            address: "127.0.0.1".to_string(),
            port: None,
            generation: 0,
            listening: false,
            active_connections: BTreeSet::new(),
            close_requested: false,
            close_scheduled: false,
            tls,
            lifecycle_label,
        };
        let retained_bytes = Self::estimate_loopback_server_state_bytes(&state);
        self.apply_memory_component_delta(0, retained_bytes)?;
        self.loopback_servers.insert(object_id, state);
        if let Some(callback) = self.last_callable_arg(args)? {
            self.add_loopback_listener(
                object_id,
                if is_tls {
                    "secureConnection"
                } else {
                    "connection"
                },
                callback,
                false,
            )?;
        }
        Ok(Value::Object(object_id))
    }

    pub(super) fn construct_loopback_socket(
        &mut self,
        connected: bool,
        remote_port: Option<u16>,
        lifecycle_label: Label,
    ) -> Result<ObjectId, InterpreterError> {
        let object_id = self.alloc_branded_object(
            "NetSocket",
            &[
                ("__maxListeners", Value::Int(10)),
                ("readable", Value::Bool(true)),
                ("writable", Value::Bool(true)),
                ("connecting", Value::Bool(!connected)),
                ("destroyed", Value::Bool(false)),
                ("bytesRead", Value::Int(0)),
                ("bytesWritten", Value::Int(0)),
                ("localAddress", Value::str("127.0.0.1")),
                ("remoteAddress", Value::str("127.0.0.1")),
                (
                    "remotePort",
                    remote_port.map_or(Value::Undefined, |port| Value::Int(i64::from(port))),
                ),
            ],
        )?;
        let state = LoopbackSocketState {
            peer: None,
            owner_server: None,
            owner_server_generation: None,
            paused: false,
            encoding_utf8: false,
            local_ended: false,
            remote_ended: false,
            destroyed: false,
            close_scheduled: false,
            bytes_read: 0,
            bytes_written: 0,
            pending_data: VecDeque::new(),
            pending_end: false,
            pending_outbound: VecDeque::new(),
            pending_outbound_end: false,
            tls: None,
            lifecycle_label,
            end_completion_callback: None,
        };
        let retained_bytes = Self::estimate_loopback_socket_state_bytes(&state);
        self.apply_memory_component_delta(0, retained_bytes)?;
        self.loopback_sockets.insert(object_id, state);
        Ok(object_id)
    }

    pub(super) fn tls_option_bool(&self, options: &Value, key: &str, default: bool) -> bool {
        match self.fs_object_property(options, key) {
            Some(Value::Bool(value)) => value,
            _ => default,
        }
    }

    pub(super) fn tls_option_has_string(&self, options: &Value, key: &str) -> bool {
        matches!(self.fs_object_property(options, key), Some(Value::Str(_)))
    }

    pub(super) fn tls_option_string_array(
        &self,
        options: &Value,
        key: &str,
        additional_temporary_bytes: u64,
    ) -> Result<Vec<String>, InterpreterError> {
        let Some(Value::Object(array)) = self.fs_object_property(options, key) else {
            return Ok(Vec::new());
        };
        let length = self.array_like_length(array)?;
        let length_u64 = u64::try_from(length).unwrap_or(u64::MAX);
        if length_u64 > MAX_TLS_ALPN_WIRE_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "TLS ALPN protocol count {length_u64} exceeds bounded wire length {MAX_TLS_ALPN_WIRE_BYTES}"
                ),
            });
        }

        let mut string_count = 0u64;
        let mut wire_bytes = 0u64;
        let mut cloned_string_bytes = 0u64;
        for index in 0..length {
            let Some(Value::Str(protocol)) = self.array_index_value(array, index)? else {
                continue;
            };
            if protocol.is_empty() || protocol.len() > MAX_TLS_ALPN_PROTOCOL_BYTES {
                return Err(InterpreterError::RangeError {
                    message: format!(
                        "TLS ALPN protocol length {} is outside the supported 1..={MAX_TLS_ALPN_PROTOCOL_BYTES} byte range",
                        protocol.len()
                    ),
                });
            }
            string_count = string_count.saturating_add(1);
            wire_bytes = wire_bytes.saturating_add(1 + protocol.len() as u64);
            cloned_string_bytes = cloned_string_bytes.saturating_add(
                MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(protocol.len() as u64),
            );
        }
        if wire_bytes > MAX_TLS_ALPN_WIRE_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "TLS ALPN wire length {wire_bytes} exceeds {MAX_TLS_ALPN_WIRE_BYTES} bytes"
                ),
            });
        }
        let vector_bytes = string_count.saturating_mul(MEMORY_ESTIMATE_MAP_ENTRY_BYTES);
        self.check_temporary_memory_budget(
            additional_temporary_bytes
                .saturating_add(vector_bytes)
                .saturating_add(cloned_string_bytes),
        )?;

        let capacity = usize::try_from(string_count).unwrap_or(usize::MAX);
        let mut protocols = Vec::with_capacity(capacity);
        for index in 0..length {
            if let Some(Value::Str(protocol)) = self.array_index_value(array, index)? {
                protocols.push(protocol.to_string());
            }
        }
        Ok(protocols)
    }

    pub(super) fn decode_tls_certificate_pem(
        &self,
        pem: &str,
    ) -> Result<Vec<u8>, InterpreterError> {
        use base64::Engine as _;

        let Some((_, body)) = pem.split_once("-----BEGIN CERTIFICATE-----") else {
            return Ok(Vec::new());
        };
        let Some((body, _)) = body.split_once("-----END CERTIFICATE-----") else {
            return Ok(Vec::new());
        };
        // Filtering and base64 decoding may briefly hold both the compacted
        // payload and decoded DER. Include fixed socket/server construction
        // headroom so those temporaries cannot combine with the subsequent
        // committed TLS state to cross the configured memory ceiling.
        self.check_temporary_memory_budget(
            (body.len() as u64)
                .saturating_mul(2)
                .saturating_add(64 * 1024),
        )?;
        let encoded: String = body.chars().filter(|ch| !ch.is_whitespace()).collect();
        Ok(base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap_or_default())
    }

    pub(super) fn construct_tls_server(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let options = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let certificate_der = match self.fs_object_property(&options, "cert") {
            Some(Value::Str(pem)) => self.decode_tls_certificate_pem(&pem)?,
            _ => Vec::new(),
        };
        let alpn_protocols = self.tls_option_string_array(
            &options,
            "ALPNProtocols",
            (certificate_der.len() as u64).saturating_add(64 * 1024),
        )?;
        let tls = HermeticTlsServerState {
            has_certificate: !certificate_der.is_empty()
                && self.tls_option_has_string(&options, "key"),
            certificate_der,
            request_cert: self.tls_option_bool(&options, "requestCert", false),
            reject_unauthorized: self.tls_option_bool(&options, "rejectUnauthorized", true),
            alpn_protocols,
        };
        self.construct_loopback_server_with_tls(args, Some(tls))
    }

    pub(super) fn install_tls_socket_metadata(
        &mut self,
        socket: ObjectId,
        tls: HermeticTlsSocketState,
    ) -> Result<(), InterpreterError> {
        let Some(state) = self.loopback_sockets.get(&socket) else {
            return Err(InterpreterError::ObjectNotFound { id: socket.0 });
        };
        let previous_tls_bytes = state
            .tls
            .as_ref()
            .map_or(0, Self::estimate_tls_socket_state_bytes);
        let next_tls_bytes = Self::estimate_tls_socket_state_bytes(&tls);
        let property_keys = [
            "encrypted",
            "authorized",
            "authorizationError",
            "servername",
            "alpnProtocol",
        ];
        let heap_index = socket.0 as usize;
        let Some(object) = self.heap.get(heap_index) else {
            return Err(InterpreterError::ObjectNotFound { id: socket.0 });
        };
        // The socket's brand becomes "TlsSocket" (bd-9vouw.150).
        let tls_brand = JsString::from("TlsSocket");
        let previous_property_bytes = Self::saturating_sum(property_keys.iter().map(|key| {
            object
                .properties
                .get(key)
                .map_or(0, |value| Self::estimate_property_entry_bytes(key, value))
        }))
        .saturating_add(Self::estimate_brand_bytes(object.brand.as_deref()));
        let scalar_property_bytes = |key: &str| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_string_bytes(key).saturating_mul(2))
        };
        let string_property_bytes = |key: &str, value: &str| {
            scalar_property_bytes(key).saturating_add(Self::estimate_string_bytes(value))
        };
        let authorization_error_bytes = if tls.handshake_complete {
            tls.authorization_error.as_ref().map_or_else(
                || scalar_property_bytes("authorizationError"),
                |error| string_property_bytes("authorizationError", error),
            )
        } else {
            scalar_property_bytes("authorizationError")
        };
        let servername_bytes = tls.servername.as_ref().map_or_else(
            || scalar_property_bytes("servername"),
            |name| string_property_bytes("servername", name),
        );
        let alpn_protocol_bytes = tls.negotiated_alpn.as_ref().map_or_else(
            || scalar_property_bytes("alpnProtocol"),
            |protocol| string_property_bytes("alpnProtocol", protocol),
        );
        let next_property_bytes = Self::estimate_brand_bytes(Some(&tls_brand))
            .saturating_add(scalar_property_bytes("encrypted"))
            .saturating_add(scalar_property_bytes("authorized"))
            .saturating_add(authorization_error_bytes)
            .saturating_add(servername_bytes)
            .saturating_add(alpn_protocol_bytes);
        // Prove the simultaneous side-table plus heap-mirror high-water mark
        // before cloning any attacker-controlled string into a Value. After
        // this point all modeled fallible checks precede the atomic commit.
        self.check_temporary_memory_budget(next_tls_bytes.saturating_add(next_property_bytes))?;
        let authorized = tls.authorized;
        let authorization_error = if tls.handshake_complete {
            tls.authorization_error
                .as_ref()
                .map_or(Value::Undefined, |error| Value::str(error.as_str()))
        } else {
            Value::Undefined
        };
        let servername = tls
            .servername
            .as_ref()
            .map_or(Value::Undefined, |name| Value::str(name.as_str()));
        let alpn_protocol = tls
            .negotiated_alpn
            .as_ref()
            .map_or(Value::Bool(false), |protocol| Value::str(protocol.as_str()));
        let property_updates = [
            ("encrypted", Value::Bool(true)),
            ("authorized", Value::Bool(authorized)),
            ("authorizationError", authorization_error),
            ("servername", servername),
            ("alpnProtocol", alpn_protocol),
        ];
        self.apply_memory_component_delta(
            previous_tls_bytes.saturating_add(previous_property_bytes),
            next_tls_bytes.saturating_add(next_property_bytes),
        )?;

        self.loopback_sockets
            .get_mut(&socket)
            .expect("TLS socket was validated before atomic metadata commit")
            .tls = Some(tls);
        self.mutate_heap(|heap| {
            let object = heap
                .get_mut(heap_index)
                .expect("TLS socket heap object was validated before atomic metadata commit");
            for (key, value) in property_updates {
                object.properties.insert(key.to_string(), value);
            }
            object.brand = Some(Box::new(tls_brand));
        });
        self.gc_write_barrier(socket);
        Ok(())
    }

    pub(super) fn loopback_port_from_value(&self, value: &Value) -> Option<u16> {
        let candidate = match value {
            Value::Object(_) => self.fs_object_property(value, "port")?,
            other => other.clone(),
        };
        u16::try_from(Self::value_as_integer(&candidate)).ok()
    }

    /// Parse the port form accepted by hermetic `server.listen`. Missing ports
    /// select the deterministic ephemeral allocator, but malformed values must
    /// not silently acquire an unrelated ephemeral listener.
    pub(super) fn loopback_listen_port_from_value(
        &self,
        value: &Value,
    ) -> Result<u16, InterpreterError> {
        let candidate = match value {
            Value::Object(_) => self
                .fs_object_property(value, "port")
                .unwrap_or(Value::Undefined),
            other => other.clone(),
        };
        let port = match &candidate {
            Value::Undefined => return Ok(0),
            Value::Int(port) => Some(*port),
            Value::Float(port) if port.inner().is_finite() && port.inner().fract() == 0.0 => {
                Some(port.inner() as i64)
            }
            Value::Str(port) => {
                let trimmed = port.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    trimmed.parse::<f64>().ok().and_then(|port| {
                        (port.is_finite() && port.fract() == 0.0).then_some(port as i64)
                    })
                }
            }
            _ => None,
        };
        port.and_then(|port| u16::try_from(port).ok())
            .ok_or_else(|| InterpreterError::RangeError {
                message: "loopback listen port must be an integer between 0 and 65535".to_string(),
            })
    }

    pub(super) fn loopback_host_from_connect_args(
        &self,
        first: &Value,
        args: RegRange,
    ) -> Result<String, InterpreterError> {
        if matches!(first, Value::Object(_)) {
            let Some(value) = self.fs_object_property(first, "host") else {
                return Ok("127.0.0.1".to_string());
            };
            return self.bounded_loopback_host_string(&value);
        }
        if args.count >= 2 {
            let candidate = self.read_reg(args.start + 1)?;
            if candidate.is_callable() {
                return Ok("127.0.0.1".to_string());
            }
            return self.bounded_loopback_host_string(&candidate);
        }
        Ok("127.0.0.1".to_string())
    }

    pub(super) fn bounded_loopback_host_string(
        &self,
        value: &Value,
    ) -> Result<String, InterpreterError> {
        let source_len = match value {
            Value::Str(host) => host
                .as_str()
                .map_or(MAX_LOOPBACK_HOST_BYTES.saturating_add(1), str::len),
            Value::BigInt(host) => host.len(),
            _ => 0,
        };
        if source_len > MAX_LOOPBACK_HOST_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "loopback host length {source_len} exceeds {MAX_LOOPBACK_HOST_BYTES} bytes"
                ),
            });
        }
        let temporary_host_bytes = match value {
            Value::Str(host) => Self::estimate_js_string_bytes(host),
            Value::BigInt(host) => Self::estimate_string_bytes(host),
            _ => Self::estimate_string_bytes("[bounded loopback host]"),
        };
        self.check_temporary_memory_budget(temporary_host_bytes.saturating_add(64 * 1024))?;
        let host = match value {
            Value::Undefined | Value::Null | Value::Bool(_) | Value::Int(_) | Value::Float(_) => {
                self.value_to_string(value)
            }
            Value::Str(host) => host.as_str().unwrap_or_default().to_string(),
            Value::BigInt(host) => host.to_string(),
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "bounded primitive loopback host".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        if host.len() > MAX_LOOPBACK_HOST_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "loopback host length {} exceeds {MAX_LOOPBACK_HOST_BYTES} bytes",
                    host.len()
                ),
            });
        }
        Ok(host)
    }

    pub(super) fn connect_loopback_socket(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.connect_loopback_socket_with_tls(args, false)
    }

    pub(super) fn connect_tls_socket(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        self.connect_loopback_socket_with_tls(args, true)
    }

    pub(super) fn parse_loopback_connect_args(
        &self,
        args: RegRange,
    ) -> Result<(Option<u16>, String, Option<Value>), InterpreterError> {
        let first = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        if matches!(first, Value::Object(_)) && !first.is_callable() {
            let port = self.loopback_port_from_value(&first);
            let mut host = self.loopback_host_from_connect_args(&first, args)?;
            if host == "localhost" {
                host = "127.0.0.1".to_string();
            }
            return Ok((port, host, Some(first)));
        }

        let port = self.loopback_port_from_value(&first);
        let mut host_candidate = None;
        let mut options_obj = None;

        if args.count >= 2 {
            let second = self.read_reg(args.start + 1)?;
            if matches!(second, Value::Object(_)) && !second.is_callable() {
                options_obj = Some(second);
            } else if !second.is_callable() && !matches!(second, Value::Undefined) {
                host_candidate = Some(self.bounded_loopback_host_string(&second)?);
                if args.count >= 3 {
                    let third = self.read_reg(args.start + 2)?;
                    if matches!(third, Value::Object(_)) && !third.is_callable() {
                        options_obj = Some(third);
                    }
                }
            }
        }

        let final_port = port.or_else(|| {
            options_obj
                .as_ref()
                .and_then(|opt| self.loopback_port_from_value(opt))
        });

        let mut host = if let Some(h) = host_candidate {
            h
        } else if let Some(opt) = &options_obj {
            if let Some(h) = self.fs_object_property(opt, "host") {
                self.bounded_loopback_host_string(&h)?
            } else {
                "127.0.0.1".to_string()
            }
        } else {
            "127.0.0.1".to_string()
        };

        if host == "localhost" {
            host = "127.0.0.1".to_string();
        }

        Ok((final_port, host, options_obj))
    }

    pub(super) fn connect_loopback_socket_with_tls(
        &mut self,
        args: RegRange,
        is_tls: bool,
    ) -> Result<Value, InterpreterError> {
        let (port, host, options_obj) = self.parse_loopback_connect_args(args)?;
        let first = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let options_ref = options_obj.as_ref().unwrap_or(&first);
        let prepared_tls = if is_tls {
            let reject_unauthorized = self.tls_option_bool(options_ref, "rejectUnauthorized", true);
            let servername_opt = self
                .fs_object_property(options_ref, "servername")
                .or_else(|| self.fs_object_property(options_ref, "host"));
            let servername = match servername_opt {
                Some(Value::Str(value)) => Some(value.to_string()),
                _ => {
                    if host != "127.0.0.1" && host.parse::<std::net::IpAddr>().is_err() {
                        Some(host.clone())
                    } else if host == "127.0.0.1" {
                        Some("localhost".to_string())
                    } else {
                        None
                    }
                }
            };
            if servername
                .as_ref()
                .is_some_and(|value| value.len() > MAX_LOOPBACK_HOST_BYTES)
            {
                return Err(InterpreterError::RangeError {
                    message: format!(
                        "TLS servername length exceeds {MAX_LOOPBACK_HOST_BYTES} bytes"
                    ),
                });
            }
            let servername_bytes = servername.as_ref().map_or(0, |value| {
                MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(value.len() as u64)
            });
            let alpn_protocols = self.tls_option_string_array(
                options_ref,
                "ALPNProtocols",
                servername_bytes
                    .saturating_add(Self::estimate_string_bytes(&host))
                    .saturating_add(64 * 1024),
            )?;
            Some(HermeticTlsSocketState {
                server_side: false,
                handshake_complete: false,
                reject_unauthorized,
                servername,
                authorized: false,
                authorization_error: Some("DEPTH_ZERO_SELF_SIGNED_CERT".to_string()),
                alpn_protocols,
                negotiated_alpn: None,
                peer_certificate_der: Vec::new(),
            })
        } else {
            None
        };
        let server = port.and_then(|port| match self.loopback_ports.get(&port) {
            Some(LoopbackPortState::Live { server, generation })
                if self.loopback_servers.get(server).is_some_and(|state| {
                    state.listening
                        && state.generation == *generation
                        && state.port == Some(port)
                        && state.address == host
                }) =>
            {
                Some((*server, *generation))
            }
            _ => None,
        });
        drop(host);
        let lifecycle_label = self.writable_invocation_label(args)?;
        let client = self.construct_loopback_socket(false, port, lifecycle_label)?;
        let connect_event = if is_tls { "secureConnect" } else { "connect" };
        let mut connect_wrapper = None;
        if let Some(callback) = self.last_callable_arg(args)? {
            // bd-asw4m.5: the connect/secureConnect callback is a public once
            // registration, so rawListeners must expose a stable wrapper with
            // .listener identity, and publication must be failure-atomic
            // across the TLS metadata install and task scheduling below.
            let (wrapper, property_object, previous_heap_len) =
                self.create_event_once_wrapper(client, connect_event, callback, None)?;
            if let Err(error) = self.insert_event_listener(
                client,
                connect_event,
                EventListenerRecord {
                    listener: wrapper,
                    once: true,
                },
                false,
            ) {
                self.rollback_event_once_wrapper(property_object, previous_heap_len);
                return Err(error);
            }
            connect_wrapper = Some((property_object, previous_heap_len));
        }
        macro_rules! rollback_connect_registration {
            ($self:expr) => {
                if let Some((property_object, previous_heap_len)) = connect_wrapper {
                    $self.rollback_inserted_event_listener(client, connect_event, false);
                    $self.rollback_event_once_wrapper(property_object, previous_heap_len);
                }
            };
        }
        if let Some(tls) = prepared_tls {
            if let Err(error) = self.install_tls_socket_metadata(client, tls) {
                rollback_connect_registration!(self);
                return Err(error);
            }
        }
        if let Some((server, generation)) = server {
            if let Err(error) = self.schedule_loopback_task(PendingLoopbackTask::Connect {
                client,
                server,
                generation,
            }) {
                rollback_connect_registration!(self);
                return Err(error);
            }
        } else {
            let label = self.loopback_socket_label(client);
            if let Err(error) = self.schedule_loopback_task(PendingLoopbackTask::Error {
                target: client,
                code: "ECONNREFUSED".to_string(),
                label,
                close_after: true,
            }) {
                rollback_connect_registration!(self);
                return Err(error);
            }
        }
        Ok(Value::Object(client))
    }

    pub(super) fn loopback_server_receiver(receiver: Value) -> Result<ObjectId, InterpreterError> {
        match receiver {
            Value::Object(object_id) => Ok(object_id),
            other => Err(InterpreterError::TypeError {
                expected: "net.Server receiver".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn loopback_socket_receiver(receiver: Value) -> Result<ObjectId, InterpreterError> {
        match receiver {
            Value::Object(object_id) => Ok(object_id),
            other => Err(InterpreterError::TypeError {
                expected: "net.Socket receiver".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn loopback_server_label(&self, server: ObjectId) -> Label {
        self.loopback_servers
            .get(&server)
            .map(|state| state.lifecycle_label.clone())
            .unwrap_or(Label::Public)
    }

    pub(super) fn loopback_socket_label(&self, socket: ObjectId) -> Label {
        self.loopback_sockets
            .get(&socket)
            .map(|state| state.lifecycle_label.clone())
            .unwrap_or(Label::Public)
    }

    pub(super) fn join_loopback_server_label(
        &mut self,
        server: ObjectId,
        label: &Label,
    ) -> Result<Label, InterpreterError> {
        let previous_bytes = self.loopback_servers_memory_bytes();
        let Some(previous_label) = self
            .loopback_servers
            .get(&server)
            .map(|state| state.lifecycle_label.clone())
        else {
            return Err(InterpreterError::ObjectNotFound { id: server.0 });
        };
        let next_label = previous_label.join(label);
        let next_bytes = previous_bytes
            .saturating_sub(Self::estimate_label_bytes(&previous_label))
            .saturating_add(Self::estimate_label_bytes(&next_label));
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.loopback_servers
            .get_mut(&server)
            .expect("loopback server was validated before atomic label commit")
            .lifecycle_label = next_label.clone();
        Ok(next_label)
    }

    pub(super) fn join_loopback_socket_label(
        &mut self,
        socket: ObjectId,
        label: &Label,
    ) -> Result<Label, InterpreterError> {
        let previous_bytes = self.loopback_sockets_memory_bytes();
        let Some(previous_label) = self
            .loopback_sockets
            .get(&socket)
            .map(|state| state.lifecycle_label.clone())
        else {
            return Err(InterpreterError::ObjectNotFound { id: socket.0 });
        };
        let next_label = previous_label.join(label);
        let next_bytes = previous_bytes
            .saturating_sub(Self::estimate_label_bytes(&previous_label))
            .saturating_add(Self::estimate_label_bytes(&next_label));
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.loopback_sockets
            .get_mut(&socket)
            .expect("loopback socket was validated before atomic label commit")
            .lifecycle_label = next_label.clone();
        Ok(next_label)
    }

    /// Validate and price one public mirror write without mutating the heap.
    /// The returned previous value is a cheap/shared snapshot used only if a
    /// later transaction stage must restore the mirror.
    pub(super) fn project_loopback_mirror_property(
        &self,
        object_id: ObjectId,
        key: &str,
        value: &Value,
    ) -> Result<(Option<Value>, u64, u64), InterpreterError> {
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if !object.extensible() && !object.properties.contains_key(key) {
            return Err(InterpreterError::TypeError {
                expected: "existing property on non-extensible object".to_string(),
                got: "new property".to_string(),
            });
        }
        if object.is_frozen {
            return Err(InterpreterError::TypeError {
                expected: "mutable object".to_string(),
                got: "frozen object".to_string(),
            });
        }
        let previous = object.properties.get(key).cloned();
        let exact_order_is_active = object.properties.exact_len() != object.properties.len();
        let owned_key_copies =
            if exact_order_is_active && Self::canonical_array_index_key(key).is_none() {
                4
            } else {
                2
            };
        let entry_bytes = |entry: &Value| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_string_bytes(key).saturating_mul(owned_key_copies))
                .saturating_add(Self::estimate_value_bytes(entry))
        };
        Ok((
            previous.clone(),
            previous.as_ref().map_or(0, &entry_bytes),
            entry_bytes(value),
        ))
    }

    /// Restore a mirror after a later transaction stage refuses. Callers reset
    /// the aggregate memory total after all owned rollback steps complete.
    pub(super) fn restore_loopback_mirror_property(
        &mut self,
        object_id: ObjectId,
        key: &str,
        previous: Option<Value>,
    ) {
        self.mutate_heap(|heap| {
            let Some(object) = heap.get_mut(object_id.0 as usize) else {
                return;
            };
            if let Some(previous) = previous {
                object.properties.insert(key.to_string(), previous);
            } else {
                object.properties.remove(key);
            }
        });
        self.gc_write_barrier(object_id);
    }

    pub(super) fn preflight_loopback_transaction(
        &self,
        requested_bytes: u64,
    ) -> Result<(), InterpreterError> {
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        Ok(())
    }

    pub(super) fn loopback_server_listen(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let server = Self::loopback_server_receiver(receiver)?;
        let invocation_label = self.writable_invocation_label(args)?;
        let first = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let requested_port = self.loopback_listen_port_from_value(&first)?;
        let requested_host = if matches!(first, Value::Object(_)) {
            match self.fs_object_property(&first, "host") {
                Some(value) => Some(self.bounded_loopback_host_string(&value)?),
                None => None,
            }
        } else if args.count >= 2 {
            let candidate = self.read_reg(args.start + 1)?;
            if matches!(&candidate, Value::Str(_)) {
                Some(self.bounded_loopback_host_string(&candidate)?)
            } else {
                None
            }
        } else {
            None
        };
        let address = match requested_host.as_deref() {
            None | Some("127.0.0.1" | "localhost") => "127.0.0.1".to_string(),
            Some(address) => {
                return Err(InterpreterError::TypeError {
                    expected: "engine-owned loopback listener".to_string(),
                    got: address.to_string(),
                });
            }
        };
        let port = if requested_port == 0 {
            let start = self.next_loopback_port.max(41_000);
            let mut candidate = start;
            loop {
                if !self.loopback_ports.contains_key(&candidate) {
                    break candidate;
                }
                candidate = candidate.checked_add(1).unwrap_or(41_000);
                if candidate == start {
                    return Err(InterpreterError::RangeError {
                        message: "no deterministic loopback ports remain".to_string(),
                    });
                }
            }
        } else {
            if self.loopback_ports.contains_key(&requested_port) {
                return Err(InterpreterError::TypeError {
                    expected: "unused deterministic loopback port".to_string(),
                    got: format!("EADDRINUSE: address already in use 127.0.0.1:{requested_port}"),
                });
            }
            requested_port
        };
        let generation = self.next_loopback_listener_generation;
        let callback = self.last_callable_arg(args)?;
        let previous_servers_bytes = self.loopback_servers_memory_bytes();
        let (next_label, next_servers_bytes) = {
            let Some(state) = self.loopback_servers.get(&server) else {
                return Err(InterpreterError::ObjectNotFound { id: server.0 });
            };
            if state.listening {
                return Err(InterpreterError::TypeError {
                    expected: "non-listening loopback server".to_string(),
                    got: "server is already listening".to_string(),
                });
            }
            let previous_state_bytes = Self::estimate_loopback_server_state_bytes(state);
            let next_label = state.lifecycle_label.join(&invocation_label);
            let next_state_bytes = previous_state_bytes
                .saturating_sub(Self::estimate_string_bytes(&state.address))
                .saturating_sub(Self::estimate_label_bytes(&state.lifecycle_label))
                .saturating_add(Self::estimate_string_bytes(&address))
                .saturating_add(Self::estimate_label_bytes(&next_label));
            (
                next_label,
                previous_servers_bytes
                    .saturating_sub(previous_state_bytes)
                    .saturating_add(next_state_bytes),
            )
        };
        let listening_value = Value::Bool(true);
        let (previous_listening, previous_property_bytes, next_property_bytes) =
            self.project_loopback_mirror_property(server, "listening", &listening_value)?;
        let listener_bytes = callback.as_ref().map_or(0, |callback| {
            Self::estimate_event_listener_record_bytes(
                &RuntimePropertyKey::from("listening"),
                &EventListenerRecord {
                    listener: callback.clone(),
                    once: true,
                },
            )
        });
        let task = PendingLoopbackTask::Listening { server, generation };
        let task_bytes = self.projected_loopback_task_registration_bytes(&task);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_servers_bytes)
            .saturating_sub(previous_property_bytes)
            .saturating_add(next_servers_bytes)
            .saturating_add(next_property_bytes)
            .saturating_add(MEMORY_ESTIMATE_LOOPBACK_PORT_BASE_BYTES)
            .saturating_add(listener_bytes)
            .saturating_add(task_bytes);
        self.preflight_loopback_transaction(requested_bytes)?;

        let previous_total = self.estimated_memory_bytes;
        let sequence = self.schedule_loopback_task(task)?;
        let mut listening_wrapper = None;
        if let Some(callback) = callback {
            // bd-asw4m.5: the listen callback is a public once registration,
            // so rawListeners exposes a stable wrapper; publication stays
            // failure-atomic across task, property, and memory commit below.
            let (wrapper, property_object, previous_heap_len) =
                self.create_event_once_wrapper(server, "listening", callback, None)?;
            if let Err(error) = self.insert_event_listener(
                server,
                "listening",
                EventListenerRecord {
                    listener: wrapper,
                    once: true,
                },
                false,
            ) {
                self.rollback_event_once_wrapper(property_object, previous_heap_len);
                self.rollback_loopback_task_registration(sequence);
                self.estimated_memory_bytes = previous_total;
                return Err(error);
            }
            listening_wrapper = Some((property_object, previous_heap_len));
        }
        if let Err(error) =
            self.set_object_property(server, "listening".to_string(), listening_value)
        {
            if let Some((property_object, previous_heap_len)) = listening_wrapper {
                self.rollback_inserted_event_listener(server, "listening", false);
                self.rollback_event_once_wrapper(property_object, previous_heap_len);
            }
            self.rollback_loopback_task_registration(sequence);
            self.estimated_memory_bytes = previous_total;
            return Err(error);
        }
        if let Err(error) = self.apply_memory_component_delta(
            previous_servers_bytes,
            next_servers_bytes.saturating_add(MEMORY_ESTIMATE_LOOPBACK_PORT_BASE_BYTES),
        ) {
            self.restore_loopback_mirror_property(server, "listening", previous_listening);
            if let Some((property_object, previous_heap_len)) = listening_wrapper {
                self.rollback_inserted_event_listener(server, "listening", false);
                self.rollback_event_once_wrapper(property_object, previous_heap_len);
            }
            self.rollback_loopback_task_registration(sequence);
            self.estimated_memory_bytes = previous_total;
            return Err(error);
        }

        self.loopback_ports
            .insert(port, LoopbackPortState::Live { server, generation });
        let state = self
            .loopback_servers
            .get_mut(&server)
            .expect("loopback server was validated before listener publication");
        state.address = address;
        state.port = Some(port);
        state.generation = generation;
        state.listening = true;
        state.close_requested = false;
        state.close_scheduled = false;
        state.lifecycle_label = next_label;
        self.next_loopback_listener_generation = self
            .next_loopback_listener_generation
            .wrapping_add(1)
            .max(1);
        self.next_loopback_port = port.checked_add(1).unwrap_or(41_000);
        Ok(Value::Object(server))
    }

    pub(super) fn loopback_server_address(
        &mut self,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let server = Self::loopback_server_receiver(receiver)?;
        let Some(state) = self.loopback_servers.get(&server) else {
            return Err(InterpreterError::ObjectNotFound { id: server.0 });
        };
        if !state.listening {
            return Ok(Value::Null);
        }
        let port = state.port.unwrap_or(0);
        let address = state.address.clone();
        Ok(Value::Object(self.alloc_object_with_properties(&[
            ("port", Value::Int(i64::from(port))),
            ("address", Value::str(address)),
            ("family", Value::str("IPv4")),
        ])?))
    }

    pub(super) fn loopback_server_close(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let server = Self::loopback_server_receiver(receiver)?;
        let invocation_label = self.writable_invocation_label(args)?;
        self.check_temporary_memory_budget(64 * 1024)?;
        let lifecycle_label = self.join_loopback_server_label(server, &invocation_label)?;
        let (should_schedule, generation, port) = {
            let Some(state) = self.loopback_servers.get_mut(&server) else {
                return Err(InterpreterError::ObjectNotFound { id: server.0 });
            };
            state.listening = false;
            state.close_requested = true;
            let should_schedule = state.active_connections.is_empty() && !state.close_scheduled;
            if should_schedule {
                state.close_scheduled = true;
            }
            (should_schedule, state.generation, state.port)
        };
        if let Some(port) = port
            && matches!(
                self.loopback_ports.get(&port),
                Some(LoopbackPortState::Live {
                    server: registered,
                    generation: registered_generation,
                }) if *registered == server && *registered_generation == generation
            )
        {
            self.loopback_ports
                .insert(port, LoopbackPortState::Closed { generation });
        }
        self.set_object_property(server, "listening".to_string(), Value::Bool(false))?;
        let mut close_wrapper = None;
        if let Some(callback) = self.last_callable_arg(args)? {
            // bd-asw4m.5: the close callback is a public once registration,
            // so rawListeners exposes a stable wrapper; a scheduling failure
            // must not leave the wrapper published.
            let (wrapper, property_object, previous_heap_len) =
                self.create_event_once_wrapper(server, "close", callback, None)?;
            if let Err(error) = self.insert_event_listener(
                server,
                "close",
                EventListenerRecord {
                    listener: wrapper,
                    once: true,
                },
                false,
            ) {
                self.rollback_event_once_wrapper(property_object, previous_heap_len);
                return Err(error);
            }
            close_wrapper = Some((property_object, previous_heap_len));
        }
        if should_schedule {
            if let Err(error) = self.schedule_loopback_task(PendingLoopbackTask::ServerClose {
                server,
                generation,
                label: lifecycle_label,
            }) {
                if let Some((property_object, previous_heap_len)) = close_wrapper {
                    self.rollback_inserted_event_listener(server, "close", false);
                    self.rollback_event_once_wrapper(property_object, previous_heap_len);
                }
                return Err(error);
            }
        }
        Ok(Value::Object(server))
    }

    pub(super) fn loopback_socket_write(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let socket = Self::loopback_socket_receiver(receiver)?;
        let chunk = self.builtin_arg(args, 0)?.unwrap_or(Value::str(""));
        let bytes = self.fs_value_bytes(&chunk)?;
        let byte_count = bytes.len() as u64;
        let binary_label = match &chunk {
            Value::Object(object_id) => self.binary_storage_label(*object_id),
            _ => Label::Public,
        };
        let invocation_label = self.writable_invocation_label(args)?.join(&binary_label);
        let previous_sockets_bytes = self.loopback_sockets_memory_bytes();
        let (previous_state_bytes, previous_label, previous_bytes_written, peer, refused) = {
            let Some(state) = self.loopback_sockets.get(&socket) else {
                return Err(InterpreterError::ObjectNotFound { id: socket.0 });
            };
            (
                Self::estimate_loopback_socket_state_bytes(state),
                state.lifecycle_label.clone(),
                state.bytes_written,
                state.peer,
                state.local_ended || state.destroyed,
            )
        };
        let data_label = previous_label.join(&invocation_label);
        let next_bytes_written = previous_bytes_written.saturating_add(byte_count);
        let (task, buffered_record) = if refused {
            drop(bytes);
            (
                Some(PendingLoopbackTask::Error {
                    target: socket,
                    code: "ERR_STREAM_WRITE_AFTER_END".to_string(),
                    label: data_label.clone(),
                    close_after: false,
                }),
                None,
            )
        } else if let Some(target) = peer {
            (
                Some(PendingLoopbackTask::Data {
                    target,
                    bytes,
                    label: data_label.clone(),
                }),
                None,
            )
        } else {
            (
                None,
                Some(LoopbackBufferedData {
                    bytes,
                    label: data_label.clone(),
                }),
            )
        };
        let buffered_bytes = buffered_record.as_ref().map_or(0, |record| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(record.bytes.len() as u64)
                .saturating_add(Self::estimate_label_bytes(&record.label))
        });
        let next_state_bytes = previous_state_bytes
            .saturating_sub(Self::estimate_label_bytes(&previous_label))
            .saturating_add(Self::estimate_label_bytes(&data_label))
            .saturating_add(buffered_bytes);
        let next_sockets_bytes = previous_sockets_bytes
            .saturating_sub(previous_state_bytes)
            .saturating_add(next_state_bytes);
        let mirror_update = if refused {
            None
        } else {
            let value = Value::Int(i64::try_from(next_bytes_written).unwrap_or(i64::MAX));
            let (previous, previous_bytes, next_bytes) =
                self.project_loopback_mirror_property(socket, "bytesWritten", &value)?;
            Some((previous, previous_bytes, next_bytes, value))
        };
        let previous_property_bytes = mirror_update
            .as_ref()
            .map_or(0, |(_, previous_bytes, _, _)| *previous_bytes);
        let next_property_bytes = mirror_update
            .as_ref()
            .map_or(0, |(_, _, next_bytes, _)| *next_bytes);
        let task_bytes = task.as_ref().map_or(0, |task| {
            self.projected_loopback_task_registration_bytes(task)
        });
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_sockets_bytes)
            .saturating_sub(previous_property_bytes)
            .saturating_add(next_sockets_bytes)
            .saturating_add(next_property_bytes)
            .saturating_add(task_bytes);
        self.preflight_loopback_transaction(requested_bytes)?;

        if buffered_record.is_some() {
            let allocation_error =
                self.memory_budget_error(requested_bytes, self.heap_object_count_u32());
            self.loopback_sockets
                .get_mut(&socket)
                .expect("socket was validated before outbound queue reservation")
                .pending_outbound
                .try_reserve(1)
                .map_err(|_| allocation_error)?;
        }

        let previous_total = self.estimated_memory_bytes;
        let sequence = match task {
            Some(task) => Some(self.schedule_loopback_task(task)?),
            None => None,
        };
        if let Some((_, _, _, value)) = &mirror_update
            && let Err(error) =
                self.set_object_property(socket, "bytesWritten".to_string(), value.clone())
        {
            if let Some(sequence) = sequence {
                self.rollback_loopback_task_registration(sequence);
            }
            self.estimated_memory_bytes = previous_total;
            return Err(error);
        }
        if let Err(error) =
            self.apply_memory_component_delta(previous_sockets_bytes, next_sockets_bytes)
        {
            if let Some((previous, _, _, _)) = mirror_update {
                self.restore_loopback_mirror_property(socket, "bytesWritten", previous);
            }
            if let Some(sequence) = sequence {
                self.rollback_loopback_task_registration(sequence);
            }
            self.estimated_memory_bytes = previous_total;
            return Err(error);
        }

        let state = self
            .loopback_sockets
            .get_mut(&socket)
            .expect("socket was validated before atomic write publication");
        state.lifecycle_label = data_label;
        if refused {
            return Ok(Value::Bool(false));
        }
        state.bytes_written = next_bytes_written;
        if let Some(record) = buffered_record {
            state.pending_outbound.push_back(record);
        }
        Ok(Value::Bool(true))
    }

    pub(super) fn maybe_schedule_loopback_close(
        &mut self,
        socket: ObjectId,
    ) -> Result<(), InterpreterError> {
        let should_schedule = if let Some(state) = self.loopback_sockets.get_mut(&socket) {
            let should_schedule = state.local_ended
                && state.remote_ended
                && !state.destroyed
                && !state.close_scheduled;
            if should_schedule {
                state.close_scheduled = true;
            }
            should_schedule
        } else {
            false
        };
        if should_schedule {
            let label = self.loopback_socket_label(socket);
            self.schedule_loopback_task(PendingLoopbackTask::Close {
                target: socket,
                had_error: false,
                label,
            })?;
        }
        Ok(())
    }

    pub(super) fn loopback_socket_end(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let socket = Self::loopback_socket_receiver(receiver)?;
        if args.count > 0 {
            let first = self.read_reg(args.start)?;
            if !first.is_callable() && !matches!(first, Value::Undefined) {
                let one_arg = RegRange {
                    start: args.start,
                    count: 1,
                };
                let _ = self.loopback_socket_write(Value::Object(socket), one_arg)?;
            }
        }
        // bd-asw4m.5: Node keeps socket.end(callback) OUTSIDE the
        // EventEmitter finish listener set, so the completion carrier is a
        // dedicated state field — invisible to listeners("finish") and
        // rawListeners("finish") — instead of a one-shot record.
        if let Some(callback) = self.last_callable_arg(args)? {
            let previous_sockets_bytes = self.loopback_sockets_memory_bytes();
            {
                let Some(state) = self.loopback_sockets.get_mut(&socket) else {
                    return Err(InterpreterError::ObjectNotFound { id: socket.0 });
                };
                state.end_completion_callback = Some(callback);
            }
            let next_sockets_bytes = self.loopback_sockets_memory_bytes();
            if let Err(error) =
                self.apply_memory_component_delta(previous_sockets_bytes, next_sockets_bytes)
            {
                if let Some(state) = self.loopback_sockets.get_mut(&socket) {
                    state.end_completion_callback = None;
                }
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(next_sockets_bytes.saturating_sub(previous_sockets_bytes));
                return Err(error);
            }
        }
        let invocation_label = self.writable_invocation_label(args)?;
        let lifecycle_label = self.join_loopback_socket_label(socket, &invocation_label)?;
        let peer = {
            let Some(state) = self.loopback_sockets.get_mut(&socket) else {
                return Err(InterpreterError::ObjectNotFound { id: socket.0 });
            };
            if state.local_ended {
                return Ok(Value::Object(socket));
            }
            state.local_ended = true;
            state.peer
        };
        let _ = self.emit_event_listener_records(
            module,
            socket,
            "finish",
            Vec::new(),
            lifecycle_label.clone(),
        )?;
        // Node fires the end-completion callback after the finish event, from
        // the dedicated carrier rather than the listener set (bd-asw4m.5).
        if let Some(callback) = self
            .loopback_sockets
            .get_mut(&socket)
            .and_then(|state| state.end_completion_callback.take())
        {
            let previous_sockets_bytes = self.loopback_sockets_memory_bytes();
            let completion = self.emit_event_listener_snapshot(
                module,
                socket,
                "finish",
                Vec::new(),
                lifecycle_label.clone(),
                vec![EventListenerRecord {
                    listener: callback,
                    once: true,
                }],
            );
            let next_sockets_bytes = self.loopback_sockets_memory_bytes();
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_sockets_bytes.saturating_sub(next_sockets_bytes));
            completion?;
        }
        if let Some(target) = peer {
            self.schedule_loopback_task(PendingLoopbackTask::End {
                target,
                label: lifecycle_label,
            })?;
        } else if let Some(state) = self.loopback_sockets.get_mut(&socket) {
            state.pending_outbound_end = true;
        }
        self.maybe_schedule_loopback_close(socket)?;
        Ok(Value::Object(socket))
    }

    pub(super) fn loopback_socket_destroy(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let socket = Self::loopback_socket_receiver(receiver)?;
        let invocation_label = self.writable_invocation_label(args)?;
        let lifecycle_label = self.join_loopback_socket_label(socket, &invocation_label)?;
        let previous_socket_bytes = self.loopback_sockets_memory_bytes();
        let peer = {
            let Some(state) = self.loopback_sockets.get_mut(&socket) else {
                return Err(InterpreterError::ObjectNotFound { id: socket.0 });
            };
            if state.destroyed || state.close_scheduled {
                return Ok(Value::Object(socket));
            }
            state.destroyed = true;
            state.close_scheduled = true;
            state.pending_data.clear();
            state.pending_end = false;
            state.pending_outbound.clear();
            state.pending_outbound_end = false;
            state.peer.take()
        };
        if let Some(target) = peer
            && let Some(state) = self.loopback_sockets.get_mut(&target)
            && state.peer == Some(socket)
        {
            state.peer = None;
        }
        self.apply_memory_component_delta(
            previous_socket_bytes,
            self.loopback_sockets_memory_bytes(),
        )?;
        self.set_object_property(socket, "destroyed".to_string(), Value::Bool(true))?;
        self.set_object_property(socket, "readable".to_string(), Value::Bool(false))?;
        self.set_object_property(socket, "writable".to_string(), Value::Bool(false))?;
        self.schedule_loopback_task(PendingLoopbackTask::Close {
            target: socket,
            had_error: false,
            label: lifecycle_label.clone(),
        })?;
        if let Some(target) = peer {
            self.schedule_loopback_task(PendingLoopbackTask::End {
                target,
                label: lifecycle_label,
            })?;
        }
        Ok(Value::Object(socket))
    }

    pub(super) fn loopback_socket_set_encoding(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let socket = Self::loopback_socket_receiver(receiver)?;
        let invocation_label = self.writable_invocation_label(args)?;
        self.join_loopback_socket_label(socket, &invocation_label)?;
        let encoding = self
            .builtin_arg(args, 0)?
            .map(|value| self.value_to_string(&value).to_ascii_lowercase())
            .unwrap_or_default();
        if let Some(state) = self.loopback_sockets.get_mut(&socket) {
            state.encoding_utf8 = matches!(encoding.as_str(), "utf8" | "utf-8");
        }
        Ok(Value::Object(socket))
    }

    pub(super) fn loopback_socket_pause(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let socket = Self::loopback_socket_receiver(receiver)?;
        let invocation_label = self.writable_invocation_label(args)?;
        self.join_loopback_socket_label(socket, &invocation_label)?;
        if let Some(state) = self.loopback_sockets.get_mut(&socket) {
            state.paused = true;
        }
        Ok(Value::Object(socket))
    }

    pub(super) fn loopback_socket_resume(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let socket = Self::loopback_socket_receiver(receiver)?;
        let invocation_label = self.writable_invocation_label(args)?;
        let lifecycle_label = self.join_loopback_socket_label(socket, &invocation_label)?;
        let previous_socket_bytes = self.loopback_sockets_memory_bytes();
        let (pending_data, pending_end) = {
            let Some(state) = self.loopback_sockets.get_mut(&socket) else {
                return Err(InterpreterError::ObjectNotFound { id: socket.0 });
            };
            state.paused = false;
            (
                std::mem::take(&mut state.pending_data),
                std::mem::take(&mut state.pending_end),
            )
        };
        self.apply_memory_component_delta(
            previous_socket_bytes,
            self.loopback_sockets_memory_bytes(),
        )?;
        for data in pending_data {
            self.schedule_loopback_task(PendingLoopbackTask::Data {
                target: socket,
                bytes: data.bytes,
                label: data.label.join(&lifecycle_label),
            })?;
        }
        if pending_end {
            self.schedule_loopback_task(PendingLoopbackTask::End {
                target: socket,
                label: lifecycle_label,
            })?;
        }
        Ok(Value::Object(socket))
    }

    pub(super) fn loopback_socket_chainable(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let socket = Self::loopback_socket_receiver(receiver)?;
        let invocation_label = self.writable_invocation_label(args)?;
        self.join_loopback_socket_label(socket, &invocation_label)?;
        Ok(Value::Object(socket))
    }

    pub(super) fn tls_socket_id(&self, receiver: Value) -> Result<ObjectId, InterpreterError> {
        let socket = Self::loopback_socket_receiver(receiver)?;
        let has_tls_state = self
            .loopback_sockets
            .get(&socket)
            .is_some_and(|state| state.tls.is_some());
        if !has_tls_state {
            return Err(InterpreterError::TypeError {
                expected: "tls.TLSSocket receiver".to_string(),
                got: "net.Socket".to_string(),
            });
        }
        Ok(socket)
    }

    pub(super) fn tls_socket_get_peer_certificate(
        &mut self,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let socket = self.tls_socket_id(receiver)?;
        let has_peer_certificate = self
            .loopback_sockets
            .get(&socket)
            .and_then(|state| state.tls.as_ref())
            .is_some_and(|tls| {
                tls.handshake_complete && !tls.server_side && !tls.peer_certificate_der.is_empty()
            });
        if !has_peer_certificate {
            return Ok(Value::Object(self.alloc_object_with_properties(&[])?));
        }
        let peer_certificate_der = {
            let tls = self
                .loopback_sockets
                .get_mut(&socket)
                .and_then(|state| state.tls.as_mut())
                .expect("TLS socket was validated before certificate access");
            std::mem::take(&mut tls.peer_certificate_der)
        };
        let raw_result = self.alloc_buffer_from_bytes(&peer_certificate_der);
        self.loopback_sockets
            .get_mut(&socket)
            .and_then(|state| state.tls.as_mut())
            .expect("TLS socket exists while restoring certificate state")
            .peer_certificate_der = peer_certificate_der;
        let raw = raw_result?;
        let certificate_label = self.loopback_socket_label(socket);
        self.join_binary_storage_label(raw, &certificate_label)?;

        // Parse the narrow X.509 metadata surface (subject.CN,
        // issuer.CN, valid_from, valid_to) via the bounded
        // `tls_x509_metadata` parser. Any parse failure is
        // fail-closed: the raw Buffer is still surfaced, the
        // optional fields are simply absent.
        let der_snapshot = self
            .loopback_sockets
            .get(&socket)
            .and_then(|state| state.tls.as_ref())
            .map(|tls| tls.peer_certificate_der.clone())
            .unwrap_or_default();
        let parsed = crate::tls_x509_metadata::parse_x509_metadata(&der_snapshot);

        // Build a flat Vec of properties so we can interleave the
        // nested `subject` / `issuer` objects alongside the scalars
        // without juggling two allocations.
        let mut props: Vec<(&str, Value)> = Vec::with_capacity(5);
        props.push(("raw", Value::Object(raw)));
        if let Ok(md) = &parsed {
            if let Some(cn) = md.subject_cn.as_deref() {
                let subject_id = self.alloc_object_with_properties(&[("CN", Value::str(cn))])?;
                props.push(("subject", Value::Object(subject_id)));
            }
            if let Some(cn) = md.issuer_cn.as_deref() {
                let issuer_id = self.alloc_object_with_properties(&[("CN", Value::str(cn))])?;
                props.push(("issuer", Value::Object(issuer_id)));
            }
            if let Some(vf) = md.valid_from.as_deref() {
                props.push(("valid_from", Value::str(vf)));
            }
            if let Some(vt) = md.valid_to.as_deref() {
                props.push(("valid_to", Value::str(vt)));
            }
        }
        Ok(Value::Object(self.alloc_object_with_properties(&props)?))
    }

    pub(super) fn tls_handshake_complete(&self, receiver: Value) -> Result<bool, InterpreterError> {
        let socket = self.tls_socket_id(receiver)?;
        Ok(self
            .loopback_sockets
            .get(&socket)
            .and_then(|state| state.tls.as_ref())
            .is_some_and(|tls| tls.handshake_complete))
    }

    pub(super) fn tls_socket_get_protocol(
        &self,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        if !self.tls_handshake_complete(receiver)? {
            return Ok(Value::Undefined);
        }
        Ok(Value::str("TLSv1.3"))
    }

    pub(super) fn tls_socket_get_cipher(
        &mut self,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        if !self.tls_handshake_complete(receiver)? {
            return Ok(Value::Undefined);
        }
        Ok(Value::Object(self.alloc_object_with_properties(&[
            ("name", Value::str("TLS_AES_256_GCM_SHA384")),
            ("standardName", Value::str("TLS_AES_256_GCM_SHA384")),
            ("version", Value::str("TLSv1.3")),
        ])?))
    }

    pub(super) fn tls_socket_is_session_reused(
        &self,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        let _ = self.tls_socket_id(receiver)?;
        Ok(Value::Bool(false))
    }

    pub(super) fn tls_socket_get_session(
        &self,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        if !self.tls_handshake_complete(receiver)? {
            return Ok(Value::Undefined);
        }
        Ok(Value::Null)
    }

    pub(super) fn rfc6125_match_dns_name(pattern: &str, hostname: &str) -> bool {
        let pattern = pattern.trim();
        let hostname = hostname.trim();
        if pattern.is_empty() || hostname.is_empty() {
            return false;
        }
        if pattern.eq_ignore_ascii_case(hostname) {
            return true;
        }
        if !pattern.contains('*') {
            return false;
        }
        let pattern_labels: Vec<&str> = pattern.split('.').collect();
        let host_labels: Vec<&str> = hostname.split('.').collect();

        // RFC 6125: must have the same number of labels and cannot wildcard a TLD (*.com)
        if pattern_labels.len() != host_labels.len() || pattern_labels.len() < 3 {
            return false;
        }

        // Non-leftmost labels must match exactly (case-insensitively)
        for (p_label, h_label) in pattern_labels[1..].iter().zip(&host_labels[1..]) {
            if !p_label.eq_ignore_ascii_case(h_label) {
                return false;
            }
        }

        let p_first = pattern_labels[0];
        let h_first = host_labels[0];

        // Disallow wildcard on IDN A-labels
        if p_first.to_ascii_lowercase().starts_with("xn--")
            || h_first.to_ascii_lowercase().starts_with("xn--")
        {
            return false;
        }

        if p_first == "*" {
            return !h_first.is_empty();
        }

        let star_count = p_first.chars().filter(|&c| c == '*').count();
        if star_count != 1 {
            return false;
        }

        let star_idx = match p_first.find('*') {
            Some(idx) => idx,
            None => return false,
        };
        let prefix = &p_first[..star_idx];
        let suffix = &p_first[star_idx + 1..];

        if h_first.len() < prefix.len() + suffix.len() {
            return false;
        }

        let h_first_lower = h_first.to_ascii_lowercase();
        let prefix_lower = prefix.to_ascii_lowercase();
        let suffix_lower = suffix.to_ascii_lowercase();

        h_first_lower.starts_with(&prefix_lower) && h_first_lower.ends_with(&suffix_lower)
    }

    pub(super) fn tls_check_server_identity(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        use std::net::IpAddr;

        let host = self
            .builtin_arg(args, 0)?
            .map(|value| self.value_to_string(&value))
            .unwrap_or_default();
        let certificate = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let subject_alt_name = self
            .fs_object_property(&certificate, "subjectaltname")
            .map(|value| self.value_to_string(&value));
        let common_name = self
            .fs_object_property(&certificate, "subject")
            .and_then(|subject| self.fs_object_property(&subject, "CN"))
            .map(|value| self.value_to_string(&value));
        let host_ip = host.parse::<IpAddr>().ok();
        let alt_matches = subject_alt_name.as_deref().is_some_and(|names| {
            names.split(',').any(|entry| {
                let entry = entry.trim();
                if let Some(host_ip) = host_ip {
                    entry
                        .strip_prefix("IP Address:")
                        .and_then(|address| address.parse::<IpAddr>().ok())
                        == Some(host_ip)
                } else if let Some(dns_pattern) = entry.strip_prefix("DNS:") {
                    Self::rfc6125_match_dns_name(dns_pattern, &host)
                } else {
                    false
                }
            })
        });
        // RFC 6125-style precedence: once a certificate supplies a SAN, the
        // legacy subject CN must not override a SAN mismatch.
        let identity_matches = if host_ip.is_some() {
            alt_matches
        } else if subject_alt_name.is_some() {
            alt_matches
        } else {
            common_name
                .as_deref()
                .is_some_and(|name| Self::rfc6125_match_dns_name(name, &host))
        };
        if identity_matches {
            return Ok(Value::Undefined);
        }
        let prototype = self.ensure_builtin_prototype("Error")?;
        let error = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_like_object(
            error,
            "Error",
            format!("Host name {host} does not match the certificate"),
        )?;
        self.set_object_property(
            error,
            "code".to_string(),
            Value::str("ERR_TLS_CERT_ALTNAME_INVALID"),
        )?;
        Ok(Value::Object(error))
    }

    pub(super) fn tls_root_certificates(&mut self) -> Result<Value, InterpreterError> {
        // Official ISRG Root X1 from https://letsencrypt.org/certs/isrgrootx1.pem
        // (SHA1 CA:BD:2A:79:A1:07:6A:31:F2:1D:25:36:35:CB:03:9D:43:29:A5:E8).
        // A widely copied PEM with serial `RQB42JUo340w` is ASN.1-corrupt
        // (cryptography ExtraData / Node ERR_OSSL_ASN1_TOO_LONG).
        const HERMETIC_ROOT_CERTIFICATES: &[&str] = &[concat!(
            "-----BEGIN CERTIFICATE-----\n",
            "MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\n",
            "TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n",
            "cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4\n",
            "WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu\n",
            "ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY\n",
            "MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc\n",
            "h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+\n",
            "0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U\n",
            "A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW\n",
            "T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH\n",
            "B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC\n",
            "B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv\n",
            "KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn\n",
            "OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn\n",
            "jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw\n",
            "qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI\n",
            "rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\n",
            "HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq\n",
            "hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL\n",
            "ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ\n",
            "3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK\n",
            "NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5\n",
            "ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur\n",
            "TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC\n",
            "jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc\n",
            "oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq\n",
            "4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA\n",
            "mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d\n",
            "emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=\n",
            "-----END CERTIFICATE-----"
        )];
        let roots: Vec<Value> = HERMETIC_ROOT_CERTIFICATES
            .iter()
            .map(|pem| Value::str(*pem))
            .collect();
        Ok(Value::Object(self.alloc_array_from_values(&roots)?))
    }

    pub(super) fn tls_get_ciphers(&mut self) -> Result<Value, InterpreterError> {
        let ciphers = [
            Value::str("tls_aes_256_gcm_sha384"),
            Value::str("tls_aes_128_gcm_sha256"),
        ];
        Ok(Value::Object(self.alloc_array_from_values(&ciphers)?))
    }

    pub(super) fn tls_create_secure_context(&mut self) -> Result<Value, InterpreterError> {
        Ok(Value::Object(
            self.alloc_branded_object("TlsSecureContext", &[])?,
        ))
    }

    pub(super) fn net_socket_instanceof(&self, args: RegRange) -> Result<Value, InterpreterError> {
        let candidate = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let is_socket = match candidate {
            Value::Object(object_id) => self.loopback_sockets.contains_key(&object_id),
            _ => false,
        };
        Ok(Value::Bool(is_socket))
    }

    pub(super) fn emit_loopback_event(
        &mut self,
        module: Option<&Ir3Module>,
        target: ObjectId,
        event: &str,
        arguments: Vec<Value>,
        emission_label: Label,
    ) -> Result<bool, InterpreterError> {
        let Some(module) = module else {
            return Ok(false);
        };
        self.emit_event_listener_records(module, target, event, arguments, emission_label)
    }

    pub(super) fn execute_pending_loopback_task(
        &mut self,
        task: PendingLoopbackTask,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let retained_bytes = Self::estimate_pending_loopback_task_bytes(&task);
        self.loopback_task_in_flight_bytes = self
            .loopback_task_in_flight_bytes
            .saturating_add(retained_bytes);
        let gc_pins = self.gc_pin_loopback_task(&task);
        let result = self.drive_pending_loopback_task(task, module);
        self.gc_unpin_network_values(gc_pins);
        self.loopback_task_in_flight_bytes = self
            .loopback_task_in_flight_bytes
            .saturating_sub(retained_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(retained_bytes);
        result
    }

    pub(super) fn drive_pending_loopback_task(
        &mut self,
        task: PendingLoopbackTask,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        match task {
            PendingLoopbackTask::Listening { server, generation } => {
                let current = self.loopback_servers.get(&server).is_some_and(|state| {
                    state.listening
                        && state.generation == generation
                        && state.port.is_some_and(|port| {
                            matches!(
                                self.loopback_ports.get(&port),
                                Some(LoopbackPortState::Live {
                                    server: registered,
                                    generation: registered_generation,
                                }) if *registered == server
                                    && *registered_generation == generation
                            )
                        })
                });
                if !current {
                    return Ok(());
                }
                let label = self.loopback_server_label(server);
                let _ = self.emit_loopback_event(module, server, "listening", Vec::new(), label)?;
            }
            PendingLoopbackTask::Connect {
                client,
                server,
                generation,
            } => {
                if !self.loopback_sockets.contains_key(&client)
                    || self
                        .loopback_sockets
                        .get(&client)
                        .is_some_and(|state| state.destroyed)
                {
                    return Ok(());
                }
                if !self.loopback_servers.get(&server).is_some_and(|state| {
                    state.listening
                        && state.generation == generation
                        && state.port.is_some_and(|port| {
                            matches!(
                                self.loopback_ports.get(&port),
                                Some(LoopbackPortState::Live {
                                    server: registered,
                                    generation: registered_generation,
                                }) if *registered == server
                                    && *registered_generation == generation
                            )
                        })
                }) {
                    let label = self.loopback_socket_label(client);
                    self.schedule_loopback_task(PendingLoopbackTask::Error {
                        target: client,
                        code: "ECONNREFUSED".to_string(),
                        label,
                        close_after: true,
                    })?;
                    return Ok(());
                }
                // Cloning TLS records below is intentional: the connection
                // admission path must release immutable side-table borrows
                // before it can allocate the accepted socket. Preflight a
                // conservative simultaneous peak: both transient records,
                // their persistent endpoint copies, plus fixed heap/task/error
                // headroom. Subsequent per-allocation checks alone would miss
                // this combined high-water mark.
                let tls_clone_bytes = self
                    .loopback_sockets
                    .get(&client)
                    .and_then(|state| state.tls.as_ref())
                    .map_or(0, Self::estimate_tls_socket_state_bytes)
                    .saturating_add(
                        self.loopback_servers
                            .get(&server)
                            .and_then(|state| state.tls.as_ref())
                            .map_or(0, Self::estimate_tls_server_state_bytes),
                    );
                self.check_temporary_memory_budget(
                    tls_clone_bytes.saturating_mul(3).saturating_add(128 * 1024),
                )?;
                let client_tls = self
                    .loopback_sockets
                    .get(&client)
                    .and_then(|state| state.tls.clone());
                let server_tls = self
                    .loopback_servers
                    .get(&server)
                    .and_then(|state| state.tls.clone());
                let remote_port = self
                    .loopback_servers
                    .get(&server)
                    .and_then(|state| state.port);
                let failure = match (client_tls.as_ref(), server_tls.as_ref()) {
                    (None, Some(_)) => Some("ERR_SSL_HTTP_REQUEST"),
                    (Some(_), None) => Some("ERR_SSL_WRONG_VERSION_NUMBER"),
                    (Some(_), Some(server_tls)) if !server_tls.has_certificate => {
                        Some("ERR_SSL_NO_CERTIFICATE_ASSIGNED")
                    }
                    (Some(client_tls), Some(_)) if client_tls.reject_unauthorized => {
                        Some("DEPTH_ZERO_SELF_SIGNED_CERT")
                    }
                    // The hermetic TLS model deliberately has no trust-store
                    // or certificate-chain validator for client identities.
                    // A server that requires authorization must therefore
                    // fail closed instead of treating an absent/unverified
                    // client certificate as authenticated.
                    (Some(_), Some(server_tls))
                        if server_tls.request_cert && server_tls.reject_unauthorized =>
                    {
                        Some("UNABLE_TO_VERIFY_LEAF_SIGNATURE")
                    }
                    _ => None,
                };
                if let Some(code) = failure {
                    let label = self
                        .loopback_socket_label(client)
                        .join(&self.loopback_server_label(server));
                    if let Some(server_tls) = server_tls.as_ref() {
                        let failed_socket =
                            self.construct_loopback_socket(false, remote_port, label.clone())?;
                        let failed_tls = HermeticTlsSocketState {
                            server_side: true,
                            handshake_complete: false,
                            reject_unauthorized: server_tls.reject_unauthorized,
                            servername: client_tls.as_ref().and_then(|tls| tls.servername.clone()),
                            authorized: false,
                            authorization_error: Some(code.to_string()),
                            alpn_protocols: server_tls.alpn_protocols.clone(),
                            negotiated_alpn: None,
                            peer_certificate_der: Vec::new(),
                        };
                        self.install_tls_socket_metadata(failed_socket, failed_tls)?;
                        if let Some(state) = self.loopback_sockets.get_mut(&failed_socket) {
                            state.destroyed = true;
                        }
                        self.set_object_property(
                            failed_socket,
                            "destroyed".to_string(),
                            Value::Bool(true),
                        )?;
                        let prototype = self.ensure_builtin_prototype("Error")?;
                        let error = self.alloc_object_with_prototype(Some(prototype))?;
                        self.initialize_error_like_object(
                            error,
                            "Error",
                            format!("TLS handshake failed: {code}"),
                        )?;
                        self.set_object_property(error, "code".to_string(), Value::str(code))?;
                        let _ = self.emit_loopback_event(
                            module,
                            server,
                            "tlsClientError",
                            vec![Value::Object(error), Value::Object(failed_socket)],
                            label.clone(),
                        )?;
                    }
                    self.schedule_loopback_task(PendingLoopbackTask::Error {
                        target: client,
                        code: code.to_string(),
                        label,
                        close_after: true,
                    })?;
                    return Ok(());
                }
                let connection_label = self
                    .loopback_sockets
                    .get(&client)
                    .map(|state| state.lifecycle_label.clone())
                    .unwrap_or(Label::Public)
                    .join(
                        &self
                            .loopback_servers
                            .get(&server)
                            .map(|state| state.lifecycle_label.clone())
                            .unwrap_or(Label::Public),
                    );
                self.join_loopback_socket_label(client, &connection_label)?;
                let accepted =
                    self.construct_loopback_socket(true, remote_port, connection_label.clone())?;
                if let (Some(mut client_tls), Some(server_tls)) = (client_tls, server_tls) {
                    let negotiated_alpn = server_tls
                        .alpn_protocols
                        .iter()
                        .find(|server_protocol| {
                            client_tls
                                .alpn_protocols
                                .iter()
                                .any(|client_protocol| client_protocol == *server_protocol)
                        })
                        .cloned();
                    client_tls.handshake_complete = true;
                    client_tls.negotiated_alpn = negotiated_alpn.clone();
                    client_tls.peer_certificate_der = server_tls.certificate_der.clone();
                    let accepted_tls = HermeticTlsSocketState {
                        server_side: true,
                        handshake_complete: true,
                        reject_unauthorized: server_tls.reject_unauthorized,
                        servername: client_tls.servername.clone(),
                        authorized: false,
                        authorization_error: server_tls
                            .request_cert
                            .then(|| "UNABLE_TO_GET_ISSUER_CERT".to_string()),
                        alpn_protocols: server_tls.alpn_protocols,
                        negotiated_alpn,
                        peer_certificate_der: Vec::new(),
                    };
                    self.install_tls_socket_metadata(client, client_tls)?;
                    self.install_tls_socket_metadata(accepted, accepted_tls)?;
                }
                self.apply_memory_component_delta(0, MEMORY_ESTIMATE_MAP_ENTRY_BYTES)?;
                self.loopback_servers
                    .get_mut(&server)
                    .expect("listening server was validated before connection admission")
                    .active_connections
                    .insert(accepted);
                if let Some(state) = self.loopback_sockets.get_mut(&client) {
                    state.peer = Some(accepted);
                }
                if let Some(state) = self.loopback_sockets.get_mut(&accepted) {
                    state.peer = Some(client);
                    state.owner_server = Some(server);
                    state.owner_server_generation = Some(generation);
                }
                let previous_socket_bytes = self.loopback_sockets_memory_bytes();
                let (pending_outbound, pending_outbound_end) = {
                    let state = self
                        .loopback_sockets
                        .get_mut(&client)
                        .expect("connecting client state");
                    (
                        std::mem::take(&mut state.pending_outbound),
                        std::mem::take(&mut state.pending_outbound_end),
                    )
                };
                self.apply_memory_component_delta(
                    previous_socket_bytes,
                    self.loopback_sockets_memory_bytes(),
                )?;
                self.set_object_property(client, "connecting".to_string(), Value::Bool(false))?;
                for data in pending_outbound {
                    self.schedule_loopback_task(PendingLoopbackTask::Data {
                        target: accepted,
                        bytes: data.bytes,
                        label: data.label.join(&connection_label),
                    })?;
                }
                if pending_outbound_end {
                    self.schedule_loopback_task(PendingLoopbackTask::End {
                        target: accepted,
                        label: connection_label.clone(),
                    })?;
                }
                let _ = self.emit_loopback_event(
                    module,
                    server,
                    if self
                        .loopback_servers
                        .get(&server)
                        .is_some_and(|state| state.tls.is_some())
                    {
                        "secureConnection"
                    } else {
                        "connection"
                    },
                    vec![Value::Object(accepted)],
                    connection_label.clone(),
                )?;
                let _ = self.emit_loopback_event(
                    module,
                    client,
                    if self
                        .loopback_sockets
                        .get(&client)
                        .is_some_and(|state| state.tls.is_some())
                    {
                        "secureConnect"
                    } else {
                        "connect"
                    },
                    Vec::new(),
                    connection_label,
                )?;
            }
            PendingLoopbackTask::Data {
                target,
                bytes,
                label,
            } => {
                if !self.loopback_sockets.contains_key(&target)
                    || self
                        .loopback_sockets
                        .get(&target)
                        .is_some_and(|state| state.destroyed)
                {
                    return Ok(());
                }
                let delivery_label = self.join_loopback_socket_label(target, &label)?;
                let paused = self
                    .loopback_sockets
                    .get(&target)
                    .is_some_and(|state| state.paused);
                if paused {
                    let record = LoopbackBufferedData {
                        bytes,
                        label: delivery_label,
                    };
                    let retained_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                        .saturating_add(record.bytes.len() as u64)
                        .saturating_add(Self::estimate_label_bytes(&record.label));
                    self.apply_memory_component_delta(0, retained_bytes)?;
                    if let Some(state) = self.loopback_sockets.get_mut(&target) {
                        state.pending_data.push_back(record);
                    }
                    return Ok(());
                }
                let (encoding_utf8, bytes_read) = {
                    let Some(state) = self.loopback_sockets.get_mut(&target) else {
                        return Ok(());
                    };
                    if state.destroyed {
                        return Ok(());
                    }
                    state.bytes_read = state.bytes_read.saturating_add(bytes.len() as u64);
                    (state.encoding_utf8, state.bytes_read)
                };
                self.set_object_property(
                    target,
                    "bytesRead".to_string(),
                    Value::Int(i64::try_from(bytes_read).unwrap_or(i64::MAX)),
                )?;
                let chunk = if encoding_utf8 {
                    Value::str(String::from_utf8_lossy(&bytes).into_owned())
                } else {
                    let buffer = self.alloc_buffer_from_bytes(&bytes)?;
                    self.join_binary_storage_label(buffer, &delivery_label)?;
                    Value::Object(buffer)
                };
                let _ =
                    self.emit_loopback_event(module, target, "data", vec![chunk], delivery_label)?;
            }
            PendingLoopbackTask::End { target, label } => {
                if !self.loopback_sockets.contains_key(&target)
                    || self
                        .loopback_sockets
                        .get(&target)
                        .is_some_and(|state| state.destroyed)
                {
                    return Ok(());
                }
                let lifecycle_label = self.join_loopback_socket_label(target, &label)?;
                let paused = self
                    .loopback_sockets
                    .get(&target)
                    .is_some_and(|state| state.paused);
                if paused {
                    if let Some(state) = self.loopback_sockets.get_mut(&target) {
                        state.pending_end = true;
                    }
                    return Ok(());
                }
                let (peer, should_reply) = {
                    let Some(state) = self.loopback_sockets.get_mut(&target) else {
                        return Ok(());
                    };
                    if state.remote_ended {
                        return Ok(());
                    }
                    state.remote_ended = true;
                    let should_reply = !state.local_ended && !state.destroyed;
                    if should_reply {
                        state.local_ended = true;
                    }
                    (state.peer, should_reply)
                };
                let _ = self.emit_loopback_event(
                    module,
                    target,
                    "end",
                    Vec::new(),
                    lifecycle_label.clone(),
                )?;
                if should_reply {
                    if let Some(peer) = peer {
                        self.schedule_loopback_task(PendingLoopbackTask::End {
                            target: peer,
                            label: lifecycle_label,
                        })?;
                    }
                }
                self.maybe_schedule_loopback_close(target)?;
                if let Some(peer) = peer {
                    self.maybe_schedule_loopback_close(peer)?;
                }
            }
            PendingLoopbackTask::Close {
                target,
                had_error,
                label,
            } => {
                let lifecycle_label = self.join_loopback_socket_label(target, &label)?;
                let previous_socket_bytes = self.loopback_sockets_memory_bytes();
                let owner_server = if let Some(state) = self.loopback_sockets.get_mut(&target) {
                    state.destroyed = true;
                    state.peer = None;
                    state.pending_data.clear();
                    state.pending_end = false;
                    state.pending_outbound.clear();
                    state.pending_outbound_end = false;
                    state.owner_server.zip(state.owner_server_generation)
                } else {
                    None
                };
                self.apply_memory_component_delta(
                    previous_socket_bytes,
                    self.loopback_sockets_memory_bytes(),
                )?;
                self.set_object_property(target, "destroyed".to_string(), Value::Bool(true))?;
                self.set_object_property(target, "readable".to_string(), Value::Bool(false))?;
                self.set_object_property(target, "writable".to_string(), Value::Bool(false))?;
                let _ = self.emit_loopback_event(
                    module,
                    target,
                    "close",
                    vec![Value::Bool(had_error)],
                    lifecycle_label,
                )?;
                if let Some((server, generation)) = owner_server {
                    let previous_server_bytes = self.loopback_servers_memory_bytes();
                    let close_label = self.loopback_servers.get(&server).and_then(|state| {
                        (state.generation == generation
                            && state.close_requested
                            && state.active_connections.len() == 1
                            && state.active_connections.contains(&target)
                            && !state.close_scheduled)
                            .then(|| state.lifecycle_label.clone())
                    });
                    if let Some(state) = self.loopback_servers.get_mut(&server) {
                        state.active_connections.remove(&target);
                        if close_label.is_some() {
                            state.close_scheduled = true;
                        }
                    }
                    self.apply_memory_component_delta(
                        previous_server_bytes,
                        self.loopback_servers_memory_bytes(),
                    )?;
                    if let Some(label) = close_label {
                        self.schedule_loopback_task(PendingLoopbackTask::ServerClose {
                            server,
                            generation,
                            label,
                        })?;
                    }
                }
            }
            PendingLoopbackTask::ServerClose {
                server,
                generation,
                label,
            } => {
                if !self
                    .loopback_servers
                    .get(&server)
                    .is_some_and(|state| state.generation == generation && !state.listening)
                {
                    return Ok(());
                }
                let lifecycle_label = self.join_loopback_server_label(server, &label)?;
                let _ =
                    self.emit_loopback_event(module, server, "close", Vec::new(), lifecycle_label)?;
            }
            PendingLoopbackTask::Error {
                target,
                code,
                label,
                close_after,
            } => {
                let lifecycle_label = self.join_loopback_socket_label(target, &label)?;
                self.set_object_property(target, "connecting".to_string(), Value::Bool(false))?;
                let prototype = self.ensure_builtin_prototype("Error")?;
                let error = self.alloc_object_with_prototype(Some(prototype))?;
                self.initialize_error_like_object(error, "Error", code.clone())?;
                self.set_object_property(error, "code".to_string(), Value::str(code))?;
                let _ = self.emit_loopback_event(
                    module,
                    target,
                    "error",
                    vec![Value::Object(error)],
                    lifecycle_label.clone(),
                )?;
                if close_after {
                    if let Some(state) = self.loopback_sockets.get_mut(&target) {
                        state.close_scheduled = true;
                    }
                    self.schedule_loopback_task(PendingLoopbackTask::Close {
                        target,
                        had_error: true,
                        label: lifecycle_label,
                    })?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn http_status_message(status: u16) -> &'static str {
        match status {
            100 => "Continue",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            418 => "I'm a Teapot",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "",
        }
    }

    pub(super) fn validate_http_header(name: &str, value: &str) -> Result<(), InterpreterError> {
        if name.is_empty() || name.len() > MAX_HTTP_HEADER_NAME_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "HTTP header name length {} exceeds {MAX_HTTP_HEADER_NAME_BYTES} bytes",
                    name.len()
                ),
            });
        }
        if value.len() > MAX_HTTP_HEADER_VALUE_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "HTTP header value length {} exceeds {MAX_HTTP_HEADER_VALUE_BYTES} bytes",
                    value.len()
                ),
            });
        }
        if !Self::is_http_token(name) {
            return Err(InterpreterError::TypeError {
                expected: "HTTP token header name".to_string(),
                got: name.to_string(),
            });
        }
        if value
            .bytes()
            .any(|byte| (byte < b' ' && byte != b'\t') || byte == 0x7f)
        {
            return Err(InterpreterError::TypeError {
                expected: "HTTP header value without control bytes".to_string(),
                got: "header value contains a control byte".to_string(),
            });
        }
        Ok(())
    }

    pub(super) fn is_http_token(value: &str) -> bool {
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
    }

    pub(super) fn validate_http_request_target(
        host: &str,
        path: &str,
        method: &str,
    ) -> Result<(), InterpreterError> {
        if !Self::is_http_token(method) {
            return Err(InterpreterError::TypeError {
                expected: "HTTP token method".to_string(),
                got: method.to_string(),
            });
        }
        if host.is_empty()
            || host.bytes().any(|byte| {
                byte.is_ascii_control()
                    || byte.is_ascii_whitespace()
                    || matches!(byte, b'/' | b'\\' | b'@' | b'?' | b'#')
            })
        {
            return Err(InterpreterError::TypeError {
                expected: "HTTP host without framing delimiters".to_string(),
                got: host.to_string(),
            });
        }
        if !path.starts_with('/')
            || path
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(InterpreterError::TypeError {
                expected: "absolute HTTP path without control bytes".to_string(),
                got: path.to_string(),
            });
        }
        Ok(())
    }

    pub(super) fn charge_http_work(
        &mut self,
        payload_bytes: usize,
        entries: usize,
    ) -> Result<(), InterpreterError> {
        let byte_units = u64::try_from(payload_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(HTTP_WORK_UNIT_BYTES - 1)
            / HTTP_WORK_UNIT_BYTES;
        let work = byte_units
            .max(1)
            .saturating_add(u64::try_from(entries).unwrap_or(u64::MAX));
        let next_executed = self.instructions_executed.saturating_add(work);
        if next_executed > self.config.instruction_budget {
            return Err(InterpreterError::BudgetExhausted {
                executed: self.instructions_executed,
                budget: self.config.instruction_budget,
            });
        }
        self.instructions_executed = next_executed;
        Ok(())
    }

    /// Return the exact rendered length for the bounded primitive subset used
    /// by HTTP metadata without cloning guest-sized strings. Objects, symbols,
    /// and callable/runtime handles are deliberately rejected: Buffer coercion
    /// can decode an attacker-sized backing store, while error/symbol display
    /// strings can retain attacker-sized descriptions.
    pub(super) fn http_primitive_string_len(
        &self,
        value: &Value,
        expected: &str,
    ) -> Result<usize, InterpreterError> {
        match value {
            Value::Undefined => Ok("undefined".len()),
            Value::Null => Ok("null".len()),
            Value::Bool(value) => Ok(if *value { "true".len() } else { "false".len() }),
            Value::Int(value) => Ok(value.to_string().len()),
            Value::Float(_) => Ok(self.value_to_string(value).len()),
            Value::Str(value) => Ok(value.len()),
            Value::BigInt(value) => Ok(value.len()),
            other => Err(InterpreterError::TypeError {
                expected: expected.to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn http_primitive_string(
        &self,
        value: &Value,
        expected: &str,
    ) -> Result<String, InterpreterError> {
        self.http_primitive_string_len(value, expected)?;
        Ok(self.value_to_string(value))
    }

    pub(super) fn bounded_http_primitive_string(
        &self,
        value: &Value,
        max_bytes: usize,
        field: &str,
    ) -> Result<String, InterpreterError> {
        let expected = format!("bounded primitive HTTP {field}");
        let rendered_len = self.http_primitive_string_len(value, &expected)?;
        if rendered_len > max_bytes {
            return Err(InterpreterError::RangeError {
                message: format!("HTTP {field} length {rendered_len} exceeds {max_bytes} bytes"),
            });
        }
        self.check_temporary_memory_budget(
            u64::try_from(rendered_len)
                .unwrap_or(u64::MAX)
                .saturating_mul(2)
                .saturating_add(64 * 1024),
        )?;
        self.http_primitive_string(value, &expected)
    }

    pub(super) fn http_body_value_len(&self, value: &Value) -> Result<usize, InterpreterError> {
        match value {
            Value::Str(value) => Ok(value.len()),
            Value::Object(_) => Ok(self.buffer_like_view(value)?.byte_length),
            other => Err(InterpreterError::TypeError {
                expected: "string, Buffer, or Uint8Array HTTP body".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn http_body_value_bytes(&self, value: &Value) -> Result<Vec<u8>, InterpreterError> {
        match value {
            Value::Str(value) => Ok(value.as_bytes().to_vec()),
            Value::Object(_) => self.bytes_for_buffer_like(value),
            other => Err(InterpreterError::TypeError {
                expected: "string, Buffer, or Uint8Array HTTP body".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn http_header_value_rendered_len(
        &self,
        value: &Value,
    ) -> Result<usize, InterpreterError> {
        let Value::Object(object_id) = value else {
            return self.http_primitive_string_len(value, "bounded primitive HTTP header value");
        };
        let Some(object) = self.heap.get(object_id.0 as usize) else {
            return Err(InterpreterError::ObjectNotFound { id: object_id.0 });
        };
        if !object.is_array {
            return Err(InterpreterError::TypeError {
                expected: "bounded primitive or primitive array HTTP header value".to_string(),
                got: "object".to_string(),
            });
        }
        let raw_length = object
            .properties
            .get("length")
            .map(Self::value_as_integer)
            .unwrap_or(0)
            .max(0);
        let length = usize::try_from(raw_length).unwrap_or(usize::MAX);
        if length > MAX_HTTP_HEADER_COUNT {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "HTTP header array length {length} exceeds {MAX_HTTP_HEADER_COUNT}"
                ),
            });
        }
        let mut rendered_len = 0usize;
        for index in 0..length {
            let entry_len = match object.properties.get(&index.to_string()) {
                Some(entry) => self.http_primitive_string_len(
                    entry,
                    "bounded primitive HTTP header array entry",
                )?,
                None => 0,
            };
            rendered_len = rendered_len
                .saturating_add(if index == 0 { 0 } else { 2 })
                .saturating_add(entry_len);
            if rendered_len > MAX_HTTP_HEADER_VALUE_BYTES {
                return Err(InterpreterError::RangeError {
                    message: format!(
                        "HTTP header value length exceeds {MAX_HTTP_HEADER_VALUE_BYTES} bytes"
                    ),
                });
            }
        }
        Ok(rendered_len)
    }

    pub(super) fn http_header_value_from_value(
        &self,
        value: &Value,
    ) -> Result<(String, Option<Vec<String>>), InterpreterError> {
        let Value::Object(object_id) = value else {
            let rendered_len =
                self.http_primitive_string_len(value, "bounded primitive HTTP header value")?;
            if rendered_len > MAX_HTTP_HEADER_VALUE_BYTES {
                return Err(InterpreterError::RangeError {
                    message: format!(
                        "HTTP header value length exceeds {MAX_HTTP_HEADER_VALUE_BYTES} bytes"
                    ),
                });
            }
            return Ok((
                self.http_primitive_string(value, "bounded primitive HTTP header value")?,
                None,
            ));
        };
        let Some(object) = self.heap.get(object_id.0 as usize) else {
            return Err(InterpreterError::ObjectNotFound { id: object_id.0 });
        };
        if !object.is_array {
            return Err(InterpreterError::TypeError {
                expected: "bounded primitive or primitive array HTTP header value".to_string(),
                got: "object".to_string(),
            });
        }
        let raw_length = object
            .properties
            .get("length")
            .map(Self::value_as_integer)
            .unwrap_or(0)
            .max(0);
        let length = usize::try_from(raw_length).unwrap_or(usize::MAX);
        if length > MAX_HTTP_HEADER_COUNT {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "HTTP header array length {length} exceeds {MAX_HTTP_HEADER_COUNT}"
                ),
            });
        }
        let mut values = Vec::with_capacity(length);
        let mut rendered = String::new();
        for index in 0..length {
            let entry = match object.properties.get(&index.to_string()) {
                Some(entry) => {
                    let entry_len = self.http_primitive_string_len(
                        entry,
                        "bounded primitive HTTP header array entry",
                    )?;
                    if rendered
                        .len()
                        .saturating_add(if index == 0 { 0 } else { 2 })
                        .saturating_add(entry_len)
                        > MAX_HTTP_HEADER_VALUE_BYTES
                    {
                        return Err(InterpreterError::RangeError {
                            message: format!(
                                "HTTP header value length exceeds {MAX_HTTP_HEADER_VALUE_BYTES} bytes"
                            ),
                        });
                    }
                    self.http_primitive_string(entry, "bounded primitive HTTP header array entry")?
                }
                None => String::new(),
            };
            let next_len = rendered
                .len()
                .saturating_add(if index == 0 { 0 } else { 2 })
                .saturating_add(entry.len());
            if next_len > MAX_HTTP_HEADER_VALUE_BYTES {
                return Err(InterpreterError::RangeError {
                    message: format!(
                        "HTTP header value length exceeds {MAX_HTTP_HEADER_VALUE_BYTES} bytes"
                    ),
                });
            }
            if index != 0 {
                rendered.push_str(", ");
            }
            rendered.push_str(&entry);
            values.push(entry);
        }
        Ok((rendered, Some(values)))
    }

    pub(super) fn http_headers_from_value(
        &mut self,
        value: Option<&Value>,
    ) -> Result<HttpHeaders, InterpreterError> {
        let Some(Value::Object(object_id)) = value else {
            return Ok(BTreeMap::new());
        };
        let (header_count, item_count, work_bytes) = {
            let object = self
                .heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            if object.properties.len() > MAX_HTTP_HEADER_COUNT {
                return Err(InterpreterError::RangeError {
                    message: format!(
                        "HTTP header count {} exceeds {MAX_HTTP_HEADER_COUNT}",
                        object.properties.len()
                    ),
                });
            }
            let mut work_bytes = 0usize;
            let mut item_count = 0usize;
            for (name, value) in &object.properties {
                Self::validate_http_header(name, "")?;
                work_bytes = work_bytes
                    .saturating_add(name.len())
                    .saturating_add(self.http_header_value_rendered_len(value)?);
                item_count = item_count.saturating_add(match value {
                    Value::Object(value_id) => self
                        .heap
                        .get(value_id.0 as usize)
                        .filter(|value_object| value_object.is_array)
                        .and_then(|value_object| value_object.properties.get("length"))
                        .map(Self::value_as_integer)
                        .and_then(|length| usize::try_from(length.max(0)).ok())
                        .unwrap_or(1),
                    _ => 1,
                });
            }
            (object.properties.len(), item_count, work_bytes)
        };
        self.charge_http_work(work_bytes, header_count.saturating_add(item_count))?;
        self.check_temporary_memory_budget(
            u64::try_from(work_bytes)
                .unwrap_or(u64::MAX)
                .saturating_mul(2)
                .saturating_add(
                    u64::try_from(item_count)
                        .unwrap_or(u64::MAX)
                        .saturating_mul(MEMORY_ESTIMATE_STRING_BASE_BYTES),
                )
                .saturating_add(64 * 1024),
        )?;
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let mut headers = BTreeMap::new();
        for (name, value) in &object.properties {
            let (value, array_values) = self.http_header_value_from_value(value)?;
            Self::validate_http_header(name, &value)?;
            headers.insert(
                name.to_ascii_lowercase(),
                HttpHeaderValue {
                    original_name: name.clone(),
                    array_values,
                    value,
                },
            );
        }
        Ok(headers)
    }

    pub(super) fn resolve_http_request(
        &mut self,
        args: RegRange,
        force_get: bool,
    ) -> Result<ResolvedHttpRequest, InterpreterError> {
        self.resolve_http_request_for_protocol(args, force_get, false)
    }

    pub(super) fn resolve_http_request_for_protocol(
        &mut self,
        args: RegRange,
        force_get: bool,
        use_tls: bool,
    ) -> Result<ResolvedHttpRequest, InterpreterError> {
        let first = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let response_callback = self.last_callable_arg(args)?.and_then(|value| match value {
            Value::Closure(closure_id) => Some(closure_id),
            _ => None,
        });
        let mut host: String;
        let port: u16;
        let expected_protocol = if use_tls { "https:" } else { "http:" };
        let mut path: String;
        let mut method = "GET".to_string();
        let mut headers = BTreeMap::new();

        match &first {
            Value::Str(url) => {
                let source = url.as_str().unwrap_or_default();
                if source.len() > MAX_HTTP_PATH_BYTES.saturating_add(MAX_LOOPBACK_HOST_BYTES + 32) {
                    return Err(InterpreterError::RangeError {
                        message: "HTTP URL exceeds the bounded facade limit".to_string(),
                    });
                }
                let parsed = Url::parse(source).map_err(|_| InterpreterError::TypeError {
                    expected: "absolute HTTP URL".to_string(),
                    got: source.to_string(),
                })?;
                if parsed.scheme() != expected_protocol.trim_end_matches(':') {
                    return Err(self.throw_legacy_url_type_error(
                        "ERR_INVALID_PROTOCOL",
                        format!(
                            "Protocol \"{}:\" not supported. Expected \"{expected_protocol}\"",
                            parsed.scheme()
                        ),
                    ));
                }
                host = parsed.host_str().unwrap_or_default().to_string();
                port = parsed
                    .port_or_known_default()
                    .unwrap_or(if use_tls { 443 } else { 80 });
                path = parsed.path().to_string();
                if let Some(query) = parsed.query() {
                    path.push('?');
                    path.push_str(query);
                }
                if let Some(options) = self.builtin_arg(args, 1)?
                    && matches!(options, Value::Object(_))
                {
                    if let Some(protocol) = self.fs_object_property(&options, "protocol")
                        && !matches!(protocol, Value::Undefined)
                    {
                        let protocol =
                            self.bounded_http_primitive_string(&protocol, 16, "protocol")?;
                        if protocol != expected_protocol {
                            return Err(self.throw_legacy_url_type_error(
                                "ERR_INVALID_PROTOCOL",
                                format!(
                                    "Protocol \"{protocol}\" not supported. Expected \"{expected_protocol}\""
                                ),
                            ));
                        }
                    }
                    if !force_get {
                        method = match self.fs_object_property(&options, "method") {
                            Some(value) => self
                                .bounded_http_primitive_string(
                                    &value,
                                    MAX_HTTP_HEADER_NAME_BYTES,
                                    "method",
                                )?
                                .to_ascii_uppercase(),
                            None => "GET".to_string(),
                        };
                        if method.is_empty() {
                            method = "GET".to_string();
                        }
                    }
                    let header_value = self.fs_object_property(&options, "headers");
                    headers = self.http_headers_from_value(header_value.as_ref())?;
                }
            }
            Value::Object(_) => {
                if let Some(protocol) = self.fs_object_property(&first, "protocol")
                    && !matches!(protocol, Value::Undefined)
                {
                    let protocol = self.bounded_http_primitive_string(&protocol, 16, "protocol")?;
                    if protocol != expected_protocol {
                        return Err(self.throw_legacy_url_type_error(
                            "ERR_INVALID_PROTOCOL",
                            format!(
                                "Protocol \"{protocol}\" not supported. Expected \"{expected_protocol}\""
                            ),
                        ));
                    }
                }
                host = match self
                    .fs_object_property(&first, "host")
                    .or_else(|| self.fs_object_property(&first, "hostname"))
                {
                    Some(value) => {
                        self.bounded_http_primitive_string(&value, MAX_LOOPBACK_HOST_BYTES, "host")?
                    }
                    None => "127.0.0.1".to_string(),
                };
                port = self
                    .fs_object_property(&first, "port")
                    .and_then(|value| u16::try_from(Self::value_as_integer(&value)).ok())
                    .unwrap_or(if use_tls { 443 } else { 80 });
                path = match self.fs_object_property(&first, "path") {
                    Some(value) => {
                        self.bounded_http_primitive_string(&value, MAX_HTTP_PATH_BYTES, "path")?
                    }
                    None => "/".to_string(),
                };
                if !force_get {
                    method = match self.fs_object_property(&first, "method") {
                        Some(value) => self
                            .bounded_http_primitive_string(
                                &value,
                                MAX_HTTP_HEADER_NAME_BYTES,
                                "method",
                            )?
                            .to_ascii_uppercase(),
                        None => "GET".to_string(),
                    };
                    if method.is_empty() {
                        method = "GET".to_string();
                    }
                }
                let header_value = self.fs_object_property(&first, "headers");
                headers = self.http_headers_from_value(header_value.as_ref())?;
            }
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "HTTP URL string or options object".to_string(),
                    got: first.type_name().to_string(),
                });
            }
        }
        if host == "localhost" {
            host = "127.0.0.1".to_string();
        }
        let internal_loopback_candidate = !use_tls && host == "127.0.0.1";
        if host.len() > MAX_LOOPBACK_HOST_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!("HTTP host length exceeds {MAX_LOOPBACK_HOST_BYTES} bytes"),
            });
        }
        if path.len() > MAX_HTTP_PATH_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!("HTTP path length exceeds {MAX_HTTP_PATH_BYTES} bytes"),
            });
        }
        Self::validate_http_request_target(&host, &path, &method)?;
        if headers.len() >= MAX_HTTP_HEADER_COUNT && !headers.contains_key("host") {
            return Err(InterpreterError::RangeError {
                message: format!("HTTP header count exceeds {MAX_HTTP_HEADER_COUNT}"),
            });
        }
        headers
            .entry("host".to_string())
            .or_insert_with(|| HttpHeaderValue {
                original_name: "Host".to_string(),
                array_values: None,
                value: format!("{host}:{port}"),
            });
        Ok(ResolvedHttpRequest {
            host,
            port,
            use_tls,
            internal_loopback_candidate,
            path,
            method,
            headers,
            response_callback,
        })
    }

    pub(super) fn http_receiver_id(
        &self,
        receiver: Option<Value>,
        expected_tag: &str,
        contains: impl FnOnce(ObjectId) -> bool,
    ) -> Result<ObjectId, InterpreterError> {
        let receiver = receiver.unwrap_or(Value::Undefined);
        let Value::Object(object_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: format!("authenticated {expected_tag} receiver"),
                got: receiver.type_name().to_string(),
            });
        };
        let tagged = self
            .heap
            .get(object_id.0 as usize)
            .is_some_and(|object| object.brand() == Some(expected_tag));
        if !tagged || !contains(object_id) {
            return Err(InterpreterError::TypeError {
                expected: format!("authenticated {expected_tag} receiver"),
                got: "forged or stale object".to_string(),
            });
        }
        Ok(object_id)
    }

    pub(super) fn construct_http_server(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            let server = match self.construct_loopback_server_with_tls(
                RegRange {
                    start: args.start,
                    count: 0,
                },
                None,
            )? {
                Value::Object(server) => server,
                _ => unreachable!("loopback server constructor returned a non-object"),
            };
            let lifecycle_label = self.writable_invocation_label(args)?;
            self.join_loopback_server_label(server, &lifecycle_label)?;
            self.set_object_brand(server, "HttpServer")?;
            let state = HttpServerState {
                lifecycle_label: lifecycle_label.clone(),
            };
            let retained = MEMORY_ESTIMATE_HTTP_SERVER_BASE_BYTES
                .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label));
            self.apply_memory_component_delta(0, retained)?;
            self.http_servers.insert(server, state);
            if let Some(callback) = self.last_callable_arg(args)? {
                self.add_loopback_listener(server, "request", callback, false)?;
            }
            Ok(Value::Object(server))
        })();
        if result.is_err() {
            let new_servers: Vec<ObjectId> = self
                .loopback_servers
                .keys()
                .copied()
                .filter(|id| id.0 as usize >= previous_heap_len)
                .collect();
            for server in new_servers {
                self.loopback_servers.remove(&server);
                self.http_servers.remove(&server);
                self.clear_event_listeners(server, None);
            }
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn construct_http_client_request(
        &mut self,
        args: RegRange,
        auto_end: bool,
    ) -> Result<Value, InterpreterError> {
        self.construct_http_client_request_for_protocol(args, auto_end, false)
    }

    pub(super) fn construct_http_client_request_for_protocol(
        &mut self,
        args: RegRange,
        auto_end: bool,
        use_tls: bool,
    ) -> Result<Value, InterpreterError> {
        let resolved = if use_tls {
            self.resolve_http_request_for_protocol(args, auto_end, true)?
        } else {
            self.resolve_http_request(args, auto_end)?
        };
        let lifecycle_label = self.join_arg_range_with_object_mutation_label(args)?;
        let state = HttpClientRequestState {
            host: resolved.host,
            port: resolved.port,
            use_tls: resolved.use_tls,
            internal_loopback_candidate: resolved.internal_loopback_candidate,
            path: resolved.path,
            method: resolved.method,
            headers: resolved.headers,
            body: Vec::new(),
            ended: false,
            response_callback: resolved.response_callback,
            egress_label: lifecycle_label.clone(),
            lifecycle_label,
        };
        let retained = Self::estimate_http_client_request_state_bytes(&state);
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let mut published_request = None;
        let result = (|| {
            self.check_temporary_memory_budget(retained.saturating_add(64 * 1024))?;
            let request = self.alloc_branded_object(
                "HttpClientRequest",
                &[
                    ("__maxListeners", Value::Int(10)),
                    ("writable", Value::Bool(true)),
                    ("writableEnded", Value::Bool(false)),
                ],
            )?;
            self.apply_memory_component_delta(0, retained)?;
            self.http_client_requests.insert(request, state);
            published_request = Some(request);
            if auto_end {
                self.finish_http_client_request(request)?;
            }
            Ok(Value::Object(request))
        })();
        // Once `.end()` has committed its one-shot transition, it may already
        // have crossed the provider seam or published deferred delivery work.
        // Never roll that request object back to a stale ObjectId merely
        // because a later callback registration was refused.
        let may_rollback = published_request.is_none_or(|request| {
            self.http_client_requests
                .get(&request)
                .is_none_or(|state| !state.ended)
        });
        if result.is_err() && may_rollback {
            self.http_client_requests
                .retain(|request, _| (request.0 as usize) < previous_heap_len);
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn construct_http_agent(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.construct_http_agent_for_protocol(args, false)
    }

    pub(super) fn construct_http_agent_for_protocol(
        &mut self,
        args: RegRange,
        use_tls: bool,
    ) -> Result<Value, InterpreterError> {
        let keep_alive = self
            .builtin_arg(args, 0)?
            .and_then(|options| self.fs_object_property(&options, "keepAlive"))
            .is_some_and(|value| matches!(value, Value::Bool(true)));
        let agent = self.alloc_branded_object(
            "HttpAgent",
            &[
                ("keepAlive", Value::Bool(keep_alive)),
                (
                    "protocol",
                    Value::str(if use_tls { "https:" } else { "http:" }),
                ),
                ("defaultPort", Value::Int(if use_tls { 443 } else { 80 })),
            ],
        )?;
        let tag = if use_tls {
            "builtin:HttpsAgent"
        } else {
            "builtin:HttpAgent"
        };
        let prototype = self.native_http_function_prototype(tag)?;
        self.store_prototype_link(agent, Some(prototype));
        self.apply_memory_component_delta(0, MEMORY_ESTIMATE_HTTP_AGENT_BASE_BYTES)?;
        self.http_agents.insert(agent);
        Ok(Value::Object(agent))
    }

    pub(super) fn http_status_codes(&mut self) -> Result<Value, InterpreterError> {
        let status_codes = self.alloc_object_with_properties(&[
            ("200", Value::str("OK")),
            ("204", Value::str("No Content")),
            ("301", Value::str("Moved Permanently")),
            ("404", Value::str("Not Found")),
            ("418", Value::str("I'm a Teapot")),
            ("500", Value::str("Internal Server Error")),
        ])?;
        Ok(Value::Object(status_codes))
    }

    pub(super) fn http_methods(&mut self) -> Result<Value, InterpreterError> {
        let methods = [
            "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE",
        ]
        .map(Value::str);
        Ok(Value::Object(self.alloc_array_from_values(&methods)?))
    }

    pub(super) fn alloc_http_headers_object(
        &mut self,
        headers: &HttpHeaders,
    ) -> Result<ObjectId, InterpreterError> {
        let object = self.alloc_object_with_properties(&[])?;
        for (name, header) in headers {
            self.set_object_property(object, name.clone(), Value::str(header.value.as_str()))?;
        }
        Ok(object)
    }

    pub(super) fn alloc_http_raw_headers(
        &mut self,
        headers: &HttpHeaders,
    ) -> Result<ObjectId, InterpreterError> {
        let values: Vec<Value> = headers
            .values()
            .flat_map(|header| {
                [
                    Value::str(header.original_name.as_str()),
                    Value::str(header.value.as_str()),
                ]
            })
            .collect();
        self.alloc_array_from_values(&values)
    }

    pub(super) fn construct_http_incoming_message(
        &mut self,
        body: Vec<u8>,
        label: Label,
        close_after_end: bool,
        server_completion: Option<HttpServerCompletion>,
    ) -> Result<ObjectId, InterpreterError> {
        if body.len() > MAX_HTTP_BODY_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!("HTTP body exceeds {MAX_HTTP_BODY_BYTES} bytes"),
            });
        }
        let state = HttpIncomingMessageState {
            body,
            encoding_utf8: false,
            delivered: false,
            close_after_end,
            server_completion,
            lifecycle_label: label,
        };
        let retained = Self::estimate_http_incoming_message_state_bytes(&state);
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            self.check_temporary_memory_budget(retained.saturating_add(64 * 1024))?;
            let socket = self.alloc_branded_object("HttpSocket", &[])?;
            let message = self.alloc_branded_object(
                "HttpIncomingMessage",
                &[
                    ("__maxListeners", Value::Int(10)),
                    ("httpVersion", Value::str("1.1")),
                    ("socket", Value::Object(socket)),
                    ("readable", Value::Bool(true)),
                ],
            )?;
            self.apply_memory_component_delta(0, retained)?;
            self.http_incoming_messages.insert(message, state);
            Ok(message)
        })();
        if result.is_err() {
            self.http_incoming_messages
                .retain(|message, _| (message.0 as usize) < previous_heap_len);
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn http_append_client_body(
        &mut self,
        request: ObjectId,
        value: &Value,
        invocation_label: Label,
    ) -> Result<(), InterpreterError> {
        let value_len = self.http_body_value_len(value)?;
        let (previous_body_len, previous_bytes, previous_label) = {
            let state = self
                .http_client_requests
                .get(&request)
                .ok_or(InterpreterError::ObjectNotFound { id: request.0 })?;
            if state.ended {
                return Err(InterpreterError::TypeError {
                    expected: "writable HTTP ClientRequest".to_string(),
                    got: "request already ended".to_string(),
                });
            }
            (
                state.body.len(),
                Self::estimate_http_client_request_state_bytes(state),
                state.lifecycle_label.clone(),
            )
        };
        let next_len = previous_body_len.saturating_add(value_len);
        if next_len > MAX_HTTP_BODY_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!("HTTP request body exceeds {MAX_HTTP_BODY_BYTES} bytes"),
            });
        }
        self.charge_http_work(value_len, 1)?;
        self.check_temporary_memory_budget(
            u64::try_from(next_len)
                .unwrap_or(u64::MAX)
                .saturating_mul(2)
                .saturating_add(
                    u64::try_from(value_len)
                        .unwrap_or(u64::MAX)
                        .saturating_mul(2),
                )
                .saturating_add(64 * 1024),
        )?;
        let bytes = self.http_body_value_bytes(value)?;
        let value_label = match value {
            Value::Object(object_id) => self.binary_storage_label(*object_id),
            _ => Label::Public,
        };
        let next_label = previous_label.join(&invocation_label).join(&value_label);
        let next_bytes = previous_bytes
            .saturating_add(bytes.len() as u64)
            .saturating_sub(Self::estimate_label_bytes(&previous_label))
            .saturating_add(Self::estimate_label_bytes(&next_label));
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        let state = self
            .http_client_requests
            .get_mut(&request)
            .expect("HTTP request was authenticated before atomic body append");
        state.body.extend_from_slice(&bytes);
        state.lifecycle_label = next_label;
        Ok(())
    }

    /// The label of a client-request method's arguments (and the bytes of a
    /// Buffer or typed-array argument), without the receiver.
    pub(super) fn join_http_client_request_egress_from_args(
        &mut self,
        request: ObjectId,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        let mut label = self.writable_invocation_label(args)?;
        for offset in 0..args.count {
            if let Some(Value::Object(object_id)) = self.builtin_arg(args, offset)? {
                label = label.join(&self.binary_storage_label(object_id));
            }
        }
        self.join_http_client_request_egress_label(request, &label)
    }

    /// bd-9vouw.8: join what a write, setHeader or end puts on the wire into
    /// the request's egress label.
    pub(super) fn join_http_client_request_egress_label(
        &mut self,
        request: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let state = self
            .http_client_requests
            .get(&request)
            .ok_or(InterpreterError::ObjectNotFound { id: request.0 })?;
        let previous_label = state.egress_label.clone();
        let next_label = previous_label.join(label);
        if next_label == previous_label {
            return Ok(());
        }
        self.apply_memory_component_delta(
            Self::estimate_label_bytes(&previous_label),
            Self::estimate_label_bytes(&next_label),
        )?;
        self.http_client_requests
            .get_mut(&request)
            .expect("HTTP request existed before egress-label commit")
            .egress_label = next_label;
        Ok(())
    }

    pub(super) fn join_http_client_request_lifecycle_label(
        &mut self,
        request: ObjectId,
        invocation_label: &Label,
    ) -> Result<(), InterpreterError> {
        let state = self
            .http_client_requests
            .get(&request)
            .ok_or(InterpreterError::ObjectNotFound { id: request.0 })?;
        let previous_bytes = Self::estimate_http_client_request_state_bytes(state);
        let previous_label = state.lifecycle_label.clone();
        let next_label = previous_label.join(invocation_label);
        if next_label == previous_label {
            return Ok(());
        }
        let next_bytes = previous_bytes
            .saturating_sub(Self::estimate_label_bytes(&previous_label))
            .saturating_add(Self::estimate_label_bytes(&next_label));
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.http_client_requests
            .get_mut(&request)
            .expect("HTTP request existed before lifecycle-label commit")
            .lifecycle_label = next_label;
        Ok(())
    }

    pub(super) fn http_append_response_body(
        &mut self,
        response: ObjectId,
        value: &Value,
        invocation_label: Label,
    ) -> Result<(), InterpreterError> {
        let value_len = self.http_body_value_len(value)?;
        let (previous_body_len, previous_bytes, previous_label) = {
            let state = self
                .http_server_responses
                .get(&response)
                .ok_or(InterpreterError::ObjectNotFound { id: response.0 })?;
            if state.ended {
                return Err(InterpreterError::TypeError {
                    expected: "writable HTTP ServerResponse".to_string(),
                    got: "response already ended".to_string(),
                });
            }
            (
                state.body.len(),
                Self::estimate_http_server_response_state_bytes(state),
                state.lifecycle_label.clone(),
            )
        };
        let next_len = previous_body_len.saturating_add(value_len);
        if next_len > MAX_HTTP_BODY_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!("HTTP response body exceeds {MAX_HTTP_BODY_BYTES} bytes"),
            });
        }
        self.charge_http_work(value_len, 1)?;
        self.check_temporary_memory_budget(
            u64::try_from(next_len)
                .unwrap_or(u64::MAX)
                .saturating_mul(2)
                .saturating_add(
                    u64::try_from(value_len)
                        .unwrap_or(u64::MAX)
                        .saturating_mul(2),
                )
                .saturating_add(64 * 1024),
        )?;
        let bytes = self.http_body_value_bytes(value)?;
        let value_label = match value {
            Value::Object(object_id) => self.binary_storage_label(*object_id),
            _ => Label::Public,
        };
        let next_label = previous_label.join(&invocation_label).join(&value_label);
        let next_bytes = previous_bytes
            .saturating_add(bytes.len() as u64)
            .saturating_sub(Self::estimate_label_bytes(&previous_label))
            .saturating_add(Self::estimate_label_bytes(&next_label));
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        let state = self
            .http_server_responses
            .get_mut(&response)
            .expect("HTTP response was authenticated before atomic body append");
        state.body.extend_from_slice(&bytes);
        state.lifecycle_label = next_label;
        Ok(())
    }

    pub(super) fn http_client_request_receiver(
        &self,
        receiver: Option<Value>,
    ) -> Result<ObjectId, InterpreterError> {
        self.http_receiver_id(receiver, "HttpClientRequest", |id| {
            self.http_client_requests.contains_key(&id)
        })
    }

    pub(super) fn http_incoming_message_receiver(
        &self,
        receiver: Option<Value>,
    ) -> Result<ObjectId, InterpreterError> {
        self.http_receiver_id(receiver, "HttpIncomingMessage", |id| {
            self.http_incoming_messages.contains_key(&id)
        })
    }

    pub(super) fn http_server_response_receiver(
        &self,
        receiver: Option<Value>,
    ) -> Result<ObjectId, InterpreterError> {
        self.http_receiver_id(receiver, "HttpServerResponse", |id| {
            self.http_server_responses.contains_key(&id)
        })
    }

    pub(super) fn http_set_header(
        &mut self,
        receiver: Option<Value>,
        args: RegRange,
        client_request: bool,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let object_id = if client_request {
            self.http_client_request_receiver(receiver)?
        } else {
            self.http_server_response_receiver(receiver)?
        };
        if client_request {
            self.join_http_client_request_egress_from_args(object_id, args)?;
        }
        let name_value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let value = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let name_len =
            self.http_primitive_string_len(&name_value, "bounded primitive HTTP header name")?;
        if name_len > MAX_HTTP_HEADER_NAME_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "HTTP header name length exceeds {MAX_HTTP_HEADER_NAME_BYTES} bytes"
                ),
            });
        }
        let rendered_len = self.http_header_value_rendered_len(&value)?;
        let item_count = match &value {
            Value::Object(object_id) => self
                .heap
                .get(object_id.0 as usize)
                .filter(|object| object.is_array)
                .and_then(|object| object.properties.get("length"))
                .map(Self::value_as_integer)
                .and_then(|length| usize::try_from(length.max(0)).ok())
                .unwrap_or(1),
            _ => 1,
        };
        self.charge_http_work(name_len.saturating_add(rendered_len), item_count)?;
        self.check_temporary_memory_budget(
            u64::try_from(rendered_len)
                .unwrap_or(u64::MAX)
                .saturating_mul(2)
                .saturating_add(
                    u64::try_from(name_len)
                        .unwrap_or(u64::MAX)
                        .saturating_mul(2),
                )
                .saturating_add(64 * 1024),
        )?;
        let name = self.http_primitive_string(&name_value, "bounded primitive HTTP header name")?;
        Self::validate_http_header(&name, "")?;
        let (rendered, array_values) = self.http_header_value_from_value(&value)?;
        Self::validate_http_header(&name, &rendered)?;
        let lower_name = name.to_ascii_lowercase();
        let header = HttpHeaderValue {
            original_name: name,
            array_values,
            value: rendered,
        };
        let invocation_label =
            self.writable_invocation_label_with_receiver(args, receiver_register)?;
        if client_request {
            let (previous_bytes, replaced_header_bytes, previous_label) = {
                let state = &self.http_client_requests[&object_id];
                if state.ended {
                    return Err(InterpreterError::TypeError {
                        expected: "mutable HTTP request headers".to_string(),
                        got: "request already ended".to_string(),
                    });
                }
                if !state.headers.contains_key(&lower_name)
                    && state.headers.len() >= MAX_HTTP_HEADER_COUNT
                {
                    return Err(InterpreterError::RangeError {
                        message: format!("HTTP header count exceeds {MAX_HTTP_HEADER_COUNT}"),
                    });
                }
                (
                    Self::estimate_http_client_request_state_bytes(state),
                    state
                        .headers
                        .get(&lower_name)
                        .map_or(0, |old| Self::estimate_http_header_bytes(&lower_name, old)),
                    state.lifecycle_label.clone(),
                )
            };
            let next_label = previous_label.join(&invocation_label);
            let next_bytes = previous_bytes
                .saturating_sub(replaced_header_bytes)
                .saturating_sub(Self::estimate_label_bytes(&previous_label))
                .saturating_add(Self::estimate_http_header_bytes(&lower_name, &header))
                .saturating_add(Self::estimate_label_bytes(&next_label));
            self.apply_memory_component_delta(previous_bytes, next_bytes)?;
            let state = self
                .http_client_requests
                .get_mut(&object_id)
                .expect("HTTP request was authenticated before header commit");
            state.headers.insert(lower_name, header);
            state.lifecycle_label = next_label;
        } else {
            let (previous_bytes, replaced_header_bytes, previous_label) = {
                let state = &self.http_server_responses[&object_id];
                if state.ended {
                    return Err(InterpreterError::TypeError {
                        expected: "mutable HTTP response headers".to_string(),
                        got: "response already ended".to_string(),
                    });
                }
                if !state.headers.contains_key(&lower_name)
                    && state.headers.len() >= MAX_HTTP_HEADER_COUNT
                {
                    return Err(InterpreterError::RangeError {
                        message: format!("HTTP header count exceeds {MAX_HTTP_HEADER_COUNT}"),
                    });
                }
                (
                    Self::estimate_http_server_response_state_bytes(state),
                    state
                        .headers
                        .get(&lower_name)
                        .map_or(0, |old| Self::estimate_http_header_bytes(&lower_name, old)),
                    state.lifecycle_label.clone(),
                )
            };
            let next_label = previous_label.join(&invocation_label);
            let next_bytes = previous_bytes
                .saturating_sub(replaced_header_bytes)
                .saturating_sub(Self::estimate_label_bytes(&previous_label))
                .saturating_add(Self::estimate_http_header_bytes(&lower_name, &header))
                .saturating_add(Self::estimate_label_bytes(&next_label));
            self.apply_memory_component_delta(previous_bytes, next_bytes)?;
            let state = self
                .http_server_responses
                .get_mut(&object_id)
                .expect("HTTP response was authenticated before header commit");
            state.headers.insert(lower_name, header);
            state.lifecycle_label = next_label;
        }
        Ok(Value::Object(object_id))
    }

    pub(super) fn http_error_value(&mut self, code: &str) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("Error")?;
        let error = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_like_object(error, "Error", code.to_string())?;
        self.set_object_property(error, "code".to_string(), Value::str(code))?;
        Ok(Value::Object(error))
    }

    pub(super) fn validate_http_client_terminal_slots(
        &self,
        request: ObjectId,
    ) -> Result<(), InterpreterError> {
        let object = self
            .heap
            .get(request.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: request.0 })?;
        for property in ["writable", "writableEnded"] {
            if !matches!(object.properties.get(property), Some(Value::Bool(_))) {
                return Err(InterpreterError::InternalError {
                    details: format!(
                        "authenticated HTTP ClientRequest lacks Boolean {property} slot"
                    ),
                });
            }
        }
        if !self.http_client_requests.contains_key(&request) {
            return Err(InterpreterError::ObjectNotFound { id: request.0 });
        }
        Ok(())
    }

    pub(super) fn mark_http_client_request_ended(
        &mut self,
        request: ObjectId,
    ) -> Result<(), InterpreterError> {
        self.validate_http_client_terminal_slots(request)?;
        self.http_client_requests
            .get_mut(&request)
            .expect("HTTP request existence was validated before terminal commit")
            .ended = true;
        self.mutate_heap(|heap| {
            let properties = &mut heap[request.0 as usize].properties;
            *properties
                .get_mut("writable")
                .expect("HTTP writable slot was validated before terminal commit") =
                Value::Bool(false);
            *properties
                .get_mut("writableEnded")
                .expect("HTTP writableEnded slot was validated before terminal commit") =
                Value::Bool(true);
        });
        Ok(())
    }

    pub(super) fn http_effect_headers(headers: &HttpHeaders) -> Vec<(String, String)> {
        // The shared HTTP/1.1 framing layer synthesizes exactly one Host field
        // from the validated URL authority. Forwarding the facade's retained
        // guest-visible Host entry would create an ambiguous duplicate.
        headers
            .values()
            .filter(|header| !header.original_name.eq_ignore_ascii_case("host"))
            .map(|header| (header.original_name.clone(), header.value.clone()))
            .collect()
    }

    pub(super) fn finish_http_client_request(
        &mut self,
        request: ObjectId,
    ) -> Result<Value, InterpreterError> {
        let (port, internal_loopback_candidate, lifecycle_label) = {
            let state = self
                .http_client_requests
                .get(&request)
                .ok_or(InterpreterError::ObjectNotFound { id: request.0 })?;
            if state.ended {
                return Ok(Value::Undefined);
            }
            (
                state.port,
                state.internal_loopback_candidate,
                state.lifecycle_label.clone(),
            )
        };

        let port_state = self.loopback_ports.get(&port).copied();
        if internal_loopback_candidate {
            match port_state {
                Some(LoopbackPortState::Live { server, generation })
                    if self.http_servers.contains_key(&server) =>
                {
                    self.validate_http_client_terminal_slots(request)?;
                    self.schedule_http_task(PendingHttpTask::DispatchRequest {
                        request,
                        server,
                        generation,
                    })?;
                    self.mark_http_client_request_ended(request)?;
                }
                Some(LoopbackPortState::Live { .. }) | Some(LoopbackPortState::Closed { .. }) => {
                    self.validate_http_client_terminal_slots(request)?;
                    self.schedule_http_task(PendingHttpTask::ClientError {
                        request,
                        code: "ECONNREFUSED".to_string(),
                        label: lifecycle_label.clone(),
                    })?;
                    self.mark_http_client_request_ended(request)?;
                }
                None => {}
            }
            if port_state.is_some() {
                return Ok(Value::Undefined);
            }
        }

        // External publication is prepared in full before the one-shot commit:
        // policy refusal, deterministic-work exhaustion, or memory refusal must
        // leave `http.get()` construction safely rollbackable. Once ended, the
        // provider effect and its single deferred delivery task are never
        // replayed through this request object.
        check_hostcall_capability_gate(self, "net:request", self.ip as u32)?;
        // bd-9vouw.8: the request leaves the engine here, so its label (URL,
        // headers, options and every body chunk) must be Public, as for a
        // `net:request` HostCall. `builtin:HttpGet` and `builtin:HttpRequest`
        // keep the Internal static clearance of the loopback facade, so
        // without this check file or response data reached the network.
        let egress_label = self
            .http_client_requests
            .get(&request)
            .map_or(Label::TopSecret, |state| state.egress_label.clone());
        let (work_bytes, header_count) = {
            let state = self
                .http_client_requests
                .get(&request)
                .expect("HTTP request remained live after route classification");
            (
                state
                    .host
                    .len()
                    .saturating_add(state.path.len())
                    .saturating_add(state.method.len())
                    .saturating_add(state.body.len())
                    .saturating_add(
                        state
                            .headers
                            .values()
                            .filter(|header| !header.original_name.eq_ignore_ascii_case("host"))
                            .map(|header| {
                                header
                                    .original_name
                                    .len()
                                    .saturating_add(header.value.len())
                            })
                            .sum::<usize>(),
                    ),
                state
                    .headers
                    .values()
                    .filter(|header| !header.original_name.eq_ignore_ascii_case("host"))
                    .count(),
            )
        };
        self.charge_http_work(work_bytes, header_count)?;
        self.check_temporary_memory_budget(
            u64::try_from(work_bytes)
                .unwrap_or(u64::MAX)
                .saturating_mul(2)
                .saturating_add(64 * 1024),
        )?;
        let (url, method, headers, body) = {
            let state = self
                .http_client_requests
                .get(&request)
                .expect("HTTP request remained live after external preflight");
            (
                format!(
                    "{}://{}:{}{}",
                    if state.use_tls { "https" } else { "http" },
                    state.host,
                    state.port,
                    state.path
                ),
                state.method.clone(),
                Self::http_effect_headers(&state.headers),
                (!state.body.is_empty()).then(|| state.body.clone()),
            )
        };
        self.validate_http_client_terminal_slots(request)?;
        if !egress_label.can_flow_to(&Label::Public) {
            // Use the same exact-request refusal journal as the legacy facade.
            // Reserve delivery first, then roll it back if evidence cannot be
            // accepted. Neither a missing sink nor a replay mismatch may consume
            // the request or turn an unrecorded refusal into handled completion.
            let error_sequence = self.schedule_http_task(PendingHttpTask::ClientError {
                request,
                code: "ERR_NETWORK".to_string(),
                label: lifecycle_label,
            })?;
            if let Err(error) =
                self.record_deferred_network_ifc_denial(&url, &method, &headers, body.as_deref())
            {
                self.cancel_http_task_registration(error_sequence);
                return Err(error);
            }
            self.mark_http_client_request_ended(request)?;
            return Ok(Value::Undefined);
        }
        let delivery_sequence =
            self.schedule_http_task(PendingHttpTask::DeliverExternalResponse {
                request,
                response: None,
            })?;
        self.mark_http_client_request_ended(request)?;
        let response = self.perform_net_request_effect(url, method, headers, body)?;
        if let Value::Object(response_id) = response {
            let Some(PendingHttpTask::DeliverExternalResponse { response, .. }) =
                self.pending_http_tasks.get_mut(&delivery_sequence)
            else {
                return Err(InterpreterError::InternalError {
                    details: "reserved external HTTP delivery task disappeared".to_string(),
                });
            };
            *response = Some(response_id);
        }
        Ok(Value::Undefined)
    }

    pub(super) fn http_header_lookup_name(
        &mut self,
        args: RegRange,
    ) -> Result<String, InterpreterError> {
        let Some(value) = self.builtin_arg(args, 0)? else {
            return Ok(String::new());
        };
        let name_len =
            self.http_primitive_string_len(&value, "bounded primitive HTTP header name")?;
        if name_len > MAX_HTTP_HEADER_NAME_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "HTTP header name length exceeds {MAX_HTTP_HEADER_NAME_BYTES} bytes"
                ),
            });
        }
        self.charge_http_work(name_len, 1)?;
        self.check_temporary_memory_budget(
            u64::try_from(name_len)
                .unwrap_or(u64::MAX)
                .saturating_mul(2)
                .saturating_add(64 * 1024),
        )?;
        Ok(self
            .http_primitive_string(&value, "bounded primitive HTTP header name")?
            .to_ascii_lowercase())
    }

    pub(super) fn http_get_header(
        &mut self,
        receiver: Option<Value>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let response = self.http_server_response_receiver(receiver)?;
        let name = self.http_header_lookup_name(args)?;
        let header = self.http_server_responses[&response]
            .headers
            .get(&name)
            .cloned();
        match header {
            Some(HttpHeaderValue {
                array_values: Some(values),
                ..
            }) => {
                let values = values
                    .iter()
                    .map(String::as_str)
                    .map(Value::str)
                    .collect::<Vec<_>>();
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }
            Some(header) => Ok(Value::str(header.value.as_str())),
            None => Ok(Value::Undefined),
        }
    }

    pub(super) fn http_has_header(
        &mut self,
        receiver: Option<Value>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let response = self.http_server_response_receiver(receiver)?;
        let name = self.http_header_lookup_name(args)?;
        Ok(Value::Bool(
            self.http_server_responses[&response]
                .headers
                .contains_key(&name),
        ))
    }

    pub(super) fn http_remove_header(
        &mut self,
        receiver: Option<Value>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let response = self.http_server_response_receiver(receiver)?;
        let name = self.http_header_lookup_name(args)?;
        let (previous_bytes, removed_bytes, previous_label) = {
            let state = &self.http_server_responses[&response];
            if state.ended {
                return Err(InterpreterError::TypeError {
                    expected: "mutable HTTP response headers".to_string(),
                    got: "response already ended".to_string(),
                });
            }
            (
                Self::estimate_http_server_response_state_bytes(state),
                state
                    .headers
                    .get(&name)
                    .map_or(0, |header| Self::estimate_http_header_bytes(&name, header)),
                state.lifecycle_label.clone(),
            )
        };
        let next_label = previous_label.join(&self.writable_invocation_label(args)?);
        let next_bytes = previous_bytes
            .saturating_sub(removed_bytes)
            .saturating_sub(Self::estimate_label_bytes(&previous_label))
            .saturating_add(Self::estimate_label_bytes(&next_label));
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        let state = self
            .http_server_responses
            .get_mut(&response)
            .expect("HTTP response was authenticated before header removal");
        state.headers.remove(&name);
        state.lifecycle_label = next_label;
        Ok(Value::Undefined)
    }

    pub(super) fn http_write_head(
        &mut self,
        receiver: Option<Value>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let response = self.http_server_response_receiver(receiver)?;
        let status = self
            .builtin_arg(args, 0)?
            .map(|value| Self::value_as_integer(&value))
            .unwrap_or(200);
        if !(100..=999).contains(&status) {
            return Err(InterpreterError::RangeError {
                message: format!("invalid HTTP status code {status}"),
            });
        }
        let second = self.builtin_arg(args, 1)?;
        let third = self.builtin_arg(args, 2)?;
        let status_message = second
            .as_ref()
            .filter(|value| matches!(value, Value::Str(_)))
            .map(|value| self.value_to_string(value))
            .unwrap_or_else(|| Self::http_status_message(status as u16).to_string());
        if status_message.len() > MAX_HTTP_HEADER_VALUE_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "HTTP status message length exceeds {MAX_HTTP_HEADER_VALUE_BYTES} bytes"
                ),
            });
        }
        if status_message.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(InterpreterError::TypeError {
                expected: "HTTP status message without control bytes".to_string(),
                got: "status message contains a control byte".to_string(),
            });
        }
        let headers_value = third.as_ref().or_else(|| {
            second
                .as_ref()
                .filter(|value| matches!(value, Value::Object(_)))
        });
        let headers = self.http_headers_from_value(headers_value)?;
        let invocation_label = self.writable_invocation_label(args)?;
        let (previous_bytes, replaced_header_bytes, previous_status_bytes, previous_label) = {
            let state = &self.http_server_responses[&response];
            if state.ended {
                return Err(InterpreterError::TypeError {
                    expected: "mutable HTTP response headers".to_string(),
                    got: "response already ended".to_string(),
                });
            }
            let inserted = headers
                .keys()
                .filter(|name| !state.headers.contains_key(*name))
                .count();
            if state.headers.len().saturating_add(inserted) > MAX_HTTP_HEADER_COUNT {
                return Err(InterpreterError::RangeError {
                    message: format!("HTTP header count exceeds {MAX_HTTP_HEADER_COUNT}"),
                });
            }
            (
                Self::estimate_http_server_response_state_bytes(state),
                headers
                    .keys()
                    .filter_map(|name| {
                        state
                            .headers
                            .get(name)
                            .map(|old| Self::estimate_http_header_bytes(name, old))
                    })
                    .sum::<u64>(),
                MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(state.status_message.len() as u64),
                state.lifecycle_label.clone(),
            )
        };
        let inserted_header_bytes = Self::estimate_http_headers_bytes(&headers);
        let next_label = previous_label.join(&invocation_label);
        let next_bytes = previous_bytes
            .saturating_sub(replaced_header_bytes)
            .saturating_sub(previous_status_bytes)
            .saturating_sub(Self::estimate_label_bytes(&previous_label))
            .saturating_add(inserted_header_bytes)
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
            .saturating_add(status_message.len() as u64)
            .saturating_add(Self::estimate_label_bytes(&next_label));
        let original_object = self.heap[response.0 as usize].clone();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            self.set_object_property(response, "statusCode".to_string(), Value::Int(status))?;
            self.set_object_property(
                response,
                "statusMessage".to_string(),
                Value::str(status_message.as_str()),
            )?;
            self.apply_memory_component_delta(previous_bytes, next_bytes)?;
            let state = self
                .http_server_responses
                .get_mut(&response)
                .expect("HTTP response was authenticated before writeHead commit");
            state.status_code = status as u16;
            state.status_message = status_message;
            state.headers.extend(headers);
            state.lifecycle_label = next_label;
            Ok(())
        })();
        if result.is_err() {
            self.mutate_heap(|heap| heap[response.0 as usize] = original_object);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result?;
        Ok(Value::Object(response))
    }

    pub(super) fn http_client_write(
        &mut self,
        receiver: Option<Value>,
        args: RegRange,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let request = self.http_client_request_receiver(receiver)?;
        self.join_http_client_request_egress_from_args(request, args)?;
        let label = self.writable_invocation_label_with_receiver(args, receiver_register)?;
        if let Some(value) = self.builtin_arg(args, 0)? {
            self.http_append_client_body(request, &value, label)?;
        } else {
            self.join_http_client_request_lifecycle_label(request, &label)?;
        }
        Ok(Value::Bool(true))
    }

    pub(super) fn http_client_end(
        &mut self,
        receiver: Option<Value>,
        args: RegRange,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let request = self.http_client_request_receiver(receiver)?;
        self.join_http_client_request_egress_from_args(request, args)?;
        let label = self.writable_invocation_label_with_receiver(args, receiver_register)?;
        let first = self.builtin_arg(args, 0)?;
        let second = self.builtin_arg(args, 1)?;
        if let Some(value) = first.as_ref()
            && !matches!(value, Value::Closure(_) | Value::Undefined)
        {
            self.http_append_client_body(request, value, label)?;
        } else {
            self.join_http_client_request_lifecycle_label(request, &label)?;
        }
        let finish_callback = match second.or(first) {
            Some(Value::Closure(callback)) => Some(callback),
            _ => None,
        };
        let result = self.finish_http_client_request(request)?;
        if let Some(callback) = finish_callback {
            let label = self.http_client_requests[&request].lifecycle_label.clone();
            self.schedule_io_callback_with_label(callback, Vec::new(), label)?;
        }
        Ok(result)
    }

    pub(super) fn http_incoming_set_encoding(
        &mut self,
        receiver: Option<Value>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let message = self.http_incoming_message_receiver(receiver)?;
        let encoding = match self.builtin_arg(args, 0)? {
            Some(Value::Str(value)) if value.len() <= 16 => value.to_ascii_lowercase(),
            Some(Value::Str(_)) => {
                return Err(InterpreterError::RangeError {
                    message: "HTTP stream encoding exceeds 16 bytes".to_string(),
                });
            }
            Some(value) => {
                return Err(InterpreterError::TypeError {
                    expected: "bounded string HTTP stream encoding".to_string(),
                    got: value.type_name().to_string(),
                });
            }
            None => String::new(),
        };
        if !matches!(encoding.as_str(), "utf8" | "utf-8") {
            return Err(InterpreterError::TypeError {
                expected: "utf8 HTTP stream encoding".to_string(),
                got: encoding,
            });
        }
        if let Some(state) = self.http_incoming_messages.get_mut(&message) {
            state.encoding_utf8 = true;
        }
        Ok(Value::Object(message))
    }

    pub(super) fn http_incoming_resume(
        &self,
        receiver: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        Ok(Value::Object(
            self.http_incoming_message_receiver(receiver)?,
        ))
    }

    pub(super) fn http_response_write(
        &mut self,
        receiver: Option<Value>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let response = self.http_server_response_receiver(receiver)?;
        if let Some(value) = self.builtin_arg(args, 0)? {
            let label = self.writable_invocation_label(args)?;
            self.http_append_response_body(response, &value, label)?;
        }
        Ok(Value::Bool(true))
    }

    pub(super) fn http_response_end(
        &mut self,
        receiver: Option<Value>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let response = self.http_server_response_receiver(receiver)?;
        if let Some(value) = self.builtin_arg(args, 0)?
            && !matches!(value, Value::Closure(_) | Value::Undefined)
        {
            let label = self.writable_invocation_label(args)?;
            self.http_append_response_body(response, &value, label)?;
        }
        self.finish_http_server_response(response)?;
        Ok(Value::Undefined)
    }

    pub(super) fn finish_http_server_response(
        &mut self,
        response: ObjectId,
    ) -> Result<(), InterpreterError> {
        let response_index = response.0 as usize;
        let response_object = self
            .heap
            .get(response_index)
            .ok_or(InterpreterError::ObjectNotFound { id: response.0 })?;
        for property in ["writable", "writableEnded"] {
            if !matches!(
                response_object.properties.get(property),
                Some(Value::Bool(_))
            ) {
                return Err(InterpreterError::InternalError {
                    details: format!(
                        "authenticated HTTP ServerResponse lacks Boolean {property} slot"
                    ),
                });
            }
        }
        let effective_status = response_object
            .properties
            .get("statusCode")
            .map(Self::value_as_integer)
            .and_then(|status| u16::try_from(status).ok());
        let explicit_status_message = match response_object.properties.get("statusMessage") {
            Some(Value::Str(message)) => {
                let message = message.as_str().unwrap_or_default();
                if message.len() > MAX_HTTP_HEADER_VALUE_BYTES {
                    return Err(InterpreterError::RangeError {
                        message: format!(
                            "HTTP status message length exceeds {MAX_HTTP_HEADER_VALUE_BYTES} bytes"
                        ),
                    });
                }
                if message.bytes().any(|byte| byte.is_ascii_control()) {
                    return Err(InterpreterError::TypeError {
                        expected: "HTTP status message without control bytes".to_string(),
                        got: "status message contains a control byte".to_string(),
                    });
                }
                Some(message.to_string())
            }
            _ => None,
        };
        let (
            old_bytes,
            publication_bytes,
            temporary_peak,
            header_count,
            status_code,
            status_message,
            suppress_body,
            add_transfer_encoding,
        ) = {
            let state = self
                .http_server_responses
                .get(&response)
                .ok_or(InterpreterError::ObjectNotFound { id: response.0 })?;
            if state.ended {
                return Ok(());
            }
            let status_code = effective_status.unwrap_or(state.status_code);
            let mut status_message = explicit_status_message
                .clone()
                .unwrap_or_else(|| state.status_message.clone());
            if status_message.is_empty() {
                status_message = Self::http_status_message(status_code).to_string();
            }
            let suppress_body = state.request_method == "HEAD" || status_code == 204;
            let add_transfer_encoding = !suppress_body
                && !state.body.is_empty()
                && !state.headers.contains_key("content-length")
                && !state.headers.contains_key("transfer-encoding");
            let header_bytes = state
                .headers
                .values()
                .map(|header| {
                    header
                        .original_name
                        .len()
                        .saturating_add(header.value.len())
                })
                .sum::<usize>();
            let projected_header_bytes = header_bytes.saturating_add(if add_transfer_encoding {
                "Transfer-Encoding".len() + "chunked".len()
            } else {
                0
            });
            let body_bytes = if suppress_body { 0 } else { state.body.len() };
            let publication_bytes = body_bytes
                .saturating_add(projected_header_bytes.saturating_mul(2))
                .saturating_add(status_message.len())
                .saturating_add(128);
            let temporary_peak = body_bytes
                .saturating_mul(3)
                .saturating_add(projected_header_bytes.saturating_mul(6))
                .saturating_add(status_message.len().saturating_mul(3))
                .saturating_add(512 * 1024);
            (
                Self::estimate_http_server_response_state_bytes(state),
                publication_bytes,
                temporary_peak,
                state.headers.len() + usize::from(add_transfer_encoding),
                status_code,
                status_message,
                suppress_body,
                add_transfer_encoding,
            )
        };
        self.charge_http_work(publication_bytes, header_count)?;
        self.check_temporary_memory_budget(u64::try_from(temporary_peak).unwrap_or(u64::MAX))?;
        let mut next = self
            .http_server_responses
            .get(&response)
            .cloned()
            .expect("HTTP response was admitted before publication snapshot");
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        next.status_code = status_code;
        next.status_message = status_message;
        if suppress_body {
            next.body.clear();
        } else if add_transfer_encoding {
            next.headers.insert(
                "transfer-encoding".to_string(),
                HttpHeaderValue {
                    original_name: "Transfer-Encoding".to_string(),
                    array_values: None,
                    value: "chunked".to_string(),
                },
            );
        }
        next.ended = true;

        // Materialize the complete guest-visible response under one rollback
        // checkpoint. The delivery task is the final fallible publication; on
        // refusal, the response remains writable and no active connection can
        // become permanently stranded behind an unreachable message object.
        let result = (|| {
            let message = self.construct_http_incoming_message(
                next.body.clone(),
                next.lifecycle_label.clone(),
                true,
                Some(HttpServerCompletion {
                    server: next.server,
                    generation: next.server_generation,
                    response,
                }),
            )?;
            let headers = self.alloc_http_headers_object(&next.headers)?;
            let raw_headers = self.alloc_http_raw_headers(&next.headers)?;
            self.set_object_property(
                message,
                "statusCode".to_string(),
                Value::Int(i64::from(next.status_code)),
            )?;
            self.set_object_property(
                message,
                "statusMessage".to_string(),
                Value::str(next.status_message.as_str()),
            )?;
            self.set_object_property(message, "headers".to_string(), Value::Object(headers))?;
            self.set_object_property(
                message,
                "rawHeaders".to_string(),
                Value::Object(raw_headers),
            )?;

            let new_bytes = Self::estimate_http_server_response_state_bytes(&next);
            self.apply_memory_component_delta(old_bytes, new_bytes)?;
            self.schedule_http_task(PendingHttpTask::DeliverResponse {
                request: next.client_request,
                message,
            })?;
            self.http_server_responses.insert(response, next);
            self.mutate_heap(|heap| {
                let properties = &mut heap[response_index].properties;
                *properties
                    .get_mut("writable")
                    .expect("HTTP writable slot was validated before terminal commit") =
                    Value::Bool(false);
                *properties
                    .get_mut("writableEnded")
                    .expect("HTTP writableEnded slot was validated before terminal commit") =
                    Value::Bool(true);
            });
            Ok(())
        })();
        if result.is_err() {
            self.http_incoming_messages
                .retain(|message, _| (message.0 as usize) < previous_heap_len);
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn complete_http_server_response(
        &mut self,
        completion: HttpServerCompletion,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let mut removed_connection = false;
        let mut schedule_close = false;
        if let Some(server_state) = self.loopback_servers.get_mut(&completion.server)
            && server_state.generation == completion.generation
        {
            removed_connection = server_state.active_connections.remove(&completion.response);
            schedule_close = removed_connection
                && server_state.close_requested
                && server_state.active_connections.is_empty()
                && !server_state.close_scheduled;
            if schedule_close {
                server_state.close_scheduled = true;
            }
        }
        if removed_connection {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(MEMORY_ESTIMATE_MAP_ENTRY_BYTES);
        }
        if let Some(response_state) = self.http_server_responses.remove(&completion.response) {
            self.clear_event_listeners(completion.response, None);
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(
                Self::estimate_http_server_response_state_bytes(&response_state),
            );
        }
        if schedule_close
            && let Err(error) = self.schedule_loopback_task(PendingLoopbackTask::ServerClose {
                server: completion.server,
                generation: completion.generation,
                label,
            })
        {
            if let Some(server_state) = self.loopback_servers.get_mut(&completion.server)
                && server_state.generation == completion.generation
            {
                server_state.close_scheduled = false;
            }
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn discard_http_incoming_message(
        &mut self,
        message: ObjectId,
    ) -> Result<(), InterpreterError> {
        let Some(state) = self.http_incoming_messages.remove(&message) else {
            return Ok(());
        };
        self.clear_event_listeners(message, None);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(Self::estimate_http_incoming_message_state_bytes(&state));
        if let Some(completion) = state.server_completion {
            self.complete_http_server_response(completion, state.lifecycle_label)?;
        }
        Ok(())
    }

    pub(super) fn execute_pending_http_task(
        &mut self,
        task: PendingHttpTask,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let retained_bytes = Self::estimate_pending_http_task_bytes(&task);
        self.http_task_in_flight_bytes = self
            .http_task_in_flight_bytes
            .saturating_add(retained_bytes);
        let gc_pins = self.gc_pin_http_task(&task);
        let result = self.drive_pending_http_task(task, module);
        self.gc_unpin_network_values(gc_pins);
        self.http_task_in_flight_bytes = self
            .http_task_in_flight_bytes
            .saturating_sub(retained_bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(retained_bytes);
        result
    }

    pub(super) fn drive_pending_http_task(
        &mut self,
        task: PendingHttpTask,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        match task {
            PendingHttpTask::DispatchRequest {
                request,
                server,
                generation,
            } => {
                if !matches!(
                    self.loopback_ports.get(&self.http_client_requests.get(&request).map_or(0, |state| state.port)),
                    Some(LoopbackPortState::Live {
                        server: live_server,
                        generation: live_generation,
                    }) if *live_server == server && *live_generation == generation
                ) || !self.http_servers.contains_key(&server)
                {
                    let label = self
                        .http_client_requests
                        .get(&request)
                        .map(|state| state.lifecycle_label.clone())
                        .unwrap_or(Label::Public);
                    return self
                        .schedule_http_task(PendingHttpTask::ClientError {
                            request,
                            code: "ECONNREFUSED".to_string(),
                            label,
                        })
                        .map(|_| ());
                }
                let (publication_bytes, header_count) = {
                    let state = self
                        .http_client_requests
                        .get(&request)
                        .ok_or(InterpreterError::ObjectNotFound { id: request.0 })?;
                    let header_bytes = state
                        .headers
                        .values()
                        .map(|header| {
                            header
                                .original_name
                                .len()
                                .saturating_add(header.value.len())
                        })
                        .sum::<usize>();
                    (
                        state
                            .body
                            .len()
                            .saturating_add(header_bytes.saturating_mul(2))
                            .saturating_add(state.method.len())
                            .saturating_add(state.path.len()),
                        state.headers.len(),
                    )
                };
                self.charge_http_work(publication_bytes, header_count)?;
                self.check_temporary_memory_budget(
                    u64::try_from(publication_bytes)
                        .unwrap_or(u64::MAX)
                        .saturating_mul(2)
                        .saturating_add(256 * 1024),
                )?;
                let request_state = self
                    .http_client_requests
                    .get(&request)
                    .cloned()
                    .expect("HTTP request remained live after publication preflight");
                let lifecycle_label = request_state.lifecycle_label.join(
                    &self
                        .http_servers
                        .get(&server)
                        .map(|state| state.lifecycle_label.clone())
                        .unwrap_or(Label::Public),
                );
                let message = self.construct_http_incoming_message(
                    request_state.body.clone(),
                    lifecycle_label.clone(),
                    true,
                    None,
                )?;
                let headers = self.alloc_http_headers_object(&request_state.headers)?;
                let raw_headers = self.alloc_http_raw_headers(&request_state.headers)?;
                self.set_object_property(
                    message,
                    "method".to_string(),
                    Value::str(request_state.method.as_str()),
                )?;
                self.set_object_property(
                    message,
                    "url".to_string(),
                    Value::str(request_state.path.as_str()),
                )?;
                self.set_object_property(message, "headers".to_string(), Value::Object(headers))?;
                self.set_object_property(
                    message,
                    "rawHeaders".to_string(),
                    Value::Object(raw_headers),
                )?;

                let response = self.alloc_branded_object(
                    "HttpServerResponse",
                    &[
                        ("__maxListeners", Value::Int(10)),
                        ("statusCode", Value::Int(200)),
                        ("statusMessage", Value::str("OK")),
                        ("writable", Value::Bool(true)),
                        ("writableEnded", Value::Bool(false)),
                    ],
                )?;
                let response_state = HttpServerResponseState {
                    client_request: request,
                    server,
                    server_generation: generation,
                    request_method: request_state.method,
                    status_code: 200,
                    status_message: "OK".to_string(),
                    headers: BTreeMap::new(),
                    body: Vec::new(),
                    ended: false,
                    lifecycle_label: lifecycle_label.clone(),
                };
                self.apply_memory_component_delta(
                    0,
                    Self::estimate_http_server_response_state_bytes(&response_state)
                        .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES),
                )?;
                self.http_server_responses.insert(response, response_state);
                self.loopback_servers
                    .get_mut(&server)
                    .expect("live HTTP server disappeared during request admission")
                    .active_connections
                    .insert(response);
                let message_task = if !request_state.body.is_empty() {
                    PendingHttpTask::MessageData { message }
                } else {
                    PendingHttpTask::MessageEnd { message }
                };
                let message_sequence = match self.schedule_http_task(message_task) {
                    Ok(sequence) => sequence,
                    Err(error) => {
                        self.discard_http_incoming_message(message)?;
                        self.complete_http_server_response(
                            HttpServerCompletion {
                                server,
                                generation,
                                response,
                            },
                            lifecycle_label.clone(),
                        )?;
                        return Err(error);
                    }
                };
                let publication = self.emit_loopback_event(
                    module,
                    server,
                    "request",
                    vec![Value::Object(message), Value::Object(response)],
                    lifecycle_label.clone(),
                );
                if let Err(error) = publication {
                    self.cancel_http_task_registration(message_sequence);
                    self.discard_http_incoming_message(message)?;
                    self.complete_http_server_response(
                        HttpServerCompletion {
                            server,
                            generation,
                            response,
                        },
                        lifecycle_label,
                    )?;
                    return Err(error);
                }
            }
            PendingHttpTask::DeliverResponse { request, message } => {
                let (response_callback, request_label) = self
                    .http_client_requests
                    .get(&request)
                    .map(|state| (state.response_callback, state.lifecycle_label.clone()))
                    .ok_or(InterpreterError::ObjectNotFound { id: request.0 })?;
                let response_label = request_label.join(
                    &self
                        .http_incoming_messages
                        .get(&message)
                        .map(|message| message.lifecycle_label.clone())
                        .unwrap_or(Label::Public),
                );
                let next_phase = if self
                    .http_incoming_messages
                    .get(&message)
                    .is_some_and(|message| !message.body.is_empty())
                {
                    PendingHttpTask::MessageData { message }
                } else {
                    PendingHttpTask::MessageEnd { message }
                };
                let next_sequence = match self.schedule_http_task(next_phase) {
                    Ok(sequence) => sequence,
                    Err(error) => {
                        self.discard_http_incoming_message(message)?;
                        return Err(error);
                    }
                };
                let publication = (|| {
                    if let (Some(module), Some(callback)) = (module, response_callback) {
                        self.with_event_job_gc_request(Vec::new(), |core| {
                            core.invoke_inline_method_call_with_argument_label(
                                Some(module),
                                Value::Closure(callback),
                                Value::Undefined,
                                vec![Value::Object(message)],
                                Some(response_label.clone()),
                            )
                        })?;
                    }
                    let _ = self.emit_loopback_event(
                        module,
                        request,
                        "response",
                        vec![Value::Object(message)],
                        response_label,
                    )?;
                    Ok(())
                })();
                if let Err(error) = publication {
                    self.cancel_http_task_registration(next_sequence);
                    self.discard_http_incoming_message(message)?;
                    return Err(error);
                }
            }
            PendingHttpTask::DeliverExternalResponse { request, response } => {
                let (response_callback, lifecycle_label) = self
                    .http_client_requests
                    .get(&request)
                    .map(|state| (state.response_callback, state.lifecycle_label.clone()))
                    .ok_or(InterpreterError::ObjectNotFound { id: request.0 })?;
                let response_label =
                    hostcall_result_contract("net:request").result_label(&lifecycle_label, None);
                let Some(response) = response else {
                    let error = self.http_error_value("ERR_NETWORK")?;
                    let _ = self.emit_loopback_event(
                        module,
                        request,
                        "error",
                        vec![error],
                        response_label,
                    )?;
                    return Ok(());
                };
                self.schedule_stream_emission(
                    response,
                    StreamEventPhase::Data,
                    response_label.clone(),
                )?;
                if let (Some(module), Some(callback)) = (module, response_callback) {
                    self.with_event_job_gc_request(Vec::new(), |core| {
                        core.invoke_inline_method_call_with_argument_label(
                            Some(module),
                            Value::Closure(callback),
                            Value::Undefined,
                            vec![Value::Object(response)],
                            Some(response_label.clone()),
                        )
                    })?;
                }
                let _ = self.emit_loopback_event(
                    module,
                    request,
                    "response",
                    vec![Value::Object(response)],
                    response_label,
                )?;
            }
            PendingHttpTask::MessageData { message } => {
                let body_len = {
                    let Some(state) = self.http_incoming_messages.get(&message) else {
                        return Ok(());
                    };
                    if state.delivered || state.body.is_empty() {
                        return Ok(());
                    }
                    state.body.len()
                };
                self.charge_http_work(body_len, 1)?;
                self.check_temporary_memory_budget(
                    u64::try_from(body_len)
                        .unwrap_or(u64::MAX)
                        .saturating_mul(3)
                        .saturating_add(128 * 1024),
                )?;
                let Some((body, encoding_utf8, lifecycle_label)) =
                    self.http_incoming_messages.get(&message).map(|state| {
                        (
                            state.body.clone(),
                            state.encoding_utf8,
                            state.lifecycle_label.clone(),
                        )
                    })
                else {
                    return Ok(());
                };
                let end_sequence =
                    match self.schedule_http_task(PendingHttpTask::MessageEnd { message }) {
                        Ok(sequence) => sequence,
                        Err(error) => {
                            self.discard_http_incoming_message(message)?;
                            return Err(error);
                        }
                    };
                let chunk = (|| {
                    if encoding_utf8 {
                        Ok(Value::str(String::from_utf8_lossy(&body).into_owned()))
                    } else {
                        let buffer = self.alloc_buffer_from_bytes(&body)?;
                        self.join_binary_storage_label(buffer, &lifecycle_label)?;
                        Ok(Value::Object(buffer))
                    }
                })();
                let chunk = match chunk {
                    Ok(chunk) => chunk,
                    Err(error) => {
                        self.cancel_http_task_registration(end_sequence);
                        self.discard_http_incoming_message(message)?;
                        return Err(error);
                    }
                };
                if let Some(current) = self.http_incoming_messages.get_mut(&message) {
                    current.delivered = true;
                }
                let emission =
                    self.emit_loopback_event(module, message, "data", vec![chunk], lifecycle_label);
                if let Err(error) = emission {
                    self.cancel_http_task_registration(end_sequence);
                    self.discard_http_incoming_message(message)?;
                    return Err(error);
                }
            }
            PendingHttpTask::MessageEnd { message } => {
                let Some((close_after_end, lifecycle_label)) = self
                    .http_incoming_messages
                    .get(&message)
                    .map(|state| (state.close_after_end, state.lifecycle_label.clone()))
                else {
                    return Ok(());
                };
                let close_sequence = if close_after_end {
                    match self.schedule_http_task(PendingHttpTask::MessageClose { message }) {
                        Ok(sequence) => Some(sequence),
                        Err(error) => {
                            self.discard_http_incoming_message(message)?;
                            return Err(error);
                        }
                    }
                } else {
                    None
                };
                let publication = (|| {
                    self.set_object_property(message, "readable".to_string(), Value::Bool(false))?;
                    let _ = self.emit_loopback_event(
                        module,
                        message,
                        "end",
                        Vec::new(),
                        lifecycle_label,
                    )?;
                    Ok(())
                })();
                if let Err(error) = publication {
                    if let Some(sequence) = close_sequence {
                        self.cancel_http_task_registration(sequence);
                    }
                    self.discard_http_incoming_message(message)?;
                    return Err(error);
                }
            }
            PendingHttpTask::MessageClose { message } => {
                let Some(state) = self.http_incoming_messages.remove(&message) else {
                    return Ok(());
                };
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(Self::estimate_http_incoming_message_state_bytes(&state));
                let completion = if let Some(completion) = state.server_completion {
                    self.complete_http_server_response(completion, state.lifecycle_label.clone())
                } else {
                    Ok(())
                };
                let emission = self.emit_loopback_event(
                    module,
                    message,
                    "close",
                    Vec::new(),
                    state.lifecycle_label.clone(),
                );
                self.clear_event_listeners(message, None);
                completion?;
                let _ = emission?;
            }
            PendingHttpTask::ClientError {
                request,
                code,
                label,
            } => {
                let error = self.http_error_value(&code)?;
                let _ = self.emit_loopback_event(module, request, "error", vec![error], label)?;
            }
            PendingHttpTask::EmitLegacyEvent {
                target,
                event,
                arguments,
                leading_callback,
                label,
            } => {
                if let Some(module) = module {
                    let records = self.event_listener_records_for(target, &event);
                    // A leading callback may remove listeners before their
                    // captured snapshot runs. Keep that snapshot alive even
                    // when no live EventEmitter registration names it.
                    let gc_pins = self.gc_pin_network_values(
                        records.iter().map(|record| record.listener.clone()),
                    );
                    let emission = (|| {
                        if let Some(callback) = leading_callback {
                            self.with_event_job_gc_request(Vec::new(), |core| {
                                core.invoke_inline_method_call_with_argument_label(
                                    Some(module),
                                    Value::Closure(callback),
                                    Value::Object(target),
                                    arguments.clone(),
                                    Some(label.clone()),
                                )
                            })?;
                        }
                        self.emit_event_listener_snapshot(
                            module, target, &event, arguments, label, records,
                        )
                    })();
                    self.gc_unpin_network_values(gc_pins);
                    let _ = emission?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn clear_http_execution_state(&mut self) {
        let registrations: Vec<u64> = self
            .pending_http_tasks
            .keys()
            .chain(self.pending_stream_emissions.keys())
            .copied()
            .collect();
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        for registration in registrations {
            self.event_loop.cancel_registration(registration);
        }
        let released_promise_bytes =
            previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
        let retained_bytes = self.http_runtime_memory_bytes();
        let targets: BTreeSet<ObjectId> = self
            .http_servers
            .keys()
            .chain(self.http_client_requests.keys())
            .chain(self.http_incoming_messages.keys())
            .chain(self.http_server_responses.keys())
            .copied()
            .chain(
                self.pending_stream_emissions
                    .values()
                    .map(|emission| emission.object_id),
            )
            .collect();
        self.http_servers.clear();
        self.http_client_requests.clear();
        self.http_incoming_messages.clear();
        self.http_server_responses.clear();
        self.http_agents.clear();
        self.pending_http_tasks.clear();
        self.pending_stream_emissions.clear();
        self.http_task_in_flight_bytes = 0;
        for target in targets {
            self.clear_event_listeners(target, None);
            self.clear_event_promise_waiters_for_target(target);
        }
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(retained_bytes)
            .saturating_sub(released_promise_bytes);
    }

    pub(super) fn clear_loopback_execution_state(&mut self) {
        let registrations: Vec<u64> = self.pending_loopback_tasks.keys().copied().collect();
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        for registration in registrations {
            self.event_loop.cancel_registration(registration);
        }
        let released_promise_bytes =
            previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
        let retained_bytes = self
            .loopback_servers_memory_bytes()
            .saturating_add(self.loopback_sockets_memory_bytes())
            .saturating_add(self.loopback_ports_memory_bytes())
            .saturating_add(self.pending_loopback_tasks_memory_bytes())
            .saturating_add(self.loopback_task_in_flight_bytes);
        let targets: Vec<ObjectId> = self
            .loopback_servers
            .keys()
            .chain(self.loopback_sockets.keys())
            .copied()
            .collect();
        self.loopback_servers.clear();
        self.loopback_sockets.clear();
        self.loopback_ports.clear();
        self.pending_loopback_tasks.clear();
        self.loopback_task_in_flight_bytes = 0;
        self.next_loopback_port = 41_000;
        for target in targets {
            self.clear_event_listeners(target, None);
            self.clear_event_promise_waiters_for_target(target);
        }
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(retained_bytes)
            .saturating_sub(released_promise_bytes);
    }

    /// bd-3894s slice (2d): register an event listener closure for `event` on the
    /// stream object `target_id`, preserving registration order. Backs the shared
    /// `EventEmitter.prototype.on` for the HTTP `ClientRequest`/`IncomingMessage`
    /// objects.
    #[cfg(test)]
    pub(super) fn register_event_listener(
        &mut self,
        target_id: ObjectId,
        event: &str,
        closure_id: u32,
    ) {
        self.insert_event_listener(
            target_id,
            event,
            EventListenerRecord {
                listener: Value::Closure(closure_id),
                once: false,
            },
            false,
        )
        .expect("test listener registration fits the memory budget");
    }

    /// Register the Promise returned by static `events.once(emitter, event)`.
    /// The requested event resolves with an array of every emitted argument.
    /// Unless the requested event is itself `error`, a linked `error` record
    /// rejects with the original first emitted value. Both records are removed
    /// before settlement so a later event cannot observe a stale sibling link.
    pub(super) fn register_event_promise_once(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count != 2 {
            return Err(InterpreterError::TypeError {
                expected: "events.once(emitter, event)".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        let target = self.read_reg(args.start)?;
        let Value::Object(target_id) = target else {
            return Err(InterpreterError::TypeError {
                expected: "EventEmitter object".to_string(),
                got: target.type_name().to_string(),
            });
        };
        let event_reg = args
            .start
            .checked_add(1)
            .ok_or(InterpreterError::RegisterOutOfBounds {
                register: args.start,
                max: self.config.max_registers,
            })?;
        let event_value = self.read_reg(event_reg)?;
        let Some(event) = self.event_name_arg(args, 1)? else {
            return Err(InterpreterError::TypeError {
                expected: "string or symbol event name".to_string(),
                got: event_value.type_name().to_string(),
            });
        };
        let registration_label = self.join_arg_range_label(args)?;
        let next_waiter_id = self
            .next_event_promise_waiter_id
            .checked_add(1)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "events.once waiter id space exhausted".to_string(),
            })?;
        let error_event = RuntimePropertyKey::from("error");
        let link_count = if event == error_event { 1 } else { 2 };
        let added_bytes = (0..link_count).fold(0u64, |total, index| {
            let link_event = if index == 0 { &event } else { &error_event };
            total.saturating_add(Self::estimate_event_promise_waiter_record_bytes(
                link_event,
                &registration_label,
            ))
        });
        let waiter_id = self.next_event_promise_waiter_id;
        let pump_reserved =
            self.reserve_readable_activation_pump(target_id, event.as_str().unwrap_or_default())?;
        let promise = match self.create_promise() {
            Ok(promise) => promise,
            Err(error) => {
                if pump_reserved {
                    self.release_readable_pump_reservation(target_id);
                }
                return Err(error);
            }
        };
        if let Err(error) = self.apply_memory_component_delta(0, added_bytes) {
            self.rollback_fresh_promise(promise);
            if pump_reserved {
                self.release_readable_pump_reservation(target_id);
            }
            return Err(error);
        }
        self.next_event_promise_waiter_id = next_waiter_id;
        let resolve_record = EventPromiseWaiterRecord {
            waiter_id,
            promise,
            action: EventPromiseWaiterAction::Resolve,
            registration_label: registration_label.clone(),
        };
        self.event_promise_waiters
            .entry(target_id)
            .or_default()
            .entry(event.clone())
            .or_default()
            .push(resolve_record);
        if event != error_event {
            self.event_promise_waiters
                .entry(target_id)
                .or_default()
                .entry(error_event.clone())
                .or_default()
                .push(EventPromiseWaiterRecord {
                    waiter_id,
                    promise,
                    action: EventPromiseWaiterAction::Reject,
                    registration_label,
                });
        }
        // bd-asw4m.4: publish one guest-visible `onceWrapper` listener per link
        // (the requested event, plus `error` for non-error waits) so
        // rawListeners()/listeners() report the registration the way Node does.
        // The wrapper is an introspection/removal carrier only — settlement runs
        // through settle_event_promise_waiters, which strips these wrappers — so
        // its `.listener` is intentionally inert and the emit dispatch loop never
        // invokes it.
        let wrapper_events = if event == error_event {
            vec![event.clone()]
        } else {
            vec![event.clone(), error_event]
        };
        let mut wrapper_rollback: Vec<(ObjectId, usize)> = Vec::new();
        for wrapper_event in &wrapper_events {
            let (wrapper, property_object, previous_heap_len) = match self
                .create_event_once_wrapper(
                    target_id,
                    wrapper_event,
                    Value::Undefined,
                    Some(waiter_id),
                ) {
                Ok(created) => created,
                Err(error) => {
                    self.unwind_static_once_wrappers(target_id, waiter_id, &wrapper_rollback);
                    self.remove_event_promise_waiter_links(target_id, waiter_id);
                    self.next_event_promise_waiter_id = waiter_id;
                    self.rollback_fresh_promise(promise);
                    if pump_reserved {
                        self.release_readable_pump_reservation(target_id);
                    }
                    return Err(error);
                }
            };
            if let Err(error) = self.insert_event_listener(
                target_id,
                wrapper_event,
                EventListenerRecord {
                    listener: wrapper,
                    once: true,
                },
                false,
            ) {
                self.rollback_event_once_wrapper(property_object, previous_heap_len);
                self.unwind_static_once_wrappers(target_id, waiter_id, &wrapper_rollback);
                self.remove_event_promise_waiter_links(target_id, waiter_id);
                self.next_event_promise_waiter_id = waiter_id;
                self.rollback_fresh_promise(promise);
                if pump_reserved {
                    self.release_readable_pump_reservation(target_id);
                }
                return Err(error);
            }
            wrapper_rollback.push((property_object, previous_heap_len));
        }
        if let Err(error) = self.activate_readable_from_data_flow_with_reservation(
            target_id,
            event.as_str().unwrap_or_default(),
            pump_reserved,
        ) {
            self.unwind_static_once_wrappers(target_id, waiter_id, &wrapper_rollback);
            self.remove_event_promise_waiter_links(target_id, waiter_id);
            self.next_event_promise_waiter_id = waiter_id;
            self.rollback_fresh_promise(promise);
            if pump_reserved {
                self.release_readable_pump_reservation(target_id);
            }
            return Err(error);
        }
        Ok(Value::Promise(promise.0))
    }

    /// Remove every event/error link belonging to one static-once waiter and
    /// release the exact conservative charge applied at registration.
    pub(super) fn remove_event_promise_waiter_links(
        &mut self,
        target_id: ObjectId,
        waiter_id: u64,
    ) {
        let mut released_bytes = 0u64;
        let mut empty_events = Vec::new();
        if let Some(by_event) = self.event_promise_waiters.get_mut(&target_id) {
            for (event, records) in by_event.iter_mut() {
                records.retain(|record| {
                    if record.waiter_id == waiter_id {
                        released_bytes = released_bytes.saturating_add(
                            Self::estimate_event_promise_waiter_record_bytes(
                                event,
                                &record.registration_label,
                            ),
                        );
                        false
                    } else {
                        true
                    }
                });
                if records.is_empty() {
                    empty_events.push(event.clone());
                }
            }
            for event in empty_events {
                by_event.remove(&event);
            }
        }
        if self
            .event_promise_waiters
            .get(&target_id)
            .is_some_and(BTreeMap::is_empty)
        {
            self.event_promise_waiters.remove(&target_id);
        }
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
        // bd-asw4m.4: drop the guest-visible once wrappers linked to this waiter
        // (the requested-event wrapper and, for non-error waits, the `error`
        // wrapper) so `rawListeners` stops reporting them the moment either link
        // settles or the registration is rolled back.
        self.remove_static_once_wrapper_listeners(target_id, waiter_id);
    }

    /// Remove every static-`events.once` wrapper listener carrier tied to
    /// `waiter_id` from the emitter's listener table, releasing each record's
    /// exact charge. The wrapper's private `event_once_wrappers` state is marked
    /// fired but retained until reset, mirroring `emitter.once()` wrappers whose
    /// carrier survives a single delivery (bd-asw4m.4).
    pub(super) fn remove_static_once_wrapper_listeners(
        &mut self,
        target_id: ObjectId,
        waiter_id: u64,
    ) {
        let matching: std::collections::BTreeSet<ObjectId> = self
            .event_once_wrappers
            .iter()
            .filter(|(_, state)| {
                state.target == target_id && state.static_once_waiter == Some(waiter_id)
            })
            .map(|(property_object, _)| *property_object)
            .collect();
        if matching.is_empty() {
            return;
        }
        let mut empty_events = Vec::new();
        let mut released = Vec::new();
        if let Some(by_event) = self.event_listeners.get_mut(&target_id) {
            for (event, records) in by_event.iter_mut() {
                records.retain(|record| {
                    if let Some(property_object) =
                        Self::event_once_wrapper_property_object(&record.listener)
                        && matching.contains(&property_object)
                    {
                        released.push((event.clone(), record.clone()));
                        return false;
                    }
                    true
                });
                if records.is_empty() {
                    empty_events.push(event.clone());
                }
            }
            for event in empty_events {
                by_event.remove(&event);
            }
        }
        if self
            .event_listeners
            .get(&target_id)
            .is_some_and(BTreeMap::is_empty)
        {
            self.event_listeners.remove(&target_id);
        }
        for (event, record) in released {
            self.release_event_listener_memory(&event, &record);
        }
        for property_object in matching {
            if let Some(state) = self.event_once_wrappers.get_mut(&property_object) {
                state.fired = true;
            }
        }
    }

    /// Fully undo the static-once wrappers created during a single
    /// `register_event_promise_once` that then failed: strip their listener
    /// records, then discard each wrapper's private state and heap carrier in
    /// reverse allocation order so the heap suffix invariant holds (bd-asw4m.4).
    pub(super) fn unwind_static_once_wrappers(
        &mut self,
        target_id: ObjectId,
        waiter_id: u64,
        inserted: &[(ObjectId, usize)],
    ) {
        self.remove_static_once_wrapper_listeners(target_id, waiter_id);
        for (property_object, previous_heap_len) in inserted.iter().rev() {
            self.rollback_event_once_wrapper(*property_object, *previous_heap_len);
        }
    }

    /// Settle every static `events.once` waiter linked to this emission. Promise
    /// reactions remain microtasks: settlement occurs during synchronous emit,
    /// while awaiting continuations run only at the normal checkpoint.
    pub(super) fn settle_event_promise_waiters(
        &mut self,
        target_id: ObjectId,
        event: &RuntimePropertyKey,
        arguments: &[Value],
        emission_label: &Label,
    ) -> Result<bool, InterpreterError> {
        let records = self
            .event_promise_waiters
            .get(&target_id)
            .and_then(|by_event| by_event.get(event))
            .cloned()
            .unwrap_or_default();
        if records.is_empty() {
            return Ok(false);
        }

        for record in records {
            let settlement_label = record.registration_label.join(emission_label);
            let settlement: Result<crate::object_model::JsValue, crate::object_model::JsValue> =
                match record.action {
                    EventPromiseWaiterAction::Resolve => {
                        let array = self.alloc_array_from_values(arguments)?;
                        Ok(crate::object_model::JsValue::Object(
                            crate::object_model::ObjectHandle(array.0),
                        ))
                    }
                    EventPromiseWaiterAction::Reject => Err(match arguments.first() {
                        Some(argument) => self.promise_value(argument)?,
                        None => crate::object_model::JsValue::Undefined,
                    }),
                };
            self.remove_event_promise_waiter_links(target_id, record.waiter_id);
            match settlement {
                Ok(value) => self.fulfill_promise(record.promise, value, settlement_label)?,
                Err(reason) => self.reject_promise(record.promise, reason, settlement_label)?,
            }
        }
        Ok(true)
    }

    /// Insert one listener record at the front or back of the shared emitter
    /// table. Meta-event delivery is handled by the receiver-aware builtin
    /// dispatch before this mutation, so the helper is also safe for the legacy
    /// HTTP setup path that has no module context.
    pub(super) fn insert_event_listener(
        &mut self,
        target_id: ObjectId,
        event: impl Into<RuntimePropertyKey>,
        record: EventListenerRecord,
        prepend: bool,
    ) -> Result<(), InterpreterError> {
        let event = event.into();
        let added_bytes = Self::estimate_event_listener_record_bytes(&event, &record);
        self.apply_memory_component_delta(0, added_bytes)?;
        let listeners = self
            .event_listeners
            .entry(target_id)
            .or_default()
            .entry(event)
            .or_default();
        if prepend {
            listeners.insert(0, record);
        } else {
            listeners.push(record);
        }
        Ok(())
    }

    pub(super) fn estimate_event_once_wrapper_state_bytes(state: &EventOnceWrapperState) -> u64 {
        MEMORY_ESTIMATE_EVENT_ONCE_WRAPPER_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
            .saturating_add(std::mem::size_of::<EventOnceWrapperState>() as u64)
            .saturating_add(Self::estimate_event_name_bytes(&state.event))
            .saturating_add(Self::estimate_value_bytes(&state.original_listener))
    }

    /// Materialize one stable callable wrapper and its public property carrier.
    /// The private state is precharged before either owner is published; a
    /// failed heap allocation releases that reservation exactly.
    pub(super) fn create_event_once_wrapper(
        &mut self,
        target: ObjectId,
        event: impl Into<RuntimePropertyKey>,
        original_listener: Value,
        static_once_waiter: Option<u64>,
    ) -> Result<(Value, ObjectId, usize), InterpreterError> {
        let state = EventOnceWrapperState {
            target,
            event: event.into(),
            original_listener: original_listener.clone(),
            fired: false,
            static_once_waiter,
        };
        let state_bytes = Self::estimate_event_once_wrapper_state_bytes(&state);
        let previous_estimated_bytes = self.estimated_memory_bytes;
        self.apply_memory_component_delta(0, state_bytes)?;

        let previous_heap_len = self.heap.len();
        let property_object =
            match self.alloc_object_with_properties(&[("listener", original_listener)]) {
                Ok(property_object) => property_object,
                Err(error) => {
                    self.rollback_heap_to_len(previous_heap_len);
                    self.estimated_memory_bytes = previous_estimated_bytes;
                    return Err(error);
                }
            };
        self.event_once_wrappers.insert(property_object, state);
        Ok((
            Value::BuiltinFunction(BuiltinFunction::emitter_once_wrapper(property_object)),
            property_object,
            previous_heap_len,
        ))
    }

    /// Roll back a wrapper that has not escaped registration. No guest code or
    /// other heap allocation runs between wrapper creation and these callers,
    /// so its property carrier is the sole heap suffix being discarded.
    pub(super) fn rollback_event_once_wrapper(
        &mut self,
        property_object: ObjectId,
        previous_heap_len: usize,
    ) {
        let released_state_bytes = self
            .event_once_wrappers
            .remove(&property_object)
            .as_ref()
            .map(Self::estimate_event_once_wrapper_state_bytes)
            .unwrap_or(0);
        let released_heap_bytes = Self::saturating_sum(
            self.heap
                .iter()
                .skip(previous_heap_len)
                .map(Self::estimate_heap_object_bytes),
        );
        debug_assert_eq!(property_object.0 as usize, previous_heap_len);
        self.rollback_heap_to_len(previous_heap_len);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(released_state_bytes)
            .saturating_sub(released_heap_bytes);
    }

    pub(super) fn event_once_wrapper_property_object(listener: &Value) -> Option<ObjectId> {
        match listener {
            Value::BuiltinFunction(BuiltinFunction {
                kind: BuiltinFunctionKind::EmitterOnceWrapper,
                bound_object: Some(property_object),
                ..
            }) => Some(ObjectId(*property_object)),
            _ => None,
        }
    }

    pub(super) fn event_once_wrapper_listener_property(&self, listener: &Value) -> Option<Value> {
        let property_object = Self::event_once_wrapper_property_object(listener)?;
        self.heap
            .get(property_object.0 as usize)?
            .properties
            .get("listener")
            .cloned()
    }

    /// Node exposes a once wrapper's truthy `.listener` value through
    /// `listeners()`, while `rawListeners()` returns the wrapper itself.
    /// Deleting the property (or assigning a falsy value) therefore falls back
    /// to the raw callable.
    pub(super) fn exposed_event_listener(&self, listener: &Value) -> Value {
        self.event_once_wrapper_listener_property(listener)
            .as_ref()
            .filter(|value| value.is_truthy())
            .cloned()
            .unwrap_or_else(|| listener.clone())
    }

    pub(super) fn exposed_event_listener_in_array(&self, listener: &Value) -> Value {
        self.event_once_wrapper_listener_property(listener)
            .as_ref()
            .filter(|value| value.is_callable())
            .cloned()
            .unwrap_or_else(|| listener.clone())
    }

    pub(super) fn event_listener_matches(
        &self,
        record: &EventListenerRecord,
        listener: &Value,
    ) -> bool {
        Self::strict_eq_values(&record.listener, listener)
            || self
                .event_once_wrapper_listener_property(&record.listener)
                .is_some_and(|original| Self::strict_eq_values(&original, listener))
    }

    /// Node's scalar fast path reports a lone once wrapper's `.listener`
    /// through the `removeListener` meta-event. Its array path instead reports
    /// the exact argument used for removal, which is the raw wrapper during
    /// automatic/direct once invocation and the original for an explicit
    /// `removeListener(type, original)` call.
    pub(super) fn event_remove_listener_meta_value(
        &self,
        target_id: ObjectId,
        event: &RuntimePropertyKey,
        removal_argument: &Value,
    ) -> Value {
        let records = self
            .event_listeners
            .get(&target_id)
            .and_then(|by_event| by_event.get(event));
        if let Some([record]) = records.map(Vec::as_slice) {
            self.exposed_event_listener(&record.listener)
        } else {
            removal_argument.clone()
        }
    }

    /// Undo the exact insertion performed immediately before a failed
    /// Readable activation. No guest callback runs between insertion and this
    /// rollback, so the inserted record is still at its known edge.
    pub(super) fn rollback_inserted_event_listener(
        &mut self,
        target_id: ObjectId,
        event: impl Into<RuntimePropertyKey>,
        prepend: bool,
    ) {
        let event = event.into();
        let (removed, event_empty) = {
            let Some(listeners) = self
                .event_listeners
                .get_mut(&target_id)
                .and_then(|by_event| by_event.get_mut(&event))
            else {
                return;
            };
            let removed = if prepend {
                (!listeners.is_empty()).then(|| listeners.remove(0))
            } else {
                listeners.pop()
            };
            (removed, listeners.is_empty())
        };
        if event_empty {
            if let Some(by_event) = self.event_listeners.get_mut(&target_id) {
                by_event.remove(&event);
            }
        }
        if self
            .event_listeners
            .get(&target_id)
            .is_some_and(BTreeMap::is_empty)
        {
            self.event_listeners.remove(&target_id);
        }
        if let Some(removed) = removed {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(Self::estimate_event_listener_record_bytes(&event, &removed));
        }
    }

    /// Snapshot all records for one event. Snapshotting before dispatch gives
    /// Node's rule that listeners added or removed during an `emit` affect only
    /// later emits, while `once` records are removed before their callback runs.
    pub(super) fn event_listener_records_for(
        &self,
        target_id: ObjectId,
        event: impl Into<RuntimePropertyKey>,
    ) -> Vec<EventListenerRecord> {
        let event = event.into();
        self.event_listeners
            .get(&target_id)
            .and_then(|by_event| by_event.get(&event))
            .cloned()
            .unwrap_or_default()
    }

    pub(super) fn is_internal_readable_pipe_listener(value: &Value) -> bool {
        matches!(
            value,
            Value::BuiltinFunction(BuiltinFunction {
                kind: BuiltinFunctionKind::StreamReadablePipeData
                    | BuiltinFunctionKind::StreamReadablePipeEnd
                    | BuiltinFunctionKind::StreamPipelineFinish
                    | BuiltinFunctionKind::StreamPipelineError,
                ..
            })
        )
    }

    pub(super) fn remove_stream_pipeline_listener_records(
        &mut self,
        token: u32,
        stages: &[ObjectId],
    ) {
        for target in stages {
            for event in ["error", "close"] {
                let listener = Value::BuiltinFunction(BuiltinFunction::stream_pipeline_listener(
                    if event == "error" {
                        BuiltinFunctionKind::StreamPipelineError
                    } else {
                        BuiltinFunctionKind::StreamPipelineFinish
                    },
                    token,
                    *target,
                ));
                while self
                    .remove_event_listener(*target, event, &listener)
                    .is_some()
                {}
            }
        }
    }

    /// Internal pipe callbacks share the ordinary dispatch table, but they are
    /// capabilities rather than guest-observable EventEmitter registrations.
    /// Hiding them prevents `listeners()` from handing guest code a clonable
    /// authenticated token that could be registered a second time.
    pub(super) fn guest_event_listener_records_for(
        &self,
        target_id: ObjectId,
        event: impl Into<RuntimePropertyKey>,
    ) -> Vec<EventListenerRecord> {
        self.event_listener_records_for(target_id, event)
            .into_iter()
            .filter(|record| !Self::is_internal_readable_pipe_listener(&record.listener))
            .collect()
    }

    pub(super) fn matching_readable_pipe_listener_count(
        &self,
        target_id: ObjectId,
        event: &str,
        kind: BuiltinFunctionKind,
        destination: ObjectId,
        token: u32,
    ) -> usize {
        let event = RuntimePropertyKey::from(event);
        self.event_listeners
            .get(&target_id)
            .and_then(|by_event| by_event.get(&event))
            .map(|records| {
                records
                    .iter()
                    .filter(|record| {
                        Self::is_readable_pipe_listener_for(
                            &record.listener,
                            kind,
                            destination,
                            token,
                        )
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// bd-3894s slice (2d): the closure ids registered for `event` on `target_id`,
    /// cloned so the caller can invoke them without holding a borrow on
    /// `event_listeners`. Empty when no listener was registered.
    #[cfg(test)]
    pub(super) fn event_listeners_for(&self, target_id: ObjectId, event: &str) -> Vec<u32> {
        self.event_listener_records_for(target_id, event)
            .into_iter()
            .filter_map(|record| match record.listener {
                Value::Closure(closure_id) => Some(closure_id),
                _ => None,
            })
            .collect()
    }

    /// Remove the most recently registered occurrence of `listener`, matching
    /// Node's duplicate-listener semantics. Empty event/object buckets are
    /// pruned so `eventNames()` reports only live events.
    pub(super) fn remove_event_listener(
        &mut self,
        target_id: ObjectId,
        event: impl Into<RuntimePropertyKey>,
        listener: &Value,
    ) -> Option<EventListenerRecord> {
        let event = event.into();
        let index = self
            .event_listeners
            .get(&target_id)?
            .get(&event)?
            .iter()
            .rposition(|record| self.event_listener_matches(record, listener))?;
        let (removed, event_empty) = {
            let listeners = self.event_listeners.get_mut(&target_id)?.get_mut(&event)?;
            let removed = listeners.remove(index);
            (removed, listeners.is_empty())
        };
        if event_empty {
            if let Some(by_event) = self.event_listeners.get_mut(&target_id) {
                by_event.remove(&event);
            }
        }
        if self
            .event_listeners
            .get(&target_id)
            .is_some_and(BTreeMap::is_empty)
        {
            self.event_listeners.remove(&target_id);
        }
        self.release_event_listener_memory(&event, &removed);
        Some(removed)
    }

    /// Remove every listener registered for `event`, emitting one
    /// `removeListener` meta-event per guest listener in Node's LIFO order
    /// (bd-asw4m.6). Internal pipe listeners are removed silently to preserve
    /// internal-listener hiding. Iterating an entry-time snapshot bounds
    /// reentrancy from meta handlers that re-register listeners, and a throwing
    /// meta handler propagates with the already-removed listeners left removed.
    /// `event_remove_listener_meta_value` supplies Node's scalar/array
    /// once-wrapper identity against the live bucket at each removal.
    pub(super) fn remove_all_listeners_for_event_with_meta(
        &mut self,
        module: &Ir3Module,
        target_id: ObjectId,
        event: &RuntimePropertyKey,
        meta_label: Label,
    ) -> Result<(), InterpreterError> {
        let snapshot = self.event_listener_records_for(target_id, event);
        for record in snapshot.into_iter().rev() {
            let removal_argument = record.listener.clone();
            let meta = self.event_remove_listener_meta_value(target_id, event, &removal_argument);
            let Some(removed) = self.remove_event_listener(target_id, event, &removal_argument)
            else {
                continue;
            };
            if Self::is_internal_readable_pipe_listener(&removed.listener) {
                self.detach_current_readable_pipe(target_id);
                continue;
            }
            self.emit_event_listener_records(
                module,
                target_id,
                "removeListener",
                vec![event.value(), meta],
                meta_label.clone(),
            )?;
        }
        Ok(())
    }

    pub(super) fn is_readable_pipe_listener_for(
        value: &Value,
        kind: BuiltinFunctionKind,
        destination: ObjectId,
        token: u32,
    ) -> bool {
        matches!(
            value,
            Value::BuiltinFunction(BuiltinFunction {
                kind: actual_kind,
                iterator_handle: Some(actual_token),
                bound_object: Some(actual_destination),
                ..
            }) if *actual_kind == kind
                && *actual_token == token
                && *actual_destination == destination.0
        )
    }

    /// Teardown for one authenticated internal pipe callback.
    /// `readable_pipe` reserves the exact upper bound for postvalidation plus
    /// both eventual listener scans before exposing the link to guest code.
    pub(super) fn remove_readable_pipe_listener_records(
        &mut self,
        target_id: ObjectId,
        event: &str,
        kind: BuiltinFunctionKind,
        destination: ObjectId,
        token: u32,
    ) -> usize {
        let event = RuntimePropertyKey::from(event);
        let (removed_count, released_bytes, event_empty) = {
            let Some(listeners) = self
                .event_listeners
                .get_mut(&target_id)
                .and_then(|by_event| by_event.get_mut(&event))
            else {
                return 0;
            };
            let mut removed_count = 0usize;
            let mut released_bytes = 0u64;
            listeners.retain(|record| {
                if Self::is_readable_pipe_listener_for(&record.listener, kind, destination, token) {
                    removed_count = removed_count.saturating_add(1);
                    released_bytes = released_bytes
                        .saturating_add(Self::estimate_event_listener_record_bytes(&event, record));
                    false
                } else {
                    true
                }
            });
            (removed_count, released_bytes, listeners.is_empty())
        };
        if event_empty {
            if let Some(by_event) = self.event_listeners.get_mut(&target_id) {
                by_event.remove(&event);
            }
        }
        if self
            .event_listeners
            .get(&target_id)
            .is_some_and(BTreeMap::is_empty)
        {
            self.event_listeners.remove(&target_id);
        }
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
        removed_count
    }

    /// Remove one specific `once` record from a pre-emit snapshot without
    /// consuming a same-listener persistent registration.
    pub(super) fn remove_once_event_listener(
        &mut self,
        target_id: ObjectId,
        event: impl Into<RuntimePropertyKey>,
        listener: &Value,
    ) -> Option<EventListenerRecord> {
        let event = event.into();
        let (removed, event_empty) = {
            let listeners = self.event_listeners.get_mut(&target_id)?.get_mut(&event)?;
            let index = listeners.iter().position(|record| {
                record.once && Self::strict_eq_values(&record.listener, listener)
            })?;
            let removed = listeners.remove(index);
            (removed, listeners.is_empty())
        };
        if event_empty {
            if let Some(by_event) = self.event_listeners.get_mut(&target_id) {
                by_event.remove(&event);
            }
        }
        if self
            .event_listeners
            .get(&target_id)
            .is_some_and(BTreeMap::is_empty)
        {
            self.event_listeners.remove(&target_id);
        }
        self.release_event_listener_memory(&event, &removed);
        Some(removed)
    }

    /// Remove one event bucket, or every bucket for an emitter, and release
    /// the same conservative memory charge applied during registration.
    pub(super) fn clear_event_listeners(
        &mut self,
        target_id: ObjectId,
        event: Option<&RuntimePropertyKey>,
    ) {
        let released_bytes = match (self.event_listeners.get(&target_id), event) {
            (Some(by_event), Some(event)) => by_event.get(event).map_or(0, |records| {
                records
                    .iter()
                    .map(|record| Self::estimate_event_listener_record_bytes(event, record))
                    .sum()
            }),
            (Some(by_event), None) => by_event
                .iter()
                .flat_map(|(event, records)| {
                    records.iter().map(move |record| {
                        Self::estimate_event_listener_record_bytes(event, record)
                    })
                })
                .sum(),
            (None, _) => 0,
        };

        if let Some(event) = event {
            if let Some(by_event) = self.event_listeners.get_mut(&target_id) {
                by_event.remove(event);
            }
            if self
                .event_listeners
                .get(&target_id)
                .is_some_and(BTreeMap::is_empty)
            {
                self.event_listeners.remove(&target_id);
            }
        } else {
            self.event_listeners.remove(&target_id);
        }
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn clear_event_promise_waiters_for_target(&mut self, target_id: ObjectId) {
        let released_bytes = self
            .event_promise_waiters
            .remove(&target_id)
            .map(|by_event| {
                by_event
                    .iter()
                    .flat_map(|(event, records)| {
                        records.iter().map(move |record| {
                            Self::estimate_event_promise_waiter_record_bytes(
                                event,
                                &record.registration_label,
                            )
                        })
                    })
                    .sum()
            })
            .unwrap_or(0);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn clear_residual_event_state(&mut self) -> Result<(), InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let released_bytes = self
            .event_listeners_memory_bytes()
            .saturating_add(self.event_promise_waiters_memory_bytes())
            .saturating_add(self.pending_io_callbacks_memory_bytes())
            .saturating_add(self.pending_fs_promise_reads_memory_bytes())
            .saturating_add(self.pending_dynamic_imports_memory_bytes())
            .saturating_add(self.deferred_callback_in_flight_bytes)
            .saturating_add(self.completed_child_processes_memory_bytes())
            .saturating_add(self.child_process_streams_memory_bytes())
            .saturating_add(self.child_process_handles_memory_bytes())
            .saturating_add(self.pending_child_process_tasks_memory_bytes())
            .saturating_add(self.child_process_task_in_flight_bytes);
        let pending_tasks = std::mem::take(&mut self.pending_child_process_tasks);
        let mut cleanup_error = None;
        for (registration, task) in pending_tasks {
            self.event_loop.cancel_registration(registration);
            if let Err(error) = self.cleanup_process_handle(&task.handle) {
                cleanup_error.get_or_insert(error);
            }
        }
        for registration in self.pending_io_callbacks.keys().copied() {
            self.event_loop.cancel_registration(registration);
        }
        self.pending_io_callbacks.clear();
        for registration in self.pending_fs_promise_reads.keys().copied() {
            self.event_loop.cancel_registration(registration);
        }
        self.pending_fs_promise_reads.clear();
        for registration in self.pending_dynamic_imports.keys().copied() {
            self.event_loop.cancel_registration(registration);
        }
        self.pending_dynamic_imports.clear();
        self.deferred_callback_in_flight_bytes = 0;
        let released_promise_bytes =
            previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
        self.event_listeners.clear();
        self.event_promise_waiters.clear();
        self.next_event_promise_waiter_id = 0;
        self.completed_child_processes.clear();
        self.child_process_streams.clear();
        self.child_process_handles.clear();
        self.child_process_task_in_flight_bytes = 0;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(released_bytes.saturating_add(released_promise_bytes));
        cleanup_error.map_or(Ok(()), Err)
    }

    pub(super) fn clear_event_once_wrapper_state(&mut self) {
        let released_bytes = self.event_once_wrappers_memory_bytes();
        self.event_once_wrappers.clear();
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn clear_object_mutation_labels(&mut self) {
        let released_bytes = self.object_mutation_labels_memory_bytes();
        self.object_mutation_labels.clear();
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn clear_url_execution_state(&mut self) {
        let released_bytes = self
            .url_objects_memory_bytes()
            .saturating_add(self.url_search_params_memory_bytes());
        self.url_objects.clear();
        self.url_search_params.clear();
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn clear_cluster_execution_state(&mut self) {
        let released_bytes = self.cluster_facades_memory_bytes();
        self.cluster_facades.clear();
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn clear_crypto_execution_state(&mut self) {
        let released_bytes = self.crypto_objects_memory_bytes();
        self.crypto_objects.clear();
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
    }

    pub(super) fn clear_stream_pipeline_execution_state(&mut self) -> Result<(), InterpreterError> {
        let tokens: Vec<u32> = self.stream_pipelines.keys().copied().collect();
        for token in tokens {
            self.abandon_stream_pipeline(token)?;
        }
        Ok(())
    }

    /// Side-table state is execution-local even when the interpreter instance
    /// is reused. Clear it before restored heap ObjectIds can alias a prior
    /// Writable, including listener and static `events.once` links keyed by
    /// the same ids.
    pub(super) fn clear_writable_execution_state(&mut self) {
        while let Some(object_id) = self.writable_streams.keys().next().copied() {
            if let Some(state) = self.writable_streams.remove(&object_id) {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(Self::estimate_writable_state_bytes(&state));
            }
            self.clear_event_listeners(object_id, None);
            self.clear_event_promise_waiters_for_target(object_id);
        }
        while let Some(object_id) = self.writable_terminal_states.keys().next().copied() {
            if let Some(state) = self.writable_terminal_states.remove(&object_id) {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(Self::estimate_writable_terminal_state_bytes(&state));
            }
            self.clear_event_listeners(object_id, None);
            self.clear_event_promise_waiters_for_target(object_id);
        }
        self.pending_writable_terminal_ticks = 0;
        self.next_writable_tick_sequence = 0;
    }

    /// Readable side-table state is execution-local for the same reason as
    /// Writable state: restoring a seeded heap can reuse an ObjectId. Cancel
    /// every engine-owned pump before dropping its side-table owner, then
    /// release the exact resident state/reservation charges and shared event
    /// records keyed by those ids.
    pub(super) fn clear_readable_execution_state(&mut self) {
        self.active_readable_listener_target = None;
        self.clear_readable_pipe_links();

        let registrations: Vec<u64> = self.pending_readable_from_pumps.keys().copied().collect();
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        for registration in registrations {
            self.event_loop.cancel_registration(registration);
        }
        let released_promise_bytes =
            previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
        let retained_bytes = self
            .readable_from_streams_memory_bytes()
            .saturating_add(self.readable_terminal_states_memory_bytes())
            .saturating_add(self.pending_readable_pumps_memory_bytes())
            .saturating_add(self.readable_pump_reservations_memory_bytes());
        let targets: BTreeSet<ObjectId> = self
            .readable_from_streams
            .keys()
            .chain(self.readable_terminal_states.keys())
            .copied()
            .collect();

        self.readable_from_streams.clear();
        self.readable_terminal_states.clear();
        self.pending_readable_from_pumps.clear();
        self.readable_pump_reservations.clear();
        for target in targets {
            self.clear_event_listeners(target, None);
            self.clear_event_promise_waiters_for_target(target);
        }
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(retained_bytes)
            .saturating_sub(released_promise_bytes);
    }

    pub(super) fn event_name_arg(
        &self,
        args: RegRange,
        index: u32,
    ) -> Result<Option<RuntimePropertyKey>, InterpreterError> {
        Ok(match self.builtin_arg(args, index)? {
            Some(Value::Str(event)) => Some(RuntimePropertyKey::String(event)),
            Some(Value::Symbol(event)) => Some(RuntimePropertyKey::Symbol(event)),
            _ => None,
        })
    }

    /// Invoke a stable `once` wrapper directly (including a wrapper obtained
    /// from `rawListeners()`). Preflight the isolated callback before consuming
    /// the one-shot state; once invocation begins, mark fired and remove the
    /// exact once record before the original callback can re-enter the emitter.
    pub(super) fn invoke_event_once_wrapper(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let property_object =
            builtin
                .bound_object
                .map(ObjectId)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "live EventEmitter once wrapper".to_string(),
                    got: "wrapper without property object".to_string(),
                })?;
        let Some(state) = self.event_once_wrappers.get(&property_object) else {
            return Err(InterpreterError::TypeError {
                expected: "live EventEmitter once wrapper".to_string(),
                got: "stale wrapper state".to_string(),
            });
        };
        if state.fired {
            return Ok(Value::Undefined);
        }
        let target = state.target;
        let event = state.event.clone();
        let original_listener = state.original_listener.clone();

        let mut arguments = Vec::with_capacity(args.count as usize);
        for index in 0..args.count {
            arguments.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
        }
        let argument_label = self.join_arg_range_label(args)?;
        self.preflight_inline_method_call_with_argument_label(
            Some(module),
            &original_listener,
            arguments.len(),
            Some(&argument_label),
        )?;

        let wrapper = Value::BuiltinFunction(builtin.clone());
        let removal_meta_listener = self.event_remove_listener_meta_value(target, &event, &wrapper);
        if self
            .remove_once_event_listener(target, &event, &wrapper)
            .is_some()
        {
            let _ = self.emit_event_listener_records(
                module,
                target,
                "removeListener",
                vec![event.value(), removal_meta_listener],
                argument_label.clone(),
            )?;
        }
        let Some(state) = self.event_once_wrappers.get_mut(&property_object) else {
            return Err(InterpreterError::TypeError {
                expected: "live EventEmitter once wrapper".to_string(),
                got: "wrapper state disappeared during callback preflight".to_string(),
            });
        };
        state.fired = true;

        let invoke = |core: &mut Self| {
            core.invoke_inline_method_call_with_argument_label_preflighted(
                Some(module),
                original_listener,
                Value::Object(target),
                arguments,
                Some(argument_label),
            )
        };
        // An armed network event may enter through a once wrapper's builtin
        // frame. Its original listener gets the same collection boundary;
        // the nested-call guard still rejects unaudited enclosing builtins.
        let (result, result_label) = if self.gc_network_task_active() {
            self.with_gc_nested_request(Vec::new(), invoke)
        } else {
            invoke(self)
        }?;
        self.replace_pending_hostcall_result_label(Some(result_label))?;
        Ok(result)
    }

    /// Invoke the current snapshot for `event` with the emitter as `this`.
    /// Returns whether at least one listener existed. An unhandled `error`
    /// re-throws its first argument as a JS exception, matching EventEmitter's
    /// fail-fast behavior.
    pub(super) fn emit_event_listener_records(
        &mut self,
        module: &Ir3Module,
        target_id: ObjectId,
        event: impl Into<RuntimePropertyKey>,
        arguments: Vec<Value>,
        emission_label: Label,
    ) -> Result<bool, InterpreterError> {
        let event = event.into();
        let records = self.event_listener_records_for(target_id, &event);
        self.emit_event_listener_snapshot(
            module,
            target_id,
            &event,
            arguments,
            emission_label,
            records,
        )
    }

    /// Dispatch a listener snapshot captured at the logical start of an emit.
    /// A leading callback may mutate the live listener table before this helper
    /// runs, but additions/removals do not change the already-started emission.
    pub(super) fn emit_event_listener_snapshot(
        &mut self,
        module: &Ir3Module,
        target_id: ObjectId,
        event: impl Into<RuntimePropertyKey>,
        arguments: Vec<Value>,
        emission_label: Label,
        records: Vec<EventListenerRecord>,
    ) -> Result<bool, InterpreterError> {
        let event = event.into();
        let gc_pins = (self.gc_network_task_active() && self.gc_in_event_loop_phase()).then(|| {
            self.gc_pin_network_values(
                std::iter::once(Value::Object(target_id))
                    .chain(arguments.iter().cloned())
                    .chain(records.iter().map(|record| record.listener.clone())),
            )
        });
        let emission = self.dispatch_event_listener_snapshot(
            module,
            target_id,
            event,
            arguments,
            emission_label,
            records,
        );
        if let Some(checkpoint) = gc_pins {
            self.gc_unpin_network_values(checkpoint);
        }
        emission
    }

    pub(super) fn dispatch_event_listener_snapshot(
        &mut self,
        module: &Ir3Module,
        target_id: ObjectId,
        event: RuntimePropertyKey,
        arguments: Vec<Value>,
        emission_label: Label,
        records: Vec<EventListenerRecord>,
    ) -> Result<bool, InterpreterError> {
        let settled_waiter =
            self.settle_event_promise_waiters(target_id, &event, &arguments, &emission_label)?;
        if records.is_empty() {
            if event.as_str() == Some("error") && !settled_waiter {
                let thrown = if let Some(value) = arguments.first() {
                    value.clone()
                } else {
                    let prototype = self.ensure_builtin_prototype("Error")?;
                    let error_id = self.alloc_object_with_prototype(Some(prototype))?;
                    self.initialize_error_like_object(
                        error_id,
                        "Error",
                        "Unhandled error.".to_string(),
                    )?;
                    Value::Object(error_id)
                };
                self.replace_pending_abrupt_slots(Some((thrown.clone(), emission_label)), None)?;
                return Err(InterpreterError::UncaughtException {
                    value: self.uncaught_exception_description(&thrown),
                });
            }
            return Ok(settled_waiter);
        }

        for record in records {
            if let Some(property_object) =
                Self::event_once_wrapper_property_object(&record.listener)
                && self
                    .event_once_wrappers
                    .get(&property_object)
                    .is_some_and(|state| state.static_once_waiter.is_some())
            {
                // bd-asw4m.4: static `events.once` wrappers are guest-visible
                // introspection carriers only. Their Promise settlement (and
                // listener removal) is driven by `settle_event_promise_waiters`
                // above, so invoking them here would duplicate settlement.
                continue;
            }
            if record.once && Self::event_once_wrapper_property_object(&record.listener).is_none() {
                // Bare one-shot records are engine-internal callbacks (pipe,
                // pipeline, and the current Writable end-callback carrier),
                // not registrations made through EventEmitter.once().
                let _ = self.remove_once_event_listener(target_id, &event, &record.listener);
            }
            let invoke = |core: &mut Self| {
                core.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    record.listener,
                    Value::Object(target_id),
                    arguments.clone(),
                    Some(emission_label.clone()),
                )
            };
            if self.gc_network_task_active() {
                self.with_event_job_gc_request(Vec::new(), invoke)?;
            } else {
                invoke(self)?;
            }
        }
        Ok(true)
    }

    /// Build the finite, pure-compute subset of `Readable.from(iterable,
    /// options)`. This slice deliberately accepts arrays and strings only:
    /// strings are one chunk (Node's `Readable.from(string)` fast path), while
    /// array elements retain identity and order. Other iterable protocols stay
    /// fail-closed until their iterator/async-iterator continuation is modeled.
    pub(super) fn construct_readable_from(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count == 0 {
            return Err(InterpreterError::TypeError {
                expected: "array or string source for Readable.from".to_string(),
                got: "missing argument".to_string(),
            });
        }

        let source = self.read_reg(args.start)?;
        let source_label = self
            .get_register_label(args.start)?
            .clone()
            .join(&match &source {
                Value::Object(object_id) => self.binary_storage_label(*object_id),
                _ => Label::Public,
            });
        match &source {
            Value::Str(_) => {}
            Value::Object(object_id)
                if self
                    .heap
                    .get(object_id.0 as usize)
                    .is_some_and(|object| object.is_array) => {}
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "array or string source for Readable.from".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        }
        let object_mode = if args.count > 1 {
            match self.read_reg(args.start + 1)? {
                Value::Object(options_id) => self
                    .heap
                    .get(options_id.0 as usize)
                    .and_then(|object| object.properties.get("objectMode"))
                    .map(Value::is_truthy)
                    .unwrap_or(true),
                Value::Undefined => true,
                _ => true,
            }
        } else {
            true
        };
        let state = ReadableFromState {
            source,
            push_only: false,
            object_mode,
            high_water_mark: 1,
            read_callback: None,
            buffer: VecDeque::new(),
            buffered_length: 0,
            eof_requested: false,
            data_readable_pending: false,
            eof_readable_pending: false,
            read_callback_active: false,
            decode_utf8: false,
            utf8_pending: Vec::new(),
            destroy_requested: false,
            destroy_error: None,
            next_index: 0,
            phase: ReadableFromPumpPhase::Data,
            flowing: false,
            paused: false,
            nonflowing_read_consumed: false,
            lifecycle_label: source_label,
            to_array_waiter: None,
        };
        let object_properties = Self::readable_object_properties(object_mode, 1);
        self.allocate_readable_with_state(state, &object_properties, true)
    }

    pub(super) fn stream_constructor_options(
        &self,
        args: RegRange,
        byte_mode_default: i64,
    ) -> Result<(bool, i64, Label), InterpreterError> {
        if args.count == 0 || matches!(self.read_reg(args.start)?, Value::Undefined | Value::Null) {
            return Ok((false, byte_mode_default, Label::Public));
        }
        let options = self.read_reg(args.start)?;
        let Value::Object(options_id) = options else {
            return Err(InterpreterError::TypeError {
                expected: "stream constructor options object".to_string(),
                got: options.type_name().to_string(),
            });
        };
        let object = self
            .heap
            .get(options_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: options_id.0 })?;
        let object_mode = object
            .properties
            .get("objectMode")
            .is_some_and(Value::is_truthy);
        let default = if object_mode { 16 } else { byte_mode_default };
        let high_water_mark = match object.properties.get("highWaterMark") {
            None | Some(Value::Undefined) => default,
            Some(Value::Int(value)) if (0..=i64::from(u32::MAX)).contains(value) => *value,
            Some(Value::Float(value))
                if value.inner().is_finite()
                    && value.inner() >= 0.0
                    && value.inner().fract() == 0.0
                    && value.inner() <= f64::from(u32::MAX) =>
            {
                value.inner() as i64
            }
            Some(value) => {
                return Err(InterpreterError::RangeError {
                    message: format!(
                        "stream highWaterMark must be a finite non-negative integer (got {})",
                        value.type_name()
                    ),
                });
            }
        };
        Ok((
            object_mode,
            high_water_mark,
            self.get_register_label(args.start)?.clone(),
        ))
    }

    pub(super) fn construct_stream_readable(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // Bun 1.3.x, the reference runtime for the compatibility corpus, uses
        // 64 KiB as the byte-mode Readable default. Object mode uses 16.
        let (object_mode, high_water_mark, lifecycle_label) =
            self.stream_constructor_options(args, 65_536)?;
        let read_callback = if args.count == 0 {
            None
        } else {
            match self.read_reg(args.start)? {
                Value::Undefined | Value::Null => None,
                Value::Object(options_id) => match self
                    .heap
                    .get(options_id.0 as usize)
                    .and_then(|object| object.properties.get("read"))
                    .cloned()
                {
                    None | Some(Value::Undefined) => None,
                    Some(value) if value.is_callable() => Some(value),
                    Some(value) => {
                        return Err(InterpreterError::TypeError {
                            expected: "callable Readable read option".to_string(),
                            got: value.type_name().to_string(),
                        });
                    }
                },
                _ => None,
            }
        };
        let state = ReadableFromState {
            source: Value::Undefined,
            push_only: true,
            object_mode,
            high_water_mark: usize::try_from(high_water_mark).unwrap_or(usize::MAX),
            read_callback,
            buffer: VecDeque::new(),
            buffered_length: 0,
            eof_requested: false,
            data_readable_pending: false,
            eof_readable_pending: false,
            read_callback_active: false,
            decode_utf8: false,
            utf8_pending: Vec::new(),
            destroy_requested: false,
            destroy_error: None,
            next_index: 0,
            phase: ReadableFromPumpPhase::Data,
            flowing: false,
            paused: false,
            nonflowing_read_consumed: false,
            lifecycle_label,
            to_array_waiter: None,
        };
        let properties = Self::readable_object_properties(object_mode, high_water_mark);
        self.allocate_readable_with_state(state, &properties, false)
    }

    pub(super) fn construct_stream_writable(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (object_mode, high_water_mark, lifecycle_label) =
            self.stream_constructor_options(args, 65_536)?;
        let (write_callback, final_callback) = if args.count == 0 {
            (None, None)
        } else {
            match self.read_reg(args.start)? {
                Value::Undefined | Value::Null => (None, None),
                Value::Object(options_id) => {
                    let object = self
                        .heap
                        .get(options_id.0 as usize)
                        .ok_or(InterpreterError::ObjectNotFound { id: options_id.0 })?;
                    let callback = |name: &str| -> Result<Option<Value>, InterpreterError> {
                        match object.properties.get(name).cloned() {
                            None | Some(Value::Undefined) => Ok(None),
                            Some(value) if value.is_callable() => Ok(Some(value)),
                            Some(value) => Err(InterpreterError::TypeError {
                                expected: format!("callable Writable {name} option"),
                                got: value.type_name().to_string(),
                            }),
                        }
                    };
                    (callback("write")?, callback("final")?)
                }
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "stream constructor options object".to_string(),
                        got: other.type_name().to_string(),
                    });
                }
            }
        };
        let properties = [
            ("__maxListeners", Value::Int(10)),
            ("writable", Value::Bool(true)),
            ("writableEnded", Value::Bool(false)),
            ("writableFinished", Value::Bool(false)),
            ("writableLength", Value::Int(0)),
            ("writableCorked", Value::Int(0)),
            ("writableNeedDrain", Value::Bool(false)),
            ("writableObjectMode", Value::Bool(object_mode)),
            ("writableHighWaterMark", Value::Int(high_water_mark)),
            ("destroyed", Value::Bool(false)),
            ("closed", Value::Bool(false)),
        ];
        let state = WritableState {
            flavor: WritableStreamFlavor::Writable,
            object_mode,
            high_water_mark: usize::try_from(high_water_mark).unwrap_or(usize::MAX),
            write_callback,
            final_callback,
            writes: WritableWriteQueue::default(),
            buffered_length: 0,
            need_drain: false,
            cork_depth: 0,
            end_requested: false,
            destroy_requested: false,
            end_callbacks: LinkedList::new(),
            end_callback_batch_remaining: 0,
            finished_end_callback_batch_remaining: 0,
            final_status: WritableFinalStatus::NotStarted,
            prefinish_emitted: false,
            finished: false,
            terminal_error: None,
            terminal_error_origin: None,
            terminal_error_emitted: false,
            tick_phase: WritableTickPhase::Callbacks,
            tick_sequence: None,
            deferred_final_tick_sequence: None,
            inside_write_invocation: false,
            lifecycle_label,
        };
        let mut projected_object = HeapObject::new();
        for (key, value) in &properties {
            projected_object
                .properties
                .insert((*key).to_string(), value.clone());
        }
        projected_object.brand = Some(Box::new(JsString::from("Writable")));
        let object_bytes = Self::estimate_heap_object_bytes(&projected_object);
        let state_bytes = Self::estimate_writable_state_bytes(&state);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_add(object_bytes)
            .saturating_add(state_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(
                requested_bytes,
                self.heap_object_count_u32().saturating_add(1),
            ));
        }
        self.apply_memory_component_delta(0, state_bytes)?;
        let object_id = match self.alloc_branded_object("Writable", &properties) {
            Ok(object_id) => object_id,
            Err(error) => {
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(state_bytes);
                return Err(error);
            }
        };
        self.writable_streams.insert(object_id, state);
        Ok(Value::Object(object_id))
    }

    /// Allocate one authenticated object that owns both existing stream-state
    /// kernels. The two side-table records and the heap object commit as one
    /// memory transaction so a refused aggregate budget cannot leave a
    /// readable-only or writable-only identity behind (bd-fw7zd.10).
    pub(super) fn construct_stream_passthrough(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count > 0 && !matches!(self.read_reg(args.start)?, Value::Undefined | Value::Null) {
            let lifecycle_label = self.get_register_label(args.start)?;
            // `stream_constructor_options` materializes one owned label and
            // the dual state needs a second owner. Admit that attacker-sized
            // physical peak before either clone exists; the later aggregate
            // transaction accounts both retained copies exactly.
            self.check_temporary_memory_budget(
                Self::estimate_label_bytes(lifecycle_label).saturating_mul(2),
            )?;
        }
        let (object_mode, high_water_mark, lifecycle_label) =
            self.stream_constructor_options(args, 65_536)?;
        let high_water_mark_usize = usize::try_from(high_water_mark).unwrap_or(usize::MAX);
        let readable_state = ReadableFromState {
            source: Value::Undefined,
            push_only: true,
            object_mode,
            high_water_mark: high_water_mark_usize,
            read_callback: None,
            buffer: VecDeque::new(),
            buffered_length: 0,
            eof_requested: false,
            data_readable_pending: false,
            eof_readable_pending: false,
            read_callback_active: false,
            decode_utf8: false,
            utf8_pending: Vec::new(),
            destroy_requested: false,
            destroy_error: None,
            next_index: 0,
            phase: ReadableFromPumpPhase::Data,
            flowing: false,
            paused: false,
            nonflowing_read_consumed: false,
            lifecycle_label: lifecycle_label.clone(),
            to_array_waiter: None,
        };
        let writable_state = WritableState {
            flavor: WritableStreamFlavor::PassThrough,
            object_mode,
            high_water_mark: high_water_mark_usize,
            write_callback: Some(Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamPassThroughWrite,
            ))),
            final_callback: Some(Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamPassThroughFinal,
            ))),
            writes: WritableWriteQueue::default(),
            buffered_length: 0,
            need_drain: false,
            cork_depth: 0,
            end_requested: false,
            destroy_requested: false,
            end_callbacks: LinkedList::new(),
            end_callback_batch_remaining: 0,
            finished_end_callback_batch_remaining: 0,
            final_status: WritableFinalStatus::NotStarted,
            prefinish_emitted: false,
            finished: false,
            terminal_error: None,
            terminal_error_origin: None,
            terminal_error_emitted: false,
            tick_phase: WritableTickPhase::Callbacks,
            tick_sequence: None,
            deferred_final_tick_sequence: None,
            inside_write_invocation: false,
            lifecycle_label,
        };
        let brand = "PassThrough";
        let properties = [
            ("__maxListeners", Value::Int(10)),
            ("readable", Value::Bool(true)),
            ("readableEnded", Value::Bool(false)),
            ("readableFlowing", Value::Null),
            ("readableLength", Value::Int(0)),
            ("readableObjectMode", Value::Bool(object_mode)),
            ("readableHighWaterMark", Value::Int(high_water_mark)),
            ("writable", Value::Bool(true)),
            ("writableEnded", Value::Bool(false)),
            ("writableFinished", Value::Bool(false)),
            ("writableLength", Value::Int(0)),
            ("writableCorked", Value::Int(0)),
            ("writableNeedDrain", Value::Bool(false)),
            ("writableObjectMode", Value::Bool(object_mode)),
            ("writableHighWaterMark", Value::Int(high_water_mark)),
            ("destroyed", Value::Bool(false)),
            ("closed", Value::Bool(false)),
        ];
        let mut projected_object = HeapObject::new();
        for (key, value) in &properties {
            projected_object
                .properties
                .insert((*key).to_string(), value.clone());
        }
        projected_object.brand = Some(Box::new(JsString::from(brand)));
        let readable_bytes = Self::estimate_readable_from_state_bytes(&readable_state);
        let writable_bytes = Self::estimate_writable_state_bytes(&writable_state);
        let object_bytes = Self::estimate_heap_object_bytes(&projected_object);
        // The projected object exists only to make the aggregate admission
        // exact. Release that duplicate property map before the real heap
        // allocation clones the fixed constructor property slice.
        drop(projected_object);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_add(readable_bytes)
            .saturating_add(writable_bytes)
            .saturating_add(object_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(
                requested_bytes,
                self.heap_object_count_u32().saturating_add(1),
            ));
        }

        let previous_total = self.estimated_memory_bytes;
        let previous_heap_len = self.heap.len();
        self.apply_memory_component_delta(0, readable_bytes.saturating_add(writable_bytes))?;
        let object_id = match self.alloc_branded_object(brand, &properties) {
            Ok(object_id) => object_id,
            Err(error) => {
                self.rollback_heap_to_len(previous_heap_len);
                self.estimated_memory_bytes = previous_total;
                return Err(error);
            }
        };
        self.readable_from_streams.insert(object_id, readable_state);
        self.writable_streams.insert(object_id, writable_state);
        Ok(Value::Object(object_id))
    }

    /// Construct one authenticated Transform by composing the existing
    /// Readable and Writable kernels. The guest callbacks remain inside the
    /// Writable state, while `flavor` is the unforgeable authority deciding
    /// which completion-token family may publish readable output.
    pub(super) fn construct_stream_transform(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count == 0 {
            return Err(InterpreterError::TypeError {
                expected: "Transform options with callable transform".to_string(),
                got: "missing options".to_string(),
            });
        }
        let options = self.read_reg(args.start)?;
        let Value::Object(options_id) = options else {
            return Err(InterpreterError::TypeError {
                expected: "Transform options object".to_string(),
                got: options.type_name().to_string(),
            });
        };
        let object = self
            .heap
            .get(options_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: options_id.0 })?;
        let transform_callback = match object.properties.get("transform").cloned() {
            Some(value) if value.is_callable() => value,
            Some(value) => {
                return Err(InterpreterError::TypeError {
                    expected: "callable Transform transform option".to_string(),
                    got: value.type_name().to_string(),
                });
            }
            None => {
                return Err(InterpreterError::TypeError {
                    expected: "callable Transform transform option".to_string(),
                    got: "missing transform".to_string(),
                });
            }
        };
        let final_callback = match object.properties.get("flush").cloned() {
            None | Some(Value::Undefined) => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamTransformFinal,
            )),
            Some(value) if value.is_callable() => value,
            Some(value) => {
                return Err(InterpreterError::TypeError {
                    expected: "callable Transform flush option".to_string(),
                    got: value.type_name().to_string(),
                });
            }
        };
        let lifecycle_label = self.get_register_label(args.start)?;
        self.check_temporary_memory_budget(
            Self::estimate_label_bytes(lifecycle_label).saturating_mul(2),
        )?;
        let (object_mode, high_water_mark, lifecycle_label) =
            self.stream_constructor_options(args, 65_536)?;
        let high_water_mark_usize = usize::try_from(high_water_mark).unwrap_or(usize::MAX);
        let readable_state = ReadableFromState {
            source: Value::Undefined,
            push_only: true,
            object_mode,
            high_water_mark: high_water_mark_usize,
            read_callback: None,
            buffer: VecDeque::new(),
            buffered_length: 0,
            eof_requested: false,
            data_readable_pending: false,
            eof_readable_pending: false,
            read_callback_active: false,
            decode_utf8: false,
            utf8_pending: Vec::new(),
            destroy_requested: false,
            destroy_error: None,
            next_index: 0,
            phase: ReadableFromPumpPhase::Data,
            flowing: false,
            paused: false,
            nonflowing_read_consumed: false,
            lifecycle_label: lifecycle_label.clone(),
            to_array_waiter: None,
        };
        let writable_state = WritableState {
            flavor: WritableStreamFlavor::Transform,
            object_mode,
            high_water_mark: high_water_mark_usize,
            write_callback: Some(transform_callback),
            final_callback: Some(final_callback),
            writes: WritableWriteQueue::default(),
            buffered_length: 0,
            need_drain: false,
            cork_depth: 0,
            end_requested: false,
            destroy_requested: false,
            end_callbacks: LinkedList::new(),
            end_callback_batch_remaining: 0,
            finished_end_callback_batch_remaining: 0,
            final_status: WritableFinalStatus::NotStarted,
            prefinish_emitted: false,
            finished: false,
            terminal_error: None,
            terminal_error_origin: None,
            terminal_error_emitted: false,
            tick_phase: WritableTickPhase::Callbacks,
            tick_sequence: None,
            deferred_final_tick_sequence: None,
            inside_write_invocation: false,
            lifecycle_label,
        };
        let brand = "Transform";
        let properties = [
            ("__maxListeners", Value::Int(10)),
            ("readable", Value::Bool(true)),
            ("readableEnded", Value::Bool(false)),
            ("readableFlowing", Value::Null),
            ("readableLength", Value::Int(0)),
            ("readableObjectMode", Value::Bool(object_mode)),
            ("readableHighWaterMark", Value::Int(high_water_mark)),
            ("writable", Value::Bool(true)),
            ("writableEnded", Value::Bool(false)),
            ("writableFinished", Value::Bool(false)),
            ("writableLength", Value::Int(0)),
            ("writableCorked", Value::Int(0)),
            ("writableNeedDrain", Value::Bool(false)),
            ("writableObjectMode", Value::Bool(object_mode)),
            ("writableHighWaterMark", Value::Int(high_water_mark)),
            ("destroyed", Value::Bool(false)),
            ("closed", Value::Bool(false)),
        ];
        let mut projected_object = HeapObject::new();
        for (key, value) in &properties {
            projected_object
                .properties
                .insert((*key).to_string(), value.clone());
        }
        projected_object.brand = Some(Box::new(JsString::from(brand)));
        let readable_bytes = Self::estimate_readable_from_state_bytes(&readable_state);
        let writable_bytes = Self::estimate_writable_state_bytes(&writable_state);
        let object_bytes = Self::estimate_heap_object_bytes(&projected_object);
        drop(projected_object);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_add(readable_bytes)
            .saturating_add(writable_bytes)
            .saturating_add(object_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(
                requested_bytes,
                self.heap_object_count_u32().saturating_add(1),
            ));
        }
        let previous_total = self.estimated_memory_bytes;
        let previous_heap_len = self.heap.len();
        self.apply_memory_component_delta(0, readable_bytes.saturating_add(writable_bytes))?;
        let object_id = match self.alloc_branded_object(brand, &properties) {
            Ok(object_id) => object_id,
            Err(error) => {
                self.rollback_heap_to_len(previous_heap_len);
                self.estimated_memory_bytes = previous_total;
                return Err(error);
            }
        };
        self.readable_from_streams.insert(object_id, readable_state);
        self.writable_streams.insert(object_id, writable_state);
        Ok(Value::Object(object_id))
    }

    /// Resolve public Writable state from engine-owned storage before ordinary
    /// heap properties. Guest writes, accessors, and deletions may mutate the
    /// compatibility mirrors, but they cannot forge these authoritative reads.
    pub(super) fn writable_state_view_value(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Option<Value> {
        if let Some(state) = self.writable_streams.get(&object_id) {
            // A duplex closes with its readable half: an explicit destroy, or
            // the shared close whose listeners run in the SettleToArray phase
            // (Node reports destroyed and closed as true inside 'close').
            let terminal_close_observable = self.readable_from_streams.get(&object_id).map_or_else(
                || state.destroy_requested || state.tick_phase == WritableTickPhase::Release,
                |readable| {
                    readable.destroy_requested
                        || readable.phase == ReadableFromPumpPhase::SettleToArray
                },
            );
            return match key {
                "writable" => Some(Value::Bool(
                    !state.end_requested && !state.destroy_requested && !state.finished,
                )),
                "writableEnded" => Some(Value::Bool(state.end_requested)),
                "writableFinished" => Some(Value::Bool(state.finished)),
                "writableLength" => Some(Value::Int(
                    i64::try_from(state.buffered_length).unwrap_or(i64::MAX),
                )),
                "writableCorked" => Some(Value::Int(i64::from(state.cork_depth))),
                "writableNeedDrain" => Some(Value::Bool(state.need_drain)),
                "writableObjectMode" => Some(Value::Bool(state.object_mode)),
                "writableHighWaterMark" => Some(Value::Int(
                    i64::try_from(state.high_water_mark).unwrap_or(i64::MAX),
                )),
                "destroyed" | "closed" => Some(Value::Bool(terminal_close_observable)),
                _ => None,
            };
        }

        let state = self.writable_terminal_states.get(&object_id)?;
        let terminal_close_observable =
            self.readable_from_streams
                .get(&object_id)
                .is_none_or(|readable| {
                    readable.destroy_requested
                        || readable.phase == ReadableFromPumpPhase::SettleToArray
                });
        match key {
            "writable" => Some(Value::Bool(false)),
            "writableEnded" => Some(Value::Bool(state.end_requested)),
            "writableFinished" => Some(Value::Bool(state.finished)),
            "writableLength" => Some(Value::Int(
                i64::try_from(state.buffered_length).unwrap_or(i64::MAX),
            )),
            "writableCorked" => Some(Value::Int(i64::from(state.cork_depth))),
            "writableNeedDrain" => Some(Value::Bool(false)),
            "writableObjectMode" => Some(Value::Bool(state.object_mode)),
            "writableHighWaterMark" => Some(Value::Int(
                i64::try_from(state.high_water_mark).unwrap_or(i64::MAX),
            )),
            "destroyed" | "closed" => Some(Value::Bool(terminal_close_observable)),
            _ => None,
        }
    }

    pub(super) fn is_writable_state_view_key(key: &str) -> bool {
        WRITABLE_STATE_VIEW_KEYS.binary_search(&key).is_ok()
    }

    /// Whether an own heap entry takes part in own-key reflection, copying
    /// and JSON. Node/Bun expose a Writable's ten authoritative views as
    /// inherited accessors, and a typed array's `length`, `buffer`,
    /// `byteLength`, `byteOffset` and `BYTES_PER_ELEMENT` are
    /// %TypedArray%.prototype accessors (ES2020 22.2.3), as are an
    /// ArrayBuffer's `byteLength` (24.1.4.1) and a DataView's `buffer`,
    /// `byteLength` and `byteOffset` (24.3.4); the engine keeps those as heap
    /// entries (plus the `__type`/`__typedArrayKind` slots), which [[Get]]
    /// and `in` still read, but they are not own keys.
    pub(super) fn own_property_visible(&self, object_id: ObjectId, key: &str) -> bool {
        let writable_view = (self.writable_streams.contains_key(&object_id)
            || self.writable_terminal_states.contains_key(&object_id))
            && Self::is_writable_state_view_key(key);
        let binary_slot = self
            .heap
            .get(object_id.0 as usize)
            .is_some_and(|object| Self::binary_slot_key(object, key));
        // The internal slots of events, targets and signals (bd-9vouw.170).
        let event_slot = event_target::EVENT_FAMILY_SLOT_KEYS.contains(&key);
        // Iterator helpers' and matchAll iterators' slots: Reflect.ownKeys of
        // `[].values().map(f)` listed ten of them (bd-9vouw.476).
        let iterator_slot = iterator_helpers::ITERATOR_HELPER_SLOT_KEYS.contains(&key)
            || iterator_helpers::REGEXP_STRING_ITERATOR_SLOT_KEYS.contains(&key);
        !(writable_view || binary_slot || event_slot || iterator_slot)
    }

    /// Whether `key` is one of the heap entries through which `object`, a
    /// typed array, DataView or ArrayBuffer, keeps an internal slot or the
    /// value of a prototype accessor (`length`, `byteLength`, ...) rather
    /// than an own property.
    pub(super) fn binary_slot_key(object: &HeapObject, key: &str) -> bool {
        if object.typed_array.is_some() {
            TYPED_ARRAY_SLOT_KEYS.contains(&key)
        } else if object.data_view.is_some() {
            DATA_VIEW_SLOT_KEYS.contains(&key)
        } else {
            object.array_buffer.is_some() && ARRAY_BUFFER_SLOT_KEYS.contains(&key)
        }
    }

    pub(super) fn own_runtime_property_visible(&self, object_id: ObjectId, key: &JsString) -> bool {
        key.as_str()
            .is_none_or(|key| self.own_property_visible(object_id, key))
    }

    /// Enumerable own String properties in the baseline object model. Array
    /// length is an own property, but must not enter JSON/Object.keys-style
    /// enumeration. Reflect.ownKeys continues to use the unfiltered own keys.
    /// ES2020 7.3.23 EnumerableOwnPropertyNames over an ordinary object's
    /// own string-keyed properties (its typed-array or String-wrapper
    /// indices excepted): the key list is taken first, then each key is
    /// checked ([[GetOwnProperty]]) and read ([[Get]]) in turn, so a getter
    /// that deletes a later key or makes it non-enumerable drops it, and a
    /// later value is read after the earlier getters ran. They were all
    /// read up front.
    pub(super) fn enumerable_own_property_entries(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
    ) -> Result<Vec<(JsString, Value)>, InterpreterError> {
        let keys = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
            .properties
            .exact_keys();
        self.join_pending_hostcall_stream_label(object_id)?;
        let mut entries = Vec::with_capacity(keys.len());
        for key in keys {
            if !self.ordinary_own_string_key_is_enumerable(object_id, &key) {
                continue;
            }
            let value = self.proxy_aware_get_runtime_property(
                module,
                object_id,
                &RuntimePropertyKey::String(key.clone()),
                Value::Object(object_id),
                0,
            )?;
            entries.push((key, value));
        }
        Ok(entries)
    }

    pub(super) fn ordinary_own_string_key_is_enumerable(
        &self,
        object_id: ObjectId,
        key: &JsString,
    ) -> bool {
        if let Some(view) = self
            .heap
            .get(object_id.0 as usize)
            .and_then(|object| object.typed_array.as_deref())
            && key
                .as_str()
                .and_then(Self::typed_array_integer_index_key)
                .is_some_and(|index| index < view.length)
        {
            return true;
        }
        self.heap.get(object_id.0 as usize).is_some_and(|object| {
            object.properties.contains_exact_key(key)
                && object
                    .own_property_attributes(&RuntimePropertyKey::String(key.clone()))
                    .enumerable
                && self.own_runtime_property_visible(object_id, key)
        })
    }

    pub(super) fn join_pending_hostcall_stream_label(
        &mut self,
        object_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        let stream_label = self.stream_state_label(object_id);
        let joined = self
            .pending_hostcall_result_label
            .clone()
            .unwrap_or(Label::Public)
            .join(&stream_label);
        self.replace_pending_hostcall_result_label(Some(joined))
    }

    pub(super) fn writable_receiver_id(
        &self,
        receiver: Value,
    ) -> Result<ObjectId, InterpreterError> {
        let Value::Object(object_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: "Writable receiver".to_string(),
                got: receiver.type_name().to_string(),
            });
        };
        if !self.writable_streams.contains_key(&object_id)
            && !self.writable_terminal_states.contains_key(&object_id)
        {
            return Err(InterpreterError::TypeError {
                expected: "Writable receiver".to_string(),
                got: "non-Writable object".to_string(),
            });
        }
        Ok(object_id)
    }

    /// Atomically append one live write record, optionally making the same
    /// transaction the terminal `end(chunk, callback)` operation. Every
    /// fallible validation and the complete resident-memory delta is checked
    /// before either linked FIFO is mutated.
    pub(super) fn append_writable_write(
        &mut self,
        object_id: ObjectId,
        value: Value,
        label: Label,
        write_callback: Option<WritableCallbackRecord>,
        end_callback: Option<WritableCallbackRecord>,
        request_end: bool,
    ) -> Result<Option<bool>, InterpreterError> {
        let Some(state) = self.writable_streams.get(&object_id) else {
            return Ok(None);
        };
        if state.end_requested || state.destroy_requested {
            return Err(InterpreterError::TypeError {
                expected: "live Writable that has not ended".to_string(),
                got: if state.destroy_requested {
                    if request_end {
                        "end after destroy".to_string()
                    } else {
                        "write after destroy".to_string()
                    }
                } else if request_end {
                    "end after end".to_string()
                } else {
                    "write after end".to_string()
                },
            });
        }
        state
            .writes
            .len()
            .checked_add(1)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "Writable write FIFO length overflows host address space".to_string(),
            })?;
        if end_callback.is_some() {
            state.end_callbacks.len().checked_add(1).ok_or_else(|| {
                InterpreterError::RangeError {
                    message: "Writable terminal callback FIFO length overflows host address space"
                        .to_string(),
                }
            })?;
        }
        let units = self.writable_chunk_units(state.object_mode, &value)?;
        let next_length = state.buffered_length.checked_add(units).ok_or_else(|| {
            InterpreterError::RangeError {
                message: "Writable buffered length overflows host address space".to_string(),
            }
        })?;
        let previous_bytes = Self::estimate_writable_state_bytes(state);
        let previous_label_bytes = Self::estimate_label_bytes(&state.lifecycle_label);
        let label_dominates = label > state.lifecycle_label;
        let mut label = Some(label);
        let next_label_bytes = if label_dominates {
            Self::estimate_label_bytes(
                label
                    .as_ref()
                    .expect("candidate Writable label remained available"),
            )
        } else {
            previous_label_bytes
        };
        let record_bytes = MEMORY_ESTIMATE_WRITABLE_WRITE_NODE_BYTES
            .saturating_add(Self::estimate_writable_value_bytes(&value))
            .saturating_add(next_label_bytes)
            .saturating_add(
                write_callback
                    .as_ref()
                    .map(Self::estimate_writable_callback_bytes)
                    .unwrap_or(0),
            );
        let end_callback_bytes = end_callback.as_ref().map_or(0, |callback| {
            MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES
                .saturating_add(Self::estimate_writable_callback_bytes(callback))
        });
        let next_bytes = previous_bytes
            .saturating_sub(previous_label_bytes)
            .saturating_add(next_label_bytes)
            .saturating_add(record_bytes)
            .saturating_add(end_callback_bytes);
        if !label_dominates {
            // The lower incoming aggregate is not retained. Drop it before the
            // retained lifecycle label is cloned into the write record so the
            // strict physical peak contains only the allocation charged by
            // `record_bytes`.
            drop(label.take());
        }
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;

        let state = self
            .writable_streams
            .get_mut(&object_id)
            .expect("Writable state survived atomic write preflight");
        if label_dominates {
            state.lifecycle_label = label
                .take()
                .expect("dominant Writable label remained owned through preflight");
        }
        debug_assert!(label.is_none());
        let record = WritableWriteRecord {
            value,
            label: state.lifecycle_label.clone(),
            units,
            callback: write_callback,
            status: WritableWriteStatus::Pending,
            completion_failed: false,
        };
        state.writes.push_back(record);
        if let Some(callback) = end_callback {
            state.end_callbacks.push_back(WritableEndCallbackRecord {
                callback,
                registered_after_end: false,
            });
        }
        state.buffered_length = next_length;
        if next_length >= state.high_water_mark {
            state.need_drain = true;
        }
        if request_end {
            state.cork_depth = 0;
            state.end_requested = true;
        }
        debug_assert_eq!(Self::estimate_writable_state_bytes(state), next_bytes);
        let below_high_water_mark = next_length < state.high_water_mark;
        self.mirror_writable_length(object_id, next_length);
        self.mirror_writable_bool(object_id, "writableNeedDrain", !below_high_water_mark);
        Ok(Some(below_high_water_mark))
    }

    /// Append one callback-only `end(callback)` record without cloning the
    /// whole Writable state. The node-counted FIFO has no spare or rounded
    /// capacity: one successful append adds exactly one charged node plus the
    /// callback payload, while a refusal leaves state and accounting unchanged.
    pub(super) fn append_writable_end_callback(
        &mut self,
        object_id: ObjectId,
        callback: WritableCallbackRecord,
        registered_after_end: bool,
        args_label: Label,
    ) -> Result<(), InterpreterError> {
        let state = self.writable_streams.get(&object_id).ok_or_else(|| {
            InterpreterError::InternalError {
                details: "Writable terminal callback append lost its state".to_string(),
            }
        })?;
        let previous_state_bytes = Self::estimate_writable_state_bytes(state);
        let previous_label_bytes = Self::estimate_label_bytes(&state.lifecycle_label);
        let label_dominates = args_label > state.lifecycle_label;
        let mut args_label = Some(args_label);
        let next_label_bytes = if label_dominates {
            Self::estimate_label_bytes(
                args_label
                    .as_ref()
                    .expect("candidate Writable end label remained available"),
            )
        } else {
            previous_label_bytes
        };
        let callback_bytes = Self::estimate_writable_callback_bytes(&callback);
        state
            .end_callbacks
            .len()
            .checked_add(1)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "Writable terminal callback FIFO length overflows host address space"
                    .to_string(),
            })?;
        let next_state_bytes = previous_state_bytes
            .saturating_sub(previous_label_bytes)
            .saturating_add(next_label_bytes)
            .saturating_add(callback_bytes)
            .saturating_add(MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES);
        if !label_dominates {
            // The caller aggregate is a checked temporary, not retained state.
            // Release it before committing the larger callback FIFO component.
            drop(args_label.take());
        }
        self.apply_memory_component_delta(previous_state_bytes, next_state_bytes)?;

        let state = self
            .writable_streams
            .get_mut(&object_id)
            .expect("Writable state was retained through terminal callback preflight");
        if label_dominates {
            state.lifecycle_label = args_label
                .take()
                .expect("dominant Writable end label remained owned through preflight");
        }
        debug_assert!(args_label.is_none());
        state.end_callbacks.push_back(WritableEndCallbackRecord {
            callback,
            registered_after_end,
        });
        if !state.destroy_requested {
            state.cork_depth = 0;
            state.end_requested = true;
        }
        debug_assert_eq!(Self::estimate_writable_state_bytes(state), next_state_bytes);
        Ok(())
    }

    pub(super) fn mirror_writable_length(&mut self, object_id: ObjectId, length: usize) {
        self.mirror_writable_usize(object_id, "writableLength", length);
    }

    pub(super) fn mirror_writable_cork_depth(&mut self, object_id: ObjectId, depth: u32) {
        self.mirror_writable_usize(
            object_id,
            "writableCorked",
            usize::try_from(depth).unwrap_or(usize::MAX),
        );
    }

    pub(super) fn mirror_writable_usize(
        &mut self,
        object_id: ObjectId,
        key: &'static str,
        value: usize,
    ) {
        let value = Value::Int(i64::try_from(value).unwrap_or(i64::MAX));
        let previous_bytes = self
            .heap
            .get(object_id.0 as usize)
            .and_then(|object| object.properties.get(key))
            .map(|previous| Self::estimate_property_entry_bytes(key, previous));
        self.mutate_heap(|heap| {
            if let Some(slot) = heap
                .get_mut(object_id.0 as usize)
                .and_then(|object| object.properties.get_mut(key))
            {
                *slot = value.clone();
            }
        });
        if let Some(previous_bytes) = previous_bytes {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_bytes)
                .saturating_add(Self::estimate_property_entry_bytes(key, &value));
        }
    }

    pub(super) fn mirror_writable_bool(
        &mut self,
        object_id: ObjectId,
        key: &'static str,
        value: bool,
    ) {
        self.mirror_readable_bool(object_id, key, value);
    }

    pub(super) fn schedule_writable_tick(
        &mut self,
        object_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        if self
            .writable_streams
            .get(&object_id)
            .is_none_or(|state| state.tick_sequence.is_some())
        {
            return Ok(());
        }
        self.preflight_writable_tick(object_id)?;
        let sequence = self.next_writable_tick_sequence;
        self.next_writable_tick_sequence = sequence + 1;
        if let Some(state) = self.writable_streams.get_mut(&object_id) {
            state.tick_sequence = Some(sequence);
        }
        Ok(())
    }

    pub(super) fn preflight_writable_tick(
        &self,
        object_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        if self
            .writable_streams
            .get(&object_id)
            .is_some_and(|state| state.tick_sequence.is_none())
        {
            self.next_writable_tick_sequence
                .checked_add(1)
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "Writable tick sequence space exhausted".to_string(),
                })?;
        }
        Ok(())
    }

    pub(super) fn schedule_writable_terminal_tick(
        &mut self,
        object_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        if self
            .writable_terminal_states
            .get(&object_id)
            .is_none_or(|state| state.tick_sequence.is_some())
        {
            return Ok(());
        }
        let sequence = self.next_writable_tick_sequence;
        let next_sequence =
            sequence
                .checked_add(1)
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "Writable tick sequence space exhausted".to_string(),
                })?;
        let next_pending = self
            .pending_writable_terminal_ticks
            .checked_add(1)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "pending terminal Writable tick count overflowed".to_string(),
            })?;
        self.next_writable_tick_sequence = next_sequence;
        self.pending_writable_terminal_ticks = next_pending;
        if let Some(state) = self.writable_terminal_states.get_mut(&object_id) {
            state.tick_sequence = Some(sequence);
        }
        Ok(())
    }

    pub(super) fn next_scheduled_writable_tick(
        &mut self,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        // Selection currently scans the engine-owned state table. Charge the
        // exact number of entries inspected (and one step for the empty scan)
        // to the shared instruction budget so many short-lived streams cannot
        // turn deterministic lifecycle work into unbounded O(N^2) host CPU.
        let terminal_scan_len = if self.pending_writable_terminal_ticks == 0 {
            0
        } else {
            self.writable_terminal_states.len()
        };
        let scan_cost = u64::try_from(
            self.writable_streams
                .len()
                .saturating_add(terminal_scan_len)
                .max(1),
        )
        .unwrap_or(u64::MAX);
        let next_executed = self.instructions_executed.saturating_add(scan_cost);
        if next_executed > self.config.instruction_budget {
            return Err(InterpreterError::BudgetExhausted {
                executed: self.instructions_executed,
                budget: self.config.instruction_budget,
            });
        }
        self.instructions_executed = next_executed;
        let active = self
            .writable_streams
            .iter()
            .filter_map(|(id, state)| state.tick_sequence.map(|sequence| (sequence, *id)))
            .min_by_key(|(sequence, _)| *sequence);
        let terminal = (self.pending_writable_terminal_ticks > 0)
            .then(|| {
                self.writable_terminal_states
                    .iter()
                    .filter_map(|(id, state)| state.tick_sequence.map(|sequence| (sequence, *id)))
                    .min_by_key(|(sequence, _)| *sequence)
            })
            .flatten();
        Ok(active
            .into_iter()
            .chain(terminal)
            .min_by_key(|(sequence, _)| *sequence)
            .map(|(_, object_id)| object_id))
    }

    pub(super) fn allocate_writable_completion_token(&mut self) -> Result<u32, InterpreterError> {
        self.preflight_writable_completion_tokens(1)?;
        let token = self.next_writable_completion_token;
        self.next_writable_completion_token = token + 1;
        Ok(token)
    }

    /// Check that the current completion-token frontier can advance by every
    /// token this public Writable transaction may publish before the caller
    /// retains chunks, callbacks, or terminal state.
    /// `u32::MAX` is deliberately never issued: advancing past it would reuse a
    /// process-lifetime authentication nonce after wraparound.
    pub(super) fn preflight_writable_completion_tokens(
        &self,
        required: u32,
    ) -> Result<(), InterpreterError> {
        self.next_writable_completion_token
            .checked_add(required)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "Writable completion token space exhausted".to_string(),
            })?;
        Ok(())
    }

    /// Admit a public transaction against every token already promised to a
    /// queued write or final callback. Tokens are assigned only when the
    /// callback becomes active, so a raw frontier check would let multiple
    /// corked streams overbook the final nonce.
    pub(super) fn preflight_writable_completion_reservations(
        &self,
        additional: u32,
    ) -> Result<(), InterpreterError> {
        let reserved = self.writable_streams.values().fold(0u64, |total, state| {
            let pending_writes = if state.write_callback.is_some() {
                u64::try_from(state.writes.pending_len()).unwrap_or(u64::MAX)
            } else {
                0
            };
            let pending_final = u64::from(
                state.end_requested && state.final_status == WritableFinalStatus::NotStarted,
            );
            total
                .saturating_add(pending_writes)
                .saturating_add(pending_final)
        });
        let required = reserved.saturating_add(u64::from(additional));
        let available = u64::from(u32::MAX - self.next_writable_completion_token);
        if required > available {
            return Err(InterpreterError::InternalError {
                details: "Writable completion token space exhausted".to_string(),
            });
        }
        Ok(())
    }

    pub(super) fn writable_chunk_units(
        &self,
        object_mode: bool,
        value: &Value,
    ) -> Result<usize, InterpreterError> {
        if object_mode {
            return Ok(1);
        }
        match value {
            Value::Str(text) => Ok(text.len()),
            Value::Object(_) => {
                let view = self.buffer_like_view(value)?;
                Ok(self.typed_array_view_bytes(&view)?.len())
            }
            other => Err(InterpreterError::TypeError {
                expected: "string, Buffer, or Uint8Array Writable chunk".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn writable_invocation_label(
        &self,
        args: RegRange,
    ) -> Result<Label, InterpreterError> {
        let label = self.join_arg_range_label(args)?;
        if let Some(context) = &self.active_inline_callback_context_label {
            return self.join_owned_label_with_temporary_budget(label, context);
        }
        Ok(label)
    }

    pub(super) fn writable_invocation_label_with_receiver(
        &self,
        args: RegRange,
        receiver_register: Option<u32>,
    ) -> Result<Label, InterpreterError> {
        let label = self.writable_invocation_label(args)?;
        let Some(receiver_register) = receiver_register else {
            return Ok(label);
        };
        self.join_owned_label_with_temporary_budget(
            label,
            self.get_register_label(receiver_register)?,
        )
    }

    pub(super) fn writable_cork(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.writable_receiver_id(receiver)?;
        let trigger_label = self.writable_invocation_label(args)?;
        if self.writable_terminal_states.contains_key(&object_id) {
            self.join_writable_terminal_label(object_id, trigger_label)?;
            return Ok(Value::Undefined);
        }
        let Some(state) = self.writable_streams.get(&object_id) else {
            return Ok(Value::Undefined);
        };
        if state.destroy_requested {
            return Ok(Value::Undefined);
        }
        let next_depth =
            state
                .cork_depth
                .checked_add(1)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "Writable cork depth overflow".to_string(),
                })?;
        let replace_label = trigger_label > state.lifecycle_label;
        if replace_label {
            self.apply_memory_component_delta(
                Self::estimate_label_bytes(&state.lifecycle_label),
                Self::estimate_label_bytes(&trigger_label),
            )?;
        }
        if let Some(state) = self.writable_streams.get_mut(&object_id) {
            state.cork_depth = next_depth;
            if replace_label {
                state.lifecycle_label = trigger_label;
            } else {
                drop(trigger_label);
            }
        }
        self.mirror_writable_cork_depth(object_id, next_depth);
        Ok(Value::Undefined)
    }

    pub(super) fn writable_uncork(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.writable_receiver_id(receiver)?;
        let trigger_label = self.writable_invocation_label(args)?;
        if self.writable_terminal_states.contains_key(&object_id) {
            self.join_writable_terminal_label(object_id, trigger_label)?;
            return Ok(Value::Undefined);
        }
        let Some(state) = self.writable_streams.get(&object_id) else {
            return Ok(Value::Undefined);
        };
        if state.destroy_requested {
            return Ok(Value::Undefined);
        }
        let next_depth = state.cork_depth.saturating_sub(1);
        let replace_label = trigger_label > state.lifecycle_label;
        if replace_label {
            self.apply_memory_component_delta(
                Self::estimate_label_bytes(&state.lifecycle_label),
                Self::estimate_label_bytes(&trigger_label),
            )?;
        }
        if let Some(state) = self.writable_streams.get_mut(&object_id) {
            state.cork_depth = next_depth;
            if replace_label {
                state.lifecycle_label = trigger_label;
            } else {
                drop(trigger_label);
            }
        }
        self.mirror_writable_cork_depth(object_id, next_depth);
        if next_depth == 0 {
            self.drive_writable(object_id, module)?;
        }
        Ok(Value::Undefined)
    }

    pub(super) fn writable_destroy(
        &mut self,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let error_register = self.writable_completion_error_register(args)?;
        let mut trigger_label = self.writable_invocation_label(args)?;
        let error = error_register.map(|reg| &self.registers[self.register_base + reg as usize]);
        if let Some(Value::Object(error_id)) = error {
            if let Some(storage_label) = self.binary_storage_label_ref(*error_id) {
                trigger_label =
                    self.join_owned_label_with_temporary_budget(trigger_label, storage_label)?;
            }
        }
        self.writable_destroy_with_trigger(receiver, error_register, trigger_label)
    }

    pub(super) fn writable_destroy_with_trigger(
        &mut self,
        receiver: Value,
        error_register: Option<u32>,
        trigger_label: Label,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.writable_receiver_id(receiver.clone())?;
        let error = error_register.map(|reg| &self.registers[self.register_base + reg as usize]);
        if self.writable_terminal_states.contains_key(&object_id) {
            self.join_writable_terminal_label(object_id, trigger_label)?;
            self.detach_readable_pipes_to_destination(object_id);
            return Ok(receiver);
        }
        let Some(current) = self.writable_streams.get(&object_id) else {
            self.detach_readable_pipes_to_destination(object_id);
            return Ok(receiver);
        };
        if current.destroy_requested {
            self.detach_readable_pipes_to_destination(object_id);
            return Ok(receiver);
        }

        let previous_bytes = Self::estimate_writable_state_bytes(current);
        let retained_active_length = current.writes.active_units();
        let lifecycle_label_bytes = if current.lifecycle_label >= trigger_label {
            Self::estimate_label_bytes(&current.lifecycle_label)
        } else {
            Self::estimate_label_bytes(&trigger_label)
        };
        let terminal_error_origin = if current.terminal_error.is_some() {
            current.terminal_error_origin
        } else {
            Some(WritableErrorOrigin::Destroy)
        };
        let finishing_after_readable_end = current.writes.all_completed()
            && matches!(
                current.flavor,
                WritableStreamFlavor::PassThrough | WritableStreamFlavor::Transform
            )
            && matches!(current.final_status, WritableFinalStatus::Active(_))
            && current.terminal_error.is_none()
            && self
                .readable_from_streams
                .get(&object_id)
                .is_some_and(|state| state.phase == ReadableFromPumpPhase::Close);
        let retain_terminal_callbacks = current.writes.all_completed()
            && (current.final_status == WritableFinalStatus::Done || finishing_after_readable_end);
        let finishing_success_batch = finishing_after_readable_end
            || (retain_terminal_callbacks
                && current.terminal_error_origin.is_none()
                && matches!(
                    current.tick_phase,
                    WritableTickPhase::Finish | WritableTickPhase::Close
                ));
        let preserved_success_callbacks = if finishing_after_readable_end {
            current.end_callbacks.len()
        } else if finishing_success_batch && current.tick_phase == WritableTickPhase::Finish {
            current.end_callback_batch_remaining
        } else {
            0
        };
        let finished_callbacks_before_destroy_error = if finishing_success_batch {
            current
                .end_callbacks
                .len()
                .saturating_sub(preserved_success_callbacks)
        } else {
            0
        };
        let end_callback_bytes = if retain_terminal_callbacks {
            u64::try_from(current.end_callbacks.len())
                .unwrap_or(u64::MAX)
                .saturating_mul(MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES)
                .saturating_add(current.end_callbacks.iter().fold(0u64, |total, record| {
                    total.saturating_add(Self::estimate_writable_callback_bytes(&record.callback))
                }))
        } else {
            0
        };
        let destroyed_state_bytes = MEMORY_ESTIMATE_WRITABLE_BASE_BYTES
            .saturating_add(lifecycle_label_bytes)
            .saturating_add(end_callback_bytes)
            .saturating_add(
                current
                    .terminal_error
                    .as_ref()
                    .map(|(value, label)| {
                        Self::estimate_writable_value_bytes(value)
                            .saturating_add(Self::estimate_label_bytes(label))
                    })
                    .or_else(|| {
                        error.map(|error| {
                            Self::estimate_writable_value_bytes(error)
                                .saturating_add(Self::estimate_label_bytes(&trigger_label))
                        })
                    })
                    .unwrap_or(0),
            );
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_bytes)
            .saturating_add(destroyed_state_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        let scheduled_tick = if current.tick_sequence.is_none() {
            if let Some(sequence) = current.deferred_final_tick_sequence {
                Some((sequence, None))
            } else {
                let sequence = self.next_writable_tick_sequence;
                let next_sequence =
                    sequence
                        .checked_add(1)
                        .ok_or_else(|| InterpreterError::InternalError {
                            details: "Writable tick sequence space exhausted".to_string(),
                        })?;
                Some((sequence, Some(next_sequence)))
            }
        } else {
            None
        };
        let error = error_register.map(|reg| self.read_reg(reg)).transpose()?;

        let mut destroyed = self
            .writable_streams
            .remove(&object_id)
            .expect("live Writable state was checked before owned teardown");
        destroyed.write_callback = None;
        destroyed.final_callback = None;
        destroyed.writes = WritableWriteQueue::default();
        // Bun retains the synchronous pre-destroy mirrors. At close, queued
        // chunks disappear while a write already inside `_write` remains
        // reflected until its abandoned callback state is collected.
        destroyed.buffered_length = retained_active_length;
        destroyed.destroy_requested = true;
        if !retain_terminal_callbacks {
            destroyed.end_callbacks = LinkedList::new();
        }
        let trigger_dominates = trigger_label > destroyed.lifecycle_label;
        let mut trigger_label = Some(trigger_label);
        if trigger_dominates {
            destroyed.lifecycle_label = trigger_label
                .take()
                .expect("dominant destroy label remained owned");
        }
        let terminal_error = match destroyed.terminal_error.take() {
            Some(existing) => {
                drop(error);
                Some(existing)
            }
            None => error.map(|error| {
                let label = if trigger_dominates {
                    destroyed.lifecycle_label.clone()
                } else {
                    trigger_label
                        .take()
                        .expect("non-dominant destroy label remained owned")
                };
                (error, label)
            }),
        };
        drop(trigger_label);
        destroyed.end_callback_batch_remaining = if finishing_success_batch {
            preserved_success_callbacks
        } else {
            destroyed.end_callbacks.len()
        };
        destroyed.finished_end_callback_batch_remaining = finished_callbacks_before_destroy_error;
        destroyed.final_status = WritableFinalStatus::Done;
        destroyed.deferred_final_tick_sequence = None;
        destroyed.prefinish_emitted = true;
        destroyed.finished |= finishing_after_readable_end;
        destroyed.terminal_error = terminal_error;
        destroyed.terminal_error_origin = terminal_error_origin;
        destroyed.tick_phase = if finishing_after_readable_end || preserved_success_callbacks > 0 {
            WritableTickPhase::Finish
        } else {
            WritableTickPhase::Error
        };
        destroyed.inside_write_invocation = false;
        if let Some((sequence, next_sequence)) = scheduled_tick {
            destroyed.tick_sequence = Some(sequence);
            if let Some(next_sequence) = next_sequence {
                self.next_writable_tick_sequence = next_sequence;
            }
        }
        debug_assert_eq!(
            Self::estimate_writable_state_bytes(&destroyed),
            destroyed_state_bytes
        );
        self.estimated_memory_bytes = requested_bytes;
        self.writable_streams.insert(object_id, destroyed);
        self.detach_readable_pipes_to_destination(object_id);

        self.mirror_writable_bool(object_id, "writable", false);
        self.mirror_writable_bool(object_id, "destroyed", true);
        // Bun exposes both flags synchronously even though listener delivery
        // remains on the deferred stream checkpoint.
        self.mirror_writable_bool(object_id, "closed", true);
        Ok(receiver)
    }

    pub(super) fn writable_callback_arg(
        &self,
        args: RegRange,
        indices: &[u32],
        temporary_label_bytes: u64,
    ) -> Result<Option<WritableCallbackRecord>, InterpreterError> {
        for index in indices {
            if let Some(value) = self.builtin_arg(args, *index)?
                && value.is_callable()
            {
                let register = args.start.checked_add(*index).ok_or(
                    InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    },
                )?;
                let label = self.get_register_label(register)?;
                self.check_temporary_memory_budget(
                    temporary_label_bytes.saturating_add(Self::estimate_label_bytes(label)),
                )?;
                return Ok(Some(WritableCallbackRecord {
                    value,
                    label: label.clone(),
                    module_specifier: self.current_module_specifier.clone(),
                }));
            }
        }
        Ok(None)
    }

    pub(super) fn writable_enqueue(
        &mut self,
        object_id: ObjectId,
        value: Value,
        label: Label,
        callback: Option<WritableCallbackRecord>,
    ) -> Result<bool, InterpreterError> {
        Ok(self
            .append_writable_write(object_id, value, label, callback, None, false)?
            .unwrap_or(false))
    }

    pub(super) fn writable_write(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.writable_receiver_id(receiver)?;
        let value = self
            .builtin_arg(args, 0)?
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "Writable chunk".to_string(),
                got: "missing argument".to_string(),
            })?;
        let label = self.join_arg_range_label(args)?;
        let label = if let Value::Object(chunk_id) = &value {
            if let Some(storage_label) = self.binary_storage_label_ref(*chunk_id) {
                self.join_owned_label_with_temporary_budget(label, storage_label)?
            } else {
                label
            }
        } else {
            label
        };
        let callback =
            self.writable_callback_arg(args, &[1, 2], Self::estimate_label_bytes(&label))?;
        let rejected_during_dual_final =
            self.readable_from_streams
                .get(&object_id)
                .is_some_and(|state| {
                    matches!(
                        state.phase,
                        ReadableFromPumpPhase::Data | ReadableFromPumpPhase::End
                    ) && state.eof_requested
                })
                && self.writable_streams.get(&object_id).is_some_and(|state| {
                    state.end_requested
                        && matches!(
                            state.flavor,
                            WritableStreamFlavor::PassThrough | WritableStreamFlavor::Transform
                        )
                        && matches!(
                            state.final_status,
                            WritableFinalStatus::Active(_) | WritableFinalStatus::Done
                        )
                });
        if rejected_during_dual_final {
            let error = self.stream_error_value("ERR_STREAM_WRITE_AFTER_END", "write after end")?;
            let error_label = if let Some(callback) = callback {
                self.append_writable_end_callback(object_id, callback, true, label)?;
                let lifecycle_label = &self
                    .writable_streams
                    .get(&object_id)
                    .expect("rejected dual-stream callback retained its Writable state")
                    .lifecycle_label;
                self.clone_dominant_label_with_temporary_budget(
                    lifecycle_label,
                    lifecycle_label,
                    0,
                )?
            } else {
                label
            };
            self.record_dual_stream_failure(
                object_id,
                error,
                error_label,
                WritableErrorOrigin::Write,
                false,
            )?;
            return Ok(Value::Bool(false));
        }
        if let Some(finished) = self
            .writable_terminal_states
            .get(&object_id)
            .map(|state| state.finished)
        {
            let error = if finished {
                WritableTerminalCallbackError::WriteAfterFinish
            } else {
                WritableTerminalCallbackError::WriteAfterDestroy
            };
            if let Some(callback) = callback {
                self.append_writable_terminal_callback(object_id, callback, error, label)?;
            } else {
                self.join_writable_terminal_label(object_id, label)?;
            }
            return Ok(Value::Bool(false));
        }
        // A live write with an implementation needs an authenticated
        // completion when it enters `drive_writable`, immediately or after an
        // earlier write/cork is released. Refuse before `writable_enqueue`
        // retains the record when the process-lifetime nonce space is already
        // exhausted. Preserve the historical missing-_write path, which
        // deliberately retains a Pending record for deterministic retry.
        if self.writable_streams.get(&object_id).is_some_and(|state| {
            !state.end_requested && !state.destroy_requested && state.write_callback.is_some()
        }) {
            self.preflight_writable_completion_reservations(1)?;
        }
        let below_high_water_mark = self.writable_enqueue(object_id, value, label, callback)?;
        self.drive_writable(object_id, module)?;
        Ok(Value::Bool(below_high_water_mark))
    }

    pub(super) fn writable_end(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.writable_receiver_id(receiver)?;
        let first = self.builtin_arg(args, 0)?;
        let chunk = first.filter(|value| {
            !value.is_callable() && !matches!(value, Value::Undefined | Value::Null)
        });
        let mut args_label = self.writable_invocation_label(args)?;
        // Resolve backing-store taint before cloning a callback label. The
        // callback preflight can then charge the one true aggregate peak rather
        // than overlooking a later, dominant object-chunk label.
        if let Some(Value::Object(chunk_id)) = chunk.as_ref()
            && let Some(storage_label) = self.binary_storage_label_ref(*chunk_id)
        {
            args_label = self.join_owned_label_with_temporary_budget(args_label, storage_label)?;
        }
        let callback =
            self.writable_callback_arg(args, &[0, 1, 2], Self::estimate_label_bytes(&args_label))?;
        if let Some((finished, accepts_late_end_callback)) = self
            .writable_terminal_states
            .get(&object_id)
            .map(|state| (state.finished, state.accepts_late_end_callback))
        {
            if let Some(callback) = callback {
                let error = if chunk.is_some() {
                    Some(if finished {
                        WritableTerminalCallbackError::WriteAfterFinish
                    } else {
                        WritableTerminalCallbackError::WriteAfterDestroy
                    })
                } else if finished || accepts_late_end_callback {
                    Some(if finished {
                        WritableTerminalCallbackError::EndAfterFinish
                    } else {
                        WritableTerminalCallbackError::EndAfterDestroy
                    })
                } else {
                    None
                };
                if let Some(error) = error {
                    self.append_writable_terminal_callback(object_id, callback, error, args_label)?;
                } else {
                    self.join_writable_terminal_label(object_id, args_label)?;
                }
            } else {
                self.join_writable_terminal_label(object_id, args_label)?;
            }
            self.detach_readable_pipes_to_destination(object_id);
            return Ok(Value::Object(object_id));
        }
        let required_completion_tokens = self
            .writable_streams
            .get(&object_id)
            .filter(|state| !state.end_requested && !state.destroy_requested)
            .map_or(0, |state| {
                let write_token = u32::from(chunk.is_some() && state.write_callback.is_some());
                let final_token = u32::from(state.final_status == WritableFinalStatus::NotStarted);
                write_token.saturating_add(final_token)
            });
        self.preflight_writable_completion_reservations(required_completion_tokens)?;
        if let Some(value) = chunk {
            self.append_writable_write(object_id, value, args_label, None, callback, true)?;
        } else {
            let Some(state) = self.writable_streams.get(&object_id) else {
                self.detach_readable_pipes_to_destination(object_id);
                return Ok(Value::Object(object_id));
            };
            let already_ended = state.end_requested;
            let already_destroyed = state.destroy_requested;
            if let Some(callback) = callback {
                self.append_writable_end_callback(
                    object_id,
                    callback,
                    already_ended || already_destroyed,
                    args_label,
                )?;
            } else if !already_ended && !already_destroyed {
                let old_label_bytes = Self::estimate_label_bytes(&state.lifecycle_label);
                let label_dominates = args_label > state.lifecycle_label;
                let mut args_label = Some(args_label);
                let next_label_bytes = if label_dominates {
                    Self::estimate_label_bytes(
                        args_label
                            .as_ref()
                            .expect("candidate Writable end label remained available"),
                    )
                } else {
                    old_label_bytes
                };
                if !label_dominates {
                    // Nothing retains this invocation aggregate. Release it
                    // before mirrors and the fallible drive phase run.
                    drop(args_label.take());
                }
                self.apply_memory_component_delta(old_label_bytes, next_label_bytes)?;
                if let Some(state) = self.writable_streams.get_mut(&object_id) {
                    state.cork_depth = 0;
                    state.end_requested = true;
                    if label_dominates {
                        state.lifecycle_label = args_label
                            .take()
                            .expect("dominant Writable end label remained owned through preflight");
                    }
                }
                debug_assert!(args_label.is_none());
            } else {
                // A repeated end without a callback retains no new state.
                // Dispose its checked aggregate before mirrors and drive.
                drop(args_label);
            }
        }
        self.detach_readable_pipes_to_destination(object_id);
        self.mirror_writable_bool(object_id, "writable", false);
        self.mirror_writable_bool(object_id, "writableEnded", true);
        self.mirror_writable_cork_depth(object_id, 0);
        self.drive_writable(object_id, module)?;
        Ok(Value::Object(object_id))
    }

    pub(super) fn writable_bound_completion(
        builtin: &BuiltinFunction,
    ) -> Result<(ObjectId, u32), InterpreterError> {
        let object_id = builtin
            .bound_object
            .ok_or_else(|| InterpreterError::InternalError {
                details: "Writable completion is missing its object binding".to_string(),
            })?;
        let token = builtin
            .iterator_handle
            .ok_or_else(|| InterpreterError::InternalError {
                details: "Writable completion is missing its token".to_string(),
            })?;
        Ok((ObjectId(object_id), token))
    }

    pub(super) fn writable_completion_error_register(
        &self,
        args: RegRange,
    ) -> Result<Option<u32>, InterpreterError> {
        if args.count == 0 {
            return Ok(None);
        }
        if args.start >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: args.start,
                max: self.config.max_registers,
            });
        }
        let actual_reg = self.register_base + args.start as usize;
        let Some(error) = self.registers.get(actual_reg) else {
            return Ok(None);
        };
        Ok((!matches!(error, Value::Undefined | Value::Null)).then_some(args.start))
    }

    pub(super) fn writable_live_binary_label_ref<'a>(
        &'a self,
        value: &Value,
        fallback: &'a Label,
    ) -> &'a Label {
        let Value::Object(object_id) = value else {
            return fallback;
        };
        self.binary_storage_label_ref(*object_id)
            .filter(|storage_label| *storage_label > fallback)
            .unwrap_or(fallback)
    }

    /// Retain a completion error without consuming the guest-visible call
    /// argument. Call/CallMethod joins argument labels into the destination
    /// only after the builtin returns, so replacing this register early would
    /// erase both normal guest state and the documented post-call IFC join.
    pub(super) fn clone_writable_completion_error(
        &self,
        reg: u32,
    ) -> Result<(Value, Label), InterpreterError> {
        let value = self.read_reg(reg)?;
        let label = self.writable_live_binary_label_ref(&value, self.get_register_label(reg)?);
        Ok((value, label.clone()))
    }

    pub(super) fn writable_write_done(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (object_id, token) = Self::writable_bound_completion(builtin)?;
        let completion_error_register = self.writable_completion_error_register(args)?;
        if let Some(state) = self.writable_streams.get_mut(&object_id) {
            state.writes.normalize_completed_prefix();
        }
        let Some(state) = self.writable_streams.get(&object_id) else {
            return Ok(Value::Undefined);
        };
        let Some(record) = state
            .writes
            .ready_front()
            .filter(|record| record.status == WritableWriteStatus::Active(token))
        else {
            return Ok(Value::Undefined);
        };
        let units = record.units;
        let resume = !state.inside_write_invocation;
        let old_dynamic = Self::estimate_writable_error_dynamic_bytes(state);
        let next_dynamic = if let Some(reg) = completion_error_register {
            let actual_reg = self.register_base + reg as usize;
            let error = &self.registers[actual_reg];
            let error_label =
                self.writable_live_binary_label_ref(error, self.get_register_label(reg)?);
            let next_lifecycle_label = if error_label > &state.lifecycle_label {
                error_label
            } else {
                &state.lifecycle_label
            };
            Self::estimate_label_bytes(next_lifecycle_label)
                .saturating_add(Self::estimate_writable_value_bytes(error))
                .saturating_add(Self::estimate_label_bytes(error_label))
        } else {
            old_dynamic
        };
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(old_dynamic)
            .saturating_add(next_dynamic);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        let scheduled_tick = if state.tick_sequence.is_none() {
            let sequence = self.next_writable_tick_sequence;
            let next_sequence =
                sequence
                    .checked_add(1)
                    .ok_or_else(|| InterpreterError::InternalError {
                        details: "Writable tick sequence space exhausted".to_string(),
                    })?;
            Some((sequence, next_sequence))
        } else {
            None
        };
        let completion_error = completion_error_register
            .map(|reg| self.clone_writable_completion_error(reg))
            .transpose()?;
        self.estimated_memory_bytes = requested_bytes;
        let state = self
            .writable_streams
            .get_mut(&object_id)
            .expect("Writable completion state survived preflight");
        state
            .writes
            .complete_active(token, completion_error.is_some())
            .expect("authenticated Writable completion remained at the ready front");
        if let Some((error, error_label)) = completion_error {
            state.writes.complete_all_ready_failed();
            state.buffered_length = 0;
            state.terminal_error = None;
            let terminal_label = if error_label > state.lifecycle_label {
                state.lifecycle_label = error_label;
                state.lifecycle_label.clone()
            } else {
                error_label
            };
            state.terminal_error = Some((error, terminal_label));
            state.terminal_error_origin = Some(WritableErrorOrigin::Write);
            state.terminal_error_emitted = false;
        } else {
            state.buffered_length = state.buffered_length.saturating_sub(units);
        }
        if let Some((sequence, next_sequence)) = scheduled_tick {
            state.tick_sequence = Some(sequence);
            self.next_writable_tick_sequence = next_sequence;
        }
        let length = self
            .writable_streams
            .get(&object_id)
            .map_or(0, |state| state.buffered_length);
        self.mirror_writable_length(object_id, length);
        if resume {
            self.drive_writable(object_id, module)?;
        }
        Ok(Value::Undefined)
    }

    pub(super) fn writable_final_done(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (object_id, token) = Self::writable_bound_completion(builtin)?;
        let completion_error_register = self.writable_completion_error_register(args)?;
        let Some(state) = self.writable_streams.get(&object_id) else {
            return Ok(Value::Undefined);
        };
        if state.final_status != WritableFinalStatus::Active(token) {
            return Ok(Value::Undefined);
        }
        let old_dynamic = Self::estimate_label_bytes(&state.lifecycle_label).saturating_add(
            state
                .terminal_error
                .as_ref()
                .map(|(value, label)| {
                    Self::estimate_writable_value_bytes(value)
                        .saturating_add(Self::estimate_label_bytes(label))
                })
                .unwrap_or(0),
        );
        let next_dynamic = if let Some(reg) = completion_error_register {
            let actual_reg = self.register_base + reg as usize;
            let error = &self.registers[actual_reg];
            let error_label =
                self.writable_live_binary_label_ref(error, self.get_register_label(reg)?);
            let next_lifecycle_label = if error_label > &state.lifecycle_label {
                error_label
            } else {
                &state.lifecycle_label
            };
            Self::estimate_label_bytes(next_lifecycle_label)
                .saturating_add(Self::estimate_writable_value_bytes(error))
                .saturating_add(Self::estimate_label_bytes(error_label))
        } else {
            old_dynamic
        };
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(old_dynamic)
            .saturating_add(next_dynamic);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        let scheduled_tick = if state.tick_sequence.is_none() {
            if let Some(sequence) = state.deferred_final_tick_sequence {
                Some((sequence, None))
            } else {
                let sequence = self.next_writable_tick_sequence;
                let next_sequence =
                    sequence
                        .checked_add(1)
                        .ok_or_else(|| InterpreterError::InternalError {
                            details: "Writable tick sequence space exhausted".to_string(),
                        })?;
                Some((sequence, Some(next_sequence)))
            }
        } else {
            None
        };
        let completion_error = completion_error_register
            .map(|reg| self.clone_writable_completion_error(reg))
            .transpose()?;
        self.estimated_memory_bytes = requested_bytes;
        let state = self
            .writable_streams
            .get_mut(&object_id)
            .expect("Writable final state survived preflight");
        state.final_status = WritableFinalStatus::Done;
        state.deferred_final_tick_sequence = None;
        if let Some((error, error_label)) = completion_error {
            state.terminal_error = None;
            let terminal_label = if error_label > state.lifecycle_label {
                state.lifecycle_label = error_label;
                state.lifecycle_label.clone()
            } else {
                error_label
            };
            state.terminal_error = Some((error, terminal_label));
            state.terminal_error_origin = Some(WritableErrorOrigin::Final);
            state.terminal_error_emitted = false;
        }
        if let Some((sequence, next_sequence)) = scheduled_tick {
            state.tick_sequence = Some(sequence);
            if let Some(next_sequence) = next_sequence {
                self.next_writable_tick_sequence = next_sequence;
            }
        }
        self.emit_writable_prefinish(object_id, module)?;
        Ok(Value::Undefined)
    }

    pub(super) fn writable_invocation_error_value(
        &mut self,
        error: &InterpreterError,
        fallback_label: Label,
    ) -> (Value, Label, bool) {
        if matches!(error, InterpreterError::UncaughtException { .. })
            && let Some((value, label)) = self.take_pending_exception_slot()
        {
            (value, label, true)
        } else {
            (Value::str(error.to_string()), fallback_label, false)
        }
    }

    pub(super) fn record_writable_terminal_error(
        &mut self,
        object_id: ObjectId,
        error: Value,
        error_label: Label,
        origin: WritableErrorOrigin,
        restore_pending_exception_on_refusal: bool,
    ) -> Result<(), InterpreterError> {
        let Some(state) = self.writable_streams.get(&object_id) else {
            return Ok(());
        };
        let old_dynamic = Self::estimate_writable_error_dynamic_bytes(state);
        let per_record = Self::estimate_writable_value_bytes(&error)
            .saturating_add(Self::estimate_label_bytes(&error_label));
        let label_dominates = error_label > state.lifecycle_label;
        let next_dynamic = (if label_dominates {
            Self::estimate_label_bytes(&error_label)
        } else {
            Self::estimate_label_bytes(&state.lifecycle_label)
        })
        .saturating_add(per_record);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(old_dynamic)
            .saturating_add(next_dynamic);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            let budget_error =
                self.memory_budget_error(requested_bytes, self.heap_object_count_u32());
            if restore_pending_exception_on_refusal {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_add(Self::estimate_value_bytes(&error))
                    .saturating_add(Self::estimate_label_bytes(&error_label));
                self.pending_exception = Some(error);
                self.pending_exception_label = error_label;
            }
            return Err(budget_error);
        }
        let scheduled_tick = if state.tick_sequence.is_none() {
            if let Some(sequence) = state.deferred_final_tick_sequence {
                Some((sequence, None))
            } else {
                let sequence = self.next_writable_tick_sequence;
                let Some(next_sequence) = sequence.checked_add(1) else {
                    if restore_pending_exception_on_refusal {
                        self.estimated_memory_bytes = self
                            .estimated_memory_bytes
                            .saturating_add(Self::estimate_value_bytes(&error))
                            .saturating_add(Self::estimate_label_bytes(&error_label));
                        self.pending_exception = Some(error);
                        self.pending_exception_label = error_label;
                    }
                    return Err(InterpreterError::InternalError {
                        details: "Writable tick sequence space exhausted".to_string(),
                    });
                };
                Some((sequence, Some(next_sequence)))
            }
        } else {
            None
        };
        self.estimated_memory_bytes = requested_bytes;
        let state = self
            .writable_streams
            .get_mut(&object_id)
            .expect("Writable terminal-error state survived preflight");
        state.terminal_error = None;
        let terminal_label = if label_dominates {
            state.lifecycle_label = error_label;
            state.lifecycle_label.clone()
        } else {
            error_label
        };
        state.terminal_error = Some((error, terminal_label));
        state.terminal_error_origin = Some(origin);
        state.terminal_error_emitted = false;
        state.final_status = WritableFinalStatus::Done;
        state.deferred_final_tick_sequence = None;
        state.inside_write_invocation = false;
        if let Some((sequence, next_sequence)) = scheduled_tick {
            state.tick_sequence = Some(sequence);
            if let Some(next_sequence) = next_sequence {
                self.next_writable_tick_sequence = next_sequence;
            }
        }
        Ok(())
    }

    /// A dual-stream callback can fail only after the Writable driver has
    /// committed end/EOF. Its final token is normally Active, but an initially
    /// empty pull lane marks it Done immediately before delayed `prefinish`.
    /// Convert either failure into one aggregate terminal transition so
    /// neither half can remain live waiting for a callback/EOF that will never
    /// arrive.
    pub(super) fn record_dual_stream_failure(
        &mut self,
        object_id: ObjectId,
        error: Value,
        error_label: Label,
        origin: WritableErrorOrigin,
        restore_pending_exception_on_refusal: bool,
    ) -> Result<(), InterpreterError> {
        let readable_lifecycle_label = self
            .readable_from_streams
            .get(&object_id)
            .filter(|state| !state.destroy_requested)
            .map(|state| {
                self.clone_dominant_label_with_temporary_budget(
                    &state.lifecycle_label,
                    &error_label,
                    Self::estimate_label_bytes(&error_label),
                )
            })
            .transpose()?;
        let readable_error = readable_lifecycle_label.as_ref().map(|_| error.clone());
        let readable_reservation = readable_lifecycle_label
            .as_ref()
            .and_then(|label| {
                self.readable_destroy_memory_projection(object_id, readable_error.as_ref(), label)
            })
            .map(|(previous, destroyed, pump)| {
                destroyed.saturating_add(pump).saturating_sub(previous)
            })
            .unwrap_or(0);

        self.apply_memory_component_delta(0, readable_reservation)?;
        if let Err(record_error) = self.record_writable_terminal_error(
            object_id,
            error,
            error_label,
            origin,
            restore_pending_exception_on_refusal,
        ) {
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(readable_reservation);
            return Err(record_error);
        }
        if let Some(state) = self.writable_streams.get_mut(&object_id) {
            state.destroy_requested = true;
            if origin == WritableErrorOrigin::Write {
                state.writes.complete_all_ready_failed();
                state.buffered_length = 0;
            }
        }
        if readable_lifecycle_label.is_some()
            && let Some(state) = self.writable_streams.get_mut(&object_id)
        {
            // Readable owns the one shared EventEmitter error/close sequence.
            state.terminal_error_emitted = true;
        }
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(readable_reservation);
        if let (Some(readable_error), Some(lifecycle_label)) =
            (readable_error, readable_lifecycle_label)
        {
            self.commit_readable_destroy(
                object_id,
                Value::Object(object_id),
                Some(readable_error),
                lifecycle_label,
            )?;
        }
        Ok(())
    }

    /// Complete the Readable half after the ordinary Writable completion
    /// kernel has retained a Transform callback error. Keeping that kernel as
    /// the sole register-to-state transfer preserves its exact accounting and
    /// FIFO failure semantics while making Readable the sole shared emitter.
    pub(super) fn destroy_dual_stream_after_writable_error(
        &mut self,
        object_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        let Some(temporary_bytes) = self
            .writable_streams
            .get(&object_id)
            .and_then(|state| state.terminal_error.as_ref())
            .map(|(error, label)| {
                Self::estimate_value_bytes(error).saturating_add(Self::estimate_label_bytes(label))
            })
        else {
            return Ok(());
        };
        self.check_temporary_memory_budget(temporary_bytes)?;
        let (error, error_label) = self
            .writable_streams
            .get(&object_id)
            .and_then(|state| state.terminal_error.clone())
            .expect("Transform terminal error survived temporary-memory preflight");
        let readable_lifecycle_label = self
            .readable_from_streams
            .get(&object_id)
            .filter(|state| !state.destroy_requested)
            .map(|state| {
                self.clone_dominant_label_with_temporary_budget(
                    &state.lifecycle_label,
                    &error_label,
                    Self::estimate_label_bytes(&error_label),
                )
            })
            .transpose()?;
        let Some(readable_lifecycle_label) = readable_lifecycle_label else {
            return Ok(());
        };
        let readable_reservation = self
            .readable_destroy_memory_projection(object_id, Some(&error), &readable_lifecycle_label)
            .map(|(previous, destroyed, pump)| {
                destroyed.saturating_add(pump).saturating_sub(previous)
            })
            .unwrap_or(0);
        self.apply_memory_component_delta(0, readable_reservation)?;
        if let Some(state) = self.writable_streams.get_mut(&object_id) {
            state.destroy_requested = true;
            state.terminal_error_emitted = true;
        }
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(readable_reservation);
        self.commit_readable_destroy(
            object_id,
            Value::Object(object_id),
            Some(error),
            readable_lifecycle_label,
        )?;
        Ok(())
    }

    pub(super) fn emit_writable_prefinish(
        &mut self,
        object_id: ObjectId,
        module: &Ir3Module,
    ) -> Result<(), InterpreterError> {
        self.emit_writable_prefinish_with_tick(object_id, module, true)
    }

    pub(super) fn emit_writable_prefinish_with_tick(
        &mut self,
        object_id: ObjectId,
        module: &Ir3Module,
        schedule_tick: bool,
    ) -> Result<(), InterpreterError> {
        let Some(state) = self.writable_streams.get(&object_id) else {
            return Ok(());
        };
        if state.prefinish_emitted || state.terminal_error.is_some() {
            return Ok(());
        }
        let label = state.lifecycle_label.clone();
        if schedule_tick {
            self.schedule_writable_tick(object_id)?;
        }
        self.writable_streams
            .get_mut(&object_id)
            .expect("Writable prefinish state survived tick scheduling")
            .prefinish_emitted = true;
        self.emit_event_listener_records(module, object_id, "prefinish", Vec::new(), label)?;
        Ok(())
    }

    pub(super) fn drive_writable(
        &mut self,
        object_id: ObjectId,
        module: &Ir3Module,
    ) -> Result<(), InterpreterError> {
        loop {
            let defer_pull_final = self.writable_streams.get(&object_id).is_some_and(|state| {
                state.end_requested
                    && state.final_status == WritableFinalStatus::NotStarted
                    && state.writes.ready_front().is_none()
                    && matches!(
                        state.flavor,
                        WritableStreamFlavor::PassThrough | WritableStreamFlavor::Transform
                    )
            }) && self.has_readable_pull_observer(object_id)
                && self
                    .readable_from_streams
                    .get(&object_id)
                    .is_some_and(|readable| {
                        readable.paused
                            && readable.phase == ReadableFromPumpPhase::Data
                            && readable.data_readable_pending
                    });
            if defer_pull_final {
                // The Readable pump resumes final activation immediately
                // after the data notification. Do not arm a placeholder tick:
                // the pre-loop fixed-point checkpoint would consume it before
                // the callback whose failure it is meant to clean up.
                return Ok(());
            }
            let action = {
                let Some(state) = self.writable_streams.get(&object_id) else {
                    return Ok(());
                };
                if state.terminal_error.is_some()
                    || state.destroy_requested
                    || state.cork_depth > 0
                    || state.writes.has_active()
                {
                    return Ok(());
                }
                if let Some(record) = state
                    .writes
                    .ready_front()
                    .filter(|record| record.status == WritableWriteStatus::Pending)
                {
                    Some((
                        false,
                        state.write_callback.clone(),
                        record.value.clone(),
                        record.label.join(&state.lifecycle_label),
                        state.flavor,
                    ))
                } else if state.end_requested
                    && state.final_status == WritableFinalStatus::NotStarted
                    && state.writes.ready_front().is_none()
                {
                    Some((
                        true,
                        state.final_callback.clone(),
                        Value::Undefined,
                        state.lifecycle_label.clone(),
                        state.flavor,
                    ))
                } else {
                    None
                }
            };

            let Some((is_final, callback, value, mut label, flavor)) = action else {
                return Ok(());
            };
            if !is_final && callback.is_none() {
                return Err(InterpreterError::TypeError {
                    expected: "Writable with a callable write implementation".to_string(),
                    got: "missing write option".to_string(),
                });
            }
            if !is_final {
                if let Value::Object(value_id) = &value
                    && let Some(storage_label) = self.binary_storage_label_ref(*value_id)
                {
                    label = self.join_owned_label_with_temporary_budget(label, storage_label)?;
                }
                self.preflight_inline_method_call_with_argument_label(
                    Some(module),
                    callback
                        .as_ref()
                        .expect("non-final Writable callback was checked"),
                    3,
                    Some(&label),
                )?;
            }
            let token = self.allocate_writable_completion_token()?;
            let Some(state) = self.writable_streams.get_mut(&object_id) else {
                return Ok(());
            };
            if !is_final {
                assert!(
                    state.writes.activate_front(token),
                    "Writable pending front survived callback preflight"
                );
                state.inside_write_invocation = true;
            } else {
                state.final_status = WritableFinalStatus::Active(token);
            }
            if is_final {
                let Some(callback) = callback else {
                    if let Some(state) = self.writable_streams.get_mut(&object_id) {
                        state.final_status = WritableFinalStatus::Done;
                    }
                    self.emit_writable_prefinish(object_id, module)?;
                    return Ok(());
                };
                let passthrough_internal = matches!(
                    &callback,
                    Value::BuiltinFunction(builtin)
                        if builtin.kind == BuiltinFunctionKind::StreamPassThroughFinal
                );
                let completion_kind = if flavor == WritableStreamFlavor::Transform {
                    BuiltinFunctionKind::StreamTransformFinalDone
                } else {
                    BuiltinFunctionKind::StreamWritableFinalDone
                };
                let completion = Value::BuiltinFunction(BuiltinFunction::writable_completion(
                    completion_kind,
                    object_id,
                    token,
                ));
                let invocation = self.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    callback,
                    Value::Object(object_id),
                    vec![completion],
                    Some(label.clone()),
                );
                if let Err(error) = invocation {
                    // A denied or contained execution cannot be resumed by
                    // converting its failure into a guest stream error.
                    if Self::stops_guest_execution(&error) {
                        return Err(error);
                    }
                    let (error_value, error_label, consumes_pending_exception) =
                        self.writable_invocation_error_value(&error, label);
                    if passthrough_internal || flavor == WritableStreamFlavor::Transform {
                        self.record_dual_stream_failure(
                            object_id,
                            error_value,
                            error_label,
                            WritableErrorOrigin::Final,
                            consumes_pending_exception,
                        )?;
                    } else {
                        self.record_writable_terminal_error(
                            object_id,
                            error_value,
                            error_label,
                            WritableErrorOrigin::Final,
                            consumes_pending_exception,
                        )?;
                    }
                }
                return Ok(());
            }

            let callback = callback.expect("non-final Writable callback was preflighted");
            let passthrough_internal = matches!(
                &callback,
                Value::BuiltinFunction(builtin)
                    if builtin.kind == BuiltinFunctionKind::StreamPassThroughWrite
            );
            let completion_kind = if flavor == WritableStreamFlavor::Transform {
                BuiltinFunctionKind::StreamTransformWriteDone
            } else {
                BuiltinFunctionKind::StreamWritableWriteDone
            };
            let completion = Value::BuiltinFunction(BuiltinFunction::writable_completion(
                completion_kind,
                object_id,
                token,
            ));
            let (invocation, callback_started) = self
                .invoke_inline_method_call_tracking_callback_start(
                    Some(module),
                    callback,
                    Value::Object(object_id),
                    vec![value, Value::str("utf8"), completion],
                    Some(label.clone()),
                );
            if let Some(state) = self.writable_streams.get_mut(&object_id) {
                state.inside_write_invocation = false;
            }
            // Bun/Node propagate a synchronous `_write` throw from write()
            // itself. Roll back only while the isolated wrapper is still in
            // reversible startup. Once CallMethod commits the callback call,
            // rest binding and other function-instantiation work may mutate
            // persistent guest state, so preserve Active/buffered state rather
            // than retrying those effects.
            if let Err(error) = invocation {
                if !callback_started {
                    let Some(state) = self.writable_streams.get_mut(&object_id) else {
                        return Err(error);
                    };
                    if state.writes.rollback_active(token) {
                        self.next_writable_completion_token = token;
                    }
                } else if !Self::stops_guest_execution(&error)
                    && (passthrough_internal || flavor == WritableStreamFlavor::Transform)
                {
                    let (error_value, error_label, consumes_pending_exception) =
                        if matches!(&error, InterpreterError::UncaughtException { .. })
                            && let Some(pending) = self.pending_exception.as_ref()
                        {
                            let pending_label = &self.pending_exception_label;
                            self.check_temporary_memory_budget(
                                Self::estimate_value_bytes(pending)
                                    .saturating_add(Self::estimate_label_bytes(pending_label)),
                            )?;
                            (pending.clone(), pending_label.clone(), false)
                        } else {
                            self.writable_invocation_error_value(&error, label)
                        };
                    self.record_dual_stream_failure(
                        object_id,
                        error_value,
                        error_label,
                        WritableErrorOrigin::Write,
                        consumes_pending_exception,
                    )?;
                }
                return Err(error);
            }
            let completed = self
                .writable_streams
                .get(&object_id)
                .is_some_and(|state| state.writes.has_completed());
            if !completed {
                return Ok(());
            }
        }
    }

    pub(super) fn transfer_writable_record_to_in_flight(
        &mut self,
        released_record_bytes: u64,
        released_node_bytes: u64,
    ) -> u64 {
        let dynamic_bytes = released_record_bytes.saturating_sub(released_node_bytes);
        self.writable_in_flight_callback_bytes = self
            .writable_in_flight_callback_bytes
            .saturating_add(dynamic_bytes);
        // The state estimator still included the removed record. Moving its
        // dynamic payload into the in-flight component preserves that charge;
        // only the now-deallocated linked-list node is released here.
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(released_node_bytes);
        dynamic_bytes
    }

    pub(super) fn add_writable_in_flight_charge(
        &mut self,
        invocation_charge: &mut u64,
        bytes: u64,
    ) -> Result<(), InterpreterError> {
        let requested_bytes = self.estimated_memory_bytes.saturating_add(bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.writable_in_flight_callback_bytes =
            self.writable_in_flight_callback_bytes.saturating_add(bytes);
        *invocation_charge = invocation_charge.saturating_add(bytes);
        self.estimated_memory_bytes = requested_bytes;
        Ok(())
    }

    pub(super) fn release_writable_in_flight_charge(
        &mut self,
        invocation_charge: &mut u64,
        bytes: u64,
    ) {
        let released = bytes.min(*invocation_charge);
        *invocation_charge -= released;
        self.writable_in_flight_callback_bytes = self
            .writable_in_flight_callback_bytes
            .saturating_sub(released);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
    }

    pub(super) fn release_all_writable_in_flight_charge(&mut self, invocation_charge: &mut u64) {
        let remaining_charge = *invocation_charge;
        self.release_writable_in_flight_charge(invocation_charge, remaining_charge);
    }

    pub(super) fn take_dominant_charged_writable_label(
        &mut self,
        left: Label,
        right: Label,
        invocation_charge: &mut u64,
    ) -> Label {
        // Preserve Label::join's full-Ord, left-on-equality winner while
        // moving the allocation instead of cloning it.
        if left >= right {
            self.release_writable_in_flight_charge(
                invocation_charge,
                Self::estimate_label_bytes(&right),
            );
            drop(right);
            left
        } else {
            self.release_writable_in_flight_charge(
                invocation_charge,
                Self::estimate_label_bytes(&left),
            );
            drop(left);
            right
        }
    }

    pub(super) fn clone_charged_writable_label(
        &mut self,
        label: &Label,
        invocation_charge: &mut u64,
    ) -> Result<Label, InterpreterError> {
        self.add_writable_in_flight_charge(invocation_charge, Self::estimate_label_bytes(label))?;
        Ok(label.clone())
    }

    pub(super) fn clone_charged_writable_lifecycle_label(
        &mut self,
        object_id: ObjectId,
        invocation_charge: &mut u64,
    ) -> Result<Label, InterpreterError> {
        let label_bytes = self
            .writable_streams
            .get(&object_id)
            .map(|state| Self::estimate_label_bytes(&state.lifecycle_label))
            .ok_or_else(|| InterpreterError::InternalError {
                details: "scheduled Writable callback lost its live state".to_string(),
            })?;
        self.add_writable_in_flight_charge(invocation_charge, label_bytes)?;
        Ok(self
            .writable_streams
            .get(&object_id)
            .expect("Writable state survived lifecycle-label preflight")
            .lifecycle_label
            .clone())
    }

    pub(super) fn clone_charged_writable_terminal_lifecycle_label(
        &mut self,
        object_id: ObjectId,
        invocation_charge: &mut u64,
    ) -> Result<Label, InterpreterError> {
        let label_bytes = self
            .writable_terminal_states
            .get(&object_id)
            .map(|state| Self::estimate_label_bytes(&state.lifecycle_label))
            .ok_or_else(|| InterpreterError::InternalError {
                details: "scheduled terminal Writable tick lost its tombstone".to_string(),
            })?;
        self.add_writable_in_flight_charge(invocation_charge, label_bytes)?;
        Ok(self
            .writable_terminal_states
            .get(&object_id)
            .expect("terminal Writable state survived lifecycle-label preflight")
            .lifecycle_label
            .clone())
    }

    /// Persist backing-store taint that appeared after a binary error value was
    /// recorded. Buffer and typed-array aliases share their ArrayBuffer label,
    /// so a deferred Writable callback must not trust the earlier snapshot.
    pub(super) fn rejoin_writable_terminal_error_binary_label(
        &mut self,
        object_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        let Some((error_id, old_dynamic, next_dynamic, rejoin_lifecycle, rejoin_error)) = ({
            let state = self.writable_streams.get(&object_id);
            state.and_then(|state| {
                let (Value::Object(error_id), error_label) = state.terminal_error.as_ref()? else {
                    return None;
                };
                let storage_label = self.binary_storage_label_ref(*error_id)?;
                let rejoin_lifecycle = storage_label > &state.lifecycle_label;
                let rejoin_error = storage_label > error_label;
                if !rejoin_lifecycle && !rejoin_error {
                    return None;
                }
                let old_dynamic = Self::estimate_writable_error_dynamic_bytes(state);
                let next_dynamic = Self::estimate_label_bytes(if rejoin_lifecycle {
                    storage_label
                } else {
                    &state.lifecycle_label
                })
                .saturating_add(Self::estimate_writable_value_bytes(
                    &state
                        .terminal_error
                        .as_ref()
                        .expect("Writable terminal error was matched above")
                        .0,
                ))
                .saturating_add(Self::estimate_label_bytes(if rejoin_error {
                    storage_label
                } else {
                    error_label
                }));
                Some((
                    *error_id,
                    old_dynamic,
                    next_dynamic,
                    rejoin_lifecycle,
                    rejoin_error,
                ))
            })
        }) else {
            return Ok(());
        };

        // Refusal is atomic: no retained label changes until the complete
        // replacement state fits.
        self.apply_memory_component_delta(old_dynamic, next_dynamic)?;

        if rejoin_lifecycle {
            let previous = {
                let state = self
                    .writable_streams
                    .get_mut(&object_id)
                    .expect("Writable state survived binary-label preflight");
                std::mem::replace(&mut state.lifecycle_label, Label::Public)
            };
            drop(previous);
            let storage_label = self
                .binary_storage_label_ref(error_id)
                .expect("binary backing survived Writable label preflight")
                .clone();
            self.writable_streams
                .get_mut(&object_id)
                .expect("Writable state survived lifecycle-label replacement")
                .lifecycle_label = storage_label;
        }
        if rejoin_error {
            let previous = {
                let state = self
                    .writable_streams
                    .get_mut(&object_id)
                    .expect("Writable state survived binary-label preflight");
                let (_, error_label) = state
                    .terminal_error
                    .as_mut()
                    .expect("Writable terminal error survived label preflight");
                std::mem::replace(error_label, Label::Public)
            };
            drop(previous);
            let storage_label = self
                .binary_storage_label_ref(error_id)
                .expect("binary backing survived Writable label preflight")
                .clone();
            self.writable_streams
                .get_mut(&object_id)
                .and_then(|state| state.terminal_error.as_mut())
                .expect("Writable terminal error survived label replacement")
                .1 = storage_label;
        }
        debug_assert_eq!(
            self.writable_streams
                .get(&object_id)
                .map(Self::estimate_writable_error_dynamic_bytes),
            Some(next_dynamic)
        );
        Ok(())
    }

    pub(super) fn clone_charged_writable_terminal_error(
        &mut self,
        object_id: ObjectId,
        invocation_charge: &mut u64,
    ) -> Result<Option<(Value, Label)>, InterpreterError> {
        self.rejoin_writable_terminal_error_binary_label(object_id)?;
        let error_bytes = self
            .writable_streams
            .get(&object_id)
            .and_then(|state| state.terminal_error.as_ref())
            .map(|(value, label)| {
                Self::estimate_writable_value_bytes(value)
                    .saturating_add(Self::estimate_label_bytes(label))
            })
            .unwrap_or(0);
        self.add_writable_in_flight_charge(invocation_charge, error_bytes)?;
        Ok(self
            .writable_streams
            .get(&object_id)
            .and_then(|state| state.terminal_error.clone()))
    }

    pub(super) fn clone_charged_writable_error(
        &mut self,
        error: &Option<(Value, Label)>,
        invocation_charge: &mut u64,
    ) -> Result<Option<(Value, Label)>, InterpreterError> {
        let Some((value, label)) = error.as_ref() else {
            return Ok(None);
        };
        let error_bytes = Self::estimate_writable_value_bytes(value).saturating_add(
            Self::estimate_label_bytes(self.writable_live_binary_label_ref(value, label)),
        );
        self.add_writable_in_flight_charge(invocation_charge, error_bytes)?;
        let live_label = self.writable_live_binary_label_ref(value, label).clone();
        Ok(Some((value.clone(), live_label)))
    }

    /// Replace one already charged label with a later, dominant backing-store
    /// label without charging an artificial old-plus-new peak.
    pub(super) fn rejoin_charged_writable_binary_label(
        &mut self,
        value: &Value,
        label: Label,
        invocation_charge: &mut u64,
    ) -> Result<Label, InterpreterError> {
        let Value::Object(object_id) = value else {
            return Ok(label);
        };
        let Some(next_label_bytes) = self
            .binary_storage_label_ref(*object_id)
            .filter(|storage_label| *storage_label > &label)
            .map(Self::estimate_label_bytes)
        else {
            return Ok(label);
        };
        let previous_label_bytes = Self::estimate_label_bytes(&label);
        let requested_bytes = self
            .estimated_memory_bytes
            .saturating_sub(previous_label_bytes)
            .saturating_add(next_label_bytes);
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        self.writable_in_flight_callback_bytes = self
            .writable_in_flight_callback_bytes
            .saturating_sub(previous_label_bytes)
            .saturating_add(next_label_bytes);
        *invocation_charge = invocation_charge
            .saturating_sub(previous_label_bytes)
            .saturating_add(next_label_bytes);
        self.estimated_memory_bytes = requested_bytes;
        drop(label);
        Ok(self
            .binary_storage_label_ref(*object_id)
            .expect("binary backing survived charged Writable label preflight")
            .clone())
    }

    pub(super) fn charged_writable_error_value(
        &mut self,
        message: &str,
        invocation_charge: &mut u64,
    ) -> Result<Value, InterpreterError> {
        self.add_writable_in_flight_charge(
            invocation_charge,
            Self::estimate_string_bytes(message),
        )?;
        Ok(Value::str(message))
    }

    pub(super) fn charged_writable_synthesized_error_inputs(
        &mut self,
        object_id: ObjectId,
        message: &str,
        invocation_charge: &mut u64,
    ) -> Result<(Option<(Value, Label)>, Label), InterpreterError> {
        let fallback_label =
            self.clone_charged_writable_lifecycle_label(object_id, invocation_charge)?;
        let error_label = self.clone_charged_writable_label(&fallback_label, invocation_charge)?;
        let error = self.charged_writable_error_value(message, invocation_charge)?;
        Ok((Some((error, error_label)), fallback_label))
    }

    pub(super) fn charged_writable_terminal_error_inputs(
        &mut self,
        object_id: ObjectId,
        invocation_charge: &mut u64,
    ) -> Result<(Option<(Value, Label)>, Label), InterpreterError> {
        let fallback_label =
            self.clone_charged_writable_lifecycle_label(object_id, invocation_charge)?;
        let error = self.clone_charged_writable_terminal_error(object_id, invocation_charge)?;
        Ok((error, fallback_label))
    }

    pub(super) fn retain_first_writable_callback_error(
        &mut self,
        first_error: &mut Option<InterpreterError>,
        first_error_charge: &mut u64,
        error: InterpreterError,
    ) -> Result<(), InterpreterError> {
        // Resource/security failures revoke the entire execution. Even a
        // single batched stream tick must not invoke a later callback after
        // one; callers release the retained-error and snapshot charges.
        if Self::stops_guest_execution(&error) {
            return Err(error);
        }
        let retained_error_bytes = first_error
            .as_ref()
            .map(Self::estimate_interpreter_error_bytes)
            .unwrap_or_else(|| Self::estimate_interpreter_error_bytes(&error));
        let desired_charge = retained_error_bytes;
        if desired_charge > *first_error_charge {
            if let Err(memory_error) = self.add_writable_in_flight_charge(
                first_error_charge,
                desired_charge - *first_error_charge,
            ) {
                // The escaping throw cannot remain resident after its exact
                // ownership charge is refused. Containment takes precedence
                // over preserving a payload that the configured ceiling says
                // may not survive this callback boundary.
                self.clear_pending_exception_slot();
                return Err(memory_error);
            }
        } else {
            self.release_writable_in_flight_charge(
                first_error_charge,
                *first_error_charge - desired_charge,
            );
        }
        if first_error.is_none() {
            *first_error = Some(error);
        }
        Ok(())
    }

    pub(super) fn take_first_writable_callback_error(
        &mut self,
        first_error: &mut Option<InterpreterError>,
        first_error_charge: &mut u64,
    ) -> Option<InterpreterError> {
        let error = first_error.take();
        let remaining_charge = *first_error_charge;
        self.release_writable_in_flight_charge(first_error_charge, remaining_charge);
        error
    }

    pub(super) fn emit_charged_writable_event_listener_records(
        &mut self,
        module: &Ir3Module,
        object_id: ObjectId,
        event: &str,
        arguments: Vec<Value>,
        mut emission_label: Label,
        mut invocation_charge: u64,
    ) -> Result<(), InterpreterError> {
        let result = (|| {
            for argument in &arguments {
                emission_label = self.rejoin_charged_writable_binary_label(
                    argument,
                    emission_label,
                    &mut invocation_charge,
                )?;
            }
            self.emit_event_listener_records(module, object_id, event, arguments, emission_label)
                .map(|_| ())
        })();
        let remaining_charge = invocation_charge;
        self.release_writable_in_flight_charge(&mut invocation_charge, remaining_charge);
        result
    }

    pub(super) fn invoke_writable_deferred_callback_raw(
        &mut self,
        module: &Ir3Module,
        callback: Value,
        object_id: ObjectId,
        arguments: Vec<Value>,
        label: Label,
    ) -> Result<(), InterpreterError> {
        self.invoke_inline_method_call_with_argument_label_preflighted(
            Some(module),
            callback,
            Value::Object(object_id),
            arguments,
            Some(label),
        )?;
        Ok(())
    }

    pub(super) fn invoke_writable_deferred_callback(
        &mut self,
        module: &Ir3Module,
        callback: WritableCallbackRecord,
        object_id: ObjectId,
        error: Option<(Value, Label)>,
        fallback_label: Label,
        mut invocation_charge: u64,
    ) -> Result<(), InterpreterError> {
        let result = (|| -> Result<(), InterpreterError> {
            let WritableCallbackRecord {
                value: callback_value,
                label: callback_label,
                module_specifier,
            } = callback;
            let retained_origin_module = match module_specifier.as_ref() {
                Some(specifier) if specifier != &module.header.source_label => {
                    let Some(record) = self.module_state.modules.get(specifier) else {
                        let reason = "Writable callback origin module is not retained";
                        self.add_writable_in_flight_charge(
                            &mut invocation_charge,
                            Self::estimate_string_bytes(specifier)
                                .saturating_add(Self::estimate_string_bytes(reason)),
                        )?;
                        return Err(InterpreterError::ModuleEvaluationFailed {
                            specifier: specifier.clone(),
                            reason: reason.to_string(),
                        });
                    };
                    let Some(compiled_module) = record.compiled_module.as_ref() else {
                        let reason = "Writable callback origin record has no retained program";
                        self.add_writable_in_flight_charge(
                            &mut invocation_charge,
                            Self::estimate_string_bytes(specifier)
                                .saturating_add(Self::estimate_string_bytes(reason)),
                        )?;
                        return Err(InterpreterError::ModuleEvaluationFailed {
                            specifier: specifier.clone(),
                            reason: reason.to_string(),
                        });
                    };
                    Some(Arc::clone(compiled_module))
                }
                _ => None,
            };
            let module_specifier_bytes = module_specifier
                .as_ref()
                .map(|specifier| Self::estimate_string_bytes(specifier))
                .unwrap_or(0);
            drop(module_specifier);
            self.release_writable_in_flight_charge(&mut invocation_charge, module_specifier_bytes);

            let callback_label = self.take_dominant_charged_writable_label(
                fallback_label,
                callback_label,
                &mut invocation_charge,
            );
            let (arguments, label, argument_value_handoff_bytes) = match error {
                Some((error, error_label)) => {
                    let handoff_bytes = Self::estimate_value_bytes(&error);
                    let error_label = self.rejoin_charged_writable_binary_label(
                        &error,
                        error_label,
                        &mut invocation_charge,
                    )?;
                    let label = self.take_dominant_charged_writable_label(
                        callback_label,
                        error_label,
                        &mut invocation_charge,
                    );
                    (vec![error], label, handoff_bytes)
                }
                None => (Vec::new(), callback_label, 0),
            };
            let callback_value_handoff_bytes = Self::estimate_value_bytes(&callback_value);
            let label_handoff_bytes = Self::estimate_label_bytes(&label);
            let invocation_module = retained_origin_module.as_deref().unwrap_or(module);
            self.preflight_inline_method_call_with_argument_label(
                Some(invocation_module),
                &callback_value,
                arguments.len(),
                Some(&label),
            )?;
            self.release_writable_in_flight_charge(
                &mut invocation_charge,
                callback_value_handoff_bytes
                    .saturating_add(argument_value_handoff_bytes)
                    .saturating_add(label_handoff_bytes),
            );

            self.invoke_writable_deferred_callback_raw(
                invocation_module,
                callback_value,
                object_id,
                arguments,
                label,
            )
        })();
        let remaining_charge = invocation_charge;
        self.release_writable_in_flight_charge(&mut invocation_charge, remaining_charge);
        debug_assert_eq!(invocation_charge, 0);
        result
    }

    pub(super) fn take_writable_end_callback(
        &mut self,
        object_id: ObjectId,
    ) -> Option<(WritableEndCallbackRecord, u64)> {
        let (callback, released) = {
            let state = self.writable_streams.get_mut(&object_id)?;
            let previous = Self::estimate_writable_state_bytes(state);
            let callback = state.end_callbacks.pop_front()?;
            let next = Self::estimate_writable_state_bytes(state);
            (callback, previous.saturating_sub(next))
        };
        let invocation_charge = self.transfer_writable_record_to_in_flight(
            released,
            MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES,
        );
        Some((callback, invocation_charge))
    }

    pub(super) fn join_writable_terminal_label(
        &mut self,
        object_id: ObjectId,
        trigger_label: Label,
    ) -> Result<(), InterpreterError> {
        let state = self
            .writable_terminal_states
            .get(&object_id)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "terminal Writable label update lost its tombstone".to_string(),
            })?;
        let previous_bytes = Self::estimate_writable_terminal_state_bytes(state);
        let trigger_dominates = trigger_label > state.lifecycle_label;
        let next_label_bytes = if trigger_dominates {
            Self::estimate_label_bytes(&trigger_label)
        } else {
            Self::estimate_label_bytes(&state.lifecycle_label)
        };
        let next_bytes = previous_bytes
            .saturating_sub(Self::estimate_label_bytes(&state.lifecycle_label))
            .saturating_add(next_label_bytes);
        let mut trigger_label = Some(trigger_label);
        if !trigger_dominates {
            drop(trigger_label.take());
        }
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        let state = self
            .writable_terminal_states
            .get_mut(&object_id)
            .expect("terminal Writable tombstone survived label preflight");
        if trigger_dominates {
            state.lifecycle_label = trigger_label
                .take()
                .expect("dominant terminal Writable label remained owned through preflight");
        }
        debug_assert!(trigger_label.is_none());
        debug_assert_eq!(
            Self::estimate_writable_terminal_state_bytes(state),
            next_bytes
        );
        Ok(())
    }

    pub(super) fn append_writable_terminal_callback(
        &mut self,
        object_id: ObjectId,
        callback: WritableCallbackRecord,
        error: WritableTerminalCallbackError,
        trigger_label: Label,
    ) -> Result<(), InterpreterError> {
        let state = self
            .writable_terminal_states
            .get(&object_id)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "post-close Writable callback lost its tombstone".to_string(),
            })?;
        state
            .callbacks
            .len()
            .checked_add(1)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "terminal Writable callback FIFO length overflows host address space"
                    .to_string(),
            })?;
        let previous_bytes = Self::estimate_writable_terminal_state_bytes(state);
        let trigger_dominates = trigger_label > state.lifecycle_label;
        let next_label_bytes = if trigger_dominates {
            Self::estimate_label_bytes(&trigger_label)
        } else {
            Self::estimate_label_bytes(&state.lifecycle_label)
        };
        let next_bytes = previous_bytes
            .saturating_sub(Self::estimate_label_bytes(&state.lifecycle_label))
            .saturating_add(next_label_bytes)
            .saturating_add(Self::estimate_writable_callback_bytes(&callback))
            .saturating_add(MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES);
        let scheduled_sequence = if state.tick_sequence.is_none() {
            let sequence = self.next_writable_tick_sequence;
            let next_sequence =
                sequence
                    .checked_add(1)
                    .ok_or_else(|| InterpreterError::InternalError {
                        details: "Writable tick sequence space exhausted".to_string(),
                    })?;
            let next_pending = self
                .pending_writable_terminal_ticks
                .checked_add(1)
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "pending terminal Writable tick count overflowed".to_string(),
                })?;
            Some((sequence, next_sequence, next_pending))
        } else {
            None
        };

        let mut trigger_label = Some(trigger_label);
        if !trigger_dominates {
            drop(trigger_label.take());
        }
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        let state = self
            .writable_terminal_states
            .get_mut(&object_id)
            .expect("terminal Writable tombstone survived callback preflight");
        if trigger_dominates {
            state.lifecycle_label = trigger_label
                .take()
                .expect("dominant terminal callback label remained owned through preflight");
        }
        debug_assert!(trigger_label.is_none());
        // Replace/drop the old lifecycle String before the linked-list node is
        // allocated; `next_bytes` already subtracts that old resident label.
        state
            .callbacks
            .push_back(WritableTerminalCallbackRecord { callback, error });
        if let Some((sequence, next_sequence, next_pending)) = scheduled_sequence {
            state.tick_sequence = Some(sequence);
            self.next_writable_tick_sequence = next_sequence;
            self.pending_writable_terminal_ticks = next_pending;
        }
        debug_assert_eq!(
            Self::estimate_writable_terminal_state_bytes(state),
            next_bytes
        );
        Ok(())
    }

    pub(super) fn take_writable_terminal_callback(
        &mut self,
        object_id: ObjectId,
    ) -> Option<(WritableTerminalCallbackRecord, u64)> {
        let (callback, released) = {
            let state = self.writable_terminal_states.get_mut(&object_id)?;
            let previous = Self::estimate_writable_terminal_state_bytes(state);
            let callback = state.callbacks.pop_front()?;
            let next = Self::estimate_writable_terminal_state_bytes(state);
            (callback, previous.saturating_sub(next))
        };
        let invocation_charge = self.transfer_writable_record_to_in_flight(
            released,
            MEMORY_ESTIMATE_WRITABLE_END_CALLBACK_BYTES,
        );
        Some((callback, invocation_charge))
    }

    pub(super) fn drive_writable_terminal_tick(
        &mut self,
        object_id: ObjectId,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let Some(module) = module else {
            return Ok(());
        };
        if !self.writable_terminal_states.contains_key(&object_id) {
            return Err(InterpreterError::InternalError {
                details: "scheduled terminal Writable tick lost its tombstone".to_string(),
            });
        }
        if self
            .writable_terminal_states
            .get(&object_id)
            .is_some_and(|state| state.callbacks.len() > 1)
        {
            self.schedule_writable_terminal_tick(object_id)?;
        }
        let Some((record, mut invocation_charge)) = self.take_writable_terminal_callback(object_id)
        else {
            return Ok(());
        };
        let prepared = (|| -> Result<(Value, Label, Label), InterpreterError> {
            let lifecycle_label = self.clone_charged_writable_terminal_lifecycle_label(
                object_id,
                &mut invocation_charge,
            )?;
            let error_label =
                self.clone_charged_writable_label(&lifecycle_label, &mut invocation_charge)?;
            let error =
                self.charged_writable_error_value(record.error.message(), &mut invocation_charge)?;
            Ok((error, error_label, lifecycle_label))
        })();
        let (error, error_label, lifecycle_label) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let remaining_charge = invocation_charge;
                self.release_writable_in_flight_charge(&mut invocation_charge, remaining_charge);
                return Err(error);
            }
        };
        self.invoke_writable_deferred_callback(
            module,
            record.callback,
            object_id,
            Some((error, error_label)),
            lifecycle_label,
            invocation_charge,
        )
    }

    #[cfg(test)]
    pub(super) fn release_writable_state_storage(&mut self, object_id: ObjectId) {
        let released = self
            .writable_streams
            .remove(&object_id)
            .map(|state| Self::estimate_writable_state_bytes(&state))
            .unwrap_or(0);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
        self.clear_event_listeners(object_id, None);
        self.clear_event_promise_waiters_for_target(object_id);
    }

    pub(super) fn terminalize_writable_state_storage(
        &mut self,
        object_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        if self.writable_terminal_states.contains_key(&object_id) {
            return Err(InterpreterError::InternalError {
                details: "Writable terminalization would replace an existing tombstone".to_string(),
            });
        }
        let state = self.writable_streams.get(&object_id).ok_or_else(|| {
            InterpreterError::InternalError {
                details: "Writable terminalization lost its live state".to_string(),
            }
        })?;
        debug_assert!(state.end_callbacks.is_empty());
        debug_assert!(state.tick_sequence.is_none());
        let previous_bytes = Self::estimate_writable_state_bytes(state);
        let next_bytes = MEMORY_ESTIMATE_WRITABLE_TERMINAL_BASE_BYTES
            .saturating_add(Self::estimate_label_bytes(&state.lifecycle_label));
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        let mut state = self
            .writable_streams
            .remove(&object_id)
            .expect("live Writable state survived terminalization preflight");
        let lifecycle_label = std::mem::replace(&mut state.lifecycle_label, Label::Public);
        let terminal = WritableTerminalState {
            object_mode: state.object_mode,
            high_water_mark: state.high_water_mark,
            end_requested: state.end_requested,
            finished: state.finished,
            buffered_length: state.buffered_length,
            cork_depth: state.cork_depth,
            accepts_late_end_callback: state.finished || state.terminal_error.is_some(),
            callbacks: LinkedList::new(),
            tick_sequence: None,
            lifecycle_label,
        };
        debug_assert_eq!(
            Self::estimate_writable_terminal_state_bytes(&terminal),
            next_bytes
        );
        drop(state);
        self.writable_terminal_states.insert(object_id, terminal);
        // A PassThrough's readable half owns the shared emitter through its
        // later end/close turn. Writable terminalization must retain those
        // listeners and waiters instead of erasing the readable lifecycle.
        if !self.readable_from_streams.contains_key(&object_id) {
            self.clear_event_listeners(object_id, None);
            self.clear_event_promise_waiters_for_target(object_id);
        }
        Ok(())
    }

    pub(super) fn drive_writable_tick(
        &mut self,
        object_id: ObjectId,
        module: Option<&Ir3Module>,
    ) -> Result<(), InterpreterError> {
        let Some(module) = module else {
            return Ok(());
        };
        loop {
            let (
                terminal_error_origin,
                terminal_error_emitted,
                buffered_length,
                cork_depth,
                phase,
                completed_front,
                writes_empty,
                need_drain,
                final_done,
                terminal_error_none,
                end_callback_batch_remaining,
                finished_end_callback_batch_remaining,
                end_callbacks_empty,
            ) = {
                let Some(state) = self.writable_streams.get(&object_id) else {
                    return Ok(());
                };
                (
                    state.terminal_error_origin,
                    state.terminal_error_emitted,
                    state.buffered_length,
                    state.cork_depth,
                    state.tick_phase,
                    state
                        .writes
                        .front()
                        .is_some_and(|record| record.status == WritableWriteStatus::Completed),
                    state.writes.is_empty(),
                    state.need_drain,
                    state.final_status == WritableFinalStatus::Done,
                    state.terminal_error.is_none(),
                    state.end_callback_batch_remaining,
                    state.finished_end_callback_batch_remaining,
                    state.end_callbacks.is_empty(),
                )
            };
            if phase == WritableTickPhase::Callbacks {
                if completed_front {
                    // Reserve the successor before removing the completed
                    // record. Sequence exhaustion must leave the FIFO and its
                    // accounting byte-for-byte retryable.
                    self.schedule_writable_tick(object_id)?;
                    let (record, released) = {
                        let state = self
                            .writable_streams
                            .get_mut(&object_id)
                            .expect("Writable state was checked above");
                        let previous = Self::estimate_writable_state_bytes(state);
                        let record = state
                            .writes
                            .pop_completed_front()
                            .expect("completed Writable front was checked");
                        let next = Self::estimate_writable_state_bytes(state);
                        (record, previous.saturating_sub(next))
                    };
                    let mut invocation_charge = self.transfer_writable_record_to_in_flight(
                        released,
                        MEMORY_ESTIMATE_WRITABLE_WRITE_NODE_BYTES,
                    );
                    let WritableWriteRecord {
                        value,
                        label,
                        callback,
                        completion_failed,
                        ..
                    } = record;
                    let value_bytes = Self::estimate_writable_value_bytes(&value);
                    drop(value);
                    self.release_writable_in_flight_charge(&mut invocation_charge, value_bytes);
                    let Some(callback) = callback else {
                        drop(label);
                        let remaining_charge = invocation_charge;
                        self.release_writable_in_flight_charge(
                            &mut invocation_charge,
                            remaining_charge,
                        );
                        return Ok(());
                    };
                    let prepared = (|| {
                        let lifecycle_label = self.clone_charged_writable_lifecycle_label(
                            object_id,
                            &mut invocation_charge,
                        )?;
                        let fallback_label = self.take_dominant_charged_writable_label(
                            label,
                            lifecycle_label,
                            &mut invocation_charge,
                        );
                        let callback_error = if completion_failed {
                            self.clone_charged_writable_terminal_error(
                                object_id,
                                &mut invocation_charge,
                            )?
                        } else {
                            None
                        };
                        Ok::<_, InterpreterError>((fallback_label, callback_error))
                    })();
                    let (fallback_label, callback_error) = match prepared {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            let remaining_charge = invocation_charge;
                            self.release_writable_in_flight_charge(
                                &mut invocation_charge,
                                remaining_charge,
                            );
                            return Err(error);
                        }
                    };
                    return self.invoke_writable_deferred_callback(
                        module,
                        callback,
                        object_id,
                        callback_error,
                        fallback_label,
                        invocation_charge,
                    );
                }
                if writes_empty && need_drain && terminal_error_none {
                    self.schedule_writable_tick(object_id)?;
                    let label = self
                        .writable_streams
                        .get(&object_id)
                        .expect("Writable drain state was checked")
                        .lifecycle_label
                        .clone();
                    self.writable_streams
                        .get_mut(&object_id)
                        .expect("Writable drain state survived label clone")
                        .need_drain = false;
                    self.mirror_writable_bool(object_id, "writableNeedDrain", false);
                    self.emit_event_listener_records(
                        module,
                        object_id,
                        "drain",
                        Vec::new(),
                        label,
                    )?;
                    return Ok(());
                }
                if !writes_empty || (!final_done && terminal_error_none) {
                    return Ok(());
                }
                let finishing_successfully = terminal_error_none;
                if let Some(state) = self.writable_streams.get_mut(&object_id) {
                    let callbacks_precede_error = matches!(
                        state.terminal_error_origin,
                        Some(WritableErrorOrigin::Write | WritableErrorOrigin::Destroy)
                    );
                    state.end_callback_batch_remaining =
                        if state.terminal_error.is_none() || callbacks_precede_error {
                            state.end_callbacks.len()
                        } else {
                            0
                        };
                    state.finished = finishing_successfully;
                    state.tick_phase = if state.terminal_error.is_some() {
                        WritableTickPhase::Error
                    } else {
                        WritableTickPhase::Finish
                    };
                }
                if finishing_successfully {
                    self.mirror_writable_bool(object_id, "writableFinished", true);
                }
                continue;
            }

            if phase == WritableTickPhase::Finish {
                if end_callback_batch_remaining > 0 {
                    self.preflight_writable_tick(object_id)?;
                    let mut phase_snapshot_charge = 0;
                    let phase_lifecycle_label = match self.clone_charged_writable_lifecycle_label(
                        object_id,
                        &mut phase_snapshot_charge,
                    ) {
                        Ok(label) => label,
                        Err(error) => {
                            self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                            return Err(error);
                        }
                    };
                    // The snapshot is fallible but non-mutating. Commit the
                    // preflighted successor only once every prerequisite is
                    // resident, immediately before consuming the callback FIFO.
                    self.schedule_writable_tick(object_id)?;
                    let mut first_callback_error = None;
                    let mut first_callback_error_charge = 0;
                    while self
                        .writable_streams
                        .get(&object_id)
                        .is_some_and(|state| state.end_callback_batch_remaining > 0)
                    {
                        if let Some(state) = self.writable_streams.get_mut(&object_id) {
                            state.end_callback_batch_remaining -= 1;
                        }
                        let Some((end_callback, invocation_charge)) =
                            self.take_writable_end_callback(object_id)
                        else {
                            self.take_first_writable_callback_error(
                                &mut first_callback_error,
                                &mut first_callback_error_charge,
                            );
                            self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                            return Err(InterpreterError::InternalError {
                                details: "Writable finish callback batch exceeds its FIFO"
                                    .to_string(),
                            });
                        };
                        let mut invocation_charge = invocation_charge;
                        let fallback_label = match self.clone_charged_writable_label(
                            &phase_lifecycle_label,
                            &mut invocation_charge,
                        ) {
                            Ok(label) => label,
                            Err(error) => {
                                let remaining_charge = invocation_charge;
                                self.release_writable_in_flight_charge(
                                    &mut invocation_charge,
                                    remaining_charge,
                                );
                                self.take_first_writable_callback_error(
                                    &mut first_callback_error,
                                    &mut first_callback_error_charge,
                                );
                                self.release_all_writable_in_flight_charge(
                                    &mut phase_snapshot_charge,
                                );
                                return Err(error);
                            }
                        };
                        if let Err(error) = self.invoke_writable_deferred_callback(
                            module,
                            end_callback.callback,
                            object_id,
                            None,
                            fallback_label,
                            invocation_charge,
                        ) && let Err(memory_error) = self.retain_first_writable_callback_error(
                            &mut first_callback_error,
                            &mut first_callback_error_charge,
                            error,
                        ) {
                            self.take_first_writable_callback_error(
                                &mut first_callback_error,
                                &mut first_callback_error_charge,
                            );
                            self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                            return Err(memory_error);
                        }
                    }
                    if let Some(state) = self.writable_streams.get_mut(&object_id)
                        && state.tick_phase == WritableTickPhase::Finish
                    {
                        state.tick_phase = if state.terminal_error_origin.is_some() {
                            WritableTickPhase::Error
                        } else {
                            WritableTickPhase::Close
                        };
                    }
                    self.mirror_writable_bool(object_id, "writableFinished", true);
                    let mut event_charge = 0;
                    let lifecycle_label = match self
                        .clone_charged_writable_label(&phase_lifecycle_label, &mut event_charge)
                    {
                        Ok(label) => label,
                        Err(error) => {
                            self.take_first_writable_callback_error(
                                &mut first_callback_error,
                                &mut first_callback_error_charge,
                            );
                            self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                            return Err(error);
                        }
                    };
                    let finish_result = self.emit_charged_writable_event_listener_records(
                        module,
                        object_id,
                        "finish",
                        Vec::new(),
                        lifecycle_label,
                        event_charge,
                    );
                    drop(phase_lifecycle_label);
                    self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                    if let Some(error) = self.take_first_writable_callback_error(
                        &mut first_callback_error,
                        &mut first_callback_error_charge,
                    ) {
                        return Err(error);
                    }
                    return finish_result;
                }
                self.schedule_writable_tick(object_id)?;
                if let Some(state) = self.writable_streams.get_mut(&object_id) {
                    state.tick_phase = if state.terminal_error_origin.is_some() {
                        WritableTickPhase::Error
                    } else {
                        WritableTickPhase::Close
                    };
                }
                self.mirror_writable_bool(object_id, "writableFinished", true);
                let mut event_charge = 0;
                let lifecycle_label =
                    self.clone_charged_writable_lifecycle_label(object_id, &mut event_charge)?;
                return self.emit_charged_writable_event_listener_records(
                    module,
                    object_id,
                    "finish",
                    Vec::new(),
                    lifecycle_label,
                    event_charge,
                );
            }

            if phase == WritableTickPhase::Error {
                if finished_end_callback_batch_remaining > 0 {
                    self.preflight_writable_tick(object_id)?;
                    let mut phase_snapshot_charge = 0;
                    let phase_lifecycle_label = match self.clone_charged_writable_lifecycle_label(
                        object_id,
                        &mut phase_snapshot_charge,
                    ) {
                        Ok(label) => label,
                        Err(error) => {
                            self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                            return Err(error);
                        }
                    };
                    self.schedule_writable_tick(object_id)?;
                    let mut first_callback_error = None;
                    let mut first_callback_error_charge = 0;
                    while self
                        .writable_streams
                        .get(&object_id)
                        .is_some_and(|state| state.finished_end_callback_batch_remaining > 0)
                    {
                        if let Some(state) = self.writable_streams.get_mut(&object_id) {
                            state.finished_end_callback_batch_remaining -= 1;
                        }
                        let Some((end_callback, invocation_charge)) =
                            self.take_writable_end_callback(object_id)
                        else {
                            self.take_first_writable_callback_error(
                                &mut first_callback_error,
                                &mut first_callback_error_charge,
                            );
                            self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                            return Err(InterpreterError::InternalError {
                                details: "Writable finished callback batch exceeds its FIFO"
                                    .to_string(),
                            });
                        };
                        let mut invocation_charge = invocation_charge;
                        let prepared = (|| {
                            let fallback_label = self.clone_charged_writable_label(
                                &phase_lifecycle_label,
                                &mut invocation_charge,
                            )?;
                            let error_label = self.clone_charged_writable_label(
                                &phase_lifecycle_label,
                                &mut invocation_charge,
                            )?;
                            let error = self.charged_writable_error_value(
                                "Cannot call end after a stream was finished",
                                &mut invocation_charge,
                            )?;
                            Ok::<_, InterpreterError>((Some((error, error_label)), fallback_label))
                        })();
                        let (callback_error, fallback_label) = match prepared {
                            Ok(prepared) => prepared,
                            Err(error) => {
                                let remaining_charge = invocation_charge;
                                self.release_writable_in_flight_charge(
                                    &mut invocation_charge,
                                    remaining_charge,
                                );
                                self.take_first_writable_callback_error(
                                    &mut first_callback_error,
                                    &mut first_callback_error_charge,
                                );
                                self.release_all_writable_in_flight_charge(
                                    &mut phase_snapshot_charge,
                                );
                                return Err(error);
                            }
                        };
                        if let Err(error) = self.invoke_writable_deferred_callback(
                            module,
                            end_callback.callback,
                            object_id,
                            callback_error,
                            fallback_label,
                            invocation_charge,
                        ) && let Err(memory_error) = self.retain_first_writable_callback_error(
                            &mut first_callback_error,
                            &mut first_callback_error_charge,
                            error,
                        ) {
                            self.take_first_writable_callback_error(
                                &mut first_callback_error,
                                &mut first_callback_error_charge,
                            );
                            self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                            return Err(memory_error);
                        }
                    }
                    let result = match self.take_first_writable_callback_error(
                        &mut first_callback_error,
                        &mut first_callback_error_charge,
                    ) {
                        Some(error) => Err(error),
                        None => Ok(()),
                    };
                    drop(phase_lifecycle_label);
                    self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                    return result;
                }
                if matches!(
                    terminal_error_origin,
                    Some(WritableErrorOrigin::Write | WritableErrorOrigin::Destroy)
                ) && end_callback_batch_remaining > 0
                {
                    self.preflight_writable_tick(object_id)?;
                    let mut phase_snapshot_charge = 0;
                    let phase_snapshot = (|| {
                        let lifecycle_label = self.clone_charged_writable_lifecycle_label(
                            object_id,
                            &mut phase_snapshot_charge,
                        )?;
                        let terminal_error = self.clone_charged_writable_terminal_error(
                            object_id,
                            &mut phase_snapshot_charge,
                        )?;
                        Ok::<_, InterpreterError>((lifecycle_label, terminal_error))
                    })();
                    let (phase_lifecycle_label, phase_terminal_error) = match phase_snapshot {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                            return Err(error);
                        }
                    };
                    self.schedule_writable_tick(object_id)?;
                    let mut first_callback_error = None;
                    let mut first_callback_error_charge = 0;
                    while self
                        .writable_streams
                        .get(&object_id)
                        .is_some_and(|state| state.end_callback_batch_remaining > 0)
                    {
                        if let Some(state) = self.writable_streams.get_mut(&object_id) {
                            state.end_callback_batch_remaining -= 1;
                        }
                        let Some((end_callback, invocation_charge)) =
                            self.take_writable_end_callback(object_id)
                        else {
                            self.take_first_writable_callback_error(
                                &mut first_callback_error,
                                &mut first_callback_error_charge,
                            );
                            self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                            return Err(InterpreterError::InternalError {
                                details: "Writable write-error callback batch exceeds its FIFO"
                                    .to_string(),
                            });
                        };
                        let mut invocation_charge = invocation_charge;
                        let prepared = (|| {
                            let fallback_label = self.clone_charged_writable_label(
                                &phase_lifecycle_label,
                                &mut invocation_charge,
                            )?;
                            let callback_error = match &phase_terminal_error {
                                Some(_) => self.clone_charged_writable_error(
                                    &phase_terminal_error,
                                    &mut invocation_charge,
                                )?,
                                None => {
                                    let error_label = self.clone_charged_writable_label(
                                        &phase_lifecycle_label,
                                        &mut invocation_charge,
                                    )?;
                                    let error = self.charged_writable_error_value(
                                        "Cannot call end after a stream was destroyed",
                                        &mut invocation_charge,
                                    )?;
                                    Some((error, error_label))
                                }
                            };
                            Ok::<_, InterpreterError>((callback_error, fallback_label))
                        })();
                        let (callback_error, fallback_label) = match prepared {
                            Ok(prepared) => prepared,
                            Err(error) => {
                                let remaining_charge = invocation_charge;
                                self.release_writable_in_flight_charge(
                                    &mut invocation_charge,
                                    remaining_charge,
                                );
                                self.take_first_writable_callback_error(
                                    &mut first_callback_error,
                                    &mut first_callback_error_charge,
                                );
                                self.release_all_writable_in_flight_charge(
                                    &mut phase_snapshot_charge,
                                );
                                return Err(error);
                            }
                        };
                        if let Err(error) = self.invoke_writable_deferred_callback(
                            module,
                            end_callback.callback,
                            object_id,
                            callback_error,
                            fallback_label,
                            invocation_charge,
                        ) && let Err(memory_error) = self.retain_first_writable_callback_error(
                            &mut first_callback_error,
                            &mut first_callback_error_charge,
                            error,
                        ) {
                            self.take_first_writable_callback_error(
                                &mut first_callback_error,
                                &mut first_callback_error_charge,
                            );
                            self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                            return Err(memory_error);
                        }
                    }
                    let result = match self.take_first_writable_callback_error(
                        &mut first_callback_error,
                        &mut first_callback_error_charge,
                    ) {
                        Some(error) => Err(error),
                        None => Ok(()),
                    };
                    drop(phase_lifecycle_label);
                    drop(phase_terminal_error);
                    self.release_all_writable_in_flight_charge(&mut phase_snapshot_charge);
                    return result;
                }
                self.preflight_writable_tick(object_id)?;
                let error_has_handler = self
                    .event_listeners
                    .get(&object_id)
                    .and_then(|by_event| by_event.get(&RuntimePropertyKey::from("error")))
                    .is_some_and(|records| !records.is_empty())
                    || self
                        .event_promise_waiters
                        .get(&object_id)
                        .and_then(|by_event| by_event.get(&RuntimePropertyKey::from("error")))
                        .is_some_and(|records| !records.is_empty());
                let prepared_error_event = if !terminal_error_emitted
                    && self
                        .writable_streams
                        .get(&object_id)
                        .is_some_and(|state| state.terminal_error.is_some())
                {
                    let mut event_charge = 0;
                    let prepared = (|| {
                        let lifecycle_label = self
                            .clone_charged_writable_lifecycle_label(object_id, &mut event_charge)?;
                        let (error, error_label) = self
                            .clone_charged_writable_terminal_error(object_id, &mut event_charge)?
                            .expect("Writable error phase retained terminal error");
                        let emission_label = self.take_dominant_charged_writable_label(
                            lifecycle_label,
                            error_label,
                            &mut event_charge,
                        );
                        Ok::<_, InterpreterError>((error, emission_label))
                    })();
                    let (error, emission_label) = match prepared {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            let remaining_charge = event_charge;
                            self.release_writable_in_flight_charge(
                                &mut event_charge,
                                remaining_charge,
                            );
                            return Err(error);
                        }
                    };
                    Some((error, emission_label, event_charge))
                } else {
                    None
                };
                // Reserve close before publishing the error phase. If the
                // error is unhandled, cancel visibility of that reservation so
                // a reused core cannot later emit close after the fatal edge.
                self.schedule_writable_tick(object_id)?;
                if let Some(state) = self.writable_streams.get_mut(&object_id) {
                    state.tick_phase = WritableTickPhase::Close;
                    state.terminal_error_emitted = true;
                }
                let error_result =
                    if let Some((error, emission_label, event_charge)) = prepared_error_event {
                        self.emit_charged_writable_event_listener_records(
                            module,
                            object_id,
                            "error",
                            vec![error],
                            emission_label,
                            event_charge,
                        )
                    } else {
                        Ok(())
                    };
                // A genuinely unhandled `error` aborts the runtime checkpoint.
                // A registered handler that throws is instead a new guest
                // failure: keep the reserved close turn, matching every other
                // lifecycle listener failure.
                if error_result.is_err()
                    && !error_has_handler
                    && let Some(state) = self.writable_streams.get_mut(&object_id)
                {
                    state.tick_sequence = None;
                }
                error_result?;
                return Ok(());
            }

            if phase == WritableTickPhase::Close {
                if terminal_error_origin.is_none() && !end_callbacks_empty {
                    self.schedule_writable_tick(object_id)?;
                    let Some((end_callback, mut invocation_charge)) =
                        self.take_writable_end_callback(object_id)
                    else {
                        return Err(InterpreterError::InternalError {
                            details: "Writable late callback FIFO became empty".to_string(),
                        });
                    };
                    let prepared = if self
                        .writable_streams
                        .get(&object_id)
                        .is_some_and(|state| state.terminal_error.is_some())
                    {
                        self.charged_writable_terminal_error_inputs(
                            object_id,
                            &mut invocation_charge,
                        )
                    } else {
                        self.charged_writable_synthesized_error_inputs(
                            object_id,
                            "Cannot call end after a stream was finished",
                            &mut invocation_charge,
                        )
                    };
                    let (error, fallback_label) = match prepared {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            let remaining_charge = invocation_charge;
                            self.release_writable_in_flight_charge(
                                &mut invocation_charge,
                                remaining_charge,
                            );
                            return Err(error);
                        }
                    };
                    return self.invoke_writable_deferred_callback(
                        module,
                        end_callback.callback,
                        object_id,
                        error,
                        fallback_label,
                        invocation_charge,
                    );
                }
                self.schedule_writable_tick(object_id)?;
                if let Some(state) = self.writable_streams.get_mut(&object_id) {
                    state.tick_phase = WritableTickPhase::Release;
                }
                if self.readable_from_streams.contains_key(&object_id) {
                    // The readable half performs the sole shared close after
                    // its EOF turn; keep compatibility mirrors open until it
                    // does so, while the writable state advances to tombstone.
                    self.mirror_writable_length(object_id, buffered_length);
                    self.mirror_writable_cork_depth(object_id, cork_depth);
                    return Ok(());
                }
                self.mirror_writable_bool(object_id, "destroyed", true);
                self.mirror_writable_bool(object_id, "closed", true);
                self.mirror_writable_length(object_id, buffered_length);
                self.mirror_writable_cork_depth(object_id, cork_depth);
                let mut event_charge = 0;
                let lifecycle_label =
                    self.clone_charged_writable_lifecycle_label(object_id, &mut event_charge)?;
                return self.emit_charged_writable_event_listener_records(
                    module,
                    object_id,
                    "close",
                    Vec::new(),
                    lifecycle_label,
                    event_charge,
                );
            }

            if !end_callbacks_empty {
                self.schedule_writable_tick(object_id)?;
            }
            if let Some((end_callback, mut invocation_charge)) =
                self.take_writable_end_callback(object_id)
            {
                let prepared = match terminal_error_origin {
                    None => self.charged_writable_synthesized_error_inputs(
                        object_id,
                        "Cannot call end after a stream was finished",
                        &mut invocation_charge,
                    ),
                    Some(WritableErrorOrigin::Final) if !end_callback.registered_after_end => self
                        .charged_writable_terminal_error_inputs(object_id, &mut invocation_charge),
                    Some(_) => self.charged_writable_synthesized_error_inputs(
                        object_id,
                        "Cannot call end after a stream was destroyed",
                        &mut invocation_charge,
                    ),
                };
                let (error, fallback_label) = match prepared {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let remaining_charge = invocation_charge;
                        self.release_writable_in_flight_charge(
                            &mut invocation_charge,
                            remaining_charge,
                        );
                        return Err(error);
                    }
                };
                return self.invoke_writable_deferred_callback(
                    module,
                    end_callback.callback,
                    object_id,
                    error,
                    fallback_label,
                    invocation_charge,
                );
            }
            self.terminalize_writable_state_storage(object_id)?;
            return Ok(());
        }
    }
}
