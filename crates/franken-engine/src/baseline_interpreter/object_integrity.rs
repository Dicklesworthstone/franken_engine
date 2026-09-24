//! Object identity operations and the private [[Extensible]] slot.
//!
//! Proxy invariants are checked against the target AFTER the trap runs. A
//! successful trap is not permission to fabricate a new target state. Ordinary
//! prototype-cycle checks inspect private links and stop at exotic boundaries;
//! they must not invoke a proposed prototype's getPrototypeOf trap.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum ObjectIntegrityOperation {
    GetPrototype,
    SetPrototype,
    IsExtensible,
    PreventExtensions,
}

impl InterpreterCore {
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

    fn object_get_prototype(
        &mut self,
        module: Option<&Ir3Module>,
        id: ObjectId,
        depth: u32,
    ) -> Result<Value, InterpreterError> {
        self.integrity_step(id, depth)?;
        let Some((target, handler)) = self.active_proxy_record(id)? else {
            return Ok(self.heap[id.0 as usize]
                .prototype
                .map_or(Value::Null, Value::Object));
        };
        let Some(result) = self.invoke_proxy_trap(
            module,
            handler,
            "getPrototypeOf",
            vec![Value::Object(target)],
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
                    Value::Object(target),
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
        if self.heap[id.0 as usize].prototype == prototype {
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
            current = self.heap[candidate.0 as usize].prototype;
            walked += 1;
        }
        if self.active_inline_callback_context_label.is_some() {
            self.reflect_admit_mutation_label(id)?;
        }
        self.mutate_heap(|heap| heap[id.0 as usize].prototype = prototype);
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
        let Some(result) =
            self.invoke_proxy_trap(module, handler, "isExtensible", vec![Value::Object(target)])?
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
            vec![Value::Object(target)],
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
