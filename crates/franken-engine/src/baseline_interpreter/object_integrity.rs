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
                Value::Object(id) => Some(*id),
                value if reflect || value.is_callable() => {
                    return Err(Self::integrity_type_error(
                        "heap object target",
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
