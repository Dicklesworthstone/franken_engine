//! ES2020 9.4.4: a sloppy, simple-parameter arguments object shares its
//! indexed values with the invocation's lexical parameter cells.
//!
//! The visible indices stay ordinary data properties. Publishing a cell write
//! updates that property and its IFC label atomically with the cell's charge,
//! so every existing reflection, iteration and serialization path observes
//! the same value. The private parameter map owns the cell; the reverse index
//! is weak and does not make an otherwise unreachable arguments object live.

use super::*;

impl InterpreterCore {
    pub(super) fn has_mapped_arguments_target(&self, args: RegRange) -> bool {
        if self.mapped_argument_bindings.is_empty() || args.count == 0 {
            return false;
        }
        let Ok(Value::Object(mut object)) = self.read_reg(args.start) else {
            return false;
        };
        // Inspect only private proxy slots, preserving all observable trap,
        // conversion and revocation checks in the actual definition.
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            if self.mapped_argument_bindings.contains_key(&object) {
                return true;
            }
            let Some(proxy) = self.heap.get(object.0 as usize) else {
                return false;
            };
            if proxy.brand() != Some(PROXY_TYPE_TAG) {
                return false;
            }
            let Some(Value::Object(target)) = proxy.properties.get(PROXY_TARGET_SLOT) else {
                return false;
            };
            object = *target;
        }
        false
    }

    pub(super) fn dispatch_mapped_arguments_definition(
        &mut self,
        cap: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        let end =
            args.start
                .checked_add(args.count)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
        let observation = self.begin_property_observation(args.start..end)?;
        let outcome = self.dispatch_builtin_hostcall_inner(cap, args, module);
        self.finish_property_read_observation(observation, outcome)
    }

    pub(super) fn mapped_argument_binding(
        &self,
        object: ObjectId,
        key: &str,
    ) -> Option<ScopeBinding> {
        let bindings = self.mapped_argument_bindings.get(&object)?;
        let index = Self::canonical_array_index_key(key)?;
        bindings.get(&index).cloned()
    }

    fn mapped_argument_entry_bytes() -> u64 {
        // Forward entry, reverse entry, and their inline keys/handles. The
        // shared cell payload is charged once by ColdBindingCells.
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_mul(2)
            .saturating_add(std::mem::size_of::<(u32, ScopeBinding)>() as u64)
            .saturating_add(std::mem::size_of::<(usize, (ObjectId, u32))>() as u64)
    }

    fn mapped_argument_map_bytes() -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_add(std::mem::size_of::<(ObjectId, BTreeMap<u32, ScopeBinding>)>() as u64)
    }

    pub(super) fn mapped_argument_bindings_memory_bytes(&self) -> u64 {
        Self::saturating_sum(self.mapped_argument_bindings.values().map(|bindings| {
            Self::mapped_argument_map_bytes().saturating_add(
                Self::mapped_argument_entry_bytes().saturating_mul(bindings.len() as u64),
            )
        }))
    }

    /// Link one present actual argument to the already initialized parameter
    /// cell. Lowering emits only the rightmost occurrence of a duplicate name,
    /// including when that occurrence has no actual argument.
    pub(super) fn map_argument_to_parameter(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let invalid = || InterpreterError::InternalError {
            details: "invalid mapped-arguments initialization".to_string(),
        };
        if args.count != 3 {
            return Err(invalid());
        }
        let Value::Object(object_id) = self.read_reg(args.start)? else {
            return Err(invalid());
        };
        let index_register = args.start.checked_add(1).ok_or_else(invalid)?;
        let name_register = args.start.checked_add(2).ok_or_else(invalid)?;
        let Value::Int(index) = self.read_reg(index_register)? else {
            return Err(invalid());
        };
        let index = u32::try_from(index).map_err(|_| invalid())?;
        let Value::Str(name) = self.read_reg(name_register)? else {
            return Err(invalid());
        };
        let name = name.as_str().ok_or_else(invalid)?;
        let object = self.heap.get(object_id.0 as usize).ok_or_else(invalid)?;
        if object.brand() != Some("Arguments") {
            return Err(invalid());
        }
        // Missing parameters do not become indexed properties, even if guest
        // code later creates such a property on the arguments object.
        if !object.properties.contains_key(&index.to_string()) {
            return Ok(Value::Object(object_id));
        }
        let binding = self
            .scope_chain
            .resolve(name)
            .map(|(_, binding)| binding.clone())
            .ok_or_else(invalid)?;
        if binding.kind.is_immutable() || !binding.state()?.initialized {
            return Err(invalid());
        }
        let cell_key = ColdBindingCells::key(&binding.state);
        if self.mapped_argument_aliases.contains_key(&cell_key)
            || self
                .mapped_argument_bindings
                .get(&object_id)
                .is_some_and(|bindings| bindings.contains_key(&index))
        {
            return Err(invalid());
        }
        let added = Self::mapped_argument_entry_bytes().saturating_add(
            if self.mapped_argument_bindings.contains_key(&object_id) {
                0
            } else {
                Self::mapped_argument_map_bytes()
            },
        );
        // The initialized cell is already charged by the active scope, so
        // registering it merely moves ownership into the shared-cell ledger.
        self.apply_memory_component_delta(0, added)?;
        self.closures.cold_cells.register_cell(&binding.state);
        self.mapped_argument_bindings
            .entry(object_id)
            .or_default()
            .insert(index, binding);
        self.mapped_argument_aliases
            .insert(cell_key, (object_id, index));
        let cell = Rc::clone(&self.mapped_argument_bindings[&object_id][&index].state);
        let cell_bytes = Self::estimate_binding_cell_payload_bytes(&cell);
        if let Err(error) = self.publish_mapped_argument_cell(object_id, index, cell_bytes, &cell) {
            self.disconnect_mapped_argument(object_id, &index.to_string());
            return Err(error);
        }
        Ok(Value::Object(object_id))
    }

    /// Commit a parameter-cell write and its mapped data-property mirror.
    /// The caller owns the old cell state and restores it if this preflight
    /// refuses. No heap/seed mutation is performed before the whole charge
    /// (cell, property value and property label) is accepted.
    pub(super) fn publish_mapped_argument_cell(
        &mut self,
        object_id: ObjectId,
        index: u32,
        previous_payload_bytes: u64,
        cell: &Rc<RefCell<ScopeBindingState>>,
    ) -> Result<u64, InterpreterError> {
        let (value, label) = {
            let state = cell
                .try_borrow()
                .map_err(|_| InterpreterError::InternalError {
                    details: "mapped argument cell is already mutably borrowed".to_string(),
                })?;
            (state.value.clone(), state.label.clone())
        };
        let key = index.to_string();
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        let old_value =
            object
                .properties
                .get(&key)
                .ok_or_else(|| InterpreterError::InternalError {
                    details: "mapped argument lost its own data property".to_string(),
                })?;
        let old_value_bytes = Self::estimate_value_bytes(old_value);
        let label_bytes = |label: &Label| {
            MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                .saturating_add(Self::estimate_string_bytes(&key).saturating_mul(2))
                .saturating_add(Self::estimate_label_bytes(label))
        };
        let old_label_bytes = object.property_labels.get(&key).map_or(0, label_bytes);
        let new_label_bytes = if matches!(label, Label::Public) {
            0
        } else {
            label_bytes(&label)
        };
        let next = self.apply_memory_component_delta(
            previous_payload_bytes
                .saturating_add(old_value_bytes)
                .saturating_add(old_label_bytes),
            Self::estimate_binding_cell_payload_bytes(cell)
                .saturating_add(Self::estimate_value_bytes(&value))
                .saturating_add(new_label_bytes),
        )?;
        self.mutate_heap(|heap| {
            let object = &mut heap[object_id.0 as usize];
            *object
                .properties
                .get_mut(&key)
                .expect("mapped argument exists") = value;
            if matches!(label, Label::Public) {
                object.property_labels.remove(&key);
            } else {
                object.property_labels.insert(key, label);
            }
        });
        self.gc_write_barrier(object_id);
        Ok(next)
    }

    pub(super) fn set_mapped_argument_value(
        &mut self,
        binding: ScopeBinding,
        value: Option<Value>,
        label: Option<&Label>,
    ) -> Result<(), InterpreterError> {
        let previous = binding.snapshot_state()?;
        let previous_bytes = Self::estimate_binding_cell_payload_bytes(&binding.state);
        // Descriptor definitions and Reflect stores admit the receiver's
        // mutation provenance before writing its data. Carry that floor into
        // the parameter too, including a definition that immediately removes
        // the mapping with writable:false.
        let value_label = if value.is_some() {
            let mut next = label.unwrap_or(&previous.label).clone();
            if let Some(context) = self.active_execution_context_label() {
                next = next.join(context);
            }
            if let Some((object, _)) = self
                .mapped_argument_aliases
                .get(&ColdBindingCells::key(&binding.state))
                && let Some(mutation) = self.object_mutation_labels.get(object)
            {
                next = next.join(mutation);
            }
            Some(next)
        } else {
            // SetProperty stages its new label before running a Proxy trap.
            // That trap may still read the OLD parameter/property value, or
            // reject the write altogether. A label-only stage must therefore
            // never lower that value's provenance before an actual commit.
            label.map(|label| previous.label.join(label))
        };
        {
            let mut state = binding.state_mut()?;
            if let Some(value) = value {
                state.value = value;
            }
            if let Some(label) = value_label {
                state.label = label;
            }
        }
        self.closures.refresh_cell(&binding.state);
        if let Err(error) = self.apply_scope_cell_write_delta(previous_bytes, &binding.state) {
            binding.restore_state(previous)?;
            self.closures.refresh_cell(&binding.state);
            return Err(error);
        }
        Ok(())
    }

    /// Disconnect only after a successful delete/descriptor transition. The
    /// ordinary property already contains the cell's latest value and label.
    pub(super) fn disconnect_mapped_argument(&mut self, object_id: ObjectId, key: &str) {
        let Some(index) = Self::canonical_array_index_key(key) else {
            return;
        };
        let Some(binding) = self
            .mapped_argument_bindings
            .get(&object_id)
            .and_then(|bindings| bindings.get(&index))
            .cloned()
        else {
            return;
        };
        let before_cells = self.scope_chain_memory_bytes();
        let bindings = self
            .mapped_argument_bindings
            .get_mut(&object_id)
            .expect("mapped object exists");
        bindings.remove(&index);
        let empty = bindings.is_empty();
        self.mapped_argument_aliases
            .remove(&ColdBindingCells::key(&binding.state));
        self.closures.cold_cells.release_cell(&binding.state);
        let released_map = if empty {
            self.mapped_argument_bindings.remove(&object_id);
            Self::mapped_argument_map_bytes()
        } else {
            0
        };
        let released = Self::mapped_argument_entry_bytes()
            .saturating_add(released_map)
            .saturating_add(before_cells.saturating_sub(self.scope_chain_memory_bytes()));
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
    }

    pub(super) fn disconnect_all_mapped_arguments(&mut self, object_id: ObjectId) {
        let Some(indices) = self
            .mapped_argument_bindings
            .get(&object_id)
            .map(|bindings| bindings.keys().copied().collect::<Vec<_>>())
        else {
            return;
        };
        for index in indices {
            self.disconnect_mapped_argument(object_id, &index.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::ParseGoal;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use crate::parser::{CanonicalEs2020Parser, ParserOptions};

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]);
        InterpreterCore::new(config, "mapped-arguments-bd-9vouw-281")
    }

    fn lower(source: &str) -> Ir3Module {
        let tree = CanonicalEs2020Parser
            .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
            .expect("mapped-arguments source parses");
        lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "mapped-arguments.js"),
            &LoweringContext::new("mapped-arguments", "mapped-decision", "mapped-policy"),
        )
        .expect("mapped-arguments source lowers")
        .ir3
    }

    fn fixture() -> (InterpreterCore, ObjectId, ScopeBinding) {
        let mut core = core();
        core.scope_chain.push(core.config.max_scope_depth).unwrap();
        let binding = ScopeBinding::with_state(BindingKind::Var, Value::Int(1), true);
        core.scope_chain
            .current_mut()
            .unwrap()
            .insert_binding("parameter".into(), binding.clone());
        core.sync_estimated_memory_bytes().unwrap();
        let object = core
            .alloc_arguments_object(&[Value::Int(1)], ArgumentsCallee::Omitted)
            .unwrap();
        core.write_reg(0, Value::Object(object)).unwrap();
        core.write_reg(1, Value::Int(0)).unwrap();
        core.write_reg(2, Value::str("parameter")).unwrap();
        core.map_argument_to_parameter(RegRange { start: 0, count: 3 })
            .unwrap();
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        (core, object, binding)
    }

    #[test]
    fn mapped_value_and_label_growth_are_atomic_and_exactly_accounted() {
        let (mut core, object, binding) = fixture();
        let before = core.estimated_memory_bytes();
        let value = Value::str("mapped strings have both a cell and an ordinary property carrier");
        let growth = 2 * InterpreterCore::estimate_value_bytes(&value);
        core.config.max_total_memory_bytes = before + growth - 1;
        assert!(matches!(
            core.set_object_property(object, "0".into(), value.clone()),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(binding.value().unwrap(), Value::Int(1));
        assert_eq!(
            core.heap[object.0 as usize].properties.get("0"),
            Some(&Value::Int(1))
        );
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );

        core.config.max_total_memory_bytes = before + growth;
        core.set_object_property(object, "0".into(), value.clone())
            .unwrap();
        assert_eq!(binding.value().unwrap(), value);
        assert_eq!(core.estimated_memory_bytes(), before + growth);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        let before_label = core.estimated_memory_bytes();
        assert!(matches!(
            core.set_own_property_label(object, "0", &Label::Secret),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(binding.label().unwrap(), Label::Public);
        assert_eq!(core.own_property_label(object, "0"), Label::Public);
        assert_eq!(core.estimated_memory_bytes(), before_label);
        core.config.max_total_memory_bytes = u64::MAX;
        core.set_own_property_label(object, "0", &Label::Secret)
            .unwrap();
        assert_eq!(binding.label().unwrap(), Label::Secret);
        assert_eq!(core.own_property_label(object, "0"), Label::Secret);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );

        core.set_own_property_attributes(
            object,
            &RuntimePropertyKey::String(JsString::from("0")),
            PropertyAttributes {
                writable: false,
                ..PropertyAttributes::DEFAULT
            },
        )
        .unwrap();
        assert!(core.mapped_argument_bindings.is_empty());
        assert!(core.mapped_argument_aliases.is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn reachable_arguments_own_cells_but_reverse_aliases_are_not_gc_roots() {
        let (mut core, arguments, binding) = fixture();
        let child = core
            .alloc_object_with_properties(&[("kept", Value::Int(7))])
            .unwrap();
        core.set_object_property(arguments, "0".into(), Value::Object(child))
            .unwrap();
        core.scope_chain.pop().unwrap();
        core.sync_estimated_memory_bytes().unwrap();
        core.gc_safe_point();
        assert!(!core.heap.is_reclaimed(arguments.0 as usize));
        assert!(!core.heap.is_reclaimed(child.0 as usize));
        assert_eq!(binding.value().unwrap(), Value::Object(child));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );

        // Keep the parameter in a lexical scope while dropping the arguments
        // object. The weak reverse table must not retain that object.
        core.scope_chain
            .current_mut()
            .unwrap()
            .insert_binding("kept_parameter".into(), binding.clone());
        core.write_reg(0, Value::Undefined).unwrap();
        core.sync_estimated_memory_bytes().unwrap();
        core.gc_safe_point();
        assert!(core.heap.is_reclaimed(arguments.0 as usize));
        assert!(!core.heap.is_reclaimed(child.0 as usize));
        assert!(core.mapped_argument_bindings.is_empty());
        assert!(core.mapped_argument_aliases.is_empty());
        core.put_runtime_name("kept_parameter", Value::Int(9), false)
            .unwrap();
        core.gc_safe_point();
        assert!(core.heap.is_reclaimed(child.0 as usize));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn mapped_stores_preserve_ifc_at_the_real_console_boundary() {
        for body in [
            "a = classified; return arguments[0];",
            "arguments[0] = classified; return a;",
            "Reflect.set(arguments, '0', classified); return a;",
            "Object.defineProperty(arguments, '0', { value: classified, writable: false }); return a;",
            "Object.defineProperty(new Proxy(arguments, {}), '0', { value: classified, writable: false }); return a;",
            "Object.defineProperties(arguments, { 0: { value: classified, writable: false } }); return a;",
            "Object.defineProperty(arguments, '0', { get value() { return classified; }, writable: false }); return a;",
        ] {
            let source =
                format!("var classified = 314159; function f(a) {{ {body} }} console.log(f(1));");
            let mut module = lower(&source);
            let literal = module
                .instructions
                .iter_mut()
                .find(|instruction| {
                    matches!(instruction, Ir3Instruction::LoadInt { value: 314159, .. })
                })
                .expect("the classified source literal");
            let Ir3Instruction::LoadInt { dst, .. } = literal else {
                unreachable!()
            };
            *literal = Ir3Instruction::Move {
                dst: *dst,
                src: 200,
            };
            for label in [Label::Public, Label::Secret] {
                let mut core = core();
                core.write_reg_with_label(200, Value::Int(42), label.clone())
                    .unwrap();
                let result = core.execute(&module);
                if label == Label::Public {
                    let result = result.unwrap_or_else(|error| panic!("{body}: {error:?}"));
                    assert_eq!(result.console_output.len(), 1, "{body}");
                    assert_eq!(result.console_output[0].message, "42", "{body}");
                } else {
                    assert!(
                        matches!(result, Err(InterpreterError::CapabilityDenied { capability })
                        if capability == "console:log:confidentiality"),
                        "{body}"
                    );
                    assert!(core.console_output().is_empty(), "{body}");
                }
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes(),
                    "{body}"
                );
            }
        }
    }

    #[test]
    fn proxy_set_cannot_relabel_an_old_mapped_value_before_its_trap() {
        for read in ["a", "original[0]"] {
            for accepted in ["true", "false"] {
                let source = format!(
                    "var classified = 314159; function f(a) {{ a = classified; \
                    var original = arguments; var proxy = new Proxy(original, {{ set(t, k, v) {{ \
                    console.log({read}); return {accepted}; }} }}); proxy[0] = 0; }} f(1);"
                );
                let mut module = lower(&source);
                let literal = module
                    .instructions
                    .iter_mut()
                    .find(|instruction| {
                        matches!(instruction, Ir3Instruction::LoadInt { value: 314159, .. })
                    })
                    .expect("classified literal");
                let Ir3Instruction::LoadInt { dst, .. } = literal else {
                    unreachable!()
                };
                *literal = Ir3Instruction::Move {
                    dst: *dst,
                    src: 200,
                };
                for label in [Label::Public, Label::Secret] {
                    let mut core = core();
                    core.write_reg_with_label(200, Value::Int(42), label.clone())
                        .unwrap();
                    let result = core.execute(&module);
                    if label == Label::Public {
                        let result = result.expect("public proxy trap remains executable");
                        assert_eq!(result.console_output.len(), 1);
                        assert_eq!(result.console_output[0].message, "42");
                    } else {
                        assert!(
                            matches!(result, Err(InterpreterError::CapabilityDenied { capability })
                            if capability == "console:log:confidentiality"),
                            "{read}, {accepted}"
                        );
                        assert!(core.console_output().is_empty());
                    }
                    assert_eq!(
                        core.estimated_memory_bytes(),
                        core.recompute_estimated_memory_bytes()
                    );
                }
            }
        }
    }

    #[test]
    fn escaped_mapped_arguments_survive_gc_stress_and_repeat_execution() {
        let module = lower(
            "function f(a) { return [arguments, value => a = value, () => a]; } \
            var pair = f({ value: 1 }); for (var i = 0; i < 80; i++) { var garbage = { i }; } \
            pair[1]({ value: 7 }); var first = pair[0][0].value; pair[0][0] = { value: 9 }; \
            first + pair[2]().value;",
        );
        let mut core = core();
        core.set_gc_stress_interval(Some(1));
        for _ in 0..2 {
            let result = core
                .execute(&module)
                .expect("mapped cells survive collection and reset");
            assert_eq!(result.value, Value::Int(16));
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}
