//! Side-effect-free selection between element storage and ordinary [[Set]].
//!
//! A true Array can still have accessors, read-only indices, holes or a Proxy
//! prototype. Its mutators must then use the existing generic property engine.
//! Do not validate by invoking getters: selection must not reorder observable
//! operations. In particular, push/pop inspect only their tail, not all of the
//! existing elements, so repeated appends/removals do not acquire an O(n) guard.

use super::*;

impl InterpreterCore {
    pub(super) fn array_mutation_requires_generic(
        &self,
        array: ObjectId,
        kind: BuiltinFunctionKind,
        args: RegRange,
    ) -> Result<bool, InterpreterError> {
        use BuiltinFunctionKind as K;
        // This guard is shared by true-Array dispatch. Mutations caused by
        // iteration callbacks/species/getters need the live cursor as well;
        // do not send a huge sparse receiver back to a logical-length scan.
        if self.sparse_array_iteration_requires_generic(array, kind) {
            return Ok(true);
        }
        if !matches!(
            kind,
            K::ArrayPush
                | K::ArrayPop
                | K::ArrayShift
                | K::ArrayUnshift
                | K::ArrayReverse
                | K::ArrayFill
        ) {
            return Ok(false);
        }
        let Some(object) = self.heap.get(array.0 as usize) else {
            return Ok(true);
        };
        let Some(length) = mutation_length(object) else {
            return Ok(true);
        };
        // These checks select the spec path, not an early exception: an empty
        // operation may succeed and a refusal may follow earlier visible writes.
        if !object.is_array || object.is_frozen || object.is_non_extensible {
            return Ok(true);
        }
        match kind {
            K::ArrayPush => {
                if args.count == 0 {
                    return Ok(false); // The caller separately guards length.
                }
                if !append_targets_absent(object, length, args.count) {
                    return Ok(true);
                }
                Ok(!self.array_mutation_plain_prototypes(array)?)
            }
            K::ArrayPop => Ok(!pop_can_use_storage(object, length)),
            K::ArrayUnshift if args.count == 0 => Ok(false),
            K::ArrayFill => {
                // A one-element fill must not scan the rest of a large array.
                // Only already-primitive numeric bounds are inspected here;
                // other conversions stay on the ordinary, observable path.
                let Some(start) = primitive_index(self.builtin_arg(args, 1)?, length, 0) else {
                    return Ok(true);
                };
                let Some(end) = primitive_index(self.builtin_arg(args, 2)?, length, length) else {
                    return Ok(true);
                };
                Ok(!plain_writable_range(object, start, end))
            }
            _ => {
                // Bulk moves already visit O(n) elements. An accessor or hole
                // can invoke guest code, which can change later destinations;
                // execute the WHOLE method generically, not just that element.
                if !self.array_has_dense_data_elements(array) {
                    return Ok(true);
                }
                if kind == K::ArrayShift && !pop_can_use_storage(object, length) {
                    return Ok(true);
                }
                if kind == K::ArrayUnshift {
                    return Ok(!append_targets_absent(object, length, args.count)
                        || !self.array_mutation_plain_prototypes(array)?);
                }
                Ok(false)
            }
        }
    }

    /// A new index may encounter a setter or a read-only inherited property.
    /// Reject exotic prototypes without asking their traps or getters anything.
    /// No receiver scan: normal push remains proportional to the appended count
    /// plus the bounded prototype depth, irrespective of the array's length.
    fn array_mutation_plain_prototypes(&self, array: ObjectId) -> Result<bool, InterpreterError> {
        let Some(object) = self.heap.get(array.0 as usize) else {
            return Ok(false);
        };
        let mut current = self.observable_prototype_link(object, array);
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(id) = current else {
                return Ok(true);
            };
            if self.proxy_record(id)?.is_some() {
                return Ok(false);
            }
            let Some(object) = self.heap.get(id.0 as usize) else {
                return Ok(false);
            };
            if object.properties.has_index_keys()
                || object.typed_array.is_some()
                || object.primitive_value.is_some()
            {
                return Ok(false);
            }
            current = self.observable_prototype_link(object, id);
        }
        Ok(current.is_none())
    }
}

fn mutation_length(object: &HeapObject) -> Option<u32> {
    let Value::Int(length) = object.properties.get("length")? else {
        return None;
    };
    u32::try_from(*length).ok()
}

fn primitive_index(value: Option<Value>, length: u32, default: u32) -> Option<u32> {
    let number = match value {
        None | Some(Value::Undefined) => return Some(default),
        Some(Value::Int(value)) => value as f64,
        Some(Value::Float(value)) => value.inner(),
        _ => return None,
    };
    let integer = if number.is_nan() { 0.0 } else { number.trunc() };
    Some(if integer < 0.0 {
        (f64::from(length) + integer).max(0.0) as u32
    } else {
        integer.min(f64::from(length)) as u32
    })
}

pub(super) fn plain_writable_range(object: &HeapObject, start: u32, end: u32) -> bool {
    range_with_keys(object, start, end, |index| {
        InterpreterCore::generic_index_key(u64::from(index))
    })
}

fn range_with_keys(
    object: &HeapObject,
    start: u32,
    end: u32,
    mut key: impl FnMut(u32) -> RuntimePropertyKey,
) -> bool {
    if start >= end {
        return true;
    }
    if object.is_frozen {
        return false;
    }
    // No overrides is an exact proof that every present numeric data property
    // is writable. Array length's special attributes do not apply to indices.
    // Ordinary dense guards now inspect numeric storage without formatting or
    // allocating a property name per element. Decorated objects retain point
    // lookups: even a one-element fill must not scan a huge named dictionary.
    let default_attributes = object.property_attributes.is_empty();
    (start..end).all(|index| {
        !matches!(
            object.properties.get_index(index),
            None | Some(Value::Accessor { .. })
        ) && (default_attributes || object.own_property_attributes(&key(index)).writable)
    })
}

fn append_targets_absent(object: &HeapObject, length: u32, count: u32) -> bool {
    let Some(end) = length.checked_add(count) else {
        // Keep the spec's partial writes and final invalid-length exception.
        return false;
    };
    (length..end).all(|index| object.properties.get_index(index).is_none())
}

fn pop_can_use_storage(object: &HeapObject, length: u32) -> bool {
    let Some(last) = length.checked_sub(1) else {
        return true;
    };
    if matches!(
        object.properties.get_index(last),
        None | Some(Value::Accessor { .. })
    ) {
        return false;
    }
    // Pop reads and deletes, but does not write this index. A non-writable
    // configurable tail is legal; a non-configurable one must throw in order.
    !object.is_frozen
        && (object.property_attributes.is_empty()
            || object
                .own_property_attributes(&InterpreterCore::generic_index_key(u64::from(last)))
                .configurable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn array(length: u32) -> HeapObject {
        let mut object = HeapObject::new();
        object.is_array = true;
        object
            .properties
            .insert("length".to_string(), Value::Int(i64::from(length)));
        object
    }

    #[test]
    fn generic_mutators_preserve_consumed_argument_and_source_labels_bd_ojvo1() {
        use BuiltinFunctionKind as K;
        let tree = crate::parser_api_stability::parse_script("0").unwrap();
        let module = crate::lowering_pipeline::lower_ir0_to_ir3(
            &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "generic-mutation-labels.js"),
            &crate::lowering_pipeline::LoweringContext::new("mutate", "labels", "builtin-only"),
        )
        .unwrap()
        .ir3;
        for throughput in [false, true] {
            for label in [Label::Public, Label::Secret] {
                for kind in [
                    K::ArrayUnshift,
                    K::ArrayFill,
                    K::ArraySplice,
                    K::ArrayShift,
                    K::ArrayCopyWithin,
                ] {
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
                    let mut core = InterpreterCore::new(config, "generic-mutation-labels");
                    let object = core.alloc_object_with_prototype(None).unwrap();
                    let length = match kind {
                        K::ArrayFill => 1,
                        K::ArrayShift | K::ArrayCopyWithin => 2,
                        _ => 0,
                    };
                    core.set_object_property(object, "length".into(), Value::Int(length))
                        .unwrap();
                    for index in 0..length {
                        core.set_object_property(object, index.to_string(), Value::Int(9))
                            .unwrap();
                    }
                    let (builtin, values, stored_index) = match kind {
                        K::ArrayUnshift => (
                            BuiltinFunction::array_unshift(),
                            vec![(7, label.clone())],
                            0,
                        ),
                        K::ArrayFill => {
                            (BuiltinFunction::array_fill(), vec![(7, label.clone())], 0)
                        }
                        K::ArraySplice => (
                            BuiltinFunction::array_splice(),
                            vec![(0, Label::Public), (0, Label::Public), (7, label.clone())],
                            0,
                        ),
                        K::ArrayShift | K::ArrayCopyWithin => {
                            let source_index = if kind == K::ArrayShift { "1" } else { "0" };
                            core.set_object_property(object, source_index.into(), Value::Int(7))
                                .unwrap();
                            core.set_own_property_label(object, source_index, &label)
                                .unwrap();
                            if kind == K::ArrayShift {
                                (BuiltinFunction::array_shift(), Vec::new(), 0)
                            } else {
                                (
                                    BuiltinFunction::array_copy_within(),
                                    vec![
                                        (1, Label::Public),
                                        (0, Label::Public),
                                        (1, Label::Public),
                                    ],
                                    1,
                                )
                            }
                        }
                        _ => unreachable!(),
                    };
                    let args = RegRange {
                        start: 0,
                        count: values.len() as u32,
                    };
                    for (register, (value, label)) in (0..).zip(values) {
                        core.write_reg_with_label(register, Value::Int(value), label)
                            .unwrap();
                    }
                    assert_eq!(
                        core.generic_array_receiver(
                            &module,
                            kind,
                            false,
                            Some(&Value::Object(object)),
                            args
                        )
                        .unwrap(),
                        Some(object)
                    );
                    let result = core
                        .dispatch_builtin_function(
                            &module,
                            &builtin,
                            args,
                            Some(Value::Object(object)),
                            None,
                        )
                        .unwrap();
                    match kind {
                        K::ArrayUnshift => assert_eq!(result, Value::Int(1)),
                        K::ArrayShift => assert_eq!(result, Value::Int(9)),
                        K::ArraySplice => {
                            let Value::Object(removed) = result else {
                                panic!("removed array");
                            };
                            assert_ne!(removed, object);
                            assert_eq!(
                                core.heap[removed.0 as usize].properties.get("length"),
                                Some(&Value::Int(0))
                            );
                        }
                        _ => assert_eq!(result, Value::Object(object)),
                    }
                    assert_eq!(
                        core.heap[object.0 as usize]
                            .properties
                            .get_index(stored_index),
                        Some(&Value::Int(7))
                    );
                    assert_eq!(
                        core.own_property_label(object, &stored_index.to_string()),
                        label,
                        "{kind:?}"
                    );
                    assert_eq!(core.json_parse_temporary_bytes, 0);
                    assert_eq!(
                        core.estimated_memory_bytes(),
                        core.recompute_estimated_memory_bytes()
                    );
                }
            }
        }
    }

    #[test]
    fn generic_hole_moves_retain_deletion_control_provenance_on_public_aliases() {
        for label in [Label::Public, Label::Secret] {
            let mut config = InterpreterConfig::quickjs_defaults();
            config
                .granted_capabilities
                .insert(RuntimeCapability::HeapAllocate);
            let mut core = InterpreterCore::new(config, "generic-hole-labels");
            let object = core.alloc_object_with_prototype(None).unwrap();
            core.set_object_property(object, "1".into(), Value::Int(9))
                .unwrap();
            core.write_reg_with_label(0, Value::Object(object), Label::Public)
                .unwrap();
            // A sensitive HasProperty/length observation can leave this
            // scoped floor even when no source value exists to be copied.
            core.generic_species_scope(|core| {
                core.json_observe_label(label.clone())?;
                core.generic_move(None, object, 0, 1)
            })
            .unwrap();
            assert_eq!(core.read_reg(0).unwrap(), Value::Object(object));
            assert_eq!(core.get_register_label(0).unwrap(), &Label::Public);
            assert_eq!(core.heap[object.0 as usize].properties.get_index(1), None);
            // A deleted property has no stored value label. Read its absence
            // in a fresh operation so only the retained shape provenance can
            // protect this public alias, without a leftover result label.
            core.replace_pending_hostcall_result_label(None).unwrap();
            let observed = core
                .generic_species_scope(|core| {
                    assert_eq!(
                        core.generic_get(None, object, &InterpreterCore::generic_index_key(1))?,
                        Value::Undefined
                    );
                    core.json_parse_context_label()
                })
                .unwrap();
            assert_eq!(observed, label);
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn generic_push_preserves_argument_labels_and_preflights_custom_names_bd_ojvo1() {
        let tree = crate::parser_api_stability::parse_script("0").unwrap();
        let module = crate::lowering_pipeline::lower_ir0_to_ir3(
            &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "generic-push-labels.js"),
            &crate::lowering_pipeline::LoweringContext::new("push", "labels", "builtin-only"),
        )
        .unwrap()
        .ir3;
        for throughput in [false, true] {
            for is_array in [false, true] {
                for label in [
                    Label::Public,
                    Label::Secret,
                    Label::Custom {
                        name: "push-input".repeat(512),
                        level: 6,
                    },
                ] {
                    for allow_headroom in [false, true] {
                        if !allow_headroom && !matches!(&label, Label::Custom { .. }) {
                            continue;
                        }
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
                        let mut core = InterpreterCore::new(config, "generic-push-labels");
                        let object = if is_array {
                            // The low-level allocator leaves length absent,
                            // selecting the same generic path as array-likes.
                            core.alloc_array_with_prototype(None).unwrap()
                        } else {
                            let object = core.alloc_object_with_prototype(None).unwrap();
                            core.set_object_property(object, "length".into(), Value::Int(0))
                                .unwrap();
                            object
                        };
                        core.write_reg_with_label(0, Value::Int(7), label.clone())
                            .unwrap();
                        let args = RegRange { start: 0, count: 1 };
                        assert_eq!(
                            core.generic_array_receiver(
                                &module,
                                BuiltinFunctionKind::ArrayPush,
                                false,
                                Some(&Value::Object(object)),
                                args,
                            )
                            .unwrap(),
                            Some(object)
                        );
                        let before = core.estimated_memory_bytes();
                        if !allow_headroom {
                            core.config.max_total_memory_bytes =
                                before + InterpreterCore::estimate_label_bytes(&label) - 1;
                        }
                        let result = core.dispatch_builtin_function(
                            &module,
                            &BuiltinFunction::array_push(),
                            args,
                            Some(Value::Object(object)),
                            None,
                        );
                        if allow_headroom {
                            assert_eq!(result.unwrap(), Value::Int(1));
                            assert_eq!(
                                core.heap[object.0 as usize].properties.get_index(0),
                                Some(&Value::Int(7))
                            );
                            assert_eq!(core.own_property_label(object, "0"), label);
                        } else {
                            assert!(matches!(
                                result,
                                Err(InterpreterError::MemoryBudgetExceeded { .. })
                            ));
                            assert_eq!(core.heap[object.0 as usize].properties.get_index(0), None);
                            assert_eq!(core.estimated_memory_bytes(), before);
                        }
                        assert_eq!(core.json_parse_temporary_bytes, 0);
                        assert_eq!(
                            core.estimated_memory_bytes(),
                            core.recompute_estimated_memory_bytes()
                        );
                    }
                }
            }
        }
    }

    fn bd_ojvo1_test_core() -> (Ir3Module, InterpreterCore) {
        let tree = crate::parser_api_stability::parse_script("0").unwrap();
        let module = crate::lowering_pipeline::lower_ir0_to_ir3(
            &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "bd-ojvo1.js"),
            &crate::lowering_pipeline::LoweringContext::new("ojvo1", "labels", "builtin-only"),
        )
        .unwrap()
        .ir3;
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        (module, InterpreterCore::new(config, "bd-ojvo1"))
    }

    fn bd_ojvo1_generic_triple(core: &mut InterpreterCore) -> ObjectId {
        let object = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(object, "length".into(), Value::Int(3))
            .unwrap();
        for (idx, val) in [("0", 10), ("1", 20), ("2", 30)] {
            core.set_object_property(object, idx.into(), Value::Int(val))
                .unwrap();
        }
        object
    }

    #[test]
    fn generic_relative_index_labels_and_noop_omitted_precision_bd_ojvo1() {
        use BuiltinFunctionKind as K;

        // 1. Fill: Secret relative start taints written slot; empty range + unconsumed reg stay Public.
        {
            let (module, mut core) = bd_ojvo1_test_core();
            let object = bd_ojvo1_generic_triple(&mut core);
            core.write_reg_with_label(0, Value::Int(7), Label::Public)
                .unwrap();
            core.write_reg_with_label(1, Value::Int(-2), Label::Secret)
                .unwrap();
            core.write_reg_with_label(2, Value::Int(2), Label::Public)
                .unwrap();
            core.dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayFill),
                RegRange { start: 0, count: 3 },
                Some(Value::Object(object)),
                None,
            )
            .unwrap();
            assert_eq!(core.own_property_label(object, "0"), Label::Public);
            assert_eq!(core.own_property_label(object, "1"), Label::Secret);
            assert_eq!(core.own_property_label(object, "2"), Label::Public);

            let noop = bd_ojvo1_generic_triple(&mut core);
            core.replace_pending_hostcall_result_label(None).unwrap();
            core.write_reg_with_label(0, Value::Int(99), Label::Secret)
                .unwrap();
            core.write_reg_with_label(1, Value::Int(2), Label::Secret)
                .unwrap();
            core.write_reg_with_label(2, Value::Int(2), Label::Secret)
                .unwrap();
            core.write_reg_with_label(5, Value::Int(42), Label::TopSecret)
                .unwrap();
            core.dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayFill),
                RegRange { start: 0, count: 3 },
                Some(Value::Object(noop)),
                None,
            )
            .unwrap();
            for key in ["0", "1", "2"] {
                assert_eq!(core.own_property_label(noop, key), Label::Public);
            }
            assert_eq!(
                core.take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
                Label::Public
            );
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }

        // 2. CopyWithin: Secret target taints destination; zero-count range stays Public.
        {
            let (module, mut core) = bd_ojvo1_test_core();
            let object = bd_ojvo1_generic_triple(&mut core);
            core.write_reg_with_label(0, Value::Int(-1), Label::Secret)
                .unwrap();
            core.write_reg_with_label(1, Value::Int(0), Label::Public)
                .unwrap();
            core.write_reg_with_label(2, Value::Int(1), Label::Public)
                .unwrap();
            core.dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayCopyWithin),
                RegRange { start: 0, count: 3 },
                Some(Value::Object(object)),
                None,
            )
            .unwrap();
            assert_eq!(
                core.heap[object.0 as usize].properties.get_index(2),
                Some(&Value::Int(10))
            );
            assert_eq!(core.own_property_label(object, "2"), Label::Secret);
            assert_eq!(core.own_property_label(object, "0"), Label::Public);

            let noop = bd_ojvo1_generic_triple(&mut core);
            core.replace_pending_hostcall_result_label(None).unwrap();
            core.write_reg_with_label(0, Value::Int(1), Label::Secret)
                .unwrap();
            core.write_reg_with_label(1, Value::Int(2), Label::Secret)
                .unwrap();
            core.write_reg_with_label(2, Value::Int(2), Label::Secret)
                .unwrap();
            core.dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayCopyWithin),
                RegRange { start: 0, count: 3 },
                Some(Value::Object(noop)),
                None,
            )
            .unwrap();
            for key in ["0", "1", "2"] {
                assert_eq!(core.own_property_label(noop, key), Label::Public);
            }
            assert_eq!(
                core.take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
                Label::Public
            );
        }

        // 3. Splice & Slice & At & With & ToSpliced: relative index labels vs no-op/omitted precision.
        {
            let (module, mut core) = bd_ojvo1_test_core();
            let object = bd_ojvo1_generic_triple(&mut core);
            core.write_reg_with_label(0, Value::Int(-2), Label::Secret)
                .unwrap();
            core.write_reg_with_label(1, Value::Int(1), Label::Public)
                .unwrap();
            let Value::Object(removed) = core
                .dispatch_builtin_function(
                    &module,
                    &BuiltinFunction::new_kind(K::ArraySplice),
                    RegRange { start: 0, count: 2 },
                    Some(Value::Object(object)),
                    None,
                )
                .unwrap()
            else {
                panic!("splice returns removed array");
            };
            assert_eq!(core.own_property_label(removed, "0"), Label::Secret);
            assert_eq!(core.own_property_label(object, "1"), Label::Secret);

            let noop_splice = bd_ojvo1_generic_triple(&mut core);
            core.replace_pending_hostcall_result_label(None).unwrap();
            core.write_reg_with_label(0, Value::Int(1), Label::Secret)
                .unwrap();
            core.write_reg_with_label(1, Value::Int(0), Label::Secret)
                .unwrap();
            core.dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArraySplice),
                RegRange { start: 0, count: 2 },
                Some(Value::Object(noop_splice)),
                None,
            )
            .unwrap();
            for key in ["0", "1", "2"] {
                assert_eq!(core.own_property_label(noop_splice, key), Label::Public);
            }
            assert_eq!(
                core.take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
                Label::Public
            );

            let slice_src = bd_ojvo1_generic_triple(&mut core);
            core.write_reg_with_label(0, Value::Int(-2), Label::Secret)
                .unwrap();
            core.write_reg_with_label(1, Value::Int(2), Label::Public)
                .unwrap();
            let Value::Object(sliced) = core
                .dispatch_builtin_function(
                    &module,
                    &BuiltinFunction::new_kind(K::ArraySliceMethod),
                    RegRange { start: 0, count: 2 },
                    Some(Value::Object(slice_src)),
                    None,
                )
                .unwrap()
            else {
                panic!("slice returns array");
            };
            assert_eq!(core.own_property_label(sliced, "0"), Label::Secret);
            assert_eq!(
                core.take_pending_hostcall_result_label(),
                Some(Label::Secret)
            );

            core.replace_pending_hostcall_result_label(None).unwrap();
            core.write_reg_with_label(0, Value::Int(2), Label::Secret)
                .unwrap();
            core.write_reg_with_label(1, Value::Int(2), Label::Secret)
                .unwrap();
            core.dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArraySliceMethod),
                RegRange { start: 0, count: 2 },
                Some(Value::Object(slice_src)),
                None,
            )
            .unwrap();
            assert_eq!(
                core.take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
                Label::Public
            );

            core.replace_pending_hostcall_result_label(None).unwrap();
            core.write_reg_with_label(0, Value::Int(-1), Label::Secret)
                .unwrap();
            let at_val = core
                .dispatch_builtin_function(
                    &module,
                    &BuiltinFunction::new_kind(K::ArrayAt),
                    RegRange { start: 0, count: 1 },
                    Some(Value::Object(slice_src)),
                    None,
                )
                .unwrap();
            assert_eq!(at_val, Value::Int(30));
            assert_eq!(
                core.take_pending_hostcall_result_label(),
                Some(Label::Secret)
            );

            core.replace_pending_hostcall_result_label(None).unwrap();
            core.write_reg_with_label(0, Value::Int(-2), Label::Secret)
                .unwrap();
            core.write_reg_with_label(1, Value::Int(99), Label::Public)
                .unwrap();
            let Value::Object(with_arr) = core
                .dispatch_builtin_function(
                    &module,
                    &BuiltinFunction::new_kind(K::ArrayWith),
                    RegRange { start: 0, count: 2 },
                    Some(Value::Object(slice_src)),
                    None,
                )
                .unwrap()
            else {
                panic!("with returns array");
            };
            for key in ["0", "1", "2"] {
                assert_eq!(core.own_property_label(with_arr, key), Label::Secret);
            }
            assert_eq!(
                core.take_pending_hostcall_result_label(),
                Some(Label::Secret)
            );

            core.replace_pending_hostcall_result_label(None).unwrap();
            core.write_reg_with_label(0, Value::Int(1), Label::Secret)
                .unwrap();
            core.write_reg_with_label(1, Value::Int(0), Label::Secret)
                .unwrap();
            let Value::Object(noop_to_spliced) = core
                .dispatch_builtin_function(
                    &module,
                    &BuiltinFunction::new_kind(K::ArrayToSpliced),
                    RegRange { start: 0, count: 2 },
                    Some(Value::Object(slice_src)),
                    None,
                )
                .unwrap()
            else {
                panic!("toSpliced returns array");
            };
            for key in ["0", "1", "2"] {
                assert_eq!(core.own_property_label(noop_to_spliced, key), Label::Public);
            }
            assert_eq!(
                core.take_pending_hostcall_result_label()
                    .unwrap_or(Label::Public),
                Label::Public
            );
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn generic_mutators_preflight_custom_labels_before_side_effects_bd_ojvo1() {
        use BuiltinFunctionKind as K;

        let custom = Label::Custom {
            name: "mutator-preflight".repeat(512),
            level: 6,
        };
        for kind in [
            K::ArrayUnshift,
            K::ArrayFill,
            K::ArrayCopyWithin,
            K::ArraySplice,
        ] {
            let (module, mut core) = bd_ojvo1_test_core();
            let object = core.alloc_object_with_prototype(None).unwrap();
            core.set_object_property(object, "length".into(), Value::Int(2))
                .unwrap();
            core.set_object_property(object, "0".into(), Value::Int(10))
                .unwrap();
            core.set_object_property(object, "1".into(), Value::Int(20))
                .unwrap();
            let args = match kind {
                K::ArrayUnshift | K::ArrayFill => {
                    core.write_reg_with_label(0, Value::Int(7), custom.clone())
                        .unwrap();
                    RegRange { start: 0, count: 1 }
                }
                K::ArrayCopyWithin => {
                    core.write_reg_with_label(0, Value::Int(1), custom.clone())
                        .unwrap();
                    core.write_reg_with_label(1, Value::Int(0), Label::Public)
                        .unwrap();
                    core.write_reg_with_label(2, Value::Int(1), Label::Public)
                        .unwrap();
                    RegRange { start: 0, count: 3 }
                }
                K::ArraySplice => {
                    core.write_reg_with_label(0, Value::Int(0), Label::Public)
                        .unwrap();
                    core.write_reg_with_label(1, Value::Int(1), Label::Public)
                        .unwrap();
                    core.write_reg_with_label(2, Value::Int(7), custom.clone())
                        .unwrap();
                    RegRange { start: 0, count: 3 }
                }
                _ => unreachable!(),
            };
            let before = core.estimated_memory_bytes();
            core.config.max_total_memory_bytes =
                before + InterpreterCore::estimate_label_bytes(&custom) - 1;
            let result = core.dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(kind),
                args,
                Some(Value::Object(object)),
                None,
            );
            assert!(
                matches!(result, Err(InterpreterError::MemoryBudgetExceeded { .. })),
                "{kind:?} must fail temporary-budget preflight before mutating"
            );
            assert_eq!(
                core.heap[object.0 as usize].properties.get("length"),
                Some(&Value::Int(2)),
                "{kind:?} must not mutate length before preflight"
            );
            assert_eq!(
                core.heap[object.0 as usize].properties.get_index(0),
                Some(&Value::Int(10)),
                "{kind:?} must not mutate index 0 before preflight"
            );
            assert_eq!(
                core.heap[object.0 as usize].properties.get_index(1),
                Some(&Value::Int(20)),
                "{kind:?} must not mutate index 1 before preflight"
            );
            assert_eq!(core.own_property_label(object, "0"), Label::Public);
            assert_eq!(core.own_property_label(object, "1"), Label::Public);
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(core.estimated_memory_bytes(), before);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn ordinary_array_methods_preserve_stored_and_argument_labels_bd_ojvo1() {
        use BuiltinFunctionKind as K;

        let (module, mut core) = bd_ojvo1_test_core();

        // push(Secret) -> pop() preserves Secret result label on ordinary Array.
        let arr = core.alloc_array_from_values(&[]).unwrap();
        core.write_reg_with_label(0, Value::Int(7), Label::Secret)
            .unwrap();
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(K::ArrayPush),
            RegRange { start: 0, count: 1 },
            Some(Value::Object(arr)),
            None,
        )
        .unwrap();
        assert_eq!(core.own_property_label(arr, "0"), Label::Secret);
        core.replace_pending_hostcall_result_label(None).unwrap();
        let popped = core
            .dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayPop),
                RegRange { start: 0, count: 0 },
                Some(Value::Object(arr)),
                None,
            )
            .unwrap();
        assert_eq!(popped, Value::Int(7));
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret)
        );

        // at(-1) and at(0) on [Public(1), Secret(7)] preserve element-specific labels.
        let at_arr = core
            .alloc_array_from_values(&[Value::Int(1), Value::Int(7)])
            .unwrap();
        core.set_own_property_label(at_arr, "1", &Label::Secret)
            .unwrap();
        core.replace_pending_hostcall_result_label(None).unwrap();
        core.write_reg_with_label(0, Value::Int(0), Label::Public)
            .unwrap();
        assert_eq!(
            core.dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayAt),
                RegRange { start: 0, count: 1 },
                Some(Value::Object(at_arr)),
                None,
            )
            .unwrap(),
            Value::Int(1)
        );
        assert_eq!(
            core.take_pending_hostcall_result_label()
                .unwrap_or(Label::Public),
            Label::Public
        );
        core.write_reg_with_label(0, Value::Int(-1), Label::Public)
            .unwrap();
        assert_eq!(
            core.dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayAt),
                RegRange { start: 0, count: 1 },
                Some(Value::Object(at_arr)),
                None,
            )
            .unwrap(),
            Value::Int(7)
        );
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret)
        );

        // unshift(Public(6)) + unshift(Secret(5), Public(6)) + shift() + fill() on ordinary Array.
        core.replace_pending_hostcall_result_label(None).unwrap();
        let unshift_pub = core.alloc_array_from_values(&[Value::Int(9)]).unwrap();
        core.write_reg_with_label(0, Value::Int(6), Label::Public)
            .unwrap();
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(K::ArrayUnshift),
            RegRange { start: 0, count: 1 },
            Some(Value::Object(unshift_pub)),
            None,
        )
        .unwrap();
        assert_eq!(core.own_property_label(unshift_pub, "0"), Label::Public);
        assert_eq!(core.own_property_label(unshift_pub, "1"), Label::Public);

        core.replace_pending_hostcall_result_label(None).unwrap();
        let unshift_arr = core.alloc_array_from_values(&[Value::Int(9)]).unwrap();
        core.write_reg_with_label(0, Value::Int(5), Label::Secret)
            .unwrap();
        core.write_reg_with_label(1, Value::Int(6), Label::Public)
            .unwrap();
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(K::ArrayUnshift),
            RegRange { start: 0, count: 2 },
            Some(Value::Object(unshift_arr)),
            None,
        )
        .unwrap();
        // Existing Public element at "0" moves to "2" before argument writes;
        // writing Secret(5) at "0" establishes the monotone species-scope floor
        // for subsequent writes in the same unshift call ("1").
        assert_eq!(core.own_property_label(unshift_arr, "0"), Label::Secret);
        assert_eq!(core.own_property_label(unshift_arr, "1"), Label::Secret);
        assert_eq!(core.own_property_label(unshift_arr, "2"), Label::Public);

        core.replace_pending_hostcall_result_label(None).unwrap();
        let shift_arr = core
            .alloc_array_from_values(&[Value::Int(1), Value::Int(7)])
            .unwrap();
        core.set_own_property_label(shift_arr, "1", &Label::Secret)
            .unwrap();
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(K::ArrayShift),
            RegRange { start: 0, count: 0 },
            Some(Value::Object(shift_arr)),
            None,
        )
        .unwrap();
        assert_eq!(core.own_property_label(shift_arr, "0"), Label::Secret);

        core.replace_pending_hostcall_result_label(None).unwrap();
        let fill_arr = core
            .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
            .unwrap();
        core.write_reg_with_label(0, Value::Int(8), Label::Secret)
            .unwrap();
        core.write_reg_with_label(1, Value::Int(1), Label::Public)
            .unwrap();
        core.write_reg_with_label(2, Value::Int(2), Label::Public)
            .unwrap();
        core.dispatch_builtin_function(
            &module,
            &BuiltinFunction::new_kind(K::ArrayFill),
            RegRange { start: 0, count: 3 },
            Some(Value::Object(fill_arr)),
            None,
        )
        .unwrap();
        assert_eq!(core.own_property_label(fill_arr, "0"), Label::Public);
        assert_eq!(core.own_property_label(fill_arr, "1"), Label::Secret);
        assert_eq!(core.own_property_label(fill_arr, "2"), Label::Public);

        // slice, concat (both spreadable array with Secret element and Confidential primitive arg),
        // toReversed, with, and toSpliced on ordinary Array [Public(2), Secret(7)].
        let src = core
            .alloc_array_from_values(&[Value::Int(2), Value::Int(7)])
            .unwrap();
        core.set_own_property_label(src, "1", &Label::Secret)
            .unwrap();

        core.replace_pending_hostcall_result_label(None).unwrap();
        let Value::Object(sliced) = core
            .dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArraySliceMethod),
                RegRange { start: 0, count: 0 },
                Some(Value::Object(src)),
                None,
            )
            .unwrap()
        else {
            panic!("slice returns array");
        };
        assert_eq!(core.own_property_label(sliced, "0"), Label::Public);
        assert_eq!(core.own_property_label(sliced, "1"), Label::Secret);
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret)
        );

        let public_head = core.alloc_array_from_values(&[Value::Int(1)]).unwrap();
        core.replace_pending_hostcall_result_label(None).unwrap();
        core.write_reg_with_label(0, Value::Int(9), Label::Confidential)
            .unwrap();
        core.write_reg_with_label(1, Value::Object(src), Label::Public)
            .unwrap();
        let Value::Object(concat_out) = core
            .dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayConcat),
                RegRange { start: 0, count: 2 },
                Some(Value::Object(public_head)),
                None,
            )
            .unwrap()
        else {
            panic!("concat returns array");
        };
        assert_eq!(core.own_property_label(concat_out, "0"), Label::Public);
        assert_eq!(
            core.own_property_label(concat_out, "1"),
            Label::Confidential
        );
        assert_eq!(
            core.own_property_label(concat_out, "2"),
            Label::Confidential
        );
        assert_eq!(core.own_property_label(concat_out, "3"), Label::Secret);
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret)
        );

        let rev_src = core
            .alloc_array_from_values(&[Value::Int(7), Value::Int(2)])
            .unwrap();
        core.set_own_property_label(rev_src, "0", &Label::Secret)
            .unwrap();
        core.replace_pending_hostcall_result_label(None).unwrap();
        let Value::Object(rev) = core
            .dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayToReversed),
                RegRange { start: 0, count: 0 },
                Some(Value::Object(rev_src)),
                None,
            )
            .unwrap()
        else {
            panic!("toReversed returns array");
        };
        assert_eq!(core.own_property_label(rev, "0"), Label::Public);
        assert_eq!(core.own_property_label(rev, "1"), Label::Secret);
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret)
        );

        core.replace_pending_hostcall_result_label(None).unwrap();
        core.write_reg_with_label(0, Value::Int(1), Label::Public)
            .unwrap();
        core.write_reg_with_label(1, Value::Int(42), Label::Public)
            .unwrap();
        let Value::Object(replaced) = core
            .dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayWith),
                RegRange { start: 0, count: 2 },
                Some(Value::Object(src)),
                None,
            )
            .unwrap()
        else {
            panic!("with returns array");
        };
        assert_eq!(core.own_property_label(replaced, "0"), Label::Public);
        assert_eq!(core.own_property_label(replaced, "1"), Label::Public);

        core.replace_pending_hostcall_result_label(None).unwrap();
        core.write_reg_with_label(0, Value::Int(1), Label::Public)
            .unwrap();
        core.write_reg_with_label(1, Value::Int(0), Label::Public)
            .unwrap();
        core.write_reg_with_label(2, Value::Int(99), Label::Confidential)
            .unwrap();
        let Value::Object(spliced_copy) = core
            .dispatch_builtin_function(
                &module,
                &BuiltinFunction::new_kind(K::ArrayToSpliced),
                RegRange { start: 0, count: 3 },
                Some(Value::Object(src)),
                None,
            )
            .unwrap()
        else {
            panic!("toSpliced returns array");
        };
        assert_eq!(core.own_property_label(spliced_copy, "0"), Label::Public);
        assert_eq!(
            core.own_property_label(spliced_copy, "1"),
            Label::Confidential
        );
        assert_eq!(core.own_property_label(spliced_copy, "2"), Label::Secret);
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret)
        );
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn tail_checks_do_not_require_dense_or_writable_preceding_elements() {
        let mut object = array(80_000);
        // No preceding elements at all. Only the last element matters to pop.
        object.properties.insert("79999".to_string(), Value::Int(7));
        assert!(pop_can_use_storage(&object, 80_000));
        assert!(append_targets_absent(&object, 80_000, 2));
        assert!(!append_targets_absent(&object, 79_999, 2));
        object.properties.remove("79999");
        assert!(!pop_can_use_storage(&object, 80_000));
    }

    #[test]
    fn tail_refusal_depends_on_configurability_not_writability() {
        let mut object = array(1);
        object.properties.insert("0".to_string(), Value::Int(3));
        let key = InterpreterCore::generic_index_key(0);
        let mut attributes = object.own_property_attributes(&key);
        attributes.writable = false;
        attributes.configurable = true;
        object.property_attributes.insert(key.clone(), attributes);
        assert!(pop_can_use_storage(&object, 1));
        let mut attributes = object.own_property_attributes(&key);
        attributes.configurable = false;
        object.property_attributes.insert(key, attributes);
        assert!(!pop_can_use_storage(&object, 1));
    }

    #[test]
    fn a_narrow_fill_checks_only_its_write_range() {
        let mut object = array(80_000);
        object.properties.insert("40000".to_string(), Value::Int(7));
        assert!(plain_writable_range(&object, 40_000, 40_001));
        assert!(!plain_writable_range(&object, 39_999, 40_001));
        assert!(plain_writable_range(&object, 80_000, 80_000));
        assert!(plain_writable_range(&object, 7, 2));
        assert_eq!(primitive_index(Some(Value::Int(-3)), 10, 0), Some(7));
        assert_eq!(primitive_index(Some(Value::Int(-30)), 10, 0), Some(0));
        assert_eq!(primitive_index(Some(Value::Int(30)), 10, 0), Some(10));
        assert_eq!(primitive_index(None, 10, 10), Some(10));
        assert_eq!(primitive_index(Some(Value::str("2")), 10, 0), None);
    }

    #[test]
    fn invalid_lengths_and_non_index_tail_writes_take_the_spec_path() {
        let mut object = array(0);
        assert_eq!(mutation_length(&object), Some(0));
        assert!(pop_can_use_storage(&object, 0));
        assert!(append_targets_absent(&object, 0, 0));
        assert!(!append_targets_absent(&object, u32::MAX, 1));
        assert!(!append_targets_absent(&object, u32::MAX - 1, 2));
        for length in [-1, i64::from(u32::MAX) + 1] {
            object
                .properties
                .insert("length".to_string(), Value::Int(length));
            assert_eq!(mutation_length(&object), None);
        }
    }

    fn reference_range(object: &HeapObject, start: u32, end: u32) -> bool {
        (start..end).all(|index| {
            let key = InterpreterCore::generic_index_key(u64::from(index));
            !matches!(
                object.own_runtime_property_value(&key),
                None | Some(Value::Accessor { .. })
            ) && object.own_property_attributes(&key).writable
        })
    }

    #[test]
    fn default_metadata_and_overrides_have_identical_range_semantics() {
        let mut object = array(128);
        for index in 0..128 {
            object
                .properties
                .insert(index.to_string(), Value::Int(index));
        }
        // One read-only index among arbitrarily many unrelated descriptors.
        // Range semantics and short-fill work must not depend on dictionary size.
        let key = InterpreterCore::generic_index_key(64);
        let mut attributes = object.own_property_attributes(&key);
        attributes.writable = false;
        object.property_attributes.insert(key, attributes);
        for unrelated in 0..128 {
            let key = RuntimePropertyKey::String(format!("named-{unrelated}").into());
            object.property_attributes.insert(key, attributes);
            for (start, end) in [(0, 64), (0, 128), (64, 65), (65, 66), (128, 128), (9, 3)] {
                assert_eq!(
                    plain_writable_range(&object, start, end),
                    reference_range(&object, start, end)
                );
            }
        }
        object.is_frozen = true;
        assert!(!plain_writable_range(&object, 1, 2));
        assert!(plain_writable_range(&object, 2, 2));
        assert!(!pop_can_use_storage(&object, 128));
    }

    #[test]
    fn ordinary_dense_guards_never_request_a_formatted_property_key() {
        let mut object = array(16_384);
        for index in 0..16_384 {
            object
                .properties
                .insert(index.to_string(), Value::Int(index));
        }
        assert!(range_with_keys(&object, 0, 16_384, |_| {
            panic!("ordinary numeric storage needs no property-name allocation")
        }));
        assert!(range_with_keys(&object, 8_192, 8_193, |_| {
            panic!("a narrow fill needs no property-name allocation either")
        }));
        // After metadata appears, only the touched index is looked up even
        // when a large unrelated descriptor dictionary is present.
        for index in 0..16_384 {
            let key = RuntimePropertyKey::String(format!("named-{index}").into());
            let mut attributes = object.own_property_attributes(&key);
            attributes.writable = false;
            object.property_attributes.insert(key, attributes);
        }
        let mut requests = Vec::new();
        assert!(range_with_keys(&object, 8_192, 8_193, |index| {
            requests.push(index);
            InterpreterCore::generic_index_key(u64::from(index))
        }));
        assert_eq!(requests, [8_192]);
    }

    #[test]
    fn range_guard_matches_the_previous_property_oracle_over_mixed_layouts() {
        fn next(seed: &mut u64) -> u64 {
            *seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *seed >> 32
        }
        let mut checks = 0;
        for initial in 1..=32_u64 {
            let mut seed = initial;
            for _ in 0..64 {
                let length = (next(&mut seed) % 24) as u32;
                let mut object = array(length);
                for index in 0..length {
                    if !next(&mut seed).is_multiple_of(5) {
                        object
                            .properties
                            .insert(index.to_string(), Value::Int(i64::from(index)));
                    }
                    if next(&mut seed).is_multiple_of(3) {
                        let key = InterpreterCore::generic_index_key(u64::from(index));
                        let mut attributes = object.own_property_attributes(&key);
                        attributes.writable = next(&mut seed).is_multiple_of(2);
                        attributes.configurable = next(&mut seed).is_multiple_of(2);
                        attributes.enumerable = next(&mut seed).is_multiple_of(2);
                        object.property_attributes.insert(key, attributes);
                    }
                }
                for index in 0..next(&mut seed) % 24 {
                    let key = RuntimePropertyKey::String(format!("named-{index}").into());
                    let mut attributes = object.own_property_attributes(&key);
                    attributes.writable = false;
                    object.property_attributes.insert(key, attributes);
                }
                object.is_frozen = next(&mut seed).is_multiple_of(17);
                for _ in 0..16 {
                    let start = (next(&mut seed) % u64::from(length + 3)) as u32;
                    let end = (next(&mut seed) % u64::from(length + 3)) as u32;
                    assert_eq!(
                        plain_writable_range(&object, start, end),
                        reference_range(&object, start, end),
                        "seed {initial}, range {start}..{end}"
                    );
                    checks += 1;
                }
            }
        }
        assert_eq!(checks, 32_768);
    }

    #[test]
    #[ignore = "core guard microbenchmark; run explicitly in release mode"]
    fn dense_range_guard_before_after_probe() {
        use std::hint::black_box;
        use std::time::Instant;
        let mut object = array(16_384);
        for index in 0..16_384 {
            object
                .properties
                .insert(index.to_string(), Value::Int(index));
        }
        // Timing includes only guard calls, not setup. Both sides execute
        // Rust; this is not an engine-versus-Node or end-to-end benchmark.
        for (name, guard) in [
            (
                "property_key_oracle",
                reference_range as fn(&HeapObject, u32, u32) -> bool,
            ),
            (
                "numeric_metadata_guard",
                plain_writable_range as fn(&HeapObject, u32, u32) -> bool,
            ),
        ] {
            let start = Instant::now();
            for _ in 0..128 {
                assert!(black_box(guard(black_box(&object), 0, 16_384)));
            }
            println!("{name}: {} ns", start.elapsed().as_nanos());
        }
    }
}
