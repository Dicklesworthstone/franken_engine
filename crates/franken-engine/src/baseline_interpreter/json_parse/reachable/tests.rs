use super::*;

// The previous allocating traversal is an independent test oracle.
// Keep its edge order, work charges and label observations unchanged.
impl InterpreterCore {
    /// Objects one step from `object` along `edges`.
    fn reference_children(&self, object: ObjectId, edges: ReachableEdges) -> Vec<ObjectId> {
        let Some(heap_object) = self.heap.get(object.0 as usize) else {
            return Vec::new();
        };
        let object_id = |value: &Value| match value {
            Value::Object(id) => Some(*id),
            _ => None,
        };
        match edges {
            // The walk visits each reachable object once and joins labels,
            // so child order does not matter: no per-key lookup for creation
            // order (bd-9vouw.333).
            ReachableEdges::Data => heap_object
                .properties
                .values_unordered()
                .filter_map(object_id)
                .collect(),
            ReachableEdges::Inspect => {
                // Every property inspect can print: string-keyed data in both
                // key forms and Symbol-keyed data (a separate sidecar that
                // `values()` skips). Accessors print as [Getter]/[Setter].
                let mut children: Vec<ObjectId> = heap_object
                    .properties
                    .all_data_values()
                    .filter_map(object_id)
                    .collect();
                children.extend(
                    heap_object
                        .properties
                        .baseline_symbol_properties()
                        .filter_map(|(_, property)| match property {
                            BaselineSymbolProperty::Data(value) => object_id(value),
                            BaselineSymbolProperty::Accessor { .. } => None,
                        }),
                );
                // Map keys are storage-key reprs, not values
                // (`collection_key_repr`); inspect prints the key objects.
                if let Some(storage_id) = self.collection_storage_id(object, "Map", "__entries")
                    && let Some(storage) = self.heap.get(storage_id.0 as usize)
                {
                    children.extend(
                        storage
                            .properties
                            .keys()
                            .filter_map(|repr| object_id(&Self::collection_key_from_repr(repr))),
                    );
                }
                // An error's message and name print through the prototype
                // chain (`chain_data_property`).
                if self.inspect_is_error(object)
                    && let Some(prototype) = heap_object.prototype
                {
                    children.push(prototype);
                }
                children
            }
        }
    }

    fn reference_observe(
        &mut self,
        value: &Value,
        edges: ReachableEdges,
    ) -> Result<(), InterpreterError> {
        let Value::Object(root) = value else {
            return Ok(());
        };
        let mut pending = Vec::new();
        let mut visited = BTreeSet::new();
        let mut charged = 0_u64;
        let outcome = (|| {
            self.json_reserve_temporary(std::mem::size_of::<ObjectId>() as u64)?;
            charged += std::mem::size_of::<ObjectId>() as u64;
            pending
                .try_reserve_exact(1)
                .map_err(|_| self.memory_budget_error(u64::MAX, self.heap_object_count_u32()))?;
            pending.push(*root);
            while let Some(object) = pending.pop() {
                self.json_charge_work()?;
                if visited.contains(&object) {
                    continue;
                }
                self.json_reserve_temporary(64)?;
                charged += 64;
                visited.insert(object);
                let label = self
                    .object_mutation_labels
                    .get(&object)
                    .into_iter()
                    .chain(self.binary_storage_label_ref(object))
                    .max();
                if let Some(label) = label {
                    self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
                    let label = label.clone();
                    self.json_observe_label(label)?;
                }
                let children = self.reference_children(object, edges);
                let bytes =
                    (children.len() as u64).saturating_mul(std::mem::size_of::<ObjectId>() as u64);
                self.json_reserve_temporary(bytes)?;
                charged += bytes;
                pending.try_reserve_exact(children.len()).map_err(|_| {
                    self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
                })?;
                pending.extend(children);
            }
            Ok(())
        })();
        drop(pending);
        drop(visited);
        self.json_release_temporary(charged);
        outcome
    }

}

fn core() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    config.instruction_budget = 10_000_000;
    InterpreterCore::new(config, "reachable-scratch")
}

fn assert_accounted(core: &InterpreterCore, inherited: u64) {
    assert_eq!(core.json_parse_temporary_bytes, inherited);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    assert!(core.pending_exception.is_none());
}

fn chain(core: &mut InterpreterCore, length: usize) -> Vec<ObjectId> {
    let nodes: Vec<_> = (0..length)
        .map(|_| core.alloc_object_with_prototype(None).unwrap())
        .collect();
    for pair in nodes.windows(2) {
        core.set_object_property(pair[0], "next".into(), Value::Object(pair[1]))
            .unwrap();
    }
    nodes
}

#[test]
fn pending_growth_is_geometric_and_reuses_paid_capacity() {
    let mut core = core();
    let mut pending = ReachablePending::default();
    let mut growths = 0;
    let mut moved = 0;
    for index in 0..16_384 {
        let old_capacity = pending.objects.capacity();
        let old_length = pending.objects.len();
        pending.push(&core, ObjectId(index), 0).unwrap();
        if pending.objects.capacity() != old_capacity {
            growths += 1;
            moved += old_length;
        }
        assert_eq!(
            pending.bytes,
            (pending.objects.capacity() * std::mem::size_of::<ObjectId>()) as u64
        );
    }
    assert!(growths <= 15, "grew {growths} times");
    assert!(moved < 2 * pending.objects.len(), "moved {moved} slots");
    core.json_reserve_temporary(pending.bytes).unwrap();
    let committed = pending.bytes;
    for index in (0..16_384).rev() {
        assert_eq!(pending.objects.pop(), Some(ObjectId(index)));
    }
    core.config.max_total_memory_bytes = core.estimated_memory_bytes();
    for index in 0..16_384 {
        pending.push(&core, ObjectId(index), committed).unwrap();
    }
    assert_eq!(pending.bytes, committed);
    drop(pending);
    core.json_release_temporary(committed);
    assert_accounted(&core, 0);
}

#[test]
fn pending_admission_includes_all_unpublished_growth() {
    let mut core = core();
    let mut pending = ReachablePending::default();
    let slot = std::mem::size_of::<ObjectId>() as u64;
    core.config.max_total_memory_bytes = core.estimated_memory_bytes() + 3 * slot;
    pending.push(&core, ObjectId(1), 0).unwrap();
    pending.push(&core, ObjectId(2), 0).unwrap();
    let capacity = pending.objects.capacity();
    assert!(matches!(
        pending.push(&core, ObjectId(3), 0),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(pending.objects, [ObjectId(1), ObjectId(2)]);
    assert_eq!(pending.objects.capacity(), capacity);
    assert_eq!(pending.bytes, 2 * slot);
    assert_accounted(&core, 0);
}

#[test]
fn pending_first_allocation_is_admitted_before_reserving() {
    let mut core = core();
    core.config.max_total_memory_bytes = core.estimated_memory_bytes();
    let mut pending = ReachablePending::default();
    assert!(matches!(
        pending.push(&core, ObjectId(0), 0),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert!(pending.objects.is_empty());
    assert_eq!(pending.objects.capacity(), 0);
    assert_eq!(pending.bytes, 0);
    assert_accounted(&core, 0);
}

fn graph(core: &mut InterpreterCore, seed: u32) -> ObjectId {
    let nodes = chain(core, 17);
    let mut state = seed;
    for (index, &node) in nodes.iter().enumerate() {
        for edge in 0..4 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let child = nodes[state as usize % nodes.len()];
            core.set_object_property(node, format!("e{edge}"), Value::Object(child))
                .unwrap();
        }
        core.set_object_property(node, "number".into(), Value::Int(index as i64))
            .unwrap();
        if index % 4 == 0 {
            core.join_direct_object_mutation_label(
                node,
                &Label::Custom {
                    name: format!("source-{index}").repeat(4),
                    level: 7,
                },
            )
            .unwrap();
        }
    }
    nodes[0]
}

#[test]
fn graph_walk_matches_original_observations_and_work_refusal_prefixes() {
    for edges in [ReachableEdges::Data, ReachableEdges::Inspect] {
        for seed in 0..16 {
            for budget in [0, 1, 2, 3, 8, 17, 32, 64, 128] {
                let mut actual = core();
                let mut expected = core();
                let a = graph(&mut actual, seed);
                let b = graph(&mut expected, seed);
                for core in [&mut actual, &mut expected] {
                    core.json_reserve_temporary(512).unwrap();
                    core.config.instruction_budget = core.instructions_executed + budget;
                }
                assert_eq!(
                    actual.observe_reachable_value(&Value::Object(a), edges),
                    expected.reference_observe(&Value::Object(b), edges),
                    "edges={edges:?}, seed={seed}, budget={budget}"
                );
                assert_eq!(actual.instructions_executed, expected.instructions_executed);
                assert_eq!(
                    actual.active_inline_callback_context_label,
                    expected.active_inline_callback_context_label
                );
                for core in [&mut actual, &mut expected] {
                    assert_accounted(core, 512);
                    core.json_release_temporary(512);
                    assert_accounted(core, 0);
                }
            }
        }
    }
}

#[test]
fn chain_charges_retained_stack_not_every_consumed_edge() {
    for edges in [ReachableEdges::Data, ReachableEdges::Inspect] {
        let mut actual = core();
        let mut expected = core();
        let a = chain(&mut actual, 512);
        let b = chain(&mut expected, 512);
        for (core, nodes) in [(&mut actual, &a), (&mut expected, &b)] {
            core.join_direct_object_mutation_label(nodes[511], &Label::Secret)
                .unwrap();
            // 64 per visited entry, plus more than one pending ObjectId.
            // The old walker additionally charges all 511 consumed edges.
            core.config.max_total_memory_bytes = core.estimated_memory_bytes() + 512 * 64 + 64;
        }
        actual
            .observe_reachable_value(&Value::Object(a[0]), edges)
            .unwrap();
        assert_eq!(actual.active_inline_callback_context_label, Some(Label::Secret));
        assert!(matches!(
            expected.reference_observe(&Value::Object(b[0]), edges),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_accounted(&actual, 0);
        assert_accounted(&expected, 0);
    }
}

#[test]
fn failed_walk_releases_only_its_own_scratch() {
    for headroom in [0, 3, 4, 63, 64, 67, 68, 127, 256, 1024] {
        let mut core = core();
        let nodes = chain(&mut core, 128);
        core.json_reserve_temporary(777).unwrap();
        let heap_len = core.heap.len();
        let before = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = before + headroom;
        assert!(matches!(
            core.json_observe_reachable_value(&Value::Object(nodes[0])),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_accounted(&core, 777);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.heap.len(), heap_len);
        core.json_release_temporary(777);
        assert_accounted(&core, 0);
    }
}

#[test]
fn cancellation_and_repeated_walks_keep_the_original_lifecycle() {
    let mut core = core();
    let nodes = chain(&mut core, 32);
    core.json_reserve_temporary(777).unwrap();
    let token = CancellationToken::new();
    token.cancel();
    core.config.cancellation_token = Some(token);
    assert_eq!(
        core.json_observe_reachable_value(&Value::Object(nodes[0])),
        Err(InterpreterError::Cancelled)
    );
    assert_accounted(&core, 777);
    core.config.cancellation_token = None;
    core.json_observe_reachable_value(&Value::Object(nodes[0]))
        .unwrap();
    assert!(core.active_inline_callback_context_label.is_none());
    core.join_direct_object_mutation_label(nodes[31], &Label::Secret)
        .unwrap();
    core.json_observe_reachable_value(&Value::Object(nodes[0]))
        .unwrap();
    assert_eq!(core.active_inline_callback_context_label, Some(Label::Secret));
    assert_accounted(&core, 777);
    core.json_release_temporary(777);
    assert_accounted(&core, 0);
}

#[test]
fn streamed_edges_match_original_for_maps_errors_symbols_and_exact_keys() {
    let mut core = core();
    let source = r#"
        var child = {};
        var map = new Map([[child, {value: 1}], ['plain', 2]]);
        var error = new Error('failure');
        var root = {child: child, alias: child, map: map, error: error};
        root.self = root;
        root[Symbol('private')] = {symbol: true};
        root['\ud800'] = {exact: true};
        Object.defineProperty(root, 'getter', {get: function () { throw 'must not run'; }});
        root;
    "#;
    let tree = crate::parser_api_stability::parse_script(source).unwrap();
    let lowered = crate::lowering_pipeline::lower_ir0_to_ir3(
        &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "reachable-edges.js"),
        &crate::lowering_pipeline::LoweringContext::new("reachable", "edge-sets", "builtin-only"),
    )
    .unwrap();
    let result = core.execute(&lowered.ir3).unwrap();
    let Value::Object(root) = result.value else {
        panic!("object expected");
    };
    assert_eq!(
        core.reference_children(root, ReachableEdges::Data)
            .iter()
            .filter(|&&id| id == root)
            .count(),
        1
    );
    for index in 0..core.heap.len() {
        let object = ObjectId(index as u32);
        for edges in [ReachableEdges::Data, ReachableEdges::Inspect] {
            let expected = core.reference_children(object, edges);
            let mut actual = Vec::new();
            core.visit_reachable_children(object, edges, |child| {
                actual.push(child);
                Ok(())
            })
            .unwrap();
            assert_eq!(actual, expected, "object={object:?}, edges={edges:?}");
        }
    }
    core.console_observe_reachable_value(&Value::Object(root))
        .unwrap();
    assert_accounted(&core, 0);
}

#[test]
fn visited_bitmap_reuses_membership_without_per_object_tree_entries() {
    let mut core = core();
    let nodes = chain(&mut core, 4096);
    core.json_reserve_temporary(777).unwrap();
    let mut visited = ReachableVisited::default();
    for &object in &nodes {
        assert!(visited.insert(&mut core, object).unwrap());
        assert!(!visited.insert(&mut core, object).unwrap());
    }
    assert!(!visited.dense.is_empty());
    assert!(visited.sparse.is_empty());
    assert_eq!(visited.bytes, (visited.dense.capacity() * 8) as u64);
    assert!(visited.bytes < nodes.len() as u64);
    for &object in nodes.iter().rev() {
        assert!(!visited.insert(&mut core, object).unwrap());
    }
    assert_accounted(&core, 777 + visited.bytes);
    let bytes = visited.bytes;
    drop(visited);
    core.json_release_temporary(bytes);
    assert_accounted(&core, 777);
    core.json_release_temporary(777);
    assert_accounted(&core, 0);
}

#[test]
fn visited_bitmap_admission_failure_keeps_membership_and_can_retry() {
    let mut core = core();
    let nodes = chain(&mut core, 1024);
    let baseline = core.estimated_memory_bytes();
    core.config.max_total_memory_bytes = baseline + 64 * 64;
    let mut visited = ReachableVisited::default();
    for &object in &nodes[..64] {
        assert!(visited.insert(&mut core, object).unwrap());
    }
    // The 64th tree entry fits, but the simultaneous bitmap does not.
    // Refusing that optional allocation must not refuse or lose the walk.
    assert!(visited.dense.is_empty());
    assert_eq!(visited.sparse.len(), 64);
    assert_eq!(visited.bytes, 64 * 64);
    assert!(matches!(
        visited.insert(&mut core, nodes[64]),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(visited.sparse.len(), 64);
    for &object in &nodes[..64] {
        assert!(!visited.insert(&mut core, object).unwrap());
    }
    assert_accounted(&core, visited.bytes);
    core.config.max_total_memory_bytes = baseline + 64 * 128 + 4096;
    for &object in &nodes[64..128] {
        assert!(visited.insert(&mut core, object).unwrap());
    }
    assert!(!visited.dense.is_empty());
    assert!(visited.sparse.is_empty());
    assert_accounted(&core, visited.bytes);
    let bytes = visited.bytes;
    drop(visited);
    core.json_release_temporary(bytes);
    assert_accounted(&core, 0);
}

#[test]
fn visited_bitmap_window_keeps_lower_upper_and_invalid_ids_distinct() {
    let mut core = core();
    let older = chain(&mut core, 1024);
    let newer = chain(&mut core, 513);
    let mut visited = ReachableVisited::default();
    let mut expected = BTreeSet::new();
    for object in newer
        .iter()
        .chain(older.iter())
        .copied()
        .chain([ObjectId(u32::MAX), ObjectId(u32::MAX - 64)])
    {
        assert_eq!(
            visited.insert(&mut core, object).unwrap(),
            expected.insert(object)
        );
    }
    assert!(!visited.dense.is_empty());
    assert!(visited.first_word > 0);
    assert!(visited.sparse.contains(&older[0]));
    assert!(visited.sparse.contains(&ObjectId(u32::MAX)));
    for &object in expected.iter().rev() {
        assert!(!visited.insert(&mut core, object).unwrap());
    }
    assert_eq!(
        visited.bytes,
        (visited.dense.capacity() * 8 + visited.sparse.len() * 64) as u64
    );
    assert_accounted(&core, visited.bytes);
    let bytes = visited.bytes;
    drop(visited);
    core.json_release_temporary(bytes);
    assert_accounted(&core, 0);
}

#[test]
fn visited_bitmap_declines_uneconomical_and_oversized_windows() {
    let mut core = core();
    let mut visited = ReachableVisited::default();
    // Synthetic membership IDs exercise the scratch carrier, not heap reads.
    // A hypothetical large heap must not cause an input-sized initialization.
    for index in 0..64 {
        visited.sparse.insert(ObjectId(index));
    }
    visited.bytes = 64 * 64;
    core.json_reserve_temporary(visited.bytes).unwrap();
    for heap_len in [
        0,
        64 * 1024,
        8 * (MAX_REACHABLE_BITMAP_BYTES + 8),
        usize::MAX,
    ] {
        visited.try_promote(&mut core, heap_len).unwrap();
        assert!(visited.dense.is_empty(), "heap_len={heap_len}");
        assert_eq!(visited.sparse.len(), 64);
        assert_eq!(visited.bytes, 64 * 64);
        assert_accounted(&core, visited.bytes);
    }
    let bytes = visited.bytes;
    drop(visited);
    core.json_release_temporary(bytes);
    assert_accounted(&core, 0);
}

#[test]
fn visited_bitmap_migration_preserves_out_of_window_sparse_members() {
    let mut core = core();
    let mut visited = ReachableVisited::default();
    for index in 4096..4160 {
        visited.sparse.insert(ObjectId(index));
    }
    visited.sparse.insert(ObjectId(u32::MAX));
    visited.bytes = visited.sparse.len() as u64 * 64;
    core.json_reserve_temporary(visited.bytes).unwrap();
    visited.try_promote(&mut core, 8192).unwrap();
    assert!(!visited.dense.is_empty());
    assert_eq!(visited.first_word, 64);
    assert_eq!(visited.sparse, BTreeSet::from([ObjectId(u32::MAX)]));
    for index in 4096..4160 {
        assert!(!visited.insert(&mut core, ObjectId(index)).unwrap());
    }
    assert!(!visited.insert(&mut core, ObjectId(u32::MAX)).unwrap());
    assert!(visited.insert(&mut core, ObjectId(4095)).unwrap());
    assert!(visited.insert(&mut core, ObjectId(8192)).unwrap());
    assert_accounted(&core, visited.bytes);
    let bytes = visited.bytes;
    drop(visited);
    core.json_release_temporary(bytes);
    assert_accounted(&core, 0);
}

fn bitmap_graph(core: &mut InterpreterCore, seed: usize) -> ObjectId {
    let nodes = chain(core, 256);
    for (index, &object) in nodes.iter().enumerate() {
        core.set_object_property(
            object,
            "alias".into(),
            Value::Object(nodes[(index * 17 + seed) % nodes.len()]),
        )
        .unwrap();
        if index == 65 || index == 191 {
            core.join_direct_object_mutation_label(
                object,
                &Label::Custom {
                    name: format!("bitmap-source-{index}"),
                    level: if index == 65 { 7 } else { 8 },
                },
            )
            .unwrap();
        }
    }
    nodes[0]
}

#[test]
fn bitmap_walk_matches_reference_labels_and_each_budget_prefix() {
    for edges in [ReachableEdges::Data, ReachableEdges::Inspect] {
        for seed in [0, 7, 127] {
            for budget in [0, 1, 63, 64, 65, 127, 128, 256, 511, 1024, 2048] {
                let mut actual = core();
                let mut expected = core();
                let a = bitmap_graph(&mut actual, seed);
                let b = bitmap_graph(&mut expected, seed);
                for core in [&mut actual, &mut expected] {
                    core.json_reserve_temporary(777).unwrap();
                    core.config.instruction_budget = core.instructions_executed + budget;
                }
                assert_eq!(
                    actual.observe_reachable_value(&Value::Object(a), edges),
                    expected.reference_observe(&Value::Object(b), edges),
                    "edges={edges:?}, seed={seed}, budget={budget}"
                );
                assert_eq!(actual.instructions_executed, expected.instructions_executed);
                assert_eq!(
                    actual.active_inline_callback_context_label,
                    expected.active_inline_callback_context_label
                );
                for core in [&mut actual, &mut expected] {
                    assert_accounted(core, 777);
                    core.json_release_temporary(777);
                    assert_accounted(core, 0);
                }
            }
        }
    }
}

#[test]
fn bitmap_walk_does_not_cache_labels_across_mutation_or_cancellation() {
    let mut core = core();
    let nodes = chain(&mut core, 512);
    core.json_reserve_temporary(777).unwrap();
    core.json_observe_reachable_value(&Value::Object(nodes[0]))
        .unwrap();
    assert!(core.active_inline_callback_context_label.is_none());
    core.join_direct_object_mutation_label(nodes[511], &Label::Secret)
        .unwrap();
    let token = CancellationToken::new();
    token.cancel();
    core.config.cancellation_token = Some(token);
    assert_eq!(
        core.json_observe_reachable_value(&Value::Object(nodes[0])),
        Err(InterpreterError::Cancelled)
    );
    assert_accounted(&core, 777);
    core.config.cancellation_token = None;
    core.json_observe_reachable_value(&Value::Object(nodes[0]))
        .unwrap();
    assert_eq!(core.active_inline_callback_context_label, Some(Label::Secret));
    assert_accounted(&core, 777);
    core.json_release_temporary(777);
    assert_accounted(&core, 0);
}

#[test]
fn bitmap_walk_keeps_live_json_getters_aliases_and_cycle_errors() {
    let source = r#"
        (function () {
            var leaves = [];
            for (var i = 0; i < 256; i++) leaves.push({id: i});
            var reads = 0;
            Object.defineProperty(leaves[8], 'mutate', {
                enumerable: true,
                get: function () {
                    reads++;
                    leaves[200].id = 1000 + reads;
                    return reads;
                }
            });
            var root = {a: leaves, b: leaves};
            var first = JSON.parse(JSON.stringify(root));
            var cyclic = {};
            cyclic.self = cyclic;
            var rejected = false;
            try { JSON.stringify(cyclic); }
            catch (error) { rejected = error instanceof TypeError; }
            var second = JSON.parse(JSON.stringify(root));
            return [first.a.length, first.a[8].mutate, first.b[8].mutate,
                    first.a[200].id, first.b[200].id, reads,
                    second.b[200].id, rejected].join('|');
        })();
    "#;
    let tree = crate::parser_api_stability::parse_script(source).unwrap();
    let lowered = crate::lowering_pipeline::lower_ir0_to_ir3(
        &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "reachable-bitmap.js"),
        &crate::lowering_pipeline::LoweringContext::new("reachable", "bitmap", "builtin-only"),
    )
    .unwrap();
    let mut core = core();
    let result = core.execute(&lowered.ir3).unwrap();
    assert_eq!(result.value, Value::str("256|1|2|1001|1002|4|1004|true"));
    assert_accounted(&core, 0);
}
