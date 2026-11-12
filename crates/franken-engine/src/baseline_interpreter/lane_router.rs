use super::*;

/// Regressions for the failure-atomic delegated-hostcall scratch frame
/// (bd-z1peg.3): exact per-element label install/restore, full-lifetime
/// charging of saved and installed storage, tight-budget refusal without
/// drift, fail-closed unknown targets, nested async side effects, stale
/// pending-provenance quarantine, and shrink-safety of the restore.
#[cfg(test)]
mod delegated_hostcall_scratch_frame_tests_bd_z1peg3 {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;

    fn scratch_core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        InterpreterCore::new(config, "bd-z1peg-3")
    }

    fn delegated(values: Vec<Value>, labels: Vec<Label>) -> DelegatedHostcallArguments {
        DelegatedHostcallArguments {
            values,
            labels,
            carrier_bytes: 0,
        }
    }

    fn register_snapshot(core: &InterpreterCore, count: usize) -> (Vec<Value>, Vec<Label>) {
        (
            core.registers[..count].to_vec(),
            core.register_labels[..count].to_vec(),
        )
    }

    #[test]
    fn labels_installed_and_restored_exactly_bd_z1peg3() {
        let mut core = scratch_core();
        core.mutate_registers(|registers| {
            registers[0] = Value::str("occupant-zero");
            registers[1] = Value::Int(41);
        });
        core.register_labels[0] = Label::Custom {
            name: "occupant-label-with-a-distinct-name".to_string(),
            level: 3,
        };
        core.register_labels[1] = Label::Secret;
        core.all_register_labels_public = false;
        // A direct write of the label file, as the production writers'
        // cache maintenance would leave it (bd-9vouw.376).
        core.register_labels_bytes.set(None);
        core.sync_estimated_memory_bytes().expect("baseline sync");
        let (values_before, labels_before) = register_snapshot(&core, 4);
        let baseline = core.estimated_memory_bytes();

        let result = core.dispatch_hostcall_with_value_args(
            "builtin:MathPow",
            delegated(
                vec![Value::Int(2), Value::Int(10)],
                vec![
                    Label::Custom {
                        name: "delegated-arg-zero".to_string(),
                        level: 2,
                    },
                    Label::Confidential,
                ],
            ),
            None,
            &Label::Public,
        );
        assert!(
            result.is_ok(),
            "pure delegated builtin must succeed: {result:?}"
        );

        let (values_after, labels_after) = register_snapshot(&core, 4);
        assert_eq!(
            values_after, values_before,
            "delegation must restore every displaced register value exactly"
        );
        assert_eq!(
            labels_after, labels_before,
            "delegation must restore every displaced per-element label exactly"
        );
        let _ = core.take_pending_hostcall_result_label();
        assert_eq!(
            core.estimated_memory_bytes(),
            baseline,
            "a pure delegation must release its whole frame charge"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "eager must equal recompute after the frame round trip"
        );
    }

    #[test]
    fn custom_label_tight_budget_refusal_is_atomic_bd_z1peg3() {
        let mut core = scratch_core();
        core.sync_estimated_memory_bytes().expect("baseline sync");
        let (values_before, labels_before) = register_snapshot(&core, 4);
        let baseline = core.estimated_memory_bytes();
        // Leave a sliver of headroom nowhere near the attacker-sized Custom
        // label the delegation would need to install and save.
        core.config.max_total_memory_bytes = baseline + 64;

        let refusal = core.dispatch_hostcall_with_value_args(
            "builtin:MathPow",
            delegated(
                vec![Value::Int(2), Value::Int(3)],
                vec![
                    Label::Custom {
                        name: "x".repeat(4096),
                        level: 4,
                    },
                    Label::Public,
                ],
            ),
            None,
            &Label::Public,
        );
        assert!(
            matches!(refusal, Err(InterpreterError::MemoryBudgetExceeded { .. })),
            "a near-budget Custom label must refuse: {refusal:?}"
        );
        let (values_after, labels_after) = register_snapshot(&core, 4);
        assert_eq!(
            values_after, values_before,
            "refusal must not move register values"
        );
        assert_eq!(
            labels_after, labels_before,
            "refusal must not move register labels"
        );
        assert!(
            core.pending_hostcall_result_label.is_none(),
            "refusal must not leave pending result provenance"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            baseline,
            "refusal must not drift the accounting end-state"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "eager must equal recompute after the refusal"
        );
    }

    #[test]
    fn unknown_target_fails_closed_without_provenance_bd_z1peg3() {
        let mut core = scratch_core();
        core.replace_pending_hostcall_result_label(Some(Label::Custom {
            name: "stale-pre-delegation-publication".to_string(),
            level: 5,
        }))
        .expect("stale publication installs");
        core.sync_estimated_memory_bytes().expect("baseline sync");
        let (values_before, labels_before) = register_snapshot(&core, 4);

        let refusal = core.dispatch_hostcall_with_value_args(
            "builtin:NoSuchDelegationTarget",
            delegated(vec![Value::Int(1)], vec![Label::Secret]),
            None,
            &Label::Public,
        );
        assert!(
            matches!(refusal, Err(InterpreterError::CapabilityDenied { .. })),
            "an unknown delegation target must fail closed: {refusal:?}"
        );
        let (values_after, labels_after) = register_snapshot(&core, 4);
        assert_eq!(values_after, values_before);
        assert_eq!(labels_after, labels_before);
        assert!(
            core.pending_hostcall_result_label.is_none(),
            "neither the stale entry publication nor any new provenance may survive the error"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "eager must equal recompute after the fail-closed error"
        );
    }

    #[test]
    fn stale_entry_publication_cannot_become_the_result_bd_z1peg3() {
        let mut core = scratch_core();
        let stale = Label::Custom {
            name: "stale-must-not-win".to_string(),
            level: 5,
        };
        core.replace_pending_hostcall_result_label(Some(stale.clone()))
            .expect("stale publication installs");

        let result = core.dispatch_hostcall_with_value_args(
            "builtin:MathPow",
            delegated(
                vec![Value::Int(3), Value::Int(2)],
                vec![Label::Public, Label::Public],
            ),
            None,
            &Label::Public,
        );
        assert!(result.is_ok(), "delegation succeeds: {result:?}");
        let published = core.take_pending_hostcall_result_label();
        assert_ne!(
            published.as_ref(),
            Some(&stale),
            "the quarantined pre-delegation label must never be published as the delegated result"
        );
    }

    #[test]
    fn nested_async_side_effects_survive_the_frame_bd_z1peg3() {
        let mut core = scratch_core();
        core.sync_estimated_memory_bytes().expect("baseline sync");
        let promises_before = core.promise_store.len();

        let result = core.dispatch_hostcall_with_value_args(
            "promise:resolve",
            delegated(vec![Value::Int(7)], vec![Label::Public]),
            None,
            &Label::Public,
        );
        assert!(
            matches!(result, Ok(Value::Promise(_))),
            "delegated promise:resolve must yield a promise: {result:?}"
        );
        assert!(
            core.promise_store.len() > promises_before,
            "the nested async side effect (a real promise) must survive the frame restore"
        );
        let _ = core.take_pending_hostcall_result_label();
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "eager must equal recompute with the retained async state"
        );
    }

    #[test]
    fn restore_is_shrink_safe_after_nested_truncation_bd_z1peg3() {
        let mut core = scratch_core();
        core.mutate_registers(|registers| {
            registers[0] = Value::str("survives-truncation");
        });
        core.register_labels[0] = Label::Secret;
        core.all_register_labels_public = false;
        core.sync_estimated_memory_bytes().expect("baseline sync");
        let original_len = core.registers.len();

        let frame = core
            .install_delegated_hostcall_scratch(
                delegated(
                    vec![Value::str("installed"), Value::Int(9)],
                    vec![Label::Confidential, Label::Public],
                ),
                2,
            )
            .expect("frame installs");
        // A hostile/nested path shrank both files below the frame's window.
        core.mutate_registers(|registers| registers.clear());
        core.register_labels.clear();
        core.register_labels_bytes.set(None);

        core.restore_delegated_hostcall_scratch(frame);
        assert_eq!(
            core.registers.len(),
            original_len,
            "restore must rebuild the register file to its pre-delegation length"
        );
        assert_eq!(
            core.registers[0],
            Value::str("survives-truncation"),
            "the displaced occupant value must come back even after truncation"
        );
        assert_eq!(
            core.register_labels[0],
            Label::Secret,
            "the displaced occupant label must come back even after truncation"
        );
        core.sync_estimated_memory_bytes()
            .expect("post-surgery resync");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "the invariant re-establishes after the shrink-safe restore"
        );
    }
}

/// Regressions for shared lexical binding-cell memory accounting (bd-sblaq):
/// clones of a `ScopeBinding` share one physical `Rc<RefCell<..>>` cell, so
/// the cell payload must be charged exactly once per physical allocation —
/// never once per alias — while every alias keeps its structural charge, and
/// the incremental estimate must track the deduped recompute exactly.
#[cfg(test)]
mod shared_binding_cell_accounting_tests_bd_sblaq {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;

    fn accounting_test_core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        InterpreterCore::new(config, "bd-sblaq")
    }

    /// Install one binding with a large payload in a fresh pushed frame,
    /// keeping the incremental estimate synchronized. Returns the payload
    /// bytes of the freshly created cell.
    fn declare_large_binding(core: &mut InterpreterCore, name: &str, len: usize) -> u64 {
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        core.scope_chain
            .current_mut()
            .expect("live frame")
            .insert_binding(
                name.to_string(),
                ScopeBinding::with_state(BindingKind::Var, Value::str("x".repeat(len)), true),
            );
        core.apply_scope_chain_memory_delta(previous_scope_bytes)
            .expect("declaration must fit the default budget");
        let binding = core
            .scope_chain
            .current_mut()
            .expect("live frame")
            .get(name)
            .cloned()
            .expect("declared binding");
        InterpreterCore::estimate_binding_cell_payload_bytes(&binding.state)
    }

    fn assert_invariant(core: &InterpreterCore, context: &str) {
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "estimated must equal recompute {context}"
        );
    }

    fn released_cell_payload_by_full_walk(
        core: &mut InterpreterCore,
        callee_frames: &[ScopeFrame],
    ) -> u64 {
        let restored = std::mem::replace(&mut core.scope_chain.frames, callee_frames.to_vec());
        let before = core.shared_binding_cell_payloads_memory_bytes();
        core.scope_chain.frames = restored;
        let after = core.shared_binding_cell_payloads_memory_bytes();
        before
            .checked_sub(after)
            .expect("callee retained caller cells")
    }

    #[test]
    fn full_payload_oracle_preserves_cell_union_without_ledger_metadata_bd_9vouw_31() {
        // Original cell-only traversal: deliberately inspect repeated maps.
        fn original_walk(frames: &[ScopeFrame]) -> u64 {
            let mut cells = BTreeSet::new();
            let mut total = 0u64;
            for frame in frames {
                for binding in frame.bindings.values() {
                    if cells.insert(Rc::as_ptr(&binding.state) as usize) {
                        total = total.saturating_add(
                            InterpreterCore::estimate_binding_cell_payload_bytes(&binding.state),
                        );
                    }
                }
            }
            total
        }

        let mut original = ScopeFrame::new();
        let shared = ScopeBinding::with_state(BindingKind::Let, Value::str("same"), true);
        original.insert_binding("binding".to_string(), shared.clone());
        let fresh =
            ScopeBinding::with_labeled_state(BindingKind::Let, Value::Int(7), Label::Secret, true);
        let mut copied = original.clone();
        copied.insert_binding("fresh".to_string(), fresh.clone());
        copied.insert_binding("fresh_alias".to_string(), fresh.clone());
        let mut equal_content = ScopeFrame::new();
        equal_content.insert_binding(
            "binding".to_string(),
            ScopeBinding::with_state(BindingKind::Let, Value::str("same"), true),
        );
        let mut core = accounting_test_core();
        core.scope_chain.frames = vec![
            original.clone(),
            original,
            copied.clone(),
            equal_content,
            copied,
        ];
        let expected = InterpreterCore::estimate_binding_cell_payload_bytes(&shared.state)
            .saturating_mul(2)
            .saturating_add(InterpreterCore::estimate_binding_cell_payload_bytes(
                &fresh.state,
            ));
        assert_eq!(original_walk(&core.scope_chain.frames), expected);

        // A reference walk must not certify the incremental ledger from its
        // own cached total, even when its map identities are reused.
        let ledger_bytes = core.closures.cold_cells.payload_bytes;
        core.closures.cold_cells.payload_bytes = u64::MAX;
        assert_eq!(core.shared_binding_cell_payloads_memory_bytes(), expected);

        shared.state.borrow_mut().value = Value::str("changed".repeat(128));
        let changed = original_walk(&core.scope_chain.frames);
        assert_ne!(changed, expected);
        assert_eq!(core.shared_binding_cell_payloads_memory_bytes(), changed);
        let borrowed = shared.state.borrow_mut();
        assert_eq!(original_walk(&core.scope_chain.frames), u64::MAX);
        assert_eq!(core.shared_binding_cell_payloads_memory_bytes(), u64::MAX);
        drop(borrowed);
        assert_eq!(core.shared_binding_cell_payloads_memory_bytes(), changed);
        core.closures.cold_cells.payload_bytes = ledger_bytes;
    }

    #[test]
    fn released_frame_payload_tracks_held_maps_cow_and_last_alias_bd_9vouw_31() {
        let mut core = accounting_test_core();
        let mut held = ScopeFrame::new();
        for index in 0..24 {
            held.insert_binding(
                format!("captured_{index}"),
                ScopeBinding::with_state(BindingKind::Let, Value::str("held".repeat(32)), true),
            );
        }
        for _ in 0..2 {
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env: vec![held.clone()],
            });
        }
        assert!(core.closures.cold_cells.holds_frame(&held));

        // The copied map shares its old cells with the held map, but its
        // twelve new cells are not held. Repeated map and binding aliases
        // must release each of those cells once, including the set spill.
        let mut copied = held.clone();
        let mut fresh_bytes = 0u64;
        for index in 0..12 {
            let binding = ScopeBinding::with_labeled_state(
                BindingKind::Let,
                Value::str(format!("fresh-{index}")),
                Label::Custom {
                    name: format!("fresh-label-{index}"),
                    level: 3,
                },
                true,
            );
            fresh_bytes += InterpreterCore::estimate_binding_cell_payload_bytes(&binding.state);
            copied.insert_binding(format!("fresh_{index}"), binding.clone());
            copied.insert_binding(format!("alias_{index}"), binding);
        }
        assert!(!core.closures.cold_cells.holds_frame(&copied));
        let restored = core.scope_chain.frames[0].clone();
        let callee_frames = [restored.clone(), held.clone(), copied.clone(), copied];
        for aliases_left in [2, 1] {
            assert_eq!(held.bindings.ledger_holds.get(), aliases_left);
            assert_eq!(
                core.released_frame_cell_payload_bytes(&callee_frames),
                fresh_bytes
            );
            assert_eq!(
                core.released_frame_cell_payload_bytes(&callee_frames),
                released_cell_payload_by_full_walk(&mut core, &callee_frames)
            );
            core.closures.pop().expect("captured alias");
        }

        // The last capture stops charging the original cells. Both maps
        // still reach them, so releasing the chain must deduplicate them.
        assert!(!core.closures.cold_cells.holds_frame(&held));
        let held_bytes =
            InterpreterCore::saturating_sum(held.bindings.values().map(|binding| {
                InterpreterCore::estimate_binding_cell_payload_bytes(&binding.state)
            }));
        assert_eq!(
            core.released_frame_cell_payload_bytes(&callee_frames),
            held_bytes + fresh_bytes
        );
        assert_eq!(
            core.released_frame_cell_payload_bytes(&callee_frames),
            released_cell_payload_by_full_walk(&mut core, &callee_frames)
        );
        assert_eq!(core.released_frame_cell_payload_bytes(&[restored]), 0);
        assert_eq!(
            callee_frames[2]
                .get("fresh_0")
                .expect("fresh cell")
                .label()
                .expect("fresh label"),
            Label::Custom {
                name: "fresh-label-0".to_string(),
                level: 3,
            }
        );
    }

    #[test]
    fn released_frame_payload_preserves_saturation_bd_9vouw_31() {
        // A compact accessor DAG has a saturated logical owner estimate
        // without allocating an attacker-sized physical payload.
        let mut value = Value::Int(1);
        for _ in 0..128 {
            let shared = Arc::new(value);
            value = Value::Accessor {
                get: Some(shared.clone()),
                set: Some(shared),
            };
        }
        let mut frame = ScopeFrame::new();
        frame.insert_binding(
            "saturated".to_string(),
            ScopeBinding::with_state(BindingKind::Let, value, true),
        );
        let mut core = accounting_test_core();
        assert_eq!(
            core.released_frame_cell_payload_bytes(&[frame.clone()]),
            u64::MAX
        );
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: vec![frame.clone()],
        });
        assert_eq!(core.released_frame_cell_payload_bytes(&[frame.clone()]), 0);
        assert!(core.memory_request_exceeds_budget(core.scope_chain_memory_bytes(), u64::MAX));
        core.closures.pop().expect("last saturated capture");
        assert_eq!(core.released_frame_cell_payload_bytes(&[frame]), u64::MAX);
    }

    #[test]
    fn captured_returns_keep_full_walk_accounting_across_completion_paths_bd_9vouw_31() {
        let module = lower_script_bd_9vouw_31(
            "function make(seed) {\
               let payload = 'captured';\
               return function run(n) {\
                 let scratch = 'local';\
                 try {\
                   if (n < 0) throw n;\
                   return seed + n + payload.length + scratch.length;\
                 } finally { let finalized = 'done'; }\
               };\
             }\
             const run = make(10);\
             let sum = 0;\
             for (let i = 0; i < 4; i++) sum += run(i);\
             try { run(-1); } catch (error) { sum += error; }\
             class Base {}\
             class Derived extends Base { constructor() { super(); this.value = run(1); } }\
             const derived = new Derived();\
             async function finish() { return run(2); }\
             const done = finish();\
             sum + derived.value;",
        );
        let mut core = accounting_test_core();
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Builtin);
        let result = core
            .execute(&module)
            .expect("captured completion paths execute");
        // Node's result is 121; the async function resolves to 25.
        assert_eq!(result.value, Value::Int(121));
        let asynchronous = core
            .async_functions
            .last()
            .expect("completed async function");
        assert!(matches!(asynchronous.phase, AsyncFunctionPhase::Completed));
        assert_eq!(
            core.promise_store
                .get(crate::promise_model::PromiseHandle(
                    asynchronous.result_promise
                ))
                .expect("async result promise")
                .state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(25))
        );
        assert!(core.call_stack.is_empty());
        assert_invariant(
            &core,
            "after ordinary, derived, async and throwing captured calls",
        );
        assert_eq!(
            core.scope_chain_memory_bytes(),
            core.scope_chain_memory_bytes_by_walk()
        );
    }

    #[test]
    fn closure_aliases_charge_shared_cell_payload_once_bd_sblaq() {
        let mut core = accounting_test_core();
        core.scope_chain
            .push(core.config.max_scope_depth)
            .expect("push frame");
        let payload_bytes = declare_large_binding(&mut core, "shared", 4096);
        assert!(payload_bytes >= 4096, "payload estimate covers the string");
        core.sync_estimated_memory_bytes().expect("sync");
        assert_invariant(&core, "after declaration");
        let before_aliases = core.estimated_memory_bytes();

        // Three closures alias the same frames (and therefore the same cell).
        let env = core.scope_chain.snapshot();
        let shallow_env_bytes = InterpreterCore::estimate_scope_chain_bytes(&env);
        for _ in 0..3 {
            let previous_closure_bytes = core.closures_memory_bytes();
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env: core.scope_chain.snapshot(),
            });
            core.apply_closures_memory_delta(previous_closure_bytes)
                .expect("closure capture fits");
        }
        assert_invariant(&core, "after three closure aliases");

        let growth = core.estimated_memory_bytes() - before_aliases;
        // Each alias pays its own structure. The frame maps it shares with
        // the live chain were charged once already (bd-9vouw.154).
        let frame_slots = env.len() as u64 * MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES;
        assert!(shallow_env_bytes > frame_slots, "the frames have bindings");
        let expected_structural = (MEMORY_ESTIMATE_CLOSURE_BASE_BYTES + frame_slots) * 3;
        assert_eq!(
            growth, expected_structural,
            "aliases must add structural bytes only, never re-charge the {payload_bytes}-byte payload"
        );
        assert!(
            growth < payload_bytes,
            "regression guard: per-alias payload double-charge is back (growth {growth} >= payload {payload_bytes})"
        );
    }

    #[test]
    fn transitive_capture_chain_charges_payload_once_bd_sblaq() {
        let mut core = accounting_test_core();
        core.scope_chain
            .push(core.config.max_scope_depth)
            .expect("push frame");
        let payload_bytes = declare_large_binding(&mut core, "outer", 4096);

        // Closure A captures the frame; closure B recaptures A's environment
        // plus an extra empty frame (a transitive capture chain).
        let previous_closure_bytes = core.closures_memory_bytes();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.apply_closures_memory_delta(previous_closure_bytes)
            .expect("closure A fits");
        let mut chained_env = core.closures[0].captured_env.clone();
        chained_env.push(ScopeFrame::new());
        let previous_closure_bytes = core.closures_memory_bytes();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: chained_env,
        });
        core.apply_closures_memory_delta(previous_closure_bytes)
            .expect("closure B fits");
        assert_invariant(&core, "after transitive capture chain");

        // The payload appears exactly once in the deduped walk even though
        // three surfaces (live chain, A, B) alias the cell.
        let walk = core.shared_binding_cell_payloads_memory_bytes();
        assert!(
            walk >= payload_bytes && walk < payload_bytes * 2,
            "walk must contain the shared payload exactly once (walk {walk}, payload {payload_bytes})"
        );
    }

    #[test]
    fn closures_sharing_a_scope_map_charge_its_keys_once_bd_9vouw_154() {
        let mut core = accounting_test_core();
        core.scope_chain
            .push(core.config.max_scope_depth)
            .expect("push frame");
        for index in 0..200 {
            core.scope_chain
                .current_mut()
                .expect("live frame")
                .declare(format!("binding_{index}"), BindingKind::Var);
        }
        core.sync_estimated_memory_bytes().expect("sync");
        let env = core.scope_chain.snapshot();
        let scope_key_bytes = env.last().expect("pushed frame").key_bytes;
        let alias_bytes = MEMORY_ESTIMATE_CLOSURE_BASE_BYTES
            + env.len() as u64 * MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES;
        assert!(scope_key_bytes > 200 * MEMORY_ESTIMATE_SCOPE_BINDING_BASE_BYTES);
        let before = core.estimated_memory_bytes();

        // Fifty closures over the scope: each pays its own structure, the
        // scope's map is not charged again.
        for _ in 0..50 {
            let previous_closure_bytes = core.closures_memory_bytes();
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env: core.scope_chain.snapshot(),
            });
            core.apply_closures_memory_delta(previous_closure_bytes)
                .expect("closure fits");
        }
        assert_invariant(&core, "after 50 closures over one scope");
        assert_eq!(core.estimated_memory_bytes() - before, 50 * alias_bytes);

        // Leaving the scope keeps its map charged, once, by the ledger.
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        core.scope_chain.pop().expect("pop the captured scope");
        core.apply_scope_chain_memory_delta(previous_scope_bytes)
            .expect("pop shrinks");
        assert_invariant(&core, "scope left, closures hold it");
        assert_eq!(
            core.estimated_memory_bytes() - before,
            50 * alias_bytes - MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES
        );

        // The collector reclaiming all but one keeps it; the last one
        // releases the map and its cells.
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        let previous_closure_bytes = core.closures_memory_bytes();
        let previous_call_stack_bytes = core.call_stack_memory_bytes();
        for index in 0..49 {
            assert!(core.closures.reclaim(index));
        }
        core.apply_scope_closure_call_stack_memory_delta(
            previous_scope_bytes,
            previous_closure_bytes,
            previous_call_stack_bytes,
        )
        .expect("reclaim shrinks");
        assert_invariant(&core, "one closure left");
        assert_eq!(
            core.estimated_memory_bytes() - before,
            alias_bytes - MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES
        );
        let held_before_last = core.closures.cold_cells.map_key_bytes;
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        let previous_closure_bytes = core.closures_memory_bytes();
        let previous_call_stack_bytes = core.call_stack_memory_bytes();
        assert!(core.closures.reclaim(49));
        core.apply_scope_closure_call_stack_memory_delta(
            previous_scope_bytes,
            previous_closure_bytes,
            previous_call_stack_bytes,
        )
        .expect("reclaim shrinks");
        assert_invariant(&core, "every closure reclaimed");
        assert_eq!(
            held_before_last,
            env.iter().map(|frame| frame.key_bytes).sum::<u64>(),
            "the ledger held each captured map once"
        );
        assert_eq!(core.closures.cold_cells.map_key_bytes, 0);
        assert!(core.closures.cold_cells.maps.is_empty());
        // The live global frame is charged by the walk again; the scope's
        // map, slot and cells are gone.
        assert!(
            core.estimated_memory_bytes()
                <= before - MEMORY_ESTIMATE_SCOPE_FRAME_BASE_BYTES - scope_key_bytes
        );
    }

    #[test]
    fn closures_over_distinct_scope_maps_charge_each_bd_9vouw_154() {
        let mut core = accounting_test_core();
        core.scope_chain
            .push(core.config.max_scope_depth)
            .expect("push frame");
        for index in 0..20 {
            core.scope_chain
                .current_mut()
                .expect("live frame")
                .declare(format!("binding_{index}"), BindingKind::Var);
        }
        core.sync_estimated_memory_bytes().expect("sync");
        let first_key_bytes = core.scope_chain.current().expect("live frame").key_bytes;
        let mut live_maps = BTreeSet::new();
        for round in 0..5 {
            let env = core.scope_chain.snapshot();
            live_maps.insert(ColdBindingCells::map_key(env.last().expect("live frame")));
            let previous_closure_bytes = core.closures_memory_bytes();
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env: env,
            });
            core.apply_closures_memory_delta(previous_closure_bytes)
                .expect("closure fits");
            // A declaration in the captured live scope copies its map
            // (copy-on-write), so the next closure holds a different one:
            // distinct physical maps, each of which must be charged.
            let previous_scope_bytes = core.scope_chain_memory_bytes();
            core.scope_chain
                .current_mut()
                .expect("live frame")
                .declare(format!("round_{round}"), BindingKind::Var);
            core.apply_scope_chain_memory_delta(previous_scope_bytes)
                .expect("declaration fits");
        }
        assert_eq!(live_maps.len(), 5, "every round captured a new map");
        assert_invariant(&core, "after closures over five distinct maps");

        // The ledger charges every distinct captured map once.
        let mut seen = BTreeSet::new();
        let mut held_key_bytes = 0u64;
        for closure in core.closures.iter() {
            for frame in &closure.captured_env {
                if seen.insert(ColdBindingCells::map_key(frame)) {
                    held_key_bytes += frame.key_bytes;
                }
            }
        }
        assert_eq!(core.closures.cold_cells.map_key_bytes, held_key_bytes);
        assert!(held_key_bytes >= 5 * first_key_bytes);
    }

    fn lower_script_bd_9vouw_31(source: &str) -> Ir3Module {
        let syntax_tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "bd_9vouw_31.js".to_string(),
                    text: source.to_string(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("ledger lifecycle source should parse");
        lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(syntax_tree, "bd_9vouw_31.js"),
            &LoweringContext::new("bd-9vouw-31", "cold-cell-ledger", "lifecycle"),
        )
        .expect("ledger lifecycle source should lower")
        .ir3
    }

    /// bd-9vouw.50: a register past the frame reads the out-of-band argument
    /// list only in the frame whose call site staged it, and only within it;
    /// restoring ends the list and its charge.
    #[test]
    fn registers_past_the_frame_read_only_their_call_sites_arguments_bd_9vouw_50() {
        let mut core = accounting_test_core();
        let max = core.config.max_registers;
        let out_of_bounds = |result: Result<Value, InterpreterError>| {
            matches!(result, Err(InterpreterError::RegisterOutOfBounds { .. }))
        };
        assert!(out_of_bounds(core.read_reg(max)));
        let depth = core.install_argument_overflow(vec![Value::Int(7)], vec![Label::Secret], 16);
        assert_eq!(depth, 0);
        assert_eq!(core.read_reg(max).expect("staged argument"), Value::Int(7));
        assert_eq!(
            core.get_register_label(max).expect("staged label"),
            &Label::Secret
        );
        assert!(out_of_bounds(core.read_reg(max + 1)));
        let entry_bytes = std::mem::size_of::<ArgumentOverflow>() as u64;
        assert_eq!(core.argument_overflow_bytes, 16 + entry_bytes);
        // An empty entry (a call site whose list fits) is charged nothing.
        // A callee frame stacked above never sees its caller's list.
        core.register_base += max as usize;
        assert!(out_of_bounds(core.read_reg(max)));
        core.register_base -= max as usize;
        // A nested call site whose list fits hides the caller's list until it
        // is done, even in the same frame (isolated calls reset the base).
        let nested = core.install_argument_overflow(Vec::new(), Vec::new(), 0);
        assert_eq!(core.argument_overflow_bytes, 16 + entry_bytes);
        assert!(out_of_bounds(core.read_reg(max)));
        core.restore_argument_overflow(nested);
        assert_eq!(
            core.read_reg(max).expect("caller list is back"),
            Value::Int(7)
        );
        core.restore_argument_overflow(depth);
        assert!(core.argument_overflow.is_empty());
        assert_eq!(core.argument_overflow_bytes, 0);
        assert!(out_of_bounds(core.read_reg(max)));
    }

    /// bd-9vouw.50: spread calls whose lists outgrow the register frame run
    /// (a nested one displaces and restores its caller's list), and nothing
    /// staged or charged outlives them.
    #[test]
    fn argument_overflow_ends_with_its_spread_calls_bd_9vouw_50() {
        let module = lower_script_bd_9vouw_31(
            "const a = Array.from({ length: 600 }, (_, i) => i);\
             function inner(...r) { return r.length; }\
             function outer(...r) { return inner(...r, ...r) + r[599]; }\
             const b = []; b.push(...a);\
             outer(...a) + b.length + Math.max(...a);",
        );
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]);
        let mut core = InterpreterCore::new(config, "bd-9vouw-50");
        let result = core.execute(&module).expect("spread program runs");
        // Node v22.2.0: 1200 + 599 + 600 + 599.
        assert_eq!(result.value, Value::Int(2998));
        assert!(core.argument_overflow.is_empty());
        assert_eq!(core.argument_overflow_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    /// bd-9vouw.468: strings built by long concatenations (appends, prepends,
    /// a read between appends, a node shared by both operands, object and
    /// array members) are concatenation nodes, charged for their nodes and
    /// pieces, and the incremental estimate equals the full walk whether or
    /// not they were joined.
    #[test]
    fn concatenation_nodes_keep_memory_accounting_exact_bd_9vouw_468() {
        let module = lower_script_bd_9vouw_31(
            "let s = ''; for (let i = 0; i < 3000; i++) s += 'abcdefg';\
             let t = ''; for (let i = 0; i < 300; i++) t = 'h\\u00e9' + t;\
             let u = ''; for (let i = 0; i < 300; i++) { u += 'x' + i; u.charCodeAt(0); }\
             const both = s + s; const o = { s, both }; const kept = [s, t, u];\
             const sum = s.length + t.length + u.length + both.length + o.s.length\
               + kept.length + o.both.length;\
             if (sum !== 127693 || kept[2].slice(-6) !== '98x299') throw new Error('got ' + sum);\
             s;",
        );
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]);
        config.instruction_budget = 10_000_000;
        let mut core = InterpreterCore::new(config, "bd-9vouw-468");
        let result = core.execute(&module).expect("concatenation program runs");
        let Value::Str(text) = &result.value else {
            panic!(
                "completion value should be the string, got {:?}",
                result.value
            );
        };
        assert_eq!(text.len(), 21_000);
        assert!(text.concat_parts().nodes >= 1, "{:?}", text.concat_parts());
        // Its nodes are charged beyond what one buffer of its bytes costs.
        assert!(
            text.retained_bytes(MEMORY_ESTIMATE_STRING_BASE_BYTES)
                > MEMORY_ESTIMATE_STRING_BASE_BYTES + 21_000
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    /// bd-9vouw.472: the in-place shift takes a dense array (and the
    /// program's shift loop leaves the estimate exact); an array with a hole
    /// or a frozen array is refused, unchanged, for the generic algorithm.
    #[test]
    fn dense_shift_moves_values_in_place_with_exact_accounting_bd_9vouw_472() {
        let module = lower_script_bd_9vouw_31(
            "const q = []; for (let i = 0; i < 500; i++) q.push('v' + i);\
             let s = ''; for (let i = 0; i < 250; i++) s += q.shift();\
             const holed = [1, , 3, 4]; holed.shift();\
             const frozen = Object.freeze([1, 2]);\
             if (q.length !== 250 || q[0] !== 'v250' || s.slice(0, 6) !== 'v0v1v2') throw new Error('q');\
             if (holed.length !== 3 || 0 in holed || holed[2] !== 4) throw new Error('holed');\
             [q, holed, frozen];",
        );
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]);
        config.instruction_budget = 10_000_000;
        let mut core = InterpreterCore::new(config, "bd-9vouw-472");
        let result = core.execute(&module).expect("shift program runs");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        let Value::Object(arrays) = result.value else {
            panic!("completion value should be an array");
        };
        let element = |core: &InterpreterCore, index: &str| match core.heap[arrays.0 as usize]
            .properties
            .get(index)
        {
            Some(Value::Object(id)) => *id,
            other => panic!("element {index}: {other:?}"),
        };
        let (queue, holed, frozen) = (
            element(&core, "0"),
            element(&core, "1"),
            element(&core, "2"),
        );
        assert_eq!(
            core.shift_dense_array_in_place(queue, 250).expect("shift"),
            Some(Value::str("v250"))
        );
        assert_eq!(core.array_like_length(queue).expect("length"), 249);
        assert_eq!(
            core.heap[queue.0 as usize].properties.get("0"),
            Some(&Value::str("v251"))
        );
        assert_eq!(core.heap[queue.0 as usize].properties.get("249"), None);
        assert_eq!(core.heap[queue.0 as usize].cached_dense_length, Some(249));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        for (refused, len) in [(holed, 3), (frozen, 2)] {
            let before = core.heap[refused.0 as usize].properties.clone();
            assert_eq!(
                core.shift_dense_array_in_place(refused, len)
                    .expect("shift"),
                None
            );
            assert_eq!(core.heap[refused.0 as usize].properties, before);
        }

        // The in-place unshift takes the queue too; the frozen array hands
        // the items back unchanged.
        let items = vec![Value::str("u0"), Value::Int(1)];
        assert_eq!(
            core.unshift_dense_array_in_place(queue, 249, items)
                .expect("unshift"),
            Ok(251)
        );
        let queue_properties = &core.heap[queue.0 as usize].properties;
        assert_eq!(queue_properties.get("0"), Some(&Value::str("u0")));
        assert_eq!(queue_properties.get("1"), Some(&Value::Int(1)));
        assert_eq!(queue_properties.get("2"), Some(&Value::str("v251")));
        assert_eq!(queue_properties.get("250"), Some(&Value::str("v499")));
        assert_eq!(core.array_like_length(queue).expect("length"), 251);
        assert_eq!(core.heap[queue.0 as usize].cached_dense_length, Some(251));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        let before = core.heap[frozen.0 as usize].properties.clone();
        assert_eq!(
            core.unshift_dense_array_in_place(frozen, 2, vec![Value::Int(0)])
                .expect("unshift"),
            Err(vec![Value::Int(0)])
        );
        assert_eq!(core.heap[frozen.0 as usize].properties, before);

        // The in-place splice: shrink by two, then grow by one.
        assert_eq!(
            core.splice_dense_array_in_place(queue, 251, 1, 3, vec![Value::str("s")])
                .expect("splice"),
            Ok(vec![Value::Int(1), Value::str("v251"), Value::str("v252")])
        );
        assert_eq!(core.array_like_length(queue).expect("length"), 249);
        let queue_properties = &core.heap[queue.0 as usize].properties;
        assert_eq!(queue_properties.get("1"), Some(&Value::str("s")));
        assert_eq!(queue_properties.get("2"), Some(&Value::str("v253")));
        assert_eq!(queue_properties.get("249"), None);
        assert_eq!(
            core.splice_dense_array_in_place(queue, 249, 0, 0, vec![Value::Int(7)])
                .expect("splice"),
            Ok(Vec::new())
        );
        assert_eq!(core.array_like_length(queue).expect("length"), 250);
        assert_eq!(
            core.heap[queue.0 as usize].properties.get("0"),
            Some(&Value::Int(7))
        );
        assert_eq!(core.heap[queue.0 as usize].cached_dense_length, Some(250));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        assert_eq!(
            core.splice_dense_array_in_place(frozen, 2, 0, 1, Vec::new())
                .expect("splice"),
            Err(Vec::new())
        );
        assert_eq!(core.heap[frozen.0 as usize].properties, before);
    }

    #[test]
    fn dense_move_proof_tracks_mutable_borrows_without_changing_checkpoints() {
        let mut core = accounting_test_core();
        let array = core
            .alloc_array_from_values(&[Value::Int(1), Value::Int(2)])
            .expect("array allocation");
        let index = array.0 as usize;
        let before = serde_json::to_value(&core.heap.value).expect("heap serialization");
        assert!(core.dense_array_moves_are_plain(array, 2).expect("proof"));
        assert_eq!(
            core.heap.slot(index).unwrap().dense_moves_plain.get(),
            Some(true)
        );
        assert_eq!(
            serde_json::to_value(&core.heap.value).expect("heap serialization"),
            before,
            "admission proofs must not change checkpoint bytes"
        );
        assert!(
            !core
                .dense_array_moves_are_plain(array, 1)
                .expect("wrong length")
        );

        let mut copied = core.heap.value.clone();
        copied.slot(index).unwrap().dense_moves_plain.set(None);
        assert_eq!(
            core.heap.value, copied,
            "proofs do not change heap equality"
        );
        copied.get_mut(index).expect("cloned object").is_frozen = true;
        assert_eq!(copied.slot(index).unwrap().dense_moves_plain.get(), None);
        assert_eq!(
            core.heap.slot(index).unwrap().dense_moves_plain.get(),
            Some(true)
        );

        core.mutate_heap(|heap| {
            let _ = heap.get_mut(index).expect("mutable object borrow");
        });
        assert_eq!(core.heap.slot(index).unwrap().dense_moves_plain.get(), None);
        assert!(
            core.dense_array_moves_are_plain(array, 2)
                .expect("revalidated")
        );
        core.mutate_heap(|heap| heap[index].is_frozen = true);
        assert_eq!(core.heap.slot(index).unwrap().dense_moves_plain.get(), None);
        assert!(!core.dense_array_moves_are_plain(array, 2).expect("frozen"));
        core.mutate_heap(|heap| heap[index].is_frozen = false);
        assert!(
            core.dense_array_moves_are_plain(array, 2)
                .expect("repaired")
        );

        core.set_own_property_attributes(
            array,
            &RuntimePropertyKey::String(JsString::from("length")),
            PropertyAttributes {
                writable: false,
                ..PropertyAttributes::DEFAULT
            },
        )
        .expect("length attributes");
        assert_eq!(core.heap.slot(index).unwrap().dense_moves_plain.get(), None);
        assert!(
            !core
                .dense_array_moves_are_plain(array, 2)
                .expect("attributes")
        );
        assert_eq!(
            core.shift_dense_array_in_place(array, 2).expect("refused"),
            None
        );
        assert_eq!(core.array_like_length(array).expect("length"), 2);
    }

    #[test]
    fn dense_move_proof_survives_plain_builtin_and_ir_queue_ends() {
        let mut core = accounting_test_core();
        let mut module = lower_script_bd_9vouw_31("undefined;");
        let array = core
            .alloc_array_from_values(&[Value::Int(1), Value::Int(2), Value::Int(3)])
            .expect("array allocation");
        let push = BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayPush);
        let pop = BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayPop);
        let mut expected = vec![1, 2, 3];
        for next in 4..20 {
            assert_eq!(
                core.shift_dense_array_in_place(array, 3).expect("shift"),
                Some(Value::Int(expected.remove(0)))
            );
            core.write_reg(0, Value::Int(next)).expect("push argument");
            assert_eq!(
                core.dispatch_builtin_function(
                    &module,
                    &push,
                    RegRange { start: 0, count: 1 },
                    Some(Value::Object(array)),
                    None,
                )
                .expect("push"),
                Value::Int(3)
            );
            expected.push(next);
            assert_eq!(
                core.heap
                    .slot(array.0 as usize)
                    .unwrap()
                    .dense_moves_plain
                    .get(),
                Some(true),
                "shift/push must retain the proof between queue steps"
            );
        }
        for next in 0..16 {
            assert_eq!(
                core.unshift_dense_array_in_place(array, 3, vec![Value::Int(-next)])
                    .expect("unshift"),
                Ok(4)
            );
            expected.insert(0, -next);
            assert_eq!(
                core.dispatch_builtin_function(
                    &module,
                    &pop,
                    RegRange { start: 0, count: 0 },
                    Some(Value::Object(array)),
                    None,
                )
                .expect("pop"),
                Value::Int(expected.pop().expect("tail"))
            );
            assert_eq!(
                core.heap
                    .slot(array.0 as usize)
                    .unwrap()
                    .dense_moves_plain
                    .get(),
                Some(true),
                "unshift/pop must retain the proof between queue steps"
            );
        }

        core.write_reg(0, Value::Object(array))
            .expect("IR receiver");
        core.write_reg(1, Value::Int(99)).expect("IR argument");
        module.instructions = vec![
            Ir3Instruction::ArrayPush {
                array: 0,
                element: 1,
            },
            Ir3Instruction::Halt,
        ];
        core.execute(&module).expect("IR append");
        expected.push(99);
        assert_eq!(
            core.heap
                .slot(array.0 as usize)
                .unwrap()
                .dense_moves_plain
                .get(),
            Some(true)
        );
        assert_eq!(
            core.heap[array.0 as usize]
                .properties
                .index_values()
                .cloned()
                .collect::<Vec<_>>(),
            expected.into_iter().map(Value::Int).collect::<Vec<_>>()
        );
        assert_eq!(core.array_like_length(array).expect("length"), 4);
        assert_invariant(&core, "after plain queue ends");
    }

    #[test]
    fn dense_prefix_splices_retain_plain_proof_and_exact_accounting() {
        let mut core = accounting_test_core();
        let mut expected: Vec<_> = (0..256).map(Value::Int).collect();
        let array = core
            .alloc_array_from_values(&expected)
            .expect("array allocation");
        core.set_own_property_label(array, "length", &Label::Secret)
            .expect("length provenance");
        for step in 0..32 {
            // Shrink by a large batch, replace at equal length, then grow.
            // Every step must preserve the proof without a later full-array
            // admission scan and retain the length property's provenance.
            for (delete_count, items) in [
                (129, vec![Value::Int(-step)]),
                (1, vec![Value::str("replacement")]),
                (1, (0..129).map(|n| Value::Int(n + step)).collect()),
            ] {
                let len = expected.len();
                let removed: Vec<_> = expected.splice(..delete_count, items.clone()).collect();
                assert_eq!(
                    core.splice_dense_array_in_place(array, len, 0, delete_count, items)
                        .expect("prefix splice"),
                    Ok(removed)
                );
                assert_eq!(
                    core.heap
                        .slot(array.0 as usize)
                        .unwrap()
                        .dense_moves_plain
                        .get(),
                    Some(true),
                    "plain splices must retain admission between calls"
                );
                assert_eq!(
                    core.array_like_length(array).expect("length"),
                    expected.len()
                );
                assert_eq!(core.own_property_label(array, "length"), Label::Secret);
                assert_eq!(
                    core.heap[array.0 as usize].own_property_attributes(
                        &RuntimePropertyKey::String(JsString::from("length")),
                    ),
                    PropertyAttributes::DEFAULT
                );
                assert_eq!(
                    core.heap[array.0 as usize]
                        .properties
                        .index_values()
                        .cloned()
                        .collect::<Vec<_>>(),
                    expected
                );
                assert_invariant(&core, "after dense prefix splice");
            }
        }
        assert_eq!(
            core.splice_dense_array_in_place(array, expected.len(), 0, expected.len(), Vec::new())
                .expect("drain dense prefix"),
            Ok(expected)
        );
        assert_eq!(core.array_like_length(array).expect("empty length"), 0);
        assert_eq!(core.own_property_label(array, "length"), Label::Secret);
        assert_eq!(core.heap[array.0 as usize].cached_dense_length, Some(0));
        assert_invariant(&core, "after complete prefix splice drain");
    }

    #[test]
    fn dense_move_proof_refuses_accessor_and_labeled_appends() {
        let mut core = accounting_test_core();
        let module = lower_script_bd_9vouw_31("undefined;");
        let push = BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayPush);
        let pop = BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayPop);
        for (value, label, popped) in [
            (
                Value::Accessor {
                    get: None,
                    set: None,
                },
                Label::Public,
                Value::Undefined,
            ),
            (Value::Int(9), Label::Secret, Value::Int(9)),
        ] {
            let array = core
                .alloc_array_from_values(&[Value::Int(1), Value::Int(2)])
                .expect("array allocation");
            assert!(core.dense_array_moves_are_plain(array, 2).expect("proof"));
            core.write_reg(0, value.clone()).expect("argument");
            core.set_register_label(0, label.clone())
                .expect("argument label");
            core.dispatch_builtin_function(
                &module,
                &push,
                RegRange { start: 0, count: 1 },
                Some(Value::Object(array)),
                None,
            )
            .expect("append");
            assert_eq!(
                core.heap
                    .slot(array.0 as usize)
                    .unwrap()
                    .dense_moves_plain
                    .get(),
                None
            );
            assert!(!core.dense_array_moves_are_plain(array, 3).expect("guard"));
            assert_eq!(
                core.shift_dense_array_in_place(array, 3).expect("refused"),
                None
            );
            assert_eq!(
                core.heap[array.0 as usize].properties.get_index(2),
                Some(&value)
            );
            assert_eq!(
                core.own_stored_runtime_property_label(
                    array,
                    &RuntimePropertyKey::String(JsString::from("2")),
                ),
                label
            );
            assert_eq!(
                core.dispatch_builtin_function(
                    &module,
                    &pop,
                    RegRange { start: 0, count: 0 },
                    Some(Value::Object(array)),
                    None,
                )
                .expect("pop"),
                popped
            );
            assert_eq!(
                core.heap
                    .slot(array.0 as usize)
                    .unwrap()
                    .dense_moves_plain
                    .get(),
                None
            );
            assert!(
                core.dense_array_moves_are_plain(array, 2)
                    .expect("revalidated")
            );
        }

        let array = core
            .alloc_array_from_values(&[Value::Int(1)])
            .expect("array allocation");
        assert_eq!(
            core.unshift_dense_array_in_place(
                array,
                1,
                vec![Value::Accessor {
                    get: None,
                    set: None
                }],
            )
            .expect("accessor unshift"),
            Ok(2)
        );
        assert_eq!(
            core.heap
                .slot(array.0 as usize)
                .unwrap()
                .dense_moves_plain
                .get(),
            Some(false)
        );
        assert!(
            !core
                .dense_array_moves_are_plain(array, 2)
                .expect("accessor guard")
        );

        // Splice can introduce an accessor while growing, shrinking, or
        // replacing at equal length. None may cache the original plain proof.
        for delete_count in 0..=2 {
            let array = core
                .alloc_array_from_values(&[Value::Int(1), Value::Int(2)])
                .expect("array allocation");
            assert!(
                core.splice_dense_array_in_place(
                    array,
                    2,
                    0,
                    delete_count,
                    vec![Value::Accessor {
                        get: None,
                        set: None
                    }],
                )
                .expect("accessor splice")
                .is_ok()
            );
            let new_len = 3 - delete_count;
            assert_eq!(
                core.heap
                    .slot(array.0 as usize)
                    .unwrap()
                    .dense_moves_plain
                    .get(),
                Some(false)
            );
            assert!(
                !core
                    .dense_array_moves_are_plain(array, new_len)
                    .expect("spliced accessor guard")
            );
            let before = core.heap[array.0 as usize].properties.clone();
            assert_eq!(
                core.splice_dense_array_in_place(array, new_len, 0, 1, Vec::new())
                    .expect("accessor falls back"),
                Err(Vec::new())
            );
            assert_eq!(core.heap[array.0 as usize].properties, before);
            assert_invariant(&core, "after accessor splice refusal");
        }
    }

    /// bd-9vouw.31: drive the cold-cell ledger through every transition a real
    /// program produces — per-iteration cells captured by many closures, a
    /// write to a cell that only closures and the live chain share, a generator
    /// parking and resuming its activation, and async activations left parked
    /// at the end. In unit-test builds every scope/closure accounting call
    /// asserts the ledger against the full payload walk, so any missed
    /// registration, release or write refresh fails here; the end state is
    /// checked against the walk-based recompute as well.
    #[test]
    fn cold_cell_ledger_tracks_closures_generators_and_parked_async_bd_9vouw_31() {
        let module = lower_script_bd_9vouw_31(
            "const fns = [];\
             let shared = 'seed';\
             for (let i = 0; i < 40; i++) { fns.push(() => i + shared.length); }\
             shared = 'a payload that grows a captured global cell after capture';\
             function* gen(n) { let acc = n; while (true) { acc = acc + (yield acc); } }\
             const g = gen(1);\
             g.next(); g.next(2); g.next(3);\
             async function pending(x) { await new Promise(() => {}); return x; }\
             const parked = [];\
             for (let i = 0; i < 5; i++) { parked.push(pending(i)); }\
             let total = 0;\
             for (const f of fns) { total = total + f(); }\
             total + g.next(4).value;",
        );
        let mut core = accounting_test_core();
        let result = core
            .execute(&module)
            .expect("ledger lifecycle program runs");
        // Node v22.2.0 prints 3070: 40 closures give sum(i) + 40 * 57 = 780 +
        // 2280, read after the captured global grew; the generator yields 10.
        assert_eq!(result.value, Value::Int(3070));
        assert!(
            core.closures.cold_cells.cells.len() >= 40,
            "every per-iteration cell captured by a live closure is in the ledger"
        );
        assert_invariant(
            &core,
            "after closures, generator park/resume and parked async",
        );
        assert_eq!(
            core.scope_chain_memory_bytes(),
            core.scope_chain_memory_bytes_by_walk()
        );
        assert_eq!(
            core.closures_memory_bytes(),
            core.closures_memory_bytes_by_walk()
        );
    }

    /// bd-9vouw.31: aliases are counted, so a cell stays charged while any
    /// closure holds it and is released with the last one; rollback pops keep
    /// the ledger exact.
    #[test]
    fn cold_cell_ledger_releases_with_last_closure_alias_bd_9vouw_31() {
        let mut core = accounting_test_core();
        core.scope_chain
            .push(core.config.max_scope_depth)
            .expect("push frame");
        let payload_bytes = declare_large_binding(&mut core, "held", 2048);
        for _ in 0..2 {
            let previous_closure_bytes = core.closures_memory_bytes();
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env: core.scope_chain.snapshot(),
            });
            core.apply_closures_memory_delta(previous_closure_bytes)
                .expect("alias fits");
        }
        let held = core
            .scope_chain
            .resolve("held")
            .map(|(_, binding)| binding.clone())
            .expect("held binding");
        assert!(core.closures.cold_cells.contains(&held.state));
        let charged_with_two_aliases = core.closures.cold_cells.payload_bytes;
        assert!(charged_with_two_aliases >= payload_bytes);

        // Drop the live frame: only the closures reach the cell now.
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        core.scope_chain.pop().expect("frame pops");
        core.apply_scope_chain_memory_delta(previous_scope_bytes)
            .expect("pop fits");
        assert_invariant(&core, "cell reachable only through closures");

        let previous_closure_bytes = core.closures_memory_bytes();
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        core.closures.pop().expect("first alias pops");
        core.apply_scope_closure_call_stack_memory_delta(
            previous_scope_bytes,
            previous_closure_bytes,
            core.call_stack_memory_bytes(),
        )
        .expect("release fits");
        assert!(core.closures.cold_cells.contains(&held.state));
        assert_eq!(
            core.closures.cold_cells.payload_bytes,
            charged_with_two_aliases
        );
        assert_invariant(&core, "one closure alias left");

        let previous_closure_bytes = core.closures_memory_bytes();
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        core.closures.pop().expect("last alias pops");
        core.apply_scope_closure_call_stack_memory_delta(
            previous_scope_bytes,
            previous_closure_bytes,
            core.call_stack_memory_bytes(),
        )
        .expect("release fits");
        // The last alias also released every global-frame cell the closures
        // captured; nothing else is cold in this fixture.
        assert!(!core.closures.cold_cells.contains(&held.state));
        assert!(core.closures.cold_cells.cells.is_empty());
        assert_eq!(core.closures.cold_cells.payload_bytes, 0);
        assert_invariant(&core, "last closure alias released");
    }

    #[test]
    fn mutation_through_alias_reprices_payload_once_bd_sblaq() {
        let mut core = accounting_test_core();
        core.scope_chain
            .push(core.config.max_scope_depth)
            .expect("push frame");
        declare_large_binding(&mut core, "mutated", 64);
        let previous_closure_bytes = core.closures_memory_bytes();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.apply_closures_memory_delta(previous_closure_bytes)
            .expect("alias fits");
        assert_invariant(&core, "before mutation");
        let before = core.estimated_memory_bytes();

        // Grow the shared cell by ~8KB through the closure's alias, mirroring
        // the StoreScoped bracket.
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        let alias = core.closures[0].captured_env[1]
            .get("mutated")
            .expect("aliased binding")
            .clone();
        {
            let mut state = alias.state.try_borrow_mut().expect("cell borrow");
            state.value = Value::str("y".repeat(8192));
        }
        core.closures.refresh_cell(&alias.state);
        core.apply_scope_chain_memory_delta(previous_scope_bytes)
            .expect("mutation fits");
        assert_invariant(&core, "after mutation through alias");

        let growth = core.estimated_memory_bytes() - before;
        assert!(
            growth >= 8192 - 64 && growth < 2 * 8192,
            "value growth must be charged exactly once, not per alias (growth {growth})"
        );
    }

    #[test]
    fn popped_frame_payload_survives_and_releases_with_last_alias_bd_sblaq() {
        let mut core = accounting_test_core();
        core.scope_chain
            .push(core.config.max_scope_depth)
            .expect("push frame");
        let payload_bytes = declare_large_binding(&mut core, "survivor", 4096);
        let previous_closure_bytes = core.closures_memory_bytes();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.apply_closures_memory_delta(previous_closure_bytes)
            .expect("alias fits");
        assert_invariant(&core, "before pop");
        let before_pop = core.estimated_memory_bytes();

        // Pop the declaring frame (the PopScope bracket): the closure alias
        // keeps the cell alive, so only structural bytes may be released.
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        let popped = core.scope_chain.pop();
        assert!(popped.is_some(), "frame must pop");
        core.apply_scope_chain_memory_delta(previous_scope_bytes)
            .expect("pop accounting");
        assert_invariant(&core, "after pop with surviving alias");
        let released_by_pop = before_pop - core.estimated_memory_bytes();
        assert!(
            released_by_pop < payload_bytes,
            "payload must stay charged while the closure alias survives (released {released_by_pop})"
        );
        assert!(
            core.shared_binding_cell_payloads_memory_bytes() >= payload_bytes,
            "walk still owns the surviving payload"
        );

        // Dropping the last alias releases the payload exactly once.
        core.closures.clear();
        core.sync_estimated_memory_bytes().expect("resync");
        assert_invariant(&core, "after last alias dropped");
        assert!(
            core.shared_binding_cell_payloads_memory_bytes() < payload_bytes,
            "payload must be uncharged once no accounted alias remains"
        );
    }

    #[test]
    fn budget_boundary_fails_fresh_payload_but_admits_shared_alias_bd_sblaq() {
        let mut core = accounting_test_core();
        core.scope_chain
            .push(core.config.max_scope_depth)
            .expect("push frame");
        let payload_bytes = declare_large_binding(&mut core, "budgeted", 4096);
        core.sync_estimated_memory_bytes().expect("sync");
        assert_invariant(&core, "before budget clamp");

        // Leave slack for one shallow capture but nowhere near a second
        // payload. Under the pre-fix per-alias model the capture below was
        // charged payload_bytes again and refused.
        let env = core.scope_chain.snapshot();
        let shallow_env_bytes = InterpreterCore::estimate_scope_chain_bytes(&env);
        let slack = MEMORY_ESTIMATE_CLOSURE_BASE_BYTES
            .saturating_add(shallow_env_bytes)
            .saturating_add(256);
        assert!(
            slack < payload_bytes,
            "test setup: slack must not cover a second payload"
        );
        core.config.max_total_memory_bytes = core.estimated_memory_bytes() + slack;

        let previous_closure_bytes = core.closures_memory_bytes();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: env,
        });
        core.apply_closures_memory_delta(previous_closure_bytes)
            .expect("a shared alias costs structure only and must fit the slack");
        assert_invariant(&core, "after alias under tight budget");

        // A second FRESH cell of the same size must still be refused — the
        // dedup must never under-charge new physical allocations.
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        let checkpoint = core
            .scope_chain
            .current()
            .expect("live frame")
            .bindings_checkpoint();
        core.scope_chain
            .current_mut()
            .expect("live frame")
            .insert_binding(
                "fresh".to_string(),
                ScopeBinding::with_state(BindingKind::Var, Value::str("z".repeat(4096)), true),
            );
        let refusal = core.apply_scope_chain_memory_delta(previous_scope_bytes);
        assert!(
            matches!(refusal, Err(InterpreterError::MemoryBudgetExceeded { .. })),
            "fresh physical payload must hit the budget: {refusal:?}"
        );
        // The interpreter's DeclareBinding rollback (bd-9vouw.154): the insert
        // copied the map the closure shares, so the original map goes back.
        let frame = core.scope_chain.current_mut().expect("live frame");
        assert!(frame.restore_copied_bindings(checkpoint));
        assert!(frame.get("fresh").is_none());
        assert_invariant(&core, "after refused declaration rollback");
    }
}

// ---------------------------------------------------------------------------
// Lane wrappers
// ---------------------------------------------------------------------------

/// Object-safe execution engine abstraction for substitutable interpreter lanes.
pub trait ExecutionEngine {
    /// Execute an IR3 module with the engine's default hook configuration.
    fn execute(
        &self,
        module: &Ir3Module,
        trace_id: &str,
    ) -> Result<ExecutionResult, InterpreterError>;

    /// Execute an IR3 module with an optional containment hook.
    fn execute_with_hook(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<ExecutionResult, InterpreterError>;
}

/// Deterministic execution profile: conservative budgets and replay-stable defaults.
pub struct QuickJsLane {
    config: InterpreterConfig,
    /// Optional sandboxed host-I/O provider (+ recorder) threaded into the
    /// interpreter so authorized `fs:` hostcalls perform and record real host
    /// effects (bd-f5b04.2.7). `None` keeps the fail-closed baseline.
    host_io: Option<Arc<dyn HostIoProvider>>,
    host_io_recorder: Option<Arc<dyn HostIoRecorder>>,
    process_spawn: Option<Arc<dyn ProcessSpawnProvider>>,
    host_effect_journal: Option<Arc<InMemoryHostEffectJournal>>,
    timer_effect_authority: Option<Arc<dyn TimerEffectAuthority>>,
    failed_console_output: Option<FailedConsoleSink>,
    entry_flow_label_ceiling: Option<Label>,
    module_resolver: Option<InstalledModuleResolver>,
}

impl Default for QuickJsLane {
    fn default() -> Self {
        Self {
            config: execution_profile_config(InterpreterConfig::quickjs_defaults()),
            host_io: None,
            host_io_recorder: None,
            process_spawn: None,
            host_effect_journal: None,
            timer_effect_authority: None,
            failed_console_output: None,
            entry_flow_label_ceiling: None,
            module_resolver: None,
        }
    }
}

impl QuickJsLane {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: InterpreterConfig) -> Self {
        Self {
            config,
            host_io: None,
            host_io_recorder: None,
            process_spawn: None,
            host_effect_journal: None,
            timer_effect_authority: None,
            failed_console_output: None,
            entry_flow_label_ceiling: None,
            module_resolver: None,
        }
    }

    /// Install a sandboxed host-I/O provider (+ optional recorder) for this lane;
    /// it is threaded into each `InterpreterCore` this lane creates (bd-f5b04.2.7).
    pub fn set_host_io(
        &mut self,
        provider: Arc<dyn HostIoProvider>,
        recorder: Option<Arc<dyn HostIoRecorder>>,
    ) {
        self.host_io = Some(provider);
        self.host_io_recorder = recorder;
    }

    /// Install the separately admitted process provider and the execution-wide
    /// host-effect journal on this lane.
    pub fn set_process_spawn(
        &mut self,
        provider: Arc<dyn ProcessSpawnProvider>,
        journal: Arc<InMemoryHostEffectJournal>,
    ) {
        self.process_spawn = Some(provider);
        self.host_effect_journal = Some(journal);
    }

    pub fn set_timer_effect_authority(&mut self, authority: Arc<dyn TimerEffectAuthority>) {
        self.timer_effect_authority = Some(authority);
    }

    /// Install the sink that receives this lane's console output when an
    /// execution fails, so output printed before a throw is not lost.
    pub fn set_failed_console_output_sink(&mut self, sink: FailedConsoleSink) {
        self.failed_console_output = Some(sink);
    }

    /// The entry module's flow label ceiling for the cores this lane
    /// creates (bd-j8f7q).
    pub fn set_entry_flow_label_ceiling(&mut self, ceiling: Label) {
        self.entry_flow_label_ceiling = Some(ceiling);
    }

    pub fn execute(
        &self,
        module: &Ir3Module,
        trace_id: &str,
    ) -> Result<ExecutionResult, InterpreterError> {
        self.execute_with_hook(module, trace_id, None)
    }

    pub fn execute_with_hook(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<ExecutionResult, InterpreterError> {
        self.execute_with_hook_and_compact_tier1(module, trace_id, hook, None)
    }

    #[cfg(test)]
    pub(super) fn execute_with_compact_tier1(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        compact_tier1: &CompactTier1Program,
    ) -> Result<ExecutionResult, InterpreterError> {
        self.execute_with_hook_and_compact_tier1(module, trace_id, None, Some(compact_tier1))
    }

    pub(super) fn execute_with_hook_and_compact_tier1(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
        compact_tier1: Option<&CompactTier1Program>,
    ) -> Result<ExecutionResult, InterpreterError> {
        execute_lane_with_provisioned_stack(
            self.config.clone(),
            self.host_io.clone(),
            self.host_io_recorder.clone(),
            self.process_spawn.clone(),
            self.host_effect_journal.clone(),
            self.timer_effect_authority.clone(),
            self.failed_console_output.clone(),
            self.entry_flow_label_ceiling.clone(),
            self.module_resolver.clone(),
            module,
            trace_id,
            hook,
            compact_tier1,
        )
    }
}

impl ExecutionEngine for QuickJsLane {
    fn execute(
        &self,
        module: &Ir3Module,
        trace_id: &str,
    ) -> Result<ExecutionResult, InterpreterError> {
        QuickJsLane::execute(self, module, trace_id)
    }

    fn execute_with_hook(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<ExecutionResult, InterpreterError> {
        QuickJsLane::execute_with_hook(self, module, trace_id, hook)
    }
}

/// Throughput execution profile: larger budgets for heavier workloads.
pub struct V8Lane {
    config: InterpreterConfig,
    /// Optional sandboxed host-I/O provider (+ recorder), mirroring [`QuickJsLane`]
    /// (bd-f5b04.2.7). `None` keeps the fail-closed baseline.
    host_io: Option<Arc<dyn HostIoProvider>>,
    host_io_recorder: Option<Arc<dyn HostIoRecorder>>,
    process_spawn: Option<Arc<dyn ProcessSpawnProvider>>,
    host_effect_journal: Option<Arc<InMemoryHostEffectJournal>>,
    timer_effect_authority: Option<Arc<dyn TimerEffectAuthority>>,
    failed_console_output: Option<FailedConsoleSink>,
    entry_flow_label_ceiling: Option<Label>,
    module_resolver: Option<InstalledModuleResolver>,
}

impl Default for V8Lane {
    fn default() -> Self {
        Self {
            config: execution_profile_config(InterpreterConfig::v8_defaults()),
            host_io: None,
            host_io_recorder: None,
            process_spawn: None,
            host_effect_journal: None,
            timer_effect_authority: None,
            failed_console_output: None,
            entry_flow_label_ceiling: None,
            module_resolver: None,
        }
    }
}

pub(super) fn execution_profile_config(mut config: InterpreterConfig) -> InterpreterConfig {
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

pub(super) fn interpreter_execution_stack_bytes(
    max_call_depth: usize,
) -> Result<usize, InterpreterError> {
    max_call_depth
        .checked_mul(INTERPRETER_EXECUTION_STACK_PER_CALL_DEPTH_BYTES)
        .and_then(|depth_bytes| {
            INTERPRETER_EXECUTION_STACK_BASE_BYTES.checked_add(depth_bytes)
        })
        .ok_or_else(|| InterpreterError::InternalError {
            details: format!(
                "configured max_call_depth {max_call_depth} overflows the native execution-stack reservation"
            ),
        })
}

pub(super) const MAX_IDLE_BASELINE_WORKERS: usize = 8;

pub(super) type BaselineWorkerOutcome =
    std::thread::Result<Result<ExecutionResult, InterpreterError>>;
pub(super) type BaselineWorkerTask =
    Box<dyn FnOnce() -> Result<ExecutionResult, InterpreterError> + Send>;

pub(super) struct PooledBaselineWorker {
    stack_bytes: usize,
    task_tx: std::sync::mpsc::SyncSender<(
        BaselineWorkerTask,
        std::sync::mpsc::SyncSender<BaselineWorkerOutcome>,
    )>,
    _join_handle: std::thread::JoinHandle<()>,
}

pub(super) fn baseline_worker_pool() -> &'static std::sync::Mutex<Vec<PooledBaselineWorker>> {
    static POOL: OnceLock<std::sync::Mutex<Vec<PooledBaselineWorker>>> = OnceLock::new();
    POOL.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

impl PooledBaselineWorker {
    pub(super) fn acquire(required_stack_bytes: usize) -> Result<Self, InterpreterError> {
        if let Ok(mut pool) = baseline_worker_pool().lock()
            && let Some(idx) = pool
                .iter()
                .position(|worker| worker.stack_bytes >= required_stack_bytes)
        {
            return Ok(pool.swap_remove(idx));
        }

        let (task_tx, task_rx) = std::sync::mpsc::sync_channel::<(
            BaselineWorkerTask,
            std::sync::mpsc::SyncSender<BaselineWorkerOutcome>,
        )>(0);
        let join_handle = std::thread::Builder::new()
            .name("frankenengine-baseline".to_string())
            .stack_size(required_stack_bytes)
            .spawn(move || {
                while let Ok((task, reply_tx)) = task_rx.recv() {
                    let outcome =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
                    let _ = reply_tx.send(outcome);
                }
            })
            .map_err(|error| InterpreterError::InternalError {
                details: format!(
                    "failed to provision {required_stack_bytes}-byte baseline execution stack: {error}"
                ),
            })?;
        Ok(Self {
            stack_bytes: required_stack_bytes,
            task_tx,
            _join_handle: join_handle,
        })
    }

    pub(super) fn release(self) {
        if let Ok(mut pool) = baseline_worker_pool().lock()
            && pool.len() < MAX_IDLE_BASELINE_WORKERS
        {
            pool.push(self);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_lane_with_provisioned_stack(
    config: InterpreterConfig,
    host_io: Option<Arc<dyn HostIoProvider>>,
    host_io_recorder: Option<Arc<dyn HostIoRecorder>>,
    process_spawn: Option<Arc<dyn ProcessSpawnProvider>>,
    host_effect_journal: Option<Arc<InMemoryHostEffectJournal>>,
    timer_effect_authority: Option<Arc<dyn TimerEffectAuthority>>,
    failed_console_output: Option<FailedConsoleSink>,
    entry_flow_label_ceiling: Option<Label>,
    module_resolver: Option<InstalledModuleResolver>,
    module: &Ir3Module,
    trace_id: &str,
    hook: Option<Arc<dyn InterpreterHook>>,
    compact_tier1: Option<&CompactTier1Program>,
) -> Result<ExecutionResult, InterpreterError> {
    let stack_bytes =
        interpreter_execution_stack_bytes(config.max_call_depth.min(MAX_NATIVE_RUN_LOOP_DEPTH))?;
    let worker = PooledBaselineWorker::acquire(stack_bytes)?;
    let module = module.clone();
    let trace_id = trace_id.to_owned();
    let compact_tier1 = compact_tier1.cloned();
    let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel::<BaselineWorkerOutcome>(1);
    let task: BaselineWorkerTask = Box::new(move || {
        let mut core = InterpreterCore::new(config, &trace_id);
        core.module_resolver = module_resolver;
        if let Some(hook) = hook {
            core.set_hook(hook);
        }
        if let Some(provider) = host_io {
            core.set_host_io(provider, host_io_recorder);
        }
        if let (Some(provider), Some(journal)) = (process_spawn, host_effect_journal) {
            core.set_process_spawn(provider, journal);
        }
        if let Some(authority) = timer_effect_authority {
            core.set_timer_effect_authority(authority);
        }
        if let Some(ceiling) = entry_flow_label_ceiling {
            core.set_entry_flow_label_ceiling(ceiling);
        }
        let execution = match compact_tier1.as_ref() {
            Some(program) => core.execute_ephemeral_with_compact_tier1(&module, program),
            None => core.execute_ephemeral(&module),
        };
        let outcome = match execution {
            Ok(result) => Ok(result),
            Err(InterpreterError::ContainmentActionRequested { action, reason }) => {
                match requested_hook_action_from_error(action.as_str(), reason.clone()) {
                    Some(requested_hook_action) => Ok(core
                        .take_execution_result_with_trace_handoff(
                            LabeledReturn {
                                value: Value::Undefined,
                                label: Label::Public,
                            },
                            Some(requested_hook_action),
                            TraceHandoff::DrainEphemeralCore,
                        )),
                    None => Err(InterpreterError::ContainmentActionRequested { action, reason }),
                }
            }
            Err(error) => Err(error),
        };
        // A failed execution keeps its console buffer in the core
        // (only a completed one moves it into the result); hand it
        // to the sink before the core is dropped.
        if outcome.is_err()
            && let Some(sink) = &failed_console_output
            && let Ok(mut captured) = sink.lock()
        {
            *captured = core.console_output().to_vec();
        }
        outcome
    });

    worker
        .task_tx
        .send((task, reply_tx))
        .map_err(|error| InterpreterError::InternalError {
            details: format!("pooled baseline execution worker disconnected on dispatch: {error}"),
        })?;
    let outcome = reply_rx
        .recv()
        .map_err(|error| InterpreterError::InternalError {
            details: format!("pooled baseline execution worker disconnected mid-run: {error}"),
        })?;
    worker.release();
    match outcome {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

impl V8Lane {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: InterpreterConfig) -> Self {
        Self {
            config,
            host_io: None,
            host_io_recorder: None,
            process_spawn: None,
            host_effect_journal: None,
            timer_effect_authority: None,
            failed_console_output: None,
            entry_flow_label_ceiling: None,
            module_resolver: None,
        }
    }

    /// Install a sandboxed host-I/O provider (+ optional recorder) for this lane,
    /// mirroring [`QuickJsLane::set_host_io`] (bd-f5b04.2.7).
    pub fn set_host_io(
        &mut self,
        provider: Arc<dyn HostIoProvider>,
        recorder: Option<Arc<dyn HostIoRecorder>>,
    ) {
        self.host_io = Some(provider);
        self.host_io_recorder = recorder;
    }

    /// Install the separately admitted process provider and the execution-wide
    /// host-effect journal on this lane.
    pub fn set_process_spawn(
        &mut self,
        provider: Arc<dyn ProcessSpawnProvider>,
        journal: Arc<InMemoryHostEffectJournal>,
    ) {
        self.process_spawn = Some(provider);
        self.host_effect_journal = Some(journal);
    }

    pub fn set_timer_effect_authority(&mut self, authority: Arc<dyn TimerEffectAuthority>) {
        self.timer_effect_authority = Some(authority);
    }

    /// Install the sink that receives this lane's console output when an
    /// execution fails, so output printed before a throw is not lost.
    pub fn set_failed_console_output_sink(&mut self, sink: FailedConsoleSink) {
        self.failed_console_output = Some(sink);
    }

    /// The entry module's flow label ceiling for the cores this lane
    /// creates (bd-j8f7q).
    pub fn set_entry_flow_label_ceiling(&mut self, ceiling: Label) {
        self.entry_flow_label_ceiling = Some(ceiling);
    }

    pub fn execute(
        &self,
        module: &Ir3Module,
        trace_id: &str,
    ) -> Result<ExecutionResult, InterpreterError> {
        self.execute_with_hook(module, trace_id, None)
    }

    pub fn execute_with_hook(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<ExecutionResult, InterpreterError> {
        self.execute_with_hook_and_compact_tier1(module, trace_id, hook, None)
    }

    pub(super) fn execute_with_hook_and_compact_tier1(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
        compact_tier1: Option<&CompactTier1Program>,
    ) -> Result<ExecutionResult, InterpreterError> {
        execute_lane_with_provisioned_stack(
            self.config.clone(),
            self.host_io.clone(),
            self.host_io_recorder.clone(),
            self.process_spawn.clone(),
            self.host_effect_journal.clone(),
            self.timer_effect_authority.clone(),
            self.failed_console_output.clone(),
            self.entry_flow_label_ceiling.clone(),
            self.module_resolver.clone(),
            module,
            trace_id,
            hook,
            compact_tier1,
        )
    }
}

impl ExecutionEngine for V8Lane {
    fn execute(
        &self,
        module: &Ir3Module,
        trace_id: &str,
    ) -> Result<ExecutionResult, InterpreterError> {
        V8Lane::execute(self, module, trace_id)
    }

    fn execute_with_hook(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<ExecutionResult, InterpreterError> {
        V8Lane::execute_with_hook(self, module, trace_id, hook)
    }
}

// ---------------------------------------------------------------------------
// Stack trace formatting (bd-2fx18)
// ---------------------------------------------------------------------------

/// Stack trace formatting configuration.
#[derive(Debug, Clone)]
pub(super) struct StackTraceConfig {
    /// Maximum number of frames to include before truncation.
    max_frames: usize,
    /// Whether to include async frame boundaries.
    include_async_frames: bool,
}

impl Default for StackTraceConfig {
    fn default() -> Self {
        Self {
            max_frames: 50,
            include_async_frames: true,
        }
    }
}

/// Information about a single stack frame for formatting.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct StackFrameInfo {
    /// Function name (or "<anonymous>" if unknown).
    function_name: String,
    /// Source file name (or "<unknown>" if unavailable).
    file_name: String,
    /// Line number (1-based, 0 if unknown).
    line_number: u32,
    /// Column number (1-based, 0 if unknown).
    column_number: u32,
    /// Whether this frame represents an async boundary.
    is_async_boundary: bool,
}

impl StackFrameInfo {
    /// Create a new stack frame with minimal information.
    pub(super) fn new(function_name: String) -> Self {
        Self {
            function_name,
            file_name: "<unknown>".to_string(),
            line_number: 0,
            column_number: 0,
            is_async_boundary: false,
        }
    }

    /// Create a new stack frame with source location.
    pub(super) fn with_location(
        function_name: String,
        file_name: String,
        line_number: u32,
        column_number: u32,
    ) -> Self {
        Self {
            function_name,
            file_name,
            line_number,
            column_number,
            is_async_boundary: false,
        }
    }

    /// Mark this frame as an async boundary.
    pub(super) fn into_async_boundary(mut self) -> Self {
        self.is_async_boundary = true;
        self
    }

    /// Format this frame in V8 style: "    at funcName (file:line:col)".
    pub(super) fn format(&self) -> String {
        if self.is_async_boundary {
            return "    at async".to_string();
        }

        let location = if self.line_number > 0 && self.column_number > 0 {
            format!(
                "{}:{}:{}",
                self.file_name, self.line_number, self.column_number
            )
        } else if self.line_number > 0 {
            format!("{}:{}", self.file_name, self.line_number)
        } else {
            self.file_name.clone()
        };

        format!("    at {} ({})", self.function_name, location)
    }
}

impl InterpreterCore {
    /// Capture current call stack and format it as a stack trace string.
    pub(super) fn format_stack_trace(&self) -> String {
        self.format_stack_trace_with_config(&StackTraceConfig::default())
    }

    /// Capture and format call stack with custom configuration.
    pub(super) fn format_stack_trace_with_config(&self, config: &StackTraceConfig) -> String {
        let (frames, omitted) = self.capture_stack_frames(config);
        self.format_captured_frames(&frames, omitted)
    }

    /// The function table belongs to the executing program, which can differ
    /// from the ordinary resolution owner for a generated Function body.
    /// Looking it up here keeps stack capture cold and does not retain another
    /// program or copy diagnostic names on every guest call (bd-9vouw.502).
    pub(super) fn stack_trace_module(&self) -> Option<&Ir3Module> {
        if let Some(handle) = self.active_generated_function_artifact {
            return self
                .resolve_generated_function_artifact(handle.owner_program_id, handle.artifact_id)
                .ok()
                .map(|artifact| artifact.compiled_module.as_ref());
        }
        self.current_module_specifier
            .as_ref()
            .and_then(|specifier| self.module_state.modules.get(specifier))
            .and_then(|record| record.compiled_module.as_deref())
    }

    /// Capture the active frame followed by its callers, newest first.
    /// A CallFrame stores the *callee's* function index and the *caller's*
    /// return address. Pairing both fields as one frame used to duplicate the
    /// innermost function and report the remaining callers in reverse order.
    /// Isolated cross-program callbacks have their own stack; their synthetic
    /// return trampoline is not a JavaScript caller and must not be printed.
    pub(super) fn capture_stack_frames(
        &self,
        config: &StackTraceConfig,
    ) -> (Vec<StackFrameInfo>, usize) {
        let module = self.stack_trace_module();
        let mut frames = Vec::new();
        let mut omitted = 0;
        if config.max_frames > 0 {
            frames.push(self.capture_current_frame(module));
        } else {
            omitted += 1;
        }

        for (index, call_frame) in self.call_stack.iter().enumerate().rev() {
            if module.is_some_and(|module| call_frame.return_ip >= module.instructions.len()) {
                continue;
            }
            if config.include_async_frames && call_frame.async_function_id.is_some() {
                if frames.len() < config.max_frames {
                    frames.push(StackFrameInfo::new("<async>".to_string()).into_async_boundary());
                } else {
                    omitted += 1;
                }
            }
            if frames.len() < config.max_frames {
                frames.push(self.capture_call_frame_info(module, index));
            } else {
                omitted += 1;
            }
        }
        (frames, omitted)
    }

    /// Capture information about the current executing frame.
    pub(super) fn capture_current_frame(&self, module: Option<&Ir3Module>) -> StackFrameInfo {
        let function_name = self
            .call_stack
            .last()
            .and_then(|frame| self.stack_trace_function_name(module, frame.function_index))
            .unwrap_or_else(|| "<anonymous>".to_string());
        self.stack_frame_with_program(function_name, module)
    }

    /// Recover the caller of this callee edge from the preceding activation.
    /// The first edge returns to top-level code, which has no function name.
    pub(super) fn capture_call_frame_info(
        &self,
        module: Option<&Ir3Module>,
        frame_index: usize,
    ) -> StackFrameInfo {
        let function_name = frame_index
            .checked_sub(1)
            .and_then(|index| self.call_stack.get(index))
            .and_then(|frame| self.stack_trace_function_name(module, frame.function_index))
            .unwrap_or_else(|| "<anonymous>".to_string());
        self.stack_frame_with_program(function_name, module)
    }

    pub(super) fn stack_trace_function_name(
        &self,
        module: Option<&Ir3Module>,
        function_index: Option<u32>,
    ) -> Option<String> {
        module?
            .function_table
            .get(function_index? as usize)?
            .name
            .as_ref()
            .filter(|name| !name.is_empty())
            .cloned()
    }

    pub(super) fn stack_frame_with_program(
        &self,
        function_name: String,
        module: Option<&Ir3Module>,
    ) -> StackFrameInfo {
        let source_file = module
            .map(|module| module.header.source_label.as_str())
            .or(self.current_module_specifier.as_deref())
            .filter(|specifier| !specifier.is_empty())
            .unwrap_or("<unknown>")
            .to_string();
        // IR3 has no instruction-to-source table yet. An instruction index is
        // not a source line, and adding `.js` corrupts real .js/.mjs/.cjs paths
        // and opaque resolver identities. Preserve the exact program label and
        // leave positions unknown until lowering supplies actual provenance.
        StackFrameInfo::with_location(function_name, source_file, 0, 0)
    }

    /// Format captured frames into a complete stack trace string.
    pub(super) fn format_captured_frames(
        &self,
        frames: &[StackFrameInfo],
        omitted: usize,
    ) -> String {
        let mut result = String::new();
        for frame_info in frames {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&frame_info.format());
        }
        if omitted > 0 {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&format!("    ... {omitted} more frames"));
        }
        result
    }
}

pub(super) fn format_requested_hook_action(action: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) if !reason.is_empty() => format!("{action} ({reason})"),
        _ => action.to_string(),
    }
}

pub(super) fn requested_hook_action_from_error(
    action: &str,
    reason: Option<String>,
) -> Option<HookAction> {
    match action {
        "challenge" => Some(HookAction::Challenge(ChallengeToken {
            // SAFETY: challenge action requires reason, validated by caller
            token: reason.expect("operation should succeed for valid inputs"),
        })),
        "sandbox" => Some(HookAction::Sandbox),
        "suspend" => Some(HookAction::Suspend),
        // SAFETY: terminate action requires reason, validated by caller
        "terminate" => Some(HookAction::Terminate(
            reason.expect("operation should succeed for valid inputs"),
        )),
        // SAFETY: quarantine action requires reason, validated by caller
        "quarantine" => Some(HookAction::Quarantine(
            reason.expect("operation should succeed for valid inputs"),
        )),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// LaneRouter — policy-directed routing
// ---------------------------------------------------------------------------

/// Execution-profile choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneChoice {
    /// Deterministic baseline-interpreter profile selected.
    QuickJs,
    /// Throughput-tuned baseline-interpreter profile selected.
    V8,
}

impl LaneChoice {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::QuickJs => DETERMINISTIC_PROFILE_LABEL,
            Self::V8 => THROUGHPUT_PROFILE_LABEL,
        }
    }

    pub const fn legacy_lineage_label(self) -> &'static str {
        match self {
            Self::QuickJs => LEGACY_QUICKJS_PROFILE_LABEL,
            Self::V8 => LEGACY_V8_PROFILE_LABEL,
        }
    }

    pub(super) fn from_label(label: &str) -> Option<Self> {
        match label {
            DETERMINISTIC_PROFILE_LABEL | LEGACY_QUICKJS_PROFILE_LABEL | "QuickJs" | "quickjs" => {
                Some(Self::QuickJs)
            }
            THROUGHPUT_PROFILE_LABEL | LEGACY_V8_PROFILE_LABEL | "V8" | "v8" => Some(Self::V8),
            _ => None,
        }
    }
}

impl fmt::Display for LaneChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_label())
    }
}

impl Serialize for LaneChoice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.stable_label())
    }
}

impl<'de> Deserialize<'de> for LaneChoice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_label(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown execution profile label `{raw}`"))
        })
    }
}

/// Reason for lane selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneReason {
    /// Security-sensitive context requires deterministic execution.
    SecuritySensitive,
    /// Throughput-optimized workload.
    ThroughputOptimized,
    /// Explicit policy directive.
    PolicyDirective,
    /// Default fallback to deterministic lane.
    DefaultFallback,
}

impl LaneReason {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::SecuritySensitive => "security_sensitive",
            Self::ThroughputOptimized => "throughput_optimized",
            Self::PolicyDirective => "policy_directive",
            Self::DefaultFallback => "default_deterministic_profile",
        }
    }

    pub(super) fn from_label(label: &str) -> Option<Self> {
        match label {
            "security_sensitive" | "SecuritySensitive" => Some(Self::SecuritySensitive),
            "throughput_optimized" | "ThroughputOptimized" => Some(Self::ThroughputOptimized),
            "policy_directive" | "PolicyDirective" => Some(Self::PolicyDirective),
            "default_deterministic_profile" | "DefaultFallback" => Some(Self::DefaultFallback),
            _ => None,
        }
    }
}

impl fmt::Display for LaneReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_label())
    }
}

impl Serialize for LaneReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.stable_label())
    }
}

impl<'de> Deserialize<'de> for LaneReason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_label(&raw)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown lane reason `{raw}`")))
    }
}

/// Result of lane routing.
#[derive(Debug, Clone)]
pub struct RoutedResult {
    /// Which lane was chosen.
    pub lane: LaneChoice,
    /// Why this lane was chosen.
    pub reason: LaneReason,
    /// The execution result.
    pub result: ExecutionResult,
}

/// Policy-directed lane router.
pub struct LaneRouter {
    quickjs: QuickJsLane,
    v8: V8Lane,
}

impl Default for LaneRouter {
    fn default() -> Self {
        Self {
            quickjs: QuickJsLane::new(),
            v8: V8Lane::new(),
        }
    }
}

impl LaneRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_configs(quickjs_config: InterpreterConfig, v8_config: InterpreterConfig) -> Self {
        Self {
            quickjs: QuickJsLane::with_config(quickjs_config),
            v8: V8Lane::with_config(v8_config),
        }
    }

    /// Install one closed-world source authority on both execution lanes.
    pub fn set_module_resolver(
        &mut self,
        resolver: ExecutionModuleResolver,
        entry_hash: ContentHash,
        context: ResolutionContext,
    ) {
        let installed = InstalledModuleResolver {
            resolver,
            entry_hash,
            context,
        };
        self.quickjs.module_resolver = Some(installed.clone());
        self.v8.module_resolver = Some(installed);
    }

    /// Install a sandboxed host-I/O provider (+ optional recorder) on both lanes so
    /// whichever lane is selected threads it into its `InterpreterCore`
    /// (bd-f5b04.2.7). The orchestrator calls this before `execute_with_hook`.
    pub fn set_host_io(
        &mut self,
        provider: Arc<dyn HostIoProvider>,
        recorder: Option<Arc<dyn HostIoRecorder>>,
    ) {
        self.quickjs.set_host_io(provider.clone(), recorder.clone());
        self.v8.set_host_io(provider, recorder);
    }

    /// Install the separately admitted process provider and shared journal on
    /// both lanes so routing cannot drop extraordinary process authority.
    pub fn set_process_spawn(
        &mut self,
        provider: Arc<dyn ProcessSpawnProvider>,
        journal: Arc<InMemoryHostEffectJournal>,
    ) {
        self.quickjs
            .set_process_spawn(provider.clone(), journal.clone());
        self.v8.set_process_spawn(provider, journal);
    }

    /// Install the same sealed timer-effect authority on both lanes so adaptive
    /// routing cannot bypass the cell/cancellation/evidence boundary.
    pub fn set_timer_effect_authority(&mut self, authority: Arc<dyn TimerEffectAuthority>) {
        self.quickjs.set_timer_effect_authority(authority.clone());
        self.v8.set_timer_effect_authority(authority);
    }

    /// Install the same failed-run console sink on both lanes so whichever
    /// lane runs the module reports what it printed before failing.
    pub fn set_failed_console_output_sink(&mut self, sink: FailedConsoleSink) {
        self.quickjs
            .set_failed_console_output_sink(Arc::clone(&sink));
        self.v8.set_failed_console_output_sink(sink);
    }

    /// Give both lanes the entry module's flow label ceiling (bd-j8f7q), so
    /// an import that cycles back to the entry is checked against it.
    pub fn set_entry_flow_label_ceiling(&mut self, ceiling: Label) {
        self.quickjs.set_entry_flow_label_ceiling(ceiling.clone());
        self.v8.set_entry_flow_label_ceiling(ceiling);
    }

    /// Route and execute the module.
    pub fn execute(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        force_lane: Option<LaneChoice>,
    ) -> Result<RoutedResult, InterpreterError> {
        self.execute_with_hook_and_compact_tier1(module, trace_id, force_lane, None, None)
    }

    pub(crate) fn execute_with_compact_tier1(
        &self,
        module: &Ir3Module,
        compact_tier1: &CompactTier1Program,
        trace_id: &str,
        force_lane: Option<LaneChoice>,
    ) -> Result<RoutedResult, InterpreterError> {
        self.execute_with_hook_and_compact_tier1(
            module,
            trace_id,
            force_lane,
            None,
            Some(compact_tier1),
        )
    }

    pub fn execute_with_hook(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        force_lane: Option<LaneChoice>,
        hook: Option<Arc<dyn InterpreterHook>>,
    ) -> Result<RoutedResult, InterpreterError> {
        self.execute_with_hook_and_compact_tier1(module, trace_id, force_lane, hook, None)
    }

    pub(crate) fn execute_with_hook_and_compact_tier1(
        &self,
        module: &Ir3Module,
        trace_id: &str,
        force_lane: Option<LaneChoice>,
        hook: Option<Arc<dyn InterpreterHook>>,
        compact_tier1: Option<&CompactTier1Program>,
    ) -> Result<RoutedResult, InterpreterError> {
        let (lane, reason) = if let Some(forced) = force_lane {
            (forced, LaneReason::PolicyDirective)
        } else {
            self.select_lane(module)
        };

        let result = match (lane, compact_tier1) {
            (LaneChoice::QuickJs, Some(program)) => self
                .quickjs
                .execute_with_hook_and_compact_tier1(module, trace_id, hook, Some(program))?,
            (LaneChoice::V8, Some(program)) => self.v8.execute_with_hook_and_compact_tier1(
                module,
                trace_id,
                hook,
                Some(program),
            )?,
            (LaneChoice::QuickJs, None) => {
                self.quickjs.execute_with_hook(module, trace_id, hook)?
            }
            (LaneChoice::V8, None) => self.v8.execute_with_hook(module, trace_id, hook)?,
        };

        Ok(RoutedResult {
            lane,
            reason,
            result,
        })
    }

    pub(super) fn select_lane(&self, module: &Ir3Module) -> (LaneChoice, LaneReason) {
        // Capabilities force the deterministic baseline profile.
        if !module.required_capabilities.is_empty() {
            return (LaneChoice::QuickJs, LaneReason::SecuritySensitive);
        }

        // Large programs use the throughput-tuned baseline profile.
        if module.instructions.len() > 1000 {
            return (LaneChoice::V8, LaneReason::ThroughputOptimized);
        }

        // Default: deterministic profile.
        (LaneChoice::QuickJs, LaneReason::DefaultFallback)
    }

    /// Enable profiling with the specified configuration.
    pub fn enable_profiling(&mut self, _config: crate::profiling::ProfilingConfig) {
        // Lane routing creates a fresh interpreter core per execution; profiling
        // is owned by the core rather than persisted on the router.
    }

    /// Disable profiling and return collected data.
    pub fn disable_profiling(&mut self) -> Option<crate::profiling::Profiler> {
        None
    }

    /// Get reference to current profiling data.
    pub fn profiling_data(&self) -> Option<&crate::profiling::Profiler> {
        None
    }
}

// ---------------------------------------------------------------------------
// Number.prototype.toFixed (exact-decimal, round-half-up)
// ---------------------------------------------------------------------------

/// The exact number of fractional decimal digits in the terminating decimal
/// expansion of a finite, non-negative `f64`.
///
/// Every finite `f64` is a dyadic rational `m * 2^e`. When `e < 0` (after
/// reducing out trailing powers of two) the value terminates after exactly
/// `-e` decimal places, because `2^e = 5^(-e) / 10^(-e)`. The bound is at most
/// 1074 (the smallest positive subnormal, `2^-1074`).
pub(super) fn exact_fractional_digit_count(value: f64) -> usize {
    debug_assert!(value.is_finite() && value >= 0.0);
    if value == 0.0 {
        return 0;
    }
    let bits = value.to_bits();
    let raw_exponent = ((bits >> 52) & 0x7ff) as i64;
    let mantissa_field = bits & 0x000f_ffff_ffff_ffff;
    let (mantissa, exp2) = if raw_exponent == 0 {
        // Subnormal: value = mantissa_field * 2^-1074.
        (mantissa_field, -1074_i64)
    } else {
        // Normal: value = (2^52 | mantissa_field) * 2^(raw_exponent - 1075).
        ((1u64 << 52) | mantissa_field, raw_exponent - 1075)
    };
    // Reduce out powers of two so `exp2` reflects the true terminating place.
    let exp2 = exp2 + i64::from(mantissa.trailing_zeros());
    if exp2 >= 0 { 0 } else { (-exp2) as usize }
}

/// Add one to a non-negative ASCII decimal digit string, propagating carry and
/// growing the string by one digit on overflow (e.g. `"99"` -> `"100"`).
pub(super) fn increment_decimal_digits(digits: &str) -> String {
    let mut bytes: Vec<u8> = digits.as_bytes().to_vec();
    let mut index = bytes.len();
    while index > 0 {
        index -= 1;
        if bytes[index] == b'9' {
            bytes[index] = b'0';
        } else {
            bytes[index] += 1;
            return String::from_utf8(bytes).expect("ascii digits remain ascii");
        }
    }
    // Carried out of the most significant digit.
    let mut result = String::with_capacity(bytes.len() + 1);
    result.push('1');
    result.push_str(std::str::from_utf8(&bytes).expect("ascii digits remain ascii"));
    result
}

/// `Number.prototype.toFixed(digits)` per ECMAScript (ES2023 21.1.3.3).
///
/// Implemented with exact decimal arithmetic so that exact dyadic ties round
/// half *up* (toward the larger magnitude) rather than to-even, matching the
/// spec's "if there are two such `n`, pick the larger `n`" tie-break. Rust's
/// `format!("{:.n$}")` uses round-half-to-even, which diverges on exact ties
/// such as `(2.5).toFixed(0)` ("3" per spec, not "2") and `(0.25).toFixed(1)`
/// ("0.3", not "0.2").
///
/// `digits` is the (already validated/clamped) fraction-digit count. The
/// magnitude is rendered to its exact terminating decimal expansion — Rust's
/// float formatter is exact when asked for at least the true number of
/// fractional digits, so no `format!` rounding is ever applied — and then
/// rounded to `digits` places by inspecting the single decimal digit at the
/// cut, which fully determines round-half-up for a non-negative value.
pub(super) fn number_to_fixed_string(num: f64, digits: usize) -> String {
    if num.is_nan() {
        return "NaN".to_string();
    }
    if num.is_infinite() {
        return if num.is_sign_positive() {
            "Infinity".to_string()
        } else {
            "-Infinity".to_string()
        };
    }
    // ES2020 20.1.3.3 step 9: from 10^21 up the result is ToString(x)
    // (`(1e21).toFixed(2)` is "1e+21", not a 22-digit integer).
    if num.abs() >= 1e21 {
        return Float64::new(num).to_string();
    }
    // Sign is handled separately on the magnitude. `num < 0.0` is false for
    // -0.0, so `(-0).toFixed(2)` yields "0.00" as the spec requires.
    let negative = num < 0.0;
    let magnitude = num.abs();

    // Exact terminating decimal expansion of the magnitude (never rounded).
    let exact_frac_len = exact_fractional_digit_count(magnitude);
    let exact = format!("{magnitude:.exact_frac_len$}");
    let (int_part, frac_part) = match exact.split_once('.') {
        Some((int_part, frac_part)) => (int_part, frac_part),
        None => (exact.as_str(), ""),
    };

    // Case A: the exact expansion is already at or below the requested
    // precision — pad with trailing zeros, no rounding possible.
    if frac_part.len() <= digits {
        if digits == 0 {
            return format_signed(negative, int_part);
        }
        let mut body = String::with_capacity(int_part.len() + 1 + digits);
        body.push_str(int_part);
        body.push('.');
        body.push_str(frac_part);
        for _ in frac_part.len()..digits {
            body.push('0');
        }
        return format_signed(negative, &body);
    }

    // Case B: must round. For a non-negative value, round-half-up keeps the
    // truncated value when the first dropped digit is < 5 and increments it
    // otherwise (>=5 covers both "above the half" and the exact tie, which the
    // spec breaks upward).
    let round_up = frac_part.as_bytes()[digits] >= b'5';
    let mut combined = String::with_capacity(int_part.len() + digits);
    combined.push_str(int_part);
    combined.push_str(&frac_part[..digits]);
    if round_up {
        combined = increment_decimal_digits(&combined);
    }

    // Re-split into integer/fraction, guaranteeing at least one integer digit.
    let min_len = digits + 1;
    if combined.len() < min_len {
        let mut padded = String::with_capacity(min_len);
        for _ in combined.len()..min_len {
            padded.push('0');
        }
        padded.push_str(&combined);
        combined = padded;
    }
    let split_at = combined.len() - digits;
    let int_str = combined[..split_at].trim_start_matches('0');
    let int_final = if int_str.is_empty() { "0" } else { int_str };
    if digits == 0 {
        format_signed(negative, int_final)
    } else {
        let frac_str = &combined[split_at..];
        format_signed(negative, &format!("{int_final}.{frac_str}"))
    }
}

/// Prefix `body` with `-` when `negative`.
///
/// The spec fixes the sign from `x < 0` on the *original* value before
/// rounding, so a strictly-negative input that rounds to zero magnitude still
/// renders with a leading `-` (e.g. `(-0.0001).toFixed(2)` -> `"-0.00"`).
/// Negative zero never reaches here with `negative == true` because
/// `-0.0 < 0.0` is false, so `(-0).toFixed(2)` -> `"0.00"`.
pub(super) fn format_signed(negative: bool, body: &str) -> String {
    if negative {
        format!("-{body}")
    } else {
        body.to_string()
    }
}

#[cfg(test)]
mod number_to_fixed_tests {
    use super::number_to_fixed_string;

    #[test]
    fn from_1e21_up_the_result_is_number_to_string() {
        // Node v22.2.0: (1e21).toFixed(2) etc.
        assert_eq!(number_to_fixed_string(1e21, 2), "1e+21");
        assert_eq!(number_to_fixed_string(-1e21, 0), "-1e+21");
        assert_eq!(number_to_fixed_string(1.5e22, 3), "1.5e+22");
        assert_eq!(
            number_to_fixed_string(999_999_999_999_999_900_000.0, 0),
            "999999999999999868928"
        );
    }

    #[test]
    fn exact_dyadic_ties_round_half_up_not_to_even() {
        // The whole point: Rust's `{:.0}` would give "2"/"0"/"2"/"4" (to-even).
        assert_eq!(number_to_fixed_string(2.5, 0), "3");
        assert_eq!(number_to_fixed_string(0.5, 0), "1");
        assert_eq!(number_to_fixed_string(1.5, 0), "2");
        assert_eq!(number_to_fixed_string(3.5, 0), "4");
        // Sub-integer dyadic ties: `{:.1}` would give "0.2"/"0.6" (to-even).
        assert_eq!(number_to_fixed_string(0.25, 1), "0.3");
        assert_eq!(number_to_fixed_string(0.125, 2), "0.13");
        assert_eq!(number_to_fixed_string(0.625, 2), "0.63");
    }

    #[test]
    fn rounding_carry_propagates() {
        assert_eq!(number_to_fixed_string(9.5, 0), "10");
        assert_eq!(number_to_fixed_string(99.5, 0), "100");
        assert_eq!(number_to_fixed_string(0.95, 1), "0.9"); // 0.95 is below the tie
        assert_eq!(number_to_fixed_string(9.95, 1), "9.9"); // 9.95 is below the tie
    }

    #[test]
    fn non_tie_values_round_by_exact_value() {
        // 1.005 is actually 1.00499999...; the spec rounds the exact value.
        assert_eq!(number_to_fixed_string(1.005, 2), "1.00");
        // 0.15 is actually 0.1499999...; rounds down at 1 digit.
        assert_eq!(number_to_fixed_string(0.15, 1), "0.1");
        // 1.231 is 1.231000...09; third fraction digit < 5 -> truncates.
        assert_eq!(number_to_fixed_string(1.231, 2), "1.23");
        // 1.238 is 1.237999...; third fraction digit >= 5 -> rounds up.
        assert_eq!(number_to_fixed_string(1.238, 2), "1.24");
        assert_eq!(number_to_fixed_string(3.7, 0), "4");
    }

    #[test]
    fn negative_values_keep_sign_per_spec() {
        assert_eq!(number_to_fixed_string(-2.5, 0), "-3");
        assert_eq!(number_to_fixed_string(-0.25, 1), "-0.3");
        // Strictly-negative input that rounds to zero magnitude keeps its sign.
        assert_eq!(number_to_fixed_string(-0.0001, 2), "-0.00");
        // Negative zero is not < 0, so no sign.
        assert_eq!(number_to_fixed_string(-0.0, 2), "0.00");
    }

    #[test]
    fn padding_and_zero_digits() {
        assert_eq!(number_to_fixed_string(1.0, 0), "1");
        assert_eq!(number_to_fixed_string(1.0, 3), "1.000");
        assert_eq!(number_to_fixed_string(0.0, 2), "0.00");
        assert_eq!(number_to_fixed_string(2.5, 4), "2.5000");
    }

    #[test]
    fn high_digit_counts_do_not_overflow() {
        // `digits` up to 100: a naive value * 10^digits would overflow f64,
        // but the exact-decimal path renders the true expansion then pads.
        let out = number_to_fixed_string(0.5, 50);
        assert_eq!(out.len(), "0.".len() + 50);
        assert!(out.starts_with("0.5"));
        assert!(out.ends_with('0'));
        // 1/8 is exactly representable: exact at 3 places, zero-padded beyond.
        let eighth = number_to_fixed_string(0.125, 10);
        assert_eq!(eighth, "0.1250000000");
    }

    #[test]
    fn non_finite_inputs() {
        assert_eq!(number_to_fixed_string(f64::NAN, 2), "NaN");
        assert_eq!(number_to_fixed_string(f64::INFINITY, 2), "Infinity");
        assert_eq!(number_to_fixed_string(f64::NEG_INFINITY, 2), "-Infinity");
    }
}

// ---------------------------------------------------------------------------
// btoa / atob / escape / unescape (bd-9vouw.96), over UTF-16 code units
// ---------------------------------------------------------------------------

/// btoa's encoding: the base64 of the code units read as Latin-1 bytes, or
/// `None` when a unit is above U+00FF.
pub(super) fn base64_encode_latin1(units: &[u16]) -> Option<Vec<u16>> {
    use base64::Engine as _;
    let bytes = units
        .iter()
        .map(|&unit| u8::try_from(unit).ok())
        .collect::<Option<Vec<u8>>>()?;
    Some(
        base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .encode_utf16()
            .collect(),
    )
}

/// atob's forgiving-base64 decode (HTML Standard), with the checks and
/// messages of Node's implementation: ASCII whitespace is ignored, `=` may
/// only end the input and at most twice, leftover bits are dropped, and the
/// result's code units are the decoded bytes.
pub(super) fn forgiving_base64_decode(units: &[u16]) -> Result<Vec<u16>, &'static str> {
    pub(super) const INVALID: &str = "Invalid character";
    let mut sextets = Vec::with_capacity(units.len());
    let (mut significant, mut equals) = (0usize, 0usize);
    for &unit in units {
        let sextet = match unit {
            0x09 | 0x0A | 0x0C | 0x0D | 0x20 => continue,
            0x3D => {
                equals += 1;
                significant += 1;
                if equals > 2 {
                    return Err(INVALID);
                }
                continue;
            }
            0x41..=0x5A => unit - 0x41,
            0x61..=0x7A => unit - 0x61 + 26,
            0x30..=0x39 => unit - 0x30 + 52,
            0x2B => 62,
            0x2F => 63,
            _ => return Err(INVALID),
        };
        if equals > 0 {
            return Err(INVALID);
        }
        significant += 1;
        sextets.push(sextet);
    }
    let mut remainder = significant % 4;
    if remainder == 0 {
        remainder = (significant - equals) % 4;
    } else if equals > 0 {
        return Err(INVALID);
    }
    if remainder == 1 {
        return Err("The string to be decoded is not correctly encoded.");
    }
    let mut decoded = Vec::with_capacity(sextets.len() / 4 * 3 + 2);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for sextet in sextets {
        buffer = (buffer << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push(((buffer >> bits) & 0xFF) as u16);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(decoded)
}

pub(super) const UPPER_HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

/// ES2020 B.2.1.1 escape: code units outside `A-Za-z0-9@*_+-./` become
/// `%XX` (below 256) or `%uXXXX`.
pub(super) fn escape_code_units(units: &[u16]) -> Vec<u16> {
    let hex = |nibble: u16| u16::from(UPPER_HEX_DIGITS[usize::from(nibble & 0xF)]);
    let mut escaped = Vec::with_capacity(units.len());
    for &unit in units {
        let kept = matches!(unit, 0x41..=0x5A | 0x61..=0x7A | 0x30..=0x39)
            || matches!(unit, 0x40 | 0x2A | 0x5F | 0x2B | 0x2D | 0x2E | 0x2F);
        if kept {
            escaped.push(unit);
        } else if unit < 256 {
            escaped.extend([u16::from(b'%'), hex(unit >> 4), hex(unit)]);
        } else {
            escaped.extend([
                u16::from(b'%'),
                u16::from(b'u'),
                hex(unit >> 12),
                hex(unit >> 8),
                hex(unit >> 4),
                hex(unit),
            ]);
        }
    }
    escaped
}

/// ES2020 B.2.1.2 unescape: `%uXXXX` and `%XX` become the code unit they
/// spell; any other `%` stays.
pub(super) fn unescape_code_units(units: &[u16]) -> Vec<u16> {
    let hex_value = |range: &[u16]| {
        range.iter().try_fold(0u16, |value, &unit| {
            char::from_u32(u32::from(unit))
                .and_then(|c| c.to_digit(16))
                .map(|digit| (value << 4) | digit as u16)
        })
    };
    let mut unescaped = Vec::with_capacity(units.len());
    let mut k = 0;
    while k < units.len() {
        if units[k] == u16::from(b'%') {
            if units.get(k + 1) == Some(&u16::from(b'u'))
                && let Some(value) = units.get(k + 2..k + 6).and_then(hex_value)
            {
                unescaped.push(value);
                k += 6;
                continue;
            }
            if let Some(value) = units.get(k + 1..k + 3).and_then(hex_value) {
                unescaped.push(value);
                k += 3;
                continue;
            }
        }
        unescaped.push(units[k]);
        k += 1;
    }
    unescaped
}

// ---------------------------------------------------------------------------
// Shared UTF-8 Percent Codec
// ---------------------------------------------------------------------------

/// ES2020 18.2.6.1 uriUnescaped: uriAlpha, DecimalDigit and uriMark
/// (`- _ . ! ~ * ' ( )`), which both encoders leave as written. RFC 3986's
/// unreserved set lacks `! * ' ( )`, which were escaped.
pub(super) fn is_uri_unreserved(c: char) -> bool {
    matches!(
        c,
        'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')'
    )
}

/// Check if a character should be encoded in a URI component context (encodeURIComponent).
/// This is more restrictive than encodeURI - only unreserved characters are allowed.
pub(super) fn should_encode_uri_component(c: char) -> bool {
    !is_uri_unreserved(c)
}

/// Check if a character should be encoded in a URI context (encodeURI).
/// This allows more characters than encodeURIComponent including some reserved ones.
pub(super) fn should_encode_uri(c: char) -> bool {
    // encodeURI allows unreserved chars plus some reserved chars used in URIs
    if is_uri_unreserved(c) {
        return false;
    }
    // Allow common URI reserved characters that should not be encoded
    !matches!(
        c,
        ';' | ',' | '/' | '?' | ':' | '@' | '&' | '=' | '+' | '$' | '#'
    )
}

/// Percent-encode a string for URI contexts using proper UTF-8 encoding.
pub(super) fn percent_encode_utf8<F>(input: &str, should_encode: F) -> String
where
    F: Fn(char) -> bool,
{
    let mut result = String::new();
    for c in input.chars() {
        if should_encode(c) {
            // Encode each byte of the UTF-8 representation
            let utf8_bytes = c.to_string().as_bytes().to_vec();
            for byte in utf8_bytes {
                result.push_str(&format!("%{:02X}", byte));
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Percent-decode a URI-encoded string, handling UTF-8 sequences properly.
/// Decode (ES2020 18.2.6.1.2): each `%XX` escape of an ASCII character is
/// that character unless it is in `reserved` (decodeURI keeps `%2F` and
/// its kin as written), and a multi-byte sequence must be complete,
/// well-formed UTF-8 (no overlong forms or surrogates). `None` is the
/// URIError case.
pub(super) fn percent_decode_utf8(encoded: &str, reserved: &str) -> Option<String> {
    pub(super) fn escaped_byte(bytes: &[u8], at: usize) -> Option<u8> {
        if bytes.get(at) != Some(&b'%') {
            return None;
        }
        let hex = bytes.get(at + 1..at + 3)?;
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()
    }

    let bytes = encoded.as_bytes();
    let mut out = String::with_capacity(encoded.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            let ch = encoded[index..].chars().next()?;
            out.push(ch);
            index += ch.len_utf8();
            continue;
        }
        let lead = escaped_byte(bytes, index)?;
        if lead < 0x80 {
            let ch = char::from(lead);
            if reserved.contains(ch) {
                out.push_str(&encoded[index..index + 3]);
            } else {
                out.push(ch);
            }
            index += 3;
            continue;
        }
        let length = match lead.leading_ones() {
            2 => 2,
            3 => 3,
            4 => 4,
            _ => return None,
        };
        let mut sequence = Vec::with_capacity(length);
        for position in 0..length {
            sequence.push(escaped_byte(bytes, index + position * 3)?);
        }
        out.push_str(std::str::from_utf8(&sequence).ok()?);
        index += length * 3;
    }
    Some(out)
}

/// [`percent_decode_utf8`] over a string's exact UTF-16 content: a lone
/// surrogate, which no escape can contain, is kept as written (ES2020
/// 18.2.6.1.2: a code unit other than `%` is appended unchanged), and the
/// well-formed runs between them decode as before. A sequence of escapes
/// that a surrogate interrupts is malformed either way.
pub(super) fn percent_decode_js_string(encoded: &JsString, reserved: &str) -> Option<JsString> {
    if let Some(text) = encoded.as_str() {
        return percent_decode_utf8(text, reserved).map(JsString::from);
    }
    let units = encoded.code_units_vec();
    let mut out: Vec<u16> = Vec::with_capacity(units.len());
    let decode_run = |run: &[u16], out: &mut Vec<u16>| -> Option<()> {
        let text = String::from_utf16(run).ok()?;
        out.extend(percent_decode_utf8(&text, reserved)?.encode_utf16());
        Some(())
    };
    let mut run_start = 0;
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        let pair_follows = units
            .get(index + 1)
            .is_some_and(|next| (0xDC00..0xE000).contains(next));
        if (0xD800..0xDC00).contains(&unit) && pair_follows {
            index += 2;
            continue;
        }
        if (0xD800..0xE000).contains(&unit) {
            decode_run(&units[run_start..index], &mut out)?;
            out.push(unit);
            run_start = index + 1;
        }
        index += 1;
    }
    decode_run(&units[run_start..], &mut out)?;
    Some(JsString::from_code_units(&out))
}

// ---------------------------------------------------------------------------
// Locale-aware date formatting implementation (bd-1j1wy)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DateFormatType {
    DateTime,
    DateOnly,
    TimeOnly,
}

/// Locale data for date formatting - supports en-US, en-GB, ja-JP
pub(super) struct LocaleData {
    month_names: &'static [&'static str; 12],
    month_names_short: &'static [&'static str; 12],
    day_names: &'static [&'static str; 7],
    day_names_short: &'static [&'static str; 7],
    date_order: DateOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DateOrder {
    Mdy, // MM/DD/YYYY (en-US)
    Dmy, // DD/MM/YYYY (en-GB)
    Ymd, // YYYY-MM-DD (ja-JP)
}

impl InterpreterCore {
    /// Get locale data for supported locales (en-US, en-GB, ja-JP)
    pub(super) fn get_locale_data(locale: &str) -> LocaleData {
        match locale {
            "en-US" => LocaleData {
                month_names: &[
                    "January",
                    "February",
                    "March",
                    "April",
                    "May",
                    "June",
                    "July",
                    "August",
                    "September",
                    "October",
                    "November",
                    "December",
                ],
                month_names_short: &[
                    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
                    "Dec",
                ],
                day_names: &[
                    "Sunday",
                    "Monday",
                    "Tuesday",
                    "Wednesday",
                    "Thursday",
                    "Friday",
                    "Saturday",
                ],
                day_names_short: &["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
                date_order: DateOrder::Mdy,
            },
            "en-GB" => LocaleData {
                month_names: &[
                    "January",
                    "February",
                    "March",
                    "April",
                    "May",
                    "June",
                    "July",
                    "August",
                    "September",
                    "October",
                    "November",
                    "December",
                ],
                month_names_short: &[
                    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
                    "Dec",
                ],
                day_names: &[
                    "Sunday",
                    "Monday",
                    "Tuesday",
                    "Wednesday",
                    "Thursday",
                    "Friday",
                    "Saturday",
                ],
                day_names_short: &["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
                date_order: DateOrder::Dmy,
            },
            "ja-JP" => LocaleData {
                month_names: &[
                    "1月", "2月", "3月", "4月", "5月", "6月", "7月", "8月", "9月", "10月", "11月",
                    "12月",
                ],
                month_names_short: &[
                    "1月", "2月", "3月", "4月", "5月", "6月", "7月", "8月", "9月", "10月", "11月",
                    "12月",
                ],
                day_names: &[
                    "日曜日",
                    "月曜日",
                    "火曜日",
                    "水曜日",
                    "木曜日",
                    "金曜日",
                    "土曜日",
                ],
                day_names_short: &["日", "月", "火", "水", "木", "金", "土"],
                date_order: DateOrder::Ymd,
            },
            _ => {
                // Fallback to en-US for unsupported locales
                Self::get_locale_data("en-US")
            }
        }
    }

    /// Format a date object according to locale-specific rules
    pub(super) fn format_date_with_locale(
        &self,
        date_val: Value,
        locale: &str,
        format_type: DateFormatType,
    ) -> Result<Value, InterpreterError> {
        let date_id = match date_val {
            Value::Object(id) => id,
            _ => return Ok(Value::str("Invalid Date")),
        };

        // Check if it's actually a Date object
        if let Some(time) = self
            .heap
            .get(date_id.0 as usize)
            .and_then(HeapObject::date_time)
        {
            if !time.is_finite() {
                return Ok(Value::str("Invalid Date"));
            }
            let timestamp = time as i64;

            let locale_data = Self::get_locale_data(locale);
            let formatted = self.format_timestamp_with_locale(timestamp, locale_data, format_type);
            return Ok(Value::str(formatted));
        }

        Ok(Value::str("Invalid Date"))
    }

    /// Format a Unix timestamp (milliseconds) according to locale rules
    pub(super) fn format_timestamp_with_locale(
        &self,
        timestamp_ms: i64,
        locale_data: LocaleData,
        format_type: DateFormatType,
    ) -> String {
        // Convert timestamp to date components
        // Simplified date calculation for demonstration (real implementation would use proper date arithmetic)
        let days_since_epoch = timestamp_ms / (1000 * 60 * 60 * 24);
        let seconds_in_day = (timestamp_ms / 1000) % (60 * 60 * 24);
        let hours = (seconds_in_day / 3600) % 24;
        let minutes = (seconds_in_day / 60) % 60;
        let seconds = seconds_in_day % 60;

        // Simplified date calculation (January 1, 1970 was a Thursday)
        // For more accurate implementation, use proper calendar algorithms
        let epoch_year = 1970;
        let mut year = epoch_year;
        let mut remaining_days = days_since_epoch;

        // Approximate year calculation (not accounting for leap years properly for simplicity)
        if remaining_days >= 365 {
            year += remaining_days / 365;
            remaining_days %= 365;
        }

        // Simplified month/day calculation
        let month = if remaining_days >= 31 {
            (remaining_days / 30).min(11)
        } else {
            0
        };
        let day = (remaining_days % 30) + 1;

        let day_of_week = (days_since_epoch + 4) % 7; // January 1, 1970 was Thursday (4)

        match format_type {
            DateFormatType::DateOnly => {
                self.format_date_part(year, month as usize, day, day_of_week as usize, locale_data)
            }
            DateFormatType::TimeOnly => {
                format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
            }
            DateFormatType::DateTime => {
                let date_part = self.format_date_part(
                    year,
                    month as usize,
                    day,
                    day_of_week as usize,
                    locale_data,
                );
                let time_part = format!("{:02}:{:02}:{:02}", hours, minutes, seconds);
                format!("{} {}", date_part, time_part)
            }
        }
    }

    /// Format the date part according to locale ordering and month names
    pub(super) fn format_date_part(
        &self,
        year: i64,
        month: usize,
        day: i64,
        day_of_week: usize,
        locale_data: LocaleData,
    ) -> String {
        let _long_month_name = locale_data.month_names[month.min(11)];
        let _month_name = locale_data.month_names_short[month.min(11)];
        let _long_day_name = locale_data.day_names[day_of_week % 7];
        let day_name = locale_data.day_names_short[day_of_week % 7];

        match locale_data.date_order {
            DateOrder::Mdy => {
                // MM/DD/YYYY format (en-US)
                format!("{} {:02}/{:02}/{}", day_name, month + 1, day, year)
            }
            DateOrder::Dmy => {
                // DD/MM/YYYY format (en-GB)
                format!("{} {:02}/{:02}/{}", day_name, day, month + 1, year)
            }
            DateOrder::Ymd => {
                // YYYY-MM-DD format (ja-JP)
                format!("{} {:04}-{:02}-{:02}", day_name, year, month + 1, day)
            }
        }
    }
}
