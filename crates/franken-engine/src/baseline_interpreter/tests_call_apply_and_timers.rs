#[allow(unused_imports)]
use super::*;

#[cfg(test)]
mod function_prototype_call_apply_tests_current {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;
    use crate::ir_contract::{
        CapabilityTag, Ir3FunctionDesc, IrHeader, IrLevel, IrSchemaVersion, RegRange,
    };

    fn test_module_with_functions(
        instructions: Vec<Ir3Instruction>,
        functions: Vec<Ir3FunctionDesc>,
    ) -> Ir3Module {
        Ir3Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: None,
                source_label: "function-prototype-call-apply-test".to_string(),
            },
            instructions,
            constant_pool: Vec::new(),
            function_table: functions,
            specialization: None,
            required_capabilities: Vec::new(),
            function_lengths: Default::default(),
            function_sources: Default::default(),
            sloppy_functions: Default::default(),
        }
    }

    fn test_config() -> InterpreterConfig {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = std::collections::BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]);
        config
    }

    fn test_interpreter() -> InterpreterCore {
        InterpreterCore::new(test_config(), "function-prototype-call-apply-test")
    }

    #[test]
    fn shared_delivery_checks_source_budget_before_rejecting_a_legacy_forged_digest() {
        use crate::module_resolver::{
            AllowAllPolicy, ModulePolicyHook, ModuleProvenance, ModuleRecord, ModuleResolver,
            ModuleSourceKind, ResolutionEvent, ResolutionResult,
        };

        struct OwnedOnlyResolver(ModuleRecord);

        impl ModuleResolver for OwnedOnlyResolver {
            fn resolve(
                &self,
                request: &ModuleRequest,
                context: &ResolutionContext,
                policy: &dyn ModulePolicyHook,
            ) -> ResolutionResult<ResolutionOutcome> {
                policy.authorize(request, &self.0, context)?;
                Ok(ResolutionOutcome {
                    module: ResolvedModule {
                        request_specifier: request.specifier.clone(),
                        canonical_specifier: self.0.id.clone(),
                        record: self.0.clone(),
                        content_hash: ContentHash::from_bytes([0; 32]),
                        probe_sequence: Vec::new(),
                    },
                    event: ResolutionEvent {
                        trace_id: context.trace_id.clone(),
                        decision_id: context.decision_id.clone(),
                        policy_id: context.policy_id.clone(),
                        component: "module_resolver".into(),
                        event: "module_resolution".into(),
                        outcome: "allow".into(),
                        error_code: String::new(),
                    },
                })
            }

            fn resolve_chain(
                &self,
                request: &ModuleRequest,
                context: &ResolutionContext,
                policy: &dyn ModulePolicyHook,
            ) -> ResolutionResult<Vec<ResolutionOutcome>> {
                Ok(vec![self.resolve(request, context, policy)?])
            }
        }

        let mut core = test_interpreter();
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::ModuleLoad);
        core.config.module_parser_options.budget.max_source_bytes = 63;
        core.module_resolver = Some(InstalledModuleResolver {
            resolver: ExecutionModuleResolver::new(
                "captured:entry",
                Arc::new(OwnedOnlyResolver(ModuleRecord {
                    id: "captured:dependency".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: " ".repeat(64),
                    dependencies: Vec::new(),
                    required_capabilities: std::collections::BTreeSet::from([
                        RuntimeCapability::ModuleLoad,
                    ]),
                    provenance: ModuleProvenance {
                        kind: ModuleSourceKind::Workspace,
                        origin: "captured-test".into(),
                    },
                })),
                Arc::new(AllowAllPolicy),
            ),
            entry_hash: ContentHash::compute(b"entry"),
            context: ResolutionContext::new("trace", "decision", "policy"),
        });
        assert!(matches!(
            core.resolve_installed_module("./dependency.cjs", ImportStyle::Require, &ImportAttributes::default()),
            Err(InterpreterError::ModuleParseFailed { error, .. })
                if error.contains("source-byte budget")
        ));
        core.config.module_parser_options.budget.max_source_bytes = 64;
        assert!(matches!(
            core.resolve_installed_module("./dependency.cjs", ImportStyle::Require, &ImportAttributes::default()),
            Err(InterpreterError::ModuleLoweringFailed { error, .. })
                if error.contains("canonical content hash is inconsistent")
        ));
    }

    #[test]
    fn shared_delivery_keeps_content_identity_when_cached_record_wrappers_change() {
        use crate::module_resolver::{
            ModuleProvenance, ModuleRecord, ModuleSourceKind, SharedModuleRecord,
        };

        let original = SharedModuleRecord::new(ModuleRecord {
            id: "captured:dependency".into(),
            syntax: ModuleSyntax::CommonJs,
            source: "module.exports = 42;".into(),
            dependencies: Vec::new(),
            required_capabilities: std::collections::BTreeSet::from([
                RuntimeCapability::ModuleLoad,
            ]),
            provenance: ModuleProvenance {
                kind: ModuleSourceKind::Workspace,
                origin: "captured-test".into(),
            },
        });
        let caller = test_module_with_functions(vec![Ir3Instruction::Halt], Vec::new());
        let mut core = test_interpreter();
        let namespace = core
            .ensure_module_record(&caller, &original.id)
            .expect("retained module namespace");
        let cached = core.module_state.modules.get_mut(&original.id).unwrap();
        cached.resolved_source_hash = Some(original.canonical_hash());
        cached.status = ModuleRuntimeStatus::Evaluated;
        for changed in [false, true] {
            let mut record = original.record().clone();
            if changed {
                record.source = "module.exports = 99;".into();
            }
            let record = Arc::new(SharedModuleRecord::new(record));
            let delivered = SharedResolvedModule {
                request_specifier: "./dependency.cjs".into(),
                canonical_specifier: record.id.clone(),
                content_hash: record.canonical_hash(),
                record,
                probe_sequence: Vec::new(),
            };
            let result = core.load_module_resolved(
                &caller,
                &original.id,
                ModuleLoadKind::Require,
                None,
                Some(delivered),
            );
            if changed {
                assert!(matches!(
                    result,
                    Err(InterpreterError::ModuleLoweringFailed { error, .. })
                        if error.contains("changed after its first authorized load")
                ));
            } else {
                assert_eq!(result.unwrap(), Value::Object(namespace));
            }
        }
    }

    fn retain_generated_test_artifact(
        core: &mut InterpreterCore,
        owner: &Ir3Module,
        generated: Ir3Module,
        function_index: u32,
        source_tag: &str,
    ) -> (
        BuiltinFunction,
        GeneratedFunctionArtifactHandle,
        Arc<Ir3Module>,
    ) {
        let owner_program = Arc::clone(
            core.module_state.modules[&owner.header.source_label]
                .compiled_module
                .as_ref()
                .expect("generated test owner program"),
        );
        let builtin = core
            .retain_generated_function_artifact(
                owner.content_hash(),
                owner.header.source_label.clone(),
                owner_program,
                InterpreterCore::derive_generated_function_provenance(
                    &owner.header.source_label,
                    "",
                    source_tag,
                ),
                generated,
                function_index,
            )
            .expect("retain generated test artifact");
        let (owner_program_id, artifact_id) =
            InterpreterCore::parse_generated_function_handle(&builtin)
                .expect("parse generated test artifact handle");
        let handle = GeneratedFunctionArtifactHandle {
            owner_program_id,
            artifact_id,
        };
        let artifact_program = Arc::clone(
            &core
                .resolve_generated_function_artifact(owner_program_id, artifact_id)
                .expect("resolve generated test artifact")
                .compiled_module,
        );
        (builtin, handle, artifact_program)
    }

    fn assert_terminal_async_failure(
        core: &InterpreterCore,
        async_id: usize,
        expected_label: Label,
    ) {
        let async_function = &core.async_functions[async_id];
        assert_eq!(async_function.phase, AsyncFunctionPhase::Completed);
        assert!(async_function.isolated_execution.is_none());
        assert!(async_function.saved_registers.is_empty());
        assert_eq!(async_function.saved_registers.capacity(), 0);
        assert!(async_function.saved_register_labels.is_empty());
        assert_eq!(async_function.saved_register_labels.capacity(), 0);
        let record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(
                async_function.result_promise,
            ))
            .expect("async result Promise");
        assert_eq!(
            record.state,
            crate::promise_model::PromiseState::Rejected(crate::object_model::JsValue::Undefined)
        );
        assert_eq!(record.label, expected_label);
    }

    fn seed_object(core: &mut InterpreterCore, properties: &[(&str, Value)]) -> ObjectId {
        core.alloc_object_with_properties(properties)
            .expect("test object allocation should succeed")
    }

    fn seed_array_like(core: &mut InterpreterCore, values: &[Value]) -> ObjectId {
        let array_id = core
            .alloc_object_with_prototype(None)
            .expect("test array allocation should succeed");
        for (index, value) in values.iter().enumerate() {
            core.set_object_property(array_id, index.to_string(), value.clone())
                .expect("test array element write should succeed");
        }
        core.set_object_property(
            array_id,
            "length".to_string(),
            Value::Int(values.len() as i64),
        )
        .expect("test array length write should succeed");
        array_id
    }

    #[test]
    fn function_prototype_call_invokes_function_with_bound_this() {
        let mut module = test_module_with_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:FunctionPrototypeCall".to_string()),
                    args: RegRange { start: 0, count: 3 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 1 },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 1,
                    key: 2,
                    dst: 3,
                },
                Ir3Instruction::Add {
                    dst: 4,
                    lhs: 0,
                    rhs: 3,
                },
                Ir3Instruction::Return { value: 4 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 5,
                name: Some("add_this_offset".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        module.constant_pool.push("offset".into());

        let mut core = test_interpreter();
        let this_id = seed_object(&mut core, &[("offset", Value::Int(7))]);
        core.mutate_registers(|r| {
            r[0] = Value::Function(0);
            r[1] = Value::Object(this_id);
            r[2] = Value::Int(5);
        });

        let result = core
            .execute(&module)
            .expect("Function.prototype.call should execute");
        assert_eq!(result.value, Value::Int(12));
    }

    #[test]
    fn function_prototype_apply_spreads_array_like_arguments() {
        let mut module = test_module_with_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:FunctionPrototypeApply".to_string()),
                    args: RegRange { start: 0, count: 3 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 2 },
                Ir3Instruction::LoadStr {
                    dst: 3,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 2,
                    key: 3,
                    dst: 4,
                },
                Ir3Instruction::Add {
                    dst: 5,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Add {
                    dst: 6,
                    lhs: 5,
                    rhs: 4,
                },
                Ir3Instruction::Return { value: 6 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 2,
                frame_size: 7,
                name: Some("sum_args_and_this_base".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        module.constant_pool.push("base".into());

        let mut core = test_interpreter();
        let this_id = seed_object(&mut core, &[("base", Value::Int(5))]);
        let args_array_id = seed_array_like(&mut core, &[Value::Int(3), Value::Int(4)]);
        core.mutate_registers(|r| {
            r[0] = Value::Function(0);
            r[1] = Value::Object(this_id);
            r[2] = Value::Object(args_array_id);
        });

        let result = core
            .execute(&module)
            .expect("Function.prototype.apply should execute");
        assert_eq!(result.value, Value::Int(12));
    }

    #[test]
    fn imported_closure_call_apply_and_reflect_apply_publish_callee_ifc_label() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 2,
                name: Some("foreign_result".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        owner.header.source_label = "foreign-owner.mjs".to_string();
        let caller = test_module_with_functions(Vec::new(), Vec::new());

        let mut core = test_interpreter();
        core.ensure_module_record(&owner, "foreign-owner.mjs")
            .expect("foreign owner program should be retained");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closure_module_origins
            .insert(0, "foreign-owner.mjs".to_string());
        // Model a Secret caller PC/callback context. The isolated owner-module
        // run must return that label through all three value-only builtin
        // dispatch forms rather than publishing a Public result.
        core.active_inline_callback_context_label = Some(Label::Secret);

        let empty_args = seed_array_like(&mut core, &[]);
        let cases = [
            ("builtin:FunctionPrototypeCall", 2),
            ("builtin:FunctionPrototypeApply", 3),
            ("builtin:ReflectApply", 3),
        ];
        for (capability, count) in cases {
            core.mutate_registers(|registers| {
                registers[0] = Value::Closure(0);
                registers[1] = Value::Undefined;
                registers[2] = Value::Object(empty_args);
            });
            let value = core
                .dispatch_builtin_hostcall(capability, RegRange { start: 0, count }, Some(&caller))
                .unwrap_or_else(|error| panic!("{capability} should dispatch: {error:?}"));
            assert_eq!(value, Value::Int(7), "wrong value from {capability}");
            assert_eq!(
                core.pending_hostcall_result_label.take(),
                Some(Label::Secret),
                "{capability} must publish the isolated callee result label"
            );
        }
    }

    #[test]
    fn foreign_inline_wrapper_preserves_per_argument_return_label_bd_ur3tk_7() {
        let mut owner = test_module_with_functions(
            vec![Ir3Instruction::Return { value: 1 }],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 2,
                frame_size: 2,
                name: Some("return_second_argument".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        owner.header.source_label = "labeled-owner.mjs".to_string();
        let caller = test_module_with_functions(
            vec![
                Ir3Instruction::CallMethod {
                    receiver: 0,
                    callee: 1,
                    args: RegRange { start: 2, count: 2 },
                    dst: 4,
                },
                Ir3Instruction::Return { value: 4 },
            ],
            Vec::new(),
        );

        let mut core = test_interpreter();
        core.ensure_module_record(&owner, "labeled-owner.mjs")
            .expect("foreign owner program should be retained");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closure_module_origins
            .insert(0, "labeled-owner.mjs".to_string());
        let receiver_label = Label::Custom {
            name: "isolated-receiver".repeat(4),
            level: 40,
        };
        let first_label = Label::Custom {
            name: "isolated-first-argument".repeat(4),
            level: 30,
        };
        let second_label = Label::Custom {
            name: "isolated-second-argument".repeat(4),
            level: 20,
        };
        core.write_reg_with_label(0, Value::str("receiver"), receiver_label.clone())
            .expect("receiver register");
        core.write_reg(1, Value::Closure(0))
            .expect("foreign closure register");
        core.write_reg_with_label(2, Value::str("first"), first_label.clone())
            .expect("first argument register");
        core.write_reg_with_label(3, Value::str("second"), second_label.clone())
            .expect("second argument register");
        core.write_reg_with_label(7, Value::str("caller"), Label::Internal)
            .expect("unrelated caller register");
        core.sync_estimated_memory_bytes()
            .expect("directly seeded foreign-closure fixture accounting");

        assert_eq!(
            core.run_loop(&caller)
                .expect("foreign method call should return"),
            Value::str("second")
        );
        assert_eq!(
            core.get_register_label(4).expect("foreign result label"),
            &second_label,
            "the returned second argument must not inherit the higher receiver or first-argument label"
        );
        assert_eq!(
            core.get_register_label(0).expect("restored receiver label"),
            &receiver_label
        );
        assert_eq!(
            core.get_register_label(2)
                .expect("restored first argument label"),
            &first_label
        );
        assert_eq!(
            core.get_register_label(7)
                .expect("restored unrelated caller label"),
            &Label::Internal
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "Custom transport ownership must be fully released after restoring the caller"
        );
    }

    #[test]
    fn foreign_direct_constructor_uses_owner_key_and_preserves_exact_ifc_bd_fw7zd_7_bd_ppfz7() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 1 },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 2,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 3,
                name: Some("foreign_constructor".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        owner.constant_pool.push("mark".into());
        owner.header.source_label = "constructor-owner.mjs".to_string();
        let mut caller = test_module_with_functions(
            vec![
                Ir3Instruction::Construct {
                    callee: 0,
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 3,
                name: Some("colliding_importer_function".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        caller.header.source_label = "constructor-caller.mjs".to_string();

        let mut core = test_interpreter();
        core.ensure_module_record(&owner, "constructor-owner.mjs")
            .expect("foreign constructor owner program should be retained");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closure_module_origins
            .insert(0, "constructor-owner.mjs".to_string());

        let caller_prototype = core
            .ensure_function_prototype(&caller, 0)
            .expect("colliding caller prototype");
        let argument = seed_object(&mut core, &[]);
        core.write_reg(0, Value::Closure(0))
            .expect("foreign constructor register");
        core.write_reg_with_label(1, Value::Object(argument), Label::Secret)
            .expect("foreign constructor argument");
        core.write_reg_with_label(7, Value::str("caller"), Label::Internal)
            .expect("unrelated caller register");
        core.sync_estimated_memory_bytes()
            .expect("directly seeded foreign-constructor fixture accounting");

        assert_eq!(
            core.run_loop(&caller)
                .expect("foreign direct construction should execute"),
            Value::Object(argument),
            "an explicit object return must win over the allocated instance"
        );
        assert_eq!(
            core.get_register_label(2)
                .expect("foreign constructor result label"),
            &Label::Secret
        );
        assert_eq!(
            core.object_mutation_labels.get(&argument),
            Some(&Label::Secret),
            "the exact argument label must reach constructor side effects"
        );
        let owner_key = (InterpreterCore::closure_prototype_owner_id(&owner), 0);
        let owner_prototype = core.function_prototypes[&owner_key];
        assert_ne!(
            owner_prototype, caller_prototype,
            "equal module-local function indices must not alias prototypes"
        );
        assert_eq!(core.function_prototypes.len(), 2);
        assert_eq!(
            core.get_register_label(7)
                .expect("restored unrelated caller label"),
            &Label::Internal
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn foreign_reflect_construct_preserves_result_and_side_effect_ifc_bd_fw7zd_7() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 1 },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 2,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 3,
                name: Some("foreign_reflect_constructor".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        owner.constant_pool.push("mark".into());
        owner.header.source_label = "reflect-constructor-owner.mjs".to_string();
        let mut caller = test_module_with_functions(Vec::new(), Vec::new());
        caller.header.source_label = "reflect-constructor-caller.mjs".to_string();

        let mut core = test_interpreter();
        core.ensure_module_record(&owner, "reflect-constructor-owner.mjs")
            .expect("foreign Reflect.construct owner program should be retained");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closure_module_origins
            .insert(0, "reflect-constructor-owner.mjs".to_string());

        let argument = seed_object(&mut core, &[]);
        let argument_list = seed_array_like(&mut core, &[Value::Object(argument)]);
        core.write_reg(0, Value::Closure(0))
            .expect("foreign Reflect.construct target");
        core.write_reg_with_label(1, Value::Object(argument_list), Label::Secret)
            .expect("foreign Reflect.construct argument list");
        core.sync_estimated_memory_bytes()
            .expect("directly seeded foreign Reflect.construct fixture accounting");

        assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:ReflectConstruct",
                RegRange { start: 0, count: 2 },
                Some(&caller),
            )
            .expect("foreign Reflect.construct should execute"),
            Value::Object(argument)
        );
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret)
        );
        assert_eq!(
            core.object_mutation_labels.get(&argument),
            Some(&Label::Secret)
        );
        assert_eq!(
            core.get_register_label(1)
                .expect("restored Reflect.construct carrier label"),
            &Label::Secret
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn reflect_construct_defaults_new_target_to_target_bd_36e01() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::LoadNewTarget { dst: 1 },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 2,
                    val: 1,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 3,
                name: Some("default_new_target".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        owner.constant_pool.push("observedNewTarget".into());
        owner.header.source_label = "default-new-target-owner.mjs".to_string();
        let mut caller = test_module_with_functions(Vec::new(), Vec::new());
        caller.header.source_label = "default-new-target-caller.mjs".to_string();

        let mut core = test_interpreter();
        core.ensure_module_record(&owner, "default-new-target-owner.mjs")
            .expect("target owner should be retained");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closure_module_origins
            .insert(0, "default-new-target-owner.mjs".to_string());
        let argument_list = seed_array_like(&mut core, &[]);
        core.write_reg(0, Value::Closure(0)).expect("target");
        core.write_reg(1, Value::Object(argument_list))
            .expect("arguments list");
        core.sync_estimated_memory_bytes()
            .expect("seeded default-newTarget fixture accounting");

        let result = core
            .dispatch_builtin_hostcall(
                "builtin:ReflectConstruct",
                RegRange { start: 0, count: 2 },
                Some(&caller),
            )
            .expect("omitted newTarget should default to target");
        let Value::Object(result_id) = result else {
            panic!("Reflect.construct should return the allocated object");
        };
        assert_eq!(
            core.heap[result_id.0 as usize]
                .properties
                .get("observedNewTarget"),
            Some(&Value::Closure(0)),
            "LoadNewTarget must observe the target when the third argument is omitted"
        );
        let target_key = (InterpreterCore::closure_prototype_owner_id(&owner), 0);
        assert_eq!(
            core.heap[result_id.0 as usize].prototype,
            Some(core.function_prototypes[&target_key])
        );
    }

    #[test]
    fn reflect_construct_explicit_cross_module_new_target_preserves_owner_and_ifc_bd_36e01() {
        let mut target_owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadThis { dst: 0 },
                Ir3Instruction::LoadNewTarget { dst: 1 },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 2,
                    val: 1,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 3,
                name: Some("target_constructor".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        target_owner.constant_pool.push("observedNewTarget".into());
        target_owner.header.source_label = "reflect-target-owner.mjs".to_string();
        let mut new_target_owner = test_module_with_functions(
            vec![Ir3Instruction::Return { value: 0 }],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("new_target_constructor".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        new_target_owner.header.source_label = "reflect-new-target-owner.mjs".to_string();
        let mut caller = test_module_with_functions(
            Vec::new(),
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("colliding_caller_function".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        caller.header.source_label = "reflect-new-target-caller.mjs".to_string();

        let mut core = test_interpreter();
        core.ensure_module_record(&target_owner, "reflect-target-owner.mjs")
            .expect("target owner should be retained");
        core.ensure_module_record(&new_target_owner, "reflect-new-target-owner.mjs")
            .expect("newTarget owner should be retained");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closure_module_origins
            .insert(0, "reflect-target-owner.mjs".to_string());
        core.closure_module_origins
            .insert(1, "reflect-new-target-owner.mjs".to_string());

        let caller_prototype = core
            .ensure_function_prototype(&caller, 0)
            .expect("colliding caller prototype");
        let argument_list = seed_array_like(&mut core, &[]);
        core.write_reg(0, Value::Closure(0)).expect("target");
        core.write_reg(1, Value::Object(argument_list))
            .expect("arguments list");
        core.write_reg_with_label(2, Value::Closure(1), Label::TopSecret)
            .expect("explicit newTarget");
        core.write_reg_with_label(7, Value::str("caller"), Label::Internal)
            .expect("unrelated caller state");
        core.sync_estimated_memory_bytes()
            .expect("seeded explicit-newTarget fixture accounting");

        let result = core
            .dispatch_builtin_hostcall(
                "builtin:ReflectConstruct",
                RegRange { start: 0, count: 3 },
                Some(&caller),
            )
            .expect("explicit cross-module newTarget should construct");
        let Value::Object(result_id) = result else {
            panic!("Reflect.construct should return the allocated object");
        };
        assert_eq!(
            core.heap[result_id.0 as usize]
                .properties
                .get("observedNewTarget"),
            Some(&Value::Closure(1)),
            "LoadNewTarget must observe the supplied newTarget"
        );
        let target_key = (
            InterpreterCore::closure_prototype_owner_id(&target_owner),
            0,
        );
        let new_target_key = (
            InterpreterCore::closure_prototype_owner_id(&new_target_owner),
            1,
        );
        let target_prototype = core.function_prototypes[&target_key];
        let new_target_prototype = core.function_prototypes[&new_target_key];
        assert_ne!(target_prototype, new_target_prototype);
        assert_ne!(new_target_prototype, caller_prototype);
        assert_eq!(
            core.heap[result_id.0 as usize].prototype,
            Some(new_target_prototype),
            "allocation must use the supplied newTarget.prototype owner"
        );
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::TopSecret),
            "the newTarget label must reach the Reflect.construct result"
        );
        assert_eq!(
            core.object_mutation_labels.get(&result_id),
            Some(&Label::TopSecret),
            "the newTarget-derived receiver label must reach constructor side effects"
        );
        assert_eq!(core.get_register_label(7), Ok(&Label::Internal));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn reflect_construct_rejects_invalid_new_target_bd_36e01() {
        let module = test_module_with_functions(
            vec![Ir3Instruction::Return { value: 0 }],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("target".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = test_interpreter();
        let argument_list = seed_array_like(&mut core, &[]);
        core.write_reg(0, Value::Function(0)).expect("target");
        core.write_reg(1, Value::Object(argument_list))
            .expect("arguments list");
        core.write_reg(2, Value::Int(7)).expect("invalid newTarget");

        let error = core
            .dispatch_builtin_hostcall(
                "builtin:ReflectConstruct",
                RegRange { start: 0, count: 3 },
                Some(&module),
            )
            .expect_err("non-constructor newTarget must fail closed");
        assert!(
            matches!(error, InterpreterError::TypeError { ref expected, .. }
                if expected.contains("newTarget")),
            "unexpected invalid-newTarget error: {error:?}"
        );
    }

    #[test]
    fn reflect_construct_rejects_mismatched_new_target_owner_bd_36e01() {
        let caller = test_module_with_functions(
            vec![Ir3Instruction::Return { value: 0 }],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("local_target".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut mismatched_owner = test_module_with_functions(
            vec![Ir3Instruction::Return { value: 0 }],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("foreign_new_target".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        mismatched_owner.header.source_label = "actual-new-target-owner.mjs".to_string();

        let mut core = test_interpreter();
        core.ensure_module_record(&mismatched_owner, "claimed-new-target-owner.mjs")
            .expect("placeholder owner record");
        core.retain_module_program("claimed-new-target-owner.mjs", &mismatched_owner)
            .expect("install deliberately mismatched retained program");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closure_module_origins
            .insert(0, "claimed-new-target-owner.mjs".to_string());
        let argument_list = seed_array_like(&mut core, &[]);
        core.write_reg(0, Value::Function(0)).expect("local target");
        core.write_reg(1, Value::Object(argument_list))
            .expect("arguments list");
        core.write_reg(2, Value::Closure(0))
            .expect("foreign newTarget");

        let error = core
            .dispatch_builtin_hostcall(
                "builtin:ReflectConstruct",
                RegRange { start: 0, count: 3 },
                Some(&caller),
            )
            .expect_err("mismatched newTarget owner must fail closed");
        assert!(
            matches!(
                error,
                InterpreterError::ModuleEvaluationFailed { ref specifier, ref reason }
                    if specifier == "claimed-new-target-owner.mjs"
                        && reason.contains("owner mismatch")
                        && reason.contains("actual-new-target-owner.mjs")
            ),
            "unexpected mismatched-newTarget-owner error: {error:?}"
        );
    }

    #[test]
    fn foreign_constructor_rejects_mismatched_retained_owner_bd_fw7zd_7() {
        let mut mismatched_owner = test_module_with_functions(
            vec![Ir3Instruction::Return { value: 0 }],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("mismatched_constructor".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        mismatched_owner.header.source_label = "actual-owner.mjs".to_string();
        let mut caller = test_module_with_functions(Vec::new(), Vec::new());
        caller.header.source_label = "constructor-caller.mjs".to_string();

        let mut core = test_interpreter();
        core.ensure_module_record(&mismatched_owner, "claimed-owner.mjs")
            .expect("placeholder owner record");
        core.retain_module_program("claimed-owner.mjs", &mismatched_owner)
            .expect("install deliberately mismatched retained program");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closure_module_origins
            .insert(0, "claimed-owner.mjs".to_string());

        let error = core
            .invoke_inline_construct(Some(&caller), Value::Closure(0), Vec::new())
            .expect_err("mismatched retained constructor owner must fail closed");
        assert!(
            matches!(
                error,
                InterpreterError::ModuleEvaluationFailed { ref specifier, ref reason }
                    if specifier == "claimed-owner.mjs"
                        && reason.contains("owner mismatch")
                        && reason.contains("actual-owner.mjs")
            ),
            "unexpected mismatched-owner error: {error:?}"
        );
        assert!(
            core.function_prototypes.is_empty(),
            "owner mismatch must be rejected before prototype allocation"
        );
    }

    #[test]
    fn async_call_site_memory_is_independent_of_retained_program_size() {
        // A package may retain a large program while having little execution
        // headroom left. Calling a tiny async function must not require a
        // second copy of that program, including when it suspends and resumes
        // after the initiating callback has returned.
        const CALL_HEADROOM: u64 = 1024 * 1024;
        for foreign in [false, true] {
            let mut owner = test_module_with_functions(
                vec![
                    Ir3Instruction::AwaitValue { promise_reg: 0 },
                    Ir3Instruction::LoadInt { dst: 1, value: 40 },
                    Ir3Instruction::Add {
                        dst: 0,
                        lhs: 0,
                        rhs: 1,
                    },
                    Ir3Instruction::AsyncReturn { value_reg: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 0,
                    arity: 1,
                    frame_size: 2,
                    name: Some("bounded_async_call".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            owner.header.source_label = "large-async-owner.mjs".to_string();
            owner.instructions.resize(32_768, Ir3Instruction::Halt);
            assert!(InterpreterCore::transient_module_wrapper_bytes(&owner) > CALL_HEADROOM);
            let caller = test_module_with_functions(vec![Ir3Instruction::Halt], Vec::new());
            let caller_module = if foreign { &caller } else { &owner };
            let mut core = test_interpreter();
            core.ensure_module_record(&owner, &owner.header.source_label)
                .expect("large owner program should be retained once");
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env: core.scope_chain.snapshot(),
            });
            core.closure_module_origins
                .insert(0, owner.header.source_label.clone());
            let awaited = core.promise_store.create();
            core.write_reg_with_label(7, Value::str("caller-sentinel"), Label::Internal)
                .expect("caller sentinel");
            let baseline = core
                .sync_estimated_memory_bytes()
                .expect("large owner fixture accounting");
            core.config.max_total_memory_bytes = baseline + CALL_HEADROOM;

            let (result, result_label) = core
                .invoke_inline_method_call_with_argument_label(
                    Some(caller_module),
                    Value::AsyncFunction(0),
                    Value::Undefined,
                    vec![Value::Promise(awaited.0)],
                    Some(Label::Confidential),
                )
                .expect("a retained large program must not be copied for an async call");
            let Value::Promise(result_handle) = result else {
                panic!("async callback must publish its Promise");
            };
            assert_eq!(result_label, Label::Confidential);
            let suspended = &core.async_functions[0];
            assert_eq!(suspended.phase, AsyncFunctionPhase::SuspendedAwait);
            assert!(suspended.isolated_execution.is_some());
            let retained_owner = core.module_state.modules[&owner.header.source_label]
                .compiled_module
                .as_ref()
                .expect("retained original program");
            assert!(Arc::ptr_eq(&suspended.owner_module, retained_owner));
            assert_eq!(retained_owner.instructions.len(), owner.instructions.len());
            assert_eq!(core.read_reg(7).unwrap(), Value::str("caller-sentinel"));
            assert_eq!(core.get_register_label(7).unwrap(), &Label::Internal);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );

            core.fulfill_promise(awaited, crate::object_model::JsValue::Int(2), Label::Secret)
                .expect("settle awaited input within the same memory ceiling");
            core.drain_microtasks(Some(caller_module))
                .expect("resume without a retained trampoline copy");
            let result = core
                .promise_store
                .get(crate::promise_model::PromiseHandle(result_handle))
                .expect("published Promise remains live");
            assert_eq!(
                result.state,
                crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(
                    42
                ))
            );
            assert_eq!(result.label, Label::Secret);
            assert_eq!(core.async_functions[0].phase, AsyncFunctionPhase::Completed);
            assert!(core.async_functions[0].isolated_execution.is_none());
            assert_eq!(core.read_reg(7).unwrap(), Value::str("caller-sentinel"));
            assert_eq!(core.get_register_label(7).unwrap(), &Label::Internal);
            assert!(core.estimated_memory_bytes() <= baseline + CALL_HEADROOM);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn deferred_foreign_async_resume_retains_owner_activation_bd_fw7zd_6() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::LoadInt { dst: 1, value: 40 },
                Ir3Instruction::Add {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 2,
                name: Some("foreign_await".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        owner.header.source_label = "foreign-async-owner.mjs".to_string();
        // If post-await execution is accidentally dispatched against the
        // resumer, saved ip=1 produces 999 instead of the owner's 42.
        let caller = test_module_with_functions(
            vec![
                Ir3Instruction::Halt,
                Ir3Instruction::LoadInt { dst: 0, value: 999 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 1,
                arity: 1,
                frame_size: 2,
                name: Some("wrong_importer_async".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );

        let mut core = test_interpreter();
        core.ensure_module_record(&owner, "foreign-async-owner.mjs")
            .expect("foreign async owner program should be retained");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closure_module_origins
            .insert(0, "foreign-async-owner.mjs".to_string());
        let awaited = core.promise_store.create();
        core.write_reg_with_label(7, Value::str("caller-sentinel"), Label::Internal)
            .expect("caller sentinel register");
        core.sync_estimated_memory_bytes()
            .expect("foreign async fixture accounting");
        let previous_reentrant_depth = core.module_reentrant_call_depth;
        let previous_foreign_call_depth = core.active_foreign_module_call_depth;

        // This is the isolated invocation path used by deferred timers,
        // EventEmitter listeners, stream callbacks, and Promise jobs.
        let (result, result_label) = core
            .invoke_inline_method_call_with_argument_label(
                Some(&caller),
                Value::AsyncFunction(0),
                Value::Undefined,
                vec![Value::Promise(awaited.0)],
                Some(Label::Confidential),
            )
            .expect("foreign async callback should publish its result Promise");
        let Value::Promise(async_result_promise) = result else {
            panic!("foreign async callback should return a Promise, got {result:?}");
        };
        assert_eq!(result_label, Label::Confidential);
        assert_eq!(
            core.read_reg(7).expect("restored caller sentinel"),
            Value::str("caller-sentinel")
        );
        assert_eq!(
            core.get_register_label(7)
                .expect("restored caller sentinel label"),
            &Label::Internal
        );
        assert_eq!(core.module_reentrant_call_depth, previous_reentrant_depth);
        assert_eq!(
            core.active_foreign_module_call_depth,
            previous_foreign_call_depth
        );

        let suspended = core
            .async_functions
            .first()
            .expect("foreign async object should exist");
        assert_eq!(suspended.phase, AsyncFunctionPhase::SuspendedAwait);
        assert!(
            suspended.isolated_execution.is_some(),
            "the owner wrapper activation must survive after the caller is restored"
        );
        let retained_owner = core.module_state.modules["foreign-async-owner.mjs"]
            .compiled_module
            .as_ref()
            .expect("retained owner program");
        assert!(Arc::ptr_eq(&suspended.owner_module, retained_owner));

        core.fulfill_promise(awaited, crate::object_model::JsValue::Int(2), Label::Secret)
            .expect("awaited Promise should be fulfillable");
        core.drain_microtasks(Some(&caller))
            .expect("foreign async resumption should use the retained owner");

        let result_record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(async_result_promise))
            .expect("foreign async result Promise");
        assert_eq!(
            result_record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(42))
        );
        assert_eq!(result_record.label, Label::Secret);
        assert_eq!(core.async_functions[0].phase, AsyncFunctionPhase::Completed);
        assert!(core.async_functions[0].isolated_execution.is_none());
        assert_eq!(core.module_reentrant_call_depth, previous_reentrant_depth);
        assert_eq!(
            core.active_foreign_module_call_depth,
            previous_foreign_call_depth
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "retained activation ownership must reconcile exactly after completion"
        );
    }

    #[test]
    fn nested_foreign_async_suspension_keeps_outer_promise_identity_bd_fw7zd_6() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 1,
                    args: RegRange { start: 0, count: 1 },
                    dst: 3,
                },
                Ir3Instruction::AwaitValue { promise_reg: 3 },
                Ir3Instruction::AwaitValue { promise_reg: 2 },
                Ir3Instruction::LoadInt { dst: 4, value: 1 },
                Ir3Instruction::Add {
                    dst: 3,
                    lhs: 3,
                    rhs: 4,
                },
                Ir3Instruction::AsyncReturn { value_reg: 3 },
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::LoadInt { dst: 1, value: 40 },
                Ir3Instruction::Add {
                    dst: 0,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 3,
                    frame_size: 5,
                    name: Some("foreign_outer".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 6,
                    arity: 1,
                    frame_size: 2,
                    name: Some("foreign_inner".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        owner.header.source_label = "foreign-nested-async-owner.mjs".to_string();
        // The outer and inner continuations resume at owner ip=3 and ip=7.
        // Caller dispatch collisions at both positions would resolve 999.
        let caller = test_module_with_functions(
            vec![
                Ir3Instruction::Halt,
                Ir3Instruction::Halt,
                Ir3Instruction::Halt,
                Ir3Instruction::LoadInt { dst: 3, value: 999 },
                Ir3Instruction::AsyncReturn { value_reg: 3 },
                Ir3Instruction::Halt,
                Ir3Instruction::Halt,
                Ir3Instruction::LoadInt { dst: 0, value: 999 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 3,
                    arity: 3,
                    frame_size: 5,
                    name: Some("wrong_outer".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 7,
                    arity: 1,
                    frame_size: 2,
                    name: Some("wrong_inner".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );

        let mut core = test_interpreter();
        core.ensure_module_record(&owner, "foreign-nested-async-owner.mjs")
            .expect("nested async owner program should be retained");
        for function_index in 0..2 {
            let closure_id = core.closures.len() as u32;
            core.closures.push(ClosureValue {
                function_index,
                captured_env: core.scope_chain.snapshot(),
            });
            core.closure_module_origins
                .insert(closure_id, "foreign-nested-async-owner.mjs".to_string());
        }
        let awaited = core.promise_store.create();
        let outer_awaited = core.promise_store.create();
        core.write_reg_with_label(7, Value::str("caller-sentinel"), Label::Internal)
            .expect("caller sentinel register");
        core.sync_estimated_memory_bytes()
            .expect("nested async fixture accounting");

        let (result, result_label) = core
            .invoke_inline_method_call_with_argument_label(
                Some(&caller),
                Value::AsyncFunction(0),
                Value::Undefined,
                vec![
                    Value::Promise(awaited.0),
                    Value::AsyncFunction(1),
                    Value::Promise(outer_awaited.0),
                ],
                Some(Label::Confidential),
            )
            .expect("nested foreign async callback should publish its outer Promise");
        let Value::Promise(outer_promise) = result else {
            panic!("nested foreign async callback should return a Promise, got {result:?}");
        };
        assert_eq!(result_label, Label::Confidential);
        assert_eq!(outer_promise, core.async_functions[0].result_promise);
        // Each async call parks its own activation (bd-9vouw.26): the inner
        // call suspends at its pending await and returns its Promise, and the
        // outer function then suspends awaiting that Promise. The inner
        // activation used to own the whole stack, leaving the outer frame
        // Executing inside it.
        assert_eq!(
            core.async_functions[0].phase,
            AsyncFunctionPhase::SuspendedAwait
        );
        assert!(core.async_functions[0].isolated_execution.is_some());
        assert_eq!(
            core.async_functions[1].phase,
            AsyncFunctionPhase::SuspendedAwait
        );
        assert!(
            core.async_functions[1].isolated_execution.is_some(),
            "the inner suspended async object must own its own activation"
        );
        assert_ne!(
            outer_promise, core.async_functions[1].result_promise,
            "the wrapper must not publish the inner suspended function's Promise"
        );

        core.fulfill_promise(awaited, crate::object_model::JsValue::Int(2), Label::Secret)
            .expect("inner awaited Promise should be fulfillable");
        core.drain_microtasks(Some(&caller))
            .expect("inner activation should resume and rehome onto the outer await");

        assert_eq!(
            core.async_functions[0].phase,
            AsyncFunctionPhase::SuspendedAwait
        );
        assert!(core.async_functions[0].isolated_execution.is_some());
        assert_eq!(core.async_functions[1].phase, AsyncFunctionPhase::Completed);
        assert!(core.async_functions[1].isolated_execution.is_none());
        assert_eq!(
            core.promise_store
                .get(crate::promise_model::PromiseHandle(outer_promise))
                .expect("still-pending outer async result Promise")
                .state,
            crate::promise_model::PromiseState::Pending
        );

        core.fulfill_promise(
            outer_awaited,
            crate::object_model::JsValue::Int(9),
            Label::Secret,
        )
        .expect("outer awaited Promise should be fulfillable");
        core.drain_microtasks(Some(&caller))
            .expect("outer activation should resume against its retained owner");

        let outer_record = core
            .promise_store
            .get(crate::promise_model::PromiseHandle(outer_promise))
            .expect("outer async result Promise");
        assert_eq!(
            outer_record.state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(43))
        );
        assert_eq!(outer_record.label, Label::Secret);
        assert_eq!(
            core.promise_store
                .get(crate::promise_model::PromiseHandle(
                    core.async_functions[1].result_promise
                ))
                .expect("inner async result Promise")
                .state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(42))
        );
        assert!(
            core.async_functions
                .iter()
                .all(|function| function.phase == AsyncFunctionPhase::Completed
                    && function.isolated_execution.is_none())
        );
        assert_eq!(
            core.read_reg(7).expect("restored caller sentinel"),
            Value::str("caller-sentinel")
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn foreign_async_initial_resource_failures_are_terminal_bd_fw7zd_6() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("foreign_resource_failure".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        owner.header.source_label = "foreign-async-resource-owner.mjs".to_string();
        let caller = test_module_with_functions(vec![Ir3Instruction::Halt], Vec::new());

        for cancellation in [false, true] {
            let token = CancellationToken::new();
            let mut config = test_config();
            if cancellation {
                token.cancel();
                config.cancellation_token = Some(token.clone());
                // Wrapper CallMethod executes at count one; cancellation fires
                // at count two before the async body executes.
                config.checkpoint_density = 2;
            } else {
                // The wrapper CallMethod consumes the only admitted
                // instruction, so the async body fails before first entry.
                config.instruction_budget = 1;
            }
            let mut core = InterpreterCore::new(config, "foreign-async-initial-failure");
            core.ensure_module_record(&owner, "foreign-async-resource-owner.mjs")
                .expect("resource-test owner program should be retained");
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env: core.scope_chain.snapshot(),
            });
            core.closure_module_origins
                .insert(0, "foreign-async-resource-owner.mjs".to_string());
            core.write_reg_with_label(7, Value::str("caller-sentinel"), Label::Internal)
                .expect("caller sentinel register");
            core.sync_estimated_memory_bytes()
                .expect("initial resource-failure fixture accounting");
            let previous_reentrant_depth = core.module_reentrant_call_depth;
            let previous_foreign_call_depth = core.active_foreign_module_call_depth;

            let error = core
                .invoke_inline_method_call_with_argument_label(
                    Some(&caller),
                    Value::AsyncFunction(0),
                    Value::Undefined,
                    Vec::new(),
                    Some(Label::Confidential),
                )
                .expect_err("resource failure must escape the isolated callback");
            if cancellation {
                assert_eq!(error, InterpreterError::Cancelled);
                token.reset();
            } else {
                assert_eq!(
                    error,
                    InterpreterError::BudgetExhausted {
                        executed: 1,
                        budget: 1,
                    }
                );
            }

            assert_eq!(core.async_functions.len(), 1);
            assert_terminal_async_failure(&core, 0, Label::Confidential);
            assert_eq!(
                core.read_reg(7).expect("restored caller sentinel"),
                Value::str("caller-sentinel")
            );
            assert_eq!(core.module_reentrant_call_depth, previous_reentrant_depth);
            assert_eq!(
                core.active_foreign_module_call_depth,
                previous_foreign_call_depth
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn foreign_async_resumption_resource_failures_are_terminal_bd_fw7zd_6() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 1,
                name: Some("foreign_resume_resource_failure".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        owner.header.source_label = "foreign-async-resume-resource-owner.mjs".to_string();
        let caller = test_module_with_functions(vec![Ir3Instruction::Halt], Vec::new());

        for cancellation in [false, true] {
            let token = CancellationToken::new();
            let mut config = test_config();
            if cancellation {
                config.cancellation_token = Some(token.clone());
                config.checkpoint_density = u64::MAX;
            }
            let mut core = InterpreterCore::new(config, "foreign-async-resume-failure");
            core.ensure_module_record(&owner, "foreign-async-resume-resource-owner.mjs")
                .expect("resume resource-test owner program should be retained");
            core.closures.push(ClosureValue {
                function_index: 0,
                captured_env: core.scope_chain.snapshot(),
            });
            core.closure_module_origins
                .insert(0, "foreign-async-resume-resource-owner.mjs".to_string());
            let awaited = core.promise_store.create();
            core.write_reg_with_label(7, Value::str("caller-sentinel"), Label::Internal)
                .expect("caller sentinel register");
            core.sync_estimated_memory_bytes()
                .expect("resume resource-failure fixture accounting");
            let previous_reentrant_depth = core.module_reentrant_call_depth;
            let previous_foreign_call_depth = core.active_foreign_module_call_depth;

            let (result, _) = core
                .invoke_inline_method_call_with_argument_label(
                    Some(&caller),
                    Value::AsyncFunction(0),
                    Value::Undefined,
                    vec![Value::Promise(awaited.0)],
                    Some(Label::Confidential),
                )
                .expect("foreign async callback should reach its first await");
            let Value::Promise(result_promise) = result else {
                panic!("foreign async callback should publish a Promise, got {result:?}");
            };
            assert_eq!(
                core.async_functions[0].phase,
                AsyncFunctionPhase::SuspendedAwait
            );
            assert!(core.async_functions[0].isolated_execution.is_some());

            if cancellation {
                token.cancel();
                core.config.checkpoint_density = 1;
            } else {
                core.config.instruction_budget = core.instructions_executed;
            }
            core.fulfill_promise(awaited, crate::object_model::JsValue::Int(2), Label::Secret)
                .expect("awaited Promise should be fulfillable");
            let error = core
                .drain_microtasks(Some(&caller))
                .expect_err("resumption resource failure must escape the microtask drain");
            if cancellation {
                assert_eq!(error, InterpreterError::Cancelled);
                token.reset();
            } else {
                assert!(matches!(
                    error,
                    InterpreterError::BudgetExhausted {
                        executed,
                        budget
                    } if executed == budget
                ));
            }

            assert_eq!(result_promise, core.async_functions[0].result_promise);
            assert_terminal_async_failure(&core, 0, Label::Secret);
            assert!(core.async_resumption_contexts.is_empty());
            assert_eq!(
                core.read_reg(7).expect("restored caller sentinel"),
                Value::str("caller-sentinel")
            );
            assert_eq!(core.module_reentrant_call_depth, previous_reentrant_depth);
            assert_eq!(
                core.active_foreign_module_call_depth,
                previous_foreign_call_depth
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn async_completion_memory_failure_repairs_the_popped_frame_bd_fw7zd_6() {
        let owner = Arc::new(test_module_with_functions(Vec::new(), Vec::new()));
        let mut core = test_interpreter();
        let result_promise = core
            .create_promise()
            .expect("async result Promise should fit");
        let async_id = core
            .push_async_function_object(AsyncFunctionObject {
                owner_module: owner,
                isolated_execution: None,
                function_index: 0,
                closure_index: None,
                saved_ip: 0,
                saved_registers: Vec::new(),
                saved_register_labels: Vec::new(),
                saved_register_base: 0,
                phase: AsyncFunctionPhase::Executing,
                result_promise: result_promise.0,
            })
            .expect("async object should fit");
        let pushed_frame = CallFrame {
            return_ip: 0,
            return_reg: 0,
            register_base: 0,
            register_width: core.config.max_registers as usize,
            function_index: Some(0),
            this_value: Value::Undefined,
            this_label: Label::Public,
            new_target_value: Value::Undefined,
            new_target_label: Label::Public,
            super_value: Value::Undefined,
            super_label: Label::Public,
            super_home_object: None,
            construct_this: None,
            derived_constructor: false,
            this_initialized: true,
            initialize_derived_this_on_return: false,
            class_instance_fields: None,
            saved_pending_exception: None,
            saved_pending_exception_label: Label::Public,
            saved_pending_return: None,
            saved_suspended_abrupt_depth: 0,
            saved_finally_mode_depth: 0,
            saved_scope_depth: core.scope_chain.depth(),
            saved_scope_chain: None,
            scope_inert_virtual_scope_bytes: 0,
            async_function_id: Some(async_id),
            native_boundary: false,
        };
        core.call_stack
            .push(pushed_frame, &mut core.closures.cold_cells);
        core.register_base = core.config.max_registers as usize;
        core.sync_estimated_memory_bytes()
            .expect("completion memory fixture accounting");
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();

        let error = core
            .complete_current_async_frame(
                None,
                Ok(Value::str("x".repeat(16 * 1024))),
                Label::Secret,
            )
            .expect_err("Promise fulfillment must exceed the calibrated ceiling");
        assert!(matches!(
            error,
            InterpreterError::MemoryBudgetExceeded { .. }
        ));
        assert_eq!(core.async_functions.len(), 1);
        assert_terminal_async_failure(&core, 0, Label::Secret);
        assert!(core.call_stack.is_empty());
        assert_eq!(core.register_base, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn fatal_async_repair_closes_await_and_combinator_fanout_bd_fw7zd_6() {
        let owner = Arc::new(test_module_with_functions(Vec::new(), Vec::new()));
        let mut core = test_interpreter();
        let root_promise = core.create_promise().expect("root async Promise");
        let waiting_promise = core.create_promise().expect("waiting async Promise");

        let root_async_id = core
            .push_async_function_object(AsyncFunctionObject {
                owner_module: Arc::clone(&owner),
                isolated_execution: None,
                function_index: 0,
                closure_index: None,
                saved_ip: 0,
                saved_registers: Vec::new(),
                saved_register_labels: Vec::new(),
                saved_register_base: 0,
                phase: AsyncFunctionPhase::Executing,
                result_promise: root_promise.0,
            })
            .expect("root async object");
        let waiting_async_id = core
            .push_async_function_object(AsyncFunctionObject {
                owner_module: owner,
                isolated_execution: None,
                function_index: 0,
                closure_index: None,
                saved_ip: 1,
                saved_registers: vec![Value::Int(7)],
                saved_register_labels: vec![Label::Secret],
                saved_register_base: 0,
                phase: AsyncFunctionPhase::SuspendedAwait,
                result_promise: waiting_promise.0,
            })
            .expect("waiting async object");
        assert_eq!(root_async_id, 0);
        assert_eq!(waiting_async_id, 1);

        let await_result = core
            .register_promise_then_for_await(root_promise, Label::Secret)
            .expect("async await dependency");
        core.async_resumption_contexts.insert(
            await_result.0,
            AsyncResumptionContext {
                async_function_id: waiting_async_id,
                result_register: 0,
            },
        );

        let root_combinator_result = core.create_promise().expect("root combinator result");
        let root_combinator_id = core
            .register_combinator(PromiseCombinatorState::Race(
                crate::promise_model::PromiseRaceTracker {
                    result_promise: root_combinator_result,
                    settled: false,
                },
            ))
            .expect("root combinator");
        core.add_combinator_watcher(
            root_promise,
            PromiseCombinatorWatcher {
                combinator_id: root_combinator_id,
                index: 0,
            },
        )
        .expect("root combinator watcher");

        let waiting_combinator_result = core.create_promise().expect("waiting combinator result");
        let waiting_combinator_id = core
            .register_combinator(PromiseCombinatorState::Race(
                crate::promise_model::PromiseRaceTracker {
                    result_promise: waiting_combinator_result,
                    settled: false,
                },
            ))
            .expect("waiting combinator");
        core.add_combinator_watcher(
            waiting_promise,
            PromiseCombinatorWatcher {
                combinator_id: waiting_combinator_id,
                index: 0,
            },
        )
        .expect("waiting combinator watcher");

        let top_level_result = core
            .register_promise_then_for_await(root_combinator_result, Label::TopSecret)
            .expect("top-level await dependency");
        core.top_level_await_resumption_contexts.insert(
            top_level_result.0,
            TopLevelAwaitResumptionContext {
                module_specifier: "terminal-fixture.mjs".to_string(),
                continuation: ModuleAwaitContinuation::AwaitValue { result_register: 0 },
            },
        );
        let combinator_descendant = core
            .register_promise_then(waiting_combinator_result, None, None, Label::Confidential)
            .expect("combinator reaction descendant");
        let unrelated = core.create_promise().expect("unrelated Promise");

        core.sync_estimated_memory_bytes()
            .expect("fanout fixture accounting");
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        let previous_witness_count = core.promise_store.witness_log().len();
        let previous_microtask_count = core.event_loop.microtasks.pending_count();
        let terminal_label = Label::Custom {
            name: "attacker-controlled-terminal-label".repeat(4096),
            level: u32::MAX,
        };

        core.terminally_reject_abandoned_async_functions(&[root_async_id], terminal_label);

        let compact_terminal_label = Label::Custom {
            name: String::new(),
            level: u32::MAX,
        };
        for handle in [
            root_promise,
            await_result,
            waiting_promise,
            root_combinator_result,
            waiting_combinator_result,
            top_level_result,
            combinator_descendant,
        ] {
            let record = core.promise_store.get(handle).expect("affected Promise");
            assert_eq!(
                record.state,
                crate::promise_model::PromiseState::Rejected(
                    crate::object_model::JsValue::Undefined
                ),
                "{handle} must not remain resumable"
            );
            assert_eq!(record.label, compact_terminal_label);
        }
        assert_eq!(
            core.promise_store
                .get(unrelated)
                .expect("unrelated Promise")
                .state,
            crate::promise_model::PromiseState::Pending
        );
        assert!(
            core.async_functions
                .iter()
                .all(|function| function.phase == AsyncFunctionPhase::Completed)
        );
        assert!(core.async_functions.iter().all(|function| {
            function.saved_registers.capacity() == 0
                && function.saved_register_labels.capacity() == 0
        }));
        assert!(core.async_resumption_contexts.is_empty());
        assert!(core.top_level_await_resumption_contexts.is_empty());
        assert!(core.promise_combinators.is_empty());
        assert!(core.promise_combinator_watchers.is_empty());
        assert_eq!(
            core.event_loop.microtasks.pending_count(),
            previous_microtask_count
        );
        assert_eq!(
            core.promise_store.witness_log().len(),
            previous_witness_count
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        assert!(core.estimated_memory_bytes() <= core.config.max_total_memory_bytes);
    }

    #[test]
    fn top_level_stops_after_same_module_async_resume_failure_bd_fw7zd_6() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 1,
                frame_size: 1,
                name: Some("same_module_async".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = test_interpreter();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        let awaited = core
            .create_promise()
            .expect("same-module awaited Promise should fit");
        core.write_reg(0, Value::AsyncFunction(0))
            .expect("same-module async callee");
        core.write_reg(1, Value::Promise(awaited.0))
            .expect("same-module awaited argument");
        core.sync_estimated_memory_bytes()
            .expect("same-module async fixture accounting");

        // The call parks at its first await in its own isolated activation and
        // the caller runs on to Halt (bd-9vouw.26; the pending await used to
        // stop the whole top-level run with Undefined).
        assert!(matches!(
            core.run_loop(&module),
            Err(InterpreterError::Halted)
        ));
        let Value::Promise(result_promise) = core.registers[2].clone() else {
            panic!(
                "same-module async call should publish a Promise, got {:?}",
                core.registers[2]
            );
        };
        assert_eq!(
            core.async_functions[0].phase,
            AsyncFunctionPhase::SuspendedAwait
        );
        assert!(core.async_functions[0].isolated_execution.is_some());

        core.fulfill_promise(awaited, crate::object_model::JsValue::Int(2), Label::Secret)
            .expect("same-module awaited Promise should be fulfillable");
        let trailing_promise = core
            .create_promise()
            .expect("trailing observable Promise should fit");
        let previous_promise_bytes = core.promise_runtime_memory_bytes();
        core.event_loop
            .microtasks
            .enqueue(crate::promise_model::Microtask::PromiseReaction {
                handler: None,
                argument: crate::object_model::JsValue::Int(99),
                result_promise: trailing_promise,
                label: Label::Public,
            });
        core.apply_promise_runtime_memory_delta(previous_promise_bytes)
            .expect("trailing microtask should fit");

        // Let the top-level driver execute one Halt and charge the mandatory
        // empty Writable-scheduler scan, then fail the resumed async body
        // before its next instruction. The trailing microtask must remain
        // untouched after the fatal checkpoint error.
        core.ip = 1;
        core.config.instruction_budget = core.instructions_executed + 2;
        let error = core
            .run_top_level_execution(&module, None)
            .expect_err("same-module resumption budget failure must escape");
        assert!(matches!(
            error,
            InterpreterError::BudgetExhausted {
                executed,
                budget
            } if executed == budget
        ));
        assert_eq!(result_promise, core.async_functions[0].result_promise);
        assert_terminal_async_failure(&core, 0, Label::Secret);
        assert!(core.async_resumption_contexts.is_empty());
        assert!(core.call_stack.is_empty());
        assert_eq!(core.register_base, 0);
        assert_eq!(
            core.promise_store
                .get(trailing_promise)
                .expect("trailing observable Promise")
                .state,
            crate::promise_model::PromiseState::Pending,
            "fatal checkpoint failure must not execute trailing event-loop work"
        );
        assert!(core.event_loop.has_pending_work());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn foreign_async_generators_retain_owner_before_body_fail_closed_bd_fw7zd_6() {
        let mut owner = test_module_with_functions(
            Vec::new(),
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("foreign_async_generator".to_string()),
                is_generator: true,
                rest_param_index: None,
            }],
        );
        owner.header.source_label = "foreign-async-generator-owner.mjs".to_string();
        let caller = test_module_with_functions(
            vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 4, count: 0 },
                    dst: 1,
                },
                Ir3Instruction::CallMethod {
                    receiver: 2,
                    callee: 0,
                    args: RegRange { start: 4, count: 0 },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("wrong_importer_async_generator".to_string()),
                is_generator: true,
                rest_param_index: None,
            }],
        );

        let mut core = test_interpreter();
        core.ensure_module_record(&owner, "foreign-async-generator-owner.mjs")
            .expect("foreign async-generator owner program should be retained");
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: core.scope_chain.snapshot(),
        });
        core.closure_module_origins
            .insert(0, "foreign-async-generator-owner.mjs".to_string());
        core.write_reg(0, Value::AsyncGeneratorFunction(0))
            .expect("async-generator callee");
        core.sync_estimated_memory_bytes()
            .expect("foreign async-generator fixture accounting");

        assert_eq!(
            core.run_loop(&caller)
                .expect("direct and method async-generator construction"),
            Value::AsyncGeneratorObject(1)
        );
        let retained_owner = core.module_state.modules["foreign-async-generator-owner.mjs"]
            .compiled_module
            .as_ref()
            .expect("retained async-generator owner");
        assert_eq!(core.async_generators.len(), 2);
        for generator in core.async_generators.iter() {
            // The owner program now lives on the canonical generator
            // activation each async generator points at.
            let activation = &core.generators[generator.generator_id as usize];
            assert!(Arc::ptr_eq(&activation.owner_module, retained_owner));
            assert_eq!(generator.phase, AsyncGeneratorPhase::SuspendedStart);
        }

        // The original fail-closed check on body execution is gone: async
        // generator bodies execute since 5afd288a6, covered by
        // async_generator_next_executes_suspended_body.
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn function_call_wrapper_preserves_receiver_and_argument_side_effect_labels_bd_ur3tk_7() {
        let mut module = test_module_with_functions(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 3, value: 1 },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 2,
                    val: 3,
                },
                Ir3Instruction::LoadInt { dst: 3, value: 2 },
                Ir3Instruction::SetProperty {
                    obj: 1,
                    key: 2,
                    val: 3,
                },
                Ir3Instruction::LoadThis { dst: 4 },
                Ir3Instruction::LoadInt { dst: 3, value: 3 },
                Ir3Instruction::SetProperty {
                    obj: 4,
                    key: 2,
                    val: 3,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 2,
                frame_size: 5,
                name: Some("mutate_each_input".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        module.constant_pool.push("mark".into());

        let mut core = test_interpreter();
        let receiver = seed_object(&mut core, &[]);
        let secret_argument = seed_object(&mut core, &[]);
        let confidential_argument = seed_object(&mut core, &[]);
        core.write_reg(0, Value::Function(0))
            .expect("callee register");
        core.write_reg_with_label(1, Value::Object(receiver), Label::Internal)
            .expect("receiver register");
        core.write_reg_with_label(2, Value::Object(secret_argument), Label::Secret)
            .expect("secret argument register");
        core.write_reg_with_label(3, Value::Object(confidential_argument), Label::Confidential)
            .expect("confidential argument register");
        core.write_reg_with_label(7, Value::str("caller"), Label::TopSecret)
            .expect("unrelated caller register");

        assert_eq!(
            core.dispatch_builtin_hostcall(
                "builtin:FunctionPrototypeCall",
                RegRange { start: 0, count: 4 },
                Some(&module),
            )
            .expect("Function.prototype.call wrapper"),
            Value::Object(secret_argument)
        );
        assert_eq!(
            core.object_mutation_labels.get(&receiver),
            Some(&Label::Internal)
        );
        assert_eq!(
            core.object_mutation_labels.get(&secret_argument),
            Some(&Label::Secret)
        );
        assert_eq!(
            core.object_mutation_labels.get(&confidential_argument),
            Some(&Label::Confidential)
        );
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret)
        );
        assert_eq!(
            core.get_register_label(1).expect("restored receiver label"),
            &Label::Internal
        );
        assert_eq!(
            core.get_register_label(3)
                .expect("restored confidential argument label"),
            &Label::Confidential
        );
        assert_eq!(
            core.get_register_label(7)
                .expect("restored unrelated caller label"),
            &Label::TopSecret
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn function_call_wrapper_preserves_exact_throw_label_bd_ur3tk_7() {
        let module = test_module_with_functions(
            vec![Ir3Instruction::Throw { value: 1 }],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 2,
                frame_size: 2,
                name: Some("throw_second_argument".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = test_interpreter();
        core.write_reg(0, Value::Function(0))
            .expect("callee register");
        core.write_reg_with_label(1, Value::str("receiver"), Label::Internal)
            .expect("receiver register");
        core.write_reg_with_label(2, Value::str("higher-unused"), Label::Secret)
            .expect("first argument register");
        core.write_reg_with_label(3, Value::str("thrown"), Label::Confidential)
            .expect("second argument register");
        core.write_reg_with_label(7, Value::str("caller"), Label::TopSecret)
            .expect("unrelated caller register");

        let error = core
            .dispatch_builtin_hostcall(
                "builtin:FunctionPrototypeCall",
                RegRange { start: 0, count: 4 },
                Some(&module),
            )
            .expect_err("explicit throw must escape the isolated wrapper");
        assert!(matches!(error, InterpreterError::UncaughtException { .. }));
        assert_eq!(core.pending_exception, Some(Value::str("thrown")));
        assert_eq!(
            core.pending_exception_label,
            Label::Confidential,
            "the thrown second argument must not inherit the higher unused first-argument label"
        );
        assert_eq!(
            core.get_register_label(2)
                .expect("restored first argument label"),
            &Label::Secret
        );
        assert_eq!(
            core.get_register_label(7)
                .expect("restored unrelated caller label"),
            &Label::TopSecret
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_wrapper_preserves_receiver_argument_return_and_throw_labels_bd_ur3tk_7() {
        let mut generated = test_module_with_functions(
            vec![
                Ir3Instruction::LoadThis { dst: 1 },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::SetProperty {
                    obj: 1,
                    key: 2,
                    val: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 3,
                name: Some("generated_mutator".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        generated.constant_pool.push("mark".into());
        let throwing_generated = test_module_with_functions(
            vec![Ir3Instruction::Throw { value: 0 }],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 1,
                name: Some("generated_thrower".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut caller = test_module_with_functions(Vec::new(), Vec::new());
        caller.header.source_label = "generated-label-owner.mjs".to_string();

        let mut core = test_interpreter();
        core.ensure_module_record(&caller, &caller.header.source_label)
            .expect("retain generated-function owner program");
        let owner_program_id = caller.content_hash();
        let owner_program = Arc::clone(
            core.module_state.modules[&caller.header.source_label]
                .compiled_module
                .as_ref()
                .expect("generated-function owner program"),
        );
        let mutator = core
            .retain_generated_function_artifact(
                owner_program_id,
                caller.header.source_label.clone(),
                Arc::clone(&owner_program),
                InterpreterCore::derive_generated_function_provenance(
                    "generated-label-owner.mjs",
                    "value",
                    "this.mark = value; return value;",
                ),
                generated,
                0,
            )
            .expect("retain generated mutator");
        let thrower = core
            .retain_generated_function_artifact(
                owner_program_id,
                caller.header.source_label.clone(),
                owner_program,
                InterpreterCore::derive_generated_function_provenance(
                    "generated-label-owner.mjs",
                    "value",
                    "throw value;",
                ),
                throwing_generated,
                0,
            )
            .expect("retain generated thrower");

        let receiver = seed_object(&mut core, &[]);
        core.write_reg_with_label(0, Value::Object(receiver), Label::Internal)
            .expect("generated receiver register");
        core.write_reg_with_label(1, Value::str("classified"), Label::Secret)
            .expect("generated argument register");
        core.write_reg_with_label(7, Value::str("caller"), Label::Confidential)
            .expect("unrelated caller register");
        let result = core
            .dispatch_builtin_function(
                &caller,
                &mutator,
                RegRange { start: 1, count: 1 },
                Some(Value::Object(receiver)),
                Some(0),
            )
            .expect("generated method-form invocation");
        assert_eq!(result, Value::str("classified"));
        assert_eq!(
            core.object_mutation_labels.get(&receiver),
            Some(&Label::Secret)
        );
        assert_eq!(
            core.take_pending_hostcall_result_label(),
            Some(Label::Secret)
        );
        assert_eq!(
            core.get_register_label(0)
                .expect("restored generated receiver label"),
            &Label::Internal
        );
        assert_eq!(
            core.get_register_label(7)
                .expect("restored unrelated caller label"),
            &Label::Confidential
        );

        core.write_reg_with_label(0, Value::Object(receiver), Label::Secret)
            .expect("higher generated receiver register");
        core.write_reg_with_label(1, Value::str("thrown"), Label::Confidential)
            .expect("generated thrown argument register");
        let error = core
            .dispatch_builtin_function(
                &caller,
                &thrower,
                RegRange { start: 1, count: 1 },
                Some(Value::Object(receiver)),
                Some(0),
            )
            .expect_err("generated explicit throw must escape");
        assert!(matches!(error, InterpreterError::UncaughtException { .. }));
        assert_eq!(core.pending_exception, Some(Value::str("thrown")));
        assert_eq!(
            core.pending_exception_label,
            Label::Confidential,
            "generated throw must retain the argument's exact label rather than the higher receiver label"
        );
        assert_eq!(
            core.get_register_label(0)
                .expect("restored higher generated receiver label"),
            &Label::Secret
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_code_observability_is_budget_atomic_and_recomputed_bd_fw7zd_8_2() {
        fn entry(
            kind: GeneratedCodeEventKind,
            instructions_consumed: u64,
            outcome: &str,
        ) -> GeneratedCodeAuditEntry {
            GeneratedCodeAuditEntry {
                source_id: "genfn:0123456789abcdef".to_string(),
                source_hash: "a".repeat(64),
                parameter_hash: "b".repeat(64),
                construction_site: "generated-observability-owner.mjs".to_string(),
                kind,
                instructions_consumed,
                caller_call_depth: usize::from(kind != GeneratedCodeEventKind::Constructed),
                granted_capabilities: match kind {
                    GeneratedCodeEventKind::Constructed => Vec::new(),
                    _ => vec!["builtin".to_string(), "console".to_string()],
                },
                outcome: outcome.to_string(),
            }
        }

        let fixture = || {
            let mut core = test_interpreter();
            core.sync_estimated_memory_bytes()
                .expect("generated observability fixture baseline");
            core
        };
        let constructed = entry(GeneratedCodeEventKind::Constructed, 0, "constructed");

        let mut probe = fixture();
        let baseline = probe.estimated_memory_bytes();
        let pair_bytes = probe.estimate_generated_code_observability_pair_bytes(&constructed);
        assert!(pair_bytes > 0);
        probe
            .record_generated_code_event(constructed.clone())
            .expect("unbounded generated observability pair");
        assert_eq!(
            probe.estimated_memory_bytes(),
            baseline.saturating_add(pair_bytes)
        );
        assert_eq!(probe.generated_code_observability_bytes, pair_bytes);
        assert_eq!(
            probe.generated_code_observability_bytes,
            probe.generated_code_observability_memory_bytes()
        );
        assert_eq!(
            probe.estimated_memory_bytes(),
            probe.recompute_estimated_memory_bytes()
        );

        let mut one_short = fixture();
        let one_short_baseline = one_short.estimated_memory_bytes();
        one_short.config.max_total_memory_bytes = one_short_baseline
            .saturating_add(pair_bytes)
            .saturating_sub(1);
        assert!(matches!(
            one_short.record_generated_code_event(constructed.clone()),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(one_short.generated_code_audit.is_empty());
        assert!(one_short.events.is_empty());
        assert_eq!(one_short.generated_code_observability_bytes, 0);
        assert_eq!(
            one_short.estimated_memory_bytes(),
            one_short_baseline,
            "one-byte-short refusal must not publish either half of the pair"
        );
        assert_eq!(
            one_short.estimated_memory_bytes(),
            one_short.recompute_estimated_memory_bytes()
        );

        let mut exact = fixture();
        let exact_baseline = exact.estimated_memory_bytes();
        exact.config.max_total_memory_bytes = exact_baseline.saturating_add(pair_bytes);
        exact
            .record_generated_code_event(constructed.clone())
            .expect("generated observability pair at exact ceiling");
        assert_eq!(exact.generated_code_audit.len(), 1);
        assert_eq!(exact.events.len(), 1);
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes()
        );

        let mut capped = fixture();
        capped.config.max_total_memory_bytes = u64::MAX;
        for _ in 0..MAX_GENERATED_CODE_AUDIT_ENTRIES {
            capped
                .record_generated_code_event(constructed.clone())
                .expect("generated observability pair below retention cap");
        }
        let capped_bytes = capped.generated_code_observability_bytes;
        capped
            .record_generated_code_event(constructed)
            .expect("generated observability pair at retention cap is dropped");
        assert_eq!(
            capped.generated_code_audit.len(),
            MAX_GENERATED_CODE_AUDIT_ENTRIES
        );
        assert_eq!(capped.events.len(), MAX_GENERATED_CODE_AUDIT_ENTRIES);
        assert_eq!(capped.generated_code_observability_bytes, capped_bytes);
        assert_eq!(
            capped.estimated_memory_bytes(),
            capped.recompute_estimated_memory_bytes(),
            "the audit and standard-event halves must stop at the same cap"
        );
    }

    #[test]
    fn bd_zaeeh_general_events_are_budget_bounded_drained_and_recomputed() {
        let fixture = || {
            let mut core = test_interpreter();
            core.sync_estimated_memory_bytes()
                .expect("general event fixture baseline");
            core
        };

        // Baseline: one general event is charged and visible to recompute.
        let mut probe = fixture();
        let baseline = probe.estimated_memory_bytes();
        probe.push_event("execution_started", "ok", None);
        let event_bytes = probe.estimated_memory_bytes().saturating_sub(baseline);
        assert!(event_bytes > 0, "a general event must be charged");
        assert_eq!(probe.events.len(), 1);
        assert_eq!(probe.general_event_bytes, event_bytes);
        assert_eq!(
            probe.general_event_bytes,
            probe.general_interpreter_events_memory_bytes()
        );
        assert_eq!(
            probe.estimated_memory_bytes(),
            probe.recompute_estimated_memory_bytes(),
            "a charged general event must keep the estimate consistent"
        );
        assert_eq!(probe.dropped_event_count, 0);

        // One-byte-short: a second event that would cross the ceiling is
        // dropped deterministically with no accounting drift.
        let mut one_short = fixture();
        one_short.push_event("execution_started", "ok", None);
        let after_first = one_short.estimated_memory_bytes();
        one_short.config.max_total_memory_bytes =
            after_first.saturating_add(event_bytes).saturating_sub(1);
        one_short.push_event("execution_started", "ok", None);
        assert_eq!(
            one_short.events.len(),
            1,
            "over-ceiling event must be dropped"
        );
        assert_eq!(one_short.dropped_event_count, 1);
        assert_eq!(
            one_short.estimated_memory_bytes(),
            after_first,
            "a dropped event must not be charged"
        );
        assert_eq!(
            one_short.estimated_memory_bytes(),
            one_short.recompute_estimated_memory_bytes()
        );

        // Exact ceiling: a second event that fits precisely is retained.
        let mut exact = fixture();
        exact.push_event("execution_started", "ok", None);
        let after_first = exact.estimated_memory_bytes();
        exact.config.max_total_memory_bytes = after_first.saturating_add(event_bytes);
        exact.push_event("execution_started", "ok", None);
        assert_eq!(
            exact.events.len(),
            2,
            "event at the exact ceiling is retained"
        );
        assert_eq!(exact.dropped_event_count, 0);
        assert_eq!(exact.general_event_bytes, event_bytes.saturating_mul(2));
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes()
        );

        // Drain on take releases the general-event charge (success/reuse
        // semantics): the estimate returns to the pre-event baseline.
        let mut drained = fixture();
        let drain_baseline = drained.estimated_memory_bytes();
        drained.push_event("execution_completed", "ok", None);
        assert!(drained.estimated_memory_bytes() > drain_baseline);
        let taken = drained.take_execution_result(
            LabeledReturn {
                value: Value::Undefined,
                label: Label::Public,
            },
            None,
        );
        assert_eq!(taken.events.len(), 1);
        assert_eq!(drained.general_event_bytes, 0);
        assert!(drained.events.is_empty());
        assert_eq!(
            drained.estimated_memory_bytes(),
            drain_baseline,
            "draining events must restore the pre-event estimate"
        );
        assert_eq!(
            drained.estimated_memory_bytes(),
            drained.recompute_estimated_memory_bytes()
        );

        // Repeated failing reuse: without a drain, general events accumulate
        // charged but stay bounded — they can never exceed the containment
        // budget, and the surplus pushes drop deterministically.
        let mut repeated = fixture();
        let cap_baseline = repeated.estimated_memory_bytes();
        repeated.config.max_total_memory_bytes =
            cap_baseline.saturating_add(event_bytes.saturating_mul(3));
        for _ in 0..20 {
            repeated.push_event("execution_started", "ok", None);
        }
        assert_eq!(
            repeated.events.len(),
            3,
            "exactly three events fit under a 3x-event ceiling"
        );
        assert_eq!(repeated.dropped_event_count, 17);
        assert!(
            repeated.estimated_memory_bytes() <= repeated.config.max_total_memory_bytes,
            "accumulated general events must never exceed the containment budget"
        );
        assert_eq!(
            repeated.estimated_memory_bytes(),
            repeated.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_code_invocation_reservation_and_lifecycle_pairs_are_exact_bd_fw7zd_8_2() {
        let provenance = InterpreterCore::derive_generated_function_provenance(
            "generated-reservation-owner.mjs",
            "value",
            "return value;",
        );
        let capabilities = vec![
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
            RuntimeCapability::Timer,
        ];
        let fixture = || {
            let mut core = test_interpreter();
            core.sync_estimated_memory_bytes()
                .expect("generated reservation fixture baseline");
            core
        };

        let mut one_short = fixture();
        let one_short_baseline = one_short.estimated_memory_bytes();
        let reservation_bytes = one_short
            .estimate_generated_code_invocation_reservation_bytes(&provenance, &capabilities);
        one_short.config.max_total_memory_bytes = one_short_baseline
            .saturating_add(reservation_bytes)
            .saturating_sub(1);
        assert!(matches!(
            one_short.reserve_generated_code_invocation_event(&provenance, &capabilities),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(one_short.generated_code_observability_reservation_bytes, 0);
        assert_eq!(one_short.estimated_memory_bytes(), one_short_baseline);

        let mut exact = fixture();
        let exact_baseline = exact.estimated_memory_bytes();
        exact.config.max_total_memory_bytes = exact_baseline.saturating_add(reservation_bytes);
        let reserved = exact
            .reserve_generated_code_invocation_event(&provenance, &capabilities)
            .expect("generated invocation reservation at exact ceiling");
        assert_eq!(reserved, reservation_bytes);
        assert_eq!(
            exact.generated_code_observability_reservation_bytes,
            reservation_bytes
        );
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes()
        );
        exact
            .sync_estimated_memory_bytes()
            .expect("eager recompute must preserve generated invocation reservation");
        assert_eq!(
            exact.generated_code_observability_reservation_bytes,
            reservation_bytes
        );
        exact
            .commit_reserved_generated_code_event(
                GeneratedCodeAuditEntry {
                    source_id: provenance.source_id.clone(),
                    source_hash: provenance.source_hash.clone(),
                    parameter_hash: provenance.parameter_hash.clone(),
                    construction_site: provenance.construction_site.clone(),
                    kind: GeneratedCodeEventKind::Faulted,
                    instructions_consumed: u64::MAX,
                    caller_call_depth: 3,
                    granted_capabilities: capabilities
                        .iter()
                        .map(|capability| {
                            InterpreterCore::contained_codegen_capability_name(*capability)
                                .to_string()
                        })
                        .collect(),
                    outcome: "faulted:memory_budget_exceeded".to_string(),
                },
                reserved,
            )
            .expect("worst-case generated invocation audit fits its reservation");
        assert_eq!(exact.generated_code_observability_reservation_bytes, 0);
        assert_eq!(exact.generated_code_observability_bytes, reservation_bytes);
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes()
        );

        exact.config.max_total_memory_bytes = DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES;
        for _ in 0..2 {
            for (kind, instructions, outcome) in [
                (GeneratedCodeEventKind::Constructed, 0, "constructed"),
                (GeneratedCodeEventKind::Invoked, 11, "completed"),
                (
                    GeneratedCodeEventKind::Faulted,
                    13,
                    "faulted:uncaught_exception",
                ),
            ] {
                let entry = GeneratedCodeAuditEntry {
                    source_id: provenance.source_id.clone(),
                    source_hash: provenance.source_hash.clone(),
                    parameter_hash: provenance.parameter_hash.clone(),
                    construction_site: provenance.construction_site.clone(),
                    kind,
                    instructions_consumed: instructions,
                    caller_call_depth: usize::from(kind != GeneratedCodeEventKind::Constructed),
                    granted_capabilities: match kind {
                        GeneratedCodeEventKind::Constructed => Vec::new(),
                        _ => vec!["builtin".to_string()],
                    },
                    outcome: outcome.to_string(),
                };
                exact
                    .record_generated_code_event(entry)
                    .expect("repeated generated lifecycle pair");
            }
        }
        assert_eq!(exact.generated_code_audit.len(), 7);
        assert_eq!(exact.events.len(), 7);
        assert_eq!(
            exact.generated_code_observability_bytes,
            exact.generated_code_observability_memory_bytes()
        );
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes()
        );

        let result = exact.take_execution_result(
            LabeledReturn {
                value: Value::Undefined,
                label: Label::Public,
            },
            None,
        );
        assert_eq!(result.generated_code_audit.len(), 7);
        assert_eq!(result.events.len(), 7);
        assert_eq!(exact.generated_code_observability_bytes, 0);
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes(),
            "draining execution observability must release its complete charge"
        );
    }

    #[test]
    fn generated_code_result_label_failure_is_a_fault_bd_fw7zd_8_2() {
        let completed_body: Result<Value, InterpreterError> = Ok(Value::Int(7));
        let public_label: Result<Label, InterpreterError> = Ok(Label::Public);
        assert_eq!(
            InterpreterCore::generated_code_invocation_outcome(&completed_body, &public_label),
            (GeneratedCodeEventKind::Invoked, "completed".to_string())
        );

        let refused_label: Result<Label, InterpreterError> =
            Err(InterpreterError::MemoryBudgetExceeded {
                requested_bytes: 4096,
                max_bytes: 2048,
                requested_heap_objects: 1,
                max_heap_objects: 1,
            });
        assert_eq!(
            InterpreterCore::generated_code_invocation_outcome(&completed_body, &refused_label),
            (
                GeneratedCodeEventKind::Faulted,
                "faulted:memory_budget_exceeded".to_string()
            ),
            "a generated call that cannot materialize its result label did not complete"
        );
    }

    #[test]
    fn generated_code_actual_construct_invoke_and_fault_paths_are_paired_bd_fw7zd_8_2() {
        let mut owner = test_module_with_functions(Vec::new(), Vec::new());
        owner.header.source_label = "generated-lifecycle-owner.mjs".to_string();
        let mut core = test_interpreter();
        core.ensure_module_record(&owner, &owner.header.source_label)
            .expect("retain generated lifecycle owner");

        for (body, expected) in [("return 7;", Value::Int(7)), ("return 8;", Value::Int(8))] {
            core.write_reg(0, Value::str(body))
                .expect("seed generated success source");
            let Value::BuiltinFunction(generated) = core
                .construct_generated_function(&owner, RegRange { start: 0, count: 1 })
                .expect("construct generated success function")
            else {
                panic!("Function constructor must return a builtin handle");
            };
            assert_eq!(
                core.dispatch_builtin_function(
                    &owner,
                    &generated,
                    RegRange { start: 1, count: 0 },
                    None,
                    None,
                )
                .expect("invoke generated success function"),
                expected
            );
        }

        core.write_reg(0, Value::str("throw 'boom';"))
            .expect("seed generated fault source");
        let Value::BuiltinFunction(faulting) = core
            .construct_generated_function(&owner, RegRange { start: 0, count: 1 })
            .expect("construct generated fault function")
        else {
            panic!("Function constructor must return a builtin handle");
        };
        assert!(matches!(
            core.dispatch_builtin_function(
                &owner,
                &faulting,
                RegRange { start: 1, count: 0 },
                None,
                None,
            ),
            Err(InterpreterError::UncaughtException { .. })
        ));

        assert_eq!(
            core.generated_code_audit
                .iter()
                .map(|entry| entry.kind)
                .collect::<Vec<_>>(),
            vec![
                GeneratedCodeEventKind::Constructed,
                GeneratedCodeEventKind::Invoked,
                GeneratedCodeEventKind::Constructed,
                GeneratedCodeEventKind::Invoked,
                GeneratedCodeEventKind::Constructed,
                GeneratedCodeEventKind::Faulted,
            ]
        );
        assert_eq!(core.events.len(), core.generated_code_audit.len());
        assert_eq!(
            core.generated_code_observability_bytes,
            core.generated_code_observability_memory_bytes()
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_function_realm_registry_is_sanitized_shared_and_budget_atomic_bd_fw7zd_8_3() {
        let fixture = || {
            let mut core = test_interpreter();
            core.sync_estimated_memory_bytes()
                .expect("generated realm fixture baseline");
            core
        };

        let mut probe = fixture();
        let probe_baseline = probe.estimated_memory_bytes();
        let probe_heap_len = probe.heap.len();
        probe
            .ensure_generated_function_realm_globals()
            .expect("initialize generated realm without a ceiling");
        let retained_delta = probe
            .estimated_memory_bytes()
            .saturating_sub(probe_baseline);
        let allocated_objects = probe.heap.len().saturating_sub(probe_heap_len);
        assert!(retained_delta > 0);
        assert!(allocated_objects > 0);

        let globals = probe
            .generated_function_realm_globals
            .as_ref()
            .expect("generated realm registry");
        for safe_name in [
            "Date",
            "Math",
            "Promise",
            "clearImmediate",
            "clearInterval",
            "clearTimeout",
            "console",
            "performance",
            "queueMicrotask",
            "setImmediate",
            "setInterval",
            "setTimeout",
            // bd-9vouw.133: the realm's namespaces, global object and the
            // stateless standard values.
            "JSON",
            "Reflect",
            "globalThis",
            "global",
            "Object",
            "Array",
            "Symbol",
            "parseInt",
            "structuredClone",
            "Atomics",
            "Blob",
            "SharedArrayBuffer",
        ] {
            assert!(
                globals.contains_key(safe_name),
                "missing safe global {safe_name}"
            );
        }
        for forbidden_name in ["Function", "process", "require", "eval"] {
            assert!(
                !globals.contains_key(forbidden_name),
                "ambient or recursive authority leaked through {forbidden_name}"
            );
        }
        // 8 realm objects (Atomics since bd-9vouw.245), Date and Promise, 7
        // timers, 50 standard constructors (EventTarget, Event, CustomEvent,
        // AbortController, AbortSignal and DOMException since bd-9vouw.170,
        // Iterator since bd-9vouw.179, Blob since bd-9vouw.226,
        // SharedArrayBuffer since bd-9vouw.244), 13 global functions.
        assert_eq!(globals.len(), 80);
        assert_eq!(
            InterpreterCore::projected_generated_function_realm_registry_bytes(),
            InterpreterCore::estimate_generated_function_realm_globals_bytes(globals),
            "generated realm preflight must include every retained binding byte"
        );

        let first_scope = probe
            .generated_function_realm_scope_frame()
            .expect("first generated realm frame");
        let second_scope = probe
            .generated_function_realm_scope_frame()
            .expect("second generated realm frame");
        assert_eq!(
            InterpreterCore::estimate_scope_frame_bytes(&first_scope),
            InterpreterCore::estimate_generated_function_realm_scope_bytes(globals)
        );
        for name in globals.keys() {
            let canonical = globals.get(name).expect("canonical safe binding");
            let first = first_scope.get(name).expect("first safe binding");
            let second = second_scope.get(name).expect("second safe binding");
            assert!(
                Rc::ptr_eq(&first.state, &canonical.state),
                "first generated invocation detached the canonical {name} binding cell"
            );
            assert!(
                Rc::ptr_eq(&second.state, &canonical.state),
                "second generated invocation detached the canonical {name} binding cell"
            );
        }
        first_scope
            .get("console")
            .expect("first console binding")
            .set_state(Value::Int(99), true)
            .expect("mutate first invocation binding");
        assert_eq!(
            second_scope
                .get("console")
                .expect("second console binding")
                .value()
                .expect("read second invocation binding"),
            Value::Int(99)
        );
        assert_eq!(
            globals
                .get("console")
                .expect("canonical console binding")
                .value()
                .expect("read canonical binding"),
            Value::Int(99)
        );
        assert_eq!(
            probe.estimated_memory_bytes(),
            probe.recompute_estimated_memory_bytes()
        );

        let mut one_short = fixture();
        let one_short_baseline = one_short.estimated_memory_bytes();
        let one_short_heap_len = one_short.heap.len();
        one_short.config.max_total_memory_bytes = one_short_baseline
            .saturating_add(retained_delta)
            .saturating_sub(1);
        assert!(matches!(
            one_short.ensure_generated_function_realm_globals(),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(one_short.generated_function_realm_globals.is_none());
        assert_eq!(one_short.heap.len(), one_short_heap_len);
        assert_eq!(one_short.estimated_memory_bytes(), one_short_baseline);
        assert_eq!(
            one_short.estimated_memory_bytes(),
            one_short.recompute_estimated_memory_bytes()
        );

        let mut exact = fixture();
        let exact_baseline = exact.estimated_memory_bytes();
        let exact_heap_len = exact.heap.len();
        exact.config.max_total_memory_bytes = exact_baseline.saturating_add(retained_delta);
        exact
            .ensure_generated_function_realm_globals()
            .expect("generated realm fits exact retained ceiling");
        assert_eq!(
            exact.heap.len().saturating_sub(exact_heap_len),
            allocated_objects
        );
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact_baseline.saturating_add(retained_delta)
        );
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes()
        );

        // Re-entrant module calls can construct a generated function while an
        // outer wrapper has a temporary, deliberately non-resident precharge.
        // Realm initialization must preserve that accounting offset while
        // proving its own retained delta exactly.
        let mut nested = fixture();
        let outer_wrapper_precharge = 12_298;
        nested
            .apply_memory_component_delta(0, outer_wrapper_precharge)
            .expect("reserve outer wrapper memory");
        nested
            .ensure_generated_function_realm_globals()
            .expect("initialize generated realm under an outer precharge");
        assert_eq!(
            nested
                .estimated_memory_bytes()
                .saturating_sub(nested.recompute_estimated_memory_bytes()),
            outer_wrapper_precharge
        );
        nested
            .apply_memory_component_delta(outer_wrapper_precharge, 0)
            .expect("release outer wrapper memory");
        assert_eq!(
            nested.estimated_memory_bytes(),
            nested.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_function_sloppy_globals_persist_and_roll_back_atomically_bd_fw7zd_8_3() {
        let artifact_handle = GeneratedFunctionArtifactHandle {
            owner_program_id: ContentHash::compute(b"generated-realm-owner"),
            artifact_id: ContentHash::compute(b"generated-realm-artifact"),
        };

        let mut core = test_interpreter();
        core.ensure_generated_function_realm_globals()
            .expect("initialize persistent generated realm");
        let first_frame = core
            .generated_function_realm_scope_frame()
            .expect("first generated realm frame");
        let stale_frame = core
            .generated_function_realm_scope_frame()
            .expect("pre-insertion generated realm frame");
        let previous_scope_bytes = core.scope_chain_memory_bytes();
        core.scope_chain.frames = vec![first_frame];
        core.apply_scope_chain_memory_delta(previous_scope_bytes)
            .expect("activate first generated realm frame");
        core.active_generated_function_artifact = Some(artifact_handle);

        core.put_runtime_name("generatedOnly", Value::Int(17), false)
            .expect("create generated-realm sloppy global");
        let canonical = core
            .generated_function_realm_globals
            .as_ref()
            .and_then(|globals| globals.get("generatedOnly"))
            .cloned()
            .expect("canonical generated sloppy global");
        let active = core.scope_chain.frames[0]
            .get("generatedOnly")
            .expect("active generated sloppy global");
        assert!(Rc::ptr_eq(&canonical.state, &active.state));

        let previous_scope_bytes = core.scope_chain_memory_bytes();
        core.scope_chain.frames = vec![stale_frame];
        core.apply_scope_chain_memory_delta(previous_scope_bytes)
            .expect("restore pre-insertion generated invocation frame");
        assert!(
            core.scope_chain.frames[0].get("generatedOnly").is_none(),
            "the stale structural frame must exercise canonical fallback"
        );
        assert_eq!(
            core.load_runtime_name("generatedOnly", false)
                .expect("load persisted generated sloppy global"),
            Value::Int(17)
        );
        let reference_token = core
            .capture_runtime_name_reference("generatedOnly")
            .expect("capture canonical generated global Reference");
        core.put_runtime_name_with_status(
            "generatedOnly",
            Value::str("persisted"),
            true,
            reference_token,
        )
        .expect("replace persisted generated sloppy global through captured Reference");
        assert_eq!(
            canonical.value().expect("canonical replacement value"),
            Value::str("persisted")
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );

        let mut refused = test_interpreter();
        refused
            .ensure_generated_function_realm_globals()
            .expect("initialize refusal generated realm");
        let refusal_frame = refused
            .generated_function_realm_scope_frame()
            .expect("refusal generated realm frame");
        let previous_scope_bytes = refused.scope_chain_memory_bytes();
        refused.scope_chain.frames = vec![refusal_frame];
        refused
            .apply_scope_chain_memory_delta(previous_scope_bytes)
            .expect("activate refusal generated realm frame");
        refused.active_generated_function_artifact = Some(artifact_handle);
        let refusal_baseline = refused.estimated_memory_bytes();
        refused.config.max_total_memory_bytes = refusal_baseline;
        assert!(matches!(
            refused.put_runtime_name("refusedGeneratedOnly", Value::Int(1), false),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(
            !refused.scope_chain.frames[0]
                .bindings
                .contains_key("refusedGeneratedOnly")
        );
        assert!(
            !refused
                .generated_function_realm_globals
                .as_ref()
                .expect("refusal canonical realm")
                .contains_key("refusedGeneratedOnly")
        );
        assert_eq!(refused.estimated_memory_bytes(), refusal_baseline);
        assert_eq!(
            refused.estimated_memory_bytes(),
            refused.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_authority_envelope_replaces_and_restores_full_caller_grants_bd_fw7zd_8_4() {
        fn fixture(
            case: &str,
            instructions: Vec<Ir3Instruction>,
            required_capabilities: Vec<CapabilityTag>,
            cancellation_token: Option<CancellationToken>,
        ) -> (
            InterpreterCore,
            BuiltinFunction,
            BTreeSet<RuntimeCapability>,
        ) {
            let mut owner = test_module_with_functions(Vec::new(), Vec::new());
            owner.header.source_label = format!("generated-authority-{case}-owner.mjs");
            let mut generated = test_module_with_functions(
                instructions,
                vec![Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some(format!("generated_authority_{case}")),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            generated.required_capabilities = required_capabilities;

            let mut config = InterpreterConfig::quickjs_defaults();
            config.granted_capabilities = RuntimeCapability::ALL.into_iter().collect();
            if let Some(token) = cancellation_token {
                config.cancellation_token = Some(token);
                // The wrapper Call executes at count one; cancellation fires
                // at count two before the generated body executes.
                config.checkpoint_density = 2;
            }
            let original_grants = config.granted_capabilities.clone();
            let mut core = InterpreterCore::new(config, format!("generated-authority-{case}"));
            core.ensure_module_record(&owner, &owner.header.source_label)
                .expect("retain generated authority owner");
            let (builtin, _, _) = retain_generated_test_artifact(
                &mut core,
                &owner,
                generated,
                0,
                &format!("authority {case}"),
            );
            (core, builtin, original_grants)
        }

        let (mut success, success_builtin, success_grants) = fixture(
            "success",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::Return { value: 0 },
            ],
            Vec::new(),
            None,
        );
        assert_eq!(
            success
                .call_generated_function_artifact(
                    &success_builtin,
                    RegRange { start: 0, count: 0 },
                    None,
                    None,
                )
                .expect("contained generated success")
                .0,
            Value::Int(7)
        );
        assert_eq!(success.config.granted_capabilities, success_grants);
        assert_eq!(
            success.generated_code_audit[0].granted_capabilities,
            ["vm_dispatch", "heap_allocate"]
        );

        let (mut fault, fault_builtin, fault_grants) = fixture(
            "fault",
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("fs:read".to_string()),
                    args: RegRange { start: 0, count: 0 },
                    dst: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![CapabilityTag("fs:read".to_string())],
            None,
        );
        assert!(matches!(
            fault.call_generated_function_artifact(
                &fault_builtin,
                RegRange { start: 0, count: 0 },
                None,
                None,
            ),
            Err(InterpreterError::CapabilityDenied { capability }) if capability == "fs:read"
        ));
        assert_eq!(fault.config.granted_capabilities, fault_grants);
        assert_eq!(
            fault.generated_code_audit[0].kind,
            GeneratedCodeEventKind::Faulted
        );
        assert_eq!(
            fault.generated_code_audit[0].granted_capabilities,
            ["vm_dispatch", "heap_allocate"]
        );

        let cancellation_token = CancellationToken::new();
        cancellation_token.cancel();
        let (mut cancelled, cancelled_builtin, cancelled_grants) = fixture(
            "cancelled",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 9 },
                Ir3Instruction::Return { value: 0 },
            ],
            Vec::new(),
            Some(cancellation_token.clone()),
        );
        assert_eq!(
            cancelled.call_generated_function_artifact(
                &cancelled_builtin,
                RegRange { start: 0, count: 0 },
                None,
                None,
            ),
            Err(InterpreterError::Cancelled)
        );
        assert_eq!(cancelled.config.granted_capabilities, cancelled_grants);
        assert_eq!(
            cancelled.generated_code_audit[0].kind,
            GeneratedCodeEventKind::Faulted
        );
        assert_eq!(
            cancelled.generated_code_audit[0].granted_capabilities,
            ["vm_dispatch", "heap_allocate"]
        );
        cancellation_token.reset();
    }

    #[test]
    fn generated_nested_closure_restores_full_caller_grants_on_all_outcomes_bd_fw7zd_8_5() {
        fn fixture(
            case: &str,
            nested_body: Vec<Ir3Instruction>,
        ) -> (
            InterpreterCore,
            Ir3Module,
            Value,
            BTreeSet<RuntimeCapability>,
        ) {
            let mut owner = test_module_with_functions(Vec::new(), Vec::new());
            owner.header.source_label = format!("generated-nested-authority-{case}-owner.mjs");
            let mut instructions = vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 1,
                    capture_count: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ];
            instructions.extend(nested_body);
            let mut generated = test_module_with_functions(
                instructions,
                vec![
                    Ir3FunctionDesc {
                        entry: 0,
                        arity: 0,
                        frame_size: 1,
                        name: Some(format!("generated_nested_{case}_outer")),
                        is_generator: false,
                        rest_param_index: None,
                    },
                    Ir3FunctionDesc {
                        entry: 2,
                        arity: 0,
                        frame_size: 1,
                        name: Some(format!("generated_nested_{case}")),
                        is_generator: false,
                        rest_param_index: None,
                    },
                ],
            );
            generated.required_capabilities = vec![CapabilityTag("fs:read".to_string())];

            let mut config = InterpreterConfig::quickjs_defaults();
            config.granted_capabilities = RuntimeCapability::ALL.into_iter().collect();
            let caller_grants = config.granted_capabilities.clone();
            let mut core = InterpreterCore::new(config, format!("generated-nested-{case}"));
            core.ensure_module_record(&owner, &owner.header.source_label)
                .expect("retain generated nested-authority owner");
            let (builtin, _, _) = retain_generated_test_artifact(
                &mut core,
                &owner,
                generated,
                0,
                &format!("nested authority {case}"),
            );
            let (nested, _) = core
                .call_generated_function_artifact(
                    &builtin,
                    RegRange { start: 0, count: 0 },
                    None,
                    None,
                )
                .expect("generated outer should return its nested closure");
            assert!(matches!(nested, Value::Closure(_)));
            assert_eq!(core.config.granted_capabilities, caller_grants);
            (core, owner, nested, caller_grants)
        }

        let (mut success, success_owner, success_nested, success_grants) = fixture(
            "success",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::Return { value: 0 },
            ],
        );
        let success_audit_rows = success.generated_code_audit.len();
        assert_eq!(
            success
                .invoke_inline_method_call(
                    Some(&success_owner),
                    success_nested,
                    Value::Undefined,
                    Vec::new(),
                )
                .expect("contained nested closure should complete"),
            Value::Int(7)
        );
        assert_eq!(success.config.granted_capabilities, success_grants);
        assert_eq!(success.generated_code_audit.len(), success_audit_rows);

        let denied_body = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("fs:read".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ];
        let (mut fault, fault_owner, fault_nested, fault_grants) =
            fixture("fault", denied_body.clone());
        let fault_audit_rows = fault.generated_code_audit.len();
        assert!(matches!(
            fault.invoke_inline_method_call(
                Some(&fault_owner),
                fault_nested.clone(),
                Value::Undefined,
                Vec::new(),
            ),
            Err(InterpreterError::CapabilityDenied { capability }) if capability == "fs:read"
        ));
        assert_eq!(fault.config.granted_capabilities, fault_grants);
        assert_eq!(fault.generated_code_audit.len(), fault_audit_rows);
        assert!(matches!(
            fault.invoke_inline_construct(Some(&fault_owner), fault_nested, Vec::new()),
            Err(InterpreterError::CapabilityDenied { capability }) if capability == "fs:read"
        ));
        assert_eq!(fault.config.granted_capabilities, fault_grants);
        assert_eq!(fault.generated_code_audit.len(), fault_audit_rows);

        let (mut cancelled, cancelled_owner, cancelled_nested, cancelled_grants) = fixture(
            "cancelled",
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 9 },
                Ir3Instruction::Return { value: 0 },
            ],
        );
        let cancellation_token = CancellationToken::new();
        cancellation_token.cancel();
        cancelled.config.cancellation_token = Some(cancellation_token.clone());
        cancelled.config.checkpoint_density = 1;
        let cancelled_audit_rows = cancelled.generated_code_audit.len();
        assert_eq!(
            cancelled.invoke_inline_method_call(
                Some(&cancelled_owner),
                cancelled_nested,
                Value::Undefined,
                Vec::new(),
            ),
            Err(InterpreterError::Cancelled)
        );
        assert_eq!(cancelled.config.granted_capabilities, cancelled_grants);
        assert_eq!(cancelled.generated_code_audit.len(), cancelled_audit_rows);
        cancellation_token.reset();

        for core in [&success, &fault, &cancelled] {
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn generated_generator_initial_and_resumed_entries_keep_contained_grants_bd_fw7zd_8_5() {
        fn fixture(
            case: &str,
            generator_body: Vec<Ir3Instruction>,
        ) -> (
            InterpreterCore,
            Ir3Module,
            u32,
            BTreeSet<RuntimeCapability>,
            usize,
        ) {
            let mut owner = test_module_with_functions(Vec::new(), Vec::new());
            owner.header.source_label = format!("generated-generator-authority-{case}-owner.mjs");
            let mut instructions = vec![
                Ir3Instruction::CreateGenerator {
                    dst: 0,
                    function_index: 1,
                    capture_count: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ];
            instructions.extend(generator_body);
            let mut generated = test_module_with_functions(
                instructions,
                vec![
                    Ir3FunctionDesc {
                        entry: 0,
                        arity: 0,
                        frame_size: 1,
                        name: Some(format!("generated_generator_{case}_outer")),
                        is_generator: false,
                        rest_param_index: None,
                    },
                    Ir3FunctionDesc {
                        entry: 2,
                        arity: 0,
                        frame_size: 2,
                        name: Some(format!("generated_generator_{case}")),
                        is_generator: true,
                        rest_param_index: None,
                    },
                ],
            );
            generated.required_capabilities = vec![CapabilityTag("fs:read".to_string())];

            let mut config = InterpreterConfig::quickjs_defaults();
            config.granted_capabilities = RuntimeCapability::ALL.into_iter().collect();
            let caller_grants = config.granted_capabilities.clone();
            let mut core = InterpreterCore::new(config, format!("generated-generator-{case}"));
            core.ensure_module_record(&owner, &owner.header.source_label)
                .expect("retain generated generator-authority owner");
            let (builtin, _, _) = retain_generated_test_artifact(
                &mut core,
                &owner,
                generated,
                0,
                &format!("generator authority {case}"),
            );
            let (generator_function, _) = core
                .call_generated_function_artifact(
                    &builtin,
                    RegRange { start: 0, count: 0 },
                    None,
                    None,
                )
                .expect("generated outer should return a generator function");
            let generator = core
                .invoke_inline_method_call(
                    Some(&owner),
                    generator_function,
                    Value::Undefined,
                    Vec::new(),
                )
                .expect("generated generator function should create an object");
            let Value::Generator(generator_id) = generator else {
                panic!("expected generated Generator object, got {generator:?}");
            };
            assert_eq!(core.config.granted_capabilities, caller_grants);
            let audit_rows = core.generated_code_audit.len();
            (core, owner, generator_id, caller_grants, audit_rows)
        }

        let denied_body = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("fs:read".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ];
        let (mut initial, initial_owner, initial_id, initial_grants, initial_audit_rows) =
            fixture("initial", denied_body.clone());
        assert!(matches!(
            initial.generator_next(&initial_owner, initial_id, Value::Undefined, Label::Public),
            Err(InterpreterError::CapabilityDenied { capability }) if capability == "fs:read"
        ));
        assert_eq!(initial.config.granted_capabilities, initial_grants);
        assert_eq!(initial.generated_code_audit.len(), initial_audit_rows);

        let mut resume_body = vec![
            Ir3Instruction::LoadInt { dst: 0, value: 41 },
            Ir3Instruction::Yield {
                value: 0,
                delegate: false,
                resume_dst: 1,
            },
        ];
        resume_body.extend(denied_body);
        let (mut resumed, resumed_owner, resumed_id, resumed_grants, resumed_audit_rows) =
            fixture("resume", resume_body);
        resumed
            .generator_next(&resumed_owner, resumed_id, Value::Undefined, Label::Public)
            .expect("generated generator should reach its first yield");
        assert_eq!(resumed.config.granted_capabilities, resumed_grants);
        let suspended_grant = resumed.generators[resumed_id as usize]
            .execution
            .as_ref()
            .and_then(|execution| execution.contained_codegen_grant)
            .expect("generated generator must persist its contained grant");
        assert_eq!(
            suspended_grant.as_slice(),
            [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate
            ]
        );
        assert!(matches!(
            resumed.generator_next(&resumed_owner, resumed_id, Value::Undefined, Label::Public),
            Err(InterpreterError::CapabilityDenied { capability }) if capability == "fs:read"
        ));
        assert_eq!(resumed.config.granted_capabilities, resumed_grants);
        assert_eq!(resumed.generated_code_audit.len(), resumed_audit_rows);

        for core in [&initial, &resumed] {
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn generated_async_pre_and_post_await_entries_keep_contained_grants_bd_fw7zd_8_5() {
        fn fixture(
            case: &str,
            async_body: Vec<Ir3Instruction>,
            async_arity: u32,
        ) -> (
            InterpreterCore,
            Ir3Module,
            Value,
            BTreeSet<RuntimeCapability>,
            usize,
        ) {
            let mut owner = test_module_with_functions(Vec::new(), Vec::new());
            owner.header.source_label = format!("generated-async-authority-{case}-owner.mjs");
            let mut instructions = vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 1,
                    capture_count: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ];
            instructions.extend(async_body);
            let mut generated = test_module_with_functions(
                instructions,
                vec![
                    Ir3FunctionDesc {
                        entry: 0,
                        arity: 0,
                        frame_size: 1,
                        name: Some(format!("generated_async_{case}_outer")),
                        is_generator: false,
                        rest_param_index: None,
                    },
                    Ir3FunctionDesc {
                        entry: 2,
                        arity: async_arity,
                        frame_size: 1,
                        name: Some(format!("generated_async_{case}")),
                        is_generator: false,
                        rest_param_index: None,
                    },
                ],
            );
            generated.required_capabilities = vec![CapabilityTag("fs:read".to_string())];

            let mut config = InterpreterConfig::quickjs_defaults();
            config.granted_capabilities = RuntimeCapability::ALL.into_iter().collect();
            let caller_grants = config.granted_capabilities.clone();
            let mut core = InterpreterCore::new(config, format!("generated-async-{case}"));
            core.ensure_module_record(&owner, &owner.header.source_label)
                .expect("retain generated async-authority owner");
            let (builtin, _, _) = retain_generated_test_artifact(
                &mut core,
                &owner,
                generated,
                0,
                &format!("async authority {case}"),
            );
            let (async_function, _) = core
                .call_generated_function_artifact(
                    &builtin,
                    RegRange { start: 0, count: 0 },
                    None,
                    None,
                )
                .expect("generated outer should return an async function");
            assert!(matches!(async_function, Value::AsyncFunction(_)));
            assert_eq!(core.config.granted_capabilities, caller_grants);
            let audit_rows = core.generated_code_audit.len();
            (core, owner, async_function, caller_grants, audit_rows)
        }

        let denied_body = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("fs:read".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::AsyncReturn { value_reg: 0 },
        ];
        let (mut initial, initial_owner, initial_async, initial_grants, initial_audit_rows) =
            fixture("initial", denied_body.clone(), 0);
        assert!(matches!(
            initial.invoke_inline_method_call(
                Some(&initial_owner),
                initial_async,
                Value::Undefined,
                Vec::new(),
            ),
            Err(InterpreterError::CapabilityDenied { capability }) if capability == "fs:read"
        ));
        assert_eq!(initial.config.granted_capabilities, initial_grants);
        assert_eq!(initial.generated_code_audit.len(), initial_audit_rows);

        let mut resumed_body = vec![Ir3Instruction::AwaitValue { promise_reg: 0 }];
        resumed_body.extend(denied_body);
        let (mut resumed, resumed_owner, resumed_async, resumed_grants, resumed_audit_rows) =
            fixture("resume", resumed_body, 1);
        let awaited = resumed.promise_store.create();
        resumed
            .sync_estimated_memory_bytes()
            .expect("generated async authority fixture accounting");
        let async_result = resumed
            .invoke_inline_method_call(
                Some(&resumed_owner),
                resumed_async,
                Value::Undefined,
                vec![Value::Promise(awaited.0)],
            )
            .expect("generated async function should suspend at its pending await");
        let Value::Promise(result_promise) = async_result else {
            panic!("expected generated async result Promise, got {async_result:?}");
        };
        assert_eq!(resumed.config.granted_capabilities, resumed_grants);
        let suspended = resumed
            .async_functions
            .last()
            .expect("generated async object should be retained");
        assert_eq!(suspended.result_promise, result_promise);
        let suspended_grant = suspended
            .isolated_execution
            .as_ref()
            .and_then(|execution| execution.contained_codegen_grant)
            .expect("generated async continuation must persist its contained grant");
        assert_eq!(
            suspended_grant.as_slice(),
            [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate
            ]
        );

        resumed
            .fulfill_promise(awaited, crate::object_model::JsValue::Int(2), Label::Public)
            .expect("awaited Promise should be fulfillable");
        assert!(matches!(
            resumed.drain_microtasks(Some(&resumed_owner)),
            Err(InterpreterError::CapabilityDenied { capability }) if capability == "fs:read"
        ));
        assert_eq!(resumed.config.granted_capabilities, resumed_grants);
        assert_eq!(resumed.generated_code_audit.len(), resumed_audit_rows);

        for core in [&initial, &resumed] {
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn generated_function_handles_do_not_alias_across_realm_rotation_bd_fw7zd_8_3() {
        let mut owner = test_module_with_functions(Vec::new(), Vec::new());
        owner.header.source_label = "generated-realm-rotation-owner.mjs".to_string();
        let generated = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("generated_realm_rotation_body".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let provenance = InterpreterCore::derive_generated_function_provenance(
            &owner.header.source_label,
            "",
            "return 7;",
        );
        let mut core = test_interpreter();
        core.ensure_module_record(&owner, &owner.header.source_label)
            .expect("retain generated realm-rotation owner");
        let owner_program = Arc::clone(
            core.module_state.modules[&owner.header.source_label]
                .compiled_module
                .as_ref()
                .expect("generated realm-rotation owner program"),
        );
        let first = core
            .retain_generated_function_artifact(
                owner.content_hash(),
                owner.header.source_label.clone(),
                Arc::clone(&owner_program),
                provenance.clone(),
                generated.clone(),
                0,
            )
            .expect("retain first-realm generated artifact");
        let (owner_program_id, first_artifact_id) =
            InterpreterCore::parse_generated_function_handle(&first)
                .expect("parse first-realm handle");
        let first_generation = core.generated_function_realm_generation;
        assert_eq!(
            core.module_state.generated_function_stores[&owner_program_id].realm_generation,
            first_generation
        );
        core.put_realm_runtime_name("realmPoison", Value::Int(99))
            .expect("seed replacement-bound realm global");

        core.rotate_generated_function_realm()
            .expect("rotate generated-function realm");
        assert_eq!(
            core.generated_function_realm_generation,
            first_generation + 1
        );
        assert!(core.module_state.generated_function_stores.is_empty());
        assert_eq!(core.module_state.retained_generated_function_bytes, 0);
        assert!(core.generated_function_realm_globals.is_none());
        assert!(core.realm_dynamic_globals.is_empty());
        assert!(matches!(
            core.resolve_generated_function_artifact(owner_program_id, first_artifact_id),
            Err(InterpreterError::ModuleEvaluationFailed { ref reason, .. })
                if reason.contains("owner store is not retained")
        ));

        let second = core
            .retain_generated_function_artifact(
                owner.content_hash(),
                owner.header.source_label.clone(),
                owner_program,
                provenance,
                generated,
                0,
            )
            .expect("retain identical source in replacement realm");
        let (_, second_artifact_id) = InterpreterCore::parse_generated_function_handle(&second)
            .expect("parse replacement-realm handle");
        assert_ne!(first_artifact_id, second_artifact_id);
        assert!(matches!(
            core.call_generated_function_artifact(
                &first,
                RegRange { start: 0, count: 0 },
                None,
                None,
            ),
            Err(InterpreterError::ModuleEvaluationFailed { ref reason, .. })
                if reason.contains("is not retained by its owner")
        ));
        assert_eq!(
            core.call_generated_function_artifact(
                &second,
                RegRange { start: 0, count: 0 },
                None,
                None,
            )
            .expect("replacement-realm artifact remains callable")
            .0,
            Value::Int(7)
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_function_compilation_scratch_preflights_and_releases_bd_fw7zd_8_2() {
        let mut owner = test_module_with_functions(Vec::new(), Vec::new());
        owner.header.source_label = "generated-compilation-owner.mjs".to_string();
        let oversized_body = " ".repeat(16 * 1024);
        let fixture = || {
            let mut core = test_interpreter();
            core.ensure_module_record(&owner, &owner.header.source_label)
                .expect("retain generated compilation owner");
            core.ensure_generated_function_realm_globals()
                .expect("initialize generated compilation realm");
            core.write_reg(0, Value::str(oversized_body.clone()))
                .expect("seed generated compilation body");
            core.sync_estimated_memory_bytes()
                .expect("generated compilation fixture baseline");
            core
        };
        let args = RegRange { start: 0, count: 1 };

        let mut one_short = fixture();
        let one_short_baseline = one_short.estimated_memory_bytes();
        let scratch_bytes = one_short
            .generated_function_compilation_scratch_bytes(args)
            .expect("deterministic generated compilation scratch");
        one_short.config.max_total_memory_bytes = one_short_baseline
            .saturating_add(scratch_bytes)
            .saturating_sub(1);
        assert!(matches!(
            one_short.construct_generated_function(&owner, args),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(one_short.module_state.generated_function_stores.is_empty());
        assert!(one_short.generated_code_audit.is_empty());
        assert!(one_short.events.is_empty());
        assert_eq!(one_short.generated_code_observability_bytes, 0);
        assert_eq!(one_short.estimated_memory_bytes(), one_short_baseline);
        assert_eq!(
            one_short.estimated_memory_bytes(),
            one_short.recompute_estimated_memory_bytes()
        );

        let mut exact = fixture();
        let exact_baseline = exact.estimated_memory_bytes();
        let exact_scratch = exact
            .generated_function_compilation_scratch_bytes(args)
            .expect("exact generated compilation scratch");
        assert_eq!(exact_scratch, scratch_bytes);
        exact.config.max_total_memory_bytes = exact_baseline.saturating_add(exact_scratch);
        assert!(matches!(
            exact
                .construct_generated_function(&owner, args)
                .expect("generated compilation at exact scratch ceiling"),
            Value::BuiltinFunction(_)
        ));
        assert_eq!(exact.generated_code_audit.len(), 1);
        assert_eq!(exact.events.len(), 1);
        assert_eq!(
            exact.generated_code_audit[0].kind,
            GeneratedCodeEventKind::Constructed
        );
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes()
        );

        let parse_failure_fixture = || {
            let mut core = test_interpreter();
            core.ensure_module_record(&owner, &owner.header.source_label)
                .expect("retain generated parse-failure owner");
            core.ensure_generated_function_realm_globals()
                .expect("initialize generated parse-failure realm");
            core.write_reg(0, Value::str("const x;"))
                .expect("seed invalid generated source");
            core.sync_estimated_memory_bytes()
                .expect("generated parse-failure baseline");
            core
        };
        let mut parse_failure = parse_failure_fixture();
        let mut reference = parse_failure_fixture();
        let parse_failure_baseline = parse_failure.estimated_memory_bytes();
        assert_eq!(reference.estimated_memory_bytes(), parse_failure_baseline);
        let error = parse_failure
            .construct_generated_function(&owner, args)
            .expect_err("a const declaration without an initializer is a guest SyntaxError");
        assert!(
            matches!(error, InterpreterError::UncaughtException { .. }),
            "invalid generated source must transport its language error: {error:?}"
        );
        let Some(Value::Object(error_id)) = parse_failure.pending_exception.as_ref() else {
            panic!("invalid generated source must retain the guest SyntaxError");
        };
        assert_eq!(
            parse_failure.chain_data_property(*error_id, "name"),
            Some(&Value::str("SyntaxError"))
        );
        let Some(Value::Str(message)) = parse_failure.chain_data_property(*error_id, "message")
        else {
            panic!("generated SyntaxError must carry a diagnostic message");
        };
        assert!(!message.is_empty());
        // Error construction is legitimate retained growth. A direct error
        // from the identical precompile state isolates that growth from any
        // leaked compilation scratch or generated artifact.
        let expected_error = reference.throw_js_error("SyntaxError", message.to_string());
        assert_eq!(error, expected_error);
        assert_eq!(parse_failure.pending_exception_label, Label::Public);
        assert!(
            parse_failure
                .module_state
                .generated_function_stores
                .is_empty()
        );
        assert!(parse_failure.generated_code_audit.is_empty());
        assert!(parse_failure.events.is_empty());
        assert_eq!(parse_failure.generated_code_observability_bytes, 0);
        assert_eq!(parse_failure.json_parse_temporary_bytes, 0);
        assert_eq!(
            parse_failure.estimated_memory_bytes(),
            reference.estimated_memory_bytes(),
            "only the guest SyntaxError and its intrinsic prototypes may remain"
        );
        assert_eq!(
            parse_failure.estimated_memory_bytes(),
            parse_failure.recompute_estimated_memory_bytes()
        );
        assert_eq!(
            reference.estimated_memory_bytes(),
            reference.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_constructor_prototype_failure_retains_selection_label() {
        for (native_failure, classify_target) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let getter_instructions = if native_failure {
                vec![
                    Ir3Instruction::LoadUndefined { dst: 0 },
                    Ir3Instruction::LoadInt { dst: 1, value: 0 },
                    Ir3Instruction::GetProperty {
                        obj: 0,
                        key: 1,
                        dst: 0,
                    },
                    Ir3Instruction::Return { value: 0 },
                ]
            } else {
                vec![
                    Ir3Instruction::LoadInt { dst: 0, value: 73 },
                    Ir3Instruction::Throw { value: 0 },
                ]
            };
            let mut owner = test_module_with_functions(
                getter_instructions,
                vec![Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 2,
                    name: Some("throwing_constructor_prototype_getter".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            owner.header.source_label = "generated-constructor-throw-owner.mjs".to_string();
            let generated = test_module_with_functions(
                vec![
                    Ir3Instruction::LoadInt { dst: 0, value: 7 },
                    Ir3Instruction::Return { value: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("unreached_generated_constructor_body".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            let mut core = test_interpreter();
            core.ensure_module_record(&owner, &owner.header.source_label)
                .expect("retain constructor getter owner");
            let (builtin, _, _) =
                retain_generated_test_artifact(&mut core, &owner, generated, 0, "return 7;");
            let target = core
                .function_prototype_bind(
                    &owner,
                    Value::BuiltinFunction(builtin.clone()),
                    None,
                    RegRange { start: 0, count: 0 },
                )
                .expect("constructible bound newTarget");
            let backing = core
                .ensure_function_own_property_object(&owner, &target)
                .expect("newTarget property backing")
                .expect("bound function property storage");
            core.set_object_runtime_property(
                backing,
                RuntimePropertyKey::String(JsString::from("prototype")),
                Value::Accessor {
                    get: Some(Arc::new(Value::Function(0))),
                    set: None,
                },
            )
            .expect("install observable prototype getter");
            if !classify_target {
                core.join_object_mutation_label(backing, &Label::Secret)
                    .expect("classify getter selection");
            }
            core.sync_estimated_memory_bytes()
                .expect("getter failure fixture memory baseline");
            let error = core
                .construct_generated_function_artifact(
                    &owner,
                    &builtin,
                    RegRange { start: 0, count: 0 },
                    target,
                    if classify_target {
                        Label::Secret
                    } else {
                        Label::Public
                    },
                )
                .expect_err("prototype getter must fail before generated execution");
            assert!(
                matches!(error, InterpreterError::UncaughtException { .. })
                    || InterpreterCore::js_catchable_error_name(&error).is_some()
            );
            if core.pending_exception.is_some() {
                assert_eq!(core.pending_exception_label, Label::Secret);
            } else {
                assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
            }
            if !native_failure {
                assert_eq!(core.pending_exception, Some(Value::Int(73)));
            }
            assert_eq!(core.active_inline_callback_context_label, None);
            assert_eq!(core.active_generated_function_artifact, None);
            assert_eq!(core.module_reentrant_call_depth, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn generated_constructor_preserves_prototype_shape_label_and_accounting() {
        let mut owner = test_module_with_functions(Vec::new(), Vec::new());
        owner.header.source_label = "generated-constructor-label-owner.mjs".to_string();
        let generated = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("generated_constructor_label_body".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = test_interpreter();
        core.ensure_module_record(&owner, &owner.header.source_label)
            .expect("retain generated constructor owner");
        let (builtin, _, _) =
            retain_generated_test_artifact(&mut core, &owner, generated, 0, "return 7;");
        let target = Value::BuiltinFunction(builtin.clone());
        let prototype = core
            .ensure_generated_function_prototype(&builtin)
            .expect("generated constructor prototype");
        let backing = core
            .ensure_function_own_property_object(&owner, &target)
            .expect("generated constructor property backing")
            .expect("generated functions own property storage");
        core.join_object_mutation_label(backing, &Label::Secret)
            .expect("classify the prototype descriptor's shape");
        core.sync_estimated_memory_bytes()
            .expect("constructor fixture memory baseline");
        let caller_grants = core.config.granted_capabilities.clone();

        let (instance, label) = core
            .construct_generated_function_artifact(
                &owner,
                &builtin,
                RegRange { start: 0, count: 0 },
                target,
                Label::Public,
            )
            .expect("generated constructor returns its allocated instance");
        let Value::Object(instance) = instance else {
            panic!("primitive return must preserve the constructor instance");
        };
        assert_eq!(core.heap[instance.0 as usize].prototype, Some(prototype));
        assert_eq!(label, Label::Secret);
        assert_eq!(core.active_inline_callback_context_label, None);
        assert_eq!(core.active_generated_function_artifact, None);
        assert_eq!(core.module_reentrant_call_depth, 0);
        assert_eq!(core.config.granted_capabilities, caller_grants);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn native_namespace_callable_keeps_secret_capture_labels_at_invocation() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadName {
                    dst: 0,
                    name_pool_index: 0,
                    allow_missing: false,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("native_export_secret_capture".into()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        owner.header.source_label = "native-export-owner.mjs".into();
        owner.constant_pool.push("captured".into());
        let caller = test_module_with_functions(Vec::new(), Vec::new());
        let mut core = test_interpreter();
        core.ensure_module_record(&owner, &owner.header.source_label)
            .unwrap();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: vec![ScopeFrame::from_bindings(BTreeMap::from([(
                "captured".into(),
                ScopeBinding::with_labeled_state(
                    BindingKind::Const,
                    Value::Int(37),
                    Label::Secret,
                    true,
                ),
            )]))],
        });
        core.closure_module_origins
            .insert(0, owner.header.source_label.clone());
        let Value::Object(object) = core.querystring_core_module().unwrap() else {
            panic!("querystring");
        };
        core.set_object_property(object, "stringify".into(), Value::Closure(0))
            .unwrap();
        let record = NativeBuiltinModule::Querystring.record("captured:closure-querystring");
        let source = ResolutionOutcome {
            module: ResolvedModule {
                request_specifier: "querystring".into(),
                canonical_specifier: record.id.clone(),
                content_hash: record.canonical_hash(),
                record,
                probe_sequence: Vec::new(),
            },
            event: crate::module_resolver::ResolutionEvent {
                trace_id: "capture".into(),
                decision_id: "capture".into(),
                policy_id: "capture".into(),
                component: "module_resolver".into(),
                event: "resolved".into(),
                outcome: "allowed".into(),
                error_code: String::new(),
            },
        };
        let source: SharedResolutionOutcome = source.into();
        let Value::Object(namespace) = core
            .load_native_builtin_namespace(
                &caller,
                &source,
                NativeBuiltinModule::Querystring,
                Some(&Label::Internal),
            )
            .expect("a public callable reference does not evaluate its captured code")
        else {
            panic!("namespace");
        };
        for holder in [namespace, object] {
            let function = core.prototype_chain_get(holder, "stringify").unwrap();
            core.write_reg(0, function).unwrap();
            core.write_reg(1, Value::Undefined).unwrap();
            let result = core
                .dispatch_builtin_hostcall(
                    "builtin:FunctionPrototypeCall",
                    RegRange { start: 0, count: 2 },
                    Some(&caller),
                )
                .expect("retained owner executes the real captured function");
            assert_eq!(result, Value::Int(37));
            assert_eq!(
                core.take_pending_hostcall_result_label(),
                Some(Label::Secret),
                "neither named nor default native exports may lower the invocation result label"
            );
        }
    }

    #[test]
    fn native_strict_alias_retains_selected_and_cached_reference_labels() {
        let caller = test_module_with_functions(Vec::new(), Vec::new());
        for (cached, label_shape) in [false, true]
            .into_iter()
            .flat_map(|cached| [(cached, false), (cached, true)])
        {
            let mut core = test_interpreter();
            let assertion = core
                .source_builtin_module(&caller, NativeBuiltinModule::Assert, None)
                .expect("execute the real assert factory");
            let holder = if cached {
                core.source_builtin_module(&caller, NativeBuiltinModule::AssertStrict, None)
                    .expect("initialize strict alias before classifying its cached reference");
                core.builtin_prototypes["\0franken-engine/native-assert"]
            } else {
                core.function_own_property_object(&caller, &assertion)
                    .unwrap()
                    .expect("assert property storage")
            };
            let strict_key = RuntimePropertyKey::String(JsString::from("strict"));
            if label_shape {
                core.join_object_mutation_label(holder, &Label::Secret)
                    .unwrap();
            } else {
                core.set_own_runtime_property_label(holder, &strict_key, &Label::Secret)
                    .unwrap();
            }
            core.clear_pending_hostcall_result_label();
            core.source_builtin_module(&caller, NativeBuiltinModule::AssertStrict, None)
                .expect("unbounded CommonJS selection retains property and shape provenance");
            assert_eq!(
                core.take_pending_hostcall_result_label(),
                Some(Label::Secret),
                "cached={cached}, shape={label_shape}: first CJS read"
            );
            core.clear_pending_hostcall_result_label();
            let record = NativeBuiltinModule::AssertStrict.record("captured:classified-strict");
            let source = ResolutionOutcome {
                module: ResolvedModule {
                    request_specifier: "assert/strict".into(),
                    canonical_specifier: record.id.clone(),
                    content_hash: record.canonical_hash(),
                    record,
                    probe_sequence: Vec::new(),
                },
                event: crate::module_resolver::ResolutionEvent {
                    trace_id: "strict-reference-label".into(),
                    decision_id: "strict-reference-label".into(),
                    policy_id: "strict-reference-label".into(),
                    component: "module_resolver".into(),
                    event: "resolved".into(),
                    outcome: "allowed".into(),
                    error_code: String::new(),
                },
            };
            let source: SharedResolutionOutcome = source.into();
            assert!(matches!(
                core.load_native_builtin_namespace(
                    &caller,
                    &source,
                    NativeBuiltinModule::AssertStrict,
                    Some(&Label::Internal),
                ),
                Err(InterpreterError::ModuleLoweringFailed { .. })
            ));
            core.clear_pending_hostcall_result_label();
            let Value::Object(namespace) = core
                .load_native_builtin_namespace(
                    &caller,
                    &source,
                    NativeBuiltinModule::AssertStrict,
                    None,
                )
                .expect("unbounded namespace retains selection provenance")
            else {
                panic!("strict namespace");
            };
            for name in ["default", "strictEqual"] {
                assert_eq!(
                    core.runtime_property_label(
                        namespace,
                        &RuntimePropertyKey::String(JsString::from(name)),
                    ),
                    Label::Secret,
                    "cached={cached}, shape={label_shape}: {name} must retain the classified reference"
                );
            }
            core.clear_pending_hostcall_result_label();
            core.source_builtin_module(&caller, NativeBuiltinModule::AssertStrict, None)
                .expect("cached CommonJS alias");
            assert_eq!(
                core.take_pending_hostcall_result_label(),
                Some(Label::Secret)
            );
            assert!(core.active_inline_callback_context_label.is_none());
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn native_timer_promises_getter_retains_private_reference_labels() {
        let caller = test_module_with_functions(Vec::new(), Vec::new());
        for cached in [false, true] {
            let mut core = test_interpreter();
            core.config.granted_capabilities.extend([
                RuntimeCapability::Builtin,
                RuntimeCapability::ModuleLoad,
                RuntimeCapability::Timer,
            ]);
            let promises = core
                .source_builtin_module(&caller, NativeBuiltinModule::TimersPromises, None)
                .expect("execute the actual timer promises factory");
            let Value::Object(promises_object) = promises else {
                panic!("timer promises exports an object");
            };
            let Value::Object(timers) = core.timers_core_module(&caller).unwrap() else {
                panic!("timers exports an object");
            };
            assert!(!core.event_loop.has_pending_work());
            assert!(core.next_tick_queue.is_empty());
            core.clear_pending_hostcall_result_label();
            assert_eq!(
                core.native_builtin_state_label(&caller, timers).unwrap(),
                Label::Internal,
                "the exact bound getter is safe to inspect without running it"
            );
            let record = NativeBuiltinModule::Timers.record("captured:timer-reference-label");
            let source = ResolutionOutcome {
                module: ResolvedModule {
                    request_specifier: "node:timers".into(),
                    canonical_specifier: record.id.clone(),
                    content_hash: record.canonical_hash(),
                    record,
                    probe_sequence: Vec::new(),
                },
                event: crate::module_resolver::ResolutionEvent {
                    trace_id: "timer-reference-label".into(),
                    decision_id: "timer-reference-label".into(),
                    policy_id: "timer-reference-label".into(),
                    component: "module_resolver".into(),
                    event: "resolved".into(),
                    outcome: "allowed".into(),
                    error_code: String::new(),
                },
            };
            let source: SharedResolutionOutcome = source.into();
            if cached {
                core.load_native_builtin_namespace(
                    &caller,
                    &source,
                    NativeBuiltinModule::Timers,
                    Some(&Label::Internal),
                )
                .expect("initialize the public namespace before classifying its carrier");
            }
            let carrier = core.builtin_prototypes["\0franken-engine/native-timers/promises"];
            let exports = RuntimePropertyKey::String(JsString::from("exports"));
            core.set_own_runtime_property_label(carrier, &exports, &Label::Secret)
                .unwrap();
            core.clear_pending_hostcall_result_label();
            assert_eq!(
                core.native_builtin_state_label(&caller, promises_object)
                    .unwrap(),
                Label::Internal,
                "only the private reference is classified, not the returned object's properties"
            );
            assert_eq!(
                core.native_builtin_state_label(&caller, timers).unwrap(),
                Label::Secret,
                "the bound carrier must participate in import admission"
            );
            assert!(matches!(
                core.load_native_builtin_namespace(
                    &caller,
                    &source,
                    NativeBuiltinModule::Timers,
                    Some(&Label::Internal),
                ),
                Err(InterpreterError::ModuleLoweringFailed { .. })
            ));
            core.clear_pending_hostcall_result_label();
            let Value::Object(namespace) = core
                .load_native_builtin_namespace(&caller, &source, NativeBuiltinModule::Timers, None)
                .expect("unbounded namespace still exposes the same module")
            else {
                panic!("timers namespace");
            };
            assert_eq!(
                core.native_builtin_state_label(&caller, namespace).unwrap(),
                Label::Secret,
                "cached={cached}: namespace defaults must retain the live carrier edge"
            );
            core.clear_pending_hostcall_result_label();
            assert_eq!(
                core.iterator_protocol_property(
                    Some(&caller),
                    timers,
                    &RuntimePropertyKey::String(JsString::from("promises")),
                    Value::Object(timers),
                )
                .expect("the native getter reads its private carrier"),
                Value::Object(promises_object)
            );
            assert_eq!(
                core.take_pending_hostcall_result_label(),
                Some(Label::Secret),
                "cached={cached}: getter invocation must retain the reference label"
            );
            assert_eq!(
                core.source_builtin_module(&caller, NativeBuiltinModule::TimersPromises, None)
                    .expect("the direct alias uses the same private carrier"),
                Value::Object(promises_object)
            );
            assert_eq!(
                core.take_pending_hostcall_result_label(),
                Some(Label::Secret)
            );
            assert!(!core.event_loop.has_pending_work());
            assert!(core.next_tick_queue.is_empty());
            assert!(core.active_inline_callback_context_label.is_none());
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn native_timer_namespace_does_not_execute_replacement_promises_getter() {
        let caller = test_module_with_functions(Vec::new(), Vec::new());
        let mut core = test_interpreter();
        core.config.granted_capabilities.extend([
            RuntimeCapability::Builtin,
            RuntimeCapability::ModuleLoad,
            RuntimeCapability::Timer,
        ]);
        let Value::Object(timers) = core.timers_core_module(&caller).unwrap() else {
            panic!("timers exports an object");
        };
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadName {
                    dst: 0,
                    name_pool_index: 0,
                    allow_missing: false,
                },
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 1,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 1 },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 2,
                },
                Ir3Instruction::Return { value: 2 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 3,
                name: Some("get".into()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        owner.header.source_label = "guest-timer-getter.mjs".into();
        owner.constant_pool = vec!["probe".into(), "hits".into()];
        core.ensure_module_record(&owner, &owner.header.source_label)
            .unwrap();
        let probe = seed_object(&mut core, &[("hits", Value::Int(0))]);
        let closure = u32::try_from(core.closures.len()).unwrap();
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: vec![ScopeFrame::from_bindings(BTreeMap::from([(
                "probe".into(),
                ScopeBinding::with_labeled_state(
                    BindingKind::Const,
                    Value::Object(probe),
                    Label::Public,
                    true,
                ),
            )]))],
        });
        core.closure_module_origins
            .insert(closure, owner.header.source_label.clone());
        let key = RuntimePropertyKey::String(JsString::from("promises"));
        core.set_object_runtime_property(
            timers,
            key.clone(),
            Value::Accessor {
                get: Some(Arc::new(Value::Closure(closure))),
                set: None,
            },
        )
        .unwrap();
        core.sync_estimated_memory_bytes().unwrap();
        core.clear_pending_hostcall_result_label();
        assert_eq!(
            core.native_builtin_state_label(&caller, timers).unwrap(),
            Label::TopSecret,
            "a guest function named get is not the authenticated bound getter"
        );
        assert_eq!(
            core.prototype_chain_get(probe, "hits").unwrap(),
            Value::Int(0),
            "state admission must not execute the replacement getter"
        );
        assert_eq!(
            core.iterator_protocol_property(Some(&caller), timers, &key, Value::Object(timers))
                .expect("an ordinary later property read runs the guest getter"),
            Value::Int(1)
        );
        assert_eq!(
            core.prototype_chain_get(probe, "hits").unwrap(),
            Value::Int(1),
            "the refusal check must use an actually executable getter"
        );
        core.clear_pending_hostcall_result_label();
        assert!(!core.event_loop.has_pending_work());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn native_stream_accessor_admission_keeps_origins_and_nested_labels() {
        let stack_bytes = interpreter_execution_stack_bytes(
            test_config().max_call_depth.min(MAX_NATIVE_RUN_LOOP_DEPTH),
        )
        .expect("production native execution stack");
        std::thread::Builder::new()
            .name("native-stream-accessor-regression".into())
            .stack_size(stack_bytes)
            .spawn(|| {
                const STREAM_FACTORY: &str = "\0franken-engine/native-stream";
                let caller = test_module_with_functions(Vec::new(), Vec::new());
                let mut core = test_interpreter();
                core.config.instruction_budget = DEFAULT_V8_BUDGET;
                core.config
                    .granted_capabilities
                    .extend([RuntimeCapability::ModuleLoad, RuntimeCapability::Timer]);
                let stream = core
                    .source_builtin_module(&caller, NativeBuiltinModule::Stream, None)
                    .expect("execute the authenticated Stream factory");
                let exports = core
                    .function_own_property_object(&caller, &stream)
                    .unwrap()
                    .expect("Stream constructor property storage");
                let readable = core.prototype_chain_get(exports, "Readable").unwrap();
                let Value::Object(prototype) = core
                    .get_v(
                        &caller,
                        &readable,
                        &RuntimePropertyKey::String(JsString::from("prototype")),
                    )
                    .unwrap()
                else {
                    panic!("Readable.prototype");
                };
                let closed = RuntimePropertyKey::String(JsString::from("closed"));
                let Some(Value::Accessor {
                    get: Some(getter), ..
                }) = core.heap[prototype.0 as usize].own_runtime_property_value(&closed)
                else {
                    panic!("the actual deferred Readable.closed getter");
                };
                let accessor_identity = match getter.as_ref() {
                    Value::Closure(id) => {
                        let origin = core.closure_module_origins.get(id);
                        let record = origin.and_then(|origin| core.module_state.modules.get(origin));
                        let function_index = core.closures.get(*id as usize)
                            .map(|closure| closure.function_index);
                        let program = record.and_then(|record| record.compiled_module.as_ref());
                        format!(
                            "origin={origin:?}, record={:?}, code={:?}, source={:?}",
                            record.map(|record| (&record.status, &record.resolved_source_hash)),
                            program.zip(function_index).and_then(|(program, index)| program.function_table.get(index as usize)),
                            program.zip(function_index).and_then(|(program, index)| program.function_sources.get(&index))
                                .map(|source| source.as_str().chars().take(160).collect::<String>()),
                        )
                    }
                    other => format!("non-closure getter: {other:?}"),
                };
                assert!(
                    core.is_deferred_native_factory_accessor(getter.as_ref(), false),
                    "the canonical getter must have authenticated factory identity: {accessor_identity}"
                );
                assert_eq!(
                    core.native_builtin_state_label(&caller, exports).unwrap(),
                    Label::Internal,
                    "canonical receiver accessors are admitted without executing them"
                );
                core.set_own_runtime_property_label(prototype, &closed, &Label::Secret)
                    .unwrap();
                assert_eq!(
                    core.native_builtin_state_label(&caller, exports).unwrap(),
                    Label::Secret,
                    "admitting immutable getter code must retain its descriptor label"
                );

                // The same compiled factory also contains the lazy Web module.
                // Its class getter has identical diagnostic name and arity,
                // but reads a captured WeakMap and returns a Promise. It must
                // stay opaque. This test-only closure is never invoked.
                let web_function_index = {
                    let program = core.module_state.modules[STREAM_FACTORY]
                        .compiled_module
                        .as_ref()
                        .expect("retained Stream program");
                    program
                        .function_table
                        .iter()
                        .enumerate()
                        .find_map(|(index, code)| {
                            let index = u32::try_from(index).expect("factory function index");
                            (code.name.as_deref() == Some("closed")
                                && code.arity == 0
                                && program.function_sources.get(&index).is_some_and(|source| {
                                    source.as_str().starts_with("get closed(")
                                }))
                            .then_some(index)
                        })
                        .expect("same-program Web writer closed getter")
                };
                let web_id = u32::try_from(core.closures.len()).unwrap();
                core.closures.push(ClosureValue {
                    function_index: web_function_index,
                    captured_env: Vec::new(),
                });
                core.closure_module_origins
                    .insert(web_id, STREAM_FACTORY.to_string());
                core.sync_estimated_memory_bytes().unwrap();
                let web_getter = Value::Closure(web_id);
                assert!(
                    !core.is_deferred_native_factory_accessor(&web_getter, false),
                    "factory identity, name and arity alone do not authenticate Web accessors"
                );
                core.set_object_runtime_property(
                    prototype,
                    closed.clone(),
                    Value::Accessor {
                        get: Some(Arc::new(web_getter)),
                        set: None,
                    },
                )
                .unwrap();
                assert_eq!(
                    core.native_builtin_state_label(&caller, exports).unwrap(),
                    Label::TopSecret,
                    "a same-program but unaudited accessor keeps the namespace opaque"
                );

                // A guest method has both an allowed immutable code name and
                // the same source-prefix form. Its separate origin still
                // prevents it from acquiring native accessor authority.
                let mut guest = test_module_with_functions(
                    vec![
                        Ir3Instruction::LoadInt { dst: 0, value: 7 },
                        Ir3Instruction::Return { value: 0 },
                    ],
                    vec![Ir3FunctionDesc {
                        entry: 0,
                        arity: 0,
                        frame_size: 1,
                        name: Some("closed".into()),
                        is_generator: false,
                        rest_param_index: None,
                    }],
                );
                guest.header.source_label = "guest-stream-getter.js".into();
                guest
                    .function_sources
                    .insert(0, "closed() { return 7; }".into());
                core.ensure_module_record(&guest, &guest.header.source_label)
                    .unwrap();
                core.module_state
                    .modules
                    .get_mut(&guest.header.source_label)
                    .unwrap()
                    .status = ModuleRuntimeStatus::Evaluated;
                let guest_id = u32::try_from(core.closures.len()).unwrap();
                core.closures.push(ClosureValue {
                    function_index: 0,
                    captured_env: Vec::new(),
                });
                core.closure_module_origins
                    .insert(guest_id, guest.header.source_label.clone());
                core.sync_estimated_memory_bytes().unwrap();
                let guest_getter = Value::Closure(guest_id);
                assert!(!core.is_deferred_native_factory_accessor(&guest_getter, false));
                core.set_object_runtime_property(
                    prototype,
                    closed,
                    Value::Accessor {
                        get: Some(Arc::new(guest_getter)),
                        set: None,
                    },
                )
                .unwrap();
                assert_eq!(
                    core.native_builtin_state_label(&caller, exports).unwrap(),
                    Label::TopSecret,
                    "guest replacement methods do not inherit the native property's admission"
                );
            })
            .expect("spawn native accessor regression")
            .join()
            .expect("native accessor regression");
    }

    #[test]
    fn native_string_decoder_intrinsic_shares_carrier_and_observes_reference_labels() {
        let stack_bytes = interpreter_execution_stack_bytes(
            test_config().max_call_depth.min(MAX_NATIVE_RUN_LOOP_DEPTH),
        )
        .expect("production native execution stack");
        std::thread::Builder::new()
            .name("native-decoder-carrier-regression".into())
            .stack_size(stack_bytes)
            .spawn(|| {
                const INTRINSIC: &str = "builtin:NativeStringDecoderModule";
                let caller = test_module_with_functions(Vec::new(), Vec::new());
                for intrinsic_first in [false, true] {
                    for classify_shape in [false, true] {
                        let mut core = test_interpreter();
                        core.config
                            .granted_capabilities
                            .insert(RuntimeCapability::ModuleLoad);
                        let first = if intrinsic_first {
                            core.dispatch_builtin_hostcall(
                                INTRINSIC,
                                RegRange { start: 0, count: 0 },
                                Some(&caller),
                            )
                        } else {
                            core.source_builtin_module(
                                &caller,
                                NativeBuiltinModule::StringDecoder,
                                None,
                            )
                        }
                        .expect("first canonical decoder load");
                        let second = if intrinsic_first {
                            core.source_builtin_module(
                                &caller,
                                NativeBuiltinModule::StringDecoder,
                                None,
                            )
                        } else {
                            core.dispatch_builtin_hostcall(
                                INTRINSIC,
                                RegRange { start: 0, count: 0 },
                                Some(&caller),
                            )
                        }
                        .expect("second canonical decoder load");
                        assert_eq!(
                            first, second,
                            "the private dependency and public provider share one decoder class"
                        );
                        let carrier =
                            core.builtin_prototypes["\0franken-engine/native-string_decoder"];
                        if classify_shape {
                            core.join_object_mutation_label(carrier, &Label::Secret)
                                .unwrap();
                        } else {
                            core.set_own_runtime_property_label(
                                carrier,
                                &RuntimePropertyKey::String(JsString::from("exports")),
                                &Label::Secret,
                            )
                            .unwrap();
                        }
                        core.clear_pending_hostcall_result_label();
                        assert_eq!(
                            core.dispatch_builtin_hostcall(
                                INTRINSIC,
                                RegRange { start: 0, count: 0 },
                                Some(&caller),
                            )
                            .expect("classified cached reference remains selectable"),
                            first
                        );
                        assert_eq!(
                            core.take_pending_hostcall_result_label(),
                            Some(Label::Secret),
                            "intrinsic_first={intrinsic_first}, shape={classify_shape}"
                        );

                        // Exercise actual HostCall publication too: zero
                        // operands do not erase the private carrier's label.
                        let invocation = test_module_with_functions(
                            vec![
                                Ir3Instruction::HostCall {
                                    capability: CapabilityTag(INTRINSIC.into()),
                                    args: RegRange { start: 0, count: 0 },
                                    dst: 0,
                                },
                                Ir3Instruction::Halt,
                            ],
                            Vec::new(),
                        );
                        core.ip = 0;
                        core.write_reg_with_label(0, Value::Undefined, Label::Public)
                            .unwrap();
                        assert_eq!(core.run_loop(&invocation), Err(InterpreterError::Halted));
                        assert_eq!(core.read_reg(0).unwrap(), first);
                        assert_eq!(core.get_register_label(0), Ok(&Label::Secret));
                        assert!(core.active_inline_callback_context_label.is_none());
                        assert_eq!(core.json_parse_temporary_bytes, 0);
                        assert_eq!(
                            core.estimated_memory_bytes(),
                            core.recompute_estimated_memory_bytes()
                        );
                    }
                }
            })
            .expect("spawn decoder carrier regression")
            .join()
            .expect("decoder carrier regression");
    }

    #[test]
    fn native_namespace_constructor_prototype_state_is_observable_without_materialization() {
        let caller = test_module_with_functions(
            vec![Ir3Instruction::Return { value: 0 }],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("Constructor".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = test_interpreter();
        let constructor = Value::Function(0);
        let exports = seed_object(&mut core, &[("Constructor", constructor.clone())]);
        let heap_before = core.heap.live_len();
        let registry_before = core.function_prototypes.len();
        assert_eq!(
            core.native_builtin_state_label(&caller, exports).unwrap(),
            Label::Internal
        );
        assert_eq!(core.heap.live_len(), heap_before);
        assert_eq!(core.function_prototypes.len(), registry_before);

        let prototype = core.ensure_function_prototype(&caller, 0).unwrap();
        core.set_object_property(prototype, "marker".to_string(), Value::Int(1))
            .unwrap();
        core.set_own_runtime_property_label(
            prototype,
            &RuntimePropertyKey::String(JsString::from("marker")),
            &Label::Secret,
        )
        .unwrap();
        assert_eq!(
            core.native_builtin_state_label(&caller, exports).unwrap(),
            Label::Secret
        );

        let replacement = core.alloc_object_with_prototype(None).unwrap();
        core.set_constructor_prototype_override(
            &caller,
            &constructor,
            Value::Object(replacement),
            Label::Public,
        )
        .unwrap();
        assert_eq!(
            core.native_builtin_state_label(&caller, exports).unwrap(),
            Label::Internal,
            "a replaced prototype must not retain the old object's label"
        );
        core.set_constructor_prototype_override(
            &caller,
            &constructor,
            Value::Object(replacement),
            Label::Secret,
        )
        .unwrap();
        assert_eq!(
            core.native_builtin_state_label(&caller, exports).unwrap(),
            Label::Secret,
            "the replacement property's own label must remain visible"
        );

        let handler = seed_object(&mut core, &[]);
        let proxy = core.create_proxy_object(replacement, handler).unwrap();
        core.set_constructor_prototype_override(
            &caller,
            &constructor,
            Value::Object(proxy),
            Label::Public,
        )
        .unwrap();
        assert_eq!(
            core.native_builtin_state_label(&caller, exports).unwrap(),
            Label::TopSecret,
            "an opaque replacement remains fail-high"
        );

        // The private replacement carrier must not create a hidden edge to
        // Object.prototype when all observable prototype links are null.
        core.store_prototype_link(exports, None);
        assert!(
            core.set_function_value_prototype(Some(&caller), &constructor, &Value::Null)
                .unwrap()
        );
        core.set_constructor_prototype_override(&caller, &constructor, Value::Null, Label::Public)
            .unwrap();
        let object_prototype = core.ensure_builtin_prototype("Object").unwrap();
        core.set_object_property(object_prototype, "unrelated".to_string(), Value::Int(1))
            .unwrap();
        core.set_own_runtime_property_label(
            object_prototype,
            &RuntimePropertyKey::String(JsString::from("unrelated")),
            &Label::Secret,
        )
        .unwrap();
        assert_eq!(
            core.native_builtin_state_label(&caller, exports).unwrap(),
            Label::Internal,
            "a private carrier's prototype is not observable namespace state"
        );
        assert!(core.console_output().is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn native_factory_deferred_accessors_retain_nested_labels() {
        let caller = test_module_with_functions(Vec::new(), Vec::new());
        for native in [
            NativeBuiltinModule::Util,
            NativeBuiltinModule::StringDecoder,
        ] {
            let mut core = test_interpreter();
            let Value::Object(exports) = core
                .source_builtin_module(&caller, native, None)
                .expect("execute the actual authenticated native factory")
            else {
                panic!("these providers export objects");
            };
            let (nested, property) = if native == NativeBuiltinModule::Util {
                let inspect = core.prototype_chain_get(exports, "inspect").unwrap();
                let Value::Object(colors) = core
                    .get_v(
                        &caller,
                        &inspect,
                        &RuntimePropertyKey::String(JsString::from("colors")),
                    )
                    .unwrap()
                else {
                    panic!("util.inspect.colors");
                };
                (colors, "gray")
            } else {
                let decoder = core.prototype_chain_get(exports, "StringDecoder").unwrap();
                let Value::Object(prototype) = core
                    .get_v(
                        &caller,
                        &decoder,
                        &RuntimePropertyKey::String(JsString::from("prototype")),
                    )
                    .unwrap()
                else {
                    panic!("StringDecoder.prototype");
                };
                (prototype, "lastNeed")
            };
            assert_eq!(
                core.native_builtin_state_label(&caller, exports).unwrap(),
                Label::Internal,
                "canonical deferred accessors do not execute at namespace creation"
            );
            core.set_own_runtime_property_label(
                nested,
                &RuntimePropertyKey::String(JsString::from(property)),
                &Label::Secret,
            )
            .unwrap();
            assert_eq!(
                core.native_builtin_state_label(&caller, exports).unwrap(),
                Label::Secret,
                "admitting exact accessor code must not erase its live state labels"
            );
            if native == NativeBuiltinModule::Util {
                let _ = core.take_pending_hostcall_result_label();
                core.get_v(
                    &caller,
                    &Value::Object(nested),
                    &RuntimePropertyKey::String(JsString::from("grey")),
                )
                .expect("the canonical alias getter remains callable later");
                assert_eq!(
                    core.take_pending_hostcall_result_label(),
                    Some(Label::Secret)
                );
            }
        }
    }

    #[test]
    fn module_namespace_prototype_is_null_without_changing_ordinary_objects() {
        let module = test_module_with_functions(Vec::new(), Vec::new());
        let mut core = test_interpreter();
        let ordinary = core.alloc_object_with_prototype(None).unwrap();
        let ordinary_prototype = core
            .object_get_prototype(Some(&module), ordinary, 0)
            .unwrap();
        assert!(matches!(ordinary_prototype, Value::Object(_)));

        let namespace = core
            .ensure_module_record(&module, "namespace-prototype.mjs")
            .unwrap();
        assert_eq!(
            core.object_get_prototype(Some(&module), namespace, 0),
            Ok(Value::Null)
        );
        assert_eq!(
            core.ensure_module_record(&module, "namespace-prototype.mjs"),
            Ok(namespace)
        );
        let handler = seed_object(&mut core, &[]);
        let proxy = core.create_proxy_object(namespace, handler).unwrap();
        assert_eq!(
            core.object_get_prototype(Some(&module), proxy, 0),
            Ok(Value::Null)
        );
        assert_eq!(
            core.object_get_prototype(Some(&module), ordinary, 0),
            Ok(ordinary_prototype)
        );
    }

    #[test]
    fn native_namespace_set_refuses_distinct_and_inherited_receivers() {
        let module = test_module_with_functions(Vec::new(), Vec::new());
        let mut core = test_interpreter();
        let record = NativeBuiltinModule::Path.record("captured:namespace-set-receivers");
        let source = ResolutionOutcome {
            module: ResolvedModule {
                request_specifier: "node:path".into(),
                canonical_specifier: record.id.clone(),
                content_hash: record.canonical_hash(),
                record,
                probe_sequence: Vec::new(),
            },
            event: crate::module_resolver::ResolutionEvent {
                trace_id: "namespace-set-receivers".into(),
                decision_id: "namespace-set-receivers".into(),
                policy_id: "namespace-set-receivers".into(),
                component: "module_resolver".into(),
                event: "resolved".into(),
                outcome: "allowed".into(),
                error_code: String::new(),
            },
        };
        let source: SharedResolutionOutcome = source.into();
        let Value::Object(namespace) = core
            .load_native_builtin_namespace(&module, &source, NativeBuiltinModule::Path, None)
            .expect("load the real native Path namespace")
        else {
            panic!("native Path must return a namespace");
        };
        let original = core.prototype_chain_get(namespace, "join").unwrap();
        let receiver = core.alloc_object_with_prototype(None).unwrap();
        let inherited = core.alloc_object_with_prototype(Some(namespace)).unwrap();
        let handler = seed_object(&mut core, &[]);
        let proxy = core.create_proxy_object(namespace, handler).unwrap();
        let export = RuntimePropertyKey::String(JsString::from("join"));
        let missing = RuntimePropertyKey::String(JsString::from("missing"));

        // An ordinary target must still write its own public properties. A
        // transparent Proxy used only as receiver may still define the same
        // value on a namespace, through [[DefineOwnProperty]] rather than [[Set]].
        let ordinary = core.alloc_object_with_prototype(None).unwrap();
        assert_eq!(
            core.proxy_aware_set_runtime_property(
                Some(&module),
                ordinary,
                &missing,
                Value::Int(7),
                Value::Object(ordinary),
                0,
            ),
            Ok(true)
        );
        assert_eq!(
            core.prototype_chain_get(ordinary, "missing"),
            Ok(Value::Int(7))
        );
        assert_eq!(
            core.proxy_aware_set_runtime_property(
                Some(&module),
                ordinary,
                &export,
                original.clone(),
                Value::Object(proxy),
                0,
            ),
            Ok(true)
        );

        // ECMA-262 10.4.6.9 never consults Receiver: an export, a missing string
        // and a missing Symbol all refuse, even for another ordinary object.
        // Node 26 agrees; Node 22/24 permit distinct/inherited receivers here.
        let keys = [
            export.clone(),
            missing.clone(),
            RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id()),
        ];
        let receivers = [
            Value::Object(namespace),
            Value::Object(receiver),
            Value::Int(8),
            Value::Object(proxy),
        ];
        let mut observed = Vec::new();
        for key in &keys {
            for receiver in &receivers {
                observed.push(core.proxy_aware_set_runtime_property(
                    Some(&module),
                    namespace,
                    key,
                    original.clone(),
                    receiver.clone(),
                    0,
                ));
            }
        }
        for target in [inherited, proxy] {
            for key in [&export, &missing] {
                observed.push(core.proxy_aware_set_runtime_property(
                    Some(&module),
                    target,
                    key,
                    original.clone(),
                    Value::Object(target),
                    0,
                ));
            }
        }
        assert_eq!(observed, vec![Ok(false); 16]);
        assert_eq!(
            core.prototype_chain_get(receiver, "join"),
            Ok(Value::Undefined)
        );
        assert_eq!(
            core.prototype_chain_get(receiver, "missing"),
            Ok(Value::Undefined)
        );
        assert_eq!(
            core.prototype_chain_get(inherited, "join"),
            Ok(original.clone())
        );
        assert_eq!(core.prototype_chain_get(namespace, "join"), Ok(original));
    }

    #[test]
    fn native_perf_hooks_retains_classified_global_reference_labels() {
        for object_reference in [false, true] {
            for operation in [
                "direct",
                "proxy_same",
                "proxy_changed",
                "assign",
                "define_same",
                "define_changed",
                "proxy_define_same",
                "proxy_define_changed",
                "receiver_same",
                "receiver_changed",
            ] {
                let module = test_module_with_functions(Vec::new(), Vec::new());
                let mut core = test_interpreter();
                let performance = if object_reference {
                    Value::Object(seed_object(&mut core, &[("public", Value::Int(73))]))
                } else {
                    Value::Int(73)
                };
                core.scope_chain.current_mut().unwrap().insert_binding(
                    "performance".to_string(),
                    ScopeBinding::with_labeled_state(
                        BindingKind::Var,
                        performance.clone(),
                        Label::Secret,
                        true,
                    ),
                );
                core.sync_estimated_memory_bytes().unwrap();
                let record = NativeBuiltinModule::PerfHooks.record("captured:classified-perf");
                let source = ResolutionOutcome {
                    module: ResolvedModule {
                        request_specifier: "perf_hooks".into(),
                        canonical_specifier: record.id.clone(),
                        content_hash: record.canonical_hash(),
                        record,
                        probe_sequence: Vec::new(),
                    },
                    event: crate::module_resolver::ResolutionEvent {
                        trace_id: "native-perf-label".into(),
                        decision_id: "native-perf-label".into(),
                        policy_id: "native-perf-label".into(),
                        component: "module_resolver".into(),
                        event: "resolved".into(),
                        outcome: "allowed".into(),
                        error_code: String::new(),
                    },
                };
                let source: SharedResolutionOutcome = source.into();
                let Value::Object(namespace) = core
                    .load_native_builtin_namespace(
                        &module,
                        &source,
                        NativeBuiltinModule::PerfHooks,
                        None,
                    )
                    .expect("unbounded imports preserve the classified reference")
                else {
                    panic!("namespace");
                };
                assert_eq!(
                    core.object_get_prototype(Some(&module), namespace, 0),
                    Ok(Value::Null)
                );
                let Value::Object(default) = core.perf_hooks_core_module().unwrap() else {
                    panic!("perf_hooks");
                };
                let key = RuntimePropertyKey::String(JsString::from("performance"));
                for holder in [namespace, default] {
                    assert_eq!(
                        core.prototype_chain_get(holder, "performance").unwrap(),
                        performance
                    );
                    assert_eq!(core.runtime_property_label(holder, &key), Label::Secret);
                }
                // Public guesses must neither relabel an unchanged export nor
                // expose its classified value through a SameValue success probe.
                assert_eq!(core.json_parse_context_label().unwrap(), Label::Public);
                let target = if operation.starts_with("receiver_") {
                    seed_object(&mut core, &[])
                } else if operation.starts_with("proxy") {
                    let handler = seed_object(&mut core, &[]);
                    core.create_proxy_object(namespace, handler).unwrap()
                } else {
                    namespace
                };
                let proposed = if operation.ends_with("changed") || operation == "assign" {
                    Value::Int(74)
                } else {
                    performance.clone()
                };
                core.write_reg_with_label(0, Value::Object(target), Label::Public)
                    .unwrap();
                core.write_reg_with_label(1, Value::str("performance"), Label::Public)
                    .unwrap();
                core.write_reg_with_label(2, proposed.clone(), Label::Public)
                    .unwrap();
                let instruction = if operation.contains("define") {
                    let descriptor = seed_object(&mut core, &[("value", proposed)]);
                    core.write_reg_with_label(2, Value::Object(descriptor), Label::Public)
                        .unwrap();
                    Ir3Instruction::HostCall {
                        capability: CapabilityTag("builtin:ReflectDefineProperty".to_string()),
                        args: RegRange { start: 0, count: 3 },
                        dst: 3,
                    }
                } else if operation == "assign" {
                    let source = seed_object(&mut core, &[("performance", proposed)]);
                    core.write_reg_with_label(1, Value::Object(source), Label::Public)
                        .unwrap();
                    Ir3Instruction::HostCall {
                        capability: CapabilityTag("builtin:ObjectAssign".to_string()),
                        args: RegRange { start: 0, count: 2 },
                        dst: 3,
                    }
                } else if operation.starts_with("receiver_") {
                    // An ordinary target delegates to the namespace receiver's
                    // DefineOwnProperty. Its SameValue result depends on the
                    // classified export, unlike a namespace target's Set.
                    let handler = seed_object(&mut core, &[]);
                    let receiver = core.create_proxy_object(namespace, handler).unwrap();
                    core.write_reg_with_label(3, Value::Object(receiver), Label::Public)
                        .unwrap();
                    Ir3Instruction::HostCall {
                        capability: CapabilityTag("builtin:ReflectSet".to_string()),
                        args: RegRange { start: 0, count: 4 },
                        dst: 4,
                    }
                } else {
                    Ir3Instruction::SetProperty {
                        obj: 0,
                        key: 1,
                        val: 2,
                    }
                };
                let write_module =
                    test_module_with_functions(vec![instruction, Ir3Instruction::Halt], Vec::new());
                let outcome = core.run_loop(&write_module);
                if matches!(
                    operation,
                    "direct" | "proxy_same" | "proxy_changed" | "assign"
                ) {
                    assert!(
                        matches!(outcome, Err(InterpreterError::TypeError { .. })),
                        "{operation}: {outcome:?}"
                    );
                } else {
                    assert_eq!(outcome, Err(InterpreterError::Halted), "{operation}");
                }
                if operation.contains("define") || operation.starts_with("receiver_") {
                    let result_register = if operation.starts_with("receiver_") {
                        4
                    } else {
                        3
                    };
                    assert_eq!(
                        core.read_reg(result_register).unwrap(),
                        Value::Bool(operation.ends_with("same")),
                        "{operation}"
                    );
                    assert_eq!(
                        core.get_register_label(result_register),
                        Ok(&Label::Secret),
                        "{operation}"
                    );
                } else if operation == "proxy_changed" {
                    // Namespace [[Set]] refuses without reading the export.
                    // The data-dependent Secret result is exercised by the
                    // receiver and DefineProperty controls above.
                    assert_eq!(core.json_parse_context_label().unwrap(), Label::Public);
                }
                for holder in [namespace, default] {
                    assert_eq!(
                        core.prototype_chain_get(holder, "performance").unwrap(),
                        performance,
                        "{operation} must retain the original value"
                    );
                    assert_eq!(
                        core.own_stored_runtime_property_label(holder, &key),
                        Label::Secret,
                        "{operation} must retain the original export label"
                    );
                }
                assert!(matches!(
                    core.load_native_builtin_namespace(
                        &module,
                        &source,
                        NativeBuiltinModule::PerfHooks,
                        Some(&Label::Internal),
                    ),
                    Err(InterpreterError::ModuleLoweringFailed { .. })
                ));
            }
        }
    }

    #[test]
    fn native_namespace_state_walk_handles_reflected_buffer_and_bounds_work() {
        let stack_bytes = interpreter_execution_stack_bytes(
            test_config().max_call_depth.min(MAX_NATIVE_RUN_LOOP_DEPTH),
        )
        .expect("production native execution stack");
        std::thread::Builder::new()
            .name("native-buffer-accessor-regression".into())
            .stack_size(stack_bytes)
            .spawn(|| {
                const BUFFER_FACTORY: &str = "\0franken-engine/native-buffer";
                let module = test_module_with_functions(Vec::new(), Vec::new());
                let mut core = test_interpreter();
                // A package may replace its realm globals before the first
                // module load. The native module retains its original binary
                // constructors and does not adopt the guest's File class.
                core.put_realm_runtime_name("Buffer", Value::Int(7))
                    .unwrap();
                core.put_realm_runtime_name("Blob", Value::Int(8)).unwrap();
                let guest_file =
                    Value::BuiltinFunction(BuiltinFunction::standard_constructor("Error"));
                core.put_realm_runtime_name("File", guest_file.clone())
                    .unwrap();
                core.config
                    .granted_capabilities
                    .insert(RuntimeCapability::ModuleLoad);
                core.ensure_function_own_property_object(
                    &module,
                    &Value::BuiltinFunction(BuiltinFunction::standard_constructor("Buffer")),
                )
                .expect("constructor reflection materializes intrinsic prototype accessors");
                let Value::Object(object) = core
                    .source_builtin_module(&module, NativeBuiltinModule::Buffer, None)
                    .expect(
                        "the complete canonical Buffer provider without process or timer grants",
                    )
                else {
                    panic!("buffer");
                };
                for name in ["Buffer", "Blob"] {
                    assert_eq!(
                        core.prototype_chain_get(object, name).unwrap(),
                        Value::BuiltinFunction(BuiltinFunction::standard_constructor(name)),
                        "the module exports the canonical binary constructor"
                    );
                }
                assert_eq!(
                    core.load_runtime_name("Buffer", false).unwrap(),
                    Value::Int(7)
                );
                assert_eq!(
                    core.load_runtime_name("Blob", false).unwrap(),
                    Value::Int(8)
                );
                assert_eq!(core.load_runtime_name("File", false).unwrap(), guest_file);
                core.set_object_property(object, "cycle".into(), Value::Object(object))
                    .unwrap();
                assert_eq!(
                    core.native_builtin_state_label(&module, object).unwrap(),
                    Label::Internal,
                    "the complete Buffer namespace admits audited nested File metadata"
                );
                let file = core.prototype_chain_get(object, "File").unwrap();
                assert!(matches!(&file, Value::Closure(_)));
                let Value::Object(prototype) = core
                    .get_v(
                        &module,
                        &file,
                        &RuntimePropertyKey::String(JsString::from("prototype")),
                    )
                    .unwrap()
                else {
                    panic!("File.prototype");
                };
                for name in ["name", "lastModified"] {
                    let key = RuntimePropertyKey::String(JsString::from(name));
                    let Some(Value::Accessor {
                        get: Some(getter), ..
                    }) = core.heap[prototype.0 as usize].own_runtime_property_value(&key)
                    else {
                        panic!("the actual deferred File metadata getter: {name}");
                    };
                    assert!(core.is_deferred_native_factory_accessor(getter.as_ref(), false));
                    assert!(!core.is_deferred_native_factory_accessor(getter.as_ref(), true));
                }
                let name = RuntimePropertyKey::String(JsString::from("name"));
                core.set_own_runtime_property_label(prototype, &name, &Label::Secret)
                    .unwrap();
                assert_eq!(
                    core.native_builtin_state_label(&module, object).unwrap(),
                    Label::Secret,
                    "admission of native getter code retains the descriptor label"
                );

                // Buffer retains a lazy Web Streams dependency in this same
                // program. Its arbitrary accessors must not inherit File's
                // narrowly authenticated deferred metadata admission.
                let web_function_index = {
                    let program = core.module_state.modules[BUFFER_FACTORY]
                        .compiled_module
                        .as_ref()
                        .expect("retained Buffer program");
                    program
                        .function_table
                        .iter()
                        .enumerate()
                        .find_map(|(index, code)| {
                            let index = u32::try_from(index).expect("factory function index");
                            (code.name.as_deref() == Some("closed")
                                && code.arity == 0
                                && program.function_sources.get(&index).is_some_and(|source| {
                                    source.as_str().starts_with("get closed(")
                                }))
                            .then_some(index)
                        })
                        .expect("same-program Web writer closed getter")
                };
                let web_id = u32::try_from(core.closures.len()).unwrap();
                core.closures.push(ClosureValue {
                    function_index: web_function_index,
                    captured_env: Vec::new(),
                });
                core.closure_module_origins
                    .insert(web_id, BUFFER_FACTORY.to_string());
                core.sync_estimated_memory_bytes().unwrap();
                let web_getter = Value::Closure(web_id);
                assert!(!core.is_deferred_native_factory_accessor(&web_getter, false));
                core.set_object_runtime_property(
                    prototype,
                    name.clone(),
                    Value::Accessor {
                        get: Some(Arc::new(web_getter)),
                        set: None,
                    },
                )
                .unwrap();
                assert_eq!(
                    core.native_builtin_state_label(&module, object).unwrap(),
                    Label::TopSecret,
                    "same-program unaudited getters remain opaque without invocation"
                );

                // Identical name, arity and source text cannot confer native
                // authority on a function compiled in a guest module.
                let mut guest = test_module_with_functions(
                    vec![
                        Ir3Instruction::LoadInt { dst: 0, value: 7 },
                        Ir3Instruction::Return { value: 0 },
                    ],
                    vec![Ir3FunctionDesc {
                        entry: 0,
                        arity: 0,
                        frame_size: 1,
                        name: Some("name".into()),
                        is_generator: false,
                        rest_param_index: None,
                    }],
                );
                guest.header.source_label = "guest-buffer-getter.js".into();
                guest
                    .function_sources
                    .insert(0, "get name() { return state(this).name; }".into());
                core.ensure_module_record(&guest, &guest.header.source_label)
                    .unwrap();
                core.module_state
                    .modules
                    .get_mut(&guest.header.source_label)
                    .unwrap()
                    .status = ModuleRuntimeStatus::Evaluated;
                let guest_id = u32::try_from(core.closures.len()).unwrap();
                core.closures.push(ClosureValue {
                    function_index: 0,
                    captured_env: Vec::new(),
                });
                core.closure_module_origins
                    .insert(guest_id, guest.header.source_label.clone());
                core.sync_estimated_memory_bytes().unwrap();
                let guest_getter = Value::Closure(guest_id);
                assert!(!core.is_deferred_native_factory_accessor(&guest_getter, false));
                core.set_object_runtime_property(
                    prototype,
                    name,
                    Value::Accessor {
                        get: Some(Arc::new(guest_getter)),
                        set: None,
                    },
                )
                .unwrap();
                assert_eq!(
                    core.native_builtin_state_label(&module, object).unwrap(),
                    Label::TopSecret,
                    "guest getter replacements never inherit the native admission"
                );
                core.config.instruction_budget = core.instructions_executed + 1;
                assert!(matches!(
                    core.native_builtin_state_label(&module, object),
                    Err(InterpreterError::BudgetExhausted { .. })
                ));
            })
            .expect("spawn native Buffer accessor regression")
            .join()
            .expect("native Buffer accessor regression");
    }

    #[test]
    fn native_namespace_bounds_recheck_live_defaults_snapshots_and_intrinsic_prototypes() {
        for cached in [false, true] {
            for poison in [
                "property",
                "nested",
                "prototype",
                "symbol",
                "getter",
                "namespace",
            ] {
                let module = test_module_with_functions(Vec::new(), Vec::new());
                let mut core = test_interpreter();
                core.ensure_builtin_prototype("Object")
                    .expect("canonical prototype");
                core.ensure_builtin_prototype("Function")
                    .expect("canonical thrower accessors");
                let Value::Object(object) = core.querystring_core_module().unwrap() else {
                    panic!("querystring must be an object");
                };
                let record = NativeBuiltinModule::Querystring.record("captured:querystring");
                let source = ResolutionOutcome {
                    module: ResolvedModule {
                        request_specifier: "querystring".into(),
                        canonical_specifier: record.id.clone(),
                        content_hash: record.canonical_hash(),
                        record,
                        probe_sequence: Vec::new(),
                    },
                    event: crate::module_resolver::ResolutionEvent {
                        trace_id: "native-bound".into(),
                        decision_id: "native-bound".into(),
                        policy_id: "native-bound".into(),
                        component: "module_resolver".into(),
                        event: "resolved".into(),
                        outcome: "allowed".into(),
                        error_code: String::new(),
                    },
                };
                let source: SharedResolutionOutcome = source.into();
                let namespace = if cached || poison == "namespace" {
                    let value = core
                        .load_native_builtin_namespace(
                            &module,
                            &source,
                            NativeBuiltinModule::Querystring,
                            Some(&Label::Internal),
                        )
                        .expect("pristine native objects and intrinsic prototypes are bounded");
                    let Value::Object(namespace) = value else {
                        panic!("namespace");
                    };
                    Some(namespace)
                } else {
                    None
                };
                let key = RuntimePropertyKey::String(JsString::from("stringify"));
                match poison {
                    "property" => core
                        .set_own_runtime_property_label(object, &key, &Label::Secret)
                        .unwrap(),
                    "nested" => {
                        let nested = core.alloc_object_with_prototype(None).unwrap();
                        core.set_object_property(nested, "cycle".into(), Value::Object(object))
                            .unwrap();
                        core.set_object_property(object, "added".into(), Value::Object(nested))
                            .unwrap();
                        core.join_object_mutation_label(nested, &Label::Secret)
                            .unwrap();
                    }
                    "prototype" => {
                        let prototype = core.builtin_prototypes["Object"];
                        core.join_object_mutation_label(prototype, &Label::Secret)
                            .unwrap();
                    }
                    "symbol" => {
                        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
                        core.set_object_runtime_property(object, key.clone(), Value::str("hidden"))
                            .unwrap();
                        core.set_own_runtime_property_label(object, &key, &Label::Secret)
                            .unwrap();
                    }
                    "getter" => core
                        .set_object_runtime_property(
                            object,
                            key,
                            Value::Accessor {
                                get: Some(Arc::new(Value::Function(0))),
                                set: None,
                            },
                        )
                        .unwrap(),
                    "namespace" => core
                        .set_own_runtime_property_label(namespace.unwrap(), &key, &Label::Secret)
                        .unwrap(),
                    _ => unreachable!(),
                }
                let error = core.load_native_builtin_namespace(
                    &module, &source, NativeBuiltinModule::Querystring, Some(&Label::Internal),
                ).expect_err("neither a cached facade nor a native descriptor grants a mutable value a lower label");
                assert!(
                    matches!(error, InterpreterError::ModuleLoweringFailed { .. }),
                    "cached={cached} poison={poison}: {error}"
                );
            }
        }
    }

    #[test]
    fn native_path_namespace_retains_shape_labels_and_cached_throw_labels() {
        for throws in [false, true] {
            let mut module = test_module_with_functions(
                vec![
                    Ir3Instruction::LoadInt { dst: 0, value: 7 },
                    Ir3Instruction::Throw { value: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("path_namespace_throwing_getter".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            module.header.source_label = "path-namespace-label-owner.mjs".to_string();
            let mut core = test_interpreter();
            core.ensure_module_record(&module, &module.header.source_label)
                .expect("retain the getter's owning module");
            let path = core.alloc_object_with_prototype(None).expect("Path object");
            let resolve = if throws {
                Value::Accessor {
                    get: Some(Arc::new(Value::Function(0))),
                    set: None,
                }
            } else {
                Value::Int(7)
            };
            core.set_object_property(path, "resolve".to_string(), resolve)
                .expect("public Path property");
            core.join_object_mutation_label(path, &Label::Secret)
                .expect("secret descriptor shape");
            core.mutate_builtin_prototypes(|prototypes| {
                prototypes.insert(PATH_MODULE_KEY.to_string(), path);
            });
            let record = NativeBuiltinModule::Path.record("captured:native-path-label");
            let source = ResolutionOutcome {
                module: ResolvedModule {
                    request_specifier: "node:path".to_string(),
                    canonical_specifier: record.id.clone(),
                    content_hash: record.canonical_hash(),
                    record,
                    probe_sequence: Vec::new(),
                },
                event: crate::module_resolver::ResolutionEvent {
                    trace_id: "path-label-test".to_string(),
                    decision_id: "path-label-test".to_string(),
                    policy_id: "path-label-test".to_string(),
                    component: "module_resolver".to_string(),
                    event: "resolved".to_string(),
                    outcome: "allowed".to_string(),
                    error_code: String::new(),
                },
            };
            let source: SharedResolutionOutcome = source.into();
            core.sync_estimated_memory_bytes()
                .expect("fixture accounting");

            if throws {
                for _ in 0..2 {
                    let error = core
                        .load_native_builtin_namespace(
                            &module,
                            &source,
                            NativeBuiltinModule::Path,
                            None,
                        )
                        .expect_err("the first and cached import must throw");
                    assert!(matches!(error, InterpreterError::UncaughtException { .. }));
                    assert_eq!(
                        core.take_pending_exception_slot(),
                        Some((Value::Int(7), Label::Secret)),
                        "descriptor selection must label the original and replayed exception"
                    );
                }
            } else {
                let namespace = core
                    .load_native_builtin_namespace(
                        &module,
                        &source,
                        NativeBuiltinModule::Path,
                        None,
                    )
                    .expect("snapshot the public value selected through a secret shape");
                let Value::Object(namespace) = namespace else {
                    panic!("native Path import must return a namespace");
                };
                assert_eq!(
                    core.runtime_property_label(
                        namespace,
                        &RuntimePropertyKey::String(JsString::from("resolve")),
                    ),
                    Label::Secret,
                );
            }
            assert_eq!(core.active_inline_callback_context_label, None);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "native facade initialization and cached throws retain exact ownership charges"
            );
        }
    }

    #[test]
    fn generated_function_store_retention_is_budget_atomic_bd_fw7zd_8() {
        let fixture = || {
            let mut owner = test_module_with_functions(Vec::new(), Vec::new());
            owner.header.source_label = "generated-budget-owner.mjs".to_string();
            let generated = test_module_with_functions(
                vec![
                    Ir3Instruction::LoadInt { dst: 0, value: 7 },
                    Ir3Instruction::Return { value: 0 },
                ],
                vec![Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("generated_budget_body".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                }],
            );
            let provenance = InterpreterCore::derive_generated_function_provenance(
                &owner.header.source_label,
                "",
                &"return 7;".repeat(17),
            );
            let mut core = test_interpreter();
            core.ensure_module_record(&owner, &owner.header.source_label)
                .expect("retain generated budget owner");
            core.ensure_generated_function_realm_globals()
                .expect("initialize generated budget realm");
            core.sync_estimated_memory_bytes()
                .expect("generated budget fixture baseline");
            (core, owner, generated, provenance)
        };

        let (mut probe, owner, generated, provenance) = fixture();
        let baseline = probe.estimated_memory_bytes();
        let repeated_generated = generated.clone();
        let repeated_provenance = provenance.clone();
        let owner_program = Arc::clone(
            probe.module_state.modules[&owner.header.source_label]
                .compiled_module
                .as_ref()
                .expect("generated budget owner program"),
        );
        let builtin = probe
            .retain_generated_function_artifact(
                owner.content_hash(),
                owner.header.source_label.clone(),
                owner_program,
                provenance,
                generated,
                0,
            )
            .expect("unbounded generated artifact retention");
        let retained_delta = probe.estimated_memory_bytes().saturating_sub(baseline);
        assert!(retained_delta > 0);
        assert_eq!(
            probe.module_state.retained_generated_function_bytes,
            probe.generated_function_stores_memory_bytes()
        );
        assert_eq!(
            probe.estimated_memory_bytes(),
            probe.recompute_estimated_memory_bytes()
        );
        let (handle_owner, handle_artifact) =
            InterpreterCore::parse_generated_function_handle(&builtin)
                .expect("parse retained generated handle");
        assert_eq!(handle_owner, owner.content_hash());
        assert!(
            probe.module_state.generated_function_stores[&handle_owner]
                .artifacts
                .contains_key(&handle_artifact)
        );
        let repeated_owner_program = Arc::clone(
            probe.module_state.modules[&owner.header.source_label]
                .compiled_module
                .as_ref()
                .expect("repeated generated owner program"),
        );
        let repeated = probe
            .retain_generated_function_artifact(
                owner.content_hash(),
                owner.header.source_label.clone(),
                repeated_owner_program,
                repeated_provenance,
                repeated_generated,
                0,
            )
            .expect("retain repeated generated source as a distinct occurrence");
        assert_ne!(builtin, repeated);
        assert_ne!(
            EvidenceLog::hash_register_value_seed(&Value::BuiltinFunction(builtin)),
            EvidenceLog::hash_register_value_seed(&Value::BuiltinFunction(repeated)),
            "register evidence hashes must bind the full owner/artifact handle"
        );

        let (mut one_short, owner, generated, provenance) = fixture();
        let one_short_baseline = one_short.estimated_memory_bytes();
        one_short.config.max_total_memory_bytes = one_short_baseline
            .saturating_add(retained_delta)
            .saturating_add(InterpreterCore::generated_function_handle_peak_bytes())
            .saturating_sub(1);
        let owner_program = Arc::clone(
            one_short.module_state.modules[&owner.header.source_label]
                .compiled_module
                .as_ref()
                .expect("one-short generated owner program"),
        );
        assert!(matches!(
            one_short.retain_generated_function_artifact(
                owner.content_hash(),
                owner.header.source_label.clone(),
                owner_program,
                provenance,
                generated,
                0,
            ),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(one_short.module_state.generated_function_stores.is_empty());
        assert_eq!(one_short.module_state.retained_generated_function_bytes, 0);
        assert_eq!(one_short.estimated_memory_bytes(), one_short_baseline);

        let (mut exact, owner, generated, provenance) = fixture();
        let exact_baseline = exact.estimated_memory_bytes();
        exact.config.max_total_memory_bytes = exact_baseline
            .saturating_add(retained_delta)
            .saturating_add(InterpreterCore::generated_function_handle_peak_bytes());
        let owner_program = Arc::clone(
            exact.module_state.modules[&owner.header.source_label]
                .compiled_module
                .as_ref()
                .expect("exact generated owner program"),
        );
        exact
            .retain_generated_function_artifact(
                owner.content_hash(),
                owner.header.source_label.clone(),
                owner_program,
                provenance,
                generated,
                0,
            )
            .expect("generated artifact fits exact retained-plus-handle peak");
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_function_handle_fails_closed_after_owner_eviction_or_replacement_bd_fw7zd_8() {
        let mut owner = test_module_with_functions(Vec::new(), Vec::new());
        owner.header.source_label = "generated-stale-owner.mjs".to_string();
        let generated = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 7 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 1,
                name: Some("generated_stale_body".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        let mut core = test_interpreter();
        core.ensure_module_record(&owner, &owner.header.source_label)
            .expect("retain stale-handle owner");
        let owner_program = Arc::clone(
            core.module_state.modules[&owner.header.source_label]
                .compiled_module
                .as_ref()
                .expect("stale-handle owner program"),
        );
        let builtin = core
            .retain_generated_function_artifact(
                owner.content_hash(),
                owner.header.source_label.clone(),
                owner_program,
                InterpreterCore::derive_generated_function_provenance(
                    &owner.header.source_label,
                    "",
                    "return 7;",
                ),
                generated,
                0,
            )
            .expect("retain stale-handle artifact");

        let (owner_program_id, artifact_id) =
            InterpreterCore::parse_generated_function_handle(&builtin)
                .expect("parse generated transient handle");
        let transient_artifact_bytes = {
            let artifact = core
                .resolve_generated_function_artifact(owner_program_id, artifact_id)
                .expect("resolve retained generated artifact");
            InterpreterCore::transient_module_wrapper_bytes(&artifact.compiled_module)
                .saturating_add(
                    InterpreterCore::estimate_generated_function_provenance_bytes(
                        &artifact.provenance,
                    ),
                )
        };
        let retained_baseline = core.estimated_memory_bytes();
        let original_ceiling = core.config.max_total_memory_bytes;
        core.config.max_total_memory_bytes = retained_baseline
            .saturating_add(transient_artifact_bytes)
            .saturating_sub(1);
        assert!(matches!(
            core.call_generated_function_artifact(
                &builtin,
                RegRange { start: 0, count: 0 },
                None,
                None,
            ),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.estimated_memory_bytes(), retained_baseline);
        assert!(
            core.resolve_generated_function_artifact(owner_program_id, artifact_id)
                .is_ok(),
            "transient refusal must not evict the retained artifact"
        );
        core.config.max_total_memory_bytes = original_ceiling;

        let (value, _) = core
            .call_generated_function_artifact(&builtin, RegRange { start: 0, count: 0 }, None, None)
            .expect("live owner executes generated artifact");
        assert_eq!(value, Value::Int(7));

        core.module_state
            .modules
            .get_mut(&owner.header.source_label)
            .expect("owner record")
            .compiled_module = None;
        let evicted = core
            .call_generated_function_artifact(&builtin, RegRange { start: 0, count: 0 }, None, None)
            .expect_err("stale handle must not execute without retained owner code");
        assert!(matches!(
            evicted,
            InterpreterError::ModuleEvaluationFailed { ref reason, .. }
                if reason.contains("owner program was evicted")
        ));

        let mut replacement = owner.clone();
        replacement.instructions.push(Ir3Instruction::Halt);
        core.module_state
            .modules
            .get_mut(&owner.header.source_label)
            .expect("owner record")
            .compiled_module = Some(Arc::new(replacement));
        let replaced = core
            .call_generated_function_artifact(&builtin, RegRange { start: 0, count: 0 }, None, None)
            .expect_err("stale handle must not alias replacement owner code");
        assert!(matches!(
            replaced,
            InterpreterError::ModuleEvaluationFailed { ref reason, .. }
                if reason.contains("owner program identity changed")
        ));
    }

    #[test]
    fn generated_nested_closure_uses_artifact_program_and_fails_closed_stale_bd_fw7zd_8_1() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 999 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("ordinary_zero".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("wrong_same_numbered_owner_function".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        owner.header.source_label = "generated-nested-owner.mjs".to_string();
        let generated = test_module_with_functions(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 1,
                    capture_count: 0,
                },
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::LoadInt { dst: 0, value: 73 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("generated_outer".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 2,
                    arity: 0,
                    frame_size: 1,
                    name: Some("generated_nested".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );

        let mut core = test_interpreter();
        core.ensure_module_record(&owner, &owner.header.source_label)
            .expect("retain generated nested owner");
        let (builtin, handle, artifact_program) =
            retain_generated_test_artifact(&mut core, &owner, generated, 0, "nested closure");
        let (nested, _) = core
            .call_generated_function_artifact(&builtin, RegRange { start: 0, count: 0 }, None, None)
            .expect("generated outer should return its nested closure");
        let Value::Closure(closure_id) = nested.clone() else {
            panic!("generated outer returned {nested:?}, expected Closure");
        };
        assert_eq!(
            core.closure_module_origins.get(&closure_id),
            Some(&owner.header.source_label)
        );
        assert_eq!(
            core.closure_generated_function_artifacts.get(&closure_id),
            Some(&handle)
        );
        let selected = core
            .foreign_closure_module(&nested, &owner)
            .expect("generated nested provenance should resolve")
            .expect("ordinary owner program must be foreign to the generated artifact");
        assert!(Arc::ptr_eq(&selected, &artifact_program));

        let value = core
            .invoke_inline_method_call(Some(&owner), nested.clone(), Value::Undefined, Vec::new())
            .expect("nested closure should execute its generated artifact program");
        assert_eq!(value, Value::Int(73));
        assert_ne!(
            value,
            Value::Int(999),
            "same-numbered ordinary owner function must never be selected"
        );
        assert_eq!(core.active_generated_function_artifact, None);

        core.module_state
            .modules
            .get_mut(&owner.header.source_label)
            .expect("generated nested owner record")
            .compiled_module = None;
        let evicted = core
            .invoke_inline_method_call(Some(&owner), nested.clone(), Value::Undefined, Vec::new())
            .expect_err("nested closure must not outlive owner-program retention");
        assert!(matches!(
            evicted,
            InterpreterError::ModuleEvaluationFailed { ref reason, .. }
                if reason.contains("owner program was evicted")
        ));

        core.module_state
            .modules
            .get_mut(&owner.header.source_label)
            .expect("generated nested owner record")
            .compiled_module = Some(Arc::new(owner.clone()));
        let replaced = core
            .invoke_inline_method_call(Some(&owner), nested, Value::Undefined, Vec::new())
            .expect_err("nested closure must not alias a replacement owner occurrence");
        assert!(matches!(
            replaced,
            InterpreterError::ModuleEvaluationFailed { ref reason, .. }
                if reason.contains("owner program identity changed")
        ));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_nested_continuations_retain_artifact_and_resolution_provenance_bd_fw7zd_8_1() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 999 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("ordinary_zero".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("wrong_same_numbered_owner_continuation".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        owner.header.source_label = "generated-continuation-owner.mjs".to_string();
        let mut core = test_interpreter();
        core.ensure_module_record(&owner, &owner.header.source_label)
            .expect("retain generated continuation owner");

        let generator_module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateGenerator {
                    dst: 0,
                    function_index: 1,
                    capture_count: 0,
                },
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::LoadInt { dst: 0, value: 41 },
                Ir3Instruction::Yield {
                    value: 0,
                    delegate: false,
                    resume_dst: 1,
                },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("generator_outer".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 2,
                    arity: 0,
                    frame_size: 2,
                    name: Some("generated_nested_generator".to_string()),
                    is_generator: true,
                    rest_param_index: None,
                },
            ],
        );
        let (generator_builtin, generator_handle, generator_program) =
            retain_generated_test_artifact(
                &mut core,
                &owner,
                generator_module,
                0,
                "nested generator",
            );
        let (generator_function, _) = core
            .call_generated_function_artifact(
                &generator_builtin,
                RegRange { start: 0, count: 0 },
                None,
                None,
            )
            .expect("generated outer should return a generator function");
        let generator_value = core
            .invoke_inline_method_call(
                Some(&owner),
                generator_function,
                Value::Undefined,
                Vec::new(),
            )
            .expect("generated generator function should construct its continuation");
        let Value::Generator(generator_id) = generator_value else {
            panic!("expected generated Generator object, got {generator_value:?}");
        };
        let generator = &core.generators[generator_id as usize];
        assert!(Arc::ptr_eq(&generator.owner_module, &generator_program));
        let invocation = generator
            .invocation
            .as_ref()
            .expect("unstarted generated generator invocation");
        assert_eq!(
            invocation.module_specifier.as_deref(),
            Some(owner.header.source_label.as_str())
        );
        assert_eq!(
            invocation.generated_function_artifact,
            Some(generator_handle)
        );
        let (yielded, yielded_label) = core
            .generator_next(&owner, generator_id, Value::Undefined, Label::Public)
            .expect("generated generator should execute its artifact body");
        assert_eq!(yielded_label, Label::Public);
        let Value::Object(yielded_id) = yielded else {
            panic!("generator.next() returned {yielded:?}, expected result object");
        };
        assert_eq!(
            core.heap[yielded_id.0 as usize].properties.get("value"),
            Some(&Value::Int(41))
        );
        let execution = core.generators[generator_id as usize]
            .execution
            .as_ref()
            .expect("yield should retain generated activation");
        assert_eq!(
            execution.current_module_specifier.as_deref(),
            Some(owner.header.source_label.as_str())
        );
        assert_eq!(
            execution.active_generated_function_artifact,
            Some(generator_handle)
        );

        let async_module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 1,
                    capture_count: 0,
                },
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::LoadInt { dst: 0, value: 42 },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("async_outer".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 2,
                    arity: 0,
                    frame_size: 1,
                    name: Some("generated_nested_async".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        let (async_builtin, async_handle, async_program) = retain_generated_test_artifact(
            &mut core,
            &owner,
            async_module,
            0,
            "nested async function",
        );
        let (async_function, _) = core
            .call_generated_function_artifact(
                &async_builtin,
                RegRange { start: 0, count: 0 },
                None,
                None,
            )
            .expect("generated outer should return an async function");
        let Value::AsyncFunction(async_closure_id) = async_function.clone() else {
            panic!("expected generated AsyncFunction, got {async_function:?}");
        };
        assert_eq!(
            core.closure_generated_function_artifacts
                .get(&async_closure_id),
            Some(&async_handle)
        );
        let async_value = core
            .invoke_inline_method_call(Some(&owner), async_function, Value::Undefined, Vec::new())
            .expect("generated async function should execute its artifact body");
        let Value::Promise(async_promise) = async_value else {
            panic!("expected generated async Promise, got {async_value:?}");
        };
        assert!(Arc::ptr_eq(
            &core
                .async_functions
                .last()
                .expect("generated async object")
                .owner_module,
            &async_program
        ));
        assert_eq!(
            core.promise_store
                .get(crate::promise_model::PromiseHandle(async_promise))
                .expect("generated async result Promise")
                .state,
            crate::promise_model::PromiseState::Fulfilled(crate::object_model::JsValue::Int(42))
        );

        let async_generator_module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncGenerator {
                    dst: 0,
                    function_index: 1,
                    capture_count: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("async_generator_outer".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 2,
                    arity: 0,
                    frame_size: 1,
                    name: Some("generated_nested_async_generator".to_string()),
                    is_generator: true,
                    rest_param_index: None,
                },
            ],
        );
        let (async_generator_builtin, async_generator_handle, async_generator_program) =
            retain_generated_test_artifact(
                &mut core,
                &owner,
                async_generator_module,
                0,
                "nested async generator",
            );
        let (async_generator_function, _) = core
            .call_generated_function_artifact(
                &async_generator_builtin,
                RegRange { start: 0, count: 0 },
                None,
                None,
            )
            .expect("generated outer should return an async-generator function");
        let Value::AsyncGeneratorFunction(async_generator_closure_id) =
            async_generator_function.clone()
        else {
            panic!("expected generated AsyncGeneratorFunction, got {async_generator_function:?}");
        };
        assert_eq!(
            core.closure_generated_function_artifacts
                .get(&async_generator_closure_id),
            Some(&async_generator_handle)
        );
        let async_generator_value = core
            .invoke_inline_method_call(
                Some(&owner),
                async_generator_function,
                Value::Undefined,
                Vec::new(),
            )
            .expect("generated async-generator function should construct its continuation");
        let Value::AsyncGeneratorObject(async_generator_id) = async_generator_value else {
            panic!("expected generated AsyncGeneratorObject, got {async_generator_value:?}");
        };
        let async_generator = &core.async_generators[async_generator_id as usize];
        let activation = &core.generators[async_generator.generator_id as usize];
        assert!(Arc::ptr_eq(
            &activation.owner_module,
            &async_generator_program
        ));
        let invocation = activation.invocation.as_ref().expect("retained invocation");
        assert_eq!(invocation.function_index, 1);
        assert_eq!(invocation.closure_index, Some(async_generator_closure_id));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_async_resume_retains_artifact_for_post_await_closure_bd_fw7zd_8_1() {
        let mut owner = test_module_with_functions(
            vec![
                Ir3Instruction::LoadInt { dst: 0, value: 999 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("ordinary_zero".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 1,
                    frame_size: 1,
                    name: Some("wrong_same_numbered_owner_async".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("wrong_same_numbered_owner_nested".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );
        owner.header.source_label = "generated-async-resume-owner.mjs".to_string();

        let generated = test_module_with_functions(
            vec![
                Ir3Instruction::CreateAsyncFunction {
                    dst: 0,
                    function_index: 1,
                    capture_count: 0,
                },
                Ir3Instruction::Return { value: 0 },
                Ir3Instruction::AwaitValue { promise_reg: 0 },
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 2,
                    capture_count: 0,
                },
                Ir3Instruction::AsyncReturn { value_reg: 0 },
                Ir3Instruction::LoadInt { dst: 0, value: 77 },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![
                Ir3FunctionDesc {
                    entry: 0,
                    arity: 0,
                    frame_size: 1,
                    name: Some("async_outer".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 2,
                    arity: 1,
                    frame_size: 1,
                    name: Some("generated_pending_async".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
                Ir3FunctionDesc {
                    entry: 5,
                    arity: 0,
                    frame_size: 1,
                    name: Some("generated_post_await_nested".to_string()),
                    is_generator: false,
                    rest_param_index: None,
                },
            ],
        );

        let mut core = test_interpreter();
        core.ensure_module_record(&owner, &owner.header.source_label)
            .expect("retain generated async-resume owner");
        let (builtin, handle, artifact_program) =
            retain_generated_test_artifact(&mut core, &owner, generated, 0, "pending async");
        let (async_function, _) = core
            .call_generated_function_artifact(&builtin, RegRange { start: 0, count: 0 }, None, None)
            .expect("generated outer should return an async function");
        let Value::AsyncFunction(async_closure_id) = async_function.clone() else {
            panic!("expected generated AsyncFunction, got {async_function:?}");
        };
        assert_eq!(
            core.closure_generated_function_artifacts
                .get(&async_closure_id),
            Some(&handle)
        );

        let awaited = core.promise_store.create();
        core.sync_estimated_memory_bytes()
            .expect("generated pending-async fixture accounting");
        let closures_before_resume = core.closures.len();
        let async_result = core
            .invoke_inline_method_call(
                Some(&owner),
                async_function,
                Value::Undefined,
                vec![Value::Promise(awaited.0)],
            )
            .expect("generated async function should suspend on its pending argument");
        let Value::Promise(async_result_promise) = async_result else {
            panic!("expected generated async Promise, got {async_result:?}");
        };
        assert_eq!(core.closures.len(), closures_before_resume);

        let suspended = core
            .async_functions
            .last()
            .expect("generated pending async object");
        assert_eq!(suspended.phase, AsyncFunctionPhase::SuspendedAwait);
        assert!(Arc::ptr_eq(&suspended.owner_module, &artifact_program));
        let execution = suspended
            .isolated_execution
            .as_ref()
            .expect("generated pending async activation");
        assert_eq!(
            execution.current_module_specifier.as_deref(),
            Some(owner.header.source_label.as_str())
        );
        assert_eq!(execution.active_generated_function_artifact, Some(handle));

        core.fulfill_promise(awaited, crate::object_model::JsValue::Int(2), Label::Secret)
            .expect("generated async awaited Promise should be fulfillable");
        core.drain_microtasks(Some(&owner))
            .expect("generated async resumption should use its artifact activation");

        assert_eq!(core.closures.len(), closures_before_resume + 1);
        let nested_closure_id =
            u32::try_from(closures_before_resume).expect("generated nested closure id");
        // The result Promise settles with the nested closure itself; before
        // bd-9vouw.69 it carried the closure's display string.
        let settled = match &core
            .promise_store
            .get(crate::promise_model::PromiseHandle(async_result_promise))
            .expect("generated async result Promise")
            .state
        {
            crate::promise_model::PromiseState::Fulfilled(value) => value.clone(),
            other => panic!("generated async result Promise not fulfilled: {other:?}"),
        };
        assert_eq!(
            core.js_value_to_value(&settled),
            Value::Closure(nested_closure_id)
        );
        assert_eq!(
            core.closure_module_origins.get(&nested_closure_id),
            Some(&owner.header.source_label)
        );
        assert_eq!(
            core.closure_generated_function_artifacts
                .get(&nested_closure_id),
            Some(&handle)
        );
        let nested_result = core
            .invoke_inline_method_call(
                Some(&owner),
                Value::Closure(nested_closure_id),
                Value::Undefined,
                Vec::new(),
            )
            .expect("post-await nested closure should execute its artifact program");
        assert_eq!(nested_result, Value::Int(77));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn generated_closure_provenance_memory_is_exact_and_budget_atomic_bd_fw7zd_8_1() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::CreateClosure {
                    dst: 0,
                    function_index: 0,
                    capture_count: 0,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            Vec::new(),
        );
        let handle = GeneratedFunctionArtifactHandle {
            owner_program_id: ContentHash::compute(b"generated-closure-memory-owner"),
            artifact_id: ContentHash::compute(b"generated-closure-memory-artifact"),
        };
        let fixture = || {
            let mut core = test_interpreter();
            core.active_generated_function_artifact = Some(handle);
            core.sync_estimated_memory_bytes()
                .expect("generated closure memory fixture");
            core
        };

        let mut probe = fixture();
        let baseline = probe.estimated_memory_bytes();
        assert!(matches!(
            probe
                .run_loop(&module)
                .expect("unbounded generated closure publication"),
            Value::Closure(0)
        ));
        let retained_delta = probe.estimated_memory_bytes().saturating_sub(baseline);
        assert!(retained_delta > 0);
        assert_eq!(
            probe.closure_generated_function_artifacts.get(&0),
            Some(&handle)
        );
        assert_eq!(
            probe.estimated_memory_bytes(),
            probe.recompute_estimated_memory_bytes()
        );

        let mut one_short = fixture();
        let one_short_baseline = one_short.estimated_memory_bytes();
        one_short.config.max_total_memory_bytes = one_short_baseline
            .saturating_add(retained_delta)
            .saturating_sub(1);
        assert!(matches!(
            one_short.run_loop(&module),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(one_short.closures.is_empty());
        assert!(one_short.closure_module_origins.is_empty());
        assert!(one_short.closure_generated_function_artifacts.is_empty());
        assert_eq!(one_short.estimated_memory_bytes(), one_short_baseline);

        let mut exact = fixture();
        let exact_baseline = exact.estimated_memory_bytes();
        exact.config.max_total_memory_bytes = exact_baseline.saturating_add(retained_delta);
        assert!(matches!(
            exact
                .run_loop(&module)
                .expect("exact generated closure provenance budget"),
            Value::Closure(0)
        ));
        assert_eq!(
            exact.estimated_memory_bytes(),
            exact.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn reflect_construct_wrapper_preserves_argument_side_effect_label_bd_ur3tk_7() {
        let mut module = test_module_with_functions(
            vec![
                Ir3Instruction::LoadThis { dst: 1 },
                Ir3Instruction::LoadStr {
                    dst: 2,
                    pool_index: 0,
                },
                Ir3Instruction::SetProperty {
                    obj: 1,
                    key: 2,
                    val: 0,
                },
                Ir3Instruction::Return { value: 1 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 3,
                name: Some("labeled_constructor".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        module.constant_pool.push("mark".into());

        for label in [Label::Public, Label::Secret] {
            let mut core = test_interpreter();
            let arguments = seed_array_like(&mut core, &[Value::str("classified")]);
            core.write_reg(0, Value::Function(0))
                .expect("constructor register");
            core.write_reg_with_label(1, Value::Object(arguments), label.clone())
                .expect("constructor argument-list register");
            let result = core
                .dispatch_builtin_hostcall(
                    "builtin:ReflectConstruct",
                    RegRange { start: 0, count: 2 },
                    Some(&module),
                )
                .expect("Reflect.construct wrapper");
            let Value::Object(constructed) = result else {
                panic!("Reflect.construct must return an object");
            };
            assert_eq!(
                core.chain_data_property(constructed, "mark"),
                Some(&Value::str("classified"))
            );
            assert_eq!(
                core.object_mutation_labels
                    .get(&constructed)
                    .unwrap_or(&Label::Public),
                &label,
                "constructor writes must retain argument-list provenance"
            );
            assert_eq!(
                core.get_register_label(1)
                    .expect("restored argument-list label"),
                &label
            );
            assert_eq!(
                core.take_pending_hostcall_result_label(),
                Some(label),
                "the returned object must also retain argument-list selection provenance"
            );
            assert!(core.active_inline_callback_context_label.is_none());
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn promise_reaction_wrapper_preserves_task_label_for_side_effects_bd_ur3tk_7() {
        let mut module = test_module_with_functions(
            vec![
                Ir3Instruction::LoadStr {
                    dst: 1,
                    pool_index: 0,
                },
                Ir3Instruction::LoadInt { dst: 2, value: 1 },
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 2,
                },
                Ir3Instruction::Return { value: 0 },
            ],
            vec![Ir3FunctionDesc {
                entry: 0,
                arity: 1,
                frame_size: 3,
                name: Some("promise_reaction_mutator".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        module.constant_pool.push("settled".into());

        let mut core = test_interpreter();
        let delivered_object = seed_object(&mut core, &[]);
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: Vec::new(),
        });
        core.write_reg_with_label(7, Value::str("caller"), Label::TopSecret)
            .expect("unrelated caller register");
        core.sync_estimated_memory_bytes()
            .expect("Promise reaction fixture accounting");

        let source = core.create_promise().expect("source Promise");
        let result = core
            .register_promise_then(
                source,
                Some(crate::closure_model::ClosureHandle(0)),
                None,
                Label::Public,
            )
            .expect("Promise reaction");
        core.fulfill_promise(
            source,
            InterpreterCore::value_to_js_value(&Value::Object(delivered_object)),
            Label::Secret,
        )
        .expect("Secret Promise settlement");
        core.drain_microtasks(Some(&module))
            .expect("Promise reaction drain");

        assert_eq!(
            core.object_mutation_labels.get(&delivered_object),
            Some(&Label::Secret),
            "the queued settlement label must govern callback side effects inside the isolated wrapper"
        );
        let result_promise = core
            .promise_store
            .get(result)
            .expect("reaction result Promise");
        assert_eq!(
            result_promise.label,
            Label::Secret,
            "the reaction return must preserve the queued settlement label"
        );
        assert_eq!(
            core.get_register_label(7)
                .expect("restored unrelated caller label"),
            &Label::TopSecret
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn array_from_honors_map_fn_and_this_arg() {
        let mut module = test_module_with_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:ArrayFrom".to_string()),
                    args: RegRange { start: 0, count: 3 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadThis { dst: 2 },
                Ir3Instruction::LoadStr {
                    dst: 3,
                    pool_index: 0,
                },
                Ir3Instruction::GetProperty {
                    obj: 2,
                    key: 3,
                    dst: 4,
                },
                Ir3Instruction::Add {
                    dst: 5,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Add {
                    dst: 6,
                    lhs: 5,
                    rhs: 4,
                },
                Ir3Instruction::Return { value: 6 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 2,
                frame_size: 7,
                name: Some("map_with_this_offset".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );
        module.constant_pool.push("offset".into());

        let mut core = test_interpreter();
        let array_like_id = seed_array_like(&mut core, &[Value::Int(1), Value::Int(2)]);
        let this_id = seed_object(&mut core, &[("offset", Value::Int(7))]);
        core.mutate_registers(|r| {
            r[0] = Value::Object(array_like_id);
            r[1] = Value::Function(0);
            r[2] = Value::Object(this_id);
        });

        let result = core.execute(&module).expect("Array.from should execute");
        let Value::Object(array_id) = result.value else {
            panic!(
                "Array.from should return an array object, got {:?}",
                result.value
            );
        };
        let array = core
            .heap
            .get(array_id.0 as usize)
            .expect("result array should exist");
        assert_eq!(array.properties.get("0"), Some(&Value::Int(8)));
        assert_eq!(array.properties.get("1"), Some(&Value::Int(10)));
        assert_eq!(array.properties.get("length"), Some(&Value::Int(2)));
    }

    #[test]
    fn array_from_rejects_non_callable_map_fn() {
        for label in [Label::Public, Label::Secret, Label::TopSecret] {
            let mut core = test_interpreter();
            let array_like_id = seed_array_like(&mut core, &[Value::Int(1)]);
            core.write_reg(0, Value::Object(array_like_id))
                .expect("source register");
            core.write_reg_with_label(1, Value::Int(99), label.clone())
                .expect("invalid mapper register");

            let err = core
                .dispatch_builtin_hostcall(
                    "builtin:ArrayFrom",
                    RegRange { start: 0, count: 2 },
                    None,
                )
                .expect_err("Array.from should reject non-callable mapFn");
            // The ordinary callback boundary seals native language errors into
            // guest objects before restoring its confidentiality context.
            let Some(Value::Object(error_id)) = core.pending_exception.as_ref() else {
                panic!("invalid mapper must retain its TypeError object: {err:?}");
            };
            let error = &core.heap[error_id.0 as usize];
            let message = InterpreterError::TypeError {
                expected: "function".to_string(),
                got: "number".to_string(),
            }
            .to_string();
            assert_eq!(
                core.chain_data_property(*error_id, "name"),
                Some(&Value::str("TypeError"))
            );
            assert_eq!(error.properties.get("message"), Some(&Value::str(&message)));
            assert_eq!(
                err,
                InterpreterError::UncaughtException {
                    value: format!("TypeError: {message}"),
                }
            );
            assert_eq!(core.pending_exception_label, label);
            assert_eq!(core.registers[0], Value::Object(array_like_id));
            assert_eq!(core.registers[1], Value::Int(99));
            assert!(core.active_inline_callback_context_label.is_none());
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn array_from_maps_string_elements_with_index() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:ArrayFrom".to_string()),
                    args: RegRange { start: 0, count: 2 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::Add {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Return { value: 2 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 2,
                frame_size: 3,
                name: Some("append_index".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );

        let mut core = test_interpreter();
        core.mutate_registers(|r| {
            r[0] = Value::str("ab");
            r[1] = Value::Function(0);
        });

        let result = core.execute(&module).expect("Array.from should execute");
        let Value::Object(array_id) = result.value else {
            panic!(
                "Array.from should return an array object, got {:?}",
                result.value
            );
        };
        let array = core
            .heap
            .get(array_id.0 as usize)
            .expect("result array should exist");
        assert_eq!(array.properties.get("0"), Some(&Value::str("a0")));
        assert_eq!(array.properties.get("1"), Some(&Value::str("b1")));
        assert_eq!(array.properties.get("length"), Some(&Value::Int(2)));
    }

    #[test]
    fn array_prototype_reduce_right_invokes_callback_from_right_to_left() {
        let module = test_module_with_functions(
            vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:ArrayPrototypeReduceRight".to_string()),
                    args: RegRange { start: 0, count: 3 },
                    dst: 0,
                },
                Ir3Instruction::Halt,
                Ir3Instruction::LoadInt { dst: 4, value: 10 },
                Ir3Instruction::Mul {
                    dst: 5,
                    lhs: 0,
                    rhs: 4,
                },
                Ir3Instruction::Add {
                    dst: 6,
                    lhs: 5,
                    rhs: 1,
                },
                Ir3Instruction::Return { value: 6 },
            ],
            vec![Ir3FunctionDesc {
                entry: 2,
                arity: 4,
                frame_size: 7,
                name: Some("reduce_right_digits".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
        );

        let mut core = test_interpreter();
        let array_id = seed_array_like(&mut core, &[Value::Int(1), Value::Int(2), Value::Int(3)]);
        core.mutate_registers(|r| {
            r[0] = Value::Object(array_id);
            r[1] = Value::Function(0);
            r[2] = Value::Int(0);
        });

        let result = core
            .execute(&module)
            .expect("Array.prototype.reduceRight should execute");
        assert_eq!(result.value, Value::Int(321));
    }
}

#[cfg(test)]
mod numeric_error_message_tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;

    fn test_core() -> InterpreterCore {
        InterpreterCore::new(
            InterpreterConfig::quickjs_defaults(),
            "numeric-error-message-test",
        )
    }

    #[test]
    fn eval_numeric_helpers_preserve_type_error_messages() {
        let mut core = test_core();
        core.mutate_registers(|r| {
            r.resize(4, Value::Undefined);
        });
        // A Symbol operand is a TypeError for every numeric operator (ES2020
        // 7.1.4 ToNumber). A non-numeric string used to be the example here,
        // but StringToNumber gives NaN for it, not a TypeError.
        core.mutate_registers(|r| {
            r[0] = Value::Symbol(SymbolId(99));
            r[1] = Value::Int(1);
        });

        let arith_err = core
            .eval_arith(0, 1, "mul")
            .expect_err("Symbol * int should remain a TypeError");
        assert_eq!(
            arith_err,
            InterpreterError::TypeError {
                expected: "number".to_string(),
                got: "symbol mul number".to_string(),
            }
        );

        let div_err = core
            .eval_div(0, 1)
            .expect_err("Symbol / int should remain a TypeError");
        assert_eq!(
            div_err,
            InterpreterError::TypeError {
                expected: "number".to_string(),
                got: "symbol / number".to_string(),
            }
        );

        let mod_err = core
            .eval_mod(0, 1)
            .expect_err("Symbol % int should remain a TypeError");
        assert_eq!(
            mod_err,
            InterpreterError::TypeError {
                expected: "number".to_string(),
                got: "symbol % number".to_string(),
            }
        );

        let exp_err = core
            .eval_exp(0, 1)
            .expect_err("Symbol ** int should remain a TypeError");
        assert_eq!(
            exp_err,
            InterpreterError::TypeError {
                expected: "number".to_string(),
                got: "symbol ** number".to_string(),
            }
        );

        let bitwise_err = core
            .eval_bitwise(0, 1, "&")
            .expect_err("Symbol bitwise int should remain a TypeError");
        assert_eq!(
            bitwise_err,
            InterpreterError::TypeError {
                expected: "number".to_string(),
                got: "symbol".to_string(),
            }
        );

        let relational_err = core
            .eval_relational(0, 1, "<")
            .expect_err("Symbol < int should remain a TypeError");
        assert_eq!(
            relational_err,
            InterpreterError::TypeError {
                expected: "comparable primitive".to_string(),
                got: "symbol < number".to_string(),
            }
        );
    }
}

#[cfg(test)]
mod event_loop_timer_microtask_tests {
    // Real coverage for two behaviors previously stubbed inside the
    // feature-gated (broken) `tests` module below: timer firing order is
    // controlled by virtual-clock delay (not registration order), and the
    // microtask checkpoint drains before any pending timer macrotask fires.
    // Filed under mock-hunt bead bd-5116c. The tests deliberately bypass the
    // feature-gated `execute_builtin_call` test shim and instead drive the
    // event loop directly via the public-in-crate `event_loop.set_timeout`
    // API — the same code path that `builtin:SetTimeout` invokes after
    // resolving its closure handle.
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use crate::baseline_interpreter::*;
    use crate::closure_model::ClosureHandle;
    use crate::ifc_artifacts::Label;

    fn test_core(trace_id: &str) -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::VmDispatch);
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        InterpreterCore::new(config, trace_id)
    }

    fn push_empty_closure(core: &mut InterpreterCore, function_index: u32) -> ClosureHandle {
        let id = core.closures.len() as u32;
        core.closures.push(ClosureValue {
            function_index,
            captured_env: Vec::new(),
        });
        ClosureHandle(id)
    }

    /// Build a one-function module whose function 0 body executes a single
    /// `Call` whose callee register (r0) is `undefined` in a fresh 0-arg frame.
    /// Running that body therefore fails with a "expected function" type error.
    /// This is the observable used to prove the timer closure body *executed*:
    /// the former stub never ran the body and returned `Ok(undefined)`, so the
    /// error only appears once the body is actually run.
    fn module_with_failing_call_function() -> Ir3Module {
        use crate::ir_contract::{Ir3FunctionDesc, IrHeader, IrLevel, IrSchemaVersion};
        Ir3Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: None,
                source_label: "timer-callback-test".to_string(),
            },
            instructions: vec![
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 0, count: 0 },
                    dst: 1,
                },
                Ir3Instruction::Return { value: 1 },
            ],
            constant_pool: Vec::new(),
            function_table: vec![Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 8,
                name: Some("timer_cb".to_string()),
                is_generator: false,
                rest_param_index: None,
            }],
            specialization: None,
            required_capabilities: Vec::new(),
            function_lengths: Default::default(),
            function_sources: Default::default(),
            sloppy_functions: Default::default(),
        }
    }

    fn timer_macrotask(handle: ClosureHandle) -> crate::promise_model::Macrotask {
        crate::promise_model::Macrotask {
            source: crate::promise_model::MacrotaskSource::Timer,
            handler: handle,
            scheduled_at: 0,
            registration_seq: 0,
            label: Label::Public,
        }
    }

    #[test]
    fn timer_callback_body_executes_when_module_present() {
        // bd-zqb1x regression: a fired timer must RUN its callback body, not
        // merely emit a witness event. The body here performs a `Call` on an
        // undefined callee, so *running* it surfaces a "expected function" type
        // error. The former stub returned Ok(undefined) without running the
        // body, so this error is proof the body actually executed.
        let mut core = test_core("timer-body-exec");
        let module = module_with_failing_call_function();
        let handle = push_empty_closure(&mut core, 0);

        let result = core.execute_macrotask_callback(&timer_macrotask(handle), Some(&module));

        let err = result.expect_err(
            "the timer callback body must execute (and its Call-on-undefined must \
             fault); the stub would have returned Ok without running the body",
        );
        assert!(
            format!("{err}").contains("function"),
            "the fault must come from executing the body's Call on a non-function \
             callee, got: {err:?}"
        );
    }

    #[test]
    fn timer_callback_without_module_is_witness_only() {
        // The test-only no-module path cannot lower/run the closure body, so it
        // falls back to the prior witness-only behaviour: no body execution, no
        // error (the Call-on-undefined fault from the body must NOT occur).
        let mut core = test_core("timer-body-no-module");
        let handle = push_empty_closure(&mut core, 0);

        let result = core.execute_macrotask_callback(&timer_macrotask(handle), None);

        assert!(
            result.is_ok(),
            "no-module drain must not execute the callback body, so the \
             body's fault must not surface; got {result:?}"
        );
    }

    #[test]
    fn timer_callback_commitment_binds_identity_order_and_position_bd_9vouw_76() {
        fn commitment(callbacks: &[Value], sequence: u64, ip: usize, tick: u64) -> ContentHash {
            let mut core = test_core("timer-witness-inputs");
            core.witness_seq = sequence;
            core.ip = ip;
            core.instructions_executed = tick;
            for callback in callbacks {
                core.record_timer_callback_witness(callback).unwrap();
            }
            core.timer_callback_witness.unwrap().1
        }

        let first = Value::Closure(1);
        let second = Value::Closure(2);
        let baseline = commitment(&[first.clone(), second.clone()], 3, 4, 5);
        assert_eq!(
            baseline,
            commitment(&[first.clone(), second.clone()], 3, 4, 5)
        );
        assert_ne!(
            baseline,
            commitment(&[second.clone(), first.clone()], 3, 4, 5)
        );
        assert_ne!(baseline, commitment(std::slice::from_ref(&first), 3, 4, 5));
        assert_ne!(
            baseline,
            commitment(&[first.clone(), second.clone()], 4, 4, 5)
        );
        assert_ne!(
            baseline,
            commitment(&[first.clone(), second.clone()], 3, 5, 5)
        );
        assert_ne!(baseline, commitment(&[first, second], 3, 4, 6));
        assert_ne!(
            commitment(&[Value::Function(1)], 0, 0, 0),
            commitment(&[Value::Closure(1)], 0, 0, 0),
            "callable kinds with the same numeric handle must remain distinct"
        );
        assert_ne!(
            commitment(
                &[Value::BuiltinFunction(BuiltinFunction::require("a.js"))],
                0,
                0,
                0
            ),
            commitment(
                &[Value::BuiltinFunction(BuiltinFunction::require("b.js"))],
                0,
                0,
                0
            ),
            "the commitment must include builtin module identity, not just its display name"
        );
    }

    #[test]
    fn timer_callback_commitment_preserves_effects_denials_and_reuse_bd_9vouw_76() {
        let mut core = test_core("timer-witness-handoff");
        for _ in 0..20_000 {
            core.record_timer_callback_witness(&Value::Closure(1))
                .unwrap();
        }
        assert!(
            core.witness_events.is_empty(),
            "ticks retain no per-callback rows"
        );
        assert_eq!(core.timer_callback_witness.unwrap().0, 20_000);

        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Console);
        for index in [1, 2] {
            assert!(check_hostcall_capability_gate(&mut core, "console:log", index).unwrap());
        }
        for index in [3, 4] {
            assert!(matches!(
                check_hostcall_capability_gate(&mut core, "fs:read", index),
                Err(InterpreterError::CapabilityDenied { .. })
            ));
        }
        let effects_and_denials = core.witness_events.clone();
        let decisions = core.hostcall_decisions.clone();
        assert_eq!(decisions.len(), 4);
        assert!(decisions[..2].iter().all(|decision| decision.allowed));
        assert!(decisions[2..].iter().all(|decision| !decision.allowed));

        let result = core.take_execution_result(
            LabeledReturn {
                value: Value::Undefined,
                label: Label::Public,
            },
            None,
        );
        assert_eq!(
            &result.witness_events[..effects_and_denials.len()],
            effects_and_denials.as_slice(),
            "folding timer callbacks must preserve every security witness verbatim"
        );
        assert_eq!(result.witness_events.len(), effects_and_denials.len() + 1);
        assert_eq!(result.hostcall_decisions, decisions);
        assert!(core.timer_callback_witness.is_none());

        let next = core.take_execution_result(
            LabeledReturn {
                value: Value::Undefined,
                label: Label::Public,
            },
            None,
        );
        assert!(
            next.witness_events.is_empty(),
            "a handoff consumes the aggregate once"
        );
    }

    #[test]
    fn microtask_grant_folding_preserves_live_authority_and_hooks_bd_9vouw_76() {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Default)]
        struct MicrotaskHook {
            decisions: Mutex<Vec<bool>>,
            refuse: AtomicBool,
        }

        impl InterpreterHook for MicrotaskHook {
            fn pre_property_access(
                &self,
                _ctx: &HookContext,
                _target: &ObjectRef,
                _key: &PropertyKey,
            ) -> HookAction {
                HookAction::Allow
            }
            fn pre_call(
                &self,
                _ctx: &HookContext,
                _callee: &FunctionRef,
                _args: &[Value],
            ) -> HookAction {
                HookAction::Allow
            }
            fn pre_allocation(
                &self,
                _ctx: &HookContext,
                _kind: AllocKind,
                _size_hint: usize,
            ) -> HookAction {
                HookAction::Allow
            }
            fn pre_import(&self, _ctx: &HookContext, _specifier: &str) -> HookAction {
                HookAction::Allow
            }
            fn pre_hostcall(
                &self,
                _ctx: &HookContext,
                capability: &str,
                allowed: bool,
            ) -> HookAction {
                assert_eq!(capability, "builtin:QueueMicrotask");
                self.decisions.lock().unwrap().push(allowed);
                if self.refuse.load(Ordering::SeqCst) {
                    HookAction::Terminate("microtask policy revoked".to_string())
                } else {
                    HookAction::Allow
                }
            }
        }

        let mut core = test_core("microtask-live-grant");
        let hook = Arc::new(MicrotaskHook::default());
        core.set_hook(hook.clone());
        let tag = "builtin:QueueMicrotask";
        assert_eq!(
            hostcall_registry_row(tag).unwrap().authority,
            Some(RuntimeCapability::Timer)
        );
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Timer);
        assert!(check_hostcall_capability_gate(&mut core, tag, 1).unwrap());
        assert!(!check_hostcall_capability_gate(&mut core, tag, 2).unwrap());
        core.config
            .granted_capabilities
            .remove(&RuntimeCapability::Timer);
        for instruction in [3, 4] {
            assert!(matches!(
                check_hostcall_capability_gate(&mut core, tag, instruction),
                Err(InterpreterError::CapabilityDenied { .. })
            ));
        }
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Timer);
        assert!(check_hostcall_capability_gate(&mut core, tag, 5).unwrap());
        assert!(!check_hostcall_capability_gate(&mut core, tag, 6).unwrap());
        hook.refuse.store(true, Ordering::SeqCst);
        assert!(matches!(
            check_hostcall_capability_gate(&mut core, tag, 7),
            Err(InterpreterError::ContainmentActionRequested { .. })
        ));
        assert_eq!(
            *hook.decisions.lock().unwrap(),
            [true, true, false, false, true, true, true],
            "folding evidence must never cache the live authority or hook decision"
        );
        assert_eq!(core.folded_hostcall_decisions, 2);
        assert_eq!(
            core.hostcall_decisions
                .iter()
                .map(|decision| (decision.instruction_index, decision.allowed))
                .collect::<Vec<_>>(),
            [(1, true), (3, false), (4, false), (5, true)],
            "every denial and the first re-grant must remain individually retained"
        );
    }

    #[test]
    fn microtask_commitment_only_records_success_and_is_consumed_once_bd_9vouw_76() {
        let mut core = test_core("microtask-witness-handoff");
        let callback = Value::Closure(push_empty_closure(&mut core, 0).0);
        core.sync_estimated_memory_bytes().unwrap();
        assert!(matches!(
            core.queue_microtask_from_value(&Value::Int(1)),
            Err(InterpreterError::TypeError { .. })
        ));
        assert!(core.microtask_enqueue_witness.is_none());
        let budget = core.config.max_total_memory_bytes;
        core.config.max_total_memory_bytes = 0;
        assert!(matches!(
            core.queue_microtask_from_value(&callback),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(core.microtask_enqueue_witness.is_none());
        assert!(core.event_loop.microtasks.is_empty());
        core.config.max_total_memory_bytes = budget;
        core.queue_microtask_from_value(&callback).unwrap();
        let (count, digest) = core.microtask_enqueue_witness.unwrap();
        assert_eq!(count, 1);
        assert_eq!(core.event_loop.microtasks.pending_count(), 1);
        let timer_digest = core
            .callback_witness_step(&callback, None, b"franken-engine.timer-callback-chain.v1\0")
            .unwrap()
            .1;
        assert_ne!(
            digest, timer_digest,
            "different callback operations are domain-separated"
        );

        let result = core.take_execution_result(
            LabeledReturn {
                value: Value::Undefined,
                label: Label::Public,
            },
            None,
        );
        assert_eq!(result.witness_events.len(), 1);
        assert_eq!(
            result.witness_events[0].payload_hash,
            ContentHash::compute(
                format!("microtask_enqueues_v1:{count}:{}", digest.to_hex()).as_bytes()
            )
        );
        assert!(core.microtask_enqueue_witness.is_none());
        let next = core.take_execution_result(
            LabeledReturn {
                value: Value::Undefined,
                label: Label::Public,
            },
            None,
        );
        assert!(next.witness_events.is_empty());

        // The successful handoff also clears the first-grant set. A reused
        // core records its next grant even when the same builtin is called.
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Timer);
        assert!(check_hostcall_capability_gate(&mut core, "builtin:QueueMicrotask", 1).unwrap());
        core.take_execution_result(
            LabeledReturn {
                value: Value::Undefined,
                label: Label::Public,
            },
            None,
        );
        assert!(check_hostcall_capability_gate(&mut core, "builtin:QueueMicrotask", 1).unwrap());
    }

    #[test]
    fn timer_ordering() {
        // Shorter-delay timers must fire before longer-delay timers, even when
        // scheduled in the opposite order. Observed via the deterministic
        // `MacrotaskExecuted` events recorded by the event loop.
        let mut core = test_core("timer-ordering-test");

        let cb_long = push_empty_closure(&mut core, 0);
        let cb_short = push_empty_closure(&mut core, 1);

        // Schedule the long-delay timer first (registration_seq = 0) and
        // the short-delay timer second (registration_seq = 1).
        core.event_loop.set_timeout(cb_long, 200, Label::Public);
        core.event_loop.set_timeout(cb_short, 50, Label::Public);
        core.sync_estimated_memory_bytes()
            .expect("seeded timers should fit memory budget");

        assert_eq!(
            core.event_loop.macrotasks.len(),
            2,
            "both timers must be queued as macrotasks",
        );

        // Drain the event loop. Each Timer macrotask emits a
        // `MacrotaskExecuted` witness event in firing order.
        core.run_event_loop_until_idle();

        let firing_order: Vec<u64> = core
            .event_loop
            .witness
            .iter()
            .filter_map(|event| match event {
                crate::promise_model::WitnessEvent::MacrotaskExecuted {
                    source: crate::promise_model::MacrotaskSource::Timer,
                    registration_seq,
                } => Some(*registration_seq),
                _ => None,
            })
            .collect();

        assert_eq!(
            firing_order,
            vec![1, 0],
            "short-delay timer (registration_seq=1) must fire before \
             long-delay timer (registration_seq=0)",
        );
        assert_eq!(
            core.event_loop.macrotasks.len(),
            0,
            "all timer macrotasks must drain",
        );
    }

    #[test]
    fn microtask_before_timer() {
        // ES2020 invariant: pending microtasks must drain at the microtask
        // checkpoint before any subsequently-due timer macrotask fires.
        // We pre-enqueue a microtask, schedule a setTimeout(closure, 0), then
        // call `drain_microtasks` (the checkpoint). The microtask must
        // complete — observable via the promise it fulfills — while the
        // timer macrotask remains pending.
        let mut core = test_core("microtask-vs-timer-test");

        let cb = push_empty_closure(&mut core, 0);

        // Pre-enqueue a microtask: an identity-propagation reaction that
        // fulfills a fresh Pending promise with Int(42) when drained.
        let pending = core.promise_store.create();
        core.event_loop
            .microtasks
            .enqueue(crate::promise_model::Microtask::PromiseReaction {
                handler: None,
                argument: crate::object_model::JsValue::Int(42),
                result_promise: pending,
                label: Label::Public,
            });

        // Schedule the timer.
        core.event_loop.set_timeout(cb, 0, Label::Public);

        assert_eq!(
            core.event_loop.macrotasks.len(),
            1,
            "timer macrotask is pending",
        );
        assert_eq!(
            core.event_loop.microtasks.pending_count(),
            1,
            "microtask is pending",
        );
        assert!(
            matches!(
                core.promise_store
                    .get(pending)
                    .expect("pending promise exists")
                    .state,
                crate::promise_model::PromiseState::Pending,
            ),
            "promise must be Pending before microtask drain",
        );

        // Run the microtask checkpoint. The pre-enqueued microtask must
        // execute (fulfilling `pending`) without the timer firing first.
        core.drain_microtasks(None)
            .expect("microtask drain fits test budget");

        assert_eq!(
            core.event_loop.microtasks.pending_count(),
            0,
            "microtask must have drained at the checkpoint",
        );
        assert!(
            matches!(
                core.promise_store
                    .get(pending)
                    .expect("pending promise still exists")
                    .state,
                crate::promise_model::PromiseState::Fulfilled(_),
            ),
            "microtask must have run and fulfilled the promise before any \
             timer fired",
        );
        // The timer macrotask must still be pending — no MacrotaskExecuted
        // witness yet.
        assert_eq!(
            core.event_loop.macrotasks.len(),
            1,
            "timer macrotask must not have fired before microtask checkpoint",
        );
        let timer_fired_pre_drain = core.event_loop.witness.iter().any(|event| {
            matches!(
                event,
                crate::promise_model::WitnessEvent::MacrotaskExecuted {
                    source: crate::promise_model::MacrotaskSource::Timer,
                    ..
                },
            )
        });
        assert!(
            !timer_fired_pre_drain,
            "no Timer MacrotaskExecuted witness may appear before the \
             microtask drain completes",
        );

        // Running the full event loop now fires the timer.
        core.run_event_loop_until_idle();
        let timer_fired_post_drain = core.event_loop.witness.iter().any(|event| {
            matches!(
                event,
                crate::promise_model::WitnessEvent::MacrotaskExecuted {
                    source: crate::promise_model::MacrotaskSource::Timer,
                    ..
                },
            )
        });
        assert!(
            timer_fired_post_drain,
            "timer must fire after microtasks have drained",
        );
        assert_eq!(
            core.event_loop.macrotasks.len(),
            0,
            "timer macrotask must drain",
        );
    }
}

/// Test-only integer extraction used by legacy in-source tests. The historical
/// `Value::as_int()` accessor was removed when the value model was refactored;
/// legacy tests call it on values they expect to be integral (timer ids,
/// counter results). Returns `Some(i64)` for `Int` and integral finite `Float`,
/// `None` otherwise.
///
/// bd-suwvw: the last in-tree callers (timer-substrate tests) migrated to the
/// object timer-handle contract (`timer_handle_id`); kept for future legacy
/// tests, allowed as dead code.
#[cfg(test)]
impl Value {
    #[allow(dead_code)]
    pub(super) fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Float(f) if f.0.is_finite() && f.0.fract() == 0.0 => Some(f.0 as i64),
            _ => None,
        }
    }
}
