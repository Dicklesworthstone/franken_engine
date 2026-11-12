//! Intrinsic initialization of JSON module values and their shared cache.
//!
//! Format and source authorization happens before this path. No guest code,
//! generated JavaScript, parser AST or nested execution state is needed.

use super::*;

impl InterpreterCore {
    pub(super) fn load_json_module(
        &mut self,
        module: &Ir3Module,
        resolved: &str,
        source: &str,
        import_bound: Option<&Label>,
    ) -> Result<Value, InterpreterError> {
        // Keep the raw source admitted while its UTF-16 decoding and parsed
        // objects are live. The original bytes remain the authenticated input.
        let source_bytes = Self::estimate_string_bytes(source);
        let outcome = (|| {
            self.json_reserve_temporary(source_bytes)?;
            let outcome = self.initialize_json_module(module, resolved, source, import_bound);
            self.json_release_temporary(source_bytes);
            outcome
        })();
        match &outcome {
            Ok(_) => {
                if let Some(record) = self.module_state.modules.get_mut(resolved) {
                    record.status = ModuleRuntimeStatus::Evaluated;
                }
            }
            Err(InterpreterError::UncaughtException { value })
                if value.starts_with("SyntaxError: ") =>
            {
                // The parser already created the actual labeled SyntaxError.
                // Cache its message without allocating a replacement exception.
                self.fail_module_record(
                    resolved,
                    &format!(
                        "{MODULE_SYNTAX_ERROR_REASON_PREFIX}{}",
                        &value["SyntaxError: ".len()..]
                    ),
                );
            }
            Err(error) => self.fail_module_record(resolved, &error.to_string()),
        }
        outcome
    }

    fn initialize_json_module(
        &mut self,
        module: &Ir3Module,
        resolved: &str,
        source: &str,
        import_bound: Option<&Label>,
    ) -> Result<Value, InterpreterError> {
        let selected_label = self.json_parse_context_label()?;
        let selected_bytes = Self::estimate_label_bytes(&selected_label);
        self.json_reserve_temporary(selected_bytes)?;
        let observation = self.begin_property_observation([]);
        self.json_release_temporary(selected_bytes);
        let observation = observation?;
        let outcome = (|| {
            self.json_observe_label(selected_label)?;
            // Source-loaded data has the ordinary module-load provenance
            // floor; a classified caller can only raise it.
            self.json_observe_label(Label::Internal)?;
            let ceiling = self.json_parse_context_label()?;
            let ceiling_bytes = Self::estimate_label_bytes(&ceiling);
            self.json_reserve_temporary(ceiling_bytes)?;
            let outcome = (|| {
                Self::check_import_flow_bound(resolved, &ceiling, import_bound)?;
                self.set_module_flow_label_ceiling(resolved, &ceiling)?;
                let value = self.json_parse_module_source(source)?;
                let parent = self
                    .active_cjs_context
                    .as_ref()
                    .map(|context| context.module_object);
                let module_object =
                    self.alloc_cjs_module_object(module, resolved, parent, value.clone())?;
                self.set_own_runtime_property_label(
                    module_object,
                    &RuntimePropertyKey::String(JsString::from("exports")),
                    &ceiling,
                )?;
                self.publish_module_export(
                    resolved,
                    JsString::from("default"),
                    value,
                    ceiling,
                    ExportPublication::Own,
                    0,
                )?;
                self.set_object_property(module_object, "loaded".to_string(), Value::Bool(true))?;
                let record = self.module_state.modules.get_mut(resolved).ok_or_else(|| {
                    InterpreterError::ModuleEvaluationFailed {
                        specifier: resolved.to_string(),
                        reason: "JSON module record disappeared during initialization".to_string(),
                    }
                })?;
                // Both require and import reuse this carrier, regardless of
                // which form reached JSON first. Object properties never
                // become named exports through CommonJS export synthesis.
                record.cjs_module_object = Some(module_object);
                Ok(Value::Object(record.namespace_object))
            })();
            self.json_release_temporary(ceiling_bytes);
            outcome
        })();
        self.finish_property_read_observation(observation, outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_resolver::{ModuleProvenance, ModuleRecord};

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::ModuleLoad,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "json-module-test")
    }

    fn caller() -> Ir3Module {
        Ir3Module {
            header: crate::ir_contract::IrHeader {
                schema_version: crate::ir_contract::IrSchemaVersion::CURRENT,
                level: crate::ir_contract::IrLevel::Ir3,
                source_hash: None,
                source_label: "captured:caller".to_string(),
            },
            instructions: vec![Ir3Instruction::Halt],
            constant_pool: Vec::new(),
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
            function_lengths: Default::default(),
            function_sources: Default::default(),
            sloppy_functions: Default::default(),
        }
    }

    fn delivered(source: &str) -> SharedResolvedModule {
        delivered_as(source, ModuleSyntax::Json, "captured:data")
    }

    fn delivered_as(source: &str, syntax: ModuleSyntax, id: &str) -> SharedResolvedModule {
        let record = ModuleRecord {
            id: id.to_string(),
            syntax,
            source: source.to_string(),
            dependencies: Vec::new(),
            required_capabilities: BTreeSet::from([RuntimeCapability::ModuleLoad]),
            provenance: ModuleProvenance {
                kind: ModuleSourceKind::Workspace,
                origin: "json-module-fixture".to_string(),
            },
        };
        ResolvedModule {
            request_specifier: "./data".to_string(),
            canonical_specifier: record.id.clone(),
            content_hash: record.canonical_hash(),
            record,
            probe_sequence: Vec::new(),
        }
        .into()
    }

    fn json_attributes() -> ImportAttributes {
        ImportAttributes::new(BTreeMap::from([("type".into(), "json".into())])).unwrap()
    }

    #[test]
    fn typed_static_import_and_require_share_the_native_json_value_in_both_orders() {
        for import_first in [false, true] {
            let mut core = core();
            let module = caller();
            let source = delivered(r#"{"answer":42}"#);
            let attributes = json_attributes();
            let kinds = if import_first {
                [ModuleLoadKind::Import(&attributes), ModuleLoadKind::Require]
            } else {
                [ModuleLoadKind::Require, ModuleLoadKind::Import(&attributes)]
            };
            let first = core
                .load_module_resolved(
                    &module,
                    "captured:data",
                    kinds[0],
                    None,
                    Some(source.clone()),
                )
                .unwrap();
            let record = core.module_state.modules.get("captured:data").unwrap();
            let value = record
                .exports
                .get(&JsString::from("default"))
                .unwrap()
                .clone();
            let Value::Object(value_object) = value else {
                panic!("JSON object");
            };
            let carrier = record.cjs_module_object.unwrap();
            assert!(record.compiled_module.is_none());
            assert_eq!(record.exports.len(), 1);
            core.set_object_property(value_object, "answer".into(), Value::Int(43))
                .unwrap();
            let work = core.instructions_executed;
            assert_eq!(
                core.load_module_resolved(&module, "captured:data", kinds[1], None, Some(source),)
                    .unwrap(),
                first
            );
            assert_eq!(
                core.instructions_executed, work,
                "cached JSON is not parsed again"
            );
            assert_eq!(
                core.iterator_protocol_property(
                    Some(&module),
                    carrier,
                    &RuntimePropertyKey::String(JsString::from("exports")),
                    Value::Object(carrier),
                )
                .unwrap(),
                Value::Object(value_object)
            );
            assert_eq!(
                core.heap[value_object.0 as usize].properties.get("answer"),
                Some(&Value::Int(43))
            );
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }

    #[test]
    fn cached_json_never_authorizes_missing_unknown_or_dynamic_attributes() {
        let mut core = core();
        let module = caller();
        let source = delivered("42");
        core.load_module_resolved(
            &module,
            "captured:data",
            ModuleLoadKind::Require,
            None,
            Some(source.clone()),
        )
        .unwrap();
        let heap_objects = core.heap.len();
        let work = core.instructions_executed;
        for (attributes, expected) in [
            (ImportAttributes::default(), "ERR_IMPORT_ATTRIBUTE_MISSING"),
            (
                ImportAttributes::new(BTreeMap::from([("type".into(), "javascript".into())]))
                    .unwrap(),
                "ERR_IMPORT_ATTRIBUTE_UNSUPPORTED",
            ),
            (
                ImportAttributes::new(BTreeMap::from([
                    ("type".into(), "json".into()),
                    ("integrity".into(), "opaque".into()),
                ]))
                .unwrap(),
                "ERR_IMPORT_ATTRIBUTE_UNSUPPORTED",
            ),
        ] {
            assert!(matches!(core.load_module_resolved(
                &module, "captured:data", ModuleLoadKind::Import(&attributes), None, Some(source.clone()),
            ), Err(InterpreterError::ModuleLoweringFailed { error, .. }) if error.contains(expected)));
        }
        assert!(matches!(core.load_module_resolved(
            &module, "captured:data", ModuleLoadKind::DynamicImport, None, Some(source),
        ), Err(InterpreterError::ModuleLoweringFailed { error, .. }) if error.contains("import-options transport")));
        assert_eq!(core.heap.len(), heap_objects);
        assert_eq!(core.instructions_executed, work);
        assert_eq!(
            core.module_state
                .modules
                .get("captured:data")
                .unwrap()
                .status,
            ModuleRuntimeStatus::Evaluated
        );
    }

    #[test]
    fn declared_format_beats_a_json_looking_source_identity() {
        let mut core = core();
        let module = caller();
        let source = delivered_as(
            "export default 42;",
            ModuleSyntax::EsModule,
            "captured:data.json",
        );
        assert!(matches!(core.load_module_resolved(
            &module, "captured:data.json", ModuleLoadKind::Import(&json_attributes()), None, Some(source),
        ), Err(InterpreterError::ModuleLoweringFailed { error, .. }) if error.contains("ERR_IMPORT_ATTRIBUTE_TYPE_INCOMPATIBLE")));
        assert!(!core.module_state.modules.contains_key("captured:data.json"));
    }

    #[test]
    fn retained_import_attribute_payload_is_part_of_program_memory_admission() {
        let mut core = core();
        let mut module = caller();
        let id = "captured:attribute-budget";
        core.ensure_module_record(&module, id).unwrap();
        module.instructions = vec![Ir3Instruction::ImportModule {
            specifier: 0,
            dst: 1,
            import_attributes: ImportAttributes::default(),
        }];
        let without_attributes = InterpreterCore::retained_module_program_bytes(&module, id);
        core.config.max_total_memory_bytes = core
            .estimated_memory_bytes()
            .saturating_add(without_attributes);
        module.instructions[0] = Ir3Instruction::ImportModule {
            specifier: 0,
            dst: 1,
            import_attributes: json_attributes(),
        };
        assert!(matches!(
            core.retain_module_program(id, &module),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(
            core.module_state
                .modules
                .get(id)
                .unwrap()
                .compiled_module
                .is_none()
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn json_initialization_keeps_caller_state_and_cached_primitive_provenance() {
        let mut core = core();
        let module = caller();
        let source = delivered("42");
        core.current_module_specifier = Some(module.header.source_label.clone());
        core.seed_register(3, Value::Int(99)).unwrap();
        let label = Label::Custom {
            name: "classified-json-source".repeat(32),
            level: 9,
        };
        core.active_inline_callback_context_label = Some(label.clone());
        core.sync_estimated_memory_bytes().unwrap();
        let scope_depth = core.scope_chain.depth();
        let namespace = core
            .load_module_resolved(
                &module,
                "captured:data",
                ModuleLoadKind::Require,
                None,
                Some(source.clone()),
            )
            .unwrap();
        assert_eq!(
            core.current_module_specifier.as_deref(),
            Some("captured:caller")
        );
        assert_eq!(core.read_reg(3).unwrap(), Value::Int(99));
        assert_eq!(core.scope_chain.depth(), scope_depth);
        assert_eq!(core.module_snapshot_in_flight_bytes, 0);
        assert_eq!(
            core.active_inline_callback_context_label,
            Some(label.clone())
        );
        let record = core.module_state.modules.get("captured:data").unwrap();
        assert_eq!(record.exports.len(), 1);
        assert_eq!(
            record.exports.get(&JsString::from("default")),
            Some(&Value::Int(42))
        );
        assert!(record.compiled_module.is_none());
        assert_eq!(record.flow_label_ceiling, Some(label.clone()));
        let module_object = record.cjs_module_object.expect("shared CommonJS carrier");
        assert_eq!(core.own_property_label(module_object, "exports"), label);
        assert_eq!(
            core.heap[module_object.0 as usize].properties.get("loaded"),
            Some(&Value::Bool(true))
        );
        core.active_inline_callback_context_label = None;
        core.replace_pending_hostcall_result_label(None).unwrap();
        core.sync_estimated_memory_bytes().unwrap();
        // A cache hit does no parsing work, even with no instruction budget left.
        let instruction_budget = core.config.instruction_budget;
        core.config.instruction_budget = core.instructions_executed;
        assert_eq!(
            core.load_module_resolved(
                &module,
                "captured:data",
                ModuleLoadKind::Require,
                None,
                Some(source),
            )
            .unwrap(),
            namespace
        );
        core.config.instruction_budget = instruction_budget;
        assert_eq!(
            core.iterator_protocol_property(
                Some(&module),
                module_object,
                &RuntimePropertyKey::String(JsString::from("exports")),
                Value::Object(module_object),
            )
            .unwrap(),
            Value::Int(42)
        );
        assert_eq!(core.pending_hostcall_result_label, Some(label));
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn custom_flow_ceiling_replacement_is_admitted_before_cache_mutation() {
        let mut core = core();
        core.ensure_module_record(&caller(), "captured:data")
            .unwrap();
        let previous = Label::Custom {
            name: "initial-json-origin".repeat(8),
            level: 8,
        };
        core.set_module_flow_label_ceiling("captured:data", &previous)
            .unwrap();
        let baseline = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = baseline;
        let replacement = Label::Custom {
            name: "larger-json-origin".repeat(128),
            level: 9,
        };
        assert!(matches!(
            core.set_module_flow_label_ceiling("captured:data", &replacement),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(
            core.module_state
                .modules
                .get("captured:data")
                .unwrap()
                .flow_label_ceiling,
            Some(previous)
        );
        assert_eq!(core.estimated_memory_bytes(), baseline);
        assert_eq!(core.recompute_estimated_memory_bytes(), baseline);
        assert_eq!(core.json_parse_temporary_bytes, 0);
    }

    #[test]
    fn json_failure_replay_keeps_its_label_and_import_does_not_use_require_cache() {
        let mut core = core();
        let module = caller();
        let source = delivered("[1,]");
        let label = Label::Custom {
            name: "classified-json-syntax".repeat(32),
            level: 9,
        };
        core.active_inline_callback_context_label = Some(label.clone());
        core.sync_estimated_memory_bytes().unwrap();
        assert!(matches!(
            core.load_module_resolved(
                &module,
                "captured:data",
                ModuleLoadKind::Require,
                None,
                Some(source.clone()),
            ),
            Err(InterpreterError::UncaughtException { .. })
        ));
        assert_eq!(core.pending_exception_label, label);
        core.replace_pending_abrupt_slots(None, None).unwrap();
        core.active_inline_callback_context_label = None;
        core.replace_pending_hostcall_result_label(None).unwrap();
        core.sync_estimated_memory_bytes().unwrap();
        assert!(matches!(
            core.load_module_resolved(
                &module,
                "captured:data",
                ModuleLoadKind::Require,
                None,
                Some(source.clone()),
            ),
            Err(InterpreterError::UncaughtException { value })
                if value.starts_with("SyntaxError: ")
        ));
        assert_eq!(core.pending_exception_label, label);
        core.replace_pending_abrupt_slots(None, None).unwrap();
        assert!(matches!(
            core.load_module_resolved(
                &module,
                "captured:data",
                ModuleLoadKind::Import(&ImportAttributes::default()),
                None,
                Some(source),
            ),
            Err(InterpreterError::ModuleLoweringFailed { error, .. })
                if error.contains("ERR_IMPORT_ATTRIBUTE_MISSING")
        ));
        assert!(core.pending_exception.is_none());
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}
