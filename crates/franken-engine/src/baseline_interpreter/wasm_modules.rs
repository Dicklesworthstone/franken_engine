//! Numeric WebAssembly modules from authorized resolver or filesystem imports.
//!
//! This route executes the native Rust VM, not the constant-body ABI adapter.
//! One realm owns each instance and its conservative state label. No host
//! functions, reference tables, or public memory/global objects are supplied.

use super::wasm_filesystem::{JsWasmOrigin, JsWasmSource};
use super::*;
use crate::wasm_runtime_lane::memory_pool::WasmMemoryPool;
use crate::wasm_runtime_lane::numeric::{
    OwnedWasmNumericInstance, WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVm,
    WasmNumericVmError, WasmStateError,
};
use crate::wasm_runtime_lane::work_pool::WasmWorkPool;
use crate::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature, WasmValueType};

// The VM derives the activation reservation from these limits and its actual
// private frame/value sizes, including retained vector capacity in callers.
const MAX_CALL_DEPTH: u32 = 64;
const MAX_CONTROL_DEPTH: usize = 128;
const MAX_LIVE_VALUES: usize = 4096;

#[derive(Debug)]
struct JsWasmExport {
    name: String,
    signature: Arc<WasmFunctionSignature>,
}

#[derive(Debug)]
pub(super) struct JsWasmModule {
    realm_generation: u64,
    origin: JsWasmOrigin,
    canonical_specifier: String,
    exports: BTreeMap<u32, Arc<JsWasmExport>>,
    bindings: Vec<(String, u32)>,
    activation_bytes: u64,
    instance: RefCell<OwnedWasmNumericInstance>,
    state_label: RefCell<Label>,
}

impl InterpreterCore {
    pub(super) fn wasm_load_error(
        specifier: &str,
        error: impl std::fmt::Display,
    ) -> InterpreterError {
        InterpreterError::ModuleLoweringFailed {
            specifier: specifier.to_string(),
            error: format!("numeric Wasm module refused: {error}"),
        }
    }

    /// A callable pins immutable code but never pins permission. Consult the
    /// current grants and the captured origin's authority, including after
    /// guest ToPrimitive conversions that may revoke or replace that authority.
    fn authorize_wasm_module(&mut self, wasm: &JsWasmModule) -> Result<(), InterpreterError> {
        self.authorize_wasm_identity(
            wasm.realm_generation,
            &wasm.origin,
            &wasm.canonical_specifier,
        )
    }

    fn authorize_wasm_identity(
        &mut self,
        realm_generation: u64,
        origin: &JsWasmOrigin,
        canonical_specifier: &str,
    ) -> Result<(), InterpreterError> {
        if realm_generation != self.generated_function_realm_generation {
            return Err(Self::wasm_load_error(
                canonical_specifier,
                "stale realm handle",
            ));
        }
        self.authorize_wasm_capabilities()?;
        let (request, record_id, content_hash) = match origin {
            JsWasmOrigin::Installed {
                request,
                record_id,
                content_hash,
            } => (request, record_id, *content_hash),
            JsWasmOrigin::Filesystem {
                canonical_root,
                content_hash,
            } => {
                return self.authorize_filesystem_wasm(
                    canonical_specifier,
                    canonical_root,
                    *content_hash,
                );
            }
        };
        let installed = self
            .module_resolver
            .as_ref()
            .ok_or_else(|| Self::wasm_load_error(canonical_specifier, "no installed resolver"))?;
        let current = installed
            .resolver
            .resolve_shared(request, &installed.context)
            .map_err(|error| Self::wasm_load_error(canonical_specifier, error))?;
        let current = current.module;
        if current.record.source.len() as u64
            > self.config.module_parser_options.budget.max_source_bytes
        {
            return Err(Self::wasm_load_error(
                canonical_specifier,
                "resolved source exceeds its byte budget",
            ));
        }
        self.check_temporary_memory_budget(Self::estimate_string_bytes(&current.record.source))?;
        if current.request_specifier != request.specifier
            || current.canonical_specifier != canonical_specifier
            || current.record.id != record_id.as_str()
            || current.record.syntax != ModuleSyntax::Wasm
            || current.content_hash != content_hash
            || current.record.canonical_hash() != content_hash
            || !crate::module_resolver::wasm_module_required_capabilities()
                .is_subset(&current.record.required_capabilities)
        {
            return Err(Self::wasm_load_error(
                canonical_specifier,
                "resolved identity or source changed",
            ));
        }
        if let Some(missing) = current
            .record
            .required_capabilities
            .difference(&self.config.granted_capabilities)
            .next()
        {
            return Err(InterpreterError::CapabilityDenied {
                capability: missing.to_string(),
            });
        }
        Ok(())
    }

    pub(super) fn authorize_wasm_namespace(
        &mut self,
        resolved: &str,
        style: ImportStyle,
    ) -> Result<(), InterpreterError> {
        if style != ImportStyle::Import {
            return Err(Self::wasm_load_error(resolved, "Wasm requires an ESM import"));
        }
        self.authorize_wasm_capabilities()?;
        let key = format!("{}:{resolved}", self.generated_function_realm_generation);
        if let Some(wasm) = self.module_state.wasm_modules.get(&key).cloned() {
            self.authorize_wasm_module(&wasm)?;
        }
        Ok(())
    }

    /// All instances spend one non-refillable run allotment. Debit intervening
    /// JS work before entry, then account accepted Wasm charges on EVERY exit,
    /// including traps and cancellation. A new export never gets fresh fuel.
    fn prepare_wasm_work(&mut self) -> Result<(WasmWorkPool, u64), InterpreterError> {
        let used = self
            .instructions_executed
            .saturating_add(self.native_hole_reads.get());
        let remaining = self.config.instruction_budget.saturating_sub(used);
        let pool = self
            .module_state
            .wasm_work_pool
            .get_or_insert_with(|| WasmWorkPool::new(self.config.instruction_budget))
            .clone();
        let debit = pool.remaining().saturating_sub(remaining);
        pool.charge(debit)
            .map_err(|_| InterpreterError::BudgetExhausted {
                executed: used,
                budget: self.config.instruction_budget,
            })?;
        let before = pool.remaining();
        Ok((pool, before))
    }

    fn finish_wasm_work(&mut self, pool: &WasmWorkPool, before: u64) {
        self.instructions_executed = self
            .instructions_executed
            .saturating_add(before.saturating_sub(pool.remaining()));
    }

    fn charge_wasm_boundary_work(&mut self, work: u64) -> Result<(), InterpreterError> {
        let (pool, before) = self.prepare_wasm_work()?;
        let debit = pool.charge(work);
        self.finish_wasm_work(&pool, before);
        debit.map_err(|_| InterpreterError::BudgetExhausted {
            executed: self
                .instructions_executed
                .saturating_add(self.native_hole_reads.get()),
            budget: self.config.instruction_budget,
        })
    }

    fn wasm_numeric_result(value: WasmBoundaryValue) -> Value {
        match value {
            WasmBoundaryValue::I32(value) => Value::Int(i64::from(value)),
            WasmBoundaryValue::I64(value) => Value::BigInt(Arc::from(value.to_string())),
            WasmBoundaryValue::F32Bits(value) => {
                Value::Float(Float64::new(f64::from(f32::from_bits(value))))
            }
            WasmBoundaryValue::F64Bits(value) => Value::Float(Float64::new(f64::from_bits(value))),
        }
    }

    /// Exported Wasm functions return undefined, one primitive, or a fresh
    /// ordinary Array for multiple results. Build directly from the native
    /// result iterator: the invocation reservation already owns those values,
    /// and each published array property uses ordinary heap admission.
    fn wasm_export_result(
        &mut self,
        results: Vec<WasmBoundaryValue>,
        label: &Label,
    ) -> Result<Value, InterpreterError> {
        let length = results.len();
        let mut values = results.into_iter();
        match length {
            0 => Ok(Value::Undefined),
            1 => Ok(Self::wasm_numeric_result(values.next().expect("one result"))),
            _ => {
                // Projection is native work too; a large result signature
                // must not turn one JS call into unmetered array construction.
                self.charge_wasm_boundary_work(length as u64)?;
                let array = self.alloc_array_with_length(length as u64)?;
                self.join_object_mutation_label(array, label)?;
                for (index, value) in values.enumerate() {
                    self.set_object_property(
                        array,
                        index.to_string(),
                        Self::wasm_numeric_result(value),
                    )?;
                }
                Ok(Value::Object(array))
            }
        }
    }

    fn wasm_execution_error(&mut self, error: WasmNumericVmError) -> InterpreterError {
        match error {
            WasmNumericVmError::InstructionBudgetExceeded { .. }
            | WasmNumericVmError::State(WasmStateError::Host(WasmHostError::WorkPool(_))) => {
                InterpreterError::BudgetExhausted {
                    executed: self
                        .instructions_executed
                        .saturating_add(self.native_hole_reads.get()),
                    budget: self.config.instruction_budget,
                }
            }
            WasmNumericVmError::State(WasmStateError::Host(
                WasmHostError::ExecutionCancelled
                | WasmHostError::Cancelled
                | WasmHostError::MemoryPoolRevoked,
            )) => InterpreterError::Cancelled,
            WasmNumericVmError::CallDepthExceeded { max } => InterpreterError::StackOverflow {
                depth: max as usize + 1,
                max: max as usize,
            },
            WasmNumericVmError::StackLimitExceeded { .. }
            | WasmNumericVmError::LiveValueLimitExceeded { .. }
            | WasmNumericVmError::LocalLimitExceeded { .. }
            | WasmNumericVmError::ControlDepthExceeded { .. }
            | WasmNumericVmError::State(WasmStateError::LimitExceeded { .. })
            | WasmNumericVmError::State(WasmStateError::AllocationFailed { .. })
            | WasmNumericVmError::State(WasmStateError::Host(
                WasmHostError::MemoryPoolExhausted { .. },
            )) => self.memory_budget_error(
                self.config.max_total_memory_bytes.saturating_add(1),
                self.heap_object_count_u32(),
            ),
            error @ (WasmNumericVmError::IntegerDivideByZero { .. }
            | WasmNumericVmError::IntegerOverflow { .. }
            | WasmNumericVmError::Unreachable { .. }
            | WasmNumericVmError::State(WasmStateError::MemoryOutOfBounds { .. })
            | WasmNumericVmError::State(WasmStateError::DataSourceOutOfBounds {
                ..
            })) => self.throw_js_error("Error", format!("WebAssembly trap: {error}")),
            error => Self::wasm_load_error("<wasm invocation>", error),
        }
    }

    pub(super) fn load_wasm_module(
        &mut self,
        module: &Ir3Module,
        resolved: &str,
        style: ImportStyle,
        attributes: &ImportAttributes,
        delivered: Option<&SharedResolvedModule>,
        import_bound: Option<&Label>,
    ) -> Result<Value, InterpreterError> {
        if style != ImportStyle::Import {
            return Err(Self::wasm_load_error(
                resolved,
                "Wasm requires an ESM import",
            ));
        }
        let label = self.clone_active_execution_context_label()?;
        Self::check_import_flow_bound(resolved, &label, import_bound)?;
        self.set_module_flow_label_ceiling(resolved, &label)?;
        let (origin, source) = self.prepare_wasm_source(resolved, attributes, delivered)?;
        let key = format!("{}:{resolved}", self.generated_function_realm_generation);
        // Source-derived validation/control maps have linear size. Include
        // decoding, immutable program, namespace metadata and instance records
        // conservatively before allocating any of them.
        let mut retained = source
            .byte_len()
            .saturating_mul(256)
            .saturating_add((key.len() as u64).saturating_mul(8))
            .saturating_add(origin.retained_bytes())
            .saturating_add(Self::estimate_label_bytes(&label))
            .saturating_add(4096);
        let mut reserved = retained;
        self.json_reserve_temporary(reserved)?;
        let mut memory_bytes = 0;
        let prepared = (|| {
            let limits = WasmNumericLimits {
                max_module_bytes: usize::try_from(
                    self.config.module_parser_options.budget.max_source_bytes,
                )
                .unwrap_or(usize::MAX),
                max_call_depth: MAX_CALL_DEPTH
                    .min(u32::try_from(self.config.max_call_depth).unwrap_or(u32::MAX)),
                max_control_depth: MAX_CONTROL_DEPTH,
                max_live_values: MAX_LIVE_VALUES,
                max_stack_values: MAX_LIVE_VALUES,
                max_locals_per_call: MAX_LIVE_VALUES,
                max_instructions: self.config.instruction_budget,
                ..WasmNumericLimits::default()
            };
            let bytes = match &source {
                JsWasmSource::Resolver(source) => crate::wasm_runtime_lane::wasm_source_bytes(
                    source,
                    limits.max_module_bytes,
                )
                .map_err(|error| Self::wasm_load_error(resolved, error))?,
                JsWasmSource::Filesystem(bytes) => Cow::Borrowed(bytes.as_slice()),
            };
            let local_bytes = WasmNumericVm::expanded_local_bytes(&bytes, &limits)
                .map_err(|error| Self::wasm_load_error(resolved, error))?;
            self.json_reserve_temporary(local_bytes)?;
            reserved = reserved.saturating_add(local_bytes);
            retained = retained.saturating_add(local_bytes);
            let vm = Arc::new(
                WasmNumericVm::parse(&bytes, limits)
                    .map_err(|error| Self::wasm_load_error(resolved, error))?,
            );
            let activation_bytes = vm.activation_memory_envelope();
            self.json_reserve_temporary(activation_bytes)?;
            reserved = reserved.saturating_add(activation_bytes);
            memory_bytes = vm
                .javascript_memory_envelope()
                .map_err(|error| Self::wasm_load_error(resolved, error))?;
            self.json_reserve_temporary(memory_bytes)?;
            reserved = reserved.saturating_add(memory_bytes);
            let mut signatures = BTreeMap::<u32, Arc<WasmFunctionSignature>>::new();
            let mut exports = BTreeMap::new();
            let mut bindings = Vec::new();
            for name in vm.export_names() {
                let (function, type_id) = vm
                    .export_identity(name)
                    .map_err(|error| Self::wasm_load_error(resolved, error))?;
                let signature = if let Some(signature) = signatures.get(&type_id) {
                    Arc::clone(signature)
                } else {
                    let signature = vm
                        .export_signature(name)
                        .map_err(|error| Self::wasm_load_error(resolved, error))?;
                    if signature.params.len() > MAX_LIVE_VALUES
                        || signature.results.len() > MAX_LIVE_VALUES
                    {
                        return Err(Self::wasm_load_error(
                            resolved,
                            "export signature exceeds the activation budget",
                        ));
                    }
                    let signature = Arc::new(signature);
                    signatures.insert(type_id, Arc::clone(&signature));
                    signature
                };
                exports.entry(function).or_insert_with(|| {
                    Arc::new(JsWasmExport {
                        name: name.to_string(),
                        signature,
                    })
                });
                bindings.push((name.to_string(), function));
            }
            let mut imports = WasmHostImports::new(BTreeSet::new());
            let (pool, before) = self.prepare_wasm_work()?;
            imports
                .bind_work_pool(pool.clone())
                .map_err(|error| Self::wasm_load_error(resolved, error))?;
            imports
                .bind_memory_pool(WasmMemoryPool::new(memory_bytes / 65_536))
                .map_err(|error| Self::wasm_load_error(resolved, error))?;
            if let Some(token) = self.config.cancellation_token.clone() {
                imports
                    .bind_execution_cancellation(token, &self.trace_id)
                    .map_err(|error| Self::wasm_load_error(resolved, error))?;
            }
            self.authorize_wasm_identity(
                self.generated_function_realm_generation,
                &origin,
                resolved,
            )?;
            let native = vm.instantiate_owned_with_imports(imports);
            self.finish_wasm_work(&pool, before);
            let native = match native {
                Ok(native) => native,
                Err(error) => {
                    let error = self.wasm_execution_error(error);
                    if matches!(error, InterpreterError::UncaughtException { .. }) {
                        self.join_pending_exception_label(&label)?;
                    }
                    return Err(error);
                }
            };
            Ok(JsWasmModule {
                realm_generation: self.generated_function_realm_generation,
                origin,
                canonical_specifier: resolved.to_string(),
                exports,
                bindings,
                activation_bytes,
                instance: RefCell::new(native),
                state_label: RefCell::new(label.clone()),
            })
        })();
        self.json_release_temporary(reserved);
        let wasm = Rc::new(prepared?);
        let retained = retained.saturating_add(memory_bytes);
        let previous = self.module_state.retained_wasm_bytes;
        self.apply_memory_component_delta(previous, previous.saturating_add(retained))?;
        self.module_state.retained_wasm_bytes = previous.saturating_add(retained);
        self.module_state
            .wasm_modules
            .insert(key.clone(), Rc::clone(&wasm));
        for (name, index) in &wasm.bindings {
            let export = &wasm.exports[index];
            let function = Value::BuiltinFunction(BuiltinFunction {
                kind: BuiltinFunctionKind::WasmExport,
                module_specifier: key.clone().into(),
                iterator_handle: Some(*index),
                bound_object: None,
            });
            if let Some(backing) = self.ensure_function_own_property_object(module, &function)? {
                for (name, value) in [
                    ("name", Value::Str(JsString::from(index.to_string()))),
                    ("length", Value::Int(export.signature.params.len() as i64)),
                ] {
                    let property = RuntimePropertyKey::String(JsString::from(name));
                    self.set_object_runtime_property(backing, property.clone(), value)?;
                    self.set_own_property_attributes(
                        backing,
                        &property,
                        FUNCTION_NAME_LENGTH_ATTRIBUTES,
                    )?;
                }
            }
            self.publish_module_export(
                resolved,
                JsString::from(name.as_str()),
                function,
                label.clone(),
                ExportPublication::Own,
            )?;
        }
        self.sort_module_namespace_keys(resolved)?;
        let record = self
            .module_state
            .modules
            .get_mut(resolved)
            .expect("loader created Wasm namespace");
        record.status = ModuleRuntimeStatus::Evaluated;
        Ok(Value::Object(record.namespace_object))
    }

    pub(super) fn dispatch_wasm_export(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let end =
            args.start
                .checked_add(args.count)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
        let observation = self.begin_property_observation(args.start..end)?;
        let outcome = self.call_wasm_export(module, builtin, args);
        self.finish_property_read_observation(observation, outcome)
    }

    fn call_wasm_export(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let wasm = self
            .module_state
            .wasm_modules
            .get(&*builtin.module_specifier)
            .cloned()
            .ok_or_else(|| {
                Self::wasm_load_error("<wasm invocation>", "unknown or expired instance")
            })?;
        self.authorize_wasm_module(&wasm)?;
        let export = builtin
            .iterator_handle
            .and_then(|id| wasm.exports.get(&id))
            .cloned()
            .ok_or_else(|| {
                Self::wasm_load_error(&wasm.canonical_specifier, "unknown export identity")
            })?;
        self.json_reserve_temporary(wasm.activation_bytes)?;
        let outcome = (|| {
            let mut label = Some(self.join_arg_range_label(args)?);
            let mut arguments = Vec::with_capacity(export.signature.params.len());
            for (index, ty) in export.signature.params.iter().enumerate() {
                let value = self
                    .builtin_arg(args, index as u32)?
                    .unwrap_or(Value::Undefined);
                let value = match ty {
                    WasmValueType::I64 => {
                        let primitive = if value.is_object_like() {
                            self.coerce_runtime_primitive(Some(module), value, false)?
                        } else {
                            value
                        };
                        self.observe_scoped_callback_result()?;
                        let Value::BigInt(digits) = self.coerce_to_bigint(primitive)? else {
                            unreachable!("ToBigInt returns BigInt")
                        };
                        self.charge_wasm_boundary_work(digits.len() as u64)?;
                        let text = bigint_ops::as_int_n(64, &digits).map_err(|error| {
                            self.throw_js_error("RangeError", error.message().to_string())
                        })?;
                        WasmBoundaryValue::I64(text.parse().expect("64-bit BigInt narrowing"))
                    }
                    ty => {
                        let number =
                            self.builtin_argument_to_number(Some(module), value, &mut label)?;
                        match ty {
                            WasmValueType::I32 => WasmBoundaryValue::I32(Self::js_to_int32(number)),
                            WasmValueType::F32 => {
                                WasmBoundaryValue::F32Bits((number as f32).to_bits())
                            }
                            WasmValueType::F64 => WasmBoundaryValue::F64Bits(number.to_bits()),
                            WasmValueType::I64 => unreachable!(),
                        }
                    }
                };
                arguments.push(value);
            }
            self.join_into_pending_hostcall_result_label(label)?;
            self.observe_scoped_callback_result()?;
            // ToPrimitive may call this same export or change resolver policy.
            // No instance borrow is live across any guest conversion callback.
            self.authorize_wasm_module(&wasm)?;
            let invocation_label = self.clone_active_execution_context_label()?;
            {
                let mut state_label = wasm.state_label.borrow_mut();
                // Label::join is max under the complete Ord, including custom
                // label tie-breaks. Move the winner without cloning the loser.
                if invocation_label > *state_label {
                    let old = Self::estimate_label_bytes(&state_label);
                    let next = Self::estimate_label_bytes(&invocation_label);
                    self.apply_memory_component_delta(old, next)?;
                    self.module_state.retained_wasm_bytes = self
                        .module_state
                        .retained_wasm_bytes
                        .saturating_sub(old)
                        .saturating_add(next);
                    *state_label = invocation_label;
                }
                self.check_temporary_memory_budget(Self::estimate_label_bytes(&state_label))?;
                self.join_into_pending_hostcall_result_label(Some(state_label.clone()))?;
            }
            // Taint is committed before execution: a write followed by a trap
            // leaves both the state and its confidentiality high-water label.
            let (pool, before) = self.prepare_wasm_work()?;
            let result = wasm
                .instance
                .borrow_mut()
                .call_export(&export.name, &arguments);
            self.finish_wasm_work(&pool, before);
            let execution = result.map_err(|error| self.wasm_execution_error(error))?;
            self.wasm_export_result(execution.results, &wasm.state_label.borrow())
        })();
        self.json_release_temporary(wasm.activation_bytes);
        outcome
    }
}
