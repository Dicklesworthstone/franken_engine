use super::*;

impl InterpreterCore {
    pub(super) fn eval_arith_values(
        left: &Value,
        right: &Value,
        operator: &str,
    ) -> Result<Value, InterpreterError> {
        let bigint_op = if operator == "sub" {
            bigint_ops::BigIntBinaryOp::Sub
        } else {
            bigint_ops::BigIntBinaryOp::Mul
        };
        if let Some(result) = Self::bigint_operands(left, right, bigint_op) {
            return result;
        }
        if let (Value::Int(left_int), Value::Int(right_int)) = (left, right) {
            return match operator {
                "sub" => Ok(js_int_sub(*left_int, *right_int)),
                "mul" => Ok(js_int_mul(*left_int, *right_int)),
                _ => Err(InterpreterError::TypeError {
                    expected: "sub or mul".to_string(),
                    got: operator.to_string(),
                }),
            };
        }
        let left_number =
            Self::coerce_to_float(left).ok_or_else(|| InterpreterError::TypeError {
                expected: "number".to_string(),
                got: format!("{} {} {}", left.type_name(), operator, right.type_name()),
            })?;
        let right_number =
            Self::coerce_to_float(right).ok_or_else(|| InterpreterError::TypeError {
                expected: "number".to_string(),
                got: format!("{} {} {}", left.type_name(), operator, right.type_name()),
            })?;
        let result = match operator {
            "sub" => left_number - right_number,
            "mul" => left_number * right_number,
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "sub or mul".to_string(),
                    got: operator.to_string(),
                });
            }
        };
        Self::number_value(result)
    }

    pub(super) fn eval_div_values(left: &Value, right: &Value) -> Result<Value, InterpreterError> {
        if let Some(result) = Self::bigint_operands(left, right, bigint_ops::BigIntBinaryOp::Div) {
            return result;
        }
        let left_number =
            Self::coerce_to_float(left).ok_or_else(|| InterpreterError::TypeError {
                expected: "number".to_string(),
                got: format!("{} / {}", left.type_name(), right.type_name()),
            })?;
        let right_number =
            Self::coerce_to_float(right).ok_or_else(|| InterpreterError::TypeError {
                expected: "number".to_string(),
                got: format!("{} / {}", left.type_name(), right.type_name()),
            })?;
        Self::number_value(left_number / right_number)
    }

    pub(super) fn number_value(value: f64) -> Result<Value, InterpreterError> {
        // bd-9vouw.2: preserve -0 and keep Value::Int to the safe-integer
        // range, exactly like the main evaluator.
        Ok(js_number_to_value(value))
    }

    /// A BigInt operation's value, or its RangeError (bd-9vouw.54).
    pub(super) fn bigint_result(
        result: Result<String, bigint_ops::BigIntError>,
    ) -> Result<Value, InterpreterError> {
        result
            .map(|digits| Value::BigInt(Arc::from(digits)))
            .map_err(|error| InterpreterError::RangeError {
                message: error.message().to_string(),
            })
    }

    /// `op` on two numeric operands when either is a BigInt: both BigInt
    /// computes, a BigInt mixed with anything else is a TypeError (ES2020
    /// 12.15.3 step 7 / 6.1.6.2). `None` when neither operand is a BigInt.
    pub(super) fn bigint_operands(
        left: &Value,
        right: &Value,
        op: bigint_ops::BigIntBinaryOp,
    ) -> Option<Result<Value, InterpreterError>> {
        match (left, right) {
            (Value::BigInt(x), Value::BigInt(y)) => {
                Some(Self::bigint_result(bigint_ops::binary(op, x, y)))
            }
            (Value::BigInt(_), other) | (other, Value::BigInt(_)) => {
                Some(Err(InterpreterError::TypeError {
                    expected: "BigInt operands on both sides (cannot mix BigInt and other types)"
                        .to_string(),
                    got: other.type_name().to_string(),
                }))
            }
            _ => None,
        }
    }

    /// IsLessThan-style order when a BigInt is involved (ES2020 7.2.13
    /// steps 3-4): `Some(None)` is undefined (NaN or an unparsable string).
    pub(super) fn bigint_relational_order(
        left: &Value,
        right: &Value,
    ) -> Result<Option<Option<Ordering>>, InterpreterError> {
        let against = |bigint: &str, other: &Value| -> Result<Option<Ordering>, InterpreterError> {
            match other {
                Value::BigInt(other) => Ok(Some(bigint_ops::compare(bigint, other))),
                Value::Str(text) => Ok(bigint_ops::from_string(text.as_ref())
                    .map(|other| bigint_ops::compare(bigint, &other))),
                other => {
                    let number = Self::coerce_to_float(other).ok_or_else(|| {
                        InterpreterError::TypeError {
                            expected: "comparable primitive".to_string(),
                            got: other.type_name().to_string(),
                        }
                    })?;
                    Ok(bigint_ops::compare_with_number(bigint, number))
                }
            }
        };
        match (left, right) {
            (Value::BigInt(x), other) => against(x, other).map(Some),
            (other, Value::BigInt(y)) => {
                against(y, other).map(|ordering| Some(ordering.map(Ordering::reverse)))
            }
            _ => Ok(None),
        }
    }

    /// Abstract equality of a BigInt with a non-BigInt primitive (ES2020
    /// 7.2.14 steps 6-7 and 12-13).
    pub(super) fn bigint_loosely_equals(bigint: &str, other: &Value) -> bool {
        match other {
            Value::Str(text) => bigint_ops::from_string(text.as_ref())
                .is_some_and(|other| bigint_ops::compare(bigint, &other) == Ordering::Equal),
            Value::Int(_) | Value::Float(_) | Value::Bool(_) => {
                Self::coerce_to_float(other)
                    .and_then(|number| bigint_ops::compare_with_number(bigint, number))
                    == Some(Ordering::Equal)
            }
            _ => false,
        }
    }

    pub(super) fn add_bigint_decimal(lhs: &str, rhs: &str) -> String {
        let (lhs_neg, lhs_abs) = lhs
            .strip_prefix('-')
            .map_or((false, lhs), |rest| (true, rest));
        let (rhs_neg, rhs_abs) = rhs
            .strip_prefix('-')
            .map_or((false, rhs), |rest| (true, rest));

        if lhs_neg == rhs_neg {
            let sum = Self::add_unsigned_decimal(lhs_abs, rhs_abs);
            if lhs_neg && sum != "0" {
                format!("-{sum}")
            } else {
                sum
            }
        } else {
            match Self::cmp_unsigned_decimal(lhs_abs, rhs_abs) {
                std::cmp::Ordering::Equal => "0".to_string(),
                std::cmp::Ordering::Greater => {
                    let diff = Self::sub_unsigned_decimal(lhs_abs, rhs_abs);
                    if lhs_neg && diff != "0" {
                        format!("-{diff}")
                    } else {
                        diff
                    }
                }
                std::cmp::Ordering::Less => {
                    let diff = Self::sub_unsigned_decimal(rhs_abs, lhs_abs);
                    if rhs_neg && diff != "0" {
                        format!("-{diff}")
                    } else {
                        diff
                    }
                }
            }
        }
    }

    pub(super) fn add_unsigned_decimal(lhs: &str, rhs: &str) -> String {
        let mut carry = 0u8;
        let mut out = Vec::with_capacity(lhs.len().max(rhs.len()) + 1);
        let mut left = lhs.as_bytes().iter().rev();
        let mut right = rhs.as_bytes().iter().rev();

        loop {
            let l = left.next().map(|b| b.saturating_sub(b'0'));
            let r = right.next().map(|b| b.saturating_sub(b'0'));
            if l.is_none() && r.is_none() && carry == 0 {
                break;
            }
            let sum = l.unwrap_or(0) + r.unwrap_or(0) + carry;
            out.push(b'0' + (sum % 10));
            carry = sum / 10;
        }

        out.reverse();
        String::from_utf8(out).unwrap_or_else(|_| "0".to_string())
    }

    pub(super) fn sub_unsigned_decimal(lhs: &str, rhs: &str) -> String {
        let mut borrow = 0i16;
        let mut out = Vec::with_capacity(lhs.len());
        let left = lhs.as_bytes().iter().rev();
        let mut right = rhs.as_bytes().iter().rev();

        for l in left {
            let mut digit = i16::from(l.saturating_sub(b'0')) - borrow;
            let r = right
                .next()
                .map(|b| i16::from(b.saturating_sub(b'0')))
                .unwrap_or(0);
            if digit < r {
                digit += 10;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(b'0' + u8::try_from(digit - r).unwrap_or(0));
        }

        while out.len() > 1 && out.last() == Some(&b'0') {
            out.pop();
        }
        out.reverse();
        String::from_utf8(out).unwrap_or_else(|_| "0".to_string())
    }

    pub(super) fn cmp_unsigned_decimal(lhs: &str, rhs: &str) -> std::cmp::Ordering {
        let lhs = lhs.trim_start_matches('0');
        let rhs = rhs.trim_start_matches('0');
        let lhs = if lhs.is_empty() { "0" } else { lhs };
        let rhs = if rhs.is_empty() { "0" } else { rhs };
        lhs.len().cmp(&rhs.len()).then_with(|| lhs.cmp(rhs))
    }

    pub(super) fn abstract_eq_values(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Undefined, Value::Undefined)
            | (Value::Null, Value::Null)
            | (Value::Bool(_), Value::Bool(_))
            | (Value::Int(_), Value::Int(_))
            | (Value::BigInt(_), Value::BigInt(_))
            | (Value::Str(_), Value::Str(_))
            | (Value::Symbol(_), Value::Symbol(_))
            | (Value::Object(_), Value::Object(_))
            | (Value::Function(_), Value::Function(_))
            | (Value::Closure(_), Value::Closure(_))
            | (Value::Iterator(_), Value::Iterator(_))
            | (Value::GeneratorFunction(_), Value::GeneratorFunction(_))
            | (Value::Generator(_), Value::Generator(_))
            | (Value::Promise(_), Value::Promise(_))
            | (Value::BuiltinFunction(_), Value::BuiltinFunction(_)) => a == b,
            // Float == Float: NaN !== NaN, but -0 == +0
            (Value::Float(fa), Value::Float(fb)) => {
                let va = fa.inner();
                let vb = fb.inner();
                if va.is_nan() || vb.is_nan() {
                    false
                } else {
                    va == vb
                }
            }
            // Int == Float or Float == Int: numeric comparison
            (Value::Int(n), Value::Float(f)) | (Value::Float(f), Value::Int(n)) => {
                let fv = f.inner();
                if fv.is_nan() { false } else { *n as f64 == fv }
            }
            (Value::BigInt(bigint), other) | (other, Value::BigInt(bigint))
                if !matches!(other, Value::Null | Value::Undefined) =>
            {
                Self::bigint_loosely_equals(bigint, other)
            }
            (Value::Null, Value::Undefined) | (Value::Undefined, Value::Null) => true,
            // ES2020 §7.2.14: null/undefined are only == to each other, never
            // to numbers, strings, or booleans via numeric coercion.
            (Value::Null, _) | (_, Value::Null) => false,
            (Value::Undefined, _) | (_, Value::Undefined) => false,
            _ => match (Self::coerce_to_float(a), Self::coerce_to_float(b)) {
                (Some(lhs), Some(rhs)) => {
                    if lhs.is_nan() || rhs.is_nan() {
                        false
                    } else {
                        lhs == rhs
                    }
                }
                _ => false,
            },
        }
    }

    /// Dispatch number-related hostcalls: isNaN, isFinite, Number.isNaN, Number.isFinite.
    ///
    /// Hostcall capabilities:
    /// - `number:isNaN` — global isNaN() function (coerces to number first)
    /// - `number:isFinite` — global isFinite() function (coerces to number first)
    /// - `number:Number.isNaN` — Number.isNaN() (strict, no coercion)
    /// - `number:Number.isFinite` — Number.isFinite() (strict, no coercion)
    pub(super) fn dispatch_number_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let timestamp_ns = self.instructions_executed;
        let args_hash = self.hostcall_arguments_hash(args);
        let outcome = self.dispatch_number_hostcall_inner(cap, args);
        self.record_hostcall_telemetry(cap, args, timestamp_ns, args_hash, &outcome);
        outcome
    }

    pub(super) fn dispatch_number_hostcall_inner(
        &self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let arg0 = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };

        match cap {
            "number:isNaN" => {
                // Global isNaN: coerces argument to number, then checks NaN
                // isNaN(undefined) = true, isNaN("hello") = true
                let number = Self::coerce_to_float(&arg0).unwrap_or(f64::NAN);
                Ok(Value::Bool(number.is_nan()))
            }
            "number:isFinite" => {
                // Global isFinite: coerces argument to number, then checks finite
                // isFinite(undefined) = false, isFinite("123") = true
                let number = Self::coerce_to_float(&arg0).unwrap_or(f64::NAN);
                Ok(Value::Bool(number.is_finite()))
            }
            "number:Number.isNaN" => {
                // Number.isNaN: strict check, no coercion
                // Number.isNaN(undefined) = false, Number.isNaN(NaN) = true
                match arg0 {
                    Value::Float(f) => Ok(Value::Bool(f.inner().is_nan())),
                    _ => Ok(Value::Bool(false)),
                }
            }
            "number:Number.isFinite" => {
                // Number.isFinite: strict check, no coercion
                // Number.isFinite(undefined) = false, Number.isFinite(42) = true
                match arg0 {
                    Value::Int(_) => Ok(Value::Bool(true)), // All integers are finite
                    Value::Float(f) => Ok(Value::Bool(f.inner().is_finite())),
                    _ => Ok(Value::Bool(false)),
                }
            }
            "number:Number.isInteger" => {
                // Number.isInteger: strict check for integer value
                match arg0 {
                    Value::Int(_) => Ok(Value::Bool(true)),
                    Value::Float(f) => {
                        let v = f.inner();
                        Ok(Value::Bool(v.is_finite() && v.fract() == 0.0))
                    }
                    _ => Ok(Value::Bool(false)),
                }
            }
            "number:Number.isSafeInteger" => {
                // Number.isSafeInteger: integer in safe range
                match arg0 {
                    Value::Int(n) => {
                        // Safe integer range: -(2^53 - 1) to (2^53 - 1)
                        const MAX_SAFE: i64 = (1i64 << 53) - 1;
                        const MIN_SAFE: i64 = -MAX_SAFE;
                        Ok(Value::Bool((MIN_SAFE..=MAX_SAFE).contains(&n)))
                    }
                    Value::Float(f) => {
                        let v = f.inner();
                        if !v.is_finite() || v.fract() != 0.0 {
                            return Ok(Value::Bool(false));
                        }
                        const MAX_SAFE: f64 = ((1i64 << 53) - 1) as f64;
                        Ok(Value::Bool((-MAX_SAFE..=MAX_SAFE).contains(&v)))
                    }
                    _ => Ok(Value::Bool(false)),
                }
            }
            _ => {
                // Unknown number hostcall
                Ok(Value::Undefined)
            }
        }
    }

    /// Dispatch console hostcalls: console.log, console.error, console.warn, console.info.
    ///
    /// Hostcall capabilities:
    /// - `console:log` — console.log(...args)
    /// - `console:error` — console.error(...args)
    /// - `console:warn` — console.warn(...args)
    ///
    /// Console output is captured in `self.console_output` for deterministic replay.
    /// Every call is also recorded into the hostcall telemetry recorder
    /// (bd-qi3hs) post-dispatch with a deterministic timestamp.
    pub(super) fn dispatch_console_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        let timestamp_ns = self.instructions_executed;
        let args_hash = self.hostcall_arguments_hash(args);
        let outcome = self.dispatch_console_hostcall_inner(cap, args, module);
        self.record_hostcall_telemetry(cap, args, timestamp_ns, args_hash, &outcome);
        outcome
    }

    pub(super) fn dispatch_console_hostcall_inner(
        &mut self,
        cap: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        let level = match cap {
            // Node's debug and dirxml are log.
            "console:log" | "console:debug" | "console:dirxml" => ConsoleLevel::Log,
            "console:error" => ConsoleLevel::Error,
            "console:warn" => ConsoleLevel::Warn,
            "console:info" => ConsoleLevel::Info,
            other => {
                let Some(method) = other
                    .strip_prefix("console:")
                    .filter(|method| CONSOLE_EXTRA_METHODS.contains(method))
                else {
                    return Ok(Value::Undefined); // Unknown console method
                };
                self.check_console_confidentiality(args, cap)?;
                self.console_extra_method(method, args, module)?;
                return Ok(Value::Undefined);
            }
        };

        self.check_console_confidentiality(args, cap)?;

        // Node's `util.format`: strings as-is, everything else through
        // `util.inspect`, `%` directives in a leading string.
        let message = self.console_format_arguments(module, args)?;

        self.push_indented_console_output(level, message)?;

        self.emit_witness(
            WitnessEventKind::HostcallDispatched,
            Some(&format!(
                "console:{}",
                match level {
                    ConsoleLevel::Log => "log",
                    ConsoleLevel::Error => "error",
                    ConsoleLevel::Warn => "warn",
                    ConsoleLevel::Info => "info",
                }
            )),
        );

        Ok(Value::Undefined)
    }

    pub(super) fn resolve_accessor_get(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        match value {
            Value::Accessor { get: Some(get), .. } => {
                let (value, label) = self.invoke_inline_method_call_with_argument_label(
                    module,
                    get.as_ref().clone(),
                    receiver,
                    Vec::new(),
                    None,
                )?;
                let label = self
                    .pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public)
                    .join(&label);
                self.replace_pending_hostcall_result_label(Some(label))?;
                Ok(value)
            }
            Value::Accessor { get: None, .. } => Ok(Value::Undefined),
            other => Ok(other),
        }
    }

    pub(super) fn resolve_accessor_set(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
        receiver: Value,
        assigned: Value,
    ) -> Result<bool, InterpreterError> {
        match value {
            Value::Accessor { set: Some(set), .. } => {
                // A property write already joined the assigned scalar's
                // label into its receiver. Carry that context into the setter
                // frame, where the value-only callback arguments otherwise
                // start Public (including inherited setters, bd-9vouw.280).
                // Reflect.set may supply any receiver, including a primitive
                // or null: an inherited setter still receives that exact this.
                let receiver_object = self.own_property_holder(module, &receiver, false)?;
                let argument_label = receiver_object
                    .and_then(|object| self.object_mutation_labels.get(&object))
                    .map(|label| {
                        self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
                        Ok::<_, InterpreterError>(label.clone())
                    })
                    .transpose()?;
                let (_, label) = self.invoke_inline_method_call_with_argument_label(
                    module,
                    set.as_ref().clone(),
                    receiver,
                    vec![assigned],
                    argument_label,
                )?;
                let label = self
                    .pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public)
                    .join(&label);
                self.replace_pending_hostcall_result_label(Some(label))?;
                self.observe_scoped_callback_result()?;
                Ok(true)
            }
            Value::Accessor { set: None, .. } => Ok(false),
            _ => Ok(false),
        }
    }

    pub(super) fn define_accessor_property(
        &mut self,
        object_id: ObjectId,
        key: RuntimePropertyKey,
        func: Value,
        kind: AccessorKind,
    ) -> Result<(), InterpreterError> {
        self.validate_executable_property_key(&key)?;
        if self.is_import_meta_object(object_id)? && key.as_str() != Some("resolve") {
            return Err(InterpreterError::TypeError {
                expected: "read-only import.meta contract field".to_string(),
                got: key
                    .as_str()
                    .map_or_else(|| key.diagnostic(), |key| format!("import.meta.{key}")),
            });
        }
        let heap_index = object_id.0 as usize;
        let object = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if !object.extensible() && !object.contains_own_runtime_property(&key) {
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
        validate_symbol_value(&self.symbol_state, &func).map_err(|got| {
            InterpreterError::TypeError {
                expected: "resolved Symbol value".to_string(),
                got,
            }
        })?;

        if let RuntimePropertyKey::Symbol(symbol) = key {
            let (get, set) = match object
                .properties
                .baseline_symbol_property(core_symbol_id(symbol))
            {
                Some(BaselineSymbolProperty::Accessor { get, set }) => (get.clone(), set.clone()),
                _ => (None, None),
            };
            let property = match kind {
                AccessorKind::Get => BaselineSymbolProperty::Accessor {
                    get: Some(func),
                    set,
                },
                AccessorKind::Set => BaselineSymbolProperty::Accessor {
                    get,
                    set: Some(func),
                },
            };
            let previous_property_bytes =
                Self::estimate_ordered_property_map_bytes_nonalloc(&object.properties);
            let next_property_bytes = Self::estimate_projected_symbol_property_map_bytes(
                &object.properties,
                symbol,
                &property,
            );
            self.check_temporary_memory_budget(previous_property_bytes.max(next_property_bytes))?;
            let mut projected_properties = object.properties.clone();
            projected_properties.insert_baseline_symbol_property(core_symbol_id(symbol), property);
            let requested_bytes = self
                .estimated_memory_bytes
                .saturating_sub(previous_property_bytes)
                .saturating_add(next_property_bytes);
            self.mutate_heap(|heap| heap[heap_index].properties = projected_properties);
            self.estimated_memory_bytes = requested_bytes;
            self.gc_write_barrier(object_id);
            return Ok(());
        }

        let RuntimePropertyKey::String(key) = key else {
            unreachable!("RuntimePropertyKey variants are exhaustive")
        };
        if object.is_array && key.as_str() == Some("length") {
            return Err(InterpreterError::RangeError {
                message: "invalid array length accessor".to_string(),
            });
        }
        let mapped_key = key
            .as_str()
            .filter(|key| self.mapped_argument_binding(object_id, key).is_some())
            .map(str::to_string);
        let (get, set) = match object.properties.get_exact(&key) {
            Some(Value::Accessor { get, set }) => (get.clone(), set.clone()),
            _ => (None, None),
        };
        let arc_value_bytes = u64::try_from(std::mem::size_of::<Value>())
            .unwrap_or(u64::MAX)
            .saturating_add(
                u64::try_from(2usize.saturating_mul(std::mem::size_of::<usize>()))
                    .unwrap_or(u64::MAX),
            );
        let new_edge_bytes =
            arc_value_bytes.saturating_add(Self::estimate_execution_seed_value_bytes(&func));
        let preserved_edge_bytes = match kind {
            AccessorKind::Get => set.as_ref(),
            AccessorKind::Set => get.as_ref(),
        }
        .map_or(0, |endpoint| {
            arc_value_bytes.saturating_add(Self::estimate_execution_seed_value_bytes(endpoint))
        });
        let prospective_accessor_bytes = new_edge_bytes.saturating_add(preserved_edge_bytes);
        let has_exact_only_properties = object.properties.exact_len() != object.properties.len();
        let ordinary_key = key.as_str().filter(|_| !has_exact_only_properties);
        let (requested_bytes, construction_peak) = match ordinary_key {
            // An ordinary key leaves every other entry's estimate as it was
            // (no exact key order before or after), so the request moves by
            // this entry's own change. Estimating the whole map before and
            // after made defining N accessors on one object O(N^2): a class
            // with many getters, a bundle's export getters (bd-9vouw.335).
            Some(ordinary) => {
                let entry_base = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
                    .saturating_add(Self::estimate_string_bytes(ordinary).saturating_mul(2));
                let previous_entry = object.properties.get(ordinary).map_or(0, |value| {
                    entry_base.saturating_add(Self::estimate_execution_seed_value_bytes(value))
                });
                let next_entry = entry_base.saturating_add(prospective_accessor_bytes);
                let requested_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(previous_entry)
                    .saturating_add(next_entry);
                #[cfg(debug_assertions)]
                {
                    let previous_property_bytes =
                        Self::estimate_ordered_property_map_bytes_nonalloc(&object.properties);
                    let next_property_bytes = Self::estimate_projected_string_accessor_map_bytes(
                        &object.properties,
                        &key,
                        prospective_accessor_bytes,
                    );
                    debug_assert_eq!(
                        requested_bytes,
                        self.estimated_memory_bytes
                            .saturating_sub(previous_property_bytes)
                            .saturating_add(next_property_bytes),
                        "an accessor entry's own delta is the whole map's (bd-9vouw.335)"
                    );
                }
                (
                    requested_bytes,
                    new_edge_bytes.saturating_add(Self::estimate_string_bytes(ordinary)),
                )
            }
            None => {
                let previous_property_bytes =
                    Self::estimate_ordered_property_map_bytes_nonalloc(&object.properties);
                let next_property_bytes = Self::estimate_projected_string_accessor_map_bytes(
                    &object.properties,
                    &key,
                    prospective_accessor_bytes,
                );
                (
                    self.estimated_memory_bytes
                        .saturating_sub(previous_property_bytes)
                        .saturating_add(next_property_bytes),
                    new_edge_bytes
                        .saturating_add(previous_property_bytes)
                        .max(next_property_bytes),
                )
            }
        };
        self.check_temporary_memory_budget(construction_peak)?;
        if self.memory_request_exceeds_budget(requested_bytes, self.config.max_total_memory_bytes) {
            return Err(self.memory_budget_error(requested_bytes, self.heap_object_count_u32()));
        }
        let accessor = match kind {
            AccessorKind::Get => Value::Accessor {
                get: Some(Arc::new(func)),
                set,
            },
            AccessorKind::Set => Value::Accessor {
                get,
                set: Some(Arc::new(func)),
            },
        };
        let mut projected_cached_dense_length = object.cached_dense_length;
        if object.is_array && projected_cached_dense_length.is_some() {
            if let Some(index) = key.as_str().and_then(Self::canonical_array_index_key) {
                if index > projected_cached_dense_length.unwrap_or(0) {
                    projected_cached_dense_length = None;
                }
            } else {
                projected_cached_dense_length = None;
            }
        }
        if let Some(key) = ordinary_key {
            let key = key.to_string();
            self.mutate_heap(|heap| {
                let object = &mut heap[heap_index];
                object.properties.insert(key, accessor);
                object.cached_dense_length = projected_cached_dense_length;
            });
        } else {
            let mut projected_properties = object.properties.clone();
            projected_properties.insert_exact(key, accessor);
            self.mutate_heap(|heap| {
                let object = &mut heap[heap_index];
                object.properties = projected_properties;
                object.cached_dense_length = projected_cached_dense_length;
            });
        }
        self.estimated_memory_bytes = requested_bytes;
        if let Some(key) = mapped_key {
            self.disconnect_mapped_argument(object_id, &key);
        }
        self.gc_write_barrier(object_id);
        Ok(())
    }

    pub(super) fn inferred_method_name(&self, key: &RuntimePropertyKey) -> JsString {
        match key {
            RuntimePropertyKey::String(name) => name.clone(),
            // ES2022 SetFunctionName: a Private Name names a function by its
            // description, `#m`.
            RuntimePropertyKey::Symbol(symbol)
                if self.symbol_state.is_class_private_name(*symbol) =>
            {
                self.symbol_description(*symbol)
                    .unwrap_or_else(|| JsString::from(""))
            }
            RuntimePropertyKey::Symbol(symbol) => self.symbol_description(*symbol).map_or_else(
                || JsString::from(""),
                |description| {
                    JsString::from("[")
                        .concat(&description)
                        .concat(&JsString::from("]"))
                },
            ),
        }
    }

    /// Give an accessor closure its [[HomeObject]] so `super.x` in a class or
    /// object-literal getter/setter resolves, and its spec name (`get x` /
    /// `set x`). Non-closures and already-registered closures are left as is.
    pub(super) fn register_accessor_home_object(
        &mut self,
        function: &Value,
        home_object: ObjectId,
        key: &RuntimePropertyKey,
        kind: AccessorKind,
        definition_label: Label,
    ) -> Result<(), InterpreterError> {
        let Value::Closure(closure_id) = function else {
            return Ok(());
        };
        if self.closure_method_metadata.contains_key(closure_id) {
            return Ok(());
        }
        let prefix = match kind {
            AccessorKind::Get => "get ",
            AccessorKind::Set => "set ",
        };
        let metadata = ClosureMethodMetadata {
            home_object,
            name: JsString::from(prefix).concat(&self.inferred_method_name(key)),
            definition_label,
        };
        let metadata_bytes = Self::estimate_closure_method_metadata_entry_bytes(&metadata);
        self.apply_memory_component_delta(0, metadata_bytes)?;
        self.closure_method_metadata.insert(*closure_id, metadata);
        Ok(())
    }

    /// Argument `index` of a builtin call, or `undefined` when absent.
    pub(super) fn arg_or_undefined(
        &self,
        args: RegRange,
        index: u32,
    ) -> Result<Value, InterpreterError> {
        if index < args.count {
            self.read_reg(args.start + index)
        } else {
            Ok(Value::Undefined)
        }
    }

    /// ES2020 7.2.10 SameValue.
    pub(super) fn same_value(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Float(a), Value::Float(b)) => {
                let (a, b) = (a.inner(), b.inner());
                (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits() || (a == b && a != 0.0)
            }
            (Value::Int(a), Value::Float(b)) | (Value::Float(b), Value::Int(a)) => {
                (*a as f64) == b.inner() && !(*a == 0 && b.inner().is_sign_negative())
            }
            _ => Self::strict_eq_values(a, b),
        }
    }

    /// `Get(descriptor, name)` when `HasProperty(descriptor, name)`, so
    /// inherited fields and getter-backed fields count (ES2020 6.2.5.5).
    /// A function descriptor is an object too (bd-9vouw.235): its own and
    /// inherited properties are read as `in` and member reads see them.
    pub(super) fn descriptor_field(
        &mut self,
        module: Option<&Ir3Module>,
        descriptor: &Value,
        name: &str,
    ) -> Result<Option<Value>, InterpreterError> {
        let key = RuntimePropertyKey::String(JsString::from(name));
        let Value::Object(descriptor_id) = *descriptor else {
            let Some(module) = module else {
                return Ok(None);
            };
            if !self.function_has_property(module, descriptor, &key)? {
                return Ok(None);
            }
            return self.get_v(module, descriptor, &key).map(Some);
        };
        if !self.proxy_aware_has_runtime_property(module, descriptor_id, &key, 0)? {
            return Ok(None);
        }
        self.proxy_aware_get_property(module, descriptor_id, name, Value::Object(descriptor_id), 0)
            .map(Some)
    }

    /// ES2020 6.2.5.5 ToPropertyDescriptor.
    pub(super) fn read_property_descriptor(
        &mut self,
        module: Option<&Ir3Module>,
        descriptor_val: &Value,
    ) -> Result<PropertyDescriptorFields, InterpreterError> {
        if !matches!(descriptor_val, Value::Object(_)) && !descriptor_val.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "object property descriptor".to_string(),
                got: descriptor_val.type_name().to_string(),
            });
        }
        let enumerable = self
            .descriptor_field(module, descriptor_val, "enumerable")?
            .map(|value| value.is_truthy());
        let configurable = self
            .descriptor_field(module, descriptor_val, "configurable")?
            .map(|value| value.is_truthy());
        let value = self.descriptor_field(module, descriptor_val, "value")?;
        let writable = self
            .descriptor_field(module, descriptor_val, "writable")?
            .map(|value| value.is_truthy());
        let mut endpoint = |name: &str| -> Result<Option<Value>, InterpreterError> {
            match self.descriptor_field(module, descriptor_val, name)? {
                Some(value) if !value.is_callable() && !matches!(value, Value::Undefined) => {
                    Err(InterpreterError::TypeError {
                        expected: format!("callable or undefined descriptor.{name}"),
                        got: value.type_name().to_string(),
                    })
                }
                field => Ok(field),
            }
        };
        let get = endpoint("get")?;
        let set = endpoint("set")?;
        let descriptor = PropertyDescriptorFields {
            value,
            writable,
            get,
            set,
            enumerable,
            configurable,
        };
        if descriptor.is_accessor() && descriptor.is_data() {
            return Err(InterpreterError::TypeError {
                expected: "either data or accessor property descriptor".to_string(),
                got: "descriptor mixes value/writable with get/set".to_string(),
            });
        }
        Ok(descriptor)
    }

    /// The heap value of an accessor property with the given endpoints.
    pub(super) fn accessor_property_value(get: Option<Value>, set: Option<Value>) -> Value {
        let endpoint = |value: Option<Value>| match value {
            None | Some(Value::Undefined) => None,
            Some(value) => Some(Arc::new(value)),
        };
        Value::Accessor {
            get: endpoint(get),
            set: endpoint(set),
        }
    }

    /// ES2020 9.1.6.3 ValidateAndApplyPropertyDescriptor for an ordinary
    /// object. `Ok(false)` means the definition was rejected; the caller
    /// decides between a TypeError (`Object.defineProperty`) and `false`.
    pub(super) fn define_own_property_from_descriptor(
        &mut self,
        obj_id: ObjectId,
        key: RuntimePropertyKey,
        descriptor: PropertyDescriptorFields,
    ) -> Result<bool, InterpreterError> {
        if key.string().is_some() && self.is_module_namespace(obj_id) {
            // SameValue exposes the retained export through a success boolean
            // (or a caught refusal), including through Reflect and proxies.
            self.reflect_observe_selected_property(obj_id, &key)?;
            let current = self
                .heap
                .get(obj_id.0 as usize)
                .and_then(|object| object.own_runtime_property_value(&key));
            return Ok(current.is_some_and(|current| {
                descriptor.configurable != Some(true)
                    && descriptor.enumerable != Some(false)
                    && descriptor.writable != Some(false)
                    && !descriptor.is_accessor()
                    && descriptor
                        .value
                        .as_ref()
                        .is_none_or(|value| Self::same_value(value, &current))
            }));
        }
        // A canonical prototype's virtual property is the current one.
        self.materialize_virtual_own_property(obj_id, &key)?;
        let object = self
            .heap
            .get(obj_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: obj_id.0 })?;
        // ES2020 9.4.2.1 [[DefineOwnProperty]] of an Array (bd-9vouw.279):
        // `length` with a value is ArraySetLength, and an index at or past a
        // non-writable `length` cannot be added.
        if object.is_array
            && key.as_str() == Some("length")
            && let Some(value) = descriptor.value.clone()
        {
            return self.array_set_length_by_definition(obj_id, &key, &value, &descriptor);
        }
        if Self::array_index_past_fixed_length(object, &key) {
            return Ok(false);
        }
        let Some(current) = object.own_runtime_property_descriptor(&key) else {
            if !object.extensible() {
                return Ok(false);
            }
            let is_accessor = descriptor.is_accessor();
            let (value, writable) = if is_accessor {
                (
                    Self::accessor_property_value(descriptor.get, descriptor.set),
                    true,
                )
            } else {
                (
                    descriptor.value.unwrap_or(Value::Undefined),
                    descriptor.writable.unwrap_or(false),
                )
            };
            let attributes = PropertyAttributes {
                writable,
                enumerable: descriptor.enumerable.unwrap_or(false),
                configurable: descriptor.configurable.unwrap_or(false),
            };
            self.define_own_property_value(obj_id, key.clone(), value)?;
            self.set_own_property_attributes(obj_id, &key, attributes)?;
            return Ok(true);
        };
        let current_attributes = object.own_property_attributes(&key);
        let is_frozen = object.is_frozen;
        if !current_attributes.configurable
            && (descriptor.configurable == Some(true)
                || descriptor
                    .enumerable
                    .is_some_and(|enumerable| enumerable != current_attributes.enumerable))
        {
            return Ok(false);
        }
        let mut attributes = current_attributes;
        let mut new_value = None;
        match current {
            // A generic descriptor changes only enumerable/configurable.
            _ if !descriptor.is_accessor() && !descriptor.is_data() => {}
            BaselineSymbolProperty::Data(current_value) if descriptor.is_data() => {
                if !current_attributes.configurable && !current_attributes.writable {
                    if descriptor.writable == Some(true)
                        || descriptor
                            .value
                            .as_ref()
                            .is_some_and(|value| !Self::same_value(value, &current_value))
                    {
                        return Ok(false);
                    }
                    return Ok(true);
                }
                new_value = descriptor.value.clone();
                if let Some(writable) = descriptor.writable {
                    attributes.writable = writable;
                }
            }
            BaselineSymbolProperty::Accessor { get, set } if descriptor.is_accessor() => {
                let changes = |field: &Option<Value>, current: &Option<Value>| {
                    field.as_ref().is_some_and(|field| {
                        !Self::same_value(field, current.as_ref().unwrap_or(&Value::Undefined))
                    })
                };
                if !current_attributes.configurable {
                    if changes(&descriptor.get, &get) || changes(&descriptor.set, &set) {
                        return Ok(false);
                    }
                    return Ok(true);
                }
                new_value = Some(Self::accessor_property_value(
                    descriptor.get.clone().or(get),
                    descriptor.set.clone().or(set),
                ));
            }
            // Converting between data and accessor kinds keeps enumerable and
            // configurable and resets the other attributes to defaults.
            _ => {
                if !current_attributes.configurable {
                    return Ok(false);
                }
                if descriptor.is_accessor() {
                    new_value = Some(Self::accessor_property_value(
                        descriptor.get.clone(),
                        descriptor.set.clone(),
                    ));
                    attributes.writable = true;
                } else {
                    new_value = Some(descriptor.value.clone().unwrap_or(Value::Undefined));
                    attributes.writable = descriptor.writable.unwrap_or(false);
                }
            }
        }
        if let Some(enumerable) = descriptor.enumerable {
            attributes.enumerable = enumerable;
        }
        if let Some(configurable) = descriptor.configurable {
            attributes.configurable = configurable;
        }
        // Every definition a frozen object accepts is a no-op.
        if is_frozen {
            return Ok(true);
        }
        if let Some(value) = new_value {
            self.define_own_property_value(obj_id, key.clone(), value)?;
        }
        self.set_own_property_attributes(obj_id, &key, attributes)?;
        Ok(true)
    }

    /// ES2020 9.4.2.1 step 3.b (bd-9vouw.279): whether `key` is an index an
    /// array does not have yet, at or past its non-writable `length`, which
    /// neither a definition nor an assignment may add (`length` cannot grow).
    pub(super) fn array_index_past_fixed_length(
        object: &HeapObject,
        key: &RuntimePropertyKey,
    ) -> bool {
        if !object.is_array || object.contains_own_runtime_property(key) {
            return false;
        }
        let Some(index) = key.as_str().and_then(Self::canonical_array_index_key) else {
            return false;
        };
        let length_key = RuntimePropertyKey::String(JsString::from("length"));
        !object.own_property_attributes(&length_key).writable
            && matches!(object.own_runtime_property_value(&length_key),
                Some(Value::Int(length)) if i64::from(index) >= length)
    }

    /// ES2020 9.4.2.4 ArraySetLength steps 3-5 for the value an array's
    /// `length` is set or defined to: ToUint32(value), then ToNumber(value),
    /// each observable (an object's valueOf runs twice); a RangeError when
    /// they differ (bd-9vouw.279). A Number passes through unconverted.
    pub(super) fn array_length_definition_value(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        if matches!(value, Value::Int(_) | Value::Float(_)) {
            return Ok(value);
        }
        let as_uint32 = Self::js_to_uint32(self.array_length_number(module, value.clone())?);
        let as_number = self.array_length_number(module, value)?;
        if f64::from(as_uint32) != as_number {
            return Err(InterpreterError::RangeError {
                message: format!("invalid array length {as_number}"),
            });
        }
        Ok(Value::Int(i64::from(as_uint32)))
    }

    /// ToNumber(value) for ArraySetLength steps 3-4 (bd-9vouw.279): an
    /// object converts through its @@toPrimitive / valueOf / toString, a
    /// string by StringToNumber ("0x0B" is 11); a Symbol or BigInt is a
    /// TypeError.
    pub(super) fn array_length_number(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<f64, InterpreterError> {
        Ok(match self.coerce_runtime_primitive(module, value, false)? {
            Value::Int(number) => number as f64,
            Value::Float(number) => number.inner(),
            Value::Str(text) => primitive_conversion::string_number(&text),
            Value::Bool(flag) => f64::from(u8::from(flag)),
            Value::Null => 0.0,
            Value::Undefined => f64::NAN,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "Number-convertible array length".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        })
    }

    /// ES2020 9.4.2.4 ArraySetLength for a definition of an array's
    /// `length` with a value (bd-9vouw.279). The new length is validated
    /// (RangeError) before the descriptor is, so `{ value: -1, configurable:
    /// true }` is a RangeError, not a rejected redefinition. `length` is
    /// never configurable, enumerable or an accessor. Keeping or growing it
    /// is an ordinary definition (a non-writable one accepts only its own
    /// value). Shrinking needs a writable `length`: elements are deleted
    /// from the end, the deletion stops past a non-configurable one, whose
    /// index + 1 becomes the length, and the definition is rejected;
    /// `writable: false` applies after the deletions. A rejected shrink
    /// used to delete the non-configurable elements too.
    pub(super) fn array_set_length_by_definition(
        &mut self,
        array_id: ObjectId,
        key: &RuntimePropertyKey,
        value: &Value,
        descriptor: &PropertyDescriptorFields,
    ) -> Result<bool, InterpreterError> {
        let new_length = Self::normalize_array_length_assignment(value)?;
        let object = self
            .heap
            .get(array_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: array_id.0 })?;
        let attributes = object.own_property_attributes(key);
        let old_length = match object.own_runtime_property_value(key) {
            Some(Value::Int(length)) => length,
            _ => 0,
        };
        if descriptor.configurable == Some(true)
            || descriptor.enumerable == Some(true)
            || descriptor.is_accessor()
        {
            return Ok(false);
        }
        if !attributes.writable {
            return Ok(new_length == old_length && descriptor.writable != Some(true));
        }
        let kept = if new_length < old_length {
            self.array_length_kept_by_nonconfigurable(array_id, key, &Value::Int(new_length))?
        } else {
            None
        };
        let final_length = kept.unwrap_or(new_length);
        if final_length != old_length {
            self.set_object_runtime_property(array_id, key.clone(), Value::Int(final_length))?;
        }
        if descriptor.writable == Some(false) {
            self.set_own_property_attributes(
                array_id,
                key,
                PropertyAttributes {
                    writable: false,
                    ..attributes
                },
            )?;
        }
        Ok(kept.is_none())
    }

    /// ES2020 7.3.14 SetIntegrityLevel(O, sealed).
    pub(super) fn seal_object(&mut self, object_id: ObjectId) -> Result<(), InterpreterError> {
        let heap_index = object_id.0 as usize;
        let object = self
            .heap
            .get(heap_index)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if object.is_frozen {
            return Ok(());
        }
        let keys = object.own_runtime_property_keys();
        self.mutate_heap(|heap| heap[heap_index].is_non_extensible = true);
        for key in keys {
            let mut attributes = self.heap[heap_index].own_property_attributes(&key);
            attributes.configurable = false;
            self.set_own_property_attributes(object_id, &key, attributes)?;
        }
        Ok(())
    }

    /// Object.seal(O), ES2020 19.1.2.20 / 7.3.14 SetIntegrityLevel "sealed":
    /// a Proxy through its traps, an object, or a function's (promise's,
    /// generator's, iterator's) backing object; any other value is returned
    /// as is. Both the hostcall and a value call run this: since standard
    /// members resolve at call time (2a427674d), `Object.seal(x)` is a value
    /// call too.
    pub(super) fn object_seal_value(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        if let Some(proxy) = self.integrity_proxy_id(&value)? {
            if !self.proxy_set_integrity_level(module, proxy, false)? {
                return Err(InterpreterError::TypeError {
                    expected: "successful preventExtensions".to_string(),
                    got: "falsy Proxy trap result".to_string(),
                });
            }
        } else if let Value::Object(object_id) = value {
            self.seal_object(object_id)?;
        } else if Self::stores_own_properties_on_backing(&value)
            && let Some(backing) = self.own_property_holder(module, &value, true)?
        {
            self.seal_object(backing)?;
        }
        Ok(value)
    }

    /// Object.isSealed(O), ES2020 19.1.2.15 / 7.3.15 TestIntegrityLevel: a
    /// Proxy through its traps, an object, or a function's (promise's,
    /// generator's, iterator's) backing object; any other value is sealed.
    /// Shared by the hostcall and a value call, as object_seal_value is.
    pub(super) fn object_is_sealed_value(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
    ) -> Result<bool, InterpreterError> {
        if let Some(proxy) = self.integrity_proxy_id(value)? {
            return self.proxy_test_integrity_level(module, proxy, false);
        }
        match value {
            Value::Object(object_id) => self.object_has_integrity_level(*object_id, false),
            holder if Self::stores_own_properties_on_backing(holder) => {
                self.backing_has_integrity_level(module, holder, false)
            }
            _ => Ok(true),
        }
    }

    /// TestIntegrityLevel of a function, promise, generator or iterator
    /// value: its backing object's; false before one exists (it is
    /// extensible) (bd-9vouw.149).
    pub(super) fn backing_has_integrity_level(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
        frozen: bool,
    ) -> Result<bool, InterpreterError> {
        match self.own_property_holder(module, value, false)? {
            Some(backing) => self.object_has_integrity_level(backing, frozen),
            None => Ok(false),
        }
    }

    /// ES2020 7.3.15 TestIntegrityLevel: sealed (`frozen == false`) or frozen.
    pub(super) fn object_has_integrity_level(
        &self,
        object_id: ObjectId,
        frozen: bool,
    ) -> Result<bool, InterpreterError> {
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        if object.extensible() {
            return Ok(false);
        }
        Ok(object.own_runtime_property_keys().iter().all(|key| {
            if let RuntimePropertyKey::String(name) = key
                && !self.own_runtime_property_visible(object_id, name)
            {
                return true;
            }
            let attributes = object.own_property_attributes(key);
            let is_accessor = matches!(
                object.own_runtime_property_value(key),
                Some(Value::Accessor { .. })
            );
            !attributes.configurable && (!frozen || is_accessor || !attributes.writable)
        }))
    }

    /// The ordinary own descriptor, including virtual data properties, as
    /// internal fields. Invariant checks must not allocate a guest object just
    /// to inspect a target property. Public reflection materializes these same
    /// fields through FromPropertyDescriptor below.
    pub(super) fn ordinary_own_property_descriptor_fields(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Option<PropertyDescriptorFields> {
        let visible = match key {
            RuntimePropertyKey::String(key) => self.own_runtime_property_visible(object_id, key),
            RuntimePropertyKey::Symbol(_) => true,
        };
        let source = visible
            .then(|| {
                self.heap.get(object_id.0 as usize).and_then(|object| {
                    object
                        .own_runtime_property_descriptor(key)
                        .map(|property| (property, object.own_property_attributes(key)))
                })
            })
            .flatten()
            .or_else(|| {
                let virtual_value = self.canonical_prototype_virtual_property(object_id, key)?;
                let attributes = self.virtual_property_attributes(object_id, key);
                Some((BaselineSymbolProperty::Data(virtual_value), attributes))
            });
        let (property, attributes) = source?;
        let fields = PropertyDescriptorFields {
            enumerable: Some(attributes.enumerable),
            configurable: Some(attributes.configurable),
            ..PropertyDescriptorFields::default()
        };
        Some(match property {
            BaselineSymbolProperty::Data(value) => PropertyDescriptorFields {
                value: Some(value),
                writable: Some(attributes.writable),
                ..fields
            },
            BaselineSymbolProperty::Accessor { get, set } => PropertyDescriptorFields {
                get: Some(get.unwrap_or(Value::Undefined)),
                set: Some(set.unwrap_or(Value::Undefined)),
                ..fields
            },
        })
    }

    /// ES2020 6.2.5.4 FromPropertyDescriptor for the own property `key` of
    /// `object_id`, or `undefined` when there is no such property.
    pub(super) fn own_property_descriptor_value(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<Value, InterpreterError> {
        let Some(fields) = self.ordinary_own_property_descriptor_fields(object_id, key) else {
            return Ok(Value::Undefined);
        };
        self.descriptor_object_from_fields(&fields, false)
    }

    /// Install an own property from a validated descriptor value, keeping
    /// array length metadata in step with an indexed definition.
    pub(super) fn define_own_property_value(
        &mut self,
        obj_id: ObjectId,
        prop_name: RuntimePropertyKey,
        effective_value: Value,
    ) -> Result<(), InterpreterError> {
        let array_index = prop_name.as_str().and_then(Self::canonical_array_index_key);
        self.set_object_runtime_property(obj_id, prop_name, effective_value)?;
        if let Some(index) = array_index {
            // Defining an own array index grows length just like an indexed
            // assignment, including accessor descriptors. Do not invoke the
            // getter while maintaining array metadata.
            self.maintain_array_index_assignment(obj_id, index)?;
        }
        Ok(())
    }

    /// Install an ordinary data property and its private per-closure method
    /// identity as one budgeted operation. Reserving the metadata first makes
    /// a later property-allocation refusal rollback without publishing either
    /// half of the method definition.
    pub(super) fn define_method_property(
        &mut self,
        object_id: ObjectId,
        key: RuntimePropertyKey,
        function: Value,
        definition_label: Label,
    ) -> Result<(), InterpreterError> {
        self.validate_executable_property_key(&key)?;
        let replaced_read_only = self
            .heap
            .get(object_id.0 as usize)
            .map(|object| object.own_property_attributes(&key))
            .filter(|attributes| !attributes.writable && attributes.configurable);
        let closure_id = match function {
            // Generator and async-generator methods (`*m(){}`, `async *m(){}`)
            // get a [[HomeObject]] too: `super.x` in their bodies reads the
            // home object's prototype (bd-9vouw.143).
            Value::Closure(closure_id)
            | Value::AsyncFunction(closure_id)
            | Value::GeneratorFunction(closure_id)
            | Value::AsyncGeneratorFunction(closure_id) => closure_id,
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "fresh closure for concise method definition".to_string(),
                    got: function.type_name().to_string(),
                });
            }
        };
        self.closures
            .get(closure_id as usize)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "valid concise-method closure".to_string(),
                got: format!("closure#{closure_id} not found"),
            })?;
        if self.closure_method_metadata.contains_key(&closure_id) {
            return Err(InterpreterError::TypeError {
                expected: "unregistered concise-method closure".to_string(),
                got: format!("closure#{closure_id} already has a [[HomeObject]]"),
            });
        }

        let metadata = ClosureMethodMetadata {
            home_object: object_id,
            name: self.inferred_method_name(&key),
            definition_label,
        };
        let metadata_bytes = Self::estimate_closure_method_metadata_entry_bytes(&metadata);
        self.apply_memory_component_delta(0, metadata_bytes)?;
        if let Err(error) = self.set_object_runtime_property(object_id, key.clone(), function) {
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(metadata_bytes);
            return Err(error);
        }
        self.closure_method_metadata.insert(closure_id, metadata);
        self.make_replaced_method_writable(object_id, &key, replaced_read_only)
    }

    /// ES2020 14.3.8 DefineMethod defines a writable, configurable property,
    /// so a method that replaced a read-only one (`static name()` over a
    /// class's own `name`, bd-9vouw.146) is writable; it keeps the replaced
    /// property's enumerability.
    pub(super) fn make_replaced_method_writable(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        replaced_read_only: Option<PropertyAttributes>,
    ) -> Result<(), InterpreterError> {
        let Some(attributes) = replaced_read_only else {
            return Ok(());
        };
        self.set_own_property_attributes(
            object_id,
            key,
            PropertyAttributes {
                writable: true,
                ..attributes
            },
        )
    }

    pub(super) fn dispatch_timer_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let timestamp_ns = self.instructions_executed;
        let args_hash = self.hostcall_arguments_hash(args);
        let outcome = self.dispatch_timer_hostcall_inner(cap, args);
        self.record_hostcall_telemetry(cap, args, timestamp_ns, args_hash, &outcome);
        outcome
    }

    pub(super) fn dispatch_timer_hostcall_inner(
        &mut self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        match cap {
            "timer:setTimeout" => {
                // args[0] = handler (function/closure), args[1] = delay_ms
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let handler_reg = args.start;
                let delay_reg =
                    args.start
                        .checked_add(1)
                        .ok_or(InterpreterError::RegisterOutOfBounds {
                            register: args.start,
                            max: self.config.max_registers,
                        })?;

                let handler_val = self.read_reg(handler_reg)?;
                let delay_val = self.read_reg(delay_reg)?;

                // Extract numeric delay
                let delay_ms = match delay_val {
                    Value::Int(i) => i.max(0) as u64,
                    Value::Float(f) => f.0.max(0.0) as u64,
                    _ => 0,
                };

                // Store active timer
                let timer_id = self.next_timer_id;
                self.next_timer_id = self.next_timer_id.wrapping_add(1);

                let handler_id = match handler_val {
                    Value::Closure(id) => Some(id),
                    _ => None,
                };

                self.active_timers.insert(
                    timer_id,
                    ActiveTimer {
                        handler: handler_id,
                        delay_ms,
                        repeating: false,
                    },
                );

                self.emit_witness(
                    WitnessEventKind::HostcallDispatched,
                    Some(&format!("timer:setTimeout:{}", timer_id)),
                );

                Ok(Value::Int(timer_id as i64))
            }
            "timer:setInterval" => {
                // Similar to setTimeout but repeating
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let handler_reg = args.start;
                let delay_reg =
                    args.start
                        .checked_add(1)
                        .ok_or(InterpreterError::RegisterOutOfBounds {
                            register: args.start,
                            max: self.config.max_registers,
                        })?;

                let handler_val = self.read_reg(handler_reg)?;
                let delay_val = self.read_reg(delay_reg)?;

                let delay_ms = match delay_val {
                    Value::Int(i) => i.max(0) as u64,
                    Value::Float(f) => f.0.max(0.0) as u64,
                    _ => 0,
                };

                let timer_id = self.next_timer_id;
                self.next_timer_id = self.next_timer_id.wrapping_add(1);

                let handler_id = match handler_val {
                    Value::Closure(id) => Some(id),
                    _ => None,
                };

                self.active_timers.insert(
                    timer_id,
                    ActiveTimer {
                        handler: handler_id,
                        delay_ms,
                        repeating: true,
                    },
                );

                self.emit_witness(
                    WitnessEventKind::HostcallDispatched,
                    Some(&format!("timer:setInterval:{}", timer_id)),
                );

                Ok(Value::Int(timer_id as i64))
            }
            "timer:clearTimeout" | "timer:clearInterval" => {
                // args[0] = timer_id to clear
                if args.count < 1 {
                    return Ok(Value::Undefined);
                }

                let timer_id_val = self.read_reg(args.start)?;
                let timer_id = match timer_id_val {
                    Value::Int(i) => i as u32,
                    _ => return Ok(Value::Undefined),
                };

                self.active_timers.remove(&timer_id);

                self.emit_witness(
                    WitnessEventKind::HostcallDispatched,
                    Some(&format!("{}:{}", cap, timer_id)),
                );

                Ok(Value::Undefined)
            }
            _ => Ok(Value::Undefined), // Unknown timer method
        }
    }

    pub(super) fn construct_node_invalid_url_error(
        &mut self,
        input: &str,
    ) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("TypeError")?;
        let error_id = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_like_object(error_id, "TypeError", format!("Invalid URL: {input}"))?;
        self.set_object_property(error_id, "code".to_string(), Value::str("ERR_INVALID_URL"))?;
        Ok(Value::Object(error_id))
    }

    pub(super) fn throw_invalid_url_error(&mut self, input: &str) -> InterpreterError {
        let thrown = match self.construct_node_invalid_url_error(input) {
            Ok(value) => value,
            Err(error) => return error,
        };
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = Label::Public;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    pub(super) fn parse_whatwg_url(
        &mut self,
        input: &str,
        base: Option<&str>,
    ) -> Result<Url, InterpreterError> {
        if let Some(base) = base {
            let parsed_base = Url::parse(base).map_err(|_| self.throw_invalid_url_error(base))?;
            parsed_base
                .join(input)
                .map_err(|_| self.throw_invalid_url_error(input))
        } else {
            Url::parse(input).map_err(|_| self.throw_invalid_url_error(input))
        }
    }

    pub(super) fn throw_legacy_url_type_error(
        &mut self,
        code: &str,
        message: String,
    ) -> InterpreterError {
        let thrown = (|| {
            let prototype = self.ensure_builtin_prototype("TypeError")?;
            let error_id = self.alloc_object_with_prototype(Some(prototype))?;
            self.initialize_error_like_object(error_id, "TypeError", message)?;
            self.set_object_property(error_id, "code".to_string(), Value::str(code))?;
            Ok::<Value, InterpreterError>(Value::Object(error_id))
        })();
        let thrown = match thrown {
            Ok(value) => value,
            Err(error) => return error,
        };
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = Label::Public;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    pub(super) fn legacy_url_file_url_input(
        &mut self,
        args: RegRange,
    ) -> Result<String, InterpreterError> {
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        match value {
            Value::Str(input) => {
                self.check_temporary_memory_budget(Self::url_parse_working_upper_bound(
                    Self::estimate_js_string_bytes(&input),
                    0,
                ))?;
                Ok(input.to_string())
            }
            Value::Object(object_id) => {
                let Some(href_bytes) = self
                    .url_objects
                    .get(&object_id)
                    .map(|state| Self::estimate_string_bytes(&state.href))
                else {
                    return Err(self.throw_legacy_url_type_error(
                        "ERR_INVALID_ARG_TYPE",
                        "The path argument must be of type string or an instance of URL"
                            .to_string(),
                    ));
                };
                self.check_temporary_memory_budget(Self::url_parse_working_upper_bound(
                    href_bytes, 0,
                ))?;
                Ok(self
                    .url_objects
                    .get(&object_id)
                    .expect("URL object was authenticated before allocation preflight")
                    .href
                    .clone())
            }
            other => Err(self.throw_legacy_url_type_error(
                "ERR_INVALID_ARG_TYPE",
                format!(
                    "The path argument must be of type string or an instance of URL. Received {}",
                    other.type_name()
                ),
            )),
        }
    }

    pub(super) fn legacy_url_file_url_to_path(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let input = self.legacy_url_file_url_input(args)?;
        let parsed = self.parse_whatwg_url(&input, None)?;
        if parsed.scheme() != "file" {
            return Err(self.throw_legacy_url_type_error(
                "ERR_INVALID_URL_SCHEME",
                "The URL must be of scheme file".to_string(),
            ));
        }
        if parsed
            .host_str()
            .is_some_and(|host| !host.eq_ignore_ascii_case("localhost"))
        {
            return Err(self.throw_legacy_url_type_error(
                "ERR_INVALID_FILE_URL_HOST",
                "File URL host must be localhost or empty on this platform".to_string(),
            ));
        }
        let encoded_path = parsed.path();
        let has_encoded_separator = encoded_path.as_bytes().windows(3).any(|window| {
            window[0] == b'%' && window[1] == b'2' && matches!(window[2], b'f' | b'F')
                || window[0] == b'%' && window[1] == b'5' && matches!(window[2], b'c' | b'C')
        });
        if has_encoded_separator {
            return Err(self.throw_legacy_url_type_error(
                "ERR_INVALID_FILE_URL_PATH",
                "File URL path must not include encoded path separators".to_string(),
            ));
        }
        let path = qs_strict_percent_decode(encoded_path).ok_or_else(|| {
            self.throw_legacy_url_type_error(
                "ERR_INVALID_FILE_URL_PATH",
                "File URL path contains an invalid percent-encoding".to_string(),
            )
        })?;
        Ok(Value::str(path))
    }

    pub(super) fn legacy_url_format_object_property(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> String {
        match self
            .heap
            .get(object_id.0 as usize)
            .and_then(|object| object.properties.get(key).cloned())
        {
            None | Some(Value::Undefined) | Some(Value::Null) => String::new(),
            Some(Value::Str(value)) => value.to_string(),
            Some(other) => self.value_to_string(&other),
        }
    }

    pub(super) fn legacy_url_format(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        if let Value::Str(input) = value {
            self.check_temporary_memory_budget(Self::url_parse_working_upper_bound(
                Self::estimate_js_string_bytes(&input),
                0,
            ))?;
            let parsed = self.parse_whatwg_url(&input, None)?;
            let href = parsed.as_str().to_string();
            self.check_temporary_memory_budget(Self::estimate_string_bytes(&href))?;
            return Ok(Value::str(href));
        }
        let Value::Object(object_id) = value else {
            return Err(self.throw_legacy_url_type_error(
                "ERR_INVALID_ARG_TYPE",
                format!(
                    "The urlObject argument must be of type object or string. Received {}",
                    value.type_name()
                ),
            ));
        };
        if let Some(href_bytes) = self
            .url_objects
            .get(&object_id)
            .map(|state| Self::estimate_string_bytes(&state.href))
        {
            self.check_temporary_memory_budget(href_bytes)?;
            return Ok(Value::str(
                self.url_objects
                    .get(&object_id)
                    .expect("URL object was authenticated before allocation preflight")
                    .href
                    .clone(),
            ));
        }
        let object_working_bound = self
            .heap
            .get(object_id.0 as usize)
            .map(Self::estimate_heap_object_bytes)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?
            .saturating_mul(3)
            .saturating_add(256);
        self.check_temporary_memory_budget(object_working_bound)?;

        let protocol = self.legacy_url_format_object_property(object_id, "protocol");
        let mut host = self.legacy_url_format_object_property(object_id, "host");
        if host.is_empty() {
            host = self.legacy_url_format_object_property(object_id, "hostname");
            let port = self.legacy_url_format_object_property(object_id, "port");
            if !host.is_empty() && !port.is_empty() {
                host.push(':');
                host.push_str(&port);
            }
        }
        let mut pathname = self.legacy_url_format_object_property(object_id, "pathname");
        let mut search = self.legacy_url_format_object_property(object_id, "search");
        let mut hash = self.legacy_url_format_object_property(object_id, "hash");
        let working_bytes = [
            protocol.len(),
            host.len(),
            pathname.len(),
            search.len(),
            hash.len(),
        ]
        .into_iter()
        .fold(64_u64, |total, len| {
            total.saturating_add(u64::try_from(len).unwrap_or(u64::MAX))
        })
        .saturating_mul(3);
        self.check_temporary_memory_budget(working_bytes)?;

        let mut formatted = String::new();
        if !protocol.is_empty() {
            formatted.push_str(protocol.trim_end_matches(':'));
            formatted.push(':');
        }
        if !host.is_empty() {
            formatted.push_str("//");
            formatted.push_str(&host);
            if !pathname.is_empty() && !pathname.starts_with('/') {
                pathname.insert(0, '/');
            }
        }
        formatted.push_str(&pathname);
        if !search.is_empty() {
            if !search.starts_with('?') {
                search.insert(0, '?');
            }
            formatted.push_str(&search);
        }
        if !hash.is_empty() {
            if !hash.starts_with('#') {
                hash.insert(0, '#');
            }
            formatted.push_str(&hash);
        }
        Ok(Value::str(formatted))
    }

    pub(super) fn legacy_url_parse(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let Value::Str(input) = value else {
            return Err(self.throw_legacy_url_type_error(
                "ERR_INVALID_ARG_TYPE",
                format!(
                    "The url argument must be of type string. Received {}",
                    value.type_name()
                ),
            ));
        };
        self.check_temporary_memory_budget(Self::url_parse_working_upper_bound(
            Self::estimate_js_string_bytes(&input),
            0,
        ))?;
        let parsed = self.parse_whatwg_url(&input, None)?;
        let protocol = format!("{}:", parsed.scheme());
        let hostname = parsed.host_str().unwrap_or_default().to_string();
        let port = parsed.port().map(|port| port.to_string());
        let host = port
            .as_ref()
            .map(|port| format!("{hostname}:{port}"))
            .unwrap_or_else(|| hostname.clone());
        let pathname = parsed.path().to_string();
        let search = parsed.query().map(|query| format!("?{query}"));
        let hash = parsed.fragment().map(|fragment| format!("#{fragment}"));
        let path = format!("{}{}", pathname, search.as_deref().unwrap_or_default());
        let href = parsed.as_str().to_string();
        let auth = if parsed.username().is_empty() {
            Value::Null
        } else {
            let mut auth = parsed.username().to_string();
            if let Some(password) = parsed.password() {
                auth.push(':');
                auth.push_str(password);
            }
            Value::str(auth)
        };
        let object_id = self.alloc_object_with_properties(&[
            ("protocol", Value::str(protocol)),
            ("slashes", Value::Bool(true)),
            ("auth", auth),
            ("host", Value::str(host)),
            ("port", port.map(Value::str).unwrap_or(Value::Null)),
            ("hostname", Value::str(hostname)),
            ("hash", hash.map(Value::str).unwrap_or(Value::Null)),
            ("search", search.map(Value::str).unwrap_or(Value::Null)),
            ("pathname", Value::str(pathname)),
            ("path", Value::str(path)),
            ("href", Value::str(href)),
        ])?;
        Ok(Value::Object(object_id))
    }

    pub(super) fn url_pairs(parsed: &Url) -> Vec<(String, String)> {
        parsed.query_pairs().into_owned().collect()
    }

    pub(super) fn serialize_url_search_params(pairs: &[(String, String)]) -> String {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (name, value) in pairs {
            serializer.append_pair(name, value);
        }
        serializer.finish()
    }

    pub(super) fn url_serialization_upper_bound(pairs: &[(String, String)]) -> u64 {
        let encoded_units = Self::saturating_sum(pairs.iter().flat_map(|(name, value)| {
            [
                u64::try_from(name.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(3),
                u64::try_from(value.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(3),
            ]
        }));
        MEMORY_ESTIMATE_STRING_BASE_BYTES
            .saturating_add(encoded_units)
            .saturating_add(
                u64::try_from(pairs.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(2),
            )
    }

    /// Conservative allocation bound for the engine's primitive string
    /// coercion. URL entry points reserve this before calling
    /// `value_to_string`, so even Buffer/Error object coercions cannot create
    /// an unmetered host allocation before URL parsing starts.
    /// A URL constructor or static argument as a string: a URL object gives
    /// its href, its stringifier (URL Standard 6.1), where the engine's
    /// conversion gave "[object URL]"; anything else that conversion
    /// (bd-9vouw.168: a user toString is not called).
    pub(super) fn url_input_to_string(&self, value: &Value) -> String {
        if let Value::Object(id) = value
            && let Some(state) = self.url_objects.get(id)
        {
            return state.href.clone();
        }
        self.value_to_string(value)
    }

    /// The join of the state labels of the URL objects among `values`: a
    /// URL argument's href flows into what the constructor or static returns.
    pub(super) fn url_argument_state_label(&self, values: &[Option<&Value>]) -> Label {
        values
            .iter()
            .flatten()
            .filter_map(|value| match value {
                Value::Object(id) => self.url_objects.get(id),
                _ => None,
            })
            .fold(Label::Public, |label, state| {
                label.join(&state.lifecycle_label)
            })
    }

    pub(super) fn url_value_to_string_upper_bound(&self, value: &Value) -> u64 {
        if let Value::Object(id) = value
            && let Some(state) = self.url_objects.get(id)
        {
            return Self::estimate_string_bytes(&state.href);
        }
        match value {
            Value::Str(text) => Self::estimate_js_string_bytes(text),
            Value::BigInt(digits) => Self::estimate_string_bytes(digits),
            Value::Object(object_id) => {
                let Some(object) = self.heap.get(object_id.0 as usize) else {
                    return MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(64);
                };
                let buffer_render = object
                    .typed_array
                    .as_ref()
                    .filter(|view| view.is_buffer)
                    .map(|view| {
                        MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(
                            u64::try_from(view.byte_length)
                                .unwrap_or(u64::MAX)
                                .saturating_mul(3),
                        )
                    })
                    .unwrap_or(0);
                buffer_render.max(
                    Self::estimate_heap_object_bytes(object)
                        .saturating_mul(2)
                        .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
                        .saturating_add(128),
                )
            }
            Value::BuiltinFunction(builtin) => {
                Self::estimate_string_bytes(&builtin.module_specifier).saturating_add(128)
            }
            // Numeric/id renderings and the remaining fixed tags are all
            // bounded well below this allocation, including a String header.
            _ => MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(128),
        }
    }

    /// Worst-case owned pair storage produced while decoding one query-like
    /// string. There can be at most one more pair than source bytes; every
    /// pair owns two String headers, and percent/form decoding cannot produce
    /// more scalar bytes than the conservatively tripled source bound.
    pub(super) fn url_decoded_pairs_upper_bound(source_bytes: u64) -> u64 {
        let pair_count = source_bytes.saturating_add(1);
        (std::mem::size_of::<Vec<(String, String)>>() as u64)
            .saturating_add(
                pair_count.saturating_mul(
                    (std::mem::size_of::<(String, String)>() as u64)
                        .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_mul(2)),
                ),
            )
            .saturating_add(source_bytes.saturating_mul(3))
    }

    /// Aggregate peak for string coercion, the `url` crate's parsed record,
    /// canonical serialization, IDNA/percent-encoding scratch, and owned query
    /// pairs. The multiplier intentionally covers simultaneous parser input
    /// and output buffers; structural pair overhead is charged separately.
    pub(super) fn url_parse_working_upper_bound(input_bytes: u64, base_bytes: u64) -> u64 {
        let source_bytes = input_bytes.saturating_add(base_bytes);
        source_bytes
            .saturating_mul(16)
            .saturating_add(Self::url_decoded_pairs_upper_bound(source_bytes))
            .saturating_add((std::mem::size_of::<Url>() as u64).saturating_mul(2))
            .saturating_add(1024)
    }

    pub(super) fn url_search_params_mutation_input_bytes(
        mutation: &UrlSearchParamsMutation,
    ) -> u64 {
        match mutation {
            UrlSearchParamsMutation::Append(name, value)
            | UrlSearchParamsMutation::Set(name, value) => Self::estimate_string_bytes(name)
                .saturating_add(Self::estimate_string_bytes(value))
                .saturating_add(std::mem::size_of::<(String, String)>() as u64),
            UrlSearchParamsMutation::Delete(name) => Self::estimate_string_bytes(name),
            UrlSearchParamsMutation::Sort => 0,
        }
    }

    pub(super) fn allocate_url_search_params_state(
        &mut self,
        pairs: Vec<(String, String)>,
        owner_url: Option<ObjectId>,
        lifecycle_label: Label,
    ) -> Result<ObjectId, InterpreterError> {
        let state = UrlSearchParamsRuntimeState {
            pairs,
            owner_url,
            lifecycle_label,
        };
        let retained_bytes = Self::estimate_url_search_params_state_bytes(&state);
        self.check_temporary_memory_budget(
            retained_bytes.saturating_add(Self::estimate_heap_object_bytes(&HeapObject::new())),
        )?;
        // The first use materializes the prototype past the rollback point;
        // a refusal takes it back with the object (bd-9vouw.157).
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let allocated = self
            .ensure_builtin_prototype("URLSearchParams")
            .and_then(|prototype| self.alloc_object_with_prototype(Some(prototype)))
            .and_then(|object_id| {
                self.apply_memory_component_delta(0, retained_bytes)?;
                Ok(object_id)
            });
        let object_id = match allocated {
            Ok(object_id) => object_id,
            Err(error) => {
                self.rollback_heap_and_new_prototypes(previous_heap_len, previous_estimated_bytes);
                return Err(error);
            }
        };
        self.url_search_params.insert(object_id, state);
        Ok(object_id)
    }

    /// `URL.canParse(input, base)`: whether `new URL(input, base)` would
    /// succeed; `URL.parse(input, base)`: that URL, or null where the
    /// constructor throws (URL Standard 6.1). Neither allocates an error.
    pub(super) fn url_static(
        &mut self,
        method: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let input_value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let base_value = match self.builtin_arg(args, 1)? {
            None | Some(Value::Undefined) => None,
            Some(value) => Some(value),
        };
        let input_bound = self.url_value_to_string_upper_bound(&input_value);
        let base_bound = base_value
            .as_ref()
            .map(|value| self.url_value_to_string_upper_bound(value))
            .unwrap_or(0);
        self.check_temporary_memory_budget(Self::url_parse_working_upper_bound(
            input_bound,
            base_bound,
        ))?;
        let url_label = self.url_argument_state_label(&[Some(&input_value), base_value.as_ref()]);
        if url_label != Label::Public {
            let label = self
                .pending_hostcall_result_label
                .clone()
                .unwrap_or(Label::Public)
                .join(&url_label);
            self.replace_pending_hostcall_result_label(Some(label))?;
        }
        let input = self.url_input_to_string(&input_value);
        let base = base_value.map(|value| self.url_input_to_string(&value));
        let parses = match base.as_deref() {
            Some(base) => Url::parse(base)
                .ok()
                .is_some_and(|base| base.join(&input).is_ok()),
            None => Url::parse(&input).is_ok(),
        };
        match (method, parses) {
            ("parse", true) => self.construct_url(args),
            ("parse", false) => Ok(Value::Null),
            (_, parses) => Ok(Value::Bool(parses)),
        }
    }

    pub(super) fn construct_url(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let input_value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let base_value = match self.builtin_arg(args, 1)? {
            None | Some(Value::Undefined) => None,
            Some(value) => Some(value),
        };
        let input_bound = self.url_value_to_string_upper_bound(&input_value);
        let base_bound = base_value
            .as_ref()
            .map(|value| self.url_value_to_string_upper_bound(value))
            .unwrap_or(0);
        self.check_temporary_memory_budget(Self::url_parse_working_upper_bound(
            input_bound,
            base_bound,
        ))?;
        let url_label = self.url_argument_state_label(&[Some(&input_value), base_value.as_ref()]);
        let input = self.url_input_to_string(&input_value);
        let base = base_value.map(|value| self.url_input_to_string(&value));
        let parsed = self.parse_whatwg_url(&input, base.as_deref())?;
        let href = parsed.as_str().to_string();
        let pairs = Self::url_pairs(&parsed);
        drop(parsed);
        drop(input);
        drop(base);
        let lifecycle_label = self.join_arg_range_label(args)?.join(&url_label);

        let projected_state_bytes = MEMORY_ESTIMATE_MAP_ENTRY_BYTES
            .saturating_mul(2)
            .saturating_add(std::mem::size_of::<UrlRuntimeState>() as u64)
            .saturating_add(std::mem::size_of::<UrlSearchParamsRuntimeState>() as u64)
            .saturating_add(Self::estimate_string_bytes(&href))
            .saturating_add(Self::estimate_url_pair_storage_bytes(&pairs))
            .saturating_add(Self::estimate_label_bytes(&lifecycle_label).saturating_mul(2));
        self.check_temporary_memory_budget(projected_state_bytes.saturating_add(
            Self::estimate_heap_object_bytes(&HeapObject::new()).saturating_mul(2),
        ))?;
        let mut url_state = UrlRuntimeState {
            href,
            search_params: ObjectId(0),
            lifecycle_label: lifecycle_label.clone(),
        };
        let mut params_state = UrlSearchParamsRuntimeState {
            pairs,
            owner_url: Some(ObjectId(0)),
            lifecycle_label,
        };

        // The first use materializes the prototypes past the rollback point;
        // a refusal takes them back with the objects (bd-9vouw.157).
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let mut url_id = None;
        let mut params_id = None;
        let outcome = (|| {
            let url_prototype = self.ensure_builtin_prototype("URL")?;
            let params_prototype = self.ensure_builtin_prototype("URLSearchParams")?;
            let allocated_url = self.alloc_object_with_prototype(Some(url_prototype))?;
            url_id = Some(allocated_url);
            let allocated_params = self.alloc_object_with_prototype(Some(params_prototype))?;
            params_id = Some(allocated_params);
            url_state.search_params = allocated_params;
            params_state.owner_url = Some(allocated_url);
            let retained_bytes = Self::estimate_url_state_bytes(&url_state)
                .saturating_add(Self::estimate_url_search_params_state_bytes(&params_state));
            self.apply_memory_component_delta(0, retained_bytes)?;
            self.url_objects.insert(allocated_url, url_state);
            self.url_search_params
                .insert(allocated_params, params_state);
            Ok(Value::Object(allocated_url))
        })();
        if outcome.is_err() {
            if let Some(id) = url_id {
                self.url_objects.remove(&id);
            }
            if let Some(id) = params_id {
                self.url_search_params.remove(&id);
            }
            self.rollback_heap_and_new_prototypes(previous_heap_len, previous_estimated_bytes);
        }
        outcome
    }

    /// `new URLSearchParams(init)` (URL Standard 6.1): a string (less a
    /// leading `?`) is form-urlencoded; an object with an @@iterator (an
    /// array, a Map, a generator) yields the pairs, each an iterable of
    /// exactly two items; any other object is a record whose own enumerable
    /// string keys name the pairs. (Only strings and URLSearchParams were
    /// accepted, so `new URLSearchParams({ q: 'x' })` threw.)
    pub(super) fn construct_url_search_params(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let initializer = self.builtin_arg(args, 0)?;
        let mut lifecycle_label = None;
        let pairs = match initializer {
            None | Some(Value::Undefined) => Vec::new(),
            Some(Value::Object(object_id)) if self.url_search_params.contains_key(&object_id) => {
                let state = &self.url_search_params[&object_id];
                self.check_temporary_memory_budget(Self::estimate_url_search_params_state_bytes(
                    state,
                ))?;
                state.pairs.clone()
            }
            Some(value) if value.is_object_like() => {
                // The initializer's reachable labels, and what its iterator
                // or getters produce, flow into the pairs.
                let mut label = self.join_arg_range_with_object_mutation_label(args)?;
                let pairs = self.url_search_params_object_pairs(module, value, &mut label)?;
                lifecycle_label = Some(label);
                pairs
            }
            Some(value) => {
                let input_bound = self.url_value_to_string_upper_bound(&value);
                self.check_temporary_memory_budget(
                    input_bound.saturating_add(Self::url_decoded_pairs_upper_bound(input_bound)),
                )?;
                let input = self.value_to_string(&value);
                let input = input.strip_prefix('?').unwrap_or(&input);
                form_urlencoded::parse(input.as_bytes())
                    .into_owned()
                    .collect()
            }
        };
        let Some(lifecycle_label) = lifecycle_label else {
            let lifecycle_label = self.join_arg_range_label(args)?;
            let object_id = self.allocate_url_search_params_state(pairs, None, lifecycle_label)?;
            return Ok(Value::Object(object_id));
        };
        let object_id =
            self.allocate_url_search_params_state(pairs, None, lifecycle_label.clone())?;
        self.finish_collection_seed(lifecycle_label)?;
        Ok(Value::Object(object_id))
    }

    pub(super) fn url_search_params_object_pairs(
        &mut self,
        module: Option<&Ir3Module>,
        init: Value,
        label: &mut Label,
    ) -> Result<Vec<(String, String)>, InterpreterError> {
        let backing = self.iterator_carrier_backing_id(&init, "URLSearchParams initializer")?;
        let iterable = match backing {
            _ if matches!(init, Value::Iterator(_) | Value::Generator(_)) => true,
            None => false,
            Some(object) if self.array_from_has_explicit_iterator(object)? => self
                .lookup_symbol_iterator_method(module, object, init.clone())?
                .is_some(),
            Some(object) => {
                let map = self.collection_storage_id(object, "Map", "__entries");
                let set = self.collection_storage_id(object, "Set", "__values");
                map.is_some()
                    || set.is_some()
                    || self
                        .heap
                        .get(object.0 as usize)
                        .is_some_and(|object| object.is_array)
            }
        };
        self.observe_collection_seed_label(label);
        let mut pairs = Vec::new();
        let mut retained_bytes = 0u64;
        if iterable {
            let mut source = self.collection_seed_source(module, init)?;
            while let Some(entry) = self.next_collection_seed(module, &mut source)? {
                self.observe_collection_seed_label(label);
                let pair = match self.url_search_params_sequence_pair(module, entry, label) {
                    Ok(pair) => pair,
                    Err(error) => return self.close_collection_seed(module, source, error),
                };
                retained_bytes = retained_bytes.saturating_add(
                    Self::estimate_url_pair_storage_bytes(std::slice::from_ref(&pair)),
                );
                if let Err(error) = self.check_temporary_memory_budget(retained_bytes) {
                    return self.close_collection_seed(module, source, error);
                }
                pairs.push(pair);
            }
            return Ok(pairs);
        }
        let Some(object) = backing else {
            return Ok(pairs);
        };
        // A later key whose name converts to an earlier one's (lone
        // surrogates become U+FFFD) replaces its value in place.
        let mut positions: BTreeMap<String, usize> = BTreeMap::new();
        for key in self.proxy_own_enumerable_string_keys(module, object)? {
            let value = self.proxy_aware_get_runtime_property(
                module,
                object,
                &RuntimePropertyKey::String(key.clone()),
                init.clone(),
                0,
            )?;
            self.observe_collection_seed_label(label);
            let name = key.to_string();
            let value = self.url_search_params_usv_string(module, value)?;
            self.observe_collection_seed_label(label);
            let pair = (name, value);
            retained_bytes = retained_bytes.saturating_add(Self::estimate_url_pair_storage_bytes(
                std::slice::from_ref(&pair),
            ));
            self.check_temporary_memory_budget(retained_bytes)?;
            match positions.get(&pair.0) {
                Some(&position) => pairs[position].1 = pair.1,
                None => {
                    positions.insert(pair.0.clone(), pairs.len());
                    pairs.push(pair);
                }
            }
        }
        Ok(pairs)
    }

    /// One `[name, value]` of a URLSearchParams sequence initializer: an
    /// iterable read to its end, which must have produced exactly two items.
    pub(super) fn url_search_params_sequence_pair(
        &mut self,
        module: Option<&Ir3Module>,
        entry: Value,
        label: &mut Label,
    ) -> Result<(String, String), InterpreterError> {
        if !entry.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "iterable [name, value] pair in the URLSearchParams initializer"
                    .to_string(),
                got: entry.type_name().to_string(),
            });
        }
        let mut items = self.collection_seed_source(module, entry)?;
        let (mut name, mut value) = (None, None);
        let mut count = 0usize;
        while let Some(item) = self.next_collection_seed(module, &mut items)? {
            self.observe_collection_seed_label(label);
            count = count.saturating_add(1);
            if count <= 2 {
                let text = self.url_search_params_usv_string(module, item)?;
                self.observe_collection_seed_label(label);
                *(if count == 1 { &mut name } else { &mut value }) = Some(text);
            }
        }
        match (name, value) {
            (Some(name), Some(value)) if count == 2 => Ok((name, value)),
            _ => Err(InterpreterError::TypeError {
                expected: "[name, value] pair of exactly two items".to_string(),
                got: format!("{count} items"),
            }),
        }
    }

    /// ToString of a URLSearchParams name or value (objects through
    /// ToPrimitive; a Symbol is a TypeError).
    pub(super) fn url_search_params_usv_string(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<String, InterpreterError> {
        let primitive = if value.is_object_like() {
            self.coerce_runtime_primitive(module, value, true)?
        } else {
            value
        };
        if matches!(primitive, Value::Symbol(_)) {
            return Err(Self::symbol_to_string_error());
        }
        let text = self.value_to_string(&primitive);
        self.check_temporary_memory_budget(Self::estimate_string_bytes(&text))?;
        Ok(text)
    }

    pub(super) fn url_search_params_receiver_id(
        &self,
        receiver: Option<Value>,
        method: &str,
    ) -> Result<ObjectId, InterpreterError> {
        let receiver = receiver.unwrap_or(Value::Undefined);
        let Value::Object(object_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: format!("URLSearchParams receiver for {method}"),
                got: receiver.type_name().to_string(),
            });
        };
        if !self.url_search_params.contains_key(&object_id) {
            return Err(InterpreterError::TypeError {
                expected: format!("branded URLSearchParams receiver for {method}"),
                got: "ordinary object".to_string(),
            });
        }
        Ok(object_id)
    }

    pub(super) fn url_object_property_value(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<Option<Value>, InterpreterError> {
        let Some(state) = self.url_objects.get(&object_id) else {
            return Ok(None);
        };
        if key == "searchParams" {
            return Ok(Some(Value::Object(state.search_params)));
        }
        if !matches!(
            key,
            "href"
                | "protocol"
                | "hostname"
                | "port"
                | "host"
                | "origin"
                | "username"
                | "password"
                | "pathname"
                | "search"
                | "hash"
        ) {
            return Ok(None);
        }
        let href_bytes = Self::estimate_string_bytes(&state.href);
        self.check_temporary_memory_budget(Self::url_parse_working_upper_bound(href_bytes, 0))?;
        let parsed = Url::parse(&state.href).map_err(|error| InterpreterError::InternalError {
            details: format!("authenticated URL state failed to reparse: {error}"),
        })?;
        let value = match key {
            "href" => Value::str(parsed.as_str()),
            "protocol" => Value::str(format!("{}:", parsed.scheme())),
            "hostname" => Value::str(parsed.host_str().unwrap_or_default()),
            "port" => Value::str(
                parsed
                    .port()
                    .map(|port| port.to_string())
                    .unwrap_or_default(),
            ),
            "host" => {
                let mut host = parsed.host_str().unwrap_or_default().to_string();
                if let Some(port) = parsed.port() {
                    host.push(':');
                    host.push_str(&port.to_string());
                }
                Value::str(host)
            }
            "origin" => Value::str(parsed.origin().ascii_serialization()),
            "username" => Value::str(parsed.username()),
            "password" => Value::str(parsed.password().unwrap_or_default()),
            "pathname" => Value::str(parsed.path()),
            "search" => Value::str(
                parsed
                    .query()
                    .filter(|query| !query.is_empty())
                    .map(|query| format!("?{query}"))
                    .unwrap_or_default(),
            ),
            "hash" => Value::str(
                parsed
                    .fragment()
                    .filter(|fragment| !fragment.is_empty())
                    .map(|fragment| format!("#{fragment}"))
                    .unwrap_or_default(),
            ),
            _ => unreachable!("URL getter key was validated before parsing"),
        };
        Ok(Some(value))
    }

    pub(super) fn set_url_object_property(
        &mut self,
        object_id: ObjectId,
        key: &str,
        value: &Value,
        mutation_label: &Label,
    ) -> Result<bool, InterpreterError> {
        // bd-9vouw.225: every URL Standard setter. Only `pathname` and `hash`
        // were handled; any other assignment made an own data property that
        // shadowed the getter while `href` kept the old value (normalize-url's
        // `urlObject.hostname = ...` to strip `www.`).
        if !matches!(
            key,
            "href"
                | "protocol"
                | "username"
                | "password"
                | "host"
                | "hostname"
                | "port"
                | "pathname"
                | "search"
                | "hash"
        ) || !self.url_objects.contains_key(&object_id)
        {
            return Ok(false);
        }
        let current = self
            .url_objects
            .get(&object_id)
            .expect("URL brand checked before state read");
        let clone_bytes = Self::estimate_url_state_bytes(current);
        let value_bound = self.url_value_to_string_upper_bound(value);
        let href_bytes = Self::estimate_string_bytes(&current.href);
        // `href` and `search` also rebuild the linked searchParams list.
        let params_rebuild_bound = if matches!(key, "href" | "search") {
            value_bound.saturating_mul(3)
        } else {
            0
        };
        let aggregate_peak = clone_bytes
            .saturating_add(value_bound)
            .saturating_add(Self::url_parse_working_upper_bound(href_bytes, value_bound))
            .saturating_add(value_bound.saturating_mul(3))
            .saturating_add(params_rebuild_bound)
            .saturating_add(Self::estimate_label_bytes(mutation_label).saturating_mul(2));
        self.check_temporary_memory_budget(aggregate_peak)?;
        let mut projected = current.clone();
        let mut parsed =
            Url::parse(&projected.href).map_err(|error| InterpreterError::InternalError {
                details: format!("authenticated URL state failed to reparse: {error}"),
            })?;
        let text = self.value_to_string(value);
        // The setters other than `href` ignore a value they cannot apply, as
        // the standard's basic URL parser with a state override does.
        match key {
            "pathname" => parsed.set_path(&text),
            "hash" if text.is_empty() => parsed.set_fragment(None),
            "hash" => parsed.set_fragment(Some(text.strip_prefix('#').unwrap_or(&text))),
            "href" => parsed = self.parse_whatwg_url(&text, None)?,
            "protocol" => {
                let _ = url::quirks::set_protocol(&mut parsed, &text);
            }
            "username" => {
                let _ = url::quirks::set_username(&mut parsed, &text);
            }
            "password" => {
                let _ = url::quirks::set_password(&mut parsed, &text);
            }
            "host" => {
                let _ = url::quirks::set_host(&mut parsed, &text);
            }
            "hostname" => {
                let _ = url::quirks::set_hostname(&mut parsed, &text);
            }
            "port" => {
                let _ = url::quirks::set_port(&mut parsed, &text);
            }
            "search" => url::quirks::set_search(&mut parsed, &text),
            _ => unreachable!("URL setter key was validated"),
        }
        let rebuilt_pairs = matches!(key, "href" | "search").then(|| Self::url_pairs(&parsed));
        projected.href = parsed.into();
        drop(text);
        projected.lifecycle_label = projected.lifecycle_label.join(mutation_label);
        let previous_bytes = clone_bytes;
        let next_bytes = Self::estimate_url_state_bytes(&projected);
        // The URL's searchParams object reflects the new query.
        let params_update = match rebuilt_pairs {
            Some(pairs) => {
                let params_id = projected.search_params;
                let params = self.url_search_params.get(&params_id).ok_or_else(|| {
                    InterpreterError::InternalError {
                        details: "URL lost its linked URLSearchParams".to_string(),
                    }
                })?;
                let mut next_params = params.clone();
                next_params.pairs = pairs;
                next_params.lifecycle_label = next_params.lifecycle_label.join(mutation_label);
                Some((
                    params_id,
                    Self::estimate_url_search_params_state_bytes(params),
                    next_params,
                ))
            }
            None => None,
        };
        let (params_previous_bytes, params_next_bytes) = params_update
            .as_ref()
            .map(|(_, previous, next)| {
                (
                    *previous,
                    Self::estimate_url_search_params_state_bytes(next),
                )
            })
            .unwrap_or((0, 0));
        self.check_temporary_memory_budget(next_bytes.saturating_add(params_next_bytes))?;
        self.apply_memory_component_delta(
            previous_bytes.saturating_add(params_previous_bytes),
            next_bytes.saturating_add(params_next_bytes),
        )?;
        self.url_objects.insert(object_id, projected);
        if let Some((params_id, _, next_params)) = params_update {
            self.url_search_params.insert(params_id, next_params);
        }
        Ok(true)
    }

    pub(super) fn mutate_url_search_params(
        &mut self,
        object_id: ObjectId,
        mutation: UrlSearchParamsMutation,
        mutation_label: &Label,
    ) -> Result<(), InterpreterError> {
        let current =
            self.url_search_params
                .get(&object_id)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "URLSearchParams receiver".to_string(),
                    got: "unbranded object".to_string(),
                })?;
        let owner_bytes = current
            .owner_url
            .and_then(|owner| self.url_objects.get(&owner))
            .map(Self::estimate_url_state_bytes)
            .unwrap_or(0);
        let current_params_bytes = Self::estimate_url_search_params_state_bytes(current);
        let previous_bytes = current_params_bytes.saturating_add(owner_bytes);
        let mutation_input_bytes = Self::url_search_params_mutation_input_bytes(&mutation);
        let mutation_label_bytes = Self::estimate_label_bytes(mutation_label);
        let projected_params_upper = current_params_bytes
            .saturating_add(mutation_input_bytes.saturating_mul(2))
            .saturating_add(std::mem::size_of::<(String, String)>() as u64);
        let sort_scratch = u64::try_from(current.pairs.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(std::mem::size_of::<(String, String)>() as u64);
        let serialized_upper = Self::url_serialization_upper_bound(&current.pairs)
            .saturating_add(mutation_input_bytes.saturating_mul(3))
            .saturating_add(2);
        let owner_parse_upper = current
            .owner_url
            .and_then(|owner| self.url_objects.get(&owner))
            .map(|owner| {
                Self::url_parse_working_upper_bound(
                    Self::estimate_string_bytes(&owner.href),
                    serialized_upper,
                )
            })
            .unwrap_or(0);
        let projection_stage = mutation_input_bytes
            .saturating_add(projected_params_upper)
            .saturating_add(sort_scratch)
            .saturating_add(mutation_label_bytes.saturating_mul(2));
        let owner_stage = mutation_input_bytes
            .saturating_add(projected_params_upper)
            .saturating_add(serialized_upper.saturating_mul(2))
            .saturating_add(owner_bytes)
            .saturating_add(owner_parse_upper)
            .saturating_add(serialized_upper.saturating_mul(3))
            .saturating_add(mutation_label_bytes.saturating_mul(3));
        self.check_temporary_memory_budget(projection_stage.max(owner_stage))?;
        let mut projected = current.clone();
        match mutation {
            UrlSearchParamsMutation::Append(name, value) => projected.pairs.push((name, value)),
            UrlSearchParamsMutation::Sort => projected
                .pairs
                .sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16())),
            UrlSearchParamsMutation::Delete(name) => {
                projected.pairs.retain(|(candidate, _)| candidate != &name);
            }
            UrlSearchParamsMutation::Set(name, value) => {
                let mut found = false;
                projected.pairs.retain_mut(|(candidate, existing)| {
                    if candidate != &name {
                        return true;
                    }
                    if found {
                        false
                    } else {
                        *existing = value.clone();
                        found = true;
                        true
                    }
                });
                if !found {
                    projected.pairs.push((name, value));
                }
            }
        }
        projected.lifecycle_label = projected.lifecycle_label.join(mutation_label);

        let serialized = Self::serialize_url_search_params(&projected.pairs);
        let mut projected_owner = if let Some(owner_id) = projected.owner_url {
            let mut owner = self.url_objects.get(&owner_id).cloned().ok_or_else(|| {
                InterpreterError::InternalError {
                    details: "linked URLSearchParams lost its authenticated owner".to_string(),
                }
            })?;
            let mut parsed =
                Url::parse(&owner.href).map_err(|error| InterpreterError::InternalError {
                    details: format!("authenticated URL state failed to reparse: {error}"),
                })?;
            parsed.set_query((!serialized.is_empty()).then_some(serialized.as_str()));
            owner.href = parsed.into();
            owner.lifecycle_label = owner.lifecycle_label.join(mutation_label);
            Some((owner_id, owner))
        } else {
            None
        };
        let next_bytes = Self::estimate_url_search_params_state_bytes(&projected).saturating_add(
            projected_owner
                .as_ref()
                .map(|(_, owner)| Self::estimate_url_state_bytes(owner))
                .unwrap_or(0),
        );
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        self.url_search_params.insert(object_id, projected);
        if let Some((owner_id, owner)) = projected_owner.take() {
            self.url_objects.insert(owner_id, owner);
        }
        Ok(())
    }

    pub(super) fn join_url_search_params_lifecycle_label(
        &mut self,
        object_id: ObjectId,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let Some(state) = self.url_search_params.get(&object_id) else {
            return Ok(());
        };
        let next_params_label = state.lifecycle_label.join(label);
        let owner_id = state.owner_url;
        let next_owner_label = owner_id
            .and_then(|owner| self.url_objects.get(&owner))
            .map(|owner| owner.lifecycle_label.join(label));
        let previous_label_bytes = Self::estimate_label_bytes(&state.lifecycle_label)
            .saturating_add(
                owner_id
                    .and_then(|owner| self.url_objects.get(&owner))
                    .map(|owner| Self::estimate_label_bytes(&owner.lifecycle_label))
                    .unwrap_or(0),
            );
        let next_label_bytes = Self::estimate_label_bytes(&next_params_label).saturating_add(
            next_owner_label
                .as_ref()
                .map(Self::estimate_label_bytes)
                .unwrap_or(0),
        );
        self.check_temporary_memory_budget(next_label_bytes)?;
        self.apply_memory_component_delta(previous_label_bytes, next_label_bytes)?;
        if let Some(state) = self.url_search_params.get_mut(&object_id) {
            state.lifecycle_label = next_params_label;
        }
        if let (Some(owner_id), Some(next_owner_label)) = (owner_id, next_owner_label)
            && let Some(owner) = self.url_objects.get_mut(&owner_id)
        {
            owner.lifecycle_label = next_owner_label;
        }
        Ok(())
    }

    pub(super) fn zlib_constants(&mut self) -> Result<Value, InterpreterError> {
        let constants = self.alloc_object_with_properties(&[
            ("Z_BEST_COMPRESSION", Value::Int(9)),
            ("Z_NO_COMPRESSION", Value::Int(0)),
            ("Z_DEFAULT_COMPRESSION", Value::Int(-1)),
            // Node's numeric brotli parameter/mode constants; options.params
            // uses these exact keys in both the facade and module-object path.
            ("BROTLI_PARAM_QUALITY", Value::Int(4)),
            ("BROTLI_PARAM_LGWIN", Value::Int(6)),
            ("BROTLI_PARAM_LGBLOCK", Value::Int(7)),
            ("BROTLI_PARAM_SIZE_HINT", Value::Int(9)),
            ("BROTLI_MODE_GENERIC", Value::Int(0)),
            ("BROTLI_MODE_TEXT", Value::Int(1)),
            ("BROTLI_MODE_FONT", Value::Int(2)),
            ("BROTLI_DEFAULT_QUALITY", Value::Int(11)),
            ("BROTLI_DEFAULT_WINDOW", Value::Int(22)),
        ])?;
        Ok(Value::Object(constants))
    }

    pub(super) fn zlib_input_byte_length(&self, value: &Value) -> Result<usize, InterpreterError> {
        match value {
            Value::Str(text) => Ok(text.len()),
            Value::Object(_) => Ok(self.buffer_like_view(value)?.byte_length),
            other => Err(InterpreterError::TypeError {
                expected: "string, Buffer, or Uint8Array zlib input".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn zlib_input_bytes(&self, value: &Value) -> Result<Vec<u8>, InterpreterError> {
        match value {
            Value::Str(text) => {
                self.check_buffer_temporary_bytes(text.len())?;
                Ok(text.as_bytes().to_vec())
            }
            Value::Object(_) => self.bytes_for_buffer_like(value),
            other => Err(InterpreterError::TypeError {
                expected: "string, Buffer, or Uint8Array zlib input".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn zlib_options_value(
        &self,
        args: RegRange,
    ) -> Result<Option<Value>, InterpreterError> {
        Ok(match self.builtin_arg(args, 1)? {
            Some(Value::Object(object_id)) => Some(Value::Object(object_id)),
            _ => None,
        })
    }

    pub(super) fn zlib_level(&self, options: Option<&Value>) -> Result<i32, InterpreterError> {
        let Some(level) = options.and_then(|value| self.fs_object_property(value, "level")) else {
            return Ok(6);
        };
        let level = match level {
            Value::Int(level) => i32::try_from(level).ok(),
            Value::Float(level) if level.inner().fract() == 0.0 => {
                i32::try_from(level.inner() as i64).ok()
            }
            _ => None,
        }
        .ok_or_else(|| InterpreterError::RangeError {
            message: "zlib level must be an integer between -1 and 9".to_string(),
        })?;
        if !(-1..=9).contains(&level) {
            return Err(InterpreterError::RangeError {
                message: format!("zlib level {level} is outside -1..=9"),
            });
        }
        Ok(if level == -1 { 6 } else { level })
    }

    pub(super) fn zlib_dictionary_value(
        &self,
        options: Option<&Value>,
    ) -> Result<Option<Value>, InterpreterError> {
        let Some(dictionary) =
            options.and_then(|value| self.fs_object_property(value, "dictionary"))
        else {
            return Ok(None);
        };
        if matches!(dictionary, Value::Undefined) {
            return Ok(None);
        }
        let Value::Object(_) = dictionary else {
            return Err(InterpreterError::TypeError {
                expected: "Buffer or Uint8Array zlib dictionary".to_string(),
                got: dictionary.type_name().to_string(),
            });
        };
        self.buffer_like_view(&dictionary)?;
        Ok(Some(dictionary))
    }

    pub(super) fn zlib_work_cost(
        input_len: usize,
        dictionary_len: usize,
        compress: bool,
        level: i32,
    ) -> u64 {
        let units = |bytes: u64| {
            (bytes.saturating_add(ZLIB_WORK_UNIT_BYTES - 1) / ZLIB_WORK_UNIT_BYTES).max(1)
        };
        let input_bytes = u64::try_from(input_len).unwrap_or(u64::MAX);
        let dictionary_bytes = u64::try_from(dictionary_len).unwrap_or(u64::MAX);
        let output_bound = if compress {
            u64::try_from(zlib_rs::compress_bound(input_len))
                .unwrap_or(u64::MAX)
                .saturating_add(32)
                .min(MAX_ARRAY_BUFFER_BYTE_LENGTH)
        } else {
            MAX_ARRAY_BUFFER_BYTE_LENGTH
        };
        let input_units = units(input_bytes.saturating_add(dictionary_bytes));
        let level_multiplier = if compress {
            u64::try_from(level.max(1)).unwrap_or(1)
        } else {
            1
        };
        input_units
            .saturating_mul(level_multiplier)
            .saturating_add(units(output_bound))
    }

    pub(super) fn charge_zlib_work(&mut self, work_cost: u64) -> Result<(), InterpreterError> {
        let next_executed = self.instructions_executed.saturating_add(work_cost);
        if next_executed > self.config.instruction_budget {
            return Err(InterpreterError::BudgetExhausted {
                executed: self.instructions_executed,
                budget: self.config.instruction_budget,
            });
        }
        self.instructions_executed = next_executed;
        Ok(())
    }

    pub(super) fn zlib_codec_preflight(
        &self,
        input_len: usize,
        dictionary_len: usize,
    ) -> Result<(), ZlibOperationFailure> {
        let input_len = u64::try_from(input_len).map_err(|_| {
            ZlibOperationFailure::Resource(InterpreterError::RangeError {
                message: "zlib input exceeds memory accounting range".to_string(),
            })
        })?;
        let dictionary_len = u64::try_from(dictionary_len).map_err(|_| {
            ZlibOperationFailure::Resource(InterpreterError::RangeError {
                message: "zlib dictionary exceeds memory accounting range".to_string(),
            })
        })?;
        if input_len > MAX_ARRAY_BUFFER_BYTE_LENGTH || dictionary_len > MAX_ARRAY_BUFFER_BYTE_LENGTH
        {
            return Err(ZlibOperationFailure::OutputLimit);
        }
        self.check_temporary_memory_budget(
            input_len
                .saturating_add(dictionary_len)
                .saturating_add(ZLIB_CODEC_WORKSPACE_BYTES)
                .saturating_add(MAX_ARRAY_BUFFER_BYTE_LENGTH)
                .saturating_add(ZLIB_IO_CHUNK_BYTES as u64),
        )?;
        Ok(())
    }

    pub(super) fn zlib_deflate_bytes(
        &self,
        format: ZlibFormat,
        input: &[u8],
        dictionary: Option<&[u8]>,
        level: i32,
    ) -> Result<Vec<u8>, ZlibOperationFailure> {
        self.zlib_codec_preflight(input.len(), dictionary.map_or(0, <[u8]>::len))?;
        let output_limit =
            usize::try_from(MAX_ARRAY_BUFFER_BYTE_LENGTH).expect("8 MiB zlib limit fits usize");
        let mut output = vec![0u8; output_limit];

        if format == ZlibFormat::Gzip {
            let cursor = Cursor::new(output.as_mut_slice());
            let mut encoder = GzBuilder::new()
                .mtime(0)
                .write(cursor, Compression::new(u32::try_from(level).unwrap_or(6)));
            encoder
                .write_all(input)
                .map_err(|_| ZlibOperationFailure::OutputLimit)?;
            let cursor = encoder
                .finish()
                .map_err(|_| ZlibOperationFailure::OutputLimit)?;
            let written = usize::try_from(cursor.position())
                .map_err(|_| ZlibOperationFailure::OutputLimit)?;
            if written > output_limit {
                return Err(ZlibOperationFailure::OutputLimit);
            }
            output.truncate(written);
            return Ok(output);
        }

        let zlib_header = format == ZlibFormat::Zlib;
        let mut encoder = zlib_rs::Deflate::new(level, zlib_header, 15);
        if let Some(dictionary) = dictionary {
            encoder
                .set_dictionary(dictionary)
                .map_err(|error| ZlibOperationFailure::data(error.as_str()))?;
        }
        let mut overflow = [0u8; 1];
        loop {
            let before_in = encoder.total_in();
            let before_out = encoder.total_out();
            let input_offset = usize::try_from(before_in)
                .map_err(|_| ZlibOperationFailure::data("invalid deflate input offset"))?;
            let output_offset =
                usize::try_from(before_out).map_err(|_| ZlibOperationFailure::OutputLimit)?;
            let output_slice = if output_offset < output_limit {
                &mut output[output_offset..]
            } else {
                &mut overflow[..]
            };
            let status = encoder
                .compress(
                    input.get(input_offset..).ok_or_else(|| {
                        ZlibOperationFailure::data("invalid deflate input offset")
                    })?,
                    output_slice,
                    zlib_rs::DeflateFlush::Finish,
                )
                .map_err(|error| ZlibOperationFailure::data(error.as_str()))?;
            let produced = encoder.total_out().saturating_sub(before_out);
            if output_offset >= output_limit && produced > 0 {
                return Err(ZlibOperationFailure::OutputLimit);
            }
            if status == zlib_rs::Status::StreamEnd {
                let written = usize::try_from(encoder.total_out())
                    .map_err(|_| ZlibOperationFailure::OutputLimit)?;
                if written > output_limit {
                    return Err(ZlibOperationFailure::OutputLimit);
                }
                output.truncate(written);
                return Ok(output);
            }
            if encoder.total_in() == before_in && encoder.total_out() == before_out {
                return Err(ZlibOperationFailure::data(
                    "deflate made no forward progress",
                ));
            }
        }
    }

    pub(super) fn zlib_inflate_stream(
        &self,
        input: &[u8],
        dictionary: Option<&[u8]>,
        zlib_header: bool,
    ) -> Result<Vec<u8>, ZlibOperationFailure> {
        self.zlib_codec_preflight(input.len(), dictionary.map_or(0, <[u8]>::len))?;
        let output_limit =
            usize::try_from(MAX_ARRAY_BUFFER_BYTE_LENGTH).expect("8 MiB zlib limit fits usize");
        let mut output = vec![0u8; output_limit];
        let mut overflow = [0u8; 1];
        let mut decoder = zlib_rs::Inflate::new(zlib_header, 15);
        let mut dictionary_installed = false;
        if !zlib_header {
            if let Some(dictionary) = dictionary {
                decoder
                    .set_dictionary(dictionary)
                    .map_err(|error| ZlibOperationFailure::data(error.as_str()))?;
                dictionary_installed = true;
            }
        }

        loop {
            let before_in = decoder.total_in();
            let before_out = decoder.total_out();
            let input_offset = usize::try_from(before_in)
                .map_err(|_| ZlibOperationFailure::data("invalid inflate input offset"))?;
            let output_offset =
                usize::try_from(before_out).map_err(|_| ZlibOperationFailure::OutputLimit)?;
            let output_slice = if output_offset < output_limit {
                &mut output[output_offset..]
            } else {
                &mut overflow[..]
            };
            let status = match decoder.decompress(
                input
                    .get(input_offset..)
                    .ok_or_else(|| ZlibOperationFailure::data("invalid inflate input offset"))?,
                output_slice,
                zlib_rs::InflateFlush::Finish,
            ) {
                Ok(status) => status,
                Err(zlib_rs::InflateError::NeedDict { .. }) if !dictionary_installed => {
                    let Some(dictionary) = dictionary else {
                        return Err(ZlibOperationFailure::need_dictionary(
                            "preset dictionary is required",
                        ));
                    };
                    decoder
                        .set_dictionary(dictionary)
                        .map_err(|error| ZlibOperationFailure::need_dictionary(error.as_str()))?;
                    dictionary_installed = true;
                    continue;
                }
                Err(error) => {
                    return Err(ZlibOperationFailure::data(error.as_str()));
                }
            };
            let produced = decoder.total_out().saturating_sub(before_out);
            if output_offset >= output_limit && produced > 0 {
                return Err(ZlibOperationFailure::OutputLimit);
            }
            if status == zlib_rs::Status::StreamEnd {
                let written = usize::try_from(decoder.total_out())
                    .map_err(|_| ZlibOperationFailure::OutputLimit)?;
                if written > output_limit {
                    return Err(ZlibOperationFailure::OutputLimit);
                }
                output.truncate(written);
                return Ok(output);
            }
            if decoder.total_in() == before_in && decoder.total_out() == before_out {
                return Err(ZlibOperationFailure::data(
                    "truncated or invalid compressed data",
                ));
            }
        }
    }

    pub(super) fn zlib_gunzip_bytes(&self, input: &[u8]) -> Result<Vec<u8>, ZlibOperationFailure> {
        self.zlib_codec_preflight(input.len(), 0)?;
        let output_limit =
            usize::try_from(MAX_ARRAY_BUFFER_BYTE_LENGTH).expect("8 MiB zlib limit fits usize");
        let mut output = vec![0u8; output_limit];
        let mut decoder = MultiGzDecoder::new(input);
        let mut written = 0usize;
        while written < output_limit {
            let end = written
                .saturating_add(ZLIB_IO_CHUNK_BYTES)
                .min(output_limit);
            let count = decoder
                .read(&mut output[written..end])
                .map_err(|error| ZlibOperationFailure::data(error.to_string()))?;
            if count == 0 {
                output.truncate(written);
                return Ok(output);
            }
            written = written
                .checked_add(count)
                .ok_or(ZlibOperationFailure::OutputLimit)?;
        }
        let mut overflow = [0u8; 1];
        match decoder.read(&mut overflow) {
            Ok(0) => {
                output.truncate(written);
                Ok(output)
            }
            Ok(_) => Err(ZlibOperationFailure::OutputLimit),
            Err(error) => Err(ZlibOperationFailure::data(error.to_string())),
        }
    }

    pub(super) fn zlib_inflate_bytes(
        &self,
        format: ZlibFormat,
        input: &[u8],
        dictionary: Option<&[u8]>,
    ) -> Result<Vec<u8>, ZlibOperationFailure> {
        match format {
            ZlibFormat::Gzip => self.zlib_gunzip_bytes(input),
            ZlibFormat::Zlib => self.zlib_inflate_stream(input, dictionary, true),
            ZlibFormat::Raw => self.zlib_inflate_stream(input, dictionary, false),
            ZlibFormat::Auto if input.starts_with(&[0x1f, 0x8b]) => self.zlib_gunzip_bytes(input),
            ZlibFormat::Auto => self.zlib_inflate_stream(input, dictionary, true),
            // Brotli never reaches the shared flate paths: dispatch_zlib_hostcall
            // routes it through brotli_decompress_bytes before this helper.
            ZlibFormat::Brotli => Err(ZlibOperationFailure::data(
                "brotli inflate must use the dedicated brotli codec",
            )),
        }
    }

    pub(super) fn alloc_zlib_buffer(
        &mut self,
        bytes: &[u8],
        live_output_capacity: usize,
        label: &Label,
        publish_hostcall_label: bool,
    ) -> Result<Value, InterpreterError> {
        let label_bytes = Self::estimate_label_bytes(label);
        let live_temporary_bytes = u64::try_from(live_output_capacity)
            .unwrap_or(u64::MAX)
            // One backing label and, for synchronous calls, one pending-result
            // label can both be retained while the codec output Vec is live.
            // A third charge covers the temporary clones used by the joins.
            .saturating_add(label_bytes.saturating_mul(3));
        let live_temporary_bytes =
            usize::try_from(live_temporary_bytes).map_err(|_| InterpreterError::RangeError {
                message: "zlib temporary memory exceeds accounting range".to_string(),
            })?;
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            let object_id =
                self.alloc_fresh_buffer_object(bytes.len(), Some(bytes), live_temporary_bytes)?;
            self.join_binary_storage_label(object_id, label)?;
            if publish_hostcall_label {
                self.replace_pending_hostcall_result_label(Some(label.clone()))?;
            }
            Ok(Value::Object(object_id))
        })();
        if result.is_err() {
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn zlib_output_limit_error(&self) -> InterpreterError {
        InterpreterError::RangeError {
            message: format!(
                "zlib output exceeds the engine Buffer cap of {MAX_ARRAY_BUFFER_BYTE_LENGTH} bytes"
            ),
        }
    }

    pub(super) fn zlib_sync_data_error(
        &mut self,
        code: &'static str,
        message: String,
        label: &Label,
    ) -> InterpreterError {
        // Materialize the shared prototype outside the transaction so a
        // rollback can never leave builtin_prototypes pointing past heap.len().
        if let Err(error) = self.ensure_builtin_prototype("Error") {
            return error;
        }
        let dominant_label = if label > &self.pending_exception_label {
            label
        } else {
            &self.pending_exception_label
        };
        if let Err(error) =
            self.check_temporary_memory_budget(Self::estimate_label_bytes(dominant_label))
        {
            return error;
        }
        let next_pending_label = dominant_label.clone();
        let previous_label_bytes = Self::estimate_label_bytes(&self.pending_exception_label);
        let next_label_bytes = Self::estimate_label_bytes(&next_pending_label);
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let thrown = match self.construct_buffer_node_error("Error", code, message) {
            Ok(value) => value,
            Err(error) => {
                self.rollback_heap_to_len(previous_heap_len);
                self.estimated_memory_bytes = previous_estimated_bytes;
                return error;
            }
        };
        if let Err(error) =
            self.apply_memory_component_delta(previous_label_bytes, next_label_bytes)
        {
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
            return error;
        }
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = next_pending_label;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    pub(super) fn schedule_zlib_data_error_callback(
        &mut self,
        callback: u32,
        code: &'static str,
        message: String,
        invocation_label: Label,
    ) -> Result<Value, InterpreterError> {
        // Keep the canonical Error prototype outside the rollback boundary;
        // builtin_prototypes must never retain an ObjectId truncated below.
        self.ensure_builtin_prototype("Error")?;
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let error = match self.construct_buffer_node_error("Error", code, message) {
            Ok(error) => error,
            Err(error) => {
                self.rollback_heap_to_len(previous_heap_len);
                self.estimated_memory_bytes = previous_estimated_bytes;
                return Err(error);
            }
        };
        if let Err(schedule_error) =
            self.schedule_io_callback_with_label(callback, vec![error], invocation_label)
        {
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
            return Err(schedule_error);
        }
        Ok(Value::Undefined)
    }

    pub(super) fn dispatch_zlib_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (compress, format, asynchronous) = match cap {
            "builtin:ZlibGzipSync" => (true, ZlibFormat::Gzip, false),
            "builtin:ZlibGunzipSync" => (false, ZlibFormat::Gzip, false),
            "builtin:ZlibDeflateSync" => (true, ZlibFormat::Zlib, false),
            "builtin:ZlibInflateSync" => (false, ZlibFormat::Zlib, false),
            "builtin:ZlibDeflateRawSync" => (true, ZlibFormat::Raw, false),
            "builtin:ZlibInflateRawSync" => (false, ZlibFormat::Raw, false),
            "builtin:ZlibUnzipSync" => (false, ZlibFormat::Auto, false),
            "builtin:ZlibBrotliCompressSync" => (true, ZlibFormat::Brotli, false),
            "builtin:ZlibBrotliDecompressSync" => (false, ZlibFormat::Brotli, false),
            "builtin:ZlibGzip" => (true, ZlibFormat::Gzip, true),
            "builtin:ZlibGunzip" => (false, ZlibFormat::Gzip, true),
            "builtin:ZlibDeflate" => (true, ZlibFormat::Zlib, true),
            "builtin:ZlibInflate" => (false, ZlibFormat::Zlib, true),
            _ => {
                return Err(InterpreterError::InternalError {
                    details: format!("unknown zlib builtin {cap}"),
                });
            }
        };
        let input_value =
            self.builtin_arg(args, 0)?
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "zlib input argument".to_string(),
                    got: "missing argument".to_string(),
                })?;
        let callback = if asynchronous {
            let callback = self
                .builtin_arg(args, args.count.saturating_sub(1))?
                .and_then(|value| match value {
                    Value::Closure(closure_id) => Some(closure_id),
                    _ => None,
                });
            Some(callback.ok_or_else(|| InterpreterError::TypeError {
                expected: "zlib callback function".to_string(),
                got: "missing or non-callable callback".to_string(),
            })?)
        } else {
            None
        };
        let options = self.zlib_options_value(args)?;
        let level = self.zlib_level(options.as_ref())?;
        let dictionary_value = self.zlib_dictionary_value(options.as_ref())?;
        let input_len = self.zlib_input_byte_length(&input_value)?;
        let dictionary_len = dictionary_value
            .as_ref()
            .map(|value| self.buffer_like_view(value).map(|view| view.byte_length))
            .transpose()?
            .unwrap_or(0);
        let input_len_u64 = u64::try_from(input_len).unwrap_or(u64::MAX);
        let dictionary_len_u64 = u64::try_from(dictionary_len).unwrap_or(u64::MAX);
        if input_len_u64 > MAX_ARRAY_BUFFER_BYTE_LENGTH
            || dictionary_len_u64 > MAX_ARRAY_BUFFER_BYTE_LENGTH
        {
            return Err(self.zlib_output_limit_error());
        }

        // Authenticate the full invocation label through borrowed register and
        // Buffer-backing labels. Then prove the worst physical peak before the
        // first attacker-sized clone or codec instruction: input + dictionary
        // copies, codec workspace, the bounded output Vec, a maximum-size
        // published Buffer, metadata, and all retained/temporary label clones.
        let invocation_label = {
            let mut dominant_label: Option<&Label> = None;
            for index in 0..args.count {
                let register =
                    args.start
                        .checked_add(index)
                        .ok_or(InterpreterError::RegisterOutOfBounds {
                            register: args.start,
                            max: u32::MAX,
                        })?;
                let candidate = self.get_register_label(register)?;
                if dominant_label.is_none_or(|current| candidate > current) {
                    dominant_label = Some(candidate);
                }
            }
            if let Value::Object(object_id) = &input_value
                && let Some(candidate) = self.binary_storage_label_ref(*object_id)
                && dominant_label.is_none_or(|current| candidate > current)
            {
                dominant_label = Some(candidate);
            }
            if let Some(Value::Object(object_id)) = dictionary_value.as_ref()
                && let Some(candidate) = self.binary_storage_label_ref(*object_id)
                && dominant_label.is_none_or(|current| candidate > current)
            {
                dominant_label = Some(candidate);
            }
            let label_bytes = dominant_label.map(Self::estimate_label_bytes).unwrap_or(0);
            self.check_temporary_memory_budget(
                input_len_u64
                    .saturating_add(dictionary_len_u64)
                    .saturating_add(ZLIB_CODEC_WORKSPACE_BYTES)
                    .saturating_add(MAX_ARRAY_BUFFER_BYTE_LENGTH.saturating_mul(2))
                    .saturating_add(ZLIB_IO_CHUNK_BYTES as u64)
                    .saturating_add(ZLIB_PUBLICATION_METADATA_BYTES)
                    .saturating_add(label_bytes.saturating_mul(3)),
            )?;
            dominant_label.cloned().unwrap_or(Label::Public)
        };

        self.charge_zlib_work(Self::zlib_work_cost(
            input_len,
            dictionary_len,
            compress,
            level,
        ))?;
        let input = self.zlib_input_bytes(&input_value)?;
        let dictionary = dictionary_value
            .as_ref()
            .map(|value| self.bytes_for_buffer_like(value))
            .transpose()?;
        let result = if format == ZlibFormat::Brotli {
            // bd-zlib-residual-l6ev2: Brotli has its own parameter surface
            // (options.params keyed by zlib.constants.BROTLI_PARAM_*) and its
            // own codec; it never shares the deflate dictionary/level path.
            let (quality, lgwin) = self.zlib_brotli_params(options.as_ref())?;
            if compress {
                Self::brotli_compress_bytes(&input, quality, lgwin)
            } else {
                Self::brotli_decompress_bytes(&input)
            }
        } else if compress {
            self.zlib_deflate_bytes(format, &input, dictionary.as_deref(), level)
        } else {
            self.zlib_inflate_bytes(format, &input, dictionary.as_deref())
        };
        // Codec workspaces are gone when the helper returns. Release the
        // caller-owned input and dictionary clones before allocating the
        // output Buffer so the publication preflight can describe the exact
        // remaining peak: output Vec capacity + committed Buffer + labels.
        drop(input);
        drop(dictionary);

        match (result, callback) {
            (Ok(bytes), None) => {
                let live_output_capacity = bytes.capacity();
                self.alloc_zlib_buffer(&bytes, live_output_capacity, &invocation_label, true)
            }
            (Ok(bytes), Some(callback)) => {
                let previous_heap_len = self.heap.len();
                let previous_estimated_bytes = self.estimated_memory_bytes;
                let live_output_capacity = bytes.capacity();
                let value =
                    self.alloc_zlib_buffer(&bytes, live_output_capacity, &invocation_label, false)?;
                drop(bytes);
                if let Err(error) = self.schedule_io_callback_with_label(
                    callback,
                    vec![Value::Null, value],
                    invocation_label,
                ) {
                    self.rollback_heap_to_len(previous_heap_len);
                    self.estimated_memory_bytes = previous_estimated_bytes;
                    return Err(error);
                }
                Ok(Value::Undefined)
            }
            (Err(ZlibOperationFailure::Data { code, message }), None) => {
                Err(self.zlib_sync_data_error(code, message, &invocation_label))
            }
            (Err(ZlibOperationFailure::Data { code, message }), Some(callback)) => {
                self.schedule_zlib_data_error_callback(callback, code, message, invocation_label)
            }
            (Err(ZlibOperationFailure::OutputLimit), _) => Err(self.zlib_output_limit_error()),
            (Err(ZlibOperationFailure::Resource(error)), _) => Err(error),
        }
    }

    /// Read one `options.params` entry keyed by a `zlib.constants.BROTLI_PARAM_*`
    /// numeric constant (the fixture shape is
    /// `{ params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } }`, so the
    /// property name is the decimal form of the constant).
    pub(super) fn zlib_brotli_param(
        &self,
        options: Option<&Value>,
        key: f64,
    ) -> Result<Option<i64>, InterpreterError> {
        let Some(params) = options.and_then(|value| self.fs_object_property(value, "params"))
        else {
            return Ok(None);
        };
        if matches!(params, Value::Undefined) {
            return Ok(None);
        }
        let Value::Object(_) = &params else {
            return Err(InterpreterError::TypeError {
                expected: "object zlib brotli params".to_string(),
                got: params.type_name().to_string(),
            });
        };
        let key_name = if key.fract() == 0.0 {
            format!("{}", key as i64)
        } else {
            format!("{key}")
        };
        match self.fs_object_property(&params, &key_name) {
            None | Some(Value::Undefined) => Ok(None),
            Some(Value::Int(value)) => Ok(Some(value)),
            Some(Value::Float(value)) if value.inner().fract() == 0.0 => {
                Ok(Some(value.inner() as i64))
            }
            Some(other) => Err(InterpreterError::RangeError {
                message: format!(
                    "zlib brotli parameter {key_name} must be an integer, got {}",
                    other.type_name()
                ),
            }),
        }
    }

    /// Parse the (quality, lgwin) pair for Brotli compression from
    /// `options.params`. Unspecified parameters fall back to the Brotli
    /// defaults Node exposes (`BROTLI_DEFAULT_QUALITY` = 11,
    /// `BROTLI_DEFAULT_WINDOW` = 22).
    pub(super) fn zlib_brotli_params(
        &self,
        options: Option<&Value>,
    ) -> Result<(u32, u32), InterpreterError> {
        const BROTLI_PARAM_QUALITY: f64 = 4.0;
        const BROTLI_PARAM_LGWIN: f64 = 6.0;
        let mut quality = 11u32;
        let mut lgwin = 22u32;
        if let Some(parsed) = self.zlib_brotli_param(options, BROTLI_PARAM_QUALITY)? {
            let parsed = u32::try_from(parsed).map_err(|_| InterpreterError::RangeError {
                message: format!("zlib brotli quality {parsed} is outside 0..=11"),
            })?;
            if parsed > 11 {
                return Err(InterpreterError::RangeError {
                    message: format!("zlib brotli quality {parsed} is outside 0..=11"),
                });
            }
            quality = parsed;
        }
        if let Some(parsed) = self.zlib_brotli_param(options, BROTLI_PARAM_LGWIN)? {
            let parsed = u32::try_from(parsed).map_err(|_| InterpreterError::RangeError {
                message: format!("zlib brotli lgwin {parsed} is outside 10..=24"),
            })?;
            if !(10..=24).contains(&parsed) {
                return Err(InterpreterError::RangeError {
                    message: format!("zlib brotli lgwin {parsed} is outside 10..=24"),
                });
            }
            lgwin = parsed;
        }
        Ok((quality, lgwin))
    }

    /// One-shot Brotli compression with explicit (quality, lgwin) parameters.
    pub(super) fn brotli_compress_bytes(
        input: &[u8],
        quality: u32,
        lgwin: u32,
    ) -> Result<Vec<u8>, ZlibOperationFailure> {
        // brotli 8.x stores both knobs as i32; the parser above already
        // range-checked quality into 0..=11 and lgwin into 10..=24.
        let params = brotli::enc::backward_references::BrotliEncoderParams {
            quality: quality as i32,
            lgwin: lgwin as i32,
            ..brotli::enc::backward_references::BrotliEncoderParams::default()
        };
        let mut output = Vec::new();
        let mut writer = brotli::CompressorWriter::with_params(&mut output, 4096, &params);
        use std::io::Write as _;
        writer
            .write_all(input)
            .map_err(|_| ZlibOperationFailure::OutputLimit)?;
        writer
            .flush()
            .map_err(|_| ZlibOperationFailure::OutputLimit)?;
        drop(writer);
        Ok(output)
    }

    /// One-shot Brotli decompression via the pull-based reader so decoder
    /// faults actually surface: the push-style DecompressorWriter buffers
    /// internally and its write/flush pair can return Ok while swallowing a
    /// corrupt stream, which would hand guests a silent empty Buffer where
    /// Node throws. Corrupt or truncated input must always fail as a data
    /// error (fixture 0009 semantics).
    pub(super) fn brotli_decompress_bytes(input: &[u8]) -> Result<Vec<u8>, ZlibOperationFailure> {
        use std::io::Read as _;
        if input.is_empty() {
            // A valid Brotli stream is never zero bytes; Node rejects this.
            return Err(ZlibOperationFailure::data("unexpected end of brotli input"));
        }
        let mut reader = brotli::Decompressor::new(input, 4096);
        let mut output = Vec::new();
        reader
            .read_to_end(&mut output)
            .map_err(|error| ZlibOperationFailure::data(error.to_string()))?;
        Ok(output)
    }
    // ---------------------------------------------------------------------
    // Deterministic Node crypto builtins (bd-2z157)
    // ---------------------------------------------------------------------

    pub(super) fn charge_crypto_work(&mut self, work: u64) -> Result<(), InterpreterError> {
        let next_executed = self.instructions_executed.saturating_add(work.max(1));
        if next_executed > self.config.instruction_budget {
            return Err(InterpreterError::BudgetExhausted {
                executed: self.instructions_executed,
                budget: self.config.instruction_budget,
            });
        }
        self.instructions_executed = next_executed;
        Ok(())
    }

    pub(super) fn crypto_byte_work(bytes: usize) -> u64 {
        u64::try_from(bytes)
            .unwrap_or(u64::MAX)
            .div_ceil(CRYPTO_WORK_UNIT_BYTES)
    }

    /// Conservative transient peak for the cipher output pipeline.
    ///
    /// Stateful cipher calls can retain the complete transformed output, a
    /// cloned raw tail, and the string-decoder combined buffer together.  A
    /// string publication can then retain up to four times that combined
    /// buffer while producing a `JsString`.  This helper intentionally also
    /// covers the cheaper Buffer-publication branch so callers can preflight
    /// once before invoking RustCrypto.
    pub(super) fn crypto_output_pipeline_peak_bytes(
        transformed_bound: u64,
        raw_output_bound: u64,
        previous_remainder_bound: u64,
    ) -> u64 {
        let stream_combined_bound = raw_output_bound.saturating_add(previous_remainder_bound);
        transformed_bound
            .saturating_add(raw_output_bound)
            .saturating_add(stream_combined_bound)
            .saturating_add(stream_combined_bound.saturating_mul(4))
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_mul(2))
            .saturating_add(CRYPTO_OUTPUT_PUBLICATION_METADATA_BYTES)
    }

    pub(super) fn crypto_output_publication_peak_bytes(
        payload_bound: u64,
        label: &Label,
        publish_result_label: bool,
    ) -> u64 {
        let label_copies = if publish_result_label { 2 } else { 1 };
        payload_bound
            .saturating_mul(4)
            .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_mul(2))
            .saturating_add(CRYPTO_OUTPUT_PUBLICATION_METADATA_BYTES)
            .saturating_add(Self::estimate_label_bytes(label).saturating_mul(label_copies))
    }

    pub(super) fn crypto_invocation_label(
        &self,
        args: RegRange,
    ) -> Result<Label, InterpreterError> {
        let mut winner: Option<&Label> = self.active_execution_context_label();
        for index in 0..args.count {
            let register =
                args.start
                    .checked_add(index)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: u32::MAX,
                    })?;
            let register_label = self.get_register_label(register)?;
            if winner.is_none_or(|current| register_label > current) {
                winner = Some(register_label);
            }
            if let Value::Object(object_id) = self.read_reg(register)?
                && let Some(backing_label) = self.binary_storage_label_ref(object_id)
                && winner.is_none_or(|current| backing_label > current)
            {
                winner = Some(backing_label);
            }
        }
        let Some(winner) = winner else {
            return Ok(Label::Public);
        };
        self.check_temporary_memory_budget(Self::estimate_label_bytes(winner))?;
        Ok(winner.clone())
    }

    pub(super) fn enforce_crypto_hmac_ingress_clearance(
        &mut self,
        capability: &str,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let clearance = Label::Internal;
        if label.can_flow_to(&clearance) {
            self.record_ifc_runtime_flow_audit(
                capability,
                label,
                &clearance,
                IfcRuntimeFlowDecision::AllowedLattice,
                None,
                None,
            );
            return Ok(());
        }
        // bd-vw7s1: generic declassification receipts and ambient flow policies
        // cannot authorize keyed authenticator derivation over un-declassified
        // secrets; any future release must carry an explicit authenticator route.
        self.record_ifc_runtime_flow_audit(
            capability,
            label,
            &clearance,
            IfcRuntimeFlowDecision::Denied,
            None,
            None,
        );
        Err(InterpreterError::CapabilityDenied {
            capability: format!("{capability}:confidentiality"),
        })
    }

    pub(super) fn crypto_input_bytes_with_mode(
        &self,
        value: &Value,
        encoding: Option<&Value>,
        allow_array_buffer: bool,
    ) -> Result<Vec<u8>, InterpreterError> {
        match value {
            Value::Str(text) => {
                let encoding = Self::crypto_input_encoding_name(encoding)?;
                self.decode_buffer_string(text, encoding)
            }
            Value::Object(_) => self.crypto_binary_view_bytes_with_mode(value, allow_array_buffer),
            other => Err(InterpreterError::TypeError {
                expected: if allow_array_buffer {
                    "string or BinaryLike crypto input".to_string()
                } else {
                    "string or ArrayBufferView crypto input".to_string()
                },
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn crypto_input_bytes(
        &self,
        value: &Value,
        encoding: Option<&Value>,
    ) -> Result<Vec<u8>, InterpreterError> {
        self.crypto_input_bytes_with_mode(value, encoding, true)
    }

    pub(super) fn crypto_update_input_bytes(
        &self,
        value: &Value,
        encoding: Option<&Value>,
    ) -> Result<Vec<u8>, InterpreterError> {
        self.crypto_input_bytes_with_mode(value, encoding, false)
    }

    /// Conservative peak allocation for materializing a guest crypto input.
    /// Callers which keep more than one input alive must sum these bounds and
    /// preflight the aggregate before cloning the first guest-controlled byte.
    pub(super) fn crypto_input_allocation_bound_with_mode(
        &self,
        value: &Value,
        encoding: Option<&Value>,
        allow_array_buffer: bool,
    ) -> Result<u64, InterpreterError> {
        let bytes = match value {
            Value::Str(text) => {
                let encoding = Self::crypto_input_encoding_name(encoding)?;
                match encoding {
                    "utf8" | "utf-8" => text.len(),
                    "ascii" | "latin1" | "binary" => text.utf16_len(),
                    "ucs2" | "ucs-2" | "utf16le" | "utf-16le" => text
                        .utf16_len()
                        .checked_mul(2)
                        .ok_or_else(|| InterpreterError::RangeError {
                            message: "crypto UTF-16 input size overflows host address space"
                                .to_string(),
                        })?,
                    "hex" => text.len() / 2,
                    // Decoding retains normalized and decoded buffers at the
                    // same time. Match decode_buffer_string's peak bound.
                    "base64" | "base64url" => text
                        .len()
                        .checked_mul(2)
                        .and_then(|length| length.checked_add(3))
                        .ok_or_else(|| InterpreterError::RangeError {
                            message: "crypto base64 input size overflows host address space"
                                .to_string(),
                        })?,
                    _ => {
                        return Err(InterpreterError::TypeError {
                            expected: "a recognized Node BufferEncoding".to_string(),
                            got: Self::crypto_diagnostic_fragment(encoding),
                        });
                    }
                }
            }
            Value::Object(_) => self.crypto_binary_view_range(value, allow_array_buffer)?.2,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: if allow_array_buffer {
                        "string or BinaryLike crypto input".to_string()
                    } else {
                        "string or ArrayBufferView crypto input".to_string()
                    },
                    got: other.type_name().to_string(),
                });
            }
        };
        Ok(u64::try_from(bytes).unwrap_or(u64::MAX))
    }

    pub(super) fn crypto_input_allocation_bound(
        &self,
        value: &Value,
        encoding: Option<&Value>,
    ) -> Result<u64, InterpreterError> {
        self.crypto_input_allocation_bound_with_mode(value, encoding, true)
    }

    pub(super) fn crypto_update_input_allocation_bound(
        &self,
        value: &Value,
        encoding: Option<&Value>,
    ) -> Result<u64, InterpreterError> {
        self.crypto_input_allocation_bound_with_mode(value, encoding, false)
    }

    pub(super) fn crypto_required_arg(
        &self,
        args: RegRange,
        index: u32,
        expected: &str,
    ) -> Result<Value, InterpreterError> {
        self.builtin_arg(args, index)?
            .ok_or_else(|| InterpreterError::TypeError {
                expected: expected.to_string(),
                got: "missing argument".to_string(),
            })
    }

    pub(super) fn crypto_required_string_arg(
        &self,
        args: RegRange,
        index: u32,
        expected: &str,
    ) -> Result<JsString, InterpreterError> {
        match self.crypto_required_arg(args, index, expected)? {
            Value::Str(value) => Ok(value),
            other => Err(InterpreterError::TypeError {
                expected: expected.to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn crypto_diagnostic_fragment(value: &str) -> String {
        const MAX_CHARS: usize = 64;
        let mut chars = value.chars();
        let mut fragment = chars.by_ref().take(MAX_CHARS).collect::<String>();
        if chars.next().is_some() {
            fragment.push_str("...");
        }
        fragment
    }

    pub(super) fn crypto_canonical_buffer_encoding(name: &str) -> Option<&'static str> {
        if name.eq_ignore_ascii_case("utf8") || name.eq_ignore_ascii_case("utf-8") {
            Some("utf8")
        } else if name.eq_ignore_ascii_case("ascii") {
            Some("ascii")
        } else if name.eq_ignore_ascii_case("latin1") || name.eq_ignore_ascii_case("binary") {
            Some("latin1")
        } else if name.eq_ignore_ascii_case("ucs2")
            || name.eq_ignore_ascii_case("ucs-2")
            || name.eq_ignore_ascii_case("utf16le")
            || name.eq_ignore_ascii_case("utf-16le")
        {
            Some("utf16le")
        } else if name.eq_ignore_ascii_case("hex") {
            Some("hex")
        } else if name.eq_ignore_ascii_case("base64") {
            Some("base64")
        } else if name.eq_ignore_ascii_case("base64url") {
            Some("base64url")
        } else {
            None
        }
    }

    pub(super) fn crypto_input_encoding_name(
        encoding: Option<&Value>,
    ) -> Result<&'static str, InterpreterError> {
        match encoding {
            None | Some(Value::Undefined) => Ok("utf8"),
            Some(Value::Str(encoding)) => Self::crypto_canonical_buffer_encoding(encoding)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "a recognized Node BufferEncoding".to_string(),
                    got: Self::crypto_diagnostic_fragment(encoding),
                }),
            Some(other) => Err(InterpreterError::TypeError {
                expected: "crypto string input encoding".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn crypto_integer_arg(
        &self,
        value: &Value,
        name: &str,
        allow_zero: bool,
    ) -> Result<usize, InterpreterError> {
        let integer = match value {
            Value::Int(value) if value.unsigned_abs() <= CRYPTO_MAX_SAFE_INTEGER as u64 => *value,
            Value::Float(value)
                if value.inner().is_finite()
                    && value.inner().fract() == 0.0
                    && value.inner().abs() <= CRYPTO_MAX_SAFE_INTEGER as f64 =>
            {
                value.inner() as i64
            }
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: format!("integer crypto {name}"),
                    got: value.type_name().to_string(),
                });
            }
        };
        let minimum = if allow_zero { 0 } else { 1 };
        if integer < minimum {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "crypto {name} must be {}",
                    if allow_zero {
                        "non-negative"
                    } else {
                        "positive"
                    }
                ),
            });
        }
        usize::try_from(integer).map_err(|_| InterpreterError::RangeError {
            message: format!("crypto {name} exceeds host addressable range"),
        })
    }

    pub(super) fn crypto_throw_node_error(
        &mut self,
        name: &str,
        code: &str,
        message: String,
        label: &Label,
    ) -> InterpreterError {
        self.crypto_throw_node_error_with_temporary_budget(name, code, message, label, 0)
    }

    pub(super) fn crypto_throw_node_error_with_temporary_budget(
        &mut self,
        name: &str,
        code: &str,
        message: String,
        label: &Label,
        already_owned_temporary_bytes: u64,
    ) -> InterpreterError {
        // Error materialization captures up to 50 stack frames.  Every frame
        // owns formatting fields before the final stack string is installed,
        // and the error/prototype objects own four string-valued properties.
        // Reserve a deliberately conservative aggregate before allocating the
        // first object so caller-owned crypto buffers cannot overlap an
        // individually successful but collectively over-budget error path.
        let source_bytes = self
            .current_module_specifier
            .as_ref()
            .map_or(16, |source| u64::try_from(source.len()).unwrap_or(u64::MAX));
        let stack_materialization_bound = source_bytes
            .saturating_add(256)
            .saturating_mul(50)
            .saturating_mul(4);
        let property_materialization_bound = u64::try_from(
            name.len()
                .saturating_add(code.len())
                .saturating_add(message.capacity()),
        )
        .unwrap_or(u64::MAX)
        .saturating_mul(4)
        .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_mul(16))
        .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_mul(16))
        .saturating_add(MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES.saturating_mul(4));
        if let Err(error) = self.check_temporary_memory_budget(
            already_owned_temporary_bytes
                .saturating_add(stack_materialization_bound)
                .saturating_add(property_materialization_bound)
                .saturating_add(Self::estimate_label_bytes(label).saturating_mul(2)),
        ) {
            return error;
        }
        if let Err(error) = self.ensure_builtin_prototype(name) {
            return error;
        }
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let thrown = match self.construct_buffer_node_error(name, code, message) {
            Ok(value) => value,
            Err(error) => {
                self.rollback_heap_to_len(previous_heap_len);
                self.estimated_memory_bytes = previous_estimated_bytes;
                return error;
            }
        };
        let dominant_label = if &self.pending_exception_label >= label {
            &self.pending_exception_label
        } else {
            label
        };
        // The caller-owned label and the pending-slot clone overlap.  Build
        // the accounted error object first, then gate both live label copies
        // together before cloning the winner.
        if let Err(error) = self.check_temporary_memory_budget(
            Self::estimate_label_bytes(dominant_label).saturating_mul(2),
        ) {
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
            return error;
        }
        let next_pending_label = dominant_label.clone();
        let previous_label_bytes = Self::estimate_label_bytes(&self.pending_exception_label);
        let next_label_bytes = Self::estimate_label_bytes(&next_pending_label);
        if let Err(error) =
            self.apply_memory_component_delta(previous_label_bytes, next_label_bytes)
        {
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
            return error;
        }
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = next_pending_label;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    pub(super) fn crypto_alloc_object(
        &mut self,
        state: CryptoObjectState,
    ) -> Result<Value, InterpreterError> {
        self.crypto_alloc_object_with_temporary_budget(state, 0)
    }

    pub(super) fn crypto_alloc_object_with_temporary_budget(
        &mut self,
        state: CryptoObjectState,
        already_owned_temporary_bytes: u64,
    ) -> Result<Value, InterpreterError> {
        let state_bytes = Self::estimate_crypto_object_state_bytes(&state);
        self.check_temporary_memory_budget(
            already_owned_temporary_bytes
                .saturating_add(state_bytes)
                .saturating_add(MEMORY_ESTIMATE_HEAP_OBJECT_BASE_BYTES)
                .saturating_add(Self::estimate_label_bytes(state.lifecycle_label())),
        )?;
        let lifecycle_label = state.lifecycle_label().clone();
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            let object_id = self.alloc_object_with_properties(&[])?;
            self.apply_memory_component_delta(0, state_bytes)?;
            self.crypto_objects.insert(object_id, state);
            self.replace_pending_hostcall_result_label(Some(lifecycle_label))?;
            Ok(Value::Object(object_id))
        })();
        if result.is_err() {
            self.crypto_objects
                .retain(|object_id, _| object_id.0 < previous_heap_len as u32);
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn crypto_receiver_id(
        &self,
        receiver: Option<Value>,
        builtin: &BuiltinFunction,
        method: &str,
    ) -> Result<ObjectId, InterpreterError> {
        let receiver = receiver.unwrap_or(Value::Undefined);
        let Value::Object(object_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: format!("authenticated crypto receiver for {method}"),
                got: receiver.type_name().to_string(),
            });
        };
        if builtin.bound_object != Some(object_id.0)
            || !self.crypto_objects.contains_key(&object_id)
        {
            return Err(InterpreterError::TypeError {
                expected: format!("authenticated crypto receiver for {method}"),
                got: "detached or forged receiver".to_string(),
            });
        }
        Ok(object_id)
    }

    pub(super) fn crypto_state_snapshot(
        &self,
        object_id: ObjectId,
    ) -> Result<CryptoObjectState, InterpreterError> {
        let state = self
            .crypto_objects
            .get(&object_id)
            .expect("authenticated crypto receiver has state");
        self.check_temporary_memory_budget(Self::estimate_crypto_object_state_bytes(state))?;
        Ok(state.clone())
    }

    pub(super) fn crypto_output_value_with_temporary_budget(
        &mut self,
        bytes: &[u8],
        encoding: Option<Value>,
        label: &Label,
        publish_result_label: bool,
        already_owned_temporary_bytes: u64,
    ) -> Result<Value, InterpreterError> {
        let payload_bound = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.check_temporary_memory_budget(already_owned_temporary_bytes.saturating_add(
            Self::crypto_output_publication_peak_bytes(payload_bound, label, publish_result_label),
        ))?;
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            let value = match encoding {
                None | Some(Value::Undefined) => {
                    let object_id = self.alloc_buffer_from_bytes(bytes)?;
                    self.join_binary_storage_label(object_id, label)?;
                    Value::Object(object_id)
                }
                Some(Value::Str(encoding)) => {
                    let Some(normalized) = Self::crypto_canonical_buffer_encoding(&encoding) else {
                        return Err(self.crypto_throw_node_error_with_temporary_budget(
                            "TypeError",
                            "ERR_UNKNOWN_ENCODING",
                            format!(
                                "Unknown encoding: {}",
                                Self::crypto_diagnostic_fragment(&encoding)
                            ),
                            label,
                            already_owned_temporary_bytes.saturating_add(payload_bound),
                        ));
                    };
                    let encoded = match self.encode_buffer_bytes(bytes, normalized) {
                        Ok(encoded) => encoded,
                        Err(InterpreterError::TypeError { .. }) => {
                            return Err(self.crypto_throw_node_error_with_temporary_budget(
                                "TypeError",
                                "ERR_UNKNOWN_ENCODING",
                                format!("Unknown encoding: {normalized}"),
                                label,
                                already_owned_temporary_bytes.saturating_add(payload_bound),
                            ));
                        }
                        Err(error) => return Err(error),
                    };
                    Value::Str(encoded)
                }
                Some(other) => {
                    return Err(self.crypto_throw_node_error_with_temporary_budget(
                        "TypeError",
                        "ERR_UNKNOWN_ENCODING",
                        format!("Unknown encoding: received {}", other.type_name()),
                        label,
                        already_owned_temporary_bytes.saturating_add(payload_bound),
                    ));
                }
            };
            if publish_result_label {
                self.replace_pending_hostcall_result_label(Some(label.clone()))?;
            }
            Ok(value)
        })();
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, InterpreterError::UncaughtException { .. }))
        {
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn crypto_canonical_output_encoding(
        encoding: &Option<Value>,
    ) -> Result<Option<String>, ()> {
        let Some(value) = encoding else {
            return Ok(None);
        };
        match value {
            Value::Undefined => Ok(None),
            Value::Str(encoding) => Self::crypto_canonical_buffer_encoding(encoding)
                .map(str::to_string)
                .map(Some)
                .ok_or(()),
            _ => Err(()),
        }
    }

    pub(super) fn crypto_utf8_incomplete_suffix_len(bytes: &[u8]) -> usize {
        let search_start = bytes.len().saturating_sub(3);
        for start in search_start..bytes.len() {
            let suffix = &bytes[start..];
            let expected_len = match suffix[0] {
                // Match Node's StringDecoder byte-prefix classification,
                // including invalid lead-byte values which are held until the
                // decoder sees the next chunk or finalizes with U+FFFD.
                0xc0..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf7 => 4,
                _ => continue,
            };
            if suffix.len() < expected_len
                && suffix[1..].iter().all(|byte| matches!(byte, 0x80..=0xbf))
            {
                return suffix.len();
            }
        }
        0
    }

    pub(super) fn crypto_encoded_stream_chunk(
        previous_remainder: &[u8],
        raw_output: &[u8],
        encoding: &str,
        final_chunk: bool,
    ) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
        let mut combined = Zeroizing::new(Vec::with_capacity(
            previous_remainder.len().saturating_add(raw_output.len()),
        ));
        combined.extend_from_slice(previous_remainder);
        combined.extend_from_slice(raw_output);
        let publish_len = if final_chunk {
            combined.len()
        } else {
            match encoding {
                "base64" | "base64url" => combined.len() / 3 * 3,
                "utf16le" => {
                    let even_len = combined.len() / 2 * 2;
                    let trailing_complete_unit_is_high_surrogate = even_len >= 2
                        && matches!(
                            u16::from_le_bytes([combined[even_len - 2], combined[even_len - 1]]),
                            0xd800..=0xdbff
                        );
                    let has_odd_tail = even_len != combined.len();
                    let trailing_unit_was_already_buffered = previous_remainder.len() >= even_len;
                    if trailing_complete_unit_is_high_surrogate
                        && (!has_odd_tail || trailing_unit_was_already_buffered)
                    {
                        even_len - 2
                    } else {
                        even_len
                    }
                }
                "utf8" => combined
                    .len()
                    .saturating_sub(Self::crypto_utf8_incomplete_suffix_len(&combined)),
                _ => combined.len(),
            }
        };
        let remainder = Zeroizing::new(combined[publish_len..].to_vec());
        combined.truncate(publish_len);
        (combined, remainder)
    }

    pub(super) fn crypto_digest_bytes(
        algorithm: CryptoHashAlgorithm,
        input: &[u8],
    ) -> Zeroizing<Vec<u8>> {
        match algorithm {
            CryptoHashAlgorithm::Md5 => Zeroizing::new(Md5::digest(input).to_vec()),
            CryptoHashAlgorithm::Sha1 => Zeroizing::new(Sha1::digest(input).to_vec()),
            CryptoHashAlgorithm::Sha256 => Zeroizing::new(Sha256::digest(input).to_vec()),
            CryptoHashAlgorithm::Sha512 => Zeroizing::new(Sha512::digest(input).to_vec()),
        }
    }

    pub(super) fn crypto_hmac_bytes(
        algorithm: CryptoHashAlgorithm,
        key: &[u8],
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, InterpreterError> {
        macro_rules! finish_hmac {
            ($digest:ty) => {{
                let mut mac = <Hmac<$digest> as Mac>::new_from_slice(key).map_err(|_| {
                    InterpreterError::TypeError {
                        expected: "valid HMAC key".to_string(),
                        got: "rejected key".to_string(),
                    }
                })?;
                mac.update(input);
                Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
            }};
        }
        match algorithm {
            CryptoHashAlgorithm::Md5 => finish_hmac!(Md5),
            CryptoHashAlgorithm::Sha1 => finish_hmac!(Sha1),
            CryptoHashAlgorithm::Sha256 => finish_hmac!(Sha256),
            CryptoHashAlgorithm::Sha512 => finish_hmac!(Sha512),
        }
    }

    pub(super) fn crypto_create_hash(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        let algorithm_name = self.crypto_required_string_arg(args, 0, "crypto hash algorithm")?;
        let Some(algorithm) = CryptoHashAlgorithm::parse(&algorithm_name) else {
            return Err(self.crypto_throw_node_error(
                "Error",
                "ERR_OSSL_EVP_UNSUPPORTED",
                format!(
                    "Digest method not supported: {}",
                    Self::crypto_diagnostic_fragment(&algorithm_name)
                ),
                &invocation_label,
            ));
        };
        self.crypto_alloc_object(CryptoObjectState::HashActive {
            algorithm,
            input: Zeroizing::new(Vec::new()),
            lifecycle_label: invocation_label,
        })
    }

    pub(super) fn crypto_create_hmac(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        self.enforce_crypto_hmac_ingress_clearance("builtin:CryptoCreateHmac", &invocation_label)?;
        let algorithm_name = self.crypto_required_string_arg(args, 0, "crypto HMAC algorithm")?;
        let Some(algorithm) = CryptoHashAlgorithm::parse(&algorithm_name) else {
            return Err(self.crypto_throw_node_error(
                "Error",
                "ERR_OSSL_EVP_UNSUPPORTED",
                format!(
                    "Digest method not supported: {}",
                    Self::crypto_diagnostic_fragment(&algorithm_name)
                ),
                &invocation_label,
            ));
        };
        let key_value = self.crypto_required_arg(args, 1, "crypto HMAC key")?;
        self.check_temporary_memory_budget(
            self.crypto_input_allocation_bound(&key_value, None)?
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        let key = Zeroizing::new(self.crypto_input_bytes(&key_value, None)?);
        if key.len() > CRYPTO_MAX_INPUT_BYTES {
            return Err(InterpreterError::RangeError {
                message: "crypto HMAC key exceeds engine input limit".to_string(),
            });
        }
        self.crypto_alloc_object(CryptoObjectState::HmacActive {
            algorithm,
            key,
            input: Zeroizing::new(Vec::new()),
            lifecycle_label: invocation_label,
        })
    }

    pub(super) fn crypto_update(
        &mut self,
        receiver: Option<Value>,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.crypto_receiver_id(receiver, builtin, "update")?;
        let invocation_label = self.crypto_invocation_label(args)?;
        if self.crypto_objects.get(&object_id).is_some_and(|state| {
            matches!(
                state,
                CryptoObjectState::HmacActive { .. } | CryptoObjectState::HmacFinalized { .. }
            )
        }) {
            self.enforce_crypto_hmac_ingress_clearance(
                "builtin:CryptoObjectUpdate",
                &invocation_label,
            )?;
        }
        let value = self.crypto_required_arg(args, 0, "crypto update input")?;
        let encoding = self.builtin_arg(args, 1)?;
        let retained_state_bytes = self
            .crypto_objects
            .get(&object_id)
            .map(Self::estimate_crypto_object_state_bytes)
            .expect("authenticated crypto receiver has state");
        let input_bound = self.crypto_update_input_allocation_bound(&value, encoding.as_ref())?;
        self.check_temporary_memory_budget(
            retained_state_bytes
                .saturating_add(input_bound)
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        let previous = self.crypto_state_snapshot(object_id)?;
        if matches!(
            previous,
            CryptoObjectState::HashFinalized { .. } | CryptoObjectState::HmacFinalized { .. }
        ) {
            let label = self.clone_dominant_label_with_temporary_budget(
                previous.lifecycle_label(),
                &invocation_label,
                Self::estimate_crypto_object_state_bytes(&previous)
                    .saturating_add(Self::estimate_label_bytes(&invocation_label)),
            )?;
            return Err(self.crypto_throw_node_error_with_temporary_budget(
                "Error",
                "ERR_CRYPTO_HASH_FINALIZED",
                "Digest already called".to_string(),
                &label,
                retained_state_bytes.saturating_add(Self::estimate_label_bytes(&invocation_label)),
            ));
        }
        let bytes = Zeroizing::new(self.crypto_update_input_bytes(&value, encoding.as_ref())?);
        let previous_input_len = match &previous {
            CryptoObjectState::HashActive { input, .. }
            | CryptoObjectState::HmacActive { input, .. } => input.len(),
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "hash or HMAC receiver".to_string(),
                    got: "cipher receiver".to_string(),
                });
            }
        };
        let next_input_len = previous_input_len.checked_add(bytes.len()).ok_or_else(|| {
            InterpreterError::RangeError {
                message: "crypto update input length overflow".to_string(),
            }
        })?;
        if next_input_len > CRYPTO_MAX_INPUT_BYTES {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "crypto update exceeds engine input limit of {CRYPTO_MAX_INPUT_BYTES} bytes"
                ),
            });
        }
        self.charge_crypto_work(Self::crypto_byte_work(bytes.len()))?;
        self.check_temporary_memory_budget(
            Self::estimate_crypto_object_state_bytes(&previous)
                .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        let next_lifecycle_label = self.clone_dominant_label_with_temporary_budget(
            previous.lifecycle_label(),
            &invocation_label,
            Self::estimate_crypto_object_state_bytes(&previous)
                .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        // At the mutation point the retained original, the snapshot, the
        // decoded input and the candidate next state can all coexist. Charge
        // the complete transient set before cloning the retained vectors.
        self.check_temporary_memory_budget(
            Self::estimate_crypto_object_state_bytes(&previous)
                .saturating_mul(2)
                .saturating_add(u64::try_from(bytes.capacity()).unwrap_or(u64::MAX))
                .saturating_add(u64::try_from(next_input_len).unwrap_or(u64::MAX))
                .saturating_add(Self::estimate_label_bytes(&next_lifecycle_label)),
        )?;
        let next = match &previous {
            CryptoObjectState::HashActive {
                algorithm, input, ..
            } => {
                let mut next_input = Zeroizing::new(Vec::with_capacity(next_input_len));
                next_input.extend_from_slice(input);
                next_input.extend_from_slice(&bytes);
                CryptoObjectState::HashActive {
                    algorithm: *algorithm,
                    input: next_input,
                    lifecycle_label: next_lifecycle_label,
                }
            }
            CryptoObjectState::HmacActive {
                algorithm,
                key,
                input,
                ..
            } => {
                let mut next_input = Zeroizing::new(Vec::with_capacity(next_input_len));
                next_input.extend_from_slice(input);
                next_input.extend_from_slice(&bytes);
                CryptoObjectState::HmacActive {
                    algorithm: *algorithm,
                    key: key.clone(),
                    input: next_input,
                    lifecycle_label: next_lifecycle_label,
                }
            }
            _ => unreachable!("active hash/HMAC state was checked"),
        };
        let previous_bytes = Self::estimate_crypto_object_state_bytes(&previous);
        let next_bytes = Self::estimate_crypto_object_state_bytes(&next);
        let previous_estimated_bytes = self.estimated_memory_bytes;
        self.apply_memory_component_delta(previous_bytes, next_bytes)?;
        let result_label = next.lifecycle_label().clone();
        self.crypto_objects.insert(object_id, next);
        if let Err(error) = self.replace_pending_hostcall_result_label(Some(result_label)) {
            self.crypto_objects.insert(object_id, previous);
            self.estimated_memory_bytes = previous_estimated_bytes;
            return Err(error);
        }
        Ok(Value::Object(object_id))
    }

    pub(super) fn crypto_digest(
        &mut self,
        receiver: Option<Value>,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.crypto_receiver_id(receiver, builtin, "digest")?;
        let invocation_label = self.crypto_invocation_label(args)?;
        let retained_state_bytes = self
            .crypto_objects
            .get(&object_id)
            .map(Self::estimate_crypto_object_state_bytes)
            .expect("authenticated crypto receiver has state");
        let invocation_label_bytes = Self::estimate_label_bytes(&invocation_label);
        self.check_temporary_memory_budget(
            retained_state_bytes.saturating_add(invocation_label_bytes),
        )?;
        let previous = self.crypto_state_snapshot(object_id)?;
        let lifecycle_label = self.clone_dominant_label_with_temporary_budget(
            previous.lifecycle_label(),
            &invocation_label,
            retained_state_bytes.saturating_add(invocation_label_bytes),
        )?;
        let lifecycle_label_bytes = Self::estimate_label_bytes(&lifecycle_label);
        let output_bound = match &previous {
            CryptoObjectState::HashActive { algorithm, .. }
            | CryptoObjectState::HmacActive { algorithm, .. } => {
                u64::try_from(algorithm.output_len()).unwrap_or(u64::MAX)
            }
            CryptoObjectState::HmacFinalized { .. }
            | CryptoObjectState::HashFinalized { .. }
            | CryptoObjectState::CipherActive { .. }
            | CryptoObjectState::CipherFinalized { .. }
            // bd-53l89: key pair handles expose no digest/final lifecycle.
            | CryptoObjectState::KeyPairActive { .. } => 0,
        };
        let candidate_state_bound = CRYPTO_STATE_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
            .saturating_add(lifecycle_label_bytes);
        let caller_temporary_bound = retained_state_bytes
            .saturating_add(invocation_label_bytes)
            .saturating_add(lifecycle_label_bytes)
            .saturating_add(output_bound);
        self.check_temporary_memory_budget(
            caller_temporary_bound
                .saturating_add(candidate_state_bound)
                .saturating_add(Self::crypto_output_publication_peak_bytes(
                    output_bound,
                    &lifecycle_label,
                    true,
                )),
        )?;
        let (output, next) = match &previous {
            CryptoObjectState::HashActive {
                algorithm, input, ..
            } => {
                self.charge_crypto_work(Self::crypto_byte_work(input.len()))?;
                (
                    Self::crypto_digest_bytes(*algorithm, input),
                    CryptoObjectState::HashFinalized {
                        lifecycle_label: lifecycle_label.clone(),
                    },
                )
            }
            CryptoObjectState::HmacActive {
                algorithm,
                key,
                input,
                ..
            } => {
                self.charge_crypto_work(Self::crypto_byte_work(
                    key.len().saturating_add(input.len()),
                ))?;
                (
                    Self::crypto_hmac_bytes(*algorithm, key, input)?,
                    CryptoObjectState::HmacFinalized {
                        lifecycle_label: lifecycle_label.clone(),
                    },
                )
            }
            CryptoObjectState::HashFinalized { .. } => {
                return Err(self.crypto_throw_node_error_with_temporary_budget(
                    "Error",
                    "ERR_CRYPTO_HASH_FINALIZED",
                    "Digest already called".to_string(),
                    &lifecycle_label,
                    retained_state_bytes
                        .saturating_add(invocation_label_bytes)
                        .saturating_add(lifecycle_label_bytes),
                ));
            }
            CryptoObjectState::HmacFinalized { .. } => (
                Zeroizing::new(Vec::new()),
                CryptoObjectState::HmacFinalized {
                    lifecycle_label: lifecycle_label.clone(),
                },
            ),
            CryptoObjectState::CipherActive { .. } | CryptoObjectState::CipherFinalized { .. } => {
                return Err(InterpreterError::TypeError {
                    expected: "hash or HMAC receiver".to_string(),
                    got: "cipher receiver".to_string(),
                });
            }
            // bd-53l89: digest/final is not a key pair operation; the
            // lifecycle gate already refuses these tags for KeyPairActive.
            CryptoObjectState::KeyPairActive { .. } => {
                return Err(InterpreterError::TypeError {
                    expected: "hash or HMAC receiver".to_string(),
                    got: "key pair receiver".to_string(),
                });
            }
        };
        self.check_temporary_memory_budget(
            Self::estimate_crypto_object_state_bytes(&previous)
                .saturating_add(u64::try_from(output.len()).unwrap_or(u64::MAX))
                .saturating_add(Self::estimate_crypto_object_state_bytes(&next)),
        )?;
        let previous_state_bytes = Self::estimate_crypto_object_state_bytes(&previous);
        let next_state_bytes = Self::estimate_crypto_object_state_bytes(&next);
        let requested_output_encoding = self.builtin_arg(args, 0)?;
        // Hash/HMAC digest has a historical Node quirk: unknown and non-string
        // encoding arguments are ignored and select the default Buffer result.
        // Cipher output validation is intentionally stricter.
        let output_encoding = Self::crypto_canonical_output_encoding(&requested_output_encoding)
            .ok()
            .flatten()
            .map(Value::str);
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            self.apply_memory_component_delta(previous_state_bytes, next_state_bytes)?;
            self.crypto_objects.insert(object_id, next);
            self.crypto_output_value_with_temporary_budget(
                &output,
                output_encoding,
                &lifecycle_label,
                true,
                retained_state_bytes
                    .saturating_add(invocation_label_bytes)
                    .saturating_add(lifecycle_label_bytes)
                    .saturating_add(u64::try_from(output.capacity()).unwrap_or(u64::MAX)),
            )
        })();
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, InterpreterError::UncaughtException { .. }))
        {
            self.crypto_objects.insert(object_id, previous);
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn crypto_copy(
        &mut self,
        receiver: Option<Value>,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.crypto_receiver_id(receiver, builtin, "copy")?;
        let invocation_label = self.crypto_invocation_label(args)?;
        let retained_state_bytes = self
            .crypto_objects
            .get(&object_id)
            .map(Self::estimate_crypto_object_state_bytes)
            .expect("authenticated crypto receiver has state");
        let invocation_label_bytes = Self::estimate_label_bytes(&invocation_label);
        self.check_temporary_memory_budget(
            retained_state_bytes.saturating_add(invocation_label_bytes),
        )?;
        let previous = self.crypto_state_snapshot(object_id)?;
        let joined_lifecycle_label = self.clone_dominant_label_with_temporary_budget(
            previous.lifecycle_label(),
            &invocation_label,
            retained_state_bytes.saturating_add(invocation_label_bytes),
        )?;
        match previous {
            CryptoObjectState::HashActive {
                algorithm, input, ..
            } => {
                self.charge_crypto_work(Self::crypto_byte_work(input.len()))?;
                self.crypto_alloc_object_with_temporary_budget(
                    CryptoObjectState::HashActive {
                        algorithm,
                        input,
                        lifecycle_label: joined_lifecycle_label,
                    },
                    invocation_label_bytes,
                )
            }
            CryptoObjectState::HashFinalized { .. } => Err(self
                .crypto_throw_node_error_with_temporary_budget(
                    "Error",
                    "ERR_CRYPTO_HASH_FINALIZED",
                    "Digest already called".to_string(),
                    &joined_lifecycle_label,
                    retained_state_bytes.saturating_add(invocation_label_bytes),
                )),
            _ => Err(InterpreterError::TypeError {
                expected: "Hash receiver for copy".to_string(),
                got: "non-Hash crypto object".to_string(),
            }),
        }
    }

    pub(super) fn crypto_pbkdf2_bytes(
        algorithm: CryptoHashAlgorithm,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) -> Result<(), InterpreterError> {
        let prf_hash = match algorithm {
            CryptoHashAlgorithm::Sha1 => crate::crypto_kdf_zeroized::PrfHash::Sha1,
            CryptoHashAlgorithm::Sha256 => crate::crypto_kdf_zeroized::PrfHash::Sha256,
            CryptoHashAlgorithm::Sha512 => crate::crypto_kdf_zeroized::PrfHash::Sha512,
            CryptoHashAlgorithm::Md5 => crate::crypto_kdf_zeroized::PrfHash::Md5,
        };
        crate::crypto_kdf_zeroized::pbkdf2_zeroized(prf_hash, password, salt, iterations, output);
        Ok(())
    }

    pub(super) fn crypto_pbkdf2(
        &mut self,
        args: RegRange,
        asynchronous: bool,
    ) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        let password_value = self.crypto_required_arg(args, 0, "PBKDF2 password")?;
        let salt_value = self.crypto_required_arg(args, 1, "PBKDF2 salt")?;
        let iterations_value = self.crypto_required_arg(args, 2, "PBKDF2 iterations")?;
        let key_len_value = self.crypto_required_arg(args, 3, "PBKDF2 key length")?;
        let digest_name = self.crypto_required_string_arg(args, 4, "PBKDF2 digest")?;
        let Some(algorithm) = CryptoHashAlgorithm::parse(&digest_name) else {
            return Err(self.crypto_throw_node_error(
                "Error",
                "ERR_CRYPTO_INVALID_DIGEST",
                format!(
                    "Invalid digest: {}",
                    Self::crypto_diagnostic_fragment(&digest_name)
                ),
                &invocation_label,
            ));
        };
        let iterations = self.crypto_integer_arg(&iterations_value, "iterations", false)?;
        if iterations > i32::MAX as usize {
            return Err(self.crypto_throw_node_error(
                "RangeError",
                "ERR_OUT_OF_RANGE",
                "PBKDF2 iterations must be less than or equal to 2147483647".to_string(),
                &invocation_label,
            ));
        }
        let iterations = u32::try_from(iterations).map_err(|_| InterpreterError::RangeError {
            message: "PBKDF2 iterations exceed u32 range".to_string(),
        })?;
        let key_len = self.crypto_integer_arg(&key_len_value, "key length", true)?;
        if key_len > CRYPTO_MAX_INPUT_BYTES {
            return Err(InterpreterError::RangeError {
                message: "PBKDF2 output exceeds engine Buffer cap".to_string(),
            });
        }
        let callback = if asynchronous {
            Some(
                match self.crypto_required_arg(args, 5, "PBKDF2 callback")? {
                    Value::Closure(callback) => callback,
                    other => {
                        return Err(InterpreterError::TypeError {
                            expected: "PBKDF2 callback function".to_string(),
                            got: other.type_name().to_string(),
                        });
                    }
                },
            )
        } else {
            None
        };
        let password_bound = self.crypto_input_allocation_bound(&password_value, None)?;
        let salt_bound = self.crypto_input_allocation_bound(&salt_value, None)?;
        self.check_temporary_memory_budget(
            password_bound
                .saturating_add(salt_bound)
                .saturating_add(u64::try_from(key_len).unwrap_or(u64::MAX).saturating_mul(2))
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        let password = Zeroizing::new(self.crypto_input_bytes(&password_value, None)?);
        let salt = Zeroizing::new(self.crypto_input_bytes(&salt_value, None)?);
        let blocks = key_len.div_ceil(algorithm.output_len());
        let password_work = Self::crypto_byte_work(password.len());
        let salt_work = Self::crypto_byte_work(salt.len().saturating_add(4));
        let per_block_work = u64::from(iterations).saturating_add(salt_work);
        let work = password_work.saturating_add(
            u64::try_from(blocks.max(1))
                .unwrap_or(u64::MAX)
                .saturating_mul(per_block_work),
        );
        self.charge_crypto_work(work)?;
        let mut output = Zeroizing::new(vec![0u8; key_len]);
        Self::crypto_pbkdf2_bytes(algorithm, &password, &salt, iterations, &mut output)?;
        drop(password);
        drop(salt);
        let output_temporary_bytes = u64::try_from(output.capacity())
            .unwrap_or(u64::MAX)
            .saturating_add(Self::estimate_label_bytes(&invocation_label));

        let Some(callback) = callback else {
            return self.crypto_output_value_with_temporary_budget(
                &output,
                None,
                &invocation_label,
                true,
                output_temporary_bytes,
            );
        };
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let key = self.crypto_output_value_with_temporary_budget(
            &output,
            None,
            &invocation_label,
            false,
            output_temporary_bytes,
        )?;
        drop(output);
        if let Err(error) =
            self.schedule_io_callback_with_label(callback, vec![Value::Null, key], invocation_label)
        {
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
            return Err(error);
        }
        Ok(Value::Undefined)
    }

    pub(super) fn crypto_scrypt_sync(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        let password_value = self.crypto_required_arg(args, 0, "scrypt password")?;
        let salt_value = self.crypto_required_arg(args, 1, "scrypt salt")?;
        let key_len_value = self.crypto_required_arg(args, 2, "scrypt key length")?;
        let key_len = self.crypto_integer_arg(&key_len_value, "key length", true)?;
        if key_len > CRYPTO_MAX_INPUT_BYTES {
            return Err(InterpreterError::RangeError {
                message: "scrypt output exceeds engine Buffer cap".to_string(),
            });
        }
        let options = self.builtin_arg(args, 3)?;
        let option_integer = |this: &Self, names: &[&str], default: usize, allow_zero: bool| {
            let Some(Value::Object(options_id)) = options.as_ref() else {
                return Ok(default);
            };
            let object = this
                .heap
                .get(options_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: options_id.0 })?;
            let mut selected = None;
            for name in names {
                if let Some(value) = object.properties.get(name) {
                    if selected.is_some() {
                        return Err(InterpreterError::TypeError {
                            expected: format!(
                                "at most one scrypt option from {}",
                                names.join(", ")
                            ),
                            got: "incompatible option pair".to_string(),
                        });
                    }
                    selected = Some((*name, value));
                }
            }
            let Some((name, value)) = selected else {
                return Ok(default);
            };
            this.crypto_integer_arg(value, name, allow_zero)
        };
        let n = option_integer(self, &["N", "cost"], 16_384, false)?;
        let r = option_integer(self, &["r", "blockSize"], 8, false)?;
        let p = option_integer(self, &["p", "parallelization"], 1, false)?;
        let configured_maxmem = option_integer(self, &["maxmem"], 32 * 1024 * 1024, true)?;
        let maxmem = if configured_maxmem == 0 {
            32 * 1024 * 1024
        } else {
            configured_maxmem
        };
        if !n.is_power_of_two() || n < 2 {
            return Err(InterpreterError::RangeError {
                message: "scrypt N must be a power of two greater than one".to_string(),
            });
        }
        let r_u32 = u32::try_from(r).map_err(|_| InterpreterError::RangeError {
            message: "scrypt r exceeds u32 range".to_string(),
        })?;
        let p_u32 = u32::try_from(p).map_err(|_| InterpreterError::RangeError {
            message: "scrypt p exceeds u32 range".to_string(),
        })?;
        let log_n = u8::try_from(n.trailing_zeros()).map_err(|_| InterpreterError::RangeError {
            message: "scrypt N logarithm exceeds u8 range".to_string(),
        })?;
        // Params::new's length is password-hash metadata constrained to
        // 10..=64, not the raw scrypt output length. Raw Node outputs may be
        // any length allowed by our Buffer cap, including zero.
        let params = scrypt::Params::new(log_n, r_u32, p_u32, 32).map_err(|_| {
            InterpreterError::RangeError {
                message: "invalid scrypt parameters".to_string(),
            }
        })?;
        let r_bytes = 128u64.saturating_mul(u64::try_from(r).unwrap_or(u64::MAX));
        let b_workspace = r_bytes.saturating_mul(u64::try_from(p).unwrap_or(u64::MAX));
        let v_workspace = r_bytes.saturating_mul(u64::try_from(n).unwrap_or(u64::MAX));
        let t_workspace = r_bytes;
        let workspace = b_workspace
            .saturating_add(v_workspace)
            .saturating_add(t_workspace);
        if workspace > u64::try_from(maxmem).unwrap_or(u64::MAX) {
            return Err(InterpreterError::RangeError {
                message: "scrypt parameters exceed maxmem".to_string(),
            });
        }
        let password_bound = self.crypto_input_allocation_bound(&password_value, None)?;
        let salt_bound = self.crypto_input_allocation_bound(&salt_value, None)?;
        let temporary_bytes = workspace
            .saturating_add(password_bound)
            .saturating_add(salt_bound)
            .saturating_add(u64::try_from(key_len).unwrap_or(u64::MAX).saturating_mul(2))
            .saturating_add(Self::estimate_label_bytes(&invocation_label));
        self.check_temporary_memory_budget(temporary_bytes)?;
        let password = Zeroizing::new(self.crypto_input_bytes(&password_value, None)?);
        let salt = Zeroizing::new(self.crypto_input_bytes(&salt_value, None)?);
        let mixing_rounds = u64::try_from(n)
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(r).unwrap_or(u64::MAX))
            .saturating_mul(u64::try_from(p).unwrap_or(u64::MAX));
        // RustCrypto performs PBKDF2(password, salt, 1, B), ROMix over each
        // p-sized B chunk, then PBKDF2(password, B, 1, output). The final
        // phase hashes the entire B workspace once per output block, so
        // charging only N*r*p leaves a large-key CPU amplification hole.
        let password_work = Self::crypto_byte_work(password.len());
        let salt_work = Self::crypto_byte_work(salt.len().saturating_add(4));
        let b_work = b_workspace.div_ceil(CRYPTO_WORK_UNIT_BYTES);
        let initial_pbkdf_blocks = b_workspace.div_ceil(32);
        let final_pbkdf_blocks = u64::try_from(key_len).unwrap_or(u64::MAX).div_ceil(32);
        let kdf_work = password_work
            .saturating_mul(2)
            .saturating_add(initial_pbkdf_blocks.saturating_mul(salt_work.saturating_add(1)))
            .saturating_add(final_pbkdf_blocks.saturating_mul(b_work.saturating_add(1)));
        let total_work = mixing_rounds.saturating_add(kdf_work);
        if total_work > CRYPTO_MAX_SCRYPT_WORK_UNITS {
            return Err(InterpreterError::BudgetExhausted {
                executed: self.instructions_executed,
                budget: self.config.instruction_budget,
            });
        }
        let work = total_work.div_ceil(CRYPTO_SCRYPT_MIXES_PER_BUDGET_TICK);
        self.charge_crypto_work(work)?;
        let mut output = Zeroizing::new(vec![0u8; key_len]);
        if !output.is_empty() {
            crate::crypto_kdf_zeroized::scrypt_zeroized_run(&password, &salt, &params, &mut output)
                .map_err(|_| InterpreterError::InternalError {
                    details: "scrypt computation failed after parameter preflight".to_string(),
                })?;
        }
        drop(password);
        drop(salt);
        let output_temporary_bytes = u64::try_from(output.capacity())
            .unwrap_or(u64::MAX)
            .saturating_add(Self::estimate_label_bytes(&invocation_label));
        self.crypto_output_value_with_temporary_budget(
            &output,
            None,
            &invocation_label,
            true,
            output_temporary_bytes,
        )
    }

    pub(super) fn crypto_timing_safe_equal(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        let left_value = self.crypto_required_arg(args, 0, "timingSafeEqual left input")?;
        let right_value = self.crypto_required_arg(args, 1, "timingSafeEqual right input")?;
        let (left_buffer, left_offset, left_len) =
            match self.crypto_binary_view_range(&left_value, true) {
                Ok(view) => view,
                Err(_) => {
                    return Err(self.crypto_throw_node_error(
                        "TypeError",
                        "ERR_INVALID_ARG_TYPE",
                        "The first argument must be an ArrayBuffer or ArrayBuffer view".to_string(),
                        &invocation_label,
                    ));
                }
            };
        let (right_buffer, right_offset, right_len) = match self
            .crypto_binary_view_range(&right_value, true)
        {
            Ok(view) => view,
            Err(_) => {
                return Err(self.crypto_throw_node_error(
                    "TypeError",
                    "ERR_INVALID_ARG_TYPE",
                    "The second argument must be an ArrayBuffer or ArrayBuffer view".to_string(),
                    &invocation_label,
                ));
            }
        };
        self.check_temporary_memory_budget(
            u64::try_from(left_len)
                .unwrap_or(u64::MAX)
                .saturating_add(u64::try_from(right_len).unwrap_or(u64::MAX))
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        let left = Zeroizing::new(self.copy_crypto_binary_view_range(
            left_buffer,
            left_offset,
            left_len,
        )?);
        let right = Zeroizing::new(self.copy_crypto_binary_view_range(
            right_buffer,
            right_offset,
            right_len,
        )?);
        self.charge_crypto_work(Self::crypto_byte_work(left.len().max(right.len())))?;
        if left.len() != right.len() {
            drop(left);
            drop(right);
            return Err(self.crypto_throw_node_error(
                "RangeError",
                "ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH",
                "Input buffers must have the same byte length".to_string(),
                &invocation_label,
            ));
        }
        self.replace_pending_hostcall_result_label(Some(invocation_label))?;
        Ok(Value::Bool(bool::from(
            left.as_slice().ct_eq(right.as_slice()),
        )))
    }

    pub(super) fn crypto_get_hashes(&mut self) -> Result<Value, InterpreterError> {
        let values = ["md5", "sha1", "sha256", "sha512"].map(Value::str);
        Ok(Value::Object(self.alloc_array_from_values(&values)?))
    }

    pub(super) fn crypto_get_ciphers(&mut self) -> Result<Value, InterpreterError> {
        let values = ["aes-128-ctr", "aes-256-cbc", "aes-256-gcm"].map(Value::str);
        Ok(Value::Object(self.alloc_array_from_values(&values)?))
    }

    pub(super) fn crypto_constants(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        if args.count != 0 {
            return Err(InterpreterError::TypeError {
                expected: "zero crypto.constants arguments".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        Ok(Value::Object(self.alloc_object_with_properties(&[
            ("RSA_PKCS1_PADDING", Value::Int(1)),
            ("RSA_NO_PADDING", Value::Int(3)),
            ("RSA_PKCS1_OAEP_PADDING", Value::Int(4)),
        ])?))
    }

    pub(super) fn perform_random_read_effect(&mut self, byte_len: usize) -> Result<Vec<u8>, ()> {
        let provider = self.host_io.clone().ok_or(())?;
        let byte_len = u64::try_from(byte_len).map_err(|_| ())?;
        let effect = create_random_read_effect(byte_len);
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
        let result = stack.handle_effect(effect.as_ref()).map_err(|_| ())?;
        let bytes = result.downcast::<Vec<u8>>().map_err(|_| ())?;
        (bytes.len() == usize::try_from(byte_len).map_err(|_| ())?)
            .then_some(bytes)
            .ok_or(())
    }

    /// Read a bounded, explicit snapshot value through the same provider and
    /// effect journal as every other host read. Missing provider authority is
    /// an error, never a fabricated absent variable.
    pub(super) fn dispatch_environment_hostcall(
        &mut self,
        capability: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let denied = || InterpreterError::CapabilityDenied {
            capability: RuntimeCapability::EnvRead.to_string(),
        };
        if !self
            .config
            .granted_capabilities
            .contains(&RuntimeCapability::EnvRead)
        {
            return Err(denied());
        }
        if args.count != 1 {
            return Err(InterpreterError::TypeError {
                expected: "one environment variable name".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        let Value::Str(name) = self.read_reg(args.start)? else {
            return Err(InterpreterError::TypeError {
                expected: "an environment variable name string".to_string(),
                got: "non-string environment variable name".to_string(),
            });
        };
        let name = name.as_str().ok_or_else(denied)?;
        validate_environment_name(name).map_err(|_| denied())?;
        let provider = self.host_io.clone().ok_or_else(denied)?;
        let effect = create_env_read_effect(name.to_string());
        let mut stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::full(),
            Some(provider),
            self.host_io_recorder.clone(),
            self.process_spawn.clone(),
            None,
            self.host_effect_journal.clone(),
        );
        let result = stack.handle_effect(effect.as_ref()).map_err(|_| denied())?;
        let value = result.downcast::<Option<String>>().map_err(|_| denied())?;
        if capability == "env:has" {
            Ok(Value::Bool(value.is_some()))
        } else {
            match value {
                Some(value) => {
                    self.check_string_limit(value.len())?;
                    Ok(Value::str(value))
                }
                None => Ok(Value::Undefined),
            }
        }
    }

    pub(super) fn require_random_read_capability(&self) -> Result<(), InterpreterError> {
        if self
            .config
            .granted_capabilities
            .contains(&RuntimeCapability::RandomRead)
        {
            Ok(())
        } else {
            Err(InterpreterError::CapabilityDenied {
                capability: RuntimeCapability::RandomRead.to_string(),
            })
        }
    }

    pub(super) fn crypto_random_failure(
        &mut self,
        invocation_label: Label,
        callback: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        const CODE: &str = "ERR_CRYPTO_OPERATION_FAILED";
        const MESSAGE: &str = "Cryptographic random source unavailable";
        if let Some(callback) = callback {
            self.ensure_builtin_prototype("Error")?;
            let previous_heap_len = self.heap.len();
            let previous_estimated_bytes = self.estimated_memory_bytes;
            let error = match self.construct_buffer_node_error("Error", CODE, MESSAGE.to_string()) {
                Ok(error) => error,
                Err(error) => {
                    self.rollback_heap_to_len(previous_heap_len);
                    self.estimated_memory_bytes = previous_estimated_bytes;
                    return Err(error);
                }
            };
            if let Err(error) = self.schedule_io_callback_with_label(
                callback,
                vec![error, Value::Undefined],
                invocation_label,
            ) {
                self.rollback_heap_to_len(previous_heap_len);
                self.estimated_memory_bytes = previous_estimated_bytes;
                return Err(error);
            }
            Ok(Value::Undefined)
        } else {
            Err(self.crypto_throw_node_error("Error", CODE, MESSAGE.to_string(), &invocation_label))
        }
    }

    pub(super) fn crypto_random_size(
        &mut self,
        value: &Value,
        name: &str,
        invocation_label: &Label,
    ) -> Result<usize, InterpreterError> {
        let size = self.crypto_integer_arg(value, name, true)?;
        let cap = usize::try_from(SANDBOXED_HOST_IO_MAX_RANDOM_BYTES_PER_REQUEST)
            .expect("random-read request cap fits usize");
        if size > cap {
            return Err(self.crypto_throw_node_error(
                "RangeError",
                "ERR_OUT_OF_RANGE",
                format!("crypto {name} exceeds the engine limit of {cap} bytes"),
                invocation_label,
            ));
        }
        Ok(size)
    }

    pub(super) fn crypto_random_bytes(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        let size_value = self.crypto_required_arg(args, 0, "random byte count")?;
        let callback = match self.builtin_arg(args, 1)? {
            None | Some(Value::Undefined) => None,
            Some(Value::Closure(callback)) => Some(callback),
            Some(other) => {
                return Err(InterpreterError::TypeError {
                    expected: "randomBytes callback function".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        if args.count > 2 {
            return Err(InterpreterError::TypeError {
                expected: "randomBytes(size[, callback])".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        self.require_random_read_capability()?;
        let size = self.crypto_random_size(&size_value, "random byte count", &invocation_label)?;
        self.check_temporary_memory_budget(
            u64::try_from(size)
                .unwrap_or(u64::MAX)
                .saturating_mul(2)
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        self.charge_crypto_work(Self::crypto_byte_work(size))?;
        let bytes = if size == 0 {
            Vec::new()
        } else {
            let Ok(bytes) = self.perform_random_read_effect(size) else {
                return self.crypto_random_failure(invocation_label, callback);
            };
            bytes
        };
        let output_label = invocation_label.join(&Label::Secret);
        let value = self.crypto_output_value_with_temporary_budget(
            &bytes,
            None,
            &output_label,
            callback.is_none(),
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        )?;
        if let Some(callback) = callback {
            self.schedule_io_callback_with_label(callback, vec![Value::Null, value], output_label)?;
            Ok(Value::Undefined)
        } else {
            Ok(value)
        }
    }

    pub(super) fn crypto_random_uuid(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        if args.count != 0 {
            return Err(InterpreterError::TypeError {
                expected: "randomUUID()".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        self.require_random_read_capability()?;
        let invocation_label = self.crypto_invocation_label(args)?;
        self.check_temporary_memory_budget(
            36_u64.saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        self.charge_crypto_work(Self::crypto_byte_work(16))?;
        let Ok(mut bytes) = self.perform_random_read_effect(16) else {
            return self.crypto_random_failure(invocation_label, None);
        };
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let uuid = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        );
        self.replace_pending_hostcall_result_label(Some(invocation_label.join(&Label::Secret)))?;
        Ok(Value::str(uuid))
    }

    pub(super) fn crypto_random_int_arg(
        value: &Value,
        name: &str,
    ) -> Result<i64, InterpreterError> {
        match value {
            Value::Int(value) if value.unsigned_abs() <= CRYPTO_MAX_SAFE_INTEGER as u64 => {
                Ok(*value)
            }
            Value::Float(value)
                if value.inner().is_finite()
                    && value.inner().fract() == 0.0
                    && value.inner().abs() <= CRYPTO_MAX_SAFE_INTEGER as f64 =>
            {
                Ok(value.inner() as i64)
            }
            other => Err(InterpreterError::TypeError {
                expected: format!("safe integer randomInt {name}"),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn crypto_random_int(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        const DOMAIN: u64 = 1_u64 << 48;
        const MAX_REJECTIONS: usize = 128;

        self.require_random_read_capability()?;
        let invocation_label = self.crypto_invocation_label(args)?;
        let first = self.crypto_required_arg(args, 0, "randomInt bound")?;
        let second = self.builtin_arg(args, 1)?;
        let third = self.builtin_arg(args, 2)?;
        if args.count > 3 {
            return Err(InterpreterError::TypeError {
                expected: "randomInt(max[, callback]) or randomInt(min, max[, callback])"
                    .to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        let (min, max, callback) = match (second, third) {
            (None, None) | (Some(Value::Undefined), None) => {
                (0, Self::crypto_random_int_arg(&first, "max")?, None)
            }
            (Some(Value::Closure(callback)), None) => (
                0,
                Self::crypto_random_int_arg(&first, "max")?,
                Some(callback),
            ),
            (Some(max), None) | (Some(max), Some(Value::Undefined)) => (
                Self::crypto_random_int_arg(&first, "min")?,
                Self::crypto_random_int_arg(&max, "max")?,
                None,
            ),
            (Some(max), Some(Value::Closure(callback))) => (
                Self::crypto_random_int_arg(&first, "min")?,
                Self::crypto_random_int_arg(&max, "max")?,
                Some(callback),
            ),
            (None, Some(_)) => {
                return Err(InterpreterError::TypeError {
                    expected: "randomInt(min, max[, callback])".to_string(),
                    got: "missing max argument".to_string(),
                });
            }
            (_, Some(other)) => {
                return Err(InterpreterError::TypeError {
                    expected: "randomInt callback function".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let Some(width_i64) = max.checked_sub(min) else {
            return Err(self.crypto_throw_node_error(
                "RangeError",
                "ERR_OUT_OF_RANGE",
                "The randomInt range overflows a safe integer".to_string(),
                &invocation_label,
            ));
        };
        if width_i64 <= 0 || width_i64 as u64 >= DOMAIN {
            return Err(self.crypto_throw_node_error(
                "RangeError",
                "ERR_OUT_OF_RANGE",
                "The value of max must be greater than min with a range at most 2^48".to_string(),
                &invocation_label,
            ));
        }
        let width = width_i64 as u64;
        let acceptance_limit = DOMAIN - (DOMAIN % width);
        let mut chosen = None;
        for _ in 0..MAX_REJECTIONS {
            self.charge_crypto_work(6)?;
            let Ok(bytes) = self.perform_random_read_effect(6) else {
                return self.crypto_random_failure(invocation_label, callback);
            };
            let sample = bytes
                .into_iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(byte));
            if sample < acceptance_limit {
                chosen = Some(sample % width);
                break;
            }
        }
        let Some(offset) = chosen else {
            return self.crypto_random_failure(invocation_label, callback);
        };
        let value = Value::Int(min + offset as i64);
        let output_label = invocation_label.join(&Label::Secret);
        if let Some(callback) = callback {
            self.schedule_io_callback_with_label(callback, vec![Value::Null, value], output_label)?;
            Ok(Value::Undefined)
        } else {
            self.replace_pending_hostcall_result_label(Some(output_label))?;
            Ok(value)
        }
    }

    pub(super) fn crypto_random_fill_sync(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if !(1..=3).contains(&args.count) {
            return Err(InterpreterError::TypeError {
                expected: "randomFillSync(buffer[, offset][, size])".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        self.require_random_read_capability()?;
        let invocation_label = self.crypto_invocation_label(args)?;
        let target = self.crypto_required_arg(args, 0, "randomFillSync Buffer")?;
        let (buffer, view_offset, view_len) = self.crypto_binary_view_range(&target, false)?;
        let offset = match self.builtin_arg(args, 1)? {
            None | Some(Value::Undefined) => 0,
            Some(value) => self.crypto_integer_arg(&value, "random fill offset", true)?,
        };
        if offset > view_len {
            return Err(self.crypto_throw_node_error(
                "RangeError",
                "ERR_OUT_OF_RANGE",
                "randomFillSync offset exceeds the target view".to_string(),
                &invocation_label,
            ));
        }
        let size = match self.builtin_arg(args, 2)? {
            None | Some(Value::Undefined) => view_len - offset,
            Some(value) => {
                self.crypto_random_size(&value, "random fill size", &invocation_label)?
            }
        };
        let end = offset
            .checked_add(size)
            .ok_or_else(|| InterpreterError::RangeError {
                message: "randomFillSync range overflows host address space".to_string(),
            })?;
        if end > view_len {
            return Err(self.crypto_throw_node_error(
                "RangeError",
                "ERR_OUT_OF_RANGE",
                "randomFillSync range exceeds the target view".to_string(),
                &invocation_label,
            ));
        }
        self.check_temporary_memory_budget(
            u64::try_from(size)
                .unwrap_or(u64::MAX)
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        self.charge_crypto_work(Self::crypto_byte_work(size))?;
        let bytes = if size == 0 {
            Vec::new()
        } else {
            let Ok(bytes) = self.perform_random_read_effect(size) else {
                return self.crypto_random_failure(invocation_label, None);
            };
            bytes
        };
        let output_label = invocation_label.join(&Label::Secret);
        let absolute_start =
            view_offset
                .checked_add(offset)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "randomFillSync backing range overflows host address space"
                        .to_string(),
                })?;
        let absolute_end =
            absolute_start
                .checked_add(size)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "randomFillSync backing range overflows host address space"
                        .to_string(),
                })?;
        self.with_array_buffer_bytes_mut(buffer, |storage| {
            let destination = storage
                .get_mut(absolute_start..absolute_end)
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "randomFillSync range exceeds backing storage".to_string(),
                })?;
            destination.copy_from_slice(&bytes);
            Ok(())
        })??;
        self.join_binary_storage_label(buffer, &output_label)?;
        self.replace_pending_hostcall_result_label(Some(output_label))?;
        Ok(target)
    }

    pub(super) fn crypto_invalid_random_int(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        Err(self.crypto_throw_node_error(
            "RangeError",
            "ERR_OUT_OF_RANGE",
            "The value of max must be greater than min".to_string(),
            &invocation_label,
        ))
    }

    pub(super) fn crypto_cipher_algorithm(
        name: &str,
        _direction: CryptoCipherDirection,
    ) -> Option<CryptoCipherAlgorithm> {
        if name.eq_ignore_ascii_case("aes-256-cbc") {
            Some(CryptoCipherAlgorithm::Aes256Cbc)
        } else if name.eq_ignore_ascii_case("aes-128-ctr") {
            Some(CryptoCipherAlgorithm::Aes128Ctr)
        } else if name.eq_ignore_ascii_case("aes-256-gcm") {
            Some(CryptoCipherAlgorithm::Aes256Gcm)
        } else {
            None
        }
    }

    pub(super) fn crypto_cipher_key_iv_lengths(algorithm: CryptoCipherAlgorithm) -> (usize, usize) {
        match algorithm {
            CryptoCipherAlgorithm::Aes256Cbc => (32, 16),
            CryptoCipherAlgorithm::Aes128Ctr => (16, 16),
            CryptoCipherAlgorithm::Aes256Gcm => (32, 12),
        }
    }

    /// Upper bound of the bounded variable-length AES-256-GCM initialization
    /// vector window (bd-lnqta). Live Node/Bun probes (2026-08-26; OpenSSL-
    /// and BoringSSL-backed runtimes) emit byte-for-byte identical tags for
    /// IV lengths 1..=128 and reject 0 and >=129 with ERR_CRYPTO_INVALID_IV.
    pub(super) const CRYPTO_GCM_MAX_IV_LEN: usize = 128;

    /// bd-lnqta: AES-256-GCM admits the bounded variable-length window
    /// above; every other algorithm keeps its exact-length contract.
    pub(super) fn crypto_cipher_iv_length_ok(
        algorithm: CryptoCipherAlgorithm,
        iv_len: usize,
    ) -> bool {
        if algorithm == CryptoCipherAlgorithm::Aes256Gcm {
            (1..=Self::CRYPTO_GCM_MAX_IV_LEN).contains(&iv_len)
        } else {
            let (_, expected_iv) = Self::crypto_cipher_key_iv_lengths(algorithm);
            iv_len == expected_iv
        }
    }

    /// bd-53l89 slice 1 (contract:
    /// docs/CRYPTO_ASYMMETRIC_KEY_LIFECYCLE_CONTRACT_V1.md §1,2,3,7,9).
    /// Entropy enters exclusively through the audited RandomRead host effect;
    /// the private seed lives only in Zeroizing storage inside
    /// `crypto_objects`; the returned JS value is an inert ObjectId handle.
    pub(super) fn crypto_generate_key_pair_sync(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        let algorithm_name = self.crypto_required_string_arg(args, 0, "key pair algorithm")?;
        if args.count > 2 {
            return Err(InterpreterError::TypeError {
                expected: "generateKeyPairSync(algorithm[, options])".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        if let Some(options) = self.builtin_arg(args, 1)? {
            if !matches!(options, Value::Undefined) {
                return Err(self.crypto_throw_node_error(
                    "Error",
                    "ERR_INVALID_ARG_VALUE",
                    "generateKeyPairSync options are not supported in this engine slice"
                        .to_string(),
                    &invocation_label,
                ));
            }
        }
        let Some(algorithm) = Self::crypto_key_pair_algorithm(&algorithm_name) else {
            return Err(self.crypto_throw_node_error(
                "Error",
                "ERR_INVALID_ARG_VALUE",
                format!(
                    "Unknown key pair algorithm: {}",
                    Self::crypto_diagnostic_fragment(&algorithm_name)
                ),
                &invocation_label,
            ));
        };
        self.require_random_read_capability()?;
        match algorithm {
            CryptoKeyPairAlgorithm::Ed25519 => {
                self.charge_crypto_work(Self::crypto_byte_work(32))?;
                let seed = match self.perform_random_read_effect(32) {
                    Ok(bytes) => Zeroizing::new(bytes),
                    Err(()) => return self.crypto_random_failure(invocation_label, None),
                };
                let Ok(seed_bytes) = <[u8; 32]>::try_from(seed.as_slice()) else {
                    return self.crypto_random_failure(invocation_label, None);
                };
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
                let public_key = signing_key.verifying_key().to_bytes().to_vec();
                self.crypto_alloc_object(CryptoObjectState::KeyPairActive {
                    algorithm,
                    private_key: Zeroizing::new(signing_key.to_bytes().to_vec()),
                    public_key,
                    lifecycle_label: invocation_label,
                })
            }
            CryptoKeyPairAlgorithm::EcP256 => {
                // Contract §2: each attempt draws exactly 32 provider bytes;
                // scalars outside [1, n-1] are rejected and redrawn, every
                // draw journaled in order. The bound is astronomically
                // unreachable (rejection ~2^-32) and fails closed.
                const P256_SCALAR_MAX_DRAWS: u64 = 64;
                let mut draws = 0_u64;
                loop {
                    draws += 1;
                    if draws > P256_SCALAR_MAX_DRAWS {
                        return Err(InterpreterError::InternalError {
                            details: "P-256 scalar redraw bound exhausted".to_string(),
                        });
                    }
                    self.charge_crypto_work(Self::crypto_byte_work(32))?;
                    let candidate = match self.perform_random_read_effect(32) {
                        Ok(bytes) => Zeroizing::new(bytes),
                        Err(()) => return self.crypto_random_failure(invocation_label, None),
                    };
                    let Ok(scalar_bytes) = <[u8; 32]>::try_from(candidate.as_slice()) else {
                        return self.crypto_random_failure(invocation_label, None);
                    };
                    let Ok(signing_key) = p256::ecdsa::SigningKey::from_slice(&scalar_bytes) else {
                        continue;
                    };
                    let public_key = signing_key
                        .verifying_key()
                        .to_encoded_point(false)
                        .as_bytes()
                        .to_vec();
                    self.charge_crypto_work(Self::crypto_byte_work(96))?;
                    return self.crypto_alloc_object(CryptoObjectState::KeyPairActive {
                        algorithm,
                        private_key: Zeroizing::new(signing_key.to_bytes().as_slice().to_vec()),
                        public_key,
                        lifecycle_label: invocation_label,
                    });
                }
            }
        }
    }

    pub(super) fn crypto_key_pair_algorithm(name: &str) -> Option<CryptoKeyPairAlgorithm> {
        match name {
            "ed25519" | "ed25519-dalek" => Some(CryptoKeyPairAlgorithm::Ed25519),
            "p256" | "prime256v1" | "secp256r1" => Some(CryptoKeyPairAlgorithm::EcP256),
            _ => None,
        }
    }

    pub(super) fn crypto_sign_sync(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        if args.count != 3 {
            return Err(InterpreterError::TypeError {
                expected: "sign(algorithm, data, key)".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        let algorithm_arg = self.builtin_arg(args, 0)?;
        let data_value = self.crypto_required_arg(args, 1, "message")?;
        let key_value = self.crypto_required_arg(args, 2, "key handle")?;
        let (algorithm, private_key, lifecycle_label) = self.crypto_key_pair_private(&key_value)?;
        let message = self.crypto_input_bytes(&data_value, None)?;
        let data_register = RegRange {
            start: args.start.saturating_add(1),
            count: 1,
        };
        let message_label = self.join_arg_range_label(data_register)?;
        self.check_temporary_memory_budget(
            u64::try_from(message.len())
                .unwrap_or(u64::MAX)
                .saturating_add(160)
                .saturating_add(Self::estimate_label_bytes(&lifecycle_label)),
        )?;
        let signature: Vec<u8> = match algorithm {
            CryptoKeyPairAlgorithm::Ed25519 => {
                Self::require_null_ed25519_algorithm(algorithm_arg, "sign", &invocation_label)?;
                self.charge_crypto_work(Self::crypto_byte_work(message.len().saturating_add(64)))?;
                let Ok(seed_bytes) = <[u8; 32]>::try_from(private_key.as_slice()) else {
                    return Err(InterpreterError::InternalError {
                        details: "ed25519 signing seed must be exactly 32 bytes".to_string(),
                    });
                };
                Self::ed25519_sign_detached(seed_bytes, &message).to_vec()
            }
            CryptoKeyPairAlgorithm::EcP256 => {
                self.require_sha256_p256_algorithm(algorithm_arg, &invocation_label)?;
                self.charge_crypto_work(Self::crypto_byte_work(message.len().saturating_add(144)))?;
                let Ok(scalar_bytes) = <[u8; 32]>::try_from(private_key.as_slice()) else {
                    return Err(InterpreterError::InternalError {
                        details: "P-256 signing scalar must be exactly 32 bytes".to_string(),
                    });
                };
                Self::p256_sign_detached_der(scalar_bytes, &message)
            }
        };
        let result_label = lifecycle_label.join(&message_label);
        self.crypto_output_value_with_temporary_budget(
            &signature,
            None,
            &result_label,
            true,
            u64::try_from(message.len()).unwrap_or(u64::MAX),
        )
    }

    /// bd-53l89 slices 2-3 (contract §5,6). Node
    /// `crypto.verify(algorithm, data, key, signature)`. The verdict consumes
    /// only public material plus caller-supplied message/signature inputs;
    /// the JoinInputs epilogue joins those operand labels onto the boolean,
    /// so a Secret message yields a Secret-labeled verdict (sound predicate
    /// secrecy).
    pub(super) fn crypto_verify_sync(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        if args.count != 4 {
            return Err(InterpreterError::TypeError {
                expected: "verify(algorithm, data, key, signature)".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        let algorithm_arg = self.builtin_arg(args, 0)?;
        let data_value = self.crypto_required_arg(args, 1, "message")?;
        let key_value = self.crypto_required_arg(args, 2, "key handle")?;
        let signature_value = self.crypto_required_arg(args, 3, "signature")?;
        let (algorithm, _private, public_key, _lifecycle) =
            self.crypto_key_pair_parts(&key_value)?;
        let message = self.crypto_input_bytes(&data_value, None)?;
        let signature = self.crypto_input_bytes(&signature_value, None)?;
        self.check_temporary_memory_budget(
            u64::try_from(message.len())
                .unwrap_or(u64::MAX)
                .saturating_add(u64::try_from(signature.len()).unwrap_or(u64::MAX))
                .saturating_add(96),
        )?;
        self.charge_crypto_work(Self::crypto_byte_work(
            message.len().saturating_add(signature.len()),
        ))?;
        let verified = match algorithm {
            CryptoKeyPairAlgorithm::Ed25519 => {
                Self::require_null_ed25519_algorithm(algorithm_arg, "verify", &invocation_label)?;
                let Ok(public_key_bytes) = <[u8; 32]>::try_from(public_key.as_slice()) else {
                    return Err(InterpreterError::InternalError {
                        details: "ed25519 public key must be exactly 32 bytes".to_string(),
                    });
                };
                match Self::ed25519_verify_detached(public_key_bytes, &message, &signature) {
                    Ok(verified) => verified,
                    Err("ERR_CRYPTO_INVALID_SIGNATURE_LENGTH") => {
                        return Err(self.crypto_throw_node_error(
                            "RangeError",
                            "ERR_CRYPTO_INVALID_SIGNATURE_LENGTH",
                            format!(
                                "Invalid Ed25519 signature length: expected 64 bytes, got {}",
                                signature.len()
                            ),
                            &invocation_label,
                        ));
                    }
                    Err(other) => {
                        return Err(InterpreterError::InternalError {
                            details: other.to_string(),
                        });
                    }
                }
            }
            CryptoKeyPairAlgorithm::EcP256 => {
                self.require_sha256_p256_algorithm(algorithm_arg, &invocation_label)?;
                match Self::p256_verify_detached_der(&public_key, &message, &signature) {
                    Ok(verified) => verified,
                    Err("ERR_CRYPTO_INVALID_SIGNATURE") => {
                        return Err(self.crypto_throw_node_error(
                            "RangeError",
                            "ERR_CRYPTO_INVALID_SIGNATURE",
                            "Invalid ECDSA signature encoding".to_string(),
                            &invocation_label,
                        ));
                    }
                    Err(other) => {
                        return Err(InterpreterError::InternalError {
                            details: other.to_string(),
                        });
                    }
                }
            }
        };
        Ok(Value::Bool(verified))
    }

    pub(super) fn require_null_ed25519_algorithm(
        value: Option<Value>,
        operation: &str,
        _invocation_label: &Label,
    ) -> Result<(), InterpreterError> {
        match value {
            None | Some(Value::Undefined) | Some(Value::Null) => Ok(()),
            Some(other) => Err(InterpreterError::TypeError {
                expected: format!("null algorithm for Ed25519 {operation}"),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// bd-53l89 slice 3: ECDSA over P-256 pins SHA-256 as the only digest in
    /// this slice; anything else is a typed argument error.
    pub(super) fn require_sha256_p256_algorithm(
        &mut self,
        value: Option<Value>,
        _invocation_label: &Label,
    ) -> Result<(), InterpreterError> {
        match value {
            Some(Value::Str(name)) if name.as_str() == Some("sha256") => Ok(()),
            other => Err(InterpreterError::TypeError {
                expected:
                    "the literal \"sha256\" digest for P-256 sign/verify in this engine slice"
                        .to_string(),
                got: other
                    .map(|value| value.type_name().to_string())
                    .unwrap_or_else(|| "null".to_string()),
            }),
        }
    }

    /// Resolve a live KeyPairActive handle to its signing-private parts
    /// (contract §1: ObjectId membership is the authority; §3: the private
    /// clone stays inside Zeroizing).
    pub(super) fn crypto_key_pair_private(
        &self,
        value: &Value,
    ) -> Result<(CryptoKeyPairAlgorithm, Zeroizing<Vec<u8>>, Label), InterpreterError> {
        let Value::Object(object_id) = value else {
            return Err(InterpreterError::TypeError {
                expected: "key pair handle".to_string(),
                got: value.type_name().to_string(),
            });
        };
        match self.crypto_objects.get(object_id) {
            Some(CryptoObjectState::KeyPairActive {
                algorithm,
                private_key,
                lifecycle_label,
                ..
            }) => Ok((*algorithm, private_key.clone(), lifecycle_label.clone())),
            Some(_) => Err(InterpreterError::TypeError {
                expected: "key pair handle".to_string(),
                got: "non-key-pair crypto object".to_string(),
            }),
            None => Err(InterpreterError::TypeError {
                expected: "key pair handle".to_string(),
                got: "detached or forged receiver".to_string(),
            }),
        }
    }

    /// Resolve a live KeyPairActive handle to all four public-facing parts.
    pub(super) fn crypto_key_pair_parts(
        &self,
        value: &Value,
    ) -> Result<CryptoKeyPairParts, InterpreterError> {
        let Value::Object(object_id) = value else {
            return Err(InterpreterError::TypeError {
                expected: "key pair handle".to_string(),
                got: value.type_name().to_string(),
            });
        };
        match self.crypto_objects.get(object_id) {
            Some(CryptoObjectState::KeyPairActive {
                algorithm,
                private_key,
                public_key,
                lifecycle_label,
            }) => Ok((
                *algorithm,
                private_key.clone(),
                public_key.clone(),
                lifecycle_label.clone(),
            )),
            Some(_) => Err(InterpreterError::TypeError {
                expected: "key pair handle".to_string(),
                got: "non-key-pair crypto object".to_string(),
            }),
            None => Err(InterpreterError::TypeError {
                expected: "key pair handle".to_string(),
                got: "detached or forged receiver".to_string(),
            }),
        }
    }

    pub(super) fn crypto_create_cipher(
        &mut self,
        args: RegRange,
        direction: CryptoCipherDirection,
    ) -> Result<Value, InterpreterError> {
        let invocation_label = self.crypto_invocation_label(args)?;
        let algorithm_name = self.crypto_required_string_arg(args, 0, "cipher algorithm")?;
        let Some(algorithm) = Self::crypto_cipher_algorithm(&algorithm_name, direction) else {
            return Err(self.crypto_throw_node_error(
                "Error",
                "ERR_CRYPTO_UNKNOWN_CIPHER",
                format!(
                    "Unknown cipher: {}",
                    Self::crypto_diagnostic_fragment(&algorithm_name)
                ),
                &invocation_label,
            ));
        };
        let key_value = self.crypto_required_arg(args, 1, "cipher key")?;
        let iv_value = self.crypto_required_arg(args, 2, "cipher IV")?;
        self.check_temporary_memory_budget(
            self.crypto_input_allocation_bound(&key_value, None)?
                .saturating_add(self.crypto_input_allocation_bound(&iv_value, None)?)
                .saturating_add(CRYPTO_STATE_BASE_BYTES)
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        let key = Zeroizing::new(self.crypto_input_bytes(&key_value, None)?);
        let iv = Zeroizing::new(self.crypto_input_bytes(&iv_value, None)?);
        let (expected_key, expected_iv) = Self::crypto_cipher_key_iv_lengths(algorithm);
        if key.len() != expected_key {
            drop(key);
            drop(iv);
            return Err(self.crypto_throw_node_error(
                "RangeError",
                "ERR_CRYPTO_INVALID_KEYLEN",
                format!("Invalid key length: expected {expected_key} bytes"),
                &invocation_label,
            ));
        }
        if !Self::crypto_cipher_iv_length_ok(algorithm, iv.len()) {
            drop(key);
            drop(iv);
            let detail = if algorithm == CryptoCipherAlgorithm::Aes256Gcm {
                // Node/Bun variable-length GCM rejection carries no expected
                // count because every length outside the window fails.
                "Invalid initialization vector".to_string()
            } else {
                format!("Invalid initialization vector: expected {expected_iv} bytes")
            };
            return Err(self.crypto_throw_node_error(
                "TypeError",
                "ERR_CRYPTO_INVALID_IV",
                detail,
                &invocation_label,
            ));
        }
        self.crypto_alloc_object(CryptoObjectState::CipherActive {
            algorithm,
            direction,
            key,
            iv,
            input: Zeroizing::new(Vec::new()),
            auth_tag: None,
            emitted: 0,
            output_encoding: None,
            output_remainder: Zeroizing::new(Vec::new()),
            lifecycle_label: invocation_label,
        })
    }

    pub(super) fn crypto_transform_cipher_all(
        algorithm: CryptoCipherAlgorithm,
        direction: CryptoCipherDirection,
        key: &[u8],
        iv: &[u8],
        input: &[u8],
        auth_tag: Option<&[u8]>,
    ) -> Result<CryptoCipherOutput, &'static str> {
        match (algorithm, direction) {
            (CryptoCipherAlgorithm::Aes256Cbc, CryptoCipherDirection::Encrypt) => {
                let mut output = Zeroizing::new(Vec::with_capacity(input.len().saturating_add(16)));
                output.extend_from_slice(input);
                let input_len = output.len();
                output.resize(input_len.saturating_add(16), 0);
                let output_len = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
                    .map_err(|_| "invalid AES-256-CBC key or IV")?
                    .encrypt_padded_mut::<Pkcs7>(&mut output, input_len)
                    .map_err(|_| "AES-256-CBC padding failed")?
                    .len();
                output.truncate(output_len);
                Ok((output, None))
            }
            (CryptoCipherAlgorithm::Aes256Cbc, CryptoCipherDirection::Decrypt) => {
                let mut output = Zeroizing::new(input.to_vec());
                let output_len = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                    .map_err(|_| "invalid AES-256-CBC key or IV")?
                    .decrypt_padded_mut::<Pkcs7>(&mut output)
                    .map_err(|_| "bad decrypt")?
                    .len();
                output.truncate(output_len);
                Ok((output, None))
            }
            (CryptoCipherAlgorithm::Aes128Ctr, _) => {
                let mut output = Zeroizing::new(input.to_vec());
                let mut cipher = ctr::Ctr128BE::<aes::Aes128>::new_from_slices(key, iv)
                    .map_err(|_| "invalid AES-128-CTR key or IV")?;
                cipher.apply_keystream(&mut output);
                Ok((output, None))
            }
            (CryptoCipherAlgorithm::Aes256Gcm, CryptoCipherDirection::Encrypt) => {
                if iv.len() == 12 {
                    let cipher = <aes_gcm::Aes256Gcm as AeadKeyInit>::new_from_slice(key)
                        .map_err(|_| "invalid AES-256-GCM key")?;
                    let nonce = aes_gcm::Nonce::<aes::cipher::consts::U12>::from_slice(iv);
                    let mut output = Zeroizing::new(input.to_vec());
                    let tag = cipher
                        .encrypt_in_place_detached(nonce, b"", &mut output)
                        .map_err(|_| "AES-256-GCM encryption failed")?;
                    Ok((output, Some(Zeroizing::new(tag.to_vec()))))
                } else {
                    Self::crypto_gcm_variable_nonce_transform(key, iv, input, direction, auth_tag)
                }
            }
            (CryptoCipherAlgorithm::Aes256Gcm, CryptoCipherDirection::Decrypt) => {
                if iv.len() == 12 {
                    let cipher = <aes_gcm::Aes256Gcm as AeadKeyInit>::new_from_slice(key)
                        .map_err(|_| "invalid AES-256-GCM key")?;
                    let nonce = aes_gcm::Nonce::<aes::cipher::consts::U12>::from_slice(iv);
                    let tag =
                        aes_gcm::Tag::from_slice(auth_tag.ok_or("authentication tag not set")?);
                    let mut output = Zeroizing::new(input.to_vec());
                    cipher
                        .decrypt_in_place_detached(nonce, b"", &mut output, tag)
                        .map_err(|_| "unable to authenticate data")?;
                    Ok((output, None))
                } else {
                    Self::crypto_gcm_variable_nonce_transform(key, iv, input, direction, auth_tag)
                }
            }
        }
    }

    /// bd-53l89 slice 2: pure Ed25519 detached signing over the stored seed
    /// (contract §2/§6 — deterministic Ed25519 nonce, no extra entropy).
    pub(super) fn ed25519_sign_detached(seed: [u8; 32], message: &[u8]) -> [u8; 64] {
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .sign(message)
            .to_bytes()
    }

    /// bd-53l89 slice 2: pure Ed25519 verification. `Err` carries the typed
    /// failure class for malformed signatures; `Ok(false)` is a legitimate
    /// reject, not an error.
    pub(super) fn ed25519_verify_detached(
        public_key: [u8; 32],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, &'static str> {
        let Ok(signature_array) = <[u8; 64]>::try_from(signature) else {
            return Err("ERR_CRYPTO_INVALID_SIGNATURE_LENGTH");
        };
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| "stored Ed25519 public key rejected")?;
        let signature = Ed25519Signature::from_slice(&signature_array)
            .map_err(|_| "ERR_CRYPTO_INVALID_SIGNATURE_LENGTH")?;
        Ok(verifying_key.verify(message, &signature).is_ok())
    }

    /// bd-53l89 slice 3: pure P-256 ECDSA signing with RFC 6979 deterministic
    /// nonces (SHA-256), returning the DER encoding Node emits. The scalar is
    /// validated at generation, so construction cannot fail here.
    pub(super) fn p256_sign_detached_der(scalar: [u8; 32], message: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&scalar)
            .expect("P-256 scalar validated during generation");
        let signature: p256::ecdsa::Signature = signing_key.sign(message);
        signature.to_der().as_bytes().to_vec()
    }

    /// bd-53l89 slice 3: pure P-256 ECDSA verification over an uncompressed
    /// SEC1 public key and a DER signature. `Err` carries the typed failure
    /// class for malformed encodings; `Ok(false)` is a legitimate reject.
    pub(super) fn p256_verify_detached_der(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, &'static str> {
        let encoded_point = p256::EncodedPoint::from_bytes(public_key)
            .map_err(|_| "stored P-256 public key rejected")?;
        let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)
            .map_err(|_| "stored P-256 public key rejected")?;
        let signature = p256::ecdsa::Signature::from_der(signature)
            .map_err(|_| "ERR_CRYPTO_INVALID_SIGNATURE")?;
        Ok(verifying_key.verify(message, &signature).is_ok())
    }

    /// bd-lnqta: NIST SP 800-38D AES-256-GCM for initialization vectors whose
    /// length differs from the audited 96-bit fast path above. J0 is derived
    /// through GHASH per §8.2.1, counters increment only the low 32 bits
    /// (§6.5 inc32), and the tag closes over the no-AAD lengths block per
    /// §7.1. Decryption verifies the caller-supplied tag in constant time
    /// and releases plaintext only on success.
    pub(super) fn crypto_gcm_variable_nonce_transform(
        key: &[u8],
        iv: &[u8],
        input: &[u8],
        direction: CryptoCipherDirection,
        auth_tag: Option<&[u8]>,
    ) -> Result<CryptoCipherOutput, &'static str> {
        debug_assert!(
            (1..=Self::CRYPTO_GCM_MAX_IV_LEN).contains(&iv.len()) && iv.len() != 12,
            "caller must bound-check the GCM IV window before dispatching here"
        );
        let cipher = aes::Aes256::new_from_slice(key).map_err(|_| "invalid AES-256-GCM key")?;
        // H = E(K, 0^128).
        let mut h_block = aes::Block::clone_from_slice(&[0u8; 16]);
        cipher.encrypt_block(&mut h_block);
        let ghash_key = universal_hash::Key::<GHash>::clone_from_slice(h_block.as_slice());
        // J0 per SP 800-38D §8.2.1: the 96-bit form concatenates a fixed
        // word; every other length runs GHASH over IV || zero-pad || [bits].
        let j0 = if iv.len() == 12 {
            let mut block = [0u8; 16];
            block[..12].copy_from_slice(iv);
            block[15] = 1;
            aes::Block::from(block)
        } else {
            let mut ghash_of_iv = GHash::new(&ghash_key);
            ghash_of_iv.update_padded(iv);
            let iv_bits = (iv.len() as u64)
                .checked_mul(8)
                .ok_or("AES-256-GCM IV bit length overflow")?;
            let mut length_block = [0u8; 16];
            length_block[8..].copy_from_slice(&iv_bits.to_be_bytes());
            ghash_of_iv.update(&[universal_hash::Block::<GHash>::clone_from_slice(
                &length_block,
            )]);
            let derived = ghash_of_iv.finalize();
            aes::Block::clone_from_slice(derived.as_slice())
        };
        // T0 = E(K, J0); data counters start at inc32(J0).
        let mut tag_base = j0;
        cipher.encrypt_block(&mut tag_base);
        let mut counter = j0;
        let mut output = Zeroizing::new(input.to_vec());
        for chunk in output.chunks_mut(16) {
            let tail = &mut counter[..];
            let low = u32::from_be_bytes([tail[12], tail[13], tail[14], tail[15]]).wrapping_add(1);
            tail[12..16].copy_from_slice(&low.to_be_bytes());
            let mut keystream = counter;
            cipher.encrypt_block(&mut keystream);
            for (byte, key_byte) in chunk.iter_mut().zip(keystream.iter()) {
                *byte ^= key_byte;
            }
        }
        // GHASH domain is the ciphertext alone (no-AAD policy), closed by
        // the §7.1 lengths block [0]^64 || [len(C)]_64. On decryption the
        // ciphertext is the caller's input, not the produced plaintext.
        let ciphertext_bytes: &[u8] = match direction {
            CryptoCipherDirection::Encrypt => &output,
            CryptoCipherDirection::Decrypt => input,
        };
        let mut ghash_over_ciphertext = GHash::new(&ghash_key);
        ghash_over_ciphertext.update_padded(ciphertext_bytes);
        let ciphertext_bits = (output.len() as u64)
            .checked_mul(8)
            .ok_or("AES-256-GCM ciphertext bit length overflow")?;
        let mut lengths_block = [0u8; 16];
        lengths_block[8..].copy_from_slice(&ciphertext_bits.to_be_bytes());
        ghash_over_ciphertext.update(&[universal_hash::Block::<GHash>::clone_from_slice(
            &lengths_block,
        )]);
        let ghash_value = ghash_over_ciphertext.finalize();
        let mut expected_tag = [0u8; 16];
        for ((slot, base), hashed) in expected_tag
            .iter_mut()
            .zip(tag_base.iter())
            .zip(ghash_value.iter())
        {
            *slot = base ^ hashed;
        }
        match direction {
            CryptoCipherDirection::Encrypt => {
                Ok((output, Some(Zeroizing::new(expected_tag.to_vec()))))
            }
            CryptoCipherDirection::Decrypt => {
                let provided = auth_tag.ok_or("authentication tag not set")?;
                if provided.len() != 16 || !bool::from(provided.ct_eq(expected_tag.as_slice())) {
                    return Err("unable to authenticate data");
                }
                Ok((output, None))
            }
        }
    }

    pub(super) fn crypto_transform_cbc_prefix(
        direction: CryptoCipherDirection,
        key: &[u8],
        iv: &[u8],
        input: &[u8],
        prefix_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        if prefix_len == 0 {
            return Ok(Zeroizing::new(Vec::new()));
        }
        let Some(prefix) = input.get(..prefix_len) else {
            return Err("AES-256-CBC prefix exceeds buffered input");
        };
        let mut output = Zeroizing::new(prefix.to_vec());
        let output_len = match direction {
            CryptoCipherDirection::Encrypt => {
                cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
                    .map_err(|_| "invalid AES-256-CBC key or IV")?
                    .encrypt_padded_mut::<NoPadding>(&mut output, prefix_len)
                    .map_err(|_| "AES-256-CBC block encryption failed")?
                    .len()
            }
            CryptoCipherDirection::Decrypt => {
                cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                    .map_err(|_| "invalid AES-256-CBC key or IV")?
                    .decrypt_padded_mut::<NoPadding>(&mut output)
                    .map_err(|_| "AES-256-CBC block decryption failed")?
                    .len()
            }
        };
        output.truncate(output_len);
        Ok(output)
    }

    pub(super) fn crypto_cipher_update(
        &mut self,
        receiver: Option<Value>,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.crypto_receiver_id(receiver, builtin, "update")?;
        let invocation_label = self.crypto_invocation_label(args)?;
        let input_value = self.crypto_required_arg(args, 0, "cipher update input")?;
        let input_encoding = self.builtin_arg(args, 1)?;
        let requested_output_encoding = self.builtin_arg(args, 2)?;
        let retained_state_bytes = self
            .crypto_objects
            .get(&object_id)
            .map(Self::estimate_crypto_object_state_bytes)
            .expect("authenticated crypto receiver has state");
        self.check_temporary_memory_budget(
            retained_state_bytes
                .saturating_add(
                    self.crypto_update_input_allocation_bound(
                        &input_value,
                        input_encoding.as_ref(),
                    )?,
                )
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        let previous = self.crypto_state_snapshot(object_id)?;
        if let CryptoObjectState::CipherFinalized {
            lifecycle_label, ..
        } = &previous
        {
            let label = self.clone_dominant_label_with_temporary_budget(
                lifecycle_label,
                &invocation_label,
                Self::estimate_crypto_object_state_bytes(&previous)
                    .saturating_add(Self::estimate_label_bytes(&invocation_label)),
            )?;
            return Err(self.crypto_throw_node_error_with_temporary_budget(
                "Error",
                "ERR_CRYPTO_INVALID_STATE",
                "Cipher context already finalized".to_string(),
                &label,
                retained_state_bytes.saturating_add(Self::estimate_label_bytes(&invocation_label)),
            ));
        }
        let bytes =
            Zeroizing::new(self.crypto_update_input_bytes(&input_value, input_encoding.as_ref())?);
        let CryptoObjectState::CipherActive {
            algorithm,
            direction,
            key,
            iv,
            input,
            auth_tag,
            emitted,
            output_encoding: previous_output_encoding,
            output_remainder: previous_output_remainder,
            lifecycle_label,
        } = &previous
        else {
            return Err(InterpreterError::TypeError {
                expected: "cipher receiver".to_string(),
                got: "hash/HMAC receiver".to_string(),
            });
        };
        let next_input_len =
            input
                .len()
                .checked_add(bytes.len())
                .ok_or_else(|| InterpreterError::RangeError {
                    message: "cipher input length overflow".to_string(),
                })?;
        if next_input_len > CRYPTO_MAX_INPUT_BYTES {
            return Err(InterpreterError::RangeError {
                message: "cipher input exceeds engine Buffer cap".to_string(),
            });
        }
        let next_lifecycle_label = self.clone_dominant_label_with_temporary_budget(
            lifecycle_label,
            &invocation_label,
            Self::estimate_crypto_object_state_bytes(&previous)
                .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        let next_input_bytes = u64::try_from(next_input_len).unwrap_or(u64::MAX);
        let candidate_state_bytes = CRYPTO_STATE_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
            .saturating_add(u64::try_from(key.capacity()).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(iv.capacity()).unwrap_or(u64::MAX))
            .saturating_add(next_input_bytes)
            .saturating_add(
                auth_tag
                    .as_ref()
                    .map_or(0, |tag| u64::try_from(tag.capacity()).unwrap_or(u64::MAX)),
            )
            .saturating_add(u64::try_from(previous_output_remainder.capacity()).unwrap_or(u64::MAX))
            .saturating_add(Self::estimate_label_bytes(&next_lifecycle_label));
        let invocation_label_bytes = Self::estimate_label_bytes(&invocation_label);
        let next_lifecycle_label_bytes = Self::estimate_label_bytes(&next_lifecycle_label);
        let previous_remainder_bytes =
            u64::try_from(previous_output_remainder.capacity()).unwrap_or(u64::MAX);
        // Peak CTR/GCM update retains the state snapshot, decoded bytes,
        // candidate state, full transformed output, sliced incremental output,
        // and its published Buffer/string together. Preflight the complete set
        // before growing the candidate input or invoking RustCrypto.
        self.check_temporary_memory_budget(
            Self::estimate_crypto_object_state_bytes(&previous)
                .saturating_add(u64::try_from(bytes.capacity()).unwrap_or(u64::MAX))
                .saturating_add(candidate_state_bytes)
                .saturating_add(Self::crypto_output_pipeline_peak_bytes(
                    next_input_bytes,
                    next_input_bytes,
                    previous_remainder_bytes,
                ))
                // The standalone joined label, published backing-store label,
                // and pending hostcall-result label can coexist.  The
                // candidate state's copy is already in candidate_state_bytes.
                .saturating_add(next_lifecycle_label_bytes.saturating_mul(3))
                .saturating_add(invocation_label_bytes),
        )?;
        self.charge_crypto_work(Self::crypto_byte_work(next_input_len))?;
        let mut next_input = Zeroizing::new(Vec::with_capacity(next_input_len));
        next_input.extend_from_slice(input);
        next_input.extend_from_slice(&bytes);
        let full_output = match algorithm {
            CryptoCipherAlgorithm::Aes256Cbc => {
                let complete_blocks = next_input.len() / 16;
                let emitted_blocks = match direction {
                    CryptoCipherDirection::Encrypt => complete_blocks,
                    // Retain the last complete ciphertext block until final so
                    // PKCS#7 padding is validated before its plaintext escapes.
                    CryptoCipherDirection::Decrypt => complete_blocks.saturating_sub(1),
                };
                Self::crypto_transform_cbc_prefix(
                    *direction,
                    key,
                    iv,
                    &next_input,
                    emitted_blocks.saturating_mul(16),
                )
                .map_err(|message| InterpreterError::InternalError {
                    details: message.to_string(),
                })?
            }
            CryptoCipherAlgorithm::Aes256Gcm if *direction == CryptoCipherDirection::Decrypt => {
                // Authenticated plaintext cannot escape before final verifies
                // the caller-supplied tag.
                Zeroizing::new(Vec::new())
            }
            CryptoCipherAlgorithm::Aes128Ctr | CryptoCipherAlgorithm::Aes256Gcm => {
                Self::crypto_transform_cipher_all(
                    *algorithm,
                    *direction,
                    key,
                    iv,
                    &next_input,
                    auth_tag.as_ref().map(|tag| tag.as_slice()),
                )
                .map_err(|message| InterpreterError::InternalError {
                    details: message.to_string(),
                })?
                .0
            }
        };
        let raw_output = Zeroizing::new(full_output.get(*emitted..).unwrap_or_default().to_vec());
        let next_emitted = full_output.len();
        let canonical_output_encoding =
            Self::crypto_canonical_output_encoding(&requested_output_encoding);
        let encoding_mismatch = canonical_output_encoding.as_ref().is_ok_and(|encoding| {
            encoding.as_ref().is_some_and(|encoding| {
                previous_output_encoding
                    .as_ref()
                    .is_some_and(|previous| previous != encoding)
            })
        });
        let (output, next_output_encoding, next_output_remainder, output_encoding_for_publication) =
            match canonical_output_encoding {
                Ok(None) | Err(()) => (
                    raw_output,
                    previous_output_encoding.clone(),
                    previous_output_remainder.clone(),
                    requested_output_encoding,
                ),
                Ok(Some(_)) if encoding_mismatch => {
                    drop(raw_output);
                    (
                        Zeroizing::new(Vec::new()),
                        previous_output_encoding.clone(),
                        previous_output_remainder.clone(),
                        None,
                    )
                }
                Ok(Some(encoding)) => {
                    let (output, remainder) = Self::crypto_encoded_stream_chunk(
                        previous_output_remainder,
                        &raw_output,
                        &encoding,
                        false,
                    );
                    (
                        output,
                        Some(encoding.clone()),
                        remainder,
                        Some(Value::str(encoding)),
                    )
                }
            };
        let next = CryptoObjectState::CipherActive {
            algorithm: *algorithm,
            direction: *direction,
            key: key.clone(),
            iv: iv.clone(),
            input: next_input,
            auth_tag: auth_tag.clone(),
            emitted: next_emitted,
            output_encoding: next_output_encoding,
            output_remainder: next_output_remainder,
            lifecycle_label: next_lifecycle_label.clone(),
        };
        let previous_state_bytes = Self::estimate_crypto_object_state_bytes(&previous);
        let next_state_bytes = Self::estimate_crypto_object_state_bytes(&next);
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            self.apply_memory_component_delta(previous_state_bytes, next_state_bytes)?;
            self.crypto_objects.insert(object_id, next);
            if encoding_mismatch {
                return Err(self.crypto_throw_node_error_with_temporary_budget(
                    "Error",
                    "ERR_INTERNAL_ASSERTION",
                    "Cannot change encoding".to_string(),
                    &next_lifecycle_label,
                    previous_state_bytes
                        .saturating_add(u64::try_from(bytes.capacity()).unwrap_or(u64::MAX))
                        .saturating_add(u64::try_from(full_output.capacity()).unwrap_or(u64::MAX))
                        .saturating_add(u64::try_from(output.capacity()).unwrap_or(u64::MAX))
                        .saturating_add(invocation_label_bytes),
                ));
            }
            self.crypto_output_value_with_temporary_budget(
                &output,
                output_encoding_for_publication,
                &next_lifecycle_label,
                true,
                previous_state_bytes
                    .saturating_add(u64::try_from(bytes.capacity()).unwrap_or(u64::MAX))
                    .saturating_add(u64::try_from(full_output.capacity()).unwrap_or(u64::MAX))
                    .saturating_add(u64::try_from(output.capacity()).unwrap_or(u64::MAX))
                    .saturating_add(invocation_label_bytes)
                    .saturating_add(next_lifecycle_label_bytes),
            )
        })();
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, InterpreterError::UncaughtException { .. }))
        {
            self.crypto_objects.insert(object_id, previous);
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn crypto_cipher_final(
        &mut self,
        receiver: Option<Value>,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.crypto_receiver_id(receiver, builtin, "final")?;
        let invocation_label = self.crypto_invocation_label(args)?;
        let requested_output_encoding = self.builtin_arg(args, 0)?;
        let retained_state_bytes = self
            .crypto_objects
            .get(&object_id)
            .map(Self::estimate_crypto_object_state_bytes)
            .expect("authenticated crypto receiver has state");
        let invocation_label_bytes = Self::estimate_label_bytes(&invocation_label);
        self.check_temporary_memory_budget(
            retained_state_bytes.saturating_add(invocation_label_bytes),
        )?;
        let previous = self.crypto_state_snapshot(object_id)?;
        let CryptoObjectState::CipherActive {
            algorithm,
            direction,
            key,
            iv,
            input,
            auth_tag: expected_auth_tag,
            emitted,
            output_encoding: previous_output_encoding,
            output_remainder: previous_output_remainder,
            lifecycle_label,
        } = &previous
        else {
            let label = self.clone_dominant_label_with_temporary_budget(
                previous.lifecycle_label(),
                &invocation_label,
                Self::estimate_crypto_object_state_bytes(&previous)
                    .saturating_add(Self::estimate_label_bytes(&invocation_label)),
            )?;
            return Err(self.crypto_throw_node_error_with_temporary_budget(
                "Error",
                "ERR_CRYPTO_INVALID_STATE",
                "Cipher context already finalized".to_string(),
                &label,
                retained_state_bytes.saturating_add(invocation_label_bytes),
            ));
        };
        let next_lifecycle_label = self.clone_dominant_label_with_temporary_budget(
            lifecycle_label,
            &invocation_label,
            Self::estimate_crypto_object_state_bytes(&previous)
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        let transformed_bound = u64::try_from(input.len().saturating_add(16)).unwrap_or(u64::MAX);
        let previous_remainder_bound =
            u64::try_from(previous_output_remainder.capacity()).unwrap_or(u64::MAX);
        let next_lifecycle_label_bytes = Self::estimate_label_bytes(&next_lifecycle_label);
        let candidate_state_bytes = CRYPTO_STATE_BASE_BYTES
            .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
            .saturating_add(16)
            .saturating_add(next_lifecycle_label_bytes);
        self.check_temporary_memory_budget(
            retained_state_bytes
                .saturating_add(candidate_state_bytes)
                .saturating_add(Self::crypto_output_pipeline_peak_bytes(
                    transformed_bound,
                    transformed_bound,
                    previous_remainder_bound,
                ))
                .saturating_add(next_lifecycle_label_bytes.saturating_mul(3))
                .saturating_add(invocation_label_bytes),
        )?;
        self.charge_crypto_work(Self::crypto_byte_work(input.len()))?;
        let transformed = Self::crypto_transform_cipher_all(
            *algorithm,
            *direction,
            key,
            iv,
            input,
            expected_auth_tag.as_ref().map(|tag| tag.as_slice()),
        );
        let (full_output, auth_tag) = match transformed {
            Ok(output) => output,
            Err(message) => {
                // Node consumes the cipher context on the first final attempt,
                // including a decrypt that fails padding validation. Install a
                // keyless tombstone before exposing the native error so retrying
                // final/update cannot reuse key, IV, or buffered ciphertext.
                let next = CryptoObjectState::CipherFinalized {
                    algorithm: *algorithm,
                    direction: *direction,
                    auth_tag: None,
                    lifecycle_label: next_lifecycle_label.clone(),
                };
                self.apply_memory_component_delta(
                    Self::estimate_crypto_object_state_bytes(&previous),
                    Self::estimate_crypto_object_state_bytes(&next),
                )?;
                self.crypto_objects.insert(object_id, next);
                let error_code = if *algorithm == CryptoCipherAlgorithm::Aes256Cbc
                    && *direction == CryptoCipherDirection::Decrypt
                    && (input.is_empty() || input.len() % 16 != 0)
                {
                    "ERR_OSSL_WRONG_FINAL_BLOCK_LENGTH"
                } else {
                    "ERR_OSSL_BAD_DECRYPT"
                };
                return Err(self.crypto_throw_node_error_with_temporary_budget(
                    "Error",
                    error_code,
                    message.to_string(),
                    &next_lifecycle_label,
                    retained_state_bytes.saturating_add(invocation_label_bytes),
                ));
            }
        };
        let raw_output = Zeroizing::new(full_output.get(*emitted..).unwrap_or_default().to_vec());
        let canonical_output_encoding =
            Self::crypto_canonical_output_encoding(&requested_output_encoding);
        let encoding_mismatch = canonical_output_encoding.as_ref().is_ok_and(|encoding| {
            encoding.as_ref().is_some_and(|encoding| {
                previous_output_encoding
                    .as_ref()
                    .is_some_and(|previous| previous != encoding)
            })
        });
        let (output, output_encoding_for_publication) = match canonical_output_encoding {
            Ok(None) | Err(()) => (raw_output, requested_output_encoding),
            Ok(Some(_)) if encoding_mismatch => {
                drop(raw_output);
                (Zeroizing::new(Vec::new()), None)
            }
            Ok(Some(encoding)) => {
                let (output, _) = Self::crypto_encoded_stream_chunk(
                    previous_output_remainder,
                    &raw_output,
                    &encoding,
                    true,
                );
                (output, Some(Value::str(encoding)))
            }
        };
        let next = CryptoObjectState::CipherFinalized {
            algorithm: *algorithm,
            direction: *direction,
            auth_tag,
            lifecycle_label: next_lifecycle_label.clone(),
        };
        let previous_state_bytes = Self::estimate_crypto_object_state_bytes(&previous);
        let next_state_bytes = Self::estimate_crypto_object_state_bytes(&next);
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            self.apply_memory_component_delta(previous_state_bytes, next_state_bytes)?;
            self.crypto_objects.insert(object_id, next);
            if encoding_mismatch {
                return Err(self.crypto_throw_node_error_with_temporary_budget(
                    "Error",
                    "ERR_INTERNAL_ASSERTION",
                    "Cannot change encoding".to_string(),
                    &next_lifecycle_label,
                    previous_state_bytes
                        .saturating_add(u64::try_from(full_output.capacity()).unwrap_or(u64::MAX))
                        .saturating_add(u64::try_from(output.capacity()).unwrap_or(u64::MAX))
                        .saturating_add(invocation_label_bytes),
                ));
            }
            self.crypto_output_value_with_temporary_budget(
                &output,
                output_encoding_for_publication,
                &next_lifecycle_label,
                true,
                previous_state_bytes
                    .saturating_add(u64::try_from(full_output.capacity()).unwrap_or(u64::MAX))
                    .saturating_add(u64::try_from(output.capacity()).unwrap_or(u64::MAX))
                    .saturating_add(invocation_label_bytes)
                    .saturating_add(next_lifecycle_label_bytes),
            )
        })();
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, InterpreterError::UncaughtException { .. }))
        {
            self.crypto_objects.insert(object_id, previous);
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn crypto_get_auth_tag(
        &mut self,
        receiver: Option<Value>,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.crypto_receiver_id(receiver, builtin, "getAuthTag")?;
        let invocation_label = self.crypto_invocation_label(args)?;
        let retained_state_bytes = self
            .crypto_objects
            .get(&object_id)
            .map(Self::estimate_crypto_object_state_bytes)
            .expect("authenticated crypto receiver has state");
        let invocation_label_bytes = Self::estimate_label_bytes(&invocation_label);
        self.check_temporary_memory_budget(
            retained_state_bytes.saturating_add(invocation_label_bytes),
        )?;
        let state = self.crypto_state_snapshot(object_id)?;
        let label = self.clone_dominant_label_with_temporary_budget(
            state.lifecycle_label(),
            &invocation_label,
            Self::estimate_crypto_object_state_bytes(&state)
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        let CryptoObjectState::CipherFinalized {
            algorithm: CryptoCipherAlgorithm::Aes256Gcm,
            direction: CryptoCipherDirection::Encrypt,
            auth_tag: Some(auth_tag),
            ..
        } = state
        else {
            return Err(self.crypto_throw_node_error_with_temporary_budget(
                "Error",
                "ERR_CRYPTO_INVALID_STATE",
                "Authentication tag is available only after final".to_string(),
                &label,
                retained_state_bytes.saturating_add(invocation_label_bytes),
            ));
        };
        self.crypto_output_value_with_temporary_budget(
            &auth_tag,
            None,
            &label,
            true,
            invocation_label_bytes
                .saturating_add(Self::estimate_label_bytes(&label))
                .saturating_add(u64::try_from(auth_tag.capacity()).unwrap_or(u64::MAX)),
        )
    }

    pub(super) fn crypto_set_auth_tag(
        &mut self,
        receiver: Option<Value>,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let object_id = self.crypto_receiver_id(receiver, builtin, "setAuthTag")?;
        let invocation_label = self.crypto_invocation_label(args)?;
        let tag_value = self.crypto_required_arg(args, 0, "authentication tag")?;
        let retained_state_bytes = self
            .crypto_objects
            .get(&object_id)
            .map(Self::estimate_crypto_object_state_bytes)
            .expect("authenticated crypto receiver has state");
        let tag_allocation_bound = self.crypto_input_allocation_bound(&tag_value, None)?;
        let invocation_label_bytes = Self::estimate_label_bytes(&invocation_label);
        let dominant_label_bytes = self
            .crypto_objects
            .get(&object_id)
            .map(|state| {
                let winner = if state.lifecycle_label() >= &invocation_label {
                    state.lifecycle_label()
                } else {
                    &invocation_label
                };
                Self::estimate_label_bytes(winner)
            })
            .expect("authenticated crypto receiver has state");
        // The retained state is already included in estimated_memory_bytes.
        // During this transactional replacement, however, its snapshot and a
        // second candidate clone coexist with the decoded tag and the joined
        // lifecycle label. Preflight that complete transient peak before the
        // first allocation; checking each clone in isolation would let their
        // overlapping lifetimes exceed the configured memory cap.
        self.check_temporary_memory_budget(
            retained_state_bytes
                .saturating_mul(2)
                .saturating_add(tag_allocation_bound.saturating_mul(2))
                .saturating_add(invocation_label_bytes)
                .saturating_add(dominant_label_bytes.saturating_mul(2)),
        )?;
        let tag = Zeroizing::new(self.crypto_input_bytes(&tag_value, None)?);
        let previous = self.crypto_state_snapshot(object_id)?;
        let CryptoObjectState::CipherActive {
            algorithm: CryptoCipherAlgorithm::Aes256Gcm,
            direction: CryptoCipherDirection::Decrypt,
            key,
            iv,
            input,
            auth_tag: previous_auth_tag,
            emitted,
            output_encoding,
            output_remainder,
            lifecycle_label,
        } = &previous
        else {
            let label = self.clone_dominant_label_with_temporary_budget(
                previous.lifecycle_label(),
                &invocation_label,
                Self::estimate_crypto_object_state_bytes(&previous)
                    .saturating_add(Self::estimate_label_bytes(&invocation_label)),
            )?;
            return Err(self.crypto_throw_node_error_with_temporary_budget(
                "Error",
                "ERR_CRYPTO_INVALID_STATE",
                "setAuthTag is available only on an active GCM decipher".to_string(),
                &label,
                retained_state_bytes
                    .saturating_add(tag_allocation_bound)
                    .saturating_add(invocation_label_bytes),
            ));
        };
        let next_lifecycle_label = self.clone_dominant_label_with_temporary_budget(
            lifecycle_label,
            &invocation_label,
            Self::estimate_crypto_object_state_bytes(&previous)
                .saturating_add(u64::try_from(tag.capacity()).unwrap_or(u64::MAX))
                .saturating_add(Self::estimate_label_bytes(&invocation_label)),
        )?;
        if previous_auth_tag.is_some() {
            return Err(self.crypto_throw_node_error_with_temporary_budget(
                "Error",
                "ERR_CRYPTO_INVALID_STATE",
                "Authentication tag has already been set".to_string(),
                &next_lifecycle_label,
                retained_state_bytes
                    .saturating_add(tag_allocation_bound)
                    .saturating_add(invocation_label_bytes),
            ));
        }
        if tag.len() != 16 {
            return Err(self.crypto_throw_node_error_with_temporary_budget(
                "TypeError",
                "ERR_CRYPTO_INVALID_AUTH_TAG",
                "Invalid authentication tag length: expected 16 bytes".to_string(),
                &next_lifecycle_label,
                retained_state_bytes
                    .saturating_add(tag_allocation_bound)
                    .saturating_add(invocation_label_bytes),
            ));
        }
        let next = CryptoObjectState::CipherActive {
            algorithm: CryptoCipherAlgorithm::Aes256Gcm,
            direction: CryptoCipherDirection::Decrypt,
            key: key.clone(),
            iv: iv.clone(),
            input: input.clone(),
            auth_tag: Some(tag),
            emitted: *emitted,
            output_encoding: output_encoding.clone(),
            output_remainder: output_remainder.clone(),
            lifecycle_label: next_lifecycle_label,
        };
        self.apply_memory_component_delta(
            Self::estimate_crypto_object_state_bytes(&previous),
            Self::estimate_crypto_object_state_bytes(&next),
        )?;
        self.crypto_objects.insert(object_id, next);
        Ok(Value::Object(object_id))
    }

    pub(super) fn crypto_rethrow_native_error_with_label(
        &mut self,
        error: &InterpreterError,
        label: &Label,
    ) -> Result<InterpreterError, InterpreterError> {
        self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
        self.crypto_rethrow_native_error_with_owned_label(error, label.clone())
    }

    pub(super) fn crypto_rethrow_native_error_with_owned_label(
        &mut self,
        error: &InterpreterError,
        label: Label,
    ) -> Result<InterpreterError, InterpreterError> {
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            let thrown = self.native_error_to_thrown_value(error)?;
            self.replace_pending_abrupt_slots(Some((thrown.clone(), label)), None)?;
            Ok(InterpreterError::UncaughtException {
                value: self.uncaught_exception_description(&thrown),
            })
        })();
        if result.is_err() {
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn crypto_rethrow_lifecycle_error(
        &mut self,
        error: &InterpreterError,
        object_id: ObjectId,
        capability: &str,
        method_args: RegRange,
    ) -> Result<InterpreterError, InterpreterError> {
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            // Construct and account the error object before cloning an
            // attacker-sized Custom label.  The heap allocation is then part
            // of estimated_memory_bytes when the label is materialized, so
            // the two peaks cannot pass independent non-reserving checks.
            let thrown = self.native_error_to_thrown_value(error)?;
            let invocation_label = self.crypto_invocation_label(method_args)?;
            let error_label = match self.crypto_objects.get(&object_id) {
                Some(state) if state.supports_lifecycle_capability(capability) => self
                    .join_owned_label_with_temporary_budget(
                        invocation_label,
                        state.lifecycle_label(),
                    )?,
                _ => Label::TopSecret,
            };
            self.replace_pending_abrupt_slots(Some((thrown.clone(), error_label)), None)?;
            Ok(InterpreterError::UncaughtException {
                value: self.uncaught_exception_description(&thrown),
            })
        })();
        if result.is_err() {
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn crypto_object_hostcall(
        &mut self,
        capability: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let receiver = match self.builtin_arg(args, 0)? {
            Some(receiver) => receiver,
            None => {
                let error = InterpreterError::TypeError {
                    expected: "authenticated crypto lifecycle receiver in argument slot 0"
                        .to_string(),
                    got: "missing argument".to_string(),
                };
                return Err(self.crypto_rethrow_native_error_with_label(&error, &Label::TopSecret)?);
            }
        };
        let object_id = match receiver {
            Value::Object(object_id) => object_id,
            other => {
                let error = InterpreterError::TypeError {
                    expected: "authenticated crypto lifecycle receiver".to_string(),
                    got: other.type_name().to_string(),
                };
                return Err(self.crypto_rethrow_native_error_with_label(&error, &Label::TopSecret)?);
            }
        };
        let Some(state) = self.crypto_objects.get(&object_id) else {
            let error = InterpreterError::TypeError {
                expected: "authenticated crypto lifecycle receiver".to_string(),
                got: "forged or detached object".to_string(),
            };
            return Err(self.crypto_rethrow_native_error_with_label(&error, &Label::TopSecret)?);
        };
        if !state.supports_lifecycle_capability(capability) {
            let error = InterpreterError::TypeError {
                expected: "authenticated crypto lifecycle receiver in argument slot 0".to_string(),
                got: format!("private crypto state incompatible with {capability}"),
            };
            return Err(self.crypto_rethrow_native_error_with_label(&error, &Label::TopSecret)?);
        }
        let kind = match capability {
            "builtin:CryptoObjectUpdate" => match state {
                CryptoObjectState::HashActive { .. }
                | CryptoObjectState::HashFinalized { .. }
                | CryptoObjectState::HmacActive { .. }
                | CryptoObjectState::HmacFinalized { .. } => BuiltinFunctionKind::CryptoUpdate,
                CryptoObjectState::CipherActive { .. }
                | CryptoObjectState::CipherFinalized { .. } => {
                    BuiltinFunctionKind::CryptoCipherUpdate
                }
                // bd-53l89: a key pair handle has no update lifecycle; the
                // typed refusal below keeps the match total without granting
                // any operation.
                CryptoObjectState::KeyPairActive { .. } => {
                    return Err(InterpreterError::TypeError {
                        expected: "hash, HMAC, or cipher receiver".to_string(),
                        got: "key pair receiver".to_string(),
                    });
                }
            },
            "builtin:CryptoObjectDigest" => BuiltinFunctionKind::CryptoDigest,
            "builtin:CryptoObjectCopy" => BuiltinFunctionKind::CryptoCopy,
            "builtin:CryptoObjectFinal" => BuiltinFunctionKind::CryptoCipherFinal,
            "builtin:CryptoObjectGetAuthTag" => BuiltinFunctionKind::CryptoGetAuthTag,
            "builtin:CryptoObjectSetAuthTag" => BuiltinFunctionKind::CryptoSetAuthTag,
            _ => {
                return Err(InterpreterError::InternalError {
                    details: format!(
                        "unknown authenticated crypto lifecycle capability: {capability}"
                    ),
                });
            }
        };
        let method_args = RegRange {
            start: args
                .start
                .checked_add(1)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?,
            count: args.count.saturating_sub(1),
        };
        let mut builtin = BuiltinFunction::new_kind(kind);
        builtin.bound_object = Some(object_id.0);
        let receiver = Some(Value::Object(object_id));
        let result = match kind {
            BuiltinFunctionKind::CryptoUpdate => {
                self.crypto_update(receiver, &builtin, method_args)
            }
            BuiltinFunctionKind::CryptoDigest => {
                self.crypto_digest(receiver, &builtin, method_args)
            }
            BuiltinFunctionKind::CryptoCopy => self.crypto_copy(receiver, &builtin, method_args),
            BuiltinFunctionKind::CryptoCipherUpdate => {
                self.crypto_cipher_update(receiver, &builtin, method_args)
            }
            BuiltinFunctionKind::CryptoCipherFinal => {
                self.crypto_cipher_final(receiver, &builtin, method_args)
            }
            BuiltinFunctionKind::CryptoGetAuthTag => {
                self.crypto_get_auth_tag(receiver, &builtin, method_args)
            }
            BuiltinFunctionKind::CryptoSetAuthTag => {
                self.crypto_set_auth_tag(receiver, &builtin, method_args)
            }
            _ => unreachable!("finite crypto lifecycle capability selected a crypto method"),
        };
        match result {
            Err(error)
                if !matches!(&error, InterpreterError::UncaughtException { .. })
                    && Self::js_catchable_error_name(&error).is_some() =>
            {
                // Inner lifecycle methods are synchronous and every
                // mutation-before-error path arms its own labeled exception.
                // Recompute the finite label only after a raw validation error
                // returns, when the inner method's snapshots and buffers have
                // dropped.  Keeping a wrapper-owned label clone alive across
                // the call would invalidate every inner peak preflight.
                Err(self.crypto_rethrow_lifecycle_error(
                    &error,
                    object_id,
                    capability,
                    method_args,
                )?)
            }
            other => other,
        }
    }

    #[inline(never)]
    pub(super) fn dispatch_destructure_iterator_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        match cap {
            "builtin:DestructureIteratorInit" => {
                if args.count != 1 {
                    return Err(InterpreterError::TypeError {
                        expected: "one destructuring iterable".to_string(),
                        got: format!("{} arguments", args.count),
                    });
                }
                let value = self.read_reg(args.start)?;
                let label = self.join_arg_range_label(args)?;
                self.replace_pending_hostcall_result_label(Some(label))?;
                let init = self.prepare_for_of_state(module, &value)?;
                self.init_iterator_from_state(value, init, IterationKind::Destructuring)
            }
            "builtin:DestructureIteratorNext" | "builtin:DestructureIteratorElide" => {
                if args.count != 1 {
                    return Err(InterpreterError::TypeError {
                        expected: "one destructuring iterator".to_string(),
                        got: format!("{} arguments", args.count),
                    });
                }
                let iterator = self.read_reg(args.start)?;
                let label = self.join_arg_range_label(args)?;
                self.replace_pending_hostcall_result_label(Some(label))?;
                let handle = self.expect_iterator_handle(iterator.clone())?;
                match self.iterator_state_mut(handle)? {
                    RuntimeIteratorState::ForOf(state) if state.done || state.closed => {
                        // The iterator record remains exhausted: later pattern
                        // elements neither call next nor emit fictitious steps.
                        return Ok(Value::Undefined);
                    }
                    RuntimeIteratorState::ForOf(_) => {}
                    RuntimeIteratorState::ForIn(_) => {
                        return Err(InterpreterError::TypeError {
                            expected: "destructuring for-of iterator".to_string(),
                            got: "for-in iterator".to_string(),
                        });
                    }
                }
                Ok(self
                    .advance_for_of_iterator_with_value_read(
                        module,
                        iterator,
                        cap == "builtin:DestructureIteratorNext",
                    )?
                    .unwrap_or(Value::Undefined))
            }
            "builtin:DestructureIteratorDone" => {
                // The second operand is the just-observed step value. It is
                // not inspected, but carries the step's callback/done-getter
                // provenance into the branch through the JoinInputs contract.
                if args.count != 2 {
                    return Err(InterpreterError::TypeError {
                        expected: "iterator and observed step".to_string(),
                        got: format!("{} arguments", args.count),
                    });
                }
                let handle = self.expect_iterator_handle(self.read_reg(args.start)?)?;
                match self.iterator_state_mut(handle)? {
                    RuntimeIteratorState::ForOf(state) => {
                        Ok(Value::Bool(state.done || state.closed))
                    }
                    RuntimeIteratorState::ForIn(_) => Err(InterpreterError::TypeError {
                        expected: "destructuring for-of iterator".to_string(),
                        got: "for-in iterator".to_string(),
                    }),
                }
            }
            _ => unreachable!("non-iterator intrinsic crossed the destructuring boundary"),
        }
    }

    #[inline(never)]
    pub(super) fn dispatch_builtin_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        // Each dispatch owns exactly one optional callback-derived label. A
        // previous failed or test-only direct dispatch must never taint the
        // next, unrelated hostcall.
        self.clear_pending_hostcall_result_label();
        self.builtin_dispatch_hit_unknown_member = false;
        // bd-9vouw.76: a language operation is not a host call, so it leaves
        // no telemetry record either. The telemetry channel only grows: once
        // it is full, a record is refused (and counted) without its input, so
        // its arguments are not serialized and hashed (bd-9vouw.348).
        let telemetry = !is_language_operation_tag(cap);
        let args_hash = (telemetry && self.telemetry_recorder.remaining_capacity() > 0)
            .then(|| self.hostcall_arguments_hash(args));
        if cap.starts_with("builtin:Math") {
            for offset in 0..args.count {
                if let Value::BigInt(_) = self.read_reg(args.start + offset)? {
                    return Err(InterpreterError::TypeError {
                        expected: "Number argument for a Math function".to_string(),
                        got: "bigint (cannot convert a BigInt value to a number)".to_string(),
                    });
                }
            }
        }
        self.gc_enter_builtin();
        let outcome = match cap {
            "builtin:ObjectDefineProperty"
            | "builtin:ObjectDefineProperties"
            | "builtin:ReflectDefineProperty"
                if self.has_mapped_arguments_target(args) =>
            {
                self.dispatch_mapped_arguments_definition(cap, args, module)
            }
            // These already have narrow helpers and can invoke nested guest
            // callbacks. Avoid reserving the broad handler's stack frame at
            // every Reflect reentry; keep GC and telemetry in this wrapper.
            "builtin:ReflectApply" => self.reflect_invocation_builtin(module, args, false),
            "builtin:ReflectConstruct" => self.reflect_invocation_builtin(module, args, true),
            "builtin:Date"
            | "builtin:DatePrototypeGetTime"
            | "builtin:DatePrototypeToString"
            | "builtin:DatePrototypeToLocaleString"
            | "builtin:DatePrototypeToLocaleDateString"
            | "builtin:DatePrototypeToLocaleTimeString" => {
                self.dispatch_date_hostcall(cap, args, module)
            }
            "builtin:DestructureIteratorInit"
            | "builtin:DestructureIteratorNext"
            | "builtin:DestructureIteratorElide"
            | "builtin:DestructureIteratorDone" => {
                self.dispatch_destructure_iterator_hostcall(cap, args, module)
            }
            _ => self.dispatch_builtin_hostcall_inner(cap, args, module),
        };
        self.gc_exit_builtin();
        // ApplyHostCall and callback-running builtins can complete nested
        // hostcalls. Record the outer builtin in completion order so its
        // deterministic timestamp cannot precede an already-retained inner
        // record and trigger a false monotonicity drop (bd-juz83).
        if telemetry {
            let timestamp_ns = self.instructions_executed;
            match args_hash {
                Some(args_hash) => {
                    self.record_hostcall_telemetry(cap, args, timestamp_ns, args_hash, &outcome);
                }
                None => {
                    // Full before the dispatch, so still full.
                    self.telemetry_recorder.refuse_while_full(timestamp_ns);
                }
            }
        }
        outcome
    }

    pub(super) fn dispatch_date_hostcall(
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
        let outcome = (|| {
            if args.count > 0 {
                let value = self.read_reg(args.start)?;
                self.observe_date_value_label(&value)?;
            }
            self.dispatch_builtin_hostcall_inner(cap, args, module)
        })();
        self.finish_property_read_observation(observation, outcome)
    }

    /// Deterministic wall-clock reading in epoch milliseconds: the fixed
    /// epoch plus the event loop's virtual time, after crediting guest work
    /// since the previous reading (one virtual millisecond per
    /// [`INSTRUCTIONS_PER_VIRTUAL_MS`] instructions). Advancing the shared
    /// event-loop clock keeps readings monotonic and consistent with timer
    /// due times (bd-9vouw.59).
    pub(super) fn virtual_wall_clock_ms(&mut self) -> f64 {
        if self.instructions_executed < self.virtual_clock_instruction_mark {
            // A reused core restarted its instruction counter.
            self.virtual_clock_instruction_mark = self.instructions_executed;
        }
        let elapsed_ms = (self.instructions_executed - self.virtual_clock_instruction_mark)
            / INSTRUCTIONS_PER_VIRTUAL_MS;
        if elapsed_ms > 0 {
            let now = self.event_loop.clock.now_ms();
            self.event_loop
                .clock
                .advance_to(now.saturating_add(elapsed_ms));
            self.virtual_clock_instruction_mark = self
                .virtual_clock_instruction_mark
                .saturating_add(elapsed_ms.saturating_mul(INSTRUCTIONS_PER_VIRTUAL_MS));
        }
        DETERMINISTIC_EPOCH_MS as f64 + self.event_loop.clock.now_ms() as f64
    }

    pub(super) fn deterministic_performance_now(&mut self) -> Value {
        const DETERMINISTIC_PERFORMANCE_BASE_TICK: u64 = 0;

        let consumed_ticks = self.instructions_executed;
        let payload = format!(
            "clock_source=deterministic_instruction_tick;base_tick={DETERMINISTIC_PERFORMANCE_BASE_TICK};consumed_ticks={consumed_ticks}"
        );
        self.nondeterminism_trace.capture(
            NondeterminismSource::TimerRead,
            payload.into_bytes(),
            consumed_ticks,
            "baseline_interpreter",
        );
        Value::Float(Float64::new(
            DETERMINISTIC_PERFORMANCE_BASE_TICK as f64 + consumed_ticks as f64,
        ))
    }

    pub(super) fn alloc_import_meta_object(&mut self) -> Result<Value, InterpreterError> {
        let origin = self
            .current_module_specifier
            .as_deref()
            .or(self.entry_module_specifier.as_deref())
            .or_else(|| {
                self.module_resolver
                    .as_ref()
                    .map(|installed| installed.resolver.entry_referrer())
            })
            .unwrap_or("");
        if let Some(object_id) = self
            .module_state
            .modules
            .get(origin)
            .and_then(|record| record.import_meta_object)
        {
            return Ok(Value::Object(object_id));
        }
        self.check_temporary_memory_budget(Self::estimate_string_bytes(origin).saturating_mul(2))?;
        let origin = origin.to_string();
        let location = self
            .module_resolver
            .as_ref()
            .and_then(|installed| installed.resolver.source_location(&origin));
        let url = location.map_or(IMPORT_META_URL_VALUE, |location| location.url.as_str());
        let dirname = location
            .and_then(|location| location.filename.parent())
            .and_then(Path::to_str)
            .unwrap_or(IMPORT_META_DIRNAME_VALUE);
        // Capture the origin on this object: an importing module may retain
        // and later read another module's import.meta.
        let url = Value::str(url);
        let dirname = Value::str(dirname);
        let resolve = Value::BuiltinFunction(BuiltinFunction::import_meta_resolve(&origin));
        let object_id = self.alloc_object_with_properties(&[
            ("url", url),
            ("dirname", dirname),
            ("resolve", resolve),
        ])?;
        let index = object_id.0 as usize;
        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(index) {
                object.is_import_meta = true;
            }
        });
        self.store_prototype_link(object_id, None);
        if let Some(record) = self.module_state.modules.get_mut(&origin) {
            record.import_meta_object = Some(object_id);
        }
        Ok(Value::Object(object_id))
    }

    pub(super) fn is_import_meta_object(
        &self,
        object_id: ObjectId,
    ) -> Result<bool, InterpreterError> {
        self.heap
            .get(object_id.0 as usize)
            .map(|object| object.is_import_meta)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })
    }

    pub(super) fn record_import_meta_contract_access(&mut self, key: &str, allowed: bool) {
        let tag = format!("builtin:ImportMeta.{key}");
        let recordable_tag = recordable_capability_tag(&tag);
        let decision = if allowed { "granted" } else { "denied" };
        self.emit_witness(
            WitnessEventKind::CapabilityChecked,
            Some(&format!("{decision}:{}", recordable_tag.as_ref())),
        );
        self.hostcall_decisions.push(HostcallDecisionRecord {
            seq: self.hostcall_decisions.len() as u64,
            capability: CapabilityTag(recordable_tag.into_owned()),
            allowed,
            instruction_index: self.ip as u32,
        });
    }

    pub(super) fn import_meta_property_value(
        &mut self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        match key {
            "url" | "dirname" => {
                self.record_import_meta_contract_access(key, true);
                if self.module_resolver.is_none() {
                    return Ok(Value::str(if key == "url" {
                        IMPORT_META_URL_VALUE
                    } else {
                        IMPORT_META_DIRNAME_VALUE
                    }));
                }
                self.heap
                    .get(object_id.0 as usize)
                    .and_then(|object| object.properties.get(key))
                    .cloned()
                    .ok_or_else(|| InterpreterError::InternalError {
                        details: "import.meta object lost its captured source metadata".to_string(),
                    })
            }
            _ => {
                self.record_import_meta_contract_access(key, false);
                Err(InterpreterError::TypeError {
                    expected: "allow-listed import.meta field (url, dirname, resolve)".to_string(),
                    got: format!("import.meta.{key}"),
                })
            }
        }
    }

    pub(super) fn dispatch_hostcall_with_value_args(
        &mut self,
        cap: &str,
        arguments: DelegatedHostcallArguments,
        module: Option<&Ir3Module>,
        delegation_inputs: &Label,
    ) -> Result<Value, InterpreterError> {
        // bd-9vouw.50: a list that does not fit a register frame goes to a
        // vector-variadic builtin directly. Its element labels join the result.
        if Self::is_vector_variadic_tag(cap)
            && arguments.values.len() > self.config.max_registers as usize
        {
            let DelegatedHostcallArguments {
                values,
                labels,
                carrier_bytes,
            } = arguments;
            self.clear_pending_hostcall_result_label();
            let mut outcome = self.dispatch_vector_variadic_builtin(module, cap, values);
            if outcome.is_ok() {
                let mut label = self.take_pending_hostcall_result_label();
                let mut join_error = None;
                for element_label in &labels {
                    let next = match label.take() {
                        Some(existing) => {
                            match self
                                .join_owned_label_with_temporary_budget(existing, element_label)
                            {
                                Ok(joined) => joined,
                                Err(error) => {
                                    join_error = Some(error);
                                    break;
                                }
                            }
                        }
                        None => element_label.clone(),
                    };
                    label = Some(next);
                }
                if let Some(error) = join_error {
                    outcome = Err(error);
                } else if let Err(error) = self.replace_pending_hostcall_result_label(label) {
                    outcome = Err(error);
                }
            }
            drop(labels);
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(carrier_bytes);
            return outcome;
        }
        let count = u32::try_from(arguments.values.len()).map_err(|_| {
            InterpreterError::RegisterOutOfBounds {
                register: u32::MAX,
                max: self.config.max_registers,
            }
        });
        let count = match count {
            Ok(count)
                if count <= MAX_CALL_ARGUMENTS
                    && arguments.values.len() == arguments.labels.len() =>
            {
                count
            }
            Ok(count) if count > MAX_CALL_ARGUMENTS => {
                self.release_delegated_hostcall_arguments(arguments);
                return Err(InterpreterError::RegisterOutOfBounds {
                    register: count,
                    max: self.config.max_registers,
                });
            }
            Ok(_) => {
                self.release_delegated_hostcall_arguments(arguments);
                return Err(InterpreterError::InternalError {
                    details: "delegated hostcall value/label arity diverged".to_string(),
                });
            }
            Err(error) => {
                self.release_delegated_hostcall_arguments(arguments);
                return Err(error);
            }
        };

        // bd-9vouw.50: arguments past the register frame are staged out of
        // band; their share of the carrier charge moves with them.
        let mut arguments = arguments;
        let in_frame = count.min(self.config.max_registers);
        let overflow_depth = if count > in_frame {
            let values = arguments.values.split_off(in_frame as usize);
            let labels = arguments.labels.split_off(in_frame as usize);
            let bytes = Self::estimate_value_vec_bytes(&values)
                .saturating_add(Self::estimate_label_vec_bytes(&labels));
            arguments.carrier_bytes = arguments.carrier_bytes.saturating_sub(bytes);
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(bytes);
            self.install_argument_overflow(values, labels, bytes)
        } else {
            self.install_argument_overflow(Vec::new(), Vec::new(), 0)
        };
        let frame = match self.install_delegated_hostcall_scratch(arguments, in_frame) {
            Ok(frame) => frame,
            Err(error) => {
                self.restore_argument_overflow(overflow_depth);
                return Err(error);
            }
        };

        let delegated_args = RegRange { start: 0, count };
        let outcome = match hostcall_registry_row(cap).map(|row| row.dispatch) {
            Some(HostcallDispatchBinding::Promise) => {
                self.dispatch_promise_hostcall(cap, delegated_args, module)
            }
            Some(HostcallDispatchBinding::ModuleRequire) => {
                self.dispatch_require_hostcall(delegated_args, module)
            }
            Some(HostcallDispatchBinding::ModuleImport) => {
                self.dispatch_import_hostcall(cap, delegated_args, module)
            }
            Some(HostcallDispatchBinding::Number) => {
                self.dispatch_number_hostcall(cap, delegated_args)
            }
            Some(HostcallDispatchBinding::Console) => {
                self.dispatch_console_hostcall(cap, delegated_args, module)
            }
            Some(HostcallDispatchBinding::Timer) => {
                self.dispatch_timer_hostcall(cap, delegated_args)
            }
            Some(HostcallDispatchBinding::ProcessSpawn) => {
                self.dispatch_process_spawn_hostcall(delegated_args)
            }
            Some(HostcallDispatchBinding::Builtin) => {
                let outcome = self.dispatch_builtin_hostcall(cap, delegated_args, module);
                // The `builtin:` registry row is a family wildcard; a
                // delegated target that fell through to the unknown-member
                // arm must fail closed instead of surfacing the silent
                // `undefined` (bd-z1peg.3, acceptance criterion 5).
                if outcome.is_ok() && std::mem::take(&mut self.builtin_dispatch_hit_unknown_member)
                {
                    Err(InterpreterError::CapabilityDenied {
                        capability: recordable_capability_tag(cap).into_owned(),
                    })
                } else {
                    outcome
                }
            }
            Some(HostcallDispatchBinding::ClientRequest) => {
                self.dispatch_client_request_create(delegated_args)
            }
            Some(HostcallDispatchBinding::HostIo) => self
                .check_host_io_confidentiality(cap, delegated_args)
                .and_then(|()| {
                    if cap == crate::capability::FS_READ_PROMISE_CAPABILITY {
                        self.dispatch_fs_promise_read(delegated_args)
                    } else {
                        self.dispatch_host_io_hostcall(cap, delegated_args)
                    }
                }),
            Some(HostcallDispatchBinding::Internal) => Ok(Value::Undefined),
            Some(HostcallDispatchBinding::DeterministicNoop) => {
                if !cap.starts_with("declassify.") && !cap.starts_with("declassify:") {
                    self.check_host_io_confidentiality(cap, delegated_args)?;
                }
                Ok(Value::Undefined)
            }
            None => Err(InterpreterError::CapabilityDenied {
                capability: recordable_capability_tag(cap).into_owned(),
            }),
        };

        self.restore_delegated_hostcall_scratch(frame);
        self.restore_argument_overflow(overflow_depth);

        match outcome {
            Ok(value) => {
                self.publish_delegated_hostcall_result_label(cap, delegation_inputs)?;
                Ok(value)
            }
            Err(error) => {
                self.clear_pending_hostcall_result_label();
                Err(error)
            }
        }
    }

    /// Install the failure-atomic delegation scratch frame for one delegated
    /// hostcall (bd-z1peg.3): move the delegated values and their EXACT
    /// per-element labels into registers `base..base+count`, saving whatever
    /// occupied those slots. Every refusal path releases the argument carrier
    /// charge and leaves the register file, labels, and accounting exactly as
    /// found. The saved Value/Label storage and the installed payloads are
    /// both charged for their full physical lifetime (the delegation's
    /// physical peak), and any STALE pre-delegation pending publication is
    /// captured into the frame so the inner dispatch can neither consume it
    /// as its own result nor leak it on error.
    pub(super) fn install_delegated_hostcall_scratch(
        &mut self,
        arguments: DelegatedHostcallArguments,
        count: u32,
    ) -> Result<DelegatedHostcallScratchFrame, InterpreterError> {
        let DelegatedHostcallArguments {
            values,
            labels,
            carrier_bytes,
        } = arguments;

        let register_base = self.register_base;
        let value_count = count as usize;
        let required_len = register_base.saturating_add(value_count);
        let original_register_len = self.registers.len();
        let original_label_len = self.register_labels.len();
        let previous_register_bytes = Self::saturating_sum(
            self.registers
                .get(register_base..required_len.min(original_register_len))
                .unwrap_or(&[])
                .iter()
                .map(Self::estimate_value_bytes),
        )
        .saturating_add(Self::saturating_sum(
            self.register_labels
                .get(register_base..required_len.min(original_label_len))
                .unwrap_or(&[])
                .iter()
                .map(Self::estimate_label_bytes),
        ));
        let next_register_bytes =
            Self::saturating_sum(values.iter().map(Self::estimate_value_bytes)).saturating_add(
                Self::saturating_sum(labels.iter().map(Self::estimate_label_bytes)),
            );
        let saved_carrier_bytes = u64::try_from(value_count)
            .unwrap_or(u64::MAX)
            .saturating_mul((std::mem::size_of::<Value>() + std::mem::size_of::<Label>()) as u64)
            .saturating_add(previous_register_bytes);
        let saved_structure_bytes = u64::try_from(value_count)
            .unwrap_or(u64::MAX)
            .saturating_mul((std::mem::size_of::<Value>() + std::mem::size_of::<Label>()) as u64);
        if let Err(error) = self.check_temporary_memory_budget(saved_structure_bytes) {
            drop(values);
            drop(labels);
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(carrier_bytes);
            return Err(error);
        }
        if let Err(error) = self.apply_memory_component_delta(
            previous_register_bytes.saturating_add(carrier_bytes),
            next_register_bytes.saturating_add(saved_carrier_bytes),
        ) {
            drop(values);
            drop(labels);
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(carrier_bytes);
            return Err(error);
        }

        let mut saved_values = Vec::with_capacity(value_count);
        self.note_registers_written_to(required_len);
        self.mutate_registers(|registers| {
            if registers.len() < required_len {
                registers.resize(required_len, Value::Undefined);
            }
            for (offset, value) in values.into_iter().enumerate() {
                saved_values.push(std::mem::replace(
                    &mut registers[register_base + offset],
                    value,
                ));
            }
        });
        if self.register_labels.len() < required_len {
            self.register_labels.resize(required_len, Label::Public);
        }
        let mut saved_labels = Vec::with_capacity(value_count);
        let (mut released_label_bytes, mut added_label_bytes) = (0u64, 0u64);
        for (offset, label) in labels.into_iter().enumerate() {
            if !matches!(&label, Label::Public) {
                self.all_register_labels_public = false;
            }
            added_label_bytes =
                added_label_bytes.saturating_add(Self::estimate_label_bytes(&label));
            let previous =
                std::mem::replace(&mut self.register_labels[register_base + offset], label);
            released_label_bytes =
                released_label_bytes.saturating_add(Self::estimate_label_bytes(&previous));
            saved_labels.push(previous);
        }
        self.adjust_register_labels_bytes(released_label_bytes, added_label_bytes);

        // A pending publication surviving from BEFORE this delegation is
        // stale provenance: were it left in place, an inner dispatch that
        // publishes nothing would have it misattributed as the delegated
        // result. Capture it (uncharged by the accounted take) into the
        // frame; restore drops it.
        let stale_entry_publication = self.take_pending_hostcall_result_label();

        // bd-9vouw.72: the staged arguments occupy `register_base..+count`; a
        // guest callback the delegated builtin runs opens its window above
        // them.
        let saved_register_width = self.register_width;
        self.register_width = self.register_width.max(value_count);
        Ok(DelegatedHostcallScratchFrame {
            register_base,
            saved_register_width,
            required_len,
            original_register_len,
            original_label_len,
            saved_values,
            saved_labels,
            previous_register_bytes,
            saved_carrier_bytes,
            stale_entry_publication,
        })
    }

    /// Restore the delegation scratch frame on EVERY outcome (bd-z1peg.3).
    /// Shrink-safe: a nested dispatch that truncated or regrew the register
    /// file cannot make the restore panic or mis-measure — the current
    /// occupancy is measured over whatever actually exists, the file is
    /// re-extended before the saved slots are written back, and both vectors
    /// are truncated to their pre-delegation lengths. The saved-carrier
    /// charge is released exactly once here, and the captured stale
    /// publication is dropped without ever reaching a result path.
    pub(super) fn restore_delegated_hostcall_scratch(
        &mut self,
        frame: DelegatedHostcallScratchFrame,
    ) {
        let DelegatedHostcallScratchFrame {
            register_base,
            saved_register_width,
            required_len,
            original_register_len,
            original_label_len,
            saved_values,
            saved_labels,
            previous_register_bytes,
            saved_carrier_bytes,
            stale_entry_publication,
        } = frame;
        self.register_width = saved_register_width;
        let current_register_bytes = Self::saturating_sum(
            self.registers
                .get(register_base..required_len.min(self.registers.len()))
                .unwrap_or(&[])
                .iter()
                .map(Self::estimate_value_bytes),
        )
        .saturating_add(Self::saturating_sum(
            self.register_labels
                .get(register_base..required_len.min(self.register_labels.len()))
                .unwrap_or(&[])
                .iter()
                .map(Self::estimate_label_bytes),
        ));
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(current_register_bytes)
            .saturating_sub(saved_carrier_bytes)
            .saturating_add(previous_register_bytes);
        self.note_registers_written_to(required_len);
        self.mutate_registers(|registers| {
            if registers.len() < required_len {
                registers.resize(required_len, Value::Undefined);
            }
            for (offset, value) in saved_values.into_iter().enumerate() {
                registers[register_base + offset] = value;
            }
            // `resize`, not `truncate`: a hostile nested truncation below the
            // pre-delegation length must be rebuilt, and truncate never grows.
            registers.resize(original_register_len, Value::Undefined);
        });
        if self.register_labels.len() < required_len {
            self.register_labels.resize(required_len, Label::Public);
        }
        let (mut released_label_bytes, mut added_label_bytes) = (0u64, 0u64);
        for (offset, label) in saved_labels.into_iter().enumerate() {
            if !matches!(&label, Label::Public) {
                self.all_register_labels_public = false;
            }
            added_label_bytes =
                added_label_bytes.saturating_add(Self::estimate_label_bytes(&label));
            let previous =
                std::mem::replace(&mut self.register_labels[register_base + offset], label);
            released_label_bytes =
                released_label_bytes.saturating_add(Self::estimate_label_bytes(&previous));
        }
        if let Some(truncated) = self.register_labels.get(original_label_len..) {
            released_label_bytes = released_label_bytes.saturating_add(Self::saturating_sum(
                truncated.iter().map(Self::estimate_label_bytes),
            ));
        }
        self.register_labels
            .resize(original_label_len, Label::Public);
        self.adjust_register_labels_bytes(released_label_bytes, added_label_bytes);
        drop(stale_entry_publication);
    }

    /// Replace an inner HostCall publication with the delegated result label
    /// without ever leaving either physically live label uncharged. The old
    /// publication's retained charge stays in place while the exact winner is
    /// selected by reference; a second charge is admitted before its one
    /// required clone, then the old charge is released only after the old
    /// label is dropped.
    pub(super) fn publish_delegated_hostcall_result_label(
        &mut self,
        cap: &str,
        delegation_inputs: &Label,
    ) -> Result<(), InterpreterError> {
        let runtime_result_label = self.pending_hostcall_result_label.take();
        let runtime_label_bytes = runtime_result_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        let public = Label::Public;
        let top_secret = Label::TopSecret;
        let contract = hostcall_result_contract(cap);
        let inner_result_label = match &contract {
            HostcallResultContract::JoinInputs => runtime_result_label.as_ref().unwrap_or(&public),
            HostcallResultContract::SourceFloor(floor) => runtime_result_label
                .as_ref()
                .filter(|runtime| *runtime >= floor)
                .unwrap_or(floor),
            HostcallResultContract::RuntimeDelegated
            | HostcallResultContract::AuthenticatedRelease => {
                runtime_result_label.as_ref().unwrap_or(&top_secret)
            }
            HostcallResultContract::FailClosed => &top_secret,
        };
        let result_label = if delegation_inputs >= inner_result_label {
            delegation_inputs
        } else {
            inner_result_label
        };
        let result_label_bytes = Self::estimate_label_bytes(result_label);
        if let Err(error) = self.apply_memory_component_delta(0, result_label_bytes) {
            drop(runtime_result_label);
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(runtime_label_bytes);
            return Err(error);
        }
        let result_label = result_label.clone();
        self.pending_hostcall_result_label = Some(result_label);
        drop(runtime_result_label);
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(runtime_label_bytes);
        Ok(())
    }

    pub(super) fn dispatch_apply_hostcall(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
        authenticated_target: Option<&str>,
    ) -> Result<Value, InterpreterError> {
        self.clear_pending_hostcall_result_label();
        if args.count < 2 {
            return Err(InterpreterError::TypeError {
                expected: "target capability and argumentsList".to_string(),
                got: "missing argument".to_string(),
            });
        }
        let target_cap = match self.read_reg(args.start)? {
            Value::Str(capability) => capability.to_string(),
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "hostcall capability string".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        if target_cap == "builtin:ApplyHostCall"
            || target_cap.starts_with(APPLY_HOSTCALL_TARGET_PREFIX)
        {
            return Err(InterpreterError::TypeError {
                expected: "non-recursive hostcall capability".to_string(),
                got: target_cap,
            });
        }
        if let Some(expected_target) = authenticated_target
            && expected_target != target_cap
        {
            return Err(InterpreterError::TypeError {
                expected: format!("lowering-authenticated hostcall target {expected_target}"),
                got: target_cap,
            });
        }
        if check_hostcall_capability_gate(self, &target_cap, self.ip as u32)? {
            let recordable_target = recordable_capability_tag(capability_gate_key(&target_cap));
            self.emit_witness(
                WitnessEventKind::HostcallDispatched,
                Some(&format!("cap:{recordable_target}")),
            );
        }
        let delegation_inputs = self.join_arg_range_with_object_mutation_label(args)?;
        let delegation_input_bytes = Self::estimate_label_bytes(&delegation_inputs);
        self.apply_memory_component_delta(0, delegation_input_bytes)?;
        let arguments_list = match self.read_reg(args.start + 1) {
            Ok(arguments_list) => arguments_list,
            Err(error) => {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(delegation_input_bytes);
                return Err(error);
            }
        };
        let arguments = match self
            .prepare_delegated_hostcall_arguments_up_to(arguments_list, MAX_CALL_ARGUMENTS)
        {
            Ok(arguments) => arguments,
            Err(error) => {
                self.estimated_memory_bytes = self
                    .estimated_memory_bytes
                    .saturating_sub(delegation_input_bytes);
                return Err(error);
            }
        };
        let previous_context = self.active_inline_callback_context_label.take();
        let context_winner = previous_context
            .as_ref()
            .filter(|current| *current >= &delegation_inputs)
            .unwrap_or(&delegation_inputs);
        let next_context_bytes = Self::estimate_label_bytes(context_winner);
        if let Err(error) = self.apply_memory_component_delta(0, next_context_bytes) {
            self.active_inline_callback_context_label = previous_context;
            self.release_delegated_hostcall_arguments(arguments);
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(delegation_input_bytes);
            return Err(error);
        }
        let next_context = context_winner.clone();
        self.active_inline_callback_context_label = Some(next_context);
        let mut outcome = self.dispatch_hostcall_with_value_args(
            &target_cap,
            arguments,
            module,
            &delegation_inputs,
        );
        if matches!(outcome, Err(InterpreterError::UncaughtException { .. }))
            && let Err(error) = self.join_pending_exception_label(&delegation_inputs)
        {
            outcome = Err(error);
        }
        let current_context_bytes = self
            .active_inline_callback_context_label
            .as_ref()
            .map(Self::estimate_label_bytes)
            .unwrap_or(0);
        self.active_inline_callback_context_label = previous_context;
        self.estimated_memory_bytes = self
            .estimated_memory_bytes
            .saturating_sub(current_context_bytes)
            .saturating_sub(delegation_input_bytes);
        outcome
    }

    /// bd-tu0c3: build and ARM a JS-catchable `TypeError` carrying Node's
    /// `ERR_INVALID_ARG_TYPE` code for a path-builtin argument-validation
    /// failure, returning the `UncaughtException` the `builtin:` HostCall arm
    /// routes into the enclosing catch frame via
    /// [`Self::route_isolated_explicit_throw`] (same mechanism as an explicit
    /// user `throw` escaping a builtin mini-lane). The thrown value has the
    /// TypeError prototype (so `e instanceof TypeError` holds) plus a `code`
    /// own property, matching what the compat corpus asserts. If constructing
    /// the error object itself fails (allocation), that fault propagates
    /// unchanged.
    pub(super) fn throw_path_arg_type_error(
        &mut self,
        arg_name: &str,
        expected: &str,
        got: &Value,
    ) -> InterpreterError {
        let received = self.node_received_description(got);
        let message =
            format!("The \"{arg_name}\" argument must be of type {expected}. Received {received}");
        let thrown = match self.construct_node_invalid_arg_type_error(&message) {
            Ok(value) => value,
            Err(err) => return err,
        };
        self.pending_exception = Some(thrown.clone());
        // Engine-constructed argument-validation errors carry no data-flow
        // taint; the HostCall dispatch site re-joins the arg labels onto the
        // exception label (bd-8enww.4.8 throw-path mirror).
        self.pending_exception_label = Label::Public;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    /// bd-tu0c3: TypeError object with `code: "ERR_INVALID_ARG_TYPE"` (Node's
    /// argument-validation error shape).
    pub(super) fn construct_node_invalid_arg_type_error(
        &mut self,
        message: &str,
    ) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("TypeError")?;
        let error_id = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_like_object(error_id, "TypeError", message.to_string())?;
        self.set_object_property(
            error_id,
            "code".to_string(),
            Value::str("ERR_INVALID_ARG_TYPE"),
        )?;
        Ok(Value::Object(error_id))
    }

    /// bd-tu0c3: read ALL hostcall args as strings for a variadic path builtin
    /// (join), throwing Node's ERR_INVALID_ARG_TYPE TypeError on the first
    /// non-string (Node validates every join argument, including `undefined`).
    pub(super) fn path_string_args(
        &mut self,
        args: RegRange,
        arg_name: &str,
    ) -> Result<Vec<String>, InterpreterError> {
        let mut parts = Vec::with_capacity(args.count as usize);
        for offset in 0..args.count {
            let reg =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            let value = self.read_reg(reg)?;
            match value {
                Value::Str(s) => parts.push(s.to_string()),
                other => {
                    return Err(self.throw_path_arg_type_error(
                        &format!("{arg_name}[{offset}]"),
                        "string",
                        &other,
                    ));
                }
            }
        }
        Ok(parts)
    }

    /// bd-tu0c3: collect `path.resolve` arguments with Node's LAZY right-to-
    /// left validation: segments are validated (string-required) from the last
    /// argument backwards and collection STOPS at the first absolute segment —
    /// arguments to its left are never inspected (Node: `resolve(7, '/a')` is
    /// `'/a'`, not a TypeError). Returned in left-to-right order for
    /// [`node_path_posix_resolve`].
    pub(super) fn path_resolve_args(
        &mut self,
        args: RegRange,
    ) -> Result<Vec<String>, InterpreterError> {
        let mut collected: Vec<String> = Vec::with_capacity(args.count as usize);
        let mut offset = args.count;
        while offset > 0 {
            offset -= 1;
            let reg =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            let value = self.read_reg(reg)?;
            let Value::Str(s) = value else {
                return Err(self.throw_path_arg_type_error(
                    &format!("paths[{offset}]"),
                    "string",
                    &value,
                ));
            };
            let segment = s.to_string();
            let is_absolute = segment.starts_with('/');
            collected.push(segment);
            if is_absolute {
                break;
            }
        }
        collected.reverse();
        Ok(collected)
    }

    /// bd-tu0c3: required string argument of a path builtin at `offset`
    /// (missing arguments read as `undefined`, which fails validation exactly
    /// like Node).
    pub(super) fn path_string_arg(
        &mut self,
        args: RegRange,
        offset: u32,
        arg_name: &str,
    ) -> Result<String, InterpreterError> {
        let value = if offset < args.count {
            let reg =
                args.start
                    .checked_add(offset)
                    .ok_or(InterpreterError::RegisterOutOfBounds {
                        register: args.start,
                        max: self.config.max_registers,
                    })?;
            self.read_reg(reg)?
        } else {
            Value::Undefined
        };
        match value {
            Value::Str(s) => Ok(s.to_string()),
            other => Err(self.throw_path_arg_type_error(arg_name, "string", &other)),
        }
    }

    /// bd-tu0c3: optional string argument of a path builtin at `offset`
    /// (`basename`'s `ext`): absent or `undefined` is accepted as `None`,
    /// any other non-string throws (Node validates `ext` only when it is not
    /// `undefined`).
    pub(super) fn path_optional_string_arg(
        &mut self,
        args: RegRange,
        offset: u32,
        arg_name: &str,
    ) -> Result<Option<String>, InterpreterError> {
        if offset >= args.count {
            return Ok(None);
        }
        let reg = args
            .start
            .checked_add(offset)
            .ok_or(InterpreterError::RegisterOutOfBounds {
                register: args.start,
                max: self.config.max_registers,
            })?;
        match self.read_reg(reg)? {
            Value::Str(s) => Ok(Some(s.to_string())),
            Value::Undefined => Ok(None),
            other => Err(self.throw_path_arg_type_error(arg_name, "string", &other)),
        }
    }

    /// bd-tu0c3: read an own string-ish property of the `path.format` path
    /// object; absent/`undefined` reads as `''`, other values are coerced with
    /// the engine's standard stringification (Node coerces via template
    /// literals). Own-property only (no prototype walk), mirroring
    /// [`Self::resolve_fs_read_encoding`]'s options-bag handling.
    pub(super) fn path_format_object_property(&self, object_id: ObjectId, key: &str) -> String {
        match self
            .heap
            .get(object_id.0 as usize)
            .and_then(|object| object.properties.get(key).cloned())
        {
            None | Some(Value::Undefined) => String::new(),
            Some(Value::Str(s)) => s.to_string(),
            Some(other) => self.value_to_string(&other),
        }
    }

    /// bd-qmy52: raw hostcall argument at `offset`, `None` when absent (the
    /// querystring/os builtins have optional trailing arguments with
    /// value-sensitive defaults, so absence must be distinguishable from an
    /// explicit `undefined` only where Node distinguishes them — it never
    /// does, both mean "use the default").
    pub(super) fn builtin_optional_arg(
        &self,
        args: RegRange,
        offset: u32,
    ) -> Result<Option<Value>, InterpreterError> {
        if offset >= args.count {
            return Ok(None);
        }
        let reg = args
            .start
            .checked_add(offset)
            .ok_or(InterpreterError::RegisterOutOfBounds {
                register: args.start,
                max: self.config.max_registers,
            })?;
        Ok(Some(self.read_reg(reg)?))
    }

    /// bd-qmy52: optional custom separator argument for querystring
    /// parse/stringify. Node treats any FALSY value (`undefined`, `null`,
    /// `''`, `0`, `false`, `NaN`) as "use the default" and stringifies
    /// everything else (`String(sep)`).
    pub(super) fn qs_separator_arg(
        &self,
        args: RegRange,
        offset: u32,
        default: &str,
    ) -> Result<String, InterpreterError> {
        let value = self
            .builtin_optional_arg(args, offset)?
            .unwrap_or(Value::Undefined);
        if !value.is_truthy() {
            return Ok(default.to_string());
        }
        Ok(self.value_to_string(&value))
    }

    /// bd-qmy52: `options.maxKeys` for `querystring.parse`. Default 1000
    /// pairs; a number that is `<= 0`, `Infinity`, `NaN`, or non-integer
    /// disables the limit (Node's `--pairs === 0` countdown never reaches 0
    /// for those); a non-number `maxKeys` (or no/non-object options) keeps the
    /// default. Own-property read only, like the other options bags.
    pub(super) fn qs_max_pairs_arg(
        &self,
        args: RegRange,
        offset: u32,
    ) -> Result<Option<u64>, InterpreterError> {
        const DEFAULT_MAX_PAIRS: u64 = 1000;
        let Some(Value::Object(options_id)) = self.builtin_optional_arg(args, offset)? else {
            return Ok(Some(DEFAULT_MAX_PAIRS));
        };
        let max_keys = self
            .heap
            .get(options_id.0 as usize)
            .and_then(|object| object.properties.get("maxKeys").cloned());
        Ok(match max_keys {
            Some(Value::Int(n)) => {
                if n > 0 {
                    Some(n as u64)
                } else {
                    None
                }
            }
            Some(Value::Float(f)) => {
                let v = f.inner();
                if v.is_finite() && v > 0.0 && v.fract() == 0.0 {
                    Some(v as u64)
                } else {
                    None
                }
            }
            _ => Some(DEFAULT_MAX_PAIRS),
        })
    }

    /// bd-qmy52: Node's `stringifyPrimitive` for `querystring.stringify`
    /// values and array elements: strings pass through, finite numbers and
    /// bigints stringify, booleans map to `true`/`false`, and EVERYTHING else
    /// (undefined, null, NaN, Infinity, objects, functions) becomes `''`.
    pub(super) fn qs_stringify_primitive(&self, value: &Value) -> JsString {
        match value {
            Value::Str(s) => s.clone(),
            Value::Int(n) => JsString::from(n.to_string()),
            Value::Float(f) if f.inner().is_finite() => JsString::from(self.value_to_string(value)),
            Value::BigInt(digits) => JsString::from(digits.to_string()),
            Value::Bool(b) => JsString::from(if *b { "true" } else { "false" }),
            _ => JsString::from(""),
        }
    }

    pub(super) fn throw_querystring_invalid_uri_error(&mut self) -> InterpreterError {
        self.throw_uri_malformed(Some("ERR_INVALID_URI"))
    }

    /// Throw a guest `SyntaxError` with `message` (a runtime-detected syntax
    /// error such as an invalid `new RegExp` pattern).
    pub(super) fn throw_syntax_error(&mut self, message: String) -> InterpreterError {
        let thrown = (|| {
            let prototype = self.ensure_builtin_prototype("SyntaxError")?;
            let error_id = self.alloc_object_with_prototype(Some(prototype))?;
            self.initialize_error_like_object(error_id, "SyntaxError", message)?;
            Ok::<Value, InterpreterError>(Value::Object(error_id))
        })();
        let thrown = match thrown {
            Ok(value) => value,
            Err(error) => return error,
        };
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = Label::Public;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    /// Throw a guest `URIError: URI malformed` (ES2020 18.2.6.1.2 Decode),
    /// with Node's `code` property when `code` is given.
    pub(super) fn throw_uri_malformed(&mut self, code: Option<&str>) -> InterpreterError {
        let thrown = (|| {
            let prototype = self.ensure_builtin_prototype("URIError")?;
            let error_id = self.alloc_object_with_prototype(Some(prototype))?;
            self.initialize_error_like_object(error_id, "URIError", "URI malformed".to_string())?;
            if let Some(code) = code {
                self.set_object_property(error_id, "code".to_string(), Value::str(code))?;
            }
            Ok::<Value, InterpreterError>(Value::Object(error_id))
        })();
        let thrown = match thrown {
            Ok(value) => value,
            Err(error) => return error,
        };
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = Label::Public;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    pub(super) fn qs_escape_js_string(
        &mut self,
        input: &JsString,
    ) -> Result<String, InterpreterError> {
        let Some(input) = input.as_str() else {
            return Err(self.throw_querystring_invalid_uri_error());
        };
        Ok(node_qs_escape(input))
    }

    /// bd-qmy52: `querystring.stringify` body over a heap object: own
    /// properties in ECMAScript `Object.keys` order (canonical array indices
    /// numerically first, then other strings by creation order), array values expand to
    /// repeated `key=element` pairs (an EMPTY array contributes nothing, bun:
    /// `stringify({e: [], f: 'y'})` is `'f=y'`), other values stringify via
    /// [`Self::qs_stringify_primitive`]; keys and values escape with
    /// [`node_qs_escape`]. An array receiver's `length` property is skipped
    /// (approximates its non-enumerability).
    pub(super) fn qs_stringify_object(
        &mut self,
        object_id: ObjectId,
        sep: &str,
        eq: &str,
    ) -> Result<String, InterpreterError> {
        let entries: Vec<(JsString, Value)> = self
            .heap
            .get(object_id.0 as usize)
            .map(|object| {
                object
                    .own_runtime_property_keys()
                    .into_iter()
                    .filter_map(|key| match key {
                        RuntimePropertyKey::String(key) => Some(key),
                        RuntimePropertyKey::Symbol(_) => None,
                    })
                    .filter(|key| {
                        !(object.is_array && key.as_str() == Some("length"))
                            && self.own_runtime_property_visible(object_id, key)
                    })
                    .filter_map(|key| {
                        object
                            .own_runtime_property_value(&RuntimePropertyKey::String(key.clone()))
                            .map(|value| (key, value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut pieces: Vec<String> = Vec::new();
        for (key, value) in entries {
            let key_prefix = format!("{}{eq}", self.qs_escape_js_string(&key)?);
            if let Value::Object(id) = value
                && self
                    .heap
                    .get(id.0 as usize)
                    .is_some_and(|object| object.is_array)
            {
                for element in self.read_array_like_values(id) {
                    let component = self.qs_stringify_primitive(&element);
                    let escaped = self.qs_escape_js_string(&component)?;
                    pieces.push(format!("{key_prefix}{escaped}"));
                }
                continue;
            }
            let component = self.qs_stringify_primitive(&value);
            let escaped = self.qs_escape_js_string(&component)?;
            pieces.push(format!("{key_prefix}{escaped}"));
        }
        Ok(pieces.join(sep))
    }

    /// bd-qmy52: build and ARM a JS-catchable `RangeError` carrying Node's
    /// `ERR_OUT_OF_RANGE` code for an os-builtin range-validation failure
    /// (`os.setPriority(0, 1000)`), returning the `UncaughtException` the
    /// `builtin:` HostCall arm routes into the enclosing catch frame — the
    /// RangeError sibling of [`Self::throw_path_arg_type_error`].
    pub(super) fn throw_os_out_of_range_error(
        &mut self,
        arg_name: &str,
        must_be: &str,
        got: &Value,
    ) -> InterpreterError {
        let message = format!(
            "The value of \"{arg_name}\" is out of range. It must be {must_be}. Received {}",
            self.value_to_string(got)
        );
        let thrown = match self.construct_node_out_of_range_error(&message) {
            Ok(value) => value,
            Err(err) => return err,
        };
        self.pending_exception = Some(thrown.clone());
        self.pending_exception_label = Label::Public;
        InterpreterError::UncaughtException {
            value: self.uncaught_exception_description(&thrown),
        }
    }

    /// bd-qmy52: RangeError object with `code: "ERR_OUT_OF_RANGE"` (Node's
    /// range-validation error shape).
    pub(super) fn construct_node_out_of_range_error(
        &mut self,
        message: &str,
    ) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("RangeError")?;
        let error_id = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_like_object(error_id, "RangeError", message.to_string())?;
        self.set_object_property(error_id, "code".to_string(), Value::str("ERR_OUT_OF_RANGE"))?;
        Ok(Value::Object(error_id))
    }

    /// bd-qmy52: Node `validateInt32`-shaped check for the os builtins
    /// (`getPriority`/`setPriority` pids and priorities): a non-number throws
    /// the JS-catchable ERR_INVALID_ARG_TYPE TypeError (same shape as the path
    /// builtins' [`Self::throw_path_arg_type_error`]); a non-integer or
    /// out-of-`[lo, hi]` number throws the JS-catchable ERR_OUT_OF_RANGE
    /// RangeError.
    pub(super) fn os_validate_int32(
        &mut self,
        value: &Value,
        arg_name: &str,
        lo: i64,
        hi: i64,
    ) -> Result<i64, InterpreterError> {
        let number = match value {
            Value::Int(n) => *n as f64,
            Value::Float(f) => f.inner(),
            other => {
                return Err(self.throw_path_arg_type_error(arg_name, "number", other));
            }
        };
        if !number.is_finite() || number.fract() != 0.0 {
            return Err(self.throw_os_out_of_range_error(arg_name, "an integer", value));
        }
        let integer = number as i64;
        if integer < lo || integer > hi {
            return Err(self.throw_os_out_of_range_error(
                arg_name,
                &format!(">= {lo} && <= {hi}"),
                value,
            ));
        }
        Ok(integer)
    }

    /// bd-qmy52: allocate one flat `{ NAME: number, … }` group of the
    /// `os.constants` object.
    pub(super) fn alloc_os_constant_group(
        &mut self,
        entries: &[(&str, i64)],
    ) -> Result<Value, InterpreterError> {
        let props: Vec<(&str, Value)> = entries
            .iter()
            .map(|(name, number)| (*name, Value::Int(*number)))
            .collect();
        Ok(Value::Object(self.alloc_object_with_properties(&props)?))
    }

    /// bd-9p2v3: allocate the hermetic primary-process `cluster` facade as one
    /// atomic heap transaction. It deliberately contains no PID, IPC handle,
    /// environment, or spawn authority: workers/settings start empty, primary
    /// flags and scheduling constants are deterministic, and fork/Worker are
    /// function-shaped fail-closed sentinels.
    pub(super) fn construct_cluster_facade(&mut self) -> Result<Value, InterpreterError> {
        if let Some(facade) = self.cluster_facades.keys().next().copied() {
            return Ok(Value::Object(facade));
        }

        // Materialize the seed-tracked prototype before the facade transaction.
        // A later rollback may truncate only objects allocated after this point,
        // so builtin_prototypes can never retain a dangling ObjectId.
        let event_emitter_prototype = self.ensure_builtin_prototype("EventEmitter")?;
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;
        let result = (|| {
            let workers = self.alloc_object_with_properties(&[])?;
            let settings = self.alloc_object_with_properties(&[])?;
            let facade = self.alloc_object_with_prototype(Some(event_emitter_prototype))?;
            let bound = |kind| {
                let mut builtin = BuiltinFunction::new_kind(kind);
                builtin.bound_object = Some(facade.0);
                Value::BuiltinFunction(builtin)
            };
            self.set_object_brand(facade, "Cluster")?;
            for (key, value) in [
                ("__maxListeners", Value::Int(10)),
                ("isPrimary", Value::Bool(true)),
                ("isMaster", Value::Bool(true)),
                ("isWorker", Value::Bool(false)),
                ("workers", Value::Object(workers)),
                ("settings", Value::Object(settings)),
                ("schedulingPolicy", Value::Int(2)),
                ("SCHED_RR", Value::Int(2)),
                ("SCHED_NONE", Value::Int(1)),
                ("Worker", bound(BuiltinFunctionKind::ClusterWorker)),
                ("fork", bound(BuiltinFunctionKind::ClusterFork)),
                ("setupPrimary", bound(BuiltinFunctionKind::ClusterSetup)),
                ("setupMaster", bound(BuiltinFunctionKind::ClusterSetup)),
                ("disconnect", bound(BuiltinFunctionKind::ClusterDisconnect)),
            ] {
                self.set_object_property(facade, key.to_string(), value)?;
            }
            let state = ClusterRuntimeState {
                settings,
                lifecycle_label: Label::Public,
            };
            self.apply_memory_component_delta(
                0,
                Self::estimate_cluster_runtime_state_bytes(&state),
            )?;
            self.cluster_facades.insert(facade, state);
            Ok(Value::Object(facade))
        })();
        if result.is_err() {
            self.cluster_facades.clear();
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        }
        result
    }

    pub(super) fn cluster_receiver_id(
        &self,
        receiver: Option<Value>,
        bound_object: Option<u32>,
        method: &str,
    ) -> Result<ObjectId, InterpreterError> {
        let receiver = receiver.unwrap_or(Value::Undefined);
        let Value::Object(object_id) = receiver else {
            return Err(InterpreterError::TypeError {
                expected: format!("cluster receiver for cluster.{method}"),
                got: receiver.type_name().to_string(),
            });
        };
        if bound_object != Some(object_id.0) {
            return Err(InterpreterError::TypeError {
                expected: format!("bound cluster receiver for cluster.{method}"),
                got: "detached or forged receiver".to_string(),
            });
        }
        let authenticated = self.cluster_facades.contains_key(&object_id)
            && self
                .heap
                .get(object_id.0 as usize)
                .is_some_and(|object| object.brand() == Some("Cluster"));
        if !authenticated {
            return Err(InterpreterError::TypeError {
                expected: format!("authenticated cluster receiver for cluster.{method}"),
                got: "unbranded object".to_string(),
            });
        }
        Ok(object_id)
    }

    pub(super) fn charge_cluster_work(&mut self, work: usize) -> Result<(), InterpreterError> {
        let work = u64::try_from(work).unwrap_or(u64::MAX);
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

    /// Replace `cluster.settings` with one newly allocated shallow merge.
    /// Existing keys survive, supplied arrays/objects retain identity, and the
    /// old settings object remains untouched until the new object is complete.
    /// Every property visited costs one instruction in addition to a fixed
    /// authentication/publication charge; heap publication and GC remembered-
    /// set changes roll back together on any memory refusal.
    pub(super) fn cluster_setup(
        &mut self,
        receiver: Option<Value>,
        bound_object: Option<u32>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let cluster_id = self.cluster_receiver_id(receiver, bound_object, "setupPrimary")?;
        let Some(options) = self.builtin_arg(args, 0)? else {
            return Ok(Value::Undefined);
        };
        if matches!(options, Value::Undefined) {
            return Ok(Value::Undefined);
        }
        let Value::Object(options_id) = options else {
            return Err(InterpreterError::TypeError {
                expected: "cluster setup options object".to_string(),
                got: options.type_name().to_string(),
            });
        };
        let settings_id = self
            .cluster_facades
            .get(&cluster_id)
            .map(|state| state.settings)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "authenticated cluster settings object".to_string(),
                got: "missing cluster runtime state".to_string(),
            })?;
        if !matches!(
            self.heap
                .get(cluster_id.0 as usize)
                .and_then(|cluster| cluster.properties.get("settings")),
            Some(Value::Object(mirrored_id)) if *mirrored_id == settings_id
        ) {
            return Err(InterpreterError::TypeError {
                expected: "authenticated cluster settings object".to_string(),
                got: "forged settings mirror".to_string(),
            });
        }
        let option_property_count = self
            .heap
            .get(options_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: options_id.0 })?
            .properties
            .len();
        let existing_property_count = self
            .heap
            .get(settings_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: settings_id.0 })?
            .properties
            .len();
        self.charge_cluster_work(
            CLUSTER_SETUP_FIXED_WORK
                .saturating_add(existing_property_count)
                .saturating_add(option_property_count),
        )?;

        let setup_label = self.writable_invocation_label(args)?;
        let next_lifecycle_label = self.join_owned_label_with_temporary_budget(
            setup_label,
            &self.cluster_facades[&cluster_id].lifecycle_label,
        )?;
        let previous_state_bytes =
            Self::estimate_cluster_runtime_state_bytes(&self.cluster_facades[&cluster_id]);
        let next_state_bytes = previous_state_bytes
            .saturating_sub(Self::estimate_label_bytes(
                &self.cluster_facades[&cluster_id].lifecycle_label,
            ))
            .saturating_add(Self::estimate_label_bytes(&next_lifecycle_label));

        let options_bytes = self
            .heap
            .get(options_id.0 as usize)
            .map(Self::estimate_heap_object_bytes)
            .unwrap_or(u64::MAX);
        let settings_bytes = self
            .heap
            .get(settings_id.0 as usize)
            .map(Self::estimate_heap_object_bytes)
            .unwrap_or(u64::MAX);
        // The two property Vec clones remain physically live while the
        // replacement object is allocated and populated. Conservatively reserve
        // a second clone-sized envelope for that unpublished merged object;
        // per-property retained-memory checks alone cannot see the live Vecs.
        let clone_and_replacement_peak = options_bytes
            .saturating_add(settings_bytes)
            .saturating_mul(2)
            .saturating_add(Self::estimate_label_bytes(&next_lifecycle_label));
        self.check_temporary_memory_budget(clone_and_replacement_peak)?;

        let existing: Vec<(String, Value)> = self
            .heap
            .get(settings_id.0 as usize)
            .expect("settings object was authenticated")
            .properties
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let updates: Vec<(String, Value)> = self
            .heap
            .get(options_id.0 as usize)
            .expect("options object was validated")
            .properties
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let previous_heap_len = self.heap.len();
        let previous_estimated_bytes = self.estimated_memory_bytes;

        let merge_result = (|| -> Result<ObjectId, InterpreterError> {
            let replacement = self.alloc_object_with_properties(&[])?;
            for (key, value) in existing {
                self.set_object_property(replacement, key, value)?;
            }
            for (key, value) in updates {
                self.set_object_property(replacement, key, value)?;
            }
            self.apply_memory_component_delta(previous_state_bytes, next_state_bytes)?;
            self.set_object_property(
                cluster_id,
                "settings".to_string(),
                Value::Object(replacement),
            )?;
            Ok(replacement)
        })();
        let replacement = match merge_result {
            Ok(replacement) => replacement,
            Err(error) => {
                self.rollback_heap_to_len(previous_heap_len);
                self.estimated_memory_bytes = previous_estimated_bytes;
                return Err(error);
            }
        };
        let state = self
            .cluster_facades
            .get_mut(&cluster_id)
            .expect("cluster receiver was authenticated");
        state.settings = replacement;
        state.lifecycle_label = next_lifecycle_label;
        Ok(Value::Undefined)
    }

    #[inline(never)]
    pub(super) fn dispatch_builtin_hostcall_inner(
        &mut self,
        cap: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        if let Some(name) = builtin_prototype_capability_name(cap) {
            if args.count != 0 {
                return Err(InterpreterError::TypeError {
                    expected: "zero builtin prototype hostcall arguments".to_string(),
                    got: format!("{} argument(s)", args.count),
                });
            }
            return self.builtin_prototype_value(name);
        }

        // bd-9vouw.17: declared factory for a static builtin read as a value.
        if let Some(inner) =
            cap.strip_prefix(crate::lowering_pipeline::STATIC_VALUE_CAPABILITY_PREFIX)
        {
            if args.count != 0 {
                return Err(InterpreterError::TypeError {
                    expected: "zero static-value factory arguments".to_string(),
                    got: format!("{} argument(s)", args.count),
                });
            }
            if cap == crate::lowering_pipeline::JSON_VALUE_CAPABILITY {
                return self.load_runtime_name("JSON", false);
            }
            let tag = canonical_static_hostcall_tag(inner).ok_or_else(|| {
                InterpreterError::TypeError {
                    expected: "known static builtin".to_string(),
                    got: inner.to_string(),
                }
            })?;
            return Ok(Value::BuiltinFunction(BuiltinFunction::static_hostcall(
                tag,
            )));
        }

        if let Some(name) = builtin_instanceof_capability_name(cap) {
            if args.count != 1 {
                return Err(InterpreterError::TypeError {
                    expected: "one builtin instanceof hostcall argument".to_string(),
                    got: format!("{} argument(s)", args.count),
                });
            }
            let candidate = self.read_reg(args.start)?;
            if !candidate.is_object_like() {
                return Ok(Value::Bool(false));
            }
            let prototype = self.ensure_builtin_prototype(name)?;
            return Ok(Value::Bool(self.value_prototype_chain_contains(
                module,
                &candidate,
                &Value::Object(prototype),
            )?));
        }

        match cap {
            "builtin:ToPropertyKey" => {
                if args.count != 1 {
                    return Err(InterpreterError::TypeError {
                        expected: "one ToPropertyKey argument".to_string(),
                        got: format!("{} arguments", args.count),
                    });
                }
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::PropertyKey)
            }
            "builtin:SloppyThis" => {
                // bd-9vouw.118: ES2020 9.2.1.2 OrdinaryCallBindThis for
                // non-strict code. With one argument, the converted value of
                // a `this` read (arrow functions, top-level code); with none,
                // a function prologue converting its frame's `this` in place,
                // so every later read and arrow closure sees one object.
                match args.count {
                    1 => {
                        let value = self.read_reg(args.start)?;
                        self.sloppy_this_value(value)
                    }
                    0 => {
                        let Some(frame) = self.call_stack.last() else {
                            return Ok(Value::Undefined);
                        };
                        let current = frame.this_value.clone();
                        let bound = self.sloppy_this_value(current.clone())?;
                        if bound != current {
                            // The frame's `this` is part of the running
                            // memory estimate: a boxed string replaces its
                            // primitive's bytes.
                            self.apply_memory_component_delta(
                                Self::estimate_value_bytes(&current),
                                Self::estimate_value_bytes(&bound),
                            )?;
                            if let Some(frame) = self.call_stack.last_mut() {
                                frame.this_value = bound.clone();
                            }
                        }
                        Ok(bound)
                    }
                    count => Err(InterpreterError::TypeError {
                        expected: "zero or one sloppy-this hostcall argument".to_string(),
                        got: format!("{count} arguments"),
                    }),
                }
            }
            "builtin:StrictDeleteResult" => {
                // bd-9vouw.136: ES2020 12.5.3.2 step 5.d. A strict-mode
                // delete whose [[Delete]] answered false (a non-configurable
                // property, a frozen object, a Proxy trap returning false)
                // is a TypeError; otherwise it evaluates to true.
                if args.count != 1 {
                    return Err(InterpreterError::TypeError {
                        expected: "one strict-delete result argument".to_string(),
                        got: format!("{} arguments", args.count),
                    });
                }
                match self.read_reg(args.start)? {
                    Value::Bool(false) => Err(InterpreterError::TypeError {
                        expected: "a deletable property in strict mode code".to_string(),
                        got: "a property that cannot be deleted".to_string(),
                    }),
                    _ => Ok(Value::Bool(true)),
                }
            }
            "builtin:ArgumentsObject" => {
                // bd-9vouw.25: the object staged by call setup for this frame.
                // A body entered without staging (a generator resumed by
                // `next()`) sees an empty arguments object.
                match self.pending_arguments_object.take() {
                    Some((depth, value, label)) if depth == self.call_stack.len() => {
                        self.replace_pending_hostcall_result_label(Some(label))?;
                        Ok(value)
                    }
                    _ => Ok(Value::Object(
                        self.alloc_arguments_object(&[], ArgumentsCallee::Omitted)?,
                    )),
                }
            }
            "builtin:MapArgument" => self.map_argument_to_parameter(args),
            "builtin:ClassPrototypeLink" => {
                // ES2020 14.6.13 ClassDefinitionEvaluation: a derived class's
                // prototype object inherits from the superclass prototype.
                // args = (prototype, parent prototype). This is class
                // machinery, so unlike a guest `o.__proto__ = p` it runs no
                // property hook (bd-9vouw.60); the IFC mutation label joins
                // exactly as that store would.
                let prototype = self.arg_or_undefined(args, 0)?;
                let parent = self.arg_or_undefined(args, 1)?;
                // A function is an object too: `class extends Function` links
                // to the callable %Function.prototype% (bd-9vouw.346) through
                // its property storage, as Object.setPrototypeOf(o, F) does
                // (bd-9vouw.98).
                let callable_link = if parent.is_callable() {
                    self.prototype_link_for_value(module, &parent)?
                } else {
                    None
                };
                let link = match parent {
                    Value::Object(parent_id) => Some(Some(parent_id)),
                    Value::Null => Some(None),
                    _ if callable_link.is_some() => callable_link,
                    // Step 6.g.ii: a superclass whose `prototype` is neither an
                    // object nor null is a TypeError (bd-9vouw.205).
                    _ if matches!(prototype, Value::Object(_)) => {
                        let received = self.node_received_description(&parent);
                        return Err(self.throw_js_error(
                            "TypeError",
                            format!(
                                "Class extends value does not have valid prototype property {received}"
                            ),
                        ));
                    }
                    _ => None,
                };
                if let (Value::Object(prototype_id), Some(link)) = (prototype, link) {
                    let label = self
                        .get_register_label(args.start)?
                        .join(self.get_register_label(args.start + 1)?);
                    self.join_object_mutation_label(prototype_id, &label)?;
                    self.store_prototype_link(prototype_id, link);
                }
                Ok(Value::Undefined)
            }
            "builtin:PrivateNameCreate" => {
                // ES2022 15.7.14 step 7: a new Private Name per class
                // evaluation, described by its source spelling `#x`.
                let description = match self.arg_or_undefined(args, 0)? {
                    Value::Str(description)
                        if description
                            .as_str()
                            .is_some_and(|name| name.starts_with('#')) =>
                    {
                        description
                    }
                    other => {
                        return Err(InterpreterError::TypeError {
                            expected: "private name description `#name`".to_string(),
                            got: other.type_name().to_string(),
                        });
                    }
                };
                self.allocate_class_private_name_symbol(description)
                    .map(Value::Symbol)
            }
            "builtin:ClassDefineField" | "builtin:ClassInitStaticFields" => {
                // ES2022 class elements. ClassDefineField(target, key,
                // function, kind) records a field, private method or
                // accessor half, or static block on the class prototype
                // (instance) or on the constructor (static);
                // ClassInitStaticFields(class) then installs the static ones
                // on the class once its methods exist.
                let module = module.ok_or_else(|| InterpreterError::InternalError {
                    details: format!("{cap} needs the executing module"),
                })?;
                let target = self.arg_or_undefined(args, 0)?;
                let target_id = match &target {
                    Value::Object(object_id) => Some(*object_id),
                    function => self.ensure_function_own_property_object(module, function)?,
                };
                let Some(target_id) = target_id else {
                    return Err(InterpreterError::TypeError {
                        expected: "class prototype or constructor".to_string(),
                        got: target.type_name().to_string(),
                    });
                };
                if cap == "builtin:ClassDefineField" {
                    let key = self.arg_or_undefined(args, 1)?;
                    let initializer = self.arg_or_undefined(args, 2)?;
                    let kind = match self.arg_or_undefined(args, 3)? {
                        Value::Int(kind @ 0..=5) => kind,
                        other => {
                            return Err(InterpreterError::TypeError {
                                expected: "class element kind 0..=5".to_string(),
                                got: format!("{other:?}"),
                            });
                        }
                    };
                    // A static field whose computed key is "prototype" would
                    // redefine the class's non-configurable `prototype`
                    // (DefineField is CreateDataPropertyOrThrow): a
                    // TypeError, raised as Node raises it, when the field is
                    // defined, before any initializer runs.
                    if target.is_callable()
                        && matches!(
                            kind,
                            crate::lowering_pipeline::CLASS_ELEMENT_FIELD
                                | crate::lowering_pipeline::CLASS_ELEMENT_NAMED_FIELD
                        )
                        && self.executable_property_key_from_value(&key).as_str()
                            == Some("prototype")
                    {
                        return Err(InterpreterError::TypeError {
                            expected: "a static class field not named prototype".to_string(),
                            got: "Classes may not have a static property named 'prototype'"
                                .to_string(),
                        });
                    }
                    let label = self
                        .get_register_label(args.start)?
                        .join(self.get_register_label(args.start + 1)?)
                        .join(self.get_register_label(args.start + 2)?);
                    self.record_class_field(target_id, kind, key, initializer, label)?;
                } else if let Some(fields) = self
                    .heap
                    .get(target_id.0 as usize)
                    .and_then(|object| object.class_fields.as_deref().cloned())
                {
                    // The list stays reachable from its slot while the
                    // initializers run, then is released.
                    self.run_class_field_initializers(module, target, target_id, &fields)?;
                    self.set_class_fields_slot(target_id, None)?;
                }
                Ok(Value::Undefined)
            }
            "builtin:ObjectLiteralPrototype" => {
                // Annex B.3.1: an object literal's `__proto__: v` entry sets
                // the literal's prototype when `v` is an object or null and
                // is ignored otherwise. args = (object, value); the object is
                // returned so a literal built entry by entry keeps it on the
                // stack (bd-9vouw.23). The IFC mutation label joins as a
                // prototype store would.
                let object = self.arg_or_undefined(args, 0)?;
                let value = self.arg_or_undefined(args, 1)?;
                // A function links to its own-property backing (bd-9vouw.98).
                let link = self.prototype_link_for_value(module, &value)?;
                if let (Value::Object(object_id), Some(link)) = (&object, link) {
                    let label = self
                        .get_register_label(args.start)?
                        .join(self.get_register_label(args.start + 1)?);
                    self.join_object_mutation_label(*object_id, &label)?;
                    self.store_prototype_link(*object_id, link);
                }
                Ok(object)
            }
            "builtin:ObjectLiteralNamedEntry" => {
                // An object literal entry `[key]: <anonymous function
                // definition>` (ES2020 12.2.6.8; bd-9vouw.237): args = (key,
                // value), the key already ToPropertyKey'd. The fresh function
                // is named by the key, and the one-entry object is returned
                // for the literal to spread in; it carries both labels as its
                // mutation label.
                let key_value = self.arg_or_undefined(args, 0)?;
                let value = self.arg_or_undefined(args, 1)?;
                let key = self.executable_property_key_from_value(&key_value);
                if let Some(module) = module {
                    self.name_anonymous_function_value(module, &value, &key)?;
                }
                let entry = self.alloc_object_with_prototype(None)?;
                let label = self
                    .get_register_label(args.start)?
                    .join(self.get_register_label(args.start + 1)?);
                self.join_object_mutation_label(entry, &label)?;
                self.set_object_runtime_property(entry, key, value)?;
                Ok(Value::Object(entry))
            }
            // The `with` statement rewrite (lowering_pipeline/with_statement.rs).
            "builtin:WithObject" => match self.arg_or_undefined(args, 0)? {
                // ES2020 13.11.7 step 2: ToObject of the expression.
                Value::Undefined | Value::Null => Err(InterpreterError::TypeError {
                    expected: "object for a with statement".to_string(),
                    got: "undefined or null".to_string(),
                }),
                primitive @ (Value::Bool(_)
                | Value::Int(_)
                | Value::Float(_)
                | Value::Str(_)
                | Value::BigInt(_)
                | Value::Symbol(_)) => Ok(Value::Object(self.alloc_primitive_wrapper(primitive)?)),
                object => Ok(object),
            },
            "builtin:WithHas" => {
                // args = (object, name).
                let object = self.arg_or_undefined(args, 0)?;
                let name = self.arg_or_undefined(args, 1)?;
                Ok(Value::Bool(self.with_has_binding(module, &object, &name)?))
            }
            "builtin:WithBase" => {
                // args = (object, fallback, name): the object when it has a
                // binding for the name, else the fallback.
                let object = self.arg_or_undefined(args, 0)?;
                let name = self.arg_or_undefined(args, 2)?;
                if self.with_has_binding(module, &object, &name)? {
                    Ok(object)
                } else {
                    self.arg_or_undefined(args, 1)
                }
            }
            // A call whose callee no `with` object supplied has no receiver.
            "builtin:WithReceiver" => Ok(Value::Undefined),
            // `require('util')` (lowering_pipeline/util_module.rs).
            "builtin:UtilInspect" => self.util_inspect_builtin(module, args),
            "builtin:UtilFormat" => self.util_format_builtin(module, args),
            "builtin:UtilTypeTag" => {
                let value = self.arg_or_undefined(args, 0)?;
                Ok(Value::str(self.util_type_tag(&value)?))
            }
            crate::capability::UTIL_PROCESS_ARGV_CAPABILITY
            | crate::capability::UTIL_PROCESS_EXEC_ARGV_CAPABILITY => {
                // The shared capability gate checked process_shape_read_allowed
                // before recording this read. Use the engine-owned realm
                // object, never a source binding or the host's ambient argv.
                let process =
                    self.process_global_object
                        .ok_or_else(|| InterpreterError::InternalError {
                            details: "native util argv read has no runtime process object"
                                .to_string(),
                        })?;
                let observation = self.begin_property_observation([])?;
                let outcome = (|| {
                    let field = if cap == crate::capability::UTIL_PROCESS_ARGV_CAPABILITY {
                        "argv"
                    } else {
                        "execArgv"
                    };
                    let key = RuntimePropertyKey::String(field.into());
                    if let Some(module) = module {
                        self.run_pre_runtime_property_access_hook(module, process, &key)?;
                    }
                    self.proxy_aware_get_runtime_property(
                        module,
                        process,
                        &key,
                        Value::Object(process),
                        0,
                    )
                })();
                self.finish_property_read_observation(observation, outcome)
            }
            "builtin:ClassMembersNonEnumerable" => {
                // ES2020 14.6.13: class methods and accessors are
                // non-enumerable and the constructor's prototype is readonly.
                // args = (constructor, constructor.prototype).
                let constructor = self.arg_or_undefined(args, 0)?;
                let prototype = self.arg_or_undefined(args, 1)?;
                let mut targets = Vec::with_capacity(2);
                if let Value::Object(prototype_id) = prototype {
                    targets.push(prototype_id);
                }
                if let Some(module) = module
                    && let Some(backing) =
                        self.own_property_holder(Some(module), &constructor, true)?
                {
                    self.set_own_property_attributes(
                        backing,
                        &RuntimePropertyKey::String(JsString::from("prototype")),
                        PropertyAttributes {
                            writable: false,
                            enumerable: false,
                            configurable: false,
                        },
                    )?;
                    targets.push(backing);
                }
                for target in targets {
                    let keys = self
                        .heap
                        .get(target.0 as usize)
                        .ok_or(InterpreterError::ObjectNotFound { id: target.0 })?
                        .own_runtime_property_keys();
                    for key in keys {
                        let object = &self.heap[target.0 as usize];
                        let mut attributes = object
                            .property_attributes
                            .get(&key)
                            .copied()
                            .unwrap_or_default();
                        attributes.enumerable = false;
                        self.set_own_property_attributes(target, &key, attributes)?;
                    }
                }
                Ok(Value::Undefined)
            }
            "builtin:RequireObjectCoercible" => {
                if args.count != 1 {
                    return Err(InterpreterError::TypeError {
                        expected: "one RequireObjectCoercible argument".to_string(),
                        got: format!("{} arguments", args.count),
                    });
                }
                Self::require_object_coercible(self.read_reg(args.start)?)
            }
            "builtin:ObjectRest" => {
                if args.count == 0 {
                    return Err(InterpreterError::TypeError {
                        expected: "object rest source argument".to_string(),
                        got: "no arguments".to_string(),
                    });
                }
                let source = Self::require_object_coercible(self.read_reg(args.start)?)?;
                let label = self.join_arg_range_with_object_mutation_label(args)?;
                let mut exclusion_bytes = 0u64;
                for offset in 1..args.count {
                    let register = args.start.checked_add(offset).ok_or(
                        InterpreterError::RegisterOutOfBounds {
                            register: args.start,
                            max: self.config.max_registers,
                        },
                    )?;
                    exclusion_bytes = exclusion_bytes
                        .saturating_add(MEMORY_ESTIMATE_MAP_ENTRY_BYTES)
                        .saturating_add(Self::estimate_value_bytes(&self.read_reg(register)?));
                }
                self.check_temporary_memory_budget(exclusion_bytes)?;
                let mut excluded = BTreeSet::new();
                for offset in 1..args.count {
                    let register = args.start.checked_add(offset).ok_or(
                        InterpreterError::RegisterOutOfBounds {
                            register: args.start,
                            max: self.config.max_registers,
                        },
                    )?;
                    let value = self.read_reg(register)?;
                    if !matches!(value, Value::Str(_) | Value::Symbol(_)) {
                        return Err(InterpreterError::TypeError {
                            expected: "canonical object-rest property key".to_string(),
                            got: value.type_name().to_string(),
                        });
                    }
                    let key = self.executable_property_key_from_value(&value);
                    self.validate_executable_property_key(&key)?;
                    excluded.insert(key);
                }
                self.apply_memory_component_delta(0, exclusion_bytes)?;
                let result = (|| {
                    let target = self.alloc_object_with_prototype(None)?;
                    self.join_object_mutation_label(target, &label)?;
                    self.copy_data_properties(module, target, source, &excluded, false)?;
                    let label = label.join(
                        self.pending_hostcall_result_label
                            .as_ref()
                            .unwrap_or(&Label::Public),
                    );
                    self.join_object_mutation_label(target, &label)?;
                    self.replace_pending_hostcall_result_label(Some(label))?;
                    Ok(Value::Object(target))
                })();
                drop(excluded);
                self.estimated_memory_bytes =
                    self.estimated_memory_bytes.saturating_sub(exclusion_bytes);
                result
            }
            "builtin:String" => {
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::String)
            }
            "builtin:Url" => self.construct_url(args),
            "builtin:UrlSearchParams" => self.construct_url_search_params(module, args),
            "builtin:UrlFileUrlToPath" => self.legacy_url_file_url_to_path(args),
            "builtin:UrlFormat" => self.legacy_url_format(args),
            "builtin:UrlParse" => self.legacy_url_parse(args),
            "builtin:ClusterFacade" => {
                if args.count != 0 {
                    return Err(InterpreterError::TypeError {
                        expected: "zero cluster facade hostcall arguments".to_string(),
                        got: format!("{} argument(s)", args.count),
                    });
                }
                let facade = self.construct_cluster_facade()?;
                if let Value::Object(object_id) = facade {
                    let lifecycle_label = self.cluster_state_label(object_id);
                    if lifecycle_label != Label::Public {
                        self.replace_pending_hostcall_result_label(Some(lifecycle_label))?;
                    }
                    Ok(Value::Object(object_id))
                } else {
                    unreachable!("cluster facade constructor returned a non-object")
                }
            }
            "builtin:EventEmitterConstructorRef" => {
                if args.count != 0 {
                    return Err(InterpreterError::TypeError {
                        expected: "zero EventEmitter constructor-reference arguments".to_string(),
                        got: format!("{} argument(s)", args.count),
                    });
                }
                Ok(Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::EventEmitterConstructor,
                )))
            }
            "builtin:EventEmitter" => {
                // bd-2dmnn / bd-dspwz: callable and constructible EventEmitter
                // references share one canonical prototype. The private method
                // table still resolves through `__type`; prototype membership
                // is identity semantics, never an authority decision.
                let prototype = self.ensure_builtin_prototype("EventEmitter")?;
                let previous_heap_len = self.heap.len();
                let previous_estimated_bytes = self.estimated_memory_bytes;
                let result = (|| {
                    let object_id = self.alloc_object_with_prototype(Some(prototype))?;
                    self.set_object_brand(object_id, "EventEmitter")?;
                    self.set_object_property(
                        object_id,
                        "__maxListeners".to_string(),
                        Value::Int(10),
                    )?;
                    Ok(Value::Object(object_id))
                })();
                if result.is_err() {
                    self.rollback_heap_to_len(previous_heap_len);
                    self.estimated_memory_bytes = previous_estimated_bytes;
                }
                result
            }
            "builtin:ZlibConstants" => {
                if args.count != 0 {
                    return Err(InterpreterError::TypeError {
                        expected: "zero zlib.constants hostcall arguments".to_string(),
                        got: format!("{} argument(s)", args.count),
                    });
                }
                self.zlib_constants()
            }
            "builtin:NetIsIP" | "builtin:NetIsIPv4" | "builtin:NetIsIPv6" => {
                let candidate = self
                    .builtin_arg(args, 0)?
                    .map(|value| self.value_to_string(&value))
                    .unwrap_or_default();
                let parsed = candidate.parse::<std::net::IpAddr>().ok();
                match cap {
                    "builtin:NetIsIP" => Ok(Value::Int(match parsed {
                        Some(std::net::IpAddr::V4(_)) => 4,
                        Some(std::net::IpAddr::V6(_)) => 6,
                        None => 0,
                    })),
                    "builtin:NetIsIPv4" => {
                        Ok(Value::Bool(matches!(parsed, Some(std::net::IpAddr::V4(_)))))
                    }
                    "builtin:NetIsIPv6" => {
                        Ok(Value::Bool(matches!(parsed, Some(std::net::IpAddr::V6(_)))))
                    }
                    _ => unreachable!("matched net IP classifier"),
                }
            }
            "builtin:NetCreateServer" => self.construct_loopback_server(args),
            "builtin:NetConnect" | "builtin:NetCreateConnection" => {
                self.connect_loopback_socket(args)
            }
            "builtin:ZlibGzipSync" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibGunzipSync" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibDeflateSync" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibInflateSync" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibDeflateRawSync" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibInflateRawSync" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibUnzipSync" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibBrotliCompressSync" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibBrotliDecompressSync" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibGzip" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibGunzip" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibDeflate" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:ZlibInflate" => self.dispatch_zlib_hostcall(cap, args),
            "builtin:CryptoCreateHash" => self.crypto_create_hash(args),
            "builtin:CryptoCreateHmac" => self.crypto_create_hmac(args),
            "builtin:CryptoTimingSafeEqual" => self.crypto_timing_safe_equal(args),
            "builtin:CryptoPbkdf2Sync" => self.crypto_pbkdf2(args, false),
            "builtin:CryptoPbkdf2" => self.crypto_pbkdf2(args, true),
            "builtin:CryptoScryptSync" => self.crypto_scrypt_sync(args),
            "builtin:CryptoCreateCipheriv" => {
                self.crypto_create_cipher(args, CryptoCipherDirection::Encrypt)
            }
            "builtin:CryptoCreateDecipheriv" => {
                self.crypto_create_cipher(args, CryptoCipherDirection::Decrypt)
            }
            "builtin:CryptoGetHashes" => self.crypto_get_hashes(),
            "builtin:CryptoGetCiphers" => self.crypto_get_ciphers(),
            "builtin:CryptoConstants" => self.crypto_constants(args),
            "builtin:CryptoInvalidRandomInt" => self.crypto_invalid_random_int(args),
            "builtin:CryptoRandomBytes" => self.crypto_random_bytes(args),
            "builtin:CryptoRandomUUID" => self.crypto_random_uuid(args),
            "builtin:CryptoRandomInt" => self.crypto_random_int(args),
            "builtin:CryptoRandomFillSync" => self.crypto_random_fill_sync(args),
            "builtin:CryptoGenerateKeyPairSync" => self.crypto_generate_key_pair_sync(args),
            "builtin:CryptoSign" => self.crypto_sign_sync(args),
            "builtin:CryptoVerify" => self.crypto_verify_sync(args),
            "builtin:CryptoObjectUpdate"
            | "builtin:CryptoObjectDigest"
            | "builtin:CryptoObjectCopy"
            | "builtin:CryptoObjectFinal"
            | "builtin:CryptoObjectGetAuthTag"
            | "builtin:CryptoObjectSetAuthTag" => self.crypto_object_hostcall(cap, args),
            "builtin:HttpCreateServer" => self.construct_http_server(args),
            "builtin:HttpGet" => self.construct_http_client_request(args, true),
            "builtin:HttpRequest" => self.construct_http_client_request(args, false),
            "builtin:HttpsGet" => self.construct_http_client_request_for_protocol(args, true, true),
            "builtin:HttpsRequest" => {
                self.construct_http_client_request_for_protocol(args, false, true)
            }
            "builtin:HttpStatusCodes" => self.http_status_codes(),
            "builtin:HttpMethods" => self.http_methods(),
            "builtin:HttpAgent" => self.construct_http_agent(args),
            "builtin:HttpsAgent" => self.construct_http_agent_for_protocol(args, true),
            "builtin:NetSocket" => {
                let lifecycle_label = self.writable_invocation_label(args)?;
                let socket = self.construct_loopback_socket(false, None, lifecycle_label)?;
                self.set_object_property(socket, "connecting".to_string(), Value::Bool(false))?;
                Ok(Value::Object(socket))
            }
            "builtin:NetSocketInstanceOf" => self.net_socket_instanceof(args),
            "builtin:TlsRootCertificates" => self.tls_root_certificates(),
            "builtin:TlsGetCiphers" => self.tls_get_ciphers(),
            "builtin:TlsCreateSecureContext" => self.tls_create_secure_context(),
            "builtin:TlsCheckServerIdentity" => self.tls_check_server_identity(args),
            "builtin:TlsCreateServer" => self.construct_tls_server(args),
            "builtin:TlsConnect" => self.connect_tls_socket(args),
            "builtin:EventsOnce" => {
                // bd-asw4m.1: static `events.once(emitter, event)` is pure
                // runtime bookkeeping. It creates a pending Promise plus linked
                // event/error waiter records; no module or host authority is
                // materialized by this dispatch.
                self.register_event_promise_once(args)
            }
            "builtin:EventsAddAbortListener" => self.register_protected_abort_listener(args),
            "builtin:StreamReadableFrom" => {
                // bd-fw7zd: statically proven `Readable.from(...)` is an
                // engine-contained finite stream. No module object or host
                // authority is materialized by this dispatch.
                self.construct_readable_from(args)
            }
            "builtin:StreamReadable" => {
                // bd-fw7zd: statically proven `new Readable(options)` exposes
                // deterministic state and explicit push(null) termination.
                self.construct_stream_readable(args)
            }
            "builtin:StreamWritable" => {
                // bd-fw7zd: engine-owned Writable state drives deterministic
                // write/final callbacks and terminal lifecycle checkpoints.
                self.construct_stream_writable(args)
            }
            "builtin:StreamPassThrough" => {
                // bd-fw7zd.10: one engine-owned object composes the existing
                // Readable and Writable kernels without materializing a module.
                self.construct_stream_passthrough(args)
            }
            "builtin:StreamTransform" => self.construct_stream_transform(args),
            "builtin:StreamPipeline" => {
                let module = module.ok_or_else(|| InterpreterError::TypeError {
                    expected: "module-backed stream.pipeline".to_string(),
                    got: "missing module context".to_string(),
                })?;
                self.construct_stream_pipeline(module, args, false)
            }
            "builtin:StreamPromisesPipeline" => {
                let module = module.ok_or_else(|| InterpreterError::TypeError {
                    expected: "module-backed stream/promises.pipeline".to_string(),
                    got: "missing module context".to_string(),
                })?;
                self.construct_stream_pipeline(module, args, true)
            }
            "builtin:ImportMeta" => {
                if args.count != 0 {
                    return Err(InterpreterError::TypeError {
                        expected: "zero import.meta hostcall arguments".to_string(),
                        got: format!("{} argument(s)", args.count),
                    });
                }
                self.alloc_import_meta_object()
            }
            crate::lowering_pipeline::MODULE_EXPORT_STAR_HOSTCALL => self.module_export_star(args),
            // bd-j8f7q: declares the unit's import contract; the contract is
            // enforced at each import edge (load_module_resolved).
            crate::lowering_pipeline::IFC_BOUNDED_IMPORTS_CONTRACT => Ok(Value::Undefined),
            "builtin:ApplyHostCall" => self.dispatch_apply_hostcall(args, module, None),
            capability if capability.starts_with(APPLY_HOSTCALL_TARGET_PREFIX) => self
                .dispatch_apply_hostcall(
                    args,
                    module,
                    capability.strip_prefix(APPLY_HOSTCALL_TARGET_PREFIX),
                ),
            // Array methods
            "builtin:ArrayPrototypePush" => {
                // Array.prototype.push implementation - adds elements to end of array and returns new length

                // Get the 'this' value (should be an array object)
                // In a proper implementation, 'this' would be passed separately,
                // but for now we'll work with what we have
                if args.count == 0 {
                    return Ok(Value::Int(0)); // No elements to push, assume empty array
                }

                // For now, create a simple array-like object and add the elements
                // This is a simplified implementation that creates a new array
                let array_id = self.alloc_array_with_prototype(None)?;

                // Collect all arguments first
                let mut elements = Vec::new();
                for i in 0..args.count {
                    let element = self.read_reg(args.start + i)?;
                    elements.push((i.to_string(), element));
                }
                let count = args.count;
                let array_index = array_id.0 as usize;

                // Incremental memory accounting (bd-s8u37): the array was just
                // allocated empty (alloc accounts only the base object), so
                // every element entry plus the length entry is net-new.
                let added_bytes = elements
                    .iter()
                    .map(|(index_str, element)| {
                        Self::estimate_property_entry_bytes(index_str, element)
                    })
                    .sum::<u64>()
                    .saturating_add(Self::estimate_property_entry_bytes(
                        "length",
                        &Value::Int(count as i64),
                    ));
                self.apply_memory_component_delta(0, added_bytes)?;

                // Add each argument as an array element and set length property
                self.mutate_heap(|heap| {
                    if let Some(obj) = heap.get_mut(array_index) {
                        for (index_str, element) in elements {
                            obj.properties.insert(index_str, element);
                        }
                        obj.properties
                            .insert("length".to_string(), Value::Int(count as i64));
                    }
                });

                // Return the new length
                Ok(Value::Int(args.count as i64))
            }
            "builtin:ArrayIsArray" => {
                let arg = self.builtin_arg(args, 0)?;
                self.array_is_array_value(arg)
            }
            "builtin:ArrayIsArrayFunction" => {
                Ok(Value::BuiltinFunction(BuiltinFunction::array_is_array()))
            }
            "builtin:ArrayPrototypePop" => {
                // Array.prototype.pop implementation - removes and returns last element from array

                // For this simplified implementation, we'll assume we're working with
                // an empty array and return undefined (as would happen with [].pop())
                // A complete implementation would need access to the 'this' array object
                // to remove the last element and update the length property

                // Simulate popping from an empty array
                Ok(Value::Undefined)
            }
            "builtin:ArrayPrototypeShift" => {
                // Array.prototype.shift implementation - removes and returns first element from array

                // For this simplified implementation, we'll assume we're working with
                // an empty array and return undefined (as would happen with [].shift())
                // A complete implementation would need access to the 'this' array object
                // to remove the first element, shift remaining elements, and update length

                // Simulate shifting from an empty array
                Ok(Value::Undefined)
            }
            "builtin:ArrayPrototypeUnshift" => {
                // Array.prototype.unshift implementation - adds elements to beginning of array and returns new length

                // For this simplified implementation, we'll create a new array with the unshift elements
                // A complete implementation would need access to the 'this' array object
                // to prepend elements and shift existing elements to the right

                // Create array object to hold the unshifted elements
                let array_id = self.alloc_array_with_prototype(None)?;

                // Add each argument as an array element at the beginning
                for i in 0..args.count {
                    let element = self.read_reg(args.start + i)?;
                    self.set_object_property(array_id, i.to_string(), element)?;
                }

                // Set length property
                self.set_object_property(
                    array_id,
                    "length".to_string(),
                    Value::Int(args.count as i64),
                )?;

                // Return the new length (JavaScript behavior: unshift returns new length, not the array)
                Ok(Value::Int(args.count as i64))
            }
            "builtin:ArrayOf" => {
                // Array.of implementation - creates new Array instance from arguments

                // Create array object to hold the arguments
                let array_id = self.alloc_array_with_prototype(None)?;

                // Add each argument as an array element
                for i in 0..args.count {
                    let element = self.read_reg(args.start + i)?;
                    self.set_object_property(array_id, i.to_string(), element)?;
                }

                // Set length property
                self.set_object_property(
                    array_id,
                    "length".to_string(),
                    Value::Int(args.count as i64),
                )?;

                // Return the new array object
                Ok(Value::Object(array_id))
            }
            "builtin:ArrayFrom" => self.array_from_builtin(module, args),

            "builtin:ArrayPrototypeJoin" => {
                // Array.prototype.join implementation - joins array elements into string
                if args.count == 0 {
                    return Ok(Value::str(""));
                }

                // Get the array object (first argument should be the array)
                let array_arg = self.read_reg(args.start)?;

                // Get the separator (default to comma)
                let separator = if args.count > 1 {
                    let sep_arg = self.read_reg(args.start + 1)?;
                    match sep_arg {
                        Value::Str(s) => s.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => ",".to_string(), // Default separator
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => ",".to_string(),
                    }
                } else {
                    ",".to_string() // Default separator
                };

                match array_arg {
                    Value::Object(obj_id) => {
                        // Get array length and elements
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(length_val) = obj.properties.get("length") {
                                if let Value::Int(len) = length_val {
                                    let length = *len as usize;
                                    let mut elements = Vec::new();

                                    // Collect array elements
                                    for i in 0..length {
                                        let element = obj
                                            .properties
                                            .get(&i.to_string())
                                            .cloned()
                                            .unwrap_or(Value::Undefined);

                                        // Convert element to string
                                        let str_val = match element {
                                            Value::Str(s) => s.to_string(),
                                            Value::Int(n) => n.to_string(),
                                            Value::Float(f) => f.to_string(),
                                            Value::Bool(b) => b.to_string(),
                                            Value::Null => "null".to_string(),
                                            Value::Undefined => "".to_string(), // undefined becomes empty string in join
                                            _ => "[object Object]".to_string(),
                                        };
                                        elements.push(str_val);
                                    }

                                    // Join elements with separator
                                    let result = elements.join(&separator);
                                    Ok(Value::str(result))
                                } else {
                                    // Invalid length, return empty string
                                    Ok(Value::str(""))
                                }
                            } else {
                                // No length property, return empty string
                                Ok(Value::str(""))
                            }
                        } else {
                            // Object not found, return empty string
                            Ok(Value::str(""))
                        }
                    }
                    _ => {
                        // Non-object argument, return empty string
                        Ok(Value::str(""))
                    }
                }
            }
            "builtin:ArrayPrototypeIncludes" => {
                // Array.prototype.includes implementation - checks if array contains a value
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                // Get the array object (first argument should be the array)
                let array_arg = self.read_reg(args.start)?;

                // Get the search element
                let search_element = if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };

                match array_arg {
                    Value::Object(obj_id) => {
                        // Get array length and search through elements
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(length_val) = obj.properties.get("length") {
                                if let Value::Int(len) = length_val {
                                    let length = *len as usize;

                                    // Search through array elements
                                    for i in 0..length {
                                        let element = obj
                                            .properties
                                            .get(&i.to_string())
                                            .cloned()
                                            .unwrap_or(Value::Undefined);

                                        // JavaScript === comparison (strict equality)
                                        let matches = match (&search_element, &element) {
                                            (Value::Int(a), Value::Int(b)) => a == b,
                                            (Value::Float(a), Value::Float(b)) => {
                                                let a_val = a.inner();
                                                let b_val = b.inner();
                                                // Handle NaN case: NaN === NaN is false in JS, but includes should find NaN
                                                if a_val.is_nan() && b_val.is_nan() {
                                                    true
                                                } else {
                                                    a_val == b_val
                                                }
                                            }
                                            (Value::Str(a), Value::Str(b)) => a == b,
                                            (Value::Bool(a), Value::Bool(b)) => a == b,
                                            (Value::Null, Value::Null) => true,
                                            (Value::Undefined, Value::Undefined) => true,
                                            (Value::Symbol(a), Value::Symbol(b)) => a == b,
                                            (Value::Object(a), Value::Object(b)) => a == b,
                                            _ => false, // Different types don't match in strict equality
                                        };

                                        if matches {
                                            return Ok(Value::Bool(true));
                                        }
                                    }

                                    // Not found
                                    Ok(Value::Bool(false))
                                } else {
                                    // Invalid length, return false
                                    Ok(Value::Bool(false))
                                }
                            } else {
                                // No length property, return false
                                Ok(Value::Bool(false))
                            }
                        } else {
                            // Object not found, return false
                            Ok(Value::Bool(false))
                        }
                    }
                    _ => {
                        // Non-object argument, return false
                        Ok(Value::Bool(false))
                    }
                }
            }
            "builtin:ArrayPrototypeIndexOf" => {
                // Array.prototype.indexOf implementation - finds first index of element in array
                if args.count == 0 {
                    return Ok(Value::Int(-1));
                }

                // Get the array object (first argument should be the array)
                let array_arg = self.read_reg(args.start)?;

                // Get the search element
                let search_element = if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };

                // Get optional start index (default to 0)
                let start_index = if args.count > 2 {
                    let start_arg = self.read_reg(args.start + 2)?;
                    match start_arg {
                        Value::Int(n) => n.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                match array_arg {
                    Value::Object(obj_id) => {
                        // Get array length and search through elements
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if let Some(length_val) = obj.properties.get("length") {
                                if let Value::Int(len) = length_val {
                                    let length = *len as usize;

                                    // Search through array elements starting from start_index
                                    for i in start_index..length {
                                        let element = obj
                                            .properties
                                            .get(&i.to_string())
                                            .cloned()
                                            .unwrap_or(Value::Undefined);

                                        // JavaScript === comparison (strict equality)
                                        let matches = match (&search_element, &element) {
                                            (Value::Int(a), Value::Int(b)) => a == b,
                                            (Value::Float(a), Value::Float(b)) => {
                                                let a_val = a.inner();
                                                let b_val = b.inner();
                                                // NaN !== NaN in indexOf (different from includes)
                                                if a_val.is_nan() || b_val.is_nan() {
                                                    false
                                                } else {
                                                    a_val == b_val
                                                }
                                            }
                                            (Value::Str(a), Value::Str(b)) => a == b,
                                            (Value::Bool(a), Value::Bool(b)) => a == b,
                                            (Value::Null, Value::Null) => true,
                                            (Value::Undefined, Value::Undefined) => true,
                                            (Value::Symbol(a), Value::Symbol(b)) => a == b,
                                            (Value::Object(a), Value::Object(b)) => a == b,
                                            _ => false, // Different types don't match in strict equality
                                        };

                                        if matches {
                                            return Ok(Value::Int(i as i64));
                                        }
                                    }

                                    // Not found
                                    Ok(Value::Int(-1))
                                } else {
                                    // Invalid length, return -1
                                    Ok(Value::Int(-1))
                                }
                            } else {
                                // No length property, return -1
                                Ok(Value::Int(-1))
                            }
                        } else {
                            // Object not found, return -1
                            Ok(Value::Int(-1))
                        }
                    }
                    _ => {
                        // Non-object argument, return -1
                        Ok(Value::Int(-1))
                    }
                }
            }
            "builtin:ArrayPrototypeSlice" => {
                // Array.prototype.slice implementation - returns shallow copy of portion of array
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                // Get the array object (first argument should be the array)
                let array_arg = self.read_reg(args.start)?;

                match array_arg {
                    Value::Object(obj_id) => {
                        // Snapshot length + relevant properties under an
                        // immutable borrow so we can release it before the
                        // &mut self calls below.
                        let array_snapshot: Option<i64> = self
                            .heap
                            .get(obj_id.0 as usize)
                            .and_then(|o| o.properties.get("length"))
                            .and_then(|v| match v {
                                Value::Int(n) => Some(*n),
                                _ => None,
                            });

                        if let Some(length) = array_snapshot {
                            // Get start index (default to 0)
                            let start_idx = if args.count > 1 {
                                let start_arg = self.read_reg(args.start + 1)?;
                                match start_arg {
                                    Value::Int(n) => {
                                        if n < 0 {
                                            (length + n).max(0) as usize
                                        } else {
                                            n.min(length) as usize
                                        }
                                    }
                                    Value::Float(f) => {
                                        let val = f.inner();
                                        if val < 0.0 {
                                            ((length as f64) + val).max(0.0) as usize
                                        } else {
                                            val.min(length as f64) as usize
                                        }
                                    }
                                    _ => 0,
                                }
                            } else {
                                0
                            };

                            // Get end index (default to array length)
                            let end_idx = if args.count > 2 {
                                let end_arg = self.read_reg(args.start + 2)?;
                                match end_arg {
                                    Value::Int(n) => {
                                        if n < 0 {
                                            (length + n).max(0) as usize
                                        } else {
                                            n.min(length) as usize
                                        }
                                    }
                                    Value::Float(f) => {
                                        let val = f.inner();
                                        if val < 0.0 {
                                            ((length as f64) + val).max(0.0) as usize
                                        } else {
                                            val.min(length as f64) as usize
                                        }
                                    }
                                    _ => length as usize,
                                }
                            } else {
                                length as usize
                            };

                            // Snapshot the slice elements under a fresh
                            // immutable borrow.
                            let slice_elements: Vec<Value> = if start_idx < end_idx {
                                if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                                    (start_idx..end_idx)
                                        .map(|i| {
                                            obj.properties
                                                .get(&i.to_string())
                                                .cloned()
                                                .unwrap_or(Value::Undefined)
                                        })
                                        .collect()
                                } else {
                                    Vec::new()
                                }
                            } else {
                                Vec::new()
                            };

                            let new_array_id = self.alloc_array_from_values(&slice_elements)?;

                            Ok(Value::Object(new_array_id))
                        } else {
                            // Invalid length, no length property, or object
                            // missing — return empty array.
                            let empty_array_id = self.alloc_array_from_values(&[])?;
                            Ok(Value::Object(empty_array_id))
                        }
                    }
                    _ => {
                        // Non-object argument, return empty array
                        let empty_array_id = self.alloc_array_from_values(&[])?;
                        Ok(Value::Object(empty_array_id))
                    }
                }
            }

            // Object methods
            "builtin:ObjectKeys" => {
                // Object.keys implementation - returns array of object's own property names
                // ES2020 19.1.2: ToObject(O) throws for undefined and null
                // (a missing argument is undefined).
                let obj_val = if args.count == 0 {
                    Value::Undefined
                } else {
                    self.read_reg(args.start)?
                };
                match obj_val {
                    Value::Undefined | Value::Null => Err(InterpreterError::TypeError {
                        expected: "object-coercible argument for Object.keys".to_string(),
                        got: obj_val.type_name().to_string(),
                    }),
                    Value::Object(obj_id) if self.active_proxy_record(obj_id)?.is_some() => {
                        // bd-9trje: a Proxy receiver must surface keys through the
                        // ownKeys trap and per-key getOwnPropertyDescriptor trap.
                        let key_values = self
                            .proxy_own_enumerable_string_keys(module, obj_id)?
                            .into_iter()
                            .map(Value::Str)
                            .collect::<Vec<_>>();
                        let array_id = self.alloc_array_from_values(&key_values)?;
                        Ok(Value::Object(array_id))
                    }
                    Value::Object(obj_id) => {
                        let mut key_values = self
                            .indexed_own_entries(obj_id)?
                            .into_iter()
                            .map(|(key, _)| Value::Str(key))
                            .collect::<Vec<_>>();
                        key_values.extend(
                            self.heap
                                .get(obj_id.0 as usize)
                                .ok_or(InterpreterError::ObjectNotFound { id: obj_id.0 })?
                                .properties
                                .exact_keys()
                                .into_iter()
                                .filter(|key| {
                                    self.ordinary_own_string_key_is_enumerable(obj_id, key)
                                })
                                .map(Value::Str),
                        );
                        self.join_pending_hostcall_stream_label(obj_id)?;
                        let array_id = self.alloc_array_from_values(&key_values)?;
                        Ok(Value::Object(array_id))
                    }
                    // bd-9vouw.17: a function's enumerable own properties are
                    // on its backing object (`length`/`name` are not enumerable),
                    // as are a promise's or generator object's.
                    ref function
                        if function.is_callable() || Self::has_exotic_backing_object(function) =>
                    {
                        let key_values = match self.own_property_holder(module, function, false)? {
                            Some(backing) if self.active_proxy_record(backing)?.is_some() => self
                                .proxy_own_enumerable_string_keys(module, backing)?
                                .into_iter()
                                .map(Value::Str)
                                .collect::<Vec<_>>(),
                            Some(backing) => self
                                .heap
                                .get(backing.0 as usize)
                                .ok_or(InterpreterError::ObjectNotFound { id: backing.0 })?
                                .properties
                                .exact_keys()
                                .into_iter()
                                .filter(|key| {
                                    self.ordinary_own_string_key_is_enumerable(backing, key)
                                })
                                .map(Value::Str)
                                .collect::<Vec<_>>(),
                            None => Vec::new(),
                        };
                        let array_id = self.alloc_array_from_values(&key_values)?;
                        Ok(Value::Object(array_id))
                    }
                    Value::Str(text) => {
                        let key_values = self
                            .string_index_entries(&text)?
                            .into_iter()
                            .map(|(key, _)| Value::Str(key))
                            .collect::<Vec<_>>();
                        let array_id = self.alloc_array_from_values(&key_values)?;
                        Ok(Value::Object(array_id))
                    }
                    _ => {
                        // Non-object argument - return empty array per JavaScript behavior
                        let array_id = self.alloc_array_from_values(&[])?;
                        Ok(Value::Object(array_id))
                    }
                }
            }
            "builtin:ObjectValues" => {
                // Object.values implementation - returns array of object's own property values
                // ES2020 19.1.2: ToObject(O) throws for undefined and null
                // (a missing argument is undefined).
                let obj_val = if args.count == 0 {
                    Value::Undefined
                } else {
                    self.read_reg(args.start)?
                };
                match obj_val {
                    Value::Undefined | Value::Null => Err(InterpreterError::TypeError {
                        expected: "object-coercible argument for Object.values".to_string(),
                        got: obj_val.type_name().to_string(),
                    }),
                    Value::Object(obj_id) if self.active_proxy_record(obj_id)?.is_some() => {
                        // bd-9trje: read each enumerable Proxy key's value through
                        // the get trap, in ownKeys-trap order, right after its
                        // descriptor (bd-9vouw.347).
                        let values = self
                            .proxy_enumerable_own_entries(module, obj_id, &Value::Object(obj_id))?
                            .into_iter()
                            .map(|(_, value)| value)
                            .collect::<Vec<_>>();
                        let array_id = self.alloc_array_from_values(&values)?;
                        Ok(Value::Object(array_id))
                    }
                    Value::Object(obj_id) => {
                        let mut values = self
                            .indexed_own_entries(obj_id)?
                            .into_iter()
                            .map(|(_, value)| value)
                            .collect::<Vec<_>>();
                        for (_, value) in self.enumerable_own_property_entries(module, obj_id)? {
                            values.push(value);
                        }
                        let array_id = self.alloc_array_from_values(&values)?;
                        Ok(Value::Object(array_id))
                    }
                    Value::Str(text) => {
                        let values = self
                            .string_index_entries(&text)?
                            .into_iter()
                            .map(|(_, value)| value)
                            .collect::<Vec<_>>();
                        let array_id = self.alloc_array_from_values(&values)?;
                        Ok(Value::Object(array_id))
                    }
                    ref holder
                        if Self::stores_own_properties_on_backing(holder)
                            || Self::is_callable_proxy(holder) =>
                    {
                        let values = self
                            .backing_enumerable_own_entries(module, holder)?
                            .into_iter()
                            .map(|(_, value)| value)
                            .collect::<Vec<_>>();
                        let array_id = self.alloc_array_from_values(&values)?;
                        Ok(Value::Object(array_id))
                    }
                    _ => {
                        // Non-object argument - return empty array per JavaScript behavior
                        let array_id = self.alloc_array_from_values(&[])?;
                        Ok(Value::Object(array_id))
                    }
                }
            }
            "builtin:ObjectEntries" => {
                // Object.entries implementation - returns array of [key, value] pairs
                // ES2020 19.1.2: ToObject(O) throws for undefined and null
                // (a missing argument is undefined).
                let obj_val = if args.count == 0 {
                    Value::Undefined
                } else {
                    self.read_reg(args.start)?
                };
                match obj_val {
                    Value::Undefined | Value::Null => Err(InterpreterError::TypeError {
                        expected: "object-coercible argument for Object.entries".to_string(),
                        got: obj_val.type_name().to_string(),
                    }),
                    Value::Object(obj_id) if self.active_proxy_record(obj_id)?.is_some() => {
                        // bd-9trje: [key, value] pairs for each enumerable Proxy key,
                        // key order from the ownKeys trap, each value from the get
                        // trap right after its descriptor (bd-9vouw.347).
                        let entries = self.proxy_enumerable_own_entries(
                            module,
                            obj_id,
                            &Value::Object(obj_id),
                        )?;
                        let mut entry_values = Vec::with_capacity(entries.len());
                        for (key, value) in entries {
                            let entry_array_id =
                                self.alloc_array_from_values(&[Value::Str(key), value])?;
                            entry_values.push(Value::Object(entry_array_id));
                        }
                        let array_id = self.alloc_array_from_values(&entry_values)?;
                        Ok(Value::Object(array_id))
                    }
                    ref value @ (Value::Object(_) | Value::Str(_)) => {
                        let (obj_id, mut entries) = match value {
                            Value::Str(text) => (None, self.string_index_entries(text)?),
                            Value::Object(obj_id) => {
                                (Some(*obj_id), self.indexed_own_entries(*obj_id)?)
                            }
                            _ => unreachable!("matched an object or a string"),
                        };
                        if let Some(obj_id) = obj_id {
                            let own = self.enumerable_own_property_entries(module, obj_id)?;
                            entries.extend(own);
                        }
                        let mut entry_values = Vec::with_capacity(entries.len());

                        // Set array elements as numeric properties, each containing a [key, value] pair
                        for (key, value) in entries {
                            let entry_array_id =
                                self.alloc_array_from_values(&[Value::Str(key), value])?;
                            entry_values.push(Value::Object(entry_array_id));
                        }
                        let array_id = self.alloc_array_from_values(&entry_values)?;
                        Ok(Value::Object(array_id))
                    }
                    ref holder
                        if Self::stores_own_properties_on_backing(holder)
                            || Self::is_callable_proxy(holder) =>
                    {
                        let entries = self.backing_enumerable_own_entries(module, holder)?;
                        let mut entry_values = Vec::with_capacity(entries.len());
                        for (key, value) in entries {
                            let entry_array_id =
                                self.alloc_array_from_values(&[Value::Str(key), value])?;
                            entry_values.push(Value::Object(entry_array_id));
                        }
                        let array_id = self.alloc_array_from_values(&entry_values)?;
                        Ok(Value::Object(array_id))
                    }
                    _ => {
                        // Non-object argument - return empty array per JavaScript behavior
                        let array_id = self.alloc_array_from_values(&[])?;
                        Ok(Value::Object(array_id))
                    }
                }
            }
            "builtin:ObjectFromEntries" => {
                // A missing iterable is undefined, which is not iterable.
                let source = if args.count == 0 {
                    Value::Undefined
                } else {
                    self.read_reg(args.start)?
                };
                self.object_from_entries_value(module, source)
            }
            // ES2022 20.1.2.13 Object.hasOwn(O, P): HasOwnProperty of
            // ToObject(O); `null` and `undefined` are a TypeError.
            "builtin:ObjectHasOwn" => {
                let object = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                if matches!(object, Value::Undefined | Value::Null) {
                    return Err(InterpreterError::TypeError {
                        expected: "object for Object.hasOwn".to_string(),
                        got: object.type_name().to_string(),
                    });
                }
                // Then ToPropertyKey(P) (bd-9vouw.279).
                let property = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let property = self.coerce_to_property_key(module, property)?;
                let own = self.value_has_own_property(module, &object, &property)?;
                Ok(Value::Bool(own))
            }
            "builtin:ObjectGroupBy" | "builtin:MapGroupBy" => {
                self.group_by_builtin(module, args, cap == "builtin:MapGroupBy")
            }
            "builtin:ArrayBufferIsView" => {
                // ES2020 24.1.3.1: true for a typed array (and so a Buffer)
                // or a DataView, false for anything else.
                let value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                Ok(Value::Bool(matches!(
                    value,
                    Value::Object(object_id)
                        if self.heap.get(object_id.0 as usize).is_some_and(|object| {
                            object.typed_array.is_some() || object.data_view.is_some()
                        })
                )))
            }
            "builtin:ObjectAssign" => {
                // Object.assign implementation - copies properties from source objects to target
                // ES2020 19.1.2.1: ToObject(target) throws for undefined and
                // null (a missing target is undefined).
                let target_val = if args.count == 0 {
                    Value::Undefined
                } else {
                    self.read_reg(args.start)?
                };
                let target_obj_id = match &target_val {
                    Value::Object(obj_id) => *obj_id,
                    Value::Undefined | Value::Null => {
                        return Err(InterpreterError::TypeError {
                            expected: "object-coercible target for Object.assign".to_string(),
                            got: target_val.type_name().to_string(),
                        });
                    }
                    // A function's own properties live on its backing object,
                    // where `f.x = 1` stores them: `Object.assign(fn, {...})`
                    // (chroma's statics) copied nothing.
                    // Promises and generator objects keep theirs on a
                    // backing object too (`Object.assign(promise, { a: 1 })`).
                    function
                        if function.is_callable() || Self::has_exotic_backing_object(function) =>
                    {
                        let backing = match module {
                            Some(module) => {
                                self.ensure_function_own_property_object(module, function)?
                            }
                            None => None,
                        };
                        let Some(backing) = backing else {
                            return Ok(target_val);
                        };
                        backing
                    }
                    // ToObject(target): a primitive target is boxed, the
                    // sources copy onto the wrapper, which is the result
                    // (`Object.assign('a', [1])` throws: the String
                    // wrapper's index 0 is not writable). It returned the
                    // primitive untouched.
                    primitive @ (Value::Bool(_)
                    | Value::Int(_)
                    | Value::Float(_)
                    | Value::Str(_)
                    | Value::BigInt(_)
                    | Value::Symbol(_)) => self.alloc_primitive_wrapper(primitive.clone())?,
                    _ => {
                        // Any other exotic value without property storage
                        // is returned as-is.
                        return Ok(target_val);
                    }
                };
                let target_val = match target_val {
                    Value::Bool(_)
                    | Value::Int(_)
                    | Value::Float(_)
                    | Value::Str(_)
                    | Value::BigInt(_)
                    | Value::Symbol(_) => Value::Object(target_obj_id),
                    other => other,
                };

                // Copy properties from each source object to target
                for i in 1..args.count {
                    let source_val = self.read_reg(args.start + i)?;
                    // ToObject of a string source has its code units as own
                    // enumerable index properties (ES2020 9.4.3), copied with
                    // Set(to, key, value, true); they were skipped
                    // (`Object.assign({}, 'ab')` gave {}).
                    if let Value::Str(text) = &source_val {
                        for (key, value) in self.string_index_entries(text)? {
                            // [[Set]] grows an array target's length
                            // (`Object.assign([], 'hi')`).
                            let committed = self.proxy_aware_set_runtime_property(
                                module,
                                target_obj_id,
                                &RuntimePropertyKey::String(key.clone()),
                                value,
                                Value::Object(target_obj_id),
                                0,
                            )?;
                            if !committed {
                                return Err(InterpreterError::TypeError {
                                    expected: "writable target property for Object.assign"
                                        .to_string(),
                                    got: format!("Cannot assign to read only property '{key}'"),
                                });
                            }
                        }
                        continue;
                    }
                    let source_obj_id = match &source_val {
                        Value::Object(source_obj_id) => Some(*source_obj_id),
                        // A function source's own enumerable properties, and
                        // a promise's, generator's or iterator's.
                        holder
                            if holder.is_callable() || Self::has_exotic_backing_object(holder) =>
                        {
                            self.own_property_holder(module, holder, false)?
                        }
                        // Skip non-object sources (null, undefined, primitives)
                        _ => None,
                    };
                    if let Some(source_obj_id) = source_obj_id {
                        self.join_pending_hostcall_stream_label(source_obj_id)?;
                        self.copy_data_properties(
                            module,
                            target_obj_id,
                            source_val,
                            &BTreeSet::new(),
                            true,
                        )?;
                    }
                }
                let mutation_label = self.join_arg_range_with_object_mutation_label(args)?;
                self.join_object_mutation_label(target_obj_id, &mutation_label)?;

                // Return the target (the function itself for a function).
                Ok(target_val)
            }
            "builtin:TemplateObject" => {
                // ES2020 12.2.9.3 GetTemplateObject (bd-9vouw.343): a tagged
                // template's `%TemplateObject(site, [cooked...], [raw...])`.
                // The first evaluation of a call site freezes the raw array,
                // makes it the cooked array's non-writable, non-enumerable,
                // non-configurable `raw`, freezes the cooked array and keeps
                // it; every later evaluation of the site answers that object.
                // A site is keyed by its module's content hash (else its label)
                // and its parse ordinal.
                let site = match self.builtin_arg(args, 0)? {
                    Some(Value::Str(site)) => site.to_string(),
                    other => {
                        return Err(InterpreterError::TypeError {
                            expected: "template call-site key".to_string(),
                            got: other
                                .map_or("undefined", |value| value.type_name())
                                .to_string(),
                        });
                    }
                };
                // A dispatch without a module (host-driven, never a lowered
                // tagged template) has no site to key, so it is not cached.
                let key = module.map(|module| {
                    let module_key = module
                        .header
                        .source_hash
                        .as_ref()
                        .map_or_else(|| module.header.source_label.clone(), |hash| hash.to_hex());
                    (module_key, site)
                });
                if let Some(cached) = key.as_ref().and_then(|key| self.template_objects.get(key)) {
                    return Ok(Value::Object(*cached));
                }
                let (Some(Value::Object(cooked)), Some(Value::Object(raw))) =
                    (self.builtin_arg(args, 1)?, self.builtin_arg(args, 2)?)
                else {
                    return Err(InterpreterError::TypeError {
                        expected: "template strings arrays".to_string(),
                        got: "non-array arguments".to_string(),
                    });
                };
                self.mutate_heap(|heap| {
                    if let Some(object) = heap.get_mut(raw.0 as usize) {
                        object.is_frozen = true;
                    }
                });
                self.set_object_property(cooked, "raw".to_string(), Value::Object(raw))?;
                self.set_own_property_attributes(
                    cooked,
                    &RuntimePropertyKey::String(JsString::from("raw")),
                    PropertyAttributes {
                        writable: false,
                        enumerable: false,
                        configurable: false,
                    },
                )?;
                self.mutate_heap(|heap| {
                    if let Some(object) = heap.get_mut(cooked.0 as usize) {
                        object.is_frozen = true;
                    }
                });
                if let Some(key) = key {
                    self.template_objects.insert(key, cooked);
                }
                Ok(Value::Object(cooked))
            }
            "builtin:ObjectFreeze" => {
                // Object.freeze implementation - makes an object immutable
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                // A Proxy freezes through its traps (ES2020 7.3.14).
                if let Some(proxy) = self.integrity_proxy_id(&obj_val)? {
                    if !self.proxy_set_integrity_level(module, proxy, true)? {
                        return Err(InterpreterError::TypeError {
                            expected: "successful preventExtensions".to_string(),
                            got: "falsy Proxy trap result".to_string(),
                        });
                    }
                    return Ok(obj_val);
                }
                match obj_val {
                    Value::Object(obj_id) => {
                        if self.is_module_namespace(obj_id) {
                            if self.heap[obj_id.0 as usize].properties.exact_len() > 0 {
                                return Err(InterpreterError::TypeError {
                                    expected: "an object Object.freeze can freeze".to_string(),
                                    got: "module namespace exports cannot become non-writable"
                                        .to_string(),
                                });
                            }
                            // An empty namespace has only the already frozen
                            // @@toStringTag property. Do not freeze its private
                            // binding carrier while a module cycle is evaluating.
                            return Ok(Value::Object(obj_id));
                        }
                        // ES2020 9.4.5.3: a typed array's elements cannot be
                        // made non-writable, so freezing one with elements is
                        // a TypeError (V8: "Cannot freeze array buffer views
                        // with elements"), not a frozen object whose bytes
                        // still change (bd-9vouw.251).
                        if self
                            .heap
                            .get(obj_id.0 as usize)
                            .and_then(|object| object.typed_array.as_deref())
                            .is_some_and(|view| view.length > 0)
                        {
                            return Err(InterpreterError::TypeError {
                                expected: "an object Object.freeze can freeze".to_string(),
                                got: "Cannot freeze array buffer views with elements".to_string(),
                            });
                        }
                        // Actually freeze the object by setting the is_frozen flag
                        self.disconnect_all_mapped_arguments(obj_id);
                        let obj_index = obj_id.0 as usize;
                        let mut object_found = false;
                        self.mutate_heap(|heap| {
                            if let Some(obj) = heap.get_mut(obj_index) {
                                obj.is_frozen = true;
                                object_found = true;
                            }
                        });
                        if !object_found {
                            return Err(InterpreterError::TypeError {
                                expected: "valid object".to_string(),
                                got: "object not found".to_string(),
                            });
                        }

                        Ok(Value::Object(obj_id))
                    }
                    // A function, promise, generator or iterator freezes the
                    // backing object that holds its own properties
                    // (bd-9vouw.149).
                    ref holder if Self::stores_own_properties_on_backing(holder) => {
                        if let Some(backing) = self.own_property_holder(module, holder, true)? {
                            self.mutate_heap(|heap| heap[backing.0 as usize].is_frozen = true);
                        }
                        Ok(holder.clone())
                    }
                    _ => {
                        // Non-object values are returned as-is (they're already "immutable")
                        Ok(obj_val)
                    }
                }
            }
            "builtin:ObjectIsFrozen" => {
                // Object.isFrozen implementation - checks if object is frozen
                if args.count == 0 {
                    return Ok(Value::Bool(true)); // Per spec, non-objects are always considered frozen
                }

                let obj_val = self.read_reg(args.start)?;
                if let Some(proxy) = self.integrity_proxy_id(&obj_val)? {
                    return Ok(Value::Bool(
                        self.proxy_test_integrity_level(module, proxy, true)?,
                    ));
                }
                match obj_val {
                    Value::Object(obj_id) => {
                        Ok(Value::Bool(self.object_has_integrity_level(obj_id, true)?))
                    }
                    ref holder if Self::stores_own_properties_on_backing(holder) => Ok(
                        Value::Bool(self.backing_has_integrity_level(module, holder, true)?),
                    ),
                    _ => {
                        // Non-object values are considered frozen
                        Ok(Value::Bool(true))
                    }
                }
            }
            "builtin:ObjectCreate" => {
                // Object.create(O, Properties) (ES2020 19.1.2.2): O must be an
                // object or null; a missing O is undefined and throws.
                let prototype_arg = self.arg_or_undefined(args, 0)?;
                // A callable proxy's record is its object identity (lookups
                // reach its traps and its function target, bd-9vouw.132); a
                // function links to its own-property backing object
                // (bd-9vouw.98: bundlers' `__toESM` does
                // `Object.create(getPrototypeOf(DerivedClass))`).
                let Some(prototype) = self.prototype_link_for_value(module, &prototype_arg)? else {
                    return Err(InterpreterError::TypeError {
                        expected: "object or null prototype for Object.create".to_string(),
                        got: prototype_arg.type_name().to_string(),
                    });
                };

                let obj_id = self.alloc_object_with_prototype(prototype)?;
                if prototype.is_none() {
                    self.store_prototype_link(obj_id, None);
                }
                let properties_arg = self.arg_or_undefined(args, 1)?;
                if !matches!(properties_arg, Value::Undefined) {
                    self.object_define_properties(module, obj_id, properties_arg, "Object.create")?;
                }

                Ok(Value::Object(obj_id))
            }

            // String methods
            // Removed duplicate StringPrototypeCharAt - implementation at line ~14142 has better JS coercion
            "builtin:StringPrototypeIndexOf" => {
                // String.prototype.indexOf implementation - returns index of first occurrence of substring
                if args.count < 2 {
                    return Ok(Value::Int(-1)); // No search string provided
                }

                let string_val = self.read_reg(args.start)?;
                let search_val = self.read_reg(args.start + 1)?;

                match (string_val, search_val) {
                    (Value::Str(haystack), Value::Str(needle)) => {
                        // Optional start position (fromIndex parameter)
                        let start_pos = if args.count >= 3 {
                            let start_val = self.read_reg(args.start + 2)?;
                            match start_val {
                                Value::Int(pos) => {
                                    if pos < 0 {
                                        0
                                    } else {
                                        pos as usize
                                    }
                                }
                                Value::Float(f) => {
                                    let pos = f.inner().floor() as i64;
                                    if pos < 0 { 0 } else { pos as usize }
                                }
                                _ => 0,
                            }
                        } else {
                            0
                        };

                        // Exact code-unit search from the UTF-16 position; a
                        // position inside a surrogate pair is a legal offset
                        // (bd-rdnhc; previously failed closed with a
                        // TypeError on split-pair boundaries).
                        Ok(Value::Int(
                            haystack
                                .utf16_index_of(&needle, start_pos)
                                .map_or(-1, |index| index as i64),
                        ))
                    }
                    _ => {
                        // Non-string arguments - return -1 per JavaScript behavior
                        Ok(Value::Int(-1))
                    }
                }
            }
            // Removed duplicate StringPrototypeSubstring - implementation at line ~14106 is more JS-compliant
            "builtin:StringPrototypeSlice" => {
                // String.prototype.slice implementation - extracts part of string with different negative index behavior
                if args.count == 0 {
                    return Ok(Value::str(""));
                }

                let string_arg = self.read_reg(args.start)?;
                let string_val = match string_arg {
                    Value::Str(s) => s.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "".to_string(),
                };

                let str_len = string_val.chars().count() as i64;

                // Get start index (default to 0)
                let start_idx = if args.count > 1 {
                    let start_arg = self.read_reg(args.start + 1)?;
                    match start_arg {
                        Value::Int(n) => {
                            if n < 0 {
                                (str_len + n).max(0) as usize
                            } else {
                                n.min(str_len) as usize
                            }
                        }
                        Value::Float(f) => {
                            let val = f.inner();
                            if val.is_nan() {
                                0
                            } else if val < 0.0 {
                                ((str_len as f64) + val).max(0.0) as usize
                            } else {
                                val.min(str_len as f64) as usize
                            }
                        }
                        _ => 0,
                    }
                } else {
                    0
                };

                // Get end index (default to string length)
                let end_idx = if args.count > 2 {
                    let end_arg = self.read_reg(args.start + 2)?;
                    match end_arg {
                        Value::Int(n) => {
                            if n < 0 {
                                (str_len + n).max(0) as usize
                            } else {
                                n.min(str_len) as usize
                            }
                        }
                        Value::Float(f) => {
                            let val = f.inner();
                            if val.is_nan() {
                                str_len as usize
                            } else if val < 0.0 {
                                ((str_len as f64) + val).max(0.0) as usize
                            } else {
                                val.min(str_len as f64) as usize
                            }
                        }
                        _ => str_len as usize,
                    }
                } else {
                    str_len as usize
                };

                // Extract substring if start < end
                if start_idx < end_idx {
                    let chars: Vec<char> = string_val.chars().collect();
                    let substring: String = chars[start_idx..end_idx].iter().collect();
                    Ok(Value::str(substring))
                } else {
                    Ok(Value::str(""))
                }
            }
            "builtin:StringPrototypeToLowerCase" => {
                // String.prototype.toLowerCase implementation - converts string to lowercase
                if args.count == 0 {
                    return Ok(Value::str(""));
                }

                let string_arg = self.read_reg(args.start)?;
                let string_val = Self::require_object_coercible_to_js_string(&string_arg)?;
                string_val
                    .try_map_unicode_spans(|text| Ok(text.to_lowercase()))
                    .map(Value::Str)
            }
            "builtin:StringPrototypeToUpperCase" => {
                // String.prototype.toUpperCase implementation - converts string to uppercase
                if args.count == 0 {
                    return Ok(Value::str(""));
                }

                let string_arg = self.read_reg(args.start)?;
                let string_val = Self::require_object_coercible_to_js_string(&string_arg)?;
                string_val
                    .try_map_unicode_spans(|text| Ok(text.to_uppercase()))
                    .map(Value::Str)
            }
            "builtin:StringPrototypeTrim" => {
                // String.prototype.trim implementation - removes whitespace from both ends
                if args.count == 0 {
                    return Ok(Value::str(""));
                }

                let string_arg = self.read_reg(args.start)?;
                let string_val = match string_arg {
                    Value::Str(s) => s.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "".to_string(),
                };

                // Remove WhiteSpace and LineTerminator from both ends.
                let trimmed = string_val.trim_matches(primitive_conversion::is_js_whitespace);
                Ok(Value::str(trimmed))
            }

            // Node `path` builtins (bd-tu0c3): pure-compute posix semantics
            // (plus the win32 join/basename/isAbsolute subset), dispatched from
            // the lowering's path-module member-call interception. No host
            // effect; argument-validation failures throw Node's
            // ERR_INVALID_ARG_TYPE TypeError (JS-catchable, `.code` set).
            "builtin:PathJoin" => {
                let parts = self.path_string_args(args, "paths")?;
                Ok(Value::str(node_path_posix_join(&parts)))
            }
            "builtin:PathResolve" => {
                let parts = self.path_resolve_args(args)?;
                Ok(Value::str(node_path_posix_resolve(&parts)))
            }
            "builtin:PathNormalize" => {
                let path = self.path_string_arg(args, 0, "path")?;
                Ok(Value::str(node_path_posix_normalize(&path)))
            }
            "builtin:PathBasename" => {
                let path = self.path_string_arg(args, 0, "path")?;
                let ext = self.path_optional_string_arg(args, 1, "ext")?;
                Ok(Value::str(node_path_basename_impl(
                    &path,
                    ext.as_deref(),
                    &['/'],
                    false,
                )))
            }
            "builtin:PathDirname" => {
                let path = self.path_string_arg(args, 0, "path")?;
                Ok(Value::str(node_path_posix_dirname(&path)))
            }
            "builtin:PathExtname" => {
                let path = self.path_string_arg(args, 0, "path")?;
                Ok(Value::str(node_path_posix_extname(&path)))
            }
            "builtin:PathIsAbsolute" => {
                let path = self.path_string_arg(args, 0, "path")?;
                Ok(Value::Bool(path.starts_with('/')))
            }
            "builtin:PathRelative" => {
                let from = self.path_string_arg(args, 0, "from")?;
                let to = self.path_string_arg(args, 1, "to")?;
                Ok(Value::str(node_path_posix_relative(&from, &to)))
            }
            "builtin:PathParse" => {
                let path = self.path_string_arg(args, 0, "path")?;
                let parsed = node_path_posix_parse(&path);
                let object_id = self.alloc_object_with_properties(&[
                    ("root", Value::str(&parsed.root)),
                    ("dir", Value::str(&parsed.dir)),
                    ("base", Value::str(&parsed.base)),
                    ("ext", Value::str(&parsed.ext)),
                    ("name", Value::str(&parsed.name)),
                ])?;
                Ok(Value::Object(object_id))
            }
            "builtin:PathFormat" => {
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let Value::Object(object_id) = value else {
                    return Err(self.throw_path_arg_type_error("pathObject", "object", &value));
                };
                let root = self.path_format_object_property(object_id, "root");
                let dir = self.path_format_object_property(object_id, "dir");
                let base = self.path_format_object_property(object_id, "base");
                let name = self.path_format_object_property(object_id, "name");
                let ext = self.path_format_object_property(object_id, "ext");
                Ok(Value::str(node_path_posix_format(
                    &root, &dir, &base, &name, &ext,
                )))
            }
            "builtin:PathWin32Join" => {
                let parts = self.path_string_args(args, "paths")?;
                Ok(Value::str(node_path_win32_join(&parts)))
            }
            "builtin:PathWin32Basename" => {
                let path = self.path_string_arg(args, 0, "path")?;
                let ext = self.path_optional_string_arg(args, 1, "ext")?;
                Ok(Value::str(node_path_basename_impl(
                    &path,
                    ext.as_deref(),
                    &['/', '\\'],
                    true,
                )))
            }
            "builtin:PathWin32IsAbsolute" => {
                let path = self.path_string_arg(args, 0, "path")?;
                Ok(Value::Bool(node_path_win32_is_absolute(&path)))
            }

            // Node `querystring` builtins (bd-qmy52): pure-compute parse/
            // stringify/escape/unescape, shared by first-class querystring
            // module methods and direct hostcalls. No host effect;
            // semantics pinned against bun 1.3.14.
            // Fixed primitive references for the retained binary factory.
            // These never consult replaceable guest realm bindings.
            "builtin:NativeBufferConstructor" | "builtin:NativeBlobConstructor" => {
                if args.count != 0 {
                    return Err(InterpreterError::TypeError {
                        expected: "zero native binary constructor arguments".to_string(),
                        got: format!("{} argument(s)", args.count),
                    });
                }
                let name = if cap == "builtin:NativeBufferConstructor" {
                    "Buffer"
                } else {
                    "Blob"
                };
                Ok(Value::BuiltinFunction(
                    BuiltinFunction::standard_constructor(name),
                ))
            }
            // Canonical dependencies of the retained native Stream factory.
            // These private calls share public module state and retain normal
            // runtime observation labels; they are not pure fresh aggregates.
            "builtin:NativeEventsModule"
            | "builtin:NativeStringDecoderModule"
            | "builtin:NativeStreamModule"
            | "builtin:NativeWebStreamsModule" => {
                if args.count != 0 {
                    return Err(InterpreterError::TypeError {
                        expected: "zero native module dependency arguments".to_string(),
                        got: format!("{} argument(s)", args.count),
                    });
                }
                let module = module.ok_or_else(|| InterpreterError::InternalError {
                    details: "native module dependency requires an executable caller".to_string(),
                })?;
                if cap == "builtin:NativeEventsModule" {
                    self.source_builtin_module(module, NativeBuiltinModule::Events, None)
                } else if cap == "builtin:NativeWebStreamsModule" {
                    let descriptor = NativeBuiltinModule::StreamWeb.record("native-web-dependency");
                    if let Some(missing) = descriptor
                        .required_capabilities
                        .difference(&self.config.granted_capabilities)
                        .next()
                    {
                        return Err(InterpreterError::CapabilityDenied {
                            capability: missing.to_string(),
                        });
                    }
                    self.source_builtin_module(module, NativeBuiltinModule::StreamWeb, None)
                } else if cap == "builtin:NativeStreamModule" {
                    // The filesystem factory may load its canonical Stream
                    // dependency lazily. This private intrinsic preserves the
                    // public provider's authority contract on every access;
                    // possessing fs never grants scheduling authority.
                    let descriptor = NativeBuiltinModule::Stream.record("native-stream-dependency");
                    if let Some(missing) = descriptor
                        .required_capabilities
                        .difference(&self.config.granted_capabilities)
                        .next()
                    {
                        return Err(InterpreterError::CapabilityDenied {
                            capability: missing.to_string(),
                        });
                    }
                    self.source_builtin_module(module, NativeBuiltinModule::Stream, None)
                } else {
                    self.source_builtin_module(module, NativeBuiltinModule::StringDecoder, None)
                }
            }
            "builtin:QuerystringModule" => {
                if args.count != 0 {
                    return Err(InterpreterError::TypeError {
                        expected: "zero querystring module factory arguments".to_string(),
                        got: format!("{} argument(s)", args.count),
                    });
                }
                self.querystring_core_module()
            }
            "builtin:QuerystringParse" => {
                let input = self
                    .builtin_optional_arg(args, 0)?
                    .unwrap_or(Value::Undefined);
                // Node: a non-string (or empty) input yields an empty object.
                let Value::Str(input) = input else {
                    return Ok(Value::Object(self.alloc_object_with_properties(&[])?));
                };
                let sep = self.qs_separator_arg(args, 1, "&")?;
                let eq = self.qs_separator_arg(args, 2, "=")?;
                let max_pairs = self.qs_max_pairs_arg(args, 3)?;
                let entries = node_qs_parse(input.as_ref(), &sep, &eq, max_pairs);
                // Node returns a null-prototype object; engine objects already
                // allocate without a prototype. Single-value keys are scalars,
                // repeated keys are real engine arrays.
                let object_id = self.alloc_object_with_properties(&[])?;
                for (key, values) in entries {
                    let value = if values.len() == 1 {
                        Value::str(values.into_iter().next().unwrap_or_default())
                    } else {
                        let elements: Vec<Value> = values.into_iter().map(Value::str).collect();
                        Value::Object(self.alloc_array_from_values(&elements)?)
                    };
                    self.set_object_property(object_id, key, value)?;
                }
                Ok(Value::Object(object_id))
            }
            "builtin:QuerystringStringify" => {
                let sep = self.qs_separator_arg(args, 1, "&")?;
                let eq = self.qs_separator_arg(args, 2, "=")?;
                let value = self
                    .builtin_optional_arg(args, 0)?
                    .unwrap_or(Value::Undefined);
                // Node: only a non-null object stringifies; every other input
                // (undefined, null, primitives) is ''.
                let Value::Object(object_id) = value else {
                    return Ok(Value::str(""));
                };
                Ok(Value::str(self.qs_stringify_object(object_id, &sep, &eq)?))
            }
            "builtin:QuerystringEscape" => {
                // Node coerces the argument with String() before escaping
                // (bun: qs.escape(42) is '42').
                let value = self
                    .builtin_optional_arg(args, 0)?
                    .unwrap_or(Value::Undefined);
                let coerced = match value {
                    Value::Str(s) => s,
                    other => JsString::from(self.value_to_string(&other)),
                };
                Ok(Value::str(self.qs_escape_js_string(&coerced)?))
            }
            "builtin:QuerystringUnescape" => {
                let value = self
                    .builtin_optional_arg(args, 0)?
                    .unwrap_or(Value::Undefined);
                let coerced = match &value {
                    Value::Str(s) => s.to_string(),
                    other => self.value_to_string(other),
                };
                Ok(Value::str(node_qs_unescape(&coerced)))
            }

            // Node `os` builtins (bd-qmy52): FIXED deterministic engine-
            // contained values (see the NODE_OS_* constants block) — the
            // engine has no ambient authority, so nothing here reads the real
            // host. getPriority/setPriority validate arguments like Node
            // (TypeError ERR_INVALID_ARG_TYPE / RangeError ERR_OUT_OF_RANGE,
            // both JS-catchable) and then return fixed/no-op results.
            "builtin:OsPlatform" => Ok(Value::str(NODE_OS_PLATFORM)),
            "builtin:OsArch" => Ok(Value::str(NODE_OS_ARCH)),
            "builtin:OsType" => Ok(Value::str("Linux")),
            "builtin:OsEndianness" => Ok(Value::str("LE")),
            "builtin:OsMachine" => Ok(Value::str("x86_64")),
            "builtin:OsRelease" => Ok(Value::str(NODE_OS_RELEASE)),
            "builtin:OsVersion" => Ok(Value::str(NODE_OS_VERSION)),
            "builtin:OsHomedir" => Ok(Value::str("/home")),
            "builtin:OsTmpdir" => Ok(Value::str("/tmp")),
            "builtin:OsHostname" => Ok(Value::str("localhost")),
            "builtin:OsUptime" => Ok(Value::Float(Float64::new(1.0))),
            "builtin:OsTotalmem" => Ok(Value::Int(NODE_OS_TOTALMEM_BYTES)),
            "builtin:OsFreemem" => Ok(Value::Int(NODE_OS_FREEMEM_BYTES)),
            "builtin:OsAvailableParallelism" => Ok(Value::Int(1)),
            "builtin:OsLoadavg" => {
                // Fixed idle load; length 3 like Node.
                let zero = Value::Float(Float64::new(0.0));
                let array_id = self.alloc_array_from_values(&[zero.clone(), zero.clone(), zero])?;
                Ok(Value::Object(array_id))
            }
            "builtin:OsCpus" => {
                // One fixed virtual CPU: non-empty, fully-typed shape.
                let times_id = self.alloc_object_with_properties(&[
                    ("user", Value::Int(0)),
                    ("nice", Value::Int(0)),
                    ("sys", Value::Int(0)),
                    ("idle", Value::Int(0)),
                    ("irq", Value::Int(0)),
                ])?;
                let cpu_id = self.alloc_object_with_properties(&[
                    ("model", Value::str("franken-virtual")),
                    ("speed", Value::Int(1000)),
                    ("times", Value::Object(times_id)),
                ])?;
                let array_id = self.alloc_array_from_values(&[Value::Object(cpu_id)])?;
                Ok(Value::Object(array_id))
            }
            "builtin:OsNetworkInterfaces" => {
                // The engine exposes NO network shape: an empty interfaces
                // map (a valid Node shape — machines can have zero non-
                // internal interfaces reported).
                Ok(Value::Object(self.alloc_object_with_properties(&[])?))
            }
            "builtin:OsUserInfo" => {
                let object_id = self.alloc_object_with_properties(&[
                    ("username", Value::str("franken")),
                    ("uid", Value::Int(0)),
                    ("gid", Value::Int(0)),
                    ("shell", Value::str("/bin/sh")),
                    ("homedir", Value::str("/home")),
                ])?;
                Ok(Value::Object(object_id))
            }
            "builtin:OsGetPriority" => {
                // Node: `getPriority(pid = 0)` — an absent/undefined pid takes
                // the default; anything else validates as an int32. The fixed
                // priority is 0 (PRIORITY_NORMAL) for every pid.
                if let Some(pid) = self.builtin_optional_arg(args, 0)?
                    && !matches!(pid, Value::Undefined)
                {
                    self.os_validate_int32(&pid, "pid", i64::from(i32::MIN), i64::from(i32::MAX))?;
                }
                Ok(Value::Int(0))
            }
            "builtin:OsSetPriority" => {
                // Node: `setPriority([pid, ]priority)` — when `priority` is
                // undefined the single-argument form applies (priority := pid,
                // pid := 0). pid validates as an int32 first (TypeError
                // ERR_INVALID_ARG_TYPE on non-number), then priority as an
                // integer in [-20, 19] (RangeError ERR_OUT_OF_RANGE outside).
                // The engine accepts valid values and does nothing (there is
                // no host process to re-prioritize); returns undefined.
                let first = self
                    .builtin_optional_arg(args, 0)?
                    .unwrap_or(Value::Undefined);
                let second = self
                    .builtin_optional_arg(args, 1)?
                    .unwrap_or(Value::Undefined);
                let (pid, priority) = if matches!(second, Value::Undefined) {
                    (Value::Int(0), first)
                } else {
                    (first, second)
                };
                self.os_validate_int32(&pid, "pid", i64::from(i32::MIN), i64::from(i32::MAX))?;
                self.os_validate_int32(&priority, "priority", -20, 19)?;
                Ok(Value::Undefined)
            }
            // `os.constants` — the nested { signals, errno, priority } object.
            "builtin:OsConstants" => self.os_constants_object(),

            // Math methods
            "builtin:MathAbs" => {
                // Math.abs implementation - returns absolute value of the argument
                if args.count > 0 {
                    let arg = self.math_argument_value(args.start, module)?;
                    match arg {
                        Value::Int(n) => {
                            // Use saturating_abs to handle i64::MIN safely (returns i64::MAX)
                            Ok(Value::Int(n.saturating_abs()))
                        }
                        Value::Float(f) => Ok(Value::Float(Float64::new(f.inner().abs()))),
                        _ => {
                            let num = Self::coerce_to_float(&arg).unwrap_or(f64::NAN);
                            Ok(Value::Float(Float64::new(num.abs())))
                        }
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
            }
            "builtin:MathCeil" => {
                // Math.ceil implementation - returns ceiling (smallest integer >= x)
                if args.count > 0 {
                    let arg = self.math_argument_value(args.start, module)?;
                    match arg {
                        Value::Int(n) => Ok(Value::Int(n)), // Integer is already its own ceiling
                        Value::Float(f) => {
                            let val = f.inner().ceil();
                            // ES2020 20.2.2.10: ceil of -0 or of -1 < x < 0 is -0 (an Int would lose the sign).
                            if val == 0.0 && val.is_sign_negative() {
                                Ok(Value::Float(Float64::new(-0.0)))
                            } else if val.is_finite()
                                && val >= i64::MIN as f64
                                && val <= i64::MAX as f64
                            {
                                Ok(Value::Int(val as i64))
                            } else {
                                Ok(Value::Float(Float64::new(val)))
                            }
                        }
                        _ => Ok(Value::Float(Float64::new(f64::NAN))),
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
            }
            "builtin:MathFloor" => {
                // Math.floor implementation - returns floor (largest integer <= x)
                if args.count > 0 {
                    let arg = self.math_argument_value(args.start, module)?;
                    match arg {
                        Value::Int(n) => Ok(Value::Int(n)), // Integer is already its own floor
                        Value::Float(f) => {
                            let val = f.inner().floor();
                            // ES2020 20.2.2.16: floor of -0 is -0 (an Int would lose the sign).
                            if val == 0.0 && val.is_sign_negative() {
                                Ok(Value::Float(Float64::new(-0.0)))
                            } else if val.is_finite()
                                && val >= i64::MIN as f64
                                && val <= i64::MAX as f64
                            {
                                Ok(Value::Int(val as i64))
                            } else {
                                Ok(Value::Float(Float64::new(val)))
                            }
                        }
                        _ => Ok(Value::Float(Float64::new(f64::NAN))),
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
            }
            "builtin:MathRound" => {
                // Math.round implementation - returns nearest integer
                if args.count > 0 {
                    let arg = self.math_argument_value(args.start, module)?;
                    match arg {
                        Value::Int(n) => Ok(Value::Int(n)), // Integer is already rounded
                        other => {
                            let input = Self::coerce_to_float(&other).unwrap_or(f64::NAN);
                            // JavaScript `Math.round`: nearest integer, ties
                            // toward +Infinity. `floor(x + 0.5)` is WRONG for
                            // arguments just below 0.5 — e.g.
                            // `0.49999999999999994 + 0.5` rounds up to exactly
                            // `1.0`, so the naive form returns 1 instead of 0.
                            // Round off the true fractional part instead.
                            let val = if input.is_nan() || input.is_infinite() {
                                input
                            } else {
                                let floor = input.floor();
                                if input - floor >= 0.5 {
                                    floor + 1.0
                                } else {
                                    floor
                                }
                            };
                            // ES2020 20.2.2.28: a zero result from -0.5 <= x < 0 or from -0 is -0.
                            if val == 0.0 && input.is_sign_negative() {
                                Ok(Value::Float(Float64::new(-0.0)))
                            } else if val.is_finite()
                                && val >= i64::MIN as f64
                                && val <= i64::MAX as f64
                            {
                                Ok(Value::Int(val as i64))
                            } else {
                                Ok(Value::Float(Float64::new(val)))
                            }
                        }
                    }
                } else {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                }
            }
            "builtin:MathMax" => {
                let values = self.builtin_argument_values(args)?;
                self.math_extremum(module, values, true)
            }
            "builtin:MathMin" => {
                let values = self.builtin_argument_values(args)?;
                self.math_extremum(module, values, false)
            }
            "builtin:MathRandom" => {
                // Math.random implementation - deterministic with proper [0,1) range
                self.math_random_impl()
            }

            // JSON methods
            "builtin:JsonStringify" => self.json_stringify_builtin(module, args),
            "builtin:JsonParse" => self.json_parse_builtin(module, args),
            "builtin:JsonRawJson" => self.json_raw_json_builtin(module, args),
            "builtin:JsonIsRawJson" => self.json_is_raw_json_builtin(args),
            "builtin:isNaN" => {
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::IsNaN)
            }
            "builtin:isFinite" => {
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::IsFinite)
            }
            "builtin:parseInt" => {
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::ParseInt)
            }
            // Removed duplicate parseFloat implementation; canonicalized in `builtin:parseFloat` below
            "builtin:NumberIsNaN" => {
                // Number.isNaN implementation - more strict than global isNaN
                if args.count == 0 {
                    return Ok(Value::Bool(false)); // Number.isNaN() with no args returns false
                }

                let arg = self.read_reg(args.start)?;
                match arg {
                    Value::Float(f) => Ok(Value::Bool(f.inner().is_nan())),
                    _ => Ok(Value::Bool(false)), // Number.isNaN only returns true for NaN numbers, not type coerced
                }
            }
            "builtin:NumberIsFinite" => {
                // Number.isFinite implementation - more strict than global isFinite
                if args.count == 0 {
                    return Ok(Value::Bool(false)); // Number.isFinite() with no args returns false
                }

                let arg = self.read_reg(args.start)?;
                match arg {
                    Value::Int(_) => Ok(Value::Bool(true)), // All integers are finite
                    Value::Float(f) => Ok(Value::Bool(f.inner().is_finite())),
                    _ => Ok(Value::Bool(false)), // Number.isFinite only returns true for finite numbers, not type coerced
                }
            }
            "builtin:ConsoleLog" => {
                self.dispatch_console_hostcall_inner("console:log", args, module)
            }
            "builtin:ConsoleError" => {
                self.dispatch_console_hostcall_inner("console:error", args, module)
            }
            "builtin:ConsoleWarn" => {
                self.dispatch_console_hostcall_inner("console:warn", args, module)
            }
            "builtin:DateNow" => {
                // Deterministic wall clock: the fixed epoch plus the run's
                // virtual elapsed time (timers fired + guest work), so timer
                // callbacks observe their delays and strict replay reproduces
                // every reading (bd-9vouw.59).
                Ok(Value::Float(Float64::new(self.virtual_wall_clock_ms())))
            }
            "builtin:PerformanceNow" => Ok(self.deterministic_performance_now()),
            "builtin:Date" => {
                // Date() / new Date([ms]) constructor — returns a Date object.
                // With no argument, uses the deterministic wall clock (epoch
                // plus virtual elapsed time, bd-9vouw.59). With an explicit
                // millisecond argument (`new Date(0)`), honor it so
                // `getTime()` round-trips (bd-cseei).
                let millis = match args.count {
                    0 => self.virtual_wall_clock_ms(),
                    1 => self.date_single_argument_time_value(args.start, module)?,
                    _ => self.date_components_time_value(args, module)?,
                };

                // Create a new Date object with a private [[DateValue]].
                // The timestamp stays a `Float` (matching
                // the existing Date unit tests); `Float64`'s JS-style Display
                // renders an integral value like `0` (not `0.0`), so
                // `new Date(0).getTime()` stringifies to "0". Use the
                // capability-checked allocator rather than poking the heap Vec.
                let date_prototype = self.ensure_builtin_prototype("Date")?;
                let date_id = self.alloc_object_with_prototype(Some(date_prototype))?;
                self.set_object_brand(date_id, "Date")?;
                let label = self.json_parse_context_label()?;
                self.join_object_mutation_label(date_id, &label)?;
                self.set_date_value(date_id, millis)?;
                Ok(Value::Object(date_id))
            }
            "builtin:ArrayBuffer" | "builtin:SharedArrayBuffer" => {
                let shared = cap == "builtin:SharedArrayBuffer";
                Ok(Value::Object(
                    self.construct_array_buffer(module, args, shared)?,
                ))
            }
            "builtin:Uint8Array"
            | "builtin:Int32Array"
            | "builtin:Uint32Array"
            | "builtin:Int8Array"
            | "builtin:Uint8ClampedArray"
            | "builtin:Int16Array"
            | "builtin:Uint16Array"
            | "builtin:Float32Array"
            | "builtin:Float64Array"
            | "builtin:BigInt64Array"
            | "builtin:BigUint64Array" => {
                let kind = TypedArrayKind::from_builtin_capability(cap).expect(
                    "typed-array constructor branch must use a known typed-array capability",
                );
                let view_id = self.construct_typed_array(module, kind, args)?;
                Ok(Value::Object(view_id))
            }
            "builtin:DataView" => {
                let view_id = self.construct_data_view(module, args)?;
                Ok(Value::Object(view_id))
            }
            "builtin:BufferFrom" => self.buffer_from(args),
            "builtin:BufferAlloc" | "builtin:BufferAllocUnsafe" => self.buffer_alloc(args),
            "builtin:BufferByteLength" => self.buffer_byte_length(args),
            "builtin:BufferConcat" => self.buffer_concat(args),
            "builtin:BufferCompare" => self.buffer_static_compare(args),
            "builtin:BufferIsBuffer" => self.buffer_is_buffer_builtin(args),
            "builtin:BufferIsEncoding" => self.buffer_is_encoding_builtin(args),
            "builtin:BufferObjectToString" | "builtin:BufferObjectReadUInt32LE" => {
                self.buffer_object_hostcall(cap, args)
            }
            "builtin:MathPow" => {
                // Math.pow(base, exponent) implementation
                if args.count < 2 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let base = self.math_argument_value(args.start, module)?;
                let exponent = self.math_argument_value(args.start + 1, module)?;

                let base_num = match base {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let exp_num = match exponent {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                // A -0 result (`Math.pow(-0, 3)`) stays -0, and a whole
                // result past 2^53 stays a double, as `**` gives them.
                Ok(js_number_to_value(js_exponentiate(base_num, exp_num)))
            }
            "builtin:StringPrototypeIncludes" => {
                // String.prototype.includes(searchString[, position]) implementation
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let Some(this_str) = Self::legacy_string_arm_operand(&this_val) else {
                    return Ok(Value::Bool(false));
                };

                // Get search string
                let search_val = self.read_reg(args.start + 1)?;
                let Some(search_str) = Self::legacy_string_arm_operand(&search_val) else {
                    return Ok(Value::Bool(false));
                };

                // Get optional position parameter
                let position = if args.count > 2 {
                    let pos_val = self.read_reg(args.start + 2)?;
                    match pos_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Exact code-unit containment from the UTF-16 position; a
                // position inside a surrogate pair is a legal offset
                // (bd-rdnhc; previously failed closed with a TypeError).
                Ok(Value::Bool(
                    this_str.utf16_index_of(&search_str, position).is_some(),
                ))
            }
            "builtin:ArrayPrototypeReverse" => {
                // Array.prototype.reverse() implementation - reverses array in place
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(this_val), // Non-arrays return themselves
                };

                // Get the array object from heap and read necessary data
                let heap_index = array_id.0 as usize;
                if let Some(array_obj) = self.heap.get(heap_index) {
                    // Get array length
                    let length = array_obj
                        .properties
                        .get("length")
                        .and_then(|v| match v {
                            Value::Int(i) => Some(*i as usize),
                            Value::Float(f) => Some(f.inner() as usize),
                            _ => None,
                        })
                        .unwrap_or(0);

                    if length <= 1 {
                        return Ok(Value::Object(array_id)); // Nothing to reverse
                    }

                    // Collect indexed properties
                    let mut indexed_props: BTreeMap<usize, Value> = BTreeMap::new();
                    for (key, value) in &array_obj.properties {
                        if let Some(index) = Self::canonical_array_index_property(key, length) {
                            indexed_props.insert(index, value.clone());
                        }
                    }

                    // Incremental memory accounting (bd-s8u37): values are
                    // preserved but key strings change (`0` <-> `length-1-0`),
                    // which shifts byte sizes for sparse arrays whose index
                    // set is not symmetric (e.g. key "0" -> "10").
                    let removed_bytes = indexed_props
                        .iter()
                        .map(|(old_index, value)| {
                            Self::estimate_property_entry_bytes(&old_index.to_string(), value)
                        })
                        .sum::<u64>();
                    let added_bytes = indexed_props
                        .iter()
                        .map(|(old_index, value)| {
                            Self::estimate_property_entry_bytes(
                                &(length - 1 - old_index).to_string(),
                                value,
                            )
                        })
                        .sum::<u64>();
                    self.apply_memory_component_delta(removed_bytes, added_bytes)?;

                    // Mutate heap to reverse the array
                    self.mutate_heap(|heap| {
                        if let Some(array_obj) = heap.get_mut(heap_index) {
                            // Remove old indexed properties
                            array_obj.properties.retain(|key, _| {
                                Self::canonical_array_index_property(key, length).is_none()
                            });

                            // Add back in reverse order
                            for (old_index, value) in indexed_props {
                                let new_index = length - 1 - old_index;
                                array_obj.properties.insert(new_index.to_string(), value);
                            }
                        }
                    });

                    Ok(Value::Object(array_id))
                } else {
                    Ok(this_val)
                }
            }
            "builtin:MathSqrt" => {
                // Math.sqrt(x) implementation - returns square root of a number
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.math_argument_value(args.start, module)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                // ES2020 20.2.2.32: the square root of -0 is -0.
                Ok(js_number_to_value(num.sqrt()))
            }
            "builtin:StringPrototypeStartsWith" => {
                // String.prototype.startsWith(searchString[, position]) implementation
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let Some(this_str) = Self::legacy_string_arm_operand(&this_val) else {
                    return Ok(Value::Bool(false));
                };

                // Get search string
                let search_val = self.read_reg(args.start + 1)?;
                let Some(search_str) = Self::legacy_string_arm_operand(&search_val) else {
                    return Ok(Value::Bool(false));
                };

                // Get optional position parameter
                let position = if args.count > 2 {
                    let pos_val = self.read_reg(args.start + 2)?;
                    match pos_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Exact code-unit prefix test at the UTF-16 position; a
                // position inside a surrogate pair is a legal offset
                // (bd-rdnhc; previously failed closed with a TypeError).
                let units = this_str.code_units_vec();
                let needle = search_str.code_units_vec();
                let position = position.min(units.len());
                Ok(Value::Bool(units[position..].starts_with(&needle)))
            }
            "builtin:StringPrototypeEndsWith" => {
                // String.prototype.endsWith(searchString[, length]) implementation
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let Some(this_str) = Self::legacy_string_arm_operand(&this_val) else {
                    return Ok(Value::Bool(false));
                };

                // Get search string
                let search_val = self.read_reg(args.start + 1)?;
                let Some(search_str) = Self::legacy_string_arm_operand(&search_val) else {
                    return Ok(Value::Bool(false));
                };

                // Get optional length parameter
                let units = this_str.code_units_vec();
                let max_utf16_len = units.len();
                let end_pos = if args.count > 2 {
                    let len_val = self.read_reg(args.start + 2)?;
                    match len_val {
                        Value::Int(i) => (i.max(0) as usize).min(max_utf16_len),
                        Value::Float(f) => (f.inner().max(0.0) as usize).min(max_utf16_len),
                        _ => max_utf16_len,
                    }
                } else {
                    max_utf16_len
                };

                // Exact code-unit suffix test against the prefix of length
                // `end_pos`; an end position inside a surrogate pair is a
                // legal offset (bd-rdnhc; previously failed closed with a
                // TypeError).
                let needle = search_str.code_units_vec();
                Ok(Value::Bool(units[..end_pos].ends_with(&needle)))
            }
            "builtin:ArrayPrototypeForEach" => {
                let (array_id, callback, this_arg, length) =
                    self.validate_array_callback_structure(args, "Array.prototype.forEach")?;

                for index in 0..length {
                    let Some(element) = self.array_index_get(module, array_id, index)? else {
                        continue;
                    };
                    self.invoke_array_callback(
                        module,
                        &callback,
                        this_arg.clone(),
                        element,
                        index,
                        array_id,
                    )?;
                }

                Ok(Value::Undefined)
            }
            // ArrayPrototypeFind: Removed duplicate dispatch arm (use occurrence at line 12492)
            "builtin:MathSin" => {
                // Math.sin(x) implementation - returns sine of x in radians
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.math_argument_value(args.start, module)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let result = num.sin();
                Ok(Value::Float(Float64::new(result)))
            }
            "builtin:MathCos" => {
                // Math.cos(x) implementation - returns cosine of x in radians
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.math_argument_value(args.start, module)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let result = num.cos();
                Ok(Value::Float(Float64::new(result)))
            }
            "builtin:StringPrototypeReplace" => {
                // String.prototype.replace(searchValue, replaceValue), ES2020
                // 21.1.3.17: a callable replacer or a GetSubstitution template.
                let this_val = self.arg_or_undefined(args, 0)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    other => JsString::from(self.value_to_string(&other)),
                };
                let search_val = self.arg_or_undefined(args, 1)?;
                let replace_val = self.arg_or_undefined(args, 2)?;
                let label = self.join_arg_range_label(args)?;
                self.string_replace_js(module, &str_text, &search_val, &replace_val, false, label)
            }
            "builtin:MathLog" => {
                // Math.log(x) implementation - returns natural logarithm of x
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.math_argument_value(args.start, module)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => Self::coerce_to_float(&arg).unwrap_or(f64::NAN),
                };

                if num < 0.0 {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else if num == 0.0 {
                    Ok(Value::Float(Float64::new(f64::NEG_INFINITY)))
                } else {
                    let result = num.ln();
                    Ok(Value::Float(Float64::new(result)))
                }
            }
            "builtin:MathExp" => {
                // Math.exp(x) implementation - returns e raised to the power of x
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.math_argument_value(args.start, module)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let result = num.exp();
                Ok(Value::Float(Float64::new(result)))
            }
            "builtin:MathTan" => {
                // Math.tan(x) implementation - returns tangent of x in radians
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.math_argument_value(args.start, module)?;
                let num = match arg {
                    Value::Int(i) => i as f64,
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                let result = num.tan();
                Ok(Value::Float(Float64::new(result)))
            }
            "builtin:MathPI" => {
                // Math.PI constant - returns the mathematical constant π
                Ok(Value::Float(Float64::new(std::f64::consts::PI)))
            }
            "builtin:StringPrototypeRepeat" => {
                // String.prototype.repeat(count) implementation
                if args.count == 0 {
                    return Ok(Value::str(""));
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s.to_string(),
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(Value::str("")),
                };

                // Get repeat count
                let count_val = self.read_reg(args.start + 1)?;
                let count = match count_val {
                    Value::Int(i) => i.max(0) as usize,
                    Value::Float(f) => f.inner().max(0.0) as usize,
                    Value::Bool(true) => 1,
                    Value::Bool(false) => 0,
                    Value::Null => 0,
                    _ => return Ok(Value::str("")),
                };

                // Prevent excessive memory usage
                if count > 1000 {
                    return Ok(Value::str(""));
                }

                let result = this_str.repeat(count);
                Ok(Value::str(result))
            }
            "builtin:PromiseResolveFunction" => {
                Ok(Value::BuiltinFunction(BuiltinFunction::promise_resolve()))
            }
            "builtin:PromiseRejectFunction" => {
                Ok(Value::BuiltinFunction(BuiltinFunction::promise_reject()))
            }
            "builtin:PromiseAllFunction" => {
                Ok(Value::BuiltinFunction(BuiltinFunction::promise_all()))
            }
            "builtin:PromiseRaceFunction" => {
                Ok(Value::BuiltinFunction(BuiltinFunction::promise_race()))
            }
            "builtin:PromiseAllSettledFunction" => Ok(Value::BuiltinFunction(
                BuiltinFunction::promise_all_settled(),
            )),
            "builtin:PromiseAnyFunction" => {
                Ok(Value::BuiltinFunction(BuiltinFunction::promise_any()))
            }
            "builtin:PromiseResolve" => {
                // Promise.resolve(value) implementation (simplified)
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };

                // Create a new Promise object (simplified - just wraps the value).
                let promise_id = self.alloc_object_with_prototype(None)?;
                self.set_object_property(
                    promise_id,
                    "__state".to_string(),
                    Value::str("fulfilled"),
                )?;
                self.set_object_property(promise_id, "__value".to_string(), value)?;
                Ok(Value::Object(promise_id))
            }
            "builtin:ArrayPrototypeReduce" => self.array_prototype_reduce(args, module),
            "builtin:StringPrototypePadStart" => {
                // String.prototype.padStart(targetLength[, padString]) implementation
                if args.count == 0 {
                    return self.read_reg(args.start);
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s.to_string(),
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(this_val),
                };

                // Get target length
                let target_length = if args.count > 1 {
                    let len_val = self.read_reg(args.start + 1)?;
                    match len_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => this_str.len(),
                    }
                } else {
                    this_str.len()
                };

                // Get pad string
                let pad_str = if args.count > 2 {
                    let pad_val = self.read_reg(args.start + 2)?;
                    match pad_val {
                        Value::Str(s) => s.to_string(),
                        Value::Int(i) => i.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => " ".to_string(),
                        _ => " ".to_string(),
                    }
                } else {
                    " ".to_string()
                };

                if target_length <= this_str.len() {
                    Ok(Value::str(this_str))
                } else {
                    let pad_needed = target_length - this_str.len();
                    let mut padding = String::new();

                    // Repeat pad string until we have enough padding
                    while padding.len() < pad_needed {
                        padding.push_str(&pad_str);
                    }

                    // Truncate to exact length needed
                    padding.truncate(pad_needed);
                    let result = format!("{}{}", padding, this_str);
                    Ok(Value::str(result))
                }
            }
            "builtin:ObjectHasOwnProperty" => {
                // Object.prototype.hasOwnProperty(property) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let prop_val = self.read_reg(args.start + 1)?;
                Ok(Value::Bool(
                    self.value_has_own_property(module, &this_val, &prop_val)?,
                ))
            }
            "builtin:ArrayPrototypeSort" => {
                // Array.prototype.sort([compareFunction]) implementation (consolidated for builtin IDs 28, 248, 385)
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(this_val), // Non-objects return as-is
                };

                let _compare_fn = if args.count > 1 {
                    Some(self.read_reg(args.start + 1)?)
                } else {
                    None
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => (*len).max(0) as usize,
                        Some(Value::Float(len)) => len.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    return Ok(this_val);
                };

                if length <= 1 {
                    return Ok(this_val); // Nothing to sort
                }

                // Collect all elements, filling holes with Undefined
                let mut elements = Vec::new();
                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    for i in 0..length {
                        if let Some(element) = obj.properties.get(&i.to_string()) {
                            elements.push(element.clone());
                        } else {
                            elements.push(Value::Undefined);
                        }
                    }
                }

                // Sort by string representation while preserving original values
                elements.sort_by(|a, b| {
                    let a_str = match a {
                        Value::Str(s) => s.to_string(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        Value::Object(_) => "[object Object]".to_string(),
                        _ => "".to_string(),
                    };

                    let b_str = match b {
                        Value::Str(s) => s.to_string(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        Value::Object(_) => "[object Object]".to_string(),
                        _ => "".to_string(),
                    };

                    a_str.cmp(&b_str)
                });

                // Incremental memory accounting (bd-s8u37): sparse arrays gain
                // entries here (holes are materialised as Undefined), so the
                // removed/added entry bytes are not symmetric in general.
                let heap_index = array_id.0 as usize;
                let removed_bytes = self.heap.get(heap_index).map_or(0, |obj| {
                    (0..length)
                        .filter_map(|i| {
                            let key = i.to_string();
                            obj.properties
                                .get(&key)
                                .map(|value| Self::estimate_property_entry_bytes(&key, value))
                        })
                        .sum::<u64>()
                });
                let added_bytes = elements
                    .iter()
                    .enumerate()
                    .map(|(i, element)| {
                        Self::estimate_property_entry_bytes(&i.to_string(), element)
                    })
                    .sum::<u64>();
                self.apply_memory_component_delta(removed_bytes, added_bytes)?;

                // Clear existing indexed properties and set sorted elements
                self.mutate_heap(|heap| {
                    if let Some(obj_mut) = heap.get_mut(heap_index) {
                        // Remove old indexed properties
                        for i in 0..length {
                            obj_mut.properties.remove(&i.to_string());
                        }

                        // Set sorted elements back in order
                        for (i, element) in elements.iter().enumerate() {
                            obj_mut.properties.insert(i.to_string(), element.clone());
                        }
                    }
                });

                Ok(this_val)
            }
            "builtin:Error" => self.construct_error_object(module, "Error", args),
            // Error subclasses (bd-bg9l1.27.10). Same shape as Error, with the
            // correct `name`. These are reached only via the `new <Name>(...)`
            // lowering interception (error_constructor_capability) since there is
            // no global binding for them on the eval scope path.
            "builtin:TypeError" => self.construct_error_object(module, "TypeError", args),
            "builtin:RangeError" => self.construct_error_object(module, "RangeError", args),
            "builtin:ReferenceError" => self.construct_error_object(module, "ReferenceError", args),
            "builtin:SyntaxError" => self.construct_error_object(module, "SyntaxError", args),
            "builtin:EvalError" => self.construct_error_object(module, "EvalError", args),
            "builtin:URIError" => self.construct_error_object(module, "URIError", args),
            "builtin:AggregateError" => self.construct_aggregate_error(module, args),
            "builtin:StringPrototypePadEnd" => {
                // String.prototype.padEnd(targetLength[, padString]) implementation
                if args.count == 0 {
                    return self.read_reg(args.start);
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s.to_string(),
                    Value::Int(i) => i.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => return Ok(this_val),
                };

                // Get target length
                let target_length = if args.count > 1 {
                    let len_val = self.read_reg(args.start + 1)?;
                    match len_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => this_str.len(),
                    }
                } else {
                    this_str.len()
                };

                // Get pad string
                let pad_str = if args.count > 2 {
                    let pad_val = self.read_reg(args.start + 2)?;
                    match pad_val {
                        Value::Str(s) => s.to_string(),
                        Value::Int(i) => i.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => " ".to_string(),
                        _ => " ".to_string(),
                    }
                } else {
                    " ".to_string()
                };

                if target_length <= this_str.len() {
                    Ok(Value::str(this_str))
                } else {
                    let pad_needed = target_length - this_str.len();
                    let mut padding = String::new();

                    // Repeat pad string until we have enough padding
                    while padding.len() < pad_needed {
                        padding.push_str(&pad_str);
                    }

                    // Truncate to exact length needed
                    padding.truncate(pad_needed);
                    let result = format!("{}{}", this_str, padding);
                    Ok(Value::str(result))
                }
            }
            "builtin:MathTrunc" => {
                // Math.trunc(x) implementation - truncates decimal part of number
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.math_argument_value(args.start, module)?;
                let num = match arg {
                    Value::Int(i) => return Ok(Value::Int(i)), // Already truncated
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                // ES2020 20.2.2.35: -0 and -1 < x < 0 truncate to -0.
                Ok(js_number_to_value(num.trunc()))
            }
            "builtin:ArrayPrototypeSplice" => {
                // Array.prototype.splice(start[, deleteCount[, ...items]]) implementation (simplified)
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-arrays return undefined
                };

                let start = if args.count > 1 {
                    let start_val = self.read_reg(args.start + 1)?;
                    match start_val {
                        Value::Int(i) => i as isize,
                        Value::Float(f) => f.inner() as isize,
                        _ => 0,
                    }
                } else {
                    0
                };

                let delete_count = if args.count > 2 {
                    let delete_val = self.read_reg(args.start + 2)?;
                    match delete_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Get items to insert (simplified - just first additional item)
                let insert_item = if args.count > 3 {
                    Some(self.read_reg(args.start + 3)?)
                } else {
                    None
                };

                // Pre-compute the result ObjectId from current heap length
                // so we don't alias `self.heap` with the mutable borrow below.
                let result_id = ObjectId(u32::try_from(self.heap.len()).unwrap_or(u32::MAX));

                // Read the array object from heap first
                let heap_index = array_id.0 as usize;
                if let Some(array_obj) = self.heap.get(heap_index) {
                    // Get array length
                    let length = array_obj
                        .properties
                        .get("length")
                        .and_then(|v| match v {
                            Value::Int(i) => Some(*i as usize),
                            Value::Float(f) => Some(f.inner() as usize),
                            _ => None,
                        })
                        .unwrap_or(0);

                    // Normalize start index
                    let actual_start = if start < 0 {
                        (length as isize + start).max(0) as usize
                    } else {
                        (start as usize).min(length)
                    };

                    // Collect existing elements
                    let mut elements: Vec<Value> = Vec::new();
                    for i in 0..length {
                        if let Some(value) = array_obj.properties.get(&i.to_string()) {
                            elements.push(value.clone());
                        } else {
                            elements.push(Value::Undefined);
                        }
                    }

                    // Create result array with deleted elements (simplified).
                    let mut result_obj = Object::new();
                    result_obj
                        .properties
                        .insert("length".to_string(), Value::Int(delete_count as i64));

                    // Add deleted elements to result (simplified)
                    for i in 0..delete_count.min(length.saturating_sub(actual_start)) {
                        if actual_start + i < elements.len() {
                            result_obj
                                .properties
                                .insert(i.to_string(), elements[actual_start + i].clone());
                        }
                    }

                    // Modify original array (simplified - just remove deleted count)
                    if delete_count > 0 {
                        elements.drain(
                            actual_start..actual_start + delete_count.min(length - actual_start),
                        );
                    }

                    // Insert new item if provided
                    if let Some(item) = insert_item {
                        elements.insert(actual_start, item);
                    }

                    // Incremental memory accounting (bd-s8u37): the rewrite
                    // below removes every numeric-keyed entry plus the old
                    // `length` entry, re-inserts the post-splice elements and
                    // new `length`, and pushes a brand-new result-array heap
                    // object that would otherwise never enter the estimate.
                    let removed_bytes = array_obj
                        .properties
                        .iter()
                        .filter(|(k, _)| k.parse::<usize>().is_ok() || k.as_str() == "length")
                        .map(|(k, v)| Self::estimate_property_entry_bytes(k, v))
                        .sum::<u64>();
                    let added_bytes = elements
                        .iter()
                        .enumerate()
                        .map(|(i, value)| {
                            Self::estimate_property_entry_bytes(&i.to_string(), value)
                        })
                        .sum::<u64>()
                        .saturating_add(Self::estimate_property_entry_bytes(
                            "length",
                            &Value::Int(elements.len() as i64),
                        ))
                        .saturating_add(Self::estimate_heap_object_bytes(&result_obj));
                    self.apply_memory_component_delta(removed_bytes, added_bytes)?;

                    // Update heap with both mutations
                    self.mutate_heap(|heap| {
                        // Update original array
                        if let Some(array_obj) = heap.get_mut(heap_index) {
                            array_obj
                                .properties
                                .retain(|k, _| k.parse::<usize>().is_err());
                            for (i, value) in elements.iter().enumerate() {
                                array_obj.properties.insert(i.to_string(), value.clone());
                            }
                            array_obj
                                .properties
                                .insert("length".to_string(), Value::Int(elements.len() as i64));
                            // splice rewrites the array densely as 0..len, so the
                            // dense-length cache must follow the new length. Without
                            // this the cache stays at the PRE-splice length, and the
                            // `ArrayPush` fast path (which trusts cached_dense_length
                            // as the next write index) appends past the end — e.g.
                            // `[1,2,3,4,5].splice(0,3); a.push(9)` would write index 5
                            // instead of 2, leaving holes. Mirrors the cache update
                            // every dense-construction site already performs.
                            array_obj.cached_dense_length = Some(elements.len() as u32);
                        }

                        // Push result array
                        heap.push(result_obj);
                    });

                    Ok(Value::Object(result_id))
                } else {
                    Ok(Value::Undefined)
                }
            }
            "builtin:Number" => {
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::Number)
            }
            "builtin:Boolean" => {
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::Boolean)
            }
            "builtin:StringPrototypeMatch" => {
                if args.count == 0 {
                    return Ok(Value::Null);
                }

                // Get the this value (should be a string)
                let this_val = self.read_reg(args.start)?;
                let this_str = match this_val {
                    Value::Str(s) => s.clone(),
                    Value::Int(i) => JsString::from(i.to_string()),
                    Value::Float(f) => JsString::from(f.to_string()),
                    Value::Bool(b) => JsString::from(b.to_string()),
                    Value::Null => JsString::from("null"),
                    Value::Undefined => JsString::from("undefined"),
                    _ => return Ok(Value::Null),
                };

                let pattern_val = self.read_reg(args.start + 1)?;
                self.string_match_value(&this_str, &pattern_val)
            }
            "builtin:Symbol" => {
                // ES2020 19.4.1.1 step 3 / 19.4.2.2 step 1: ToString of an
                // object description or key runs its toString (or
                // @@toPrimitive); it used the non-calling display string.
                let description = if args.count > 0 {
                    let value = self.read_reg(args.start)?;
                    let value =
                        if value.is_object_like() {
                            Value::Str(self.scoped_conversion(|this| {
                                this.conversion_to_string(module, value)
                            })?)
                        } else {
                            value
                        };
                    self.symbol_description_argument(Some(value))?
                } else {
                    None
                };
                self.allocate_private_symbol(description).map(Value::Symbol)
            }
            "builtin:SymbolFor" => {
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let value = if value.is_object_like() {
                    Value::Str(
                        self.scoped_conversion(|this| this.conversion_to_string(module, value))?,
                    )
                } else {
                    value
                };
                let key = self.symbol_registry_key_argument(value)?;
                self.intern_global_symbol(key).map(Value::Symbol)
            }
            "builtin:SymbolKeyFor" => {
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let Value::Symbol(symbol) = value else {
                    return Err(InterpreterError::TypeError {
                        expected: "Symbol".to_string(),
                        got: value.type_name().to_string(),
                    });
                };
                Ok(self
                    .symbol_state
                    .key_for(symbol)
                    .cloned()
                    .map(Value::Str)
                    .unwrap_or(Value::Undefined))
            }
            "builtin:typeof" => {
                // typeof operator implementation
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };

                let type_string = match value {
                    Value::Undefined => "undefined",
                    Value::Bool(_) => "boolean",
                    Value::Int(_) | Value::Float(_) => "number",
                    Value::BigInt(_) => "bigint",
                    Value::Symbol(_) => "symbol",
                    Value::Str(_) => "string",
                    // A Symbol is a Value::Symbol; no heap object is one,
                    // whatever its properties (bd-9vouw.150).
                    Value::Object(_) => "object",
                    Value::Function(_) | Value::Closure(_) | Value::BuiltinFunction(_) => {
                        "function"
                    }
                    Value::Null => "object", // In JavaScript, typeof null === "object"
                    _ => "object",
                };

                Ok(Value::str(type_string))
            }
            "builtin:ArrayPrototypeFlat" => {
                // Array.prototype.flat([depth]) implementation (simplified)
                if args.count == 0 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-arrays return undefined
                };

                let depth = if args.count > 1 {
                    let depth_val = self.read_reg(args.start + 1)?;
                    match depth_val {
                        Value::Int(i) => i.max(0) as usize,
                        Value::Float(f) => f.inner().max(0.0) as usize,
                        _ => 1,
                    }
                } else {
                    1
                };

                // Snapshot outer array length + outer elements; also snapshot
                // every inner (level-1) array's elements. Done entirely under
                // immutable borrows so we can safely allocate + set below.
                let outer_snapshot: Vec<Value> =
                    if let Some(array_obj) = self.heap.get(array_id.0 as usize) {
                        let length = array_obj
                            .properties
                            .get("length")
                            .and_then(|v| match v {
                                Value::Int(i) => Some(*i as usize),
                                Value::Float(f) => Some(f.inner() as usize),
                                _ => None,
                            })
                            .unwrap_or(0);
                        (0..length)
                            .filter_map(|i| array_obj.properties.get(&i.to_string()).cloned())
                            .collect()
                    } else {
                        Vec::new()
                    };

                if !outer_snapshot.is_empty() {
                    // Pre-flatten level 1 under immutable borrows.
                    let mut flat_elements: Vec<Value> = Vec::new();
                    for value in outer_snapshot {
                        let flattened = if depth > 0 {
                            match &value {
                                Value::Object(inner_id) => {
                                    if let Some(inner_obj) = self.heap.get(inner_id.0 as usize) {
                                        if inner_obj.properties.contains_key("length") {
                                            let inner_length = inner_obj
                                                .properties
                                                .get("length")
                                                .and_then(|v| match v {
                                                    Value::Int(i) => Some(*i as usize),
                                                    Value::Float(f) => Some(f.inner() as usize),
                                                    _ => None,
                                                })
                                                .unwrap_or(0);
                                            let elems: Vec<Value> = (0..inner_length)
                                                .filter_map(|j| {
                                                    inner_obj
                                                        .properties
                                                        .get(&j.to_string())
                                                        .cloned()
                                                })
                                                .collect();
                                            Some(elems)
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                }
                                _ => None,
                            }
                        } else {
                            None
                        };
                        match flattened {
                            Some(elems) => flat_elements.extend(elems),
                            None => flat_elements.push(value),
                        }
                    }

                    // Create a new flattened array
                    let result_id = self.alloc_object_with_prototype(None)?;

                    // Set up result array
                    for (i, value) in flat_elements.iter().enumerate() {
                        self.set_object_property(result_id, i.to_string(), value.clone())?;
                    }
                    self.set_object_property(
                        result_id,
                        "length".to_string(),
                        Value::Int(flat_elements.len() as i64),
                    )?;

                    Ok(Value::Object(result_id))
                } else {
                    Ok(Value::Undefined)
                }
            }
            // Removed duplicate StringPrototypeSearch - implementation at line ~13482 has better JS fallbacks
            "builtin:ArrayPrototypeSome" => {
                let (array_id, callback, this_arg, length) =
                    self.validate_array_callback_structure(args, "Array.prototype.some")?;

                for index in 0..length {
                    let Some(element) = self.array_index_get(module, array_id, index)? else {
                        continue;
                    };

                    let predicate_result = self.invoke_array_callback(
                        module,
                        &callback,
                        this_arg.clone(),
                        element,
                        index,
                        array_id,
                    )?;
                    if predicate_result.is_truthy() {
                        return Ok(Value::Bool(true));
                    }
                }

                Ok(Value::Bool(false))
            }
            "builtin:MathSign" => {
                // Math.sign(x) implementation - returns sign of a number
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let arg = self.math_argument_value(args.start, module)?;
                let num = match arg {
                    Value::Int(i) => {
                        if i > 0 {
                            return Ok(Value::Int(1));
                        } else if i < 0 {
                            return Ok(Value::Int(-1));
                        } else {
                            return Ok(Value::Int(0));
                        }
                    }
                    Value::Float(f) => f.inner(),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    Value::Undefined => f64::NAN,
                    _ => f64::NAN,
                };

                if num.is_nan() {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else if num > 0.0 {
                    Ok(Value::Int(1))
                } else if num < 0.0 {
                    Ok(Value::Int(-1))
                } else {
                    // +0 and -0 answer themselves (Math.sign(-0) is -0).
                    Ok(Value::Float(Float64::new(num)))
                }
            }
            "builtin:ObjectDefineProperty" => {
                // Object.defineProperty(O, P, Attributes), ES2020 19.1.2.4:
                // TypeError unless O and Attributes are objects.
                let obj_val = self.arg_or_undefined(args, 0)?;
                let prop_val = self.arg_or_undefined(args, 1)?;
                // Step 2, ToPropertyKey(P), runs an object key's hooks after
                // step 1's type check (bd-9vouw.279).
                let prop_val = if obj_val.is_object_like() {
                    self.coerce_to_property_key(module, prop_val)?
                } else {
                    prop_val
                };
                let prop_name = self.executable_property_key_from_value(&prop_val);
                let descriptor_val = self.arg_or_undefined(args, 2)?;
                let Some(obj_id) = self.own_property_holder(module, &obj_val, true)? else {
                    return Err(InterpreterError::TypeError {
                        expected: "object target for Object.defineProperty".to_string(),
                        got: obj_val.type_name().to_string(),
                    });
                };
                let mut descriptor = self.read_property_descriptor(module, &descriptor_val)?;
                // A mapped arguments index writes a parameter cell as well
                // as this property. Admit descriptor provenance before that
                // write, including when writable:false disconnects the map.
                let mapped_target = self.has_mapped_arguments_target(args);
                if mapped_target {
                    let mutation_label = self.join_arg_range_with_object_mutation_label(args)?;
                    self.join_object_mutation_label(obj_id, &mutation_label)?;
                }
                // ES2020 9.4.2.4 steps 3-5 for an array's `length`:
                // ToUint32(value), then ToNumber(value), each observable (an
                // object's valueOf runs twice); a RangeError when they differ
                // (bd-9vouw.279).
                if prop_name.as_str() == Some("length")
                    && self
                        .heap
                        .get(obj_id.0 as usize)
                        .is_some_and(|object| object.is_array)
                    && let Some(value) = descriptor.value.take()
                {
                    descriptor.value = Some(self.array_length_definition_value(module, value)?);
                }
                // A Proxy defines through its defineProperty trap or its
                // target (bd-9vouw.147).
                if !self
                    .proxy_aware_define_own_property(module, obj_id, prop_name, descriptor, 0)?
                {
                    return Err(InterpreterError::TypeError {
                        expected: DEFINE_PROPERTY_REJECTED.to_string(),
                        got: "non-configurable, non-writable or non-extensible target".to_string(),
                    });
                }
                if !mapped_target {
                    let mutation_label = self.join_arg_range_with_object_mutation_label(args)?;
                    self.join_object_mutation_label(obj_id, &mutation_label)?;
                }
                Ok(obj_val) // Return the original object
            }
            "builtin:ObjectDefineProperties" => {
                // Object.defineProperties(O, Properties), ES2020 19.1.2.3.
                let obj_val = self.arg_or_undefined(args, 0)?;
                let Some(obj_id) = self.own_property_holder(module, &obj_val, true)? else {
                    return Err(InterpreterError::TypeError {
                        expected: "object target for Object.defineProperties".to_string(),
                        got: obj_val.type_name().to_string(),
                    });
                };
                let props_val = self.arg_or_undefined(args, 1)?;
                let mapped_target = self.has_mapped_arguments_target(args);
                if mapped_target {
                    let mutation_label = self.join_arg_range_with_object_mutation_label(args)?;
                    self.join_object_mutation_label(obj_id, &mutation_label)?;
                }
                self.object_define_properties(
                    module,
                    obj_id,
                    props_val,
                    "Object.defineProperties",
                )?;
                if !mapped_target {
                    let mutation_label = self.join_arg_range_with_object_mutation_label(args)?;
                    self.join_object_mutation_label(obj_id, &mutation_label)?;
                }
                Ok(obj_val)
            }
            "builtin:Proxy" => {
                let (target, call_target) =
                    self.read_proxy_target_argument(module, args, "Proxy target object")?;
                let handler = self.read_object_argument(args, 1, "Proxy handler object")?;
                let proxy_id = self.create_proxy_object(target, handler)?;
                self.proxy_value(proxy_id, call_target)
            }
            "builtin:ProxyRevocable" => {
                let (target, call_target) =
                    self.read_proxy_target_argument(module, args, "Proxy.revocable target object")?;
                let handler =
                    self.read_object_argument(args, 1, "Proxy.revocable handler object")?;
                let proxy_id = self.create_proxy_object(target, handler)?;
                let proxy = self.proxy_value(proxy_id, call_target)?;
                let result_id = self.alloc_object_with_properties(&[
                    ("proxy", proxy),
                    (
                        "revoke",
                        Value::BuiltinFunction(BuiltinFunction::proxy_revoke(proxy_id)),
                    ),
                ])?;
                Ok(Value::Object(result_id))
            }
            "builtin:ReflectGetPrototypeOf" => self.object_integrity_builtin(
                module,
                args,
                ObjectIntegrityOperation::GetPrototype,
                true,
            ),
            "builtin:ReflectSetPrototypeOf" => self.object_integrity_builtin(
                module,
                args,
                ObjectIntegrityOperation::SetPrototype,
                true,
            ),
            "builtin:ReflectIsExtensible" => self.object_integrity_builtin(
                module,
                args,
                ObjectIntegrityOperation::IsExtensible,
                true,
            ),
            "builtin:ReflectPreventExtensions" => self.object_integrity_builtin(
                module,
                args,
                ObjectIntegrityOperation::PreventExtensions,
                true,
            ),
            "builtin:ReflectGet" => {
                self.reflect_property_builtin(module, args, ReflectPropertyOperation::Get)
            }
            "builtin:ReflectSet" => {
                self.reflect_property_builtin(module, args, ReflectPropertyOperation::Set)
            }
            "builtin:ReflectHas" => {
                self.reflect_property_builtin(module, args, ReflectPropertyOperation::Has)
            }
            "builtin:ReflectOwnKeys" => {
                // A function is an object: its names, then its symbols.
                let value = self.arg_or_undefined(args, 0)?;
                if !matches!(value, Value::Object(_)) && value.is_callable() {
                    let mut keys = self.function_own_property_names(module, &value)?;
                    keys.extend(self.function_own_property_symbols(module, &value)?);
                    let array_id = self.alloc_array_from_values(&keys)?;
                    return Ok(Value::Object(array_id));
                }
                // So is a promise, generator or iterator (bd-9vouw.149).
                if Self::has_exotic_backing_object(&value) {
                    let keys = self.exotic_own_property_keys(module, &value)?;
                    let array_id = self.alloc_array_from_values(&keys)?;
                    return Ok(Value::Object(array_id));
                }
                let target = self.read_object_argument(args, 0, "Reflect.ownKeys target object")?;
                let keys = self.proxy_aware_own_property_keys(module, target, 0)?;
                self.join_pending_hostcall_stream_label(target)?;
                let array_id = self.alloc_array_from_values(&keys)?;
                Ok(Value::Object(array_id))
            }
            "builtin:ReflectDeleteProperty" => {
                self.reflect_property_builtin(module, args, ReflectPropertyOperation::Delete)
            }
            "builtin:ReflectApply" => self.reflect_invocation_builtin(module, args, false),
            "builtin:ReflectConstruct" => self.reflect_invocation_builtin(module, args, true),
            "builtin:ConstructSuperSpread" => self.construct_super_spread_builtin(module, args),
            "builtin:Map" => {
                // Map([iterable]) constructor implementation
                let (map_id, entries_id) = self.alloc_empty_map()?;

                let iterable = self.arg_or_undefined(args, 0)?;
                if !matches!(iterable, Value::Undefined | Value::Null) {
                    match self.collection_seed_adder(module, map_id, "Map")? {
                        None => self.seed_map_entries_from_iterable(
                            module,
                            entries_id,
                            Some(map_id),
                            iterable,
                        )?,
                        Some(adder) => {
                            self.seed_collection_with_adder(module, map_id, adder, true, iterable)?
                        }
                    }
                }

                Ok(Value::Object(map_id))
            }
            "builtin:Set" => {
                // Set([iterable]) constructor implementation
                let set_id = self.alloc_empty_set()?;
                let values_id = self
                    .collection_storage_id(set_id, "Set", "__values")
                    .expect("a new Set has its value storage");

                let iterable = self.arg_or_undefined(args, 0)?;
                if !matches!(iterable, Value::Undefined | Value::Null) {
                    match self.collection_seed_adder(module, set_id, "Set")? {
                        None => self.seed_set_values_from_iterable(
                            module,
                            values_id,
                            Some(set_id),
                            iterable,
                            false,
                        )?,
                        Some(adder) => {
                            self.seed_collection_with_adder(module, set_id, adder, false, iterable)?
                        }
                    }
                }

                Ok(Value::Object(set_id))
            }
            "builtin:WeakMap" => {
                let previous_heap_len = self.heap.len();
                let previous_estimated_bytes = self.estimated_memory_bytes;
                let mut published_weakmap = None;
                let outcome = (|| {
                    let weakmap_prototype = self.ensure_builtin_prototype("WeakMap")?;
                    let weakmap_id = self.alloc_object_with_prototype(Some(weakmap_prototype))?;
                    published_weakmap = Some(weakmap_id);

                    self.set_object_brand(weakmap_id, "WeakMap")?;

                    self.apply_memory_component_delta(0, MEMORY_ESTIMATE_MAP_ENTRY_BYTES)?;
                    self.weakmap_storage
                        .insert(weakmap_id, WeakMapStorage::new());

                    Ok(weakmap_id)
                })();
                if outcome.is_err() {
                    if let Some(weakmap_id) = published_weakmap {
                        self.weakmap_storage.remove(&weakmap_id);
                    }
                    self.rollback_heap_to_len(previous_heap_len);
                    self.estimated_memory_bytes = previous_estimated_bytes;
                }
                let weakmap_id = outcome?;
                // Seeding runs after that rollback boundary: it can run guest
                // code (a user iterator, an entry getter) whose allocations
                // the program may keep, so a seeding error must not roll the
                // heap back. The seed's own application is atomic.
                let iterable = self.arg_or_undefined(args, 0)?;
                if !matches!(iterable, Value::Undefined | Value::Null) {
                    match self.collection_seed_adder(module, weakmap_id, "WeakMap")? {
                        None => self.seed_weakmap_from_iterable(module, weakmap_id, iterable)?,
                        Some(adder) => self.seed_collection_with_adder(
                            module, weakmap_id, adder, true, iterable,
                        )?,
                    }
                }
                Ok(Value::Object(weakmap_id))
            }
            "builtin:WeakRef" => self.construct_weak_ref(args),
            "builtin:FinalizationRegistry" => self.construct_finalization_registry(args),
            "builtin:WeakSet" => {
                // WeakSet([iterable]) constructor implementation (simplified)
                let weakset_prototype = self.ensure_builtin_prototype("WeakSet")?;
                let weakset_id = self.alloc_object_with_prototype(Some(weakset_prototype))?;
                let values_id = self.alloc_object_with_prototype(None)?;

                self.set_object_brand(weakset_id, "WeakSet")?;
                self.set_object_property(
                    weakset_id,
                    "__values".to_string(),
                    Value::Object(values_id),
                )?;
                self.hide_internal_slots(weakset_id, &["__values"])?;

                // Note: In a full implementation, WeakSet would use weak references
                let iterable = self.arg_or_undefined(args, 0)?;
                if !matches!(iterable, Value::Undefined | Value::Null) {
                    match self.collection_seed_adder(module, weakset_id, "WeakSet")? {
                        None => self.seed_set_values_from_iterable(
                            module, values_id, None, iterable, true,
                        )?,
                        Some(adder) => self.seed_collection_with_adder(
                            module, weakset_id, adder, false, iterable,
                        )?,
                    }
                }

                Ok(Value::Object(weakset_id))
            }
            "builtin:MapPrototypeSet" => {
                // Map.prototype.set(key, value) implementation
                if args.count < 3 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let map_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be maps
                };

                // Check if it's actually a Map
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if map_obj.brand() != Some("Map") {
                        return Ok(Value::Undefined);
                    }
                }

                let key = self.read_reg(args.start + 1)?;
                let value = self.read_reg(args.start + 2)?;
                self.map_collection_set(map_id, key, value)
            }
            "builtin:MapPrototypeGet" => {
                // Map.prototype.get(key) implementation
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let map_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be maps
                };

                // Check if it's actually a Map
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if map_obj.brand() != Some("Map") {
                        return Ok(Value::Undefined);
                    }
                }

                let key = self.read_reg(args.start + 1)?;

                // Get the value from the map
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if let Some(Value::Object(entries_id)) = map_obj.properties.get("__entries") {
                        if let Some(entries_obj) = self.heap.get(entries_id.0 as usize) {
                            let key_str = Self::collection_key_repr(&key);

                            if let Some(value) = entries_obj.properties.get(&key_str) {
                                return Ok(value.clone());
                            }
                        }
                    }
                }

                Ok(Value::Undefined)
            }
            "builtin:SetPrototypeAdd" => {
                // Set.prototype.add(value) implementation
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let set_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be sets
                };

                // Check if it's actually a Set
                if let Some(set_obj) = self.heap.get(set_id.0 as usize) {
                    if set_obj.brand() != Some("Set") {
                        return Ok(Value::Undefined);
                    }
                }

                let value = self.read_reg(args.start + 1)?;
                self.set_collection_add(set_id, value)
            }
            "builtin:SetPrototypeHas" => {
                // Set.prototype.has(value) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let set_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects can't be sets
                };

                // Check if it's actually a Set
                if let Some(set_obj) = self.heap.get(set_id.0 as usize) {
                    if set_obj.brand() != Some("Set") {
                        return Ok(Value::Bool(false));
                    }
                }

                let value = self.read_reg(args.start + 1)?;

                // Check if the set has the value
                if let Some(set_obj) = self.heap.get(set_id.0 as usize) {
                    if let Some(Value::Object(values_id)) = set_obj.properties.get("__values") {
                        if let Some(values_obj) = self.heap.get(values_id.0 as usize) {
                            let value_str = Self::collection_key_repr(&value);

                            if values_obj.properties.contains_key(&value_str) {
                                return Ok(Value::Bool(true));
                            }
                        }
                    }
                }

                Ok(Value::Bool(false))
            }

            "builtin:MapPrototypeHas" => {
                // Map.prototype.has(key) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let map_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects can't be maps
                };

                // Check if it's actually a Map
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if map_obj.brand() != Some("Map") {
                        return Ok(Value::Bool(false));
                    }
                }

                let key = self.read_reg(args.start + 1)?;

                // Check if the map has the key
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if let Some(Value::Object(entries_id)) = map_obj.properties.get("__entries") {
                        if let Some(entries_obj) = self.heap.get(entries_id.0 as usize) {
                            let key_str = Self::collection_key_repr(&key);

                            if entries_obj.properties.contains_key(&key_str) {
                                return Ok(Value::Bool(true));
                            }
                        }
                    }
                }

                Ok(Value::Bool(false))
            }

            "builtin:MapPrototypeDelete" => {
                // Map.prototype.delete(key) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let map_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects can't be maps
                };

                // Check if it's actually a Map
                if let Some(map_obj) = self.heap.get(map_id.0 as usize) {
                    if map_obj.brand() != Some("Map") {
                        return Ok(Value::Bool(false));
                    }
                } else {
                    return Ok(Value::Bool(false));
                }

                let key = self.read_reg(args.start + 1)?;
                Ok(Value::Bool(self.collection_delete(
                    map_id,
                    "Map",
                    "__entries",
                    &key,
                )?))
            }

            "builtin:SetPrototypeDelete" => {
                // Set.prototype.delete(value) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let set_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects can't be sets
                };

                // Check if it's actually a Set
                if let Some(set_obj) = self.heap.get(set_id.0 as usize) {
                    if set_obj.brand() != Some("Set") {
                        return Ok(Value::Bool(false));
                    }
                } else {
                    return Ok(Value::Bool(false));
                }

                let value = self.read_reg(args.start + 1)?;
                Ok(Value::Bool(
                    self.collection_delete(set_id, "Set", "__values", &value)?,
                ))
            }

            "builtin:SetPrototypeClear" => {
                // Set.prototype.clear() implementation
                let this_val = self.read_reg(args.start)?;
                let set_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be sets
                };

                // Check if it's actually a Set
                if let Some(set_obj) = self.heap.get(set_id.0 as usize) {
                    if set_obj.brand() != Some("Set") {
                        return Ok(Value::Undefined);
                    }
                } else {
                    return Ok(Value::Undefined);
                }

                self.collection_clear(set_id, "Set", "__values")
            }

            "builtin:ArrayPrototypeLastIndexOf" => {
                // Array.prototype.lastIndexOf(searchElement, fromIndex) implementation
                if args.count < 2 {
                    return Ok(Value::Int(-1));
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Int(-1)), // Non-objects can't be arrays
                };

                let search_element = self.read_reg(args.start + 1)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => return Ok(Value::Int(-1)),
                    }
                } else {
                    return Ok(Value::Int(-1));
                };

                if length == 0 {
                    return Ok(Value::Int(-1));
                }

                // Get fromIndex if provided, otherwise start from the end
                let from_index = if args.count >= 3 {
                    let from_value = self.read_reg(args.start + 2)?;
                    Self::require_number_coercible_index(
                        &from_value,
                        "Array.prototype.lastIndexOf",
                    )?;
                    match from_value {
                        Value::Int(idx) => idx,
                        Value::Float(idx) => idx.inner() as i64,
                        _ => length as i64 - 1,
                    }
                } else {
                    length as i64 - 1
                };

                // Convert negative indices to positive
                let start_idx = if from_index < 0 {
                    let adjusted = (length as i64) + from_index;
                    if adjusted < 0 {
                        return Ok(Value::Int(-1));
                    }
                    adjusted as usize
                } else {
                    (from_index as usize).min(length - 1)
                };

                // Search backwards from start_idx
                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    for i in (0..=start_idx).rev() {
                        if let Some(element) = obj.properties.get(&i.to_string()) {
                            if Self::values_equal(element, &search_element) {
                                return Ok(Value::Int(i as i64));
                            }
                        }
                    }
                }

                Ok(Value::Int(-1))
            }

            "builtin:ArrayPrototypeFindIndex" => {
                let (array_id, callback, this_arg, length) =
                    self.validate_array_callback_structure(args, "Array.prototype.findIndex")?;

                for index in 0..length {
                    let element = self
                        .array_index_get(module, array_id, index)?
                        .unwrap_or(Value::Undefined);
                    let predicate_result = self.invoke_array_callback(
                        module,
                        &callback,
                        this_arg.clone(),
                        element,
                        index,
                        array_id,
                    )?;
                    if predicate_result.is_truthy() {
                        let index_value =
                            i64::try_from(index).map_err(|_| InterpreterError::TypeError {
                                expected: "array index within i64".to_string(),
                                got: index.to_string(),
                            })?;
                        return Ok(Value::Int(index_value));
                    }
                }

                Ok(Value::Int(-1))
            }

            "builtin:StringPrototypeCharCodeAt" => {
                let receiver = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let index = if args.count >= 2 {
                    Some(self.read_reg(args.start + 1)?)
                } else {
                    None
                };
                Self::string_prototype_char_code_at_value(receiver, index)
            }

            "builtin:StringFromCharCode" => {
                let values = self.builtin_argument_values(args)?;
                self.string_from_char_code(module, values)
            }

            "builtin:StringRaw" => {
                // String.raw(template, ...substitutions) (bd-bl591, ES2020
                // 21.1.2.4): raw = ToObject(Get(ToObject(template), "raw")),
                // LengthOfArrayLike(raw) segments, each ToString(Get(raw, i)),
                // with ToString(substitutions[i]) between consecutive ones.
                // Every step is observable: an undefined / null template or
                // raw is a TypeError, as is a Symbol length, segment or
                // substitution, and getters and conversion hooks run in that
                // order. It returned "" for a missing template or raw and
                // stringified Symbols.
                let template = self.arg_or_undefined(args, 0)?;
                let raw = match template {
                    Value::Undefined | Value::Null => {
                        return Err(self.throw_js_error(
                            "TypeError",
                            "Cannot convert undefined or null to object".to_string(),
                        ));
                    }
                    Value::Object(template_id) => self.proxy_aware_get_property(
                        module,
                        template_id,
                        "raw",
                        template.clone(),
                        0,
                    )?,
                    _ => Value::Undefined,
                };
                let raw_id = match raw {
                    Value::Object(raw_id) => raw_id,
                    // A string's code units are a String wrapper's elements.
                    Value::Str(text) => {
                        let units = self
                            .string_index_entries(&text)?
                            .into_iter()
                            .map(|(_, unit)| unit)
                            .collect::<Vec<_>>();
                        self.alloc_array_from_values(&units)?
                    }
                    Value::Undefined | Value::Null => {
                        return Err(self.throw_js_error(
                            "TypeError",
                            "Cannot convert undefined or null to object".to_string(),
                        ));
                    }
                    // Other primitives' wrappers have no length: no segments.
                    _ => return Ok(Value::str(String::new())),
                };
                let length = self.proxy_aware_get_property(
                    module,
                    raw_id,
                    "length",
                    Value::Object(raw_id),
                    0,
                )?;
                let length = self
                    .scoped_conversion(|this| this.conversion_to_number(module, length, false))?;
                // ToLength.
                let length = if length.is_nan() || length <= 0.0 {
                    0
                } else {
                    length.min(9_007_199_254_740_991.0).floor() as u64
                };
                let mut result = String::new();
                for index in 0..length {
                    let segment = self.proxy_aware_get_property(
                        module,
                        raw_id,
                        &index.to_string(),
                        Value::Object(raw_id),
                        0,
                    )?;
                    let segment =
                        self.scoped_conversion(|this| this.conversion_to_string(module, segment))?;
                    result.push_str(segment.as_ref());
                    self.check_string_limit(result.len())?;
                    if index + 1 == length {
                        break;
                    }
                    // Substitutions occupy argument slots 1.. (slot 0 is the
                    // template); past the last one the separator is "".
                    let slot = u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1);
                    if slot < args.count {
                        let substitution = self.arg_or_undefined(args, slot)?;
                        let substitution = self.scoped_conversion(|this| {
                            this.conversion_to_string(module, substitution)
                        })?;
                        result.push_str(substitution.as_ref());
                    }
                }
                Ok(Value::str(result))
            }

            "builtin:ObjectGetOwnPropertyNames" => {
                // Object.getOwnPropertyNames(obj) implementation
                let obj_val = self.arg_or_undefined(args, 0)?;
                match obj_val {
                    // ToObject (ES2020 19.1.2.10 GetOwnPropertyKeys step 1).
                    Value::Undefined | Value::Null => Err(self.throw_js_error(
                        "TypeError",
                        "Cannot convert undefined or null to object".to_string(),
                    )),
                    // A String wrapper's own names: its indices, then length.
                    Value::Str(ref text) => {
                        let mut names = self
                            .string_index_entries(text)?
                            .into_iter()
                            .map(|(key, _)| Value::Str(key))
                            .collect::<Vec<_>>();
                        names.push(Value::str("length"));
                        Ok(Value::Object(self.alloc_array_from_values(&names)?))
                    }
                    Value::Object(obj_id) if self.active_proxy_record(obj_id)?.is_some() => {
                        // bd-9trje: getOwnPropertyNames returns EVERY own String key
                        // (enumerable or not) surfaced by the ownKeys trap — no
                        // per-key descriptor consultation.
                        let property_name_values = self
                            .proxy_aware_own_property_keys(module, obj_id, 0)?
                            .into_iter()
                            .filter(|key| matches!(key, Value::Str(_)))
                            .collect::<Vec<_>>();
                        let array_id = self.alloc_array_from_values(&property_name_values)?;
                        Ok(Value::Object(array_id))
                    }
                    Value::Object(obj_id) => {
                        let mut property_name_values = self
                            .indexed_own_entries(obj_id)?
                            .into_iter()
                            .map(|(key, _)| Value::Str(key))
                            .collect::<Vec<_>>();
                        // A String wrapper's `length` follows its indices, as
                        // for a string primitive above (bd-9vouw.356).
                        let string_wrapper =
                            matches!(self.primitive_wrapper_value(obj_id), Some(Value::Str(_)));
                        if string_wrapper {
                            property_name_values.push(Value::str("length"));
                        }
                        // bd-9vouw.122: %Array.prototype%'s virtual names first.
                        let virtual_names = self
                            .canonical_prototype_virtual_own_keys(obj_id)
                            .into_iter()
                            .filter(|key| matches!(key, Value::Str(_)))
                            .collect::<Vec<_>>();
                        property_name_values.extend(virtual_names.iter().cloned());
                        property_name_values.extend(
                            self.heap
                                .get(obj_id.0 as usize)
                                .ok_or(InterpreterError::ObjectNotFound { id: obj_id.0 })?
                                .properties
                                .exact_keys()
                                .into_iter()
                                .filter(|key| {
                                    self.own_runtime_property_visible(obj_id, key)
                                        && !(string_wrapper && key.as_str() == Some("length"))
                                })
                                .map(Value::Str)
                                .filter(|key| !virtual_names.contains(key)),
                        );
                        self.join_pending_hostcall_stream_label(obj_id)?;
                        let array_id = self.alloc_array_from_values(&property_name_values)?;
                        Ok(Value::Object(array_id))
                    }
                    ref function if function.is_callable() => {
                        let names = self.function_own_property_names(module, function)?;
                        let array_id = self.alloc_array_from_values(&names)?;
                        Ok(Value::Object(array_id))
                    }
                    ref exotic if Self::has_exotic_backing_object(exotic) => {
                        let names = self
                            .exotic_own_property_keys(module, exotic)?
                            .into_iter()
                            .filter(|key| matches!(key, Value::Str(_)))
                            .collect::<Vec<_>>();
                        let array_id = self.alloc_array_from_values(&names)?;
                        Ok(Value::Object(array_id))
                    }
                    _ => {
                        // Non-object argument, return empty array
                        let empty_array_id = self.alloc_array_from_values(&[])?;
                        Ok(Value::Object(empty_array_id))
                    }
                }
            }

            "builtin:ObjectGetOwnPropertySymbols" => {
                let values = match self.arg_or_undefined(args, 0)? {
                    // ToObject (ES2020 19.1.2.11 GetOwnPropertyKeys step 1).
                    Value::Undefined | Value::Null => {
                        return Err(self.throw_js_error(
                            "TypeError",
                            "Cannot convert undefined or null to object".to_string(),
                        ));
                    }
                    Value::Object(object_id) => self
                        .proxy_aware_own_property_keys(module, object_id, 0)?
                        .into_iter()
                        .filter(|key| matches!(key, Value::Symbol(_)))
                        .collect::<Vec<_>>(),
                    ref function if function.is_callable() => {
                        self.function_own_property_symbols(module, function)?
                    }
                    ref exotic if Self::has_exotic_backing_object(exotic) => self
                        .exotic_own_property_keys(module, exotic)?
                        .into_iter()
                        .filter(|key| matches!(key, Value::Symbol(_)))
                        .collect(),
                    _ => Vec::new(),
                };
                Ok(Value::Object(self.alloc_array_from_values(&values)?))
            }

            "builtin:ObjectGetPrototypeOf" => self.object_integrity_builtin(
                module,
                args,
                ObjectIntegrityOperation::GetPrototype,
                false,
            ),

            "builtin:PromiseReject" => {
                // Promise.reject(reason) implementation
                let reason = if args.count >= 1 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };

                // Create a rejected Promise object
                let promise_id = self.alloc_object_with_prototype(None)?;

                // Set Promise metadata
                self.set_object_brand(promise_id, "Promise")?;
                self.set_object_property(
                    promise_id,
                    "__state".to_string(),
                    Value::str("rejected"),
                )?;
                self.set_object_property(promise_id, "__value".to_string(), reason)?;

                Ok(Value::Object(promise_id))
            }

            "builtin:MathAtan2" => {
                // Math.atan2(y, x) implementation
                if args.count < 2 {
                    return Ok(Value::Float(f64::NAN.into()));
                }

                let y_val = self.math_argument_value(args.start, module)?;
                let x_val = self.math_argument_value(args.start + 1, module)?;

                let y = match y_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    _ => f64::NAN,
                };

                let x = match x_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    _ => f64::NAN,
                };

                let result = y.atan2(x);
                Ok(Value::Float(result.into()))
            }

            "builtin:FunctionPrototypeCall" => {
                let function = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                self.forward_function_invocation(
                    module,
                    function,
                    (args.count > 0).then_some(args.start),
                    RegRange {
                        start: args.start.saturating_add(u32::from(args.count > 0)),
                        count: args.count.saturating_sub(1),
                    },
                    false,
                )
            }

            "builtin:MathAsin" => {
                // Math.asin(x) implementation - arcsine
                if args.count == 0 {
                    return Ok(Value::Float(f64::NAN.into()));
                }

                let x_val = self.math_argument_value(args.start, module)?;
                let x = match x_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    _ => f64::NAN,
                };

                let result = x.asin();
                Ok(Value::Float(result.into()))
            }

            "builtin:MathAcos" => {
                // Math.acos(x) implementation - arccosine
                if args.count == 0 {
                    return Ok(Value::Float(f64::NAN.into()));
                }

                let x_val = self.math_argument_value(args.start, module)?;
                let x = match x_val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    _ => f64::NAN,
                };

                let result = x.acos();
                Ok(Value::Float(result.into()))
            }

            // `new RegExp(...)` and RegExp literals.
            "builtin:RegExp" => {
                let pattern_value = self.arg_or_undefined(args, 0)?;
                let flags_value = self.arg_or_undefined(args, 1)?;
                self.construct_regexp(module, pattern_value, flags_value, false)
            }

            "builtin:ArrayPrototypeReduceRight" => self.array_prototype_reduce_right(args, module),

            "builtin:StringPrototypeSubstr" => {
                // String.prototype.substr(start, length) implementation
                let this_val = self.read_reg(args.start)?;
                let string_val = match this_val {
                    Value::Str(s) => s.to_string(),
                    _ => {
                        // Try to convert to string
                        match this_val {
                            Value::Int(n) => n.to_string(),
                            Value::Float(f) => f.to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Null => "null".to_string(),
                            Value::Undefined => "undefined".to_string(),
                            _ => return Ok(Value::str("")),
                        }
                    }
                };

                let start_idx = if args.count >= 2 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(n) => n as i32,
                        Value::Float(f) => f.inner() as i32,
                        _ => 0,
                    }
                } else {
                    0
                };

                let length_param = if args.count >= 3 {
                    match self.read_reg(args.start + 2)? {
                        Value::Int(n) => Some(n as u32),
                        Value::Float(f) => Some(f.inner() as u32),
                        _ => None,
                    }
                } else {
                    None
                };

                let str_len = string_val.len() as i32;

                // Calculate actual start position
                let actual_start = if start_idx < 0 {
                    0.max(str_len + start_idx) as usize
                } else {
                    (start_idx as usize).min(str_len as usize)
                };

                // Calculate length
                let actual_length = if let Some(len) = length_param {
                    if len == 0 {
                        return Ok(Value::str(""));
                    }
                    len as usize
                } else {
                    (str_len as usize).saturating_sub(actual_start)
                };

                // Extract substring
                let chars: Vec<char> = string_val.chars().collect();
                let end_pos = (actual_start + actual_length).min(chars.len());

                if actual_start >= chars.len() {
                    Ok(Value::str(""))
                } else {
                    let result: String = chars[actual_start..end_pos].iter().collect();
                    Ok(Value::str(result))
                }
            }

            "builtin:NumberPrototypeToString" => {
                // Number.prototype.toString(radix) implementation - unified spec-consistent version
                let this_val = self.read_reg(args.start)?;

                let number_val = Self::number_receiver_to_f64(&this_val);

                let radix = self
                    .optional_number_hostcall_integer_arg(args, 1)?
                    .unwrap_or(10);

                if !(2..=36).contains(&radix) {
                    return Err(InterpreterError::RangeError {
                        message: format!("toString() radix must be between 2 and 36 (got {radix})"),
                    });
                }

                self.number_to_string_impl(number_val, radix as i32)
                    .map(Value::str)
            }

            "builtin:PromiseAll" => {
                self.dispatch_promise_combinator(PromiseCombinatorKind::All, args, module)
            }

            "builtin:FunctionPrototypeApply" => {
                let function = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                self.forward_function_invocation(
                    module,
                    function,
                    (args.count > 0).then_some(args.start),
                    RegRange {
                        start: args.start.saturating_add(u32::from(args.count > 0)),
                        count: args.count.saturating_sub(1),
                    },
                    true,
                )
            }

            "builtin:StringPrototypeLocaleCompare" => {
                // String.prototype.localeCompare(that) implementation
                let this_val = self.read_reg(args.start)?;
                let this_string = match this_val {
                    Value::Str(s) => s.to_string(),
                    _ => {
                        // Try to convert to string
                        match this_val {
                            Value::Int(n) => n.to_string(),
                            Value::Float(f) => f.to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Null => "null".to_string(),
                            Value::Undefined => "undefined".to_string(),
                            _ => return Ok(Value::Int(0)),
                        }
                    }
                };

                let that_string = if args.count >= 2 {
                    match self.read_reg(args.start + 1)? {
                        Value::Str(s) => s.to_string(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => String::new(),
                    }
                } else {
                    "undefined".to_string()
                };

                // The same collation as String.prototype.localeCompare.
                let options = if args.count >= 4 {
                    self.read_reg(args.start + 3)?
                } else {
                    Value::Undefined
                };
                let options = self.collation_options(&options)?;
                let ordering = collation::locale_compare(&this_string, &that_string, &options);
                Ok(Value::Int(ordering as i64))
            }

            "builtin:DatePrototypeGetTime" => {
                // Date.prototype.getTime() implementation
                let this_val = self.read_reg(args.start)?;
                let date_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Float(f64::NAN.into())), // Non-objects can't be dates
                };

                // Check if it's actually a Date
                if let Some(time) = self
                    .heap
                    .get(date_id.0 as usize)
                    .and_then(HeapObject::date_time)
                {
                    return Ok(Value::Float(Float64::new(time)));
                }

                // Invalid date or not a date object
                Ok(Value::Float(f64::NAN.into()))
            }

            // Locale-aware Date hostcall arms (bd-1j1wy). Keep this comment
            // textually distinct from the module-tail provider-section header:
            // the intl surface contract anchors an authority slice on that
            // exact header string and fails closed on duplicate matches
            // (bd-vpxgj).
            "builtin:DatePrototypeToLocaleString" => {
                let this_val = self.read_reg(args.start)?;
                let locale_arg = if args.count > 0 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::str("en-US")
                };

                let locale = match locale_arg {
                    Value::Str(s) => s.to_string(),
                    _ => "en-US".to_string(),
                };

                self.format_date_with_locale(this_val, &locale, DateFormatType::DateTime)
            }

            "builtin:DatePrototypeToLocaleDateString" => {
                let this_val = self.read_reg(args.start)?;
                let locale_arg = if args.count > 0 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::str("en-US")
                };

                let locale = match locale_arg {
                    Value::Str(s) => s.to_string(),
                    _ => "en-US".to_string(),
                };

                self.format_date_with_locale(this_val, &locale, DateFormatType::DateOnly)
            }

            "builtin:DatePrototypeToLocaleTimeString" => {
                let this_val = self.read_reg(args.start)?;
                let locale_arg = if args.count > 0 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::str("en-US")
                };

                let locale = match locale_arg {
                    Value::Str(s) => s.to_string(),
                    _ => "en-US".to_string(),
                };

                self.format_date_with_locale(this_val, &locale, DateFormatType::TimeOnly)
            }

            "builtin:DatePrototypeToString" => {
                // Date.prototype.toString() implementation
                let this_val = self.read_reg(args.start)?;
                let date_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::str("Invalid Date")), // Non-objects can't be dates
                };

                // Check if it's actually a Date
                if self
                    .heap
                    .get(date_id.0 as usize)
                    .is_some_and(|date_obj| date_obj.brand() == Some("Date"))
                {
                    // Use locale-aware formatting with default en-US locale
                    return self.format_date_with_locale(
                        this_val,
                        "en-US",
                        DateFormatType::DateTime,
                    );
                }

                // Invalid date or not a date object
                Ok(Value::str("Invalid Date"))
            }

            "builtin:ObjectPrototypeValueOf" => {
                // Object.prototype.valueOf() implementation
                let this_val = self.read_reg(args.start)?;
                self.object_prototype_value_of_value(this_val)
            }

            // Removed duplicate ArrayPrototypeFlatMap - implementation at line ~13119 is more complete
            "builtin:MathHypot" => {
                // Math.hypot(...values) implementation - Euclidean distance
                if args.count == 0 {
                    return Ok(Value::Float(0.0.into()));
                }

                let mut sum_of_squares = 0.0;
                let mut has_infinity = false;
                let mut has_nan = false;

                // Process all arguments
                for i in 0..args.count {
                    let arg_val = self.math_argument_value(args.start + i, module)?;
                    let num_val = match arg_val {
                        Value::Int(n) => n as f64,
                        Value::Float(f) => f.inner(),
                        _ => f64::NAN,
                    };

                    if num_val.is_nan() {
                        has_nan = true;
                    } else if num_val.is_infinite() {
                        has_infinity = true;
                    } else {
                        sum_of_squares += num_val * num_val;
                    }
                }

                // ES2020 20.2.2.18 steps 4-5: an infinite argument makes the
                // result +Infinity even beside a NaN.
                let result = if has_infinity {
                    f64::INFINITY
                } else if has_nan {
                    f64::NAN
                } else {
                    sum_of_squares.sqrt()
                };

                Ok(Value::Float(result.into()))
            }

            // Removed duplicate ArrayPrototypeCopyWithin - implementation at line ~13993 has better ES2015 compliance
            "builtin:ArrayPrototypeFill" => {
                // Array.prototype.fill(value, start, end) implementation
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be arrays
                };

                let fill_value = if args.count >= 2 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as i32,
                        Some(Value::Float(len)) => len.inner() as i32,
                        _ => return Ok(Value::Object(array_id)),
                    }
                } else {
                    return Ok(Value::Object(array_id));
                };

                if length <= 0 {
                    return Ok(Value::Object(array_id));
                }

                let start = if args.count >= 3 {
                    match self.read_reg(args.start + 2)? {
                        Value::Int(s) => s as i32,
                        Value::Float(s) => s.inner() as i32,
                        _ => 0,
                    }
                } else {
                    0
                };

                let end = if args.count >= 4 {
                    match self.read_reg(args.start + 3)? {
                        Value::Int(e) => e as i32,
                        Value::Float(e) => e.inner() as i32,
                        _ => length,
                    }
                } else {
                    length
                };

                // Normalize negative indices
                let start_idx = if start < 0 {
                    (length + start).max(0) as usize
                } else {
                    (start as usize).min(length as usize)
                };

                let end_idx = if end < 0 {
                    (length + end).max(0) as usize
                } else {
                    (end as usize).min(length as usize)
                };

                // Fill the array elements
                if start_idx < end_idx {
                    for i in start_idx..end_idx {
                        self.set_object_property(array_id, i.to_string(), fill_value.clone())?;
                    }
                }

                Ok(Value::Object(array_id))
            }

            "builtin:StringPrototypeCodePointAt" => {
                // String.prototype.codePointAt(index): UTF-16 code-unit
                // indexed over exact units, matching the receiver-aware
                // string_code_point_at_impl seam (bd-rdnhc; previously
                // scalar-indexed over the projection).
                let this_val = self.read_reg(args.start)?;
                let Some(string_val) = Self::legacy_string_arm_operand(&this_val) else {
                    return Ok(Value::Undefined);
                };

                let index = if args.count >= 2 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(idx) => idx as usize,
                        Value::Float(idx) => idx.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                Ok(match string_val.code_point_at(index) {
                    Some(code_point) => Value::Int(i64::from(code_point)),
                    None => Value::Undefined,
                })
            }

            "builtin:StringFromCodePoint" => {
                let values = self.builtin_argument_values(args)?;
                self.string_from_code_point(module, values)
            }

            "builtin:MathImul" => {
                // Math.imul(x, y) implementation - 32-bit integer multiplication
                if args.count < 2 {
                    return Ok(Value::Int(0));
                }

                let x_val = self.math_argument_value(args.start, module)?;
                let y_val = self.math_argument_value(args.start + 1, module)?;

                // ECMA `Math.imul` is ToUint32 on both operands, then a
                // wrapping 32-bit signed multiply. `f64 as i32` saturates, so
                // float operands >= 2^31 must route through `js_to_int32`
                // (modular) — e.g. `Math.imul(2**31, 2)` is `0`, not `-2`.
                let x = match x_val {
                    Value::Int(n) => n as i32,
                    Value::Float(f) => Self::js_to_int32(f.inner()),
                    _ => 0,
                };

                let y = match y_val {
                    Value::Int(n) => n as i32,
                    Value::Float(f) => Self::js_to_int32(f.inner()),
                    _ => 0,
                };

                // Perform 32-bit integer multiplication
                let result = x.wrapping_mul(y) as i64;
                Ok(Value::Int(result))
            }

            // Removed duplicate ArrayPrototypeAt - implementation at line ~13242 is more concise

            // Removed duplicate StringPrototypeAt - implementation at line ~13959 is more complete
            "builtin:ObjectGetOwnPropertyDescriptor" => {
                // Object.getOwnPropertyDescriptor(obj, prop) implementation
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                // ES2020 19.1.2.8: ToObject(O), a TypeError for undefined and
                // null, then ToPropertyKey(P), whose object hooks run
                // (bd-9vouw.279).
                if matches!(obj_val, Value::Undefined | Value::Null) {
                    return Err(InterpreterError::TypeError {
                        expected: "object for Object.getOwnPropertyDescriptor".to_string(),
                        got: obj_val.type_name().to_string(),
                    });
                }
                let prop_val = self.read_reg(args.start + 1)?;
                let prop_val = self.coerce_to_property_key(module, prop_val)?;
                let prop_name = self.executable_property_key_from_value(&prop_val);
                // bd-9vouw.17: a function's own properties (its `length` and
                // `name` included) are on its backing object. `prototype`
                // keeps its dedicated path.
                if !matches!(obj_val, Value::Object(_))
                    && obj_val.is_callable()
                    && prop_name.as_str() == Some("prototype")
                    && self.function_has_intrinsic_prototype(&obj_val)
                {
                    return self.function_prototype_descriptor(module, &obj_val);
                }
                // ToObject of a string is a String exotic object, whose
                // indices and `length` are its own (bd-9vouw.356); no other
                // primitive's wrapper has own properties.
                if let Value::Str(text) = &obj_val {
                    let text = text.clone();
                    return Ok(self
                        .string_own_property_descriptor(&text, &prop_name)?
                        .unwrap_or(Value::Undefined));
                }
                let Some(obj_id) = self.own_property_holder(module, &obj_val, true)? else {
                    return Ok(Value::Undefined); // Primitives have no own property descriptors here
                };
                self.join_pending_hostcall_stream_label(obj_id)?;
                // A Proxy answers through its getOwnPropertyDescriptor trap
                // or its target (bd-9vouw.147).
                self.proxy_aware_own_property_descriptor(module, obj_id, &prop_name, 0)
            }

            // ES2020 26.1.7 Reflect.getOwnPropertyDescriptor: the
            // Object.getOwnPropertyDescriptor result, except that a non-object
            // target is a TypeError instead of being converted.
            "builtin:ReflectGetOwnPropertyDescriptor" => {
                let target = self.arg_or_undefined(args, 0)?;
                if !target.is_object_like() {
                    return Err(InterpreterError::TypeError {
                        expected: "object target for Reflect.getOwnPropertyDescriptor".to_string(),
                        got: target.type_name().to_string(),
                    });
                }
                self.dispatch_builtin_hostcall_inner(
                    "builtin:ObjectGetOwnPropertyDescriptor",
                    args,
                    module,
                )
            }

            // ES2020 26.1.3 Reflect.defineProperty: Object.defineProperty
            // that reports whether the definition succeeded instead of
            // throwing. A non-object target or attributes value, a malformed
            // descriptor and a Proxy invariant violation are still TypeErrors;
            // only the rejected definition itself answers false.
            "builtin:ReflectDefineProperty" => {
                let target = self.arg_or_undefined(args, 0)?;
                let attributes = self.arg_or_undefined(args, 2)?;
                if !target.is_object_like() || !attributes.is_object_like() {
                    return Err(InterpreterError::TypeError {
                        expected: "object target and attributes for Reflect.defineProperty"
                            .to_string(),
                        got: format!("{}, {}", target.type_name(), attributes.type_name()),
                    });
                }
                match self.dispatch_builtin_hostcall_inner(
                    "builtin:ObjectDefineProperty",
                    args,
                    module,
                ) {
                    Ok(_) => Ok(Value::Bool(true)),
                    Err(InterpreterError::TypeError { expected, .. })
                        if expected == DEFINE_PROPERTY_REJECTED =>
                    {
                        Ok(Value::Bool(false))
                    }
                    Err(error) => Err(error),
                }
            }

            "builtin:ObjectGetOwnPropertyDescriptors" => {
                // Object.getOwnPropertyDescriptors(O), ES2020 19.1.2.9:
                // ToObject(O) (a primitive's wrapper; undefined and null are
                // TypeErrors), then each key of [[OwnPropertyKeys]] through
                // [[GetOwnProperty]], so a Proxy's ownKeys and
                // getOwnPropertyDescriptor traps run, in key order
                // (bd-9vouw.347). Only the ordinary heap path ran: a Proxy
                // gave {} and a primitive was a TypeError.
                let obj_val = match self.arg_or_undefined(args, 0)? {
                    nullish @ (Value::Undefined | Value::Null) => {
                        return Err(InterpreterError::TypeError {
                            expected: "object for Object.getOwnPropertyDescriptors".to_string(),
                            got: nullish.type_name().to_string(),
                        });
                    }
                    primitive @ (Value::Bool(_)
                    | Value::Int(_)
                    | Value::Float(_)
                    | Value::Str(_)
                    | Value::BigInt(_)
                    | Value::Symbol(_)) => Value::Object(self.alloc_primitive_wrapper(primitive)?),
                    other => other,
                };
                let Some(obj_id) = self.own_property_holder(module, &obj_val, true)? else {
                    return Err(InterpreterError::TypeError {
                        expected: "object for Object.getOwnPropertyDescriptors".to_string(),
                        got: obj_val.type_name().to_string(),
                    });
                };
                self.join_pending_hostcall_stream_label(obj_id)?;
                // Guest traps run while native locals hold the result: no
                // collection until this returns.
                self.gc_nested_request = None;
                let keys = self.proxy_aware_own_property_keys(module, obj_id, 0)?;
                let result_id = self.alloc_object_with_prototype(None)?;
                for key in keys {
                    let key = self.executable_property_key_from_value(&key);
                    let descriptor =
                        self.proxy_aware_own_property_descriptor(module, obj_id, &key, 0)?;
                    if !matches!(descriptor, Value::Undefined) {
                        self.set_object_runtime_property(result_id, key, descriptor)?;
                    }
                }
                Ok(Value::Object(result_id))
            }

            "builtin:ObjectGetPropertyDescriptor" => {
                // Object.getPropertyDescriptor(obj, prop) implementation
                // Similar to getOwnPropertyDescriptor but walks the prototype chain
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let obj_val = self.read_reg(args.start)?;
                let obj_id = match obj_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects don't have properties
                };

                let prop_val = self.read_reg(args.start + 1)?;
                let prop_key = self.executable_property_key_from_value(&prop_val);

                // Use our prototype chain descriptor lookup
                self.join_pending_hostcall_stream_label(obj_id)?;
                self.prototype_chain_get_property_descriptor(obj_id, &prop_key)
            }

            // Removed duplicate MathClz32 - implementation at line ~12775 has better type conversion
            "builtin:ArrayPrototypeEntries" => self.array_prototype_iterator(args, "entries"),

            "builtin:ArrayPrototypeKeys" => self.array_prototype_iterator(args, "keys"),

            "builtin:ArrayPrototypeValues" => self.array_prototype_iterator(args, "values"),

            "builtin:ObjectSetPrototypeOf" => self.object_integrity_builtin(
                module,
                args,
                ObjectIntegrityOperation::SetPrototype,
                false,
            ),

            "builtin:SymbolIterator" => Ok(Value::Symbol(WellKnownSymbol::Iterator.id())),

            "builtin:WellKnownSymbol" => {
                let identity = match self.builtin_arg(args, 0)? {
                    Some(Value::Int(id)) => WellKnownSymbol::ALL
                        .into_iter()
                        .find(|symbol| i64::from(symbol.id().0) == id),
                    _ => None,
                };
                let symbol = identity.ok_or_else(|| InterpreterError::TypeError {
                    expected: "canonical well-known symbol identity".to_string(),
                    got: "invalid well-known symbol id".to_string(),
                })?;
                Ok(Value::Symbol(symbol.id()))
            }

            "builtin:StringPrototypeNormalize" => {
                // String.prototype.normalize(form) implementation - Unicode normalization
                let this_val = self.read_reg(args.start)?;
                let string_val = Self::require_object_coercible_to_js_string(&this_val)?;

                let form = if args.count >= 2 {
                    match self.read_reg(args.start + 1)? {
                        Value::Undefined => "NFC".to_string(),
                        value => Self::value_to_primitive_string(&value),
                    }
                } else {
                    "NFC".to_string()
                };

                let normalized = string_val
                    .try_map_unicode_spans(|text| normalize_unicode_string(text, &form))
                    .map_err(|message| InterpreterError::RangeError { message })?;

                Ok(Value::Str(normalized))
            }

            "builtin:StringPrototypeTrimStart" => {
                // String.prototype.trimStart() implementation - remove leading whitespace
                let this_val = self.read_reg(args.start)?;
                let string_val = match this_val {
                    Value::Str(s) => s.to_string(),
                    _ => {
                        // Try to convert to string
                        match this_val {
                            Value::Int(n) => n.to_string(),
                            Value::Float(f) => f.to_string(),
                            Value::Bool(b) => b.to_string(),
                            Value::Null => "null".to_string(),
                            Value::Undefined => "undefined".to_string(),
                            _ => return Ok(Value::str("")),
                        }
                    }
                };

                // Remove leading WhiteSpace and LineTerminator.
                let trimmed = string_val.trim_start_matches(primitive_conversion::is_js_whitespace);
                Ok(Value::str(trimmed))
            }

            // Removed duplicate StringPrototypeTrimEnd - implementation at line ~13975 is more JS-compliant

            // StringPrototypePadStart: Removed duplicate dispatch arm (use first occurrence instead)

            // StringPrototypePadEnd: Removed duplicate dispatch arm (use first occurrence instead)

            // Removed duplicate ObjectPrototypeHasOwnProperty - implementation at line 9134 (builtin:ObjectHasOwnProperty) is identical
            "builtin:ArrayPrototypeFind" => {
                let (array_id, callback, this_arg, length) =
                    self.validate_array_callback_structure(args, "Array.prototype.find")?;

                for index in 0..length {
                    let element = self
                        .array_index_get(module, array_id, index)?
                        .unwrap_or(Value::Undefined);
                    let predicate_result = self.invoke_array_callback(
                        module,
                        &callback,
                        this_arg.clone(),
                        element.clone(),
                        index,
                        array_id,
                    )?;
                    if predicate_result.is_truthy() {
                        return Ok(element);
                    }
                }

                Ok(Value::Undefined)
            }

            // StringPrototypeStartsWith: Removed duplicate dispatch arm (use first occurrence instead)

            // StringPrototypeEndsWith: Removed duplicate dispatch arm (use first occurrence instead)
            "builtin:NumberIsInteger" => {
                // Number.isInteger(value) implementation - determines if value is finite integer
                if args.count == 0 {
                    return Ok(Value::Bool(false));
                }

                let value = self.read_reg(args.start)?;
                let is_integer = match value {
                    Value::Int(_) => true, // All integers are integers
                    Value::Float(f) => {
                        let num = f.inner();
                        num.is_finite() && num.fract() == 0.0 // Finite and no fractional part
                    }
                    _ => false, // Non-numbers are not integers
                };

                Ok(Value::Bool(is_integer))
            }
            "builtin:NumberIsSafeInteger" => {
                // ES2020 20.1.2.5: an integral Number with |n| <= 2^53 - 1.
                const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
                let is_safe = match (args.count > 0)
                    .then(|| self.read_reg(args.start))
                    .transpose()?
                {
                    Some(Value::Int(n)) => (n as f64).abs() <= MAX_SAFE,
                    Some(Value::Float(f)) => {
                        let n = f.inner();
                        n.is_finite() && n.fract() == 0.0 && n.abs() <= MAX_SAFE
                    }
                    _ => false,
                };
                Ok(Value::Bool(is_safe))
            }

            "builtin:NumberParseFloat" => {
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::ParseFloat)
            }

            // StringPrototypeRepeat: Removed duplicate dispatch arm (use first occurrence instead)
            "builtin:NumberParseInt" => {
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::ParseInt)
            }
            "builtin:ArrayPrototypeFilter" => {
                // Array.prototype.filter(callback[, thisArg]) implementation (simplified)
                if args.count < 2 {
                    // Return empty array if no callback provided
                    let empty_array_id = self.alloc_array_with_prototype(None)?;
                    self.set_object_property(empty_array_id, "length".to_string(), Value::Int(0))?;
                    return Ok(Value::Object(empty_array_id));
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_array_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                let _callback = self.read_reg(args.start + 1)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result array
                let result_array_id = self.alloc_array_with_prototype(None)?;

                // Collect truthy elements first to avoid borrow checker issues
                let mut filtered_elements = Vec::new();
                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    for i in 0..length {
                        if let Some(element) = obj.properties.get(&i.to_string()) {
                            let is_truthy = match element {
                                Value::Bool(false) | Value::Null | Value::Undefined => false,
                                Value::Int(0) => false,
                                Value::Float(f) if f.inner() == 0.0 || f.inner().is_nan() => false,
                                Value::Str(s) if s.is_empty() => false,
                                _ => true,
                            };

                            if is_truthy {
                                filtered_elements.push(element.clone());
                            }
                        }
                    }
                }

                // Set the filtered elements to the result array
                for (i, element) in filtered_elements.iter().enumerate() {
                    self.set_object_property(result_array_id, i.to_string(), element.clone())?;
                }

                // Set result array length
                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(filtered_elements.len() as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }

            // StringPrototypeIncludes: Removed duplicate dispatch arm (use first occurrence instead)

            // Removed duplicate NumberIsNaNMethod - implementation at line 8404 (builtin:NumberIsNaN) is identical

            // ArrayPrototypeReverse: Removed duplicate dispatch arm (use first occurrence instead)
            "builtin:MathAtan" => {
                // Math.atan(x) implementation
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.math_argument_value(args.start, module)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                Ok(Value::Float(Float64::new(num.atan())))
            }

            // Removed duplicate ArrayPrototypeFill - implementation at line ~11593 has better JS semantics
            "builtin:ObjectPrototypePropertyIsEnumerable" => {
                // Object.prototype.propertyIsEnumerable(prop) implementation
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let this_val = self.read_reg(args.start)?;
                let object_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Bool(false)), // Non-objects don't have enumerable properties
                };

                let prop_val = self.read_reg(args.start + 1)?;
                // All ordinary own properties are enumerable in this simplified
                // model; Writable state mirrors are inherited accessors.
                self.join_pending_hostcall_stream_label(object_id)?;
                Ok(Value::Bool(self.object_own_property_contains(
                    &Value::Object(object_id),
                    &prop_val,
                )))
            }

            "builtin:StringPrototypeConcat" => {
                // String.prototype.concat(...strings) implementation
                let this_val = self.read_reg(args.start)?;
                let mut result = match this_val {
                    Value::Str(s) => s.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                // Concatenate all additional arguments
                for i in 1..args.count {
                    let arg_val = self.read_reg(args.start + i)?;
                    let arg_str = match arg_val {
                        Value::Str(s) => s.to_string(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => "[object Object]".to_string(),
                    };
                    result.push_str(&arg_str);
                }

                Ok(Value::str(result))
            }

            // Removed duplicate MathAtan2 - implementation at line ~10995 has correct argument handling
            "builtin:MathLog10" => {
                // Math.log10(x) implementation
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.math_argument_value(args.start, module)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                Ok(Value::Float(Float64::new(num.log10())))
            }

            // Removed duplicate ObjectPrototypeValueOf - implementation at line ~11410 is identical
            "builtin:MathLog2" => {
                // Math.log2(x) implementation
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.math_argument_value(args.start, module)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                Ok(Value::Float(Float64::new(num.log2())))
            }

            // Removed duplicate ArrayPrototypeReduceRight - implementation at line ~11114 is identical
            "builtin:ObjectPrototypeToString" => {
                // Object.prototype.toString() implementation
                let this_val = self.read_reg(args.start)?;

                match &this_val {
                    Value::Object(obj_id) => {
                        // Check explicit array metadata first.
                        if let Some(obj) = self.heap.get(obj_id.0 as usize) {
                            if obj.is_array {
                                Ok(Value::str("[object Array]"))
                            } else {
                                Ok(Value::str("[object Object]"))
                            }
                        } else {
                            Ok(Value::str("[object Object]"))
                        }
                    }
                    _ => Ok(Value::str(InterpreterCore::value_to_object_to_string_tag(
                        &this_val,
                    ))),
                }
            }

            // Removed duplicate StringFromCharCode - implementation at line ~10858 is identical

            // Removed duplicate MathAcos - implementation at line ~11059 is identical

            // Removed duplicate ArrayPrototypeLastIndexOf - implementation at line ~10742 is identical
            "builtin:RegExpPrototypeTest" => {
                let this_val = self.read_reg(args.start)?;
                // ES2020 21.2.5.13 step 3: ToString(S), a missing argument
                // being undefined ("undefined"), runs an object argument's
                // conversion methods (bd-9vouw.213).
                if self.regexp_source_flags_from_value(&this_val).is_some() {
                    let input = Value::str(self.builtin_arg_text(module, args, 1)?);
                    return self.regexp_test_value(&this_val, &input);
                }
                if args.count < 2 {
                    return Ok(Value::Bool(false));
                }

                let input = self.read_reg(args.start + 1)?;
                self.regexp_test_value(&this_val, &input)
            }

            // Removed duplicate StringPrototypeCodePointAt - implementation at line ~11708 is identical

            // Removed duplicate MathAsin - implementation at line ~11042 is identical

            // builtin:ArrayPrototypeFindIndex - Duplicate removed, consolidated to line 10807

            // Removed duplicate ObjectGetOwnPropertyNames - implementation at line ~10883 is more complete

            // Removed duplicate StringPrototypeNormalize - implementation at line ~12187 is identical
            "builtin:MathCbrt" => {
                // Math.cbrt(x) implementation (cube root)
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.math_argument_value(args.start, module)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                Ok(Value::Float(Float64::new(num.cbrt())))
            }

            // Removed duplicate ArrayPrototypeFlat - implementation at line ~9886 is more complete

            // Removed duplicate PromiseResolve - implementation at line ~9255 is identical
            "builtin:StringPrototypeReplaceAll" => {
                // String.prototype.replaceAll (ES2021 22.1.3.19): every
                // occurrence; a non-global RegExp search is a TypeError.
                let this_val = self.arg_or_undefined(args, 0)?;
                let str_text = match this_val {
                    Value::Str(s) => s,
                    other => JsString::from(self.value_to_string(&other)),
                };
                let search_val = self.arg_or_undefined(args, 1)?;
                let replace_val = self.arg_or_undefined(args, 2)?;
                let label = self.join_arg_range_label(args)?;
                if self
                    .regexp_source_flags_from_value(&search_val)
                    .is_some_and(|(_, flags)| !flags.contains('g'))
                {
                    return Err(InterpreterError::TypeError {
                        expected: "global RegExp for String.prototype.replaceAll".to_string(),
                        got: "non-global RegExp".to_string(),
                    });
                }
                self.string_replace_js(module, &str_text, &search_val, &replace_val, true, label)
            }

            "builtin:MathClz32" => {
                // Math.clz32(x) implementation (count leading zeros in 32-bit binary)
                if args.count == 0 {
                    return Ok(Value::Int(32)); // All zeros if no argument
                }

                // ECMA `Math.clz32` is `clz` over ToUint32(x). `f64 as u32`
                // saturates, so float/string operands must route through
                // `js_to_uint32` (modular) — e.g. `Math.clz32(2**32)` is `32`
                // (ToUint32 = 0), not `0`, and `Math.clz32(-1.5)` is `0`.
                let val = self.math_argument_value(args.start, module)?;
                let num = match val {
                    Value::Int(n) => n as u32,
                    Value::Float(f) => Self::js_to_uint32(f.inner()),
                    Value::Str(s) => Self::js_to_uint32(s.parse::<f64>().unwrap_or(0.0)),
                    Value::Bool(true) => 1,
                    Value::Bool(false) => 0,
                    Value::Null => 0,
                    _ => 0,
                };

                Ok(Value::Int(num.leading_zeros() as i64))
            }

            "builtin:ArrayPrototypeFlatMap" => {
                // Array.prototype.flatMap(callback[, thisArg]) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_array_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                let _callback = self.read_reg(args.start + 1)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result array
                let result_array_id = self.alloc_array_with_prototype(None)?;
                let mut result_length = 0;

                // Simplified implementation: copy elements and flatten one level.
                let elements_to_copy = self
                    .heap
                    .get(array_id.0 as usize)
                    .map(|obj| {
                        (0..length)
                            .filter_map(|i| obj.properties.get(&i.to_string()).cloned())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                for element in elements_to_copy {
                    self.set_object_property(result_array_id, result_length.to_string(), element)?;
                    result_length += 1;
                }

                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(result_length as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }

            // ObjectDefineProperty: Removed duplicate dispatch arm (use first occurrence instead)
            "builtin:StringPrototypeAt" => {
                // String.prototype.at(index) implementation (ES2022)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let index = if args.count > 1 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(n) => n,
                        Value::Float(f) => f.inner() as i64,
                        _ => 0,
                    }
                } else {
                    0
                };

                let chars: Vec<char> = str_text.chars().collect();
                let len = chars.len() as i64;

                // Handle negative indices (count from end)
                let actual_index = if index < 0 { len + index } else { index };

                if actual_index >= 0 && (actual_index as usize) < chars.len() {
                    Ok(Value::str(chars[actual_index as usize].to_string()))
                } else {
                    Ok(Value::Undefined)
                }
            }

            "builtin:MathFround" => {
                // Math.fround(x) implementation (round to nearest 32-bit float)
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.math_argument_value(args.start, module)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                // Convert to f32 and back to f64 to simulate 32-bit float rounding
                let rounded = num as f32 as f64;
                Ok(Value::Float(Float64::new(rounded)))
            }

            "builtin:ArrayPrototypeAt" => {
                // Array.prototype.at(index) implementation (ES2022)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be arrays
                };

                let index = match self.read_reg(args.start + 1)? {
                    Value::Int(n) => n,
                    Value::Float(f) => f.inner() as i64,
                    _ => return Ok(Value::Undefined),
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len,
                        Some(Value::Float(len)) => len.inner() as i64,
                        _ => return Ok(Value::Undefined),
                    }
                } else {
                    return Ok(Value::Undefined);
                };

                // Handle negative indices (count from end)
                let actual_index = if index < 0 { length + index } else { index };

                if actual_index >= 0 && actual_index < length {
                    if let Some(obj) = self.heap.get(array_id.0 as usize) {
                        if let Some(element) = obj.properties.get(&(actual_index.to_string())) {
                            return Ok(element.clone());
                        }
                    }
                }

                Ok(Value::Undefined)
            }

            // Removed duplicate ObjectGetPrototypeOf - implementation at line ~10941 uses correct prototype field
            "builtin:StringPrototypeToWellFormed" => {
                // String.prototype.toWellFormed() (ES2024 §22.1.3.29): each
                // unpaired surrogate is replaced with U+FFFD; every other
                // code unit is preserved. The lossy UTF-8 projection carried
                // by `JsString` is exactly that mapping (bd-neika replaced
                // the earlier control-char stub, which was not spec
                // behavior).
                let this_val = self.read_reg(args.start)?;
                let well_formed = match this_val {
                    Value::Str(s) => s.as_utf8_projection().to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                Ok(Value::str(well_formed))
            }

            "builtin:MathAcosh" => {
                // Math.acosh(x) implementation (inverse hyperbolic cosine)
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.math_argument_value(args.start, module)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                // acosh is only defined for x >= 1
                if num < 1.0 {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else {
                    Ok(Value::Float(Float64::new(num.acosh())))
                }
            }

            "builtin:ArrayFromAsync" => self.array_from_async_builtin(module, args),

            "builtin:ObjectIs" => {
                // Object.is(value1, value2) implementation (slot 0 is the
                // receiver). A missing argument is undefined, so
                // `Object.is()` and `Object.is(undefined)` are true; they
                // answered false.
                let val1 = self.arg_or_undefined(args, 1)?;
                let val2 = self.arg_or_undefined(args, 2)?;

                Ok(Value::Bool(Self::same_value(&val1, &val2)))
            }

            "builtin:StringPrototypeIsWellFormed" => {
                // String.prototype.isWellFormed() (ES2024 §22.1.3.10): true
                // iff the string contains no unpaired surrogate. Non-string
                // receivers coerce through primitive strings, which are
                // always well-formed. (bd-neika replaced the earlier
                // control-char stub, which was not spec behavior.)
                let this_val = self.read_reg(args.start)?;
                let is_well_formed = match this_val {
                    Value::Str(s) => s.is_well_formed(),
                    _ => true,
                };

                Ok(Value::Bool(is_well_formed))
            }

            "builtin:MathAsinh" => {
                // Math.asinh(x) implementation (inverse hyperbolic sine)
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.math_argument_value(args.start, module)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                // asinh is defined for all real numbers
                Ok(Value::Float(Float64::new(num.asinh())))
            }

            "builtin:ArrayPrototypeWith" => {
                // Array.prototype.with(index, value) implementation (ES2023)
                if args.count < 3 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_array_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                let index = match self.read_reg(args.start + 1)? {
                    Value::Int(n) => n,
                    Value::Float(f) => f.inner() as i64,
                    _ => return Ok(Value::Undefined),
                };

                let value = self.read_reg(args.start + 2)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len,
                        Some(Value::Float(len)) => len.inner() as i64,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Handle negative indices
                let actual_index = if index < 0 { length + index } else { index };

                // Check bounds
                if actual_index < 0 || actual_index >= length {
                    return Ok(Value::Undefined);
                }

                // Create a new array with the replaced value
                let result_array_id = self.alloc_array_with_prototype(None)?;

                // Copy all elements, replacing the one at the specified
                // index. Snapshot under an immutable borrow so we can call
                // &mut self set_object_property without aliasing.
                let original_elements: Vec<Value> =
                    if let Some(obj) = self.heap.get(array_id.0 as usize) {
                        (0..length)
                            .map(|i| {
                                obj.properties
                                    .get(&i.to_string())
                                    .cloned()
                                    .unwrap_or(Value::Undefined)
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };
                for (i, element) in original_elements.iter().enumerate() {
                    let element_value = if (i as i64) == actual_index {
                        value.clone()
                    } else {
                        element.clone()
                    };
                    self.set_object_property(result_array_id, i.to_string(), element_value)?;
                }

                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(length),
                )?;

                Ok(Value::Object(result_array_id))
            }

            // Removed duplicate ObjectSetPrototypeOf - implementation at line ~11927 uses correct prototype field

            // StringPrototypeToLowerCase: Removed duplicate dispatch arm (use first occurrence at line 8124)
            "builtin:MathAtanh" => {
                // Math.atanh(x) implementation (inverse hyperbolic tangent)
                if args.count == 0 {
                    return Ok(Value::Float(Float64::new(f64::NAN)));
                }

                let val = self.math_argument_value(args.start, module)?;
                let num = match val {
                    Value::Int(n) => n as f64,
                    Value::Float(f) => f.inner(),
                    Value::Str(s) => s.parse::<f64>().unwrap_or(f64::NAN),
                    Value::Bool(true) => 1.0,
                    Value::Bool(false) => 0.0,
                    Value::Null => 0.0,
                    _ => f64::NAN,
                };

                // atanh is NaN outside [-1, 1] and -Infinity / +Infinity at
                // -1 / 1 (ES2020 20.2.2.7).
                if num < -1.0 || num > 1.0 {
                    Ok(Value::Float(Float64::new(f64::NAN)))
                } else {
                    Ok(Value::Float(Float64::new(num.atanh())))
                }
            }

            "builtin:ArrayPrototypeToReversed" => {
                // Array.prototype.toReversed() implementation (ES2023)
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_array_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result array (immutable operation)
                let result_array_id = self.alloc_array_with_prototype(None)?;

                // Copy elements in reverse order without holding the source borrow across writes.
                let reversed_elements = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    (0..length)
                        .map(|i| {
                            let reverse_index = length - 1 - i;
                            let element = obj
                                .properties
                                .get(&reverse_index.to_string())
                                .cloned()
                                .unwrap_or(Value::Undefined);
                            (i, element)
                        })
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                for (i, element) in reversed_elements {
                    self.set_object_property(result_array_id, i.to_string(), element)?;
                }

                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(length as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }

            // StringPrototypeToUpperCase: Removed duplicate dispatch arm (use first occurrence at line 8136)

            // Removed duplicate MathHypot - implementation at line ~11456 is more complete
            "builtin:ArrayPrototypeToSorted" => {
                // Array.prototype.toSorted([compareFunction]) implementation (ES2023)
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_array_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result array (immutable operation)
                let result_array_id = self.alloc_array_with_prototype(None)?;

                // Copy and sort elements (simplified string-based sorting).
                let mut elements_with_indices =
                    if let Some(obj) = self.heap.get(array_id.0 as usize) {
                        (0..length)
                            .map(|i| {
                                let element = obj
                                    .properties
                                    .get(&i.to_string())
                                    .cloned()
                                    .unwrap_or(Value::Undefined);
                                (i, element)
                            })
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    };

                // Simple string-based sort (like default Array.sort)
                elements_with_indices.sort_by(|(_i1, a), (_i2, b)| {
                    let a_str = match a {
                        Value::Str(s) => s.to_string(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => "[object Object]".to_string(),
                    };
                    let b_str = match b {
                        Value::Str(s) => s.to_string(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => "[object Object]".to_string(),
                    };
                    a_str.cmp(&b_str)
                });

                // Set sorted elements in result array
                for (new_index, (_original_index, element)) in
                    elements_with_indices.iter().enumerate()
                {
                    self.set_object_property(
                        result_array_id,
                        new_index.to_string(),
                        element.clone(),
                    )?;
                }

                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(length as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }

            // Removed duplicate ObjectPropertyIsEnumerable - implementation at line 12025 (builtin:ObjectPrototypePropertyIsEnumerable) is identical

            // StringPrototypeTrimStart: Removed duplicate dispatch arm (use first occurrence instead)

            // Removed duplicate MathImul - implementation at line ~11636 has correct argument handling
            "builtin:ArrayPrototypeToSpliced" => {
                // Array.prototype.toSpliced(start, deleteCount, ...items) implementation (ES2023)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty array
                        let empty_array_id = self.alloc_array_with_prototype(None)?;
                        self.set_object_property(
                            empty_array_id,
                            "length".to_string(),
                            Value::Int(0),
                        )?;
                        return Ok(Value::Object(empty_array_id));
                    }
                };

                let start = if args.count > 1 {
                    match self.read_reg(args.start + 1)? {
                        Value::Int(n) => n,
                        Value::Float(f) => f.inner() as i64,
                        _ => 0,
                    }
                } else {
                    0
                };

                let delete_count = if args.count > 2 {
                    match self.read_reg(args.start + 2)? {
                        Value::Int(n) => n as usize,
                        Value::Float(f) => f.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Handle negative start index
                let actual_start = if start < 0 {
                    (length as i64 + start).max(0) as usize
                } else {
                    (start as usize).min(length)
                };

                // Calculate actual delete count
                let actual_delete_count = delete_count.min(length - actual_start);

                // Create result array (immutable operation)
                let result_array_id = self.alloc_array_with_prototype(None)?;
                let mut result_index = 0;

                // Snapshot source elements before mutating the result array.
                let source_elements = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    (0..length)
                        .map(|i| {
                            obj.properties
                                .get(&i.to_string())
                                .cloned()
                                .unwrap_or(Value::Undefined)
                        })
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };

                // Copy elements before start.
                for element in source_elements.iter().take(actual_start) {
                    self.set_object_property(
                        result_array_id,
                        result_index.to_string(),
                        element.clone(),
                    )?;
                    result_index += 1;
                }

                // Add new items (if any).
                for i in 3..args.count {
                    let item = self.read_reg(args.start + i)?;
                    self.set_object_property(result_array_id, result_index.to_string(), item)?;
                    result_index += 1;
                }

                // Copy elements after deleted section.
                for element in source_elements
                    .iter()
                    .skip(actual_start + actual_delete_count)
                {
                    self.set_object_property(
                        result_array_id,
                        result_index.to_string(),
                        element.clone(),
                    )?;
                    result_index += 1;
                }

                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(result_index as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }

            "builtin:ObjectIsExtensible" => self.object_integrity_builtin(
                module,
                RegRange {
                    start: args.start.saturating_add(1),
                    count: args.count.saturating_sub(1),
                },
                ObjectIntegrityOperation::IsExtensible,
                false,
            ),

            "builtin:StringPrototypeTrimEnd" => {
                // String.prototype.trimEnd() implementation (ES2019)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                // Trim WhiteSpace and LineTerminator from the end.
                let trimmed = str_text
                    .trim_end_matches(primitive_conversion::is_js_whitespace)
                    .to_string();
                Ok(Value::str(trimmed))
            }

            // Removed duplicate MathSign - implementation at line ~10088 is identical
            "builtin:ArrayPrototypeGroup" => {
                // Array.prototype.group(callback) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty object
                        let empty_obj_id = self.alloc_object_with_prototype(None)?;
                        return Ok(Value::Object(empty_obj_id));
                    }
                };

                let _callback = self.read_reg(args.start + 1)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result object (simplified grouping)
                let result_obj_id = self.alloc_object_with_prototype(None)?;

                // Simplified implementation: group by string representation
                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    let mut groups: std::collections::BTreeMap<String, Vec<Value>> =
                        std::collections::BTreeMap::new();

                    for i in 0..length {
                        if let Some(element) = obj.properties.get(&i.to_string()) {
                            // Simple grouping key based on element type/value
                            let key = match element {
                                Value::Str(s) => format!("string:{}", s),
                                Value::Int(n) => format!("number:{}", n),
                                Value::Float(f) => format!("number:{}", f.inner()),
                                Value::Bool(b) => format!("boolean:{}", b),
                                Value::Null => "null".to_string(),
                                Value::Undefined => "undefined".to_string(),
                                _ => "object".to_string(),
                            };

                            groups.entry(key).or_default().push(element.clone());
                        }
                    }

                    // Convert groups to object properties (each group becomes an array)
                    for (key, values) in groups {
                        let group_array_id = self.alloc_array_with_prototype(None)?;

                        for (i, value) in values.iter().enumerate() {
                            self.set_object_property(group_array_id, i.to_string(), value.clone())?;
                        }

                        self.set_object_property(
                            group_array_id,
                            "length".to_string(),
                            Value::Int(values.len() as i64),
                        )?;

                        self.set_object_property(
                            result_obj_id,
                            key,
                            Value::Object(group_array_id),
                        )?;
                    }
                }

                Ok(Value::Object(result_obj_id))
            }

            "builtin:ObjectPreventExtensions" => self.object_integrity_builtin(
                module,
                RegRange {
                    start: args.start.saturating_add(1),
                    count: args.count.saturating_sub(1),
                },
                ObjectIntegrityOperation::PreventExtensions,
                false,
            ),

            "builtin:StringPrototypeSearch" => {
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s.clone(),
                    other => JsString::from(self.value_to_string(&other)),
                };

                let pattern_val = if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    return Ok(Value::Int(-1));
                };

                self.string_search_value(&str_text, &pattern_val)
            }

            // Removed duplicate MathTrunc - implementation at line ~9554 is identical
            "builtin:ArrayPrototypeGroupToMap" => {
                // Array.prototype.groupToMap(callback) implementation (simplified)
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => {
                        // Non-objects can't be arrays, return empty map-like object
                        let empty_obj_id = self.alloc_object_with_prototype(None)?;
                        return Ok(Value::Object(empty_obj_id));
                    }
                };

                let _callback = self.read_reg(args.start + 1)?;

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len as usize,
                        Some(Value::Float(len)) => len.inner() as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                // Create result Map-like object
                let result_obj_id = self.alloc_object_with_prototype(None)?;

                // Simplified implementation: group by element type
                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    let mut groups: std::collections::BTreeMap<String, Vec<Value>> =
                        std::collections::BTreeMap::new();

                    for i in 0..length {
                        if let Some(element) = obj.properties.get(&i.to_string()) {
                            // Group by type for simplicity
                            let type_key = match element {
                                Value::Str(_) => "string",
                                Value::Int(_) => "number",
                                Value::Float(_) => "number",
                                Value::BigInt(_) => "bigint",
                                Value::Bool(_) => "boolean",
                                Value::Null => "null",
                                Value::Undefined => "undefined",
                                _ => "object",
                            }
                            .to_string();

                            groups.entry(type_key).or_default().push(element.clone());
                        }
                    }

                    // Convert groups to Map entries
                    for (key, values) in groups {
                        let group_array_id = self.alloc_array_with_prototype(None)?;

                        for (i, value) in values.iter().enumerate() {
                            self.set_object_property(group_array_id, i.to_string(), value.clone())?;
                        }

                        self.set_object_property(
                            group_array_id,
                            "length".to_string(),
                            Value::Int(values.len() as i64),
                        )?;

                        self.set_object_property(
                            result_obj_id,
                            key,
                            Value::Object(group_array_id),
                        )?;
                    }
                }

                Ok(Value::Object(result_obj_id))
            }

            "builtin:ObjectSeal" => {
                // Object.seal(O), ES2020 19.1.2.20 / 7.3.14 SetIntegrityLevel
                // "sealed": non-extensible, every own property non-configurable.
                let obj_val = self.arg_or_undefined(args, 1)?;
                self.object_seal_value(module, obj_val)
            }

            // Removed duplicate StringPrototypeSubstr - implementation at line ~11150 is identical
            "builtin:NumberPrototypeToFixed" => {
                // Number.prototype.toFixed(digits) implementation
                let this_val = self.read_reg(args.start)?;
                let num = Self::number_receiver_to_f64(&this_val);

                let digits = self
                    .optional_number_hostcall_integer_arg(args, 1)?
                    .unwrap_or_default();
                if !(0..=100).contains(&digits) {
                    return Err(InterpreterError::RangeError {
                        message: format!(
                            "toFixed() digits must be between 0 and 100 (got {digits})"
                        ),
                    });
                }

                Ok(Value::str(number_to_fixed_string(num, digits as usize)))
            }

            "builtin:ArrayPrototypeCopyWithin" => {
                // Array.prototype.copyWithin(target, start[, end]) implementation (ES2015)
                if args.count < 3 {
                    return Ok(Value::Undefined);
                }

                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects can't be arrays
                };

                let target = match self.read_reg(args.start + 1)? {
                    Value::Int(n) => n,
                    Value::Float(f) => f.inner() as i64,
                    _ => return Ok(Value::Undefined),
                };

                let start = match self.read_reg(args.start + 2)? {
                    Value::Int(n) => n,
                    Value::Float(f) => f.inner() as i64,
                    _ => return Ok(Value::Undefined),
                };

                let end = if args.count > 3 {
                    match self.read_reg(args.start + 3)? {
                        Value::Int(n) => Some(n),
                        Value::Float(f) => Some(f.inner() as i64),
                        _ => None,
                    }
                } else {
                    None
                };

                // Get array length
                let length = if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    match obj.properties.get("length") {
                        Some(Value::Int(len)) => *len,
                        Some(Value::Float(len)) => len.inner() as i64,
                        _ => return Ok(Value::Undefined),
                    }
                } else {
                    return Ok(Value::Undefined);
                };

                // Normalize indices. ES2015 §22.1.3.3: non-negative relative
                // indices clamp to `len` (inclusive), not `len - 1` — clamping
                // to `len - 1` made `copyWithin(len, 0, 1)` overwrite the last
                // element instead of being a no-op, and on an empty array it
                // produced index `-1` (inserting a bogus "-1" property).
                let actual_target = if target < 0 {
                    (length + target).max(0)
                } else {
                    target.min(length)
                };

                let actual_start = if start < 0 {
                    (length + start).max(0)
                } else {
                    start.min(length)
                };

                let actual_end = end.map_or(length, |e| {
                    if e < 0 {
                        (length + e).max(0)
                    } else {
                        e.min(length)
                    }
                });

                // Copy elements within the array
                let array_index = array_id.0 as usize;

                // First, collect elements to copy using read-only access
                let mut elements_to_copy = Vec::new();
                if let Some(array_obj) = self.heap.get(array_index) {
                    for i in actual_start..actual_end {
                        if let Some(element) = array_obj.properties.get(&i.to_string()) {
                            elements_to_copy.push(element.clone());
                        } else {
                            elements_to_copy.push(Value::Undefined);
                        }
                    }
                }

                // Then, copy to target positions using mutate_heap
                self.mutate_heap(|heap| {
                    if let Some(array_obj) = heap.get_mut(array_index) {
                        for (offset, element) in elements_to_copy.into_iter().enumerate() {
                            let target_index = actual_target + offset as i64;
                            if target_index < length {
                                array_obj
                                    .properties
                                    .insert(target_index.to_string(), element);
                            }
                        }
                    }
                });

                Ok(Value::Object(array_id))
            }

            "builtin:StringPrototypeAnchor" => {
                // String.prototype.anchor(name) implementation (deprecated HTML wrapper)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let name = if args.count > 1 {
                    match self.read_reg(args.start + 1)? {
                        Value::Str(s) => s.to_string(),
                        Value::Int(n) => n.to_string(),
                        Value::Float(f) => f.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        Value::Undefined => "undefined".to_string(),
                        _ => "[object Object]".to_string(),
                    }
                } else {
                    "undefined".to_string()
                };

                let result = format!("<a name=\"{}\">{}</a>", name, str_text);
                Ok(Value::str(result))
            }

            "builtin:NumberPrototypeToExponential" => {
                // Number.prototype.toExponential(fractionDigits) implementation
                let this_val = self.read_reg(args.start)?;
                let num = Self::number_receiver_to_f64(&this_val);

                let fraction_digits = self.optional_number_hostcall_integer_arg(args, 1)?;
                if let Some(digits) = fraction_digits
                    && !(0..=100).contains(&digits)
                {
                    return Err(InterpreterError::RangeError {
                        message: format!(
                            "toExponential() fractionDigits must be between 0 and 100 (got {digits})"
                        ),
                    });
                }

                if num.is_nan() {
                    Ok(Value::str("NaN"))
                } else if num.is_infinite() {
                    if num.is_sign_positive() {
                        Ok(Value::str("Infinity"))
                    } else {
                        Ok(Value::str("-Infinity"))
                    }
                } else {
                    let formatted = if let Some(digits) = fraction_digits {
                        format!("{:.precision$e}", num, precision = digits as usize)
                    } else {
                        format!("{:e}", num)
                    };
                    Ok(Value::str(formatted))
                }
            }

            // Removed duplicate ArrayPrototypeValues - implementation at line ~11973 uses proper iterator semantics
            "builtin:ObjectIsSealed" => {
                // Object.isSealed(O), ES2020 19.1.2.15 / 7.3.15 TestIntegrityLevel.
                let obj_val = self.arg_or_undefined(args, 1)?;
                Ok(Value::Bool(self.object_is_sealed_value(module, &obj_val)?))
            }

            "builtin:StringPrototypeBig" => {
                // String.prototype.big() implementation (deprecated HTML wrapper)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let result = format!("<big>{}</big>", str_text);
                Ok(Value::str(result))
            }

            "builtin:NumberPrototypeToPrecision" => {
                // Number.prototype.toPrecision(precision) implementation
                let this_val = self.read_reg(args.start)?;
                let num = Self::number_receiver_to_f64(&this_val);

                let precision = self.optional_number_hostcall_integer_arg(args, 1)?;
                if let Some(precision) = precision
                    && !(1..=100).contains(&precision)
                {
                    return Err(InterpreterError::RangeError {
                        message: format!(
                            "toPrecision() precision must be between 1 and 100 (got {precision})"
                        ),
                    });
                }

                if num.is_nan() {
                    Ok(Value::str("NaN"))
                } else if num.is_infinite() {
                    if num.is_sign_positive() {
                        Ok(Value::str("Infinity"))
                    } else {
                        Ok(Value::str("-Infinity"))
                    }
                } else {
                    let formatted = if let Some(prec) = precision {
                        let prec = prec as usize;
                        // Use exponential notation if number is too large/small for fixed precision
                        if num.abs() >= 10_f64.powi(prec as i32) || (num.abs() < 1.0 && num != 0.0)
                        {
                            format!("{:.precision$e}", num, precision = prec.saturating_sub(1))
                        } else {
                            format!("{:.precision$}", num, precision = prec.saturating_sub(1))
                        }
                    } else {
                        num.to_string()
                    };
                    Ok(Value::str(formatted))
                }
            }

            // Removed duplicate ArrayPrototypeKeys - implementation at line ~11907 uses proper iterator semantics
            "builtin:WeakMapPrototypeHas" => {
                let this_val = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let weakmap_id = self.validate_weakmap_receiver(this_val)?;
                let key = if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };

                // WeakMap only accepts object keys
                let Value::Object(key_object_id) = key else {
                    return Ok(Value::Bool(false));
                };

                let has_key = self
                    .weakmap_storage
                    .get(&weakmap_id)
                    .map(|storage| storage.has(key_object_id.0))
                    .unwrap_or(false);

                Ok(Value::Bool(has_key))
            }

            "builtin:StringPrototypeBlink" => {
                // String.prototype.blink() implementation (deprecated HTML wrapper)
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let result = format!("<blink>{}</blink>", str_text);
                Ok(Value::str(result))
            }

            "builtin:NumberPrototypeValueOf" => {
                // Number.prototype.valueOf() implementation
                let this_val = self.read_reg(args.start)?;

                match this_val {
                    Value::Int(n) => Ok(Value::Int(n)),
                    Value::Float(f) => Ok(Value::Float(f)),
                    Value::Object(obj_id) => {
                        // A Number wrapper's [[NumberData]] (bd-9vouw.73).
                        if let Some(number @ (Value::Int(_) | Value::Float(_))) =
                            self.primitive_wrapper_value(obj_id)
                        {
                            return Ok(number.clone());
                        }
                        // Not a Number object, return NaN
                        Ok(Value::Float(Float64::new(f64::NAN)))
                    }
                    _ => {
                        // Primitive numbers return themselves, others return NaN
                        Ok(Value::Float(Float64::new(f64::NAN)))
                    }
                }
            }

            // Removed duplicate ArrayPrototypeEntries - implementation at line ~11841 uses proper iterator semantics
            "builtin:WeakMapPrototypeGet" => {
                let this_val = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                let weakmap_id = self.validate_weakmap_receiver(this_val)?;
                let key = if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };

                // WeakMap only accepts object keys
                let Value::Object(key_object_id) = key else {
                    return Ok(Value::Undefined);
                };

                let value = self
                    .weakmap_storage
                    .get(&weakmap_id)
                    .and_then(|storage| storage.get(key_object_id.0))
                    .cloned()
                    .unwrap_or(Value::Undefined);

                Ok(value)
            }

            // ArrayPrototypeReverse: Removed duplicate dispatch arm (use first occurrence instead)

            // StringPrototypeToLowerCase: Removed duplicate dispatch arm (use first occurrence at line 8124)

            // StringPrototypeToUpperCase: Removed duplicate dispatch arm (use first occurrence at line 8137)

            // ObjectPrototypeToString: Removed duplicate dispatch arm (use first occurrence instead)

            // StringPrototypeTrim: Removed duplicate dispatch arm (use first occurrence instead)

            // NumberIsInteger: Removed duplicate dispatch arm (use first occurrence instead)

            // StringPrototypeEndsWith: Removed duplicate dispatch arm (use first occurrence instead)

            // Removed duplicate NumberIsNaN - implementation at line ~8618 has correct argument handling

            // Removed duplicate NumberIsFinite - implementation at line ~8630 has correct argument handling
            "builtin:StringPrototypeCharAt" => {
                let receiver = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                // Slot 0 is the receiver; the position converts observably
                // when the guest call has a module.
                let index = match module {
                    Some(module) => self.builtin_number_arg(module, args, 1)?,
                    None => self.builtin_arg(args, 1)?,
                };
                Self::string_prototype_char_at_value(receiver, index)
            }

            "builtin:ArrayPrototypeEvery" => {
                // Array.prototype.every() implementation with callback invocation
                let (array_id, callback, this_arg, array_length) =
                    self.validate_array_callback_structure(args, "Array.prototype.every")?;

                // Empty array case: every() returns true (per ES specification)
                if array_length == 0 {
                    return Ok(Value::Bool(true));
                }

                // For each element, invoke callback and check for falsy result
                for index in 0..array_length {
                    let Some(element) = self.array_index_get(module, array_id, index)? else {
                        continue;
                    };

                    let result = self.invoke_array_callback(
                        module,
                        &callback,
                        this_arg.clone(),
                        element,
                        index,
                        array_id,
                    )?;

                    // Short-circuit on first falsy result
                    if !result.is_truthy() {
                        return Ok(Value::Bool(false));
                    }
                }

                // All elements passed the predicate
                Ok(Value::Bool(true))
            }

            // Removed duplicate NumberPrototypeToString - implementation at line ~11219 is identical
            "builtin:StringPrototypeSubstring" => {
                // String.prototype.substring() implementation - returns substring between indices
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s.to_string(),
                    Value::Null => "null".to_string(),
                    Value::Undefined => "undefined".to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Int(n) => n.to_string(),
                    Value::Float(f) => f.to_string(),
                    Value::Object(_) => "[object Object]".to_string(),
                    _ => "[object Object]".to_string(),
                };

                let len = str_text.len();
                let start = if args.count >= 2 {
                    let start_val = self.read_reg(args.start + 1)?;
                    match start_val {
                        Value::Int(n) => n.max(0).min(len as i64) as usize,
                        Value::Float(f) => f.inner().max(0.0).min(len as f64) as usize,
                        _ => 0,
                    }
                } else {
                    0
                };

                let end = if args.count >= 3 {
                    let end_val = self.read_reg(args.start + 2)?;
                    match end_val {
                        Value::Int(n) => n.max(0).min(len as i64) as usize,
                        Value::Float(f) => f.inner().max(0.0).min(len as f64) as usize,
                        _ => len,
                    }
                } else {
                    len
                };

                let (actual_start, actual_end) = if start <= end {
                    (start, end)
                } else {
                    (end, start)
                };
                let result: String = str_text
                    .chars()
                    .skip(actual_start)
                    .take(actual_end - actual_start)
                    .collect();
                Ok(Value::str(result))
            }

            // Removed duplicate ArrayPrototypeReduce - implementation at line ~9273 properly fails-closed

            // Removed duplicate ObjectGetOwnPropertyNames - implementation at line ~10883 has correct argument handling
            "builtin:StringPrototypeSplit" => {
                // String.prototype.split(separator, limit), ES2020 21.1.3.19
                // and 21.2.5.13: string and RegExp separators (RegExp capture
                // groups are spliced into the result), and `limit` caps the
                // number of elements (bd-9vouw.40).
                let this_val = self.read_reg(args.start)?;
                let str_text = match this_val {
                    Value::Str(s) => s.clone(),
                    other => JsString::from(self.value_to_string(&other)),
                };
                let separator = self.arg_or_undefined(args, 1)?;
                let limit = Self::split_limit(self.arg_or_undefined(args, 2)?);
                let regexp_separator = self.regexp_source_flags_from_value(&separator);
                let mut pieces: Vec<Value> = Vec::new();
                if limit == 0 {
                    // `split(sep, 0)` is always empty.
                } else if let Some((source, flags)) = regexp_separator {
                    pieces = self.regexp_split_pieces(&str_text, &source, &flags)?;
                } else if matches!(separator, Value::Undefined) {
                    pieces.push(Value::Str(str_text));
                } else {
                    let separator_text = match &separator {
                        Value::Str(text) => text.to_string(),
                        other => self.value_to_string(other),
                    };
                    if separator_text.is_empty() {
                        pieces.extend(str_text.chars().map(|ch| Value::str(ch.to_string())));
                    } else {
                        pieces.extend(str_text.split(separator_text.as_str()).map(Value::str));
                    }
                }
                pieces.truncate(limit);
                let result_array_id = self.alloc_array_from_values(&pieces)?;
                Ok(Value::Object(result_array_id))
            }

            "builtin:ArrayPrototypeMap" => {
                // Array.prototype.map() implementation with callback invocation
                let (array_id, callback, this_arg, array_length) =
                    self.validate_array_callback_structure(args, "Array.prototype.map")?;

                // Create result array
                let result_array_id = self.alloc_array_with_prototype(None)?;

                // Empty array case: map() returns empty array
                if array_length == 0 {
                    self.set_object_property(result_array_id, "length".to_string(), Value::Int(0))?;
                    return Ok(Value::Object(result_array_id));
                }

                // For each element, invoke callback and collect result
                for index in 0..array_length {
                    let Some(element) = self.array_index_get(module, array_id, index)? else {
                        continue;
                    };

                    let (mapped_result, mapped_label) = self.with_gc_nested_request(
                        vec![Value::Object(result_array_id)],
                        |core| {
                            core.invoke_labeled_array_callback(
                                module,
                                &callback,
                                this_arg.clone(),
                                element,
                                index,
                                array_id,
                            )
                        },
                    )?;

                    self.create_labeled_data_property_or_throw(
                        result_array_id,
                        index.to_string(),
                        mapped_result,
                        &mapped_label,
                    )?;
                }

                // Set result array length
                self.set_object_property(
                    result_array_id,
                    "length".to_string(),
                    Value::Int(array_length as i64),
                )?;

                Ok(Value::Object(result_array_id))
            }

            // Removed duplicate DateNow - implementation at line ~8728 is identical
            "builtin:ArrayPrototypeConcat" => {
                // Array.prototype.concat() implementation - concatenates arrays
                let this_val = self.read_reg(args.start)?;
                let array_id = match this_val {
                    Value::Object(id) => id,
                    _ => return Ok(Value::Undefined), // Non-objects return undefined
                };

                let result_array_id = self.alloc_array_with_prototype(None)?;

                if let Some(obj) = self.heap.get(array_id.0 as usize) {
                    let length_prop = obj
                        .properties
                        .get("length")
                        .cloned()
                        .unwrap_or(Value::Int(0));
                    let length = match length_prop {
                        Value::Int(n) => n.max(0) as usize,
                        _ => 0,
                    };

                    // Copy elements from original array
                    let elements: Vec<_> = (0..length)
                        .filter_map(|i| obj.properties.get(&i.to_string()).cloned())
                        .collect();

                    let mut result_index = 0;
                    for element in elements {
                        self.set_object_property(
                            result_array_id,
                            result_index.to_string(),
                            element,
                        )?;
                        result_index += 1;
                    }

                    // Concatenate additional arguments
                    for arg_idx in 1..args.count {
                        let arg_val = self.read_reg(args.start + arg_idx)?;
                        match arg_val {
                            Value::Object(concat_id) => {
                                // If it's an array, concatenate its elements
                                let elements_to_add =
                                    if let Some(concat_obj) = self.heap.get(concat_id.0 as usize) {
                                        if let Some(concat_length_prop) =
                                            concat_obj.properties.get("length")
                                        {
                                            let concat_length = match concat_length_prop {
                                                Value::Int(n) => (*n).max(0) as usize,
                                                _ => 0,
                                            };

                                            let mut elements = Vec::new();
                                            for i in 0..concat_length {
                                                if let Some(element) =
                                                    concat_obj.properties.get(&i.to_string())
                                                {
                                                    elements.push(element.clone());
                                                }
                                            }
                                            elements
                                        } else {
                                            Vec::new()
                                        }
                                    } else {
                                        Vec::new()
                                    };

                                for element in elements_to_add {
                                    self.set_object_property(
                                        result_array_id,
                                        result_index.to_string(),
                                        element,
                                    )?;
                                    result_index += 1;
                                }
                            }
                            _ => {
                                // Non-array values are added as single elements
                                self.set_object_property(
                                    result_array_id,
                                    result_index.to_string(),
                                    arg_val,
                                )?;
                                result_index += 1;
                            }
                        }
                    }

                    self.set_object_property(
                        result_array_id,
                        "length".to_string(),
                        Value::Int(result_index as i64),
                    )?;
                }

                Ok(Value::Object(result_array_id))
            }

            // Removed duplicate JSONStringify - implementation at line 8242 has better JS compliance and correct argument handling
            // Removed duplicate JSONParse - implementation at line 8286 has better JS compliance and correct argument handling

            // builtin:ArrayPrototypeFind - Duplicate removed, consolidated to line 12438

            // builtin:ArrayPrototypeFindIndex - Duplicate removed, consolidated to line 10807
            "builtin:EncodeURIComponent" => {
                // encodeURIComponent(value): slot-0 convention, shared by direct
                // calls and the first-class value. A lone surrogate is a
                // URIError (ES2020 18.2.6.1.1 step 3.e).
                let input = self.builtin_arg_js_text(module, args, 0)?;
                match input.as_str() {
                    Some(text) => Ok(Value::str(percent_encode_utf8(
                        text,
                        should_encode_uri_component,
                    ))),
                    None => Err(self.throw_uri_malformed(None)),
                }
            }

            "builtin:DecodeURIComponent" => {
                // decodeURIComponent(value): slot-0 convention, shared by direct
                // calls and the first-class value. A malformed escape is a
                // URIError (ES2020 18.2.6.1.2), which callers catch.
                let encoded = self.builtin_arg_js_text(module, args, 0)?;
                match percent_decode_js_string(&encoded, "") {
                    Some(decoded) => Ok(Value::Str(decoded)),
                    None => Err(self.throw_uri_malformed(None)),
                }
            }

            "builtin:EncodeURI" => {
                // encodeURI(value): slot-0 convention, shared by direct
                // calls and the first-class value. A lone surrogate is a
                // URIError (ES2020 18.2.6.1.1 step 3.e).
                let input = self.builtin_arg_js_text(module, args, 0)?;
                match input.as_str() {
                    Some(text) => Ok(Value::str(percent_encode_utf8(text, should_encode_uri))),
                    None => Err(self.throw_uri_malformed(None)),
                }
            }

            "builtin:DecodeURI" => {
                // decodeURI(value): slot-0 convention, shared by direct
                // calls and the first-class value. A malformed escape is a
                // URIError (ES2020 18.2.6.1.2), which callers catch.
                let encoded = self.builtin_arg_js_text(module, args, 0)?;
                match percent_decode_js_string(&encoded, ";/?:@&=+$,#") {
                    Some(decoded) => Ok(Value::Str(decoded)),
                    None => Err(self.throw_uri_malformed(None)),
                }
            }

            "builtin:SetTimeout" | "builtin:SetInterval" | "builtin:SetImmediate" => {
                // setTimeout()/setInterval()/setImmediate() — deterministic
                // timer scheduling (bd-suwvw). Receiver-placeholder
                // convention: real args start at `args.start + 1`.
                // setImmediate has no delay argument; its extra callback args
                // start right after the callback.
                let is_interval = cap == "builtin:SetInterval";
                let is_immediate = cap == "builtin:SetImmediate";
                if args.count < 2 {
                    return Ok(Value::Int(0)); // Missing callback.
                }
                let callback_val = self.read_reg(args.start + 1)?;
                let delay_val = if is_immediate || args.count < 3 {
                    None
                } else {
                    Some(self.read_reg(args.start + 2)?)
                };
                let extra_start: u32 = if is_immediate { 2 } else { 3 };
                let mut extra_args = Vec::new();
                let mut index = extra_start;
                while index < args.count {
                    extra_args.push(self.read_reg(args.start + index)?);
                    index += 1;
                }
                let registration_label = self.join_arg_range_label(args)?;
                self.timer_schedule_from_values(
                    callback_val,
                    delay_val,
                    extra_args,
                    is_interval,
                    is_immediate,
                    registration_label,
                )
            }

            "builtin:ClearTimeout" | "builtin:ClearInterval" | "builtin:ClearImmediate" => {
                // clearTimeout()/clearInterval()/clearImmediate() — cancel a
                // timer through deterministic state (bd-suwvw). Accepts the
                // Timeout/Immediate handle object or a legacy integer id;
                // anything else (undefined/null/garbage) is a no-op, matching
                // Node.
                if args.count < 2 {
                    return Ok(Value::Undefined);
                }
                let handle_val = self.read_reg(args.start + 1)?;
                let witness_tag = match cap {
                    "builtin:ClearTimeout" => "builtin:clearTimeout",
                    "builtin:ClearInterval" => "builtin:clearInterval",
                    _ => "builtin:clearImmediate",
                };
                let operation = match cap {
                    "builtin:ClearTimeout" => Some(TimerOperation::ClearTimeout),
                    "builtin:ClearInterval" => Some(TimerOperation::ClearInterval),
                    _ => None,
                };
                let ifc_label = self.join_arg_range_label(args)?;
                self.timer_clear_from_value(&handle_val, witness_tag, operation, ifc_label)
            }

            "builtin:QueueMicrotask" => {
                // queueMicrotask(cb) — enqueue a plain microtask (bd-suwvw).
                // Receiver-placeholder convention (real arg at start + 1).
                if args.count < 2 {
                    return Err(InterpreterError::TypeError {
                        expected: "function".to_string(),
                        got: "undefined".to_string(),
                    });
                }
                let callback_val = self.read_reg(args.start + 1)?;
                self.queue_microtask_from_value(&callback_val)
            }

            "builtin:ProcessExit" => {
                // process.exit([code]) — end the program now (bd-my9hk).
                // Slot-0 convention. Without a code, the exit status is
                // `process.exitCode`, else 0, as in Node.
                let requested = if args.count == 0 {
                    None
                } else {
                    Self::process_exit_code_from_value(&self.read_reg(args.start)?)?
                };
                Err(InterpreterError::ProcessExit {
                    code: requested.or(self.process_exit_code).unwrap_or(0),
                })
            }

            "builtin:ProcessSetExitCode" => {
                // process.exitCode = value (bd-my9hk): the status a normal
                // completion reports; `undefined` clears it. The assignment's
                // value is the assigned value.
                if args.count < 1 {
                    return Err(InterpreterError::TypeError {
                        expected: "process.exitCode value".to_string(),
                        got: "no argument".to_string(),
                    });
                }
                let value = self.read_reg(args.start)?;
                self.process_exit_code = Self::process_exit_code_from_value(&value)?;
                Ok(value)
            }

            "builtin:Eval" => {
                // The inert `eval` value (bd-9vouw.191): kept and compared as
                // a function, never a compiler. Every call (indirect eval,
                // `(0, eval)(src)`, a stored copy) fails closed with a
                // catchable EvalError; direct `eval(src)` is refused at
                // lowering without the runtime.eval effect.
                Err(self.throw_js_error(
                    "EvalError",
                    "code generation from strings is not permitted: eval requires the runtime.eval effect".to_string(),
                ))
            }

            "builtin:ProcessNextTick" => {
                // process.nextTick(cb[, ...args]) — enqueue onto the dedicated
                // next-tick job queue, which drains before Promise microtasks
                // (bd-8nrud). Slot-0 convention (no receiver placeholder).
                if args.count < 1 {
                    return Err(InterpreterError::TypeError {
                        expected: "process.nextTick callback function".to_string(),
                        got: "undefined".to_string(),
                    });
                }
                let callback = self.read_reg(args.start)?;
                if !matches!(
                    callback,
                    Value::Closure(_)
                        | Value::Function(_)
                        | Value::BuiltinFunction(_)
                        | Value::AsyncFunction(_)
                ) {
                    return Err(InterpreterError::TypeError {
                        expected: "process.nextTick callback function".to_string(),
                        got: callback.type_name().to_string(),
                    });
                }
                let mut forwarded = Vec::with_capacity(args.count.saturating_sub(1) as usize);
                for offset in 1..args.count {
                    let register = args.start.checked_add(offset).ok_or(
                        InterpreterError::RegisterOutOfBounds {
                            register: args.start,
                            max: self.config.max_registers,
                        },
                    )?;
                    forwarded.push(self.read_reg(register)?);
                }
                let label = self.join_arg_range_label(args)?;
                let previous_bytes = self.next_tick_queue_memory_bytes();
                self.next_tick_queue.push_back(NextTickTask {
                    callback,
                    args: forwarded,
                    label,
                });
                if let Err(error) = self.apply_memory_component_delta(
                    previous_bytes,
                    self.next_tick_queue_memory_bytes(),
                ) {
                    self.next_tick_queue.pop_back();
                    return Err(error);
                }
                Ok(Value::Undefined)
            }

            "builtin:TimersPromisesSetTimeout" => {
                // require('timers/promises').setTimeout(ms[, value]) —
                // returns a promise fulfilled with `value` after `ms`
                // (bd-suwvw). Slot-0 convention (no receiver placeholder).
                let delay_val = if args.count > 0 {
                    Some(self.read_reg(args.start)?)
                } else {
                    None
                };
                let value = if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };
                self.timers_promises_schedule_from_values(delay_val, &value, false)
            }

            "builtin:TimersPromisesSetImmediate" => {
                // require('timers/promises').setImmediate([value]) (bd-suwvw).
                let value = if args.count > 0 {
                    self.read_reg(args.start)?
                } else {
                    Value::Undefined
                };
                self.timers_promises_schedule_from_values(None, &value, true)
            }

            "builtin:TimersPromisesSetInterval" => {
                // require('timers/promises').setInterval([ms[, value]]) —
                // returns a deterministic async-iterable interval object
                // consumed by `for await` (bd-suwvw). Each `next` advances the
                // virtual clock by the (clamped) delay and yields `value`.
                let delay_ms = if args.count > 0 {
                    Self::timer_delay_ms_from_value(&self.read_reg(args.start)?)
                } else {
                    1
                };
                let value = if args.count > 1 {
                    self.read_reg(args.start + 1)?
                } else {
                    Value::Undefined
                };
                let object_id = self.alloc_branded_object(
                    TIMERS_PROMISES_INTERVAL_TYPE,
                    &[
                        ("__delayMs", Value::Int(delay_ms as i64)),
                        ("__value", value),
                        (
                            "next",
                            Value::BuiltinFunction(BuiltinFunction::new_kind(
                                BuiltinFunctionKind::TimersPromisesIntervalNext,
                            )),
                        ),
                        (
                            "return",
                            Value::BuiltinFunction(BuiltinFunction::new_kind(
                                BuiltinFunctionKind::TimersPromisesIntervalReturn,
                            )),
                        ),
                    ],
                )?;
                // `for await` (desugared to the async iteration protocol)
                // finds the iterator through @@asyncIterator.
                self.set_symbol_property(
                    object_id,
                    WellKnownSymbol::AsyncIterator.id(),
                    BaselineSymbolProperty::Data(Value::BuiltinFunction(
                        BuiltinFunction::new_kind(BuiltinFunctionKind::AsyncGeneratorIteratorSelf),
                    )),
                )?;
                Ok(Value::Object(object_id))
            }

            // Removed duplicate parseFloat - keep single canonical implementation on `builtin:parseFloat` and alias.
            "builtin:parseFloat" => {
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::ParseFloat)
            }
            "builtin:Btoa" | "builtin:Atob" | "builtin:Escape" | "builtin:Unescape" => {
                self.string_codec_builtin(module, cap, args)
            }
            "builtin:StructuredClone" => self.structured_clone_builtin(module, args),
            // Removed duplicate ParseInt - implementation at line 8385 (builtin:parseInt) is identical
            "builtin:ParseFloat" => {
                self.primitive_conversion_builtin(module, args, PrimitiveConversion::ParseFloat)
            }

            // Removed duplicate IsNaN - implementation at line 8326 has better JS compliance and explicit type conversion rules

            // Removed duplicate IsFinite - implementation at line 8354 has better JS compliance and explicit type conversion rules
            "builtin:ConsoleInfo" => {
                self.dispatch_console_hostcall_inner("console:info", args, module)
            }

            "builtin:StringPrototypeToLocaleLowerCase" => {
                // String.prototype.toLocaleLowerCase() implementation - simplified locale-aware lowercase
                let this_val = self.read_reg(args.start)?;
                let str_text = Self::require_object_coercible_to_js_string(&this_val)?;

                // Root-locale casing; locale selection remains a separate surface.
                str_text
                    .try_map_unicode_spans(|text| Ok(text.to_lowercase()))
                    .map(Value::Str)
            }

            "builtin:StringPrototypeToLocaleUpperCase" => {
                // String.prototype.toLocaleUpperCase() implementation - simplified locale-aware uppercase
                let this_val = self.read_reg(args.start)?;
                let str_text = Self::require_object_coercible_to_js_string(&this_val)?;

                // Root-locale casing; locale selection remains a separate surface.
                str_text
                    .try_map_unicode_spans(|text| Ok(text.to_uppercase()))
                    .map(Value::Str)
            }

            _ => {
                // Unknown builtin method - return undefined. The delegated
                // ApplyHostCall path converts this deterministic fallthrough
                // into a fail-closed CapabilityDenied via the flag
                // (bd-z1peg.3); direct lowering never emits unknown tags.
                self.builtin_dispatch_hit_unknown_member = true;
                Ok(Value::Undefined)
            }
        }
    }
}
