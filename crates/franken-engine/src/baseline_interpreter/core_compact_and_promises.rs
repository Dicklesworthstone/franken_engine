use super::*;

impl InterpreterCore {
    #[inline]
    pub(super) fn execute_compact_tier1_instruction(
        &mut self,
        module: &Ir3Module,
        instruction: CompactTier1Instruction,
    ) -> Result<(), InterpreterError> {
        use CompactTier1Opcode as Op;

        let dst = u32::from(instruction.dst);
        let lhs = u32::from(instruction.lhs);
        let rhs = u32::from(instruction.rhs);
        match instruction.opcode {
            Op::Baseline => unreachable!("baseline cells never enter compact dispatch"),
            Op::LoadInt => {
                let value = instruction.payload as i64;
                let val = if value >= MIN_SAFE_INTEGER && value <= MAX_SAFE_INTEGER {
                    Value::Int(value)
                } else {
                    Value::Float(Float64::new(value as f64))
                };
                self.write_reg(dst, val)?;
                self.ip += 1;
            }
            Op::LoadFloat => {
                self.write_reg(
                    dst,
                    Value::Float(Float64::new(f64::from_bits(instruction.payload))),
                )?;
                self.ip += 1;
            }
            Op::LoadBool => {
                self.write_reg(dst, Value::Bool(instruction.payload != 0))?;
                self.ip += 1;
            }
            Op::LoadNull => {
                self.write_reg(dst, Value::Null)?;
                self.ip += 1;
            }
            Op::LoadUndefined => {
                self.write_reg(dst, Value::Undefined)?;
                self.ip += 1;
            }
            Op::Move => {
                if !self.static_move(dst, lhs) {
                    let result_label = self.unary_operation_label(lhs)?;
                    let value = self.read_reg(lhs)?;
                    self.write_reg_with_label(dst, value, result_label)?;
                }
                self.ip += 1;
            }
            Op::Add => {
                if let Some((result, slot)) =
                    self.compact_public_number_arithmetic(dst, lhs, rhs, Op::Add)
                {
                    self.write_static_slot(slot, result);
                    self.record_tier_i_specialization();
                } else {
                    let _bigint_peak = self.preflight_bigint_add(dst, lhs, rhs)?;
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_add(Some(module), lhs, rhs)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                }
                self.ip += 1;
            }
            Op::Sub => {
                if let Some((result, slot)) =
                    self.compact_public_number_arithmetic(dst, lhs, rhs, Op::Sub)
                {
                    self.write_static_slot(slot, result);
                    self.record_tier_i_specialization();
                } else {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_arith(lhs, rhs, "sub")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                }
                self.ip += 1;
            }
            Op::Mul => {
                if let Some((result, slot)) =
                    self.compact_public_number_arithmetic(dst, lhs, rhs, Op::Mul)
                {
                    self.write_static_slot(slot, result);
                    self.record_tier_i_specialization();
                } else {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_arith(lhs, rhs, "mul")?;
                    self.write_reg_with_label(dst, result, result_label)?;
                }
                self.ip += 1;
            }
            Op::Div => {
                if let Some((result, slot)) =
                    self.compact_public_number_arithmetic(dst, lhs, rhs, Op::Div)
                {
                    self.write_static_slot(slot, result);
                    self.record_tier_i_specialization();
                } else {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_div(lhs, rhs)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                }
                self.ip += 1;
            }
            Op::Mod => {
                if let Some((result, slot)) =
                    self.compact_public_number_arithmetic(dst, lhs, rhs, Op::Mod)
                {
                    self.write_static_slot(slot, result);
                    self.record_tier_i_specialization();
                } else {
                    let result_label = self.binary_operation_label(lhs, rhs)?;
                    let result = self.eval_mod(lhs, rhs)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                }
                self.ip += 1;
            }
            Op::Exp => {
                let result_label = self.binary_operation_label(lhs, rhs)?;
                let result = self.eval_exp(lhs, rhs)?;
                self.write_reg_with_label(dst, result, result_label)?;
                self.ip += 1;
            }
            Op::UnaryNeg => {
                let result_label = self.unary_operation_label(lhs)?;
                let result = self.eval_unary_neg(lhs)?;
                self.write_reg_with_label(dst, result, result_label)?;
                self.ip += 1;
            }
            // `++`/`--` (bd-9vouw.119): a public safe integer steps in place,
            // as `x -= -1` did through the Sub fast path; anything else
            // (a BigInt, a float, a string) steps through `eval_step`.
            Op::Inc | Op::Dec => {
                let delta: i64 = if instruction.opcode == Op::Inc { 1 } else { -1 };
                let stepped = self
                    .compact_public_int_operands(dst, lhs, lhs)
                    .and_then(|(value, _, slot)| Some((value.checked_add(delta)?, slot)))
                    .filter(|(value, _)| (MIN_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value));
                if let Some((stepped, slot)) = stepped {
                    self.write_static_slot(slot, Value::Int(stepped));
                    self.record_tier_i_specialization();
                } else {
                    let result_label = self.unary_operation_label(lhs)?;
                    let result = self.eval_step(lhs, delta)?;
                    self.write_reg_with_label(dst, result, result_label)?;
                }
                self.ip += 1;
            }
            Op::UnaryPlus => {
                let result_label = self.unary_operation_label(lhs)?;
                let result = self.eval_unary_plus(lhs)?;
                self.write_reg_with_label(dst, result, result_label)?;
                self.ip += 1;
            }
            Op::LogicalNot => {
                let result_label = self.unary_operation_label(lhs)?;
                let value = self.read_reg(lhs)?;
                self.write_reg_with_label(dst, Value::Bool(!value.is_truthy()), result_label)?;
                self.ip += 1;
            }
            Op::BitNot => {
                let result_label = self.unary_operation_label(lhs)?;
                let result = self.eval_bit_not(lhs)?;
                self.write_reg_with_label(dst, result, result_label)?;
                self.ip += 1;
            }
            Op::Lt => {
                self.execute_compact_relational(dst, lhs, rhs, "<")?;
            }
            Op::Lte => {
                self.execute_compact_relational(dst, lhs, rhs, "<=")?;
            }
            Op::Gt => {
                self.execute_compact_relational(dst, lhs, rhs, ">")?;
            }
            Op::Gte => {
                self.execute_compact_relational(dst, lhs, rhs, ">=")?;
            }
            Op::Eq => {
                self.execute_compact_equality(dst, lhs, rhs, false, false)?;
            }
            Op::StrictEq => {
                self.execute_compact_equality(dst, lhs, rhs, true, false)?;
            }
            Op::NotEq => {
                self.execute_compact_equality(dst, lhs, rhs, false, true)?;
            }
            Op::StrictNotEq => {
                self.execute_compact_equality(dst, lhs, rhs, true, true)?;
            }
            Op::BitAnd => {
                self.execute_compact_bitwise(dst, lhs, rhs, "&")?;
            }
            Op::BitOr => {
                self.execute_compact_bitwise(dst, lhs, rhs, "|")?;
            }
            Op::BitXor => {
                self.execute_compact_bitwise(dst, lhs, rhs, "^")?;
            }
            Op::Shl => {
                self.execute_compact_bitwise(dst, lhs, rhs, "<<")?;
            }
            Op::Shr => {
                self.execute_compact_bitwise(dst, lhs, rhs, ">>")?;
            }
            Op::Ushr => {
                self.execute_compact_bitwise(dst, lhs, rhs, ">>>")?;
            }
            Op::Jump => {
                self.compact_tier1_jump(instruction.payload as u32);
            }
            Op::JumpIf => {
                self.push_branch_pc_label_if_tainted(module, lhs)?;
                let branch_taken = self
                    .compact_borrowed_reg(lhs)?
                    .is_some_and(Value::is_truthy);
                self.record_tier_i_specialization();
                if branch_taken {
                    self.compact_tier1_jump(instruction.payload as u32);
                } else {
                    self.ip += 1;
                }
            }
            Op::JumpIfNullish => {
                self.push_branch_pc_label_if_tainted(module, lhs)?;
                let branch_taken = self
                    .compact_borrowed_reg(lhs)?
                    .is_none_or(Value::is_nullish);
                self.record_tier_i_specialization();
                if branch_taken {
                    self.compact_tier1_jump(instruction.payload as u32);
                } else {
                    self.ip += 1;
                }
            }
            Op::Halt => return Err(InterpreterError::Halted),
        }
        Ok(())
    }

    /// Borrow a register without cloning its value. A logically absent slot is
    /// `undefined`, matching `read_reg`; the caller selects the corresponding
    /// truth/nullish behavior. Register-bound errors retain the canonical
    /// ordering by falling through this shared check.
    #[inline(always)]
    pub(super) fn compact_borrowed_reg(
        &self,
        reg: u32,
    ) -> Result<Option<&Value>, InterpreterError> {
        if reg >= self.config.max_registers {
            return Err(InterpreterError::RegisterOutOfBounds {
                register: reg,
                max: self.config.max_registers,
            });
        }
        Ok(self.registers.get(self.register_base + reg as usize))
    }

    #[inline(always)]
    pub(super) fn record_tier_i_specialization(&mut self) {
        self.tier_i_specialized_instructions_executed = self
            .tier_i_specialized_instructions_executed
            .saturating_add(1);
    }

    /// Return copied integer operands only when the entire label/write path is
    /// statically equivalent to the generic Tier-R transaction. Any dynamic
    /// value, non-Public input label, active labeled execution context,
    /// destination growth, dynamic destination ownership, or over-budget base
    /// state falls back before mutation to the canonical helpers.
    #[inline(always)]
    pub(super) fn compact_public_int_operands(
        &self,
        dst: u32,
        lhs: u32,
        rhs: u32,
    ) -> Option<(i64, i64, StaticWriteSlot)> {
        if dst >= self.config.max_registers
            || lhs >= self.config.max_registers
            || rhs >= self.config.max_registers
        {
            return None;
        }
        let actual_dst = self.register_base.checked_add(dst as usize)?;
        let actual_lhs = self.register_base.checked_add(lhs as usize)?;
        let actual_rhs = self.register_base.checked_add(rhs as usize)?;
        let (Value::Int(left), Value::Int(right)) = (
            self.registers.get(actual_lhs)?,
            self.registers.get(actual_rhs)?,
        ) else {
            return None;
        };
        let labels_public = if self.all_register_labels_public {
            actual_lhs < self.register_labels.len() && actual_rhs < self.register_labels.len()
        } else {
            matches!(self.register_labels.get(actual_lhs), Some(Label::Public))
                && matches!(self.register_labels.get(actual_rhs), Some(Label::Public))
        };
        if !labels_public
            || !self.static_register_write_eligible(actual_dst, &Value::Undefined, &Label::Public)
        {
            return None;
        }
        Some((*left, *right, StaticWriteSlot(actual_dst)))
    }

    /// Borrow Number operands and compute a primitive result only when the
    /// full value/label write owns no dynamic bytes. This extends compact
    /// arithmetic to floating and mixed Numbers without cloning `Value`s or
    /// repeating the canonical label, coercion, and destination checks.
    ///
    /// No state changes until the caller consumes the checked slot. Aliased
    /// operands are read before the write; non-Numbers, non-Public labels,
    /// callback/method contexts, dynamic destinations and exhausted budgets
    /// remain on the canonical transaction path.
    #[inline(always)]
    pub(super) fn compact_public_number_arithmetic(
        &self,
        dst: u32,
        lhs: u32,
        rhs: u32,
        opcode: CompactTier1Opcode,
    ) -> Option<(Value, StaticWriteSlot)> {
        use CompactTier1Opcode as Op;

        if dst >= self.config.max_registers
            || lhs >= self.config.max_registers
            || rhs >= self.config.max_registers
        {
            return None;
        }
        let actual_dst = self.register_base.checked_add(dst as usize)?;
        let actual_lhs = self.register_base.checked_add(lhs as usize)?;
        let actual_rhs = self.register_base.checked_add(rhs as usize)?;
        let left = self.registers.get(actual_lhs)?;
        let right = self.registers.get(actual_rhs)?;
        let labels_public = if self.all_register_labels_public {
            actual_lhs < self.register_labels.len() && actual_rhs < self.register_labels.len()
        } else {
            matches!(self.register_labels.get(actual_lhs), Some(Label::Public))
                && matches!(self.register_labels.get(actual_rhs), Some(Label::Public))
        };
        if !matches!(left, Value::Int(_) | Value::Float(_))
            || !matches!(right, Value::Int(_) | Value::Float(_))
            || !labels_public
            || !self.static_register_write_eligible(actual_dst, &Value::Undefined, &Label::Public)
        {
            return None;
        }

        let result = if let (Value::Int(left), Value::Int(right)) = (left, right) {
            match opcode {
                Op::Add => js_int_add(*left, *right),
                Op::Sub => js_int_sub(*left, *right),
                Op::Mul => js_int_mul(*left, *right),
                Op::Div => js_number_to_value(*left as f64 / *right as f64),
                Op::Mod => js_int_mod(*left, *right),
                _ => unreachable!("compact Number arithmetic opcode is statically selected"),
            }
        } else {
            let number = |value: &Value| match value {
                Value::Int(value) => *value as f64,
                Value::Float(value) => value.inner(),
                _ => unreachable!("compact Number operands were checked before arithmetic"),
            };
            let (left, right) = (number(left), number(right));
            js_number_to_value(match opcode {
                Op::Add => left + right,
                Op::Sub => left - right,
                Op::Mul => left * right,
                Op::Div => left / right,
                Op::Mod => left % right,
                _ => unreachable!("compact Number arithmetic opcode is statically selected"),
            })
        };
        // Float64 retains NaN payload bits. Let the canonical operator
        // choose that representation, including NaNs produced from otherwise
        // numeric inputs, rather than relying on optimizer propagation here.
        if matches!(&result, Value::Float(value) if value.is_nan()) {
            return None;
        }
        Some((result, StaticWriteSlot(actual_dst)))
    }

    /// `Move dst, src` when the source value and label own no dynamic bytes
    /// and the destination is eligible for a static write: the write
    /// `write_reg_with_label` makes on its static path, without cloning the
    /// label through a budget check (a static label is zero bytes; the
    /// eligibility check refuses an over-budget state, which the generic
    /// path reports) (bd-9vouw.504). False leaves every register untouched.
    #[inline(always)]
    pub(super) fn static_move(&mut self, dst: u32, src: u32) -> bool {
        if dst >= self.config.max_registers || src >= self.config.max_registers {
            return false;
        }
        let actual_src = self.register_base + src as usize;
        let actual_dst = self.register_base + dst as usize;
        let (Some(value), Some(label)) = (
            self.registers.get(actual_src),
            self.register_labels.get(actual_src),
        ) else {
            return false;
        };
        if !Self::static_register_value(value) || !Self::static_register_label(label) {
            return false;
        }
        let (value, label) = (value.clone(), label.clone());
        if !self.static_register_write_eligible(actual_dst, &value, &label) {
            return false;
        }
        self.note_register_written(actual_dst);
        self.mutate_registers_by_bytes(0, 0, |registers| registers[actual_dst] = value);
        if !(self.all_register_labels_public && matches!(&label, Label::Public)) {
            if !matches!(&label, Label::Public) {
                self.all_register_labels_public = false;
            }
            self.register_labels[actual_dst] = label;
        }
        true
    }

    /// Store a compact operator's Public primitive result in the slot
    /// the compact numeric operand guards found eligible: the write
    /// `write_reg_with_label` makes on its static path, without checking
    /// eligibility a second time (bd-9vouw.504). Nothing runs between the
    /// check and this write but the operator's primitive numeric arithmetic.
    #[inline(always)]
    pub(super) fn write_static_slot(&mut self, slot: StaticWriteSlot, value: Value) {
        debug_assert!(Self::static_register_value(&value));
        let StaticWriteSlot(actual_reg) = slot;
        self.note_register_written(actual_reg);
        self.mutate_registers_by_bytes(0, 0, |registers| registers[actual_reg] = value);
        if !self.all_register_labels_public {
            self.register_labels[actual_reg] = Label::Public;
        }
    }

    #[inline]
    pub(super) fn execute_compact_relational(
        &mut self,
        dst: u32,
        lhs: u32,
        rhs: u32,
        operator: &str,
    ) -> Result<(), InterpreterError> {
        if let Some((left, right, slot)) = self.compact_public_int_operands(dst, lhs, rhs) {
            // Preserve the canonical interpreter's current numeric comparison
            // projection through f64, including its behavior above 2^53.
            let left = left as f64;
            let right = right as f64;
            let result = match operator {
                "<" => left < right,
                "<=" => left <= right,
                ">" => left > right,
                ">=" => left >= right,
                _ => unreachable!("compact relational opcode is statically validated"),
            };
            self.write_static_slot(slot, Value::Bool(result));
            self.record_tier_i_specialization();
        } else {
            let result_label = self.binary_operation_label(lhs, rhs)?;
            let result = self.eval_relational(lhs, rhs, operator)?;
            self.write_reg_with_label(dst, result, result_label)?;
        }
        self.ip += 1;
        Ok(())
    }

    #[inline]
    pub(super) fn execute_compact_equality(
        &mut self,
        dst: u32,
        lhs: u32,
        rhs: u32,
        strict: bool,
        negate: bool,
    ) -> Result<(), InterpreterError> {
        if let Some((left, right, slot)) = self.compact_public_int_operands(dst, lhs, rhs) {
            let matches = left == right;
            self.write_static_slot(slot, Value::Bool(if negate { !matches } else { matches }));
            self.record_tier_i_specialization();
        } else {
            let result_label = self.binary_operation_label(lhs, rhs)?;
            let result = self.eval_equality(lhs, rhs, strict, negate)?;
            self.write_reg_with_label(dst, result, result_label)?;
        }
        self.ip += 1;
        Ok(())
    }

    #[inline]
    pub(super) fn execute_compact_bitwise(
        &mut self,
        dst: u32,
        lhs: u32,
        rhs: u32,
        operator: &str,
    ) -> Result<(), InterpreterError> {
        if let Some((left, right, slot)) = self.compact_public_int_operands(dst, lhs, rhs) {
            let left = left as i32;
            let right = right as i32;
            let shift = (right as u32) & 31;
            let result = match operator {
                "&" => (left & right) as i64,
                "|" => (left | right) as i64,
                "^" => (left ^ right) as i64,
                "<<" => left.wrapping_shl(shift) as i64,
                ">>" => left.wrapping_shr(shift) as i64,
                ">>>" => (left as u32).wrapping_shr(shift) as i64,
                _ => unreachable!("compact bitwise opcode is statically validated"),
            };
            self.write_static_slot(slot, Value::Int(result));
            self.record_tier_i_specialization();
        } else {
            let result_label = self.binary_operation_label(lhs, rhs)?;
            let result = self.eval_bitwise(lhs, rhs, operator)?;
            self.write_reg_with_label(dst, result, result_label)?;
        }
        self.ip += 1;
        Ok(())
    }

    #[inline]
    pub(super) fn compact_tier1_jump(&mut self, target: u32) {
        let target_ip = target as usize;
        if target_ip < self.ip && self.jit_record_loop_iteration(self.ip) {
            let iteration_count = self.jit_get_loop_iteration_count(self.ip);
            self.emit_tier_promotion_event(0, iteration_count);
        }
        self.ip = target_ip;
    }

    // -- Arithmetic helpers ------------------------------------------------

    pub(super) fn check_string_limit(&self, len: usize) -> Result<(), InterpreterError> {
        if len > self.config.max_string_size {
            Err(InterpreterError::StringLimitExceeded {
                length: len,
                max: self.config.max_string_size,
            })
        } else {
            Ok(())
        }
    }

    pub(super) fn eval_add(
        &self,
        module: Option<&Ir3Module>,
        lhs: u32,
        rhs: u32,
    ) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;
        match (&a, &b) {
            // Int + Int: stay in integer domain if within safe integer range, else promote to float
            (Value::Int(x), Value::Int(y)) => Ok(js_int_add(*x, *y)),
            (Value::BigInt(x), Value::BigInt(y)) => {
                Ok(Value::BigInt(Arc::from(Self::add_bigint_decimal(x, y))))
            }
            // Float + Float: float arithmetic
            (Value::Float(x), Value::Float(y)) => Ok(js_number_to_value(x.inner() + y.inner())),
            // Int + Float or Float + Int: promote to float
            (Value::Int(x), Value::Float(y)) => Ok(js_number_to_value(*x as f64 + y.inner())),
            (Value::Float(x), Value::Int(y)) => Ok(js_number_to_value(x.inner() + *y as f64)),
            // String concatenation. `JsString::concat` joins exact UTF-16
            // code units, so a trailing high surrogate heals against a
            // leading low surrogate into the supplementary code point
            // (bd-neika); well-formed operands keep the UTF-8 fast path.
            (Value::Str(x), Value::Str(y)) => {
                self.check_string_limit(x.len().saturating_add(y.len()))?;
                Ok(Value::Str(x.concat(y)))
            }
            (Value::Str(_), Value::Symbol(_)) | (Value::Symbol(_), Value::Str(_)) => {
                Err(InterpreterError::TypeError {
                    expected: "string-concatenable value".to_string(),
                    got: "symbol".to_string(),
                })
            }
            (Value::Str(x), other) => {
                let other_str = match other {
                    Value::Object(id) => self.object_to_coerced_string(*id),
                    Value::Iterator(_) | Value::Generator(_) => "[object Object]".to_string(),
                    Value::Promise(_) => "[object Promise]".to_string(),
                    callable if callable.is_callable() => {
                        self.function_native_source_text(module, callable)
                    }
                    _ => other.to_string(),
                };
                self.check_string_limit(x.len().saturating_add(other_str.len()))?;
                Ok(Value::Str(x.concat(&JsString::from(other_str))))
            }
            (other, Value::Str(y)) => {
                let other_str = match other {
                    Value::Object(id) => self.object_to_coerced_string(*id),
                    Value::Iterator(_) | Value::Generator(_) => "[object Object]".to_string(),
                    Value::Promise(_) => "[object Promise]".to_string(),
                    callable if callable.is_callable() => {
                        self.function_native_source_text(module, callable)
                    }
                    _ => other.to_string(),
                };
                self.check_string_limit(other_str.len().saturating_add(y.len()))?;
                Ok(Value::Str(JsString::from(other_str).concat(y)))
            }
            _ => {
                // JS coercion: non-string primitives coerce to number for +.
                // Use float coercion to handle all numeric cases properly.
                let x = Self::coerce_to_float(&a).ok_or_else(|| InterpreterError::TypeError {
                    expected: "number or string".to_string(),
                    got: format!("{} + {}", a.type_name(), b.type_name()),
                })?;
                let y = Self::coerce_to_float(&b).ok_or_else(|| InterpreterError::TypeError {
                    expected: "number or string".to_string(),
                    got: format!("{} + {}", a.type_name(), b.type_name()),
                })?;
                let result = x + y;
                Ok(js_number_to_value(result))
            }
        }
    }

    pub(super) fn eval_arith(
        &self,
        lhs: u32,
        rhs: u32,
        op: &str,
    ) -> Result<Value, InterpreterError> {
        self.eval_arith_operands(self.read_reg(lhs)?, self.read_reg(rhs)?, op)
    }

    /// `Inc`/`Dec` (bd-9vouw.119): the register's value plus `delta` of its
    /// own numeric type.
    pub(super) fn eval_step(&self, src: u32, delta: i64) -> Result<Value, InterpreterError> {
        Self::step_numeric(&self.read_reg(src)?, delta)
    }

    /// ToNumeric(`value`) plus `delta` (1 or -1) of the same type: a BigInt
    /// steps by `1n`, anything else by the Number 1, computed as `value -
    /// -delta`, the subtraction the earlier `x -= -1` desugar ran. A Symbol,
    /// or an object not yet converted to a primitive, is the subtraction's
    /// TypeError.
    pub(super) fn step_numeric(value: &Value, delta: i64) -> Result<Value, InterpreterError> {
        let unit = match value {
            Value::BigInt(_) => Value::BigInt(Arc::from((-delta).to_string().as_str())),
            _ => Value::Int(-delta),
        };
        Self::eval_arith_values(value, &unit, "sub")
    }

    pub(super) fn eval_arith_operands(
        &self,
        a: Value,
        b: Value,
        op: &str,
    ) -> Result<Value, InterpreterError> {
        let bigint_op = if op == "sub" {
            bigint_ops::BigIntBinaryOp::Sub
        } else {
            bigint_ops::BigIntBinaryOp::Mul
        };
        if let Some(result) = Self::bigint_operands(&a, &b, bigint_op) {
            return result;
        }

        // Fast path: Int op Int stays in integer domain if safe and not producing -0.0
        if let (Value::Int(x), Value::Int(y)) = (&a, &b) {
            match op {
                "sub" => return Ok(js_int_sub(*x, *y)),
                "mul" => return Ok(js_int_mul(*x, *y)),
                _ => {
                    return Err(InterpreterError::TypeError {
                        expected: "sub or mul".to_string(),
                        got: op.to_string(),
                    });
                }
            }
        }

        // Float path: use float arithmetic
        let x = Self::coerce_to_float(&a).ok_or_else(|| InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} {} {}", a.type_name(), op, b.type_name()),
        })?;
        let y = Self::coerce_to_float(&b).ok_or_else(|| InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} {} {}", a.type_name(), op, b.type_name()),
        })?;
        let result = match op {
            "sub" => x - y,
            "mul" => x * y,
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "sub or mul".to_string(),
                    got: op.to_string(),
                });
            }
        };

        Ok(js_number_to_value(result))
    }

    pub(super) fn eval_div(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        self.eval_div_operands(self.read_reg(lhs)?, self.read_reg(rhs)?)
    }

    pub(super) fn eval_div_operands(&self, a: Value, b: Value) -> Result<Value, InterpreterError> {
        if let Some(result) = Self::bigint_operands(&a, &b, bigint_ops::BigIntBinaryOp::Div) {
            return result;
        }
        let x = Self::coerce_to_float(&a).ok_or_else(|| InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} / {}", a.type_name(), b.type_name()),
        })?;
        let y = Self::coerce_to_float(&b).ok_or_else(|| InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} / {}", a.type_name(), b.type_name()),
        })?;

        // JS division semantics: x/0 = Infinity (or -Infinity), 0/0 = NaN, 0 / -5 = -0.0
        let result = x / y;
        Ok(js_number_to_value(result))
    }

    pub(super) fn eval_mod(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        self.eval_mod_operands(self.read_reg(lhs)?, self.read_reg(rhs)?)
    }

    pub(super) fn eval_mod_operands(&self, a: Value, b: Value) -> Result<Value, InterpreterError> {
        if let Some(result) = Self::bigint_operands(&a, &b, bigint_ops::BigIntBinaryOp::Rem) {
            return result;
        }

        // Share the exact integer remainder, negative-zero and overflow cases
        // with compact Number arithmetic.
        if let (Value::Int(x), Value::Int(y)) = (&a, &b) {
            return Ok(js_int_mod(*x, *y));
        }

        let x = Self::coerce_to_float(&a).ok_or_else(|| InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} % {}", a.type_name(), b.type_name()),
        })?;
        let y = Self::coerce_to_float(&b).ok_or_else(|| InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} % {}", a.type_name(), b.type_name()),
        })?;

        // JS modulo semantics: x % 0 = NaN
        let result = x % y;
        Ok(js_number_to_value(result))
    }

    pub(super) fn eval_exp(&self, lhs: u32, rhs: u32) -> Result<Value, InterpreterError> {
        self.eval_exp_operands(self.read_reg(lhs)?, self.read_reg(rhs)?)
    }

    pub(super) fn eval_exp_operands(&self, a: Value, b: Value) -> Result<Value, InterpreterError> {
        if let Some(result) = Self::bigint_operands(&a, &b, bigint_ops::BigIntBinaryOp::Exp) {
            return result;
        }
        let x = Self::coerce_to_float(&a).ok_or_else(|| InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} ** {}", a.type_name(), b.type_name()),
        })?;
        let y = Self::coerce_to_float(&b).ok_or_else(|| InterpreterError::TypeError {
            expected: "number".to_string(),
            got: format!("{} ** {}", a.type_name(), b.type_name()),
        })?;

        Ok(js_number_to_value(js_exponentiate(x, y)))
    }

    pub(super) fn eval_unary_plus(&self, src: u32) -> Result<Value, InterpreterError> {
        self.eval_unary_plus_operand(self.read_reg(src)?)
    }

    pub(super) fn eval_unary_plus_operand(&self, value: Value) -> Result<Value, InterpreterError> {
        match &value {
            Value::Int(n) => {
                if *n >= MIN_SAFE_INTEGER && *n <= MAX_SAFE_INTEGER {
                    Ok(Value::Int(*n))
                } else {
                    Ok(Value::Float(Float64::new(*n as f64)))
                }
            }
            Value::Float(f) => Ok(Value::Float(*f)),
            _ => {
                let number =
                    Self::coerce_to_float(&value).ok_or_else(|| InterpreterError::TypeError {
                        expected: "number-coercible primitive".to_string(),
                        got: value.type_name().to_string(),
                    })?;
                Ok(js_number_to_value(number))
            }
        }
    }

    pub(super) fn eval_unary_neg(&self, src: u32) -> Result<Value, InterpreterError> {
        self.eval_unary_neg_operand(self.read_reg(src)?)
    }

    pub(super) fn eval_unary_neg_operand(&self, value: Value) -> Result<Value, InterpreterError> {
        match &value {
            Value::Int(0) => Ok(Value::Float(Float64::new(-0.0))),
            Value::Int(n) => {
                if let Some(negated) = n.checked_neg() {
                    if negated >= MIN_SAFE_INTEGER && negated <= MAX_SAFE_INTEGER {
                        return Ok(Value::Int(negated));
                    }
                }
                Ok(Value::Float(Float64::new(-(*n as f64))))
            }
            Value::Float(f) => {
                let inner = f.inner();
                Ok(Value::Float(Float64::new(-inner)))
            }
            Value::BigInt(digits) => Ok(Value::BigInt(Arc::from(bigint_ops::negate(digits)))),
            _ => {
                let number =
                    Self::coerce_to_float(&value).ok_or_else(|| InterpreterError::TypeError {
                        expected: "number-coercible primitive".to_string(),
                        got: value.type_name().to_string(),
                    })?;
                Ok(js_number_to_value(-number))
            }
        }
    }

    /// ECMAScript `ToUint32` for a floating-point operand (ECMA-262 §7.1.7):
    /// truncate toward zero and reduce modulo 2^32. Rust's `f64 as u32` cast
    /// *saturates* (since 1.45), so any operand outside `[0, 2^32)` would clamp
    /// to `0` / `u32::MAX` instead of wrapping — wrong for JS semantics
    /// (e.g. `Math.clz32(2**32)` is `32`, not `0`; `Math.clz32(-1.5)` is `0`,
    /// not `32`). NaN and ±Infinity map to 0. `f64 % 2^32` via `rem_euclid` is
    /// exact (IEEE `fmod` is exact), so this is precise for every finite input,
    /// including magnitudes past 2^53.
    pub(super) fn js_to_uint32(value: f64) -> u32 {
        if !value.is_finite() {
            return 0;
        }
        value.trunc().rem_euclid(4_294_967_296.0) as u32
    }

    /// ECMAScript `ToInt32` for a floating-point operand (ECMA-262 §7.1.6):
    /// `ToUint32` reinterpreted as signed. Saturating `f64 as i32` would
    /// collapse every operand whose magnitude exceeds 2^31 to `i32::MAX` —
    /// wrong for JS bitwise/shift semantics, which require modular wrapping
    /// (e.g. `(3000000000.5) | 0` is `-1294967296`, not `2147483647`).
    pub(super) fn js_to_int32(value: f64) -> i32 {
        Self::js_to_uint32(value) as i32
    }

    pub(super) fn eval_bit_not(&self, src: u32) -> Result<Value, InterpreterError> {
        self.eval_bit_not_operand(self.read_reg(src)?)
    }

    pub(super) fn eval_bit_not_operand(&self, value: Value) -> Result<Value, InterpreterError> {
        if let Value::BigInt(digits) = &value {
            return Ok(Value::BigInt(Arc::from(bigint_ops::bitwise_not(digits))));
        }
        // JS bitwise ops: ToInt32 conversion
        let number = match &value {
            Value::Int(n) => *n as i32,
            Value::Float(f) => Self::js_to_int32(f.inner()),
            _ => {
                let n =
                    Self::coerce_to_float(&value).ok_or_else(|| InterpreterError::TypeError {
                        expected: "number-coercible primitive".to_string(),
                        got: value.type_name().to_string(),
                    })?;
                Self::js_to_int32(n)
            }
        };
        Ok(Value::Int((!number) as i64))
    }

    pub(super) fn eval_relational(
        &self,
        lhs: u32,
        rhs: u32,
        op: &str,
    ) -> Result<Value, InterpreterError> {
        self.eval_relational_operands(self.read_reg(lhs)?, self.read_reg(rhs)?, op)
    }

    pub(super) fn eval_relational_operands(
        &self,
        a: Value,
        b: Value,
        op: &str,
    ) -> Result<Value, InterpreterError> {
        // String comparison: lexicographic over exact UTF-16 code units per
        // ES2020 7.2.13 IsLessThan (bd-rdnhc; previously the derived
        // code-point/byte order, which disagrees for astral content and
        // projects lone surrogates to U+FFFD).
        if let (Value::Str(x), Value::Str(y)) = (&a, &b) {
            let ordering = x.utf16_cmp(y);
            let result = match op {
                "<" => ordering == Ordering::Less,
                "<=" => matches!(ordering, Ordering::Less | Ordering::Equal),
                ">" => ordering == Ordering::Greater,
                ">=" => matches!(ordering, Ordering::Greater | Ordering::Equal),
                _ => {
                    return Err(InterpreterError::TypeError {
                        expected: "relational operator".to_string(),
                        got: op.to_string(),
                    });
                }
            };
            return Ok(Value::Bool(result));
        }
        if let Some(ordering) = Self::bigint_relational_order(&a, &b)? {
            return Ok(Value::Bool(ordering.is_some_and(|ordering| match op {
                "<" => ordering == Ordering::Less,
                "<=" => ordering != Ordering::Greater,
                ">" => ordering == Ordering::Greater,
                _ => ordering != Ordering::Less,
            })));
        }

        // Numeric comparison using float (NaN comparisons return false)
        let x = Self::coerce_to_float(&a).ok_or_else(|| InterpreterError::TypeError {
            expected: "comparable primitive".to_string(),
            got: format!("{} {op} {}", a.type_name(), b.type_name()),
        })?;
        let y = Self::coerce_to_float(&b).ok_or_else(|| InterpreterError::TypeError {
            expected: "comparable primitive".to_string(),
            got: format!("{} {op} {}", a.type_name(), b.type_name()),
        })?;

        // JS: any comparison involving NaN returns false
        let result = match op {
            "<" => x < y,
            "<=" => x <= y,
            ">" => x > y,
            ">=" => x >= y,
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "relational operator".to_string(),
                    got: op.to_string(),
                });
            }
        };
        Ok(Value::Bool(result))
    }

    pub(super) fn eval_equality(
        &self,
        lhs: u32,
        rhs: u32,
        strict: bool,
        negate: bool,
    ) -> Result<Value, InterpreterError> {
        let a = self.read_reg(lhs)?;
        let b = self.read_reg(rhs)?;
        let matches = if strict {
            Self::strict_eq_values(&a, &b)
        } else {
            Self::abstract_eq_values(&a, &b)
        };
        Ok(Value::Bool(if negate { !matches } else { matches }))
    }

    /// JavaScript strict equality (===): same type + same value.
    /// For floats: NaN !== NaN, but -0 === +0.
    pub(super) fn strict_eq_values(a: &Value, b: &Value) -> bool {
        match (a, b) {
            // Float === Float: NaN !== NaN, but -0 === +0
            (Value::Float(fa), Value::Float(fb)) => {
                let va = fa.inner();
                let vb = fb.inner();
                if va.is_nan() || vb.is_nan() {
                    false
                } else {
                    va == vb
                }
            }
            // Int === Float or Float === Int: compare as numbers
            (Value::Int(n), Value::Float(f)) | (Value::Float(f), Value::Int(n)) => {
                let fv = f.inner();
                if fv.is_nan() { false } else { *n as f64 == fv }
            }
            // All other types: use derived PartialEq
            _ => a == b,
        }
    }

    pub(super) fn eval_bitwise(
        &self,
        lhs: u32,
        rhs: u32,
        op: &str,
    ) -> Result<Value, InterpreterError> {
        self.eval_bitwise_operands(self.read_reg(lhs)?, self.read_reg(rhs)?, op)
    }

    pub(super) fn eval_bitwise_operands(
        &self,
        a: Value,
        b: Value,
        op: &str,
    ) -> Result<Value, InterpreterError> {
        if matches!(a, Value::BigInt(_)) || matches!(b, Value::BigInt(_)) {
            let bigint_op = match op {
                "&" => bigint_ops::BigIntBinaryOp::And,
                "|" => bigint_ops::BigIntBinaryOp::Or,
                "^" => bigint_ops::BigIntBinaryOp::Xor,
                "<<" => bigint_ops::BigIntBinaryOp::Shl,
                ">>" => bigint_ops::BigIntBinaryOp::Shr,
                // BigInt::unsignedRightShift throws (ES2020 6.1.6.2.11).
                _ => {
                    return Err(InterpreterError::TypeError {
                        expected: "BigInt operator other than >>>".to_string(),
                        got: op.to_string(),
                    });
                }
            };
            return Self::bigint_operands(&a, &b, bigint_op)
                .expect("a BigInt operand selects the BigInt path");
        }

        // JS ToInt32: truncate toward zero then reduce modulo 2^32 (wrapping,
        // not saturating — see `js_to_int32`).
        let to_i32 = |v: &Value| -> Result<i32, InterpreterError> {
            match v {
                Value::Int(n) => Ok(*n as i32),
                Value::Float(f) => Ok(Self::js_to_int32(f.inner())),
                _ => {
                    let n =
                        Self::coerce_to_float(v).ok_or_else(|| InterpreterError::TypeError {
                            expected: "number".to_string(),
                            got: v.type_name().to_string(),
                        })?;
                    Ok(Self::js_to_int32(n))
                }
            }
        };

        let x = to_i32(&a)?;
        let y = to_i32(&b)?;
        let shift = (y as u32) & 31;

        let result = match op {
            "&" => (x & y) as i64,
            "|" => (x | y) as i64,
            "^" => (x ^ y) as i64,
            "<<" => x.wrapping_shl(shift) as i64,
            ">>" => x.wrapping_shr(shift) as i64,
            ">>>" => (x as u32).wrapping_shr(shift) as i64,
            _ => {
                return Err(InterpreterError::TypeError {
                    expected: "bitwise operator".to_string(),
                    got: op.to_string(),
                });
            }
        };
        Ok(Value::Int(result))
    }

    /// `lhs instanceof rhs`. The label is the result label of a user
    /// `Symbol.hasInstance` handler when one decided the result.
    pub(super) fn eval_instanceof(
        &mut self,
        module: &Ir3Module,
        lhs: u32,
        rhs: u32,
    ) -> Result<(Value, Option<Label>), InterpreterError> {
        let candidate = self.read_reg(lhs)?;
        let constructor = self.read_reg(rhs)?;
        // ES2020 12.10.4 InstanceofOperator step 2: GetMethod(target,
        // @@hasInstance). A user handler (typically `static
        // [Symbol.hasInstance]`) decides the result via ToBoolean. The
        // intrinsic Function.prototype[@@hasInstance] is OrdinaryHasInstance,
        // which the code below performs.
        if let Some(handler) = self.user_has_instance_handler(module, &constructor)? {
            // The intrinsic Function.prototype[@@hasInstance], found along a
            // backing object's chain, is the OrdinaryHasInstance below; no
            // guest call is needed, and it answers false for a target that
            // is not callable (bd-9vouw.268).
            if matches!(&handler, Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::FunctionPrototypeHasInstance)
            {
                if !constructor.is_callable() {
                    return Ok((Value::Bool(false), None));
                }
                return Ok((
                    self.ordinary_instanceof(module, candidate, constructor)?,
                    None,
                ));
            }
            let call_labels = self.clone_isolated_call_labels_from_registers(
                Some(rhs),
                RegRange {
                    start: lhs,
                    count: 1,
                },
            )?;
            let (result, label) = self.invoke_inline_method_call_with_labels(
                Some(module),
                handler,
                constructor,
                vec![candidate],
                None,
                call_labels,
            )?;
            return Ok((Value::Bool(result.is_truthy()), Some(label)));
        }
        Ok((
            self.ordinary_instanceof(module, candidate, constructor)?,
            None,
        ))
    }

    /// A callable `Symbol.hasInstance` on an object target, or among a user
    /// function's own properties (static class members).
    pub(super) fn user_has_instance_handler(
        &mut self,
        module: &Ir3Module,
        target: &Value,
    ) -> Result<Option<Value>, InterpreterError> {
        let backing = match target {
            Value::Object(object_id) => Some(*object_id),
            Value::Function(_)
            | Value::Closure(_)
            | Value::GeneratorFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncGeneratorFunction(_) => {
                self.function_own_property_object(module, target)?
            }
            Value::BuiltinFunction(builtin)
                if matches!(
                    builtin.kind,
                    BuiltinFunctionKind::GeneratedFunction
                        | BuiltinFunctionKind::NativeHttpFunction
                        | BuiltinFunctionKind::NativeChildProcessFunction
                ) =>
            {
                self.function_own_property_object(module, target)?
            }
            _ => None,
        };
        let Some(backing) = backing else {
            return Ok(None);
        };
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::HasInstance.id());
        self.optional_callable_runtime_property(Some(module), backing, &key, target.clone())
    }

    pub(super) fn ordinary_instanceof(
        &mut self,
        module: &Ir3Module,
        candidate: Value,
        constructor: Value,
    ) -> Result<Value, InterpreterError> {
        let mut constructor = constructor;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            match self.bound_function_target(&constructor)? {
                Some(target) => constructor = target,
                None => break,
            }
        }
        // ES2020 12.10.4 InstanceofOperator step 4: the target must be
        // callable, not constructible; a generator function has an object
        // `prototype` its generators inherit from (bd-9vouw.120).
        if !constructor.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable instanceof target".to_string(),
                got: constructor.type_name().to_string(),
            });
        }
        if !candidate.is_object_like() {
            return Ok(Value::Bool(false));
        }
        // A callable proxy (bd-9vouw.132) or a callable that is no
        // constructor (generator, async and arrow functions, methods):
        // OrdinaryHasInstance reads `prototype` through [[Get]]; anything but
        // an object (an arrow's undefined) is a TypeError.
        let prototype = if Self::is_callable_proxy(&constructor)
            || !self.is_constructible_value(&constructor)
            || matches!(
                &constructor,
                Value::BuiltinFunction(builtin)
                    if matches!(
                        builtin.kind,
                        BuiltinFunctionKind::GeneratedFunction
                            | BuiltinFunctionKind::NativeHttpFunction
                            | BuiltinFunctionKind::NativeChildProcessFunction
                    )
            ) {
            let key = RuntimePropertyKey::String(JsString::from("prototype"));
            match self.get_v(module, &constructor, &key)? {
                Value::Object(prototype) => prototype,
                // A function is an object: `F.prototype = fn` (Test262
                // S13.2.2_A1) is searched for as that function.
                function if function.is_callable() => {
                    return Ok(Value::Bool(self.value_prototype_chain_contains(
                        Some(module),
                        &candidate,
                        &function,
                    )?));
                }
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "object-valued constructor prototype".into(),
                        got: other.type_name().into(),
                    });
                }
            }
        } else if let Some((value, _)) =
            self.constructor_prototype_override(module, &constructor)?
        {
            match value {
                Value::Object(prototype) => prototype,
                function if function.is_callable() => {
                    return Ok(Value::Bool(self.value_prototype_chain_contains(
                        Some(module),
                        &candidate,
                        &function,
                    )?));
                }
                _ => {
                    return Err(InterpreterError::TypeError {
                        expected: "object-valued constructor prototype".into(),
                        got: value.type_name().into(),
                    });
                }
            }
        } else {
            match constructor {
                Value::Function(func_idx) => self.ensure_function_prototype(module, func_idx)?,
                Value::Closure(closure_id) => {
                    self.closures.get(closure_id as usize).ok_or_else(|| {
                        InterpreterError::TypeError {
                            expected: "valid closure".to_string(),
                            got: format!("closure#{closure_id} not found"),
                        }
                    })?;
                    let owner_module =
                        self.foreign_closure_module(&Value::Closure(closure_id), module)?;
                    self.ensure_closure_prototype(
                        owner_module.as_deref().unwrap_or(module),
                        closure_id,
                    )?
                }
                Value::BuiltinFunction(builtin)
                    if builtin.kind == BuiltinFunctionKind::EventEmitterConstructor =>
                {
                    self.ensure_builtin_prototype("EventEmitter")?
                }
                // bd-9vouw.34: `x instanceof Date`, `x instanceof Promise`,
                // `x instanceof R` for a standard constructor value `R`.
                Value::BuiltinFunction(builtin)
                    if builtin.kind == BuiltinFunctionKind::StandardConstructor =>
                {
                    let name = Self::standard_constructor_name(&builtin)?;
                    self.ensure_builtin_prototype(name)?
                }
                Value::BuiltinFunction(builtin)
                    if Self::materialized_global_prototype_name(&builtin).is_some() =>
                {
                    let name =
                        Self::materialized_global_prototype_name(&builtin).expect("guarded above");
                    self.ensure_builtin_prototype(name)?
                }
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "function".to_string(),
                        got: other.type_name().to_string(),
                    });
                }
            }
        };

        Ok(Value::Bool(self.value_prototype_chain_contains(
            Some(module),
            &candidate,
            &Value::Object(prototype),
        )?))
    }

    pub(super) fn eval_in_operator(
        &mut self,
        module: &Ir3Module,
        lhs: u32,
        rhs: u32,
    ) -> Result<Value, InterpreterError> {
        let key_value = self.read_reg(lhs)?;
        let target = self.read_reg(rhs)?;
        // ES2020 12.10.3: a non-object right operand throws before
        // ToPropertyKey(left) runs its toString.
        if key_value.is_object_like() && !target.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "object right operand of `in`".to_string(),
                got: target.type_name().to_string(),
            });
        }
        let key_value = self.property_key_primitive(module, key_value)?;
        let key = self.executable_property_key_from_value(&key_value);
        match target {
            Value::Object(object_id) => {
                self.heap
                    .get(object_id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
                self.run_pre_runtime_property_access_hook(module, object_id, &key)?;
                Ok(Value::Bool(self.proxy_aware_has_runtime_property(
                    Some(module),
                    object_id,
                    &key,
                    0,
                )?))
            }
            ref function if function.is_callable() => Ok(Value::Bool(
                self.function_has_property(module, function, &key)?,
            )),
            // Promises, generators, iterators and async objects are objects
            // without a heap backing: [[HasProperty]] sees the members their
            // [[Get]] supplies, then their prototype's chain. lodash tests
            // `Symbol.toStringTag in Object(Promise.resolve())` at load, and
            // every such `in` threw "expected object, got object".
            ref object_like @ (Value::Promise(_)
            | Value::Generator(_)
            | Value::AsyncGeneratorObject(_)
            | Value::Iterator(_)
            | Value::AsyncFunctionObject(_)) => Ok(Value::Bool(self.exotic_has_property(
                module,
                object_like,
                &key,
            )?)),
            other => Err(InterpreterError::TypeError {
                expected: "object".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// [[HasProperty]] of a promise, generator, async generator, iterator or
    /// async function object: its own properties (on its backing object),
    /// the members its [[Get]] supplies, then its prototype's chain.
    pub(super) fn exotic_has_property(
        &mut self,
        module: &Ir3Module,
        object_like: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<bool, InterpreterError> {
        if self.exotic_has_own_property(module, object_like, key)? {
            return Ok(true);
        }
        let supplied = match object_like {
            Value::Promise(_) => key.as_str().is_some_and(|name| {
                !matches!(Self::promise_property_value(name), Value::Undefined)
            }),
            Value::Generator(_) | Value::AsyncGeneratorObject(_) => match key {
                RuntimePropertyKey::String(_) => key
                    .as_str()
                    .is_some_and(|name| matches!(name, "next" | "return" | "throw")),
                RuntimePropertyKey::Symbol(symbol) => {
                    let iterator = if matches!(object_like, Value::Generator(_)) {
                        WellKnownSymbol::Iterator
                    } else {
                        WellKnownSymbol::AsyncIterator
                    };
                    *symbol == iterator.id()
                }
            },
            Value::Iterator(handle) => !matches!(
                self.iterator_runtime_property_value(*handle, key),
                Value::Undefined
            ),
            _ => false,
        };
        if supplied {
            return Ok(true);
        }
        // A promise built by a Promise subclass inherits from that class's
        // prototype (bd-9vouw.137), a generator from its function's
        // `prototype` (bd-9vouw.120).
        if let Some(prototype) = self.exotic_prototype_override(module, object_like)? {
            return self.proxy_aware_has_runtime_property(Some(module), prototype, key, 0);
        }
        if let Some(&intrinsic_prototype) = self
            .exotic_intrinsic_prototype_name(object_like)
            .and_then(|name| self.builtin_prototypes.get(name))
        {
            return self.proxy_aware_has_runtime_property(
                Some(module),
                intrinsic_prototype,
                key,
                0,
            );
        }
        self.object_prototype_has_property(module, key)
    }

    /// Whether Object.prototype (allocated, or the builtins it supplies
    /// virtually) has `key`.
    pub(super) fn object_prototype_has_property(
        &mut self,
        module: &Ir3Module,
        key: &RuntimePropertyKey,
    ) -> Result<bool, InterpreterError> {
        match self.builtin_prototypes.get("Object").copied() {
            Some(object_prototype) => {
                self.proxy_aware_has_runtime_property(Some(module), object_prototype, key, 0)
            }
            None => Ok(key.as_str().is_some_and(|name| {
                name == "constructor" || Self::object_prototype_method(name).is_some()
            })),
        }
    }

    /// HasBinding(name) of the object Environment Record of a `with`
    /// statement (ES2020 8.1.1.2.1): [[HasProperty]], unless the object's
    /// @@unscopables blocks the name.
    pub(super) fn with_has_binding(
        &mut self,
        module: Option<&Ir3Module>,
        object: &Value,
        name: &Value,
    ) -> Result<bool, InterpreterError> {
        let key = self.executable_property_key_from_value(name);
        let found = match object {
            Value::Object(object_id) => {
                if let Some(module) = module {
                    self.run_pre_runtime_property_access_hook(module, *object_id, &key)?;
                }
                self.proxy_aware_has_runtime_property(module, *object_id, &key, 0)?
            }
            function if function.is_callable() => match module {
                Some(module) => self.function_has_property(module, function, &key)?,
                None => false,
            },
            _ => false,
        };
        let Value::Object(object_id) = object else {
            return Ok(found);
        };
        if !found {
            return Ok(false);
        }
        // An array inherits Array.prototype[@@unscopables] once
        // Array.prototype exists; make sure it does.
        if self
            .heap
            .get(object_id.0 as usize)
            .is_some_and(|object| object.is_array)
        {
            self.ensure_builtin_prototype("Array")?;
        }
        let unscopables_key = RuntimePropertyKey::Symbol(WellKnownSymbol::Unscopables.id());
        let unscopables = self.proxy_aware_get_runtime_property(
            module,
            *object_id,
            &unscopables_key,
            object.clone(),
            0,
        )?;
        // ES2020 8.1.1.2.1 step 5: only an object @@unscopables blocks (a
        // deleted or replaced Array.prototype[@@unscopables] blocks nothing).
        let Value::Object(unscopables_id) = unscopables else {
            return Ok(true);
        };
        let blocked =
            self.proxy_aware_get_runtime_property(module, unscopables_id, &key, unscopables, 0)?;
        Ok(!blocked.is_truthy())
    }

    /// [[HasProperty]] of a function value (ES2020 7.3.11), for `in`: its own
    /// properties (its backing object once that exists, else the standard
    /// name/length/prototype), a builtin constructor's statics, what its
    /// backing object inherits (a class's parent statics), then
    /// Function.prototype: its builtins, then the allocated object and its
    /// chain up to Object.prototype.
    pub(super) fn function_has_property(
        &mut self,
        module: &Ir3Module,
        function: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<bool, InterpreterError> {
        if let Some(backing) =
            self.authoritative_standard_constructor_backing(module, function, key)?
        {
            if self
                .heap
                .get(backing.0 as usize)
                .is_some_and(|object| object.contains_own_runtime_property(key))
            {
                return Ok(true);
            }
            return match self.function_value_prototype(Some(module), function)? {
                Value::Object(prototype) => {
                    self.proxy_aware_has_runtime_property(Some(module), prototype, key, 0)
                }
                prototype if prototype.is_callable() => {
                    self.function_has_property(module, &prototype, key)
                }
                _ => Ok(false),
            };
        }
        // A callable proxy and %Function.prototype% have complete property
        // chains on their backing objects (bd-9vouw.132, bd-9vouw.346).
        if let Value::BuiltinFunction(builtin) = function
            && matches!(
                builtin.kind,
                BuiltinFunctionKind::CallableProxy | BuiltinFunctionKind::FunctionPrototype
            )
            && let Some(backing) = Self::builtin_function_property_object(builtin)
        {
            return self.proxy_aware_has_runtime_property(Some(module), backing, key, 0);
        }
        let own = match self.function_own_property_exists(module, function, key)? {
            Some(own) => own,
            None => self.object_own_property_contains(function, &key.value()),
        };
        if own {
            return Ok(true);
        }
        if let Value::BuiltinFunction(builtin) = function
            && builtin.kind == BuiltinFunctionKind::StandardConstructor
            && let Some(name) = key.as_str()
            && !matches!(
                self.standard_constructor_property(builtin, name)?,
                Value::Undefined
            )
        {
            return Ok(true);
        }
        if let Some(backing) = self.function_own_property_object(module, function)?
            && self.proxy_aware_has_runtime_property(Some(module), backing, key, 0)?
        {
            return Ok(true);
        }
        if key
            .as_str()
            .is_some_and(|name| Self::function_prototype_property(name).is_some())
        {
            return Ok(true);
        }
        // bd-9vouw.272: a sloppy ordinary function owns `caller` and
        // `arguments`; any other function inherits %Function.prototype%'s
        // accessors, which, like its Symbol-keyed members, exist only once it
        // is made (see primitive_prototype_get).
        let restricted = matches!(key.as_str(), Some("caller" | "arguments"));
        if restricted && self.is_sloppy_ordinary_function(module, function)? {
            return Ok(true);
        }
        if matches!(key, RuntimePropertyKey::Symbol(_)) || restricted {
            self.ensure_builtin_prototype("Function")?;
        }
        // A generator, async or async generator function's kind prototype
        // inherits from Function.prototype.
        let kind_prototype = Self::function_intrinsic_prototype_name(function)
            .and_then(|name| self.builtin_prototypes.get(name))
            .or_else(|| self.builtin_prototypes.get("Function"))
            .copied();
        if let Some(function_prototype) = kind_prototype {
            return self.proxy_aware_has_runtime_property(Some(module), function_prototype, key, 0);
        }
        self.object_prototype_has_property(module, key)
    }

    pub(super) fn derive_iteration_engine_id(
        &self,
        label: &str,
        canonical: String,
    ) -> EngineObjectId {
        let schema_id = SchemaId::from_definition(b"franken-engine.baseline.iteration-trace.v1");
        let preimage = format!("{}|{}|{}", self.trace_id, label, canonical);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "baseline_interpreter.iterator_protocol",
            &schema_id,
            preimage.as_bytes(),
        )
        .unwrap_or_default()
    }

    /// Start the replay trace of one iteration, or return
    /// `UNTRACED_ITERATION` once `MAX_ITERATION_TRACES` traces exist.
    pub(super) fn start_iteration_trace(
        &mut self,
        kind: IterationKind,
        discriminator: impl FnOnce() -> String,
    ) -> usize {
        let trace_index = self.iteration_traces.len();
        if trace_index >= MAX_ITERATION_TRACES {
            return UNTRACED_ITERATION;
        }
        let discriminator = discriminator();
        let trace_id = self
            .derive_iteration_engine_id("trace", format!("{trace_index}|{}|{discriminator}", kind));
        let record_id = self.derive_iteration_engine_id(
            "record",
            format!("{trace_index}|{}|{discriminator}", kind),
        );
        self.iteration_traces
            .push(IterationTrace::new(trace_id, record_id, kind));
        trace_index
    }

    pub(super) fn iteration_ref_for_object(&self, object_id: ObjectId) -> EngineObjectId {
        self.derive_iteration_engine_id("object", object_id.0.to_string())
    }

    pub(super) fn iteration_ref_for_value(&self, value: &Value) -> EngineObjectId {
        match value {
            Value::Object(object_id) => self.iteration_ref_for_object(*object_id),
            other => {
                self.derive_iteration_engine_id("value", format!("{}|{}", other.type_name(), other))
            }
        }
    }

    pub(super) fn iterator_value_from_runtime(&self, value: &Value) -> IteratorValue {
        match value {
            Value::Undefined => IteratorValue::Undefined,
            Value::Null => IteratorValue::Null,
            Value::Bool(value) => IteratorValue::Boolean(*value),
            Value::Int(value) => IteratorValue::Integer(*value),
            Value::Float(value) => {
                let scaled = value.inner() * 1_000_000.0;
                let fixed = if scaled.is_finite() {
                    scaled.round().clamp(i64::MIN as f64, i64::MAX as f64) as i64
                } else {
                    0
                };
                IteratorValue::FixedPoint(fixed)
            }
            Value::Str(value) => IteratorValue::String(value.to_string()),
            Value::Object(object_id) => {
                IteratorValue::ObjectRef(self.iteration_ref_for_object(*object_id))
            }
            other => IteratorValue::ObjectRef(self.iteration_ref_for_value(other)),
        }
    }

    /// Whether events of `trace_index` are still recorded. Callers check it
    /// before deriving the ids an event carries.
    pub(super) fn iteration_traced(&self, trace_index: usize) -> bool {
        self.iteration_traces
            .get(trace_index)
            .is_some_and(|trace| trace.events.len() < MAX_ITERATION_TRACE_EVENTS)
    }

    pub(super) fn record_iteration_event<F>(&mut self, trace_index: usize, make_event: F)
    where
        F: FnOnce(EngineObjectId, u64) -> IterationEvent,
    {
        if let Some(trace) = self.iteration_traces.get_mut(trace_index)
            && trace.events.len() < MAX_ITERATION_TRACE_EVENTS
        {
            let event = make_event(trace.record_id.clone(), trace.events.len() as u64);
            trace.record_event(event);
        }
    }

    pub(super) fn record_for_in_iteration_next_result(
        &mut self,
        trace_index: usize,
        value: Option<Value>,
    ) {
        self.record_iteration_next_result_impl(trace_index, value, true, true);
    }

    pub(super) fn record_iteration_next_result_impl(
        &mut self,
        trace_index: usize,
        value: Option<Value>,
        exact_for_in_key: bool,
        read_value: bool,
    ) {
        if !self.iteration_traced(trace_index) {
            return;
        }
        let result = match value.as_ref() {
            Some(_) if !read_value => IteratorResult::value(IteratorValue::Unobserved),
            Some(Value::Str(value)) if exact_for_in_key => IteratorResult::value(
                IteratorValue::String(RuntimePropertyKey::String(value.clone()).diagnostic()),
            ),
            Some(value) => IteratorResult::value(self.iterator_value_from_runtime(value)),
            None => IteratorResult::done(),
        };
        let done = result.done;
        let value_for_event = result.value.clone();

        self.record_iteration_event(trace_index, |record_id, step_index| {
            make_next_event(record_id, step_index, result)
        });
        self.record_iteration_event(trace_index, |record_id, step_index| IterationEvent {
            record_id,
            step_index,
            operation: IterationOperation::IteratorComplete { done },
            completion: IterationCompletion::Normal,
        });
        if !done && read_value {
            self.record_iteration_event(trace_index, |record_id, step_index| IterationEvent {
                record_id,
                step_index,
                operation: IterationOperation::IteratorValue {
                    value: value_for_event,
                },
                completion: IterationCompletion::Normal,
            });
        }
    }

    pub(super) fn close_reason_from_ir(reason: IteratorCloseReason) -> CloseReason {
        match reason {
            IteratorCloseReason::Break => CloseReason::Break,
            IteratorCloseReason::Continue => CloseReason::Continue,
            IteratorCloseReason::Return => CloseReason::Return,
            IteratorCloseReason::Throw => CloseReason::Throw,
        }
    }

    pub(super) fn record_iterator_close_event(
        &mut self,
        trace_index: usize,
        reason: CloseReason,
        return_called: bool,
        completion: IterationCompletion,
    ) {
        self.record_iteration_event(trace_index, |record_id, step_index| {
            let mut event = make_close_event(record_id, step_index, reason, return_called);
            event.completion = completion;
            event
        });
    }

    pub(super) fn init_for_in_iterator(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        // ES2020 13.7.5.12 ForIn/OfHeadEvaluation: ToObject(exprValue), so a
        // primitive enumerates its wrapper (a string its indices).
        let mut continue_at = None;
        let callable = value.is_callable().then(|| value.clone());
        let object_id = match value {
            Value::Object(object_id) => object_id,
            // Step 7.a: an undefined or null object enumerates nothing (the
            // body never runs) and is not ToObject'd, which would throw:
            // `for (k in opts)` with `opts` omitted, preact's `h(type, null)`.
            Value::Undefined | Value::Null => {
                let empty = self.alloc_object_with_prototype(None)?;
                let trace_index =
                    self.start_iteration_trace(IterationKind::ForIn, || "nullish".to_string());
                let handle =
                    self.alloc_iterator(RuntimeIteratorState::ForIn(RuntimeForInState {
                        object_id: empty,
                        keys: Vec::new(),
                        next_index: 0,
                        deleted_keys: BTreeSet::new(),
                        done: false,
                        closed: false,
                        trace_index,
                    }))?;
                return Ok(Value::Iterator(handle));
            }
            primitive @ (Value::Str(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::Bool(_)
            | Value::BigInt(_)
            | Value::Symbol(_)) => self.alloc_primitive_wrapper(primitive)?,
            // A function's own properties live on its backing object (its
            // `name` and `length` are not enumerable), bd-9vouw.17; `Date`'s
            // and `Promise`'s on their property object, a callable proxy's
            // on its proxy (bd-9vouw.278).
            Value::BuiltinFunction(ref builtin)
                if Self::builtin_function_property_object(builtin).is_some() =>
            {
                Self::builtin_function_property_object(builtin).expect("checked by the guard")
            }
            ref function if function.is_callable() && module.is_some() => {
                let module = module.expect("checked above");
                self.ensure_function_own_property_object(module, function)?
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "function with an own-property object".to_string(),
                        got: function.type_name().to_string(),
                    })?
            }
            // So do a promise's, generator's or iterator's; its inherited
            // ones come from its intrinsic prototype (bd-9vouw.149), or for
            // a promise a Promise subclass built, that class's (bd-9vouw.137),
            // and for a generator its function's `prototype` (bd-9vouw.120).
            ref exotic if Self::has_exotic_backing_object(exotic) && module.is_some() => {
                let module = module.expect("checked above");
                continue_at = match self.exotic_prototype_override(module, exotic)? {
                    Some(prototype) => Some(prototype),
                    None => match self.exotic_intrinsic_prototype_name(exotic) {
                        Some(name) => Some(self.ensure_builtin_prototype(name)?),
                        None => None,
                    },
                };
                self.ensure_function_own_property_object(module, exotic)?
                    .ok_or_else(|| InterpreterError::TypeError {
                        expected: "object with an own-property object".to_string(),
                        got: exotic.type_name().to_string(),
                    })?
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "object".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };

        // A function's inherited keys come from its value-level [[Prototype]]
        // (%Function.prototype%, a parent class, a function-kind intrinsic),
        // not from its backing object's link, which defaults to
        // Object.prototype (bd-9vouw.488): enumerate the backing objects of
        // the callable ancestors, then continue at the first ordinary object.
        let mut leading = Vec::new();
        if let (Some(function), Some(module)) = (callable.as_ref(), module) {
            let mut prototype = self.function_value_prototype(Some(module), function)?;
            for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
                if !prototype.is_callable() {
                    break;
                }
                let backing = match &prototype {
                    Value::BuiltinFunction(builtin) => {
                        Self::builtin_function_property_object(builtin)
                    }
                    other => self.function_own_property_object(module, other)?,
                };
                leading.extend(backing);
                prototype = self.function_value_prototype(Some(module), &prototype)?;
            }
            if let Value::Object(prototype) = prototype {
                continue_at = Some(prototype);
            }
        }
        let keys = self.collect_for_in_keys_continuing(module, object_id, &leading, continue_at)?;
        let trace_index =
            self.start_iteration_trace(IterationKind::ForIn, || format!("object:{}", object_id.0));
        if self.iteration_traced(trace_index) {
            let object_ref = self.iteration_ref_for_object(object_id);
            let event_keys = keys
                .iter()
                .cloned()
                .map(|key| RuntimePropertyKey::String(key).diagnostic())
                .collect();
            self.record_iteration_event(trace_index, |record_id, step_index| {
                make_enumerate_event(record_id, step_index, object_ref, event_keys)
            });
        }
        let handle = self.alloc_iterator(RuntimeIteratorState::ForIn(RuntimeForInState {
            object_id,
            keys,
            next_index: 0,
            deleted_keys: BTreeSet::new(),
            done: false,
            closed: false,
            trace_index,
        }))?;
        Ok(Value::Iterator(handle))
    }

    pub(super) fn advance_for_in_iterator(
        &mut self,
        iterator: Value,
    ) -> Result<Option<Value>, InterpreterError> {
        let handle = self.expect_iterator_handle(iterator)?;
        let (trace_index, next_value) = match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForIn(state) => {
                if state.closed || state.done {
                    state.done = true;
                    (state.trace_index, None)
                } else {
                    let mut next_value = None;
                    while state.next_index < state.keys.len() {
                        let key = state.keys[state.next_index].clone();
                        state.next_index += 1;
                        if !state.deleted_keys.contains(&key) {
                            next_value = Some(Value::Str(key));
                            break;
                        }
                    }
                    if next_value.is_none() {
                        state.done = true;
                    }
                    (state.trace_index, next_value)
                }
            }
            RuntimeIteratorState::ForOf(_) => {
                return Err(InterpreterError::TypeError {
                    expected: "for..in iterator".to_string(),
                    got: "for..of iterator".to_string(),
                });
            }
        };
        self.record_for_in_iteration_next_result(trace_index, next_value.clone());
        Ok(next_value)
    }

    pub(super) fn prepare_for_of_state(
        &mut self,
        module: Option<&Ir3Module>,
        iterable: &Value,
    ) -> Result<RuntimeForOfInit, InterpreterError> {
        match iterable {
            Value::Iterator(handle) => return Ok(RuntimeForOfInit::from_existing(*handle)),
            Value::Generator(_) => {
                return Ok(RuntimeForOfInit::from_receiver(
                    iterable.clone(),
                    Value::BuiltinFunction(BuiltinFunction::new_kind(
                        BuiltinFunctionKind::GeneratorNext,
                    )),
                ));
            }
            _ => {}
        }
        // bd-suwvw: the timers/promises setInterval iterable is an
        // engine-vended deterministic async iterable — `for await` drives it
        // through the shared for-of machinery, advancing the virtual clock
        // per step (checked before the custom @@iterator probe; the object
        // has no user-visible iterator protocol).
        if let Value::Object(object_id) = iterable
            && let Some(object) = self.heap.get(object_id.0 as usize)
            && object.brand() == Some(TIMERS_PROMISES_INTERVAL_TYPE)
        {
            let delay_ms = match object.properties.get("__delayMs") {
                Some(Value::Int(ms)) => (*ms).max(1) as u64,
                _ => 1,
            };
            let value = object
                .properties
                .get("__value")
                .cloned()
                .unwrap_or(Value::Undefined);
            return Ok(RuntimeForOfInit::from_timers_interval(delay_ms, value));
        }

        // A Map's or Set's live entry list (bd-9vouw.131): entries added
        // by the loop body are visited, deleted ones are not. Only when
        // GetMethod(obj, @@iterator) would find the intrinsic method: a
        // subclass instance or an @@iterator override takes the ordinary
        // path below (quick-lru's `class QuickLRU extends Map` iterates
        // itself with its own generator).
        if let Value::Object(object_id) = iterable {
            let collection = if let Some(storage) = self
                .collection_storage_id(*object_id, "Map")
                .filter(|_| self.collection_iterates_intrinsically(*object_id, "Map"))
            {
                Some((storage, true, RuntimeTypedArrayIteratorKind::Entries))
            } else {
                self.collection_storage_id(*object_id, "Set")
                    .filter(|_| self.collection_iterates_intrinsically(*object_id, "Set"))
                    .map(|storage| (storage, false, RuntimeTypedArrayIteratorKind::Values))
            };
            if let Some((storage, is_map, kind)) = collection {
                return Ok(RuntimeForOfInit::from_collection(
                    RuntimeCollectionIterator {
                        collection: *object_id,
                        storage,
                        is_map,
                        kind,
                    },
                ));
            }
        }

        if let Some(module) = module
            && let Some(init) = self.prepare_custom_for_of_state(module, iterable)?
        {
            return Ok(init);
        }

        if module.is_some() && iterable.is_object_like() {
            // Numeric properties and length do not make an object iterable.
            // GetMethod already performed the observable lookup above; do not
            // add a second lookup or a Proxy has trap when it was nullish.
            return Err(InterpreterError::TypeError {
                expected: "callable Symbol.iterator method".to_string(),
                got: "null or undefined Symbol.iterator".to_string(),
            });
        }

        Ok(RuntimeForOfInit::from_values(
            self.collect_for_of_values(iterable)?,
        ))
    }

    /// Whether GetMethod(`object_id`, @@iterator) on a Map or Set (`kind`)
    /// finds the intrinsic iterator method: no object on the prototype chain
    /// up to the implicit or materialized %Map.prototype% / %Set.prototype%
    /// (a plain subclass's prototypes included) stores its own @@iterator or
    /// is a Proxy, the chain reaches that prototype, and `delete` did not
    /// remove the virtual method. Anything else (an override, a reparented
    /// collection) has to go through the lookup and call.
    pub(super) fn collection_iterates_intrinsically(
        &self,
        object_id: ObjectId,
        kind: &str,
    ) -> bool {
        let iterator = core_symbol_id(WellKnownSymbol::Iterator.id());
        let canonical = self.builtin_prototypes.get(kind).copied();
        let mut current = object_id;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(object) = self.heap.get(current.0 as usize) else {
                return false;
            };
            if object
                .properties
                .baseline_symbol_property(iterator)
                .is_some()
                || !matches!(self.proxy_record(current), Ok(None))
            {
                return false;
            }
            if Some(current) == canonical {
                break;
            }
            match object.prototype {
                Some(prototype) => current = prototype,
                // The implicit canonical prototype.
                None if !object.is_null_prototype && current == object_id => match canonical {
                    Some(prototype) => current = prototype,
                    None => break,
                },
                None => return false,
            }
        }
        if canonical.is_some_and(|prototype| prototype != current) {
            return false;
        }
        !self.canonical_virtual_property_deleted(
            kind,
            &RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id()),
        )
    }

    /// Look up the exact typed `Symbol.iterator` property. Ordinary strings
    /// such as `"@@iterator"` and `"Symbol(1)"` remain ordinary string keys;
    /// treating them as Symbols would reintroduce the identity collision this
    /// migration removes.
    pub(super) fn lookup_symbol_iterator_method(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        receiver: Value,
    ) -> Result<Option<Value>, InterpreterError> {
        let iterator_key = RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id());
        self.optional_callable_runtime_property(module, object_id, &iterator_key, receiver)
    }

    pub(super) fn prepare_custom_for_of_state(
        &mut self,
        module: &Ir3Module,
        iterable: &Value,
    ) -> Result<Option<RuntimeForOfInit>, InterpreterError> {
        if !iterable.is_object_like() {
            return Ok(None);
        }
        let Some(iterable_id) = self.iterator_carrier_backing_id(iterable, "iterable object")?
        else {
            return Ok(None);
        };
        let receiver = iterable.clone();
        let iterator_method =
            self.lookup_symbol_iterator_method(Some(module), iterable_id, receiver.clone())?;

        let Some(iterator_method) = iterator_method else {
            return Ok(None);
        };

        let lookup_label = self.pending_hostcall_result_label.clone();
        // bd-9vouw.70: the intrinsic Array.prototype[Symbol.iterator] is not
        // called. Its ArrayIterator would never be visible to guest code, and
        // its `next` is the intrinsic, so the consumption record steps the
        // array itself: the same length and indexed reads that `next` performs.
        // Calling it, and then its `next` for every element, went through an
        // isolated activation that snapshotted the whole execution state.
        if let (Value::BuiltinFunction(builtin), Value::Object(object_id)) =
            (&iterator_method, iterable)
            && builtin.kind == BuiltinFunctionKind::ArrayValues
        {
            let callback_label = self.intrinsic_array_values_label(*object_id, lookup_label);
            let label = self
                .pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public)
                .join(&callback_label);
            self.replace_pending_hostcall_result_label(Some(label))?;
            return Ok(Some(RuntimeForOfInit::from_array(*object_id)));
        }
        let (iterator_value, callback_label) = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            iterator_method,
            receiver,
            Vec::new(),
            lookup_label,
        )?;
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&callback_label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        self.prepare_custom_iterator_result(module, iterator_value)
            .map(Some)
    }

    /// Capture the iterator's next method once. Both for-of and spread use
    /// this boundary, rather than re-reading a mutable next property per step.
    pub(super) fn prepare_custom_iterator_result(
        &mut self,
        module: &Ir3Module,
        iterator_value: Value,
    ) -> Result<RuntimeForOfInit, InterpreterError> {
        let backing = match &iterator_value {
            Value::Iterator(handle) => return Ok(RuntimeForOfInit::from_existing(*handle)),
            Value::Generator(_) => {
                return Ok(RuntimeForOfInit::from_receiver(
                    iterator_value,
                    Value::BuiltinFunction(BuiltinFunction::new_kind(
                        BuiltinFunctionKind::GeneratorNext,
                    )),
                ));
            }
            // Preserve the exact receiver even when properties live on a
            // separate backing object (for example a builtin function).
            value => self.iterator_carrier_backing_id(value, "object returned by @@iterator")?,
        };
        let iterator_receiver = iterator_value;
        // GetIterator caches Get(iterator, "next"), not GetMethod. A missing
        // or noncallable value fails only if a consumer actually takes a step;
        // an empty pattern must still be able to close the acquired iterator.
        let next_method = match backing {
            Some(iterator_object) => self.iterator_protocol_property(
                Some(module),
                iterator_object,
                &RuntimePropertyKey::String(JsString::from("next")),
                iterator_receiver.clone(),
            )?,
            None => Value::Undefined,
        };

        Ok(RuntimeForOfInit::from_receiver(
            iterator_receiver,
            next_method,
        ))
    }

    pub(super) fn optional_callable_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &str,
        receiver: Value,
    ) -> Result<Option<Value>, InterpreterError> {
        self.optional_callable_runtime_property(
            module,
            object_id,
            &RuntimePropertyKey::String(JsString::from(key)),
            receiver,
        )
    }

    pub(super) fn optional_callable_runtime_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        receiver: Value,
    ) -> Result<Option<Value>, InterpreterError> {
        let value = self.iterator_protocol_property(module, object_id, key, receiver)?;
        match value {
            Value::Undefined | Value::Null => Ok(None),
            value if value.is_callable() => Ok(Some(value)),
            other => Err(InterpreterError::TypeError {
                expected: format!("callable property '{}' or undefined", key.diagnostic()),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// bd-es2ra: resolve the ordinary-property backing object for an
    /// object-like iterator-protocol carrier. `Value::Object` is its own
    /// backing; the only function-like values with ordinary-property storage
    /// in this engine are the builtin kinds that own a property object. Every
    /// other object-like carrier has no ordinary property storage, so its
    /// protocol properties read as `undefined` — callers get `Ok(None)`.
    /// Primitives reject with the caller's TypeError expectation, matching
    /// the historical messages. Twin: core `iterator_carrier_backing_id`
    /// (which resolves through core's materialized function objects).
    pub(super) fn iterator_carrier_backing_id(
        &self,
        value: &Value,
        expected: &str,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        if !value.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: expected.to_string(),
                got: value.type_name().to_string(),
            });
        }
        Ok(match value {
            Value::Object(object_id) => Some(*object_id),
            Value::BuiltinFunction(builtin) => Self::builtin_function_property_object(builtin),
            _ => None,
        })
    }

    pub(super) fn iterator_protocol_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        if let Some(module) = module {
            self.run_pre_runtime_property_access_hook(module, object_id, key)?;
        }
        if self.active_inline_callback_context_label.is_some() {
            self.reflect_observe_selected_property(object_id, key)?;
        }
        let stored_label = self.runtime_property_label(object_id, key);
        // Publish before Get: a getter that throws still carries the property
        // selection provenance. Successful callback labels join this value.
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&stored_label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        self.observe_scoped_callback_result()?;
        let value = self.proxy_aware_get_runtime_property(module, object_id, key, receiver, 0);
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&stored_label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        self.observe_scoped_callback_result()?;
        value
    }

    pub(super) fn iterator_result_property(
        &mut self,
        module: &Ir3Module,
        result: &Value,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        // bd-es2ra: every object-like carrier is a valid iterator result;
        // only primitives reject. A carrier without ordinary-property backing
        // reads its protocol properties as undefined.
        let Some(result_id) = self.iterator_carrier_backing_id(result, "iterator result object")?
        else {
            return Ok(Value::Undefined);
        };
        self.iterator_protocol_property(
            Some(module),
            result_id,
            &RuntimePropertyKey::String(JsString::from(key)),
            result.clone(),
        )
    }

    pub(super) fn iterator_result_done(
        &mut self,
        module: &Ir3Module,
        result: &Value,
    ) -> Result<bool, InterpreterError> {
        Ok(self
            .iterator_result_property(module, result, "done")?
            .is_truthy())
    }

    pub(super) fn iterator_result_value(
        &mut self,
        module: &Ir3Module,
        result: &Value,
    ) -> Result<Value, InterpreterError> {
        self.iterator_result_property(module, result, "value")
    }

    pub(super) fn init_for_of_iterator(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        let init = self.prepare_for_of_state(module, &value)?;
        self.init_iterator_from_state(value, init, IterationKind::ForOf)
    }

    pub(super) fn init_iterator_from_state(
        &mut self,
        value: Value,
        init: RuntimeForOfInit,
        kind: IterationKind,
    ) -> Result<Value, InterpreterError> {
        self.init_iterator_from_state_with_symbol(value, init, kind, IteratorSymbolKind::Iterator)
    }

    pub(super) fn init_iterator_from_state_with_symbol(
        &mut self,
        value: Value,
        init: RuntimeForOfInit,
        kind: IterationKind,
        symbol_kind: IteratorSymbolKind,
    ) -> Result<Value, InterpreterError> {
        let trace_index = self
            .start_iteration_trace(kind, || format!("iterable:{}|{}", value.type_name(), value));
        if self.iteration_traced(trace_index) {
            let iterable_ref = self.iteration_ref_for_value(&value);
            self.record_iteration_event(trace_index, |record_id, step_index| {
                make_get_iterator_event(record_id, step_index, symbol_kind, iterable_ref)
            });
        }
        let storage = init.collection.as_ref().map(|iterator| iterator.storage);
        let handle = self.alloc_iterator(RuntimeIteratorState::ForOf(RuntimeForOfState {
            values: init.values,
            next_index: 0,
            array: init.array,
            typed_array: init.typed_array,
            collection: init.collection,
            iterator_receiver: init.iterator_receiver,
            next_method: init.next_method,
            timers_interval: init.timers_interval,
            done: false,
            closed: false,
            return_called: false,
            trace_index,
        }))?;
        if let Some(storage) = storage {
            self.collection_iterators
                .entry(storage)
                .or_default()
                .insert(handle);
        }
        Ok(Value::Iterator(handle))
    }

    pub(super) fn advance_for_of_iterator(
        &mut self,
        module: Option<&Ir3Module>,
        iterator: Value,
    ) -> Result<Option<Value>, InterpreterError> {
        self.advance_for_of_iterator_with_value_read(module, iterator, true)
    }

    /// Advance the canonical iterator once. Elisions perform IteratorStep but
    /// not IteratorValue: a custom result's `value` getter must not run.
    pub(super) fn advance_for_of_iterator_with_value_read(
        &mut self,
        module: Option<&Ir3Module>,
        iterator: Value,
        read_value: bool,
    ) -> Result<Option<Value>, InterpreterError> {
        enum ForOfStep {
            Done,
            Value(Value),
            Array {
                iterator: RuntimeArrayIterator,
                index: usize,
            },
            TypedArray {
                iterator: RuntimeTypedArrayIterator,
                index: usize,
            },
            Collection {
                iterator: RuntimeCollectionIterator,
                index: usize,
            },
            /// bd-suwvw: timers/promises interval tick — advance the virtual
            /// clock by the delay, then yield the value.
            IntervalTick {
                delay_ms: u64,
                value: Value,
            },
            Custom {
                receiver: Value,
                next_method: Value,
            },
        }

        let handle = self.expect_iterator_handle(iterator)?;
        // ES2024 23.1.5.1 %ArrayIteratorPrototype%.next: a typed array
        // iterator reads its array's current view each step, so it sees a
        // resize, and an array out of bounds is a TypeError (bd-9vouw.256).
        let fresh_typed_view = match self.iterators.get(handle as usize) {
            Some(RuntimeIteratorState::ForOf(state)) if !state.closed && !state.done => state
                .typed_array
                .as_ref()
                .and_then(|iterator| self.heap.get(iterator.object.0 as usize))
                .and_then(|object| object.typed_array.as_deref().cloned()),
            _ => None,
        };
        if let Some(view) = &fresh_typed_view {
            Self::reject_out_of_bounds_typed_array(view, "next")?;
        }
        let (trace_index, step) = match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForOf(state) => {
                if state.closed || state.done {
                    state.done = true;
                    (state.trace_index, ForOfStep::Done)
                } else if let Some((delay_ms, value)) = state.timers_interval.clone() {
                    (
                        state.trace_index,
                        ForOfStep::IntervalTick { delay_ms, value },
                    )
                } else if let Some(next_method) = state.next_method.clone() {
                    let receiver = state.iterator_receiver.clone().ok_or_else(|| {
                        InterpreterError::TypeError {
                            expected: "custom for..of iterator receiver".to_string(),
                            got: "missing iterator receiver".to_string(),
                        }
                    })?;
                    (
                        state.trace_index,
                        ForOfStep::Custom {
                            receiver,
                            next_method,
                        },
                    )
                } else if let Some(iterator) = state.array.clone() {
                    (
                        state.trace_index,
                        ForOfStep::Array {
                            iterator,
                            index: state.next_index,
                        },
                    )
                } else if let Some(iterator) = state.collection.clone() {
                    (
                        state.trace_index,
                        ForOfStep::Collection {
                            iterator,
                            index: state.next_index,
                        },
                    )
                } else if let Some(mut iterator) = state.typed_array.clone() {
                    if let Some(view) = fresh_typed_view {
                        iterator.view = view;
                    }
                    if state.next_index >= iterator.view.length {
                        state.done = true;
                        (state.trace_index, ForOfStep::Done)
                    } else {
                        let index = state.next_index;
                        state.next_index += 1;
                        (state.trace_index, ForOfStep::TypedArray { iterator, index })
                    }
                } else if let Some(value) = state.values.get(state.next_index).cloned() {
                    state.next_index += 1;
                    (state.trace_index, ForOfStep::Value(value))
                } else {
                    state.done = true;
                    (state.trace_index, ForOfStep::Done)
                }
            }
            RuntimeIteratorState::ForIn(_) => {
                return Err(InterpreterError::TypeError {
                    expected: "for..of iterator".to_string(),
                    got: "for..in iterator".to_string(),
                });
            }
        };

        let (receiver, next_method) = match step {
            ForOfStep::Done => {
                self.record_iteration_next_result_impl(trace_index, None, false, read_value);
                return Ok(None);
            }
            ForOfStep::Value(value) => {
                self.record_iteration_next_result_impl(
                    trace_index,
                    Some(value.clone()),
                    false,
                    read_value,
                );
                return Ok(Some(value));
            }
            ForOfStep::Array { iterator, index } => {
                let receiver = Value::Object(iterator.object_id);
                // A typed array iterated by Array.prototype.values / keys /
                // entries reads its view's length each step, and a view out
                // of bounds is a TypeError (ES2024 23.1.5.1 step 2.b.ii), as
                // `ta.values()` does above; it iterated as empty
                // (bd-9vouw.360).
                let typed_view = self
                    .heap
                    .get(iterator.object_id.0 as usize)
                    .and_then(|object| object.typed_array.as_deref().cloned());
                let length = if let Some(view) = typed_view {
                    Self::reject_out_of_bounds_typed_array(&view, "next")?;
                    view.length
                } else {
                    let length = self.iterator_protocol_property(
                        module,
                        iterator.object_id,
                        &RuntimePropertyKey::String(JsString::from("length")),
                        receiver.clone(),
                    )?;
                    if matches!(length, Value::BigInt(_) | Value::Symbol(_)) {
                        return Err(InterpreterError::TypeError {
                            expected: "number-compatible array-like length".to_string(),
                            got: length.type_name().to_string(),
                        });
                    }
                    let length = Self::coerce_to_float(&length).unwrap_or(f64::NAN);
                    if length.is_nan() || length <= 0.0 {
                        0
                    } else {
                        length.floor().min(9_007_199_254_740_991.0) as usize
                    }
                };
                if index >= length {
                    if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                        state.done = true;
                    }
                    self.record_iteration_next_result_impl(trace_index, None, false, read_value);
                    return Ok(None);
                }
                // Advance before the indexed Get, as ArrayIterator.next does.
                // A throwing getter must not make a later next retry that key.
                if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                    state.next_index =
                        index
                            .checked_add(1)
                            .ok_or_else(|| InterpreterError::RangeError {
                                message: "array iterator index exceeds the platform range"
                                    .to_string(),
                            })?;
                }
                let index_value =
                    Value::Int(
                        i64::try_from(index).map_err(|_| InterpreterError::RangeError {
                            message: "array iterator index exceeds the integer range".to_string(),
                        })?,
                    );
                let value = match iterator.kind {
                    RuntimeTypedArrayIteratorKind::Keys => index_value,
                    RuntimeTypedArrayIteratorKind::Values
                    | RuntimeTypedArrayIteratorKind::Entries => {
                        let element = self.iterator_protocol_property(
                            module,
                            iterator.object_id,
                            &RuntimePropertyKey::String(JsString::from(index.to_string())),
                            receiver,
                        )?;
                        if iterator.kind == RuntimeTypedArrayIteratorKind::Entries {
                            Value::Object(self.alloc_array_from_values(&[index_value, element])?)
                        } else {
                            element
                        }
                    }
                };
                self.record_iteration_next_result_impl(
                    trace_index,
                    Some(value.clone()),
                    false,
                    read_value,
                );
                return Ok(Some(value));
            }
            ForOfStep::Collection { iterator, index } => {
                // The entry at `index` of the live insertion order; past its
                // end the iterator is done for good, even if entries are
                // added later (ES2020 23.1.5.2.1 step 12).
                let Some((repr, stored)) = self.collection_entry_at(iterator.storage, index) else {
                    if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                        state.done = true;
                    }
                    self.record_iteration_next_result_impl(trace_index, None, false, read_value);
                    return Ok(None);
                };
                if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                    state.next_index = index.saturating_add(1);
                }
                if let Some(collection_label) = self
                    .object_mutation_labels
                    .get(&iterator.collection)
                    .cloned()
                {
                    let label = self
                        .pending_hostcall_result_label
                        .as_ref()
                        .unwrap_or(&Label::Public)
                        .join(&collection_label);
                    self.replace_pending_hostcall_result_label(Some(label))?;
                }
                let value = if iterator.is_map {
                    let key = Self::collection_key_from_repr(&repr);
                    match iterator.kind {
                        RuntimeTypedArrayIteratorKind::Keys => key,
                        RuntimeTypedArrayIteratorKind::Values => stored,
                        RuntimeTypedArrayIteratorKind::Entries => {
                            Value::Object(self.alloc_array_from_values(&[key, stored])?)
                        }
                    }
                } else if iterator.kind == RuntimeTypedArrayIteratorKind::Entries {
                    Value::Object(self.alloc_array_from_values(&[stored.clone(), stored])?)
                } else {
                    stored
                };
                self.record_iteration_next_result_impl(
                    trace_index,
                    Some(value.clone()),
                    false,
                    read_value,
                );
                return Ok(Some(value));
            }
            ForOfStep::TypedArray { iterator, index } => {
                let storage_label = self.binary_storage_label(iterator.view.buffer);
                let label = self
                    .pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public)
                    .join(&storage_label);
                self.replace_pending_hostcall_result_label(Some(label))?;
                let element = self.with_array_buffer_bytes(iterator.view.buffer, |bytes| {
                    Self::read_typed_array_element_bytes(&iterator.view, bytes, index)
                })??;
                let value = match iterator.kind {
                    RuntimeTypedArrayIteratorKind::Entries => {
                        let index =
                            i64::try_from(index).map_err(|_| InterpreterError::TypeError {
                                expected: "typed-array iterator index within i64".to_string(),
                                got: index.to_string(),
                            })?;
                        Value::Object(self.alloc_array_from_values(&[Value::Int(index), element])?)
                    }
                    RuntimeTypedArrayIteratorKind::Keys => {
                        Value::Int(i64::try_from(index).map_err(|_| {
                            InterpreterError::TypeError {
                                expected: "typed-array iterator index within i64".to_string(),
                                got: index.to_string(),
                            }
                        })?)
                    }
                    RuntimeTypedArrayIteratorKind::Values => element,
                };
                self.record_iteration_next_result_impl(
                    trace_index,
                    Some(value.clone()),
                    false,
                    read_value,
                );
                return Ok(Some(value));
            }
            ForOfStep::IntervalTick { delay_ms, value } => {
                // bd-suwvw: one deterministic interval tick — the "await"
                // between iterations is modeled as a virtual-clock advance.
                let now = self.event_loop.clock.now_ms();
                self.event_loop
                    .clock
                    .advance_to(now.saturating_add(delay_ms));
                self.record_iteration_next_result_impl(
                    trace_index,
                    Some(value.clone()),
                    false,
                    read_value,
                );
                return Ok(Some(value));
            }
            ForOfStep::Custom {
                receiver,
                next_method,
            } => (receiver, next_method),
        };
        let module = module.ok_or_else(|| InterpreterError::TypeError {
            expected: "module-backed iterator.next dispatch".to_string(),
            got: "missing module context".to_string(),
        })?;
        let lookup_label = self.pending_hostcall_result_label.clone();
        let (result, callback_label) = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            next_method,
            receiver,
            Vec::new(),
            lookup_label,
        )?;
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&callback_label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        if self.iterator_result_done(module, &result)? {
            if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
                state.done = true;
            }
            self.record_iteration_next_result_impl(trace_index, None, false, read_value);
            Ok(None)
        } else {
            let value = if read_value {
                self.iterator_result_value(module, &result)?
            } else {
                Value::Undefined
            };
            self.record_iteration_next_result_impl(
                trace_index,
                Some(value.clone()),
                false,
                read_value,
            );
            Ok(Some(value))
        }
    }

    /// Map a host [`InterpreterError`] to the JS error-constructor name it
    /// should surface as when it escapes into a JS `try`/`catch` block
    /// (bd-8enww.4.3). Returns `None` for engine faults and resource limits
    /// (budget, memory, cancellation, containment, …) which must NOT be
    /// swallowed by untrusted `catch` blocks — those keep propagating as host
    /// errors to the eval boundary. A stack overflow is a RangeError, as in
    /// every JS engine (bd-9vouw.72): catching one unwinds the frames it
    /// counted, so the depth limit still holds for whatever runs next.
    pub(super) fn js_catchable_error_name(err: &InterpreterError) -> Option<&'static str> {
        match err {
            // Language type errors: `null.x`, bad receivers, non-callable
            // calls, and "assignment to constant variable" all surface as
            // `TypeError` in JS.
            InterpreterError::TypeError { .. } | InterpreterError::ConstAssignment { .. } => {
                Some("TypeError")
            }
            InterpreterError::RangeError { .. } | InterpreterError::StackOverflow { .. } => {
                Some("RangeError")
            }
            InterpreterError::HostFilesystem { .. } | InterpreterError::HostProcess { .. } => {
                Some("Error")
            }
            // Temporal-dead-zone access of a `let`/`const` binding is a
            // `ReferenceError` per ES semantics.
            InterpreterError::UninitializedBinding { .. }
            | InterpreterError::UndefinedBinding { .. } => Some("ReferenceError"),
            _ => None,
        }
    }

    /// Whether an error ends the entire guest execution rather than one
    /// JavaScript activation. This shares the catch boundary used by the VM:
    /// engine faults, resource limits, cancellation, capability denials and
    /// containment must not be converted into deferred guest cleanup work.
    pub(super) fn stops_guest_execution(error: &InterpreterError) -> bool {
        !matches!(
            error,
            InterpreterError::Halted | InterpreterError::UncaughtException { .. }
        ) && Self::js_catchable_error_name(error).is_none()
    }

    /// Build a JS error object (name/message/stack) for a host
    /// [`InterpreterError`] so it can be bound as the catch parameter when a
    /// native runtime error is caught by JS `try`/`catch` (bd-8enww.4.3). The
    /// `message` preserves the interpreter's diagnostic string so logs can
    /// still distinguish the originating fault; a stack overflow carries the
    /// message code tests for (`Maximum call stack size exceeded`).
    pub(super) fn native_error_to_thrown_value(
        &mut self,
        err: &InterpreterError,
    ) -> Result<Value, InterpreterError> {
        let name = Self::js_catchable_error_name(err).unwrap_or("Error");
        let message = match err {
            InterpreterError::StackOverflow { .. } => {
                "Maximum call stack size exceeded".to_string()
            }
            // The message already is the JavaScript text ("Invalid time
            // value"); the Display prefix is for host diagnostics.
            InterpreterError::RangeError { message } => message.clone(),
            // A property access on null or undefined (bd-9vouw.108):
            // "Cannot read properties of null (reading 'x')", as Node.
            InterpreterError::TypeError { expected, got }
                if expected == "object"
                    && (got.starts_with("null (") || got.starts_with("undefined (")) =>
            {
                let action = if got.contains(" (setting '") {
                    "set"
                } else {
                    "read"
                };
                format!("Cannot {action} properties of {got}")
            }
            // JSON.stringify of a cycle: Node's first line, which code
            // matching on "circular structure" reads. Node goes on to name
            // the property path that closes the circle; that path can carry
            // labeled keys, so it stays out of the message.
            InterpreterError::TypeError { expected, got }
                if expected == "acyclic JSON value" && got == "circular structure" =>
            {
                "Converting circular structure to JSON".to_string()
            }
            _ => err.to_string(),
        };
        let prototype = self.ensure_builtin_prototype(name)?;
        let error_id = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_like_object(error_id, name, message)?;
        if let InterpreterError::HostFilesystem { code, .. } = err {
            self.set_object_property(error_id, "code".to_string(), Value::str(code.as_str()))?;
        }
        if let InterpreterError::HostProcess {
            code,
            status,
            signal,
            stdout,
            stderr,
            ..
        } = err
        {
            let code_value = if code == "CHILD_PROCESS_EXIT" {
                status.map_or(Value::Null, |status| Value::Int(i64::from(status)))
            } else {
                Value::str(code.as_str())
            };
            let stdout = self.process_output_value(stdout, None)?;
            let stderr = self.process_output_value(stderr, None)?;
            self.set_object_property(error_id, "code".to_string(), code_value)?;
            self.set_object_property(
                error_id,
                "status".to_string(),
                status.map_or(Value::Null, |status| Value::Int(i64::from(status))),
            )?;
            self.set_object_property(
                error_id,
                "signal".to_string(),
                signal.map_or(Value::Null, |signal| Value::Int(i64::from(signal))),
            )?;
            self.set_object_property(error_id, "stdout".to_string(), stdout)?;
            self.set_object_property(error_id, "stderr".to_string(), stderr)?;
        }
        Ok(Value::Object(error_id))
    }

    /// `AggregateError(errors, message, options)` (ES2021 20.5.7.1.1,
    /// bd-9vouw.75). `new` and a plain call construct alike.
    pub(super) fn construct_aggregate_error(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("AggregateError")?;
        let error_id = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_aggregate_error(module, error_id, args)?;
        Ok(Value::Object(error_id))
    }

    /// Steps 3-7: `message` and `cause` as for the other native errors (they
    /// are the second and third arguments here), then `errors` =
    /// IterableToList(errors) as an own non-enumerable array. A non-iterable
    /// `errors` is a TypeError, not an array-like.
    pub(super) fn initialize_aggregate_error(
        &mut self,
        module: Option<&Ir3Module>,
        error_id: ObjectId,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        let message_args = RegRange {
            start: args.start.saturating_add(1),
            count: args.count.saturating_sub(1),
        };
        let message = self.error_message_from_args(module, message_args)?;
        self.initialize_error_object(error_id, message)?;
        self.install_error_cause(error_id, message_args)?;
        let errors = self.iterable_to_array(
            module,
            RegRange {
                start: args.start,
                count: args.count.min(1),
            },
        )?;
        let key = RuntimePropertyKey::String(JsString::from("errors"));
        let mut label = if args.count > 0 {
            self.get_register_label(args.start)?.clone()
        } else {
            Label::Public
        };
        if let Some(iteration_label) = self.take_pending_hostcall_result_label() {
            label = label.join(&iteration_label);
        }
        self.set_own_runtime_property_label(error_id, &key, &label)?;
        self.set_object_property(error_id, "errors".to_string(), errors)?;
        self.set_own_property_attributes(error_id, &key, NON_ENUMERABLE_DATA_ATTRIBUTES)
    }

    /// `builtin:Error` / `builtin:TypeError` / … hostcall arms (bd-bg9l1.27.10).
    pub(super) fn construct_error_object(
        &mut self,
        module: Option<&Ir3Module>,
        name: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let message = self.error_message_from_args(module, args)?;
        let prototype = self.ensure_builtin_prototype(name)?;
        let error_id = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_object(error_id, message)?;
        self.install_error_cause(error_id, args)?;

        Ok(Value::Object(error_id))
    }

    /// ES2022 20.5.8.1 InstallErrorCause: when the second constructor
    /// argument is an object that has a `cause` (own or inherited), the error
    /// gets an own non-enumerable `cause` with that value and its IFC label.
    /// `new Error(m, { cause })` used to drop it, so `err.cause.message`
    /// threw. An accessor `cause` would need a guest getter call and is left
    /// uninstalled.
    pub(super) fn install_error_cause(
        &mut self,
        object_id: ObjectId,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        if args.count < 2 {
            return Ok(());
        }
        let options_register = args.start + 1;
        let Value::Object(options) = self.read_reg(options_register)? else {
            return Ok(());
        };
        let Some(cause) = self
            .chain_data_property(options, "cause")
            .filter(|value| !matches!(value, Value::Accessor { .. }))
            .cloned()
        else {
            return Ok(());
        };
        let key = RuntimePropertyKey::String(JsString::from("cause"));
        let label = self.get_register_label(options_register)?.clone();
        self.set_own_runtime_property_label(object_id, &key, &label)?;
        self.set_object_property(object_id, "cause".to_string(), cause)?;
        self.set_own_property_attributes(object_id, &key, NON_ENUMERABLE_DATA_ATTRIBUTES)
    }

    /// An engine-raised error named `name` (native faults, host errors). Its
    /// prototype normally supplies `name`; an own non-enumerable `name` is
    /// added only when the inherited one differs.
    pub(super) fn initialize_error_like_object(
        &mut self,
        object_id: ObjectId,
        name: &str,
        message: String,
    ) -> Result<(), InterpreterError> {
        let inherited = matches!(
            self.chain_data_property(object_id, "name"),
            Some(Value::Str(inherited)) if inherited.as_ref() == name
        );
        if !inherited {
            self.set_object_property(object_id, "name".to_string(), Value::str(name))?;
            self.set_own_property_attributes(
                object_id,
                &RuntimePropertyKey::String(JsString::from("name")),
                NON_ENUMERABLE_DATA_ATTRIBUTES,
            )?;
        }
        self.initialize_error_object(object_id, Some(message))
    }

    /// ES2020 19.5.1.1 steps 3-4: an own non-enumerable `message` when one was
    /// given, plus V8's own non-enumerable `stack`. `name` stays inherited, so
    /// `JSON.stringify(err)` is `{}` and a subclass's prototype `name` shows.
    pub(super) fn initialize_error_object(
        &mut self,
        object_id: ObjectId,
        message: Option<String>,
    ) -> Result<(), InterpreterError> {
        if let Some(message) = &message {
            self.set_object_property(
                object_id,
                "message".to_string(),
                Value::str(message.as_str()),
            )?;
            self.set_own_property_attributes(
                object_id,
                &RuntimePropertyKey::String(JsString::from("message")),
                NON_ENUMERABLE_DATA_ATTRIBUTES,
            )?;
        }
        // Like V8, `stack` starts with the `Name: message` summary above the
        // frames, so `console.error(err.stack)` shows what went wrong.
        let name = match self.chain_data_property(object_id, "name") {
            Some(Value::Str(name)) => name.to_string(),
            _ => "Error".to_string(),
        };
        let message = message.unwrap_or_default();
        let header = if message.is_empty() {
            name
        } else if name.is_empty() {
            message
        } else {
            format!("{name}: {message}")
        };
        let frames = self.format_stack_trace();
        let stack_trace = if frames.is_empty() {
            header
        } else {
            format!("{header}\n{frames}")
        };
        self.set_object_property(object_id, "stack".to_string(), Value::str(stack_trace))?;
        self.set_own_property_attributes(
            object_id,
            &RuntimePropertyKey::String(JsString::from("stack")),
            NON_ENUMERABLE_DATA_ATTRIBUTES,
        )
    }

    pub(super) fn alloc_iterator_result_object(
        &mut self,
        next_value: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        let result_id = self.alloc_object_with_prototype(None)?;
        let (value, done) = match next_value {
            Some(value) => (value, false),
            None => (Value::Undefined, true),
        };
        self.set_object_property(result_id, "value".to_string(), value)?;
        self.set_object_property(result_id, "done".to_string(), Value::Bool(done))?;
        Ok(Value::Object(result_id))
    }

    pub(super) fn iterator_property_value(&self, iterator_handle: u32, key: &str) -> Value {
        match key {
            "next" => Value::BuiltinFunction(BuiltinFunction::iterator_next(iterator_handle)),
            _ => Value::Undefined,
        }
    }

    pub(super) fn iterator_runtime_property_value(
        &self,
        iterator_handle: u32,
        key: &RuntimePropertyKey,
    ) -> Value {
        match key {
            RuntimePropertyKey::String(key) => key.as_str().map_or(Value::Undefined, |key| {
                self.iterator_property_value(iterator_handle, key)
            }),
            RuntimePropertyKey::Symbol(symbol) if *symbol == WellKnownSymbol::Iterator.id() => {
                Value::BuiltinFunction(BuiltinFunction::iterator_self(iterator_handle))
            }
            RuntimePropertyKey::Symbol(_) => Value::Undefined,
        }
    }

    // =====================================================================
    // E4.T3 (`bd-fqlfw.4.3`): String.prototype family — intrinsic-table
    // generated dispatch, coexisting with the legacy `BuiltinFunctionKind`
    // match arms.
    //
    // The `string_*_impl` fns below hold the family's semantics in exactly one
    // place: the legacy exec arms in `dispatch_builtin_function` delegate to
    // them after the same receiver coercion, and the table-driven path
    // (`dispatch_string_intrinsic`) reaches the same fns through the generated
    // glue (`intrinsics_table::string_prototype::ROWS` + `generate_glue`).
    // Parity between the two routes is asserted by
    // `string_intrinsic_table_parity_tests`. The flip that retires the legacy
    // arms is migration-plan step 5 and is NOT part of this change.
    // =====================================================================

    /// Generated glue for the String.prototype family table, built once.
    ///
    /// Returns `None` if the table fails codegen or cross-artifact
    /// verification. During coexist the legacy arms still serve production
    /// dispatch, so a broken table degrades to legacy behavior; the parity
    /// tests assert the glue builds, making breakage loud at CI time. The
    /// flip (migration-plan step 5) upgrades this to fail-closed.
    #[allow(dead_code)] // production caller lands at the family flip (E4 step 5)
    pub(super) fn string_family_glue() -> Option<&'static GeneratedGlue<'static>> {
        static GLUE: OnceLock<Option<GeneratedGlue<'static>>> = OnceLock::new();
        GLUE.get_or_init(|| {
            let glue = generate_glue(crate::intrinsics_table::string_prototype::ROWS).ok()?;
            glue.verify().ok()?;
            Some(glue)
        })
        .as_ref()
    }

    /// Resolve a row's declared `impl_fn` identifier to its hand-written
    /// semantic fn. ONE mechanical line per method, colocated here — versus
    /// the five scattered edit sites of the legacy seam. A row naming an
    /// unknown identifier resolves to `None`; the binding-completeness parity
    /// test fails on any such drift.
    #[allow(dead_code)] // production caller lands at the family flip (E4 step 5)
    #[allow(clippy::type_complexity)]
    pub(super) fn string_intrinsic_impl_binding(
        impl_fn: &str,
    ) -> Option<fn(&mut Self, &Ir3Module, &JsString, RegRange) -> Result<Value, InterpreterError>>
    {
        Some(match impl_fn {
            "string_char_at_impl" => Self::string_char_at_impl,
            "string_char_code_at_impl" => Self::string_char_code_at_impl,
            "string_at_impl" => Self::string_at_impl,
            "string_to_upper_case_impl" => {
                |core, _, value, args| core.string_to_upper_case_impl(value, args)
            }
            "string_to_lower_case_impl" => {
                |core, _, value, args| core.string_to_lower_case_impl(value, args)
            }
            "string_trim_impl" => |core, _, value, args| core.string_trim_impl(value, args),
            "string_trim_start_impl" => {
                |core, _, value, args| core.string_trim_start_impl(value, args)
            }
            "string_trim_end_impl" => |core, _, value, args| core.string_trim_end_impl(value, args),
            "string_replace_all_impl" => {
                |core, _, value, args| core.string_replace_all_impl(value, args)
            }
            "string_code_point_at_impl" => Self::string_code_point_at_impl,
            "string_locale_compare_impl" => {
                |core, _, value, args| core.string_locale_compare_impl(value, args)
            }
            "string_normalize_impl" => Self::string_normalize_impl,
            "string_split_impl" => Self::string_split_impl,
            "string_includes_impl" => Self::string_includes_impl,
            "string_starts_with_impl" => Self::string_starts_with_impl,
            "string_ends_with_impl" => Self::string_ends_with_impl,
            "string_index_of_impl" => Self::string_index_of_impl,
            "string_last_index_of_impl" => Self::string_last_index_of_impl,
            "string_slice_impl" => Self::string_slice_impl,
            "string_substring_impl" => Self::string_substring_impl,
            "string_replace_impl" => |core, _, value, args| core.string_replace_impl(value, args),
            "string_match_impl" => Self::string_match_impl,
            "string_search_impl" => Self::string_search_impl,
            "string_repeat_impl" => Self::string_repeat_impl,
            "string_pad_start_impl" => Self::string_pad_start_impl,
            "string_pad_end_impl" => Self::string_pad_end_impl,
            _ => return None,
        })
    }

    /// Table-driven dispatch for `String.prototype.<method_key>` (E4.T3).
    ///
    /// Returns `None` when the method is not a generated-dispatch row of the
    /// String family (unknown name, manual escape-hatch row, or glue
    /// failure), in which case the caller falls back to the legacy seam.
    /// Receiver coercion is applied per the row's declared [`ThisCoercion`],
    /// so the coercion policy is table data rather than per-site code. The
    /// row's declared arity is documentation, not an enforcement gate: JS
    /// tolerates missing/extra arguments and the legacy arms behave that way.
    #[allow(dead_code)] // production caller lands at the family flip (E4 step 5)
    pub(super) fn dispatch_string_intrinsic(
        &mut self,
        module: &Ir3Module,
        method_key: &str,
        receiver: Value,
        args: RegRange,
    ) -> Option<Result<Value, InterpreterError>> {
        let glue = Self::string_family_glue()?;
        let full_name = format!("String.prototype.{method_key}");
        let row = glue.registry.get(full_name.as_str())?;
        let impl_fn = match &row.impl_binding {
            ImplBinding::Generated { impl_fn } => Self::string_intrinsic_impl_binding(impl_fn)?,
            // Manual escape-hatch rows keep their documented legacy site.
            ImplBinding::Manual { .. } => return None,
        };
        let coerced = match row.this_coercion {
            // Coercion keeps exact UTF-16 code units for string receivers so
            // lone surrogates survive table dispatch identically to the
            // legacy seam (bd-neika); non-string receivers coerce through
            // the (always well-formed) primitive-string path as before.
            ThisCoercion::ToString => {
                match Self::require_object_coercible_to_js_string(&receiver) {
                    Ok(value) => value,
                    Err(error) => return Some(Err(error)),
                }
            }
            // String-family rows declare ToString; any other coercion is not
            // generated by this seam.
            _ => return None,
        };
        Some(impl_fn(self, module, &coerced, args))
    }

    /// Uniform per-row IFC result-label policy evaluator (E4.T4, `bd-fqlfw.4.4`).
    ///
    /// Evaluates a row's DECLARED [`IfcPropagation`] policy into the result
    /// label for one intrinsic dispatch. The table row is the single source of
    /// propagation truth, replacing hand-wired per-site joins — the omission
    /// pattern behind the bd-0zybl under-tainting class (GetProperty wrote dst
    /// via `write_reg` with no label join, laundering a Secret object's field
    /// to Public). Label conventions follow the dominant register contract
    /// (BinaryOp / UnaryOp / HostCall): the result label is a pure function of
    /// the dispatch inputs, since the dispatch fully overwrites dst's value.
    ///
    /// Returns `Ok(None)` for [`IfcPropagation::Custom`] policies: those name
    /// a hand-written propagation fn owned by the row's documented manual
    /// site; generated glue must not guess at irregular flows (e.g. callback
    /// lanes whose result label depends on the callback's return — bd-ooaka).
    #[allow(dead_code)] // production caller lands at the family flip (E4 step 5)
    pub(super) fn intrinsic_result_label(
        &self,
        policy: &IfcPropagation,
        receiver_label: &Label,
        args: RegRange,
    ) -> Result<Option<Label>, InterpreterError> {
        Ok(Some(match policy {
            IfcPropagation::PropagateReceiverLabel => receiver_label.clone(),
            IfcPropagation::JoinReceiverAndArgs => {
                receiver_label.join(&self.join_arg_range_label(args)?)
            }
            IfcPropagation::JoinArgs => self.join_arg_range_label(args)?,
            IfcPropagation::Constant(class) => class.to_label(),
            IfcPropagation::Custom(_) => return Ok(None),
        }))
    }

    /// Register-shaped table dispatch with uniform IFC propagation (E4.T4,
    /// `bd-fqlfw.4.4`).
    ///
    /// Mirrors the production `CallMethod` register shape: reads the receiver
    /// from `receiver_reg`, dispatches `String.prototype.<method_key>` through
    /// the generated glue ([`Self::dispatch_string_intrinsic`]), and on
    /// success writes the result value to `dst` AND sets `dst`'s IFC label per
    /// the row's declared [`IfcPropagation`] policy. This is the seam the
    /// family flip (migration-plan step 5) routes the production arm through.
    /// The legacy seam performs no label propagation for these methods — a
    /// `secret.toUpperCase()` result kept dst's stale label — which is exactly
    /// the hand-wiring-omission class the per-row policy retires.
    ///
    /// Returns `None` when the method is not a generated-dispatch row of the
    /// String family (caller falls back to the legacy seam, unchanged). On an
    /// `Err` dispatch outcome neither dst's value nor its label is touched,
    /// matching the legacy arms (the error propagates before `write_reg`).
    #[allow(dead_code)] // production caller lands at the family flip (E4 step 5)
    pub(super) fn dispatch_string_intrinsic_to_reg(
        &mut self,
        module: &Ir3Module,
        method_key: &str,
        receiver_reg: u32,
        args: RegRange,
        dst: u32,
    ) -> Option<Result<(), InterpreterError>> {
        let glue = Self::string_family_glue()?;
        let full_name = format!("String.prototype.{method_key}");
        let row = glue.registry.get(full_name.as_str())?;
        let receiver = match self.read_reg(receiver_reg) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        // Capture the receiver's label before dispatch: the impl may allocate
        // (e.g. `split`), and the policy must see the pre-dispatch state.
        let receiver_label = match self.get_register_label(receiver_reg) {
            Ok(label) => label.clone(),
            Err(error) => return Some(Err(error)),
        };
        let value = match self.dispatch_string_intrinsic(module, method_key, receiver, args)? {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let label = match self.intrinsic_result_label(&row.ifc, &receiver_label, args) {
            Ok(label) => label,
            Err(error) => return Some(Err(error)),
        };
        let write_result = match label {
            Some(label) => self.write_reg_with_label(dst, value, label),
            None => self.write_reg(dst, value),
        };
        if let Err(error) = write_result {
            return Some(Err(error));
        }
        Some(Ok(()))
    }

    // ---- String.prototype semantic impl fns (single source of truth) ----
    // Signature contract (required by the fn-pointer binding above):
    //   fn(&mut Self, this_str: &JsString, args: RegRange) -> Result<Value, InterpreterError>
    // `this_str` is the already-coerced receiver (ToString applied by the
    // dispatching seam, legacy or generated).

    pub(super) fn string_char_at_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let index = self.builtin_number_arg(module, args, 0)?;
        Self::string_prototype_char_at_value(Value::Str(this_str.clone()), index)
    }

    pub(super) fn string_char_code_at_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let index = self.builtin_number_arg(module, args, 0)?;
        Self::string_prototype_char_code_at_value(Value::Str(this_str.clone()), index)
    }

    pub(super) fn string_at_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let index = self.builtin_number_arg(module, args, 0)?;
        Self::string_prototype_at_value(Value::Str(this_str.clone()), index)
    }

    pub(super) fn string_to_upper_case_impl(
        &mut self,
        this_str: &JsString,
        _args: RegRange,
    ) -> Result<Value, InterpreterError> {
        this_str
            .try_map_unicode_spans(|text| Ok(text.to_uppercase()))
            .map(Value::Str)
    }

    pub(super) fn string_to_lower_case_impl(
        &mut self,
        this_str: &JsString,
        _args: RegRange,
    ) -> Result<Value, InterpreterError> {
        this_str
            .try_map_unicode_spans(|text| Ok(text.to_lowercase()))
            .map(Value::Str)
    }

    /// TrimString (ES2020 21.1.3.29.1): drop leading and/or trailing
    /// WhiteSpace and LineTerminator code units. Rust's `str::trim` kept
    /// U+FEFF and dropped U+0085, and its UTF-8 projection replaced a lone
    /// surrogate; the code units of such a string are trimmed exactly.
    pub(super) fn js_trim_string(text: &JsString, start: bool, end: bool) -> JsString {
        let is_space = primitive_conversion::is_js_whitespace;
        if let Some(text) = text.as_str() {
            return JsString::from(match (start, end) {
                (true, true) => text.trim_matches(is_space),
                (true, false) => text.trim_start_matches(is_space),
                _ => text.trim_end_matches(is_space),
            });
        }
        let units = text.code_units_vec();
        let unit_is_space = |unit: u16| char::from_u32(u32::from(unit)).is_some_and(is_space);
        let mut from = 0;
        let mut to = units.len();
        while start && from < to && unit_is_space(units[from]) {
            from += 1;
        }
        while end && to > from && unit_is_space(units[to - 1]) {
            to -= 1;
        }
        JsString::from_code_units(&units[from..to])
    }

    pub(super) fn string_trim_impl(
        &mut self,
        this_str: &JsString,
        _args: RegRange,
    ) -> Result<Value, InterpreterError> {
        Ok(Value::Str(Self::js_trim_string(this_str, true, true)))
    }

    pub(super) fn string_trim_start_impl(
        &mut self,
        this_str: &JsString,
        _args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2019 21.1.3.27: trim leading whitespace only.
        Ok(Value::Str(Self::js_trim_string(this_str, true, false)))
    }

    pub(super) fn string_trim_end_impl(
        &mut self,
        this_str: &JsString,
        _args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2019 21.1.3.26: trim trailing whitespace only.
        Ok(Value::Str(Self::js_trim_string(this_str, false, true)))
    }

    /// Intrinsic-table binding (fixed signature, no module); see
    /// [`Self::string_replace_all_method`].
    pub(super) fn string_replace_all_impl(
        &mut self,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.string_replace_all_with_module(None, this_str, args)
    }

    pub(super) fn string_replace_all_method(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.string_replace_all_with_module(Some(module), this_str, args)
    }

    /// ES2021 22.1.3.19 String.prototype.replaceAll: every occurrence of a
    /// string or global RegExp search value; a non-global RegExp is a
    /// TypeError.
    pub(super) fn string_replace_all_with_module(
        &mut self,
        module: Option<&Ir3Module>,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (search, replacement) = self.string_replace_args(module, args)?;
        if self
            .regexp_source_flags_from_value(&search)
            .is_some_and(|(_, flags)| !flags.contains('g'))
        {
            return Err(InterpreterError::TypeError {
                expected: "global RegExp for String.prototype.replaceAll".to_string(),
                got: "non-global RegExp".to_string(),
            });
        }
        let label = self.join_arg_range_label(args)?;
        self.string_replace_js(module, this_str, &search, &replacement, true, label)
    }

    pub(super) fn string_code_point_at_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2015 21.1.3.3 CodePointAt: UTF-16 code-unit indexed, consistent
        // with charAt/charCodeAt/at. A valid high+low pair combines into its
        // supplementary code point, an unpaired surrogate yields its own
        // unit value, and out-of-range / negative => `undefined`.
        // (bd-rdnhc; previously Unicode-scalar indexed.)
        let index = match self.builtin_number_arg(module, args, 0)? {
            Some(arg) => Self::value_as_integer(&arg),
            None => 0,
        };
        if index < 0 {
            return Ok(Value::Undefined);
        }
        Ok(match this_str.code_point_at(index as usize) {
            Some(code_point) => Value::Int(i64::from(code_point)),
            None => Value::Undefined,
        })
    }

    pub(super) fn string_locale_compare_impl(
        &mut self,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let that_string = match self.builtin_arg(args, 0)? {
            Some(value) => self.value_to_string(&value),
            None => "undefined".to_string(),
        };
        let options = self.builtin_arg(args, 2)?.unwrap_or(Value::Undefined);
        let options = self.collation_options(&options)?;
        let ordering =
            collation::locale_compare(this_str.as_utf8_projection(), &that_string, &options);
        Ok(Value::Int(ordering as i64))
    }

    /// The `sensitivity`, `numeric` and `ignorePunctuation` options of
    /// localeCompare (ECMA-402 Intl.Collator); an unknown sensitivity is a
    /// RangeError, as in Node. The locale argument does not change the
    /// order (collation.rs uses the root order).
    pub(super) fn collation_options(
        &mut self,
        options: &Value,
    ) -> Result<collation::CollationOptions, InterpreterError> {
        let mut parsed = collation::CollationOptions::default();
        let Value::Object(options_id) = options else {
            return Ok(parsed);
        };
        let options_id = *options_id;
        let mut read = |key: &str| {
            self.proxy_aware_get_property(None, options_id, key, Value::Object(options_id), 0)
        };
        let sensitivity = read("sensitivity")?;
        let numeric = read("numeric")?;
        let ignore_punctuation = read("ignorePunctuation")?;
        parsed.sensitivity = match &sensitivity {
            Value::Undefined => collation::Sensitivity::Variant,
            Value::Str(text) => match text.as_str() {
                Some("base") => collation::Sensitivity::Base,
                Some("accent") => collation::Sensitivity::Accent,
                Some("case") => collation::Sensitivity::Case,
                Some("variant") => collation::Sensitivity::Variant,
                _ => {
                    return Err(InterpreterError::RangeError {
                        message: format!(
                            "Value {text} out of range for Intl.Collator options property sensitivity"
                        ),
                    });
                }
            },
            other => {
                return Err(InterpreterError::RangeError {
                    message: format!(
                        "Value {} out of range for Intl.Collator options property sensitivity",
                        other.type_name()
                    ),
                });
            }
        };
        parsed.numeric = numeric.is_truthy();
        parsed.ignore_punctuation = ignore_punctuation.is_truthy();
        Ok(parsed)
    }

    pub(super) fn string_normalize_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let form = match self.builtin_string_arg(module, args, 0)? {
            Some(Value::Undefined) | None => "NFC".to_string(),
            Some(value) => self.value_to_string(&value),
        };
        let normalized = this_str
            .try_map_unicode_spans(|text| normalize_unicode_string(text, &form))
            .map_err(|message| InterpreterError::RangeError { message })?;
        Ok(Value::Str(normalized))
    }

    /// ToUint32 of a split `limit`; `undefined` means no limit.
    pub(super) fn split_limit(limit: Value) -> usize {
        match limit {
            Value::Undefined => usize::MAX,
            other => {
                let number = Self::coerce_to_float(&other).unwrap_or(f64::NAN);
                if number.is_finite() {
                    usize::try_from(number.trunc().rem_euclid(4_294_967_296.0) as u64)
                        .unwrap_or(usize::MAX)
                } else {
                    0
                }
            }
        }
    }

    /// ES2020 21.2.5.13 RegExp.prototype[@@split]: the pieces between matches,
    /// with each match's capture groups spliced in. An empty match never
    /// splits at either end of the input or directly after a previous match.
    pub(super) fn regexp_split_pieces(
        &mut self,
        subject: &JsString,
        source: &str,
        flags: &str,
    ) -> Result<Vec<Value>, InterpreterError> {
        let regex = self.compile_regexp_pattern(source, flags)?;
        let prepared =
            self.prepare_regexp_input(subject, flags.contains('u') || flags.contains('v'))?;
        let input = prepared.text();
        let mut pieces = Vec::new();
        if input.is_empty() {
            if !regex.is_match("")? {
                pieces.push(Value::str(""));
            }
            return Ok(pieces);
        }
        let mut last = 0usize;
        let mut budget = self.regexp_retention_budget();
        // @@split runs its own sticky splitter: the caller's flag is moot.
        let matches = self.regexp_all_captures(
            &regex,
            input,
            CaptureRetention::AllGroups,
            &mut budget,
            false,
        )?;
        if let Some(spans) = matches.last() {
            self.record_legacy_regexp_input_match(subject, &prepared, spans);
        }
        for spans in matches {
            let Some((start, end)) = spans[0] else {
                continue;
            };
            if start == end && (start == 0 || start >= input.len() || start == last) {
                continue;
            }
            // Group pieces can overlap (`(?=(.*))`), so their text is
            // charged too: it is not bounded by the input length.
            let piece_bytes = spans[1..]
                .iter()
                .flatten()
                .fold(start - last, |total, (from, to)| {
                    total.saturating_add(to - from)
                })
                .saturating_add(spans.len().saturating_mul(std::mem::size_of::<Value>()));
            self.regexp_charge_retained(&mut budget, piece_bytes)?;
            pieces.push(Value::Str(
                self.decode_regexp_text(&prepared, &input[last..start])?,
            ));
            for group in &spans[1..] {
                pieces.push(match group {
                    Some((from, to)) => {
                        Value::Str(self.decode_regexp_text(&prepared, &input[*from..*to])?)
                    }
                    None => Value::Undefined,
                });
            }
            last = end;
        }
        pieces.push(Value::Str(
            self.decode_regexp_text(&prepared, &input[last..])?,
        ));
        Ok(pieces)
    }

    pub(super) fn string_split_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.19: split into an array of substrings. An
        // `undefined` separator yields the whole string as one element; an
        // empty separator splits per UTF-16 code unit (surrogate pairs
        // split into their halves, matching donor runtimes); a non-empty
        // separator matches exact code units, so lone-surrogate content in
        // either operand survives losslessly (bd-3kvat; previously
        // per-scalar over the lossy projection). A RegExp separator splits
        // on its matches with capture groups spliced in, and `limit` caps
        // the element count (bd-9vouw.40).
        let limit = Self::split_limit(
            self.builtin_number_arg(module, args, 1)?
                .unwrap_or(Value::Undefined),
        );
        let separator_value = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let regexp = self.regexp_source_flags_from_value(&separator_value);
        let separator_value = if regexp.is_none() && !matches!(separator_value, Value::Undefined) {
            self.builtin_string_arg(module, args, 0)?
                .unwrap_or(Value::Undefined)
        } else {
            separator_value
        };
        if limit == 0 {
            return Ok(Value::Object(self.alloc_array_from_values(&[])?));
        }
        if let Some((source, flags)) = regexp {
            let mut pieces = self.regexp_split_pieces(this_str, &source, &flags)?;
            pieces.truncate(limit);
            return Ok(Value::Object(self.alloc_array_from_values(&pieces)?));
        }
        let pieces: Vec<JsString> = match separator_value {
            Value::Undefined => vec![this_str.clone()],
            separator_value => {
                let separator = match separator_value {
                    Value::Str(s) => s,
                    other => JsString::from(self.value_to_string(&other)),
                };
                let units = this_str.code_units_vec();
                let needle = separator.code_units_vec();
                if needle.is_empty() {
                    units
                        .iter()
                        .map(|unit| JsString::from_code_units(std::slice::from_ref(unit)))
                        .collect()
                } else {
                    let mut split_pieces = Vec::new();
                    let mut piece_start = 0usize;
                    let mut cursor = 0usize;
                    while cursor + needle.len() <= units.len() {
                        if units[cursor..cursor + needle.len()] == needle[..] {
                            split_pieces
                                .push(JsString::from_code_units(&units[piece_start..cursor]));
                            cursor += needle.len();
                            piece_start = cursor;
                        } else {
                            cursor += 1;
                        }
                    }
                    split_pieces.push(JsString::from_code_units(&units[piece_start..]));
                    split_pieces
                }
            }
        };
        let pieces = &pieces[..pieces.len().min(limit)];
        let result = self.alloc_array_with_prototype(None)?;
        for (index, piece) in pieces.iter().enumerate() {
            self.set_object_property(result, index.to_string(), Value::Str(piece.clone()))?;
        }
        self.set_object_property(
            result,
            "length".to_string(),
            Value::Int(i64::try_from(pieces.len()).unwrap_or(i64::MAX)),
        )?;
        Ok(Value::Object(result))
    }

    pub(super) fn string_includes_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.7: substring containment from an optional start
        // position (bd-9a8cz.1). Positions are UTF-16 code-unit offsets and
        // the search runs over exact code units, so lone surrogates match
        // exactly and a position inside a surrogate pair is a legal offset
        // (bd-rdnhc; previously scalar-indexed over the projection).
        let search = self.builtin_search_js_string(module, args, 0)?;
        let unit_len = this_str.utf16_len();
        let from = match self.builtin_number_arg(module, args, 1)? {
            Some(arg) => Self::value_as_integer(&arg).clamp(0, unit_len as i64) as usize,
            None => 0,
        };
        Ok(Value::Bool(
            this_str.utf16_index_of(&search, from).is_some(),
        ))
    }

    pub(super) fn string_starts_with_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.20: prefix test at an optional position, over exact
        // UTF-16 code units (bd-9a8cz.1, bd-rdnhc). Only the needle-long
        // slice at `from` is built, not the receiver's units (bd-9vouw.467);
        // canonical JsStrings are equal exactly when their units are.
        let search = self.builtin_search_js_string(module, args, 0)?;
        let len = this_str.utf16_len();
        let from = match self.builtin_number_arg(module, args, 1)? {
            Some(arg) => Self::value_as_integer(&arg).clamp(0, len as i64) as usize,
            None => 0,
        };
        let end = from + search.utf16_len();
        Ok(Value::Bool(
            end <= len && this_str.utf16_slice(from, end) == search,
        ))
    }

    pub(super) fn string_ends_with_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.6: suffix test against the prefix of code-unit
        // length `endPosition` (default = full length) (bd-9a8cz.1,
        // bd-rdnhc). Only the needle-long slice before `end` is built
        // (bd-9vouw.467).
        let search = self.builtin_search_js_string(module, args, 0)?;
        let len = this_str.utf16_len();
        let end = match self.builtin_number_arg(module, args, 1)? {
            Some(Value::Undefined) | None => len,
            Some(arg) => Self::value_as_integer(&arg).clamp(0, len as i64) as usize,
        };
        Ok(Value::Bool(
            end.checked_sub(search.utf16_len())
                .is_some_and(|start| this_str.utf16_slice(start, end) == search),
        ))
    }

    pub(super) fn string_index_of_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.8: first UTF-16 code-unit index of `search` at/after
        // an optional start position, else -1 (bd-9a8cz.1, bd-rdnhc; the
        // returned index now composes with the code-unit-indexed
        // charAt/charCodeAt/at rather than scalar offsets).
        let search = self.builtin_search_js_string(module, args, 0)?;
        let unit_len = this_str.utf16_len();
        let from = match self.builtin_number_arg(module, args, 1)? {
            Some(arg) => Self::value_as_integer(&arg).clamp(0, unit_len as i64) as usize,
            None => 0,
        };
        Ok(Value::Int(
            this_str
                .utf16_index_of(&search, from)
                .map_or(-1, |index| index as i64),
        ))
    }

    pub(super) fn string_last_index_of_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.9: highest UTF-16 code-unit start index of `search`
        // at/before an optional position (default = end of string), else -1
        // (bd-9a8cz.1, bd-rdnhc).
        let search = self.builtin_search_js_string(module, args, 0)?;
        let unit_len = this_str.utf16_len();
        let from = match self.builtin_number_arg(module, args, 1)? {
            Some(Value::Undefined) | None => unit_len,
            // A NaN position (`'x'.lastIndexOf('x', 'a')`) searches from the end.
            Some(arg) if Self::coerce_to_float(&arg).is_none_or(f64::is_nan) => unit_len,
            Some(arg) => Self::value_as_integer(&arg).clamp(0, unit_len as i64) as usize,
        };
        Ok(Value::Int(
            this_str
                .utf16_last_index_of(&search, from)
                .map_or(-1, |index| index as i64),
        ))
    }

    pub(super) fn string_slice_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.18: negative indices count from the end; an
        // empty/inverted range yields "". Indices are UTF-16 code-unit
        // offsets over exact units, composing with the unit-indexed search
        // family; a boundary inside a surrogate pair yields the lone half
        // losslessly (bd-9a8cz.1, bd-3kvat; previously scalar-indexed).
        let len = this_str.utf16_len() as i64;
        let normalize = |n: i64| -> i64 {
            if n < 0 {
                len.saturating_add(n).max(0)
            } else {
                n.min(len)
            }
        };
        let start = match self.builtin_number_arg(module, args, 0)? {
            Some(Value::Undefined) | None => 0,
            Some(arg) => normalize(Self::value_as_integer(&arg)),
        };
        let end = match self.builtin_number_arg(module, args, 1)? {
            Some(Value::Undefined) | None => len,
            Some(arg) => normalize(Self::value_as_integer(&arg)),
        };
        if start >= end {
            return Ok(Value::str(String::new()));
        }
        Ok(Value::Str(
            this_str.utf16_slice(start as usize, end as usize),
        ))
    }

    pub(super) fn string_substring_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.21: clamp both indices to [0, len], then swap so
        // start <= end. Indices are UTF-16 code-unit offsets over exact
        // units; split-pair boundaries are lossless (bd-9a8cz.1, bd-3kvat;
        // previously scalar-indexed).
        let len = this_str.utf16_len() as i64;
        let clamp_idx = |n: i64| -> i64 { n.clamp(0, len) };
        let start = match self.builtin_number_arg(module, args, 0)? {
            Some(Value::Undefined) | None => 0,
            Some(arg) => clamp_idx(Self::value_as_integer(&arg)),
        };
        let end = match self.builtin_number_arg(module, args, 1)? {
            Some(Value::Undefined) | None => len,
            Some(arg) => clamp_idx(Self::value_as_integer(&arg)),
        };
        let (lo, hi) = if start <= end {
            (start, end)
        } else {
            (end, start)
        };
        Ok(Value::Str(this_str.utf16_slice(lo as usize, hi as usize)))
    }

    pub(super) fn string_substr_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 Annex B B.2.3.1 (String.prototype.substr): `substr(start, length)`.
        // `start` is coerced via ToIntegerOrInfinity; a negative start counts from
        // the end (`max(size + start, 0)`), a non-negative one clamps to `size`.
        // An omitted `length` takes the rest of the string; the result length is
        // `max(min(length, size - start), 0)`, so a non-positive length yields "".
        // This is deliberately NOT `substring`, which clamps both args to [0, len]
        // and swaps them. `size` and both offsets are UTF-16 code-unit counts
        // over exact units (bd-fqlfw.2.11.2, bd-3kvat; previously scalar).
        let size = this_str.utf16_len() as i64;
        let int_start = match self.builtin_number_arg(module, args, 0)? {
            Some(Value::Undefined) | None => 0,
            Some(arg) => Self::value_as_integer(&arg),
        };
        let int_length = match self.builtin_number_arg(module, args, 1)? {
            Some(Value::Undefined) | None => size,
            Some(arg) => Self::value_as_integer(&arg),
        };
        let start = if int_start < 0 {
            size.saturating_add(int_start).max(0)
        } else {
            int_start.min(size)
        };
        let result_length = int_length.min(size - start).max(0);
        if result_length == 0 {
            return Ok(Value::str(String::new()));
        }
        let end = start + result_length;
        Ok(Value::Str(
            this_str.utf16_slice(start as usize, end as usize),
        ))
    }

    /// Intrinsic-table binding (fixed signature, no module): a callable
    /// replacer needs a module and is only reachable through
    /// [`Self::string_replace_method`].
    pub(super) fn string_replace_impl(
        &mut self,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.string_replace_with_module(None, this_str, args)
    }

    pub(super) fn string_replace_method(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.string_replace_with_module(Some(module), this_str, args)
    }

    /// The search and replacement arguments of replace and replaceAll. With
    /// a module (the guest call path) an object search value that is not a
    /// RegExp is ToString'd, then a replacement that is not callable;
    /// without one (the module-less intrinsic binding) they pass through.
    pub(super) fn string_replace_args(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<(Value, Value), InterpreterError> {
        let search = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let replacement = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let Some(module) = module else {
            return Ok((search, replacement));
        };
        let search =
            if search.is_object_like() && self.regexp_source_flags_from_value(&search).is_none() {
                self.builtin_string_arg(module, args, 0)?
                    .unwrap_or(Value::Undefined)
            } else {
                search
            };
        let replacement = if replacement.is_object_like() && !replacement.is_callable() {
            self.builtin_string_arg(module, args, 1)?
                .unwrap_or(Value::Undefined)
        } else {
            replacement
        };
        Ok((search, replacement))
    }

    pub(super) fn string_replace_with_module(
        &mut self,
        module: Option<&Ir3Module>,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let (search, replacement) = self.string_replace_args(module, args)?;
        let label = self.join_arg_range_label(args)?;
        self.string_replace_js(module, this_str, &search, &replacement, false, label)
    }

    /// The pattern argument of match, matchAll and search: a RegExp stays
    /// as it is; any other value except undefined is ToString'd (observably
    /// for an object), as RegExpCreate would. A Symbol is a TypeError.
    pub(super) fn string_pattern_arg(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let pattern = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        if matches!(pattern, Value::Undefined)
            || self.regexp_source_flags_from_value(&pattern).is_some()
        {
            return Ok(pattern);
        }
        Ok(self
            .builtin_string_arg(module, args, 0)?
            .unwrap_or(Value::Undefined))
    }

    pub(super) fn string_match_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let pattern = self.string_pattern_arg(module, args)?;
        self.string_match_value(this_str, &pattern)
    }

    pub(super) fn string_search_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let pattern = self.string_pattern_arg(module, args)?;
        self.string_search_value(this_str, &pattern)
    }

    pub(super) fn string_repeat_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.16 step 4: `ToIntegerOrInfinity(count)`; a count that is
        // negative (or +Infinity) throws RangeError, while a NaN count coerces to
        // 0 (-> ""). An oversize result also fails closed with RangeError, matching
        // the stdlib path (`stdlib::exec_string_method`) and V8's "Invalid string
        // length". (bd-9a8cz.1, bd-8tsdh) This path previously clamped a negative
        // count to 0 (returning "") and reported the size guard as a TypeError,
        // both of which diverged from the spec and from the stdlib path.
        let count = self.builtin_number_arg(module, args, 0)?;
        // +Infinity is a RangeError even for the empty string, whose
        // repetition the length guard below lets through ("".repeat(Infinity)
        // returned "").
        let infinite = match &count {
            Some(Value::Float(number)) => number.inner() == f64::INFINITY,
            Some(Value::Str(text)) => primitive_conversion::string_number(text) == f64::INFINITY,
            _ => false,
        };
        if infinite {
            return Err(InterpreterError::RangeError {
                message: "Invalid count value: Infinity".to_string(),
            });
        }
        let count_int = match count {
            Some(arg) => Self::value_as_integer(&arg),
            None => 0,
        };
        if count_int < 0 {
            return Err(InterpreterError::RangeError {
                message: format!("repeat count must be non-negative (got {count_int})"),
            });
        }
        let count = count_int as usize;
        let result_len = this_str.len().saturating_mul(count);
        if result_len > 10_000_000 {
            return Err(InterpreterError::RangeError {
                message: format!("repeat resulting length {result_len} exceeds maximum 10000000"),
            });
        }
        Ok(Value::str(this_str.repeat(count)))
    }

    pub(super) fn string_pad_start_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.14: left-pad to `targetLength` (UTF-16 code-unit
        // count) with `padString` (default " "). (bd-9a8cz.1, bd-3kvat)
        Ok(Value::Str(
            self.string_pad_value(module, this_str, args, true)?,
        ))
    }

    pub(super) fn string_pad_end_impl(
        &mut self,
        module: &Ir3Module,
        this_str: &JsString,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // ES2020 21.1.3.13: right-pad to `targetLength` (UTF-16 code-unit
        // count) with `padString` (default " "). (bd-9a8cz.1, bd-3kvat)
        Ok(Value::Str(
            self.string_pad_value(module, this_str, args, false)?,
        ))
    }

    pub(super) fn string_property_value(receiver: &JsString, key: &str) -> Value {
        // String primitives expose indexed own properties over their exact
        // UTF-16 code units. Reuse the canonical array-index parser so
        // non-canonical keys such as `"01"` remain ordinary missing
        // properties, while supplementary characters still occupy two
        // independently observable indices and lone surrogates survive
        // without being projected through U+FFFD.
        // code_unit_at reads ASCII text directly (bd-9vouw.467).
        if let Some(index) = Self::canonical_array_index_property(key, receiver.utf16_len()) {
            return receiver
                .code_unit_at(index)
                .map_or(Value::Undefined, |unit| {
                    Value::Str(JsString::from_code_units(&[unit]))
                });
        }
        if key == "length" {
            return Value::Int(i64::try_from(receiver.utf16_len()).unwrap_or(i64::MAX));
        }
        Self::string_prototype_method(key).unwrap_or(Value::Undefined)
    }

    /// `String.prototype` methods; receiver-independent (the receiver is
    /// supplied at call time).
    pub(super) fn string_prototype_method(key: &str) -> Option<Value> {
        let method = match key {
            "charAt" => Value::BuiltinFunction(BuiltinFunction::string_char_at()),
            "charCodeAt" => Value::BuiltinFunction(BuiltinFunction::string_char_code_at()),
            "at" => Value::BuiltinFunction(BuiltinFunction::string_at()),
            // Locale-sensitive case mapping uses the root locale, as Node's
            // default `en-US` does for everything but a few special casings.
            "toUpperCase" => Value::BuiltinFunction(BuiltinFunction::string_to_upper_case()),
            "toLowerCase" => Value::BuiltinFunction(BuiltinFunction::string_to_lower_case()),
            "toLocaleUpperCase" | "toLocaleLowerCase" => {
                let kind = if key == "toLocaleUpperCase" {
                    BuiltinFunctionKind::StringToUpperCase
                } else {
                    BuiltinFunctionKind::StringToLowerCase
                };
                Value::BuiltinFunction(BuiltinFunction::string_to_locale_case(kind, key))
            }
            "concat" => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StringPrototypeConcat,
            )),
            "trim" => Value::BuiltinFunction(BuiltinFunction::string_trim()),
            // Annex B: trimLeft and trimRight are the same function objects
            // as trimStart and trimEnd, named "trimStart"/"trimEnd".
            "trimStart" | "trimLeft" => {
                Value::BuiltinFunction(BuiltinFunction::string_trim_start())
            }
            "trimEnd" | "trimRight" => Value::BuiltinFunction(BuiltinFunction::string_trim_end()),
            "replaceAll" => Value::BuiltinFunction(BuiltinFunction::string_replace_all()),
            "codePointAt" => Value::BuiltinFunction(BuiltinFunction::string_code_point_at()),
            "localeCompare" => Value::BuiltinFunction(BuiltinFunction::string_locale_compare()),
            "normalize" => Value::BuiltinFunction(BuiltinFunction::string_normalize()),
            "split" => Value::BuiltinFunction(BuiltinFunction::string_split()),
            "includes" => Value::BuiltinFunction(BuiltinFunction::string_includes()),
            "startsWith" => Value::BuiltinFunction(BuiltinFunction::string_starts_with()),
            "endsWith" => Value::BuiltinFunction(BuiltinFunction::string_ends_with()),
            "indexOf" => Value::BuiltinFunction(BuiltinFunction::string_index_of()),
            "lastIndexOf" => Value::BuiltinFunction(BuiltinFunction::string_last_index_of()),
            "slice" => Value::BuiltinFunction(BuiltinFunction::string_slice()),
            "substring" => Value::BuiltinFunction(BuiltinFunction::string_substring()),
            "substr" => Value::BuiltinFunction(BuiltinFunction::string_substr()),
            name if STRING_HTML_METHODS.iter().any(|(html, _, _)| *html == name) => {
                Value::BuiltinFunction(BuiltinFunction {
                    kind: BuiltinFunctionKind::StringHtmlMethod,
                    module_specifier: BuiltinModuleSpecifier::from_nonempty(
                        STRING_HTML_METHODS
                            .iter()
                            .find(|(html, _, _)| *html == name)
                            .map_or("anchor", |(html, _, _)| *html),
                    ),
                    iterator_handle: None,
                    bound_object: None,
                })
            }
            "replace" => Value::BuiltinFunction(BuiltinFunction::string_replace()),
            "match" => Value::BuiltinFunction(BuiltinFunction::string_match()),
            "matchAll" => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StringMatchAll,
            )),
            "search" => Value::BuiltinFunction(BuiltinFunction::string_search()),
            "repeat" => Value::BuiltinFunction(BuiltinFunction::string_repeat()),
            "padStart" => Value::BuiltinFunction(BuiltinFunction::string_pad_start()),
            "padEnd" => Value::BuiltinFunction(BuiltinFunction::string_pad_end()),
            "isWellFormed" => Value::BuiltinFunction(BuiltinFunction::string_is_well_formed()),
            "toWellFormed" => Value::BuiltinFunction(BuiltinFunction::string_to_well_formed()),
            "valueOf" => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StringValueOf,
            )),
            "toString" => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StringToString,
            )),
            _ => return None,
        };
        Some(method)
    }

    pub(super) fn regexp_source_flags_from_value(&self, value: &Value) -> Option<(String, String)> {
        match value {
            Value::Object(object_id) => self.regexp_source_flags_from_object(*object_id),
            _ => None,
        }
    }

    /// `/source/flags` (ES2020 21.2.5.14); an empty pattern renders as
    /// `(?:)` so the result is not a `//` comment (21.2.3.2.4
    /// EscapeRegExpPattern).
    pub(super) fn regexp_display(source: &str, flags: &str) -> String {
        let source = if source.is_empty() { "(?:)" } else { source };
        format!("/{source}/{flags}")
    }

    /// ES2020 21.2.3.2.4 EscapeRegExpPattern, as V8 applies it, so a
    /// RegExp's `source` reads back as a literal body (bd-9vouw.243): an
    /// empty pattern is `(?:)`, a `/` outside a character class is escaped,
    /// and a line terminator (or a backslash before one) becomes its escape
    /// sequence. `new RegExp('a/b').source` was `a/b` and
    /// `String(new RegExp('a/b'))` the unparsable `/a/b/`; Node gives `a\/b`
    /// and `/a\/b/`. The escaped pattern matches what the original did.
    /// No-claim: a `v`-flag class nested inside another ends the class
    /// scan at its first `]`.
    pub(super) fn escape_regexp_pattern(source: String) -> String {
        if source.is_empty() {
            return "(?:)".to_string();
        }
        let line_terminator_escape = |c: char| match c {
            '\n' => Some("\\n"),
            '\r' => Some("\\r"),
            '\u{2028}' => Some("\\u2028"),
            '\u{2029}' => Some("\\u2029"),
            _ => None,
        };
        if !source.contains(|c: char| c == '/' || line_terminator_escape(c).is_some()) {
            return source;
        }
        let mut escaped = String::with_capacity(source.len() + 4);
        let mut in_class = false;
        let mut chars = source.chars();
        while let Some(c) = chars.next() {
            if let Some(escape) = line_terminator_escape(c) {
                escaped.push_str(escape);
                continue;
            }
            match c {
                '\\' => match chars.next() {
                    Some(next) => match line_terminator_escape(next) {
                        Some(escape) => escaped.push_str(escape),
                        None => {
                            escaped.push('\\');
                            escaped.push(next);
                        }
                    },
                    None => escaped.push('\\'),
                },
                '/' if !in_class => escaped.push_str("\\/"),
                '[' => {
                    in_class = true;
                    escaped.push(c);
                }
                ']' => {
                    in_class = false;
                    escaped.push(c);
                }
                _ => escaped.push(c),
            }
        }
        escaped
    }

    /// ES2020 21.2.3.1 RegExp(pattern, flags), for a construction, a call
    /// (`called`: NewTarget undefined) and a literal. IsRegExp runs once (it
    /// reads pattern[@@match]): a called RegExp returns a pattern that
    /// IsRegExp whose `constructor` is RegExp when no flags are given; a
    /// RegExp pattern copies its source, and its flags when none are given;
    /// any other object IsRegExp accepts supplies its `source` and `flags`
    /// properties. ToString then converts both through ToPrimitive, so an
    /// object's toString / valueOf runs (and may throw); they read
    /// "[object Object]".
    pub(super) fn construct_regexp(
        &mut self,
        module: Option<&Ir3Module>,
        pattern_value: Value,
        flags_value: Value,
        called: bool,
    ) -> Result<Value, InterpreterError> {
        let pattern_is_regexp = match module {
            Some(module) => self.is_regexp_observable(module, &pattern_value)?,
            None => false,
        };
        if let (true, true, Value::Undefined, Some(module)) =
            (called, pattern_is_regexp, &flags_value, module)
        {
            let constructor = self.get_v(
                module,
                &pattern_value,
                &RuntimePropertyKey::String(JsString::from("constructor")),
            )?;
            if matches!(&constructor, Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::StandardConstructor
                    && Self::standard_constructor_name(builtin).ok() == Some("RegExp"))
            {
                return Ok(pattern_value);
            }
        }
        let regexp_slots = match &pattern_value {
            Value::Object(id) => self.regexp_source_flags_from_object(*id),
            _ => None,
        };
        let (pattern_source, flags_source) = match (regexp_slots, module) {
            (Some((source, flags)), _) => {
                let flags = match flags_value {
                    Value::Undefined => Value::str(flags),
                    other => other,
                };
                (Value::str(source), flags)
            }
            (None, Some(module)) if pattern_is_regexp => {
                let source = self.get_v(
                    module,
                    &pattern_value,
                    &RuntimePropertyKey::String(JsString::from("source")),
                )?;
                let flags = match flags_value {
                    Value::Undefined => self.get_v(
                        module,
                        &pattern_value,
                        &RuntimePropertyKey::String(JsString::from("flags")),
                    )?,
                    other => other,
                };
                (source, flags)
            }
            _ => (pattern_value, flags_value),
        };
        // A literal's pattern and flags are strings already: no ToString.
        let pattern = match pattern_source {
            Value::Undefined => String::new(),
            Value::Str(text) => text.to_string(),
            other => self
                .scoped_conversion(|this| this.conversion_to_string(module, other))?
                .to_string(),
        };
        let flags = match flags_source {
            Value::Undefined => String::new(),
            Value::Str(text) => text.to_string(),
            other => self
                .scoped_conversion(|this| this.conversion_to_string(module, other))?
                .to_string(),
        };
        // ES2020 21.2.3.2.2 RegExpInitialize: invalid flags or a pattern that
        // does not parse are a SyntaxError here, not at the first match (the
        // literal's early-error rule). A pattern in the compiled cache already
        // ran, so a literal evaluated in a loop is checked once.
        let compiled = self
            .regexp_cache
            .borrow()
            .iter()
            .any(|(cached, cached_flags, _)| *cached == pattern && *cached_flags == flags);
        if !compiled && let Some(message) = regexp_literal_early_error(&pattern, &flags) {
            return Err(self.throw_syntax_error(message));
        }
        Ok(Value::Object(self.alloc_regexp_object(pattern, flags)?))
    }

    pub(super) fn regexp_source_flags_from_object(
        &self,
        object_id: ObjectId,
    ) -> Option<(String, String)> {
        let object = self.heap.get(object_id.0 as usize)?;
        if object.brand() != Some("RegExp") {
            return None;
        }

        Some(object.regexp.as_ref().map_or_else(
            || (String::new(), String::new()),
            |slots| (slots.source.clone(), slots.flags.clone()),
        ))
    }

    /// Compile a RegExp pattern, reusing this interpreter's recent
    /// compilation of the same pattern and flags. Compiling dominated every
    /// `exec`, `test`, `match`, `replace` and `split` call: about 670 us per
    /// `re.exec` in a loop. A compiled `Regex` is immutable, so reuse cannot
    /// change a result. Guest code chooses the patterns, so only short
    /// patterns whose compiled form fits the cache limits are kept; any other
    /// pattern compiles under the default limits every time, as before.
    pub(super) fn compile_regexp_pattern(
        &self,
        pattern: &str,
        flags: &str,
    ) -> Result<CompiledRegExp, InterpreterError> {
        if pattern.len() > REGEXP_CACHE_MAX_PATTERN_BYTES {
            return Self::build_regexp(pattern, flags);
        }
        if let Some(regex) = self
            .regexp_cache
            .borrow()
            .iter()
            .find(|(cached_pattern, cached_flags, _)| {
                cached_pattern == pattern && cached_flags == flags
            })
            .map(|(_, _, regex)| regex.clone())
        {
            return Ok(regex);
        }
        let mut builder = Self::regexp_builder(pattern, flags)?;
        let built = match Self::es_repetition_matcher(pattern, flags) {
            Some(regexp) => Ok(regexp),
            None => builder
                .size_limit(REGEXP_CACHE_MAX_PROGRAM_BYTES)
                .dfa_size_limit(REGEXP_CACHE_MAX_DFA_BYTES)
                .build()
                .map(CompiledRegExp::Automaton),
        };
        let regex = match built {
            Ok(CompiledRegExp::Backtracking(regexp))
                if regexp.program_len() > REGEXP_CACHE_MAX_BACKTRACK_INSTRUCTIONS =>
            {
                return Ok(CompiledRegExp::Backtracking(regexp));
            }
            Ok(regex) => regex,
            // Too large for the cache limits, or not expressible by `regex`:
            // the default limits or the backtracking matcher decide. Only a
            // small backtracking program is kept.
            Err(_) => match Self::build_regexp(pattern, flags)? {
                CompiledRegExp::Backtracking(regexp)
                    if regexp.program_len() <= REGEXP_CACHE_MAX_BACKTRACK_INSTRUCTIONS =>
                {
                    CompiledRegExp::Backtracking(regexp)
                }
                uncached => return Ok(uncached),
            },
        };
        let mut cache = self.regexp_cache.borrow_mut();
        if cache.len() == REGEXP_CACHE_ENTRIES {
            cache.pop_front();
        }
        cache.push_back((pattern.to_string(), flags.to_string(), regex.clone()));
        Ok(regex)
    }

    pub(super) fn regexp_builder(
        pattern: &str,
        flags: &str,
    ) -> Result<RegexBuilder, InterpreterError> {
        // Both routes refuse an oversized pattern before translating or
        // parsing it (franken_engine#2).
        if pattern.len() > MAX_PATTERN_LEN {
            return Err(InterpreterError::RangeError {
                message: format!("Invalid regular expression: {PATTERN_TOO_LARGE}"),
            });
        }
        if (flags.contains('u') || flags.contains('v'))
            && regexp_syntax::property_escape_count(pattern) > regexp_syntax::MAX_PROPERTY_ESCAPES
        {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Invalid regular expression: {}",
                    regexp_syntax::TOO_MANY_PROPERTY_ESCAPES
                ),
            });
        }
        // The backtracking parser refuses these; the `regex` crate would
        // compile them as nested repetitions.
        if regexp_syntax::has_nested_quantifier(pattern, flags) {
            return Err(InterpreterError::TypeError {
                expected: "valid RegExp pattern".to_string(),
                got: "Nothing to repeat".to_string(),
            });
        }
        let mut case_insensitive = false;
        let mut multi_line = false;
        let mut dot_matches_new_line = false;

        for flag in flags.chars() {
            match flag {
                'i' => case_insensitive = true,
                'm' => multi_line = true,
                's' => dot_matches_new_line = true,
                'g' | 'u' | 'y' | 'd' | 'v' => {}
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "supported RegExp flag".to_string(),
                        got: other.to_string(),
                    });
                }
            }
        }

        let mut builder = RegexBuilder::new(&regexp_syntax::js_pattern_to_rust(pattern, flags));
        builder
            .case_insensitive(case_insensitive)
            .multi_line(multi_line)
            .dot_matches_new_line(dot_matches_new_line)
            .unicode(true);
        Ok(builder)
    }

    /// The backtracking matcher for a pattern whose repetitions the `regex`
    /// crate would answer differently from ES2020 (captures nested in a
    /// repeated atom, or a repeated atom that can match empty), when this
    /// module's parser accepts it (bd-9vouw.367).
    pub(super) fn es_repetition_matcher(pattern: &str, flags: &str) -> Option<CompiledRegExp> {
        if !BacktrackRegExp::needs_es_repetition_semantics(pattern, flags) {
            return None;
        }
        BacktrackRegExp::new(pattern, flags)
            .ok()
            .map(|regexp| CompiledRegExp::Backtracking(Rc::new(regexp)))
    }

    /// Compile under the default limits: the `regex` crate for the patterns
    /// it can express, the backtracking matcher for look-around,
    /// backreferences, repetitions with ES2020-only results and the rest. A
    /// pattern neither accepts is invalid.
    pub(super) fn build_regexp(
        pattern: &str,
        flags: &str,
    ) -> Result<CompiledRegExp, InterpreterError> {
        let builder = Self::regexp_builder(pattern, flags)?;
        if let Some(regexp) = Self::es_repetition_matcher(pattern, flags) {
            return Ok(regexp);
        }
        if let Ok(regex) = builder.build() {
            return Ok(CompiledRegExp::Automaton(regex));
        }
        BacktrackRegExp::new(pattern, flags)
            .map(|regexp| CompiledRegExp::Backtracking(Rc::new(regexp)))
            .map_err(|message| InterpreterError::TypeError {
                expected: "valid RegExp pattern".to_string(),
                got: message,
            })
    }

    /// The native-retention budget of one global RegExp operation: the
    /// guest's remaining memory headroom (franken_engine#2). Results a global
    /// match, replace or split holds natively before they reach the guest
    /// heap are charged here, so a match matrix the guest could never hold
    /// fails closed instead of being built first.
    pub(super) fn regexp_retention_budget(&self) -> RetentionBudget {
        let used = self.total_memory_bytes_from_base(self.estimated_memory_bytes);
        RetentionBudget::new(self.config.max_total_memory_bytes.saturating_sub(used))
    }

    pub(super) fn regexp_global_match_error(&self, error: GlobalMatchError) -> InterpreterError {
        match error {
            GlobalMatchError::Interpreter(error) => error,
            GlobalMatchError::Retention { requested_bytes } => self.memory_budget_error(
                self.estimated_memory_bytes.saturating_add(requested_bytes),
                self.heap_object_count_u32(),
            ),
        }
    }

    /// [`CompiledRegExp::all_captures`] charged to `budget`.
    /// Every match of a global exec loop from position 0. A sticky pattern's
    /// loop stops at its first failure: each match must start where the
    /// previous one left lastIndex (bd-9vouw.315). The leftmost match from a
    /// position starts there whenever one can, so the sticky matches are
    /// the leading run of the leftmost ones that start where expected.
    pub(super) fn regexp_all_captures(
        &self,
        regex: &CompiledRegExp,
        input: &str,
        retention: CaptureRetention,
        budget: &mut RetentionBudget,
        sticky: bool,
    ) -> Result<Vec<Captures>, InterpreterError> {
        let mut all = regex
            .all_captures(input, retention, budget)
            .map_err(|error| self.regexp_global_match_error(error))?;
        if sticky {
            let mut expected = 0usize;
            let contiguous = all
                .iter()
                .take_while(|spans| match spans[0] {
                    Some((from, to)) if from == expected => {
                        // The exec loop's AdvanceStringIndex past an empty
                        // match, as all_captures steps.
                        expected = if from == to {
                            to + input[to..].chars().next().map_or(1, char::len_utf8)
                        } else {
                            to
                        };
                        true
                    }
                    _ => false,
                })
                .count();
            all.truncate(contiguous);
        }
        Ok(all)
    }

    /// Charge `bytes` of native result text to `budget`.
    pub(super) fn regexp_charge_retained(
        &self,
        budget: &mut RetentionBudget,
        bytes: usize,
    ) -> Result<(), InterpreterError> {
        budget
            .charge(u64::try_from(bytes).unwrap_or(u64::MAX))
            .map_err(|error| self.regexp_global_match_error(error))
    }

    pub(super) fn regexp_test_value(
        &mut self,
        receiver: &Value,
        input: &Value,
    ) -> Result<Value, InterpreterError> {
        self.regexp_test_value_from(receiver, input, None)
    }

    /// [`Self::regexp_test_value`] with `lastIndex` already coerced
    /// (`regexp_coerced_last_index`).
    pub(super) fn regexp_test_value_from(
        &mut self,
        receiver: &Value,
        input: &Value,
        last_index: Option<f64>,
    ) -> Result<Value, InterpreterError> {
        let Some((source, flags)) = self.regexp_source_flags_from_value(receiver) else {
            return Ok(Value::Bool(false));
        };
        // ES2020 21.2.5.13: test is RegExpExec(R, S) !== null, so a global or
        // sticky regex reads and advances lastIndex exactly as exec does.
        // Ignoring it made `while (re.test(s))` over a /g regex loop forever.
        if flags.contains('g') || flags.contains('y') {
            let result = self.regexp_prototype_exec_from(receiver.clone(), input, last_index)?;
            return Ok(Value::Bool(!matches!(result, Value::Null)));
        }
        let regex = self.compile_regexp_pattern(&source, &flags)?;
        let subject = match input {
            Value::Str(text) => text.clone(),
            other => JsString::from(Self::value_to_primitive_string(other)),
        };
        let prepared =
            self.prepare_regexp_input(&subject, flags.contains('u') || flags.contains('v'))?;
        // bd-9vouw.113: a successful test records the legacy statics, so it
        // needs the capture spans, not only a yes/no.
        let found = regex.captures_at(prepared.text(), 0, false)?;
        let matched = found.as_ref().is_some_and(|spans| spans[0].is_some());
        if let Some(spans) = &found {
            self.record_legacy_regexp_input_match(&subject, &prepared, spans);
        }
        Ok(Value::Bool(matched))
    }

    pub(super) fn string_match_value(
        &mut self,
        subject: &JsString,
        pattern: &Value,
    ) -> Result<Value, InterpreterError> {
        if let Some((source, flags)) = self.regexp_source_flags_from_value(pattern) {
            // ES2020 21.2.5.6 @@match: a non-global pattern is one
            // RegExpExec, so a sticky one matches at (and updates)
            // `lastIndex`; a global one first sets `lastIndex` to 0, which
            // is where the exec loop leaves it.
            if !flags.contains('g') {
                return self.regexp_prototype_exec(pattern.clone(), &Value::Str(subject.clone()));
            }
            if let Value::Object(regexp_id) = pattern {
                self.set_regexp_last_index(*regexp_id, 0)?;
            }
            let regex = self.compile_regexp_pattern(&source, &flags)?;
            let prepared =
                self.prepare_regexp_input(subject, flags.contains('u') || flags.contains('v'))?;
            let input = prepared.text();
            let result_id = self.alloc_array_with_prototype(None)?;
            let mut count = 0usize;
            let mut budget = self.regexp_retention_budget();
            // A sticky loop may stop early, so its last kept match needs
            // its groups for the legacy RegExp statics.
            let sticky = flags.contains('y');
            let matches = self.regexp_all_captures(
                &regex,
                input,
                if sticky {
                    CaptureRetention::AllGroups
                } else {
                    CaptureRetention::WholeMatchExceptLast
                },
                &mut budget,
                sticky,
            )?;
            if let Some(spans) = matches.last() {
                self.record_legacy_regexp_input_match(subject, &prepared, spans);
            }
            for spans in matches {
                let Some((from, to)) = spans[0] else {
                    continue;
                };
                self.set_object_property(
                    result_id,
                    count.to_string(),
                    Value::Str(self.decode_regexp_text(&prepared, &input[from..to])?),
                )?;
                count = count.saturating_add(1);
            }
            if count == 0 {
                return Ok(Value::Null);
            }
            self.set_object_property(
                result_id,
                "length".to_string(),
                Value::Int(i64::try_from(count).unwrap_or(i64::MAX)),
            )?;
            return Ok(Value::Object(result_id));
        }

        // ES2020 21.1.3.11 step 3: any other value is `new RegExp(value)`.
        let regex = self.compile_regexp_pattern(&self.regexp_create_source(pattern), "")?;
        Ok(self
            .regexp_exec_at(&regex, subject, 0, false, false, false)?
            .map_or(Value::Null, |(result, _)| result))
    }

    /// The pattern `RegExpCreate(value, undefined)` compiles: `undefined` is
    /// the empty pattern, anything else its string.
    pub(super) fn regexp_create_source(&self, pattern: &Value) -> String {
        match pattern {
            Value::Undefined => String::new(),
            other => self.value_to_string(other),
        }
    }

    /// A RegExp object with the given source and flags and `lastIndex` 0.
    pub(super) fn alloc_regexp_object(
        &mut self,
        source: String,
        flags: String,
    ) -> Result<ObjectId, InterpreterError> {
        let regexp_prototype = self.ensure_builtin_prototype("RegExp")?;
        let regexp_id = self.alloc_object_with_prototype(Some(regexp_prototype))?;
        self.set_object_brand(regexp_id, "RegExp")?;
        self.set_regexp_source_and_flags(regexp_id, source, &flags)?;
        self.set_object_property(regexp_id, "lastIndex".to_string(), Value::Int(0))?;
        // `lastIndex` is an own writable, non-enumerable, non-configurable
        // data property (ES2020 21.2.3.2.2 RegExpAlloc); is-regex reads its
        // descriptor.
        self.set_own_property_attributes(
            regexp_id,
            &RuntimePropertyKey::String(JsString::from("lastIndex")),
            PropertyAttributes {
                writable: true,
                enumerable: false,
                configurable: false,
            },
        )?;
        Ok(regexp_id)
    }

    /// Write the [[OriginalSource]] and [[OriginalFlags]] slots of a RegExp
    /// ([`HeapObject::regexp`]), charging the change to the heap estimate.
    pub(super) fn set_regexp_source_and_flags(
        &mut self,
        regexp_id: ObjectId,
        source: String,
        flags: &str,
    ) -> Result<(), InterpreterError> {
        let source = Self::escape_regexp_pattern(source);
        // The `flags` getter lists the flags in "dgimsuvy" order whatever
        // order they were written in (ES2025 22.2.6.4): `/a/gd.flags` is
        // "dg". A letter outside that set stays, after them.
        let canonical: String = REGEXP_FLAG_ORDER
            .chars()
            .filter(|flag| flags.contains(*flag))
            .chain(
                flags
                    .chars()
                    .filter(|flag| !REGEXP_FLAG_ORDER.contains(*flag)),
            )
            .collect();
        let index = regexp_id.0 as usize;
        let previous = self
            .heap
            .get(index)
            .ok_or(InterpreterError::ObjectNotFound { id: regexp_id.0 })?;
        let previous_bytes = Self::estimate_heap_object_bytes(previous);
        let mut projected = previous.clone();
        projected.regexp = Some(Box::new(RegExpSlots {
            source,
            flags: canonical,
        }));
        let projected_bytes = Self::estimate_heap_object_bytes(&projected);
        self.apply_memory_component_delta(previous_bytes, projected_bytes)?;
        self.mutate_heap(|heap| heap[index] = projected);
        Ok(())
    }

    /// Annex B `RegExp.prototype.compile(pattern, flags)` (ES2020 B.2.5.1),
    /// which was missing (bd-9vouw.241): RegExpInitialize of the receiver in
    /// place, returning it. A RegExp pattern lends its source and flags, and
    /// `flags` must then be undefined; any other pattern, and the flags, go
    /// through ToString, with undefined read as "". A pattern or flags that
    /// does not parse is a SyntaxError that leaves the receiver as it was.
    /// The new source and flags are in place before `lastIndex` is set to 0,
    /// so a read-only `lastIndex` is a TypeError after the receiver changed,
    /// as `Set(obj, "lastIndex", 0, true)` is. No-claim: a subclass instance
    /// is recompiled as in Node v22.2.0 (the legacy RegExp features proposal
    /// would make that a TypeError).
    pub(super) fn regexp_prototype_compile(
        &mut self,
        module: &Ir3Module,
        receiver: Value,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let regexp_id = match receiver {
            Value::Object(id) if self.regexp_source_flags_from_object(id).is_some() => id,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "RegExp receiver for RegExp.prototype.compile".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let pattern = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let flags = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let (source, flags) = match self.regexp_source_flags_from_value(&pattern) {
            Some(source_and_flags) => {
                if !matches!(flags, Value::Undefined) {
                    return Err(InterpreterError::TypeError {
                        expected:
                            "undefined flags with a RegExp pattern for RegExp.prototype.compile"
                                .to_string(),
                        got: flags.type_name().to_string(),
                    });
                }
                source_and_flags
            }
            None => {
                let source = match pattern {
                    Value::Undefined => String::new(),
                    _ => self.builtin_arg_text(Some(module), args, 0)?,
                };
                let flags = match flags {
                    Value::Undefined => String::new(),
                    _ => self.builtin_arg_text(Some(module), args, 1)?,
                };
                (source, flags)
            }
        };
        if let Some(message) = regexp_literal_early_error(&source, &flags) {
            return Err(self.throw_syntax_error(message));
        }
        self.set_regexp_source_and_flags(regexp_id, source, &flags)?;
        self.set_regexp_last_index(regexp_id, 0)?;
        Ok(Value::Object(regexp_id))
    }

    /// ES2020 21.1.3.12 String.prototype.matchAll: an iterator over every
    /// match of a global RegExp (a RegExp without `g` is a TypeError; any
    /// other pattern becomes `new RegExp(pattern, "g")`), each result shaped
    /// like RegExp.prototype.exec's (index, input, groups). It runs on a
    /// private clone, so the argument's own `lastIndex` is untouched, and
    /// lazily: the %RegExpStringIteratorPrototype% iterator runs one exec per
    /// `next` (they were all collected up front, so 5,000 matches of a 34 KB
    /// string were all alive at once and exceeded the memory budget,
    /// bd-9vouw.476). An empty match advances the clone by AdvanceStringIndex.
    pub(super) fn string_match_all_value(
        &mut self,
        input: &JsString,
        pattern: &Value,
        label: &Label,
    ) -> Result<Value, InterpreterError> {
        let (source, flags, last_index) = match self.regexp_source_flags_from_value(pattern) {
            Some((source, flags)) => {
                if !flags.contains('g') {
                    return Err(InterpreterError::TypeError {
                        expected: "global RegExp for String.prototype.matchAll".to_string(),
                        got: format!("RegExp with flags \"{flags}\""),
                    });
                }
                let last_index = match pattern {
                    Value::Object(id) => self
                        .heap
                        .get(id.0 as usize)
                        .and_then(|object| object.properties.get("lastIndex").cloned())
                        .unwrap_or(Value::Int(0)),
                    _ => Value::Int(0),
                };
                (source, flags, last_index)
            }
            None => {
                let source = match pattern {
                    Value::Undefined => String::new(),
                    other => self.value_to_string(other),
                };
                (source, "g".to_string(), Value::Int(0))
            }
        };
        let full_unicode = flags.contains('u') || flags.contains('v');
        let clone = self.alloc_regexp_object(source, flags)?;
        self.set_object_property(clone, "lastIndex".to_string(), last_index)?;
        self.create_regexp_string_iterator(
            Value::Object(clone),
            input.clone(),
            true,
            full_unicode,
            label,
        )
    }

    /// ES2020 21.1.3.18 String.prototype.search: the index of the first
    /// match in UTF-16 code units. Any value other than a RegExp is
    /// `new RegExp(value)`.
    pub(super) fn string_search_value(
        &mut self,
        subject: &JsString,
        pattern: &Value,
    ) -> Result<Value, InterpreterError> {
        let (source, flags) = self
            .regexp_source_flags_from_value(pattern)
            .unwrap_or_else(|| (self.regexp_create_source(pattern), String::new()));
        let regex = self.compile_regexp_pattern(&source, &flags)?;
        let prepared =
            self.prepare_regexp_input(subject, flags.contains('u') || flags.contains('v'))?;
        // ES2020 21.2.5.9 @@search: RegExpExec with lastIndex 0, so a sticky
        // pattern matches only at the start (bd-9vouw.315).
        let found = regex.captures_at(prepared.text(), 0, flags.contains('y'))?;
        if let Some(spans) = &found {
            self.record_legacy_regexp_input_match(subject, &prepared, spans);
        }
        Ok(Value::Int(
            found.and_then(|spans| spans[0]).map_or(-1, |(from, _)| {
                i64::try_from(prepared.unit_index(from)).unwrap_or(i64::MAX)
            }),
        ))
    }

    /// ES2020 21.1.3.17 String.prototype.replace and replaceAll over a string
    /// or RegExp search value. A callable replacer receives (match, ...groups,
    /// offset, string) with the UTF-16 offset; otherwise the replacement is a
    /// GetSubstitution template.
    /// ToString of a replace value or a replacer's result: observable for an
    /// object (its toString or valueOf runs) and a TypeError for a Symbol;
    /// any other primitive converts without guest code (bd-9vouw.358).
    pub(super) fn replacement_to_string(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
    ) -> Result<JsString, InterpreterError> {
        if let Value::Str(text) = value {
            return Ok(text.clone());
        }
        if value.is_object_like() || matches!(value, Value::Symbol(_)) {
            let value = value.clone();
            return self.scoped_conversion(|this| this.conversion_to_string(module, value));
        }
        Ok(JsString::from(self.value_to_string(value)))
    }

    pub(super) fn string_replace_js(
        &mut self,
        module: Option<&Ir3Module>,
        subject: &JsString,
        search: &Value,
        replace: &Value,
        all: bool,
        label: Label,
    ) -> Result<Value, InterpreterError> {
        let regexp = self.regexp_source_flags_from_value(search);
        let full_unicode = regexp
            .as_ref()
            .is_some_and(|(_, flags)| flags.contains('u') || flags.contains('v'));
        let prepared = self.prepare_regexp_input(subject, full_unicode)?;
        let input = prepared.text();
        let mut matches: Vec<(usize, usize, Vec<Option<String>>)> = Vec::new();
        let mut group_names: Vec<Option<String>> = Vec::new();
        // Every match is held natively until the output is built, so the
        // match list is charged to the guest's memory headroom
        // (franken_engine#2).
        // A replaceValue that is not callable is ToString'd before anything
        // is matched (ES2020 21.2.5.8 step 6, 21.1.3.17 step 5): an object's
        // own toString or valueOf runs, and its throw is the call's; a direct
        // `re[Symbol.replace](s, obj)` read it as "[object Object]"
        // (bd-9vouw.358).
        let callable = replace.is_callable();
        let template_value = if callable {
            JsString::from("")
        } else {
            self.replacement_to_string(module, replace)?
        };
        let template = self.prepare_regexp_input(&template_value, full_unicode)?;
        let mut budget = self.regexp_retention_budget();
        let match_entry_bytes = std::mem::size_of::<(usize, usize, Vec<Option<String>>)>();
        if let Some((source, flags)) = regexp {
            let regex = self.compile_regexp_pattern(&source, &flags)?;
            group_names = regex.group_names().into_iter().skip(1).collect();
            // ES2020 21.2.5.8 @@replace: a global pattern first sets
            // `lastIndex` to 0 (the exec loop leaves it there); a sticky
            // one matches only at `lastIndex` and updates it.
            let regexp_id = match search {
                Value::Object(id) => Some(*id),
                _ => None,
            };
            let found = if all || flags.contains('g') {
                if flags.contains('g')
                    && let Some(regexp_id) = regexp_id
                {
                    self.set_regexp_last_index(regexp_id, 0)?;
                }
                self.regexp_all_captures(
                    &regex,
                    input,
                    CaptureRetention::AllGroups,
                    &mut budget,
                    flags.contains('y'),
                )?
            } else if flags.contains('y')
                && let Some(regexp_id) = regexp_id
            {
                self.sticky_regexp_captures(regexp_id, &regex, &prepared)?
                    .into_iter()
                    .collect()
            } else {
                regex.captures_at(input, 0, false)?.into_iter().collect()
            };
            if let Some(spans) = found.last() {
                self.record_legacy_regexp_input_match(subject, &prepared, spans);
            }
            for spans in found {
                let Some((start, end)) = spans[0] else {
                    continue;
                };
                // Group text is copied out per match and can overlap
                // (`(?=(.*))`), so it is charged to the same budget.
                let group_bytes = spans[1..]
                    .iter()
                    .flatten()
                    .fold(0usize, |total, (from, to)| total.saturating_add(to - from))
                    .saturating_add(
                        spans
                            .len()
                            .saturating_mul(std::mem::size_of::<Option<String>>()),
                    )
                    .saturating_add(match_entry_bytes);
                self.regexp_charge_retained(&mut budget, group_bytes)?;
                let groups = spans[1..]
                    .iter()
                    .map(|group| group.map(|(from, to)| input[from..to].to_string()))
                    .collect();
                matches.push((start, end, groups));
            }
        } else {
            let needle_value = match search {
                Value::Str(text) => text.clone(),
                other => JsString::from(self.value_to_string(other)),
            };
            let needle = self.prepare_regexp_input(&needle_value, full_unicode)?;
            self.regexp_charge_retained(&mut budget, needle.retained_bytes() as usize)?;
            let needle = needle.text();
            if !all {
                if let Some(index) = input.find(needle) {
                    matches.push((index, index + needle.len(), Vec::new()));
                }
            } else if needle.is_empty() {
                for (index, _) in input.char_indices() {
                    self.regexp_charge_retained(&mut budget, match_entry_bytes)?;
                    matches.push((index, index, Vec::new()));
                }
                matches.push((input.len(), input.len(), Vec::new()));
            } else {
                let mut position = 0;
                while let Some(offset) = input[position..].find(needle) {
                    self.regexp_charge_retained(&mut budget, match_entry_bytes)?;
                    let start = position + offset;
                    matches.push((start, start + needle.len(), Vec::new()));
                    position = start + needle.len();
                }
            }
        }
        let mut output = self.prepare_regexp_output(input.len(), full_unicode)?;
        let mut last = 0usize;
        // Names are identifiers, not matcher units. The replacement template
        // uses the encoded carrier too, so compare it with encoded names
        // while keeping the original names on a callback's groups object.
        let substitution_names: Vec<Option<String>> = group_names
            .iter()
            .map(|name| {
                name.as_ref().map(|name| {
                    RegExpInput::encode(&JsString::from(name.as_str()), full_unicode).into_owned()
                })
            })
            .collect();
        // The replacer's position (UTF-16) is counted on from the previous
        // match (matches come in order) and its string argument is made
        // once: decoding the prefix and copying the subject per call made a
        // callback replace over a long string quadratic (bd-9vouw.480).
        let mut position_cursor = (0usize, 0usize);
        let subject_value = callable.then(|| Value::Str(subject.clone()));
        for (start, end, groups) in matches {
            self.append_regexp_output(&mut output, &input[last..start])?;
            let matched = &input[start..end];
            if let Some(subject_value) = &subject_value {
                let mut arguments = Vec::with_capacity(groups.len() + 3);
                arguments.push(Value::Str(self.decode_regexp_text(&prepared, matched)?));
                for group in &groups {
                    arguments.push(match group {
                        Some(text) => Value::Str(self.decode_regexp_text(&prepared, text)?),
                        None => Value::Undefined,
                    });
                }
                let (cursor_byte, cursor_units) = position_cursor;
                let offset = cursor_units + prepared.unit_length(&input[cursor_byte..start]);
                position_cursor = (start, offset);
                arguments.push(Value::Int(i64::try_from(offset).unwrap_or(i64::MAX)));
                arguments.push(subject_value.clone());
                // ES2020 21.2.5.8 step 14.l: with named groups the replacer
                // also receives the groups object, as its last argument.
                if group_names.iter().any(Option::is_some) {
                    // OrdinaryObjectCreate(null), as a match's `groups` is
                    // (bd-9vouw.365): `None` alone links Object.prototype.
                    let named = self.alloc_object_with_prototype(None)?;
                    self.store_prototype_link(named, None);
                    for (name, value) in group_names.iter().zip(&arguments[1..1 + groups.len()]) {
                        if let Some(name) = name {
                            self.set_object_property(named, name.clone(), value.clone())?;
                        }
                    }
                    arguments.push(Value::Object(named));
                }
                self.preflight_inline_method_call_with_argument_label(
                    module,
                    replace,
                    arguments.len(),
                    Some(&label),
                )?;
                let (result, _) = self.invoke_inline_method_call_with_argument_label_preflighted(
                    module,
                    replace.clone(),
                    Value::Undefined,
                    arguments,
                    Some(label.clone()),
                )?;
                // ToString of the replacer's result (ES2020 21.1.3.17 step
                // 6.e, 21.2.5.8 step 14.l.iii): an object's own toString
                // runs, and a Symbol is a TypeError (bd-9vouw.358).
                let text = self.replacement_to_string(module, &result)?;
                let replacement = self.prepare_regexp_input(&text, full_unicode)?;
                self.append_regexp_output(&mut output, replacement.text())?;
            } else {
                // A template can expand far beyond its own length (`$'`
                // repeated). Append directly with decoded-length admission
                // for each piece, avoiding a second replacement allocation.
                self.get_substitution(
                    matched,
                    input,
                    start,
                    end,
                    &groups,
                    &substitution_names,
                    template.text(),
                    &mut output,
                )?;
            }
            last = end;
        }
        self.append_regexp_output(&mut output, &input[last..])?;
        let result = self.decode_regexp_text(&prepared, output.text())?;
        self.replace_pending_hostcall_result_label(Some(label))?;
        Ok(Value::Str(result))
    }

    /// ES2020 21.1.3.17.1 GetSubstitution: `$$`, `$&`, `` $` ``, `$'`, `$n`,
    /// `$nn`, and `$<name>` when the pattern has named groups (the group's
    /// text, empty for an unknown or unmatched name; `$<` without a closing
    /// `>`, or with no named groups, stays literal). `names[i]` names
    /// `groups[i]`.
    ///
    /// Each borrowed piece is admitted against decoded string length and
    /// live native capacity before it is appended (franken_engine#2).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn get_substitution(
        &self,
        matched: &str,
        input: &str,
        start: usize,
        end: usize,
        groups: &[Option<String>],
        names: &[Option<String>],
        template: &str,
        output: &mut RegExpOutput,
    ) -> Result<(), InterpreterError> {
        let has_named_groups = names.iter().any(Option::is_some);
        let bytes = template.as_bytes();
        let group = |index: usize| {
            (1..=groups.len())
                .contains(&index)
                .then(|| groups[index - 1].as_deref().unwrap_or_default())
        };
        let mut index = 0usize;
        while index < template.len() {
            if bytes[index] == b'$' && index + 1 < template.len() {
                let next = bytes[index + 1];
                let expansion = match next {
                    b'$' => Some(("$", 2)),
                    b'<' if has_named_groups => template[index + 2..].find('>').map(|close| {
                        let name = &template[index + 2..index + 2 + close];
                        let text = names
                            .iter()
                            .position(|candidate| candidate.as_deref() == Some(name))
                            .and_then(|position| groups.get(position).and_then(Option::as_deref))
                            .unwrap_or_default();
                        (text, close + 3)
                    }),
                    b'&' => Some((matched, 2)),
                    b'`' => Some((&input[..start], 2)),
                    b'\'' => Some((&input[end..], 2)),
                    b'0'..=b'9' => {
                        let first = usize::from(next - b'0');
                        let two_digit = bytes
                            .get(index + 2)
                            .filter(|digit| digit.is_ascii_digit())
                            .and_then(|digit| group(first * 10 + usize::from(*digit - b'0')));
                        match two_digit {
                            Some(text) => Some((text, 3)),
                            None => group(first).map(|text| (text, 2)),
                        }
                    }
                    _ => None,
                };
                if let Some((text, width)) = expansion {
                    self.append_regexp_output(output, text)?;
                    index += width;
                    continue;
                }
            }
            let ch = template[index..].chars().next().unwrap_or('\u{fffd}');
            self.append_regexp_output(output, &template[index..index + ch.len_utf8()])?;
            index += ch.len_utf8().max(1);
        }
        Ok(())
    }

    /// Coerce a `Number.prototype` receiver to an `f64`, mirroring the
    /// receiver-less `builtin:NumberPrototype*` handlers (bd-i08nh).
    pub(super) fn number_receiver_to_f64(receiver: &Value) -> f64 {
        match receiver {
            Value::Int(n) => *n as f64,
            Value::Float(f) => f.inner(),
            Value::Bool(true) => 1.0,
            Value::Bool(false) | Value::Null => 0.0,
            Value::Str(s) => s.trim().parse::<f64>().unwrap_or(f64::NAN),
            _ => f64::NAN,
        }
    }

    /// Receiver-aware `Number.prototype` method seam (bd-i08nh): resolve a
    /// member access on a number PRIMITIVE (e.g. `(3.14).toFixed(2)`) to the
    /// corresponding builtin. Mirrors `string_property_value` /
    /// `array_prototype_method`. Unknown keys resolve to `undefined` (a number
    /// member access is not a TypeError in ES2020).
    pub(super) fn number_property_value(key: &str) -> Value {
        match key {
            "toFixed" => Value::BuiltinFunction(BuiltinFunction::number_to_fixed()),
            "toPrecision" => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NumberToPrecision,
            )),
            "toExponential" => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NumberToExponential,
            )),
            "toLocaleString" => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NumberToLocaleString,
            )),
            "toString" => Value::BuiltinFunction(BuiltinFunction::number_to_string()),
            "valueOf" => Value::BuiltinFunction(BuiltinFunction::number_value_of()),
            _ => Value::Undefined,
        }
    }

    /// `Boolean.prototype` methods (ES2020 19.3.3).
    pub(super) fn boolean_prototype_method(key: &str) -> Option<Value> {
        let kind = match key {
            "toString" => BuiltinFunctionKind::BooleanPrototypeToString,
            "valueOf" => BuiltinFunctionKind::BooleanPrototypeValueOf,
            _ => return None,
        };
        Some(Value::BuiltinFunction(BuiltinFunction::new_kind(kind)))
    }

    /// ES2020 19.3.3 thisBooleanValue. Boolean.prototype is itself a Boolean
    /// object whose value is false.
    pub(super) fn this_boolean_value(&self, receiver: Value) -> Result<bool, InterpreterError> {
        match receiver {
            Value::Bool(value) => Ok(value),
            Value::Object(object_id)
                if self.builtin_prototypes.get("Boolean") == Some(&object_id) =>
            {
                Ok(false)
            }
            other => Err(InterpreterError::TypeError {
                expected: "Boolean receiver (thisBooleanValue)".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// A string primitive's own properties: its code-unit indices and
    /// `length` (the String exotic object's own properties).
    pub(super) fn string_own_property_value(receiver: &JsString, key: &str) -> Option<Value> {
        if Self::canonical_array_index_property(key, receiver.utf16_len()).is_some()
            || key == "length"
        {
            Some(Self::string_property_value(receiver, key))
        } else {
            None
        }
    }

    /// ES2020 6.2.4.8 GetValue on a primitive base: [[Get]] on ToObject(base)
    /// with the primitive itself as the receiver, so members a program adds
    /// to `String.prototype`, `Number.prototype`, `Boolean.prototype`,
    /// `BigInt.prototype` or `Object.prototype` are found, user definitions
    /// win over the builtins, and `constructor` is the type's constructor.
    /// The caller has already resolved the wrapper's own properties (a
    /// string's indices and length). The canonical prototypes are allocated
    /// lazily: until a program touches one, nothing can have been added to
    /// it, and its members are the static builtin tables. Nothing is
    /// allocated here. Returns the value and the object that supplied it (for
    /// the stored-label join), if any.
    pub(super) fn primitive_prototype_get(
        &mut self,
        module: &Ir3Module,
        type_name: &'static str,
        key: &RuntimePropertyKey,
        receiver: Value,
    ) -> Result<(Value, Option<ObjectId>), InterpreterError> {
        // A prototype is made on first use, and its Symbol-keyed members
        // (%Function.prototype%[@@hasInstance], bd-9vouw.268; BigInt's and
        // Symbol's @@toStringTag, bd-9vouw.270) exist only on it: a Symbol
        // read through a primitive or function materializes it, or fell
        // through to %Object.prototype% and read undefined
        // (`Object.prototype.toString.call(1n)` was "[object Object]").
        // So are %Function.prototype%'s `caller` and `arguments` accessors
        // (bd-9vouw.272).
        let restricted_function_property =
            type_name == "Function" && matches!(key.as_str(), Some("caller" | "arguments"));
        if (matches!(key, RuntimePropertyKey::Symbol(_)) || restricted_function_property)
            && canonical_builtin_prototype_name(type_name).is_some()
        {
            self.ensure_builtin_prototype(type_name)?;
        }
        if let Some(&prototype) = self.builtin_prototypes.get(type_name) {
            let value =
                self.proxy_aware_get_runtime_property(Some(module), prototype, key, receiver, 0)?;
            return Ok((value, Some(prototype)));
        }
        if let Some(name) = key.as_str() {
            if let Some(value) = Self::canonical_prototype_method(type_name, name) {
                return Ok((value, None));
            }
            if name == "constructor" && type_name == "Promise" {
                return Ok((
                    self.promise_intrinsic_constructor()
                        .unwrap_or(Value::Undefined),
                    None,
                ));
            }
            if name == "constructor" && type_name == "Function" {
                return Ok((
                    Value::BuiltinFunction(BuiltinFunction::function_constructor()),
                    None,
                ));
            }
            if name == "constructor"
                && (STANDARD_CONSTRUCTOR_GLOBALS.contains(&type_name)
                    || FUNCTION_KIND_INTRINSICS.contains(&type_name))
            {
                return Ok((
                    Value::BuiltinFunction(BuiltinFunction::standard_constructor(type_name)),
                    None,
                ));
            }
        }
        if let Some(&object_prototype) = self.builtin_prototypes.get("Object") {
            let value = self.proxy_aware_get_runtime_property(
                Some(module),
                object_prototype,
                key,
                receiver,
                0,
            )?;
            return Ok((value, Some(object_prototype)));
        }
        Ok((
            key.as_str()
                .and_then(Self::object_prototype_method)
                .map_or(Value::Undefined, Value::BuiltinFunction),
            None,
        ))
    }

    /// `BigInt.prototype` methods on a BigInt primitive (ES2020 20.2.3).
    pub(super) fn bigint_property_value(key: &str) -> Value {
        match key {
            "toString" | "toLocaleString" => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::BigIntToString,
            )),
            "valueOf" => Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::BigIntValueOf,
            )),
            _ => Value::Undefined,
        }
    }

    /// %Promise%, the constructor this realm installed as the global
    /// `Promise`, for `promise.constructor` and
    /// `Promise.prototype.constructor`; `None` once a program has replaced
    /// the global.
    pub(super) fn promise_intrinsic_constructor(&self) -> Option<Value> {
        self.materialized_intrinsic_constructor("Promise")
    }

    /// The constructor this realm installed as the global `name` when that
    /// is a materialized constructor (`Date`, `Promise`, `Function`: a
    /// builtin with its own property object), for the `constructor` of its
    /// prototype, so `new Date().constructor === Date` (rfdc keys its clone
    /// handlers by constructor). `None` once a program has replaced the
    /// global.
    pub(super) fn materialized_intrinsic_constructor(&self, name: &str) -> Option<Value> {
        let value = if let Some(binding) = self.realm_dynamic_globals.get(name) {
            binding.state.borrow().value.clone()
        } else {
            // A Script declaration moves this name from its injected cell to
            // the global object record. Retain the intrinsic identity there
            // until the program replaces the constructor.
            let global = self.realm_global_object?;
            let key = RuntimePropertyKey::String(name.into());
            if self.runtime_property_label(global, &key) != Label::Public {
                return None;
            }
            self.heap
                .get(global.0 as usize)?
                .own_runtime_property_value(&key)?
        };
        matches!(
            &value,
            Value::BuiltinFunction(builtin)
                if Self::materialized_global_prototype_name(builtin) == Some(name)
        )
        .then_some(value)
    }

    pub(super) fn promise_property_value(key: &str) -> Value {
        match key {
            "then" => Value::BuiltinFunction(BuiltinFunction::promise_then()),
            "catch" => Value::BuiltinFunction(BuiltinFunction::promise_catch()),
            "finally" => Value::BuiltinFunction(BuiltinFunction::promise_finally()),
            _ => Value::Undefined,
        }
    }

    pub(super) fn close_iterator(
        &mut self,
        module: &Ir3Module,
        iterator: Value,
        reason: IteratorCloseReason,
    ) -> Result<(), InterpreterError> {
        let handle = self.expect_iterator_handle(iterator)?;
        let (trace_index, return_target) = match self.iterator_state_mut(handle)? {
            RuntimeIteratorState::ForIn(state) => {
                state.closed = true;
                state.done = true;
                (state.trace_index, None)
            }
            RuntimeIteratorState::ForOf(state) => {
                let return_target = if state.return_called {
                    None
                } else {
                    state.iterator_receiver.clone()
                };
                state.closed = true;
                state.done = true;
                (state.trace_index, return_target)
            }
        };
        let close_reason = if reason == IteratorCloseReason::Break
            && self
                .iteration_traces
                .get(trace_index)
                .is_some_and(|trace| trace.kind == IterationKind::Destructuring)
        {
            CloseReason::DestructuringExhausted
        } else {
            Self::close_reason_from_ir(reason)
        };

        let Some(receiver) = return_target else {
            self.record_iterator_close_event(
                trace_index,
                close_reason,
                false,
                IterationCompletion::Normal,
            );
            return Ok(());
        };
        let return_method = match &receiver {
            Value::Generator(_) => Some(Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::GeneratorReturn,
            ))),
            Value::Iterator(_) => None,
            other => match self.iterator_carrier_backing_id(other, "iterator receiver")? {
                Some(object_id) => self.optional_callable_property(
                    Some(module),
                    object_id,
                    "return",
                    receiver.clone(),
                )?,
                None => None,
            },
        };
        let Some(return_method) = return_method else {
            self.record_iterator_close_event(
                trace_index,
                close_reason,
                false,
                IterationCompletion::Normal,
            );
            return Ok(());
        };

        if let RuntimeIteratorState::ForOf(state) = self.iterator_state_mut(handle)? {
            state.return_called = true;
        }
        let lookup_label = self.pending_hostcall_result_label.clone();
        let (invocation, callback_started) = self
            .invoke_inline_method_call_tracking_callback_start(
                Some(module),
                return_method,
                receiver,
                Vec::new(),
                lookup_label,
            );
        let result = match invocation {
            Ok((result, _label)) => result,
            Err(error) => {
                if callback_started {
                    self.record_iterator_close_event(
                        trace_index,
                        close_reason,
                        true,
                        IterationCompletion::CloseThrew,
                    );
                }
                return Err(error);
            }
        };
        if !result.is_object_like() {
            if callback_started {
                self.record_iterator_close_event(
                    trace_index,
                    close_reason,
                    true,
                    IterationCompletion::InvalidResult,
                );
            }
            return Err(InterpreterError::TypeError {
                expected: "object returned by iterator.return".to_string(),
                got: result.type_name().to_string(),
            });
        }
        if callback_started {
            self.record_iterator_close_event(
                trace_index,
                close_reason,
                true,
                IterationCompletion::Normal,
            );
        }
        Ok(())
    }

    pub(super) fn prototype_chain_contains(
        &self,
        object_id: ObjectId,
        prototype: ObjectId,
    ) -> Result<bool, InterpreterError> {
        let mut current = self.observable_prototype_link(
            self.heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?,
            object_id,
        );
        let mut depth = 0u32;
        let mut visited = ChainGuard::default();
        visited.insert(object_id);

        while let Some(id) = current {
            if id == prototype {
                return Ok(true);
            }
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                return Ok(false);
            }
            current = self.observable_prototype_link(
                self.heap
                    .get(id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?,
                id,
            );
            depth += 1;
        }

        Ok(false)
    }

    /// The [[Prototype]] link user code observes (bd-9vouw.34). Ordinary
    /// objects and arrays are allocated without a stored link. Unless that
    /// link was explicitly nulled, it is the realm's %Array.prototype%
    /// (arrays) or %Object.prototype%, which ends every chain. Only
    /// intrinsics that already exist are followed: one never allocated holds
    /// no properties to find, and [`Self::chain_reaches_object_prototype`]
    /// answers membership without allocating.
    pub(super) fn observable_prototype_link(
        &self,
        object: &HeapObject,
        id: ObjectId,
    ) -> Option<ObjectId> {
        if object.prototype.is_some() || object.is_null_prototype {
            return object.prototype;
        }
        let object_prototype = self.builtin_prototypes.get("Object").copied();
        if object_prototype == Some(id) {
            return None;
        }
        if object.is_array
            && let Some(array_prototype) = self.builtin_prototypes.get("Array").copied()
            && array_prototype != id
        {
            return Some(array_prototype);
        }
        object_prototype
    }

    /// [`Self::observable_prototype_link`] by id.
    pub(super) fn observable_prototype_of(&self, id: ObjectId) -> Option<ObjectId> {
        self.heap
            .get(id.0 as usize)
            .and_then(|object| self.observable_prototype_link(object, id))
    }

    /// Whether `object.__proto__` reaches %Object.prototype%'s `__proto__`
    /// accessor (Annex B.2.2.1): neither the receiver nor any object before
    /// %Object.prototype% on its chain has an own `__proto__`, and the chain
    /// does reach %Object.prototype%. Otherwise `__proto__` is an ordinary
    /// property name: an own data property (JSON.parse, defineProperty,
    /// spread) is read and written as data, and a null-prototype object has
    /// no such accessor, so a read is undefined and a write defines it
    /// (bd-9vouw.318). A Proxy receiver keeps the accessor path, whose
    /// setter runs its setPrototypeOf trap (bd-9vouw.311).
    pub(super) fn proto_key_reaches_accessor(&self, id: ObjectId) -> bool {
        let key = RuntimePropertyKey::String(JsString::from("__proto__"));
        let object_prototype = self.builtin_prototypes.get("Object").copied();
        let mut current = id;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(object) = self.heap.get(current.0 as usize) else {
                return false;
            };
            if object.brand() == Some(PROXY_TYPE_TAG) {
                return current == id;
            }
            if object.contains_own_runtime_property(&key) {
                return false;
            }
            // Unless `delete Object.prototype.__proto__` removed it
            // (bd-9vouw.284).
            if Some(current) == object_prototype {
                return !self.virtual_own_property_deleted(current, &key);
            }
            // An implicit link is followed (%Array.prototype% for an array,
            // then %Object.prototype%), so a redefined or deleted
            // Object.prototype.__proto__ is seen (bd-9vouw.284); an
            // unallocated %Object.prototype% is pristine, an explicit null
            // ends the chain without the accessor.
            match self.observable_prototype_link(object, current) {
                Some(next) => current = next,
                None => return !object.is_null_prototype,
            }
        }
        false
    }

    /// Whether `id`'s chain ends at %Object.prototype%, allocated or not; an
    /// explicit null link ends it before.
    pub(super) fn chain_reaches_object_prototype(&self, id: ObjectId) -> bool {
        let object_prototype = self.builtin_prototypes.get("Object").copied();
        let mut current = id;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            if Some(current) == object_prototype {
                return true;
            }
            let Some(object) = self.heap.get(current.0 as usize) else {
                return false;
            };
            match object.prototype {
                Some(next) => current = next,
                None => return !object.is_null_prototype,
            }
        }
        false
    }

    /// [[GetPrototypeOf]] of an ordinary object, allocating the default
    /// intrinsic the first time user code observes it (bd-9vouw.34).
    pub(super) fn ordinary_get_prototype_of(
        &mut self,
        id: ObjectId,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let object = self
            .heap
            .get(id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
        if object.prototype.is_some() || object.is_null_prototype {
            return Ok(object.prototype);
        }
        let is_array = object.is_array;
        let object_prototype = self.ensure_builtin_prototype("Object")?;
        if object_prototype == id {
            return Ok(None);
        }
        if is_array {
            let array_prototype = self.ensure_builtin_prototype("Array")?;
            if array_prototype != id {
                return Ok(Some(array_prototype));
            }
        }
        Ok(Some(object_prototype))
    }

    /// Store `prototype` as `id`'s [[Prototype]]; `None` is an explicit null.
    pub(super) fn store_prototype_link(&mut self, id: ObjectId, prototype: Option<ObjectId>) {
        self.mutate_heap(|heap| {
            if let Some(object) = heap.get_mut(id.0 as usize) {
                object.prototype = prototype;
                object.is_null_prototype = prototype.is_none();
            }
        });
    }

    /// Whether `needle` is on the [[Prototype]] chain of the object-like
    /// `value` (OrdinaryHasInstance step 7 and `isPrototypeOf`). A function
    /// value's chain starts at its function [[Prototype]], so
    /// `f instanceof Object` and `B instanceof Function` hold (bd-9vouw.34).
    pub(super) fn value_prototype_chain_contains(
        &mut self,
        module: Option<&Ir3Module>,
        value: &Value,
        needle: &Value,
    ) -> Result<bool, InterpreterError> {
        // A function needle is linked into chains as its own-property
        // backing object (prototype_link_for_value: `Object.create(fn)`,
        // `F.prototype = fn; new F()`), so a link to that object is the
        // function. Without a backing no object links to it.
        let needle_backing = self.own_property_holder(module, needle, false)?;
        let mut current = value.clone();
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let next = match &current {
                // A proxy answers [[GetPrototypeOf]] through its trap or its
                // target (ES2020 9.5.1): `new Proxy([], {}) instanceof Array`.
                Value::Object(id) if self.active_proxy_record(*id)?.is_some() => {
                    self.object_get_prototype(module, *id, 0)?
                }
                Value::Object(id) => self
                    .observable_prototype_of(*id)
                    .map_or(Value::Null, Value::Object),
                callable if callable.is_callable() => {
                    self.function_value_prototype(module, callable)?
                }
                // A promise (a subclass's through its prototype, bd-9vouw.137),
                // generator, async generator (its function's `prototype`) or
                // iterator continues at its prototype: `gen() instanceof
                // genFn`, `it instanceof Object` (bd-9vouw.120).
                exotic @ (Value::Promise(_)
                | Value::Generator(_)
                | Value::AsyncGeneratorObject(_)
                | Value::Iterator(_)) => match match module {
                    Some(module) => self.exotic_prototype_override(module, exotic)?,
                    None => None,
                } {
                    Some(prototype) => Value::Object(prototype),
                    None => {
                        let name = self
                            .exotic_intrinsic_prototype_name(exotic)
                            .expect("an exotic value has an intrinsic prototype");
                        Value::Object(self.ensure_builtin_prototype(name)?)
                    }
                },
                _ => return Ok(false),
            };
            if next == *needle
                || (needle_backing.is_some()
                    && self.own_property_holder(module, &next, false)? == needle_backing)
            {
                return Ok(true);
            }
            if matches!(next, Value::Null) {
                return Ok(false);
            }
            current = next;
        }
        Ok(false)
    }

    /// Whether `key` names a builtin method this engine supplies virtually
    /// (not as an own property of the shared prototype objects) somewhere on
    /// `object_id`'s chain, so `'push' in []` and `'hasOwnProperty' in {}`
    /// agree with the [[Get]] fallbacks (bd-9vouw.34).
    /// Whether `object_id` inherits the Array.prototype builtins through an
    /// array further up its chain (`F.prototype = [...]`,
    /// `Object.create([])`): an array whose own link is the default one
    /// reaches %Array.prototype%, which is not allocated until a program
    /// names it (with it allocated, the canonical-prototype walk serves the
    /// methods). The root itself is the caller's `is_array` check.
    pub(super) fn chain_inherits_array_prototype(&self, object_id: ObjectId) -> bool {
        let array_prototype = self.builtin_prototypes.get("Array").copied();
        let mut current = self.observable_prototype_of(object_id);
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(id) = current else {
                return false;
            };
            let Some(object) = self.heap.get(id.0 as usize) else {
                return false;
            };
            if object.is_array {
                return !object.is_null_prototype
                    && (object.prototype.is_none() || object.prototype == array_prototype);
            }
            current = self.observable_prototype_link(object, id);
        }
        false
    }

    /// The collection whose `size` accessor a [[Get]] or HasProperty of
    /// `size` on `object_id` reaches: a Map or Set instance's (implicit
    /// prototype link), or one whose chain reaches %Map.prototype% /
    /// %Set.prototype% (a subclass instance, `Object.create(Map.prototype)`).
    pub(super) fn collection_size_owner(&self, object_id: ObjectId) -> Option<&'static str> {
        ["Map", "Set"].into_iter().find(|owner| {
            self.collection_storage_id(object_id, owner).is_some()
                || self.chain_reaches_canonical_prototype(object_id, owner)
        })
    }

    pub(super) fn chain_has_virtual_builtin_property(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> bool {
        if key == "size"
            && let Some(owner) = self.collection_size_owner(object_id)
            && !self.canonical_virtual_name_deleted(owner, key)
        {
            return true;
        }
        let root_is_array = self
            .heap
            .get(object_id.0 as usize)
            .is_some_and(|object| object.is_array);
        if (root_is_array || self.chain_inherits_array_prototype(object_id))
            && Self::array_prototype_method(key).is_some()
            && !self.canonical_virtual_name_deleted("Array", key)
        {
            return true;
        }
        if self
            .builtin_prototype_method_for_chain(object_id, key)
            .is_some()
        {
            return true;
        }
        self.chain_reaches_object_prototype(object_id)
            && (key == "constructor" || Self::object_prototype_method(key).is_some())
            && !self.canonical_virtual_name_deleted("Object", key)
    }

    /// Walk the prototype chain to find a property value.
    pub(super) fn prototype_chain_get(
        &mut self,
        object_id: ObjectId,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        self.prototype_chain_get_with_receiver(None, object_id, key, Value::Object(object_id))
    }

    pub(super) fn prototype_chain_get_with_receiver(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &str,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        self.prototype_chain_get_with_receiver_runtime(
            module,
            object_id,
            &RuntimePropertyKey::String(JsString::from(key)),
            receiver,
        )
    }

    pub(super) fn prototype_chain_get_with_receiver_runtime(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        self.prototype_chain_get_with_receiver_runtime_at_depth(module, object_id, key, receiver, 0)
    }

    /// Preserve one traversal budget across ordinary and Proxy prototype links.
    /// A Proxy is an internal-method boundary, never a map to skip over.
    pub(super) fn prototype_chain_get_with_receiver_runtime_at_depth(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        receiver: Value,
        initial_depth: u32,
    ) -> Result<Value, InterpreterError> {
        self.validate_executable_property_key(key)?;
        if let Some(key) = key.as_str() {
            if let Some(value) = self.writable_state_view_value(object_id, key) {
                return Ok(value);
            }
            if let Some(value) = self.typed_array_indexed_get_property(object_id, key)? {
                return Ok(value);
            }
        }

        let mut current = Some(object_id);
        let mut depth = initial_depth;
        let mut visited = ChainGuard::default();

        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                // Deterministic decision: fold, don't record (bd-9vouw.18).
                self.nondeterminism_trace.witness_deterministic(
                    NondeterminismSource::PropertyResolution,
                    format!(
                        "chain_limit_reached:key={},depth={}",
                        key.diagnostic(),
                        depth
                    )
                    .as_bytes(),
                );
                return Ok(Value::Undefined);
            }
            if self.proxy_record(id)?.is_some() {
                return self.proxy_aware_get_runtime_property(module, id, key, receiver, depth);
            }
            if let Some(key) = key.as_str() {
                if let Some(value) = self.writable_state_view_value(id, key) {
                    return Ok(value);
                }
                if let Some(value) = self.typed_array_indexed_get_property(id, key)? {
                    return Ok(value);
                }
                if let Some(value) = self.string_wrapper_own_property(id, key) {
                    return Ok(value);
                }
            }
            let (property_value, next_prototype) = {
                let Some(object) = self.heap.get(id.0 as usize) else {
                    return Err(InterpreterError::ObjectNotFound { id: id.0 });
                };
                (
                    object.own_runtime_property_value(key),
                    self.observable_prototype_link(object, id),
                )
            };
            if let Some(val) = property_value {
                // Capture property resolution success for deterministic replay
                self.capture_property_resolution_found(key, id, depth);
                // A materialized constructor walks its actual function
                // prototype, while its own storage has an ordinary object's
                // implicit chain. Preserve the label of this resolved owner
                // before a getter runs or throws (bd-9vouw.366).
                if let Some(module) = module
                    && self
                        .authoritative_standard_constructor_backing(module, &receiver, key)?
                        .is_some()
                {
                    let label = self.runtime_property_label(id, key);
                    if label != Label::Public {
                        self.join_into_pending_hostcall_result_label(Some(label))?;
                    }
                }
                return self.resolve_accessor_get(module, val, receiver);
            }
            // RegExp.prototype.global, Map.prototype.size, ...: accessors the
            // prototype describes without storing (bd-9vouw.162).
            if let Some(module) = module
                && let Some(getter) = self.prototype_getter_at(id, key)
            {
                self.capture_property_resolution_found(key, id, depth);
                return self.call_prototype_getter(module, &getter, receiver);
            }
            let skip_inherited_buffer_fallback = self.builtin_prototypes.get("Buffer") == Some(&id)
                && key.as_str().is_some_and(|k| {
                    k != "constructor" && Self::buffer_prototype_method(k).is_none()
                });
            if !skip_inherited_buffer_fallback
                && let Some(val) = self.canonical_prototype_virtual_property(id, key)
            {
                self.capture_property_resolution_found(key, id, depth);
                return Ok(val);
            }
            if id == object_id
                && !self.builtin_prototypes.contains_key("Array")
                && self.heap.get(id.0 as usize).is_some_and(|obj| {
                    obj.is_array && !obj.is_null_prototype && obj.prototype.is_none()
                })
                && !self.canonical_virtual_property_deleted("Array", key)
            {
                let implicit_array_val = match key {
                    RuntimePropertyKey::String(name) => match name.as_str() {
                        Some("constructor") => Some(Value::BuiltinFunction(
                            BuiltinFunction::standard_constructor("Array"),
                        )),
                        Some(method) => {
                            Self::array_prototype_method(method).map(Value::BuiltinFunction)
                        }
                        None => None,
                    },
                    RuntimePropertyKey::Symbol(symbol)
                        if *symbol == WellKnownSymbol::Iterator.id() =>
                    {
                        Some(Value::BuiltinFunction(BuiltinFunction::array_values()))
                    }
                    RuntimePropertyKey::Symbol(_) => None,
                };
                if let Some(val) = implicit_array_val {
                    self.capture_property_resolution_found(key, id, depth + 1);
                    return Ok(val);
                }
            }
            current = next_prototype;
            depth += 1;
        }

        // URL fields are native accessors over authenticated side-table state.
        // Consult them only after ordinary own/inherited properties have had a
        // chance to shadow the accessor, and never trust guest heap metadata as
        // a brand (bd-8y0gs).
        if matches!(
            key,
            RuntimePropertyKey::Symbol(symbol)
                if *symbol == WellKnownSymbol::Iterator.id()
        ) {
            let Some(root) = self.heap.get(object_id.0 as usize) else {
                return Err(InterpreterError::ObjectNotFound { id: object_id.0 });
            };
            let root_has_implicit_array_prototype =
                root.is_array && !root.is_null_prototype && root.prototype.is_none();
            let root_is_typed_array = root.typed_array.is_some();
            // A deleted %Array.prototype%[@@iterator] (bd-9vouw.93) leaves
            // arrays without one, like every prototype's virtual method below.
            let array_deleted = self.canonical_virtual_property_deleted("Array", key);
            if root_has_implicit_array_prototype && !array_deleted {
                return Ok(Value::BuiltinFunction(BuiltinFunction::array_values()));
            }
            // %TypedArray%.prototype[@@iterator] is
            // %TypedArray%.prototype.values (ES2020 22.2.3.32), so a typed
            // array, Int8Array.prototype and %TypedArray%.prototype give one
            // function.
            if (root_is_typed_array
                || self.chain_reaches_canonical_prototype(object_id, "TypedArray"))
                && !self.canonical_virtual_property_deleted("TypedArray", key)
            {
                return Ok(Value::BuiltinFunction(BuiltinFunction::typed_array_values()));
            }
            // %Array.prototype%[@@iterator] is %Array.prototype.values%
            // (ES2020 22.1.3.31): read from Array.prototype itself or from an
            // object inheriting from it (`Object.create(Array.prototype)`).
            if (self.chain_reaches_canonical_prototype(object_id, "Array")
                || self.chain_inherits_array_prototype(object_id))
                && !array_deleted
            {
                return Ok(Value::BuiltinFunction(BuiltinFunction::array_values()));
            }
            // Map.prototype[@@iterator] is Map.prototype.entries, Set's is
            // Set.prototype.values (ES2020 23.1.3.12, 23.2.3.11) and
            // String.prototype[@@iterator] the string iterator (21.1.3.29),
            // read from the prototypes themselves too: only instances and
            // primitives had them, so `typeof Map.prototype[Symbol.iterator]`
            // was "undefined".
            for (prototype, kind) in [
                ("Map", BuiltinFunctionKind::MapEntries),
                ("Set", BuiltinFunctionKind::SetValues),
                ("String", BuiltinFunctionKind::StringIterator),
            ] {
                if self.chain_reaches_canonical_prototype(object_id, prototype)
                    && !self.canonical_virtual_property_deleted(prototype, key)
                {
                    return Ok(Value::BuiltinFunction(BuiltinFunction::new_kind(kind)));
                }
            }
            // URLSearchParams.prototype[@@iterator] is its entries (bd-9vouw.126).
            if (self.url_search_params.contains_key(&object_id)
                || self.chain_reaches_canonical_prototype(object_id, "URLSearchParams"))
                && !self.canonical_virtual_property_deleted("URLSearchParams", key)
            {
                return Ok(Value::BuiltinFunction(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::UrlSearchParamsEntries,
                )));
            }
        }
        // RegExp.prototype's symbol-keyed methods (ES2020 21.2.5.6-11), once
        // own and inherited properties have had their chance to shadow them.
        if let RuntimePropertyKey::Symbol(symbol) = key
            && let Some(method) = regexp_symbol_method_key(*symbol)
            && self.chain_has_regexp_prototype(object_id)
            && !self.canonical_virtual_property_deleted("RegExp", key)
        {
            return Ok(Value::BuiltinFunction(
                BuiltinFunction::regexp_symbol_method(method),
            ));
        }
        let Some(key_text) = key.as_str() else {
            self.nondeterminism_trace.witness_deterministic(
                NondeterminismSource::PropertyResolution,
                format!(
                    "property_not_found:key={},final_depth={}",
                    key.diagnostic(),
                    depth
                )
                .as_bytes(),
            );
            return Ok(Value::Undefined);
        };
        // Consult virtual function prototypes only after real own/inherited
        // properties, including an explicitly stored undefined, have won.
        // Materialized constructors already walk their actual prototype;
        // a custom parent must not acquire Function.prototype's members.
        let authoritative_standard_backing = match module {
            Some(module) => {
                self.authoritative_standard_constructor_backing(module, &receiver, key)?
            }
            None => None,
        };
        if receiver.is_callable()
            && authoritative_standard_backing.is_none()
            && !matches!(&receiver, Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::FunctionPrototype)
            && let Some(value) = Self::function_prototype_property(key_text)
            && !self.canonical_virtual_property_deleted("Function", key)
        {
            return Ok(value);
        }
        // `size` of a Map or Set is %Map.prototype% / %Set.prototype%'s
        // accessor, not an own property (bd-9vouw.140): a subclass's
        // `get size()` walked above shadows it, and its getter checks the
        // receiver (`Object.create(Map.prototype).size` throws).
        if key_text == "size"
            && let Some(module) = module
            && let Some(owner) = self.collection_size_owner(object_id)
            && !self.canonical_virtual_property_deleted(owner, key)
        {
            return self.call_prototype_getter(
                module,
                &BuiltinFunction::prototype_getter(owner, "size"),
                receiver,
            );
        }
        if let Some(value) = self.url_object_property_value(object_id, key_text)? {
            return Ok(value);
        }
        // bd-9vouw.17: `constructor` of the canonical builtin prototypes is
        // virtual (never an own, enumerable property of the shared
        // prototypes), so `thrown.constructor === TypeError` and
        // `[].constructor === Array` hold without changing enumeration.
        if key_text == "constructor"
            && let Some(constructor) = self.standard_constructor_for_chain(object_id)
        {
            return Ok(constructor);
        }
        // `Error.prototype.toString` for error objects (own/inherited data
        // properties walked above still win, e.g. a user `toString`).
        if key_text == "toString"
            && self.chain_has_error_prototype(object_id)
            && !self.canonical_virtual_property_deleted("Error", key)
        {
            return Ok(Value::BuiltinFunction(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ErrorPrototypeToString,
            )));
        }

        // Array exotic objects expose their prototype methods (e.g. `push`)
        // even though we do not allocate a shared `Array.prototype` object.
        // This is a fallback: own/inherited data properties walked above win,
        // so a user-assigned `arr.push = ...` still shadows the builtin
        // (bd-bg9l1.27.9 / DISC-012).
        let root_is_array = self
            .heap
            .get(object_id.0 as usize)
            .map(|object| object.is_array)
            .unwrap_or(false);
        if let Some(builtin) = Self::array_prototype_method(key_text)
            && (root_is_array || self.chain_inherits_array_prototype(object_id))
            && !self.canonical_virtual_property_deleted("Array", key)
        {
            return Ok(Value::BuiltinFunction(builtin));
        }
        // bd-9vouw.17: the canonical `Array.prototype`, `String.prototype`
        // and `Number.prototype` objects (and objects inheriting from them)
        // expose the builtin methods as values, so
        // `Array.prototype.every.call(arrayLike, f)` works.
        if let Some(method) = self.builtin_prototype_method_for_chain(object_id, key_text) {
            return Ok(method);
        }

        // Map/Set exotic objects expose their prototype methods via member
        // access (bd-juodx). Like arrays, own/inherited data properties walked
        // above win first — so `m.size` resolves to the `size` data property,
        // and a user-assigned `m.set = …` shadows the builtin.
        let root_has_readable = self.readable_from_streams.contains_key(&object_id);
        let root_has_writable = self.writable_streams.contains_key(&object_id)
            || self.writable_terminal_states.contains_key(&object_id);
        let root_type_tag = if self.url_search_params.contains_key(&object_id) {
            Some("URLSearchParams".to_string())
        } else if root_has_readable && root_has_writable {
            Some(
                match self
                    .writable_streams
                    .get(&object_id)
                    .map(|state| state.flavor)
                {
                    Some(WritableStreamFlavor::Transform) => "Transform",
                    _ => "PassThrough",
                }
                .to_string(),
            )
        } else if root_has_readable {
            Some("Readable".to_string())
        } else if root_has_writable {
            Some("Writable".to_string())
        } else {
            self.heap
                .get(object_id.0 as usize)
                .and_then(|object| object.brand().map(str::to_string))
        };
        let root_is_buffer = self.heap.get(object_id.0 as usize).is_some_and(|object| {
            object
                .typed_array
                .as_ref()
                .is_some_and(|view| view.is_buffer)
        });
        if root_is_buffer && let Some(builtin) = Self::buffer_prototype_method(key_text) {
            return Ok(Value::BuiltinFunction(builtin));
        }
        if let Some(tag) = root_type_tag.as_deref()
            && (tag != "URLSearchParams" || self.url_search_params.contains_key(&object_id))
            && let Some(builtin) = Self::collection_prototype_method(tag, key_text)
            && !self.canonical_virtual_property_deleted(tag, key)
        {
            return Ok(Value::BuiltinFunction(builtin));
        }

        // Object.prototype's methods only reach objects whose chain reaches
        // Object.prototype: `Object.create(null)` dictionaries have no
        // `toString` / `hasOwnProperty` (a key like "toString" read a builtin
        // function), matching the `in` check's rule.
        if self.chain_reaches_object_prototype(object_id)
            && let Some(builtin) = Self::object_prototype_method(key_text)
            && !self.canonical_virtual_property_deleted("Object", key)
        {
            return Ok(Value::BuiltinFunction(builtin));
        }

        // Deterministic decision: fold, don't record (bd-9vouw.18).
        self.nondeterminism_trace.witness_deterministic(
            NondeterminismSource::PropertyResolution,
            format!(
                "property_not_found:key={},final_depth={}",
                key.diagnostic(),
                depth
            )
            .as_bytes(),
        );
        Ok(Value::Undefined)
    }

    /// Return whether an existing own-property read can bypass the generic
    /// proxy/prototype resolver and the special-object IFC carrier scans.
    ///
    /// This is deliberately a proof-by-exclusion fast path: every object kind
    /// whose native own-read semantics or skipped IFC carrier can affect this
    /// hit remains on the generic path. The caller still runs the typed
    /// property hook, resolves accessors, joins stored-property and destination
    /// labels, and emits the same deterministic property-resolution event.
    #[cfg(test)]
    pub(super) fn ordinary_own_property_read_fast_path_eligible(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> bool {
        self.ordinary_own_property_read_object(object_id, key)
            .is_some_and(|object| object.contains_own_runtime_property(key))
    }

    /// The object of an own-property read the fast path may serve, by the
    /// exclusions above, whether or not it has the key.
    pub(super) fn ordinary_own_property_read_object(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Option<&HeapObject> {
        if key.as_str() == Some("__proto__") {
            return None;
        }
        #[cfg(test)]
        if FORCE_GENERIC_OWN_PROPERTY_READS.with(std::cell::Cell::get) {
            return None;
        }
        let object = self.heap.get(object_id.0 as usize)?;
        // An own data property answers before the prototype is consulted, so
        // a prototype does not matter here (bd-9vouw.504: instances of
        // classes and constructors now take this path). Of the generic walk's
        // depth-0 special cases, a String wrapper's index/length properties
        // are the one the exclusions below do not already cover.
        if object.is_import_meta
            || object.primitive_value.is_some()
            || object.array_buffer.is_some()
            || object.typed_array.is_some()
            || object.data_view.is_some()
            || object.brand() == Some(PROXY_TYPE_TAG)
        {
            return None;
        }

        // These host-object tables are empty in almost every program: the
        // emptiness test spares a lookup per table on every read.
        fn absent<V>(table: &BTreeMap<ObjectId, V>, object_id: &ObjectId) -> bool {
            table.is_empty() || !table.contains_key(object_id)
        }
        (absent(&self.url_objects, &object_id)
            && absent(&self.url_search_params, &object_id)
            && absent(&self.cluster_facades, &object_id)
            && !self
                .cluster_facades
                .values()
                .any(|state| state.settings == object_id)
            && absent(&self.readable_from_streams, &object_id)
            && absent(&self.readable_terminal_states, &object_id)
            && absent(&self.writable_streams, &object_id)
            && absent(&self.writable_terminal_states, &object_id)
            && absent(&self.loopback_servers, &object_id)
            && absent(&self.loopback_sockets, &object_id))
        .then_some(object)
    }

    /// The fast path's read (bd-9vouw.504): the own property's value, and
    /// for a data property its stored label, one lookup each. A data
    /// property's label is final: no code runs between this read and the
    /// label join. An accessor's getter may delete or relabel the property
    /// first, so its label is read after the getter, as before.
    pub(super) fn ordinary_own_property_fast_read(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Option<(Value, Option<Label>)> {
        let object = self.ordinary_own_property_read_object(object_id, key)?;
        let value = object.own_runtime_property_value(key)?;
        if matches!(value, Value::Accessor { .. }) {
            return Some((value, None));
        }
        let label = self.own_stored_runtime_property_label(object_id, key);
        Some((value, Some(label)))
    }

    pub(super) fn capture_property_resolution_found(
        &mut self,
        key: &RuntimePropertyKey,
        object_id: ObjectId,
        depth: u32,
    ) {
        // Deterministic decision: fold, don't record (bd-9vouw.18). The bytes
        // go through a reused buffer: a Vec per property read was malloc and
        // free on every found [[Get]].
        let mut payload = std::mem::take(&mut self.property_witness_scratch);
        write_property_resolution_found_payload(&mut payload, key, object_id, depth);
        self.nondeterminism_trace
            .witness_deterministic(NondeterminismSource::PropertyResolution, &payload);
        if payload.capacity() <= PROPERTY_WITNESS_SCRATCH_MAX_CAPACITY {
            self.property_witness_scratch = payload;
        }
    }

    /// The call-argument scratch vectors, empty, for a call to fill
    /// (bd-9vouw.497).
    pub(super) fn take_call_argument_scratch(&mut self) -> (Vec<Value>, Vec<Label>) {
        let mut values = std::mem::take(&mut self.call_argument_value_scratch);
        let mut labels = std::mem::take(&mut self.call_argument_label_scratch);
        values.clear();
        labels.clear();
        (values, labels)
    }

    /// Keep a call's drained argument vectors for the next call, unless they
    /// grew past CALL_ARGUMENT_SCRATCH_MAX_CAPACITY.
    pub(super) fn restore_call_argument_scratch(
        &mut self,
        mut values: Vec<Value>,
        mut labels: Vec<Label>,
    ) {
        values.clear();
        labels.clear();
        if values.capacity() <= CALL_ARGUMENT_SCRATCH_MAX_CAPACITY {
            self.call_argument_value_scratch = values;
        }
        if labels.capacity() <= CALL_ARGUMENT_SCRATCH_MAX_CAPACITY {
            self.call_argument_label_scratch = labels;
        }
    }

    /// Resolve an `Array.prototype` method name to its receiver-aware builtin
    /// callable. Only `push` is wired today (bd-bg9l1.27.9 / DISC-012); the
    /// receiver-less `builtin:ArrayPrototype*` hostcalls remain the
    /// detached-function path for the others.
    pub(super) fn array_prototype_method(key: &str) -> Option<BuiltinFunction> {
        match key {
            "push" => Some(BuiltinFunction::array_push()),
            "toLocaleString" => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ArrayToLocaleString,
            )),
            "pop" => Some(BuiltinFunction::array_pop()),
            "shift" => Some(BuiltinFunction::array_shift()),
            "unshift" => Some(BuiltinFunction::array_unshift()),
            "indexOf" => Some(BuiltinFunction::array_index_of()),
            "includes" => Some(BuiltinFunction::array_includes()),
            "reverse" => Some(BuiltinFunction::array_reverse()),
            "fill" => Some(BuiltinFunction::array_fill()),
            "at" => Some(BuiltinFunction::array_at()),
            "flat" => Some(BuiltinFunction::array_flat()),
            "join" => Some(BuiltinFunction::array_join()),
            "toString" => Some(BuiltinFunction::array_to_string()),
            "forEach" => Some(BuiltinFunction::array_for_each()),
            "map" => Some(BuiltinFunction::array_map()),
            "filter" => Some(BuiltinFunction::array_filter()),
            "find" => Some(BuiltinFunction::array_find()),
            "findIndex" => Some(BuiltinFunction::array_find_index()),
            "findLast" => Some(BuiltinFunction::array_find_last()),
            "findLastIndex" => Some(BuiltinFunction::array_find_last_index()),
            "flatMap" => Some(BuiltinFunction::array_flat_map()),
            "copyWithin" => Some(BuiltinFunction::array_copy_within()),
            "some" => Some(BuiltinFunction::array_some()),
            "every" => Some(BuiltinFunction::array_every()),
            "reduce" => Some(BuiltinFunction::array_reduce()),
            "reduceRight" => Some(BuiltinFunction::array_reduce_right()),
            "sort" => Some(BuiltinFunction::array_sort()),
            "concat" => Some(BuiltinFunction::array_concat()),
            "slice" => Some(BuiltinFunction::array_slice_method()),
            "lastIndexOf" => Some(BuiltinFunction::array_last_index_of()),
            "splice" => Some(BuiltinFunction::array_splice()),
            "toReversed" => Some(BuiltinFunction::array_to_reversed()),
            "toSorted" => Some(BuiltinFunction::array_to_sorted()),
            "with" => Some(BuiltinFunction::array_with()),
            "toSpliced" => Some(BuiltinFunction::array_to_spliced()),
            "entries" => Some(BuiltinFunction::array_entries()),
            "keys" => Some(BuiltinFunction::array_keys()),
            "values" => Some(BuiltinFunction::array_values()),
            _ => None,
        }
    }

    /// Build a receiver-bound crypto method for focused interpreter tests.
    ///
    /// Production property lookup intentionally never calls this helper: all
    /// accepted crypto lifecycle operations arrive through finite HostCalls.
    /// Keeping authenticated objects methodless at the generic JS property
    /// boundary prevents computed, escaped, and excluded fluent uses from
    /// dynamically recovering privileged crypto dispatch (bd-2z157).
    #[cfg(test)]
    pub(super) fn crypto_test_method(
        &self,
        object_id: ObjectId,
        key: &str,
    ) -> Option<BuiltinFunction> {
        let state = self.crypto_objects.get(&object_id)?;
        let kind = match (state, key) {
            (
                CryptoObjectState::HashActive { .. }
                | CryptoObjectState::HashFinalized { .. }
                | CryptoObjectState::HmacActive { .. }
                | CryptoObjectState::HmacFinalized { .. },
                "update",
            ) => BuiltinFunctionKind::CryptoUpdate,
            (
                CryptoObjectState::HashActive { .. }
                | CryptoObjectState::HashFinalized { .. }
                | CryptoObjectState::HmacActive { .. }
                | CryptoObjectState::HmacFinalized { .. },
                "digest",
            ) => BuiltinFunctionKind::CryptoDigest,
            (
                CryptoObjectState::HashActive { .. } | CryptoObjectState::HashFinalized { .. },
                "copy",
            ) => BuiltinFunctionKind::CryptoCopy,
            (
                CryptoObjectState::CipherActive { .. } | CryptoObjectState::CipherFinalized { .. },
                "update",
            ) => BuiltinFunctionKind::CryptoCipherUpdate,
            (
                CryptoObjectState::CipherActive { .. } | CryptoObjectState::CipherFinalized { .. },
                "final",
            ) => BuiltinFunctionKind::CryptoCipherFinal,
            (
                CryptoObjectState::CipherActive {
                    algorithm: CryptoCipherAlgorithm::Aes256Gcm,
                    direction: CryptoCipherDirection::Encrypt,
                    ..
                }
                | CryptoObjectState::CipherFinalized {
                    algorithm: CryptoCipherAlgorithm::Aes256Gcm,
                    direction: CryptoCipherDirection::Encrypt,
                    ..
                },
                "getAuthTag",
            ) => BuiltinFunctionKind::CryptoGetAuthTag,
            (
                CryptoObjectState::CipherActive {
                    algorithm: CryptoCipherAlgorithm::Aes256Gcm,
                    direction: CryptoCipherDirection::Decrypt,
                    ..
                }
                | CryptoObjectState::CipherFinalized {
                    algorithm: CryptoCipherAlgorithm::Aes256Gcm,
                    direction: CryptoCipherDirection::Decrypt,
                    ..
                },
                "setAuthTag",
            ) => BuiltinFunctionKind::CryptoSetAuthTag,
            _ => return None,
        };
        let mut builtin = BuiltinFunction::new_kind(kind);
        builtin.bound_object = Some(object_id.0);
        Some(builtin)
    }

    /// Resolve a Map/Set prototype method name to its receiver-aware builtin
    /// callable (bd-juodx). `.size` is a data property, not a method.
    pub(super) fn collection_prototype_method(
        type_tag: &str,
        key: &str,
    ) -> Option<BuiltinFunction> {
        if matches!(type_tag, "PassThrough" | "Transform") {
            return match key {
                "destroy" => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::StreamPassThroughDestroy,
                )),
                "unpipe" => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::StreamReadableUnpipe,
                )),
                _ => Self::collection_prototype_method("Readable", key)
                    .or_else(|| Self::collection_prototype_method("Writable", key)),
            };
        }
        if matches!(
            type_tag,
            "HttpServer" | "HttpClientRequest" | "HttpIncomingMessage" | "HttpServerResponse"
        ) {
            let method = match (type_tag, key) {
                ("HttpServer", "listen") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::NetServerListen,
                )),
                ("HttpServer", "address") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::NetServerAddress,
                )),
                ("HttpServer", "close") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::NetServerClose,
                )),
                ("HttpClientRequest", "write") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpClientRequestWrite,
                )),
                ("HttpClientRequest", "end") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpClientRequestEnd,
                )),
                ("HttpClientRequest", "setHeader") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpClientRequestSetHeader,
                )),
                ("HttpIncomingMessage", "setEncoding") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpIncomingMessageSetEncoding,
                )),
                ("HttpIncomingMessage", "resume") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpIncomingMessageResume,
                )),
                ("HttpServerResponse", "setHeader") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpServerResponseSetHeader,
                )),
                ("HttpServerResponse", "getHeader") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpServerResponseGetHeader,
                )),
                ("HttpServerResponse", "hasHeader") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpServerResponseHasHeader,
                )),
                ("HttpServerResponse", "removeHeader") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpServerResponseRemoveHeader,
                )),
                ("HttpServerResponse", "writeHead") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpServerResponseWriteHead,
                )),
                ("HttpServerResponse", "write") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpServerResponseWrite,
                )),
                ("HttpServerResponse", "end") => Some(BuiltinFunction::new_kind(
                    BuiltinFunctionKind::HttpServerResponseEnd,
                )),
                _ => None,
            };
            return method.or_else(|| Self::collection_prototype_method("EventEmitter", key));
        }
        match (type_tag, key) {
            ("Map", "set") => Some(BuiltinFunction::map_set()),
            ("Map", "get") => Some(BuiltinFunction::map_get()),
            ("Map", "has") => Some(BuiltinFunction::map_has()),
            ("Map", "delete") => Some(BuiltinFunction::map_delete()),
            ("Set", "add") => Some(BuiltinFunction::set_add()),
            ("Set", "has") => Some(BuiltinFunction::set_has()),
            ("Set", "delete") => Some(BuiltinFunction::set_delete()),
            ("Map", "clear") => Some(BuiltinFunction::map_clear()),
            ("Set", "clear") => Some(BuiltinFunction::set_clear()),
            ("Map", "forEach") => Some(BuiltinFunction::new_kind(BuiltinFunctionKind::MapForEach)),
            ("Set", "forEach") => Some(BuiltinFunction::new_kind(BuiltinFunctionKind::SetForEach)),
            ("Map", "keys") => Some(BuiltinFunction::new_kind(BuiltinFunctionKind::MapKeys)),
            ("Map", "values") => Some(BuiltinFunction::new_kind(BuiltinFunctionKind::MapValues)),
            ("Map", "entries") => Some(BuiltinFunction::new_kind(BuiltinFunctionKind::MapEntries)),
            ("Set", "values" | "keys") => {
                Some(BuiltinFunction::new_kind(BuiltinFunctionKind::SetValues))
            }
            ("Set", "entries") => Some(BuiltinFunction::new_kind(BuiltinFunctionKind::SetEntries)),
            ("Set", method) if set_algebra::SET_ALGEBRA_METHODS.contains(&method) => {
                Some(BuiltinFunction {
                    kind: BuiltinFunctionKind::SetMethod,
                    module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                    iterator_handle: None,
                    bound_object: None,
                })
            }
            ("Date", "getTime") => Some(BuiltinFunction::date_get_time()),
            // Annex B B.2.4.3: the initial value of toGMTString is
            // %Date.prototype.toUTCString% itself (bd-9vouw.240).
            ("Date", "toGMTString") => Some(BuiltinFunction {
                kind: BuiltinFunctionKind::DatePrototypeMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty("toUTCString"),
                iterator_handle: None,
                bound_object: None,
            }),
            ("Date", method) if DATE_PROTOTYPE_METHODS.contains(&method) => Some(BuiltinFunction {
                kind: BuiltinFunctionKind::DatePrototypeMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                iterator_handle: None,
                bound_object: None,
            }),
            ("URLSearchParams", "get") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsGet,
            )),
            ("URLSearchParams", "has") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsHas,
            )),
            ("URLSearchParams", "getAll") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsGetAll,
            )),
            ("URLSearchParams", "append") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsAppend,
            )),
            ("URLSearchParams", "sort") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsSort,
            )),
            ("URLSearchParams", "delete") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsDelete,
            )),
            ("URLSearchParams", "set") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsSet,
            )),
            ("URLSearchParams", "toString") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsToString,
            )),
            ("URLSearchParams", "keys") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsKeys,
            )),
            ("URLSearchParams", "values") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsValues,
            )),
            ("URLSearchParams", "entries") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsEntries,
            )),
            ("URLSearchParams", "forEach") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::UrlSearchParamsForEach,
            )),
            ("FsStats", "isFile") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::FsStatsIsFile,
            )),
            ("FsStats", "isDirectory") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::FsStatsIsDirectory,
            )),
            ("FsStats" | "FsDirent", "isSymbolicLink") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::FsEntryIsSymbolicLink,
            )),
            ("FsDirent", "isFile") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::FsDirentIsFile,
            )),
            ("FsDirent", "isDirectory") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::FsDirentIsDirectory,
            )),
            // bd-3894s slice (2b): the writable `ClientRequest` returned by
            // `http.request(url[, opts])` exposes `.write`/`.end` via member access,
            // exactly like Map/Set/Date expose their methods through the `__type`
            // tag. `.write` accumulates the request body; `.end` performs the
            // deferred egress.
            ("ClientRequest", "write") => Some(BuiltinFunction::client_request_write()),
            ("ClientRequest", "end") => Some(BuiltinFunction::client_request_end()),
            ("Readable" | "PassThrough" | "Transform", "pause") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamReadablePause,
            )),
            ("Readable" | "PassThrough" | "Transform", "resume") => Some(
                BuiltinFunction::new_kind(BuiltinFunctionKind::StreamReadableResume),
            ),
            ("Readable" | "PassThrough" | "Transform", "isPaused") => Some(
                BuiltinFunction::new_kind(BuiltinFunctionKind::StreamReadableIsPaused),
            ),
            ("Readable" | "PassThrough" | "Transform", "push") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamReadablePush,
            )),
            ("Readable" | "PassThrough" | "Transform", "toArray") => Some(
                BuiltinFunction::new_kind(BuiltinFunctionKind::StreamReadableToArray),
            ),
            ("Readable" | "PassThrough" | "Transform", "read") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamReadableRead,
            )),
            ("Readable" | "PassThrough" | "Transform", "unshift") => Some(
                BuiltinFunction::new_kind(BuiltinFunctionKind::StreamReadableUnshift),
            ),
            ("Readable" | "PassThrough" | "Transform", "pipe") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamReadablePipe,
            )),
            ("Readable" | "PassThrough" | "Transform", "unpipe") => Some(
                BuiltinFunction::new_kind(BuiltinFunctionKind::StreamReadableUnpipe),
            ),
            ("Readable" | "PassThrough" | "Transform", "setEncoding") => Some(
                BuiltinFunction::new_kind(BuiltinFunctionKind::StreamReadableSetEncoding),
            ),
            ("Readable", "destroy") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamReadableDestroy,
            )),
            ("PassThrough", "destroy") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamPassThroughDestroy,
            )),
            ("Transform", "destroy") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamPassThroughDestroy,
            )),
            ("Writable" | "PassThrough" | "Transform", "write") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamWritableWrite,
            )),
            ("Writable" | "PassThrough" | "Transform", "end") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamWritableEnd,
            )),
            ("Writable" | "PassThrough" | "Transform", "cork") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamWritableCork,
            )),
            ("Writable" | "PassThrough" | "Transform", "uncork") => Some(
                BuiltinFunction::new_kind(BuiltinFunctionKind::StreamWritableUncork),
            ),
            ("Writable", "destroy") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::StreamWritableDestroy,
            )),
            ("NetServer" | "TlsServer", "listen") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetServerListen,
            )),
            ("NetServer" | "TlsServer", "address") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetServerAddress,
            )),
            ("NetServer" | "TlsServer", "close") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetServerClose,
            )),
            ("NetSocket" | "TlsSocket", "write") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetSocketWrite,
            )),
            // bd-m42c2: lifecycle kill and bounded stdin bridge.
            ("ChildProcess", "kill") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ChildProcessKill,
            )),
            ("ChildProcessStdin", "write") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ChildProcessStdinWrite,
            )),
            ("ChildProcessStdin", "end") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ChildProcessStdinEnd,
            )),
            ("NetSocket" | "TlsSocket", "end") => {
                Some(BuiltinFunction::new_kind(BuiltinFunctionKind::NetSocketEnd))
            }
            ("NetSocket" | "TlsSocket", "destroy") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetSocketDestroy,
            )),
            ("NetSocket" | "TlsSocket", "setEncoding") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetSocketSetEncoding,
            )),
            ("NetSocket" | "TlsSocket", "pause") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetSocketPause,
            )),
            ("NetSocket" | "TlsSocket", "resume") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetSocketResume,
            )),
            ("NetSocket" | "TlsSocket", "ref") => {
                Some(BuiltinFunction::new_kind(BuiltinFunctionKind::NetSocketRef))
            }
            ("NetSocket" | "TlsSocket", "unref") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetSocketUnref,
            )),
            ("NetSocket" | "TlsSocket", "setNoDelay") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetSocketSetNoDelay,
            )),
            ("NetSocket" | "TlsSocket", "setKeepAlive") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::NetSocketSetKeepAlive,
            )),
            ("TlsSocket", "getPeerCertificate") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::TlsSocketGetPeerCertificate,
            )),
            ("TlsSocket", "getProtocol") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::TlsSocketGetProtocol,
            )),
            ("TlsSocket", "getCipher") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::TlsSocketGetCipher,
            )),
            ("TlsSocket", "isSessionReused") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::TlsSocketIsSessionReused,
            )),
            ("TlsSocket", "getSession") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::TlsSocketGetSession,
            )),
            // bd-3894s / bd-2dmnn: standalone EventEmitter objects and both HTTP
            // stream tags resolve against one receiver-aware EventEmitter method
            // surface and one listener side table.
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "on" | "addListener",
            ) => Some(BuiltinFunction::emitter_on()),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "once",
            ) => Some(BuiltinFunction::new_kind(BuiltinFunctionKind::EmitterOnce)),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "off" | "removeListener",
            ) => Some(BuiltinFunction::new_kind(BuiltinFunctionKind::EmitterOff)),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "removeAllListeners",
            ) => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::EmitterRemoveAllListeners,
            )),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "listenerCount",
            ) => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::EmitterListenerCount,
            )),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "eventNames",
            ) => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::EmitterEventNames,
            )),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "prependListener",
            ) => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::EmitterPrependListener,
            )),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "prependOnceListener",
            ) => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::EmitterPrependOnceListener,
            )),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "emit",
            ) => Some(BuiltinFunction::new_kind(BuiltinFunctionKind::EmitterEmit)),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "getMaxListeners",
            ) => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::EmitterGetMaxListeners,
            )),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "setMaxListeners",
            ) => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::EmitterSetMaxListeners,
            )),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "listeners",
            ) => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::EmitterListeners,
            )),
            (
                "ClientRequest" | "IncomingMessage" | "EventEmitter" | "Readable" | "Writable"
                | "NetServer" | "NetSocket" | "TlsServer" | "TlsSocket" | "Cluster"
                | "ChildProcess" | "ChildProcessStream",
                "rawListeners",
            ) => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::EmitterRawListeners,
            )),
            ("RegExp", "test") => Some(BuiltinFunction::regexp_test()),
            ("RegExp", "exec") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::RegExpPrototypeExec,
            )),
            ("RegExp", "toString") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::RegExpPrototypeToString,
            )),
            ("RegExp", "compile") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::RegExpPrototypeCompile,
            )),
            ("WeakRef", "deref") => {
                Some(BuiltinFunction::new_kind(BuiltinFunctionKind::WeakRefDeref))
            }
            ("FinalizationRegistry", method @ ("register" | "unregister")) => {
                Some(BuiltinFunction {
                    kind: BuiltinFunctionKind::FinalizationRegistryMethod,
                    module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                    iterator_handle: None,
                    bound_object: None,
                })
            }
            ("WeakSet", method @ ("add" | "has" | "delete")) => Some(BuiltinFunction {
                kind: BuiltinFunctionKind::WeakSetMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                iterator_handle: None,
                bound_object: None,
            }),
            ("TextEncoder", method @ ("encode" | "encodeInto"))
            | ("TextDecoder", method @ "decode") => Some(BuiltinFunction {
                kind: BuiltinFunctionKind::TextCodecMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                iterator_handle: None,
                bound_object: None,
            }),
            ("WeakMap", method @ ("get" | "set" | "has" | "delete")) => Some(BuiltinFunction {
                kind: BuiltinFunctionKind::WeakMapMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                iterator_handle: None,
                bound_object: None,
            }),
            ("SharedArrayBuffer", method @ ("slice" | "grow")) => Some(BuiltinFunction {
                kind: BuiltinFunctionKind::SharedArrayBufferMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                iterator_handle: None,
                bound_object: None,
            }),
            ("ArrayBuffer", "slice") => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ArrayBufferSlice,
            )),
            ("ArrayBuffer", method)
                if resizable_buffers::ARRAY_BUFFER_METHODS.contains(&method) =>
            {
                Some(BuiltinFunction {
                    kind: BuiltinFunctionKind::ArrayBufferMethod,
                    module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                    iterator_handle: None,
                    bound_object: None,
                })
            }
            ("DataView", "getUint8") => Some(BuiltinFunction::data_view_get_uint8()),
            ("DataView", "setUint8") => Some(BuiltinFunction::data_view_set_uint8()),
            ("DataView", "getInt32") => Some(BuiltinFunction::data_view_get_int32()),
            ("DataView", "setInt32") => Some(BuiltinFunction::data_view_set_int32()),
            ("DataView", "getUint32") => Some(BuiltinFunction::data_view_get_uint32()),
            ("DataView", "setUint32") => Some(BuiltinFunction::data_view_set_uint32()),
            ("DataView", method) if DATA_VIEW_METHODS.contains(&method) => Some(BuiltinFunction {
                kind: BuiltinFunctionKind::DataViewMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                iterator_handle: None,
                bound_object: None,
            }),
            _ => None,
        }
        .or_else(|| Self::typed_array_prototype_method(type_tag, key))
    }

    pub(super) fn typed_array_prototype_method(
        type_tag: &str,
        key: &str,
    ) -> Option<BuiltinFunction> {
        TypedArrayKind::from_type_name(type_tag)?;
        match key {
            "set" => Some(BuiltinFunction::typed_array_set()),
            "subarray" => Some(BuiltinFunction::typed_array_subarray()),
            "slice" => Some(BuiltinFunction::typed_array_slice()),
            "fill" => Some(BuiltinFunction::typed_array_fill()),
            "copyWithin" => Some(BuiltinFunction::typed_array_copy_within()),
            "entries" => Some(BuiltinFunction::typed_array_entries()),
            "keys" => Some(BuiltinFunction::typed_array_keys()),
            "values" => Some(BuiltinFunction::typed_array_values()),
            method if TYPED_ARRAY_METHODS.contains(&method) => Some(BuiltinFunction {
                kind: BuiltinFunctionKind::TypedArrayMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                iterator_handle: None,
                bound_object: None,
            }),
            // ES2020 22.2.3: these behave as their Array.prototype namesakes
            // over the typed array's elements (%TypedArray%.prototype.toString
            // is Array.prototype.toString itself). Every one of them used to
            // throw "unsupported TypedArray method". They are distinct
            // functions that first ValidateTypedArray(this): the specifier
            // marks them for that check in dispatch.
            "toString" => Self::array_prototype_method(key),
            "join" | "indexOf" | "lastIndexOf" | "includes" | "at" | "forEach" | "reduce"
            | "reduceRight" | "find" | "findIndex" | "findLast" | "findLastIndex" | "some"
            | "every" | "toLocaleString" => {
                Self::array_prototype_method(key).map(|builtin| BuiltinFunction {
                    module_specifier: BuiltinModuleSpecifier::from_nonempty(
                        TYPED_ARRAY_PROTOTYPE_SPECIFIER,
                    ),
                    ..builtin
                })
            }
            _ => None,
        }
    }

    pub(super) fn buffer_prototype_method(key: &str) -> Option<BuiltinFunction> {
        let kind = match key {
            "toString" => BuiltinFunctionKind::BufferToString,
            "slice" | "subarray" => BuiltinFunctionKind::BufferSharedSlice,
            "indexOf" => BuiltinFunctionKind::BufferIndexOf,
            "includes" => BuiltinFunctionKind::BufferIncludes,
            "equals" => BuiltinFunctionKind::BufferEquals,
            "compare" => BuiltinFunctionKind::BufferCompare,
            "readUInt8" => BuiltinFunctionKind::BufferReadUInt8,
            "writeUInt8" => BuiltinFunctionKind::BufferWriteUInt8,
            "readUInt16LE" => BuiltinFunctionKind::BufferReadUInt16Le,
            "readUInt16BE" => BuiltinFunctionKind::BufferReadUInt16Be,
            "writeUInt16LE" => BuiltinFunctionKind::BufferWriteUInt16Le,
            "writeUInt16BE" => BuiltinFunctionKind::BufferWriteUInt16Be,
            "readInt32LE" => BuiltinFunctionKind::BufferReadInt32Le,
            "readInt32BE" => BuiltinFunctionKind::BufferReadInt32Be,
            "writeInt32LE" => BuiltinFunctionKind::BufferWriteInt32Le,
            "writeInt32BE" => BuiltinFunctionKind::BufferWriteInt32Be,
            "readUInt32LE" => BuiltinFunctionKind::BufferReadUInt32Le,
            "readUInt32BE" => BuiltinFunctionKind::BufferReadUInt32Be,
            "writeUInt32LE" => BuiltinFunctionKind::BufferWriteUInt32Le,
            "writeUInt32BE" => BuiltinFunctionKind::BufferWriteUInt32Be,
            "copy" => BuiltinFunctionKind::BufferCopy,
            "toJSON" => BuiltinFunctionKind::BufferToJson,
            "swap16" => BuiltinFunctionKind::BufferSwap16,
            "swap32" => BuiltinFunctionKind::BufferSwap32,
            "swap64" => BuiltinFunctionKind::BufferSwap64,
            name if BUFFER_NUMERIC_METHODS.contains(&name) => {
                return Some(BuiltinFunction {
                    kind: BuiltinFunctionKind::BufferNumericMethod,
                    module_specifier: BuiltinModuleSpecifier::from_nonempty(name),
                    iterator_handle: None,
                    bound_object: None,
                });
            }
            _ => return None,
        };
        Some(BuiltinFunction::new_kind(kind))
    }

    pub(super) fn object_prototype_method(key: &str) -> Option<BuiltinFunction> {
        match key {
            "hasOwnProperty" => Some(BuiltinFunction::object_has_own_property()),
            "propertyIsEnumerable" => Some(BuiltinFunction::object_property_is_enumerable()),
            "valueOf" => Some(BuiltinFunction::object_value_of()),
            "toString" => Some(BuiltinFunction::object_to_string()),
            "isPrototypeOf" => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ObjectPrototypeIsPrototypeOf,
            )),
            "toLocaleString" => Some(BuiltinFunction::new_kind(
                BuiltinFunctionKind::ObjectPrototypeToLocaleString,
            )),
            method if object_integrity::LEGACY_ACCESSOR_METHODS.contains(&method) => {
                Some(BuiltinFunction {
                    kind: BuiltinFunctionKind::ObjectLegacyAccessor,
                    module_specifier: BuiltinModuleSpecifier::from_nonempty(method),
                    iterator_handle: None,
                    bound_object: None,
                })
            }
            _ => None,
        }
    }

    /// Whether the callable `function` has an intrinsic own `prototype`
    /// (ordinary functions, classes, generators, constructors) as opposed to
    /// one a program defined on it.
    pub(super) fn function_has_intrinsic_prototype(&self, function: &Value) -> bool {
        // Generated functions own an ordinary descriptor on their backing
        // object, so writes, defineProperty and freeze use that authority.
        !matches!(function, Value::BuiltinFunction(builtin)
            if builtin.kind == BuiltinFunctionKind::GeneratedFunction)
            && self.object_own_property_contains(function, &Value::str("prototype"))
    }

    pub(super) fn object_own_property_contains(&self, receiver: &Value, property: &Value) -> bool {
        let property_key = self.executable_property_key_from_value(property);
        if self
            .validate_executable_property_key(&property_key)
            .is_err()
        {
            return false;
        }
        if let Some(key) = property_key.as_str() {
            match receiver {
                Value::Function(_) => return matches!(key, "name" | "length" | "prototype"),
                Value::Closure(closure_id) => {
                    // Concise methods and arrow functions have no `prototype`.
                    return if self.closure_method_metadata.contains_key(closure_id)
                        || self.arrow_lexical_this.contains_key(closure_id)
                    {
                        matches!(key, "name" | "length")
                    } else {
                        matches!(key, "name" | "length" | "prototype")
                    };
                }
                Value::GeneratorFunction(_) | Value::AsyncGeneratorFunction(_) => {
                    return matches!(key, "name" | "length" | "prototype");
                }
                Value::AsyncFunction(_) => return matches!(key, "name" | "length"),
                // bd-9vouw.17: every standard constructor but Proxy has an own
                // `prototype` (ES2020 26.2.2), as do Date and Promise.
                Value::BuiltinFunction(builtin) if key == "prototype" => {
                    if builtin.kind == BuiltinFunctionKind::GeneratedFunction {
                        return true;
                    }
                    if Self::materialized_global_prototype_name(builtin).is_some() {
                        return true;
                    }
                    if builtin.kind == BuiltinFunctionKind::StandardConstructor {
                        return Self::standard_constructor_name(builtin)
                            .is_ok_and(|name| name != "Proxy");
                    }
                }
                _ => {}
            }
        }
        // A string primitive's own properties are its indices and `length`
        // (ToObject(this) in Object.prototype.hasOwnProperty).
        if let (Value::Str(text), Some(key)) = (receiver, property_key.as_str()) {
            return Self::string_own_property_value(text, key).is_some();
        }
        let Value::Object(object_id) = receiver else {
            return false;
        };
        if property_key
            .as_str()
            .is_some_and(|key| self.string_wrapper_own_property(*object_id, key).is_some())
        {
            return true;
        }
        if let RuntimePropertyKey::String(key) = &property_key
            && !self.own_runtime_property_visible(*object_id, key)
        {
            return false;
        }
        self.heap
            .get(object_id.0 as usize)
            .map(|object| object.contains_own_runtime_property(&property_key))
            .unwrap_or(false)
            || self
                .canonical_prototype_virtual_property(*object_id, &property_key)
                .is_some()
            // A built-in prototype's accessor (`Map.prototype.size`) is its
            // own property, as [[HasProperty]] already finds (bd-9vouw.249).
            || self
                .prototype_getter_at(*object_id, &property_key)
                .is_some()
    }

    pub(super) fn object_own_property_is_enumerable(
        &self,
        receiver: &Value,
        property: &Value,
    ) -> bool {
        if matches!(receiver, Value::BuiltinFunction(builtin)
            if builtin.kind == BuiltinFunctionKind::GeneratedFunction)
            && matches!(property, Value::Str(name) if name.as_str() == Some("prototype"))
        {
            return false;
        }
        if matches!(receiver, Value::Function(_) | Value::Closure(_)) {
            // Function `name`/`prototype` are virtual non-enumerable own
            // properties; concise methods expose only `name`.
            return false;
        }
        if let Value::Object(object_id) = receiver {
            match self.executable_property_key_from_value(property) {
                RuntimePropertyKey::String(key) => {
                    return self.ordinary_own_string_key_is_enumerable(*object_id, &key);
                }
                // A Symbol-keyed property's [[Enumerable]] decides too: it was
                // reported enumerable whenever it existed, so
                // `Set.prototype.propertyIsEnumerable(Symbol.toStringTag)`
                // was true (Test262 verifyProperty on @@toStringTag).
                // A virtual one (%Array.prototype%[@@iterator]) is not
                // enumerable: only a stored property can be.
                key @ RuntimePropertyKey::Symbol(_) => {
                    return self.heap.get(object_id.0 as usize).is_some_and(|object| {
                        object.contains_own_runtime_property(&key)
                            && object.own_property_attributes(&key).enumerable
                    });
                }
            }
        }
        self.object_own_property_contains(receiver, property)
    }

    /// Object.prototype.valueOf (ES2020 19.1.3.7): ToObject(this) — the
    /// object itself, a wrapper object included; a new wrapper object for a
    /// primitive (`typeof Object.prototype.valueOf.call(true)` is "object");
    /// a TypeError for undefined and null. Primitives came back unwrapped
    /// and undefined/null did not throw.
    pub(super) fn object_prototype_value_of_value(
        &mut self,
        receiver: Value,
    ) -> Result<Value, InterpreterError> {
        match receiver {
            Value::Undefined | Value::Null => Err(InterpreterError::TypeError {
                expected: "object-coercible this for Object.prototype.valueOf".to_string(),
                got: receiver.type_name().to_string(),
            }),
            Value::Bool(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::Str(_)
            | Value::Symbol(_)
            | Value::BigInt(_) => Ok(Value::Object(self.alloc_primitive_wrapper(receiver)?)),
            other => Ok(other),
        }
    }

    pub(super) fn object_prototype_to_string_value(&self, receiver: &Value) -> Value {
        if let Value::Iterator(handle) = receiver {
            let tag = match self.iterator_intrinsic_prototype_name(*handle) {
                MAP_ITERATOR_PROTOTYPE => "Map Iterator",
                SET_ITERATOR_PROTOTYPE => "Set Iterator",
                _ => "Array Iterator",
            };
            return Value::str(format!("[object {tag}]"));
        }
        let Value::Object(object_id) = receiver else {
            return Value::str(Self::value_to_object_to_string_tag(receiver));
        };
        if let Some(tag) = self.data_to_string_tag(*object_id) {
            return Value::str(format!("[object {tag}]"));
        }
        Value::str(format!(
            "[object {}]",
            self.object_to_string_tag(*object_id)
        ))
    }

    /// Object.prototype.toString called as a function (ES2024 20.1.3.6):
    /// the builtinTag from the receiver's kind (IsArray looks through a
    /// Proxy, and a revoked one is a TypeError), then Get(O, @@toStringTag)
    /// on the receiver (a primitive reads its prototype's), whose String
    /// value replaces the builtinTag. Only an object whose first tag was an
    /// accessor read it (bd-9vouw.93); a function's, a primitive's, an
    /// iterator's, generator's or promise's tag was fixed by its kind, so an
    /// own `fn[Symbol.toStringTag]`, a deleted `Promise.prototype` tag or a
    /// Proxy's target were not seen (bd-9vouw.270).
    pub(super) fn object_prototype_to_string_with_getters(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
    ) -> Result<Value, InterpreterError> {
        let builtin_tag = match receiver {
            Value::Undefined => return Ok(Value::str("[object Undefined]")),
            Value::Null => return Ok(Value::str("[object Null]")),
            Value::Bool(_) => "Boolean",
            Value::Int(_) | Value::Float(_) => "Number",
            Value::Str(_) => "String",
            Value::Object(object_id) if self.active_proxy_record(*object_id)?.is_some() => {
                if self.generic_is_array(*object_id)? {
                    "Array"
                } else {
                    "Object"
                }
            }
            // Typed arrays have no builtinTag of their own: theirs comes
            // from the %TypedArray.prototype% getter.
            Value::Object(object_id)
                if self
                    .heap
                    .get(object_id.0 as usize)
                    .is_some_and(|object| object.typed_array.is_some()) =>
            {
                "Object"
            }
            Value::Object(object_id) => self.object_to_string_tag(*object_id),
            callable if callable.is_callable() => "Function",
            _ => "Object",
        };
        // Guest code (a tag getter, a proxy trap) runs while native locals
        // hold values: no collection until this returns.
        self.gc_nested_request = None;
        let key = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
        Ok(match self.get_v(module, receiver, &key)? {
            Value::Str(tag) => Value::str(format!("[object {tag}]")),
            _ => Value::str(format!("[object {builtin_tag}]")),
        })
    }

    /// ES2020 19.1.3.6 steps 15-16: a String-valued @@toStringTag found on
    /// the object or its prototype chain replaces the builtinTag (`Math`,
    /// `JSON`, transpiled ES modules' `Symbol.toStringTag: 'Module'`, a
    /// class's own `static [Symbol.toStringTag] = ...`). It was ignored, so
    /// `String(Math)` was "[object Object]". Only data properties are read:
    /// an accessor would need a guest call, and keeps the builtinTag.
    pub(super) fn data_to_string_tag(&self, object_id: ObjectId) -> Option<String> {
        let to_string_tag = core_symbol_id(WellKnownSymbol::ToStringTag.id());
        let mut current = Some(object_id);
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let id = current?;
            let object = self.heap.get(id.0 as usize)?;
            match object.properties.baseline_symbol_property(to_string_tag) {
                Some(BaselineSymbolProperty::Data(Value::Str(tag))) => {
                    return Some(tag.to_string());
                }
                Some(_) => return None,
                None => {}
            }
            current = self.observable_prototype_of(id);
        }
        None
    }

    /// ES2020 19.1.3.6: the builtinTag of an object from its internal slots
    /// (Array, Error, Date, RegExp) or, for objects whose prototype supplies a
    /// standard @@toStringTag (Map, Set, WeakMap, WeakSet, ArrayBuffer,
    /// DataView, typed arrays), that tag. Every object used to answer
    /// "[object Object]" (only arrays were told apart), so type checks such as
    /// `Object.prototype.toString.call(d) === '[object Date]'` failed and
    /// isPlainObject-style checks accepted Dates and Maps. Error objects have
    /// no [[ErrorData]] brand here, so an Error is an object whose prototype
    /// chain reaches a built-in Error prototype. A data @@toStringTag takes
    /// precedence ([`Self::data_to_string_tag`]). Not modelled: a guest-defined
    /// @@toStringTag getter.
    pub(super) fn object_to_string_tag(&self, object_id: ObjectId) -> &'static str {
        let Some(object) = self.heap.get(object_id.0 as usize) else {
            return "Object";
        };
        if object.is_array {
            return "Array";
        }
        // These tags are no builtinTag but the @@toStringTag data property of
        // the kind's prototype (ES2020 23.1.3.13, 24.1.4.4, ...), which
        // [`Self::data_to_string_tag`] has already looked for along the
        // object's chain. Once that prototype exists and the object's link is
        // explicit, finding none there means it was deleted or bypassed
        // (`delete WeakSet.prototype[Symbol.toStringTag]`, a null prototype):
        // "Object", not the kind (bd-9vouw.93). Before that nothing can have
        // changed it.
        let prototype_tag = |tag: &'static str| -> &'static str {
            if (object.prototype.is_some() || object.is_null_prototype)
                && self.builtin_prototypes.contains_key(tag)
            {
                "Object"
            } else {
                tag
            }
        };
        match object.primitive_value.as_deref() {
            Some(Value::Bool(_)) => return "Boolean",
            Some(Value::Int(_) | Value::Float(_)) => return "Number",
            Some(Value::Str(_)) => return "String",
            Some(Value::BigInt(_)) => return prototype_tag("BigInt"),
            Some(Value::Symbol(_)) => return prototype_tag("Symbol"),
            _ => {}
        }
        if let Some(view) = &object.typed_array {
            return view.kind.type_name();
        }
        if object.data_view.is_some() {
            return prototype_tag("DataView");
        }
        if object.array_buffer.is_some() {
            return prototype_tag(if object.brand() == Some("SharedArrayBuffer") {
                "SharedArrayBuffer"
            } else {
                "ArrayBuffer"
            });
        }
        if let Some(type_tag) = object.brand() {
            match type_tag {
                "Date" => return "Date",
                "RegExp" => return "RegExp",
                "Arguments" => return "Arguments",
                "Map" => return prototype_tag("Map"),
                "Set" => return prototype_tag("Set"),
                "WeakMap" => return prototype_tag("WeakMap"),
                "WeakSet" => return prototype_tag("WeakSet"),
                "WeakRef" => return prototype_tag("WeakRef"),
                "FinalizationRegistry" => return prototype_tag("FinalizationRegistry"),
                _ => {}
            }
        }
        let error_prototypes = ERROR_PROTOTYPE_NAMES
            .iter()
            .filter_map(|name| self.builtin_prototypes.get(*name).copied())
            .collect::<Vec<_>>();
        // The NativeError prototypes are ordinary objects (ES2020
        // 19.5.6.3), not Error instances, although their chains reach
        // Error.prototype: `TypeError.prototype` is "[object Object]".
        if error_prototypes.contains(&object_id) {
            return "Object";
        }
        let mut current = object.prototype;
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(prototype) = current else {
                break;
            };
            if error_prototypes.contains(&prototype) {
                return "Error";
            }
            current = self
                .heap
                .get(prototype.0 as usize)
                .and_then(|next| next.prototype);
        }
        "Object"
    }

    /// Storage key for a Map key / Set value (bd-juodx). Every Map/Set path,
    /// including the `builtin:Map*`/`Set*` hostcalls, keys storage through
    /// this one function.
    ///
    /// The encoding is injective over SameValueZero classes:
    /// - `-0` and `+0` share `n:0`, and `1` and `1.0` share `n:1`;
    /// - Symbols, functions, closures, generators and Promises key by identity;
    /// - BigInts key by value;
    /// - strings with lone surrogates key by their exact UTF-16 code units.
    ///
    /// [`Self::collection_key_from_repr`] inverts it, so Map iteration returns
    /// the original keys.
    pub(super) fn collection_key_repr(value: &Value) -> String {
        match value {
            Value::Str(s) => match s.as_str() {
                Some(text) => format!("s:{text}"),
                None => {
                    let units: Vec<String> =
                        s.encode_utf16().map(|unit| format!("{unit:04x}")).collect();
                    format!("u:{}", units.join(","))
                }
            },
            Value::Int(i) => format!("n:{i}"),
            Value::Float(f) if f.inner() == 0.0 => "n:0".to_string(),
            Value::Float(f) => format!("n:{}", f.inner()),
            Value::Bool(b) => format!("b:{b}"),
            Value::Null => "null".to_string(),
            Value::Undefined => "undefined".to_string(),
            Value::Object(id) => format!("o:{}", id.0),
            Value::BigInt(digits) => format!("B:{digits}"),
            Value::Symbol(symbol) => format!("y:{}", symbol.0),
            Value::Function(index) => format!("F:{index}"),
            Value::Closure(index) => format!("c:{index}"),
            Value::Iterator(index) => format!("i:{index}"),
            Value::GeneratorFunction(index) => format!("gf:{index}"),
            Value::Generator(index) => format!("g:{index}"),
            Value::AsyncFunction(index) => format!("af:{index}"),
            Value::AsyncFunctionObject(index) => format!("ao:{index}"),
            Value::AsyncGeneratorFunction(index) => format!("agf:{index}"),
            Value::AsyncGeneratorObject(index) => format!("ag:{index}"),
            Value::Promise(index) => format!("p:{index}"),
            Value::BuiltinFunction(builtin) => serde_json::to_string(builtin)
                .map(|json| format!("bf:{json}"))
                .unwrap_or_else(|_| "other".to_string()),
            // Accessor records are internal descriptor payloads, never
            // JavaScript values.
            Value::Accessor { .. } => "other".to_string(),
        }
    }

    /// Set.prototype.add and Map.prototype.set store -0 as +0 (ES2020
    /// 23.2.3.1 step 4, 23.1.3.9 step 5). Map keys round-trip through
    /// [`Self::collection_key_repr`], which already maps -0 to `n:0`; Set
    /// members are stored as values and need the conversion explicitly.
    pub(super) fn collection_canonical_member(value: Value) -> Value {
        match value {
            Value::Float(number) if number.inner() == 0.0 => Value::Int(0),
            other => other,
        }
    }

    /// Invert [`Self::collection_key_repr`] for iteration.
    pub(super) fn collection_key_from_repr(repr: &str) -> Value {
        let Some((tag, payload)) = repr.split_once(':') else {
            return match repr {
                "null" => Value::Null,
                _ => Value::Undefined,
            };
        };
        let index = || payload.parse::<u32>().ok();
        let decoded = match tag {
            "s" => Some(Value::str(payload)),
            "u" => payload
                .split(',')
                .map(|unit| u16::from_str_radix(unit, 16).ok())
                .collect::<Option<Vec<u16>>>()
                .map(|units| Value::Str(JsString::from_code_units(&units))),
            "n" => Some(match payload.parse::<i64>() {
                Ok(int) => Value::Int(int),
                Err(_) => js_number_to_value(payload.parse::<f64>().unwrap_or(f64::NAN)),
            }),
            "b" => Some(Value::Bool(payload == "true")),
            "o" => index().map(|id| Value::Object(ObjectId(id))),
            "B" => Some(Value::BigInt(Arc::from(payload))),
            "y" => index().map(|id| Value::Symbol(SymbolId(id))),
            "F" => index().map(Value::Function),
            "c" => index().map(Value::Closure),
            "i" => index().map(Value::Iterator),
            "gf" => index().map(Value::GeneratorFunction),
            "g" => index().map(Value::Generator),
            "af" => index().map(Value::AsyncFunction),
            "ao" => index().map(Value::AsyncFunctionObject),
            "agf" => index().map(Value::AsyncGeneratorFunction),
            "ag" => index().map(Value::AsyncGeneratorObject),
            "p" => index().map(Value::Promise),
            "bf" => serde_json::from_str(payload)
                .ok()
                .map(Value::BuiltinFunction),
            _ => None,
        };
        decoded.unwrap_or(Value::Undefined)
    }

    /// Iteration snapshot of a Map (`[key, value]` pairs) or a Set (values),
    /// in insertion order, or `None` for any other object. Backs `for...of`,
    /// array spread and `Array.from` over collections, which previously failed
    /// with "expected callable Symbol.iterator method".
    pub(super) fn collection_iteration_values(
        &mut self,
        object_id: ObjectId,
    ) -> Result<Option<Vec<Value>>, InterpreterError> {
        if let Some(values_id) = self.collection_storage_id(object_id, "Set") {
            let values = self
                .heap
                .get(values_id.0 as usize)
                .map(|storage| storage.properties.values().cloned().collect())
                .unwrap_or_default();
            return Ok(Some(values));
        }
        let Some(entries_id) = self.collection_storage_id(object_id, "Map") else {
            return Ok(None);
        };
        let entries: Vec<(String, Value)> = self
            .heap
            .get(entries_id.0 as usize)
            .map(|storage| {
                storage
                    .properties
                    .iter()
                    .map(|(repr, value)| (repr.to_string(), value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        let mut pairs = Vec::with_capacity(entries.len());
        for (repr, value) in entries {
            let pair =
                self.alloc_array_from_values(&[Self::collection_key_from_repr(&repr), value])?;
            pairs.push(Value::Object(pair));
        }
        Ok(Some(pairs))
    }

    /// The receiver's collection storage, gated on its private brand. Map
    /// and Set never consult guest properties for their backing object.
    /// WeakMap/WeakSet use the private weak side table instead of heap storage.
    pub(super) fn collection_storage_id(
        &self,
        obj_id: ObjectId,
        type_tag: &str,
    ) -> Option<ObjectId> {
        let obj = self.heap.get(obj_id.0 as usize)?;
        if obj.brand() != Some(type_tag) {
            return None;
        }
        match type_tag {
            "Map" | "Set" => obj.collection_storage.as_deref().copied(),
            "FinalizationRegistry" => match obj.properties.get("__tokens") {
                Some(Value::Object(id)) => Some(*id),
                _ => None,
            },
            _ => None,
        }
    }

    /// Publish a private Map/Set backing edge after charging its allocation.
    /// A collection's integrity level governs its ordinary properties only.
    pub(super) fn set_collection_storage(
        &mut self,
        obj_id: ObjectId,
        storage_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        let object = self
            .heap
            .get(obj_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: obj_id.0 })?;
        if !matches!(object.brand(), Some("Map" | "Set")) {
            return Err(InterpreterError::TypeError {
                expected: "Map or Set receiver for private collection storage".to_string(),
                got: "object".to_string(),
            });
        }
        let previous_bytes = object
            .collection_storage
            .as_ref()
            .map_or(0, |_| std::mem::size_of::<ObjectId>() as u64);
        if self.heap.get(storage_id.0 as usize).is_none() {
            return Err(InterpreterError::ObjectNotFound { id: storage_id.0 });
        }
        self.apply_memory_component_delta(previous_bytes, std::mem::size_of::<ObjectId>() as u64)?;
        self.mutate_heap(|heap| {
            let storage = &mut heap[obj_id.0 as usize].collection_storage;
            match storage.as_deref_mut() {
                Some(current) => *current = storage_id,
                None => *storage = Some(Box::new(storage_id)),
            }
        });
        self.gc_write_barrier(obj_id);
        Ok(())
    }

    pub(super) fn collection_size(&self, obj_id: ObjectId, type_tag: &str) -> Option<usize> {
        self.collection_storage_id(obj_id, type_tag)
            .and_then(|storage| self.heap.get(storage.0 as usize))
            .map(|storage| storage.properties.len())
    }

    /// ES2020 23.1.3 / 23.2.3: every Map and Set method requires a receiver
    /// with the matching [[MapData]] / [[SetData]] slot and throws a TypeError
    /// otherwise. `has`/`get`/`delete`/`clear` used to answer `false` or
    /// `undefined` for any other receiver, and `set`/`add` silently did
    /// nothing on a plain object.
    pub(super) fn collection_receiver(
        &self,
        receiver: &Value,
        type_tag: &str,
        method: &str,
    ) -> Result<ObjectId, InterpreterError> {
        match receiver {
            Value::Object(id) if self.collection_storage_id(*id, type_tag).is_some() => Ok(*id),
            other => Err(InterpreterError::TypeError {
                expected: format!("{type_tag} receiver for {type_tag}.prototype.{method}"),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn map_collection_set(
        &mut self,
        map_id: ObjectId,
        key: Value,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        if let Some(entries_id) = self.collection_storage_id(map_id, "Map") {
            let repr = Self::collection_key_repr(&key);
            self.set_object_property(entries_id, repr, value)?;
        }
        Ok(Value::Object(map_id))
    }

    /// A new empty Map: the object and its entry storage.
    pub(super) fn alloc_empty_map(&mut self) -> Result<(ObjectId, ObjectId), InterpreterError> {
        let prototype = self.ensure_builtin_prototype("Map")?;
        let map_id = self.alloc_object_with_prototype(Some(prototype))?;
        let entries_id = self.alloc_object_with_prototype(None)?;
        self.set_object_brand(map_id, "Map")?;
        self.set_collection_storage(map_id, entries_id)?;
        Ok((map_id, entries_id))
    }

    /// ES2024 Object.groupBy / Map.groupBy (GroupBy, 7.3.35): the values of
    /// `items` (iterated like Array.from's source; undefined and null throw)
    /// grouped by `callbackfn(value, index)`, in first-seen order of the
    /// keys. Object.groupBy keys by ToPropertyKey into a null-prototype
    /// object of arrays; Map.groupBy keys by SameValueZero into a Map of
    /// arrays. Every item is read before the first callback runs.
    pub(super) fn group_by_builtin(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
        into_map: bool,
    ) -> Result<Value, InterpreterError> {
        let items = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let callback = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        if matches!(items, Value::Undefined | Value::Null) {
            return Err(InterpreterError::TypeError {
                expected: "object-coercible items for groupBy".to_string(),
                got: items.type_name().to_string(),
            });
        }
        if !callback.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable groupBy callback".to_string(),
                got: callback.type_name().to_string(),
            });
        }
        let list = self.iterable_to_array(
            module,
            RegRange {
                start: args.start,
                count: args.count.min(1),
            },
        )?;
        let Value::Object(list_id) = list else {
            return Err(InterpreterError::InternalError {
                details: "groupBy item list is not an array".to_string(),
            });
        };
        let values = self.array_like_values(list_id)?;
        let mut groups: Vec<(String, Value, Vec<Value>)> = Vec::new();
        for (index, value) in values.into_iter().enumerate() {
            let (key, _) = self.invoke_inline_method_call_with_argument_label(
                module,
                callback.clone(),
                Value::Undefined,
                vec![
                    value.clone(),
                    Value::Int(i64::try_from(index).unwrap_or(i64::MAX)),
                ],
                None,
            )?;
            let key = if into_map {
                Self::collection_canonical_member(key)
            } else {
                self.coerce_runtime_property_key(module, key)?
            };
            let identity = Self::collection_key_repr(&key);
            match groups
                .iter_mut()
                .find(|(existing, ..)| *existing == identity)
            {
                Some((_, _, members)) => members.push(value),
                None => groups.push((identity, key, vec![value])),
            }
        }
        if into_map {
            let (map_id, _) = self.alloc_empty_map()?;
            for (_, key, members) in groups {
                let array = self.alloc_array_from_values(&members)?;
                self.map_collection_set(map_id, key, Value::Object(array))?;
            }
            return Ok(Value::Object(map_id));
        }
        let object = self.alloc_object_with_prototype(None)?;
        self.store_prototype_link(object, None);
        for (_, key, members) in groups {
            let array = self.alloc_array_from_values(&members)?;
            let key = self.executable_property_key_from_value(&key);
            self.set_object_runtime_property(object, key, Value::Object(array))?;
        }
        Ok(Value::Object(object))
    }

    pub(super) fn set_collection_add(
        &mut self,
        set_id: ObjectId,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        let value = Self::collection_canonical_member(value);
        if let Some(values_id) = self.collection_storage_id(set_id, "Set") {
            let repr = Self::collection_key_repr(&value);
            self.set_object_property(values_id, repr, value)?;
        }
        Ok(Value::Object(set_id))
    }

    pub(super) fn collection_get(&self, obj_id: ObjectId, type_tag: &str, key: &Value) -> Value {
        if let Some(storage_id) = self.collection_storage_id(obj_id, type_tag)
            && let Some(storage) = self.heap.get(storage_id.0 as usize)
            && let Some(v) = storage.properties.get(&Self::collection_key_repr(key))
        {
            return v.clone();
        }
        Value::Undefined
    }

    pub(super) fn collection_has(&self, obj_id: ObjectId, type_tag: &str, key: &Value) -> bool {
        self.collection_storage_id(obj_id, type_tag)
            .and_then(|sid| self.heap.get(sid.0 as usize))
            .map(|storage| {
                storage
                    .properties
                    .contains_key(&Self::collection_key_repr(key))
            })
            .unwrap_or(false)
    }

    pub(super) fn collection_delete(
        &mut self,
        obj_id: ObjectId,
        type_tag: &str,
        key: &Value,
    ) -> Result<bool, InterpreterError> {
        let Some(storage_id) = self.collection_storage_id(obj_id, type_tag) else {
            return Ok(false);
        };
        let repr = Self::collection_key_repr(key);
        // Live iterators and forEach walks past the removed entry move back
        // (bd-9vouw.131). A forEach walk has no iterator: counting only
        // iterators skipped the entry after one its callback deleted
        // (bd-9vouw.314).
        let tracked = self.collection_iterators.contains_key(&storage_id)
            || self
                .collection_for_each_cursors
                .iter()
                .any(|(cursor_storage, _)| *cursor_storage == storage_id);
        let position = tracked
            .then(|| {
                self.heap
                    .get(storage_id.0 as usize)
                    .and_then(|storage| storage.properties.insertion_key_position(&repr))
            })
            .flatten();
        let removed = self.remove_object_property(storage_id, &repr)?;
        if removed && let Some(position) = position {
            self.collection_entry_removed(storage_id, position);
        }
        Ok(removed)
    }

    /// `Map.prototype.clear` / `Set.prototype.clear` (bd-juodx): empties the
    /// internal storage object and resets `size` to 0; returns `undefined`. The
    /// storage object holds only entries, so clearing all its properties is
    /// exactly the contents reset.
    pub(super) fn collection_clear(
        &mut self,
        obj_id: ObjectId,
        type_tag: &str,
    ) -> Result<Value, InterpreterError> {
        if let Some(storage_id) = self.collection_storage_id(obj_id, type_tag) {
            self.clear_object_properties(storage_id)?;
            self.collection_storage_cleared(storage_id);
        }
        Ok(Value::Undefined)
    }

    /// Walk the prototype chain to find a property descriptor.
    /// Unlike getOwnPropertyDescriptor, this traverses the entire prototype chain.
    pub(super) fn prototype_chain_get_property_descriptor(
        &mut self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Result<Value, InterpreterError> {
        self.validate_executable_property_key(key)?;
        let mut current = Some(object_id);
        let mut depth = 0u32;
        let mut visited = ChainGuard::default();

        while let Some(id) = current {
            if depth >= MAX_PROTOTYPE_CHAIN_DEPTH || !visited.insert(id) {
                // Deterministic decision: fold, don't record (bd-9vouw.18).
                self.nondeterminism_trace.witness_deterministic(
                    NondeterminismSource::PropertyResolution,
                    format!(
                        "descriptor_chain_limit_reached:key={},depth={}",
                        key.diagnostic(),
                        depth
                    )
                    .as_bytes(),
                );
                return Ok(Value::Undefined);
            }

            let (descriptor_source, next_prototype) = {
                let object = self
                    .heap
                    .get(id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
                let visible = match key {
                    RuntimePropertyKey::String(key) => self.own_runtime_property_visible(id, key),
                    RuntimePropertyKey::Symbol(_) => true,
                };
                (
                    visible
                        .then(|| object.own_runtime_property_value(key))
                        .flatten(),
                    object.prototype,
                )
            };

            if descriptor_source.is_some() {
                let descriptor = self.own_property_descriptor_value(id, key)?;

                // Deterministic decision: fold, don't record (bd-9vouw.18).
                self.nondeterminism_trace.witness_deterministic(
                    NondeterminismSource::PropertyResolution,
                    format!(
                        "descriptor_found:key={},object_id={},depth={}",
                        key.diagnostic(),
                        id.0,
                        depth
                    )
                    .as_bytes(),
                );

                return Ok(descriptor);
            }

            current = next_prototype;
            depth += 1;
        }

        // Deterministic decision: fold, don't record (bd-9vouw.18).
        self.nondeterminism_trace.witness_deterministic(
            NondeterminismSource::PropertyResolution,
            format!(
                "descriptor_not_found:key={},final_depth={}",
                key.diagnostic(),
                depth
            )
            .as_bytes(),
        );
        Ok(Value::Undefined)
    }

    /// ES2020 19.1.2.3.1 ObjectDefineProperties, shared by
    /// `Object.defineProperties` and `Object.create`: every enumerable own
    /// descriptor is read and validated before any property is defined.
    pub(super) fn object_define_properties(
        &mut self,
        module: Option<&Ir3Module>,
        target_id: ObjectId,
        properties_arg: Value,
        caller: &str,
    ) -> Result<(), InterpreterError> {
        let properties_id = match properties_arg {
            Value::Object(properties_id) => properties_id,
            Value::Undefined | Value::Null => {
                return Err(InterpreterError::TypeError {
                    expected: format!("object-coercible {caller} properties"),
                    got: properties_arg.type_name().to_string(),
                });
            }
            // ToObject(string) has an enumerable own index property per
            // code unit, a string, which ToPropertyDescriptor rejects
            // (bd-9vouw.235); the other primitives have no enumerable own
            // keys to define.
            Value::Str(text) if text.utf16_len() > 0 => {
                return Err(InterpreterError::TypeError {
                    expected: format!("object property descriptors for {caller}"),
                    got: "string".to_string(),
                });
            }
            _ => return Ok(()),
        };
        let keys = self
            .heap
            .get(properties_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound {
                id: properties_id.0,
            })?
            .properties
            .exact_keys()
            .into_iter()
            .filter(|key| self.ordinary_own_string_key_is_enumerable(properties_id, key))
            .collect::<Vec<_>>();
        let mut definitions = Vec::with_capacity(keys.len());
        for key in keys {
            let key_text = key.to_string();
            let descriptor_val = self.proxy_aware_get_property(
                module,
                properties_id,
                &key_text,
                Value::Object(properties_id),
                0,
            )?;
            let descriptor = self.read_property_descriptor(module, &descriptor_val)?;
            definitions.push((key, descriptor));
        }
        for (key, mut descriptor) in definitions {
            let prop_name = self.executable_property_key_from_value(&Value::Str(key));
            // ArraySetLength converts a `length` value as defineProperty
            // does (bd-9vouw.338).
            if prop_name.as_str() == Some("length")
                && self
                    .heap
                    .get(target_id.0 as usize)
                    .is_some_and(|object| object.is_array)
                && let Some(value) = descriptor.value.take()
            {
                descriptor.value = Some(self.array_length_definition_value(module, value)?);
            }
            if !self.define_own_property_from_descriptor(target_id, prop_name, descriptor)? {
                return Err(InterpreterError::TypeError {
                    expected: format!("definable property for {caller}"),
                    got: "non-configurable, non-writable or non-extensible target".to_string(),
                });
            }
        }
        Ok(())
    }

    pub(super) fn read_object_argument(
        &self,
        args: RegRange,
        offset: u32,
        expected: &str,
    ) -> Result<ObjectId, InterpreterError> {
        if offset >= args.count {
            return Err(InterpreterError::TypeError {
                expected: expected.to_string(),
                got: "missing argument".to_string(),
            });
        }
        match self.read_reg(args.start + offset)? {
            Value::Object(object_id) => Ok(object_id),
            other => Err(InterpreterError::TypeError {
                expected: expected.to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// ProxyCreate's target (ES2020 9.5.14 step 1): an object, or a function
    /// (bd-9vouw.132), whose own-property storage the proxy record's target
    /// slot then holds, returned with the function itself.
    pub(super) fn read_proxy_target_argument(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
        expected: &str,
    ) -> Result<(ObjectId, Option<Value>), InterpreterError> {
        let target = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };
        if let Value::Object(object_id) = target {
            return Ok((object_id, None));
        }
        if target.is_callable()
            && let Some(storage) = self.own_property_holder(module, &target, true)?
        {
            return Ok((storage, Some(target)));
        }
        Err(InterpreterError::TypeError {
            expected: expected.to_string(),
            got: target.type_name().to_string(),
        })
    }

    /// The value guest code holds for a new proxy: the record itself over an
    /// object target, a callable proxy over a function target.
    pub(super) fn proxy_value(
        &mut self,
        proxy_id: ObjectId,
        call_target: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        let Some(call_target) = call_target else {
            return Ok(Value::Object(proxy_id));
        };
        self.set_object_property(proxy_id, PROXY_CALL_TARGET_SLOT.to_string(), call_target)?;
        Ok(Self::callable_proxy_value(proxy_id))
    }

    /// The callable proxy value of a proxy record over a function.
    pub(super) fn callable_proxy_value(proxy_id: ObjectId) -> Value {
        Value::BuiltinFunction(BuiltinFunction {
            kind: BuiltinFunctionKind::CallableProxy,
            module_specifier: BuiltinModuleSpecifier::default(),
            iterator_handle: None,
            bound_object: Some(proxy_id.0),
        })
    }

    /// Whether `value` is a proxy over a function (bd-9vouw.132).
    pub(super) fn is_callable_proxy(value: &Value) -> bool {
        matches!(
            value,
            Value::BuiltinFunction(builtin) if builtin.kind == BuiltinFunctionKind::CallableProxy
        )
    }

    /// The proxy record of a callable proxy value.
    pub(super) fn callable_proxy_record_id(
        builtin: &BuiltinFunction,
    ) -> Result<ObjectId, InterpreterError> {
        builtin
            .bound_object
            .map(ObjectId)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "callable Proxy record".to_string(),
                got: "missing proxy object".to_string(),
            })
    }

    /// The callable target of a proxy record over a function.
    pub(super) fn proxy_call_target(&self, proxy_id: ObjectId) -> Option<Value> {
        self.heap
            .get(proxy_id.0 as usize)?
            .properties
            .get(PROXY_CALL_TARGET_SLOT)
            .cloned()
    }

    /// The target a trap receives: the function for a callable proxy (whose
    /// target slot holds the function's property storage), else the object.
    pub(super) fn proxy_trap_target(&self, proxy_id: ObjectId, target: ObjectId) -> Value {
        self.proxy_call_target(proxy_id)
            .unwrap_or(Value::Object(target))
    }

    pub(super) fn proxy_record(
        &self,
        object_id: ObjectId,
    ) -> Result<Option<(ObjectId, ObjectId, bool)>, InterpreterError> {
        // Every property access asks; build the error only when it fails.
        let Some(object) = self.heap.get(object_id.0 as usize) else {
            return Err(InterpreterError::ObjectNotFound { id: object_id.0 });
        };
        if object.brand() != Some(PROXY_TYPE_TAG) {
            return Ok(None);
        }

        let target = match object.properties.get(PROXY_TARGET_SLOT) {
            Some(Value::Object(target)) => *target,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "well-formed Proxy target slot".to_string(),
                    got: other.map_or("missing".to_string(), |value| value.type_name().to_string()),
                });
            }
        };
        let handler = match object.properties.get(PROXY_HANDLER_SLOT) {
            Some(Value::Object(handler)) => *handler,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "well-formed Proxy handler slot".to_string(),
                    got: other.map_or("missing".to_string(), |value| value.type_name().to_string()),
                });
            }
        };
        let revoked = matches!(
            object.properties.get(PROXY_REVOKED_SLOT),
            Some(Value::Bool(true))
        );
        Ok(Some((target, handler, revoked)))
    }

    /// The TypeError a strict-code write throws when [[Set]] returns false
    /// (ES2020 6.2.4.9 step 6.d), naming why: a Proxy's falsy set trap, a
    /// frozen object, a non-extensible object without the property, or a
    /// read-only property. Since sloppy writes fail silently (bd-9vouw.146),
    /// [[Set]] reports false instead of erring, and every strict failure read
    /// as a Proxy trap's.
    pub(super) fn rejected_strict_set_error(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> InterpreterError {
        let type_error = |expected: &str, got: &str| InterpreterError::TypeError {
            expected: expected.to_string(),
            got: got.to_string(),
        };
        if matches!(self.proxy_record(object_id), Ok(Some(_))) {
            return type_error("successful Proxy set trap", "falsy set trap result");
        }
        match self.heap.get(object_id.0 as usize) {
            Some(object) if object.is_frozen => type_error("mutable object", "frozen object"),
            Some(object) if !object.extensible() && !object.contains_own_runtime_property(key) => {
                type_error("existing property on non-extensible object", "new property")
            }
            _ => type_error("writable property", "read-only property"),
        }
    }

    pub(super) fn active_proxy_record(
        &self,
        object_id: ObjectId,
    ) -> Result<Option<(ObjectId, ObjectId)>, InterpreterError> {
        match self.proxy_record(object_id)? {
            Some((_target, _handler, true)) => Err(InterpreterError::TypeError {
                expected: "active Proxy object".to_string(),
                got: "revoked Proxy".to_string(),
            }),
            Some((target, handler, false)) => Ok(Some((target, handler))),
            None => Ok(None),
        }
    }

    pub(super) fn create_proxy_object(
        &mut self,
        target: ObjectId,
        handler: ObjectId,
    ) -> Result<ObjectId, InterpreterError> {
        let proxy_id = self.alloc_object_with_prototype(None)?;
        self.set_object_brand(proxy_id, PROXY_TYPE_TAG)?;
        self.set_object_property(
            proxy_id,
            PROXY_TARGET_SLOT.to_string(),
            Value::Object(target),
        )?;
        self.set_object_property(
            proxy_id,
            PROXY_HANDLER_SLOT.to_string(),
            Value::Object(handler),
        )?;
        self.set_object_property(proxy_id, PROXY_REVOKED_SLOT.to_string(), Value::Bool(false))?;
        Ok(proxy_id)
    }

    pub(super) fn revoke_proxy_object(
        &mut self,
        proxy_id: ObjectId,
    ) -> Result<(), InterpreterError> {
        if self.proxy_record(proxy_id)?.is_none() {
            return Err(InterpreterError::TypeError {
                expected: "Proxy object".to_string(),
                got: "ordinary object".to_string(),
            });
        }
        self.set_object_property(proxy_id, PROXY_REVOKED_SLOT.to_string(), Value::Bool(true))
    }

    pub(super) fn proxy_trap_value(
        &mut self,
        module: Option<&Ir3Module>,
        handler_id: ObjectId,
        trap_name: &str,
    ) -> Result<Option<Value>, InterpreterError> {
        self.json_charge_work()?;
        let depth = self.proxy_trap_lookup_depth;
        if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
            return Err(InterpreterError::StackOverflow {
                depth: depth as usize,
                max: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
            });
        }
        self.proxy_trap_lookup_depth = depth + 1;
        let result = self.proxy_trap_value_inner(module, handler_id, trap_name);
        self.proxy_trap_lookup_depth = depth;
        result
    }

    pub(super) fn proxy_trap_value_inner(
        &mut self,
        module: Option<&Ir3Module>,
        handler_id: ObjectId,
        trap_name: &str,
    ) -> Result<Option<Value>, InterpreterError> {
        let key = RuntimePropertyKey::String(JsString::from(trap_name));
        if self.active_inline_callback_context_label.is_some() {
            self.reflect_observe_selected_property(handler_id, &key)?;
        }
        let result = self.prototype_chain_get_with_receiver(
            module,
            handler_id,
            trap_name,
            Value::Object(handler_id),
        );
        self.observe_scoped_callback_result()?;
        match result? {
            Value::Undefined | Value::Null => Ok(None),
            trap @ (Value::Function(_) | Value::Closure(_) | Value::BuiltinFunction(_)) => {
                Ok(Some(trap))
            }
            other => Err(InterpreterError::TypeError {
                expected: format!("callable Proxy.{trap_name} trap or undefined"),
                got: other.type_name().to_string(),
            }),
        }
    }

    pub(super) fn invoke_proxy_trap(
        &mut self,
        module: Option<&Ir3Module>,
        handler_id: ObjectId,
        trap_name: &str,
        arguments: Vec<Value>,
    ) -> Result<Option<Value>, InterpreterError> {
        let Some(trap) = self.proxy_trap_value(module, handler_id, trap_name)? else {
            return Ok(None);
        };
        self.call_proxy_trap(module, handler_id, trap_name, trap, arguments)
            .map(Some)
    }

    /// Call a trap already read from the handler (with the handler as
    /// `this`), joining its result label into the pending hostcall result.
    pub(super) fn call_proxy_trap(
        &mut self,
        module: Option<&Ir3Module>,
        handler_id: ObjectId,
        trap_name: &str,
        trap: Value,
        arguments: Vec<Value>,
    ) -> Result<Value, InterpreterError> {
        let module = module.ok_or_else(|| InterpreterError::TypeError {
            expected: format!("module-backed Proxy.{trap_name} trap dispatch"),
            got: "missing module context".to_string(),
        })?;
        let (value, label) = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            trap,
            Value::Object(handler_id),
            arguments,
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

    /// The live record of a callable proxy: its handler and function target
    /// (a revoked proxy is a TypeError).
    pub(super) fn callable_proxy_parts(
        &self,
        builtin: &BuiltinFunction,
    ) -> Result<(ObjectId, ObjectId, Value), InterpreterError> {
        let proxy = Self::callable_proxy_record_id(builtin)?;
        let (_target, handler) =
            self.active_proxy_record(proxy)?
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "callable Proxy record".to_string(),
                    got: "ordinary object".to_string(),
                })?;
        let function =
            self.proxy_call_target(proxy)
                .ok_or_else(|| InterpreterError::TypeError {
                    expected: "callable Proxy target".to_string(),
                    got: "missing target".to_string(),
                })?;
        Ok((proxy, handler, function))
    }

    /// ES2020 9.5.12 [[Call]] of a proxy over a function: the handler's
    /// `apply` trap with (target, thisArgument, CreateArrayFromList(args)),
    /// else a call of the target with the same `this` and arguments
    /// (bd-9vouw.132).
    pub(super) fn call_callable_proxy(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        let (_proxy, handler, function) = self.callable_proxy_parts(builtin)?;
        let this_argument = receiver.unwrap_or(Value::Undefined);
        let mut arguments = Vec::with_capacity(args.count as usize);
        for index in 0..args.count {
            arguments.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
        }
        let label = self.join_arg_range_label(args)?;
        if let Some(trap) = self.proxy_trap_value(Some(module), handler, "apply")? {
            let list = self.alloc_array_from_values(&arguments)?;
            return self.call_proxy_trap(
                Some(module),
                handler,
                "apply",
                trap,
                vec![function, this_argument, Value::Object(list)],
            );
        }
        self.preflight_inline_method_call_with_argument_label(
            Some(module),
            &function,
            arguments.len(),
            Some(&label),
        )?;
        let (result, result_label) = self
            .invoke_inline_method_call_with_argument_label_preflighted(
                Some(module),
                function,
                this_argument,
                arguments,
                Some(label),
            )?;
        self.replace_pending_hostcall_result_label(Some(result_label))?;
        Ok(result)
    }

    /// ES2020 9.5.13 [[Construct]] of a proxy over a function: the target
    /// must be a constructor; the handler's `construct` trap gets (target,
    /// CreateArrayFromList(args), newTarget) and must return an object, else
    /// the target is constructed. No-claim: `new.target` is the target, not
    /// the proxy, when there is no trap (a `get` trap does not see the
    /// `prototype` read of OrdinaryCreateFromConstructor).
    pub(super) fn construct_callable_proxy(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        new_target: Option<Value>,
    ) -> Result<(Value, Label), InterpreterError> {
        // `new P()` passes the proxy itself; Reflect.construct its newTarget.
        let explicit_new_target = new_target.filter(|value| {
            !matches!(value, Value::BuiltinFunction(other)
                if other.kind == BuiltinFunctionKind::CallableProxy
                    && other.bound_object == builtin.bound_object)
        });
        let (_proxy, handler, function) = self.callable_proxy_parts(builtin)?;
        if !self.is_constructible_value(&function) {
            return Err(InterpreterError::TypeError {
                expected: "Proxy with a constructor target".to_string(),
                got: format!("{} is not a constructor", function.type_name()),
            });
        }
        let mut arguments = Vec::with_capacity(args.count as usize);
        for index in 0..args.count {
            arguments.push(self.builtin_arg(args, index)?.unwrap_or(Value::Undefined));
        }
        let label = self.join_arg_range_label(args)?;
        if let Some(trap) = self.proxy_trap_value(Some(module), handler, "construct")? {
            let list = self.alloc_array_from_values(&arguments)?;
            let result = self.call_proxy_trap(
                Some(module),
                handler,
                "construct",
                trap,
                vec![
                    function,
                    Value::Object(list),
                    explicit_new_target.unwrap_or_else(|| Value::BuiltinFunction(builtin.clone())),
                ],
            )?;
            if !result.is_object_like() {
                return Err(InterpreterError::TypeError {
                    expected: "object from the Proxy construct trap".to_string(),
                    got: result.type_name().to_string(),
                });
            }
            return Ok((result, label));
        }
        let target_is_proxy = Self::is_callable_proxy(&function);
        let (value, result_label) = self.invoke_inline_construct_with_labels(
            Some(module),
            function,
            arguments,
            Some(IsolatedCallLabels {
                receiver: Label::Public,
                arguments: IsolatedArgumentLabels::Uniform(label.clone()),
            }),
            // A callable proxy target receives this proxy as newTarget too.
            explicit_new_target
                .or_else(|| target_is_proxy.then(|| Value::BuiltinFunction(builtin.clone())))
                .map(|value| (value, Label::Public)),
        )?;
        Ok((value, result_label.join(&label)))
    }

    pub(super) fn proxy_aware_get_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &str,
        receiver: Value,
        depth: u32,
    ) -> Result<Value, InterpreterError> {
        self.proxy_aware_get_runtime_property(
            module,
            object_id,
            &RuntimePropertyKey::String(JsString::from(key)),
            receiver,
            depth,
        )
    }

    pub(super) fn proxy_aware_get_runtime_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        receiver: Value,
        depth: u32,
    ) -> Result<Value, InterpreterError> {
        if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
            return Err(InterpreterError::TypeError {
                expected: "bounded Proxy get recursion".to_string(),
                got: format!("depth {depth}"),
            });
        }
        if self.is_import_meta_object(object_id)? {
            let Some(key) = key.as_str() else {
                return Err(InterpreterError::TypeError {
                    expected: "well-formed import.meta contract field (url, dirname, resolve)"
                        .to_string(),
                    got: key.diagnostic(),
                });
            };
            if key != "resolve" {
                return self.import_meta_property_value(object_id, key);
            }
            // The callable is an ordinary own property. Honor replacements,
            // accessors and deletion through the same path as computed reads.
            self.record_import_meta_contract_access(key, true);
        }
        let Some((target, handler)) = self.active_proxy_record(object_id)? else {
            if self.active_inline_callback_context_label.is_some() {
                self.reflect_observe_selected_property(object_id, key)?;
            }
            return self.prototype_chain_get_with_receiver_runtime_at_depth(
                module, object_id, key, receiver, depth,
            );
        };

        if let Some(value) = self.invoke_proxy_trap(
            module,
            handler,
            "get",
            vec![
                self.proxy_trap_target(object_id, target),
                key.value(),
                receiver.clone(),
            ],
        )? {
            self.validate_proxy_get_trap_result(module, target, key, &value, depth + 1)?;
            return Ok(value);
        }

        // Without a trap a callable proxy reads its function target (whose
        // `call`, `prototype`, ... are not on its property storage).
        if let Some(module) = module
            && let Some(function) = self.proxy_call_target(object_id)
        {
            return self.get_v_with_receiver(module, &function, key, receiver, depth + 1);
        }
        self.proxy_aware_get_runtime_property(module, target, key, receiver, depth + 1)
    }

    #[cfg(test)]
    pub(super) fn proxy_aware_set_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &str,
        value: Value,
        receiver: Value,
        depth: u32,
    ) -> Result<bool, InterpreterError> {
        self.proxy_aware_set_runtime_property(
            module,
            object_id,
            &RuntimePropertyKey::String(JsString::from(key)),
            value,
            receiver,
            depth,
        )
    }

    /// ES2020 9.4.2.4 ArraySetLength steps 16-17 for an array `length`
    /// write: elements are deleted from the end and the deletion stops at
    /// the first one that cannot be deleted (a non-configurable element), so
    /// `length` stays one past it and the write reports failure (bd-9vouw.197).
    /// `Some(kept length)` when such an element sits at or above the new
    /// length, `None` otherwise (and for anything but an array's `length`).
    pub(super) fn array_length_kept_by_nonconfigurable(
        &self,
        array_id: ObjectId,
        key: &RuntimePropertyKey,
        value: &Value,
    ) -> Result<Option<i64>, InterpreterError> {
        let Some(object) = self.heap.get(array_id.0 as usize) else {
            return Err(InterpreterError::ObjectNotFound { id: array_id.0 });
        };
        if !object.is_array || key.as_str() != Some("length") {
            return Ok(None);
        }
        let new_length = Self::normalize_array_length_assignment(value)?;
        // Only an explicit attribute entry makes an element non-configurable
        // (a frozen array never reaches here), so the scan is over that map,
        // not over every element.
        let blocking = object
            .property_attributes
            .iter()
            .filter(|(_, attributes)| !attributes.configurable)
            .filter_map(|(candidate, _)| {
                let name = candidate.as_str()?;
                let index = Self::canonical_array_index_key(name)?;
                (i64::from(index) >= new_length && object.properties.get(name).is_some())
                    .then_some(index)
            })
            .max();
        Ok(blocking.map(|index| i64::from(index) + 1))
    }

    /// Module namespaces retain writable data descriptors for ESM
    /// reflection, but their exotic [[Set]] and [[DefineOwnProperty]] methods
    /// do not let guests replace exports. Authenticate the heap identity
    /// against the private runtime records; a forged @@toStringTag is not a
    /// namespace. The tag check keeps ordinary property stores on their fast
    /// path. Source modules and native providers use the same exotic methods.
    pub(super) fn is_module_namespace(&self, object_id: ObjectId) -> bool {
        let tag = RuntimePropertyKey::Symbol(WellKnownSymbol::ToStringTag.id());
        if !matches!(
            self.heap.get(object_id.0 as usize)
                .and_then(|object| object.own_runtime_property_value(&tag)),
            Some(Value::Str(value)) if value.as_str() == Some("Module")
        ) {
            return false;
        }
        self.module_state
            .modules
            .values()
            .any(|record| record.namespace_object == object_id)
    }

    /// When `[[Set]]` of `key` on `object_id` (its own receiver) takes the
    /// ordinary path with nothing to observe: the number of objects
    /// `reflect_observe_selected_property` visits, else `None` (bd-9vouw.504).
    ///
    /// It holds for a plain extensible object (no array, wrapper, binary
    /// storage, Proxy, import.meta or built-in prototype) whose chain is
    /// ordinary objects without mutation or binary-storage labels, when the
    /// first object holding `key` has it as a writable data property with a
    /// Public stored label and no object before it answers through a
    /// prototype getter or a read-only virtual property. Any active context
    /// must be Public, as must a pending callback result. The ordinary path's
    /// observations then add Public to Public and its admissions join Public,
    /// so what remains of them is one budget check and one charge per object
    /// visited plus three admissions.
    pub(super) fn plain_store_observation_steps(
        &self,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
    ) -> Option<u32> {
        #[cfg(test)]
        if FORCE_GENERIC_STORES.with(std::cell::Cell::get) {
            return None;
        }
        let name = key.as_str()?;
        if name == "__proto__"
            || self
                .active_inline_callback_context_label
                .as_ref()
                .is_some_and(|context| !matches!(context, Label::Public))
            || self
                .pending_hostcall_result_label
                .as_ref()
                .is_some_and(|label| !matches!(label, Label::Public))
        {
            return None;
        }
        let ordinary = |object: &HeapObject, id: ObjectId| {
            !(object.is_import_meta
                || object.is_array
                || object.primitive_value.is_some()
                || object.array_buffer.is_some()
                || object.typed_array.is_some()
                || object.data_view.is_some()
                || object.brand() == Some(PROXY_TYPE_TAG)
                || self.object_mutation_labels.contains_key(&id)
                || self.is_module_namespace(id))
        };
        let receiver = self.heap.get(object_id.0 as usize)?;
        if !ordinary(receiver, object_id)
            || receiver.is_frozen
            || self
                .builtin_prototypes
                .values()
                .any(|prototype| *prototype == object_id)
        {
            return None;
        }
        let mut current = object_id;
        let mut steps = 0u32;
        loop {
            steps += 1;
            if steps > 32 {
                return None;
            }
            let object = self.heap.get(current.0 as usize)?;
            if !ordinary(object, current) {
                return None;
            }
            if let Some(found) = object.own_runtime_property_value(key) {
                let writable_data = !matches!(found, Value::Accessor { .. })
                    && object.own_property_attributes(key).writable;
                let public = matches!(
                    self.own_stored_runtime_property_label(current, key),
                    Label::Public
                );
                // An inherited key is defined on the receiver, which must
                // take new properties.
                let definable = current == object_id || receiver.extensible();
                return (writable_data && public && definable).then_some(steps);
            }
            if !self.virtual_property_is_writable(current, key)
                || self.prototype_getter_at(current, key).is_some()
            {
                return None;
            }
            match self.observable_prototype_link(object, current) {
                Some(next) => current = next,
                // The key is new: [[Set]] defines it on the receiver.
                None => return receiver.extensible().then_some(steps),
            }
        }
    }

    pub(super) fn proxy_aware_set_runtime_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        value: Value,
        receiver: Value,
        depth: u32,
    ) -> Result<bool, InterpreterError> {
        // ECMA-262 10.4.6.9: namespace [[Set]] always refuses, without
        // inspecting Receiver, including a distinct object, inheritance or
        // transparent Proxy forwarding. Writable export descriptors support
        // reflection and do not authorize the ordinary descriptor path.
        // [[DefineOwnProperty]] retains its separate SameValue behavior.
        if self.is_module_namespace(object_id) {
            return Ok(false);
        }
        // bd-9vouw.504: the ordinary store with nothing to observe. Its
        // effects other than the write: without a context, none; in a Public
        // one, a budget check of the unchanged state (first made by
        // observe_scoped_callback_result) and one charge per object
        // reflect_observe_selected_property visits plus one per admission
        // (the object, the receiver and the resolved receiver), in that order.
        // A store into the receiver's own or a new key of a non-array object
        // ends in set_object_runtime_property.
        if depth == 0
            && matches!(&receiver, Value::Object(id) if *id == object_id)
            && let Some(steps) = self.plain_store_observation_steps(object_id, key)
        {
            if self.active_inline_callback_context_label.is_some() {
                self.check_temporary_memory_budget(0)?;
                for _ in 0..steps + 3 {
                    self.json_charge_work()?;
                }
            }
            self.set_object_runtime_property(object_id, key.clone(), value)?;
            return Ok(true);
        }
        if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
            return Err(InterpreterError::TypeError {
                expected: "bounded Proxy set recursion".to_string(),
                got: format!("depth {depth}"),
            });
        }
        if self.is_import_meta_object(object_id)? && key.as_str() != Some("resolve") {
            if let Some(key) = key.as_str() {
                self.record_import_meta_contract_access(key, false);
            }
            return Err(InterpreterError::TypeError {
                expected: "read-only import.meta contract field".to_string(),
                got: key
                    .as_str()
                    .map_or_else(|| key.diagnostic(), |key| format!("import.meta.{key}")),
            });
        }
        let Some((target, handler)) = self.active_proxy_record(object_id)? else {
            if self.active_inline_callback_context_label.is_some() {
                // A Proxy trap getter may have raised the context after the
                // Reflect entry check and then returned undefined. Admission
                // at the actual mutation site must include that observation.
                self.observe_scoped_callback_result()?;
                self.reflect_observe_selected_property(object_id, key)?;
                self.reflect_admit_mutation_label(object_id)?;
                if let Value::Object(receiver) = &receiver {
                    self.reflect_admit_mutation_label(*receiver)?;
                }
            }
            // [[Set]] of `__proto__` that reaches %Object.prototype%'s
            // accessor runs its setter (Annex B.2.2.1.2), as SetProperty
            // does: Object.assign and Reflect.set of a `__proto__` key set
            // the prototype, and a refused change is a TypeError
            // (bd-9vouw.318). They defined an own `__proto__` data property.
            if key.as_str() == Some("__proto__")
                && receiver == Value::Object(object_id)
                && self.proto_key_reaches_accessor(object_id)
            {
                if let Some(new_proto) = self.prototype_link_for_value(module, &value)?
                    && !self.object_set_prototype(module, object_id, new_proto, 0)?
                {
                    return Err(InterpreterError::TypeError {
                        expected: "a permitted __proto__ change".to_string(),
                        got: "a cyclic or refused prototype".to_string(),
                    });
                }
                return Ok(true);
            }
            let mut define_on_receiver = false;
            if let Some(key) = key.as_str() {
                match self
                    .typed_array_set_runtime_property(module, object_id, key, &value, &receiver)?
                {
                    Some(TypedArraySetOutcome::Done(success)) => return Ok(success),
                    Some(TypedArraySetOutcome::DefineOnReceiver) => define_on_receiver = true,
                    None => {}
                }
            }
            // A String wrapper's own indices and `length` are non-writable
            // (ES2020 9.4.3.1): OrdinarySet fails, so `Object.assign('a',
            // [1])` throws and a sloppy `wrapper[0] = 'x'` does nothing. The
            // write created an ordinary own property.
            if key
                .as_str()
                .is_some_and(|key| self.string_wrapper_own_property(object_id, key).is_some())
            {
                return Ok(false);
            }
            let mut owner = object_id;
            let mut owner_depth = depth;
            if !define_on_receiver {
                loop {
                    if owner_depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                        return Err(InterpreterError::StackOverflow {
                            depth: owner_depth as usize,
                            max: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
                        });
                    }
                    // OrdinarySet delegates to the prototype's [[Set]] before
                    // consulting the receiver. Preserve that receiver exactly. A
                    // typed array's [[Set]] answers numeric keys itself
                    // (ES2024 10.4.5.5).
                    if owner != object_id
                        && (self.proxy_record(owner)?.is_some()
                            || self.is_module_namespace(owner)
                            || self
                                .heap
                                .get(owner.0 as usize)
                                .is_some_and(|object| object.typed_array.is_some()))
                    {
                        return self.proxy_aware_set_runtime_property(
                            module,
                            owner,
                            key,
                            value,
                            receiver,
                            owner_depth,
                        );
                    }
                    let Some(object) = self.heap.get(owner.0 as usize) else {
                        return Err(InterpreterError::ObjectNotFound { id: owner.0 });
                    };
                    // A typed array's, DataView's or ArrayBuffer's `length`,
                    // `byteLength`, ... entries keep internal slots, not own
                    // properties: the write goes on to the prototype's
                    // getter-only accessor and fails. It replaced the slot, so
                    // `ta.length = 0` made `ta.length` read 0 and
                    // Array.prototype.push on a typed array changed nothing
                    // instead of throwing.
                    let slot = key
                        .as_str()
                        .is_some_and(|name| Self::binary_slot_key(object, name));
                    if !slot && let Some(property) = object.own_runtime_property_value(key) {
                        if matches!(&property, Value::Accessor { .. }) {
                            return self.resolve_accessor_set(module, property, receiver, value);
                        }
                        // ES2020 9.1.9.2 OrdinarySetWithOwnDescriptor: an own or
                        // inherited non-writable data property rejects the write.
                        if !object.own_property_attributes(key).writable {
                            return Ok(false);
                        }
                        break;
                    }
                    // bd-9vouw.17: so do %Function.prototype%'s virtual `length`
                    // and `name` (ES2020 19.2.3); a write must not shadow them
                    // with a new own property.
                    if !self.virtual_property_is_writable(owner, key) {
                        return Ok(false);
                    }
                    // A built-in prototype's getter-only accessor
                    // (`RegExp.prototype.source`, `Map.prototype.size`) has no
                    // setter, so OrdinarySet fails (ES2020 9.1.9.2 step 3.e): a
                    // sloppy `re.source = 'x'` does nothing and a strict one
                    // throws. The write created an own property that then
                    // answered reads (bd-9vouw.150). Event's returnValue and
                    // cancelBubble have setters in the DOM and keep the old
                    // behavior.
                    if let Some(getter) = self.prototype_getter_at(owner, key)
                        && !matches!(
                            getter.module_specifier.0.as_deref(),
                            Some("Event.returnValue" | "Event.cancelBubble")
                        )
                    {
                        // Object.prototype.__proto__ has a setter, called on
                        // the receiver (bd-9vouw.284).
                        if getter.module_specifier.0.as_deref() == Some("Object.__proto__") {
                            self.object_proto_setter_call(module, receiver, value)?;
                            return Ok(true);
                        }
                        return Ok(false);
                    }
                    // OrdinarySet follows the same observable prototype chain
                    // as [[Get]], including implicit Object/Array prototypes.
                    // Literal initialization uses CreateDataProperty and is
                    // independent of these inherited descriptors (bd-9vouw.280).
                    match self.observable_prototype_link(object, owner) {
                        Some(prototype) => {
                            owner = prototype;
                            owner_depth += 1;
                        }
                        None => break,
                    }
                }
            }
            // OrdinarySetWithOwnDescriptor consults Receiver.[[GetOwnProperty]]
            // and then Receiver.[[DefineOwnProperty]]. Unwrapping a Proxy here
            // skips both traps, including splice's species-result length write.
            // The descriptor walk above still owns inherited setter dispatch.
            let proxy_receiver = match &receiver {
                Value::Object(id) => Some(*id),
                Value::BuiltinFunction(builtin)
                    if builtin.kind == BuiltinFunctionKind::CallableProxy =>
                {
                    Some(Self::callable_proxy_record_id(builtin)?)
                }
                _ => None,
            };
            if let Some(receiver_id) = proxy_receiver
                && self.proxy_record(receiver_id)?.is_some()
            {
                let current =
                    self.proxy_target_descriptor_fields(module, receiver_id, key, depth + 1)?;
                self.observe_scoped_callback_result()?;
                if self.active_inline_callback_context_label.is_some() {
                    self.reflect_admit_mutation_label(receiver_id)?;
                }
                let fields = if let Some(current) = current {
                    if current.is_accessor() || current.writable != Some(true) {
                        return Ok(false);
                    }
                    PropertyDescriptorFields {
                        value: Some(value),
                        ..PropertyDescriptorFields::default()
                    }
                } else {
                    PropertyDescriptorFields {
                        value: Some(value),
                        writable: Some(true),
                        enumerable: Some(true),
                        configurable: Some(true),
                        ..PropertyDescriptorFields::default()
                    }
                };
                return self.proxy_aware_define_own_property(
                    module,
                    receiver_id,
                    key.clone(),
                    fields,
                    depth + 1,
                );
            }
            // Resolve backing storage only after the descriptor walk has ruled
            // out an inherited setter: setters and Proxy traps must receive
            // the original callable, promise or iterator identity. A data
            // write may materialize that receiver's own storage (bd-9vouw.280).
            let receiver_id = if Self::stores_own_properties_on_backing(&receiver) {
                self.own_property_holder(module, &receiver, true)?
            } else {
                self.proxy_set_receiver_object(&receiver)?
            };
            let Some(receiver_id) = receiver_id else {
                return Ok(false);
            };
            if self.is_module_namespace(receiver_id) {
                // A transparent Proxy receiver forwards an unchanged data
                // value through [[DefineOwnProperty]], as Node does. A bare
                // namespace receiver still rejects even a SameValue write.
                if key.string().is_some()
                    && matches!(&receiver, Value::Object(id) if *id != receiver_id)
                {
                    return self.define_own_property_from_descriptor(
                        receiver_id,
                        key.clone(),
                        PropertyDescriptorFields {
                            value: Some(value),
                            ..PropertyDescriptorFields::default()
                        },
                    );
                }
                return Ok(false);
            }
            if self.active_inline_callback_context_label.is_some() {
                self.reflect_admit_mutation_label(receiver_id)?;
            }
            // A write over a canonical prototype's virtual property keeps its
            // attributes (bd-9vouw.379).
            self.materialize_virtual_own_property(receiver_id, key)?;
            let Some(receiver_object) = self.heap.get(receiver_id.0 as usize) else {
                return Err(InterpreterError::ObjectNotFound { id: receiver_id.0 });
            };
            if receiver_object.is_frozen
                || (!receiver_object.extensible()
                    && !receiver_object.contains_own_runtime_property(key))
                || (receiver_object.contains_own_runtime_property(key)
                    && !receiver_object.own_property_attributes(key).writable)
                || matches!(
                    receiver_object.own_runtime_property_value(key),
                    Some(Value::Accessor { .. })
                )
            {
                // OrdinarySetWithOwnDescriptor does not invoke or overwrite
                // an accessor on a distinct receiver of a data-property write.
                return Ok(false);
            }
            // CreateDataProperty of an index past a non-writable `length`
            // is rejected (bd-9vouw.279).
            if Self::array_index_past_fixed_length(receiver_object, key) {
                return Ok(false);
            }
            if let Some(kept_length) =
                self.array_length_kept_by_nonconfigurable(receiver_id, key, &value)?
            {
                self.set_object_runtime_property(
                    receiver_id,
                    key.clone(),
                    Value::Int(kept_length),
                )?;
                return Ok(false);
            }
            if let Some(context_label) = self.active_inline_callback_context_label.clone() {
                let existing = self.own_stored_runtime_property_label(receiver_id, key);
                let combined = existing.join(&context_label);
                self.set_own_runtime_property_label(receiver_id, key, &combined)?;
                if let Err(err) = self.set_object_runtime_property(receiver_id, key.clone(), value)
                {
                    self.set_own_runtime_property_label(receiver_id, key, &existing)?;
                    return Err(err);
                }
            } else {
                self.set_object_runtime_property(receiver_id, key.clone(), value)?;
            }
            // An array receiver's length grows with the index written, for
            // every caller of [[Set]]: the SetProperty instruction,
            // Object.assign (`Object.assign(vals, [4, 4])`, cli-table3's
            // column widths) and Reflect.set left it unchanged.
            if let Some(index) = key.as_str().and_then(Self::canonical_array_index_key) {
                self.maintain_array_index_assignment(receiver_id, index)?;
            }
            return Ok(true);
        };

        if let Some(result) = self.invoke_proxy_trap(
            module,
            handler,
            "set",
            vec![
                self.proxy_trap_target(object_id, target),
                key.value(),
                value.clone(),
                receiver.clone(),
            ],
        )? {
            if !result.is_truthy() {
                return Ok(false);
            }
            self.validate_proxy_set_trap_result(module, target, key, &value, depth + 1)?;
            return Ok(true);
        }

        self.proxy_aware_set_runtime_property(module, target, key, value, receiver, depth + 1)
    }

    /// Resolve the object on which ordinary `[[Set]]` creates/replaces a data
    /// property when its Proxy receiver traps have already been handled. Other
    /// callers use this only to inspect backing storage; a distinct ordinary
    /// Reflect receiver keeps its identity.
    pub(super) fn proxy_set_receiver_object(
        &self,
        receiver: &Value,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let mut object_id = match receiver {
            Value::Object(object_id) => *object_id,
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::CallableProxy =>
            {
                Self::callable_proxy_record_id(builtin)?
            }
            _ => return Ok(None),
        };
        let mut depth = 0u32;
        while depth < MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some((target, _handler)) = self.active_proxy_record(object_id)? else {
                return Ok(Some(object_id));
            };
            object_id = target;
            depth += 1;
        }
        Err(InterpreterError::TypeError {
            expected: "bounded Proxy receiver recursion".to_string(),
            got: format!("depth {depth}"),
        })
    }

    pub(super) fn proxy_aware_has_runtime_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        depth: u32,
    ) -> Result<bool, InterpreterError> {
        if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
            return Err(InterpreterError::TypeError {
                expected: "bounded Proxy has recursion".to_string(),
                got: format!("depth {depth}"),
            });
        }
        let Some((target, handler)) = self.active_proxy_record(object_id)? else {
            if self.active_inline_callback_context_label.is_some() {
                self.reflect_observe_selected_property(object_id, key)?;
            }
            let mut current = Some(object_id);
            let mut depth = depth;
            while let Some(id) = current {
                if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
                    return Err(InterpreterError::StackOverflow {
                        depth: depth as usize,
                        max: MAX_PROTOTYPE_CHAIN_DEPTH as usize,
                    });
                }
                if id != object_id && self.proxy_record(id)?.is_some() {
                    return self.proxy_aware_has_runtime_property(module, id, key, depth);
                }
                if let Some(name) = key.as_str() {
                    if self.writable_state_view_value(id, name).is_some() {
                        return Ok(true);
                    }
                    if let Some(value) = self.typed_array_indexed_get_property(id, name)? {
                        return Ok(!matches!(value, Value::Undefined));
                    }
                    if self.string_wrapper_own_property(id, name).is_some() {
                        return Ok(true);
                    }
                }
                let object = self
                    .heap
                    .get(id.0 as usize)
                    .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
                if object.contains_own_runtime_property(key)
                    || self.prototype_getter_at(id, key).is_some()
                {
                    return Ok(true);
                }
                current = self.observable_prototype_link(object, id);
                depth += 1;
            }
            // The virtual @@iterator of the canonical Array, %TypedArray%,
            // Map, Set and String prototypes (served by [[Get]]'s fallback)
            // is found by HasProperty too: `Symbol.iterator in Map.prototype`.
            if matches!(
                key,
                RuntimePropertyKey::Symbol(symbol) if *symbol == WellKnownSymbol::Iterator.id()
            ) {
                let root_has_implicit_iterator =
                    self.heap.get(object_id.0 as usize).is_some_and(|object| {
                        object.typed_array.is_some()
                            || (object.is_array
                                && !object.is_null_prototype
                                && object.prototype.is_none())
                    });
                return Ok(root_has_implicit_iterator
                    || self.chain_inherits_array_prototype(object_id)
                    || ["Array", "TypedArray", "Map", "Set", "String"]
                        .iter()
                        .any(|name| self.chain_reaches_canonical_prototype(object_id, name)));
            }
            return Ok(key
                .as_str()
                .is_some_and(|key| self.chain_has_virtual_builtin_property(object_id, key)));
        };

        if let Some(result) = self.invoke_proxy_trap(
            module,
            handler,
            "has",
            vec![self.proxy_trap_target(object_id, target), key.value()],
        )? {
            if result.is_truthy() {
                return Ok(true);
            }
            self.validate_proxy_property_absence(module, target, key, "has", depth + 1)?;
            return Ok(false);
        }

        // A callable proxy without the trap asks its function target.
        if let Some(module) = module
            && let Some(function) = self.proxy_call_target(object_id)
        {
            return match &function {
                Value::BuiltinFunction(inner)
                    if inner.kind == BuiltinFunctionKind::CallableProxy =>
                {
                    let inner = Self::callable_proxy_record_id(inner)?;
                    self.proxy_aware_has_runtime_property(Some(module), inner, key, depth + 1)
                }
                _ => self.function_has_property(module, &function, key),
            };
        }
        self.proxy_aware_has_runtime_property(module, target, key, depth + 1)
    }

    pub(super) fn proxy_aware_delete_runtime_property(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        depth: u32,
    ) -> Result<bool, InterpreterError> {
        if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
            return Err(InterpreterError::TypeError {
                expected: "bounded Proxy delete recursion".to_string(),
                got: format!("depth {depth}"),
            });
        }
        let Some((target, handler)) = self.active_proxy_record(object_id)? else {
            self.validate_executable_property_key(key)?;
            // bd-9vouw.93: a canonical prototype's virtual own property (a
            // method, `constructor`, @@iterator) is configurable, so deleting
            // it, or a stored property shadowing it, leaves it absent:
            // `delete Array.prototype.fill` returned true and left `fill`.
            // Its accessors (`Map.prototype.size`) too: `delete` returned true
            // and left them, own and with a descriptor (bd-9vouw.249).
            let virtual_property = self
                .canonical_prototype_virtual_property(object_id, key)
                .is_some()
                || self.prototype_getter_at(object_id, key).is_some();
            let object = self
                .heap
                .get(object_id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
            if object.is_array && key.as_str() == Some("length") {
                return Ok(false);
            }
            if let Some(view) = &object.typed_array
                && let Some(index) = key.as_str().and_then(Self::typed_array_integer_index_key)
            {
                return Ok(index >= view.length);
            }
            // [[Delete]] reports success, not whether a map entry was removed.
            // An absent own property succeeds even on a frozen object or when
            // an inherited property with the same name remains observable.
            if !object.contains_own_runtime_property(key) {
                if virtual_property {
                    if object.is_frozen || !self.virtual_property_is_configurable(object_id, key) {
                        return Ok(false);
                    }
                    self.delete_virtual_own_property(object_id, key)?;
                }
                return Ok(true);
            }
            // ES2020 9.1.10.1 OrdinaryDelete: a non-configurable own property
            // is not deleted.
            if !object.own_property_attributes(key).configurable {
                return Ok(false);
            }
            if self.active_inline_callback_context_label.is_some() {
                self.observe_scoped_callback_result()?;
                self.reflect_admit_mutation_label(object_id)?;
            }
            let removed = self.remove_object_runtime_property(object_id, key)?;
            if removed && virtual_property {
                self.delete_virtual_own_property(object_id, key)?;
            }
            if removed && let Some(key) = key.string() {
                self.mark_deleted_for_in_iterators(object_id, key);
            }
            return Ok(removed);
        };

        if let Some(result) = self.invoke_proxy_trap(
            module,
            handler,
            "deleteProperty",
            vec![self.proxy_trap_target(object_id, target), key.value()],
        )? {
            if !result.is_truthy() {
                return Ok(false);
            }
            self.validate_proxy_property_absence(module, target, key, "deleteProperty", depth + 1)?;
            return Ok(true);
        }

        self.proxy_aware_delete_runtime_property(module, target, key, depth + 1)
    }

    pub(super) fn ordinary_own_property_key_values(
        &self,
        object_id: ObjectId,
    ) -> Result<Vec<Value>, InterpreterError> {
        let mut keys: Vec<Value> = self
            .indexed_own_entries(object_id)?
            .into_iter()
            .map(|(key, _)| Value::Str(key))
            .collect();
        // A String wrapper's `length` follows its indices (ES2020 9.4.3.3);
        // Reflect.ownKeys(new String('ab')) left it out (bd-9vouw.356).
        let string_wrapper = matches!(self.primitive_wrapper_value(object_id), Some(Value::Str(_)));
        if string_wrapper {
            keys.push(Value::Str(JsString::from("length")));
        }
        let virtual_keys = self.canonical_prototype_virtual_own_keys(object_id);
        keys.extend(virtual_keys.iter().cloned());
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        keys.extend(
            object
                .own_runtime_property_keys()
                .into_iter()
                .filter_map(|key| match key {
                    RuntimePropertyKey::String(key)
                        if self.own_runtime_property_visible(object_id, &key)
                            && !(string_wrapper && key.as_str() == Some("length")) =>
                    {
                        Some(Value::Str(key))
                    }
                    RuntimePropertyKey::Symbol(symbol) => Some(Value::Symbol(symbol)),
                    RuntimePropertyKey::String(_) => None,
                })
                .filter(|key| !virtual_keys.contains(key)),
        );
        // String keys come before Symbol keys (ES2020 9.1.11.1).
        keys.sort_by_key(|key| matches!(key, Value::Symbol(_)));
        Ok(keys)
    }

    /// bd-9vouw.122: the own keys %Array.prototype% supplies virtually, in
    /// Node's order: `length`, `constructor`, the methods this engine serves,
    /// and @@iterator. Empty for any other object. Without them
    /// `Object.getOwnPropertyNames(Array.prototype)` was empty (Node: 40
    /// names). @@unscopables is an ordinary own property
    /// (install_array_unscopables), listed after these.
    ///
    /// bd-9vouw.249: every other prototype that serves its methods
    /// virtually (VIRTUAL_METHOD_PROTOTYPES) lists `constructor`, the methods
    /// this engine serves among those Node v22.2.0 records for it
    /// (BUILTIN_FUNCTION_LENGTHS, in that table's order), then its accessors
    /// (PROTOTYPE_GETTERS). `Object.getOwnPropertyNames(Map.prototype)` was
    /// empty. No-claim: the methods are in alphabetical order, not Node's
    /// creation order.
    ///
    /// The other canonical prototypes list what
    /// [`Self::canonical_prototype_own_virtual_value`] supplies for them the
    /// same way: Object.prototype its `constructor` and methods,
    /// Error.prototype its `constructor` and `toString`, a NativeError's or a
    /// concrete typed array's prototype its `constructor`. Each was missing
    /// from `Object.getOwnPropertyNames` (Object.prototype listed nothing)
    /// though `hasOwnProperty` answered true.
    pub(super) fn canonical_prototype_virtual_own_keys(&self, object_id: ObjectId) -> Vec<Value> {
        let Some(name) = self
            .builtin_prototypes
            .iter()
            .find(|(_, prototype)| **prototype == object_id)
            .map(|(name, _)| name.as_str())
        else {
            return Vec::new();
        };
        if name != "Array" {
            let owner = format!("{name}.prototype");
            let methods = builtin_function_lengths::BUILTIN_FUNCTION_LENGTHS
                .iter()
                .filter(|(entry_owner, key, _)| *entry_owner == owner && !key.starts_with('['))
                .map(|(_, key, _)| *key);
            let mut names: Vec<&str> = Vec::new();
            let leading: &[&str] = if name == "Function" {
                &["length", "name", "constructor"]
            } else {
                &["constructor"]
            };
            for key in leading.iter().copied().chain(methods) {
                if !names.contains(&key)
                    && self
                        .canonical_prototype_own_virtual_value(object_id, key)
                        .is_some()
                {
                    names.push(key);
                }
            }
            for (_, key, _) in prototype_getters::PROTOTYPE_GETTERS
                .iter()
                .filter(|(entry_owner, key, _)| *entry_owner == name && !key.starts_with("@@"))
            {
                if !names.contains(key)
                    && !(self.virtual_property_deletions
                        && self.virtual_own_property_deleted(
                            object_id,
                            &RuntimePropertyKey::String(JsString::from(*key)),
                        ))
                {
                    names.push(key);
                }
            }
            return names.into_iter().map(Value::str).collect();
        }
        let mut keys: Vec<Value> = ARRAY_PROTOTYPE_OWN_NAMES
            .iter()
            .filter(|name| {
                self.canonical_prototype_own_virtual_value(object_id, name)
                    .is_some()
            })
            .map(|name| Value::str(*name))
            .collect();
        let iterator = WellKnownSymbol::Iterator.id();
        if !self.virtual_own_property_deleted(object_id, &RuntimePropertyKey::Symbol(iterator)) {
            keys.push(Value::Symbol(iterator));
        }
        keys
    }

    pub(super) fn proxy_aware_own_property_keys(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        depth: u32,
    ) -> Result<Vec<Value>, InterpreterError> {
        if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
            return Err(InterpreterError::TypeError {
                expected: "bounded Proxy ownKeys recursion".to_string(),
                got: format!("depth {depth}"),
            });
        }
        let Some((target, handler)) = self.active_proxy_record(object_id)? else {
            return self.ordinary_own_property_key_values(object_id);
        };

        if let Some(result) = self.invoke_proxy_trap(
            module,
            handler,
            "ownKeys",
            vec![self.proxy_trap_target(object_id, target)],
        )? {
            let key_values = self.observable_proxy_own_keys_list(module, result)?;
            let mut seen = BTreeSet::new();
            for key_value in &key_values {
                if !matches!(key_value, Value::Str(_) | Value::Symbol(_)) {
                    return Err(InterpreterError::TypeError {
                        expected: "string or Symbol Proxy.ownKeys result key".to_string(),
                        got: key_value.type_name().to_string(),
                    });
                }
                let key = self.executable_property_key_from_value(key_value);
                self.validate_executable_property_key(&key)?;
                if !seen.insert(key.clone()) {
                    return Err(InterpreterError::TypeError {
                        expected: "unique Proxy.ownKeys result keys".to_string(),
                        got: format!("duplicate key {}", key.diagnostic()),
                    });
                }
            }
            self.validate_proxy_own_keys_trap_result(module, object_id, target, seen, depth + 1)?;
            return Ok(key_values);
        }

        self.proxy_target_own_property_keys(module, object_id, target, depth + 1)
    }

    pub(super) fn proxy_target_own_property_keys(
        &mut self,
        module: Option<&Ir3Module>,
        proxy: ObjectId,
        target: ObjectId,
        depth: u32,
    ) -> Result<Vec<Value>, InterpreterError> {
        match self.proxy_call_target(proxy) {
            Some(function) => self.function_own_property_keys(module, &function, depth),
            None => self.proxy_aware_own_property_keys(module, target, depth),
        }
    }

    /// Whether `key` is an enumerable own String property of `object_id`.
    ///
    /// For a Proxy receiver this consults the `getOwnPropertyDescriptor` trap
    /// (ES OrdinaryOwnPropertyKeys consumers — Object.keys/values/entries,
    /// for-in, JSON — must check per-key enumerability through the trap), and
    /// falls through to the target when the trap is absent. Ordinary objects
    /// use their existing own-key visibility (bd-9trje).
    pub(super) fn own_string_key_is_enumerable(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &JsString,
        depth: u32,
    ) -> Result<bool, InterpreterError> {
        if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
            return Err(InterpreterError::TypeError {
                expected: "bounded Proxy getOwnPropertyDescriptor recursion".to_string(),
                got: format!("depth {depth}"),
            });
        }
        if self.active_proxy_record(object_id)?.is_none() {
            return Ok(self.ordinary_own_string_key_is_enumerable(object_id, key));
        }
        // Enumeration consumes [[GetOwnProperty]], including the complete
        // descriptor conversion and target invariants, not just an unchecked
        // Get of the trap result's `enumerable` field (bd-9vouw.513).
        let descriptor = self.proxy_target_descriptor_fields(
            module,
            object_id,
            &RuntimePropertyKey::String(key.clone()),
            depth,
        )?;
        Ok(descriptor.is_some_and(|fields| fields.enumerable == Some(true)))
    }

    /// Own enumerable String keys of `object_id` in ES order, honoring the
    /// Proxy `ownKeys` + `getOwnPropertyDescriptor` traps (bd-9trje). Used by
    /// the Object.keys/values/entries proxy branch.
    /// ES2020 7.3.22 EnumerableOwnPropertyNames(O, key+value) for a Proxy:
    /// [[OwnPropertyKeys]], then for each string key its [[GetOwnProperty]]
    /// and, when enumerable, its [[Get]] before the next key's descriptor
    /// (Object.entries / Object.values, bd-9vouw.347). Reading every
    /// descriptor first, then every value, ran the traps out of order.
    pub(super) fn proxy_enumerable_own_entries(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        receiver: &Value,
    ) -> Result<Vec<(JsString, Value)>, InterpreterError> {
        // Guest traps run while native locals hold their results: no
        // collection until this returns.
        self.gc_nested_request = None;
        let keys = self.proxy_aware_own_property_keys(module, object_id, 0)?;
        let mut entries = Vec::new();
        for key_value in keys {
            if let Value::Str(key) = key_value
                && self.own_string_key_is_enumerable(module, object_id, &key, 0)?
            {
                let value = self.proxy_aware_get_runtime_property(
                    module,
                    object_id,
                    &RuntimePropertyKey::String(key.clone()),
                    receiver.clone(),
                    0,
                )?;
                entries.push((key, value));
            }
        }
        Ok(entries)
    }

    pub(super) fn proxy_own_enumerable_string_keys(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
    ) -> Result<Vec<JsString>, InterpreterError> {
        let keys = self.proxy_aware_own_property_keys(module, object_id, 0)?;
        let mut result = Vec::new();
        for key_value in keys {
            if let Value::Str(key) = key_value
                && self.own_string_key_is_enumerable(module, object_id, &key, 0)?
            {
                result.push(key);
            }
        }
        Ok(result)
    }

    /// The next `[[GetPrototypeOf]]` link in a for-in chain walk, honoring the
    /// Proxy `getPrototypeOf` trap and falling through to the target when the
    /// trap is absent; ordinary objects use their stored prototype (bd-9trje).
    pub(super) fn proxy_aware_prototype_link(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        let Some((target, handler)) = self.active_proxy_record(object_id)? else {
            return Ok(self.observable_prototype_of(object_id));
        };
        match self.invoke_proxy_trap(
            module,
            handler,
            "getPrototypeOf",
            vec![self.proxy_trap_target(object_id, target)],
        )? {
            // Trap absent: the target's prototype governs.
            None => Ok(self.observable_prototype_of(target)),
            Some(Value::Object(prototype_id)) => Ok(Some(prototype_id)),
            Some(Value::Null) => Ok(None),
            Some(other) => Err(InterpreterError::TypeError {
                expected: "object or null from Proxy.getPrototypeOf".to_string(),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// CopyDataProperties excludes keys *before* consulting a descriptor or
    /// invoking a getter. Copying everything and deleting excluded properties
    /// afterwards duplicates observable reads and is not object-rest semantics.
    pub(super) fn copy_data_properties(
        &mut self,
        module: Option<&Ir3Module>,
        target_id: ObjectId,
        source: Value,
        excluded: &BTreeSet<RuntimePropertyKey>,
        use_target_set: bool,
    ) -> Result<(), InterpreterError> {
        if let Value::Str(text) = &source {
            // String own properties are UTF-16 code units, unlike string
            // iteration, which combines surrogate pairs into code points.
            for (index, unit) in text.encode_utf16().enumerate() {
                self.charge_property_copy_work()?;
                let key = RuntimePropertyKey::String(index.to_string().into());
                if !excluded.contains(&key) {
                    self.copy_data_property_write(
                        module,
                        target_id,
                        key,
                        Value::Str(JsString::from_code_units(&[unit])),
                        use_target_set,
                        Label::Public,
                    )?;
                }
            }
            return Ok(());
        }
        if !source.is_object_like() {
            // Null/undefined are ignored by spread. Object-rest callers perform
            // RequireObjectCoercible before entering this shared operation.
            return Ok(());
        }
        // A function's, promise's, generator's or iterator's own properties
        // are on its backing object; none exist until one was stored.
        let Some(source_id) = self.own_property_holder(module, &source, false)? else {
            return Ok(());
        };
        let source_object = self
            .heap
            .get(source_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: source_id.0 })?;
        self.check_temporary_memory_budget(Self::estimate_ordered_property_map_bytes_nonalloc(
            &source_object.properties,
        ))?;
        let keys = self.proxy_aware_own_property_keys(module, source_id, 0)?;
        // Retain the key snapshot under the shared memory budget throughout
        // nested getters/traps, not just during the initial allocation check.
        let key_bytes = Self::estimate_value_vec_bytes(&keys);
        self.apply_memory_component_delta(0, key_bytes)?;
        let result = (|| {
            for key_value in &keys {
                self.charge_property_copy_work()?;
                let key = self.executable_property_key_from_value(key_value);
                if excluded.contains(&key)
                    || !self.copy_own_key_is_enumerable(module, source_id, &key, 0)?
                {
                    continue;
                }
                if let Some(module) = module {
                    self.run_pre_runtime_property_access_hook(module, source_id, &key)?;
                }
                let label = self
                    .runtime_property_label(source_id, &key)
                    .join(&self.process_dynamic_value_label(&source, &mut BTreeSet::new()))
                    .join(&self.stream_state_label(source_id));
                let value = self.proxy_aware_get_runtime_property(
                    module,
                    source_id,
                    &key,
                    source.clone(),
                    0,
                )?;
                self.copy_data_property_write(
                    module,
                    target_id,
                    key,
                    value,
                    use_target_set,
                    label,
                )?;
            }
            Ok(())
        })();
        drop(keys);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(key_bytes);
        result
    }

    pub(super) fn charge_property_copy_work(&mut self) -> Result<(), InterpreterError> {
        let next = self.instructions_executed.checked_add(1);
        if next.is_none_or(|next| next > self.config.instruction_budget) {
            return Err(InterpreterError::BudgetExhausted {
                executed: self.instructions_executed,
                budget: self.config.instruction_budget,
            });
        }
        self.instructions_executed = next.expect("instruction budget checked above");
        Ok(())
    }

    pub(super) fn copy_own_key_is_enumerable(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        key: &RuntimePropertyKey,
        depth: u32,
    ) -> Result<bool, InterpreterError> {
        if depth >= MAX_PROTOTYPE_CHAIN_DEPTH {
            return Err(InterpreterError::TypeError {
                expected: "bounded object-copy descriptor recursion".to_string(),
                got: format!("depth {depth}"),
            });
        }
        if self.active_proxy_record(object_id)?.is_some() {
            // Copying consumes the same checked [[GetOwnProperty]] operation
            // as key/value enumeration, including Symbol-keyed descriptors.
            let descriptor = self.proxy_target_descriptor_fields(module, object_id, key, depth)?;
            return Ok(descriptor.is_some_and(|fields| fields.enumerable == Some(true)));
        }
        let object = self
            .heap
            .get(object_id.0 as usize)
            .ok_or(InterpreterError::ObjectNotFound { id: object_id.0 })?;
        // A typed array's in-range indices are enumerable own properties
        // that live in its buffer, not among the heap entries.
        if let (Some(view), RuntimePropertyKey::String(name)) = (&object.typed_array, key)
            && name
                .as_str()
                .and_then(Self::typed_array_integer_index_key)
                .is_some_and(|index| index < view.length)
        {
            return Ok(true);
        }
        // So are a String wrapper's code-unit indices, which are not heap
        // entries either; its `length` is not enumerable (ES2020 9.4.3.1).
        // Object.assign({}, new String('ab')) copied nothing (bd-9vouw.356).
        if let RuntimePropertyKey::String(name) = key
            && let Some(name) = name.as_str()
            && self.string_wrapper_own_property(object_id, name).is_some()
        {
            return Ok(name != "length");
        }
        // Recheck existence per key: an earlier getter may delete a later
        // property, even though that key remains in the ownKeys snapshot.
        // CopyDataProperties and Object.assign copy only [[Enumerable]] keys.
        Ok(object.contains_own_runtime_property(key)
            && object.own_property_attributes(key).enumerable
            && match key {
                RuntimePropertyKey::String(name) => {
                    self.own_runtime_property_visible(object_id, name)
                }
                RuntimePropertyKey::Symbol(_) => true,
            })
    }

    pub(super) fn copy_data_property_write(
        &mut self,
        module: Option<&Ir3Module>,
        target_id: ObjectId,
        key: RuntimePropertyKey,
        value: Value,
        use_target_set: bool,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let label = label
            .join(
                self.pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public),
            )
            .join(
                self.object_mutation_labels
                    .get(&target_id)
                    .unwrap_or(&Label::Public),
            )
            .join(&self.clone_active_execution_context_label()?);
        self.join_object_mutation_label(target_id, &label)?;
        // Object.assign uses [[Set]], which cannot replace a module export.
        // Preserve the export's provenance even when the caller catches refusal.
        if !use_target_set || !self.is_module_namespace(target_id) {
            self.set_own_runtime_property_label(target_id, &key, &label)?;
        }
        if use_target_set {
            if !self.proxy_aware_set_runtime_property(
                module,
                target_id,
                &key,
                value,
                Value::Object(target_id),
                0,
            )? {
                return Err(InterpreterError::TypeError {
                    expected: "successful Object.assign property write".to_string(),
                    got: key.diagnostic(),
                });
            }
        } else {
            self.set_object_runtime_property(target_id, key, value)?;
        }
        Ok(())
    }

    /// bd-9vouw.37: an ordinary-object operand of `+` or a template
    /// substitution converts through the observable ToPrimitive (it may define
    /// toString / valueOf / @@toPrimitive on itself or its prototype chain),
    /// which only the reentrant Tier-R path can run.
    pub(super) fn register_needs_observable_to_primitive(&self, register: u32) -> bool {
        // Borrowed peek: this runs ahead of every compact arithmetic op.
        // Functions convert through Function.prototype.toString or their own
        // `toString`/`valueOf`, and promises, generator objects and iterators
        // through theirs (own, else inherited), which only the reentrant path
        // can run.
        register < self.config.max_registers
            && self
                .registers
                .get(self.register_base + register as usize)
                .is_some_and(|value| {
                    matches!(
                        value,
                        Value::Object(_)
                            | Value::Promise(_)
                            | Value::Generator(_)
                            | Value::AsyncGeneratorObject(_)
                            | Value::Iterator(_)
                    ) || value.is_callable()
                })
    }

    /// bd-9vouw.37: operand registers of the numeric operators whose object
    /// operands convert through ToPrimitive with hint "number" (ES2020
    /// 12.6-12.12 ToNumeric / 7.2.13 Abstract Relational Comparison).
    pub(super) fn numeric_conversion_operands(
        instruction: &Ir3Instruction,
    ) -> Option<(u32, Option<u32>)> {
        match instruction {
            Ir3Instruction::Sub { lhs, rhs, .. }
            | Ir3Instruction::Mul { lhs, rhs, .. }
            | Ir3Instruction::Div { lhs, rhs, .. }
            | Ir3Instruction::Mod { lhs, rhs, .. }
            | Ir3Instruction::Exp { lhs, rhs, .. }
            | Ir3Instruction::Lt { lhs, rhs, .. }
            | Ir3Instruction::Lte { lhs, rhs, .. }
            | Ir3Instruction::Gt { lhs, rhs, .. }
            | Ir3Instruction::Gte { lhs, rhs, .. }
            | Ir3Instruction::BitAnd { lhs, rhs, .. }
            | Ir3Instruction::BitOr { lhs, rhs, .. }
            | Ir3Instruction::BitXor { lhs, rhs, .. }
            | Ir3Instruction::Shl { lhs, rhs, .. }
            | Ir3Instruction::Shr { lhs, rhs, .. }
            | Ir3Instruction::Ushr { lhs, rhs, .. } => Some((*lhs, Some(*rhs))),
            Ir3Instruction::UnaryNeg { src, .. }
            | Ir3Instruction::UnaryPlus { src, .. }
            | Ir3Instruction::BitNot { src, .. }
            | Ir3Instruction::Inc { src, .. }
            | Ir3Instruction::Dec { src, .. } => Some((*src, None)),
            _ => None,
        }
    }

    /// ES2020 7.2.14 Abstract Equality converts an object operand with
    /// ToPrimitive (hint "default") only when the other operand is a
    /// non-nullish primitive; object == object is identity and null /
    /// undefined never convert (bd-9vouw.37).
    pub(super) fn loose_equality_needs_to_primitive(&self, lhs: u32, rhs: u32) -> bool {
        let peek = |register: u32| {
            (register < self.config.max_registers)
                .then(|| self.registers.get(self.register_base + register as usize))
                .flatten()
        };
        let converts_against = |register: u32| {
            matches!(
                peek(register),
                Some(
                    Value::Str(_)
                        | Value::Int(_)
                        | Value::Float(_)
                        | Value::Bool(_)
                        | Value::BigInt(_)
                        | Value::Symbol(_)
                )
            )
        };
        (self.register_needs_observable_to_primitive(lhs) && converts_against(rhs))
            || (self.register_needs_observable_to_primitive(rhs) && converts_against(lhs))
    }

    /// Whether a numeric operator has an object operand, or a loose equality
    /// compares an object with a primitive; only the reentrant Tier-R path can
    /// run that conversion (bd-9vouw.37).
    /// The instructions run_loop_dispatch's Tier-R arms always return to the
    /// reentrant path for: a HostCall (but the generator prologue's, which
    /// suspends there), the for-in / for-of iterator steps, IteratorClose,
    /// ArraySlice and SpreadIntoArray.
    pub(super) fn tier_r_always_reentrant(&self, instruction: &Ir3Instruction) -> bool {
        match instruction {
            Ir3Instruction::HostCall { capability, .. } => {
                !(self.suspend_at_generator_prologue
                    && capability.0 == crate::capability::GENERATOR_PROLOGUE_CAPABILITY)
            }
            Ir3Instruction::ForInInit { .. }
            | Ir3Instruction::ForInNext { .. }
            | Ir3Instruction::ForOfInit { .. }
            | Ir3Instruction::ForOfNext { .. }
            | Ir3Instruction::IteratorClose { .. }
            | Ir3Instruction::ArraySlice { .. }
            | Ir3Instruction::SpreadIntoArray { .. } => true,
            _ => false,
        }
    }

    pub(super) fn numeric_operator_needs_to_primitive(&self, instruction: &Ir3Instruction) -> bool {
        if let Ir3Instruction::Eq { lhs, rhs, .. } | Ir3Instruction::NotEq { lhs, rhs, .. } =
            instruction
        {
            return self.loose_equality_needs_to_primitive(*lhs, *rhs);
        }
        Self::numeric_conversion_operands(instruction).is_some_and(|(lhs, rhs)| {
            self.register_needs_observable_to_primitive(lhs)
                || rhs.is_some_and(|rhs| self.register_needs_observable_to_primitive(rhs))
        })
    }

    /// Compact tier-1 counterpart of the operand-conversion checks for `+`
    /// and the numeric operators (bd-9vouw.37). Unary cells keep their source
    /// in `lhs`.
    pub(super) fn compact_operator_needs_to_primitive(
        &self,
        compact: &CompactTier1Instruction,
    ) -> bool {
        use CompactTier1Opcode as Op;
        let needs =
            |register: u16| self.register_needs_observable_to_primitive(u32::from(register));
        match compact.opcode {
            Op::Add
            | Op::Sub
            | Op::Mul
            | Op::Div
            | Op::Mod
            | Op::Exp
            | Op::Lt
            | Op::Lte
            | Op::Gt
            | Op::Gte
            | Op::BitAnd
            | Op::BitOr
            | Op::BitXor
            | Op::Shl
            | Op::Shr
            | Op::Ushr => needs(compact.lhs) || needs(compact.rhs),
            Op::UnaryNeg | Op::UnaryPlus | Op::BitNot | Op::Inc | Op::Dec => needs(compact.lhs),
            Op::Eq | Op::NotEq => self
                .loose_equality_needs_to_primitive(u32::from(compact.lhs), u32::from(compact.rhs)),
            _ => false,
        }
    }

    /// ES2020 7.1.1 ToPrimitive with hint "number" for an operand register
    /// (bd-9vouw.37). Objects with guest conversion hooks run them, joining
    /// the methods' result label into `pending_hostcall_result_label`. An
    /// engine Date converts to its time value (Date.prototype.valueOf); other
    /// engine objects take their non-observable string form, which the
    /// numeric operator then converts with ToNumber (`[5]` -> "5" -> 5,
    /// `{}` -> "[object Object]" -> NaN).
    pub(super) fn observable_to_numeric_primitive_operand(
        &mut self,
        module: &Ir3Module,
        register: u32,
    ) -> Result<Value, InterpreterError> {
        let value = self.read_reg(register)?;
        if value.is_callable()
            || matches!(
                value,
                Value::Promise(_)
                    | Value::Generator(_)
                    | Value::AsyncGeneratorObject(_)
                    | Value::Iterator(_)
            )
        {
            // A function's own valueOf/toString, else Function.prototype.toString;
            // a promise's, generator object's or iterator's own or inherited.
            return self.coerce_runtime_primitive_with_hint(Some(module), value, "number");
        }
        let Value::Object(object_id) = value else {
            return Ok(value);
        };
        if !self.object_has_user_conversion_hook(object_id) {
            // A primitive wrapper's valueOf answers its primitive
            // (bd-9vouw.73); the operator applies ToNumber to it.
            if let Some(primitive) = self.primitive_wrapper_value(object_id) {
                return Ok(primitive.clone());
            }
            if let Some(time) = self
                .heap
                .get(object_id.0 as usize)
                .and_then(HeapObject::date_time)
            {
                self.observe_date_value_label(&value)?;
                return Ok(Value::Float(Float64::new(time)));
            }
            return self.engine_object_string_primitive(module, object_id);
        }
        self.coerce_runtime_primitive_with_hint(Some(module), value, "number")
    }

    /// ES2020 7.1.1 ToPrimitive for an operand register (hint "string" when
    /// `prefer_string`, else "default"). Objects with guest conversion hooks
    /// run them, joining the methods' result label into
    /// `pending_hostcall_result_label`; engine objects keep their
    /// non-observable string form; primitives pass through unchanged.
    pub(super) fn observable_to_primitive_operand(
        &mut self,
        module: &Ir3Module,
        register: u32,
        prefer_string: bool,
    ) -> Result<Value, InterpreterError> {
        let value = self.read_reg(register)?;
        // Functions, and promises, generator objects and iterators (no
        // property storage of their own), convert through their methods:
        // `gen + ''` is "[object Generator]", not "[object Object]".
        if value.is_callable()
            || matches!(
                value,
                Value::Promise(_)
                    | Value::Generator(_)
                    | Value::AsyncGeneratorObject(_)
                    | Value::Iterator(_)
            )
        {
            let hint = if prefer_string { "string" } else { "default" };
            return self.coerce_runtime_primitive_with_hint(Some(module), value, hint);
        }
        let Value::Object(object_id) = value else {
            return Ok(value);
        };
        if !self.object_has_user_conversion_hook(object_id) {
            // A primitive wrapper: valueOf answers its primitive (hint
            // "default"); toString answers its string form (hint "string").
            if let Some(primitive) = self.primitive_wrapper_value(object_id) {
                return Ok(match primitive {
                    Value::Str(_) => primitive.clone(),
                    other if prefer_string => Value::str(self.value_to_string(other)),
                    other => other.clone(),
                });
            }
            return self.engine_object_string_primitive(module, object_id);
        }
        let hint = if prefer_string { "string" } else { "default" };
        self.coerce_runtime_primitive_with_hint(Some(module), value, hint)
    }

    /// String form of an object with no guest conversion hook: an array runs
    /// Array.prototype.toString, i.e. the observable join, because its
    /// elements may define toString (bd-9vouw.37); other engine objects keep
    /// their established string form (plain objects "[object Object]").
    pub(super) fn engine_object_string_primitive(
        &mut self,
        module: &Ir3Module,
        object_id: ObjectId,
    ) -> Result<Value, InterpreterError> {
        self.observe_date_value_label(&Value::Object(object_id))?;
        if self
            .heap
            .get(object_id.0 as usize)
            .is_some_and(|object| object.is_array)
        {
            return self
                .array_join_observable(module, object_id, &JsString::from(","))
                .map(Value::Str);
        }
        Ok(Value::Str(JsString::from(
            self.object_to_coerced_string(object_id),
        )))
    }

    /// Whether the object or its prototype chain defines a guest `toString` /
    /// `valueOf` method or any `@@toPrimitive` property (bd-9vouw.37).
    pub(super) fn object_has_user_conversion_hook(&self, object_id: ObjectId) -> bool {
        let to_primitive = WellKnownSymbol::ToPrimitive.id();
        // A Date converts through Date.prototype[@@toPrimitive]: the
        // intrinsic one is not a guest hook, so a Date keeps its
        // non-observable string form, but a Date without it converts
        // generically (OrdinaryToPrimitive reads "default" as "number")
        // (bd-9vouw.259).
        let is_date = self
            .heap
            .get(object_id.0 as usize)
            .is_some_and(|object| object.brand() == Some("Date"));
        let object_prototype = self.builtin_prototypes.get("Object").copied();
        let mut reaches_object_prototype = false;
        let mut to_primitive_seen = false;
        let mut current = Some(object_id);
        // Bounded like the other prototype walks; a longer chain keeps the
        // non-observable conversion.
        for _ in 0..128 {
            let Some(id) = current else {
                break;
            };
            let Some(object) = self.heap.get(id.0 as usize) else {
                break;
            };
            reaches_object_prototype |= Some(id) == object_prototype;
            // The intrinsic prototypes supply their conversion methods
            // virtually, so a stored `toString` or `valueOf` is the program's:
            // a function, or a value OrdinaryToPrimitive skips (`null`, a
            // number) and an accessor, which only the generic path reads.
            // `{ valueOf: null, toString: null } + ''` is a TypeError; the
            // engine's string form answered "[object Object]".
            if object.properties.contains_key("toString")
                || object.properties.contains_key("valueOf")
            {
                return true;
            }
            // The first @@toPrimitive on the chain is the one ToPrimitive
            // calls.
            if !to_primitive_seen
                && let Some(hook) = object
                    .properties
                    .baseline_symbol_property(core_symbol_id(to_primitive))
            {
                if !matches!(hook, BaselineSymbolProperty::Data(Value::BuiltinFunction(builtin))
                    if builtin.kind == BuiltinFunctionKind::DatePrototypeToPrimitive)
                {
                    return true;
                }
                to_primitive_seen = true;
            }
            current = self.observable_prototype_link(object, id);
            // %Object.prototype% is materialized on first use; until then an
            // ordinary object's default link resolves to nothing here, yet
            // its chain does reach the intrinsic's virtual conversion
            // methods. Only an explicit null prototype ends a chain without
            // them. Reading the unmaterialized link as null sent every nested
            // array through a guest toString call (a call frame per level,
            // and a fresh cycle guard), and made the result depend on whether
            // earlier code had touched Object.prototype (bd-9vouw.481).
            if current.is_none() && object_prototype.is_none() && !object.is_null_prototype {
                reaches_object_prototype = true;
            }
        }
        // A chain that ends without %Object.prototype% (`Object.create(null)`)
        // has no conversion methods at all: OrdinaryToPrimitive throws.
        if current.is_none() && !reaches_object_prototype {
            return true;
        }
        is_date && !to_primitive_seen
    }

    /// Route an error raised while a reentrant instruction ran guest code: a
    /// guest throw unwinds to the nearest handler exactly like `throw`;
    /// anything else propagates.
    pub(super) fn route_reentrant_guest_error(
        &mut self,
        module: &Ir3Module,
        error: InterpreterError,
    ) -> Result<(), InterpreterError> {
        self.clear_pending_hostcall_result_label();
        match self.route_isolated_explicit_throw(module, error)? {
            None => Ok(()),
            Some(error) => Err(error),
        }
    }

    /// ToString for a template-literal substitution that is already a
    /// primitive, or an object handled by the non-observable fallback.
    pub(super) fn template_part_js_string(&self, val: Value) -> Result<JsString, InterpreterError> {
        Ok(match val {
            Value::Str(s) => s,
            Value::Int(n) => JsString::from(n.to_string()),
            Value::BigInt(n) => JsString::from(n.as_ref()),
            Value::Float(f) => JsString::from(f.to_string()),
            Value::Bool(b) => JsString::from(if b { "true" } else { "false" }),
            Value::Null => JsString::from("null"),
            Value::Undefined => JsString::from("undefined"),
            Value::Symbol(_) => {
                return Err(InterpreterError::TypeError {
                    expected: "template literal substitution coercible to string".to_string(),
                    got: "symbol".to_string(),
                });
            }
            Value::Object(id) => JsString::from(self.object_to_coerced_string(id)),
            Value::Iterator(_) | Value::Generator(_) | Value::Accessor { .. } => {
                JsString::from("[object Object]")
            }
            Value::Promise(_) => JsString::from("[object Promise]"),
            ref callable @ (Value::Function(_)
            | Value::Closure(_)
            | Value::GeneratorFunction(_)
            | Value::BuiltinFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncGeneratorFunction(_)) => {
                JsString::from(self.function_native_source_text(None, callable))
            }
            Value::AsyncFunctionObject(_) => JsString::from("function"),
            Value::AsyncGeneratorObject(_) => JsString::from("object"),
        })
    }

    /// bd-9vouw.279: ToPropertyKey(value) for a built-in's key argument
    /// (Object.defineProperty, getOwnPropertyDescriptor, hasOwn,
    /// hasOwnProperty, propertyIsEnumerable): an object key converts through
    /// its @@toPrimitive / toString / valueOf, which may throw. It was read
    /// with the engine's internal representation, so `[1, 2]` defined
    /// "[object#15]" instead of "1,2". Primitives come back unchanged.
    pub(super) fn coerce_to_property_key(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        if value.is_object_like() && module.is_some() {
            self.coerce_runtime_property_key(module, value)
        } else {
            Ok(value)
        }
    }

    /// Resolve observable ToPrimitive(string) hooks once. Source property names
    /// are coerced eagerly; saved assignment references defer this to PutValue.
    pub(super) fn coerce_runtime_property_key(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<Value, InterpreterError> {
        let primitive = self.coerce_runtime_primitive(module, value, true)?;
        let result = match primitive {
            Value::Str(_) | Value::Symbol(_) => primitive,
            Value::Int(number) => Value::str(ryu_js::Buffer::new().format(number as f64)),
            Value::Float(number) if number.inner().is_finite() => {
                let mut buffer = ryu_js::Buffer::new();
                Value::str(buffer.format(number.inner()))
            }
            Value::BigInt(digits) => {
                self.check_string_limit(digits.len())?;
                self.check_temporary_memory_budget((digits.len() as u64).saturating_mul(3))?;
                Value::str(digits.as_ref())
            }
            other => Value::str(self.value_to_string(&other)),
        };
        self.validate_executable_property_key(&self.executable_property_key_from_value(&result))?;
        Ok(result)
    }

    /// Shared observable ToPrimitive for property keys and array-like length.
    pub(super) fn coerce_runtime_primitive(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
        prefer_string: bool,
    ) -> Result<Value, InterpreterError> {
        let hint = if prefer_string { "string" } else { "number" };
        self.coerce_runtime_primitive_with_hint(module, value, hint)
    }

    /// ES2020 7.1.1.1 OrdinaryToPrimitive(O, hint): toString then valueOf
    /// for the "string" hint (`prefer_string`), valueOf then toString
    /// otherwise; the first primitive result wins, and two object results
    /// are a TypeError. Each method's result label joins the pending one.
    pub(super) fn ordinary_to_primitive(
        &mut self,
        module: Option<&Ir3Module>,
        object_id: ObjectId,
        value: &Value,
        prefer_string: bool,
    ) -> Result<Value, InterpreterError> {
        let names = if prefer_string {
            ["toString", "valueOf"]
        } else {
            ["valueOf", "toString"]
        };
        for name in names {
            let method = self.iterator_protocol_property(
                module,
                object_id,
                &RuntimePropertyKey::String(JsString::from(name)),
                value.clone(),
            )?;
            self.observe_scoped_callback_result()?;
            if !method.is_callable() {
                continue;
            }
            let (result, label) = self.invoke_inline_method_call_with_argument_label(
                module,
                method,
                value.clone(),
                Vec::new(),
                None,
            )?;
            let label = self
                .pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public)
                .join(&label);
            self.replace_pending_hostcall_result_label(Some(label))?;
            self.observe_scoped_callback_result()?;
            if !result.is_object_like() {
                return Ok(result);
            }
        }
        Err(InterpreterError::TypeError {
            expected: "primitive conversion result".to_string(),
            got: "object from both conversion methods".to_string(),
        })
    }

    /// ES2020 7.1.1 ToPrimitive with an explicit hint: "string", "number" or
    /// "default" (`+` and `==`). @@toPrimitive receives the hint; without it
    /// OrdinaryToPrimitive tries toString first only for "string".
    pub(super) fn coerce_runtime_primitive_with_hint(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
        hint: &'static str,
    ) -> Result<Value, InterpreterError> {
        let prefer_string = hint == "string";
        Ok(if value.is_object_like() {
            if let Some(object_id) =
                self.iterator_carrier_backing_id(&value, "property key object")?
            {
                let exotic_key = RuntimePropertyKey::Symbol(WellKnownSymbol::ToPrimitive.id());
                let exotic = self.optional_callable_runtime_property(
                    module,
                    object_id,
                    &exotic_key,
                    value.clone(),
                )?;
                self.observe_scoped_callback_result()?;
                match exotic {
                    // Date.prototype[@@toPrimitive] (ES2020 20.3.4.45) is
                    // OrdinaryToPrimitive with "default" read as "string"
                    // (bd-9vouw.259).
                    Some(Value::BuiltinFunction(builtin))
                        if builtin.kind == BuiltinFunctionKind::DatePrototypeToPrimitive =>
                    {
                        self.ordinary_to_primitive(module, object_id, &value, hint != "number")?
                    }
                    Some(method) => {
                        let (result, label) = self.invoke_inline_method_call_with_argument_label(
                            module,
                            method,
                            value.clone(),
                            vec![Value::str(hint)],
                            None,
                        )?;
                        let label = self
                            .pending_hostcall_result_label
                            .as_ref()
                            .unwrap_or(&Label::Public)
                            .join(&label);
                        self.replace_pending_hostcall_result_label(Some(label))?;
                        self.observe_scoped_callback_result()?;
                        if result.is_object_like() {
                            return Err(InterpreterError::TypeError {
                                expected: "primitive from Symbol.toPrimitive".to_string(),
                                got: result.type_name().to_string(),
                            });
                        }
                        result
                    }
                    None => self.ordinary_to_primitive(module, object_id, &value, prefer_string)?,
                }
            } else if value.is_callable() {
                // Functions have no @@toPrimitive, so OrdinaryToPrimitive
                // reaches Function.prototype.toString unless the function
                // has its own `toString`/`valueOf` (Object.prototype.valueOf
                // returns the function itself and is skipped).
                let names = if prefer_string {
                    ["toString", "valueOf"]
                } else {
                    ["valueOf", "toString"]
                };
                let backing = match module {
                    Some(module) => self.function_own_property_object(module, &value)?,
                    None => None,
                };
                let mut primitive = None;
                for name in names {
                    let own = backing.and_then(|backing| {
                        self.heap
                            .get(backing.0 as usize)
                            .and_then(|object| object.properties.get(name).cloned())
                    });
                    let Some(method) = own.filter(Value::is_callable) else {
                        if name == "toString" {
                            primitive =
                                Some(Value::str(self.function_native_source_text(module, &value)));
                            break;
                        }
                        continue;
                    };
                    let (result, label) = self.invoke_inline_method_call_with_argument_label(
                        module,
                        method,
                        value.clone(),
                        Vec::new(),
                        None,
                    )?;
                    let label = self
                        .pending_hostcall_result_label
                        .as_ref()
                        .unwrap_or(&Label::Public)
                        .join(&label);
                    self.replace_pending_hostcall_result_label(Some(label))?;
                    self.observe_scoped_callback_result()?;
                    if !result.is_object_like() {
                        primitive = Some(result);
                        break;
                    }
                }
                primitive.ok_or_else(|| InterpreterError::TypeError {
                    expected: "primitive conversion result".to_string(),
                    got: "object from both conversion methods".to_string(),
                })?
            } else if let Some(module) = module {
                self.exotic_to_primitive(module, value, hint)?
            } else {
                // No program to run a conversion method in: the builtinTag
                // Object.prototype.toString would answer.
                Value::str(Self::value_to_object_to_string_tag(&value))
            }
        } else {
            value
        })
    }

    /// ES2020 7.1.1 ToPrimitive of a promise, generator, async generator or
    /// iterator value (no property storage of its own): @@toPrimitive, else
    /// OrdinaryToPrimitive over `toString`/`valueOf`, each read like [[Get]]
    /// (own properties, then Promise.prototype or Object.prototype), so
    /// `String(promise)` is "[object Promise]" through
    /// Object.prototype.toString. These values threw a TypeError.
    pub(super) fn exotic_to_primitive(
        &mut self,
        module: &Ir3Module,
        value: Value,
        hint: &'static str,
    ) -> Result<Value, InterpreterError> {
        let to_primitive = RuntimePropertyKey::Symbol(WellKnownSymbol::ToPrimitive.id());
        let exotic = self.exotic_conversion_method(module, &value, &to_primitive)?;
        if exotic.is_callable() {
            let result =
                self.call_conversion_method(module, exotic, &value, vec![Value::str(hint)])?;
            if result.is_object_like() {
                return Err(InterpreterError::TypeError {
                    expected: "primitive from Symbol.toPrimitive".to_string(),
                    got: result.type_name().to_string(),
                });
            }
            return Ok(result);
        }
        let names = if hint == "string" {
            ["toString", "valueOf"]
        } else {
            ["valueOf", "toString"]
        };
        for name in names {
            let method = self.exotic_conversion_method(
                module,
                &value,
                &RuntimePropertyKey::String(JsString::from(name)),
            )?;
            if !method.is_callable() {
                continue;
            }
            let result = self.call_conversion_method(module, method, &value, Vec::new())?;
            if !result.is_object_like() {
                return Ok(result);
            }
        }
        Err(InterpreterError::TypeError {
            expected: "primitive conversion result".to_string(),
            got: "object from both conversion methods".to_string(),
        })
    }

    /// Call a conversion method with `value` as `this`, joining its result
    /// label into the pending hostcall result label.
    pub(super) fn call_conversion_method(
        &mut self,
        module: &Ir3Module,
        method: Value,
        value: &Value,
        arguments: Vec<Value>,
    ) -> Result<Value, InterpreterError> {
        let (result, label) = self.invoke_inline_method_call_with_argument_label(
            Some(module),
            method,
            value.clone(),
            arguments,
            None,
        )?;
        let label = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&label);
        self.replace_pending_hostcall_result_label(Some(label))?;
        self.observe_scoped_callback_result()?;
        Ok(result)
    }

    /// ES2020 7.3.2 GetV(V, P): [[Get]] of `key` on any value, with `value`
    /// as the receiver; a primitive reads its prototype's (ToObject is not
    /// observable here). Undefined and null are a TypeError.
    pub(super) fn get_v(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<Value, InterpreterError> {
        self.get_v_with_receiver(module, value, key, value.clone(), 0)
    }

    /// [[Get]] of `key` on any value with an explicit receiver (the `this` of
    /// a getter): an object's (Proxy-aware), a function's own and
    /// synthesized members then Function.prototype's, a primitive's
    /// prototype's. `Reflect.get(fn, key, receiver)` and the fallback of a
    /// callable proxy without a `get` trap read functions through it.
    pub(super) fn get_v_with_receiver(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        key: &RuntimePropertyKey,
        receiver: Value,
        depth: u32,
    ) -> Result<Value, InterpreterError> {
        let prototype = match value {
            Value::Object(object_id) => {
                return self.proxy_aware_get_runtime_property(
                    Some(module),
                    *object_id,
                    key,
                    receiver,
                    depth,
                );
            }
            Value::BuiltinFunction(builtin)
                if matches!(
                    builtin.kind,
                    BuiltinFunctionKind::CallableProxy | BuiltinFunctionKind::FunctionPrototype
                ) =>
            {
                let backing = Self::builtin_function_property_object(builtin).ok_or_else(|| {
                    InterpreterError::TypeError {
                        expected: "built-in function with property storage".to_string(),
                        got: builtin.display_name().to_string(),
                    }
                })?;
                return self.proxy_aware_get_runtime_property(
                    Some(module),
                    backing,
                    key,
                    receiver,
                    depth,
                );
            }
            Value::Promise(_)
            | Value::Generator(_)
            | Value::AsyncGeneratorObject(_)
            | Value::Iterator(_) => return self.exotic_conversion_method(module, value, key),
            Value::Undefined | Value::Null => {
                return Err(InterpreterError::TypeError {
                    expected: "object-coercible value".to_string(),
                    got: value.type_name().to_string(),
                });
            }
            callable if callable.is_callable() => {
                if let Some(own) =
                    self.function_own_get(module, callable, key, receiver.clone(), depth)?
                {
                    return Ok(own);
                }
                if let Some(parent) = Self::native_error_constructor_parent(callable) {
                    return self.get_v_with_receiver(
                        module,
                        &parent,
                        key,
                        receiver,
                        depth.saturating_add(1),
                    );
                }
                let prototype =
                    Self::function_intrinsic_prototype_name(callable).unwrap_or("Function");
                if prototype != "Function" {
                    self.ensure_builtin_prototype(prototype)?;
                }
                prototype
            }
            Value::Str(_) => "String",
            Value::Bool(_) => "Boolean",
            Value::BigInt(_) => "BigInt",
            Value::Symbol(_) => "Symbol",
            Value::Int(_) | Value::Float(_) => "Number",
            _ => "Object",
        };
        Ok(self
            .primitive_prototype_get(module, prototype, key, receiver)?
            .0)
    }

    /// A function's own or synthesized member `key`, as the GetProperty
    /// instruction reads it: its backing object's (own, or inherited there
    /// as a class's parent statics; a deleted `name` / `length` falls to
    /// Function.prototype), else its `name`, `length`, `prototype`, a bound
    /// function's or a standard constructor's members and Function.prototype's
    /// builtins. `None` when the read continues on its intrinsic prototype.
    pub(super) fn function_own_get(
        &mut self,
        module: &Ir3Module,
        function: &Value,
        key: &RuntimePropertyKey,
        receiver: Value,
        depth: u32,
    ) -> Result<Option<Value>, InterpreterError> {
        if let Some(backing) =
            self.authoritative_standard_constructor_backing(module, function, key)?
        {
            if self
                .heap
                .get(backing.0 as usize)
                .is_some_and(|object| object.contains_own_runtime_property(key))
            {
                return self
                    .proxy_aware_get_runtime_property(Some(module), backing, key, receiver, depth)
                    .map(Some);
            }
            let prototype = self.function_value_prototype(Some(module), function)?;
            return if matches!(prototype, Value::Null) {
                Ok(Some(Value::Undefined))
            } else {
                self.get_v_with_receiver(module, &prototype, key, receiver, depth.saturating_add(1))
                    .map(Some)
            };
        }
        let name_or_length = matches!(key.as_str(), Some("name" | "length"));
        if (key.as_str() != Some("prototype")
            || !self.function_has_intrinsic_prototype(function)
            || self.function_backing_has_own_property(module, function, key)?)
            && let Some(backing) = self.function_own_property_object(module, function)?
        {
            let own = self
                .heap
                .get(backing.0 as usize)
                .is_some_and(|object| object.contains_own_runtime_property(key));
            if own || (!name_or_length && self.chain_contains_runtime_property(backing, key)) {
                return self
                    .proxy_aware_get_runtime_property(Some(module), backing, key, receiver, depth)
                    .map(Some);
            }
            if name_or_length {
                return Ok(None);
            }
        }
        let Some(name) = key.as_str() else {
            return Ok(None);
        };
        let value = match function {
            Value::Function(index) => self.function_property_value(module, *index, name)?,
            Value::Closure(closure_id) => {
                let owner_module = self.foreign_closure_module(function, module)?;
                self.closure_property_value(
                    owner_module.as_deref().unwrap_or(module),
                    *closure_id,
                    name,
                )?
            }
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::GeneratedFunction
                    && name == "prototype" =>
            {
                Value::Object(self.ensure_generated_function_prototype(builtin)?)
            }
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::BoundFunction =>
            {
                match self.bound_function_property(builtin, name)? {
                    Some(value) => value,
                    None => Self::function_prototype_property(name).unwrap_or(Value::Undefined),
                }
            }
            Value::BuiltinFunction(builtin)
                if name == "prototype"
                    && Self::materialized_global_prototype_name(builtin).is_some() =>
            {
                let prototype = Self::materialized_global_prototype_name(builtin)
                    .expect("checked by the guard");
                self.builtin_prototype_value(prototype)?
            }
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::Require && name == "main" =>
            {
                self.cjs_main_module()
            }
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::Require && name == "resolve" =>
            {
                Value::BuiltinFunction(BuiltinFunction::require_resolve(builtin))
            }
            Value::BuiltinFunction(builtin)
                if Self::builtin_function_property_object(builtin).is_some() =>
            {
                let property_object =
                    Self::builtin_function_property_object(builtin).expect("checked by the guard");
                self.proxy_aware_get_runtime_property(
                    Some(module),
                    property_object,
                    key,
                    receiver,
                    depth,
                )?
            }
            Value::BuiltinFunction(builtin)
                if builtin.kind == BuiltinFunctionKind::StandardConstructor =>
            {
                self.standard_constructor_property(builtin, name)?
            }
            Value::GeneratorFunction(_) | Value::AsyncGeneratorFunction(_)
                if name == "prototype" =>
            {
                self.generator_function_prototype(module, function)?
                    .unwrap_or(Value::Undefined)
            }
            other => match name {
                "name" | "length" => self
                    .function_standard_own_value(module, other, name)?
                    .unwrap_or(Value::Undefined),
                _ => Self::function_prototype_property(name).unwrap_or(Value::Undefined),
            },
        };
        Ok((!matches!(value, Value::Undefined)).then_some(value))
    }

    /// [[Get]] of a conversion method on a promise, generator, async
    /// generator or iterator value: its own properties, then Promise.prototype
    /// (for a promise) or Object.prototype.
    pub(super) fn exotic_conversion_method(
        &mut self,
        module: &Ir3Module,
        value: &Value,
        key: &RuntimePropertyKey,
    ) -> Result<Value, InterpreterError> {
        if Self::has_exotic_backing_object(value)
            && let Some((own, _)) = self.exotic_own_property_get(module, value, key)?
        {
            return Ok(own);
        }
        if let Some(prototype) = self.exotic_prototype_override(module, value)? {
            return self.proxy_aware_get_runtime_property(
                Some(module),
                prototype,
                key,
                value.clone(),
                0,
            );
        }
        // The intrinsic prototype is materialized for the read: it holds the
        // built-in members, such as an array or Map iterator's `next`, which
        // Object.prototype does not (the Set methods call `keys().next`
        // through [[Get]], bd-9vouw.161).
        let prototype = self
            .exotic_intrinsic_prototype_name(value)
            .unwrap_or("Object");
        self.ensure_builtin_prototype(prototype)?;
        Ok(self
            .primitive_prototype_get(module, prototype, key, value.clone())?
            .0)
    }

    pub(super) fn require_object_coercible(value: Value) -> Result<Value, InterpreterError> {
        if matches!(value, Value::Null | Value::Undefined) {
            return Err(InterpreterError::TypeError {
                expected: "non-nullish object destructuring source".to_string(),
                got: value.type_name().to_string(),
            });
        }
        Ok(value)
    }

    // -- Promise hostcall dispatch ------------------------------------------

    /// Convert a baseline `Value` that `JsValue` can express exactly:
    /// primitives other than BigInt, well-formed strings, symbols, objects and
    /// function indices. Use [`Self::promise_value`] for arbitrary values.
    pub(super) fn value_to_js_value(val: &Value) -> crate::object_model::JsValue {
        match val {
            Value::Undefined => crate::object_model::JsValue::Undefined,
            Value::Null => crate::object_model::JsValue::Null,
            Value::Bool(b) => crate::object_model::JsValue::Bool(*b),
            Value::Int(n) => crate::object_model::JsValue::Int(*n),
            Value::Float(f) => crate::object_model::JsValue::Float(f.inner().to_bits()),
            Value::Str(s) => crate::object_model::JsValue::Str(s.to_string()),
            Value::Symbol(symbol) => crate::object_model::JsValue::Symbol(*symbol),
            Value::Object(id) => {
                crate::object_model::JsValue::Object(crate::object_model::ObjectHandle(id.0))
            }
            Value::Function(idx) => crate::object_model::JsValue::Function(*idx),
            _ => crate::object_model::JsValue::Str(val.to_string()),
        }
    }

    /// Convert any `Value` for the promise subsystem without loss
    /// (bd-9vouw.69). Values `JsValue` cannot express exactly (closures,
    /// generators, iterators, promises, builtin and bound functions, BigInt,
    /// accessors, non-well-formed strings) travel as a carrier id charged to
    /// the memory budget; [`Self::js_value_to_value`] restores them.
    pub(super) fn promise_value(
        &mut self,
        value: &Value,
    ) -> Result<crate::object_model::JsValue, InterpreterError> {
        let representable = match value {
            Value::Undefined
            | Value::Null
            | Value::Bool(_)
            | Value::Int(_)
            | Value::Float(_)
            | Value::Symbol(_)
            | Value::Object(_)
            | Value::Function(_) => true,
            Value::Str(text) => text.as_str().is_some(),
            _ => false,
        };
        if representable {
            return Ok(Self::value_to_js_value(value));
        }
        let id = self.next_promise_value_carrier;
        let next = id
            .checked_add(1)
            .ok_or_else(|| InterpreterError::TypeError {
                expected: "promise value carrier capacity".to_string(),
                got: format!("carrier id {id} exhausted"),
            })?;
        self.apply_memory_component_delta(0, Self::estimate_promise_value_carrier_bytes(value))?;
        self.promise_value_carriers.insert(id, value.clone());
        self.next_promise_value_carrier = next;
        Ok(crate::object_model::JsValue::Function(id))
    }

    pub(super) fn estimate_promise_value_carrier_bytes(value: &Value) -> u64 {
        MEMORY_ESTIMATE_MAP_ENTRY_BYTES.saturating_add(Self::estimate_value_bytes(value))
    }

    pub(super) fn promise_value_carriers_memory_bytes(&self) -> u64 {
        Self::saturating_sum(
            self.promise_value_carriers
                .values()
                .map(Self::estimate_promise_value_carrier_bytes),
        )
    }

    /// Convert a promise-subsystem `JsValue` back, restoring carried values.
    pub(super) fn js_value_to_value(&self, jv: &crate::object_model::JsValue) -> Value {
        match jv {
            crate::object_model::JsValue::Undefined => Value::Undefined,
            crate::object_model::JsValue::Null => Value::Null,
            crate::object_model::JsValue::Bool(b) => Value::Bool(*b),
            crate::object_model::JsValue::Int(n) => Value::Int(*n),
            crate::object_model::JsValue::Str(s) => Value::str(s.as_str()),
            crate::object_model::JsValue::Float(bits) => {
                Value::Float(Float64::new(f64::from_bits(*bits)))
            }
            crate::object_model::JsValue::Object(handle) => Value::Object(ObjectId(handle.0)),
            crate::object_model::JsValue::Function(idx) if *idx >= PROMISE_VALUE_CARRIER_BASE => {
                self.promise_value_carriers
                    .get(idx)
                    .cloned()
                    .unwrap_or_else(|| panic!("use of reclaimed promise value carrier {idx}"))
            }
            crate::object_model::JsValue::Function(idx) => Value::Function(*idx),
            crate::object_model::JsValue::Symbol(symbol) => Value::Symbol(*symbol),
        }
    }

    pub(super) fn collect_promise_combinator_inputs(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Vec<Value>, InterpreterError> {
        if args.count == 0 {
            return Ok(Vec::new());
        }
        let first = self.read_reg(args.start)?;
        if args.count == 1 {
            return self.promise_combinator_iterable_values(module, first);
        }
        let mut values = Vec::with_capacity(args.count as usize);
        for i in 0..args.count {
            let reg = args
                .start
                .checked_add(i)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
            values.push(self.read_reg(reg)?);
        }
        Ok(values)
    }

    /// IterableToList of a Promise combinator's argument (ES2020 25.6.4.1
    /// steps 3-5): an ordinary array with the builtin iterator is read
    /// directly; anything else goes through the for-of protocol, so a Set, a
    /// Map's `values()`, a generator or a user iterable work, and a
    /// non-iterable is an error the caller turns into a rejection. (An
    /// object's indexed properties were read instead, so `Promise.all(set)`
    /// resolved to `[]`, and a non-object, a generator included, was a
    /// single input.)
    pub(super) fn promise_combinator_iterable_values(
        &mut self,
        module: Option<&Ir3Module>,
        iterable: Value,
    ) -> Result<Vec<Value>, InterpreterError> {
        if let Value::Object(array_id) = iterable
            && self
                .heap
                .get(array_id.0 as usize)
                .is_some_and(|object| object.is_array)
            && !self.array_from_has_explicit_iterator(array_id)?
        {
            return self.array_like_values(array_id);
        }
        let iterator = self.init_for_of_iterator(module, iterable)?;
        let mut values = Vec::new();
        while let Some(value) = self.advance_for_of_iterator(module, iterator.clone())? {
            values.push(value);
        }
        Ok(values)
    }

    /// IfAbruptRejectPromise for a combinator's iterable: a guest-visible
    /// failure (not iterable, a throwing iterator) rejects the returned
    /// promise instead of throwing; a resource refusal stays an interpreter
    /// error.
    pub(super) fn reject_promise_combinator_input(
        &mut self,
        error: InterpreterError,
    ) -> Result<Value, InterpreterError> {
        let (thrown, label) = if matches!(error, InterpreterError::UncaughtException { .. }) {
            match self.take_pending_exception_slot() {
                Some(slot) => slot,
                None => return Err(error),
            }
        } else if Self::js_catchable_error_name(&error).is_some() {
            (self.native_error_to_thrown_value(&error)?, Label::Public)
        } else {
            return Err(error);
        };
        let promise = self.create_promise()?;
        self.reject_promise(promise, Self::value_to_js_value(&thrown), label)?;
        Ok(Value::Promise(promise.0))
    }

    pub(super) fn read_array_like_values(&self, obj_id: ObjectId) -> Vec<Value> {
        self.array_like_values(obj_id).unwrap_or_default()
    }

    pub(super) fn alloc_array_from_values(
        &mut self,
        values: &[Value],
    ) -> Result<ObjectId, InterpreterError> {
        let id = self.alloc_array_with_prototype(None)?;
        for (index, value) in values.iter().cloned().enumerate() {
            self.set_object_property(id, index.to_string(), value)?;
        }
        let length = values.len() as i64;
        self.set_object_property(id, "length".to_string(), Value::Int(length))?;
        // Update cached dense length
        let obj_index = id.0 as usize;
        let cached_length = length as u32;
        self.mutate_heap(|heap| {
            if let Some(obj) = heap.get_mut(obj_index) {
                obj.cached_dense_length = Some(cached_length);
            }
        });
        Ok(id)
    }

    pub(super) fn alloc_object_with_properties(
        &mut self,
        props: &[(&str, Value)],
    ) -> Result<ObjectId, InterpreterError> {
        let id = self.alloc_object_with_prototype(None)?;
        for (key, value) in props {
            self.set_object_property(id, (*key).to_string(), value.clone())?;
        }
        Ok(id)
    }

    /// A host object of kind `brand` (bd-9vouw.150) with `props`.
    pub(super) fn alloc_branded_object(
        &mut self,
        brand: &str,
        props: &[(&str, Value)],
    ) -> Result<ObjectId, InterpreterError> {
        let id = self.alloc_object_with_properties(props)?;
        self.set_object_brand(id, brand)?;
        Ok(id)
    }

    pub(super) fn build_promise_all_result(
        &mut self,
        values: Vec<crate::object_model::JsValue>,
    ) -> Result<crate::object_model::JsValue, InterpreterError> {
        let value_objs: Vec<Value> = values
            .iter()
            .map(|value| self.js_value_to_value(value))
            .collect();
        let array_id = self.alloc_array_from_values(&value_objs)?;
        Ok(Self::value_to_js_value(&Value::Object(array_id)))
    }

    pub(super) fn build_aggregate_error(
        &mut self,
        errors: Vec<crate::object_model::JsValue>,
    ) -> Result<crate::object_model::JsValue, InterpreterError> {
        let error_values: Vec<Value> = errors
            .iter()
            .map(|value| self.js_value_to_value(value))
            .collect();
        let errors_array = self.alloc_array_from_values(&error_values)?;
        self.build_aggregate_error_from_array(errors_array)
    }

    pub(super) fn build_aggregate_error_from_array(
        &mut self,
        errors_array: ObjectId,
    ) -> Result<crate::object_model::JsValue, InterpreterError> {
        // bd-9vouw.75: an AggregateError instance, as Promise.any specifies
        // (ES2021 27.2.4.3.1 step 8), not a plain object named like one.
        let prototype = self.ensure_builtin_prototype("AggregateError")?;
        let error_id = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_object(error_id, Some("All promises were rejected".to_string()))?;
        self.set_object_property(error_id, "errors".to_string(), Value::Object(errors_array))?;
        self.set_own_property_attributes(
            error_id,
            &RuntimePropertyKey::String(JsString::from("errors")),
            NON_ENUMERABLE_DATA_ATTRIBUTES,
        )?;
        Ok(Self::value_to_js_value(&Value::Object(error_id)))
    }

    /// Count scratch ownership alongside the currently dequeued job, so even
    /// a nested memory reconciliation retains the reservation. Release it on
    /// every exit; callers must root their locals before any observable call.
    pub(super) fn with_promise_temporary_bytes<T>(
        &mut self,
        bytes: u64,
        operation: impl FnOnce(&mut Self) -> Result<T, InterpreterError>,
    ) -> Result<T, InterpreterError> {
        self.apply_memory_component_delta(0, bytes)?;
        self.promise_in_flight_task_bytes = self.promise_in_flight_task_bytes.saturating_add(bytes);
        let result = operation(self);
        self.promise_in_flight_task_bytes = self.promise_in_flight_task_bytes.saturating_sub(bytes);
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(bytes);
        result
    }

    pub(super) fn native_combinator_element(
        &self,
        combinator_id: u64,
        index: u32,
    ) -> Option<(&crate::object_model::JsValue, Option<&str>)> {
        match self.promise_combinators.get(&combinator_id)? {
            PromiseCombinatorState::All(tracker) => {
                tracker.values.get(&index).map(|value| (value, None))
            }
            PromiseCombinatorState::AllSettled(tracker) => tracker
                .outcomes
                .get(&index)
                .map(|outcome| (&outcome.value, Some(outcome.status.as_str()))),
            PromiseCombinatorState::Any(tracker) => {
                tracker.errors.get(&index).map(|value| (value, None))
            }
            PromiseCombinatorState::Race(_) => None,
        }
    }

    /// Materialize directly from the retained tracker. There is no cloned
    /// result map or full-length temporary vector: only one converted value,
    /// its bounded index key and an optional allSettled status coexist with
    /// the already-accounted tracker and destination heap objects.
    pub(super) fn build_native_combinator_result(
        &mut self,
        combinator_id: u64,
    ) -> Result<crate::object_model::JsValue, InterpreterError> {
        let (total, aggregate_error) = match self.promise_combinators.get(&combinator_id) {
            Some(PromiseCombinatorState::All(tracker)) => (tracker.total, false),
            Some(PromiseCombinatorState::AllSettled(tracker)) => (tracker.total, false),
            Some(PromiseCombinatorState::Any(tracker)) => (tracker.total, true),
            _ => {
                return Err(InterpreterError::InternalError {
                    details: "missing completed native combinator tracker".to_string(),
                });
            }
        };
        let array = self.alloc_array_with_prototype(None)?;
        for index in 0..total {
            let (value, status) = self
                .native_combinator_element(combinator_id, index)
                .expect("completed bounded tracker has every element");
            let value_bytes = match value {
                crate::object_model::JsValue::Str(text) => Self::estimate_string_bytes(text),
                crate::object_model::JsValue::Function(id) if *id >= PROMISE_VALUE_CARRIER_BASE => {
                    self.promise_value_carriers
                        .get(id)
                        .map_or(0, Self::estimate_value_bytes)
                }
                _ => 0,
            };
            let index_digits = u64::from(index.checked_ilog10().unwrap_or(0) + 1);
            let key_bytes = MEMORY_ESTIMATE_STRING_BASE_BYTES.saturating_add(index_digits.max(6));
            let status_bytes = status.map_or(0, Self::estimate_string_bytes);
            self.with_promise_temporary_bytes(
                value_bytes
                    .saturating_add(key_bytes)
                    .saturating_add(status_bytes),
                |core| {
                    let (value, status) = core
                        .native_combinator_element(combinator_id, index)
                        .expect("native construction invokes no guest code");
                    let value = core.js_value_to_value(value);
                    let status = status.map(|status| (Value::str(status), status == "fulfilled"));
                    let element = if let Some((status, fulfilled)) = status {
                        let entry = core.alloc_object_with_prototype(None)?;
                        core.set_object_property(entry, "status".to_string(), status)?;
                        core.set_object_property(
                            entry,
                            if fulfilled { "value" } else { "reason" }.to_string(),
                            value,
                        )?;
                        Value::Object(entry)
                    } else {
                        value
                    };
                    core.set_object_property(array, index.to_string(), element)
                },
            )?;
        }
        self.with_promise_temporary_bytes(Self::estimate_string_bytes("length"), |core| {
            core.set_object_property(array, "length".to_string(), Value::Int(i64::from(total)))
        })?;
        if aggregate_error {
            self.build_aggregate_error_from_array(array)
        } else {
            Ok(crate::object_model::JsValue::Object(
                crate::object_model::ObjectHandle(array.0),
            ))
        }
    }

    pub(super) fn register_combinator(
        &mut self,
        state: PromiseCombinatorState,
    ) -> Result<u64, InterpreterError> {
        let id = self.next_promise_combinator_id;
        let next_id = id
            .checked_add(1)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "Promise combinator id space exhausted".to_string(),
            })?;
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let entry_bytes = Self::promise_combinator_entry_bytes(&state);
        self.promise_combinators.insert(id, state);
        self.promise_combinators_bytes = self.promise_combinators_bytes.saturating_add(entry_bytes);
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_promise_bytes) {
            self.promise_combinators.remove(&id);
            self.promise_combinators_bytes =
                self.promise_combinators_bytes.saturating_sub(entry_bytes);
            return Err(error);
        }
        self.next_promise_combinator_id = next_id;
        Ok(id)
    }

    pub(super) fn add_combinator_watcher(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        watcher: PromiseCombinatorWatcher,
    ) -> Result<(), InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        // One more watcher, and a new map entry when the promise had none.
        let added_bytes = if self.promise_combinator_watchers.contains_key(&handle) {
            Self::promise_combinator_watchers_bytes_for(1)
        } else {
            Self::promise_combinator_watcher_entry_bytes(1)
        };
        self.promise_combinator_watchers
            .entry(handle)
            .or_default()
            .push(watcher);
        self.promise_combinator_watchers_bytes = self
            .promise_combinator_watchers_bytes
            .saturating_add(added_bytes);
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_promise_bytes) {
            let remove_entry =
                if let Some(watchers) = self.promise_combinator_watchers.get_mut(&handle) {
                    watchers.pop();
                    watchers.is_empty()
                } else {
                    false
                };
            if remove_entry {
                self.promise_combinator_watchers.remove(&handle);
            }
            self.promise_combinator_watchers_bytes = self
                .promise_combinator_watchers_bytes
                .saturating_sub(added_bytes);
            return Err(error);
        }
        Ok(())
    }

    /// Register a native element in the same reaction list as ordinary
    /// `.then`, so a pending input's later settlement keeps registration order.
    /// Watchers only retain dependency ownership for fatal cleanup; they no
    /// longer settle an aggregate synchronously (bd-9vouw.295).
    pub(super) fn register_native_combinator_reaction(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        result_promise: crate::promise_model::PromiseHandle,
        watcher: PromiseCombinatorWatcher,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let pending = !self.promise_is_settled(handle);
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let (next_store_bytes, next_queue_bytes) = self
            .promise_store
            .projected_then_into_memory_bytes(handle, &label, &self.event_loop.microtasks)
            .map_err(|error| InterpreterError::TypeError {
                expected: "valid combinator input promise".to_string(),
                got: error.to_string(),
            })?;
        let next_promise_bytes = previous_promise_bytes
            .saturating_sub(self.promise_store.estimated_memory_bytes())
            .saturating_sub(self.event_loop.microtasks.estimated_memory_bytes())
            .saturating_add(next_store_bytes)
            .saturating_add(next_queue_bytes);
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
        self.promise_store
            .then_for_combinator(
                handle,
                result_promise,
                label,
                crate::promise_model::PromiseCombinatorReaction {
                    combinator_id: watcher.combinator_id,
                    index: watcher.index,
                },
                &mut self.event_loop.microtasks,
            )
            .expect("preflighted native combinator reaction remains valid");
        self.settle_projected_promise_bytes(next_promise_bytes)?;
        if pending {
            self.add_combinator_watcher(handle, watcher)?;
        }
        Ok(())
    }

    pub(super) fn enqueue_native_combinator_job(
        &mut self,
        job: crate::promise_model::Microtask,
    ) -> Result<(), InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let previous_queue_bytes = self.event_loop.microtasks.estimated_memory_bytes();
        let next_queue_bytes = self
            .event_loop
            .microtasks
            .projected_enqueue_memory_bytes(&job);
        let next_promise_bytes = previous_promise_bytes
            .saturating_sub(previous_queue_bytes)
            .saturating_add(next_queue_bytes);
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
        self.event_loop.microtasks.enqueue(job);
        self.settle_projected_promise_bytes(next_promise_bytes)
    }

    pub(super) fn join_combinator_result_label(
        &mut self,
        result_promise: crate::promise_model::PromiseHandle,
        label: &Label,
    ) -> Result<(), InterpreterError> {
        let previous_store_bytes = self.promise_store.estimated_memory_bytes();
        let next_store_bytes = self
            .promise_store
            .projected_join_label_memory_bytes(result_promise, label)
            .map_err(|error| InterpreterError::InternalError {
                details: format!("missing native combinator result: {error}"),
            })?;
        self.apply_memory_component_delta(previous_store_bytes, next_store_bytes)?;
        self.promise_store
            .join_label(result_promise, label)
            .expect("preflighted combinator result remains valid");
        Ok(())
    }

    /// Admit both the label and the map entry before either owner changes.
    /// A native job has no guest callback, so its tracker cannot change
    /// between this preflight and the following record operation.
    pub(super) fn prepare_combinator_observation(
        &mut self,
        combinator_id: u64,
        index: u32,
        kind: crate::promise_model::ReactionKind,
        value: &crate::object_model::JsValue,
        label: &Label,
    ) -> Result<Option<u64>, InterpreterError> {
        let Some(state) = self.promise_combinators.get(&combinator_id) else {
            return Ok(None);
        };
        let Some(entry_bytes) = state.observation_memory_growth(index, kind, value) else {
            return Ok(None);
        };
        let result_promise = state.result_promise();
        let previous_store_bytes = self.promise_store.estimated_memory_bytes();
        let next_store_bytes = self
            .promise_store
            .projected_join_label_memory_bytes(result_promise, label)
            .map_err(|error| InterpreterError::InternalError {
                details: format!("missing native combinator result: {error}"),
            })?;
        self.apply_memory_component_delta(
            previous_store_bytes,
            next_store_bytes.saturating_add(entry_bytes),
        )?;
        self.promise_store
            .join_label(result_promise, label)
            .expect("preflighted combinator result remains valid");
        Ok(Some(entry_bytes))
    }

    /// A refused native job must not strand an aggregate or leave a partially
    /// admitted tracker behind. Reuse the allocation-free fatal Promise walk;
    /// queued element jobs become inert when their tracker is removed.
    pub(super) fn terminally_reject_native_combinator(
        &mut self,
        result_promise: crate::promise_model::PromiseHandle,
        job_label: &Label,
    ) {
        let label = self
            .promise_store
            .get(result_promise)
            .map(|record| {
                if record.label.level() > job_label.level() {
                    Self::terminal_async_failure_label(&record.label)
                } else {
                    Self::terminal_async_failure_label(job_label)
                }
            })
            .unwrap_or_else(|_| Self::terminal_async_failure_label(job_label));
        if let Ok(epoch) = self
            .promise_store
            .terminally_reject_without_jobs(result_promise, &label)
        {
            self.close_terminal_async_promise_dependencies(epoch, &label);
        }
        self.estimated_memory_bytes = self.recompute_base_estimated_memory_bytes();
    }

    pub(super) fn remove_combinator_and_watchers(
        &mut self,
        combinator_id: u64,
    ) -> Result<(), InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let removed_state = self.promise_combinators.remove(&combinator_id);
        if let Some(state) = &removed_state {
            self.promise_combinators_bytes = self
                .promise_combinators_bytes
                .saturating_sub(Self::promise_combinator_entry_bytes(state));
        }
        let mut removed_watcher_bytes = 0u64;
        self.promise_combinator_watchers.retain(|_, watchers| {
            let before = watchers.len();
            watchers.retain(|watcher| watcher.combinator_id != combinator_id);
            let kept = !watchers.is_empty();
            removed_watcher_bytes = removed_watcher_bytes.saturating_add(if kept {
                Self::promise_combinator_watchers_bytes_for(before - watchers.len())
            } else {
                Self::promise_combinator_watcher_entry_bytes(before)
            });
            kept
        });
        self.promise_combinator_watchers_bytes = self
            .promise_combinator_watchers_bytes
            .saturating_sub(removed_watcher_bytes);
        drop(removed_state);
        self.apply_promise_runtime_memory_delta(previous_promise_bytes)?;
        Ok(())
    }

    pub(super) fn create_promise(
        &mut self,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let handle = self.promise_store.create();
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_promise_bytes) {
            let rolled_back = self.promise_store.rollback_last_created(handle);
            debug_assert!(rolled_back, "fresh Promise creation must be rollback-safe");
            return Err(error);
        }
        Ok(handle)
    }

    pub(super) fn rollback_fresh_promise(&mut self, handle: crate::promise_model::PromiseHandle) {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        if self.promise_store.rollback_last_created(handle) {
            let released_bytes =
                previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(released_bytes);
        }
    }

    pub(super) fn remove_pending_promise_at_execution_boundary(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
    ) -> Result<(), InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        self.promise_store
            .remove_pending_at_execution_boundary(handle)
            .map_err(|error| InterpreterError::InternalError {
                details: format!(
                    "owned pending Promise {handle} could not be removed at execution boundary: {error}"
                ),
            })?;
        let released_bytes =
            previous_promise_bytes.saturating_sub(self.promise_runtime_memory_bytes());
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released_bytes);
        Ok(())
    }

    pub(super) fn create_fulfilled_promise(
        &mut self,
        value: crate::object_model::JsValue,
        label: Label,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        let handle = self.create_promise()?;
        if let Err(error) = self.fulfill_promise(handle, value, label) {
            self.rollback_fresh_promise(handle);
            return Err(error);
        }
        Ok(handle)
    }

    pub(super) fn create_rejected_promise(
        &mut self,
        reason: crate::object_model::JsValue,
        label: Label,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        let handle = self.create_promise()?;
        if let Err(error) = self.reject_promise(handle, reason, label) {
            self.rollback_fresh_promise(handle);
            return Err(error);
        }
        Ok(handle)
    }

    pub(super) fn register_promise_then(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        on_fulfilled: Option<crate::closure_model::ClosureHandle>,
        on_rejected: Option<crate::closure_model::ClosureHandle>,
        label: Label,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let (next_store_bytes, next_queue_bytes) = self
            .promise_store
            .projected_then_memory_bytes(handle, &label, &self.event_loop.microtasks)
            .map_err(|error| InterpreterError::TypeError {
                expected: "valid promise handle".to_string(),
                got: error.to_string(),
            })?;
        let next_promise_bytes = next_store_bytes
            .saturating_add(
                self.event_loop
                    .estimated_memory_bytes()
                    .saturating_sub(self.event_loop.microtasks.estimated_memory_bytes())
                    .saturating_add(next_queue_bytes),
            )
            .saturating_add(self.promise_combinators_memory_bytes())
            .saturating_add(self.promise_combinator_watchers_memory_bytes())
            .saturating_add(self.promise_in_flight_task_bytes);
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
        let result = self
            .promise_store
            .then(
                handle,
                on_fulfilled,
                on_rejected,
                label,
                &mut self.event_loop.microtasks,
            )
            .expect("preflighted Promise.then mutation must remain valid");
        self.settle_projected_promise_bytes(next_promise_bytes)?;
        Ok(result)
    }

    /// [`Self::register_promise_then`] into an existing result promise
    /// (bd-9vouw.137), with the same exact memory preflight.
    pub(super) fn register_promise_then_into(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        on_fulfilled: Option<crate::closure_model::ClosureHandle>,
        on_rejected: Option<crate::closure_model::ClosureHandle>,
        result_promise: crate::promise_model::PromiseHandle,
        label: Label,
    ) -> Result<(), InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let (next_store_bytes, next_queue_bytes) = self
            .promise_store
            .projected_then_into_memory_bytes(handle, &label, &self.event_loop.microtasks)
            .map_err(|error| InterpreterError::TypeError {
                expected: "valid promise handle".to_string(),
                got: error.to_string(),
            })?;
        let next_promise_bytes = next_store_bytes
            .saturating_add(
                self.event_loop
                    .estimated_memory_bytes()
                    .saturating_sub(self.event_loop.microtasks.estimated_memory_bytes())
                    .saturating_add(next_queue_bytes),
            )
            .saturating_add(self.promise_combinators_memory_bytes())
            .saturating_add(self.promise_combinator_watchers_memory_bytes())
            .saturating_add(self.promise_in_flight_task_bytes);
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
        self.promise_store
            .then_into(
                handle,
                on_fulfilled,
                on_rejected,
                result_promise,
                label,
                &mut self.event_loop.microtasks,
            )
            .expect("preflighted Promise.then mutation must remain valid");
        self.settle_projected_promise_bytes(next_promise_bytes)?;
        Ok(())
    }

    /// An await's internal reaction promise (`register_promise_then_for_await`)
    /// exists only as the key of its resumption context. Once the context is
    /// consumed and the awaiting code resumed, nothing can observe it; left
    /// pending it stayed a collector root forever, one record per `await`
    /// (bd-9vouw.57). Remove it, releasing its exact charge. A carrier that
    /// is no longer pending (cancellation settles it) is left to the
    /// collector.
    pub(super) fn release_await_carrier(&mut self, carrier: crate::promise_model::PromiseHandle) {
        let before = self.promise_runtime_memory_bytes();
        if self
            .promise_store
            .remove_pending_at_execution_boundary(carrier)
            .is_ok()
        {
            let released = before.saturating_sub(self.promise_runtime_memory_bytes());
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
        }
    }

    pub(super) fn register_promise_then_for_await(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        label: crate::ifc_artifacts::Label,
    ) -> Result<crate::promise_model::PromiseHandle, InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let (next_store_bytes, next_queue_bytes) = self
            .promise_store
            .projected_then_memory_bytes(handle, &label, &self.event_loop.microtasks)
            .map_err(|error| InterpreterError::TypeError {
                expected: "valid promise handle".to_string(),
                got: error.to_string(),
            })?;
        let next_promise_bytes = next_store_bytes
            .saturating_add(
                self.event_loop
                    .estimated_memory_bytes()
                    .saturating_sub(self.event_loop.microtasks.estimated_memory_bytes())
                    .saturating_add(next_queue_bytes),
            )
            .saturating_add(self.promise_combinators_memory_bytes())
            .saturating_add(self.promise_combinator_watchers_memory_bytes())
            .saturating_add(self.promise_in_flight_task_bytes);
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
        let result = self
            .promise_store
            .then_for_await(handle, label, &mut self.event_loop.microtasks)
            .expect("preflighted await reaction mutation must remain valid");
        self.settle_projected_promise_bytes(next_promise_bytes)?;
        Ok(result)
    }

    pub(super) fn fulfill_promise(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        value: crate::object_model::JsValue,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let (next_store_bytes, next_queue_bytes) = self
            .promise_store
            .projected_fulfill_memory_bytes(handle, &value, &label, &self.event_loop.microtasks)
            .map_err(|e| InterpreterError::TypeError {
                expected: "pending promise".to_string(),
                got: e.to_string(),
            })?;
        let next_promise_bytes = next_store_bytes
            .saturating_add(
                self.event_loop
                    .estimated_memory_bytes()
                    .saturating_sub(self.event_loop.microtasks.estimated_memory_bytes())
                    .saturating_add(next_queue_bytes),
            )
            .saturating_add(self.promise_combinators_memory_bytes())
            .saturating_add(self.promise_combinator_watchers_memory_bytes())
            .saturating_add(self.promise_in_flight_task_bytes);
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
        self.promise_store
            .fulfill(handle, value, label, &mut self.event_loop.microtasks)
            .expect("preflighted Promise fulfillment must remain valid");
        self.settle_projected_promise_bytes(next_promise_bytes)?;
        self.release_settled_combinator_watchers(handle);
        Ok(())
    }

    pub(super) fn reject_promise(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
        reason: crate::object_model::JsValue,
        label: crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let (next_store_bytes, next_queue_bytes) = self
            .promise_store
            .projected_reject_memory_bytes(handle, &reason, &label, &self.event_loop.microtasks)
            .map_err(|e| InterpreterError::TypeError {
                expected: "pending promise".to_string(),
                got: e.to_string(),
            })?;
        let next_promise_bytes = next_store_bytes
            .saturating_add(
                self.event_loop
                    .estimated_memory_bytes()
                    .saturating_sub(self.event_loop.microtasks.estimated_memory_bytes())
                    .saturating_add(next_queue_bytes),
            )
            .saturating_add(self.promise_combinators_memory_bytes())
            .saturating_add(self.promise_combinator_watchers_memory_bytes())
            .saturating_add(self.promise_in_flight_task_bytes);
        self.apply_memory_component_delta(previous_promise_bytes, next_promise_bytes)?;
        self.promise_store
            .reject(handle, reason, label, &mut self.event_loop.microtasks)
            .expect("preflighted Promise rejection must remain valid");
        self.settle_projected_promise_bytes(next_promise_bytes)?;
        self.release_settled_combinator_watchers(handle);
        Ok(())
    }

    /// Settlement already queued native reactions together with `.then`
    /// callbacks. Transfer dependency ownership to those jobs without running
    /// the aggregate, allocating result objects, or taking a cascade snapshot.
    pub(super) fn release_settled_combinator_watchers(
        &mut self,
        handle: crate::promise_model::PromiseHandle,
    ) {
        if let Some(watchers) = self.promise_combinator_watchers.remove(&handle) {
            let bytes = Self::promise_combinator_watcher_entry_bytes(watchers.len());
            self.promise_combinator_watchers_bytes =
                self.promise_combinator_watchers_bytes.saturating_sub(bytes);
            self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(bytes);
        }
    }

    pub(super) fn update_combinator_fulfillment(
        &mut self,
        module: Option<&Ir3Module>,
        combinator_id: u64,
        index: u32,
        value: &crate::object_model::JsValue,
        label: &crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let Some(growth) = self.prepare_combinator_observation(
            combinator_id,
            index,
            crate::promise_model::ReactionKind::Fulfill,
            value,
            label,
        )?
        else {
            return Ok(());
        };
        // Record only an admitted retained payload. Terminal materialization
        // borrows this tracker instead of cloning the whole aggregate. The
        // record grows the tracker by exactly the admitted `growth`.
        let mut resolution = None;
        if let Some(state) = self.promise_combinators.get_mut(&combinator_id) {
            self.promise_combinators_bytes = self.promise_combinators_bytes.saturating_add(growth);
            match state {
                PromiseCombinatorState::All(tracker) => {
                    if tracker.record_fulfillment(index, value.clone()) {
                        tracker.mark_settled();
                        resolution = Some((tracker.result_promise, true));
                    }
                }
                PromiseCombinatorState::AllSettled(tracker) => {
                    if tracker.record_fulfillment(index, value.clone()) {
                        resolution = Some((tracker.result_promise, true));
                    }
                }
                PromiseCombinatorState::Race(tracker) => {
                    if tracker.try_settle() {
                        resolution = Some((tracker.result_promise, false));
                    }
                }
                PromiseCombinatorState::Any(tracker) => {
                    tracker.mark_settled();
                    resolution = Some((tracker.result_promise, false));
                }
            }
        }
        if let Some((handle, materialize)) = resolution {
            let label_bytes = Self::estimate_label_bytes(
                &self
                    .promise_store
                    .get(handle)
                    .expect("native result exists")
                    .label,
            );
            let direct_value_bytes = if materialize {
                0
            } else {
                crate::promise_model::estimate_js_value_memory_bytes(value)
            };
            self.with_promise_temporary_bytes(
                label_bytes.saturating_add(direct_value_bytes),
                |core| {
                    let label = core
                        .promise_store
                        .get(handle)
                        .expect("native construction invokes no guest code")
                        .label
                        .clone();
                    let value = if materialize {
                        core.build_native_combinator_result(combinator_id)?
                    } else {
                        value.clone()
                    };
                    core.resolve_native_combinator_result(module, handle, value, label, materialize)
                },
            )?;
            self.remove_combinator_and_watchers(combinator_id)?;
        }
        Ok(())
    }

    pub(super) fn update_combinator_rejection(
        &mut self,
        module: Option<&Ir3Module>,
        combinator_id: u64,
        index: u32,
        reason: &crate::object_model::JsValue,
        label: &crate::ifc_artifacts::Label,
    ) -> Result<(), InterpreterError> {
        let Some(growth) = self.prepare_combinator_observation(
            combinator_id,
            index,
            crate::promise_model::ReactionKind::Reject,
            reason,
            label,
        )?
        else {
            return Ok(());
        };
        let mut resolution = None;
        if let Some(state) = self.promise_combinators.get_mut(&combinator_id) {
            // The record grows the tracker by exactly the admitted `growth`.
            self.promise_combinators_bytes = self.promise_combinators_bytes.saturating_add(growth);
            match state {
                PromiseCombinatorState::All(tracker) => {
                    tracker.mark_settled();
                    resolution = Some((tracker.result_promise, false, false));
                }
                PromiseCombinatorState::AllSettled(tracker) => {
                    if tracker.record_rejection(index, reason.clone()) {
                        resolution = Some((tracker.result_promise, true, true));
                    }
                }
                PromiseCombinatorState::Race(tracker) => {
                    if tracker.try_settle() {
                        resolution = Some((tracker.result_promise, false, false));
                    }
                }
                PromiseCombinatorState::Any(tracker) => {
                    if tracker.record_rejection(index, reason.clone()) {
                        tracker.mark_settled();
                        resolution = Some((tracker.result_promise, true, false));
                    }
                }
            }
        }
        if let Some((handle, materialize, fulfill)) = resolution {
            let label_bytes = Self::estimate_label_bytes(
                &self
                    .promise_store
                    .get(handle)
                    .expect("native result exists")
                    .label,
            );
            let direct_value_bytes = if materialize {
                0
            } else {
                crate::promise_model::estimate_js_value_memory_bytes(reason)
            };
            self.with_promise_temporary_bytes(
                label_bytes.saturating_add(direct_value_bytes),
                |core| {
                    let label = core
                        .promise_store
                        .get(handle)
                        .expect("native construction invokes no guest code")
                        .label
                        .clone();
                    let value = if materialize {
                        core.build_native_combinator_result(combinator_id)?
                    } else {
                        reason.clone()
                    };
                    if fulfill {
                        core.resolve_native_combinator_result(module, handle, value, label, true)
                    } else {
                        core.reject_promise(handle, value, label)
                    }
                },
            )?;
            self.remove_combinator_and_watchers(combinator_id)?;
        }
        Ok(())
    }

    pub(super) fn dispatch_promise_combinator(
        &mut self,
        kind: PromiseCombinatorKind,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        let label = self.join_arg_range_with_object_mutation_label(args)?.join(
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
        );
        let mut inputs = match self.collect_promise_combinator_inputs(module, args) {
            Ok(inputs) => inputs,
            Err(error) => return self.reject_promise_combinator_input(error),
        };
        // Each element goes through PromiseResolve (ES2020 25.6.4.1.1 step
        // 8.i, Promise.resolve): a thenable becomes a promise that adopts it
        // (bd-9vouw.174). This runs before the rollback snapshot below: a
        // `then` getter is guest code whose effects stay.
        for input in &mut inputs {
            if matches!(input, Value::Object(_)) {
                let handle = self.create_promise()?;
                let element = std::mem::replace(input, Value::Promise(handle.0));
                self.resolve_promise_with_value(module, handle, element, label.clone())?;
            }
        }
        for input in &inputs {
            if let Value::Promise(handle) = input {
                // The combinator observes every input's rejection, as the
                // spec's `then` on each input would, including inputs after
                // the one that settles it: all of them are handled (bd-xzemw).
                self.promise_store
                    .mark_rejection_handled(crate::promise_model::PromiseHandle(*handle))
                    .map_err(|error| InterpreterError::TypeError {
                        expected: "promise".to_string(),
                        got: error.to_string(),
                    })?;
            }
        }

        let previous_estimated_bytes = self.estimated_memory_bytes;
        let promise_snapshot_bytes = self.promise_runtime_memory_bytes();
        self.apply_memory_component_delta(0, promise_snapshot_bytes)?;
        let previous_store = self.promise_store.clone();
        let previous_event_loop = self.event_loop.clone();
        let previous_combinators = self.promise_combinators.clone();
        let previous_watchers = self.promise_combinator_watchers.clone();
        let previous_combinator_bytes = (
            self.promise_combinators_bytes,
            self.promise_combinator_watchers_bytes,
        );
        let previous_combinator_id = self.next_promise_combinator_id;
        let previous_heap_len = self.heap.len();

        let result = self.dispatch_promise_combinator_inputs(kind, inputs, label);
        if result.is_err() {
            self.promise_store = previous_store;
            self.event_loop = previous_event_loop;
            self.promise_combinators = previous_combinators;
            self.promise_combinator_watchers = previous_watchers;
            (
                self.promise_combinators_bytes,
                self.promise_combinator_watchers_bytes,
            ) = previous_combinator_bytes;
            self.next_promise_combinator_id = previous_combinator_id;
            self.rollback_heap_to_len(previous_heap_len);
            self.estimated_memory_bytes = previous_estimated_bytes;
        } else {
            drop(previous_store);
            drop(previous_event_loop);
            drop(previous_combinators);
            drop(previous_watchers);
            self.estimated_memory_bytes = self
                .estimated_memory_bytes
                .saturating_sub(promise_snapshot_bytes);
        }
        result
    }

    pub(super) fn dispatch_promise_combinator_inputs(
        &mut self,
        kind: PromiseCombinatorKind,
        inputs: Vec<Value>,
        label: Label,
    ) -> Result<Value, InterpreterError> {
        let total = inputs.len() as u32;
        let result_promise = self.create_promise()?;
        self.join_combinator_result_label(result_promise, &label)?;

        match kind {
            PromiseCombinatorKind::All | PromiseCombinatorKind::AllSettled if total == 0 => {
                let empty = self.build_promise_all_result(Vec::new())?;
                self.fulfill_promise(result_promise, empty, label)?;
                return Ok(Value::Promise(result_promise.0));
            }
            PromiseCombinatorKind::Any if total == 0 => {
                let aggregate = self.build_aggregate_error(Vec::new())?;
                self.reject_promise(result_promise, aggregate, label)?;
                return Ok(Value::Promise(result_promise.0));
            }
            PromiseCombinatorKind::Race if total == 0 => {
                return Ok(Value::Promise(result_promise.0));
            }
            _ => {}
        }

        let state = match kind {
            PromiseCombinatorKind::All => {
                PromiseCombinatorState::All(crate::promise_model::PromiseAllTracker {
                    result_promise,
                    values: BTreeMap::new(),
                    total,
                    resolved_count: 0,
                    settled: false,
                })
            }
            PromiseCombinatorKind::AllSettled => {
                PromiseCombinatorState::AllSettled(crate::promise_model::PromiseAllSettledTracker {
                    result_promise,
                    outcomes: BTreeMap::new(),
                    total,
                    settled_count: 0,
                })
            }
            PromiseCombinatorKind::Race => {
                PromiseCombinatorState::Race(crate::promise_model::PromiseRaceTracker {
                    result_promise,
                    settled: false,
                })
            }
            PromiseCombinatorKind::Any => {
                PromiseCombinatorState::Any(crate::promise_model::PromiseAnyTracker {
                    result_promise,
                    errors: BTreeMap::new(),
                    total,
                    rejected_count: 0,
                    settled: false,
                })
            }
        };

        let combinator_id = self.register_combinator(state)?;

        for (index, input) in inputs.into_iter().enumerate() {
            let index = index as u32;
            match input {
                Value::Promise(handle) => {
                    let promise_handle = crate::promise_model::PromiseHandle(handle);
                    self.register_native_combinator_reaction(
                        promise_handle,
                        result_promise,
                        PromiseCombinatorWatcher {
                            combinator_id,
                            index,
                        },
                        label.clone(),
                    )?;
                }
                other => {
                    let js_val = self.promise_value(&other)?;
                    self.enqueue_native_combinator_job(
                        crate::promise_model::Microtask::PromiseCombinator {
                            combinator: crate::promise_model::PromiseCombinatorReaction {
                                combinator_id,
                                index,
                            },
                            kind: crate::promise_model::ReactionKind::Fulfill,
                            argument: js_val,
                            result_promise,
                            label: label.clone(),
                        },
                    )?;
                }
            }
        }

        Ok(Value::Promise(result_promise.0))
    }

    pub(super) fn promise_reaction_handler_from_value(
        &mut self,
        value: Value,
        role: &str,
    ) -> Result<Option<crate::closure_model::ClosureHandle>, InterpreterError> {
        match value {
            Value::Undefined | Value::Null => Ok(None),
            Value::Closure(closure_id) => {
                self.closures.get(closure_id as usize).ok_or_else(|| {
                    InterpreterError::TypeError {
                        expected: format!("valid Promise reaction {role} closure"),
                        got: format!("closure#{closure_id} not found"),
                    }
                })?;
                Ok(Some(crate::closure_model::ClosureHandle(closure_id)))
            }
            Value::Function(function_index) => {
                let closure_id = u32::try_from(self.closures.len()).map_err(|_| {
                    InterpreterError::TypeError {
                        expected: "closure table capacity".to_string(),
                        got: format!("exceeded u32::MAX ({})", self.closures.len()),
                    }
                })?;
                let previous_closure_bytes = self.closures_memory_bytes();
                self.closures.push(ClosureValue {
                    function_index,
                    captured_env: Vec::new(),
                });
                if let Some(origin) = self.current_module_specifier.clone() {
                    self.closure_module_origins.insert(closure_id, origin);
                }
                if let Some(handle) = self.active_generated_function_artifact {
                    self.closure_generated_function_artifacts
                        .insert(closure_id, handle);
                }
                if let Err(err) = self.apply_closures_memory_delta(previous_closure_bytes) {
                    self.closures.pop();
                    self.remove_closure_program_provenance(closure_id);
                    return Err(err);
                }
                Ok(Some(crate::closure_model::ClosureHandle(closure_id)))
            }
            Value::GeneratorFunction(_)
            | Value::AsyncFunction(_)
            | Value::AsyncGeneratorFunction(_)
            | Value::BuiltinFunction(_) => {
                Ok(Some(self.register_promise_reaction_callable(value)?))
            }
            _ => Ok(None),
        }
    }

    /// Register a callable Promise reaction handler that has no closure-table
    /// backing (a builtin such as `console.log`, or an async/generator
    /// function object). The callable is retained in
    /// `promise_reaction_callables` under a synthetic handle id at or above
    /// [`PROMISE_REACTION_CALLABLE_BASE`]; `execute_promise_reaction_handler`
    /// resolves such ids back to the stored callee (bd-sxh8o.1).
    pub(super) fn register_promise_reaction_callable(
        &mut self,
        callable: Value,
    ) -> Result<crate::closure_model::ClosureHandle, InterpreterError> {
        if self.closures.len() >= PROMISE_REACTION_CALLABLE_BASE as usize {
            return Err(InterpreterError::TypeError {
                expected: "closure table below the reaction-callable id base".to_string(),
                got: format!("{} closures", self.closures.len()),
            });
        }
        let id = self.next_promise_reaction_callable_id;
        if id == u32::MAX {
            return Err(InterpreterError::TypeError {
                expected: "Promise reaction callable id capacity".to_string(),
                got: "exhausted synthetic reaction-callable id space".to_string(),
            });
        }
        let previous_bytes = self.promise_reaction_callables_memory_bytes();
        self.promise_reaction_callables.insert(id, callable);
        if let Err(error) = self.apply_memory_component_delta(
            previous_bytes,
            self.promise_reaction_callables_memory_bytes(),
        ) {
            self.promise_reaction_callables.remove(&id);
            return Err(error);
        }
        self.next_promise_reaction_callable_id = id.saturating_add(1);
        Ok(crate::closure_model::ClosureHandle(id))
    }

    pub(super) fn promise_reaction_arg(
        &self,
        args: RegRange,
        offset: u32,
    ) -> Result<Option<Value>, InterpreterError> {
        if args.count <= offset {
            return Ok(None);
        }
        let register =
            args.start
                .checked_add(offset)
                .ok_or(InterpreterError::RegisterOutOfBounds {
                    register: args.start,
                    max: self.config.max_registers,
                })?;
        Ok(Some(self.read_reg(register)?))
    }

    /// Arm `value` as the pending guest exception and return the error that
    /// unwinds to the nearest handler, exactly like a `throw` statement.
    pub(super) fn throw_guest_value(
        &mut self,
        value: Value,
        label: Label,
    ) -> Result<InterpreterError, InterpreterError> {
        let description = self.uncaught_exception_description(&value);
        self.replace_pending_abrupt_slots(Some((value, label)), None)?;
        Ok(InterpreterError::UncaughtException { value: description })
    }

    /// Reaction handlers for `promise.finally(onFinally)`: a callable
    /// onFinally is wrapped in the Then Finally / Catch Finally steps; a
    /// non-callable one passes the settlement through unchanged (ES2020
    /// 25.6.5.3; bd-9vouw.39 — this used to be `then(onFinally, onFinally)`,
    /// which swallowed rejections).
    pub(super) fn promise_finally_handlers(
        &mut self,
        on_finally: Option<Value>,
        constructor: Value,
    ) -> Result<
        (
            Option<crate::closure_model::ClosureHandle>,
            Option<crate::closure_model::ClosureHandle>,
        ),
        InterpreterError,
    > {
        let Some(on_finally) = on_finally.filter(Value::is_callable) else {
            return Ok((None, None));
        };
        let holder = self.alloc_object_with_properties(&[
            ("__onFinally", on_finally),
            ("__constructor", constructor),
        ])?;
        let then_finally = self.promise_reaction_handler_from_value(
            Value::BuiltinFunction(BuiltinFunction::bound_to(
                BuiltinFunctionKind::PromiseThenFinally,
                holder,
            )),
            "onFinally",
        )?;
        let catch_finally = self.promise_reaction_handler_from_value(
            Value::BuiltinFunction(BuiltinFunction::bound_to(
                BuiltinFunctionKind::PromiseCatchFinally,
                holder,
            )),
            "onFinally",
        )?;
        Ok((then_finally, catch_finally))
    }

    /// ES2020 25.6.5.3 step 3: SpeciesConstructor(promise, %Promise%), which
    /// Then Finally and Catch Finally resolve onFinally's result with
    /// (bd-9vouw.349). %Promise% for an undefined `constructor` or an
    /// undefined or null @@species; a TypeError for a non-object
    /// `constructor` or a species that is not a constructor.
    pub(super) fn promise_finally_species_constructor(
        &mut self,
        module: &Ir3Module,
        promise: &Value,
    ) -> Result<Value, InterpreterError> {
        let intrinsic = Value::BuiltinFunction(BuiltinFunction::standard_constructor("Promise"));
        let constructor = self.get_v(
            module,
            promise,
            &RuntimePropertyKey::String(JsString::from("constructor")),
        )?;
        if matches!(constructor, Value::Undefined) {
            return Ok(intrinsic);
        }
        if !constructor.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "object or undefined promise constructor".to_string(),
                got: constructor.type_name().to_string(),
            });
        }
        let species = self.species_of_constructor(module, &constructor)?;
        if matches!(species, Value::Undefined | Value::Null) {
            return Ok(intrinsic);
        }
        if !self.is_constructible_value(&species) {
            return Err(InterpreterError::TypeError {
                expected: "constructor @@species for a promise".to_string(),
                got: species.type_name().to_string(),
            });
        }
        Ok(species)
    }

    /// A property of the engine-owned holder a Promise.prototype.finally step
    /// is bound to (bd-9vouw.39).
    pub(super) fn promise_finally_bound_property(
        &self,
        builtin: &BuiltinFunction,
        name: &str,
    ) -> Result<Value, InterpreterError> {
        builtin
            .bound_object
            .and_then(|holder| self.heap.get(holder as usize))
            .and_then(|holder| holder.properties.get(name).cloned())
            .ok_or_else(|| InterpreterError::InternalError {
                details: format!("Promise.prototype.finally step lost its bound {name}"),
            })
    }

    /// ES2020 25.6.5.3.1 Then Finally / 25.6.5.3.2 Catch Finally: call
    /// onFinally() with no arguments (a throw from it rejects the chain),
    /// resolve its result with PromiseResolve(C, result) for the
    /// SpeciesConstructor C taken when finally was called, and return
    /// Invoke(that promise, "then", «thunk»), where the thunk returns the
    /// original value or throws the original reason. The `then` call, the
    /// C construction and their jobs are observable (bd-9vouw.349): a
    /// promise result was chained internally, past its own `then`, and any
    /// other result passed the settlement through at once.
    pub(super) fn promise_finally_step(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        // Guest code runs while native locals hold values: no collection
        // until this returns.
        self.gc_nested_request = None;
        let settlement = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let on_finally = self.promise_finally_bound_property(builtin, "__onFinally")?;
        let constructor = self.promise_finally_bound_property(builtin, "__constructor")?;
        let fulfilled = builtin.kind == BuiltinFunctionKind::PromiseThenFinally;
        let result =
            self.invoke_inline_method_call(Some(module), on_finally, Value::Undefined, Vec::new())?;
        let label = self
            .pending_hostcall_result_label
            .clone()
            .unwrap_or(Label::Public);
        let promise = self.promise_resolve_with_constructor(module, constructor, result, label)?;
        let carrier = self.alloc_object_with_properties(&[("__value", settlement)])?;
        let thunk = Value::BuiltinFunction(BuiltinFunction::bound_to(
            if fulfilled {
                BuiltinFunctionKind::PromiseFinallyValueThunk
            } else {
                BuiltinFunctionKind::PromiseFinallyThrower
            },
            carrier,
        ));
        let then = self.get_v(
            module,
            &promise,
            &RuntimePropertyKey::String(JsString::from("then")),
        )?;
        if !then.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable then of the promise onFinally's result resolves to".to_string(),
                got: then.type_name().to_string(),
            });
        }
        self.invoke_inline_method_call(Some(module), then, promise, vec![thunk])
    }

    pub(super) fn dispatch_promise_reaction_builtin(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
        receiver: Option<Value>,
        kind: PromiseReactionKind,
    ) -> Result<Value, InterpreterError> {
        let receiver = receiver.unwrap_or(Value::Undefined);
        // ES2020 25.6.5.3 step 3: finally takes SpeciesConstructor(this,
        // %Promise%) before it reads `then` (bd-9vouw.349).
        let mut finally_constructor = None;
        // ES2020 25.6.5.1 / 25.6.5.3: catch and finally are
        // Invoke(this, "then", ...), so a thenable `this`, or a promise
        // whose `then` was replaced, runs that `then`; only a promise with
        // the intrinsic `then` takes the native path below. Both demanded
        // a promise (bd-9vouw.274).
        if matches!(
            kind,
            PromiseReactionKind::Catch | PromiseReactionKind::Finally
        ) {
            if matches!(kind, PromiseReactionKind::Finally) && !receiver.is_object_like() {
                return Err(InterpreterError::TypeError {
                    expected: "object receiver for Promise.prototype.finally".to_string(),
                    got: receiver.type_name().to_string(),
                });
            }
            // Guest code (a `then` getter, a user `then`) runs while native
            // locals hold values: no collection until this returns.
            self.gc_nested_request = None;
            if matches!(kind, PromiseReactionKind::Finally) {
                finally_constructor =
                    Some(self.promise_finally_species_constructor(module, &receiver)?);
            }
            let then = self.get_v(
                module,
                &receiver,
                &RuntimePropertyKey::String(JsString::from("then")),
            )?;
            let intrinsic = matches!(receiver, Value::Promise(_))
                && matches!(&then, Value::BuiltinFunction(builtin)
                    if builtin.kind == BuiltinFunctionKind::PromiseThen);
            if !intrinsic {
                if !then.is_callable() {
                    return Err(InterpreterError::TypeError {
                        expected: "callable then of a Promise.prototype.catch/finally receiver"
                            .to_string(),
                        got: then.type_name().to_string(),
                    });
                }
                let handler = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                let arguments = match kind {
                    PromiseReactionKind::Catch => vec![Value::Undefined, handler],
                    _ if handler.is_callable() => {
                        let constructor = finally_constructor.clone().unwrap_or(Value::Undefined);
                        let holder = self.alloc_object_with_properties(&[
                            ("__onFinally", handler),
                            ("__constructor", constructor),
                        ])?;
                        vec![
                            Value::BuiltinFunction(BuiltinFunction::bound_to(
                                BuiltinFunctionKind::PromiseThenFinally,
                                holder,
                            )),
                            Value::BuiltinFunction(BuiltinFunction::bound_to(
                                BuiltinFunctionKind::PromiseCatchFinally,
                                holder,
                            )),
                        ]
                    }
                    _ => vec![handler.clone(), handler],
                };
                return self.invoke_inline_method_call(Some(module), then, receiver, arguments);
            }
        }
        // ES2020 25.6.5.4 steps 3-4 (and catch/finally through then): the
        // result comes from SpeciesConstructor(promise, %Promise%).
        let species_result = if matches!(receiver, Value::Promise(_)) {
            self.promise_species_result(module, &receiver)?
        } else {
            None
        };
        let handle = match receiver {
            Value::Promise(h) => crate::promise_model::PromiseHandle(h),
            other => {
                let method = match kind {
                    PromiseReactionKind::Then => "then",
                    PromiseReactionKind::Catch => "catch",
                    PromiseReactionKind::Finally => "finally",
                };
                return Err(InterpreterError::TypeError {
                    expected: format!("promise receiver for Promise.prototype.{method}"),
                    got: other.type_name().to_string(),
                });
            }
        };
        let label = self.join_arg_range_label(args)?.join(
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
        );
        let (on_fulfilled, on_rejected) = match kind {
            PromiseReactionKind::Then => {
                let on_fulfilled = match self.builtin_arg(args, 0)? {
                    Some(value) => {
                        self.promise_reaction_handler_from_value(value, "onFulfilled")?
                    }
                    None => None,
                };
                let on_rejected = match self.builtin_arg(args, 1)? {
                    Some(value) => self.promise_reaction_handler_from_value(value, "onRejected")?,
                    None => None,
                };
                (on_fulfilled, on_rejected)
            }
            PromiseReactionKind::Catch => {
                let on_rejected = match self.builtin_arg(args, 0)? {
                    Some(value) => self.promise_reaction_handler_from_value(value, "onRejected")?,
                    None => None,
                };
                (None, on_rejected)
            }
            // ES2020 25.6.5.3: a callable onFinally is wrapped so it runs with
            // no arguments and the original settlement passes through; a
            // non-callable one passes the settlement through unchanged
            // (bd-9vouw.39; this was `then(onFinally, onFinally)`, which
            // swallowed rejections).
            PromiseReactionKind::Finally => {
                let on_finally = self.builtin_arg(args, 0)?;
                let constructor = finally_constructor.clone().unwrap_or_else(|| {
                    Value::BuiltinFunction(BuiltinFunction::standard_constructor("Promise"))
                });
                self.promise_finally_handlers(on_finally, constructor)?
            }
        };
        Ok(match species_result {
            Some(capability) => match Self::capability_native_promise(&capability) {
                Some(result) => {
                    self.register_promise_then_into(
                        handle,
                        on_fulfilled,
                        on_rejected,
                        result,
                        label,
                    )?;
                    Value::Promise(result.0)
                }
                // A capability that is not an engine promise's own functions
                // (a species returning any object) receives the derived
                // promise's settlement through its resolve and reject, one
                // job later (bd-9vouw.282).
                None => {
                    let derived = self.register_promise_then(
                        handle,
                        on_fulfilled,
                        on_rejected,
                        label.clone(),
                    )?;
                    let resolve = self.promise_reaction_handler_from_value(
                        capability.resolve.clone(),
                        "onFulfilled",
                    )?;
                    let reject = self.promise_reaction_handler_from_value(
                        capability.reject.clone(),
                        "onRejected",
                    )?;
                    self.register_promise_then(derived, resolve, reject, label)?;
                    capability.promise
                }
            },
            None => Value::Promise(
                self.register_promise_then(handle, on_fulfilled, on_rejected, label)?
                    .0,
            ),
        })
    }

    /// bd-9vouw.137: the capability of then/catch/finally on `promise` when
    /// SpeciesConstructor(promise, %Promise%) is not %Promise%:
    /// NewPromiseCapability of the species (bd-9vouw.282: any constructor).
    /// `None` keeps %Promise%: `constructor` undefined or %Promise%, or a
    /// species that is undefined, null or %Promise%. A non-object
    /// `constructor` or a species that is not a constructor is a TypeError.
    pub(super) fn promise_species_result(
        &mut self,
        module: &Ir3Module,
        promise: &Value,
    ) -> Result<Option<promise_capability::PromiseCapabilityRecord>, InterpreterError> {
        let constructor = self.get_v(
            module,
            promise,
            &RuntimePropertyKey::String(JsString::from("constructor")),
        )?;
        if matches!(constructor, Value::Undefined) {
            return Ok(None);
        }
        if !constructor.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "object or undefined promise constructor".to_string(),
                got: constructor.type_name().to_string(),
            });
        }
        let species = self.species_of_constructor(module, &constructor)?;
        if matches!(species, Value::Undefined | Value::Null)
            || Self::is_intrinsic_promise_constructor(&species)
        {
            return Ok(None);
        }
        if !self.is_constructible_value(&species) {
            return Err(InterpreterError::TypeError {
                expected: "constructor @@species for a promise".to_string(),
                got: species.type_name().to_string(),
            });
        }
        self.new_promise_capability_record(module, species, vec![promise.clone()])
            .map(Some)
    }

    /// Dispatch a `promise:*` hostcall to the internal promise subsystem.
    ///
    /// Supported capabilities:
    /// - `promise:constructor` — create a pending promise, return its handle.
    /// - `promise:resolve` — resolve a promise or create a pre-resolved one.
    ///   arg0 = promise handle (or value to wrap), arg1 = value.
    /// - `promise:reject` — reject a promise or create a pre-rejected one.
    ///   arg0 = promise handle (or reason), arg1 = reason.
    /// - `promise:then` — register .then(onFulfilled, onRejected).
    ///   arg0 = promise handle value.
    /// - `promise:catch` — sugar for .then(undefined, onRejected).
    ///   arg0 = promise handle value.
    /// - `promise:finally` — register a finally handler.
    ///   arg0 = promise handle value.
    /// - `promise:all` — create a Promise.all aggregate.
    /// - `promise:race` — create a Promise.race aggregate.
    /// - `promise:allSettled` — create a Promise.allSettled aggregate.
    /// - `promise:any` — create a Promise.any aggregate.
    pub(super) fn dispatch_promise_hostcall(
        &mut self,
        cap: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        let timestamp_ns = self.instructions_executed;
        let args_hash = self.hostcall_arguments_hash(args);
        let outcome = self.dispatch_promise_hostcall_inner(cap, args, module);
        self.record_hostcall_telemetry(cap, args, timestamp_ns, args_hash, &outcome);
        outcome
    }

    /// Dispatch a CommonJS `require` and emit exactly one completeness-aware
    /// telemetry record for both success and failure.
    pub(super) fn dispatch_require_hostcall(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        self.dispatch_require_hostcall_with_native_effect_provenance(args, module, &mut false)
    }

    pub(super) fn dispatch_require_hostcall_with_native_effect_provenance(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
        native_effect: &mut bool,
    ) -> Result<Value, InterpreterError> {
        let args_hash = self.hostcall_arguments_hash(args);
        let outcome = self.dispatch_require_hostcall_inner(args, module, native_effect);
        // Module evaluation can recursively complete another module hostcall.
        // Record in completion order so nested records remain timestamp-
        // monotonic while retaining deterministic instruction-clock time.
        let timestamp_ns = self.instructions_executed;
        self.record_hostcall_telemetry("module:require", args, timestamp_ns, args_hash, &outcome);
        outcome
    }

    /// Create a require value for the executing captured module only. Node's
    /// arbitrary virtual bases and URL objects need an explicitly captured
    /// route contract; accepting them here would confer another referrer's
    /// authority or fall back to the host filesystem. Exact string metadata
    /// covers `import.meta.url` (including query/fragment) and `__filename`.
    pub(super) fn create_require(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let origin = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let Value::Str(origin) = origin else {
            return Err(InterpreterError::TypeError {
                expected: "createRequire origin string for the current captured module".to_string(),
                got: origin.type_name().to_string(),
            });
        };
        let origin = origin.as_str().ok_or_else(|| InterpreterError::TypeError {
            expected: "well-formed createRequire origin string".to_string(),
            got: "unpaired UTF-16 surrogate".to_string(),
        })?;
        let referrer = self
            .current_module_specifier
            .as_deref()
            .filter(|id| {
                self.module_resolver
                    .as_ref()
                    .and_then(|installed| installed.resolver.source_location(id))
                    .is_some_and(|location| location.matches_create_require_origin(origin))
            })
            .ok_or_else(|| InterpreterError::TypeError {
                expected:
                    "createRequire origin equal to the current captured URL or absolute filename"
                        .to_string(),
                got: "unregistered or different module origin".to_string(),
            })?;
        // Each factory call is a distinct function, including its .resolve
        // and user-defined properties. The existing builtin identity and GC
        // traversal already include bound_object; dispatch still uses only
        // the captured module_specifier. Ordinary CJS require keeps None.
        let holder_bytes = Self::estimate_heap_object_bytes(&HeapObject::new());
        let mut require = self.construct_require_builtin(referrer, holder_bytes)?;
        self.run_pre_allocation_hook(module, AllocKind::Function, referrer.len())?;
        require.bound_object = Some(self.alloc_object_with_prototype(None)?.0);
        Ok(Value::BuiltinFunction(require))
    }

    /// `require.resolve(request)` (bd-9vouw.199): the filename `require` would
    /// load (within the module root), the request itself for a core module
    /// (as Node returns 'fs' and 'node:fs'), or a catchable MODULE_NOT_FOUND
    /// Error (bd-9vouw.188). Packages probe optional dependencies with it
    /// (`try { require.resolve('x') } catch {}`); it was undefined. The
    /// `options` argument and `require.resolve.paths` are not supported.
    pub(super) fn require_resolve(&mut self, args: RegRange) -> Result<Value, InterpreterError> {
        let request = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };
        let Value::Str(request) = request else {
            return Err(InterpreterError::RequireSpecifierNotString {
                got: request.type_name().to_string(),
            });
        };
        let specifier = Self::utf8_module_specifier(&request)?;
        if self.module_resolver.is_some() {
            let resolved =
                match self.resolve_installed_module_metadata(specifier, ImportStyle::Require) {
                    Ok(resolved) => resolved,
                    Err(InterpreterError::ModuleResolutionFailed { reason, .. }) => {
                        return Err(self.throw_module_resolution_failure(
                            request.as_ref(),
                            &reason,
                            ImportStyle::Require,
                        ));
                    }
                    Err(error) => return Err(error),
                };
            let metadata = &resolved.module.metadata;
            if metadata.provenance.kind == ModuleSourceKind::BuiltIn {
                let canonical = metadata.provenance.origin.as_str();
                let name = if node_builtin_specifier(specifier) == Some(canonical) {
                    specifier
                } else {
                    canonical
                };
                return Ok(Value::str(name));
            }
            let filename = self.module_filename_view(&metadata.id);
            self.check_temporary_memory_budget(Self::estimate_string_bytes(filename))?;
            return Ok(Value::str(filename));
        }
        if node_builtin_specifier(specifier).is_some() {
            return Ok(Value::Str(request));
        }
        if is_node_core_module_specifier(specifier) {
            return Err(self.throw_module_resolution_failure(
                request.as_ref(),
                &ModuleResolutionFailureReason::ModuleNotFound,
                ImportStyle::Require,
            ));
        }
        match self.resolve_require_specifier(specifier) {
            Ok(resolved) => Ok(Value::str(resolved)),
            Err(InterpreterError::ModuleResolutionFailed { reason, .. }) => Err(self
                .throw_module_resolution_failure(request.as_ref(), &reason, ImportStyle::Require)),
            Err(error) => Err(error),
        }
    }

    /// Synchronous URL resolution is metadata only. The callable has already
    /// installed its defining module's identity; neither its receiver nor an
    /// optional second argument can replace that authority or its URL base.
    pub(super) fn import_meta_resolve(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let argument = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let primitive = self.coerce_runtime_primitive(module, argument, true)?;
        if matches!(primitive, Value::Symbol(_)) {
            return Err(Self::symbol_to_string_error());
        }
        self.check_temporary_memory_budget(self.url_value_to_string_upper_bound(&primitive))?;
        let request = match primitive {
            Value::Str(request) => request,
            value => JsString::from(self.value_to_string(&value)),
        };
        let specifier = Self::utf8_module_specifier(&request)?;
        if self.module_resolver.is_some() {
            let resolved =
                match self.resolve_installed_module_metadata(specifier, ImportStyle::Import) {
                    Ok(resolved) => resolved,
                    Err(InterpreterError::ModuleResolutionFailed { reason, .. }) => {
                        return Err(self.throw_module_resolution_failure(
                            request.as_ref(),
                            &reason,
                            ImportStyle::Import,
                        ));
                    }
                    Err(error) => return Err(error),
                };
            let metadata = &resolved.module.metadata;
            let url = match &metadata.target {
                ModuleMetadataTarget::AbsoluteUrl(url) => url.as_str(),
                ModuleMetadataTarget::SourceUrl => self
                    .module_resolver
                    .as_ref()
                    .and_then(|installed| installed.resolver.source_location(&metadata.id))
                    .map(|location| location.url.as_str())
                    .ok_or_else(|| InterpreterError::InternalError {
                        details: "authorized URL metadata lost its source location".to_string(),
                    })?,
                ModuleMetadataTarget::Filename => {
                    return Err(InterpreterError::InternalError {
                        details: "filename metadata escaped URL-purpose validation".to_string(),
                    });
                }
            };
            self.check_temporary_memory_budget(Self::estimate_string_bytes(url))?;
            return Ok(Value::str(url));
        }
        match self.resolve_import_meta_url(specifier) {
            Ok(url) => {
                self.check_temporary_memory_budget(Self::estimate_string_bytes(&url))?;
                Ok(Value::str(url))
            }
            Err(InterpreterError::ModuleResolutionFailed { reason, .. }) => Err(self
                .throw_module_resolution_failure(request.as_ref(), &reason, ImportStyle::Import)),
            Err(error) => Err(error),
        }
    }

    pub(super) fn dispatch_require_hostcall_inner(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
        native_effect: &mut bool,
    ) -> Result<Value, InterpreterError> {
        let spec_val = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };
        let specifier = match spec_val {
            Value::Str(specifier) => specifier,
            other => {
                return Err(InterpreterError::RequireSpecifierNotString {
                    got: other.type_name().to_string(),
                });
            }
        };
        let module = module.ok_or_else(|| InterpreterError::InternalError {
            details: "module:require apply hostcall missing module context".to_string(),
        })?;
        match self.require_module_with_native_effect_provenance(module, &specifier, native_effect) {
            // Node names the request as written, not the resolved path.
            Err(InterpreterError::ModuleResolutionFailed { reason, .. }) => Err(self
                .throw_module_resolution_failure(
                    specifier.as_ref(),
                    &reason,
                    ImportStyle::Require,
                )),
            result => result,
        }
    }

    /// Preserve the catchable Node code of an admitted resolution outcome.
    /// Package encapsulation and private imports errors must remain distinct
    /// from absence so npm feature-detection can select the right fallback.
    pub(super) fn throw_module_resolution_failure(
        &mut self,
        specifier: &str,
        reason: &ModuleResolutionFailureReason,
        style: ImportStyle,
    ) -> InterpreterError {
        let (name, message) = match reason {
            ModuleResolutionFailureReason::PackagePathNotExported => (
                "Error",
                format!("Package subpath '{specifier}' is not exported"),
            ),
            ModuleResolutionFailureReason::PackageImportNotDefined => (
                "TypeError",
                format!("Package import specifier '{specifier}' is not defined"),
            ),
            ModuleResolutionFailureReason::NativeAddonUnsupported => (
                "Error",
                format!("Native addon '{specifier}' cannot be loaded: {reason}"),
            ),
            _ => (
                "Error",
                format!("Cannot find module '{specifier}'\n{reason}"),
            ),
        };
        let error = self.throw_js_error(name, message);
        if let Some(Value::Object(error_id)) = self.pending_exception.clone()
            && let Err(failure) = self.set_object_property(
                error_id,
                "code".to_string(),
                Value::str(reason.guest_error_code(style)),
            )
        {
            return failure;
        }
        error
    }

    /// Dispatch an ESM import and emit exactly one module-load telemetry record
    /// for both success and failure.
    ///
    /// `ImportModule` is an IR read effect rather than a HostCall, so its caller
    /// applies the shared live gate explicitly before reaching this telemetry
    /// and resolver boundary.
    pub(super) fn dispatch_import_hostcall(
        &mut self,
        capability: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        self.dispatch_import_hostcall_with_native_effect_provenance(
            capability,
            args,
            module,
            &ImportAttributes::default(),
            &mut false,
        )
    }

    pub(super) fn dispatch_import_hostcall_with_native_effect_provenance(
        &mut self,
        capability: &str,
        args: RegRange,
        module: Option<&Ir3Module>,
        import_attributes: &ImportAttributes,
        native_effect: &mut bool,
    ) -> Result<Value, InterpreterError> {
        *native_effect = false;
        // Telemetry's arguments_hash identifies register operands, as for other
        // instructions. Static attributes are authenticated by the enclosing
        // IR hash and checked on every request; this hash is not a route grant.
        let args_hash = self.hostcall_arguments_hash(args);
        let outcome = if capability == crate::capability::DYNAMIC_IMPORT_CAPABILITY {
            self.dynamic_import(args, module)
        } else {
            self.dispatch_import_hostcall_inner(args, module, import_attributes, native_effect)
        };
        // See `dispatch_require_hostcall`: nested module evaluation records
        // inner completions first, so the outer record takes its timestamp at
        // completion as well.
        let timestamp_ns = self.instructions_executed;
        self.record_hostcall_telemetry(capability, args, timestamp_ns, args_hash, &outcome);
        outcome
    }

    pub(super) fn dispatch_import_hostcall_inner(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
        import_attributes: &ImportAttributes,
        native_effect: &mut bool,
    ) -> Result<Value, InterpreterError> {
        let specifier_value = if args.count > 0 {
            self.read_reg(args.start)?
        } else {
            Value::Undefined
        };
        let specifier = match specifier_value {
            Value::Str(specifier) => specifier,
            other => {
                return Err(InterpreterError::ImportSpecifierNotString {
                    got: other.type_name().to_string(),
                });
            }
        };
        let module = module.ok_or_else(|| InterpreterError::InternalError {
            details: "module import hostcall missing module context".to_string(),
        })?;
        self.import_module_with_native_effect_provenance(
            module,
            &specifier,
            import_attributes,
            native_effect,
        )
    }

    /// `import(specifier)` (ES2020 12.3.10.1 with HostImportModuleDynamically
    /// and FinishDynamicImport, 15.2.1.17-18): a new promise fulfilled with
    /// the module's namespace object, or rejected with what ToString of the
    /// specifier, resolution or evaluation threw. A guest-catchable failure
    /// never throws at the call site; engine faults, resource limits and
    /// lowering refusals end the run, as they do for a static import.
    ///
    /// ToString is observable on the calling stack. Resolution, policy and
    /// evaluation run as a host job after the current checkpoint, using the
    /// initiating module's captured context and the ordinary loader/cache.
    pub(super) fn dynamic_import(
        &mut self,
        args: RegRange,
        module: Option<&Ir3Module>,
    ) -> Result<Value, InterpreterError> {
        if args.count > 1 {
            return Err(InterpreterError::ModuleLoweringFailed {
                specifier: "<dynamic import>".to_string(),
                error: "dynamic import options are not transported by the runtime yet".to_string(),
            });
        }
        let module = module.ok_or_else(|| InterpreterError::InternalError {
            details: "module:dynamic_import hostcall missing module context".to_string(),
        })?;
        let mut specifier_label = self.join_arg_range_label(args)?;
        let specifier = self
            .builtin_search_js_string(module, args, 0)
            .and_then(|specifier| {
                let specifier = Self::utf8_module_specifier(&specifier)?;
                self.check_temporary_memory_budget(Self::estimate_string_bytes(specifier))?;
                Ok(specifier.to_string())
            });
        if let Some(label) = self.pending_hostcall_result_label.as_ref() {
            specifier_label =
                self.join_owned_label_with_temporary_budget(specifier_label, label)?;
        }
        // Intrinsic Promise allocation is unobservable. Do it after the
        // arbitrary guest ToString callback, so no unrooted Promise spans it.
        let promise = self.create_promise()?;
        let specifier = match specifier {
            Ok(specifier) => specifier,
            Err(error) => {
                let result = self
                    .dynamic_import_rejection(error, &specifier_label)
                    .and_then(|(reason, label)| self.reject_promise(promise, reason, label));
                if let Err(error) = result {
                    self.rollback_fresh_promise(promise);
                    return Err(error);
                }
                return Ok(Value::Promise(promise.0));
            }
        };
        let referrer = self
            .current_module_specifier
            .as_deref()
            .unwrap_or(&module.header.source_label);
        let owner_module = self
            .module_state
            .modules
            .get(referrer)
            .and_then(|record| record.compiled_module.as_ref())
            .filter(|program| program.header.source_label == module.header.source_label)
            .cloned();
        let Some(owner_module) = owner_module else {
            let error = InterpreterError::ModuleEvaluationFailed {
                specifier: referrer.to_string(),
                reason: "dynamic import's initiating module program is not retained".to_string(),
            };
            self.rollback_fresh_promise(promise);
            return Err(error);
        };
        let capture_bytes = Self::estimate_string_bytes(referrer)
            .saturating_add(
                self.active_cjs_context
                    .as_ref()
                    .map(|context| Self::estimate_string_bytes(&context.module_specifier))
                    .unwrap_or(0),
            )
            .saturating_add(
                self.active_execution_context_label()
                    .map(Self::estimate_label_bytes)
                    .unwrap_or(0),
            );
        if let Err(error) = self.check_temporary_memory_budget(capture_bytes) {
            self.rollback_fresh_promise(promise);
            return Err(error);
        }
        let task = PendingDynamicImportTask {
            owner_module,
            referrer: referrer.to_string(),
            specifier,
            promise,
            label: specifier_label,
            cjs_context: self.active_cjs_context.clone(),
            inline_context_label: self.active_execution_context_label().cloned(),
            source_ip: self.ip,
        };
        let retained_bytes = Self::pending_dynamic_import_task_bytes(&task);
        if let Err(error) = self.apply_memory_component_delta(0, retained_bytes) {
            self.rollback_fresh_promise(promise);
            return Err(error);
        }
        let previous_promise_bytes = self.promise_runtime_memory_bytes();
        let sequence = self.event_loop.schedule_io_completion(
            crate::closure_model::ClosureHandle(u32::MAX),
            task.label.clone(),
        );
        if let Err(error) = self.apply_promise_runtime_memory_delta(previous_promise_bytes) {
            self.event_loop.rollback_last_scheduled(sequence);
            self.estimated_memory_bytes =
                self.estimated_memory_bytes.saturating_sub(retained_bytes);
            self.rollback_fresh_promise(promise);
            return Err(error);
        }
        self.pending_dynamic_imports
            .insert(sequence, Arc::new(task));
        Ok(Value::Promise(promise.0))
    }
}
