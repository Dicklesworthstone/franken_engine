//! RegExp.prototype[@@match], [@@search], [@@replace] and [@@split] as
//! ES2024 22.2.6 specifies them, for a receiver whose reads are observable
//! (bd-9vouw.257).
//!
//! The engine's matcher answers these directly for a pristine RegExp
//! ([`InterpreterCore::regexp_is_pristine`]): every read the algorithms
//! make of it answers what the matcher assumes, so the result is the same.
//! Any other receiver (a user `exec`, own, inherited or a subclass method;
//! an own or prototype override of `flags` or a flag getter; a non-number
//! `lastIndex`; a subclass instance; a plain object) takes the algorithms
//! here, which read what the specification reads, in its order: RegExpExec,
//! `flags`, `lastIndex` gets and sets, and each exec result's `length`,
//! `0`, `index`, captures and `groups`. String.prototype.match, search,
//! replace and split reach them too, through the receiver's builtin
//! @@method.
//!
//! No-claim: @@matchAll keeps the matcher path (its RegExpStringIterator
//! is not a lazy iterator here); `lastIndex` writes reach object
//! receivers only (a function receiver's are not modeled).

use super::*;

/// The %RegExp.prototype% names the algorithms read. A stored own property
/// of one of these names (a guest assignment or definition) overrides the
/// intrinsic, which is served virtually.
const PROTOCOL_PROTOTYPE_NAMES: [&str; 12] = [
    "exec",
    "flags",
    "global",
    "unicode",
    "unicodeSets",
    "sticky",
    "hasIndices",
    "ignoreCase",
    "multiline",
    "dotAll",
    "source",
    "constructor",
];

impl InterpreterCore {
    /// Whether the matcher may answer for `receiver`: a RegExp whose only
    /// own property is `lastIndex` (a number), whose prototype is the
    /// intrinsic %RegExp.prototype% with no stored override of a name the
    /// algorithms read.
    pub(super) fn regexp_is_pristine(&self, receiver: &Value) -> bool {
        let Value::Object(id) = receiver else {
            return false;
        };
        let Some(object) = self.heap.get(id.0 as usize) else {
            return false;
        };
        if object.brand() != Some("RegExp") || object.regexp.is_none() {
            return false;
        }
        if !matches!(
            object.properties.get("lastIndex"),
            None | Some(Value::Int(_) | Value::Float(_))
        ) || object
            .properties
            .keys()
            .any(|key| key.as_str() != "lastIndex")
        {
            return false;
        }
        let Some(prototype) = self.builtin_prototypes.get("RegExp").copied() else {
            return false;
        };
        object.prototype == Some(prototype)
            && self
                .heap
                .get(prototype.0 as usize)
                .is_some_and(|prototype| {
                    prototype.deleted_virtual_keys.is_empty()
                        && PROTOCOL_PROTOTYPE_NAMES
                            .iter()
                            .all(|name| prototype.properties.get(name).is_none())
                })
    }

    /// RegExp.prototype[@@match / @@search / @@replace / @@split] for a
    /// receiver that is not pristine, with `string` not yet converted,
    /// `extra` the method's second argument (replaceValue, limit) and
    /// `label` the join of the arguments' labels, which every guest call
    /// receives and the result carries. `None` for @@matchAll, which keeps
    /// the matcher path.
    pub(super) fn regexp_symbol_method_generic(
        &mut self,
        module: &Ir3Module,
        method: &str,
        rx: &Value,
        string: Value,
        extra: Value,
        label: &Label,
    ) -> Result<Option<Value>, InterpreterError> {
        if !matches!(method, "@@match" | "@@search" | "@@replace" | "@@split") {
            return Ok(None);
        }
        if !rx.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: format!("object receiver for RegExp.prototype[{method}]"),
                got: rx.type_name().to_string(),
            });
        }
        // Guest code runs below while native locals hold values: no
        // collection until this returns.
        self.gc_nested_request = None;
        let input = self.protocol_to_string(module, string)?;
        let result = match method {
            "@@match" => self.regexp_symbol_match_generic(module, rx, &input, label)?,
            "@@search" => self.regexp_symbol_search_generic(module, rx, &input, label)?,
            "@@replace" => self.regexp_symbol_replace_generic(module, rx, &input, extra, label)?,
            _ => self.regexp_symbol_split_generic(module, rx, &input, extra, label)?,
        };
        let joined = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(label);
        self.replace_pending_hostcall_result_label(Some(joined))?;
        Ok(Some(result))
    }

    /// String.prototype.replaceAll step 2.b (ES2021 22.1.3.19) for a
    /// RegExp search value that is not pristine: ToString(Get(searchValue,
    /// "flags")) must contain "g" (undefined or null flags are a
    /// TypeError). A pristine RegExp's flags are checked from its slot by
    /// the matcher path.
    pub(super) fn string_replace_all_observable_flags_check(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        args: RegRange,
    ) -> Result<(), InterpreterError> {
        if matches!(receiver, Value::Undefined | Value::Null) {
            return Ok(());
        }
        let Some(search) = self.builtin_arg(args, 0)? else {
            return Ok(());
        };
        if self.regexp_source_flags_from_value(&search).is_none()
            || self.regexp_is_pristine(&search)
        {
            return Ok(());
        }
        self.gc_nested_request = None;
        let flags = self.protocol_get(module, &search, "flags")?;
        if matches!(flags, Value::Undefined | Value::Null) {
            return Err(InterpreterError::TypeError {
                expected: "RegExp flags for String.prototype.replaceAll".to_string(),
                got: flags.type_name().to_string(),
            });
        }
        if !self
            .protocol_to_string(module, flags)?
            .as_utf8_projection()
            .contains('g')
        {
            return Err(InterpreterError::TypeError {
                expected: "global RegExp for String.prototype.replaceAll".to_string(),
                got: "non-global RegExp".to_string(),
            });
        }
        Ok(())
    }

    fn protocol_get(
        &mut self,
        module: &Ir3Module,
        object: &Value,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        self.get_v(
            module,
            object,
            &RuntimePropertyKey::String(JsString::from(key)),
        )
    }

    /// ES2020 7.1.12 ToString, running an object's conversion; a Symbol is
    /// a TypeError.
    fn protocol_to_string(
        &mut self,
        module: &Ir3Module,
        value: Value,
    ) -> Result<JsString, InterpreterError> {
        match self.object_to_string_primitive(Some(module), value)? {
            Value::Symbol(_) => Err(Self::symbol_to_string_error()),
            Value::Str(text) => Ok(text),
            other => Ok(JsString::from(self.value_to_string(&other))),
        }
    }

    /// ES2020 7.1.5 ToIntegerOrInfinity, after ToNumber (an object's
    /// conversion runs; a Symbol or BigInt is a TypeError).
    fn protocol_to_integer(
        &mut self,
        module: &Ir3Module,
        value: Value,
    ) -> Result<f64, InterpreterError> {
        let primitive = self.object_to_number_primitive(Some(module), value)?;
        if matches!(primitive, Value::Symbol(_) | Value::BigInt(_)) {
            return Err(InterpreterError::TypeError {
                expected: "value convertible to a number".to_string(),
                got: primitive.type_name().to_string(),
            });
        }
        let number = Self::coerce_to_float(&primitive).unwrap_or(f64::NAN);
        Ok(if number.is_nan() { 0.0 } else { number.trunc() })
    }

    /// ES2020 7.1.20 ToLength.
    fn protocol_to_length(
        &mut self,
        module: &Ir3Module,
        value: Value,
    ) -> Result<f64, InterpreterError> {
        Ok(self
            .protocol_to_integer(module, value)?
            .clamp(0.0, MAX_SAFE_INTEGER as f64))
    }

    /// A number as a value: an integer that fits stays an Int.
    fn protocol_number(number: f64) -> Value {
        if number.fract() == 0.0 && number.abs() <= MAX_SAFE_INTEGER as f64 {
            Value::Int(number as i64)
        } else {
            Value::Float(Float64::new(number))
        }
    }

    /// Set(O, key, value, true) (ES2020 7.3.4): a failed set is a
    /// TypeError.
    fn protocol_set(
        &mut self,
        module: &Ir3Module,
        object: &Value,
        key: &str,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let Value::Object(id) = object else {
            return Err(InterpreterError::TypeError {
                expected: format!("an object whose {key} can be set"),
                got: object.type_name().to_string(),
            });
        };
        let set = self.proxy_aware_set_runtime_property(
            Some(module),
            *id,
            &RuntimePropertyKey::String(JsString::from(key)),
            value,
            object.clone(),
            0,
        )?;
        if !set {
            return Err(InterpreterError::TypeError {
                expected: format!("a writable {key}"),
                got: "a property that cannot be set".to_string(),
            });
        }
        Ok(())
    }

    /// ES2020 21.2.5.2.1 RegExpExec(R, S): a callable `exec` other than the
    /// intrinsic one runs (its result must be an object or null);
    /// otherwise R must be a RegExp and RegExpBuiltinExec runs.
    fn regexp_exec_generic(
        &mut self,
        module: &Ir3Module,
        rx: &Value,
        input: &JsString,
        label: &Label,
    ) -> Result<Value, InterpreterError> {
        let exec = self.protocol_get(module, rx, "exec")?;
        let intrinsic = matches!(&exec, Value::BuiltinFunction(builtin)
            if builtin.kind == BuiltinFunctionKind::RegExpPrototypeExec);
        let subject = Value::Str(input.clone());
        if exec.is_callable() && !intrinsic {
            return self.regexp_call_user_exec(module, exec, rx, &subject, Some(label.clone()));
        }
        if self.regexp_source_flags_from_value(rx).is_none() {
            return Err(InterpreterError::TypeError {
                expected: "a RegExp, or an object with a callable exec".to_string(),
                got: rx.type_name().to_string(),
            });
        }
        let last_index = self.regexp_coerced_last_index(module, rx)?;
        self.regexp_prototype_exec_from(rx.clone(), &subject, last_index)
    }

    /// ES2024 22.2.7.3 AdvanceStringIndex.
    fn advance_string_index(units: &[u16], index: f64, unicode: bool) -> f64 {
        if !unicode || index + 1.0 >= units.len() as f64 {
            return index + 1.0;
        }
        let at = index as usize;
        let surrogate_pair = (0xD800..=0xDBFF).contains(&units[at])
            && units
                .get(at + 1)
                .is_some_and(|trail| (0xDC00..=0xDFFF).contains(trail));
        index + if surrogate_pair { 2.0 } else { 1.0 }
    }

    /// ToString(Get(rx, "flags")).
    fn regexp_protocol_flags(
        &mut self,
        module: &Ir3Module,
        rx: &Value,
    ) -> Result<String, InterpreterError> {
        let flags = self.protocol_get(module, rx, "flags")?;
        Ok(self
            .protocol_to_string(module, flags)?
            .as_utf8_projection()
            .to_string())
    }

    /// When the matched string of a global match is empty, lastIndex moves
    /// past it (AdvanceStringIndex of ToLength(Get(rx, "lastIndex"))).
    fn regexp_protocol_step_past_empty(
        &mut self,
        module: &Ir3Module,
        rx: &Value,
        units: &[u16],
        full_unicode: bool,
    ) -> Result<(), InterpreterError> {
        let last_index = self.protocol_get(module, rx, "lastIndex")?;
        let this_index = self.protocol_to_length(module, last_index)?;
        let next = Self::advance_string_index(units, this_index, full_unicode);
        self.protocol_set(module, rx, "lastIndex", Self::protocol_number(next))
    }

    /// ES2024 22.2.6.8 RegExp.prototype[@@match].
    fn regexp_symbol_match_generic(
        &mut self,
        module: &Ir3Module,
        rx: &Value,
        input: &JsString,
        label: &Label,
    ) -> Result<Value, InterpreterError> {
        let flags = self.regexp_protocol_flags(module, rx)?;
        if !flags.contains('g') {
            return self.regexp_exec_generic(module, rx, input, label);
        }
        let full_unicode = flags.contains('u') || flags.contains('v');
        self.protocol_set(module, rx, "lastIndex", Value::Int(0))?;
        let units = input.code_units_vec();
        let mut matches = Vec::new();
        loop {
            // A guest exec decides when this ends; each step costs an
            // instruction of the run's budget.
            self.charge_property_copy_work()?;
            let result = self.regexp_exec_generic(module, rx, input, label)?;
            if matches!(result, Value::Null) {
                if matches.is_empty() {
                    return Ok(Value::Null);
                }
                return Ok(Value::Object(self.alloc_array_from_values(&matches)?));
            }
            let matched = self.protocol_get(module, &result, "0")?;
            let matched = self.protocol_to_string(module, matched)?;
            let empty = matched.utf16_len() == 0;
            matches.push(Value::Str(matched));
            if empty {
                self.regexp_protocol_step_past_empty(module, rx, &units, full_unicode)?;
            }
        }
    }

    /// ES2024 22.2.6.12 RegExp.prototype[@@search].
    fn regexp_symbol_search_generic(
        &mut self,
        module: &Ir3Module,
        rx: &Value,
        input: &JsString,
        label: &Label,
    ) -> Result<Value, InterpreterError> {
        let previous = self.protocol_get(module, rx, "lastIndex")?;
        let positive_zero = |value: &Value| match value {
            Value::Int(0) => true,
            Value::Float(number) => number.0 == 0.0 && number.0.is_sign_positive(),
            _ => false,
        };
        if !positive_zero(&previous) {
            self.protocol_set(module, rx, "lastIndex", Value::Int(0))?;
        }
        let result = self.regexp_exec_generic(module, rx, input, label)?;
        let current = self.protocol_get(module, rx, "lastIndex")?;
        if !Self::same_value(&current, &previous) {
            self.protocol_set(module, rx, "lastIndex", previous)?;
        }
        if matches!(result, Value::Null) {
            return Ok(Value::Int(-1));
        }
        self.protocol_get(module, &result, "index")
    }

    /// ES2024 22.2.6.11 RegExp.prototype[@@replace].
    fn regexp_symbol_replace_generic(
        &mut self,
        module: &Ir3Module,
        rx: &Value,
        input: &JsString,
        replace_value: Value,
        label: &Label,
    ) -> Result<Value, InterpreterError> {
        let units = input.code_units_vec();
        let length = units.len();
        let functional = replace_value.is_callable();
        let template = if functional {
            Vec::new()
        } else {
            self.protocol_to_string(module, replace_value.clone())?
                .code_units_vec()
        };
        let flags = self.regexp_protocol_flags(module, rx)?;
        let global = flags.contains('g');
        let full_unicode = flags.contains('u') || flags.contains('v');
        if global {
            self.protocol_set(module, rx, "lastIndex", Value::Int(0))?;
        }
        let mut results = Vec::new();
        loop {
            self.charge_property_copy_work()?;
            let result = self.regexp_exec_generic(module, rx, input, label)?;
            if matches!(result, Value::Null) {
                break;
            }
            results.push(result.clone());
            if !global {
                break;
            }
            let matched = self.protocol_get(module, &result, "0")?;
            if self.protocol_to_string(module, matched)?.utf16_len() == 0 {
                self.regexp_protocol_step_past_empty(module, rx, &units, full_unicode)?;
            }
        }

        let mut accumulated = Vec::<u16>::new();
        let mut next_source_position = 0usize;
        for result in results {
            let result_length = self.protocol_get(module, &result, "length")?;
            let result_length = self.protocol_to_length(module, result_length)?;
            let capture_count = (result_length - 1.0).max(0.0);
            let matched = self.protocol_get(module, &result, "0")?;
            let matched = self.protocol_to_string(module, matched)?.code_units_vec();
            let position = self.protocol_get(module, &result, "index")?;
            let position = self
                .protocol_to_integer(module, position)?
                .clamp(0.0, length as f64) as usize;
            let mut captures = Vec::<Option<Vec<u16>>>::new();
            let mut index = 1.0;
            while index <= capture_count {
                self.charge_property_copy_work()?;
                let capture = self.protocol_get(module, &result, &(index as u64).to_string())?;
                captures.push(if matches!(capture, Value::Undefined) {
                    None
                } else {
                    Some(self.protocol_to_string(module, capture)?.code_units_vec())
                });
                index += 1.0;
            }
            let named_captures = self.protocol_get(module, &result, "groups")?;
            let replacement = if functional {
                let mut arguments = vec![Value::Str(JsString::from_code_units(&matched))];
                arguments.extend(captures.iter().map(|capture| {
                    capture.as_ref().map_or(Value::Undefined, |units| {
                        Value::Str(JsString::from_code_units(units))
                    })
                }));
                arguments.push(Self::protocol_number(position as f64));
                arguments.push(Value::Str(input.clone()));
                if !matches!(named_captures, Value::Undefined) {
                    arguments.push(named_captures);
                }
                let (value, result_label) = self.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    replace_value.clone(),
                    Value::Undefined,
                    arguments,
                    Some(label.clone()),
                )?;
                let joined = self
                    .pending_hostcall_result_label
                    .as_ref()
                    .unwrap_or(&Label::Public)
                    .join(&result_label);
                self.replace_pending_hostcall_result_label(Some(joined))?;
                self.observe_scoped_callback_result()?;
                self.protocol_to_string(module, value)?.code_units_vec()
            } else {
                // ToObject(namedCaptures): null is a TypeError; a primitive
                // reads its prototype's properties, as its wrapper would.
                let named = match named_captures {
                    Value::Undefined => None,
                    Value::Null => {
                        return Err(InterpreterError::TypeError {
                            expected: "object or undefined exec result groups".to_string(),
                            got: "null".to_string(),
                        });
                    }
                    other => Some(other),
                };
                self.protocol_get_substitution(
                    module,
                    &matched,
                    &units,
                    position,
                    &captures,
                    named.as_ref(),
                    &template,
                )?
            };
            if position >= next_source_position {
                accumulated.extend_from_slice(&units[next_source_position..position]);
                accumulated.extend_from_slice(&replacement);
                self.check_string_limit(accumulated.len())?;
                next_source_position = position + matched.len();
            }
        }
        if next_source_position < length {
            accumulated.extend_from_slice(&units[next_source_position..]);
            self.check_string_limit(accumulated.len())?;
        }
        Ok(Value::Str(JsString::from_code_units(&accumulated)))
    }

    /// ES2024 22.1.3.19.1 GetSubstitution over UTF-16, with `$<name>` read
    /// from a groups object through [[Get]] and ToString.
    #[allow(clippy::too_many_arguments)]
    fn protocol_get_substitution(
        &mut self,
        module: &Ir3Module,
        matched: &[u16],
        string: &[u16],
        position: usize,
        captures: &[Option<Vec<u16>>],
        named_captures: Option<&Value>,
        template: &[u16],
    ) -> Result<Vec<u16>, InterpreterError> {
        const DOLLAR: u16 = b'$' as u16;
        let is_digit = |unit: u16| (u16::from(b'0')..=u16::from(b'9')).contains(&unit);
        let tail = (position + matched.len()).min(string.len());
        let capture_count = captures.len();
        let mut result = Vec::with_capacity(template.len());
        let mut at = 0usize;
        while at < template.len() {
            // A template can expand far beyond its own length (`$'`
            // repeated), so the expansion is bounded while it is built.
            self.check_string_limit(result.len())?;
            let unit = template[at];
            let Some(&next) = template.get(at + 1).filter(|_| unit == DOLLAR) else {
                result.push(unit);
                at += 1;
                continue;
            };
            match next {
                n if n == DOLLAR => {
                    result.push(DOLLAR);
                    at += 2;
                }
                n if n == u16::from(b'&') => {
                    result.extend_from_slice(matched);
                    at += 2;
                }
                n if n == u16::from(b'`') => {
                    result.extend_from_slice(&string[..position.min(string.len())]);
                    at += 2;
                }
                n if n == u16::from(b'\'') => {
                    result.extend_from_slice(&string[tail..]);
                    at += 2;
                }
                n if is_digit(n) => {
                    let first = usize::from(n - u16::from(b'0'));
                    let two_digit = template
                        .get(at + 2)
                        .copied()
                        .filter(|unit| is_digit(*unit))
                        .map(|unit| first * 10 + usize::from(unit - u16::from(b'0')))
                        .filter(|index| *index <= capture_count);
                    let (index, digits) = match two_digit {
                        Some(index) => (index, 2),
                        None => (first, 1),
                    };
                    if (1..=capture_count).contains(&index) {
                        if let Some(capture) = &captures[index - 1] {
                            result.extend_from_slice(capture);
                        }
                    } else {
                        result.extend_from_slice(&template[at..at + 1 + digits]);
                    }
                    at += 1 + digits;
                }
                n if n == u16::from(b'<') => {
                    let Some(groups) = named_captures else {
                        result.extend_from_slice(&template[at..at + 2]);
                        at += 2;
                        continue;
                    };
                    let Some(close) = template[at + 2..]
                        .iter()
                        .position(|unit| *unit == u16::from(b'>'))
                    else {
                        result.extend_from_slice(&template[at..at + 2]);
                        at += 2;
                        continue;
                    };
                    let name = JsString::from_code_units(&template[at + 2..at + 2 + close]);
                    let capture = self.get_v(module, groups, &RuntimePropertyKey::String(name))?;
                    if !matches!(capture, Value::Undefined) {
                        result.extend(self.protocol_to_string(module, capture)?.code_units_vec());
                    }
                    at += 3 + close;
                }
                _ => {
                    result.push(DOLLAR);
                    at += 1;
                }
            }
        }
        Ok(result)
    }

    /// ES2024 22.2.6.14 RegExp.prototype[@@split].
    fn regexp_symbol_split_generic(
        &mut self,
        module: &Ir3Module,
        rx: &Value,
        input: &JsString,
        limit: Value,
        label: &Label,
    ) -> Result<Value, InterpreterError> {
        // SpeciesConstructor(rx, %RegExp%) (ES2020 7.3.20).
        let intrinsic = Value::BuiltinFunction(BuiltinFunction::standard_constructor("RegExp"));
        let constructor = self.protocol_get(module, rx, "constructor")?;
        let species = if matches!(constructor, Value::Undefined) {
            intrinsic
        } else {
            if !constructor.is_object_like() {
                return Err(InterpreterError::TypeError {
                    expected: "object or undefined RegExp constructor".to_string(),
                    got: constructor.type_name().to_string(),
                });
            }
            match self.species_of_constructor(module, &constructor)? {
                Value::Undefined | Value::Null => intrinsic,
                species if self.is_constructible_value(&species) => species,
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "constructor @@species for a RegExp".to_string(),
                        got: other.type_name().to_string(),
                    });
                }
            }
        };
        let flags = self.regexp_protocol_flags(module, rx)?;
        let unicode_matching = flags.contains('u') || flags.contains('v');
        let new_flags = if flags.contains('y') {
            flags
        } else {
            format!("{flags}y")
        };
        let (splitter, splitter_label) = self.invoke_inline_construct_with_labels(
            Some(module),
            species,
            vec![rx.clone(), Value::str(new_flags)],
            Some(IsolatedCallLabels {
                receiver: Label::Public,
                arguments: IsolatedArgumentLabels::Uniform(label.clone()),
            }),
            None,
        )?;
        let joined = self
            .pending_hostcall_result_label
            .as_ref()
            .unwrap_or(&Label::Public)
            .join(&splitter_label);
        self.replace_pending_hostcall_result_label(Some(joined))?;
        self.observe_scoped_callback_result()?;
        // ToUint32(limit), 2^32 - 1 for undefined.
        let limit = if matches!(limit, Value::Undefined) {
            u64::from(u32::MAX)
        } else {
            let integer = self.protocol_to_integer(module, limit)?;
            if integer.is_finite() {
                integer.rem_euclid(4_294_967_296.0) as u64
            } else {
                0
            }
        };
        let mut parts = Vec::<Value>::new();
        if limit == 0 {
            return Ok(Value::Object(self.alloc_array_from_values(&parts)?));
        }
        let units = input.code_units_vec();
        let size = units.len();
        if size == 0 {
            if matches!(
                self.regexp_exec_generic(module, &splitter, input, label)?,
                Value::Null
            ) {
                parts.push(Value::Str(input.clone()));
            }
            return Ok(Value::Object(self.alloc_array_from_values(&parts)?));
        }
        let mut start = 0usize;
        let mut at = start;
        while at < size {
            self.charge_property_copy_work()?;
            self.protocol_set(
                module,
                &splitter,
                "lastIndex",
                Self::protocol_number(at as f64),
            )?;
            let found = self.regexp_exec_generic(module, &splitter, input, label)?;
            if matches!(found, Value::Null) {
                at = Self::advance_string_index(&units, at as f64, unicode_matching) as usize;
                continue;
            }
            let last_index = self.protocol_get(module, &splitter, "lastIndex")?;
            let end = self
                .protocol_to_length(module, last_index)?
                .min(size as f64) as usize;
            if end == start {
                at = Self::advance_string_index(&units, at as f64, unicode_matching) as usize;
                continue;
            }
            parts.push(Value::Str(JsString::from_code_units(&units[start..at])));
            if parts.len() as u64 == limit {
                return Ok(Value::Object(self.alloc_array_from_values(&parts)?));
            }
            start = end;
            let found_length = self.protocol_get(module, &found, "length")?;
            let capture_count = (self.protocol_to_length(module, found_length)? - 1.0).max(0.0);
            let mut index = 1.0;
            while index <= capture_count {
                self.charge_property_copy_work()?;
                parts.push(self.protocol_get(module, &found, &(index as u64).to_string())?);
                if parts.len() as u64 == limit {
                    return Ok(Value::Object(self.alloc_array_from_values(&parts)?));
                }
                index += 1.0;
            }
            at = start;
        }
        parts.push(Value::Str(JsString::from_code_units(&units[start..size])));
        Ok(Value::Object(self.alloc_array_from_values(&parts)?))
    }
}
