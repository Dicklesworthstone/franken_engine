//! ES2025 Iterator helpers (bd-9vouw.179), as Node v22 ships them: the
//! `Iterator` global, an abstract constructor whose `prototype` is
//! %IteratorPrototype%; `Iterator.from`; and on %IteratorPrototype% the lazy
//! `map`, `filter`, `take`, `drop` and `flatMap`, which return iterator
//! helpers (%IteratorHelperPrototype%), and the eager `reduce`, `toArray`,
//! `forEach`, `some`, `every` and `find`.
//!
//! A helper is an ordinary object whose hidden slots hold its kind, the
//! underlying iterator record (the iterator and its `next` method, read once),
//! the callback, a counter and the remaining take/drop count; a `flatMap`
//! helper also holds its current inner iterator record. `next` advances it one
//! step and `return` closes the inner and the underlying iterator. A callback
//! that throws closes the underlying iterator before the throw propagates
//! (IteratorClose with a throw completion: an error from `return` is dropped),
//! and so does a bad argument (ES2025's argument validation closes the
//! receiver).
//!
//! No-claim: a helper's generator state is one running flag (a reentrant
//! `next` or `return` is a TypeError); Iterator.prototype's `constructor` and
//! @@toStringTag are plain values, not the specification's accessors.

use super::*;

/// %IteratorHelperPrototype%: `next` and `return` of the lazy helpers.
pub(super) const ITERATOR_HELPER_PROTOTYPE: &str = "%IteratorHelperPrototype%";
/// %WrapForValidIteratorPrototype%: what `Iterator.from` wraps an iterator
/// that does not inherit from %IteratorPrototype% in.
pub(super) const WRAP_FOR_VALID_ITERATOR_PROTOTYPE: &str = "%WrapForValidIteratorPrototype%";
/// %RegExpStringIteratorPrototype% (ES2020 21.2.7.1): the prototype of the
/// iterator String.prototype.matchAll returns (bd-9vouw.476).
pub(super) const REGEXP_STRING_ITERATOR_PROTOTYPE: &str = "%RegExpStringIteratorPrototype%";

/// (specifier, owner, name) of each built-in: the specifier names the
/// `IteratorHelperMethod` builtin, the owner and name give its `name` and
/// `length` (builtin_function_lengths). %IteratorPrototype%'s methods are in
/// Node's own-key order.
pub(super) const ITERATOR_HELPER_METHODS: [(&str, &str, &str); 17] = [
    ("Iterator.from", "Iterator", "from"),
    ("Iterator.prototype.reduce", "Iterator.prototype", "reduce"),
    (
        "Iterator.prototype.toArray",
        "Iterator.prototype",
        "toArray",
    ),
    (
        "Iterator.prototype.forEach",
        "Iterator.prototype",
        "forEach",
    ),
    ("Iterator.prototype.some", "Iterator.prototype", "some"),
    ("Iterator.prototype.every", "Iterator.prototype", "every"),
    ("Iterator.prototype.find", "Iterator.prototype", "find"),
    ("Iterator.prototype.map", "Iterator.prototype", "map"),
    ("Iterator.prototype.filter", "Iterator.prototype", "filter"),
    ("Iterator.prototype.take", "Iterator.prototype", "take"),
    ("Iterator.prototype.drop", "Iterator.prototype", "drop"),
    (
        "Iterator.prototype.flatMap",
        "Iterator.prototype",
        "flatMap",
    ),
    ("IteratorHelper.next", ITERATOR_HELPER_PROTOTYPE, "next"),
    ("IteratorHelper.return", ITERATOR_HELPER_PROTOTYPE, "return"),
    (
        "WrapForValidIterator.next",
        WRAP_FOR_VALID_ITERATOR_PROTOTYPE,
        "next",
    ),
    (
        "WrapForValidIterator.return",
        WRAP_FOR_VALID_ITERATOR_PROTOTYPE,
        "return",
    ),
    (
        "RegExpStringIterator.next",
        REGEXP_STRING_ITERATOR_PROTOTYPE,
        "next",
    ),
];

const KIND_SLOT: &str = "__iteratorHelperKind";
const ITERATED_SLOT: &str = "__iteratorHelperIterated";
const NEXT_SLOT: &str = "__iteratorHelperNext";
const CALLBACK_SLOT: &str = "__iteratorHelperCallback";
const COUNTER_SLOT: &str = "__iteratorHelperCounter";
const REMAINING_SLOT: &str = "__iteratorHelperRemaining";
const INNER_SLOT: &str = "__iteratorHelperInner";
const INNER_NEXT_SLOT: &str = "__iteratorHelperInnerNext";
const DONE_SLOT: &str = "__iteratorHelperDone";
const RUNNING_SLOT: &str = "__iteratorHelperRunning";

/// Hidden from own-key enumeration and reflection (`own_property_visible`).
pub(super) const ITERATOR_HELPER_SLOT_KEYS: [&str; 10] = [
    KIND_SLOT,
    ITERATED_SLOT,
    NEXT_SLOT,
    CALLBACK_SLOT,
    COUNTER_SLOT,
    REMAINING_SLOT,
    INNER_SLOT,
    INNER_NEXT_SLOT,
    DONE_SLOT,
    RUNNING_SLOT,
];

/// A matchAll iterator's slots: the RegExp it runs (a private clone), the
/// subject, whether the RegExp is full-Unicode, and whether it is done.
const RSI_REGEXP_SLOT: &str = "__regexpStringIteratorRegExp";
const RSI_STRING_SLOT: &str = "__regexpStringIteratorString";
const RSI_UNICODE_SLOT: &str = "__regexpStringIteratorUnicode";
const RSI_DONE_SLOT: &str = "__regexpStringIteratorDone";

/// Hidden from own-key enumeration and reflection (`own_property_visible`).
pub(super) const REGEXP_STRING_ITERATOR_SLOT_KEYS: [&str; 4] = [
    RSI_REGEXP_SLOT,
    RSI_STRING_SLOT,
    RSI_UNICODE_SLOT,
    RSI_DONE_SLOT,
];

/// A wrapper made by `Iterator.from` carries this kind.
const WRAPPER_KIND: &str = "wrap";

pub(super) fn helper_method(specifier: &'static str) -> Value {
    Value::BuiltinFunction(BuiltinFunction {
        kind: BuiltinFunctionKind::IteratorHelperMethod,
        module_specifier: BuiltinModuleSpecifier::from_nonempty(specifier),
        iterator_handle: None,
        bound_object: None,
    })
}

fn string_key(key: &str) -> RuntimePropertyKey {
    RuntimePropertyKey::String(JsString::from(key))
}

impl InterpreterCore {
    /// `new Iterator()` (and Reflect.construct with Iterator as NewTarget):
    /// Iterator is abstract (ES2025 27.1.3.1), Node's message.
    pub(super) fn abstract_iterator_construction_error(&mut self) -> InterpreterError {
        self.throw_js_error(
            "TypeError",
            "Abstract class Iterator not directly constructable".to_string(),
        )
    }

    pub(super) fn iterator_helper_method(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        let specifier = builtin
            .module_specifier
            .0
            .as_deref()
            .unwrap_or_default()
            .to_string();
        let receiver = receiver.unwrap_or(Value::Undefined);
        let arg = |core: &Self, index: u32| -> Result<Value, InterpreterError> {
            Ok(core.builtin_arg(args, index)?.unwrap_or(Value::Undefined))
        };
        match specifier.as_str() {
            "Iterator.from" => {
                let object = arg(self, 0)?;
                self.iterator_from(module, object)
            }
            "IteratorHelper.next" => self.iterator_helper_next(module, &receiver),
            "RegExpStringIterator.next" => self.regexp_string_iterator_next(&receiver),
            "IteratorHelper.return" => self.iterator_helper_return(module, &receiver),
            "WrapForValidIterator.next" => {
                let wrapper = self.iterator_helper_receiver(&receiver, true, "next")?;
                let iterated = self.iterator_helper_slot(wrapper, ITERATED_SLOT)?;
                let next = self.iterator_helper_slot(wrapper, NEXT_SLOT)?;
                self.invoke_inline_method_call(Some(module), next, iterated, Vec::new())
            }
            "WrapForValidIterator.return" => {
                let wrapper = self.iterator_helper_receiver(&receiver, true, "return")?;
                let iterated = self.iterator_helper_slot(wrapper, ITERATED_SLOT)?;
                let return_method = self.get_v(module, &iterated, &string_key("return"))?;
                if matches!(return_method, Value::Undefined | Value::Null) {
                    return self.alloc_iterator_result_object(None);
                }
                self.invoke_inline_method_call(Some(module), return_method, iterated, Vec::new())
            }
            other => {
                let method = other.strip_prefix("Iterator.prototype.").unwrap_or(other);
                // GetIteratorDirect's first step: the receiver is an object.
                if !receiver.is_object_like() {
                    return Err(InterpreterError::TypeError {
                        expected: format!("an iterator object for Iterator.prototype.{method}"),
                        got: receiver.type_name().to_string(),
                    });
                }
                match method {
                    "map" | "filter" | "flatMap" | "take" | "drop" => {
                        let argument = arg(self, 0)?;
                        self.iterator_helper_create(module, method, receiver, argument)
                    }
                    _ => {
                        let first = arg(self, 0)?;
                        let initial = if args.count > 1 {
                            Some(arg(self, 1)?)
                        } else {
                            None
                        };
                        self.iterator_eager_method(module, method, receiver, first, initial)
                    }
                }
            }
        }
    }

    /// The helper behind `receiver` (or the `Iterator.from` wrapper when
    /// `wrapper` is set): an object with the kind slot.
    fn iterator_helper_receiver(
        &self,
        receiver: &Value,
        wrapper: bool,
        method: &str,
    ) -> Result<ObjectId, InterpreterError> {
        if let Value::Object(id) = receiver
            && let Some(Value::Str(kind)) = self
                .heap
                .get(id.0 as usize)
                .and_then(|object| object.properties.get(KIND_SLOT))
            && (kind.as_str() == Some(WRAPPER_KIND)) == wrapper
        {
            return Ok(*id);
        }
        Err(InterpreterError::TypeError {
            expected: format!(
                "an {} for {method}",
                if wrapper {
                    "Iterator.from wrapper"
                } else {
                    "iterator helper"
                }
            ),
            got: receiver.type_name().to_string(),
        })
    }

    /// CreateRegExpStringIterator(R, S, global, fullUnicode) (ES2020
    /// 21.2.7.1) for a global `regexp`: each `next` runs one exec, so only
    /// the match being consumed is alive (bd-9vouw.476).
    pub(super) fn create_regexp_string_iterator(
        &mut self,
        regexp: ObjectId,
        subject: JsString,
        full_unicode: bool,
    ) -> Result<Value, InterpreterError> {
        let prototype = self.ensure_builtin_prototype(REGEXP_STRING_ITERATOR_PROTOTYPE)?;
        let iterator = self.alloc_object_with_prototype(Some(prototype))?;
        self.iterator_helper_set(iterator, RSI_REGEXP_SLOT, Value::Object(regexp))?;
        self.iterator_helper_set(iterator, RSI_STRING_SLOT, Value::Str(subject))?;
        self.iterator_helper_set(iterator, RSI_UNICODE_SLOT, Value::Bool(full_unicode))?;
        self.iterator_helper_set(iterator, RSI_DONE_SLOT, Value::Bool(false))?;
        self.hide_internal_slots(iterator, &REGEXP_STRING_ITERATOR_SLOT_KEYS)?;
        Ok(Value::Object(iterator))
    }

    /// %RegExpStringIteratorPrototype%.next (ES2020 21.2.7.1.1): the next
    /// match, or done once exec finds none. An empty match moves lastIndex on
    /// (AdvanceStringIndex), or the next exec would find it again.
    fn regexp_string_iterator_next(&mut self, receiver: &Value) -> Result<Value, InterpreterError> {
        let iterator = match receiver {
            Value::Object(id)
                if self
                    .heap
                    .get(id.0 as usize)
                    .is_some_and(|object| object.properties.contains_key(RSI_REGEXP_SLOT)) =>
            {
                *id
            }
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "a RegExp String Iterator for next".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        if matches!(
            self.iterator_helper_slot(iterator, RSI_DONE_SLOT)?,
            Value::Bool(true)
        ) {
            return self.alloc_iterator_result_object(None);
        }
        let regexp = self.iterator_helper_slot(iterator, RSI_REGEXP_SLOT)?;
        let subject = self.iterator_helper_slot(iterator, RSI_STRING_SLOT)?;
        // Each exec costs what the guest `re.exec(s)` it stands for would:
        // one instruction of the run's budget.
        self.charge_property_copy_work()?;
        let result = self.regexp_prototype_exec(regexp.clone(), &subject)?;
        let Value::Object(result_id) = result else {
            self.iterator_helper_set(iterator, RSI_DONE_SLOT, Value::Bool(true))?;
            return self.alloc_iterator_result_object(None);
        };
        let empty_match = matches!(
            self.heap
                .get(result_id.0 as usize)
                .and_then(|object| object.properties.get("0")),
            Some(Value::Str(matched)) if matched.is_empty()
        );
        if empty_match && let (Value::Object(regexp_id), Value::Str(text)) = (&regexp, &subject) {
            let this_index = match self
                .heap
                .get(regexp_id.0 as usize)
                .and_then(|object| object.properties.get("lastIndex"))
            {
                Some(Value::Int(index)) => usize::try_from(*index).unwrap_or(0),
                _ => 0,
            };
            let full_unicode = matches!(
                self.iterator_helper_slot(iterator, RSI_UNICODE_SLOT)?,
                Value::Bool(true)
            );
            let surrogate_pair = full_unicode
                && text
                    .code_unit_at(this_index)
                    .is_some_and(|unit| (0xD800..=0xDBFF).contains(&unit))
                && text
                    .code_unit_at(this_index + 1)
                    .is_some_and(|unit| (0xDC00..=0xDFFF).contains(&unit));
            let next = this_index + if surrogate_pair { 2 } else { 1 };
            self.set_object_property(
                *regexp_id,
                "lastIndex".to_string(),
                Value::Int(i64::try_from(next).unwrap_or(i64::MAX)),
            )?;
        }
        self.alloc_iterator_result_object(Some(result))
    }

    fn iterator_helper_slot(&self, id: ObjectId, slot: &str) -> Result<Value, InterpreterError> {
        self.heap
            .get(id.0 as usize)
            .and_then(|object| object.properties.get(slot).cloned())
            .ok_or_else(|| InterpreterError::InternalError {
                details: format!("iterator helper lost its {slot} slot"),
            })
    }

    fn iterator_helper_set(
        &mut self,
        id: ObjectId,
        slot: &str,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.set_object_property(id, slot.to_string(), value)
    }

    /// GetIteratorDirect(obj): the iterator record of an iterator object, its
    /// `next` read once.
    fn iterator_direct_next(
        &mut self,
        module: &Ir3Module,
        iterator: &Value,
    ) -> Result<Value, InterpreterError> {
        self.get_v(module, iterator, &string_key("next"))
    }

    /// IteratorStepValue: call `next`, check the result is an object, and
    /// read `done` then `value`. `None` once the iterator is done.
    fn iterator_helper_step_value(
        &mut self,
        module: &Ir3Module,
        iterator: &Value,
        next: &Value,
    ) -> Result<Option<Value>, InterpreterError> {
        let result = self.invoke_inline_method_call(
            Some(module),
            next.clone(),
            iterator.clone(),
            Vec::new(),
        )?;
        if !result.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "an iterator result object".to_string(),
                got: result.type_name().to_string(),
            });
        }
        if self.iterator_result_done(module, &result)? {
            return Ok(None);
        }
        self.iterator_result_property(module, &result, "value")
            .map(Some)
    }

    /// IteratorClose(iterator, normal completion): call `return` if there is
    /// one, which must give an object.
    fn iterator_helper_close(
        &mut self,
        module: &Ir3Module,
        iterator: &Value,
    ) -> Result<(), InterpreterError> {
        let return_method = self.get_v(module, iterator, &string_key("return"))?;
        if matches!(return_method, Value::Undefined | Value::Null) {
            return Ok(());
        }
        if !return_method.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "a callable iterator return method".to_string(),
                got: return_method.type_name().to_string(),
            });
        }
        let result = self.invoke_inline_method_call(
            Some(module),
            return_method,
            iterator.clone(),
            Vec::new(),
        )?;
        if !result.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "an object from iterator return()".to_string(),
                got: result.type_name().to_string(),
            });
        }
        Ok(())
    }

    /// IteratorClose(iterator, throw completion): `return` is called and its
    /// own outcome dropped; the original throw continues. Budget,
    /// containment and exit errors are not JS throws and pass through.
    fn iterator_helper_close_after_throw(
        &mut self,
        module: &Ir3Module,
        iterator: &Value,
        error: InterpreterError,
    ) -> InterpreterError {
        let (thrown, label) = match self.thrown_completion_value(error, &Label::Public) {
            Ok(thrown) => thrown,
            Err(fatal) => return fatal,
        };
        match self.get_v(module, iterator, &string_key("return")) {
            Ok(return_method) if return_method.is_callable() => {
                if let Err(error) = self.invoke_inline_method_call(
                    Some(module),
                    return_method,
                    iterator.clone(),
                    Vec::new(),
                ) && let Err(fatal) = self.thrown_completion_value(error, &Label::Public)
                {
                    return fatal;
                }
            }
            Ok(_) => {}
            Err(error) => {
                if let Err(fatal) = self.thrown_completion_value(error, &Label::Public) {
                    return fatal;
                }
            }
        }
        self.throw_guest_value(thrown, label)
            .unwrap_or_else(|error| error)
    }

    /// A TypeError or RangeError about an argument, after closing the
    /// receiver (ES2025 closes the underlying iterator on a failed argument
    /// check).
    fn iterator_helper_argument_error(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
        name: &'static str,
        message: String,
    ) -> InterpreterError {
        let error = self.throw_js_error(name, message);
        self.iterator_helper_close_after_throw(module, receiver, error)
    }

    /// `map`, `filter`, `flatMap`, `take` and `drop`: validate the argument,
    /// read `next`, and make the helper.
    fn iterator_helper_create(
        &mut self,
        module: &Ir3Module,
        kind: &str,
        receiver: Value,
        argument: Value,
    ) -> Result<Value, InterpreterError> {
        let (callback, remaining) = match kind {
            "take" | "drop" => {
                let mut label = None;
                let number =
                    match self.builtin_argument_to_number(Some(module), argument, &mut label) {
                        Ok(number) => number,
                        Err(error) => {
                            return Err(
                                self.iterator_helper_close_after_throw(module, &receiver, error)
                            );
                        }
                    };
                let limit = if number.is_infinite() {
                    number
                } else {
                    number.trunc()
                };
                if number.is_nan() || limit < 0.0 {
                    return Err(self.iterator_helper_argument_error(
                        module,
                        &receiver,
                        "RangeError",
                        format!("{kind} limit must be a non-negative number"),
                    ));
                }
                (Value::Undefined, Value::Float(Float64::new(limit)))
            }
            _ => {
                if !argument.is_callable() {
                    return Err(self.iterator_helper_argument_error(
                        module,
                        &receiver,
                        "TypeError",
                        format!(
                            "{} is not a function",
                            self.uncaught_exception_description(&argument)
                        ),
                    ));
                }
                (argument, Value::Undefined)
            }
        };
        let next = self.iterator_direct_next(module, &receiver)?;
        let prototype = self.ensure_builtin_prototype(ITERATOR_HELPER_PROTOTYPE)?;
        let helper = self.alloc_object_with_prototype(Some(prototype))?;
        for (slot, value) in [
            (KIND_SLOT, Value::str(kind)),
            (ITERATED_SLOT, receiver),
            (NEXT_SLOT, next),
            (CALLBACK_SLOT, callback),
            (COUNTER_SLOT, Value::Int(0)),
            (REMAINING_SLOT, remaining),
            (INNER_SLOT, Value::Undefined),
            (INNER_NEXT_SLOT, Value::Undefined),
            (DONE_SLOT, Value::Bool(false)),
            (RUNNING_SLOT, Value::Bool(false)),
        ] {
            self.iterator_helper_set(helper, slot, value)?;
        }
        self.hide_internal_slots(helper, &ITERATOR_HELPER_SLOT_KEYS)?;
        Ok(Value::Object(helper))
    }

    fn iterator_helper_flag(&self, id: ObjectId, slot: &str) -> bool {
        matches!(
            self.heap
                .get(id.0 as usize)
                .and_then(|object| object.properties.get(slot)),
            Some(Value::Bool(true))
        )
    }

    fn iterator_helper_next(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
    ) -> Result<Value, InterpreterError> {
        let helper = self.iterator_helper_receiver(receiver, false, "next")?;
        if self.iterator_helper_flag(helper, RUNNING_SLOT) {
            return Err(InterpreterError::TypeError {
                expected: "an iterator helper that is not running".to_string(),
                got: "a reentrant next()".to_string(),
            });
        }
        if self.iterator_helper_flag(helper, DONE_SLOT) {
            return self.alloc_iterator_result_object(None);
        }
        self.iterator_helper_set(helper, RUNNING_SLOT, Value::Bool(true))?;
        let step = self.iterator_helper_step(module, helper);
        self.iterator_helper_set(helper, RUNNING_SLOT, Value::Bool(false))?;
        match step {
            Ok(Some(value)) => self.alloc_iterator_result_object(Some(value)),
            Ok(None) => {
                self.iterator_helper_set(helper, DONE_SLOT, Value::Bool(true))?;
                self.alloc_iterator_result_object(None)
            }
            Err(error) => {
                self.iterator_helper_set(helper, DONE_SLOT, Value::Bool(true))?;
                Err(error)
            }
        }
    }

    fn iterator_helper_counter(&self, helper: ObjectId) -> Result<i64, InterpreterError> {
        match self.iterator_helper_slot(helper, COUNTER_SLOT)? {
            Value::Int(counter) => Ok(counter),
            _ => Ok(0),
        }
    }

    fn iterator_helper_bump(
        &mut self,
        helper: ObjectId,
        counter: i64,
    ) -> Result<(), InterpreterError> {
        self.iterator_helper_set(helper, COUNTER_SLOT, Value::Int(counter.saturating_add(1)))
    }

    /// One step of a lazy helper: the value it yields, or `None` when done.
    fn iterator_helper_step(
        &mut self,
        module: &Ir3Module,
        helper: ObjectId,
    ) -> Result<Option<Value>, InterpreterError> {
        let kind = match self.iterator_helper_slot(helper, KIND_SLOT)? {
            Value::Str(kind) => kind.to_string(),
            _ => String::new(),
        };
        let iterated = self.iterator_helper_slot(helper, ITERATED_SLOT)?;
        let next = self.iterator_helper_slot(helper, NEXT_SLOT)?;
        let callback = self.iterator_helper_slot(helper, CALLBACK_SLOT)?;
        match kind.as_str() {
            "map" => {
                let Some(value) = self.iterator_helper_step_value(module, &iterated, &next)? else {
                    return Ok(None);
                };
                let counter = self.iterator_helper_counter(helper)?;
                let mapped = match self.invoke_inline_method_call(
                    Some(module),
                    callback,
                    Value::Undefined,
                    vec![value, Value::Int(counter)],
                ) {
                    Ok(mapped) => mapped,
                    Err(error) => {
                        return Err(
                            self.iterator_helper_close_after_throw(module, &iterated, error)
                        );
                    }
                };
                self.iterator_helper_bump(helper, counter)?;
                Ok(Some(mapped))
            }
            "filter" => loop {
                let Some(value) = self.iterator_helper_step_value(module, &iterated, &next)? else {
                    return Ok(None);
                };
                let counter = self.iterator_helper_counter(helper)?;
                let selected = match self.invoke_inline_method_call(
                    Some(module),
                    callback.clone(),
                    Value::Undefined,
                    vec![value.clone(), Value::Int(counter)],
                ) {
                    Ok(selected) => selected,
                    Err(error) => {
                        return Err(
                            self.iterator_helper_close_after_throw(module, &iterated, error)
                        );
                    }
                };
                self.iterator_helper_bump(helper, counter)?;
                if selected.is_truthy() {
                    return Ok(Some(value));
                }
            },
            "take" => {
                let remaining = self.iterator_helper_remaining(helper)?;
                if remaining == 0.0 {
                    self.iterator_helper_close(module, &iterated)?;
                    return Ok(None);
                }
                if remaining.is_finite() {
                    self.iterator_helper_set(
                        helper,
                        REMAINING_SLOT,
                        Value::Float(Float64::new(remaining - 1.0)),
                    )?;
                }
                self.iterator_helper_step_value(module, &iterated, &next)
            }
            "drop" => {
                let mut remaining = self.iterator_helper_remaining(helper)?;
                while remaining > 0.0 {
                    if remaining.is_finite() {
                        remaining -= 1.0;
                        self.iterator_helper_set(
                            helper,
                            REMAINING_SLOT,
                            Value::Float(Float64::new(remaining)),
                        )?;
                    }
                    if self
                        .iterator_helper_step_value(module, &iterated, &next)?
                        .is_none()
                    {
                        return Ok(None);
                    }
                }
                self.iterator_helper_step_value(module, &iterated, &next)
            }
            "flatMap" => loop {
                let inner = self.iterator_helper_slot(helper, INNER_SLOT)?;
                if !matches!(inner, Value::Undefined) {
                    let inner_next = self.iterator_helper_slot(helper, INNER_NEXT_SLOT)?;
                    match self.iterator_helper_step_value(module, &inner, &inner_next) {
                        Ok(Some(value)) => return Ok(Some(value)),
                        Ok(None) => {
                            self.iterator_helper_set(helper, INNER_SLOT, Value::Undefined)?;
                            self.iterator_helper_set(helper, INNER_NEXT_SLOT, Value::Undefined)?;
                        }
                        Err(error) => {
                            return Err(
                                self.iterator_helper_close_after_throw(module, &iterated, error)
                            );
                        }
                    }
                }
                let Some(value) = self.iterator_helper_step_value(module, &iterated, &next)? else {
                    return Ok(None);
                };
                let counter = self.iterator_helper_counter(helper)?;
                let flattened = self
                    .invoke_inline_method_call(
                        Some(module),
                        callback.clone(),
                        Value::Undefined,
                        vec![value, Value::Int(counter)],
                    )
                    .and_then(|mapped| self.iterator_flattenable(module, mapped, false));
                let (inner, inner_next) = match flattened {
                    Ok(record) => record,
                    Err(error) => {
                        return Err(
                            self.iterator_helper_close_after_throw(module, &iterated, error)
                        );
                    }
                };
                self.iterator_helper_set(helper, INNER_SLOT, inner)?;
                self.iterator_helper_set(helper, INNER_NEXT_SLOT, inner_next)?;
                self.iterator_helper_bump(helper, counter)?;
            },
            other => Err(InterpreterError::InternalError {
                details: format!("unknown iterator helper kind {other}"),
            }),
        }
    }

    fn iterator_helper_remaining(&self, helper: ObjectId) -> Result<f64, InterpreterError> {
        Ok(match self.iterator_helper_slot(helper, REMAINING_SLOT)? {
            Value::Float(remaining) => remaining.inner(),
            Value::Int(remaining) => remaining as f64,
            _ => 0.0,
        })
    }

    /// %IteratorHelperPrototype%.return: close the inner iterator of a
    /// `flatMap` helper, then the underlying one, and finish the helper.
    fn iterator_helper_return(
        &mut self,
        module: &Ir3Module,
        receiver: &Value,
    ) -> Result<Value, InterpreterError> {
        let helper = self.iterator_helper_receiver(receiver, false, "return")?;
        if self.iterator_helper_flag(helper, RUNNING_SLOT) {
            return Err(InterpreterError::TypeError {
                expected: "an iterator helper that is not running".to_string(),
                got: "a reentrant return()".to_string(),
            });
        }
        if self.iterator_helper_flag(helper, DONE_SLOT) {
            return self.alloc_iterator_result_object(None);
        }
        self.iterator_helper_set(helper, DONE_SLOT, Value::Bool(true))?;
        let iterated = self.iterator_helper_slot(helper, ITERATED_SLOT)?;
        let inner = self.iterator_helper_slot(helper, INNER_SLOT)?;
        if !matches!(inner, Value::Undefined) {
            self.iterator_helper_set(helper, INNER_SLOT, Value::Undefined)?;
            if let Err(error) = self.iterator_helper_close(module, &inner) {
                return Err(self.iterator_helper_close_after_throw(module, &iterated, error));
            }
        }
        self.iterator_helper_close(module, &iterated)?;
        self.alloc_iterator_result_object(None)
    }

    /// GetIteratorFlattenable(value): its @@iterator result, or the value
    /// itself when it has none; a primitive is refused, except a string when
    /// `iterate_strings` (Iterator.from). Returns the iterator and its `next`.
    fn iterator_flattenable(
        &mut self,
        module: &Ir3Module,
        value: Value,
        iterate_strings: bool,
    ) -> Result<(Value, Value), InterpreterError> {
        if !value.is_object_like() && !(iterate_strings && matches!(value, Value::Str(_))) {
            return Err(InterpreterError::TypeError {
                expected: "an iterable or iterator object".to_string(),
                got: value.type_name().to_string(),
            });
        }
        // A string iterates with String.prototype's @@iterator, which `get_v`
        // does not reach on a primitive.
        let method = if matches!(value, Value::Str(_)) {
            Value::BuiltinFunction(BuiltinFunction::string_iterator())
        } else {
            self.get_v(
                module,
                &value,
                &RuntimePropertyKey::Symbol(WellKnownSymbol::Iterator.id()),
            )?
        };
        let iterator = if matches!(method, Value::Undefined | Value::Null) {
            value
        } else {
            self.invoke_inline_method_call(Some(module), method, value, Vec::new())?
        };
        if !iterator.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "an iterator object".to_string(),
                got: iterator.type_name().to_string(),
            });
        }
        let next = self.iterator_direct_next(module, &iterator)?;
        Ok((iterator, next))
    }

    /// Whether `value` inherits from %IteratorPrototype% (OrdinaryHasInstance
    /// with %Iterator%).
    fn inherits_iterator_prototype(&self, value: &Value) -> bool {
        match value {
            Value::Iterator(_) | Value::Generator(_) => true,
            Value::Object(id) => self.chain_reaches_canonical_prototype(*id, ITERATOR_PROTOTYPE),
            _ => false,
        }
    }

    /// Iterator.from(O): the iterator itself when it already inherits from
    /// %IteratorPrototype%, else a %WrapForValidIteratorPrototype% wrapper.
    fn iterator_from(
        &mut self,
        module: &Ir3Module,
        object: Value,
    ) -> Result<Value, InterpreterError> {
        let (iterator, next) = self.iterator_flattenable(module, object, true)?;
        if self.inherits_iterator_prototype(&iterator) {
            return Ok(iterator);
        }
        let prototype = self.ensure_builtin_prototype(WRAP_FOR_VALID_ITERATOR_PROTOTYPE)?;
        let wrapper = self.alloc_object_with_prototype(Some(prototype))?;
        for (slot, value) in [
            (KIND_SLOT, Value::str(WRAPPER_KIND)),
            (ITERATED_SLOT, iterator),
            (NEXT_SLOT, next),
        ] {
            self.iterator_helper_set(wrapper, slot, value)?;
        }
        self.hide_internal_slots(wrapper, &[KIND_SLOT, ITERATED_SLOT, NEXT_SLOT])?;
        Ok(Value::Object(wrapper))
    }

    /// `reduce`, `toArray`, `forEach`, `some`, `every` and `find`.
    fn iterator_eager_method(
        &mut self,
        module: &Ir3Module,
        method: &str,
        receiver: Value,
        callback: Value,
        initial: Option<Value>,
    ) -> Result<Value, InterpreterError> {
        if method != "toArray" && !callback.is_callable() {
            return Err(self.iterator_helper_argument_error(
                module,
                &receiver,
                "TypeError",
                format!(
                    "{} is not a function",
                    self.uncaught_exception_description(&callback)
                ),
            ));
        }
        let next = self.iterator_direct_next(module, &receiver)?;
        let mut counter: i64 = 0;
        let mut accumulator = Value::Undefined;
        let mut items = Vec::new();
        if method == "reduce" {
            match initial {
                Some(initial) => accumulator = initial,
                None => {
                    let Some(first) = self.iterator_helper_step_value(module, &receiver, &next)?
                    else {
                        return Err(self.throw_js_error(
                            "TypeError",
                            "Reduce of empty iterator with no initial value".to_string(),
                        ));
                    };
                    accumulator = first;
                    counter = 1;
                }
            }
        }
        while let Some(value) = self.iterator_helper_step_value(module, &receiver, &next)? {
            if method == "toArray" {
                items.push(value);
                continue;
            }
            let arguments = if method == "reduce" {
                vec![accumulator.clone(), value.clone(), Value::Int(counter)]
            } else {
                vec![value.clone(), Value::Int(counter)]
            };
            let result = match self.invoke_inline_method_call(
                Some(module),
                callback.clone(),
                Value::Undefined,
                arguments,
            ) {
                Ok(result) => result,
                Err(error) => {
                    return Err(self.iterator_helper_close_after_throw(module, &receiver, error));
                }
            };
            counter = counter.saturating_add(1);
            match method {
                "reduce" => accumulator = result,
                "some" if result.is_truthy() => {
                    self.iterator_helper_close(module, &receiver)?;
                    return Ok(Value::Bool(true));
                }
                "every" if !result.is_truthy() => {
                    self.iterator_helper_close(module, &receiver)?;
                    return Ok(Value::Bool(false));
                }
                "find" if result.is_truthy() => {
                    self.iterator_helper_close(module, &receiver)?;
                    return Ok(value);
                }
                _ => {}
            }
        }
        Ok(match method {
            "reduce" => accumulator,
            "toArray" => Value::Object(self.alloc_array_from_values(&items)?),
            "some" => Value::Bool(false),
            "every" => Value::Bool(true),
            _ => Value::Undefined,
        })
    }
}
