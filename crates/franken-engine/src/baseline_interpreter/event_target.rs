//! WHATWG DOM `EventTarget`, `Event` and `CustomEvent`, and `AbortController`,
//! `AbortSignal` and `DOMException`, as Node v22 exposes them as globals
//! (bd-9vouw.170). fetch-style APIs, timers/promises and stream helpers take
//! an AbortSignal, and libraries subclass EventTarget at load.
//!
//! State lives in hidden own slots: an EventTarget keeps its listener records
//! (plain objects) in an array, an Event its fields, an AbortSignal its
//! aborted flag, reason, abort algorithms (the listeners added with it as
//! `signal`) and the signals `AbortSignal.any` made from it. The accessor
//! fields are prototype getters (`PROTOTYPE_GETTERS`); the methods are served
//! from the canonical prototypes, so subclasses inherit them.
//!
//! No-claim: one target, no tree, so an event only ever reaches its target
//! (eventPhase AT_TARGET) and `bubbles`/`composed` change nothing; `onabort`
//! is a plain own property, called before the abort listeners; a listener
//! that throws does not stop the other listeners, and the first error is
//! rethrown from dispatchEvent (Node reports it as an uncaught exception
//! instead); `isTrusted` is always false; an `AbortSignal.timeout` timer keeps
//! the event loop running (Node's is unref'd).
//! Source links use non-reused object IDs without keeping the sources alive.
//! Existing dependent links still use strong heap references. Settled links
//! are detached, but full weak-dependent GC semantics are not provided here.

use super::*;

/// The constructors this module builds; `new` is required for each.
pub(super) const EVENT_TARGET_FAMILY: [&str; 6] = [
    "EventTarget",
    "Event",
    "CustomEvent",
    "AbortController",
    "AbortSignal",
    "DOMException",
];

/// (specifier, owner, name) of each method: the specifier names the
/// `EventTargetMethod` builtin, the owner and name give its `name` and
/// `length` (`builtin_function_lengths`).
pub(super) const EVENT_TARGET_METHODS: [(&str, &str, &str); 13] = [
    (
        "EventTarget.addEventListener",
        "EventTarget.prototype",
        "addEventListener",
    ),
    (
        "EventTarget.removeEventListener",
        "EventTarget.prototype",
        "removeEventListener",
    ),
    (
        "EventTarget.dispatchEvent",
        "EventTarget.prototype",
        "dispatchEvent",
    ),
    ("Event.preventDefault", "Event.prototype", "preventDefault"),
    (
        "Event.stopPropagation",
        "Event.prototype",
        "stopPropagation",
    ),
    (
        "Event.stopImmediatePropagation",
        "Event.prototype",
        "stopImmediatePropagation",
    ),
    ("Event.composedPath", "Event.prototype", "composedPath"),
    (
        "AbortController.abort",
        "AbortController.prototype",
        "abort",
    ),
    (
        "AbortSignal.throwIfAborted",
        "AbortSignal.prototype",
        "throwIfAborted",
    ),
    ("AbortSignal.abort", "AbortSignal", "abort"),
    ("AbortSignal.timeout", "AbortSignal", "timeout"),
    ("AbortSignal.any", "AbortSignal", "any"),
    // The timer callback of AbortSignal.timeout, bound to its signal.
    ("AbortSignal.timeoutFire", "AbortSignal", ""),
];

// An engine-private HeapObject brand, never an option or a guest property.
// The ordinary object memory meter and collector own its storage and lifetime.
const PROTECTED_ABORT_LISTENER_BRAND: &str = "ProtectedAbortListener";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventArraySlot {
    Listeners,
    SignalAlgorithms,
    SignalDependents,
}

/// Legacy DOMException codes (WebIDL 3.14.1); any other name has code 0.
const DOM_EXCEPTION_CODES: [(&str, i64); 21] = [
    ("IndexSizeError", 1),
    ("HierarchyRequestError", 3),
    ("WrongDocumentError", 4),
    ("InvalidCharacterError", 5),
    ("NoModificationAllowedError", 7),
    ("NotFoundError", 8),
    ("NotSupportedError", 9),
    ("InvalidStateError", 11),
    ("SyntaxError", 12),
    ("InvalidModificationError", 13),
    ("NamespaceError", 14),
    ("InvalidAccessError", 15),
    ("TypeMismatchError", 17),
    ("SecurityError", 18),
    ("NetworkError", 19),
    ("AbortError", 20),
    ("URLMismatchError", 21),
    ("QuotaExceededError", 22),
    ("TimeoutError", 23),
    ("InvalidNodeTypeError", 24),
    ("DataCloneError", 25),
];

/// Event phase constants (DOM 2.2), on `Event`.
pub(super) const EVENT_PHASE_CONSTANTS: [(&str, i64); 4] = [
    ("NONE", 0),
    ("CAPTURING_PHASE", 1),
    ("AT_TARGET", 2),
    ("BUBBLING_PHASE", 3),
];

impl InterpreterCore {
    /// `new X(...)` for one of [`EVENT_TARGET_FAMILY`]. The object gets the
    /// canonical prototype; a subclass's `new.target` prototype replaces it
    /// afterwards (construct_builtin_with_new_target).
    pub(super) fn construct_event_target_family(
        &mut self,
        module: &Ir3Module,
        name: &str,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        match name {
            "EventTarget" => Ok(Value::Object(self.alloc_event_target("EventTarget")?)),
            "Event" | "CustomEvent" => {
                let Some(event_type) = self.builtin_arg(args, 0)? else {
                    return Err(InterpreterError::TypeError {
                        expected: format!("the \"type\" argument of new {name}()"),
                        got: "no argument".to_string(),
                    });
                };
                let event_type = self.event_family_to_string(module, event_type)?;
                let init = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                let bubbles = self.event_init_flag(module, &init, "bubbles")?;
                let cancelable = self.event_init_flag(module, &init, "cancelable")?;
                let composed = self.event_init_flag(module, &init, "composed")?;
                let detail = if name == "CustomEvent" && init.is_object_like() {
                    match self.get_v(
                        module,
                        &init,
                        &RuntimePropertyKey::String(JsString::from("detail")),
                    )? {
                        Value::Undefined => Value::Null,
                        value => value,
                    }
                } else {
                    Value::Null
                };
                let event =
                    self.alloc_event(name, &event_type, [bubbles, cancelable, composed], detail)?;
                Ok(Value::Object(event))
            }
            "AbortController" => {
                let signal = self.alloc_abort_signal()?;
                let prototype = self.ensure_builtin_prototype("AbortController")?;
                let controller = self.alloc_object_with_prototype(Some(prototype))?;
                self.set_host_slots(controller, HostObjectSlots::AbortController(signal))?;
                Ok(Value::Object(controller))
            }
            "AbortSignal" => Err(InterpreterError::TypeError {
                expected: "AbortSignal from AbortController or its statics".to_string(),
                got: "Illegal constructor".to_string(),
            }),
            "DOMException" => {
                let message = match self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined) {
                    Value::Undefined => String::new(),
                    value => self.event_family_to_string(module, value)?,
                };
                let name = match self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined) {
                    Value::Undefined => "Error".to_string(),
                    value => self.event_family_to_string(module, value)?,
                };
                Ok(Value::Object(self.alloc_dom_exception(&message, &name)?))
            }
            other => Err(InterpreterError::TypeError {
                expected: "an EventTarget family constructor".to_string(),
                got: other.to_string(),
            }),
        }
    }

    /// A method of the family, named by the builtin's specifier.
    pub(super) fn event_target_method(
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
            "EventTarget.addEventListener" => {
                let target = self.event_target_receiver(&receiver, "addEventListener")?;
                let (event_type, callback, options) = (arg(self, 0)?, arg(self, 1)?, arg(self, 2)?);
                self.event_target_add_listener(module, target, event_type, callback, options)?;
                Ok(Value::Undefined)
            }
            "EventTarget.removeEventListener" => {
                let target = self.event_target_receiver(&receiver, "removeEventListener")?;
                let event_type = arg(self, 0)?;
                let event_type = self.event_family_to_string(module, event_type)?;
                let callback = arg(self, 1)?;
                let options = arg(self, 2)?;
                let capture = self.event_listener_capture(module, &options)?;
                if let Some(record) =
                    self.event_target_find_record(target, &event_type, &callback, capture)?
                {
                    self.event_target_remove_record(target, record)?;
                }
                Ok(Value::Undefined)
            }
            "EventTarget.dispatchEvent" => {
                self.event_target_receiver(&receiver, "dispatchEvent")?;
                let event = arg(self, 0)?;
                self.event_target_dispatch(module, &receiver, &event)
            }
            "Event.preventDefault" => {
                let event = self.event_receiver(&receiver, "preventDefault")?;
                self.mutate_event_slots(event, |slots| {
                    if slots.cancelable && !slots.in_passive {
                        slots.default_prevented = true;
                    }
                })?;
                Ok(Value::Undefined)
            }
            "Event.stopPropagation" => {
                let event = self.event_receiver(&receiver, "stopPropagation")?;
                self.mutate_event_slots(event, |slots| {
                    slots.stop = true;
                })?;
                Ok(Value::Undefined)
            }
            "Event.stopImmediatePropagation" => {
                let event = self.event_receiver(&receiver, "stopImmediatePropagation")?;
                self.mutate_event_slots(event, |slots| {
                    slots.stop = true;
                    slots.stop_immediate = true;
                })?;
                Ok(Value::Undefined)
            }
            "Event.composedPath" => {
                let event = self.event_receiver(&receiver, "composedPath")?;
                let path = match self.event_slots_cloned(event)? {
                    slots if slots.dispatching => vec![slots.current_target],
                    _ => Vec::new(),
                };
                Ok(Value::Object(self.alloc_array_from_values(&path)?))
            }
            "AbortController.abort" => {
                let signal = match &receiver {
                    Value::Object(id) => match self
                        .heap
                        .get(id.0 as usize)
                        .and_then(HeapObject::abort_controller_signal)
                    {
                        Some(signal) => signal,
                        None => {
                            return Err(InterpreterError::TypeError {
                                expected: "AbortController receiver for abort".to_string(),
                                got: receiver.type_name().to_string(),
                            });
                        }
                    },
                    other => {
                        return Err(InterpreterError::TypeError {
                            expected: "AbortController receiver for abort".to_string(),
                            got: other.type_name().to_string(),
                        });
                    }
                };
                let reason = arg(self, 0)?;
                self.abort_signal(module, signal, reason)?;
                Ok(Value::Undefined)
            }
            "AbortSignal.throwIfAborted" => {
                let signal = self.abort_signal_receiver(&receiver, "throwIfAborted")?;
                let slots = self.abort_signal_slots_cloned(signal)?;
                if slots.aborted {
                    let label = self.clone_active_execution_context_label()?;
                    return Err(self.throw_guest_value(slots.reason, label)?);
                }
                Ok(Value::Undefined)
            }
            "AbortSignal.abort" => {
                let signal = self.alloc_abort_signal()?;
                let reason = self.abort_reason_or_default(arg(self, 0)?)?;
                self.signal_mark_aborted(signal, reason)?;
                Ok(Value::Object(signal))
            }
            "AbortSignal.timeout" => {
                let delay = match arg(self, 0)? {
                    Value::Int(ms) if ms >= 0 => ms,
                    Value::Float(ms) if ms.inner().is_finite() && ms.inner() >= 0.0 => {
                        ms.inner() as i64
                    }
                    other => {
                        return Err(InterpreterError::TypeError {
                            expected: "a non-negative number of milliseconds".to_string(),
                            got: other.type_name().to_string(),
                        });
                    }
                };
                let signal = self.alloc_abort_signal()?;
                let fire = Value::BuiltinFunction(BuiltinFunction {
                    kind: BuiltinFunctionKind::EventTargetMethod,
                    module_specifier: BuiltinModuleSpecifier::from_nonempty(
                        "AbortSignal.timeoutFire",
                    ),
                    iterator_handle: None,
                    bound_object: Some(signal.0),
                });
                let label = self.clone_active_execution_context_label()?;
                self.timer_schedule_from_values(
                    fire,
                    Some(Value::Int(delay)),
                    Vec::new(),
                    false,
                    false,
                    label,
                )?;
                Ok(Value::Object(signal))
            }
            "AbortSignal.timeoutFire" => {
                let Some(signal) = builtin.bound_object.map(ObjectId) else {
                    return Ok(Value::Undefined);
                };
                if !self.abort_signal_is_aborted(signal) {
                    let reason = self.alloc_dom_exception(
                        "The operation was aborted due to timeout",
                        "TimeoutError",
                    )?;
                    self.signal_abort_with(module, signal, Value::Object(reason))?;
                }
                Ok(Value::Undefined)
            }
            "AbortSignal.any" => self.abort_signal_any(module, args),
            other => Err(InterpreterError::TypeError {
                expected: "an EventTarget family method".to_string(),
                got: other.to_string(),
            }),
        }
    }

    /// The methods served from a family prototype (`canonical_prototype_method`).
    pub(super) fn event_target_prototype_method(name: &str, key: &str) -> Option<Value> {
        let specifier = format!("{name}.{key}");
        EVENT_TARGET_METHODS
            .iter()
            .find(|(entry, owner, method)| {
                *entry == specifier && owner.ends_with(".prototype") && !method.is_empty()
            })
            .map(|(entry, _, _)| {
                Value::BuiltinFunction(BuiltinFunction {
                    kind: BuiltinFunctionKind::EventTargetMethod,
                    module_specifier: BuiltinModuleSpecifier::from_nonempty(entry),
                    iterator_handle: None,
                    bound_object: None,
                })
            })
    }

    /// `AbortSignal.abort`, `timeout` and `any` as values of the constructor.
    pub(super) fn abort_signal_static(key: &str) -> Option<Value> {
        matches!(key, "abort" | "timeout" | "any").then(|| {
            Value::BuiltinFunction(BuiltinFunction {
                kind: BuiltinFunctionKind::EventTargetMethod,
                module_specifier: BuiltinModuleSpecifier::from_nonempty(&format!(
                    "AbortSignal.{key}"
                )),
                iterator_handle: None,
                bound_object: None,
            })
        })
    }

    /// Whether `id` has the internal slots a family accessor needs.
    pub(super) fn has_event_family_brand(&self, id: ObjectId, owner: &str) -> bool {
        let Some(object) = self.heap.get(id.0 as usize) else {
            return false;
        };
        match owner {
            "Event" => object.event_slots().is_some(),
            "CustomEvent" => object
                .event_slots()
                .is_some_and(|slots| slots.detail.is_some()),
            "AbortController" => object.abort_controller_signal().is_some(),
            "AbortSignal" => object.abort_signal_slots().is_some(),
            _ => false,
        }
    }

    /// The value of a family accessor (`event.type`, `signal.aborted`, ...),
    /// or `None` when `owner` is not in the family.
    pub(super) fn event_family_getter(
        &self,
        owner: &str,
        key: &str,
        id: ObjectId,
    ) -> Option<Value> {
        let object = self.heap.get(id.0 as usize)?;
        match owner {
            "Event" => {
                let slots = object.event_slots()?;
                Some(match key {
                    "type" => Value::Str(slots.event_type.clone()),
                    "bubbles" => Value::Bool(slots.bubbles),
                    "cancelable" => Value::Bool(slots.cancelable),
                    "composed" => Value::Bool(slots.composed),
                    "defaultPrevented" => Value::Bool(slots.default_prevented),
                    "eventPhase" => Value::Int(slots.phase),
                    "target" | "srcElement" => slots.target.clone(),
                    "currentTarget" => slots.current_target.clone(),
                    "timeStamp" => slots.time_stamp.clone(),
                    "cancelBubble" => Value::Bool(slots.stop),
                    "returnValue" => Value::Bool(!slots.default_prevented),
                    _ => return None,
                })
            }
            "CustomEvent" if key == "detail" => object.event_slots()?.detail.clone(),
            "AbortController" if key == "signal" => {
                object.abort_controller_signal().map(Value::Object)
            }
            "AbortSignal" => {
                let slots = object.abort_signal_slots()?;
                Some(match key {
                    "aborted" => Value::Bool(slots.aborted),
                    "reason" => slots.reason.clone(),
                    _ => return None,
                })
            }
            _ => None,
        }
    }

    /// An object with the given canonical prototype and an empty listener list.
    fn alloc_event_target(&mut self, prototype: &str) -> Result<ObjectId, InterpreterError> {
        let prototype = self.ensure_builtin_prototype(prototype)?;
        let target = self.alloc_object_with_prototype(Some(prototype))?;
        let listeners = self.alloc_array_from_values(&[])?;
        self.set_host_slots(
            target,
            HostObjectSlots::EventTarget(EventTargetSlots {
                listeners: Some(listeners),
            }),
        )?;
        Ok(target)
    }

    fn alloc_abort_signal(&mut self) -> Result<ObjectId, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("AbortSignal")?;
        let signal = self.alloc_object_with_prototype(Some(prototype))?;
        let listeners = self.alloc_array_from_values(&[])?;
        let algorithms = self.alloc_array_from_values(&[])?;
        let dependents = self.alloc_array_from_values(&[])?;
        self.set_host_slots(
            signal,
            HostObjectSlots::AbortSignal(AbortSignalSlots {
                listeners: Some(listeners),
                aborted: false,
                reason: Value::Undefined,
                algorithms: Some(algorithms),
                dependents: Some(dependents),
                is_composite: false,
                sources: None,
            }),
        )?;
        self.set_object_property(signal, "onabort".to_string(), Value::Null)?;
        self.hide_internal_slots(signal, &["onabort"])?;
        Ok(signal)
    }

    /// A new Event (or CustomEvent) with `flags` = [bubbles, cancelable,
    /// composed].
    fn alloc_event(
        &mut self,
        prototype: &str,
        event_type: &str,
        flags: [bool; 3],
        detail: Value,
    ) -> Result<ObjectId, InterpreterError> {
        let prototype_id = self.ensure_builtin_prototype(prototype)?;
        let event = self.alloc_object_with_prototype(Some(prototype_id))?;
        let time_stamp = self.deterministic_performance_now();
        self.set_host_slots(
            event,
            HostObjectSlots::Event(EventSlots {
                event_type: JsString::from(event_type),
                bubbles: flags[0],
                cancelable: flags[1],
                composed: flags[2],
                default_prevented: false,
                phase: 0,
                target: Value::Null,
                current_target: Value::Null,
                time_stamp,
                stop: false,
                stop_immediate: false,
                in_passive: false,
                dispatching: false,
                detail: (prototype == "CustomEvent").then_some(detail),
            }),
        )?;
        // Node: `isTrusted` is an own property of every event.
        self.set_object_property(event, "isTrusted".to_string(), Value::Bool(false))?;
        Ok(event)
    }

    /// `new DOMException(message, name)`: an Error with the name, the
    /// message and the legacy code.
    fn alloc_dom_exception(
        &mut self,
        message: &str,
        name: &str,
    ) -> Result<ObjectId, InterpreterError> {
        let prototype = self.ensure_builtin_prototype("DOMException")?;
        let error = self.alloc_object_with_prototype(Some(prototype))?;
        self.initialize_error_like_object(error, name, message.to_string())?;
        let code = DOM_EXCEPTION_CODES
            .iter()
            .find(|(entry, _)| *entry == name)
            .map_or(0, |(_, code)| *code);
        self.set_object_property(error, "code".to_string(), Value::Int(code))?;
        self.hide_internal_slots(error, &["code"])?;
        Ok(error)
    }

    fn abort_reason_or_default(&mut self, reason: Value) -> Result<Value, InterpreterError> {
        Ok(match reason {
            Value::Undefined => {
                Value::Object(self.alloc_dom_exception("This operation was aborted", "AbortError")?)
            }
            reason => reason,
        })
    }

    /// AbortController.abort / signal abort (DOM 3.2.4): nothing for an
    /// aborted signal; otherwise abort it with `reason` (an AbortError by
    /// default).
    fn abort_signal(
        &mut self,
        module: &Ir3Module,
        signal: ObjectId,
        reason: Value,
    ) -> Result<(), InterpreterError> {
        if self.abort_signal_is_aborted(signal) {
            return Ok(());
        }
        let reason = self.abort_reason_or_default(reason)?;
        self.signal_abort_with(module, signal, reason)
    }

    /// Set the reason on the signal and on each not-yet-aborted dependent,
    /// then run the abort steps (abort algorithms, the `abort` event) of the
    /// signal and then of those dependents.
    fn signal_abort_with(
        &mut self,
        module: &Ir3Module,
        signal: ObjectId,
        reason: Value,
    ) -> Result<(), InterpreterError> {
        self.signal_mark_aborted(signal, reason.clone())?;
        let mut to_abort = Vec::new();
        for dependent in self.event_array_objects(signal, EventArraySlot::SignalDependents)? {
            if !self.abort_signal_is_aborted(dependent) {
                self.signal_mark_aborted(dependent, reason.clone())?;
                to_abort.push(dependent);
            }
        }
        // Every composed descendant is registered directly on its root by
        // AbortSignal.any. All reasons above are published before guest code
        // runs, so reentrant aborts cannot replace the winning reason.
        // Keep the dependency array rooted through dispatch: callbacks may
        // allocate or collect, and `to_abort` itself only holds native IDs.
        let mut first_error = None;
        let mut outcome = Ok(());
        for target in std::iter::once(signal).chain(to_abort.iter().copied()) {
            let step = self
                .signal_run_abort_steps(module, target)
                .map(|()| (Value::Undefined, Label::Public));
            // Preserve the existing guest-exception/host-refusal distinction.
            // A guest listener may not skip another signal's abort algorithms;
            // an execution-budget or capability refusal still stops dispatch.
            if let Err(error) = self.event_listener_outcome(step, &mut first_error) {
                outcome = Err(error);
                break;
            }
        }
        // The internal array helpers treat a `None` list as empty. Clear
        // without allocating after callbacks, including on a host refusal.
        let cleanup = self.set_event_array_slot(signal, EventArraySlot::SignalDependents, None);
        outcome?;
        cleanup?;
        self.signal_unlink_aborted_sources(&to_abort)?;
        if let Some((thrown, label)) = first_error {
            return Err(self.throw_guest_value(thrown, label)?);
        }
        Ok(())
    }

    /// Drop settled composites from every original source, including sources
    /// that have not aborted. Prune each source once rather than rebuilding a
    /// shared source's entire list for every child in a large fan-out.
    fn signal_unlink_aborted_sources(
        &mut self,
        dependents: &[ObjectId],
    ) -> Result<(), InterpreterError> {
        let mut seen = std::collections::BTreeSet::new();
        let mut sources = Vec::new();
        for dependent in dependents {
            for original in self.signal_source_objects(*dependent)? {
                if seen.insert(original.0) {
                    sources.push(original);
                }
            }
        }
        for original in sources {
            let mut remaining =
                self.event_array_objects(original, EventArraySlot::SignalDependents)?;
            let previous_len = remaining.len();
            remaining.retain(|dependent| !self.abort_signal_is_aborted(*dependent));
            if remaining.len() == previous_len {
                continue;
            }
            let list = if remaining.is_empty() {
                None
            } else {
                let values: Vec<Value> = remaining.into_iter().map(Value::Object).collect();
                Some(self.alloc_array_from_values(&values)?)
            };
            self.set_event_array_slot(original, EventArraySlot::SignalDependents, list)?;
        }
        for dependent in dependents {
            // Keep `is_composite` true: an empty dependent is not a new root.
            self.mutate_abort_signal_slots(*dependent, |slots| {
                slots.is_composite = true;
                slots.sources = None;
            })?;
        }
        Ok(())
    }

    /// The heap never reuses object IDs. Integer IDs therefore act as weak
    /// source handles: skip reclaimed sources instead of retaining them via
    /// Value::Object edges traced by the collector. The source list itself is
    /// still an ordinary accounted, traced array owned by the composite.
    fn signal_source_objects(
        &mut self,
        signal: ObjectId,
    ) -> Result<Vec<ObjectId>, InterpreterError> {
        let Some(list) = self
            .heap
            .get(signal.0 as usize)
            .and_then(HeapObject::abort_signal_slots)
            .and_then(|slots| slots.sources)
        else {
            return Ok(Vec::new());
        };
        Ok(self
            .array_like_values(list)?
            .into_iter()
            .filter_map(|value| match value {
                Value::Int(id) => u32::try_from(id).ok().map(ObjectId),
                _ => None,
            })
            .filter(|source| self.is_abort_signal(*source))
            .collect())
    }

    fn signal_mark_aborted(
        &mut self,
        signal: ObjectId,
        reason: Value,
    ) -> Result<(), InterpreterError> {
        // Admit the potentially allocating reason before publishing aborted.
        self.mutate_abort_signal_slots(signal, |slots| {
            slots.reason = reason;
            slots.aborted = true;
        })
    }

    /// Remove the listeners added with this signal, then fire `abort`.
    fn signal_run_abort_steps(
        &mut self,
        module: &Ir3Module,
        signal: ObjectId,
    ) -> Result<(), InterpreterError> {
        // No guest code runs while these records are removed. Detach the
        // snapshot first so removing N listeners does not repeatedly rebuild
        // this signal's abort list. The target lists retain live records until
        // removal; dispatch/collection only resume after the drain completes.
        let records = self.event_array_objects(signal, EventArraySlot::SignalAlgorithms)?;
        self.set_event_array_slot(signal, EventArraySlot::SignalAlgorithms, None)?;
        for record in records {
            if let Value::Object(target) = self.record_slot(record, "target") {
                self.event_target_remove_record(target, record)?;
            }
        }
        let event = self.alloc_event("Event", "abort", [false, false, false], Value::Null)?;
        self.event_target_dispatch(module, &Value::Object(signal), &Value::Object(event))?;
        Ok(())
    }

    /// `AbortSignal.any(signals)`: abort at once with the first aborted
    /// input's reason, otherwise subscribe directly to the inputs' root
    /// sources (DOM's create-a-dependent-abort-signal algorithm). Registering
    /// only on intermediate composites loses nested cancellation and changes
    /// event order. A set deduplicates roots without sorting their order.
    fn abort_signal_any(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let list = self.iterable_to_array(
            Some(module),
            RegRange {
                start: args.start,
                count: args.count.min(1),
            },
        )?;
        let Value::Object(list) = list else {
            return Err(InterpreterError::TypeError {
                expected: "an iterable of AbortSignals".to_string(),
                got: list.type_name().to_string(),
            });
        };
        let mut sources = Vec::new();
        for value in self.array_like_values(list)? {
            match value {
                Value::Object(id) if self.is_abort_signal(id) => sources.push(id),
                other => {
                    return Err(InterpreterError::TypeError {
                        expected: "AbortSignal elements for AbortSignal.any".to_string(),
                        got: other.type_name().to_string(),
                    });
                }
            }
        }
        let result = self.alloc_abort_signal()?;
        for source in &sources {
            if self.abort_signal_is_aborted(*source) {
                let reason = self.abort_signal_reason(*source);
                self.signal_mark_aborted(result, reason)?;
                return Ok(Value::Object(result));
            }
        }
        let mut roots = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for source in sources {
            let candidates = if self.abort_signal_is_composite(source) {
                self.signal_source_objects(source)?
            } else {
                vec![source]
            };
            for root in candidates {
                if seen.insert(root.0) {
                    roots.push(root);
                }
            }
        }
        let root_values: Vec<Value> = roots
            .iter()
            .map(|root| Value::Int(i64::from(root.0)))
            .collect();
        let root_list = self.alloc_array_from_values(&root_values)?;
        self.mutate_abort_signal_slots(result, |slots| {
            slots.is_composite = true;
            slots.sources = Some(root_list);
        })?;
        for root in roots {
            self.event_array_push(
                root,
                EventArraySlot::SignalDependents,
                Value::Object(result),
            )?;
        }
        Ok(Value::Object(result))
    }

    /// addEventListener(type, callback, options) (DOM 2.7.3).
    fn event_target_add_listener(
        &mut self,
        module: &Ir3Module,
        target: ObjectId,
        event_type: Value,
        callback: Value,
        options: Value,
    ) -> Result<(), InterpreterError> {
        let event_type = self.event_family_to_string(module, event_type)?;
        // A null or undefined listener has no effect (Node warns).
        if matches!(callback, Value::Undefined | Value::Null) {
            return Ok(());
        }
        if !callback.is_object_like() {
            return Err(InterpreterError::TypeError {
                expected: "a function or an object with handleEvent as listener".to_string(),
                got: callback.type_name().to_string(),
            });
        }
        let capture = self.event_listener_capture(module, &options)?;
        let (once, passive, signal) = if options.is_object_like() {
            let once = self.event_init_flag(module, &options, "once")?;
            let passive = self.event_init_flag(module, &options, "passive")?;
            let signal = self.get_v(
                module,
                &options,
                &RuntimePropertyKey::String(JsString::from("signal")),
            )?;
            (once, passive, signal)
        } else {
            (false, false, Value::Undefined)
        };
        let signal = match signal {
            Value::Undefined => None,
            Value::Object(id) if self.is_abort_signal(id) => Some(id),
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "an AbortSignal as the signal option".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        if signal.is_some_and(|signal| self.abort_signal_is_aborted(signal)) {
            return Ok(());
        }
        if self
            .event_target_find_record(target, &event_type, &callback, capture)?
            .is_some()
        {
            return Ok(());
        }
        let record = self.alloc_object_with_properties(&[
            ("type", Value::str(event_type.as_str())),
            ("callback", callback),
            ("capture", Value::Bool(capture)),
            ("once", Value::Bool(once)),
            ("passive", Value::Bool(passive)),
            ("removed", Value::Bool(false)),
            ("target", Value::Object(target)),
        ])?;
        if let Some(signal) = signal {
            // Object IDs are never reused. A weak backlink permits cleanup
            // without retaining an otherwise unreachable cancellation source.
            self.set_record_slot(record, "signal", Value::Int(i64::from(signal.0)))?;
        }
        let previous_list = self.event_array_slot_id(target, EventArraySlot::Listeners);
        self.event_array_push(target, EventArraySlot::Listeners, Value::Object(record))?;
        if let Some(signal) = signal
            && let Err(error) = self.event_array_push(
                signal,
                EventArraySlot::SignalAlgorithms,
                Value::Object(record),
            )
        {
            // A refusal while adding cancellation must not leave an active,
            // uncancellable listener on the target. Restoring the old list
            // needs no replacement array or guest callback.
            self.set_record_slot(record, "removed", Value::Bool(true))?;
            self.set_event_array_slot(target, EventArraySlot::Listeners, previous_list)?;
            return Err(error);
        }
        Ok(())
    }

    /// The first-class events.addAbortListener facade's private registration
    /// primitive. It does not invoke guest code or coerce operands. Publish the
    /// complete once-listener record only after its allocation and private
    /// brand have been admitted by the existing native memory budget.
    pub(super) fn register_protected_abort_listener(
        &mut self,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count != 2 {
            return Err(InterpreterError::TypeError {
                expected: "signal and listener for protected abort registration".to_string(),
                got: format!("{} argument(s)", args.count),
            });
        }
        let signal = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let signal = self.abort_signal_receiver(&signal, "addAbortListener")?;
        let callback = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        if !callback.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "callable abort listener".to_string(),
                got: callback.type_name().to_string(),
            });
        }
        // addEventListener deduplicates by callback and capture. A duplicate
        // protected registration must not upgrade an existing ordinary record
        // or change whether that original registration was one-shot.
        if self
            .event_target_find_record(signal, "abort", &callback, false)?
            .is_some()
        {
            return Ok(Value::Undefined);
        }
        let record = self.alloc_branded_object(
            PROTECTED_ABORT_LISTENER_BRAND,
            &[
                ("type", Value::str("abort")),
                ("callback", callback),
                ("capture", Value::Bool(false)),
                ("once", Value::Bool(true)),
                ("passive", Value::Bool(false)),
                ("removed", Value::Bool(false)),
                ("target", Value::Object(signal)),
            ],
        )?;
        self.event_array_push(signal, EventArraySlot::Listeners, Value::Object(record))?;
        Ok(Value::Undefined)
    }

    /// The `capture` of a listener's options: a boolean, or the option.
    fn event_listener_capture(
        &mut self,
        module: &Ir3Module,
        options: &Value,
    ) -> Result<bool, InterpreterError> {
        if options.is_object_like() {
            return self.event_init_flag(module, options, "capture");
        }
        Ok(options.is_truthy())
    }

    fn event_target_find_record(
        &mut self,
        target: ObjectId,
        event_type: &str,
        callback: &Value,
        capture: bool,
    ) -> Result<Option<ObjectId>, InterpreterError> {
        for record in self.event_array_objects(target, EventArraySlot::Listeners)? {
            let same_type = matches!(
                self.record_slot(record, "type"),
                Value::Str(text) if text.as_str() == Some(event_type)
            );
            if same_type
                && Self::same_value(&self.record_slot(record, "callback"), callback)
                && self.record_slot(record, "capture").is_truthy() == capture
                && !self.record_slot(record, "removed").is_truthy()
            {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Mark the record removed (a dispatch in progress skips it) and drop it
    /// from both owning lists. Explicit removal and once-delivery share this
    /// path: neither may leave a completed callback rooted by a long-lived
    /// signal. Keep its callback intact for an in-flight dispatch snapshot.
    fn event_target_remove_record(
        &mut self,
        target: ObjectId,
        record: ObjectId,
    ) -> Result<(), InterpreterError> {
        self.set_record_slot(record, "removed", Value::Bool(true))?;
        self.event_array_remove(target, EventArraySlot::Listeners, record)?;
        if let Value::Int(signal) = self.record_slot(record, "signal")
            && let Ok(signal) = u32::try_from(signal)
        {
            let signal = ObjectId(signal);
            if self.is_abort_signal(signal) {
                self.event_array_remove(signal, EventArraySlot::SignalAlgorithms, record)?;
            }
        }
        if self.has_record_slot(record, "signal") {
            self.set_record_slot(record, "signal", Value::Undefined)?;
        }
        Ok(())
    }

    /// dispatchEvent(event) (DOM 2.9) on a single target: the matching
    /// listeners, in order, with the target as `this` and currentTarget.
    fn event_target_dispatch(
        &mut self,
        module: &Ir3Module,
        target_value: &Value,
        event_value: &Value,
    ) -> Result<Value, InterpreterError> {
        let Value::Object(target) = target_value else {
            return Err(InterpreterError::TypeError {
                expected: "EventTarget receiver for dispatchEvent".to_string(),
                got: target_value.type_name().to_string(),
            });
        };
        let target = *target;
        let event = match event_value {
            Value::Object(id) if self.is_event(*id) => *id,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "an Event as the argument of dispatchEvent".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        let initial_slots = self.event_slots_cloned(event)?;
        if initial_slots.dispatching {
            let error = self.alloc_dom_exception(
                "The event is already being dispatched",
                "InvalidStateError",
            )?;
            let label = self.clone_active_execution_context_label()?;
            return Err(self.throw_guest_value(Value::Object(error), label)?);
        }
        let event_type = initial_slots.event_type.to_string();
        self.mutate_event_slots(event, |slots| {
            slots.target = target_value.clone();
            slots.current_target = target_value.clone();
            slots.phase = 2;
            slots.dispatching = true;
        })?;
        let mut first_error: Option<(Value, Label)> = None;
        if event_type == "abort" && self.is_abort_signal(target) {
            let handler = self.record_slot(target, "onabort");
            if handler.is_callable() {
                let outcome = self.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    handler,
                    target_value.clone(),
                    vec![event_value.clone()],
                    None,
                );
                self.event_listener_outcome(outcome, &mut first_error)?;
            }
        }
        let records: Vec<ObjectId> = self
            .event_array_objects(target, EventArraySlot::Listeners)?
            .into_iter()
            .filter(|record| {
                matches!(
                    self.record_slot(*record, "type"),
                    Value::Str(text) if text.as_str() == Some(event_type.as_str())
                )
            })
            .collect();
        for record in records {
            if self.record_slot(record, "removed").is_truthy() {
                continue;
            }
            let protected_abort_listener = event_type == "abort"
                && self
                    .heap
                    .get(record.0 as usize)
                    .is_some_and(|object| object.brand() == Some(PROTECTED_ABORT_LISTENER_BRAND));
            if self
                .heap
                .get(event.0 as usize)
                .and_then(HeapObject::event_slots)
                .is_some_and(|slots| slots.stop_immediate)
                && !protected_abort_listener
            {
                // Ordinary listeners stay suppressed. Protected abort
                // registrations later in the same snapshot still run at their
                // original positions with this exact signal and Event.
                continue;
            }
            if self.record_slot(record, "once").is_truthy() {
                self.event_target_remove_record(target, record)?;
            }
            let passive = self.record_slot(record, "passive").is_truthy();
            self.mutate_event_slots(event, |slots| {
                slots.in_passive = passive;
            })?;
            let callback = self.record_slot(record, "callback");
            let outcome = if callback.is_callable() {
                self.invoke_inline_method_call_with_argument_label(
                    Some(module),
                    callback,
                    target_value.clone(),
                    vec![event_value.clone()],
                    None,
                )
            } else {
                let handle_event = self.get_v(
                    module,
                    &callback,
                    &RuntimePropertyKey::String(JsString::from("handleEvent")),
                );
                match handle_event {
                    Ok(handle_event) if handle_event.is_callable() => self
                        .invoke_inline_method_call_with_argument_label(
                            Some(module),
                            handle_event,
                            callback,
                            vec![event_value.clone()],
                            None,
                        ),
                    Ok(_) => Ok((Value::Undefined, Label::Public)),
                    Err(error) => Err(error),
                }
            };
            self.mutate_event_slots(event, |slots| {
                slots.in_passive = false;
            })?;
            self.event_listener_outcome(outcome, &mut first_error)?;
        }
        // Node leaves target and currentTarget set after the dispatch.
        self.mutate_event_slots(event, |slots| {
            slots.phase = 0;
            slots.dispatching = false;
        })?;
        if let Some((thrown, label)) = first_error {
            return Err(self.throw_guest_value(thrown, label)?);
        }
        let canceled = self
            .heap
            .get(event.0 as usize)
            .and_then(HeapObject::event_slots)
            .is_some_and(|slots| slots.cancelable && slots.default_prevented);
        Ok(Value::Bool(!canceled))
    }

    /// Keep the first guest error a listener threw and go on with the
    /// others; a host refusal still propagates.
    fn event_listener_outcome(
        &mut self,
        outcome: Result<(Value, Label), InterpreterError>,
        first_error: &mut Option<(Value, Label)>,
    ) -> Result<(), InterpreterError> {
        let Err(error) = outcome else {
            return Ok(());
        };
        let pending = self
            .take_pending_hostcall_result_label()
            .unwrap_or(Label::Public);
        let label = self.clone_active_execution_context_label()?.join(&pending);
        let thrown = self.thrown_completion_value(error, &label)?;
        if first_error.is_none() {
            *first_error = Some(thrown);
        }
        Ok(())
    }

    fn is_event_target(&self, id: ObjectId) -> bool {
        self.heap
            .get(id.0 as usize)
            .is_some_and(HeapObject::is_event_target)
    }

    fn is_event(&self, id: ObjectId) -> bool {
        self.heap
            .get(id.0 as usize)
            .is_some_and(|object| object.event_slots().is_some())
    }

    fn is_abort_signal(&self, id: ObjectId) -> bool {
        self.heap
            .get(id.0 as usize)
            .is_some_and(|object| object.abort_signal_slots().is_some())
    }

    fn abort_signal_is_aborted(&self, id: ObjectId) -> bool {
        self.heap
            .get(id.0 as usize)
            .and_then(HeapObject::abort_signal_slots)
            .is_some_and(|slots| slots.aborted)
    }

    fn abort_signal_is_composite(&self, id: ObjectId) -> bool {
        self.heap
            .get(id.0 as usize)
            .and_then(HeapObject::abort_signal_slots)
            .is_some_and(|slots| slots.is_composite)
    }

    fn abort_signal_reason(&self, id: ObjectId) -> Value {
        self.heap
            .get(id.0 as usize)
            .and_then(HeapObject::abort_signal_slots)
            .map(|slots| slots.reason.clone())
            .unwrap_or(Value::Undefined)
    }

    fn event_slots_cloned(&self, id: ObjectId) -> Result<EventSlots, InterpreterError> {
        self.heap
            .get(id.0 as usize)
            .and_then(HeapObject::event_slots)
            .cloned()
            .ok_or_else(|| InterpreterError::InternalError {
                details: "Event lost its internal slots".to_string(),
            })
    }

    fn abort_signal_slots_cloned(
        &self,
        id: ObjectId,
    ) -> Result<AbortSignalSlots, InterpreterError> {
        self.heap
            .get(id.0 as usize)
            .and_then(HeapObject::abort_signal_slots)
            .cloned()
            .ok_or_else(|| InterpreterError::InternalError {
                details: "AbortSignal lost its internal slots".to_string(),
            })
    }

    fn mutate_event_slots<R>(
        &mut self,
        id: ObjectId,
        mutate: impl FnOnce(&mut EventSlots) -> R,
    ) -> Result<R, InterpreterError> {
        self.mutate_host_slots(id, |slots| match slots {
            HostObjectSlots::Event(event) => Ok(mutate(event)),
            _ => Err(InterpreterError::InternalError {
                details: "Event lost its internal slots".to_string(),
            }),
        })?
    }

    fn mutate_abort_signal_slots<R>(
        &mut self,
        id: ObjectId,
        mutate: impl FnOnce(&mut AbortSignalSlots) -> R,
    ) -> Result<R, InterpreterError> {
        self.mutate_host_slots(id, |slots| match slots {
            HostObjectSlots::AbortSignal(signal) => Ok(mutate(signal)),
            _ => Err(InterpreterError::InternalError {
                details: "AbortSignal lost its internal slots".to_string(),
            }),
        })?
    }

    fn event_target_receiver(
        &self,
        receiver: &Value,
        method: &str,
    ) -> Result<ObjectId, InterpreterError> {
        match receiver {
            Value::Object(id) if self.is_event_target(*id) => Ok(*id),
            other => Err(InterpreterError::TypeError {
                expected: format!("EventTarget receiver for {method}"),
                got: other.type_name().to_string(),
            }),
        }
    }

    fn event_receiver(&self, receiver: &Value, method: &str) -> Result<ObjectId, InterpreterError> {
        match receiver {
            Value::Object(id) if self.is_event(*id) => Ok(*id),
            other => Err(InterpreterError::TypeError {
                expected: format!("Event receiver for {method}"),
                got: other.type_name().to_string(),
            }),
        }
    }

    fn abort_signal_receiver(
        &self,
        receiver: &Value,
        method: &str,
    ) -> Result<ObjectId, InterpreterError> {
        match receiver {
            Value::Object(id) if self.is_abort_signal(*id) => Ok(*id),
            other => Err(InterpreterError::TypeError {
                expected: format!("AbortSignal receiver for {method}"),
                got: other.type_name().to_string(),
            }),
        }
    }

    /// ToBoolean of `init[key]`, false for a missing init.
    fn event_init_flag(
        &mut self,
        module: &Ir3Module,
        init: &Value,
        key: &str,
    ) -> Result<bool, InterpreterError> {
        if !init.is_object_like() {
            return Ok(false);
        }
        Ok(self
            .get_v(
                module,
                init,
                &RuntimePropertyKey::String(JsString::from(key)),
            )?
            .is_truthy())
    }

    fn event_family_to_string(
        &mut self,
        module: &Ir3Module,
        value: Value,
    ) -> Result<String, InterpreterError> {
        let primitive = if value.is_object_like() {
            self.coerce_runtime_primitive(Some(module), value, true)?
        } else {
            value
        };
        if matches!(primitive, Value::Symbol(_)) {
            return Err(Self::symbol_to_string_error());
        }
        Ok(self.value_to_string(&primitive))
    }

    fn has_record_slot(&self, id: ObjectId, slot: &str) -> bool {
        self.heap
            .get(id.0 as usize)
            .is_some_and(|object| object.properties.get(slot).is_some())
    }

    fn record_slot(&self, id: ObjectId, slot: &str) -> Value {
        self.heap
            .get(id.0 as usize)
            .and_then(|object| object.properties.get(slot).cloned())
            .unwrap_or(Value::Undefined)
    }

    fn set_record_slot(
        &mut self,
        id: ObjectId,
        slot: &str,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.set_object_property(id, slot.to_string(), value)
    }

    fn event_array_slot_id(&self, id: ObjectId, slot: EventArraySlot) -> Option<ObjectId> {
        let object = self.heap.get(id.0 as usize)?;
        match slot {
            EventArraySlot::Listeners => object.event_target_listeners(),
            EventArraySlot::SignalAlgorithms => object.abort_signal_slots()?.algorithms,
            EventArraySlot::SignalDependents => object.abort_signal_slots()?.dependents,
        }
    }

    fn set_event_array_slot(
        &mut self,
        id: ObjectId,
        slot: EventArraySlot,
        list: Option<ObjectId>,
    ) -> Result<(), InterpreterError> {
        self.mutate_host_slots(id, |host_slots| match (slot, host_slots) {
            (EventArraySlot::Listeners, HostObjectSlots::EventTarget(target)) => {
                target.listeners = list;
                Ok(())
            }
            (EventArraySlot::Listeners, HostObjectSlots::AbortSignal(signal)) => {
                signal.listeners = list;
                Ok(())
            }
            (EventArraySlot::SignalAlgorithms, HostObjectSlots::AbortSignal(signal)) => {
                signal.algorithms = list;
                Ok(())
            }
            (EventArraySlot::SignalDependents, HostObjectSlots::AbortSignal(signal)) => {
                signal.dependents = list;
                Ok(())
            }
            _ => Err(InterpreterError::InternalError {
                details: "EventTarget/AbortSignal lost its internal array slot".to_string(),
            }),
        })?
    }

    /// The objects of the array in `slot` of `id`.
    fn event_array_objects(
        &mut self,
        id: ObjectId,
        slot: EventArraySlot,
    ) -> Result<Vec<ObjectId>, InterpreterError> {
        let Some(list) = self.event_array_slot_id(id, slot) else {
            return Ok(Vec::new());
        };
        Ok(self
            .array_like_values(list)?
            .into_iter()
            .filter_map(|value| match value {
                Value::Object(entry) => Some(entry),
                _ => None,
            })
            .collect())
    }

    /// Append to the array in `slot` of `id` (a fresh array, so a
    /// dispatch iterating the old one is unaffected).
    fn event_array_push(
        &mut self,
        id: ObjectId,
        slot: EventArraySlot,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let mut values: Vec<Value> = self
            .event_array_objects(id, slot)?
            .into_iter()
            .map(Value::Object)
            .collect();
        values.push(value);
        let list = self.alloc_array_from_values(&values)?;
        self.set_event_array_slot(id, slot, Some(list))
    }

    /// Remove an internal record without touching any other registration.
    /// A missing entry is a no-op; empty lists need no heap allocation. Nonempty
    /// replacements preserve the old array for dispatch snapshots.
    fn event_array_remove(
        &mut self,
        id: ObjectId,
        slot: EventArraySlot,
        record: ObjectId,
    ) -> Result<(), InterpreterError> {
        let mut entries = self.event_array_objects(id, slot)?;
        let before = entries.len();
        entries.retain(|entry| *entry != record);
        if entries.len() == before {
            return Ok(());
        }
        let replacement = if entries.is_empty() {
            None
        } else {
            let values: Vec<Value> = entries.into_iter().map(Value::Object).collect();
            Some(self.alloc_array_from_values(&values)?)
        };
        self.set_event_array_slot(id, slot, replacement)
    }
}

#[cfg(test)]
mod abort_graph_tests {
    use super::*;
    use crate::ir_contract::Ir0Module;
    use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};

    fn runtime() -> (InterpreterCore, Ir3Module) {
        let tree = crate::parser_api_stability::parse_script("0;").expect("empty program");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "abort-graph-unit.js"),
            &LoweringContext::new("abort-graph-unit", "abort-graph-unit", "abort-graph-unit"),
        )
        .expect("empty program lowers")
        .ir3;
        // The grants a program's execution has: without HeapAllocate every
        // allocation helper refuses, and these tests never reached their
        // checks.
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let core = InterpreterCore::new(config, "abort-graph-unit");
        (core, module)
    }

    fn any(core: &mut InterpreterCore, module: &Ir3Module, sources: &[ObjectId]) -> ObjectId {
        let values: Vec<Value> = sources.iter().copied().map(Value::Object).collect();
        let list = core.alloc_array_from_values(&values).expect("source array");
        core.seed_register(0, Value::Object(list))
            .expect("source register");
        match core
            .abort_signal_any(module, RegRange { start: 0, count: 1 })
            .expect("composite signal")
        {
            Value::Object(signal) => signal,
            other => panic!("expected signal object, got {other:?}"),
        }
    }

    #[test]
    fn native_source_sets_flatten_and_deduplicate_in_input_order() {
        let (mut core, module) = runtime();
        let a = core.alloc_abort_signal().expect("a");
        let b = core.alloc_abort_signal().expect("b");
        let first = any(&mut core, &module, &[b, a, b]);
        let second = any(&mut core, &module, &[first, a, first]);
        assert_eq!(core.signal_source_objects(second).unwrap(), vec![b, a]);
        let Some(source_list) = core.abort_signal_slots_cloned(second).unwrap().sources else {
            panic!("a dependent keeps its ordered source set");
        };
        assert_eq!(
            core.array_like_values(source_list).unwrap(),
            vec![Value::Int(i64::from(b.0)), Value::Int(i64::from(a.0))],
            "source links must not be strong object references"
        );
        for source in [a, b] {
            assert_eq!(
                core.event_array_objects(source, EventArraySlot::SignalDependents)
                    .unwrap(),
                vec![first, second]
            );
        }
        assert!(
            core.event_array_objects(first, EventArraySlot::SignalDependents)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn native_settlement_unlinks_all_original_sources_without_removing_live_peers() {
        let (mut core, module) = runtime();
        let a = core.alloc_abort_signal().expect("a");
        let b = core.alloc_abort_signal().expect("b");
        let first = any(&mut core, &module, &[a, b]);
        let second = any(&mut core, &module, &[first]);
        let live = any(&mut core, &module, &[b]);
        core.signal_abort_with(&module, a, Value::str("cancel"))
            .expect("abort a");
        assert!(
            core.event_array_objects(a, EventArraySlot::SignalDependents)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            core.event_array_objects(b, EventArraySlot::SignalDependents)
                .unwrap(),
            vec![live]
        );
        for signal in [first, second] {
            assert!(core.abort_signal_is_composite(signal));
            assert!(core.signal_source_objects(signal).unwrap().is_empty());
            assert_eq!(core.abort_signal_reason(signal), Value::str("cancel"));
        }
        core.signal_abort_with(&module, b, Value::str("later"))
            .expect("abort b");
        assert_eq!(core.abort_signal_reason(live), Value::str("later"));
        assert_eq!(core.abort_signal_reason(second), Value::str("cancel"));
        assert!(
            core.event_array_objects(b, EventArraySlot::SignalDependents)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn native_empty_composite_does_not_become_an_original_source() {
        let (mut core, module) = runtime();
        let empty = any(&mut core, &module, &[]);
        let nested = any(&mut core, &module, &[empty, empty]);
        assert!(
            core.event_array_objects(empty, EventArraySlot::SignalDependents)
                .unwrap()
                .is_empty()
        );
        assert!(core.signal_source_objects(nested).unwrap().is_empty());
        assert!(!core.abort_signal_is_aborted(nested));
    }

    #[test]
    fn completed_requests_do_not_accumulate_on_a_long_lived_shared_source() {
        let (mut core, module) = runtime();
        let shared = core.alloc_abort_signal().expect("shared source");
        for request_id in 0..32 {
            let request = core.alloc_abort_signal().expect("request source");
            let combined = any(&mut core, &module, &[request, shared]);
            let nested = any(&mut core, &module, &[combined]);
            core.signal_abort_with(&module, request, Value::Int(request_id))
                .expect("finish request");
            assert!(
                core.event_array_objects(shared, EventArraySlot::SignalDependents)
                    .unwrap()
                    .is_empty(),
                "the shared source must release request {request_id}"
            );
            assert_eq!(core.abort_signal_reason(nested), Value::Int(request_id));
        }
        let last = any(&mut core, &module, &[shared]);
        core.signal_abort_with(&module, shared, Value::str("shutdown"))
            .expect("new subscriptions still work after pruning");
        assert_eq!(core.abort_signal_reason(last), Value::str("shutdown"));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn weak_source_handles_ignore_absent_and_unbranded_objects() {
        let (mut core, module) = runtime();
        let original = core.alloc_abort_signal().expect("original source");
        let dependent = any(&mut core, &module, &[original]);
        let ordinary = core
            .alloc_object_with_prototype(None)
            .expect("ordinary object");
        let list = core
            .alloc_array_from_values(&[
                Value::Int(-1),
                Value::Int(i64::from(u32::MAX)),
                Value::Int(i64::from(ordinary.0)),
                Value::Int(i64::from(original.0)),
            ])
            .expect("weak handles");
        core.mutate_abort_signal_slots(dependent, |slots| {
            slots.is_composite = true;
            slots.sources = Some(list);
        })
        .expect("source list");
        assert_eq!(
            core.signal_source_objects(dependent).unwrap(),
            vec![original]
        );
        let nested = any(&mut core, &module, &[dependent]);
        assert_eq!(core.signal_source_objects(nested).unwrap(), vec![original]);
    }

    fn listen(
        core: &mut InterpreterCore,
        module: &Ir3Module,
        target: ObjectId,
        signal: ObjectId,
        callback: Value,
        flags: [bool; 2],
    ) -> ObjectId {
        let options = core
            .alloc_object_with_properties(&[
                ("signal", Value::Object(signal)),
                ("capture", Value::Bool(flags[0])),
                ("once", Value::Bool(flags[1])),
            ])
            .expect("listener options");
        core.event_target_add_listener(
            module,
            target,
            Value::str("work"),
            callback.clone(),
            Value::Object(options),
        )
        .expect("signal-bound listener");
        core.event_target_find_record(target, "work", &callback, flags[0])
            .expect("listener lookup")
            .expect("registered listener")
    }

    fn listener_object(core: &mut InterpreterCore) -> Value {
        // EventListener objects are valid even without a handleEvent method.
        // Public-path fixtures below exercise actual guest callback invocation.
        Value::Object(
            core.alloc_object_with_prototype(None)
                .expect("listener object"),
        )
    }

    #[test]
    fn explicit_listener_removal_unlinks_only_its_abort_algorithm() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let callback = listener_object(&mut core);
        let other_callback = listener_object(&mut core);
        let record = listen(&mut core, &module, target, signal, callback, [false, false]);
        let peer = listen(
            &mut core,
            &module,
            target,
            signal,
            other_callback,
            [false, false],
        );
        assert_eq!(
            core.record_slot(record, "signal"),
            Value::Int(i64::from(signal.0))
        );
        core.event_target_remove_record(target, record).unwrap();
        assert_eq!(
            core.event_array_objects(signal, EventArraySlot::SignalAlgorithms)
                .unwrap(),
            vec![peer]
        );
        assert_eq!(
            core.event_array_objects(target, EventArraySlot::Listeners)
                .unwrap(),
            vec![peer]
        );
        assert_eq!(core.record_slot(record, "signal"), Value::Undefined);
        let list = core.event_array_slot_id(signal, EventArraySlot::SignalAlgorithms);
        core.event_target_remove_record(target, record).unwrap();
        assert_eq!(
            core.event_array_slot_id(signal, EventArraySlot::SignalAlgorithms),
            list,
            "idempotent unlink"
        );
        core.abort_signal(&module, signal, Value::Undefined)
            .unwrap();
        assert!(core.record_slot(peer, "removed").is_truthy());
        assert!(
            core.event_array_objects(target, EventArraySlot::Listeners)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn once_delivery_releases_abort_algorithm_but_retains_its_callback_snapshot() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let callback = listener_object(&mut core);
        let record = listen(
            &mut core,
            &module,
            target,
            signal,
            callback.clone(),
            [false, true],
        );
        let event = core
            .alloc_event("Event", "work", [false; 3], Value::Null)
            .unwrap();
        core.event_target_dispatch(&module, &Value::Object(target), &Value::Object(event))
            .unwrap();
        assert!(
            core.event_array_objects(signal, EventArraySlot::SignalAlgorithms)
                .unwrap()
                .is_empty()
        );
        assert!(
            core.event_array_objects(target, EventArraySlot::Listeners)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            core.record_slot(record, "callback"),
            callback,
            "snapshot must retain its callback"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn completed_listeners_do_not_accumulate_on_a_long_lived_signal() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let callback = listener_object(&mut core);
        for attempt in 0..128 {
            let record = listen(
                &mut core,
                &module,
                target,
                signal,
                callback.clone(),
                [false, false],
            );
            core.event_target_remove_record(target, record).unwrap();
            assert!(
                core.event_array_objects(signal, EventArraySlot::SignalAlgorithms)
                    .unwrap()
                    .is_empty(),
                "completed registration {attempt} was retained"
            );
        }
        assert!(!core.abort_signal_is_aborted(signal));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn listener_reregistration_belongs_to_the_new_signal_only() {
        let (mut core, module) = runtime();
        let first = core.alloc_abort_signal().unwrap();
        let second = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let callback = listener_object(&mut core);
        let old = listen(
            &mut core,
            &module,
            target,
            first,
            callback.clone(),
            [false, false],
        );
        core.event_target_remove_record(target, old).unwrap();
        let new = listen(&mut core, &module, target, second, callback, [false, false]);
        core.abort_signal(&module, first, Value::Undefined).unwrap();
        assert_eq!(
            core.event_array_objects(target, EventArraySlot::Listeners)
                .unwrap(),
            vec![new]
        );
        assert_eq!(
            core.event_array_objects(second, EventArraySlot::SignalAlgorithms)
                .unwrap(),
            vec![new]
        );
        core.abort_signal(&module, second, Value::Undefined)
            .unwrap();
        assert!(
            core.event_array_objects(target, EventArraySlot::Listeners)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn capture_registrations_and_duplicate_requests_keep_distinct_ownership() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let callback = listener_object(&mut core);
        let bubbling = listen(
            &mut core,
            &module,
            target,
            signal,
            callback.clone(),
            [false, false],
        );
        let capture = listen(
            &mut core,
            &module,
            target,
            signal,
            callback.clone(),
            [true, false],
        );
        assert_eq!(
            listen(&mut core, &module, target, signal, callback, [false, false]),
            bubbling
        );
        assert_eq!(
            core.event_array_objects(signal, EventArraySlot::SignalAlgorithms)
                .unwrap(),
            vec![bubbling, capture]
        );
        core.event_target_remove_record(target, bubbling).unwrap();
        assert_eq!(
            core.event_array_objects(signal, EventArraySlot::SignalAlgorithms)
                .unwrap(),
            vec![capture]
        );
        core.abort_signal(&module, signal, Value::Undefined)
            .unwrap();
        assert!(
            core.event_array_objects(target, EventArraySlot::Listeners)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn abort_drain_removes_every_listener_without_rebuilding_the_signal_list() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let mut targets = Vec::new();
        for _ in 0..24 {
            let target = core.alloc_event_target("EventTarget").unwrap();
            let callback = listener_object(&mut core);
            listen(&mut core, &module, target, signal, callback, [false, false]);
            targets.push(target);
        }
        core.abort_signal(&module, signal, Value::Undefined)
            .unwrap();
        assert_eq!(
            core.event_array_slot_id(signal, EventArraySlot::SignalAlgorithms),
            None
        );
        for target in targets {
            assert!(
                core.event_array_objects(target, EventArraySlot::Listeners)
                    .unwrap()
                    .is_empty()
            );
        }
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn cancellation_registration_refusal_restores_the_original_target_list() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let existing = listener_object(&mut core);
        let peer = listen(&mut core, &module, target, signal, existing, [false, false]);
        let callback = listener_object(&mut core);
        let options = core
            .alloc_object_with_properties(&[("signal", Value::Object(signal))])
            .unwrap();
        let target_list = core.event_array_slot_id(target, EventArraySlot::Listeners);
        let signal_list = core.event_array_slot_id(signal, EventArraySlot::SignalAlgorithms);
        // Permit the listener record and replacement target list, but refuse
        // the third allocation: its cancellation registration's new array.
        let before = core.heap.live_len();
        core.config.max_heap_objects = u32::try_from(before + 2).unwrap();
        core.event_target_add_listener(
            &module,
            target,
            Value::str("work"),
            callback,
            Value::Object(options),
        )
        .expect_err("cancellation registration must fail at the object limit");
        assert_eq!(
            core.heap.live_len(),
            before + 2,
            "reach the cancellation allocation"
        );
        assert_eq!(
            core.event_array_slot_id(target, EventArraySlot::Listeners),
            target_list
        );
        assert_eq!(
            core.event_array_slot_id(signal, EventArraySlot::SignalAlgorithms),
            signal_list
        );
        assert_eq!(
            core.event_array_objects(target, EventArraySlot::Listeners)
                .unwrap(),
            vec![peer]
        );
        assert!(!core.record_slot(peer, "removed").is_truthy());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn protected_abort_records_resist_stop_without_exposing_a_forgeable_option() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let ordinary = listener_object(&mut core);
        let options = core
            .alloc_object_with_properties(&[
                ("once", Value::Bool(true)),
                ("resistStopPropagation", Value::Bool(true)),
                ("__type", Value::str(PROTECTED_ABORT_LISTENER_BRAND)),
            ])
            .unwrap();
        core.event_target_add_listener(
            &module,
            signal,
            Value::str("abort"),
            ordinary,
            Value::Object(options),
        )
        .unwrap();
        let ordinary = core
            .event_array_objects(signal, EventArraySlot::Listeners)
            .unwrap()[0];
        // Even a property on the internal record does not confer the brand.
        core.set_record_slot(
            ordinary,
            "__type",
            Value::str(PROTECTED_ABORT_LISTENER_BRAND),
        )
        .unwrap();
        core.seed_register(0, Value::Object(signal)).unwrap();
        core.seed_register(
            1,
            Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray)),
        )
        .unwrap();
        core.register_protected_abort_listener(RegRange { start: 0, count: 2 })
            .unwrap();
        let protected = core
            .event_array_objects(signal, EventArraySlot::Listeners)
            .unwrap()[1];
        assert_eq!(
            core.heap[protected.0 as usize].brand(),
            Some(PROTECTED_ABORT_LISTENER_BRAND)
        );
        let event = core
            .alloc_event("Event", "abort", [false; 3], Value::Null)
            .unwrap();
        core.mutate_event_slots(event, |slots| {
            slots.stop_immediate = true;
        })
        .unwrap();
        core.event_target_dispatch(&module, &Value::Object(signal), &Value::Object(event))
            .unwrap();
        assert!(!core.record_slot(ordinary, "removed").is_truthy());
        assert!(core.record_slot(protected, "removed").is_truthy());
        assert_eq!(
            core.event_array_objects(signal, EventArraySlot::Listeners)
                .unwrap(),
            vec![ordinary]
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn protected_abort_registration_preserves_existing_callback_options() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let callback =
            Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray));
        core.event_target_add_listener(
            &module,
            signal,
            Value::str("abort"),
            callback.clone(),
            Value::Undefined,
        )
        .unwrap();
        let original = core
            .event_array_objects(signal, EventArraySlot::Listeners)
            .unwrap();
        core.seed_register(0, Value::Object(signal)).unwrap();
        core.seed_register(1, callback).unwrap();
        let before = core.estimated_memory_bytes();
        core.register_protected_abort_listener(RegRange { start: 0, count: 2 })
            .unwrap();
        assert_eq!(
            core.event_array_objects(signal, EventArraySlot::Listeners)
                .unwrap(),
            original
        );
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.heap[original[0].0 as usize].brand(), None);
        assert!(!core.record_slot(original[0], "once").is_truthy());
    }

    #[test]
    fn protected_abort_registration_refusal_never_attaches_a_partial_record() {
        let (mut core, _) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        core.seed_register(0, Value::Object(signal)).unwrap();
        core.seed_register(
            1,
            Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray)),
        )
        .unwrap();
        let original = core.event_array_slot_id(signal, EventArraySlot::Listeners);
        let before = core.heap.live_len();
        // Admit the fully branded record, refuse the replacement listener list.
        core.config.max_heap_objects = u32::try_from(before + 1).unwrap();
        core.register_protected_abort_listener(RegRange { start: 0, count: 2 })
            .expect_err("listener-list allocation is refused");
        assert_eq!(core.heap.live_len(), before + 1);
        assert_eq!(
            core.event_array_slot_id(signal, EventArraySlot::Listeners),
            original
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn protected_abort_intrinsic_requires_builtin_authority_before_registration() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        core.seed_register(0, Value::Object(signal)).unwrap();
        core.seed_register(
            1,
            Value::BuiltinFunction(BuiltinFunction::new_kind(BuiltinFunctionKind::ArrayIsArray)),
        )
        .unwrap();
        core.config
            .granted_capabilities
            .remove(&RuntimeCapability::Builtin);
        let tag = "builtin:EventsAddAbortListener";
        assert!(matches!(
            check_hostcall_capability_gate(&mut core, tag, 0),
            Err(InterpreterError::CapabilityDenied { .. })
        ));
        assert!(
            core.event_array_objects(signal, EventArraySlot::Listeners)
                .unwrap()
                .is_empty()
        );
        core.config
            .granted_capabilities
            .insert(RuntimeCapability::Builtin);
        assert!(check_hostcall_capability_gate(&mut core, tag, 1).unwrap());
        core.dispatch_builtin_hostcall(tag, RegRange { start: 0, count: 2 }, Some(&module))
            .unwrap();
        assert_eq!(
            core.event_array_objects(signal, EventArraySlot::Listeners)
                .unwrap()
                .len(),
            1
        );
    }
}
