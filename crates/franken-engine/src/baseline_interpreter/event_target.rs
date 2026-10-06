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

const LISTENERS_SLOT: &str = "__eventTargetListeners";
const EVENT_TYPE_SLOT: &str = "__eventType";
const EVENT_BUBBLES_SLOT: &str = "__eventBubbles";
const EVENT_CANCELABLE_SLOT: &str = "__eventCancelable";
const EVENT_COMPOSED_SLOT: &str = "__eventComposed";
const EVENT_DEFAULT_PREVENTED_SLOT: &str = "__eventDefaultPrevented";
const EVENT_PHASE_SLOT: &str = "__eventPhase";
const EVENT_TARGET_SLOT: &str = "__eventTarget";
const EVENT_CURRENT_TARGET_SLOT: &str = "__eventCurrentTarget";
const EVENT_TIME_STAMP_SLOT: &str = "__eventTimeStamp";
const EVENT_STOP_SLOT: &str = "__eventStop";
const EVENT_STOP_IMMEDIATE_SLOT: &str = "__eventStopImmediate";
const EVENT_IN_PASSIVE_SLOT: &str = "__eventInPassiveListener";
const EVENT_DISPATCHING_SLOT: &str = "__eventDispatching";
const EVENT_DETAIL_SLOT: &str = "__eventDetail";
const CONTROLLER_SIGNAL_SLOT: &str = "__controllerSignal";
const SIGNAL_ABORTED_SLOT: &str = "__signalAborted";
const SIGNAL_REASON_SLOT: &str = "__signalReason";
const SIGNAL_ALGORITHMS_SLOT: &str = "__signalAbortAlgorithms";
const SIGNAL_DEPENDENTS_SLOT: &str = "__signalDependents";
// Present only on composed signals (including any([])); absence denotes a
// root signal. Flattened source order is retained, not a chain of composites.
// Store source IDs as integers so a live composite does not root an abandoned
// source and, transitively, all the other composites registered on that source.
const SIGNAL_SOURCES_SLOT: &str = "__signalSources";

/// The internal slots above: never own keys guest code lists.
pub(super) const EVENT_FAMILY_SLOT_KEYS: [&str; 21] = [
    LISTENERS_SLOT,
    EVENT_TYPE_SLOT,
    EVENT_BUBBLES_SLOT,
    EVENT_CANCELABLE_SLOT,
    EVENT_COMPOSED_SLOT,
    EVENT_DEFAULT_PREVENTED_SLOT,
    EVENT_PHASE_SLOT,
    EVENT_TARGET_SLOT,
    EVENT_CURRENT_TARGET_SLOT,
    EVENT_TIME_STAMP_SLOT,
    EVENT_STOP_SLOT,
    EVENT_STOP_IMMEDIATE_SLOT,
    EVENT_IN_PASSIVE_SLOT,
    EVENT_DISPATCHING_SLOT,
    EVENT_DETAIL_SLOT,
    CONTROLLER_SIGNAL_SLOT,
    SIGNAL_ABORTED_SLOT,
    SIGNAL_REASON_SLOT,
    SIGNAL_ALGORITHMS_SLOT,
    SIGNAL_DEPENDENTS_SLOT,
    SIGNAL_SOURCES_SLOT,
];

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
                self.set_object_property(
                    controller,
                    CONTROLLER_SIGNAL_SLOT.to_string(),
                    Value::Object(signal),
                )?;
                self.hide_internal_slots(controller, &[CONTROLLER_SIGNAL_SLOT])?;
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
                if self.event_slot(event, EVENT_CANCELABLE_SLOT).is_truthy()
                    && !self.event_slot(event, EVENT_IN_PASSIVE_SLOT).is_truthy()
                {
                    self.set_event_slot(event, EVENT_DEFAULT_PREVENTED_SLOT, Value::Bool(true))?;
                }
                Ok(Value::Undefined)
            }
            "Event.stopPropagation" => {
                let event = self.event_receiver(&receiver, "stopPropagation")?;
                self.set_event_slot(event, EVENT_STOP_SLOT, Value::Bool(true))?;
                Ok(Value::Undefined)
            }
            "Event.stopImmediatePropagation" => {
                let event = self.event_receiver(&receiver, "stopImmediatePropagation")?;
                self.set_event_slot(event, EVENT_STOP_SLOT, Value::Bool(true))?;
                self.set_event_slot(event, EVENT_STOP_IMMEDIATE_SLOT, Value::Bool(true))?;
                Ok(Value::Undefined)
            }
            "Event.composedPath" => {
                let event = self.event_receiver(&receiver, "composedPath")?;
                let path = if self.event_slot(event, EVENT_DISPATCHING_SLOT).is_truthy() {
                    vec![self.event_slot(event, EVENT_CURRENT_TARGET_SLOT)]
                } else {
                    Vec::new()
                };
                Ok(Value::Object(self.alloc_array_from_values(&path)?))
            }
            "AbortController.abort" => {
                let controller = match &receiver {
                    Value::Object(id) if self.has_event_slot(*id, CONTROLLER_SIGNAL_SLOT) => *id,
                    other => {
                        return Err(InterpreterError::TypeError {
                            expected: "AbortController receiver for abort".to_string(),
                            got: other.type_name().to_string(),
                        });
                    }
                };
                let Value::Object(signal) = self.event_slot(controller, CONTROLLER_SIGNAL_SLOT)
                else {
                    return Err(InterpreterError::InternalError {
                        details: "AbortController lost its signal".to_string(),
                    });
                };
                let reason = arg(self, 0)?;
                self.abort_signal(module, signal, reason)?;
                Ok(Value::Undefined)
            }
            "AbortSignal.throwIfAborted" => {
                let signal = self.abort_signal_receiver(&receiver, "throwIfAborted")?;
                if self.event_slot(signal, SIGNAL_ABORTED_SLOT).is_truthy() {
                    let reason = self.event_slot(signal, SIGNAL_REASON_SLOT);
                    let label = self.clone_active_execution_context_label()?;
                    return Err(self.throw_guest_value(reason, label)?);
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
                if !self.event_slot(signal, SIGNAL_ABORTED_SLOT).is_truthy() {
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
        match owner {
            "Event" => self.has_event_slot(id, EVENT_TYPE_SLOT),
            "CustomEvent" => self.has_event_slot(id, EVENT_DETAIL_SLOT),
            "AbortController" => self.has_event_slot(id, CONTROLLER_SIGNAL_SLOT),
            "AbortSignal" => self.has_event_slot(id, SIGNAL_ABORTED_SLOT),
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
        let slot = match (owner, key) {
            ("Event", "type") => EVENT_TYPE_SLOT,
            ("Event", "bubbles") => EVENT_BUBBLES_SLOT,
            ("Event", "cancelable") => EVENT_CANCELABLE_SLOT,
            ("Event", "composed") => EVENT_COMPOSED_SLOT,
            ("Event", "defaultPrevented") => EVENT_DEFAULT_PREVENTED_SLOT,
            ("Event", "eventPhase") => EVENT_PHASE_SLOT,
            ("Event", "target" | "srcElement") => EVENT_TARGET_SLOT,
            ("Event", "currentTarget") => EVENT_CURRENT_TARGET_SLOT,
            ("Event", "timeStamp") => EVENT_TIME_STAMP_SLOT,
            ("Event", "cancelBubble") => EVENT_STOP_SLOT,
            ("Event", "returnValue") => {
                return Some(Value::Bool(
                    !self
                        .event_slot(id, EVENT_DEFAULT_PREVENTED_SLOT)
                        .is_truthy(),
                ));
            }
            ("CustomEvent", "detail") => EVENT_DETAIL_SLOT,
            ("AbortController", "signal") => CONTROLLER_SIGNAL_SLOT,
            ("AbortSignal", "aborted") => SIGNAL_ABORTED_SLOT,
            ("AbortSignal", "reason") => SIGNAL_REASON_SLOT,
            _ => return None,
        };
        Some(self.event_slot(id, slot))
    }

    /// An object with the given canonical prototype and an empty listener list.
    fn alloc_event_target(&mut self, prototype: &str) -> Result<ObjectId, InterpreterError> {
        let prototype = self.ensure_builtin_prototype(prototype)?;
        let target = self.alloc_object_with_prototype(Some(prototype))?;
        let listeners = self.alloc_array_from_values(&[])?;
        self.set_object_property(target, LISTENERS_SLOT.to_string(), Value::Object(listeners))?;
        self.hide_internal_slots(target, &[LISTENERS_SLOT])?;
        Ok(target)
    }

    fn alloc_abort_signal(&mut self) -> Result<ObjectId, InterpreterError> {
        let signal = self.alloc_event_target("AbortSignal")?;
        let algorithms = self.alloc_array_from_values(&[])?;
        let dependents = self.alloc_array_from_values(&[])?;
        for (slot, value) in [
            (SIGNAL_ABORTED_SLOT, Value::Bool(false)),
            (SIGNAL_REASON_SLOT, Value::Undefined),
            (SIGNAL_ALGORITHMS_SLOT, Value::Object(algorithms)),
            (SIGNAL_DEPENDENTS_SLOT, Value::Object(dependents)),
            ("onabort", Value::Null),
        ] {
            self.set_object_property(signal, slot.to_string(), value)?;
        }
        self.hide_internal_slots(
            signal,
            &[
                SIGNAL_ABORTED_SLOT,
                SIGNAL_REASON_SLOT,
                SIGNAL_ALGORITHMS_SLOT,
                SIGNAL_DEPENDENTS_SLOT,
                "onabort",
            ],
        )?;
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
        let mut slots = vec![
            (EVENT_TYPE_SLOT, Value::str(event_type)),
            (EVENT_BUBBLES_SLOT, Value::Bool(flags[0])),
            (EVENT_CANCELABLE_SLOT, Value::Bool(flags[1])),
            (EVENT_COMPOSED_SLOT, Value::Bool(flags[2])),
            (EVENT_DEFAULT_PREVENTED_SLOT, Value::Bool(false)),
            (EVENT_PHASE_SLOT, Value::Int(0)),
            (EVENT_TARGET_SLOT, Value::Null),
            (EVENT_CURRENT_TARGET_SLOT, Value::Null),
            (EVENT_TIME_STAMP_SLOT, time_stamp),
            (EVENT_STOP_SLOT, Value::Bool(false)),
            (EVENT_STOP_IMMEDIATE_SLOT, Value::Bool(false)),
            (EVENT_IN_PASSIVE_SLOT, Value::Bool(false)),
            (EVENT_DISPATCHING_SLOT, Value::Bool(false)),
        ];
        if prototype == "CustomEvent" {
            slots.push((EVENT_DETAIL_SLOT, detail));
        }
        let keys: Vec<&str> = slots.iter().map(|(slot, _)| *slot).collect();
        for (slot, value) in slots {
            self.set_object_property(event, slot.to_string(), value)?;
        }
        self.hide_internal_slots(event, &keys)?;
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
        if self.event_slot(signal, SIGNAL_ABORTED_SLOT).is_truthy() {
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
        for dependent in self.event_array_objects(signal, SIGNAL_DEPENDENTS_SLOT)? {
            if !self.event_slot(dependent, SIGNAL_ABORTED_SLOT).is_truthy() {
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
        // The internal array helpers treat an undefined list as empty. Clear
        // without allocating after callbacks, including on a host refusal.
        let cleanup = self.set_event_slot(signal, SIGNAL_DEPENDENTS_SLOT, Value::Undefined);
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
            let mut remaining = self.event_array_objects(original, SIGNAL_DEPENDENTS_SLOT)?;
            let previous_len = remaining.len();
            remaining.retain(|dependent| {
                !self.event_slot(*dependent, SIGNAL_ABORTED_SLOT).is_truthy()
            });
            if remaining.len() == previous_len {
                continue;
            }
            let list = if remaining.is_empty() {
                Value::Undefined
            } else {
                let values: Vec<Value> = remaining.into_iter().map(Value::Object).collect();
                Value::Object(self.alloc_array_from_values(&values)?)
            };
            self.set_event_slot(original, SIGNAL_DEPENDENTS_SLOT, list)?;
        }
        for dependent in dependents {
            // Keep the slot present: an empty dependent is not a new root.
            self.set_event_slot(*dependent, SIGNAL_SOURCES_SLOT, Value::Undefined)?;
        }
        Ok(())
    }

    /// The heap never reuses object IDs. Integer IDs therefore act as weak
    /// source handles: skip reclaimed sources instead of retaining them via
    /// Value::Object edges traced by the collector. The source list itself is
    /// still an ordinary accounted, traced array owned by the composite.
    fn signal_source_objects(&mut self, signal: ObjectId) -> Result<Vec<ObjectId>, InterpreterError> {
        let Value::Object(list) = self.event_slot(signal, SIGNAL_SOURCES_SLOT) else {
            return Ok(Vec::new());
        };
        Ok(self
            .array_like_values(list)?
            .into_iter()
            .filter_map(|value| match value {
                Value::Int(id) => u32::try_from(id).ok().map(ObjectId),
                _ => None,
            })
            .filter(|source| self.has_event_slot(*source, SIGNAL_ABORTED_SLOT))
            .collect())
    }

    fn signal_mark_aborted(
        &mut self,
        signal: ObjectId,
        reason: Value,
    ) -> Result<(), InterpreterError> {
        // Admit the potentially allocating reason before publishing aborted.
        self.set_event_slot(signal, SIGNAL_REASON_SLOT, reason)?;
        self.set_event_slot(signal, SIGNAL_ABORTED_SLOT, Value::Bool(true))
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
        let records = self.event_array_objects(signal, SIGNAL_ALGORITHMS_SLOT)?;
        self.set_event_slot(signal, SIGNAL_ALGORITHMS_SLOT, Value::Undefined)?;
        for record in records {
            if let Value::Object(target) = self.event_slot(record, "target") {
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
                Value::Object(id) if self.has_event_slot(id, SIGNAL_ABORTED_SLOT) => {
                    sources.push(id)
                }
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
            if self.event_slot(*source, SIGNAL_ABORTED_SLOT).is_truthy() {
                let reason = self.event_slot(*source, SIGNAL_REASON_SLOT);
                self.signal_mark_aborted(result, reason)?;
                return Ok(Value::Object(result));
            }
        }
        let mut roots = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for source in sources {
            let candidates = if self.has_event_slot(source, SIGNAL_SOURCES_SLOT) {
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
        self.set_event_slot(result, SIGNAL_SOURCES_SLOT, Value::Object(root_list))?;
        self.hide_internal_slots(result, &[SIGNAL_SOURCES_SLOT])?;
        for root in roots {
            self.event_array_push(root, SIGNAL_DEPENDENTS_SLOT, Value::Object(result))?;
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
            Value::Object(id) if self.has_event_slot(id, SIGNAL_ABORTED_SLOT) => Some(id),
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "an AbortSignal as the signal option".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        if signal.is_some_and(|signal| self.event_slot(signal, SIGNAL_ABORTED_SLOT).is_truthy()) {
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
            self.set_event_slot(record, "signal", Value::Int(i64::from(signal.0)))?;
        }
        let previous_list = self.event_slot(target, LISTENERS_SLOT);
        self.event_array_push(target, LISTENERS_SLOT, Value::Object(record))?;
        if let Some(signal) = signal
            && let Err(error) =
                self.event_array_push(signal, SIGNAL_ALGORITHMS_SLOT, Value::Object(record))
        {
            // A refusal while adding cancellation must not leave an active,
            // uncancellable listener on the target. Restoring the old list
            // needs no replacement array or guest callback.
            self.set_event_slot(record, "removed", Value::Bool(true))?;
            self.set_event_slot(target, LISTENERS_SLOT, previous_list)?;
            return Err(error);
        }
        Ok(())
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
        for record in self.event_array_objects(target, LISTENERS_SLOT)? {
            let same_type = matches!(
                self.event_slot(record, "type"),
                Value::Str(text) if text.as_str() == Some(event_type)
            );
            if same_type
                && Self::same_value(&self.event_slot(record, "callback"), callback)
                && self.event_slot(record, "capture").is_truthy() == capture
                && !self.event_slot(record, "removed").is_truthy()
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
        self.set_event_slot(record, "removed", Value::Bool(true))?;
        self.event_array_remove(target, LISTENERS_SLOT, record)?;
        if let Value::Int(signal) = self.event_slot(record, "signal")
            && let Ok(signal) = u32::try_from(signal)
        {
            let signal = ObjectId(signal);
            if self.has_event_slot(signal, SIGNAL_ABORTED_SLOT) {
                self.event_array_remove(signal, SIGNAL_ALGORITHMS_SLOT, record)?;
            }
        }
        if self.has_event_slot(record, "signal") {
            self.set_event_slot(record, "signal", Value::Undefined)?;
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
            Value::Object(id) if self.has_event_slot(*id, EVENT_TYPE_SLOT) => *id,
            other => {
                return Err(InterpreterError::TypeError {
                    expected: "an Event as the argument of dispatchEvent".to_string(),
                    got: other.type_name().to_string(),
                });
            }
        };
        if self.event_slot(event, EVENT_DISPATCHING_SLOT).is_truthy() {
            let error = self.alloc_dom_exception(
                "The event is already being dispatched",
                "InvalidStateError",
            )?;
            let label = self.clone_active_execution_context_label()?;
            return Err(self.throw_guest_value(Value::Object(error), label)?);
        }
        self.set_event_slot(event, EVENT_TARGET_SLOT, target_value.clone())?;
        self.set_event_slot(event, EVENT_CURRENT_TARGET_SLOT, target_value.clone())?;
        self.set_event_slot(event, EVENT_PHASE_SLOT, Value::Int(2))?;
        self.set_event_slot(event, EVENT_DISPATCHING_SLOT, Value::Bool(true))?;
        let event_type = match self.event_slot(event, EVENT_TYPE_SLOT) {
            Value::Str(text) => text.to_string(),
            _ => String::new(),
        };
        let mut first_error: Option<(Value, Label)> = None;
        if event_type == "abort" && self.has_event_slot(target, SIGNAL_ABORTED_SLOT) {
            let handler = self.event_slot(target, "onabort");
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
            .event_array_objects(target, LISTENERS_SLOT)?
            .into_iter()
            .filter(|record| {
                matches!(
                    self.event_slot(*record, "type"),
                    Value::Str(text) if text.as_str() == Some(event_type.as_str())
                )
            })
            .collect();
        for record in records {
            if self.event_slot(record, "removed").is_truthy() {
                continue;
            }
            if self
                .event_slot(event, EVENT_STOP_IMMEDIATE_SLOT)
                .is_truthy()
            {
                break;
            }
            if self.event_slot(record, "once").is_truthy() {
                self.event_target_remove_record(target, record)?;
            }
            let passive = self.event_slot(record, "passive");
            self.set_event_slot(event, EVENT_IN_PASSIVE_SLOT, passive)?;
            let callback = self.event_slot(record, "callback");
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
            self.set_event_slot(event, EVENT_IN_PASSIVE_SLOT, Value::Bool(false))?;
            self.event_listener_outcome(outcome, &mut first_error)?;
        }
        // Node leaves target and currentTarget set after the dispatch.
        self.set_event_slot(event, EVENT_PHASE_SLOT, Value::Int(0))?;
        self.set_event_slot(event, EVENT_DISPATCHING_SLOT, Value::Bool(false))?;
        if let Some((thrown, label)) = first_error {
            return Err(self.throw_guest_value(thrown, label)?);
        }
        let canceled = self.event_slot(event, EVENT_CANCELABLE_SLOT).is_truthy()
            && self
                .event_slot(event, EVENT_DEFAULT_PREVENTED_SLOT)
                .is_truthy();
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
        let label = self.clone_active_execution_context_label()?;
        let thrown = self.thrown_completion_value(error, &label)?;
        if first_error.is_none() {
            *first_error = Some(thrown);
        }
        Ok(())
    }

    fn event_target_receiver(
        &self,
        receiver: &Value,
        method: &str,
    ) -> Result<ObjectId, InterpreterError> {
        match receiver {
            Value::Object(id) if self.has_event_slot(*id, LISTENERS_SLOT) => Ok(*id),
            other => Err(InterpreterError::TypeError {
                expected: format!("EventTarget receiver for {method}"),
                got: other.type_name().to_string(),
            }),
        }
    }

    fn event_receiver(&self, receiver: &Value, method: &str) -> Result<ObjectId, InterpreterError> {
        match receiver {
            Value::Object(id) if self.has_event_slot(*id, EVENT_TYPE_SLOT) => Ok(*id),
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
            Value::Object(id) if self.has_event_slot(*id, SIGNAL_ABORTED_SLOT) => Ok(*id),
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

    fn has_event_slot(&self, id: ObjectId, slot: &str) -> bool {
        self.heap
            .get(id.0 as usize)
            .is_some_and(|object| object.properties.get(slot).is_some())
    }

    fn event_slot(&self, id: ObjectId, slot: &str) -> Value {
        self.heap
            .get(id.0 as usize)
            .and_then(|object| object.properties.get(slot).cloned())
            .unwrap_or(Value::Undefined)
    }

    fn set_event_slot(
        &mut self,
        id: ObjectId,
        slot: &str,
        value: Value,
    ) -> Result<(), InterpreterError> {
        self.set_object_property(id, slot.to_string(), value)
    }

    /// The objects of the array in slot `slot` of `id`.
    fn event_array_objects(
        &mut self,
        id: ObjectId,
        slot: &str,
    ) -> Result<Vec<ObjectId>, InterpreterError> {
        let Value::Object(list) = self.event_slot(id, slot) else {
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

    /// Append to the array in slot `slot` of `id` (a fresh array, so a
    /// dispatch iterating the old one is unaffected).
    fn event_array_push(
        &mut self,
        id: ObjectId,
        slot: &str,
        value: Value,
    ) -> Result<(), InterpreterError> {
        let mut values: Vec<Value> = self
            .event_array_objects(id, slot)?
            .into_iter()
            .map(Value::Object)
            .collect();
        values.push(value);
        let list = self.alloc_array_from_values(&values)?;
        self.set_event_slot(id, slot, Value::Object(list))
    }

    /// Remove an internal record without touching any other registration.
    /// A missing entry is a no-op; empty lists need no heap allocation. Nonempty
    /// replacements preserve the old array for dispatch snapshots.
    fn event_array_remove(
        &mut self,
        id: ObjectId,
        slot: &str,
        record: ObjectId,
    ) -> Result<(), InterpreterError> {
        let mut entries = self.event_array_objects(id, slot)?;
        let before = entries.len();
        entries.retain(|entry| *entry != record);
        if entries.len() == before {
            return Ok(());
        }
        let replacement = if entries.is_empty() {
            Value::Undefined
        } else {
            let values: Vec<Value> = entries.into_iter().map(Value::Object).collect();
            Value::Object(self.alloc_array_from_values(&values)?)
        };
        self.set_event_slot(id, slot, replacement)
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
        let core = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "abort-graph-unit");
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
        assert_eq!(
            core.signal_source_objects(second).unwrap(),
            vec![b, a]
        );
        let Value::Object(source_list) = core.event_slot(second, SIGNAL_SOURCES_SLOT) else {
            panic!("a dependent keeps its ordered source set");
        };
        assert_eq!(
            core.array_like_values(source_list).unwrap(),
            vec![Value::Int(i64::from(b.0)), Value::Int(i64::from(a.0))],
            "source links must not be strong object references"
        );
        for source in [a, b] {
            assert_eq!(
                core.event_array_objects(source, SIGNAL_DEPENDENTS_SLOT)
                    .unwrap(),
                vec![first, second]
            );
        }
        assert!(
            core.event_array_objects(first, SIGNAL_DEPENDENTS_SLOT)
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
            core.event_array_objects(a, SIGNAL_DEPENDENTS_SLOT)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            core.event_array_objects(b, SIGNAL_DEPENDENTS_SLOT).unwrap(),
            vec![live]
        );
        for signal in [first, second] {
            assert!(core.has_event_slot(signal, SIGNAL_SOURCES_SLOT));
            assert!(
                core.signal_source_objects(signal).unwrap().is_empty()
            );
            assert_eq!(
                core.event_slot(signal, SIGNAL_REASON_SLOT),
                Value::str("cancel")
            );
        }
        core.signal_abort_with(&module, b, Value::str("later"))
            .expect("abort b");
        assert_eq!(core.event_slot(live, SIGNAL_REASON_SLOT), Value::str("later"));
        assert_eq!(
            core.event_slot(second, SIGNAL_REASON_SLOT),
            Value::str("cancel")
        );
        assert!(
            core.event_array_objects(b, SIGNAL_DEPENDENTS_SLOT)
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
            core.event_array_objects(empty, SIGNAL_DEPENDENTS_SLOT)
                .unwrap()
                .is_empty()
        );
        assert!(
            core.signal_source_objects(nested).unwrap().is_empty()
        );
        assert!(!core.event_slot(nested, SIGNAL_ABORTED_SLOT).is_truthy());
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
                core.event_array_objects(shared, SIGNAL_DEPENDENTS_SLOT)
                    .unwrap()
                    .is_empty(),
                "the shared source must release request {request_id}"
            );
            assert_eq!(
                core.event_slot(nested, SIGNAL_REASON_SLOT),
                Value::Int(request_id)
            );
        }
        let last = any(&mut core, &module, &[shared]);
        core.signal_abort_with(&module, shared, Value::str("shutdown"))
            .expect("new subscriptions still work after pruning");
        assert_eq!(
            core.event_slot(last, SIGNAL_REASON_SLOT),
            Value::str("shutdown")
        );
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
        let ordinary = core.alloc_object_with_prototype(None).expect("ordinary object");
        let list = core
            .alloc_array_from_values(&[
                Value::Int(-1),
                Value::Int(i64::from(u32::MAX)),
                Value::Int(i64::from(ordinary.0)),
                Value::Int(i64::from(original.0)),
            ])
            .expect("weak handles");
        core.set_event_slot(dependent, SIGNAL_SOURCES_SLOT, Value::Object(list))
            .expect("source list");
        assert_eq!(core.signal_source_objects(dependent).unwrap(), vec![original]);
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
            module, target, Value::str("work"), callback.clone(), Value::Object(options),
        )
        .expect("signal-bound listener");
        core.event_target_find_record(target, "work", &callback, flags[0])
            .expect("listener lookup")
            .expect("registered listener")
    }

    fn listener_object(core: &mut InterpreterCore) -> Value {
        // EventListener objects are valid even without a handleEvent method.
        // Public-path fixtures below exercise actual guest callback invocation.
        Value::Object(core.alloc_object_with_prototype(None).expect("listener object"))
    }

    #[test]
    fn explicit_listener_removal_unlinks_only_its_abort_algorithm() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let callback = listener_object(&mut core);
        let other_callback = listener_object(&mut core);
        let record = listen(&mut core, &module, target, signal, callback, [false, false]);
        let peer = listen(&mut core, &module, target, signal, other_callback, [false, false]);
        assert_eq!(core.event_slot(record, "signal"), Value::Int(i64::from(signal.0)));
        core.event_target_remove_record(target, record).unwrap();
        assert_eq!(core.event_array_objects(signal, SIGNAL_ALGORITHMS_SLOT).unwrap(), vec![peer]);
        assert_eq!(core.event_array_objects(target, LISTENERS_SLOT).unwrap(), vec![peer]);
        assert_eq!(core.event_slot(record, "signal"), Value::Undefined);
        let list = core.event_slot(signal, SIGNAL_ALGORITHMS_SLOT);
        core.event_target_remove_record(target, record).unwrap();
        assert_eq!(core.event_slot(signal, SIGNAL_ALGORITHMS_SLOT), list, "idempotent unlink");
        core.abort_signal(&module, signal, Value::Undefined).unwrap();
        assert!(core.event_slot(peer, "removed").is_truthy());
        assert!(core.event_array_objects(target, LISTENERS_SLOT).unwrap().is_empty());
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn once_delivery_releases_abort_algorithm_but_retains_its_callback_snapshot() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let callback = listener_object(&mut core);
        let record = listen(&mut core, &module, target, signal, callback.clone(), [false, true]);
        let event = core.alloc_event("Event", "work", [false; 3], Value::Null).unwrap();
        core.event_target_dispatch(&module, &Value::Object(target), &Value::Object(event)).unwrap();
        assert!(core.event_array_objects(signal, SIGNAL_ALGORITHMS_SLOT).unwrap().is_empty());
        assert!(core.event_array_objects(target, LISTENERS_SLOT).unwrap().is_empty());
        assert_eq!(core.event_slot(record, "callback"), callback, "snapshot must retain its callback");
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn completed_listeners_do_not_accumulate_on_a_long_lived_signal() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let callback = listener_object(&mut core);
        for attempt in 0..128 {
            let record = listen(&mut core, &module, target, signal, callback.clone(), [false, false]);
            core.event_target_remove_record(target, record).unwrap();
            assert!(core.event_array_objects(signal, SIGNAL_ALGORITHMS_SLOT).unwrap().is_empty(),
                "completed registration {attempt} was retained");
        }
        assert!(!core.event_slot(signal, SIGNAL_ABORTED_SLOT).is_truthy());
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn listener_reregistration_belongs_to_the_new_signal_only() {
        let (mut core, module) = runtime();
        let first = core.alloc_abort_signal().unwrap();
        let second = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let callback = listener_object(&mut core);
        let old = listen(&mut core, &module, target, first, callback.clone(), [false, false]);
        core.event_target_remove_record(target, old).unwrap();
        let new = listen(&mut core, &module, target, second, callback, [false, false]);
        core.abort_signal(&module, first, Value::Undefined).unwrap();
        assert_eq!(core.event_array_objects(target, LISTENERS_SLOT).unwrap(), vec![new]);
        assert_eq!(core.event_array_objects(second, SIGNAL_ALGORITHMS_SLOT).unwrap(), vec![new]);
        core.abort_signal(&module, second, Value::Undefined).unwrap();
        assert!(core.event_array_objects(target, LISTENERS_SLOT).unwrap().is_empty());
    }

    #[test]
    fn capture_registrations_and_duplicate_requests_keep_distinct_ownership() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let callback = listener_object(&mut core);
        let bubbling = listen(&mut core, &module, target, signal, callback.clone(), [false, false]);
        let capture = listen(&mut core, &module, target, signal, callback.clone(), [true, false]);
        assert_eq!(listen(&mut core, &module, target, signal, callback, [false, false]), bubbling);
        assert_eq!(core.event_array_objects(signal, SIGNAL_ALGORITHMS_SLOT).unwrap(), vec![bubbling, capture]);
        core.event_target_remove_record(target, bubbling).unwrap();
        assert_eq!(core.event_array_objects(signal, SIGNAL_ALGORITHMS_SLOT).unwrap(), vec![capture]);
        core.abort_signal(&module, signal, Value::Undefined).unwrap();
        assert!(core.event_array_objects(target, LISTENERS_SLOT).unwrap().is_empty());
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
        core.abort_signal(&module, signal, Value::Undefined).unwrap();
        assert_eq!(core.event_slot(signal, SIGNAL_ALGORITHMS_SLOT), Value::Undefined);
        for target in targets {
            assert!(core.event_array_objects(target, LISTENERS_SLOT).unwrap().is_empty());
        }
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn cancellation_registration_refusal_restores_the_original_target_list() {
        let (mut core, module) = runtime();
        let signal = core.alloc_abort_signal().unwrap();
        let target = core.alloc_event_target("EventTarget").unwrap();
        let existing = listener_object(&mut core);
        let peer = listen(&mut core, &module, target, signal, existing, [false, false]);
        let callback = listener_object(&mut core);
        let options = core.alloc_object_with_properties(&[("signal", Value::Object(signal))]).unwrap();
        let target_list = core.event_slot(target, LISTENERS_SLOT);
        let signal_list = core.event_slot(signal, SIGNAL_ALGORITHMS_SLOT);
        // Permit the listener record and replacement target list, but refuse
        // the third allocation: its cancellation registration's new array.
        let before = core.heap.live_len();
        core.config.max_heap_objects = u32::try_from(before + 2).unwrap();
        core.event_target_add_listener(
            &module, target, Value::str("work"), callback, Value::Object(options),
        )
        .expect_err("cancellation registration must fail at the object limit");
        assert_eq!(core.heap.live_len(), before + 2, "reach the cancellation allocation");
        assert_eq!(core.event_slot(target, LISTENERS_SLOT), target_list);
        assert_eq!(core.event_slot(signal, SIGNAL_ALGORITHMS_SLOT), signal_list);
        assert_eq!(core.event_array_objects(target, LISTENERS_SLOT).unwrap(), vec![peer]);
        assert!(!core.event_slot(peer, "removed").is_truthy());
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }
}
