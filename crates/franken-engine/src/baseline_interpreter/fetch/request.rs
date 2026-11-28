//! Native buffered Request objects. Construction is pure computation; only
//! the existing fetch hostcall can acquire network authority.

use super::*;

pub(in crate::baseline_interpreter) const REQUEST_METHODS: [&str; 5] =
    ["text", "json", "arrayBuffer", "bytes", "clone"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::baseline_interpreter) struct FetchRequestSlots {
    pub url: String,
    pub method: String,
    pub headers: ObjectId,
    // A null body remains reusable; an empty non-null body is consumable.
    pub body: Option<Vec<u8>>,
    pub body_used: bool,
    pub redirect: FetchRedirectMode,
    pub signal: ObjectId,
}

impl BuiltinFunction {
    pub(in crate::baseline_interpreter) fn fetch_request_method(name: &str) -> Option<Self> {
        REQUEST_METHODS.contains(&name).then(|| Self {
            kind: BuiltinFunctionKind::FetchRequestMethod,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(name),
            iterator_handle: None,
            bound_object: None,
        })
    }
}

impl HeapObject {
    pub(in crate::baseline_interpreter) fn fetch_request_slots(
        &self,
    ) -> Option<&FetchRequestSlots> {
        match self.host_slots.as_deref() {
            Some(HostObjectSlots::FetchRequest(slots)) => Some(slots),
            _ => None,
        }
    }
}

struct RequestInit {
    body: Value,
    headers: Option<Vec<(String, String)>>,
    method: Option<String>,
    redirect: Option<FetchRedirectMode>,
    // None means absent; Some(None) explicitly disconnects an inherited signal.
    signal: Option<Option<ObjectId>>,
    unsupported: Option<&'static str>,
    invalid_window: bool,
}

impl InterpreterCore {
    fn fetch_request_enum(
        &mut self,
        module: Option<&Ir3Module>,
        init: &Value,
        name: &str,
        choices: &[&str],
        scratch: &mut u64,
    ) -> Result<Option<String>, InterpreterError> {
        let value = self.fetch_property(module, init, name)?;
        if matches!(value, Value::Undefined) {
            return Ok(None);
        }
        let text = self.fetch_string(module, value, scratch)?;
        if !choices.contains(&text.as_str()) {
            return Err(fetch_type_error(&format!(
                "a valid RequestInit.{name} value"
            )));
        }
        Ok(Some(text))
    }

    fn convert_fetch_request_init(
        &mut self,
        module: Option<&Ir3Module>,
        init: &Value,
        scratch: &mut u64,
    ) -> Result<RequestInit, InterpreterError> {
        if !matches!(init, Value::Undefined | Value::Null) && !init.is_object_like() {
            return Err(fetch_type_error("a Request init dictionary"));
        }
        self.json_observe_reachable_value(init)?;
        let mut unsupported = None;
        // Dictionary values convert immediately after each Get, in Web IDL
        // lexicographic order. Semantic validation follows the full conversion.
        let body = self.fetch_property(module, init, "body")?;
        self.gc_pin_network_values([body.clone()]);
        let body = self.normalize_fetch_body(module, body, scratch)?;
        self.gc_pin_network_values([body.clone()]);
        for (name, choices, supported) in [
            (
                "cache",
                &[
                    "default",
                    "no-store",
                    "reload",
                    "no-cache",
                    "force-cache",
                    "only-if-cached",
                ][..],
                "default",
            ),
            (
                "credentials",
                &["omit", "same-origin", "include"][..],
                "same-origin",
            ),
            ("duplex", &["half"][..], "half"),
        ] {
            if self
                .fetch_request_enum(module, init, name, choices, scratch)?
                .is_some_and(|value| value != supported)
            {
                unsupported.get_or_insert(name);
            }
        }
        let headers = self.fetch_property(module, init, "headers")?;
        let headers = if matches!(headers, Value::Undefined) {
            None
        } else {
            Some(self.fetch_request_headers(module, headers, scratch)?)
        };
        let integrity = self.fetch_property(module, init, "integrity")?;
        if !matches!(integrity, Value::Undefined)
            && !self.fetch_string(module, integrity, scratch)?.is_empty()
        {
            unsupported.get_or_insert("integrity");
        }
        let keepalive = self.fetch_property(module, init, "keepalive")?;
        self.json_observe_reachable_value(&keepalive)?;
        if keepalive.is_truthy() {
            unsupported.get_or_insert("keepalive");
        }
        let method = self.fetch_property(module, init, "method")?;
        let method = if matches!(method, Value::Undefined) {
            None
        } else {
            let module = module.ok_or_else(|| InterpreterError::InternalError {
                details: "Request method conversion requires its executing module".to_string(),
            })?;
            Some(self.fetch_object_byte_string(module, method, scratch)?)
        };
        for (name, choices, supported) in [
            (
                "mode",
                &["navigate", "same-origin", "no-cors", "cors"][..],
                "cors",
            ),
            ("priority", &["high", "low", "auto"][..], "auto"),
        ] {
            if self
                .fetch_request_enum(module, init, name, choices, scratch)?
                .is_some_and(|value| value != supported)
            {
                unsupported.get_or_insert(name);
            }
        }
        let redirect = self
            .fetch_request_enum(
                module,
                init,
                "redirect",
                &["follow", "error", "manual"],
                scratch,
            )?
            .map(|value| match value.as_str() {
                "error" => FetchRedirectMode::Error,
                "manual" => FetchRedirectMode::Manual,
                _ => FetchRedirectMode::Follow,
            });
        let referrer = self.fetch_property(module, init, "referrer")?;
        if !matches!(referrer, Value::Undefined)
            && self.fetch_string(module, referrer, scratch)? != "about:client"
        {
            unsupported.get_or_insert("referrer");
        }
        if self
            .fetch_request_enum(
                module,
                init,
                "referrerPolicy",
                &[
                    "",
                    "no-referrer",
                    "no-referrer-when-downgrade",
                    "same-origin",
                    "origin",
                    "strict-origin",
                    "origin-when-cross-origin",
                    "strict-origin-when-cross-origin",
                    "unsafe-url",
                ],
                scratch,
            )?
            .is_some_and(|value| !value.is_empty())
        {
            unsupported.get_or_insert("referrerPolicy");
        }
        let signal = self.fetch_property(module, init, "signal")?;
        self.json_observe_reachable_value(&signal)?;
        self.gc_pin_network_values([signal.clone()]);
        let signal = match signal {
            Value::Undefined => None,
            Value::Null => Some(None),
            Value::Object(id)
                if self
                    .heap
                    .get(id.0 as usize)
                    .is_some_and(|object| object.abort_signal_slots().is_some()) =>
            {
                Some(Some(id))
            }
            _ => return Err(fetch_type_error("an AbortSignal or null")),
        };
        let window = self.fetch_property(module, init, "window")?;
        self.json_observe_reachable_value(&window)?;
        Ok(RequestInit {
            body,
            headers,
            method,
            redirect,
            signal,
            unsupported,
            invalid_window: !matches!(window, Value::Undefined | Value::Null),
        })
    }

    fn alloc_fetch_request(
        &mut self,
        mut slots: FetchRequestSlots,
        fields: Vec<(String, String)>,
        label: &Label,
    ) -> Result<ObjectId, InterpreterError> {
        let pins = self.gc_pin_network_values([Value::Object(slots.signal)]);
        let result = (|| {
            let prototype = self.ensure_builtin_prototype("Headers")?;
            let headers = self.alloc_object_with_prototype(Some(prototype))?;
            self.gc_pin_network_values([Value::Object(headers)]);
            self.set_host_slots(
                headers,
                HostObjectSlots::FetchHeaders(FetchHeadersSlots {
                    fields,
                    immutable: false,
                }),
            )?;
            self.join_object_mutation_label(headers, label)?;
            let prototype = self.ensure_builtin_prototype("Request")?;
            let request = self.alloc_object_with_prototype(Some(prototype))?;
            slots.headers = headers;
            self.set_host_slots(request, HostObjectSlots::FetchRequest(slots))?;
            self.join_object_mutation_label(request, label)?;
            Ok(request)
        })();
        self.gc_unpin_network_values(pins);
        result
    }

    /// The shared constructor algorithm for `new Request` and `fetch`.
    /// Native input identity takes precedence over any guest stringifier or
    /// metadata property. Transfer is committed only after all validations,
    /// allocations and label admission have succeeded.
    pub(in crate::baseline_interpreter) fn prepare_fetch_request(
        &mut self,
        module: Option<&Ir3Module>,
        input: Value,
        init: Value,
        scratch: &mut u64,
    ) -> Result<ObjectId, InterpreterError> {
        self.json_observe_reachable_value(&input)?;
        let pins = self.gc_pin_network_values([input.clone(), init.clone()]);
        let result = (|| {
            let source = match &input {
                Value::Object(id)
                    if self
                        .heap
                        .get(id.0 as usize)
                        .is_some_and(|object| object.fetch_request_slots().is_some()) =>
                {
                    Some(*id)
                }
                _ => None,
            };
            // RequestInfo converts before RequestInit; parsing the converted
            // string is part of the later constructor algorithm.
            let input_url = if source.is_none() {
                Some(self.fetch_string(module, input, scratch)?)
            } else {
                None
            };
            let init = self.convert_fetch_request_init(module, &init, scratch)?;
            let mut slots;
            let mut fields;
            if let Some(source) = source {
                // Init getters may have mutated or consumed the original
                // request, headers or dependent signal under a newer label.
                self.json_observe_reachable_value(&Value::Object(source))?;
                let source_slots = self.heap[source.0 as usize]
                    .fetch_request_slots()
                    .expect("authenticated Request");
                let headers = source_slots.headers;
                let bytes = Self::estimate_host_object_slots_bytes(
                    self.heap[source.0 as usize]
                        .host_slots
                        .as_deref()
                        .expect("Request slots"),
                )
                .saturating_add(Self::estimate_host_object_slots_bytes(
                    self.heap[headers.0 as usize]
                        .host_slots
                        .as_deref()
                        .expect("Headers slots"),
                ));
                self.fetch_reserve(scratch, bytes)?;
                self.fetch_charge_bytes(usize::try_from(bytes).unwrap_or(usize::MAX))?;
                self.json_observe_reachable_value(&Value::Object(headers))?;
                slots = self.heap[source.0 as usize]
                    .fetch_request_slots()
                    .expect("Request slots")
                    .clone();
                fields = self.heap[headers.0 as usize]
                    .fetch_headers_slots()
                    .expect("Headers slots")
                    .fields
                    .clone();
            } else {
                let url_text = input_url.expect("converted RequestInfo string");
                self.fetch_reserve(
                    scratch,
                    (url_text.len() as u64)
                        .saturating_mul(6)
                        .saturating_add(1024),
                )?;
                let url = Url::parse(&url_text)
                    .map_err(|_| fetch_type_error("an absolute Request URL"))?;
                if !url.username().is_empty() || url.password().is_some() {
                    return Err(fetch_type_error(
                        "a Request URL without embedded credentials",
                    ));
                }
                slots = FetchRequestSlots {
                    url: url.to_string(),
                    method: "GET".to_string(),
                    headers: ObjectId(0),
                    body: None,
                    body_used: false,
                    redirect: FetchRedirectMode::Follow,
                    signal: ObjectId(0),
                };
                fields = Vec::new();
            }
            if init.invalid_window {
                return Err(fetch_type_error("a null RequestInit.window"));
            }
            if let Some(option) = init.unsupported {
                return Err(fetch_type_error(&format!(
                    "the supported default for RequestInit.{option}"
                )));
            }
            if let Some(mut method) = init.method {
                if !http_token(&method)
                    || ["CONNECT", "TRACE", "TRACK"]
                        .iter()
                        .any(|forbidden| method.eq_ignore_ascii_case(forbidden))
                {
                    return Err(fetch_type_error("a permitted HTTP method"));
                }
                for canonical in ["DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"] {
                    if method.eq_ignore_ascii_case(canonical) {
                        method = canonical.to_string();
                        break;
                    }
                }
                slots.method = method;
            }
            if let Some(redirect) = init.redirect {
                slots.redirect = redirect;
            }
            if let Some(headers) = init.headers {
                fields = self.fetch_fill_header_fields(headers, scratch)?;
            }
            let inherits_body = matches!(init.body, Value::Null | Value::Undefined);
            if inherits_body {
                if slots.body_used {
                    return Err(fetch_type_error("an unused Request body"));
                }
            } else {
                let (body, content_type) = self.fetch_request_body(module, init.body, scratch)?;
                slots.body = body;
                slots.body_used = false;
                if let Some(content_type) = content_type
                    && !fields.iter().any(|(name, _)| name == "content-type")
                {
                    self.fetch_stage_header_pair(
                        &mut fields,
                        "content-type".to_string(),
                        content_type,
                        scratch,
                    )?;
                }
            }
            if matches!(slots.method.as_str(), "GET" | "HEAD") && slots.body.is_some() {
                return Err(fetch_type_error("a GET or HEAD request without a body"));
            }
            let source_signal = init.signal.unwrap_or(source.map(|_| slots.signal));
            if let Some(signal) = source_signal {
                self.json_observe_reachable_value(&Value::Object(signal))?;
            }
            slots.signal = self.alloc_fetch_dependent_signal(source_signal)?;
            let label = self.json_parse_context_label()?;
            self.join_object_mutation_label(slots.signal, &label)?;
            let transferred_bytes = if inherits_body && source.is_some() {
                slots.body.as_ref().map(Vec::len)
            } else {
                None
            };
            slots.body_used = false;
            let request = self.alloc_fetch_request(slots, fields, &label)?;
            self.gc_pin_network_values([Value::Object(request)]);
            self.join_into_pending_hostcall_result_label(Some(label.clone()))?;
            if let (Some(source), Some(bytes)) = (source, transferred_bytes) {
                self.join_object_mutation_label(source, &label)?;
                self.mutate_heap(|heap| {
                    if let Some(HostObjectSlots::FetchRequest(slots)) =
                        heap[source.0 as usize].host_slots.as_deref_mut()
                    {
                        slots.body_used = true;
                        if let Some(body) = &mut slots.body {
                            // Keep the non-null body state while releasing its
                            // transferred bytes from the source's memory meter.
                            *body = Vec::new();
                        }
                    }
                });
                self.apply_memory_component_delta(bytes as u64, 0)?;
            }
            Ok(request)
        })();
        self.gc_unpin_network_values(pins);
        result
    }

    pub(in crate::baseline_interpreter) fn construct_fetch_request(
        &mut self,
        module: &Ir3Module,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        if args.count == 0 {
            return Err(fetch_type_error("the required Request input"));
        }
        let input = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        let init = self.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
        let label = self.join_arg_range_label(args)?;
        self.scoped_conversion(|core| {
            core.json_observe_label(label)?;
            let mut scratch = 0;
            let result = core
                .prepare_fetch_request(Some(module), input, init, &mut scratch)
                .map(Value::Object);
            let result = core.finish_fetch_object_result(result);
            core.json_release_temporary(scratch);
            result
        })
    }

    pub(in crate::baseline_interpreter) fn fetch_request_getter(
        &mut self,
        id: ObjectId,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        let slots = self
            .heap
            .get(id.0 as usize)
            .and_then(HeapObject::fetch_request_slots)
            .ok_or_else(|| fetch_type_error("a Request receiver"))?;
        Ok(match key {
            "url" | "method" => {
                let text = if key == "url" {
                    &slots.url
                } else {
                    &slots.method
                };
                self.check_temporary_memory_budget(Self::estimate_string_bytes(text))?;
                Value::str(text.as_str())
            }
            "headers" => Value::Object(slots.headers),
            "signal" => Value::Object(slots.signal),
            "bodyUsed" => Value::Bool(slots.body_used),
            "redirect" => Value::str(match slots.redirect {
                FetchRedirectMode::Follow => "follow",
                FetchRedirectMode::Error => "error",
                FetchRedirectMode::Manual => "manual",
            }),
            "destination" | "referrerPolicy" | "integrity" => Value::str(""),
            "referrer" => Value::str("about:client"),
            "mode" => Value::str("cors"),
            "credentials" => Value::str("same-origin"),
            "cache" => Value::str("default"),
            "duplex" => Value::str("half"),
            "keepalive" | "isReloadNavigation" | "isHistoryNavigation" => Value::Bool(false),
            _ => return Err(fetch_type_error("a known Request getter")),
        })
    }

    fn clone_fetch_request(
        &mut self,
        id: ObjectId,
        label: &Label,
    ) -> Result<ObjectId, InterpreterError> {
        let slots = self.heap[id.0 as usize]
            .fetch_request_slots()
            .expect("validated Request");
        if slots.body_used {
            return Err(fetch_type_error("an unused Request body"));
        }
        let headers = slots.headers;
        let scratch = Self::estimate_host_object_slots_bytes(
            self.heap[id.0 as usize]
                .host_slots
                .as_deref()
                .expect("Request slots"),
        )
        .saturating_add(Self::estimate_host_object_slots_bytes(
            self.heap[headers.0 as usize]
                .host_slots
                .as_deref()
                .expect("Headers slots"),
        ));
        self.json_reserve_temporary(scratch)?;
        let result = (|| {
            self.fetch_charge_bytes(usize::try_from(scratch).unwrap_or(usize::MAX))?;
            self.json_observe_reachable_value(&Value::Object(id))?;
            let mut slots = self.heap[id.0 as usize]
                .fetch_request_slots()
                .expect("Request slots")
                .clone();
            let fields = self.heap[headers.0 as usize]
                .fetch_headers_slots()
                .expect("Headers slots")
                .fields
                .clone();
            slots.signal = self.alloc_fetch_dependent_signal(Some(slots.signal))?;
            let label = label.join(&self.json_parse_context_label()?);
            self.join_object_mutation_label(slots.signal, &label)?;
            let request = self.alloc_fetch_request(slots, fields, &label)?;
            self.gc_pin_network_values([Value::Object(request)]);
            self.join_into_pending_hostcall_result_label(Some(label))?;
            Ok(request)
        })();
        self.json_release_temporary(scratch);
        result
    }

    pub(in crate::baseline_interpreter) fn dispatch_fetch_request_method(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let method = builtin.display_name();
        if !REQUEST_METHODS.contains(&method) {
            return Err(fetch_type_error("a known Request method"));
        }
        let receiver = receiver.unwrap_or(Value::Undefined);
        let id = match &receiver {
            Value::Object(id)
                if self
                    .heap
                    .get(id.0 as usize)
                    .is_some_and(|object| object.fetch_request_slots().is_some()) =>
            {
                Some(*id)
            }
            _ => None,
        };
        let mut label = match id {
            Some(id) => self.fetch_receiver_label(id, args, receiver_register)?,
            None => self
                .join_arg_range_label(args)?
                .join(&self.json_parse_context_label()?),
        };
        if let Some(register) = receiver_register {
            label = label.join(self.get_register_label(register)?);
        }
        let mut owned_promise = None;
        let mut resolution_committed = false;
        let outcome = self.scoped_conversion(|core| {
            core.json_observe_label(label.clone())?;
            let pins = core.gc_pin_network_values([receiver.clone()]);
            let result = (|| {
                if method == "clone" {
                    let id = id.ok_or_else(|| fetch_type_error("a Request receiver"))?;
                    return core.clone_fetch_request(id, &label).map(Value::Object);
                }
                let promise = core.create_promise()?;
                owned_promise = Some(promise);
                core.gc_pin_network_values([Value::Promise(promise.0)]);
                let consumed = match id {
                    Some(id) => core.consume_fetch_body(id, method, &label),
                    None => Err(fetch_type_error("a Request receiver")),
                };
                let completed = core.complete_fetch_promise(Some(module), promise, consumed, label);
                resolution_committed = completed.is_ok();
                completed
            })();
            let result = core.finish_fetch_object_result(result);
            core.gc_unpin_network_values(pins);
            result
        });
        if outcome.is_err()
            && !resolution_committed
            && let Some(promise) = owned_promise
        {
            self.discard_unpublished_fetch_promise(promise)?;
        }
        outcome
    }
}
