//! Buffered Fetch over the existing authorized and journaled HTTP effect.
//!
//! Public buffered Response and Headers objects share authenticated native slots
//! with network responses. Redirects reuse the authorized, journaled request
//! path for each hop. Received Location and status carry the network source label,
//! so following requires the existing IFC policy to authorize the next sink.
//! Native Request objects share the same buffered body and authorization path.
//! Streaming bodies are not yet supported.
//! Request header values are restricted to ASCII because the shared native
//! sender frames String headers as UTF-8; received headers preserve Latin-1.
//! Fetch Standard: https://fetch.spec.whatwg.org/#body-mixin

use super::*;

mod objects;
mod request;

pub(super) use objects::FetchHeadersIteratorSlots;
pub(super) use request::{FetchRequestSlots, REQUEST_METHODS};

pub(super) enum NetworkRequestOutcome {
    Response(Vec<u8>),
    Unavailable,
    Denied,
    TransportFailure,
    JournalFailure(String),
    InvalidProviderResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum FetchRedirectMode {
    Follow,
    Error,
    Manual,
}

enum FetchResponseAction {
    Response(Value),
    Redirect {
        status: u16,
        url: Url,
        // Transfer this URL's temporary allocation admission to the loop.
        reserved_bytes: u64,
    },
}

pub(super) const RESPONSE_METHODS: [&str; 5] = ["text", "json", "arrayBuffer", "bytes", "clone"];
pub(super) const HEADERS_METHODS: [&str; 10] = [
    "get",
    "has",
    "getSetCookie",
    "append",
    "set",
    "delete",
    "entries",
    "keys",
    "values",
    "forEach",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FetchResponseSlots {
    pub status: u16,
    pub status_text: String,
    pub url: String,
    pub headers: ObjectId,
    // None is a null body. Some(empty) is an empty but consumable body.
    pub body: Option<Vec<u8>>,
    pub body_used: bool,
    #[serde(default)]
    pub redirected: bool,
    #[serde(default = "default_fetch_response_type")]
    pub response_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FetchHeadersSlots {
    // Retain every pair, including duplicate singleton fields and Set-Cookie.
    // Fetch lookup combines fields; Node IncomingMessage filtering does not.
    pub fields: Vec<(String, String)>,
    #[serde(default = "default_fetch_headers_immutable")]
    pub immutable: bool,
}

fn default_fetch_response_type() -> String {
    "basic".to_string()
}

fn default_fetch_headers_immutable() -> bool {
    true
}

impl BuiltinFunction {
    pub(super) fn fetch_response_method(name: &str) -> Option<Self> {
        RESPONSE_METHODS.contains(&name).then(|| Self {
            kind: BuiltinFunctionKind::FetchResponseMethod,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(name),
            iterator_handle: None,
            bound_object: None,
        })
    }

    pub(super) fn fetch_headers_method(name: &str) -> Option<Self> {
        HEADERS_METHODS.contains(&name).then(|| Self {
            kind: BuiltinFunctionKind::FetchHeadersMethod,
            module_specifier: BuiltinModuleSpecifier::from_nonempty(name),
            iterator_handle: None,
            bound_object: None,
        })
    }
}

impl HeapObject {
    pub(super) fn fetch_response_slots(&self) -> Option<&FetchResponseSlots> {
        match self.host_slots.as_deref() {
            Some(HostObjectSlots::FetchResponse(slots)) => Some(slots),
            _ => None,
        }
    }

    pub(super) fn fetch_headers_slots(&self) -> Option<&FetchHeadersSlots> {
        match self.host_slots.as_deref() {
            Some(HostObjectSlots::FetchHeaders(slots)) => Some(slots),
            _ => None,
        }
    }
}

fn fetch_type_error(message: &str) -> InterpreterError {
    InterpreterError::TypeError {
        expected: message.to_string(),
        got: "invalid Fetch input or response state".to_string(),
    }
}

fn http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'\x60'
                        | b'|'
                        | b'~'
                )
        })
}

impl InterpreterCore {
    pub(super) fn install_fetch_prototype_members(
        &mut self,
        owner: &str,
        prototype: ObjectId,
    ) -> Result<(), InterpreterError> {
        let methods: &[&str] = match owner {
            "Response" => &RESPONSE_METHODS,
            "Request" => &REQUEST_METHODS,
            "Headers" => &HEADERS_METHODS,
            _ => return Ok(()),
        };
        for name in methods {
            let method = match owner {
                "Response" => BuiltinFunction::fetch_response_method(name),
                "Request" => BuiltinFunction::fetch_request_method(name),
                _ => BuiltinFunction::fetch_headers_method(name),
            }
            .expect("closed Fetch method table");
            let key = RuntimePropertyKey::String(JsString::from(*name));
            self.set_object_runtime_property(
                prototype,
                key.clone(),
                Value::BuiltinFunction(method),
            )?;
            self.set_own_property_attributes(
                prototype,
                &key,
                PropertyAttributes {
                    writable: true,
                    enumerable: true,
                    configurable: true,
                },
            )?;
        }
        Ok(())
    }

    fn fetch_reserve(&mut self, scratch: &mut u64, bytes: u64) -> Result<(), InterpreterError> {
        self.json_reserve_temporary(bytes)?;
        *scratch = scratch.saturating_add(bytes);
        Ok(())
    }

    fn fetch_charge_bytes(&mut self, bytes: usize) -> Result<(), InterpreterError> {
        // Charge a small fixed cost even for empty fields/values.
        for _ in 0..bytes.div_ceil(64).max(1) {
            self.json_charge_work()?;
        }
        Ok(())
    }

    fn fetch_string(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
        scratch: &mut u64,
    ) -> Result<String, InterpreterError> {
        self.json_observe_reachable_value(&value)?;
        let text = self.conversion_to_string(module, value)?;
        // len() is allocation-free even for an unjoined rope. Admit its
        // projection and retained normalization copy before flattening it.
        self.fetch_reserve(
            scratch,
            (text.len() as u64)
                .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
                .saturating_mul(2),
        )?;
        let projection = text.as_utf8_projection();
        self.fetch_charge_bytes(projection.len())?;
        Ok(projection.to_string())
    }

    fn fetch_property(
        &mut self,
        module: Option<&Ir3Module>,
        object: &Value,
        name: &str,
    ) -> Result<Value, InterpreterError> {
        if matches!(object, Value::Undefined | Value::Null) {
            return Ok(Value::Undefined);
        }
        let module = module.ok_or_else(|| InterpreterError::InternalError {
            details: "Fetch option access requires its executing module".to_string(),
        })?;
        self.get_v(
            module,
            object,
            &RuntimePropertyKey::String(JsString::from(name)),
        )
    }

    fn fetch_request_headers(
        &mut self,
        module: Option<&Ir3Module>,
        input: Value,
        scratch: &mut u64,
    ) -> Result<Vec<(String, String)>, InterpreterError> {
        if matches!(input, Value::Undefined) {
            return Ok(Vec::new());
        }
        let module = module.ok_or_else(|| InterpreterError::InternalError {
            details: "Fetch header conversion requires its executing module".to_string(),
        })?;
        self.fetch_convert_headers_init(module, input, scratch)
    }

    fn normalize_fetch_body(
        &mut self,
        module: Option<&Ir3Module>,
        input: Value,
        scratch: &mut u64,
    ) -> Result<Value, InterpreterError> {
        if matches!(input, Value::Undefined | Value::Null) {
            return Ok(input);
        }
        if self.is_authenticated_readable_stream_body(module, &input)? {
            // BodyInit conversion must keep stream identity through the whole
            // init dictionary. Extraction below rejects this unsupported body
            // only after later getters have had their required effects.
            return Ok(input);
        }
        if let Value::Object(id) = &input {
            let object = self
                .heap
                .get(id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
            if object.blob.is_some()
                || object.typed_array.is_some()
                || object.data_view.is_some()
                || object.array_buffer.is_some()
                || self.url_search_params.contains_key(id)
            {
                // BodyInit keeps native identity through dictionary conversion.
                // Extract the current bytes only in Request steps, after later
                // dictionary getters have had their observable effects.
                self.json_observe_reachable_value(&input)?;
                return Ok(input);
            }
        }
        self.fetch_string(module, input, scratch).map(Value::str)
    }

    fn fetch_request_body(
        &mut self,
        module: Option<&Ir3Module>,
        input: Value,
        scratch: &mut u64,
    ) -> Result<(Option<Vec<u8>>, Option<String>), InterpreterError> {
        if matches!(input, Value::Undefined | Value::Null) {
            return Ok((None, None));
        }
        self.json_observe_reachable_value(&input)?;
        if self.is_authenticated_readable_stream_body(module, &input)? {
            return Err(fetch_type_error(
                "a buffered Fetch body (ReadableStream bodies are not supported)",
            ));
        }
        if let Value::Object(id) = &input {
            if let Some(state) = self.url_search_params.get(id) {
                // Fetch 5.2, extract step 10: serialize the native list, without
                // invoking an overridden stringifier or iterator. Reachable
                // ordinary-property labels do not include this side-table state.
                let label = self.clone_dominant_label_with_temporary_budget(
                    &state.lifecycle_label,
                    &Label::Public,
                    0,
                )?;
                self.json_observe_label(label)?;
                self.json_charge_work()?;
                let pair_count = self.url_search_params[id].pairs.len();
                for index in 0..pair_count {
                    let (name, value) = &self.url_search_params[id].pairs[index];
                    let encoded_bytes = name
                        .len()
                        .saturating_add(value.len())
                        .saturating_mul(3)
                        .saturating_add(2);
                    self.fetch_charge_bytes(encoded_bytes)?;
                }
                const CONTENT_TYPE: &str = "application/x-www-form-urlencoded;charset=UTF-8";
                let serialized_bound =
                    Self::url_serialization_upper_bound(&self.url_search_params[id].pairs);
                // Include the serializer's old/new String allocation peak.
                // into_bytes transfers that allocation without another copy.
                self.fetch_reserve(
                    scratch,
                    serialized_bound
                        .saturating_mul(3)
                        .saturating_add(Self::estimate_string_bytes(CONTENT_TYPE)),
                )?;
                let serialized =
                    Self::serialize_url_search_params(&self.url_search_params[id].pairs);
                return Ok((
                    Some(serialized.into_bytes()),
                    Some(CONTENT_TYPE.to_string()),
                ));
            }
            let object = self
                .heap
                .get(id.0 as usize)
                .ok_or(InterpreterError::ObjectNotFound { id: id.0 })?;
            if let Some(blob) = &object.blob {
                let bytes = blob.bytes.len() as u64;
                let type_bytes = Self::estimate_string_bytes(&blob.content_type);
                self.fetch_reserve(scratch, bytes.saturating_add(type_bytes))?;
                let blob = self.heap[id.0 as usize]
                    .blob
                    .as_ref()
                    .expect("blob remains rooted");
                return Ok((
                    Some(blob.bytes.clone()),
                    (!blob.content_type.is_empty()).then(|| blob.content_type.clone()),
                ));
            }
            let length = if let Some(view) = &object.typed_array {
                Some(view.byte_length)
            } else if let Some(view) = &object.data_view {
                Some(view.byte_length)
            } else {
                object
                    .array_buffer
                    .as_ref()
                    .map(|backing| backing.bytes.len())
            };
            if let Some(length) = length {
                self.fetch_reserve(scratch, length as u64)?;
                if let Some(label) = self.binary_storage_label_ref(*id).cloned() {
                    self.json_observe_label(label)?;
                }
                return Ok((Some(self.text_codec_input_bytes(&input)?), None));
            }
        }
        let text = self.fetch_string(module, input, scratch)?;
        self.fetch_reserve(scratch, text.len() as u64)?;
        Ok((
            Some(text.into_bytes()),
            Some("text/plain;charset=UTF-8".to_string()),
        ))
    }

    /// IR and first-class calls have already checked the operation gate.
    /// Conversion hooks can introduce new data, so concrete request provenance
    /// is checked again after conversion and immediately before egress.
    pub(super) fn dispatch_fetch_hostcall(
        &mut self,
        module: Option<&Ir3Module>,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        self.check_host_io_confidentiality("net:request", args)?;
        let inputs = self.join_arg_range_label(args)?;
        self.gc_enter_builtin();
        let mut owned_promise = None;
        let mut resolution_committed = false;
        let outcome = self.scoped_conversion(|core| {
            core.json_observe_label(inputs)?;
            let promise = core.create_promise()?;
            owned_promise = Some(promise);
            let pins = core.gc_pin_network_values([Value::Promise(promise.0)]);
            let mut scratch = 0;
            let completed = (|| {
                let request_result = (|| {
                    if args.count == 0 {
                        return Err(fetch_type_error("the required Fetch input"));
                    }
                    let input = core.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                    let init = core.builtin_arg(args, 1)?.unwrap_or(Value::Undefined);
                    let request = core.prepare_fetch_request(module, input, init, &mut scratch)?;
                    core.gc_pin_network_values([Value::Object(request)]);
                    core.send_fetch_request_object(request, &mut scratch)
                })();
                let label = core.json_parse_context_label()?.join(&Label::Internal);
                core.complete_fetch_promise(module, promise, request_result, label)
            })();
            core.json_release_temporary(scratch);
            core.gc_unpin_network_values(pins);
            resolution_committed = completed.is_ok();
            completed
        });
        let cleanup = if outcome.is_err() && !resolution_committed {
            owned_promise.map_or(Ok(()), |promise| {
                self.discard_unpublished_fetch_promise(promise)
            })
        } else {
            Ok(())
        };
        self.gc_exit_builtin();
        cleanup?;
        outcome
    }

    /// Snapshot native Request state after all observable conversions. Guest
    /// properties such as `url`, `headers` and `signal` cannot forge these
    /// authenticated slots or hide the labels on their retained children.
    fn send_fetch_request_object(
        &mut self,
        request: ObjectId,
        scratch: &mut u64,
    ) -> Result<Value, InterpreterError> {
        self.json_observe_reachable_value(&Value::Object(request))?;
        let slots = self.heap[request.0 as usize]
            .fetch_request_slots()
            .ok_or_else(|| fetch_type_error("a Request receiver"))?;
        let signal = slots.signal;
        self.check_fetch_abort_signal(signal)?;
        let object = &self.heap[request.0 as usize];
        let slots = object.fetch_request_slots().expect("authenticated Request");
        if slots.body_used {
            return Err(fetch_type_error("an unused Request body"));
        }
        let headers_id = slots.headers;
        let bytes = Self::estimate_host_object_slots_bytes(
            object.host_slots.as_deref().expect("Request slots"),
        )
        .saturating_add(Self::estimate_host_object_slots_bytes(
            self.heap[headers_id.0 as usize]
                .host_slots
                .as_deref()
                .ok_or_else(|| fetch_type_error("native Request headers"))?,
        ))
        .saturating_add((slots.url.len() as u64).saturating_mul(6))
        .saturating_add(1024);
        self.fetch_reserve(scratch, bytes)?;
        self.fetch_charge_bytes(usize::try_from(bytes).unwrap_or(usize::MAX))?;
        let slots = self.heap[request.0 as usize]
            .fetch_request_slots()
            .expect("authenticated Request");
        let mut url = Url::parse(&slots.url)
            .map_err(|_| fetch_type_error("an absolute HTTP or HTTPS URL"))?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(fetch_type_error(
                "an HTTP or HTTPS URL without embedded credentials",
            ));
        }
        url.set_fragment(None);
        let method = slots.method.clone();
        let redirect = slots.redirect;
        let headers = self.heap[headers_id.0 as usize]
            .fetch_headers_slots()
            .ok_or_else(|| fetch_type_error("native Request headers"))?;
        if headers.fields.iter().any(|(_, value)| !value.is_ascii()) {
            return Err(fetch_type_error(
                "ASCII request header values (Latin-1 wire values are not supported)",
            ));
        }
        let headers = headers.fields.clone();
        let label = self.json_parse_context_label()?;
        self.join_object_mutation_label(request, &label)?;
        let mut body = None;
        self.mutate_heap(|heap| {
            if let Some(HostObjectSlots::FetchRequest(slots)) =
                heap[request.0 as usize].host_slots.as_deref_mut()
                && let Some(bytes) = slots.body.as_mut()
            {
                slots.body_used = true;
                body = Some(std::mem::take(bytes));
            }
        });
        self.apply_memory_component_delta(body.as_ref().map_or(0, |bytes| bytes.len() as u64), 0)?;
        self.perform_fetch_request(url, method, headers, body, redirect, signal)
    }

    fn check_fetch_abort_signal(&mut self, signal: ObjectId) -> Result<(), InterpreterError> {
        self.json_observe_reachable_value(&Value::Object(signal))?;
        let slots = self
            .heap
            .get(signal.0 as usize)
            .and_then(HeapObject::abort_signal_slots)
            .ok_or_else(|| InterpreterError::InternalError {
                details: "Request lost its native AbortSignal".to_string(),
            })?;
        if !slots.aborted {
            return Ok(());
        }
        let bytes = Self::estimate_execution_seed_value_bytes(&slots.reason);
        self.json_reserve_temporary(bytes)?;
        let outcome = (|| {
            let reason = self.heap[signal.0 as usize]
                .abort_signal_slots()
                .expect("authenticated AbortSignal")
                .reason
                .clone();
            let label = self.json_parse_context_label()?;
            Err(self.throw_guest_value(reason, label)?)
        })();
        self.json_release_temporary(bytes);
        outcome
    }

    fn discard_unpublished_fetch_promise(
        &mut self,
        promise: crate::promise_model::PromiseHandle,
    ) -> Result<(), InterpreterError> {
        if matches!(
            self.promise_state(promise.0),
            Some(crate::promise_model::PromiseState::Pending)
        ) {
            // Conversion/then getters may have allocated later guest Promises.
            // Only the Fetch-owned, still-unpublished pending record is removed.
            self.remove_pending_promise_at_execution_boundary(promise)?;
        }
        Ok(())
    }

    fn complete_fetch_promise(
        &mut self,
        module: Option<&Ir3Module>,
        promise: crate::promise_model::PromiseHandle,
        result: Result<Value, InterpreterError>,
        label: Label,
    ) -> Result<Value, InterpreterError> {
        let label = label.join(&self.json_parse_context_label()?);
        self.join_into_pending_hostcall_result_label(Some(label.clone()))?;
        match result {
            Ok(value) => self.resolve_promise_with_value(module, promise, value, label)?,
            Err(error) => {
                // This helper refuses capability/IFC/resource/cancellation
                // failures. Only JavaScript completions become rejections.
                let (thrown, exception_label) = self.catchable_thrown_value(error)?;
                let label = label
                    .join(&exception_label)
                    .join(&self.json_parse_context_label()?);
                self.join_into_pending_hostcall_result_label(Some(label.clone()))?;
                let reason = self.promise_value(&thrown)?;
                self.reject_promise(promise, reason, label)?;
            }
        }
        Ok(Value::Promise(promise.0))
    }

    /// Keep each redirect inside the same live authority, IFC, resource and
    /// effect-recording boundaries as an explicit request. No received bytes
    /// become a Public URL merely because the transport supplied a redirect.
    fn perform_fetch_request(
        &mut self,
        mut url: Url,
        mut method: String,
        mut headers: Vec<(String, String)>,
        mut body: Option<Vec<u8>>,
        redirect: FetchRedirectMode,
        signal: ObjectId,
    ) -> Result<Value, InterpreterError> {
        let mut redirect_count = 0u8;
        let mut url_reserved_bytes = 0;
        let result = (|| {
            loop {
                let mut scratch = 0;
                let hop = (|| {
                    self.json_charge_work()?;
                    self.check_fetch_abort_signal(signal)?;
                    // Argument conversion can execute guest code after the
                    // outer dispatch gate. Recheck that decision at egress,
                    // including the initial request.
                    check_hostcall_capability_gate(self, "net:request", self.ip as u32)?;
                    let request_bytes = Self::estimate_string_bytes(url.as_str())
                        .saturating_add(Self::estimate_string_bytes(&method))
                        .saturating_add(
                            (headers.len() as u64).saturating_mul(std::mem::size_of::<(
                                String,
                                String,
                            )>()
                                as u64),
                        )
                        .saturating_add(Self::saturating_sum(headers.iter().map(
                            |(name, value)| {
                                Self::estimate_string_bytes(name)
                                    .saturating_add(Self::estimate_string_bytes(value))
                            },
                        )))
                        .saturating_add(body.as_ref().map_or(0, |bytes| bytes.len() as u64));
                    self.fetch_reserve(&mut scratch, request_bytes)?;
                    self.fetch_charge_bytes(usize::try_from(request_bytes).unwrap_or(usize::MAX))?;
                    let request_label = self.json_parse_context_label()?;
                    if let Err(error) = self.evaluate_sink_flow_decision(
                        "net:request",
                        &request_label,
                        &Label::Public,
                    ) {
                        // Conversion hooks can introduce private data after
                        // the outer argument check, including on the first hop.
                        // Bind every concrete refusal to the exact request.
                        if self.host_effect_journal.is_some() || self.host_io_recorder.is_some() {
                            self.record_deferred_network_ifc_denial(
                                url.as_str(),
                                &method,
                                &headers,
                                body.as_deref(),
                            )?;
                        }
                        return Err(error);
                    }
                    let response_label =
                        hostcall_result_contract("net:fetch").result_label(&request_label, None);
                    let outcome = self.perform_net_request_bytes(
                        url.as_str().to_string(),
                        method.clone(),
                        headers.clone(),
                        body.clone(),
                    )?;
                    self.json_observe_label(response_label.clone())?;
                    let bytes = match outcome {
                        NetworkRequestOutcome::Response(bytes) => bytes,
                        NetworkRequestOutcome::Unavailable
                        | NetworkRequestOutcome::TransportFailure => {
                            return Err(fetch_type_error("a successful network response"));
                        }
                        NetworkRequestOutcome::Denied => {
                            return Err(InterpreterError::CapabilityDenied {
                                capability: "net:request".to_string(),
                            });
                        }
                        NetworkRequestOutcome::JournalFailure(details) => {
                            return Err(InterpreterError::InternalError {
                                details: format!("Fetch host-effect journal failed: {details}"),
                            });
                        }
                        NetworkRequestOutcome::InvalidProviderResult => {
                            return Err(InterpreterError::InternalError {
                                details: "Fetch provider returned an incompatible response kind"
                                    .to_string(),
                            });
                        }
                    };
                    self.fetch_reserve(&mut scratch, bytes.len() as u64)?;
                    match self.build_fetch_response(
                        &bytes,
                        &method,
                        &url,
                        redirect,
                        redirect_count,
                        &response_label,
                    )? {
                        FetchResponseAction::Response(value) => Ok(Some(value)),
                        FetchResponseAction::Redirect {
                            status,
                            url: next_url,
                            reserved_bytes,
                        } => {
                            // URL parsing has already normalized host casing,
                            // IDNA and default ports. Compare without allocating
                            // another owned origin while staging the next hop.
                            let cross_origin = url.scheme() != next_url.scheme()
                                || url.host_str() != next_url.host_str()
                                || url.port_or_known_default() != next_url.port_or_known_default();
                            url = next_url;
                            self.json_release_temporary(url_reserved_bytes);
                            url_reserved_bytes = reserved_bytes;
                            if cross_origin {
                                headers.retain(|(name, _)| {
                                    !matches!(
                                        name.as_str(),
                                        "authorization"
                                            | "proxy-authorization"
                                            | "cookie"
                                            | "cookie2"
                                            | "host"
                                    )
                                });
                            }
                            if (matches!(status, 301 | 302) && method == "POST")
                                || (status == 303 && !matches!(method.as_str(), "GET" | "HEAD"))
                            {
                                self.fetch_reserve(
                                    &mut scratch,
                                    Self::estimate_string_bytes("GET"),
                                )?;
                                method = "GET".to_string();
                                body = None;
                                // This server surface accepts caller-supplied
                                // framing fields; they must not outlive a body
                                // any more than Fetch's body metadata does.
                                headers.retain(|(name, _)| {
                                    !matches!(
                                        name.as_str(),
                                        "content-encoding"
                                            | "content-language"
                                            | "content-location"
                                            | "content-type"
                                            | "content-length"
                                            | "transfer-encoding"
                                    )
                                });
                            }
                            redirect_count += 1;
                            Ok(None)
                        }
                    }
                })();
                self.json_release_temporary(scratch);
                if let Some(value) = hop? {
                    return Ok(value);
                }
            }
        })();
        self.json_release_temporary(url_reserved_bytes);
        result
    }

    fn build_fetch_response(
        &mut self,
        raw: &[u8],
        method: &str,
        url: &Url,
        redirect: FetchRedirectMode,
        redirect_count: u8,
        label: &Label,
    ) -> Result<FetchResponseAction, InterpreterError> {
        use frankenengine_extension_host::host_io::{
            SANDBOXED_HOST_IO_MAX_BYTES, parse_http_response,
        };
        if raw.len() as u64 > SANDBOXED_HOST_IO_MAX_BYTES {
            return Err(InterpreterError::InternalError {
                details: "Fetch provider response exceeds its bounded byte contract".to_string(),
            });
        }
        let parsed = parse_http_response(raw, method)
            .map_err(|_| fetch_type_error("a complete, valid HTTP response"))?;
        // Latin-1 headers can expand to two UTF-8 bytes. Admit native staging
        // before copying. The payload uses the shared HTTP framing parser.
        let mut scratch = (raw.len() as u64).saturating_mul(4).saturating_add(
            (parsed.header_count() as u64)
                .saturating_mul(std::mem::size_of::<(String, String)>() as u64),
        );
        self.json_reserve_temporary(scratch)?;
        let mut retained_scratch = 0;
        let result = (|| {
            self.fetch_charge_bytes(raw.len())?;
            let status = parsed.status;
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                match redirect {
                    FetchRedirectMode::Error => {
                        return Err(fetch_type_error("a response without an HTTP redirect"));
                    }
                    // As in server Fetch, expose the actual response, including
                    // Location and body, for callers handling redirects manually.
                    FetchRedirectMode::Manual => {}
                    FetchRedirectMode::Follow => {
                        let mut locations = parsed
                            .headers()
                            .filter(|(name, _)| name.eq_ignore_ascii_case(b"location"));
                        if let Some((_, location)) = locations.next() {
                            if locations.next().is_some() {
                                return Err(fetch_type_error("one unambiguous Location header"));
                            }
                            self.fetch_reserve(
                                &mut scratch,
                                (location.len() as u64)
                                    .saturating_add(url.as_str().len() as u64)
                                    .saturating_mul(8)
                                    .saturating_add(1024),
                            )?;
                            let location: String =
                                location.iter().map(|byte| char::from(*byte)).collect();
                            let mut next_url = url
                                .join(&location)
                                .map_err(|_| fetch_type_error("a valid redirect Location URL"))?;
                            if !matches!(next_url.scheme(), "http" | "https")
                                || !next_url.username().is_empty()
                                || next_url.password().is_some()
                            {
                                return Err(fetch_type_error(
                                    "an HTTP or HTTPS redirect without embedded credentials",
                                ));
                            }
                            if redirect_count == 20 {
                                return Err(fetch_type_error("at most 20 HTTP redirects"));
                            }
                            // Removing a fragment truncates URL text but does
                            // not shrink its backing String. Retain admission
                            // for the pre-truncation allocation and its growth.
                            let reserved_bytes =
                                Self::estimate_string_bytes(next_url.as_str()).saturating_mul(2);
                            next_url.set_fragment(None);
                            self.fetch_reserve(&mut scratch, reserved_bytes)?;
                            retained_scratch = reserved_bytes;
                            return Ok(FetchResponseAction::Redirect {
                                status,
                                url: next_url,
                                reserved_bytes,
                            });
                        }
                    }
                }
            }
            let mut fields = Vec::with_capacity(parsed.header_count());
            for (name, value) in parsed.headers() {
                self.fetch_charge_bytes(name.len().saturating_add(value.len()))?;
                fields.push((
                    name.iter()
                        .map(|byte| char::from(*byte).to_ascii_lowercase())
                        .collect::<String>(),
                    value
                        .iter()
                        .map(|byte| char::from(*byte))
                        .collect::<String>(),
                ));
            }
            let status_text = parsed
                .status_text
                .iter()
                .map(|byte| char::from(*byte))
                .collect();
            let body = if method == "HEAD" || matches!(status, 101 | 103 | 204 | 205 | 304) {
                None
            } else {
                Some(
                    parsed
                        .body_bytes()
                        .map_err(|_| fetch_type_error("a complete HTTP body"))?
                        .into_owned(),
                )
            };
            self.alloc_fetch_response(
                FetchResponseSlots {
                    status,
                    status_text,
                    url: url.as_str().to_string(),
                    headers: ObjectId(0),
                    body,
                    body_used: false,
                    redirected: redirect_count != 0,
                    response_type: default_fetch_response_type(),
                },
                fields,
                true,
                label,
            )
            .map(|id| FetchResponseAction::Response(Value::Object(id)))
        })();
        self.json_release_temporary(scratch.saturating_sub(retained_scratch));
        result
    }

    fn alloc_fetch_response(
        &mut self,
        mut slots: FetchResponseSlots,
        fields: Vec<(String, String)>,
        immutable: bool,
        label: &Label,
    ) -> Result<ObjectId, InterpreterError> {
        let headers_prototype = self.ensure_builtin_prototype("Headers")?;
        let headers = self.alloc_object_with_prototype(Some(headers_prototype))?;
        self.set_host_slots(
            headers,
            HostObjectSlots::FetchHeaders(FetchHeadersSlots { fields, immutable }),
        )?;
        self.join_object_mutation_label(headers, label)?;
        let pins = self.gc_pin_network_values([Value::Object(headers)]);
        let result = (|| {
            let prototype = self.ensure_builtin_prototype("Response")?;
            let response = self.alloc_object_with_prototype(Some(prototype))?;
            slots.headers = headers;
            self.set_host_slots(response, HostObjectSlots::FetchResponse(slots))?;
            self.join_object_mutation_label(response, label)?;
            Ok(response)
        })();
        self.gc_unpin_network_values(pins);
        result
    }

    pub(super) fn fetch_response_getter(
        &mut self,
        id: ObjectId,
        key: &str,
    ) -> Result<Value, InterpreterError> {
        let slots = self
            .heap
            .get(id.0 as usize)
            .and_then(HeapObject::fetch_response_slots)
            .ok_or_else(|| fetch_type_error("a Response receiver"))?;
        Ok(match key {
            "status" => Value::Int(i64::from(slots.status)),
            "statusText" => {
                self.check_temporary_memory_budget(Self::estimate_string_bytes(
                    &slots.status_text,
                ))?;
                Value::str(slots.status_text.as_str())
            }
            "url" => {
                self.check_temporary_memory_budget(Self::estimate_string_bytes(&slots.url))?;
                Value::str(slots.url.as_str())
            }
            "ok" => Value::Bool((200..300).contains(&slots.status)),
            "headers" => Value::Object(slots.headers),
            "bodyUsed" => Value::Bool(slots.body_used),
            "redirected" => Value::Bool(slots.redirected),
            "type" => {
                self.check_temporary_memory_budget(Self::estimate_string_bytes(
                    &slots.response_type,
                ))?;
                Value::str(slots.response_type.as_str())
            }
            _ => return Err(fetch_type_error("a known Response getter")),
        })
    }

    fn fetch_receiver_label(
        &self,
        id: ObjectId,
        args: RegRange,
        receiver_register: Option<u32>,
    ) -> Result<Label, InterpreterError> {
        let mut label = self
            .join_arg_range_label(args)?
            .join(&self.json_parse_context_label()?);
        if let Some(register) = receiver_register {
            label = label.join(self.get_register_label(register)?);
        }
        if let Some(stored) = self.object_mutation_labels.get(&id) {
            label = label.join(stored);
        }
        Ok(label)
    }

    pub(super) fn dispatch_fetch_response_method(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let method = builtin.display_name();
        if !RESPONSE_METHODS.contains(&method) {
            return Err(fetch_type_error("a known Response method"));
        }
        let receiver = receiver.unwrap_or(Value::Undefined);
        let id = match &receiver {
            Value::Object(id)
                if self
                    .heap
                    .get(id.0 as usize)
                    .and_then(HeapObject::fetch_response_slots)
                    .is_some() =>
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
                    let id = id.ok_or_else(|| fetch_type_error("a Response receiver"))?;
                    return core.clone_fetch_response(id, &label).map(Value::Object);
                }
                let promise = core.create_promise()?;
                owned_promise = Some(promise);
                core.gc_pin_network_values([Value::Promise(promise.0)]);
                let consumed = match id {
                    Some(id) => core.consume_fetch_body(id, method, &label),
                    None => Err(fetch_type_error("a Response receiver")),
                };
                let completed = core.complete_fetch_promise(Some(module), promise, consumed, label);
                resolution_committed = completed.is_ok();
                completed
            })();
            // clone() fails synchronously. Seal the observed body state into
            // its exception before the conversion scope restores its caller.
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

    fn consume_fetch_body(
        &mut self,
        id: ObjectId,
        method: &str,
        label: &Label,
    ) -> Result<Value, InterpreterError> {
        let (body, body_used) = match self.heap[id.0 as usize].host_slots.as_deref() {
            Some(HostObjectSlots::FetchResponse(slots)) => (&slots.body, slots.body_used),
            Some(HostObjectSlots::FetchRequest(slots)) => (&slots.body, slots.body_used),
            _ => return Err(fetch_type_error("a Request or Response body")),
        };
        if body_used {
            return Err(fetch_type_error("an unused Request or Response body"));
        }
        let has_body = body.is_some();
        let length = body.as_ref().map_or(0, Vec::len);
        // Admission precedes disturbance. Move, do not clone, the retained
        // buffer into charged scratch for the duration of conversion.
        self.json_reserve_temporary(length as u64)?;
        let mut bytes = Vec::new();
        let outcome = (|| {
            if has_body {
                // Consumption is an observable mutation even when the body is
                // empty. A private receiver/control decision taints bodyUsed.
                let existing_label_bytes = self
                    .object_mutation_labels
                    .get(&id)
                    .map_or(0, Self::estimate_label_bytes);
                self.check_temporary_memory_budget(
                    existing_label_bytes.saturating_add(Self::estimate_label_bytes(label)),
                )?;
                self.join_object_mutation_label(id, label)?;
            }
            self.mutate_heap(|heap| {
                let (body, used) = match heap[id.0 as usize].host_slots.as_deref_mut() {
                    Some(HostObjectSlots::FetchResponse(slots)) => {
                        (&mut slots.body, &mut slots.body_used)
                    }
                    Some(HostObjectSlots::FetchRequest(slots)) => {
                        (&mut slots.body, &mut slots.body_used)
                    }
                    _ => unreachable!("validated native Fetch body"),
                };
                if let Some(body) = body.as_mut() {
                    *used = true;
                    bytes = std::mem::take(body);
                }
            });
            self.apply_memory_component_delta(length as u64, 0)?;
            for _ in 0..bytes.len().div_ceil(64) {
                self.json_charge_work()?;
            }
            if matches!(method, "arrayBuffer" | "bytes") {
                let buffer = if method == "bytes" {
                    self.alloc_uint8_array_from_bytes(&bytes)?
                } else {
                    let buffer = self.alloc_array_buffer_object(bytes.len())?;
                    self.with_array_buffer_bytes_mut(buffer, |backing| {
                        backing.copy_from_slice(&bytes)
                    })?;
                    buffer
                };
                self.join_object_mutation_label(buffer, label)?;
                self.join_binary_storage_label(buffer, label)?;
                // A byte view also exposes its backing ArrayBuffer. Preserve
                // provenance on both objects, including an empty result.
                let backing = self.heap[buffer.0 as usize]
                    .typed_array
                    .as_deref()
                    .map(|view| view.buffer);
                if let Some(backing) = backing {
                    self.join_object_mutation_label(backing, label)?;
                }
                return Ok(Value::Object(buffer));
            }
            // The existing native module-data parser removes one leading BOM.
            // Pass it the original decoded text; text() removes that BOM here.
            let decoded = if method == "json" {
                bytes.as_slice()
            } else {
                bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes)
            };
            let (utf8, utf16) =
                decoded
                    .utf8_chunks()
                    .fold((0usize, 0usize), |(utf8, utf16), chunk| {
                        let replacement = usize::from(!chunk.invalid().is_empty());
                        (
                            utf8.saturating_add(chunk.valid().len())
                                .saturating_add(3 * replacement),
                            utf16
                                .saturating_add(chunk.valid().encode_utf16().count())
                                .saturating_add(replacement),
                        )
                    });
            self.check_string_limit(utf16)?;
            let text_copies = if method == "json" { 1 } else { 2 };
            let text_scratch = (utf8 as u64)
                .saturating_add(MEMORY_ESTIMATE_STRING_BASE_BYTES)
                .saturating_mul(text_copies);
            self.json_reserve_temporary(text_scratch)?;
            let result = (|| {
                let text = String::from_utf8_lossy(decoded);
                if method == "json" {
                    self.json_parse_module_source(&text)
                } else {
                    Ok(Value::str(text.into_owned()))
                }
            })();
            self.json_release_temporary(text_scratch);
            result
        })();
        drop(bytes);
        self.json_release_temporary(length as u64);
        outcome
    }

    fn clone_fetch_response(
        &mut self,
        id: ObjectId,
        label: &Label,
    ) -> Result<ObjectId, InterpreterError> {
        // Headers can have been classified by a later mutation without
        // changing the Response receiver's earlier label.
        self.json_observe_reachable_value(&Value::Object(id))?;
        let object = &self.heap[id.0 as usize];
        let slots = object.fetch_response_slots().expect("validated response");
        if slots.body_used {
            return Err(fetch_type_error("an unused Response body"));
        }
        let headers = slots.headers;
        let response_bytes = Self::estimate_host_object_slots_bytes(
            object.host_slots.as_deref().expect("response slots"),
        );
        let header_bytes = Self::estimate_host_object_slots_bytes(
            self.heap[headers.0 as usize]
                .host_slots
                .as_deref()
                .expect("header slots"),
        );
        let scratch = response_bytes.saturating_add(header_bytes);
        self.json_reserve_temporary(scratch)?;
        let result = (|| {
            self.fetch_charge_bytes(usize::try_from(scratch).unwrap_or(usize::MAX))?;
            let slots = self.heap[id.0 as usize]
                .fetch_response_slots()
                .expect("response slots")
                .clone();
            let fields = self.heap[headers.0 as usize]
                .fetch_headers_slots()
                .expect("header slots")
                .fields
                .clone();
            let immutable = self.heap[headers.0 as usize]
                .fetch_headers_slots()
                .expect("header slots")
                .immutable;
            let observed = self.json_parse_context_label()?;
            let label = self.clone_dominant_label_with_temporary_budget(label, &observed, 0)?;
            self.alloc_fetch_response(slots, fields, immutable, &label)
        })();
        self.json_release_temporary(scratch);
        result
    }

    pub(super) fn dispatch_fetch_headers_method(
        &mut self,
        module: &Ir3Module,
        builtin: &BuiltinFunction,
        args: RegRange,
        receiver: Option<Value>,
        receiver_register: Option<u32>,
    ) -> Result<Value, InterpreterError> {
        let method = builtin.display_name();
        if !HEADERS_METHODS.contains(&method) {
            return Err(fetch_type_error("a known Headers method"));
        }
        let Some(Value::Object(id)) = receiver else {
            return Err(fetch_type_error("a Headers receiver"));
        };
        if self
            .heap
            .get(id.0 as usize)
            .and_then(HeapObject::fetch_headers_slots)
            .is_none()
        {
            return Err(fetch_type_error("a Headers receiver"));
        }
        let label = self.fetch_receiver_label(id, args, receiver_register)?;
        self.scoped_conversion(|core| {
            core.json_observe_label(label)?;
            let mut scratch = 0;
            let result = (|| {
                let name = if method == "getSetCookie" {
                    "set-cookie".to_string()
                } else {
                    let value = core.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
                    core.fetch_string(Some(module), value, &mut scratch)?
                };
                if !http_token(&name) {
                    return Err(fetch_type_error("a valid HTTP header name"));
                }
                let field_count = core.heap[id.0 as usize]
                    .fetch_headers_slots()
                    .expect("validated headers")
                    .fields
                    .len();
                let mut count = 0usize;
                let mut bytes = 0u64;
                for index in 0..field_count {
                    let (matches, field_bytes, value_bytes) = {
                        let (key, value) = &core.heap[id.0 as usize]
                            .fetch_headers_slots()
                            .expect("validated headers")
                            .fields[index];
                        (
                            key.eq_ignore_ascii_case(&name),
                            key.len().saturating_add(value.len()),
                            Self::estimate_string_bytes(value),
                        )
                    };
                    core.fetch_charge_bytes(field_bytes)?;
                    if matches {
                        if method == "has" {
                            return Ok(Value::Bool(true));
                        }
                        count += 1;
                        bytes = bytes.saturating_add(value_bytes);
                    }
                }
                if method == "has" {
                    return Ok(Value::Bool(false));
                }
                core.fetch_reserve(
                    &mut scratch,
                    bytes
                        .saturating_mul(2)
                        .saturating_add((count as u64).saturating_mul(64)),
                )?;
                let mut values =
                    Vec::with_capacity(if method == "getSetCookie" { count } else { 0 });
                let mut output = String::new();
                let mut matched = 0usize;
                for index in 0..field_count {
                    let (matches, field_bytes) = {
                        let (key, value) = &core.heap[id.0 as usize]
                            .fetch_headers_slots()
                            .expect("validated headers")
                            .fields[index];
                        (
                            key.eq_ignore_ascii_case(&name),
                            key.len().saturating_add(value.len()),
                        )
                    };
                    core.fetch_charge_bytes(field_bytes)?;
                    if !matches {
                        continue;
                    }
                    let value = &core.heap[id.0 as usize]
                        .fetch_headers_slots()
                        .expect("validated headers")
                        .fields[index]
                        .1;
                    if method == "getSetCookie" {
                        values.push(Value::str(value.as_str()));
                    } else {
                        if matched > 0 {
                            output.push_str(", ");
                        }
                        output.push_str(value);
                    }
                    matched += 1;
                }
                if method == "getSetCookie" {
                    let array = core.alloc_array_from_values(&values)?;
                    let label = core.json_parse_context_label()?;
                    core.join_object_mutation_label(array, &label)?;
                    return Ok(Value::Object(array));
                }
                if count == 0 {
                    return Ok(Value::Null);
                }
                core.check_string_limit(output.encode_utf16().count())?;
                Ok(Value::str(output))
            })();
            let result = core.finish_fetch_object_result(result);
            core.json_release_temporary(scratch);
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::NetworkEgress,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "fetch-private-state")
    }

    fn response(core: &mut InterpreterCore, body: Option<Vec<u8>>) -> ObjectId {
        core.alloc_fetch_response(
            FetchResponseSlots {
                status: 200,
                status_text: "OK".into(),
                url: "http://example.test/".into(),
                headers: ObjectId(0),
                body,
                body_used: false,
                redirected: false,
                response_type: default_fetch_response_type(),
            },
            vec![("x-test".into(), "kept alive".into())],
            true,
            &Label::Public,
        )
        .unwrap()
    }

    fn module(source: &str) -> Ir3Module {
        use crate::ast::ParseGoal;
        use crate::ir_contract::Ir0Module;
        use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
        use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "fetch-private.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .unwrap();
        lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "fetch-private.js"),
            &LoweringContext::new("fetch-private", "decision", "policy"),
        )
        .unwrap()
        .ir3
    }

    fn assert_balanced(core: &InterpreterCore) {
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }

    #[test]
    fn body_consumption_and_binary_backing_keep_private_selection_provenance() {
        let mut core = core();
        let original = response(&mut core, Some(vec![0, 255, 239, 187, 191]));
        let copy = core.clone_fetch_response(original, &Label::Public).unwrap();
        let Value::Object(buffer) = core
            .consume_fetch_body(original, "arrayBuffer", &Label::Secret)
            .unwrap()
        else {
            panic!("ArrayBuffer result");
        };
        assert_eq!(
            core.text_codec_input_bytes(&Value::Object(buffer)).unwrap(),
            [0, 255, 239, 187, 191]
        );
        assert_eq!(core.binary_storage_label_ref(buffer), Some(&Label::Secret));
        assert_eq!(
            core.object_mutation_labels.get(&original),
            Some(&Label::Secret)
        );
        assert_eq!(
            core.fetch_response_getter(original, "bodyUsed").unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            core.fetch_response_getter(copy, "bodyUsed").unwrap(),
            Value::Bool(false)
        );
        assert_eq!(
            core.heap[copy.0 as usize]
                .fetch_response_slots()
                .unwrap()
                .body
                .as_deref(),
            Some([0, 255, 239, 187, 191].as_slice())
        );
        assert_balanced(&core);
    }

    #[test]
    fn byte_body_views_keep_exact_storage_provenance_and_independent_backings() {
        for body in [Vec::new(), vec![0, 255, 239, 187, 191, 128]] {
            let mut core = core();
            let original = response(&mut core, Some(body.clone()));
            let copy = core.clone_fetch_response(original, &Label::Public).unwrap();
            let Value::Object(view) = core
                .consume_fetch_body(original, "bytes", &Label::Secret)
                .unwrap()
            else {
                panic!("Uint8Array result");
            };
            let backing = core.heap[view.0 as usize]
                .typed_array
                .as_deref()
                .unwrap()
                .clone();
            assert_eq!(backing.kind, TypedArrayKind::Uint8);
            assert_eq!(backing.byte_offset, 0);
            assert_eq!(backing.byte_length, body.len());
            assert_eq!(
                core.text_codec_input_bytes(&Value::Object(view)).unwrap(),
                body
            );
            assert_eq!(core.object_mutation_labels.get(&view), Some(&Label::Secret));
            assert_eq!(
                core.object_mutation_labels.get(&backing.buffer),
                Some(&Label::Secret)
            );
            assert_eq!(core.binary_storage_label_ref(view), Some(&Label::Secret));
            core.with_array_buffer_bytes_mut(backing.buffer, |bytes| bytes.fill(7))
                .unwrap();
            assert_eq!(
                core.heap[copy.0 as usize]
                    .fetch_response_slots()
                    .unwrap()
                    .body
                    .as_ref()
                    .unwrap(),
                &body
            );
            assert!(matches!(
                core.consume_fetch_body(original, "bytes", &Label::Public),
                Err(InterpreterError::TypeError { .. })
            ));
            assert_balanced(&core);
        }
    }

    #[test]
    fn byte_body_admission_precedes_disturbance_and_preserves_outer_scratch() {
        let mut core = core();
        let id = response(&mut core, Some(vec![42; 4096]));
        core.json_reserve_temporary(97).unwrap();
        let baseline = core.estimated_memory_bytes();
        let objects = core.heap.len();
        core.config.max_total_memory_bytes = baseline + 4095;
        assert!(matches!(
            core.consume_fetch_body(id, "bytes", &Label::Public),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.heap.len(), objects);
        assert_eq!(
            core.fetch_response_getter(id, "bodyUsed").unwrap(),
            Value::Bool(false)
        );
        assert_eq!(core.json_parse_temporary_bytes, 97);
        core.json_release_temporary(97);
        assert_balanced(&core);
    }

    #[test]
    fn native_body_methods_publish_private_promise_settlement_labels() {
        for method in ["text", "json", "arrayBuffer", "bytes"] {
            let mut core = core();
            let id = response(&mut core, Some(br#"{"answer":42}"#.to_vec()));
            core.seed_register(11, Value::Object(id)).unwrap();
            core.set_register_label(11, Label::Secret).unwrap();
            let builtin = BuiltinFunction::fetch_response_method(method).unwrap();
            let result = core
                .dispatch_fetch_response_method(
                    &module("0;"),
                    &builtin,
                    RegRange { start: 0, count: 0 },
                    Some(Value::Object(id)),
                    Some(11),
                )
                .unwrap();
            let Value::Promise(handle) = result else {
                panic!("body method returns Promise");
            };
            assert_eq!(
                core.promise_store
                    .get(crate::promise_model::PromiseHandle(handle))
                    .unwrap()
                    .label,
                Label::Secret
            );
            assert_eq!(core.object_mutation_labels.get(&id), Some(&Label::Secret));
            assert_balanced(&core);
        }
    }

    #[test]
    fn clone_and_body_staging_refuse_before_disturbing_or_allocating() {
        for clone in [false, true] {
            let mut core = core();
            let id = response(&mut core, Some(vec![42; 4096]));
            let baseline = core.estimated_memory_bytes();
            let objects = core.heap.len();
            core.config.max_total_memory_bytes = baseline + 4095;
            let outcome = if clone {
                core.clone_fetch_response(id, &Label::Public)
                    .map(Value::Object)
            } else {
                core.consume_fetch_body(id, "arrayBuffer", &Label::Public)
            };
            assert!(matches!(
                outcome,
                Err(InterpreterError::MemoryBudgetExceeded { .. })
            ));
            assert_eq!(core.heap.len(), objects);
            assert_eq!(
                core.fetch_response_getter(id, "bodyUsed").unwrap(),
                Value::Bool(false)
            );
            assert_eq!(
                core.heap[id.0 as usize]
                    .fetch_response_slots()
                    .unwrap()
                    .body
                    .as_ref()
                    .unwrap()
                    .len(),
                4096
            );
            assert_eq!(core.estimated_memory_bytes(), baseline);
            assert_balanced(&core);
        }
    }

    #[test]
    fn decoded_text_admits_both_string_copies_and_releases_failed_scratch() {
        let mut core = core();
        let id = response(&mut core, Some(vec![255; 4096]));
        let baseline = core.estimated_memory_bytes();
        // One three-byte replacement buffer fits; its simultaneously live
        // returned JsString allocation does not.
        core.config.max_total_memory_bytes = baseline + 3 * 4096 + 256;
        assert!(matches!(
            core.consume_fetch_body(id, "text", &Label::Public),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(
            core.fetch_response_getter(id, "bodyUsed").unwrap(),
            Value::Bool(true)
        );
        assert!(
            core.heap[id.0 as usize]
                .fetch_response_slots()
                .unwrap()
                .body
                .as_ref()
                .unwrap()
                .is_empty()
        );
        assert_balanced(&core);
    }

    #[test]
    fn null_body_reads_do_not_disturb_and_release_only_their_own_scratch() {
        let mut core = core();
        let id = response(&mut core, None);
        core.json_reserve_temporary(97).unwrap();
        for _ in 0..2 {
            assert_eq!(
                core.consume_fetch_body(id, "text", &Label::Public).unwrap(),
                Value::str("")
            );
            assert_eq!(
                core.fetch_response_getter(id, "bodyUsed").unwrap(),
                Value::Bool(false)
            );
            assert_eq!(core.json_parse_temporary_bytes, 97);
        }
        core.json_release_temporary(97);
        assert_balanced(&core);
    }

    #[test]
    fn header_has_scan_is_charged_to_the_instruction_budget() {
        let mut core = core();
        let id = response(&mut core, None);
        let headers = core.heap[id.0 as usize]
            .fetch_response_slots()
            .unwrap()
            .headers;
        core.set_host_slots(
            headers,
            HostObjectSlots::FetchHeaders(FetchHeadersSlots {
                immutable: true,
                fields: (0..1024)
                    .map(|index| (format!("x-{index}"), "value".into()))
                    .collect(),
            }),
        )
        .unwrap();
        core.seed_register(0, Value::str("missing")).unwrap();
        core.config.instruction_budget = core.instructions_executed + 5;
        let outcome = core.dispatch_fetch_headers_method(
            &module("0;"),
            &BuiltinFunction::fetch_headers_method("has").unwrap(),
            RegRange { start: 0, count: 1 },
            Some(Value::Object(headers)),
            None,
        );
        assert!(
            matches!(outcome, Err(InterpreterError::BudgetExhausted { .. })),
            "{outcome:?}"
        );
        assert_balanced(&core);
    }

    #[test]
    fn native_form_extraction_observes_lifecycle_labels_without_mutating_the_list() {
        for label in [
            Label::Secret,
            Label::Custom {
                name: "private-form".repeat(32),
                level: 4,
            },
        ] {
            let mut core = core();
            let pairs = vec![("a b".to_string(), "x+y%".to_string())];
            let id = core
                .allocate_url_search_params_state(pairs.clone(), None, label.clone())
                .unwrap();
            assert_eq!(
                core.object_mutation_labels
                    .get(&id)
                    .unwrap_or(&Label::Public),
                &Label::Public
            );
            let mut scratch = 0;
            let normalized = core
                .normalize_fetch_body(None, Value::Object(id), &mut scratch)
                .unwrap();
            assert_eq!(normalized, Value::Object(id));
            let (body, content_type) = core
                .fetch_request_body(None, normalized, &mut scratch)
                .unwrap();
            assert_eq!(body.as_deref(), Some(b"a+b=x%2By%25".as_slice()));
            assert_eq!(
                content_type.as_deref(),
                Some("application/x-www-form-urlencoded;charset=UTF-8")
            );
            assert_eq!(core.json_parse_context_label().unwrap(), label);
            assert_eq!(core.url_search_params[&id].pairs, pairs);
            drop(body);
            drop(content_type);
            core.json_release_temporary(scratch);
            assert_balanced(&core);
        }
    }

    #[test]
    fn native_form_serialization_refuses_memory_and_fuel_without_consuming_state() {
        for memory_limited in [true, false] {
            let mut core = core();
            let pairs = if memory_limited {
                vec![("x".repeat(4096), " ".repeat(4096))]
            } else {
                vec![(String::new(), String::new()); 1024]
            };
            let id = core
                .allocate_url_search_params_state(pairs.clone(), None, Label::Public)
                .unwrap();
            let before = core.instructions_executed;
            if memory_limited {
                core.config.max_total_memory_bytes = core.estimated_memory_bytes() + 4096;
            } else {
                core.config.instruction_budget = before + 8;
            }
            let mut scratch = 0;
            let outcome = core.fetch_request_body(None, Value::Object(id), &mut scratch);
            if memory_limited {
                assert!(
                    matches!(outcome, Err(InterpreterError::MemoryBudgetExceeded { .. })),
                    "{outcome:?}"
                );
                assert!(
                    core.instructions_executed > before + 2,
                    "the serializer admission follows charged input traversal"
                );
            } else {
                assert!(
                    matches!(outcome, Err(InterpreterError::BudgetExhausted { .. })),
                    "{outcome:?}"
                );
            }
            assert_eq!(core.url_search_params[&id].pairs, pairs);
            core.json_release_temporary(scratch);
            assert_balanced(&core);
        }
    }

    #[test]
    fn response_hidden_headers_participate_in_provenance_and_heap_label_projection() {
        let mut core = core();
        let id = response(&mut core, None);
        let headers = core.heap[id.0 as usize]
            .fetch_response_slots()
            .unwrap()
            .headers;
        core.join_object_mutation_label(headers, &Label::Secret)
            .unwrap();
        assert_eq!(
            core.process_dynamic_value_label_ref(&Value::Object(id), &mut BTreeSet::new()),
            Some(&Label::Secret),
        );
        core.clear_current_register_frame();
        core.set_reg(0, Value::Object(id));
        core.set_register_label(0, Label::Internal).unwrap();
        let sources = core.capture_heap_label_sources();
        assert_eq!(sources[id.0 as usize], Some(0));
        assert_eq!(sources[headers.0 as usize], Some(0));
        assert_balanced(&core);
    }

    #[test]
    fn protected_headers_survive_gc_and_body_state_restores_from_execution_seed() {
        let mut core = core();
        let id = response(&mut core, Some(b"restorable".to_vec()));
        core.seed_register(0, Value::Object(id)).unwrap();
        let headers = core.heap[id.0 as usize]
            .fetch_response_slots()
            .unwrap()
            .headers;
        let seed = core.capture_execution_seed().unwrap();
        core.gc_safe_point();
        assert_eq!(
            core.heap[headers.0 as usize]
                .fetch_headers_slots()
                .unwrap()
                .fields[0]
                .1,
            "kept alive"
        );
        assert_eq!(
            core.consume_fetch_body(id, "text", &Label::Secret).unwrap(),
            Value::str("restorable")
        );
        assert_eq!(
            core.fetch_response_getter(id, "bodyUsed").unwrap(),
            Value::Bool(true)
        );
        core.reset_execution_state_from_seed(&seed).unwrap();
        assert_eq!(
            core.fetch_response_getter(id, "bodyUsed").unwrap(),
            Value::Bool(false)
        );
        assert_eq!(
            core.consume_fetch_body(id, "text", &Label::Public).unwrap(),
            Value::str("restorable")
        );
        drop(seed);
        assert_balanced(&core);
    }

    #[derive(Debug)]
    struct DeniedNetwork;

    impl HostIoProvider for DeniedNetwork {
        fn name(&self) -> &str {
            "fetch-pending-cleanup"
        }

        fn perform(
            &self,
            _request: &frankenengine_extension_host::host_io::HostIoRequest,
            _granted: &[frankenengine_extension_host::host_io::HostIoCapability],
        ) -> HostIoOutcome {
            Err(HostIoError::Denied {
                reason: "fixture endpoint denial".into(),
            })
        }
    }

    #[test]
    fn reentrant_guest_promise_survives_cleanup_of_unpublished_fetch_promise() {
        let mut core = core();
        core.set_host_io(Arc::new(DeniedNetwork), None);
        let outcome = core.execute(&module(
            r#"
            let retained;
            fetch('http://example.test/denied', {
                get body() { retained = new Promise(() => {}); return undefined; }
            });
        "#,
        ));
        assert!(
            matches!(&outcome, Err(InterpreterError::CapabilityDenied { capability })
            if capability == "net:request"),
            "{outcome:?}"
        );
        assert_eq!(core.promise_store.slot_count(), 2);
        assert_eq!(core.promise_store.len(), 1);
        assert!(
            core.promise_state(0).is_none(),
            "Fetch-owned pending Promise removed"
        );
        assert_eq!(
            core.promise_state(1),
            Some(crate::promise_model::PromiseState::Pending)
        );
        assert_balanced(&core);
    }
}
