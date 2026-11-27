//! Buffered Fetch through the native parser, lowering, interpreter and recorded
//! host-I/O bridge. Providers return deterministic HTTP bytes; no external
//! server is needed. Redirects exercise the same provider and transcript with
//! explicit IFC authorization for received Location data. Streaming and public
//! Fetch constructors are outside this slice. Request header values require ASCII.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    AllocKind, ExecutionResult, FunctionRef, HookAction, HookContext, InterpreterConfig,
    InterpreterCore, InterpreterError, InterpreterHook, ObjectRef, PropertyKey, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::{
    FlowPolicy, FlowPolicyEnforcement, FlowRule, IfcSchemaVersion, Label,
};
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_engine::signature_preimage::{SIGNATURE_SENTINEL, Signature};
use frankenengine_extension_host::host_io::budget::HostIoBudgetError;
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoError, HostIoOutcome, HostIoProvider, HostIoRecorder,
    HostIoRequest, HostIoResponse, InMemoryHostIoTranscript,
};

#[derive(Clone, Debug)]
enum Reply {
    Raw(Vec<u8>),
    Sequence(Vec<Reply>),
    Transport,
    Denied,
    Budget,
    WrongKind,
}

#[derive(Debug)]
struct RecordedNetwork {
    reply: Reply,
    requests: Mutex<Vec<HostIoRequest>>,
}

impl RecordedNetwork {
    fn new(reply: Reply) -> Self {
        Self {
            reply,
            requests: Mutex::new(Vec::new()),
        }
    }

    fn answer(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        assert!(granted.contains(&request.required_capability()));
        assert!(matches!(request, HostIoRequest::NetworkRequest { .. }));
        let index = {
            let mut requests = self.requests.lock().unwrap();
            let index = requests.len();
            requests.push(request.clone());
            index
        };
        let reply = match &self.reply {
            Reply::Sequence(replies) => replies.get(index).expect("unexpected extra provider call"),
            reply => reply,
        };
        match reply {
            Reply::Raw(response) => Ok(HostIoResponse::NetworkRequest {
                response: response.clone(),
            }),
            Reply::Transport => Err(HostIoError::Io {
                detail: "fixture connection reset".into(),
            }),
            Reply::Denied => Err(HostIoError::Denied {
                reason: "fixture endpoint policy".into(),
            }),
            Reply::Budget => Err(HostIoError::Denied {
                reason: HostIoBudgetError::RequestsExhausted.code().into(),
            }),
            Reply::WrongKind => Ok(HostIoResponse::NetworkSend { bytes_sent: 0 }),
            Reply::Sequence(_) => panic!("nested reply sequences are not supported"),
        }
    }

    fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl HostIoProvider for RecordedNetwork {
    fn name(&self) -> &str {
        "buffered-fetch-fixture"
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        self.answer(request, granted)
    }

    fn perform_controlled(
        &self,
        request: &HostIoRequest,
        granted: &[HostIoCapability],
        _control: Arc<dyn HostIoControl>,
    ) -> HostIoOutcome {
        self.answer(request, granted)
    }
}

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "buffered-fetch.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("Fetch test parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "buffered-fetch.js"),
        &LoweringContext::new("fetch-trace", "fetch-decision", "fetch-policy"),
    )
    .expect("Fetch test lowers")
    .ir3
}

fn config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = 1_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
        RuntimeCapability::NetworkEgress,
    ]
    .into_iter()
    .collect();
    config
}

// Received network data has an Internal source floor. These positive fixtures
// explicitly authorize that flow at the next Public network sink; production
// defaults and the strict-refusal test below retain their existing lattice.
fn redirect_config() -> InterpreterConfig {
    let mut config = config();
    config.ifc_flow_policy = Some(FlowPolicy {
        policy_id: "fetch-redirect-test".into(),
        extension_id: "fetch-redirect-test".into(),
        label_classes: [Label::Public, Label::Internal].into_iter().collect(),
        clearance_classes: [Label::Public, Label::Internal].into_iter().collect(),
        allowed_flows: vec![FlowRule {
            source_label: Label::Internal,
            sink_clearance: Label::Public,
        }],
        prohibited_flows: vec![],
        declassification_routes: vec![],
        enforcement_mode: FlowPolicyEnforcement::LatticeOpen,
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    });
    config
}

fn response(status: u16, headers: &str, body: &[u8]) -> Reply {
    let text = if status == 404 { "Not Found" } else { "OK" };
    let mut bytes = format!(
        "HTTP/1.1 {status} {text}\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len(),
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    Reply::Raw(bytes)
}

struct Run {
    result: Result<ExecutionResult, InterpreterError>,
    core: InterpreterCore,
    provider: Arc<RecordedNetwork>,
    transcript: Arc<InMemoryHostIoTranscript>,
}

fn run_module(module: &Ir3Module, reply: Reply, config: InterpreterConfig) -> Run {
    let provider = Arc::new(RecordedNetwork::new(reply));
    let transcript = Arc::new(InMemoryHostIoTranscript::recording());
    transcript.begin_execution().unwrap();
    let mut core = InterpreterCore::new(config, "buffered-fetch");
    core.set_host_io(provider.clone(), Some(transcript.clone()));
    let result = core.execute(module);
    Run {
        result,
        core,
        provider,
        transcript,
    }
}

fn run_case(source: &str, reply: Reply) -> Run {
    run_module(&lower(source), reply, config())
}

fn messages(run: &Run) -> Vec<&str> {
    run.result
        .as_ref()
        .expect("native Fetch execution succeeds")
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect()
}

fn one_recorded_request(run: &Run) {
    assert_eq!(run.provider.count(), 1);
    assert_eq!(run.transcript.recorded_entries().len(), 1);
    if let Ok(result) = &run.result {
        assert_eq!(
            result
                .hostcall_decisions
                .iter()
                .filter(|decision| decision.capability.0 == "net:request")
                .count(),
            2,
            "Fetch authorizes entry and rechecks concrete egress after argument conversion",
        );
    }
}

#[test]
fn response_metadata_headers_clone_and_single_consumption() {
    let run = run_case(
        r#"
        fetch('http://example.test/data#fragment').then(async response => {
            console.log(response.status, response.statusText, response.ok, response.bodyUsed);
            console.log(response.url, response.redirected, response.type);
            console.log(response.headers.get('X-Test'), response.headers.has('x-test'));
            console.log(response.headers.get('missing'), response.headers.has('missing'));
            console.log(response.headers.getSetCookie().join('|'));
            const copy = response.clone();
            const text = response.text();
            console.log(response.bodyUsed, copy.bodyUsed);
            console.log(await text);
            try { await response.json(); } catch (error) { console.log(error.name); }
            try { response.clone(); } catch (error) { console.log(error.name); }
            console.log((await copy.json()).answer, copy.bodyUsed);
        });
    "#,
        response(
            200,
            "X-Test: first\r\nX-Test: second\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n",
            br#"{"answer":42}"#,
        ),
    );
    assert_eq!(
        messages(&run),
        [
            "200 OK true false",
            "http://example.test/data false basic",
            "first, second true",
            "null false",
            "a=1|b=2",
            "true false",
            r#"{"answer":42}"#,
            "TypeError",
            "TypeError",
            "42 true",
        ]
    );
    one_recorded_request(&run);
}

#[test]
fn binary_body_is_exact_while_text_strips_one_bom_and_replaces_invalid_utf8() {
    let body = b"\xef\xbb\xbf\xef\xbb\xbfA\xff\0";
    let run = run_case(
        r#"
        fetch('http://example.test/bytes').then(async response => {
            const copy = response.clone();
            const text = await response.text();
            console.log(text.charCodeAt(0), text.charCodeAt(1), text.charCodeAt(2), text.charCodeAt(3));
            console.log(Array.from(new Uint8Array(await copy.arrayBuffer())).join(','));
        });
    "#,
        response(200, "", body),
    );
    assert_eq!(
        messages(&run),
        ["65279 65 65533 0", "239,187,191,239,187,191,65,255,0",]
    );
    one_recorded_request(&run);
}

#[test]
fn byte_body_method_returns_an_independent_exact_uint8_array() {
    let run = run_case(
        r#"
        fetch('http://example.test/bytes').then(async response => {
            const copy = response.clone();
            const read = response.bytes;
            console.log(read.name, read.length, response.bodyUsed);
            const pending = read.call(response);
            console.log(pending instanceof Promise, response.bodyUsed, copy.bodyUsed);
            const bytes = await pending;
            console.log(bytes instanceof Uint8Array, bytes.byteOffset, bytes.byteLength);
            console.log(Array.from(bytes).join(','));
            bytes.fill(7);
            console.log(Array.from(new Uint8Array(await copy.arrayBuffer())).join(','));
            try { await response.bytes(); } catch (error) { console.log(error.name); }
            try { response.clone(); } catch (error) { console.log(error.name); }
            const invalid = read.call({});
            console.log(invalid instanceof Promise);
            try { await invalid; } catch (error) { console.log(error.name); }
        });
    "#,
        response(200, "", &[0, 255, 239, 187, 191, 128]),
    );
    assert_eq!(
        messages(&run),
        [
            "bytes 0 false",
            "true true false",
            "true 0 6",
            "0,255,239,187,191,128",
            "0,255,239,187,191,128",
            "TypeError",
            "TypeError",
            "true",
            "TypeError",
        ]
    );
    one_recorded_request(&run);
}

#[test]
fn byte_body_method_distinguishes_null_and_empty_bodies() {
    for (status, init, expected) in [
        (204, "{}", vec!["0 false", "0 false"]),
        (200, "{method:'HEAD'}", vec!["0 false", "0 false"]),
        (200, "{}", vec!["0 true", "TypeError true"]),
    ] {
        let source = format!(
            r#"
            fetch('http://example.test/empty', {init}).then(async response => {{
                console.log((await response.bytes()).byteLength, response.bodyUsed);
                try {{ console.log((await response.bytes()).byteLength, response.bodyUsed); }}
                catch (error) {{ console.log(error.name, response.bodyUsed); }}
            }});
        "#
        );
        let run = run_case(&source, response(status, "", b""));
        assert_eq!(messages(&run), expected);
        one_recorded_request(&run);
    }
}

#[test]
fn json_decodes_one_bom_and_rejects_syntax_without_swallowing_body_used() {
    for (body, expected) in [
        (b"\xef\xbb\xbf{\"answer\":42}".as_slice(), "42 true"),
        (
            b"\xef\xbb\xbf\xef\xbb\xbf{\"answer\":42}".as_slice(),
            "SyntaxError true",
        ),
        (b"{".as_slice(), "SyntaxError true"),
    ] {
        let run = run_case(
            r#"
            fetch('http://example.test/json').then(async response => {
                try { console.log((await response.json()).answer, response.bodyUsed); }
                catch (error) { console.log(error.name, response.bodyUsed); }
            });
        "#,
            response(200, "", body),
        );
        assert_eq!(messages(&run), [expected]);
    }
}

#[test]
fn null_bodies_can_be_read_repeatedly_but_empty_bodies_are_consumed() {
    for (status, init, expected) in [
        (204, "{}", vec!["false", "false", "0 false"]),
        (200, "{method:'HEAD'}", vec!["false", "false", "0 false"]),
        (200, "{}", vec!["false", "true", "TypeError true"]),
    ] {
        let source = format!(
            r#"
            fetch('http://example.test/empty', {init}).then(async response => {{
                console.log(response.bodyUsed);
                await response.text();
                console.log(response.bodyUsed);
                try {{ console.log((await response.arrayBuffer()).byteLength, response.bodyUsed); }}
                catch (error) {{ console.log(error.name, response.bodyUsed); }}
            }});
        "#
        );
        let run = run_case(&source, response(status, "", b""));
        assert_eq!(messages(&run), expected);
    }
}

#[test]
fn error_http_status_resolves_and_malformed_transport_bytes_reject() {
    let run = run_case(
        r#"
        fetch('http://example.test/missing').then(async response => {
            console.log(response.status, response.ok, await response.text());
        }, () => console.log('unexpected rejection'));
    "#,
        response(404, "", b"missing"),
    );
    assert_eq!(messages(&run), ["404 false missing"]);
    one_recorded_request(&run);
    let malformed = run_case(
        r#"
        fetch('http://example.test/malformed').catch(error => console.log(error.name));
        console.log('continued');
    "#,
        Reply::Raw(b"not HTTP".to_vec()),
    );
    assert_eq!(messages(&malformed), ["continued", "TypeError"]);
    one_recorded_request(&malformed);
}

#[test]
fn first_class_fetch_preserves_authority_and_ordinary_rejection() {
    for call in [
        "fetch('http://example.test/failure')",
        "globalThis.fetch('http://example.test/failure')",
        "alias('http://example.test/failure')",
        "alias.call(null, 'http://example.test/failure')",
        "alias.apply(null, ['http://example.test/failure'])",
        "bound('http://example.test/failure')",
    ] {
        let source = format!(
            "const alias = fetch; const bound = fetch.bind(null); \
             {call}.catch(error => console.log(error.name)); console.log('continued');"
        );
        let run = run_case(&source, Reply::Transport);
        assert_eq!(messages(&run), ["continued", "TypeError"], "{call}");
        one_recorded_request(&run);
        let mut denied_config = config();
        denied_config
            .granted_capabilities
            .remove(&RuntimeCapability::NetworkEgress);
        let denied = run_module(&lower(&source), Reply::Transport, denied_config);
        assert!(
            matches!(&denied.result, Err(InterpreterError::CapabilityDenied { capability })
            if capability == "net:request"),
            "{call}: {:?}",
            denied.result
        );
        assert_eq!(denied.provider.count(), 0);
        assert!(denied.transcript.recorded_entries().is_empty());
        assert!(denied.core.console_output().is_empty());
    }
}

#[test]
fn retrieving_native_fetch_is_pure_and_does_not_grant_network_authority() {
    let mut config = config();
    config
        .granted_capabilities
        .remove(&RuntimeCapability::NetworkEgress);
    let run = run_module(
        &lower(
            "const alias = fetch; const member = globalThis.fetch; \
         console.log(typeof alias, alias === member);",
        ),
        Reply::Denied,
        config,
    );
    assert_eq!(messages(&run), ["function true"]);
    assert_eq!(run.provider.count(), 0);
    assert!(run.transcript.recorded_entries().is_empty());
    // The first-class invocation test independently checks net:request denial
    // for every call shape under this same missing NetworkEgress grant.
}

#[test]
fn no_provider_and_invalid_requests_return_rejected_promises() {
    let mut core = InterpreterCore::new(config(), "fetch-no-provider");
    let result = core
        .execute(&lower(
            "fetch('http://example.test/no-provider').catch(error => console.log(error.name));",
        ))
        .unwrap();
    assert_eq!(result.console_output[0].message, "TypeError");
    for call in [
        "fetch()",
        "fetch('/relative')",
        "fetch('http://example.test/', {method:'GET', body:''})",
        "fetch('http://example.test/', {method:'GET', body:new URLSearchParams('')})",
        "fetch('http://example.test/', {method:'HEAD', body:new URLSearchParams('')})",
        "fetch('http://example.test/', {method:'TRACE'})",
        "fetch('http://example.test/', {headers:{'bad name':'value'}})",
        "fetch('http://example.test/', {headers:{x:'line\\r\\nbreak'}})",
        // Explicit bounded-slice limitation: no silent UTF-8 rewriting of
        // ByteString header octets, and no non-ByteString code points.
        "fetch('http://example.test/', {headers:{x:'\\u00e9'}})",
        "fetch('http://example.test/', {headers:{x:'\\ud83d\\ude00'}})",
    ] {
        let run = run_case(
            &format!("{call}.catch(error => console.log(error.name));"),
            response(200, "", b""),
        );
        assert_eq!(messages(&run), ["TypeError"], "{call}");
        assert_eq!(run.provider.count(), 0);
        assert!(run.transcript.recorded_entries().is_empty());
    }
}

#[test]
fn request_dictionary_conversion_order_and_exact_throw_identity() {
    for (init, expected) in [
        (
            "get body(){trace+='b';return {toString(){trace+='B';throw failure;}}}, \
             get headers(){trace+='h';throw 1}, get method(){trace+='m';throw 2}",
            "bB true",
        ),
        (
            "get body(){trace+='b';return undefined}, \
             get headers(){trace+='h';return {x:{toString(){trace+='H';throw failure;}}}}, \
             get method(){trace+='m';throw 2}",
            "bhH true",
        ),
        (
            "get headers(){const pair=[{toString(){trace+='N';throw failure}},'value']; \
             Object.defineProperty(pair,'1',{get(){trace+='V';throw 2}}); return [pair]}, \
             get method(){trace+='m';throw 3}",
            "N true",
        ),
    ] {
        let source = format!(
            r#"
            let trace = '';
            const failure = {{marker:17}};
            fetch('http://example.test/', {{{init}}})
                .catch(error => console.log(trace, error === failure));
        "#
        );
        let run = run_case(&source, response(200, "", b""));
        assert_eq!(messages(&run), [expected]);
        assert_eq!(run.provider.count(), 0);
    }
}

#[test]
fn request_conversion_preserves_all_guest_rejection_values() {
    for thrown in [
        "() => 42",
        "12345678901234567890n",
        "'\\ud800'",
        "Promise.resolve(7)",
        "Math.max",
    ] {
        let source = format!(
            "const failure = {thrown}; \
             fetch('http://example.test/', {{get body(){{throw failure}}}}) \
                .catch(error => console.log(error === failure));"
        );
        let run = run_case(&source, response(200, "", b""));
        assert_eq!(messages(&run), ["true"], "{thrown}");
        assert_eq!(run.provider.count(), 0);
    }
}

#[test]
fn binary_request_body_and_extra_argument_side_effects_reach_the_shared_sender() {
    let run = run_case(
        r#"
        let extra = 0;
        fetch('http://example.test/upload#removed',
            {method:'post', headers:[['X-Test','one'], ['x-test','two']],
             body:new Uint8Array([0,255,13,10])},
            extra = 7
        ).then(response => console.log(extra, response.status));
    "#,
        response(200, "", b""),
    );
    assert_eq!(messages(&run), ["7 200"]);
    one_recorded_request(&run);
    let requests = run.provider.requests.lock().unwrap();
    let HostIoRequest::NetworkRequest {
        payload,
        endpoint,
        use_tls,
        ..
    } = &requests[0]
    else {
        panic!("network request");
    };
    assert_eq!(endpoint, "example.test:80");
    assert!(!use_tls);
    assert!(payload.starts_with(b"POST /upload HTTP/1.1\r\n"));
    assert!(
        payload
            .windows(b"x-test: one\r\n".len())
            .any(|bytes| bytes == b"x-test: one\r\n")
    );
    assert!(
        payload
            .windows(b"x-test: two\r\n".len())
            .any(|bytes| bytes == b"x-test: two\r\n")
    );
    assert!(payload.ends_with(b"\r\n\r\n\0\xff\r\n"));
}

#[test]
fn url_search_params_body_uses_native_pairs_after_dictionary_conversion() {
    let run = run_case(
        r#"
        const params = new URLSearchParams(
            'a+b=x%2By%25&a+b=%C3%A9%F0%9F%92%A9&=&bad=%EF%BF%BD');
        let conversions = 0;
        function forbidden() { conversions += 1; throw 'native list required'; }
        Object.defineProperty(params, 'toString', {get: forbidden});
        Object.defineProperty(params, Symbol.toPrimitive, {get: forbidden});
        Object.defineProperty(params, Symbol.iterator, {get: forbidden});
        fetch('http://example.test/form', {
            get body() { return params; },
            get headers() { params.append('from headers', '1'); return {}; },
            get method() { params.append('from method', '2'); return 'POST'; }
        }).then(response => console.log(response.status, conversions));
        params.append('after capture', 'not sent');
        "#,
        response(200, "", b""),
    );
    assert_eq!(messages(&run), ["200 0"]);
    one_recorded_request(&run);
    let requests = run.provider.requests.lock().unwrap();
    let HostIoRequest::NetworkRequest { payload, .. } = &requests[0] else {
        panic!("network request");
    };
    let separator = payload
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    assert_eq!(
        &payload[separator + 4..],
        b"a+b=x%2By%25&a+b=%C3%A9%F0%9F%92%A9&=&bad=%EF%BF%BD&from+headers=1&from+method=2",
    );
    let headers = std::str::from_utf8(&payload[..separator]).unwrap();
    assert!(
        headers.lines().any(|line| {
            line == "content-type: application/x-www-form-urlencoded;charset=UTF-8"
        })
    );
}

#[test]
fn form_body_defaults_preserve_explicit_content_type_and_require_native_brand() {
    for (body, headers, expected_type, expected_body) in [
        (
            "new URLSearchParams('')",
            "{}",
            "application/x-www-form-urlencoded;charset=UTF-8",
            "",
        ),
        (
            "new URLSearchParams('a=b')",
            "{'CoNtEnT-TyPe':'application/custom'}",
            "application/custom",
            "a=b",
        ),
        (
            "new URLSearchParams('a=b')",
            "{'Content-Type':''}",
            "",
            "a=b",
        ),
        (
            "{[Symbol.toStringTag]:'URLSearchParams',toString(){return 'ordinary'}}",
            "{}",
            "text/plain;charset=UTF-8",
            "ordinary",
        ),
    ] {
        let source = format!(
            "fetch('http://example.test/form', \
             {{method:'POST', body:{body}, headers:{headers}}}) \
                .then(response => console.log(response.status));"
        );
        let run = run_case(&source, response(200, "", b""));
        assert_eq!(messages(&run), ["200"], "{source}");
        one_recorded_request(&run);
        let requests = run.provider.requests.lock().unwrap();
        let HostIoRequest::NetworkRequest { payload, .. } = &requests[0] else {
            panic!("network request");
        };
        let separator = payload
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap();
        assert_eq!(
            &payload[separator + 4..],
            expected_body.as_bytes(),
            "{source}"
        );
        let headers = std::str::from_utf8(&payload[..separator]).unwrap();
        let content_types: Vec<_> = headers
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-type")
                    .then_some(value.trim())
            })
            .collect();
        assert_eq!(content_types, [expected_type], "{source}");
    }
}

#[test]
fn security_provider_contract_and_host_quota_failures_remain_fatal() {
    for reply in [Reply::Denied, Reply::Budget, Reply::WrongKind] {
        for call in ["fetch", "alias"] {
            let run = run_case(
                &format!(
                    "const alias = fetch; try {{ {call}('http://example.test/denied') \
                 .catch(() => console.log('rejected')); }} \
                 catch (error) {{ console.log('caught'); }} console.log('continued');"
                ),
                reply.clone(),
            );
            match reply {
                Reply::Denied => assert!(matches!(&run.result,
                    Err(InterpreterError::CapabilityDenied { capability }) if capability == "net:request")),
                Reply::Budget | Reply::WrongKind => assert!(
                    matches!(&run.result, Err(InterpreterError::InternalError { .. })),
                    "{:?}",
                    run.result
                ),
                _ => unreachable!(),
            }
            assert!(run.core.console_output().is_empty());
            one_recorded_request(&run);
        }
    }
}

#[test]
fn secret_provenance_introduced_by_an_option_getter_cannot_reach_the_provider() {
    let mut module = lower(
        r#"
        const payload = '__fetch_private_body__';
        fetch('http://example.test/upload', {method:'POST', get body(){return payload}})
            .catch(() => console.log('rejected'));
        console.log('continued');
    "#,
    );
    let mut replaced = 0;
    for instruction in &mut module.instructions {
        if let Ir3Instruction::LoadStr { dst, pool_index } = *instruction
            && module.constant_pool[pool_index as usize].as_str() == Some("__fetch_private_body__")
        {
            *instruction = Ir3Instruction::Move { dst, src: 255 };
            replaced += 1;
        }
    }
    assert_eq!(replaced, 1);
    let provider = Arc::new(RecordedNetwork::new(response(200, "", b"")));
    let mut core = InterpreterCore::new(config(), "fetch-private-body");
    core.set_host_io(provider.clone(), None);
    core.seed_register(255, Value::str("private body")).unwrap();
    core.set_register_label(255, Label::Secret).unwrap();
    let outcome = core.execute(&module);
    assert!(
        matches!(outcome, Err(InterpreterError::CapabilityDenied { .. })),
        "{outcome:?}"
    );
    assert!(core.console_output().is_empty());
    assert_eq!(provider.count(), 0);
}

#[test]
fn private_form_mutation_during_header_conversion_cannot_reach_the_provider() {
    let mut module = lower(
        r#"
        const payload = '__fetch_private_form__';
        const params = new URLSearchParams('public=1');
        fetch('http://example.test/form', {
            body: params,
            get headers() { params.append('private', payload); return {}; },
            method: 'POST'
        }).catch(() => console.log('rejected'));
        console.log('continued');
        "#,
    );
    let mut replaced = 0;
    for instruction in &mut module.instructions {
        if let Ir3Instruction::LoadStr { dst, pool_index } = *instruction
            && module.constant_pool[pool_index as usize].as_str() == Some("__fetch_private_form__")
        {
            *instruction = Ir3Instruction::Move { dst, src: 255 };
            replaced += 1;
        }
    }
    assert_eq!(replaced, 1);
    let provider = Arc::new(RecordedNetwork::new(response(200, "", b"")));
    let mut core = InterpreterCore::new(config(), "fetch-private-form");
    core.set_host_io(provider.clone(), None);
    core.seed_register(255, Value::str("private value"))
        .unwrap();
    core.set_register_label(255, Label::Secret).unwrap();
    let outcome = core.execute(&module);
    assert!(
        matches!(outcome, Err(InterpreterError::CapabilityDenied { .. })),
        "{outcome:?}"
    );
    assert!(core.console_output().is_empty());
    assert_eq!(provider.count(), 0);
}

#[test]
fn recorded_fetch_replays_the_same_bytes_without_another_provider_call() {
    let source = "fetch('http://example.test/replay').then(r => r.text()).then(console.log);";
    let first = run_case(source, response(200, "", b"recorded"));
    assert_eq!(messages(&first), ["recorded"]);
    let entries = first.transcript.finish_execution().unwrap();
    assert_eq!(entries.len(), 1);
    let replay = Arc::new(InMemoryHostIoTranscript::replaying(entries.clone()));
    replay.begin_execution().unwrap();
    let provider = Arc::new(RecordedNetwork::new(Reply::Denied));
    let mut core = InterpreterCore::new(config(), "fetch-replay");
    core.set_host_io(provider.clone(), Some(replay.clone()));
    let result = core.execute(&lower(source)).unwrap();
    assert_eq!(result.console_output[0].message, "recorded");
    assert_eq!(provider.count(), 0);
    assert_eq!(replay.finish_execution().unwrap(), entries);
}

#[test]
fn legacy_network_request_keeps_incoming_message_shape_and_failure_behavior() {
    let mut module = lower(
        r#"
        const response = '__legacy_request__';
        console.log(response.statusCode, response.statusMessage, response.body);
        console.log(response.headers['x-test'], typeof response.text);
    "#,
    );
    for instruction in &mut module.instructions {
        if let Ir3Instruction::LoadStr { dst, pool_index } = *instruction
            && module.constant_pool[pool_index as usize].as_str() == Some("__legacy_request__")
        {
            *instruction = Ir3Instruction::HostCall {
                capability: CapabilityTag("net:request".into()),
                args: RegRange {
                    start: 255,
                    count: 1,
                },
                dst,
            };
        }
    }
    let provider = Arc::new(RecordedNetwork::new(response(
        200,
        "X-Test: legacy\r\n",
        b"ok",
    )));
    let mut core = InterpreterCore::new(config(), "legacy-network");
    core.set_host_io(provider.clone(), None);
    core.seed_register(255, Value::str("http://example.test/legacy"))
        .unwrap();
    let result = core.execute(&module).unwrap();
    let messages: Vec<_> = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(messages, ["200 OK ok", "legacy undefined"]);
    assert_eq!(provider.count(), 1);

    let mut module = lower("0;");
    module.instructions = vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("net:request".into()),
            args: RegRange {
                start: 255,
                count: 1,
            },
            dst: 0,
        },
        Ir3Instruction::Return { value: 0 },
    ];
    for reply in [Reply::Transport, Reply::Denied] {
        let provider = Arc::new(RecordedNetwork::new(reply));
        let mut core = InterpreterCore::new(config(), "legacy-network-failure");
        core.set_host_io(provider, None);
        core.seed_register(255, Value::str("http://example.test/legacy"))
            .unwrap();
        assert_eq!(core.execute(&module).unwrap().value, Value::Undefined);
    }
}

fn assert_recorded_hops(run: &Run, count: usize) {
    assert_eq!(run.provider.count(), count);
    assert_eq!(run.transcript.recorded_entries().len(), count);
    if let Ok(result) = &run.result {
        assert_eq!(
            result
                .hostcall_decisions
                .iter()
                .filter(|decision| decision.capability.0 == "net:request")
                .count(),
            count + 1,
            "the entry gate and every concrete network egress are authorized",
        );
    }
}

fn request_parts(request: &HostIoRequest) -> (&str, &[u8]) {
    let HostIoRequest::NetworkRequest { payload, .. } = request else {
        panic!("network request");
    };
    let separator = payload
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .expect("HTTP request header terminator");
    (
        std::str::from_utf8(&payload[..separator]).unwrap(),
        &payload[separator + 4..],
    )
}

#[test]
fn redirects_resolve_relative_locations_and_preserve_final_metadata_through_clone() {
    let run = run_module(
        &lower(
            r#"
            fetch('http://EXAMPLE.test:80/start/entry#removed').then(async response => {
                const copy = response.clone();
                console.log(response.status, response.url, response.redirected, response.type);
                console.log(copy.url, copy.redirected);
                console.log(await response.text(), await copy.text());
            });
            "#,
        ),
        Reply::Sequence(vec![
            response(
                302,
                "Location: ../next?step=1#discarded\r\n",
                b"intermediate",
            ),
            response(307, "Location: ?step=2\r\n", b"intermediate"),
            response(200, "", b"final"),
        ]),
        redirect_config(),
    );
    assert_eq!(
        messages(&run),
        [
            "200 http://example.test/next?step=2 true basic",
            "http://example.test/next?step=2 true",
            "final final",
        ],
    );
    assert_recorded_hops(&run, 3);
    let requests = run.provider.requests.lock().unwrap();
    assert!(
        request_parts(&requests[0])
            .0
            .starts_with("GET /start/entry HTTP/1.1")
    );
    assert!(
        request_parts(&requests[1])
            .0
            .starts_with("GET /next?step=1 HTTP/1.1")
    );
    assert!(
        request_parts(&requests[2])
            .0
            .starts_with("GET /next?step=2 HTTP/1.1")
    );
}

#[test]
fn redirect_statuses_rewrite_only_required_methods_and_replay_preserved_binary_bodies() {
    for (status, method, expected_method) in [
        (301, "POST", "GET"),
        (302, "POST", "GET"),
        (303, "PUT", "GET"),
        (301, "PUT", "PUT"),
        (302, "PATCH", "PATCH"),
        (307, "POST", "POST"),
        (308, "PUT", "PUT"),
        (303, "HEAD", "HEAD"),
    ] {
        let has_body = method != "HEAD";
        let body = if has_body {
            "new Uint8Array([0,255,13,10])"
        } else {
            "undefined"
        };
        let framing = if has_body {
            ",'Content-Length':'4'"
        } else {
            ""
        };
        let source = format!(
            "fetch('http://example.test/source', {{method:'{method}', body:{body}, \
             headers:{{'Content-Type':'application/test','Content-Language':'en', \
             'Content-Encoding':'identity','Content-Location':'/source','X-Keep':'yes'{framing}}}}}) \
             .then(r => console.log(r.status, r.redirected));"
        );
        let run = run_module(
            &lower(&source),
            Reply::Sequence(vec![
                response(status, "Location: /target\r\n", b""),
                response(200, "", b""),
            ]),
            redirect_config(),
        );
        assert_eq!(messages(&run), ["200 true"], "{status} {method}");
        assert_recorded_hops(&run, 2);
        let requests = run.provider.requests.lock().unwrap();
        let (head, sent_body) = request_parts(&requests[1]);
        assert!(
            head.starts_with(&format!("{expected_method} /target HTTP/1.1")),
            "{status} {method}: {head}"
        );
        assert!(head.lines().any(|line| line == "x-keep: yes"));
        let rewritten = expected_method != method;
        let expected_body: &[u8] = if has_body && !rewritten {
            &[0, 255, 13, 10]
        } else {
            &[]
        };
        assert_eq!(sent_body, expected_body, "{status} {method}");
        for name in [
            "content-type",
            "content-language",
            "content-encoding",
            "content-location",
        ] {
            assert_eq!(
                head.lines()
                    .any(|line| line.starts_with(&format!("{name}:"))),
                !rewritten,
                "{status} {method}: {name}"
            );
        }
        if rewritten {
            assert!(!head.lines().any(|line| line == "content-length: 4"));
            assert!(
                !head
                    .lines()
                    .any(|line| line.starts_with("transfer-encoding:"))
            );
        }
    }
}

#[test]
fn origin_changes_remove_credentials_without_restoring_them_on_a_return_redirect() {
    let run = run_module(
        &lower(
            r#"
            fetch('http://example.test/start', {
                headers: {
                    Authorization: 'Bearer private',
                    'Proxy-Authorization': 'Basic private',
                    Cookie: 'session=private',
                    Cookie2: 'legacy=private',
                    Host: 'example.test',
                    'X-Keep': 'retained'
                }
            }).then(r => console.log(r.url, r.redirected));
            "#,
        ),
        Reply::Sequence(vec![
            response(307, "Location: http://EXAMPLE.test:80/same\r\n", b""),
            response(307, "Location: https://other.test:8443/cross\r\n", b""),
            response(307, "Location: http://example.test/back\r\n", b""),
            response(200, "", b""),
        ]),
        redirect_config(),
    );
    assert_eq!(messages(&run), ["http://example.test/back true"]);
    assert_recorded_hops(&run, 4);
    let requests = run.provider.requests.lock().unwrap();
    let (same_origin, _) = request_parts(&requests[1]);
    assert!(
        same_origin
            .lines()
            .any(|line| line == "authorization: Bearer private")
    );
    assert!(
        same_origin
            .lines()
            .any(|line| line == "cookie: session=private")
    );
    for request in &requests[2..] {
        let (head, _) = request_parts(request);
        assert!(head.lines().any(|line| line == "x-keep: retained"));
        for name in ["authorization", "proxy-authorization", "cookie", "cookie2"] {
            assert!(
                !head
                    .lines()
                    .any(|line| line.starts_with(&format!("{name}:")))
            );
        }
        assert_eq!(
            head.lines()
                .filter(|line| line.to_ascii_lowercase().starts_with("host:"))
                .count(),
            1,
            "the new URL supplies the only Host field"
        );
    }
    assert!(matches!(
        &requests[2],
        HostIoRequest::NetworkRequest { endpoint, use_tls: true, .. }
            if endpoint == "other.test:8443"
    ));
}

#[test]
fn redirect_modes_keep_manual_responses_and_reject_error_even_without_location() {
    for headers in ["", "Location: file:///private\r\n"] {
        let manual = run_case(
            "fetch('http://example.test/', {redirect:'manual'}).then(async r => \
             console.log(r.status, r.redirected, r.type, await r.text()));",
            response(302, headers, b"inspect"),
        );
        assert_eq!(messages(&manual), ["302 false basic inspect"]);
        one_recorded_request(&manual);
        let error = run_case(
            "fetch('http://example.test/', {redirect:'error'}) \
             .catch(e => console.log(e.name));",
            response(302, headers, b"inspect"),
        );
        assert_eq!(messages(&error), ["TypeError"]);
        one_recorded_request(&error);
    }
    let missing_location = run_case(
        "fetch('http://example.test/').then(r => console.log(r.status, r.redirected));",
        response(302, "", b""),
    );
    assert_eq!(messages(&missing_location), ["302 false"]);
    one_recorded_request(&missing_location);
    for redirect in ["'FOLLOW'", "'invalid'", "null", "Symbol('follow')"] {
        let run = run_case(
            &format!(
                "fetch('http://example.test/', {{redirect:{redirect}}}) \
                 .catch(e => console.log(e.name));"
            ),
            response(200, "", b""),
        );
        assert_eq!(messages(&run), ["TypeError"], "{redirect}");
        assert_eq!(run.provider.count(), 0);
        assert!(run.transcript.recorded_entries().is_empty());
    }
}

#[test]
fn redirect_dictionary_conversion_follows_method_and_preserves_throw_identity() {
    let run = run_case(
        r#"
        let trace = '';
        const failure = {marker:19};
        fetch('http://example.test/', {
            get body() { trace += 'b'; return undefined; },
            get headers() { trace += 'h'; return {}; },
            get method() {
                trace += 'm';
                return {toString() { trace += 'M'; return 'GET'; }};
            },
            get redirect() {
                trace += 'r';
                return {toString() { trace += 'R'; throw failure; }};
            }
        }).catch(error => console.log(trace, error === failure));
        "#,
        response(200, "", b""),
    );
    assert_eq!(messages(&run), ["bhmMrR true"]);
    assert_eq!(run.provider.count(), 0);
    assert!(run.transcript.recorded_entries().is_empty());
}

#[test]
fn invalid_ambiguous_or_credentialed_redirects_reject_without_another_request() {
    for headers in [
        "Location: file:///private\r\n",
        "Location: ftp://example.test/file\r\n",
        "Location: http://user:password@example.test/private\r\n",
        "Location: http://[invalid\r\n",
        "Location: /one\r\nLocation: /two\r\n",
    ] {
        let run = run_module(
            &lower("fetch('http://example.test/').catch(error => console.log(error.name));"),
            response(302, headers, b""),
            redirect_config(),
        );
        assert_eq!(messages(&run), ["TypeError"], "{headers}");
        one_recorded_request(&run);
    }
}

#[test]
fn redirect_limit_allows_twenty_hops_and_rejects_the_next_one() {
    let source = "fetch('http://example.test/loop') \
        .then(r => console.log(r.status, r.redirected)) \
        .catch(error => console.log(error.name));";
    let mut replies = vec![response(302, "Location: /loop\r\n", b""); 20];
    replies.push(response(200, "", b""));
    let allowed = run_module(&lower(source), Reply::Sequence(replies), redirect_config());
    assert_eq!(messages(&allowed), ["200 true"]);
    assert_recorded_hops(&allowed, 21);

    let refused = run_module(
        &lower(source),
        response(302, "Location: /loop\r\n", b""),
        redirect_config(),
    );
    assert_eq!(messages(&refused), ["TypeError"]);
    assert_recorded_hops(&refused, 21);
}

#[test]
fn received_redirect_provenance_requires_explicit_egress_authorization_and_replays_denial() {
    use frankenengine_engine::baseline_interpreter::IfcRuntimeFlowDecision;

    let source = "try { fetch('http://example.test/start') \
        .catch(() => console.log('caught promise')); } \
        catch (error) { console.log('caught guest'); } console.log('continued');";
    let run = run_case(source, response(302, "Location: /private-target\r\n", b""));
    assert!(matches!(
        &run.result,
        Err(InterpreterError::CapabilityDenied { capability })
            if capability == "net:request:confidentiality"
    ));
    assert!(run.core.console_output().is_empty());
    assert_eq!(run.provider.count(), 1);
    assert!(run.core.ifc_runtime_flow_audit().iter().any(|entry| {
        entry.capability == "net:request"
            && entry.source_label == Label::Internal
            && entry.sink_clearance == Label::Public
            && entry.decision == IfcRuntimeFlowDecision::Denied
    }));
    let entries = run.transcript.finish_execution().unwrap();
    assert_eq!(
        entries.len(),
        2,
        "response and exact refused redirect are recorded"
    );
    assert!(
        matches!(
            &entries[1].1,
            Err(HostIoError::Denied { reason }) if reason == "FLOW_POLICY_BLOCKED"
        ),
        "{:?}",
        entries[1]
    );
    assert!(
        request_parts(&entries[1].0)
            .0
            .starts_with("GET /private-target HTTP/1.1")
    );

    let replay = Arc::new(InMemoryHostIoTranscript::replaying(entries.clone()));
    replay.begin_execution().unwrap();
    let provider = Arc::new(RecordedNetwork::new(Reply::Denied));
    let mut core = InterpreterCore::new(config(), "fetch-redirect-denial-replay");
    core.set_host_io(provider.clone(), Some(replay.clone()));
    let result = core.execute(&lower(source));
    assert!(matches!(
        result,
        Err(InterpreterError::CapabilityDenied { capability })
            if capability == "net:request:confidentiality"
    ));
    assert!(core.console_output().is_empty());
    assert_eq!(provider.count(), 0);
    assert_eq!(replay.finish_execution().unwrap(), entries);
}

#[test]
fn redirected_provider_security_and_quota_failures_remain_fatal() {
    let source = "try { fetch('http://example.test/start') \
        .catch(() => console.log('caught promise')); } \
        catch (error) { console.log('caught guest'); } console.log('continued');";
    for reply in [Reply::Denied, Reply::Budget, Reply::WrongKind] {
        let run = run_module(
            &lower(source),
            Reply::Sequence(vec![
                response(307, "Location: https://other.test/denied\r\n", b""),
                reply.clone(),
            ]),
            redirect_config(),
        );
        match reply {
            Reply::Denied => assert!(matches!(
                &run.result,
                Err(InterpreterError::CapabilityDenied { capability })
                    if capability == "net:request"
            )),
            Reply::Budget | Reply::WrongKind => assert!(
                matches!(&run.result, Err(InterpreterError::InternalError { .. })),
                "{:?}",
                run.result
            ),
            _ => unreachable!(),
        }
        assert!(run.core.console_output().is_empty());
        assert_recorded_hops(&run, 2);
    }

    let transport = run_module(
        &lower("fetch('http://example.test/start').catch(error => console.log(error.name));"),
        Reply::Sequence(vec![
            response(307, "Location: /unavailable\r\n", b""),
            Reply::Transport,
        ]),
        redirect_config(),
    );
    assert_eq!(messages(&transport), ["TypeError"]);
    assert_recorded_hops(&transport, 2);
}

#[test]
fn redirected_responses_replay_every_hop_without_calling_a_live_provider() {
    let source = "fetch('http://example.test/start').then(async r => \
        console.log(r.url, r.redirected, await r.text()));";
    let first = run_module(
        &lower(source),
        Reply::Sequence(vec![
            response(302, "Location: /finish\r\n", b""),
            response(200, "", b"recorded redirect body"),
        ]),
        redirect_config(),
    );
    assert_eq!(
        messages(&first),
        ["http://example.test/finish true recorded redirect body"]
    );
    assert_recorded_hops(&first, 2);
    let entries = first.transcript.finish_execution().unwrap();
    let replay = Arc::new(InMemoryHostIoTranscript::replaying(entries.clone()));
    replay.begin_execution().unwrap();
    let provider = Arc::new(RecordedNetwork::new(Reply::Denied));
    let mut core = InterpreterCore::new(redirect_config(), "fetch-redirect-replay");
    core.set_host_io(provider.clone(), Some(replay.clone()));
    let result = core.execute(&lower(source)).unwrap();
    assert_eq!(
        result.console_output[0].message,
        "http://example.test/finish true recorded redirect body"
    );
    assert_eq!(provider.count(), 0);
    assert_eq!(replay.finish_execution().unwrap(), entries);
}

struct StopNetworkEgress {
    calls: AtomicUsize,
    stop_at: usize,
}

impl InterpreterHook for StopNetworkEgress {
    fn instruction_hooks_enabled(&self) -> bool {
        false
    }

    fn pre_property_access(
        &self,
        _ctx: &HookContext,
        _target: &ObjectRef,
        _key: &PropertyKey,
    ) -> HookAction {
        HookAction::Allow
    }

    fn pre_call(&self, _ctx: &HookContext, _callee: &FunctionRef, _args: &[Value]) -> HookAction {
        HookAction::Allow
    }

    fn pre_allocation(
        &self,
        _ctx: &HookContext,
        _kind: AllocKind,
        _size_hint: usize,
    ) -> HookAction {
        HookAction::Allow
    }

    fn pre_import(&self, _ctx: &HookContext, _specifier: &str) -> HookAction {
        HookAction::Allow
    }

    fn pre_hostcall(&self, _ctx: &HookContext, capability: &str, _allowed: bool) -> HookAction {
        if capability == "net:request"
            && self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.stop_at
        {
            HookAction::Sandbox
        } else {
            HookAction::Allow
        }
    }
}

#[test]
fn live_containment_rechecks_first_egress_after_conversion_and_every_redirect() {
    for (stop_at, expected_requests) in [(2, 0), (3, 1)] {
        let hook = Arc::new(StopNetworkEgress {
            calls: AtomicUsize::new(0),
            stop_at,
        });
        let provider = Arc::new(RecordedNetwork::new(response(
            302,
            "Location: /next\r\n",
            b"",
        )));
        let transcript = Arc::new(InMemoryHostIoTranscript::recording());
        transcript.begin_execution().unwrap();
        let mut core = InterpreterCore::new(redirect_config(), "fetch-live-redirect-gate");
        core.set_host_io(provider.clone(), Some(transcript.clone()));
        core.set_hook(hook.clone());
        let result = core.execute(&lower(
            "try { fetch('http://example.test/start', {get redirect() { return 'follow'; }}) \
             .catch(() => console.log('caught promise')); } \
             catch (error) { console.log('caught guest'); } console.log('continued');",
        ));
        assert!(
            matches!(
                &result,
                Err(InterpreterError::ContainmentActionRequested { action, reason: None })
                    if action == "sandbox"
            ),
            "{result:?}"
        );
        assert!(core.console_output().is_empty());
        assert_eq!(hook.calls.load(Ordering::SeqCst), stop_at);
        assert_eq!(provider.count(), expected_requests);
        assert_eq!(transcript.recorded_entries().len(), expected_requests);
    }
}

fn serve_http_responses(
    listener: std::net::TcpListener,
    replies: Vec<Reply>,
) -> std::thread::JoinHandle<Vec<Vec<u8>>> {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let mut requests = Vec::new();
        for reply in replies {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut peer = loop {
                match listener.accept() {
                    Ok((peer, _)) => break peer,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "expected Fetch hop did not connect"
                        );
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("HTTP test accept failed: {error}"),
                }
            };
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            loop {
                let length = peer.read(&mut chunk).unwrap();
                assert_ne!(length, 0, "client closed before a complete request");
                request.extend_from_slice(&chunk[..length]);
                assert!(
                    request.len() <= 64 * 1024,
                    "test request must remain bounded"
                );
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let body_len = String::from_utf8_lossy(&request[..end])
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
                    if request.len() >= end + 4 + body_len {
                        break;
                    }
                }
            }
            let Reply::Raw(bytes) = reply else {
                panic!("real server requires a raw HTTP response");
            };
            peer.write_all(&bytes).unwrap();
            drop(peer);
            requests.push(request);
        }
        requests
    })
}

#[test]
fn real_redirect_crosses_authorized_sockets_strips_credentials_and_replays_offline() {
    use frankenengine_extension_host::host_io::{
        NetworkDestinationAllowlist, NetworkEgressPolicy, SandboxedHostIo,
    };
    use std::net::TcpListener;
    use std::time::Duration;

    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let first_address = first.local_addr().unwrap();
    let second_address = second.local_addr().unwrap();
    let destination = format!("http://{second_address}/done");
    let first_server = serve_http_responses(
        first,
        vec![response(307, &format!("Location: {destination}\r\n"), b"")],
    );
    let second_server = serve_http_responses(second, vec![response(200, "", b"served")]);
    let root = tempfile::tempdir().unwrap();
    let provider = Arc::new(
        SandboxedHostIo::with_root(root.path())
            .unwrap()
            .with_egress_policy(NetworkEgressPolicy::Allowlist(
                NetworkDestinationAllowlist::new([first_address, second_address]).unwrap(),
            ))
            .with_network_timeout(Duration::from_secs(2))
            .unwrap(),
    );
    let source = format!(
        "fetch('http://{first_address}/start', {{method:'POST', body:'payload',\
         headers:{{Authorization:'Bearer test', Cookie:'session=test', 'X-Keep':'yes'}}}})\
         .then(async r => console.log(r.status, r.url, r.redirected, await r.text()));"
    );
    let module = lower(&source);
    let transcript = Arc::new(InMemoryHostIoTranscript::recording());
    transcript.begin_execution().unwrap();
    let mut core = InterpreterCore::new(redirect_config(), "fetch-real-redirect");
    core.set_host_io(provider.clone(), Some(transcript.clone()));
    let result = core.execute(&module);
    let first_requests = first_server.join().unwrap();
    let second_requests = second_server.join().unwrap();
    let result = result.unwrap();
    assert_eq!(
        result.console_output[0].message,
        format!("200 {destination} true served")
    );
    assert_eq!(first_requests.len(), 1);
    assert_eq!(second_requests.len(), 1);
    let first_wire = String::from_utf8_lossy(&first_requests[0]).to_ascii_lowercase();
    let second_wire = String::from_utf8_lossy(&second_requests[0]).to_ascii_lowercase();
    assert!(first_wire.contains("authorization: bearer test\r\n"));
    assert!(first_wire.contains("cookie: session=test\r\n"));
    assert!(!second_wire.contains("authorization:"));
    assert!(!second_wire.contains("cookie:"));
    assert!(second_wire.starts_with("post /done http/1.1\r\n"));
    assert!(second_wire.contains("x-keep: yes\r\n"));
    assert!(second_wire.ends_with("\r\n\r\npayload"));
    let entries = transcript.finish_execution().unwrap();
    assert_eq!(entries.len(), 2);

    // Both listeners are gone and the actual provider is permanently revoked.
    // A successful replay therefore cannot depend on live network execution.
    provider.network_revocation().revoke();
    let replay = Arc::new(InMemoryHostIoTranscript::replaying(entries.clone()));
    replay.begin_execution().unwrap();
    let mut replay_core = InterpreterCore::new(redirect_config(), "fetch-real-redirect-replay");
    replay_core.set_host_io(provider, Some(replay.clone()));
    let replayed = replay_core.execute(&module).unwrap();
    assert_eq!(replayed.console_output, result.console_output);
    assert_eq!(replay.finish_execution().unwrap(), entries);
}

#[test]
fn real_redirect_rechecks_destination_allowlist_before_opening_the_next_socket() {
    use frankenengine_extension_host::host_io::{
        NetworkDestinationAllowlist, NetworkEgressPolicy, SandboxedHostIo,
    };
    use std::net::TcpListener;
    use std::time::Duration;

    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let denied = TcpListener::bind("127.0.0.1:0").unwrap();
    denied.set_nonblocking(true).unwrap();
    let first_address = first.local_addr().unwrap();
    let denied_address = denied.local_addr().unwrap();
    let server = serve_http_responses(
        first,
        vec![response(
            302,
            &format!("Location: http://{denied_address}/private\r\n"),
            b"",
        )],
    );
    let root = tempfile::tempdir().unwrap();
    let provider = Arc::new(
        SandboxedHostIo::with_root(root.path())
            .unwrap()
            .with_egress_policy(NetworkEgressPolicy::Allowlist(
                NetworkDestinationAllowlist::new([first_address]).unwrap(),
            ))
            .with_network_timeout(Duration::from_secs(2))
            .unwrap(),
    );
    let transcript = Arc::new(InMemoryHostIoTranscript::recording());
    transcript.begin_execution().unwrap();
    let mut core = InterpreterCore::new(redirect_config(), "fetch-redirect-denied-destination");
    core.set_host_io(provider, Some(transcript.clone()));
    let result = core.execute(&lower(&format!(
        "fetch('http://{first_address}/start').catch(() => console.log('caught'));\
         console.log('continued');"
    )));
    assert_eq!(server.join().unwrap().len(), 1);
    assert!(matches!(
        result,
        Err(InterpreterError::CapabilityDenied { capability }) if capability == "net:request"
    ));
    assert!(core.console_output().is_empty());
    assert_eq!(
        transcript.recorded_entries().len(),
        2,
        "record success and denied redirect"
    );
    assert!(matches!(
        denied.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}
