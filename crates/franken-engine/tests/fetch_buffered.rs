//! Buffered Fetch through the native parser, lowering, interpreter and recorded
//! host-I/O bridge. Providers return deterministic HTTP bytes; no external
//! server is needed. Streaming/redirect following and public Fetch constructors
//! are outside this slice. Request header values currently require ASCII.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_extension_host::host_io::budget::HostIoBudgetError;
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoError, HostIoOutcome, HostIoProvider, HostIoRecorder,
    HostIoRequest, HostIoResponse, InMemoryHostIoTranscript,
};

#[derive(Clone, Debug)]
enum Reply {
    Raw(Vec<u8>),
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
        self.requests.lock().unwrap().push(request.clone());
        match &self.reply {
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
            1,
            "Fetch checks the existing request operation exactly once",
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
