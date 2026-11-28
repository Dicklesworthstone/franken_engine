//! Native Request values cross the real authorized HTTP boundary, including
//! one-use bodies, cancellation, confidentiality and recorded offline replay.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    IfcRuntimeFlowDecision, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_extension_host::host_io::{
    HostIoError, HostIoRecorder, HostIoRequest, HostIoResponse, InMemoryHostIoTranscript,
    NetworkDestinationAllowlist, NetworkEgressPolicy, SandboxedHostIo,
};

fn lower(source: &str) -> Ir3Module {
    let source = format!(
        "function check(value, message) {{ if (!value) throw new Error(message); }}\n{source}"
    );
    lower_source(&source)
}

fn lower_source(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "fetch-request-network.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("Request network fixture parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "fetch-request-network.js"),
        &LoweringContext::new("fetch-request", "decision", "policy"),
    )
    .expect("Request network fixture lowers")
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

fn provider(address: SocketAddr) -> (tempfile::TempDir, Arc<SandboxedHostIo>) {
    let root = tempfile::tempdir().unwrap();
    let provider = Arc::new(
        SandboxedHostIo::with_root(root.path())
            .unwrap()
            .with_egress_policy(NetworkEgressPolicy::Allowlist(
                NetworkDestinationAllowlist::new([address]).unwrap(),
            ))
            .with_network_timeout(Duration::from_secs(2))
            .unwrap(),
    );
    (root, provider)
}

fn recording() -> Arc<InMemoryHostIoTranscript> {
    let transcript = Arc::new(InMemoryHostIoTranscript::recording());
    transcript.begin_execution().unwrap();
    transcript
}

fn assert_no_connection(listener: &TcpListener) {
    listener.set_nonblocking(true).unwrap();
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

fn serve_once(listener: TcpListener) -> std::thread::JoinHandle<Vec<u8>> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut peer = loop {
            match listener.accept() {
                Ok((peer, _)) => break peer,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "Request never reached its socket"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("Request fixture accept failed: {error}"),
            }
        };
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let length = peer.read(&mut chunk).unwrap();
            assert_ne!(length, 0, "client closed before completing its request");
            request.extend_from_slice(&chunk[..length]);
            assert!(request.len() <= 64 * 1024, "fixture request is bounded");
            if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let length = std::str::from_utf8(&request[..end])
                    .unwrap()
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
                if request.len() >= end + 4 + length {
                    break;
                }
            }
        }
        peer.write_all(
            b"HTTP/1.1 201 Created\r\nContent-Length: 6\r\nConnection: close\r\n\r\nstored",
        )
        .unwrap();
        request
    })
}

#[test]
fn request_posts_private_native_bytes_once_and_replays_without_a_live_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = serve_once(listener);
    let (_root, provider) = provider(address);
    let source = format!(
        r#"
        const bytes = new Uint8Array([0, 255, 65]);
        const request = new Request('http://{address}/upload?part=1#local', {{
            method: 'post', headers: {{'X-Source': 'original'}}, body: bytes
        }});
        bytes[2] = 66;
        const copy = request.clone();
        copy.headers.set('X-Source', 'clone');
        request.toString = () => {{ throw new Error('Request was coerced'); }};
        const first = fetch(request);
        check(request.bodyUsed && !copy.bodyUsed, 'fetch consumes only its input body');
        const second = fetch(request).then(
            () => {{ throw new Error('used Request was sent twice'); }},
            error => check(error.name === 'TypeError', 'used body rejection')
        );
        Promise.all([
            first.then(async response => {{
                check(response.status === 201, 'live response status');
                check(await response.text() === 'stored', 'live response body');
            }}),
            copy.bytes().then(value => {{
                check(value.length === 3 && value[0] === 0 && value[1] === 255 && value[2] === 65,
                      'cloned binary snapshot');
                check(copy.headers.get('x-source') === 'clone', 'clone owns its header list');
            }}),
            second
        ]).then(() => console.log('ok')).catch(error => console.log('failed: ' + error.message));
        "#
    );
    let module = lower(&source);
    let transcript = recording();
    let mut core = InterpreterCore::new(config(), "request-real-socket");
    core.set_host_io(provider.clone(), Some(transcript.clone()));
    let outcome = core.execute(&module);
    let wire = server.join().unwrap();
    let result = outcome.expect("native Request completes");
    let messages: Vec<_> = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(messages, ["ok"]);
    let end = wire
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let head = std::str::from_utf8(&wire[..end])
        .unwrap()
        .to_ascii_lowercase();
    assert!(head.starts_with("post /upload?part=1 http/1.1\r\n"));
    assert!(head.contains("\r\nx-source: original"));
    assert!(!head.contains("clone"));
    assert_eq!(&wire[end + 4..], &[0, 255, 65]);
    let entries = transcript.finish_execution().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "used-body rejection creates no second effect"
    );

    // The server has exited and the actual provider is revoked. Recorded bytes
    // must be enough to reproduce construction, consumption and the response.
    provider.network_revocation().revoke();
    let replay = Arc::new(InMemoryHostIoTranscript::replaying(entries.clone()));
    replay.begin_execution().unwrap();
    let mut core = InterpreterCore::new(config(), "request-offline-replay");
    core.set_host_io(provider, Some(replay.clone()));
    let replayed = core.execute(&module).unwrap();
    assert_eq!(replayed.console_output, result.console_output);
    assert_eq!(replay.finish_execution().unwrap(), entries);
}

#[test]
fn dependent_request_abort_cannot_be_suppressed_and_opens_no_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (_root, provider) = provider(address);
    let source = format!(
        r#"
        const controller = new AbortController();
        controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
        controller.signal.addEventListener = () => {{ throw new Error('public listener used'); }};
        const request = new Request('http://{address}/cancelled', {{signal: controller.signal}});
        const copy = request.clone();
        check(request.signal !== controller.signal && copy.signal !== request.signal,
              'request and clone own dependent signals');
        const reason = {{marker: 'cancelled'}};
        controller.abort(reason);
        check(request.signal.aborted && copy.signal.aborted, 'native cancellation dependencies');
        fetch(copy).then(
            () => console.log('failed: cancelled Request completed'),
            error => console.log(error === reason ? 'ok' : 'failed: wrong abort reason')
        );
        "#
    );
    let transcript = recording();
    let mut core = InterpreterCore::new(config(), "request-abort");
    core.set_host_io(provider, Some(transcript.clone()));
    let result = core.execute(&lower(&source)).unwrap();
    let messages: Vec<_> = result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(messages, ["ok"]);
    assert!(transcript.finish_execution().unwrap().is_empty());
    assert_no_connection(&listener);
}

#[test]
fn request_still_obeys_destination_policy_as_an_uncatchable_host_refusal() {
    let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
    let denied = TcpListener::bind("127.0.0.1:0").unwrap();
    let (_root, provider) = provider(allowed.local_addr().unwrap());
    let address = denied.local_addr().unwrap();
    let source = format!(
        r#"
        const request = new Request('http://{address}/denied');
        try {{ fetch(request).catch(() => console.log('promise caught')); }}
        catch (error) {{ console.log('guest caught'); }}
        console.log('continued');
        "#
    );
    let transcript = recording();
    let mut core = InterpreterCore::new(config(), "request-denied-destination");
    core.set_host_io(provider, Some(transcript.clone()));
    let result = core.execute(&lower(&source));
    assert!(matches!(
        result,
        Err(InterpreterError::CapabilityDenied { capability }) if capability == "net:request"
    ));
    assert!(core.console_output().is_empty());
    let entries = transcript.finish_execution().unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(&entries[0].1, Err(HostIoError::Denied { .. })));
    assert_no_connection(&denied);
    assert_no_connection(&allowed);
}

#[test]
fn inherited_and_late_mutated_request_secrets_never_reach_an_allowed_socket() {
    for body in [
        "const request = new Request(url, {method:'POST', body:secret}); fetch(request.clone());",
        "const request = new Request(url); request.headers.set('X-Secret', secret); fetch(request.clone());",
        "const request = new Request(url); fetch(request, {get headers() { request.headers.set('X-Secret', secret); return undefined; }});",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (_root, provider) = provider(address);
        let mut module = lower(&format!(
            "const url = 'http://{address}/private'; const secret = '__request_secret__'; {body}"
        ));
        // Inject an authenticated classified source after lowering rather than
        // pretending a public JavaScript literal is secret by itself.
        let mut replacements = 0;
        for instruction in &mut module.instructions {
            if let Ir3Instruction::LoadStr { dst, pool_index } = *instruction
                && module.constant_pool[pool_index as usize].as_str() == Some("__request_secret__")
            {
                *instruction = Ir3Instruction::Move { dst, src: 255 };
                replacements += 1;
            }
        }
        assert_eq!(replacements, 1);
        let transcript = recording();
        let mut core = InterpreterCore::new(config(), "request-private-egress");
        core.set_host_io(provider, Some(transcript.clone()));
        core.seed_register(255, Value::str("classified request data"))
            .unwrap();
        core.set_register_label(255, Label::Secret).unwrap();
        let result = core.execute(&module);
        assert!(
            matches!(
                &result,
                Err(InterpreterError::CapabilityDenied { capability })
                    if capability == "net:request:confidentiality"
            ),
            "{body}: {result:?}"
        );
        assert!(core.console_output().is_empty());
        assert!(core.ifc_runtime_flow_audit().iter().any(|entry| {
            entry.capability == "net:request"
                && entry.source_label == Label::Secret
                && entry.decision == IfcRuntimeFlowDecision::Denied
        }));
        assert!(
            transcript
                .finish_execution()
                .unwrap()
                .iter()
                .all(|entry| { matches!(&entry.1, Err(HostIoError::Denied { .. })) })
        );
        assert_no_connection(&listener);
    }
}

fn lower_with_classified_request_source(source: &str) -> Ir3Module {
    // These refusal probes use Rust assertions. An unused JavaScript check()
    // helper would introduce an unrelated, unsummarized Error-construction
    // sink under the conservative network exception ceiling.
    let mut module = lower_source(source);
    if let Some(main) = module.function_table.first_mut() {
        main.frame_size = main.frame_size.max(256);
    }
    let mut replacements = 0;
    for instruction in &mut module.instructions {
        if let Ir3Instruction::LoadStr { dst, pool_index } = *instruction
            && module.constant_pool[pool_index as usize].as_str() == Some("__request_secret__")
        {
            *instruction = Ir3Instruction::Move { dst, src: 255 };
            replacements += 1;
        }
    }
    assert_eq!(replacements, 1);
    module
}

// The init object is Public at the outer gate: its accessor closure is not
// a data edge. Only invoking the getter introduces the classified binding.
fn late_classified_request(address: SocketAddr) -> Ir3Module {
    lower_with_classified_request_source(&format!(
        r#"
        const secret = '__request_secret__';
        try {{
            fetch('http://{address}/private?part=1#local', {{
                method: 'POST', headers: {{'X-Public': 'kept'}},
                get body() {{ return secret; }}
            }}).catch(() => console.log('promise caught'));
        }} catch (error) {{ console.log('guest caught'); }}
        console.log('continued');
        "#
    ))
}

fn execute_classified_request(
    module: &Ir3Module,
    provider: Arc<SandboxedHostIo>,
    transcript: Arc<InMemoryHostIoTranscript>,
) -> (InterpreterCore, InterpreterError) {
    let mut core = InterpreterCore::new(config(), "request-converted-ifc-denial");
    core.set_host_io(provider, Some(transcript));
    core.seed_register(255, Value::str("classified request data"))
        .unwrap();
    core.set_register_label(255, Label::Secret).unwrap();
    let error = core
        .execute(module)
        .expect_err("classified request cannot cross the network boundary");
    (core, error)
}

#[test]
fn initial_request_getter_denial_records_exact_bytes_and_replays_offline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (_root, provider) = provider(address);
    let module = late_classified_request(address);
    let transcript = recording();
    let (core, error) = execute_classified_request(&module, provider.clone(), transcript.clone());
    assert!(matches!(
        error,
        InterpreterError::CapabilityDenied { capability }
            if capability == "net:request:confidentiality"
    ));
    assert!(core.console_output().is_empty());
    assert!(core.ifc_runtime_flow_audit().iter().any(|entry| {
        entry.capability == "net:request"
            && entry.source_label == Label::Secret
            && entry.sink_clearance == Label::Public
            && entry.decision == IfcRuntimeFlowDecision::Denied
    }));
    assert_no_connection(&listener);
    let entries = transcript.finish_execution().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "the concrete initial refusal is replayable"
    );
    assert!(matches!(
        &entries[0].1,
        Err(HostIoError::Denied { reason }) if reason == "FLOW_POLICY_BLOCKED"
    ));
    let HostIoRequest::NetworkRequest {
        endpoint,
        payload,
        use_tls,
        ..
    } = &entries[0].0
    else {
        panic!("converted denial must identify the concrete network request");
    };
    assert_eq!(endpoint, &address.to_string());
    assert!(!*use_tls);
    assert_eq!(
        payload,
        format!(
            "POST /private?part=1 HTTP/1.1\r\nHost: {address}\r\n\
             x-public: kept\r\ncontent-type: text/plain;charset=UTF-8\r\n\
             Content-Length: 23\r\nConnection: close\r\n\r\nclassified request data"
        )
        .as_bytes()
    );

    // A refused real request remains replayable after the provider's network
    // authority is revoked. Replaying it must consume its one refusal entry.
    provider.network_revocation().revoke();
    let replay = Arc::new(InMemoryHostIoTranscript::replaying(entries.clone()));
    replay.begin_execution().unwrap();
    let (core, error) = execute_classified_request(&module, provider, replay.clone());
    assert!(matches!(
        error,
        InterpreterError::CapabilityDenied { capability }
            if capability == "net:request:confidentiality"
    ));
    assert!(core.console_output().is_empty());
    assert_eq!(replay.finish_execution().unwrap(), entries);
    assert_no_connection(&listener);
}

#[test]
fn initial_request_getter_denial_rejects_missing_or_changed_replay_evidence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (_root, provider) = provider(address);
    let module = late_classified_request(address);
    let transcript = recording();
    let (_, error) = execute_classified_request(&module, provider.clone(), transcript.clone());
    assert!(matches!(
        error,
        InterpreterError::CapabilityDenied { capability }
            if capability == "net:request:confidentiality"
    ));
    let entries = transcript.finish_execution().unwrap();
    assert_eq!(entries.len(), 1);
    assert_no_connection(&listener);
    provider.network_revocation().revoke();

    let mut changed_request = entries.clone();
    let HostIoRequest::NetworkRequest { payload, .. } = &mut changed_request[0].0 else {
        panic!("recorded denial must contain the concrete request");
    };
    payload.push(b'!');
    let mut changed_outcome = entries.clone();
    changed_outcome[0].1 = Ok(HostIoResponse::NetworkRequest {
        response: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
    });
    for (case, evidence, poisoned) in [
        ("missing refusal", Vec::new(), true),
        ("different request bytes", changed_request, true),
        ("success replacing refusal", changed_outcome, false),
    ] {
        let replay = Arc::new(InMemoryHostIoTranscript::replaying(evidence));
        replay.begin_execution().unwrap();
        let (core, error) = execute_classified_request(&module, provider.clone(), replay.clone());
        assert!(
            matches!(
                &error,
                InterpreterError::InternalError { details }
                    if details.contains("deferred network IFC transcript mismatch")
            ),
            "{case}: {error:?}"
        );
        assert!(core.console_output().is_empty(), "{case}");
        // Request divergence poisons the recorder itself. A matching request
        // with the wrong outcome is consumed, then refused by the interpreter.
        assert_eq!(replay.finish_execution().is_err(), poisoned, "{case}");
        assert_no_connection(&listener);
    }
}

#[test]
fn initial_argument_ifc_denial_does_not_invent_a_converted_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (_root, provider) = provider(address);
    let module = lower_with_classified_request_source(&format!(
        r#"
        const secret = '__request_secret__';
        try {{
            fetch('http://{address}/private', {{
                method: 'POST', body: secret,
                get headers() {{ throw 'argument conversion ran'; }}
            }}).catch(() => console.log('promise caught'));
        }} catch (error) {{ console.log('guest caught'); }}
        console.log('continued');
        "#
    ));
    let transcript = recording();
    let (core, error) = execute_classified_request(&module, provider, transcript.clone());
    // The static HostCall's pre-dispatch check names net:fetch; a first-class
    // call names the shared native net:request gate. Both must remain fatal
    // before conversion and before any concrete request can be recorded.
    assert!(
        matches!(
            &error,
            InterpreterError::CapabilityDenied { capability }
                if matches!(capability.as_str(),
                    "net:fetch:confidentiality" | "net:request:confidentiality")
        ),
        "early argument refusal: {error:?}"
    );
    assert!(core.console_output().is_empty());
    assert!(transcript.finish_execution().unwrap().is_empty());
    assert_no_connection(&listener);
}
