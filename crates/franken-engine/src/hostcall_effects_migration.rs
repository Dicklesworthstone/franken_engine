//! Migration of hostcall + capability model to algebraic effects.
//!
//! This module implements the migration from the current hostcall dispatch system
//! to the algebraic effects substrate. Each hostcall family becomes an Effect,
//! and each capability profile becomes a Handler in the HandlerStack.
//!
//! Track PP.3 (bd-cixqu.42.3) - Migrate hostcall + capability model to algebraic effects.

#![forbid(unsafe_code)]

use std::any::{Any, TypeId};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::algebraic_effects::{
    Effect, EffectCapabilities, EffectError, EffectPriority, EffectResult, ErasedEffect, Handler,
    HandlerStack, ProcSpawnEffect,
};
use crate::capability::{CapabilityProfile, ProfileKind, RuntimeCapability};
use frankenengine_extension_host::host_effect_journal::{
    HostEffectJournalError, HostEffectJournalMode, InMemoryHostEffectJournal,
};
use frankenengine_extension_host::host_io::{
    FsOperation, HostIoCapability, HostIoError, HostIoProvider, HostIoRecorder, HostIoRequest,
    HostIoResponse, SANDBOXED_HOST_IO_MAX_BYTES,
};
use frankenengine_extension_host::process_spawn::{
    ProcessSpawnCapability, ProcessSpawnError, ProcessSpawnProvider, ProcessSpawnRecorder,
    ProcessSpawnRequest, ProcessSpawnResponse, perform_recorded,
};

// ---------------------------------------------------------------------------
// Hostcall Effect implementations
// ---------------------------------------------------------------------------

/// Console hostcall effect (log, error, warn, info).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleHostcallEffect {
    pub method: String, // "log", "error", "warn", "info"
    pub args: Vec<String>,
}

impl Effect for ConsoleHostcallEffect {
    type Output = ();

    fn effect_name(&self) -> &'static str {
        "hostcall:console"
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::Console])
    }

    fn priority(&self) -> EffectPriority {
        EffectPriority::Normal
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((self.method.clone(), self.args.clone()))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(String, Vec<String>)>()
    }
}

/// Filesystem hostcall effect. The security capability remains the existing
/// read/write class while `operation` records the concrete filesystem action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsHostcallEffect {
    pub operation: FsOperation,
    pub path: String,
    pub arguments: Vec<String>,
    pub content: Option<Vec<u8>>,
}

impl Effect for FsHostcallEffect {
    type Output = ();

    fn effect_name(&self) -> &'static str {
        match self.operation.required_capability() {
            HostIoCapability::FsRead => "hostcall:fs:read",
            HostIoCapability::FsWrite => "hostcall:fs:write",
            HostIoCapability::NetworkSend | HostIoCapability::NetworkRecv => {
                unreachable!("filesystem operations cannot require a network capability")
            }
        }
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        match self.operation.required_capability() {
            HostIoCapability::FsRead => EffectCapabilities::runtime([RuntimeCapability::FsRead]),
            HostIoCapability::FsWrite => EffectCapabilities::runtime([RuntimeCapability::FsWrite]),
            HostIoCapability::NetworkSend | HostIoCapability::NetworkRecv => {
                unreachable!("filesystem operations cannot require a network capability")
            }
        }
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((
            self.operation,
            self.path.clone(),
            self.arguments.clone(),
            self.content.clone(),
        ))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(FsOperation, String, Vec<String>, Option<Vec<u8>>)>()
    }
}

/// Network hostcall effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHostcallEffect {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl Effect for NetworkHostcallEffect {
    type Output = ();

    fn effect_name(&self) -> &'static str {
        "hostcall:network"
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::NetworkEgress])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((
            self.url.clone(),
            self.method.clone(),
            self.headers.clone(),
            self.body.clone(),
        ))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(String, String, Vec<(String, String)>, Option<Vec<u8>>)>()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Timer hostcall effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimerHostcallEffect {
    pub operation: TimerOperation,
    pub duration_ms: Option<u64>,
    pub timer_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimerOperation {
    SetTimeout,
    SetInterval,
    ClearTimeout,
    ClearInterval,
}

impl Effect for TimerHostcallEffect {
    type Output = ();

    fn effect_name(&self) -> &'static str {
        "hostcall:timer"
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::Timer])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((self.operation.clone(), self.duration_ms, self.timer_id))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(TimerOperation, Option<u64>, Option<u64>)>()
    }
}

/// Module loading hostcall effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleHostcallEffect {
    pub module_path: String,
    pub import_type: ModuleImportType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModuleImportType {
    Require,
    EsModuleImport,
}

impl Effect for ModuleHostcallEffect {
    type Output = ();

    fn effect_name(&self) -> &'static str {
        "hostcall:module"
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::ModuleLoad])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((self.module_path.clone(), self.import_type.clone()))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(String, ModuleImportType)>()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleExports {
    pub default: Option<String>,      // Serialized value
    pub named: Vec<(String, String)>, // name -> serialized value
}

// ---------------------------------------------------------------------------
// Capability Profile Handlers
// ---------------------------------------------------------------------------

/// Handler implementing FullCaps capability profile.
///
/// With no host I/O provider installed, filesystem and network hostcalls remain
/// fail-closed and return `CapabilityDenied`, preserving the bd-6wc97 posture.
/// When a sandboxed provider is deliberately installed, those requests are
/// routed to the provider after capability mapping. The engine never performs
/// host filesystem or network I/O directly.
#[derive(Debug, Default)]
pub struct FullCapsHandler {
    host_io: Option<Arc<dyn HostIoProvider>>,
    host_io_recorder: Option<Arc<dyn HostIoRecorder>>,
    host_effect_journal: Option<Arc<InMemoryHostEffectJournal>>,
}

impl FullCapsHandler {
    /// Construct a FullCaps handler with no host I/O provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a FullCaps handler backed by a sandboxed host I/O provider.
    #[must_use]
    pub fn with_host_io(provider: Arc<dyn HostIoProvider>) -> Self {
        Self {
            host_io: Some(provider),
            host_io_recorder: None,
            host_effect_journal: None,
        }
    }

    /// Construct a FullCaps handler with host I/O record/replay enabled.
    #[must_use]
    pub fn with_host_io_recorded(
        provider: Arc<dyn HostIoProvider>,
        recorder: Arc<dyn HostIoRecorder>,
    ) -> Self {
        Self {
            host_io: Some(provider),
            host_io_recorder: Some(recorder),
            host_effect_journal: None,
        }
    }

    /// Construct the ordinary host-I/O handler with an optional globally
    /// ordered journal. Process execution remains a separate handler and trust
    /// boundary.
    #[must_use]
    pub fn with_effect_providers(
        host_io: Option<Arc<dyn HostIoProvider>>,
        host_io_recorder: Option<Arc<dyn HostIoRecorder>>,
        host_effect_journal: Option<Arc<InMemoryHostEffectJournal>>,
    ) -> Self {
        Self {
            host_io,
            host_io_recorder,
            host_effect_journal,
        }
    }

    /// Whether this handler dispatches side-effecting hostcalls
    /// (`fs:read` / `fs:write` / `network`) to the engine's real hostcall
    /// implementations.
    ///
    /// Returns `true` only when an extension-host provider has been installed.
    /// With no provider, no real in-engine fs/network executor exists. Rather
    /// than SIMULATE those effects (the prior behaviour
    /// — fake fs reads / discarded writes / hardcoded network responses, which
    /// handed callers fake data while claiming full capability),
    /// [`FullCapsHandler::handle`] now EXPLICITLY DENIES `fs:read`, `fs:write`
    /// and `network` with `CapabilityDenied`.
    #[must_use]
    pub fn dispatches_real_hostcalls(&self) -> bool {
        self.host_io.is_some()
    }

    fn route_host_io(
        &self,
        effect: &dyn ErasedEffect,
    ) -> Result<Option<EffectResult>, EffectError> {
        let Some(provider) = self.host_io.as_deref() else {
            return Err(EffectError::CapabilityDenied {
                required: effect.required_capabilities(),
            });
        };

        let request = Self::host_io_request_from_effect(effect)?;
        let granted = [request.required_capability()];
        let outcome = if let Some(journal) = self.host_effect_journal.as_deref() {
            match journal.replay_host_io(&request) {
                Some(recorded) => recorded,
                None => {
                    let reservation = journal
                        .reserve_host_io(&request)
                        .map_err(|error| host_effect_journal_error("full_caps_handler", error))?;
                    let live = provider.perform(&request, &granted);
                    journal
                        .complete_host_io(reservation, &request, &live)
                        .map_err(|error| host_effect_journal_error("full_caps_handler", error))?;
                    live
                }
            }
        } else {
            match self
                .host_io_recorder
                .as_deref()
                .and_then(|recorder| recorder.replay(&request))
            {
                Some(recorded) => recorded,
                None => {
                    let live = provider.perform(&request, &granted);
                    if let Some(recorder) = self.host_io_recorder.as_deref() {
                        recorder.record(&request, &live);
                    }
                    live
                }
            }
        };

        match outcome {
            Ok(response) => Ok(Some(Self::effect_result_from_host_io(&response))),
            Err(HostIoError::Io { detail }) => Err(EffectError::HandlerError {
                handler: "full_caps_handler".to_string(),
                message: detail,
                code: None,
            }),
            Err(HostIoError::Fs { code, detail }) => Err(EffectError::HandlerError {
                handler: "full_caps_handler".to_string(),
                message: detail,
                code: Some(code),
            }),
            Err(_) => Err(EffectError::CapabilityDenied {
                required: effect.required_capabilities(),
            }),
        }
    }

    fn host_io_request_from_effect(
        effect: &dyn ErasedEffect,
    ) -> Result<HostIoRequest, EffectError> {
        match effect.effect_name() {
            "hostcall:fs:read" | "hostcall:fs:write" => {
                let params = effect
                    .parameters()
                    .downcast::<(FsOperation, String, Vec<String>, Option<Vec<u8>>)>()
                    .map_err(|_| EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected (FsOperation, String, Vec<String>, Option<Vec<u8>>) parameters".to_string(),
                    })?;
                let (operation, path, arguments, content) = *params;
                Ok(match operation {
                    FsOperation::Read => HostIoRequest::FsRead { path },
                    FsOperation::Write => HostIoRequest::FsWrite {
                        path,
                        data: content.unwrap_or_default(),
                    },
                    _ => HostIoRequest::FsMeta {
                        operation,
                        path,
                        arguments,
                        data: content.unwrap_or_default(),
                    },
                })
            }
            "hostcall:network" => {
                let params = effect
                    .parameters()
                    .downcast::<(String, String, Vec<(String, String)>, Option<Vec<u8>>)>()
                    .map_err(|_| EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected (url, method, headers, body) network parameters"
                            .to_string(),
                    })?;
                let (url, method, headers, body) = *params;
                // bd-656a2: turn the semantic http intent (url + method + headers
                // + body) into the raw wire request the network mechanism sends.
                // The url is split into a concrete `host:port` connect endpoint
                // (so `SandboxedHostIo::connect`'s `to_socket_addrs` can resolve
                // it) and an HTTP/1.1 request line + Host header + body payload.
                let (endpoint, payload, use_tls) =
                    http_request_to_wire(&url, &method, &headers, body.as_deref());
                // bd-3894s slice (4): route the egress as a single-socket
                // round trip so the guest can observe the real response. The
                // response read is bounded by the same per-operation byte cap the
                // provider enforces. (`NetworkSend` would only carry the egress and
                // close the socket before any reply could be read.)
                // bd-3894s slice (5): an https URL sets `use_tls` so the network
                // mechanism performs the round trip inside a real TLS session.
                Ok(HostIoRequest::NetworkRequest {
                    endpoint,
                    payload,
                    max_len: SANDBOXED_HOST_IO_MAX_BYTES,
                    use_tls,
                })
            }
            other => Err(EffectError::InvalidParameters {
                effect_name: other.to_string(),
                reason: "not an fs/network hostcall".to_string(),
            }),
        }
    }

    fn effect_result_from_host_io(response: &HostIoResponse) -> EffectResult {
        match response {
            HostIoResponse::FsRead { bytes } => EffectResult::new(bytes.clone()),
            HostIoResponse::FsWrite { bytes_written } => EffectResult::new(*bytes_written),
            HostIoResponse::FsMeta { result } => EffectResult::new(result.clone()),
            HostIoResponse::NetworkSend { bytes_sent } => EffectResult::new(*bytes_sent),
            HostIoResponse::NetworkRecv { bytes } => EffectResult::new(bytes.clone()),
            // bd-3894s slice (4): the raw response bytes flow back to the
            // interpreter, which parses them into a JS response object.
            HostIoResponse::NetworkRequest { response } => EffectResult::new(response.clone()),
        }
    }
}

const fn process_spawn_error_code(error: &ProcessSpawnError) -> &'static str {
    match error {
        ProcessSpawnError::Denied { .. } => "PROCESS_SPAWN_DENIED",
        ProcessSpawnError::FlowPolicyBlocked => "PROCESS_SPAWN_FLOW_POLICY_BLOCKED",
        ProcessSpawnError::CapabilityMissing { .. } => "PROCESS_SPAWN_CAPABILITY_MISSING",
        ProcessSpawnError::PolicyViolation { .. } => "PROCESS_SPAWN_POLICY_VIOLATION",
        ProcessSpawnError::LimitExceeded { .. } => "PROCESS_SPAWN_LIMIT_EXCEEDED",
        ProcessSpawnError::UnknownHandle { .. } => "PROCESS_SPAWN_UNKNOWN_HANDLE",
        ProcessSpawnError::InvalidState { .. } => "PROCESS_SPAWN_INVALID_STATE",
        ProcessSpawnError::NotImplemented { .. } => "PROCESS_SPAWN_NOT_IMPLEMENTED",
        ProcessSpawnError::TimedOut { .. } => "PROCESS_SPAWN_TIMED_OUT",
        ProcessSpawnError::Io { .. } => "PROCESS_SPAWN_IO",
        ProcessSpawnError::ReplayDivergence { .. } => "PROCESS_SPAWN_REPLAY_DIVERGENCE",
    }
}

fn host_effect_journal_error(handler: &str, error: HostEffectJournalError) -> EffectError {
    EffectError::HandlerError {
        handler: handler.to_string(),
        message: error.to_string(),
        code: Some("HOST_EFFECT_JOURNAL".to_string()),
    }
}

/// Stable error code returned when the algebraic-effects migration stack is
/// asked to execute a timer without an interpreter-owned event-loop provider.
///
/// The production JavaScript timer implementation lives in `InterpreterCore`;
/// this migration handler has no callback, cell permit, cancellation token, or
/// replay recorder to hand to that implementation. Returning a timer handle
/// here would therefore fabricate successful scheduling.
pub const TIMER_PROVIDER_UNAVAILABLE_CODE: &str = "TIMER_PROVIDER_UNAVAILABLE";

fn reject_unbound_timer(
    handler: &'static str,
    effect: &dyn ErasedEffect,
) -> Result<Option<EffectResult>, EffectError> {
    let params = effect
        .parameters()
        .downcast::<(TimerOperation, Option<u64>, Option<u64>)>()
        .map_err(|_| EffectError::InvalidParameters {
            effect_name: effect.effect_name().to_string(),
            reason: "Expected (TimerOperation, Option<u64>, Option<u64>) parameters".to_string(),
        })?;
    let (operation, duration_ms, timer_id) = *params;
    let invalid_reason = match operation {
        TimerOperation::SetTimeout | TimerOperation::SetInterval => match (duration_ms, timer_id) {
            (None, _) => Some("set timer operation requires duration_ms"),
            (Some(_), Some(_)) => Some("set timer operation must not include timer_id"),
            (Some(_), None) => None,
        },
        TimerOperation::ClearTimeout | TimerOperation::ClearInterval => {
            match (duration_ms, timer_id) {
                (_, None) => Some("clear timer operation requires timer_id"),
                (Some(_), Some(_)) => Some("clear timer operation must not include duration_ms"),
                (None, Some(_)) => None,
            }
        }
    };
    if let Some(reason) = invalid_reason {
        return Err(EffectError::InvalidParameters {
            effect_name: effect.effect_name().to_string(),
            reason: reason.to_string(),
        });
    }

    Err(EffectError::HandlerError {
        handler: handler.to_string(),
        message: "timer effect requires an interpreter-owned event-loop provider".to_string(),
        code: Some(TIMER_PROVIDER_UNAVAILABLE_CODE.to_string()),
    })
}

impl Handler for FullCapsHandler {
    fn can_handle(&self, effect_name: &str) -> bool {
        effect_name.starts_with("hostcall:")
    }

    fn handle(&self, effect: &dyn ErasedEffect) -> Result<Option<EffectResult>, EffectError> {
        // FullCaps is permitted to invoke all hostcalls, but `fs:read`,
        // `fs:write`, and `network` are explicitly denied unless a sandboxed
        // extension-host provider is installed. `console` and `module` keep
        // their in-process migration paths. Timer effects fail closed until an
        // interpreter-owned event-loop provider is explicitly installed; this
        // handler cannot manufacture a callback-bearing timer.
        match effect.effect_name() {
            "hostcall:console" => {
                if let Ok(params) = effect.parameters().downcast::<(String, Vec<String>)>() {
                    let (method, args) = *params;
                    // Simulate console output
                    match method.as_str() {
                        "log" => println!("[LOG] {}", args.join(" ")),
                        "error" => eprintln!("[ERROR] {}", args.join(" ")),
                        "warn" => eprintln!("[WARN] {}", args.join(" ")),
                        "info" => println!("[INFO] {}", args.join(" ")),
                        _ => {
                            return Err(EffectError::InvalidParameters {
                                effect_name: effect.effect_name().to_string(),
                                reason: format!("Unknown console method: {}", method),
                            });
                        }
                    }
                    Ok(Some(EffectResult::new(())))
                } else {
                    Err(EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected (String, Vec<String>) parameters".to_string(),
                    })
                }
            }
            "hostcall:fs:read" | "hostcall:fs:write" | "hostcall:network" => {
                // bd-6wc97 / bd-6wc97.1 decision: EXPLICIT-DENY by design.
                // There is no real in-engine fs/network executor (only
                // `MockFsHandler`); routing to host `std::fs`/sockets would be a
                // sandbox escape. If an extension-host provider is installed,
                // route the request there; otherwise keep the explicit deny.
                // These arms previously
                // SIMULATED the effects — a canned fs read, a discarded write,
                // a hardcoded network response — handing callers FAKE data while
                // the Full profile claimed full capability. That is exactly the
                // dishonesty `bd-1lw7r.11` guards against, so deny rather than
                // fake.
                self.route_host_io(effect)
            }
            "hostcall:timer" => reject_unbound_timer(self.handler_name(), effect),
            "hostcall:module" => {
                if let Ok(params) = effect.parameters().downcast::<(String, ModuleImportType)>() {
                    let (module_path, import_type) = *params;
                    // Simulate module loading
                    let exports = ModuleExports {
                        default: Some(format!(
                            r#"{{"module": "{}", "type": "{:?}"}}"#,
                            module_path, import_type
                        )),
                        named: vec![
                            ("version".to_string(), r#""1.0.0""#.to_string()),
                            ("name".to_string(), format!(r#""{}""#, module_path)),
                        ],
                    };
                    Ok(Some(EffectResult::new(exports)))
                } else {
                    Err(EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected module parameters".to_string(),
                    })
                }
            }
            _ => Ok(None), // Unknown effect, let other handlers try
        }
    }

    fn provided_capabilities(&self) -> EffectCapabilities {
        // Extraordinary process authority is never provided by an ordinary
        // profile handler. It appears only when a ProcessSpawnHandler backed by
        // an explicitly installed provider joins the stack.
        EffectCapabilities::runtime(
            RuntimeCapability::ALL
                .iter()
                .copied()
                .filter(|capability| *capability != RuntimeCapability::ProcessSpawn),
        )
    }

    fn priority(&self) -> EffectPriority {
        EffectPriority::High
    }

    fn handler_name(&self) -> &'static str {
        "full_caps_handler"
    }
}

/// Extraordinary process authority is orthogonal to every ordinary profile.
/// This handler exists only when the product installs a provider backed by a
/// live signed admission; its presence is the handler-stack capability witness.
#[derive(Debug)]
pub struct ProcessSpawnHandler {
    provider: Arc<dyn ProcessSpawnProvider>,
    recorder: Option<Arc<dyn ProcessSpawnRecorder>>,
    host_effect_journal: Option<Arc<InMemoryHostEffectJournal>>,
}

impl ProcessSpawnHandler {
    #[must_use]
    pub fn new(
        provider: Arc<dyn ProcessSpawnProvider>,
        recorder: Option<Arc<dyn ProcessSpawnRecorder>>,
        host_effect_journal: Option<Arc<InMemoryHostEffectJournal>>,
    ) -> Self {
        Self {
            provider,
            recorder,
            host_effect_journal,
        }
    }

    #[must_use]
    pub const fn dispatches_real_process_spawn(&self) -> bool {
        true
    }

    fn journaled_outcome(
        &self,
        journal: &InMemoryHostEffectJournal,
        request: &ProcessSpawnRequest,
        granted: &[ProcessSpawnCapability],
    ) -> Result<Result<ProcessSpawnResponse, ProcessSpawnError>, EffectError> {
        if journal.mode() == HostEffectJournalMode::Replay {
            return Ok(match self.provider.prepare_request(request) {
                Ok(prepared) => journal.replay_process_spawn(&prepared).ok_or_else(|| {
                    host_effect_journal_error(
                        "process_spawn_handler",
                        HostEffectJournalError::Lifecycle {
                            detail: "replay journal omitted a typed process outcome".to_string(),
                        },
                    )
                })?,
                Err(failure) => journal
                    .replay_process_spawn_preparation_failure(request, &failure)
                    .ok_or_else(|| {
                        host_effect_journal_error(
                            "process_spawn_handler",
                            HostEffectJournalError::Lifecycle {
                                detail: "replay journal omitted a typed preparation outcome"
                                    .to_string(),
                            },
                        )
                    })?,
            });
        }
        let reservation = journal
            .reserve_process_spawn(request)
            .map_err(|error| host_effect_journal_error("process_spawn_handler", error))?;
        let prepared = match self.provider.prepare_request(request) {
            Ok(prepared) => prepared,
            Err(error) => {
                let outcome = Err(error);
                journal
                    .complete_process_spawn(reservation, request, &outcome)
                    .map_err(|error| host_effect_journal_error("process_spawn_handler", error))?;
                return Ok(outcome);
            }
        };
        let reservation = journal
            .bind_prepared_process_spawn(reservation, &prepared)
            .map_err(|error| host_effect_journal_error("process_spawn_handler", error))?;
        let outcome = self.provider.perform(&prepared, granted);
        journal
            .complete_process_spawn(reservation, &prepared, &outcome)
            .map_err(|error| host_effect_journal_error("process_spawn_handler", error))?;
        Ok(outcome)
    }

    fn route(&self, effect: &dyn ErasedEffect) -> Result<Option<EffectResult>, EffectError> {
        let request = effect
            .parameters()
            .downcast::<ProcessSpawnRequest>()
            .map_err(|_| EffectError::InvalidParameters {
                effect_name: effect.effect_name().to_string(),
                reason: "expected a typed ProcessSpawnRequest".to_string(),
            })?;
        let granted = [ProcessSpawnCapability::Spawn];
        let outcome = if let Some(journal) = self.host_effect_journal.as_deref() {
            self.journaled_outcome(journal, request.as_ref(), &granted)?
        } else {
            perform_recorded(
                self.provider.as_ref(),
                self.recorder.as_deref(),
                request.as_ref(),
                &granted,
            )
        };
        match outcome {
            Ok(response) => Ok(Some(EffectResult::new(response))),
            // Reaching this handler already proves that the typed
            // `ProcessSpawn` capability was present in the stack. Preserve the
            // provider's concrete denial/limit/I/O reason as a handler error so
            // the interpreter can construct Node's catchable child-process
            // error shape while the journal retains the exact denied outcome.
            // Converting policy denials back into `CapabilityDenied` here would
            // erase `executable_alias_denied`, timeout, and ENOENT-relevant
            // evidence after the real capability gate had already succeeded.
            Err(error) => Err(EffectError::HandlerError {
                handler: "process_spawn_handler".to_string(),
                message: error.to_string(),
                code: Some(process_spawn_error_code(&error).to_string()),
            }),
        }
    }
}

impl Handler for ProcessSpawnHandler {
    fn can_handle(&self, effect_name: &str) -> bool {
        effect_name == "proc:spawn"
    }

    fn handle(&self, effect: &dyn ErasedEffect) -> Result<Option<EffectResult>, EffectError> {
        self.route(effect)
    }

    fn provided_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::ProcessSpawn])
    }

    fn priority(&self) -> EffectPriority {
        EffectPriority::Critical
    }

    fn handler_name(&self) -> &'static str {
        "process_spawn_handler"
    }
}

/// Handler implementing EngineCoreCaps capability profile.
#[derive(Debug)]
pub struct EngineCoreHandler;

impl Handler for EngineCoreHandler {
    fn can_handle(&self, effect_name: &str) -> bool {
        matches!(
            effect_name,
            "hostcall:console" | "hostcall:timer" | "hostcall:builtin"
        )
    }

    fn handle(&self, effect: &dyn ErasedEffect) -> Result<Option<EffectResult>, EffectError> {
        match effect.effect_name() {
            "hostcall:console" => {
                if let Ok(params) = effect.parameters().downcast::<(String, Vec<String>)>() {
                    let (method, args) = *params;
                    // EngineCore allows console operations
                    match method.as_str() {
                        "log" => println!("[ENGINE-LOG] {}", args.join(" ")),
                        "error" => eprintln!("[ENGINE-ERROR] {}", args.join(" ")),
                        "warn" => eprintln!("[ENGINE-WARN] {}", args.join(" ")),
                        "info" => println!("[ENGINE-INFO] {}", args.join(" ")),
                        _ => {
                            return Err(EffectError::InvalidParameters {
                                effect_name: effect.effect_name().to_string(),
                                reason: format!("Unknown console method: {}", method),
                            });
                        }
                    }
                    Ok(Some(EffectResult::new(())))
                } else {
                    Err(EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected console parameters".to_string(),
                    })
                }
            }
            "hostcall:timer" => reject_unbound_timer(self.handler_name(), effect),
            _ => Ok(None), // Not handled by EngineCore
        }
    }

    fn provided_capabilities(&self) -> EffectCapabilities {
        use RuntimeCapability::*;
        EffectCapabilities::runtime([
            VmDispatch,
            GcInvoke,
            IrLowering,
            HeapAllocate,
            Console,
            Timer,
            Builtin,
        ])
    }

    fn priority(&self) -> EffectPriority {
        EffectPriority::Normal
    }

    fn handler_name(&self) -> &'static str {
        "engine_core_handler"
    }
}

/// Handler implementing ComputeOnlyCaps (denies all hostcalls).
#[derive(Debug)]
pub struct ComputeOnlyHandler;

impl Handler for ComputeOnlyHandler {
    fn can_handle(&self, effect_name: &str) -> bool {
        effect_name.starts_with("hostcall:")
    }

    fn handle(&self, effect: &dyn ErasedEffect) -> Result<Option<EffectResult>, EffectError> {
        // ComputeOnly denies all hostcalls
        Err(EffectError::CapabilityDenied {
            required: effect.required_capabilities(),
        })
    }

    fn provided_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::none() // No capabilities provided
    }

    fn priority(&self) -> EffectPriority {
        EffectPriority::High // High priority to block before others
    }

    fn handler_name(&self) -> &'static str {
        "compute_only_handler"
    }
}

/// Handler granting the `PolicyCaps` capability set.
///
/// This is a capability-granting handler, NOT an executor: the algebraic-effects
/// migration bridge has no concrete `policy:*` effect executors yet, so `handle`
/// always defers (`Ok(None)`) and `can_handle` is `false`. Its sole job is to
/// surface the canonical Policy capability set via `provided_capabilities` so a
/// `HandlerStack` built from a `Policy` profile aggregates the right gate
/// (`HandlerStack::update_capabilities`). With the gate correct, a policy effect
/// whose required capabilities are granted but unimplemented surfaces as
/// `EffectError::Unhandled` (honest) rather than `CapabilityDenied` (wrong) — the
/// behaviour when this arm was the `ComputeOnlyHandler` placeholder, which
/// stripped the profile to zero capabilities.
#[derive(Debug)]
pub struct PolicyCapsHandler;

impl Handler for PolicyCapsHandler {
    fn can_handle(&self, _effect_name: &str) -> bool {
        // No concrete policy:* effect executor exists in the migration bridge.
        false
    }

    fn handle(&self, _effect: &dyn ErasedEffect) -> Result<Option<EffectResult>, EffectError> {
        Ok(None)
    }

    fn provided_capabilities(&self) -> EffectCapabilities {
        use RuntimeCapability::*;
        // Mirrors CapabilityProfile::policy() in capability.rs.
        EffectCapabilities::runtime([PolicyRead, PolicyWrite, EvidenceEmit, DecisionInvoke])
    }

    fn priority(&self) -> EffectPriority {
        EffectPriority::Normal
    }

    fn handler_name(&self) -> &'static str {
        "policy_caps_handler"
    }
}

/// Handler granting the `RemoteCaps` capability set.
///
/// Capability-granting handler with the same contract as [`PolicyCapsHandler`]:
/// it surfaces the canonical Remote capability set so a `Remote` profile's
/// `HandlerStack` gates correctly, but defers execution (no `remote:*` effect
/// executor exists in the migration bridge yet).
#[derive(Debug)]
pub struct RemoteCapsHandler;

impl Handler for RemoteCapsHandler {
    fn can_handle(&self, _effect_name: &str) -> bool {
        false
    }

    fn handle(&self, _effect: &dyn ErasedEffect) -> Result<Option<EffectResult>, EffectError> {
        Ok(None)
    }

    fn provided_capabilities(&self) -> EffectCapabilities {
        use RuntimeCapability::*;
        // Mirrors CapabilityProfile::remote() in capability.rs.
        EffectCapabilities::runtime([NetworkEgress, LeaseManagement, IdempotencyDerive])
    }

    fn priority(&self) -> EffectPriority {
        EffectPriority::Normal
    }

    fn handler_name(&self) -> &'static str {
        "remote_caps_handler"
    }
}

// ---------------------------------------------------------------------------
// Migration API
// ---------------------------------------------------------------------------

/// Create a HandlerStack from a CapabilityProfile.
///
/// This function migrates the old capability model to the new algebraic effects model
/// by creating appropriate handlers for each profile type.
pub fn create_handler_stack_from_profile(profile: &CapabilityProfile) -> HandlerStack {
    let mut stack = HandlerStack::new();

    match profile.kind() {
        ProfileKind::Full => {
            stack.add_handler(Arc::new(FullCapsHandler::new()));
        }
        ProfileKind::EngineCore => {
            stack.add_handler(Arc::new(EngineCoreHandler));
        }
        ProfileKind::Policy => {
            // Grants the canonical PolicyCaps set so the stack gate matches the
            // profile (previously stripped to ComputeOnly — zero capabilities).
            stack.add_handler(Arc::new(PolicyCapsHandler));
        }
        ProfileKind::Remote => {
            // Grants the canonical RemoteCaps set so the stack gate matches the
            // profile (previously stripped to ComputeOnly — zero capabilities).
            stack.add_handler(Arc::new(RemoteCapsHandler));
        }
        ProfileKind::ComputeOnly => {
            stack.add_handler(Arc::new(ComputeOnlyHandler));
        }
    }

    stack
}

/// Like [`create_handler_stack_from_profile`], but for the `Full` profile installs
/// a [`FullCapsHandler`] backed by a real sandboxed [`HostIoProvider`] (optionally
/// wrapped in a [`HostIoRecorder`] for deterministic replay) so `fs` / `network`
/// hostcalls dispatch to actual host I/O instead of the fail-closed deny default.
///
/// Non-`Full` profiles never perform host I/O, so they ignore `host_io` and build
/// exactly as [`create_handler_stack_from_profile`]. This is the engine-side seam
/// for the proof-carrying host-effect pipeline (bd-f5b04.2.6): the product layer
/// constructs a sandboxed provider (plus a recorder for replay) and threads it
/// here so a `run` actually produces and records real effects. Installing the
/// provider is what makes [`FullCapsHandler::dispatches_real_hostcalls`] report
/// `true`.
pub fn create_handler_stack_from_profile_with_host_io(
    profile: &CapabilityProfile,
    host_io: Arc<dyn HostIoProvider>,
    recorder: Option<Arc<dyn HostIoRecorder>>,
) -> HandlerStack {
    if profile.kind() != ProfileKind::Full {
        // Only the Full profile performs fs/network host I/O; for every other
        // profile the provider is irrelevant and the default stack is correct.
        return create_handler_stack_from_profile(profile);
    }
    let mut stack = HandlerStack::new();
    let handler = match recorder {
        Some(recorder) => FullCapsHandler::with_host_io_recorded(host_io, recorder),
        None => FullCapsHandler::with_host_io(host_io),
    };
    stack.add_handler(Arc::new(handler));
    stack
}

/// Build a profile with filesystem/network and process providers as independent
/// trust boundaries. Ordinary host I/O remains Full-only. An explicitly
/// installed process provider is orthogonal to the base profile and supplies
/// only `ProcessSpawn`, reflecting its separate signed per-run admission.
pub fn create_handler_stack_from_profile_with_effect_providers(
    profile: &CapabilityProfile,
    host_io: Option<Arc<dyn HostIoProvider>>,
    host_io_recorder: Option<Arc<dyn HostIoRecorder>>,
    process_spawn: Option<Arc<dyn ProcessSpawnProvider>>,
    process_spawn_recorder: Option<Arc<dyn ProcessSpawnRecorder>>,
    host_effect_journal: Option<Arc<InMemoryHostEffectJournal>>,
) -> HandlerStack {
    let mut stack = if profile.kind() == ProfileKind::Full {
        let mut stack = HandlerStack::new();
        stack.add_handler(Arc::new(FullCapsHandler::with_effect_providers(
            host_io,
            host_io_recorder,
            host_effect_journal.clone(),
        )));
        stack
    } else {
        create_handler_stack_from_profile(profile)
    };
    if let Some(provider) = process_spawn {
        stack.add_handler(Arc::new(ProcessSpawnHandler::new(
            provider,
            process_spawn_recorder,
            host_effect_journal,
        )));
    }
    stack
}

/// Convert a legacy hostcall tag to an appropriate Effect.
///
/// This function provides compatibility with the existing hostcall dispatch system
/// by converting hostcall tags and parameters to the new Effect types.
/// bd-656a2: serialize a semantic http request (`url` + `method` + `headers` +
/// optional `body`) into the raw bytes the network mechanism writes to the
/// socket, plus the concrete `host:port` endpoint to connect to.
///
/// This is deliberately a minimal, dependency-free HTTP/1.1 request builder
/// (the engine has no http/url crate): it strips a leading `http://`/`https://`
/// scheme, splits the remainder into an authority (`host[:port]`) and a request
/// path (defaulting to `/`), defaults the port to 80 (http) or 443 (https) when
/// the authority omits one, and emits
/// `"<METHOD> <path> HTTP/1.1\r\nHost: <authority>\r\n"` followed by any
/// caller-supplied headers, the blank-line terminator, and the body. The
/// returned `use_tls` flag (bd-3894s slice 5) is true for an `https://` URL and
/// tells the network mechanism to wrap the connection in a real TLS session
/// before writing these bytes. The product layer (`franken_node`) owns SSRF
/// policy and must authorize the endpoint BEFORE this effect is issued — this
/// function performs no policy check, only framing.
fn http_request_to_wire(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> (String, Vec<u8>, bool) {
    let (rest, use_tls) = match url.strip_prefix("https://") {
        Some(rest) => (rest, true),
        None => (url.strip_prefix("http://").unwrap_or(url), false),
    };
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let endpoint = if authority.contains(':') {
        authority.to_string()
    } else if use_tls {
        format!("{authority}:443")
    } else {
        format!("{authority}:80")
    };
    let request_target = if path.is_empty() { "/" } else { path };
    let mut request = format!("{method} {request_target} HTTP/1.1\r\nHost: {authority}\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    // bd-3894s slice (2): a request that carries a body needs an explicit framing
    // length so the peer knows where the body ends. Node/undici synthesize a
    // `Content-Length` header automatically when the caller did not supply an
    // explicit framing header; mirror that so the egress is a well-formed
    // HTTP/1.1 request AND the recorded host effect faithfully reflects the bytes
    // actually sent. Only synthesized when a body is present and the caller set
    // neither `Content-Length` nor `Transfer-Encoding` (case-insensitive).
    if let Some(body) = body {
        let has_framing_header = headers.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding")
        });
        if !has_framing_header {
            request.push_str("Content-Length: ");
            request.push_str(&body.len().to_string());
            request.push_str("\r\n");
        }
    }
    // bd-3894s slice (4): the network mechanism does a single-socket round trip
    // and reads the response to EOF. HTTP/1.1 defaults to keep-alive, so unless
    // the peer is told to close, that read would block until the connect/read
    // timeout. Synthesize `Connection: close` (unless the caller already framed a
    // `Connection` header) so the peer closes after responding and the round trip
    // terminates promptly — exactly what a minimal one-shot HTTP client does.
    let has_connection_header = headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("connection"));
    if !has_connection_header {
        request.push_str("Connection: close\r\n");
    }
    request.push_str("\r\n");
    let mut payload = request.into_bytes();
    if let Some(body) = body {
        payload.extend_from_slice(body);
    }
    (endpoint, payload, use_tls)
}

#[must_use]
pub fn create_fs_effect(
    operation: FsOperation,
    path: String,
    arguments: Vec<String>,
    content: Option<Vec<u8>>,
) -> Box<dyn ErasedEffect> {
    Box::new(FsHostcallEffect {
        operation,
        path,
        arguments,
        content,
    })
}

pub fn create_effect_from_hostcall_tag(
    tag: &str,
    args: &[String],
) -> Result<Box<dyn ErasedEffect>, EffectError> {
    match tag {
        tag if tag.starts_with("console:") => {
            let method = tag.strip_prefix("console:").unwrap_or("log");
            let effect = ConsoleHostcallEffect {
                method: method.to_string(),
                args: args.to_vec(),
            };
            Ok(Box::new(effect))
        }
        tag if tag.starts_with("fs:") => {
            let operation = if tag == "fs:read" {
                FsOperation::Read
            } else if tag == "fs:write" {
                FsOperation::Write
            } else {
                return Err(EffectError::InvalidParameters {
                    effect_name: tag.to_string(),
                    reason: "Unknown fs operation".to_string(),
                });
            };
            let path = args.first().cloned().unwrap_or_default();
            let content = if matches!(operation, FsOperation::Write) {
                args.get(1).map(|s| s.as_bytes().to_vec())
            } else {
                None
            };
            Ok(create_fs_effect(operation, path, Vec::new(), content))
        }
        tag if tag.starts_with("timer:") => {
            let operation = match tag {
                "timer:setTimeout" => TimerOperation::SetTimeout,
                "timer:setInterval" => TimerOperation::SetInterval,
                "timer:clearTimeout" => TimerOperation::ClearTimeout,
                "timer:clearInterval" => TimerOperation::ClearInterval,
                _ => {
                    return Err(EffectError::InvalidParameters {
                        effect_name: tag.to_string(),
                        reason: "Unknown timer operation".to_string(),
                    });
                }
            };
            let value = args.first().ok_or_else(|| EffectError::InvalidParameters {
                effect_name: tag.to_string(),
                reason: match &operation {
                    TimerOperation::SetTimeout | TimerOperation::SetInterval => {
                        "Missing timer duration"
                    }
                    TimerOperation::ClearTimeout | TimerOperation::ClearInterval => {
                        "Missing timer ID"
                    }
                }
                .to_string(),
            })?;
            let parsed = value
                .parse::<u64>()
                .map_err(|_| EffectError::InvalidParameters {
                    effect_name: tag.to_string(),
                    reason: match &operation {
                        TimerOperation::SetTimeout | TimerOperation::SetInterval => {
                            "Invalid timer duration"
                        }
                        TimerOperation::ClearTimeout | TimerOperation::ClearInterval => {
                            "Invalid timer ID"
                        }
                    }
                    .to_string(),
                })?;
            let (duration_ms, timer_id) = match &operation {
                TimerOperation::SetTimeout | TimerOperation::SetInterval => (Some(parsed), None),
                TimerOperation::ClearTimeout | TimerOperation::ClearInterval => {
                    (None, Some(parsed))
                }
            };
            let effect = TimerHostcallEffect {
                operation,
                duration_ms,
                timer_id,
            };
            Ok(Box::new(effect))
        }
        tag if tag.starts_with("module:") => {
            let module_path = args.first().cloned().unwrap_or_default();
            let import_type = if tag.contains("require") {
                ModuleImportType::Require
            } else {
                ModuleImportType::EsModuleImport
            };
            let effect = ModuleHostcallEffect {
                module_path,
                import_type,
            };
            Ok(Box::new(effect))
        }
        // bd-656a2: the http leg. The JS `http.get(url)` / `http.request(url)`
        // lowering (CJS require-binding/inline form, mirror of the fs lowering)
        // emits a `net:request` HostCall carrying the URL as arg[0]. Slice 1 is
        // the GET egress (`http.get` and the default `http.request` method are
        // GET); request bodies, options objects, callbacks, the ClientRequest/
        // response objects, `fetch`, and ESM `http` imports are follow-up slices.
        // The URL is turned into a concrete `host:port` endpoint plus an HTTP/1.1
        // request payload at the effect->HostIoRequest boundary
        // (`host_io_request_from_effect`), keeping this builder a pure semantic
        // intent carrier.
        tag if tag.starts_with("net:") => {
            let url = args.first().cloned().unwrap_or_default();
            let effect = NetworkHostcallEffect {
                url,
                method: "GET".to_string(),
                headers: Vec::new(),
                body: None,
            };
            Ok(Box::new(effect))
        }
        _ => Err(EffectError::Unhandled {
            effect_name: tag.to_string(),
        }),
    }
}

/// bd-3894s slice (2): build the network host effect from a fully-resolved
/// request intent (`url` + `method` + `headers` + optional `body`).
///
/// The string-args `create_effect_from_hostcall_tag` builder above can only
/// recover the URL (arg[0]) and always frames a bodyless `GET`, because the
/// request `method`/`headers`/`body` live in the call's options/init object
/// (`fetch(url, { method, headers, body })` / `http.request(url, { method,
/// headers })`), a structured JS value that the interpreter — not the
/// string-args boundary — must read off the heap. The interpreter resolves
/// those fields (`resolve_net_request_options`) and calls this so the recorded,
/// signed EffectReceipt AND the wire egress faithfully reflect the real request
/// (a `POST` with a body must never be recorded — or sent — as a benign `GET`).
/// Keeping the `Box<dyn ErasedEffect>` construction here avoids leaking the
/// effect-trait machinery into the interpreter.
pub fn create_network_effect(
    url: String,
    method: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
) -> Box<dyn ErasedEffect> {
    Box::new(NetworkHostcallEffect {
        url,
        method,
        headers,
        body,
    })
}

/// Preserve the complete typed process request when entering the algebraic
/// effect stack. String-tag conversion is intentionally not supported for this
/// extraordinary authority because it would discard argv/env/cwd/stdio/limit
/// boundaries before policy and replay inspect them.
pub fn create_process_spawn_effect(request: ProcessSpawnRequest) -> Box<dyn ErasedEffect> {
    Box::new(ProcSpawnEffect { request })
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenengine_extension_host::host_effect_journal::{
        HostEffectJournalAttemptRecord, HostEffectJournalEntry,
    };
    use frankenengine_extension_host::host_io::HostIoCapability;
    use frankenengine_extension_host::process_spawn::{
        InMemoryProcessSpawnTranscript, ProcessExit, ProcessLaunch, ProcessSpawnOutcome,
        ProcessStdio,
    };
    use std::collections::BTreeMap;

    #[test]
    fn test_full_caps_handler_console() {
        let handler = FullCapsHandler::new();
        let effect = ConsoleHostcallEffect {
            method: "log".to_string(),
            args: vec!["test".to_string(), "message".to_string()],
        };

        assert!(handler.can_handle(Effect::effect_name(&effect)));
        let result = handler.handle(&effect);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn full_caps_fs_network_are_explicitly_denied_bd_6wc97() {
        // bd-6wc97 (decision bd-6wc97.1): FullCapsHandler no longer SIMULATES
        // side-effecting fs/network hostcalls (the bd-1lw7r.11 dishonesty — fake
        // data while claiming full capability). With no real in-engine executor,
        // it EXPLICITLY DENIES them with `CapabilityDenied`. Timer dispatch is
        // independently provider-gated and must not fabricate a handle.
        let handler = FullCapsHandler::new();
        assert!(
            !handler.dispatches_real_hostcalls(),
            "no real fs/network executor exists, so this must stay false (bd-6wc97)"
        );

        // fs:read — denied, not a canned "simulated content of {path}" buffer.
        let fs_read = FsHostcallEffect {
            operation: FsOperation::Read,
            path: "/etc/hostname".to_string(),
            arguments: Vec::new(),
            content: None,
        };
        assert!(
            matches!(
                handler.handle(&fs_read),
                Err(EffectError::CapabilityDenied { .. })
            ),
            "fs:read must be explicitly denied (bd-6wc97)"
        );

        // fs:write — denied, not a discarded write.
        let fs_write = FsHostcallEffect {
            operation: FsOperation::Write,
            path: "/tmp/out".to_string(),
            arguments: Vec::new(),
            content: Some(b"data".to_vec()),
        };
        assert!(
            matches!(
                handler.handle(&fs_write),
                Err(EffectError::CapabilityDenied { .. })
            ),
            "fs:write must be explicitly denied (bd-6wc97)"
        );

        // network — denied, not a hardcoded simulated response.
        let net_effect = NetworkHostcallEffect {
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
        };
        assert!(
            matches!(
                handler.handle(&net_effect),
                Err(EffectError::CapabilityDenied { .. })
            ),
            "network must be explicitly denied (bd-6wc97)"
        );

        // No event-loop provider is installed, so timer dispatch returns a
        // stable typed error instead of the former constant handle `42`.
        let timer_effect = TimerHostcallEffect {
            operation: TimerOperation::SetTimeout,
            duration_ms: Some(10),
            timer_id: None,
        };
        assert!(
            matches!(
                handler.handle(&timer_effect),
                Err(EffectError::HandlerError { code: Some(code), .. })
                    if code == TIMER_PROVIDER_UNAVAILABLE_CODE
            ),
            "an unbound timer must fail closed rather than return a synthetic handle"
        );
    }

    fn assert_timer_provider_unavailable(handler: &dyn Handler, effect: &TimerHostcallEffect) {
        assert!(
            matches!(
                handler.handle(effect),
                Err(EffectError::HandlerError { code: Some(code), .. })
                    if code == TIMER_PROVIDER_UNAVAILABLE_CODE
            ),
            "{} must reject an unbound timer without fabricating success",
            handler.handler_name()
        );
    }

    #[test]
    fn every_unbound_timer_operation_fails_closed_for_full_and_engine_core() {
        let effects = [
            TimerHostcallEffect {
                operation: TimerOperation::SetTimeout,
                duration_ms: Some(0),
                timer_id: None,
            },
            TimerHostcallEffect {
                operation: TimerOperation::SetInterval,
                duration_ms: Some(25),
                timer_id: None,
            },
            TimerHostcallEffect {
                operation: TimerOperation::ClearTimeout,
                duration_ms: None,
                timer_id: Some(7),
            },
            TimerHostcallEffect {
                operation: TimerOperation::ClearInterval,
                duration_ms: None,
                timer_id: Some(8),
            },
        ];
        let full = FullCapsHandler::new();
        let engine = EngineCoreHandler;
        for effect in &effects {
            assert_timer_provider_unavailable(&full, effect);
            assert_timer_provider_unavailable(&engine, effect);
        }
    }

    #[test]
    fn malformed_timer_parameters_fail_before_provider_dispatch() {
        let handler = FullCapsHandler::new();
        let malformed = [
            TimerHostcallEffect {
                operation: TimerOperation::SetTimeout,
                duration_ms: None,
                timer_id: None,
            },
            TimerHostcallEffect {
                operation: TimerOperation::SetInterval,
                duration_ms: Some(1),
                timer_id: Some(9),
            },
            TimerHostcallEffect {
                operation: TimerOperation::ClearTimeout,
                duration_ms: None,
                timer_id: None,
            },
            TimerHostcallEffect {
                operation: TimerOperation::ClearInterval,
                duration_ms: Some(1),
                timer_id: Some(9),
            },
        ];
        for effect in &malformed {
            assert!(
                matches!(
                    handler.handle(effect),
                    Err(EffectError::InvalidParameters { .. })
                ),
                "malformed timer parameters must be rejected before provider lookup"
            );
        }
    }

    #[derive(Debug, Default)]
    struct RecordingHostIo {
        seen: std::sync::Mutex<Vec<(HostIoRequest, Vec<HostIoCapability>)>>,
    }

    impl HostIoProvider for RecordingHostIo {
        fn name(&self) -> &str {
            "recording-test-host-io"
        }

        fn perform(
            &self,
            request: &HostIoRequest,
            granted: &[HostIoCapability],
        ) -> Result<HostIoResponse, HostIoError> {
            self.seen
                .lock()
                .unwrap()
                .push((request.clone(), granted.to_vec()));
            Ok(match request {
                HostIoRequest::FsRead { .. } => HostIoResponse::FsRead {
                    bytes: b"real-bytes".to_vec(),
                },
                HostIoRequest::FsWrite { data, .. } => HostIoResponse::FsWrite {
                    bytes_written: data.len() as u64,
                },
                HostIoRequest::FsMeta { .. } => HostIoResponse::FsMeta {
                    result: frankenengine_extension_host::host_io::FsMetaResult::Unit,
                },
                HostIoRequest::NetworkSend { payload, .. } => HostIoResponse::NetworkSend {
                    bytes_sent: payload.len() as u64,
                },
                HostIoRequest::NetworkRecv { max_len, .. } => HostIoResponse::NetworkRecv {
                    bytes: vec![0; *max_len as usize],
                },
                HostIoRequest::NetworkRequest { .. } => HostIoResponse::NetworkRequest {
                    response: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
                },
            })
        }
    }

    #[derive(Debug)]
    struct NeverCalledHostIo;

    impl HostIoProvider for NeverCalledHostIo {
        fn name(&self) -> &str {
            "never-called"
        }

        fn perform(
            &self,
            _request: &HostIoRequest,
            _granted: &[HostIoCapability],
        ) -> Result<HostIoResponse, HostIoError> {
            panic!("provider must not be called in replay mode");
        }
    }

    #[derive(Debug, Default)]
    struct RecordingProcessSpawn {
        seen: std::sync::Mutex<Vec<ProcessSpawnRequest>>,
    }

    impl ProcessSpawnProvider for RecordingProcessSpawn {
        fn name(&self) -> &str {
            "recording-test-process-spawn"
        }

        fn perform(
            &self,
            request: &ProcessSpawnRequest,
            granted: &[ProcessSpawnCapability],
        ) -> ProcessSpawnOutcome {
            assert_eq!(granted, &[ProcessSpawnCapability::Spawn]);
            self.seen.lock().unwrap().push(request.clone());
            Ok(ProcessSpawnResponse::Run {
                exit: ProcessExit {
                    success: true,
                    code: Some(0),
                    signal: None,
                },
                stdout: b"typed-process-output".to_vec(),
                stderr: Vec::new(),
            })
        }

        fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
            Ok(ProcessSpawnResponse::Cleaned { was_present: false })
        }
    }

    #[derive(Debug)]
    struct ReservationObservingProcessSpawn {
        journal: Arc<InMemoryHostEffectJournal>,
        prepare_seen: std::sync::atomic::AtomicBool,
    }

    impl ProcessSpawnProvider for ReservationObservingProcessSpawn {
        fn name(&self) -> &str {
            "reservation-observing-process-spawn"
        }

        fn prepare_request(
            &self,
            request: &ProcessSpawnRequest,
        ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
            assert!(matches!(
                self.journal.attempt_records().as_slice(),
                [HostEffectJournalAttemptRecord::Uncompleted {
                    sequence: 0,
                    family,
                    request_kind,
                    ..
                }] if family == "process_spawn" && request_kind == request.kind()
            ));
            self.prepare_seen
                .store(true, std::sync::atomic::Ordering::Release);
            Ok(request.clone())
        }

        fn perform(
            &self,
            _request: &ProcessSpawnRequest,
            granted: &[ProcessSpawnCapability],
        ) -> ProcessSpawnOutcome {
            assert_eq!(granted, &[ProcessSpawnCapability::Spawn]);
            assert!(self.prepare_seen.load(std::sync::atomic::Ordering::Acquire));
            Ok(ProcessSpawnResponse::Run {
                exit: ProcessExit {
                    success: true,
                    code: Some(0),
                    signal: None,
                },
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }

        fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
            Ok(ProcessSpawnResponse::Cleaned { was_present: false })
        }
    }

    #[derive(Debug)]
    struct CanonicalizingProcessSpawn {
        canonical_executable: String,
        seen: std::sync::Mutex<Vec<ProcessSpawnRequest>>,
    }

    impl ProcessSpawnProvider for CanonicalizingProcessSpawn {
        fn name(&self) -> &str {
            "canonicalizing-test-process-spawn"
        }

        fn prepare_request(
            &self,
            request: &ProcessSpawnRequest,
        ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
            let mut prepared = request.clone();
            match &mut prepared {
                ProcessSpawnRequest::Run { launch, .. } | ProcessSpawnRequest::Spawn { launch } => {
                    launch.executable.clone_from(&self.canonical_executable);
                }
                ProcessSpawnRequest::WriteStdin { .. }
                | ProcessSpawnRequest::CloseStdin { .. }
                | ProcessSpawnRequest::Wait { .. }
                | ProcessSpawnRequest::Kill { .. }
                | ProcessSpawnRequest::Cleanup { .. } => {}
            }
            Ok(prepared)
        }

        fn perform(
            &self,
            request: &ProcessSpawnRequest,
            granted: &[ProcessSpawnCapability],
        ) -> ProcessSpawnOutcome {
            assert_eq!(granted, &[ProcessSpawnCapability::Spawn]);
            self.seen.lock().unwrap().push(request.clone());
            Ok(ProcessSpawnResponse::Run {
                exit: ProcessExit {
                    success: true,
                    code: Some(0),
                    signal: None,
                },
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }

        fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
            Ok(ProcessSpawnResponse::Cleaned { was_present: false })
        }
    }

    #[derive(Debug)]
    struct PreparationDenyingProcessSpawn {
        failure: ProcessSpawnError,
        perform_calls: std::sync::atomic::AtomicUsize,
    }

    impl ProcessSpawnProvider for PreparationDenyingProcessSpawn {
        fn name(&self) -> &str {
            "preparation-denying-test-process-spawn"
        }

        fn prepare_request(
            &self,
            _request: &ProcessSpawnRequest,
        ) -> Result<ProcessSpawnRequest, ProcessSpawnError> {
            Err(self.failure.clone())
        }

        fn perform(
            &self,
            _request: &ProcessSpawnRequest,
            _granted: &[ProcessSpawnCapability],
        ) -> ProcessSpawnOutcome {
            self.perform_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Err(ProcessSpawnError::Denied {
                reason: "preparation denial must prevent dispatch".to_string(),
            })
        }

        fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
            Ok(ProcessSpawnResponse::Cleaned { was_present: false })
        }
    }

    #[derive(Debug)]
    struct DenyingProcessSpawn;

    impl ProcessSpawnProvider for DenyingProcessSpawn {
        fn name(&self) -> &str {
            "denying-test-process-spawn"
        }

        fn perform(
            &self,
            _request: &ProcessSpawnRequest,
            _granted: &[ProcessSpawnCapability],
        ) -> ProcessSpawnOutcome {
            Err(ProcessSpawnError::PolicyViolation {
                code: "executable_alias_denied".to_string(),
                detail: "bare executable alias missing is not signed into policy".to_string(),
            })
        }

        fn cleanup_handle(&self, _handle: &str) -> ProcessSpawnOutcome {
            Ok(ProcessSpawnResponse::Cleaned { was_present: false })
        }
    }

    fn process_run_request() -> ProcessSpawnRequest {
        ProcessSpawnRequest::Run {
            launch: ProcessLaunch {
                executable: "/usr/bin/true".to_string(),
                argv: Vec::new(),
                env: BTreeMap::new(),
                cwd: Some("/".to_string()),
                shell: false,
                stdio: ProcessStdio::default(),
            },
            stdin: Vec::new(),
            timeout_millis: Some(100),
        }
    }

    #[test]
    fn process_provider_is_an_orthogonal_explicit_capability_witness_bd_x85a7() {
        let effect = create_process_spawn_effect(process_run_request());
        let mut ordinary_full = create_handler_stack_from_profile(&CapabilityProfile::full());
        assert!(!ordinary_full.can_handle("proc:spawn"));
        assert!(matches!(
            ordinary_full.handle_effect(effect.as_ref()),
            Err(EffectError::CapabilityDenied { .. })
        ));

        let provider = Arc::new(RecordingProcessSpawn::default());
        let journal = Arc::new(InMemoryHostEffectJournal::recording());
        journal.begin_execution().unwrap();
        let mut admitted = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(provider.clone()),
            None,
            Some(journal.clone()),
        );
        let result = admitted
            .handle_effect(effect.as_ref())
            .expect("signed process handler must dispatch independently of base profile")
            .downcast::<ProcessSpawnResponse>()
            .expect("typed process response");
        assert!(matches!(result, ProcessSpawnResponse::Run { .. }));
        assert_eq!(
            provider.seen.lock().unwrap().as_slice(),
            &[process_run_request()]
        );
        let entries = journal.finish_execution().unwrap();
        assert!(matches!(
            entries.as_slice(),
            [HostEffectJournalEntry::ProcessSpawn { .. }]
        ));
    }

    #[test]
    fn process_journal_preflight_refuses_before_provider_invocation_bd_x85a7() {
        let provider = Arc::new(RecordingProcessSpawn::default());
        let journal = Arc::new(InMemoryHostEffectJournal::recording());
        let mut stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(provider.clone()),
            None,
            Some(journal),
        );
        let error = stack
            .handle_effect(create_process_spawn_effect(process_run_request()).as_ref())
            .unwrap_err();
        assert!(matches!(
            error,
            EffectError::HandlerError { ref code, .. }
                if code.as_deref() == Some("HOST_EFFECT_JOURNAL")
        ));
        assert!(provider.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn family_local_process_recorder_is_replay_only_without_global_reservation_bd_x85a7_2() {
        let provider = Arc::new(RecordingProcessSpawn::default());
        let recorder = Arc::new(InMemoryProcessSpawnTranscript::recording());
        recorder.begin_execution().expect("begin legacy transcript");
        let mut stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(provider.clone()),
            Some(recorder.clone()),
            None,
        );

        let error = stack
            .handle_effect(create_process_spawn_effect(process_run_request()).as_ref())
            .expect_err("live process dispatch without a global reservation must fail closed");
        assert!(matches!(
            error,
            EffectError::HandlerError { ref code, .. }
                if code.as_deref() == Some("PROCESS_SPAWN_DENIED")
        ));
        assert!(provider.seen.lock().unwrap().is_empty());
        let entries = recorder
            .finish_execution()
            .expect("finish legacy transcript");
        assert!(matches!(
            entries.as_slice(),
            [(_, Err(ProcessSpawnError::Denied { .. }))]
        ));
    }

    #[test]
    fn process_reservation_precedes_provider_preparation_and_dispatch_bd_x85a7_2() {
        let journal = Arc::new(InMemoryHostEffectJournal::recording());
        journal.begin_execution().expect("begin global journal");
        let provider = Arc::new(ReservationObservingProcessSpawn {
            journal: journal.clone(),
            prepare_seen: std::sync::atomic::AtomicBool::new(false),
        });
        let mut stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(provider.clone()),
            None,
            Some(journal.clone()),
        );
        let request = process_run_request();

        stack
            .handle_effect(create_process_spawn_effect(request.clone()).as_ref())
            .expect("journaled process effect must dispatch");
        assert!(
            provider
                .prepare_seen
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert!(matches!(
            journal.finish_execution().as_deref(),
            Ok([HostEffectJournalEntry::ProcessSpawn {
                request: recorded,
                outcome: Ok(ProcessSpawnResponse::Run { .. }),
            }]) if recorded == &request
        ));
    }

    #[test]
    fn process_journal_binds_and_replays_the_policy_prepared_request_bd_x85a7_2() {
        let mut request = process_run_request();
        let ProcessSpawnRequest::Run { launch, .. } = &mut request else {
            unreachable!("fixture is a run request");
        };
        launch.executable = "signed-tool-alias".to_string();

        let journal = Arc::new(InMemoryHostEffectJournal::recording());
        journal.begin_execution().expect("begin recording journal");
        let recording_provider = Arc::new(CanonicalizingProcessSpawn {
            canonical_executable: "/policy/v1/signed-tool".to_string(),
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut recording_stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(recording_provider.clone()),
            None,
            Some(journal.clone()),
        );
        recording_stack
            .handle_effect(create_process_spawn_effect(request.clone()).as_ref())
            .expect("canonical request dispatches");
        let entries = journal
            .finish_execution()
            .expect("finish recording journal");
        assert!(matches!(
            entries.as_slice(),
            [HostEffectJournalEntry::ProcessSpawn {
                request: ProcessSpawnRequest::Run { launch, .. },
                ..
            }] if launch.executable == "/policy/v1/signed-tool"
        ));
        assert!(matches!(
            recording_provider.seen.lock().unwrap().as_slice(),
            [ProcessSpawnRequest::Run { launch, .. }]
                if launch.executable == "/policy/v1/signed-tool"
        ));

        let exact = Arc::new(InMemoryHostEffectJournal::replaying(entries.clone()));
        exact.begin_execution().expect("begin exact replay");
        let exact_provider = Arc::new(CanonicalizingProcessSpawn {
            canonical_executable: "/policy/v1/signed-tool".to_string(),
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut exact_stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(exact_provider.clone()),
            None,
            Some(exact.clone()),
        );
        exact_stack
            .handle_effect(create_process_spawn_effect(request.clone()).as_ref())
            .expect("matching canonical mapping replays");
        assert!(exact_provider.seen.lock().unwrap().is_empty());
        assert_eq!(exact.finish_execution().unwrap(), entries);

        let divergent = Arc::new(InMemoryHostEffectJournal::replaying(entries));
        divergent.begin_execution().expect("begin divergent replay");
        let divergent_provider = Arc::new(CanonicalizingProcessSpawn {
            canonical_executable: "/policy/v2/signed-tool".to_string(),
            seen: std::sync::Mutex::new(Vec::new()),
        });
        let mut divergent_stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(divergent_provider.clone()),
            None,
            Some(divergent.clone()),
        );
        let error = divergent_stack
            .handle_effect(create_process_spawn_effect(request).as_ref())
            .expect_err("changed canonical mapping must diverge before dispatch");
        assert!(matches!(
            error,
            EffectError::HandlerError { ref code, .. }
                if code.as_deref() == Some("PROCESS_SPAWN_REPLAY_DIVERGENCE")
        ));
        assert!(divergent_provider.seen.lock().unwrap().is_empty());
        assert!(divergent.finish_execution().is_err());
    }

    #[test]
    fn replay_preparation_failure_cannot_reuse_recorded_success_bd_x85a7_2() {
        let request = process_run_request();
        let recorded_success = HostEffectJournalEntry::ProcessSpawn {
            request: request.clone(),
            outcome: Ok(ProcessSpawnResponse::Run {
                exit: ProcessExit {
                    success: true,
                    code: Some(0),
                    signal: None,
                },
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
        };
        let failure = ProcessSpawnError::PolicyViolation {
            code: "executable_alias_denied".to_string(),
            detail: "current policy refuses preparation".to_string(),
        };
        let journal = Arc::new(InMemoryHostEffectJournal::replaying(vec![recorded_success]));
        journal.begin_execution().expect("begin replay");
        let provider = Arc::new(PreparationDenyingProcessSpawn {
            failure,
            perform_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(provider.clone()),
            None,
            Some(journal.clone()),
        );

        let error = stack
            .handle_effect(create_process_spawn_effect(request).as_ref())
            .expect_err("current preparation denial must not replay recorded success");
        assert!(matches!(
            error,
            EffectError::HandlerError { ref code, .. }
                if code.as_deref() == Some("PROCESS_SPAWN_REPLAY_DIVERGENCE")
        ));
        assert_eq!(
            provider
                .perform_calls
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert!(journal.finish_execution().is_err());
    }

    #[test]
    fn replay_accepts_only_the_exact_recorded_preparation_failure_bd_x85a7_2() {
        let request = process_run_request();
        let failure = ProcessSpawnError::PolicyViolation {
            code: "executable_alias_denied".to_string(),
            detail: "policy refuses preparation".to_string(),
        };
        let entry = HostEffectJournalEntry::ProcessSpawn {
            request: request.clone(),
            outcome: Err(failure.clone()),
        };
        let journal = Arc::new(InMemoryHostEffectJournal::replaying(vec![entry.clone()]));
        journal.begin_execution().expect("begin replay");
        let provider = Arc::new(PreparationDenyingProcessSpawn {
            failure,
            perform_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(provider.clone()),
            None,
            Some(journal.clone()),
        );

        let error = stack
            .handle_effect(create_process_spawn_effect(request).as_ref())
            .expect_err("recorded preparation denial remains a typed guest error");
        assert!(matches!(
            error,
            EffectError::HandlerError { ref code, .. }
                if code.as_deref() == Some("PROCESS_SPAWN_POLICY_VIOLATION")
        ));
        assert_eq!(
            provider
                .perform_calls
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert_eq!(journal.finish_execution().unwrap(), vec![entry.clone()]);

        let different_journal = Arc::new(InMemoryHostEffectJournal::replaying(vec![entry]));
        different_journal
            .begin_execution()
            .expect("begin unequal-failure replay");
        let different_provider = Arc::new(PreparationDenyingProcessSpawn {
            failure: ProcessSpawnError::PolicyViolation {
                code: "different_policy_denial".to_string(),
                detail: "the current preparation failure changed".to_string(),
            },
            perform_calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut different_stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(different_provider.clone()),
            None,
            Some(different_journal.clone()),
        );
        let error = different_stack
            .handle_effect(create_process_spawn_effect(process_run_request()).as_ref())
            .expect_err("a different preparation failure must diverge");
        assert!(matches!(
            error,
            EffectError::HandlerError { ref code, .. }
                if code.as_deref() == Some("PROCESS_SPAWN_REPLAY_DIVERGENCE")
        ));
        assert_eq!(
            different_provider
                .perform_calls
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
        assert!(different_journal.finish_execution().is_err());
    }

    #[test]
    fn admitted_provider_denial_preserves_guest_error_evidence_bd_x85a7() {
        let journal = Arc::new(InMemoryHostEffectJournal::recording());
        journal.begin_execution().unwrap();
        let mut stack = create_handler_stack_from_profile_with_effect_providers(
            &CapabilityProfile::compute_only(),
            None,
            None,
            Some(Arc::new(DenyingProcessSpawn)),
            None,
            Some(journal.clone()),
        );
        let error = stack
            .handle_effect(create_process_spawn_effect(process_run_request()).as_ref())
            .unwrap_err();
        assert!(matches!(
            error,
            EffectError::HandlerError {
                ref message,
                ref code,
                ..
            } if code.as_deref() == Some("PROCESS_SPAWN_POLICY_VIOLATION")
                && message.contains("executable_alias_denied")
        ));
        assert!(matches!(
            journal.finish_execution().unwrap().as_slice(),
            [HostEffectJournalEntry::ProcessSpawn {
                outcome: Err(ProcessSpawnError::PolicyViolation { code, .. }),
                ..
            }] if code == "executable_alias_denied"
        ));
    }

    /// bd-656a2 (http leg): the `net:request` hostcall tag (emitted by the JS
    /// http.get/http.request lowering) builds a `hostcall:network` effect that
    /// round-trips through `host_io_request_from_effect` to a concrete
    /// `host:port` NetworkRequest carrying a framed HTTP/1.1 GET request.
    /// bd-3894s slice (4): the request is a single-socket `NetworkRequest`
    /// round trip (not a fire-and-forget `NetworkSend`) so the guest can observe
    /// the response, and the framing carries `Connection: close`.
    #[test]
    fn create_effect_from_net_request_tag_builds_network_effect_bd_656a2() {
        let effect =
            create_effect_from_hostcall_tag("net:request", &["http://example.test/p".to_string()])
                .expect("net:request tag must build a network effect");
        assert_eq!(effect.effect_name(), "hostcall:network");
        let request = FullCapsHandler::host_io_request_from_effect(effect.as_ref())
            .expect("network effect must map to a HostIoRequest");
        match request {
            HostIoRequest::NetworkRequest {
                endpoint, payload, ..
            } => {
                assert_eq!(
                    endpoint, "example.test:80",
                    "url with no port must default to :80 and strip the path"
                );
                let wire = String::from_utf8(payload).expect("ascii request line");
                assert!(
                    wire.starts_with("GET /p HTTP/1.1\r\n"),
                    "request line must target the path: {wire:?}"
                );
                assert!(
                    wire.contains("Host: example.test\r\n"),
                    "Host header must carry the authority: {wire:?}"
                );
                assert!(
                    wire.contains("Connection: close\r\n"),
                    "round-trip framing must request connection close: {wire:?}"
                );
            }
            other => panic!("expected NetworkRequest, got {other:?}"),
        }
    }

    /// bd-3894s slice (2): `create_network_effect` carries the resolved request
    /// `method` + `headers` + `body` (recovered by the interpreter from a
    /// `fetch(url, init)` / `http.request(url, options)` options object) all the
    /// way through to the framed HTTP/1.1 wire request, so a POST-with-body is
    /// sent — and recorded — faithfully rather than collapsed to a bodyless GET.
    #[test]
    fn create_network_effect_frames_method_headers_and_body_bd_3894s() {
        let effect = create_network_effect(
            "http://example.test/submit".to_string(),
            "POST".to_string(),
            vec![("Content-Type".to_string(), "application/json".to_string())],
            Some(b"{\"k\":1}".to_vec()),
        );
        assert_eq!(effect.effect_name(), "hostcall:network");
        let request = FullCapsHandler::host_io_request_from_effect(effect.as_ref())
            .expect("network effect must map to a HostIoRequest");
        let HostIoRequest::NetworkRequest {
            endpoint, payload, ..
        } = request
        else {
            panic!("expected a NetworkRequest host io request");
        };
        assert_eq!(endpoint, "example.test:80");
        let wire = String::from_utf8(payload).expect("ascii request line");
        assert!(
            wire.starts_with("POST /submit HTTP/1.1\r\n"),
            "method + target framed: {wire:?}"
        );
        assert!(
            wire.contains("Content-Type: application/json\r\n"),
            "caller header framed: {wire:?}"
        );
        assert!(
            wire.contains("Content-Length: 7\r\n"),
            "synthesized framing length matches the body: {wire:?}"
        );
        assert!(
            wire.ends_with("\r\n\r\n{\"k\":1}"),
            "body follows the blank-line terminator: {wire:?}"
        );
    }

    /// bd-656a2: unit coverage for the dependency-free HTTP/1.1 wire builder —
    /// scheme stripping, default port/path, header emission, and body framing.
    #[test]
    fn http_request_to_wire_defaults_and_framing_bd_656a2() {
        // explicit port + multi-segment path are preserved verbatim.
        // bd-3894s slice (4): the round-trip framing now appends `Connection: close`
        // (so the peer closes and the response read terminates) before the
        // blank-line terminator.
        let (endpoint, payload, use_tls) =
            http_request_to_wire("http://127.0.0.1:8080/a/b", "GET", &[], None);
        assert_eq!(endpoint, "127.0.0.1:8080");
        assert!(!use_tls, "http scheme must not request TLS");
        let wire = String::from_utf8(payload).unwrap();
        assert_eq!(
            wire, "GET /a/b HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: close\r\n\r\n",
            "round-trip GET frames Host + Connection: close: {wire:?}"
        );

        // bd-3894s slice (4): a caller-supplied `Connection` header is honored and
        // not duplicated.
        let (_endpoint, payload, _use_tls) = http_request_to_wire(
            "http://h:1/",
            "GET",
            &[("Connection".to_string(), "keep-alive".to_string())],
            None,
        );
        let wire = String::from_utf8(payload).unwrap();
        assert_eq!(
            wire.to_ascii_lowercase().matches("connection:").count(),
            1,
            "caller Connection header is honored and not duplicated: {wire:?}"
        );
        assert!(
            wire.contains("Connection: keep-alive\r\n"),
            "caller Connection value is preserved: {wire:?}"
        );

        // no scheme and no path -> default port 80 and default request target "/".
        let (endpoint, payload, use_tls) = http_request_to_wire("example.test", "GET", &[], None);
        assert_eq!(endpoint, "example.test:80");
        assert!(!use_tls, "schemeless url must not request TLS");
        let wire = String::from_utf8(payload).unwrap();
        assert!(wire.starts_with("GET / HTTP/1.1\r\nHost: example.test\r\n"));

        // caller headers are emitted and the body follows the blank-line terminator.
        // bd-3894s slice (2): a body with no caller framing header gets an
        // auto-synthesized Content-Length so the egress is a well-formed request.
        let (_endpoint, payload, _use_tls) = http_request_to_wire(
            "http://h:1/",
            "POST",
            &[("X-T".to_string(), "1".to_string())],
            Some(b"hi"),
        );
        let wire = String::from_utf8(payload).unwrap();
        assert!(
            wire.starts_with("POST / HTTP/1.1\r\nHost: h:1\r\n"),
            "method/target/host framed: {wire:?}"
        );
        assert!(
            wire.contains("X-T: 1\r\n"),
            "header must be framed: {wire:?}"
        );
        assert!(
            wire.contains("Content-Length: 2\r\n"),
            "a body with no caller framing header gets a synthesized Content-Length: {wire:?}"
        );
        assert!(
            wire.ends_with("\r\n\r\nhi"),
            "body follows terminator: {wire:?}"
        );

        // bd-3894s slice (2): a caller-supplied framing header (Content-Length or
        // Transfer-Encoding, case-insensitive) is honored, not duplicated.
        let (_endpoint, payload, _use_tls) = http_request_to_wire(
            "http://h:1/",
            "POST",
            &[("content-length".to_string(), "5".to_string())],
            Some(b"hello"),
        );
        let wire = String::from_utf8(payload).unwrap();
        assert_eq!(
            wire.to_ascii_lowercase().matches("content-length").count(),
            1,
            "caller Content-Length is honored and not duplicated: {wire:?}"
        );
        assert!(wire.ends_with("\r\n\r\nhello"), "body framed: {wire:?}");

        // bd-3894s slice (2): a bodyless GET is unchanged — no synthesized framing.
        let (_endpoint, payload, _use_tls) = http_request_to_wire("http://h:1/", "GET", &[], None);
        let wire = String::from_utf8(payload).unwrap();
        assert!(
            !wire.to_ascii_lowercase().contains("content-length"),
            "bodyless GET carries no synthesized Content-Length: {wire:?}"
        );
    }

    /// bd-3894s slice (5): an `https://` URL sets the TLS marker and defaults the
    /// connect port to 443 (an explicit port is preserved); the framed request
    /// bytes are scheme-independent. The marker flows through
    /// `host_io_request_from_effect` into `NetworkRequest::use_tls` so the
    /// network mechanism performs the round trip inside a real TLS session.
    #[test]
    fn http_request_to_wire_https_sets_tls_and_port_443_bd_3894s() {
        let (endpoint, payload, use_tls) =
            http_request_to_wire("https://example.test/p", "GET", &[], None);
        assert_eq!(endpoint, "example.test:443", "https defaults to port 443");
        assert!(use_tls, "https scheme must request TLS");
        let wire = String::from_utf8(payload).unwrap();
        assert!(
            wire.starts_with("GET /p HTTP/1.1\r\nHost: example.test\r\n"),
            "framing is scheme-independent: {wire:?}"
        );

        let (endpoint, _payload, use_tls) =
            http_request_to_wire("https://example.test:8443/p", "GET", &[], None);
        assert_eq!(endpoint, "example.test:8443", "explicit port is preserved");
        assert!(use_tls);

        // End-to-end through the effect layer: the https marker lands on the
        // HostIoRequest the provider receives.
        let effect =
            create_effect_from_hostcall_tag("net:request", &["https://example.test/p".to_string()])
                .expect("net:request tag must build a network effect");
        let request = FullCapsHandler::host_io_request_from_effect(effect.as_ref())
            .expect("network effect must map to a HostIoRequest");
        let HostIoRequest::NetworkRequest {
            endpoint, use_tls, ..
        } = request
        else {
            panic!("expected a NetworkRequest host io request");
        };
        assert_eq!(endpoint, "example.test:443");
        assert!(use_tls, "https effect must carry the TLS marker");
    }

    #[test]
    fn full_caps_with_provider_routes_fs_and_network_bd_lrbbz_7() {
        let provider = Arc::new(RecordingHostIo::default());
        let handler = FullCapsHandler::with_host_io(provider.clone());
        assert!(handler.dispatches_real_hostcalls());

        let fs_read = FsHostcallEffect {
            operation: FsOperation::Read,
            path: "/data/x".to_string(),
            arguments: Vec::new(),
            content: None,
        };
        assert!(handler.handle(&fs_read).expect("fs read routed").is_some());

        let fs_write = FsHostcallEffect {
            operation: FsOperation::Write,
            path: "/data/y".to_string(),
            arguments: Vec::new(),
            content: Some(b"abc".to_vec()),
        };
        assert!(
            handler
                .handle(&fs_write)
                .expect("fs write routed")
                .is_some()
        );

        let network = NetworkHostcallEffect {
            url: "https://host:443".to_string(),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: Some(b"hi".to_vec()),
        };
        assert!(handler.handle(&network).expect("network routed").is_some());

        let seen = provider.seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        for (request, granted) in seen.iter() {
            assert_eq!(granted.as_slice(), &[request.required_capability()]);
        }
    }

    #[test]
    fn full_caps_records_and_replays_host_io_bd_lrbbz_7() {
        use frankenengine_extension_host::host_io::InMemoryHostIoTranscript;

        let provider = Arc::new(RecordingHostIo::default());
        let recorder = Arc::new(InMemoryHostIoTranscript::recording());
        let record_handler = FullCapsHandler::with_host_io_recorded(provider, recorder.clone());
        recorder.begin_execution().expect("begin recording");
        let network = NetworkHostcallEffect {
            url: "https://host:443".to_string(),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: Some(b"hi".to_vec()),
        };
        assert!(record_handler.handle(&network).is_ok());
        let recorded = recorder.finish_execution().expect("finish recording");
        assert_eq!(recorded.len(), 1);

        let replay = Arc::new(InMemoryHostIoTranscript::replaying(recorded));
        replay.begin_execution().expect("begin replay");
        let replay_handler =
            FullCapsHandler::with_host_io_recorded(Arc::new(NeverCalledHostIo), replay.clone());
        assert!(replay_handler.handle(&network).is_ok());
        replay.finish_execution().expect("finish replay");
    }

    #[test]
    fn full_caps_stack_with_sandboxed_provider_performs_real_fs_bd_f5b04_2_6() {
        use frankenengine_extension_host::host_io::{InMemoryHostIoTranscript, SandboxedHostIo};

        // A real sandbox root in a unique temp dir.
        let mut root = std::env::temp_dir();
        root.push(format!(
            "frankenengine_stack_sandbox_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch root");

        let provider = Arc::new(SandboxedHostIo::with_root(&root).expect("sandboxed provider"));
        let recorder = Arc::new(InMemoryHostIoTranscript::recording());
        let mut stack = create_handler_stack_from_profile_with_host_io(
            &CapabilityProfile::full(),
            provider,
            Some(recorder.clone()),
        );

        // A real write dispatched through the algebraic-effects stack lands real
        // bytes on disk (proves the substrate executes effects, not just gates).
        let write = FsHostcallEffect {
            operation: FsOperation::Write,
            path: "report.txt".to_string(),
            arguments: Vec::new(),
            content: Some(b"real effect bytes".to_vec()),
        };
        stack
            .handle_effect(&write)
            .expect("fs write dispatched through the Full stack");
        assert_eq!(
            std::fs::read(root.join("report.txt")).expect("written file on disk"),
            b"real effect bytes",
            "the dispatched effect must have produced a real file"
        );

        // A real read dispatched through the same stack succeeds (bytes off disk).
        let read = FsHostcallEffect {
            operation: FsOperation::Read,
            path: "report.txt".to_string(),
            arguments: Vec::new(),
            content: None,
        };
        stack
            .handle_effect(&read)
            .expect("fs read dispatched through the Full stack");

        // Both real effects were captured in the deterministic-replay transcript.
        assert_eq!(
            recorder.entries().len(),
            2,
            "both dispatched effects must be recorded for replay"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn non_full_profile_ignores_host_io_provider_bd_f5b04_2_6() {
        use frankenengine_extension_host::host_io::SandboxedHostIo;

        let mut root = std::env::temp_dir();
        root.push(format!(
            "frankenengine_nonfull_sandbox_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch root");
        let provider = Arc::new(SandboxedHostIo::with_root(&root).expect("sandboxed provider"));

        // A ComputeOnly profile must build exactly the default stack regardless of
        // any supplied provider (only Full performs host I/O).
        let with_provider = create_handler_stack_from_profile_with_host_io(
            &CapabilityProfile::compute_only(),
            provider,
            None,
        );
        let default = create_handler_stack_from_profile(&CapabilityProfile::compute_only());
        assert_eq!(with_provider.handler_names(), default.handler_names());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_compute_only_denies_hostcalls() {
        let handler = ComputeOnlyHandler;
        let effect = ConsoleHostcallEffect {
            method: "log".to_string(),
            args: vec!["test".to_string()],
        };

        assert!(handler.can_handle(Effect::effect_name(&effect)));
        let result = handler.handle(&effect);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EffectError::CapabilityDenied { .. }
        ));
    }

    #[test]
    fn test_engine_core_allows_console() {
        let handler = EngineCoreHandler;
        let effect = ConsoleHostcallEffect {
            method: "log".to_string(),
            args: vec!["engine".to_string(), "test".to_string()],
        };

        assert!(handler.can_handle(Effect::effect_name(&effect)));
        let result = handler.handle(&effect);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_engine_core_rejects_network() {
        let handler = EngineCoreHandler;
        let effect = NetworkHostcallEffect {
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
        };

        assert!(!handler.can_handle(Effect::effect_name(&effect)));
    }

    #[test]
    fn test_capability_profile_to_handler_stack() {
        let full_profile = CapabilityProfile::full();
        let stack = create_handler_stack_from_profile(&full_profile);
        assert!(stack.can_handle("hostcall:console"));

        let compute_profile = CapabilityProfile::compute_only();
        let stack = create_handler_stack_from_profile(&compute_profile);
        assert!(stack.can_handle("hostcall:console")); // Can handle but will deny
    }

    // bd-08wwg: Policy/Remote profiles must grant their canonical capability sets,
    // not the empty ComputeOnly set the placeholder used.

    #[test]
    fn policy_profile_stack_grants_policy_capabilities() {
        use RuntimeCapability::*;
        let stack = create_handler_stack_from_profile(&CapabilityProfile::policy());
        let granted = stack.capabilities();
        // Every capability CapabilityProfile::policy() grants must be satisfied.
        let required =
            EffectCapabilities::runtime([PolicyRead, PolicyWrite, EvidenceEmit, DecisionInvoke]);
        assert!(
            required.is_satisfied_by(granted),
            "Policy stack must grant the PolicyCaps set, got {granted:?}"
        );
        // A capability outside the profile must still be denied (no over-grant).
        let off_profile = EffectCapabilities::runtime([FsWrite]);
        assert!(
            !off_profile.is_satisfied_by(granted),
            "Policy stack must not grant FsWrite"
        );
    }

    #[test]
    fn remote_profile_stack_grants_remote_capabilities() {
        use RuntimeCapability::*;
        let stack = create_handler_stack_from_profile(&CapabilityProfile::remote());
        let granted = stack.capabilities();
        let required =
            EffectCapabilities::runtime([NetworkEgress, LeaseManagement, IdempotencyDerive]);
        assert!(
            required.is_satisfied_by(granted),
            "Remote stack must grant the RemoteCaps set, got {granted:?}"
        );
        let off_profile = EffectCapabilities::runtime([PolicyWrite]);
        assert!(
            !off_profile.is_satisfied_by(granted),
            "Remote stack must not grant PolicyWrite"
        );
    }

    #[test]
    fn policy_and_remote_stacks_are_not_stripped_to_compute_only() {
        // Regression for the ComputeOnly placeholder: a ComputeOnly stack grants
        // nothing, but Policy/Remote stacks must grant a non-empty capability set.
        let compute = create_handler_stack_from_profile(&CapabilityProfile::compute_only());
        assert!(
            compute.capabilities().runtime_caps.is_empty(),
            "ComputeOnly grants nothing"
        );
        let policy = create_handler_stack_from_profile(&CapabilityProfile::policy());
        let remote = create_handler_stack_from_profile(&CapabilityProfile::remote());
        assert!(
            !policy.capabilities().runtime_caps.is_empty(),
            "Policy must not be stripped to ComputeOnly"
        );
        assert!(
            !remote.capabilities().runtime_caps.is_empty(),
            "Remote must not be stripped to ComputeOnly"
        );
    }

    #[test]
    fn test_hostcall_tag_to_effect_conversion() {
        let effect =
            create_effect_from_hostcall_tag("console:log", &["hello".to_string()]).unwrap();
        assert_eq!(effect.as_ref().effect_name(), "hostcall:console");

        let effect = create_effect_from_hostcall_tag("fs:read", &["test.txt".to_string()]).unwrap();
        assert_eq!(effect.as_ref().effect_name(), "hostcall:fs:read");

        let effect =
            create_effect_from_hostcall_tag("timer:setTimeout", &["1000".to_string()]).unwrap();
        assert_eq!(effect.as_ref().effect_name(), "hostcall:timer");
        let params = effect
            .parameters()
            .downcast::<(TimerOperation, Option<u64>, Option<u64>)>()
            .expect("typed timer parameters");
        assert!(matches!(&params.0, TimerOperation::SetTimeout));
        assert_eq!(params.1, Some(1000));
        assert_eq!(params.2, None);

        let effect =
            create_effect_from_hostcall_tag("timer:clearTimeout", &["17".to_string()]).unwrap();
        let params = effect
            .parameters()
            .downcast::<(TimerOperation, Option<u64>, Option<u64>)>()
            .expect("typed timer parameters");
        assert!(matches!(&params.0, TimerOperation::ClearTimeout));
        assert_eq!(params.1, None);
        assert_eq!(params.2, Some(17));
    }

    #[test]
    fn timer_tag_conversion_rejects_missing_and_non_numeric_values() {
        for (tag, args) in [
            ("timer:setTimeout", Vec::<String>::new()),
            ("timer:setInterval", vec!["not-a-duration".to_string()]),
            ("timer:clearTimeout", Vec::<String>::new()),
            ("timer:clearInterval", vec!["not-an-id".to_string()]),
        ] {
            assert!(
                matches!(
                    create_effect_from_hostcall_tag(tag, &args),
                    Err(EffectError::InvalidParameters { .. })
                ),
                "{tag} must reject malformed public tag arguments"
            );
        }
    }

    #[test]
    fn test_handler_stack_composition() {
        let mut stack = HandlerStack::new();
        stack.add_handler(Arc::new(ComputeOnlyHandler)); // Higher priority, should block
        stack.add_handler(Arc::new(FullCapsHandler::new())); // Lower priority due to ordering

        let effect = ConsoleHostcallEffect {
            method: "log".to_string(),
            args: vec!["test".to_string()],
        };

        // ComputeOnly should block before FullCaps gets to handle it
        let result = stack.handle_effect(&effect);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EffectError::CapabilityDenied { .. }
        ));
    }
}
