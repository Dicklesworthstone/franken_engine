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
    HandlerStack,
};
use crate::capability::{CapabilityProfile, ProfileKind, RuntimeCapability};
use frankenengine_extension_host::host_io::{
    HostIoError, HostIoProvider, HostIoRecorder, HostIoRequest, HostIoResponse,
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

/// Filesystem hostcall effect (read, write).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsHostcallEffect {
    pub operation: FsOperation,
    pub path: String,
    pub content: Option<Vec<u8>>, // For write operations
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FsOperation {
    Read,
    Write,
}

impl Effect for FsHostcallEffect {
    type Output = ();

    fn effect_name(&self) -> &'static str {
        match self.operation {
            FsOperation::Read => "hostcall:fs:read",
            FsOperation::Write => "hostcall:fs:write",
        }
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        match self.operation {
            FsOperation::Read => EffectCapabilities::runtime([RuntimeCapability::FsRead]),
            FsOperation::Write => EffectCapabilities::runtime([RuntimeCapability::FsWrite]),
        }
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((
            self.operation.clone(),
            self.path.clone(),
            self.content.clone(),
        ))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(FsOperation, String, Option<Vec<u8>>)>()
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
        let outcome = match self
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
        };

        match outcome {
            Ok(response) => Ok(Some(Self::effect_result_from_host_io(&response))),
            Err(HostIoError::Io { detail }) => Err(EffectError::HandlerError {
                handler: "full_caps_handler".to_string(),
                message: detail,
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
                    .downcast::<(FsOperation, String, Option<Vec<u8>>)>()
                    .map_err(|_| EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected (FsOperation, String, Option<Vec<u8>>) parameters"
                            .to_string(),
                    })?;
                let (operation, path, content) = *params;
                Ok(match operation {
                    FsOperation::Read => HostIoRequest::FsRead { path },
                    FsOperation::Write => HostIoRequest::FsWrite {
                        path,
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
                let (url, _method, _headers, body) = *params;
                Ok(HostIoRequest::NetworkSend {
                    endpoint: url,
                    payload: body.unwrap_or_default(),
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
            HostIoResponse::NetworkSend { bytes_sent } => EffectResult::new(*bytes_sent),
            HostIoResponse::NetworkRecv { bytes } => EffectResult::new(bytes.clone()),
        }
    }
}

impl Handler for FullCapsHandler {
    fn can_handle(&self, effect_name: &str) -> bool {
        effect_name.starts_with("hostcall:")
    }

    fn handle(&self, effect: &dyn ErasedEffect) -> Result<Option<EffectResult>, EffectError> {
        // FullCaps is permitted to invoke all hostcalls, but `fs:read`,
        // `fs:write`, and `network` are explicitly denied unless a sandboxed
        // extension-host provider is installed. `console`, `timer`, and
        // `module` keep their in-process migration paths.
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
            "hostcall:timer" => {
                if let Ok(params) = effect
                    .parameters()
                    .downcast::<(TimerOperation, Option<u64>, Option<u64>)>()
                {
                    let (operation, duration_ms, timer_id) = *params;
                    // Simulate timer operations
                    match operation {
                        TimerOperation::SetTimeout | TimerOperation::SetInterval => {
                            let new_timer_id = 42u64; // Simulated timer ID
                            println!(
                                "Setting timer for {}ms -> ID {}",
                                duration_ms.unwrap_or(0),
                                new_timer_id
                            );
                            Ok(Some(EffectResult::new(Some(new_timer_id))))
                        }
                        TimerOperation::ClearTimeout | TimerOperation::ClearInterval => {
                            println!("Clearing timer ID {}", timer_id.unwrap_or(0));
                            Ok(Some(EffectResult::new(None::<u64>)))
                        }
                    }
                } else {
                    Err(EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected timer parameters".to_string(),
                    })
                }
            }
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
        // FullCaps provides all runtime capabilities
        EffectCapabilities::runtime(RuntimeCapability::ALL.iter().copied())
    }

    fn priority(&self) -> EffectPriority {
        EffectPriority::High
    }

    fn handler_name(&self) -> &'static str {
        "full_caps_handler"
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
            "hostcall:timer" => {
                // EngineCore allows timer operations
                if let Ok(params) = effect
                    .parameters()
                    .downcast::<(TimerOperation, Option<u64>, Option<u64>)>()
                {
                    let (operation, duration_ms, timer_id) = *params;
                    match operation {
                        TimerOperation::SetTimeout | TimerOperation::SetInterval => {
                            let new_timer_id = 100u64; // Engine-specific timer ID
                            println!(
                                "[ENGINE] Setting timer for {}ms -> ID {}",
                                duration_ms.unwrap_or(0),
                                new_timer_id
                            );
                            Ok(Some(EffectResult::new(Some(new_timer_id))))
                        }
                        TimerOperation::ClearTimeout | TimerOperation::ClearInterval => {
                            println!("[ENGINE] Clearing timer ID {}", timer_id.unwrap_or(0));
                            Ok(Some(EffectResult::new(None::<u64>)))
                        }
                    }
                } else {
                    Err(EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected timer parameters".to_string(),
                    })
                }
            }
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

/// Convert a legacy hostcall tag to an appropriate Effect.
///
/// This function provides compatibility with the existing hostcall dispatch system
/// by converting hostcall tags and parameters to the new Effect types.
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
            let effect = FsHostcallEffect {
                operation,
                path,
                content,
            };
            Ok(Box::new(effect))
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
            let duration_ms = args.first().and_then(|s| s.parse().ok());
            let timer_id = args.get(1).and_then(|s| s.parse().ok());
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
        _ => Err(EffectError::Unhandled {
            effect_name: tag.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenengine_extension_host::host_io::HostIoCapability;

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
        // it EXPLICITLY DENIES them with `CapabilityDenied`. `timer` keeps its
        // in-process path and the helper stays `false`.
        let handler = FullCapsHandler::new();
        assert!(
            !handler.dispatches_real_hostcalls(),
            "no real fs/network executor exists, so this must stay false (bd-6wc97)"
        );

        // fs:read — denied, not a canned "simulated content of {path}" buffer.
        let fs_read = FsHostcallEffect {
            operation: FsOperation::Read,
            path: "/etc/hostname".to_string(),
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

        // timer keeps its in-process path (the decision denies only fs/network).
        let timer_effect = TimerHostcallEffect {
            operation: TimerOperation::SetTimeout,
            duration_ms: Some(10),
            timer_id: None,
        };
        assert!(
            handler.handle(&timer_effect).is_ok(),
            "timer must remain handled (bd-6wc97 denies only fs/network)"
        );
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
                HostIoRequest::NetworkSend { payload, .. } => HostIoResponse::NetworkSend {
                    bytes_sent: payload.len() as u64,
                },
                HostIoRequest::NetworkRecv { max_len, .. } => HostIoResponse::NetworkRecv {
                    bytes: vec![0; *max_len as usize],
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

    #[test]
    fn full_caps_with_provider_routes_fs_and_network_bd_lrbbz_7() {
        let provider = Arc::new(RecordingHostIo::default());
        let handler = FullCapsHandler::with_host_io(provider.clone());
        assert!(handler.dispatches_real_hostcalls());

        let fs_read = FsHostcallEffect {
            operation: FsOperation::Read,
            path: "/data/x".to_string(),
            content: None,
        };
        assert!(handler.handle(&fs_read).expect("fs read routed").is_some());

        let fs_write = FsHostcallEffect {
            operation: FsOperation::Write,
            path: "/data/y".to_string(),
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
        let network = NetworkHostcallEffect {
            url: "https://host:443".to_string(),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: Some(b"hi".to_vec()),
        };
        assert!(record_handler.handle(&network).is_ok());
        assert_eq!(recorder.entries().len(), 1);

        let replay = Arc::new(InMemoryHostIoTranscript::replaying(recorder.entries()));
        let replay_handler =
            FullCapsHandler::with_host_io_recorded(Arc::new(NeverCalledHostIo), replay);
        assert!(replay_handler.handle(&network).is_ok());
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
