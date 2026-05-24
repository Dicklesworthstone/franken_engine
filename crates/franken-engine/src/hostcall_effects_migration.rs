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
#[derive(Debug)]
pub struct FullCapsHandler;

impl Handler for FullCapsHandler {
    fn can_handle(&self, effect_name: &str) -> bool {
        effect_name.starts_with("hostcall:")
    }

    fn handle(&self, effect: &dyn ErasedEffect) -> Result<Option<EffectResult>, EffectError> {
        // FullCaps allows all hostcalls - dispatch to actual implementation
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
            "hostcall:fs:read" => {
                if let Ok(params) = effect
                    .parameters()
                    .downcast::<(FsOperation, String, Option<Vec<u8>>)>()
                {
                    let (_, path, _) = *params;
                    // Simulate file read
                    let content = format!("simulated content of {}", path).into_bytes();
                    Ok(Some(EffectResult::new(Some(content))))
                } else {
                    Err(EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected (FsOperation, String, Option<Vec<u8>>) parameters"
                            .to_string(),
                    })
                }
            }
            "hostcall:fs:write" => {
                if let Ok(params) = effect
                    .parameters()
                    .downcast::<(FsOperation, String, Option<Vec<u8>>)>()
                {
                    let (_, path, content) = *params;
                    // Simulate file write
                    println!(
                        "Writing {} bytes to {}",
                        content.as_ref().map_or(0, |c| c.len()),
                        path
                    );
                    Ok(Some(EffectResult::new(Some(Vec::<u8>::new()))))
                } else {
                    Err(EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected (FsOperation, String, Option<Vec<u8>>) parameters"
                            .to_string(),
                    })
                }
            }
            "hostcall:network" => {
                if let Ok(params) =
                    effect
                        .parameters()
                        .downcast::<(String, String, Vec<(String, String)>, Option<Vec<u8>>)>()
                {
                    let (url, method, _, _) = *params;
                    // Simulate network request
                    let response = NetworkResponse {
                        status: 200,
                        headers: vec![("content-type".to_string(), "application/json".to_string())],
                        body: format!(
                            r#"{{"result": "simulated response for {} {}", "success": true}}"#,
                            method, url
                        )
                        .into_bytes(),
                    };
                    Ok(Some(EffectResult::new(response)))
                } else {
                    Err(EffectError::InvalidParameters {
                        effect_name: effect.effect_name().to_string(),
                        reason: "Expected network parameters".to_string(),
                    })
                }
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
            stack.add_handler(Arc::new(FullCapsHandler));
        }
        ProfileKind::EngineCore => {
            stack.add_handler(Arc::new(EngineCoreHandler));
        }
        ProfileKind::Policy => {
            // Policy profile handler would be implemented here
            // For now, using ComputeOnly as placeholder
            stack.add_handler(Arc::new(ComputeOnlyHandler));
        }
        ProfileKind::Remote => {
            // Remote profile handler would be implemented here
            // For now, using ComputeOnly as placeholder
            stack.add_handler(Arc::new(ComputeOnlyHandler));
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
            let duration_ms = args.get(0).and_then(|s| s.parse().ok());
            let timer_id = args.get(1).and_then(|s| s.parse().ok());
            let effect = TimerHostcallEffect {
                operation,
                duration_ms,
                timer_id,
            };
            Ok(Box::new(effect))
        }
        tag if tag.starts_with("module:") => {
            let module_path = args.get(0).unwrap_or(&String::new()).clone();
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

    #[test]
    fn test_full_caps_handler_console() {
        let handler = FullCapsHandler;
        let effect = ConsoleHostcallEffect {
            method: "log".to_string(),
            args: vec!["test".to_string(), "message".to_string()],
        };

        assert!(handler.can_handle(effect.effect_name()));
        let result = handler.handle(&effect);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_compute_only_denies_hostcalls() {
        let handler = ComputeOnlyHandler;
        let effect = ConsoleHostcallEffect {
            method: "log".to_string(),
            args: vec!["test".to_string()],
        };

        assert!(handler.can_handle(effect.effect_name()));
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

        assert!(handler.can_handle(effect.effect_name()));
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

        assert!(!handler.can_handle(effect.effect_name()));
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

    #[test]
    fn test_hostcall_tag_to_effect_conversion() {
        let effect =
            create_effect_from_hostcall_tag("console:log", &["hello".to_string()]).unwrap();
        assert_eq!(effect.effect_name(), "hostcall:console");

        let effect = create_effect_from_hostcall_tag("fs:read", &["test.txt".to_string()]).unwrap();
        assert_eq!(effect.effect_name(), "hostcall:fs:read");

        let effect =
            create_effect_from_hostcall_tag("timer:setTimeout", &["1000".to_string()]).unwrap();
        assert_eq!(effect.effect_name(), "hostcall:timer");
    }

    #[test]
    fn test_handler_stack_composition() {
        let mut stack = HandlerStack::new();
        stack.add_handler(Arc::new(ComputeOnlyHandler)); // Higher priority, should block
        stack.add_handler(Arc::new(FullCapsHandler)); // Lower priority due to ordering

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
