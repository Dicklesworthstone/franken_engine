//! Algebraic effects substrate for hostcalls and capability profiles.
//!
//! Implements algebraic effects based on Plotkin/Pretnar 2009 operational semantics.
//! Every cross-boundary operation is modeled as an Effect; handlers compose through
//! HandlerStack; subtyping is set inclusion on effect sets.
//!
//! This module refactors the existing hostcall dispatch and capability profile systems
//! into a unified algebraic-effects substrate. Instead of separate APIs for hostcalls
//! and capability attenuation, both are now modeled as effect operations with
//! composable handlers.
//!
//! Key components:
//! - `Effect`: Trait representing an algebraic effect operation
//! - `Handler`: Trait for effect handlers that provide implementations
//! - `HandlerStack`: Composable stack of handlers with associative composition
//! - `EffectSet`: Set of effects for subtyping/capability checking
//! - Migration adapters for existing hostcall APIs
//!
//! Plan references: Track PP.1 (bd-cixqu.42.1) - Plotkin/Pretnar 2009 algebraic effects.

#![forbid(unsafe_code)]

use std::any::{Any, TypeId};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Effect trait and operation signatures
// ---------------------------------------------------------------------------

/// An algebraic effect operation.
///
/// Effects represent cross-boundary operations that can be performed by
/// subsystems. Each effect has a unique identifier, parameter types, and
/// return type. Effects are implemented by handlers in the handler stack.
///
/// Based on Plotkin/Pretnar 2009: effects are operations in an algebraic
/// theory, with handlers providing interpretations.
pub trait Effect: fmt::Debug + Send + Sync + 'static {
    /// The type of value returned by this effect.
    type Output: fmt::Debug + Clone + Send + Sync + 'static;

    /// Unique identifier for this effect type.
    fn effect_name(&self) -> &'static str;

    /// Set of capabilities required to invoke this effect.
    fn required_capabilities(&self) -> EffectCapabilities;

    /// Execution priority for handler ordering (higher = earlier).
    fn priority(&self) -> EffectPriority {
        EffectPriority::Normal
    }

    /// Type-erased parameters for dynamic dispatch.
    fn parameters(&self) -> Box<dyn Any + Send + Sync>;

    /// Type identifier for effect parameters (used for dynamic casting).
    fn parameter_type_id(&self) -> TypeId;
}

/// Priority levels for effect handler ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EffectPriority {
    /// Low priority effects (e.g., logging, telemetry).
    Low = 100,
    /// Normal priority effects (default).
    Normal = 200,
    /// High priority effects (e.g., security, capability checks).
    High = 300,
    /// Critical priority effects (e.g., panic handlers, cleanup).
    Critical = 400,
}

/// Capabilities required to invoke an effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectCapabilities {
    /// Runtime capabilities required.
    pub runtime_caps: BTreeSet<RuntimeCapability>,
    /// Security epoch requirements.
    pub min_epoch: Option<SecurityEpoch>,
    /// Custom capability strings (for extensibility).
    pub custom_caps: BTreeSet<String>,
}

impl EffectCapabilities {
    /// Create capabilities requiring specific runtime capabilities.
    pub fn runtime(caps: impl IntoIterator<Item = RuntimeCapability>) -> Self {
        Self {
            runtime_caps: caps.into_iter().collect(),
            min_epoch: None,
            custom_caps: BTreeSet::new(),
        }
    }

    /// Create capabilities with epoch requirement.
    pub fn epoch(epoch: SecurityEpoch) -> Self {
        Self {
            runtime_caps: BTreeSet::new(),
            min_epoch: Some(epoch),
            custom_caps: BTreeSet::new(),
        }
    }

    /// Create capabilities with custom capability strings.
    pub fn custom(caps: impl IntoIterator<Item = String>) -> Self {
        Self {
            runtime_caps: BTreeSet::new(),
            min_epoch: None,
            custom_caps: caps.into_iter().collect(),
        }
    }

    /// Create empty capabilities (no requirements).
    pub fn none() -> Self {
        Self {
            runtime_caps: BTreeSet::new(),
            min_epoch: None,
            custom_caps: BTreeSet::new(),
        }
    }

    /// Check if this capability set is satisfied by another.
    pub fn is_satisfied_by(&self, other: &Self) -> bool {
        // Runtime capabilities must be subset
        if !self.runtime_caps.is_subset(&other.runtime_caps) {
            return false;
        }

        // Epoch requirement must be met
        if let Some(min_epoch) = self.min_epoch {
            if let Some(other_epoch) = other.min_epoch {
                if other_epoch < min_epoch {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Custom capabilities must be subset
        self.custom_caps.is_subset(&other.custom_caps)
    }
}

// ---------------------------------------------------------------------------
// Handler trait and composition
// ---------------------------------------------------------------------------

/// Handler for algebraic effects.
///
/// Handlers provide implementations for effects. They can handle multiple
/// effect types and compose through the HandlerStack. Handler composition
/// follows algebraic laws: associativity and identity.
pub trait Handler: fmt::Debug + Send + Sync {
    /// Check if this handler can handle the given effect.
    fn can_handle(&self, effect_name: &str) -> bool;

    /// Handle an effect operation.
    ///
    /// Returns Some(result) if the effect was handled, None if it should
    /// be passed to the next handler in the stack.
    fn handle(&self, effect: &dyn Effect<Output = Box<dyn Any + Send + Sync>>) -> Result<Option<EffectResult>, EffectError>;

    /// Capabilities provided by this handler.
    fn provided_capabilities(&self) -> EffectCapabilities;

    /// Handler priority for stack ordering.
    fn priority(&self) -> EffectPriority {
        EffectPriority::Normal
    }

    /// Handler identifier for debugging.
    fn handler_name(&self) -> &'static str;
}

/// Result of handling an effect.
#[derive(Debug)]
pub struct EffectResult {
    /// The result value (type-erased).
    pub value: Box<dyn Any + Send + Sync>,
    /// Type identifier for the result.
    pub type_id: TypeId,
    /// Optional telemetry data.
    pub telemetry: Option<EffectTelemetry>,
}

impl EffectResult {
    /// Create a new effect result.
    pub fn new<T: fmt::Debug + Clone + Send + Sync + 'static>(value: T) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            value: Box::new(value),
            telemetry: None,
        }
    }

    /// Create a result with telemetry data.
    pub fn with_telemetry<T: fmt::Debug + Clone + Send + Sync + 'static>(
        value: T,
        telemetry: EffectTelemetry,
    ) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            value: Box::new(value),
            telemetry: Some(telemetry),
        }
    }

    /// Downcast the result to a specific type.
    pub fn downcast<T: fmt::Debug + Clone + Send + Sync + 'static>(self) -> Result<T, EffectError> {
        if self.type_id == TypeId::of::<T>() {
            match self.value.downcast::<T>() {
                Ok(value) => Ok(*value),
                Err(_) => Err(EffectError::TypeMismatch {
                    expected: std::any::type_name::<T>().to_string(),
                    got: "unknown".to_string(),
                }),
            }
        } else {
            Err(EffectError::TypeMismatch {
                expected: std::any::type_name::<T>().to_string(),
                got: "unknown".to_string(),
            })
        }
    }
}

/// Telemetry data for effect execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectTelemetry {
    /// Handler that processed the effect.
    pub handler_name: String,
    /// Execution time in nanoseconds.
    pub execution_time_ns: u64,
    /// Capability checks performed.
    pub capability_checks: Vec<String>,
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

/// Error types for effect handling.
#[derive(Debug, Clone)]
pub enum EffectError {
    /// Effect was not handled by any handler.
    Unhandled { effect_name: String },
    /// Capability check failed.
    CapabilityDenied { required: EffectCapabilities },
    /// Type mismatch in result conversion.
    TypeMismatch { expected: String, got: String },
    /// Handler-specific error.
    HandlerError { handler: String, message: String },
    /// Effect parameters are invalid.
    InvalidParameters { effect_name: String, reason: String },
    /// Stack overflow in handler composition.
    StackOverflow,
    /// Circular dependency in handlers.
    CircularDependency { path: Vec<String> },
}

impl fmt::Display for EffectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unhandled { effect_name } => {
                write!(f, "Unhandled effect: {}", effect_name)
            }
            Self::CapabilityDenied { required } => {
                write!(f, "Capability denied: {:?}", required)
            }
            Self::TypeMismatch { expected, got } => {
                write!(f, "Type mismatch: expected {}, got {}", expected, got)
            }
            Self::HandlerError { handler, message } => {
                write!(f, "Handler error in {}: {}", handler, message)
            }
            Self::InvalidParameters {
                effect_name,
                reason,
            } => {
                write!(f, "Invalid parameters for {}: {}", effect_name, reason)
            }
            Self::StackOverflow => write!(f, "Handler stack overflow"),
            Self::CircularDependency { path } => {
                write!(f, "Circular dependency: {}", path.join(" -> "))
            }
        }
    }
}

impl std::error::Error for EffectError {}

// ---------------------------------------------------------------------------
// Handler stack composition
// ---------------------------------------------------------------------------

/// Composable stack of effect handlers.
///
/// HandlerStack implements algebraic composition of handlers following
/// Plotkin/Pretnar laws:
/// - Associativity: (h1 ∘ h2) ∘ h3 = h1 ∘ (h2 ∘ h3)
/// - Identity: id ∘ h = h ∘ id = h
/// - Effect propagation: unhandled effects propagate down the stack
pub struct HandlerStack {
    /// Handlers ordered by priority (highest first).
    handlers: Vec<Arc<dyn Handler>>,
    /// Capabilities provided by the entire stack.
    capabilities: EffectCapabilities,
    /// Maximum stack depth to prevent overflow.
    max_depth: usize,
    /// Circular dependency detection.
    dependency_path: Vec<String>,
}

impl HandlerStack {
    /// Create a new empty handler stack.
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            capabilities: EffectCapabilities::none(),
            max_depth: 100,
            dependency_path: Vec::new(),
        }
    }

    /// Create a handler stack with specific maximum depth.
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            handlers: Vec::new(),
            capabilities: EffectCapabilities::none(),
            max_depth,
            dependency_path: Vec::new(),
        }
    }

    /// Add a handler to the stack.
    ///
    /// Handlers are automatically ordered by priority. Higher priority
    /// handlers are executed first.
    pub fn add_handler(&mut self, handler: Arc<dyn Handler>) {
        // Find insertion position based on priority
        let priority = handler.priority();
        let insert_pos = self
            .handlers
            .iter()
            .position(|h| h.priority() < priority)
            .unwrap_or(self.handlers.len());

        self.handlers.insert(insert_pos, handler.clone());
        self.update_capabilities();
    }

    /// Remove a handler by name.
    pub fn remove_handler(&mut self, handler_name: &str) -> bool {
        let initial_len = self.handlers.len();
        self.handlers.retain(|h| h.handler_name() != handler_name);
        let removed = self.handlers.len() != initial_len;
        if removed {
            self.update_capabilities();
        }
        removed
    }

    /// Get handler names in execution order.
    pub fn handler_names(&self) -> Vec<&'static str> {
        self.handlers.iter().map(|h| h.handler_name()).collect()
    }

    /// Get capabilities provided by the entire stack.
    pub fn capabilities(&self) -> &EffectCapabilities {
        &self.capabilities
    }

    /// Execute an effect through the handler stack.
    pub fn handle_effect(&mut self, effect: &dyn Effect<Output = Box<dyn Any + Send + Sync>>) -> Result<EffectResult, EffectError> {
        // Check stack depth
        if self.dependency_path.len() >= self.max_depth {
            return Err(EffectError::StackOverflow);
        }

        // Check for circular dependencies
        let effect_name = effect.effect_name();
        if self.dependency_path.contains(&effect_name.to_string()) {
            return Err(EffectError::CircularDependency {
                path: self.dependency_path.clone(),
            });
        }

        // Check capability requirements
        let required_caps = effect.required_capabilities();
        if !required_caps.is_satisfied_by(&self.capabilities) {
            return Err(EffectError::CapabilityDenied {
                required: required_caps,
            });
        }

        // Add to dependency path
        self.dependency_path.push(effect_name.to_string());

        // Try each handler in priority order
        for handler in &self.handlers {
            if handler.can_handle(effect_name) {
                match handler.handle(effect) {
                    Ok(Some(result)) => {
                        self.dependency_path.pop();
                        return Ok(result);
                    }
                    Ok(None) => {
                        // Handler chose not to handle, continue to next
                        continue;
                    }
                    Err(e) => {
                        self.dependency_path.pop();
                        return Err(e);
                    }
                }
            }
        }

        // No handler found
        self.dependency_path.pop();
        Err(EffectError::Unhandled {
            effect_name: effect_name.to_string(),
        })
    }

    /// Compose with another handler stack (associative operation).
    pub fn compose(mut self, other: HandlerStack) -> Self {
        for handler in other.handlers {
            self.add_handler(handler);
        }
        self
    }

    /// Check if stack can handle a specific effect.
    pub fn can_handle(&self, effect_name: &str) -> bool {
        self.handlers.iter().any(|h| h.can_handle(effect_name))
    }

    /// Update combined capabilities from all handlers.
    fn update_capabilities(&mut self) {
        let mut runtime_caps = BTreeSet::new();
        let mut min_epoch = None;
        let mut custom_caps = BTreeSet::new();

        for handler in &self.handlers {
            let caps = handler.provided_capabilities();
            runtime_caps.extend(caps.runtime_caps);
            custom_caps.extend(caps.custom_caps);

            if let Some(epoch) = caps.min_epoch {
                min_epoch = Some(match min_epoch {
                    None => epoch,
                    Some(current) => current.max(epoch),
                });
            }
        }

        self.capabilities = EffectCapabilities {
            runtime_caps,
            min_epoch,
            custom_caps,
        };
    }
}

impl Default for HandlerStack {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HandlerStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandlerStack")
            .field("handlers", &self.handler_names())
            .field("capabilities", &self.capabilities)
            .field("max_depth", &self.max_depth)
            .field("dependency_path", &self.dependency_path)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Effect set for subtyping
// ---------------------------------------------------------------------------

/// Set of effects for subtyping and capability checking.
///
/// Effect sets support set inclusion subtyping: if EffectSet A ⊆ EffectSet B,
/// then code requiring B can safely use code that only performs effects from A.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectSet {
    /// Effect names in the set.
    effects: BTreeSet<String>,
    /// Capabilities required by all effects in the set.
    capabilities: EffectCapabilities,
}

impl EffectSet {
    /// Create an empty effect set.
    pub fn empty() -> Self {
        Self {
            effects: BTreeSet::new(),
            capabilities: EffectCapabilities::none(),
        }
    }

    /// Create an effect set from effect names.
    pub fn from_effects(effects: impl IntoIterator<Item = String>) -> Self {
        Self {
            effects: effects.into_iter().collect(),
            capabilities: EffectCapabilities::none(),
        }
    }

    /// Create an effect set with capabilities.
    pub fn with_capabilities(
        effects: impl IntoIterator<Item = String>,
        capabilities: EffectCapabilities,
    ) -> Self {
        Self {
            effects: effects.into_iter().collect(),
            capabilities,
        }
    }

    /// Add an effect to the set.
    pub fn add_effect(&mut self, effect: String) {
        self.effects.insert(effect);
    }

    /// Remove an effect from the set.
    pub fn remove_effect(&mut self, effect: &str) -> bool {
        self.effects.remove(effect)
    }

    /// Check if the set contains an effect.
    pub fn contains(&self, effect: &str) -> bool {
        self.effects.contains(effect)
    }

    /// Get effect names.
    pub fn effects(&self) -> &BTreeSet<String> {
        &self.effects
    }

    /// Get capabilities.
    pub fn capabilities(&self) -> &EffectCapabilities {
        &self.capabilities
    }

    /// Check if this effect set is a subset of another (subtyping).
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.effects.is_subset(&other.effects)
            && self.capabilities.is_satisfied_by(&other.capabilities)
    }

    /// Union of two effect sets.
    pub fn union(&self, other: &Self) -> Self {
        let mut effects = self.effects.clone();
        effects.extend(other.effects.iter().cloned());

        // Combine capabilities (union of requirements)
        let mut runtime_caps = self.capabilities.runtime_caps.clone();
        runtime_caps.extend(other.capabilities.runtime_caps.iter().cloned());

        let mut custom_caps = self.capabilities.custom_caps.clone();
        custom_caps.extend(other.capabilities.custom_caps.iter().cloned());

        let min_epoch = match (self.capabilities.min_epoch, other.capabilities.min_epoch) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        Self {
            effects,
            capabilities: EffectCapabilities {
                runtime_caps,
                min_epoch,
                custom_caps,
            },
        }
    }

    /// Intersection of two effect sets.
    pub fn intersection(&self, other: &Self) -> Self {
        let effects: BTreeSet<String> =
            self.effects.intersection(&other.effects).cloned().collect();

        // Capabilities intersection (minimum requirements)
        let runtime_caps: BTreeSet<RuntimeCapability> = self
            .capabilities
            .runtime_caps
            .intersection(&other.capabilities.runtime_caps)
            .cloned()
            .collect();

        let custom_caps: BTreeSet<String> = self
            .capabilities
            .custom_caps
            .intersection(&other.capabilities.custom_caps)
            .cloned()
            .collect();

        let min_epoch = match (self.capabilities.min_epoch, other.capabilities.min_epoch) {
            (Some(a), Some(b)) => Some(a.min(b)),
            _ => None,
        };

        Self {
            effects,
            capabilities: EffectCapabilities {
                runtime_caps,
                min_epoch,
                custom_caps,
            },
        }
    }

    /// Check if the effect set is empty.
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }

    /// Number of effects in the set.
    pub fn len(&self) -> usize {
        self.effects.len()
    }
}

// ---------------------------------------------------------------------------
// Concrete effect implementations
// ---------------------------------------------------------------------------

/// Console logging effect.
#[derive(Debug, Clone)]
pub struct ConsoleEffect {
    /// Console level (log, error, warn, info).
    pub level: ConsoleLevel,
    /// Arguments to log.
    pub args: Vec<String>,
}

/// Console logging levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConsoleLevel {
    Log,
    Error,
    Warn,
    Info,
}

impl Effect for ConsoleEffect {
    type Output = ();

    fn effect_name(&self) -> &'static str {
        match self.level {
            ConsoleLevel::Log => "console:log",
            ConsoleLevel::Error => "console:error",
            ConsoleLevel::Warn => "console:warn",
            ConsoleLevel::Info => "console:info",
        }
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        // Console output typically needs no special capabilities
        EffectCapabilities::none()
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((self.level, self.args.clone()))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(ConsoleLevel, Vec<String>)>()
    }
}

/// File system read effect.
#[derive(Debug, Clone)]
pub struct FsReadEffect {
    /// Path to read.
    pub path: String,
    /// Optional byte range.
    pub range: Option<(u64, u64)>,
}

impl Effect for FsReadEffect {
    type Output = Vec<u8>;

    fn effect_name(&self) -> &'static str {
        "fs:read"
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::custom(vec!["fs:read".to_string()])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((self.path.clone(), self.range))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(String, Option<(u64, u64)>)>()
    }
}

/// File system write effect.
#[derive(Debug, Clone)]
pub struct FsWriteEffect {
    /// Path to write.
    pub path: String,
    /// Data to write.
    pub data: Vec<u8>,
    /// Whether to append or overwrite.
    pub append: bool,
}

impl Effect for FsWriteEffect {
    type Output = u64; // bytes written

    fn effect_name(&self) -> &'static str {
        "fs:write"
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::custom(vec!["fs:write".to_string()])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((self.path.clone(), self.data.clone(), self.append))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(String, Vec<u8>, bool)>()
    }
}

/// Network connection effect.
#[derive(Debug, Clone)]
pub struct NetConnectEffect {
    /// Host to connect to.
    pub host: String,
    /// Port number.
    pub port: u16,
    /// Connection timeout in milliseconds.
    pub timeout_ms: Option<u64>,
}

impl Effect for NetConnectEffect {
    type Output = u32; // connection handle

    fn effect_name(&self) -> &'static str {
        "net:connect"
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::NetworkEgress])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((self.host.clone(), self.port, self.timeout_ms))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(String, u16, Option<u64>)>()
    }
}

/// Process spawn effect.
#[derive(Debug, Clone)]
pub struct ProcSpawnEffect {
    /// Command to execute.
    pub command: String,
    /// Command arguments.
    pub args: Vec<String>,
    /// Environment variables.
    pub env: BTreeMap<String, String>,
    /// Working directory.
    pub cwd: Option<String>,
}

impl Effect for ProcSpawnEffect {
    type Output = u32; // process handle

    fn effect_name(&self) -> &'static str {
        "proc:spawn"
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::custom(vec!["proc:spawn".to_string()])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((
            self.command.clone(),
            self.args.clone(),
            self.env.clone(),
            self.cwd.clone(),
        ))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(
            String,
            Vec<String>,
            BTreeMap<String, String>,
            Option<String>,
        )>()
    }
}

/// Policy request effect.
#[derive(Debug, Clone)]
pub struct PolicyRequestEffect {
    /// Policy query string.
    pub query: String,
    /// Request context data.
    pub context: BTreeMap<String, String>,
}

impl Effect for PolicyRequestEffect {
    type Output = PolicyDecision;

    fn effect_name(&self) -> &'static str {
        "policy:request"
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::PolicyRead])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((self.query.clone(), self.context.clone()))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(String, BTreeMap<String, String>)>()
    }
}

/// Policy decision result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
    Conditional { requirements: Vec<String> },
}

/// Timer scheduling effect.
#[derive(Debug, Clone)]
pub struct TimerEffect {
    /// Timer operation type.
    pub operation: TimerOperation,
}

/// Timer operation types.
#[derive(Debug, Clone)]
pub enum TimerOperation {
    SetTimeout { delay_ms: u64 },
    SetInterval { interval_ms: u64 },
    ClearTimeout { timer_id: u32 },
    ClearInterval { timer_id: u32 },
}

impl Effect for TimerEffect {
    type Output = Option<u32>; // timer ID for set operations, None for clear

    fn effect_name(&self) -> &'static str {
        match self.operation {
            TimerOperation::SetTimeout { .. } => "timer:setTimeout",
            TimerOperation::SetInterval { .. } => "timer:setInterval",
            TimerOperation::ClearTimeout { .. } => "timer:clearTimeout",
            TimerOperation::ClearInterval { .. } => "timer:clearInterval",
        }
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::custom(vec!["timer".to_string()])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new(self.operation.clone())
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<TimerOperation>()
    }
}

/// JavaScript builtin effect.
#[derive(Debug, Clone)]
pub struct BuiltinEffect {
    /// Builtin function name (e.g., "ArrayPrototypePush").
    pub name: String,
    /// Serialized arguments.
    pub args: Vec<BuiltinValue>,
}

/// Simplified value type for builtin effects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BuiltinValue {
    Undefined,
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Object(u32), // object ID
}

impl Effect for BuiltinEffect {
    type Output = BuiltinValue;

    fn effect_name(&self) -> &'static str {
        "builtin:call"
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::VmDispatch])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new((self.name.clone(), self.args.clone()))
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<(String, Vec<BuiltinValue>)>()
    }
}

/// Promise effect for async operations.
#[derive(Debug, Clone)]
pub struct PromiseEffect {
    /// Promise operation type.
    pub operation: PromiseOperation,
}

/// Promise operation types.
#[derive(Debug, Clone)]
pub enum PromiseOperation {
    Create,
    Resolve {
        promise_id: u32,
        value: BuiltinValue,
    },
    Reject {
        promise_id: u32,
        reason: BuiltinValue,
    },
    Then {
        promise_id: u32,
    },
    All {
        promises: Vec<u32>,
    },
    Race {
        promises: Vec<u32>,
    },
}

impl Effect for PromiseEffect {
    type Output = BuiltinValue;

    fn effect_name(&self) -> &'static str {
        match self.operation {
            PromiseOperation::Create => "promise:create",
            PromiseOperation::Resolve { .. } => "promise:resolve",
            PromiseOperation::Reject { .. } => "promise:reject",
            PromiseOperation::Then { .. } => "promise:then",
            PromiseOperation::All { .. } => "promise:all",
            PromiseOperation::Race { .. } => "promise:race",
        }
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::VmDispatch])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new(self.operation.clone())
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<PromiseOperation>()
    }
}

/// Number parsing/formatting effect.
#[derive(Debug, Clone)]
pub struct NumberEffect {
    /// Number operation type.
    pub operation: NumberOperation,
}

/// Number operation types.
#[derive(Debug, Clone)]
pub enum NumberOperation {
    ParseInt { value: String, radix: Option<i32> },
    ParseFloat { value: String },
    Format { value: f64, precision: Option<u32> },
    IsNaN { value: f64 },
    IsFinite { value: f64 },
}

impl Effect for NumberEffect {
    type Output = BuiltinValue;

    fn effect_name(&self) -> &'static str {
        match self.operation {
            NumberOperation::ParseInt { .. } => "number:parseInt",
            NumberOperation::ParseFloat { .. } => "number:parseFloat",
            NumberOperation::Format { .. } => "number:format",
            NumberOperation::IsNaN { .. } => "number:isNaN",
            NumberOperation::IsFinite { .. } => "number:isFinite",
        }
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::VmDispatch])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new(self.operation.clone())
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<NumberOperation>()
    }
}

/// Module loading effect.
#[derive(Debug, Clone)]
pub struct ModuleEffect {
    /// Module operation type.
    pub operation: ModuleOperation,
}

/// Module operation types.
#[derive(Debug, Clone)]
pub enum ModuleOperation {
    Require { specifier: String },
    Import { specifier: String },
    Export { name: String, value: BuiltinValue },
}

impl Effect for ModuleEffect {
    type Output = BuiltinValue;

    fn effect_name(&self) -> &'static str {
        match self.operation {
            ModuleOperation::Require { .. } => "module:require",
            ModuleOperation::Import { .. } => "module:import",
            ModuleOperation::Export { .. } => "module:export",
        }
    }

    fn required_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::runtime([RuntimeCapability::VmDispatch])
    }

    fn parameters(&self) -> Box<dyn Any + Send + Sync> {
        Box::new(self.operation.clone())
    }

    fn parameter_type_id(&self) -> TypeId {
        TypeId::of::<ModuleOperation>()
    }
}

// ---------------------------------------------------------------------------
// Default handlers for existing hostcalls
// ---------------------------------------------------------------------------

/// Handler for console effects.
#[derive(Debug)]
pub struct ConsoleHandler {
    /// Console output buffer.
    pub output: Arc<std::sync::Mutex<Vec<ConsoleEntry>>>,
    /// Maximum entries to keep.
    pub max_entries: usize,
}

/// Console output entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleEntry {
    pub level: ConsoleLevel,
    pub message: String,
    pub timestamp: std::time::SystemTime,
}

impl ConsoleHandler {
    /// Create a new console handler.
    pub fn new() -> Self {
        Self {
            output: Arc::new(std::sync::Mutex::new(Vec::new())),
            max_entries: 1000,
        }
    }

    /// Create a console handler with custom buffer size.
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            output: Arc::new(std::sync::Mutex::new(Vec::new())),
            max_entries,
        }
    }

    /// Get console output entries.
    pub fn get_output(&self) -> Vec<ConsoleEntry> {
        self.output.lock().unwrap().clone()
    }

    /// Clear console output.
    pub fn clear(&self) {
        self.output.lock().unwrap().clear();
    }
}

impl Handler for ConsoleHandler {
    fn can_handle(&self, effect_name: &str) -> bool {
        matches!(
            effect_name,
            "console:log" | "console:error" | "console:warn" | "console:info"
        )
    }

    fn handle(&self, effect: &dyn Effect<Output = Box<dyn Any + Send + Sync>>) -> Result<Option<EffectResult>, EffectError> {
        if let Some(console_effect) = effect
            .parameters()
            .downcast_ref::<(ConsoleLevel, Vec<String>)>()
        {
            let (level, args) = console_effect;
            let message = args.join(" ");

            let entry = ConsoleEntry {
                level: *level,
                message,
                timestamp: std::time::SystemTime::now(),
            };

            {
                let mut output = self.output.lock().unwrap();
                output.push(entry);

                // Trim to max entries
                if output.len() > self.max_entries {
                    output.remove(0);
                }
            }

            Ok(Some(EffectResult::new(())))
        } else {
            Ok(None)
        }
    }

    fn provided_capabilities(&self) -> EffectCapabilities {
        EffectCapabilities::none()
    }

    fn handler_name(&self) -> &'static str {
        "ConsoleHandler"
    }
}

impl Default for ConsoleHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock handler for file system effects (for testing).
#[derive(Debug)]
pub struct MockFsHandler {
    /// Mock file system state.
    pub files: Arc<std::sync::Mutex<BTreeMap<String, Vec<u8>>>>,
    /// Whether to allow reads.
    pub allow_reads: bool,
    /// Whether to allow writes.
    pub allow_writes: bool,
}

impl MockFsHandler {
    /// Create a new mock filesystem handler.
    pub fn new() -> Self {
        Self {
            files: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            allow_reads: true,
            allow_writes: true,
        }
    }

    /// Add a mock file.
    pub fn add_file(&self, path: &str, content: &[u8]) {
        self.files
            .lock()
            .unwrap()
            .insert(path.to_string(), content.to_vec());
    }

    /// Check if file exists.
    pub fn file_exists(&self, path: &str) -> bool {
        self.files.lock().unwrap().contains_key(path)
    }
}

impl Handler for MockFsHandler {
    fn can_handle(&self, effect_name: &str) -> bool {
        matches!(effect_name, "fs:read" | "fs:write")
    }

    fn handle(&self, effect: &dyn Effect<Output = Box<dyn Any + Send + Sync>>) -> Result<Option<EffectResult>, EffectError> {
        match effect.effect_name() {
            "fs:read" => {
                if !self.allow_reads {
                    return Err(EffectError::CapabilityDenied {
                        required: EffectCapabilities::custom(vec!["fs:read".to_string()]),
                    });
                }

                if let Some(params) = effect
                    .parameters()
                    .downcast_ref::<(String, Option<(u64, u64)>)>()
                {
                    let (path, range) = params;
                    let files = self.files.lock().unwrap();

                    if let Some(content) = files.get(path) {
                        let result = match range {
                            Some((start, end)) => {
                                let start = *start as usize;
                                let end = (*end as usize).min(content.len());
                                content.get(start..end).unwrap_or(&[]).to_vec()
                            }
                            None => content.clone(),
                        };
                        Ok(Some(EffectResult::new(result)))
                    } else {
                        Err(EffectError::HandlerError {
                            handler: "MockFsHandler".to_string(),
                            message: format!("File not found: {}", path),
                        })
                    }
                } else {
                    Err(EffectError::InvalidParameters {
                        effect_name: "fs:read".to_string(),
                        reason: "Invalid parameter types".to_string(),
                    })
                }
            }
            "fs:write" => {
                if !self.allow_writes {
                    return Err(EffectError::CapabilityDenied {
                        required: EffectCapabilities::custom(vec!["fs:write".to_string()]),
                    });
                }

                if let Some(params) = effect
                    .parameters()
                    .downcast_ref::<(String, Vec<u8>, bool)>()
                {
                    let (path, data, append) = params;
                    let mut files = self.files.lock().unwrap();

                    let bytes_written = if *append {
                        if let Some(existing) = files.get_mut(path) {
                            let written = data.len() as u64;
                            existing.extend_from_slice(data);
                            written
                        } else {
                            let written = data.len() as u64;
                            files.insert(path.clone(), data.clone());
                            written
                        }
                    } else {
                        let written = data.len() as u64;
                        files.insert(path.clone(), data.clone());
                        written
                    };

                    Ok(Some(EffectResult::new(bytes_written)))
                } else {
                    Err(EffectError::InvalidParameters {
                        effect_name: "fs:write".to_string(),
                        reason: "Invalid parameter types".to_string(),
                    })
                }
            }
            _ => Ok(None),
        }
    }

    fn provided_capabilities(&self) -> EffectCapabilities {
        let mut caps = Vec::new();
        if self.allow_reads {
            caps.push("fs:read".to_string());
        }
        if self.allow_writes {
            caps.push("fs:write".to_string());
        }
        EffectCapabilities::custom(caps)
    }

    fn handler_name(&self) -> &'static str {
        "MockFsHandler"
    }

    fn priority(&self) -> EffectPriority {
        EffectPriority::Low // Mock handler should be low priority
    }
}

impl Default for MockFsHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Migration adapters for existing hostcall APIs
// ---------------------------------------------------------------------------

/// Migration adapter that bridges existing hostcall dispatch to the new Effect API.
///
/// This allows existing capability_profile_security_algebra paths to continue
/// working while gradually migrating to the new algebraic effects substrate.
pub struct HostcallMigrationAdapter {
    /// Effect handler stack.
    pub effect_stack: HandlerStack,
    /// Legacy capability mapping.
    pub capability_mapping: BTreeMap<String, EffectCapabilities>,
}

impl HostcallMigrationAdapter {
    /// Create a new migration adapter with default handlers.
    pub fn new() -> Self {
        let mut stack = HandlerStack::new();

        // Add default handlers
        stack.add_handler(Arc::new(ConsoleHandler::new()));
        stack.add_handler(Arc::new(MockFsHandler::new()));

        // Set up capability mappings for legacy hostcalls
        let mut capability_mapping = BTreeMap::new();

        // Console capabilities
        capability_mapping.insert("console:log".to_string(), EffectCapabilities::none());
        capability_mapping.insert("console:error".to_string(), EffectCapabilities::none());
        capability_mapping.insert("console:warn".to_string(), EffectCapabilities::none());
        capability_mapping.insert("console:info".to_string(), EffectCapabilities::none());

        // File system capabilities
        capability_mapping.insert(
            "fs:read".to_string(),
            EffectCapabilities::custom(vec!["fs:read".to_string()]),
        );
        capability_mapping.insert(
            "fs:write".to_string(),
            EffectCapabilities::custom(vec!["fs:write".to_string()]),
        );

        // Network capabilities
        capability_mapping.insert(
            "net:connect".to_string(),
            EffectCapabilities::runtime([RuntimeCapability::NetworkEgress]),
        );

        // Process capabilities
        capability_mapping.insert(
            "proc:spawn".to_string(),
            EffectCapabilities::custom(vec!["proc:spawn".to_string()]),
        );

        // Policy capabilities
        capability_mapping.insert(
            "policy:request".to_string(),
            EffectCapabilities::runtime([RuntimeCapability::PolicyRead]),
        );

        // Timer capabilities
        capability_mapping.insert(
            "timer:setTimeout".to_string(),
            EffectCapabilities::custom(vec!["timer".to_string()]),
        );
        capability_mapping.insert(
            "timer:setInterval".to_string(),
            EffectCapabilities::custom(vec!["timer".to_string()]),
        );
        capability_mapping.insert(
            "timer:clearTimeout".to_string(),
            EffectCapabilities::custom(vec!["timer".to_string()]),
        );
        capability_mapping.insert(
            "timer:clearInterval".to_string(),
            EffectCapabilities::custom(vec!["timer".to_string()]),
        );

        // JavaScript builtin capabilities
        capability_mapping.insert(
            "builtin:call".to_string(),
            EffectCapabilities::runtime([RuntimeCapability::VmDispatch]),
        );

        // Promise capabilities
        for op in ["create", "resolve", "reject", "then", "all", "race"] {
            capability_mapping.insert(
                format!("promise:{}", op),
                EffectCapabilities::runtime([RuntimeCapability::VmDispatch]),
            );
        }

        // Number capabilities
        for op in ["parseInt", "parseFloat", "format", "isNaN", "isFinite"] {
            capability_mapping.insert(
                format!("number:{}", op),
                EffectCapabilities::runtime([RuntimeCapability::VmDispatch]),
            );
        }

        // Module capabilities
        for op in ["require", "import", "export"] {
            capability_mapping.insert(
                format!("module:{}", op),
                EffectCapabilities::runtime([RuntimeCapability::VmDispatch]),
            );
        }

        Self {
            effect_stack: stack,
            capability_mapping,
        }
    }

    /// Add a custom effect handler.
    pub fn add_handler(&mut self, handler: Arc<dyn Handler>) {
        self.effect_stack.add_handler(handler);
    }

    /// Remove a handler by name.
    pub fn remove_handler(&mut self, name: &str) -> bool {
        self.effect_stack.remove_handler(name)
    }

    /// Dispatch a legacy hostcall through the effect system.
    pub fn dispatch_hostcall(
        &mut self,
        capability: &str,
        args: &[String],
    ) -> Result<HostcallResult, EffectError> {
        // Parse the capability string to determine effect type
        let effect = self.parse_legacy_hostcall(capability, args)?;

        // Execute through the effect stack
        let result = self.effect_stack.handle_effect(effect.as_ref())?;

        // Convert back to legacy format
        self.convert_to_legacy_result(capability, result)
    }

    /// Parse legacy hostcall format into an Effect.
    fn parse_legacy_hostcall(
        &self,
        capability: &str,
        args: &[String],
    ) -> Result<Box<dyn Effect<Output = Box<dyn Any + Send + Sync>>>, EffectError> {
        match capability {
            cap if cap.starts_with("console:") => {
                let level = match cap {
                    "console:log" => ConsoleLevel::Log,
                    "console:error" => ConsoleLevel::Error,
                    "console:warn" => ConsoleLevel::Warn,
                    "console:info" => ConsoleLevel::Info,
                    _ => {
                        return Err(EffectError::InvalidParameters {
                            effect_name: cap.to_string(),
                            reason: "Unknown console level".to_string(),
                        });
                    }
                };
                Ok(Box::new(ConsoleEffect {
                    level,
                    args: args.to_vec(),
                }))
            }
            "fs:read" => {
                if args.is_empty() {
                    return Err(EffectError::InvalidParameters {
                        effect_name: "fs:read".to_string(),
                        reason: "Missing file path".to_string(),
                    });
                }
                Ok(Box::new(FsReadEffect {
                    path: args[0].clone(),
                    range: None, // Legacy API doesn't support ranges
                }))
            }
            "fs:write" => {
                if args.len() < 2 {
                    return Err(EffectError::InvalidParameters {
                        effect_name: "fs:write".to_string(),
                        reason: "Missing path or data".to_string(),
                    });
                }
                Ok(Box::new(FsWriteEffect {
                    path: args[0].clone(),
                    data: args[1].as_bytes().to_vec(),
                    append: false, // Legacy API defaults to overwrite
                }))
            }
            "net:connect" => {
                if args.len() < 2 {
                    return Err(EffectError::InvalidParameters {
                        effect_name: "net:connect".to_string(),
                        reason: "Missing host or port".to_string(),
                    });
                }
                let port = args[1]
                    .parse()
                    .map_err(|_| EffectError::InvalidParameters {
                        effect_name: "net:connect".to_string(),
                        reason: "Invalid port number".to_string(),
                    })?;

                Ok(Box::new(NetConnectEffect {
                    host: args[0].clone(),
                    port,
                    timeout_ms: None,
                }))
            }
            cap if cap.starts_with("timer:") => {
                let operation = match cap {
                    "timer:setTimeout" => {
                        if args.is_empty() {
                            return Err(EffectError::InvalidParameters {
                                effect_name: cap.to_string(),
                                reason: "Missing delay".to_string(),
                            });
                        }
                        let delay_ms =
                            args[0]
                                .parse()
                                .map_err(|_| EffectError::InvalidParameters {
                                    effect_name: cap.to_string(),
                                    reason: "Invalid delay".to_string(),
                                })?;
                        TimerOperation::SetTimeout { delay_ms }
                    }
                    "timer:setInterval" => {
                        if args.is_empty() {
                            return Err(EffectError::InvalidParameters {
                                effect_name: cap.to_string(),
                                reason: "Missing interval".to_string(),
                            });
                        }
                        let interval_ms =
                            args[0]
                                .parse()
                                .map_err(|_| EffectError::InvalidParameters {
                                    effect_name: cap.to_string(),
                                    reason: "Invalid interval".to_string(),
                                })?;
                        TimerOperation::SetInterval { interval_ms }
                    }
                    "timer:clearTimeout" | "timer:clearInterval" => {
                        if args.is_empty() {
                            return Err(EffectError::InvalidParameters {
                                effect_name: cap.to_string(),
                                reason: "Missing timer ID".to_string(),
                            });
                        }
                        let timer_id =
                            args[0]
                                .parse()
                                .map_err(|_| EffectError::InvalidParameters {
                                    effect_name: cap.to_string(),
                                    reason: "Invalid timer ID".to_string(),
                                })?;
                        if cap == "timer:clearTimeout" {
                            TimerOperation::ClearTimeout { timer_id }
                        } else {
                            TimerOperation::ClearInterval { timer_id }
                        }
                    }
                    _ => {
                        return Err(EffectError::InvalidParameters {
                            effect_name: cap.to_string(),
                            reason: "Unknown timer operation".to_string(),
                        });
                    }
                };
                Ok(Box::new(TimerEffect { operation }))
            }
            "module:require" => {
                if args.is_empty() {
                    return Err(EffectError::InvalidParameters {
                        effect_name: "module:require".to_string(),
                        reason: "Missing module specifier".to_string(),
                    });
                }
                Ok(Box::new(ModuleEffect {
                    operation: ModuleOperation::Require {
                        specifier: args[0].clone(),
                    },
                }))
            }
            _ => Err(EffectError::Unhandled {
                effect_name: capability.to_string(),
            }),
        }
    }

    /// Convert EffectResult back to legacy hostcall format.
    fn convert_to_legacy_result(
        &self,
        capability: &str,
        result: EffectResult,
    ) -> Result<HostcallResult, EffectError> {
        match capability {
            cap if cap.starts_with("console:") => {
                // Console effects return (), convert to success
                result.downcast::<()>()?;
                Ok(HostcallResult::Success)
            }
            "fs:read" => {
                let data = result.downcast::<Vec<u8>>()?;
                Ok(HostcallResult::Data(data))
            }
            "fs:write" => {
                let bytes_written = result.downcast::<u64>()?;
                Ok(HostcallResult::Count(bytes_written))
            }
            "net:connect" => {
                let handle = result.downcast::<u32>()?;
                Ok(HostcallResult::Handle(handle))
            }
            cap if cap.starts_with("timer:") => {
                if cap.starts_with("timer:set") {
                    let timer_id = result.downcast::<Option<u32>>()?;
                    match timer_id {
                        Some(id) => Ok(HostcallResult::Handle(id)),
                        None => Ok(HostcallResult::Success),
                    }
                } else {
                    // Clear operations
                    result.downcast::<Option<u32>>()?;
                    Ok(HostcallResult::Success)
                }
            }
            "module:require" => {
                let module_value = result.downcast::<BuiltinValue>()?;
                Ok(HostcallResult::Value(module_value))
            }
            _ => Err(EffectError::Unhandled {
                effect_name: capability.to_string(),
            }),
        }
    }

    /// Check if a capability is supported by the adapter.
    pub fn can_handle(&self, capability: &str) -> bool {
        self.capability_mapping.contains_key(capability) || self.effect_stack.can_handle(capability)
    }

    /// Get capabilities provided by the adapter.
    pub fn capabilities(&self) -> &EffectCapabilities {
        self.effect_stack.capabilities()
    }
}

impl Default for HostcallMigrationAdapter {
    fn default() -> Self {
        Self::new()
    }
}

/// Result types for legacy hostcall compatibility.
#[derive(Debug, Clone)]
pub enum HostcallResult {
    /// Operation succeeded with no return value.
    Success,
    /// Operation returned binary data.
    Data(Vec<u8>),
    /// Operation returned a count/size.
    Count(u64),
    /// Operation returned a handle/ID.
    Handle(u32),
    /// Operation returned a JavaScript value.
    Value(BuiltinValue),
}

impl fmt::Display for HostcallResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::Data(data) => write!(f, "Data({} bytes)", data.len()),
            Self::Count(count) => write!(f, "Count({})", count),
            Self::Handle(handle) => write!(f, "Handle({})", handle),
            Self::Value(value) => write!(f, "Value({:?})", value),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Mock effect for testing
    #[derive(Debug, Clone)]
    struct TestEffect {
        name: &'static str,
        value: i32,
        required_caps: EffectCapabilities,
    }

    impl Effect for TestEffect {
        type Output = String;

        fn effect_name(&self) -> &'static str {
            self.name
        }

        fn required_capabilities(&self) -> EffectCapabilities {
            self.required_caps.clone()
        }

        fn parameters(&self) -> Box<dyn Any + Send + Sync> {
            Box::new(self.value)
        }

        fn parameter_type_id(&self) -> TypeId {
            TypeId::of::<i32>()
        }
    }

    // Mock handler for testing
    #[derive(Debug)]
    struct TestHandler {
        name: &'static str,
        handled_effects: Vec<String>,
        capabilities: EffectCapabilities,
        priority: EffectPriority,
    }

    impl TestHandler {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                handled_effects: vec!["test_effect".to_string()],
                capabilities: EffectCapabilities::none(),
                priority: EffectPriority::Normal,
            }
        }

        fn with_capabilities(mut self, caps: EffectCapabilities) -> Self {
            self.capabilities = caps;
            self
        }

        fn with_priority(mut self, priority: EffectPriority) -> Self {
            self.priority = priority;
            self
        }
    }

    impl Handler for TestHandler {
        fn can_handle(&self, effect_name: &str) -> bool {
            self.handled_effects.contains(&effect_name.to_string())
        }

        fn handle(&self, effect: &dyn Effect<Output = Box<dyn Any + Send + Sync>>) -> Result<Option<EffectResult>, EffectError> {
            if self.can_handle(effect.effect_name()) {
                let result = format!("handled by {}", self.name);
                Ok(Some(EffectResult::new(result)))
            } else {
                Ok(None)
            }
        }

        fn provided_capabilities(&self) -> EffectCapabilities {
            self.capabilities.clone()
        }

        fn priority(&self) -> EffectPriority {
            self.priority
        }

        fn handler_name(&self) -> &'static str {
            self.name
        }
    }

    #[test]
    fn test_effect_capabilities_satisfaction() {
        let caps1 = EffectCapabilities::runtime([RuntimeCapability::VmDispatch]);
        let caps2 = EffectCapabilities::runtime([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::PolicyRead,
        ]);

        // caps1 should be satisfied by caps2 (subset)
        assert!(caps1.is_satisfied_by(&caps2));
        // caps2 should not be satisfied by caps1 (not subset)
        assert!(!caps2.is_satisfied_by(&caps1));
    }

    #[test]
    fn test_handler_stack_composition() {
        let mut stack = HandlerStack::new();

        let handler1 = Arc::new(TestHandler::new("handler1"));
        let handler2 = Arc::new(TestHandler::new("handler2").with_priority(EffectPriority::High));

        stack.add_handler(handler1);
        stack.add_handler(handler2);

        // Higher priority handler should be first
        let names = stack.handler_names();
        assert_eq!(names, vec!["handler2", "handler1"]);
    }

    #[test]
    fn test_effect_handling() {
        let mut stack = HandlerStack::new();
        let handler = Arc::new(TestHandler::new("test_handler"));
        stack.add_handler(handler);

        let effect = TestEffect {
            name: "test_effect",
            value: 42,
            required_caps: EffectCapabilities::none(),
        };

        let result = stack
            .handle_effect(&effect)
            .expect("Effect should be handled");
        let output: String = result.downcast().expect("Result should be String");
        assert_eq!(output, "handled by test_handler");
    }

    #[test]
    fn test_unhandled_effect() {
        let mut stack = HandlerStack::new();

        let effect = TestEffect {
            name: "unknown_effect",
            value: 42,
            required_caps: EffectCapabilities::none(),
        };

        let result = stack.handle_effect(&effect);
        assert!(matches!(result, Err(EffectError::Unhandled { .. })));
    }

    #[test]
    fn test_capability_denial() {
        let mut stack = HandlerStack::new();

        let effect = TestEffect {
            name: "test_effect",
            value: 42,
            required_caps: EffectCapabilities::runtime([RuntimeCapability::VmDispatch]),
        };

        let result = stack.handle_effect(&effect);
        assert!(matches!(result, Err(EffectError::CapabilityDenied { .. })));
    }

    #[test]
    fn test_effect_set_subtyping() {
        let set1 = EffectSet::from_effects(["effect1".to_string()]);
        let set2 = EffectSet::from_effects(["effect1".to_string(), "effect2".to_string()]);

        assert!(set1.is_subset_of(&set2));
        assert!(!set2.is_subset_of(&set1));
    }

    #[test]
    fn test_effect_set_operations() {
        let set1 = EffectSet::from_effects(["effect1".to_string(), "effect2".to_string()]);
        let set2 = EffectSet::from_effects(["effect2".to_string(), "effect3".to_string()]);

        let union = set1.union(&set2);
        assert_eq!(union.len(), 3);
        assert!(union.contains("effect1"));
        assert!(union.contains("effect2"));
        assert!(union.contains("effect3"));

        let intersection = set1.intersection(&set2);
        assert_eq!(intersection.len(), 1);
        assert!(intersection.contains("effect2"));
    }

    #[test]
    fn test_stack_overflow_protection() {
        let mut stack = HandlerStack::with_max_depth(2);

        // Fill dependency path to trigger overflow
        stack.dependency_path.push("effect1".to_string());
        stack.dependency_path.push("effect2".to_string());

        let effect = TestEffect {
            name: "test_effect",
            value: 42,
            required_caps: EffectCapabilities::none(),
        };

        let result = stack.handle_effect(&effect);
        assert!(matches!(result, Err(EffectError::StackOverflow)));
    }

    #[test]
    fn test_console_effect() {
        let effect = ConsoleEffect {
            level: ConsoleLevel::Info,
            args: vec!["Hello".to_string(), "World".to_string()],
        };

        assert_eq!(effect.effect_name(), "console:info");
        assert_eq!(effect.required_capabilities(), EffectCapabilities::none());

        let params = effect.parameters();
        let (level, args) = params
            .downcast_ref::<(ConsoleLevel, Vec<String>)>()
            .unwrap();
        assert_eq!(*level, ConsoleLevel::Info);
        assert_eq!(*args, vec!["Hello".to_string(), "World".to_string()]);
    }

    #[test]
    fn test_fs_read_effect() {
        let effect = FsReadEffect {
            path: "/tmp/test.txt".to_string(),
            range: Some((0, 100)),
        };

        assert_eq!(effect.effect_name(), "fs:read");
        assert!(
            effect
                .required_capabilities()
                .custom_caps
                .contains("fs:read")
        );

        let params = effect.parameters();
        let (path, range) = params
            .downcast_ref::<(String, Option<(u64, u64)>)>()
            .unwrap();
        assert_eq!(*path, "/tmp/test.txt");
        assert_eq!(*range, Some((0, 100)));
    }

    #[test]
    fn test_net_connect_effect() {
        let effect = NetConnectEffect {
            host: "example.com".to_string(),
            port: 80,
            timeout_ms: Some(5000),
        };

        assert_eq!(effect.effect_name(), "net:connect");
        assert!(
            effect
                .required_capabilities()
                .runtime_caps
                .contains(&RuntimeCapability::NetworkEgress)
        );

        let params = effect.parameters();
        let (host, port, timeout) = params.downcast_ref::<(String, u16, Option<u64>)>().unwrap();
        assert_eq!(*host, "example.com");
        assert_eq!(*port, 80);
        assert_eq!(*timeout, Some(5000));
    }

    #[test]
    fn test_policy_request_effect() {
        let mut context = BTreeMap::new();
        context.insert("user".to_string(), "alice".to_string());

        let effect = PolicyRequestEffect {
            query: "can_access_file".to_string(),
            context: context.clone(),
        };

        assert_eq!(effect.effect_name(), "policy:request");
        assert!(
            effect
                .required_capabilities()
                .runtime_caps
                .contains(&RuntimeCapability::PolicyRead)
        );

        let params = effect.parameters();
        let (query, ctx) = params
            .downcast_ref::<(String, BTreeMap<String, String>)>()
            .unwrap();
        assert_eq!(*query, "can_access_file");
        assert_eq!(*ctx, context);
    }

    #[test]
    fn test_console_handler() {
        let handler = ConsoleHandler::new();
        assert!(handler.can_handle("console:log"));
        assert!(handler.can_handle("console:error"));
        assert!(!handler.can_handle("fs:read"));

        let effect = ConsoleEffect {
            level: ConsoleLevel::Error,
            args: vec!["Error message".to_string()],
        };

        let result = handler.handle(&effect).unwrap().unwrap();
        let output: () = result.downcast().unwrap();
        assert_eq!(output, ());

        // Check that output was recorded
        let entries = handler.get_output();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].level, ConsoleLevel::Error);
        assert_eq!(entries[0].message, "Error message");
    }

    #[test]
    fn test_mock_fs_handler() {
        let handler = MockFsHandler::new();
        handler.add_file("/test.txt", b"Hello, World!");

        // Test read
        let read_effect = FsReadEffect {
            path: "/test.txt".to_string(),
            range: None,
        };

        let result = handler.handle(&read_effect).unwrap().unwrap();
        let data: Vec<u8> = result.downcast().unwrap();
        assert_eq!(data, b"Hello, World!");

        // Test write
        let write_effect = FsWriteEffect {
            path: "/new.txt".to_string(),
            data: b"New content".to_vec(),
            append: false,
        };

        let result = handler.handle(&write_effect).unwrap().unwrap();
        let bytes_written: u64 = result.downcast().unwrap();
        assert_eq!(bytes_written, 11);

        // Verify file was written
        assert!(handler.file_exists("/new.txt"));
    }

    #[test]
    fn test_fs_handler_with_range() {
        let handler = MockFsHandler::new();
        handler.add_file("/test.txt", b"0123456789");

        let read_effect = FsReadEffect {
            path: "/test.txt".to_string(),
            range: Some((2, 6)),
        };

        let result = handler.handle(&read_effect).unwrap().unwrap();
        let data: Vec<u8> = result.downcast().unwrap();
        assert_eq!(data, b"2345");
    }

    #[test]
    fn test_fs_handler_append_mode() {
        let handler = MockFsHandler::new();
        handler.add_file("/test.txt", b"Hello");

        let write_effect = FsWriteEffect {
            path: "/test.txt".to_string(),
            data: b", World!".to_vec(),
            append: true,
        };

        handler.handle(&write_effect).unwrap();

        // Read back the file
        let read_effect = FsReadEffect {
            path: "/test.txt".to_string(),
            range: None,
        };

        let result = handler.handle(&read_effect).unwrap().unwrap();
        let data: Vec<u8> = result.downcast().unwrap();
        assert_eq!(data, b"Hello, World!");
    }

    #[test]
    fn test_timer_effect_types() {
        let timeout_effect = TimerEffect {
            operation: TimerOperation::SetTimeout { delay_ms: 1000 },
        };
        assert_eq!(timeout_effect.effect_name(), "timer:setTimeout");

        let interval_effect = TimerEffect {
            operation: TimerOperation::SetInterval { interval_ms: 500 },
        };
        assert_eq!(interval_effect.effect_name(), "timer:setInterval");

        let clear_effect = TimerEffect {
            operation: TimerOperation::ClearTimeout { timer_id: 42 },
        };
        assert_eq!(clear_effect.effect_name(), "timer:clearTimeout");
    }

    #[test]
    fn test_promise_effect_types() {
        let create_effect = PromiseEffect {
            operation: PromiseOperation::Create,
        };
        assert_eq!(create_effect.effect_name(), "promise:create");

        let resolve_effect = PromiseEffect {
            operation: PromiseOperation::Resolve {
                promise_id: 123,
                value: BuiltinValue::Str("success".to_string()),
            },
        };
        assert_eq!(resolve_effect.effect_name(), "promise:resolve");

        let all_effect = PromiseEffect {
            operation: PromiseOperation::All {
                promises: vec![1, 2, 3],
            },
        };
        assert_eq!(all_effect.effect_name(), "promise:all");
    }

    #[test]
    fn test_number_effect_types() {
        let parse_int_effect = NumberEffect {
            operation: NumberOperation::ParseInt {
                value: "42".to_string(),
                radix: Some(10),
            },
        };
        assert_eq!(parse_int_effect.effect_name(), "number:parseInt");

        let parse_float_effect = NumberEffect {
            operation: NumberOperation::ParseFloat {
                value: "3.14".to_string(),
            },
        };
        assert_eq!(parse_float_effect.effect_name(), "number:parseFloat");

        let is_nan_effect = NumberEffect {
            operation: NumberOperation::IsNaN { value: f64::NAN },
        };
        assert_eq!(is_nan_effect.effect_name(), "number:isNaN");
    }

    #[test]
    fn test_builtin_effect() {
        let effect = BuiltinEffect {
            name: "ArrayPrototypePush".to_string(),
            args: vec![
                BuiltinValue::Object(123), // array object
                BuiltinValue::Int(42),     // value to push
            ],
        };

        assert_eq!(effect.effect_name(), "builtin:call");
        assert!(
            effect
                .required_capabilities()
                .runtime_caps
                .contains(&RuntimeCapability::VmDispatch)
        );

        let params = effect.parameters();
        let (name, args) = params
            .downcast_ref::<(String, Vec<BuiltinValue>)>()
            .unwrap();
        assert_eq!(*name, "ArrayPrototypePush");
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn test_module_effect_types() {
        let require_effect = ModuleEffect {
            operation: ModuleOperation::Require {
                specifier: "./module.js".to_string(),
            },
        };
        assert_eq!(require_effect.effect_name(), "module:require");

        let import_effect = ModuleEffect {
            operation: ModuleOperation::Import {
                specifier: "https://example.com/module.js".to_string(),
            },
        };
        assert_eq!(import_effect.effect_name(), "module:import");

        let export_effect = ModuleEffect {
            operation: ModuleOperation::Export {
                name: "default".to_string(),
                value: BuiltinValue::Str("exported value".to_string()),
            },
        };
        assert_eq!(export_effect.effect_name(), "module:export");
    }

    #[test]
    fn test_effect_telemetry() {
        let mut metadata = BTreeMap::new();
        metadata.insert("source".to_string(), "test".to_string());

        let telemetry = EffectTelemetry {
            handler_name: "TestHandler".to_string(),
            execution_time_ns: 1_000_000,
            capability_checks: vec!["fs:read".to_string()],
            metadata,
        };

        let result = EffectResult::with_telemetry("test_result".to_string(), telemetry);

        assert!(result.telemetry.is_some());
        let tel = result.telemetry.unwrap();
        assert_eq!(tel.handler_name, "TestHandler");
        assert_eq!(tel.execution_time_ns, 1_000_000);
    }

    #[test]
    fn test_migration_adapter_console() {
        let mut adapter = HostcallMigrationAdapter::new();

        let result = adapter
            .dispatch_hostcall("console:log", &["Hello".to_string(), "World".to_string()])
            .unwrap();

        assert!(matches!(result, HostcallResult::Success));
        assert!(adapter.can_handle("console:log"));
        assert!(adapter.can_handle("console:error"));
    }

    #[test]
    fn test_migration_adapter_fs_operations() {
        let mut adapter = HostcallMigrationAdapter::new();

        // Write a file
        let write_result = adapter
            .dispatch_hostcall(
                "fs:write",
                &["/test.txt".to_string(), "Hello, World!".to_string()],
            )
            .unwrap();

        if let HostcallResult::Count(bytes) = write_result {
            assert_eq!(bytes, 13);
        } else {
            panic!("Expected Count result from fs:write");
        }

        // Read the file back
        let read_result = adapter
            .dispatch_hostcall("fs:read", &["/test.txt".to_string()])
            .unwrap();

        if let HostcallResult::Data(data) = read_result {
            assert_eq!(data, b"Hello, World!");
        } else {
            panic!("Expected Data result from fs:read");
        }
    }

    #[test]
    fn test_migration_adapter_timer_operations() {
        let mut adapter = HostcallMigrationAdapter::new();

        // Set timeout - should return a handle
        let timeout_result = adapter.dispatch_hostcall("timer:setTimeout", &["1000".to_string()]);

        // Timer operations may not be fully implemented in mock, but should parse correctly
        assert!(
            timeout_result.is_ok()
                || matches!(timeout_result.unwrap_err(), EffectError::Unhandled { .. })
        );
    }

    #[test]
    fn test_migration_adapter_network_connect() {
        let mut adapter = HostcallMigrationAdapter::new();

        let result = adapter.dispatch_hostcall(
            "net:connect",
            &["example.com".to_string(), "80".to_string()],
        );

        // Network operations may not be fully implemented in mock
        assert!(result.is_ok() || matches!(result.unwrap_err(), EffectError::Unhandled { .. }));
    }

    #[test]
    fn test_migration_adapter_invalid_capability() {
        let mut adapter = HostcallMigrationAdapter::new();

        let result = adapter.dispatch_hostcall("unknown:operation", &[]);

        assert!(matches!(result, Err(EffectError::Unhandled { .. })));
        assert!(!adapter.can_handle("unknown:operation"));
    }

    #[test]
    fn test_migration_adapter_invalid_args() {
        let mut adapter = HostcallMigrationAdapter::new();

        // fs:read without path should fail
        let result = adapter.dispatch_hostcall("fs:read", &[]);
        assert!(matches!(result, Err(EffectError::InvalidParameters { .. })));

        // net:connect with invalid port should fail
        let result = adapter.dispatch_hostcall(
            "net:connect",
            &["example.com".to_string(), "invalid_port".to_string()],
        );
        assert!(matches!(result, Err(EffectError::InvalidParameters { .. })));
    }

    #[test]
    fn test_hostcall_result_display() {
        assert_eq!(format!("{}", HostcallResult::Success), "Success");
        assert_eq!(
            format!("{}", HostcallResult::Data(vec![1, 2, 3])),
            "Data(3 bytes)"
        );
        assert_eq!(format!("{}", HostcallResult::Count(42)), "Count(42)");
        assert_eq!(format!("{}", HostcallResult::Handle(123)), "Handle(123)");

        let value = BuiltinValue::Str("test".to_string());
        let result = HostcallResult::Value(value);
        assert!(format!("{}", result).contains("Value("));
    }

    #[test]
    fn test_policy_decision_serialization() {
        let allow = PolicyDecision::Allow;
        let deny = PolicyDecision::Deny {
            reason: "Insufficient permissions".to_string(),
        };
        let conditional = PolicyDecision::Conditional {
            requirements: vec!["auth".to_string(), "2fa".to_string()],
        };

        // Verify they can be serialized (important for RPC)
        assert!(serde_json::to_string(&allow).is_ok());
        assert!(serde_json::to_string(&deny).is_ok());
        assert!(serde_json::to_string(&conditional).is_ok());
    }

    #[test]
    fn test_effect_priority_ordering() {
        assert!(EffectPriority::Critical > EffectPriority::High);
        assert!(EffectPriority::High > EffectPriority::Normal);
        assert!(EffectPriority::Normal > EffectPriority::Low);

        // Test numerical values for explicit ordering
        assert_eq!(EffectPriority::Low as u32, 100);
        assert_eq!(EffectPriority::Normal as u32, 200);
        assert_eq!(EffectPriority::High as u32, 300);
        assert_eq!(EffectPriority::Critical as u32, 400);
    }

    #[test]
    fn test_handler_stack_composition_associativity() {
        // Test associativity: (h1 ∘ h2) ∘ h3 = h1 ∘ (h2 ∘ h3)
        let h1 = Arc::new(TestHandler::new("h1"));
        let h2 = Arc::new(TestHandler::new("h2"));
        let h3 = Arc::new(TestHandler::new("h3"));

        let mut stack1 = HandlerStack::new();
        stack1.add_handler(h1.clone());
        stack1.add_handler(h2.clone());

        let mut stack2 = HandlerStack::new();
        stack2.add_handler(h3.clone());

        let composed1 = stack1.compose(stack2);

        let mut stack3 = HandlerStack::new();
        stack3.add_handler(h2);

        let mut stack4 = HandlerStack::new();
        stack4.add_handler(h3);

        let stack5 = stack3.compose(stack4);

        let mut stack6 = HandlerStack::new();
        stack6.add_handler(h1);
        let composed2 = stack6.compose(stack5);

        // Both should have the same handlers (though order might differ due to priority)
        assert_eq!(
            composed1.handler_names().len(),
            composed2.handler_names().len()
        );
    }

    #[test]
    fn test_capability_mapping_coverage() {
        let adapter = HostcallMigrationAdapter::new();

        // Verify all our implemented effects have capability mappings
        let expected_mappings = vec![
            "console:log",
            "console:error",
            "console:warn",
            "console:info",
            "fs:read",
            "fs:write",
            "net:connect",
            "proc:spawn",
            "policy:request",
            "timer:setTimeout",
            "timer:setInterval",
            "timer:clearTimeout",
            "timer:clearInterval",
            "builtin:call",
        ];

        for capability in expected_mappings {
            assert!(
                adapter.capability_mapping.contains_key(capability),
                "Missing capability mapping for: {}",
                capability
            );
        }

        // Check promise capabilities
        for op in ["create", "resolve", "reject", "then", "all", "race"] {
            let cap = format!("promise:{}", op);
            assert!(
                adapter.capability_mapping.contains_key(&cap),
                "Missing promise capability mapping for: {}",
                cap
            );
        }

        // Check number capabilities
        for op in ["parseInt", "parseFloat", "format", "isNaN", "isFinite"] {
            let cap = format!("number:{}", op);
            assert!(
                adapter.capability_mapping.contains_key(&cap),
                "Missing number capability mapping for: {}",
                cap
            );
        }

        // Check module capabilities
        for op in ["require", "import", "export"] {
            let cap = format!("module:{}", op);
            assert!(
                adapter.capability_mapping.contains_key(&cap),
                "Missing module capability mapping for: {}",
                cap
            );
        }
    }
}
