//! Closure and lexical scope model.
//!
//! Runtime representation of ES2020 lexical scoping semantics:
//! - **Scope chains** with push/pop lifecycle matching block entry/exit.
//! - **Variable hoisting** (`var`, `function`) to the nearest function/global scope.
//! - **Block-scoped bindings** (`let`, `const`) with Temporal Dead Zone (TDZ) enforcement.
//! - **Closure capture** — snapshot of free-variable references at function-creation time.
//! - **IFC label propagation** — every binding and capture carries an IFC [`Label`].
//!
//! Builds on the static types in [`ir_contract`] (`ScopeId`, `ScopeKind`, `BindingKind`,
//! `ResolvedBinding`) and the IFC lattice in [`ifc_artifacts`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ifc_artifacts::Label;
use crate::ir_contract::{BindingId, BindingKind, ScopeId, ScopeKind};

// ---------------------------------------------------------------------------
// Runtime value type
// ---------------------------------------------------------------------------

/// Runtime value stored in a binding slot.
///
/// Uses the engine's fixed-point millionths convention for numbers
/// (`1_000_000` = 1.0) to guarantee deterministic serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvValue {
    /// JavaScript `undefined`.
    Undefined,
    /// JavaScript `null`.
    Null,
    /// Boolean.
    Bool(bool),
    /// Fixed-point millionths integer (`1_000_000` = 1.0).
    Number(i64),
    /// String value.
    Str(String),
    /// Opaque reference to an object (index into an external object heap).
    ObjectRef(u64),
    /// Opaque reference to a closure (index into the [`ClosureStore`]).
    ClosureRef(ClosureHandle),
    /// Temporal Dead Zone sentinel — accessing this is a ReferenceError.
    Tdz,
}

impl std::fmt::Display for EnvValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undefined => f.write_str("undefined"),
            Self::Null => f.write_str("null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Number(n) => write!(f, "{n}"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::ObjectRef(id) => write!(f, "ObjectRef({id})"),
            Self::ClosureRef(h) => write!(f, "ClosureRef({})", h.0),
            Self::Tdz => f.write_str("<TDZ>"),
        }
    }
}

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

/// Opaque handle to a closure in the [`ClosureStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ClosureHandle(pub u32);

/// Opaque handle to an environment record in the [`ScopeChain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EnvironmentHandle(pub u32);

// ---------------------------------------------------------------------------
// Binding slot
// ---------------------------------------------------------------------------

/// A single binding slot inside an environment record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingSlot {
    /// Human-readable name (for diagnostics).
    pub name: String,
    /// Unique binding id from scope resolution.
    pub binding_id: BindingId,
    /// `let` / `const` / `var` / etc.
    pub kind: BindingKind,
    /// Current value (or [`EnvValue::Tdz`] before initialization).
    pub value: EnvValue,
    /// Whether this binding has been initialized (past TDZ for `let`/`const`).
    pub initialized: bool,
    /// Whether assignment is permitted (`false` for `const` after init).
    pub mutable: bool,
    /// IFC security label attached to this binding's current value.
    pub label: Label,
}

impl BindingSlot {
    /// Create a new binding in the TDZ state for `let`/`const`.
    pub fn new_lexical(name: String, binding_id: BindingId, kind: BindingKind) -> Self {
        let mutable = kind != BindingKind::Const;
        Self {
            name,
            binding_id,
            kind,
            value: EnvValue::Tdz,
            initialized: false,
            mutable,
            label: Label::Public,
        }
    }

    /// Create a hoisted binding (var/function) — initialized to `undefined`.
    pub fn new_hoisted(name: String, binding_id: BindingId, kind: BindingKind) -> Self {
        Self {
            name,
            binding_id,
            kind,
            value: EnvValue::Undefined,
            initialized: true,
            mutable: true,
            label: Label::Public,
        }
    }

    /// Create a parameter binding — initialized to its argument value.
    pub fn new_parameter(
        name: String,
        binding_id: BindingId,
        value: EnvValue,
        label: Label,
    ) -> Self {
        Self {
            name,
            binding_id,
            kind: BindingKind::Parameter,
            value,
            initialized: true,
            mutable: true,
            label,
        }
    }
}

// ---------------------------------------------------------------------------
// Environment record
// ---------------------------------------------------------------------------

/// Classification of environment records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnvironmentKind {
    /// Declarative environment created by blocks, catch, for-of, etc.
    Declarative,
    /// Object environment (e.g. `with` statement — not recommended in strict mode).
    Object,
    /// Global environment.
    Global,
    /// Module environment.
    Module,
    /// Function environment.
    Function,
}

/// A runtime environment record — the binding storage for one scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRecord {
    /// Handle for back-references.
    pub handle: EnvironmentHandle,
    /// Static scope id this environment corresponds to.
    pub scope_id: ScopeId,
    /// Kind of scope.
    pub scope_kind: ScopeKind,
    /// Kind of environment record.
    pub env_kind: EnvironmentKind,
    /// Bindings stored in this environment, keyed by name.
    pub bindings: BTreeMap<String, BindingSlot>,
    /// Optional `this` binding for function environments.
    pub this_binding: Option<EnvValue>,
    /// Optional `arguments` object reference for function environments.
    pub arguments_handle: Option<u64>,
    /// Maximum IFC label of any binding in this environment.
    pub max_label: Label,
}

impl EnvironmentRecord {
    /// Create a new empty environment record.
    pub fn new(
        handle: EnvironmentHandle,
        scope_id: ScopeId,
        scope_kind: ScopeKind,
        env_kind: EnvironmentKind,
    ) -> Self {
        Self {
            handle,
            scope_id,
            scope_kind,
            env_kind,
            bindings: BTreeMap::new(),
            this_binding: None,
            arguments_handle: None,
            max_label: Label::Public,
        }
    }

    /// Insert a binding slot into this environment.
    pub fn add_binding(&mut self, slot: BindingSlot) {
        if slot.label > self.max_label {
            self.max_label = slot.label.clone();
        }
        self.bindings.insert(slot.name.clone(), slot);
    }

    /// Look up a binding by name in this environment only.
    pub fn get_binding(&self, name: &str) -> Option<&BindingSlot> {
        self.bindings.get(name)
    }

    /// Look up a binding by name mutably.
    pub fn get_binding_mut(&mut self, name: &str) -> Option<&mut BindingSlot> {
        self.bindings.get_mut(name)
    }

    /// Returns true when this environment acts as a hoisting target for `var`.
    pub fn is_var_scope(&self) -> bool {
        matches!(
            self.scope_kind,
            ScopeKind::Function | ScopeKind::Global | ScopeKind::Module
        )
    }
}

// ---------------------------------------------------------------------------
// Closure capture
// ---------------------------------------------------------------------------

/// A single captured variable reference inside a closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureCapture {
    /// Name of the captured binding.
    pub name: String,
    /// Binding id in the source scope.
    pub binding_id: BindingId,
    /// Scope where the binding lives.
    pub source_scope: ScopeId,
    /// IFC label at capture time.
    pub label: Label,
}

/// A closure — a function bundled with its captured environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Closure {
    /// Unique handle.
    pub handle: ClosureHandle,
    /// Human-readable function name (empty for anonymous).
    pub name: String,
    /// Parameter count.
    pub arity: u32,
    /// Whether this function is strict mode.
    pub strict: bool,
    /// Captured bindings from enclosing scopes.
    pub captures: Vec<ClosureCapture>,
    /// Maximum IFC label across all captures.
    pub max_capture_label: Label,
    /// Handle to the environment that was active when the closure was created.
    pub creation_env: EnvironmentHandle,
}

// ---------------------------------------------------------------------------
// Scope errors
// ---------------------------------------------------------------------------

/// Errors that can arise during scope chain operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeError {
    /// Attempted to read a `let`/`const` binding before initialization.
    TemporalDeadZone { name: String },
    /// Attempted to assign to a `const` binding after initialization.
    ConstAssignment { name: String },
    /// Binding not found in any enclosing scope.
    UndeclaredVariable { name: String },
    /// Scope chain is empty (no active scope).
    EmptyScopeChain,
    /// IFC label on the value exceeds the maximum permitted by the scope.
    LabelViolation {
        name: String,
        value_label: Label,
        scope_max: Label,
    },
    /// Duplicate binding in the same scope (for `let`/`const`).
    DuplicateBinding { name: String },
    /// Invalid environment handle.
    InvalidEnvironment { handle: EnvironmentHandle },
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TemporalDeadZone { name } => {
                write!(
                    f,
                    "ReferenceError: cannot access '{name}' before initialization"
                )
            }
            Self::ConstAssignment { name } => {
                write!(f, "TypeError: assignment to constant variable '{name}'")
            }
            Self::UndeclaredVariable { name } => {
                write!(f, "ReferenceError: '{name}' is not defined")
            }
            Self::EmptyScopeChain => f.write_str("InternalError: scope chain is empty"),
            Self::LabelViolation {
                name,
                value_label,
                scope_max,
            } => {
                write!(
                    f,
                    "IFCError: label {value_label:?} on '{name}' exceeds scope maximum {scope_max:?}"
                )
            }
            Self::DuplicateBinding { name } => {
                write!(
                    f,
                    "SyntaxError: identifier '{name}' has already been declared"
                )
            }
            Self::InvalidEnvironment { handle } => {
                write!(f, "InternalError: invalid environment handle {}", handle.0)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scope chain
// ---------------------------------------------------------------------------

/// The runtime scope chain — manages a stack of [`EnvironmentRecord`]s.
///
/// Supports:
/// - `push_scope` / `pop_scope` for block entry/exit.
/// - `var` hoisting to the nearest function/global scope.
/// - `let` / `const` lexical declarations with TDZ.
/// - Variable lookup walking the scope chain.
/// - Closure capture computation.
/// - IFC label checking on writes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeChain {
    /// All environment records, indexed by `EnvironmentHandle`.
    environments: Vec<EnvironmentRecord>,
    /// The active scope stack (handles, innermost last).
    chain: Vec<EnvironmentHandle>,
    /// Next handle id.
    next_handle: u32,
}

impl ScopeChain {
    /// Create a new scope chain with a single global environment.
    pub fn new() -> Self {
        let global_handle = EnvironmentHandle(0);
        let global_scope = ScopeId { depth: 0, index: 0 };
        let global_env = EnvironmentRecord::new(
            global_handle,
            global_scope,
            ScopeKind::Global,
            EnvironmentKind::Global,
        );
        Self {
            environments: vec![global_env],
            chain: vec![global_handle],
            next_handle: 1,
        }
    }

    /// Push a new scope onto the chain. Returns the handle.
    pub fn push_scope(&mut self, scope_id: ScopeId, scope_kind: ScopeKind) -> EnvironmentHandle {
        let env_kind = match scope_kind {
            ScopeKind::Global => EnvironmentKind::Global,
            ScopeKind::Module => EnvironmentKind::Module,
            ScopeKind::Function => EnvironmentKind::Function,
            ScopeKind::Block | ScopeKind::Catch => EnvironmentKind::Declarative,
        };
        let handle = EnvironmentHandle(self.next_handle);
        self.next_handle += 1;
        let env = EnvironmentRecord::new(handle, scope_id, scope_kind, env_kind);
        self.environments.push(env);
        self.chain.push(handle);
        handle
    }

    /// Pop the innermost scope. Returns the popped handle, or error if empty.
    pub fn pop_scope(&mut self) -> Result<EnvironmentHandle, ScopeError> {
        if self.chain.len() <= 1 {
            return Err(ScopeError::EmptyScopeChain);
        }
        Ok(self.chain.pop().expect("checked non-empty"))
    }

    /// Current (innermost) environment handle.
    pub fn current_handle(&self) -> Result<EnvironmentHandle, ScopeError> {
        self.chain
            .last()
            .copied()
            .ok_or(ScopeError::EmptyScopeChain)
    }

    /// Number of environments in the chain stack.
    pub fn depth(&self) -> usize {
        self.chain.len()
    }

    /// Get a reference to an environment by handle.
    pub fn get_env(&self, handle: EnvironmentHandle) -> Result<&EnvironmentRecord, ScopeError> {
        self.environments
            .get(handle.0 as usize)
            .ok_or(ScopeError::InvalidEnvironment { handle })
    }

    /// Get a mutable reference to an environment by handle.
    pub fn get_env_mut(
        &mut self,
        handle: EnvironmentHandle,
    ) -> Result<&mut EnvironmentRecord, ScopeError> {
        self.environments
            .get_mut(handle.0 as usize)
            .ok_or(ScopeError::InvalidEnvironment { handle })
    }

    // -----------------------------------------------------------------------
    // Binding declarations
    // -----------------------------------------------------------------------

    /// Declare a `var` — hoisted to the nearest function/global scope.
    pub fn declare_var(&mut self, name: String, binding_id: BindingId) -> Result<(), ScopeError> {
        // Walk outward to find the var-scope.
        let target_handle = self.find_var_scope()?;
        let env = self.get_env_mut(target_handle)?;
        // `var` re-declaration in the same scope is allowed (no-op if exists).
        if !env.bindings.contains_key(&name) {
            let slot = BindingSlot::new_hoisted(name, binding_id, BindingKind::Var);
            env.add_binding(slot);
        }
        Ok(())
    }

    /// Declare a `let` binding in the current scope (TDZ until initialized).
    pub fn declare_let(&mut self, name: String, binding_id: BindingId) -> Result<(), ScopeError> {
        let handle = self.current_handle()?;
        let env = self.get_env_mut(handle)?;
        if env.bindings.contains_key(&name) {
            return Err(ScopeError::DuplicateBinding { name });
        }
        let slot = BindingSlot::new_lexical(name, binding_id, BindingKind::Let);
        env.add_binding(slot);
        Ok(())
    }

    /// Declare a `const` binding in the current scope (TDZ until initialized).
    pub fn declare_const(&mut self, name: String, binding_id: BindingId) -> Result<(), ScopeError> {
        let handle = self.current_handle()?;
        let env = self.get_env_mut(handle)?;
        if env.bindings.contains_key(&name) {
            return Err(ScopeError::DuplicateBinding { name });
        }
        let slot = BindingSlot::new_lexical(name, binding_id, BindingKind::Const);
        env.add_binding(slot);
        Ok(())
    }

    /// Declare a function declaration — hoisted like `var`.
    pub fn declare_function(
        &mut self,
        name: String,
        binding_id: BindingId,
        value: EnvValue,
    ) -> Result<(), ScopeError> {
        let target_handle = self.find_var_scope()?;
        let env = self.get_env_mut(target_handle)?;
        // Function declarations overwrite previous var/function of the same name.
        let mut slot = BindingSlot::new_hoisted(name, binding_id, BindingKind::FunctionDecl);
        slot.value = value;
        env.add_binding(slot);
        Ok(())
    }

    /// Declare a parameter binding in the current (function) scope.
    pub fn declare_parameter(
        &mut self,
        name: String,
        binding_id: BindingId,
        value: EnvValue,
        label: Label,
    ) -> Result<(), ScopeError> {
        let handle = self.current_handle()?;
        let env = self.get_env_mut(handle)?;
        let slot = BindingSlot::new_parameter(name, binding_id, value, label);
        env.add_binding(slot);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Variable access
    // -----------------------------------------------------------------------

    /// Initialize a `let`/`const` binding (move it out of TDZ).
    pub fn initialize_binding(
        &mut self,
        name: &str,
        value: EnvValue,
        label: Label,
    ) -> Result<(), ScopeError> {
        let (handle, _) = self.resolve_binding(name)?;
        let env = self.get_env_mut(handle)?;
        let slot = env
            .get_binding_mut(name)
            .ok_or_else(|| ScopeError::UndeclaredVariable {
                name: name.to_string(),
            })?;
        slot.value = value;
        slot.initialized = true;
        slot.label = label.clone();
        if label > env.max_label {
            env.max_label = label;
        }
        Ok(())
    }

    /// Read a variable, walking the scope chain outward.
    pub fn get_value(&self, name: &str) -> Result<&EnvValue, ScopeError> {
        let (handle, _) = self.resolve_binding(name)?;
        let env = self.get_env(handle)?;
        let slot = env
            .get_binding(name)
            .ok_or_else(|| ScopeError::UndeclaredVariable {
                name: name.to_string(),
            })?;
        if !slot.initialized {
            return Err(ScopeError::TemporalDeadZone {
                name: name.to_string(),
            });
        }
        Ok(&slot.value)
    }

    /// Write to a variable, walking the scope chain outward.
    pub fn set_value(
        &mut self,
        name: &str,
        value: EnvValue,
        label: Label,
    ) -> Result<(), ScopeError> {
        let (handle, _) = self.resolve_binding(name)?;
        let env = self.get_env_mut(handle)?;
        let slot = env
            .get_binding_mut(name)
            .ok_or_else(|| ScopeError::UndeclaredVariable {
                name: name.to_string(),
            })?;
        if !slot.initialized {
            return Err(ScopeError::TemporalDeadZone {
                name: name.to_string(),
            });
        }
        if !slot.mutable {
            return Err(ScopeError::ConstAssignment {
                name: name.to_string(),
            });
        }
        slot.value = value;
        slot.label = label.clone();
        if label > env.max_label {
            env.max_label = label;
        }
        Ok(())
    }

    /// Resolve which environment contains a binding. Returns (handle, scope_id).
    pub fn resolve_binding(&self, name: &str) -> Result<(EnvironmentHandle, ScopeId), ScopeError> {
        for &handle in self.chain.iter().rev() {
            let env = self.get_env(handle)?;
            if env.bindings.contains_key(name) {
                return Ok((handle, env.scope_id));
            }
        }
        Err(ScopeError::UndeclaredVariable {
            name: name.to_string(),
        })
    }

    // -----------------------------------------------------------------------
    // Closure capture
    // -----------------------------------------------------------------------

    /// Compute the set of captures for a closure being created in the current scope.
    ///
    /// Given a list of free variable names used by the function body, returns
    /// [`ClosureCapture`] entries for each one that resolves to an enclosing scope.
    pub fn compute_captures(
        &self,
        free_vars: &[String],
    ) -> Result<Vec<ClosureCapture>, ScopeError> {
        let mut captures = Vec::new();
        for var_name in free_vars {
            let (handle, scope_id) = self.resolve_binding(var_name)?;
            let env = self.get_env(handle)?;
            let slot = env
                .get_binding(var_name)
                .ok_or_else(|| ScopeError::UndeclaredVariable {
                    name: var_name.clone(),
                })?;
            captures.push(ClosureCapture {
                name: var_name.clone(),
                binding_id: slot.binding_id,
                source_scope: scope_id,
                label: slot.label.clone(),
            });
        }
        Ok(captures)
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Walk outward from the current scope to find the nearest var-scope
    /// (function, global, or module).
    fn find_var_scope(&self) -> Result<EnvironmentHandle, ScopeError> {
        for &handle in self.chain.iter().rev() {
            let env = self.get_env(handle)?;
            if env.is_var_scope() {
                return Ok(handle);
            }
        }
        Err(ScopeError::EmptyScopeChain)
    }
}

impl Default for ScopeChain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Closure store
// ---------------------------------------------------------------------------

/// Arena for closures created during execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClosureStore {
    closures: Vec<Closure>,
}

impl ClosureStore {
    pub fn new() -> Self {
        Self {
            closures: Vec::new(),
        }
    }

    /// Create a closure and return its handle.
    pub fn create_closure(
        &mut self,
        name: String,
        arity: u32,
        strict: bool,
        captures: Vec<ClosureCapture>,
        creation_env: EnvironmentHandle,
    ) -> ClosureHandle {
        let handle = ClosureHandle(self.closures.len() as u32);
        let max_capture_label = captures
            .iter()
            .map(|c| &c.label)
            .max()
            .cloned()
            .unwrap_or(Label::Public);
        self.closures.push(Closure {
            handle,
            name,
            arity,
            strict,
            captures,
            max_capture_label,
            creation_env,
        });
        handle
    }

    /// Get a closure by handle.
    pub fn get(&self, handle: ClosureHandle) -> Option<&Closure> {
        self.closures.get(handle.0 as usize)
    }

    /// Number of closures in the store.
    pub fn len(&self) -> usize {
        self.closures.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.closures.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: a fresh scope chain (starts with global).
    fn fresh_chain() -> ScopeChain {
        ScopeChain::new()
    }

    // ----- scope push/pop -----

    #[test]
    fn global_scope_exists_after_new() {
        let chain = fresh_chain();
        assert_eq!(chain.depth(), 1);
        let handle = chain.current_handle().unwrap();
        let env = chain.get_env(handle).unwrap();
        assert_eq!(env.scope_kind, ScopeKind::Global);
    }

    #[test]
    fn push_and_pop_scope() {
        let mut chain = fresh_chain();
        let block_id = ScopeId { depth: 1, index: 0 };
        let h = chain.push_scope(block_id, ScopeKind::Block);
        assert_eq!(chain.depth(), 2);
        let popped = chain.pop_scope().unwrap();
        assert_eq!(popped, h);
        assert_eq!(chain.depth(), 1);
    }

    #[test]
    fn pop_global_scope_fails() {
        let mut chain = fresh_chain();
        let result = chain.pop_scope();
        assert!(matches!(result, Err(ScopeError::EmptyScopeChain)));
    }

    // ----- var hoisting -----

    #[test]
    fn var_hoisted_to_global() {
        let mut chain = fresh_chain();
        let block_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_var("x".into(), 1).unwrap();
        // Var should be in the global scope, not the block.
        let global_handle = EnvironmentHandle(0);
        let global_env = chain.get_env(global_handle).unwrap();
        assert!(global_env.get_binding("x").is_some());
        // Block should not have it.
        let block_handle = chain.current_handle().unwrap();
        let block_env = chain.get_env(block_handle).unwrap();
        assert!(block_env.get_binding("x").is_none());
    }

    #[test]
    fn var_hoisted_to_function_not_global() {
        let mut chain = fresh_chain();
        let fn_id = ScopeId { depth: 1, index: 0 };
        let fn_handle = chain.push_scope(fn_id, ScopeKind::Function);
        let block_id = ScopeId { depth: 2, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_var("y".into(), 2).unwrap();
        // Var should land in function scope, not global.
        let fn_env = chain.get_env(fn_handle).unwrap();
        assert!(fn_env.get_binding("y").is_some());
        let global_env = chain.get_env(EnvironmentHandle(0)).unwrap();
        assert!(global_env.get_binding("y").is_none());
    }

    #[test]
    fn var_redeclaration_is_noop() {
        let mut chain = fresh_chain();
        chain.declare_var("x".into(), 1).unwrap();
        chain.declare_var("x".into(), 2).unwrap(); // no error
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Undefined);
    }

    // ----- let/const TDZ -----

    #[test]
    fn let_starts_in_tdz() {
        let mut chain = fresh_chain();
        chain.declare_let("a".into(), 10).unwrap();
        let result = chain.get_value("a");
        assert!(matches!(result, Err(ScopeError::TemporalDeadZone { .. })));
    }

    #[test]
    fn let_accessible_after_init() {
        let mut chain = fresh_chain();
        chain.declare_let("a".into(), 10).unwrap();
        chain
            .initialize_binding("a", EnvValue::Number(42_000_000), Label::Public)
            .unwrap();
        let val = chain.get_value("a").unwrap();
        assert_eq!(*val, EnvValue::Number(42_000_000));
    }

    #[test]
    fn const_assignment_after_init_fails() {
        let mut chain = fresh_chain();
        chain.declare_const("PI".into(), 20).unwrap();
        chain
            .initialize_binding("PI", EnvValue::Number(3_141_593), Label::Public)
            .unwrap();
        let result = chain.set_value("PI", EnvValue::Number(0), Label::Public);
        assert!(matches!(result, Err(ScopeError::ConstAssignment { .. })));
    }

    #[test]
    fn const_value_preserved_after_failed_assignment() {
        let mut chain = fresh_chain();
        chain.declare_const("C".into(), 30).unwrap();
        chain
            .initialize_binding("C", EnvValue::Number(100), Label::Public)
            .unwrap();
        let _ = chain.set_value("C", EnvValue::Number(999), Label::Public);
        let val = chain.get_value("C").unwrap();
        assert_eq!(*val, EnvValue::Number(100));
    }

    #[test]
    fn let_reassignment_works() {
        let mut chain = fresh_chain();
        chain.declare_let("x".into(), 11).unwrap();
        chain
            .initialize_binding("x", EnvValue::Number(1), Label::Public)
            .unwrap();
        chain
            .set_value("x", EnvValue::Number(2), Label::Public)
            .unwrap();
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Number(2));
    }

    // ----- duplicate lexical declarations -----

    #[test]
    fn duplicate_let_in_same_scope_fails() {
        let mut chain = fresh_chain();
        chain.declare_let("x".into(), 1).unwrap();
        let result = chain.declare_let("x".into(), 2);
        assert!(matches!(result, Err(ScopeError::DuplicateBinding { .. })));
    }

    #[test]
    fn same_name_let_in_different_scopes_ok() {
        let mut chain = fresh_chain();
        chain.declare_let("x".into(), 1).unwrap();
        chain
            .initialize_binding("x", EnvValue::Number(10), Label::Public)
            .unwrap();

        let block_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_let("x".into(), 2).unwrap();
        chain
            .initialize_binding("x", EnvValue::Number(20), Label::Public)
            .unwrap();
        // Inner x shadows outer x.
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Number(20));

        chain.pop_scope().unwrap();
        // Outer x is visible again.
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Number(10));
    }

    // ----- variable shadowing -----

    #[test]
    fn block_scoped_let_shadows_var() {
        let mut chain = fresh_chain();
        chain.declare_var("x".into(), 1).unwrap();
        chain
            .set_value("x", EnvValue::Number(100), Label::Public)
            .unwrap();

        let block_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_let("x".into(), 2).unwrap();
        chain
            .initialize_binding("x", EnvValue::Number(200), Label::Public)
            .unwrap();
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Number(200));

        chain.pop_scope().unwrap();
        let val = chain.get_value("x").unwrap();
        assert_eq!(*val, EnvValue::Number(100));
    }

    // ----- undeclared variable -----

    #[test]
    fn undeclared_variable_error() {
        let chain = fresh_chain();
        let result = chain.get_value("nope");
        assert!(matches!(result, Err(ScopeError::UndeclaredVariable { .. })));
    }

    // ----- closure capture -----

    #[test]
    fn capture_from_enclosing_scope() {
        let mut chain = fresh_chain();
        chain.declare_let("outer".into(), 1).unwrap();
        chain
            .initialize_binding("outer", EnvValue::Number(42), Label::Public)
            .unwrap();

        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);

        let captures = chain.compute_captures(&["outer".into()]).unwrap();
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].name, "outer");
        assert_eq!(captures[0].source_scope, ScopeId { depth: 0, index: 0 });
    }

    #[test]
    fn closure_sees_mutations_through_captures() {
        let mut chain = fresh_chain();
        chain.declare_let("counter".into(), 1).unwrap();
        chain
            .initialize_binding("counter", EnvValue::Number(0), Label::Public)
            .unwrap();

        // Simulate closure creation — capture resolves to global env.
        let captures = chain.compute_captures(&["counter".into()]).unwrap();
        assert_eq!(captures[0].binding_id, 1);

        // Mutate from outer scope.
        chain
            .set_value("counter", EnvValue::Number(1), Label::Public)
            .unwrap();

        // Re-reading sees the updated value (closures share the binding).
        let val = chain.get_value("counter").unwrap();
        assert_eq!(*val, EnvValue::Number(1));
    }

    #[test]
    fn capture_undeclared_fails() {
        let chain = fresh_chain();
        let result = chain.compute_captures(&["missing".into()]);
        assert!(matches!(result, Err(ScopeError::UndeclaredVariable { .. })));
    }

    // ----- function declaration hoisting -----

    #[test]
    fn function_decl_hoisted_with_value() {
        let mut chain = fresh_chain();
        let closure_ref = EnvValue::ClosureRef(ClosureHandle(0));
        chain
            .declare_function("foo".into(), 50, closure_ref.clone())
            .unwrap();
        let val = chain.get_value("foo").unwrap();
        assert_eq!(*val, closure_ref);
    }

    #[test]
    fn function_decl_overwrites_var() {
        let mut chain = fresh_chain();
        chain.declare_var("f".into(), 1).unwrap();
        let val = chain.get_value("f").unwrap();
        assert_eq!(*val, EnvValue::Undefined);

        let closure_ref = EnvValue::ClosureRef(ClosureHandle(7));
        chain
            .declare_function("f".into(), 2, closure_ref.clone())
            .unwrap();
        let val = chain.get_value("f").unwrap();
        assert_eq!(*val, closure_ref);
    }

    // ----- parameter bindings -----

    #[test]
    fn parameter_binding_is_mutable() {
        let mut chain = fresh_chain();
        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        chain
            .declare_parameter("arg".into(), 100, EnvValue::Number(5), Label::Public)
            .unwrap();
        let val = chain.get_value("arg").unwrap();
        assert_eq!(*val, EnvValue::Number(5));
        chain
            .set_value("arg", EnvValue::Number(10), Label::Public)
            .unwrap();
        let val = chain.get_value("arg").unwrap();
        assert_eq!(*val, EnvValue::Number(10));
    }

    // ----- IFC label propagation -----

    #[test]
    fn ifc_label_propagates_on_init() {
        let mut chain = fresh_chain();
        chain.declare_let("secret".into(), 1).unwrap();
        chain
            .initialize_binding("secret", EnvValue::Str("key".into()), Label::Secret)
            .unwrap();
        let handle = chain.current_handle().unwrap();
        let env = chain.get_env(handle).unwrap();
        assert!(env.max_label >= Label::Secret);
        let slot = env.get_binding("secret").unwrap();
        assert_eq!(slot.label, Label::Secret);
    }

    #[test]
    fn ifc_label_propagates_on_set() {
        let mut chain = fresh_chain();
        chain.declare_var("data".into(), 1).unwrap();
        chain
            .set_value(
                "data",
                EnvValue::Str("classified".into()),
                Label::Confidential,
            )
            .unwrap();
        let global = chain.get_env(EnvironmentHandle(0)).unwrap();
        assert!(global.max_label >= Label::Confidential);
    }

    #[test]
    fn capture_carries_ifc_label() {
        let mut chain = fresh_chain();
        chain.declare_let("classified".into(), 1).unwrap();
        chain
            .initialize_binding(
                "classified",
                EnvValue::Str("data".into()),
                Label::Confidential,
            )
            .unwrap();

        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        let captures = chain.compute_captures(&["classified".into()]).unwrap();
        assert_eq!(captures[0].label, Label::Confidential);
    }

    // ----- nested closures -----

    #[test]
    fn nested_scope_chain_traversal() {
        let mut chain = fresh_chain();
        chain.declare_var("a".into(), 1).unwrap();
        chain
            .set_value("a", EnvValue::Number(1), Label::Public)
            .unwrap();

        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        chain.declare_let("b".into(), 2).unwrap();
        chain
            .initialize_binding("b", EnvValue::Number(2), Label::Public)
            .unwrap();

        let block_id = ScopeId { depth: 2, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_let("c".into(), 3).unwrap();
        chain
            .initialize_binding("c", EnvValue::Number(3), Label::Public)
            .unwrap();

        // All three variables visible from innermost scope.
        assert_eq!(*chain.get_value("a").unwrap(), EnvValue::Number(1));
        assert_eq!(*chain.get_value("b").unwrap(), EnvValue::Number(2));
        assert_eq!(*chain.get_value("c").unwrap(), EnvValue::Number(3));
    }

    #[test]
    fn nested_closure_captures_multiple_scopes() {
        let mut chain = fresh_chain();
        chain.declare_let("outer".into(), 1).unwrap();
        chain
            .initialize_binding("outer", EnvValue::Number(10), Label::Public)
            .unwrap();

        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        chain.declare_let("middle".into(), 2).unwrap();
        chain
            .initialize_binding("middle", EnvValue::Number(20), Label::Internal)
            .unwrap();

        let inner_fn_id = ScopeId { depth: 2, index: 0 };
        chain.push_scope(inner_fn_id, ScopeKind::Function);

        let captures = chain
            .compute_captures(&["outer".into(), "middle".into()])
            .unwrap();
        assert_eq!(captures.len(), 2);
        // outer comes from global scope.
        assert_eq!(captures[0].source_scope, ScopeId { depth: 0, index: 0 });
        assert_eq!(captures[0].label, Label::Public);
        // middle comes from enclosing function.
        assert_eq!(captures[1].source_scope, ScopeId { depth: 1, index: 0 });
        assert_eq!(captures[1].label, Label::Internal);
    }

    // ----- closure store -----

    #[test]
    fn closure_store_create_and_get() {
        let mut store = ClosureStore::new();
        assert!(store.is_empty());

        let captures = vec![ClosureCapture {
            name: "x".into(),
            binding_id: 1,
            source_scope: ScopeId { depth: 0, index: 0 },
            label: Label::Public,
        }];
        let h = store.create_closure("add".into(), 2, true, captures, EnvironmentHandle(0));
        assert_eq!(store.len(), 1);
        let closure = store.get(h).unwrap();
        assert_eq!(closure.name, "add");
        assert_eq!(closure.arity, 2);
        assert!(closure.strict);
        assert_eq!(closure.captures.len(), 1);
        assert_eq!(closure.max_capture_label, Label::Public);
    }

    #[test]
    fn closure_store_max_capture_label() {
        let mut store = ClosureStore::new();
        let captures = vec![
            ClosureCapture {
                name: "a".into(),
                binding_id: 1,
                source_scope: ScopeId { depth: 0, index: 0 },
                label: Label::Public,
            },
            ClosureCapture {
                name: "b".into(),
                binding_id: 2,
                source_scope: ScopeId { depth: 0, index: 0 },
                label: Label::Secret,
            },
        ];
        let h = store.create_closure("f".into(), 0, false, captures, EnvironmentHandle(0));
        let closure = store.get(h).unwrap();
        assert_eq!(closure.max_capture_label, Label::Secret);
    }

    // ----- serde round-trip -----

    #[test]
    fn env_value_serde_roundtrip() {
        let values = [
            EnvValue::Undefined,
            EnvValue::Null,
            EnvValue::Bool(true),
            EnvValue::Number(3_141_593),
            EnvValue::Str("hello".into()),
            EnvValue::ObjectRef(42),
            EnvValue::ClosureRef(ClosureHandle(7)),
            EnvValue::Tdz,
        ];
        for val in &values {
            let json = serde_json::to_string(val).unwrap();
            let back: EnvValue = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, val);
        }
    }

    #[test]
    fn binding_slot_serde_roundtrip() {
        let slot = BindingSlot::new_lexical("x".into(), 42, BindingKind::Let);
        let json = serde_json::to_string(&slot).unwrap();
        let back: BindingSlot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, slot);
    }

    #[test]
    fn closure_serde_roundtrip() {
        let closure = Closure {
            handle: ClosureHandle(0),
            name: "test".into(),
            arity: 1,
            strict: true,
            captures: vec![ClosureCapture {
                name: "x".into(),
                binding_id: 1,
                source_scope: ScopeId { depth: 0, index: 0 },
                label: Label::Internal,
            }],
            max_capture_label: Label::Internal,
            creation_env: EnvironmentHandle(0),
        };
        let json = serde_json::to_string(&closure).unwrap();
        let back: Closure = serde_json::from_str(&json).unwrap();
        assert_eq!(back, closure);
    }

    // ----- scope error display -----

    #[test]
    fn scope_error_messages() {
        let tdz = ScopeError::TemporalDeadZone { name: "x".into() };
        assert!(tdz.to_string().contains("before initialization"));

        let const_err = ScopeError::ConstAssignment { name: "PI".into() };
        assert!(const_err.to_string().contains("constant variable"));

        let undecl = ScopeError::UndeclaredVariable { name: "y".into() };
        assert!(undecl.to_string().contains("not defined"));

        let dup = ScopeError::DuplicateBinding { name: "z".into() };
        assert!(dup.to_string().contains("already been declared"));
    }

    // ----- environment record properties -----

    #[test]
    fn is_var_scope_classification() {
        let cases = [
            (ScopeKind::Global, true),
            (ScopeKind::Module, true),
            (ScopeKind::Function, true),
            (ScopeKind::Block, false),
            (ScopeKind::Catch, false),
        ];
        for (kind, expected) in cases {
            let env = EnvironmentRecord::new(
                EnvironmentHandle(0),
                ScopeId { depth: 0, index: 0 },
                kind,
                EnvironmentKind::Declarative,
            );
            assert_eq!(env.is_var_scope(), expected, "ScopeKind::{kind:?}");
        }
    }

    // ----- env_value display -----

    #[test]
    fn env_value_display_formats() {
        assert_eq!(EnvValue::Undefined.to_string(), "undefined");
        assert_eq!(EnvValue::Null.to_string(), "null");
        assert_eq!(EnvValue::Bool(false).to_string(), "false");
        assert_eq!(EnvValue::Number(1_000_000).to_string(), "1000000");
        assert_eq!(EnvValue::Str("hi".into()).to_string(), "\"hi\"");
        assert_eq!(EnvValue::Tdz.to_string(), "<TDZ>");
    }

    // ----- this binding on function scope -----

    #[test]
    fn function_env_this_binding() {
        let mut chain = fresh_chain();
        let fn_id = ScopeId { depth: 1, index: 0 };
        let fn_handle = chain.push_scope(fn_id, ScopeKind::Function);
        let env = chain.get_env_mut(fn_handle).unwrap();
        env.this_binding = Some(EnvValue::ObjectRef(99));
        let env = chain.get_env(fn_handle).unwrap();
        assert_eq!(env.this_binding, Some(EnvValue::ObjectRef(99)));
    }

    // ----- catch scope -----

    #[test]
    fn catch_scope_binds_error_variable() {
        let mut chain = fresh_chain();
        let catch_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(catch_id, ScopeKind::Catch);
        chain.declare_let("err".into(), 1).unwrap();
        chain
            .initialize_binding("err", EnvValue::Str("oops".into()), Label::Public)
            .unwrap();
        let val = chain.get_value("err").unwrap();
        assert_eq!(*val, EnvValue::Str("oops".into()));
        // Catch is not a var scope.
        chain.pop_scope().unwrap();
        let result = chain.get_value("err");
        assert!(result.is_err());
    }

    // ----- module scope -----

    #[test]
    fn module_scope_is_var_target() {
        let mut chain = fresh_chain();
        let mod_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(mod_id, ScopeKind::Module);
        let block_id = ScopeId { depth: 2, index: 0 };
        chain.push_scope(block_id, ScopeKind::Block);
        chain.declare_var("modVar".into(), 1).unwrap();
        // Should be in the module scope, not global.
        let mod_handle = EnvironmentHandle(1);
        let mod_env = chain.get_env(mod_handle).unwrap();
        assert!(mod_env.get_binding("modVar").is_some());
    }

    // ----- write to TDZ binding fails -----

    #[test]
    fn write_to_tdz_binding_fails() {
        let mut chain = fresh_chain();
        chain.declare_let("x".into(), 1).unwrap();
        let result = chain.set_value("x", EnvValue::Number(1), Label::Public);
        assert!(matches!(result, Err(ScopeError::TemporalDeadZone { .. })));
    }

    // ----- scope chain default impl -----

    #[test]
    fn scope_chain_default() {
        let chain = ScopeChain::default();
        assert_eq!(chain.depth(), 1);
    }

    // ----- resolve_binding returns correct scope -----

    #[test]
    fn resolve_binding_identifies_correct_scope() {
        let mut chain = fresh_chain();
        chain.declare_var("global_var".into(), 1).unwrap();

        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        chain.declare_let("fn_local".into(), 2).unwrap();
        chain
            .initialize_binding("fn_local", EnvValue::Number(1), Label::Public)
            .unwrap();

        let (_, scope) = chain.resolve_binding("global_var").unwrap();
        assert_eq!(scope, ScopeId { depth: 0, index: 0 });

        let (_, scope) = chain.resolve_binding("fn_local").unwrap();
        assert_eq!(scope, fn_id);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display uniqueness, edge cases, serde, defaults
    // -----------------------------------------------------------------------

    #[test]
    fn env_value_display_uniqueness_for_types() {
        let displays: std::collections::BTreeSet<String> = [
            EnvValue::Undefined,
            EnvValue::Null,
            EnvValue::Bool(true),
            EnvValue::Number(42),
            EnvValue::Str("x".into()),
            EnvValue::ObjectRef(1),
            EnvValue::ClosureRef(ClosureHandle(0)),
            EnvValue::Tdz,
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            8,
            "all 8 EnvValue variant types must produce unique Display"
        );
    }

    #[test]
    fn scope_error_serde_roundtrip_all_variants() {
        let variants: [ScopeError; 5] = [
            ScopeError::TemporalDeadZone { name: "x".into() },
            ScopeError::ConstAssignment { name: "PI".into() },
            ScopeError::UndeclaredVariable { name: "y".into() },
            ScopeError::DuplicateBinding { name: "z".into() },
            ScopeError::EmptyScopeChain,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ScopeError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn scope_error_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            ScopeError::TemporalDeadZone { name: "a".into() },
            ScopeError::ConstAssignment { name: "b".into() },
            ScopeError::UndeclaredVariable { name: "c".into() },
            ScopeError::DuplicateBinding { name: "d".into() },
            ScopeError::EmptyScopeChain,
        ]
        .iter()
        .map(|e| e.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            5,
            "all 5 ScopeError variants must have unique Display"
        );
    }

    #[test]
    fn scope_error_empty_scope_chain_display_non_empty() {
        let err = ScopeError::EmptyScopeChain;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn closure_store_empty_initially() {
        let store = ClosureStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.get(ClosureHandle(0)).is_none());
    }

    #[test]
    fn closure_store_multiple_closures() {
        let mut store = ClosureStore::new();
        let h1 = store.create_closure("f1".into(), 1, true, vec![], EnvironmentHandle(0));
        let h2 = store.create_closure("f2".into(), 2, false, vec![], EnvironmentHandle(0));
        assert_eq!(store.len(), 2);
        assert_ne!(h1, h2);
        assert_eq!(store.get(h1).unwrap().name, "f1");
        assert_eq!(store.get(h2).unwrap().name, "f2");
    }

    #[test]
    fn environment_record_serde_roundtrip() {
        let env = EnvironmentRecord::new(
            EnvironmentHandle(0),
            ScopeId { depth: 0, index: 0 },
            ScopeKind::Global,
            EnvironmentKind::Declarative,
        );
        let json = serde_json::to_string(&env).unwrap();
        let back: EnvironmentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(env.scope_kind, back.scope_kind);
        assert_eq!(env.env_kind, back.env_kind);
    }

    #[test]
    fn pop_global_scope_fails_underflow() {
        let mut chain = fresh_chain();
        let result = chain.pop_scope();
        assert!(matches!(result, Err(ScopeError::EmptyScopeChain)));
    }

    #[test]
    fn closure_handle_serde_roundtrip() {
        let h = ClosureHandle(42);
        let json = serde_json::to_string(&h).unwrap();
        let back: ClosureHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone equality, JSON field presence, boundary,
    // ord determinism
    // -----------------------------------------------------------------------

    // --- Clone equality (5 tests) ---

    #[test]
    fn enrichment_clone_eq_closure_handle() {
        let a = ClosureHandle(99);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_environment_handle() {
        let a = EnvironmentHandle(255);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_binding_slot() {
        let a = BindingSlot::new_lexical("alpha".into(), 7, BindingKind::Let);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_closure_capture() {
        let a = ClosureCapture {
            name: "captured".into(),
            binding_id: 42,
            source_scope: ScopeId { depth: 3, index: 1 },
            label: Label::Confidential,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_closure() {
        let a = Closure {
            handle: ClosureHandle(5),
            name: "myClosure".into(),
            arity: 3,
            strict: true,
            captures: vec![ClosureCapture {
                name: "v".into(),
                binding_id: 10,
                source_scope: ScopeId { depth: 1, index: 0 },
                label: Label::Secret,
            }],
            max_capture_label: Label::Secret,
            creation_env: EnvironmentHandle(2),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // --- JSON field presence (3 tests) ---

    #[test]
    fn enrichment_json_field_presence_binding_slot() {
        let slot = BindingSlot::new_parameter(
            "param1".into(),
            99,
            EnvValue::Number(500_000),
            Label::Internal,
        );
        let json = serde_json::to_string(&slot).unwrap();
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"binding_id\""));
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"value\""));
        assert!(json.contains("\"initialized\""));
        assert!(json.contains("\"mutable\""));
        assert!(json.contains("\"label\""));
    }

    #[test]
    fn enrichment_json_field_presence_environment_record() {
        let mut env = EnvironmentRecord::new(
            EnvironmentHandle(3),
            ScopeId { depth: 2, index: 1 },
            ScopeKind::Function,
            EnvironmentKind::Function,
        );
        env.this_binding = Some(EnvValue::ObjectRef(77));
        env.arguments_handle = Some(88);
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("\"handle\""));
        assert!(json.contains("\"scope_id\""));
        assert!(json.contains("\"scope_kind\""));
        assert!(json.contains("\"env_kind\""));
        assert!(json.contains("\"bindings\""));
        assert!(json.contains("\"this_binding\""));
        assert!(json.contains("\"arguments_handle\""));
        assert!(json.contains("\"max_label\""));
    }

    #[test]
    fn enrichment_json_field_presence_closure() {
        let c = Closure {
            handle: ClosureHandle(0),
            name: "fn_name".into(),
            arity: 2,
            strict: false,
            captures: vec![],
            max_capture_label: Label::Public,
            creation_env: EnvironmentHandle(1),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"handle\""));
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"arity\""));
        assert!(json.contains("\"strict\""));
        assert!(json.contains("\"captures\""));
        assert!(json.contains("\"max_capture_label\""));
        assert!(json.contains("\"creation_env\""));
    }

    // --- Serde roundtrip (1 test) ---

    #[test]
    fn enrichment_scope_chain_serde_roundtrip() {
        let mut chain = fresh_chain();
        chain.declare_var("g".into(), 1).unwrap();
        chain
            .set_value("g", EnvValue::Number(1_000_000), Label::Public)
            .unwrap();
        let fn_id = ScopeId { depth: 1, index: 0 };
        chain.push_scope(fn_id, ScopeKind::Function);
        chain.declare_let("local".into(), 2).unwrap();
        chain
            .initialize_binding("local", EnvValue::Str("hello".into()), Label::Internal)
            .unwrap();
        let json = serde_json::to_string(&chain).unwrap();
        let back: ScopeChain = serde_json::from_str(&json).unwrap();
        assert_eq!(back.depth(), chain.depth());
        // Verify bindings survived the round-trip.
        let val = back.get_value("g").unwrap();
        assert_eq!(*val, EnvValue::Number(1_000_000));
        let val = back.get_value("local").unwrap();
        assert_eq!(*val, EnvValue::Str("hello".into()));
    }

    // --- Display uniqueness (1 test) ---

    #[test]
    fn enrichment_env_value_display_all_distinct_with_varied_data() {
        // Use different data from the existing test to confirm Display
        // is sensitive to the carried payload, not just the variant tag.
        let displays: std::collections::BTreeSet<String> = [
            EnvValue::Undefined,
            EnvValue::Null,
            EnvValue::Bool(false),
            EnvValue::Number(0),
            EnvValue::Str("".into()),
            EnvValue::ObjectRef(0),
            EnvValue::ClosureRef(ClosureHandle(0)),
            EnvValue::Tdz,
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            8,
            "all 8 variants must have unique Display even with zero/empty payloads"
        );
    }

    // --- Boundary condition (1 test) ---

    #[test]
    fn enrichment_boundary_zero_arity_empty_captures_max_handle() {
        let mut store = ClosureStore::new();
        let h = store.create_closure(
            String::new(),               // anonymous (empty name)
            0,                           // zero arity
            false,                       // non-strict
            vec![],                      // no captures
            EnvironmentHandle(u32::MAX), // max handle value
        );
        let c = store.get(h).unwrap();
        assert_eq!(c.name, "");
        assert_eq!(c.arity, 0);
        assert!(!c.strict);
        assert!(c.captures.is_empty());
        assert_eq!(c.max_capture_label, Label::Public); // default for empty captures
        assert_eq!(c.creation_env, EnvironmentHandle(u32::MAX));
    }

    // --- Ord determinism (1 test) ---

    #[test]
    fn enrichment_closure_handle_ord_determinism() {
        let handles = [
            ClosureHandle(5),
            ClosureHandle(2),
            ClosureHandle(9),
            ClosureHandle(0),
            ClosureHandle(7),
        ];
        let mut sorted_a = handles;
        sorted_a.sort();
        let mut sorted_b = handles;
        sorted_b.sort();
        assert_eq!(sorted_a, sorted_b, "Ord must be deterministic across sorts");
        // Verify the actual ordering is by inner u32.
        assert_eq!(sorted_a[0], ClosureHandle(0));
        assert_eq!(sorted_a[4], ClosureHandle(9));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: JSON field-name stability, serde variant
    // distinctness, Debug distinctness, Copy semantics, Hash consistency,
    // boundary/edge cases, Clone independence, Display format checks
    // -----------------------------------------------------------------------

    // --- JSON field-name stability (5 tests) ---

    #[test]
    fn json_field_names_closure_capture() {
        let cap = ClosureCapture {
            name: "x".into(),
            binding_id: 1,
            source_scope: ScopeId { depth: 0, index: 0 },
            label: Label::Public,
        };
        let json = serde_json::to_string(&cap).unwrap();
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"binding_id\""));
        assert!(json.contains("\"source_scope\""));
        assert!(json.contains("\"label\""));
    }

    #[test]
    fn json_field_names_scope_chain() {
        let chain = fresh_chain();
        let json = serde_json::to_string(&chain).unwrap();
        assert!(json.contains("\"environments\""));
        assert!(json.contains("\"chain\""));
        assert!(json.contains("\"next_handle\""));
    }

    #[test]
    fn json_field_names_closure_store() {
        let store = ClosureStore::new();
        let json = serde_json::to_string(&store).unwrap();
        assert!(json.contains("\"closures\""));
    }

    #[test]
    fn json_field_names_scope_error_tdz() {
        let err = ScopeError::TemporalDeadZone { name: "abc".into() };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"TemporalDeadZone\""));
        assert!(json.contains("\"name\""));
    }

    #[test]
    fn json_field_names_scope_error_label_violation() {
        let err = ScopeError::LabelViolation {
            name: "x".into(),
            value_label: Label::Secret,
            scope_max: Label::Public,
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("\"LabelViolation\""));
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"value_label\""));
        assert!(json.contains("\"scope_max\""));
    }

    // --- Serde variant distinctness (3 tests) ---

    #[test]
    fn serde_env_value_variants_distinct_json() {
        let variants = [
            EnvValue::Undefined,
            EnvValue::Null,
            EnvValue::Bool(true),
            EnvValue::Number(1),
            EnvValue::Str("s".into()),
            EnvValue::ObjectRef(1),
            EnvValue::ClosureRef(ClosureHandle(1)),
            EnvValue::Tdz,
        ];
        let jsons: std::collections::BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(
            jsons.len(),
            8,
            "all 8 EnvValue variants must serialize to distinct JSON"
        );
    }

    #[test]
    fn serde_environment_kind_variants_distinct_json() {
        let variants = [
            EnvironmentKind::Declarative,
            EnvironmentKind::Object,
            EnvironmentKind::Global,
            EnvironmentKind::Module,
            EnvironmentKind::Function,
        ];
        let jsons: std::collections::BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(
            jsons.len(),
            5,
            "all 5 EnvironmentKind variants must produce distinct JSON"
        );
    }

    #[test]
    fn serde_scope_error_variants_distinct_json() {
        let variants = [
            ScopeError::TemporalDeadZone { name: "a".into() },
            ScopeError::ConstAssignment { name: "a".into() },
            ScopeError::UndeclaredVariable { name: "a".into() },
            ScopeError::EmptyScopeChain,
            ScopeError::LabelViolation {
                name: "a".into(),
                value_label: Label::Public,
                scope_max: Label::Public,
            },
            ScopeError::DuplicateBinding { name: "a".into() },
            ScopeError::InvalidEnvironment {
                handle: EnvironmentHandle(0),
            },
        ];
        let jsons: std::collections::BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(
            jsons.len(),
            7,
            "all 7 ScopeError variants must produce distinct JSON"
        );
    }

    // --- Debug distinctness (3 tests) ---

    #[test]
    fn debug_env_value_variants_distinct() {
        let variants: [EnvValue; 8] = [
            EnvValue::Undefined,
            EnvValue::Null,
            EnvValue::Bool(false),
            EnvValue::Number(0),
            EnvValue::Str(String::new()),
            EnvValue::ObjectRef(0),
            EnvValue::ClosureRef(ClosureHandle(0)),
            EnvValue::Tdz,
        ];
        let debugs: std::collections::BTreeSet<String> =
            variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(
            debugs.len(),
            8,
            "all 8 EnvValue variants must have distinct Debug"
        );
    }

    #[test]
    fn debug_environment_kind_variants_distinct() {
        let variants = [
            EnvironmentKind::Declarative,
            EnvironmentKind::Object,
            EnvironmentKind::Global,
            EnvironmentKind::Module,
            EnvironmentKind::Function,
        ];
        let debugs: std::collections::BTreeSet<String> =
            variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(
            debugs.len(),
            5,
            "all 5 EnvironmentKind variants must have distinct Debug"
        );
    }

    #[test]
    fn debug_scope_error_variants_distinct() {
        let variants = [
            ScopeError::TemporalDeadZone { name: "n".into() },
            ScopeError::ConstAssignment { name: "n".into() },
            ScopeError::UndeclaredVariable { name: "n".into() },
            ScopeError::EmptyScopeChain,
            ScopeError::LabelViolation {
                name: "n".into(),
                value_label: Label::Public,
                scope_max: Label::Public,
            },
            ScopeError::DuplicateBinding { name: "n".into() },
            ScopeError::InvalidEnvironment {
                handle: EnvironmentHandle(0),
            },
        ];
        let debugs: std::collections::BTreeSet<String> =
            variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(
            debugs.len(),
            7,
            "all 7 ScopeError variants must have distinct Debug"
        );
    }

    // --- Copy semantics (2 tests) ---

    #[test]
    fn copy_semantics_closure_handle() {
        let a = ClosureHandle(42);
        let b = a; // Copy
        let c = a; // still valid — Copy
        assert_eq!(b, c);
        assert_eq!(a, b);
    }

    #[test]
    fn copy_semantics_environment_handle() {
        let a = EnvironmentHandle(99);
        let b = a; // Copy
        let c = a; // still valid
        assert_eq!(b, c);
        assert_eq!(a, b);
    }

    // --- Hash consistency (2 tests) ---

    #[test]
    fn hash_consistency_closure_handle() {
        use std::hash::{Hash, Hasher};
        let h1 = ClosureHandle(17);
        let h2 = ClosureHandle(17);
        let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
        let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
        h1.hash(&mut hasher1);
        h2.hash(&mut hasher2);
        assert_eq!(
            hasher1.finish(),
            hasher2.finish(),
            "equal ClosureHandles must hash equally"
        );
    }

    #[test]
    fn hash_consistency_environment_handle() {
        use std::hash::{Hash, Hasher};
        let h1 = EnvironmentHandle(255);
        let h2 = EnvironmentHandle(255);
        let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
        let mut hasher2 = std::collections::hash_map::DefaultHasher::new();
        h1.hash(&mut hasher1);
        h2.hash(&mut hasher2);
        assert_eq!(
            hasher1.finish(),
            hasher2.finish(),
            "equal EnvironmentHandles must hash equally"
        );
    }

    // --- Clone independence (3 tests) ---

    #[test]
    fn clone_independence_binding_slot_mutation() {
        let a = BindingSlot::new_hoisted("x".into(), 1, BindingKind::Var);
        let mut b = a.clone();
        b.value = EnvValue::Number(999);
        b.label = Label::Secret;
        // a is unchanged
        assert_eq!(a.value, EnvValue::Undefined);
        assert_eq!(a.label, Label::Public);
        assert_ne!(a.value, b.value);
    }

    #[test]
    fn clone_independence_closure() {
        let a = Closure {
            handle: ClosureHandle(0),
            name: "orig".into(),
            arity: 1,
            strict: false,
            captures: vec![ClosureCapture {
                name: "c".into(),
                binding_id: 1,
                source_scope: ScopeId { depth: 0, index: 0 },
                label: Label::Public,
            }],
            max_capture_label: Label::Public,
            creation_env: EnvironmentHandle(0),
        };
        let mut b = a.clone();
        b.name = "modified".into();
        b.captures.clear();
        assert_eq!(a.name, "orig");
        assert_eq!(a.captures.len(), 1);
    }

    #[test]
    fn clone_independence_scope_chain() {
        let mut a = fresh_chain();
        a.declare_var("v".into(), 1).unwrap();
        let mut b = a.clone();
        b.declare_let("extra".into(), 2).unwrap();
        // a should not have the new binding
        assert!(a.get_value("extra").is_err());
        assert!(b.get_value("v").is_ok());
    }

    // --- Display format checks (5 tests) ---

    #[test]
    fn display_env_value_objectref_format() {
        let v = EnvValue::ObjectRef(12345);
        assert_eq!(v.to_string(), "ObjectRef(12345)");
    }

    #[test]
    fn display_env_value_closureref_format() {
        let v = EnvValue::ClosureRef(ClosureHandle(7));
        assert_eq!(v.to_string(), "ClosureRef(7)");
    }

    #[test]
    fn display_scope_error_invalid_environment() {
        let err = ScopeError::InvalidEnvironment {
            handle: EnvironmentHandle(42),
        };
        let s = err.to_string();
        assert!(s.contains("42"), "Display should include handle value");
        assert!(s.contains("invalid environment handle"));
    }

    #[test]
    fn display_scope_error_label_violation_format() {
        let err = ScopeError::LabelViolation {
            name: "secret_data".into(),
            value_label: Label::TopSecret,
            scope_max: Label::Internal,
        };
        let s = err.to_string();
        assert!(s.contains("secret_data"));
        assert!(s.contains("TopSecret"));
        assert!(s.contains("Internal"));
    }

    #[test]
    fn display_env_value_str_with_quotes() {
        let v = EnvValue::Str("hello world".into());
        assert_eq!(v.to_string(), "\"hello world\"");
    }

    // --- Serde roundtrip additional (4 tests) ---

    #[test]
    fn serde_roundtrip_environment_kind_all_variants() {
        let variants = [
            EnvironmentKind::Declarative,
            EnvironmentKind::Object,
            EnvironmentKind::Global,
            EnvironmentKind::Module,
            EnvironmentKind::Function,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: EnvironmentKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn serde_roundtrip_closure_capture() {
        let cap = ClosureCapture {
            name: "deep_var".into(),
            binding_id: 777,
            source_scope: ScopeId { depth: 5, index: 3 },
            label: Label::TopSecret,
        };
        let json = serde_json::to_string(&cap).unwrap();
        let back: ClosureCapture = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, back);
    }

    #[test]
    fn serde_roundtrip_closure_store() {
        let mut store = ClosureStore::new();
        store.create_closure("f".into(), 2, true, vec![], EnvironmentHandle(0));
        store.create_closure(
            "g".into(),
            1,
            false,
            vec![ClosureCapture {
                name: "z".into(),
                binding_id: 99,
                source_scope: ScopeId { depth: 1, index: 0 },
                label: Label::Confidential,
            }],
            EnvironmentHandle(3),
        );
        let json = serde_json::to_string(&store).unwrap();
        let back: ClosureStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.get(ClosureHandle(0)).unwrap().name, "f");
        assert_eq!(back.get(ClosureHandle(1)).unwrap().name, "g");
        assert_eq!(
            back.get(ClosureHandle(1)).unwrap().max_capture_label,
            Label::Confidential
        );
    }

    #[test]
    fn serde_roundtrip_scope_error_label_violation() {
        let err = ScopeError::LabelViolation {
            name: "x".into(),
            value_label: Label::TopSecret,
            scope_max: Label::Internal,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: ScopeError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // --- Boundary/edge cases (8 tests) ---

    #[test]
    fn boundary_binding_slot_empty_name() {
        let slot = BindingSlot::new_lexical(String::new(), 0, BindingKind::Let);
        assert_eq!(slot.name, "");
        assert_eq!(slot.value, EnvValue::Tdz);
        assert!(!slot.initialized);
    }

    #[test]
    fn boundary_env_value_number_extremes() {
        let min_val = EnvValue::Number(i64::MIN);
        let max_val = EnvValue::Number(i64::MAX);
        let json_min = serde_json::to_string(&min_val).unwrap();
        let json_max = serde_json::to_string(&max_val).unwrap();
        let back_min: EnvValue = serde_json::from_str(&json_min).unwrap();
        let back_max: EnvValue = serde_json::from_str(&json_max).unwrap();
        assert_eq!(back_min, min_val);
        assert_eq!(back_max, max_val);
    }

    #[test]
    fn boundary_env_value_objectref_zero_and_max() {
        let zero = EnvValue::ObjectRef(0);
        let max = EnvValue::ObjectRef(u64::MAX);
        let j0 = serde_json::to_string(&zero).unwrap();
        let jm = serde_json::to_string(&max).unwrap();
        let b0: EnvValue = serde_json::from_str(&j0).unwrap();
        let bm: EnvValue = serde_json::from_str(&jm).unwrap();
        assert_eq!(b0, zero);
        assert_eq!(bm, max);
    }

    #[test]
    fn boundary_closure_handle_zero() {
        let h = ClosureHandle(0);
        assert_eq!(h.0, 0);
        let json = serde_json::to_string(&h).unwrap();
        let back: ClosureHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn boundary_closure_handle_max() {
        let h = ClosureHandle(u32::MAX);
        assert_eq!(h.0, u32::MAX);
        let json = serde_json::to_string(&h).unwrap();
        let back: ClosureHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn boundary_deep_scope_nesting() {
        let mut chain = fresh_chain();
        // Push 50 nested block scopes
        for i in 0..50u32 {
            chain.push_scope(
                ScopeId {
                    depth: i + 1,
                    index: 0,
                },
                ScopeKind::Block,
            );
        }
        assert_eq!(chain.depth(), 51); // 1 global + 50 blocks
        // Declare var in deepest — should hoist to global
        chain.declare_var("deep".into(), 1).unwrap();
        let global = chain.get_env(EnvironmentHandle(0)).unwrap();
        assert!(global.get_binding("deep").is_some());
        // Pop all
        for _ in 0..50 {
            chain.pop_scope().unwrap();
        }
        assert_eq!(chain.depth(), 1);
    }

    #[test]
    fn boundary_many_bindings_in_single_scope() {
        let mut chain = fresh_chain();
        for i in 0..100u32 {
            let name = format!("v{i}");
            chain.declare_var(name, i).unwrap();
        }
        let global = chain.get_env(EnvironmentHandle(0)).unwrap();
        assert_eq!(global.bindings.len(), 100);
        // BTreeMap keeps them sorted
        let first_key = global.bindings.keys().next().unwrap();
        assert_eq!(first_key, "v0");
    }

    #[test]
    fn boundary_scope_id_zero_zero() {
        let sid = ScopeId { depth: 0, index: 0 };
        let json = serde_json::to_string(&sid).unwrap();
        let back: ScopeId = serde_json::from_str(&json).unwrap();
        assert_eq!(sid, back);
    }

    // --- Behavioral edge cases (5 tests) ---

    #[test]
    fn duplicate_const_in_same_scope_fails() {
        let mut chain = fresh_chain();
        chain.declare_const("C".into(), 1).unwrap();
        let result = chain.declare_const("C".into(), 2);
        assert!(matches!(result, Err(ScopeError::DuplicateBinding { .. })));
    }

    #[test]
    fn get_env_invalid_handle_returns_error() {
        let chain = fresh_chain();
        let result = chain.get_env(EnvironmentHandle(999));
        assert!(matches!(result, Err(ScopeError::InvalidEnvironment { .. })));
    }

    #[test]
    fn get_env_mut_invalid_handle_returns_error() {
        let mut chain = fresh_chain();
        let result = chain.get_env_mut(EnvironmentHandle(999));
        assert!(matches!(result, Err(ScopeError::InvalidEnvironment { .. })));
    }

    #[test]
    fn closure_store_get_out_of_bounds_returns_none() {
        let store = ClosureStore::new();
        assert!(store.get(ClosureHandle(0)).is_none());
        assert!(store.get(ClosureHandle(u32::MAX)).is_none());
    }

    #[test]
    fn env_record_max_label_tracks_highest_binding() {
        let mut env = EnvironmentRecord::new(
            EnvironmentHandle(0),
            ScopeId { depth: 0, index: 0 },
            ScopeKind::Global,
            EnvironmentKind::Global,
        );
        assert_eq!(env.max_label, Label::Public);
        let mut slot = BindingSlot::new_hoisted("a".into(), 1, BindingKind::Var);
        slot.label = Label::Internal;
        env.add_binding(slot);
        assert_eq!(env.max_label, Label::Internal);
        let mut slot2 = BindingSlot::new_hoisted("b".into(), 2, BindingKind::Var);
        slot2.label = Label::Secret;
        env.add_binding(slot2);
        assert_eq!(env.max_label, Label::Secret);
        // Adding a lower label binding doesn't reduce max_label
        let slot3 = BindingSlot::new_hoisted("c".into(), 3, BindingKind::Var);
        env.add_binding(slot3);
        assert_eq!(env.max_label, Label::Secret);
    }

    // --- Ord determinism additional (2 tests) ---

    #[test]
    fn ord_determinism_environment_handle() {
        let handles = [
            EnvironmentHandle(10),
            EnvironmentHandle(3),
            EnvironmentHandle(7),
            EnvironmentHandle(0),
            EnvironmentHandle(5),
        ];
        let mut sorted_a = handles;
        sorted_a.sort();
        let mut sorted_b = handles;
        sorted_b.sort();
        assert_eq!(sorted_a, sorted_b);
        assert_eq!(sorted_a[0], EnvironmentHandle(0));
        assert_eq!(sorted_a[4], EnvironmentHandle(10));
    }

    #[test]
    fn ord_closure_handle_in_btreeset() {
        let mut set = std::collections::BTreeSet::new();
        set.insert(ClosureHandle(3));
        set.insert(ClosureHandle(1));
        set.insert(ClosureHandle(3)); // duplicate
        set.insert(ClosureHandle(5));
        assert_eq!(set.len(), 3);
        let as_vec: Vec<_> = set.into_iter().collect();
        assert_eq!(
            as_vec,
            vec![ClosureHandle(1), ClosureHandle(3), ClosureHandle(5)]
        );
    }

    // --- ClosureStore default/new equivalence (1 test) ---

    #[test]
    fn closure_store_default_eq_new() {
        let a = ClosureStore::new();
        let b = ClosureStore::default();
        assert_eq!(a.len(), b.len());
        assert!(a.is_empty());
        assert!(b.is_empty());
    }

    // --- BindingSlot constructor correctness (2 tests) ---

    #[test]
    fn binding_slot_lexical_let_is_mutable() {
        let slot = BindingSlot::new_lexical("x".into(), 1, BindingKind::Let);
        assert!(slot.mutable, "let bindings should be mutable");
        assert!(!slot.initialized, "let starts uninitialized");
        assert_eq!(slot.value, EnvValue::Tdz);
        assert_eq!(slot.label, Label::Public);
    }

    #[test]
    fn binding_slot_lexical_const_is_immutable() {
        let slot = BindingSlot::new_lexical("C".into(), 2, BindingKind::Const);
        assert!(!slot.mutable, "const bindings should be immutable");
        assert!(!slot.initialized);
        assert_eq!(slot.value, EnvValue::Tdz);
    }
}
