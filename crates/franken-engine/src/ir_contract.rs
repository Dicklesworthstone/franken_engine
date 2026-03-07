//! Multi-level IR contract (`IR0`/`IR1`/`IR2`/`IR3`/`IR4`).
//!
//! Defines the five-level Intermediate Representation stack:
//! - **IR0 (SyntaxIR)**: Direct AST output from the parser, structurally canonical.
//! - **IR1 (SpecIR)**: Spec-level semantic representation with scope/binding resolution.
//! - **IR2 (CapabilityIR)**: Annotated with capability intent, effect boundaries, and IFC flow labels.
//! - **IR3 (ExecIR)**: Execution-ready flat instruction stream with proof-to-specialization linkage.
//! - **IR4 (WitnessIR)**: Post-execution witness artifacts for deterministic replay and forensic audit.
//!
//! Every level provides canonical serialization via [`deterministic_serde::CanonicalValue`] and
//! content-addressed hashing via [`hash_tiers::ContentHash`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ast::{AssignmentOperator, BinaryOperator, SyntaxTree, UnaryOperator};
use crate::deterministic_serde::{self, CanonicalValue};
use crate::hash_tiers::ContentHash;
use crate::ifc_artifacts::Label;

// ---------------------------------------------------------------------------
// Schema versioning
// ---------------------------------------------------------------------------

/// Version identifier for the IR schema. All serialized IR artifacts carry this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IrSchemaVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl IrSchemaVersion {
    pub const CURRENT: Self = Self {
        major: 0,
        minor: 1,
        patch: 0,
    };

    pub fn canonical_value(self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "major".to_string(),
            CanonicalValue::U64(u64::from(self.major)),
        );
        map.insert(
            "minor".to_string(),
            CanonicalValue::U64(u64::from(self.minor)),
        );
        map.insert(
            "patch".to_string(),
            CanonicalValue::U64(u64::from(self.patch)),
        );
        CanonicalValue::Map(map)
    }
}

impl std::fmt::Display for IrSchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ---------------------------------------------------------------------------
// IR Level discriminant
// ---------------------------------------------------------------------------

/// Discriminant for the five IR levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IrLevel {
    /// IR0: direct parser output (SyntaxIR).
    Ir0,
    /// IR1: scope/binding resolved (SpecIR).
    Ir1,
    /// IR2: capability + IFC annotated (CapabilityIR).
    Ir2,
    /// IR3: execution-ready flat instructions (ExecIR).
    Ir3,
    /// IR4: post-execution witness (WitnessIR).
    Ir4,
}

impl IrLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ir0 => "ir0",
            Self::Ir1 => "ir1",
            Self::Ir2 => "ir2",
            Self::Ir3 => "ir3",
            Self::Ir4 => "ir4",
        }
    }
}

impl std::fmt::Display for IrLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Common envelope: every IR artifact carries this header
// ---------------------------------------------------------------------------

/// Common header present on every IR artifact at every level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrHeader {
    /// Schema version for forward-compatible deserialization.
    pub schema_version: IrSchemaVersion,
    /// Which IR level this artifact represents.
    pub level: IrLevel,
    /// Content hash of the source artifact that produced this level.
    /// `None` for IR0 (parser output has no predecessor IR).
    pub source_hash: Option<ContentHash>,
    /// Optional human-readable source label.
    pub source_label: String,
}

impl IrHeader {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "level".to_string(),
            CanonicalValue::String(self.level.as_str().to_string()),
        );
        map.insert(
            "schema_version".to_string(),
            self.schema_version.canonical_value(),
        );
        map.insert(
            "source_hash".to_string(),
            match &self.source_hash {
                Some(hash) => CanonicalValue::Bytes(hash.as_bytes().to_vec()),
                None => CanonicalValue::Null,
            },
        );
        map.insert(
            "source_label".to_string(),
            CanonicalValue::String(self.source_label.clone()),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// IR0 — SyntaxIR (wraps ast::SyntaxTree)
// ---------------------------------------------------------------------------

/// IR0 artifact: the direct parser output wrapped with a canonical header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ir0Module {
    pub header: IrHeader,
    pub tree: SyntaxTree,
}

impl Ir0Module {
    /// Create an IR0 module from a parsed syntax tree.
    pub fn from_syntax_tree(tree: SyntaxTree, source_label: impl Into<String>) -> Self {
        Self {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir0,
                source_hash: None,
                source_label: source_label.into(),
            },
            tree,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("header".to_string(), self.header.canonical_value());
        map.insert("tree".to_string(), self.tree.canonical_value());
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }
}

// ---------------------------------------------------------------------------
// IR1 — SpecIR (scope/binding resolved)
// ---------------------------------------------------------------------------

/// Unique identifier for a binding within a scope.
pub type BindingId = u32;

/// Scope identifier (depth + index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ScopeId {
    pub depth: u32,
    pub index: u32,
}

impl ScopeId {
    pub fn canonical_value(self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "depth".to_string(),
            CanonicalValue::U64(u64::from(self.depth)),
        );
        map.insert(
            "index".to_string(),
            CanonicalValue::U64(u64::from(self.index)),
        );
        CanonicalValue::Map(map)
    }
}

/// A resolved binding reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedBinding {
    pub name: String,
    pub binding_id: BindingId,
    pub scope: ScopeId,
    pub kind: BindingKind,
}

impl ResolvedBinding {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "binding_id".to_string(),
            CanonicalValue::U64(u64::from(self.binding_id)),
        );
        map.insert(
            "kind".to_string(),
            CanonicalValue::String(self.kind.as_str().to_string()),
        );
        map.insert(
            "name".to_string(),
            CanonicalValue::String(self.name.clone()),
        );
        map.insert("scope".to_string(), self.scope.canonical_value());
        CanonicalValue::Map(map)
    }
}

/// Classification of bindings in IR1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingKind {
    /// `let` binding (block-scoped, not hoisted).
    Let,
    /// `const` binding (block-scoped, immutable).
    Const,
    /// `var` binding (function-scoped, hoisted).
    Var,
    /// Function parameter.
    Parameter,
    /// Module import binding.
    Import,
    /// Function declaration (hoisted).
    FunctionDecl,
}

impl BindingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Let => "let",
            Self::Const => "const",
            Self::Var => "var",
            Self::Parameter => "parameter",
            Self::Import => "import",
            Self::FunctionDecl => "function_decl",
        }
    }
}

/// Scope node in the resolved scope tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeNode {
    pub scope_id: ScopeId,
    pub parent: Option<ScopeId>,
    pub kind: ScopeKind,
    pub bindings: Vec<ResolvedBinding>,
}

impl ScopeNode {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "bindings".to_string(),
            CanonicalValue::Array(
                self.bindings
                    .iter()
                    .map(ResolvedBinding::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "kind".to_string(),
            CanonicalValue::String(self.kind.as_str().to_string()),
        );
        map.insert(
            "parent".to_string(),
            match self.parent {
                Some(parent) => parent.canonical_value(),
                None => CanonicalValue::Null,
            },
        );
        map.insert("scope_id".to_string(), self.scope_id.canonical_value());
        CanonicalValue::Map(map)
    }
}

/// Classification of scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeKind {
    Global,
    Module,
    Function,
    Block,
    Catch,
}

impl ScopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Module => "module",
            Self::Function => "function",
            Self::Block => "block",
            Self::Catch => "catch",
        }
    }
}

/// IR1 operation — semantically resolved, position-independent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ir1Op {
    /// Load a literal value.
    LoadLiteral { value: Ir1Literal },
    /// Reference a resolved binding.
    LoadBinding { binding_id: BindingId },
    /// Store to a resolved binding.
    StoreBinding { binding_id: BindingId },
    /// Call a function value.
    Call { arg_count: u32 },
    /// Return from current function.
    Return,
    /// Import a module by specifier.
    ImportModule { specifier: String },
    /// Export a binding from the module.
    ExportBinding { name: String, binding_id: BindingId },
    /// Await an expression (async context).
    Await,
    /// No-op placeholder.
    Nop,
    /// Binary operation: pop two operands, push result.
    BinaryOp { operator: BinaryOperator },
    /// Unary operation: pop operand, push result.
    UnaryOp { operator: UnaryOperator },
    /// Assignment: store top-of-stack to binding, with compound operator.
    AssignOp {
        binding_id: BindingId,
        operator: AssignmentOperator,
    },
    /// Jump label marker (jump target in linear IR).
    Label { id: u32 },
    /// Unconditional jump to label.
    Jump { label_id: u32 },
    /// Jump if top-of-stack is falsy.
    JumpIfFalsy { label_id: u32 },
    /// Object property read: key on top-of-stack, object below.
    GetProperty { key: String },
    /// Object property write: value on top, key below, object below that.
    SetProperty { key: String },
    /// Create a new array from top N elements.
    NewArray { count: u32 },
    /// Create a new object from top N key-value pairs.
    NewObject { count: u32 },
    /// Throw the value on top-of-stack.
    Throw,
    /// Load `this` binding.
    LoadThis,
    /// Declare a function and bind it.
    DeclareFunction { name: String, binding_id: BindingId },
    /// Begin a try block; on exception, jump to catch_label.
    BeginTry { catch_label: u32 },
    /// End a try block.
    EndTry,
    /// Pop/discard top-of-stack value.
    Pop,
}

impl Ir1Op {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::LoadLiteral { value } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("load_literal".to_string()),
                );
                map.insert("value".to_string(), value.canonical_value());
            }
            Self::LoadBinding { binding_id } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("load_binding".to_string()),
                );
                map.insert(
                    "binding_id".to_string(),
                    CanonicalValue::U64(u64::from(*binding_id)),
                );
            }
            Self::StoreBinding { binding_id } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("store_binding".to_string()),
                );
                map.insert(
                    "binding_id".to_string(),
                    CanonicalValue::U64(u64::from(*binding_id)),
                );
            }
            Self::Call { arg_count } => {
                map.insert("op".to_string(), CanonicalValue::String("call".to_string()));
                map.insert(
                    "arg_count".to_string(),
                    CanonicalValue::U64(u64::from(*arg_count)),
                );
            }
            Self::Return => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("return".to_string()),
                );
            }
            Self::ImportModule { specifier } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("import_module".to_string()),
                );
                map.insert(
                    "specifier".to_string(),
                    CanonicalValue::String(specifier.clone()),
                );
            }
            Self::ExportBinding { name, binding_id } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("export_binding".to_string()),
                );
                map.insert(
                    "binding_id".to_string(),
                    CanonicalValue::U64(u64::from(*binding_id)),
                );
                map.insert("name".to_string(), CanonicalValue::String(name.clone()));
            }
            Self::Await => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("await".to_string()),
                );
            }
            Self::Nop => {
                map.insert("op".to_string(), CanonicalValue::String("nop".to_string()));
            }
            Self::BinaryOp { operator } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("binary_op".to_string()),
                );
                map.insert(
                    "operator".to_string(),
                    CanonicalValue::String(operator.as_str().to_string()),
                );
            }
            Self::UnaryOp { operator } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("unary_op".to_string()),
                );
                map.insert(
                    "operator".to_string(),
                    CanonicalValue::String(operator.as_str().to_string()),
                );
            }
            Self::AssignOp {
                binding_id,
                operator,
            } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("assign_op".to_string()),
                );
                map.insert(
                    "binding_id".to_string(),
                    CanonicalValue::U64(u64::from(*binding_id)),
                );
                map.insert(
                    "operator".to_string(),
                    CanonicalValue::String(operator.as_str().to_string()),
                );
            }
            Self::Label { id } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("label".to_string()),
                );
                map.insert("id".to_string(), CanonicalValue::U64(u64::from(*id)));
            }
            Self::Jump { label_id } => {
                map.insert("op".to_string(), CanonicalValue::String("jump".to_string()));
                map.insert(
                    "label_id".to_string(),
                    CanonicalValue::U64(u64::from(*label_id)),
                );
            }
            Self::JumpIfFalsy { label_id } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("jump_if_falsy".to_string()),
                );
                map.insert(
                    "label_id".to_string(),
                    CanonicalValue::U64(u64::from(*label_id)),
                );
            }
            Self::GetProperty { key } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("get_property".to_string()),
                );
                map.insert("key".to_string(), CanonicalValue::String(key.clone()));
            }
            Self::SetProperty { key } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("set_property".to_string()),
                );
                map.insert("key".to_string(), CanonicalValue::String(key.clone()));
            }
            Self::NewArray { count } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("new_array".to_string()),
                );
                map.insert("count".to_string(), CanonicalValue::U64(u64::from(*count)));
            }
            Self::NewObject { count } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("new_object".to_string()),
                );
                map.insert("count".to_string(), CanonicalValue::U64(u64::from(*count)));
            }
            Self::Throw => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("throw".to_string()),
                );
            }
            Self::LoadThis => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("load_this".to_string()),
                );
            }
            Self::DeclareFunction { name, binding_id } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("declare_function".to_string()),
                );
                map.insert("name".to_string(), CanonicalValue::String(name.clone()));
                map.insert(
                    "binding_id".to_string(),
                    CanonicalValue::U64(u64::from(*binding_id)),
                );
            }
            Self::BeginTry { catch_label } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("begin_try".to_string()),
                );
                map.insert(
                    "catch_label".to_string(),
                    CanonicalValue::U64(u64::from(*catch_label)),
                );
            }
            Self::EndTry => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("end_try".to_string()),
                );
            }
            Self::Pop => {
                map.insert("op".to_string(), CanonicalValue::String("pop".to_string()));
            }
        }
        CanonicalValue::Map(map)
    }
}

/// Literal values in IR1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ir1Literal {
    String(String),
    Integer(i64),
    Boolean(bool),
    Null,
    Undefined,
}

impl Ir1Literal {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::String(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("string".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::String(value.clone()));
            }
            Self::Integer(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("integer".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::I64(*value));
            }
            Self::Boolean(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("boolean".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::Bool(*value));
            }
            Self::Null => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("null".to_string()),
                );
            }
            Self::Undefined => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("undefined".to_string()),
                );
            }
        }
        CanonicalValue::Map(map)
    }
}

/// IR1 module: scope-resolved, position-independent spec-level representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ir1Module {
    pub header: IrHeader,
    /// Scope tree capturing all bindings.
    pub scopes: Vec<ScopeNode>,
    /// Flattened operation sequence.
    pub ops: Vec<Ir1Op>,
}

impl Ir1Module {
    pub fn new(source_hash: ContentHash, source_label: impl Into<String>) -> Self {
        Self {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir1,
                source_hash: Some(source_hash),
                source_label: source_label.into(),
            },
            scopes: Vec::new(),
            ops: Vec::new(),
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("header".to_string(), self.header.canonical_value());
        map.insert(
            "ops".to_string(),
            CanonicalValue::Array(self.ops.iter().map(Ir1Op::canonical_value).collect()),
        );
        map.insert(
            "scopes".to_string(),
            CanonicalValue::Array(self.scopes.iter().map(ScopeNode::canonical_value).collect()),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }
}

// ---------------------------------------------------------------------------
// IR2 — CapabilityIR (capability + IFC annotations)
// ---------------------------------------------------------------------------

/// Capability tag for hostcall dispatch.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CapabilityTag(pub String);

impl CapabilityTag {
    pub fn canonical_value(&self) -> CanonicalValue {
        CanonicalValue::String(self.0.clone())
    }
}

/// Effect boundary marker for capability-annotated operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectBoundary {
    /// Pure computation — no side effects.
    Pure,
    /// Reads from external state.
    ReadEffect,
    /// Writes to external state.
    WriteEffect,
    /// Network I/O.
    NetworkEffect,
    /// File system I/O.
    FsEffect,
    /// Hostcall invocation (capability-gated).
    HostcallEffect,
}

impl EffectBoundary {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pure => "pure",
            Self::ReadEffect => "read",
            Self::WriteEffect => "write",
            Self::NetworkEffect => "network",
            Self::FsEffect => "fs",
            Self::HostcallEffect => "hostcall",
        }
    }
}

/// IFC flow annotation on an IR2 operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowAnnotation {
    /// Security label of the data being operated on.
    pub data_label: Label,
    /// Required clearance to read the result.
    pub sink_clearance: Label,
    /// Whether a declassification obligation is pending.
    pub declassification_required: bool,
}

impl FlowAnnotation {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "data_label".to_string(),
            CanonicalValue::String(format!("{:?}", self.data_label)),
        );
        map.insert(
            "declassification_required".to_string(),
            CanonicalValue::Bool(self.declassification_required),
        );
        map.insert(
            "sink_clearance".to_string(),
            CanonicalValue::String(format!("{:?}", self.sink_clearance)),
        );
        CanonicalValue::Map(map)
    }
}

/// IR2 operation — capability-annotated and flow-labeled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ir2Op {
    /// The underlying IR1 operation.
    pub inner: Ir1Op,
    /// Effect boundary classification.
    pub effect: EffectBoundary,
    /// Required capability (if this operation needs one).
    pub required_capability: Option<CapabilityTag>,
    /// IFC flow annotation (if data flows through this operation).
    pub flow: Option<FlowAnnotation>,
}

impl Ir2Op {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "effect".to_string(),
            CanonicalValue::String(self.effect.as_str().to_string()),
        );
        map.insert(
            "flow".to_string(),
            match &self.flow {
                Some(flow) => flow.canonical_value(),
                None => CanonicalValue::Null,
            },
        );
        map.insert("inner".to_string(), self.inner.canonical_value());
        map.insert(
            "required_capability".to_string(),
            match &self.required_capability {
                Some(cap) => cap.canonical_value(),
                None => CanonicalValue::Null,
            },
        );
        CanonicalValue::Map(map)
    }
}

/// IR2 module: capability-annotated, IFC-labeled semantic representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ir2Module {
    pub header: IrHeader,
    /// Scope tree (inherited from IR1).
    pub scopes: Vec<ScopeNode>,
    /// Capability-annotated operation sequence.
    pub ops: Vec<Ir2Op>,
    /// Aggregate set of capabilities required by this module.
    pub required_capabilities: Vec<CapabilityTag>,
}

impl Ir2Module {
    pub fn new(source_hash: ContentHash, source_label: impl Into<String>) -> Self {
        Self {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir2,
                source_hash: Some(source_hash),
                source_label: source_label.into(),
            },
            scopes: Vec::new(),
            ops: Vec::new(),
            required_capabilities: Vec::new(),
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("header".to_string(), self.header.canonical_value());
        map.insert(
            "ops".to_string(),
            CanonicalValue::Array(self.ops.iter().map(Ir2Op::canonical_value).collect()),
        );
        map.insert(
            "required_capabilities".to_string(),
            CanonicalValue::Array(
                self.required_capabilities
                    .iter()
                    .map(CapabilityTag::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "scopes".to_string(),
            CanonicalValue::Array(self.scopes.iter().map(ScopeNode::canonical_value).collect()),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }
}

// ---------------------------------------------------------------------------
// IR3 — ExecIR (flat instruction stream with proof linkage)
// ---------------------------------------------------------------------------

/// Register index for the flat register machine.
pub type Reg = u32;

/// Instruction index into the flat instruction array.
pub type InstrIndex = u32;

/// Register range [start, start+count).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegRange {
    pub start: Reg,
    pub count: u32,
}

impl RegRange {
    pub fn canonical_value(self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "count".to_string(),
            CanonicalValue::U64(u64::from(self.count)),
        );
        map.insert(
            "start".to_string(),
            CanonicalValue::U64(u64::from(self.start)),
        );
        CanonicalValue::Map(map)
    }
}

/// IR3 instruction set — flat, indexed operations for the register machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ir3Instruction {
    /// Load an integer constant into a register.
    LoadInt { dst: Reg, value: i64 },
    /// Load a string constant from the constant pool.
    LoadStr { dst: Reg, pool_index: u32 },
    /// Load boolean constant.
    LoadBool { dst: Reg, value: bool },
    /// Load null.
    LoadNull { dst: Reg },
    /// Load undefined.
    LoadUndefined { dst: Reg },
    /// Arithmetic: dst = lhs + rhs.
    Add { dst: Reg, lhs: Reg, rhs: Reg },
    /// Arithmetic: dst = lhs - rhs.
    Sub { dst: Reg, lhs: Reg, rhs: Reg },
    /// Arithmetic: dst = lhs * rhs.
    Mul { dst: Reg, lhs: Reg, rhs: Reg },
    /// Arithmetic: dst = lhs / rhs.
    Div { dst: Reg, lhs: Reg, rhs: Reg },
    /// Copy register.
    Move { dst: Reg, src: Reg },
    /// Unconditional jump.
    Jump { target: InstrIndex },
    /// Conditional jump (jump if register is truthy).
    JumpIf { cond: Reg, target: InstrIndex },
    /// Call a function value with args.
    Call {
        callee: Reg,
        args: RegRange,
        dst: Reg,
    },
    /// Return a value from the current frame.
    Return { value: Reg },
    /// Capability-checked hostcall.
    HostCall {
        capability: CapabilityTag,
        args: RegRange,
        dst: Reg,
    },
    /// Object property read: dst = obj[key].
    GetProperty { obj: Reg, key: Reg, dst: Reg },
    /// Object property write: obj[key] = val.
    SetProperty { obj: Reg, key: Reg, val: Reg },
    /// Allocate a new object on the heap.
    NewObject { dst: Reg },
    /// Allocate a new array on the heap.
    NewArray { dst: Reg },
    /// Halt execution.
    Halt,
}

impl Ir3Instruction {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::LoadInt { dst, value } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("load_int".to_string()),
                );
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
                map.insert("value".to_string(), CanonicalValue::I64(*value));
            }
            Self::LoadStr { dst, pool_index } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("load_str".to_string()),
                );
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
                map.insert(
                    "pool_index".to_string(),
                    CanonicalValue::U64(u64::from(*pool_index)),
                );
            }
            Self::LoadBool { dst, value } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("load_bool".to_string()),
                );
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
                map.insert("value".to_string(), CanonicalValue::Bool(*value));
            }
            Self::LoadNull { dst } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("load_null".to_string()),
                );
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
            }
            Self::LoadUndefined { dst } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("load_undefined".to_string()),
                );
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
            }
            Self::Add { dst, lhs, rhs } => {
                map.insert("op".to_string(), CanonicalValue::String("add".to_string()));
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
                map.insert("lhs".to_string(), CanonicalValue::U64(u64::from(*lhs)));
                map.insert("rhs".to_string(), CanonicalValue::U64(u64::from(*rhs)));
            }
            Self::Sub { dst, lhs, rhs } => {
                map.insert("op".to_string(), CanonicalValue::String("sub".to_string()));
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
                map.insert("lhs".to_string(), CanonicalValue::U64(u64::from(*lhs)));
                map.insert("rhs".to_string(), CanonicalValue::U64(u64::from(*rhs)));
            }
            Self::Mul { dst, lhs, rhs } => {
                map.insert("op".to_string(), CanonicalValue::String("mul".to_string()));
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
                map.insert("lhs".to_string(), CanonicalValue::U64(u64::from(*lhs)));
                map.insert("rhs".to_string(), CanonicalValue::U64(u64::from(*rhs)));
            }
            Self::Div { dst, lhs, rhs } => {
                map.insert("op".to_string(), CanonicalValue::String("div".to_string()));
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
                map.insert("lhs".to_string(), CanonicalValue::U64(u64::from(*lhs)));
                map.insert("rhs".to_string(), CanonicalValue::U64(u64::from(*rhs)));
            }
            Self::Move { dst, src } => {
                map.insert("op".to_string(), CanonicalValue::String("move".to_string()));
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
                map.insert("src".to_string(), CanonicalValue::U64(u64::from(*src)));
            }
            Self::Jump { target } => {
                map.insert("op".to_string(), CanonicalValue::String("jump".to_string()));
                map.insert(
                    "target".to_string(),
                    CanonicalValue::U64(u64::from(*target)),
                );
            }
            Self::JumpIf { cond, target } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("jump_if".to_string()),
                );
                map.insert("cond".to_string(), CanonicalValue::U64(u64::from(*cond)));
                map.insert(
                    "target".to_string(),
                    CanonicalValue::U64(u64::from(*target)),
                );
            }
            Self::Call { callee, args, dst } => {
                map.insert("op".to_string(), CanonicalValue::String("call".to_string()));
                map.insert("args".to_string(), args.canonical_value());
                map.insert(
                    "callee".to_string(),
                    CanonicalValue::U64(u64::from(*callee)),
                );
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
            }
            Self::Return { value } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("return".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::U64(u64::from(*value)));
            }
            Self::HostCall {
                capability,
                args,
                dst,
            } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("hostcall".to_string()),
                );
                map.insert("args".to_string(), args.canonical_value());
                map.insert("capability".to_string(), capability.canonical_value());
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
            }
            Self::GetProperty { obj, key, dst } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("get_property".to_string()),
                );
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
                map.insert("key".to_string(), CanonicalValue::U64(u64::from(*key)));
                map.insert("obj".to_string(), CanonicalValue::U64(u64::from(*obj)));
            }
            Self::SetProperty { obj, key, val } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("set_property".to_string()),
                );
                map.insert("key".to_string(), CanonicalValue::U64(u64::from(*key)));
                map.insert("obj".to_string(), CanonicalValue::U64(u64::from(*obj)));
                map.insert("val".to_string(), CanonicalValue::U64(u64::from(*val)));
            }
            Self::NewObject { dst } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("new_object".to_string()),
                );
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
            }
            Self::NewArray { dst } => {
                map.insert(
                    "op".to_string(),
                    CanonicalValue::String("new_array".to_string()),
                );
                map.insert("dst".to_string(), CanonicalValue::U64(u64::from(*dst)));
            }
            Self::Halt => {
                map.insert("op".to_string(), CanonicalValue::String("halt".to_string()));
            }
        }
        CanonicalValue::Map(map)
    }
}

/// IR3 function descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ir3FunctionDesc {
    /// Entry instruction index.
    pub entry: InstrIndex,
    /// Number of parameters.
    pub arity: u32,
    /// Number of registers needed for this frame.
    pub frame_size: u32,
    /// Human-readable name (for diagnostics).
    pub name: Option<String>,
}

impl Ir3FunctionDesc {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "arity".to_string(),
            CanonicalValue::U64(u64::from(self.arity)),
        );
        map.insert(
            "entry".to_string(),
            CanonicalValue::U64(u64::from(self.entry)),
        );
        map.insert(
            "frame_size".to_string(),
            CanonicalValue::U64(u64::from(self.frame_size)),
        );
        map.insert(
            "name".to_string(),
            match &self.name {
                Some(name) => CanonicalValue::String(name.clone()),
                None => CanonicalValue::Null,
            },
        );
        CanonicalValue::Map(map)
    }
}

/// Proof-to-specialization linkage for IR3 artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationLinkage {
    /// Which security proofs justify this specialization.
    pub proof_input_ids: Vec<String>,
    /// Classification of the optimization.
    pub optimization_class: String,
    /// When this specialization expires (security epoch).
    pub validity_epoch: u64,
    /// How to revert to the unspecialized baseline.
    pub rollback_token: ContentHash,
}

impl SpecializationLinkage {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "optimization_class".to_string(),
            CanonicalValue::String(self.optimization_class.clone()),
        );
        map.insert(
            "proof_input_ids".to_string(),
            CanonicalValue::Array(
                self.proof_input_ids
                    .iter()
                    .map(|id| CanonicalValue::String(id.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "rollback_token".to_string(),
            CanonicalValue::Bytes(self.rollback_token.as_bytes().to_vec()),
        );
        map.insert(
            "validity_epoch".to_string(),
            CanonicalValue::U64(self.validity_epoch),
        );
        CanonicalValue::Map(map)
    }
}

/// IR3 module: flat, indexed instruction stream ready for execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ir3Module {
    pub header: IrHeader,
    /// Flat instruction array.
    pub instructions: Vec<Ir3Instruction>,
    /// String constant pool.
    pub constant_pool: Vec<String>,
    /// Function table with entry points and frame layout.
    pub function_table: Vec<Ir3FunctionDesc>,
    /// Proof-to-specialization linkage (if specialized).
    pub specialization: Option<SpecializationLinkage>,
    /// Aggregate capabilities required by hostcall instructions.
    pub required_capabilities: Vec<CapabilityTag>,
}

impl Ir3Module {
    pub fn new(source_hash: ContentHash, source_label: impl Into<String>) -> Self {
        Self {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir3,
                source_hash: Some(source_hash),
                source_label: source_label.into(),
            },
            instructions: Vec::new(),
            constant_pool: Vec::new(),
            function_table: Vec::new(),
            specialization: None,
            required_capabilities: Vec::new(),
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "constant_pool".to_string(),
            CanonicalValue::Array(
                self.constant_pool
                    .iter()
                    .map(|s| CanonicalValue::String(s.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "function_table".to_string(),
            CanonicalValue::Array(
                self.function_table
                    .iter()
                    .map(Ir3FunctionDesc::canonical_value)
                    .collect(),
            ),
        );
        map.insert("header".to_string(), self.header.canonical_value());
        map.insert(
            "instructions".to_string(),
            CanonicalValue::Array(
                self.instructions
                    .iter()
                    .map(Ir3Instruction::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "required_capabilities".to_string(),
            CanonicalValue::Array(
                self.required_capabilities
                    .iter()
                    .map(CapabilityTag::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "specialization".to_string(),
            match &self.specialization {
                Some(spec) => spec.canonical_value(),
                None => CanonicalValue::Null,
            },
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }
}

// ---------------------------------------------------------------------------
// IR4 — WitnessIR (post-execution witness artifacts)
// ---------------------------------------------------------------------------

/// Classification of witness events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessEventKind {
    /// A hostcall was dispatched.
    HostcallDispatched,
    /// A capability was checked.
    CapabilityChecked,
    /// An exception was raised.
    ExceptionRaised,
    /// A GC cycle was triggered.
    GcTriggered,
    /// Execution completed normally.
    ExecutionCompleted,
    /// A flow label was checked.
    FlowLabelChecked,
    /// A declassification was requested.
    DeclassificationRequested,
}

impl WitnessEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostcallDispatched => "hostcall_dispatched",
            Self::CapabilityChecked => "capability_checked",
            Self::ExceptionRaised => "exception_raised",
            Self::GcTriggered => "gc_triggered",
            Self::ExecutionCompleted => "execution_completed",
            Self::FlowLabelChecked => "flow_label_checked",
            Self::DeclassificationRequested => "declassification_requested",
        }
    }
}

/// A single witness event captured during execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessEvent {
    /// Monotonic sequence number within this execution.
    pub seq: u64,
    /// Kind of event.
    pub kind: WitnessEventKind,
    /// Instruction index at which the event occurred.
    pub instruction_index: InstrIndex,
    /// Deterministic content hash of the event payload.
    pub payload_hash: ContentHash,
    /// Monotonic timestamp (logical tick).
    pub timestamp_tick: u64,
}

impl WitnessEvent {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "instruction_index".to_string(),
            CanonicalValue::U64(u64::from(self.instruction_index)),
        );
        map.insert(
            "kind".to_string(),
            CanonicalValue::String(self.kind.as_str().to_string()),
        );
        map.insert(
            "payload_hash".to_string(),
            CanonicalValue::Bytes(self.payload_hash.as_bytes().to_vec()),
        );
        map.insert("seq".to_string(), CanonicalValue::U64(self.seq));
        map.insert(
            "timestamp_tick".to_string(),
            CanonicalValue::U64(self.timestamp_tick),
        );
        CanonicalValue::Map(map)
    }
}

/// Execution outcome for the witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionOutcome {
    /// Normal completion with a return value.
    Completed,
    /// Terminated by exception.
    Exception,
    /// Terminated by timeout (budget exhaustion).
    Timeout,
    /// Terminated by explicit halt instruction.
    Halted,
}

impl ExecutionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Exception => "exception",
            Self::Timeout => "timeout",
            Self::Halted => "halted",
        }
    }
}

/// Hostcall decision record within the witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallDecisionRecord {
    /// Sequence number within this execution.
    pub seq: u64,
    /// Capability that was checked.
    pub capability: CapabilityTag,
    /// Whether the capability check passed.
    pub allowed: bool,
    /// Instruction index of the hostcall.
    pub instruction_index: InstrIndex,
}

impl HostcallDecisionRecord {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("allowed".to_string(), CanonicalValue::Bool(self.allowed));
        map.insert("capability".to_string(), self.capability.canonical_value());
        map.insert(
            "instruction_index".to_string(),
            CanonicalValue::U64(u64::from(self.instruction_index)),
        );
        map.insert("seq".to_string(), CanonicalValue::U64(self.seq));
        CanonicalValue::Map(map)
    }
}

/// IR4 module: post-execution witness artifacts for replay and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ir4Module {
    pub header: IrHeader,
    /// Content hash of the IR3 module that was executed.
    pub executed_ir3_hash: ContentHash,
    /// Execution outcome.
    pub outcome: ExecutionOutcome,
    /// Witness event trace (append-only during execution).
    pub events: Vec<WitnessEvent>,
    /// Hostcall decision log.
    pub hostcall_decisions: Vec<HostcallDecisionRecord>,
    /// Total instructions executed.
    pub instructions_executed: u64,
    /// Execution duration in logical ticks.
    pub duration_ticks: u64,
    /// Which specializations were active during execution (IR3 linkage).
    pub active_specialization_ids: Vec<String>,
}

impl Ir4Module {
    pub fn new(executed_ir3_hash: ContentHash, source_label: impl Into<String>) -> Self {
        Self {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir4,
                source_hash: Some(executed_ir3_hash.clone()),
                source_label: source_label.into(),
            },
            executed_ir3_hash,
            outcome: ExecutionOutcome::Completed,
            events: Vec::new(),
            hostcall_decisions: Vec::new(),
            instructions_executed: 0,
            duration_ticks: 0,
            active_specialization_ids: Vec::new(),
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "active_specialization_ids".to_string(),
            CanonicalValue::Array(
                self.active_specialization_ids
                    .iter()
                    .map(|id| CanonicalValue::String(id.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "duration_ticks".to_string(),
            CanonicalValue::U64(self.duration_ticks),
        );
        map.insert(
            "events".to_string(),
            CanonicalValue::Array(
                self.events
                    .iter()
                    .map(WitnessEvent::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "executed_ir3_hash".to_string(),
            CanonicalValue::Bytes(self.executed_ir3_hash.as_bytes().to_vec()),
        );
        map.insert("header".to_string(), self.header.canonical_value());
        map.insert(
            "hostcall_decisions".to_string(),
            CanonicalValue::Array(
                self.hostcall_decisions
                    .iter()
                    .map(HostcallDecisionRecord::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "instructions_executed".to_string(),
            CanonicalValue::U64(self.instructions_executed),
        );
        map.insert(
            "outcome".to_string(),
            CanonicalValue::String(self.outcome.as_str().to_string()),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn content_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }
}

// ---------------------------------------------------------------------------
// IR Errors
// ---------------------------------------------------------------------------

/// Stable error codes for IR contract violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrErrorCode {
    /// Schema version mismatch.
    SchemaVersionMismatch,
    /// Unexpected IR level.
    LevelMismatch,
    /// Source hash verification failed.
    SourceHashMismatch,
    /// Canonical hash verification failed.
    HashVerificationFailed,
    /// Missing required capability annotation in IR2.
    MissingCapabilityAnnotation,
    /// Invalid specialization linkage in IR3.
    InvalidSpecializationLinkage,
    /// Witness integrity violation in IR4.
    WitnessIntegrityViolation,
}

impl IrErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SchemaVersionMismatch => "IR_SCHEMA_VERSION_MISMATCH",
            Self::LevelMismatch => "IR_LEVEL_MISMATCH",
            Self::SourceHashMismatch => "IR_SOURCE_HASH_MISMATCH",
            Self::HashVerificationFailed => "IR_HASH_VERIFICATION_FAILED",
            Self::MissingCapabilityAnnotation => "IR_MISSING_CAPABILITY_ANNOTATION",
            Self::InvalidSpecializationLinkage => "IR_INVALID_SPECIALIZATION_LINKAGE",
            Self::WitnessIntegrityViolation => "IR_WITNESS_INTEGRITY_VIOLATION",
        }
    }
}

impl std::fmt::Display for IrErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error type for IR contract violations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrError {
    pub code: IrErrorCode,
    pub message: String,
    pub level: IrLevel,
}

impl IrError {
    pub fn new(code: IrErrorCode, message: impl Into<String>, level: IrLevel) -> Self {
        Self {
            code,
            message: message.into(),
            level,
        }
    }
}

impl std::fmt::Display for IrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.level, self.code, self.message)
    }
}

impl std::error::Error for IrError {}

// ---------------------------------------------------------------------------
// Verification helpers
// ---------------------------------------------------------------------------

/// Verify that an IR0 module's content hash matches an expected value.
pub fn verify_ir0_hash(module: &Ir0Module, expected: &ContentHash) -> Result<(), IrError> {
    let actual = module.content_hash();
    if &actual != expected {
        return Err(IrError::new(
            IrErrorCode::HashVerificationFailed,
            format!(
                "IR0 hash mismatch: expected {}, got {}",
                hex::encode(expected.as_bytes()),
                hex::encode(actual.as_bytes()),
            ),
            IrLevel::Ir0,
        ));
    }
    Ok(())
}

/// Verify that an IR1 module's source hash matches the expected IR0 hash.
pub fn verify_ir1_source(module: &Ir1Module, ir0_hash: &ContentHash) -> Result<(), IrError> {
    match &module.header.source_hash {
        Some(source_hash) if source_hash == ir0_hash => Ok(()),
        Some(source_hash) => Err(IrError::new(
            IrErrorCode::SourceHashMismatch,
            format!(
                "IR1 source hash mismatch: expected {}, got {}",
                hex::encode(ir0_hash.as_bytes()),
                hex::encode(source_hash.as_bytes()),
            ),
            IrLevel::Ir1,
        )),
        None => Err(IrError::new(
            IrErrorCode::SourceHashMismatch,
            "IR1 module missing source_hash",
            IrLevel::Ir1,
        )),
    }
}

/// Verify that an IR3 module has valid specialization linkage if present.
pub fn verify_ir3_specialization(module: &Ir3Module) -> Result<(), IrError> {
    if let Some(spec) = &module.specialization {
        if spec.proof_input_ids.is_empty() {
            return Err(IrError::new(
                IrErrorCode::InvalidSpecializationLinkage,
                "specialization linkage has no proof inputs",
                IrLevel::Ir3,
            ));
        }
        if spec.optimization_class.is_empty() {
            return Err(IrError::new(
                IrErrorCode::InvalidSpecializationLinkage,
                "specialization linkage has empty optimization_class",
                IrLevel::Ir3,
            ));
        }
    }
    Ok(())
}

/// Verify that an IR4 witness is consistent with the IR3 module it was produced from.
pub fn verify_ir4_linkage(witness: &Ir4Module, ir3_hash: &ContentHash) -> Result<(), IrError> {
    if &witness.executed_ir3_hash != ir3_hash {
        return Err(IrError::new(
            IrErrorCode::WitnessIntegrityViolation,
            format!(
                "IR4 witness references IR3 hash {}, but expected {}",
                hex::encode(witness.executed_ir3_hash.as_bytes()),
                hex::encode(ir3_hash.as_bytes()),
            ),
            IrLevel::Ir4,
        ));
    }
    // Verify event sequence monotonicity.
    for window in witness.events.windows(2) {
        if window[1].seq <= window[0].seq {
            return Err(IrError::new(
                IrErrorCode::WitnessIntegrityViolation,
                format!(
                    "IR4 witness events not monotonic: seq {} followed by {}",
                    window[0].seq, window[1].seq
                ),
                IrLevel::Ir4,
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Structured events
// ---------------------------------------------------------------------------

/// Structured event emitted by IR contract operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrContractEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub level: IrLevel,
    pub content_hash: Option<String>,
}

impl IrContractEvent {
    fn ok(trace_id: &str, event: &str, level: IrLevel, hash: Option<&ContentHash>) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            component: "ir_contract".to_string(),
            event: event.to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            level,
            content_hash: hash.map(|h| hex::encode(h.as_bytes())),
        }
    }

    fn err(trace_id: &str, event: &str, level: IrLevel, code: IrErrorCode) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            component: "ir_contract".to_string(),
            event: event.to_string(),
            outcome: "error".to_string(),
            error_code: Some(code.as_str().to_string()),
            level,
            content_hash: None,
        }
    }
}

/// Stable error code string for an `IrError`.
pub fn error_code(err: &IrError) -> &'static str {
    err.code.as_str()
}

// ---------------------------------------------------------------------------
// Verified pipeline (event-emitting wrappers)
// ---------------------------------------------------------------------------

/// A thin wrapper around the verification helpers that emits structured events.
pub struct IrVerifier {
    events: Vec<IrContractEvent>,
}

impl IrVerifier {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Verify an IR0 module's content hash and emit an event.
    pub fn verify_ir0(
        &mut self,
        module: &Ir0Module,
        expected: &ContentHash,
        trace_id: &str,
    ) -> Result<(), IrError> {
        match verify_ir0_hash(module, expected) {
            Ok(()) => {
                let hash = module.content_hash();
                self.events.push(IrContractEvent::ok(
                    trace_id,
                    "ir0_hash_verified",
                    IrLevel::Ir0,
                    Some(&hash),
                ));
                Ok(())
            }
            Err(e) => {
                self.events.push(IrContractEvent::err(
                    trace_id,
                    "ir0_hash_verified",
                    IrLevel::Ir0,
                    e.code,
                ));
                Err(e)
            }
        }
    }

    /// Verify IR1 source linkage and emit an event.
    pub fn verify_ir1(
        &mut self,
        module: &Ir1Module,
        ir0_hash: &ContentHash,
        trace_id: &str,
    ) -> Result<(), IrError> {
        match verify_ir1_source(module, ir0_hash) {
            Ok(()) => {
                let hash = module.content_hash();
                self.events.push(IrContractEvent::ok(
                    trace_id,
                    "ir1_source_verified",
                    IrLevel::Ir1,
                    Some(&hash),
                ));
                Ok(())
            }
            Err(e) => {
                self.events.push(IrContractEvent::err(
                    trace_id,
                    "ir1_source_verified",
                    IrLevel::Ir1,
                    e.code,
                ));
                Err(e)
            }
        }
    }

    /// Verify IR3 specialization linkage and emit an event.
    pub fn verify_ir3(&mut self, module: &Ir3Module, trace_id: &str) -> Result<(), IrError> {
        match verify_ir3_specialization(module) {
            Ok(()) => {
                let hash = module.content_hash();
                self.events.push(IrContractEvent::ok(
                    trace_id,
                    "ir3_specialization_verified",
                    IrLevel::Ir3,
                    Some(&hash),
                ));
                Ok(())
            }
            Err(e) => {
                self.events.push(IrContractEvent::err(
                    trace_id,
                    "ir3_specialization_verified",
                    IrLevel::Ir3,
                    e.code,
                ));
                Err(e)
            }
        }
    }

    /// Verify IR4 witness linkage and emit an event.
    pub fn verify_ir4(
        &mut self,
        witness: &Ir4Module,
        ir3_hash: &ContentHash,
        trace_id: &str,
    ) -> Result<(), IrError> {
        match verify_ir4_linkage(witness, ir3_hash) {
            Ok(()) => {
                let hash = witness.content_hash();
                self.events.push(IrContractEvent::ok(
                    trace_id,
                    "ir4_linkage_verified",
                    IrLevel::Ir4,
                    Some(&hash),
                ));
                Ok(())
            }
            Err(e) => {
                self.events.push(IrContractEvent::err(
                    trace_id,
                    "ir4_linkage_verified",
                    IrLevel::Ir4,
                    e.code,
                ));
                Err(e)
            }
        }
    }

    /// Drain all accumulated events.
    pub fn drain_events(&mut self) -> Vec<IrContractEvent> {
        std::mem::take(&mut self.events)
    }
}

impl Default for IrVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{ExpressionStatement, ParseGoal, SourceSpan, Statement, SyntaxTree};

    fn make_span() -> SourceSpan {
        SourceSpan::new(0, 10, 1, 1, 1, 11)
    }

    fn make_syntax_tree() -> SyntaxTree {
        use crate::ast::Expression;
        SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(42),
                span: make_span(),
            })],
            span: make_span(),
        }
    }

    // -- Schema version --

    #[test]
    fn schema_version_display() {
        assert_eq!(IrSchemaVersion::CURRENT.to_string(), "0.1.0");
    }

    #[test]
    fn schema_version_serde_roundtrip() {
        let version = IrSchemaVersion::CURRENT;
        let json = serde_json::to_string(&version).unwrap();
        let restored: IrSchemaVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(version, restored);
    }

    #[test]
    fn schema_version_canonical_deterministic() {
        let a = IrSchemaVersion::CURRENT.canonical_value();
        let b = IrSchemaVersion::CURRENT.canonical_value();
        assert_eq!(a, b);
    }

    // -- IR Level --

    #[test]
    fn ir_level_as_str() {
        assert_eq!(IrLevel::Ir0.as_str(), "ir0");
        assert_eq!(IrLevel::Ir1.as_str(), "ir1");
        assert_eq!(IrLevel::Ir2.as_str(), "ir2");
        assert_eq!(IrLevel::Ir3.as_str(), "ir3");
        assert_eq!(IrLevel::Ir4.as_str(), "ir4");
    }

    #[test]
    fn ir_level_ordering() {
        assert!(IrLevel::Ir0 < IrLevel::Ir1);
        assert!(IrLevel::Ir1 < IrLevel::Ir2);
        assert!(IrLevel::Ir2 < IrLevel::Ir3);
        assert!(IrLevel::Ir3 < IrLevel::Ir4);
    }

    #[test]
    fn ir_level_serde_roundtrip() {
        for level in [
            IrLevel::Ir0,
            IrLevel::Ir1,
            IrLevel::Ir2,
            IrLevel::Ir3,
            IrLevel::Ir4,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let restored: IrLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, restored);
        }
    }

    // -- IR0 --

    #[test]
    fn ir0_from_syntax_tree() {
        let tree = make_syntax_tree();
        let ir0 = Ir0Module::from_syntax_tree(tree.clone(), "test.js");
        assert_eq!(ir0.header.level, IrLevel::Ir0);
        assert!(ir0.header.source_hash.is_none());
        assert_eq!(ir0.tree, tree);
    }

    #[test]
    fn ir0_canonical_bytes_deterministic() {
        let tree = make_syntax_tree();
        let ir0a = Ir0Module::from_syntax_tree(tree.clone(), "test.js");
        let ir0b = Ir0Module::from_syntax_tree(tree, "test.js");
        assert_eq!(ir0a.canonical_bytes(), ir0b.canonical_bytes());
    }

    #[test]
    fn ir0_content_hash_deterministic() {
        let tree = make_syntax_tree();
        let ir0a = Ir0Module::from_syntax_tree(tree.clone(), "test.js");
        let ir0b = Ir0Module::from_syntax_tree(tree, "test.js");
        assert_eq!(ir0a.content_hash(), ir0b.content_hash());
    }

    #[test]
    fn ir0_content_hash_changes_with_content() {
        let tree1 = make_syntax_tree();
        let tree2 = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![],
            span: make_span(),
        };
        let ir0a = Ir0Module::from_syntax_tree(tree1, "a.js");
        let ir0b = Ir0Module::from_syntax_tree(tree2, "b.js");
        assert_ne!(ir0a.content_hash(), ir0b.content_hash());
    }

    #[test]
    fn ir0_serde_roundtrip() {
        let tree = make_syntax_tree();
        let ir0 = Ir0Module::from_syntax_tree(tree, "test.js");
        let json = serde_json::to_string(&ir0).unwrap();
        let restored: Ir0Module = serde_json::from_str(&json).unwrap();
        assert_eq!(ir0, restored);
    }

    // -- IR1 --

    #[test]
    fn ir1_construction() {
        let source_hash = ContentHash::compute(b"test");
        let ir1 = Ir1Module::new(source_hash.clone(), "test.js");
        assert_eq!(ir1.header.level, IrLevel::Ir1);
        assert_eq!(ir1.header.source_hash, Some(source_hash));
    }

    #[test]
    fn ir1_with_ops_canonical_deterministic() {
        let source_hash = ContentHash::compute(b"test");
        let mut ir1a = Ir1Module::new(source_hash.clone(), "test.js");
        ir1a.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(42),
        });
        ir1a.ops.push(Ir1Op::Return);

        let mut ir1b = Ir1Module::new(source_hash, "test.js");
        ir1b.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(42),
        });
        ir1b.ops.push(Ir1Op::Return);

        assert_eq!(ir1a.canonical_bytes(), ir1b.canonical_bytes());
        assert_eq!(ir1a.content_hash(), ir1b.content_hash());
    }

    #[test]
    fn ir1_serde_roundtrip() {
        let source_hash = ContentHash::compute(b"test");
        let mut ir1 = Ir1Module::new(source_hash, "test.js");
        ir1.scopes.push(ScopeNode {
            scope_id: ScopeId { depth: 0, index: 0 },
            parent: None,
            kind: ScopeKind::Global,
            bindings: vec![ResolvedBinding {
                name: "x".to_string(),
                binding_id: 0,
                scope: ScopeId { depth: 0, index: 0 },
                kind: BindingKind::Let,
            }],
        });
        ir1.ops.push(Ir1Op::LoadBinding { binding_id: 0 });

        let json = serde_json::to_string(&ir1).unwrap();
        let restored: Ir1Module = serde_json::from_str(&json).unwrap();
        assert_eq!(ir1, restored);
    }

    #[test]
    fn ir1_scope_kinds_as_str() {
        assert_eq!(ScopeKind::Global.as_str(), "global");
        assert_eq!(ScopeKind::Module.as_str(), "module");
        assert_eq!(ScopeKind::Function.as_str(), "function");
        assert_eq!(ScopeKind::Block.as_str(), "block");
        assert_eq!(ScopeKind::Catch.as_str(), "catch");
    }

    #[test]
    fn ir1_binding_kinds_as_str() {
        assert_eq!(BindingKind::Let.as_str(), "let");
        assert_eq!(BindingKind::Const.as_str(), "const");
        assert_eq!(BindingKind::Var.as_str(), "var");
        assert_eq!(BindingKind::Parameter.as_str(), "parameter");
        assert_eq!(BindingKind::Import.as_str(), "import");
        assert_eq!(BindingKind::FunctionDecl.as_str(), "function_decl");
    }

    #[test]
    fn ir1_all_ops_canonical() {
        let ops = vec![
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("hello".to_string()),
            },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(42),
            },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Boolean(true),
            },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Null,
            },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            },
            Ir1Op::LoadBinding { binding_id: 0 },
            Ir1Op::StoreBinding { binding_id: 1 },
            Ir1Op::Call { arg_count: 2 },
            Ir1Op::Return,
            Ir1Op::ImportModule {
                specifier: "mod".to_string(),
            },
            Ir1Op::ExportBinding {
                name: "x".to_string(),
                binding_id: 0,
            },
            Ir1Op::Await,
            Ir1Op::Nop,
        ];
        for op in &ops {
            let cv = op.canonical_value();
            assert!(matches!(cv, CanonicalValue::Map(_)));
        }
    }

    // -- IR2 --

    #[test]
    fn ir2_construction() {
        let source_hash = ContentHash::compute(b"test");
        let ir2 = Ir2Module::new(source_hash, "test.js");
        assert_eq!(ir2.header.level, IrLevel::Ir2);
    }

    #[test]
    fn ir2_capability_annotation() {
        let source_hash = ContentHash::compute(b"test");
        let mut ir2 = Ir2Module::new(source_hash, "test.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Call { arg_count: 1 },
            effect: EffectBoundary::HostcallEffect,
            required_capability: Some(CapabilityTag("fs:read".to_string())),
            flow: Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: false,
            }),
        });
        ir2.required_capabilities
            .push(CapabilityTag("fs:read".to_string()));

        assert_eq!(ir2.required_capabilities.len(), 1);
        assert_eq!(ir2.ops[0].effect, EffectBoundary::HostcallEffect);
    }

    #[test]
    fn ir2_canonical_deterministic() {
        let source_hash = ContentHash::compute(b"test");
        let make_ir2 = || {
            let mut ir2 = Ir2Module::new(source_hash.clone(), "test.js");
            ir2.ops.push(Ir2Op {
                inner: Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(42),
                },
                effect: EffectBoundary::Pure,
                required_capability: None,
                flow: None,
            });
            ir2
        };
        assert_eq!(make_ir2().canonical_bytes(), make_ir2().canonical_bytes());
    }

    #[test]
    fn ir2_serde_roundtrip() {
        let source_hash = ContentHash::compute(b"test");
        let mut ir2 = Ir2Module::new(source_hash, "test.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Nop,
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        let json = serde_json::to_string(&ir2).unwrap();
        let restored: Ir2Module = serde_json::from_str(&json).unwrap();
        assert_eq!(ir2, restored);
    }

    #[test]
    fn effect_boundary_as_str() {
        assert_eq!(EffectBoundary::Pure.as_str(), "pure");
        assert_eq!(EffectBoundary::ReadEffect.as_str(), "read");
        assert_eq!(EffectBoundary::WriteEffect.as_str(), "write");
        assert_eq!(EffectBoundary::NetworkEffect.as_str(), "network");
        assert_eq!(EffectBoundary::FsEffect.as_str(), "fs");
        assert_eq!(EffectBoundary::HostcallEffect.as_str(), "hostcall");
    }

    // -- IR3 --

    #[test]
    fn ir3_construction() {
        let source_hash = ContentHash::compute(b"test");
        let ir3 = Ir3Module::new(source_hash, "test.js");
        assert_eq!(ir3.header.level, IrLevel::Ir3);
        assert!(ir3.specialization.is_none());
    }

    #[test]
    fn ir3_with_instructions_canonical_deterministic() {
        let source_hash = ContentHash::compute(b"test");
        let make_ir3 = || {
            let mut ir3 = Ir3Module::new(source_hash.clone(), "test.js");
            ir3.instructions
                .push(Ir3Instruction::LoadInt { dst: 0, value: 42 });
            ir3.instructions
                .push(Ir3Instruction::LoadInt { dst: 1, value: 10 });
            ir3.instructions.push(Ir3Instruction::Add {
                dst: 2,
                lhs: 0,
                rhs: 1,
            });
            ir3.instructions.push(Ir3Instruction::Return { value: 2 });
            ir3.function_table.push(Ir3FunctionDesc {
                entry: 0,
                arity: 0,
                frame_size: 3,
                name: Some("main".to_string()),
            });
            ir3
        };
        assert_eq!(make_ir3().canonical_bytes(), make_ir3().canonical_bytes());
        assert_eq!(make_ir3().content_hash(), make_ir3().content_hash());
    }

    #[test]
    fn ir3_with_specialization() {
        let source_hash = ContentHash::compute(b"test");
        let mut ir3 = Ir3Module::new(source_hash, "test.js");
        ir3.specialization = Some(SpecializationLinkage {
            proof_input_ids: vec!["proof-1".to_string()],
            optimization_class: "hostcall_dispatch".to_string(),
            validity_epoch: 42,
            rollback_token: ContentHash::compute(b"baseline"),
        });
        let json = serde_json::to_string(&ir3).unwrap();
        let restored: Ir3Module = serde_json::from_str(&json).unwrap();
        assert_eq!(ir3, restored);
    }

    #[test]
    fn ir3_all_instruction_types_canonical() {
        let instructions = vec![
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::LoadBool {
                dst: 0,
                value: true,
            },
            Ir3Instruction::LoadNull { dst: 0 },
            Ir3Instruction::LoadUndefined { dst: 0 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Sub {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Mul {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Div {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Move { dst: 0, src: 1 },
            Ir3Instruction::Jump { target: 0 },
            Ir3Instruction::JumpIf { cond: 0, target: 1 },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("net:connect".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::Halt,
        ];
        for instr in &instructions {
            let cv = instr.canonical_value();
            assert!(matches!(cv, CanonicalValue::Map(_)));
        }
    }

    #[test]
    fn ir3_serde_roundtrip() {
        let source_hash = ContentHash::compute(b"test");
        let mut ir3 = Ir3Module::new(source_hash, "test.js");
        ir3.instructions
            .push(Ir3Instruction::LoadInt { dst: 0, value: 42 });
        ir3.instructions.push(Ir3Instruction::Halt);
        ir3.constant_pool.push("hello".to_string());
        ir3.required_capabilities
            .push(CapabilityTag("fs:read".to_string()));
        let json = serde_json::to_string(&ir3).unwrap();
        let restored: Ir3Module = serde_json::from_str(&json).unwrap();
        assert_eq!(ir3, restored);
    }

    // -- IR4 --

    #[test]
    fn ir4_construction() {
        let ir3_hash = ContentHash::compute(b"ir3");
        let ir4 = Ir4Module::new(ir3_hash.clone(), "test.js");
        assert_eq!(ir4.header.level, IrLevel::Ir4);
        assert_eq!(ir4.executed_ir3_hash, ir3_hash);
        assert_eq!(ir4.outcome, ExecutionOutcome::Completed);
    }

    #[test]
    fn ir4_with_events_canonical_deterministic() {
        let ir3_hash = ContentHash::compute(b"ir3");
        let make_ir4 = || {
            let mut ir4 = Ir4Module::new(ir3_hash.clone(), "test.js");
            ir4.events.push(WitnessEvent {
                seq: 0,
                kind: WitnessEventKind::HostcallDispatched,
                instruction_index: 5,
                payload_hash: ContentHash::compute(b"payload"),
                timestamp_tick: 100,
            });
            ir4.hostcall_decisions.push(HostcallDecisionRecord {
                seq: 0,
                capability: CapabilityTag("fs:read".to_string()),
                allowed: true,
                instruction_index: 5,
            });
            ir4.instructions_executed = 10;
            ir4.duration_ticks = 200;
            ir4
        };
        assert_eq!(make_ir4().canonical_bytes(), make_ir4().canonical_bytes());
        assert_eq!(make_ir4().content_hash(), make_ir4().content_hash());
    }

    #[test]
    fn ir4_serde_roundtrip() {
        let ir3_hash = ContentHash::compute(b"ir3");
        let mut ir4 = Ir4Module::new(ir3_hash, "test.js");
        ir4.outcome = ExecutionOutcome::Exception;
        ir4.active_specialization_ids.push("spec-1".to_string());
        let json = serde_json::to_string(&ir4).unwrap();
        let restored: Ir4Module = serde_json::from_str(&json).unwrap();
        assert_eq!(ir4, restored);
    }

    #[test]
    fn execution_outcome_as_str() {
        assert_eq!(ExecutionOutcome::Completed.as_str(), "completed");
        assert_eq!(ExecutionOutcome::Exception.as_str(), "exception");
        assert_eq!(ExecutionOutcome::Timeout.as_str(), "timeout");
        assert_eq!(ExecutionOutcome::Halted.as_str(), "halted");
    }

    #[test]
    fn witness_event_kind_as_str() {
        assert_eq!(
            WitnessEventKind::HostcallDispatched.as_str(),
            "hostcall_dispatched"
        );
        assert_eq!(
            WitnessEventKind::CapabilityChecked.as_str(),
            "capability_checked"
        );
        assert_eq!(
            WitnessEventKind::ExceptionRaised.as_str(),
            "exception_raised"
        );
        assert_eq!(WitnessEventKind::GcTriggered.as_str(), "gc_triggered");
        assert_eq!(
            WitnessEventKind::ExecutionCompleted.as_str(),
            "execution_completed"
        );
        assert_eq!(
            WitnessEventKind::FlowLabelChecked.as_str(),
            "flow_label_checked"
        );
        assert_eq!(
            WitnessEventKind::DeclassificationRequested.as_str(),
            "declassification_requested"
        );
    }

    // -- Verification --

    #[test]
    fn verify_ir0_hash_passes_for_matching() {
        let tree = make_syntax_tree();
        let ir0 = Ir0Module::from_syntax_tree(tree, "test.js");
        let hash = ir0.content_hash();
        assert!(verify_ir0_hash(&ir0, &hash).is_ok());
    }

    #[test]
    fn verify_ir0_hash_fails_for_mismatch() {
        let tree = make_syntax_tree();
        let ir0 = Ir0Module::from_syntax_tree(tree, "test.js");
        let wrong_hash = ContentHash::compute(b"wrong");
        let err = verify_ir0_hash(&ir0, &wrong_hash).unwrap_err();
        assert_eq!(err.code, IrErrorCode::HashVerificationFailed);
    }

    #[test]
    fn verify_ir1_source_passes() {
        let ir0_hash = ContentHash::compute(b"ir0");
        let ir1 = Ir1Module::new(ir0_hash.clone(), "test.js");
        assert!(verify_ir1_source(&ir1, &ir0_hash).is_ok());
    }

    #[test]
    fn verify_ir1_source_fails_mismatch() {
        let ir0_hash = ContentHash::compute(b"ir0");
        let ir1 = Ir1Module::new(ir0_hash.clone(), "test.js");
        let wrong_hash = ContentHash::compute(b"wrong");
        let err = verify_ir1_source(&ir1, &wrong_hash).unwrap_err();
        assert_eq!(err.code, IrErrorCode::SourceHashMismatch);
    }

    #[test]
    fn verify_ir3_specialization_passes_for_none() {
        let source_hash = ContentHash::compute(b"test");
        let ir3 = Ir3Module::new(source_hash, "test.js");
        assert!(verify_ir3_specialization(&ir3).is_ok());
    }

    #[test]
    fn verify_ir3_specialization_passes_for_valid() {
        let source_hash = ContentHash::compute(b"test");
        let mut ir3 = Ir3Module::new(source_hash, "test.js");
        ir3.specialization = Some(SpecializationLinkage {
            proof_input_ids: vec!["proof-1".to_string()],
            optimization_class: "hostcall_dispatch".to_string(),
            validity_epoch: 1,
            rollback_token: ContentHash::compute(b"baseline"),
        });
        assert!(verify_ir3_specialization(&ir3).is_ok());
    }

    #[test]
    fn verify_ir3_specialization_fails_empty_proofs() {
        let source_hash = ContentHash::compute(b"test");
        let mut ir3 = Ir3Module::new(source_hash, "test.js");
        ir3.specialization = Some(SpecializationLinkage {
            proof_input_ids: vec![],
            optimization_class: "hostcall_dispatch".to_string(),
            validity_epoch: 1,
            rollback_token: ContentHash::compute(b"baseline"),
        });
        let err = verify_ir3_specialization(&ir3).unwrap_err();
        assert_eq!(err.code, IrErrorCode::InvalidSpecializationLinkage);
    }

    #[test]
    fn verify_ir3_specialization_fails_empty_class() {
        let source_hash = ContentHash::compute(b"test");
        let mut ir3 = Ir3Module::new(source_hash, "test.js");
        ir3.specialization = Some(SpecializationLinkage {
            proof_input_ids: vec!["proof-1".to_string()],
            optimization_class: String::new(),
            validity_epoch: 1,
            rollback_token: ContentHash::compute(b"baseline"),
        });
        let err = verify_ir3_specialization(&ir3).unwrap_err();
        assert_eq!(err.code, IrErrorCode::InvalidSpecializationLinkage);
    }

    #[test]
    fn verify_ir4_linkage_passes() {
        let ir3_hash = ContentHash::compute(b"ir3");
        let mut ir4 = Ir4Module::new(ir3_hash.clone(), "test.js");
        ir4.events.push(WitnessEvent {
            seq: 0,
            kind: WitnessEventKind::ExecutionCompleted,
            instruction_index: 0,
            payload_hash: ContentHash::compute(b"done"),
            timestamp_tick: 100,
        });
        assert!(verify_ir4_linkage(&ir4, &ir3_hash).is_ok());
    }

    #[test]
    fn verify_ir4_linkage_fails_wrong_hash() {
        let ir3_hash = ContentHash::compute(b"ir3");
        let ir4 = Ir4Module::new(ir3_hash, "test.js");
        let wrong_hash = ContentHash::compute(b"wrong");
        let err = verify_ir4_linkage(&ir4, &wrong_hash).unwrap_err();
        assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);
    }

    #[test]
    fn verify_ir4_linkage_fails_non_monotonic_events() {
        let ir3_hash = ContentHash::compute(b"ir3");
        let mut ir4 = Ir4Module::new(ir3_hash.clone(), "test.js");
        ir4.events.push(WitnessEvent {
            seq: 1,
            kind: WitnessEventKind::HostcallDispatched,
            instruction_index: 0,
            payload_hash: ContentHash::compute(b"a"),
            timestamp_tick: 100,
        });
        ir4.events.push(WitnessEvent {
            seq: 0, // non-monotonic
            kind: WitnessEventKind::CapabilityChecked,
            instruction_index: 1,
            payload_hash: ContentHash::compute(b"b"),
            timestamp_tick: 200,
        });
        let err = verify_ir4_linkage(&ir4, &ir3_hash).unwrap_err();
        assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);
    }

    // -- Error types --

    #[test]
    fn ir_error_display() {
        let err = IrError::new(
            IrErrorCode::SchemaVersionMismatch,
            "expected 0.1.0, got 0.2.0",
            IrLevel::Ir1,
        );
        let display = err.to_string();
        assert!(display.contains("ir1"));
        assert!(display.contains("IR_SCHEMA_VERSION_MISMATCH"));
    }

    #[test]
    fn ir_error_code_as_str() {
        assert_eq!(
            IrErrorCode::SchemaVersionMismatch.as_str(),
            "IR_SCHEMA_VERSION_MISMATCH"
        );
        assert_eq!(IrErrorCode::LevelMismatch.as_str(), "IR_LEVEL_MISMATCH");
        assert_eq!(
            IrErrorCode::SourceHashMismatch.as_str(),
            "IR_SOURCE_HASH_MISMATCH"
        );
        assert_eq!(
            IrErrorCode::HashVerificationFailed.as_str(),
            "IR_HASH_VERIFICATION_FAILED"
        );
        assert_eq!(
            IrErrorCode::MissingCapabilityAnnotation.as_str(),
            "IR_MISSING_CAPABILITY_ANNOTATION"
        );
        assert_eq!(
            IrErrorCode::InvalidSpecializationLinkage.as_str(),
            "IR_INVALID_SPECIALIZATION_LINKAGE"
        );
        assert_eq!(
            IrErrorCode::WitnessIntegrityViolation.as_str(),
            "IR_WITNESS_INTEGRITY_VIOLATION"
        );
    }

    #[test]
    fn ir_error_serde_roundtrip() {
        let err = IrError::new(IrErrorCode::SourceHashMismatch, "test error", IrLevel::Ir2);
        let json = serde_json::to_string(&err).unwrap();
        let restored: IrError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    // -- Full pipeline hash chain --

    #[test]
    fn full_pipeline_hash_chain() {
        // IR0
        let tree = make_syntax_tree();
        let ir0 = Ir0Module::from_syntax_tree(tree, "test.js");
        let ir0_hash = ir0.content_hash();

        // IR1 references IR0
        let mut ir1 = Ir1Module::new(ir0_hash.clone(), "test.js");
        ir1.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(42),
        });
        let ir1_hash = ir1.content_hash();
        assert!(verify_ir1_source(&ir1, &ir0_hash).is_ok());

        // IR2 references IR1
        let mut ir2 = Ir2Module::new(ir1_hash.clone(), "test.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(42),
            },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        let ir2_hash = ir2.content_hash();

        // IR3 references IR2
        let mut ir3 = Ir3Module::new(ir2_hash.clone(), "test.js");
        ir3.instructions
            .push(Ir3Instruction::LoadInt { dst: 0, value: 42 });
        ir3.instructions.push(Ir3Instruction::Halt);
        let ir3_hash = ir3.content_hash();
        assert!(verify_ir3_specialization(&ir3).is_ok());

        // IR4 references IR3
        let mut ir4 = Ir4Module::new(ir3_hash.clone(), "test.js");
        ir4.events.push(WitnessEvent {
            seq: 0,
            kind: WitnessEventKind::ExecutionCompleted,
            instruction_index: 1,
            payload_hash: ContentHash::compute(b"result:42"),
            timestamp_tick: 100,
        });
        ir4.instructions_executed = 2;
        ir4.duration_ticks = 100;
        assert!(verify_ir4_linkage(&ir4, &ir3_hash).is_ok());

        // Hashes are all distinct
        assert_ne!(ir0_hash, ir1_hash);
        assert_ne!(ir1_hash, ir2_hash);
        assert_ne!(ir2_hash, ir3_hash);
        let ir4_hash = ir4.content_hash();
        assert_ne!(ir3_hash, ir4_hash);
    }

    // -- Determinism across runs --

    #[test]
    fn all_levels_deterministic_across_runs() {
        for _ in 0..3 {
            let tree = make_syntax_tree();
            let ir0 = Ir0Module::from_syntax_tree(tree, "det.js");
            let hash0 = ir0.content_hash();

            let mut ir1 = Ir1Module::new(hash0.clone(), "det.js");
            ir1.ops.push(Ir1Op::Nop);
            let hash1 = ir1.content_hash();

            let ir2 = Ir2Module::new(hash1.clone(), "det.js");
            let hash2 = ir2.content_hash();

            let ir3 = Ir3Module::new(hash2.clone(), "det.js");
            let hash3 = ir3.content_hash();

            let ir4 = Ir4Module::new(hash3, "det.js");
            let hash4 = ir4.content_hash();

            // These are computed fresh each iteration; determinism means
            // identical results each time. We verify by collecting into
            // a set-like check.
            assert_eq!(
                hash0,
                Ir0Module::from_syntax_tree(make_syntax_tree(), "det.js").content_hash()
            );
            assert_ne!(hash0, hash4);
        }
    }

    // -- Structured events --

    #[test]
    fn verifier_emits_ok_events_on_success() {
        let tree = make_syntax_tree();
        let ir0 = Ir0Module::from_syntax_tree(tree, "ev.js");
        let ir0_hash = ir0.content_hash();

        let mut verifier = IrVerifier::new();
        verifier.verify_ir0(&ir0, &ir0_hash, "t-1").unwrap();

        let ir1 = Ir1Module::new(ir0_hash.clone(), "ev.js");
        verifier.verify_ir1(&ir1, &ir0_hash, "t-1").unwrap();

        let ir3 = Ir3Module::new(ContentHash::compute(b"ir2"), "ev.js");
        verifier.verify_ir3(&ir3, "t-1").unwrap();

        let ir3_hash = ir3.content_hash();
        let ir4 = Ir4Module::new(ir3_hash.clone(), "ev.js");
        verifier.verify_ir4(&ir4, &ir3_hash, "t-1").unwrap();

        let events = verifier.drain_events();
        assert_eq!(events.len(), 4);
        assert!(events.iter().all(|e| e.outcome == "ok"));
        assert!(events.iter().all(|e| e.component == "ir_contract"));
        assert!(events.iter().all(|e| e.trace_id == "t-1"));
        assert!(events.iter().all(|e| e.content_hash.is_some()));

        let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
        assert_eq!(event_names[0], "ir0_hash_verified");
        assert_eq!(event_names[1], "ir1_source_verified");
        assert_eq!(event_names[2], "ir3_specialization_verified");
        assert_eq!(event_names[3], "ir4_linkage_verified");
    }

    #[test]
    fn verifier_emits_error_events_on_failure() {
        let tree = make_syntax_tree();
        let ir0 = Ir0Module::from_syntax_tree(tree, "ev.js");
        let wrong_hash = ContentHash::compute(b"wrong");

        let mut verifier = IrVerifier::new();
        let _ = verifier.verify_ir0(&ir0, &wrong_hash, "t-err");

        let events = verifier.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "error");
        assert_eq!(
            events[0].error_code.as_deref(),
            Some("IR_HASH_VERIFICATION_FAILED")
        );
        assert!(events[0].content_hash.is_none());
    }

    #[test]
    fn verifier_event_serde_roundtrip() {
        let tree = make_syntax_tree();
        let ir0 = Ir0Module::from_syntax_tree(tree, "serde.js");
        let ir0_hash = ir0.content_hash();

        let mut verifier = IrVerifier::new();
        verifier.verify_ir0(&ir0, &ir0_hash, "t-serde").unwrap();

        let events = verifier.drain_events();
        let json = serde_json::to_string(&events).unwrap();
        let restored: Vec<IrContractEvent> = serde_json::from_str(&json).unwrap();
        assert_eq!(events, restored);
    }

    // -- error_code function --

    #[test]
    fn error_code_returns_stable_strings() {
        let cases = [
            (
                IrErrorCode::SchemaVersionMismatch,
                "IR_SCHEMA_VERSION_MISMATCH",
            ),
            (IrErrorCode::LevelMismatch, "IR_LEVEL_MISMATCH"),
            (IrErrorCode::SourceHashMismatch, "IR_SOURCE_HASH_MISMATCH"),
            (
                IrErrorCode::HashVerificationFailed,
                "IR_HASH_VERIFICATION_FAILED",
            ),
            (
                IrErrorCode::MissingCapabilityAnnotation,
                "IR_MISSING_CAPABILITY_ANNOTATION",
            ),
            (
                IrErrorCode::InvalidSpecializationLinkage,
                "IR_INVALID_SPECIALIZATION_LINKAGE",
            ),
            (
                IrErrorCode::WitnessIntegrityViolation,
                "IR_WITNESS_INTEGRITY_VIOLATION",
            ),
        ];
        for (code, expected) in &cases {
            let err = IrError::new(*code, "test", IrLevel::Ir0);
            assert_eq!(error_code(&err), *expected);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: leaf enum serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn scope_kind_serde_roundtrip() {
        for kind in [
            ScopeKind::Global,
            ScopeKind::Module,
            ScopeKind::Function,
            ScopeKind::Block,
            ScopeKind::Catch,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let restored: ScopeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn binding_kind_serde_roundtrip() {
        for kind in [
            BindingKind::Let,
            BindingKind::Const,
            BindingKind::Var,
            BindingKind::Parameter,
            BindingKind::Import,
            BindingKind::FunctionDecl,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let restored: BindingKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn effect_boundary_serde_roundtrip() {
        for eb in [
            EffectBoundary::Pure,
            EffectBoundary::ReadEffect,
            EffectBoundary::WriteEffect,
            EffectBoundary::NetworkEffect,
            EffectBoundary::FsEffect,
            EffectBoundary::HostcallEffect,
        ] {
            let json = serde_json::to_string(&eb).unwrap();
            let restored: EffectBoundary = serde_json::from_str(&json).unwrap();
            assert_eq!(eb, restored);
        }
    }

    #[test]
    fn witness_event_kind_serde_roundtrip() {
        for kind in [
            WitnessEventKind::HostcallDispatched,
            WitnessEventKind::CapabilityChecked,
            WitnessEventKind::ExceptionRaised,
            WitnessEventKind::GcTriggered,
            WitnessEventKind::ExecutionCompleted,
            WitnessEventKind::FlowLabelChecked,
            WitnessEventKind::DeclassificationRequested,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let restored: WitnessEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn execution_outcome_serde_roundtrip() {
        for outcome in [
            ExecutionOutcome::Completed,
            ExecutionOutcome::Exception,
            ExecutionOutcome::Timeout,
            ExecutionOutcome::Halted,
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            let restored: ExecutionOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, restored);
        }
    }

    #[test]
    fn ir_error_code_serde_roundtrip() {
        for code in [
            IrErrorCode::SchemaVersionMismatch,
            IrErrorCode::LevelMismatch,
            IrErrorCode::SourceHashMismatch,
            IrErrorCode::HashVerificationFailed,
            IrErrorCode::MissingCapabilityAnnotation,
            IrErrorCode::InvalidSpecializationLinkage,
            IrErrorCode::WitnessIntegrityViolation,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let restored: IrErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, restored);
        }
    }

    #[test]
    fn ir1_literal_serde_roundtrip() {
        for lit in [
            Ir1Literal::String("hello".to_string()),
            Ir1Literal::Integer(i64::MIN),
            Ir1Literal::Integer(0),
            Ir1Literal::Boolean(true),
            Ir1Literal::Boolean(false),
            Ir1Literal::Null,
            Ir1Literal::Undefined,
        ] {
            let json = serde_json::to_string(&lit).unwrap();
            let restored: Ir1Literal = serde_json::from_str(&json).unwrap();
            assert_eq!(lit, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn ir_header_serde_roundtrip() {
        let header = IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir2,
            source_hash: Some(ContentHash::compute(b"src")),
            source_label: "test.js".to_string(),
        };
        let json = serde_json::to_string(&header).unwrap();
        let restored: IrHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(header, restored);

        // Also test with None source_hash
        let header_none = IrHeader {
            source_hash: None,
            ..header
        };
        let json2 = serde_json::to_string(&header_none).unwrap();
        let restored2: IrHeader = serde_json::from_str(&json2).unwrap();
        assert_eq!(header_none, restored2);
    }

    #[test]
    fn flow_annotation_serde_roundtrip() {
        let fa = FlowAnnotation {
            data_label: Label::Internal,
            sink_clearance: Label::Public,
            declassification_required: true,
        };
        let json = serde_json::to_string(&fa).unwrap();
        let restored: FlowAnnotation = serde_json::from_str(&json).unwrap();
        assert_eq!(fa, restored);
    }

    #[test]
    fn reg_range_serde_roundtrip() {
        let rr = RegRange { start: 5, count: 3 };
        let json = serde_json::to_string(&rr).unwrap();
        let restored: RegRange = serde_json::from_str(&json).unwrap();
        assert_eq!(rr, restored);
    }

    #[test]
    fn ir3_function_desc_serde_roundtrip() {
        let desc = Ir3FunctionDesc {
            entry: 10,
            arity: 2,
            frame_size: 8,
            name: Some("myFunc".to_string()),
        };
        let json = serde_json::to_string(&desc).unwrap();
        let restored: Ir3FunctionDesc = serde_json::from_str(&json).unwrap();
        assert_eq!(desc, restored);

        // Test with None name
        let desc_anon = Ir3FunctionDesc { name: None, ..desc };
        let json2 = serde_json::to_string(&desc_anon).unwrap();
        let restored2: Ir3FunctionDesc = serde_json::from_str(&json2).unwrap();
        assert_eq!(desc_anon, restored2);
    }

    #[test]
    fn specialization_linkage_serde_roundtrip() {
        let sl = SpecializationLinkage {
            proof_input_ids: vec!["p1".to_string(), "p2".to_string()],
            optimization_class: "hostcall_dispatch".to_string(),
            validity_epoch: 99,
            rollback_token: ContentHash::compute(b"baseline"),
        };
        let json = serde_json::to_string(&sl).unwrap();
        let restored: SpecializationLinkage = serde_json::from_str(&json).unwrap();
        assert_eq!(sl, restored);
    }

    #[test]
    fn witness_event_serde_roundtrip() {
        let we = WitnessEvent {
            seq: 42,
            kind: WitnessEventKind::FlowLabelChecked,
            instruction_index: 17,
            payload_hash: ContentHash::compute(b"flow_check"),
            timestamp_tick: 5000,
        };
        let json = serde_json::to_string(&we).unwrap();
        let restored: WitnessEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(we, restored);
    }

    #[test]
    fn hostcall_decision_record_serde_roundtrip() {
        let hdr = HostcallDecisionRecord {
            seq: 3,
            capability: CapabilityTag("net:connect".to_string()),
            allowed: false,
            instruction_index: 22,
        };
        let json = serde_json::to_string(&hdr).unwrap();
        let restored: HostcallDecisionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(hdr, restored);
    }

    #[test]
    fn capability_tag_serde_roundtrip() {
        let tag = CapabilityTag("fs:write".to_string());
        let json = serde_json::to_string(&tag).unwrap();
        let restored: CapabilityTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, restored);
    }

    #[test]
    fn ir_contract_event_serde_roundtrip() {
        let ok_event = IrContractEvent {
            trace_id: "t-1".to_string(),
            component: "ir_contract".to_string(),
            event: "ir0_hash_verified".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            level: IrLevel::Ir0,
            content_hash: Some("abcdef".to_string()),
        };
        let json = serde_json::to_string(&ok_event).unwrap();
        let restored: IrContractEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ok_event, restored);

        let err_event = IrContractEvent {
            trace_id: "t-2".to_string(),
            component: "ir_contract".to_string(),
            event: "ir3_specialization_verified".to_string(),
            outcome: "error".to_string(),
            error_code: Some("IR_INVALID_SPECIALIZATION_LINKAGE".to_string()),
            level: IrLevel::Ir3,
            content_hash: None,
        };
        let json2 = serde_json::to_string(&err_event).unwrap();
        let restored2: IrContractEvent = serde_json::from_str(&json2).unwrap();
        assert_eq!(err_event, restored2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display coverage
    // -----------------------------------------------------------------------

    #[test]
    fn ir_level_display_all_variants() {
        assert_eq!(IrLevel::Ir0.to_string(), "ir0");
        assert_eq!(IrLevel::Ir1.to_string(), "ir1");
        assert_eq!(IrLevel::Ir2.to_string(), "ir2");
        assert_eq!(IrLevel::Ir3.to_string(), "ir3");
        assert_eq!(IrLevel::Ir4.to_string(), "ir4");
    }

    #[test]
    fn ir_error_code_display_matches_as_str() {
        for code in [
            IrErrorCode::SchemaVersionMismatch,
            IrErrorCode::LevelMismatch,
            IrErrorCode::SourceHashMismatch,
            IrErrorCode::HashVerificationFailed,
            IrErrorCode::MissingCapabilityAnnotation,
            IrErrorCode::InvalidSpecializationLinkage,
            IrErrorCode::WitnessIntegrityViolation,
        ] {
            assert_eq!(code.to_string(), code.as_str());
        }
    }

    #[test]
    fn ir_error_display_exact_format() {
        let err = IrError::new(
            IrErrorCode::LevelMismatch,
            "expected ir2, got ir3",
            IrLevel::Ir2,
        );
        assert_eq!(
            err.to_string(),
            "[ir2] IR_LEVEL_MISMATCH: expected ir2, got ir3"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: IrVerifier error paths
    // -----------------------------------------------------------------------

    #[test]
    fn verifier_ir1_error_emits_event() {
        let ir0_hash = ContentHash::compute(b"ir0");
        let ir1 = Ir1Module::new(ir0_hash, "test.js");
        let wrong = ContentHash::compute(b"wrong");

        let mut verifier = IrVerifier::new();
        let err = verifier.verify_ir1(&ir1, &wrong, "t-e1").unwrap_err();
        assert_eq!(err.code, IrErrorCode::SourceHashMismatch);

        let events = verifier.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "error");
        assert_eq!(events[0].level, IrLevel::Ir1);
        assert_eq!(
            events[0].error_code.as_deref(),
            Some("IR_SOURCE_HASH_MISMATCH")
        );
    }

    #[test]
    fn verifier_ir3_error_emits_event() {
        let source_hash = ContentHash::compute(b"test");
        let mut ir3 = Ir3Module::new(source_hash, "test.js");
        ir3.specialization = Some(SpecializationLinkage {
            proof_input_ids: vec![],
            optimization_class: "opt".to_string(),
            validity_epoch: 1,
            rollback_token: ContentHash::compute(b"rb"),
        });

        let mut verifier = IrVerifier::new();
        let err = verifier.verify_ir3(&ir3, "t-e3").unwrap_err();
        assert_eq!(err.code, IrErrorCode::InvalidSpecializationLinkage);

        let events = verifier.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "error");
        assert_eq!(events[0].level, IrLevel::Ir3);
        assert_eq!(
            events[0].error_code.as_deref(),
            Some("IR_INVALID_SPECIALIZATION_LINKAGE")
        );
    }

    #[test]
    fn verifier_ir4_error_emits_event() {
        let ir3_hash = ContentHash::compute(b"ir3");
        let ir4 = Ir4Module::new(ir3_hash, "test.js");
        let wrong = ContentHash::compute(b"wrong");

        let mut verifier = IrVerifier::new();
        let err = verifier.verify_ir4(&ir4, &wrong, "t-e4").unwrap_err();
        assert_eq!(err.code, IrErrorCode::WitnessIntegrityViolation);

        let events = verifier.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "error");
        assert_eq!(events[0].level, IrLevel::Ir4);
        assert_eq!(
            events[0].error_code.as_deref(),
            Some("IR_WITNESS_INTEGRITY_VIOLATION")
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: verify_ir1_source None source_hash
    // -----------------------------------------------------------------------

    #[test]
    fn verify_ir1_source_fails_none_source_hash() {
        let ir1 = Ir1Module {
            header: IrHeader {
                schema_version: IrSchemaVersion::CURRENT,
                level: IrLevel::Ir1,
                source_hash: None,
                source_label: "test.js".to_string(),
            },
            scopes: Vec::new(),
            ops: Vec::new(),
        };
        let ir0_hash = ContentHash::compute(b"ir0");
        let err = verify_ir1_source(&ir1, &ir0_hash).unwrap_err();
        assert_eq!(err.code, IrErrorCode::SourceHashMismatch);
        assert!(err.message.contains("missing source_hash"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: IrVerifier Default
    // -----------------------------------------------------------------------

    #[test]
    fn ir_verifier_default() {
        let mut verifier = IrVerifier::default();
        let events = verifier.drain_events();
        assert!(events.is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: Ir1Op all-variant serde
    // -----------------------------------------------------------------------

    #[test]
    fn ir1_op_serde_all_variants() {
        let ops = vec![
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("s".to_string()),
            },
            Ir1Op::LoadBinding { binding_id: 0 },
            Ir1Op::StoreBinding { binding_id: 1 },
            Ir1Op::Call { arg_count: 3 },
            Ir1Op::Return,
            Ir1Op::ImportModule {
                specifier: "m".to_string(),
            },
            Ir1Op::ExportBinding {
                name: "x".to_string(),
                binding_id: 0,
            },
            Ir1Op::Await,
            Ir1Op::Nop,
        ];
        for op in &ops {
            let json = serde_json::to_string(op).unwrap();
            let restored: Ir1Op = serde_json::from_str(&json).unwrap();
            assert_eq!(*op, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: Ir3Instruction all-variant serde
    // -----------------------------------------------------------------------

    #[test]
    fn ir3_instruction_serde_all_variants() {
        let instrs = vec![
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadBool {
                dst: 2,
                value: true,
            },
            Ir3Instruction::LoadNull { dst: 3 },
            Ir3Instruction::LoadUndefined { dst: 4 },
            Ir3Instruction::Add {
                dst: 5,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Sub {
                dst: 5,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Mul {
                dst: 5,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Div {
                dst: 5,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Move { dst: 0, src: 1 },
            Ir3Instruction::Jump { target: 10 },
            Ir3Instruction::JumpIf {
                cond: 0,
                target: 11,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 1, count: 2 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("net:connect".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 0,
                key: 1,
                dst: 2,
            },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::Halt,
        ];
        for instr in &instrs {
            let json = serde_json::to_string(instr).unwrap();
            let restored: Ir3Instruction = serde_json::from_str(&json).unwrap();
            assert_eq!(*instr, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: Ir2Op with flow serde
    // -----------------------------------------------------------------------

    #[test]
    fn ir2_op_with_flow_serde_roundtrip() {
        let op = Ir2Op {
            inner: Ir1Op::Call { arg_count: 1 },
            effect: EffectBoundary::NetworkEffect,
            required_capability: Some(CapabilityTag("net:fetch".to_string())),
            flow: Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Public,
                declassification_required: true,
            }),
        };
        let json = serde_json::to_string(&op).unwrap();
        let restored: Ir2Op = serde_json::from_str(&json).unwrap();
        assert_eq!(op, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScopeNode serde roundtrip (multiple scope kinds)
    // -----------------------------------------------------------------------

    #[test]
    fn scope_node_all_kinds_serde_roundtrip() {
        for kind in [
            ScopeKind::Global,
            ScopeKind::Module,
            ScopeKind::Function,
            ScopeKind::Block,
            ScopeKind::Catch,
        ] {
            let node = ScopeNode {
                scope_id: ScopeId { depth: 1, index: 2 },
                parent: Some(ScopeId { depth: 0, index: 0 }),
                kind,
                bindings: vec![ResolvedBinding {
                    name: "x".to_string(),
                    binding_id: 0,
                    scope: ScopeId { depth: 1, index: 2 },
                    kind: BindingKind::Const,
                }],
            };
            let json = serde_json::to_string(&node).unwrap();
            let restored: ScopeNode = serde_json::from_str(&json).unwrap();
            assert_eq!(node, restored);
        }
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn ir_error_is_std_error() {
        let err = IrError::new(IrErrorCode::SchemaVersionMismatch, "test", IrLevel::Ir0);
        let dyn_err: &dyn std::error::Error = &err;
        assert!(!dyn_err.to_string().is_empty());
    }

    #[test]
    fn ir_error_code_as_str_all_distinct() {
        let codes = [
            IrErrorCode::SchemaVersionMismatch,
            IrErrorCode::LevelMismatch,
            IrErrorCode::SourceHashMismatch,
            IrErrorCode::HashVerificationFailed,
            IrErrorCode::MissingCapabilityAnnotation,
            IrErrorCode::InvalidSpecializationLinkage,
            IrErrorCode::WitnessIntegrityViolation,
        ];
        let mut strs = std::collections::BTreeSet::new();
        for c in &codes {
            strs.insert(c.as_str());
        }
        assert_eq!(strs.len(), codes.len());
    }

    #[test]
    fn ir_level_as_str_all_distinct() {
        let levels = [
            IrLevel::Ir0,
            IrLevel::Ir1,
            IrLevel::Ir2,
            IrLevel::Ir3,
            IrLevel::Ir4,
        ];
        let mut strs = std::collections::BTreeSet::new();
        for l in &levels {
            strs.insert(l.as_str());
        }
        assert_eq!(strs.len(), levels.len());
    }

    #[test]
    fn scope_kind_as_str_all_distinct() {
        let kinds = [
            ScopeKind::Global,
            ScopeKind::Module,
            ScopeKind::Function,
            ScopeKind::Block,
            ScopeKind::Catch,
        ];
        let mut strs = std::collections::BTreeSet::new();
        for k in &kinds {
            strs.insert(k.as_str());
        }
        assert_eq!(strs.len(), kinds.len());
    }

    #[test]
    fn binding_kind_as_str_all_distinct() {
        let kinds = [
            BindingKind::Let,
            BindingKind::Const,
            BindingKind::Var,
            BindingKind::Parameter,
            BindingKind::Import,
            BindingKind::FunctionDecl,
        ];
        let mut strs = std::collections::BTreeSet::new();
        for k in &kinds {
            strs.insert(k.as_str());
        }
        assert_eq!(strs.len(), kinds.len());
    }

    #[test]
    fn effect_boundary_as_str_all_distinct() {
        let effects = [
            EffectBoundary::Pure,
            EffectBoundary::ReadEffect,
            EffectBoundary::WriteEffect,
            EffectBoundary::NetworkEffect,
            EffectBoundary::FsEffect,
        ];
        let mut strs = std::collections::BTreeSet::new();
        for e in &effects {
            strs.insert(e.as_str());
        }
        assert_eq!(strs.len(), effects.len());
    }

    #[test]
    fn witness_event_kind_all_distinct_as_str() {
        let kinds = [
            WitnessEventKind::HostcallDispatched,
            WitnessEventKind::CapabilityChecked,
            WitnessEventKind::ExceptionRaised,
            WitnessEventKind::GcTriggered,
            WitnessEventKind::ExecutionCompleted,
            WitnessEventKind::FlowLabelChecked,
            WitnessEventKind::DeclassificationRequested,
        ];
        let mut strs = std::collections::BTreeSet::new();
        for k in &kinds {
            strs.insert(k.as_str());
        }
        assert_eq!(strs.len(), kinds.len());
    }

    #[test]
    fn execution_outcome_as_str_all_distinct() {
        let outcomes = [
            ExecutionOutcome::Completed,
            ExecutionOutcome::Exception,
            ExecutionOutcome::Timeout,
            ExecutionOutcome::Halted,
        ];
        let mut strs = std::collections::BTreeSet::new();
        for o in &outcomes {
            strs.insert(o.as_str());
        }
        assert_eq!(strs.len(), outcomes.len());
    }

    #[test]
    fn capability_tag_serde_preserves_value() {
        let tag = CapabilityTag("net:fetch".to_string());
        let json = serde_json::to_string(&tag).unwrap();
        let back: CapabilityTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag.0, back.0);
    }

    #[test]
    fn witness_event_canonical_value_deterministic() {
        let event = WitnessEvent {
            seq: 1,
            kind: WitnessEventKind::HostcallDispatched,
            instruction_index: InstrIndex::from(42u32),
            payload_hash: ContentHash::compute(b"payload"),
            timestamp_tick: 100,
        };
        let cv1 = event.canonical_value();
        let cv2 = event.canonical_value();
        assert_eq!(cv1, cv2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-02-26 session 2
    // -----------------------------------------------------------------------

    #[test]
    fn schema_version_current_value() {
        let v = IrSchemaVersion::CURRENT;
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 1);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn reg_range_canonical_value_content() {
        let rr = RegRange { start: 7, count: 3 };
        let cv = rr.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(m.get("start"), Some(&CanonicalValue::U64(7)));
            assert_eq!(m.get("count"), Some(&CanonicalValue::U64(3)));
            assert_eq!(m.len(), 2);
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn ir3_function_desc_canonical_value_with_name() {
        let desc = Ir3FunctionDesc {
            entry: 10,
            arity: 2,
            frame_size: 8,
            name: Some("main".to_string()),
        };
        let cv = desc.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(m.get("entry"), Some(&CanonicalValue::U64(10)));
            assert_eq!(m.get("arity"), Some(&CanonicalValue::U64(2)));
            assert_eq!(m.get("frame_size"), Some(&CanonicalValue::U64(8)));
            assert_eq!(
                m.get("name"),
                Some(&CanonicalValue::String("main".to_string()))
            );
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn ir3_function_desc_canonical_value_none_name_is_null() {
        let desc = Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 4,
            name: None,
        };
        let cv = desc.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(m.get("name"), Some(&CanonicalValue::Null));
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn specialization_linkage_canonical_value_content() {
        let sl = SpecializationLinkage {
            proof_input_ids: vec!["p1".to_string(), "p2".to_string()],
            optimization_class: "hoist".to_string(),
            validity_epoch: 42,
            rollback_token: ContentHash::compute(b"rb"),
        };
        let cv = sl.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(
                m.get("optimization_class"),
                Some(&CanonicalValue::String("hoist".to_string()))
            );
            assert_eq!(m.get("validity_epoch"), Some(&CanonicalValue::U64(42)));
            if let Some(CanonicalValue::Array(ids)) = m.get("proof_input_ids") {
                assert_eq!(ids.len(), 2);
                assert_eq!(ids[0], CanonicalValue::String("p1".to_string()));
                assert_eq!(ids[1], CanonicalValue::String("p2".to_string()));
            } else {
                panic!("expected proof_input_ids Array");
            }
            assert!(m.contains_key("rollback_token"));
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn hostcall_decision_record_canonical_value_content() {
        let hdr = HostcallDecisionRecord {
            seq: 5,
            capability: CapabilityTag("fs:read".to_string()),
            allowed: false,
            instruction_index: 20,
        };
        let cv = hdr.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(m.get("seq"), Some(&CanonicalValue::U64(5)));
            assert_eq!(m.get("allowed"), Some(&CanonicalValue::Bool(false)));
            assert_eq!(m.get("instruction_index"), Some(&CanonicalValue::U64(20)));
            assert!(m.contains_key("capability"));
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn ir3_instruction_canonical_op_strings() {
        let cases: Vec<(Ir3Instruction, &str)> = vec![
            (Ir3Instruction::LoadInt { dst: 0, value: 1 }, "load_int"),
            (
                Ir3Instruction::LoadStr {
                    dst: 0,
                    pool_index: 0,
                },
                "load_str",
            ),
            (
                Ir3Instruction::LoadBool {
                    dst: 0,
                    value: true,
                },
                "load_bool",
            ),
            (Ir3Instruction::LoadNull { dst: 0 }, "load_null"),
            (Ir3Instruction::LoadUndefined { dst: 0 }, "load_undefined"),
            (
                Ir3Instruction::Add {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
                "add",
            ),
            (
                Ir3Instruction::Sub {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
                "sub",
            ),
            (
                Ir3Instruction::Mul {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
                "mul",
            ),
            (
                Ir3Instruction::Div {
                    dst: 0,
                    lhs: 1,
                    rhs: 2,
                },
                "div",
            ),
            (Ir3Instruction::Move { dst: 0, src: 1 }, "move"),
            (Ir3Instruction::Jump { target: 0 }, "jump"),
            (Ir3Instruction::JumpIf { cond: 0, target: 1 }, "jump_if"),
            (
                Ir3Instruction::Call {
                    callee: 0,
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                "call",
            ),
            (Ir3Instruction::Return { value: 0 }, "return"),
            (
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("x".to_string()),
                    args: RegRange { start: 0, count: 0 },
                    dst: 1,
                },
                "hostcall",
            ),
            (
                Ir3Instruction::GetProperty {
                    obj: 0,
                    key: 1,
                    dst: 2,
                },
                "get_property",
            ),
            (
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 1,
                    val: 2,
                },
                "set_property",
            ),
            (Ir3Instruction::Halt, "halt"),
        ];
        for (instr, expected_op) in &cases {
            let cv = instr.canonical_value();
            if let CanonicalValue::Map(m) = cv {
                assert_eq!(
                    m.get("op"),
                    Some(&CanonicalValue::String(expected_op.to_string())),
                    "op mismatch for {:?}",
                    instr,
                );
            } else {
                panic!("expected Map for {:?}", instr);
            }
        }
    }

    #[test]
    fn ir4_new_defaults() {
        let ir3_hash = ContentHash::compute(b"ir3");
        let ir4 = Ir4Module::new(ir3_hash.clone(), "defaults.js");
        assert_eq!(ir4.outcome, ExecutionOutcome::Completed);
        assert!(ir4.events.is_empty());
        assert!(ir4.hostcall_decisions.is_empty());
        assert_eq!(ir4.instructions_executed, 0);
        assert_eq!(ir4.duration_ticks, 0);
        assert!(ir4.active_specialization_ids.is_empty());
        assert_eq!(ir4.executed_ir3_hash, ir3_hash);
    }

    #[test]
    fn ir1_content_hash_changes_with_ops() {
        let src = ContentHash::compute(b"src");
        let ir1a = Ir1Module::new(src.clone(), "a.js");
        let mut ir1b = Ir1Module::new(src, "a.js");
        ir1b.ops.push(Ir1Op::Nop);
        assert_ne!(ir1a.content_hash(), ir1b.content_hash());
    }

    #[test]
    fn ir3_content_hash_changes_with_instructions() {
        let src = ContentHash::compute(b"src");
        let ir3a = Ir3Module::new(src.clone(), "a.js");
        let mut ir3b = Ir3Module::new(src, "a.js");
        ir3b.instructions.push(Ir3Instruction::Halt);
        assert_ne!(ir3a.content_hash(), ir3b.content_hash());
    }

    #[test]
    fn ir4_content_hash_changes_with_outcome() {
        let ir3_hash = ContentHash::compute(b"ir3");
        let ir4a = Ir4Module::new(ir3_hash.clone(), "a.js");
        let mut ir4b = Ir4Module::new(ir3_hash, "a.js");
        ir4b.outcome = ExecutionOutcome::Timeout;
        assert_ne!(ir4a.content_hash(), ir4b.content_hash());
    }

    #[test]
    fn verifier_drain_events_clears_state() {
        let tree = make_syntax_tree();
        let ir0 = Ir0Module::from_syntax_tree(tree, "drain.js");
        let hash = ir0.content_hash();

        let mut verifier = IrVerifier::new();
        verifier.verify_ir0(&ir0, &hash, "t-drain").unwrap();
        assert_eq!(verifier.drain_events().len(), 1);
        // Second drain is empty
        assert!(verifier.drain_events().is_empty());
    }

    #[test]
    fn ir_header_canonical_value_content() {
        let header = IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir2,
            source_hash: Some(ContentHash::compute(b"src")),
            source_label: "test.js".to_string(),
        };
        let cv = header.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(
                m.get("source_label"),
                Some(&CanonicalValue::String("test.js".to_string()))
            );
            assert_eq!(
                m.get("level"),
                Some(&CanonicalValue::String("ir2".to_string()))
            );
            assert!(m.contains_key("schema_version"));
            assert!(m.contains_key("source_hash"));
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn ir_header_canonical_value_none_source_hash_is_null() {
        let header = IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir0,
            source_hash: None,
            source_label: "test.js".to_string(),
        };
        let cv = header.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(m.get("source_hash"), Some(&CanonicalValue::Null));
        } else {
            panic!("expected Map");
        }
    }

    // -- Enrichment: serde roundtrip for untested types (PearlTower 2026-02-27) --

    #[test]
    fn resolved_binding_serde_roundtrip() {
        let b = ResolvedBinding {
            name: "myVar".to_string(),
            binding_id: 42,
            scope: ScopeId { depth: 1, index: 0 },
            kind: BindingKind::Let,
        };
        let json = serde_json::to_string(&b).unwrap();
        let back: ResolvedBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn resolved_binding_all_kinds_serde_roundtrip() {
        let kinds = [
            BindingKind::Let,
            BindingKind::Const,
            BindingKind::Var,
            BindingKind::Parameter,
            BindingKind::Import,
            BindingKind::FunctionDecl,
        ];
        for (i, kind) in kinds.iter().enumerate() {
            let b = ResolvedBinding {
                name: format!("binding_{i}"),
                binding_id: i as u32,
                scope: ScopeId {
                    depth: 0,
                    index: i as u32,
                },
                kind: *kind,
            };
            let json = serde_json::to_string(&b).unwrap();
            let back: ResolvedBinding = serde_json::from_str(&json).unwrap();
            assert_eq!(b, back);
        }
        assert_eq!(kinds.len(), 6);
    }

    // -- Enrichment: PearlTower 2026-02-26 session 7 --

    #[test]
    fn scope_id_canonical_value_content() {
        let sid = ScopeId { depth: 3, index: 7 };
        let cv = sid.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(m.get("depth"), Some(&CanonicalValue::U64(3)));
            assert_eq!(m.get("index"), Some(&CanonicalValue::U64(7)));
            assert_eq!(m.len(), 2);
        } else {
            panic!("expected Map from ScopeId::canonical_value");
        }
    }

    #[test]
    fn ir1_literal_canonical_value_all_variants() {
        let cases: Vec<(Ir1Literal, &str)> = vec![
            (Ir1Literal::String("hello".to_string()), "string"),
            (Ir1Literal::Integer(42), "integer"),
            (Ir1Literal::Boolean(false), "boolean"),
            (Ir1Literal::Null, "null"),
            (Ir1Literal::Undefined, "undefined"),
        ];
        for (lit, expected_kind) in &cases {
            let cv = lit.canonical_value();
            if let CanonicalValue::Map(m) = cv {
                assert_eq!(
                    m.get("kind"),
                    Some(&CanonicalValue::String(expected_kind.to_string())),
                    "kind mismatch for {:?}",
                    lit,
                );
            } else {
                panic!("expected Map for {:?}", lit);
            }
        }
    }

    #[test]
    fn ir2_op_canonical_value_with_flow() {
        let op = Ir2Op {
            inner: Ir1Op::Call { arg_count: 2 },
            effect: EffectBoundary::NetworkEffect,
            required_capability: Some(CapabilityTag("net:outbound".to_string())),
            flow: Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: true,
            }),
        };
        let cv = op.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(
                m.get("effect"),
                Some(&CanonicalValue::String("network".to_string()))
            );
            assert!(
                !matches!(m.get("flow"), Some(CanonicalValue::Null)),
                "flow should not be Null when present"
            );
            assert!(
                !matches!(m.get("required_capability"), Some(CanonicalValue::Null)),
                "required_capability should not be Null when present"
            );
            assert!(m.contains_key("inner"));
        } else {
            panic!("expected Map from Ir2Op::canonical_value");
        }
    }

    #[test]
    fn ir2_module_content_hash_changes_with_ops() {
        let src = ContentHash::compute(b"src");
        let ir2a = Ir2Module::new(src.clone(), "a.js");
        let mut ir2b = Ir2Module::new(src, "a.js");
        ir2b.ops.push(Ir2Op {
            inner: Ir1Op::Nop,
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        assert_ne!(ir2a.content_hash(), ir2b.content_hash());
    }

    #[test]
    fn ir3_function_desc_canonical_value_content() {
        let desc = Ir3FunctionDesc {
            entry: 10,
            arity: 3,
            frame_size: 8,
            name: Some("myFunc".to_string()),
        };
        let cv = desc.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(m.get("entry"), Some(&CanonicalValue::U64(10)));
            assert_eq!(m.get("arity"), Some(&CanonicalValue::U64(3)));
            assert_eq!(m.get("frame_size"), Some(&CanonicalValue::U64(8)));
            assert_eq!(
                m.get("name"),
                Some(&CanonicalValue::String("myFunc".to_string()))
            );
        } else {
            panic!("expected Map from Ir3FunctionDesc::canonical_value");
        }
    }

    #[test]
    fn ir3_function_desc_canonical_value_no_name() {
        let desc = Ir3FunctionDesc {
            entry: 0,
            arity: 0,
            frame_size: 1,
            name: None,
        };
        let cv = desc.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(m.get("name"), Some(&CanonicalValue::Null));
        } else {
            panic!("expected Map from Ir3FunctionDesc::canonical_value");
        }
    }

    #[test]
    fn resolved_binding_canonical_value_content() {
        let binding = ResolvedBinding {
            name: "counter".to_string(),
            binding_id: 5,
            scope: ScopeId { depth: 1, index: 2 },
            kind: BindingKind::Const,
        };
        let cv = binding.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(
                m.get("name"),
                Some(&CanonicalValue::String("counter".to_string()))
            );
            assert_eq!(m.get("binding_id"), Some(&CanonicalValue::U64(5)));
            assert_eq!(
                m.get("kind"),
                Some(&CanonicalValue::String("const".to_string()))
            );
            // scope is a nested Map
            assert!(matches!(m.get("scope"), Some(CanonicalValue::Map(_))));
            assert_eq!(m.len(), 4);
        } else {
            panic!("expected Map from ResolvedBinding::canonical_value");
        }
    }

    #[test]
    fn flow_annotation_canonical_value_content() {
        let ann = FlowAnnotation {
            data_label: Label::Internal,
            sink_clearance: Label::Internal,
            declassification_required: true,
        };
        let cv = ann.canonical_value();
        if let CanonicalValue::Map(m) = cv {
            assert_eq!(
                m.get("declassification_required"),
                Some(&CanonicalValue::Bool(true))
            );
            // data_label and sink_clearance should be Strings (Debug format)
            assert!(matches!(
                m.get("data_label"),
                Some(CanonicalValue::String(_))
            ));
            assert!(matches!(
                m.get("sink_clearance"),
                Some(CanonicalValue::String(_))
            ));
            assert_eq!(m.len(), 3);
        } else {
            panic!("expected Map from FlowAnnotation::canonical_value");
        }
    }
}
