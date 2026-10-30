//! Deterministic module resolver trait with policy hooks.
//!
//! This module defines resolution contracts for ES module `import` and
//! CommonJS `require` semantics, with capability-aware policy checks at
//! resolution time.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::deterministic_serde::{CanonicalSink, CanonicalValue, CanonicalWriter, encode_value};
use crate::hash_tiers::ContentHash;
use crate::module_compatibility_matrix::CompatibilityMode;

pub type ResolutionResult<T> = Result<T, Box<ResolutionError>>;
pub type RegistryResult<T> = Result<T, RegistryError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSyntax {
    EsModule,
    CommonJs,
    Wasm,
}

impl ModuleSyntax {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EsModule => "esm",
            Self::CommonJs => "cjs",
            Self::Wasm => "wasm",
        }
    }
}

pub fn wasm_module_required_capabilities() -> BTreeSet<RuntimeCapability> {
    BTreeSet::from([RuntimeCapability::ModuleLoad, RuntimeCapability::VmDispatch])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportStyle {
    Import,
    Require,
}

impl ImportStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Require => "require",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSourceKind {
    BuiltIn,
    Workspace,
    ExternalRegistry,
}

impl ModuleSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuiltIn => "builtin",
            Self::Workspace => "workspace",
            Self::ExternalRegistry => "external_registry",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleProvenance {
    pub kind: ModuleSourceKind,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleDependency {
    pub specifier: String,
    pub style: ImportStyle,
}

impl ModuleDependency {
    pub fn new(specifier: impl Into<String>, style: ImportStyle) -> Self {
        Self {
            specifier: specifier.into(),
            style,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleDefinition {
    pub syntax: ModuleSyntax,
    pub source: String,
    pub dependencies: Vec<ModuleDependency>,
    pub required_capabilities: BTreeSet<RuntimeCapability>,
    pub provenance_origin: String,
}

impl ModuleDefinition {
    pub fn new(syntax: ModuleSyntax, source: impl Into<String>) -> Self {
        Self {
            syntax,
            source: source.into(),
            dependencies: Vec::new(),
            required_capabilities: BTreeSet::new(),
            provenance_origin: "<unspecified>".to_string(),
        }
    }

    pub fn with_dependency(mut self, dependency: ModuleDependency) -> Self {
        self.dependencies.push(dependency);
        self
    }

    pub fn require_capability(mut self, capability: RuntimeCapability) -> Self {
        self.required_capabilities.insert(capability);
        self
    }

    pub fn with_provenance(mut self, provenance_origin: impl Into<String>) -> Self {
        self.provenance_origin = provenance_origin.into();
        self
    }
}

fn apply_wasm_module_contract(
    module_key: &str,
    mut definition: ModuleDefinition,
) -> ModuleDefinition {
    if definition.syntax == ModuleSyntax::Wasm || module_key.trim().ends_with(".wasm") {
        definition.syntax = ModuleSyntax::Wasm;
        definition
            .required_capabilities
            .extend(wasm_module_required_capabilities());
    }
    definition
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExternalPackageExportTarget {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub condition_targets: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalPackageDefinition {
    pub package_name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub exports: BTreeMap<String, ExternalPackageExportTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExternalPackageWildcardExport {
    pattern: String,
    specificity: usize,
}

impl ExternalPackageDefinition {
    pub fn new(package_name: impl Into<String>) -> Self {
        let package_name = package_name.into();
        Self {
            package_name: normalize_registered_package_name(&package_name),
            exports: BTreeMap::new(),
        }
    }

    pub fn with_export(
        mut self,
        export_key: impl Into<String>,
        export_target: ExternalPackageExportTarget,
    ) -> Self {
        let export_key = export_key.into();
        self.exports
            .insert(normalize_package_export_key(&export_key), export_target);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRecord {
    pub id: String,
    pub syntax: ModuleSyntax,
    pub source: String,
    pub dependencies: Vec<ModuleDependency>,
    pub required_capabilities: BTreeSet<RuntimeCapability>,
    pub provenance: ModuleProvenance,
}

impl ModuleRecord {
    fn from_definition(
        id: String,
        source_kind: ModuleSourceKind,
        definition: ModuleDefinition,
    ) -> Self {
        Self {
            id,
            syntax: definition.syntax,
            source: definition.source,
            dependencies: definition.dependencies,
            required_capabilities: definition.required_capabilities,
            provenance: ModuleProvenance {
                kind: source_kind,
                origin: definition.provenance_origin,
            },
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let dependencies = self
            .dependencies
            .iter()
            .map(|dep| {
                CanonicalValue::map_from_entries([
                    ("specifier", CanonicalValue::str(dep.specifier.clone())),
                    ("style", CanonicalValue::str(dep.style.as_str())),
                ])
            })
            .collect();
        let required_caps = self
            .required_capabilities
            .iter()
            .map(|cap| CanonicalValue::str(cap.to_string()))
            .collect();
        CanonicalValue::map_from_entries([
            ("id", CanonicalValue::str(self.id.clone())),
            ("syntax", CanonicalValue::str(self.syntax.as_str())),
            ("source", CanonicalValue::str(self.source.clone())),
            ("dependencies", CanonicalValue::Array(dependencies)),
            (
                "required_capabilities",
                CanonicalValue::Array(required_caps),
            ),
            (
                "provenance",
                CanonicalValue::map_from_entries([
                    ("kind", CanonicalValue::str(self.provenance.kind.as_str())),
                    (
                        "origin",
                        CanonicalValue::str(self.provenance.origin.clone()),
                    ),
                ]),
            ),
        ])
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut writer = CanonicalWriter::new();
        self.write_canonical(&mut writer);
        writer.finish()
    }

    pub fn canonical_hash(&self) -> ContentHash {
        let mut writer = CanonicalWriter::hasher();
        self.write_canonical(&mut writer);
        writer.finish_hash()
    }

    /// Keep the complete canonical record in the identity check, but borrow
    /// its fields. Native require/import cache hits recheck this hash; neither
    /// an owned value tree nor a full encoded source buffer is needed there.
    /// Field order and container clamping match `canonical_value` exactly.
    fn write_canonical<S: CanonicalSink>(&self, writer: &mut CanonicalWriter<S>) {
        writer.map_header(6);
        writer.key("dependencies");
        let count = writer.array_header(self.dependencies.len());
        for dependency in self.dependencies.iter().take(count) {
            writer.map_header(2);
            writer.key("specifier");
            writer.string(&dependency.specifier);
            writer.key("style");
            writer.string(dependency.style.as_str());
        }
        writer.key("id");
        writer.string(&self.id);
        writer.key("provenance");
        writer.map_header(2);
        writer.key("kind");
        writer.string(self.provenance.kind.as_str());
        writer.key("origin");
        writer.string(&self.provenance.origin);
        writer.key("required_capabilities");
        let count = writer.array_header(self.required_capabilities.len());
        for capability in self.required_capabilities.iter().take(count) {
            // Capability iteration follows the enum's BTreeSet ordering,
            // exactly as the public value representation does.
            writer.string(&capability.to_string());
        }
        writer.key("source");
        writer.string(&self.source);
        writer.key("syntax");
        writer.string(self.syntax.as_str());
    }
}

/// Immutable execution payload with an engine-computed canonical hash.
///
/// Construction only moves the record; it does not hash or grant authority.
/// Native execution checks its source and memory budgets before requesting the
/// hash. Fields are private and access is read-only, so a cached digest cannot
/// outlive a mutation of the record it identifies. This is not a serialized
/// proof or a cached policy decision.
#[derive(Debug)]
pub struct SharedModuleRecord {
    record: ModuleRecord,
    canonical_hash: OnceLock<ContentHash>,
}

impl SharedModuleRecord {
    pub fn new(record: ModuleRecord) -> Self {
        Self {
            record,
            canonical_hash: OnceLock::new(),
        }
    }

    pub fn record(&self) -> &ModuleRecord {
        &self.record
    }

    pub fn canonical_hash(&self) -> ContentHash {
        *self
            .canonical_hash
            .get_or_init(|| self.record.canonical_hash())
    }
}

impl std::ops::Deref for SharedModuleRecord {
    type Target = ModuleRecord;

    fn deref(&self) -> &Self::Target {
        self.record()
    }
}

/// Native CommonJS objects implemented by the interpreter itself.
///
/// This is deliberately narrower than Node's builtin name inventory. A
/// resolver may deliver one of these source-free descriptors for a captured
/// require or import route. The interpreter
/// rechecks the complete descriptor before dispatching the real realm object;
/// no source text or filesystem fallback is used to manufacture a builtin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeBuiltinModule {    Buffer,
    Crypto,
    Zlib,
    Fs,
    FsPromises,
    Events,
    Os,
    Querystring,
    Url,
    Timers,
    PerfHooks,
    Path,
    PathPosix,
    PathWin32,
    Util,
    UtilTypes,
    Assert,
    AssertStrict,
    StringDecoder,
    TimersPromises,
    Stream,
    StreamPromises,
    StreamConsumers,
    StreamWeb,
    Module,
    Readline,
    ReadlinePromises,
    DiagnosticsChannel,
    Http,
    Https,
}

impl NativeBuiltinModule {
    pub fn from_specifier(specifier: &str) -> Option<Self> {
        match specifier {
            "buffer" | "node:buffer" => Some(Self::Buffer),
            "crypto" | "node:crypto" => Some(Self::Crypto),
            "zlib" | "node:zlib" => Some(Self::Zlib),
            "fs" | "node:fs" => Some(Self::Fs),
            "fs/promises" | "node:fs/promises" => Some(Self::FsPromises),
            "module" | "node:module" => Some(Self::Module),
            "http" | "node:http" => Some(Self::Http),
            "https" | "node:https" => Some(Self::Https),
            "events" | "node:events" => Some(Self::Events),
            "os" | "node:os" => Some(Self::Os),
            "querystring" | "node:querystring" => Some(Self::Querystring),
            "url" | "node:url" => Some(Self::Url),
            "timers" | "node:timers" => Some(Self::Timers),
            "perf_hooks" | "node:perf_hooks" => Some(Self::PerfHooks),
            "path" | "node:path" => Some(Self::Path),
            "path/posix" | "node:path/posix" => Some(Self::PathPosix),
            "path/win32" | "node:path/win32" => Some(Self::PathWin32),
            "util" | "node:util" => Some(Self::Util),
            "util/types" | "node:util/types" => Some(Self::UtilTypes),
            "assert" | "node:assert" => Some(Self::Assert),
            "assert/strict" | "node:assert/strict" => Some(Self::AssertStrict),
            "string_decoder" | "node:string_decoder" => Some(Self::StringDecoder),
            "timers/promises" | "node:timers/promises" => Some(Self::TimersPromises),
            "stream" | "node:stream" => Some(Self::Stream),
            "stream/promises" | "node:stream/promises" => Some(Self::StreamPromises),
            "stream/consumers" | "node:stream/consumers" => Some(Self::StreamConsumers),
            "stream/web" | "node:stream/web" => Some(Self::StreamWeb),
            "readline" | "node:readline" => Some(Self::Readline),
            "readline/promises" | "node:readline/promises" => Some(Self::ReadlinePromises),
            "diagnostics_channel" | "node:diagnostics_channel" => Some(Self::DiagnosticsChannel),
            _ => None,
        }
    }

    pub fn canonical_specifier(self) -> &'static str {
        match self {
            Self::Buffer => "node:buffer",
            Self::Crypto => "node:crypto",
            Self::Zlib => "node:zlib",
            Self::Fs => "node:fs",
            Self::FsPromises => "node:fs/promises",
            Self::Module => "node:module",
            Self::Http => "node:http",
            Self::Https => "node:https",
            Self::Events => "node:events",
            Self::Os => "node:os",
            Self::Querystring => "node:querystring",
            Self::Url => "node:url",
            Self::Timers => "node:timers",
            Self::PerfHooks => "node:perf_hooks",
            Self::Path => "node:path",
            Self::PathPosix => "node:path/posix",
            Self::PathWin32 => "node:path/win32",
            Self::Util => "node:util",
            Self::UtilTypes => "node:util/types",
            Self::Assert => "node:assert",
            Self::AssertStrict => "node:assert/strict",
            Self::StringDecoder => "node:string_decoder",
            Self::TimersPromises => "node:timers/promises",
            Self::Stream => "node:stream",
            Self::StreamPromises => "node:stream/promises",
            Self::StreamConsumers => "node:stream/consumers",
            Self::StreamWeb => "node:stream/web",
            Self::Readline => "node:readline",
            Self::ReadlinePromises => "node:readline/promises",
            Self::DiagnosticsChannel => "node:diagnostics_channel",
        }
    }

    /// Engine-owned identity and capability contract for a native provider.
    /// The caller supplies its graph-scoped module id, never executable text.
    pub fn record(self, id: impl Into<String>) -> ModuleRecord {
        let mut required_capabilities =
            BTreeSet::from([RuntimeCapability::ModuleLoad, RuntimeCapability::Builtin]);
        // Stream completion, readline cursor callbacks and diagnostics
        // subscriber errors use the native nextTick/microtask queues, whose
        // scheduling authority is Timer.
        if matches!(
            self,
            Self::Timers
                | Self::TimersPromises
                | Self::Stream
                | Self::StreamPromises
                | Self::Readline
                | Self::ReadlinePromises
                | Self::DiagnosticsChannel
        ) {
            required_capabilities.insert(RuntimeCapability::Timer);
        }
        ModuleRecord {
            id: id.into(),
            syntax: ModuleSyntax::CommonJs,
            source: String::new(),
            dependencies: Vec::new(),
            required_capabilities,
            provenance: ModuleProvenance {
                kind: ModuleSourceKind::BuiltIn,
                origin: format!(
                    "franken-engine/native-builtin/v1:{}",
                    self.canonical_specifier()
                ),
            },
        }
    }

    /// Reject forged source, dependencies, format, provenance or capability
    /// reductions before invoking a native provider. A BuiltIn tag alone is
    /// not authority to bypass ordinary source evaluation.
    pub fn from_record(record: &ModuleRecord) -> Option<Self> {
        if record.id.is_empty() {
            return None;
        }
        let name = record
            .provenance
            .origin
            .strip_prefix("franken-engine/native-builtin/v1:")?;
        let builtin = Self::from_specifier(name)?;
        (record == &builtin.record(record.id.clone())).then_some(builtin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleRequest {
    pub specifier: String,
    pub referrer: Option<String>,
    pub style: ImportStyle,
    #[serde(
        default = "default_compatibility_mode",
        skip_serializing_if = "is_native_compatibility_mode"
    )]
    pub compatibility_mode: CompatibilityMode,
}

impl ModuleRequest {
    pub fn new(specifier: impl Into<String>, style: ImportStyle) -> Self {
        Self {
            specifier: specifier.into(),
            referrer: None,
            style,
            compatibility_mode: default_compatibility_mode(),
        }
    }

    pub fn with_referrer(mut self, referrer: impl Into<String>) -> Self {
        self.referrer = Some(referrer.into());
        self
    }

    pub fn with_compatibility_mode(mut self, compatibility_mode: CompatibilityMode) -> Self {
        self.compatibility_mode = compatibility_mode;
        self
    }
}

const fn default_compatibility_mode() -> CompatibilityMode {
    CompatibilityMode::Native
}

fn is_native_compatibility_mode(mode: &CompatibilityMode) -> bool {
    *mode == CompatibilityMode::Native
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl ResolutionContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedModule {
    pub request_specifier: String,
    pub canonical_specifier: String,
    pub record: ModuleRecord,
    pub content_hash: ContentHash,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probe_sequence: Vec<String>,
}

/// Execution delivery of shared immutable bytes, with fresh request metadata.
///
/// `content_hash` is still the provider's claim. The interpreter must compare
/// it with `record.canonical_hash()` after its resource checks; moving an owned
/// result here never authenticates or silently repairs an incorrect digest.
#[derive(Debug, Clone)]
pub struct SharedResolvedModule {
    pub request_specifier: String,
    pub canonical_specifier: String,
    pub record: Arc<SharedModuleRecord>,
    pub content_hash: ContentHash,
    pub probe_sequence: Vec<String>,
}

impl From<ResolvedModule> for SharedResolvedModule {
    fn from(module: ResolvedModule) -> Self {
        Self {
            request_specifier: module.request_specifier,
            canonical_specifier: module.canonical_specifier,
            record: Arc::new(SharedModuleRecord::new(module.record)),
            content_hash: module.content_hash,
            probe_sequence: module.probe_sequence,
        }
    }
}

pub const MODULE_RESOLUTION_TRACE_SCHEMA_VERSION: &str = "rgc.module-resolution.trace.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionOutcome {
    pub module: ResolvedModule,
    pub event: ResolutionEvent,
}

/// Source sharing never shares a request's authorization or event context.
#[derive(Debug, Clone)]
pub struct SharedResolutionOutcome {
    pub module: SharedResolvedModule,
    pub event: ResolutionEvent,
}

impl From<ResolutionOutcome> for SharedResolutionOutcome {
    fn from(outcome: ResolutionOutcome) -> Self {
        Self {
            module: outcome.module.into(),
            event: outcome.event,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleResolutionTraceRecord {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub request_specifier: String,
    pub canonical_specifier: String,
    pub source_kind: String,
    pub probe_sequence: Vec<String>,
    pub outcome: String,
    pub error_code: String,
}

impl ModuleResolutionTraceRecord {
    pub const fn schema_version() -> &'static str {
        MODULE_RESOLUTION_TRACE_SCHEMA_VERSION
    }

    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl ResolutionOutcome {
    pub fn trace_record(&self) -> ModuleResolutionTraceRecord {
        ModuleResolutionTraceRecord {
            schema_version: ModuleResolutionTraceRecord::schema_version().to_string(),
            trace_id: self.event.trace_id.clone(),
            decision_id: self.event.decision_id.clone(),
            policy_id: self.event.policy_id.clone(),
            component: self.event.component.clone(),
            event: self.event.event.clone(),
            request_specifier: self.module.request_specifier.clone(),
            canonical_specifier: self.module.canonical_specifier.clone(),
            source_kind: self.module.record.provenance.kind.as_str().to_string(),
            probe_sequence: self.module.probe_sequence.clone(),
            outcome: self.event.outcome.clone(),
            error_code: self.event.error_code.clone(),
        }
    }
}

pub type HostApiAuthorizationResult<T> = Result<T, Box<HostApiAuthorizationError>>;

const HOST_API_COMPONENT: &str = "host_api_surface";
const HOST_API_EVENT: &str = "host_api_authorization";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostApiErrorCode {
    UnsupportedModule,
    UnsupportedOperation,
    PolicyDenied,
}

impl HostApiErrorCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::UnsupportedModule => "FE-HOSTAPI-0001",
            Self::UnsupportedOperation => "FE-HOSTAPI-0002",
            Self::PolicyDenied => "FE-HOSTAPI-0003",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostApiRequest {
    pub module_specifier: String,
    pub operation: String,
}

impl HostApiRequest {
    pub fn new(module_specifier: impl Into<String>, operation: impl Into<String>) -> Self {
        Self {
            module_specifier: module_specifier.into(),
            operation: operation.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostApiPermissionDescriptor {
    pub descriptor_id: String,
    pub module_specifier: String,
    pub operation: String,
    pub required_capabilities: BTreeSet<RuntimeCapability>,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostApiDecisionEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub decision_stable_id: String,
    pub descriptor_id: Option<String>,
    pub module_specifier: String,
    pub operation: String,
    pub required_capabilities: BTreeSet<RuntimeCapability>,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostApiAuthorizationOutcome {
    pub descriptor: HostApiPermissionDescriptor,
    pub event: HostApiDecisionEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostApiAuthorizationError {
    pub code: HostApiErrorCode,
    pub message: String,
    pub event: HostApiDecisionEvent,
}

impl HostApiAuthorizationError {
    fn new(
        code: HostApiErrorCode,
        message: impl Into<String>,
        context: &ResolutionContext,
        descriptor: Option<&HostApiPermissionDescriptor>,
        module_specifier: &str,
        operation: &str,
        remediation: impl Into<String>,
    ) -> Self {
        let message = message.into();
        let remediation = remediation.into();
        let required_capabilities = descriptor
            .map(|value| value.required_capabilities.clone())
            .unwrap_or_default();
        let descriptor_id = descriptor.map(|value| value.descriptor_id.clone());
        let decision_stable_id = host_api_decision_stable_id(
            context,
            descriptor_id.as_deref(),
            module_specifier,
            operation,
            "deny",
            code.stable_code(),
        );
        let event = HostApiDecisionEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: HOST_API_COMPONENT.to_string(),
            event: HOST_API_EVENT.to_string(),
            outcome: "deny".to_string(),
            error_code: code.stable_code().to_string(),
            decision_stable_id,
            descriptor_id,
            module_specifier: module_specifier.to_string(),
            operation: operation.to_string(),
            required_capabilities,
            remediation,
        };
        Self {
            code,
            message,
            event,
        }
    }
}

impl fmt::Display for HostApiAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (trace_id={}, decision_id={}, policy_id={})",
            self.code.stable_code(),
            self.message,
            self.event.trace_id,
            self.event.decision_id,
            self.event.policy_id
        )
    }
}

impl std::error::Error for HostApiAuthorizationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySafeHostApiSurface {
    descriptors: BTreeMap<String, BTreeMap<String, HostApiPermissionDescriptor>>,
}

impl Default for CapabilitySafeHostApiSurface {
    fn default() -> Self {
        Self::standard()
    }
}

impl CapabilitySafeHostApiSurface {
    pub fn standard() -> Self {
        let mut surface = Self {
            descriptors: BTreeMap::new(),
        };

        surface.insert_descriptor(
            "hostapi.node-fs.read-file.v1",
            "node:fs",
            "read_file",
            &[RuntimeCapability::FsRead],
            "Grant `fs_read` capability (or a profile that includes it) before calling node:fs.read_file.",
        );
        surface.insert_descriptor(
            "hostapi.node-fs.write-file.v1",
            "node:fs",
            "write_file",
            &[RuntimeCapability::FsWrite],
            "Grant `fs_write` capability (and `fs_read` for read/modify/write flows) before calling node:fs.write_file.",
        );
        surface.insert_descriptor(
            "hostapi.node-net.connect.v1",
            "node:net",
            "connect",
            &[RuntimeCapability::NetworkEgress],
            "Grant `network_egress` capability before calling node:net.connect.",
        );
        surface.insert_descriptor(
            "hostapi.node-process.spawn.v1",
            "node:process",
            "spawn",
            &[RuntimeCapability::ProcessSpawn],
            "Grant `process_spawn` capability before calling node:process.spawn.",
        );
        for (descriptor_id, operation) in [
            ("hostapi.node-crypto.create-hash.v1", "create_hash"),
            ("hostapi.node-crypto.create-hmac.v1", "create_hmac"),
            (
                "hostapi.node-crypto.timing-safe-equal.v1",
                "timing_safe_equal",
            ),
            ("hostapi.node-crypto.pbkdf2-sync.v1", "pbkdf2_sync"),
            ("hostapi.node-crypto.pbkdf2.v1", "pbkdf2"),
            ("hostapi.node-crypto.scrypt-sync.v1", "scrypt_sync"),
            ("hostapi.node-crypto.create-cipheriv.v1", "create_cipheriv"),
            (
                "hostapi.node-crypto.create-decipheriv.v1",
                "create_decipheriv",
            ),
            ("hostapi.node-crypto.get-hashes.v1", "get_hashes"),
            ("hostapi.node-crypto.get-ciphers.v1", "get_ciphers"),
            ("hostapi.node-crypto.constants.v1", "constants"),
        ] {
            surface.insert_descriptor(
                descriptor_id,
                "node:crypto",
                operation,
                &[RuntimeCapability::Builtin],
                "Grant `builtin` capability before calling deterministic node:crypto compute operations.",
            );
        }

        surface
    }

    pub fn authorize(
        &self,
        request: &HostApiRequest,
        context: &ResolutionContext,
        policy: &CapabilityPolicyHook,
    ) -> HostApiAuthorizationResult<HostApiAuthorizationOutcome> {
        let module_specifier = canonicalize_host_api_module(&request.module_specifier);
        let operation = canonicalize_host_api_operation(&request.operation);

        let module_descriptors = self.descriptors.get(&module_specifier).ok_or_else(|| {
            let supported_modules = self.supported_modules().join(", ");
            Box::new(HostApiAuthorizationError::new(
                HostApiErrorCode::UnsupportedModule,
                format!(
                    "unsupported host API module '{}' for operation '{}'",
                    request.module_specifier.trim(),
                    request.operation.trim()
                ),
                context,
                None,
                &module_specifier,
                &operation,
                format!("Use one of [{supported_modules}] and an explicit capability descriptor."),
            ))
        })?;

        let descriptor = module_descriptors.get(&operation).ok_or_else(|| {
            let supported_ops = module_descriptors
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            Box::new(HostApiAuthorizationError::new(
                HostApiErrorCode::UnsupportedOperation,
                format!(
                    "unsupported host API operation '{}' for module '{}'",
                    request.operation.trim(),
                    request.module_specifier.trim()
                ),
                context,
                None,
                &module_specifier,
                &operation,
                format!(
                    "Use one of [{supported_ops}] for module '{module_specifier}' or register a new descriptor."
                ),
            ))
        })?;

        policy.authorize_host_api(descriptor, context)?;

        let decision_stable_id = host_api_decision_stable_id(
            context,
            Some(descriptor.descriptor_id.as_str()),
            &module_specifier,
            &operation,
            "allow",
            "none",
        );
        let event = HostApiDecisionEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: HOST_API_COMPONENT.to_string(),
            event: HOST_API_EVENT.to_string(),
            outcome: "allow".to_string(),
            error_code: "none".to_string(),
            decision_stable_id,
            descriptor_id: Some(descriptor.descriptor_id.clone()),
            module_specifier,
            operation,
            required_capabilities: descriptor.required_capabilities.clone(),
            remediation: descriptor.remediation.clone(),
        };

        Ok(HostApiAuthorizationOutcome {
            descriptor: descriptor.clone(),
            event,
        })
    }

    pub fn descriptor(
        &self,
        module_specifier: &str,
        operation: &str,
    ) -> Option<&HostApiPermissionDescriptor> {
        let module_specifier = canonicalize_host_api_module(module_specifier);
        let operation = canonicalize_host_api_operation(operation);
        self.descriptors
            .get(&module_specifier)
            .and_then(|ops| ops.get(&operation))
    }

    pub fn supported_modules(&self) -> Vec<String> {
        self.descriptors.keys().cloned().collect()
    }

    fn insert_descriptor(
        &mut self,
        descriptor_id: &str,
        module_specifier: &str,
        operation: &str,
        required_capabilities: &[RuntimeCapability],
        remediation: &str,
    ) {
        let module_specifier = canonicalize_host_api_module(module_specifier);
        let operation = canonicalize_host_api_operation(operation);
        let descriptor = HostApiPermissionDescriptor {
            descriptor_id: descriptor_id.to_string(),
            module_specifier: module_specifier.clone(),
            operation: operation.clone(),
            required_capabilities: required_capabilities.iter().copied().collect(),
            remediation: remediation.to_string(),
        };
        self.descriptors
            .entry(module_specifier)
            .or_default()
            .insert(operation, descriptor);
    }
}

fn canonicalize_host_api_module(module_specifier: &str) -> String {
    let normalized = module_specifier.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "fs" | "node:fs" => "node:fs".to_string(),
        "net" | "node:net" => "node:net".to_string(),
        "process" | "node:process" => "node:process".to_string(),
        "crypto" | "node:crypto" => "node:crypto".to_string(),
        _ => normalized,
    }
}

fn canonicalize_host_api_operation(operation: &str) -> String {
    operation.trim().to_ascii_lowercase()
}

fn host_api_decision_stable_id(
    context: &ResolutionContext,
    descriptor_id: Option<&str>,
    module_specifier: &str,
    operation: &str,
    outcome: &str,
    error_code: &str,
) -> String {
    let mut map = BTreeMap::new();
    map.insert(
        "decision_id".to_string(),
        CanonicalValue::String(context.decision_id.clone()),
    );
    map.insert(
        "descriptor_id".to_string(),
        descriptor_id
            .map(|value| CanonicalValue::String(value.to_string()))
            .unwrap_or(CanonicalValue::Null),
    );
    map.insert(
        "error_code".to_string(),
        CanonicalValue::String(error_code.to_string()),
    );
    map.insert(
        "module_specifier".to_string(),
        CanonicalValue::String(module_specifier.to_string()),
    );
    map.insert(
        "operation".to_string(),
        CanonicalValue::String(operation.to_string()),
    );
    map.insert(
        "outcome".to_string(),
        CanonicalValue::String(outcome.to_string()),
    );
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(context.policy_id.clone()),
    );
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(context.trace_id.clone()),
    );
    let digest = ContentHash::compute(&encode_value(&CanonicalValue::Map(map))).to_hex();
    format!("hostapi-dec-{}", &digest[..16])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionErrorCode {
    EmptySpecifier,
    InvalidReferrer,
    /// Invalid or unadmitted route. Installed execution keeps this refusal
    /// outside guest exception handling, even for a CommonJS optional load.
    UnsupportedSpecifier,
    /// An admitted lookup found no module. Installed CommonJS execution
    /// exposes this as the catchable Node `MODULE_NOT_FOUND` error. A closed
    /// graph must not use this for routes outside its captured lookup domain.
    ModuleNotFound,
    PolicyDenied,
    /// A captured package exports selection denied this subpath. This is a
    /// guest-visible package boundary, not a runtime capability-policy denial.
    PackagePathNotExported,
    /// A captured package scope has no matching private imports mapping.
    PackageImportNotDefined,
}

impl ResolutionErrorCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::EmptySpecifier => "FE-MODRES-0001",
            Self::InvalidReferrer => "FE-MODRES-0002",
            Self::UnsupportedSpecifier => "FE-MODRES-0003",
            Self::ModuleNotFound => "FE-MODRES-0004",
            Self::PolicyDenied => "FE-MODRES-0005",
            Self::PackagePathNotExported => "FE-MODRES-0006",
            Self::PackageImportNotDefined => "FE-MODRES-0007",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionError {
    pub code: ResolutionErrorCode,
    pub message: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_specifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_specifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<ModuleSourceKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probe_sequence: Vec<String>,
    pub event: ResolutionEvent,
}

impl ResolutionError {
    fn new(
        code: ResolutionErrorCode,
        message: impl Into<String>,
        context: &ResolutionContext,
    ) -> Self {
        let message = message.into();
        let event = error_event(context, code);
        Self {
            code,
            message,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            request_specifier: String::new(),
            canonical_specifier: None,
            source_kind: None,
            probe_sequence: Vec::new(),
            event,
        }
    }

    fn with_resolution_attempt(
        mut self,
        request_specifier: impl Into<String>,
        canonical_specifier: Option<String>,
        source_kind: Option<ModuleSourceKind>,
        probe_sequence: Vec<String>,
    ) -> Self {
        self.request_specifier = request_specifier.into();
        self.canonical_specifier = canonical_specifier;
        self.source_kind = source_kind;
        self.probe_sequence = probe_sequence;
        self
    }

    /// A policy hook may hide a denied resource behind a not-found code.
    /// Keep that diagnostic, but never turn a policy-origin refusal into
    /// the catchable absence of an admitted optional dependency.
    fn into_policy_denial(mut self) -> Self {
        if self.code != ResolutionErrorCode::PolicyDenied {
            self.message = format!(
                "module policy denied ({}): {}",
                self.code.stable_code(),
                self.message
            );
        }
        self.code = ResolutionErrorCode::PolicyDenied;
        self.event.error_code = self.code.stable_code().to_string();
        self
    }

    pub fn trace_record(&self) -> ModuleResolutionTraceRecord {
        let request_specifier = if self.request_specifier.trim().is_empty() {
            "<unknown>".to_string()
        } else {
            self.request_specifier.clone()
        };
        let canonical_specifier = self
            .canonical_specifier
            .clone()
            .unwrap_or_else(|| request_specifier.clone());
        ModuleResolutionTraceRecord {
            schema_version: ModuleResolutionTraceRecord::schema_version().to_string(),
            trace_id: self.trace_id.clone(),
            decision_id: self.decision_id.clone(),
            policy_id: self.policy_id.clone(),
            component: self.event.component.clone(),
            event: self.event.event.clone(),
            request_specifier,
            canonical_specifier,
            source_kind: self
                .source_kind
                .map(ModuleSourceKind::as_str)
                .unwrap_or("unresolved")
                .to_string(),
            probe_sequence: self.probe_sequence.clone(),
            outcome: self.event.outcome.clone(),
            error_code: self.event.error_code.clone(),
        }
    }
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (trace_id={}, decision_id={}, policy_id={})",
            self.code.stable_code(),
            self.message,
            self.trace_id,
            self.decision_id,
            self.policy_id
        )
    }
}

impl std::error::Error for ResolutionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryErrorCode {
    EmptyKey,
    OutsideRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryError {
    pub code: RegistryErrorCode,
    pub message: String,
}

impl RegistryError {
    fn empty_key() -> Self {
        Self {
            code: RegistryErrorCode::EmptyKey,
            message: "module key must not be empty".to_string(),
        }
    }

    fn outside_root(root_dir: &str, path: &str) -> Self {
        Self {
            code: RegistryErrorCode::OutsideRoot,
            message: format!(
                "workspace module path '{}' escapes resolver root '{}'",
                path, root_dir
            ),
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for RegistryError {}

pub trait ModulePolicyHook {
    fn authorize(
        &self,
        request: &ModuleRequest,
        resolved: &ModuleRecord,
        context: &ResolutionContext,
    ) -> ResolutionResult<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AllowAllPolicy;

impl ModulePolicyHook for AllowAllPolicy {
    fn authorize(
        &self,
        _request: &ModuleRequest,
        _resolved: &ModuleRecord,
        _context: &ResolutionContext,
    ) -> ResolutionResult<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityPolicyHook {
    #[serde(default)]
    pub granted_capabilities: BTreeSet<RuntimeCapability>,
    #[serde(default)]
    pub denied_specifiers: BTreeSet<String>,
    #[serde(default)]
    pub denied_host_api_descriptors: BTreeSet<String>,
}

impl CapabilityPolicyHook {
    pub fn new(granted_capabilities: BTreeSet<RuntimeCapability>) -> Self {
        Self {
            granted_capabilities,
            denied_specifiers: BTreeSet::new(),
            denied_host_api_descriptors: BTreeSet::new(),
        }
    }

    pub fn deny_specifier(mut self, specifier: impl Into<String>) -> Self {
        self.denied_specifiers.insert(specifier.into());
        self
    }

    pub fn deny_host_api_descriptor(mut self, descriptor_id: impl Into<String>) -> Self {
        self.denied_host_api_descriptors
            .insert(descriptor_id.into());
        self
    }

    pub fn authorize_host_api(
        &self,
        descriptor: &HostApiPermissionDescriptor,
        context: &ResolutionContext,
    ) -> HostApiAuthorizationResult<()> {
        if self
            .denied_host_api_descriptors
            .contains(&descriptor.descriptor_id)
        {
            return Err(Box::new(HostApiAuthorizationError::new(
                HostApiErrorCode::PolicyDenied,
                format!(
                    "host API descriptor '{}' denied by policy",
                    descriptor.descriptor_id
                ),
                context,
                Some(descriptor),
                &descriptor.module_specifier,
                &descriptor.operation,
                "Remove descriptor deny-list entry or request an approved policy override.",
            )));
        }

        let missing: Vec<RuntimeCapability> = descriptor
            .required_capabilities
            .difference(&self.granted_capabilities)
            .copied()
            .collect();
        if missing.is_empty() {
            return Ok(());
        }

        let missing_list = missing
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        Err(Box::new(HostApiAuthorizationError::new(
            HostApiErrorCode::PolicyDenied,
            format!(
                "host API '{}' operation '{}' denied due to missing capabilities [{}]",
                descriptor.module_specifier, descriptor.operation, missing_list
            ),
            context,
            Some(descriptor),
            &descriptor.module_specifier,
            &descriptor.operation,
            descriptor.remediation.clone(),
        )))
    }
}

impl ModulePolicyHook for CapabilityPolicyHook {
    fn authorize(
        &self,
        request: &ModuleRequest,
        resolved: &ModuleRecord,
        context: &ResolutionContext,
    ) -> ResolutionResult<()> {
        if self.denied_specifiers.contains(&request.specifier)
            || self.denied_specifiers.contains(&resolved.id)
        {
            return Err(Box::new(ResolutionError::new(
                ResolutionErrorCode::PolicyDenied,
                format!(
                    "resolution denied by policy deny-list for specifier '{}'",
                    request.specifier
                ),
                context,
            )));
        }

        let missing: Vec<RuntimeCapability> = resolved
            .required_capabilities
            .difference(&self.granted_capabilities)
            .copied()
            .collect();
        if missing.is_empty() {
            return Ok(());
        }

        let missing_list = missing
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        Err(Box::new(ResolutionError::new(
            ResolutionErrorCode::PolicyDenied,
            format!(
                "resolution denied due to missing capabilities [{}] for module '{}'",
                missing_list, resolved.id
            ),
            context,
        )))
    }
}

pub trait ModuleResolver {
    fn resolve(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<ResolutionOutcome>;

    /// Resolve an exact runtime request while permitting immutable source
    /// sharing. Implementations must authorize every request, including cache
    /// hits. The default retains the owned resolver's claimed hash unchanged;
    /// native execution verifies it after enforcing its source/memory budgets.
    fn resolve_shared(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<SharedResolutionOutcome> {
        self.resolve(request, context, policy).map(Into::into)
    }

    fn resolve_chain(
        &self,
        entry_request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<Vec<ResolutionOutcome>>;
}

/// Runtime-owned resolver installation used by native execution.
///
/// The resolver and policy must be thread-safe because interpreter lanes run on
/// a provisioned execution thread. The entry referrer is the already-authorized
/// engine record id for the top-level source; nested loads replace it with the
/// id of the module currently being evaluated. Keeping this object source-only
/// lets the existing interpreter retain ownership of parsing, lowering,
/// CommonJS caching, ESM live bindings, cycles, IFC and effect authority.
#[derive(Clone)]
pub struct ExecutionModuleResolver {
    entry_referrer: String,
    resolver: Arc<dyn ModuleResolver + Send + Sync>,
    policy: Arc<dyn ModulePolicyHook + Send + Sync>,
    source_locations: Arc<BTreeMap<String, ModuleSourceLocation>>,
}

struct ExecutionModulePolicy<'a>(&'a dyn ModulePolicyHook);

impl ModulePolicyHook for ExecutionModulePolicy<'_> {
    fn authorize(
        &self,
        request: &ModuleRequest,
        resolved: &ModuleRecord,
        context: &ResolutionContext,
    ) -> ResolutionResult<()> {
        self.0
            .authorize(request, resolved, context)
            .map_err(|error| Box::new((*error).into_policy_denial()))
    }
}

/// Guest-visible origin metadata supplied by the trusted source-capture host.
///
/// These values never authorize an I/O operation or serve as resolver keys.
/// The URL may distinguish separate ESM query/fragment instances of one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSourceLocation {
    pub filename: PathBuf,
    pub url: String,
}

impl ModuleSourceLocation {
    /// Recognize the current module's trusted `createRequire` base without
    /// interpreting guest input as a path or looking up another module.
    /// The caller must select this location using its current opaque id;
    /// matching metadata never grants a different module's resolution routes.
    pub fn matches_create_require_origin(&self, origin: &str) -> bool {
        self.filename.is_absolute()
            && ((origin.starts_with("file://") && origin == self.url)
                || self.filename.to_str() == Some(origin))
    }
}

impl ExecutionModuleResolver {
    pub fn new(
        entry_referrer: impl Into<String>,
        resolver: Arc<dyn ModuleResolver + Send + Sync>,
        policy: Arc<dyn ModulePolicyHook + Send + Sync>,
    ) -> Self {
        Self {
            entry_referrer: entry_referrer.into(),
            resolver,
            policy,
            source_locations: Arc::default(),
        }
    }

    /// Bind capture-derived metadata to opaque module identities. This does
    /// not enable filesystem resolution or read the named files.
    pub fn with_source_locations(
        mut self,
        locations: BTreeMap<String, ModuleSourceLocation>,
    ) -> Self {
        self.source_locations = Arc::new(locations);
        self
    }

    pub fn source_location(&self, id: &str) -> Option<&ModuleSourceLocation> {
        self.source_locations.get(id)
    }

    pub fn entry_referrer(&self) -> &str {
        &self.entry_referrer
    }

    pub fn resolve(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
    ) -> ResolutionResult<ResolutionOutcome> {
        self.resolver
            .resolve(request, context, &ExecutionModulePolicy(self.policy.as_ref()))
    }

    pub fn resolve_shared(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
    ) -> ResolutionResult<SharedResolutionOutcome> {
        self.resolver.resolve_shared(
            request,
            context,
            &ExecutionModulePolicy(self.policy.as_ref()),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicModuleResolver {
    root_dir: String,
    builtins: BTreeMap<String, ModuleRecord>,
    workspace_modules: BTreeMap<String, ModuleRecord>,
    external_modules: BTreeMap<String, ModuleRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    external_packages: BTreeMap<String, ExternalPackageDefinition>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    external_package_wildcard_exports: BTreeMap<String, Vec<ExternalPackageWildcardExport>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExternalPackageResolutionError {
    code: ResolutionErrorCode,
    message: String,
    resolved_candidate: Option<String>,
    probe_sequence: Vec<String>,
}

impl Default for DeterministicModuleResolver {
    fn default() -> Self {
        Self::new("/")
    }
}

impl DeterministicModuleResolver {
    pub fn new(root_dir: impl Into<String>) -> Self {
        Self {
            root_dir: normalize_absolute_path(&root_dir.into()),
            builtins: BTreeMap::new(),
            workspace_modules: BTreeMap::new(),
            external_modules: BTreeMap::new(),
            external_packages: BTreeMap::new(),
            external_package_wildcard_exports: BTreeMap::new(),
        }
    }

    pub fn root_dir(&self) -> &str {
        &self.root_dir
    }

    pub fn register_builtin(
        &mut self,
        specifier: impl Into<String>,
        definition: ModuleDefinition,
    ) -> RegistryResult<()> {
        let specifier = specifier.into();
        if specifier.trim().is_empty() {
            return Err(RegistryError::empty_key());
        }
        let definition = apply_wasm_module_contract(&specifier, definition);
        let id = format!("builtin:{specifier}");
        let record = ModuleRecord::from_definition(id, ModuleSourceKind::BuiltIn, definition);
        self.builtins.insert(specifier, record);
        Ok(())
    }

    pub fn register_workspace_module(
        &mut self,
        path: impl Into<String>,
        definition: ModuleDefinition,
    ) -> RegistryResult<()> {
        let path = path.into();
        if path.trim().is_empty() {
            return Err(RegistryError::empty_key());
        }

        let absolute_path = if path.starts_with('/') {
            normalize_absolute_path(&path)
        } else {
            normalize_absolute_path(&join_paths(&self.root_dir, &path))
        };
        if !is_within_workspace_root(&self.root_dir, &absolute_path) {
            return Err(RegistryError::outside_root(&self.root_dir, &absolute_path));
        }

        let definition = apply_wasm_module_contract(&absolute_path, definition);
        let record = ModuleRecord::from_definition(
            absolute_path.clone(),
            ModuleSourceKind::Workspace,
            definition,
        );
        self.workspace_modules.insert(absolute_path, record);
        Ok(())
    }

    pub fn register_external_module(
        &mut self,
        specifier: impl Into<String>,
        definition: ModuleDefinition,
    ) -> RegistryResult<()> {
        let raw_specifier = specifier.into();
        if raw_specifier.trim().is_empty() {
            return Err(RegistryError::empty_key());
        }
        let specifier = normalize_external_specifier_path(&raw_specifier);
        if specifier.is_empty() {
            return Err(RegistryError::empty_key());
        }

        let definition = apply_wasm_module_contract(&specifier, definition);
        let id = format!("external:{specifier}");
        let record =
            ModuleRecord::from_definition(id, ModuleSourceKind::ExternalRegistry, definition);
        self.external_modules.insert(specifier, record);
        Ok(())
    }

    pub fn register_external_package(
        &mut self,
        mut package: ExternalPackageDefinition,
    ) -> RegistryResult<()> {
        if package.package_name.trim().is_empty() {
            return Err(RegistryError::empty_key());
        }

        package.package_name = normalize_registered_package_name(&package.package_name);
        if package.package_name.is_empty() {
            return Err(RegistryError::empty_key());
        }
        package.exports = package
            .exports
            .into_iter()
            .map(|(export_key, export_target)| {
                (normalize_package_export_key(&export_key), export_target)
            })
            .collect();

        let package_name = package.package_name.clone();
        let wildcard_exports = build_package_wildcard_exports(&package.exports);
        self.external_packages.insert(package_name.clone(), package);
        self.external_package_wildcard_exports
            .insert(package_name, wildcard_exports);
        Ok(())
    }

    fn resolve_candidate<'a>(
        &'a self,
        request: &ModuleRequest,
        context: &ResolutionContext,
    ) -> ResolutionResult<(String, &'a ModuleRecord, Vec<String>)> {
        let specifier = request.specifier.trim();
        let mut probe_sequence = Vec::new();
        if specifier.is_empty() {
            return Err(Box::new(
                ResolutionError::new(
                    ResolutionErrorCode::EmptySpecifier,
                    "module specifier must not be empty",
                    context,
                )
                .with_resolution_attempt(
                    request.specifier.clone(),
                    None,
                    None,
                    Vec::new(),
                ),
            ));
        }

        if let Some(record) = self.builtins.get(specifier) {
            probe_sequence.push(specifier.to_string());
            return Ok((specifier.to_string(), record, probe_sequence));
        }

        if is_relative_specifier(specifier) {
            let referrer = match request.referrer.as_deref() {
                Some(referrer) => referrer,
                None => {
                    return Err(Box::new(
                        ResolutionError::new(
                            ResolutionErrorCode::InvalidReferrer,
                            format!(
                                "relative specifier '{}' requires a referrer module",
                                request.specifier
                            ),
                            context,
                        )
                        .with_resolution_attempt(
                            request.specifier.clone(),
                            None,
                            None,
                            probe_sequence.clone(),
                        ),
                    ));
                }
            };
            let allow_probes = self.allow_relative_import_probes(request, referrer);
            if let Some(external_referrer) = referrer.strip_prefix("external:") {
                let normalized_external_referrer =
                    normalize_external_specifier_path(external_referrer);
                if external_referrer_must_be_registered(&normalized_external_referrer)
                    && !self
                        .external_modules
                        .contains_key(&normalized_external_referrer)
                {
                    return Err(Box::new(
                        ResolutionError::new(
                            ResolutionErrorCode::InvalidReferrer,
                            format!("external referrer '{}' is not registered", referrer),
                            context,
                        )
                        .with_resolution_attempt(
                            request.specifier.clone(),
                            None,
                            None,
                            probe_sequence.clone(),
                        ),
                    ));
                }
                let package_root = external_package_root(&normalized_external_referrer);
                let base_dir = external_referrer_directory(&normalized_external_referrer);
                let resolved_base =
                    normalize_external_specifier_path(&join_paths(&base_dir, specifier));
                if !is_within_external_package_root(&package_root, &resolved_base) {
                    return Err(Box::new(
                        ResolutionError::new(
                            ResolutionErrorCode::UnsupportedSpecifier,
                            format!(
                                "relative specifier '{}' escapes external package root '{}'",
                                request.specifier, package_root
                            ),
                            context,
                        )
                        .with_resolution_attempt(
                            request.specifier.clone(),
                            Some(resolved_base),
                            Some(ModuleSourceKind::ExternalRegistry),
                            probe_sequence,
                        ),
                    ));
                }
                let (relative_probes, candidate) = self.lookup_external_candidate(
                    &resolved_base,
                    request.style,
                    request.compatibility_mode,
                    allow_probes,
                );
                probe_sequence.extend(relative_probes);
                return match candidate {
                    Some((resolved, record)) => Ok((resolved, record, probe_sequence)),
                    None => Err(Box::new(
                        ResolutionError::new(
                            ResolutionErrorCode::ModuleNotFound,
                            format!(
                                "unable to resolve relative specifier '{}' from '{}'",
                                request.specifier, referrer
                            ),
                            context,
                        )
                        .with_resolution_attempt(
                            request.specifier.clone(),
                            None,
                            None,
                            probe_sequence,
                        ),
                    )),
                };
            }
            let base_dir = match self.referrer_directory(referrer, context) {
                Ok(base_dir) => base_dir,
                Err(error) => {
                    return Err(Box::new((*error).with_resolution_attempt(
                        request.specifier.clone(),
                        None,
                        None,
                        probe_sequence.clone(),
                    )));
                }
            };
            let resolved_base = normalize_absolute_path(&join_paths(&base_dir, specifier));
            if !is_within_workspace_root(&self.root_dir, &resolved_base) {
                return Err(Box::new(
                    ResolutionError::new(
                        ResolutionErrorCode::UnsupportedSpecifier,
                        format!(
                            "relative specifier '{}' escapes workspace root '{}'",
                            request.specifier, self.root_dir
                        ),
                        context,
                    )
                    .with_resolution_attempt(
                        request.specifier.clone(),
                        Some(resolved_base),
                        Some(ModuleSourceKind::Workspace),
                        probe_sequence,
                    ),
                ));
            }
            let (relative_probes, candidate) = self.lookup_workspace_candidate(
                &resolved_base,
                request.style,
                request.compatibility_mode,
                allow_probes,
            );
            probe_sequence.extend(relative_probes);
            return match candidate {
                Some((resolved, record)) => Ok((resolved, record, probe_sequence)),
                None => Err(Box::new(
                    ResolutionError::new(
                        ResolutionErrorCode::ModuleNotFound,
                        format!(
                            "unable to resolve relative specifier '{}' from '{}'",
                            request.specifier, referrer
                        ),
                        context,
                    )
                    .with_resolution_attempt(
                        request.specifier.clone(),
                        None,
                        None,
                        probe_sequence,
                    ),
                )),
            };
        }

        if specifier.starts_with('/') {
            let resolved_base = normalize_absolute_path(specifier);
            if !is_within_workspace_root(&self.root_dir, &resolved_base) {
                return Err(Box::new(
                    ResolutionError::new(
                        ResolutionErrorCode::UnsupportedSpecifier,
                        format!(
                            "absolute specifier '{}' escapes workspace root '{}'",
                            request.specifier, self.root_dir
                        ),
                        context,
                    )
                    .with_resolution_attempt(
                        request.specifier.clone(),
                        Some(resolved_base),
                        Some(ModuleSourceKind::Workspace),
                        probe_sequence,
                    ),
                ));
            }
            let (absolute_probes, candidate) = self.lookup_workspace_candidate(
                &resolved_base,
                request.style,
                request.compatibility_mode,
                true,
            );
            probe_sequence.extend(absolute_probes);
            return match candidate {
                Some((resolved, record)) => Ok((resolved, record, probe_sequence)),
                None => Err(Box::new(
                    ResolutionError::new(
                        ResolutionErrorCode::ModuleNotFound,
                        format!("unable to resolve absolute specifier '{specifier}'"),
                        context,
                    )
                    .with_resolution_attempt(
                        request.specifier.clone(),
                        None,
                        None,
                        probe_sequence,
                    ),
                )),
            };
        }

        if let Some(package_candidate) =
            self.resolve_external_package_candidate(specifier, request.style)
        {
            return match package_candidate {
                Ok((resolved, record, package_probes)) => {
                    probe_sequence.extend(package_probes);
                    Ok((resolved, record, probe_sequence))
                }
                Err(error) => {
                    probe_sequence.extend(error.probe_sequence);
                    Err(Box::new(
                        ResolutionError::new(error.code, error.message, context)
                            .with_resolution_attempt(
                                request.specifier.clone(),
                                error.resolved_candidate,
                                Some(ModuleSourceKind::ExternalRegistry),
                                probe_sequence,
                            ),
                    ))
                }
            };
        }

        let (external_probes, external_candidate) = self.lookup_external_candidate(
            specifier,
            request.style,
            request.compatibility_mode,
            true,
        );
        probe_sequence.extend(external_probes);
        if let Some((resolved, record)) = external_candidate {
            return Ok((resolved, record, probe_sequence));
        }

        let workspace_base = normalize_absolute_path(&join_paths(&self.root_dir, specifier));
        if !is_within_workspace_root(&self.root_dir, &workspace_base) {
            return Err(Box::new(
                ResolutionError::new(
                    ResolutionErrorCode::UnsupportedSpecifier,
                    format!(
                        "bare specifier '{}' escapes workspace root '{}'",
                        request.specifier, self.root_dir
                    ),
                    context,
                )
                .with_resolution_attempt(
                    request.specifier.clone(),
                    Some(workspace_base),
                    Some(ModuleSourceKind::Workspace),
                    probe_sequence,
                ),
            ));
        }
        let (workspace_probes, workspace_candidate) = self.lookup_workspace_candidate(
            &workspace_base,
            request.style,
            request.compatibility_mode,
            true,
        );
        probe_sequence.extend(workspace_probes);
        if let Some((resolved, record)) = workspace_candidate {
            return Ok((resolved, record, probe_sequence));
        }

        Err(Box::new(
            ResolutionError::new(
                ResolutionErrorCode::ModuleNotFound,
                format!("unable to resolve bare specifier '{specifier}'"),
                context,
            )
            .with_resolution_attempt(
                request.specifier.clone(),
                None,
                None,
                probe_sequence,
            ),
        ))
    }

    fn referrer_directory(
        &self,
        referrer: &str,
        context: &ResolutionContext,
    ) -> ResolutionResult<String> {
        if referrer.starts_with("builtin:") {
            return Err(Box::new(ResolutionError::new(
                ResolutionErrorCode::UnsupportedSpecifier,
                format!(
                    "relative resolution from non-workspace referrer '{}' is not supported",
                    referrer
                ),
                context,
            )));
        }

        let normalized = if referrer.starts_with('/') {
            normalize_absolute_path(referrer)
        } else {
            normalize_absolute_path(&join_paths(&self.root_dir, referrer))
        };
        if !is_within_workspace_root(&self.root_dir, &normalized) {
            return Err(Box::new(ResolutionError::new(
                ResolutionErrorCode::InvalidReferrer,
                format!(
                    "workspace referrer '{}' escapes resolver root '{}'",
                    referrer, self.root_dir
                ),
                context,
            )));
        }
        if !self.workspace_modules.contains_key(&normalized) {
            return Err(Box::new(ResolutionError::new(
                ResolutionErrorCode::InvalidReferrer,
                format!("workspace referrer '{}' is not registered", referrer),
                context,
            )));
        }
        Ok(parent_directory(&normalized))
    }

    fn lookup_workspace_candidate<'a>(
        &'a self,
        resolved_base: &str,
        style: ImportStyle,
        compatibility_mode: CompatibilityMode,
        allow_probes: bool,
    ) -> (Vec<String>, Option<(String, &'a ModuleRecord)>) {
        let mut probes = Vec::new();
        let candidates = if allow_probes {
            candidate_paths(resolved_base, style, compatibility_mode)
        } else {
            vec![resolved_base.to_string()]
        };
        for candidate in candidates {
            probes.push(candidate.clone());
            if let Some(record) = self.workspace_modules.get(&candidate) {
                return (probes, Some((candidate, record)));
            }
        }
        (probes, None)
    }

    fn lookup_external_candidate<'a>(
        &'a self,
        specifier: &str,
        style: ImportStyle,
        compatibility_mode: CompatibilityMode,
        allow_probes: bool,
    ) -> (Vec<String>, Option<(String, &'a ModuleRecord)>) {
        let mut probes = Vec::new();
        let candidates = if allow_probes {
            candidate_paths(specifier, style, compatibility_mode)
        } else {
            vec![specifier.to_string()]
        };
        for candidate in candidates {
            probes.push(candidate.clone());
            if let Some(record) = self.external_modules.get(&candidate) {
                return (probes, Some((candidate, record)));
            }
        }
        (probes, None)
    }

    #[allow(clippy::type_complexity)]
    fn resolve_external_package_candidate<'a>(
        &'a self,
        specifier: &str,
        style: ImportStyle,
    ) -> Option<Result<(String, &'a ModuleRecord, Vec<String>), ExternalPackageResolutionError>>
    {
        let (package_name, export_key) = parse_package_specifier(specifier)?;
        let package = self.external_packages.get(&package_name)?;
        let wildcard_exports = self
            .external_package_wildcard_exports
            .get(&package_name)
            .map(Vec::as_slice);

        let mut probe_sequence = vec![specifier.to_string()];
        let Some((export_target, capture)) =
            resolve_package_export_target(package, wildcard_exports, &export_key)
        else {
            return Some(Err(ExternalPackageResolutionError {
                code: ResolutionErrorCode::UnsupportedSpecifier,
                message: format!("package '{package_name}' has no export entry for '{export_key}'"),
                resolved_candidate: None,
                probe_sequence,
            }));
        };

        let Some((path_template, selected_condition)) =
            resolve_package_export_path(export_target, style)
        else {
            return Some(Err(ExternalPackageResolutionError {
                code: ResolutionErrorCode::UnsupportedSpecifier,
                message: format!(
                    "package '{package_name}' export '{export_key}' has no matching '{}' or default condition target",
                    style.as_str()
                ),
                resolved_candidate: None,
                probe_sequence,
            }));
        };

        let rendered = apply_wildcard_capture(path_template, &capture);
        let candidate =
            normalize_external_specifier_path(&join_paths(&package.package_name, &rendered));
        if probe_sequence.last() != Some(&candidate) {
            probe_sequence.push(candidate.clone());
        }
        if !is_within_external_package_root(&package.package_name, &candidate) {
            return Some(Err(ExternalPackageResolutionError {
                code: ResolutionErrorCode::UnsupportedSpecifier,
                message: format!(
                    "package '{package_name}' export '{export_key}' resolved via condition '{selected_condition}' to '{candidate}', which escapes the package root"
                ),
                resolved_candidate: Some(candidate),
                probe_sequence,
            }));
        }

        match self.external_modules.get(&candidate) {
            Some(record) => Some(Ok((candidate, record, probe_sequence))),
            None => Some(Err(ExternalPackageResolutionError {
                code: ResolutionErrorCode::ModuleNotFound,
                message: format!(
                    "package '{package_name}' export '{export_key}' resolved via condition '{selected_condition}' to '{candidate}', but no module was registered at that target"
                ),
                resolved_candidate: Some(candidate),
                probe_sequence,
            })),
        }
    }

    fn referrer_module_syntax(&self, referrer: &str) -> Option<ModuleSyntax> {
        if let Some(external_referrer) = referrer.strip_prefix("external:") {
            let normalized_external_referrer = normalize_external_specifier_path(external_referrer);
            return self
                .external_modules
                .get(&normalized_external_referrer)
                .map(|record| record.syntax);
        }
        if let Some(builtin_referrer) = referrer.strip_prefix("builtin:") {
            return self
                .builtins
                .get(builtin_referrer)
                .map(|record| record.syntax);
        }

        let normalized = if referrer.starts_with('/') {
            normalize_absolute_path(referrer)
        } else {
            normalize_absolute_path(&join_paths(&self.root_dir, referrer))
        };
        self.workspace_modules
            .get(&normalized)
            .map(|record| record.syntax)
    }

    fn allow_relative_import_probes(&self, request: &ModuleRequest, referrer: &str) -> bool {
        if request.style != ImportStyle::Import
            || request.compatibility_mode == CompatibilityMode::BunCompat
        {
            return true;
        }

        if referrer.starts_with("external:") {
            return matches!(
                self.referrer_module_syntax(referrer),
                Some(ModuleSyntax::CommonJs)
            );
        }

        !matches!(
            self.referrer_module_syntax(referrer),
            Some(ModuleSyntax::EsModule | ModuleSyntax::Wasm)
        )
    }
}

// Borrow registered source until every graph edge has passed the ordinary
// resolver and policy checks. This is per-call work, not an authorization or
// content cache: duplicate edges still resolve and authorize independently.
#[derive(Debug)]
struct AuthorizedModuleCandidate<'a> {
    request_specifier: String,
    canonical_specifier: String,
    record: &'a ModuleRecord,
    probe_sequence: Vec<String>,
}

impl AuthorizedModuleCandidate<'_> {
    fn into_outcome(self, context: &ResolutionContext) -> ResolutionOutcome {
        ResolutionOutcome {
            module: ResolvedModule {
                request_specifier: self.request_specifier,
                canonical_specifier: self.canonical_specifier,
                record: self.record.clone(),
                content_hash: self.record.canonical_hash(),
                probe_sequence: self.probe_sequence,
            },
            event: success_event(context),
        }
    }
}

impl DeterministicModuleResolver {
    fn resolve_authorized(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<AuthorizedModuleCandidate<'_>> {
        let (canonical_specifier, record, probe_sequence) =
            self.resolve_candidate(request, context)?;
        if request.style == ImportStyle::Require && record.syntax == ModuleSyntax::Wasm {
            return Err(Box::new(
                ResolutionError::new(
                    ResolutionErrorCode::UnsupportedSpecifier,
                    format!(
                        "require() of WebAssembly module '{}' is not supported; use import with explicit wasm capabilities",
                        canonical_specifier
                    ),
                    context,
                )
                .with_resolution_attempt(
                    request.specifier.clone(),
                    Some(canonical_specifier.clone()),
                    Some(record.provenance.kind),
                    probe_sequence.clone(),
                ),
            ));
        }
        if request.style == ImportStyle::Require
            && record.syntax == ModuleSyntax::EsModule
            && request.compatibility_mode != CompatibilityMode::BunCompat
        {
            return Err(Box::new(
                ResolutionError::new(
                    ResolutionErrorCode::UnsupportedSpecifier,
                    format!(
                        "ERR_REQUIRE_ESM: require() of ES module '{}' is not supported; use dynamic import() or provide a CommonJS entry point",
                        canonical_specifier
                    ),
                    context,
                )
                .with_resolution_attempt(
                    request.specifier.clone(),
                    Some(canonical_specifier.clone()),
                    Some(record.provenance.kind),
                    probe_sequence.clone(),
                ),
            ));
        }
        policy
            .authorize(request, record, context)
            .map_err(|error| {
                Box::new((*error).into_policy_denial().with_resolution_attempt(
                    request.specifier.clone(),
                    Some(canonical_specifier.clone()),
                    Some(record.provenance.kind),
                    probe_sequence.clone(),
                ))
            })?;

        Ok(AuthorizedModuleCandidate {
            request_specifier: request.specifier.clone(),
            canonical_specifier,
            record,
            probe_sequence,
        })
    }

    fn resolve_chain_records(
        &self,
        entry_request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<Vec<AuthorizedModuleCandidate<'_>>> {
        let entry = self.resolve_authorized(entry_request, context, policy)?;
        let mut visited = BTreeSet::from([entry.record.id.as_str()]);
        let mut outcomes = vec![entry];
        let mut parent_index = 0;

        // First-discovery order is already a breadth-first parent queue. Scan
        // each borrowed dependency slice directly instead of eagerly cloning
        // every outgoing edge into a second request queue.
        while parent_index < outcomes.len() {
            let parent = outcomes[parent_index].record;
            parent_index += 1;
            for dependency in &parent.dependencies {
                let request =
                    ModuleRequest::new(dependency.specifier.clone(), dependency.style)
                        .with_referrer(parent.id.as_str())
                        .with_compatibility_mode(entry_request.compatibility_mode);
                // Duplicate edges, cycles and differently styled aliases still
                // perform their complete lookup, format and policy checks.
                let outcome = self.resolve_authorized(&request, context, policy)?;
                if visited.insert(outcome.record.id.as_str()) {
                    outcomes.push(outcome);
                }
            }
        }
        Ok(outcomes)
    }
}

impl ModuleResolver for DeterministicModuleResolver {
    fn resolve(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<ResolutionOutcome> {
        Ok(self
            .resolve_authorized(request, context, policy)?
            .into_outcome(context))
    }

    fn resolve_chain(
        &self,
        entry_request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<Vec<ResolutionOutcome>> {
        // Materialize and hash only distinct records after the complete graph
        // is admitted. A later denial returns no partial graph and performs no
        // source cloning or hashing for earlier candidates.
        Ok(self
            .resolve_chain_records(entry_request, context, policy)?
            .into_iter()
            .map(|candidate| candidate.into_outcome(context))
            .collect())
    }
}

fn success_event(context: &ResolutionContext) -> ResolutionEvent {
    ResolutionEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: "module_resolver".to_string(),
        event: "module_resolution".to_string(),
        outcome: "allow".to_string(),
        error_code: "none".to_string(),
    }
}

fn error_event(context: &ResolutionContext, code: ResolutionErrorCode) -> ResolutionEvent {
    ResolutionEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: "module_resolver".to_string(),
        event: "module_resolution".to_string(),
        outcome: "deny".to_string(),
        error_code: code.stable_code().to_string(),
    }
}

fn is_relative_specifier(specifier: &str) -> bool {
    specifier == "."
        || specifier == ".."
        || specifier.starts_with("./")
        || specifier.starts_with("../")
}

fn candidate_paths(
    base: &str,
    style: ImportStyle,
    compatibility_mode: CompatibilityMode,
) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();

    let mut push = |candidate: String| {
        if seen.insert(candidate.clone()) {
            candidates.push(candidate);
        }
    };

    push(base.to_string());

    if is_module_file_name(base) {
        return candidates;
    }

    let suffixes: Vec<&str> = match style {
        ImportStyle::Import => vec![".mjs", ".js", "/index.mjs", "/index.js"],
        ImportStyle::Require => {
            let mut suffixes = vec![".cjs", ".js", "/index.cjs", "/index.js"];
            if compatibility_mode == CompatibilityMode::BunCompat {
                suffixes.extend([".mjs", "/index.mjs"]);
            }
            suffixes
        }
    };

    for suffix in suffixes {
        push(format!("{base}{suffix}"));
    }

    candidates
}

fn package_condition_order(style: ImportStyle) -> &'static [&'static str] {
    match style {
        ImportStyle::Import => &["import", "default"],
        ImportStyle::Require => &["require", "default"],
    }
}

fn normalize_registered_package_name(package_name: &str) -> String {
    let normalized = normalize_external_specifier_path(package_name.trim());
    external_package_root(&normalized)
}

fn normalize_package_export_key(export_key: &str) -> String {
    let trimmed = export_key.trim();
    if trimmed.is_empty() || trimmed == "." {
        return ".".to_string();
    }

    let stripped = trimmed
        .strip_prefix("./")
        .or_else(|| trimmed.strip_prefix('/'))
        .unwrap_or(trimmed);
    let normalized = normalize_external_specifier_path(stripped);
    if normalized.is_empty() {
        ".".to_string()
    } else {
        format!("./{normalized}")
    }
}

fn parse_package_specifier(specifier: &str) -> Option<(String, String)> {
    if specifier.starts_with('.') || specifier.starts_with('/') {
        return None;
    }

    let mut segments = specifier.split('/');
    let first = segments.next()?;
    if first.is_empty() {
        return None;
    }

    let (package_name, tail) = if first.starts_with('@') {
        let second = segments.next()?;
        (
            format!("{first}/{second}"),
            specifier[first.len() + 1 + second.len()..]
                .strip_prefix('/')
                .unwrap_or(""),
        )
    } else {
        (
            first.to_string(),
            specifier[first.len()..].strip_prefix('/').unwrap_or(""),
        )
    };

    let export_key = if tail.is_empty() && !specifier.ends_with('/') {
        ".".to_string()
    } else {
        format!("./{tail}")
    };

    Some((package_name, export_key))
}

fn resolve_package_export_target<'a>(
    package: &'a ExternalPackageDefinition,
    wildcard_exports: Option<&'a [ExternalPackageWildcardExport]>,
    export_key: &str,
) -> Option<(&'a ExternalPackageExportTarget, String)> {
    if let Some(exact) = package.exports.get(export_key) {
        return Some((exact, String::new()));
    }

    if let Some(wildcard_exports) = wildcard_exports {
        for wildcard in wildcard_exports {
            let Some(capture) = capture_single_wildcard(&wildcard.pattern, export_key) else {
                continue;
            };
            if let Some(target) = package.exports.get(&wildcard.pattern) {
                return Some((target, capture));
            }
        }
        return None;
    }

    resolve_package_export_target_by_scanning(&package.exports, export_key)
}

fn resolve_package_export_target_by_scanning<'a>(
    exports: &'a BTreeMap<String, ExternalPackageExportTarget>,
    export_key: &str,
) -> Option<(&'a ExternalPackageExportTarget, String)> {
    let mut wildcard_matches = Vec::new();
    for (pattern, target) in exports {
        let Some(capture) = capture_single_wildcard(pattern, export_key) else {
            continue;
        };
        wildcard_matches.push((pattern_specificity(pattern), pattern, target, capture));
    }

    wildcard_matches.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(right.1)));
    wildcard_matches
        .into_iter()
        .next()
        .map(|(_, _, target, capture)| (target, capture))
}

fn build_package_wildcard_exports(
    exports: &BTreeMap<String, ExternalPackageExportTarget>,
) -> Vec<ExternalPackageWildcardExport> {
    let mut wildcard_exports: Vec<_> = exports
        .keys()
        .filter(|pattern| has_single_wildcard(pattern))
        .map(|pattern| ExternalPackageWildcardExport {
            pattern: pattern.clone(),
            specificity: pattern_specificity(pattern),
        })
        .collect();
    wildcard_exports.sort_by(|left, right| {
        right
            .specificity
            .cmp(&left.specificity)
            .then(left.pattern.cmp(&right.pattern))
    });
    wildcard_exports
}

fn has_single_wildcard(pattern: &str) -> bool {
    let Some(wildcard_index) = pattern.find('*') else {
        return false;
    };
    !pattern[wildcard_index + 1..].contains('*')
}

fn resolve_package_export_path(
    export_target: &ExternalPackageExportTarget,
    style: ImportStyle,
) -> Option<(&str, String)> {
    for condition in package_condition_order(style) {
        if let Some(path_template) = export_target.condition_targets.get(*condition) {
            return Some((path_template.as_str(), (*condition).to_string()));
        }
    }

    export_target
        .fallback_target
        .as_deref()
        .map(|path| (path, "fallback".to_string()))
}

fn capture_single_wildcard(pattern: &str, value: &str) -> Option<String> {
    let wildcard_index = pattern.find('*')?;
    if pattern[wildcard_index + 1..].contains('*') {
        return None;
    }

    let prefix = &pattern[..wildcard_index];
    let suffix = &pattern[wildcard_index + 1..];
    if !value.starts_with(prefix) || !value.ends_with(suffix) {
        return None;
    }

    let capture_start = prefix.len();
    let capture_end = value.len().checked_sub(suffix.len())?;
    if capture_start > capture_end {
        return None;
    }

    Some(value[capture_start..capture_end].to_string())
}

fn apply_wildcard_capture(template: &str, capture: &str) -> String {
    match template.find('*') {
        Some(index) => {
            let mut output = String::new();
            output.push_str(&template[..index]);
            output.push_str(capture);
            output.push_str(&template[index + 1..]);
            output
        }
        None => template.to_string(),
    }
}

fn pattern_specificity(pattern: &str) -> usize {
    pattern.chars().filter(|ch| *ch != '*').count()
}

fn normalize_absolute_path(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            value => stack.push(value),
        }
    }

    if stack.is_empty() {
        return "/".to_string();
    }

    format!("/{}", stack.join("/"))
}

fn is_within_workspace_root(root_dir: &str, path: &str) -> bool {
    if root_dir == "/" {
        return path.starts_with('/');
    }

    path == root_dir
        || path
            .strip_prefix(root_dir)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn join_paths(base: &str, child: &str) -> String {
    if child.starts_with('/') {
        return child.to_string();
    }

    if base.ends_with('/') {
        format!("{base}{child}")
    } else {
        format!("{base}/{child}")
    }
}

fn normalize_external_specifier_path(path: &str) -> String {
    normalize_absolute_path(&format!("/{path}"))
        .trim_start_matches('/')
        .to_string()
}

fn external_package_root(referrer: &str) -> String {
    let normalized = normalize_external_specifier_path(referrer);
    let segments: Vec<&str> = normalized
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return normalized;
    }

    let package_root_len = if segments[0].starts_with('@') {
        segments.len().min(2)
    } else {
        1
    };
    let mut package_root = segments[..package_root_len]
        .iter()
        .map(|segment| (*segment).to_string())
        .collect::<Vec<_>>();
    let subpath = &segments[package_root_len..];
    if subpath.is_empty()
        && let Some(last) = package_root.last_mut()
        && is_module_file_name(last)
    {
        *last = strip_module_file_extension(last);
    }
    package_root.join("/")
}

fn is_within_external_package_root(package_root: &str, path: &str) -> bool {
    path == package_root
        || path
            .strip_prefix(package_root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn external_referrer_must_be_registered(referrer: &str) -> bool {
    let normalized = normalize_external_specifier_path(referrer);
    normalized != external_package_root(&normalized)
}

fn external_referrer_directory(referrer: &str) -> String {
    let normalized = normalize_external_specifier_path(referrer);
    let segments: Vec<&str> = normalized
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if segments.is_empty() {
        return normalized;
    }

    let package_root_len = if segments[0].starts_with('@') {
        segments.len().min(2)
    } else {
        1
    };
    let mut package_root = segments[..package_root_len]
        .iter()
        .map(|segment| (*segment).to_string())
        .collect::<Vec<_>>();
    let subpath = &segments[package_root_len..];

    if subpath.is_empty() {
        if let Some(last) = package_root.last_mut()
            && is_module_file_name(last)
        {
            *last = strip_module_file_extension(last);
        }
        return package_root.join("/");
    }

    if subpath.len() == 1 {
        return package_root.join("/");
    }

    package_root.extend(
        subpath[..subpath.len() - 1]
            .iter()
            .map(|segment| (*segment).to_string()),
    );
    package_root.join("/")
}

fn is_module_file_name(name: &str) -> bool {
    name.ends_with(".mjs")
        || name.ends_with(".cjs")
        || name.ends_with(".js")
        || name.ends_with(".wasm")
}

fn strip_module_file_extension(name: &str) -> String {
    name.strip_suffix(".mjs")
        .or_else(|| name.strip_suffix(".cjs"))
        .or_else(|| name.strip_suffix(".js"))
        .or_else(|| name.strip_suffix(".wasm"))
        .unwrap_or(name)
        .to_string()
}

fn parent_directory(path: &str) -> String {
    let normalized = normalize_absolute_path(path);
    if normalized == "/" {
        return normalized;
    }

    match normalized.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(index) => normalized[..index].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ResolutionContext {
        ResolutionContext::new("trace-1", "decision-1", "policy-1")
    }

    #[test]
    fn shared_records_move_source_and_hash_immutable_bytes_lazily() {
        let record = ModuleRecord::from_definition(
            "captured:dependency".into(),
            ModuleSourceKind::Workspace,
            ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 42;"),
        );
        let source = record.source.as_ptr();
        let expected = ContentHash::compute(&encode_value(&record.canonical_value()));
        let shared = Arc::new(SharedModuleRecord::new(record));
        assert_eq!(shared.source.as_ptr(), source);
        assert!(shared.canonical_hash.get().is_none());
        let mut owned = shared.record().clone();
        owned.source = "module.exports = 99;".into();
        assert_ne!(owned.canonical_hash(), expected);
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || shared.canonical_hash())
            })
            .collect();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), expected);
        }
        assert_eq!(shared.canonical_hash.get(), Some(&expected));
        assert_eq!(shared.source.as_ptr(), source);
        assert_eq!(shared.source, "module.exports = 42;");
    }

    #[test]
    fn owned_to_shared_delivery_preserves_unverified_hash_and_request_metadata() {
        let record = NativeBuiltinModule::Buffer.record("captured:buffer");
        let claimed_hash = ContentHash::compute(b"forged provider claim");
        let shared: SharedResolutionOutcome = ResolutionOutcome {
            module: ResolvedModule {
                request_specifier: "buffer".into(),
                canonical_specifier: record.id.clone(),
                record,
                content_hash: claimed_hash,
                probe_sequence: vec!["buffer".into(), "node:buffer".into()],
            },
            event: ResolutionEvent {
                trace_id: "current-trace".into(),
                decision_id: "current-decision".into(),
                policy_id: "current-policy".into(),
                component: "module_resolver".into(),
                event: "module_resolution".into(),
                outcome: "allow".into(),
                error_code: String::new(),
            },
        }
        .into();
        assert!(shared.module.record.canonical_hash.get().is_none());
        assert_eq!(shared.module.content_hash, claimed_hash);
        assert_eq!(shared.module.request_specifier, "buffer");
        assert_eq!(shared.module.canonical_specifier, "captured:buffer");
        assert_eq!(shared.module.probe_sequence, ["buffer", "node:buffer"]);
        assert_eq!(shared.event.trace_id, "current-trace");
        let repeated = shared.clone();
        assert!(Arc::ptr_eq(&shared.module.record, &repeated.module.record));
        assert_ne!(shared.module.record.canonical_hash(), claimed_hash);
        assert_eq!(
            NativeBuiltinModule::from_record(&shared.module.record),
            Some(NativeBuiltinModule::Buffer)
        );
    }

    #[test]
    fn create_require_origin_matches_exact_trusted_file_metadata() {
        let location = ModuleSourceLocation {
            filename: PathBuf::from("/original project/nested/entry.mjs"),
            url: "file:///original%20project/nested/entry.mjs?instance=2#kept".into(),
        };
        assert!(location.matches_create_require_origin(&location.url));
        assert!(location.matches_create_require_origin("/original project/nested/entry.mjs"));
        for origin in [
            "",
            "./entry.mjs",
            "/original project/entry.mjs",
            "file:///original%20project/nested/entry.mjs",
            "file:///original%20project/nested/entry.mjs?instance=1#kept",
            "file:///original%20project/nested/entry.mjs?instance=2#changed",
            "file:///original project/nested/entry.mjs?instance=2#kept",
            "captured:graph:entry",
        ] {
            assert!(!location.matches_create_require_origin(origin), "{origin}");
        }
        let non_file = ModuleSourceLocation {
            filename: PathBuf::from("/original/entry.mjs"),
            url: "https://example.test/entry.mjs".into(),
        };
        assert!(!non_file.matches_create_require_origin(&non_file.url));
        let relative_file = ModuleSourceLocation {
            filename: PathBuf::from("relative/entry.mjs"),
            url: "file:///relative/entry.mjs".into(),
        };
        assert!(!relative_file.matches_create_require_origin(&relative_file.url));
        assert!(!relative_file.matches_create_require_origin("relative/entry.mjs"));
        let empty_url = ModuleSourceLocation {
            filename: PathBuf::from("/original/entry.mjs"),
            url: String::new(),
        };
        assert!(!empty_url.matches_create_require_origin(""));
    }

    #[test]
    fn native_builtin_descriptors_bind_exact_provider_and_capabilities() {
        for name in [
            "buffer",
            "crypto",
            "zlib",
            "http",
            "https",
            "fs",
            "fs/promises",
            "module",
            "events",
            "os",
            "querystring",
            "url",
            "timers",
            "perf_hooks",
            "path",
            "path/posix",
            "path/win32",
            "util",
            "util/types",
            "assert",
            "assert/strict",
            "string_decoder",
            "timers/promises",
            "stream",
            "stream/promises",
            "stream/consumers",
            "stream/web",
            "readline",
            "readline/promises",
            "diagnostics_channel",
        ] {
            let builtin = NativeBuiltinModule::from_specifier(name).unwrap();
            assert_eq!(builtin.canonical_specifier(), format!("node:{name}"));
            assert_eq!(
                NativeBuiltinModule::from_specifier(&format!("node:{name}")),
                Some(builtin)
            );
            let record = builtin.record("captured:graph:terminal");
            assert_eq!(NativeBuiltinModule::from_record(&record), Some(builtin));
            assert!(record.source.is_empty());
            assert!(record.dependencies.is_empty());
            assert_eq!(record.provenance.kind, ModuleSourceKind::BuiltIn);
            assert!(
                record
                    .required_capabilities
                    .contains(&RuntimeCapability::ModuleLoad)
            );
            assert!(
                record
                    .required_capabilities
                    .contains(&RuntimeCapability::Builtin)
            );
            assert!(
                !record
                    .required_capabilities
                    .contains(&RuntimeCapability::RandomRead),
                "loading {name} must not require or grant entropy authority"
            );
            for effect in [
                RuntimeCapability::FsRead,
                RuntimeCapability::FsWrite,
                RuntimeCapability::NetworkEgress,
            ] {
                assert!(
                    !record.required_capabilities.contains(&effect),
                    "loading {name} must not require or grant {effect:?} authority"
                );
            }
            assert_eq!(
                record
                    .required_capabilities
                    .contains(&RuntimeCapability::Timer),
                matches!(
                    name,
                    "timers"
                        | "timers/promises"
                        | "stream"
                        | "stream/promises"
                        | "readline"
                        | "readline/promises"
                        | "diagnostics_channel"
                )
            );
            let request = ModuleRequest::new(name, ImportStyle::Require);
            let denied = CapabilityPolicyHook::new(BTreeSet::from([RuntimeCapability::ModuleLoad]));
            assert!(denied.authorize(&request, &record, &context()).is_err());
            let allowed = CapabilityPolicyHook::new(record.required_capabilities.clone());
            assert!(allowed.authorize(&request, &record, &context()).is_ok());
        }
        for name in [
            "fs/unknown",
            "path/unknown",
            "stream/unknown",
            "readline/unknown",
            "diagnostics_channel/unknown",
            "node:unknown",
            "node:node:buffer",
            "./buffer",
            "Buffer",
        ] {
            assert!(
                NativeBuiltinModule::from_specifier(name).is_none(),
                "{name}"
            );
        }
    }

    #[test]
    fn native_builtin_descriptor_cannot_smuggle_source_or_reduce_authority() {
        for builtin in [
            NativeBuiltinModule::Buffer,
            NativeBuiltinModule::Crypto,
            NativeBuiltinModule::Zlib,
            NativeBuiltinModule::Http,
            NativeBuiltinModule::Https,
            NativeBuiltinModule::Fs,
            NativeBuiltinModule::FsPromises,
            NativeBuiltinModule::StreamConsumers,
            NativeBuiltinModule::StreamWeb,
            NativeBuiltinModule::Readline,
            NativeBuiltinModule::ReadlinePromises,
            NativeBuiltinModule::DiagnosticsChannel,
        ] {
            let original = builtin.record("captured:graph:native");
            let mut forged = original.clone();
            forged.source = "module.exports = require('fs');".into();
            assert!(NativeBuiltinModule::from_record(&forged).is_none());
            forged = original.clone();
            forged
                .dependencies
                .push(ModuleDependency::new("fs", ImportStyle::Require));
            assert!(NativeBuiltinModule::from_record(&forged).is_none());
            forged = original.clone();
            forged
                .required_capabilities
                .remove(&RuntimeCapability::Builtin);
            assert!(NativeBuiltinModule::from_record(&forged).is_none());
            forged = original.clone();
            forged.provenance.kind = ModuleSourceKind::Workspace;
            assert!(NativeBuiltinModule::from_record(&forged).is_none());
            forged = original.clone();
            forged.provenance.origin = "franken-engine/native-builtin/v1:buffer".into();
            assert!(NativeBuiltinModule::from_record(&forged).is_none());
            forged = original.clone();
            forged.syntax = ModuleSyntax::EsModule;
            assert!(NativeBuiltinModule::from_record(&forged).is_none());
            forged = original;
            forged.id.clear();
            assert!(NativeBuiltinModule::from_record(&forged).is_none());
        }
    }

    #[test]
    fn builtin_resolution_is_deterministic() {
        let mut resolver = DeterministicModuleResolver::new("/workspace");
        resolver
            .register_builtin(
                "franken:std/fs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const read = true;")
                    .require_capability(RuntimeCapability::FsRead)
                    .with_provenance("builtin:franken:std/fs"),
            )
            .expect("serde serialization should succeed");

        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        let policy = CapabilityPolicyHook::new(granted);

        let request = ModuleRequest::new("franken:std/fs", ImportStyle::Import);
        // SAFETY: Test uses built-in module "franken:std/fs" which exists in resolver.
        // resolve() only fails for unknown modules or policy violations (both impossible here).
        let first = resolver
            .resolve(&request, &context(), &policy)
            .expect("serde serialization should succeed");
        // SAFETY: Same module request as above, guaranteed to succeed for same reasons.
        let second = resolver
            .resolve(&request, &context(), &policy)
            .expect("serde serialization should succeed");

        assert_eq!(first.module.canonical_specifier, "franken:std/fs");
        assert_eq!(first.module.record.id, "builtin:franken:std/fs");
        assert_eq!(first.module.content_hash, second.module.content_hash);
        assert_eq!(first.event.component, "module_resolver");
        assert_eq!(first.event.outcome, "allow");
        assert_eq!(first.event.error_code, "none");
        assert_eq!(first.module.probe_sequence, vec!["franken:std/fs"]);
        assert_eq!(first.module.probe_sequence, second.module.probe_sequence);
    }

    #[test]
    fn import_requires_explicit_relative_extension_outside_bun_compat() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './lib';"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/lib.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");

        let import_error = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Import).with_referrer("/app/main.mjs"),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("native mode should reject extensionless relative ESM imports");
        assert_eq!(import_error.code, ResolutionErrorCode::ModuleNotFound);
        assert_eq!(import_error.probe_sequence, vec!["/app/lib"]);

        let bun_import_outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Import)
                    .with_referrer("/app/main.mjs")
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("bun_compat should continue probing extensionless relative ESM imports");
        assert_eq!(
            bun_import_outcome.module.canonical_specifier,
            "/app/lib.mjs"
        );
        assert_eq!(
            bun_import_outcome.module.probe_sequence,
            vec!["/app/lib", "/app/lib.mjs"]
        );

        let require_request =
            ModuleRequest::new("./lib", ImportStyle::Require).with_referrer("/app/main.mjs");
        let require_outcome = resolver
            .resolve(&require_request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(require_outcome.module.canonical_specifier, "/app/lib.cjs");
        assert_eq!(
            require_outcome.module.probe_sequence,
            vec!["/app/lib", "/app/lib.cjs"]
        );
    }

    #[test]
    fn external_relative_import_requires_explicit_extension_outside_bun_compat() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "some-pkg/sub.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'sub';"),
            )
            .expect("serde serialization should succeed");

        let native_error = resolver
            .resolve(
                &ModuleRequest::new("./sub", ImportStyle::Import)
                    .with_referrer("external:some-pkg"),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("native mode should reject extensionless external ESM relatives");
        assert_eq!(native_error.code, ResolutionErrorCode::ModuleNotFound);
        assert_eq!(native_error.probe_sequence, vec!["some-pkg/sub"]);

        let node_error = resolver
            .resolve(
                &ModuleRequest::new("./sub", ImportStyle::Import)
                    .with_referrer("external:some-pkg")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("node_compat should reject extensionless external ESM relatives");
        assert_eq!(node_error.code, ResolutionErrorCode::ModuleNotFound);
        assert_eq!(node_error.probe_sequence, vec!["some-pkg/sub"]);

        let bun_outcome = resolver
            .resolve(
                &ModuleRequest::new("./sub", ImportStyle::Import)
                    .with_referrer("external:some-pkg")
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("bun_compat should keep probing external ESM relatives");
        assert_eq!(bun_outcome.module.canonical_specifier, "some-pkg/sub.mjs");
        assert_eq!(
            bun_outcome.module.probe_sequence,
            vec!["some-pkg/sub", "some-pkg/sub.mjs"]
        );
    }

    #[test]
    fn external_relative_specifier_cannot_escape_package_root() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "some-pkg/entry.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import '../other-pkg/private.mjs';"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "other-pkg/private.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'secret';"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("../other-pkg/private.mjs", ImportStyle::Import)
                    .with_referrer("external:some-pkg/entry.mjs"),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("external relative import must not escape its package root");
        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert!(
            error
                .message
                .contains("escapes external package root 'some-pkg'")
        );
        assert!(error.probe_sequence.is_empty());
    }

    #[test]
    fn external_relative_require_cannot_escape_package_root() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "some-pkg/entry.cjs",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "module.exports = require('../other-pkg/private.cjs');",
                ),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "other-pkg/private.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 42;"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("../other-pkg/private.cjs", ImportStyle::Require)
                    .with_referrer("external:some-pkg/entry.cjs"),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("external relative require must not escape its package root");
        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert!(
            error
                .message
                .contains("escapes external package root 'some-pkg'")
        );
        assert!(error.probe_sequence.is_empty());
    }

    #[test]
    fn external_package_root_strips_extension_probe_entry_suffix() {
        assert_eq!(external_package_root("pkg.js"), "pkg");
        assert_eq!(external_package_root("@scope/pkg.js"), "@scope/pkg");
        assert_eq!(external_package_root("pkg/index.cjs"), "pkg");
        assert_eq!(external_package_root("pkg/index.mjs"), "pkg");
        assert_eq!(external_package_root("@scope/pkg/index.mjs"), "@scope/pkg");
    }

    #[test]
    fn require_rejects_esm_resolution_even_when_extension_probing_finds_js() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_workspace_module(
                "/repo/pkg/index.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'esm';"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("pkg", ImportStyle::Require),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("require() of an ESM-only package entry must fail closed");

        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert_eq!(
            error.event.error_code,
            ResolutionErrorCode::UnsupportedSpecifier.stable_code()
        );
        assert!(error.message.contains("ERR_REQUIRE_ESM"));
        assert!(error.message.contains("/repo/pkg/index.js"));
    }

    #[test]
    fn require_allows_esm_resolution_in_bun_compat_mode() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_workspace_module(
                "/repo/pkg/index.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'esm';"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("pkg", ImportStyle::Require)
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("bun_compat should allow require() of ESM package entry");

        assert_eq!(outcome.module.canonical_specifier, "/repo/pkg/index.js");
        assert_eq!(outcome.module.record.syntax, ModuleSyntax::EsModule);
        assert_eq!(
            outcome.module.probe_sequence,
            vec![
                "pkg",
                "pkg.cjs",
                "pkg.js",
                "pkg/index.cjs",
                "pkg/index.js",
                "pkg.mjs",
                "pkg/index.mjs",
                "/repo/pkg",
                "/repo/pkg.cjs",
                "/repo/pkg.js",
                "/repo/pkg/index.cjs",
                "/repo/pkg/index.js"
            ]
        );
    }

    #[test]
    fn resolve_chain_propagates_bun_compat_mode_to_nested_require_dependencies() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_workspace_module(
                "/repo/main.cjs",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "const lib = require('./lib.mjs'); module.exports = lib;",
                )
                .with_dependency(ModuleDependency::new("./lib.mjs", ImportStyle::Require)),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/repo/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const value = 1;"),
            )
            .expect("serde serialization should succeed");

        let outcomes = resolver
            .resolve_chain(
                &ModuleRequest::new("/repo/main.cjs", ImportStyle::Require)
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("bun_compat should propagate to nested require() edges");

        let specifiers = outcomes
            .iter()
            .map(|outcome| outcome.module.canonical_specifier.as_str())
            .collect::<Vec<_>>();
        assert_eq!(specifiers, vec!["/repo/main.cjs", "/repo/lib.mjs"]);
        assert_eq!(outcomes[1].module.record.syntax, ModuleSyntax::EsModule);
    }

    #[test]
    fn policy_denies_missing_capabilities_with_stable_error_fields() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/secure.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 7;")
                    .require_capability(RuntimeCapability::FsWrite),
            )
            .expect("serde serialization should succeed");

        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        let policy = CapabilityPolicyHook::new(granted);

        let request = ModuleRequest::new("/app/secure.js", ImportStyle::Require);
        let error = resolver
            .resolve(&request, &context(), &policy)
            .expect_err("expected policy denial");

        assert_eq!(error.code, ResolutionErrorCode::PolicyDenied);
        assert_eq!(error.event.component, "module_resolver");
        assert_eq!(error.event.event, "module_resolution");
        assert_eq!(error.event.outcome, "deny");
        assert_eq!(
            error.event.error_code,
            ResolutionErrorCode::PolicyDenied.stable_code()
        );
        assert!(error.message.contains("fs_write"));
    }

    #[test]
    fn policy_error_codes_cannot_masquerade_as_optional_dependency_absence() {
        struct Refuse(ResolutionErrorCode);
        impl ModulePolicyHook for Refuse {
            fn authorize(
                &self,
                _request: &ModuleRequest,
                _resolved: &ModuleRecord,
                context: &ResolutionContext,
            ) -> ResolutionResult<()> {
                Err(Box::new(ResolutionError::new(self.0, "hidden resource", context)))
            }
        }

        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/dep.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 7;"),
            )
            .expect("fixture source");
        let request = ModuleRequest::new("/app/dep.cjs", ImportStyle::Require);
        for code in [
            ResolutionErrorCode::EmptySpecifier,
            ResolutionErrorCode::InvalidReferrer,
            ResolutionErrorCode::UnsupportedSpecifier,
            ResolutionErrorCode::ModuleNotFound,
            ResolutionErrorCode::PolicyDenied,
            ResolutionErrorCode::PackagePathNotExported,
            ResolutionErrorCode::PackageImportNotDefined,
        ] {
            let error = resolver
                .resolve(&request, &context(), &Refuse(code))
                .expect_err("a hook refusal is always a policy refusal");
            assert_eq!(error.code, ResolutionErrorCode::PolicyDenied);
            assert_eq!(error.event.error_code, ResolutionErrorCode::PolicyDenied.stable_code());
            assert_eq!(error.request_specifier, "/app/dep.cjs");
            assert!(error.message.contains("hidden resource"));
            if code != ResolutionErrorCode::PolicyDenied {
                assert!(error.message.contains(code.stable_code()));
            }
            let installed = ExecutionModuleResolver::new(
                "/app/entry.cjs",
                Arc::new(resolver.clone()),
                Arc::new(Refuse(code)),
            );
            let shared_error = installed
                .resolve_shared(&request, &context())
                .expect_err("shared delivery must preserve policy refusal normalization");
            assert_eq!(shared_error.code, ResolutionErrorCode::PolicyDenied);
            assert_eq!(shared_error.request_specifier, "/app/dep.cjs");
        }
    }

    #[test]
    fn external_resolution_preserves_provenance() {
        let mut resolver = DeterministicModuleResolver::new("/workspace");
        // SAFETY: Test scenario with valid module definition and provenance; registration should succeed
        resolver
            .register_external_module(
                "left-pad",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = function(){};")
                    .with_provenance("registry:npm:left-pad@1.3.0"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("left-pad", ImportStyle::Require);
        // SAFETY: Test scenario with valid request and registered module; resolution should succeed
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");

        assert_eq!(
            outcome.module.record.provenance.kind,
            ModuleSourceKind::ExternalRegistry
        );
        assert_eq!(
            outcome.module.record.provenance.origin,
            "registry:npm:left-pad@1.3.0"
        );
        assert_eq!(outcome.module.probe_sequence, vec!["left-pad"]);
    }

    #[test]
    fn relative_resolution_requires_referrer() {
        let resolver = DeterministicModuleResolver::default();
        let request = ModuleRequest::new("./dep", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("missing referrer should fail");

        assert_eq!(error.code, ResolutionErrorCode::InvalidReferrer);
        assert_eq!(
            error.event.error_code,
            ResolutionErrorCode::InvalidReferrer.stable_code()
        );
    }

    // -----------------------------------------------------------------------
    // Empty specifier rejection
    // -----------------------------------------------------------------------

    #[test]
    fn empty_specifier_returns_empty_specifier_error() {
        let resolver = DeterministicModuleResolver::default();
        let request = ModuleRequest::new("", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("empty specifier should fail");
        assert_eq!(error.code, ResolutionErrorCode::EmptySpecifier);
        assert_eq!(error.code.stable_code(), "FE-MODRES-0001");
    }

    #[test]
    fn whitespace_only_specifier_returns_empty_specifier_error() {
        let resolver = DeterministicModuleResolver::default();
        let request = ModuleRequest::new("   ", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("whitespace-only specifier should fail");
        assert_eq!(error.code, ResolutionErrorCode::EmptySpecifier);
    }

    // -----------------------------------------------------------------------
    // Empty key rejection for register methods
    // -----------------------------------------------------------------------

    #[test]
    fn register_builtin_with_empty_key_returns_error() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        let err = resolver
            .register_builtin("", ModuleDefinition::new(ModuleSyntax::EsModule, ""))
            .unwrap_err();
        assert_eq!(err.code, RegistryErrorCode::EmptyKey);
    }

    #[test]
    fn register_workspace_module_with_empty_path_returns_error() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        let err = resolver
            .register_workspace_module("", ModuleDefinition::new(ModuleSyntax::EsModule, ""))
            .unwrap_err();
        assert_eq!(err.code, RegistryErrorCode::EmptyKey);
    }

    #[test]
    fn register_external_module_with_empty_specifier_returns_error() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        let err = resolver
            .register_external_module("", ModuleDefinition::new(ModuleSyntax::CommonJs, ""))
            .unwrap_err();
        assert_eq!(err.code, RegistryErrorCode::EmptyKey);
    }

    #[test]
    fn register_external_module_normalizes_specifier_and_record_id() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "pkg/./entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("noncanonical external specifier should register canonically");

        assert!(!resolver.external_modules.contains_key("pkg/./entry.cjs"));
        let record = resolver
            .external_modules
            .get("pkg/entry.cjs")
            .expect("normalized external key should be stored");
        assert_eq!(record.id, "external:pkg/entry.cjs");
    }

    #[test]
    fn register_external_package_precomputes_sorted_wildcard_exports() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_package(
                ExternalPackageDefinition::new("wild-pkg")
                    .with_export(".", ExternalPackageExportTarget::default())
                    .with_export("./feature/*", ExternalPackageExportTarget::default())
                    .with_export(
                        "./feature/internal/*",
                        ExternalPackageExportTarget::default(),
                    )
                    .with_export("./invalid/*/*", ExternalPackageExportTarget::default()),
            )
            .expect("wildcard package should register");

        let wildcard_patterns: Vec<&str> = resolver
            .external_package_wildcard_exports
            .get("wild-pkg")
            .expect("wildcard index should be stored by normalized package name")
            .iter()
            .map(|wildcard| wildcard.pattern.as_str())
            .collect();

        assert_eq!(
            wildcard_patterns,
            vec!["./feature/internal/*", "./feature/*"]
        );
    }

    #[test]
    fn package_exports_reject_targets_that_escape_package_root() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        // SAFETY: Test scenario with valid package definition and exports; registration should succeed
        resolver
            .register_external_package(ExternalPackageDefinition::new("locked-pkg").with_export(
                ".",
                ExternalPackageExportTarget {
                    condition_targets: BTreeMap::from([(
                        "default".to_string(),
                        "../other-pkg/private.js".to_string(),
                    )]),
                    fallback_target: None,
                },
            ))
            .expect("serde serialization should succeed");
        // SAFETY: Test scenario with valid module definition; registration should succeed
        resolver
            .register_external_module(
                "other-pkg/private.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'secret';"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("locked-pkg", ImportStyle::Import),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("exports target must not escape the declaring package root");
        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert!(error.message.contains("escapes the package root"));
        assert_eq!(
            error.probe_sequence,
            vec!["locked-pkg", "other-pkg/private.js"]
        );
    }

    #[test]
    fn package_exports_fallback_target_resolves_when_no_condition_matches() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_package(ExternalPackageDefinition::new("fallback-pkg").with_export(
                ".",
                ExternalPackageExportTarget {
                    condition_targets: BTreeMap::new(),
                    fallback_target: Some("./dist/index.js".to_string()),
                },
            ))
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "fallback-pkg/dist/index.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 'fallback';"),
            )
            .expect("serde serialization should succeed");

        for style in [ImportStyle::Import, ImportStyle::Require] {
            let outcome = resolver
                .resolve(
                    &ModuleRequest::new("fallback-pkg", style),
                    &context(),
                    &AllowAllPolicy,
                )
                .unwrap_or_else(|error| {
                    // SAFETY: Test-only panic to validate fallback target resolution logic.
                    // Test expects successful resolution for all import styles with registered fallback.
                    panic!(
                        "fallback_target exports entry should resolve for style {style:?}: {error}"
                    )
                });
            assert_eq!(
                outcome.module.canonical_specifier,
                "fallback-pkg/dist/index.js"
            );
            assert_eq!(
                outcome.module.record.id,
                "external:fallback-pkg/dist/index.js"
            );
            assert_eq!(
                outcome.module.probe_sequence,
                vec!["fallback-pkg", "fallback-pkg/dist/index.js"]
            );
        }
    }

    // -----------------------------------------------------------------------
    // Module not found
    // -----------------------------------------------------------------------

    #[test]
    fn unresolvable_bare_specifier_returns_module_not_found() {
        let resolver = DeterministicModuleResolver::new("/workspace");
        let request = ModuleRequest::new("nonexistent-package", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("unregistered specifier should fail");
        assert_eq!(error.code, ResolutionErrorCode::ModuleNotFound);
        assert_eq!(error.code.stable_code(), "FE-MODRES-0004");
    }

    #[test]
    fn unresolvable_relative_specifier_returns_module_not_found() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, ""),
            )
            .expect("serde serialization should succeed");
        let request =
            ModuleRequest::new("./missing", ImportStyle::Import).with_referrer("/app/main.js");
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("missing relative should fail");
        assert_eq!(error.code, ResolutionErrorCode::ModuleNotFound);
    }

    // -----------------------------------------------------------------------
    // Absolute specifier resolution
    // -----------------------------------------------------------------------

    #[test]
    fn absolute_specifier_resolves_workspace_module() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/lib/util.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("/app/lib/util.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.module.canonical_specifier, "/app/lib/util.js");
    }

    // -----------------------------------------------------------------------
    // Bare specifier resolved from workspace
    // -----------------------------------------------------------------------

    #[test]
    fn bare_specifier_resolves_from_workspace_with_extension_probing() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/utils.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 42;"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("utils", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.module.canonical_specifier, "/app/utils.js");
        assert_eq!(
            outcome.module.probe_sequence,
            vec![
                "utils",
                "utils.mjs",
                "utils.js",
                "utils/index.mjs",
                "utils/index.js",
                "/app/utils",
                "/app/utils.mjs",
                "/app/utils.js"
            ]
        );
    }

    // -----------------------------------------------------------------------
    // Index file probing
    // -----------------------------------------------------------------------

    #[test]
    fn bun_compat_import_probes_index_mjs_for_directory_specifier() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './lib';"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/lib/index.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("./lib", ImportStyle::Import)
            .with_referrer("/app/main.mjs")
            .with_compatibility_mode(CompatibilityMode::BunCompat);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.module.canonical_specifier, "/app/lib/index.mjs");
    }

    #[test]
    fn require_probes_index_cjs_for_directory_specifier() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './lib';"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/lib/index.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");

        let request =
            ModuleRequest::new("./lib", ImportStyle::Require).with_referrer("/app/main.js");
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.module.canonical_specifier, "/app/lib/index.cjs");
    }

    // -----------------------------------------------------------------------
    // Relative resolution from non-workspace referrer
    // -----------------------------------------------------------------------

    #[test]
    fn relative_from_builtin_referrer_returns_unsupported_specifier() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_builtin(
                "franken:fs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const read = true;"),
            )
            .expect("serde serialization should succeed");

        let request =
            ModuleRequest::new("./sub", ImportStyle::Import).with_referrer("builtin:franken:fs");
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("relative from builtin referrer should fail");
        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert_eq!(error.code.stable_code(), "FE-MODRES-0003");
    }

    #[test]
    fn relative_from_unregistered_workspace_referrer_returns_invalid_referrer() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/sub.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let request =
            ModuleRequest::new("./sub.mjs", ImportStyle::Import).with_referrer("/app/missing.mjs");
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("relative resolution from missing workspace referrer should fail");
        assert_eq!(error.code, ResolutionErrorCode::InvalidReferrer);
        assert!(error.message.contains("not registered"));
        assert!(error.probe_sequence.is_empty());
    }

    #[test]
    fn relative_from_unregistered_external_file_referrer_returns_invalid_referrer() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/sub.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("./sub.mjs", ImportStyle::Import)
            .with_referrer("external:pkg/missing.mjs");
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("relative resolution from missing external file referrer should fail");
        assert_eq!(error.code, ResolutionErrorCode::InvalidReferrer);
        assert!(error.message.contains("not registered"));
        assert!(error.probe_sequence.is_empty());
    }

    #[test]
    fn normalized_external_file_referrer_resolves_relative_imports() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./sub');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/sub.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./sub", ImportStyle::Import)
                    .with_referrer("external:pkg/./entry.cjs"),
                &context(),
                &AllowAllPolicy,
            )
            .expect("normalized-equivalent external referrer should resolve");

        assert_eq!(outcome.module.canonical_specifier, "pkg/sub.js");
        assert_eq!(
            outcome.module.probe_sequence,
            vec!["pkg/sub", "pkg/sub.mjs", "pkg/sub.js"]
        );
    }

    #[test]
    fn node_compat_external_relative_require_skips_mjs_probes() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./lib');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("node_compat require should not probe .mjs candidates");
        assert_eq!(error.code, ResolutionErrorCode::ModuleNotFound);
        assert_eq!(
            error.probe_sequence,
            vec![
                "pkg/lib",
                "pkg/lib.cjs",
                "pkg/lib.js",
                "pkg/lib/index.cjs",
                "pkg/lib/index.js",
            ]
        );
    }

    #[test]
    fn node_compat_external_relative_require_esm_js_returns_err_require_esm() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./lib');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("node_compat require should reject ESM .js targets");
        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert!(error.message.contains("ERR_REQUIRE_ESM"));
        assert!(error.message.contains("pkg/lib.js"));
        assert_eq!(
            error.probe_sequence,
            vec!["pkg/lib", "pkg/lib.cjs", "pkg/lib.js"]
        );
    }

    #[test]
    fn node_compat_external_relative_require_explicit_mjs_returns_err_require_esm() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "module.exports = require('./lib.mjs');",
                ),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("./lib.mjs", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("node_compat require should reject explicit .mjs targets");
        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert!(error.message.contains("ERR_REQUIRE_ESM"));
        assert!(error.message.contains("pkg/lib.mjs"));
        assert_eq!(error.probe_sequence, vec!["pkg/lib.mjs"]);
    }

    #[test]
    fn node_compat_external_relative_require_explicit_js_esm_returns_err_require_esm() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "module.exports = require('./lib.js');",
                ),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("./lib.js", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("node_compat require should reject explicit .js ESM targets");
        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert!(error.message.contains("ERR_REQUIRE_ESM"));
        assert!(error.message.contains("pkg/lib.js"));
        assert_eq!(error.probe_sequence, vec!["pkg/lib.js"]);
    }

    #[test]
    fn node_compat_external_relative_require_explicit_js_cjs_resolves() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "module.exports = require('./lib.js');",
                ),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib.js", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("node_compat should resolve explicit .js CJS targets");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib.js");
        assert_eq!(outcome.module.record.id, "external:pkg/lib.js");
        assert_eq!(outcome.module.record.syntax, ModuleSyntax::CommonJs);
        assert_eq!(outcome.module.probe_sequence, vec!["pkg/lib.js"]);
    }

    #[test]
    fn bun_compat_external_relative_require_explicit_mjs_resolves() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "module.exports = require('./lib.mjs');",
                ),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib.mjs", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("bun_compat should allow explicit .mjs require targets");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib.mjs");
        assert_eq!(outcome.module.record.id, "external:pkg/lib.mjs");
        assert_eq!(outcome.module.record.syntax, ModuleSyntax::EsModule);
        assert_eq!(outcome.module.probe_sequence, vec!["pkg/lib.mjs"]);
    }

    #[test]
    fn bun_compat_external_relative_require_explicit_js_esm_resolves() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "module.exports = require('./lib.js');",
                ),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib.js", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("bun_compat should allow explicit .js ESM require targets");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib.js");
        assert_eq!(outcome.module.record.id, "external:pkg/lib.js");
        assert_eq!(outcome.module.record.syntax, ModuleSyntax::EsModule);
        assert_eq!(outcome.module.probe_sequence, vec!["pkg/lib.js"]);
    }

    #[test]
    fn bun_compat_external_relative_require_explicit_js_cjs_resolves() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "module.exports = require('./lib.js');",
                ),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib.js", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("bun_compat should resolve explicit .js CJS targets");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib.js");
        assert_eq!(outcome.module.record.id, "external:pkg/lib.js");
        assert_eq!(outcome.module.record.syntax, ModuleSyntax::CommonJs);
        assert_eq!(outcome.module.probe_sequence, vec!["pkg/lib.js"]);
    }

    #[test]
    fn node_compat_external_relative_require_prefers_js_over_mjs() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./lib');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("node_compat require should resolve to .js before .mjs");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib.js");
        assert_eq!(outcome.module.record.id, "external:pkg/lib.js");
        assert_eq!(
            outcome.module.probe_sequence,
            vec!["pkg/lib", "pkg/lib.cjs", "pkg/lib.js"]
        );
    }

    #[test]
    fn node_compat_external_relative_require_prefers_cjs_over_js() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./lib');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("node_compat require should resolve to .cjs before .js");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib.cjs");
        assert_eq!(outcome.module.record.id, "external:pkg/lib.cjs");
        assert_eq!(
            outcome.module.probe_sequence,
            vec!["pkg/lib", "pkg/lib.cjs"]
        );
    }

    #[test]
    fn node_compat_external_relative_require_prefers_extension_over_index() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./lib');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib/index.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 2;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("node_compat require should prefer extension before index");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib.js");
        assert_eq!(outcome.module.record.id, "external:pkg/lib.js");
        assert_eq!(
            outcome.module.probe_sequence,
            vec!["pkg/lib", "pkg/lib.cjs", "pkg/lib.js"]
        );
    }

    #[test]
    fn node_compat_external_relative_require_falls_back_to_index_cjs() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./lib');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib/index.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 2;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("node_compat require should fall back to index.cjs");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib/index.cjs");
        assert_eq!(outcome.module.record.id, "external:pkg/lib/index.cjs");
        assert_eq!(
            outcome.module.probe_sequence,
            vec!["pkg/lib", "pkg/lib.cjs", "pkg/lib.js", "pkg/lib/index.cjs"]
        );
    }

    #[test]
    fn node_compat_external_relative_require_ignores_index_mjs() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./lib');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib/index.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 2;"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("node_compat require should not probe index.mjs candidates");
        assert_eq!(error.code, ResolutionErrorCode::ModuleNotFound);
        assert_eq!(
            error.probe_sequence,
            vec![
                "pkg/lib",
                "pkg/lib.cjs",
                "pkg/lib.js",
                "pkg/lib/index.cjs",
                "pkg/lib/index.js",
            ]
        );
    }

    #[test]
    fn node_compat_external_relative_require_falls_back_to_index_js() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./lib');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib/index.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 2;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("node_compat require should fall back to index.js");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib/index.js");
        assert_eq!(outcome.module.record.id, "external:pkg/lib/index.js");
        assert_eq!(
            outcome.module.probe_sequence,
            vec![
                "pkg/lib",
                "pkg/lib.cjs",
                "pkg/lib.js",
                "pkg/lib/index.cjs",
                "pkg/lib/index.js",
            ]
        );
    }

    #[test]
    fn node_compat_external_relative_require_prefers_index_cjs_over_index_js() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./lib');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib/index.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib/index.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 2;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("node_compat require should prefer index.cjs over index.js");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib/index.cjs");
        assert_eq!(outcome.module.record.id, "external:pkg/lib/index.cjs");
        assert_eq!(
            outcome.module.probe_sequence,
            vec!["pkg/lib", "pkg/lib.cjs", "pkg/lib.js", "pkg/lib/index.cjs",]
        );
    }

    #[test]
    fn node_compat_external_relative_require_does_not_probe_index_mjs_when_index_js_present() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/entry.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = require('./lib');"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib/index.js",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib/index.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 2;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Require)
                    .with_referrer("external:pkg/entry.cjs")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("node_compat require should resolve index.js without probing index.mjs");
        assert_eq!(outcome.module.canonical_specifier, "pkg/lib/index.js");
        assert_eq!(outcome.module.record.id, "external:pkg/lib/index.js");
        assert_eq!(
            outcome.module.probe_sequence,
            vec![
                "pkg/lib",
                "pkg/lib.cjs",
                "pkg/lib.js",
                "pkg/lib/index.cjs",
                "pkg/lib/index.js",
            ]
        );
    }

    // -----------------------------------------------------------------------
    // resolve_chain
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_chain_traverses_dependencies() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/entry.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './dep.js';")
                    .with_dependency(ModuleDependency::new("./dep.js", ImportStyle::Import)),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/dep.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("/app/entry.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");

        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].module.canonical_specifier, "/app/entry.js");
        assert_eq!(chain[1].module.canonical_specifier, "/app/dep.js");
    }

    #[test]
    fn resolve_chain_deduplicates_circular_dependencies() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/a.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './b.js';")
                    .with_dependency(ModuleDependency::new("./b.js", ImportStyle::Import)),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/b.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './a.js';")
                    .with_dependency(ModuleDependency::new("./a.js", ImportStyle::Import)),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("/app/a.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");

        // Should resolve both but not loop infinitely
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn resolve_chain_single_module_no_deps() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/leaf.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("/app/leaf.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(chain.len(), 1);
    }

    // -----------------------------------------------------------------------
    // CapabilityPolicyHook deny-list
    // -----------------------------------------------------------------------

    #[test]
    fn capability_policy_denies_listed_specifier() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/allowed.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let policy = CapabilityPolicyHook::new(BTreeSet::new()).deny_specifier("/app/allowed.js");

        let request = ModuleRequest::new("/app/allowed.js", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &policy)
            .expect_err("deny-listed specifier should fail");
        assert_eq!(error.code, ResolutionErrorCode::PolicyDenied);
    }

    // -----------------------------------------------------------------------
    // AllowAllPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn allow_all_policy_permits_any_module() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/anything.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                    .require_capability(RuntimeCapability::FsWrite)
                    .require_capability(RuntimeCapability::NetworkEgress),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("/app/anything.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.event.outcome, "allow");
    }

    // -----------------------------------------------------------------------
    // ModuleSyntax / ImportStyle / ModuleSourceKind as_str
    // -----------------------------------------------------------------------

    #[test]
    fn module_syntax_as_str() {
        assert_eq!(ModuleSyntax::EsModule.as_str(), "esm");
        assert_eq!(ModuleSyntax::CommonJs.as_str(), "cjs");
        assert_eq!(ModuleSyntax::Wasm.as_str(), "wasm");
    }

    #[test]
    fn import_style_as_str() {
        assert_eq!(ImportStyle::Import.as_str(), "import");
        assert_eq!(ImportStyle::Require.as_str(), "require");
    }

    #[test]
    fn module_source_kind_as_str() {
        assert_eq!(ModuleSourceKind::BuiltIn.as_str(), "builtin");
        assert_eq!(ModuleSourceKind::Workspace.as_str(), "workspace");
        assert_eq!(
            ModuleSourceKind::ExternalRegistry.as_str(),
            "external_registry"
        );
    }

    // -----------------------------------------------------------------------
    // ModuleRecord canonical value/hash determinism
    // -----------------------------------------------------------------------

    #[test]
    fn module_record_borrowed_encoding_and_hash_match_owned_reference() {
        use crate::deterministic_serde::encode_value;

        let sources = [
            String::new(),
            "export const answer = 42;".to_string(),
            "// \0é🚀\r\nmodule.exports = 'λ';".to_string(),
            "a".repeat(63),
            "a".repeat(64),
            "a".repeat(65),
            "x".repeat(1024 * 1024),
        ];
        let capability_sets = [
            BTreeSet::new(),
            BTreeSet::from([RuntimeCapability::FsRead, RuntimeCapability::ModuleLoad]),
            RuntimeCapability::ALL.into_iter().collect(),
        ];
        for syntax in [
            ModuleSyntax::EsModule,
            ModuleSyntax::CommonJs,
            ModuleSyntax::Wasm,
        ] {
            for kind in [
                ModuleSourceKind::BuiltIn,
                ModuleSourceKind::Workspace,
                ModuleSourceKind::ExternalRegistry,
            ] {
                for source in &sources {
                    for capabilities in &capability_sets {
                        let record = ModuleRecord {
                            id: "captured:\0é🚀?instance=1".into(),
                            syntax,
                            source: source.clone(),
                            dependencies: vec![
                                ModuleDependency::new("./z.cjs", ImportStyle::Require),
                                ModuleDependency::new("./a.mjs?é", ImportStyle::Import),
                                ModuleDependency::new("./z.cjs", ImportStyle::Import),
                                ModuleDependency::new("./z.cjs", ImportStyle::Require),
                            ],
                            required_capabilities: capabilities.clone(),
                            provenance: ModuleProvenance {
                                kind,
                                origin: "captured:root\0🚀".into(),
                            },
                        };
                        // The independently maintained owned representation
                        // remains the oracle for every byte and identity bit.
                        let reference = encode_value(&record.canonical_value());
                        assert_eq!(record.canonical_bytes(), reference);
                        assert_eq!(record.canonical_hash(), ContentHash::compute(&reference));
                    }
                }
            }
        }
    }

    #[test]
    fn streaming_module_hash_retains_every_authority_and_identity_field() {
        use crate::deterministic_serde::encode_value;

        let original = ModuleRecord {
            id: "captured:root:module".into(),
            syntax: ModuleSyntax::EsModule,
            source: "export const answer=42;".into(),
            dependencies: vec![
                ModuleDependency::new("./first.cjs", ImportStyle::Require),
                ModuleDependency::new("./second.mjs", ImportStyle::Import),
            ],
            required_capabilities: BTreeSet::from([
                RuntimeCapability::ModuleLoad,
                RuntimeCapability::FsRead,
            ]),
            provenance: ModuleProvenance {
                kind: ModuleSourceKind::Workspace,
                origin: "captured:graph-pin".into(),
            },
        };
        let original_hash = original.canonical_hash();
        for field in 0..10 {
            let mut changed = original.clone();
            match field {
                0 => changed.id.push_str("?different-instance"),
                1 => changed.syntax = ModuleSyntax::CommonJs,
                2 => changed.source.push_str("\n// changed"),
                3 => changed.dependencies[0].style = ImportStyle::Import,
                4 => changed.dependencies.reverse(),
                5 => changed.dependencies.push(changed.dependencies[0].clone()),
                6 => {
                    changed
                        .required_capabilities
                        .remove(&RuntimeCapability::FsRead);
                }
                7 => changed.provenance.kind = ModuleSourceKind::ExternalRegistry,
                8 => changed.provenance.origin.push_str(":changed"),
                9 => changed.dependencies.clear(),
                _ => unreachable!(),
            }
            let reference = encode_value(&changed.canonical_value());
            assert_eq!(changed.canonical_hash(), ContentHash::compute(&reference));
            assert_ne!(
                changed.canonical_hash(),
                original_hash,
                "changed field {field}"
            );
        }
    }

    #[test]
    fn module_record_canonical_hash_is_deterministic() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/det.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                    .with_provenance("workspace:/app/det.js"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("/app/det.js", ImportStyle::Import);
        let r1 = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        let r2 = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(r1.module.content_hash, r2.module.content_hash);
        assert_eq!(
            r1.module.record.canonical_bytes(),
            r2.module.record.canonical_bytes()
        );
    }

    // -----------------------------------------------------------------------
    // ResolutionErrorCode stable codes
    // -----------------------------------------------------------------------

    #[test]
    fn all_resolution_error_codes_have_fe_modres_prefix() {
        let codes = [
            ResolutionErrorCode::EmptySpecifier,
            ResolutionErrorCode::InvalidReferrer,
            ResolutionErrorCode::UnsupportedSpecifier,
            ResolutionErrorCode::ModuleNotFound,
            ResolutionErrorCode::PolicyDenied,
            ResolutionErrorCode::PackagePathNotExported,
            ResolutionErrorCode::PackageImportNotDefined,
        ];
        for code in &codes {
            let stable = code.stable_code();
            assert!(
                stable.starts_with("FE-MODRES-"),
                "stable_code {} must start with FE-MODRES-",
                stable
            );
        }
    }

    #[test]
    fn resolution_error_codes_are_unique() {
        let codes = [
            ResolutionErrorCode::EmptySpecifier.stable_code(),
            ResolutionErrorCode::InvalidReferrer.stable_code(),
            ResolutionErrorCode::UnsupportedSpecifier.stable_code(),
            ResolutionErrorCode::ModuleNotFound.stable_code(),
            ResolutionErrorCode::PolicyDenied.stable_code(),
            ResolutionErrorCode::PackagePathNotExported.stable_code(),
            ResolutionErrorCode::PackageImportNotDefined.stable_code(),
        ];
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "all stable codes must be unique");
    }

    #[test]
    fn package_resolution_codes_from_policy_remain_uncatchable_denials() {
        for code in [
            ResolutionErrorCode::PackagePathNotExported,
            ResolutionErrorCode::PackageImportNotDefined,
        ] {
            let error = ResolutionError::new(code, "policy hid an existing source", &context())
                .into_policy_denial();
            assert_eq!(error.code, ResolutionErrorCode::PolicyDenied);
            assert_eq!(error.event.error_code, "FE-MODRES-0005");
            assert!(error.message.contains(code.stable_code()));
        }
    }

    // -----------------------------------------------------------------------
    // ResolutionError Display
    // -----------------------------------------------------------------------

    #[test]
    fn resolution_error_display_includes_stable_code_and_trace() {
        let resolver = DeterministicModuleResolver::default();
        let request = ModuleRequest::new("", ImportStyle::Import);
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("empty specifier should fail");
        let display = format!("{error}");
        assert!(display.contains("FE-MODRES-0001"));
        assert!(display.contains("trace-1"));
        assert!(display.contains("decision-1"));
        assert!(display.contains("policy-1"));
    }

    // -----------------------------------------------------------------------
    // Serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn module_syntax_serde_round_trip() {
        for syntax in &[
            ModuleSyntax::EsModule,
            ModuleSyntax::CommonJs,
            ModuleSyntax::Wasm,
        ] {
            let json = serde_json::to_string(syntax).expect("serde serialization should succeed");
            let decoded: ModuleSyntax =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(&decoded, syntax);
        }
    }

    #[test]
    fn import_style_serde_round_trip() {
        for style in &[ImportStyle::Import, ImportStyle::Require] {
            let json = serde_json::to_string(style).expect("serde serialization should succeed");
            let decoded: ImportStyle =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(&decoded, style);
        }
    }

    #[test]
    fn resolution_error_code_serde_round_trip() {
        let codes = [
            ResolutionErrorCode::EmptySpecifier,
            ResolutionErrorCode::InvalidReferrer,
            ResolutionErrorCode::UnsupportedSpecifier,
            ResolutionErrorCode::ModuleNotFound,
            ResolutionErrorCode::PolicyDenied,
            ResolutionErrorCode::PackagePathNotExported,
            ResolutionErrorCode::PackageImportNotDefined,
        ];
        for code in &codes {
            let json = serde_json::to_string(code).expect("serde serialization should succeed");
            let decoded: ResolutionErrorCode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(&decoded, code);
        }
    }

    #[test]
    fn module_definition_builder_chain() {
        let def = ModuleDefinition::new(ModuleSyntax::EsModule, "import 'x'; export default 1;")
            .with_dependency(ModuleDependency::new("x", ImportStyle::Import))
            .require_capability(RuntimeCapability::FsRead)
            .with_provenance("test:origin");

        assert_eq!(def.dependencies.len(), 1);
        assert_eq!(def.dependencies[0].specifier, "x");
        assert!(
            def.required_capabilities
                .contains(&RuntimeCapability::FsRead)
        );
        assert_eq!(def.provenance_origin, "test:origin");
    }

    // -----------------------------------------------------------------------
    // Path normalization
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_absolute_path_resolves_dotdot() {
        assert_eq!(normalize_absolute_path("/a/b/../c"), "/a/c");
        assert_eq!(normalize_absolute_path("/a/./b/./c"), "/a/b/c");
        assert_eq!(normalize_absolute_path("/a/b/../../c"), "/c");
    }

    #[test]
    fn normalize_absolute_path_root() {
        assert_eq!(normalize_absolute_path("/"), "/");
        assert_eq!(normalize_absolute_path("///"), "/");
    }

    #[test]
    fn parent_directory_of_file() {
        assert_eq!(parent_directory("/a/b/c.js"), "/a/b");
        assert_eq!(parent_directory("/a.js"), "/");
        assert_eq!(parent_directory("/"), "/");
    }

    // -----------------------------------------------------------------------
    // Workspace module with relative path
    // -----------------------------------------------------------------------

    #[test]
    fn register_workspace_module_with_relative_path_normalizes_to_absolute() {
        let mut resolver = DeterministicModuleResolver::new("/workspace");
        resolver
            .register_workspace_module(
                "src/lib.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("/workspace/src/lib.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.module.canonical_specifier, "/workspace/src/lib.js");
    }

    // -----------------------------------------------------------------------
    // Duplicate registration overwrites
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_builtin_registration_overwrites_previous() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_builtin(
                "franken:util",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const v = 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_builtin(
                "franken:util",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const v = 2;"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("franken:util", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.module.record.source, "export const v = 2;");
    }

    // -----------------------------------------------------------------------
    // Default resolver root dir
    // -----------------------------------------------------------------------

    #[test]
    fn default_resolver_has_root_dir_slash() {
        let resolver = DeterministicModuleResolver::default();
        assert_eq!(resolver.root_dir(), "/");
    }

    // -- Enrichment: ordering --

    #[test]
    fn module_syntax_ordering() {
        assert!(ModuleSyntax::EsModule < ModuleSyntax::CommonJs);
        assert!(ModuleSyntax::CommonJs < ModuleSyntax::Wasm);
    }

    #[test]
    fn import_style_ordering() {
        assert!(ImportStyle::Import < ImportStyle::Require);
    }

    #[test]
    fn module_source_kind_ordering() {
        assert!(ModuleSourceKind::BuiltIn < ModuleSourceKind::Workspace);
        assert!(ModuleSourceKind::Workspace < ModuleSourceKind::ExternalRegistry);
    }

    // -- Enrichment: error trait --

    #[test]
    fn resolution_error_is_std_error() {
        let event = ResolutionEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "resolver".to_string(),
            event: "resolve".to_string(),
            outcome: "error".to_string(),
            error_code: "FE_MODRES_EMPTY".to_string(),
        };
        let err = ResolutionError {
            code: ResolutionErrorCode::EmptySpecifier,
            message: "empty".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            request_specifier: String::new(),
            canonical_specifier: None,
            source_kind: None,
            probe_sequence: Vec::new(),
            event,
        };
        let e: Box<dyn std::error::Error> = Box::new(err);
        assert!(!e.to_string().is_empty());
    }

    #[test]
    fn registry_error_is_std_error() {
        let err = RegistryError {
            code: RegistryErrorCode::EmptyKey,
            message: "key empty".to_string(),
        };
        let e: Box<dyn std::error::Error> = Box::new(err);
        assert!(!e.to_string().is_empty());
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn module_provenance_serde_roundtrip() {
        let mp = ModuleProvenance {
            kind: ModuleSourceKind::BuiltIn,
            origin: "franken:core".to_string(),
        };
        let json = serde_json::to_string(&mp).expect("serde serialization should succeed");
        let restored: ModuleProvenance =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(mp, restored);
    }

    #[test]
    fn module_dependency_serde_roundtrip() {
        let md = ModuleDependency {
            specifier: "./utils.js".to_string(),
            style: ImportStyle::Import,
        };
        let json = serde_json::to_string(&md).expect("serde serialization should succeed");
        let restored: ModuleDependency =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(md, restored);
    }

    #[test]
    fn module_request_serde_roundtrip() {
        let mr = ModuleRequest::new("franken:core", ImportStyle::Import);
        let json = serde_json::to_string(&mr).expect("serde serialization should succeed");
        let restored: ModuleRequest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(mr, restored);
    }

    #[test]
    fn module_request_serde_roundtrip_with_bun_compat_mode() {
        let mr = ModuleRequest::new("pkg", ImportStyle::Require)
            .with_referrer("/repo/main.cjs")
            .with_compatibility_mode(CompatibilityMode::BunCompat);
        let json = serde_json::to_string(&mr).expect("serde serialization should succeed");
        let restored: ModuleRequest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(mr, restored);
        assert_eq!(restored.compatibility_mode, CompatibilityMode::BunCompat);
    }

    #[test]
    fn module_request_legacy_json_defaults_to_native_compat_mode() {
        let restored: ModuleRequest = serde_json::from_str(
            r#"{"specifier":"pkg","referrer":"/repo/main.cjs","style":"require"}"#,
        )
        .expect("serde serialization should succeed");
        assert_eq!(restored.compatibility_mode, CompatibilityMode::Native);
    }

    #[test]
    fn resolution_context_serde_roundtrip() {
        let ctx = ResolutionContext {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
        };
        let json = serde_json::to_string(&ctx).expect("serde serialization should succeed");
        let restored: ResolutionContext =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(ctx, restored);
    }

    #[test]
    fn registry_error_serde_roundtrip() {
        let err = RegistryError {
            code: RegistryErrorCode::EmptyKey,
            message: "key must not be empty".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serde serialization should succeed");
        let restored: RegistryError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, restored);
    }

    #[test]
    fn allow_all_policy_default_serde() {
        let p = AllowAllPolicy;
        let json = serde_json::to_string(&p).expect("serde serialization should succeed");
        let restored: AllowAllPolicy =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(p, restored);
    }

    #[test]
    fn module_source_kind_serde_roundtrip() {
        for kind in [
            ModuleSourceKind::BuiltIn,
            ModuleSourceKind::Workspace,
            ModuleSourceKind::ExternalRegistry,
        ] {
            let json = serde_json::to_string(&kind).expect("serde serialization should succeed");
            let restored: ModuleSourceKind =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(kind, restored);
        }
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn module_syntax_display_unique() {
        let displays: BTreeSet<String> = [
            ModuleSyntax::EsModule,
            ModuleSyntax::CommonJs,
            ModuleSyntax::Wasm,
        ]
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn import_style_display_unique() {
        let displays: BTreeSet<String> = [ImportStyle::Import, ImportStyle::Require]
            .iter()
            .map(|s| s.as_str().to_string())
            .collect();
        assert_eq!(displays.len(), 2);
    }

    #[test]
    fn resolution_error_code_stable_codes_unique_in_set() {
        let codes = [
            ResolutionErrorCode::EmptySpecifier,
            ResolutionErrorCode::InvalidReferrer,
            ResolutionErrorCode::UnsupportedSpecifier,
            ResolutionErrorCode::ModuleNotFound,
            ResolutionErrorCode::PolicyDenied,
            ResolutionErrorCode::PackagePathNotExported,
            ResolutionErrorCode::PackageImportNotDefined,
        ];
        let stable: BTreeSet<String> = codes.iter().map(|c| c.stable_code().to_string()).collect();
        assert_eq!(stable.len(), codes.len());
    }

    // ── Enrichment: path normalization edge cases ───────────────

    #[test]
    fn normalize_deeply_nested_dotdot() {
        assert_eq!(normalize_absolute_path("/a/b/c/d/../../e"), "/a/b/e");
    }

    #[test]
    fn normalize_dotdot_at_root_stays_at_root() {
        assert_eq!(normalize_absolute_path("/../../../a"), "/a");
    }

    // ── Enrichment: default resolver ────────────────────────────

    #[test]
    fn default_resolver_is_empty() {
        let resolver = DeterministicModuleResolver::default();
        // No modules registered, so any resolve should fail
        let request = ModuleRequest::new("anything", ImportStyle::Import);
        let err = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("empty resolver cannot resolve");
        assert_eq!(err.code, ResolutionErrorCode::ModuleNotFound);
    }

    // ── Enrichment: resolve_chain with policy denial ────────────

    #[test]
    fn resolve_chain_fails_on_policy_denial_of_entry() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/restricted.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                    .require_capability(RuntimeCapability::FsWrite),
            )
            .expect("serde serialization should succeed");

        let policy = CapabilityPolicyHook::new(BTreeSet::new()); // no caps granted
        let request = ModuleRequest::new("/app/restricted.js", ImportStyle::Import);
        let err = resolver
            .resolve_chain(&request, &context(), &policy)
            .expect_err("should deny due to missing cap");
        assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
    }

    // ── Enrichment: RegistryErrorCode serde ─────────────────────

    #[test]
    fn registry_error_code_serde_roundtrip() {
        let code = RegistryErrorCode::EmptyKey;
        let json = serde_json::to_string(&code).expect("serde serialization should succeed");
        let back: RegistryErrorCode =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(code, back);
    }

    // ── Enrichment: capability policy with multiple caps ────────

    #[test]
    fn capability_policy_grants_multiple_caps() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/multi.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                    .require_capability(RuntimeCapability::FsRead)
                    .require_capability(RuntimeCapability::FsWrite),
            )
            .expect("serde serialization should succeed");

        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        granted.insert(RuntimeCapability::FsWrite);
        let policy = CapabilityPolicyHook::new(granted);

        let request = ModuleRequest::new("/app/multi.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &policy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.event.outcome, "allow");
    }

    // ── Enrichment: serde roundtrips for remaining types ─────────

    #[test]
    fn module_definition_serde_roundtrip() {
        let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
            .with_dependency(ModuleDependency::new("./util", ImportStyle::Import))
            .require_capability(RuntimeCapability::FsRead)
            .with_provenance("test:origin");
        let json = serde_json::to_string(&def).expect("serde serialization should succeed");
        let restored: ModuleDefinition =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(def, restored);
    }

    #[test]
    fn resolution_event_serde_roundtrip() {
        let ev = ResolutionEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "module_resolver".to_string(),
            event: "module_resolution".to_string(),
            outcome: "allow".to_string(),
            error_code: "none".to_string(),
        };
        let json = serde_json::to_string(&ev).expect("serde serialization should succeed");
        let restored: ResolutionEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(ev, restored);
    }

    #[test]
    fn resolved_module_serde_roundtrip_preserves_probe_sequence() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let request = ModuleRequest::new("/app/lib", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");

        let value =
            serde_json::to_value(&outcome.module).expect("serde serialization should succeed");
        assert_eq!(
            value.get("probe_sequence"),
            Some(&serde_json::json!(["/app/lib", "/app/lib.mjs"]))
        );

        let restored: ResolvedModule =
            serde_json::from_value(value).expect("serde serialization should succeed");
        assert_eq!(outcome.module, restored);
    }

    #[test]
    fn resolved_module_serde_omits_empty_probe_sequence() {
        let record = ModuleRecord::from_definition(
            "/app/manual.js".to_string(),
            ModuleSourceKind::Workspace,
            ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
        );
        let module = ResolvedModule {
            request_specifier: "/app/manual.js".to_string(),
            canonical_specifier: "/app/manual.js".to_string(),
            content_hash: record.canonical_hash(),
            record,
            probe_sequence: Vec::new(),
        };

        let value = serde_json::to_value(&module).expect("serde serialization should succeed");
        assert!(value.get("probe_sequence").is_none());

        let restored: ResolvedModule =
            serde_json::from_value(value).expect("serde serialization should succeed");
        assert!(restored.probe_sequence.is_empty());
    }

    #[test]
    fn resolution_outcome_serde_roundtrip_preserves_probe_trace() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "left-pad",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = pad;"),
            )
            .expect("serde serialization should succeed");
        let request = ModuleRequest::new("left-pad", ImportStyle::Require);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");

        let json = serde_json::to_string(&outcome).expect("serde serialization should succeed");
        let restored: ResolutionOutcome =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(outcome, restored);
        assert_eq!(restored.module.probe_sequence, vec!["left-pad"]);
    }

    #[test]
    fn resolution_outcome_trace_record_roundtrip_preserves_required_fields() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import x from './lib';"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Import)
                    .with_referrer("/app/main.mjs")
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("serde serialization should succeed");

        let trace = outcome.trace_record();
        assert_eq!(trace.schema_version, MODULE_RESOLUTION_TRACE_SCHEMA_VERSION);
        assert_eq!(trace.request_specifier, "./lib");
        assert_eq!(trace.canonical_specifier, "/app/lib.mjs");
        assert_eq!(trace.source_kind, "workspace");
        assert_eq!(trace.probe_sequence, vec!["/app/lib", "/app/lib.mjs"]);
        assert_eq!(trace.outcome, "allow");
        assert_eq!(trace.error_code, "none");

        let restored: ModuleResolutionTraceRecord = serde_json::from_str(
            &trace
                .to_json_line()
                .expect("serde serialization should succeed"),
        )
        .expect("serde serialization should succeed");
        assert_eq!(restored, trace);
    }

    #[test]
    fn resolution_error_trace_record_preserves_partial_probe_sequence() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './missing';"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("./missing", ImportStyle::Import)
                    .with_referrer("/app/main.mjs"),
                &context(),
                &AllowAllPolicy,
            )
            .unwrap_err();

        let trace = error.trace_record();
        assert_eq!(trace.schema_version, MODULE_RESOLUTION_TRACE_SCHEMA_VERSION);
        assert_eq!(trace.request_specifier, "./missing");
        assert_eq!(trace.canonical_specifier, "./missing");
        assert_eq!(trace.source_kind, "unresolved");
        assert_eq!(trace.probe_sequence, vec!["/app/missing"]);
        assert_eq!(trace.outcome, "deny");
        assert_eq!(
            trace.error_code,
            ResolutionErrorCode::ModuleNotFound.stable_code()
        );
    }

    #[test]
    fn capability_policy_hook_serde_roundtrip() {
        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        granted.insert(RuntimeCapability::NetworkEgress);
        let hook = CapabilityPolicyHook::new(granted)
            .deny_specifier("evil-pkg")
            .deny_specifier("malware");
        let json = serde_json::to_string(&hook).expect("serde serialization should succeed");
        let restored: CapabilityPolicyHook =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(hook, restored);
    }

    #[test]
    fn deterministic_module_resolver_serde_roundtrip() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_builtin(
                "franken:fs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const read = true;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/lib.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "left-pad",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = pad;"),
            )
            .expect("serde serialization should succeed");
        let json = serde_json::to_string(&resolver).expect("serde serialization should succeed");
        let restored: DeterministicModuleResolver =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(resolver, restored);
    }

    #[test]
    fn resolution_error_serde_roundtrip() {
        let ev = ResolutionEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "module_resolver".to_string(),
            event: "module_resolution".to_string(),
            outcome: "deny".to_string(),
            error_code: "FE-MODRES-0001".to_string(),
        };
        let err = ResolutionError {
            code: ResolutionErrorCode::EmptySpecifier,
            message: "specifier empty".to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            request_specifier: String::new(),
            canonical_specifier: None,
            source_kind: None,
            probe_sequence: Vec::new(),
            event: ev,
        };
        let json = serde_json::to_string(&err).expect("serde serialization should succeed");
        let restored: ResolutionError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, restored);
    }

    // ── Enrichment: relative resolution with ../ ─────────────────

    #[test]
    fn dotdot_relative_specifier_resolves_parent_directory() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/shared/util.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const x = 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/src/main.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import '../shared/util.js';"),
            )
            .expect("serde serialization should succeed");
        let request = ModuleRequest::new("../shared/util.js", ImportStyle::Import)
            .with_referrer("/app/src/main.js");
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.module.canonical_specifier, "/app/shared/util.js");
    }

    // ── Enrichment: deep dependency chain ────────────────────────

    #[test]
    fn resolve_chain_traverses_three_level_dependency_graph() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/a.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './b.js';")
                    .with_dependency(ModuleDependency::new("./b.js", ImportStyle::Import)),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/b.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './c.js';")
                    .with_dependency(ModuleDependency::new("./c.js", ImportStyle::Import)),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/c.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 3;"),
            )
            .expect("serde serialization should succeed");
        let request = ModuleRequest::new("/app/a.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].module.canonical_specifier, "/app/a.js");
        assert_eq!(chain[1].module.canonical_specifier, "/app/b.js");
        assert_eq!(chain[2].module.canonical_specifier, "/app/c.js");
    }

    // ── Enrichment: transitive policy denial ─────────────────────

    #[test]
    fn resolve_chain_fails_on_transitive_dependency_policy_denial() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/entry.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './restricted.js';")
                    .with_dependency(ModuleDependency::new(
                        "./restricted.js",
                        ImportStyle::Import,
                    )),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/restricted.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                    .require_capability(RuntimeCapability::FsWrite),
            )
            .expect("serde serialization should succeed");
        let policy = CapabilityPolicyHook::new(BTreeSet::new());
        let request = ModuleRequest::new("/app/entry.js", ImportStyle::Import);
        let err = resolver
            .resolve_chain(&request, &context(), &policy)
            .expect_err("transitive dependency should be denied");
        assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
    }

    // ── Enrichment: deny by resolved module id ───────────────────

    #[test]
    fn capability_policy_denies_by_resolved_module_id() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/target.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");
        let policy = CapabilityPolicyHook::new(BTreeSet::new()).deny_specifier("/app/target.js");
        let request = ModuleRequest::new("/app/target.js", ImportStyle::Import);
        let err = resolver
            .resolve(&request, &context(), &policy)
            .expect_err("deny by module id should fail");
        assert_eq!(err.code, ResolutionErrorCode::PolicyDenied);
    }

    // ── Enrichment: RegistryError Display ────────────────────────

    #[test]
    fn registry_error_display_contains_code_and_message() {
        let err = RegistryError {
            code: RegistryErrorCode::EmptyKey,
            message: "module key must not be empty".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("EmptyKey"));
        assert!(display.contains("module key must not be empty"));
    }

    // ── Enrichment: canonical hash differs on source change ──────

    #[test]
    fn canonical_hash_differs_when_source_differs() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/v1.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/v2.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 2;"),
            )
            .expect("serde serialization should succeed");
        let r1 = resolver
            .resolve(
                &ModuleRequest::new("/app/v1.js", ImportStyle::Import),
                &context(),
                &AllowAllPolicy,
            )
            .expect("serde serialization should succeed");
        let r2 = resolver
            .resolve(
                &ModuleRequest::new("/app/v2.js", ImportStyle::Import),
                &context(),
                &AllowAllPolicy,
            )
            .expect("serde serialization should succeed");
        assert_ne!(r1.module.content_hash, r2.module.content_hash);
    }

    // ── Enrichment: whitespace-only keys rejected ────────────────

    #[test]
    fn register_builtin_with_whitespace_only_key_returns_error() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        let err = resolver
            .register_builtin("   ", ModuleDefinition::new(ModuleSyntax::EsModule, ""))
            .unwrap_err();
        assert_eq!(err.code, RegistryErrorCode::EmptyKey);
    }

    #[test]
    fn register_workspace_with_whitespace_only_path_returns_error() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        let err = resolver
            .register_workspace_module("  \t ", ModuleDefinition::new(ModuleSyntax::EsModule, ""))
            .unwrap_err();
        assert_eq!(err.code, RegistryErrorCode::EmptyKey);
    }

    #[test]
    fn register_external_with_whitespace_only_specifier_returns_error() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        let err = resolver
            .register_external_module(" ", ModuleDefinition::new(ModuleSyntax::CommonJs, ""))
            .unwrap_err();
        assert_eq!(err.code, RegistryErrorCode::EmptyKey);
    }

    // ── Enrichment: overwrite for workspace and external ─────────

    #[test]
    fn duplicate_workspace_registration_overwrites_previous() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/mod.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const v = 1;"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_workspace_module(
                "/app/mod.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const v = 2;"),
            )
            .expect("serde serialization should succeed");
        let request = ModuleRequest::new("/app/mod.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.module.record.source, "export const v = 2;");
    }

    #[test]
    fn duplicate_external_registration_overwrites_previous() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "lodash",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "v1"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "lodash",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "v2"),
            )
            .expect("serde serialization should succeed");
        let request = ModuleRequest::new("lodash", ImportStyle::Require);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.module.record.source, "v2");
    }

    // ── Enrichment: external module extension probing ────────────

    #[test]
    fn external_module_resolves_with_extension_probing() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "my-pkg.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");
        let request = ModuleRequest::new("my-pkg", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.module.canonical_specifier, "my-pkg.js");
    }

    // ── Enrichment: relative from external referrer ──────────────

    #[test]
    fn native_relative_import_from_external_esm_referrer_requires_extension() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "some-pkg",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export { default } from './sub';"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "some-pkg/sub.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("./sub", ImportStyle::Import)
                    .with_referrer("external:some-pkg"),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("native mode should require explicit extension for external ESM relatives");
        assert_eq!(error.code, ResolutionErrorCode::ModuleNotFound);
        assert_eq!(error.probe_sequence, vec!["some-pkg/sub"]);
    }

    #[test]
    fn bun_compat_relative_import_from_external_esm_referrer_resolves_against_package_root() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "some-pkg/sub.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./sub", ImportStyle::Import)
                    .with_referrer("external:some-pkg")
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("bun_compat should resolve external relative dependency");
        assert_eq!(outcome.module.canonical_specifier, "some-pkg/sub.mjs");
        assert_eq!(outcome.module.record.id, "external:some-pkg/sub.mjs");
    }

    #[test]
    fn external_extension_probe_entry_uses_package_root_for_relative_dependencies() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "pkg.js",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "const sub = require('./sub'); module.exports = sub;",
                )
                .with_dependency(ModuleDependency::new("./sub", ImportStyle::Require)),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/sub.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");

        let outcomes = resolver
            .resolve_chain(
                &ModuleRequest::new("pkg", ImportStyle::Require),
                &context(),
                &AllowAllPolicy,
            )
            .expect("relative dependency should resolve from bare package entry file");
        let ids = outcomes
            .iter()
            .map(|outcome| outcome.module.record.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["external:pkg.js", "external:pkg/sub.cjs"]);
    }

    #[test]
    fn scoped_external_extension_probe_entry_uses_package_root_for_relative_dependencies() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "@scope/pkg.js",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "const sub = require('./sub'); module.exports = sub;",
                )
                .with_dependency(ModuleDependency::new("./sub", ImportStyle::Require)),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "@scope/pkg/sub.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .expect("serde serialization should succeed");

        let outcomes = resolver
            .resolve_chain(
                &ModuleRequest::new("@scope/pkg", ImportStyle::Require),
                &context(),
                &AllowAllPolicy,
            )
            .expect("scoped relative dependency should resolve from extension-probe package root");
        let ids = outcomes
            .iter()
            .map(|outcome| outcome.module.record.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec!["external:@scope/pkg.js", "external:@scope/pkg/sub.cjs"]
        );
    }

    #[test]
    fn scoped_external_relative_import_requires_explicit_extension_outside_bun_compat() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "@scope/pkg.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export { default } from './sub';"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "@scope/pkg/sub.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .expect("serde serialization should succeed");

        let native_error = resolver
            .resolve(
                &ModuleRequest::new("./sub", ImportStyle::Import)
                    .with_referrer("external:@scope/pkg.js"),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err(
                "native mode should require explicit extension for scoped external ESM relatives",
            );
        assert_eq!(native_error.code, ResolutionErrorCode::ModuleNotFound);
        assert_eq!(native_error.probe_sequence, vec!["@scope/pkg/sub"]);

        let node_error = resolver
            .resolve(
                &ModuleRequest::new("./sub", ImportStyle::Import)
                    .with_referrer("external:@scope/pkg.js")
                    .with_compatibility_mode(CompatibilityMode::NodeCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("node_compat should reject extensionless scoped external ESM relatives");
        assert_eq!(node_error.code, ResolutionErrorCode::ModuleNotFound);
        assert_eq!(node_error.probe_sequence, vec!["@scope/pkg/sub"]);

        let bun_outcome = resolver
            .resolve(
                &ModuleRequest::new("./sub", ImportStyle::Import)
                    .with_referrer("external:@scope/pkg.js")
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("bun_compat should probe scoped external ESM relatives from package root");
        assert_eq!(bun_outcome.module.canonical_specifier, "@scope/pkg/sub.mjs");
        assert_eq!(
            bun_outcome.module.probe_sequence,
            vec!["@scope/pkg/sub", "@scope/pkg/sub.mjs"]
        );
    }

    #[test]
    fn scoped_external_relative_specifier_cannot_escape_package_root() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "@scope/pkg.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import '../other-pkg/private.mjs';"),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "@scope/other-pkg/private.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'secret';"),
            )
            .expect("serde serialization should succeed");

        let error = resolver
            .resolve(
                &ModuleRequest::new("../other-pkg/private.mjs", ImportStyle::Import)
                    .with_referrer("external:@scope/pkg.js"),
                &context(),
                &AllowAllPolicy,
            )
            .expect_err("scoped external relative import must not escape its package root");
        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert!(
            error
                .message
                .contains("escapes external package root '@scope/pkg'")
        );
        assert!(error.probe_sequence.is_empty());
    }

    #[test]
    fn resolve_chain_supports_external_relative_require_edges_in_bun_compat_mode() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/index.cjs",
                ModuleDefinition::new(
                    ModuleSyntax::CommonJs,
                    "const lib = require('./lib.mjs'); module.exports = lib;",
                )
                .with_dependency(ModuleDependency::new("./lib.mjs", ImportStyle::Require)),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'esm';"),
            )
            .expect("serde serialization should succeed");

        let outcomes = resolver
            .resolve_chain(
                &ModuleRequest::new("pkg", ImportStyle::Require)
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect("bun_compat chain should follow external package relative require");
        let ids = outcomes
            .iter()
            .map(|outcome| outcome.module.record.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["external:pkg/index.cjs", "external:pkg/lib.mjs"]);
    }

    #[test]
    fn resolve_chain_supports_external_relative_import_edges_from_index_mjs_in_bun_compat_mode() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "pkg/index.mjs",
                ModuleDefinition::new(
                    ModuleSyntax::EsModule,
                    "import './sub.mjs'; export default 'esm';",
                )
                .with_dependency(ModuleDependency::new("./sub.mjs", ImportStyle::Import)),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "pkg/sub.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const value = 1;"),
            )
            .expect("serde serialization should succeed");

        let outcomes = resolver
            .resolve_chain(
                &ModuleRequest::new("pkg", ImportStyle::Require)
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect(
                "bun_compat chain should keep external index.mjs imports inside the package root",
            );
        let ids = outcomes
            .iter()
            .map(|outcome| outcome.module.record.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["external:pkg/index.mjs", "external:pkg/sub.mjs"]);
        assert_eq!(outcomes[0].module.canonical_specifier, "pkg/index.mjs");
        assert_eq!(outcomes[1].module.canonical_specifier, "pkg/sub.mjs");
    }

    #[test]
    fn resolve_chain_supports_scoped_external_relative_import_edges_from_index_mjs_in_bun_compat_mode()
     {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_external_module(
                "@scope/pkg/index.mjs",
                ModuleDefinition::new(
                    ModuleSyntax::EsModule,
                    "import './sub.mjs'; export default 'esm';",
                )
                .with_dependency(ModuleDependency::new("./sub.mjs", ImportStyle::Import)),
            )
            .expect("serde serialization should succeed");
        resolver
            .register_external_module(
                "@scope/pkg/sub.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const value = 1;"),
            )
            .expect("serde serialization should succeed");

        let outcomes = resolver
            .resolve_chain(
                &ModuleRequest::new("@scope/pkg", ImportStyle::Require)
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .expect(
                "bun_compat chain should keep scoped external index.mjs imports inside the package root",
            );
        let ids = outcomes
            .iter()
            .map(|outcome| outcome.module.record.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "external:@scope/pkg/index.mjs",
                "external:@scope/pkg/sub.mjs",
            ]
        );
        assert_eq!(
            outcomes[0].module.canonical_specifier,
            "@scope/pkg/index.mjs"
        );
        assert_eq!(outcomes[1].module.canonical_specifier, "@scope/pkg/sub.mjs");
    }

    // ── Enrichment: ModuleRequest with_referrer serde ────────────

    #[test]
    fn module_request_with_referrer_serde_roundtrip() {
        let mr = ModuleRequest::new("./dep", ImportStyle::Import).with_referrer("/app/main.js");
        let json = serde_json::to_string(&mr).expect("serde serialization should succeed");
        let restored: ModuleRequest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(mr, restored);
        assert_eq!(restored.referrer.as_deref(), Some("/app/main.js"));
    }

    // ── Enrichment: canonical_value structure ─────────────────────

    #[test]
    fn module_record_canonical_value_includes_all_fields() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/full.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './x'; export default 1;")
                    .with_dependency(ModuleDependency::new("./x", ImportStyle::Import))
                    .require_capability(RuntimeCapability::FsRead)
                    .with_provenance("workspace:/app/full.js"),
            )
            .expect("serde serialization should succeed");
        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        let policy = CapabilityPolicyHook::new(granted);
        let request = ModuleRequest::new("/app/full.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &policy)
            .expect("serde serialization should succeed");
        let cv = outcome.module.record.canonical_value();
        let bytes = outcome.module.record.canonical_bytes();
        assert!(!bytes.is_empty());
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("id"));
            assert!(map.contains_key("syntax"));
            assert!(map.contains_key("source"));
            assert!(map.contains_key("dependencies"));
            assert!(map.contains_key("required_capabilities"));
            assert!(map.contains_key("provenance"));
        } else {
            // SAFETY: Test-only panic to validate canonical module value structure
            // expects Value::Map from canonical serialization. Any other type is test failure.
            panic!("canonical_value should be a Map");
        }
    }

    // ── Enrichment: candidate_paths diverge by style ─────────────

    #[test]
    fn candidate_paths_import_includes_mjs_suffixes() {
        let candidates =
            candidate_paths("/app/lib", ImportStyle::Import, CompatibilityMode::Native);
        assert!(candidates.contains(&"/app/lib".to_string()));
        assert!(candidates.contains(&"/app/lib.mjs".to_string()));
        assert!(candidates.contains(&"/app/lib.js".to_string()));
        assert!(candidates.contains(&"/app/lib/index.mjs".to_string()));
        assert!(candidates.contains(&"/app/lib/index.js".to_string()));
        assert!(!candidates.contains(&"/app/lib.cjs".to_string()));
    }

    #[test]
    fn candidate_paths_import_includes_mjs_suffixes_in_node_compat_mode() {
        let candidates = candidate_paths(
            "/app/lib",
            ImportStyle::Import,
            CompatibilityMode::NodeCompat,
        );
        assert!(candidates.contains(&"/app/lib".to_string()));
        assert!(candidates.contains(&"/app/lib.mjs".to_string()));
        assert!(candidates.contains(&"/app/lib.js".to_string()));
        assert!(candidates.contains(&"/app/lib/index.mjs".to_string()));
        assert!(candidates.contains(&"/app/lib/index.js".to_string()));
        assert!(!candidates.contains(&"/app/lib.cjs".to_string()));
    }

    #[test]
    fn candidate_paths_require_includes_cjs_suffixes() {
        let candidates =
            candidate_paths("/app/lib", ImportStyle::Require, CompatibilityMode::Native);
        assert!(candidates.contains(&"/app/lib".to_string()));
        assert!(candidates.contains(&"/app/lib.cjs".to_string()));
        assert!(candidates.contains(&"/app/lib.js".to_string()));
        assert!(candidates.contains(&"/app/lib/index.cjs".to_string()));
        assert!(candidates.contains(&"/app/lib/index.js".to_string()));
        assert!(!candidates.contains(&"/app/lib.mjs".to_string()));
    }

    #[test]
    fn candidate_paths_require_excludes_mjs_suffixes_in_node_compat_mode() {
        let candidates = candidate_paths(
            "/app/lib",
            ImportStyle::Require,
            CompatibilityMode::NodeCompat,
        );
        assert!(candidates.contains(&"/app/lib".to_string()));
        assert!(candidates.contains(&"/app/lib.cjs".to_string()));
        assert!(candidates.contains(&"/app/lib.js".to_string()));
        assert!(candidates.contains(&"/app/lib/index.cjs".to_string()));
        assert!(candidates.contains(&"/app/lib/index.js".to_string()));
        assert!(!candidates.contains(&"/app/lib.mjs".to_string()));
        assert!(!candidates.contains(&"/app/lib/index.mjs".to_string()));
    }

    #[test]
    fn candidate_paths_require_includes_mjs_suffixes_in_bun_compat_mode() {
        let candidates = candidate_paths(
            "/app/lib",
            ImportStyle::Require,
            CompatibilityMode::BunCompat,
        );
        assert!(candidates.contains(&"/app/lib".to_string()));
        assert!(candidates.contains(&"/app/lib.cjs".to_string()));
        assert!(candidates.contains(&"/app/lib.js".to_string()));
        assert!(candidates.contains(&"/app/lib/index.cjs".to_string()));
        assert!(candidates.contains(&"/app/lib/index.js".to_string()));
        assert!(candidates.contains(&"/app/lib.mjs".to_string()));
        assert!(candidates.contains(&"/app/lib/index.mjs".to_string()));
    }

    #[test]
    fn candidate_paths_import_with_explicit_extension_has_single_candidate() {
        let candidates = candidate_paths(
            "/app/lib.mjs",
            ImportStyle::Import,
            CompatibilityMode::Native,
        );
        assert_eq!(candidates, vec!["/app/lib.mjs".to_string()]);
    }

    #[test]
    fn candidate_paths_require_with_explicit_extension_has_single_candidate() {
        let candidates = candidate_paths(
            "/app/lib.cjs",
            ImportStyle::Require,
            CompatibilityMode::NodeCompat,
        );
        assert_eq!(candidates, vec!["/app/lib.cjs".to_string()]);
    }

    #[test]
    fn candidate_paths_import_with_explicit_cjs_extension_has_single_candidate() {
        let candidates = candidate_paths(
            "/app/lib.cjs",
            ImportStyle::Import,
            CompatibilityMode::Native,
        );
        assert_eq!(candidates, vec!["/app/lib.cjs".to_string()]);
    }

    #[test]
    fn candidate_paths_require_with_explicit_mjs_extension_has_single_candidate() {
        let candidates = candidate_paths(
            "/app/lib.mjs",
            ImportStyle::Require,
            CompatibilityMode::NodeCompat,
        );
        assert_eq!(candidates, vec!["/app/lib.mjs".to_string()]);
    }

    #[test]
    fn candidate_paths_import_with_explicit_js_extension_has_single_candidate() {
        let candidates = candidate_paths(
            "/app/lib.js",
            ImportStyle::Import,
            CompatibilityMode::Native,
        );
        assert_eq!(candidates, vec!["/app/lib.js".to_string()]);
    }

    #[test]
    fn candidate_paths_require_with_explicit_js_extension_has_single_candidate() {
        let candidates = candidate_paths(
            "/app/lib.js",
            ImportStyle::Require,
            CompatibilityMode::NodeCompat,
        );
        assert_eq!(candidates, vec!["/app/lib.js".to_string()]);
    }

    #[test]
    fn allow_relative_import_probes_node_compat_esm_referrer_is_false() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export {};"),
            )
            .expect("register ESM referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Import)
            .with_referrer("/app/main.mjs")
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        assert!(
            !resolver.allow_relative_import_probes(&request, "/app/main.mjs"),
            "node_compat ESM referrer should require explicit extensions"
        );
    }

    #[test]
    fn allow_relative_import_probes_require_style_is_true_even_for_esm_referrer() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export {};"),
            )
            .expect("register ESM referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Require)
            .with_referrer("/app/main.mjs")
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        assert!(
            resolver.allow_relative_import_probes(&request, "/app/main.mjs"),
            "require style should always allow relative probes"
        );
    }

    #[test]
    fn allow_relative_import_probes_require_style_external_referrer_is_true() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "pkg/index.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export {};"),
            )
            .expect("register external ESM referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Require)
            .with_referrer("external:pkg/index.mjs")
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        assert!(
            resolver.allow_relative_import_probes(&request, "external:pkg/index.mjs"),
            "require style should allow relative probes for external referrers"
        );
    }

    #[test]
    fn allow_relative_import_probes_node_compat_cjs_referrer_is_true() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = {};"),
            )
            .expect("register CJS referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Import)
            .with_referrer("/app/main.cjs")
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        assert!(
            resolver.allow_relative_import_probes(&request, "/app/main.cjs"),
            "node_compat CJS referrer should allow relative probes"
        );
    }

    #[test]
    fn allow_relative_import_probes_native_cjs_referrer_is_true() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = {};"),
            )
            .expect("register CJS referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Import)
            .with_referrer("/app/main.cjs")
            .with_compatibility_mode(CompatibilityMode::Native);
        assert!(
            resolver.allow_relative_import_probes(&request, "/app/main.cjs"),
            "native CJS referrer should allow relative probes"
        );
    }

    #[test]
    fn allow_relative_import_probes_node_compat_external_esm_referrer_is_false() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "pkg/index.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export {};"),
            )
            .expect("register external ESM referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Import)
            .with_referrer("external:pkg/index.mjs")
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        assert!(
            !resolver.allow_relative_import_probes(&request, "external:pkg/index.mjs"),
            "node_compat external ESM referrer should require explicit extensions"
        );
    }

    #[test]
    fn allow_relative_import_probes_node_compat_external_cjs_referrer_is_true() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "pkg/index.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = {};"),
            )
            .expect("register external CJS referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Import)
            .with_referrer("external:pkg/index.cjs")
            .with_compatibility_mode(CompatibilityMode::NodeCompat);
        assert!(
            resolver.allow_relative_import_probes(&request, "external:pkg/index.cjs"),
            "node_compat external CJS referrer should allow relative probes"
        );
    }

    #[test]
    fn allow_relative_import_probes_bun_compat_esm_referrer_is_true() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export {};"),
            )
            .expect("register ESM referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Import)
            .with_referrer("/app/main.mjs")
            .with_compatibility_mode(CompatibilityMode::BunCompat);
        assert!(
            resolver.allow_relative_import_probes(&request, "/app/main.mjs"),
            "bun_compat ESM referrer should allow relative probes"
        );
    }

    #[test]
    fn allow_relative_import_probes_bun_compat_external_esm_referrer_is_true() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "pkg/index.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export {};"),
            )
            .expect("register external ESM referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Import)
            .with_referrer("external:pkg/index.mjs")
            .with_compatibility_mode(CompatibilityMode::BunCompat);
        assert!(
            resolver.allow_relative_import_probes(&request, "external:pkg/index.mjs"),
            "bun_compat external ESM referrer should allow relative probes"
        );
    }

    #[test]
    fn allow_relative_import_probes_bun_compat_cjs_referrer_is_true() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/main.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = {};"),
            )
            .expect("register CJS referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Import)
            .with_referrer("/app/main.cjs")
            .with_compatibility_mode(CompatibilityMode::BunCompat);
        assert!(
            resolver.allow_relative_import_probes(&request, "/app/main.cjs"),
            "bun_compat CJS referrer should allow relative probes"
        );
    }

    #[test]
    fn allow_relative_import_probes_bun_compat_external_cjs_referrer_is_true() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_external_module(
                "pkg/index.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = {};"),
            )
            .expect("register external CJS referrer");
        let request = ModuleRequest::new("./dep", ImportStyle::Import)
            .with_referrer("external:pkg/index.cjs")
            .with_compatibility_mode(CompatibilityMode::BunCompat);
        assert!(
            resolver.allow_relative_import_probes(&request, "external:pkg/index.cjs"),
            "bun_compat external CJS referrer should allow relative probes"
        );
    }

    // ── Enrichment: join_paths edge cases ────────────────────────

    #[test]
    fn join_paths_absolute_child_returns_child() {
        assert_eq!(join_paths("/base", "/absolute/path"), "/absolute/path");
    }

    #[test]
    fn join_paths_base_with_trailing_slash() {
        assert_eq!(join_paths("/base/", "child.js"), "/base/child.js");
    }

    #[test]
    fn join_paths_base_without_trailing_slash() {
        assert_eq!(join_paths("/base", "child.js"), "/base/child.js");
    }

    // ── Enrichment: absolute specifier not found ─────────────────

    #[test]
    fn absolute_specifier_not_found_returns_module_not_found() {
        let resolver = DeterministicModuleResolver::new("/app");
        let request = ModuleRequest::new("/nonexistent/path.js", ImportStyle::Import);
        let err = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("unregistered absolute path should fail");
        assert_eq!(err.code, ResolutionErrorCode::UnsupportedSpecifier);
    }

    // ── Enrichment: capability-safe host API surface ────────────

    #[test]
    fn host_api_surface_exposes_expected_descriptors() {
        let surface = CapabilitySafeHostApiSurface::standard();
        assert!(surface.descriptor("node:fs", "read_file").is_some());
        assert!(surface.descriptor("node:fs", "write_file").is_some());
        assert!(surface.descriptor("node:net", "connect").is_some());
        assert!(surface.descriptor("node:process", "spawn").is_some());
        let create_hash = surface
            .descriptor("node:crypto", "create_hash")
            .expect("deterministic hash descriptor");
        assert_eq!(
            create_hash.required_capabilities,
            BTreeSet::from([RuntimeCapability::Builtin])
        );
        assert!(surface.descriptor("node:crypto", "create_hmac").is_some());
        assert!(
            surface
                .descriptor("node:crypto", "timing_safe_equal")
                .is_some()
        );
        assert!(surface.descriptor("node:crypto", "pbkdf2_sync").is_some());
        assert!(surface.descriptor("node:crypto", "scrypt_sync").is_some());
        assert!(
            surface
                .descriptor("node:crypto", "create_cipheriv")
                .is_some()
        );
        assert!(
            surface
                .descriptor("node:crypto", "create_decipheriv")
                .is_some()
        );
        assert!(surface.descriptor("node:crypto", "get_hashes").is_some());
        assert!(surface.descriptor("node:crypto", "get_ciphers").is_some());
        assert!(surface.descriptor("node:crypto", "constants").is_some());
        assert!(
            surface.descriptor("node:crypto", "random_int").is_none(),
            "argument-blind host authorization must not overgrant entropy-producing randomInt"
        );
        assert!(
            surface.descriptor("node:crypto", "random_bytes").is_none(),
            "entropy-producing operations stay fail-closed until a trusted entropy capability exists"
        );
    }

    #[test]
    fn host_api_authorization_allows_granted_operation() {
        let surface = CapabilitySafeHostApiSurface::standard();
        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        let policy = CapabilityPolicyHook::new(granted);
        let request = HostApiRequest::new("node:fs", "read_file");
        let outcome = surface
            .authorize(&request, &context(), &policy)
            .expect("serde serialization should succeed");
        assert_eq!(outcome.event.outcome, "allow");
        assert_eq!(outcome.event.error_code, "none");
        assert!(outcome.event.decision_stable_id.starts_with("hostapi-dec-"));
        assert_eq!(outcome.event.module_specifier, "node:fs");
        assert_eq!(outcome.event.operation, "read_file");
    }

    #[test]
    fn host_api_authorization_denies_missing_capability_deterministically() {
        let surface = CapabilitySafeHostApiSurface::standard();
        let policy = CapabilityPolicyHook::new(BTreeSet::new());
        let request = HostApiRequest::new(" node:process ", " spawn ");
        let err1 = surface
            .authorize(&request, &context(), &policy)
            .expect_err("process spawn should be denied without capability");
        let err2 = surface
            .authorize(&request, &context(), &policy)
            .expect_err("repeat denial should be stable");
        assert_eq!(err1.code, HostApiErrorCode::PolicyDenied);
        assert_eq!(err1.event.error_code, "FE-HOSTAPI-0003");
        assert_eq!(err1.event.module_specifier, "node:process");
        assert_eq!(err1.event.operation, "spawn");
        assert_eq!(err1.event.decision_stable_id, err2.event.decision_stable_id);
    }

    #[test]
    fn host_api_authorization_rejects_unsupported_module_with_guidance() {
        let surface = CapabilitySafeHostApiSurface::standard();
        let policy = CapabilityPolicyHook::new(BTreeSet::new());
        let request = HostApiRequest::new("node:dgram", "send");
        let err = surface
            .authorize(&request, &context(), &policy)
            .expect_err("unsupported module should deny");
        assert_eq!(err.code, HostApiErrorCode::UnsupportedModule);
        assert_eq!(err.event.error_code, "FE-HOSTAPI-0001");
        assert!(err.event.required_capabilities.is_empty());
        assert!(err.event.remediation.contains("node:fs"));
        assert!(err.event.remediation.contains("node:crypto"));
    }

    #[test]
    fn host_api_authorization_rejects_unsupported_operation_with_guidance() {
        let surface = CapabilitySafeHostApiSurface::standard();
        let policy = CapabilityPolicyHook::new(BTreeSet::new());
        let request = HostApiRequest::new("node:fs", "delete_tree");
        let err = surface
            .authorize(&request, &context(), &policy)
            .expect_err("unsupported operation should deny");
        assert_eq!(err.code, HostApiErrorCode::UnsupportedOperation);
        assert_eq!(err.event.error_code, "FE-HOSTAPI-0002");
        assert!(err.event.required_capabilities.is_empty());
        assert!(err.event.remediation.contains("read_file"));
        assert!(err.event.remediation.contains("write_file"));
    }

    #[test]
    fn host_api_authorization_policy_can_block_descriptor() {
        let surface = CapabilitySafeHostApiSurface::standard();
        let descriptor = surface
            .descriptor("node:fs", "read_file")
            .expect("descriptor exists");
        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        let policy = CapabilityPolicyHook::new(granted)
            .deny_host_api_descriptor(descriptor.descriptor_id.clone());
        let request = HostApiRequest::new("node:fs", "read_file");
        let err = surface
            .authorize(&request, &context(), &policy)
            .expect_err("descriptor deny-list should fail closed");
        assert_eq!(err.code, HostApiErrorCode::PolicyDenied);
        assert!(err.message.contains(&descriptor.descriptor_id));
    }
}
