//! Deterministic module resolver trait with policy hooks.
//!
//! This module defines resolution contracts for ES module `import` and
//! CommonJS `require` semantics, with capability-aware policy checks at
//! resolution time.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;
use crate::module_compatibility_matrix::CompatibilityMode;

pub type ResolutionResult<T> = Result<T, Box<ResolutionError>>;
pub type RegistryResult<T> = Result<T, RegistryError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSyntax {
    EsModule,
    CommonJs,
}

impl ModuleSyntax {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EsModule => "esm",
            Self::CommonJs => "cjs",
        }
    }
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
        let mut map = BTreeMap::new();
        map.insert("id".to_string(), CanonicalValue::String(self.id.clone()));
        map.insert(
            "syntax".to_string(),
            CanonicalValue::String(self.syntax.as_str().to_string()),
        );
        map.insert(
            "source".to_string(),
            CanonicalValue::String(self.source.clone()),
        );

        let dependencies = self
            .dependencies
            .iter()
            .map(|dep| {
                let mut entry = BTreeMap::new();
                entry.insert(
                    "specifier".to_string(),
                    CanonicalValue::String(dep.specifier.clone()),
                );
                entry.insert(
                    "style".to_string(),
                    CanonicalValue::String(dep.style.as_str().to_string()),
                );
                CanonicalValue::Map(entry)
            })
            .collect();
        map.insert(
            "dependencies".to_string(),
            CanonicalValue::Array(dependencies),
        );

        let required_caps = self
            .required_capabilities
            .iter()
            .map(|cap| CanonicalValue::String(cap.to_string()))
            .collect();
        map.insert(
            "required_capabilities".to_string(),
            CanonicalValue::Array(required_caps),
        );

        let mut provenance = BTreeMap::new();
        provenance.insert(
            "kind".to_string(),
            CanonicalValue::String(self.provenance.kind.as_str().to_string()),
        );
        provenance.insert(
            "origin".to_string(),
            CanonicalValue::String(self.provenance.origin.clone()),
        );
        map.insert("provenance".to_string(), CanonicalValue::Map(provenance));

        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
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

pub const MODULE_RESOLUTION_TRACE_SCHEMA_VERSION: &str = "rgc.module-resolution.trace.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionOutcome {
    pub module: ResolvedModule,
    pub event: ResolutionEvent,
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
        surface.insert_descriptor(
            "hostapi.node-crypto.random-bytes.v1",
            "node:crypto",
            "random_bytes",
            &[RuntimeCapability::IdempotencyDerive],
            "Grant `idempotency_derive` capability before calling node:crypto.random_bytes.",
        );
        surface.insert_descriptor(
            "hostapi.node-crypto.sha256.v1",
            "node:crypto",
            "sha256",
            &[RuntimeCapability::IdempotencyDerive],
            "Grant `idempotency_derive` capability before calling node:crypto.sha256.",
        );

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
    UnsupportedSpecifier,
    ModuleNotFound,
    PolicyDenied,
}

impl ResolutionErrorCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::EmptySpecifier => "FE-MODRES-0001",
            Self::InvalidReferrer => "FE-MODRES-0002",
            Self::UnsupportedSpecifier => "FE-MODRES-0003",
            Self::ModuleNotFound => "FE-MODRES-0004",
            Self::PolicyDenied => "FE-MODRES-0005",
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

    fn resolve_chain(
        &self,
        entry_request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<Vec<ResolutionOutcome>>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicModuleResolver {
    root_dir: String,
    builtins: BTreeMap<String, ModuleRecord>,
    workspace_modules: BTreeMap<String, ModuleRecord>,
    external_modules: BTreeMap<String, ModuleRecord>,
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
        let specifier = specifier.into();
        if specifier.trim().is_empty() {
            return Err(RegistryError::empty_key());
        }

        let id = format!("external:{specifier}");
        let record =
            ModuleRecord::from_definition(id, ModuleSourceKind::ExternalRegistry, definition);
        self.external_modules.insert(specifier, record);
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
                let package_root = external_package_root(external_referrer);
                let base_dir = external_referrer_directory(external_referrer);
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
                let (relative_probes, candidate) =
                    self.lookup_external_candidate(&resolved_base, request.style, allow_probes);
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
            let (relative_probes, candidate) =
                self.lookup_workspace_candidate(&resolved_base, request.style, allow_probes);
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
            let (absolute_probes, candidate) =
                self.lookup_workspace_candidate(&resolved_base, request.style, true);
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

        let (external_probes, external_candidate) =
            self.lookup_external_candidate(specifier, request.style, true);
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
        let (workspace_probes, workspace_candidate) =
            self.lookup_workspace_candidate(&workspace_base, request.style, true);
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
        Ok(parent_directory(&normalized))
    }

    fn lookup_workspace_candidate<'a>(
        &'a self,
        resolved_base: &str,
        style: ImportStyle,
        allow_probes: bool,
    ) -> (Vec<String>, Option<(String, &'a ModuleRecord)>) {
        let mut probes = Vec::new();
        let candidates = if allow_probes {
            candidate_paths(resolved_base, style)
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
        allow_probes: bool,
    ) -> (Vec<String>, Option<(String, &'a ModuleRecord)>) {
        let mut probes = Vec::new();
        let candidates = if allow_probes {
            candidate_paths(specifier, style)
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

    fn referrer_module_syntax(&self, referrer: &str) -> Option<ModuleSyntax> {
        if let Some(external_referrer) = referrer.strip_prefix("external:") {
            return self
                .external_modules
                .get(external_referrer)
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
            Some(ModuleSyntax::EsModule)
        )
    }
}

impl ModuleResolver for DeterministicModuleResolver {
    fn resolve(
        &self,
        request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<ResolutionOutcome> {
        let (canonical_specifier, record, probe_sequence) =
            self.resolve_candidate(request, context)?;
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
                Box::new((*error).with_resolution_attempt(
                    request.specifier.clone(),
                    Some(canonical_specifier.clone()),
                    Some(record.provenance.kind),
                    probe_sequence.clone(),
                ))
            })?;

        let resolved = ResolvedModule {
            request_specifier: request.specifier.clone(),
            canonical_specifier,
            record: record.clone(),
            content_hash: record.canonical_hash(),
            probe_sequence,
        };

        Ok(ResolutionOutcome {
            module: resolved,
            event: success_event(context),
        })
    }

    fn resolve_chain(
        &self,
        entry_request: &ModuleRequest,
        context: &ResolutionContext,
        policy: &dyn ModulePolicyHook,
    ) -> ResolutionResult<Vec<ResolutionOutcome>> {
        let mut queue = VecDeque::new();
        queue.push_back(entry_request.clone());

        let mut outcomes = Vec::new();
        let mut visited = BTreeSet::new();

        while let Some(request) = queue.pop_front() {
            let outcome = self.resolve(&request, context, policy)?;
            let module_id = outcome.module.record.id.clone();
            if !visited.insert(module_id.clone()) {
                continue;
            }

            for dependency in &outcome.module.record.dependencies {
                queue.push_back(
                    ModuleRequest::new(dependency.specifier.clone(), dependency.style)
                        .with_referrer(module_id.clone())
                        .with_compatibility_mode(request.compatibility_mode),
                );
            }

            outcomes.push(outcome);
        }

        Ok(outcomes)
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

fn candidate_paths(base: &str, style: ImportStyle) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();

    let mut push = |candidate: String| {
        if seen.insert(candidate.clone()) {
            candidates.push(candidate);
        }
    };

    push(base.to_string());

    let suffixes: &[&str] = match style {
        ImportStyle::Import => &[".mjs", ".js", "/index.mjs", "/index.js"],
        ImportStyle::Require => &[".cjs", ".js", "/index.cjs", "/index.js"],
    };

    for suffix in suffixes {
        push(format!("{base}{suffix}"));
    }

    candidates
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
    name.ends_with(".mjs") || name.ends_with(".cjs") || name.ends_with(".js")
}

fn strip_module_file_extension(name: &str) -> String {
    name.strip_suffix(".mjs")
        .or_else(|| name.strip_suffix(".cjs"))
        .or_else(|| name.strip_suffix(".js"))
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
    fn builtin_resolution_is_deterministic() {
        let mut resolver = DeterministicModuleResolver::new("/workspace");
        resolver
            .register_builtin(
                "franken:std/fs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const read = true;")
                    .require_capability(RuntimeCapability::FsRead)
                    .with_provenance("builtin:franken:std/fs"),
            )
            .unwrap();

        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        let policy = CapabilityPolicyHook::new(granted);

        let request = ModuleRequest::new("franken:std/fs", ImportStyle::Import);
        let first = resolver.resolve(&request, &context(), &policy).unwrap();
        let second = resolver.resolve(&request, &context(), &policy).unwrap();

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
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/lib.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .unwrap();

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
            .unwrap();
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
            .unwrap();

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
            .unwrap();
        resolver
            .register_external_module(
                "other-pkg/private.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'secret';"),
            )
            .unwrap();

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
    fn external_package_root_strips_extension_probe_entry_suffix() {
        assert_eq!(external_package_root("pkg.js"), "pkg");
        assert_eq!(external_package_root("@scope/pkg.js"), "@scope/pkg");
        assert_eq!(external_package_root("pkg/index.cjs"), "pkg");
    }

    #[test]
    fn require_rejects_esm_resolution_even_when_extension_probing_finds_js() {
        let mut resolver = DeterministicModuleResolver::new("/repo");
        resolver
            .register_workspace_module(
                "/repo/pkg/index.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'esm';"),
            )
            .unwrap();

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
            .unwrap();

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
            .unwrap();
        resolver
            .register_workspace_module(
                "/repo/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const value = 1;"),
            )
            .unwrap();

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
            .unwrap();

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
    fn external_resolution_preserves_provenance() {
        let mut resolver = DeterministicModuleResolver::new("/workspace");
        resolver
            .register_external_module(
                "left-pad",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = function(){};")
                    .with_provenance("registry:npm:left-pad@1.3.0"),
            )
            .unwrap();

        let request = ModuleRequest::new("left-pad", ImportStyle::Require);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();

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
            .unwrap();
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
            .unwrap();

        let request = ModuleRequest::new("/app/lib/util.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
            .unwrap();

        let request = ModuleRequest::new("utils", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/lib/index.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();

        let request = ModuleRequest::new("./lib", ImportStyle::Import)
            .with_referrer("/app/main.mjs")
            .with_compatibility_mode(CompatibilityMode::BunCompat);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(outcome.module.canonical_specifier, "/app/lib/index.mjs");
    }

    #[test]
    fn require_probes_index_cjs_for_directory_specifier() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/lib/index.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .unwrap();

        let request =
            ModuleRequest::new("./lib", ImportStyle::Require).with_referrer("/app/main.js");
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
            .unwrap();

        let request =
            ModuleRequest::new("./sub", ImportStyle::Import).with_referrer("builtin:franken:fs");
        let error = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .expect_err("relative from builtin referrer should fail");
        assert_eq!(error.code, ResolutionErrorCode::UnsupportedSpecifier);
        assert_eq!(error.code.stable_code(), "FE-MODRES-0003");
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
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/dep.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();

        let request = ModuleRequest::new("/app/entry.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .unwrap();

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
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/b.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './a.js';")
                    .with_dependency(ModuleDependency::new("./a.js", ImportStyle::Import)),
            )
            .unwrap();

        let request = ModuleRequest::new("/app/a.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .unwrap();

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
            .unwrap();

        let request = ModuleRequest::new("/app/leaf.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
            .unwrap();

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
            .unwrap();

        let request = ModuleRequest::new("/app/anything.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        assert_eq!(outcome.event.outcome, "allow");
    }

    // -----------------------------------------------------------------------
    // ModuleSyntax / ImportStyle / ModuleSourceKind as_str
    // -----------------------------------------------------------------------

    #[test]
    fn module_syntax_as_str() {
        assert_eq!(ModuleSyntax::EsModule.as_str(), "esm");
        assert_eq!(ModuleSyntax::CommonJs.as_str(), "cjs");
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
    fn module_record_canonical_hash_is_deterministic() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/det.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                    .with_provenance("workspace:/app/det.js"),
            )
            .unwrap();

        let request = ModuleRequest::new("/app/det.js", ImportStyle::Import);
        let r1 = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
        let r2 = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
        ];
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "all stable codes must be unique");
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
        for syntax in &[ModuleSyntax::EsModule, ModuleSyntax::CommonJs] {
            let json = serde_json::to_string(syntax).expect("serialize");
            let decoded: ModuleSyntax = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, syntax);
        }
    }

    #[test]
    fn import_style_serde_round_trip() {
        for style in &[ImportStyle::Import, ImportStyle::Require] {
            let json = serde_json::to_string(style).expect("serialize");
            let decoded: ImportStyle = serde_json::from_str(&json).expect("deserialize");
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
        ];
        for code in &codes {
            let json = serde_json::to_string(code).expect("serialize");
            let decoded: ResolutionErrorCode = serde_json::from_str(&json).expect("deserialize");
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
            .unwrap();

        let request = ModuleRequest::new("/workspace/src/lib.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
            .unwrap();
        resolver
            .register_builtin(
                "franken:util",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const v = 2;"),
            )
            .unwrap();

        let request = ModuleRequest::new("franken:util", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
        let json = serde_json::to_string(&mp).expect("serialize");
        let restored: ModuleProvenance = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mp, restored);
    }

    #[test]
    fn module_dependency_serde_roundtrip() {
        let md = ModuleDependency {
            specifier: "./utils.js".to_string(),
            style: ImportStyle::Import,
        };
        let json = serde_json::to_string(&md).expect("serialize");
        let restored: ModuleDependency = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(md, restored);
    }

    #[test]
    fn module_request_serde_roundtrip() {
        let mr = ModuleRequest::new("franken:core", ImportStyle::Import);
        let json = serde_json::to_string(&mr).expect("serialize");
        let restored: ModuleRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mr, restored);
    }

    #[test]
    fn module_request_serde_roundtrip_with_bun_compat_mode() {
        let mr = ModuleRequest::new("pkg", ImportStyle::Require)
            .with_referrer("/repo/main.cjs")
            .with_compatibility_mode(CompatibilityMode::BunCompat);
        let json = serde_json::to_string(&mr).expect("serialize");
        let restored: ModuleRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(mr, restored);
        assert_eq!(restored.compatibility_mode, CompatibilityMode::BunCompat);
    }

    #[test]
    fn module_request_legacy_json_defaults_to_native_compat_mode() {
        let restored: ModuleRequest = serde_json::from_str(
            r#"{"specifier":"pkg","referrer":"/repo/main.cjs","style":"require"}"#,
        )
        .expect("deserialize");
        assert_eq!(restored.compatibility_mode, CompatibilityMode::Native);
    }

    #[test]
    fn resolution_context_serde_roundtrip() {
        let ctx = ResolutionContext {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
        };
        let json = serde_json::to_string(&ctx).expect("serialize");
        let restored: ResolutionContext = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ctx, restored);
    }

    #[test]
    fn registry_error_serde_roundtrip() {
        let err = RegistryError {
            code: RegistryErrorCode::EmptyKey,
            message: "key must not be empty".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: RegistryError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, restored);
    }

    #[test]
    fn allow_all_policy_default_serde() {
        let p = AllowAllPolicy;
        let json = serde_json::to_string(&p).expect("serialize");
        let restored: AllowAllPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, restored);
    }

    #[test]
    fn module_source_kind_serde_roundtrip() {
        for kind in [
            ModuleSourceKind::BuiltIn,
            ModuleSourceKind::Workspace,
            ModuleSourceKind::ExternalRegistry,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let restored: ModuleSourceKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(kind, restored);
        }
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn module_syntax_display_unique() {
        let displays: BTreeSet<String> = [ModuleSyntax::EsModule, ModuleSyntax::CommonJs]
            .iter()
            .map(|s| s.as_str().to_string())
            .collect();
        assert_eq!(displays.len(), 2);
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
        ];
        let stable: BTreeSet<String> = codes.iter().map(|c| c.stable_code().to_string()).collect();
        assert_eq!(stable.len(), 5);
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
            .unwrap();

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
        let json = serde_json::to_string(&code).expect("serialize");
        let back: RegistryErrorCode = serde_json::from_str(&json).expect("deserialize");
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
            .unwrap();

        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        granted.insert(RuntimeCapability::FsWrite);
        let policy = CapabilityPolicyHook::new(granted);

        let request = ModuleRequest::new("/app/multi.js", ImportStyle::Import);
        let outcome = resolver.resolve(&request, &context(), &policy).unwrap();
        assert_eq!(outcome.event.outcome, "allow");
    }

    // ── Enrichment: serde roundtrips for remaining types ─────────

    #[test]
    fn module_definition_serde_roundtrip() {
        let def = ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
            .with_dependency(ModuleDependency::new("./util", ImportStyle::Import))
            .require_capability(RuntimeCapability::FsRead)
            .with_provenance("test:origin");
        let json = serde_json::to_string(&def).expect("serialize");
        let restored: ModuleDefinition = serde_json::from_str(&json).expect("deserialize");
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
        let json = serde_json::to_string(&ev).expect("serialize");
        let restored: ResolutionEvent = serde_json::from_str(&json).expect("deserialize");
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
            .unwrap();

        let request = ModuleRequest::new("/app/lib", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();

        let value = serde_json::to_value(&outcome.module).expect("serialize");
        assert_eq!(
            value.get("probe_sequence"),
            Some(&serde_json::json!(["/app/lib", "/app/lib.mjs"]))
        );

        let restored: ResolvedModule = serde_json::from_value(value).expect("deserialize");
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

        let value = serde_json::to_value(&module).expect("serialize");
        assert!(value.get("probe_sequence").is_none());

        let restored: ResolvedModule = serde_json::from_value(value).expect("deserialize");
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
            .unwrap();
        let request = ModuleRequest::new("left-pad", ImportStyle::Require);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();

        let json = serde_json::to_string(&outcome).expect("serialize");
        let restored: ResolutionOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(outcome, restored);
        assert_eq!(restored.module.probe_sequence, vec!["left-pad"]);
    }

    #[test]
    fn resolution_outcome_trace_record_roundtrip_preserves_required_fields() {
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module(
                "/app/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();

        let outcome = resolver
            .resolve(
                &ModuleRequest::new("./lib", ImportStyle::Import)
                    .with_referrer("/app/main.mjs")
                    .with_compatibility_mode(CompatibilityMode::BunCompat),
                &context(),
                &AllowAllPolicy,
            )
            .unwrap();

        let trace = outcome.trace_record();
        assert_eq!(trace.schema_version, MODULE_RESOLUTION_TRACE_SCHEMA_VERSION);
        assert_eq!(trace.request_specifier, "./lib");
        assert_eq!(trace.canonical_specifier, "/app/lib.mjs");
        assert_eq!(trace.source_kind, "workspace");
        assert_eq!(trace.probe_sequence, vec!["/app/lib", "/app/lib.mjs"]);
        assert_eq!(trace.outcome, "allow");
        assert_eq!(trace.error_code, "none");

        let restored: ModuleResolutionTraceRecord =
            serde_json::from_str(&trace.to_json_line().expect("serialize")).expect("deserialize");
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
            .unwrap();

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
        let json = serde_json::to_string(&hook).expect("serialize");
        let restored: CapabilityPolicyHook = serde_json::from_str(&json).expect("deserialize");
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
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/lib.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();
        resolver
            .register_external_module(
                "left-pad",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = pad;"),
            )
            .unwrap();
        let json = serde_json::to_string(&resolver).expect("serialize");
        let restored: DeterministicModuleResolver =
            serde_json::from_str(&json).expect("deserialize");
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
        let json = serde_json::to_string(&err).expect("serialize");
        let restored: ResolutionError = serde_json::from_str(&json).expect("deserialize");
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
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/src/main.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import '../shared/util.js';"),
            )
            .unwrap();
        let request = ModuleRequest::new("../shared/util.js", ImportStyle::Import)
            .with_referrer("/app/src/main.js");
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/b.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "import './c.js';")
                    .with_dependency(ModuleDependency::new("./c.js", ImportStyle::Import)),
            )
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/c.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 3;"),
            )
            .unwrap();
        let request = ModuleRequest::new("/app/a.js", ImportStyle::Import);
        let chain = resolver
            .resolve_chain(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/restricted.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;")
                    .require_capability(RuntimeCapability::FsWrite),
            )
            .unwrap();
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
            .unwrap();
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
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/v2.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 2;"),
            )
            .unwrap();
        let r1 = resolver
            .resolve(
                &ModuleRequest::new("/app/v1.js", ImportStyle::Import),
                &context(),
                &AllowAllPolicy,
            )
            .unwrap();
        let r2 = resolver
            .resolve(
                &ModuleRequest::new("/app/v2.js", ImportStyle::Import),
                &context(),
                &AllowAllPolicy,
            )
            .unwrap();
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
            .unwrap();
        resolver
            .register_workspace_module(
                "/app/mod.js",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export const v = 2;"),
            )
            .unwrap();
        let request = ModuleRequest::new("/app/mod.js", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
            .unwrap();
        resolver
            .register_external_module(
                "lodash",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "v2"),
            )
            .unwrap();
        let request = ModuleRequest::new("lodash", ImportStyle::Require);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
            .unwrap();
        let request = ModuleRequest::new("my-pkg", ImportStyle::Import);
        let outcome = resolver
            .resolve(&request, &context(), &AllowAllPolicy)
            .unwrap();
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
            .unwrap();
        resolver
            .register_external_module(
                "some-pkg/sub.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 1;"),
            )
            .unwrap();

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
            .unwrap();

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
            .unwrap();
        resolver
            .register_external_module(
                "pkg/sub.cjs",
                ModuleDefinition::new(ModuleSyntax::CommonJs, "module.exports = 1;"),
            )
            .unwrap();

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
            .unwrap();
        resolver
            .register_external_module(
                "pkg/lib.mjs",
                ModuleDefinition::new(ModuleSyntax::EsModule, "export default 'esm';"),
            )
            .unwrap();

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

    // ── Enrichment: ModuleRequest with_referrer serde ────────────

    #[test]
    fn module_request_with_referrer_serde_roundtrip() {
        let mr = ModuleRequest::new("./dep", ImportStyle::Import).with_referrer("/app/main.js");
        let json = serde_json::to_string(&mr).expect("serialize");
        let restored: ModuleRequest = serde_json::from_str(&json).expect("deserialize");
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
            .unwrap();
        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        let policy = CapabilityPolicyHook::new(granted);
        let request = ModuleRequest::new("/app/full.js", ImportStyle::Import);
        let outcome = resolver.resolve(&request, &context(), &policy).unwrap();
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
            panic!("canonical_value should be a Map");
        }
    }

    // ── Enrichment: candidate_paths diverge by style ─────────────

    #[test]
    fn candidate_paths_import_includes_mjs_suffixes() {
        let candidates = candidate_paths("/app/lib", ImportStyle::Import);
        assert!(candidates.contains(&"/app/lib".to_string()));
        assert!(candidates.contains(&"/app/lib.mjs".to_string()));
        assert!(candidates.contains(&"/app/lib.js".to_string()));
        assert!(candidates.contains(&"/app/lib/index.mjs".to_string()));
        assert!(candidates.contains(&"/app/lib/index.js".to_string()));
        assert!(!candidates.contains(&"/app/lib.cjs".to_string()));
    }

    #[test]
    fn candidate_paths_require_includes_cjs_suffixes() {
        let candidates = candidate_paths("/app/lib", ImportStyle::Require);
        assert!(candidates.contains(&"/app/lib".to_string()));
        assert!(candidates.contains(&"/app/lib.cjs".to_string()));
        assert!(candidates.contains(&"/app/lib.js".to_string()));
        assert!(candidates.contains(&"/app/lib/index.cjs".to_string()));
        assert!(candidates.contains(&"/app/lib/index.js".to_string()));
        assert!(!candidates.contains(&"/app/lib.mjs".to_string()));
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
        assert!(surface.descriptor("node:crypto", "random_bytes").is_some());
        assert!(surface.descriptor("node:crypto", "sha256").is_some());
    }

    #[test]
    fn host_api_authorization_allows_granted_operation() {
        let surface = CapabilitySafeHostApiSurface::standard();
        let mut granted = BTreeSet::new();
        granted.insert(RuntimeCapability::FsRead);
        let policy = CapabilityPolicyHook::new(granted);
        let request = HostApiRequest::new("node:fs", "read_file");
        let outcome = surface.authorize(&request, &context(), &policy).unwrap();
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
