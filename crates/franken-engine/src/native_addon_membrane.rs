//! Capability-safe Node-API and native-addon membrane planning.
//!
//! This module inventories native-addon cohorts, derives deterministic ABI
//! fingerprints, and plans whether an addon can run directly behind a
//! capability membrane, through a fallback lane, or not at all.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityProfile, RuntimeCapability};
use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;
use crate::module_resolver::ResolutionContext;
use crate::self_replacement::{DelegateType, SandboxConfiguration};
use crate::slot_registry::{AuthorityEnvelope, SlotCapability};

pub const COMPONENT: &str = "native_addon_membrane";
pub const EVENT: &str = "native_addon_route_plan";
pub const INVENTORY_SCHEMA_VERSION: &str = "franken-engine.native-addon-membrane.v1";
pub const MEMBRANE_REPORT_SCHEMA_VERSION: &str = "franken-engine.native-addon-membrane.report.v1";
pub const HANDLE_SAFETY_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.native-addon-membrane.handle-safety.v1";
pub const EXECUTION_DISPOSITION_SCHEMA_VERSION: &str =
    "franken-engine.native-addon-membrane.execution-disposition.v1";
pub const FALLBACK_RECEIPTS_SCHEMA_VERSION: &str =
    "franken-engine.native-addon-membrane.fallback-receipts.v1";
pub const TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.trace-ids.v1";
pub const RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.native-addon-membrane.run-manifest.v1";
pub const BEAD_ID: &str = "bd-1lsy.5.9";

pub type NativeAddonMembraneResult<T> = Result<T, Box<NativeAddonMembraneError>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonAbiSurface {
    NodeApi,
    Nan,
    V8Direct,
    ForeignFfi,
    Unknown,
}

impl NativeAddonAbiSurface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeApi => "node_api",
            Self::Nan => "nan",
            Self::V8Direct => "v8_direct",
            Self::ForeignFfi => "foreign_ffi",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for NativeAddonAbiSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonCohort {
    NodeApiPortable,
    NodeApiIsolateBound,
    NodeApiPrivileged,
    LegacyNan,
    V8Binding,
    ForeignFfi,
    Unknown,
}

impl NativeAddonCohort {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeApiPortable => "node_api_portable",
            Self::NodeApiIsolateBound => "node_api_isolate_bound",
            Self::NodeApiPrivileged => "node_api_privileged",
            Self::LegacyNan => "legacy_nan",
            Self::V8Binding => "v8_binding",
            Self::ForeignFfi => "foreign_ffi",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for NativeAddonCohort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonFallbackMode {
    WasmPort,
    DelegateCell,
}

impl NativeAddonFallbackMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WasmPort => "wasm_port",
            Self::DelegateCell => "delegate_cell",
        }
    }
}

impl fmt::Display for NativeAddonFallbackMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonRoute {
    DirectMembrane,
    WasmPort,
    DelegateCell,
}

impl NativeAddonRoute {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectMembrane => "direct_membrane",
            Self::WasmPort => "wasm_port",
            Self::DelegateCell => "delegate_cell",
        }
    }
}

impl fmt::Display for NativeAddonRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonSupportStatus {
    Direct,
    FallbackOnly,
    Unsupported,
}

impl NativeAddonSupportStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::FallbackOnly => "fallback_only",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for NativeAddonSupportStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonRiskClassification {
    Low,
    Medium,
    High,
    Critical,
}

impl NativeAddonRiskClassification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for NativeAddonRiskClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonHandleDiscipline {
    NodeApiOnly,
    ThreadSafeFunctionOnly,
    FinalizerBounded,
    ExternalBuffer,
    RawPointerEscape,
}

impl NativeAddonHandleDiscipline {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeApiOnly => "node_api_only",
            Self::ThreadSafeFunctionOnly => "thread_safe_function_only",
            Self::FinalizerBounded => "finalizer_bounded",
            Self::ExternalBuffer => "external_buffer",
            Self::RawPointerEscape => "raw_pointer_escape",
        }
    }

    pub const fn is_direct_safe(self) -> bool {
        matches!(
            self,
            Self::NodeApiOnly | Self::ThreadSafeFunctionOnly | Self::FinalizerBounded
        )
    }
}

impl fmt::Display for NativeAddonHandleDiscipline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonSymbolClass {
    ValueExport,
    FunctionExport,
    ThreadSafeFunction,
    Finalizer,
    PropertyAccessor,
    ExternalBuffer,
    ForeignCallback,
    GlobalStateHook,
    Unknown,
}

impl NativeAddonSymbolClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValueExport => "value_export",
            Self::FunctionExport => "function_export",
            Self::ThreadSafeFunction => "thread_safe_function",
            Self::Finalizer => "finalizer",
            Self::PropertyAccessor => "property_accessor",
            Self::ExternalBuffer => "external_buffer",
            Self::ForeignCallback => "foreign_callback",
            Self::GlobalStateHook => "global_state_hook",
            Self::Unknown => "unknown",
        }
    }

    pub const fn is_direct_safe(self) -> bool {
        matches!(
            self,
            Self::ValueExport
                | Self::FunctionExport
                | Self::ThreadSafeFunction
                | Self::Finalizer
                | Self::PropertyAccessor
        )
    }
}

impl fmt::Display for NativeAddonSymbolClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonInvocationChannel {
    InProcessMembrane,
    HostcallSession,
}

impl NativeAddonInvocationChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InProcessMembrane => "in_process_membrane",
            Self::HostcallSession => "hostcall_session",
        }
    }
}

impl fmt::Display for NativeAddonInvocationChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonCrashContainment {
    InProcessMembrane,
    WasmSandbox,
    DelegateCellBoundary,
}

impl NativeAddonCrashContainment {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InProcessMembrane => "in_process_membrane",
            Self::WasmSandbox => "wasm_sandbox",
            Self::DelegateCellBoundary => "delegate_cell_boundary",
        }
    }
}

impl fmt::Display for NativeAddonCrashContainment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonMembraneErrorCode {
    MissingCapability,
    UnsupportedAbiSurface,
    UnsafeDirectSurface,
    NoFallbackRoute,
}

impl NativeAddonMembraneErrorCode {
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::MissingCapability => "FE-NAM-0001",
            Self::UnsupportedAbiSurface => "FE-NAM-0002",
            Self::UnsafeDirectSurface => "FE-NAM-0003",
            Self::NoFallbackRoute => "FE-NAM-0004",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonSymbol {
    pub symbol_name: String,
    pub class: NativeAddonSymbolClass,
    pub required_capabilities: BTreeSet<RuntimeCapability>,
}

impl NativeAddonSymbol {
    pub fn new(symbol_name: impl Into<String>, class: NativeAddonSymbolClass) -> Self {
        Self {
            symbol_name: symbol_name.into(),
            class,
            required_capabilities: BTreeSet::new(),
        }
    }

    pub fn require_capability(mut self, capability: RuntimeCapability) -> Self {
        self.required_capabilities.insert(capability);
        self
    }

    fn normalized(&self) -> Self {
        Self {
            symbol_name: self.symbol_name.trim().to_string(),
            class: self.class,
            required_capabilities: self.required_capabilities.clone(),
        }
    }

    fn canonical_value(&self) -> CanonicalValue {
        let normalized = self.normalized();
        let mut map = BTreeMap::new();
        map.insert(
            "class".to_string(),
            CanonicalValue::String(normalized.class.as_str().to_string()),
        );
        map.insert(
            "required_capabilities".to_string(),
            CanonicalValue::Array(
                normalized
                    .required_capabilities
                    .iter()
                    .map(|cap| CanonicalValue::String(cap.to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "symbol_name".to_string(),
            CanonicalValue::String(normalized.symbol_name),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonLoadRequest {
    pub addon_id: String,
    pub package_name: String,
    pub package_version: String,
    pub module_specifier: String,
    pub addon_path: String,
    pub abi_surface: NativeAddonAbiSurface,
    pub node_api_version: Option<u32>,
    pub supported_fallbacks: BTreeSet<NativeAddonFallbackMode>,
    pub symbol_exports: Vec<NativeAddonSymbol>,
    pub handle_discipline: NativeAddonHandleDiscipline,
    pub uses_foreign_heap: bool,
    pub uses_process_global_state: bool,
    pub requires_filesystem_read: bool,
    pub requires_filesystem_write: bool,
    pub requires_network_egress: bool,
    pub requires_process_spawn: bool,
    pub requires_module_linkage: bool,
    pub uses_async_workers: bool,
    pub wasm_portable: bool,
}

impl NativeAddonLoadRequest {
    pub fn new(
        addon_id: impl Into<String>,
        package_name: impl Into<String>,
        package_version: impl Into<String>,
        module_specifier: impl Into<String>,
        addon_path: impl Into<String>,
        abi_surface: NativeAddonAbiSurface,
    ) -> Self {
        Self {
            addon_id: addon_id.into(),
            package_name: package_name.into(),
            package_version: package_version.into(),
            module_specifier: module_specifier.into(),
            addon_path: addon_path.into(),
            abi_surface,
            node_api_version: None,
            supported_fallbacks: BTreeSet::new(),
            symbol_exports: Vec::new(),
            handle_discipline: NativeAddonHandleDiscipline::NodeApiOnly,
            uses_foreign_heap: false,
            uses_process_global_state: false,
            requires_filesystem_read: false,
            requires_filesystem_write: false,
            requires_network_egress: false,
            requires_process_spawn: false,
            requires_module_linkage: false,
            uses_async_workers: false,
            wasm_portable: false,
        }
    }

    pub fn with_node_api_version(mut self, version: u32) -> Self {
        self.node_api_version = Some(version);
        self
    }

    pub fn with_symbol(mut self, symbol: NativeAddonSymbol) -> Self {
        self.symbol_exports.push(symbol);
        self
    }

    pub fn allow_fallback(mut self, fallback: NativeAddonFallbackMode) -> Self {
        self.supported_fallbacks.insert(fallback);
        self
    }

    pub fn with_handle_discipline(mut self, discipline: NativeAddonHandleDiscipline) -> Self {
        self.handle_discipline = discipline;
        self
    }

    pub fn cohort(&self) -> NativeAddonCohort {
        match self.abi_surface {
            NativeAddonAbiSurface::NodeApi => {
                if self.uses_process_global_state
                    || self.uses_foreign_heap
                    || !self.handle_discipline.is_direct_safe()
                {
                    NativeAddonCohort::NodeApiPrivileged
                } else if self.uses_async_workers
                    || self
                        .symbol_exports
                        .iter()
                        .any(|symbol| symbol.class == NativeAddonSymbolClass::ThreadSafeFunction)
                {
                    NativeAddonCohort::NodeApiIsolateBound
                } else {
                    NativeAddonCohort::NodeApiPortable
                }
            }
            NativeAddonAbiSurface::Nan => NativeAddonCohort::LegacyNan,
            NativeAddonAbiSurface::V8Direct => NativeAddonCohort::V8Binding,
            NativeAddonAbiSurface::ForeignFfi => NativeAddonCohort::ForeignFfi,
            NativeAddonAbiSurface::Unknown => NativeAddonCohort::Unknown,
        }
    }

    pub fn required_capabilities(&self) -> BTreeSet<RuntimeCapability> {
        let mut caps = BTreeSet::from([RuntimeCapability::ExtensionLifecycle]);
        if self.requires_filesystem_read {
            caps.insert(RuntimeCapability::FsRead);
        }
        if self.requires_filesystem_write {
            caps.insert(RuntimeCapability::FsWrite);
        }
        if self.requires_network_egress {
            caps.insert(RuntimeCapability::NetworkEgress);
        }
        if self.requires_process_spawn {
            caps.insert(RuntimeCapability::ProcessSpawn);
        }
        if self.uses_foreign_heap
            || matches!(
                self.handle_discipline,
                NativeAddonHandleDiscipline::ExternalBuffer
                    | NativeAddonHandleDiscipline::RawPointerEscape
            )
        {
            caps.insert(RuntimeCapability::HeapAllocate);
        }
        for symbol in &self.symbol_exports {
            caps.extend(symbol.required_capabilities.iter().copied());
        }
        caps
    }

    pub fn required_slot_capabilities(&self) -> Vec<SlotCapability> {
        let mut caps = vec![SlotCapability::EmitEvidence, SlotCapability::InvokeHostcall];
        if self.requires_module_linkage {
            push_slot_capability(&mut caps, SlotCapability::ModuleAccess);
        }
        if self.uses_async_workers
            || self
                .symbol_exports
                .iter()
                .any(|symbol| symbol.class == NativeAddonSymbolClass::ThreadSafeFunction)
        {
            push_slot_capability(&mut caps, SlotCapability::ScheduleAsync);
        }
        if self.uses_foreign_heap
            || matches!(
                self.handle_discipline,
                NativeAddonHandleDiscipline::ExternalBuffer
                    | NativeAddonHandleDiscipline::RawPointerEscape
            )
        {
            push_slot_capability(&mut caps, SlotCapability::HeapAlloc);
        }
        caps.sort_by_key(|cap| slot_capability_sort_key(*cap));
        caps
    }

    pub fn symbol_families(&self) -> Vec<String> {
        self.symbol_exports
            .iter()
            .map(|symbol| symbol.class.as_str().to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn abi_fingerprint(&self) -> ContentHash {
        ContentHash::compute(&encode_value(&self.canonical_value()))
    }

    fn normalized_symbols(&self) -> Vec<NativeAddonSymbol> {
        let mut symbols: Vec<_> = self
            .symbol_exports
            .iter()
            .map(NativeAddonSymbol::normalized)
            .collect();
        symbols.sort_by(|lhs, rhs| {
            (lhs.symbol_name.as_str(), lhs.class.as_str())
                .cmp(&(rhs.symbol_name.as_str(), rhs.class.as_str()))
        });
        symbols
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "abi_surface".to_string(),
            CanonicalValue::String(self.abi_surface.as_str().to_string()),
        );
        map.insert(
            "addon_id".to_string(),
            CanonicalValue::String(self.addon_id.trim().to_string()),
        );
        map.insert(
            "addon_path".to_string(),
            CanonicalValue::String(self.addon_path.trim().to_string()),
        );
        map.insert(
            "handle_discipline".to_string(),
            CanonicalValue::String(self.handle_discipline.as_str().to_string()),
        );
        map.insert(
            "module_specifier".to_string(),
            CanonicalValue::String(self.module_specifier.trim().to_string()),
        );
        map.insert(
            "node_api_version".to_string(),
            self.node_api_version
                .map(|value| CanonicalValue::U64(u64::from(value)))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "package_name".to_string(),
            CanonicalValue::String(self.package_name.trim().to_string()),
        );
        map.insert(
            "package_version".to_string(),
            CanonicalValue::String(self.package_version.trim().to_string()),
        );
        map.insert(
            "requires_filesystem_read".to_string(),
            CanonicalValue::Bool(self.requires_filesystem_read),
        );
        map.insert(
            "requires_filesystem_write".to_string(),
            CanonicalValue::Bool(self.requires_filesystem_write),
        );
        map.insert(
            "requires_module_linkage".to_string(),
            CanonicalValue::Bool(self.requires_module_linkage),
        );
        map.insert(
            "requires_network_egress".to_string(),
            CanonicalValue::Bool(self.requires_network_egress),
        );
        map.insert(
            "requires_process_spawn".to_string(),
            CanonicalValue::Bool(self.requires_process_spawn),
        );
        map.insert(
            "supported_fallbacks".to_string(),
            CanonicalValue::Array(
                self.supported_fallbacks
                    .iter()
                    .map(|mode| CanonicalValue::String(mode.as_str().to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "symbol_exports".to_string(),
            CanonicalValue::Array(
                self.normalized_symbols()
                    .iter()
                    .map(NativeAddonSymbol::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "uses_async_workers".to_string(),
            CanonicalValue::Bool(self.uses_async_workers),
        );
        map.insert(
            "uses_foreign_heap".to_string(),
            CanonicalValue::Bool(self.uses_foreign_heap),
        );
        map.insert(
            "uses_process_global_state".to_string(),
            CanonicalValue::Bool(self.uses_process_global_state),
        );
        map.insert(
            "wasm_portable".to_string(),
            CanonicalValue::Bool(self.wasm_portable),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonSupportSurface {
    pub addon_id: String,
    pub package_name: String,
    pub package_version: String,
    pub module_specifier: String,
    pub addon_path: String,
    pub cohort: NativeAddonCohort,
    pub abi_surface: NativeAddonAbiSurface,
    pub support_status: NativeAddonSupportStatus,
    pub selected_route: Option<NativeAddonRoute>,
    pub missing_capabilities: BTreeSet<RuntimeCapability>,
    pub direct_blockers: Vec<String>,
    pub supported_fallbacks: Vec<NativeAddonFallbackMode>,
    pub required_capabilities: BTreeSet<RuntimeCapability>,
    pub required_slot_capabilities: Vec<SlotCapability>,
    pub symbol_families: Vec<String>,
    pub risk_classification: NativeAddonRiskClassification,
    pub owner_route: String,
    pub remediation_hint: String,
    pub abi_fingerprint: ContentHash,
}

impl NativeAddonSupportSurface {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "abi_fingerprint".to_string(),
            CanonicalValue::String(self.abi_fingerprint.to_hex()),
        );
        map.insert(
            "abi_surface".to_string(),
            CanonicalValue::String(self.abi_surface.as_str().to_string()),
        );
        map.insert(
            "addon_id".to_string(),
            CanonicalValue::String(self.addon_id.clone()),
        );
        map.insert(
            "addon_path".to_string(),
            CanonicalValue::String(self.addon_path.clone()),
        );
        map.insert(
            "cohort".to_string(),
            CanonicalValue::String(self.cohort.as_str().to_string()),
        );
        map.insert(
            "direct_blockers".to_string(),
            CanonicalValue::Array(
                self.direct_blockers
                    .iter()
                    .map(|value| CanonicalValue::String(value.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "missing_capabilities".to_string(),
            CanonicalValue::Array(
                self.missing_capabilities
                    .iter()
                    .map(|cap| CanonicalValue::String(cap.to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "module_specifier".to_string(),
            CanonicalValue::String(self.module_specifier.clone()),
        );
        map.insert(
            "package_name".to_string(),
            CanonicalValue::String(self.package_name.clone()),
        );
        map.insert(
            "package_version".to_string(),
            CanonicalValue::String(self.package_version.clone()),
        );
        map.insert(
            "owner_route".to_string(),
            CanonicalValue::String(self.owner_route.clone()),
        );
        map.insert(
            "required_capabilities".to_string(),
            CanonicalValue::Array(
                self.required_capabilities
                    .iter()
                    .map(|cap| CanonicalValue::String(cap.to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "required_slot_capabilities".to_string(),
            CanonicalValue::Array(
                self.required_slot_capabilities
                    .iter()
                    .map(|cap| CanonicalValue::String(format!("{cap:?}")))
                    .collect(),
            ),
        );
        map.insert(
            "selected_route".to_string(),
            self.selected_route
                .map(|route| CanonicalValue::String(route.as_str().to_string()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "remediation_hint".to_string(),
            CanonicalValue::String(self.remediation_hint.clone()),
        );
        map.insert(
            "risk_classification".to_string(),
            CanonicalValue::String(self.risk_classification.as_str().to_string()),
        );
        map.insert(
            "symbol_families".to_string(),
            CanonicalValue::Array(
                self.symbol_families
                    .iter()
                    .map(|family| CanonicalValue::String(family.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "support_status".to_string(),
            CanonicalValue::String(self.support_status.as_str().to_string()),
        );
        map.insert(
            "supported_fallbacks".to_string(),
            CanonicalValue::Array(
                self.supported_fallbacks
                    .iter()
                    .map(|mode| CanonicalValue::String(mode.as_str().to_string()))
                    .collect(),
            ),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonDecisionEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub decision_stable_id: String,
    pub addon_id: String,
    pub module_specifier: String,
    pub package_name: String,
    pub cohort: NativeAddonCohort,
    pub abi_surface: NativeAddonAbiSurface,
    pub support_status: NativeAddonSupportStatus,
    pub selected_route: Option<NativeAddonRoute>,
    pub missing_capabilities: BTreeSet<RuntimeCapability>,
    pub direct_blockers: Vec<String>,
    pub abi_fingerprint: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonExecutionPlan {
    pub route: NativeAddonRoute,
    pub invocation_channel: NativeAddonInvocationChannel,
    pub crash_containment: NativeAddonCrashContainment,
    pub delegate_type: Option<DelegateType>,
    pub capability_envelope: Option<AuthorityEnvelope>,
    pub sandbox: Option<SandboxConfiguration>,
    pub required_capabilities: BTreeSet<RuntimeCapability>,
    pub support_surface: NativeAddonSupportSurface,
    pub event: NativeAddonDecisionEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonCompatibilityMatrixEntry {
    pub addon_id: String,
    pub package_name: String,
    pub package_version: String,
    pub cohort: NativeAddonCohort,
    pub abi_surface: NativeAddonAbiSurface,
    pub support_status: NativeAddonSupportStatus,
    pub selected_route: Option<NativeAddonRoute>,
    pub abi_fingerprint: ContentHash,
    pub notes: String,
}

impl NativeAddonCompatibilityMatrixEntry {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "abi_fingerprint".to_string(),
            CanonicalValue::String(self.abi_fingerprint.to_hex()),
        );
        map.insert(
            "abi_surface".to_string(),
            CanonicalValue::String(self.abi_surface.as_str().to_string()),
        );
        map.insert(
            "addon_id".to_string(),
            CanonicalValue::String(self.addon_id.clone()),
        );
        map.insert(
            "cohort".to_string(),
            CanonicalValue::String(self.cohort.as_str().to_string()),
        );
        map.insert(
            "notes".to_string(),
            CanonicalValue::String(self.notes.clone()),
        );
        map.insert(
            "package_name".to_string(),
            CanonicalValue::String(self.package_name.clone()),
        );
        map.insert(
            "package_version".to_string(),
            CanonicalValue::String(self.package_version.clone()),
        );
        map.insert(
            "selected_route".to_string(),
            self.selected_route
                .map(|route| CanonicalValue::String(route.as_str().to_string()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "support_status".to_string(),
            CanonicalValue::String(self.support_status.as_str().to_string()),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonAbiFingerprintEntry {
    pub addon_id: String,
    pub package_name: String,
    pub cohort: NativeAddonCohort,
    pub abi_surface: NativeAddonAbiSurface,
    pub supported_fallbacks: Vec<NativeAddonFallbackMode>,
    pub symbol_families: Vec<String>,
    pub fingerprint: ContentHash,
}

impl NativeAddonAbiFingerprintEntry {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "abi_surface".to_string(),
            CanonicalValue::String(self.abi_surface.as_str().to_string()),
        );
        map.insert(
            "addon_id".to_string(),
            CanonicalValue::String(self.addon_id.clone()),
        );
        map.insert(
            "cohort".to_string(),
            CanonicalValue::String(self.cohort.as_str().to_string()),
        );
        map.insert(
            "fingerprint".to_string(),
            CanonicalValue::String(self.fingerprint.to_hex()),
        );
        map.insert(
            "package_name".to_string(),
            CanonicalValue::String(self.package_name.clone()),
        );
        map.insert(
            "symbol_families".to_string(),
            CanonicalValue::Array(
                self.symbol_families
                    .iter()
                    .map(|family| CanonicalValue::String(family.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "supported_fallbacks".to_string(),
            CanonicalValue::Array(
                self.supported_fallbacks
                    .iter()
                    .map(|mode| CanonicalValue::String(mode.as_str().to_string()))
                    .collect(),
            ),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonCoverageGap {
    pub addon_id: String,
    pub reason_code: String,
    pub message: String,
}

impl NativeAddonCoverageGap {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "addon_id".to_string(),
            CanonicalValue::String(self.addon_id.clone()),
        );
        map.insert(
            "message".to_string(),
            CanonicalValue::String(self.message.clone()),
        );
        map.insert(
            "reason_code".to_string(),
            CanonicalValue::String(self.reason_code.clone()),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonInventoryReport {
    pub schema_version: String,
    pub support_surface: Vec<NativeAddonSupportSurface>,
    pub compatibility_matrix: Vec<NativeAddonCompatibilityMatrixEntry>,
    pub abi_fingerprint_index: Vec<NativeAddonAbiFingerprintEntry>,
    pub cohort_counts: BTreeMap<String, u32>,
    pub required_addon_ids: Vec<String>,
    pub coverage_gaps: Vec<NativeAddonCoverageGap>,
    pub coverage_complete: bool,
    pub report_hash: ContentHash,
}

impl NativeAddonInventoryReport {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "abi_fingerprint_index".to_string(),
            CanonicalValue::Array(
                self.abi_fingerprint_index
                    .iter()
                    .map(NativeAddonAbiFingerprintEntry::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "cohort_counts".to_string(),
            CanonicalValue::Map(
                self.cohort_counts
                    .iter()
                    .map(|(key, value)| (key.clone(), CanonicalValue::U64(u64::from(*value))))
                    .collect(),
            ),
        );
        map.insert(
            "coverage_complete".to_string(),
            CanonicalValue::Bool(self.coverage_complete),
        );
        map.insert(
            "coverage_gaps".to_string(),
            CanonicalValue::Array(
                self.coverage_gaps
                    .iter()
                    .map(NativeAddonCoverageGap::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "compatibility_matrix".to_string(),
            CanonicalValue::Array(
                self.compatibility_matrix
                    .iter()
                    .map(NativeAddonCompatibilityMatrixEntry::canonical_value)
                    .collect(),
            ),
        );
        map.insert(
            "required_addon_ids".to_string(),
            CanonicalValue::Array(
                self.required_addon_ids
                    .iter()
                    .map(|addon_id| CanonicalValue::String(addon_id.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "support_surface".to_string(),
            CanonicalValue::Array(
                self.support_surface
                    .iter()
                    .map(NativeAddonSupportSurface::canonical_value)
                    .collect(),
            ),
        );
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonMembraneReport {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_unix_ms: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub addon_count: usize,
    pub direct_count: usize,
    pub fallback_only_count: usize,
    pub unsupported_count: usize,
    pub inventory_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonHandleSafetyEntry {
    pub addon_id: String,
    pub package_name: String,
    pub handle_discipline: NativeAddonHandleDiscipline,
    pub required_slot_capabilities: Vec<SlotCapability>,
    pub direct_safe: bool,
    pub direct_blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonExecutionDispositionEntry {
    pub addon_id: String,
    pub package_name: String,
    pub support_status: NativeAddonSupportStatus,
    pub selected_route: Option<NativeAddonRoute>,
    pub invocation_channel: Option<NativeAddonInvocationChannel>,
    pub crash_containment: Option<NativeAddonCrashContainment>,
    pub error_code: String,
    pub missing_capabilities: BTreeSet<RuntimeCapability>,
    pub direct_blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonFallbackReceipt {
    pub addon_id: String,
    pub package_name: String,
    pub route: NativeAddonRoute,
    pub crash_containment: NativeAddonCrashContainment,
    pub delegate_type: Option<DelegateType>,
    pub capability_envelope: Option<AuthorityEnvelope>,
    pub sandbox: Option<SandboxConfiguration>,
    pub direct_blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonTraceIdsArtifact {
    pub schema_version: String,
    pub trace_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonRunManifest {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub run_id: String,
    pub generated_at_unix_ms: u64,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub addon_count: usize,
    pub inventory_hash: ContentHash,
    pub artifacts: Vec<String>,
    pub operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonArtifactWriteRequest {
    pub run_id: String,
    pub command_transcript: Vec<String>,
    pub generated_at_unix_ms: u64,
    pub required_addon_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAddonArtifactBundle {
    pub run_dir: PathBuf,
    pub step_logs_dir: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub inventory_path: PathBuf,
    pub support_surface_path: PathBuf,
    pub compatibility_matrix_path: PathBuf,
    pub abi_fingerprint_index_path: PathBuf,
    pub membrane_report_path: PathBuf,
    pub handle_safety_report_path: PathBuf,
    pub execution_disposition_path: PathBuf,
    pub fallback_receipts_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeAddonArtifactWriteErrorCode {
    InvalidRunId,
    Io,
    Serialization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonArtifactWriteError {
    pub code: NativeAddonArtifactWriteErrorCode,
    pub path: String,
    pub message: String,
}

impl fmt::Display for NativeAddonArtifactWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {} ({})", self.code, self.message, self.path)
    }
}

impl std::error::Error for NativeAddonArtifactWriteError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonMembraneError {
    pub code: NativeAddonMembraneErrorCode,
    pub message: String,
    pub event: NativeAddonDecisionEvent,
}

impl fmt::Display for NativeAddonMembraneError {
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

impl std::error::Error for NativeAddonMembraneError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeAddonMembrane {
    pub max_direct_node_api_version: u32,
    pub delegate_cell_type: DelegateType,
    pub base_delegate_sandbox: SandboxConfiguration,
}

impl Default for NativeAddonMembrane {
    fn default() -> Self {
        Self::standard()
    }
}

impl NativeAddonMembrane {
    pub fn standard() -> Self {
        Self {
            max_direct_node_api_version: 10,
            delegate_cell_type: DelegateType::ExternalProcess,
            base_delegate_sandbox: SandboxConfiguration::default(),
        }
    }

    pub fn assess_support_surface(
        &self,
        request: &NativeAddonLoadRequest,
        profile: &CapabilityProfile,
    ) -> NativeAddonSupportSurface {
        let required_capabilities = request.required_capabilities();
        let missing_capabilities: BTreeSet<_> = required_capabilities
            .iter()
            .filter(|cap| !profile.has(**cap))
            .copied()
            .collect();
        let mut direct_blockers = self.direct_blockers(request);
        direct_blockers.sort();
        direct_blockers.dedup();
        let symbol_families = request.symbol_families();

        let selected_route = if !missing_capabilities.is_empty() {
            None
        } else if direct_blockers.is_empty() {
            Some(NativeAddonRoute::DirectMembrane)
        } else if request.wasm_portable
            && request
                .supported_fallbacks
                .contains(&NativeAddonFallbackMode::WasmPort)
        {
            Some(NativeAddonRoute::WasmPort)
        } else if request
            .supported_fallbacks
            .contains(&NativeAddonFallbackMode::DelegateCell)
        {
            Some(NativeAddonRoute::DelegateCell)
        } else {
            None
        };

        let support_status = match selected_route {
            Some(NativeAddonRoute::DirectMembrane) => NativeAddonSupportStatus::Direct,
            Some(NativeAddonRoute::WasmPort | NativeAddonRoute::DelegateCell) => {
                NativeAddonSupportStatus::FallbackOnly
            }
            None => NativeAddonSupportStatus::Unsupported,
        };
        let risk_classification = classify_risk(
            request,
            support_status,
            selected_route,
            &missing_capabilities,
        );
        let owner_route = owner_route(
            request,
            support_status,
            selected_route,
            &missing_capabilities,
        );
        let remediation_hint = remediation_hint(
            request,
            selected_route,
            &missing_capabilities,
            &direct_blockers,
        );

        NativeAddonSupportSurface {
            addon_id: request.addon_id.trim().to_string(),
            package_name: request.package_name.trim().to_string(),
            package_version: request.package_version.trim().to_string(),
            module_specifier: request.module_specifier.trim().to_string(),
            addon_path: request.addon_path.trim().to_string(),
            cohort: request.cohort(),
            abi_surface: request.abi_surface,
            support_status,
            selected_route,
            missing_capabilities,
            direct_blockers,
            supported_fallbacks: request.supported_fallbacks.iter().copied().collect(),
            required_capabilities,
            required_slot_capabilities: request.required_slot_capabilities(),
            symbol_families,
            risk_classification,
            owner_route,
            remediation_hint,
            abi_fingerprint: request.abi_fingerprint(),
        }
    }

    pub fn plan(
        &self,
        request: &NativeAddonLoadRequest,
        context: &ResolutionContext,
        profile: &CapabilityProfile,
    ) -> NativeAddonMembraneResult<NativeAddonExecutionPlan> {
        let support_surface = self.assess_support_surface(request, profile);
        let route = match support_surface.selected_route {
            Some(route) => route,
            None => {
                return Err(Box::new(self.build_error(
                    context,
                    &support_surface,
                    self.classify_failure(&support_surface),
                )));
            }
        };

        let (invocation_channel, crash_containment, delegate_type, capability_envelope, sandbox) =
            match route {
                NativeAddonRoute::DirectMembrane => (
                    NativeAddonInvocationChannel::InProcessMembrane,
                    NativeAddonCrashContainment::InProcessMembrane,
                    None,
                    None,
                    None,
                ),
                NativeAddonRoute::WasmPort => (
                    NativeAddonInvocationChannel::HostcallSession,
                    NativeAddonCrashContainment::WasmSandbox,
                    Some(DelegateType::WasmBacked),
                    Some(self.delegate_authority_envelope(request)),
                    Some(self.delegate_sandbox(request)),
                ),
                NativeAddonRoute::DelegateCell => (
                    NativeAddonInvocationChannel::HostcallSession,
                    NativeAddonCrashContainment::DelegateCellBoundary,
                    Some(self.delegate_cell_type),
                    Some(self.delegate_authority_envelope(request)),
                    Some(self.delegate_sandbox(request)),
                ),
            };

        let outcome = if route == NativeAddonRoute::DirectMembrane {
            "allow"
        } else {
            "fallback"
        };
        let event = self.build_event(&support_surface, context, outcome, "none", Some(route));

        Ok(NativeAddonExecutionPlan {
            route,
            invocation_channel,
            crash_containment,
            delegate_type,
            capability_envelope,
            sandbox,
            required_capabilities: support_surface.required_capabilities.clone(),
            support_surface,
            event,
        })
    }

    pub fn inventory_report(
        &self,
        requests: &[NativeAddonLoadRequest],
        profile: &CapabilityProfile,
    ) -> NativeAddonInventoryReport {
        self.inventory_report_with_requirements(requests, profile, &[])
    }

    pub fn inventory_report_with_requirements(
        &self,
        requests: &[NativeAddonLoadRequest],
        profile: &CapabilityProfile,
        required_addon_ids: &[String],
    ) -> NativeAddonInventoryReport {
        let mut support_surface = Vec::with_capacity(requests.len());
        let mut compatibility_matrix = Vec::with_capacity(requests.len());
        let mut abi_fingerprint_index = Vec::with_capacity(requests.len());
        let mut cohort_counts = BTreeMap::new();

        for request in requests {
            let surface = self.assess_support_surface(request, profile);
            *cohort_counts
                .entry(surface.cohort.as_str().to_string())
                .or_insert(0) += 1;
            compatibility_matrix.push(NativeAddonCompatibilityMatrixEntry {
                addon_id: surface.addon_id.clone(),
                package_name: surface.package_name.clone(),
                package_version: surface.package_version.clone(),
                cohort: surface.cohort,
                abi_surface: surface.abi_surface,
                support_status: surface.support_status,
                selected_route: surface.selected_route,
                abi_fingerprint: surface.abi_fingerprint.clone(),
                notes: compatibility_notes(&surface),
            });
            abi_fingerprint_index.push(NativeAddonAbiFingerprintEntry {
                addon_id: surface.addon_id.clone(),
                package_name: surface.package_name.clone(),
                cohort: surface.cohort,
                abi_surface: surface.abi_surface,
                supported_fallbacks: surface.supported_fallbacks.clone(),
                symbol_families: surface.symbol_families.clone(),
                fingerprint: surface.abi_fingerprint.clone(),
            });
            support_surface.push(surface);
        }

        support_surface.sort_by(|lhs, rhs| {
            (
                lhs.addon_id.as_str(),
                lhs.package_name.as_str(),
                lhs.module_specifier.as_str(),
                lhs.abi_fingerprint.to_hex(),
            )
                .cmp(&(
                    rhs.addon_id.as_str(),
                    rhs.package_name.as_str(),
                    rhs.module_specifier.as_str(),
                    rhs.abi_fingerprint.to_hex(),
                ))
        });
        compatibility_matrix.sort_by(|lhs, rhs| {
            (
                lhs.addon_id.as_str(),
                lhs.package_name.as_str(),
                lhs.abi_fingerprint.to_hex(),
            )
                .cmp(&(
                    rhs.addon_id.as_str(),
                    rhs.package_name.as_str(),
                    rhs.abi_fingerprint.to_hex(),
                ))
        });
        abi_fingerprint_index.sort_by(|lhs, rhs| {
            (
                lhs.addon_id.as_str(),
                lhs.package_name.as_str(),
                lhs.fingerprint.to_hex(),
            )
                .cmp(&(
                    rhs.addon_id.as_str(),
                    rhs.package_name.as_str(),
                    rhs.fingerprint.to_hex(),
                ))
        });

        let required_addon_ids = normalize_required_addon_ids(required_addon_ids);
        let observed_addon_ids = support_surface
            .iter()
            .map(|surface| surface.addon_id.as_str())
            .collect::<BTreeSet<_>>();
        let coverage_gaps = required_addon_ids
            .iter()
            .filter(|addon_id| !observed_addon_ids.contains(addon_id.as_str()))
            .map(|addon_id| NativeAddonCoverageGap {
                addon_id: addon_id.clone(),
                reason_code: "missing_from_inventory_input".to_string(),
                message: format!(
                    "required addon '{}' is missing from the inventory input",
                    addon_id
                ),
            })
            .collect::<Vec<_>>();
        let coverage_complete = coverage_gaps.is_empty();

        let mut report = NativeAddonInventoryReport {
            schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
            support_surface,
            compatibility_matrix,
            abi_fingerprint_index,
            cohort_counts,
            required_addon_ids,
            coverage_gaps,
            coverage_complete,
            report_hash: ContentHash::compute(b"pending-native-addon-report"),
        };
        report.report_hash = report.canonical_hash();
        report
    }

    pub fn write_artifact_bundle(
        &self,
        artifact_root: impl AsRef<Path>,
        context: &ResolutionContext,
        requests: &[NativeAddonLoadRequest],
        profile: &CapabilityProfile,
        artifact_request: &NativeAddonArtifactWriteRequest,
    ) -> Result<NativeAddonArtifactBundle, NativeAddonArtifactWriteError> {
        let run_id = normalize_run_id(artifact_request.run_id.clone())?;
        let run_dir = artifact_root.as_ref().join(&run_id);
        fs::create_dir_all(&run_dir).map_err(|err| NativeAddonArtifactWriteError {
            code: NativeAddonArtifactWriteErrorCode::Io,
            path: run_dir.display().to_string(),
            message: err.to_string(),
        })?;
        let step_logs_dir = run_dir.join("step_logs");
        fs::create_dir_all(&step_logs_dir).map_err(|err| NativeAddonArtifactWriteError {
            code: NativeAddonArtifactWriteErrorCode::Io,
            path: step_logs_dir.display().to_string(),
            message: err.to_string(),
        })?;

        let inventory = self.inventory_report_with_requirements(
            requests,
            profile,
            &artifact_request.required_addon_ids,
        );
        let mut events = Vec::with_capacity(requests.len());
        let mut handle_safety = Vec::with_capacity(requests.len());
        let mut execution_disposition = Vec::with_capacity(requests.len());
        let mut fallback_receipts = Vec::new();

        for request in requests {
            let support_surface = self.assess_support_surface(request, profile);
            handle_safety.push(NativeAddonHandleSafetyEntry {
                addon_id: support_surface.addon_id.clone(),
                package_name: support_surface.package_name.clone(),
                handle_discipline: request.handle_discipline,
                required_slot_capabilities: support_surface.required_slot_capabilities.clone(),
                direct_safe: support_surface.direct_blockers.is_empty()
                    && support_surface.missing_capabilities.is_empty(),
                direct_blockers: support_surface.direct_blockers.clone(),
            });

            match self.plan(request, context, profile) {
                Ok(plan) => {
                    events.push(plan.event.clone());
                    execution_disposition.push(NativeAddonExecutionDispositionEntry {
                        addon_id: plan.support_surface.addon_id.clone(),
                        package_name: plan.support_surface.package_name.clone(),
                        support_status: plan.support_surface.support_status,
                        selected_route: Some(plan.route),
                        invocation_channel: Some(plan.invocation_channel),
                        crash_containment: Some(plan.crash_containment),
                        error_code: plan.event.error_code.clone(),
                        missing_capabilities: plan.support_surface.missing_capabilities.clone(),
                        direct_blockers: plan.support_surface.direct_blockers.clone(),
                    });
                    if plan.route != NativeAddonRoute::DirectMembrane {
                        fallback_receipts.push(NativeAddonFallbackReceipt {
                            addon_id: plan.support_surface.addon_id.clone(),
                            package_name: plan.support_surface.package_name.clone(),
                            route: plan.route,
                            crash_containment: plan.crash_containment,
                            delegate_type: plan.delegate_type,
                            capability_envelope: plan.capability_envelope.clone(),
                            sandbox: plan.sandbox.clone(),
                            direct_blockers: plan.support_surface.direct_blockers.clone(),
                        });
                    }
                }
                Err(err) => {
                    let err = *err;
                    events.push(err.event.clone());
                    execution_disposition.push(NativeAddonExecutionDispositionEntry {
                        addon_id: err.event.addon_id.clone(),
                        package_name: err.event.package_name.clone(),
                        support_status: err.event.support_status,
                        selected_route: err.event.selected_route,
                        invocation_channel: None,
                        crash_containment: None,
                        error_code: err.event.error_code.clone(),
                        missing_capabilities: err.event.missing_capabilities.clone(),
                        direct_blockers: err.event.direct_blockers.clone(),
                    });
                }
            }
        }

        handle_safety.sort_by(|lhs, rhs| {
            (lhs.addon_id.as_str(), lhs.package_name.as_str())
                .cmp(&(rhs.addon_id.as_str(), rhs.package_name.as_str()))
        });
        execution_disposition.sort_by(|lhs, rhs| {
            (lhs.addon_id.as_str(), lhs.package_name.as_str())
                .cmp(&(rhs.addon_id.as_str(), rhs.package_name.as_str()))
        });
        fallback_receipts.sort_by(|lhs, rhs| {
            (lhs.addon_id.as_str(), lhs.package_name.as_str())
                .cmp(&(rhs.addon_id.as_str(), rhs.package_name.as_str()))
        });
        events.sort_by(|lhs, rhs| {
            (
                lhs.addon_id.as_str(),
                lhs.package_name.as_str(),
                lhs.decision_stable_id.as_str(),
            )
                .cmp(&(
                    rhs.addon_id.as_str(),
                    rhs.package_name.as_str(),
                    rhs.decision_stable_id.as_str(),
                ))
        });

        let membrane_report = NativeAddonMembraneReport {
            schema_version: MEMBRANE_REPORT_SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            component: COMPONENT.to_string(),
            generated_at_unix_ms: artifact_request.generated_at_unix_ms,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            addon_count: inventory.support_surface.len(),
            direct_count: inventory
                .support_surface
                .iter()
                .filter(|surface| surface.support_status == NativeAddonSupportStatus::Direct)
                .count(),
            fallback_only_count: inventory
                .support_surface
                .iter()
                .filter(|surface| surface.support_status == NativeAddonSupportStatus::FallbackOnly)
                .count(),
            unsupported_count: inventory
                .support_surface
                .iter()
                .filter(|surface| surface.support_status == NativeAddonSupportStatus::Unsupported)
                .count(),
            inventory_hash: inventory.report_hash.clone(),
        };
        let trace_ids = NativeAddonTraceIdsArtifact {
            schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
            trace_ids: vec![context.trace_id.clone()],
        };

        let run_manifest_path = run_dir.join("run_manifest.json");
        let events_path = run_dir.join("events.jsonl");
        let commands_path = run_dir.join("commands.txt");
        let trace_ids_path = run_dir.join("trace_ids.json");
        let inventory_path = run_dir.join("native_addon_inventory.json");
        let support_surface_path = run_dir.join("native_addon_support_surface.json");
        let compatibility_matrix_path = run_dir.join("addon_compatibility_matrix.json");
        let abi_fingerprint_index_path = run_dir.join("addon_abi_fingerprint_index.json");
        let membrane_report_path = run_dir.join("native_addon_membrane_report.json");
        let handle_safety_report_path = run_dir.join("addon_handle_safety_report.json");
        let execution_disposition_path = run_dir.join("addon_execution_disposition.json");
        let fallback_receipts_path = run_dir.join("addon_fallback_receipts.json");
        let artifact_names = artifact_names();
        let run_dir_display = run_dir.display().to_string();
        let mut commands = artifact_request.command_transcript.clone();
        commands.extend([
            format!("cat {}/run_manifest.json", run_dir_display),
            format!(
                "jq '.' {}/native_addon_membrane_report.json",
                run_dir_display
            ),
            format!(
                "jq '.support_surface[]' {}/native_addon_inventory.json",
                run_dir_display
            ),
            format!("ls -1 {}/step_logs", run_dir_display),
            format!("cat {}/commands.txt", run_dir_display),
        ]);
        let run_manifest = NativeAddonRunManifest {
            schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            component: COMPONENT.to_string(),
            run_id,
            generated_at_unix_ms: artifact_request.generated_at_unix_ms,
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            addon_count: inventory.support_surface.len(),
            inventory_hash: inventory.report_hash.clone(),
            artifacts: artifact_names,
            operator_verification: commands.clone(),
        };

        write_json_artifact(&inventory_path, &inventory)?;
        write_json_artifact(&support_surface_path, &inventory.support_surface)?;
        write_json_artifact(&compatibility_matrix_path, &inventory.compatibility_matrix)?;
        write_json_artifact(
            &abi_fingerprint_index_path,
            &inventory.abi_fingerprint_index,
        )?;
        write_json_artifact(&membrane_report_path, &membrane_report)?;
        write_json_artifact(&handle_safety_report_path, &handle_safety)?;
        write_json_artifact(&execution_disposition_path, &execution_disposition)?;
        write_json_artifact(&fallback_receipts_path, &fallback_receipts)?;
        write_json_artifact(&trace_ids_path, &trace_ids)?;
        write_json_artifact(&run_manifest_path, &run_manifest)?;
        write_jsonl_artifact(&events_path, &events)?;
        write_text_artifact(&commands_path, &commands.join("\n"))?;

        Ok(NativeAddonArtifactBundle {
            run_dir,
            step_logs_dir,
            run_manifest_path,
            events_path,
            commands_path,
            trace_ids_path,
            inventory_path,
            support_surface_path,
            compatibility_matrix_path,
            abi_fingerprint_index_path,
            membrane_report_path,
            handle_safety_report_path,
            execution_disposition_path,
            fallback_receipts_path,
        })
    }

    fn direct_blockers(&self, request: &NativeAddonLoadRequest) -> Vec<String> {
        let mut blockers = Vec::new();
        if request.abi_surface != NativeAddonAbiSurface::NodeApi {
            blockers.push(format!(
                "direct membrane requires node_api surface, found {}",
                request.abi_surface.as_str()
            ));
        }
        if request
            .node_api_version
            .is_some_and(|version| version > self.max_direct_node_api_version)
        {
            blockers.push(format!(
                "node_api version {} exceeds direct membrane ceiling {}",
                request.node_api_version.unwrap_or_default(),
                self.max_direct_node_api_version
            ));
        }
        if !request.handle_discipline.is_direct_safe() {
            blockers.push(format!(
                "handle discipline '{}' is not direct-safe",
                request.handle_discipline.as_str()
            ));
        }
        if request.uses_foreign_heap {
            blockers.push("foreign heap access requires fallback containment".to_string());
        }
        if request.uses_process_global_state {
            blockers.push("process-global state requires fallback containment".to_string());
        }
        for symbol in request.normalized_symbols() {
            if !symbol.class.is_direct_safe() {
                blockers.push(format!(
                    "symbol '{}' uses non-direct-safe class '{}'",
                    symbol.symbol_name,
                    symbol.class.as_str()
                ));
            }
        }
        blockers
    }

    fn classify_failure(
        &self,
        support_surface: &NativeAddonSupportSurface,
    ) -> NativeAddonMembraneErrorCode {
        if !support_surface.missing_capabilities.is_empty() {
            NativeAddonMembraneErrorCode::MissingCapability
        } else if support_surface.abi_surface != NativeAddonAbiSurface::NodeApi
            && support_surface.selected_route.is_none()
        {
            NativeAddonMembraneErrorCode::UnsupportedAbiSurface
        } else if !support_surface.direct_blockers.is_empty()
            && support_surface.supported_fallbacks.is_empty()
        {
            NativeAddonMembraneErrorCode::UnsafeDirectSurface
        } else {
            NativeAddonMembraneErrorCode::NoFallbackRoute
        }
    }

    fn build_error(
        &self,
        context: &ResolutionContext,
        support_surface: &NativeAddonSupportSurface,
        code: NativeAddonMembraneErrorCode,
    ) -> NativeAddonMembraneError {
        let event = self.build_event(support_surface, context, "deny", code.stable_code(), None);
        let message = match code {
            NativeAddonMembraneErrorCode::MissingCapability => format!(
                "native addon '{}' is missing required capabilities [{}]",
                support_surface.addon_id,
                support_surface
                    .missing_capabilities
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            NativeAddonMembraneErrorCode::UnsupportedAbiSurface => format!(
                "native addon '{}' uses unsupported abi surface '{}'",
                support_surface.addon_id,
                support_surface.abi_surface.as_str()
            ),
            NativeAddonMembraneErrorCode::UnsafeDirectSurface => format!(
                "native addon '{}' is unsafe for direct routing and exposes no approved fallback",
                support_surface.addon_id
            ),
            NativeAddonMembraneErrorCode::NoFallbackRoute => format!(
                "native addon '{}' cannot be routed because no viable fallback remained after direct blockers [{}]",
                support_surface.addon_id,
                support_surface.direct_blockers.join("; ")
            ),
        };
        NativeAddonMembraneError {
            code,
            message,
            event,
        }
    }

    fn build_event(
        &self,
        support_surface: &NativeAddonSupportSurface,
        context: &ResolutionContext,
        outcome: &str,
        error_code: &str,
        selected_route: Option<NativeAddonRoute>,
    ) -> NativeAddonDecisionEvent {
        NativeAddonDecisionEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: EVENT.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.to_string(),
            decision_stable_id: native_addon_decision_stable_id(
                context,
                &support_surface.addon_id,
                &support_surface.abi_fingerprint,
                support_surface.support_status,
                selected_route,
                error_code,
            ),
            addon_id: support_surface.addon_id.clone(),
            module_specifier: support_surface.module_specifier.clone(),
            package_name: support_surface.package_name.clone(),
            cohort: support_surface.cohort,
            abi_surface: support_surface.abi_surface,
            support_status: support_surface.support_status,
            selected_route,
            missing_capabilities: support_surface.missing_capabilities.clone(),
            direct_blockers: support_surface.direct_blockers.clone(),
            abi_fingerprint: support_surface.abi_fingerprint.clone(),
        }
    }

    fn delegate_authority_envelope(&self, request: &NativeAddonLoadRequest) -> AuthorityEnvelope {
        let required = request.required_slot_capabilities();
        AuthorityEnvelope {
            required: required.clone(),
            permitted: required,
        }
    }

    fn delegate_sandbox(&self, request: &NativeAddonLoadRequest) -> SandboxConfiguration {
        let mut sandbox = self.base_delegate_sandbox.clone();
        if request.uses_foreign_heap
            || matches!(
                request.handle_discipline,
                NativeAddonHandleDiscipline::ExternalBuffer
                    | NativeAddonHandleDiscipline::RawPointerEscape
            )
        {
            sandbox.max_heap_bytes = sandbox.max_heap_bytes.max(128 * 1024 * 1024);
        }
        if request.uses_async_workers {
            sandbox.max_execution_ns = sandbox.max_execution_ns.max(10_000_000_000);
            sandbox.max_hostcalls = sandbox.max_hostcalls.max(20_000);
        }
        if request.requires_network_egress {
            sandbox.network_egress_allowed = true;
        }
        if request.requires_filesystem_read || request.requires_filesystem_write {
            sandbox.filesystem_access_allowed = true;
        }
        sandbox
    }
}

fn compatibility_notes(surface: &NativeAddonSupportSurface) -> String {
    let metadata_prefix = format!(
        "risk={} owner_route={} remediation={}",
        surface.risk_classification.as_str(),
        surface.owner_route,
        surface.remediation_hint
    );
    if !surface.missing_capabilities.is_empty() {
        return format!(
            "{metadata_prefix}; missing capabilities: {}",
            surface
                .missing_capabilities
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !surface.direct_blockers.is_empty() {
        let fallback = surface
            .selected_route
            .map(|route| route.as_str().to_string())
            .unwrap_or_else(|| "none".to_string());
        return format!(
            "{metadata_prefix}; direct blockers: {}; selected fallback: {}",
            surface.direct_blockers.join("; "),
            fallback
        );
    }
    format!("{metadata_prefix}; direct membrane eligible")
}

fn normalize_required_addon_ids(required_addon_ids: &[String]) -> Vec<String> {
    required_addon_ids
        .iter()
        .map(|addon_id| addon_id.trim())
        .filter(|addon_id| !addon_id.is_empty())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn classify_risk(
    request: &NativeAddonLoadRequest,
    support_status: NativeAddonSupportStatus,
    selected_route: Option<NativeAddonRoute>,
    missing_capabilities: &BTreeSet<RuntimeCapability>,
) -> NativeAddonRiskClassification {
    if !missing_capabilities.is_empty() {
        return NativeAddonRiskClassification::Critical;
    }

    if matches!(
        request.abi_surface,
        NativeAddonAbiSurface::V8Direct
            | NativeAddonAbiSurface::ForeignFfi
            | NativeAddonAbiSurface::Unknown
    ) {
        return NativeAddonRiskClassification::Critical;
    }

    if matches!(selected_route, Some(NativeAddonRoute::DelegateCell))
        || request.uses_foreign_heap
        || request.uses_process_global_state
        || matches!(
            request.handle_discipline,
            NativeAddonHandleDiscipline::ExternalBuffer
                | NativeAddonHandleDiscipline::RawPointerEscape
        )
    {
        return NativeAddonRiskClassification::High;
    }

    if matches!(selected_route, Some(NativeAddonRoute::WasmPort))
        || matches!(
            request.cohort(),
            NativeAddonCohort::NodeApiIsolateBound | NativeAddonCohort::LegacyNan
        )
        || support_status == NativeAddonSupportStatus::FallbackOnly
    {
        return NativeAddonRiskClassification::Medium;
    }

    NativeAddonRiskClassification::Low
}

fn owner_route(
    request: &NativeAddonLoadRequest,
    support_status: NativeAddonSupportStatus,
    selected_route: Option<NativeAddonRoute>,
    missing_capabilities: &BTreeSet<RuntimeCapability>,
) -> String {
    if !missing_capabilities.is_empty()
        || matches!(request.cohort(), NativeAddonCohort::NodeApiPrivileged)
    {
        return "security-capability-review".to_string();
    }

    match selected_route {
        Some(NativeAddonRoute::DirectMembrane) => match request.cohort() {
            NativeAddonCohort::NodeApiPortable => "interop-native-addon".to_string(),
            NativeAddonCohort::NodeApiIsolateBound => "runtime-async-isolation".to_string(),
            NativeAddonCohort::NodeApiPrivileged => "security-capability-review".to_string(),
            NativeAddonCohort::LegacyNan => "interop-wasm-porting".to_string(),
            NativeAddonCohort::V8Binding => "compatibility-v8-binding".to_string(),
            NativeAddonCohort::ForeignFfi => "compatibility-ffi-review".to_string(),
            NativeAddonCohort::Unknown => "interop-native-addon".to_string(),
        },
        Some(NativeAddonRoute::WasmPort) => "interop-wasm-porting".to_string(),
        Some(NativeAddonRoute::DelegateCell) => "runtime-delegate-cell".to_string(),
        None => match (support_status, request.abi_surface) {
            (_, NativeAddonAbiSurface::V8Direct) => "compatibility-v8-binding".to_string(),
            (_, NativeAddonAbiSurface::ForeignFfi) => "compatibility-ffi-review".to_string(),
            (_, NativeAddonAbiSurface::Unknown) => "interop-native-addon".to_string(),
            (NativeAddonSupportStatus::Unsupported, _) => "interop-native-addon".to_string(),
            _ => "interop-native-addon".to_string(),
        },
    }
}

fn remediation_hint(
    request: &NativeAddonLoadRequest,
    selected_route: Option<NativeAddonRoute>,
    missing_capabilities: &BTreeSet<RuntimeCapability>,
    direct_blockers: &[String],
) -> String {
    if !missing_capabilities.is_empty() {
        return format!(
            "grant missing capabilities ({}) or keep the addon unsupported until the package matrix and policy contract are updated",
            missing_capabilities
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    match selected_route {
        Some(NativeAddonRoute::DirectMembrane) => match request.cohort() {
            NativeAddonCohort::NodeApiIsolateBound => {
                "keep the direct membrane path, but preserve async-worker isolation and threadsafe-function coverage in verification".to_string()
            }
            _ => "retain the stable Node-API surface and current handle discipline".to_string(),
        },
        Some(NativeAddonRoute::WasmPort) => {
            "prefer a maintained WASM port for this cohort and keep delegate-cell fallback for unsupported host features".to_string()
        }
        Some(NativeAddonRoute::DelegateCell) => {
            "route through the delegate cell and isolate unsafe pointer or heap behavior behind the hostcall session boundary".to_string()
        }
        None if direct_blockers.iter().any(|blocker| blocker.contains("node_api surface")) => {
            "port the addon to the stable Node-API surface or publish it as fallback-only/unsupported with explicit operator guidance".to_string()
        }
        None => {
            "publish the unsupported disposition with owner-routed remediation instead of silently omitting the addon cohort".to_string()
        }
    }
}

fn native_addon_decision_stable_id(
    context: &ResolutionContext,
    addon_id: &str,
    abi_fingerprint: &ContentHash,
    support_status: NativeAddonSupportStatus,
    selected_route: Option<NativeAddonRoute>,
    error_code: &str,
) -> String {
    let mut map = BTreeMap::new();
    map.insert(
        "abi_fingerprint".to_string(),
        CanonicalValue::String(abi_fingerprint.to_hex()),
    );
    map.insert(
        "addon_id".to_string(),
        CanonicalValue::String(addon_id.to_string()),
    );
    map.insert(
        "decision_id".to_string(),
        CanonicalValue::String(context.decision_id.clone()),
    );
    map.insert(
        "error_code".to_string(),
        CanonicalValue::String(error_code.to_string()),
    );
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(context.policy_id.clone()),
    );
    map.insert(
        "selected_route".to_string(),
        selected_route
            .map(|route| CanonicalValue::String(route.as_str().to_string()))
            .unwrap_or(CanonicalValue::Null),
    );
    map.insert(
        "support_status".to_string(),
        CanonicalValue::String(support_status.as_str().to_string()),
    );
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(context.trace_id.clone()),
    );
    let digest = ContentHash::compute(&encode_value(&CanonicalValue::Map(map))).to_hex();
    format!("native-addon-dec-{}", &digest[..16])
}

fn push_slot_capability(caps: &mut Vec<SlotCapability>, capability: SlotCapability) {
    if !caps.contains(&capability) {
        caps.push(capability);
    }
}

fn slot_capability_sort_key(capability: SlotCapability) -> u8 {
    match capability {
        SlotCapability::ReadSource => 0,
        SlotCapability::EmitIr => 1,
        SlotCapability::HeapAlloc => 2,
        SlotCapability::ScheduleAsync => 3,
        SlotCapability::InvokeHostcall => 4,
        SlotCapability::ModuleAccess => 5,
        SlotCapability::TriggerGc => 6,
        SlotCapability::EmitEvidence => 7,
    }
}

fn normalize_run_id(run_id: String) -> Result<String, NativeAddonArtifactWriteError> {
    let trimmed = run_id.trim();
    let path = Path::new(trimmed);
    if trimmed.is_empty()
        || path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err(NativeAddonArtifactWriteError {
            code: NativeAddonArtifactWriteErrorCode::InvalidRunId,
            path: trimmed.to_string(),
            message: "run_id must be a single normal path component".to_string(),
        });
    }
    Ok(trimmed.to_string())
}

fn artifact_names() -> Vec<String> {
    [
        "addon_abi_fingerprint_index.json",
        "addon_compatibility_matrix.json",
        "addon_execution_disposition.json",
        "addon_fallback_receipts.json",
        "addon_handle_safety_report.json",
        "commands.txt",
        "events.jsonl",
        "native_addon_inventory.json",
        "native_addon_membrane_report.json",
        "native_addon_support_surface.json",
        "run_manifest.json",
        "step_logs/",
        "trace_ids.json",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn write_json_artifact<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), NativeAddonArtifactWriteError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|err| NativeAddonArtifactWriteError {
        code: NativeAddonArtifactWriteErrorCode::Serialization,
        path: path.display().to_string(),
        message: err.to_string(),
    })?;
    fs::write(path, bytes).map_err(|err| NativeAddonArtifactWriteError {
        code: NativeAddonArtifactWriteErrorCode::Io,
        path: path.display().to_string(),
        message: err.to_string(),
    })
}

fn write_jsonl_artifact<T: Serialize>(
    path: &Path,
    values: &[T],
) -> Result<(), NativeAddonArtifactWriteError> {
    let mut jsonl = String::new();
    for value in values {
        let line = serde_json::to_string(value).map_err(|err| NativeAddonArtifactWriteError {
            code: NativeAddonArtifactWriteErrorCode::Serialization,
            path: path.display().to_string(),
            message: err.to_string(),
        })?;
        jsonl.push_str(&line);
        jsonl.push('\n');
    }
    fs::write(path, jsonl).map_err(|err| NativeAddonArtifactWriteError {
        code: NativeAddonArtifactWriteErrorCode::Io,
        path: path.display().to_string(),
        message: err.to_string(),
    })
}

fn write_text_artifact(path: &Path, text: &str) -> Result<(), NativeAddonArtifactWriteError> {
    fs::write(path, text).map_err(|err| NativeAddonArtifactWriteError {
        code: NativeAddonArtifactWriteErrorCode::Io,
        path: path.display().to_string(),
        message: err.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ResolutionContext {
        ResolutionContext::new("trace-test", "decision-test", "policy-test")
    }

    fn simple_request() -> NativeAddonLoadRequest {
        NativeAddonLoadRequest::new(
            "test-addon",
            "test-pkg",
            "1.0.0",
            "test-pkg",
            "./build/test.node",
            NativeAddonAbiSurface::NodeApi,
        )
    }

    fn full_profile() -> CapabilityProfile {
        CapabilityProfile::full()
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn constants_non_empty() {
        assert!(!COMPONENT.is_empty());
        assert!(!EVENT.is_empty());
        assert!(!INVENTORY_SCHEMA_VERSION.is_empty());
        assert!(!MEMBRANE_REPORT_SCHEMA_VERSION.is_empty());
        assert!(!HANDLE_SAFETY_REPORT_SCHEMA_VERSION.is_empty());
        assert!(!EXECUTION_DISPOSITION_SCHEMA_VERSION.is_empty());
        assert!(!FALLBACK_RECEIPTS_SCHEMA_VERSION.is_empty());
        assert!(!TRACE_IDS_SCHEMA_VERSION.is_empty());
        assert!(!RUN_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!BEAD_ID.is_empty());
    }

    #[test]
    fn schema_versions_prefixed() {
        assert!(INVENTORY_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(MEMBRANE_REPORT_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(HANDLE_SAFETY_REPORT_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(EXECUTION_DISPOSITION_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(FALLBACK_RECEIPTS_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(TRACE_IDS_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(RUN_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    // -----------------------------------------------------------------------
    // NativeAddonAbiSurface
    // -----------------------------------------------------------------------

    #[test]
    fn abi_surface_as_str_all_distinct() {
        let variants = [
            NativeAddonAbiSurface::NodeApi,
            NativeAddonAbiSurface::Nan,
            NativeAddonAbiSurface::V8Direct,
            NativeAddonAbiSurface::ForeignFfi,
            NativeAddonAbiSurface::Unknown,
        ];
        let strs: BTreeSet<_> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(strs.len(), variants.len());
    }

    #[test]
    fn abi_surface_display_matches_as_str() {
        for variant in [
            NativeAddonAbiSurface::NodeApi,
            NativeAddonAbiSurface::Nan,
            NativeAddonAbiSurface::V8Direct,
        ] {
            assert_eq!(variant.to_string(), variant.as_str());
        }
    }

    #[test]
    fn abi_surface_serde_roundtrip() {
        for variant in [
            NativeAddonAbiSurface::NodeApi,
            NativeAddonAbiSurface::Nan,
            NativeAddonAbiSurface::V8Direct,
            NativeAddonAbiSurface::ForeignFfi,
            NativeAddonAbiSurface::Unknown,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: NativeAddonAbiSurface = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // -----------------------------------------------------------------------
    // NativeAddonCohort
    // -----------------------------------------------------------------------

    #[test]
    fn cohort_as_str_all_distinct() {
        let variants = [
            NativeAddonCohort::NodeApiPortable,
            NativeAddonCohort::NodeApiIsolateBound,
            NativeAddonCohort::NodeApiPrivileged,
            NativeAddonCohort::LegacyNan,
            NativeAddonCohort::V8Binding,
            NativeAddonCohort::ForeignFfi,
            NativeAddonCohort::Unknown,
        ];
        let strs: BTreeSet<_> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(strs.len(), variants.len());
    }

    #[test]
    fn cohort_display_matches_as_str() {
        assert_eq!(
            NativeAddonCohort::NodeApiPortable.to_string(),
            NativeAddonCohort::NodeApiPortable.as_str()
        );
    }

    #[test]
    fn cohort_serde_roundtrip() {
        for variant in [
            NativeAddonCohort::NodeApiPortable,
            NativeAddonCohort::LegacyNan,
            NativeAddonCohort::V8Binding,
            NativeAddonCohort::ForeignFfi,
            NativeAddonCohort::Unknown,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: NativeAddonCohort = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // -----------------------------------------------------------------------
    // NativeAddonFallbackMode
    // -----------------------------------------------------------------------

    #[test]
    fn fallback_mode_as_str_distinct() {
        assert_ne!(
            NativeAddonFallbackMode::WasmPort.as_str(),
            NativeAddonFallbackMode::DelegateCell.as_str()
        );
    }

    #[test]
    fn fallback_mode_display_matches_as_str() {
        assert_eq!(NativeAddonFallbackMode::WasmPort.to_string(), "wasm_port");
        assert_eq!(
            NativeAddonFallbackMode::DelegateCell.to_string(),
            "delegate_cell"
        );
    }

    #[test]
    fn fallback_mode_serde_roundtrip() {
        for variant in [
            NativeAddonFallbackMode::WasmPort,
            NativeAddonFallbackMode::DelegateCell,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: NativeAddonFallbackMode = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // -----------------------------------------------------------------------
    // NativeAddonRoute
    // -----------------------------------------------------------------------

    #[test]
    fn route_as_str_all_distinct() {
        let variants = [
            NativeAddonRoute::DirectMembrane,
            NativeAddonRoute::WasmPort,
            NativeAddonRoute::DelegateCell,
        ];
        let strs: BTreeSet<_> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(strs.len(), variants.len());
    }

    #[test]
    fn route_serde_roundtrip() {
        for variant in [
            NativeAddonRoute::DirectMembrane,
            NativeAddonRoute::WasmPort,
            NativeAddonRoute::DelegateCell,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: NativeAddonRoute = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // -----------------------------------------------------------------------
    // NativeAddonSupportStatus
    // -----------------------------------------------------------------------

    #[test]
    fn support_status_as_str_all_distinct() {
        let variants = [
            NativeAddonSupportStatus::Direct,
            NativeAddonSupportStatus::FallbackOnly,
            NativeAddonSupportStatus::Unsupported,
        ];
        let strs: BTreeSet<_> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(strs.len(), variants.len());
    }

    #[test]
    fn support_status_serde_roundtrip() {
        for variant in [
            NativeAddonSupportStatus::Direct,
            NativeAddonSupportStatus::FallbackOnly,
            NativeAddonSupportStatus::Unsupported,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: NativeAddonSupportStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // -----------------------------------------------------------------------
    // NativeAddonHandleDiscipline
    // -----------------------------------------------------------------------

    #[test]
    fn handle_discipline_as_str_all_distinct() {
        let variants = [
            NativeAddonHandleDiscipline::NodeApiOnly,
            NativeAddonHandleDiscipline::ThreadSafeFunctionOnly,
            NativeAddonHandleDiscipline::FinalizerBounded,
            NativeAddonHandleDiscipline::ExternalBuffer,
            NativeAddonHandleDiscipline::RawPointerEscape,
        ];
        let strs: BTreeSet<_> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(strs.len(), variants.len());
    }

    #[test]
    fn handle_discipline_is_direct_safe() {
        assert!(NativeAddonHandleDiscipline::NodeApiOnly.is_direct_safe());
        assert!(NativeAddonHandleDiscipline::ThreadSafeFunctionOnly.is_direct_safe());
        assert!(NativeAddonHandleDiscipline::FinalizerBounded.is_direct_safe());
        assert!(!NativeAddonHandleDiscipline::ExternalBuffer.is_direct_safe());
        assert!(!NativeAddonHandleDiscipline::RawPointerEscape.is_direct_safe());
    }

    #[test]
    fn handle_discipline_serde_roundtrip() {
        for variant in [
            NativeAddonHandleDiscipline::NodeApiOnly,
            NativeAddonHandleDiscipline::ExternalBuffer,
            NativeAddonHandleDiscipline::RawPointerEscape,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: NativeAddonHandleDiscipline = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // -----------------------------------------------------------------------
    // NativeAddonSymbolClass
    // -----------------------------------------------------------------------

    #[test]
    fn symbol_class_as_str_all_distinct() {
        let variants = [
            NativeAddonSymbolClass::ValueExport,
            NativeAddonSymbolClass::FunctionExport,
            NativeAddonSymbolClass::ThreadSafeFunction,
            NativeAddonSymbolClass::Finalizer,
            NativeAddonSymbolClass::PropertyAccessor,
            NativeAddonSymbolClass::ExternalBuffer,
            NativeAddonSymbolClass::ForeignCallback,
            NativeAddonSymbolClass::GlobalStateHook,
            NativeAddonSymbolClass::Unknown,
        ];
        let strs: BTreeSet<_> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(strs.len(), variants.len());
    }

    #[test]
    fn symbol_class_is_direct_safe() {
        assert!(NativeAddonSymbolClass::ValueExport.is_direct_safe());
        assert!(NativeAddonSymbolClass::FunctionExport.is_direct_safe());
        assert!(NativeAddonSymbolClass::ThreadSafeFunction.is_direct_safe());
        assert!(NativeAddonSymbolClass::Finalizer.is_direct_safe());
        assert!(NativeAddonSymbolClass::PropertyAccessor.is_direct_safe());
        assert!(!NativeAddonSymbolClass::ExternalBuffer.is_direct_safe());
        assert!(!NativeAddonSymbolClass::ForeignCallback.is_direct_safe());
        assert!(!NativeAddonSymbolClass::GlobalStateHook.is_direct_safe());
        assert!(!NativeAddonSymbolClass::Unknown.is_direct_safe());
    }

    // -----------------------------------------------------------------------
    // NativeAddonInvocationChannel
    // -----------------------------------------------------------------------

    #[test]
    fn invocation_channel_as_str_distinct() {
        assert_ne!(
            NativeAddonInvocationChannel::InProcessMembrane.as_str(),
            NativeAddonInvocationChannel::HostcallSession.as_str()
        );
    }

    #[test]
    fn invocation_channel_display_matches_as_str() {
        assert_eq!(
            NativeAddonInvocationChannel::InProcessMembrane.to_string(),
            "in_process_membrane"
        );
    }

    // -----------------------------------------------------------------------
    // NativeAddonCrashContainment
    // -----------------------------------------------------------------------

    #[test]
    fn crash_containment_as_str_all_distinct() {
        let variants = [
            NativeAddonCrashContainment::InProcessMembrane,
            NativeAddonCrashContainment::WasmSandbox,
            NativeAddonCrashContainment::DelegateCellBoundary,
        ];
        let strs: BTreeSet<_> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(strs.len(), variants.len());
    }

    // -----------------------------------------------------------------------
    // NativeAddonMembraneErrorCode
    // -----------------------------------------------------------------------

    #[test]
    fn error_code_stable_codes_all_distinct() {
        let codes = [
            NativeAddonMembraneErrorCode::MissingCapability,
            NativeAddonMembraneErrorCode::UnsupportedAbiSurface,
            NativeAddonMembraneErrorCode::UnsafeDirectSurface,
            NativeAddonMembraneErrorCode::NoFallbackRoute,
        ];
        let strs: BTreeSet<_> = codes.iter().map(|c| c.stable_code()).collect();
        assert_eq!(strs.len(), codes.len());
    }

    #[test]
    fn error_code_stable_codes_prefixed() {
        for code in [
            NativeAddonMembraneErrorCode::MissingCapability,
            NativeAddonMembraneErrorCode::UnsupportedAbiSurface,
            NativeAddonMembraneErrorCode::UnsafeDirectSurface,
            NativeAddonMembraneErrorCode::NoFallbackRoute,
        ] {
            assert!(code.stable_code().starts_with("FE-NAM-"));
        }
    }

    // -----------------------------------------------------------------------
    // NativeAddonSymbol
    // -----------------------------------------------------------------------

    #[test]
    fn symbol_new_defaults() {
        let sym = NativeAddonSymbol::new("test_fn", NativeAddonSymbolClass::FunctionExport);
        assert_eq!(sym.symbol_name, "test_fn");
        assert_eq!(sym.class, NativeAddonSymbolClass::FunctionExport);
        assert!(sym.required_capabilities.is_empty());
    }

    #[test]
    fn symbol_require_capability_adds() {
        let sym = NativeAddonSymbol::new("test_fn", NativeAddonSymbolClass::FunctionExport)
            .require_capability(RuntimeCapability::HeapAllocate);
        assert!(
            sym.required_capabilities
                .contains(&RuntimeCapability::HeapAllocate)
        );
    }

    #[test]
    fn symbol_normalized_trims_name() {
        let sym = NativeAddonSymbol::new("  spaced  ", NativeAddonSymbolClass::ValueExport);
        let normalized = sym.normalized();
        assert_eq!(normalized.symbol_name, "spaced");
    }

    #[test]
    fn symbol_serde_roundtrip() {
        let sym = NativeAddonSymbol::new("fn1", NativeAddonSymbolClass::Finalizer)
            .require_capability(RuntimeCapability::GcInvoke);
        let json = serde_json::to_string(&sym).unwrap();
        let back: NativeAddonSymbol = serde_json::from_str(&json).unwrap();
        assert_eq!(sym, back);
    }

    // -----------------------------------------------------------------------
    // NativeAddonLoadRequest
    // -----------------------------------------------------------------------

    #[test]
    fn load_request_new_defaults() {
        let req = simple_request();
        assert_eq!(req.addon_id, "test-addon");
        assert_eq!(req.abi_surface, NativeAddonAbiSurface::NodeApi);
        assert!(req.node_api_version.is_none());
        assert!(req.supported_fallbacks.is_empty());
        assert!(req.symbol_exports.is_empty());
        assert_eq!(
            req.handle_discipline,
            NativeAddonHandleDiscipline::NodeApiOnly
        );
        assert!(!req.uses_foreign_heap);
        assert!(!req.uses_process_global_state);
    }

    #[test]
    fn load_request_builder_methods() {
        let req = simple_request()
            .with_node_api_version(8)
            .with_symbol(NativeAddonSymbol::new(
                "fn1",
                NativeAddonSymbolClass::FunctionExport,
            ))
            .allow_fallback(NativeAddonFallbackMode::WasmPort)
            .with_handle_discipline(NativeAddonHandleDiscipline::ExternalBuffer);
        assert_eq!(req.node_api_version, Some(8));
        assert_eq!(req.symbol_exports.len(), 1);
        assert!(
            req.supported_fallbacks
                .contains(&NativeAddonFallbackMode::WasmPort)
        );
        assert_eq!(
            req.handle_discipline,
            NativeAddonHandleDiscipline::ExternalBuffer
        );
    }

    #[test]
    fn load_request_cohort_portable() {
        let req = simple_request();
        assert_eq!(req.cohort(), NativeAddonCohort::NodeApiPortable);
    }

    #[test]
    fn load_request_cohort_isolate_bound() {
        let mut req = simple_request();
        req.uses_async_workers = true;
        assert_eq!(req.cohort(), NativeAddonCohort::NodeApiIsolateBound);
    }

    #[test]
    fn load_request_cohort_privileged() {
        let mut req = simple_request();
        req.uses_process_global_state = true;
        assert_eq!(req.cohort(), NativeAddonCohort::NodeApiPrivileged);
    }

    #[test]
    fn load_request_cohort_nan() {
        let req = NativeAddonLoadRequest::new(
            "nan-addon",
            "nan-pkg",
            "1.0.0",
            "nan-pkg",
            "./nan.node",
            NativeAddonAbiSurface::Nan,
        );
        assert_eq!(req.cohort(), NativeAddonCohort::LegacyNan);
    }

    #[test]
    fn load_request_cohort_v8_direct() {
        let req = NativeAddonLoadRequest::new(
            "v8-addon",
            "v8-pkg",
            "1.0.0",
            "v8-pkg",
            "./v8.node",
            NativeAddonAbiSurface::V8Direct,
        );
        assert_eq!(req.cohort(), NativeAddonCohort::V8Binding);
    }

    #[test]
    fn load_request_cohort_foreign_ffi() {
        let req = NativeAddonLoadRequest::new(
            "ffi-addon",
            "ffi-pkg",
            "1.0.0",
            "ffi-pkg",
            "./ffi.node",
            NativeAddonAbiSurface::ForeignFfi,
        );
        assert_eq!(req.cohort(), NativeAddonCohort::ForeignFfi);
    }

    #[test]
    fn load_request_required_capabilities_base() {
        let req = simple_request();
        let caps = req.required_capabilities();
        assert!(caps.contains(&RuntimeCapability::ExtensionLifecycle));
    }

    #[test]
    fn load_request_required_capabilities_fs_read() {
        let mut req = simple_request();
        req.requires_filesystem_read = true;
        let caps = req.required_capabilities();
        assert!(caps.contains(&RuntimeCapability::FsRead));
    }

    #[test]
    fn load_request_required_capabilities_network() {
        let mut req = simple_request();
        req.requires_network_egress = true;
        let caps = req.required_capabilities();
        assert!(caps.contains(&RuntimeCapability::NetworkEgress));
    }

    #[test]
    fn load_request_required_capabilities_foreign_heap() {
        let mut req = simple_request();
        req.uses_foreign_heap = true;
        let caps = req.required_capabilities();
        assert!(caps.contains(&RuntimeCapability::HeapAllocate));
    }

    #[test]
    fn load_request_required_slot_capabilities_base() {
        let req = simple_request();
        let caps = req.required_slot_capabilities();
        assert!(caps.contains(&SlotCapability::EmitEvidence));
        assert!(caps.contains(&SlotCapability::InvokeHostcall));
    }

    #[test]
    fn load_request_required_slot_capabilities_module_linkage() {
        let mut req = simple_request();
        req.requires_module_linkage = true;
        let caps = req.required_slot_capabilities();
        assert!(caps.contains(&SlotCapability::ModuleAccess));
    }

    #[test]
    fn load_request_abi_fingerprint_deterministic() {
        let r1 = simple_request();
        let r2 = simple_request();
        assert_eq!(r1.abi_fingerprint(), r2.abi_fingerprint());
    }

    #[test]
    fn load_request_abi_fingerprint_differs_with_different_addon() {
        let r1 = simple_request();
        let r2 = NativeAddonLoadRequest::new(
            "other-addon",
            "test-pkg",
            "1.0.0",
            "test-pkg",
            "./build/test.node",
            NativeAddonAbiSurface::NodeApi,
        );
        assert_ne!(r1.abi_fingerprint(), r2.abi_fingerprint());
    }

    #[test]
    fn load_request_serde_roundtrip() {
        let req = simple_request()
            .with_node_api_version(8)
            .with_symbol(NativeAddonSymbol::new(
                "fn1",
                NativeAddonSymbolClass::FunctionExport,
            ));
        let json = serde_json::to_string(&req).unwrap();
        let back: NativeAddonLoadRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    // -----------------------------------------------------------------------
    // NativeAddonMembrane
    // -----------------------------------------------------------------------

    #[test]
    fn membrane_standard_defaults() {
        let m = NativeAddonMembrane::standard();
        assert_eq!(m.max_direct_node_api_version, 10);
        assert_eq!(m.delegate_cell_type, DelegateType::ExternalProcess);
    }

    #[test]
    fn membrane_default_equals_standard() {
        assert_eq!(
            NativeAddonMembrane::default(),
            NativeAddonMembrane::standard()
        );
    }

    #[test]
    fn membrane_assess_direct_for_safe_addon() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let surface = m.assess_support_surface(&req, &full_profile());
        assert_eq!(surface.support_status, NativeAddonSupportStatus::Direct);
        assert_eq!(
            surface.selected_route,
            Some(NativeAddonRoute::DirectMembrane)
        );
        assert!(surface.missing_capabilities.is_empty());
        assert!(surface.direct_blockers.is_empty());
    }

    #[test]
    fn membrane_assess_fallback_for_unsafe_handle() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request()
            .with_handle_discipline(NativeAddonHandleDiscipline::ExternalBuffer)
            .allow_fallback(NativeAddonFallbackMode::DelegateCell);
        let surface = m.assess_support_surface(&req, &full_profile());
        assert_eq!(
            surface.support_status,
            NativeAddonSupportStatus::FallbackOnly
        );
        assert_eq!(surface.selected_route, Some(NativeAddonRoute::DelegateCell));
    }

    #[test]
    fn membrane_assess_unsupported_no_fallback() {
        let m = NativeAddonMembrane::standard();
        let req =
            simple_request().with_handle_discipline(NativeAddonHandleDiscipline::RawPointerEscape);
        let surface = m.assess_support_surface(&req, &full_profile());
        assert_eq!(
            surface.support_status,
            NativeAddonSupportStatus::Unsupported
        );
        assert_eq!(surface.selected_route, None);
    }

    #[test]
    fn membrane_assess_unsupported_missing_capabilities() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request();
        req.requires_network_egress = true;
        let surface = m.assess_support_surface(&req, &CapabilityProfile::compute_only());
        assert_eq!(
            surface.support_status,
            NativeAddonSupportStatus::Unsupported
        );
        assert!(!surface.missing_capabilities.is_empty());
    }

    #[test]
    fn membrane_assess_wasm_fallback_preferred_over_delegate() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request()
            .with_handle_discipline(NativeAddonHandleDiscipline::ExternalBuffer)
            .allow_fallback(NativeAddonFallbackMode::WasmPort)
            .allow_fallback(NativeAddonFallbackMode::DelegateCell);
        req.wasm_portable = true;
        let surface = m.assess_support_surface(&req, &full_profile());
        assert_eq!(surface.selected_route, Some(NativeAddonRoute::WasmPort));
    }

    #[test]
    fn membrane_assess_non_node_api_blocked() {
        let m = NativeAddonMembrane::standard();
        let req = NativeAddonLoadRequest::new(
            "nan-addon",
            "nan-pkg",
            "1.0.0",
            "nan-pkg",
            "./nan.node",
            NativeAddonAbiSurface::Nan,
        );
        let surface = m.assess_support_surface(&req, &full_profile());
        assert!(!surface.direct_blockers.is_empty());
    }

    #[test]
    fn membrane_assess_high_api_version_blocked() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request().with_node_api_version(99);
        let surface = m.assess_support_surface(&req, &full_profile());
        assert!(!surface.direct_blockers.is_empty());
    }

    // -----------------------------------------------------------------------
    // NativeAddonMembrane::plan
    // -----------------------------------------------------------------------

    #[test]
    fn membrane_plan_success_direct() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let plan = m.plan(&req, &context(), &full_profile()).unwrap();
        assert_eq!(plan.route, NativeAddonRoute::DirectMembrane);
        assert_eq!(
            plan.invocation_channel,
            NativeAddonInvocationChannel::InProcessMembrane
        );
        assert_eq!(
            plan.crash_containment,
            NativeAddonCrashContainment::InProcessMembrane
        );
        assert!(plan.delegate_type.is_none());
        assert!(plan.capability_envelope.is_none());
        assert!(plan.sandbox.is_none());
    }

    #[test]
    fn membrane_plan_success_delegate_cell() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request()
            .with_handle_discipline(NativeAddonHandleDiscipline::ExternalBuffer)
            .allow_fallback(NativeAddonFallbackMode::DelegateCell);
        let plan = m.plan(&req, &context(), &full_profile()).unwrap();
        assert_eq!(plan.route, NativeAddonRoute::DelegateCell);
        assert_eq!(
            plan.invocation_channel,
            NativeAddonInvocationChannel::HostcallSession
        );
        assert_eq!(
            plan.crash_containment,
            NativeAddonCrashContainment::DelegateCellBoundary
        );
        assert!(plan.delegate_type.is_some());
        assert!(plan.capability_envelope.is_some());
        assert!(plan.sandbox.is_some());
    }

    #[test]
    fn membrane_plan_failure_returns_error() {
        let m = NativeAddonMembrane::standard();
        let req =
            simple_request().with_handle_discipline(NativeAddonHandleDiscipline::RawPointerEscape);
        let err = m.plan(&req, &context(), &full_profile()).unwrap_err();
        assert!(!err.message.is_empty());
        assert!(!err.event.trace_id.is_empty());
    }

    #[test]
    fn membrane_plan_error_missing_capability() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request();
        req.requires_network_egress = true;
        let err = m
            .plan(&req, &context(), &CapabilityProfile::compute_only())
            .unwrap_err();
        assert_eq!(err.code, NativeAddonMembraneErrorCode::MissingCapability);
    }

    // -----------------------------------------------------------------------
    // NativeAddonMembrane::inventory_report
    // -----------------------------------------------------------------------

    #[test]
    fn inventory_report_empty_requests() {
        let m = NativeAddonMembrane::standard();
        let report = m.inventory_report(&[], &full_profile());
        assert_eq!(report.schema_version, INVENTORY_SCHEMA_VERSION);
        assert!(report.support_surface.is_empty());
        assert!(report.compatibility_matrix.is_empty());
        assert!(report.abi_fingerprint_index.is_empty());
        assert!(report.cohort_counts.is_empty());
    }

    #[test]
    fn inventory_report_single_request() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let report = m.inventory_report(&[req], &full_profile());
        assert_eq!(report.support_surface.len(), 1);
        assert_eq!(report.compatibility_matrix.len(), 1);
        assert_eq!(report.abi_fingerprint_index.len(), 1);
        assert_eq!(*report.cohort_counts.get("node_api_portable").unwrap(), 1);
    }

    #[test]
    fn inventory_report_hash_deterministic() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let r1 = m.inventory_report(std::slice::from_ref(&req), &full_profile());
        let r2 = m.inventory_report(std::slice::from_ref(&req), &full_profile());
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn inventory_report_multiple_requests_counted() {
        let m = NativeAddonMembrane::standard();
        let r1 = simple_request();
        let r2 = NativeAddonLoadRequest::new(
            "addon-2",
            "pkg-2",
            "2.0.0",
            "pkg-2",
            "./build/a2.node",
            NativeAddonAbiSurface::NodeApi,
        );
        let report = m.inventory_report(&[r1, r2], &full_profile());
        assert_eq!(report.support_surface.len(), 2);
        assert_eq!(*report.cohort_counts.get("node_api_portable").unwrap(), 2);
    }

    #[test]
    fn inventory_report_required_addon_coverage_is_explicit() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let report = m.inventory_report_with_requirements(
            std::slice::from_ref(&req),
            &full_profile(),
            &[
                " missing-addon ".to_string(),
                req.addon_id.clone(),
                "missing-addon".to_string(),
            ],
        );

        assert_eq!(
            report.required_addon_ids,
            vec!["missing-addon".to_string(), req.addon_id.clone()]
        );
        assert!(!report.coverage_complete);
        assert_eq!(report.coverage_gaps.len(), 1);
        assert_eq!(report.coverage_gaps[0].addon_id, "missing-addon");
        assert_eq!(
            report.coverage_gaps[0].reason_code,
            "missing_from_inventory_input"
        );
        assert!(report.coverage_gaps[0].message.contains("missing-addon"));
    }

    // -----------------------------------------------------------------------
    // direct_blockers
    // -----------------------------------------------------------------------

    #[test]
    fn direct_blockers_empty_for_safe_addon() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let blockers = m.direct_blockers(&req);
        assert!(blockers.is_empty());
    }

    #[test]
    fn direct_blockers_non_node_api() {
        let m = NativeAddonMembrane::standard();
        let req = NativeAddonLoadRequest::new(
            "v8",
            "v8-pkg",
            "1.0.0",
            "v8-pkg",
            "./v8.node",
            NativeAddonAbiSurface::V8Direct,
        );
        let blockers = m.direct_blockers(&req);
        assert!(!blockers.is_empty());
        assert!(blockers[0].contains("node_api"));
    }

    #[test]
    fn direct_blockers_high_api_version() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request().with_node_api_version(99);
        let blockers = m.direct_blockers(&req);
        assert!(blockers.iter().any(|b| b.contains("version")));
    }

    #[test]
    fn direct_blockers_unsafe_handle() {
        let m = NativeAddonMembrane::standard();
        let req =
            simple_request().with_handle_discipline(NativeAddonHandleDiscipline::RawPointerEscape);
        let blockers = m.direct_blockers(&req);
        assert!(blockers.iter().any(|b| b.contains("direct-safe")));
    }

    #[test]
    fn direct_blockers_foreign_heap() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request();
        req.uses_foreign_heap = true;
        let blockers = m.direct_blockers(&req);
        assert!(blockers.iter().any(|b| b.contains("foreign heap")));
    }

    #[test]
    fn direct_blockers_process_global_state() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request();
        req.uses_process_global_state = true;
        let blockers = m.direct_blockers(&req);
        assert!(blockers.iter().any(|b| b.contains("process-global")));
    }

    #[test]
    fn direct_blockers_unsafe_symbol_class() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request().with_symbol(NativeAddonSymbol::new(
            "unsafe_buf",
            NativeAddonSymbolClass::ExternalBuffer,
        ));
        let blockers = m.direct_blockers(&req);
        assert!(blockers.iter().any(|b| b.contains("non-direct-safe")));
    }

    // -----------------------------------------------------------------------
    // classify_failure
    // -----------------------------------------------------------------------

    #[test]
    fn classify_failure_missing_capability() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request();
        req.requires_network_egress = true;
        let surface = m.assess_support_surface(&req, &CapabilityProfile::compute_only());
        assert_eq!(
            m.classify_failure(&surface),
            NativeAddonMembraneErrorCode::MissingCapability
        );
    }

    #[test]
    fn classify_failure_unsupported_abi() {
        let m = NativeAddonMembrane::standard();
        let req = NativeAddonLoadRequest::new(
            "v8-addon",
            "v8-pkg",
            "1.0.0",
            "v8-pkg",
            "./v8.node",
            NativeAddonAbiSurface::V8Direct,
        );
        let surface = m.assess_support_surface(&req, &full_profile());
        assert_eq!(
            m.classify_failure(&surface),
            NativeAddonMembraneErrorCode::UnsupportedAbiSurface
        );
    }

    // -----------------------------------------------------------------------
    // Error display
    // -----------------------------------------------------------------------

    #[test]
    fn membrane_error_display_contains_stable_code() {
        let m = NativeAddonMembrane::standard();
        let req =
            simple_request().with_handle_discipline(NativeAddonHandleDiscipline::RawPointerEscape);
        let err = m.plan(&req, &context(), &full_profile()).unwrap_err();
        let display = err.to_string();
        assert!(display.contains("FE-NAM-"));
    }

    #[test]
    fn membrane_error_is_std_error() {
        let m = NativeAddonMembrane::standard();
        let req =
            simple_request().with_handle_discipline(NativeAddonHandleDiscipline::RawPointerEscape);
        let err = m.plan(&req, &context(), &full_profile()).unwrap_err();
        let _: &dyn std::error::Error = &*err;
    }

    #[test]
    fn artifact_write_error_display() {
        let err = NativeAddonArtifactWriteError {
            code: NativeAddonArtifactWriteErrorCode::InvalidRunId,
            path: "bad/path".to_string(),
            message: "invalid".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("invalid"));
        assert!(display.contains("bad/path"));
    }

    #[test]
    fn artifact_write_error_is_std_error() {
        let err = NativeAddonArtifactWriteError {
            code: NativeAddonArtifactWriteErrorCode::Io,
            path: String::new(),
            message: String::new(),
        };
        let _: &dyn std::error::Error = &err;
    }

    // -----------------------------------------------------------------------
    // normalize_run_id
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_run_id_valid() {
        assert_eq!(
            normalize_run_id("valid-run-id".to_string()).unwrap(),
            "valid-run-id"
        );
    }

    #[test]
    fn normalize_run_id_trims() {
        assert_eq!(
            normalize_run_id("  trimmed  ".to_string()).unwrap(),
            "trimmed"
        );
    }

    #[test]
    fn normalize_run_id_rejects_empty() {
        assert!(normalize_run_id(String::new()).is_err());
    }

    #[test]
    fn normalize_run_id_rejects_path_traversal() {
        assert!(normalize_run_id("../escape".to_string()).is_err());
    }

    #[test]
    fn normalize_run_id_rejects_absolute() {
        assert!(normalize_run_id("/absolute".to_string()).is_err());
    }

    // -----------------------------------------------------------------------
    // artifact_names
    // -----------------------------------------------------------------------

    #[test]
    fn artifact_names_non_empty() {
        let names = artifact_names();
        assert!(!names.is_empty());
        for name in &names {
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn artifact_names_sorted() {
        let names = artifact_names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    // -----------------------------------------------------------------------
    // compatibility_notes
    // -----------------------------------------------------------------------

    #[test]
    fn load_request_symbol_families_are_sorted_and_deduped() {
        let req = simple_request()
            .with_symbol(NativeAddonSymbol::new(
                "beta",
                NativeAddonSymbolClass::FunctionExport,
            ))
            .with_symbol(NativeAddonSymbol::new(
                "alpha",
                NativeAddonSymbolClass::ValueExport,
            ))
            .with_symbol(NativeAddonSymbol::new(
                "gamma",
                NativeAddonSymbolClass::FunctionExport,
            ));

        assert_eq!(
            req.symbol_families(),
            vec!["function_export".to_string(), "value_export".to_string()]
        );
    }

    #[test]
    fn compatibility_notes_direct_eligible() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let surface = m.assess_support_surface(&req, &full_profile());
        assert_eq!(
            surface.risk_classification,
            NativeAddonRiskClassification::Low
        );
        assert_eq!(surface.owner_route, "interop-native-addon");
        assert_eq!(
            surface.remediation_hint,
            "retain the stable Node-API surface and current handle discipline"
        );
        assert!(surface.symbol_families.is_empty());
        let notes = compatibility_notes(&surface);
        assert_eq!(
            notes,
            "risk=low owner_route=interop-native-addon remediation=retain the stable Node-API surface and current handle discipline; direct membrane eligible"
        );
    }

    #[test]
    fn compatibility_notes_missing_caps() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request();
        req.requires_network_egress = true;
        let surface = m.assess_support_surface(&req, &CapabilityProfile::compute_only());
        assert_eq!(
            surface.risk_classification,
            NativeAddonRiskClassification::Critical
        );
        assert_eq!(surface.owner_route, "security-capability-review");
        assert_eq!(
            surface.remediation_hint,
            "grant missing capabilities (network_egress) or keep the addon unsupported until the package matrix and policy contract are updated"
        );
        let notes = compatibility_notes(&surface);
        assert!(notes.starts_with(
            "risk=critical owner_route=security-capability-review remediation=grant missing capabilities (network_egress)"
        ));
        assert!(notes.contains("missing capabilities: network_egress"));
    }

    #[test]
    fn compatibility_notes_direct_blockers() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request()
            .with_handle_discipline(NativeAddonHandleDiscipline::ExternalBuffer)
            .allow_fallback(NativeAddonFallbackMode::DelegateCell);
        let surface = m.assess_support_surface(&req, &full_profile());
        assert_eq!(surface.symbol_families, vec!["external_buffer".to_string()]);
        assert_eq!(
            surface.risk_classification,
            NativeAddonRiskClassification::High
        );
        assert_eq!(surface.owner_route, "runtime-delegate-cell");
        assert_eq!(
            surface.remediation_hint,
            "route through the delegate cell and isolate unsafe pointer or heap behavior behind the hostcall session boundary"
        );
        let notes = compatibility_notes(&surface);
        assert!(notes.starts_with(
            "risk=high owner_route=runtime-delegate-cell remediation=route through the delegate cell"
        ));
        assert!(notes.contains("direct blockers:"));
        assert!(notes.contains("selected fallback: delegate_cell"));
    }

    // -----------------------------------------------------------------------
    // slot_capability_sort_key
    // -----------------------------------------------------------------------

    #[test]
    fn slot_capability_sort_key_ordered() {
        let caps = [
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::HeapAlloc,
            SlotCapability::ScheduleAsync,
            SlotCapability::InvokeHostcall,
            SlotCapability::ModuleAccess,
            SlotCapability::TriggerGc,
            SlotCapability::EmitEvidence,
        ];
        for pair in caps.windows(2) {
            assert!(slot_capability_sort_key(pair[0]) < slot_capability_sort_key(pair[1]));
        }
    }

    // -----------------------------------------------------------------------
    // push_slot_capability
    // -----------------------------------------------------------------------

    #[test]
    fn push_slot_capability_adds_new() {
        let mut caps = Vec::new();
        push_slot_capability(&mut caps, SlotCapability::HeapAlloc);
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn push_slot_capability_deduplicates() {
        let mut caps = vec![SlotCapability::HeapAlloc];
        push_slot_capability(&mut caps, SlotCapability::HeapAlloc);
        assert_eq!(caps.len(), 1);
    }

    // -----------------------------------------------------------------------
    // NativeAddonMembrane serde
    // -----------------------------------------------------------------------

    #[test]
    fn membrane_serde_roundtrip() {
        let m = NativeAddonMembrane::standard();
        let json = serde_json::to_string(&m).unwrap();
        let back: NativeAddonMembrane = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    // -----------------------------------------------------------------------
    // delegate_sandbox adjustments
    // -----------------------------------------------------------------------

    #[test]
    fn delegate_sandbox_base_when_simple() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let sandbox = m.delegate_sandbox(&req);
        assert_eq!(sandbox, SandboxConfiguration::default());
    }

    #[test]
    fn delegate_sandbox_increases_heap_for_foreign_heap() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request();
        req.uses_foreign_heap = true;
        let sandbox = m.delegate_sandbox(&req);
        assert!(sandbox.max_heap_bytes >= 128 * 1024 * 1024);
    }

    #[test]
    fn delegate_sandbox_increases_timeout_for_async_workers() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request();
        req.uses_async_workers = true;
        let sandbox = m.delegate_sandbox(&req);
        assert!(sandbox.max_execution_ns >= 10_000_000_000);
        assert!(sandbox.max_hostcalls >= 20_000);
    }

    #[test]
    fn delegate_sandbox_allows_network_when_required() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request();
        req.requires_network_egress = true;
        let sandbox = m.delegate_sandbox(&req);
        assert!(sandbox.network_egress_allowed);
    }

    #[test]
    fn delegate_sandbox_allows_fs_when_required() {
        let m = NativeAddonMembrane::standard();
        let mut req = simple_request();
        req.requires_filesystem_read = true;
        let sandbox = m.delegate_sandbox(&req);
        assert!(sandbox.filesystem_access_allowed);
    }

    // -----------------------------------------------------------------------
    // decision_stable_id
    // -----------------------------------------------------------------------

    #[test]
    fn decision_stable_id_deterministic() {
        let ctx = context();
        let fingerprint = ContentHash::compute(b"test");
        let id1 = native_addon_decision_stable_id(
            &ctx,
            "addon-1",
            &fingerprint,
            NativeAddonSupportStatus::Direct,
            Some(NativeAddonRoute::DirectMembrane),
            "none",
        );
        let id2 = native_addon_decision_stable_id(
            &ctx,
            "addon-1",
            &fingerprint,
            NativeAddonSupportStatus::Direct,
            Some(NativeAddonRoute::DirectMembrane),
            "none",
        );
        assert_eq!(id1, id2);
    }

    #[test]
    fn decision_stable_id_prefixed() {
        let ctx = context();
        let fingerprint = ContentHash::compute(b"test");
        let id = native_addon_decision_stable_id(
            &ctx,
            "addon-1",
            &fingerprint,
            NativeAddonSupportStatus::Direct,
            Some(NativeAddonRoute::DirectMembrane),
            "none",
        );
        assert!(id.starts_with("native-addon-dec-"));
    }

    #[test]
    fn decision_stable_id_differs_for_different_addons() {
        let ctx = context();
        let fingerprint = ContentHash::compute(b"test");
        let id1 = native_addon_decision_stable_id(
            &ctx,
            "addon-1",
            &fingerprint,
            NativeAddonSupportStatus::Direct,
            Some(NativeAddonRoute::DirectMembrane),
            "none",
        );
        let id2 = native_addon_decision_stable_id(
            &ctx,
            "addon-2",
            &fingerprint,
            NativeAddonSupportStatus::Direct,
            Some(NativeAddonRoute::DirectMembrane),
            "none",
        );
        assert_ne!(id1, id2);
    }

    // -----------------------------------------------------------------------
    // Canonical hash / report hash
    // -----------------------------------------------------------------------

    #[test]
    fn inventory_report_canonical_hash_stable() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let r1 = m.inventory_report(std::slice::from_ref(&req), &full_profile());
        let r2 = m.inventory_report(std::slice::from_ref(&req), &full_profile());
        assert_eq!(r1.canonical_hash(), r2.canonical_hash());
    }

    #[test]
    fn inventory_report_canonical_bytes_non_empty() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let report = m.inventory_report(&[req], &full_profile());
        assert!(!report.canonical_bytes().is_empty());
    }

    // -----------------------------------------------------------------------
    // Struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn decision_event_serde_roundtrip() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let surface = m.assess_support_surface(&req, &full_profile());
        let event = m.build_event(
            &surface,
            &context(),
            "allow",
            "none",
            Some(NativeAddonRoute::DirectMembrane),
        );
        let json = serde_json::to_string(&event).unwrap();
        let back: NativeAddonDecisionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn support_surface_serde_roundtrip() {
        let m = NativeAddonMembrane::standard();
        let req = simple_request();
        let surface = m.assess_support_surface(&req, &full_profile());
        let json = serde_json::to_string(&surface).unwrap();
        let back: NativeAddonSupportSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(surface, back);
    }

    #[test]
    fn membrane_report_serde_roundtrip() {
        let report = NativeAddonMembraneReport {
            schema_version: MEMBRANE_REPORT_SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            component: COMPONENT.to_string(),
            generated_at_unix_ms: 1_000_000,
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            addon_count: 5,
            direct_count: 3,
            fallback_only_count: 1,
            unsupported_count: 1,
            inventory_hash: ContentHash::compute(b"test"),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: NativeAddonMembraneReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn inventory_report_serde_roundtrip() {
        let report = NativeAddonInventoryReport {
            schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
            support_surface: Vec::new(),
            compatibility_matrix: Vec::new(),
            abi_fingerprint_index: Vec::new(),
            cohort_counts: BTreeMap::new(),
            required_addon_ids: Vec::new(),
            coverage_gaps: Vec::new(),
            coverage_complete: true,
            report_hash: ContentHash::compute(b"empty"),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: NativeAddonInventoryReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }
}
