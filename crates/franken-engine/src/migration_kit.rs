//! Node/Bun-to-FrankenEngine migration kit with behavior validation.
//!
//! Provides compatibility analysis, capability inference, behavior validation,
//! migration manifest generation, and guided remediation for migrating
//! Node.js/Bun extensions to FrankenEngine.
//!
//! Plan reference: Section 15, Execution Pillar 2, bd-3bz4.2.
//! Cross-refs: bd-3bz4.1 (extension\_registry), bd-3bz4.3 (governance\_hooks),
//!   bd-j7z (feature\_parity\_tracker), 9F.6 (tri-runtime lockstep oracle).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// =========================================================================
// Constants
// =========================================================================

pub const COMPONENT: &str = "migration_kit";
const MIGRATION_ZONE: &str = "migration-kit";
const MANIFEST_SCHEMA_DEF: &[u8] = b"MigrationManifest.v1";
pub const REPORT_SCHEMA_DEF: &[u8] = b"MigrationAnalysisReport.v1";
const DIVERGENCE_SCHEMA_DEF: &[u8] = b"BehaviorDivergence.v1";
const REMEDIATION_SCHEMA_DEF: &[u8] = b"RemediationStep.v1";

const MAX_API_ENTRIES: usize = 10_000;
const MAX_DEPENDENCY_ENTRIES: usize = 5_000;
const MAX_DIVERGENCES: usize = 10_000;
const MAX_REMEDIATION_STEPS: usize = 5_000;
const MAX_SOURCE_FILES: usize = 50_000;

// =========================================================================
// Error types
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationKitError {
    AnalysisFailed {
        detail: String,
    },
    ManifestGenerationFailed {
        detail: String,
    },
    CapabilityInferenceFailed {
        detail: String,
    },
    BehaviorValidationFailed {
        detail: String,
    },
    RemediationUnavailable {
        detail: String,
    },
    InvalidPackageJson {
        detail: String,
    },
    UnsupportedApiDetected {
        api: String,
        detail: String,
    },
    IncompatibleDependency {
        name: String,
        reason: String,
    },
    LockstepMismatch {
        runtime: String,
        detail: String,
    },
    ReportGenerationFailed {
        detail: String,
    },
    DeterminismViolation {
        detail: String,
    },
    TooManyEntries {
        kind: String,
        count: usize,
        max: usize,
    },
    InternalError {
        detail: String,
    },
}

impl MigrationKitError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AnalysisFailed { .. } => "FE-MK-0001",
            Self::ManifestGenerationFailed { .. } => "FE-MK-0002",
            Self::CapabilityInferenceFailed { .. } => "FE-MK-0003",
            Self::BehaviorValidationFailed { .. } => "FE-MK-0004",
            Self::RemediationUnavailable { .. } => "FE-MK-0005",
            Self::InvalidPackageJson { .. } => "FE-MK-0006",
            Self::UnsupportedApiDetected { .. } => "FE-MK-0007",
            Self::IncompatibleDependency { .. } => "FE-MK-0008",
            Self::LockstepMismatch { .. } => "FE-MK-0009",
            Self::ReportGenerationFailed { .. } => "FE-MK-0010",
            Self::DeterminismViolation { .. } => "FE-MK-0011",
            Self::TooManyEntries { .. } => "FE-MK-0012",
            Self::InternalError { .. } => "FE-MK-0099",
        }
    }
}

impl fmt::Display for MigrationKitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnalysisFailed { detail } => write!(f, "analysis failed: {detail}"),
            Self::ManifestGenerationFailed { detail } => {
                write!(f, "manifest generation failed: {detail}")
            }
            Self::CapabilityInferenceFailed { detail } => {
                write!(f, "capability inference failed: {detail}")
            }
            Self::BehaviorValidationFailed { detail } => {
                write!(f, "behavior validation failed: {detail}")
            }
            Self::RemediationUnavailable { detail } => {
                write!(f, "remediation unavailable: {detail}")
            }
            Self::InvalidPackageJson { detail } => {
                write!(f, "invalid package.json: {detail}")
            }
            Self::UnsupportedApiDetected { api, detail } => {
                write!(f, "unsupported API '{api}': {detail}")
            }
            Self::IncompatibleDependency { name, reason } => {
                write!(f, "incompatible dependency '{name}': {reason}")
            }
            Self::LockstepMismatch { runtime, detail } => {
                write!(f, "lockstep mismatch for {runtime}: {detail}")
            }
            Self::ReportGenerationFailed { detail } => {
                write!(f, "report generation failed: {detail}")
            }
            Self::DeterminismViolation { detail } => {
                write!(f, "determinism violation: {detail}")
            }
            Self::TooManyEntries { kind, count, max } => {
                write!(f, "too many {kind} entries: {count} exceeds max {max}")
            }
            Self::InternalError { detail } => write!(f, "internal error: {detail}"),
        }
    }
}

impl std::error::Error for MigrationKitError {}

// =========================================================================
// Enums
// =========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SourceRuntime {
    Node,
    Bun,
}

impl fmt::Display for SourceRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node => write!(f, "Node.js"),
            Self::Bun => write!(f, "Bun"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ApiSupportLevel {
    FullySupported,
    PartiallySupported,
    Unsupported,
    Deprecated,
    RequiresPolyfill,
}

impl ApiSupportLevel {
    pub fn is_migration_blocker(&self) -> bool {
        matches!(self, Self::Unsupported)
    }

    pub fn compatibility_weight_millionths(&self) -> u64 {
        match self {
            Self::FullySupported => 1_000_000,
            Self::PartiallySupported => 700_000,
            Self::Deprecated => 500_000,
            Self::RequiresPolyfill => 400_000,
            Self::Unsupported => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DivergenceKind {
    SemanticDifference,
    TimingDifference,
    OutputFormatDifference,
    ErrorBehaviorDifference,
    MissingFeature,
    SecurityPolicyDifference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DivergenceSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl DivergenceSeverity {
    pub fn penalty_millionths(&self) -> u64 {
        match self {
            Self::Critical => 200_000,
            Self::High => 100_000,
            Self::Medium => 50_000,
            Self::Low => 20_000,
            Self::Informational => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InferredCapabilityKind {
    FileSystem,
    Network,
    ProcessSpawn,
    EnvironmentAccess,
    CryptoAccess,
    TimerAccess,
    WorkerThreads,
    ChildProcess,
    DynamicImport,
    WasmExecution,
    SharedMemory,
    NativeAddon,
}

impl InferredCapabilityKind {
    pub fn franken_capability_name(&self) -> &'static str {
        match self {
            Self::FileSystem => "cap:fs",
            Self::Network => "cap:net",
            Self::ProcessSpawn => "cap:process:spawn",
            Self::EnvironmentAccess => "cap:env",
            Self::CryptoAccess => "cap:crypto",
            Self::TimerAccess => "cap:timer",
            Self::WorkerThreads => "cap:worker",
            Self::ChildProcess => "cap:process:child",
            Self::DynamicImport => "cap:import:dynamic",
            Self::WasmExecution => "cap:wasm",
            Self::SharedMemory => "cap:shared-memory",
            Self::NativeAddon => "cap:native-addon",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RemediationCategory {
    ApiReplacement,
    DependencySwap,
    ConfigChange,
    CodeRefactor,
    PolyfillAddition,
    SecurityPolicyUpdate,
    FeatureDisable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RemediationEffort {
    Trivial,
    Low,
    Medium,
    High,
    Significant,
}

impl RemediationEffort {
    pub fn weight_millionths(&self) -> u64 {
        match self {
            Self::Trivial => 100_000,
            Self::Low => 300_000,
            Self::Medium => 500_000,
            Self::High => 800_000,
            Self::Significant => 1_000_000,
        }
    }
}

// =========================================================================
// Core structs
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiUsageEntry {
    pub api_name: String,
    pub module_path: String,
    pub usage_count: u64,
    pub support_level: ApiSupportLevel,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEntry {
    pub name: String,
    pub version_spec: String,
    pub compatible: bool,
    pub migration_notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityReport {
    pub source_runtime: SourceRuntime,
    pub total_apis_used: u64,
    pub fully_supported_count: u64,
    pub partially_supported_count: u64,
    pub unsupported_count: u64,
    pub deprecated_count: u64,
    pub polyfill_required_count: u64,
    pub compatibility_score_millionths: u64,
    pub api_entries: Vec<ApiUsageEntry>,
    pub dependency_entries: Vec<DependencyEntry>,
    pub report_content_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorDivergence {
    pub divergence_id: EngineObjectId,
    pub kind: DivergenceKind,
    pub severity: DivergenceSeverity,
    pub test_case: String,
    pub node_bun_result: String,
    pub franken_result: String,
    pub explanation: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorValidationReport {
    pub total_test_cases: u64,
    pub passing_count: u64,
    pub divergence_count: u64,
    pub parity_score_millionths: u64,
    pub divergences: Vec<BehaviorDivergence>,
    pub report_content_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferredCapability {
    pub kind: InferredCapabilityKind,
    pub confidence_millionths: u64,
    pub evidence_sources: Vec<String>,
    pub franken_capability_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityInferenceResult {
    pub inferred_capabilities: Vec<InferredCapability>,
    pub minimum_capability_set: BTreeSet<String>,
    pub recommended_capability_set: BTreeSet<String>,
    pub capability_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationStep {
    pub step_id: EngineObjectId,
    pub category: RemediationCategory,
    pub effort: RemediationEffort,
    pub title: String,
    pub description: String,
    pub before_snippet: String,
    pub after_snippet: String,
    pub affected_files: Vec<String>,
    pub priority_score_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationManifest {
    pub manifest_id: EngineObjectId,
    pub source_runtime: SourceRuntime,
    pub source_package_name: String,
    pub source_version: String,
    pub franken_extension_name: String,
    pub franken_extension_version: String,
    pub required_capabilities: BTreeSet<String>,
    pub entry_point: String,
    pub compatibility_score_millionths: u64,
    pub parity_score_millionths: u64,
    pub remediation_count: u64,
    pub migration_readiness_score_millionths: u64,
    pub manifest_content_hash: ContentHash,
    pub created_epoch: SecurityEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub details: BTreeMap<String, String>,
}

// =========================================================================
// Config
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationConfig {
    pub source_runtime: SourceRuntime,
    pub analyze_dependencies: bool,
    pub infer_capabilities: bool,
    pub run_behavior_validation: bool,
    pub min_compatibility_score_millionths: u64,
    pub max_divergence_count: u64,
    pub deterministic_seed: u64,
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self {
            source_runtime: SourceRuntime::Node,
            analyze_dependencies: true,
            infer_capabilities: true,
            run_behavior_validation: true,
            min_compatibility_score_millionths: 800_000,
            max_divergence_count: 100,
            deterministic_seed: 42,
        }
    }
}

// =========================================================================
// Input types
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockstepTestResult {
    pub test_name: String,
    pub node_output: String,
    pub franken_output: String,
    pub node_exit_code: i32,
    pub franken_exit_code: i32,
    pub node_duration_us: u64,
    pub franken_duration_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestGenerationInput {
    pub source_runtime: SourceRuntime,
    pub source_package_name: String,
    pub source_version: String,
    pub entry_point: String,
    pub compatibility: CompatibilityReport,
    pub behavior: BehaviorValidationReport,
    pub capabilities: CapabilityInferenceResult,
    pub epoch: SecurityEpoch,
}

// =========================================================================
// Known API database
// =========================================================================

pub struct KnownApi {
    pub module_name: &'static str,
    pub api_name: &'static str,
    pub support_level: ApiSupportLevel,
    pub notes: &'static str,
}

const KNOWN_APIS: &[KnownApi] = &[
    KnownApi {
        module_name: "fs",
        api_name: "readFile",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic fs sandbox",
    },
    KnownApi {
        module_name: "fs",
        api_name: "writeFile",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic fs sandbox",
    },
    KnownApi {
        module_name: "fs",
        api_name: "readdir",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic fs sandbox",
    },
    KnownApi {
        module_name: "fs",
        api_name: "stat",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic fs sandbox",
    },
    KnownApi {
        module_name: "fs",
        api_name: "mkdir",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic fs sandbox",
    },
    KnownApi {
        module_name: "fs",
        api_name: "unlink",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic fs sandbox",
    },
    KnownApi {
        module_name: "path",
        api_name: "join",
        support_level: ApiSupportLevel::FullySupported,
        notes: "platform-normalized paths",
    },
    KnownApi {
        module_name: "path",
        api_name: "resolve",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic resolution",
    },
    KnownApi {
        module_name: "path",
        api_name: "basename",
        support_level: ApiSupportLevel::FullySupported,
        notes: "",
    },
    KnownApi {
        module_name: "os",
        api_name: "platform",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "returns virtual platform",
    },
    KnownApi {
        module_name: "os",
        api_name: "cpus",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "returns budgeted CPU info",
    },
    KnownApi {
        module_name: "http",
        api_name: "createServer",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "sandboxed networking",
    },
    KnownApi {
        module_name: "http",
        api_name: "request",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "requires cap:net",
    },
    KnownApi {
        module_name: "https",
        api_name: "createServer",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "sandboxed TLS",
    },
    KnownApi {
        module_name: "https",
        api_name: "request",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "requires cap:net",
    },
    KnownApi {
        module_name: "net",
        api_name: "createConnection",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "requires cap:net",
    },
    KnownApi {
        module_name: "crypto",
        api_name: "createHash",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic hashing",
    },
    KnownApi {
        module_name: "crypto",
        api_name: "randomBytes",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "deterministic PRNG in sandbox",
    },
    KnownApi {
        module_name: "crypto",
        api_name: "createCipheriv",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "subset of ciphers",
    },
    KnownApi {
        module_name: "child_process",
        api_name: "exec",
        support_level: ApiSupportLevel::Unsupported,
        notes: "no shell access in sandbox",
    },
    KnownApi {
        module_name: "child_process",
        api_name: "spawn",
        support_level: ApiSupportLevel::Unsupported,
        notes: "no process spawn in sandbox",
    },
    KnownApi {
        module_name: "child_process",
        api_name: "fork",
        support_level: ApiSupportLevel::Unsupported,
        notes: "use worker_threads instead",
    },
    KnownApi {
        module_name: "cluster",
        api_name: "fork",
        support_level: ApiSupportLevel::Unsupported,
        notes: "not applicable in sandboxed runtime",
    },
    KnownApi {
        module_name: "worker_threads",
        api_name: "Worker",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "deterministic scheduling",
    },
    KnownApi {
        module_name: "worker_threads",
        api_name: "isMainThread",
        support_level: ApiSupportLevel::FullySupported,
        notes: "",
    },
    KnownApi {
        module_name: "events",
        api_name: "EventEmitter",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic event ordering",
    },
    KnownApi {
        module_name: "stream",
        api_name: "Readable",
        support_level: ApiSupportLevel::FullySupported,
        notes: "",
    },
    KnownApi {
        module_name: "stream",
        api_name: "Writable",
        support_level: ApiSupportLevel::FullySupported,
        notes: "",
    },
    KnownApi {
        module_name: "stream",
        api_name: "Transform",
        support_level: ApiSupportLevel::FullySupported,
        notes: "",
    },
    KnownApi {
        module_name: "buffer",
        api_name: "Buffer",
        support_level: ApiSupportLevel::FullySupported,
        notes: "bounded allocation",
    },
    KnownApi {
        module_name: "url",
        api_name: "URL",
        support_level: ApiSupportLevel::FullySupported,
        notes: "WHATWG URL",
    },
    KnownApi {
        module_name: "url",
        api_name: "URLSearchParams",
        support_level: ApiSupportLevel::FullySupported,
        notes: "",
    },
    KnownApi {
        module_name: "util",
        api_name: "promisify",
        support_level: ApiSupportLevel::FullySupported,
        notes: "",
    },
    KnownApi {
        module_name: "util",
        api_name: "inspect",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "sandboxed output",
    },
    KnownApi {
        module_name: "process",
        api_name: "env",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "sandboxed env vars via cap:env",
    },
    KnownApi {
        module_name: "process",
        api_name: "exit",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "triggers controlled shutdown",
    },
    KnownApi {
        module_name: "process",
        api_name: "argv",
        support_level: ApiSupportLevel::PartiallySupported,
        notes: "sandboxed arguments",
    },
    KnownApi {
        module_name: "dns",
        api_name: "resolve",
        support_level: ApiSupportLevel::Unsupported,
        notes: "no DNS in sandbox",
    },
    KnownApi {
        module_name: "dgram",
        api_name: "createSocket",
        support_level: ApiSupportLevel::Unsupported,
        notes: "no UDP in sandbox",
    },
    KnownApi {
        module_name: "vm",
        api_name: "createContext",
        support_level: ApiSupportLevel::Unsupported,
        notes: "use FrankenEngine isolation",
    },
    KnownApi {
        module_name: "native",
        api_name: "addon",
        support_level: ApiSupportLevel::Unsupported,
        notes: "native addons not supported",
    },
    KnownApi {
        module_name: "timers",
        api_name: "setTimeout",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic virtual clock",
    },
    KnownApi {
        module_name: "timers",
        api_name: "setInterval",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic virtual clock",
    },
    KnownApi {
        module_name: "timers",
        api_name: "setImmediate",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic scheduling",
    },
    KnownApi {
        module_name: "console",
        api_name: "log",
        support_level: ApiSupportLevel::FullySupported,
        notes: "captured output",
    },
    KnownApi {
        module_name: "assert",
        api_name: "strict",
        support_level: ApiSupportLevel::FullySupported,
        notes: "",
    },
    KnownApi {
        module_name: "zlib",
        api_name: "gzip",
        support_level: ApiSupportLevel::FullySupported,
        notes: "deterministic compression",
    },
    KnownApi {
        module_name: "querystring",
        api_name: "parse",
        support_level: ApiSupportLevel::Deprecated,
        notes: "use URLSearchParams",
    },
    KnownApi {
        module_name: "punycode",
        api_name: "encode",
        support_level: ApiSupportLevel::Deprecated,
        notes: "use url.domainToASCII",
    },
];

pub fn lookup_api(module_name: &str, api_name: &str) -> Option<&'static KnownApi> {
    KNOWN_APIS
        .iter()
        .find(|a| a.module_name == module_name && a.api_name == api_name)
}

fn lookup_module(module_name: &str) -> ApiSupportLevel {
    let mut best = None;
    for api in KNOWN_APIS {
        if api.module_name == module_name {
            let current = best.unwrap_or(ApiSupportLevel::Unsupported);
            if (api.support_level as u8) < (current as u8) {
                best = Some(api.support_level);
            }
        }
    }
    best.unwrap_or(ApiSupportLevel::Unsupported)
}

// =========================================================================
// Capability inference patterns
// =========================================================================

struct CapabilityPattern {
    pattern: &'static str,
    kind: InferredCapabilityKind,
    confidence_millionths: u64,
}

const CAPABILITY_PATTERNS: &[CapabilityPattern] = &[
    CapabilityPattern {
        pattern: "require(\"fs\")",
        kind: InferredCapabilityKind::FileSystem,
        confidence_millionths: 950_000,
    },
    CapabilityPattern {
        pattern: "require('fs')",
        kind: InferredCapabilityKind::FileSystem,
        confidence_millionths: 950_000,
    },
    CapabilityPattern {
        pattern: "from \"fs\"",
        kind: InferredCapabilityKind::FileSystem,
        confidence_millionths: 950_000,
    },
    CapabilityPattern {
        pattern: "from 'fs'",
        kind: InferredCapabilityKind::FileSystem,
        confidence_millionths: 950_000,
    },
    CapabilityPattern {
        pattern: "require(\"fs/promises\")",
        kind: InferredCapabilityKind::FileSystem,
        confidence_millionths: 950_000,
    },
    CapabilityPattern {
        pattern: "require('fs/promises')",
        kind: InferredCapabilityKind::FileSystem,
        confidence_millionths: 950_000,
    },
    CapabilityPattern {
        pattern: "require(\"net\")",
        kind: InferredCapabilityKind::Network,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "require('net')",
        kind: InferredCapabilityKind::Network,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "require(\"http\")",
        kind: InferredCapabilityKind::Network,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "require('http')",
        kind: InferredCapabilityKind::Network,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "require(\"https\")",
        kind: InferredCapabilityKind::Network,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "require('https')",
        kind: InferredCapabilityKind::Network,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "from \"http\"",
        kind: InferredCapabilityKind::Network,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "from 'http'",
        kind: InferredCapabilityKind::Network,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "require(\"child_process\")",
        kind: InferredCapabilityKind::ChildProcess,
        confidence_millionths: 950_000,
    },
    CapabilityPattern {
        pattern: "require('child_process')",
        kind: InferredCapabilityKind::ChildProcess,
        confidence_millionths: 950_000,
    },
    CapabilityPattern {
        pattern: "from \"child_process\"",
        kind: InferredCapabilityKind::ChildProcess,
        confidence_millionths: 950_000,
    },
    CapabilityPattern {
        pattern: "from 'child_process'",
        kind: InferredCapabilityKind::ChildProcess,
        confidence_millionths: 950_000,
    },
    CapabilityPattern {
        pattern: "process.env",
        kind: InferredCapabilityKind::EnvironmentAccess,
        confidence_millionths: 850_000,
    },
    CapabilityPattern {
        pattern: "process.spawn",
        kind: InferredCapabilityKind::ProcessSpawn,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "require(\"crypto\")",
        kind: InferredCapabilityKind::CryptoAccess,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "require('crypto')",
        kind: InferredCapabilityKind::CryptoAccess,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "from \"crypto\"",
        kind: InferredCapabilityKind::CryptoAccess,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "from 'crypto'",
        kind: InferredCapabilityKind::CryptoAccess,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "setTimeout",
        kind: InferredCapabilityKind::TimerAccess,
        confidence_millionths: 800_000,
    },
    CapabilityPattern {
        pattern: "setInterval",
        kind: InferredCapabilityKind::TimerAccess,
        confidence_millionths: 800_000,
    },
    CapabilityPattern {
        pattern: "require(\"worker_threads\")",
        kind: InferredCapabilityKind::WorkerThreads,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "require('worker_threads')",
        kind: InferredCapabilityKind::WorkerThreads,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "new Worker",
        kind: InferredCapabilityKind::WorkerThreads,
        confidence_millionths: 700_000,
    },
    CapabilityPattern {
        pattern: "import(",
        kind: InferredCapabilityKind::DynamicImport,
        confidence_millionths: 800_000,
    },
    CapabilityPattern {
        pattern: "WebAssembly",
        kind: InferredCapabilityKind::WasmExecution,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: "SharedArrayBuffer",
        kind: InferredCapabilityKind::SharedMemory,
        confidence_millionths: 900_000,
    },
    CapabilityPattern {
        pattern: ".node\")",
        kind: InferredCapabilityKind::NativeAddon,
        confidence_millionths: 800_000,
    },
    CapabilityPattern {
        pattern: "node-gyp",
        kind: InferredCapabilityKind::NativeAddon,
        confidence_millionths: 850_000,
    },
    CapabilityPattern {
        pattern: "napi",
        kind: InferredCapabilityKind::NativeAddon,
        confidence_millionths: 850_000,
    },
];

// =========================================================================
// Known dependency compatibility
// =========================================================================

struct KnownDependency {
    name: &'static str,
    compatible: bool,
    notes: &'static str,
}

const KNOWN_DEPENDENCIES: &[KnownDependency] = &[
    KnownDependency {
        name: "express",
        compatible: false,
        notes: "requires http server; use franken-http adapter",
    },
    KnownDependency {
        name: "lodash",
        compatible: true,
        notes: "pure JS; fully compatible",
    },
    KnownDependency {
        name: "axios",
        compatible: false,
        notes: "requires cap:net; use franken-fetch",
    },
    KnownDependency {
        name: "moment",
        compatible: true,
        notes: "pure JS; consider date-fns",
    },
    KnownDependency {
        name: "date-fns",
        compatible: true,
        notes: "pure JS; fully compatible",
    },
    KnownDependency {
        name: "uuid",
        compatible: true,
        notes: "pure JS; deterministic PRNG mode available",
    },
    KnownDependency {
        name: "chalk",
        compatible: true,
        notes: "pure JS; ANSI output captured",
    },
    KnownDependency {
        name: "commander",
        compatible: true,
        notes: "pure JS; sandboxed argv",
    },
    KnownDependency {
        name: "yargs",
        compatible: true,
        notes: "pure JS; sandboxed argv",
    },
    KnownDependency {
        name: "sharp",
        compatible: false,
        notes: "native addon; not supported",
    },
    KnownDependency {
        name: "bcrypt",
        compatible: false,
        notes: "native addon; use bcryptjs",
    },
    KnownDependency {
        name: "sqlite3",
        compatible: false,
        notes: "native addon; use frankensqlite",
    },
    KnownDependency {
        name: "better-sqlite3",
        compatible: false,
        notes: "native addon; use frankensqlite",
    },
    KnownDependency {
        name: "ws",
        compatible: false,
        notes: "requires cap:net; use franken-ws",
    },
    KnownDependency {
        name: "dotenv",
        compatible: true,
        notes: "sandboxed env; cap:env required",
    },
    KnownDependency {
        name: "zod",
        compatible: true,
        notes: "pure JS; fully compatible",
    },
    KnownDependency {
        name: "typescript",
        compatible: true,
        notes: "dev dependency only",
    },
    KnownDependency {
        name: "jest",
        compatible: true,
        notes: "test runner; works in sandbox",
    },
    KnownDependency {
        name: "vitest",
        compatible: true,
        notes: "test runner; works in sandbox",
    },
    KnownDependency {
        name: "pg",
        compatible: false,
        notes: "requires cap:net; use franken-pg adapter",
    },
    KnownDependency {
        name: "redis",
        compatible: false,
        notes: "requires cap:net; use franken-kv",
    },
    KnownDependency {
        name: "mongoose",
        compatible: false,
        notes: "requires cap:net; not supported",
    },
];

fn lookup_dependency(name: &str) -> Option<&'static KnownDependency> {
    KNOWN_DEPENDENCIES.iter().find(|d| d.name == name)
}

// =========================================================================
// Core functions
// =========================================================================

pub fn analyze_package(
    package_json: &str,
    config: &MigrationConfig,
) -> Result<CompatibilityReport, MigrationKitError> {
    let parsed: serde_json::Value =
        serde_json::from_str(package_json).map_err(|e| MigrationKitError::InvalidPackageJson {
            detail: e.to_string(),
        })?;

    let mut api_entries = Vec::new();
    let mut dependency_entries = Vec::new();

    // Extract dependencies
    if config.analyze_dependencies {
        for dep_key in &["dependencies", "devDependencies", "peerDependencies"] {
            if let Some(deps) = parsed.get(dep_key).and_then(|v| v.as_object()) {
                for (name, version_val) in deps {
                    let version_spec = version_val.as_str().unwrap_or("*").to_string();
                    let (compatible, migration_notes) = match lookup_dependency(name) {
                        Some(known) => (known.compatible, known.notes.to_string()),
                        None => (
                            true,
                            "unknown dependency; manual review recommended".to_string(),
                        ),
                    };
                    dependency_entries.push(DependencyEntry {
                        name: name.clone(),
                        version_spec,
                        compatible,
                        migration_notes,
                    });
                }
            }
        }
    }

    if dependency_entries.len() > MAX_DEPENDENCY_ENTRIES {
        return Err(MigrationKitError::TooManyEntries {
            kind: "dependency".to_string(),
            count: dependency_entries.len(),
            max: MAX_DEPENDENCY_ENTRIES,
        });
    }

    // Extract main/module entry points to infer API usage
    let entry_fields = ["main", "module", "exports"];
    for field in &entry_fields {
        if let Some(val) = parsed.get(field).and_then(|v| v.as_str()) {
            let ext = if val.ends_with(".mjs") || val.ends_with(".ts") {
                "esm"
            } else {
                "cjs"
            };
            api_entries.push(ApiUsageEntry {
                api_name: format!("entry:{ext}"),
                module_path: val.to_string(),
                usage_count: 1,
                support_level: ApiSupportLevel::FullySupported,
                notes: format!("entry point via {field}"),
            });
        }
    }

    // Infer APIs from dependencies
    for dep in &dependency_entries {
        let module_support = lookup_module(&dep.name);
        if module_support != ApiSupportLevel::Unsupported {
            api_entries.push(ApiUsageEntry {
                api_name: dep.name.clone(),
                module_path: format!("node_modules/{}", dep.name),
                usage_count: 1,
                support_level: module_support,
                notes: dep.migration_notes.clone(),
            });
        }
    }

    // Check for Node built-in references in scripts
    if let Some(scripts) = parsed.get("scripts").and_then(|v| v.as_object()) {
        for (script_name, script_val) in scripts {
            if let Some(cmd) = script_val.as_str()
                && (cmd.contains("node ") || cmd.contains("npx "))
            {
                api_entries.push(ApiUsageEntry {
                    api_name: "runtime:node-cli".to_string(),
                    module_path: format!("scripts.{script_name}"),
                    usage_count: 1,
                    support_level: ApiSupportLevel::PartiallySupported,
                    notes: "CLI invocation needs franken-cli adapter".to_string(),
                });
            }
        }
    }

    if api_entries.len() > MAX_API_ENTRIES {
        return Err(MigrationKitError::TooManyEntries {
            kind: "api".to_string(),
            count: api_entries.len(),
            max: MAX_API_ENTRIES,
        });
    }

    // Compute counts and score
    let mut fully_supported_count: u64 = 0;
    let mut partially_supported_count: u64 = 0;
    let mut unsupported_count: u64 = 0;
    let mut deprecated_count: u64 = 0;
    let mut polyfill_required_count: u64 = 0;
    let mut weight_sum: u64 = 0;

    for entry in &api_entries {
        match entry.support_level {
            ApiSupportLevel::FullySupported => fully_supported_count += 1,
            ApiSupportLevel::PartiallySupported => partially_supported_count += 1,
            ApiSupportLevel::Unsupported => unsupported_count += 1,
            ApiSupportLevel::Deprecated => deprecated_count += 1,
            ApiSupportLevel::RequiresPolyfill => polyfill_required_count += 1,
        }
        weight_sum += entry.support_level.compatibility_weight_millionths();
    }

    let total_apis_used = api_entries.len() as u64;
    let compatibility_score_millionths =
        weight_sum.checked_div(total_apis_used).unwrap_or(1_000_000);

    // Sort for determinism
    api_entries.sort_by(|a, b| a.api_name.cmp(&b.api_name));
    dependency_entries.sort_by(|a, b| a.name.cmp(&b.name));

    let report_bytes = serde_json::to_vec(&(&api_entries, &dependency_entries)).unwrap_or_default();
    let report_content_hash = ContentHash::compute(&report_bytes);

    Ok(CompatibilityReport {
        source_runtime: config.source_runtime,
        total_apis_used,
        fully_supported_count,
        partially_supported_count,
        unsupported_count,
        deprecated_count,
        polyfill_required_count,
        compatibility_score_millionths,
        api_entries,
        dependency_entries,
        report_content_hash,
    })
}

pub fn infer_capabilities(
    source_files: &[SourceFile],
    _config: &MigrationConfig,
) -> Result<CapabilityInferenceResult, MigrationKitError> {
    if source_files.len() > MAX_SOURCE_FILES {
        return Err(MigrationKitError::TooManyEntries {
            kind: "source_file".to_string(),
            count: source_files.len(),
            max: MAX_SOURCE_FILES,
        });
    }

    let mut capability_evidence: BTreeMap<InferredCapabilityKind, Vec<(String, u64)>> =
        BTreeMap::new();

    for file in source_files {
        for pattern in CAPABILITY_PATTERNS {
            if file.content.contains(pattern.pattern) {
                capability_evidence
                    .entry(pattern.kind)
                    .or_default()
                    .push((file.path.clone(), pattern.confidence_millionths));
            }
        }
    }

    let mut inferred_capabilities = Vec::new();
    let mut minimum_capability_set = BTreeSet::new();
    let mut recommended_capability_set = BTreeSet::new();

    for kind in capability_evidence.keys() {
        let evidence = &capability_evidence[kind];
        let max_confidence = evidence.iter().map(|(_, c)| *c).max().unwrap_or(0);
        let evidence_sources: Vec<String> = evidence.iter().map(|(p, _)| p.clone()).collect();
        let cap_name = kind.franken_capability_name().to_string();

        inferred_capabilities.push(InferredCapability {
            kind: *kind,
            confidence_millionths: max_confidence,
            evidence_sources,
            franken_capability_name: cap_name.clone(),
        });

        if max_confidence >= 800_000 {
            minimum_capability_set.insert(cap_name.clone());
        }
        recommended_capability_set.insert(cap_name);
    }

    inferred_capabilities.sort_by_key(|c| std::cmp::Reverse(c.confidence_millionths));

    let cap_bytes =
        serde_json::to_vec(&(&inferred_capabilities, &minimum_capability_set)).unwrap_or_default();
    let capability_hash = ContentHash::compute(&cap_bytes);

    Ok(CapabilityInferenceResult {
        inferred_capabilities,
        minimum_capability_set,
        recommended_capability_set,
        capability_hash,
    })
}

pub fn validate_behavior(
    test_results: &[LockstepTestResult],
    config: &MigrationConfig,
) -> Result<BehaviorValidationReport, MigrationKitError> {
    if test_results.is_empty() {
        return Err(MigrationKitError::BehaviorValidationFailed {
            detail: "no test results provided".to_string(),
        });
    }

    let schema_id = SchemaId::from_definition(DIVERGENCE_SCHEMA_DEF);

    let mut divergences = Vec::new();
    let mut passing_count: u64 = 0;

    for (idx, result) in test_results.iter().enumerate() {
        let outputs_match = result.node_output == result.franken_output;
        let exit_codes_match = result.node_exit_code == result.franken_exit_code;

        if outputs_match && exit_codes_match {
            passing_count += 1;
            continue;
        }

        let (kind, severity, explanation, remediation) = if !exit_codes_match && !outputs_match {
            (
                DivergenceKind::SemanticDifference,
                DivergenceSeverity::Critical,
                format!(
                    "both output and exit code differ: node exit={} franken exit={}",
                    result.node_exit_code, result.franken_exit_code
                ),
                "review test logic for runtime-specific behavior".to_string(),
            )
        } else if !exit_codes_match {
            (
                DivergenceKind::ErrorBehaviorDifference,
                DivergenceSeverity::High,
                format!(
                    "exit code mismatch: node={} franken={}",
                    result.node_exit_code, result.franken_exit_code
                ),
                "check error handling paths for runtime differences".to_string(),
            )
        } else {
            let severity =
                classify_output_divergence_severity(&result.node_output, &result.franken_output);
            let kind = if result.node_duration_us > 0
                && result.franken_duration_us > 0
                && timing_divergence_significant(
                    result.node_duration_us,
                    result.franken_duration_us,
                ) {
                DivergenceKind::TimingDifference
            } else {
                DivergenceKind::OutputFormatDifference
            };
            (
                kind,
                severity,
                "output content differs between runtimes".to_string(),
                "normalize output format or adjust expectations".to_string(),
            )
        };

        let canonical_bytes = format!("divergence:{}:{}", config.deterministic_seed, idx);
        let divergence_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            MIGRATION_ZONE,
            &schema_id,
            canonical_bytes.as_bytes(),
        )
        .map_err(|e| MigrationKitError::InternalError {
            detail: format!("id derivation failed: {e}"),
        })?;

        divergences.push(BehaviorDivergence {
            divergence_id,
            kind,
            severity,
            test_case: result.test_name.clone(),
            node_bun_result: result.node_output.clone(),
            franken_result: result.franken_output.clone(),
            explanation,
            remediation,
        });
    }

    if divergences.len() > MAX_DIVERGENCES {
        return Err(MigrationKitError::TooManyEntries {
            kind: "divergence".to_string(),
            count: divergences.len(),
            max: MAX_DIVERGENCES,
        });
    }

    let total_test_cases = test_results.len() as u64;
    let divergence_count = divergences.len() as u64;

    let parity_score_millionths = if total_test_cases == 0 {
        0
    } else {
        passing_count
            .saturating_mul(1_000_000)
            .checked_div(total_test_cases)
            .unwrap_or(0)
    };

    divergences.sort_by_key(|d| d.severity);

    let report_bytes = serde_json::to_vec(&(&passing_count, &divergences)).unwrap_or_default();
    let report_content_hash = ContentHash::compute(&report_bytes);

    Ok(BehaviorValidationReport {
        total_test_cases,
        passing_count,
        divergence_count,
        parity_score_millionths,
        divergences,
        report_content_hash,
    })
}

fn classify_output_divergence_severity(
    node_output: &str,
    franken_output: &str,
) -> DivergenceSeverity {
    let node_trimmed = node_output.trim();
    let franken_trimmed = franken_output.trim();

    if node_trimmed == franken_trimmed {
        return DivergenceSeverity::Informational;
    }

    let node_lower = node_trimmed.to_lowercase();
    let franken_lower = franken_trimmed.to_lowercase();

    if node_lower == franken_lower {
        return DivergenceSeverity::Low;
    }

    // Check if one is a prefix of the other (trailing whitespace/newline difference)
    if node_lower.starts_with(&franken_lower) || franken_lower.starts_with(&node_lower) {
        return DivergenceSeverity::Low;
    }

    // Significant content difference
    let node_len = node_trimmed.len();
    let franken_len = franken_trimmed.len();
    let len_ratio = if node_len > franken_len {
        franken_len
            .saturating_mul(100)
            .checked_div(node_len)
            .unwrap_or(0)
    } else {
        node_len
            .saturating_mul(100)
            .checked_div(franken_len)
            .unwrap_or(0)
    };

    if len_ratio < 50 {
        DivergenceSeverity::High
    } else {
        DivergenceSeverity::Medium
    }
}

fn timing_divergence_significant(node_us: u64, franken_us: u64) -> bool {
    if node_us == 0 || franken_us == 0 {
        return false;
    }
    let ratio = if franken_us > node_us {
        franken_us.saturating_mul(100) / node_us
    } else {
        node_us.saturating_mul(100) / franken_us
    };
    ratio > 200 // >2x difference
}

pub fn generate_remediation(
    compatibility: &CompatibilityReport,
    behavior: &BehaviorValidationReport,
    _capabilities: &CapabilityInferenceResult,
) -> Result<Vec<RemediationStep>, MigrationKitError> {
    let schema_id = SchemaId::from_definition(REMEDIATION_SCHEMA_DEF);

    let mut steps = Vec::new();
    let mut step_idx: u64 = 0;

    // Remediation from unsupported APIs
    for entry in &compatibility.api_entries {
        if entry.support_level == ApiSupportLevel::Unsupported {
            let canonical = format!("remediation:api:{}:{step_idx}", entry.api_name);
            let step_id = engine_object_id::derive_id(
                ObjectDomain::EvidenceRecord,
                MIGRATION_ZONE,
                &schema_id,
                canonical.as_bytes(),
            )
            .map_err(|e| MigrationKitError::InternalError {
                detail: format!("id derivation failed: {e}"),
            })?;

            steps.push(RemediationStep {
                step_id,
                category: RemediationCategory::ApiReplacement,
                effort: RemediationEffort::Medium,
                title: format!("Replace unsupported API: {}", entry.api_name),
                description: format!(
                    "The API '{}' from module '{}' is not supported in FrankenEngine. {}",
                    entry.api_name, entry.module_path, entry.notes
                ),
                before_snippet: format!("require('{}')", entry.module_path),
                after_snippet: "// Use FrankenEngine equivalent API".to_string(),
                affected_files: vec![entry.module_path.clone()],
                priority_score_millionths: 900_000,
            });
            step_idx += 1;
        }
    }

    // Remediation from deprecated APIs
    for entry in &compatibility.api_entries {
        if entry.support_level == ApiSupportLevel::Deprecated {
            let canonical = format!("remediation:deprecated:{}:{step_idx}", entry.api_name);
            let step_id = engine_object_id::derive_id(
                ObjectDomain::EvidenceRecord,
                MIGRATION_ZONE,
                &schema_id,
                canonical.as_bytes(),
            )
            .map_err(|e| MigrationKitError::InternalError {
                detail: format!("id derivation failed: {e}"),
            })?;

            steps.push(RemediationStep {
                step_id,
                category: RemediationCategory::ApiReplacement,
                effort: RemediationEffort::Low,
                title: format!("Replace deprecated API: {}", entry.api_name),
                description: format!(
                    "The API '{}' is deprecated. {}",
                    entry.api_name, entry.notes
                ),
                before_snippet: format!("require('{}')", entry.module_path),
                after_snippet: "// Use recommended replacement".to_string(),
                affected_files: vec![entry.module_path.clone()],
                priority_score_millionths: 600_000,
            });
            step_idx += 1;
        }
    }

    // Remediation from incompatible dependencies
    for dep in &compatibility.dependency_entries {
        if !dep.compatible {
            let canonical = format!("remediation:dep:{}:{step_idx}", dep.name);
            let step_id = engine_object_id::derive_id(
                ObjectDomain::EvidenceRecord,
                MIGRATION_ZONE,
                &schema_id,
                canonical.as_bytes(),
            )
            .map_err(|e| MigrationKitError::InternalError {
                detail: format!("id derivation failed: {e}"),
            })?;

            steps.push(RemediationStep {
                step_id,
                category: RemediationCategory::DependencySwap,
                effort: RemediationEffort::High,
                title: format!("Replace incompatible dependency: {}", dep.name),
                description: format!(
                    "Dependency '{}' ({}) is not compatible. {}",
                    dep.name, dep.version_spec, dep.migration_notes
                ),
                before_snippet: format!("\"{}\": \"{}\"", dep.name, dep.version_spec),
                after_snippet: "// Use FrankenEngine-compatible alternative".to_string(),
                affected_files: vec!["package.json".to_string()],
                priority_score_millionths: 800_000,
            });
            step_idx += 1;
        }
    }

    // Remediation from behavior divergences
    for divergence in &behavior.divergences {
        if divergence.severity == DivergenceSeverity::Critical
            || divergence.severity == DivergenceSeverity::High
        {
            let canonical = format!("remediation:behavior:{}:{step_idx}", divergence.test_case);
            let step_id = engine_object_id::derive_id(
                ObjectDomain::EvidenceRecord,
                MIGRATION_ZONE,
                &schema_id,
                canonical.as_bytes(),
            )
            .map_err(|e| MigrationKitError::InternalError {
                detail: format!("id derivation failed: {e}"),
            })?;

            let effort = match divergence.severity {
                DivergenceSeverity::Critical => RemediationEffort::Significant,
                _ => RemediationEffort::Medium,
            };

            steps.push(RemediationStep {
                step_id,
                category: RemediationCategory::CodeRefactor,
                effort,
                title: format!("Fix behavior divergence: {}", divergence.test_case),
                description: format!(
                    "Test '{}' shows {:?} divergence. {}",
                    divergence.test_case, divergence.kind, divergence.explanation
                ),
                before_snippet: divergence.node_bun_result.clone(),
                after_snippet: divergence.franken_result.clone(),
                affected_files: vec![divergence.test_case.clone()],
                priority_score_millionths: divergence
                    .severity
                    .penalty_millionths()
                    .saturating_mul(5),
            });
            step_idx += 1;
        }
    }

    // Sort by priority descending
    steps.sort_by_key(|s| std::cmp::Reverse(s.priority_score_millionths));

    if steps.len() > MAX_REMEDIATION_STEPS {
        steps.truncate(MAX_REMEDIATION_STEPS);
    }

    Ok(steps)
}

pub fn generate_manifest(
    input: ManifestGenerationInput,
) -> Result<MigrationManifest, MigrationKitError> {
    if input.source_package_name.is_empty() {
        return Err(MigrationKitError::ManifestGenerationFailed {
            detail: "source_package_name is empty".to_string(),
        });
    }

    let schema_id = SchemaId::from_definition(MANIFEST_SCHEMA_DEF);

    let franken_extension_name = input
        .source_package_name
        .replace('/', "__")
        .replace('@', "");

    let readiness = compute_migration_readiness(&input.compatibility, &input.behavior);

    let canonical_bytes = format!(
        "manifest:{}:{}:{}",
        input.source_package_name,
        input.source_version,
        input.epoch.as_u64()
    );

    let manifest_id = engine_object_id::derive_id(
        ObjectDomain::SignedManifest,
        MIGRATION_ZONE,
        &schema_id,
        canonical_bytes.as_bytes(),
    )
    .map_err(|e| MigrationKitError::InternalError {
        detail: format!("id derivation failed: {e}"),
    })?;

    let manifest_bytes = serde_json::to_vec(&(
        format!("{:?}", input.source_runtime),
        &input.source_package_name,
        &input.source_version,
        &franken_extension_name,
        "0.1.0", // franken_extension_version
        &input.capabilities.minimum_capability_set,
        &input.entry_point,
        input.compatibility.compatibility_score_millionths,
        input.behavior.parity_score_millionths,
        readiness,
        input.epoch.as_u64(),
    ))
    .expect("migration manifest must serialize for content hash");
    let manifest_content_hash = ContentHash::compute(&manifest_bytes);

    Ok(MigrationManifest {
        manifest_id,
        source_runtime: input.source_runtime,
        source_package_name: input.source_package_name,
        source_version: input.source_version,
        franken_extension_name,
        franken_extension_version: "0.1.0".to_string(),
        required_capabilities: input.capabilities.minimum_capability_set,
        entry_point: input.entry_point,
        compatibility_score_millionths: input.compatibility.compatibility_score_millionths,
        parity_score_millionths: input.behavior.parity_score_millionths,
        remediation_count: 0,
        migration_readiness_score_millionths: readiness,
        manifest_content_hash,
        created_epoch: input.epoch,
    })
}

pub fn compute_migration_readiness(
    compatibility: &CompatibilityReport,
    behavior: &BehaviorValidationReport,
) -> u64 {
    // Weighted average: 40% compatibility, 60% behavior parity
    let compat_weighted = compatibility
        .compatibility_score_millionths
        .saturating_mul(400_000)
        / 1_000_000;
    let parity_weighted = behavior.parity_score_millionths.saturating_mul(600_000) / 1_000_000;

    // Penalty for critical divergences
    let critical_count = behavior
        .divergences
        .iter()
        .filter(|d| d.severity == DivergenceSeverity::Critical)
        .count() as u64;
    let penalty = critical_count.saturating_mul(100_000);

    compat_weighted
        .saturating_add(parity_weighted)
        .saturating_sub(penalty)
}

pub fn emit_migration_event(event: &MigrationEvent) -> String {
    serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string())
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_package_json() -> String {
        r#"{
            "name": "test-extension",
            "version": "1.0.0",
            "main": "index.js",
            "dependencies": {
                "lodash": "^4.17.21"
            }
        }"#
        .to_string()
    }

    fn complex_package_json() -> String {
        r#"{
            "name": "@myorg/complex-ext",
            "version": "2.3.1",
            "main": "dist/index.js",
            "module": "dist/index.mjs",
            "dependencies": {
                "lodash": "^4.17.21",
                "express": "^4.18.0",
                "axios": "^1.5.0",
                "zod": "^3.22.0",
                "sharp": "^0.33.0",
                "uuid": "^9.0.0"
            },
            "devDependencies": {
                "typescript": "^5.3.0",
                "jest": "^29.7.0"
            },
            "scripts": {
                "build": "tsc",
                "start": "node dist/index.js",
                "test": "jest"
            }
        }"#
        .to_string()
    }

    fn default_config() -> MigrationConfig {
        MigrationConfig::default()
    }

    fn make_source_file(path: &str, content: &str) -> SourceFile {
        SourceFile {
            path: path.to_string(),
            content: content.to_string(),
        }
    }

    fn make_test_result(name: &str, node_out: &str, franken_out: &str) -> LockstepTestResult {
        LockstepTestResult {
            test_name: name.to_string(),
            node_output: node_out.to_string(),
            franken_output: franken_out.to_string(),
            node_exit_code: 0,
            franken_exit_code: 0,
            node_duration_us: 1000,
            franken_duration_us: 1200,
        }
    }

    // ---- Package analysis tests ----

    #[test]
    fn test_analyze_minimal_package() {
        let report = analyze_package(&minimal_package_json(), &default_config()).unwrap();
        assert_eq!(report.source_runtime, SourceRuntime::Node);
        assert!(report.total_apis_used > 0);
        assert!(report.compatibility_score_millionths > 0);
    }

    #[test]
    fn test_analyze_complex_package() {
        let report = analyze_package(&complex_package_json(), &default_config()).unwrap();
        assert!(report.dependency_entries.len() >= 6);
        let incompatible: Vec<_> = report
            .dependency_entries
            .iter()
            .filter(|d| !d.compatible)
            .collect();
        assert!(!incompatible.is_empty());
    }

    #[test]
    fn test_analyze_empty_package() {
        let report = analyze_package("{}", &default_config()).unwrap();
        assert_eq!(report.total_apis_used, 0);
        assert_eq!(report.compatibility_score_millionths, 1_000_000);
    }

    #[test]
    fn test_analyze_invalid_json() {
        let err = analyze_package("not json", &default_config()).unwrap_err();
        assert_eq!(err.code(), "FE-MK-0006");
    }

    #[test]
    fn test_analyze_malformed_package() {
        let err = analyze_package("{invalid", &default_config()).unwrap_err();
        assert!(matches!(err, MigrationKitError::InvalidPackageJson { .. }));
    }

    #[test]
    fn test_analyze_no_dependencies() {
        let json = r#"{"name": "bare", "version": "0.0.1"}"#;
        let report = analyze_package(json, &default_config()).unwrap();
        assert!(report.dependency_entries.is_empty());
    }

    #[test]
    fn test_analyze_dependencies_disabled() {
        let config = MigrationConfig {
            analyze_dependencies: false,
            ..default_config()
        };
        let report = analyze_package(&complex_package_json(), &config).unwrap();
        assert!(report.dependency_entries.is_empty());
    }

    #[test]
    fn test_analyze_esm_entry_point() {
        let json = r#"{"name": "esm-pkg", "version": "1.0.0", "module": "dist/index.mjs"}"#;
        let report = analyze_package(json, &default_config()).unwrap();
        let esm_entries: Vec<_> = report
            .api_entries
            .iter()
            .filter(|e| e.api_name == "entry:esm")
            .collect();
        assert_eq!(esm_entries.len(), 1);
    }

    #[test]
    fn test_analyze_scripts_with_node_cli() {
        let json =
            r#"{"name": "cli-pkg", "version": "1.0.0", "scripts": {"start": "node server.js"}}"#;
        let report = analyze_package(json, &default_config()).unwrap();
        let cli_entries: Vec<_> = report
            .api_entries
            .iter()
            .filter(|e| e.api_name == "runtime:node-cli")
            .collect();
        assert_eq!(cli_entries.len(), 1);
    }

    #[test]
    fn test_analyze_known_incompatible_dependency() {
        let json = r#"{"name": "x", "version": "1.0.0", "dependencies": {"sharp": "^0.33.0"}}"#;
        let report = analyze_package(json, &default_config()).unwrap();
        let sharp = report
            .dependency_entries
            .iter()
            .find(|d| d.name == "sharp")
            .unwrap();
        assert!(!sharp.compatible);
    }

    #[test]
    fn test_analyze_unknown_dependency() {
        let json =
            r#"{"name": "x", "version": "1.0.0", "dependencies": {"my-custom-lib": "^1.0.0"}}"#;
        let report = analyze_package(json, &default_config()).unwrap();
        let custom = report
            .dependency_entries
            .iter()
            .find(|d| d.name == "my-custom-lib")
            .unwrap();
        assert!(custom.compatible);
        assert!(custom.migration_notes.contains("manual review"));
    }

    #[test]
    fn test_analyze_deterministic() {
        let report1 = analyze_package(&complex_package_json(), &default_config()).unwrap();
        let report2 = analyze_package(&complex_package_json(), &default_config()).unwrap();
        assert_eq!(report1.report_content_hash, report2.report_content_hash);
        assert_eq!(
            report1.compatibility_score_millionths,
            report2.compatibility_score_millionths
        );
    }

    // ---- Capability inference tests ----

    #[test]
    fn test_infer_fs_capability() {
        let files = vec![make_source_file(
            "index.js",
            "const fs = require('fs');\nfs.readFile('test.txt');",
        )];
        let result = infer_capabilities(&files, &default_config()).unwrap();
        assert!(result.minimum_capability_set.contains("cap:fs"));
    }

    #[test]
    fn test_infer_network_capability() {
        let files = vec![make_source_file(
            "server.js",
            "const http = require('http');\nhttp.createServer();",
        )];
        let result = infer_capabilities(&files, &default_config()).unwrap();
        assert!(result.minimum_capability_set.contains("cap:net"));
    }

    #[test]
    fn test_infer_crypto_capability() {
        let files = vec![make_source_file(
            "auth.js",
            "const crypto = require('crypto');\ncrypto.createHash('sha256');",
        )];
        let result = infer_capabilities(&files, &default_config()).unwrap();
        assert!(result.minimum_capability_set.contains("cap:crypto"));
    }

    #[test]
    fn test_infer_child_process_capability() {
        let files = vec![make_source_file(
            "runner.js",
            "const { exec } = require('child_process');",
        )];
        let result = infer_capabilities(&files, &default_config()).unwrap();
        assert!(result.minimum_capability_set.contains("cap:process:child"));
    }

    #[test]
    fn test_infer_env_capability() {
        let files = vec![make_source_file(
            "config.js",
            "const port = process.env.PORT || 3000;",
        )];
        let result = infer_capabilities(&files, &default_config()).unwrap();
        assert!(result.minimum_capability_set.contains("cap:env"));
    }

    #[test]
    fn test_infer_no_capabilities_from_empty() {
        let files = vec![make_source_file("empty.js", "// empty file")];
        let result = infer_capabilities(&files, &default_config()).unwrap();
        assert!(result.minimum_capability_set.is_empty());
    }

    #[test]
    fn test_infer_multiple_capabilities() {
        let files = vec![make_source_file(
            "app.js",
            r#"
            const fs = require('fs');
            const http = require('http');
            const crypto = require('crypto');
            const port = process.env.PORT;
            "#,
        )];
        let result = infer_capabilities(&files, &default_config()).unwrap();
        assert!(result.minimum_capability_set.len() >= 4);
    }

    #[test]
    fn test_infer_from_multiple_files() {
        let files = vec![
            make_source_file("a.js", "const fs = require('fs');"),
            make_source_file("b.js", "const http = require('http');"),
        ];
        let result = infer_capabilities(&files, &default_config()).unwrap();
        assert!(result.minimum_capability_set.contains("cap:fs"));
        assert!(result.minimum_capability_set.contains("cap:net"));
    }

    #[test]
    fn test_infer_wasm_capability() {
        let files = vec![make_source_file(
            "wasm.js",
            "const instance = await WebAssembly.instantiate(buffer);",
        )];
        let result = infer_capabilities(&files, &default_config()).unwrap();
        assert!(result.minimum_capability_set.contains("cap:wasm"));
    }

    #[test]
    fn test_infer_shared_memory() {
        let files = vec![make_source_file(
            "worker.js",
            "const sab = new SharedArrayBuffer(1024);",
        )];
        let result = infer_capabilities(&files, &default_config()).unwrap();
        assert!(result.minimum_capability_set.contains("cap:shared-memory"));
    }

    #[test]
    fn test_infer_deterministic() {
        let files = vec![make_source_file("a.js", "const fs = require('fs');")];
        let r1 = infer_capabilities(&files, &default_config()).unwrap();
        let r2 = infer_capabilities(&files, &default_config()).unwrap();
        assert_eq!(r1.capability_hash, r2.capability_hash);
    }

    // ---- Behavior validation tests ----

    #[test]
    fn test_validate_all_passing() {
        let results = vec![
            make_test_result("test1", "ok", "ok"),
            make_test_result("test2", "42", "42"),
        ];
        let report = validate_behavior(&results, &default_config()).unwrap();
        assert_eq!(report.passing_count, 2);
        assert_eq!(report.divergence_count, 0);
        assert_eq!(report.parity_score_millionths, 1_000_000);
    }

    #[test]
    fn test_validate_with_divergence() {
        let results = vec![
            make_test_result("test1", "ok", "ok"),
            make_test_result("test2", "expected", "different"),
        ];
        let report = validate_behavior(&results, &default_config()).unwrap();
        assert_eq!(report.passing_count, 1);
        assert_eq!(report.divergence_count, 1);
        assert_eq!(report.parity_score_millionths, 500_000);
    }

    #[test]
    fn test_validate_exit_code_mismatch() {
        let results = vec![LockstepTestResult {
            test_name: "exit-test".to_string(),
            node_output: "ok".to_string(),
            franken_output: "ok".to_string(),
            node_exit_code: 0,
            franken_exit_code: 1,
            node_duration_us: 100,
            franken_duration_us: 100,
        }];
        let report = validate_behavior(&results, &default_config()).unwrap();
        assert_eq!(report.divergence_count, 1);
        assert_eq!(
            report.divergences[0].kind,
            DivergenceKind::ErrorBehaviorDifference
        );
    }

    #[test]
    fn test_validate_both_mismatch() {
        let results = vec![LockstepTestResult {
            test_name: "both-diff".to_string(),
            node_output: "result-a".to_string(),
            franken_output: "result-b".to_string(),
            node_exit_code: 0,
            franken_exit_code: 1,
            node_duration_us: 100,
            franken_duration_us: 100,
        }];
        let report = validate_behavior(&results, &default_config()).unwrap();
        assert_eq!(report.divergences[0].severity, DivergenceSeverity::Critical);
    }

    #[test]
    fn test_validate_empty_results() {
        let err = validate_behavior(&[], &default_config()).unwrap_err();
        assert_eq!(err.code(), "FE-MK-0004");
    }

    #[test]
    fn test_validate_all_divergent() {
        let results = vec![
            make_test_result("t1", "a", "b"),
            make_test_result("t2", "c", "d"),
            make_test_result("t3", "e", "f"),
        ];
        let report = validate_behavior(&results, &default_config()).unwrap();
        assert_eq!(report.passing_count, 0);
        assert_eq!(report.divergence_count, 3);
        assert_eq!(report.parity_score_millionths, 0);
    }

    #[test]
    fn test_validate_deterministic() {
        let results = vec![
            make_test_result("t1", "ok", "ok"),
            make_test_result("t2", "a", "b"),
        ];
        let r1 = validate_behavior(&results, &default_config()).unwrap();
        let r2 = validate_behavior(&results, &default_config()).unwrap();
        assert_eq!(r1.report_content_hash, r2.report_content_hash);
    }

    // ---- Remediation tests ----

    #[test]
    fn test_remediation_from_unsupported_apis() {
        let compat = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 1,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 1,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 0,
            api_entries: vec![ApiUsageEntry {
                api_name: "child_process.exec".to_string(),
                module_path: "child_process".to_string(),
                usage_count: 1,
                support_level: ApiSupportLevel::Unsupported,
                notes: "no shell access".to_string(),
            }],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 0,
            passing_count: 0,
            divergence_count: 0,
            parity_score_millionths: 0,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"test"),
        };

        let steps = generate_remediation(&compat, &behavior, &caps).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].category, RemediationCategory::ApiReplacement);
    }

    #[test]
    fn test_remediation_from_incompatible_deps() {
        let compat = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 0,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![DependencyEntry {
                name: "sharp".to_string(),
                version_spec: "^0.33.0".to_string(),
                compatible: false,
                migration_notes: "native addon".to_string(),
            }],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 0,
            passing_count: 0,
            divergence_count: 0,
            parity_score_millionths: 0,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"test"),
        };

        let steps = generate_remediation(&compat, &behavior, &caps).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].category, RemediationCategory::DependencySwap);
    }

    #[test]
    fn test_remediation_empty_reports() {
        let compat = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 0,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 0,
            passing_count: 0,
            divergence_count: 0,
            parity_score_millionths: 0,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"test"),
        };

        let steps = generate_remediation(&compat, &behavior, &caps).unwrap();
        assert!(steps.is_empty());
    }

    // ---- Manifest generation tests ----

    #[test]
    fn test_generate_manifest() {
        let compat = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 2,
            fully_supported_count: 2,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 10,
            passing_count: 10,
            divergence_count: 0,
            parity_score_millionths: 1_000_000,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::from(["cap:fs".to_string()]),
            recommended_capability_set: BTreeSet::from(["cap:fs".to_string()]),
            capability_hash: ContentHash::compute(b"test"),
        };

        let manifest = generate_manifest(ManifestGenerationInput {
            source_runtime: SourceRuntime::Node,
            source_package_name: "my-extension".to_string(),
            source_version: "1.0.0".to_string(),
            entry_point: "index.js".to_string(),
            compatibility: compat,
            behavior,
            capabilities: caps,
            epoch: SecurityEpoch::from_raw(1),
        })
        .unwrap();

        assert_eq!(manifest.source_package_name, "my-extension");
        assert_eq!(manifest.franken_extension_name, "my-extension");
        assert!(manifest.required_capabilities.contains("cap:fs"));
        assert_eq!(manifest.migration_readiness_score_millionths, 1_000_000);
    }

    #[test]
    fn test_generate_manifest_scoped_package() {
        let compat = CompatibilityReport {
            source_runtime: SourceRuntime::Bun,
            total_apis_used: 0,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 1,
            passing_count: 1,
            divergence_count: 0,
            parity_score_millionths: 1_000_000,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"test"),
        };

        let manifest = generate_manifest(ManifestGenerationInput {
            source_runtime: SourceRuntime::Bun,
            source_package_name: "@myorg/my-pkg".to_string(),
            source_version: "2.0.0".to_string(),
            entry_point: "src/index.ts".to_string(),
            compatibility: compat,
            behavior,
            capabilities: caps,
            epoch: SecurityEpoch::from_raw(5),
        })
        .unwrap();

        assert_eq!(manifest.franken_extension_name, "myorg__my-pkg");
        assert_eq!(manifest.source_runtime, SourceRuntime::Bun);
    }

    #[test]
    fn test_generate_manifest_empty_name() {
        let compat = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 0,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 1,
            passing_count: 1,
            divergence_count: 0,
            parity_score_millionths: 1_000_000,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"test"),
        };

        let err = generate_manifest(ManifestGenerationInput {
            source_runtime: SourceRuntime::Node,
            source_package_name: String::new(),
            source_version: "1.0.0".to_string(),
            entry_point: "index.js".to_string(),
            compatibility: compat,
            behavior,
            capabilities: caps,
            epoch: SecurityEpoch::from_raw(1),
        })
        .unwrap_err();

        assert_eq!(err.code(), "FE-MK-0002");
    }

    // ---- Readiness score tests ----

    #[test]
    fn test_readiness_perfect() {
        let compat = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 5,
            fully_supported_count: 5,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 10,
            passing_count: 10,
            divergence_count: 0,
            parity_score_millionths: 1_000_000,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        assert_eq!(compute_migration_readiness(&compat, &behavior), 1_000_000);
    }

    #[test]
    fn test_readiness_zero_compatibility() {
        let compat = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 5,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 5,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 0,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 10,
            passing_count: 10,
            divergence_count: 0,
            parity_score_millionths: 1_000_000,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let score = compute_migration_readiness(&compat, &behavior);
        assert_eq!(score, 600_000);
    }

    #[test]
    fn test_readiness_with_critical_penalty() {
        let schema_id = SchemaId::from_definition(DIVERGENCE_SCHEMA_DEF);
        let div_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            MIGRATION_ZONE,
            &schema_id,
            b"test-div",
        )
        .unwrap();

        let compat = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 1,
            fully_supported_count: 1,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 10,
            passing_count: 9,
            divergence_count: 1,
            parity_score_millionths: 900_000,
            divergences: vec![BehaviorDivergence {
                divergence_id: div_id,
                kind: DivergenceKind::SemanticDifference,
                severity: DivergenceSeverity::Critical,
                test_case: "critical-test".to_string(),
                node_bun_result: "a".to_string(),
                franken_result: "b".to_string(),
                explanation: "test".to_string(),
                remediation: "fix".to_string(),
            }],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let score = compute_migration_readiness(&compat, &behavior);
        // 400_000 (40% of 1M) + 540_000 (60% of 900k) - 100_000 (1 critical) = 840_000
        assert_eq!(score, 840_000);
    }

    // ---- Event emission tests ----

    #[test]
    fn test_emit_event() {
        let event = MigrationEvent {
            trace_id: "tr-001".to_string(),
            decision_id: "d-001".to_string(),
            component: COMPONENT.to_string(),
            event: "analysis_started".to_string(),
            outcome: "success".to_string(),
            error_code: None,
            details: BTreeMap::new(),
        };
        let json = emit_migration_event(&event);
        assert!(json.contains("tr-001"));
        assert!(json.contains("analysis_started"));
    }

    #[test]
    fn test_emit_event_with_error() {
        let event = MigrationEvent {
            trace_id: "tr-002".to_string(),
            decision_id: "d-002".to_string(),
            component: COMPONENT.to_string(),
            event: "analysis_failed".to_string(),
            outcome: "failure".to_string(),
            error_code: Some("FE-MK-0001".to_string()),
            details: BTreeMap::from([("reason".to_string(), "parse error".to_string())]),
        };
        let json = emit_migration_event(&event);
        assert!(json.contains("FE-MK-0001"));
    }

    // ---- API support level tests ----

    #[test]
    fn test_api_support_level_blocker() {
        assert!(ApiSupportLevel::Unsupported.is_migration_blocker());
        assert!(!ApiSupportLevel::FullySupported.is_migration_blocker());
        assert!(!ApiSupportLevel::PartiallySupported.is_migration_blocker());
    }

    #[test]
    fn test_api_support_weights() {
        assert_eq!(
            ApiSupportLevel::FullySupported.compatibility_weight_millionths(),
            1_000_000
        );
        assert_eq!(
            ApiSupportLevel::Unsupported.compatibility_weight_millionths(),
            0
        );
    }

    // ---- Error code stability tests ----

    #[test]
    fn test_error_codes_unique() {
        let errors = vec![
            MigrationKitError::AnalysisFailed {
                detail: String::new(),
            },
            MigrationKitError::ManifestGenerationFailed {
                detail: String::new(),
            },
            MigrationKitError::CapabilityInferenceFailed {
                detail: String::new(),
            },
            MigrationKitError::BehaviorValidationFailed {
                detail: String::new(),
            },
            MigrationKitError::RemediationUnavailable {
                detail: String::new(),
            },
            MigrationKitError::InvalidPackageJson {
                detail: String::new(),
            },
            MigrationKitError::UnsupportedApiDetected {
                api: String::new(),
                detail: String::new(),
            },
            MigrationKitError::IncompatibleDependency {
                name: String::new(),
                reason: String::new(),
            },
            MigrationKitError::LockstepMismatch {
                runtime: String::new(),
                detail: String::new(),
            },
            MigrationKitError::ReportGenerationFailed {
                detail: String::new(),
            },
            MigrationKitError::DeterminismViolation {
                detail: String::new(),
            },
            MigrationKitError::TooManyEntries {
                kind: String::new(),
                count: 0,
                max: 0,
            },
            MigrationKitError::InternalError {
                detail: String::new(),
            },
        ];
        let mut codes: BTreeSet<&str> = BTreeSet::new();
        for err in &errors {
            assert!(codes.insert(err.code()), "duplicate code: {}", err.code());
        }
        assert_eq!(codes.len(), errors.len());
    }

    #[test]
    fn test_error_display() {
        let err = MigrationKitError::InvalidPackageJson {
            detail: "unexpected EOF".to_string(),
        };
        assert_eq!(err.to_string(), "invalid package.json: unexpected EOF");
    }

    // ---- Known API database tests ----

    #[test]
    fn test_lookup_known_api() {
        let api = lookup_api("fs", "readFile").unwrap();
        assert_eq!(api.support_level, ApiSupportLevel::FullySupported);
    }

    #[test]
    fn test_lookup_unknown_api() {
        assert!(lookup_api("nonexistent", "foo").is_none());
    }

    #[test]
    fn test_lookup_module_support() {
        assert_eq!(lookup_module("fs"), ApiSupportLevel::FullySupported);
        assert_eq!(lookup_module("child_process"), ApiSupportLevel::Unsupported);
        assert_eq!(lookup_module("nonexistent"), ApiSupportLevel::Unsupported);
    }

    // ---- Serde roundtrip tests ----

    #[test]
    fn test_serde_roundtrip_config() {
        let config = MigrationConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let roundtripped: MigrationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, roundtripped);
    }

    #[test]
    fn test_serde_roundtrip_error() {
        let err = MigrationKitError::AnalysisFailed {
            detail: "test error".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let roundtripped: MigrationKitError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, roundtripped);
    }

    #[test]
    fn test_serde_roundtrip_compatibility_report() {
        let report = analyze_package(&minimal_package_json(), &default_config()).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let roundtripped: CompatibilityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, roundtripped);
    }

    // ---- Divergence severity tests ----

    #[test]
    fn test_divergence_severity_penalty() {
        assert_eq!(DivergenceSeverity::Critical.penalty_millionths(), 200_000);
        assert_eq!(DivergenceSeverity::Informational.penalty_millionths(), 0);
    }

    #[test]
    fn test_classify_output_whitespace_only() {
        let sev = classify_output_divergence_severity("hello  ", "hello");
        assert_eq!(sev, DivergenceSeverity::Informational);
    }

    #[test]
    fn test_classify_output_case_difference() {
        let sev = classify_output_divergence_severity("Hello World", "hello world");
        assert_eq!(sev, DivergenceSeverity::Low);
    }

    #[test]
    fn test_classify_output_significant_difference() {
        let sev = classify_output_divergence_severity(
            "this is a very long output string that is totally different",
            "x",
        );
        assert_eq!(sev, DivergenceSeverity::High);
    }

    // ---- Source runtime display ----

    #[test]
    fn test_source_runtime_display() {
        assert_eq!(format!("{}", SourceRuntime::Node), "Node.js");
        assert_eq!(format!("{}", SourceRuntime::Bun), "Bun");
    }

    // ---- Capability kind names ----

    #[test]
    fn test_capability_kind_names() {
        assert_eq!(
            InferredCapabilityKind::FileSystem.franken_capability_name(),
            "cap:fs"
        );
        assert_eq!(
            InferredCapabilityKind::Network.franken_capability_name(),
            "cap:net"
        );
        assert_eq!(
            InferredCapabilityKind::NativeAddon.franken_capability_name(),
            "cap:native-addon"
        );
    }

    // ---- Timing divergence ----

    #[test]
    fn test_timing_divergence_significant() {
        assert!(timing_divergence_significant(100, 300));
        assert!(!timing_divergence_significant(100, 150));
        assert!(!timing_divergence_significant(0, 100));
    }

    // ---- Remediation effort ----

    #[test]
    fn test_remediation_effort_weights() {
        assert!(
            RemediationEffort::Trivial.weight_millionths()
                < RemediationEffort::Significant.weight_millionths()
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: leaf enum serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn source_runtime_serde_roundtrip() {
        for rt in [SourceRuntime::Node, SourceRuntime::Bun] {
            let json = serde_json::to_string(&rt).unwrap();
            let restored: SourceRuntime = serde_json::from_str(&json).unwrap();
            assert_eq!(rt, restored);
        }
    }

    #[test]
    fn api_support_level_serde_roundtrip() {
        for level in [
            ApiSupportLevel::FullySupported,
            ApiSupportLevel::PartiallySupported,
            ApiSupportLevel::Unsupported,
            ApiSupportLevel::Deprecated,
            ApiSupportLevel::RequiresPolyfill,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let restored: ApiSupportLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, restored);
        }
    }

    #[test]
    fn divergence_kind_serde_roundtrip() {
        for kind in [
            DivergenceKind::SemanticDifference,
            DivergenceKind::TimingDifference,
            DivergenceKind::OutputFormatDifference,
            DivergenceKind::ErrorBehaviorDifference,
            DivergenceKind::MissingFeature,
            DivergenceKind::SecurityPolicyDifference,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let restored: DivergenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn divergence_severity_serde_roundtrip() {
        for sev in [
            DivergenceSeverity::Critical,
            DivergenceSeverity::High,
            DivergenceSeverity::Medium,
            DivergenceSeverity::Low,
            DivergenceSeverity::Informational,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let restored: DivergenceSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, restored);
        }
    }

    #[test]
    fn inferred_capability_kind_serde_roundtrip() {
        for kind in [
            InferredCapabilityKind::FileSystem,
            InferredCapabilityKind::Network,
            InferredCapabilityKind::ProcessSpawn,
            InferredCapabilityKind::EnvironmentAccess,
            InferredCapabilityKind::CryptoAccess,
            InferredCapabilityKind::TimerAccess,
            InferredCapabilityKind::WorkerThreads,
            InferredCapabilityKind::ChildProcess,
            InferredCapabilityKind::DynamicImport,
            InferredCapabilityKind::WasmExecution,
            InferredCapabilityKind::SharedMemory,
            InferredCapabilityKind::NativeAddon,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let restored: InferredCapabilityKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn remediation_category_serde_roundtrip() {
        for cat in [
            RemediationCategory::ApiReplacement,
            RemediationCategory::DependencySwap,
            RemediationCategory::ConfigChange,
            RemediationCategory::CodeRefactor,
            RemediationCategory::PolyfillAddition,
            RemediationCategory::SecurityPolicyUpdate,
            RemediationCategory::FeatureDisable,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let restored: RemediationCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, restored);
        }
    }

    #[test]
    fn remediation_effort_serde_roundtrip() {
        for effort in [
            RemediationEffort::Trivial,
            RemediationEffort::Low,
            RemediationEffort::Medium,
            RemediationEffort::High,
            RemediationEffort::Significant,
        ] {
            let json = serde_json::to_string(&effort).unwrap();
            let restored: RemediationEffort = serde_json::from_str(&json).unwrap();
            assert_eq!(effort, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: MigrationKitError serde all variants
    // -----------------------------------------------------------------------

    #[test]
    fn migration_kit_error_serde_all_variants() {
        let errors: Vec<MigrationKitError> = vec![
            MigrationKitError::AnalysisFailed { detail: "a".into() },
            MigrationKitError::ManifestGenerationFailed { detail: "b".into() },
            MigrationKitError::CapabilityInferenceFailed { detail: "c".into() },
            MigrationKitError::BehaviorValidationFailed { detail: "d".into() },
            MigrationKitError::RemediationUnavailable { detail: "e".into() },
            MigrationKitError::InvalidPackageJson { detail: "f".into() },
            MigrationKitError::UnsupportedApiDetected {
                api: "g".into(),
                detail: "h".into(),
            },
            MigrationKitError::IncompatibleDependency {
                name: "i".into(),
                reason: "j".into(),
            },
            MigrationKitError::LockstepMismatch {
                runtime: "k".into(),
                detail: "l".into(),
            },
            MigrationKitError::ReportGenerationFailed { detail: "m".into() },
            MigrationKitError::DeterminismViolation { detail: "n".into() },
            MigrationKitError::TooManyEntries {
                kind: "o".into(),
                count: 99,
                max: 50,
            },
            MigrationKitError::InternalError { detail: "p".into() },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: MigrationKitError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: MigrationKitError Display all variants
    // -----------------------------------------------------------------------

    #[test]
    fn migration_kit_error_display_all_variants() {
        let cases: Vec<(MigrationKitError, &str)> = vec![
            (
                MigrationKitError::AnalysisFailed { detail: "x".into() },
                "analysis failed: x",
            ),
            (
                MigrationKitError::ManifestGenerationFailed { detail: "x".into() },
                "manifest generation failed: x",
            ),
            (
                MigrationKitError::CapabilityInferenceFailed { detail: "x".into() },
                "capability inference failed: x",
            ),
            (
                MigrationKitError::BehaviorValidationFailed { detail: "x".into() },
                "behavior validation failed: x",
            ),
            (
                MigrationKitError::RemediationUnavailable { detail: "x".into() },
                "remediation unavailable: x",
            ),
            (
                MigrationKitError::InvalidPackageJson { detail: "x".into() },
                "invalid package.json: x",
            ),
            (
                MigrationKitError::UnsupportedApiDetected {
                    api: "a".into(),
                    detail: "d".into(),
                },
                "unsupported API 'a': d",
            ),
            (
                MigrationKitError::IncompatibleDependency {
                    name: "n".into(),
                    reason: "r".into(),
                },
                "incompatible dependency 'n': r",
            ),
            (
                MigrationKitError::LockstepMismatch {
                    runtime: "Bun".into(),
                    detail: "x".into(),
                },
                "lockstep mismatch for Bun: x",
            ),
            (
                MigrationKitError::ReportGenerationFailed { detail: "x".into() },
                "report generation failed: x",
            ),
            (
                MigrationKitError::DeterminismViolation { detail: "x".into() },
                "determinism violation: x",
            ),
            (
                MigrationKitError::TooManyEntries {
                    kind: "api".into(),
                    count: 99,
                    max: 50,
                },
                "too many api entries: 99 exceeds max 50",
            ),
            (
                MigrationKitError::InternalError { detail: "x".into() },
                "internal error: x",
            ),
        ];
        for (err, expected) in &cases {
            assert_eq!(err.to_string(), *expected);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: MigrationConfig default values
    // -----------------------------------------------------------------------

    #[test]
    fn migration_config_default_values() {
        let c = MigrationConfig::default();
        assert_eq!(c.source_runtime, SourceRuntime::Node);
        assert!(c.analyze_dependencies);
        assert!(c.infer_capabilities);
        assert!(c.run_behavior_validation);
        assert_eq!(c.min_compatibility_score_millionths, 800_000);
        assert_eq!(c.max_divergence_count, 100);
        assert_eq!(c.deterministic_seed, 42);
    }

    // -----------------------------------------------------------------------
    // Enrichment: all capability kind names
    // -----------------------------------------------------------------------

    #[test]
    fn inferred_capability_kind_all_names() {
        let expected = [
            (InferredCapabilityKind::FileSystem, "cap:fs"),
            (InferredCapabilityKind::Network, "cap:net"),
            (InferredCapabilityKind::ProcessSpawn, "cap:process:spawn"),
            (InferredCapabilityKind::EnvironmentAccess, "cap:env"),
            (InferredCapabilityKind::CryptoAccess, "cap:crypto"),
            (InferredCapabilityKind::TimerAccess, "cap:timer"),
            (InferredCapabilityKind::WorkerThreads, "cap:worker"),
            (InferredCapabilityKind::ChildProcess, "cap:process:child"),
            (InferredCapabilityKind::DynamicImport, "cap:import:dynamic"),
            (InferredCapabilityKind::WasmExecution, "cap:wasm"),
            (InferredCapabilityKind::SharedMemory, "cap:shared-memory"),
            (InferredCapabilityKind::NativeAddon, "cap:native-addon"),
        ];
        for (kind, name) in &expected {
            assert_eq!(kind.franken_capability_name(), *name);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: all weight/penalty values
    // -----------------------------------------------------------------------

    #[test]
    fn api_support_level_all_weights() {
        assert_eq!(
            ApiSupportLevel::FullySupported.compatibility_weight_millionths(),
            1_000_000
        );
        assert_eq!(
            ApiSupportLevel::PartiallySupported.compatibility_weight_millionths(),
            700_000
        );
        assert_eq!(
            ApiSupportLevel::Deprecated.compatibility_weight_millionths(),
            500_000
        );
        assert_eq!(
            ApiSupportLevel::RequiresPolyfill.compatibility_weight_millionths(),
            400_000
        );
        assert_eq!(
            ApiSupportLevel::Unsupported.compatibility_weight_millionths(),
            0
        );
    }

    #[test]
    fn divergence_severity_all_penalties() {
        assert_eq!(DivergenceSeverity::Critical.penalty_millionths(), 200_000);
        assert_eq!(DivergenceSeverity::High.penalty_millionths(), 100_000);
        assert_eq!(DivergenceSeverity::Medium.penalty_millionths(), 50_000);
        assert_eq!(DivergenceSeverity::Low.penalty_millionths(), 20_000);
        assert_eq!(DivergenceSeverity::Informational.penalty_millionths(), 0);
    }

    #[test]
    fn remediation_effort_all_weights() {
        assert_eq!(RemediationEffort::Trivial.weight_millionths(), 100_000);
        assert_eq!(RemediationEffort::Low.weight_millionths(), 300_000);
        assert_eq!(RemediationEffort::Medium.weight_millionths(), 500_000);
        assert_eq!(RemediationEffort::High.weight_millionths(), 800_000);
        assert_eq!(
            RemediationEffort::Significant.weight_millionths(),
            1_000_000
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn migration_event_serde_roundtrip() {
        let event = MigrationEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            component: "migration_kit".to_string(),
            event: "test".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("FE-MK-0001".to_string()),
            details: BTreeMap::from([("k".to_string(), "v".to_string())]),
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: MigrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    #[test]
    fn lockstep_test_result_serde_roundtrip() {
        let r = LockstepTestResult {
            test_name: "t1".to_string(),
            node_output: "ok".to_string(),
            franken_output: "ok".to_string(),
            node_exit_code: 0,
            franken_exit_code: 1,
            node_duration_us: 100,
            franken_duration_us: 200,
        };
        let json = serde_json::to_string(&r).unwrap();
        let restored: LockstepTestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, restored);
    }

    #[test]
    fn source_file_serde_roundtrip() {
        let sf = SourceFile {
            path: "index.js".to_string(),
            content: "console.log('hi');".to_string(),
        };
        let json = serde_json::to_string(&sf).unwrap();
        let restored: SourceFile = serde_json::from_str(&json).unwrap();
        assert_eq!(sf, restored);
    }

    #[test]
    fn api_usage_entry_serde_roundtrip() {
        let entry = ApiUsageEntry {
            api_name: "readFile".to_string(),
            module_path: "fs".to_string(),
            usage_count: 5,
            support_level: ApiSupportLevel::FullySupported,
            notes: "sandboxed".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: ApiUsageEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
    }

    #[test]
    fn dependency_entry_serde_roundtrip() {
        let de = DependencyEntry {
            name: "lodash".to_string(),
            version_spec: "^4.17.21".to_string(),
            compatible: true,
            migration_notes: "pure JS".to_string(),
        };
        let json = serde_json::to_string(&de).unwrap();
        let restored: DependencyEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(de, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn api_support_level_ordering() {
        assert!(ApiSupportLevel::FullySupported < ApiSupportLevel::Unsupported);
        assert!(ApiSupportLevel::PartiallySupported < ApiSupportLevel::Deprecated);
    }

    #[test]
    fn divergence_severity_ordering() {
        assert!(DivergenceSeverity::Critical < DivergenceSeverity::Informational);
    }

    #[test]
    fn remediation_effort_ordering() {
        assert!(RemediationEffort::Trivial < RemediationEffort::Significant);
    }

    #[test]
    fn source_runtime_ordering() {
        assert!(SourceRuntime::Node < SourceRuntime::Bun);
    }

    // -----------------------------------------------------------------------
    // Enrichment: is_migration_blocker completeness
    // -----------------------------------------------------------------------

    #[test]
    fn api_support_level_blocker_completeness() {
        assert!(!ApiSupportLevel::FullySupported.is_migration_blocker());
        assert!(!ApiSupportLevel::PartiallySupported.is_migration_blocker());
        assert!(ApiSupportLevel::Unsupported.is_migration_blocker());
        assert!(!ApiSupportLevel::Deprecated.is_migration_blocker());
        assert!(!ApiSupportLevel::RequiresPolyfill.is_migration_blocker());
    }

    // -- Enrichment: std::error --

    #[test]
    fn migration_kit_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(MigrationKitError::AnalysisFailed {
                detail: "fail".into(),
            }),
            Box::new(MigrationKitError::ManifestGenerationFailed {
                detail: "fail".into(),
            }),
            Box::new(MigrationKitError::CapabilityInferenceFailed {
                detail: "fail".into(),
            }),
            Box::new(MigrationKitError::InvalidPackageJson {
                detail: "missing".into(),
            }),
            Box::new(MigrationKitError::UnsupportedApiDetected {
                api: "eval".into(),
                detail: "banned".into(),
            }),
            Box::new(MigrationKitError::IncompatibleDependency {
                name: "lodash".into(),
                reason: "native".into(),
            }),
            Box::new(MigrationKitError::DeterminismViolation {
                detail: "Math.random".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            7,
            "all 7 tested variants produce distinct messages"
        );
    }

    // ====================================================================
    // Enrichment: classify_output_divergence_severity
    // ====================================================================

    #[test]
    fn classify_divergence_exact_match_after_trim() {
        let sev = classify_output_divergence_severity("  hello  ", "hello");
        assert_eq!(sev, DivergenceSeverity::Informational);
    }

    #[test]
    fn classify_divergence_case_only_difference() {
        let sev = classify_output_divergence_severity("Hello World", "hello world");
        assert_eq!(sev, DivergenceSeverity::Low);
    }

    #[test]
    fn classify_divergence_prefix_relation() {
        let sev = classify_output_divergence_severity("hello world extra", "hello world");
        assert_eq!(sev, DivergenceSeverity::Low);
    }

    #[test]
    fn classify_divergence_medium_severity_similar_length() {
        // 60% length ratio => Medium
        let sev = classify_output_divergence_severity("abcdefghij", "ZYXWVU");
        assert_eq!(sev, DivergenceSeverity::Medium);
    }

    #[test]
    fn classify_divergence_high_severity_very_different_length() {
        // <50% length ratio => High
        let sev = classify_output_divergence_severity(
            "this is a very long output string that is significantly longer",
            "short",
        );
        assert_eq!(sev, DivergenceSeverity::High);
    }

    #[test]
    fn classify_divergence_both_empty_after_trim() {
        let sev = classify_output_divergence_severity("  ", "  ");
        assert_eq!(sev, DivergenceSeverity::Informational);
    }

    // ====================================================================
    // Enrichment: timing_divergence_significant
    // ====================================================================

    #[test]
    fn timing_divergence_both_zero() {
        assert!(!timing_divergence_significant(0, 0));
    }

    #[test]
    fn timing_divergence_one_zero() {
        assert!(!timing_divergence_significant(100, 0));
        assert!(!timing_divergence_significant(0, 100));
    }

    #[test]
    fn timing_divergence_within_ratio() {
        // 150/100 = 150% < 200% => not significant
        assert!(!timing_divergence_significant(100, 150));
    }

    #[test]
    fn timing_divergence_exceeds_ratio() {
        // 300/100 = 300% > 200% => significant
        assert!(timing_divergence_significant(100, 300));
    }

    #[test]
    fn timing_divergence_symmetric() {
        assert!(timing_divergence_significant(300, 100));
        assert!(timing_divergence_significant(100, 300));
    }

    // ====================================================================
    // Enrichment: infer_capabilities patterns
    // ====================================================================

    #[test]
    fn infer_timer_pattern() {
        let files = vec![SourceFile {
            path: "app.js".into(),
            content: "setTimeout(fn, 1000)".into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        assert!(
            result
                .inferred_capabilities
                .iter()
                .any(|c| c.kind == InferredCapabilityKind::TimerAccess)
        );
        assert!(result.minimum_capability_set.contains("cap:timer"));
    }

    #[test]
    fn infer_set_interval_pattern() {
        let files = vec![SourceFile {
            path: "worker.js".into(),
            content: "setInterval(() => {}, 5000)".into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        assert!(
            result
                .inferred_capabilities
                .iter()
                .any(|c| c.kind == InferredCapabilityKind::TimerAccess)
        );
    }

    #[test]
    fn infer_dynamic_import_pattern() {
        let files = vec![SourceFile {
            path: "loader.js".into(),
            content: r#"const mod = await import("./plugin.js")"#.into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        assert!(
            result
                .inferred_capabilities
                .iter()
                .any(|c| c.kind == InferredCapabilityKind::DynamicImport)
        );
        assert!(result.minimum_capability_set.contains("cap:import:dynamic"));
    }

    #[test]
    fn infer_native_addon_node_gyp() {
        let files = vec![SourceFile {
            path: "binding.gyp".into(),
            content: "node-gyp rebuild".into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        assert!(
            result
                .inferred_capabilities
                .iter()
                .any(|c| c.kind == InferredCapabilityKind::NativeAddon)
        );
    }

    #[test]
    fn infer_native_addon_napi() {
        let files = vec![SourceFile {
            path: "index.js".into(),
            content: "const binding = require('napi-module')".into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        assert!(
            result
                .inferred_capabilities
                .iter()
                .any(|c| c.kind == InferredCapabilityKind::NativeAddon)
        );
    }

    #[test]
    fn infer_worker_threads_pattern() {
        let files = vec![SourceFile {
            path: "pool.js".into(),
            content: r#"const { Worker } = require("worker_threads")"#.into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        assert!(
            result
                .inferred_capabilities
                .iter()
                .any(|c| c.kind == InferredCapabilityKind::WorkerThreads)
        );
        assert!(result.minimum_capability_set.contains("cap:worker"));
    }

    #[test]
    fn infer_new_worker_lower_confidence() {
        let files = vec![SourceFile {
            path: "main.js".into(),
            content: "const w = new Worker('./w.js')".into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        let cap = result
            .inferred_capabilities
            .iter()
            .find(|c| c.kind == InferredCapabilityKind::WorkerThreads)
            .unwrap();
        assert_eq!(cap.confidence_millionths, 700_000);
        // 700_000 < 800_000 threshold => NOT in minimum set
        assert!(!result.minimum_capability_set.contains("cap:worker"));
        // but IS in recommended set
        assert!(result.recommended_capability_set.contains("cap:worker"));
    }

    #[test]
    fn infer_wasm_execution() {
        let files = vec![SourceFile {
            path: "wasm.js".into(),
            content: "WebAssembly.instantiate(buffer)".into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        assert!(
            result
                .inferred_capabilities
                .iter()
                .any(|c| c.kind == InferredCapabilityKind::WasmExecution)
        );
        assert!(result.minimum_capability_set.contains("cap:wasm"));
    }

    #[test]
    fn infer_shared_memory() {
        let files = vec![SourceFile {
            path: "shared.js".into(),
            content: "const buf = new SharedArrayBuffer(1024)".into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        assert!(
            result
                .inferred_capabilities
                .iter()
                .any(|c| c.kind == InferredCapabilityKind::SharedMemory)
        );
        assert!(result.minimum_capability_set.contains("cap:shared-memory"));
    }

    #[test]
    fn infer_esm_import_fs() {
        let files = vec![SourceFile {
            path: "mod.mjs".into(),
            content: r#"import { readFile } from "fs""#.into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        assert!(
            result
                .inferred_capabilities
                .iter()
                .any(|c| c.kind == InferredCapabilityKind::FileSystem)
        );
    }

    #[test]
    fn infer_esm_import_crypto() {
        let files = vec![SourceFile {
            path: "crypto.mjs".into(),
            content: r#"import { randomBytes } from "crypto""#.into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        assert!(
            result
                .inferred_capabilities
                .iter()
                .any(|c| c.kind == InferredCapabilityKind::CryptoAccess)
        );
    }

    #[test]
    fn infer_capabilities_too_many_files() {
        let files: Vec<SourceFile> = (0..MAX_SOURCE_FILES + 1)
            .map(|i| SourceFile {
                path: format!("f{i}.js"),
                content: String::new(),
            })
            .collect();
        let config = MigrationConfig::default();
        let err = infer_capabilities(&files, &config).unwrap_err();
        assert_eq!(err.code(), "FE-MK-0012");
    }

    // ====================================================================
    // Enrichment: validate_behavior — timing divergence path
    // ====================================================================

    #[test]
    fn validate_behavior_timing_divergence() {
        let config = MigrationConfig::default();
        let results = vec![LockstepTestResult {
            test_name: "timer_test".into(),
            node_output: "result_a".into(),
            franken_output: "result_b".into(),
            node_exit_code: 0,
            franken_exit_code: 0,
            node_duration_us: 100,
            franken_duration_us: 500, // >2x
        }];
        let report = validate_behavior(&results, &config).unwrap();
        assert_eq!(report.divergence_count, 1);
        assert_eq!(report.divergences[0].kind, DivergenceKind::TimingDifference);
    }

    #[test]
    fn validate_behavior_output_format_divergence_no_timing() {
        let config = MigrationConfig::default();
        let results = vec![LockstepTestResult {
            test_name: "fmt_test".into(),
            node_output: "hello".into(),
            franken_output: "Hello".into(),
            node_exit_code: 0,
            franken_exit_code: 0,
            node_duration_us: 100,
            franken_duration_us: 120, // within 2x
        }];
        let report = validate_behavior(&results, &config).unwrap();
        assert_eq!(report.divergence_count, 1);
        assert_eq!(
            report.divergences[0].kind,
            DivergenceKind::OutputFormatDifference
        );
    }

    #[test]
    fn validate_behavior_exit_code_only_mismatch() {
        let config = MigrationConfig::default();
        let results = vec![LockstepTestResult {
            test_name: "exit_test".into(),
            node_output: "ok".into(),
            franken_output: "ok".into(),
            node_exit_code: 0,
            franken_exit_code: 1,
            node_duration_us: 100,
            franken_duration_us: 100,
        }];
        let report = validate_behavior(&results, &config).unwrap();
        assert_eq!(report.divergence_count, 1);
        assert_eq!(
            report.divergences[0].kind,
            DivergenceKind::ErrorBehaviorDifference
        );
        assert_eq!(report.divergences[0].severity, DivergenceSeverity::High);
    }

    #[test]
    fn validate_behavior_critical_both_differ() {
        let config = MigrationConfig::default();
        let results = vec![LockstepTestResult {
            test_name: "critical_test".into(),
            node_output: "node_out".into(),
            franken_output: "franken_out".into(),
            node_exit_code: 0,
            franken_exit_code: 1,
            node_duration_us: 100,
            franken_duration_us: 100,
        }];
        let report = validate_behavior(&results, &config).unwrap();
        assert_eq!(report.divergence_count, 1);
        assert_eq!(
            report.divergences[0].kind,
            DivergenceKind::SemanticDifference
        );
        assert_eq!(report.divergences[0].severity, DivergenceSeverity::Critical);
    }

    #[test]
    fn validate_behavior_mixed_pass_and_fail() {
        let config = MigrationConfig::default();
        let results = vec![
            LockstepTestResult {
                test_name: "pass".into(),
                node_output: "ok".into(),
                franken_output: "ok".into(),
                node_exit_code: 0,
                franken_exit_code: 0,
                node_duration_us: 50,
                franken_duration_us: 50,
            },
            LockstepTestResult {
                test_name: "fail".into(),
                node_output: "a".into(),
                franken_output: "b".into(),
                node_exit_code: 0,
                franken_exit_code: 0,
                node_duration_us: 50,
                franken_duration_us: 50,
            },
        ];
        let report = validate_behavior(&results, &config).unwrap();
        assert_eq!(report.total_test_cases, 2);
        assert_eq!(report.passing_count, 1);
        assert_eq!(report.divergence_count, 1);
        assert_eq!(report.parity_score_millionths, 500_000);
    }

    // ====================================================================
    // Enrichment: generate_remediation — deprecated APIs + divergences
    // ====================================================================

    #[test]
    fn generate_remediation_deprecated_api_step() {
        let compatibility = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 1,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 1,
            polyfill_required_count: 0,
            compatibility_score_millionths: 500_000,
            api_entries: vec![ApiUsageEntry {
                api_name: "url.parse".into(),
                module_path: "url".into(),
                usage_count: 3,
                support_level: ApiSupportLevel::Deprecated,
                notes: "use new URL() constructor".into(),
            }],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 1,
            passing_count: 1,
            divergence_count: 0,
            parity_score_millionths: 1_000_000,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"test"),
        };
        let steps = generate_remediation(&compatibility, &behavior, &caps).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].category, RemediationCategory::ApiReplacement);
        assert_eq!(steps[0].effort, RemediationEffort::Low);
        assert!(steps[0].title.contains("deprecated"));
    }

    #[test]
    fn generate_remediation_behavior_divergence_critical() {
        let schema_id = SchemaId::from_definition(DIVERGENCE_SCHEMA_DEF);
        let div_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            MIGRATION_ZONE,
            &schema_id,
            b"test-div",
        )
        .unwrap();
        let compatibility = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 0,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 1,
            passing_count: 0,
            divergence_count: 1,
            parity_score_millionths: 0,
            divergences: vec![BehaviorDivergence {
                divergence_id: div_id,
                kind: DivergenceKind::SemanticDifference,
                severity: DivergenceSeverity::Critical,
                test_case: "crash_test".into(),
                node_bun_result: "ok".into(),
                franken_result: "CRASH".into(),
                explanation: "fatal divergence".into(),
                remediation: "fix it".into(),
            }],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"test"),
        };
        let steps = generate_remediation(&compatibility, &behavior, &caps).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].category, RemediationCategory::CodeRefactor);
        assert_eq!(steps[0].effort, RemediationEffort::Significant);
        assert_eq!(
            steps[0].priority_score_millionths,
            DivergenceSeverity::Critical
                .penalty_millionths()
                .saturating_mul(5)
        );
    }

    #[test]
    fn generate_remediation_behavior_divergence_high() {
        let schema_id = SchemaId::from_definition(DIVERGENCE_SCHEMA_DEF);
        let div_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            MIGRATION_ZONE,
            &schema_id,
            b"test-div-high",
        )
        .unwrap();
        let compatibility = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 0,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 1,
            passing_count: 0,
            divergence_count: 1,
            parity_score_millionths: 0,
            divergences: vec![BehaviorDivergence {
                divergence_id: div_id,
                kind: DivergenceKind::OutputFormatDifference,
                severity: DivergenceSeverity::High,
                test_case: "format_test".into(),
                node_bun_result: "old".into(),
                franken_result: "new".into(),
                explanation: "format issue".into(),
                remediation: "update format".into(),
            }],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"test"),
        };
        let steps = generate_remediation(&compatibility, &behavior, &caps).unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].effort, RemediationEffort::Medium);
    }

    #[test]
    fn generate_remediation_skips_low_severity_divergences() {
        let schema_id = SchemaId::from_definition(DIVERGENCE_SCHEMA_DEF);
        let div_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            MIGRATION_ZONE,
            &schema_id,
            b"test-div-low",
        )
        .unwrap();
        let compatibility = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 0,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 1,
            passing_count: 0,
            divergence_count: 1,
            parity_score_millionths: 0,
            divergences: vec![BehaviorDivergence {
                divergence_id: div_id,
                kind: DivergenceKind::OutputFormatDifference,
                severity: DivergenceSeverity::Low,
                test_case: "minor_test".into(),
                node_bun_result: "a".into(),
                franken_result: "A".into(),
                explanation: "case difference".into(),
                remediation: "normalize".into(),
            }],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"test"),
        };
        let steps = generate_remediation(&compatibility, &behavior, &caps).unwrap();
        assert!(steps.is_empty());
    }

    // ====================================================================
    // Enrichment: generate_manifest
    // ====================================================================

    #[test]
    fn generate_manifest_scoped_package_name_transform() {
        let compatibility = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 0,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 1,
            passing_count: 1,
            divergence_count: 0,
            parity_score_millionths: 1_000_000,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"test"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"test"),
        };
        let input = ManifestGenerationInput {
            source_runtime: SourceRuntime::Node,
            source_package_name: "@scope/my-pkg".into(),
            source_version: "1.0.0".into(),
            entry_point: "index.js".into(),
            compatibility,
            behavior,
            capabilities: caps,
            epoch: SecurityEpoch::from_raw(1),
        };
        let manifest = generate_manifest(input).unwrap();
        assert_eq!(manifest.franken_extension_name, "scope__my-pkg");
        assert_eq!(manifest.franken_extension_version, "0.1.0");
    }

    #[test]
    fn generate_manifest_deterministic() {
        let mk_input = || {
            let compatibility = CompatibilityReport {
                source_runtime: SourceRuntime::Node,
                total_apis_used: 1,
                fully_supported_count: 1,
                partially_supported_count: 0,
                unsupported_count: 0,
                deprecated_count: 0,
                polyfill_required_count: 0,
                compatibility_score_millionths: 1_000_000,
                api_entries: vec![],
                dependency_entries: vec![],
                report_content_hash: ContentHash::compute(b"det"),
            };
            let behavior = BehaviorValidationReport {
                total_test_cases: 2,
                passing_count: 2,
                divergence_count: 0,
                parity_score_millionths: 1_000_000,
                divergences: vec![],
                report_content_hash: ContentHash::compute(b"det"),
            };
            let caps = CapabilityInferenceResult {
                inferred_capabilities: vec![],
                minimum_capability_set: BTreeSet::new(),
                recommended_capability_set: BTreeSet::new(),
                capability_hash: ContentHash::compute(b"det"),
            };
            ManifestGenerationInput {
                source_runtime: SourceRuntime::Node,
                source_package_name: "test-pkg".into(),
                source_version: "2.0.0".into(),
                entry_point: "main.js".into(),
                compatibility,
                behavior,
                capabilities: caps,
                epoch: SecurityEpoch::from_raw(5),
            }
        };
        let m1 = generate_manifest(mk_input()).unwrap();
        let m2 = generate_manifest(mk_input()).unwrap();
        assert_eq!(m1.manifest_id, m2.manifest_id);
        assert_eq!(m1.manifest_content_hash, m2.manifest_content_hash);
    }

    // ====================================================================
    // Enrichment: compute_migration_readiness
    // ====================================================================

    #[test]
    fn compute_readiness_zero_scores() {
        let compatibility = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 0,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 0,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"z"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 0,
            passing_count: 0,
            divergence_count: 0,
            parity_score_millionths: 0,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"z"),
        };
        let readiness = compute_migration_readiness(&compatibility, &behavior);
        assert_eq!(readiness, 0);
    }

    #[test]
    fn compute_readiness_critical_penalty() {
        let schema_id = SchemaId::from_definition(DIVERGENCE_SCHEMA_DEF);
        let div_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            MIGRATION_ZONE,
            &schema_id,
            b"crit",
        )
        .unwrap();
        let compatibility = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 1,
            fully_supported_count: 1,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"c"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 1,
            passing_count: 0,
            divergence_count: 1,
            parity_score_millionths: 0,
            divergences: vec![BehaviorDivergence {
                divergence_id: div_id,
                kind: DivergenceKind::SemanticDifference,
                severity: DivergenceSeverity::Critical,
                test_case: "c".into(),
                node_bun_result: "a".into(),
                franken_result: "b".into(),
                explanation: String::new(),
                remediation: String::new(),
            }],
            report_content_hash: ContentHash::compute(b"c"),
        };
        let readiness = compute_migration_readiness(&compatibility, &behavior);
        // 40% of 1M = 400_000, 60% of 0 = 0, penalty = 100_000
        assert_eq!(readiness, 300_000);
    }

    // ====================================================================
    // Enrichment: analyze_package — Bun runtime, peer deps, ts entry
    // ====================================================================

    #[test]
    fn analyze_package_bun_runtime() {
        let config = MigrationConfig {
            source_runtime: SourceRuntime::Bun,
            ..MigrationConfig::default()
        };
        let pkg = r#"{"name":"bun-pkg","dependencies":{"express":"^4"}}"#;
        let report = analyze_package(pkg, &config).unwrap();
        assert_eq!(report.source_runtime, SourceRuntime::Bun);
    }

    #[test]
    fn analyze_package_peer_deps() {
        let config = MigrationConfig::default();
        let pkg = r#"{"name":"test","peerDependencies":{"react":"^18"}}"#;
        let report = analyze_package(pkg, &config).unwrap();
        assert!(!report.dependency_entries.is_empty());
        assert_eq!(report.dependency_entries[0].name, "react");
    }

    #[test]
    fn analyze_package_ts_entry_as_esm() {
        let config = MigrationConfig::default();
        let pkg = r#"{"name":"ts-app","main":"index.ts"}"#;
        let report = analyze_package(pkg, &config).unwrap();
        let esm_entry = report
            .api_entries
            .iter()
            .find(|e| e.api_name == "entry:esm");
        assert!(esm_entry.is_some());
    }

    #[test]
    fn analyze_package_mjs_entry_as_esm() {
        let config = MigrationConfig::default();
        let pkg = r#"{"name":"esm-app","module":"dist/index.mjs"}"#;
        let report = analyze_package(pkg, &config).unwrap();
        let esm_entry = report
            .api_entries
            .iter()
            .find(|e| e.api_name == "entry:esm");
        assert!(esm_entry.is_some());
    }

    #[test]
    fn analyze_package_cjs_entry() {
        let config = MigrationConfig::default();
        let pkg = r#"{"name":"cjs-app","main":"dist/index.js"}"#;
        let report = analyze_package(pkg, &config).unwrap();
        let cjs_entry = report
            .api_entries
            .iter()
            .find(|e| e.api_name == "entry:cjs");
        assert!(cjs_entry.is_some());
    }

    #[test]
    fn analyze_package_node_cli_scripts() {
        let config = MigrationConfig::default();
        let pkg = r#"{"name":"cli","scripts":{"build":"node build.js","test":"npx jest"}}"#;
        let report = analyze_package(pkg, &config).unwrap();
        let cli_entries: Vec<_> = report
            .api_entries
            .iter()
            .filter(|e| e.api_name == "runtime:node-cli")
            .collect();
        assert_eq!(cli_entries.len(), 2);
    }

    // ====================================================================
    // Enrichment: serde roundtrips
    // ====================================================================

    #[test]
    fn serde_roundtrip_migration_manifest() {
        let compatibility = CompatibilityReport {
            source_runtime: SourceRuntime::Node,
            total_apis_used: 0,
            fully_supported_count: 0,
            partially_supported_count: 0,
            unsupported_count: 0,
            deprecated_count: 0,
            polyfill_required_count: 0,
            compatibility_score_millionths: 1_000_000,
            api_entries: vec![],
            dependency_entries: vec![],
            report_content_hash: ContentHash::compute(b"s"),
        };
        let behavior = BehaviorValidationReport {
            total_test_cases: 1,
            passing_count: 1,
            divergence_count: 0,
            parity_score_millionths: 1_000_000,
            divergences: vec![],
            report_content_hash: ContentHash::compute(b"s"),
        };
        let caps = CapabilityInferenceResult {
            inferred_capabilities: vec![],
            minimum_capability_set: BTreeSet::new(),
            recommended_capability_set: BTreeSet::new(),
            capability_hash: ContentHash::compute(b"s"),
        };
        let input = ManifestGenerationInput {
            source_runtime: SourceRuntime::Node,
            source_package_name: "serde-test".into(),
            source_version: "1.0.0".into(),
            entry_point: "index.js".into(),
            compatibility,
            behavior,
            capabilities: caps,
            epoch: SecurityEpoch::from_raw(1),
        };
        let manifest = generate_manifest(input).unwrap();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: MigrationManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn serde_roundtrip_behavior_validation_report() {
        let config = MigrationConfig::default();
        let results = vec![LockstepTestResult {
            test_name: "t".into(),
            node_output: "a".into(),
            franken_output: "b".into(),
            node_exit_code: 0,
            franken_exit_code: 0,
            node_duration_us: 10,
            franken_duration_us: 10,
        }];
        let report = validate_behavior(&results, &config).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let back: BehaviorValidationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn serde_roundtrip_capability_inference_result() {
        let files = vec![SourceFile {
            path: "app.js".into(),
            content: r#"require("fs")"#.into(),
        }];
        let config = MigrationConfig::default();
        let result = infer_capabilities(&files, &config).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: CapabilityInferenceResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn serde_roundtrip_lockstep_test_result() {
        let ltr = LockstepTestResult {
            test_name: "rt".into(),
            node_output: "ok".into(),
            franken_output: "ok".into(),
            node_exit_code: 0,
            franken_exit_code: 0,
            node_duration_us: 42,
            franken_duration_us: 43,
        };
        let json = serde_json::to_string(&ltr).unwrap();
        let back: LockstepTestResult = serde_json::from_str(&json).unwrap();
        assert_eq!(ltr, back);
    }

    #[test]
    fn serde_roundtrip_migration_config() {
        let config = MigrationConfig {
            source_runtime: SourceRuntime::Bun,
            analyze_dependencies: false,
            infer_capabilities: false,
            run_behavior_validation: false,
            min_compatibility_score_millionths: 900_000,
            max_divergence_count: 50,
            deterministic_seed: 99,
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: MigrationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn serde_roundtrip_migration_event() {
        let mut details = BTreeMap::new();
        details.insert("key".into(), "val".into());
        let event = MigrationEvent {
            trace_id: "t1".into(),
            decision_id: "d1".into(),
            component: COMPONENT.into(),
            event: "test".into(),
            outcome: "ok".into(),
            error_code: Some("FE-MK-0001".into()),
            details,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: MigrationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn serde_roundtrip_remediation_step() {
        let schema_id = SchemaId::from_definition(REMEDIATION_SCHEMA_DEF);
        let step_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            MIGRATION_ZONE,
            &schema_id,
            b"serde-step",
        )
        .unwrap();
        let step = RemediationStep {
            step_id,
            category: RemediationCategory::PolyfillAddition,
            effort: RemediationEffort::Trivial,
            title: "Add polyfill".into(),
            description: "Need polyfill for X".into(),
            before_snippet: "old".into(),
            after_snippet: "new".into(),
            affected_files: vec!["lib.js".into()],
            priority_score_millionths: 700_000,
        };
        let json = serde_json::to_string(&step).unwrap();
        let back: RemediationStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, back);
    }

    // ====================================================================
    // Enrichment: error variant exhaustive coverage
    // ====================================================================

    #[test]
    fn error_code_all_13_variants_unique() {
        let codes: Vec<&str> = vec![
            MigrationKitError::AnalysisFailed {
                detail: String::new(),
            }
            .code(),
            MigrationKitError::ManifestGenerationFailed {
                detail: String::new(),
            }
            .code(),
            MigrationKitError::CapabilityInferenceFailed {
                detail: String::new(),
            }
            .code(),
            MigrationKitError::BehaviorValidationFailed {
                detail: String::new(),
            }
            .code(),
            MigrationKitError::RemediationUnavailable {
                detail: String::new(),
            }
            .code(),
            MigrationKitError::InvalidPackageJson {
                detail: String::new(),
            }
            .code(),
            MigrationKitError::UnsupportedApiDetected {
                api: String::new(),
                detail: String::new(),
            }
            .code(),
            MigrationKitError::IncompatibleDependency {
                name: String::new(),
                reason: String::new(),
            }
            .code(),
            MigrationKitError::LockstepMismatch {
                runtime: String::new(),
                detail: String::new(),
            }
            .code(),
            MigrationKitError::ReportGenerationFailed {
                detail: String::new(),
            }
            .code(),
            MigrationKitError::DeterminismViolation {
                detail: String::new(),
            }
            .code(),
            MigrationKitError::TooManyEntries {
                kind: String::new(),
                count: 0,
                max: 0,
            }
            .code(),
            MigrationKitError::InternalError {
                detail: String::new(),
            }
            .code(),
        ];
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), 13, "all 13 error variants have unique codes");
    }

    #[test]
    fn error_serde_roundtrip_all_variants() {
        let variants = vec![
            MigrationKitError::AnalysisFailed { detail: "a".into() },
            MigrationKitError::ManifestGenerationFailed { detail: "b".into() },
            MigrationKitError::CapabilityInferenceFailed { detail: "c".into() },
            MigrationKitError::BehaviorValidationFailed { detail: "d".into() },
            MigrationKitError::RemediationUnavailable { detail: "e".into() },
            MigrationKitError::InvalidPackageJson { detail: "f".into() },
            MigrationKitError::UnsupportedApiDetected {
                api: "g".into(),
                detail: "h".into(),
            },
            MigrationKitError::IncompatibleDependency {
                name: "i".into(),
                reason: "j".into(),
            },
            MigrationKitError::LockstepMismatch {
                runtime: "k".into(),
                detail: "l".into(),
            },
            MigrationKitError::ReportGenerationFailed { detail: "m".into() },
            MigrationKitError::DeterminismViolation { detail: "n".into() },
            MigrationKitError::TooManyEntries {
                kind: "o".into(),
                count: 1,
                max: 2,
            },
            MigrationKitError::InternalError { detail: "p".into() },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: MigrationKitError = serde_json::from_str(&json).unwrap();
            assert_eq!(v, &back);
        }
    }

    // ====================================================================
    // Enrichment: enum coverage
    // ====================================================================

    #[test]
    fn divergence_severity_penalty_ordering() {
        assert!(
            DivergenceSeverity::Critical.penalty_millionths()
                > DivergenceSeverity::High.penalty_millionths()
        );
        assert!(
            DivergenceSeverity::High.penalty_millionths()
                > DivergenceSeverity::Medium.penalty_millionths()
        );
        assert!(
            DivergenceSeverity::Medium.penalty_millionths()
                > DivergenceSeverity::Low.penalty_millionths()
        );
        assert!(
            DivergenceSeverity::Low.penalty_millionths()
                > DivergenceSeverity::Informational.penalty_millionths()
        );
        assert_eq!(DivergenceSeverity::Informational.penalty_millionths(), 0);
    }

    #[test]
    fn remediation_effort_weight_ordering() {
        assert!(
            RemediationEffort::Significant.weight_millionths()
                > RemediationEffort::High.weight_millionths()
        );
        assert!(
            RemediationEffort::High.weight_millionths()
                > RemediationEffort::Medium.weight_millionths()
        );
        assert!(
            RemediationEffort::Medium.weight_millionths()
                > RemediationEffort::Low.weight_millionths()
        );
        assert!(
            RemediationEffort::Low.weight_millionths()
                > RemediationEffort::Trivial.weight_millionths()
        );
    }

    #[test]
    fn all_capability_kinds_have_names() {
        let kinds = [
            InferredCapabilityKind::FileSystem,
            InferredCapabilityKind::Network,
            InferredCapabilityKind::ProcessSpawn,
            InferredCapabilityKind::EnvironmentAccess,
            InferredCapabilityKind::CryptoAccess,
            InferredCapabilityKind::TimerAccess,
            InferredCapabilityKind::WorkerThreads,
            InferredCapabilityKind::ChildProcess,
            InferredCapabilityKind::DynamicImport,
            InferredCapabilityKind::WasmExecution,
            InferredCapabilityKind::SharedMemory,
            InferredCapabilityKind::NativeAddon,
        ];
        let mut names = BTreeSet::new();
        for kind in &kinds {
            let name = kind.franken_capability_name();
            assert!(name.starts_with("cap:"));
            names.insert(name);
        }
        assert_eq!(
            names.len(),
            12,
            "all 12 capability kinds map to unique names"
        );
    }

    #[test]
    fn source_runtime_display() {
        assert_eq!(format!("{}", SourceRuntime::Node), "Node.js");
        assert_eq!(format!("{}", SourceRuntime::Bun), "Bun");
    }

    #[test]
    fn api_support_level_compatibility_weight_ordering() {
        assert!(
            ApiSupportLevel::FullySupported.compatibility_weight_millionths()
                > ApiSupportLevel::PartiallySupported.compatibility_weight_millionths()
        );
        assert!(
            ApiSupportLevel::PartiallySupported.compatibility_weight_millionths()
                > ApiSupportLevel::Deprecated.compatibility_weight_millionths()
        );
        assert!(
            ApiSupportLevel::Deprecated.compatibility_weight_millionths()
                > ApiSupportLevel::RequiresPolyfill.compatibility_weight_millionths()
        );
        assert_eq!(
            ApiSupportLevel::Unsupported.compatibility_weight_millionths(),
            0
        );
    }

    #[test]
    fn emit_migration_event_json_output() {
        let event = MigrationEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            component: COMPONENT.into(),
            event: "test".into(),
            outcome: "pass".into(),
            error_code: None,
            details: BTreeMap::new(),
        };
        let json = emit_migration_event(&event);
        assert!(json.contains("migration_kit"));
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["outcome"], "pass");
    }
}
