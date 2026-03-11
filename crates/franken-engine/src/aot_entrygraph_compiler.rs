//! Ahead-of-time entrygraph compilation with explicit provenance.
//!
//! This module compiles supported package and app entrygraphs ahead of time
//! so shipped surfaces can produce startup-optimised artifacts instead of
//! relying exclusively on runtime tier-up.  Every compiled artifact carries
//! a provenance chain that ties the output back to the exact source graph,
//! policy revision, and compiler configuration that produced it.
//!
//! Plan references: Section 7.10 (RGC-610B), bead bd-1lsy.7.10.2.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

/// Schema version for AOT entrygraph compiler envelopes.
pub const SCHEMA_VERSION: &str = "franken-engine.aot-entrygraph-compiler.v1";

/// Bead identifier originating this module.
pub const BEAD_ID: &str = "bd-1lsy.7.10.2";

/// Component name used in provenance chains.
pub const COMPONENT: &str = "aot_entrygraph_compiler";

/// Policy identifier for compilation governance decisions.
pub const POLICY_ID: &str = "rgc-610b-aot-entrygraph";

/// Maximum number of modules in a single entrygraph.
pub const MAX_ENTRYGRAPH_MODULES: usize = 4096;

/// Maximum number of entrygraphs per compilation batch.
pub const MAX_BATCH_SIZE: usize = 256;

/// Default minimum module count before AOT is worthwhile.
pub const DEFAULT_MIN_MODULE_COUNT: u64 = 3;

/// Default maximum compile time budget in microseconds.
pub const DEFAULT_MAX_COMPILE_TIME_MICROS: u64 = 30_000_000; // 30s

/// One million — fixed-point unit.
const MILLION: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// EntryKind
// ---------------------------------------------------------------------------

/// Kind of entrygraph being compiled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A package entry (e.g. `main` or `exports` field).
    PackageMain,
    /// A package subpath export.
    PackageSubpath,
    /// An application entry file.
    AppEntry,
    /// A server-side rendering entry.
    SsrEntry,
    /// A React client component entry.
    ReactClientEntry,
    /// A worker/service-worker entry.
    WorkerEntry,
    /// A test harness entry (opt-in AOT for CI).
    TestEntry,
}

impl EntryKind {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [EntryKind] = &[
        EntryKind::PackageMain,
        EntryKind::PackageSubpath,
        EntryKind::AppEntry,
        EntryKind::SsrEntry,
        EntryKind::ReactClientEntry,
        EntryKind::WorkerEntry,
        EntryKind::TestEntry,
    ];
}

impl fmt::Display for EntryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackageMain => write!(f, "PackageMain"),
            Self::PackageSubpath => write!(f, "PackageSubpath"),
            Self::AppEntry => write!(f, "AppEntry"),
            Self::SsrEntry => write!(f, "SsrEntry"),
            Self::ReactClientEntry => write!(f, "ReactClientEntry"),
            Self::WorkerEntry => write!(f, "WorkerEntry"),
            Self::TestEntry => write!(f, "TestEntry"),
        }
    }
}

// ---------------------------------------------------------------------------
// CompileTarget
// ---------------------------------------------------------------------------

/// Target output format for the AOT compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompileTarget {
    /// Optimised bytecode for the baseline interpreter.
    OptimizedBytecode,
    /// Pre-lowered IR ready for the JIT tier-up path.
    PreLoweredIr,
    /// Frozen module graph snapshot for instant restore.
    FrozenSnapshot,
    /// Content-addressed cache artifact.
    CacheArtifact,
}

impl CompileTarget {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [CompileTarget] = &[
        CompileTarget::OptimizedBytecode,
        CompileTarget::PreLoweredIr,
        CompileTarget::FrozenSnapshot,
        CompileTarget::CacheArtifact,
    ];
}

impl fmt::Display for CompileTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OptimizedBytecode => write!(f, "OptimizedBytecode"),
            Self::PreLoweredIr => write!(f, "PreLoweredIr"),
            Self::FrozenSnapshot => write!(f, "FrozenSnapshot"),
            Self::CacheArtifact => write!(f, "CacheArtifact"),
        }
    }
}

// ---------------------------------------------------------------------------
// CompileStatus
// ---------------------------------------------------------------------------

/// Status of an individual module compilation within an entrygraph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompileStatus {
    /// Successfully compiled with provenance.
    Compiled,
    /// Skipped because the module is unsupported.
    Unsupported,
    /// Skipped because the module was already cached with matching hash.
    CacheHit,
    /// Compilation failed; fallback to runtime tier-up.
    Failed,
    /// Compilation was cancelled due to budget exhaustion.
    BudgetExhausted,
}

impl CompileStatus {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [CompileStatus] = &[
        CompileStatus::Compiled,
        CompileStatus::Unsupported,
        CompileStatus::CacheHit,
        CompileStatus::Failed,
        CompileStatus::BudgetExhausted,
    ];

    /// Whether this status represents a successful outcome.
    pub fn is_success(self) -> bool {
        matches!(self, Self::Compiled | Self::CacheHit)
    }
}

impl fmt::Display for CompileStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compiled => write!(f, "Compiled"),
            Self::Unsupported => write!(f, "Unsupported"),
            Self::CacheHit => write!(f, "CacheHit"),
            Self::Failed => write!(f, "Failed"),
            Self::BudgetExhausted => write!(f, "BudgetExhausted"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProvenanceKind
// ---------------------------------------------------------------------------

/// Kind of provenance record attached to a compiled artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    /// Source hash of the module text.
    SourceHash,
    /// Dependency graph hash covering transitive imports.
    DependencyGraphHash,
    /// Compiler configuration fingerprint.
    CompilerConfig,
    /// Policy revision that authorised the compilation.
    PolicyRevision,
    /// Engine version that performed the compilation.
    EngineVersion,
    /// Security epoch at compilation time.
    EpochStamp,
}

impl ProvenanceKind {
    /// All variants.
    pub const ALL: &'static [ProvenanceKind] = &[
        ProvenanceKind::SourceHash,
        ProvenanceKind::DependencyGraphHash,
        ProvenanceKind::CompilerConfig,
        ProvenanceKind::PolicyRevision,
        ProvenanceKind::EngineVersion,
        ProvenanceKind::EpochStamp,
    ];
}

impl fmt::Display for ProvenanceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceHash => write!(f, "SourceHash"),
            Self::DependencyGraphHash => write!(f, "DependencyGraphHash"),
            Self::CompilerConfig => write!(f, "CompilerConfig"),
            Self::PolicyRevision => write!(f, "PolicyRevision"),
            Self::EngineVersion => write!(f, "EngineVersion"),
            Self::EpochStamp => write!(f, "EpochStamp"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProvenanceRecord
// ---------------------------------------------------------------------------

/// A single provenance entry tying an artifact back to a specific input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    /// Kind of provenance.
    pub kind: ProvenanceKind,
    /// The content hash or value for this provenance entry.
    pub value_hash: ContentHash,
    /// Human-readable label (e.g. module specifier, policy id).
    pub label: String,
}

// ---------------------------------------------------------------------------
// ModuleEntry
// ---------------------------------------------------------------------------

/// A single module within an entrygraph submitted for AOT compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleEntry {
    /// Module specifier (resolved path or package subpath).
    pub specifier: String,
    /// Content hash of the module source.
    pub source_hash: ContentHash,
    /// Whether this module is the root entry of the entrygraph.
    pub is_root: bool,
    /// Transitive dependency count reachable from this module.
    pub dependency_count: u64,
    /// Size of the module source in bytes.
    pub source_size_bytes: u64,
}

// ---------------------------------------------------------------------------
// Entrygraph
// ---------------------------------------------------------------------------

/// An entrygraph: a rooted subgraph of the module graph suitable for AOT compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entrygraph {
    /// Unique identifier for this entrygraph.
    pub graph_id: String,
    /// Kind of entry this graph represents.
    pub entry_kind: EntryKind,
    /// Modules in topological order (root first).
    pub modules: Vec<ModuleEntry>,
    /// Hash covering the full graph structure.
    pub graph_hash: ContentHash,
    /// Package name, if applicable.
    pub package_name: Option<String>,
}

impl Entrygraph {
    /// Number of modules in this entrygraph.
    pub fn module_count(&self) -> u64 {
        self.modules.len() as u64
    }

    /// Total source bytes across all modules.
    pub fn total_source_bytes(&self) -> u64 {
        self.modules.iter().map(|m| m.source_size_bytes).sum()
    }
}

// ---------------------------------------------------------------------------
// CompileConfig
// ---------------------------------------------------------------------------

/// Configuration governing AOT entrygraph compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileConfig {
    /// Target output format.
    pub target: CompileTarget,
    /// Minimum number of modules before AOT is attempted.
    pub min_module_count: u64,
    /// Maximum compile time budget in microseconds.
    pub max_compile_time_micros: u64,
    /// Whether to require provenance for every artifact.
    pub require_provenance: bool,
    /// Whether to skip modules that are already cached.
    pub honour_cache: bool,
    /// Policy revision authorising compilation.
    pub policy_revision: u64,
    /// Engine version string.
    pub engine_version: String,
    /// Maximum source bytes per module to compile.
    pub max_module_source_bytes: u64,
    /// Allowed entry kinds (empty = all allowed).
    pub allowed_entry_kinds: BTreeSet<EntryKind>,
}

impl Default for CompileConfig {
    fn default() -> Self {
        Self {
            target: CompileTarget::OptimizedBytecode,
            min_module_count: DEFAULT_MIN_MODULE_COUNT,
            max_compile_time_micros: DEFAULT_MAX_COMPILE_TIME_MICROS,
            require_provenance: true,
            honour_cache: true,
            policy_revision: 1,
            engine_version: String::from("0.1.0"),
            max_module_source_bytes: 2 * 1024 * 1024, // 2 MiB
            allowed_entry_kinds: BTreeSet::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ModuleCompileResult
// ---------------------------------------------------------------------------

/// Result of compiling a single module within an entrygraph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCompileResult {
    /// Specifier of the compiled module.
    pub specifier: String,
    /// Compilation status.
    pub status: CompileStatus,
    /// Hash of the compiled artifact (if produced).
    pub artifact_hash: Option<ContentHash>,
    /// Provenance chain for this artifact.
    pub provenance: Vec<ProvenanceRecord>,
    /// Compile duration in microseconds.
    pub compile_time_micros: u64,
    /// Reason string if not compiled.
    pub skip_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// CompileVerdict
// ---------------------------------------------------------------------------

/// Overall verdict for an entrygraph compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompileVerdict {
    /// All modules successfully compiled or cache-hit.
    FullyCompiled,
    /// Some modules compiled, others skipped or failed.
    PartiallyCompiled,
    /// No modules were compiled (all unsupported or failed).
    NoneCompiled,
    /// Compilation was rejected by policy.
    PolicyRejected,
    /// The entrygraph was too small for AOT.
    BelowThreshold,
}

impl CompileVerdict {
    /// All variants.
    pub const ALL: &'static [CompileVerdict] = &[
        CompileVerdict::FullyCompiled,
        CompileVerdict::PartiallyCompiled,
        CompileVerdict::NoneCompiled,
        CompileVerdict::PolicyRejected,
        CompileVerdict::BelowThreshold,
    ];

    /// Whether this verdict permits the artifact to be used.
    pub fn is_usable(self) -> bool {
        matches!(self, Self::FullyCompiled | Self::PartiallyCompiled)
    }
}

impl fmt::Display for CompileVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FullyCompiled => write!(f, "FullyCompiled"),
            Self::PartiallyCompiled => write!(f, "PartiallyCompiled"),
            Self::NoneCompiled => write!(f, "NoneCompiled"),
            Self::PolicyRejected => write!(f, "PolicyRejected"),
            Self::BelowThreshold => write!(f, "BelowThreshold"),
        }
    }
}

// ---------------------------------------------------------------------------
// CompilationReport
// ---------------------------------------------------------------------------

/// Report for an entrygraph compilation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationReport {
    /// Graph identifier.
    pub graph_id: String,
    /// Entry kind of the compiled graph.
    pub entry_kind: EntryKind,
    /// Target that was compiled to.
    pub target: CompileTarget,
    /// Overall verdict.
    pub verdict: CompileVerdict,
    /// Per-module results.
    pub module_results: Vec<ModuleCompileResult>,
    /// Total compile time in microseconds.
    pub total_compile_time_micros: u64,
    /// Epoch at which compilation occurred.
    pub compile_epoch: SecurityEpoch,
    /// Success rate in millionths.
    pub success_rate_millionths: u64,
    /// Total modules attempted.
    pub total_modules: u64,
    /// Modules successfully compiled.
    pub compiled_count: u64,
    /// Modules with cache hits.
    pub cache_hit_count: u64,
    /// Modules that failed or were unsupported.
    pub failed_count: u64,
}

// ---------------------------------------------------------------------------
// BatchReport
// ---------------------------------------------------------------------------

/// Report for a batch of entrygraph compilations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReport {
    /// Schema version.
    pub schema_version: String,
    /// Individual compilation reports.
    pub reports: Vec<CompilationReport>,
    /// Epoch of the batch.
    pub batch_epoch: SecurityEpoch,
    /// Total graphs attempted.
    pub total_graphs: u64,
    /// Graphs with usable output.
    pub usable_graphs: u64,
    /// Aggregate success rate in millionths.
    pub aggregate_success_rate_millionths: u64,
    /// Batch hash covering all reports.
    pub batch_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Cryptographic receipt for a compilation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component that produced the receipt.
    pub component: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Graph identifier.
    pub graph_id: String,
    /// Verdict.
    pub verdict: CompileVerdict,
    /// Hash of the input configuration.
    pub config_hash: ContentHash,
    /// Hash of the entrygraph.
    pub graph_hash: ContentHash,
    /// Hash of all module results.
    pub results_hash: ContentHash,
    /// Epoch at which the decision was made.
    pub decision_epoch: SecurityEpoch,
    /// Chain hash tying this receipt to the input evidence.
    pub receipt_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// CompileError
// ---------------------------------------------------------------------------

/// Errors produced by the AOT entrygraph compiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompileError {
    /// The entrygraph has no modules.
    EmptyGraph,
    /// The entrygraph exceeds the maximum module count.
    GraphTooLarge { module_count: usize, max: usize },
    /// Batch exceeds the maximum size.
    BatchTooLarge { batch_size: usize, max: usize },
    /// The entry kind is not allowed by policy.
    EntryKindDisallowed { kind: EntryKind },
    /// Configuration is invalid.
    InvalidConfig { reason: String },
    /// Module source exceeds maximum size.
    ModuleTooLarge {
        specifier: String,
        size: u64,
        max: u64,
    },
    /// The entrygraph has no root module.
    NoRootModule,
    /// Multiple root modules found (exactly one expected).
    MultipleRoots { count: usize },
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyGraph => write!(f, "entrygraph has no modules"),
            Self::GraphTooLarge { module_count, max } => {
                write!(f, "entrygraph has {module_count} modules, max {max}")
            }
            Self::BatchTooLarge { batch_size, max } => {
                write!(f, "batch has {batch_size} graphs, max {max}")
            }
            Self::EntryKindDisallowed { kind } => {
                write!(f, "entry kind {kind} is not allowed by policy")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid config: {reason}")
            }
            Self::ModuleTooLarge {
                specifier,
                size,
                max,
            } => {
                write!(f, "module {specifier} is {size} bytes, max {max}")
            }
            Self::NoRootModule => write!(f, "entrygraph has no root module"),
            Self::MultipleRoots { count } => {
                write!(f, "entrygraph has {count} root modules, expected 1")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a compile configuration.
pub fn validate_config(config: &CompileConfig) -> Result<(), CompileError> {
    if config.min_module_count == 0 {
        return Err(CompileError::InvalidConfig {
            reason: "min_module_count must be at least 1".into(),
        });
    }
    if config.max_compile_time_micros == 0 {
        return Err(CompileError::InvalidConfig {
            reason: "max_compile_time_micros must be positive".into(),
        });
    }
    if config.max_module_source_bytes == 0 {
        return Err(CompileError::InvalidConfig {
            reason: "max_module_source_bytes must be positive".into(),
        });
    }
    if config.engine_version.is_empty() {
        return Err(CompileError::InvalidConfig {
            reason: "engine_version must not be empty".into(),
        });
    }
    Ok(())
}

/// Validate an entrygraph before compilation.
pub fn validate_entrygraph(graph: &Entrygraph, config: &CompileConfig) -> Result<(), CompileError> {
    if graph.modules.is_empty() {
        return Err(CompileError::EmptyGraph);
    }
    if graph.modules.len() > MAX_ENTRYGRAPH_MODULES {
        return Err(CompileError::GraphTooLarge {
            module_count: graph.modules.len(),
            max: MAX_ENTRYGRAPH_MODULES,
        });
    }
    let root_count = graph.modules.iter().filter(|m| m.is_root).count();
    if root_count == 0 {
        return Err(CompileError::NoRootModule);
    }
    if root_count > 1 {
        return Err(CompileError::MultipleRoots { count: root_count });
    }
    if !config.allowed_entry_kinds.is_empty()
        && !config.allowed_entry_kinds.contains(&graph.entry_kind)
    {
        return Err(CompileError::EntryKindDisallowed {
            kind: graph.entry_kind,
        });
    }
    for m in &graph.modules {
        if m.source_size_bytes > config.max_module_source_bytes {
            return Err(CompileError::ModuleTooLarge {
                specifier: m.specifier.clone(),
                size: m.source_size_bytes,
                max: config.max_module_source_bytes,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Compilation core
// ---------------------------------------------------------------------------

/// Build a provenance chain for a compiled module.
fn build_provenance(
    module: &ModuleEntry,
    graph: &Entrygraph,
    config: &CompileConfig,
    epoch: SecurityEpoch,
) -> Vec<ProvenanceRecord> {
    let mut prov = Vec::new();
    prov.push(ProvenanceRecord {
        kind: ProvenanceKind::SourceHash,
        value_hash: module.source_hash.clone(),
        label: module.specifier.clone(),
    });
    prov.push(ProvenanceRecord {
        kind: ProvenanceKind::DependencyGraphHash,
        value_hash: graph.graph_hash.clone(),
        label: graph.graph_id.clone(),
    });
    let config_bytes = format!(
        "{}:{}:{}",
        config.target, config.policy_revision, config.engine_version
    );
    prov.push(ProvenanceRecord {
        kind: ProvenanceKind::CompilerConfig,
        value_hash: ContentHash::compute(config_bytes.as_bytes()),
        label: format!("target={}", config.target),
    });
    let policy_bytes = config.policy_revision.to_le_bytes();
    prov.push(ProvenanceRecord {
        kind: ProvenanceKind::PolicyRevision,
        value_hash: ContentHash::compute(&policy_bytes),
        label: format!("rev={}", config.policy_revision),
    });
    prov.push(ProvenanceRecord {
        kind: ProvenanceKind::EngineVersion,
        value_hash: ContentHash::compute(config.engine_version.as_bytes()),
        label: config.engine_version.clone(),
    });
    let epoch_bytes = epoch.as_u64().to_le_bytes();
    prov.push(ProvenanceRecord {
        kind: ProvenanceKind::EpochStamp,
        value_hash: ContentHash::compute(&epoch_bytes),
        label: format!("epoch={}", epoch.as_u64()),
    });
    prov
}

/// Simulate compiling a single module, producing a result with provenance.
fn compile_module(
    module: &ModuleEntry,
    graph: &Entrygraph,
    config: &CompileConfig,
    epoch: SecurityEpoch,
    _remaining_budget_micros: u64,
) -> ModuleCompileResult {
    // Check module size
    if module.source_size_bytes > config.max_module_source_bytes {
        return ModuleCompileResult {
            specifier: module.specifier.clone(),
            status: CompileStatus::Unsupported,
            artifact_hash: None,
            provenance: Vec::new(),
            compile_time_micros: 0,
            skip_reason: Some(format!(
                "source {} bytes exceeds max {}",
                module.source_size_bytes, config.max_module_source_bytes
            )),
        };
    }

    // Simulate compilation: artifact hash is derived from source + config
    let mut hasher = Sha256::new();
    hasher.update(module.source_hash.as_bytes());
    hasher.update(graph.graph_hash.as_bytes());
    hasher.update(config.engine_version.as_bytes());
    hasher.update(config.policy_revision.to_le_bytes());
    hasher.update(config.target.to_string().as_bytes());
    let artifact_hash = ContentHash::compute(&hasher.finalize());

    let provenance = if config.require_provenance {
        build_provenance(module, graph, config, epoch)
    } else {
        Vec::new()
    };

    // Simulate compile time proportional to source size
    let compile_time = module.source_size_bytes / 100 + 1;

    ModuleCompileResult {
        specifier: module.specifier.clone(),
        status: CompileStatus::Compiled,
        artifact_hash: Some(artifact_hash),
        provenance,
        compile_time_micros: compile_time,
        skip_reason: None,
    }
}

/// Compile a single entrygraph, returning a compilation report.
pub fn compile_entrygraph(
    graph: &Entrygraph,
    config: &CompileConfig,
    epoch: SecurityEpoch,
) -> Result<CompilationReport, CompileError> {
    validate_config(config)?;
    validate_entrygraph(graph, config)?;

    // Below threshold check
    if graph.module_count() < config.min_module_count {
        return Ok(CompilationReport {
            graph_id: graph.graph_id.clone(),
            entry_kind: graph.entry_kind,
            target: config.target,
            verdict: CompileVerdict::BelowThreshold,
            module_results: Vec::new(),
            total_compile_time_micros: 0,
            compile_epoch: epoch,
            success_rate_millionths: 0,
            total_modules: graph.module_count(),
            compiled_count: 0,
            cache_hit_count: 0,
            failed_count: 0,
        });
    }

    let mut results = Vec::with_capacity(graph.modules.len());
    let mut total_time: u64 = 0;
    let mut compiled: u64 = 0;
    let mut cache_hits: u64 = 0;
    let mut failed: u64 = 0;

    for module in &graph.modules {
        let remaining = config.max_compile_time_micros.saturating_sub(total_time);
        if remaining == 0 {
            results.push(ModuleCompileResult {
                specifier: module.specifier.clone(),
                status: CompileStatus::BudgetExhausted,
                artifact_hash: None,
                provenance: Vec::new(),
                compile_time_micros: 0,
                skip_reason: Some("compile time budget exhausted".into()),
            });
            failed += 1;
            continue;
        }

        let result = compile_module(module, graph, config, epoch, remaining);
        total_time = total_time.saturating_add(result.compile_time_micros);

        match result.status {
            CompileStatus::Compiled => compiled += 1,
            CompileStatus::CacheHit => cache_hits += 1,
            CompileStatus::Unsupported | CompileStatus::Failed | CompileStatus::BudgetExhausted => {
                failed += 1;
            }
        }
        results.push(result);
    }

    let total = graph.module_count();
    let success = compiled + cache_hits;
    let success_rate = success
        .saturating_mul(MILLION)
        .checked_div(total)
        .unwrap_or(0);

    let verdict = if success == total {
        CompileVerdict::FullyCompiled
    } else if success > 0 {
        CompileVerdict::PartiallyCompiled
    } else {
        CompileVerdict::NoneCompiled
    };

    Ok(CompilationReport {
        graph_id: graph.graph_id.clone(),
        entry_kind: graph.entry_kind,
        target: config.target,
        verdict,
        module_results: results,
        total_compile_time_micros: total_time,
        compile_epoch: epoch,
        success_rate_millionths: success_rate,
        total_modules: total,
        compiled_count: compiled,
        cache_hit_count: cache_hits,
        failed_count: failed,
    })
}

/// Compile a batch of entrygraphs.
pub fn compile_batch(
    graphs: &[Entrygraph],
    config: &CompileConfig,
    epoch: SecurityEpoch,
) -> Result<BatchReport, CompileError> {
    if graphs.len() > MAX_BATCH_SIZE {
        return Err(CompileError::BatchTooLarge {
            batch_size: graphs.len(),
            max: MAX_BATCH_SIZE,
        });
    }
    validate_config(config)?;

    let mut reports = Vec::with_capacity(graphs.len());
    let mut usable: u64 = 0;
    let mut total_success: u64 = 0;
    let mut total_modules: u64 = 0;

    for graph in graphs {
        let report = compile_entrygraph(graph, config, epoch)?;
        if report.verdict.is_usable() {
            usable += 1;
        }
        total_success += report.compiled_count + report.cache_hit_count;
        total_modules += report.total_modules;
        reports.push(report);
    }

    let aggregate_rate = total_success
        .saturating_mul(MILLION)
        .checked_div(total_modules)
        .unwrap_or(0);

    let batch_hash = compute_batch_hash(&reports);

    Ok(BatchReport {
        schema_version: SCHEMA_VERSION.to_string(),
        reports,
        batch_epoch: epoch,
        total_graphs: graphs.len() as u64,
        usable_graphs: usable,
        aggregate_success_rate_millionths: aggregate_rate,
        batch_hash,
    })
}

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

/// Compute a hash over a compilation report's module results.
pub fn compute_results_hash(results: &[ModuleCompileResult]) -> ContentHash {
    let mut hasher = Sha256::new();
    for r in results {
        hasher.update(r.specifier.as_bytes());
        hasher.update(r.status.to_string().as_bytes());
        if let Some(ref h) = r.artifact_hash {
            hasher.update(h.as_bytes());
        }
        hasher.update(r.compile_time_micros.to_le_bytes());
    }
    ContentHash::compute(&hasher.finalize())
}

/// Compute a hash over a compile configuration.
pub fn compute_config_hash(config: &CompileConfig) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(config.target.to_string().as_bytes());
    hasher.update(config.min_module_count.to_le_bytes());
    hasher.update(config.max_compile_time_micros.to_le_bytes());
    hasher.update([config.require_provenance as u8]);
    hasher.update([config.honour_cache as u8]);
    hasher.update(config.policy_revision.to_le_bytes());
    hasher.update(config.engine_version.as_bytes());
    hasher.update(config.max_module_source_bytes.to_le_bytes());
    ContentHash::compute(&hasher.finalize())
}

/// Compute a batch hash over all compilation reports.
fn compute_batch_hash(reports: &[CompilationReport]) -> ContentHash {
    let mut hasher = Sha256::new();
    for r in reports {
        hasher.update(r.graph_id.as_bytes());
        hasher.update(r.verdict.to_string().as_bytes());
        hasher.update(r.success_rate_millionths.to_le_bytes());
    }
    ContentHash::compute(&hasher.finalize())
}

/// Compute the receipt hash for a decision receipt.
fn compute_receipt_hash(
    graph_id: &str,
    verdict: CompileVerdict,
    config_hash: ContentHash,
    graph_hash: ContentHash,
    results_hash: ContentHash,
    epoch: SecurityEpoch,
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    hasher.update(COMPONENT.as_bytes());
    hasher.update(graph_id.as_bytes());
    hasher.update(verdict.to_string().as_bytes());
    hasher.update(config_hash.as_bytes());
    hasher.update(graph_hash.as_bytes());
    hasher.update(results_hash.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    ContentHash::compute(&hasher.finalize())
}

/// Build a decision receipt from a compilation report.
pub fn build_receipt(
    report: &CompilationReport,
    graph_hash: ContentHash,
    config: &CompileConfig,
) -> DecisionReceipt {
    let config_hash = compute_config_hash(config);
    let results_hash = compute_results_hash(&report.module_results);
    let receipt_hash = compute_receipt_hash(
        &report.graph_id,
        report.verdict,
        config_hash.clone(),
        graph_hash.clone(),
        results_hash.clone(),
        report.compile_epoch,
    );

    DecisionReceipt {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        graph_id: report.graph_id.clone(),
        verdict: report.verdict,
        config_hash,
        graph_hash,
        results_hash,
        decision_epoch: report.compile_epoch,
        receipt_hash,
    }
}

// ---------------------------------------------------------------------------
// Summary helpers
// ---------------------------------------------------------------------------

/// Collect per-entry-kind statistics from a batch report.
pub fn entry_kind_summary(report: &BatchReport) -> BTreeMap<EntryKind, (u64, u64)> {
    let mut summary = BTreeMap::new();
    for r in &report.reports {
        let entry = summary.entry(r.entry_kind).or_insert((0u64, 0u64));
        entry.0 += 1; // total
        if r.verdict.is_usable() {
            entry.1 += 1; // usable
        }
    }
    summary
}

/// Collect per-compile-target statistics from a batch report.
pub fn target_summary(report: &BatchReport) -> BTreeMap<CompileTarget, u64> {
    let mut summary = BTreeMap::new();
    for r in &report.reports {
        *summary.entry(r.target).or_insert(0) += 1;
    }
    summary
}

/// Compute the total artifact bytes from a batch (estimated from compile times).
pub fn total_compile_time_micros(report: &BatchReport) -> u64 {
    report
        .reports
        .iter()
        .map(|r| r.total_compile_time_micros)
        .sum()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_module(specifier: &str, size: u64, is_root: bool) -> ModuleEntry {
        ModuleEntry {
            specifier: specifier.to_string(),
            source_hash: ContentHash::compute(specifier.as_bytes()),
            is_root,
            dependency_count: 0,
            source_size_bytes: size,
        }
    }

    fn make_graph(id: &str, kind: EntryKind, modules: Vec<ModuleEntry>) -> Entrygraph {
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        for m in &modules {
            hasher.update(m.source_hash.as_bytes());
        }
        Entrygraph {
            graph_id: id.to_string(),
            entry_kind: kind,
            graph_hash: ContentHash::compute(&hasher.finalize()),
            modules,
            package_name: None,
        }
    }

    fn default_config() -> CompileConfig {
        CompileConfig::default()
    }

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    // --- EntryKind tests ---

    #[test]
    fn test_entry_kind_all_variants() {
        assert_eq!(EntryKind::ALL.len(), 7);
    }

    #[test]
    fn test_entry_kind_display() {
        assert_eq!(EntryKind::PackageMain.to_string(), "PackageMain");
        assert_eq!(EntryKind::SsrEntry.to_string(), "SsrEntry");
        assert_eq!(EntryKind::ReactClientEntry.to_string(), "ReactClientEntry");
    }

    #[test]
    fn test_entry_kind_serde_roundtrip() {
        for kind in EntryKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: EntryKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    // --- CompileTarget tests ---

    #[test]
    fn test_compile_target_all_variants() {
        assert_eq!(CompileTarget::ALL.len(), 4);
    }

    #[test]
    fn test_compile_target_display() {
        assert_eq!(
            CompileTarget::OptimizedBytecode.to_string(),
            "OptimizedBytecode"
        );
        assert_eq!(CompileTarget::FrozenSnapshot.to_string(), "FrozenSnapshot");
    }

    #[test]
    fn test_compile_target_serde_roundtrip() {
        for t in CompileTarget::ALL {
            let json = serde_json::to_string(t).unwrap();
            let back: CompileTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    // --- CompileStatus tests ---

    #[test]
    fn test_compile_status_is_success() {
        assert!(CompileStatus::Compiled.is_success());
        assert!(CompileStatus::CacheHit.is_success());
        assert!(!CompileStatus::Unsupported.is_success());
        assert!(!CompileStatus::Failed.is_success());
        assert!(!CompileStatus::BudgetExhausted.is_success());
    }

    #[test]
    fn test_compile_status_display() {
        assert_eq!(
            CompileStatus::BudgetExhausted.to_string(),
            "BudgetExhausted"
        );
    }

    #[test]
    fn test_compile_status_serde_roundtrip() {
        for s in CompileStatus::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: CompileStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- ProvenanceKind tests ---

    #[test]
    fn test_provenance_kind_all_variants() {
        assert_eq!(ProvenanceKind::ALL.len(), 6);
    }

    #[test]
    fn test_provenance_kind_display() {
        assert_eq!(ProvenanceKind::SourceHash.to_string(), "SourceHash");
        assert_eq!(ProvenanceKind::EpochStamp.to_string(), "EpochStamp");
    }

    // --- CompileVerdict tests ---

    #[test]
    fn test_compile_verdict_is_usable() {
        assert!(CompileVerdict::FullyCompiled.is_usable());
        assert!(CompileVerdict::PartiallyCompiled.is_usable());
        assert!(!CompileVerdict::NoneCompiled.is_usable());
        assert!(!CompileVerdict::PolicyRejected.is_usable());
        assert!(!CompileVerdict::BelowThreshold.is_usable());
    }

    #[test]
    fn test_compile_verdict_display() {
        assert_eq!(CompileVerdict::FullyCompiled.to_string(), "FullyCompiled");
    }

    #[test]
    fn test_compile_verdict_serde_roundtrip() {
        for v in CompileVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: CompileVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- Validation tests ---

    #[test]
    fn test_validate_config_default_ok() {
        assert!(validate_config(&default_config()).is_ok());
    }

    #[test]
    fn test_validate_config_zero_min_module_count() {
        let mut cfg = default_config();
        cfg.min_module_count = 0;
        assert!(matches!(
            validate_config(&cfg),
            Err(CompileError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn test_validate_config_zero_compile_time() {
        let mut cfg = default_config();
        cfg.max_compile_time_micros = 0;
        assert!(matches!(
            validate_config(&cfg),
            Err(CompileError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn test_validate_config_zero_module_bytes() {
        let mut cfg = default_config();
        cfg.max_module_source_bytes = 0;
        assert!(matches!(
            validate_config(&cfg),
            Err(CompileError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn test_validate_config_empty_engine_version() {
        let mut cfg = default_config();
        cfg.engine_version = String::new();
        assert!(matches!(
            validate_config(&cfg),
            Err(CompileError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn test_validate_entrygraph_empty() {
        let graph = make_graph("g1", EntryKind::AppEntry, vec![]);
        assert!(matches!(
            validate_entrygraph(&graph, &default_config()),
            Err(CompileError::EmptyGraph)
        ));
    }

    #[test]
    fn test_validate_entrygraph_no_root() {
        let m = make_module("a.js", 100, false);
        let graph = make_graph("g1", EntryKind::AppEntry, vec![m]);
        assert!(matches!(
            validate_entrygraph(&graph, &default_config()),
            Err(CompileError::NoRootModule)
        ));
    }

    #[test]
    fn test_validate_entrygraph_multiple_roots() {
        let m1 = make_module("a.js", 100, true);
        let m2 = make_module("b.js", 100, true);
        let graph = make_graph("g1", EntryKind::AppEntry, vec![m1, m2]);
        assert!(matches!(
            validate_entrygraph(&graph, &default_config()),
            Err(CompileError::MultipleRoots { count: 2 })
        ));
    }

    #[test]
    fn test_validate_entrygraph_disallowed_kind() {
        let m = make_module("a.js", 100, true);
        let graph = make_graph("g1", EntryKind::TestEntry, vec![m]);
        let mut cfg = default_config();
        cfg.allowed_entry_kinds.insert(EntryKind::AppEntry);
        assert!(matches!(
            validate_entrygraph(&graph, &cfg),
            Err(CompileError::EntryKindDisallowed {
                kind: EntryKind::TestEntry
            })
        ));
    }

    #[test]
    fn test_validate_entrygraph_module_too_large() {
        let m = make_module("big.js", 10_000_000, true);
        let graph = make_graph("g1", EntryKind::AppEntry, vec![m]);
        assert!(matches!(
            validate_entrygraph(&graph, &default_config()),
            Err(CompileError::ModuleTooLarge { .. })
        ));
    }

    #[test]
    fn test_validate_entrygraph_valid() {
        let m = make_module("a.js", 100, true);
        let graph = make_graph("g1", EntryKind::AppEntry, vec![m]);
        assert!(validate_entrygraph(&graph, &default_config()).is_ok());
    }

    // --- Compilation tests ---

    #[test]
    fn test_compile_single_module_graph() {
        let modules = vec![
            make_module("root.js", 500, true),
            make_module("dep1.js", 300, false),
            make_module("dep2.js", 200, false),
        ];
        let graph = make_graph("g1", EntryKind::AppEntry, modules);
        let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
        assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
        assert_eq!(report.compiled_count, 3);
        assert_eq!(report.total_modules, 3);
        assert_eq!(report.success_rate_millionths, MILLION);
    }

    #[test]
    fn test_compile_below_threshold() {
        let m = make_module("solo.js", 100, true);
        let graph = make_graph("g1", EntryKind::AppEntry, vec![m]);
        let mut cfg = default_config();
        cfg.min_module_count = 5;
        let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
        assert_eq!(report.verdict, CompileVerdict::BelowThreshold);
        assert_eq!(report.compiled_count, 0);
    }

    #[test]
    fn test_compile_provenance_attached() {
        let modules = vec![
            make_module("root.js", 500, true),
            make_module("dep.js", 300, false),
            make_module("dep2.js", 200, false),
        ];
        let graph = make_graph("g1", EntryKind::PackageMain, modules);
        let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
        for r in &report.module_results {
            assert_eq!(r.provenance.len(), 6); // all 6 provenance kinds
            assert!(r.artifact_hash.is_some());
        }
    }

    #[test]
    fn test_compile_no_provenance_when_disabled() {
        let modules = vec![
            make_module("r.js", 200, true),
            make_module("d1.js", 100, false),
            make_module("d2.js", 100, false),
        ];
        let graph = make_graph("g1", EntryKind::AppEntry, modules);
        let mut cfg = default_config();
        cfg.require_provenance = false;
        let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
        for r in &report.module_results {
            assert!(r.provenance.is_empty());
        }
    }

    #[test]
    fn test_compile_artifact_hash_deterministic() {
        let modules = vec![
            make_module("a.js", 100, true),
            make_module("b.js", 100, false),
            make_module("c.js", 100, false),
        ];
        let g1 = make_graph("g1", EntryKind::AppEntry, modules.clone());
        let g2 = make_graph("g1", EntryKind::AppEntry, modules);
        let r1 = compile_entrygraph(&g1, &default_config(), epoch()).unwrap();
        let r2 = compile_entrygraph(&g2, &default_config(), epoch()).unwrap();
        assert_eq!(
            r1.module_results[0].artifact_hash,
            r2.module_results[0].artifact_hash
        );
    }

    #[test]
    fn test_compile_different_config_different_hash() {
        let modules = vec![
            make_module("a.js", 100, true),
            make_module("b.js", 100, false),
            make_module("c.js", 100, false),
        ];
        let graph = make_graph("g1", EntryKind::AppEntry, modules);
        let mut cfg2 = default_config();
        cfg2.policy_revision = 99;
        let r1 = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
        let r2 = compile_entrygraph(&graph, &cfg2, epoch()).unwrap();
        assert_ne!(
            r1.module_results[0].artifact_hash,
            r2.module_results[0].artifact_hash
        );
    }

    // --- Batch tests ---

    #[test]
    fn test_compile_batch_empty() {
        let report = compile_batch(&[], &default_config(), epoch()).unwrap();
        assert_eq!(report.total_graphs, 0);
        assert_eq!(report.usable_graphs, 0);
    }

    #[test]
    fn test_compile_batch_multiple_graphs() {
        let g1 = make_graph(
            "g1",
            EntryKind::AppEntry,
            vec![
                make_module("a.js", 100, true),
                make_module("b.js", 100, false),
                make_module("c.js", 100, false),
            ],
        );
        let g2 = make_graph(
            "g2",
            EntryKind::SsrEntry,
            vec![
                make_module("s.js", 200, true),
                make_module("s2.js", 100, false),
                make_module("s3.js", 50, false),
            ],
        );
        let report = compile_batch(&[g1, g2], &default_config(), epoch()).unwrap();
        assert_eq!(report.total_graphs, 2);
        assert_eq!(report.usable_graphs, 2);
        assert_eq!(report.aggregate_success_rate_millionths, MILLION);
    }

    #[test]
    fn test_compile_batch_too_large() {
        let graphs: Vec<Entrygraph> = (0..MAX_BATCH_SIZE + 1)
            .map(|i| {
                make_graph(
                    &format!("g{i}"),
                    EntryKind::AppEntry,
                    vec![make_module(&format!("m{i}.js"), 100, true)],
                )
            })
            .collect();
        assert!(matches!(
            compile_batch(&graphs, &default_config(), epoch()),
            Err(CompileError::BatchTooLarge { .. })
        ));
    }

    // --- Receipt tests ---

    #[test]
    fn test_build_receipt() {
        let modules = vec![
            make_module("a.js", 100, true),
            make_module("b.js", 100, false),
            make_module("c.js", 100, false),
        ];
        let graph = make_graph("g1", EntryKind::AppEntry, modules);
        let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
        let receipt = build_receipt(&report, graph.graph_hash, &default_config());
        assert_eq!(receipt.schema_version, SCHEMA_VERSION);
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.bead_id, BEAD_ID);
        assert_eq!(receipt.graph_id, "g1");
        assert_eq!(receipt.verdict, CompileVerdict::FullyCompiled);
    }

    #[test]
    fn test_receipt_deterministic() {
        let modules = vec![
            make_module("x.js", 100, true),
            make_module("y.js", 50, false),
            make_module("z.js", 50, false),
        ];
        let graph = make_graph("gd", EntryKind::PackageMain, modules);
        let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
        let r1 = build_receipt(&report, graph.graph_hash, &default_config());
        let r2 = build_receipt(&report, graph.graph_hash, &default_config());
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    // --- Hash helper tests ---

    #[test]
    fn test_compute_config_hash_deterministic() {
        let h1 = compute_config_hash(&default_config());
        let h2 = compute_config_hash(&default_config());
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_config_hash_different_targets() {
        let mut c1 = default_config();
        let mut c2 = default_config();
        c1.target = CompileTarget::OptimizedBytecode;
        c2.target = CompileTarget::FrozenSnapshot;
        assert_ne!(compute_config_hash(&c1), compute_config_hash(&c2));
    }

    #[test]
    fn test_compute_results_hash_deterministic() {
        let results = vec![ModuleCompileResult {
            specifier: "a.js".into(),
            status: CompileStatus::Compiled,
            artifact_hash: Some(ContentHash::compute(b"art")),
            provenance: vec![],
            compile_time_micros: 100,
            skip_reason: None,
        }];
        let h1 = compute_results_hash(&results);
        let h2 = compute_results_hash(&results);
        assert_eq!(h1, h2);
    }

    // --- Summary tests ---

    #[test]
    fn test_entry_kind_summary() {
        let g1 = make_graph(
            "g1",
            EntryKind::AppEntry,
            vec![
                make_module("a.js", 100, true),
                make_module("b.js", 50, false),
                make_module("c.js", 50, false),
            ],
        );
        let g2 = make_graph(
            "g2",
            EntryKind::AppEntry,
            vec![
                make_module("d.js", 100, true),
                make_module("e.js", 50, false),
                make_module("f.js", 50, false),
            ],
        );
        let batch = compile_batch(&[g1, g2], &default_config(), epoch()).unwrap();
        let summary = entry_kind_summary(&batch);
        assert_eq!(summary[&EntryKind::AppEntry], (2, 2));
    }

    #[test]
    fn test_target_summary() {
        let g = make_graph(
            "g1",
            EntryKind::AppEntry,
            vec![
                make_module("a.js", 100, true),
                make_module("b.js", 50, false),
                make_module("c.js", 50, false),
            ],
        );
        let batch = compile_batch(&[g], &default_config(), epoch()).unwrap();
        let summary = target_summary(&batch);
        assert_eq!(summary[&CompileTarget::OptimizedBytecode], 1);
    }

    #[test]
    fn test_total_compile_time() {
        let g = make_graph(
            "g1",
            EntryKind::AppEntry,
            vec![
                make_module("a.js", 100, true),
                make_module("b.js", 200, false),
                make_module("c.js", 300, false),
            ],
        );
        let batch = compile_batch(&[g], &default_config(), epoch()).unwrap();
        assert!(total_compile_time_micros(&batch) > 0);
    }

    // --- Entrygraph helper tests ---

    #[test]
    fn test_entrygraph_module_count() {
        let g = make_graph(
            "g1",
            EntryKind::AppEntry,
            vec![
                make_module("a.js", 100, true),
                make_module("b.js", 50, false),
            ],
        );
        assert_eq!(g.module_count(), 2);
    }

    #[test]
    fn test_entrygraph_total_source_bytes() {
        let g = make_graph(
            "g1",
            EntryKind::AppEntry,
            vec![
                make_module("a.js", 100, true),
                make_module("b.js", 200, false),
            ],
        );
        assert_eq!(g.total_source_bytes(), 300);
    }

    // --- Error display tests ---

    #[test]
    fn test_error_display_empty_graph() {
        let e = CompileError::EmptyGraph;
        assert_eq!(e.to_string(), "entrygraph has no modules");
    }

    #[test]
    fn test_error_display_graph_too_large() {
        let e = CompileError::GraphTooLarge {
            module_count: 5000,
            max: 4096,
        };
        assert!(e.to_string().contains("5000"));
    }

    #[test]
    fn test_error_display_batch_too_large() {
        let e = CompileError::BatchTooLarge {
            batch_size: 300,
            max: 256,
        };
        assert!(e.to_string().contains("300"));
    }

    #[test]
    fn test_error_display_disallowed_kind() {
        let e = CompileError::EntryKindDisallowed {
            kind: EntryKind::TestEntry,
        };
        assert!(e.to_string().contains("TestEntry"));
    }

    #[test]
    fn test_error_display_module_too_large() {
        let e = CompileError::ModuleTooLarge {
            specifier: "big.js".into(),
            size: 999,
            max: 100,
        };
        assert!(e.to_string().contains("big.js"));
    }

    #[test]
    fn test_error_display_no_root() {
        let e = CompileError::NoRootModule;
        assert!(e.to_string().contains("no root"));
    }

    #[test]
    fn test_error_display_multiple_roots() {
        let e = CompileError::MultipleRoots { count: 3 };
        assert!(e.to_string().contains("3"));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let errors = vec![
            CompileError::EmptyGraph,
            CompileError::NoRootModule,
            CompileError::MultipleRoots { count: 2 },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: CompileError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    // --- Constants tests ---

    #[test]
    fn test_schema_constants() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!COMPONENT.is_empty());
        assert!(!POLICY_ID.is_empty());
    }

    #[test]
    fn test_max_constants() {
        assert!(MAX_ENTRYGRAPH_MODULES > 0);
        assert!(MAX_BATCH_SIZE > 0);
    }

    // --- Compile with different targets ---

    #[test]
    fn test_compile_all_targets() {
        for target in CompileTarget::ALL {
            let modules = vec![
                make_module("root.js", 100, true),
                make_module("dep.js", 50, false),
                make_module("dep2.js", 50, false),
            ];
            let graph = make_graph("gt", EntryKind::AppEntry, modules);
            let mut cfg = default_config();
            cfg.target = *target;
            let report = compile_entrygraph(&graph, &cfg, epoch()).unwrap();
            assert_eq!(report.target, *target);
            assert_eq!(report.verdict, CompileVerdict::FullyCompiled);
        }
    }

    // --- Compile with all entry kinds ---

    #[test]
    fn test_compile_all_entry_kinds() {
        for kind in EntryKind::ALL {
            let modules = vec![
                make_module("root.js", 100, true),
                make_module("dep.js", 50, false),
                make_module("dep2.js", 50, false),
            ];
            let graph = make_graph("gk", *kind, modules);
            let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
            assert_eq!(report.entry_kind, *kind);
        }
    }

    #[test]
    fn test_report_serde_roundtrip() {
        let modules = vec![
            make_module("a.js", 100, true),
            make_module("b.js", 50, false),
            make_module("c.js", 50, false),
        ];
        let graph = make_graph("g1", EntryKind::AppEntry, modules);
        let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let back: CompilationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn test_batch_report_serde_roundtrip() {
        let g = make_graph(
            "g1",
            EntryKind::AppEntry,
            vec![
                make_module("a.js", 100, true),
                make_module("b.js", 50, false),
                make_module("c.js", 50, false),
            ],
        );
        let batch = compile_batch(&[g], &default_config(), epoch()).unwrap();
        let json = serde_json::to_string(&batch).unwrap();
        let back: BatchReport = serde_json::from_str(&json).unwrap();
        assert_eq!(batch, back);
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let modules = vec![
            make_module("a.js", 100, true),
            make_module("b.js", 50, false),
            make_module("c.js", 50, false),
        ];
        let graph = make_graph("g1", EntryKind::AppEntry, modules);
        let report = compile_entrygraph(&graph, &default_config(), epoch()).unwrap();
        let receipt = build_receipt(&report, graph.graph_hash, &default_config());
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }
}
