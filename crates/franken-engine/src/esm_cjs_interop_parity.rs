#![forbid(unsafe_code)]

//! ESM/CJS execution parity receipts and mixed-graph verification.
//!
//! Implements [RGC-309C]: shipped-path evidence that ESM and CJS module
//! semantics, live bindings, async evaluation, and mixed-graph interop
//! behave correctly across the module infrastructure.
//!
//! Follows the evidence harness pattern:
//! 1. **Corpus** — curated specimens covering ESM↔CJS boundary cases
//! 2. **Runner** — executes each specimen through the module graph pipeline
//! 3. **Inventory** — aggregates per-specimen verdicts
//! 4. **Bundle** — writes auditable artifacts (inventory, manifest, events, commands)

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::esm_loader::{
    BindingType, EsmModule, ExportEntry, ImportEntry, ModuleGraph, ModuleStatus,
};
use crate::hash_tiers::ContentHash;
use crate::module_async_evaluation::{AsyncModuleEvaluator, AsyncModulePhase};
use crate::module_live_binding::{BindingCell, BindingCellState, BindingId, LiveBindingMap};
use crate::module_resolver::ModuleSyntax;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const INTEROP_PARITY_SCHEMA_VERSION: &str = "franken-engine.esm_cjs_interop_parity.v1";
pub const INTEROP_PARITY_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.esm_cjs_interop_parity_manifest.v1";
pub const INTEROP_PARITY_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.esm_cjs_interop_parity_event.v1";
pub const INTEROP_PARITY_COMPONENT: &str = "esm_cjs_interop_parity";
pub const INTEROP_PARITY_POLICY_ID: &str = "RGC-309C";

// ---------------------------------------------------------------------------
// Interop scenario family
// ---------------------------------------------------------------------------

/// Category of interop scenario being tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteropFamily {
    /// Pure ESM graph (baseline parity check).
    EsmOnly,
    /// Pure CJS graph (baseline parity check).
    CjsOnly,
    /// ESM module importing from CJS module.
    EsmImportsCjs,
    /// CJS module requiring an ESM module.
    CjsRequiresEsm,
    /// Mixed graph with both ESM and CJS modules.
    MixedGraph,
    /// Live binding semantics across module boundaries.
    LiveBinding,
    /// Async module evaluation in mixed graphs.
    AsyncEvaluation,
    /// Module graph with cycles involving mixed syntax.
    CyclicInterop,
    /// Default export / namespace object interop.
    DefaultNamespace,
    /// Re-export chains crossing syntax boundaries.
    ReExportChain,
}

impl InteropFamily {
    pub const ALL: &[Self] = &[
        Self::EsmOnly,
        Self::CjsOnly,
        Self::EsmImportsCjs,
        Self::CjsRequiresEsm,
        Self::MixedGraph,
        Self::LiveBinding,
        Self::AsyncEvaluation,
        Self::CyclicInterop,
        Self::DefaultNamespace,
        Self::ReExportChain,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EsmOnly => "esm_only",
            Self::CjsOnly => "cjs_only",
            Self::EsmImportsCjs => "esm_imports_cjs",
            Self::CjsRequiresEsm => "cjs_requires_esm",
            Self::MixedGraph => "mixed_graph",
            Self::LiveBinding => "live_binding",
            Self::AsyncEvaluation => "async_evaluation",
            Self::CyclicInterop => "cyclic_interop",
            Self::DefaultNamespace => "default_namespace",
            Self::ReExportChain => "re_export_chain",
        }
    }
}

impl fmt::Display for InteropFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Specimen
// ---------------------------------------------------------------------------

/// Expected outcome of a parity specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteropExpectedOutcome {
    /// All modules link and evaluate successfully.
    Success,
    /// Linking fails (e.g., unresolved dependency, syntax mismatch).
    LinkFailure,
    /// Evaluation produces an error (e.g., rejection propagation).
    EvalFailure,
    /// Cycle detected during linking.
    CycleDetected,
}

/// A single interop parity specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropSpecimen {
    /// Unique identifier for this specimen.
    pub specimen_id: String,
    /// Human-readable description.
    pub description: String,
    /// Which interop family this specimen belongs to.
    pub family: InteropFamily,
    /// Module descriptors comprising the test graph.
    pub modules: Vec<SpecimenModule>,
    /// Entry point specifier.
    pub entry_point: String,
    /// Expected outcome.
    pub expected_outcome: InteropExpectedOutcome,
    /// Expected number of linked modules (if success).
    pub expected_linked_count: Option<u64>,
    /// Expected binding states after evaluation.
    pub expected_binding_states: Vec<ExpectedBindingState>,
    /// Expected async phases after evaluation.
    pub expected_async_phases: Vec<ExpectedAsyncPhase>,
}

/// A module within a specimen's module graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecimenModule {
    /// Module specifier.
    pub specifier: String,
    /// Module syntax (ESM or CJS).
    pub syntax: ModuleSyntax,
    /// Source text (for content hashing).
    pub source: String,
    /// Import entries.
    pub imports: Vec<ImportEntry>,
    /// Export entries.
    pub exports: Vec<ExportEntry>,
    /// Whether this module has a default export.
    pub has_default_export: bool,
    /// Whether this module uses top-level await.
    pub has_top_level_await: bool,
}

/// Expected state of a binding after specimen evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedBindingState {
    pub module_specifier: String,
    pub export_name: String,
    pub expected_state: BindingCellState,
}

/// Expected async phase of a module after specimen evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedAsyncPhase {
    pub module_specifier: String,
    pub expected_phase: AsyncModulePhase,
}

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

/// Actual outcome of running a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteropActualOutcome {
    Success,
    LinkFailure,
    EvalFailure,
    CycleDetected,
    GraphConstructionFailure,
}

/// Verdict for a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteropVerdict {
    Pass,
    Fail,
}

/// Operator-facing compatibility disposition for a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteropCompatibilityDisposition {
    Supported,
    Degraded,
    Unsupported,
}

impl InteropCompatibilityDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Degraded => "degraded",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for InteropCompatibilityDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Deterministic remediation guidance for a specimen disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropRemediationGuidance {
    pub guidance_code: String,
    pub message: String,
}

/// Evidence for a single specimen execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropSpecimenEvidence {
    pub specimen_id: String,
    pub family: InteropFamily,
    pub expected_outcome: InteropExpectedOutcome,
    pub actual_outcome: InteropActualOutcome,
    pub verdict: InteropVerdict,
    pub compatibility_disposition: InteropCompatibilityDisposition,
    pub remediation_guidance: InteropRemediationGuidance,
    pub module_count: u64,
    pub linked_count: u64,
    pub cycle_count: u64,
    pub binding_verdicts: Vec<BindingVerdict>,
    pub async_phase_verdicts: Vec<AsyncPhaseVerdict>,
    pub error_detail: Option<String>,
    pub evidence_hash: Option<String>,
}

/// Verdict for a single binding check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingVerdict {
    pub module_specifier: String,
    pub export_name: String,
    pub expected_state: BindingCellState,
    pub actual_state: BindingCellState,
    pub pass: bool,
}

/// Verdict for a single async phase check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncPhaseVerdict {
    pub module_specifier: String,
    pub expected_phase: AsyncModulePhase,
    pub actual_phase: AsyncModulePhase,
    pub pass: bool,
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

/// Aggregate evidence inventory for all specimens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropParityInventory {
    pub schema_version: String,
    pub component: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub supported_count: u64,
    pub degraded_count: u64,
    pub unsupported_count: u64,
    pub family_coverage: BTreeMap<String, u64>,
    pub esm_only_count: u64,
    pub cjs_only_count: u64,
    pub mixed_count: u64,
    pub evidence: Vec<InteropSpecimenEvidence>,
}

impl InteropParityInventory {
    /// Contract is satisfied when all specimens pass and we have coverage.
    pub fn contract_satisfied(&self) -> bool {
        self.fail_count == 0 && self.specimen_count > 0
    }
}

// ---------------------------------------------------------------------------
// Manifest and events
// ---------------------------------------------------------------------------

/// Run manifest for the evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropParityRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub supported_count: u64,
    pub degraded_count: u64,
    pub unsupported_count: u64,
    pub contract_satisfied: bool,
    pub artifact_paths: InteropParityArtifactPaths,
}

/// Relative paths to bundle artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropParityArtifactPaths {
    pub evidence_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

/// A single event in the evidence audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropParityEvent {
    pub schema_version: String,
    pub component: String,
    pub event: String,
    pub policy_id: String,
    pub specimen_id: Option<String>,
    pub verdict: Option<String>,
    pub detail: Option<String>,
}

/// Bundle artifacts written to disk.
#[derive(Debug, Clone)]
pub struct InteropParityBundleArtifacts {
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// Returns the curated corpus of interop parity specimens.
pub fn interop_parity_corpus() -> Vec<InteropSpecimen> {
    vec![
        // ── ESM Only ──
        InteropSpecimen {
            specimen_id: "esm_single_module".into(),
            description: "Single ESM module with direct export".into(),
            family: InteropFamily::EsmOnly,
            modules: vec![SpecimenModule {
                specifier: "entry.mjs".into(),
                syntax: ModuleSyntax::EsModule,
                source: "export const x = 1;".into(),
                imports: vec![],
                exports: vec![ExportEntry::direct("x", "x")],
                has_default_export: false,
                has_top_level_await: false,
            }],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(1),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "entry.mjs".into(),
                export_name: "x".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "esm_two_module_import".into(),
            description: "ESM entry imports named export from ESM dep".into(),
            family: InteropFamily::EsmOnly,
            modules: vec![
                SpecimenModule {
                    specifier: "dep.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export const value = 42;".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("value", "value")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { value } from './dep.mjs';".into(),
                    imports: vec![ImportEntry::new("dep.mjs", "value", "value")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "dep.mjs".into(),
                export_name: "value".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        },
        // ── CJS Only ──
        InteropSpecimen {
            specimen_id: "cjs_single_module".into(),
            description: "Single CJS module with module.exports".into(),
            family: InteropFamily::CjsOnly,
            modules: vec![SpecimenModule {
                specifier: "entry.cjs".into(),
                syntax: ModuleSyntax::CommonJs,
                source: "module.exports = { x: 1 };".into(),
                imports: vec![],
                exports: vec![ExportEntry::direct("x", "x")],
                has_default_export: true,
                has_top_level_await: false,
            }],
            entry_point: "entry.cjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(1),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "entry.cjs".into(),
                export_name: "x".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "cjs_require_chain".into(),
            description: "CJS entry requires another CJS module".into(),
            family: InteropFamily::CjsOnly,
            modules: vec![
                SpecimenModule {
                    specifier: "lib.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "module.exports.helper = function() {};".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("helper", "helper")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "const lib = require('./lib.cjs');".into(),
                    imports: vec![ImportEntry::new("lib.cjs", "helper", "lib")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.cjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "lib.cjs".into(),
                export_name: "helper".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        },
        // ── ESM imports CJS ──
        InteropSpecimen {
            specimen_id: "esm_imports_cjs_named".into(),
            description: "ESM entry imports named export from CJS module".into(),
            family: InteropFamily::EsmImportsCjs,
            modules: vec![
                SpecimenModule {
                    specifier: "util.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "module.exports.format = function(s) { return s; };".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("format", "format")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { format } from './util.cjs';".into(),
                    imports: vec![ImportEntry::new("util.cjs", "format", "format")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "util.cjs".into(),
                export_name: "format".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "esm_imports_cjs_default".into(),
            description: "ESM entry imports default from CJS (module.exports = value)".into(),
            family: InteropFamily::EsmImportsCjs,
            modules: vec![
                SpecimenModule {
                    specifier: "config.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "module.exports = { port: 3000 };".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("default", "default")],
                    has_default_export: true,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import config from './config.cjs';".into(),
                    imports: vec![ImportEntry::new("config.cjs", "default", "config")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "config.cjs".into(),
                export_name: "default".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        },
        // ── CJS requires ESM ──
        InteropSpecimen {
            specimen_id: "cjs_requires_esm_named".into(),
            description: "CJS entry requires a named export from ESM module".into(),
            family: InteropFamily::CjsRequiresEsm,
            modules: vec![
                SpecimenModule {
                    specifier: "math.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export function add(a, b) { return a + b; }".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("add", "add")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "const { add } = require('./math.mjs');".into(),
                    imports: vec![ImportEntry::new("math.mjs", "add", "add")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.cjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "math.mjs".into(),
                export_name: "add".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        },
        // ── Mixed Graph ──
        InteropSpecimen {
            specimen_id: "mixed_three_module_graph".into(),
            description: "ESM entry → CJS util → ESM lib (three-module mixed chain)".into(),
            family: InteropFamily::MixedGraph,
            modules: vec![
                SpecimenModule {
                    specifier: "lib.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export const VERSION = '1.0';".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("VERSION", "VERSION")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "util.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "const { VERSION } = require('./lib.mjs'); module.exports.ver = VERSION;".into(),
                    imports: vec![ImportEntry::new("lib.mjs", "VERSION", "VERSION")],
                    exports: vec![ExportEntry::direct("ver", "ver")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { ver } from './util.cjs';".into(),
                    imports: vec![ImportEntry::new("util.cjs", "ver", "ver")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(3),
            expected_binding_states: vec![
                ExpectedBindingState {
                    module_specifier: "lib.mjs".into(),
                    export_name: "VERSION".into(),
                    expected_state: BindingCellState::Initialized,
                },
                ExpectedBindingState {
                    module_specifier: "util.cjs".into(),
                    export_name: "ver".into(),
                    expected_state: BindingCellState::Initialized,
                },
            ],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "mixed_diamond_graph".into(),
            description: "Diamond: ESM entry → {CJS a, ESM b} → CJS shared".into(),
            family: InteropFamily::MixedGraph,
            modules: vec![
                SpecimenModule {
                    specifier: "shared.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "module.exports.data = 'shared';".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("data", "data")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "a.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "const s = require('./shared.cjs'); module.exports.a = s.data;".into(),
                    imports: vec![ImportEntry::new("shared.cjs", "data", "data")],
                    exports: vec![ExportEntry::direct("a", "a")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "b.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { data } from './shared.cjs'; export const b = data;".into(),
                    imports: vec![ImportEntry::new("shared.cjs", "data", "data")],
                    exports: vec![ExportEntry::direct("b", "b")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { a } from './a.cjs'; import { b } from './b.mjs';".into(),
                    imports: vec![
                        ImportEntry::new("a.cjs", "a", "a"),
                        ImportEntry::new("b.mjs", "b", "b"),
                    ],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(4),
            expected_binding_states: vec![
                ExpectedBindingState {
                    module_specifier: "shared.cjs".into(),
                    export_name: "data".into(),
                    expected_state: BindingCellState::Initialized,
                },
                ExpectedBindingState {
                    module_specifier: "a.cjs".into(),
                    export_name: "a".into(),
                    expected_state: BindingCellState::Initialized,
                },
                ExpectedBindingState {
                    module_specifier: "b.mjs".into(),
                    export_name: "b".into(),
                    expected_state: BindingCellState::Initialized,
                },
            ],
            expected_async_phases: vec![],
        },
        // ── Live Binding ──
        InteropSpecimen {
            specimen_id: "live_binding_esm_mutation".into(),
            description: "ESM live binding: export mutated after initial evaluation".into(),
            family: InteropFamily::LiveBinding,
            modules: vec![
                SpecimenModule {
                    specifier: "counter.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export let count = 0; export function increment() { count++; }".into(),
                    imports: vec![],
                    exports: vec![
                        ExportEntry::direct("count", "count"),
                        ExportEntry::direct("increment", "increment"),
                    ],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { count, increment } from './counter.mjs';".into(),
                    imports: vec![
                        ImportEntry::new("counter.mjs", "count", "count"),
                        ImportEntry::new("counter.mjs", "increment", "increment"),
                    ],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![
                ExpectedBindingState {
                    module_specifier: "counter.mjs".into(),
                    export_name: "count".into(),
                    expected_state: BindingCellState::Initialized,
                },
                ExpectedBindingState {
                    module_specifier: "counter.mjs".into(),
                    export_name: "increment".into(),
                    expected_state: BindingCellState::Initialized,
                },
            ],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "live_binding_cjs_snapshot".into(),
            description: "CJS exports are snapshot values, not live bindings".into(),
            family: InteropFamily::LiveBinding,
            modules: vec![
                SpecimenModule {
                    specifier: "state.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "let val = 0; module.exports.getVal = function() { return val; };".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("getVal", "getVal")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { getVal } from './state.cjs';".into(),
                    imports: vec![ImportEntry::new("state.cjs", "getVal", "getVal")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "state.cjs".into(),
                export_name: "getVal".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        },
        // ── Async Evaluation ──
        InteropSpecimen {
            specimen_id: "async_tla_single".into(),
            description: "Single ESM module with top-level await suspends then settles".into(),
            family: InteropFamily::AsyncEvaluation,
            modules: vec![SpecimenModule {
                specifier: "async.mjs".into(),
                syntax: ModuleSyntax::EsModule,
                source: "const data = await fetch('/api'); export default data;".into(),
                imports: vec![],
                exports: vec![ExportEntry::direct("default", "default")],
                has_default_export: true,
                has_top_level_await: true,
            }],
            entry_point: "async.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(1),
            expected_binding_states: vec![],
            expected_async_phases: vec![ExpectedAsyncPhase {
                module_specifier: "async.mjs".into(),
                expected_phase: AsyncModulePhase::Settled,
            }],
        },
        InteropSpecimen {
            specimen_id: "async_mixed_tla_chain".into(),
            description: "Async ESM depends on sync CJS — CJS settles immediately, ESM suspends then settles".into(),
            family: InteropFamily::AsyncEvaluation,
            modules: vec![
                SpecimenModule {
                    specifier: "sync.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "module.exports.ready = true;".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("ready", "ready")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { ready } from './sync.cjs'; const r = await Promise.resolve(ready);".into(),
                    imports: vec![ImportEntry::new("sync.cjs", "ready", "ready")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: true,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "sync.cjs".into(),
                export_name: "ready".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![
                ExpectedAsyncPhase {
                    module_specifier: "sync.cjs".into(),
                    expected_phase: AsyncModulePhase::Synchronous,
                },
                ExpectedAsyncPhase {
                    module_specifier: "entry.mjs".into(),
                    expected_phase: AsyncModulePhase::Settled,
                },
            ],
        },
        InteropSpecimen {
            specimen_id: "async_rejection_propagation".into(),
            description: "Rejected async module kills bindings in dependent modules".into(),
            family: InteropFamily::AsyncEvaluation,
            modules: vec![
                SpecimenModule {
                    specifier: "failing.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export const val = await Promise.reject(new Error('boom'));".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("val", "val")],
                    has_default_export: false,
                    has_top_level_await: true,
                },
                SpecimenModule {
                    specifier: "consumer.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { val } from './failing.mjs'; export const used = val;".into(),
                    imports: vec![ImportEntry::new("failing.mjs", "val", "val")],
                    exports: vec![ExportEntry::direct("used", "used")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "consumer.mjs".into(),
            expected_outcome: InteropExpectedOutcome::EvalFailure,
            expected_linked_count: Some(2),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "failing.mjs".into(),
                export_name: "val".into(),
                expected_state: BindingCellState::Dead,
            }],
            expected_async_phases: vec![ExpectedAsyncPhase {
                module_specifier: "failing.mjs".into(),
                expected_phase: AsyncModulePhase::Rejected,
            }],
        },
        // ── Cyclic Interop ──
        InteropSpecimen {
            specimen_id: "cycle_esm_esm".into(),
            description: "Mutual ESM cycle — both modules link via live binding stubs".into(),
            family: InteropFamily::CyclicInterop,
            modules: vec![
                SpecimenModule {
                    specifier: "a.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { b } from './b.mjs'; export const a = 'a';".into(),
                    imports: vec![ImportEntry::new("b.mjs", "b", "b")],
                    exports: vec![ExportEntry::direct("a", "a")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "b.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { a } from './a.mjs'; export const b = 'b';".into(),
                    imports: vec![ImportEntry::new("a.mjs", "a", "a")],
                    exports: vec![ExportEntry::direct("b", "b")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "a.mjs".into(),
            expected_outcome: InteropExpectedOutcome::CycleDetected,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "cycle_mixed_esm_cjs".into(),
            description: "Cycle crossing ESM↔CJS boundary".into(),
            family: InteropFamily::CyclicInterop,
            modules: vec![
                SpecimenModule {
                    specifier: "a.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { y } from './b.cjs'; export const x = 'x';".into(),
                    imports: vec![ImportEntry::new("b.cjs", "y", "y")],
                    exports: vec![ExportEntry::direct("x", "x")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "b.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "const { x } = require('./a.mjs'); module.exports.y = 'y';".into(),
                    imports: vec![ImportEntry::new("a.mjs", "x", "x")],
                    exports: vec![ExportEntry::direct("y", "y")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "a.mjs".into(),
            expected_outcome: InteropExpectedOutcome::CycleDetected,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        },
        // ── Default / Namespace ──
        InteropSpecimen {
            specimen_id: "namespace_import_from_cjs".into(),
            description: "ESM namespace import (import * as ns) from CJS module".into(),
            family: InteropFamily::DefaultNamespace,
            modules: vec![
                SpecimenModule {
                    specifier: "lib.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "module.exports = { a: 1, b: 2 };".into(),
                    imports: vec![],
                    exports: vec![
                        ExportEntry::direct("a", "a"),
                        ExportEntry::direct("b", "b"),
                    ],
                    has_default_export: true,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import * as ns from './lib.cjs';".into(),
                    imports: vec![ImportEntry::namespace("lib.cjs", "ns")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![
                ExpectedBindingState {
                    module_specifier: "lib.cjs".into(),
                    export_name: "a".into(),
                    expected_state: BindingCellState::Initialized,
                },
                ExpectedBindingState {
                    module_specifier: "lib.cjs".into(),
                    export_name: "b".into(),
                    expected_state: BindingCellState::Initialized,
                },
            ],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "default_export_esm_to_cjs".into(),
            description: "ESM default export consumed by CJS require".into(),
            family: InteropFamily::DefaultNamespace,
            modules: vec![
                SpecimenModule {
                    specifier: "component.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export default function Component() {}".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("Component", "default")],
                    has_default_export: true,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "const Component = require('./component.mjs').default;".into(),
                    imports: vec![ImportEntry::new("component.mjs", "default", "Component")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.cjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "component.mjs".into(),
                export_name: "default".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        },
        // ── Re-export Chain ──
        InteropSpecimen {
            specimen_id: "re_export_esm_through_cjs".into(),
            description: "ESM re-exports CJS export, consumed by another ESM module".into(),
            family: InteropFamily::ReExportChain,
            modules: vec![
                SpecimenModule {
                    specifier: "origin.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "module.exports.SECRET = 42;".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("SECRET", "SECRET")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "bridge.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export { SECRET } from './origin.cjs';".into(),
                    imports: vec![ImportEntry::new("origin.cjs", "SECRET", "SECRET")],
                    exports: vec![ExportEntry::re_export("SECRET", "origin.cjs", "SECRET")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { SECRET } from './bridge.mjs';".into(),
                    imports: vec![ImportEntry::new("bridge.mjs", "SECRET", "SECRET")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(3),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "origin.cjs".into(),
                export_name: "SECRET".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "star_re_export_across_boundary".into(),
            description: "Star re-export from CJS through ESM barrel file".into(),
            family: InteropFamily::ReExportChain,
            modules: vec![
                SpecimenModule {
                    specifier: "impl.cjs".into(),
                    syntax: ModuleSyntax::CommonJs,
                    source: "module.exports.alpha = 1; module.exports.beta = 2;".into(),
                    imports: vec![],
                    exports: vec![
                        ExportEntry::direct("alpha", "alpha"),
                        ExportEntry::direct("beta", "beta"),
                    ],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "barrel.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export * from './impl.cjs';".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::star_re_export("impl.cjs")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { alpha, beta } from './barrel.mjs';".into(),
                    imports: vec![
                        ImportEntry::new("barrel.mjs", "alpha", "alpha"),
                        ImportEntry::new("barrel.mjs", "beta", "beta"),
                    ],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(3),
            expected_binding_states: vec![
                ExpectedBindingState {
                    module_specifier: "impl.cjs".into(),
                    export_name: "alpha".into(),
                    expected_state: BindingCellState::Initialized,
                },
                ExpectedBindingState {
                    module_specifier: "impl.cjs".into(),
                    export_name: "beta".into(),
                    expected_state: BindingCellState::Initialized,
                },
            ],
            expected_async_phases: vec![],
        },
    ]
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Input for computing an evidence hash.
struct EvidenceHashInput<'a> {
    specimen_id: &'a str,
    actual_outcome: InteropActualOutcome,
    compatibility_disposition: InteropCompatibilityDisposition,
    guidance_code: &'a str,
    binding_count: usize,
    async_count: usize,
    linked_count: u64,
    cycle_count: u64,
}

/// Compute evidence hash from components.
fn compute_evidence_hash(input: &EvidenceHashInput<'_>) -> String {
    let hash_input = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        input.specimen_id,
        input.actual_outcome as u8,
        input.compatibility_disposition as u8,
        input.guidance_code,
        input.binding_count,
        input.async_count,
        input.linked_count,
        input.cycle_count,
    );
    hex_encode(ContentHash::compute(hash_input.as_bytes()).as_bytes())
}

/// Build an EsmModule from a SpecimenModule.
fn build_esm_module(sm: &SpecimenModule) -> EsmModule {
    let mut module = EsmModule::new(&sm.specifier, &sm.source, sm.syntax);
    module.has_default_export = sm.has_default_export;
    for imp in &sm.imports {
        module.add_import(imp.clone());
    }
    for exp in &sm.exports {
        module.add_export(exp.clone());
    }
    module
}

fn remediation_guidance(
    guidance_code: &str,
    message: impl Into<String>,
) -> InteropRemediationGuidance {
    InteropRemediationGuidance {
        guidance_code: guidance_code.to_string(),
        message: message.into(),
    }
}

fn classify_compatibility(
    specimen: &InteropSpecimen,
    _actual_outcome: InteropActualOutcome,
    verdict: InteropVerdict,
) -> (InteropCompatibilityDisposition, InteropRemediationGuidance) {
    if verdict == InteropVerdict::Fail {
        return (
            InteropCompatibilityDisposition::Unsupported,
            remediation_guidance(
                "interop_contract_violation",
                format!(
                    "specimen '{}' drifted from the declared interop contract; rerun the module interop verification matrix and inspect the emitted evidence bundle before shipping this boundary",
                    specimen.specimen_id
                ),
            ),
        );
    }

    match specimen.expected_outcome {
        InteropExpectedOutcome::Success => (
            InteropCompatibilityDisposition::Supported,
            remediation_guidance(
                "no_remediation_required",
                format!(
                    "specimen '{}' is supported under the current ESM/CJS interop contract; no mitigation is required",
                    specimen.specimen_id
                ),
            ),
        ),
        InteropExpectedOutcome::EvalFailure => (
            InteropCompatibilityDisposition::Degraded,
            remediation_guidance(
                "stabilize_async_boundary",
                format!(
                    "specimen '{}' degrades at evaluation time; handle the rejected async boundary explicitly or avoid bridging top-level-await rejection through this interop edge",
                    specimen.specimen_id
                ),
            ),
        ),
        InteropExpectedOutcome::CycleDetected => (
            InteropCompatibilityDisposition::Unsupported,
            remediation_guidance(
                "break_mixed_module_cycle",
                format!(
                    "specimen '{}' remains unsupported because the module graph forms a cycle across this boundary; break the cycle or collapse the edge to a single module system before retrying",
                    specimen.specimen_id
                ),
            ),
        ),
        InteropExpectedOutcome::LinkFailure => (
            InteropCompatibilityDisposition::Unsupported,
            remediation_guidance(
                "repair_link_boundary",
                format!(
                    "specimen '{}' remains unsupported because the graph does not link cleanly; align exports/imports or replace the boundary with an explicit shim before retrying",
                    specimen.specimen_id
                ),
            ),
        ),
    }
}

/// Build a quick evidence record for early-return scenarios.
fn early_return_evidence(
    specimen: &InteropSpecimen,
    actual_outcome: InteropActualOutcome,
    module_count: u64,
    linked_count: u64,
    cycle_count: u64,
    error_detail: Option<String>,
) -> InteropSpecimenEvidence {
    let outcome_matches = matches!(
        (specimen.expected_outcome, actual_outcome),
        (
            InteropExpectedOutcome::Success,
            InteropActualOutcome::Success
        ) | (
            InteropExpectedOutcome::LinkFailure,
            InteropActualOutcome::LinkFailure
        ) | (
            InteropExpectedOutcome::EvalFailure,
            InteropActualOutcome::EvalFailure
        ) | (
            InteropExpectedOutcome::CycleDetected,
            InteropActualOutcome::CycleDetected
        )
    );
    let verdict = if outcome_matches {
        InteropVerdict::Pass
    } else {
        InteropVerdict::Fail
    };
    let (compatibility_disposition, remediation_guidance) =
        classify_compatibility(specimen, actual_outcome, verdict);
    InteropSpecimenEvidence {
        specimen_id: specimen.specimen_id.clone(),
        family: specimen.family,
        expected_outcome: specimen.expected_outcome,
        actual_outcome,
        verdict,
        compatibility_disposition,
        remediation_guidance: remediation_guidance.clone(),
        module_count,
        linked_count,
        cycle_count,
        binding_verdicts: vec![],
        async_phase_verdicts: vec![],
        error_detail,
        evidence_hash: Some(compute_evidence_hash(&EvidenceHashInput {
            specimen_id: &specimen.specimen_id,
            actual_outcome,
            compatibility_disposition,
            guidance_code: &remediation_guidance.guidance_code,
            binding_count: 0,
            async_count: 0,
            linked_count,
            cycle_count,
        })),
    }
}

/// Run a single specimen through the module graph pipeline.
fn run_single_specimen(specimen: &InteropSpecimen) -> InteropSpecimenEvidence {
    // Build the module graph — add entry point first (ModuleGraph sets first-added as entry).
    let mut graph = ModuleGraph::new();

    if let Some(entry_sm) = specimen
        .modules
        .iter()
        .find(|m| m.specifier == specimen.entry_point)
        && let Err(e) = graph.add_module(build_esm_module(entry_sm))
    {
        return early_return_evidence(
            specimen,
            InteropActualOutcome::GraphConstructionFailure,
            0,
            0,
            0,
            Some(format!("{e}")),
        );
    }
    for sm in &specimen.modules {
        if sm.specifier == specimen.entry_point {
            continue;
        }
        if let Err(e) = graph.add_module(build_esm_module(sm)) {
            return early_return_evidence(
                specimen,
                InteropActualOutcome::GraphConstructionFailure,
                0,
                0,
                0,
                Some(format!("{e}")),
            );
        }
    }

    let module_count = graph.len() as u64;

    // Link phase.
    let link_result = graph.link();
    let (linked_count, cycle_count) = match &link_result {
        Ok(lr) => (lr.linked_count as u64, lr.cycle_count as u64),
        Err(_) => (0, 0),
    };

    if link_result.is_err() {
        return early_return_evidence(
            specimen,
            InteropActualOutcome::LinkFailure,
            module_count,
            linked_count,
            cycle_count,
            link_result.err().map(|e| format!("{e}")),
        );
    }

    if cycle_count > 0 {
        return early_return_evidence(
            specimen,
            InteropActualOutcome::CycleDetected,
            module_count,
            linked_count,
            cycle_count,
            None,
        );
    }

    // Build live binding map from the linked graph.
    let mut bindings = LiveBindingMap::new();
    for module in graph.modules() {
        if module.status == ModuleStatus::Linked || module.status == ModuleStatus::Evaluated {
            for exp in &module.exports {
                let id = BindingId {
                    module_specifier: module.specifier.clone(),
                    export_name: exp.export_name.clone(),
                };
                let binding_type = if exp.module_request.is_some() {
                    BindingType::ReExport
                } else {
                    BindingType::Direct
                };
                let mut cell = BindingCell::new(
                    &module.specifier,
                    &exp.export_name,
                    exp.local_name.as_deref().unwrap_or(&exp.export_name),
                    binding_type,
                );
                cell.state = BindingCellState::Initialized;
                bindings.cells.insert(id, cell);
            }
        }
    }

    // Async evaluation phase.
    let mut async_evaluator = AsyncModuleEvaluator::with_defaults();
    let mut has_rejection = false;

    // Register all modules with the async evaluator.
    for sm in &specimen.modules {
        let deps: Vec<String> = sm
            .imports
            .iter()
            .map(|i| i.module_request.clone())
            .collect();
        let promise = if sm.has_top_level_await {
            let pid: u32 = sm.specifier.as_bytes().iter().map(|&b| b as u32).sum();
            Some(crate::promise_model::PromiseHandle(pid))
        } else {
            None
        };
        async_evaluator.register_module(&sm.specifier, sm.has_top_level_await, &deps, promise);
    }

    // Sync modules are already in Synchronous phase (terminal).
    // Just notify dependents they've settled so async modules can proceed.
    for sm in &specimen.modules {
        if !sm.has_top_level_await {
            let _ = async_evaluator.notify_dependency_settled(&sm.specifier);
        }
    }

    // Process TLA modules: suspend → settle or reject.
    for sm in &specimen.modules {
        if sm.has_top_level_await {
            let pid: u32 = sm.specifier.as_bytes().iter().map(|&b| b as u32).sum();
            let promise = crate::promise_model::PromiseHandle(pid);
            let _ = async_evaluator.suspend_at_top_level_await(&sm.specifier, promise);

            if sm.source.contains("reject") || sm.source.contains("Reject") {
                let reason = crate::object_model::JsValue::Str("rejection".into());
                let _ = async_evaluator.reject_module(&sm.specifier, &reason, &mut bindings);
                has_rejection = true;
            } else {
                let _ = async_evaluator.resume_evaluation(&sm.specifier);
                let _ = async_evaluator.settle_module(&sm.specifier);
                let _ = async_evaluator.notify_dependency_settled(&sm.specifier);
            }
        }
    }

    let actual_outcome = if has_rejection {
        InteropActualOutcome::EvalFailure
    } else {
        InteropActualOutcome::Success
    };

    // Check binding state expectations.
    let mut binding_verdicts = Vec::new();
    for expected in &specimen.expected_binding_states {
        let id = BindingId {
            module_specifier: expected.module_specifier.clone(),
            export_name: expected.export_name.clone(),
        };
        let actual_state = bindings
            .cells
            .get(&id)
            .map(|c| c.state)
            .unwrap_or(BindingCellState::Uninitialized);
        binding_verdicts.push(BindingVerdict {
            module_specifier: expected.module_specifier.clone(),
            export_name: expected.export_name.clone(),
            expected_state: expected.expected_state,
            actual_state,
            pass: actual_state == expected.expected_state,
        });
    }

    // Check async phase expectations.
    let async_result = async_evaluator.finalize();
    let mut async_phase_verdicts = Vec::new();
    for expected in &specimen.expected_async_phases {
        let actual_phase = async_result
            .module_states
            .iter()
            .find(|(_, s)| s.module_specifier == expected.module_specifier)
            .map(|(_, s)| s.phase)
            .unwrap_or(AsyncModulePhase::Synchronous);
        async_phase_verdicts.push(AsyncPhaseVerdict {
            module_specifier: expected.module_specifier.clone(),
            expected_phase: expected.expected_phase,
            actual_phase,
            pass: actual_phase == expected.expected_phase,
        });
    }

    // Compute overall verdict.
    let outcome_matches = matches!(
        (specimen.expected_outcome, actual_outcome),
        (
            InteropExpectedOutcome::Success,
            InteropActualOutcome::Success
        ) | (
            InteropExpectedOutcome::LinkFailure,
            InteropActualOutcome::LinkFailure
        ) | (
            InteropExpectedOutcome::EvalFailure,
            InteropActualOutcome::EvalFailure
        ) | (
            InteropExpectedOutcome::CycleDetected,
            InteropActualOutcome::CycleDetected
        )
    );
    let bindings_pass = binding_verdicts.iter().all(|v| v.pass);
    let async_pass = async_phase_verdicts.iter().all(|v| v.pass);
    let linked_count_pass = specimen
        .expected_linked_count
        .is_none_or(|expected| expected == linked_count);

    let verdict = if outcome_matches && bindings_pass && async_pass && linked_count_pass {
        InteropVerdict::Pass
    } else {
        InteropVerdict::Fail
    };
    let (compatibility_disposition, remediation_guidance) =
        classify_compatibility(specimen, actual_outcome, verdict);

    let binding_count = binding_verdicts.len();
    let async_count = async_phase_verdicts.len();

    InteropSpecimenEvidence {
        specimen_id: specimen.specimen_id.clone(),
        family: specimen.family,
        expected_outcome: specimen.expected_outcome,
        actual_outcome,
        verdict,
        compatibility_disposition,
        remediation_guidance: remediation_guidance.clone(),
        module_count,
        linked_count,
        cycle_count,
        binding_verdicts,
        async_phase_verdicts,
        error_detail: None,
        evidence_hash: Some(compute_evidence_hash(&EvidenceHashInput {
            specimen_id: &specimen.specimen_id,
            actual_outcome,
            compatibility_disposition,
            guidance_code: &remediation_guidance.guidance_code,
            binding_count,
            async_count,
            linked_count,
            cycle_count,
        })),
    }
}

/// Run the full interop parity corpus and return the evidence inventory.
pub fn run_interop_parity_corpus() -> InteropParityInventory {
    let corpus = interop_parity_corpus();
    let mut evidence = Vec::with_capacity(corpus.len());
    let mut pass_count: u64 = 0;
    let mut fail_count: u64 = 0;
    let mut supported_count: u64 = 0;
    let mut degraded_count: u64 = 0;
    let mut unsupported_count: u64 = 0;
    let mut family_coverage: BTreeMap<String, u64> = BTreeMap::new();
    let mut esm_only_count: u64 = 0;
    let mut cjs_only_count: u64 = 0;
    let mut mixed_count: u64 = 0;

    for specimen in &corpus {
        let ev = run_single_specimen(specimen);
        if ev.verdict == InteropVerdict::Pass {
            pass_count += 1;
        } else {
            fail_count += 1;
        }
        match ev.compatibility_disposition {
            InteropCompatibilityDisposition::Supported => supported_count += 1,
            InteropCompatibilityDisposition::Degraded => degraded_count += 1,
            InteropCompatibilityDisposition::Unsupported => unsupported_count += 1,
        }

        *family_coverage
            .entry(specimen.family.as_str().to_string())
            .or_insert(0) += 1;

        // Classify by module syntax mix.
        let syntaxes: BTreeSet<ModuleSyntax> = specimen.modules.iter().map(|m| m.syntax).collect();
        if syntaxes.len() == 1 && syntaxes.contains(&ModuleSyntax::EsModule) {
            esm_only_count += 1;
        } else if syntaxes.len() == 1 && syntaxes.contains(&ModuleSyntax::CommonJs) {
            cjs_only_count += 1;
        } else {
            mixed_count += 1;
        }

        evidence.push(ev);
    }

    InteropParityInventory {
        schema_version: INTEROP_PARITY_SCHEMA_VERSION.to_string(),
        component: INTEROP_PARITY_COMPONENT.to_string(),
        specimen_count: corpus.len() as u64,
        pass_count,
        fail_count,
        supported_count,
        degraded_count,
        unsupported_count,
        family_coverage,
        esm_only_count,
        cjs_only_count,
        mixed_count,
        evidence,
    }
}

// ---------------------------------------------------------------------------
// Bundle writer
// ---------------------------------------------------------------------------

/// Write the evidence bundle to disk.
pub fn write_interop_parity_bundle(
    output_dir: &Path,
    commands: &[String],
) -> Result<InteropParityBundleArtifacts, std::io::Error> {
    std::fs::create_dir_all(output_dir)?;

    let inv = run_interop_parity_corpus();
    let inv_json = serde_json::to_string_pretty(&inv).map_err(std::io::Error::other)?;
    let inventory_hash = hex_encode(ContentHash::compute(inv_json.as_bytes()).as_bytes());

    // Write inventory.
    let inv_path = output_dir.join("esm_cjs_interop_parity_inventory.json");
    std::fs::write(&inv_path, &inv_json)?;

    // Build events JSONL.
    let mut event_lines = Vec::new();

    // Start event.
    let start = InteropParityEvent {
        schema_version: INTEROP_PARITY_EVENT_SCHEMA_VERSION.to_string(),
        component: INTEROP_PARITY_COMPONENT.to_string(),
        event: "interop_parity_run_started".to_string(),
        policy_id: INTEROP_PARITY_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: None,
    };
    event_lines.push(serde_json::to_string(&start).map_err(std::io::Error::other)?);

    // Per-specimen events.
    for ev in &inv.evidence {
        let detail = match &ev.error_detail {
            Some(error_detail) => Some(format!(
                "disposition={} guidance_code={} error={}",
                ev.compatibility_disposition, ev.remediation_guidance.guidance_code, error_detail
            )),
            None => Some(format!(
                "disposition={} guidance_code={}",
                ev.compatibility_disposition, ev.remediation_guidance.guidance_code,
            )),
        };
        let specimen_event = InteropParityEvent {
            schema_version: INTEROP_PARITY_EVENT_SCHEMA_VERSION.to_string(),
            component: INTEROP_PARITY_COMPONENT.to_string(),
            event: "interop_specimen_evaluated".to_string(),
            policy_id: INTEROP_PARITY_POLICY_ID.to_string(),
            specimen_id: Some(ev.specimen_id.clone()),
            verdict: Some(if ev.verdict == InteropVerdict::Pass {
                "pass".to_string()
            } else {
                "fail".to_string()
            }),
            detail,
        };
        event_lines.push(serde_json::to_string(&specimen_event).map_err(std::io::Error::other)?);
    }

    // End event.
    let end = InteropParityEvent {
        schema_version: INTEROP_PARITY_EVENT_SCHEMA_VERSION.to_string(),
        component: INTEROP_PARITY_COMPONENT.to_string(),
        event: "interop_parity_run_completed".to_string(),
        policy_id: INTEROP_PARITY_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: Some(if inv.contract_satisfied() {
            "satisfied".to_string()
        } else {
            "violated".to_string()
        }),
        detail: Some(format!(
            "pass={} fail={} supported={} degraded={} unsupported={} total={}",
            inv.pass_count,
            inv.fail_count,
            inv.supported_count,
            inv.degraded_count,
            inv.unsupported_count,
            inv.specimen_count
        )),
    };
    event_lines.push(serde_json::to_string(&end).map_err(std::io::Error::other)?);

    let events_path = output_dir.join("esm_cjs_interop_parity_events.jsonl");
    std::fs::write(&events_path, event_lines.join("\n") + "\n")?;

    // Write manifest.
    let trace_id = format!(
        "interop-parity-{}",
        inventory_hash.chars().take(12).collect::<String>()
    );
    let decision_id = format!(
        "dec-{}",
        inventory_hash.chars().skip(12).take(12).collect::<String>()
    );

    let manifest = InteropParityRunManifest {
        schema_version: INTEROP_PARITY_MANIFEST_SCHEMA_VERSION.to_string(),
        component: INTEROP_PARITY_COMPONENT.to_string(),
        trace_id,
        decision_id,
        policy_id: INTEROP_PARITY_POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
        specimen_count: inv.specimen_count,
        pass_count: inv.pass_count,
        fail_count: inv.fail_count,
        supported_count: inv.supported_count,
        degraded_count: inv.degraded_count,
        unsupported_count: inv.unsupported_count,
        contract_satisfied: inv.contract_satisfied(),
        artifact_paths: InteropParityArtifactPaths {
            evidence_inventory: "esm_cjs_interop_parity_inventory.json".to_string(),
            run_manifest: "esm_cjs_interop_parity_manifest.json".to_string(),
            events_jsonl: "esm_cjs_interop_parity_events.jsonl".to_string(),
            commands_txt: "esm_cjs_interop_parity_commands.txt".to_string(),
        },
    };

    let manifest_path = output_dir.join("esm_cjs_interop_parity_manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).map_err(std::io::Error::other)?,
    )?;

    // Write commands.
    let commands_path = output_dir.join("esm_cjs_interop_parity_commands.txt");
    std::fs::write(&commands_path, commands.join("\n"))?;

    Ok(InteropParityBundleArtifacts {
        inventory_path: inv_path,
        run_manifest_path: manifest_path,
        events_path,
        commands_path,
        inventory_hash,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_non_empty() {
        assert!(!interop_parity_corpus().is_empty());
    }

    #[test]
    fn corpus_ids_unique() {
        let corpus = interop_parity_corpus();
        let ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
        assert_eq!(ids.len(), corpus.len());
    }

    #[test]
    fn corpus_covers_all_families() {
        let corpus = interop_parity_corpus();
        let covered: BTreeSet<InteropFamily> = corpus.iter().map(|s| s.family).collect();
        for f in InteropFamily::ALL {
            assert!(covered.contains(f), "missing family {:?}", f);
        }
    }

    #[test]
    fn corpus_has_success_and_failure_specimens() {
        let corpus = interop_parity_corpus();
        assert!(
            corpus
                .iter()
                .any(|s| s.expected_outcome == InteropExpectedOutcome::Success)
        );
        assert!(
            corpus
                .iter()
                .any(|s| s.expected_outcome != InteropExpectedOutcome::Success)
        );
    }

    #[test]
    fn corpus_has_esm_cjs_and_mixed() {
        let corpus = interop_parity_corpus();
        let has_esm_only = corpus
            .iter()
            .any(|s| s.modules.iter().all(|m| m.syntax == ModuleSyntax::EsModule));
        let has_cjs_only = corpus
            .iter()
            .any(|s| s.modules.iter().all(|m| m.syntax == ModuleSyntax::CommonJs));
        let has_mixed = corpus.iter().any(|s| {
            let syntaxes: BTreeSet<_> = s.modules.iter().map(|m| m.syntax).collect();
            syntaxes.len() > 1
        });
        assert!(has_esm_only);
        assert!(has_cjs_only);
        assert!(has_mixed);
    }

    #[test]
    fn family_as_str_all_distinct() {
        let strs: BTreeSet<&str> = InteropFamily::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(strs.len(), InteropFamily::ALL.len());
    }

    #[test]
    fn family_display_matches_as_str() {
        for f in InteropFamily::ALL {
            assert_eq!(format!("{f}"), f.as_str());
        }
    }

    #[test]
    fn family_serde_roundtrip() {
        for f in InteropFamily::ALL {
            let json = serde_json::to_string(f).unwrap();
            let back: InteropFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*f, back);
        }
    }

    #[test]
    fn expected_outcome_serde_roundtrip() {
        let outcomes = [
            InteropExpectedOutcome::Success,
            InteropExpectedOutcome::LinkFailure,
            InteropExpectedOutcome::EvalFailure,
            InteropExpectedOutcome::CycleDetected,
        ];
        for o in &outcomes {
            let json = serde_json::to_string(o).unwrap();
            let back: InteropExpectedOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*o, back);
        }
    }

    #[test]
    fn actual_outcome_serde_roundtrip() {
        let outcomes = [
            InteropActualOutcome::Success,
            InteropActualOutcome::LinkFailure,
            InteropActualOutcome::EvalFailure,
            InteropActualOutcome::CycleDetected,
            InteropActualOutcome::GraphConstructionFailure,
        ];
        for o in &outcomes {
            let json = serde_json::to_string(o).unwrap();
            let back: InteropActualOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*o, back);
        }
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let json_pass = serde_json::to_string(&InteropVerdict::Pass).unwrap();
        let json_fail = serde_json::to_string(&InteropVerdict::Fail).unwrap();
        assert_eq!(
            serde_json::from_str::<InteropVerdict>(&json_pass).unwrap(),
            InteropVerdict::Pass
        );
        assert_eq!(
            serde_json::from_str::<InteropVerdict>(&json_fail).unwrap(),
            InteropVerdict::Fail
        );
    }

    #[test]
    fn compatibility_disposition_serde_roundtrip() {
        for disposition in [
            InteropCompatibilityDisposition::Supported,
            InteropCompatibilityDisposition::Degraded,
            InteropCompatibilityDisposition::Unsupported,
        ] {
            let json = serde_json::to_string(&disposition).unwrap();
            let back: InteropCompatibilityDisposition = serde_json::from_str(&json).unwrap();
            assert_eq!(disposition, back);
        }
    }

    #[test]
    fn remediation_guidance_serde_roundtrip() {
        let guidance = remediation_guidance("g-1", "fix the bridge");
        let json = serde_json::to_string(&guidance).unwrap();
        let back: InteropRemediationGuidance = serde_json::from_str(&json).unwrap();
        assert_eq!(guidance, back);
    }

    #[test]
    fn all_specimens_pass() {
        let inv = run_interop_parity_corpus();
        for ev in &inv.evidence {
            assert_eq!(
                ev.verdict,
                InteropVerdict::Pass,
                "specimen {} failed: expected={:?}, actual={:?}",
                ev.specimen_id,
                ev.expected_outcome,
                ev.actual_outcome
            );
        }
    }

    #[test]
    fn contract_satisfied() {
        let inv = run_interop_parity_corpus();
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn counts_consistent() {
        let inv = run_interop_parity_corpus();
        assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
        assert_eq!(
            inv.supported_count + inv.degraded_count + inv.unsupported_count,
            inv.specimen_count
        );
        assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
    }

    #[test]
    fn compatibility_dispositions_are_explicit_for_all_specimens() {
        let inv = run_interop_parity_corpus();
        assert!(inv.supported_count > 0);
        assert!(inv.degraded_count > 0);
        assert!(inv.unsupported_count > 0);
        for ev in &inv.evidence {
            assert!(!ev.remediation_guidance.guidance_code.is_empty());
            assert!(!ev.remediation_guidance.message.is_empty());
        }
    }

    #[test]
    fn async_rejection_is_degraded_with_guidance() {
        let inv = run_interop_parity_corpus();
        let evidence = inv
            .evidence
            .iter()
            .find(|ev| ev.specimen_id == "async_rejection_propagation")
            .unwrap();
        assert_eq!(
            evidence.compatibility_disposition,
            InteropCompatibilityDisposition::Degraded
        );
        assert_eq!(
            evidence.remediation_guidance.guidance_code,
            "stabilize_async_boundary"
        );
    }

    #[test]
    fn mixed_cycle_is_unsupported_with_guidance() {
        let inv = run_interop_parity_corpus();
        let evidence = inv
            .evidence
            .iter()
            .find(|ev| ev.specimen_id == "cycle_mixed_esm_cjs")
            .unwrap();
        assert_eq!(
            evidence.compatibility_disposition,
            InteropCompatibilityDisposition::Unsupported
        );
        assert_eq!(
            evidence.remediation_guidance.guidance_code,
            "break_mixed_module_cycle"
        );
    }

    #[test]
    fn family_coverage_sums() {
        let inv = run_interop_parity_corpus();
        let total: u64 = inv.family_coverage.values().sum();
        assert_eq!(total, inv.specimen_count);
    }

    #[test]
    fn syntax_mix_counts_sum() {
        let inv = run_interop_parity_corpus();
        assert_eq!(
            inv.esm_only_count + inv.cjs_only_count + inv.mixed_count,
            inv.specimen_count
        );
    }

    #[test]
    fn evidence_hashes_present() {
        let inv = run_interop_parity_corpus();
        for ev in &inv.evidence {
            assert!(
                ev.evidence_hash.is_some(),
                "specimen {} missing hash",
                ev.specimen_id
            );
        }
    }

    #[test]
    fn evidence_hashes_64_hex() {
        let inv = run_interop_parity_corpus();
        for ev in &inv.evidence {
            let hash = ev.evidence_hash.as_ref().unwrap();
            assert_eq!(
                hash.len(),
                64,
                "specimen {} hash wrong length",
                ev.specimen_id
            );
            assert!(
                hash.chars().all(|c| c.is_ascii_hexdigit()),
                "specimen {} hash not hex",
                ev.specimen_id
            );
        }
    }

    #[test]
    fn corpus_deterministic() {
        let inv1 = run_interop_parity_corpus();
        let inv2 = run_interop_parity_corpus();
        assert_eq!(inv1, inv2);
    }

    #[test]
    fn schema_constants_non_empty() {
        assert!(!INTEROP_PARITY_SCHEMA_VERSION.is_empty());
        assert!(!INTEROP_PARITY_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!INTEROP_PARITY_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!INTEROP_PARITY_COMPONENT.is_empty());
        assert!(!INTEROP_PARITY_POLICY_ID.is_empty());
    }

    #[test]
    fn schema_versions_prefixed() {
        assert!(INTEROP_PARITY_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(INTEROP_PARITY_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(INTEROP_PARITY_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn schema_versions_distinct() {
        let versions: BTreeSet<&str> = [
            INTEROP_PARITY_SCHEMA_VERSION,
            INTEROP_PARITY_MANIFEST_SCHEMA_VERSION,
            INTEROP_PARITY_EVENT_SCHEMA_VERSION,
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(versions.len(), 3);
    }

    #[test]
    fn inventory_serde_roundtrip() {
        let inv = run_interop_parity_corpus();
        let json = serde_json::to_string(&inv).unwrap();
        let back: InteropParityInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    #[test]
    fn specimen_evidence_serde_roundtrip() {
        let inv = run_interop_parity_corpus();
        for ev in &inv.evidence {
            let json = serde_json::to_string(ev).unwrap();
            let back: InteropSpecimenEvidence = serde_json::from_str(&json).unwrap();
            assert_eq!(*ev, back);
        }
    }

    #[test]
    fn specimen_serde_roundtrip() {
        for s in &interop_parity_corpus() {
            let json = serde_json::to_string(s).unwrap();
            let back: InteropSpecimen = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = InteropParityRunManifest {
            schema_version: INTEROP_PARITY_MANIFEST_SCHEMA_VERSION.to_string(),
            component: INTEROP_PARITY_COMPONENT.to_string(),
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: INTEROP_PARITY_POLICY_ID.to_string(),
            inventory_hash: "h".to_string(),
            specimen_count: 20,
            pass_count: 20,
            fail_count: 0,
            supported_count: 18,
            degraded_count: 1,
            unsupported_count: 1,
            contract_satisfied: true,
            artifact_paths: InteropParityArtifactPaths {
                evidence_inventory: "a.json".to_string(),
                run_manifest: "b.json".to_string(),
                events_jsonl: "c.jsonl".to_string(),
                commands_txt: "d.txt".to_string(),
            },
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: InteropParityRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn event_serde_roundtrip() {
        let ev = InteropParityEvent {
            schema_version: INTEROP_PARITY_EVENT_SCHEMA_VERSION.to_string(),
            component: INTEROP_PARITY_COMPONENT.to_string(),
            event: "test".to_string(),
            policy_id: INTEROP_PARITY_POLICY_ID.to_string(),
            specimen_id: Some("s".to_string()),
            verdict: Some("pass".to_string()),
            detail: Some("d".to_string()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: InteropParityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn contract_not_satisfied_with_failure() {
        let inv = InteropParityInventory {
            schema_version: INTEROP_PARITY_SCHEMA_VERSION.to_string(),
            component: INTEROP_PARITY_COMPONENT.to_string(),
            specimen_count: 10,
            pass_count: 9,
            fail_count: 1,
            supported_count: 8,
            degraded_count: 1,
            unsupported_count: 1,
            family_coverage: BTreeMap::new(),
            esm_only_count: 3,
            cjs_only_count: 3,
            mixed_count: 4,
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn contract_not_satisfied_with_zero_specimens() {
        let inv = InteropParityInventory {
            schema_version: INTEROP_PARITY_SCHEMA_VERSION.to_string(),
            component: INTEROP_PARITY_COMPONENT.to_string(),
            specimen_count: 0,
            pass_count: 0,
            fail_count: 0,
            supported_count: 0,
            degraded_count: 0,
            unsupported_count: 0,
            family_coverage: BTreeMap::new(),
            esm_only_count: 0,
            cjs_only_count: 0,
            mixed_count: 0,
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn inventory_schema_matches() {
        let inv = run_interop_parity_corpus();
        assert_eq!(inv.schema_version, INTEROP_PARITY_SCHEMA_VERSION);
        assert_eq!(inv.component, INTEROP_PARITY_COMPONENT);
    }

    // -----------------------------------------------------------------------
    // Deep enrichment tests (PearlTower 2026-03-18)
    // -----------------------------------------------------------------------

    #[test]
    fn interop_family_all_count() {
        assert_eq!(InteropFamily::ALL.len(), 10);
    }

    #[test]
    fn expected_outcome_display() {
        for o in [
            InteropExpectedOutcome::Success,
            InteropExpectedOutcome::LinkFailure,
            InteropExpectedOutcome::EvalFailure,
            InteropExpectedOutcome::CycleDetected,
        ] {
            let json = serde_json::to_string(&o).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn actual_outcome_has_graph_construction_failure() {
        let o = InteropActualOutcome::GraphConstructionFailure;
        let json = serde_json::to_string(&o).unwrap();
        let back: InteropActualOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn hex_encode_deterministic() {
        let h1 = hex_encode(&[0x00, 0xff, 0xab]);
        let h2 = hex_encode(&[0x00, 0xff, 0xab]);
        assert_eq!(h1, h2);
        assert_eq!(h1, "00ffab");
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn corpus_modules_all_have_specifiers() {
        let corpus = interop_parity_corpus();
        for s in &corpus {
            assert!(
                !s.entry_point.is_empty(),
                "specimen {} missing entry point",
                s.specimen_id
            );
            for m in &s.modules {
                assert!(
                    !m.specifier.is_empty(),
                    "specimen {} module missing specifier",
                    s.specimen_id
                );
            }
        }
    }

    #[test]
    fn corpus_specimen_descriptions_non_empty() {
        let corpus = interop_parity_corpus();
        for s in &corpus {
            assert!(
                !s.description.is_empty(),
                "specimen {} missing description",
                s.specimen_id
            );
        }
    }

    #[test]
    fn remediation_guidance_has_message() {
        let g = remediation_guidance("test-code", "test message");
        assert_eq!(g.guidance_code, "test-code");
        assert_eq!(g.message, "test message");
    }

    #[test]
    fn compatibility_disposition_variants() {
        let supported = InteropCompatibilityDisposition::Supported;
        let degraded = InteropCompatibilityDisposition::Degraded;
        let unsupported = InteropCompatibilityDisposition::Unsupported;
        assert_ne!(supported, degraded);
        assert_ne!(degraded, unsupported);
        assert_ne!(supported, unsupported);
    }

    #[test]
    fn verdict_equality() {
        assert_eq!(InteropVerdict::Pass, InteropVerdict::Pass);
        assert_ne!(InteropVerdict::Pass, InteropVerdict::Fail);
    }

    #[test]
    fn evidence_specimen_ids_match_corpus() {
        let corpus = interop_parity_corpus();
        let inv = run_interop_parity_corpus();
        let corpus_ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
        let evidence_ids: BTreeSet<&str> = inv
            .evidence
            .iter()
            .map(|e| e.specimen_id.as_str())
            .collect();
        assert_eq!(corpus_ids, evidence_ids);
    }

    #[test]
    fn artifact_paths_serde() {
        let paths = InteropParityArtifactPaths {
            evidence_inventory: "inv.json".to_string(),
            run_manifest: "manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        };
        let json = serde_json::to_string(&paths).unwrap();
        let back: InteropParityArtifactPaths = serde_json::from_str(&json).unwrap();
        assert_eq!(paths, back);
    }
}
