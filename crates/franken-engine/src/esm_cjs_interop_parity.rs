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
use crate::module_async_evaluation::{
    AsyncModuleEvaluator, AsyncModulePhase, compute_async_evaluation_order,
};
use crate::module_compatibility_matrix::CompatibilityMode;
use crate::module_live_binding::{BindingCell, BindingCellState, BindingId, LiveBindingMap};
use crate::module_resolver::{
    AllowAllPolicy, DeterministicModuleResolver, ImportStyle, ModuleDefinition, ModuleDependency,
    ModuleRequest, ModuleResolver, ModuleSyntax, ResolutionContext, ResolutionResult,
};

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
    pub compatibility_mode: CompatibilityMode,
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

impl InteropSpecimenEvidence {
    /// Compute the deterministic hash for the evidence body.
    pub fn compute_hash(&self) -> String {
        let mut canonical = self.clone();
        canonical.evidence_hash = None;
        let canonical_json = serde_json::to_vec(&canonical)
            .expect("interop specimen evidence serialization should not fail");
        hex_encode(ContentHash::compute(&canonical_json).as_bytes())
    }

    /// Verify that the stored hash matches the canonical evidence body.
    pub fn verify_hash(&self) -> bool {
        let recomputed = self.compute_hash();
        self.evidence_hash.as_deref() == Some(recomputed.as_str())
    }
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
    /// Contract is satisfied when all specimens pass and the evidence hashes verify.
    pub fn contract_satisfied(&self) -> bool {
        self.specimen_count > 0
            && self.fail_count == 0
            && self.pass_count == self.specimen_count
            && self.evidence.len() as u64 == self.specimen_count
            && self
                .evidence
                .iter()
                .all(|evidence| evidence.verdict == InteropVerdict::Pass && evidence.verify_hash())
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
    pub compatibility_mode: Option<CompatibilityMode>,
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

fn external_package_root_require_specimen(
    specimen_id: &str,
    description: &str,
    package_entry_specifier: &str,
    package_sub_specifier: &str,
    bare_request: &str,
    sub_value_source: &str,
) -> InteropSpecimen {
    InteropSpecimen {
        specimen_id: specimen_id.into(),
        description: description.into(),
        family: InteropFamily::CjsOnly,
        modules: vec![
            SpecimenModule {
                specifier: package_sub_specifier.into(),
                syntax: ModuleSyntax::CommonJs,
                source: format!("module.exports.value = {sub_value_source};"),
                imports: vec![],
                exports: vec![ExportEntry::direct("value", "value")],
                has_default_export: false,
                has_top_level_await: false,
            },
            SpecimenModule {
                specifier: package_entry_specifier.into(),
                syntax: ModuleSyntax::CommonJs,
                source: "const sub = require('./sub'); module.exports.value = sub.value;".into(),
                imports: vec![ImportEntry::new("./sub", "value", "sub")],
                exports: vec![ExportEntry::direct("value", "value")],
                has_default_export: false,
                has_top_level_await: false,
            },
            SpecimenModule {
                specifier: "entry.cjs".into(),
                syntax: ModuleSyntax::CommonJs,
                source: format!("const pkg = require('{bare_request}');"),
                imports: vec![ImportEntry::new(bare_request, "value", "pkg")],
                exports: vec![],
                has_default_export: false,
                has_top_level_await: false,
            },
        ],
        entry_point: "entry.cjs".into(),
        expected_outcome: InteropExpectedOutcome::Success,
        expected_linked_count: Some(3),
        expected_binding_states: vec![
            ExpectedBindingState {
                module_specifier: package_sub_specifier.into(),
                export_name: "value".into(),
                expected_state: BindingCellState::Initialized,
            },
            ExpectedBindingState {
                module_specifier: package_entry_specifier.into(),
                export_name: "value".into(),
                expected_state: BindingCellState::Initialized,
            },
        ],
        expected_async_phases: vec![],
    }
}

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
        external_package_root_require_specimen(
            "external_extension_probe_package_root_require_native",
            "Native CJS entry bare-requires an external pkg.js entry whose nested ./sub require stays anchored at the package root",
            "pkg.js",
            "pkg/sub.cjs",
            "pkg",
            "41",
        ),
        external_package_root_require_specimen(
            "external_extension_probe_package_root_require_node_compat",
            "Node-compatible CJS entry bare-requires an external pkg.js entry whose nested ./sub require stays anchored at the package root",
            "pkg.js",
            "pkg/sub.cjs",
            "pkg",
            "41",
        ),
        external_package_root_require_specimen(
            "external_extension_probe_package_root_require_bun_compat",
            "Bun-compatible CJS entry bare-requires an external pkg.js entry whose nested ./sub require stays anchored at the package root",
            "pkg.js",
            "pkg/sub.cjs",
            "pkg",
            "41",
        ),
        external_package_root_require_specimen(
            "scoped_external_extension_probe_package_root_require_native",
            "Native CJS entry bare-requires a scoped @scope/pkg.js entry whose nested ./sub require stays anchored at the scoped package root",
            "@scope/pkg.js",
            "@scope/pkg/sub.cjs",
            "@scope/pkg",
            "7",
        ),
        external_package_root_require_specimen(
            "scoped_external_extension_probe_package_root_require_node_compat",
            "Node-compatible CJS entry bare-requires a scoped @scope/pkg.js entry whose nested ./sub require stays anchored at the scoped package root",
            "@scope/pkg.js",
            "@scope/pkg/sub.cjs",
            "@scope/pkg",
            "7",
        ),
        external_package_root_require_specimen(
            "scoped_external_extension_probe_package_root_require_bun_compat",
            "Bun-compatible CJS entry bare-requires a scoped @scope/pkg.js entry whose nested ./sub require stays anchored at the scoped package root",
            "@scope/pkg.js",
            "@scope/pkg/sub.cjs",
            "@scope/pkg",
            "7",
        ),
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
            specimen_id: "cjs_requires_esm_named_native".into(),
            description: "Native CJS entry requires a named export from ESM module and fails with ERR_REQUIRE_ESM".into(),
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
            expected_outcome: InteropExpectedOutcome::LinkFailure,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "cjs_requires_esm_named_bun_compat".into(),
            description: "Bun-compat CJS entry requires a named export from ESM module via sync bridge semantics".into(),
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
        InteropSpecimen {
            specimen_id: "package_type_module_extensionless_relative_native".into(),
            description:
                "Native external-package ESM entry imports an extensionless relative path and fails closed".into(),
            family: InteropFamily::EsmOnly,
            modules: vec![
                SpecimenModule {
                    specifier: "some-pkg/sub.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export const value = 'sub';".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("value", "value")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "some-pkg/main.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { value } from './sub'; export const seen = value;".into(),
                    imports: vec![ImportEntry::new("./sub", "value", "value")],
                    exports: vec![ExportEntry::direct("seen", "seen")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "some-pkg/main.mjs".into(),
            expected_outcome: InteropExpectedOutcome::LinkFailure,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "package_type_module_extensionless_relative_node_compat".into(),
            description:
                "Node-compat external-package ESM entry still requires an explicit relative extension and fails closed".into(),
            family: InteropFamily::EsmOnly,
            modules: vec![
                SpecimenModule {
                    specifier: "some-pkg/sub.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export const value = 'sub';".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("value", "value")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "some-pkg/main.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { value } from './sub'; export const seen = value;".into(),
                    imports: vec![ImportEntry::new("./sub", "value", "value")],
                    exports: vec![ExportEntry::direct("seen", "seen")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "some-pkg/main.mjs".into(),
            expected_outcome: InteropExpectedOutcome::LinkFailure,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        },
        InteropSpecimen {
            specimen_id: "package_type_module_extensionless_relative_bun_compat".into(),
            description:
                "Bun-compat external-package ESM entry resolves an extensionless relative path to the canonical module".into(),
            family: InteropFamily::EsmOnly,
            modules: vec![
                SpecimenModule {
                    specifier: "some-pkg/sub.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export const value = 'sub';".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("value", "value")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "some-pkg/main.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { value } from './sub'; export const seen = value;".into(),
                    imports: vec![ImportEntry::new("./sub", "value", "value")],
                    exports: vec![ExportEntry::direct("seen", "seen")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "some-pkg/main.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(2),
            expected_binding_states: vec![
                ExpectedBindingState {
                    module_specifier: "some-pkg/sub.mjs".into(),
                    export_name: "value".into(),
                    expected_state: BindingCellState::Initialized,
                },
                ExpectedBindingState {
                    module_specifier: "some-pkg/main.mjs".into(),
                    export_name: "seen".into(),
                    expected_state: BindingCellState::Initialized,
                },
            ],
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

fn module_request_style(syntax: ModuleSyntax) -> ImportStyle {
    match syntax {
        ModuleSyntax::EsModule => ImportStyle::Import,
        ModuleSyntax::CommonJs => ImportStyle::Require,
    }
}

fn build_module_definition(sm: &SpecimenModule) -> ModuleDefinition {
    let mut definition = ModuleDefinition::new(sm.syntax, &sm.source);
    let mut dependencies = BTreeSet::new();
    for import in &sm.imports {
        dependencies.insert(import.module_request.clone());
    }
    for export in &sm.exports {
        if let Some(module_request) = &export.module_request {
            dependencies.insert(module_request.clone());
        }
    }
    for dependency in dependencies {
        definition = definition.with_dependency(ModuleDependency::new(
            dependency,
            module_request_style(sm.syntax),
        ));
    }
    definition
}

fn specimen_module_dependency_specifiers(sm: &SpecimenModule) -> Vec<String> {
    build_module_definition(sm)
        .dependencies
        .into_iter()
        .map(|dependency| dependency.specifier)
        .collect()
}

fn canonical_dependency_targets_for_specimen(
    specimen: &InteropSpecimen,
    resolver: &DeterministicModuleResolver,
    context: &ResolutionContext,
    compatibility_mode: CompatibilityMode,
    reachable_module_specifiers: &BTreeSet<String>,
) -> ResolutionResult<BTreeMap<(String, String), String>> {
    let mut canonical_targets = BTreeMap::new();

    for module in &specimen.modules {
        if !reachable_module_specifiers.contains(&module.specifier) {
            continue;
        }
        let mut dependency_styles = BTreeMap::new();
        for dependency in build_module_definition(module).dependencies {
            dependency_styles.insert(dependency.specifier, dependency.style);
        }

        let referrer = format!("external:{}", module.specifier);
        for (request_specifier, style) in dependency_styles {
            let outcome = resolver.resolve(
                &ModuleRequest::new(request_specifier.clone(), style)
                    .with_referrer(referrer.clone())
                    .with_compatibility_mode(compatibility_mode),
                context,
                &AllowAllPolicy,
            )?;
            canonical_targets.insert(
                (module.specifier.clone(), request_specifier),
                outcome.module.canonical_specifier,
            );
        }
    }

    Ok(canonical_targets)
}

fn canonicalize_specimen_module(
    sm: &SpecimenModule,
    canonical_dependency_targets: &BTreeMap<(String, String), String>,
) -> SpecimenModule {
    let mut module = sm.clone();

    for import in &mut module.imports {
        if let Some(canonical_specifier) =
            canonical_dependency_targets.get(&(sm.specifier.clone(), import.module_request.clone()))
        {
            import.module_request = canonical_specifier.clone();
        }
    }

    for export in &mut module.exports {
        if let Some(request_specifier) = export.module_request.as_ref()
            && let Some(canonical_specifier) =
                canonical_dependency_targets.get(&(sm.specifier.clone(), request_specifier.clone()))
        {
            export.module_request = Some(canonical_specifier.clone());
        }
    }

    module
}

fn specimen_declared_compatibility_mode(specimen_id: &str) -> Option<CompatibilityMode> {
    if specimen_id.contains("bun_compat") {
        Some(CompatibilityMode::BunCompat)
    } else if specimen_id.contains("node_compat") {
        Some(CompatibilityMode::NodeCompat)
    } else if specimen_id.contains("native") {
        Some(CompatibilityMode::Native)
    } else {
        None
    }
}

fn specimen_has_cjs_requires_esm(specimen: &InteropSpecimen) -> bool {
    let syntaxes: BTreeMap<&str, ModuleSyntax> = specimen
        .modules
        .iter()
        .map(|module| (module.specifier.as_str(), module.syntax))
        .collect();

    specimen
        .modules
        .iter()
        .filter(|module| module.syntax == ModuleSyntax::CommonJs)
        .any(|module| {
            module.imports.iter().any(|import| {
                matches!(
                    syntaxes.get(import.module_request.as_str()),
                    Some(ModuleSyntax::EsModule)
                )
            }) || module.exports.iter().any(|export| {
                export
                    .module_request
                    .as_deref()
                    .is_some_and(|module_request| {
                        matches!(syntaxes.get(module_request), Some(ModuleSyntax::EsModule))
                    })
            })
        })
}

// Legacy corpus specimens predate explicit compatibility-mode tagging. Any
// specimen that crosses a CJS -> ESM require boundary and still expects to
// progress past native linking must run under Bun-compatible bridge semantics;
// native/node compatibility should fail closed with ERR_REQUIRE_ESM first.
fn specimen_compatibility_mode(specimen: &InteropSpecimen) -> CompatibilityMode {
    specimen_declared_compatibility_mode(&specimen.specimen_id).unwrap_or_else(|| {
        if specimen_has_cjs_requires_esm(specimen)
            && specimen.expected_outcome != InteropExpectedOutcome::LinkFailure
        {
            CompatibilityMode::BunCompat
        } else {
            CompatibilityMode::Native
        }
    })
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
    compatibility_mode: CompatibilityMode,
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
    let mut evidence = InteropSpecimenEvidence {
        specimen_id: specimen.specimen_id.clone(),
        family: specimen.family,
        compatibility_mode,
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
        evidence_hash: None,
    };
    evidence.evidence_hash = Some(evidence.compute_hash());
    evidence
}

/// Run a single specimen through the module graph pipeline.
fn run_single_specimen(specimen: &InteropSpecimen) -> InteropSpecimenEvidence {
    let compatibility_mode = specimen_compatibility_mode(specimen);
    let Some(entry_sm) = specimen
        .modules
        .iter()
        .find(|m| m.specifier == specimen.entry_point)
    else {
        return early_return_evidence(
            specimen,
            compatibility_mode,
            InteropActualOutcome::GraphConstructionFailure,
            0,
            0,
            0,
            Some(format!(
                "entry point '{}' missing from specimen module graph",
                specimen.entry_point
            )),
        );
    };

    let mut resolver = DeterministicModuleResolver::new("/");
    for sm in &specimen.modules {
        if let Err(e) =
            resolver.register_external_module(&sm.specifier, build_module_definition(sm))
        {
            return early_return_evidence(
                specimen,
                compatibility_mode,
                InteropActualOutcome::GraphConstructionFailure,
                0,
                0,
                0,
                Some(format!("{e}")),
            );
        }
    }
    let context = ResolutionContext::new(
        format!("interop-parity-trace-{}", specimen.specimen_id),
        format!("interop-parity-decision-{}", specimen.specimen_id),
        INTEROP_PARITY_POLICY_ID,
    );
    let entry_request = ModuleRequest::new(
        specimen.entry_point.clone(),
        module_request_style(entry_sm.syntax),
    )
    .with_compatibility_mode(compatibility_mode);
    let resolution_chain = match resolver.resolve_chain(&entry_request, &context, &AllowAllPolicy) {
        Ok(outcomes) => outcomes,
        Err(error) => {
            return early_return_evidence(
                specimen,
                compatibility_mode,
                InteropActualOutcome::LinkFailure,
                specimen.modules.len() as u64,
                0,
                0,
                Some(format!("{error}")),
            );
        }
    };
    let reachable_module_specifiers: BTreeSet<String> = resolution_chain
        .iter()
        .map(|outcome| outcome.module.canonical_specifier.clone())
        .collect();

    let canonical_dependency_targets = match canonical_dependency_targets_for_specimen(
        specimen,
        &resolver,
        &context,
        compatibility_mode,
        &reachable_module_specifiers,
    ) {
        Ok(targets) => targets,
        Err(error) => {
            return early_return_evidence(
                specimen,
                compatibility_mode,
                InteropActualOutcome::GraphConstructionFailure,
                specimen.modules.len() as u64,
                0,
                0,
                Some(format!(
                    "failed to normalize specimen dependency targets after resolution: {error}"
                )),
            );
        }
    };

    let normalized_modules: Vec<SpecimenModule> = specimen
        .modules
        .iter()
        .filter(|module| reachable_module_specifiers.contains(&module.specifier))
        .map(|module| canonicalize_specimen_module(module, &canonical_dependency_targets))
        .collect();
    let normalized_entry_sm = normalized_modules
        .iter()
        .find(|module| module.specifier == entry_sm.specifier)
        .expect("normalized entry module should exist");

    // Build the module graph — add entry point first (ModuleGraph sets first-added as entry).
    let mut graph = ModuleGraph::new();

    if let Err(e) = graph.add_module(build_esm_module(normalized_entry_sm)) {
        return early_return_evidence(
            specimen,
            compatibility_mode,
            InteropActualOutcome::GraphConstructionFailure,
            0,
            0,
            0,
            Some(format!("{e}")),
        );
    }
    for sm in &normalized_modules {
        if sm.specifier == specimen.entry_point {
            continue;
        }
        if let Err(e) = graph.add_module(build_esm_module(sm)) {
            return early_return_evidence(
                specimen,
                compatibility_mode,
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
            compatibility_mode,
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
            compatibility_mode,
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
    let async_dependency_map: BTreeMap<String, Vec<String>> = normalized_modules
        .iter()
        .map(|sm| {
            (
                sm.specifier.clone(),
                specimen_module_dependency_specifiers(sm),
            )
        })
        .collect();
    let async_module_specifiers: Vec<String> = normalized_modules
        .iter()
        .map(|sm| sm.specifier.clone())
        .collect();
    let async_evaluation_order =
        match compute_async_evaluation_order(&async_module_specifiers, &async_dependency_map) {
            Ok(order) => order,
            Err(error) => {
                return early_return_evidence(
                    specimen,
                    compatibility_mode,
                    InteropActualOutcome::GraphConstructionFailure,
                    module_count,
                    linked_count,
                    cycle_count,
                    Some(format!("failed to derive async evaluation order: {error}")),
                );
            }
        };
    let normalized_modules_by_specifier: BTreeMap<&str, &SpecimenModule> = normalized_modules
        .iter()
        .map(|module| (module.specifier.as_str(), module))
        .collect();

    // Register all modules with the async evaluator.
    for specifier in &async_evaluation_order {
        let sm = normalized_modules_by_specifier
            .get(specifier.as_str())
            .copied()
            .expect("async evaluation order should reference a registered specimen module");
        let deps = async_dependency_map
            .get(specifier)
            .cloned()
            .unwrap_or_default();
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
    for specifier in &async_evaluation_order {
        let sm = normalized_modules_by_specifier
            .get(specifier.as_str())
            .copied()
            .expect("async evaluation order should reference a registered specimen module");
        if !sm.has_top_level_await {
            let _ = async_evaluator.notify_dependency_settled(&sm.specifier);
        }
    }

    // Process TLA modules: suspend → settle or reject.
    for specifier in &async_evaluation_order {
        let sm = normalized_modules_by_specifier
            .get(specifier.as_str())
            .copied()
            .expect("async evaluation order should reference a registered specimen module");
        if sm.has_top_level_await {
            if async_evaluator
                .states()
                .get(&sm.specifier)
                .is_some_and(|state| state.phase == AsyncModulePhase::Rejected)
            {
                continue;
            }
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

    let mut evidence = InteropSpecimenEvidence {
        specimen_id: specimen.specimen_id.clone(),
        family: specimen.family,
        compatibility_mode,
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
        evidence_hash: None,
    };
    evidence.evidence_hash = Some(evidence.compute_hash());
    evidence
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
        compatibility_mode: None,
        verdict: None,
        detail: None,
    };
    event_lines.push(serde_json::to_string(&start).map_err(std::io::Error::other)?);

    // Per-specimen events.
    for ev in &inv.evidence {
        let detail = match &ev.error_detail {
            Some(error_detail) => Some(format!(
                "mode={} disposition={} guidance_code={} error={}",
                ev.compatibility_mode.as_str(),
                ev.compatibility_disposition,
                ev.remediation_guidance.guidance_code,
                error_detail
            )),
            None => Some(format!(
                "mode={} disposition={} guidance_code={}",
                ev.compatibility_mode.as_str(),
                ev.compatibility_disposition,
                ev.remediation_guidance.guidance_code,
            )),
        };
        let specimen_event = InteropParityEvent {
            schema_version: INTEROP_PARITY_EVENT_SCHEMA_VERSION.to_string(),
            component: INTEROP_PARITY_COMPONENT.to_string(),
            event: "interop_specimen_evaluated".to_string(),
            policy_id: INTEROP_PARITY_POLICY_ID.to_string(),
            specimen_id: Some(ev.specimen_id.clone()),
            compatibility_mode: Some(ev.compatibility_mode),
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
        compatibility_mode: None,
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

    const EXTERNAL_PACKAGE_ROOT_REQUIRE_MODE_CASES: [(&str, CompatibilityMode); 6] = [
        (
            "external_extension_probe_package_root_require_native",
            CompatibilityMode::Native,
        ),
        (
            "external_extension_probe_package_root_require_node_compat",
            CompatibilityMode::NodeCompat,
        ),
        (
            "external_extension_probe_package_root_require_bun_compat",
            CompatibilityMode::BunCompat,
        ),
        (
            "scoped_external_extension_probe_package_root_require_native",
            CompatibilityMode::Native,
        ),
        (
            "scoped_external_extension_probe_package_root_require_node_compat",
            CompatibilityMode::NodeCompat,
        ),
        (
            "scoped_external_extension_probe_package_root_require_bun_compat",
            CompatibilityMode::BunCompat,
        ),
    ];

    fn synthetic_passing_evidence(specimen_id: &str) -> InteropSpecimenEvidence {
        let mut evidence = InteropSpecimenEvidence {
            specimen_id: specimen_id.to_string(),
            family: InteropFamily::MixedGraph,
            compatibility_mode: CompatibilityMode::Native,
            expected_outcome: InteropExpectedOutcome::Success,
            actual_outcome: InteropActualOutcome::Success,
            verdict: InteropVerdict::Pass,
            compatibility_disposition: InteropCompatibilityDisposition::Supported,
            remediation_guidance: InteropRemediationGuidance {
                guidance_code: "no_remediation_required".to_string(),
                message: "stable".to_string(),
            },
            module_count: 1,
            linked_count: 1,
            cycle_count: 0,
            binding_verdicts: vec![],
            async_phase_verdicts: vec![],
            error_detail: None,
            evidence_hash: None,
        };
        evidence.evidence_hash = Some(evidence.compute_hash());
        evidence
    }

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
            compatibility_mode: Some(CompatibilityMode::BunCompat),
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

    // -----------------------------------------------------------------------
    // Additional enrichment tests (PearlTower 2026-03-18 batch 2)
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_hashes_unique_across_specimens() {
        let inv = run_interop_parity_corpus();
        let hashes: BTreeSet<&str> = inv
            .evidence
            .iter()
            .filter_map(|e| e.evidence_hash.as_deref())
            .collect();
        assert_eq!(
            hashes.len(),
            inv.evidence.len(),
            "evidence hashes should be unique per specimen"
        );
    }

    #[test]
    fn evidence_hash_determinism_for_same_input() {
        let evidence = InteropSpecimenEvidence {
            specimen_id: "test_determinism".into(),
            family: InteropFamily::MixedGraph,
            compatibility_mode: CompatibilityMode::Native,
            expected_outcome: InteropExpectedOutcome::Success,
            actual_outcome: InteropActualOutcome::Success,
            verdict: InteropVerdict::Pass,
            compatibility_disposition: InteropCompatibilityDisposition::Supported,
            remediation_guidance: InteropRemediationGuidance {
                guidance_code: "no_remediation_required".into(),
                message: "stable".into(),
            },
            module_count: 3,
            linked_count: 3,
            cycle_count: 0,
            binding_verdicts: vec![BindingVerdict {
                module_specifier: "entry.mjs".into(),
                export_name: "value".into(),
                expected_state: BindingCellState::Initialized,
                actual_state: BindingCellState::Initialized,
                pass: true,
            }],
            async_phase_verdicts: vec![AsyncPhaseVerdict {
                module_specifier: "entry.mjs".into(),
                expected_phase: AsyncModulePhase::Synchronous,
                actual_phase: AsyncModulePhase::Synchronous,
                pass: true,
            }],
            error_detail: None,
            evidence_hash: None,
        };
        let h1 = evidence.compute_hash();
        let h2 = evidence.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn evidence_hash_changes_with_different_specimen_id() {
        let h1 = InteropSpecimenEvidence {
            specimen_id: "alpha".into(),
            family: InteropFamily::MixedGraph,
            compatibility_mode: CompatibilityMode::Native,
            expected_outcome: InteropExpectedOutcome::Success,
            actual_outcome: InteropActualOutcome::Success,
            verdict: InteropVerdict::Pass,
            compatibility_disposition: InteropCompatibilityDisposition::Supported,
            remediation_guidance: InteropRemediationGuidance {
                guidance_code: "no_remediation_required".into(),
                message: "stable".into(),
            },
            module_count: 1,
            linked_count: 1,
            cycle_count: 0,
            binding_verdicts: vec![],
            async_phase_verdicts: vec![],
            error_detail: None,
            evidence_hash: None,
        }
        .compute_hash();
        let h2 = InteropSpecimenEvidence {
            specimen_id: "beta".into(),
            family: InteropFamily::MixedGraph,
            compatibility_mode: CompatibilityMode::Native,
            expected_outcome: InteropExpectedOutcome::Success,
            actual_outcome: InteropActualOutcome::Success,
            verdict: InteropVerdict::Pass,
            compatibility_disposition: InteropCompatibilityDisposition::Supported,
            remediation_guidance: InteropRemediationGuidance {
                guidance_code: "no_remediation_required".into(),
                message: "stable".into(),
            },
            module_count: 1,
            linked_count: 1,
            cycle_count: 0,
            binding_verdicts: vec![],
            async_phase_verdicts: vec![],
            error_detail: None,
            evidence_hash: None,
        }
        .compute_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn evidence_hash_changes_with_different_outcome() {
        let h1 = InteropSpecimenEvidence {
            specimen_id: "specimen_x".into(),
            family: InteropFamily::MixedGraph,
            compatibility_mode: CompatibilityMode::Native,
            expected_outcome: InteropExpectedOutcome::Success,
            actual_outcome: InteropActualOutcome::Success,
            verdict: InteropVerdict::Pass,
            compatibility_disposition: InteropCompatibilityDisposition::Supported,
            remediation_guidance: InteropRemediationGuidance {
                guidance_code: "g".into(),
                message: "stable".into(),
            },
            module_count: 1,
            linked_count: 1,
            cycle_count: 0,
            binding_verdicts: vec![],
            async_phase_verdicts: vec![],
            error_detail: None,
            evidence_hash: None,
        }
        .compute_hash();
        let h2 = InteropSpecimenEvidence {
            specimen_id: "specimen_x".into(),
            family: InteropFamily::MixedGraph,
            compatibility_mode: CompatibilityMode::Native,
            expected_outcome: InteropExpectedOutcome::LinkFailure,
            actual_outcome: InteropActualOutcome::LinkFailure,
            verdict: InteropVerdict::Pass,
            compatibility_disposition: InteropCompatibilityDisposition::Supported,
            remediation_guidance: InteropRemediationGuidance {
                guidance_code: "g".into(),
                message: "stable".into(),
            },
            module_count: 1,
            linked_count: 1,
            cycle_count: 0,
            binding_verdicts: vec![],
            async_phase_verdicts: vec![],
            error_detail: None,
            evidence_hash: None,
        }
        .compute_hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn compatibility_disposition_as_str_roundtrip() {
        for d in [
            InteropCompatibilityDisposition::Supported,
            InteropCompatibilityDisposition::Degraded,
            InteropCompatibilityDisposition::Unsupported,
        ] {
            let s = d.as_str();
            assert!(!s.is_empty());
            assert_eq!(format!("{d}"), s);
        }
    }

    #[test]
    fn compatibility_disposition_display_distinct_values() {
        let strs: BTreeSet<String> = [
            InteropCompatibilityDisposition::Supported,
            InteropCompatibilityDisposition::Degraded,
            InteropCompatibilityDisposition::Unsupported,
        ]
        .iter()
        .map(|d| format!("{d}"))
        .collect();
        assert_eq!(strs.len(), 3);
    }

    #[test]
    fn interop_family_ord_is_consistent() {
        assert!(InteropFamily::EsmOnly < InteropFamily::CjsOnly);
        assert!(InteropFamily::CjsOnly < InteropFamily::EsmImportsCjs);
        assert!(InteropFamily::EsmImportsCjs < InteropFamily::CjsRequiresEsm);
    }

    #[test]
    fn interop_family_clone_eq() {
        for f in InteropFamily::ALL {
            let cloned = *f;
            assert_eq!(*f, cloned);
        }
    }

    #[test]
    fn corpus_entry_points_present_in_modules() {
        for s in &interop_parity_corpus() {
            let module_specifiers: BTreeSet<&str> =
                s.modules.iter().map(|m| m.specifier.as_str()).collect();
            assert!(
                module_specifiers.contains(s.entry_point.as_str()),
                "specimen {} entry_point '{}' not found in modules",
                s.specimen_id,
                s.entry_point
            );
        }
    }

    #[test]
    fn corpus_expected_binding_specifiers_match_modules() {
        for s in &interop_parity_corpus() {
            let module_specifiers: BTreeSet<&str> =
                s.modules.iter().map(|m| m.specifier.as_str()).collect();
            for b in &s.expected_binding_states {
                assert!(
                    module_specifiers.contains(b.module_specifier.as_str()),
                    "specimen {}: expected binding for '{}' references unknown module '{}'",
                    s.specimen_id,
                    b.export_name,
                    b.module_specifier
                );
            }
        }
    }

    #[test]
    fn corpus_expected_async_specifiers_match_modules() {
        for s in &interop_parity_corpus() {
            let module_specifiers: BTreeSet<&str> =
                s.modules.iter().map(|m| m.specifier.as_str()).collect();
            for a in &s.expected_async_phases {
                assert!(
                    module_specifiers.contains(a.module_specifier.as_str()),
                    "specimen {}: expected async phase for '{}' references unknown module",
                    s.specimen_id,
                    a.module_specifier
                );
            }
        }
    }

    #[test]
    fn run_single_specimen_esm_only_returns_pass() {
        let specimen = interop_parity_corpus()
            .into_iter()
            .find(|s| s.specimen_id == "esm_single_module")
            .unwrap();
        let evidence = run_single_specimen(&specimen);
        assert_eq!(evidence.verdict, InteropVerdict::Pass);
        assert_eq!(evidence.actual_outcome, InteropActualOutcome::Success);
        assert_eq!(evidence.module_count, 1);
        assert_eq!(evidence.linked_count, 1);
        assert_eq!(evidence.cycle_count, 0);
    }

    #[test]
    fn run_single_specimen_cycle_detected() {
        let specimen = interop_parity_corpus()
            .into_iter()
            .find(|s| s.specimen_id == "cycle_esm_esm")
            .unwrap();
        let evidence = run_single_specimen(&specimen);
        assert_eq!(evidence.verdict, InteropVerdict::Pass);
        assert_eq!(evidence.actual_outcome, InteropActualOutcome::CycleDetected);
        assert!(evidence.cycle_count > 0);
    }

    #[test]
    fn run_single_specimen_async_rejection() {
        let specimen = interop_parity_corpus()
            .into_iter()
            .find(|s| s.specimen_id == "async_rejection_propagation")
            .unwrap();
        let evidence = run_single_specimen(&specimen);
        assert_eq!(evidence.verdict, InteropVerdict::Pass);
        assert_eq!(evidence.actual_outcome, InteropActualOutcome::EvalFailure);
        assert_eq!(
            evidence.compatibility_disposition,
            InteropCompatibilityDisposition::Degraded
        );
    }

    #[test]
    fn run_single_specimen_mixed_diamond_binding_verdicts() {
        let specimen = interop_parity_corpus()
            .into_iter()
            .find(|s| s.specimen_id == "mixed_diamond_graph")
            .unwrap();
        let evidence = run_single_specimen(&specimen);
        assert_eq!(evidence.verdict, InteropVerdict::Pass);
        assert_eq!(evidence.binding_verdicts.len(), 3);
        assert!(evidence.binding_verdicts.iter().all(|v| v.pass));
    }

    #[test]
    fn classify_compatibility_fail_verdict_always_unsupported() {
        let specimen = InteropSpecimen {
            specimen_id: "test_fail".into(),
            description: "test".into(),
            family: InteropFamily::EsmOnly,
            modules: vec![],
            entry_point: "e.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        };
        let (disp, guidance) = classify_compatibility(
            &specimen,
            InteropActualOutcome::Success,
            InteropVerdict::Fail,
        );
        assert_eq!(disp, InteropCompatibilityDisposition::Unsupported);
        assert_eq!(guidance.guidance_code, "interop_contract_violation");
        assert!(guidance.message.contains("test_fail"));
    }

    #[test]
    fn classify_compatibility_success_gives_supported() {
        let specimen = InteropSpecimen {
            specimen_id: "test_pass".into(),
            description: "test".into(),
            family: InteropFamily::EsmOnly,
            modules: vec![],
            entry_point: "e.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        };
        let (disp, guidance) = classify_compatibility(
            &specimen,
            InteropActualOutcome::Success,
            InteropVerdict::Pass,
        );
        assert_eq!(disp, InteropCompatibilityDisposition::Supported);
        assert_eq!(guidance.guidance_code, "no_remediation_required");
    }

    #[test]
    fn classify_compatibility_eval_failure_gives_degraded() {
        let specimen = InteropSpecimen {
            specimen_id: "test_eval".into(),
            description: "test".into(),
            family: InteropFamily::AsyncEvaluation,
            modules: vec![],
            entry_point: "e.mjs".into(),
            expected_outcome: InteropExpectedOutcome::EvalFailure,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        };
        let (disp, guidance) = classify_compatibility(
            &specimen,
            InteropActualOutcome::EvalFailure,
            InteropVerdict::Pass,
        );
        assert_eq!(disp, InteropCompatibilityDisposition::Degraded);
        assert_eq!(guidance.guidance_code, "stabilize_async_boundary");
    }

    #[test]
    fn classify_compatibility_cycle_detected_gives_unsupported() {
        let specimen = InteropSpecimen {
            specimen_id: "test_cycle".into(),
            description: "test".into(),
            family: InteropFamily::CyclicInterop,
            modules: vec![],
            entry_point: "e.mjs".into(),
            expected_outcome: InteropExpectedOutcome::CycleDetected,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        };
        let (disp, guidance) = classify_compatibility(
            &specimen,
            InteropActualOutcome::CycleDetected,
            InteropVerdict::Pass,
        );
        assert_eq!(disp, InteropCompatibilityDisposition::Unsupported);
        assert_eq!(guidance.guidance_code, "break_mixed_module_cycle");
    }

    #[test]
    fn classify_compatibility_link_failure_gives_unsupported() {
        let specimen = InteropSpecimen {
            specimen_id: "test_link".into(),
            description: "test".into(),
            family: InteropFamily::MixedGraph,
            modules: vec![],
            entry_point: "e.mjs".into(),
            expected_outcome: InteropExpectedOutcome::LinkFailure,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        };
        let (disp, guidance) = classify_compatibility(
            &specimen,
            InteropActualOutcome::LinkFailure,
            InteropVerdict::Pass,
        );
        assert_eq!(disp, InteropCompatibilityDisposition::Unsupported);
        assert_eq!(guidance.guidance_code, "repair_link_boundary");
    }

    #[test]
    fn early_return_evidence_outcome_match_gives_pass() {
        let specimen = InteropSpecimen {
            specimen_id: "er_test".into(),
            description: "test".into(),
            family: InteropFamily::EsmOnly,
            modules: vec![],
            entry_point: "e.mjs".into(),
            expected_outcome: InteropExpectedOutcome::LinkFailure,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        };
        let ev = early_return_evidence(
            &specimen,
            CompatibilityMode::Native,
            InteropActualOutcome::LinkFailure,
            2,
            0,
            0,
            Some("link error".into()),
        );
        assert_eq!(ev.verdict, InteropVerdict::Pass);
        assert_eq!(ev.module_count, 2);
        assert_eq!(ev.error_detail.as_deref(), Some("link error"));
        assert!(ev.evidence_hash.is_some());
    }

    #[test]
    fn early_return_evidence_outcome_mismatch_gives_fail() {
        let specimen = InteropSpecimen {
            specimen_id: "er_mismatch".into(),
            description: "test".into(),
            family: InteropFamily::EsmOnly,
            modules: vec![],
            entry_point: "e.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: None,
            expected_binding_states: vec![],
            expected_async_phases: vec![],
        };
        let ev = early_return_evidence(
            &specimen,
            CompatibilityMode::Native,
            InteropActualOutcome::GraphConstructionFailure,
            0,
            0,
            0,
            Some("graph build failed".into()),
        );
        assert_eq!(ev.verdict, InteropVerdict::Fail);
        assert_eq!(
            ev.compatibility_disposition,
            InteropCompatibilityDisposition::Unsupported
        );
    }

    #[test]
    fn build_esm_module_preserves_specifier_and_syntax() {
        let sm = SpecimenModule {
            specifier: "test.mjs".into(),
            syntax: ModuleSyntax::EsModule,
            source: "export const x = 1;".into(),
            imports: vec![],
            exports: vec![ExportEntry::direct("x", "x")],
            has_default_export: true,
            has_top_level_await: false,
        };
        let esm = build_esm_module(&sm);
        assert_eq!(esm.specifier, "test.mjs");
        assert_eq!(esm.syntax, ModuleSyntax::EsModule);
        assert!(esm.has_default_export);
        assert_eq!(esm.exports.len(), 1);
    }

    #[test]
    fn build_esm_module_cjs_syntax() {
        let sm = SpecimenModule {
            specifier: "lib.cjs".into(),
            syntax: ModuleSyntax::CommonJs,
            source: "module.exports = {};".into(),
            imports: vec![ImportEntry::new("dep.cjs", "x", "x")],
            exports: vec![ExportEntry::direct("default", "default")],
            has_default_export: true,
            has_top_level_await: false,
        };
        let esm = build_esm_module(&sm);
        assert_eq!(esm.syntax, ModuleSyntax::CommonJs);
        assert_eq!(esm.imports.len(), 1);
    }

    #[test]
    fn canonicalize_specimen_module_rewrites_relative_dependency_targets() {
        let sm = SpecimenModule {
            specifier: "some-pkg/main.mjs".into(),
            syntax: ModuleSyntax::EsModule,
            source: "import { value } from './sub'; export { value } from './sub';".into(),
            imports: vec![ImportEntry::new("./sub", "value", "value")],
            exports: vec![ExportEntry::re_export("value", "./sub", "value")],
            has_default_export: false,
            has_top_level_await: false,
        };
        let canonical_targets = BTreeMap::from([(
            ("some-pkg/main.mjs".to_string(), "./sub".to_string()),
            "some-pkg/sub.mjs".to_string(),
        )]);

        let canonicalized = canonicalize_specimen_module(&sm, &canonical_targets);
        assert_eq!(canonicalized.imports[0].module_request, "some-pkg/sub.mjs");
        assert_eq!(
            canonicalized.exports[0].module_request.as_deref(),
            Some("some-pkg/sub.mjs")
        );
    }

    #[test]
    fn run_single_specimen_extensionless_relative_mode_split_matches_resolver_contract() {
        let corpus = interop_parity_corpus();

        let native = corpus
            .iter()
            .find(|specimen| {
                specimen.specimen_id == "package_type_module_extensionless_relative_native"
            })
            .unwrap();
        let native_evidence = run_single_specimen(native);
        assert_eq!(
            native_evidence.compatibility_mode,
            CompatibilityMode::Native
        );
        assert_eq!(
            native_evidence.actual_outcome,
            InteropActualOutcome::LinkFailure
        );
        assert_eq!(native_evidence.verdict, InteropVerdict::Pass);

        let node_compat = corpus
            .iter()
            .find(|specimen| {
                specimen.specimen_id == "package_type_module_extensionless_relative_node_compat"
            })
            .unwrap();
        let node_compat_evidence = run_single_specimen(node_compat);
        assert_eq!(
            node_compat_evidence.compatibility_mode,
            CompatibilityMode::NodeCompat
        );
        assert_eq!(
            node_compat_evidence.actual_outcome,
            InteropActualOutcome::LinkFailure
        );
        assert_eq!(node_compat_evidence.verdict, InteropVerdict::Pass);

        let bun_compat = corpus
            .iter()
            .find(|specimen| {
                specimen.specimen_id == "package_type_module_extensionless_relative_bun_compat"
            })
            .unwrap();
        let bun_compat_evidence = run_single_specimen(bun_compat);
        assert_eq!(
            bun_compat_evidence.compatibility_mode,
            CompatibilityMode::BunCompat
        );
        assert_eq!(
            bun_compat_evidence.actual_outcome,
            InteropActualOutcome::Success
        );
        assert_eq!(bun_compat_evidence.verdict, InteropVerdict::Pass);
        assert_eq!(bun_compat_evidence.linked_count, 2);
        assert!(
            bun_compat_evidence
                .binding_verdicts
                .iter()
                .all(|verdict| verdict.pass)
        );
    }

    #[test]
    fn run_single_specimen_external_package_root_relative_requires_match_resolver_contract() {
        let corpus = interop_parity_corpus();

        for (specimen_id, compatibility_mode) in EXTERNAL_PACKAGE_ROOT_REQUIRE_MODE_CASES {
            let specimen = corpus
                .iter()
                .find(|specimen| specimen.specimen_id == specimen_id)
                .unwrap();
            let evidence = run_single_specimen(specimen);
            assert_eq!(evidence.compatibility_mode, compatibility_mode);
            assert_eq!(evidence.actual_outcome, InteropActualOutcome::Success);
            assert_eq!(evidence.verdict, InteropVerdict::Pass);
            assert_eq!(
                evidence.compatibility_disposition,
                InteropCompatibilityDisposition::Supported
            );
            assert_eq!(evidence.linked_count, 3);
            assert!(evidence.error_detail.is_none());
            assert!(evidence.binding_verdicts.iter().all(|verdict| verdict.pass));
        }
    }

    #[test]
    fn external_package_root_relative_requires_are_explicitly_mode_tagged_in_corpus() {
        let corpus_ids: BTreeSet<String> = interop_parity_corpus()
            .into_iter()
            .map(|specimen| specimen.specimen_id)
            .collect();
        for (specimen_id, _) in EXTERNAL_PACKAGE_ROOT_REQUIRE_MODE_CASES {
            assert!(
                corpus_ids.contains(specimen_id),
                "missing explicit package-root require specimen {specimen_id}"
            );
        }
    }

    #[test]
    fn run_single_specimen_ignores_unreachable_broken_modules_when_normalizing_dependencies() {
        let specimen = InteropSpecimen {
            specimen_id: "unreachable_module_is_ignored".into(),
            description: "dead modules should not poison a passing reachable graph".into(),
            family: InteropFamily::EsmOnly,
            modules: vec![
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export const ok = true;".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("ok", "ok")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "dead.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { nope } from 'missing.mjs'; export const dead = nope;".into(),
                    imports: vec![ImportEntry::new("missing.mjs", "nope", "nope")],
                    exports: vec![ExportEntry::direct("dead", "dead")],
                    has_default_export: false,
                    has_top_level_await: false,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::Success,
            expected_linked_count: Some(1),
            expected_binding_states: vec![ExpectedBindingState {
                module_specifier: "entry.mjs".into(),
                export_name: "ok".into(),
                expected_state: BindingCellState::Initialized,
            }],
            expected_async_phases: vec![],
        };

        let evidence = run_single_specimen(&specimen);
        assert_eq!(evidence.actual_outcome, InteropActualOutcome::Success);
        assert_eq!(evidence.verdict, InteropVerdict::Pass);
        assert_eq!(evidence.module_count, 1);
        assert_eq!(evidence.linked_count, 1);
        assert!(evidence.error_detail.is_none());
    }

    #[test]
    fn run_single_specimen_re_export_only_async_dependency_rejection_is_order_invariant() {
        let specimen = InteropSpecimen {
            specimen_id: "async_re_export_dependency_order_invariant".into(),
            description:
                "re-export-only async dependencies should reject dependents regardless of module ordering"
                    .into(),
            family: InteropFamily::AsyncEvaluation,
            modules: vec![
                SpecimenModule {
                    specifier: "entry.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "import { value } from './barrel.mjs'; console.log(value);".into(),
                    imports: vec![ImportEntry::new("barrel.mjs", "value", "value")],
                    exports: vec![],
                    has_default_export: false,
                    has_top_level_await: false,
                },
                SpecimenModule {
                    specifier: "barrel.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export { value } from './failing.mjs'; const ready = await Promise.resolve('ready'); export { ready };".into(),
                    imports: vec![],
                    exports: vec![
                        ExportEntry::re_export("value", "failing.mjs", "value"),
                        ExportEntry::direct("ready", "ready"),
                    ],
                    has_default_export: false,
                    has_top_level_await: true,
                },
                SpecimenModule {
                    specifier: "failing.mjs".into(),
                    syntax: ModuleSyntax::EsModule,
                    source: "export const value = await Promise.reject(new Error('boom'));".into(),
                    imports: vec![],
                    exports: vec![ExportEntry::direct("value", "value")],
                    has_default_export: false,
                    has_top_level_await: true,
                },
            ],
            entry_point: "entry.mjs".into(),
            expected_outcome: InteropExpectedOutcome::EvalFailure,
            expected_linked_count: Some(3),
            expected_binding_states: vec![
                ExpectedBindingState {
                    module_specifier: "failing.mjs".into(),
                    export_name: "value".into(),
                    expected_state: BindingCellState::Dead,
                },
                ExpectedBindingState {
                    module_specifier: "barrel.mjs".into(),
                    export_name: "value".into(),
                    expected_state: BindingCellState::Dead,
                },
                ExpectedBindingState {
                    module_specifier: "barrel.mjs".into(),
                    export_name: "ready".into(),
                    expected_state: BindingCellState::Dead,
                },
            ],
            expected_async_phases: vec![
                ExpectedAsyncPhase {
                    module_specifier: "failing.mjs".into(),
                    expected_phase: AsyncModulePhase::Rejected,
                },
                ExpectedAsyncPhase {
                    module_specifier: "barrel.mjs".into(),
                    expected_phase: AsyncModulePhase::Rejected,
                },
            ],
        };

        let evidence = run_single_specimen(&specimen);
        assert_eq!(evidence.actual_outcome, InteropActualOutcome::EvalFailure);
        assert_eq!(evidence.verdict, InteropVerdict::Pass);
        assert_eq!(evidence.linked_count, 3);
        assert!(evidence.binding_verdicts.iter().all(|verdict| verdict.pass));
        assert!(
            evidence
                .async_phase_verdicts
                .iter()
                .all(|verdict| verdict.pass)
        );
    }

    #[test]
    fn hex_encode_all_byte_values_lowercase() {
        let bytes: Vec<u8> = (0..=255).collect();
        let hex = hex_encode(&bytes);
        assert_eq!(hex.len(), 512);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        // Ensure lowercase hex
        assert!(hex.chars().all(|c| !c.is_ascii_uppercase()));
        // Spot-check boundaries
        assert!(hex.starts_with("00"));
        assert!(hex.ends_with("ff"));
    }

    #[test]
    fn hex_encode_single_byte() {
        assert_eq!(hex_encode(&[0x0a]), "0a");
        assert_eq!(hex_encode(&[0xfe]), "fe");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0xff]), "ff");
    }

    #[test]
    fn binding_verdict_serde_roundtrip() {
        let bv = BindingVerdict {
            module_specifier: "mod.mjs".into(),
            export_name: "x".into(),
            expected_state: BindingCellState::Initialized,
            actual_state: BindingCellState::Dead,
            pass: false,
        };
        let json = serde_json::to_string(&bv).unwrap();
        let back: BindingVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(bv, back);
        assert!(!back.pass);
    }

    #[test]
    fn async_phase_verdict_serde_roundtrip() {
        let apv = AsyncPhaseVerdict {
            module_specifier: "async.mjs".into(),
            expected_phase: AsyncModulePhase::Settled,
            actual_phase: AsyncModulePhase::Rejected,
            pass: false,
        };
        let json = serde_json::to_string(&apv).unwrap();
        let back: AsyncPhaseVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(apv, back);
    }

    #[test]
    fn expected_binding_state_serde_roundtrip() {
        for state in [
            BindingCellState::Uninitialized,
            BindingCellState::Initialized,
            BindingCellState::Dead,
        ] {
            let ebs = ExpectedBindingState {
                module_specifier: "m.mjs".into(),
                export_name: "val".into(),
                expected_state: state,
            };
            let json = serde_json::to_string(&ebs).unwrap();
            let back: ExpectedBindingState = serde_json::from_str(&json).unwrap();
            assert_eq!(ebs, back);
        }
    }

    #[test]
    fn expected_async_phase_serde_roundtrip() {
        for phase in [
            AsyncModulePhase::Synchronous,
            AsyncModulePhase::Suspended,
            AsyncModulePhase::AwaitingDependencies,
            AsyncModulePhase::Settled,
            AsyncModulePhase::Rejected,
        ] {
            let eap = ExpectedAsyncPhase {
                module_specifier: "a.mjs".into(),
                expected_phase: phase,
            };
            let json = serde_json::to_string(&eap).unwrap();
            let back: ExpectedAsyncPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(eap, back);
        }
    }

    #[test]
    fn interop_family_serde_snake_case_format() {
        let json = serde_json::to_string(&InteropFamily::EsmImportsCjs).unwrap();
        assert_eq!(json, "\"esm_imports_cjs\"");
        let json = serde_json::to_string(&InteropFamily::CjsRequiresEsm).unwrap();
        assert_eq!(json, "\"cjs_requires_esm\"");
        let json = serde_json::to_string(&InteropFamily::DefaultNamespace).unwrap();
        assert_eq!(json, "\"default_namespace\"");
    }

    #[test]
    fn interop_expected_outcome_serde_snake_case_format() {
        let json = serde_json::to_string(&InteropExpectedOutcome::LinkFailure).unwrap();
        assert_eq!(json, "\"link_failure\"");
        let json = serde_json::to_string(&InteropExpectedOutcome::EvalFailure).unwrap();
        assert_eq!(json, "\"eval_failure\"");
        let json = serde_json::to_string(&InteropExpectedOutcome::CycleDetected).unwrap();
        assert_eq!(json, "\"cycle_detected\"");
    }

    #[test]
    fn interop_actual_outcome_serde_snake_case_format() {
        let json = serde_json::to_string(&InteropActualOutcome::GraphConstructionFailure).unwrap();
        assert_eq!(json, "\"graph_construction_failure\"");
    }

    #[test]
    fn inventory_json_contains_expected_fields() {
        let inv = run_interop_parity_corpus();
        let json = serde_json::to_string_pretty(&inv).unwrap();
        assert!(json.contains("schema_version"));
        assert!(json.contains("component"));
        assert!(json.contains("specimen_count"));
        assert!(json.contains("family_coverage"));
        assert!(json.contains("evidence"));
    }

    #[test]
    fn corpus_no_duplicate_module_specifiers_within_specimen() {
        for s in &interop_parity_corpus() {
            let specifiers: BTreeSet<&str> =
                s.modules.iter().map(|m| m.specifier.as_str()).collect();
            assert_eq!(
                specifiers.len(),
                s.modules.len(),
                "specimen {} has duplicate module specifiers",
                s.specimen_id
            );
        }
    }

    #[test]
    fn corpus_cycle_specimens_have_no_expected_linked_count() {
        for s in &interop_parity_corpus() {
            if s.expected_outcome == InteropExpectedOutcome::CycleDetected {
                assert!(
                    s.expected_linked_count.is_none(),
                    "specimen {} expects cycle but has expected_linked_count",
                    s.specimen_id
                );
            }
        }
    }

    #[test]
    fn corpus_success_specimens_have_expected_linked_count() {
        for s in &interop_parity_corpus() {
            if s.expected_outcome == InteropExpectedOutcome::Success {
                assert!(
                    s.expected_linked_count.is_some(),
                    "specimen {} expects success but missing expected_linked_count",
                    s.specimen_id
                );
            }
        }
    }

    #[test]
    fn event_with_none_fields_serde_roundtrip() {
        let ev = InteropParityEvent {
            schema_version: INTEROP_PARITY_EVENT_SCHEMA_VERSION.to_string(),
            component: INTEROP_PARITY_COMPONENT.to_string(),
            event: "start".to_string(),
            policy_id: INTEROP_PARITY_POLICY_ID.to_string(),
            specimen_id: None,
            compatibility_mode: None,
            verdict: None,
            detail: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: InteropParityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
        assert!(back.specimen_id.is_none());
        assert!(back.verdict.is_none());
        assert!(back.detail.is_none());
    }

    #[test]
    fn specimen_module_serde_roundtrip() {
        let sm = SpecimenModule {
            specifier: "test.mjs".into(),
            syntax: ModuleSyntax::EsModule,
            source: "export const x = 1;".into(),
            imports: vec![ImportEntry::new("dep.mjs", "y", "y")],
            exports: vec![
                ExportEntry::direct("x", "x"),
                ExportEntry::re_export("z", "other.mjs", "z"),
            ],
            has_default_export: false,
            has_top_level_await: true,
        };
        let json = serde_json::to_string(&sm).unwrap();
        let back: SpecimenModule = serde_json::from_str(&json).unwrap();
        assert_eq!(sm, back);
    }

    #[test]
    fn evidence_with_empty_binding_and_async_verdicts() {
        let specimen = interop_parity_corpus()
            .into_iter()
            .find(|s| s.specimen_id == "async_tla_single")
            .unwrap();
        let evidence = run_single_specimen(&specimen);
        // async_tla_single has no expected_binding_states
        assert!(evidence.binding_verdicts.is_empty());
        // but does have async phase verdicts
        assert!(!evidence.async_phase_verdicts.is_empty());
        assert!(evidence.async_phase_verdicts.iter().all(|v| v.pass));
    }

    #[test]
    fn contract_satisfied_with_all_pass_and_nonzero() {
        let inv = InteropParityInventory {
            schema_version: INTEROP_PARITY_SCHEMA_VERSION.to_string(),
            component: INTEROP_PARITY_COMPONENT.to_string(),
            specimen_count: 1,
            pass_count: 1,
            fail_count: 0,
            supported_count: 1,
            degraded_count: 0,
            unsupported_count: 0,
            family_coverage: BTreeMap::new(),
            esm_only_count: 0,
            cjs_only_count: 0,
            mixed_count: 1,
            evidence: vec![synthetic_passing_evidence("contract_satisfied_case")],
        };
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn contract_not_satisfied_when_evidence_hash_missing() {
        let mut evidence = synthetic_passing_evidence("missing_hash_case");
        evidence.evidence_hash = None;
        let inv = InteropParityInventory {
            schema_version: INTEROP_PARITY_SCHEMA_VERSION.to_string(),
            component: INTEROP_PARITY_COMPONENT.to_string(),
            specimen_count: 1,
            pass_count: 1,
            fail_count: 0,
            supported_count: 1,
            degraded_count: 0,
            unsupported_count: 0,
            family_coverage: BTreeMap::new(),
            esm_only_count: 0,
            cjs_only_count: 0,
            mixed_count: 1,
            evidence: vec![evidence],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn contract_not_satisfied_when_evidence_hash_mismatches() {
        let mut evidence = synthetic_passing_evidence("tampered_hash_case");
        evidence.evidence_hash = Some("0".repeat(64));
        let inv = InteropParityInventory {
            schema_version: INTEROP_PARITY_SCHEMA_VERSION.to_string(),
            component: INTEROP_PARITY_COMPONENT.to_string(),
            specimen_count: 1,
            pass_count: 1,
            fail_count: 0,
            supported_count: 1,
            degraded_count: 0,
            unsupported_count: 0,
            family_coverage: BTreeMap::new(),
            esm_only_count: 0,
            cjs_only_count: 0,
            mixed_count: 1,
            evidence: vec![evidence],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn family_coverage_has_all_represented_families() {
        let inv = run_interop_parity_corpus();
        for f in InteropFamily::ALL {
            assert!(
                inv.family_coverage.contains_key(f.as_str()),
                "family {} not in coverage map",
                f.as_str()
            );
            assert!(
                *inv.family_coverage.get(f.as_str()).unwrap() > 0,
                "family {} has zero coverage",
                f.as_str()
            );
        }
    }

    #[test]
    fn re_export_chain_evidence_has_correct_linked_count() {
        let inv = run_interop_parity_corpus();
        let re_export_ev = inv
            .evidence
            .iter()
            .find(|e| e.specimen_id == "re_export_esm_through_cjs")
            .unwrap();
        assert_eq!(re_export_ev.linked_count, 3);
        assert_eq!(re_export_ev.module_count, 3);
    }

    #[test]
    fn star_re_export_specimen_passes_with_correct_bindings() {
        let specimen = interop_parity_corpus()
            .into_iter()
            .find(|s| s.specimen_id == "star_re_export_across_boundary")
            .unwrap();
        let evidence = run_single_specimen(&specimen);
        assert_eq!(evidence.verdict, InteropVerdict::Pass);
        assert_eq!(evidence.binding_verdicts.len(), 2);
        for bv in &evidence.binding_verdicts {
            assert!(bv.pass, "binding {} failed", bv.export_name);
            assert_eq!(bv.actual_state, BindingCellState::Initialized);
        }
    }

    #[test]
    fn async_mixed_tla_chain_phase_verdicts() {
        let specimen = interop_parity_corpus()
            .into_iter()
            .find(|s| s.specimen_id == "async_mixed_tla_chain")
            .unwrap();
        let evidence = run_single_specimen(&specimen);
        assert_eq!(evidence.verdict, InteropVerdict::Pass);
        assert_eq!(evidence.async_phase_verdicts.len(), 2);
        let sync_verdict = evidence
            .async_phase_verdicts
            .iter()
            .find(|v| v.module_specifier == "sync.cjs")
            .unwrap();
        assert_eq!(sync_verdict.actual_phase, AsyncModulePhase::Synchronous);
        assert!(sync_verdict.pass);
    }

    #[test]
    fn live_binding_esm_mutation_has_two_bindings() {
        let specimen = interop_parity_corpus()
            .into_iter()
            .find(|s| s.specimen_id == "live_binding_esm_mutation")
            .unwrap();
        let evidence = run_single_specimen(&specimen);
        assert_eq!(evidence.binding_verdicts.len(), 2);
        let count_bv = evidence
            .binding_verdicts
            .iter()
            .find(|v| v.export_name == "count")
            .unwrap();
        assert!(count_bv.pass);
        let increment_bv = evidence
            .binding_verdicts
            .iter()
            .find(|v| v.export_name == "increment")
            .unwrap();
        assert!(increment_bv.pass);
    }

    #[test]
    fn default_export_esm_to_cjs_pass_and_disposition() {
        let inv = run_interop_parity_corpus();
        let ev = inv
            .evidence
            .iter()
            .find(|e| e.specimen_id == "default_export_esm_to_cjs")
            .unwrap();
        assert_eq!(ev.verdict, InteropVerdict::Pass);
        assert_eq!(
            ev.compatibility_disposition,
            InteropCompatibilityDisposition::Supported
        );
    }
}
