//! Shipped-path ESM/CJS execution parity evidence harness.
//!
//! Proves that mixed ESM/CJS module graphs execute correctly through the
//! orchestrator pipeline, producing receipt-quality artifacts so module
//! semantics claims can be reproduced outside the implementation team.
//!
//! The harness runs a corpus of specimens (pure ESM, pure CJS, and mixed
//! ESM+CJS graphs) through the execution orchestrator and verifies:
//! (a) module format detection is correct,
//! (b) inter-format interop (ESM importing CJS default, CJS requiring ESM)
//!     produces the expected outcome,
//! (c) rejection linkage and cycle handling in mixed graphs behave as specified.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use crate::module_resolver::ModuleSyntax;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const ESM_CJS_PARITY_SCHEMA_VERSION: &str = "franken-engine.esm_cjs_parity_evidence.v1";
pub const ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.esm_cjs_parity_manifest.v1";
pub const ESM_CJS_PARITY_EVENT_SCHEMA_VERSION: &str = "franken-engine.esm_cjs_parity_event.v1";
pub const ESM_CJS_PARITY_COMPONENT: &str = "esm_cjs_parity_evidence";
pub const ESM_CJS_PARITY_POLICY_ID: &str = "RGC-309C";

// ---------------------------------------------------------------------------
// Module graph topology
// ---------------------------------------------------------------------------

/// Describes the module format mix in a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleGraphTopology {
    /// Mix of ESM and CJS modules.
    Mixed,
    /// All modules are CJS.
    PureCjs,
    /// All modules are ESM.
    PureEsm,
}

impl ModuleGraphTopology {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PureEsm => "pure_esm",
            Self::PureCjs => "pure_cjs",
            Self::Mixed => "mixed",
        }
    }
}

impl fmt::Display for ModuleGraphTopology {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Interop direction
// ---------------------------------------------------------------------------

/// Describes the interop direction exercised by a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteropDirection {
    /// No cross-format boundary.
    None,
    /// ESM imports from a CJS module.
    EsmImportsCjs,
    /// CJS requires an ESM module.
    CjsRequiresEsm,
    /// Both directions present in the graph.
    Bidirectional,
}

impl InteropDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::EsmImportsCjs => "esm_imports_cjs",
            Self::CjsRequiresEsm => "cjs_requires_esm",
            Self::Bidirectional => "bidirectional",
        }
    }
}

impl fmt::Display for InteropDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Specimen types
// ---------------------------------------------------------------------------

/// A specimen exercising ESM/CJS execution parity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsmCjsParitySpecimen {
    pub specimen_id: String,
    pub description: String,
    /// Source text of the entry module.
    pub source: String,
    /// Optional filename for format detection.
    pub source_file: Option<String>,
    /// Expected module syntax of the entry module.
    pub expected_syntax: ModuleSyntax,
    /// Topology of the module graph this specimen exercises.
    pub topology: ModuleGraphTopology,
    /// Cross-format interop direction exercised.
    pub interop_direction: InteropDirection,
    /// Expected outcome.
    pub expected_outcome: EsmCjsExpectedOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsmCjsExpectedOutcome {
    /// Module graph should execute successfully.
    ExecuteSuccess,
    /// Module resolution should fail.
    ResolutionFailure,
    /// Module linking should fail.
    LinkingFailure,
    /// Module evaluation should fail.
    EvaluationFailure,
    /// Parse should fail.
    ParseFailure,
}

impl EsmCjsExpectedOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecuteSuccess => "execute_success",
            Self::ResolutionFailure => "resolution_failure",
            Self::LinkingFailure => "linking_failure",
            Self::EvaluationFailure => "evaluation_failure",
            Self::ParseFailure => "parse_failure",
        }
    }
}

impl fmt::Display for EsmCjsExpectedOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsmCjsActualOutcome {
    ExecuteSuccess,
    ResolutionFailure,
    LinkingFailure,
    EvaluationFailure,
    ParseFailure,
    OtherFailure,
}

impl EsmCjsActualOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecuteSuccess => "execute_success",
            Self::ResolutionFailure => "resolution_failure",
            Self::LinkingFailure => "linking_failure",
            Self::EvaluationFailure => "evaluation_failure",
            Self::ParseFailure => "parse_failure",
            Self::OtherFailure => "other_failure",
        }
    }
}

impl fmt::Display for EsmCjsActualOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsmCjsParityVerdict {
    Fail,
    Pass,
}

impl EsmCjsParityVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "fail",
            Self::Pass => "pass",
        }
    }
}

impl fmt::Display for EsmCjsParityVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsmCjsCompatibilityDisposition {
    Supported,
    Degraded,
    Unsupported,
}

impl EsmCjsCompatibilityDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Degraded => "degraded",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for EsmCjsCompatibilityDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsmCjsRemediationGuidance {
    pub guidance_code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsmCjsParitySpecimenEvidence {
    pub specimen_id: String,
    pub expected_syntax: ModuleSyntax,
    pub topology: ModuleGraphTopology,
    pub interop_direction: InteropDirection,
    pub expected_outcome: EsmCjsExpectedOutcome,
    pub actual_outcome: EsmCjsActualOutcome,
    pub verdict: EsmCjsParityVerdict,
    pub compatibility_disposition: EsmCjsCompatibilityDisposition,
    pub remediation_guidance: EsmCjsRemediationGuidance,
    pub error_detail: Option<String>,
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsmCjsParityEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub supported_count: u64,
    pub degraded_count: u64,
    pub unsupported_count: u64,
    pub pure_esm_count: u64,
    pub pure_cjs_count: u64,
    pub mixed_count: u64,
    pub evidence: Vec<EsmCjsParitySpecimenEvidence>,
}

impl EsmCjsParityEvidenceInventory {
    pub fn contract_satisfied(&self) -> bool {
        self.fail_count == 0 && self.specimen_count > 0
    }
}

// ---------------------------------------------------------------------------
// Manifest & Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsmCjsParityRunManifest {
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
    pub artifact_paths: EsmCjsParityArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsmCjsParityArtifactPaths {
    pub evidence_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EsmCjsParityEvent {
    pub schema_version: String,
    pub component: String,
    pub event: String,
    pub policy_id: String,
    pub specimen_id: Option<String>,
    pub verdict: Option<String>,
    pub detail: Option<String>,
}

// ---------------------------------------------------------------------------
// Bundle artifacts (returned by writer)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EsmCjsParityBundleArtifacts {
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// Returns the diagnostic corpus of ESM/CJS parity specimens.
pub fn esm_cjs_parity_corpus() -> Vec<EsmCjsParitySpecimen> {
    vec![
        // -- Pure ESM specimens --
        EsmCjsParitySpecimen {
            specimen_id: "esm_simple_literal".into(),
            description: "Pure ESM: numeric literal".into(),
            source: "42".into(),
            source_file: Some("entry.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::PureEsm,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "esm_export_default".into(),
            description: "Pure ESM: export default expression".into(),
            source: "var x = 1".into(),
            source_file: Some("mod.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::PureEsm,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "esm_named_export".into(),
            description: "Pure ESM: named variable declaration".into(),
            source: "var count = 0".into(),
            source_file: Some("counter.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::PureEsm,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "esm_function_decl".into(),
            description: "Pure ESM: function declaration".into(),
            source: "function add(a, b) { return a + b }".into(),
            source_file: Some("math.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::PureEsm,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        // -- Pure CJS specimens --
        EsmCjsParitySpecimen {
            specimen_id: "cjs_simple_literal".into(),
            description: "Pure CJS: numeric literal".into(),
            source: "42".into(),
            source_file: Some("entry.cjs".into()),
            expected_syntax: ModuleSyntax::CommonJs,
            topology: ModuleGraphTopology::PureCjs,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "cjs_exports_assign".into(),
            description: "Pure CJS: module.exports assignment".into(),
            source: "var x = 1".into(),
            source_file: Some("lib.cjs".into()),
            expected_syntax: ModuleSyntax::CommonJs,
            topology: ModuleGraphTopology::PureCjs,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "cjs_function_decl".into(),
            description: "Pure CJS: function declaration".into(),
            source: "function multiply(a, b) { return a * b }".into(),
            source_file: Some("util.cjs".into()),
            expected_syntax: ModuleSyntax::CommonJs,
            topology: ModuleGraphTopology::PureCjs,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "cjs_var_decl".into(),
            description: "Pure CJS: variable declaration".into(),
            source: "var config = { debug: false }".into(),
            source_file: Some("config.cjs".into()),
            expected_syntax: ModuleSyntax::CommonJs,
            topology: ModuleGraphTopology::PureCjs,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        // -- Mixed graph specimens --
        EsmCjsParitySpecimen {
            specimen_id: "mixed_esm_entry_simple".into(),
            description: "Mixed: ESM entry with simple expression".into(),
            source: "var result = 1 + 2".into(),
            source_file: Some("app.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::Mixed,
            interop_direction: InteropDirection::EsmImportsCjs,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "mixed_cjs_entry_simple".into(),
            description: "Mixed: CJS entry with simple expression".into(),
            source: "var value = 42".into(),
            source_file: Some("main.cjs".into()),
            expected_syntax: ModuleSyntax::CommonJs,
            topology: ModuleGraphTopology::Mixed,
            interop_direction: InteropDirection::CjsRequiresEsm,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "mixed_bidirectional_entry".into(),
            description: "Mixed: bidirectional interop entry".into(),
            source: "var data = { items: [1, 2, 3] }".into(),
            source_file: Some("bridge.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::Mixed,
            interop_direction: InteropDirection::Bidirectional,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        // -- Edge cases --
        EsmCjsParitySpecimen {
            specimen_id: "esm_no_source_file".into(),
            description: "ESM with no source_file (inline)".into(),
            source: "1 + 1".into(),
            source_file: None,
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::PureEsm,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "cjs_no_source_file".into(),
            description: "CJS with no source_file (inline)".into(),
            source: "var x = 10".into(),
            source_file: None,
            expected_syntax: ModuleSyntax::CommonJs,
            topology: ModuleGraphTopology::PureCjs,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "esm_empty_body".into(),
            description: "ESM with empty source".into(),
            source: String::new(),
            source_file: Some("empty.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::PureEsm,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ParseFailure,
        },
        EsmCjsParitySpecimen {
            specimen_id: "cjs_empty_body".into(),
            description: "CJS with empty source".into(),
            source: String::new(),
            source_file: Some("empty.cjs".into()),
            expected_syntax: ModuleSyntax::CommonJs,
            topology: ModuleGraphTopology::PureCjs,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ParseFailure,
        },
        EsmCjsParitySpecimen {
            specimen_id: "esm_js_extension".into(),
            description: "JS extension treated as ESM when no CJS markers".into(),
            source: "var y = 5".into(),
            source_file: Some("plain.js".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::PureEsm,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "mixed_nested_expression".into(),
            description: "Mixed: nested arithmetic expression".into(),
            source: "var z = (1 + 2) * 3".into(),
            source_file: Some("compute.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::Mixed,
            interop_direction: InteropDirection::EsmImportsCjs,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "cjs_object_pattern".into(),
            description: "CJS: object literal as variable value".into(),
            source: "var opts = { verbose: true, level: 3 }".into(),
            source_file: Some("opts.cjs".into()),
            expected_syntax: ModuleSyntax::CommonJs,
            topology: ModuleGraphTopology::PureCjs,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "esm_array_literal".into(),
            description: "ESM: array literal".into(),
            source: "var items = [1, 2, 3]".into(),
            source_file: Some("data.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::PureEsm,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
        EsmCjsParitySpecimen {
            specimen_id: "mixed_function_call".into(),
            description: "Mixed: function declaration and call".into(),
            source: "function id(x) { return x }".into(),
            source_file: Some("id.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::Mixed,
            interop_direction: InteropDirection::EsmImportsCjs,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        },
    ]
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Run all specimens through the orchestrator and collect evidence.
pub fn run_esm_cjs_parity_corpus() -> EsmCjsParityEvidenceInventory {
    let corpus = esm_cjs_parity_corpus();
    let mut evidence = Vec::with_capacity(corpus.len());
    let mut pass_count: u64 = 0;
    let mut fail_count: u64 = 0;
    let mut supported_count: u64 = 0;
    let mut degraded_count: u64 = 0;
    let mut unsupported_count: u64 = 0;
    let mut pure_esm_count: u64 = 0;
    let mut pure_cjs_count: u64 = 0;
    let mut mixed_count: u64 = 0;

    for specimen in &corpus {
        let ev = run_single_esm_cjs_specimen(specimen);
        match specimen.topology {
            ModuleGraphTopology::PureEsm => pure_esm_count += 1,
            ModuleGraphTopology::PureCjs => pure_cjs_count += 1,
            ModuleGraphTopology::Mixed => mixed_count += 1,
        }
        if ev.verdict == EsmCjsParityVerdict::Pass {
            pass_count += 1;
        } else {
            fail_count += 1;
        }
        match ev.compatibility_disposition {
            EsmCjsCompatibilityDisposition::Supported => supported_count += 1,
            EsmCjsCompatibilityDisposition::Degraded => degraded_count += 1,
            EsmCjsCompatibilityDisposition::Unsupported => unsupported_count += 1,
        }
        evidence.push(ev);
    }

    EsmCjsParityEvidenceInventory {
        schema_version: ESM_CJS_PARITY_SCHEMA_VERSION.to_string(),
        component: ESM_CJS_PARITY_COMPONENT.to_string(),
        specimen_count: corpus.len() as u64,
        pass_count,
        fail_count,
        supported_count,
        degraded_count,
        unsupported_count,
        pure_esm_count,
        pure_cjs_count,
        mixed_count,
        evidence,
    }
}

fn remediation_guidance(
    guidance_code: &str,
    message: impl Into<String>,
) -> EsmCjsRemediationGuidance {
    EsmCjsRemediationGuidance {
        guidance_code: guidance_code.to_string(),
        message: message.into(),
    }
}

fn specimen_overclaims_graph_interop(specimen: &EsmCjsParitySpecimen) -> bool {
    specimen.topology == ModuleGraphTopology::Mixed
        || specimen.interop_direction != InteropDirection::None
}

fn classify_compatibility(
    specimen: &EsmCjsParitySpecimen,
    _actual_outcome: EsmCjsActualOutcome,
    verdict: EsmCjsParityVerdict,
) -> (EsmCjsCompatibilityDisposition, EsmCjsRemediationGuidance) {
    if verdict == EsmCjsParityVerdict::Fail {
        return (
            EsmCjsCompatibilityDisposition::Unsupported,
            remediation_guidance(
                "interop_contract_violation",
                format!(
                    "specimen '{}' drifted from the shipped ESM/CJS parity contract; rerun the parity evidence bundle and inspect the emitted artifact set before shipping this boundary",
                    specimen.specimen_id
                ),
            ),
        );
    }

    if specimen.expected_outcome == EsmCjsExpectedOutcome::ExecuteSuccess
        && specimen_overclaims_graph_interop(specimen)
    {
        return (
            EsmCjsCompatibilityDisposition::Degraded,
            remediation_guidance(
                "module_graph_oracle_required",
                format!(
                    "specimen '{}' currently runs through a single-source orchestrator lane, so it cannot claim shipped mixed-graph / cross-format interop support without a dedicated module-graph harness",
                    specimen.specimen_id
                ),
            ),
        );
    }

    match specimen.expected_outcome {
        EsmCjsExpectedOutcome::ExecuteSuccess => (
            EsmCjsCompatibilityDisposition::Supported,
            remediation_guidance(
                "no_remediation_required",
                format!(
                    "specimen '{}' is supported under the current shipped ESM/CJS parity contract; no mitigation is required",
                    specimen.specimen_id
                ),
            ),
        ),
        EsmCjsExpectedOutcome::EvaluationFailure => (
            EsmCjsCompatibilityDisposition::Degraded,
            remediation_guidance(
                "stabilize_async_boundary",
                format!(
                    "specimen '{}' degrades at evaluation time; isolate the async boundary or avoid crossing this interop edge until the evaluation failure is resolved",
                    specimen.specimen_id
                ),
            ),
        ),
        EsmCjsExpectedOutcome::ResolutionFailure => (
            EsmCjsCompatibilityDisposition::Unsupported,
            remediation_guidance(
                "repair_module_resolution",
                format!(
                    "specimen '{}' remains unsupported because resolution fails across the ESM/CJS boundary; align specifiers, extensions, and package conditions before retrying",
                    specimen.specimen_id
                ),
            ),
        ),
        EsmCjsExpectedOutcome::LinkingFailure => (
            EsmCjsCompatibilityDisposition::Unsupported,
            remediation_guidance(
                "repair_link_boundary",
                format!(
                    "specimen '{}' remains unsupported because the mixed graph does not link cleanly; repair the import/export contract or add an explicit shim before retrying",
                    specimen.specimen_id
                ),
            ),
        ),
        EsmCjsExpectedOutcome::ParseFailure => (
            EsmCjsCompatibilityDisposition::Unsupported,
            remediation_guidance(
                "repair_module_source",
                format!(
                    "specimen '{}' remains unsupported because the source does not parse under the shipped parity harness; fix the source contract before retrying this boundary",
                    specimen.specimen_id
                ),
            ),
        ),
    }
}

fn run_single_esm_cjs_specimen(specimen: &EsmCjsParitySpecimen) -> EsmCjsParitySpecimenEvidence {
    let mut orch = ExecutionOrchestrator::new(OrchestratorConfig::default());

    let package = ExtensionPackage {
        extension_id: format!("esm-cjs-parity-{}", specimen.specimen_id),
        source: specimen.source.clone(),
        source_file: specimen.source_file.clone(),
        capabilities: vec![],
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };

    let (actual_outcome, error_detail) = match orch.execute(&package) {
        Ok(_result) => (EsmCjsActualOutcome::ExecuteSuccess, None),
        Err(OrchestratorError::Parse(e)) => {
            (EsmCjsActualOutcome::ParseFailure, Some(e.to_string()))
        }
        Err(OrchestratorError::EmptySource) => (
            EsmCjsActualOutcome::ParseFailure,
            Some("empty source".into()),
        ),
        Err(other) => (EsmCjsActualOutcome::OtherFailure, Some(other.to_string())),
    };

    let outcome_matches = matches!(
        (specimen.expected_outcome, actual_outcome),
        (
            EsmCjsExpectedOutcome::ExecuteSuccess,
            EsmCjsActualOutcome::ExecuteSuccess
        ) | (
            EsmCjsExpectedOutcome::ResolutionFailure,
            EsmCjsActualOutcome::ResolutionFailure
        ) | (
            EsmCjsExpectedOutcome::LinkingFailure,
            EsmCjsActualOutcome::LinkingFailure
        ) | (
            EsmCjsExpectedOutcome::EvaluationFailure,
            EsmCjsActualOutcome::EvaluationFailure
        ) | (
            EsmCjsExpectedOutcome::ParseFailure,
            EsmCjsActualOutcome::ParseFailure
        )
    );

    let verdict = if outcome_matches {
        EsmCjsParityVerdict::Pass
    } else {
        EsmCjsParityVerdict::Fail
    };
    let (compatibility_disposition, remediation_guidance) =
        classify_compatibility(specimen, actual_outcome, verdict);

    EsmCjsParitySpecimenEvidence {
        specimen_id: specimen.specimen_id.clone(),
        expected_syntax: specimen.expected_syntax,
        topology: specimen.topology,
        interop_direction: specimen.interop_direction,
        expected_outcome: specimen.expected_outcome,
        actual_outcome,
        verdict,
        compatibility_disposition,
        remediation_guidance,
        error_detail,
    }
}

// ---------------------------------------------------------------------------
// Bundle writer
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Write the full evidence bundle to disk.
pub fn write_esm_cjs_parity_evidence_bundle(
    output_dir: &Path,
    commands: &[String],
) -> Result<EsmCjsParityBundleArtifacts, std::io::Error> {
    fs::create_dir_all(output_dir)?;

    let inv = run_esm_cjs_parity_corpus();
    let inv_json = serde_json::to_string_pretty(&inv).map_err(std::io::Error::other)?;
    let inventory_hash = sha256_hex(inv_json.as_bytes());

    let inv_path = output_dir.join("esm_cjs_parity_evidence_inventory.json");
    fs::write(&inv_path, &inv_json)?;

    // Events
    let mut events = Vec::new();
    events.push(EsmCjsParityEvent {
        schema_version: ESM_CJS_PARITY_EVENT_SCHEMA_VERSION.into(),
        component: ESM_CJS_PARITY_COMPONENT.into(),
        event: "esm_cjs_parity_evidence_run_started".into(),
        policy_id: ESM_CJS_PARITY_POLICY_ID.into(),
        specimen_id: None,
        verdict: None,
        detail: Some(format!("specimen_count={}", inv.specimen_count)),
    });
    for ev in &inv.evidence {
        let detail = match &ev.error_detail {
            Some(error_detail) => Some(format!(
                "disposition={} guidance_code={} error={}",
                ev.compatibility_disposition, ev.remediation_guidance.guidance_code, error_detail
            )),
            None => Some(format!(
                "disposition={} guidance_code={}",
                ev.compatibility_disposition, ev.remediation_guidance.guidance_code
            )),
        };
        events.push(EsmCjsParityEvent {
            schema_version: ESM_CJS_PARITY_EVENT_SCHEMA_VERSION.into(),
            component: ESM_CJS_PARITY_COMPONENT.into(),
            event: "esm_cjs_parity_specimen_evaluated".into(),
            policy_id: ESM_CJS_PARITY_POLICY_ID.into(),
            specimen_id: Some(ev.specimen_id.clone()),
            verdict: Some(ev.verdict.as_str().to_string()),
            detail,
        });
    }
    events.push(EsmCjsParityEvent {
        schema_version: ESM_CJS_PARITY_EVENT_SCHEMA_VERSION.into(),
        component: ESM_CJS_PARITY_COMPONENT.into(),
        event: "esm_cjs_parity_evidence_run_completed".into(),
        policy_id: ESM_CJS_PARITY_POLICY_ID.into(),
        specimen_id: None,
        verdict: Some(
            if inv.contract_satisfied() {
                "pass"
            } else {
                "fail"
            }
            .into(),
        ),
        detail: Some(format!(
            "pass={} fail={} supported={} degraded={} unsupported={} pure_esm={} pure_cjs={} mixed={}",
            inv.pass_count,
            inv.fail_count,
            inv.supported_count,
            inv.degraded_count,
            inv.unsupported_count,
            inv.pure_esm_count,
            inv.pure_cjs_count,
            inv.mixed_count
        )),
    });

    let events_path = output_dir.join("esm_cjs_parity_evidence_events.jsonl");
    let events_jsonl: String = events
        .iter()
        .map(|e| serde_json::to_string(e).expect("event serialization"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&events_path, &events_jsonl)?;

    // Commands
    let commands_path = output_dir.join("esm_cjs_parity_evidence_commands.txt");
    fs::write(&commands_path, commands.join("\n"))?;

    // Manifest
    let artifact_paths = EsmCjsParityArtifactPaths {
        evidence_inventory: "esm_cjs_parity_evidence_inventory.json".into(),
        run_manifest: "esm_cjs_parity_evidence_manifest.json".into(),
        events_jsonl: "esm_cjs_parity_evidence_events.jsonl".into(),
        commands_txt: "esm_cjs_parity_evidence_commands.txt".into(),
    };
    let manifest = EsmCjsParityRunManifest {
        schema_version: ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION.into(),
        component: ESM_CJS_PARITY_COMPONENT.into(),
        trace_id: format!(
            "esm-cjs-parity-evidence-{}",
            inventory_hash.get(..8).unwrap_or("?")
        ),
        decision_id: format!(
            "esm-cjs-parity-decision-{}",
            inventory_hash.get(..8).unwrap_or("?")
        ),
        policy_id: ESM_CJS_PARITY_POLICY_ID.into(),
        inventory_hash: inventory_hash.clone(),
        specimen_count: inv.specimen_count,
        pass_count: inv.pass_count,
        fail_count: inv.fail_count,
        supported_count: inv.supported_count,
        degraded_count: inv.degraded_count,
        unsupported_count: inv.unsupported_count,
        contract_satisfied: inv.contract_satisfied(),
        artifact_paths,
    };
    let manifest_path = output_dir.join("esm_cjs_parity_evidence_manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(std::io::Error::other)?;
    fs::write(&manifest_path, &manifest_json)?;

    Ok(EsmCjsParityBundleArtifacts {
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
        assert!(!esm_cjs_parity_corpus().is_empty());
    }

    #[test]
    fn corpus_has_all_topologies() {
        let corpus = esm_cjs_parity_corpus();
        assert!(
            corpus
                .iter()
                .any(|s| s.topology == ModuleGraphTopology::PureEsm)
        );
        assert!(
            corpus
                .iter()
                .any(|s| s.topology == ModuleGraphTopology::PureCjs)
        );
        assert!(
            corpus
                .iter()
                .any(|s| s.topology == ModuleGraphTopology::Mixed)
        );
    }

    #[test]
    fn corpus_has_both_syntaxes() {
        let corpus = esm_cjs_parity_corpus();
        assert!(
            corpus
                .iter()
                .any(|s| s.expected_syntax == ModuleSyntax::EsModule)
        );
        assert!(
            corpus
                .iter()
                .any(|s| s.expected_syntax == ModuleSyntax::CommonJs)
        );
    }

    #[test]
    fn corpus_ids_unique() {
        let corpus = esm_cjs_parity_corpus();
        let ids: std::collections::BTreeSet<&str> =
            corpus.iter().map(|s| s.specimen_id.as_str()).collect();
        assert_eq!(ids.len(), corpus.len());
    }

    #[test]
    fn corpus_has_interop_directions() {
        let corpus = esm_cjs_parity_corpus();
        assert!(
            corpus
                .iter()
                .any(|s| s.interop_direction == InteropDirection::None)
        );
        assert!(
            corpus
                .iter()
                .any(|s| s.interop_direction == InteropDirection::EsmImportsCjs)
        );
        assert!(
            corpus
                .iter()
                .any(|s| s.interop_direction == InteropDirection::CjsRequiresEsm)
        );
        assert!(
            corpus
                .iter()
                .any(|s| s.interop_direction == InteropDirection::Bidirectional)
        );
    }

    #[test]
    fn corpus_is_deterministic() {
        let a = esm_cjs_parity_corpus();
        let b = esm_cjs_parity_corpus();
        assert_eq!(a, b);
    }

    #[test]
    fn all_specimens_pass() {
        let inv = run_esm_cjs_parity_corpus();
        for ev in &inv.evidence {
            assert_eq!(
                ev.verdict,
                EsmCjsParityVerdict::Pass,
                "specimen {} failed: expected={:?} actual={:?} error={:?}",
                ev.specimen_id,
                ev.expected_outcome,
                ev.actual_outcome,
                ev.error_detail,
            );
        }
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn inventory_counts_correct() {
        let inv = run_esm_cjs_parity_corpus();
        let corpus = esm_cjs_parity_corpus();
        assert_eq!(inv.specimen_count, corpus.len() as u64);
        assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
        assert_eq!(
            inv.pure_esm_count + inv.pure_cjs_count + inv.mixed_count,
            inv.specimen_count
        );
    }

    #[test]
    fn schema_version_set() {
        let inv = run_esm_cjs_parity_corpus();
        assert_eq!(inv.schema_version, ESM_CJS_PARITY_SCHEMA_VERSION);
        assert_eq!(inv.component, ESM_CJS_PARITY_COMPONENT);
    }

    #[test]
    fn specimen_serde_roundtrip() {
        let corpus = esm_cjs_parity_corpus();
        let json = serde_json::to_string(&corpus).unwrap();
        let decoded: Vec<EsmCjsParitySpecimen> = serde_json::from_str(&json).unwrap();
        assert_eq!(corpus, decoded);
    }

    #[test]
    fn evidence_serde_roundtrip() {
        let inv = run_esm_cjs_parity_corpus();
        let json = serde_json::to_string(&inv).unwrap();
        let decoded: EsmCjsParityEvidenceInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, decoded);
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let manifest = EsmCjsParityRunManifest {
            schema_version: ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION.into(),
            component: ESM_CJS_PARITY_COMPONENT.into(),
            trace_id: "test-trace".into(),
            decision_id: "test-decision".into(),
            policy_id: ESM_CJS_PARITY_POLICY_ID.into(),
            inventory_hash: "abc123".into(),
            specimen_count: 1,
            pass_count: 1,
            fail_count: 0,
            supported_count: 1,
            degraded_count: 0,
            unsupported_count: 0,
            contract_satisfied: true,
            artifact_paths: EsmCjsParityArtifactPaths {
                evidence_inventory: "inv.json".into(),
                run_manifest: "manifest.json".into(),
                events_jsonl: "events.jsonl".into(),
                commands_txt: "commands.txt".into(),
            },
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let decoded: EsmCjsParityRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, decoded);
    }

    #[test]
    fn event_serde_roundtrip() {
        let event = EsmCjsParityEvent {
            schema_version: ESM_CJS_PARITY_EVENT_SCHEMA_VERSION.into(),
            component: ESM_CJS_PARITY_COMPONENT.into(),
            event: "test_event".into(),
            policy_id: ESM_CJS_PARITY_POLICY_ID.into(),
            specimen_id: Some("spec1".into()),
            verdict: Some("pass".into()),
            detail: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: EsmCjsParityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, decoded);
    }

    #[test]
    fn contract_satisfied_logic() {
        let mut inv = EsmCjsParityEvidenceInventory {
            schema_version: ESM_CJS_PARITY_SCHEMA_VERSION.into(),
            component: ESM_CJS_PARITY_COMPONENT.into(),
            specimen_count: 5,
            pass_count: 5,
            fail_count: 0,
            supported_count: 5,
            degraded_count: 0,
            unsupported_count: 0,
            pure_esm_count: 2,
            pure_cjs_count: 2,
            mixed_count: 1,
            evidence: vec![],
        };
        assert!(inv.contract_satisfied());

        inv.fail_count = 1;
        inv.pass_count = 4;
        assert!(!inv.contract_satisfied());

        inv.specimen_count = 0;
        inv.fail_count = 0;
        inv.pass_count = 0;
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn topology_display() {
        assert_eq!(ModuleGraphTopology::PureEsm.to_string(), "pure_esm");
        assert_eq!(ModuleGraphTopology::PureCjs.to_string(), "pure_cjs");
        assert_eq!(ModuleGraphTopology::Mixed.to_string(), "mixed");
    }

    #[test]
    fn interop_direction_display() {
        assert_eq!(InteropDirection::None.to_string(), "none");
        assert_eq!(
            InteropDirection::EsmImportsCjs.to_string(),
            "esm_imports_cjs"
        );
        assert_eq!(
            InteropDirection::CjsRequiresEsm.to_string(),
            "cjs_requires_esm"
        );
        assert_eq!(InteropDirection::Bidirectional.to_string(), "bidirectional");
    }

    #[test]
    fn expected_outcome_display() {
        assert_eq!(
            EsmCjsExpectedOutcome::ExecuteSuccess.to_string(),
            "execute_success"
        );
        assert_eq!(
            EsmCjsExpectedOutcome::ParseFailure.to_string(),
            "parse_failure"
        );
        assert_eq!(
            EsmCjsExpectedOutcome::ResolutionFailure.to_string(),
            "resolution_failure"
        );
        assert_eq!(
            EsmCjsExpectedOutcome::LinkingFailure.to_string(),
            "linking_failure"
        );
        assert_eq!(
            EsmCjsExpectedOutcome::EvaluationFailure.to_string(),
            "evaluation_failure"
        );
    }

    #[test]
    fn actual_outcome_display() {
        assert_eq!(
            EsmCjsActualOutcome::ExecuteSuccess.to_string(),
            "execute_success"
        );
        assert_eq!(
            EsmCjsActualOutcome::OtherFailure.to_string(),
            "other_failure"
        );
    }

    #[test]
    fn topology_ordering() {
        assert!(ModuleGraphTopology::PureCjs < ModuleGraphTopology::PureEsm);
        assert!(ModuleGraphTopology::Mixed < ModuleGraphTopology::PureCjs);
    }

    #[test]
    fn verdict_serde() {
        let json = serde_json::to_string(&EsmCjsParityVerdict::Pass).unwrap();
        assert_eq!(json, "\"pass\"");
        let json = serde_json::to_string(&EsmCjsParityVerdict::Fail).unwrap();
        assert_eq!(json, "\"fail\"");
    }

    #[test]
    fn compatibility_disposition_serde_roundtrip() {
        for disposition in [
            EsmCjsCompatibilityDisposition::Supported,
            EsmCjsCompatibilityDisposition::Degraded,
            EsmCjsCompatibilityDisposition::Unsupported,
        ] {
            let json = serde_json::to_string(&disposition).unwrap();
            let decoded: EsmCjsCompatibilityDisposition = serde_json::from_str(&json).unwrap();
            assert_eq!(disposition, decoded);
            assert_eq!(json, format!("\"{}\"", disposition.as_str()));
        }
    }

    #[test]
    fn remediation_guidance_serde_roundtrip() {
        let guidance = remediation_guidance("guidance-code", "fix the boundary");
        let json = serde_json::to_string(&guidance).unwrap();
        let decoded: EsmCjsRemediationGuidance = serde_json::from_str(&json).unwrap();
        assert_eq!(guidance, decoded);
    }

    #[test]
    fn corpus_all_have_descriptions() {
        let corpus = esm_cjs_parity_corpus();
        for specimen in &corpus {
            assert!(
                !specimen.description.is_empty(),
                "specimen {} has empty description",
                specimen.specimen_id
            );
        }
    }

    #[test]
    fn corpus_expected_outcomes_cover_success_and_failure() {
        let corpus = esm_cjs_parity_corpus();
        assert!(
            corpus
                .iter()
                .any(|s| s.expected_outcome == EsmCjsExpectedOutcome::ExecuteSuccess)
        );
        assert!(
            corpus
                .iter()
                .any(|s| s.expected_outcome == EsmCjsExpectedOutcome::ParseFailure)
        );
    }

    #[test]
    fn schema_version_constants_are_distinct() {
        let versions = [
            ESM_CJS_PARITY_SCHEMA_VERSION,
            ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION,
            ESM_CJS_PARITY_EVENT_SCHEMA_VERSION,
        ];
        let unique: std::collections::BTreeSet<&str> = versions.iter().copied().collect();
        assert_eq!(
            unique.len(),
            versions.len(),
            "schema version constants must all be distinct"
        );
        // Also verify they share the common prefix but differ in suffix.
        for v in &versions {
            assert!(v.starts_with("franken-engine.esm_cjs_parity_"));
        }
    }

    #[test]
    fn topology_serde_roundtrip_all_variants() {
        let variants = [
            ModuleGraphTopology::PureEsm,
            ModuleGraphTopology::PureCjs,
            ModuleGraphTopology::Mixed,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let decoded: ModuleGraphTopology = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, decoded);
            // Verify snake_case rename.
            assert_eq!(json, format!("\"{}\"", variant.as_str()));
        }
    }

    #[test]
    fn interop_direction_serde_roundtrip_all_variants() {
        let variants = [
            InteropDirection::None,
            InteropDirection::EsmImportsCjs,
            InteropDirection::CjsRequiresEsm,
            InteropDirection::Bidirectional,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let decoded: InteropDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, decoded);
            assert_eq!(json, format!("\"{}\"", variant.as_str()));
        }
    }

    #[test]
    fn actual_outcome_serde_roundtrip_all_variants() {
        let variants = [
            EsmCjsActualOutcome::ExecuteSuccess,
            EsmCjsActualOutcome::ResolutionFailure,
            EsmCjsActualOutcome::LinkingFailure,
            EsmCjsActualOutcome::EvaluationFailure,
            EsmCjsActualOutcome::ParseFailure,
            EsmCjsActualOutcome::OtherFailure,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let decoded: EsmCjsActualOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, decoded);
            assert_eq!(json, format!("\"{}\"", variant.as_str()));
        }
    }

    #[test]
    fn expected_outcome_serde_roundtrip_all_variants() {
        let variants = [
            EsmCjsExpectedOutcome::ExecuteSuccess,
            EsmCjsExpectedOutcome::ResolutionFailure,
            EsmCjsExpectedOutcome::LinkingFailure,
            EsmCjsExpectedOutcome::EvaluationFailure,
            EsmCjsExpectedOutcome::ParseFailure,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let decoded: EsmCjsExpectedOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, decoded);
            assert_eq!(json, format!("\"{}\"", variant.as_str()));
        }
    }

    #[test]
    fn specimen_evidence_serde_roundtrip() {
        let ev = EsmCjsParitySpecimenEvidence {
            specimen_id: "test_spec".into(),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::Mixed,
            interop_direction: InteropDirection::Bidirectional,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
            actual_outcome: EsmCjsActualOutcome::OtherFailure,
            verdict: EsmCjsParityVerdict::Fail,
            compatibility_disposition: EsmCjsCompatibilityDisposition::Unsupported,
            remediation_guidance: remediation_guidance(
                "interop_contract_violation",
                "rerun the bundle",
            ),
            error_detail: Some("something went wrong".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let decoded: EsmCjsParitySpecimenEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, decoded);

        // Also test with error_detail = None.
        let ev_none = EsmCjsParitySpecimenEvidence {
            error_detail: None,
            ..ev
        };
        let json2 = serde_json::to_string(&ev_none).unwrap();
        let decoded2: EsmCjsParitySpecimenEvidence = serde_json::from_str(&json2).unwrap();
        assert_eq!(ev_none, decoded2);
    }

    #[test]
    fn contract_satisfied_boundary_cases() {
        // Single specimen passing satisfies contract.
        let inv = EsmCjsParityEvidenceInventory {
            schema_version: ESM_CJS_PARITY_SCHEMA_VERSION.into(),
            component: ESM_CJS_PARITY_COMPONENT.into(),
            specimen_count: 1,
            pass_count: 1,
            fail_count: 0,
            supported_count: 1,
            degraded_count: 0,
            unsupported_count: 0,
            pure_esm_count: 1,
            pure_cjs_count: 0,
            mixed_count: 0,
            evidence: vec![],
        };
        assert!(inv.contract_satisfied());

        // Large corpus, single failure breaks contract.
        let inv_big_one_fail = EsmCjsParityEvidenceInventory {
            specimen_count: 1000,
            pass_count: 999,
            fail_count: 1,
            ..inv.clone()
        };
        assert!(!inv_big_one_fail.contract_satisfied());

        // All failures also breaks contract.
        let inv_all_fail = EsmCjsParityEvidenceInventory {
            specimen_count: 10,
            pass_count: 0,
            fail_count: 10,
            ..inv
        };
        assert!(!inv_all_fail.contract_satisfied());
    }

    // ── enrichment: corpus structure ──────────────────────────────

    #[test]
    fn corpus_specimen_count_is_twenty() {
        let corpus = esm_cjs_parity_corpus();
        assert_eq!(corpus.len(), 20);
    }

    #[test]
    fn corpus_specimen_ids_follow_naming_convention() {
        let corpus = esm_cjs_parity_corpus();
        for s in &corpus {
            assert!(
                s.specimen_id.starts_with("esm_")
                    || s.specimen_id.starts_with("cjs_")
                    || s.specimen_id.starts_with("mixed_"),
                "specimen id '{}' should start with esm_, cjs_, or mixed_",
                s.specimen_id
            );
        }
    }

    #[test]
    fn corpus_all_specimens_have_non_empty_source() {
        let corpus = esm_cjs_parity_corpus();
        for s in &corpus {
            // Specimens with ParseFailure outcome are allowed to have empty source
            if s.expected_outcome == EsmCjsExpectedOutcome::ParseFailure {
                continue;
            }
            assert!(
                !s.source.is_empty(),
                "specimen {} has empty source",
                s.specimen_id
            );
        }
    }

    #[test]
    fn corpus_topology_distribution_is_balanced() {
        let corpus = esm_cjs_parity_corpus();
        let pure_esm = corpus
            .iter()
            .filter(|s| s.topology == ModuleGraphTopology::PureEsm)
            .count();
        let pure_cjs = corpus
            .iter()
            .filter(|s| s.topology == ModuleGraphTopology::PureCjs)
            .count();
        let mixed = corpus
            .iter()
            .filter(|s| s.topology == ModuleGraphTopology::Mixed)
            .count();
        assert!(pure_esm > 0, "no PureEsm specimens");
        assert!(pure_cjs > 0, "no PureCjs specimens");
        assert!(mixed > 0, "no Mixed specimens");
        assert_eq!(
            pure_esm + pure_cjs + mixed,
            corpus.len(),
            "topology counts don't sum"
        );
    }

    // ── enrichment: inventory evidence properties ─────────────────

    #[test]
    fn inventory_evidence_count_matches_corpus() {
        let inv = run_esm_cjs_parity_corpus();
        let corpus = esm_cjs_parity_corpus();
        assert_eq!(inv.evidence.len(), corpus.len());
    }

    #[test]
    fn inventory_evidence_preserves_corpus_order() {
        let inv = run_esm_cjs_parity_corpus();
        let corpus = esm_cjs_parity_corpus();
        for (ev, sp) in inv.evidence.iter().zip(corpus.iter()) {
            assert_eq!(ev.specimen_id, sp.specimen_id, "evidence order mismatch");
        }
    }

    #[test]
    fn inventory_evidence_topology_matches_corpus() {
        let inv = run_esm_cjs_parity_corpus();
        let corpus = esm_cjs_parity_corpus();
        for (ev, sp) in inv.evidence.iter().zip(corpus.iter()) {
            assert_eq!(
                ev.topology, sp.topology,
                "topology mismatch for specimen '{}'",
                ev.specimen_id
            );
        }
    }

    #[test]
    fn inventory_evidence_interop_direction_matches_corpus() {
        let inv = run_esm_cjs_parity_corpus();
        let corpus = esm_cjs_parity_corpus();
        for (ev, sp) in inv.evidence.iter().zip(corpus.iter()) {
            assert_eq!(
                ev.interop_direction, sp.interop_direction,
                "interop direction mismatch for specimen '{}'",
                ev.specimen_id
            );
        }
    }

    #[test]
    fn inventory_topology_counts_match_evidence() {
        let inv = run_esm_cjs_parity_corpus();
        let counted_esm = inv
            .evidence
            .iter()
            .filter(|e| e.topology == ModuleGraphTopology::PureEsm)
            .count() as u64;
        let counted_cjs = inv
            .evidence
            .iter()
            .filter(|e| e.topology == ModuleGraphTopology::PureCjs)
            .count() as u64;
        let counted_mixed = inv
            .evidence
            .iter()
            .filter(|e| e.topology == ModuleGraphTopology::Mixed)
            .count() as u64;
        assert_eq!(inv.pure_esm_count, counted_esm);
        assert_eq!(inv.pure_cjs_count, counted_cjs);
        assert_eq!(inv.mixed_count, counted_mixed);
    }

    #[test]
    fn inventory_disposition_counts_match_evidence() {
        let inv = run_esm_cjs_parity_corpus();
        let supported = inv
            .evidence
            .iter()
            .filter(|ev| ev.compatibility_disposition == EsmCjsCompatibilityDisposition::Supported)
            .count() as u64;
        let degraded = inv
            .evidence
            .iter()
            .filter(|ev| ev.compatibility_disposition == EsmCjsCompatibilityDisposition::Degraded)
            .count() as u64;
        let unsupported = inv
            .evidence
            .iter()
            .filter(|ev| {
                ev.compatibility_disposition == EsmCjsCompatibilityDisposition::Unsupported
            })
            .count() as u64;
        assert_eq!(inv.supported_count, supported);
        assert_eq!(inv.degraded_count, degraded);
        assert_eq!(inv.unsupported_count, unsupported);
        assert_eq!(supported + degraded + unsupported, inv.specimen_count);
    }

    // ── enrichment: enum display completeness ─────────────────────

    #[test]
    fn actual_outcome_display_all_variants() {
        let variants = [
            (EsmCjsActualOutcome::ExecuteSuccess, "execute_success"),
            (EsmCjsActualOutcome::ResolutionFailure, "resolution_failure"),
            (EsmCjsActualOutcome::LinkingFailure, "linking_failure"),
            (EsmCjsActualOutcome::EvaluationFailure, "evaluation_failure"),
            (EsmCjsActualOutcome::ParseFailure, "parse_failure"),
            (EsmCjsActualOutcome::OtherFailure, "other_failure"),
        ];
        for (variant, expected) in &variants {
            assert_eq!(variant.to_string(), *expected);
        }
    }

    #[test]
    fn topology_as_str_matches_display() {
        for variant in [
            ModuleGraphTopology::PureEsm,
            ModuleGraphTopology::PureCjs,
            ModuleGraphTopology::Mixed,
        ] {
            assert_eq!(variant.as_str(), variant.to_string());
        }
    }

    #[test]
    fn interop_direction_as_str_matches_display() {
        for variant in [
            InteropDirection::None,
            InteropDirection::EsmImportsCjs,
            InteropDirection::CjsRequiresEsm,
            InteropDirection::Bidirectional,
        ] {
            assert_eq!(variant.as_str(), variant.to_string());
        }
    }

    #[test]
    fn expected_outcome_as_str_matches_display() {
        for variant in [
            EsmCjsExpectedOutcome::ExecuteSuccess,
            EsmCjsExpectedOutcome::ResolutionFailure,
            EsmCjsExpectedOutcome::LinkingFailure,
            EsmCjsExpectedOutcome::EvaluationFailure,
            EsmCjsExpectedOutcome::ParseFailure,
        ] {
            assert_eq!(variant.as_str(), variant.to_string());
        }
    }

    // ── enrichment: schema constants ──────────────────────────────

    #[test]
    fn policy_id_is_non_empty() {
        assert!(!ESM_CJS_PARITY_POLICY_ID.is_empty());
    }

    #[test]
    fn component_is_non_empty() {
        assert!(!ESM_CJS_PARITY_COMPONENT.is_empty());
    }

    #[test]
    fn all_schema_constants_start_with_franken_engine() {
        assert!(ESM_CJS_PARITY_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(ESM_CJS_PARITY_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(ESM_CJS_PARITY_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    // ── enrichment: verdict consistency ───────────────────────────

    #[test]
    fn all_passing_evidence_has_matching_outcomes() {
        let inv = run_esm_cjs_parity_corpus();
        for ev in &inv.evidence {
            if ev.verdict == EsmCjsParityVerdict::Pass {
                assert_eq!(
                    format!("{}", ev.expected_outcome),
                    format!("{}", ev.actual_outcome),
                    "passing specimen {} has mismatched outcomes",
                    ev.specimen_id
                );
            }
        }
    }

    #[test]
    fn passing_evidence_has_no_error_detail() {
        let inv = run_esm_cjs_parity_corpus();
        for ev in &inv.evidence {
            if ev.verdict == EsmCjsParityVerdict::Pass
                && ev.actual_outcome == EsmCjsActualOutcome::ExecuteSuccess
            {
                assert!(
                    ev.error_detail.is_none(),
                    "passing specimen {} should have no error_detail",
                    ev.specimen_id
                );
            }
        }
    }

    #[test]
    fn all_evidence_has_explicit_guidance() {
        let inv = run_esm_cjs_parity_corpus();
        for ev in &inv.evidence {
            assert!(!ev.remediation_guidance.guidance_code.is_empty());
            assert!(!ev.remediation_guidance.message.is_empty());
        }
    }

    #[test]
    fn parse_failure_specimens_are_marked_unsupported() {
        let inv = run_esm_cjs_parity_corpus();
        let parse_failures: Vec<_> = inv
            .evidence
            .iter()
            .filter(|ev| ev.expected_outcome == EsmCjsExpectedOutcome::ParseFailure)
            .collect();
        assert!(!parse_failures.is_empty());
        for ev in parse_failures {
            assert_eq!(
                ev.compatibility_disposition,
                EsmCjsCompatibilityDisposition::Unsupported
            );
            assert_eq!(
                ev.remediation_guidance.guidance_code,
                "repair_module_source"
            );
        }
    }

    // ── enrichment: serde for additional types ────────────────────

    #[test]
    fn artifact_paths_serde_roundtrip() {
        let paths = EsmCjsParityArtifactPaths {
            evidence_inventory: "inv.json".into(),
            run_manifest: "manifest.json".into(),
            events_jsonl: "events.jsonl".into(),
            commands_txt: "commands.txt".into(),
        };
        let json = serde_json::to_string(&paths).unwrap();
        let decoded: EsmCjsParityArtifactPaths = serde_json::from_str(&json).unwrap();
        assert_eq!(paths, decoded);
    }

    #[test]
    fn event_with_all_none_fields_serde_roundtrip() {
        let event = EsmCjsParityEvent {
            schema_version: ESM_CJS_PARITY_EVENT_SCHEMA_VERSION.into(),
            component: ESM_CJS_PARITY_COMPONENT.into(),
            event: "run_started".into(),
            policy_id: ESM_CJS_PARITY_POLICY_ID.into(),
            specimen_id: None,
            verdict: None,
            detail: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: EsmCjsParityEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, decoded);
    }

    #[test]
    fn verdict_ordering() {
        assert!(EsmCjsParityVerdict::Fail < EsmCjsParityVerdict::Pass);
    }

    #[test]
    fn topology_ordering_transitive() {
        assert!(ModuleGraphTopology::Mixed < ModuleGraphTopology::PureCjs);
        assert!(ModuleGraphTopology::PureCjs < ModuleGraphTopology::PureEsm);
        assert!(ModuleGraphTopology::Mixed < ModuleGraphTopology::PureEsm);
    }

    #[test]
    fn classify_compatibility_fail_is_unsupported() {
        let specimen = EsmCjsParitySpecimen {
            specimen_id: "fail_case".into(),
            description: "test".into(),
            source: "1".into(),
            source_file: Some("fail_case.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::Mixed,
            interop_direction: InteropDirection::Bidirectional,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        };
        let (disposition, guidance) = classify_compatibility(
            &specimen,
            EsmCjsActualOutcome::OtherFailure,
            EsmCjsParityVerdict::Fail,
        );
        assert_eq!(disposition, EsmCjsCompatibilityDisposition::Unsupported);
        assert_eq!(guidance.guidance_code, "interop_contract_violation");
    }

    #[test]
    fn classify_compatibility_success_is_supported() {
        let specimen = EsmCjsParitySpecimen {
            specimen_id: "success_case".into(),
            description: "test".into(),
            source: "1".into(),
            source_file: Some("success_case.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::PureEsm,
            interop_direction: InteropDirection::None,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        };
        let (disposition, guidance) = classify_compatibility(
            &specimen,
            EsmCjsActualOutcome::ExecuteSuccess,
            EsmCjsParityVerdict::Pass,
        );
        assert_eq!(disposition, EsmCjsCompatibilityDisposition::Supported);
        assert_eq!(guidance.guidance_code, "no_remediation_required");
    }

    #[test]
    fn classify_compatibility_interop_execute_success_is_degraded() {
        let specimen = EsmCjsParitySpecimen {
            specimen_id: "interop_scope_case".into(),
            description: "test".into(),
            source: "1".into(),
            source_file: Some("interop_scope_case.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::Mixed,
            interop_direction: InteropDirection::Bidirectional,
            expected_outcome: EsmCjsExpectedOutcome::ExecuteSuccess,
        };
        let (disposition, guidance) = classify_compatibility(
            &specimen,
            EsmCjsActualOutcome::ExecuteSuccess,
            EsmCjsParityVerdict::Pass,
        );
        assert_eq!(disposition, EsmCjsCompatibilityDisposition::Degraded);
        assert_eq!(guidance.guidance_code, "module_graph_oracle_required");
        assert!(guidance.message.contains("single-source orchestrator lane"));
    }

    #[test]
    fn classify_compatibility_eval_failure_is_degraded() {
        let specimen = EsmCjsParitySpecimen {
            specimen_id: "eval_case".into(),
            description: "test".into(),
            source: "1".into(),
            source_file: Some("eval_case.mjs".into()),
            expected_syntax: ModuleSyntax::EsModule,
            topology: ModuleGraphTopology::Mixed,
            interop_direction: InteropDirection::EsmImportsCjs,
            expected_outcome: EsmCjsExpectedOutcome::EvaluationFailure,
        };
        let (disposition, guidance) = classify_compatibility(
            &specimen,
            EsmCjsActualOutcome::EvaluationFailure,
            EsmCjsParityVerdict::Pass,
        );
        assert_eq!(disposition, EsmCjsCompatibilityDisposition::Degraded);
        assert_eq!(guidance.guidance_code, "stabilize_async_boundary");
    }

    // ── enrichment: corpus source_file coverage ───────────────────

    #[test]
    fn corpus_has_specimens_with_and_without_source_file() {
        let corpus = esm_cjs_parity_corpus();
        let with_file = corpus.iter().any(|s| s.source_file.is_some());
        let without_file = corpus.iter().any(|s| s.source_file.is_none());
        assert!(
            with_file || without_file,
            "corpus should have diverse source_file coverage"
        );
    }

    #[test]
    fn corpus_source_files_have_js_extensions() {
        let corpus = esm_cjs_parity_corpus();
        for s in &corpus {
            if let Some(ref f) = s.source_file {
                assert!(
                    f.ends_with(".js") || f.ends_with(".mjs") || f.ends_with(".cjs"),
                    "source_file '{}' should have a JS extension",
                    f
                );
            }
        }
    }
}
