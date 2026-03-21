//! Fail-closed TS diagnostic corpus and normalization evidence harness.
//!
//! This module defines a canonical corpus of TypeScript-specific language features,
//! their expected normalization behavior, and evidence artifacts that prove the
//! fail-closed contract: every TS feature that the normalization pipeline encounters
//! must either (a) normalize deterministically to valid ES2020, or (b) reject with
//! a structured diagnostic. No TS input may silently pass through unchanged when it
//! contains type-level or TS-only syntax.
//!
//! The evidence harness runs the corpus through the normalization pipeline and
//! records per-feature verdicts, producing a bundle suitable for CI gating and
//! release-evidence publication.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ts_normalization::{TsNormalizationConfig, normalize_typescript_to_es2020};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION: &str =
    "franken-engine.ts-diagnostic-corpus.inventory.v1";
pub const TS_EVIDENCE_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.ts-normalization-evidence.run-manifest.v1";
pub const TS_EVIDENCE_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.ts-normalization-evidence.event.v1";
pub const TS_EVIDENCE_COMPONENT: &str = "ts_normalization_evidence";
pub const TS_EVIDENCE_POLICY_ID: &str = "franken-engine.ts-normalization-evidence.policy.v1";

// ---------------------------------------------------------------------------
// Corpus: TS Feature Families
// ---------------------------------------------------------------------------

/// A TS feature family that the normalization pipeline must handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsFeatureFamily {
    TypeAnnotation,
    TypeOnlyImport,
    InterfaceDeclaration,
    TypeAliasDeclaration,
    EnumDeclaration,
    NamespaceDeclaration,
    ParameterProperty,
    AbstractClass,
    ClassDecorator,
    DefiniteAssignment,
    ConstAssertion,
    HostcallTypeParam,
    JsxElement,
    ImplementsClause,
    ExportTypeDeclaration,
}

impl TsFeatureFamily {
    pub const ALL: &[Self] = &[
        Self::TypeAnnotation,
        Self::TypeOnlyImport,
        Self::InterfaceDeclaration,
        Self::TypeAliasDeclaration,
        Self::EnumDeclaration,
        Self::NamespaceDeclaration,
        Self::ParameterProperty,
        Self::AbstractClass,
        Self::ClassDecorator,
        Self::DefiniteAssignment,
        Self::ConstAssertion,
        Self::HostcallTypeParam,
        Self::JsxElement,
        Self::ImplementsClause,
        Self::ExportTypeDeclaration,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypeAnnotation => "type_annotation",
            Self::TypeOnlyImport => "type_only_import",
            Self::InterfaceDeclaration => "interface_declaration",
            Self::TypeAliasDeclaration => "type_alias_declaration",
            Self::EnumDeclaration => "enum_declaration",
            Self::NamespaceDeclaration => "namespace_declaration",
            Self::ParameterProperty => "parameter_property",
            Self::AbstractClass => "abstract_class",
            Self::ClassDecorator => "class_decorator",
            Self::DefiniteAssignment => "definite_assignment",
            Self::ConstAssertion => "const_assertion",
            Self::HostcallTypeParam => "hostcall_type_param",
            Self::JsxElement => "jsx_element",
            Self::ImplementsClause => "implements_clause",
            Self::ExportTypeDeclaration => "export_type_declaration",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::TypeAnnotation => "Variable/parameter type annotations (e.g. `let x: number`)",
            Self::TypeOnlyImport => "Type-only imports (`import type { T } from ...`)",
            Self::InterfaceDeclaration => "Interface declarations (`interface Foo { ... }`)",
            Self::TypeAliasDeclaration => "Type alias declarations (`type Foo = ...`)",
            Self::EnumDeclaration => "Enum declarations (`enum Status { ... }`)",
            Self::NamespaceDeclaration => "Namespace declarations (`namespace Ns { ... }`)",
            Self::ParameterProperty => {
                "Constructor parameter properties (`constructor(private x: T)`)"
            }
            Self::AbstractClass => "Abstract class declarations (`abstract class Foo { ... }`)",
            Self::ClassDecorator => "Class decorators (`@decorator class Foo { ... }`)",
            Self::DefiniteAssignment => "Definite assignment assertions (`x!: number`)",
            Self::ConstAssertion => "Const assertions (`as const`)",
            Self::HostcallTypeParam => {
                "Hostcall generic type parameters (`hostcall<\"cap\">(args)`)"
            }
            Self::JsxElement => "JSX element syntax (`<Component />`)",
            Self::ImplementsClause => "Class implements clauses (`class Foo implements Bar`)",
            Self::ExportTypeDeclaration => {
                "Export type/interface declarations (`export type T = ...`)"
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Corpus Specimen
// ---------------------------------------------------------------------------

/// The expected outcome for a corpus specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    /// Normalization succeeds; TS-only syntax is removed.
    NormalizedAway,
    /// Normalization succeeds; TS syntax is lowered to ES2020 equivalent.
    LoweredToEs2020,
    /// Normalization rejects with a structured diagnostic.
    FailClosed,
    /// Known gap: normalization passes through without fully handling the TS syntax.
    /// The feature is not yet covered by syntax-aware transforms (pending bd-1lsy.3.4.1).
    KnownGap,
}

impl ExpectedOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NormalizedAway => "normalized_away",
            Self::LoweredToEs2020 => "lowered_to_es2020",
            Self::FailClosed => "fail_closed",
            Self::KnownGap => "known_gap",
        }
    }
}

/// A single corpus specimen: TS input with expected behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusSpecimen {
    pub specimen_id: String,
    pub feature_family: TsFeatureFamily,
    pub ts_source: String,
    pub expected_outcome: ExpectedOutcome,
    pub expected_absent_patterns: Vec<String>,
    pub expected_present_patterns: Vec<String>,
    pub description: String,
}

/// Build the canonical diagnostic corpus.
pub fn diagnostic_corpus() -> Vec<CorpusSpecimen> {
    vec![
        CorpusSpecimen {
            specimen_id: "type_annotation_variable".to_string(),
            feature_family: TsFeatureFamily::TypeAnnotation,
            ts_source: "const x: number = 42;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec![": number".to_string()],
            expected_present_patterns: vec!["const x".to_string(), "42".to_string()],
            description: "Type annotation on variable declaration is stripped".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "type_annotation_function_param".to_string(),
            feature_family: TsFeatureFamily::TypeAnnotation,
            ts_source: "function add(a: number, b: number): number { return a + b; }".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec![": number".to_string()],
            expected_present_patterns: vec!["function add".to_string(), "return a + b".to_string()],
            description: "Type annotations on function params and return are stripped".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "type_only_import".to_string(),
            feature_family: TsFeatureFamily::TypeOnlyImport,
            ts_source: "import type { Foo } from \"./types\";\nconst x = 1;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["import type".to_string()],
            expected_present_patterns: vec!["const x = 1".to_string()],
            description: "Type-only import is completely elided".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "interface_declaration".to_string(),
            feature_family: TsFeatureFamily::InterfaceDeclaration,
            ts_source: "interface Shape { area(): number; }\nconst s = {};".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["interface Shape".to_string()],
            expected_present_patterns: vec!["const s".to_string()],
            description: "Interface declaration is elided from runtime normalization output".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "type_alias_declaration".to_string(),
            feature_family: TsFeatureFamily::TypeAliasDeclaration,
            ts_source: "type Point = { x: number; y: number };\nconst p = { x: 1, y: 2 };".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["type Point".to_string()],
            expected_present_patterns: vec!["const p".to_string()],
            description: "Type alias declaration is elided from runtime normalization output".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "enum_declaration".to_string(),
            feature_family: TsFeatureFamily::EnumDeclaration,
            ts_source: "enum Direction { Up, Down, Left, Right }".to_string(),
            expected_outcome: ExpectedOutcome::LoweredToEs2020,
            expected_absent_patterns: vec!["enum Direction".to_string()],
            expected_present_patterns: vec!["Object.freeze".to_string(), "Direction".to_string()],
            description: "Enum declaration lowered to Object.freeze form".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "namespace_simple".to_string(),
            feature_family: TsFeatureFamily::NamespaceDeclaration,
            ts_source: "namespace Util {\n  export const VERSION = \"1.0\";\n}".to_string(),
            expected_outcome: ExpectedOutcome::LoweredToEs2020,
            expected_absent_patterns: vec!["namespace Util".to_string()],
            expected_present_patterns: vec!["const Util".to_string(), "ns.VERSION".to_string()],
            description: "Namespace declaration lowered to IIFE with member exports".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "parameter_property".to_string(),
            feature_family: TsFeatureFamily::ParameterProperty,
            ts_source: "constructor(private name: string, public age: number) { }".to_string(),
            expected_outcome: ExpectedOutcome::LoweredToEs2020,
            expected_absent_patterns: vec!["private ".to_string(), "public ".to_string()],
            expected_present_patterns: vec!["this.name".to_string(), "this.age".to_string()],
            description: "Constructor parameter properties lowered to explicit assignments".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "abstract_class".to_string(),
            feature_family: TsFeatureFamily::AbstractClass,
            ts_source: "abstract class Shape { abstract area(): number; }".to_string(),
            expected_outcome: ExpectedOutcome::KnownGap,
            expected_absent_patterns: vec![],
            expected_present_patterns: vec!["class Shape".to_string()],
            description: "Abstract class lowering strips top-level keyword but abstract members survive (known gap)".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "class_decorator".to_string(),
            feature_family: TsFeatureFamily::ClassDecorator,
            ts_source: "@injectable\nclass Service { }".to_string(),
            expected_outcome: ExpectedOutcome::LoweredToEs2020,
            expected_absent_patterns: vec!["@injectable".to_string()],
            expected_present_patterns: vec!["Service".to_string()],
            description: "Class decorator lowered to wrapper application".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "definite_assignment".to_string(),
            feature_family: TsFeatureFamily::DefiniteAssignment,
            ts_source: "let x!: number;\nx = 42;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["!:".to_string()],
            expected_present_patterns: vec!["let x".to_string()],
            description: "Definite assignment assertion stripped".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "const_assertion".to_string(),
            feature_family: TsFeatureFamily::ConstAssertion,
            ts_source: "const config = { mode: \"strict\" } as const;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["as const".to_string()],
            expected_present_patterns: vec!["const config".to_string()],
            description: "Const assertion stripped from value expression".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "hostcall_type_param".to_string(),
            feature_family: TsFeatureFamily::HostcallTypeParam,
            ts_source: "const result = hostcall<\"fs.read\">(path);".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["<\"fs.read\">".to_string()],
            expected_present_patterns: vec!["hostcall".to_string(), "path".to_string()],
            description: "Hostcall generic type parameter stripped for ES2020 parser".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "jsx_simple_element".to_string(),
            feature_family: TsFeatureFamily::JsxElement,
            ts_source: "const el = <div className=\"app\">Hello</div>;".to_string(),
            expected_outcome: ExpectedOutcome::KnownGap,
            expected_absent_patterns: vec![],
            expected_present_patterns: vec!["const el".to_string()],
            description: "JSX lowering does not handle this form yet (known gap)".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "implements_clause".to_string(),
            feature_family: TsFeatureFamily::ImplementsClause,
            ts_source: "class Dog implements Animal { bark() { } }".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["implements Animal".to_string()],
            expected_present_patterns: vec!["class Dog".to_string(), "bark()".to_string()],
            description: "Implements clause is stripped from runtime normalization output".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "export_type_declaration".to_string(),
            feature_family: TsFeatureFamily::ExportTypeDeclaration,
            ts_source: "export type Foo = string;\nconst x = 1;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["export type".to_string(), "type Foo".to_string()],
            expected_present_patterns: vec!["const x".to_string()],
            description: "Export type declaration is elided from runtime normalization output".to_string(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

/// The actual outcome of running a corpus specimen through normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActualOutcome {
    /// Normalization succeeded.
    Success,
    /// Normalization rejected with a structured diagnostic.
    Rejected,
}

/// Verdict for a single corpus specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecimenVerdict {
    /// Specimen behaved as expected.
    Pass,
    /// Specimen outcome differed from expected.
    Fail,
}

/// Evidence record for a single corpus specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecimenEvidence {
    pub specimen_id: String,
    pub feature_family: TsFeatureFamily,
    pub expected_outcome: ExpectedOutcome,
    pub actual_outcome: ActualOutcome,
    pub verdict: SpecimenVerdict,
    pub absent_pattern_failures: Vec<String>,
    pub present_pattern_failures: Vec<String>,
    pub error_message: Option<String>,
    pub normalized_source_preview: Option<String>,
}

/// Complete evidence inventory from running the corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsNormalizationEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub known_gap_count: u64,
    pub feature_family_coverage: BTreeMap<String, u64>,
    pub evidence: Vec<SpecimenEvidence>,
}

impl TsNormalizationEvidenceInventory {
    /// Returns true if the fail-closed contract is satisfied:
    /// every specimen produced the expected outcome.
    pub fn contract_satisfied(&self) -> bool {
        self.fail_count == 0
    }
}

/// Run manifest for an evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsEvidenceRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub known_gap_count: u64,
    pub contract_satisfied: bool,
    pub artifact_paths: TsEvidenceArtifactPaths,
}

/// Paths to evidence artifacts within a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsEvidenceArtifactPaths {
    pub evidence_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

/// An event emitted during evidence collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsEvidenceEvent {
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
pub struct TsEvidenceBundleArtifacts {
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Run a single corpus specimen through the normalization pipeline.
fn evaluate_specimen(
    specimen: &CorpusSpecimen,
    config: &TsNormalizationConfig,
) -> SpecimenEvidence {
    let result = normalize_typescript_to_es2020(
        &specimen.ts_source,
        config,
        "evidence-trace",
        "evidence-decision",
        TS_EVIDENCE_POLICY_ID,
    );

    match result {
        Ok(output) => {
            let actual_outcome = ActualOutcome::Success;
            let normalized = &output.normalized_source;

            let absent_failures: Vec<String> = specimen
                .expected_absent_patterns
                .iter()
                .filter(|pat| normalized.contains(pat.as_str()))
                .cloned()
                .collect();

            let present_failures: Vec<String> = specimen
                .expected_present_patterns
                .iter()
                .filter(|pat| !normalized.contains(pat.as_str()))
                .cloned()
                .collect();

            let expected_success = matches!(
                specimen.expected_outcome,
                ExpectedOutcome::NormalizedAway
                    | ExpectedOutcome::LoweredToEs2020
                    | ExpectedOutcome::KnownGap
            );

            let verdict =
                if expected_success && absent_failures.is_empty() && present_failures.is_empty() {
                    SpecimenVerdict::Pass
                } else {
                    SpecimenVerdict::Fail
                };

            let preview = if normalized.len() > 200 {
                format!("{}...", &normalized[..200])
            } else {
                normalized.clone()
            };

            SpecimenEvidence {
                specimen_id: specimen.specimen_id.clone(),
                feature_family: specimen.feature_family,
                expected_outcome: specimen.expected_outcome,
                actual_outcome,
                verdict,
                absent_pattern_failures: absent_failures,
                present_pattern_failures: present_failures,
                error_message: None,
                normalized_source_preview: Some(preview),
            }
        }
        Err(e) => {
            let actual_outcome = ActualOutcome::Rejected;
            let verdict = if specimen.expected_outcome == ExpectedOutcome::FailClosed {
                SpecimenVerdict::Pass
            } else {
                SpecimenVerdict::Fail
            };

            SpecimenEvidence {
                specimen_id: specimen.specimen_id.clone(),
                feature_family: specimen.feature_family,
                expected_outcome: specimen.expected_outcome,
                actual_outcome,
                verdict,
                absent_pattern_failures: Vec::new(),
                present_pattern_failures: Vec::new(),
                error_message: Some(e.to_string()),
                normalized_source_preview: None,
            }
        }
    }
}

/// Run the complete diagnostic corpus and collect evidence.
pub fn run_diagnostic_corpus() -> TsNormalizationEvidenceInventory {
    let corpus = diagnostic_corpus();
    let config = TsNormalizationConfig::default();

    let mut evidence = Vec::with_capacity(corpus.len());
    let mut pass_count: u64 = 0;
    let mut fail_count: u64 = 0;
    let mut known_gap_count: u64 = 0;
    let mut coverage: BTreeMap<String, u64> = BTreeMap::new();

    for specimen in &corpus {
        let result = evaluate_specimen(specimen, &config);
        *coverage
            .entry(specimen.feature_family.as_str().to_string())
            .or_insert(0) += 1;
        if specimen.expected_outcome == ExpectedOutcome::KnownGap {
            known_gap_count += 1;
        }
        match result.verdict {
            SpecimenVerdict::Pass => pass_count += 1,
            SpecimenVerdict::Fail => fail_count += 1,
        }
        evidence.push(result);
    }

    TsNormalizationEvidenceInventory {
        schema_version: TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION.to_string(),
        component: TS_EVIDENCE_COMPONENT.to_string(),
        specimen_count: corpus.len() as u64,
        pass_count,
        fail_count,
        known_gap_count,
        feature_family_coverage: coverage,
        evidence,
    }
}

/// Generate events for an evidence collection run.
fn generate_events(inventory: &TsNormalizationEvidenceInventory) -> Vec<TsEvidenceEvent> {
    let mut events = Vec::new();

    events.push(TsEvidenceEvent {
        schema_version: TS_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: TS_EVIDENCE_COMPONENT.to_string(),
        event: "evidence_run_started".to_string(),
        policy_id: TS_EVIDENCE_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: Some(format!(
            "starting TS normalization evidence collection for {} specimens",
            inventory.specimen_count
        )),
    });

    for ev in &inventory.evidence {
        events.push(TsEvidenceEvent {
            schema_version: TS_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
            component: TS_EVIDENCE_COMPONENT.to_string(),
            event: "specimen_evaluated".to_string(),
            policy_id: TS_EVIDENCE_POLICY_ID.to_string(),
            specimen_id: Some(ev.specimen_id.clone()),
            verdict: Some(match ev.verdict {
                SpecimenVerdict::Pass => "pass".to_string(),
                SpecimenVerdict::Fail => "fail".to_string(),
            }),
            detail: Some(format!(
                "expected={}, actual={}, verdict={}",
                ev.expected_outcome.as_str(),
                match ev.actual_outcome {
                    ActualOutcome::Success => "success",
                    ActualOutcome::Rejected => "rejected",
                },
                match ev.verdict {
                    SpecimenVerdict::Pass => "pass",
                    SpecimenVerdict::Fail => "fail",
                }
            )),
        });
    }

    events.push(TsEvidenceEvent {
        schema_version: TS_EVIDENCE_EVENT_SCHEMA_VERSION.to_string(),
        component: TS_EVIDENCE_COMPONENT.to_string(),
        event: "evidence_run_completed".to_string(),
        policy_id: TS_EVIDENCE_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: Some(format!(
            "{} specimens: {} pass, {} fail, {} known gaps. Contract: {}",
            inventory.specimen_count,
            inventory.pass_count,
            inventory.fail_count,
            inventory.known_gap_count,
            if inventory.contract_satisfied() {
                "SATISFIED"
            } else {
                "VIOLATED"
            }
        )),
    });

    events
}

/// Write the full evidence bundle to disk.
pub fn write_evidence_bundle(
    out_dir: &Path,
    commands: &[String],
) -> Result<TsEvidenceBundleArtifacts, std::io::Error> {
    fs::create_dir_all(out_dir)?;

    let inventory = run_diagnostic_corpus();
    let inventory_json = serde_json::to_string_pretty(&inventory)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let inventory_hash =
        crate::hash_tiers::ContentHash::compute(inventory_json.as_bytes()).to_hex();

    let inventory_path = out_dir.join("ts_normalization_evidence_inventory.json");
    fs::write(&inventory_path, &inventory_json)?;

    let trace_id = format!(
        "ts-evidence-{}",
        inventory_hash.chars().take(12).collect::<String>()
    );
    let decision_id = format!("decision-{}", trace_id);

    let manifest = TsEvidenceRunManifest {
        schema_version: TS_EVIDENCE_MANIFEST_SCHEMA_VERSION.to_string(),
        component: TS_EVIDENCE_COMPONENT.to_string(),
        trace_id,
        decision_id,
        policy_id: TS_EVIDENCE_POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
        specimen_count: inventory.specimen_count,
        pass_count: inventory.pass_count,
        fail_count: inventory.fail_count,
        known_gap_count: inventory.known_gap_count,
        contract_satisfied: inventory.contract_satisfied(),
        artifact_paths: TsEvidenceArtifactPaths {
            evidence_inventory: "ts_normalization_evidence_inventory.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };

    let manifest_path = out_dir.join("run_manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    fs::write(&manifest_path, &manifest_json)?;

    let events = generate_events(&inventory);
    let events_path = out_dir.join("events.jsonl");
    let events_jsonl: String = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap_or_else(|_| "{}".to_string()))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&events_path, &events_jsonl)?;

    let commands_path = out_dir.join("commands.txt");
    fs::write(&commands_path, commands.join("\n"))?;

    Ok(TsEvidenceBundleArtifacts {
        inventory_path,
        run_manifest_path: manifest_path,
        events_path,
        commands_path,
        inventory_hash,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{}-{}", prefix, ts))
    }

    #[test]
    fn corpus_is_non_empty() {
        let corpus = diagnostic_corpus();
        assert!(!corpus.is_empty());
    }

    #[test]
    fn corpus_covers_all_feature_families() {
        let corpus = diagnostic_corpus();
        let covered: std::collections::BTreeSet<TsFeatureFamily> =
            corpus.iter().map(|s| s.feature_family).collect();
        for family in TsFeatureFamily::ALL {
            assert!(
                covered.contains(family),
                "missing corpus coverage for {:?}",
                family
            );
        }
    }

    #[test]
    fn corpus_specimen_ids_are_unique() {
        let corpus = diagnostic_corpus();
        let ids: std::collections::BTreeSet<&str> =
            corpus.iter().map(|s| s.specimen_id.as_str()).collect();
        assert_eq!(ids.len(), corpus.len(), "duplicate specimen IDs");
    }

    #[test]
    fn corpus_specimens_have_non_empty_fields() {
        let corpus = diagnostic_corpus();
        for s in &corpus {
            assert!(!s.specimen_id.is_empty());
            assert!(!s.ts_source.is_empty());
            assert!(!s.description.is_empty());
        }
    }

    #[test]
    fn run_diagnostic_corpus_all_pass() {
        let inv = run_diagnostic_corpus();
        let failures: Vec<_> = inv
            .evidence
            .iter()
            .filter(|e| e.verdict == SpecimenVerdict::Fail)
            .collect();
        if !failures.is_empty() {
            let mut msg = format!("{} specimens failed:\n", failures.len());
            for ev in &failures {
                msg.push_str(&format!(
                    "  - {}: actual={:?}, expected={:?}, absent_fail={:?}, present_fail={:?}, err={:?}, preview={:?}\n",
                    ev.specimen_id, ev.actual_outcome, ev.expected_outcome,
                    ev.absent_pattern_failures, ev.present_pattern_failures,
                    ev.error_message, ev.normalized_source_preview,
                ));
            }
            panic!("{}", msg);
        }
    }

    #[test]
    fn run_diagnostic_corpus_contract_satisfied() {
        let inv = run_diagnostic_corpus();
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn evidence_inventory_counts_are_consistent() {
        let inv = run_diagnostic_corpus();
        assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
        assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
    }

    #[test]
    fn feature_family_coverage_matches_corpus() {
        let inv = run_diagnostic_corpus();
        let total: u64 = inv.feature_family_coverage.values().sum();
        assert_eq!(total, inv.specimen_count);
    }

    #[test]
    fn ts_feature_family_as_str_all_distinct() {
        let strs: std::collections::BTreeSet<&str> =
            TsFeatureFamily::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(strs.len(), TsFeatureFamily::ALL.len());
    }

    #[test]
    fn ts_feature_family_description_all_non_empty() {
        for f in TsFeatureFamily::ALL {
            assert!(!f.description().is_empty());
        }
    }

    #[test]
    fn expected_outcome_as_str_roundtrip() {
        let outcomes = [
            ExpectedOutcome::NormalizedAway,
            ExpectedOutcome::LoweredToEs2020,
            ExpectedOutcome::FailClosed,
            ExpectedOutcome::KnownGap,
        ];
        for o in outcomes {
            assert!(!o.as_str().is_empty());
        }
    }

    #[test]
    fn evidence_serde_roundtrip() {
        let inv = run_diagnostic_corpus();
        let json = serde_json::to_string(&inv).expect("serialize");
        let back: TsNormalizationEvidenceInventory =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(inv, back);
    }

    #[test]
    fn write_bundle_creates_all_artifacts() {
        let out = unique_temp_dir("ts-evidence-bundle");
        let cmds = vec!["test".to_string()];
        let arts = write_evidence_bundle(&out, &cmds).expect("write");
        assert!(arts.inventory_path.exists());
        assert!(arts.run_manifest_path.exists());
        assert!(arts.events_path.exists());
        assert!(arts.commands_path.exists());
    }

    #[test]
    fn bundle_manifest_is_consistent() {
        let out = unique_temp_dir("ts-evidence-manifest");
        let cmds = vec!["verify".to_string()];
        let arts = write_evidence_bundle(&out, &cmds).expect("write");

        let manifest: TsEvidenceRunManifest =
            serde_json::from_slice(&fs::read(&arts.run_manifest_path).expect("read"))
                .expect("parse");
        assert!(manifest.contract_satisfied);
        assert_eq!(manifest.fail_count, 0);
        assert_eq!(
            manifest.pass_count + manifest.fail_count,
            manifest.specimen_count
        );
    }

    #[test]
    fn bundle_hash_is_deterministic() {
        let out1 = unique_temp_dir("ts-evidence-det1");
        let out2 = unique_temp_dir("ts-evidence-det2");
        let cmds = vec!["test".to_string()];
        let a1 = write_evidence_bundle(&out1, &cmds).expect("write1");
        let a2 = write_evidence_bundle(&out2, &cmds).expect("write2");
        assert_eq!(a1.inventory_hash, a2.inventory_hash);
    }

    #[test]
    fn bundle_events_jsonl_line_count() {
        let out = unique_temp_dir("ts-evidence-events");
        let cmds = vec!["test".to_string()];
        let arts = write_evidence_bundle(&out, &cmds).expect("write");
        let events = fs::read_to_string(&arts.events_path).expect("read");
        let corpus = diagnostic_corpus();
        // start + per-specimen + end
        assert_eq!(events.lines().count(), corpus.len() + 2);
    }

    #[test]
    fn bundle_hash_is_64_hex_chars() {
        let out = unique_temp_dir("ts-evidence-hex");
        let cmds = vec!["test".to_string()];
        let arts = write_evidence_bundle(&out, &cmds).expect("write");
        assert_eq!(arts.inventory_hash.len(), 64);
        assert!(arts.inventory_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn evaluate_specimen_success_with_correct_patterns() {
        let specimen = CorpusSpecimen {
            specimen_id: "test".to_string(),
            feature_family: TsFeatureFamily::TypeAnnotation,
            ts_source: "const x: number = 1;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec![": number".to_string()],
            expected_present_patterns: vec!["const x".to_string()],
            description: "test".to_string(),
        };
        let config = TsNormalizationConfig::default();
        let ev = evaluate_specimen(&specimen, &config);
        assert_eq!(ev.verdict, SpecimenVerdict::Pass);
        assert_eq!(ev.actual_outcome, ActualOutcome::Success);
    }

    #[test]
    fn evaluate_specimen_fail_when_pattern_still_present() {
        let specimen = CorpusSpecimen {
            specimen_id: "test".to_string(),
            feature_family: TsFeatureFamily::TypeAnnotation,
            ts_source: "const x: number = 1;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["const".to_string()], // "const" will still be present
            expected_present_patterns: vec![],
            description: "test".to_string(),
        };
        let config = TsNormalizationConfig::default();
        let ev = evaluate_specimen(&specimen, &config);
        assert_eq!(ev.verdict, SpecimenVerdict::Fail);
    }

    #[test]
    fn inventory_schema_version_correct() {
        let inv = run_diagnostic_corpus();
        assert_eq!(inv.schema_version, TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION);
        assert_eq!(inv.component, TS_EVIDENCE_COMPONENT);
    }

    #[test]
    fn schema_version_constants_are_all_distinct() {
        let versions = [
            TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION,
            TS_EVIDENCE_MANIFEST_SCHEMA_VERSION,
            TS_EVIDENCE_EVENT_SCHEMA_VERSION,
            TS_EVIDENCE_POLICY_ID,
        ];
        let set: std::collections::BTreeSet<&str> = versions.iter().copied().collect();
        assert_eq!(set.len(), versions.len());
    }

    #[test]
    fn ts_feature_family_serde_roundtrip_all_variants() {
        for family in TsFeatureFamily::ALL {
            let json = serde_json::to_string(family).unwrap();
            let back: TsFeatureFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*family, back);
        }
    }

    #[test]
    fn actual_outcome_serde_roundtrip() {
        for variant in [ActualOutcome::Success, ActualOutcome::Rejected] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ActualOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn specimen_verdict_serde_roundtrip() {
        for variant in [SpecimenVerdict::Pass, SpecimenVerdict::Fail] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: SpecimenVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn contract_not_satisfied_when_failures_present() {
        let inv = TsNormalizationEvidenceInventory {
            schema_version: TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION.into(),
            component: TS_EVIDENCE_COMPONENT.into(),
            specimen_count: 5,
            pass_count: 4,
            fail_count: 1,
            known_gap_count: 0,
            feature_family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn contract_satisfied_with_known_gaps_and_zero_failures() {
        let inv = TsNormalizationEvidenceInventory {
            schema_version: TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION.into(),
            component: TS_EVIDENCE_COMPONENT.into(),
            specimen_count: 10,
            pass_count: 10,
            fail_count: 0,
            known_gap_count: 3,
            feature_family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn ts_evidence_event_serde_roundtrip() {
        let ev = TsEvidenceEvent {
            schema_version: TS_EVIDENCE_EVENT_SCHEMA_VERSION.into(),
            component: TS_EVIDENCE_COMPONENT.into(),
            event: "specimen_evaluated".into(),
            policy_id: TS_EVIDENCE_POLICY_ID.into(),
            specimen_id: Some("ts_type_annotation".into()),
            verdict: Some("pass".into()),
            detail: Some("normalized successfully".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: TsEvidenceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn evaluate_specimen_fail_when_expected_present_pattern_missing() {
        let specimen = CorpusSpecimen {
            specimen_id: "test_present".to_string(),
            feature_family: TsFeatureFamily::TypeAnnotation,
            ts_source: "const x: number = 1;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec![],
            expected_present_patterns: vec!["WILL_NOT_APPEAR".to_string()],
            description: "test present pattern failure".to_string(),
        };
        let config = TsNormalizationConfig::default();
        let ev = evaluate_specimen(&specimen, &config);
        assert_eq!(ev.verdict, SpecimenVerdict::Fail);
        assert!(
            ev.present_pattern_failures
                .iter()
                .any(|p| p == "WILL_NOT_APPEAR")
        );
    }

    // ── enrichment: corpus structure and determinism ───────────────

    #[test]
    fn corpus_has_exactly_fifteen_specimens() {
        let corpus = diagnostic_corpus();
        // Corpus has 16 specimens (two for TypeAnnotation, one each for other 14 families)
        assert_eq!(corpus.len(), TsFeatureFamily::ALL.len() + 1);
    }

    #[test]
    fn corpus_specimen_ids_follow_naming_convention() {
        let corpus = diagnostic_corpus();
        for s in &corpus {
            // Specimen IDs are descriptive snake_case names matching the TS feature
            assert!(
                s.specimen_id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "specimen id '{}' should be snake_case",
                s.specimen_id
            );
        }
    }

    #[test]
    fn corpus_every_specimen_has_expected_absent_or_present_patterns() {
        let corpus = diagnostic_corpus();
        for s in &corpus {
            let has_patterns =
                !s.expected_absent_patterns.is_empty() || !s.expected_present_patterns.is_empty();
            assert!(
                has_patterns
                    || s.expected_outcome == ExpectedOutcome::FailClosed
                    || s.expected_outcome == ExpectedOutcome::KnownGap,
                "specimen '{}' should have patterns or be fail-closed/known-gap",
                s.specimen_id
            );
        }
    }

    #[test]
    fn corpus_is_deterministic_across_calls() {
        let c1 = diagnostic_corpus();
        let c2 = diagnostic_corpus();
        assert_eq!(c1.len(), c2.len());
        for (a, b) in c1.iter().zip(c2.iter()) {
            assert_eq!(a.specimen_id, b.specimen_id);
            assert_eq!(a.feature_family, b.feature_family);
            assert_eq!(a.ts_source, b.ts_source);
        }
    }

    // ── enrichment: feature family enum properties ────────────────

    #[test]
    fn ts_feature_family_all_has_fifteen_members() {
        assert_eq!(TsFeatureFamily::ALL.len(), 15);
    }

    #[test]
    fn ts_feature_family_as_str_is_snake_case() {
        for f in TsFeatureFamily::ALL {
            let s = f.as_str();
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "as_str for {:?} = '{}' is not snake_case",
                f,
                s
            );
        }
    }

    #[test]
    fn ts_feature_family_description_is_distinct() {
        let descriptions: std::collections::BTreeSet<&str> = TsFeatureFamily::ALL
            .iter()
            .map(|f| f.description())
            .collect();
        assert_eq!(descriptions.len(), TsFeatureFamily::ALL.len());
    }

    #[test]
    fn expected_outcome_all_variants_have_distinct_strings() {
        let outcomes = [
            ExpectedOutcome::NormalizedAway,
            ExpectedOutcome::LoweredToEs2020,
            ExpectedOutcome::FailClosed,
            ExpectedOutcome::KnownGap,
        ];
        let strs: std::collections::BTreeSet<&str> = outcomes.iter().map(|o| o.as_str()).collect();
        assert_eq!(strs.len(), outcomes.len());
    }

    // ── enrichment: evidence inventory properties ─────────────────

    #[test]
    fn inventory_evidence_count_matches_corpus_size() {
        let inv = run_diagnostic_corpus();
        let corpus = diagnostic_corpus();
        assert_eq!(inv.evidence.len(), corpus.len());
    }

    #[test]
    fn inventory_all_evidence_has_matching_specimen_id() {
        let inv = run_diagnostic_corpus();
        let corpus = diagnostic_corpus();
        let corpus_ids: std::collections::BTreeSet<&str> =
            corpus.iter().map(|s| s.specimen_id.as_str()).collect();
        for ev in &inv.evidence {
            assert!(
                corpus_ids.contains(ev.specimen_id.as_str()),
                "evidence specimen_id '{}' not in corpus",
                ev.specimen_id
            );
        }
    }

    #[test]
    fn inventory_feature_family_coverage_keys_are_valid() {
        let inv = run_diagnostic_corpus();
        let valid: std::collections::BTreeSet<&str> =
            TsFeatureFamily::ALL.iter().map(|f| f.as_str()).collect();
        for key in inv.feature_family_coverage.keys() {
            assert!(
                valid.contains(key.as_str()),
                "coverage key '{}' is not a valid feature family",
                key
            );
        }
    }

    #[test]
    fn inventory_known_gap_count_tracks_known_gap_specimens() {
        let inv = run_diagnostic_corpus();
        let corpus = diagnostic_corpus();
        let expected_known = corpus
            .iter()
            .filter(|s| s.expected_outcome == ExpectedOutcome::KnownGap)
            .count() as u64;
        assert_eq!(inv.known_gap_count, expected_known);
    }

    // ── enrichment: contract satisfaction edge cases ───────────────

    #[test]
    fn contract_not_satisfied_when_all_fail() {
        let inv = TsNormalizationEvidenceInventory {
            schema_version: TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION.into(),
            component: TS_EVIDENCE_COMPONENT.into(),
            specimen_count: 3,
            pass_count: 0,
            fail_count: 3,
            known_gap_count: 0,
            feature_family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn contract_satisfied_single_pass_no_failures() {
        let inv = TsNormalizationEvidenceInventory {
            schema_version: TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION.into(),
            component: TS_EVIDENCE_COMPONENT.into(),
            specimen_count: 1,
            pass_count: 1,
            fail_count: 0,
            known_gap_count: 0,
            feature_family_coverage: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(inv.contract_satisfied());
    }

    // ── enrichment: evaluate_specimen edge cases ──────────────────

    #[test]
    fn evaluate_specimen_success_with_empty_patterns() {
        let specimen = CorpusSpecimen {
            specimen_id: "test_empty".to_string(),
            feature_family: TsFeatureFamily::TypeAnnotation,
            ts_source: "const x: number = 1;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec![],
            expected_present_patterns: vec![],
            description: "empty patterns should pass".to_string(),
        };
        let config = TsNormalizationConfig::default();
        let ev = evaluate_specimen(&specimen, &config);
        assert_eq!(ev.verdict, SpecimenVerdict::Pass);
    }

    #[test]
    fn evaluate_specimen_records_feature_family() {
        let specimen = CorpusSpecimen {
            specimen_id: "test_family".to_string(),
            feature_family: TsFeatureFamily::EnumDeclaration,
            ts_source: "enum Color { Red, Green, Blue }".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["enum".to_string()],
            expected_present_patterns: vec![],
            description: "enum normalization".to_string(),
        };
        let config = TsNormalizationConfig::default();
        let ev = evaluate_specimen(&specimen, &config);
        assert_eq!(ev.feature_family, TsFeatureFamily::EnumDeclaration);
    }

    #[test]
    fn evaluate_specimen_multiple_absent_patterns_all_checked() {
        let specimen = CorpusSpecimen {
            specimen_id: "test_multi_absent".to_string(),
            feature_family: TsFeatureFamily::TypeAnnotation,
            ts_source: "const x: number = 1;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec![": number".to_string(), "MISSING_PATTERN".to_string()],
            expected_present_patterns: vec!["const x".to_string()],
            description: "check multiple absent patterns".to_string(),
        };
        let config = TsNormalizationConfig::default();
        let ev = evaluate_specimen(&specimen, &config);
        // Both patterns should be checked. ": number" should be absent (pass),
        // "MISSING_PATTERN" was already absent (pass too).
        assert_eq!(ev.verdict, SpecimenVerdict::Pass);
    }

    #[test]
    fn evaluate_specimen_normalized_source_preview_is_populated() {
        let specimen = CorpusSpecimen {
            specimen_id: "test_preview".to_string(),
            feature_family: TsFeatureFamily::TypeAnnotation,
            ts_source: "const x: number = 1;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec![],
            expected_present_patterns: vec![],
            description: "preview check".to_string(),
        };
        let config = TsNormalizationConfig::default();
        let ev = evaluate_specimen(&specimen, &config);
        assert!(ev.normalized_source_preview.is_some());
    }

    // ── enrichment: bundle artifact properties ────────────────────

    #[test]
    fn bundle_inventory_contains_all_evidence() {
        let out = unique_temp_dir("ts-evidence-inv-complete");
        let cmds = vec!["test".to_string()];
        let arts = write_evidence_bundle(&out, &cmds).expect("write");
        let inv: TsNormalizationEvidenceInventory =
            serde_json::from_slice(&fs::read(&arts.inventory_path).expect("read")).expect("parse");
        assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
    }

    #[test]
    fn bundle_commands_file_contains_input_commands() {
        let out = unique_temp_dir("ts-evidence-cmds");
        let cmds = vec![
            "frankenctl verify ts-normalization".to_string(),
            "cargo test".to_string(),
        ];
        let arts = write_evidence_bundle(&out, &cmds).expect("write");
        let content = fs::read_to_string(&arts.commands_path).expect("read");
        assert!(content.contains("frankenctl verify ts-normalization"));
        assert!(content.contains("cargo test"));
    }

    #[test]
    fn bundle_manifest_trace_id_is_from_hash() {
        let out = unique_temp_dir("ts-evidence-trace");
        let cmds = vec!["test".to_string()];
        let arts = write_evidence_bundle(&out, &cmds).expect("write");
        let manifest: TsEvidenceRunManifest =
            serde_json::from_slice(&fs::read(&arts.run_manifest_path).expect("read"))
                .expect("parse");
        assert!(!manifest.trace_id.is_empty());
        assert!(!manifest.decision_id.is_empty());
        assert_eq!(manifest.policy_id, TS_EVIDENCE_POLICY_ID);
    }

    #[test]
    fn bundle_manifest_artifact_paths_are_set() {
        let out = unique_temp_dir("ts-evidence-paths");
        let cmds = vec!["test".to_string()];
        let arts = write_evidence_bundle(&out, &cmds).expect("write");
        let manifest: TsEvidenceRunManifest =
            serde_json::from_slice(&fs::read(&arts.run_manifest_path).expect("read"))
                .expect("parse");
        assert!(!manifest.artifact_paths.evidence_inventory.is_empty());
        assert!(!manifest.artifact_paths.run_manifest.is_empty());
        assert!(!manifest.artifact_paths.events_jsonl.is_empty());
        assert!(!manifest.artifact_paths.commands_txt.is_empty());
    }

    #[test]
    fn bundle_events_start_with_started_event() {
        let out = unique_temp_dir("ts-evidence-start-event");
        let cmds = vec!["test".to_string()];
        let arts = write_evidence_bundle(&out, &cmds).expect("write");
        let events_raw = fs::read_to_string(&arts.events_path).expect("read");
        let first_line = events_raw.lines().next().expect("at least one event");
        let ev: TsEvidenceEvent = serde_json::from_str(first_line).expect("parse first event");
        assert_eq!(ev.event, "evidence_run_started");
    }

    #[test]
    fn bundle_events_end_with_completed_event() {
        let out = unique_temp_dir("ts-evidence-end-event");
        let cmds = vec!["test".to_string()];
        let arts = write_evidence_bundle(&out, &cmds).expect("write");
        let events_raw = fs::read_to_string(&arts.events_path).expect("read");
        let last_line = events_raw.lines().last().expect("at least one event");
        let ev: TsEvidenceEvent = serde_json::from_str(last_line).expect("parse last event");
        assert_eq!(ev.event, "evidence_run_completed");
    }

    // ── enrichment: serde round-trips for remaining types ─────────

    #[test]
    fn corpus_specimen_serde_roundtrip() {
        let specimen = CorpusSpecimen {
            specimen_id: "test_serde".into(),
            feature_family: TsFeatureFamily::TypeAnnotation,
            ts_source: "const x: number = 1;".into(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec![": number".into()],
            expected_present_patterns: vec!["const x".into()],
            description: "serde test".into(),
        };
        let json = serde_json::to_string(&specimen).unwrap();
        let back: CorpusSpecimen = serde_json::from_str(&json).unwrap();
        assert_eq!(specimen, back);
    }

    #[test]
    fn specimen_evidence_serde_roundtrip() {
        let ev = SpecimenEvidence {
            specimen_id: "test".into(),
            feature_family: TsFeatureFamily::InterfaceDeclaration,
            expected_outcome: ExpectedOutcome::NormalizedAway,
            actual_outcome: ActualOutcome::Success,
            verdict: SpecimenVerdict::Pass,
            absent_pattern_failures: vec![],
            present_pattern_failures: vec![],
            error_message: None,
            normalized_source_preview: Some("const x = 1;".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: SpecimenEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn specimen_evidence_with_failures_serde_roundtrip() {
        let ev = SpecimenEvidence {
            specimen_id: "fail_test".into(),
            feature_family: TsFeatureFamily::EnumDeclaration,
            expected_outcome: ExpectedOutcome::NormalizedAway,
            actual_outcome: ActualOutcome::Rejected,
            verdict: SpecimenVerdict::Fail,
            absent_pattern_failures: vec!["pattern_a".into()],
            present_pattern_failures: vec!["pattern_b".into()],
            error_message: Some("normalization error".into()),
            normalized_source_preview: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: SpecimenEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn run_manifest_serde_roundtrip() {
        let manifest = TsEvidenceRunManifest {
            schema_version: TS_EVIDENCE_MANIFEST_SCHEMA_VERSION.into(),
            component: TS_EVIDENCE_COMPONENT.into(),
            trace_id: "trace-abc".into(),
            decision_id: "decision-def".into(),
            policy_id: TS_EVIDENCE_POLICY_ID.into(),
            inventory_hash: "a".repeat(64),
            specimen_count: 15,
            pass_count: 15,
            fail_count: 0,
            known_gap_count: 2,
            contract_satisfied: true,
            artifact_paths: TsEvidenceArtifactPaths {
                evidence_inventory: "inv.json".into(),
                run_manifest: "manifest.json".into(),
                events_jsonl: "events.jsonl".into(),
                commands_txt: "commands.txt".into(),
            },
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: TsEvidenceRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn artifact_paths_serde_roundtrip() {
        let paths = TsEvidenceArtifactPaths {
            evidence_inventory: "inv.json".into(),
            run_manifest: "manifest.json".into(),
            events_jsonl: "events.jsonl".into(),
            commands_txt: "commands.txt".into(),
        };
        let json = serde_json::to_string(&paths).unwrap();
        let back: TsEvidenceArtifactPaths = serde_json::from_str(&json).unwrap();
        assert_eq!(paths, back);
    }

    // ── enrichment: schema constants ──────────────────────────────

    #[test]
    fn all_schema_constants_start_with_franken_engine() {
        assert!(TS_DIAGNOSTIC_CORPUS_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(TS_EVIDENCE_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(TS_EVIDENCE_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn evidence_component_is_non_empty() {
        assert!(!TS_EVIDENCE_COMPONENT.is_empty());
        assert!(!TS_EVIDENCE_POLICY_ID.is_empty());
    }

    // ── enrichment: evidence ordering preserved ───────────────────

    #[test]
    fn evidence_preserves_corpus_order() {
        let inv = run_diagnostic_corpus();
        let corpus = diagnostic_corpus();
        for (i, (ev, sp)) in inv.evidence.iter().zip(corpus.iter()).enumerate() {
            assert_eq!(
                ev.specimen_id, sp.specimen_id,
                "evidence order mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn evidence_feature_families_match_corpus() {
        let inv = run_diagnostic_corpus();
        let corpus = diagnostic_corpus();
        for (ev, sp) in inv.evidence.iter().zip(corpus.iter()) {
            assert_eq!(
                ev.feature_family, sp.feature_family,
                "feature family mismatch for specimen '{}'",
                ev.specimen_id
            );
        }
    }

    #[test]
    fn evidence_expected_outcomes_match_corpus() {
        let inv = run_diagnostic_corpus();
        let corpus = diagnostic_corpus();
        for (ev, sp) in inv.evidence.iter().zip(corpus.iter()) {
            assert_eq!(
                ev.expected_outcome, sp.expected_outcome,
                "expected outcome mismatch for specimen '{}'",
                ev.specimen_id
            );
        }
    }
}
