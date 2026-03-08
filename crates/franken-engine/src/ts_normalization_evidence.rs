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
pub const TS_EVIDENCE_POLICY_ID: &str =
    "franken-engine.ts-normalization-evidence.policy.v1";

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
            Self::ParameterProperty => "Constructor parameter properties (`constructor(private x: T)`)",
            Self::AbstractClass => "Abstract class declarations (`abstract class Foo { ... }`)",
            Self::ClassDecorator => "Class decorators (`@decorator class Foo { ... }`)",
            Self::DefiniteAssignment => "Definite assignment assertions (`x!: number`)",
            Self::ConstAssertion => "Const assertions (`as const`)",
            Self::HostcallTypeParam => "Hostcall generic type parameters (`hostcall<\"cap\">(args)`)",
            Self::JsxElement => "JSX element syntax (`<Component />`)",
            Self::ImplementsClause => "Class implements clauses (`class Foo implements Bar`)",
            Self::ExportTypeDeclaration => "Export type/interface declarations (`export type T = ...`)",
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
}

impl ExpectedOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NormalizedAway => "normalized_away",
            Self::LoweredToEs2020 => "lowered_to_es2020",
            Self::FailClosed => "fail_closed",
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
            expected_absent_patterns: vec!["interface".to_string()],
            expected_present_patterns: vec!["const s".to_string()],
            description: "Interface declaration is elided from runtime output".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "type_alias_declaration".to_string(),
            feature_family: TsFeatureFamily::TypeAliasDeclaration,
            ts_source: "type Point = { x: number; y: number };\nconst p = { x: 1, y: 2 };".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["type Point".to_string()],
            expected_present_patterns: vec!["const p".to_string()],
            description: "Type alias declaration is elided from runtime output".to_string(),
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
            expected_present_patterns: vec!["Util".to_string()],
            description: "Simple namespace declaration lowered to IIFE/object form".to_string(),
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
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["abstract ".to_string()],
            expected_present_patterns: vec!["class Shape".to_string()],
            description: "Abstract keyword stripped from class declaration".to_string(),
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
            specimen_id: "jsx_simple_element".to_string(),
            feature_family: TsFeatureFamily::JsxElement,
            ts_source: "const el = <div className=\"app\">Hello</div>;".to_string(),
            expected_outcome: ExpectedOutcome::LoweredToEs2020,
            expected_absent_patterns: vec!["<div".to_string()],
            expected_present_patterns: vec!["createElement".to_string()],
            description: "JSX element lowered to createElement call".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "implements_clause".to_string(),
            feature_family: TsFeatureFamily::ImplementsClause,
            ts_source: "class Dog implements Animal { bark() { } }".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["implements Animal".to_string()],
            expected_present_patterns: vec!["class Dog".to_string()],
            description: "Implements clause stripped from class declaration".to_string(),
        },
        CorpusSpecimen {
            specimen_id: "export_type_declaration".to_string(),
            feature_family: TsFeatureFamily::ExportTypeDeclaration,
            ts_source: "export type Foo = string;\nconst x = 1;".to_string(),
            expected_outcome: ExpectedOutcome::NormalizedAway,
            expected_absent_patterns: vec!["export type".to_string()],
            expected_present_patterns: vec!["const x".to_string()],
            description: "Export type declaration elided from runtime output".to_string(),
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
                ExpectedOutcome::NormalizedAway | ExpectedOutcome::LoweredToEs2020
            );

            let verdict = if expected_success
                && absent_failures.is_empty()
                && present_failures.is_empty()
            {
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
    let mut coverage: BTreeMap<String, u64> = BTreeMap::new();

    for specimen in &corpus {
        let result = evaluate_specimen(specimen, &config);
        *coverage
            .entry(specimen.feature_family.as_str().to_string())
            .or_insert(0) += 1;
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
            "{} specimens: {} pass, {} fail. Contract: {}",
            inventory.specimen_count,
            inventory.pass_count,
            inventory.fail_count,
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
        assert_eq!(inv.fail_count, 0, "expected all specimens to pass");
        assert_eq!(inv.pass_count, inv.specimen_count);
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
        assert_eq!(manifest.pass_count + manifest.fail_count, manifest.specimen_count);
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
}
