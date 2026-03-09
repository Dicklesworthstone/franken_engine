#![forbid(unsafe_code)]

//! Evidence harness proving that TypeScript normalization is correctly wired
//! into the shipped execution paths (orchestrator `execute()` pipeline).
//!
//! The harness runs a corpus of JS and TS specimens through the orchestrator
//! and verifies: (a) JS sources pass through unchanged, (b) TS sources are
//! detected and normalized before parsing, (c) the `SourceIngestionSummary`
//! in the result faithfully records what happened.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use crate::ts_normalization::SourceLanguage;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const TS_SHIPPED_PATH_SCHEMA_VERSION: &str =
    "franken-engine.ts_shipped_path_evidence.v1";
pub const TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.ts_shipped_path_manifest.v1";
pub const TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.ts_shipped_path_event.v1";
pub const TS_SHIPPED_PATH_COMPONENT: &str = "ts_shipped_path_evidence";
pub const TS_SHIPPED_PATH_POLICY_ID: &str = "RGC-204";

// ---------------------------------------------------------------------------
// Specimen types
// ---------------------------------------------------------------------------

/// A specimen exercising the shipped TS integration path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShippedPathSpecimen {
    pub specimen_id: String,
    pub description: String,
    pub source: String,
    pub source_file: Option<String>,
    pub expected_language: SourceLanguage,
    pub expected_normalization: bool,
    pub expected_outcome: ShippedPathExpectedOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShippedPathExpectedOutcome {
    /// Source should execute successfully.
    ExecuteSuccess,
    /// Source should fail at TS normalization.
    NormalizationFailure,
    /// Source should fail at parse.
    ParseFailure,
}

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShippedPathSpecimenEvidence {
    pub specimen_id: String,
    pub expected_language: SourceLanguage,
    pub actual_language: SourceLanguage,
    pub expected_normalization: bool,
    pub actual_normalization: bool,
    pub expected_outcome: ShippedPathExpectedOutcome,
    pub actual_outcome: ShippedPathActualOutcome,
    pub verdict: ShippedPathVerdict,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShippedPathActualOutcome {
    ExecuteSuccess,
    NormalizationFailure,
    ParseFailure,
    OtherFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShippedPathVerdict {
    Pass,
    Fail,
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsShippedPathEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub js_count: u64,
    pub ts_count: u64,
    pub evidence: Vec<ShippedPathSpecimenEvidence>,
}

impl TsShippedPathEvidenceInventory {
    pub fn contract_satisfied(&self) -> bool {
        self.fail_count == 0 && self.specimen_count > 0
    }
}

// ---------------------------------------------------------------------------
// Manifest & Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShippedPathEvidenceRunManifest {
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
    pub artifact_paths: ShippedPathEvidenceArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShippedPathEvidenceArtifactPaths {
    pub evidence_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShippedPathEvidenceEvent {
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
pub struct ShippedPathBundleArtifacts {
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// Returns the diagnostic corpus of shipped-path specimens.
pub fn shipped_path_corpus() -> Vec<ShippedPathSpecimen> {
    vec![
        // -- JavaScript specimens (no normalization expected) --
        ShippedPathSpecimen {
            specimen_id: "js_literal".into(),
            description: "Plain JS numeric literal".into(),
            source: "42".into(),
            source_file: None,
            expected_language: SourceLanguage::JavaScript,
            expected_normalization: false,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "js_addition".into(),
            description: "JS addition expression".into(),
            source: "1 + 2".into(),
            source_file: Some("app.js".into()),
            expected_language: SourceLanguage::JavaScript,
            expected_normalization: false,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "js_var_decl".into(),
            description: "JS variable declaration".into(),
            source: "var x = 10".into(),
            source_file: Some("index.js".into()),
            expected_language: SourceLanguage::JavaScript,
            expected_normalization: false,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "js_function".into(),
            description: "JS function declaration".into(),
            source: "function f() { return 1 }".into(),
            source_file: None,
            expected_language: SourceLanguage::JavaScript,
            expected_normalization: false,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "js_object_literal".into(),
            description: "JS object literal".into(),
            source: "var o = { a: 1, b: 2 }".into(),
            source_file: None,
            expected_language: SourceLanguage::JavaScript,
            expected_normalization: false,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        // -- TypeScript specimens (normalization expected) --
        ShippedPathSpecimen {
            specimen_id: "ts_type_annotation_by_ext".into(),
            description: "TS detected by .ts extension, type annotation stripped".into(),
            source: "var x: number = 42".into(),
            source_file: Some("app.ts".into()),
            expected_language: SourceLanguage::TypeScript,
            expected_normalization: true,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "ts_type_annotation_by_content".into(),
            description: "TS detected by content heuristic (interface keyword)".into(),
            source: "interface Foo {} \nvar x = 1".into(),
            source_file: None,
            expected_language: SourceLanguage::TypeScript,
            expected_normalization: true,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "ts_type_only_import".into(),
            description: "TS type-only import elided during normalization".into(),
            source: "import type { Foo } from './foo'\nvar x = 1".into(),
            source_file: Some("mod.ts".into()),
            expected_language: SourceLanguage::TypeScript,
            expected_normalization: true,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "ts_return_typed_by_ext".into(),
            description: "TS function return type annotation stripped via .ts detection".into(),
            source: "function f(): number { return 42 }".into(),
            source_file: Some("typed.ts".into()),
            expected_language: SourceLanguage::TypeScript,
            expected_normalization: true,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "ts_const_assertion".into(),
            description: "TS const assertion stripped".into(),
            source: "var x = [1, 2, 3] as const".into(),
            source_file: Some("data.ts".into()),
            expected_language: SourceLanguage::TypeScript,
            expected_normalization: true,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "ts_definite_assignment".into(),
            description: "TS definite assignment assertion normalized".into(),
            source: "var x!: string\nx = 'hello'".into(),
            source_file: Some("assign.ts".into()),
            expected_language: SourceLanguage::TypeScript,
            expected_normalization: true,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "ts_mts_extension".into(),
            description: "TS detected by .mts extension".into(),
            source: "var x: number = 10".into(),
            source_file: Some("lib.mts".into()),
            expected_language: SourceLanguage::TypeScript,
            expected_normalization: true,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "ts_cts_extension".into(),
            description: "TS detected by .cts extension".into(),
            source: "var y: boolean = true".into(),
            source_file: Some("util.cts".into()),
            expected_language: SourceLanguage::TypeScript,
            expected_normalization: true,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        // -- Edge cases --
        ShippedPathSpecimen {
            specimen_id: "js_no_source_file".into(),
            description: "JS with no source_file defaults to JS detection".into(),
            source: "1 + 1".into(),
            source_file: None,
            expected_language: SourceLanguage::JavaScript,
            expected_normalization: false,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
        ShippedPathSpecimen {
            specimen_id: "ts_tsx_extension".into(),
            description: "TSX detected by .tsx extension".into(),
            source: "var x: number = 5".into(),
            source_file: Some("component.tsx".into()),
            expected_language: SourceLanguage::TypeScript,
            expected_normalization: true,
            expected_outcome: ShippedPathExpectedOutcome::ExecuteSuccess,
        },
    ]
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Run all specimens through the orchestrator and collect evidence.
pub fn run_shipped_path_corpus() -> TsShippedPathEvidenceInventory {
    let corpus = shipped_path_corpus();
    let mut evidence = Vec::with_capacity(corpus.len());
    let mut pass_count: u64 = 0;
    let mut fail_count: u64 = 0;
    let mut js_count: u64 = 0;
    let mut ts_count: u64 = 0;

    for specimen in &corpus {
        let ev = run_single_specimen(specimen);
        match ev.expected_language {
            SourceLanguage::JavaScript => js_count += 1,
            SourceLanguage::TypeScript => ts_count += 1,
        }
        if ev.verdict == ShippedPathVerdict::Pass {
            pass_count += 1;
        } else {
            fail_count += 1;
        }
        evidence.push(ev);
    }

    TsShippedPathEvidenceInventory {
        schema_version: TS_SHIPPED_PATH_SCHEMA_VERSION.to_string(),
        component: TS_SHIPPED_PATH_COMPONENT.to_string(),
        specimen_count: corpus.len() as u64,
        pass_count,
        fail_count,
        js_count,
        ts_count,
        evidence,
    }
}

fn run_single_specimen(specimen: &ShippedPathSpecimen) -> ShippedPathSpecimenEvidence {
    let mut orch = ExecutionOrchestrator::new(OrchestratorConfig::default());

    let package = ExtensionPackage {
        extension_id: format!("shipped-path-{}", specimen.specimen_id),
        source: specimen.source.clone(),
        source_file: specimen.source_file.clone(),
        capabilities: vec![],
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };

    let (actual_outcome, actual_language, actual_normalization, error_detail) =
        match orch.execute(&package) {
            Ok(result) => (
                ShippedPathActualOutcome::ExecuteSuccess,
                result.source_ingestion.source_language,
                result.source_ingestion.normalization_applied,
                None,
            ),
            Err(OrchestratorError::TsNormalization(e)) => (
                ShippedPathActualOutcome::NormalizationFailure,
                SourceLanguage::TypeScript,
                false,
                Some(e.to_string()),
            ),
            Err(OrchestratorError::Parse(e)) => (
                ShippedPathActualOutcome::ParseFailure,
                // Language detection happens before parse, so we infer from
                // the specimen's expectation.
                specimen.expected_language,
                specimen.expected_normalization,
                Some(e.to_string()),
            ),
            Err(other) => (
                ShippedPathActualOutcome::OtherFailure,
                specimen.expected_language,
                false,
                Some(other.to_string()),
            ),
        };

    let outcome_matches = matches!(
        (specimen.expected_outcome, actual_outcome),
        (ShippedPathExpectedOutcome::ExecuteSuccess, ShippedPathActualOutcome::ExecuteSuccess)
            | (
                ShippedPathExpectedOutcome::NormalizationFailure,
                ShippedPathActualOutcome::NormalizationFailure,
            )
            | (ShippedPathExpectedOutcome::ParseFailure, ShippedPathActualOutcome::ParseFailure)
    );

    let language_matches = specimen.expected_language == actual_language;
    let normalization_matches = specimen.expected_normalization == actual_normalization;

    let verdict = if outcome_matches && language_matches && normalization_matches {
        ShippedPathVerdict::Pass
    } else {
        ShippedPathVerdict::Fail
    };

    ShippedPathSpecimenEvidence {
        specimen_id: specimen.specimen_id.clone(),
        expected_language: specimen.expected_language,
        actual_language,
        expected_normalization: specimen.expected_normalization,
        actual_normalization,
        expected_outcome: specimen.expected_outcome,
        actual_outcome,
        verdict,
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
pub fn write_shipped_path_evidence_bundle(
    output_dir: &Path,
    commands: &[String],
) -> Result<ShippedPathBundleArtifacts, std::io::Error> {
    fs::create_dir_all(output_dir)?;

    let inv = run_shipped_path_corpus();
    let inv_json = serde_json::to_string_pretty(&inv)
        .map_err(std::io::Error::other)?;
    let inventory_hash = sha256_hex(inv_json.as_bytes());

    let inv_path = output_dir.join("ts_shipped_path_evidence_inventory.json");
    fs::write(&inv_path, &inv_json)?;

    // Events
    let mut events = Vec::new();
    events.push(ShippedPathEvidenceEvent {
        schema_version: TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION.into(),
        component: TS_SHIPPED_PATH_COMPONENT.into(),
        event: "shipped_path_evidence_run_started".into(),
        policy_id: TS_SHIPPED_PATH_POLICY_ID.into(),
        specimen_id: None,
        verdict: None,
        detail: Some(format!("specimen_count={}", inv.specimen_count)),
    });
    for ev in &inv.evidence {
        events.push(ShippedPathEvidenceEvent {
            schema_version: TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION.into(),
            component: TS_SHIPPED_PATH_COMPONENT.into(),
            event: "shipped_path_specimen_evaluated".into(),
            policy_id: TS_SHIPPED_PATH_POLICY_ID.into(),
            specimen_id: Some(ev.specimen_id.clone()),
            verdict: Some(format!("{:?}", ev.verdict)),
            detail: ev.error_detail.clone(),
        });
    }
    events.push(ShippedPathEvidenceEvent {
        schema_version: TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION.into(),
        component: TS_SHIPPED_PATH_COMPONENT.into(),
        event: "shipped_path_evidence_run_completed".into(),
        policy_id: TS_SHIPPED_PATH_POLICY_ID.into(),
        specimen_id: None,
        verdict: Some(if inv.contract_satisfied() {
            "pass"
        } else {
            "fail"
        }
        .into()),
        detail: Some(format!(
            "pass={} fail={} js={} ts={}",
            inv.pass_count, inv.fail_count, inv.js_count, inv.ts_count
        )),
    });

    let events_path = output_dir.join("ts_shipped_path_evidence_events.jsonl");
    let events_jsonl: String = events
        .iter()
        .map(|e| serde_json::to_string(e).expect("event serialization"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&events_path, &events_jsonl)?;

    // Commands
    let commands_path = output_dir.join("ts_shipped_path_evidence_commands.txt");
    fs::write(&commands_path, commands.join("\n"))?;

    // Manifest
    let artifact_paths = ShippedPathEvidenceArtifactPaths {
        evidence_inventory: "ts_shipped_path_evidence_inventory.json".into(),
        run_manifest: "ts_shipped_path_evidence_manifest.json".into(),
        events_jsonl: "ts_shipped_path_evidence_events.jsonl".into(),
        commands_txt: "ts_shipped_path_evidence_commands.txt".into(),
    };
    let manifest = ShippedPathEvidenceRunManifest {
        schema_version: TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION.into(),
        component: TS_SHIPPED_PATH_COMPONENT.into(),
        trace_id: format!("shipped-path-evidence-{}", inventory_hash.get(..8).unwrap_or("?")),
        decision_id: format!("shipped-path-decision-{}", inventory_hash.get(..8).unwrap_or("?")),
        policy_id: TS_SHIPPED_PATH_POLICY_ID.into(),
        inventory_hash: inventory_hash.clone(),
        specimen_count: inv.specimen_count,
        pass_count: inv.pass_count,
        fail_count: inv.fail_count,
        contract_satisfied: inv.contract_satisfied(),
        artifact_paths,
    };
    let manifest_path = output_dir.join("ts_shipped_path_evidence_manifest.json");
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(std::io::Error::other)?;
    fs::write(&manifest_path, &manifest_json)?;

    Ok(ShippedPathBundleArtifacts {
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
        assert!(!shipped_path_corpus().is_empty());
    }

    #[test]
    fn corpus_has_js_and_ts() {
        let corpus = shipped_path_corpus();
        assert!(corpus.iter().any(|s| s.expected_language == SourceLanguage::JavaScript));
        assert!(corpus.iter().any(|s| s.expected_language == SourceLanguage::TypeScript));
    }

    #[test]
    fn corpus_ids_unique() {
        let corpus = shipped_path_corpus();
        let ids: std::collections::BTreeSet<&str> =
            corpus.iter().map(|s| s.specimen_id.as_str()).collect();
        assert_eq!(ids.len(), corpus.len());
    }

    #[test]
    fn corpus_has_normalization_and_passthrough() {
        let corpus = shipped_path_corpus();
        assert!(corpus.iter().any(|s| s.expected_normalization));
        assert!(corpus.iter().any(|s| !s.expected_normalization));
    }

    #[test]
    fn all_specimens_pass() {
        let inv = run_shipped_path_corpus();
        for ev in &inv.evidence {
            assert_eq!(
                ev.verdict,
                ShippedPathVerdict::Pass,
                "specimen {} failed: expected_lang={:?} actual_lang={:?} \
                 expected_norm={} actual_norm={} expected_outcome={:?} \
                 actual_outcome={:?} error={:?}",
                ev.specimen_id,
                ev.expected_language,
                ev.actual_language,
                ev.expected_normalization,
                ev.actual_normalization,
                ev.expected_outcome,
                ev.actual_outcome,
                ev.error_detail,
            );
        }
    }

    #[test]
    fn contract_satisfied() {
        let inv = run_shipped_path_corpus();
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn counts_consistent() {
        let inv = run_shipped_path_corpus();
        assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
        assert_eq!(inv.js_count + inv.ts_count, inv.specimen_count);
        assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
    }

    #[test]
    fn js_specimens_not_normalized() {
        let inv = run_shipped_path_corpus();
        for ev in &inv.evidence {
            if ev.expected_language == SourceLanguage::JavaScript {
                assert!(!ev.actual_normalization, "JS specimen {} was normalized", ev.specimen_id);
            }
        }
    }

    #[test]
    fn ts_specimens_are_normalized() {
        let inv = run_shipped_path_corpus();
        for ev in &inv.evidence {
            if ev.expected_language == SourceLanguage::TypeScript
                && ev.expected_outcome == ShippedPathExpectedOutcome::ExecuteSuccess
            {
                assert!(
                    ev.actual_normalization,
                    "TS specimen {} was not normalized",
                    ev.specimen_id
                );
            }
        }
    }

    #[test]
    fn schema_constants_non_empty() {
        assert!(!TS_SHIPPED_PATH_SCHEMA_VERSION.is_empty());
        assert!(!TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!TS_SHIPPED_PATH_COMPONENT.is_empty());
        assert!(!TS_SHIPPED_PATH_POLICY_ID.is_empty());
    }

    #[test]
    fn schema_versions_prefixed() {
        assert!(TS_SHIPPED_PATH_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn inventory_serde_roundtrip() {
        let inv = run_shipped_path_corpus();
        let json = serde_json::to_string(&inv).unwrap();
        let back: TsShippedPathEvidenceInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    #[test]
    fn specimen_evidence_serde_roundtrip() {
        let inv = run_shipped_path_corpus();
        for ev in &inv.evidence {
            let json = serde_json::to_string(ev).unwrap();
            let back: ShippedPathSpecimenEvidence = serde_json::from_str(&json).unwrap();
            assert_eq!(*ev, back);
        }
    }

    #[test]
    fn corpus_specimen_serde_roundtrip() {
        for s in &shipped_path_corpus() {
            let json = serde_json::to_string(s).unwrap();
            let back: ShippedPathSpecimen = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = ShippedPathEvidenceRunManifest {
            schema_version: TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION.into(),
            component: TS_SHIPPED_PATH_COMPONENT.into(),
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: TS_SHIPPED_PATH_POLICY_ID.into(),
            inventory_hash: "h".into(),
            specimen_count: 15,
            pass_count: 15,
            fail_count: 0,
            contract_satisfied: true,
            artifact_paths: ShippedPathEvidenceArtifactPaths {
                evidence_inventory: "a.json".into(),
                run_manifest: "b.json".into(),
                events_jsonl: "c.jsonl".into(),
                commands_txt: "d.txt".into(),
            },
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: ShippedPathEvidenceRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn event_serde_roundtrip() {
        let ev = ShippedPathEvidenceEvent {
            schema_version: TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION.into(),
            component: TS_SHIPPED_PATH_COMPONENT.into(),
            event: "test".into(),
            policy_id: TS_SHIPPED_PATH_POLICY_ID.into(),
            specimen_id: Some("s".into()),
            verdict: Some("pass".into()),
            detail: Some("d".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: ShippedPathEvidenceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn corpus_deterministic() {
        let inv1 = run_shipped_path_corpus();
        let inv2 = run_shipped_path_corpus();
        assert_eq!(inv1, inv2);
    }

    #[test]
    fn language_detection_correct_for_all_specimens() {
        let inv = run_shipped_path_corpus();
        for ev in &inv.evidence {
            assert_eq!(
                ev.expected_language, ev.actual_language,
                "language mismatch for {}",
                ev.specimen_id
            );
        }
    }

    #[test]
    fn normalization_flag_correct_for_all_specimens() {
        let inv = run_shipped_path_corpus();
        for ev in &inv.evidence {
            if ev.expected_outcome == ShippedPathExpectedOutcome::ExecuteSuccess {
                assert_eq!(
                    ev.expected_normalization, ev.actual_normalization,
                    "normalization flag mismatch for {}",
                    ev.specimen_id
                );
            }
        }
    }

    #[test]
    fn all_schema_versions_are_distinct() {
        let versions = [
            TS_SHIPPED_PATH_SCHEMA_VERSION,
            TS_SHIPPED_PATH_MANIFEST_SCHEMA_VERSION,
            TS_SHIPPED_PATH_EVENT_SCHEMA_VERSION,
        ];
        let set: std::collections::BTreeSet<&str> = versions.iter().copied().collect();
        assert_eq!(set.len(), versions.len(), "schema versions must be distinct");
    }

    #[test]
    fn contract_not_satisfied_when_fail_count_nonzero() {
        let inv = TsShippedPathEvidenceInventory {
            schema_version: TS_SHIPPED_PATH_SCHEMA_VERSION.into(),
            component: TS_SHIPPED_PATH_COMPONENT.into(),
            specimen_count: 5,
            pass_count: 4,
            fail_count: 1,
            js_count: 2,
            ts_count: 3,
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn contract_not_satisfied_when_zero_specimens() {
        let inv = TsShippedPathEvidenceInventory {
            schema_version: TS_SHIPPED_PATH_SCHEMA_VERSION.into(),
            component: TS_SHIPPED_PATH_COMPONENT.into(),
            specimen_count: 0,
            pass_count: 0,
            fail_count: 0,
            js_count: 0,
            ts_count: 0,
            evidence: vec![],
        };
        assert!(!inv.contract_satisfied());
    }

    #[test]
    fn expected_outcome_serde_roundtrip() {
        for variant in [
            ShippedPathExpectedOutcome::ExecuteSuccess,
            ShippedPathExpectedOutcome::NormalizationFailure,
            ShippedPathExpectedOutcome::ParseFailure,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ShippedPathExpectedOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn actual_outcome_serde_roundtrip() {
        for variant in [
            ShippedPathActualOutcome::ExecuteSuccess,
            ShippedPathActualOutcome::NormalizationFailure,
            ShippedPathActualOutcome::ParseFailure,
            ShippedPathActualOutcome::OtherFailure,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ShippedPathActualOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for variant in [ShippedPathVerdict::Pass, ShippedPathVerdict::Fail] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: ShippedPathVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    #[test]
    fn sha256_hex_deterministic() {
        let a = sha256_hex(b"hello world");
        let b = sha256_hex(b"hello world");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "SHA-256 hex should be 64 chars");
    }

    #[test]
    fn sha256_hex_distinct_for_different_inputs() {
        let a = sha256_hex(b"input-a");
        let b = sha256_hex(b"input-b");
        assert_ne!(a, b);
    }

    #[test]
    fn corpus_has_multiple_source_file_extensions() {
        let corpus = shipped_path_corpus();
        let extensions: std::collections::BTreeSet<String> = corpus
            .iter()
            .filter_map(|s| {
                s.source_file
                    .as_ref()
                    .and_then(|f| f.rsplit('.').next().map(|e| e.to_string()))
            })
            .collect();
        // Should include at least: js, ts, mts, cts, tsx
        assert!(
            extensions.len() >= 4,
            "expected ≥4 file extensions, got {:?}",
            extensions
        );
    }
}
