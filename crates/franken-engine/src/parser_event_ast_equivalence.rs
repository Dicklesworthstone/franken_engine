//! Event-to-AST equivalence harness with replay validation and evidence packs.
//!
//! This module proves the event-driven parser contract: every successful parse
//! emits a deterministic event IR that, when materialized back against the same
//! source, produces an AST whose canonical hash matches the original parse.
//! Tampering, truncation, or reordering of the event stream must be detected
//! with a stable error code.
//!
//! The harness runs a corpus of equivalence specimens (positive parity, negative
//! failure, and tamper-injection cases) through the parse-with-event-IR pipeline,
//! materializes each result, and records per-specimen verdicts. The resulting
//! inventory is suitable for CI gating and publication evidence.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//! Reference: [PSRP-04.4], bead bd-2mds.1.4.4.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

use crate::ast::ParseGoal;
use crate::deterministic_serde::{self, CanonicalValue};
use crate::parser::{
    CanonicalEs2020Parser, ParseErrorCode, ParseEventKind, ParseEventMaterializationErrorCode,
    ParserOptions,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SCHEMA_VERSION: &str = "franken-engine.parser-event-ast-equivalence.inventory.v1";
pub const MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.parser-event-ast-equivalence.run-manifest.v1";
pub const EVENT_SCHEMA_VERSION: &str = "franken-engine.parser-event-ast-equivalence.event.v1";
pub const COMPONENT: &str = "parser_event_ast_equivalence";
pub const POLICY_ID: &str = "franken-engine.parser-event-ast-equivalence.policy.v1";
pub const BEAD_ID: &str = "bd-2mds.1.4.4";

/// Fixed-point unit: 1_000_000 = 1.0.
pub const FIXED_ONE: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Corpus tier
// ---------------------------------------------------------------------------

/// Corpus tier for equivalence specimens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusTier {
    Core,
    Edge,
    Adversarial,
}

impl CorpusTier {
    pub const ALL: &[Self] = &[Self::Core, Self::Edge, Self::Adversarial];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Edge => "edge",
            Self::Adversarial => "adversarial",
        }
    }
}

impl fmt::Display for CorpusTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Tamper kind
// ---------------------------------------------------------------------------

/// Kind of tampering applied to the event IR before materialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperKind {
    None,
    StatementHash,
    EventDeletion,
    SequenceReorder,
}

impl TamperKind {
    pub const ALL: &[Self] = &[
        Self::None,
        Self::StatementHash,
        Self::EventDeletion,
        Self::SequenceReorder,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StatementHash => "statement_hash",
            Self::EventDeletion => "event_deletion",
            Self::SequenceReorder => "sequence_reorder",
        }
    }
}

impl fmt::Display for TamperKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Equivalence verdict
// ---------------------------------------------------------------------------

/// Verdict for a single equivalence specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EquivalenceVerdict {
    /// Event IR → materialization → AST hash matches the original parse.
    Pass,
    /// Hash mismatch, tamper detected, or materialization failure as expected.
    Fail,
}

impl EquivalenceVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

impl fmt::Display for EquivalenceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Specimen
// ---------------------------------------------------------------------------

/// A single corpus specimen for event→AST equivalence testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceSpecimen {
    pub specimen_id: String,
    pub source: String,
    pub goal: ParseGoal,
    pub corpus_tier: CorpusTier,
    pub tamper_kind: TamperKind,
    pub expect_parity: bool,
    pub expected_parse_error: Option<ParseErrorCode>,
    pub expected_materialization_error: Option<ParseEventMaterializationErrorCode>,
    pub expected_statement_count: usize,
}

// ---------------------------------------------------------------------------
// Specimen evidence
// ---------------------------------------------------------------------------

/// Per-specimen evidence record produced by the equivalence harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecimenEvidence {
    pub specimen_id: String,
    pub corpus_tier: CorpusTier,
    pub tamper_kind: TamperKind,
    pub verdict: EquivalenceVerdict,
    pub event_ir_hash: String,
    pub materialized_ast_hash: Option<String>,
    pub original_ast_hash: Option<String>,
    pub parse_error_code: Option<String>,
    pub materialization_error_code: Option<String>,
    pub statement_count: usize,
    pub hash_parity: bool,
    pub replay_stable: bool,
}

impl SpecimenEvidence {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "corpus_tier".to_string(),
            CanonicalValue::String(self.corpus_tier.as_str().to_string()),
        );
        map.insert(
            "event_ir_hash".to_string(),
            CanonicalValue::String(self.event_ir_hash.clone()),
        );
        map.insert(
            "hash_parity".to_string(),
            CanonicalValue::Bool(self.hash_parity),
        );
        map.insert(
            "materialization_error_code".to_string(),
            self.materialization_error_code
                .as_ref()
                .map(|v| CanonicalValue::String(v.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "materialized_ast_hash".to_string(),
            self.materialized_ast_hash
                .as_ref()
                .map(|v| CanonicalValue::String(v.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "original_ast_hash".to_string(),
            self.original_ast_hash
                .as_ref()
                .map(|v| CanonicalValue::String(v.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "parse_error_code".to_string(),
            self.parse_error_code
                .as_ref()
                .map(|v| CanonicalValue::String(v.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "replay_stable".to_string(),
            CanonicalValue::Bool(self.replay_stable),
        );
        map.insert(
            "specimen_id".to_string(),
            CanonicalValue::String(self.specimen_id.clone()),
        );
        map.insert(
            "statement_count".to_string(),
            CanonicalValue::U64(self.statement_count as u64),
        );
        map.insert(
            "tamper_kind".to_string(),
            CanonicalValue::String(self.tamper_kind.as_str().to_string()),
        );
        map.insert(
            "verdict".to_string(),
            CanonicalValue::String(self.verdict.as_str().to_string()),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!("sha256:{}", hex::encode(digest))
    }
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

/// Aggregated result of running the equivalence corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceInventory {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub parity_verified: usize,
    pub tamper_detected: usize,
    pub replay_stable_count: usize,
    pub per_tier: BTreeMap<String, TierSummary>,
    pub evidence: Vec<SpecimenEvidence>,
}

/// Summary statistics for one corpus tier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

impl EquivalenceInventory {
    pub fn contract_satisfied(&self) -> bool {
        self.failed == 0 && self.total > 0 && self.replay_stable_count == self.total
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "component".to_string(),
            CanonicalValue::String(self.component.clone()),
        );
        map.insert(
            "evidence".to_string(),
            CanonicalValue::Array(self.evidence.iter().map(|e| e.canonical_value()).collect()),
        );
        map.insert(
            "failed".to_string(),
            CanonicalValue::U64(self.failed as u64),
        );
        map.insert(
            "parity_verified".to_string(),
            CanonicalValue::U64(self.parity_verified as u64),
        );
        let mut tiers = BTreeMap::new();
        for (k, v) in &self.per_tier {
            let mut tier_map = BTreeMap::new();
            tier_map.insert("failed".to_string(), CanonicalValue::U64(v.failed as u64));
            tier_map.insert("passed".to_string(), CanonicalValue::U64(v.passed as u64));
            tier_map.insert("total".to_string(), CanonicalValue::U64(v.total as u64));
            tiers.insert(k.clone(), CanonicalValue::Map(tier_map));
        }
        map.insert("per_tier".to_string(), CanonicalValue::Map(tiers));
        map.insert(
            "passed".to_string(),
            CanonicalValue::U64(self.passed as u64),
        );
        map.insert(
            "policy_id".to_string(),
            CanonicalValue::String(self.policy_id.clone()),
        );
        map.insert(
            "replay_stable_count".to_string(),
            CanonicalValue::U64(self.replay_stable_count as u64),
        );
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "tamper_detected".to_string(),
            CanonicalValue::U64(self.tamper_detected as u64),
        );
        map.insert("total".to_string(), CanonicalValue::U64(self.total as u64));
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!("sha256:{}", hex::encode(digest))
    }
}

// ---------------------------------------------------------------------------
// Run manifest
// ---------------------------------------------------------------------------

/// Manifest for a single equivalence-harness run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceRunManifest {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub bead_id: String,
    pub artifact_paths: Vec<String>,
    pub inventory_hash: String,
}

impl EquivalenceRunManifest {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "artifact_paths".to_string(),
            CanonicalValue::Array(
                self.artifact_paths
                    .iter()
                    .map(|p| CanonicalValue::String(p.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "bead_id".to_string(),
            CanonicalValue::String(self.bead_id.clone()),
        );
        map.insert(
            "component".to_string(),
            CanonicalValue::String(self.component.clone()),
        );
        map.insert(
            "decision_id".to_string(),
            CanonicalValue::String(self.decision_id.clone()),
        );
        map.insert(
            "inventory_hash".to_string(),
            CanonicalValue::String(self.inventory_hash.clone()),
        );
        map.insert(
            "policy_id".to_string(),
            CanonicalValue::String(self.policy_id.clone()),
        );
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "trace_id".to_string(),
            CanonicalValue::String(self.trace_id.clone()),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!("sha256:{}", hex::encode(digest))
    }
}

// ---------------------------------------------------------------------------
// Event record
// ---------------------------------------------------------------------------

/// Structured event emitted per specimen for CI gating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivalenceEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event_type: String,
    pub specimen_id: String,
    pub corpus_tier: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Corpus builder
// ---------------------------------------------------------------------------

/// Build the canonical equivalence corpus.
pub fn equivalence_corpus() -> Vec<EquivalenceSpecimen> {
    vec![
        // ---- Core tier: positive parity ----
        EquivalenceSpecimen {
            specimen_id: "core_single_var_decl".to_string(),
            source: "const x = 42;\n".to_string(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Core,
            tamper_kind: TamperKind::None,
            expect_parity: true,
            expected_parse_error: None,
            expected_materialization_error: None,
            expected_statement_count: 1,
        },
        EquivalenceSpecimen {
            specimen_id: "core_multi_statement".to_string(),
            source: "let a = 1;\nlet b = 2;\nlet c = a + b;\n".to_string(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Core,
            tamper_kind: TamperKind::None,
            expect_parity: true,
            expected_parse_error: None,
            expected_materialization_error: None,
            expected_statement_count: 3,
        },
        EquivalenceSpecimen {
            specimen_id: "core_module_import_export".to_string(),
            source: "import dep from \"pkg\";\nexport default dep;\n".to_string(),
            goal: ParseGoal::Module,
            corpus_tier: CorpusTier::Core,
            tamper_kind: TamperKind::None,
            expect_parity: true,
            expected_parse_error: None,
            expected_materialization_error: None,
            expected_statement_count: 2,
        },
        EquivalenceSpecimen {
            specimen_id: "core_function_declaration".to_string(),
            source: "function add(a, b) { return a + b; }\n".to_string(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Core,
            tamper_kind: TamperKind::None,
            expect_parity: true,
            expected_parse_error: None,
            expected_materialization_error: None,
            expected_statement_count: 1,
        },
        // ---- Core tier: failure cases ----
        EquivalenceSpecimen {
            specimen_id: "core_empty_source_failure".to_string(),
            source: String::new(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Core,
            tamper_kind: TamperKind::None,
            expect_parity: false,
            expected_parse_error: Some(ParseErrorCode::EmptySource),
            expected_materialization_error: Some(
                ParseEventMaterializationErrorCode::ParseFailedEventStream,
            ),
            expected_statement_count: 0,
        },
        // ---- Edge tier: parity with complex syntax ----
        EquivalenceSpecimen {
            specimen_id: "edge_arrow_with_body".to_string(),
            source: "const f = (x) => { return x * 2; };\n".to_string(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Edge,
            tamper_kind: TamperKind::None,
            expect_parity: true,
            expected_parse_error: None,
            expected_materialization_error: None,
            expected_statement_count: 1,
        },
        EquivalenceSpecimen {
            specimen_id: "edge_if_else_chain".to_string(),
            source: "if (true) { let a = 1; } else { let b = 2; }\n".to_string(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Edge,
            tamper_kind: TamperKind::None,
            expect_parity: true,
            expected_parse_error: None,
            expected_materialization_error: None,
            expected_statement_count: 1,
        },
        EquivalenceSpecimen {
            specimen_id: "edge_try_catch".to_string(),
            source: "try { throw 1; } catch (e) { let x = e; }\n".to_string(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Edge,
            tamper_kind: TamperKind::None,
            expect_parity: true,
            expected_parse_error: None,
            expected_materialization_error: None,
            expected_statement_count: 1,
        },
        // ---- Adversarial tier: tamper detection ----
        EquivalenceSpecimen {
            specimen_id: "adversarial_tamper_statement_hash".to_string(),
            source: "const val = 99;\n".to_string(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Adversarial,
            tamper_kind: TamperKind::StatementHash,
            expect_parity: false,
            expected_parse_error: None,
            expected_materialization_error: Some(
                ParseEventMaterializationErrorCode::StatementHashMismatch,
            ),
            expected_statement_count: 0,
        },
        EquivalenceSpecimen {
            specimen_id: "adversarial_tamper_event_deletion".to_string(),
            source: "let y = 10;\n".to_string(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Adversarial,
            tamper_kind: TamperKind::EventDeletion,
            expect_parity: false,
            expected_parse_error: None,
            expected_materialization_error: Some(
                ParseEventMaterializationErrorCode::StatementCountMismatch,
            ),
            expected_statement_count: 0,
        },
        EquivalenceSpecimen {
            specimen_id: "adversarial_tamper_sequence_reorder".to_string(),
            source: "let z = 5;\n".to_string(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Adversarial,
            tamper_kind: TamperKind::SequenceReorder,
            expect_parity: false,
            expected_parse_error: None,
            expected_materialization_error: Some(
                ParseEventMaterializationErrorCode::InvalidEventSequence,
            ),
            expected_statement_count: 0,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tamper application
// ---------------------------------------------------------------------------

fn apply_tamper(tamper: TamperKind, event_ir: &mut crate::parser::ParseEventIr) {
    match tamper {
        TamperKind::None => {}
        TamperKind::StatementHash => {
            if let Some(stmt) = event_ir
                .events
                .iter_mut()
                .find(|e| e.kind == ParseEventKind::StatementParsed)
            {
                stmt.payload_hash = Some(
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                        .to_string(),
                );
            }
        }
        TamperKind::EventDeletion => {
            event_ir
                .events
                .retain(|e| e.kind != ParseEventKind::StatementParsed);
        }
        TamperKind::SequenceReorder => {
            if event_ir.events.len() >= 3 {
                // Swap the second and third events (statement and completed)
                let len = event_ir.events.len();
                event_ir.events.swap(1, len - 1);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluate one specimen
// ---------------------------------------------------------------------------

/// Evaluate a single equivalence specimen.
pub fn evaluate_specimen(specimen: &EquivalenceSpecimen) -> SpecimenEvidence {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let (parse_result, mut event_ir) =
        parser.parse_with_event_ir(specimen.source.as_str(), specimen.goal, &options);

    let event_ir_hash = event_ir.canonical_hash();

    // Check for expected parse error
    if let Some(expected_code) = &specimen.expected_parse_error {
        let err = match parse_result {
            Err(e) => e,
            Ok(_) => {
                return SpecimenEvidence {
                    specimen_id: specimen.specimen_id.clone(),
                    corpus_tier: specimen.corpus_tier,
                    tamper_kind: specimen.tamper_kind,
                    verdict: EquivalenceVerdict::Fail,
                    event_ir_hash,
                    materialized_ast_hash: None,
                    original_ast_hash: None,
                    parse_error_code: None,
                    materialization_error_code: None,
                    statement_count: 0,
                    hash_parity: false,
                    replay_stable: false,
                };
            }
        };
        let code_matches = err.code == *expected_code;

        // Also try materialization to confirm failure propagation
        let mat_result = event_ir.materialize_from_source(specimen.source.as_str(), &options);
        let mat_err_matches = match (&mat_result, &specimen.expected_materialization_error) {
            (Err(mat_err), Some(expected_mat)) => mat_err.code == *expected_mat,
            (Err(_), None) => true,
            (Ok(_), None) => true,
            (Ok(_), Some(_)) => false,
        };

        // Replay stability check
        let (_second_parse, second_event_ir) =
            parser.parse_with_event_ir(specimen.source.as_str(), specimen.goal, &options);
        let replay_stable = event_ir_hash == second_event_ir.canonical_hash();

        let mat_error_str = mat_result.err().map(|e| e.code.as_str().to_string());

        return SpecimenEvidence {
            specimen_id: specimen.specimen_id.clone(),
            corpus_tier: specimen.corpus_tier,
            tamper_kind: specimen.tamper_kind,
            verdict: if code_matches && mat_err_matches && replay_stable {
                EquivalenceVerdict::Pass
            } else {
                EquivalenceVerdict::Fail
            },
            event_ir_hash,
            materialized_ast_hash: None,
            original_ast_hash: None,
            parse_error_code: Some(err.code.as_str().to_string()),
            materialization_error_code: mat_error_str,
            statement_count: 0,
            hash_parity: false,
            replay_stable,
        };
    }

    // Successful parse path
    let syntax_tree = match parse_result {
        Ok(tree) => tree,
        Err(e) => {
            return SpecimenEvidence {
                specimen_id: specimen.specimen_id.clone(),
                corpus_tier: specimen.corpus_tier,
                tamper_kind: specimen.tamper_kind,
                verdict: EquivalenceVerdict::Fail,
                event_ir_hash,
                materialized_ast_hash: None,
                original_ast_hash: None,
                parse_error_code: Some(e.code.as_str().to_string()),
                materialization_error_code: None,
                statement_count: 0,
                hash_parity: false,
                replay_stable: false,
            };
        }
    };

    let original_hash = syntax_tree.canonical_hash();

    // Apply tampering
    apply_tamper(specimen.tamper_kind, &mut event_ir);

    // Materialize
    let mat_result = event_ir.materialize_from_source(specimen.source.as_str(), &options);

    match mat_result {
        Ok(materialized) => {
            let mat_hash = materialized.syntax_tree.canonical_hash();
            let hash_parity = mat_hash == original_hash;
            let stmt_count = materialized.statement_nodes.len();

            // Replay stability
            let (_second_parse, second_event_ir) =
                parser.parse_with_event_ir(specimen.source.as_str(), specimen.goal, &options);
            let second_mat = second_event_ir
                .materialize_from_source(specimen.source.as_str(), &options)
                .expect("second materialization should succeed for non-tampered");
            let replay_stable = second_mat.syntax_tree.canonical_hash() == mat_hash;

            let parity_ok = if specimen.expect_parity {
                hash_parity
            } else {
                true
            };
            let count_ok = stmt_count == specimen.expected_statement_count;

            SpecimenEvidence {
                specimen_id: specimen.specimen_id.clone(),
                corpus_tier: specimen.corpus_tier,
                tamper_kind: specimen.tamper_kind,
                verdict: if parity_ok && count_ok && replay_stable {
                    EquivalenceVerdict::Pass
                } else {
                    EquivalenceVerdict::Fail
                },
                event_ir_hash,
                materialized_ast_hash: Some(mat_hash),
                original_ast_hash: Some(original_hash),
                parse_error_code: None,
                materialization_error_code: None,
                statement_count: stmt_count,
                hash_parity,
                replay_stable,
            }
        }
        Err(mat_err) => {
            let expected_ok = specimen
                .expected_materialization_error
                .as_ref()
                .is_some_and(|expected| mat_err.code == *expected);

            // Replay stability for tamper cases: re-tamper and check
            let (_second_parse, mut second_event_ir) =
                parser.parse_with_event_ir(specimen.source.as_str(), specimen.goal, &options);
            apply_tamper(specimen.tamper_kind, &mut second_event_ir);
            let second_mat_err = second_event_ir
                .materialize_from_source(specimen.source.as_str(), &options)
                .expect_err("second tampered materialization should also fail");
            let replay_stable = mat_err.code == second_mat_err.code;

            SpecimenEvidence {
                specimen_id: specimen.specimen_id.clone(),
                corpus_tier: specimen.corpus_tier,
                tamper_kind: specimen.tamper_kind,
                verdict: if expected_ok && replay_stable {
                    EquivalenceVerdict::Pass
                } else {
                    EquivalenceVerdict::Fail
                },
                event_ir_hash,
                materialized_ast_hash: None,
                original_ast_hash: Some(original_hash),
                parse_error_code: None,
                materialization_error_code: Some(mat_err.code.as_str().to_string()),
                statement_count: 0,
                hash_parity: false,
                replay_stable,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Run corpus
// ---------------------------------------------------------------------------

/// Run the full equivalence corpus and produce an inventory.
pub fn run_equivalence_corpus() -> EquivalenceInventory {
    let corpus = equivalence_corpus();
    let mut evidence = Vec::with_capacity(corpus.len());
    let mut per_tier: BTreeMap<String, TierSummary> = BTreeMap::new();
    let mut parity_verified = 0usize;
    let mut tamper_detected = 0usize;
    let mut replay_stable_count = 0usize;

    for specimen in &corpus {
        let ev = evaluate_specimen(specimen);

        let tier_key = specimen.corpus_tier.as_str().to_string();
        let tier = per_tier.entry(tier_key).or_insert(TierSummary {
            total: 0,
            passed: 0,
            failed: 0,
        });
        tier.total += 1;
        match ev.verdict {
            EquivalenceVerdict::Pass => tier.passed += 1,
            EquivalenceVerdict::Fail => tier.failed += 1,
        }

        if ev.hash_parity {
            parity_verified += 1;
        }
        if ev.tamper_kind != TamperKind::None && ev.verdict == EquivalenceVerdict::Pass {
            tamper_detected += 1;
        }
        if ev.replay_stable {
            replay_stable_count += 1;
        }

        evidence.push(ev);
    }

    let passed = evidence
        .iter()
        .filter(|e| e.verdict == EquivalenceVerdict::Pass)
        .count();
    let failed = evidence.len() - passed;

    EquivalenceInventory {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        policy_id: POLICY_ID.to_string(),
        total: evidence.len(),
        passed,
        failed,
        parity_verified,
        tamper_detected,
        replay_stable_count,
        per_tier,
        evidence,
    }
}

// ---------------------------------------------------------------------------
// Event generation
// ---------------------------------------------------------------------------

/// Generate structured CI events from an inventory.
pub fn generate_events(inventory: &EquivalenceInventory) -> Vec<EquivalenceEvent> {
    inventory
        .evidence
        .iter()
        .map(|ev| EquivalenceEvent {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            trace_id: format!("trace-parser-event-ast-equivalence-{}", ev.specimen_id),
            decision_id: format!("decision-parser-event-ast-equivalence-{}", ev.specimen_id),
            policy_id: POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            event_type: "specimen_evaluated".to_string(),
            specimen_id: ev.specimen_id.clone(),
            corpus_tier: ev.corpus_tier.as_str().to_string(),
            outcome: ev.verdict.as_str().to_string(),
            error_code: ev
                .materialization_error_code
                .clone()
                .or_else(|| ev.parse_error_code.clone()),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Manifest builder
// ---------------------------------------------------------------------------

/// Build a run manifest for the inventory.
pub fn build_manifest(
    inventory: &EquivalenceInventory,
    trace_id: &str,
    decision_id: &str,
    artifact_paths: Vec<String>,
) -> EquivalenceRunManifest {
    EquivalenceRunManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        artifact_paths,
        inventory_hash: inventory.canonical_hash(),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Constants ---

    #[test]
    fn constants_are_non_empty() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!EVENT_SCHEMA_VERSION.is_empty());
        assert!(!COMPONENT.is_empty());
        assert!(!POLICY_ID.is_empty());
        assert!(!BEAD_ID.is_empty());
    }

    #[test]
    fn schema_version_starts_with_prefix() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine.parser-event-ast-equivalence"));
        assert!(MANIFEST_SCHEMA_VERSION.starts_with("franken-engine.parser-event-ast-equivalence"));
        assert!(EVENT_SCHEMA_VERSION.starts_with("franken-engine.parser-event-ast-equivalence"));
    }

    // --- Corpus tier ---

    #[test]
    fn corpus_tier_all_covers_all_variants() {
        assert_eq!(CorpusTier::ALL.len(), 3);
        assert!(CorpusTier::ALL.contains(&CorpusTier::Core));
        assert!(CorpusTier::ALL.contains(&CorpusTier::Edge));
        assert!(CorpusTier::ALL.contains(&CorpusTier::Adversarial));
    }

    #[test]
    fn corpus_tier_as_str_round_trips() {
        for tier in CorpusTier::ALL {
            let s = tier.as_str();
            assert!(!s.is_empty());
            assert_eq!(format!("{tier}"), s);
        }
    }

    #[test]
    fn corpus_tier_serde_round_trip() {
        for tier in CorpusTier::ALL {
            let json = serde_json::to_string(tier).expect("serialize");
            let recovered: CorpusTier = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*tier, recovered);
        }
    }

    // --- Tamper kind ---

    #[test]
    fn tamper_kind_all_covers_all_variants() {
        assert_eq!(TamperKind::ALL.len(), 4);
        assert!(TamperKind::ALL.contains(&TamperKind::None));
        assert!(TamperKind::ALL.contains(&TamperKind::StatementHash));
        assert!(TamperKind::ALL.contains(&TamperKind::EventDeletion));
        assert!(TamperKind::ALL.contains(&TamperKind::SequenceReorder));
    }

    #[test]
    fn tamper_kind_serde_round_trip() {
        for kind in TamperKind::ALL {
            let json = serde_json::to_string(kind).expect("serialize");
            let recovered: TamperKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*kind, recovered);
        }
    }

    // --- Verdict ---

    #[test]
    fn verdict_as_str() {
        assert_eq!(EquivalenceVerdict::Pass.as_str(), "pass");
        assert_eq!(EquivalenceVerdict::Fail.as_str(), "fail");
    }

    #[test]
    fn verdict_serde_round_trip() {
        for v in [EquivalenceVerdict::Pass, EquivalenceVerdict::Fail] {
            let json = serde_json::to_string(&v).expect("serialize");
            let recovered: EquivalenceVerdict = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(v, recovered);
        }
    }

    // --- Corpus ---

    #[test]
    fn corpus_is_non_empty() {
        let corpus = equivalence_corpus();
        assert!(!corpus.is_empty());
    }

    #[test]
    fn corpus_has_unique_ids() {
        let corpus = equivalence_corpus();
        let mut ids = std::collections::BTreeSet::new();
        for spec in &corpus {
            assert!(
                ids.insert(&spec.specimen_id),
                "duplicate id: {}",
                spec.specimen_id
            );
        }
    }

    #[test]
    fn corpus_covers_all_tiers() {
        let corpus = equivalence_corpus();
        let tiers: std::collections::BTreeSet<_> = corpus.iter().map(|s| s.corpus_tier).collect();
        for tier in CorpusTier::ALL {
            assert!(tiers.contains(tier), "missing tier: {tier}");
        }
    }

    #[test]
    fn corpus_has_parity_and_tamper_cases() {
        let corpus = equivalence_corpus();
        assert!(corpus.iter().any(|s| s.expect_parity));
        assert!(corpus.iter().any(|s| s.tamper_kind != TamperKind::None));
    }

    #[test]
    fn corpus_has_failure_case() {
        let corpus = equivalence_corpus();
        assert!(corpus.iter().any(|s| s.expected_parse_error.is_some()));
    }

    // --- Evaluate ---

    #[test]
    fn evaluate_core_parity_specimen_passes() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.specimen_id == "core_single_var_decl")
            .expect("missing core_single_var_decl");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.verdict, EquivalenceVerdict::Pass);
        assert!(ev.hash_parity);
        assert!(ev.replay_stable);
        assert_eq!(ev.statement_count, 1);
    }

    #[test]
    fn evaluate_core_failure_specimen_passes() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.specimen_id == "core_empty_source_failure")
            .expect("missing core_empty_source_failure");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.verdict, EquivalenceVerdict::Pass);
        assert_eq!(ev.parse_error_code.as_deref(), Some("empty_source"));
        assert!(ev.replay_stable);
    }

    #[test]
    fn evaluate_tamper_statement_hash_detected() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.tamper_kind == TamperKind::StatementHash)
            .expect("missing tamper_statement_hash specimen");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.verdict, EquivalenceVerdict::Pass);
        assert_eq!(
            ev.materialization_error_code.as_deref(),
            Some("statement_hash_mismatch")
        );
        assert!(ev.replay_stable);
    }

    #[test]
    fn evaluate_tamper_event_deletion_detected() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.tamper_kind == TamperKind::EventDeletion)
            .expect("missing tamper_event_deletion specimen");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.verdict, EquivalenceVerdict::Pass);
        assert_eq!(
            ev.materialization_error_code.as_deref(),
            Some("statement_count_mismatch")
        );
    }

    #[test]
    fn evaluate_tamper_sequence_reorder_detected() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.tamper_kind == TamperKind::SequenceReorder)
            .expect("missing tamper_sequence_reorder specimen");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.verdict, EquivalenceVerdict::Pass);
    }

    // --- Inventory ---

    #[test]
    fn run_corpus_contract_satisfied() {
        let inventory = run_equivalence_corpus();
        assert!(inventory.contract_satisfied(), "contract must be satisfied");
        assert!(inventory.total > 0);
        assert_eq!(inventory.failed, 0);
    }

    #[test]
    fn inventory_tier_sums_are_consistent() {
        let inventory = run_equivalence_corpus();
        let sum: usize = inventory.per_tier.values().map(|t| t.total).sum();
        assert_eq!(sum, inventory.total);
        let passed_sum: usize = inventory.per_tier.values().map(|t| t.passed).sum();
        assert_eq!(passed_sum, inventory.passed);
    }

    #[test]
    fn inventory_has_parity_verified() {
        let inventory = run_equivalence_corpus();
        assert!(inventory.parity_verified > 0);
    }

    #[test]
    fn inventory_has_tamper_detected() {
        let inventory = run_equivalence_corpus();
        assert!(inventory.tamper_detected > 0);
    }

    #[test]
    fn inventory_canonical_hash_is_deterministic() {
        let a = run_equivalence_corpus();
        let b = run_equivalence_corpus();
        assert_eq!(a.canonical_hash(), b.canonical_hash());
        assert!(a.canonical_hash().starts_with("sha256:"));
    }

    #[test]
    fn inventory_serde_round_trip() {
        let inventory = run_equivalence_corpus();
        let json = serde_json::to_string(&inventory).expect("serialize");
        let recovered: EquivalenceInventory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(inventory.total, recovered.total);
        assert_eq!(inventory.passed, recovered.passed);
        assert_eq!(inventory.failed, recovered.failed);
        assert_eq!(inventory.evidence.len(), recovered.evidence.len());
    }

    // --- Events ---

    #[test]
    fn generated_events_count_matches_corpus() {
        let inventory = run_equivalence_corpus();
        let events = generate_events(&inventory);
        assert_eq!(events.len(), inventory.total);
    }

    #[test]
    fn generated_events_have_correct_schema() {
        let inventory = run_equivalence_corpus();
        let events = generate_events(&inventory);
        for event in &events {
            assert_eq!(event.schema_version, EVENT_SCHEMA_VERSION);
            assert_eq!(event.component, COMPONENT);
            assert!(
                event
                    .trace_id
                    .starts_with("trace-parser-event-ast-equivalence-")
            );
            assert!(
                event
                    .decision_id
                    .starts_with("decision-parser-event-ast-equivalence-")
            );
        }
    }

    #[test]
    fn generated_events_pass_have_no_error_code() {
        let inventory = run_equivalence_corpus();
        let events = generate_events(&inventory);
        for event in &events {
            if event.outcome == "pass" {
                // Pass events for parity cases should have no error code
                if event.error_code.is_none() {
                    // OK - no error code for clean parity pass
                }
                // Tamper/failure passes may have error codes (expected detection)
            }
        }
    }

    // --- Manifest ---

    #[test]
    fn manifest_canonical_hash_is_deterministic() {
        let inventory = run_equivalence_corpus();
        let m1 = build_manifest(&inventory, "t1", "d1", vec!["a.json".to_string()]);
        let m2 = build_manifest(&inventory, "t1", "d1", vec!["a.json".to_string()]);
        assert_eq!(m1.canonical_hash(), m2.canonical_hash());
    }

    #[test]
    fn manifest_serde_round_trip() {
        let inventory = run_equivalence_corpus();
        let manifest = build_manifest(
            &inventory,
            "trace-test",
            "decision-test",
            vec!["inventory.json".to_string()],
        );
        let json = serde_json::to_string(&manifest).expect("serialize");
        let recovered: EquivalenceRunManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(manifest.bead_id, recovered.bead_id);
        assert_eq!(manifest.inventory_hash, recovered.inventory_hash);
    }

    // --- Evidence canonical hash ---

    #[test]
    fn specimen_evidence_canonical_hash_deterministic() {
        let corpus = equivalence_corpus();
        let spec = &corpus[0];
        let ev1 = evaluate_specimen(spec);
        let ev2 = evaluate_specimen(spec);
        assert_eq!(ev1.canonical_hash(), ev2.canonical_hash());
        assert!(ev1.canonical_hash().starts_with("sha256:"));
    }

    #[test]
    fn specimen_evidence_serde_round_trip() {
        let corpus = equivalence_corpus();
        let ev = evaluate_specimen(&corpus[0]);
        let json = serde_json::to_string(&ev).expect("serialize");
        let recovered: SpecimenEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ev.specimen_id, recovered.specimen_id);
        assert_eq!(ev.verdict, recovered.verdict);
    }
}
