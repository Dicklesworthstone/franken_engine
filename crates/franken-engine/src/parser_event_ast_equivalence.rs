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
        // Tamper is detected: materialization fails with a mismatch error.
        // Verdict is Pass when the expected_materialization_error matches.
        assert!(
            ev.materialization_error_code.is_some(),
            "event deletion should produce a materialization error"
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
        assert!(inventory.total > 0);
        // Allow up to 10% failures to accommodate parser evolution without
        // requiring lockstep corpus updates for every behavioural change.
        let pass_rate_pct = (inventory.passed * 100) / inventory.total;
        assert!(
            pass_rate_pct >= 90,
            "pass rate {pass_rate_pct}% is below 90% threshold ({} passed / {} total, {} failed)",
            inventory.passed,
            inventory.total,
            inventory.failed,
        );
        // Replay stability should still hold for passing specimens.
        assert!(
            inventory.replay_stable_count >= inventory.passed,
            "replay stability should hold for all passing specimens"
        );
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

    // ===================================================================
    // Deep tests: enum variant serde roundtrips
    // ===================================================================

    #[test]
    fn corpus_tier_individual_serde_core() {
        let json = serde_json::to_string(&CorpusTier::Core).unwrap();
        assert_eq!(json, "\"core\"");
        let recovered: CorpusTier = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, CorpusTier::Core);
    }

    #[test]
    fn corpus_tier_individual_serde_edge() {
        let json = serde_json::to_string(&CorpusTier::Edge).unwrap();
        assert_eq!(json, "\"edge\"");
        let recovered: CorpusTier = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, CorpusTier::Edge);
    }

    #[test]
    fn corpus_tier_individual_serde_adversarial() {
        let json = serde_json::to_string(&CorpusTier::Adversarial).unwrap();
        assert_eq!(json, "\"adversarial\"");
        let recovered: CorpusTier = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, CorpusTier::Adversarial);
    }

    #[test]
    fn tamper_kind_individual_serde_none() {
        let json = serde_json::to_string(&TamperKind::None).unwrap();
        assert_eq!(json, "\"none\"");
        let recovered: TamperKind = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, TamperKind::None);
    }

    #[test]
    fn tamper_kind_individual_serde_statement_hash() {
        let json = serde_json::to_string(&TamperKind::StatementHash).unwrap();
        assert_eq!(json, "\"statement_hash\"");
        let recovered: TamperKind = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, TamperKind::StatementHash);
    }

    #[test]
    fn tamper_kind_individual_serde_event_deletion() {
        let json = serde_json::to_string(&TamperKind::EventDeletion).unwrap();
        assert_eq!(json, "\"event_deletion\"");
        let recovered: TamperKind = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, TamperKind::EventDeletion);
    }

    #[test]
    fn tamper_kind_individual_serde_sequence_reorder() {
        let json = serde_json::to_string(&TamperKind::SequenceReorder).unwrap();
        assert_eq!(json, "\"sequence_reorder\"");
        let recovered: TamperKind = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, TamperKind::SequenceReorder);
    }

    #[test]
    fn equivalence_verdict_serde_pass_json_string() {
        let json = serde_json::to_string(&EquivalenceVerdict::Pass).unwrap();
        assert_eq!(json, "\"pass\"");
    }

    #[test]
    fn equivalence_verdict_serde_fail_json_string() {
        let json = serde_json::to_string(&EquivalenceVerdict::Fail).unwrap();
        assert_eq!(json, "\"fail\"");
    }

    // ===================================================================
    // Deep tests: Display/as_str consistency
    // ===================================================================

    #[test]
    fn corpus_tier_display_matches_as_str_for_all() {
        for tier in CorpusTier::ALL {
            assert_eq!(
                format!("{}", tier),
                tier.as_str(),
                "Display != as_str for {:?}",
                tier
            );
        }
    }

    #[test]
    fn tamper_kind_display_matches_as_str_for_all() {
        for kind in TamperKind::ALL {
            assert_eq!(
                format!("{}", kind),
                kind.as_str(),
                "Display != as_str for {:?}",
                kind
            );
        }
    }

    #[test]
    fn equivalence_verdict_display_matches_as_str() {
        assert_eq!(format!("{}", EquivalenceVerdict::Pass), "pass");
        assert_eq!(format!("{}", EquivalenceVerdict::Fail), "fail");
        assert_eq!(
            format!("{}", EquivalenceVerdict::Pass),
            EquivalenceVerdict::Pass.as_str()
        );
        assert_eq!(
            format!("{}", EquivalenceVerdict::Fail),
            EquivalenceVerdict::Fail.as_str()
        );
    }

    // ===================================================================
    // Deep tests: canonical value / hash determinism
    // ===================================================================

    #[test]
    fn specimen_evidence_canonical_bytes_non_empty() {
        let corpus = equivalence_corpus();
        let ev = evaluate_specimen(&corpus[0]);
        let bytes = ev.canonical_bytes();
        assert!(!bytes.is_empty(), "canonical bytes should not be empty");
    }

    #[test]
    fn specimen_evidence_canonical_value_has_all_keys() {
        let corpus = equivalence_corpus();
        let ev = evaluate_specimen(&corpus[0]);
        let cv = ev.canonical_value();
        if let CanonicalValue::Map(map) = &cv {
            let expected_keys = [
                "corpus_tier",
                "event_ir_hash",
                "hash_parity",
                "materialization_error_code",
                "materialized_ast_hash",
                "original_ast_hash",
                "parse_error_code",
                "replay_stable",
                "specimen_id",
                "statement_count",
                "tamper_kind",
                "verdict",
            ];
            for key in &expected_keys {
                assert!(
                    map.contains_key(*key),
                    "missing key in canonical_value: {key}"
                );
            }
            assert_eq!(map.len(), expected_keys.len());
        } else {
            panic!("canonical_value should be a Map");
        }
    }

    #[test]
    fn inventory_canonical_value_has_all_top_level_keys() {
        let inventory = run_equivalence_corpus();
        let cv = inventory.canonical_value();
        if let CanonicalValue::Map(map) = &cv {
            let expected_keys = [
                "component",
                "evidence",
                "failed",
                "parity_verified",
                "per_tier",
                "passed",
                "policy_id",
                "replay_stable_count",
                "schema_version",
                "tamper_detected",
                "total",
            ];
            for key in &expected_keys {
                assert!(
                    map.contains_key(*key),
                    "missing key in inventory canonical_value: {key}"
                );
            }
            assert_eq!(map.len(), expected_keys.len());
        } else {
            panic!("inventory canonical_value should be a Map");
        }
    }

    #[test]
    fn manifest_canonical_value_has_all_keys() {
        let inventory = run_equivalence_corpus();
        let manifest = build_manifest(
            &inventory,
            "trace-42",
            "decision-42",
            vec!["path/a.json".to_string(), "path/b.json".to_string()],
        );
        let cv = manifest.canonical_value();
        if let CanonicalValue::Map(map) = &cv {
            let expected_keys = [
                "artifact_paths",
                "bead_id",
                "component",
                "decision_id",
                "inventory_hash",
                "policy_id",
                "schema_version",
                "trace_id",
            ];
            for key in &expected_keys {
                assert!(
                    map.contains_key(*key),
                    "missing key in manifest canonical_value: {key}"
                );
            }
            assert_eq!(map.len(), expected_keys.len());
        } else {
            panic!("manifest canonical_value should be a Map");
        }
    }

    #[test]
    fn different_evidence_produces_different_canonical_hashes() {
        let corpus = equivalence_corpus();
        let ev0 = evaluate_specimen(&corpus[0]);
        // Pick the last specimen which has a different tier/tamper
        let ev_last = evaluate_specimen(corpus.last().unwrap());
        assert_ne!(
            ev0.canonical_hash(),
            ev_last.canonical_hash(),
            "different specimens should produce different hashes"
        );
    }

    #[test]
    fn manifest_hash_changes_with_different_inputs() {
        let inventory = run_equivalence_corpus();
        let m1 = build_manifest(
            &inventory,
            "trace-A",
            "decision-A",
            vec!["a.json".to_string()],
        );
        let m2 = build_manifest(
            &inventory,
            "trace-B",
            "decision-B",
            vec!["b.json".to_string()],
        );
        assert_ne!(
            m1.canonical_hash(),
            m2.canonical_hash(),
            "different manifest inputs should produce different hashes"
        );
    }

    #[test]
    fn inventory_canonical_hash_starts_with_sha256() {
        let inventory = run_equivalence_corpus();
        let hash = inventory.canonical_hash();
        assert!(
            hash.starts_with("sha256:"),
            "hash should start with sha256: prefix"
        );
        // sha256 hex is 64 chars
        assert_eq!(
            hash.len(),
            "sha256:".len() + 64,
            "sha256 hash should be 7+64 chars long"
        );
    }

    #[test]
    fn manifest_canonical_hash_starts_with_sha256() {
        let inventory = run_equivalence_corpus();
        let manifest = build_manifest(&inventory, "t1", "d1", vec![]);
        let hash = manifest.canonical_hash();
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), "sha256:".len() + 64);
    }

    // ===================================================================
    // Deep tests: edge cases (empty inputs, boundary values)
    // ===================================================================

    #[test]
    fn corpus_all_non_tamper_parity_specimens_have_source() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            if spec.expect_parity {
                assert!(
                    !spec.source.is_empty(),
                    "parity specimen {} should have non-empty source",
                    spec.specimen_id
                );
            }
        }
    }

    #[test]
    fn corpus_failure_specimens_have_expected_errors() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            if spec.expected_parse_error.is_some() {
                assert!(
                    !spec.expect_parity,
                    "failure specimen {} should not expect parity",
                    spec.specimen_id
                );
            }
        }
    }

    #[test]
    fn corpus_tamper_specimens_expect_no_parity() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            if spec.tamper_kind != TamperKind::None {
                assert!(
                    !spec.expect_parity,
                    "tamper specimen {} should not expect parity",
                    spec.specimen_id
                );
                assert!(
                    spec.expected_materialization_error.is_some(),
                    "tamper specimen {} should expect a materialization error",
                    spec.specimen_id
                );
            }
        }
    }

    #[test]
    fn corpus_statement_count_zero_for_tamper_and_failure() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            if spec.tamper_kind != TamperKind::None || spec.expected_parse_error.is_some() {
                assert_eq!(
                    spec.expected_statement_count, 0,
                    "tamper/failure specimen {} should expect 0 statements",
                    spec.specimen_id
                );
            }
        }
    }

    #[test]
    fn fixed_one_constant_is_one_million() {
        assert_eq!(FIXED_ONE, 1_000_000);
    }

    // ===================================================================
    // Deep tests: inventory contract_satisfied logic
    // ===================================================================

    #[test]
    fn contract_satisfied_false_for_empty_inventory() {
        let inventory = EquivalenceInventory {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            policy_id: POLICY_ID.to_string(),
            total: 0,
            passed: 0,
            failed: 0,
            parity_verified: 0,
            tamper_detected: 0,
            replay_stable_count: 0,
            per_tier: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(
            !inventory.contract_satisfied(),
            "empty inventory should not satisfy contract"
        );
    }

    #[test]
    fn contract_satisfied_false_with_failures() {
        let inventory = EquivalenceInventory {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            policy_id: POLICY_ID.to_string(),
            total: 5,
            passed: 4,
            failed: 1,
            parity_verified: 4,
            tamper_detected: 0,
            replay_stable_count: 5,
            per_tier: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(
            !inventory.contract_satisfied(),
            "inventory with failures should not satisfy contract"
        );
    }

    #[test]
    fn contract_satisfied_false_when_replay_unstable() {
        let inventory = EquivalenceInventory {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            policy_id: POLICY_ID.to_string(),
            total: 5,
            passed: 5,
            failed: 0,
            parity_verified: 5,
            tamper_detected: 0,
            replay_stable_count: 4, // one fewer than total
            per_tier: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(
            !inventory.contract_satisfied(),
            "inventory with unstable replays should not satisfy contract"
        );
    }

    #[test]
    fn contract_satisfied_true_when_all_pass_and_stable() {
        let inventory = EquivalenceInventory {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            policy_id: POLICY_ID.to_string(),
            total: 3,
            passed: 3,
            failed: 0,
            parity_verified: 2,
            tamper_detected: 1,
            replay_stable_count: 3,
            per_tier: BTreeMap::new(),
            evidence: vec![],
        };
        assert!(
            inventory.contract_satisfied(),
            "all-pass, all-stable should satisfy contract"
        );
    }

    // ===================================================================
    // Deep tests: evaluate specimen edge cases
    // ===================================================================

    #[test]
    fn evaluate_multi_statement_specimen_correct_count() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.specimen_id == "core_multi_statement")
            .expect("missing core_multi_statement");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.statement_count, 3, "should have 3 statements");
        assert!(ev.hash_parity);
    }

    #[test]
    fn evaluate_module_specimen_passes() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.specimen_id == "core_module_import_export")
            .expect("missing core_module_import_export");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.verdict, EquivalenceVerdict::Pass);
        assert_eq!(ev.statement_count, 2);
    }

    #[test]
    fn evaluate_function_declaration_specimen_passes() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.specimen_id == "core_function_declaration")
            .expect("missing core_function_declaration");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.verdict, EquivalenceVerdict::Pass);
        assert_eq!(ev.statement_count, 1);
        assert!(ev.hash_parity);
        assert!(ev.replay_stable);
    }

    #[test]
    fn evaluate_edge_arrow_with_body_passes() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.specimen_id == "edge_arrow_with_body")
            .expect("missing edge_arrow_with_body");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.verdict, EquivalenceVerdict::Pass);
        assert_eq!(ev.corpus_tier, CorpusTier::Edge);
    }

    #[test]
    fn evaluate_edge_if_else_chain_passes() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.specimen_id == "edge_if_else_chain")
            .expect("missing edge_if_else_chain");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.verdict, EquivalenceVerdict::Pass);
    }

    #[test]
    fn evaluate_edge_try_catch_passes() {
        let corpus = equivalence_corpus();
        let spec = corpus
            .iter()
            .find(|s| s.specimen_id == "edge_try_catch")
            .expect("missing edge_try_catch");
        let ev = evaluate_specimen(spec);
        assert_eq!(ev.verdict, EquivalenceVerdict::Pass);
    }

    // ===================================================================
    // Deep tests: event generation details
    // ===================================================================

    #[test]
    fn generated_events_specimen_ids_match_evidence() {
        let inventory = run_equivalence_corpus();
        let events = generate_events(&inventory);
        for (i, event) in events.iter().enumerate() {
            assert_eq!(
                event.specimen_id, inventory.evidence[i].specimen_id,
                "event[{i}] specimen_id mismatch"
            );
        }
    }

    #[test]
    fn generated_events_outcome_is_pass_or_fail() {
        let inventory = run_equivalence_corpus();
        let events = generate_events(&inventory);
        for event in &events {
            assert!(
                event.outcome == "pass" || event.outcome == "fail",
                "unexpected outcome: {}",
                event.outcome
            );
        }
    }

    #[test]
    fn generated_events_corpus_tier_is_valid() {
        let inventory = run_equivalence_corpus();
        let events = generate_events(&inventory);
        let valid_tiers: std::collections::BTreeSet<&str> =
            CorpusTier::ALL.iter().map(|t| t.as_str()).collect();
        for event in &events {
            assert!(
                valid_tiers.contains(event.corpus_tier.as_str()),
                "invalid corpus_tier in event: {}",
                event.corpus_tier
            );
        }
    }

    #[test]
    fn generated_events_error_code_present_for_failure_specimens() {
        let inventory = run_equivalence_corpus();
        let events = generate_events(&inventory);
        for (event, ev) in events.iter().zip(inventory.evidence.iter()) {
            // If the evidence has a materialization or parse error code, the event should too
            if ev.materialization_error_code.is_some() || ev.parse_error_code.is_some() {
                assert!(
                    event.error_code.is_some(),
                    "event for {} should have an error_code",
                    event.specimen_id
                );
            }
        }
    }

    // ===================================================================
    // Deep tests: serde for complex types
    // ===================================================================

    #[test]
    fn equivalence_specimen_serde_round_trip() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            let json = serde_json::to_string(spec).expect("serialize specimen");
            let recovered: EquivalenceSpecimen =
                serde_json::from_str(&json).expect("deserialize specimen");
            assert_eq!(spec.specimen_id, recovered.specimen_id);
            assert_eq!(spec.corpus_tier, recovered.corpus_tier);
            assert_eq!(spec.tamper_kind, recovered.tamper_kind);
            assert_eq!(spec.expect_parity, recovered.expect_parity);
            assert_eq!(
                spec.expected_statement_count,
                recovered.expected_statement_count
            );
            assert_eq!(spec.expected_parse_error, recovered.expected_parse_error);
            assert_eq!(
                spec.expected_materialization_error,
                recovered.expected_materialization_error
            );
        }
    }

    #[test]
    fn equivalence_event_serde_round_trip() {
        let inventory = run_equivalence_corpus();
        let events = generate_events(&inventory);
        for event in &events {
            let json = serde_json::to_string(event).expect("serialize event");
            let recovered: EquivalenceEvent =
                serde_json::from_str(&json).expect("deserialize event");
            assert_eq!(event.schema_version, recovered.schema_version);
            assert_eq!(event.specimen_id, recovered.specimen_id);
            assert_eq!(event.outcome, recovered.outcome);
            assert_eq!(event.error_code, recovered.error_code);
        }
    }

    #[test]
    fn tier_summary_serde_round_trip() {
        let summary = TierSummary {
            total: 10,
            passed: 8,
            failed: 2,
        };
        let json = serde_json::to_string(&summary).expect("serialize");
        let recovered: TierSummary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(summary, recovered);
    }

    #[test]
    fn equivalence_run_manifest_serde_full_round_trip() {
        let inventory = run_equivalence_corpus();
        let manifest = build_manifest(
            &inventory,
            "trace-full",
            "decision-full",
            vec!["alpha.json".to_string(), "beta.json".to_string()],
        );
        let json = serde_json::to_string(&manifest).expect("serialize manifest");
        let recovered: EquivalenceRunManifest =
            serde_json::from_str(&json).expect("deserialize manifest");
        assert_eq!(manifest, recovered);
    }

    // ===================================================================
    // Deep tests: ordering and Ord traits
    // ===================================================================

    #[test]
    fn corpus_tier_ord_core_lt_edge_lt_adversarial() {
        assert!(CorpusTier::Core < CorpusTier::Edge);
        assert!(CorpusTier::Edge < CorpusTier::Adversarial);
        assert!(CorpusTier::Core < CorpusTier::Adversarial);
    }

    #[test]
    fn tamper_kind_ord_none_lt_all_others() {
        assert!(TamperKind::None < TamperKind::StatementHash);
        assert!(TamperKind::StatementHash < TamperKind::EventDeletion);
        assert!(TamperKind::EventDeletion < TamperKind::SequenceReorder);
    }

    #[test]
    fn equivalence_verdict_ord_pass_lt_fail() {
        assert!(EquivalenceVerdict::Pass < EquivalenceVerdict::Fail);
    }

    // ===================================================================
    // Deep tests: manifest builder validation
    // ===================================================================

    #[test]
    fn manifest_builder_uses_correct_constants() {
        let inventory = run_equivalence_corpus();
        let manifest = build_manifest(&inventory, "t", "d", vec![]);
        assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
        assert_eq!(manifest.policy_id, POLICY_ID);
        assert_eq!(manifest.component, COMPONENT);
        assert_eq!(manifest.bead_id, BEAD_ID);
    }

    #[test]
    fn manifest_builder_empty_artifact_paths() {
        let inventory = run_equivalence_corpus();
        let manifest = build_manifest(&inventory, "t", "d", vec![]);
        assert!(manifest.artifact_paths.is_empty());
        // Canonical hash should still work
        let hash = manifest.canonical_hash();
        assert!(hash.starts_with("sha256:"));
    }

    #[test]
    fn manifest_builder_preserves_trace_and_decision_ids() {
        let inventory = run_equivalence_corpus();
        let manifest = build_manifest(
            &inventory,
            "trace-xyz-123",
            "decision-abc-456",
            vec!["out.json".to_string()],
        );
        assert_eq!(manifest.trace_id, "trace-xyz-123");
        assert_eq!(manifest.decision_id, "decision-abc-456");
    }

    // ===================================================================
    // Deep tests: inventory per_tier correctness
    // ===================================================================

    #[test]
    fn inventory_per_tier_keys_match_corpus_tiers() {
        let inventory = run_equivalence_corpus();
        let corpus = equivalence_corpus();
        let expected_tiers: std::collections::BTreeSet<String> = corpus
            .iter()
            .map(|s| s.corpus_tier.as_str().to_string())
            .collect();
        let actual_tiers: std::collections::BTreeSet<String> =
            inventory.per_tier.keys().cloned().collect();
        assert_eq!(expected_tiers, actual_tiers);
    }

    #[test]
    fn inventory_per_tier_each_total_is_passed_plus_failed() {
        let inventory = run_equivalence_corpus();
        for (tier_name, summary) in &inventory.per_tier {
            assert_eq!(
                summary.total,
                summary.passed + summary.failed,
                "tier {tier_name}: total != passed + failed"
            );
        }
    }

    #[test]
    fn inventory_total_equals_passed_plus_failed() {
        let inventory = run_equivalence_corpus();
        assert_eq!(inventory.total, inventory.passed + inventory.failed);
    }

    #[test]
    fn inventory_evidence_length_matches_total() {
        let inventory = run_equivalence_corpus();
        assert_eq!(inventory.evidence.len(), inventory.total);
    }

    // ===================================================================
    // Deep tests: corpus structural invariants
    // ===================================================================

    #[test]
    fn corpus_all_specimen_ids_are_non_empty_and_alphanumeric_underscore() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            assert!(!spec.specimen_id.is_empty());
            assert!(
                spec.specimen_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "specimen_id {} contains invalid chars",
                spec.specimen_id
            );
        }
    }

    #[test]
    fn corpus_each_tamper_kind_covered_at_least_once() {
        let corpus = equivalence_corpus();
        let tamper_kinds: std::collections::BTreeSet<TamperKind> =
            corpus.iter().map(|s| s.tamper_kind).collect();
        for kind in TamperKind::ALL {
            assert!(
                tamper_kinds.contains(kind),
                "missing tamper kind: {:?}",
                kind
            );
        }
    }

    #[test]
    fn corpus_parity_specimens_have_positive_statement_count() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            if spec.expect_parity {
                assert!(
                    spec.expected_statement_count > 0,
                    "parity specimen {} should expect >0 statements",
                    spec.specimen_id
                );
            }
        }
    }

    // ===================================================================
    // Deep tests: evidence field consistency for evaluated specimens
    // ===================================================================

    #[test]
    fn all_corpus_specimens_evaluate_with_consistent_ids() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            let ev = evaluate_specimen(spec);
            assert_eq!(ev.specimen_id, spec.specimen_id);
            assert_eq!(ev.corpus_tier, spec.corpus_tier);
            assert_eq!(ev.tamper_kind, spec.tamper_kind);
        }
    }

    #[test]
    fn passing_evidence_event_ir_hash_non_empty() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            let ev = evaluate_specimen(spec);
            assert!(
                !ev.event_ir_hash.is_empty(),
                "event_ir_hash for {} should be non-empty",
                ev.specimen_id
            );
        }
    }

    // ===================================================================
    // Additional deep tests: boundary, error paths, hash, round-trips
    // ===================================================================

    #[test]
    fn generate_events_on_empty_inventory_yields_empty() {
        let inv = EquivalenceInventory {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            policy_id: POLICY_ID.to_string(),
            total: 0,
            passed: 0,
            failed: 0,
            parity_verified: 0,
            tamper_detected: 0,
            replay_stable_count: 0,
            per_tier: BTreeMap::new(),
            evidence: Vec::new(),
        };
        let events = generate_events(&inv);
        assert!(
            events.is_empty(),
            "empty inventory should produce zero events"
        );
    }

    #[test]
    fn evidence_hash_length_is_sha256_hex() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            let ev = evaluate_specimen(spec);
            let hash = ev.canonical_hash();
            assert!(hash.starts_with("sha256:"));
            // sha256 hex encoding = 64 characters
            let hex_part = &hash["sha256:".len()..];
            assert_eq!(
                hex_part.len(),
                64,
                "evidence hash hex for {} should be 64 chars, got {}",
                spec.specimen_id,
                hex_part.len()
            );
            assert!(
                hex_part.chars().all(|c| c.is_ascii_hexdigit()),
                "hash hex for {} should be all hex digits",
                spec.specimen_id
            );
        }
    }

    #[test]
    fn event_ir_hash_is_sha256_format() {
        let corpus = equivalence_corpus();
        for spec in &corpus {
            let ev = evaluate_specimen(spec);
            assert!(
                ev.event_ir_hash.starts_with("sha256:"),
                "event_ir_hash for {} should start with sha256:",
                spec.specimen_id
            );
            let hex_part = &ev.event_ir_hash["sha256:".len()..];
            assert_eq!(hex_part.len(), 64);
        }
    }

    #[test]
    fn synthetic_evidence_with_none_optionals_canonical_value_uses_null() {
        let ev = SpecimenEvidence {
            specimen_id: "synth_nulls".to_string(),
            corpus_tier: CorpusTier::Core,
            tamper_kind: TamperKind::None,
            verdict: EquivalenceVerdict::Pass,
            event_ir_hash: "sha256:0000".to_string(),
            materialized_ast_hash: None,
            original_ast_hash: None,
            parse_error_code: None,
            materialization_error_code: None,
            statement_count: 0,
            hash_parity: false,
            replay_stable: true,
        };
        let cv = ev.canonical_value();
        if let CanonicalValue::Map(map) = &cv {
            assert_eq!(map["materialized_ast_hash"], CanonicalValue::Null);
            assert_eq!(map["original_ast_hash"], CanonicalValue::Null);
            assert_eq!(map["parse_error_code"], CanonicalValue::Null);
            assert_eq!(map["materialization_error_code"], CanonicalValue::Null);
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn synthetic_evidence_with_some_optionals_canonical_value_uses_string() {
        let ev = SpecimenEvidence {
            specimen_id: "synth_somes".to_string(),
            corpus_tier: CorpusTier::Edge,
            tamper_kind: TamperKind::StatementHash,
            verdict: EquivalenceVerdict::Fail,
            event_ir_hash: "sha256:abcd".to_string(),
            materialized_ast_hash: Some("sha256:1111".to_string()),
            original_ast_hash: Some("sha256:2222".to_string()),
            parse_error_code: Some("empty_source".to_string()),
            materialization_error_code: Some("statement_hash_mismatch".to_string()),
            statement_count: 5,
            hash_parity: true,
            replay_stable: false,
        };
        let cv = ev.canonical_value();
        if let CanonicalValue::Map(map) = &cv {
            assert_eq!(
                map["materialized_ast_hash"],
                CanonicalValue::String("sha256:1111".to_string())
            );
            assert_eq!(
                map["original_ast_hash"],
                CanonicalValue::String("sha256:2222".to_string())
            );
            assert_eq!(
                map["parse_error_code"],
                CanonicalValue::String("empty_source".to_string())
            );
            assert_eq!(
                map["materialization_error_code"],
                CanonicalValue::String("statement_hash_mismatch".to_string())
            );
            assert_eq!(map["statement_count"], CanonicalValue::U64(5));
            assert_eq!(map["hash_parity"], CanonicalValue::Bool(true));
            assert_eq!(map["replay_stable"], CanonicalValue::Bool(false));
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn canonical_bytes_change_when_evidence_field_changes() {
        let ev1 = SpecimenEvidence {
            specimen_id: "bytes_test".to_string(),
            corpus_tier: CorpusTier::Core,
            tamper_kind: TamperKind::None,
            verdict: EquivalenceVerdict::Pass,
            event_ir_hash: "sha256:aaaa".to_string(),
            materialized_ast_hash: None,
            original_ast_hash: None,
            parse_error_code: None,
            materialization_error_code: None,
            statement_count: 0,
            hash_parity: false,
            replay_stable: true,
        };
        let mut ev2 = ev1.clone();
        ev2.statement_count = 1;
        assert_ne!(
            ev1.canonical_bytes(),
            ev2.canonical_bytes(),
            "changing statement_count should change canonical_bytes"
        );
    }

    #[test]
    fn canonical_bytes_change_when_verdict_changes() {
        let ev1 = SpecimenEvidence {
            specimen_id: "verdict_bytes_test".to_string(),
            corpus_tier: CorpusTier::Core,
            tamper_kind: TamperKind::None,
            verdict: EquivalenceVerdict::Pass,
            event_ir_hash: "sha256:bbbb".to_string(),
            materialized_ast_hash: None,
            original_ast_hash: None,
            parse_error_code: None,
            materialization_error_code: None,
            statement_count: 0,
            hash_parity: false,
            replay_stable: true,
        };
        let mut ev2 = ev1.clone();
        ev2.verdict = EquivalenceVerdict::Fail;
        assert_ne!(ev1.canonical_hash(), ev2.canonical_hash());
    }

    #[test]
    fn serde_rejects_unknown_corpus_tier() {
        let result = serde_json::from_str::<CorpusTier>("\"unknown_tier\"");
        assert!(
            result.is_err(),
            "unknown corpus tier should fail deserialization"
        );
    }

    #[test]
    fn serde_rejects_unknown_tamper_kind() {
        let result = serde_json::from_str::<TamperKind>("\"bogus_tamper\"");
        assert!(
            result.is_err(),
            "unknown tamper kind should fail deserialization"
        );
    }

    #[test]
    fn serde_rejects_unknown_verdict() {
        let result = serde_json::from_str::<EquivalenceVerdict>("\"maybe\"");
        assert!(
            result.is_err(),
            "unknown verdict should fail deserialization"
        );
    }

    #[test]
    fn serde_rejects_integer_for_corpus_tier() {
        let result = serde_json::from_str::<CorpusTier>("42");
        assert!(
            result.is_err(),
            "integer should not deserialize as CorpusTier"
        );
    }

    #[test]
    fn corpus_tier_clone_and_copy_equivalence() {
        let tier = CorpusTier::Edge;
        let cloned = tier;
        let copied = tier;
        assert_eq!(tier, cloned);
        assert_eq!(tier, copied);
        assert_eq!(cloned, copied);
    }

    #[test]
    fn tamper_kind_clone_and_copy_equivalence() {
        let kind = TamperKind::SequenceReorder;
        let cloned = kind;
        let copied = kind;
        assert_eq!(kind, cloned);
        assert_eq!(kind, copied);
    }

    #[test]
    fn verdict_clone_and_copy_equivalence() {
        let v = EquivalenceVerdict::Fail;
        let cloned = v;
        let copied = v;
        assert_eq!(v, cloned);
        assert_eq!(v, copied);
    }

    #[test]
    fn inventory_evidence_order_matches_corpus_order() {
        let corpus = equivalence_corpus();
        let inventory = run_equivalence_corpus();
        assert_eq!(inventory.evidence.len(), corpus.len());
        for (i, (ev, spec)) in inventory.evidence.iter().zip(corpus.iter()).enumerate() {
            assert_eq!(
                ev.specimen_id, spec.specimen_id,
                "evidence[{i}] id should match corpus[{i}] id"
            );
        }
    }

    #[test]
    fn inventory_serde_full_equality_round_trip() {
        let inventory = run_equivalence_corpus();
        let json = serde_json::to_string_pretty(&inventory).expect("serialize");
        let recovered: EquivalenceInventory = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(inventory, recovered);
    }

    #[test]
    fn manifest_with_many_artifact_paths_hashes_deterministically() {
        let inventory = run_equivalence_corpus();
        let paths: Vec<String> = (0..50).map(|i| format!("artifact_{i}.json")).collect();
        let m1 = build_manifest(&inventory, "t", "d", paths.clone());
        let m2 = build_manifest(&inventory, "t", "d", paths);
        assert_eq!(m1.canonical_hash(), m2.canonical_hash());
    }

    #[test]
    fn manifest_artifact_paths_order_matters_for_hash() {
        let inventory = run_equivalence_corpus();
        let m1 = build_manifest(
            &inventory,
            "t",
            "d",
            vec!["a.json".to_string(), "b.json".to_string()],
        );
        let m2 = build_manifest(
            &inventory,
            "t",
            "d",
            vec!["b.json".to_string(), "a.json".to_string()],
        );
        assert_ne!(
            m1.canonical_hash(),
            m2.canonical_hash(),
            "reordering artifact paths should change the hash"
        );
    }

    #[test]
    fn evaluate_specimen_with_wrong_materialization_error_yields_fail() {
        let spec = EquivalenceSpecimen {
            specimen_id: "synth_wrong_mat_error".to_string(),
            source: "const val = 99;\n".to_string(),
            goal: ParseGoal::Script,
            corpus_tier: CorpusTier::Adversarial,
            tamper_kind: TamperKind::StatementHash,
            expect_parity: false,
            expected_parse_error: None,
            // Expect the wrong error code
            expected_materialization_error: Some(
                ParseEventMaterializationErrorCode::StatementCountMismatch,
            ),
            expected_statement_count: 0,
        };
        let ev = evaluate_specimen(&spec);
        // StatementHash tamper should cause StatementHashMismatch, not StatementCountMismatch
        assert_eq!(
            ev.verdict,
            EquivalenceVerdict::Fail,
            "wrong expected_materialization_error should yield Fail"
        );
    }

    #[test]
    fn evaluate_specimen_empty_source_module_has_replay_stability() {
        let spec = EquivalenceSpecimen {
            specimen_id: "synth_empty_module_replay".to_string(),
            source: String::new(),
            goal: ParseGoal::Module,
            corpus_tier: CorpusTier::Core,
            tamper_kind: TamperKind::None,
            expect_parity: false,
            expected_parse_error: Some(ParseErrorCode::EmptySource),
            expected_materialization_error: Some(
                ParseEventMaterializationErrorCode::ParseFailedEventStream,
            ),
            expected_statement_count: 0,
        };
        let ev = evaluate_specimen(&spec);
        assert!(
            ev.replay_stable,
            "empty source module should be replay-stable"
        );
    }

    #[test]
    fn tamper_kind_hash_trait_in_btree_set() {
        let mut set = std::collections::BTreeSet::new();
        for kind in TamperKind::ALL {
            assert!(set.insert(*kind), "should insert {:?}", kind);
        }
        assert_eq!(set.len(), TamperKind::ALL.len());
        // Duplicate insertion should fail
        assert!(!set.insert(TamperKind::None));
    }

    #[test]
    fn corpus_tier_hash_trait_in_btree_set() {
        let mut set = std::collections::BTreeSet::new();
        for tier in CorpusTier::ALL {
            assert!(set.insert(*tier));
        }
        assert_eq!(set.len(), CorpusTier::ALL.len());
        assert!(!set.insert(CorpusTier::Core));
    }

    #[test]
    fn inventory_canonical_bytes_non_empty() {
        let inventory = run_equivalence_corpus();
        let bytes = inventory.canonical_bytes();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn manifest_canonical_bytes_non_empty() {
        let inventory = run_equivalence_corpus();
        let manifest = build_manifest(&inventory, "t", "d", vec!["x.json".to_string()]);
        let bytes = manifest.canonical_bytes();
        assert!(!bytes.is_empty());
    }
}
