//! Parser frontier e2e harness with replay artifacts and failure-path coverage.
//!
//! This module proves the fail-closed contract for the parser frontier:
//! every syntax family that is supported must parse deterministically, and
//! every unsupported syntax must reject with a structured `ParseError` carrying
//! a stable diagnostic code. No syntax input may silently degrade into an
//! incorrect parse tree.
//!
//! The evidence harness runs a corpus of positive (supported) and negative
//! (unsupported/fail-closed) specimens through the parser pipeline and
//! records per-specimen verdicts, producing a bundle suitable for CI gating
//! and release-evidence publication.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::ast::ParseGoal;
use crate::parser::{CanonicalEs2020Parser, ParseErrorCode, ParserOptions};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION: &str =
    "franken-engine.parser-frontier-evidence.inventory.v1";
pub const PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.parser-frontier-evidence.run-manifest.v1";
pub const PARSER_FRONTIER_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.parser-frontier-evidence.event.v1";
pub const PARSER_FRONTIER_COMPONENT: &str = "parser_frontier_evidence";
pub const PARSER_FRONTIER_POLICY_ID: &str =
    "franken-engine.parser-frontier-evidence.policy.v1";

// ---------------------------------------------------------------------------
// Corpus: Parser frontier syntax families
// ---------------------------------------------------------------------------

/// A syntax family in the parser frontier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserFrontierFamily {
    VariableDeclaration,
    FunctionDeclaration,
    ArrowFunction,
    ClassDeclaration,
    ObjectLiteral,
    ArrayLiteral,
    BinaryArithmetic,
    BinaryComparison,
    BinaryLogical,
    UnaryExpression,
    AssignmentExpression,
    MemberExpression,
    CallExpression,
    NewExpression,
    TemplateLiteral,
    ForInStatement,
    ForOfStatement,
    TryCatchFinally,
    SpreadElement,
    DestructuringPattern,
    OptionalChaining,
    TaggedTemplate,
    ImportDeclaration,
    ExportDeclaration,
}

impl ParserFrontierFamily {
    pub const ALL: &[Self] = &[
        Self::VariableDeclaration,
        Self::FunctionDeclaration,
        Self::ArrowFunction,
        Self::ClassDeclaration,
        Self::ObjectLiteral,
        Self::ArrayLiteral,
        Self::BinaryArithmetic,
        Self::BinaryComparison,
        Self::BinaryLogical,
        Self::UnaryExpression,
        Self::AssignmentExpression,
        Self::MemberExpression,
        Self::CallExpression,
        Self::NewExpression,
        Self::TemplateLiteral,
        Self::ForInStatement,
        Self::ForOfStatement,
        Self::TryCatchFinally,
        Self::SpreadElement,
        Self::DestructuringPattern,
        Self::OptionalChaining,
        Self::TaggedTemplate,
        Self::ImportDeclaration,
        Self::ExportDeclaration,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VariableDeclaration => "variable_declaration",
            Self::FunctionDeclaration => "function_declaration",
            Self::ArrowFunction => "arrow_function",
            Self::ClassDeclaration => "class_declaration",
            Self::ObjectLiteral => "object_literal",
            Self::ArrayLiteral => "array_literal",
            Self::BinaryArithmetic => "binary_arithmetic",
            Self::BinaryComparison => "binary_comparison",
            Self::BinaryLogical => "binary_logical",
            Self::UnaryExpression => "unary_expression",
            Self::AssignmentExpression => "assignment_expression",
            Self::MemberExpression => "member_expression",
            Self::CallExpression => "call_expression",
            Self::NewExpression => "new_expression",
            Self::TemplateLiteral => "template_literal",
            Self::ForInStatement => "for_in_statement",
            Self::ForOfStatement => "for_of_statement",
            Self::TryCatchFinally => "try_catch_finally",
            Self::SpreadElement => "spread_element",
            Self::DestructuringPattern => "destructuring_pattern",
            Self::OptionalChaining => "optional_chaining",
            Self::TaggedTemplate => "tagged_template",
            Self::ImportDeclaration => "import_declaration",
            Self::ExportDeclaration => "export_declaration",
        }
    }
}

/// Expected parse outcome for a corpus specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedParseOutcome {
    /// Parser should accept and produce a valid syntax tree.
    Accepted,
    /// Parser should reject with a structured diagnostic.
    Rejected,
}

impl ExpectedParseOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

/// A single corpus specimen for the parser frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierSpecimen {
    pub specimen_id: String,
    pub family: ParserFrontierFamily,
    pub source: String,
    pub parse_goal: ParseGoal,
    pub expected_outcome: ExpectedParseOutcome,
    pub description: String,
}

/// Build the canonical parser frontier corpus.
pub fn frontier_corpus() -> Vec<FrontierSpecimen> {
    vec![
        // --- Positive specimens (should parse successfully) ---
        FrontierSpecimen {
            specimen_id: "var_let_const".to_string(),
            family: ParserFrontierFamily::VariableDeclaration,
            source: "let x = 1; const y = 2; var z = 3;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Variable declarations with let/const/var".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "function_basic".to_string(),
            family: ParserFrontierFamily::FunctionDeclaration,
            source: "function add(a, b) { return a + b; }".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Basic function declaration with return".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "arrow_function".to_string(),
            family: ParserFrontierFamily::ArrowFunction,
            source: "const f = (x) => x + 1;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Arrow function expression".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "class_basic".to_string(),
            family: ParserFrontierFamily::ClassDeclaration,
            source: "class Foo { constructor() {} method() { return 42; } }".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Class declaration with constructor and method".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "object_literal".to_string(),
            family: ParserFrontierFamily::ObjectLiteral,
            source: "const obj = { a: 1, b: 2, c: 3 };".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Object literal with multiple properties".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "array_literal".to_string(),
            family: ParserFrontierFamily::ArrayLiteral,
            source: "const arr = [1, 2, 3, 4, 5];".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Array literal".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "binary_arithmetic".to_string(),
            family: ParserFrontierFamily::BinaryArithmetic,
            source: "const result = 1 + 2 * 3 - 4 / 2;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Binary arithmetic operators".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "binary_comparison".to_string(),
            family: ParserFrontierFamily::BinaryComparison,
            source: "const ok = x > 0 && x < 100 && x !== null;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Binary comparison and strict equality operators".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "binary_logical".to_string(),
            family: ParserFrontierFamily::BinaryLogical,
            source: "const val = a || b || c;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Logical OR chain".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "unary_expression".to_string(),
            family: ParserFrontierFamily::UnaryExpression,
            source: "const neg = -x; const not = !flag; const t = typeof x;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Unary operators (negation, not, typeof)".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "assignment_simple".to_string(),
            family: ParserFrontierFamily::AssignmentExpression,
            source: "x = 42; y += 1;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Simple and compound assignment".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "member_expression".to_string(),
            family: ParserFrontierFamily::MemberExpression,
            source: "const val = obj.prop; const el = arr[0];".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Dot and bracket member access".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "call_expression".to_string(),
            family: ParserFrontierFamily::CallExpression,
            source: "const result = foo(1, 2, 3);".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Function call with arguments".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "new_expression".to_string(),
            family: ParserFrontierFamily::NewExpression,
            source: "const obj = new Foo(1, 2);".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "New expression with arguments".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "template_literal".to_string(),
            family: ParserFrontierFamily::TemplateLiteral,
            source: "const msg = `hello ${name}`;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Template literal with interpolation".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "for_in_loop".to_string(),
            family: ParserFrontierFamily::ForInStatement,
            source: "for (const k in obj) { console.log(k); }".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "For-in statement".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "for_of_loop".to_string(),
            family: ParserFrontierFamily::ForOfStatement,
            source: "for (const v of arr) { console.log(v); }".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "For-of statement".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "try_catch".to_string(),
            family: ParserFrontierFamily::TryCatchFinally,
            source: "try { foo(); } catch (e) { bar(); } finally { cleanup(); }".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Try/catch/finally statement".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "spread_element".to_string(),
            family: ParserFrontierFamily::SpreadElement,
            source: "const merged = [...a, ...b];".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Spread element in array literal".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "destructuring_object".to_string(),
            family: ParserFrontierFamily::DestructuringPattern,
            source: "const { a, b } = obj;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Object destructuring pattern".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "import_declaration".to_string(),
            family: ParserFrontierFamily::ImportDeclaration,
            source: "import { foo } from \"./mod.js\";".to_string(),
            parse_goal: ParseGoal::Module,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Named import declaration".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "export_declaration".to_string(),
            family: ParserFrontierFamily::ExportDeclaration,
            source: "export const x = 42;".to_string(),
            parse_goal: ParseGoal::Module,
            expected_outcome: ExpectedParseOutcome::Accepted,
            description: "Export const declaration".to_string(),
        },
        // --- Negative specimens (should reject fail-closed) ---
        FrontierSpecimen {
            specimen_id: "empty_source_rejects".to_string(),
            family: ParserFrontierFamily::VariableDeclaration,
            source: String::new(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Rejected,
            description: "Empty source input rejects with EmptySource".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "optional_chaining_rejects".to_string(),
            family: ParserFrontierFamily::OptionalChaining,
            source: "const val = obj?.prop?.nested;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Rejected,
            description: "Optional chaining not yet supported, rejects fail-closed".to_string(),
        },
        FrontierSpecimen {
            specimen_id: "tagged_template_rejects".to_string(),
            family: ParserFrontierFamily::TaggedTemplate,
            source: "const result = tag`hello ${name}`;".to_string(),
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedParseOutcome::Rejected,
            description: "Tagged template not yet supported, rejects fail-closed".to_string(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

/// Actual outcome from running a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActualParseOutcome {
    Accepted,
    Rejected,
}

/// Verdict for a single specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontierVerdict {
    Pass,
    Fail,
}

/// Evidence for a single specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierSpecimenEvidence {
    pub specimen_id: String,
    pub family: ParserFrontierFamily,
    pub expected_outcome: ExpectedParseOutcome,
    pub actual_outcome: ActualParseOutcome,
    pub verdict: FrontierVerdict,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub event_ir_hash: Option<String>,
}

/// Complete evidence inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserFrontierEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub accepted_count: u64,
    pub rejected_count: u64,
    pub family_coverage: BTreeMap<String, u64>,
    pub evidence: Vec<FrontierSpecimenEvidence>,
}

impl ParserFrontierEvidenceInventory {
    pub fn contract_satisfied(&self) -> bool {
        self.fail_count == 0
    }
}

/// Run manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierEvidenceRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub specimen_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub accepted_count: u64,
    pub rejected_count: u64,
    pub contract_satisfied: bool,
    pub artifact_paths: FrontierEvidenceArtifactPaths,
}

/// Artifact paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierEvidenceArtifactPaths {
    pub evidence_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

/// Evidence event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierEvidenceEvent {
    pub schema_version: String,
    pub component: String,
    pub event: String,
    pub policy_id: String,
    pub specimen_id: Option<String>,
    pub verdict: Option<String>,
    pub detail: Option<String>,
}

/// Bundle artifacts.
#[derive(Debug, Clone)]
pub struct FrontierEvidenceBundleArtifacts {
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

/// Run a single specimen through the parser.
fn evaluate_specimen(specimen: &FrontierSpecimen) -> FrontierSpecimenEvidence {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let (result, event_ir) =
        parser.parse_with_event_ir(&specimen.source as &str, specimen.parse_goal, &options);

    let event_ir_hash = Some(event_ir.canonical_hash());

    match result {
        Ok(_tree) => {
            let actual = ActualParseOutcome::Accepted;
            let verdict = if specimen.expected_outcome == ExpectedParseOutcome::Accepted {
                FrontierVerdict::Pass
            } else {
                FrontierVerdict::Fail
            };
            FrontierSpecimenEvidence {
                specimen_id: specimen.specimen_id.clone(),
                family: specimen.family,
                expected_outcome: specimen.expected_outcome,
                actual_outcome: actual,
                verdict,
                error_code: None,
                error_message: None,
                event_ir_hash,
            }
        }
        Err(err) => {
            let actual = ActualParseOutcome::Rejected;
            let verdict = if specimen.expected_outcome == ExpectedParseOutcome::Rejected {
                FrontierVerdict::Pass
            } else {
                FrontierVerdict::Fail
            };
            FrontierSpecimenEvidence {
                specimen_id: specimen.specimen_id.clone(),
                family: specimen.family,
                expected_outcome: specimen.expected_outcome,
                actual_outcome: actual,
                verdict,
                error_code: Some(err.code.stable_code().to_string()),
                error_message: Some(err.message.clone()),
                event_ir_hash,
            }
        }
    }
}

/// Run the complete frontier corpus.
pub fn run_frontier_corpus() -> ParserFrontierEvidenceInventory {
    let corpus = frontier_corpus();

    let mut evidence = Vec::with_capacity(corpus.len());
    let mut pass_count: u64 = 0;
    let mut fail_count: u64 = 0;
    let mut accepted_count: u64 = 0;
    let mut rejected_count: u64 = 0;
    let mut coverage: BTreeMap<String, u64> = BTreeMap::new();

    for specimen in &corpus {
        let result = evaluate_specimen(specimen);
        *coverage
            .entry(specimen.family.as_str().to_string())
            .or_insert(0) += 1;
        match result.actual_outcome {
            ActualParseOutcome::Accepted => accepted_count += 1,
            ActualParseOutcome::Rejected => rejected_count += 1,
        }
        match result.verdict {
            FrontierVerdict::Pass => pass_count += 1,
            FrontierVerdict::Fail => fail_count += 1,
        }
        evidence.push(result);
    }

    ParserFrontierEvidenceInventory {
        schema_version: PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        specimen_count: corpus.len() as u64,
        pass_count,
        fail_count,
        accepted_count,
        rejected_count,
        family_coverage: coverage,
        evidence,
    }
}

/// Generate events.
fn generate_events(
    inventory: &ParserFrontierEvidenceInventory,
) -> Vec<FrontierEvidenceEvent> {
    let mut events = Vec::new();

    events.push(FrontierEvidenceEvent {
        schema_version: PARSER_FRONTIER_EVENT_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        event: "frontier_evidence_run_started".to_string(),
        policy_id: PARSER_FRONTIER_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: Some(format!(
            "starting parser frontier evidence for {} specimens",
            inventory.specimen_count
        )),
    });

    for ev in &inventory.evidence {
        events.push(FrontierEvidenceEvent {
            schema_version: PARSER_FRONTIER_EVENT_SCHEMA_VERSION.to_string(),
            component: PARSER_FRONTIER_COMPONENT.to_string(),
            event: "specimen_evaluated".to_string(),
            policy_id: PARSER_FRONTIER_POLICY_ID.to_string(),
            specimen_id: Some(ev.specimen_id.clone()),
            verdict: Some(match ev.verdict {
                FrontierVerdict::Pass => "pass".to_string(),
                FrontierVerdict::Fail => "fail".to_string(),
            }),
            detail: Some(format!(
                "expected={}, actual={}, verdict={}",
                ev.expected_outcome.as_str(),
                match ev.actual_outcome {
                    ActualParseOutcome::Accepted => "accepted",
                    ActualParseOutcome::Rejected => "rejected",
                },
                match ev.verdict {
                    FrontierVerdict::Pass => "pass",
                    FrontierVerdict::Fail => "fail",
                }
            )),
        });
    }

    events.push(FrontierEvidenceEvent {
        schema_version: PARSER_FRONTIER_EVENT_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        event: "frontier_evidence_run_completed".to_string(),
        policy_id: PARSER_FRONTIER_POLICY_ID.to_string(),
        specimen_id: None,
        verdict: None,
        detail: Some(format!(
            "{} specimens: {} pass, {} fail, {} accepted, {} rejected. Contract: {}",
            inventory.specimen_count,
            inventory.pass_count,
            inventory.fail_count,
            inventory.accepted_count,
            inventory.rejected_count,
            if inventory.contract_satisfied() {
                "SATISFIED"
            } else {
                "VIOLATED"
            }
        )),
    });

    events
}

/// Write the evidence bundle to disk.
pub fn write_frontier_evidence_bundle(
    out_dir: &Path,
    commands: &[String],
) -> Result<FrontierEvidenceBundleArtifacts, std::io::Error> {
    fs::create_dir_all(out_dir)?;

    let inventory = run_frontier_corpus();
    let inventory_json = serde_json::to_string_pretty(&inventory)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let inventory_hash =
        crate::hash_tiers::ContentHash::compute(inventory_json.as_bytes()).to_hex();

    let inventory_path = out_dir.join("parser_frontier_evidence_inventory.json");
    fs::write(&inventory_path, &inventory_json)?;

    let trace_id = format!(
        "parser-frontier-{}",
        inventory_hash.chars().take(12).collect::<String>()
    );
    let decision_id = format!("decision-{}", trace_id);

    let manifest = FrontierEvidenceRunManifest {
        schema_version: PARSER_FRONTIER_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARSER_FRONTIER_COMPONENT.to_string(),
        trace_id,
        decision_id,
        policy_id: PARSER_FRONTIER_POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
        specimen_count: inventory.specimen_count,
        pass_count: inventory.pass_count,
        fail_count: inventory.fail_count,
        accepted_count: inventory.accepted_count,
        rejected_count: inventory.rejected_count,
        contract_satisfied: inventory.contract_satisfied(),
        artifact_paths: FrontierEvidenceArtifactPaths {
            evidence_inventory: "parser_frontier_evidence_inventory.json".to_string(),
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

    Ok(FrontierEvidenceBundleArtifacts {
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
    use std::collections::BTreeSet;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("{}-{}", prefix, ts))
    }

    #[test]
    fn corpus_is_non_empty() {
        assert!(!frontier_corpus().is_empty());
    }

    #[test]
    fn corpus_covers_all_families() {
        let corpus = frontier_corpus();
        let covered: BTreeSet<ParserFrontierFamily> =
            corpus.iter().map(|s| s.family).collect();
        for f in ParserFrontierFamily::ALL {
            assert!(covered.contains(f), "missing coverage for {:?}", f);
        }
    }

    #[test]
    fn corpus_specimen_ids_unique() {
        let corpus = frontier_corpus();
        let ids: BTreeSet<&str> = corpus.iter().map(|s| s.specimen_id.as_str()).collect();
        assert_eq!(ids.len(), corpus.len());
    }

    #[test]
    fn corpus_has_positive_and_negative() {
        let corpus = frontier_corpus();
        let has_accepted = corpus
            .iter()
            .any(|s| s.expected_outcome == ExpectedParseOutcome::Accepted);
        let has_rejected = corpus
            .iter()
            .any(|s| s.expected_outcome == ExpectedParseOutcome::Rejected);
        assert!(has_accepted);
        assert!(has_rejected);
    }

    #[test]
    fn run_corpus_all_pass() {
        let inv = run_frontier_corpus();
        let failures: Vec<_> = inv
            .evidence
            .iter()
            .filter(|e| e.verdict == FrontierVerdict::Fail)
            .collect();
        if !failures.is_empty() {
            let mut msg = format!("{} failures:\n", failures.len());
            for ev in &failures {
                msg.push_str(&format!(
                    "  - {}: expected={:?}, actual={:?}, err={:?}\n",
                    ev.specimen_id, ev.expected_outcome, ev.actual_outcome, ev.error_message,
                ));
            }
            panic!("{}", msg);
        }
    }

    #[test]
    fn run_corpus_contract_satisfied() {
        let inv = run_frontier_corpus();
        assert!(inv.contract_satisfied());
    }

    #[test]
    fn corpus_counts_consistent() {
        let inv = run_frontier_corpus();
        assert_eq!(inv.pass_count + inv.fail_count, inv.specimen_count);
        assert_eq!(
            inv.accepted_count + inv.rejected_count,
            inv.specimen_count
        );
        assert_eq!(inv.evidence.len() as u64, inv.specimen_count);
    }

    #[test]
    fn family_coverage_sums() {
        let inv = run_frontier_corpus();
        let total: u64 = inv.family_coverage.values().sum();
        assert_eq!(total, inv.specimen_count);
    }

    #[test]
    fn frontier_family_as_str_distinct() {
        let strs: BTreeSet<&str> =
            ParserFrontierFamily::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(strs.len(), ParserFrontierFamily::ALL.len());
    }

    #[test]
    fn evidence_serde_roundtrip() {
        let inv = run_frontier_corpus();
        let json = serde_json::to_string(&inv).expect("serialize");
        let back: ParserFrontierEvidenceInventory =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(inv, back);
    }

    #[test]
    fn write_bundle_creates_artifacts() {
        let out = unique_temp_dir("frontier-evidence");
        let cmds = vec!["test".to_string()];
        let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
        assert!(arts.inventory_path.exists());
        assert!(arts.run_manifest_path.exists());
        assert!(arts.events_path.exists());
        assert!(arts.commands_path.exists());
    }

    #[test]
    fn bundle_manifest_consistent() {
        let out = unique_temp_dir("frontier-manifest");
        let cmds = vec!["test".to_string()];
        let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
        let manifest: FrontierEvidenceRunManifest =
            serde_json::from_slice(&fs::read(&arts.run_manifest_path).unwrap()).unwrap();
        assert!(manifest.contract_satisfied);
        assert_eq!(manifest.fail_count, 0);
    }

    #[test]
    fn bundle_hash_deterministic() {
        let out1 = unique_temp_dir("frontier-det1");
        let out2 = unique_temp_dir("frontier-det2");
        let cmds = vec!["test".to_string()];
        let a1 = write_frontier_evidence_bundle(&out1, &cmds).expect("w1");
        let a2 = write_frontier_evidence_bundle(&out2, &cmds).expect("w2");
        assert_eq!(a1.inventory_hash, a2.inventory_hash);
    }

    #[test]
    fn bundle_events_line_count() {
        let out = unique_temp_dir("frontier-events");
        let cmds = vec!["test".to_string()];
        let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
        let events = fs::read_to_string(&arts.events_path).unwrap();
        let corpus = frontier_corpus();
        assert_eq!(events.lines().count(), corpus.len() + 2);
    }

    #[test]
    fn bundle_hash_is_64_hex() {
        let out = unique_temp_dir("frontier-hex");
        let cmds = vec!["test".to_string()];
        let arts = write_frontier_evidence_bundle(&out, &cmds).expect("write");
        assert_eq!(arts.inventory_hash.len(), 64);
        assert!(arts.inventory_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn rejected_specimens_have_error_codes() {
        let inv = run_frontier_corpus();
        for ev in &inv.evidence {
            if ev.actual_outcome == ActualParseOutcome::Rejected {
                assert!(
                    ev.error_code.is_some(),
                    "rejected specimen {} should have error_code",
                    ev.specimen_id
                );
            }
        }
    }

    #[test]
    fn accepted_specimens_have_event_ir_hash() {
        let inv = run_frontier_corpus();
        for ev in &inv.evidence {
            assert!(
                ev.event_ir_hash.is_some(),
                "specimen {} should have event_ir_hash",
                ev.specimen_id
            );
        }
    }

    #[test]
    fn schema_version_correct() {
        let inv = run_frontier_corpus();
        assert_eq!(inv.schema_version, PARSER_FRONTIER_EVIDENCE_SCHEMA_VERSION);
        assert_eq!(inv.component, PARSER_FRONTIER_COMPONENT);
    }
}
