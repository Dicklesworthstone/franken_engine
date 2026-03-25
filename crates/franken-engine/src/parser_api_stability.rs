//! Parser API stability contracts, versioning policy, and compatibility tests.
//!
//! This module formalises the public parser API surface into a versioned
//! stability contract.  It defines which types, functions, and version
//! strings constitute the *stable* surface, records an explicit schema
//! evolution policy, and provides deterministic compatibility checks that
//! integration consumers can run to detect breaking changes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::{
    CANONICAL_AST_CONTRACT_VERSION, CANONICAL_AST_HASH_ALGORITHM, CANONICAL_AST_HASH_PREFIX,
    CANONICAL_AST_SCHEMA_VERSION, ParseGoal, SyntaxTree,
};
use crate::deterministic_serde::{self, CanonicalValue};
use crate::parser::{
    CanonicalEs2020Parser, Es2020Parser, GrammarCompletenessMatrix, MaterializedSyntaxTree,
    PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION, PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX,
    PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION, PARSE_EVENT_IR_COMPONENT,
    PARSE_EVENT_IR_CONTRACT_VERSION, PARSE_EVENT_IR_DECISION_PREFIX, PARSE_EVENT_IR_HASH_ALGORITHM,
    PARSE_EVENT_IR_HASH_PREFIX, PARSE_EVENT_IR_POLICY_ID, PARSE_EVENT_IR_SCHEMA_VERSION,
    PARSE_EVENT_IR_TRACE_PREFIX, PARSER_DIAGNOSTIC_HASH_ALGORITHM, PARSER_DIAGNOSTIC_HASH_PREFIX,
    PARSER_DIAGNOSTIC_SCHEMA_VERSION, PARSER_DIAGNOSTIC_TAXONOMY_VERSION, ParseBudgetKind,
    ParseDiagnosticCategory, ParseDiagnosticSeverity, ParseDiagnosticTaxonomy, ParseError,
    ParseErrorCode, ParseEventIr, ParseEventKind, ParserBudget, ParserMode, ParserOptions,
};

// ---------------------------------------------------------------------------
// Stability contract versioning
// ---------------------------------------------------------------------------

/// Current version of the parser API stability contract.
pub const API_STABILITY_CONTRACT_VERSION: &str = "franken-engine.parser-api-stability.contract.v1";

/// Schema version for serialised compatibility reports.
pub const API_STABILITY_SCHEMA_VERSION: &str = "franken-engine.parser-api-stability.schema.v1";

/// Minimum contract versions the current implementation promises to accept
/// from older serialised artifacts during migration.
pub const MINIMUM_COMPATIBLE_AST_CONTRACT: &str = "franken-engine.parser-ast.contract.v1";
pub const MINIMUM_COMPATIBLE_EVENT_IR_CONTRACT: &str = "franken-engine.parser-event-ir.contract.v2";
pub const MINIMUM_COMPATIBLE_MATERIALIZER_CONTRACT: &str =
    "franken-engine.parser-event-ast-materializer.contract.v1";
pub const MINIMUM_COMPATIBLE_DIAGNOSTIC_SCHEMA: &str =
    "franken-engine.parser-diagnostics.schema.v1";

// ---------------------------------------------------------------------------
// Schema evolution policy
// ---------------------------------------------------------------------------

/// Evolution rule governing how a particular API surface may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvolutionRule {
    /// Field additions are allowed; removals require a major version bump.
    AdditiveOnly,
    /// Changes of any kind require a new major version.
    Frozen,
    /// Internal implementation detail; no stability promise.
    Internal,
}

/// One row of the public API stability manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiSurfaceEntry {
    pub surface_id: String,
    pub description: String,
    pub evolution_rule: EvolutionRule,
    pub current_version: String,
    pub minimum_compatible_version: String,
}

/// Full manifest of every versioned surface in the parser subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiStabilityManifest {
    pub contract_version: String,
    pub schema_version: String,
    pub entries: Vec<ApiSurfaceEntry>,
}

impl ApiStabilityManifest {
    /// Build the canonical manifest reflecting the current API state.
    pub fn current() -> Self {
        let entries = vec![
            ApiSurfaceEntry {
                surface_id: "ast.contract".into(),
                description: "Canonical AST structure and hash semantics".into(),
                evolution_rule: EvolutionRule::AdditiveOnly,
                current_version: CANONICAL_AST_CONTRACT_VERSION.into(),
                minimum_compatible_version: MINIMUM_COMPATIBLE_AST_CONTRACT.into(),
            },
            ApiSurfaceEntry {
                surface_id: "ast.schema".into(),
                description: "AST field ordering and key names".into(),
                evolution_rule: EvolutionRule::Frozen,
                current_version: CANONICAL_AST_SCHEMA_VERSION.into(),
                minimum_compatible_version: CANONICAL_AST_SCHEMA_VERSION.into(),
            },
            ApiSurfaceEntry {
                surface_id: "event_ir.contract".into(),
                description: "Parse Event IR provenance and envelope contract".into(),
                evolution_rule: EvolutionRule::AdditiveOnly,
                current_version: PARSE_EVENT_IR_CONTRACT_VERSION.into(),
                minimum_compatible_version: MINIMUM_COMPATIBLE_EVENT_IR_CONTRACT.into(),
            },
            ApiSurfaceEntry {
                surface_id: "event_ir.schema".into(),
                description: "Event IR field ordering and key names".into(),
                evolution_rule: EvolutionRule::Frozen,
                current_version: PARSE_EVENT_IR_SCHEMA_VERSION.into(),
                minimum_compatible_version: PARSE_EVENT_IR_SCHEMA_VERSION.into(),
            },
            ApiSurfaceEntry {
                surface_id: "materializer.contract".into(),
                description: "Event→AST materializer contract".into(),
                evolution_rule: EvolutionRule::AdditiveOnly,
                current_version: PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION.into(),
                minimum_compatible_version: MINIMUM_COMPATIBLE_MATERIALIZER_CONTRACT.into(),
            },
            ApiSurfaceEntry {
                surface_id: "materializer.schema".into(),
                description: "Materializer field ordering".into(),
                evolution_rule: EvolutionRule::Frozen,
                current_version: PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION.into(),
                minimum_compatible_version: PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION.into(),
            },
            ApiSurfaceEntry {
                surface_id: "diagnostics.taxonomy".into(),
                description: "Stable diagnostic codes and categories".into(),
                evolution_rule: EvolutionRule::AdditiveOnly,
                current_version: PARSER_DIAGNOSTIC_TAXONOMY_VERSION.into(),
                minimum_compatible_version: PARSER_DIAGNOSTIC_TAXONOMY_VERSION.into(),
            },
            ApiSurfaceEntry {
                surface_id: "diagnostics.schema".into(),
                description: "Diagnostics envelope schema".into(),
                evolution_rule: EvolutionRule::Frozen,
                current_version: PARSER_DIAGNOSTIC_SCHEMA_VERSION.into(),
                minimum_compatible_version: MINIMUM_COMPATIBLE_DIAGNOSTIC_SCHEMA.into(),
            },
        ];
        Self {
            contract_version: API_STABILITY_CONTRACT_VERSION.into(),
            schema_version: API_STABILITY_SCHEMA_VERSION.into(),
            entries,
        }
    }

    /// Number of surfaces tracked.
    pub fn surface_count(&self) -> usize {
        self.entries.len()
    }

    /// Look up a surface entry by its stable identifier.
    pub fn entry(&self, surface_id: &str) -> Option<&ApiSurfaceEntry> {
        self.entries.iter().find(|e| e.surface_id == surface_id)
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "contract_version".into(),
            CanonicalValue::String(self.contract_version.clone()),
        );
        map.insert(
            "schema_version".into(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        let entries_cv: Vec<CanonicalValue> = self
            .entries
            .iter()
            .map(|e| {
                let mut m = BTreeMap::new();
                m.insert(
                    "current_version".into(),
                    CanonicalValue::String(e.current_version.clone()),
                );
                m.insert(
                    "description".into(),
                    CanonicalValue::String(e.description.clone()),
                );
                m.insert(
                    "evolution_rule".into(),
                    CanonicalValue::String(
                        serde_json::to_string(&e.evolution_rule)
                            .expect("evolution_rule must serialize for canonical hash"),
                    ),
                );
                m.insert(
                    "minimum_compatible_version".into(),
                    CanonicalValue::String(e.minimum_compatible_version.clone()),
                );
                m.insert(
                    "surface_id".into(),
                    CanonicalValue::String(e.surface_id.clone()),
                );
                CanonicalValue::Map(m)
            })
            .collect();
        map.insert("entries".into(), CanonicalValue::Array(entries_cv));
        CanonicalValue::Map(map)
    }

    pub fn canonical_hash(&self) -> String {
        let bytes = deterministic_serde::encode_value(&self.canonical_value());
        let digest = Sha256::digest(bytes);
        format!("sha256:{}", hex::encode(digest))
    }
}

// ---------------------------------------------------------------------------
// Compatibility check engine
// ---------------------------------------------------------------------------

/// Outcome of a single compatibility check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckVerdict {
    Pass,
    Fail,
    Skipped,
}

/// One compatibility check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityCheckResult {
    pub check_id: String,
    pub description: String,
    pub verdict: CheckVerdict,
    pub detail: String,
}

/// Full compatibility report across all checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityReport {
    pub contract_version: String,
    pub schema_version: String,
    pub results: Vec<CompatibilityCheckResult>,
}

impl CompatibilityReport {
    pub fn pass_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.verdict == CheckVerdict::Pass)
            .count()
    }

    pub fn fail_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.verdict == CheckVerdict::Fail)
            .count()
    }

    pub fn all_passed(&self) -> bool {
        self.fail_count() == 0
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "contract_version".into(),
            CanonicalValue::String(self.contract_version.clone()),
        );
        map.insert(
            "fail_count".into(),
            CanonicalValue::U64(self.fail_count() as u64),
        );
        map.insert(
            "pass_count".into(),
            CanonicalValue::U64(self.pass_count() as u64),
        );
        let results_cv: Vec<CanonicalValue> = self
            .results
            .iter()
            .map(|r| {
                let mut m = BTreeMap::new();
                m.insert(
                    "check_id".into(),
                    CanonicalValue::String(r.check_id.clone()),
                );
                m.insert("detail".into(), CanonicalValue::String(r.detail.clone()));
                m.insert(
                    "verdict".into(),
                    CanonicalValue::String(
                        serde_json::to_string(&r.verdict)
                            .expect("verdict must serialize for canonical hash"),
                    ),
                );
                CanonicalValue::Map(m)
            })
            .collect();
        map.insert("results".into(), CanonicalValue::Array(results_cv));
        map.insert(
            "schema_version".into(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_hash(&self) -> String {
        let bytes = deterministic_serde::encode_value(&self.canonical_value());
        let digest = Sha256::digest(bytes);
        format!("sha256:{}", hex::encode(digest))
    }
}

// ---------------------------------------------------------------------------
// Version string stability checks
// ---------------------------------------------------------------------------

/// Known-good golden version strings that constitute the stable surface.
/// Any change to these values is a breaking API change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenVersionVector {
    pub ast_contract: String,
    pub ast_schema: String,
    pub ast_hash_algorithm: String,
    pub ast_hash_prefix: String,
    pub event_ir_contract: String,
    pub event_ir_schema: String,
    pub event_ir_hash_algorithm: String,
    pub event_ir_hash_prefix: String,
    pub event_ir_policy_id: String,
    pub event_ir_component: String,
    pub event_ir_trace_prefix: String,
    pub event_ir_decision_prefix: String,
    pub materializer_contract: String,
    pub materializer_schema: String,
    pub materializer_node_id_prefix: String,
    pub diagnostic_taxonomy: String,
    pub diagnostic_schema: String,
    pub diagnostic_hash_algorithm: String,
    pub diagnostic_hash_prefix: String,
}

impl GoldenVersionVector {
    /// The golden version vector as of the v1 API stability contract.
    pub fn v1() -> Self {
        Self {
            ast_contract: "franken-engine.parser-ast.contract.v1".into(),
            ast_schema: "franken-engine.parser-ast.schema.v1".into(),
            ast_hash_algorithm: "sha256".into(),
            ast_hash_prefix: "sha256:".into(),
            event_ir_contract: "franken-engine.parser-event-ir.contract.v2".into(),
            event_ir_schema: "franken-engine.parser-event-ir.schema.v2".into(),
            event_ir_hash_algorithm: "sha256".into(),
            event_ir_hash_prefix: "sha256:".into(),
            event_ir_policy_id: "franken-engine.parser-event-producer.policy.v1".into(),
            event_ir_component: "canonical_es2020_parser".into(),
            event_ir_trace_prefix: "trace-parser-event-".into(),
            event_ir_decision_prefix: "decision-parser-event-".into(),
            materializer_contract: "franken-engine.parser-event-ast-materializer.contract.v1"
                .into(),
            materializer_schema: "franken-engine.parser-event-ast-materializer.schema.v1".into(),
            materializer_node_id_prefix: "ast-node-".into(),
            diagnostic_taxonomy: "franken-engine.parser-diagnostics.taxonomy.v1".into(),
            diagnostic_schema: "franken-engine.parser-diagnostics.schema.v1".into(),
            diagnostic_hash_algorithm: "sha256".into(),
            diagnostic_hash_prefix: "sha256:".into(),
        }
    }

    /// Compare against live constants and return mismatches.
    pub fn check_against_live(&self) -> Vec<(String, String, String)> {
        let mut mismatches = Vec::new();
        let checks: Vec<(&str, &str, &str)> = vec![
            (
                "ast_contract",
                &self.ast_contract,
                CANONICAL_AST_CONTRACT_VERSION,
            ),
            ("ast_schema", &self.ast_schema, CANONICAL_AST_SCHEMA_VERSION),
            (
                "ast_hash_algorithm",
                &self.ast_hash_algorithm,
                CANONICAL_AST_HASH_ALGORITHM,
            ),
            (
                "ast_hash_prefix",
                &self.ast_hash_prefix,
                CANONICAL_AST_HASH_PREFIX,
            ),
            (
                "event_ir_contract",
                &self.event_ir_contract,
                PARSE_EVENT_IR_CONTRACT_VERSION,
            ),
            (
                "event_ir_schema",
                &self.event_ir_schema,
                PARSE_EVENT_IR_SCHEMA_VERSION,
            ),
            (
                "event_ir_hash_algorithm",
                &self.event_ir_hash_algorithm,
                PARSE_EVENT_IR_HASH_ALGORITHM,
            ),
            (
                "event_ir_hash_prefix",
                &self.event_ir_hash_prefix,
                PARSE_EVENT_IR_HASH_PREFIX,
            ),
            (
                "event_ir_policy_id",
                &self.event_ir_policy_id,
                PARSE_EVENT_IR_POLICY_ID,
            ),
            (
                "event_ir_component",
                &self.event_ir_component,
                PARSE_EVENT_IR_COMPONENT,
            ),
            (
                "event_ir_trace_prefix",
                &self.event_ir_trace_prefix,
                PARSE_EVENT_IR_TRACE_PREFIX,
            ),
            (
                "event_ir_decision_prefix",
                &self.event_ir_decision_prefix,
                PARSE_EVENT_IR_DECISION_PREFIX,
            ),
            (
                "materializer_contract",
                &self.materializer_contract,
                PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION,
            ),
            (
                "materializer_schema",
                &self.materializer_schema,
                PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION,
            ),
            (
                "materializer_node_id_prefix",
                &self.materializer_node_id_prefix,
                PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX,
            ),
            (
                "diagnostic_taxonomy",
                &self.diagnostic_taxonomy,
                PARSER_DIAGNOSTIC_TAXONOMY_VERSION,
            ),
            (
                "diagnostic_schema",
                &self.diagnostic_schema,
                PARSER_DIAGNOSTIC_SCHEMA_VERSION,
            ),
            (
                "diagnostic_hash_algorithm",
                &self.diagnostic_hash_algorithm,
                PARSER_DIAGNOSTIC_HASH_ALGORITHM,
            ),
            (
                "diagnostic_hash_prefix",
                &self.diagnostic_hash_prefix,
                PARSER_DIAGNOSTIC_HASH_PREFIX,
            ),
        ];
        for (name, golden, live) in checks {
            if golden != live {
                mismatches.push((name.into(), golden.into(), live.into()));
            }
        }
        mismatches
    }
}

// ---------------------------------------------------------------------------
// Ergonomic integration patterns
// ---------------------------------------------------------------------------

/// Convenience for the common "parse a string and get an AST" use case.
pub fn parse_script(source: &str) -> Result<SyntaxTree, ParseError> {
    let parser = CanonicalEs2020Parser;
    parser.parse(source, ParseGoal::Script)
}

/// Convenience for the common "parse a module string and get an AST" use case.
pub fn parse_module(source: &str) -> Result<SyntaxTree, ParseError> {
    let parser = CanonicalEs2020Parser;
    parser.parse(source, ParseGoal::Module)
}

/// Parse and simultaneously produce Event IR for audit/replay.
pub fn parse_with_audit(
    source: &str,
    goal: ParseGoal,
) -> (Result<SyntaxTree, ParseError>, ParseEventIr) {
    let parser = CanonicalEs2020Parser;
    parser.parse_with_event_ir(source, goal, &ParserOptions::default())
}

/// Parse, produce Event IR, and materialise the AST for full provenance.
pub fn parse_with_full_provenance(
    source: &str,
    goal: ParseGoal,
) -> (
    Result<SyntaxTree, ParseError>,
    ParseEventIr,
    Result<MaterializedSyntaxTree, crate::parser::ParseEventMaterializationError>,
) {
    let parser = CanonicalEs2020Parser;
    parser.parse_with_materialized_ast(source, goal, &ParserOptions::default())
}

// ---------------------------------------------------------------------------
// Compatibility report builder
// ---------------------------------------------------------------------------

/// Run all compatibility checks against the live parser API surface and
/// produce a structured report.
pub fn run_compatibility_checks() -> CompatibilityReport {
    let mut results = Vec::new();

    // 1. Version string stability
    let golden = GoldenVersionVector::v1();
    let mismatches = golden.check_against_live();
    results.push(CompatibilityCheckResult {
        check_id: "version_strings".into(),
        description: "All golden version strings match live constants".into(),
        verdict: if mismatches.is_empty() {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: if mismatches.is_empty() {
            format!("all {} version strings match", 19)
        } else {
            format!(
                "{} mismatch(es): {}",
                mismatches.len(),
                mismatches
                    .iter()
                    .map(|(name, g, l)| format!("{}(golden={}, live={})", name, g, l))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    });

    // 2. Diagnostic taxonomy completeness
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    let all_codes = ParseErrorCode::ALL;
    let missing: Vec<_> = all_codes
        .iter()
        .filter(|code| taxonomy.rule_for(**code).is_none())
        .collect();
    results.push(CompatibilityCheckResult {
        check_id: "diagnostic_taxonomy_completeness".into(),
        description: "Every ParseErrorCode has a taxonomy rule".into(),
        verdict: if missing.is_empty() {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: if missing.is_empty() {
            format!("all {} error codes covered", all_codes.len())
        } else {
            format!("{} codes missing taxonomy rules", missing.len())
        },
    });

    // 3. Diagnostic code stability (format check)
    let code_format_ok = all_codes.iter().all(|code| {
        let dc = code.stable_diagnostic_code();
        dc.starts_with("FE-PARSER-DIAG-") && dc.ends_with("-0001")
    });
    results.push(CompatibilityCheckResult {
        check_id: "diagnostic_code_format".into(),
        description: "Stable diagnostic codes follow FE-PARSER-DIAG-*-0001 pattern".into(),
        verdict: if code_format_ok {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: if code_format_ok {
            "all codes match pattern".into()
        } else {
            "some codes violate naming convention".into()
        },
    });

    // 4. Parse-goal enum stability
    let goals_stable =
        ParseGoal::Script.as_str() == "script" && ParseGoal::Module.as_str() == "module";
    results.push(CompatibilityCheckResult {
        check_id: "parse_goal_stability".into(),
        description: "ParseGoal::Script and ::Module as_str values are stable".into(),
        verdict: if goals_stable {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: format!(
            "Script={}, Module={}",
            ParseGoal::Script.as_str(),
            ParseGoal::Module.as_str()
        ),
    });

    // 5. Parser mode stability
    let mode_stable = ParserMode::ScalarReference.as_str() == "scalar_reference";
    results.push(CompatibilityCheckResult {
        check_id: "parser_mode_stability".into(),
        description: "ParserMode::ScalarReference as_str is stable".into(),
        verdict: if mode_stable {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: format!("ScalarReference={}", ParserMode::ScalarReference.as_str()),
    });

    // 6. Default budget values stability
    let budget = ParserBudget::default();
    let budget_stable = budget.max_source_bytes == 1_048_576
        && budget.max_token_count == 65_536
        && budget.max_recursion_depth == 256;
    results.push(CompatibilityCheckResult {
        check_id: "default_budget_stability".into(),
        description: "Default ParserBudget values are stable".into(),
        verdict: if budget_stable {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: format!(
            "max_source_bytes={}, max_token_count={}, max_recursion_depth={}",
            budget.max_source_bytes, budget.max_token_count, budget.max_recursion_depth
        ),
    });

    // 7. Event kind enum stability
    let event_kinds_stable = ParseEventKind::ParseStarted.as_str() == "parse_started"
        && ParseEventKind::StatementParsed.as_str() == "statement_parsed"
        && ParseEventKind::ParseCompleted.as_str() == "parse_completed"
        && ParseEventKind::ParseFailed.as_str() == "parse_failed";
    results.push(CompatibilityCheckResult {
        check_id: "event_kind_stability".into(),
        description: "ParseEventKind as_str values are stable".into(),
        verdict: if event_kinds_stable {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: format!(
            "ParseStarted={}, StatementParsed={}, ParseCompleted={}, ParseFailed={}",
            ParseEventKind::ParseStarted.as_str(),
            ParseEventKind::StatementParsed.as_str(),
            ParseEventKind::ParseCompleted.as_str(),
            ParseEventKind::ParseFailed.as_str(),
        ),
    });

    // 8. Budget kind enum stability
    let budget_kinds_stable = ParseBudgetKind::SourceBytes.as_str() == "source_bytes"
        && ParseBudgetKind::TokenCount.as_str() == "token_count"
        && ParseBudgetKind::RecursionDepth.as_str() == "recursion_depth";
    results.push(CompatibilityCheckResult {
        check_id: "budget_kind_stability".into(),
        description: "ParseBudgetKind as_str values are stable".into(),
        verdict: if budget_kinds_stable {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: format!(
            "SourceBytes={}, TokenCount={}, RecursionDepth={}",
            ParseBudgetKind::SourceBytes.as_str(),
            ParseBudgetKind::TokenCount.as_str(),
            ParseBudgetKind::RecursionDepth.as_str(),
        ),
    });

    // 9. Grammar coverage matrix has families
    let matrix = GrammarCompletenessMatrix::scalar_reference_es2020();
    let has_families = !matrix.families.is_empty();
    results.push(CompatibilityCheckResult {
        check_id: "grammar_matrix_populated".into(),
        description: "Grammar completeness matrix has at least one family".into(),
        verdict: if has_families {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: format!("{} families", matrix.families.len()),
    });

    // 10. Diagnostic category stability
    let categories_stable = ParseDiagnosticCategory::Input.as_str() == "input"
        && ParseDiagnosticCategory::Goal.as_str() == "goal"
        && ParseDiagnosticCategory::Syntax.as_str() == "syntax"
        && ParseDiagnosticCategory::Encoding.as_str() == "encoding"
        && ParseDiagnosticCategory::Resource.as_str() == "resource"
        && ParseDiagnosticCategory::System.as_str() == "system";
    results.push(CompatibilityCheckResult {
        check_id: "diagnostic_category_stability".into(),
        description: "ParseDiagnosticCategory as_str values are stable".into(),
        verdict: if categories_stable {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: "all 6 categories match".into(),
    });

    // 11. Diagnostic severity stability
    let severity_stable = ParseDiagnosticSeverity::Error.as_str() == "error"
        && ParseDiagnosticSeverity::Fatal.as_str() == "fatal";
    results.push(CompatibilityCheckResult {
        check_id: "diagnostic_severity_stability".into(),
        description: "ParseDiagnosticSeverity as_str values are stable".into(),
        verdict: if severity_stable {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: format!(
            "Error={}, Fatal={}",
            ParseDiagnosticSeverity::Error.as_str(),
            ParseDiagnosticSeverity::Fatal.as_str()
        ),
    });

    // 12. Manifest surface count
    let manifest = ApiStabilityManifest::current();
    results.push(CompatibilityCheckResult {
        check_id: "manifest_surface_count".into(),
        description: "API stability manifest tracks expected number of surfaces".into(),
        verdict: if manifest.surface_count() == 8 {
            CheckVerdict::Pass
        } else {
            CheckVerdict::Fail
        },
        detail: format!("{} surfaces tracked", manifest.surface_count()),
    });

    CompatibilityReport {
        contract_version: API_STABILITY_CONTRACT_VERSION.into(),
        schema_version: API_STABILITY_SCHEMA_VERSION.into(),
        results,
    }
}

// ---------------------------------------------------------------------------
// Integration log entry for structured downstream logging
// ---------------------------------------------------------------------------

/// Structured log entry emitted by integration consumers of the parser API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationLogEntry {
    pub operation: String,
    pub source_label: String,
    pub goal: ParseGoal,
    pub mode: ParserMode,
    pub outcome: IntegrationOutcome,
    pub ast_hash: Option<String>,
    pub event_count: Option<u64>,
    pub diagnostic_code: Option<String>,
    pub detail: String,
}

/// Outcome classification for integration log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrationOutcome {
    Success,
    ParseFailure,
    MaterializationFailure,
    VersionMismatch,
}

impl IntegrationLogEntry {
    pub fn from_parse_success(
        source_label: &str,
        goal: ParseGoal,
        tree: &SyntaxTree,
        event_ir: &ParseEventIr,
    ) -> Self {
        Self {
            operation: "parse".into(),
            source_label: source_label.into(),
            goal,
            mode: event_ir.parser_mode,
            outcome: IntegrationOutcome::Success,
            ast_hash: Some(tree.canonical_hash()),
            event_count: Some(event_ir.events.len() as u64),
            diagnostic_code: None,
            detail: format!(
                "{} statements, {} events",
                tree.body.len(),
                event_ir.events.len()
            ),
        }
    }

    pub fn from_parse_failure(source_label: &str, goal: ParseGoal, error: &ParseError) -> Self {
        let diagnostic = error.normalized_diagnostic();
        Self {
            operation: "parse".into(),
            source_label: source_label.into(),
            goal,
            mode: ParserMode::ScalarReference,
            outcome: IntegrationOutcome::ParseFailure,
            ast_hash: None,
            event_count: None,
            diagnostic_code: Some(diagnostic.diagnostic_code),
            detail: error.message.clone(),
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "ast_hash".into(),
            self.ast_hash
                .as_ref()
                .map(|h| CanonicalValue::String(h.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("detail".into(), CanonicalValue::String(self.detail.clone()));
        map.insert(
            "diagnostic_code".into(),
            self.diagnostic_code
                .as_ref()
                .map(|c| CanonicalValue::String(c.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "event_count".into(),
            self.event_count
                .map(CanonicalValue::U64)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "goal".into(),
            CanonicalValue::String(self.goal.as_str().into()),
        );
        map.insert(
            "mode".into(),
            CanonicalValue::String(self.mode.as_str().into()),
        );
        map.insert(
            "operation".into(),
            CanonicalValue::String(self.operation.clone()),
        );
        map.insert(
            "outcome".into(),
            CanonicalValue::String(
                serde_json::to_string(&self.outcome)
                    .expect("outcome must serialize for canonical hash"),
            ),
        );
        map.insert(
            "source_label".into(),
            CanonicalValue::String(self.source_label.clone()),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Migration compatibility check
// ---------------------------------------------------------------------------

/// Check whether an artifact serialised with a given version string is
/// acceptable under the current minimum-compatibility policy.
pub fn is_version_compatible(surface_id: &str, artifact_version: &str) -> bool {
    let manifest = ApiStabilityManifest::current();
    match manifest.entry(surface_id) {
        Some(entry) => artifact_version >= entry.minimum_compatible_version.as_str(),
        None => false,
    }
}

/// Summary of a migration compatibility assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAssessment {
    pub surface_id: String,
    pub artifact_version: String,
    pub current_version: String,
    pub minimum_compatible: String,
    pub compatible: bool,
    pub needs_migration: bool,
}

/// Assess whether an artifact from a specific surface version needs migration.
pub fn assess_migration(surface_id: &str, artifact_version: &str) -> Option<MigrationAssessment> {
    let manifest = ApiStabilityManifest::current();
    manifest.entry(surface_id).map(|entry| {
        let compatible = artifact_version >= entry.minimum_compatible_version.as_str();
        let needs_migration = artifact_version != entry.current_version;
        MigrationAssessment {
            surface_id: surface_id.into(),
            artifact_version: artifact_version.into(),
            current_version: entry.current_version.clone(),
            minimum_compatible: entry.minimum_compatible_version.clone(),
            compatible,
            needs_migration,
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::SourceSpan;
    use crate::parser::{ParseDiagnosticEnvelope, ParseEventMaterializationErrorCode};

    // -- Manifest tests --

    #[test]
    fn manifest_current_has_expected_surfaces() {
        let m = ApiStabilityManifest::current();
        assert_eq!(m.surface_count(), 8);
        assert_eq!(m.contract_version, API_STABILITY_CONTRACT_VERSION);
        assert_eq!(m.schema_version, API_STABILITY_SCHEMA_VERSION);
    }

    #[test]
    fn manifest_lookup_by_surface_id() {
        let m = ApiStabilityManifest::current();
        let ast = m.entry("ast.contract").unwrap();
        assert_eq!(ast.current_version, CANONICAL_AST_CONTRACT_VERSION);
        assert_eq!(ast.evolution_rule, EvolutionRule::AdditiveOnly);
    }

    #[test]
    fn manifest_lookup_missing_surface_returns_none() {
        let m = ApiStabilityManifest::current();
        assert!(m.entry("nonexistent.surface").is_none());
    }

    #[test]
    fn manifest_canonical_hash_deterministic() {
        let m1 = ApiStabilityManifest::current();
        let m2 = ApiStabilityManifest::current();
        assert_eq!(m1.canonical_hash(), m2.canonical_hash());
    }

    #[test]
    fn manifest_all_surfaces_have_versions() {
        let m = ApiStabilityManifest::current();
        for entry in &m.entries {
            assert!(
                !entry.current_version.is_empty(),
                "empty version for {}",
                entry.surface_id
            );
            assert!(!entry.minimum_compatible_version.is_empty());
        }
    }

    #[test]
    fn manifest_frozen_surfaces_have_matching_min_compat() {
        let m = ApiStabilityManifest::current();
        for entry in &m.entries {
            if entry.evolution_rule == EvolutionRule::Frozen {
                assert_eq!(
                    entry.current_version, entry.minimum_compatible_version,
                    "frozen surface {} min compat must equal current",
                    entry.surface_id
                );
            }
        }
    }

    // -- Golden version vector tests --

    #[test]
    fn golden_v1_matches_live_constants() {
        let golden = GoldenVersionVector::v1();
        let mismatches = golden.check_against_live();
        assert!(
            mismatches.is_empty(),
            "golden version mismatches: {:?}",
            mismatches
        );
    }

    #[test]
    fn golden_v1_all_fields_populated() {
        let g = GoldenVersionVector::v1();
        assert!(!g.ast_contract.is_empty());
        assert!(!g.ast_schema.is_empty());
        assert!(!g.event_ir_contract.is_empty());
        assert!(!g.event_ir_schema.is_empty());
        assert!(!g.materializer_contract.is_empty());
        assert!(!g.diagnostic_taxonomy.is_empty());
    }

    #[test]
    fn golden_v1_detects_hypothetical_drift() {
        let mut g = GoldenVersionVector::v1();
        g.ast_contract = "franken-engine.parser-ast.contract.v99".into();
        let mismatches = g.check_against_live();
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].0, "ast_contract");
    }

    // -- Compatibility report tests --

    #[test]
    fn compatibility_report_all_pass() {
        let report = run_compatibility_checks();
        assert!(
            report.all_passed(),
            "failed checks: {:?}",
            report
                .results
                .iter()
                .filter(|r| r.verdict == CheckVerdict::Fail)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn compatibility_report_check_count() {
        let report = run_compatibility_checks();
        assert_eq!(report.results.len(), 12);
    }

    #[test]
    fn compatibility_report_canonical_hash_deterministic() {
        let r1 = run_compatibility_checks();
        let r2 = run_compatibility_checks();
        assert_eq!(r1.canonical_hash(), r2.canonical_hash());
    }

    #[test]
    fn compatibility_report_pass_fail_counts() {
        let report = run_compatibility_checks();
        assert_eq!(report.pass_count(), 12);
        assert_eq!(report.fail_count(), 0);
    }

    // -- Ergonomic parse helpers --

    #[test]
    fn parse_script_simple() {
        let tree = parse_script("42;").unwrap();
        assert_eq!(tree.goal, ParseGoal::Script);
        assert!(!tree.body.is_empty());
    }

    #[test]
    fn parse_module_import() {
        let tree = parse_module("import x from 'y';").unwrap();
        assert_eq!(tree.goal, ParseGoal::Module);
        assert!(!tree.body.is_empty());
    }

    #[test]
    fn parse_script_empty_source_error() {
        let err = parse_script("").unwrap_err();
        assert_eq!(err.code, ParseErrorCode::EmptySource);
    }

    #[test]
    fn parse_module_empty_source_error() {
        let err = parse_module("").unwrap_err();
        assert_eq!(err.code, ParseErrorCode::EmptySource);
    }

    #[test]
    fn parse_with_audit_produces_event_ir() {
        let (result, event_ir) = parse_with_audit("42;", ParseGoal::Script);
        assert!(result.is_ok());
        assert_eq!(event_ir.schema_version, PARSE_EVENT_IR_SCHEMA_VERSION);
        assert_eq!(event_ir.contract_version, PARSE_EVENT_IR_CONTRACT_VERSION);
        assert!(!event_ir.events.is_empty());
    }

    #[test]
    fn parse_with_audit_failure_still_produces_event_ir() {
        let (result, event_ir) = parse_with_audit("", ParseGoal::Script);
        assert!(result.is_err());
        assert!(!event_ir.events.is_empty());
        assert!(
            event_ir
                .events
                .iter()
                .any(|e| e.kind == ParseEventKind::ParseFailed)
        );
    }

    #[test]
    fn parse_with_full_provenance_success() {
        let (result, event_ir, mat_result) = parse_with_full_provenance("42;", ParseGoal::Script);
        assert!(result.is_ok());
        assert!(!event_ir.events.is_empty());
        let mat = mat_result.unwrap();
        assert_eq!(
            mat.contract_version,
            PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION
        );
    }

    #[test]
    fn parse_with_full_provenance_failure() {
        let (result, event_ir, mat_result) = parse_with_full_provenance("", ParseGoal::Script);
        assert!(result.is_err());
        assert!(!event_ir.events.is_empty());
        assert!(mat_result.is_err());
    }

    // -- AST roundtrip stability --

    #[test]
    fn ast_canonical_hash_deterministic() {
        let t1 = parse_script("42;").unwrap();
        let t2 = parse_script("42;").unwrap();
        assert_eq!(t1.canonical_hash(), t2.canonical_hash());
    }

    #[test]
    fn ast_canonical_hash_differs_for_different_input() {
        let t1 = parse_script("42;").unwrap();
        let t2 = parse_script("43;").unwrap();
        assert_ne!(t1.canonical_hash(), t2.canonical_hash());
    }

    #[test]
    fn ast_serde_roundtrip() {
        let tree = parse_script("42;").unwrap();
        let json = serde_json::to_string(&tree).unwrap();
        let restored: SyntaxTree = serde_json::from_str(&json).unwrap();
        assert_eq!(tree, restored);
    }

    #[test]
    fn ast_canonical_hash_stable_across_serde_roundtrip() {
        let tree = parse_script("42;").unwrap();
        let hash_before = tree.canonical_hash();
        let json = serde_json::to_string(&tree).unwrap();
        let restored: SyntaxTree = serde_json::from_str(&json).unwrap();
        assert_eq!(hash_before, restored.canonical_hash());
    }

    // -- Event IR stability --

    #[test]
    fn event_ir_serde_roundtrip() {
        let (_, ir) = parse_with_audit("42;", ParseGoal::Script);
        let json = serde_json::to_string(&ir).unwrap();
        let restored: ParseEventIr = serde_json::from_str(&json).unwrap();
        assert_eq!(ir, restored);
    }

    #[test]
    fn event_ir_canonical_hash_deterministic() {
        let (_, ir1) = parse_with_audit("42;", ParseGoal::Script);
        let (_, ir2) = parse_with_audit("42;", ParseGoal::Script);
        assert_eq!(ir1.canonical_hash(), ir2.canonical_hash());
    }

    #[test]
    fn event_ir_trace_id_has_stable_prefix() {
        let (_, ir) = parse_with_audit("42;", ParseGoal::Script);
        for event in &ir.events {
            assert!(
                event.trace_id.starts_with(PARSE_EVENT_IR_TRACE_PREFIX),
                "trace_id {} missing prefix {}",
                event.trace_id,
                PARSE_EVENT_IR_TRACE_PREFIX
            );
        }
    }

    #[test]
    fn event_ir_decision_id_has_stable_prefix() {
        let (_, ir) = parse_with_audit("42;", ParseGoal::Script);
        for event in &ir.events {
            assert!(
                event
                    .decision_id
                    .starts_with(PARSE_EVENT_IR_DECISION_PREFIX),
                "decision_id {} missing prefix {}",
                event.decision_id,
                PARSE_EVENT_IR_DECISION_PREFIX
            );
        }
    }

    #[test]
    fn event_ir_policy_and_component_stable() {
        let (_, ir) = parse_with_audit("42;", ParseGoal::Script);
        for event in &ir.events {
            assert_eq!(event.policy_id, PARSE_EVENT_IR_POLICY_ID);
            assert_eq!(event.component, PARSE_EVENT_IR_COMPONENT);
        }
    }

    #[test]
    fn event_ir_sequence_monotonically_increasing() {
        let (_, ir) = parse_with_audit("42;", ParseGoal::Script);
        for (i, event) in ir.events.iter().enumerate() {
            assert_eq!(event.sequence, i as u64);
        }
    }

    #[test]
    fn event_ir_starts_with_parse_started_ends_with_completed() {
        let (_, ir) = parse_with_audit("42;", ParseGoal::Script);
        assert_eq!(
            ir.events.first().unwrap().kind,
            ParseEventKind::ParseStarted
        );
        assert_eq!(
            ir.events.last().unwrap().kind,
            ParseEventKind::ParseCompleted
        );
    }

    // -- Materialisation stability --

    #[test]
    fn materialised_ast_serde_roundtrip() {
        let (_, _, mat_result) = parse_with_full_provenance("42;", ParseGoal::Script);
        let mat = mat_result.unwrap();
        let json = serde_json::to_string(&mat).unwrap();
        let restored: MaterializedSyntaxTree = serde_json::from_str(&json).unwrap();
        assert_eq!(mat, restored);
    }

    #[test]
    fn materialised_ast_node_ids_have_stable_prefix() {
        let (_, _, mat_result) = parse_with_full_provenance("42;", ParseGoal::Script);
        let mat = mat_result.unwrap();
        assert!(
            mat.root_node_id
                .starts_with(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX)
        );
        for node in &mat.statement_nodes {
            assert!(
                node.node_id
                    .starts_with(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX)
            );
        }
    }

    #[test]
    fn materialised_ast_canonical_hash_deterministic() {
        let (_, _, m1) = parse_with_full_provenance("42;", ParseGoal::Script);
        let (_, _, m2) = parse_with_full_provenance("42;", ParseGoal::Script);
        assert_eq!(m1.unwrap().canonical_hash(), m2.unwrap().canonical_hash());
    }

    // -- Diagnostic envelope stability --

    #[test]
    fn diagnostic_envelope_from_each_error_code() {
        for code in ParseErrorCode::ALL {
            let err = ParseError {
                code,
                message: "test".into(),
                source_label: "test.js".into(),
                span: None,
                witness: None,
            };
            let diag = err.normalized_diagnostic();
            assert_eq!(diag.parse_error_code, code);
            assert!(!diag.diagnostic_code.is_empty());
            assert_eq!(diag.schema_version, PARSER_DIAGNOSTIC_SCHEMA_VERSION);
            assert_eq!(diag.taxonomy_version, PARSER_DIAGNOSTIC_TAXONOMY_VERSION);
        }
    }

    #[test]
    fn diagnostic_envelope_serde_roundtrip() {
        let err = parse_script("").unwrap_err();
        let diag = err.normalized_diagnostic();
        let json = serde_json::to_string(&diag).unwrap();
        let restored: ParseDiagnosticEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(diag, restored);
    }

    #[test]
    fn diagnostic_envelope_canonical_hash_deterministic() {
        let err = parse_script("").unwrap_err();
        let d1 = err.normalized_diagnostic();
        let d2 = err.normalized_diagnostic();
        assert_eq!(d1.canonical_hash(), d2.canonical_hash());
    }

    // -- Migration compatibility --

    #[test]
    fn is_version_compatible_current_versions() {
        assert!(is_version_compatible(
            "ast.contract",
            CANONICAL_AST_CONTRACT_VERSION
        ));
        assert!(is_version_compatible(
            "event_ir.contract",
            PARSE_EVENT_IR_CONTRACT_VERSION
        ));
        assert!(is_version_compatible(
            "materializer.contract",
            PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION
        ));
    }

    #[test]
    fn is_version_compatible_unknown_surface() {
        assert!(!is_version_compatible("nonexistent", "v1"));
    }

    #[test]
    fn assess_migration_current_is_compatible() {
        let a = assess_migration("ast.contract", CANONICAL_AST_CONTRACT_VERSION).unwrap();
        assert!(a.compatible);
        assert!(!a.needs_migration);
    }

    #[test]
    fn assess_migration_unknown_surface_returns_none() {
        assert!(assess_migration("nonexistent", "v1").is_none());
    }

    #[test]
    fn assess_migration_old_version_needs_migration() {
        let a = assess_migration(
            "event_ir.contract",
            "franken-engine.parser-event-ir.contract.v1",
        )
        .unwrap();
        assert!(a.needs_migration);
    }

    // -- Integration log entry --

    #[test]
    fn integration_log_success() {
        let (result, ir) = parse_with_audit("42;", ParseGoal::Script);
        let tree = result.unwrap();
        let log = IntegrationLogEntry::from_parse_success("test.js", ParseGoal::Script, &tree, &ir);
        assert_eq!(log.outcome, IntegrationOutcome::Success);
        assert!(log.ast_hash.is_some());
        assert!(log.event_count.is_some());
        assert!(log.diagnostic_code.is_none());
    }

    #[test]
    fn integration_log_failure() {
        let err = parse_script("").unwrap_err();
        let log = IntegrationLogEntry::from_parse_failure("test.js", ParseGoal::Script, &err);
        assert_eq!(log.outcome, IntegrationOutcome::ParseFailure);
        assert!(log.ast_hash.is_none());
        assert!(log.diagnostic_code.is_some());
    }

    #[test]
    fn integration_log_canonical_value_deterministic() {
        let (result, ir) = parse_with_audit("42;", ParseGoal::Script);
        let tree = result.unwrap();
        let l1 = IntegrationLogEntry::from_parse_success("test.js", ParseGoal::Script, &tree, &ir);
        let l2 = IntegrationLogEntry::from_parse_success("test.js", ParseGoal::Script, &tree, &ir);
        let b1 = deterministic_serde::encode_value(&l1.canonical_value());
        let b2 = deterministic_serde::encode_value(&l2.canonical_value());
        assert_eq!(b1, b2);
    }

    #[test]
    fn integration_log_serde_roundtrip() {
        let (result, ir) = parse_with_audit("42;", ParseGoal::Script);
        let tree = result.unwrap();
        let log = IntegrationLogEntry::from_parse_success("test.js", ParseGoal::Script, &tree, &ir);
        let json = serde_json::to_string(&log).unwrap();
        let restored: IntegrationLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(log, restored);
    }

    // -- Parser options and budget ergonomics --

    #[test]
    fn parser_options_default_mode() {
        let opts = ParserOptions::default();
        assert_eq!(opts.mode, ParserMode::ScalarReference);
    }

    #[test]
    fn parser_budget_serde_roundtrip() {
        let budget = ParserBudget::default();
        let json = serde_json::to_string(&budget).unwrap();
        let restored: ParserBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, restored);
    }

    #[test]
    fn parser_budget_custom_values() {
        let budget = ParserBudget {
            max_source_bytes: 512,
            max_token_count: 100,
            max_recursion_depth: 32,
        };
        let parser = CanonicalEs2020Parser;
        let opts = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget,
        };
        let result = parser.parse_with_options("42;", ParseGoal::Script, &opts);
        assert!(result.is_ok());
    }

    #[test]
    fn parser_budget_source_too_large_triggers_error() {
        let budget = ParserBudget {
            max_source_bytes: 1,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        };
        let parser = CanonicalEs2020Parser;
        let opts = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget,
        };
        let err = parser
            .parse_with_options("42;", ParseGoal::Script, &opts)
            .unwrap_err();
        assert!(
            err.code == ParseErrorCode::SourceTooLarge
                || err.code == ParseErrorCode::BudgetExceeded
        );
    }

    // -- Grammar coverage --

    #[test]
    fn grammar_matrix_parser_mode_scalar_reference() {
        let parser = CanonicalEs2020Parser;
        let matrix = parser.scalar_reference_grammar_matrix();
        assert_eq!(matrix.parser_mode, ParserMode::ScalarReference);
    }

    #[test]
    fn grammar_matrix_summary_nonzero_families() {
        let matrix = GrammarCompletenessMatrix::scalar_reference_es2020();
        let summary = matrix.summary();
        assert!(summary.family_count > 0);
    }

    #[test]
    fn grammar_matrix_serde_roundtrip() {
        let matrix = GrammarCompletenessMatrix::scalar_reference_es2020();
        let json = serde_json::to_string(&matrix).unwrap();
        let restored: GrammarCompletenessMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(matrix, restored);
    }

    // -- Evolution rule semantics --

    #[test]
    fn evolution_rule_serde_roundtrip() {
        for rule in [
            EvolutionRule::AdditiveOnly,
            EvolutionRule::Frozen,
            EvolutionRule::Internal,
        ] {
            let json = serde_json::to_string(&rule).unwrap();
            let restored: EvolutionRule = serde_json::from_str(&json).unwrap();
            assert_eq!(rule, restored);
        }
    }

    #[test]
    fn api_surface_entry_serde_roundtrip() {
        let entry = ApiSurfaceEntry {
            surface_id: "test.surface".into(),
            description: "test description".into(),
            evolution_rule: EvolutionRule::AdditiveOnly,
            current_version: "v1".into(),
            minimum_compatible_version: "v1".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: ApiSurfaceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
    }

    // -- Cross-goal consistency --

    #[test]
    fn module_export_parses_correctly() {
        let tree = parse_module("export default 42;").unwrap();
        assert_eq!(tree.goal, ParseGoal::Module);
        assert_eq!(tree.body.len(), 1);
    }

    #[test]
    fn script_and_module_produce_different_hashes_for_same_source() {
        let s = parse_script("42;").unwrap();
        let m = parse_module("42;").unwrap();
        assert_ne!(s.canonical_hash(), m.canonical_hash());
    }

    // -- Check verdict types --

    #[test]
    fn check_verdict_serde_roundtrip() {
        for v in [
            CheckVerdict::Pass,
            CheckVerdict::Fail,
            CheckVerdict::Skipped,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: CheckVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn integration_outcome_serde_roundtrip() {
        for o in [
            IntegrationOutcome::Success,
            IntegrationOutcome::ParseFailure,
            IntegrationOutcome::MaterializationFailure,
            IntegrationOutcome::VersionMismatch,
        ] {
            let json = serde_json::to_string(&o).unwrap();
            let restored: IntegrationOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(o, restored);
        }
    }

    // -- Materialization error codes --

    #[test]
    fn materialization_failure_produces_correct_error_code() {
        let (_, _, mat) = parse_with_full_provenance("", ParseGoal::Script);
        let err = mat.unwrap_err();
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::ParseFailedEventStream
        );
    }

    // -- SourceSpan stability --

    #[test]
    fn source_span_serde_roundtrip() {
        let span = SourceSpan::new(0, 3, 1, 1, 1, 4);
        let json = serde_json::to_string(&span).unwrap();
        let restored: SourceSpan = serde_json::from_str(&json).unwrap();
        assert_eq!(span, restored);
    }

    #[test]
    fn source_span_canonical_value_deterministic() {
        let s1 = SourceSpan::new(0, 3, 1, 1, 1, 4);
        let s2 = SourceSpan::new(0, 3, 1, 1, 1, 4);
        let b1 = deterministic_serde::encode_value(&s1.canonical_value());
        let b2 = deterministic_serde::encode_value(&s2.canonical_value());
        assert_eq!(b1, b2);
    }

    // -- Error display stability --

    #[test]
    fn parse_error_display_no_span() {
        let err = parse_script("").unwrap_err();
        let display = format!("{}", err);
        assert!(display.contains("EmptySource"));
    }

    #[test]
    fn parse_error_is_std_error() {
        let err = parse_script("").unwrap_err();
        let _: &dyn std::error::Error = &err;
    }

    // -- Multiple statement parsing --

    #[test]
    fn multi_statement_event_ir_has_expected_event_count() {
        let source = "import x from 'y';\n42;";
        let (result, ir) = parse_with_audit(source, ParseGoal::Module);
        assert!(result.is_ok());
        let tree = result.unwrap();
        // 1 ParseStarted + N StatementParsed + 1 ParseCompleted = N + 2
        assert_eq!(ir.events.len(), tree.body.len() + 2);
    }

    #[test]
    fn multi_statement_materialised_nodes_match_tree() {
        let source = "import x from 'y';\n42;";
        let (result, _, mat_result) = parse_with_full_provenance(source, ParseGoal::Module);
        let tree = result.unwrap();
        let mat = mat_result.unwrap();
        assert_eq!(mat.statement_nodes.len(), tree.body.len());
    }

    // -- Taxonomy --

    #[test]
    fn taxonomy_v1_covers_all_codes() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        for code in ParseErrorCode::ALL {
            assert!(
                taxonomy.rule_for(code).is_some(),
                "missing taxonomy rule for {:?}",
                code
            );
        }
    }

    #[test]
    fn taxonomy_v1_serde_roundtrip() {
        let t = ParseDiagnosticTaxonomy::v1();
        let json = serde_json::to_string(&t).unwrap();
        let restored: ParseDiagnosticTaxonomy = serde_json::from_str(&json).unwrap();
        assert_eq!(t, restored);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn evolution_rule_debug_distinct() {
        let all = [
            EvolutionRule::AdditiveOnly,
            EvolutionRule::Frozen,
            EvolutionRule::Internal,
        ];
        let set: std::collections::BTreeSet<String> =
            all.iter().map(|r| format!("{r:?}")).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn check_verdict_debug_distinct() {
        let all = [
            CheckVerdict::Pass,
            CheckVerdict::Fail,
            CheckVerdict::Skipped,
        ];
        let set: std::collections::BTreeSet<String> =
            all.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn integration_outcome_debug_distinct() {
        let all = [
            IntegrationOutcome::Success,
            IntegrationOutcome::ParseFailure,
            IntegrationOutcome::MaterializationFailure,
            IntegrationOutcome::VersionMismatch,
        ];
        let set: std::collections::BTreeSet<String> =
            all.iter().map(|o| format!("{o:?}")).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn api_stability_manifest_serde_roundtrip() {
        let manifest = ApiStabilityManifest::current();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: ApiStabilityManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }
}
