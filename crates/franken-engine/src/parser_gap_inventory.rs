use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::SourceSpan;
use crate::deterministic_serde::{self, CanonicalValue};
use crate::parser::{
    PARSER_DIAGNOSTIC_HASH_ALGORITHM, PARSER_DIAGNOSTIC_HASH_PREFIX,
    PARSER_DIAGNOSTIC_TAXONOMY_VERSION, ParseDiagnosticCategory, ParseDiagnosticEnvelope,
    ParseDiagnosticSeverity, ParseErrorCode,
};

pub const UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION: &str =
    "franken-engine.unsupported-syntax-diagnostic.v1";
pub const PARSER_GAP_INVENTORY_SCHEMA_VERSION: &str = "franken-engine.parser-gap-inventory.v1";
pub const PARSER_GAP_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.parser-gap-inventory.run-manifest.v1";
pub const PARSER_GAP_EVENT_SCHEMA_VERSION: &str = "franken-engine.parser-gap-inventory.event.v1";
pub const PARSER_GAP_COMPONENT: &str = "parser_gap_inventory";
pub const PARSER_GAP_POLICY_ID: &str = "franken-engine.parser-gap-inventory.policy.v1";

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserGapStage {
    Ir0ToIr1,
    Ir1ToIr3,
}

impl ParserGapStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ir0ToIr1 => "ir0_to_ir1",
            Self::Ir1ToIr3 => "ir1_to_ir3",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserGapRemediationStatus {
    FailClosed,
    OpenPlaceholder,
}

impl ParserGapRemediationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::OpenPlaceholder => "open_placeholder",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParserGapSiteId {
    ForInStatementPlaceholder,
    ForOfStatementPlaceholder,
    NewExpressionCallPlaceholder,
    TemplateLiteralRawPlaceholder,
    BinaryNonArithmeticAddPlaceholder,
    NonIdentifierAssignmentNopPlaceholder,
}

impl ParserGapSiteId {
    pub const ALL: [Self; 6] = [
        Self::BinaryNonArithmeticAddPlaceholder,
        Self::ForInStatementPlaceholder,
        Self::ForOfStatementPlaceholder,
        Self::NewExpressionCallPlaceholder,
        Self::NonIdentifierAssignmentNopPlaceholder,
        Self::TemplateLiteralRawPlaceholder,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForInStatementPlaceholder => "lower_ir0_to_ir1.for_in_placeholder",
            Self::ForOfStatementPlaceholder => "lower_ir0_to_ir1.for_of_placeholder",
            Self::NewExpressionCallPlaceholder => "lower_ir0_to_ir1.new_call_placeholder",
            Self::TemplateLiteralRawPlaceholder => {
                "lower_ir0_to_ir1.template_literal_raw_placeholder"
            }
            Self::BinaryNonArithmeticAddPlaceholder => {
                "lower_ir1_to_ir3.binary_non_arithmetic_add_placeholder"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "lower_ir0_to_ir1.assignment_non_identifier_nop_placeholder"
            }
        }
    }

    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::ForInStatementPlaceholder => "FE-PARSER-GAP-FOR-IN-0001",
            Self::ForOfStatementPlaceholder => "FE-PARSER-GAP-FOR-OF-0001",
            Self::NewExpressionCallPlaceholder => "FE-PARSER-GAP-NEW-0001",
            Self::TemplateLiteralRawPlaceholder => "FE-PARSER-GAP-TEMPLATE-0001",
            Self::BinaryNonArithmeticAddPlaceholder => "FE-PARSER-GAP-BINARY-0001",
            Self::NonIdentifierAssignmentNopPlaceholder => "FE-PARSER-GAP-ASSIGN-0001",
        }
    }

    pub const fn stage(self) -> ParserGapStage {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => ParserGapStage::Ir1ToIr3,
            Self::ForInStatementPlaceholder
            | Self::ForOfStatementPlaceholder
            | Self::NewExpressionCallPlaceholder
            | Self::TemplateLiteralRawPlaceholder
            | Self::NonIdentifierAssignmentNopPlaceholder => ParserGapStage::Ir0ToIr1,
        }
    }

    pub const fn remediation_status(self) -> ParserGapRemediationStatus {
        match self {
            Self::ForInStatementPlaceholder
            | Self::ForOfStatementPlaceholder
            | Self::NewExpressionCallPlaceholder
            | Self::TemplateLiteralRawPlaceholder => ParserGapRemediationStatus::FailClosed,
            Self::BinaryNonArithmeticAddPlaceholder
            | Self::NonIdentifierAssignmentNopPlaceholder => {
                ParserGapRemediationStatus::OpenPlaceholder
            }
        }
    }

    pub const fn owner(self) -> &'static str {
        "lowering_pipeline"
    }

    pub const fn feature_family(self) -> &'static str {
        match self {
            Self::ForInStatementPlaceholder => "for_in_statement",
            Self::ForOfStatementPlaceholder => "for_of_statement",
            Self::NewExpressionCallPlaceholder => "new_expression",
            Self::TemplateLiteralRawPlaceholder => "template_literal",
            Self::BinaryNonArithmeticAddPlaceholder => "binary_non_arithmetic_expression",
            Self::NonIdentifierAssignmentNopPlaceholder => "member_assignment_expression",
        }
    }

    pub const fn api_surface(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => "lower_ir1_to_ir3",
            Self::ForInStatementPlaceholder
            | Self::ForOfStatementPlaceholder
            | Self::NewExpressionCallPlaceholder
            | Self::TemplateLiteralRawPlaceholder
            | Self::NonIdentifierAssignmentNopPlaceholder => "lower_ir0_to_ir1",
        }
    }

    pub const fn syntax_shape(self) -> &'static str {
        match self {
            Self::ForInStatementPlaceholder => "for (let key in object) { ... }",
            Self::ForOfStatementPlaceholder => "for (const item of iterable) { ... }",
            Self::NewExpressionCallPlaceholder => "new Ctor(arg1, arg2)",
            Self::TemplateLiteralRawPlaceholder => "`hello ${name}`",
            Self::BinaryNonArithmeticAddPlaceholder => "a < b, a && b, a | b",
            Self::NonIdentifierAssignmentNopPlaceholder => "obj[prop] = value",
        }
    }

    pub const fn observed_fallback_behavior(self) -> &'static str {
        match self {
            Self::ForInStatementPlaceholder => {
                "historically evaluated the object for side effects, initialized the loop binding to undefined, and ran the body once"
            }
            Self::ForOfStatementPlaceholder => {
                "historically evaluated the iterable for side effects, initialized the loop binding to undefined, and ran the body once"
            }
            Self::NewExpressionCallPlaceholder => {
                "historically lowered constructors as plain calls, dropping allocation semantics"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "historically lowered template literals to the static quasi string and discarded interpolation semantics"
            }
            Self::BinaryNonArithmeticAddPlaceholder => {
                "still lowers comparisons, logical operators, and bitwise operators to an Add IR3 instruction placeholder"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "still lowers property and other non-identifier assignments to a Nop placeholder"
            }
        }
    }

    pub const fn required_fail_closed_contract(self) -> &'static str {
        match self {
            Self::ForInStatementPlaceholder => {
                "reject before IR1 lowering with FE-PARSER-GAP-FOR-IN-0001 instead of executing placeholder iteration"
            }
            Self::ForOfStatementPlaceholder => {
                "reject before IR1 lowering with FE-PARSER-GAP-FOR-OF-0001 instead of executing placeholder iteration"
            }
            Self::NewExpressionCallPlaceholder => {
                "reject before IR1 lowering with FE-PARSER-GAP-NEW-0001 instead of emitting a call placeholder"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "reject before IR1 lowering with FE-PARSER-GAP-TEMPLATE-0001 instead of emitting a raw-string placeholder"
            }
            Self::BinaryNonArithmeticAddPlaceholder => {
                "reject before IR3 lowering with FE-PARSER-GAP-BINARY-0001 instead of emitting an Add placeholder"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "reject before IR1 lowering with FE-PARSER-GAP-ASSIGN-0001 instead of emitting a Nop placeholder"
            }
        }
    }

    pub const fn source_reference(self) -> &'static str {
        match self {
            Self::ForInStatementPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_statement_to_ir1_with_flow/Statement::ForIn"
            }
            Self::ForOfStatementPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_statement_to_ir1_with_flow/Statement::ForOf"
            }
            Self::NewExpressionCallPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_expression_to_ir1/Expression::New"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_expression_to_ir1/Expression::TemplateLiteral"
            }
            Self::BinaryNonArithmeticAddPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_ir1_to_ir2/Ir1Op::BinaryOp"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_expression_to_ir1/Expression::Assignment"
            }
        }
    }

    pub const fn message_template(self) -> &'static str {
        match self {
            Self::ForInStatementPlaceholder => {
                "for-in lowering is not implemented; fail-closed parser-gap contract rejected placeholder execution"
            }
            Self::ForOfStatementPlaceholder => {
                "for-of lowering is not implemented; fail-closed parser-gap contract rejected placeholder execution"
            }
            Self::NewExpressionCallPlaceholder => {
                "constructor lowering is not implemented; fail-closed parser-gap contract rejected call placeholder lowering"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "template literal lowering is not implemented; fail-closed parser-gap contract rejected raw-string placeholder lowering"
            }
            Self::BinaryNonArithmeticAddPlaceholder => {
                "non-arithmetic binary lowering is not implemented; fail-closed parser-gap contract must reject add placeholder lowering"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "non-identifier assignment lowering is not implemented; fail-closed parser-gap contract must reject nop placeholder lowering"
            }
        }
    }

    pub const fn blocking_workloads(self) -> &'static [&'static str] {
        match self {
            Self::ForInStatementPlaceholder => &[
                "migration readiness scans that enumerate object keys",
                "compatibility probes that depend on full for-in property traversal",
            ],
            Self::ForOfStatementPlaceholder => &[
                "iterator-heavy workloads over arrays, sets, and custom iterables",
                "runtime compatibility smoke tests that depend on protocol-driven iteration",
            ],
            Self::NewExpressionCallPlaceholder => &[
                "constructor-based package bootstrap paths",
                "Date/URL/Map/Set allocation flows during migration readiness checks",
            ],
            Self::TemplateLiteralRawPlaceholder => &[
                "diagnostic and URL construction that depends on interpolation semantics",
                "module-resolution scaffolds that rely on computed template strings",
            ],
            Self::BinaryNonArithmeticAddPlaceholder => &[
                "branch guards driven by comparisons and logical operators",
                "bitwise-heavy compatibility suites and parser promotion gates",
            ],
            Self::NonIdentifierAssignmentNopPlaceholder => &[
                "object mutation workloads that assign through member expressions",
                "extension host compatibility probes that depend on property writes",
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserGapSiteDescriptor {
    pub site_id: String,
    pub stage: ParserGapStage,
    pub remediation_status: ParserGapRemediationStatus,
    pub owner: String,
    pub feature_family: String,
    pub api_surface: String,
    pub syntax_shape: String,
    pub observed_fallback_behavior: String,
    pub required_fail_closed_contract: String,
    pub desired_diagnostic_code: String,
    pub blocking_workloads: Vec<String>,
    pub source_reference: String,
}

impl ParserGapSiteDescriptor {
    pub fn from_site(site: ParserGapSiteId) -> Self {
        Self {
            site_id: site.as_str().to_string(),
            stage: site.stage(),
            remediation_status: site.remediation_status(),
            owner: site.owner().to_string(),
            feature_family: site.feature_family().to_string(),
            api_surface: site.api_surface().to_string(),
            syntax_shape: site.syntax_shape().to_string(),
            observed_fallback_behavior: site.observed_fallback_behavior().to_string(),
            required_fail_closed_contract: site.required_fail_closed_contract().to_string(),
            desired_diagnostic_code: site.diagnostic_code().to_string(),
            blocking_workloads: site
                .blocking_workloads()
                .iter()
                .map(|workload| workload.to_string())
                .collect(),
            source_reference: site.source_reference().to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserGapInventory {
    pub schema_version: String,
    pub diagnostic_schema_version: String,
    pub taxonomy_version: String,
    pub component: String,
    pub sites: Vec<ParserGapSiteDescriptor>,
}

impl ParserGapInventory {
    pub fn fail_closed_site_count(&self) -> usize {
        self.sites
            .iter()
            .filter(|site| site.remediation_status == ParserGapRemediationStatus::FailClosed)
            .count()
    }

    pub fn open_placeholder_site_count(&self) -> usize {
        self.sites
            .iter()
            .filter(|site| site.remediation_status == ParserGapRemediationStatus::OpenPlaceholder)
            .count()
    }
}

pub fn parser_gap_inventory() -> ParserGapInventory {
    let sites = ParserGapSiteId::ALL
        .iter()
        .map(|site| ParserGapSiteDescriptor::from_site(*site))
        .collect();
    ParserGapInventory {
        schema_version: PARSER_GAP_INVENTORY_SCHEMA_VERSION.to_string(),
        diagnostic_schema_version: UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION.to_string(),
        taxonomy_version: PARSER_DIAGNOSTIC_TAXONOMY_VERSION.to_string(),
        component: PARSER_GAP_COMPONENT.to_string(),
        sites,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedSyntaxDiagnostic {
    pub schema_version: String,
    pub taxonomy_version: String,
    pub hash_algorithm: String,
    pub hash_prefix: String,
    pub parse_error_code: ParseErrorCode,
    pub diagnostic_code: String,
    pub category: ParseDiagnosticCategory,
    pub severity: ParseDiagnosticSeverity,
    pub message_template: String,
    pub source_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<SourceSpan>,
    pub site_id: String,
    pub stage: ParserGapStage,
    pub owner: String,
    pub feature_family: String,
    pub api_surface: String,
}

impl UnsupportedSyntaxDiagnostic {
    pub fn from_site(
        site: ParserGapSiteId,
        source_label: impl Into<String>,
        span: Option<SourceSpan>,
    ) -> Self {
        Self {
            schema_version: UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION.to_string(),
            taxonomy_version: PARSER_DIAGNOSTIC_TAXONOMY_VERSION.to_string(),
            hash_algorithm: PARSER_DIAGNOSTIC_HASH_ALGORITHM.to_string(),
            hash_prefix: PARSER_DIAGNOSTIC_HASH_PREFIX.to_string(),
            parse_error_code: ParseErrorCode::UnsupportedSyntax,
            diagnostic_code: site.diagnostic_code().to_string(),
            category: ParseDiagnosticCategory::Syntax,
            severity: ParseDiagnosticSeverity::Error,
            message_template: site.message_template().to_string(),
            source_label: source_label.into(),
            span,
            site_id: site.as_str().to_string(),
            stage: site.stage(),
            owner: site.owner().to_string(),
            feature_family: site.feature_family().to_string(),
            api_surface: site.api_surface().to_string(),
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "taxonomy_version".to_string(),
            CanonicalValue::String(self.taxonomy_version.clone()),
        );
        map.insert(
            "hash_algorithm".to_string(),
            CanonicalValue::String(self.hash_algorithm.clone()),
        );
        map.insert(
            "hash_prefix".to_string(),
            CanonicalValue::String(self.hash_prefix.clone()),
        );
        map.insert(
            "parse_error_code".to_string(),
            CanonicalValue::String(self.parse_error_code.as_str().to_string()),
        );
        map.insert(
            "diagnostic_code".to_string(),
            CanonicalValue::String(self.diagnostic_code.clone()),
        );
        map.insert(
            "category".to_string(),
            CanonicalValue::String(self.category.as_str().to_string()),
        );
        map.insert(
            "severity".to_string(),
            CanonicalValue::String(self.severity.as_str().to_string()),
        );
        map.insert(
            "message_template".to_string(),
            CanonicalValue::String(self.message_template.clone()),
        );
        map.insert(
            "source_label".to_string(),
            CanonicalValue::String(self.source_label.clone()),
        );
        map.insert(
            "span".to_string(),
            self.span
                .as_ref()
                .map(SourceSpan::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "site_id".to_string(),
            CanonicalValue::String(self.site_id.clone()),
        );
        map.insert(
            "stage".to_string(),
            CanonicalValue::String(self.stage.as_str().to_string()),
        );
        map.insert(
            "owner".to_string(),
            CanonicalValue::String(self.owner.clone()),
        );
        map.insert(
            "feature_family".to_string(),
            CanonicalValue::String(self.feature_family.clone()),
        );
        map.insert(
            "api_surface".to_string(),
            CanonicalValue::String(self.api_surface.clone()),
        );
        CanonicalValue::Map(map)
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(deterministic_serde::encode_value(&self.canonical_value()));
        format!("{}{}", self.hash_prefix, hex::encode(digest))
    }

    pub fn parse_diagnostic_envelope(&self) -> ParseDiagnosticEnvelope {
        ParseDiagnosticEnvelope {
            schema_version: ParseDiagnosticEnvelope::schema_version().to_string(),
            taxonomy_version: self.taxonomy_version.clone(),
            hash_algorithm: self.hash_algorithm.clone(),
            hash_prefix: self.hash_prefix.clone(),
            parse_error_code: self.parse_error_code,
            diagnostic_code: self.diagnostic_code.clone(),
            category: self.category,
            severity: self.severity,
            message_template: self.message_template.clone(),
            source_label: self.source_label.clone(),
            span: self.span.clone(),
            budget_kind: None,
            witness: None,
        }
    }
}

impl fmt::Display for UnsupportedSyntaxDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (site={}, source={})",
            self.diagnostic_code, self.message_template, self.site_id, self.source_label
        )?;
        if let Some(span) = &self.span {
            write!(f, " at {}:{}", span.start_line, span.start_column)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserGapInventoryArtifactPaths {
    pub parser_gap_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserGapInventoryRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub site_count: u64,
    pub fail_closed_site_count: u64,
    pub open_placeholder_site_count: u64,
    pub diagnostic_schema_version: String,
    pub artifact_paths: ParserGapInventoryArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParserGapInventoryEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserGapInventoryArtifacts {
    pub out_dir: PathBuf,
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
    pub site_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ParserGapInventoryWriteError {
    #[error("failed to serialize `{path}`: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("bundle output directory is already locked by another writer: `{path}`")]
    Busy { path: String },
    #[error("failed to write `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
}

pub fn write_parser_gap_inventory_bundle(
    out_dir: impl AsRef<Path>,
    command_lines: &[String],
) -> Result<ParserGapInventoryArtifacts, ParserGapInventoryWriteError> {
    let out_dir = out_dir.as_ref().to_path_buf();
    fs::create_dir_all(&out_dir).map_err(|source| ParserGapInventoryWriteError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;

    let inventory = parser_gap_inventory();
    let inventory_path = out_dir.join("parser_gap_inventory.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");

    let inventory_bytes = canonical_json_bytes(&inventory, &inventory_path)?;
    let inventory_hash = sha256_hex(&inventory_bytes);

    let short_hash = inventory_hash.chars().take(16).collect::<String>();
    let trace_id = format!("trace-parser-gap-{short_hash}");
    let decision_id = format!("decision-parser-gap-{short_hash}");

    let manifest = ParserGapInventoryRunManifest {
        schema_version: PARSER_GAP_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARSER_GAP_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: PARSER_GAP_POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
        site_count: inventory.sites.len() as u64,
        fail_closed_site_count: inventory.fail_closed_site_count() as u64,
        open_placeholder_site_count: inventory.open_placeholder_site_count() as u64,
        diagnostic_schema_version: UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION.to_string(),
        artifact_paths: ParserGapInventoryArtifactPaths {
            parser_gap_inventory: "parser_gap_inventory.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };
    let manifest_bytes = canonical_json_bytes(&manifest, &run_manifest_path)?;

    let events = build_inventory_events(&inventory, &trace_id, &decision_id);
    let mut events_jsonl = String::new();
    for event in &events {
        let line =
            serde_json::to_string(event).map_err(|source| ParserGapInventoryWriteError::Json {
                path: events_path.display().to_string(),
                source,
            })?;
        events_jsonl.push_str(&line);
        events_jsonl.push('\n');
    }

    let mut commands_buf = String::new();
    for command in command_lines {
        commands_buf.push_str(command);
        commands_buf.push('\n');
    }

    let _bundle_lock = acquire_bundle_write_lock(&out_dir)?;
    remove_commit_marker(&run_manifest_path)?;
    write_atomic(&inventory_path, &inventory_bytes)?;
    write_atomic(&events_path, events_jsonl.as_bytes())?;
    write_atomic(&commands_path, commands_buf.as_bytes())?;
    // Publish the manifest last so its presence acts as a commit marker for the bundle.
    write_atomic(&run_manifest_path, &manifest_bytes)?;

    Ok(ParserGapInventoryArtifacts {
        out_dir,
        inventory_path,
        run_manifest_path,
        events_path,
        commands_path,
        inventory_hash,
        site_count: inventory.sites.len(),
    })
}

fn build_inventory_events(
    inventory: &ParserGapInventory,
    trace_id: &str,
    decision_id: &str,
) -> Vec<ParserGapInventoryEvent> {
    let mut events = vec![ParserGapInventoryEvent {
        schema_version: PARSER_GAP_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: PARSER_GAP_POLICY_ID.to_string(),
        component: PARSER_GAP_COMPONENT.to_string(),
        event: "inventory_started".to_string(),
        outcome: "started".to_string(),
        site_id: None,
        diagnostic_code: None,
        detail: Some("authoritative parser-gap inventory generation began".to_string()),
    }];

    events.extend(inventory.sites.iter().map(|site| ParserGapInventoryEvent {
        schema_version: PARSER_GAP_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: PARSER_GAP_POLICY_ID.to_string(),
        component: PARSER_GAP_COMPONENT.to_string(),
        event: "gap_site_recorded".to_string(),
        outcome: site.remediation_status.as_str().to_string(),
        site_id: Some(site.site_id.clone()),
        diagnostic_code: Some(site.desired_diagnostic_code.clone()),
        detail: Some(site.observed_fallback_behavior.clone()),
    }));

    events.push(ParserGapInventoryEvent {
        schema_version: PARSER_GAP_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: PARSER_GAP_POLICY_ID.to_string(),
        component: PARSER_GAP_COMPONENT.to_string(),
        event: "inventory_completed".to_string(),
        outcome: "completed".to_string(),
        site_id: None,
        diagnostic_code: None,
        detail: Some(format!(
            "{} sites recorded ({} fail-closed, {} open placeholders)",
            inventory.sites.len(),
            inventory.fail_closed_site_count(),
            inventory.open_placeholder_site_count()
        )),
    });

    events
}

fn canonical_json_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, ParserGapInventoryWriteError> {
    serde_json::to_vec(value).map_err(|source| ParserGapInventoryWriteError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn acquire_bundle_write_lock(
    out_dir: &Path,
) -> Result<BundleWriteLock, ParserGapInventoryWriteError> {
    let lock_path = out_dir.join(".parser_gap_inventory.lock");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(BundleWriteLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            Err(ParserGapInventoryWriteError::Busy {
                path: lock_path.display().to_string(),
            })
        }
        Err(source) => Err(ParserGapInventoryWriteError::Io {
            path: lock_path.display().to_string(),
            source,
        }),
    }
}

fn remove_commit_marker(path: &Path) -> Result<(), ParserGapInventoryWriteError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ParserGapInventoryWriteError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ParserGapInventoryWriteError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ParserGapInventoryWriteError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| ParserGapInventoryWriteError::Io {
        path: temp_path.display().to_string(),
        source,
    })?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(ParserGapInventoryWriteError::Io {
            path: path.display().to_string(),
            source,
        });
    }
    Ok(())
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let sequence = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = OsString::from(".");
    match path.file_name() {
        Some(file_name) => temp_name.push(file_name),
        None => temp_name.push("artifact"),
    }
    temp_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(temp_name)
}

#[derive(Debug)]
struct BundleWriteLock {
    path: PathBuf,
}

impl Drop for BundleWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        env::temp_dir().join(format!("frankenengine-{label}-{}-{nanos}", process::id()))
    }

    fn span() -> SourceSpan {
        SourceSpan {
            start_line: 2,
            start_column: 4,
            end_line: 2,
            end_column: 12,
            start_offset: 10,
            end_offset: 18,
        }
    }

    #[test]
    fn parser_gap_inventory_has_unique_site_ids_and_codes() {
        let inventory = parser_gap_inventory();
        let site_ids: std::collections::BTreeSet<&str> = inventory
            .sites
            .iter()
            .map(|site| site.site_id.as_str())
            .collect();
        let diagnostic_codes: std::collections::BTreeSet<&str> = inventory
            .sites
            .iter()
            .map(|site| site.desired_diagnostic_code.as_str())
            .collect();
        assert_eq!(site_ids.len(), ParserGapSiteId::ALL.len());
        assert_eq!(diagnostic_codes.len(), ParserGapSiteId::ALL.len());
        assert_eq!(inventory.fail_closed_site_count(), 4);
        assert_eq!(inventory.open_placeholder_site_count(), 2);
    }

    #[test]
    fn unsupported_syntax_diagnostic_projects_into_parser_envelope() {
        let diagnostic = UnsupportedSyntaxDiagnostic::from_site(
            ParserGapSiteId::ForInStatementPlaceholder,
            "ir0",
            Some(span()),
        );
        let envelope = diagnostic.parse_diagnostic_envelope();
        assert_eq!(envelope.parse_error_code, ParseErrorCode::UnsupportedSyntax);
        assert_eq!(envelope.diagnostic_code, "FE-PARSER-GAP-FOR-IN-0001");
        assert_eq!(envelope.category, ParseDiagnosticCategory::Syntax);
        assert_eq!(envelope.severity, ParseDiagnosticSeverity::Error);
        assert_eq!(envelope.span, Some(span()));
        assert!(
            diagnostic
                .canonical_hash()
                .starts_with(crate::parser::PARSER_DIAGNOSTIC_HASH_PREFIX)
        );
    }

    #[test]
    fn write_parser_gap_inventory_bundle_emits_expected_artifacts() {
        let out_dir = unique_temp_dir("parser-gap-inventory");
        let commands = vec![
            "franken_parser_gap_inventory".to_string(),
            "--out-dir".to_string(),
            "artifacts/parser_gap_inventory/test-run".to_string(),
        ];
        let artifacts =
            write_parser_gap_inventory_bundle(&out_dir, &commands).expect("bundle should write");
        assert!(artifacts.inventory_path.exists());
        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.commands_path.exists());

        let inventory: ParserGapInventory =
            serde_json::from_slice(&fs::read(&artifacts.inventory_path).expect("read inventory"))
                .expect("inventory json");
        assert_eq!(inventory.sites.len(), ParserGapSiteId::ALL.len());

        let manifest: ParserGapInventoryRunManifest =
            serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
                .expect("manifest json");
        assert_eq!(manifest.site_count as usize, ParserGapSiteId::ALL.len());
        assert_eq!(manifest.fail_closed_site_count, 4);
        assert_eq!(manifest.open_placeholder_site_count, 2);
        assert_eq!(
            manifest.artifact_paths.parser_gap_inventory,
            "parser_gap_inventory.json"
        );

        let events = fs::read_to_string(&artifacts.events_path).expect("read events");
        assert_eq!(events.lines().count(), ParserGapSiteId::ALL.len() + 2);

        let commands_txt = fs::read_to_string(&artifacts.commands_path).expect("read commands");
        assert!(commands_txt.contains("franken_parser_gap_inventory"));
        assert!(commands_txt.contains("--out-dir"));
        assert!(!out_dir.join(".parser_gap_inventory.lock").exists());
    }

    #[test]
    fn unique_temp_path_is_distinct_for_each_write_attempt() {
        let target = Path::new("artifacts/parser_gap_inventory.json");
        let first = unique_temp_path(target);
        let second = unique_temp_path(target);
        assert_ne!(first, second);
        assert_eq!(first.parent(), second.parent());
        assert_ne!(first.file_name(), Some(target.as_os_str()));
        assert_ne!(second.file_name(), Some(target.as_os_str()));
    }

    #[test]
    fn bundle_write_lock_rejects_concurrent_writer_until_release() {
        let out_dir = unique_temp_dir("parser-gap-lock");
        fs::create_dir_all(&out_dir).expect("create lock dir");

        let first = acquire_bundle_write_lock(&out_dir).expect("first lock");
        let second = acquire_bundle_write_lock(&out_dir).expect_err("second lock should fail");
        assert!(matches!(second, ParserGapInventoryWriteError::Busy { .. }));

        drop(first);

        acquire_bundle_write_lock(&out_dir).expect("lock should be acquirable after release");
    }

    #[test]
    fn failed_rewrite_removes_stale_manifest_commit_marker() {
        let out_dir = unique_temp_dir("parser-gap-stale-manifest");
        fs::create_dir_all(&out_dir).expect("create out dir");
        let run_manifest_path = out_dir.join("run_manifest.json");
        fs::write(&run_manifest_path, "{\"stale\":true}\n").expect("seed stale manifest");
        fs::create_dir_all(out_dir.join("parser_gap_inventory.json"))
            .expect("create blocking directory");

        let commands = vec!["franken_parser_gap_inventory".to_string()];
        let err = write_parser_gap_inventory_bundle(&out_dir, &commands)
            .expect_err("rewrite should fail when target path is a directory");
        assert!(matches!(err, ParserGapInventoryWriteError::Io { .. }));
        assert!(
            !run_manifest_path.exists(),
            "stale commit marker should be removed on failed rewrite"
        );
        assert!(
            !out_dir.join(".parser_gap_inventory.lock").exists(),
            "bundle lock should be released after failure",
        );
    }
}
