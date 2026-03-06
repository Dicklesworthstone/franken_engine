use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const LOWERING_GAP_INVENTORY_SCHEMA_VERSION: &str = "franken-engine.lowering-gap-inventory.v1";
pub const LOWERING_GAP_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.lowering-gap-inventory.run-manifest.v1";
pub const LOWERING_GAP_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.lowering-gap-inventory.event.v1";
pub const LOWERING_GAP_COMPONENT: &str = "lowering_gap_inventory";
pub const LOWERING_GAP_POLICY_ID: &str = "franken-engine.lowering-gap-inventory.policy.v1";

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoweringGapStage {
    Ir0ToIr1,
    Ir1ToIr3,
}

impl LoweringGapStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ir0ToIr1 => "ir0_to_ir1",
            Self::Ir1ToIr3 => "ir1_to_ir3",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoweringGapStatus {
    FailClosed,
    OpenPlaceholder,
}

impl LoweringGapStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::OpenPlaceholder => "open_placeholder",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoweringGapSiteId {
    BinaryNonArithmeticAddPlaceholder,
    ForInStatementPlaceholder,
    ForOfStatementPlaceholder,
    NewExpressionCallPlaceholder,
    NonIdentifierAssignmentNopPlaceholder,
    TemplateLiteralRawPlaceholder,
}

impl LoweringGapSiteId {
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
            Self::BinaryNonArithmeticAddPlaceholder => {
                "lower_ir1_to_ir3.binary_non_arithmetic_add_placeholder"
            }
            Self::ForInStatementPlaceholder => "lower_ir0_to_ir1.for_in_placeholder",
            Self::ForOfStatementPlaceholder => "lower_ir0_to_ir1.for_of_placeholder",
            Self::NewExpressionCallPlaceholder => "lower_ir0_to_ir1.new_call_placeholder",
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "lower_ir0_to_ir1.assignment_non_identifier_nop_placeholder"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "lower_ir0_to_ir1.template_literal_raw_placeholder"
            }
        }
    }

    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => "FE-PARSER-GAP-BINARY-0001",
            Self::ForInStatementPlaceholder => "FE-PARSER-GAP-FOR-IN-0001",
            Self::ForOfStatementPlaceholder => "FE-PARSER-GAP-FOR-OF-0001",
            Self::NewExpressionCallPlaceholder => "FE-PARSER-GAP-NEW-0001",
            Self::NonIdentifierAssignmentNopPlaceholder => "FE-PARSER-GAP-ASSIGN-0001",
            Self::TemplateLiteralRawPlaceholder => "FE-PARSER-GAP-TEMPLATE-0001",
        }
    }

    pub const fn stage(self) -> LoweringGapStage {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => LoweringGapStage::Ir1ToIr3,
            Self::ForInStatementPlaceholder
            | Self::ForOfStatementPlaceholder
            | Self::NewExpressionCallPlaceholder
            | Self::NonIdentifierAssignmentNopPlaceholder
            | Self::TemplateLiteralRawPlaceholder => LoweringGapStage::Ir0ToIr1,
        }
    }

    pub const fn status(self) -> LoweringGapStatus {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder
            | Self::NonIdentifierAssignmentNopPlaceholder => LoweringGapStatus::OpenPlaceholder,
            Self::ForInStatementPlaceholder
            | Self::ForOfStatementPlaceholder
            | Self::NewExpressionCallPlaceholder
            | Self::TemplateLiteralRawPlaceholder => LoweringGapStatus::FailClosed,
        }
    }

    pub const fn owner(self) -> &'static str {
        "lowering_pipeline"
    }

    pub const fn ast_node_family(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => "expression.binary_non_arithmetic",
            Self::ForInStatementPlaceholder => "statement.for_in",
            Self::ForOfStatementPlaceholder => "statement.for_of",
            Self::NewExpressionCallPlaceholder => "expression.new",
            Self::NonIdentifierAssignmentNopPlaceholder => "expression.assignment_member_target",
            Self::TemplateLiteralRawPlaceholder => "expression.template_literal",
        }
    }

    pub const fn emitted_ir_shape(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => "ir3.instruction.add_placeholder",
            Self::ForInStatementPlaceholder => "no_ir.fail_closed_diagnostic",
            Self::ForOfStatementPlaceholder => "no_ir.fail_closed_diagnostic",
            Self::NewExpressionCallPlaceholder => "no_ir.fail_closed_diagnostic",
            Self::NonIdentifierAssignmentNopPlaceholder => "ir1.op.nop_placeholder",
            Self::TemplateLiteralRawPlaceholder => "no_ir.fail_closed_diagnostic",
        }
    }

    pub const fn execution_consequence(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => {
                "comparison, logical, and bitwise intent collapses into arithmetic addition in IR3"
            }
            Self::ForInStatementPlaceholder => {
                "enumeration semantics are unavailable because lowering rejects the node before IR1"
            }
            Self::ForOfStatementPlaceholder => {
                "iterator-driven execution is unavailable because lowering rejects the node before IR1"
            }
            Self::NewExpressionCallPlaceholder => {
                "constructor allocation/prototype semantics never reach execution because lowering stops early"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "member-target assignment drops the mutation and produces no write effect in IR1"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "template interpolation semantics never reach execution because lowering stops early"
            }
        }
    }

    pub const fn user_visible_divergence(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => {
                "guards, branching predicates, and bitwise-heavy code can report success while executing the wrong operator semantics"
            }
            Self::ForInStatementPlaceholder => {
                "for-in syntax parses but cannot execute as an object-key iteration workload"
            }
            Self::ForOfStatementPlaceholder => {
                "for-of syntax parses but cannot execute as an iterator protocol workload"
            }
            Self::NewExpressionCallPlaceholder => {
                "constructor-style package bootstrap code parses but cannot lower honestly into allocation semantics"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "property writes appear accepted by the frontend but do not mutate runtime state"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "template literals parse but cannot lower with interpolation-preserving semantics"
            }
        }
    }

    pub const fn target_replacement_strategy(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => {
                "replace operator collapse with dedicated comparison/logical/bitwise lowering and fail-closed parity diagnostics"
            }
            Self::ForInStatementPlaceholder => {
                "add iterator/key-enumeration aware loop lowering that preserves body execution order and binding updates"
            }
            Self::ForOfStatementPlaceholder => {
                "add iterator-protocol aware loop lowering with deterministic next/done sequencing"
            }
            Self::NewExpressionCallPlaceholder => {
                "add allocation-aware constructor lowering with explicit this/prototype initialization semantics"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "replace nop store placeholder with explicit member/element write lowering and alias-aware mutation effects"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "lower template quasis and expressions into concatenation/coercion-aware IR instead of raw-string fallback"
            }
        }
    }

    pub const fn source_reference(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_ir1_to_ir3/Ir1Op::BinaryOp"
            }
            Self::ForInStatementPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_statement_to_ir1_with_flow/Statement::ForIn"
            }
            Self::ForOfStatementPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_statement_to_ir1_with_flow/Statement::ForOf"
            }
            Self::NewExpressionCallPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_expression_to_ir1/Expression::New"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_expression_to_ir1/Expression::Assignment"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "crates/franken-engine/src/lowering_pipeline.rs::lower_expression_to_ir1/Expression::TemplateLiteral"
            }
        }
    }

    pub const fn regression_test_hint(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => {
                "lower_non_arithmetic_binary_currently_collapses_to_add_placeholder"
            }
            Self::ForInStatementPlaceholder => "lower_for_in_statement_fails_closed",
            Self::ForOfStatementPlaceholder => "lower_for_of_statement_fails_closed",
            Self::NewExpressionCallPlaceholder => "lower_new_expression_fails_closed",
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "lower_member_assignment_currently_emits_nop_placeholder"
            }
            Self::TemplateLiteralRawPlaceholder => "lower_template_literal_fails_closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringGapSiteDescriptor {
    pub site_id: String,
    pub diagnostic_code: String,
    pub stage: LoweringGapStage,
    pub status: LoweringGapStatus,
    pub owner: String,
    pub ast_node_family: String,
    pub emitted_ir_shape: String,
    pub execution_consequence: String,
    pub user_visible_divergence: String,
    pub target_replacement_strategy: String,
    pub parser_ready_syntax: bool,
    pub execution_ready_semantics: bool,
    pub source_reference: String,
    pub regression_test_hint: String,
}

impl LoweringGapSiteDescriptor {
    pub fn from_site(site: LoweringGapSiteId) -> Self {
        Self {
            site_id: site.as_str().to_string(),
            diagnostic_code: site.diagnostic_code().to_string(),
            stage: site.stage(),
            status: site.status(),
            owner: site.owner().to_string(),
            ast_node_family: site.ast_node_family().to_string(),
            emitted_ir_shape: site.emitted_ir_shape().to_string(),
            execution_consequence: site.execution_consequence().to_string(),
            user_visible_divergence: site.user_visible_divergence().to_string(),
            target_replacement_strategy: site.target_replacement_strategy().to_string(),
            parser_ready_syntax: true,
            execution_ready_semantics: false,
            source_reference: site.source_reference().to_string(),
            regression_test_hint: site.regression_test_hint().to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringGapInventory {
    pub schema_version: String,
    pub component: String,
    pub sites: Vec<LoweringGapSiteDescriptor>,
}

impl LoweringGapInventory {
    pub fn fail_closed_site_count(&self) -> usize {
        self.sites
            .iter()
            .filter(|site| site.status == LoweringGapStatus::FailClosed)
            .count()
    }

    pub fn open_placeholder_site_count(&self) -> usize {
        self.sites
            .iter()
            .filter(|site| site.status == LoweringGapStatus::OpenPlaceholder)
            .count()
    }

    pub fn parser_ready_site_count(&self) -> usize {
        self.sites
            .iter()
            .filter(|site| site.parser_ready_syntax)
            .count()
    }

    pub fn execution_ready_site_count(&self) -> usize {
        self.sites
            .iter()
            .filter(|site| site.execution_ready_semantics)
            .count()
    }
}

pub fn lowering_gap_inventory() -> LoweringGapInventory {
    let sites = LoweringGapSiteId::ALL
        .iter()
        .map(|site| LoweringGapSiteDescriptor::from_site(*site))
        .collect();
    LoweringGapInventory {
        schema_version: LOWERING_GAP_INVENTORY_SCHEMA_VERSION.to_string(),
        component: LOWERING_GAP_COMPONENT.to_string(),
        sites,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringGapInventoryArtifactPaths {
    pub lowering_gap_inventory: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringGapInventoryRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub site_count: u64,
    pub fail_closed_site_count: u64,
    pub open_placeholder_site_count: u64,
    pub parser_ready_site_count: u64,
    pub execution_ready_site_count: u64,
    pub artifact_paths: LoweringGapInventoryArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringGapInventoryEvent {
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
pub struct LoweringGapInventoryArtifacts {
    pub out_dir: PathBuf,
    pub inventory_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
    pub site_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum LoweringGapInventoryWriteError {
    #[error("failed to serialize `{path}`: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("bundle output directory is already locked by another writer: `{path}`")]
    Busy { path: String },
}

pub fn write_lowering_gap_inventory_bundle(
    out_dir: impl AsRef<Path>,
    command_lines: &[String],
) -> Result<LoweringGapInventoryArtifacts, LoweringGapInventoryWriteError> {
    let out_dir = out_dir.as_ref().to_path_buf();
    fs::create_dir_all(&out_dir).map_err(|source| LoweringGapInventoryWriteError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;

    let inventory = lowering_gap_inventory();
    let inventory_path = out_dir.join("lowering_gap_inventory.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");

    let inventory_bytes = canonical_json_bytes(&inventory, &inventory_path)?;
    let inventory_hash = sha256_hex(&inventory_bytes);

    let short_hash = inventory_hash.chars().take(16).collect::<String>();
    let trace_id = format!("trace-lowering-gap-{short_hash}");
    let decision_id = format!("decision-lowering-gap-{short_hash}");

    let manifest = LoweringGapInventoryRunManifest {
        schema_version: LOWERING_GAP_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: LOWERING_GAP_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: LOWERING_GAP_POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
        site_count: inventory.sites.len() as u64,
        fail_closed_site_count: inventory.fail_closed_site_count() as u64,
        open_placeholder_site_count: inventory.open_placeholder_site_count() as u64,
        parser_ready_site_count: inventory.parser_ready_site_count() as u64,
        execution_ready_site_count: inventory.execution_ready_site_count() as u64,
        artifact_paths: LoweringGapInventoryArtifactPaths {
            lowering_gap_inventory: "lowering_gap_inventory.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };
    let manifest_bytes = canonical_json_bytes(&manifest, &run_manifest_path)?;

    let events = build_inventory_events(&inventory, &trace_id, &decision_id);
    let mut events_jsonl = String::new();
    for event in &events {
        let line = serde_json::to_string(event).map_err(|source| {
            LoweringGapInventoryWriteError::Json {
                path: events_path.display().to_string(),
                source,
            }
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
    // Publish the manifest last so its presence acts as a commit marker.
    write_atomic(&run_manifest_path, &manifest_bytes)?;

    Ok(LoweringGapInventoryArtifacts {
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
    inventory: &LoweringGapInventory,
    trace_id: &str,
    decision_id: &str,
) -> Vec<LoweringGapInventoryEvent> {
    let mut events = vec![LoweringGapInventoryEvent {
        schema_version: LOWERING_GAP_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: LOWERING_GAP_POLICY_ID.to_string(),
        component: LOWERING_GAP_COMPONENT.to_string(),
        event: "inventory_started".to_string(),
        outcome: "started".to_string(),
        site_id: None,
        diagnostic_code: None,
        detail: Some("authoritative lowering-gap inventory generation began".to_string()),
    }];

    events.extend(
        inventory
            .sites
            .iter()
            .map(|site| LoweringGapInventoryEvent {
                schema_version: LOWERING_GAP_EVENT_SCHEMA_VERSION.to_string(),
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                policy_id: LOWERING_GAP_POLICY_ID.to_string(),
                component: LOWERING_GAP_COMPONENT.to_string(),
                event: "gap_site_recorded".to_string(),
                outcome: site.status.as_str().to_string(),
                site_id: Some(site.site_id.clone()),
                diagnostic_code: Some(site.diagnostic_code.clone()),
                detail: Some(site.user_visible_divergence.clone()),
            }),
    );

    events.push(LoweringGapInventoryEvent {
        schema_version: LOWERING_GAP_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: LOWERING_GAP_POLICY_ID.to_string(),
        component: LOWERING_GAP_COMPONENT.to_string(),
        event: "inventory_completed".to_string(),
        outcome: "completed".to_string(),
        site_id: None,
        diagnostic_code: None,
        detail: Some(format!(
            "{} sites recorded ({} fail-closed, {} open placeholders, {} parser-ready, {} execution-ready)",
            inventory.sites.len(),
            inventory.fail_closed_site_count(),
            inventory.open_placeholder_site_count(),
            inventory.parser_ready_site_count(),
            inventory.execution_ready_site_count(),
        )),
    });

    events
}

fn canonical_json_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, LoweringGapInventoryWriteError> {
    serde_json::to_vec(value).map_err(|source| LoweringGapInventoryWriteError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn acquire_bundle_write_lock(
    out_dir: &Path,
) -> Result<BundleWriteLock, LoweringGapInventoryWriteError> {
    let lock_path = out_dir.join(".lowering_gap_inventory.lock");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(BundleWriteLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            Err(LoweringGapInventoryWriteError::Busy {
                path: lock_path.display().to_string(),
            })
        }
        Err(source) => Err(LoweringGapInventoryWriteError::Io {
            path: lock_path.display().to_string(),
            source,
        }),
    }
}

fn remove_commit_marker(path: &Path) -> Result<(), LoweringGapInventoryWriteError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(LoweringGapInventoryWriteError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), LoweringGapInventoryWriteError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| LoweringGapInventoryWriteError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| LoweringGapInventoryWriteError::Io {
        path: temp_path.display().to_string(),
        source,
    })?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(LoweringGapInventoryWriteError::Io {
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
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        env::temp_dir().join(format!("frankenengine-{label}-{}-{nanos}", process::id()))
    }

    #[test]
    fn lowering_gap_site_ids_and_diagnostic_codes_are_unique() {
        let mut site_ids = std::collections::BTreeSet::new();
        let mut diagnostic_codes = std::collections::BTreeSet::new();
        for site in LoweringGapSiteId::ALL {
            assert!(site_ids.insert(site.as_str()));
            assert!(diagnostic_codes.insert(site.diagnostic_code()));
        }
    }

    #[test]
    fn lowering_gap_inventory_distinguishes_parser_and_execution_readiness() {
        let inventory = lowering_gap_inventory();
        assert_eq!(inventory.sites.len(), LoweringGapSiteId::ALL.len());
        assert_eq!(
            inventory.parser_ready_site_count(),
            LoweringGapSiteId::ALL.len()
        );
        assert_eq!(inventory.execution_ready_site_count(), 0);
        assert_eq!(inventory.fail_closed_site_count(), 4);
        assert_eq!(inventory.open_placeholder_site_count(), 2);
    }

    #[test]
    fn binary_placeholder_descriptor_is_explicit_about_wrong_ir_shape() {
        let descriptor = LoweringGapSiteDescriptor::from_site(
            LoweringGapSiteId::BinaryNonArithmeticAddPlaceholder,
        );
        assert_eq!(descriptor.stage, LoweringGapStage::Ir1ToIr3);
        assert_eq!(descriptor.status, LoweringGapStatus::OpenPlaceholder);
        assert_eq!(
            descriptor.emitted_ir_shape,
            "ir3.instruction.add_placeholder"
        );
        assert!(
            descriptor
                .user_visible_divergence
                .contains("wrong operator semantics")
        );
        assert_eq!(
            descriptor.regression_test_hint,
            "lower_non_arithmetic_binary_currently_collapses_to_add_placeholder"
        );
    }

    #[test]
    fn write_lowering_gap_inventory_bundle_emits_expected_artifacts() {
        let out_dir = unique_temp_dir("lowering-gap-inventory");
        let commands = vec![
            "franken_lowering_gap_inventory".to_string(),
            "--out-dir".to_string(),
            out_dir.display().to_string(),
        ];
        let artifacts =
            write_lowering_gap_inventory_bundle(&out_dir, &commands).expect("write artifacts");
        assert!(artifacts.inventory_path.exists());
        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.commands_path.exists());

        let inventory: LoweringGapInventory =
            serde_json::from_slice(&fs::read(&artifacts.inventory_path).expect("read inventory"))
                .expect("inventory json");
        assert_eq!(inventory.sites.len(), LoweringGapSiteId::ALL.len());

        let manifest: LoweringGapInventoryRunManifest =
            serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
                .expect("manifest json");
        assert_eq!(manifest.site_count as usize, LoweringGapSiteId::ALL.len());
        assert_eq!(manifest.fail_closed_site_count, 4);
        assert_eq!(manifest.open_placeholder_site_count, 2);
        assert_eq!(
            manifest.parser_ready_site_count,
            LoweringGapSiteId::ALL.len() as u64
        );
        assert_eq!(manifest.execution_ready_site_count, 0);

        let events = fs::read_to_string(&artifacts.events_path).expect("read events");
        assert_eq!(events.lines().count(), LoweringGapSiteId::ALL.len() + 2);

        let commands_txt = fs::read_to_string(&artifacts.commands_path).expect("read commands");
        assert!(commands_txt.contains("franken_lowering_gap_inventory"));
        assert!(commands_txt.contains("--out-dir"));
        assert!(!out_dir.join(".lowering_gap_inventory.lock").exists());
    }

    #[test]
    fn unique_temp_path_is_distinct_for_each_write_attempt() {
        let target = Path::new("artifacts/lowering_gap_inventory.json");
        let first = unique_temp_path(target);
        let second = unique_temp_path(target);
        assert_ne!(first, second);
        assert_eq!(first.parent(), second.parent());
        assert_ne!(first.file_name(), Some(target.as_os_str()));
        assert_ne!(second.file_name(), Some(target.as_os_str()));
    }

    #[test]
    fn bundle_write_lock_rejects_concurrent_writer_until_release() {
        let out_dir = unique_temp_dir("lowering-gap-lock");
        fs::create_dir_all(&out_dir).expect("create lock dir");

        let first = acquire_bundle_write_lock(&out_dir).expect("first lock");
        let second = acquire_bundle_write_lock(&out_dir).expect_err("second lock should fail");
        assert!(matches!(
            second,
            LoweringGapInventoryWriteError::Busy { .. }
        ));

        drop(first);

        acquire_bundle_write_lock(&out_dir).expect("lock should be acquirable after release");
    }

    #[test]
    fn busy_bundle_write_does_not_mutate_existing_artifacts() {
        let out_dir = unique_temp_dir("lowering-gap-busy");
        fs::create_dir_all(&out_dir).expect("create out dir");
        let events_path = out_dir.join("events.jsonl");
        fs::write(&events_path, "previous-events\n").expect("seed events");
        let commands = vec!["franken_lowering_gap_inventory".to_string()];

        let lock = acquire_bundle_write_lock(&out_dir).expect("hold lock");
        let err = write_lowering_gap_inventory_bundle(&out_dir, &commands)
            .expect_err("write should block");
        assert!(matches!(err, LoweringGapInventoryWriteError::Busy { .. }));
        assert_eq!(
            fs::read_to_string(&events_path).expect("read events after busy failure"),
            "previous-events\n"
        );
        drop(lock);
    }

    #[test]
    fn failed_rewrite_removes_stale_manifest_commit_marker() {
        let out_dir = unique_temp_dir("lowering-gap-stale-manifest");
        fs::create_dir_all(&out_dir).expect("create out dir");
        let run_manifest_path = out_dir.join("run_manifest.json");
        fs::write(&run_manifest_path, "{\"stale\":true}\n").expect("seed stale manifest");
        fs::create_dir_all(out_dir.join("lowering_gap_inventory.json"))
            .expect("create blocking directory");

        let commands = vec!["franken_lowering_gap_inventory".to_string()];
        let err = write_lowering_gap_inventory_bundle(&out_dir, &commands)
            .expect_err("rewrite should fail when target path is a directory");
        assert!(matches!(err, LoweringGapInventoryWriteError::Io { .. }));
        assert!(
            !run_manifest_path.exists(),
            "stale commit marker should be removed on failed rewrite"
        );
        assert!(
            !out_dir.join(".lowering_gap_inventory.lock").exists(),
            "bundle lock should be released after failure",
        );
    }
}
