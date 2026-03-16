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
    Resolved,
}

impl LoweringGapStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::OpenPlaceholder => "open_placeholder",
            Self::Resolved => "resolved",
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
            | Self::NonIdentifierAssignmentNopPlaceholder
            | Self::ForInStatementPlaceholder
            | Self::ForOfStatementPlaceholder
            | Self::NewExpressionCallPlaceholder
            | Self::TemplateLiteralRawPlaceholder => LoweringGapStatus::Resolved,
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
            Self::BinaryNonArithmeticAddPlaceholder => "ir3.instruction.typed_binary_op",
            Self::ForInStatementPlaceholder => "ir1.for_in_init_next_loop",
            Self::ForOfStatementPlaceholder => "ir1.for_of_init_next_close_loop",
            Self::NewExpressionCallPlaceholder => "ir3.instruction.construct",
            Self::NonIdentifierAssignmentNopPlaceholder => "ir1.op.set_property",
            Self::TemplateLiteralRawPlaceholder => "ir3.instruction.template_literal",
        }
    }

    pub const fn execution_consequence(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => {
                "resolved: all 23 binary operators lower to typed IR3 instructions (Lt, Gte, Eq, BitAnd, etc.)"
            }
            Self::ForInStatementPlaceholder => {
                "resolved: for-in lowers to ForInInit/ForInNext IR1 loop with key-binding semantics"
            }
            Self::ForOfStatementPlaceholder => {
                "resolved: for-of lowers to ForOfInit/ForOfNext/IteratorClose IR1 loop with value-binding semantics"
            }
            Self::NewExpressionCallPlaceholder => {
                "resolved: new-expression lowers to Construct IR1 op with proper this-allocation and constructor semantics"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "resolved: member-target assignment lowers to SetProperty IR1 op with proper mutation semantics"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "resolved: template literal lowers to TemplateLiteral IR3 instruction with type coercion"
            }
        }
    }

    pub const fn user_visible_divergence(self) -> &'static str {
        match self {
            Self::BinaryNonArithmeticAddPlaceholder => {
                "resolved: all binary operators lower to typed instructions preserving correct operator semantics"
            }
            Self::ForInStatementPlaceholder => {
                "resolved: for-in lowers and executes as a real key-enumeration loop"
            }
            Self::ForOfStatementPlaceholder => {
                "resolved: for-of lowers and executes as a real iterator-protocol loop"
            }
            Self::NewExpressionCallPlaceholder => {
                "resolved: constructor semantics lower with proper this-allocation and prototype chain"
            }
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "resolved: property writes lower to SetProperty with proper mutation semantics"
            }
            Self::TemplateLiteralRawPlaceholder => {
                "resolved: template literals lower with interpolation-preserving type coercion semantics"
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
                "resolved: member/element writes now lower through SetProperty with alias-aware mutation effects"
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
                "lower_non_arithmetic_binary_emits_typed_instruction"
            }
            Self::ForInStatementPlaceholder => "lower_for_in_statement_produces_ir1_ops",
            Self::ForOfStatementPlaceholder => "lower_for_of_statement_produces_ir1_ops",
            Self::NewExpressionCallPlaceholder => "lower_new_expression_emits_construct",
            Self::NonIdentifierAssignmentNopPlaceholder => {
                "lower_computed_member_assignment_uses_dynamic_key_without_nop"
            }
            Self::TemplateLiteralRawPlaceholder => "lower_template_literal_emits_template_op",
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
    fn schema_version_constants_are_non_empty() {
        assert!(!LOWERING_GAP_INVENTORY_SCHEMA_VERSION.is_empty());
        assert!(!LOWERING_GAP_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!LOWERING_GAP_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!LOWERING_GAP_COMPONENT.is_empty());
        assert!(!LOWERING_GAP_POLICY_ID.is_empty());
    }

    #[test]
    fn lowering_gap_stage_serde_round_trip() {
        for stage in [LoweringGapStage::Ir0ToIr1, LoweringGapStage::Ir1ToIr3] {
            let json = serde_json::to_string(&stage).unwrap();
            let back: LoweringGapStage = serde_json::from_str(&json).unwrap();
            assert_eq!(back, stage);
            assert!(!stage.as_str().is_empty());
        }
    }

    #[test]
    fn lowering_gap_status_serde_round_trip() {
        for status in [
            LoweringGapStatus::FailClosed,
            LoweringGapStatus::OpenPlaceholder,
            LoweringGapStatus::Resolved,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: LoweringGapStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
            assert!(!status.as_str().is_empty());
        }
    }

    #[test]
    fn lowering_gap_site_id_all_has_six_variants() {
        assert_eq!(LoweringGapSiteId::ALL.len(), 6);
    }

    #[test]
    fn lowering_gap_site_id_all_resolved() {
        for site in LoweringGapSiteId::ALL {
            assert_eq!(site.status(), LoweringGapStatus::Resolved);
        }
    }

    #[test]
    fn lowering_gap_site_id_owner_is_always_lowering_pipeline() {
        for site in LoweringGapSiteId::ALL {
            assert_eq!(site.owner(), "lowering_pipeline");
        }
    }

    #[test]
    fn lowering_gap_site_id_serde_round_trip() {
        for site in LoweringGapSiteId::ALL {
            let json = serde_json::to_string(&site).unwrap();
            let back: LoweringGapSiteId = serde_json::from_str(&json).unwrap();
            assert_eq!(back, site);
        }
    }

    #[test]
    fn lowering_gap_site_id_ast_node_families_are_distinct() {
        let families: std::collections::BTreeSet<&str> = LoweringGapSiteId::ALL
            .iter()
            .map(|site| site.ast_node_family())
            .collect();
        assert_eq!(families.len(), LoweringGapSiteId::ALL.len());
    }

    #[test]
    fn lowering_gap_site_id_emitted_ir_shapes_non_empty() {
        for site in LoweringGapSiteId::ALL {
            assert!(!site.emitted_ir_shape().is_empty());
            assert!(!site.execution_consequence().is_empty());
            assert!(!site.user_visible_divergence().is_empty());
            assert!(!site.target_replacement_strategy().is_empty());
            assert!(!site.source_reference().is_empty());
            assert!(!site.regression_test_hint().is_empty());
        }
    }

    #[test]
    fn lowering_gap_site_descriptor_from_site_populates_all_fields() {
        let desc =
            LoweringGapSiteDescriptor::from_site(LoweringGapSiteId::ForOfStatementPlaceholder);
        assert_eq!(desc.site_id, "lower_ir0_to_ir1.for_of_placeholder");
        assert_eq!(desc.diagnostic_code, "FE-PARSER-GAP-FOR-OF-0001");
        assert_eq!(desc.stage, LoweringGapStage::Ir0ToIr1);
        assert_eq!(desc.status, LoweringGapStatus::Resolved);
        assert_eq!(desc.owner, "lowering_pipeline");
        assert_eq!(desc.ast_node_family, "statement.for_of");
        assert!(desc.parser_ready_syntax);
        assert!(!desc.execution_ready_semantics);
        assert!(!desc.emitted_ir_shape.is_empty());
        assert!(!desc.regression_test_hint.is_empty());
    }

    #[test]
    fn lowering_gap_inventory_event_serde_round_trip() {
        let event = LoweringGapInventoryEvent {
            schema_version: LOWERING_GAP_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: LOWERING_GAP_POLICY_ID.to_string(),
            component: LOWERING_GAP_COMPONENT.to_string(),
            event: "gap_site_recorded".to_string(),
            outcome: "resolved".to_string(),
            site_id: Some("test_site".to_string()),
            diagnostic_code: Some("FE-TEST-0001".to_string()),
            detail: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: LoweringGapInventoryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn lowering_gap_inventory_run_manifest_serde_round_trip() {
        let manifest = LoweringGapInventoryRunManifest {
            schema_version: LOWERING_GAP_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
            component: LOWERING_GAP_COMPONENT.to_string(),
            trace_id: "trace-test".to_string(),
            decision_id: "decision-test".to_string(),
            policy_id: LOWERING_GAP_POLICY_ID.to_string(),
            inventory_hash: "abc123".to_string(),
            site_count: 6,
            fail_closed_site_count: 0,
            open_placeholder_site_count: 0,
            parser_ready_site_count: 6,
            execution_ready_site_count: 0,
            artifact_paths: LoweringGapInventoryArtifactPaths {
                lowering_gap_inventory: "inventory.json".to_string(),
                run_manifest: "manifest.json".to_string(),
                events_jsonl: "events.jsonl".to_string(),
                commands_txt: "commands.txt".to_string(),
            },
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: LoweringGapInventoryRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, manifest);
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
        assert_eq!(inventory.fail_closed_site_count(), 0);
        assert_eq!(inventory.open_placeholder_site_count(), 0);
    }

    #[test]
    fn binary_placeholder_descriptor_reflects_resolved_state() {
        let descriptor = LoweringGapSiteDescriptor::from_site(
            LoweringGapSiteId::BinaryNonArithmeticAddPlaceholder,
        );
        assert_eq!(descriptor.stage, LoweringGapStage::Ir1ToIr3);
        assert_eq!(descriptor.status, LoweringGapStatus::Resolved);
        assert_eq!(
            descriptor.emitted_ir_shape,
            "ir3.instruction.typed_binary_op"
        );
        assert!(descriptor.user_visible_divergence.contains("resolved"));
        assert_eq!(
            descriptor.regression_test_hint,
            "lower_non_arithmetic_binary_emits_typed_instruction"
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
        assert_eq!(manifest.fail_closed_site_count, 0);
        assert_eq!(manifest.open_placeholder_site_count, 0);
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
    fn lowering_gap_stage_as_str_matches_serde_name() {
        let ir0 = LoweringGapStage::Ir0ToIr1;
        let ir1 = LoweringGapStage::Ir1ToIr3;
        let json0: String = serde_json::from_str(&serde_json::to_string(&ir0).unwrap()).unwrap();
        let json1: String = serde_json::from_str(&serde_json::to_string(&ir1).unwrap()).unwrap();
        assert_eq!(json0, ir0.as_str());
        assert_eq!(json1, ir1.as_str());
    }

    #[test]
    fn lowering_gap_status_as_str_matches_serde_name() {
        for status in [
            LoweringGapStatus::FailClosed,
            LoweringGapStatus::OpenPlaceholder,
            LoweringGapStatus::Resolved,
        ] {
            let json: String =
                serde_json::from_str(&serde_json::to_string(&status).unwrap()).unwrap();
            assert_eq!(json, status.as_str());
        }
    }

    #[test]
    fn site_id_stage_assignment_is_deterministic() {
        assert_eq!(
            LoweringGapSiteId::BinaryNonArithmeticAddPlaceholder.stage(),
            LoweringGapStage::Ir1ToIr3
        );
        for site in [
            LoweringGapSiteId::ForInStatementPlaceholder,
            LoweringGapSiteId::ForOfStatementPlaceholder,
            LoweringGapSiteId::NewExpressionCallPlaceholder,
            LoweringGapSiteId::NonIdentifierAssignmentNopPlaceholder,
            LoweringGapSiteId::TemplateLiteralRawPlaceholder,
        ] {
            assert_eq!(site.stage(), LoweringGapStage::Ir0ToIr1);
        }
    }

    #[test]
    fn diagnostic_codes_follow_naming_convention() {
        for site in LoweringGapSiteId::ALL {
            let code = site.diagnostic_code();
            assert!(
                code.starts_with("FE-PARSER-GAP-"),
                "code must start with FE-PARSER-GAP-: {code}"
            );
            assert!(code.ends_with("-0001"), "code must end with -0001: {code}");
        }
    }

    #[test]
    fn source_references_point_to_lowering_pipeline() {
        for site in LoweringGapSiteId::ALL {
            let reference = site.source_reference();
            assert!(
                reference.contains("lowering_pipeline.rs"),
                "source_reference must mention lowering_pipeline.rs: {reference}"
            );
        }
    }

    #[test]
    fn execution_consequences_contain_resolved_prefix() {
        for site in LoweringGapSiteId::ALL {
            let consequence = site.execution_consequence();
            assert!(
                consequence.starts_with("resolved:"),
                "all sites are resolved so consequence must start with 'resolved:': {consequence}"
            );
        }
    }

    #[test]
    fn emitted_ir_shapes_reference_valid_ir_levels() {
        for site in LoweringGapSiteId::ALL {
            let shape = site.emitted_ir_shape();
            assert!(
                shape.starts_with("ir1.") || shape.starts_with("ir3."),
                "emitted_ir_shape must reference ir1 or ir3: {shape}"
            );
        }
    }

    #[test]
    fn inventory_content_hash_is_deterministic() {
        let artifacts_a = {
            let out_dir = unique_temp_dir("lowering-gap-hash-a");
            write_lowering_gap_inventory_bundle(&out_dir, &[]).unwrap()
        };
        let artifacts_b = {
            let out_dir = unique_temp_dir("lowering-gap-hash-b");
            write_lowering_gap_inventory_bundle(&out_dir, &[]).unwrap()
        };
        assert_eq!(artifacts_a.inventory_hash, artifacts_b.inventory_hash);
        assert_eq!(artifacts_a.site_count, artifacts_b.site_count);
    }

    #[test]
    fn inventory_hash_is_64_hex_chars() {
        let out_dir = unique_temp_dir("lowering-gap-hash-len");
        let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &[]).unwrap();
        assert_eq!(artifacts.inventory_hash.len(), 64);
        assert!(
            artifacts
                .inventory_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn build_inventory_events_has_start_sites_and_end() {
        let inventory = lowering_gap_inventory();
        let events = build_inventory_events(&inventory, "t1", "d1");
        assert_eq!(events.len(), inventory.sites.len() + 2);
        assert_eq!(events.first().unwrap().event, "inventory_started");
        assert_eq!(events.last().unwrap().event, "inventory_completed");
        for event in &events[1..events.len() - 1] {
            assert_eq!(event.event, "gap_site_recorded");
            assert!(event.site_id.is_some());
            assert!(event.diagnostic_code.is_some());
        }
    }

    #[test]
    fn event_trace_and_decision_ids_are_consistent() {
        let inventory = lowering_gap_inventory();
        let events = build_inventory_events(&inventory, "trace-abc", "decision-xyz");
        for event in &events {
            assert_eq!(event.trace_id, "trace-abc");
            assert_eq!(event.decision_id, "decision-xyz");
            assert_eq!(event.policy_id, LOWERING_GAP_POLICY_ID);
            assert_eq!(event.component, LOWERING_GAP_COMPONENT);
        }
    }

    #[test]
    fn descriptor_serde_roundtrip_preserves_all_fields() {
        for site in LoweringGapSiteId::ALL {
            let desc = LoweringGapSiteDescriptor::from_site(site);
            let json = serde_json::to_string(&desc).unwrap();
            let back: LoweringGapSiteDescriptor = serde_json::from_str(&json).unwrap();
            assert_eq!(back, desc);
        }
    }

    #[test]
    fn inventory_schema_version_embedded_correctly() {
        let inventory = lowering_gap_inventory();
        assert_eq!(
            inventory.schema_version,
            LOWERING_GAP_INVENTORY_SCHEMA_VERSION
        );
        assert_eq!(inventory.component, LOWERING_GAP_COMPONENT);
    }

    #[test]
    fn regression_test_hints_are_distinct() {
        let hints: std::collections::BTreeSet<&str> = LoweringGapSiteId::ALL
            .iter()
            .map(|site| site.regression_test_hint())
            .collect();
        assert_eq!(hints.len(), LoweringGapSiteId::ALL.len());
    }

    #[test]
    fn site_id_ordering_is_stable() {
        let mut sorted = LoweringGapSiteId::ALL.to_vec();
        sorted.sort();
        assert_eq!(sorted, LoweringGapSiteId::ALL.to_vec());
    }

    #[test]
    fn sha256_hex_produces_correct_length_and_format() {
        let hash = sha256_hex(b"test input");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        assert_eq!(sha256_hex(b"hello"), sha256_hex(b"hello"));
        assert_ne!(sha256_hex(b"hello"), sha256_hex(b"world"));
    }

    #[test]
    fn empty_commands_produce_empty_commands_txt() {
        let out_dir = unique_temp_dir("lowering-gap-empty-cmds");
        let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &[]).unwrap();
        let commands_txt = fs::read_to_string(&artifacts.commands_path).unwrap();
        assert!(commands_txt.is_empty());
    }

    #[test]
    fn manifest_trace_id_embeds_inventory_hash_prefix() {
        let out_dir = unique_temp_dir("lowering-gap-trace-prefix");
        let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &[]).unwrap();
        let manifest: LoweringGapInventoryRunManifest =
            serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).unwrap()).unwrap();
        let short_hash = &artifacts.inventory_hash[..16];
        assert!(
            manifest.trace_id.contains(short_hash),
            "trace_id should embed first 16 chars of inventory hash"
        );
        assert!(
            manifest.decision_id.contains(short_hash),
            "decision_id should embed first 16 chars of inventory hash"
        );
    }

    #[test]
    fn artifact_paths_in_manifest_are_relative() {
        let out_dir = unique_temp_dir("lowering-gap-rel-paths");
        let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &[]).unwrap();
        let manifest: LoweringGapInventoryRunManifest =
            serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).unwrap()).unwrap();
        assert!(!manifest.artifact_paths.lowering_gap_inventory.contains('/'));
        assert!(!manifest.artifact_paths.run_manifest.contains('/'));
        assert!(!manifest.artifact_paths.events_jsonl.contains('/'));
        assert!(!manifest.artifact_paths.commands_txt.contains('/'));
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
