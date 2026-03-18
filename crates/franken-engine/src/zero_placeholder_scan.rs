use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::lowering_gap_inventory::{self, LoweringGapInventory, LoweringGapStatus};
use crate::parser_gap_inventory::{self, ParserGapInventory, ParserGapRemediationStatus};

pub const ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION: &str = "franken-engine.zero-placeholder-scan.v1";
pub const ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.zero-placeholder-scan.trace-ids.v1";
pub const ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.zero-placeholder-scan.run-manifest.v1";
pub const ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.zero-placeholder-scan.event.v1";
pub const ZERO_PLACEHOLDER_SCAN_COMPONENT: &str = "zero_placeholder_scan";
pub const ZERO_PLACEHOLDER_SCAN_POLICY_ID: &str = "franken-engine.zero-placeholder-scan.policy.v1";
pub const ZERO_PLACEHOLDER_SCAN_FINDING_COUNT: usize = 16;

const DOCS_HELP_AUDIT_CONTRACT_JSON: &str =
    include_str!("../../../docs/rgc_docs_help_surface_audit_v1.json");
const CLI_DOCS_HELP_POLICY_ID: &str = "policy-rgc-docs-help-surface-audit-v1";
const CLI_DOCS_HELP_BEAD_ID: &str = "bd-1lsy.10.11.1";
const JSON_RUNTIME_BEAD_ID: &str = "bd-1lsy.4.9.1";
const ITERATOR_RUNTIME_BEAD_ID: &str = "bd-1lsy.4.8";

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZeroPlaceholderSubsystem {
    Parser,
    Lowering,
    Runtime,
    CliDocs,
}

impl ZeroPlaceholderSubsystem {
    pub const ALL: [Self; 4] = [Self::Parser, Self::Lowering, Self::Runtime, Self::CliDocs];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::Lowering => "lowering",
            Self::Runtime => "runtime",
            Self::CliDocs => "cli_docs",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZeroPlaceholderStatus {
    OpenPlaceholder,
    FailClosed,
    Resolved,
}

impl ZeroPlaceholderStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenPlaceholder => "open_placeholder",
            Self::FailClosed => "fail_closed",
            Self::Resolved => "resolved",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZeroPlaceholderSeverity {
    High,
    Medium,
    Low,
}

impl ZeroPlaceholderSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroPlaceholderFinding {
    pub finding_id: String,
    pub subsystem: ZeroPlaceholderSubsystem,
    pub status: ZeroPlaceholderStatus,
    pub severity: ZeroPlaceholderSeverity,
    pub owner: String,
    pub owner_bead_id: String,
    pub subject_area: String,
    pub source_reference: String,
    pub observed_behavior: String,
    pub required_behavior: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroPlaceholderInventory {
    pub schema_version: String,
    pub component: String,
    pub findings: Vec<ZeroPlaceholderFinding>,
}

impl ZeroPlaceholderInventory {
    pub fn open_placeholder_finding_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.status == ZeroPlaceholderStatus::OpenPlaceholder)
            .count()
    }

    pub fn fail_closed_finding_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.status == ZeroPlaceholderStatus::FailClosed)
            .count()
    }

    pub fn resolved_finding_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.status == ZeroPlaceholderStatus::Resolved)
            .count()
    }

    pub fn subsystem_summaries(&self) -> Vec<ZeroPlaceholderSubsystemSummary> {
        ZeroPlaceholderSubsystem::ALL
            .iter()
            .map(|subsystem| {
                let findings = self
                    .findings
                    .iter()
                    .filter(|finding| finding.subsystem == *subsystem);
                let mut finding_count = 0u64;
                let mut open_placeholder_finding_count = 0u64;
                let mut fail_closed_finding_count = 0u64;
                let mut resolved_finding_count = 0u64;

                for finding in findings {
                    finding_count += 1;
                    match finding.status {
                        ZeroPlaceholderStatus::OpenPlaceholder => {
                            open_placeholder_finding_count += 1;
                        }
                        ZeroPlaceholderStatus::FailClosed => {
                            fail_closed_finding_count += 1;
                        }
                        ZeroPlaceholderStatus::Resolved => {
                            resolved_finding_count += 1;
                        }
                    }
                }

                ZeroPlaceholderSubsystemSummary {
                    subsystem: *subsystem,
                    finding_count,
                    open_placeholder_finding_count,
                    fail_closed_finding_count,
                    resolved_finding_count,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroPlaceholderSubsystemSummary {
    pub subsystem: ZeroPlaceholderSubsystem,
    pub finding_count: u64,
    pub open_placeholder_finding_count: u64,
    pub fail_closed_finding_count: u64,
    pub resolved_finding_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroPlaceholderScanArtifactPaths {
    pub zero_placeholder_inventory: String,
    pub trace_ids: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroPlaceholderScanTraceIds {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroPlaceholderScanRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub finding_count: u64,
    pub open_placeholder_finding_count: u64,
    pub fail_closed_finding_count: u64,
    pub resolved_finding_count: u64,
    pub subsystem_summaries: Vec<ZeroPlaceholderSubsystemSummary>,
    pub artifact_paths: ZeroPlaceholderScanArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZeroPlaceholderScanEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<ZeroPlaceholderSubsystem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroPlaceholderScanArtifacts {
    pub out_dir: PathBuf,
    pub inventory_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub inventory_hash: String,
    pub finding_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ZeroPlaceholderScanWriteError {
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

#[derive(Debug, Clone, Deserialize)]
struct DocsHelpSurfaceAuditContract {
    policy_id: String,
    required_help_fragments: Vec<String>,
    banned_help_fragments: Vec<String>,
    required_readme_fragments: Vec<String>,
    banned_readme_fragments: Vec<String>,
}

pub fn zero_placeholder_scan_inventory() -> ZeroPlaceholderInventory {
    let parser_inventory = parser_gap_inventory::parser_gap_inventory();
    let lowering_inventory = lowering_gap_inventory::lowering_gap_inventory();

    let mut findings = Vec::with_capacity(ZERO_PLACEHOLDER_SCAN_FINDING_COUNT);
    findings.extend(parser_findings(&parser_inventory));
    findings.extend(lowering_findings(&lowering_inventory));
    findings.extend(runtime_findings());
    findings.push(cli_docs_truth_guard_finding());

    ZeroPlaceholderInventory {
        schema_version: ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        findings,
    }
}

pub fn write_zero_placeholder_scan_bundle(
    out_dir: impl AsRef<Path>,
    command_lines: &[String],
) -> Result<ZeroPlaceholderScanArtifacts, ZeroPlaceholderScanWriteError> {
    let out_dir = out_dir.as_ref().to_path_buf();
    fs::create_dir_all(&out_dir).map_err(|source| ZeroPlaceholderScanWriteError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;

    let inventory = zero_placeholder_scan_inventory();
    let inventory_path = out_dir.join("zero_placeholder_inventory.json");
    let trace_ids_path = out_dir.join("trace_ids.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");

    let inventory_bytes = canonical_json_bytes(&inventory, &inventory_path)?;
    let inventory_hash = sha256_hex(&inventory_bytes);
    let short_hash = inventory_hash.chars().take(16).collect::<String>();
    let trace_id = format!("trace-zero-placeholder-{short_hash}");
    let decision_id = format!("decision-zero-placeholder-{short_hash}");

    let trace_ids = ZeroPlaceholderScanTraceIds {
        schema_version: ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
    };
    let trace_ids_bytes = canonical_json_bytes(&trace_ids, &trace_ids_path)?;

    let manifest = ZeroPlaceholderScanRunManifest {
        schema_version: ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
        inventory_hash: inventory_hash.clone(),
        finding_count: inventory.findings.len() as u64,
        open_placeholder_finding_count: inventory.open_placeholder_finding_count() as u64,
        fail_closed_finding_count: inventory.fail_closed_finding_count() as u64,
        resolved_finding_count: inventory.resolved_finding_count() as u64,
        subsystem_summaries: inventory.subsystem_summaries(),
        artifact_paths: ZeroPlaceholderScanArtifactPaths {
            zero_placeholder_inventory: "zero_placeholder_inventory.json".to_string(),
            trace_ids: "trace_ids.json".to_string(),
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
            serde_json::to_string(event).map_err(|source| ZeroPlaceholderScanWriteError::Json {
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
    write_atomic(&trace_ids_path, &trace_ids_bytes)?;
    write_atomic(&events_path, events_jsonl.as_bytes())?;
    write_atomic(&commands_path, commands_buf.as_bytes())?;
    write_atomic(&run_manifest_path, &manifest_bytes)?;

    Ok(ZeroPlaceholderScanArtifacts {
        out_dir,
        inventory_path,
        trace_ids_path,
        run_manifest_path,
        events_path,
        commands_path,
        inventory_hash,
        finding_count: inventory.findings.len(),
    })
}

fn parser_findings(inventory: &ParserGapInventory) -> Vec<ZeroPlaceholderFinding> {
    inventory
        .sites
        .iter()
        .map(|site| ZeroPlaceholderFinding {
            finding_id: format!("parser::{}", site.site_id),
            subsystem: ZeroPlaceholderSubsystem::Parser,
            status: map_parser_status(site.remediation_status),
            severity: severity_for_status(map_parser_status(site.remediation_status)),
            owner: site.owner.clone(),
            owner_bead_id: bead_id_for_parser_feature(&site.feature_family).to_string(),
            subject_area: site.feature_family.clone(),
            source_reference: site.source_reference.clone(),
            observed_behavior: site.observed_fallback_behavior.clone(),
            required_behavior: site.required_fail_closed_contract.clone(),
            diagnostic_code: Some(site.desired_diagnostic_code.clone()),
        })
        .collect()
}

fn lowering_findings(inventory: &LoweringGapInventory) -> Vec<ZeroPlaceholderFinding> {
    inventory
        .sites
        .iter()
        .map(|site| ZeroPlaceholderFinding {
            finding_id: format!("lowering::{}", site.site_id),
            subsystem: ZeroPlaceholderSubsystem::Lowering,
            status: map_lowering_status(site.status),
            severity: severity_for_status(map_lowering_status(site.status)),
            owner: site.owner.clone(),
            owner_bead_id: bead_id_for_lowering_family(&site.ast_node_family).to_string(),
            subject_area: site.ast_node_family.clone(),
            source_reference: site.source_reference.clone(),
            observed_behavior: site.user_visible_divergence.clone(),
            required_behavior: site.target_replacement_strategy.clone(),
            diagnostic_code: Some(site.diagnostic_code.clone()),
        })
        .collect()
}

fn runtime_findings() -> Vec<ZeroPlaceholderFinding> {
    vec![
        ZeroPlaceholderFinding {
            finding_id: "runtime::json_parse_compound_placeholder".to_string(),
            subsystem: ZeroPlaceholderSubsystem::Runtime,
            status: ZeroPlaceholderStatus::OpenPlaceholder,
            severity: ZeroPlaceholderSeverity::High,
            owner: "stdlib".to_string(),
            owner_bead_id: JSON_RUNTIME_BEAD_ID.to_string(),
            subject_area: "json.parse.compound".to_string(),
            source_reference: "crates/franken-engine/src/stdlib.rs::json_parse".to_string(),
            observed_behavior:
                "JSON.parse returns a [json-compound:<len>] descriptor for arrays and objects instead of a heap-backed value."
                    .to_string(),
            required_behavior:
                "Parse arrays and objects into deterministic runtime values without placeholder descriptors."
                    .to_string(),
            diagnostic_code: None,
        },
        ZeroPlaceholderFinding {
            finding_id: "runtime::json_stringify_object_placeholder".to_string(),
            subsystem: ZeroPlaceholderSubsystem::Runtime,
            status: ZeroPlaceholderStatus::OpenPlaceholder,
            severity: ZeroPlaceholderSeverity::High,
            owner: "stdlib".to_string(),
            owner_bead_id: JSON_RUNTIME_BEAD_ID.to_string(),
            subject_area: "json.stringify.object".to_string(),
            source_reference: "crates/franken-engine/src/stdlib.rs::json_stringify".to_string(),
            observed_behavior:
                "JSON.stringify returns the [json-object] placeholder for Object and Function values instead of traversing heap state."
                    .to_string(),
            required_behavior:
                "Stringify object graphs and callable values through deterministic heap traversal instead of placeholder output."
                    .to_string(),
            diagnostic_code: None,
        },
        ZeroPlaceholderFinding {
            finding_id: "runtime::iterator_ir3_placeholder_execution".to_string(),
            subsystem: ZeroPlaceholderSubsystem::Runtime,
            status: ZeroPlaceholderStatus::Resolved,
            severity: ZeroPlaceholderSeverity::Low,
            owner: "iterator_protocol".to_string(),
            owner_bead_id: ITERATOR_RUNTIME_BEAD_ID.to_string(),
            subject_area: "iterator_protocol.ir3_execution".to_string(),
            source_reference:
                "crates/franken-engine/src/lowering_pipeline.rs::lower_ir1_to_ir3(iterator ops); crates/franken-engine/src/baseline_interpreter.rs"
                    .to_string(),
            observed_behavior:
                "IR1 iterator ops now lower into dedicated IR3 iterator instructions, and baseline_interpreter executes deterministic for..in/for..of next/done/close state transitions without placeholder Move/Jump lowering."
                    .to_string(),
            required_behavior:
                "Lower iterator protocol ops into dedicated IR3 instructions and execute deterministic next/done/close semantics in the baseline interpreter without placeholder moves or no-op close behavior."
                    .to_string(),
            diagnostic_code: None,
        },
    ]
}

fn cli_docs_truth_guard_finding() -> ZeroPlaceholderFinding {
    let required_behavior = format!(
        "Keep README/help claims aligned with the shipped CLI surface and the {CLI_DOCS_HELP_POLICY_ID} contract."
    );
    let source_reference = "docs/rgc_docs_help_surface_audit_v1.json; README.md; crates/franken-engine/src/bin/frankenctl.rs";

    let contract =
        match serde_json::from_str::<DocsHelpSurfaceAuditContract>(DOCS_HELP_AUDIT_CONTRACT_JSON) {
            Ok(contract) => contract,
            Err(error) => {
                return ZeroPlaceholderFinding {
                    finding_id: "cli_docs::help_surface_truth_guard".to_string(),
                    subsystem: ZeroPlaceholderSubsystem::CliDocs,
                    status: ZeroPlaceholderStatus::FailClosed,
                    severity: ZeroPlaceholderSeverity::Medium,
                    owner: "docs_help_surface_audit".to_string(),
                    owner_bead_id: CLI_DOCS_HELP_BEAD_ID.to_string(),
                    subject_area: "surface.help_and_readme".to_string(),
                    source_reference: source_reference.to_string(),
                    observed_behavior: format!(
                        "docs/help truth contract could not be parsed: {error}"
                    ),
                    required_behavior,
                    diagnostic_code: None,
                };
            }
        };

    let repo_root = repo_root();
    let readme_path = repo_root.join("README.md");
    let help_source_path = repo_root.join("crates/franken-engine/src/bin/frankenctl.rs");
    let readme = match fs::read_to_string(&readme_path) {
        Ok(contents) => contents,
        Err(error) => {
            return ZeroPlaceholderFinding {
                finding_id: "cli_docs::help_surface_truth_guard".to_string(),
                subsystem: ZeroPlaceholderSubsystem::CliDocs,
                status: ZeroPlaceholderStatus::FailClosed,
                severity: ZeroPlaceholderSeverity::Medium,
                owner: "docs_help_surface_audit".to_string(),
                owner_bead_id: CLI_DOCS_HELP_BEAD_ID.to_string(),
                subject_area: "surface.help_and_readme".to_string(),
                source_reference: source_reference.to_string(),
                observed_behavior: format!(
                    "docs/help truth guard could not read {}: {error}",
                    readme_path.display()
                ),
                required_behavior,
                diagnostic_code: None,
            };
        }
    };
    let help_source = match fs::read_to_string(&help_source_path) {
        Ok(contents) => contents,
        Err(error) => {
            return ZeroPlaceholderFinding {
                finding_id: "cli_docs::help_surface_truth_guard".to_string(),
                subsystem: ZeroPlaceholderSubsystem::CliDocs,
                status: ZeroPlaceholderStatus::FailClosed,
                severity: ZeroPlaceholderSeverity::Medium,
                owner: "docs_help_surface_audit".to_string(),
                owner_bead_id: CLI_DOCS_HELP_BEAD_ID.to_string(),
                subject_area: "surface.help_and_readme".to_string(),
                source_reference: source_reference.to_string(),
                observed_behavior: format!(
                    "docs/help truth guard could not read {}: {error}",
                    help_source_path.display()
                ),
                required_behavior,
                diagnostic_code: None,
            };
        }
    };

    let (status, severity, observed_behavior) =
        evaluate_cli_docs_truth_guard(&contract, &readme, &help_source);

    ZeroPlaceholderFinding {
        finding_id: "cli_docs::help_surface_truth_guard".to_string(),
        subsystem: ZeroPlaceholderSubsystem::CliDocs,
        status,
        severity,
        owner: "docs_help_surface_audit".to_string(),
        owner_bead_id: CLI_DOCS_HELP_BEAD_ID.to_string(),
        subject_area: "surface.help_and_readme".to_string(),
        source_reference: source_reference.to_string(),
        observed_behavior,
        required_behavior,
        diagnostic_code: None,
    }
}

fn evaluate_cli_docs_truth_guard(
    contract: &DocsHelpSurfaceAuditContract,
    readme: &str,
    help_source: &str,
) -> (ZeroPlaceholderStatus, ZeroPlaceholderSeverity, String) {
    let mut mismatches = Vec::new();

    for fragment in &contract.required_readme_fragments {
        if !readme.contains(fragment) {
            mismatches.push(format!("missing README fragment `{fragment}`"));
        }
    }
    for fragment in &contract.banned_readme_fragments {
        if readme.contains(fragment) {
            mismatches.push(format!("banned README fragment present `{fragment}`"));
        }
    }
    for fragment in &contract.required_help_fragments {
        if !help_source.contains(fragment) {
            mismatches.push(format!("missing help fragment `{fragment}`"));
        }
    }
    for fragment in &contract.banned_help_fragments {
        if help_source.contains(fragment) {
            mismatches.push(format!("banned help fragment present `{fragment}`"));
        }
    }

    if mismatches.is_empty() {
        (
            ZeroPlaceholderStatus::Resolved,
            ZeroPlaceholderSeverity::Low,
            format!(
                "README/help source currently satisfies the {} contract: {} required README fragments, {} required help fragments, and no banned fragments detected.",
                contract.policy_id,
                contract.required_readme_fragments.len(),
                contract.required_help_fragments.len(),
            ),
        )
    } else {
        (
            ZeroPlaceholderStatus::FailClosed,
            ZeroPlaceholderSeverity::Medium,
            format!(
                "docs/help truth contract drift detected under {}: {}",
                contract.policy_id,
                mismatches.join("; "),
            ),
        )
    }
}

fn build_inventory_events(
    inventory: &ZeroPlaceholderInventory,
    trace_id: &str,
    decision_id: &str,
) -> Vec<ZeroPlaceholderScanEvent> {
    let mut events = vec![ZeroPlaceholderScanEvent {
        schema_version: ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        event: "inventory_started".to_string(),
        outcome: "started".to_string(),
        subsystem: None,
        finding_id: None,
        detail: Some("authoritative zero-placeholder scan generation began".to_string()),
    }];

    events.extend(
        inventory
            .findings
            .iter()
            .map(|finding| ZeroPlaceholderScanEvent {
                schema_version: ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.to_string(),
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
                component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
                event: "finding_recorded".to_string(),
                outcome: finding.status.as_str().to_string(),
                subsystem: Some(finding.subsystem),
                finding_id: Some(finding.finding_id.clone()),
                detail: Some(finding.observed_behavior.clone()),
            }),
    );

    events.push(ZeroPlaceholderScanEvent {
        schema_version: ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        event: "inventory_completed".to_string(),
        outcome: "completed".to_string(),
        subsystem: None,
        finding_id: None,
        detail: Some(format!(
            "{} findings recorded ({} open placeholders, {} fail-closed, {} resolved)",
            inventory.findings.len(),
            inventory.open_placeholder_finding_count(),
            inventory.fail_closed_finding_count(),
            inventory.resolved_finding_count(),
        )),
    });

    events
}

fn canonical_json_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, ZeroPlaceholderScanWriteError> {
    serde_json::to_vec(value).map_err(|source| ZeroPlaceholderScanWriteError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn acquire_bundle_write_lock(
    out_dir: &Path,
) -> Result<BundleWriteLock, ZeroPlaceholderScanWriteError> {
    let lock_path = out_dir.join(".zero_placeholder_scan.lock");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(BundleWriteLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            Err(ZeroPlaceholderScanWriteError::Busy {
                path: lock_path.display().to_string(),
            })
        }
        Err(source) => Err(ZeroPlaceholderScanWriteError::Io {
            path: lock_path.display().to_string(),
            source,
        }),
    }
}

fn remove_commit_marker(path: &Path) -> Result<(), ZeroPlaceholderScanWriteError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ZeroPlaceholderScanWriteError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ZeroPlaceholderScanWriteError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ZeroPlaceholderScanWriteError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| ZeroPlaceholderScanWriteError::Io {
        path: temp_path.display().to_string(),
        source,
    })?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(ZeroPlaceholderScanWriteError::Io {
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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn map_parser_status(status: ParserGapRemediationStatus) -> ZeroPlaceholderStatus {
    match status {
        ParserGapRemediationStatus::OpenPlaceholder => ZeroPlaceholderStatus::OpenPlaceholder,
        ParserGapRemediationStatus::FailClosed => ZeroPlaceholderStatus::FailClosed,
        ParserGapRemediationStatus::Resolved => ZeroPlaceholderStatus::Resolved,
    }
}

fn map_lowering_status(status: LoweringGapStatus) -> ZeroPlaceholderStatus {
    match status {
        LoweringGapStatus::OpenPlaceholder => ZeroPlaceholderStatus::OpenPlaceholder,
        LoweringGapStatus::FailClosed => ZeroPlaceholderStatus::FailClosed,
        LoweringGapStatus::Resolved => ZeroPlaceholderStatus::Resolved,
    }
}

fn severity_for_status(status: ZeroPlaceholderStatus) -> ZeroPlaceholderSeverity {
    match status {
        ZeroPlaceholderStatus::OpenPlaceholder => ZeroPlaceholderSeverity::High,
        ZeroPlaceholderStatus::FailClosed => ZeroPlaceholderSeverity::Medium,
        ZeroPlaceholderStatus::Resolved => ZeroPlaceholderSeverity::Low,
    }
}

fn bead_id_for_parser_feature(feature_family: &str) -> &'static str {
    match feature_family {
        "for_in_statement" | "for_of_statement" => "bd-1lsy.4.8",
        "new_expression" | "template_literal" => "bd-1lsy.4.7.2",
        "binary_non_arithmetic_expression" => "bd-1lsy.4.7.3",
        "member_assignment_expression" => "bd-1lsy.4.7.1",
        _ => "bd-1lsy.9.5.1",
    }
}

fn bead_id_for_lowering_family(ast_node_family: &str) -> &'static str {
    match ast_node_family {
        "statement.for_in" | "statement.for_of" => "bd-1lsy.4.8",
        "expression.new" | "expression.template_literal" => "bd-1lsy.4.7.2",
        "expression.binary_non_arithmetic" => "bd-1lsy.4.7.3",
        "expression.assignment_member_target" => "bd-1lsy.4.7.1",
        _ => "bd-1lsy.9.5.1",
    }
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

    fn sample_contract() -> DocsHelpSurfaceAuditContract {
        DocsHelpSurfaceAuditContract {
            policy_id: CLI_DOCS_HELP_POLICY_ID.to_string(),
            required_help_fragments: vec!["frankenctl usage:".to_string()],
            banned_help_fragments: vec!["frankenctl init".to_string()],
            required_readme_fragments: vec!["frankenctl compile".to_string()],
            banned_readme_fragments: vec!["frankenctl shadow-run".to_string()],
        }
    }

    #[test]
    fn schema_version_constants_are_non_empty() {
        assert!(!ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.is_empty());
        assert!(!ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION.is_empty());
        assert!(!ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!ZERO_PLACEHOLDER_SCAN_COMPONENT.is_empty());
        assert!(!ZERO_PLACEHOLDER_SCAN_POLICY_ID.is_empty());
        const { assert!(ZERO_PLACEHOLDER_SCAN_FINDING_COUNT > 0) };
    }

    #[test]
    fn zero_placeholder_subsystem_all_has_four_variants() {
        assert_eq!(ZeroPlaceholderSubsystem::ALL.len(), 4);
    }

    #[test]
    fn zero_placeholder_subsystem_serde_round_trip() {
        for subsystem in ZeroPlaceholderSubsystem::ALL {
            let json = serde_json::to_string(&subsystem).unwrap();
            let back: ZeroPlaceholderSubsystem = serde_json::from_str(&json).unwrap();
            assert_eq!(back, subsystem);
            assert!(!subsystem.as_str().is_empty());
        }
    }

    #[test]
    fn zero_placeholder_status_serde_round_trip() {
        for status in [
            ZeroPlaceholderStatus::OpenPlaceholder,
            ZeroPlaceholderStatus::FailClosed,
            ZeroPlaceholderStatus::Resolved,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: ZeroPlaceholderStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
            assert!(!status.as_str().is_empty());
        }
    }

    #[test]
    fn zero_placeholder_severity_serde_round_trip() {
        for severity in [
            ZeroPlaceholderSeverity::High,
            ZeroPlaceholderSeverity::Medium,
            ZeroPlaceholderSeverity::Low,
        ] {
            let json = serde_json::to_string(&severity).unwrap();
            let back: ZeroPlaceholderSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(back, severity);
            assert!(!severity.as_str().is_empty());
        }
    }

    #[test]
    fn severity_maps_correctly_from_status() {
        assert_eq!(
            severity_for_status(ZeroPlaceholderStatus::OpenPlaceholder),
            ZeroPlaceholderSeverity::High
        );
        assert_eq!(
            severity_for_status(ZeroPlaceholderStatus::FailClosed),
            ZeroPlaceholderSeverity::Medium
        );
        assert_eq!(
            severity_for_status(ZeroPlaceholderStatus::Resolved),
            ZeroPlaceholderSeverity::Low
        );
    }

    #[test]
    fn finding_ids_are_unique() {
        let inventory = zero_placeholder_scan_inventory();
        let ids: std::collections::BTreeSet<&str> = inventory
            .findings
            .iter()
            .map(|finding| finding.finding_id.as_str())
            .collect();
        assert_eq!(ids.len(), inventory.findings.len());
    }

    #[test]
    fn subsystem_summaries_cover_all_subsystems() {
        let inventory = zero_placeholder_scan_inventory();
        let summaries = inventory.subsystem_summaries();
        assert_eq!(summaries.len(), ZeroPlaceholderSubsystem::ALL.len());

        let total_from_summaries: u64 = summaries.iter().map(|s| s.finding_count).sum();
        assert_eq!(total_from_summaries as usize, inventory.findings.len());

        for summary in &summaries {
            assert_eq!(
                summary.finding_count,
                summary.open_placeholder_finding_count
                    + summary.fail_closed_finding_count
                    + summary.resolved_finding_count
            );
        }
    }

    #[test]
    fn zero_placeholder_finding_serde_round_trip() {
        let finding = ZeroPlaceholderFinding {
            finding_id: "test::finding".to_string(),
            subsystem: ZeroPlaceholderSubsystem::Runtime,
            status: ZeroPlaceholderStatus::OpenPlaceholder,
            severity: ZeroPlaceholderSeverity::High,
            owner: "test_owner".to_string(),
            owner_bead_id: "bd-test".to_string(),
            subject_area: "test.area".to_string(),
            source_reference: "src/test.rs".to_string(),
            observed_behavior: "observed".to_string(),
            required_behavior: "required".to_string(),
            diagnostic_code: Some("FE-TEST-0001".to_string()),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: ZeroPlaceholderFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
    }

    #[test]
    fn zero_placeholder_scan_event_serde_round_trip() {
        let event = ZeroPlaceholderScanEvent {
            schema_version: ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
            component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
            event: "finding_recorded".to_string(),
            outcome: "open_placeholder".to_string(),
            subsystem: Some(ZeroPlaceholderSubsystem::Parser),
            finding_id: Some("parser::test".to_string()),
            detail: Some("test detail".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ZeroPlaceholderScanEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn cli_docs_truth_guard_reports_all_mismatches() {
        let contract = DocsHelpSurfaceAuditContract {
            policy_id: "test-policy".to_string(),
            required_help_fragments: vec!["required_help".to_string()],
            banned_help_fragments: vec![],
            required_readme_fragments: vec!["required_readme".to_string()],
            banned_readme_fragments: vec!["banned_readme".to_string()],
        };
        let (status, _, detail) =
            evaluate_cli_docs_truth_guard(&contract, "banned_readme present", "no match");
        assert_eq!(status, ZeroPlaceholderStatus::FailClosed);
        assert!(detail.contains("missing README fragment"));
        assert!(detail.contains("banned README fragment present"));
        assert!(detail.contains("missing help fragment"));
    }

    #[test]
    fn zero_placeholder_inventory_aggregates_all_subsystems() {
        let inventory = zero_placeholder_scan_inventory();
        assert_eq!(
            inventory.findings.len(),
            ZERO_PLACEHOLDER_SCAN_FINDING_COUNT
        );
        assert_eq!(inventory.open_placeholder_finding_count(), 2);

        let parser_count = inventory
            .findings
            .iter()
            .filter(|finding| finding.subsystem == ZeroPlaceholderSubsystem::Parser)
            .count();
        let lowering_count = inventory
            .findings
            .iter()
            .filter(|finding| finding.subsystem == ZeroPlaceholderSubsystem::Lowering)
            .count();
        let runtime_count = inventory
            .findings
            .iter()
            .filter(|finding| finding.subsystem == ZeroPlaceholderSubsystem::Runtime)
            .count();
        let cli_docs_count = inventory
            .findings
            .iter()
            .filter(|finding| finding.subsystem == ZeroPlaceholderSubsystem::CliDocs)
            .count();

        assert_eq!(parser_count, 6);
        assert_eq!(lowering_count, 6);
        assert_eq!(runtime_count, 3);
        assert_eq!(cli_docs_count, 1);
    }

    #[test]
    fn runtime_findings_keep_iterator_gap_resolved() {
        let inventory = zero_placeholder_scan_inventory();
        let runtime_findings: Vec<_> = inventory
            .findings
            .iter()
            .filter(|finding| finding.subsystem == ZeroPlaceholderSubsystem::Runtime)
            .collect();
        assert_eq!(runtime_findings.len(), 3);
        assert_eq!(
            runtime_findings
                .iter()
                .filter(|finding| finding.status == ZeroPlaceholderStatus::OpenPlaceholder)
                .count(),
            2
        );
        let iterator_finding = runtime_findings
            .iter()
            .find(|finding| finding.finding_id == "runtime::iterator_ir3_placeholder_execution")
            .expect("iterator runtime finding");
        assert_eq!(iterator_finding.status, ZeroPlaceholderStatus::Resolved);
        assert_eq!(iterator_finding.severity, ZeroPlaceholderSeverity::Low);
    }

    #[test]
    fn runtime_findings_include_iterator_ir3_placeholder_gap() {
        let inventory = zero_placeholder_scan_inventory();
        let finding = inventory
            .findings
            .iter()
            .find(|finding| finding.finding_id == "runtime::iterator_ir3_placeholder_execution")
            .expect("iterator runtime placeholder finding");
        assert_eq!(finding.owner_bead_id, ITERATOR_RUNTIME_BEAD_ID);
        assert!(finding.source_reference.contains("lowering_pipeline"));
        assert!(finding.source_reference.contains("baseline_interpreter"));
        assert!(
            finding
                .observed_behavior
                .contains("dedicated IR3 iterator instructions")
        );
    }

    #[test]
    fn cli_docs_truth_guard_resolves_when_fragments_match() {
        let contract = sample_contract();
        let (status, severity, detail) =
            evaluate_cli_docs_truth_guard(&contract, "frankenctl compile\n", "frankenctl usage:\n");
        assert_eq!(status, ZeroPlaceholderStatus::Resolved);
        assert_eq!(severity, ZeroPlaceholderSeverity::Low);
        assert!(detail.contains("satisfies"));
    }

    #[test]
    fn cli_docs_truth_guard_fails_closed_on_fragment_drift() {
        let contract = sample_contract();
        let (status, severity, detail) =
            evaluate_cli_docs_truth_guard(&contract, "shadow", "frankenctl init");
        assert_eq!(status, ZeroPlaceholderStatus::FailClosed);
        assert_eq!(severity, ZeroPlaceholderSeverity::Medium);
        assert!(detail.contains("drift detected"));
        assert!(detail.contains("missing README fragment"));
        assert!(detail.contains("banned help fragment present"));
    }

    #[test]
    fn write_zero_placeholder_scan_bundle_emits_expected_artifacts() {
        let out_dir = unique_temp_dir("zero-placeholder-scan");
        let commands = vec![
            "franken_zero_placeholder_scan".to_string(),
            "--out-dir".to_string(),
            out_dir.display().to_string(),
        ];
        let artifacts =
            write_zero_placeholder_scan_bundle(&out_dir, &commands).expect("write artifacts");
        assert!(artifacts.inventory_path.exists());
        assert!(artifacts.trace_ids_path.exists());
        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.commands_path.exists());

        let inventory: ZeroPlaceholderInventory =
            serde_json::from_slice(&fs::read(&artifacts.inventory_path).expect("read inventory"))
                .expect("inventory json");
        assert_eq!(
            inventory.findings.len(),
            ZERO_PLACEHOLDER_SCAN_FINDING_COUNT
        );

        let manifest: ZeroPlaceholderScanRunManifest =
            serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
                .expect("manifest json");
        assert_eq!(
            manifest.finding_count as usize,
            ZERO_PLACEHOLDER_SCAN_FINDING_COUNT
        );
        assert_eq!(manifest.open_placeholder_finding_count, 2);
        assert_eq!(
            manifest.open_placeholder_finding_count
                + manifest.fail_closed_finding_count
                + manifest.resolved_finding_count,
            manifest.finding_count
        );
        assert_eq!(manifest.subsystem_summaries.len(), 4);

        let trace_ids: ZeroPlaceholderScanTraceIds =
            serde_json::from_slice(&fs::read(&artifacts.trace_ids_path).expect("read trace ids"))
                .expect("trace ids json");
        assert_eq!(
            trace_ids.schema_version,
            ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION
        );
        assert_eq!(trace_ids.inventory_hash, artifacts.inventory_hash);

        let events = fs::read_to_string(&artifacts.events_path).expect("read events");
        assert_eq!(
            events.lines().count(),
            ZERO_PLACEHOLDER_SCAN_FINDING_COUNT + 2
        );

        let commands_txt = fs::read_to_string(&artifacts.commands_path).expect("read commands");
        assert!(commands_txt.contains("franken_zero_placeholder_scan"));
        assert!(commands_txt.contains("--out-dir"));
        assert!(!out_dir.join(".zero_placeholder_scan.lock").exists());
    }

    #[test]
    fn unique_temp_path_is_distinct_for_each_write_attempt() {
        let target = Path::new("artifacts/zero_placeholder_inventory.json");
        let first = unique_temp_path(target);
        let second = unique_temp_path(target);
        assert_ne!(first, second);
        assert_eq!(first.parent(), second.parent());
        assert_ne!(first.file_name(), Some(target.as_os_str()));
        assert_ne!(second.file_name(), Some(target.as_os_str()));
    }

    #[test]
    fn bundle_write_lock_rejects_concurrent_writer_until_release() {
        let out_dir = unique_temp_dir("zero-placeholder-lock");
        fs::create_dir_all(&out_dir).expect("create lock dir");

        let first = acquire_bundle_write_lock(&out_dir).expect("first lock");
        let second = acquire_bundle_write_lock(&out_dir).expect_err("second lock should fail");
        assert!(matches!(second, ZeroPlaceholderScanWriteError::Busy { .. }));

        drop(first);

        acquire_bundle_write_lock(&out_dir).expect("lock should be acquirable after release");
    }

    #[test]
    fn busy_bundle_write_does_not_mutate_existing_artifacts() {
        let out_dir = unique_temp_dir("zero-placeholder-busy");
        fs::create_dir_all(&out_dir).expect("create out dir");
        let events_path = out_dir.join("events.jsonl");
        fs::write(&events_path, "previous-events\n").expect("seed events");
        let commands = vec!["franken_zero_placeholder_scan".to_string()];

        let lock = acquire_bundle_write_lock(&out_dir).expect("hold lock");
        let err = write_zero_placeholder_scan_bundle(&out_dir, &commands)
            .expect_err("write should block");
        assert!(matches!(err, ZeroPlaceholderScanWriteError::Busy { .. }));
        assert_eq!(
            fs::read_to_string(&events_path).expect("read events after busy failure"),
            "previous-events\n"
        );
        drop(lock);
    }

    #[test]
    fn failed_rewrite_removes_stale_manifest_commit_marker() {
        let out_dir = unique_temp_dir("zero-placeholder-stale-manifest");
        fs::create_dir_all(&out_dir).expect("create out dir");
        let run_manifest_path = out_dir.join("run_manifest.json");
        fs::write(&run_manifest_path, "{\"stale\":true}\n").expect("seed stale manifest");
        fs::create_dir_all(out_dir.join("zero_placeholder_inventory.json"))
            .expect("create blocking directory");

        let commands = vec!["franken_zero_placeholder_scan".to_string()];
        let err = write_zero_placeholder_scan_bundle(&out_dir, &commands)
            .expect_err("rewrite should fail when target path is a directory");
        assert!(matches!(err, ZeroPlaceholderScanWriteError::Io { .. }));
        assert!(
            !run_manifest_path.exists(),
            "stale commit marker should be removed on failed rewrite"
        );
        assert!(
            !out_dir.join(".zero_placeholder_scan.lock").exists(),
            "bundle lock should be released after failure",
        );
    }

    #[test]
    fn schema_version_constants_are_all_distinct() {
        let versions = [
            ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION,
            ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION,
            ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION,
            ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION,
            ZERO_PLACEHOLDER_SCAN_POLICY_ID,
        ];
        let unique: std::collections::BTreeSet<&str> = versions.iter().copied().collect();
        assert_eq!(
            unique.len(),
            versions.len(),
            "all schema version / policy constants must be distinct"
        );
    }

    #[test]
    fn scan_event_serde_round_trip_with_none_optionals() {
        let event = ZeroPlaceholderScanEvent {
            schema_version: ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: "trace-none".to_string(),
            decision_id: "decision-none".to_string(),
            policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
            component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
            event: "inventory_started".to_string(),
            outcome: "started".to_string(),
            subsystem: None,
            finding_id: None,
            detail: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        // None fields with skip_serializing_if should be absent from JSON
        assert!(!json.contains("subsystem"));
        assert!(!json.contains("finding_id"));
        assert!(!json.contains("detail"));
        let back: ZeroPlaceholderScanEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn finding_serde_round_trip_with_none_diagnostic_code() {
        let finding = ZeroPlaceholderFinding {
            finding_id: "test::no_diag".to_string(),
            subsystem: ZeroPlaceholderSubsystem::Runtime,
            status: ZeroPlaceholderStatus::FailClosed,
            severity: ZeroPlaceholderSeverity::Medium,
            owner: "test_owner".to_string(),
            owner_bead_id: "bd-test-none".to_string(),
            subject_area: "test.area".to_string(),
            source_reference: "src/test.rs".to_string(),
            observed_behavior: "observed".to_string(),
            required_behavior: "required".to_string(),
            diagnostic_code: None,
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(!json.contains("diagnostic_code"));
        let back: ZeroPlaceholderFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, finding);
    }

    #[test]
    fn bead_id_fallbacks_for_unknown_feature_families() {
        // Parser: unknown families fall back to the default bead id
        let default_parser = bead_id_for_parser_feature("unknown_feature");
        assert_eq!(default_parser, "bd-1lsy.9.5.1");

        // Known families map to specific bead IDs
        assert_eq!(
            bead_id_for_parser_feature("for_in_statement"),
            "bd-1lsy.4.8"
        );
        assert_eq!(
            bead_id_for_parser_feature("for_of_statement"),
            "bd-1lsy.4.8"
        );
        assert_eq!(
            bead_id_for_parser_feature("new_expression"),
            "bd-1lsy.4.7.2"
        );
        assert_eq!(
            bead_id_for_parser_feature("template_literal"),
            "bd-1lsy.4.7.2"
        );
        assert_eq!(
            bead_id_for_parser_feature("binary_non_arithmetic_expression"),
            "bd-1lsy.4.7.3"
        );
        assert_eq!(
            bead_id_for_parser_feature("member_assignment_expression"),
            "bd-1lsy.4.7.1"
        );

        // Lowering: unknown families also fall back to the default
        let default_lowering = bead_id_for_lowering_family("unknown_node");
        assert_eq!(default_lowering, "bd-1lsy.9.5.1");

        assert_eq!(
            bead_id_for_lowering_family("statement.for_in"),
            "bd-1lsy.4.8"
        );
        assert_eq!(
            bead_id_for_lowering_family("expression.new"),
            "bd-1lsy.4.7.2"
        );
        assert_eq!(
            bead_id_for_lowering_family("expression.binary_non_arithmetic"),
            "bd-1lsy.4.7.3"
        );
        assert_eq!(
            bead_id_for_lowering_family("expression.assignment_member_target"),
            "bd-1lsy.4.7.1"
        );
    }

    #[test]
    fn cli_docs_truth_guard_detects_banned_readme_fragment_only() {
        let contract = DocsHelpSurfaceAuditContract {
            policy_id: "test-policy".to_string(),
            required_help_fragments: vec![],
            banned_help_fragments: vec![],
            required_readme_fragments: vec![],
            banned_readme_fragments: vec!["deprecated_feature".to_string()],
        };
        // Banned fragment present => FailClosed
        let (status, severity, detail) = evaluate_cli_docs_truth_guard(
            &contract,
            "This README mentions deprecated_feature which is banned",
            "clean help source",
        );
        assert_eq!(status, ZeroPlaceholderStatus::FailClosed);
        assert_eq!(severity, ZeroPlaceholderSeverity::Medium);
        assert!(detail.contains("banned README fragment present"));

        // Banned fragment absent => Resolved
        let (status2, severity2, _) = evaluate_cli_docs_truth_guard(
            &contract,
            "clean README without banned content",
            "clean help source",
        );
        assert_eq!(status2, ZeroPlaceholderStatus::Resolved);
        assert_eq!(severity2, ZeroPlaceholderSeverity::Low);
    }

    #[test]
    fn subsystem_summaries_on_empty_inventory_yields_zeros() {
        let inventory = ZeroPlaceholderInventory {
            schema_version: ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.to_string(),
            component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
            findings: vec![],
        };
        assert_eq!(inventory.open_placeholder_finding_count(), 0);
        assert_eq!(inventory.fail_closed_finding_count(), 0);
        assert_eq!(inventory.resolved_finding_count(), 0);

        let summaries = inventory.subsystem_summaries();
        assert_eq!(summaries.len(), 4);
        for summary in &summaries {
            assert_eq!(summary.finding_count, 0);
            assert_eq!(summary.open_placeholder_finding_count, 0);
            assert_eq!(summary.fail_closed_finding_count, 0);
            assert_eq!(summary.resolved_finding_count, 0);
        }
    }

    // --- Enrichment tests (PearlTower 2026-03-16) ---

    #[test]
    fn zero_placeholder_subsystem_serde_roundtrip() {
        for s in ZeroPlaceholderSubsystem::ALL {
            let json = serde_json::to_string(&s).unwrap();
            let back: ZeroPlaceholderSubsystem = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn zero_placeholder_subsystem_as_str_distinct() {
        let strs: std::collections::BTreeSet<&str> = ZeroPlaceholderSubsystem::ALL
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(strs.len(), ZeroPlaceholderSubsystem::ALL.len());
    }

    #[test]
    fn zero_placeholder_status_serde_roundtrip() {
        for s in [
            ZeroPlaceholderStatus::OpenPlaceholder,
            ZeroPlaceholderStatus::FailClosed,
            ZeroPlaceholderStatus::Resolved,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: ZeroPlaceholderStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn zero_placeholder_severity_serde_roundtrip() {
        for s in [
            ZeroPlaceholderSeverity::Low,
            ZeroPlaceholderSeverity::Medium,
            ZeroPlaceholderSeverity::High,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: ZeroPlaceholderSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn schema_version_constants_non_empty() {
        assert!(!ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.is_empty());
        assert!(!ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION.is_empty());
        assert!(!ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!ZERO_PLACEHOLDER_SCAN_COMPONENT.is_empty());
        assert!(!ZERO_PLACEHOLDER_SCAN_POLICY_ID.is_empty());
    }

    #[test]
    fn subsystem_all_has_four_variants() {
        assert_eq!(ZeroPlaceholderSubsystem::ALL.len(), 4);
    }

    #[test]
    fn cli_docs_truth_guard_resolves_clean_input() {
        let contract = DocsHelpSurfaceAuditContract {
            policy_id: "test".to_string(),
            required_help_fragments: vec![],
            banned_help_fragments: vec![],
            required_readme_fragments: vec![],
            banned_readme_fragments: vec![],
        };
        let (status, severity, _) = evaluate_cli_docs_truth_guard(&contract, "clean", "clean");
        assert_eq!(status, ZeroPlaceholderStatus::Resolved);
        assert_eq!(severity, ZeroPlaceholderSeverity::Low);
    }

    #[test]
    fn cli_docs_truth_guard_detects_banned_help_fragment() {
        let contract = DocsHelpSurfaceAuditContract {
            policy_id: "test".to_string(),
            required_help_fragments: vec![],
            banned_help_fragments: vec!["obsolete_cmd".to_string()],
            required_readme_fragments: vec![],
            banned_readme_fragments: vec![],
        };
        let (status, _, detail) = evaluate_cli_docs_truth_guard(
            &contract,
            "clean readme",
            "help contains obsolete_cmd here",
        );
        assert_eq!(status, ZeroPlaceholderStatus::FailClosed);
        assert!(detail.contains("banned"));
    }

    #[test]
    fn finding_count_sixteen() {
        assert_eq!(ZERO_PLACEHOLDER_SCAN_FINDING_COUNT, 16);
    }

    // --- Deep enrichment tests (PearlTower 2026-03-18) ---

    #[test]
    fn subsystem_serde_json_value_matches_as_str() {
        for subsystem in ZeroPlaceholderSubsystem::ALL {
            let json = serde_json::to_string(&subsystem).unwrap();
            let expected = format!("\"{}\"", subsystem.as_str());
            assert_eq!(
                json, expected,
                "serde JSON for {subsystem:?} must match as_str"
            );
        }
    }

    #[test]
    fn status_serde_json_value_matches_as_str() {
        for status in [
            ZeroPlaceholderStatus::OpenPlaceholder,
            ZeroPlaceholderStatus::FailClosed,
            ZeroPlaceholderStatus::Resolved,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let expected = format!("\"{}\"", status.as_str());
            assert_eq!(
                json, expected,
                "serde JSON for {status:?} must match as_str"
            );
        }
    }

    #[test]
    fn severity_serde_json_value_matches_as_str() {
        for severity in [
            ZeroPlaceholderSeverity::High,
            ZeroPlaceholderSeverity::Medium,
            ZeroPlaceholderSeverity::Low,
        ] {
            let json = serde_json::to_string(&severity).unwrap();
            let expected = format!("\"{}\"", severity.as_str());
            assert_eq!(
                json, expected,
                "serde JSON for {severity:?} must match as_str"
            );
        }
    }

    #[test]
    fn subsystem_ordering_matches_all_array_order() {
        let all = ZeroPlaceholderSubsystem::ALL;
        for window in all.windows(2) {
            assert!(
                window[0] < window[1],
                "ALL array must be in Ord order: {window:?}"
            );
        }
    }

    #[test]
    fn status_ordering_is_total() {
        let statuses = [
            ZeroPlaceholderStatus::OpenPlaceholder,
            ZeroPlaceholderStatus::FailClosed,
            ZeroPlaceholderStatus::Resolved,
        ];
        for a in &statuses {
            for b in &statuses {
                if a == b {
                    assert!(a.cmp(b) == std::cmp::Ordering::Equal);
                } else {
                    assert!(a.cmp(b) != std::cmp::Ordering::Equal);
                }
            }
        }
    }

    #[test]
    fn severity_ordering_is_total() {
        let sevs = [
            ZeroPlaceholderSeverity::High,
            ZeroPlaceholderSeverity::Medium,
            ZeroPlaceholderSeverity::Low,
        ];
        for a in &sevs {
            for b in &sevs {
                if a == b {
                    assert!(a.cmp(b) == std::cmp::Ordering::Equal);
                } else {
                    assert!(a.cmp(b) != std::cmp::Ordering::Equal);
                }
            }
        }
    }

    #[test]
    fn write_error_display_json_variant() {
        let source = serde_json::from_str::<i32>("not_json").unwrap_err();
        let err = ZeroPlaceholderScanWriteError::Json {
            path: "/tmp/test.json".to_string(),
            source,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to serialize"),
            "Json error Display must mention serialization: {msg}"
        );
        assert!(msg.contains("/tmp/test.json"), "must contain path: {msg}");
    }

    #[test]
    fn write_error_display_io_variant() {
        let source = io::Error::new(ErrorKind::PermissionDenied, "denied");
        let err = ZeroPlaceholderScanWriteError::Io {
            path: "/tmp/test.bin".to_string(),
            source,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to write"),
            "Io error Display must mention write: {msg}"
        );
        assert!(msg.contains("/tmp/test.bin"), "must contain path: {msg}");
    }

    #[test]
    fn write_error_display_busy_variant() {
        let err = ZeroPlaceholderScanWriteError::Busy {
            path: "/tmp/lock".to_string(),
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("already locked"),
            "Busy error Display must mention lock: {msg}"
        );
        assert!(msg.contains("/tmp/lock"), "must contain path: {msg}");
    }

    #[test]
    fn sha256_hex_deterministic_for_same_input() {
        let h1 = sha256_hex(b"hello world");
        let h2 = sha256_hex(b"hello world");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64, "SHA-256 hex digest must be 64 chars");
    }

    #[test]
    fn sha256_hex_empty_input_is_known_digest() {
        let h = sha256_hex(b"");
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_hex_different_inputs_differ() {
        let h1 = sha256_hex(b"input_a");
        let h2 = sha256_hex(b"input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn canonical_json_bytes_deterministic() {
        let finding = ZeroPlaceholderFinding {
            finding_id: "det::test".to_string(),
            subsystem: ZeroPlaceholderSubsystem::Parser,
            status: ZeroPlaceholderStatus::Resolved,
            severity: ZeroPlaceholderSeverity::Low,
            owner: "owner".to_string(),
            owner_bead_id: "bd-det".to_string(),
            subject_area: "det.area".to_string(),
            source_reference: "src/det.rs".to_string(),
            observed_behavior: "obs".to_string(),
            required_behavior: "req".to_string(),
            diagnostic_code: Some("DET-001".to_string()),
        };
        let path = Path::new("/tmp/det.json");
        let bytes1 = canonical_json_bytes(&finding, path).unwrap();
        let bytes2 = canonical_json_bytes(&finding, path).unwrap();
        assert_eq!(bytes1, bytes2, "canonical JSON must be deterministic");
        let hash1 = sha256_hex(&bytes1);
        let hash2 = sha256_hex(&bytes2);
        assert_eq!(hash1, hash2, "deterministic bytes => deterministic hash");
    }

    #[test]
    fn inventory_counts_mixed_statuses() {
        let findings = vec![
            ZeroPlaceholderFinding {
                finding_id: "a".to_string(),
                subsystem: ZeroPlaceholderSubsystem::Parser,
                status: ZeroPlaceholderStatus::OpenPlaceholder,
                severity: ZeroPlaceholderSeverity::High,
                owner: "o".to_string(),
                owner_bead_id: "b".to_string(),
                subject_area: "s".to_string(),
                source_reference: "r".to_string(),
                observed_behavior: "obs".to_string(),
                required_behavior: "req".to_string(),
                diagnostic_code: None,
            },
            ZeroPlaceholderFinding {
                finding_id: "b".to_string(),
                subsystem: ZeroPlaceholderSubsystem::Lowering,
                status: ZeroPlaceholderStatus::FailClosed,
                severity: ZeroPlaceholderSeverity::Medium,
                owner: "o".to_string(),
                owner_bead_id: "b".to_string(),
                subject_area: "s".to_string(),
                source_reference: "r".to_string(),
                observed_behavior: "obs".to_string(),
                required_behavior: "req".to_string(),
                diagnostic_code: None,
            },
            ZeroPlaceholderFinding {
                finding_id: "c".to_string(),
                subsystem: ZeroPlaceholderSubsystem::Runtime,
                status: ZeroPlaceholderStatus::Resolved,
                severity: ZeroPlaceholderSeverity::Low,
                owner: "o".to_string(),
                owner_bead_id: "b".to_string(),
                subject_area: "s".to_string(),
                source_reference: "r".to_string(),
                observed_behavior: "obs".to_string(),
                required_behavior: "req".to_string(),
                diagnostic_code: None,
            },
            ZeroPlaceholderFinding {
                finding_id: "d".to_string(),
                subsystem: ZeroPlaceholderSubsystem::Parser,
                status: ZeroPlaceholderStatus::Resolved,
                severity: ZeroPlaceholderSeverity::Low,
                owner: "o".to_string(),
                owner_bead_id: "b".to_string(),
                subject_area: "s".to_string(),
                source_reference: "r".to_string(),
                observed_behavior: "obs".to_string(),
                required_behavior: "req".to_string(),
                diagnostic_code: None,
            },
        ];
        let inventory = ZeroPlaceholderInventory {
            schema_version: ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.to_string(),
            component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
            findings,
        };
        assert_eq!(inventory.open_placeholder_finding_count(), 1);
        assert_eq!(inventory.fail_closed_finding_count(), 1);
        assert_eq!(inventory.resolved_finding_count(), 2);
        let summaries = inventory.subsystem_summaries();
        let parser_summary = summaries
            .iter()
            .find(|s| s.subsystem == ZeroPlaceholderSubsystem::Parser)
            .unwrap();
        assert_eq!(parser_summary.finding_count, 2);
        assert_eq!(parser_summary.open_placeholder_finding_count, 1);
        assert_eq!(parser_summary.resolved_finding_count, 1);
        let cli_docs_summary = summaries
            .iter()
            .find(|s| s.subsystem == ZeroPlaceholderSubsystem::CliDocs)
            .unwrap();
        assert_eq!(cli_docs_summary.finding_count, 0);
    }

    #[test]
    fn build_inventory_events_bookends_and_per_finding() {
        let inventory = ZeroPlaceholderInventory {
            schema_version: ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.to_string(),
            component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
            findings: vec![
                ZeroPlaceholderFinding {
                    finding_id: "evt::a".to_string(),
                    subsystem: ZeroPlaceholderSubsystem::Runtime,
                    status: ZeroPlaceholderStatus::Resolved,
                    severity: ZeroPlaceholderSeverity::Low,
                    owner: "o".to_string(),
                    owner_bead_id: "b".to_string(),
                    subject_area: "s".to_string(),
                    source_reference: "r".to_string(),
                    observed_behavior: "obs_a".to_string(),
                    required_behavior: "req".to_string(),
                    diagnostic_code: None,
                },
                ZeroPlaceholderFinding {
                    finding_id: "evt::b".to_string(),
                    subsystem: ZeroPlaceholderSubsystem::Parser,
                    status: ZeroPlaceholderStatus::OpenPlaceholder,
                    severity: ZeroPlaceholderSeverity::High,
                    owner: "o".to_string(),
                    owner_bead_id: "b".to_string(),
                    subject_area: "s".to_string(),
                    source_reference: "r".to_string(),
                    observed_behavior: "obs_b".to_string(),
                    required_behavior: "req".to_string(),
                    diagnostic_code: None,
                },
            ],
        };
        let events = build_inventory_events(&inventory, "trace-t", "decision-d");
        assert_eq!(events.len(), 4, "start + 2 findings + end");
        assert_eq!(events[0].event, "inventory_started");
        assert_eq!(events[0].outcome, "started");
        assert!(events[0].subsystem.is_none());
        assert_eq!(events[1].event, "finding_recorded");
        assert_eq!(events[1].outcome, "resolved");
        assert_eq!(events[1].finding_id.as_deref(), Some("evt::a"));
        assert_eq!(events[2].event, "finding_recorded");
        assert_eq!(events[2].outcome, "open_placeholder");
        assert_eq!(events[2].finding_id.as_deref(), Some("evt::b"));
        assert_eq!(events[3].event, "inventory_completed");
        assert_eq!(events[3].outcome, "completed");
        assert!(events[3].detail.as_ref().unwrap().contains("2 findings"));
    }

    #[test]
    fn build_inventory_events_empty_findings() {
        let inventory = ZeroPlaceholderInventory {
            schema_version: ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.to_string(),
            component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
            findings: vec![],
        };
        let events = build_inventory_events(&inventory, "t", "d");
        assert_eq!(events.len(), 2, "start + end, no finding events");
        assert_eq!(events[0].event, "inventory_started");
        assert_eq!(events[1].event, "inventory_completed");
        assert!(events[1].detail.as_ref().unwrap().contains("0 findings"));
    }

    #[test]
    fn unique_temp_path_preserves_parent_dir() {
        let path = Path::new("/some/dir/artifact.json");
        let tmp = unique_temp_path(path);
        assert_eq!(tmp.parent().unwrap(), Path::new("/some/dir"));
        let name = tmp.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with('.'), "temp file must be hidden: {name}");
        assert!(
            name.ends_with(".tmp"),
            "temp file must end with .tmp: {name}"
        );
        assert!(
            name.contains("artifact.json"),
            "temp file must embed original name: {name}"
        );
    }

    #[test]
    fn unique_temp_path_no_parent_uses_dot() {
        let path = Path::new("standalone.bin");
        let tmp = unique_temp_path(path);
        assert_eq!(tmp.parent().unwrap(), Path::new("."));
    }

    #[test]
    fn map_parser_status_covers_all_variants() {
        assert_eq!(
            map_parser_status(ParserGapRemediationStatus::OpenPlaceholder),
            ZeroPlaceholderStatus::OpenPlaceholder
        );
        assert_eq!(
            map_parser_status(ParserGapRemediationStatus::FailClosed),
            ZeroPlaceholderStatus::FailClosed
        );
        assert_eq!(
            map_parser_status(ParserGapRemediationStatus::Resolved),
            ZeroPlaceholderStatus::Resolved
        );
    }

    #[test]
    fn map_lowering_status_covers_all_variants() {
        assert_eq!(
            map_lowering_status(LoweringGapStatus::OpenPlaceholder),
            ZeroPlaceholderStatus::OpenPlaceholder
        );
        assert_eq!(
            map_lowering_status(LoweringGapStatus::FailClosed),
            ZeroPlaceholderStatus::FailClosed
        );
        assert_eq!(
            map_lowering_status(LoweringGapStatus::Resolved),
            ZeroPlaceholderStatus::Resolved
        );
    }

    #[test]
    fn severity_for_status_exhaustive_roundtrip() {
        let pairs = [
            (
                ZeroPlaceholderStatus::OpenPlaceholder,
                ZeroPlaceholderSeverity::High,
            ),
            (
                ZeroPlaceholderStatus::FailClosed,
                ZeroPlaceholderSeverity::Medium,
            ),
            (
                ZeroPlaceholderStatus::Resolved,
                ZeroPlaceholderSeverity::Low,
            ),
        ];
        for (status, expected_severity) in pairs {
            let computed = severity_for_status(status);
            assert_eq!(computed, expected_severity);
            assert_eq!(computed.as_str(), expected_severity.as_str());
        }
    }

    #[test]
    fn cli_docs_truth_guard_empty_contract_always_resolves() {
        let contract = DocsHelpSurfaceAuditContract {
            policy_id: "empty".to_string(),
            required_help_fragments: vec![],
            banned_help_fragments: vec![],
            required_readme_fragments: vec![],
            banned_readme_fragments: vec![],
        };
        let (status, _, _) = evaluate_cli_docs_truth_guard(&contract, "", "");
        assert_eq!(status, ZeroPlaceholderStatus::Resolved);
        let (status2, _, _) = evaluate_cli_docs_truth_guard(&contract, "anything", "anything else");
        assert_eq!(status2, ZeroPlaceholderStatus::Resolved);
    }

    #[test]
    fn cli_docs_truth_guard_multiple_required_all_present() {
        let contract = DocsHelpSurfaceAuditContract {
            policy_id: "multi".to_string(),
            required_help_fragments: vec!["alpha".to_string(), "beta".to_string()],
            banned_help_fragments: vec![],
            required_readme_fragments: vec!["gamma".to_string(), "delta".to_string()],
            banned_readme_fragments: vec![],
        };
        let readme = "gamma and delta are here";
        let help = "alpha and beta are here";
        let (status, severity, detail) = evaluate_cli_docs_truth_guard(&contract, readme, help);
        assert_eq!(status, ZeroPlaceholderStatus::Resolved);
        assert_eq!(severity, ZeroPlaceholderSeverity::Low);
        assert!(detail.contains("2 required README fragments"));
        assert!(detail.contains("2 required help fragments"));
    }

    #[test]
    fn cli_docs_truth_guard_partial_required_yields_failclosed() {
        let contract = DocsHelpSurfaceAuditContract {
            policy_id: "partial".to_string(),
            required_help_fragments: vec!["present".to_string(), "missing_frag".to_string()],
            banned_help_fragments: vec![],
            required_readme_fragments: vec![],
            banned_readme_fragments: vec![],
        };
        let (status, _, detail) = evaluate_cli_docs_truth_guard(&contract, "", "present here");
        assert_eq!(status, ZeroPlaceholderStatus::FailClosed);
        assert!(detail.contains("missing help fragment"));
        assert!(detail.contains("missing_frag"));
    }

    #[test]
    fn subsystem_summary_serde_round_trip() {
        let summary = ZeroPlaceholderSubsystemSummary {
            subsystem: ZeroPlaceholderSubsystem::Runtime,
            finding_count: 5,
            open_placeholder_finding_count: 2,
            fail_closed_finding_count: 1,
            resolved_finding_count: 2,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: ZeroPlaceholderSubsystemSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back, summary);
    }

    #[test]
    fn artifact_paths_serde_round_trip() {
        let paths = ZeroPlaceholderScanArtifactPaths {
            zero_placeholder_inventory: "inv.json".to_string(),
            trace_ids: "trace.json".to_string(),
            run_manifest: "manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        };
        let json = serde_json::to_string(&paths).unwrap();
        let back: ZeroPlaceholderScanArtifactPaths = serde_json::from_str(&json).unwrap();
        assert_eq!(back, paths);
    }

    #[test]
    fn trace_ids_serde_round_trip() {
        let trace_ids = ZeroPlaceholderScanTraceIds {
            schema_version: ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION.to_string(),
            component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
            trace_id: "trace-abc".to_string(),
            decision_id: "decision-abc".to_string(),
            policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
            inventory_hash: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&trace_ids).unwrap();
        let back: ZeroPlaceholderScanTraceIds = serde_json::from_str(&json).unwrap();
        assert_eq!(back, trace_ids);
    }

    #[test]
    fn run_manifest_serde_round_trip() {
        let manifest = ZeroPlaceholderScanRunManifest {
            schema_version: ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
            component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
            trace_id: "trace-m".to_string(),
            decision_id: "decision-m".to_string(),
            policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
            inventory_hash: "aabb".to_string(),
            finding_count: 3,
            open_placeholder_finding_count: 1,
            fail_closed_finding_count: 1,
            resolved_finding_count: 1,
            subsystem_summaries: vec![ZeroPlaceholderSubsystemSummary {
                subsystem: ZeroPlaceholderSubsystem::Parser,
                finding_count: 3,
                open_placeholder_finding_count: 1,
                fail_closed_finding_count: 1,
                resolved_finding_count: 1,
            }],
            artifact_paths: ZeroPlaceholderScanArtifactPaths {
                zero_placeholder_inventory: "i.json".to_string(),
                trace_ids: "t.json".to_string(),
                run_manifest: "m.json".to_string(),
                events_jsonl: "e.jsonl".to_string(),
                commands_txt: "c.txt".to_string(),
            },
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let back: ZeroPlaceholderScanRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, manifest);
    }

    #[test]
    fn inventory_serde_round_trip_full() {
        let inventory = ZeroPlaceholderInventory {
            schema_version: ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.to_string(),
            component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
            findings: vec![ZeroPlaceholderFinding {
                finding_id: "serde::a".to_string(),
                subsystem: ZeroPlaceholderSubsystem::Lowering,
                status: ZeroPlaceholderStatus::FailClosed,
                severity: ZeroPlaceholderSeverity::Medium,
                owner: "owner".to_string(),
                owner_bead_id: "bd-serde".to_string(),
                subject_area: "area".to_string(),
                source_reference: "ref".to_string(),
                observed_behavior: "obs".to_string(),
                required_behavior: "req".to_string(),
                diagnostic_code: Some("CODE".to_string()),
            }],
        };
        let json = serde_json::to_string(&inventory).unwrap();
        let back: ZeroPlaceholderInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inventory);
    }

    #[test]
    fn lowering_family_bead_ids_symmetric_with_parser() {
        // statement.for_in <=> for_in_statement map to same bead
        assert_eq!(
            bead_id_for_parser_feature("for_in_statement"),
            bead_id_for_lowering_family("statement.for_in")
        );
        assert_eq!(
            bead_id_for_parser_feature("for_of_statement"),
            bead_id_for_lowering_family("statement.for_of")
        );
        assert_eq!(
            bead_id_for_parser_feature("new_expression"),
            bead_id_for_lowering_family("expression.new")
        );
        assert_eq!(
            bead_id_for_parser_feature("template_literal"),
            bead_id_for_lowering_family("expression.template_literal")
        );
        assert_eq!(
            bead_id_for_parser_feature("binary_non_arithmetic_expression"),
            bead_id_for_lowering_family("expression.binary_non_arithmetic")
        );
        assert_eq!(
            bead_id_for_parser_feature("member_assignment_expression"),
            bead_id_for_lowering_family("expression.assignment_member_target")
        );
    }

    #[test]
    fn subsystem_deserialize_rejects_unknown_variant() {
        let result = serde_json::from_str::<ZeroPlaceholderSubsystem>("\"unknown_subsystem\"");
        assert!(result.is_err(), "unknown variant must fail deserialization");
    }

    #[test]
    fn status_deserialize_rejects_unknown_variant() {
        let result = serde_json::from_str::<ZeroPlaceholderStatus>("\"not_a_status\"");
        assert!(result.is_err(), "unknown status must fail deserialization");
    }

    #[test]
    fn severity_deserialize_rejects_unknown_variant() {
        let result = serde_json::from_str::<ZeroPlaceholderSeverity>("\"critical\"");
        assert!(
            result.is_err(),
            "unknown severity must fail deserialization"
        );
    }

    #[test]
    fn event_schema_version_propagated_in_build_events() {
        let inventory = ZeroPlaceholderInventory {
            schema_version: ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.to_string(),
            component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
            findings: vec![ZeroPlaceholderFinding {
                finding_id: "ev::schema".to_string(),
                subsystem: ZeroPlaceholderSubsystem::CliDocs,
                status: ZeroPlaceholderStatus::Resolved,
                severity: ZeroPlaceholderSeverity::Low,
                owner: "o".to_string(),
                owner_bead_id: "b".to_string(),
                subject_area: "s".to_string(),
                source_reference: "r".to_string(),
                observed_behavior: "obs".to_string(),
                required_behavior: "req".to_string(),
                diagnostic_code: None,
            }],
        };
        let events = build_inventory_events(&inventory, "t-schema", "d-schema");
        for event in &events {
            assert_eq!(
                event.schema_version,
                ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION
            );
            assert_eq!(event.policy_id, ZERO_PLACEHOLDER_SCAN_POLICY_ID);
            assert_eq!(event.component, ZERO_PLACEHOLDER_SCAN_COMPONENT);
            assert_eq!(event.trace_id, "t-schema");
            assert_eq!(event.decision_id, "d-schema");
        }
    }
}
