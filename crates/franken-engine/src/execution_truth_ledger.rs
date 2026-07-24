#![forbid(unsafe_code)]

//! Executable truth ledger for the performance/conformance bridge.
//!
//! The ledger deliberately separates three questions that older completion
//! records sometimes collapsed:
//!
//! 1. Does code or a tool execute?
//! 2. Is that code on the production execution path?
//! 3. Does observed evidence support the public claim posture?
//!
//! A type name, a backend enum, an input-only hash, or a synthetic duration can
//! therefore be preserved as useful planning evidence without being promoted
//! into runtime evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Component, Path};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use chrono::{DateTime, Utc};
#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
use rustix::fs::{CWD, RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

pub const LEDGER_SCHEMA_VERSION: &str = "franken-engine.execution-truth-ledger.v1";
pub const REPORT_SCHEMA_VERSION: &str =
    "franken-engine.execution-truth-ledger.validation-report.v1";
pub const EVENT_SCHEMA_VERSION: &str = "franken-engine.execution-truth-ledger.validation-event.v1";
pub const COMPONENT: &str = "execution_truth_ledger";
pub const OWNING_BEAD: &str = "bd-performance-conformance-bridge-tu32j.1.1";
pub const LEDGER_ID: &str = "franken-engine-performance-conformance-bridge-truth-v1";
pub const RENDERED_MARKDOWN_PATH: &str = "docs/EXECUTION_TRUTH_LEDGER_V1.md";

pub const ERROR_IO: &str = "FE-TRUTH-1001";
pub const ERROR_JSON: &str = "FE-TRUTH-1002";
pub const ERROR_SCHEMA: &str = "FE-TRUTH-1003";
pub const ERROR_SURFACE: &str = "FE-TRUTH-1004";
pub const ERROR_ORDER_OR_DUPLICATE: &str = "FE-TRUTH-1005";
pub const ERROR_OWNER: &str = "FE-TRUTH-1006";
pub const ERROR_CLASSIFICATION: &str = "FE-TRUTH-1007";
pub const ERROR_TRACKER_DRIFT: &str = "FE-TRUTH-1008";
pub const ERROR_CLAIM_DRIFT: &str = "FE-TRUTH-1009";
pub const ERROR_UNSAFE_PATH: &str = "FE-TRUTH-1010";
pub const ERROR_MISSING_PROOF: &str = "FE-TRUTH-1011";
pub const ERROR_SOURCE_RANGE: &str = "FE-TRUTH-1012";
pub const ERROR_CONTENT_DRIFT: &str = "FE-TRUTH-1013";
pub const ERROR_HASH_MISMATCH: &str = "FE-TRUTH-1014";
pub const ERROR_JSON_ASSERTION: &str = "FE-TRUTH-1015";
pub const ERROR_FORBIDDEN_TEXT: &str = "FE-TRUTH-1016";
pub const ERROR_GIT_TRACKING: &str = "FE-TRUTH-1017";
pub const ERROR_STALE: &str = "FE-TRUTH-1018";
pub const ERROR_MARKDOWN_DRIFT: &str = "FE-TRUTH-1019";
pub const ERROR_FINDING: &str = "FE-TRUTH-1020";
pub const ERROR_REPO_ROOT: &str = "FE-TRUTH-1022";
pub const ERROR_GIT_UNAVAILABLE: &str = "FE-TRUTH-1023";

/// The minimum governed surface required by BRIDGE-00.1. Additional rows may
/// be added, but omitting one of these rows is a hard verifier failure.
pub const REQUIRED_SUBJECT_IDS: &[&str] = &[
    "bead:bd-11p",
    "bead:bd-1lsy.7.10",
    "bead:bd-1lsy.7.3",
    "bead:bd-6a61n.1.8",
    "bead:bd-cixqu.7.17",
    "bead:bd-o4cbn",
    "bead:bd-w2dov",
    "claim:FE-CLAIM-001",
    "claim:FE-CLAIM-009",
    "claim:FE-CLAIM-010",
    "claim:FE-CLAIM-016",
    "claim:FE-CLAIM-017",
    "claim:FE-CLAIM-018",
    "claim:FE-CLAIM-019",
    "claim:FE-CLAIM-020",
    "claim:FE-CLAIM-021",
    "claim:FE-CLAIM-025",
    "claim:FE-CLAIM-026",
    "claim:FE-CLAIM-TEST262",
];

const REQUIRED_CLASSIFICATION_LABELS: &[&str] = &[
    "executable",
    "observed",
    "planning_provenance",
    "production_wired",
    "simulated",
    "synthetic_estimate",
    "test_only",
];
const MAX_PROOF_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVENT_REASON_BYTES: usize = 768;
static EVENT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTruthLedger {
    pub schema_version: String,
    pub ledger_id: String,
    pub owning_bead: String,
    pub source_cutoff_utc: String,
    pub max_age_days: u64,
    pub rendered_markdown_path: String,
    pub purpose: String,
    pub assumptions: Vec<String>,
    pub exclusions: Vec<String>,
    pub classification_definitions: BTreeMap<String, String>,
    pub subjects: Vec<TruthSubject>,
    pub findings: Vec<TruthFinding>,
    pub provenance_edges: Vec<ProvenanceEdge>,
    pub legal: LegalRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Bead,
    Claim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    Executable,
    Observed,
    PlanningProvenance,
    ProductionWired,
    Simulated,
    SyntheticEstimate,
    TestOnly,
}

impl EvidenceClass {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::Observed => "observed",
            Self::PlanningProvenance => "planning_provenance",
            Self::ProductionWired => "production_wired",
            Self::Simulated => "simulated",
            Self::SyntheticEstimate => "synthetic_estimate",
            Self::TestOnly => "test_only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimPosture {
    Hypothesis,
    NotApplicable,
    Observed,
    Target,
}

impl ClaimPosture {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Hypothesis => "hypothesis",
            Self::NotApplicable => "not_applicable",
            Self::Observed => "observed",
            Self::Target => "target",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TruthSubject {
    pub subject_id: String,
    pub kind: SubjectKind,
    pub title: String,
    pub current_state: String,
    pub claim_posture: ClaimPosture,
    pub classifications: Vec<EvidenceClass>,
    pub runtime_reality: String,
    pub user_impact: String,
    pub limitations: Vec<String>,
    pub downstream_decisions: Vec<String>,
    pub proofs: Vec<EvidenceProbe>,
    pub revalidation: RevalidationOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevalidationOwner {
    pub owner_id: String,
    pub role: String,
    pub trigger: String,
    pub command: String,
    pub fallback: String,
    pub kill_rule: String,
    pub rollback: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Artifact,
    ClaimMatrix,
    CiWiring,
    Manifest,
    Source,
    Tracker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProbe {
    pub proof_id: String,
    pub kind: ProbeKind,
    pub path: String,
    #[serde(default = "required_proof_by_default")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
    #[serde(default)]
    pub must_contain: Vec<String>,
    #[serde(default)]
    pub forbidden_text: Vec<String>,
    #[serde(default)]
    pub json_assertions: Vec<JsonAssertion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_git_tracked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    pub interpretation: String,
}

const fn required_proof_by_default() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonAssertion {
    pub pointer: String,
    pub expected: JsonValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TruthFinding {
    pub finding_id: String,
    pub severity: String,
    pub status: String,
    pub summary: String,
    pub opportunity_score: u8,
    pub relevance_score: u8,
    pub score_rationale: String,
    pub implementation_budget: String,
    pub subject_ids: Vec<String>,
    pub correction_owner: String,
    pub successor_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceEdge {
    pub from: String,
    pub relation: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalRecord {
    pub repository_license: String,
    pub external_corpora: Vec<ExternalCorpusRecord>,
    pub review_owner: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalCorpusRecord {
    pub name: String,
    pub source: String,
    pub revision: String,
    pub license: String,
    pub redistribution: String,
}

#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub run_id: String,
    pub trace_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub attempt: u32,
    pub as_of_utc: DateTime<Utc>,
}

impl ValidationContext {
    #[must_use]
    pub fn deterministic_for_tests(as_of_utc: DateTime<Utc>) -> Self {
        Self {
            run_id: "run-execution-truth-ledger-test".to_string(),
            trace_id: "trace-execution-truth-ledger-test".to_string(),
            scenario_id: "canonical-validation".to_string(),
            seed: 0,
            attempt: 1,
            as_of_utc,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFinding {
    pub error_code: String,
    pub phase: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub schema_version: String,
    pub ledger_path: String,
    pub ledger_sha256: String,
    pub source_cutoff_utc: String,
    pub as_of_utc: String,
    pub status: String,
    pub subject_count: usize,
    pub proof_count: usize,
    pub checks_run: usize,
    pub error_count: usize,
    pub findings: Vec<ValidationFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationEvent {
    pub schema_version: String,
    pub run_id: String,
    pub trace_id: String,
    pub test_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub attempt: u32,
    pub source_cutoff: String,
    pub platform: String,
    pub phase: String,
    pub sequence: u64,
    pub decision: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_id: Option<String>,
    pub duration_us: u64,
    pub artifact_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationOutput {
    pub report: ValidationReport,
    pub events: Vec<ValidationEvent>,
}

impl ValidationOutput {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.report.error_count == 0
    }
}

struct Validator<'a> {
    repo_root: &'a Path,
    ledger_path: &'a Path,
    context: &'a ValidationContext,
    source_cutoff: String,
    ledger_sha256: String,
    findings: Vec<ValidationFinding>,
    events: Vec<ValidationEvent>,
    checks_run: usize,
    proof_count: usize,
    subject_count: usize,
    sequence: u64,
}

impl<'a> Validator<'a> {
    fn new(repo_root: &'a Path, ledger_path: &'a Path, context: &'a ValidationContext) -> Self {
        Self {
            repo_root,
            ledger_path,
            context,
            source_cutoff: "unknown".to_string(),
            ledger_sha256: String::new(),
            findings: Vec::new(),
            events: Vec::new(),
            checks_run: 0,
            proof_count: 0,
            subject_count: 0,
            sequence: 0,
        }
    }

    fn check(
        &mut self,
        phase: &str,
        subject_id: Option<&str>,
        proof_id: Option<&str>,
        outcome: Result<String, (&'static str, String)>,
        started: Instant,
        artifact_hashes: BTreeMap<String, String>,
    ) {
        self.checks_run += 1;
        self.sequence += 1;
        let duration_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let (decision, reason, error_code) = match outcome {
            Ok(reason) => ("pass".to_string(), reason, None),
            Err((code, reason)) => {
                self.findings.push(ValidationFinding {
                    error_code: code.to_string(),
                    phase: phase.to_string(),
                    reason: bounded_redacted_reason(&reason, self.repo_root),
                    subject_id: subject_id.map(str::to_string),
                    proof_id: proof_id.map(str::to_string),
                });
                ("fail".to_string(), reason, Some(code.to_string()))
            }
        };
        self.events.push(ValidationEvent {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            run_id: self.context.run_id.clone(),
            trace_id: self.context.trace_id.clone(),
            test_id: proof_id.unwrap_or("ledger").to_string(),
            scenario_id: self.context.scenario_id.clone(),
            seed: self.context.seed,
            attempt: self.context.attempt,
            source_cutoff: self.source_cutoff.clone(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            phase: phase.to_string(),
            sequence: self.sequence,
            decision,
            reason: bounded_redacted_reason(&reason, self.repo_root),
            error_code,
            subject_id: subject_id.map(str::to_string),
            proof_id: proof_id.map(str::to_string),
            duration_us,
            artifact_hashes,
        });
    }

    fn finish(self) -> ValidationOutput {
        let error_count = self.findings.len();
        ValidationOutput {
            report: ValidationReport {
                schema_version: REPORT_SCHEMA_VERSION.to_string(),
                ledger_path: path_for_report(self.repo_root, self.ledger_path),
                ledger_sha256: self.ledger_sha256,
                source_cutoff_utc: self.source_cutoff,
                as_of_utc: self.context.as_of_utc.to_rfc3339(),
                status: if error_count == 0 { "pass" } else { "fail" }.to_string(),
                subject_count: self.subject_count,
                proof_count: self.proof_count,
                checks_run: self.checks_run,
                error_count,
                findings: self.findings,
            },
            events: self.events,
        }
    }
}

/// Load and validate the canonical ledger while always returning a structured
/// report, including for missing or malformed ledger input.
#[must_use]
pub fn validate_ledger_file(
    repo_root: &Path,
    ledger_path: &Path,
    context: &ValidationContext,
) -> ValidationOutput {
    let mut validator = Validator::new(repo_root, ledger_path, context);

    let root_started = Instant::now();
    match fs::canonicalize(repo_root) {
        Ok(root) if root.is_dir() => {
            validator.check(
                "preflight.repo_root",
                None,
                None,
                Ok("repository root resolved".to_string()),
                root_started,
                BTreeMap::new(),
            );
        }
        Ok(_) | Err(_) => {
            validator.check(
                "preflight.repo_root",
                None,
                None,
                Err((
                    ERROR_REPO_ROOT,
                    format!(
                        "repository root is missing or not a directory: {}",
                        repo_root.display()
                    ),
                )),
                root_started,
                BTreeMap::new(),
            );
            return validator.finish();
        }
    }

    let read_started = Instant::now();
    let bytes = match fs::read(ledger_path) {
        Ok(bytes) => {
            validator.ledger_sha256 = sha256_hex(&bytes);
            let mut hashes = BTreeMap::new();
            hashes.insert("ledger".to_string(), validator.ledger_sha256.clone());
            validator.check(
                "ledger.read",
                None,
                None,
                Ok("ledger bytes loaded".to_string()),
                read_started,
                hashes,
            );
            bytes
        }
        Err(error) => {
            validator.check(
                "ledger.read",
                None,
                None,
                Err((
                    ERROR_IO,
                    format!("failed to read {}: {error}", ledger_path.display()),
                )),
                read_started,
                BTreeMap::new(),
            );
            return validator.finish();
        }
    };

    let parse_started = Instant::now();
    let ledger: ExecutionTruthLedger = match serde_json::from_slice::<ExecutionTruthLedger>(&bytes)
    {
        Ok(ledger) => {
            validator.source_cutoff = ledger.source_cutoff_utc.clone();
            validator.check(
                "ledger.parse",
                None,
                None,
                Ok("ledger JSON parsed".to_string()),
                parse_started,
                BTreeMap::new(),
            );
            ledger
        }
        Err(error) => {
            validator.check(
                "ledger.parse",
                None,
                None,
                Err((ERROR_JSON, format!("ledger JSON is malformed: {error}"))),
                parse_started,
                BTreeMap::new(),
            );
            return validator.finish();
        }
    };

    validator.subject_count = ledger.subjects.len();
    validator.proof_count = ledger
        .subjects
        .iter()
        .map(|subject| subject.proofs.len())
        .sum();
    validate_structure(&ledger, &mut validator);
    validate_freshness(&ledger, &mut validator);
    validate_tracker_bindings(&ledger, &mut validator);
    validate_claim_bindings(&ledger, &mut validator);
    validate_proofs(&ledger, &mut validator);
    validate_rendered_markdown(&ledger, &mut validator);
    validator.finish()
}

fn validate_structure(ledger: &ExecutionTruthLedger, validator: &mut Validator<'_>) {
    let started = Instant::now();
    let outcome = if ledger.schema_version != LEDGER_SCHEMA_VERSION {
        Err((
            ERROR_SCHEMA,
            format!(
                "schema mismatch: expected {LEDGER_SCHEMA_VERSION}, got {}",
                ledger.schema_version
            ),
        ))
    } else if ledger.owning_bead != OWNING_BEAD {
        Err((
            ERROR_SCHEMA,
            format!(
                "owning bead mismatch: expected {OWNING_BEAD}, got {}",
                ledger.owning_bead
            ),
        ))
    } else if ledger.ledger_id != LEDGER_ID
        || ledger.rendered_markdown_path != RENDERED_MARKDOWN_PATH
        || ledger.legal.review_owner != OWNING_BEAD
    {
        Err((
            ERROR_SCHEMA,
            format!(
                "ledger identity, generated report path, and legal review owner must be {LEDGER_ID}, {RENDERED_MARKDOWN_PATH}, and {OWNING_BEAD}"
            ),
        ))
    } else if [
        ledger.ledger_id.as_str(),
        ledger.rendered_markdown_path.as_str(),
        ledger.purpose.as_str(),
        ledger.legal.repository_license.as_str(),
        ledger.legal.review_owner.as_str(),
    ]
    .iter()
    .any(|field| field.trim().is_empty())
        || ledger.assumptions.is_empty()
        || ledger.exclusions.is_empty()
        || ledger.findings.is_empty()
        || ledger.provenance_edges.is_empty()
        || ledger.legal.external_corpora.is_empty()
    {
        Err((
            ERROR_SCHEMA,
            "top-level identity, scope, findings, provenance, and legal fields must be non-empty"
                .to_string(),
        ))
    } else if ledger
        .assumptions
        .iter()
        .chain(&ledger.exclusions)
        .any(|entry| entry.trim().is_empty())
        || ledger.legal.external_corpora.iter().any(|corpus| {
            [
                corpus.name.as_str(),
                corpus.source.as_str(),
                corpus.revision.as_str(),
                corpus.license.as_str(),
                corpus.redistribution.as_str(),
            ]
            .iter()
            .any(|field| field.trim().is_empty())
        })
    {
        Err((
            ERROR_SCHEMA,
            "assumptions and exclusions cannot contain empty entries".to_string(),
        ))
    } else {
        let actual_classes: Vec<_> = ledger
            .classification_definitions
            .keys()
            .map(String::as_str)
            .collect();
        if actual_classes != REQUIRED_CLASSIFICATION_LABELS
            || ledger
                .classification_definitions
                .values()
                .any(|definition| definition.trim().is_empty())
        {
            Err((
                ERROR_SCHEMA,
                format!(
                    "classification vocabulary must define exactly: {}",
                    REQUIRED_CLASSIFICATION_LABELS.join(", ")
                ),
            ))
        } else {
            Ok("schema, scope, legal record, and owning bead match".to_string())
        }
    };
    validator.check(
        "structure.schema",
        None,
        None,
        outcome,
        started,
        BTreeMap::new(),
    );

    let started = Instant::now();
    let subject_ids: Vec<&str> = ledger
        .subjects
        .iter()
        .map(|subject| subject.subject_id.as_str())
        .collect();
    let unique: BTreeSet<&str> = subject_ids.iter().copied().collect();
    let mut sorted = subject_ids.clone();
    sorted.sort_unstable();
    let outcome = if unique.len() != subject_ids.len() {
        Err((
            ERROR_ORDER_OR_DUPLICATE,
            "duplicate subject_id in governed surface".to_string(),
        ))
    } else if sorted != subject_ids {
        Err((
            ERROR_ORDER_OR_DUPLICATE,
            "subjects must be ordered lexicographically by subject_id".to_string(),
        ))
    } else {
        let missing: Vec<_> = REQUIRED_SUBJECT_IDS
            .iter()
            .copied()
            .filter(|required| !unique.contains(required))
            .collect();
        if missing.is_empty() {
            Ok(format!(
                "all {} mandatory subjects are present",
                REQUIRED_SUBJECT_IDS.len()
            ))
        } else {
            Err((
                ERROR_SURFACE,
                format!(
                    "mandatory governed subjects missing: {}",
                    missing.join(", ")
                ),
            ))
        }
    };
    validator.check(
        "structure.governed_surface",
        None,
        None,
        outcome,
        started,
        BTreeMap::new(),
    );

    let known_subjects: BTreeSet<&str> = subject_ids.iter().copied().collect();
    let mut global_proof_ids = BTreeSet::new();
    for subject in &ledger.subjects {
        let started = Instant::now();
        let mut classification_labels: Vec<_> = subject
            .classifications
            .iter()
            .map(|class| class.stable_label())
            .collect();
        let original_labels = classification_labels.clone();
        classification_labels.sort_unstable();
        let class_unique: BTreeSet<_> = original_labels.iter().copied().collect();
        let posture_is_supported = match subject.claim_posture {
            ClaimPosture::Observed => subject.classifications.contains(&EvidenceClass::Observed),
            _ => true,
        };
        let production_is_executable = !subject
            .classifications
            .contains(&EvidenceClass::ProductionWired)
            || subject.classifications.contains(&EvidenceClass::Executable);
        let synthetic_is_simulated = !subject
            .classifications
            .contains(&EvidenceClass::SyntheticEstimate)
            || subject.classifications.contains(&EvidenceClass::Simulated);
        let identity_matches_kind = match subject.kind {
            SubjectKind::Bead => {
                subject.subject_id.starts_with("bead:")
                    && subject.claim_posture == ClaimPosture::NotApplicable
            }
            SubjectKind::Claim => {
                subject.subject_id.starts_with("claim:")
                    && subject.claim_posture != ClaimPosture::NotApplicable
            }
        };
        let outcome = if !identity_matches_kind
            || subject.title.trim().is_empty()
            || subject.current_state.trim().is_empty()
        {
            Err((
                ERROR_SURFACE,
                "subject kind, identifier prefix, posture, title, or current state is inconsistent"
                    .to_string(),
            ))
        } else if subject.classifications.is_empty() {
            Err((
                ERROR_CLASSIFICATION,
                "subject has no evidence classification".to_string(),
            ))
        } else if classification_labels != original_labels
            || class_unique.len() != original_labels.len()
        {
            Err((
                ERROR_CLASSIFICATION,
                "classifications must be unique and lexicographically ordered".to_string(),
            ))
        } else if !posture_is_supported {
            Err((
                ERROR_CLASSIFICATION,
                "observed claim posture requires observed evidence classification".to_string(),
            ))
        } else if !production_is_executable {
            Err((
                ERROR_CLASSIFICATION,
                "production_wired requires executable".to_string(),
            ))
        } else if !synthetic_is_simulated {
            Err((
                ERROR_CLASSIFICATION,
                "synthetic_estimate requires simulated".to_string(),
            ))
        } else if subject.runtime_reality.trim().is_empty()
            || subject.user_impact.trim().is_empty()
            || subject.limitations.is_empty()
            || subject.downstream_decisions.is_empty()
            || subject.proofs.is_empty()
            || subject
                .limitations
                .iter()
                .chain(&subject.downstream_decisions)
                .any(|entry| entry.trim().is_empty())
        {
            Err((
                ERROR_SURFACE,
                "subject must include reality, user impact, limitations, downstream decisions, and proof"
                    .to_string(),
            ))
        } else {
            Ok("subject classification contract is complete".to_string())
        };
        validator.check(
            "structure.subject",
            Some(&subject.subject_id),
            None,
            outcome,
            started,
            BTreeMap::new(),
        );

        let owner_started = Instant::now();
        let owner = &subject.revalidation;
        let cargo_without_rch =
            owner.command.contains("cargo ") && !owner.command.contains("rch exec --");
        let outcome = if [
            owner.owner_id.as_str(),
            owner.role.as_str(),
            owner.trigger.as_str(),
            owner.command.as_str(),
            owner.fallback.as_str(),
            owner.kill_rule.as_str(),
            owner.rollback.as_str(),
        ]
        .iter()
        .any(|field| field.trim().is_empty())
        {
            Err((
                ERROR_OWNER,
                "revalidation ownership and recovery fields must be non-empty".to_string(),
            ))
        } else if cargo_without_rch {
            Err((
                ERROR_OWNER,
                "Rust-heavy revalidation command contains cargo without rch exec --".to_string(),
            ))
        } else {
            Ok(format!("revalidation owner={}", owner.owner_id))
        };
        validator.check(
            "structure.owner",
            Some(&subject.subject_id),
            None,
            outcome,
            owner_started,
            BTreeMap::new(),
        );

        let proof_ids: Vec<&str> = subject
            .proofs
            .iter()
            .map(|probe| probe.proof_id.as_str())
            .collect();
        let mut sorted_proof_ids = proof_ids.clone();
        sorted_proof_ids.sort_unstable();
        let proof_started = Instant::now();
        let malformed_proof = subject.proofs.iter().find(|proof| {
            let has_content_binding = proof.file_sha256.is_some()
                || proof.range_sha256.is_some()
                || !proof.must_contain.is_empty()
                || !proof.forbidden_text.is_empty()
                || !proof.json_assertions.is_empty()
                || proof.expected_git_tracked.is_some();
            let line_pair_is_consistent = proof.start_line.is_some() == proof.end_line.is_some();
            let hashes_are_well_formed = proof
                .file_sha256
                .iter()
                .chain(proof.range_sha256.iter())
                .all(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
            proof.proof_id.trim().is_empty()
                || proof.path.trim().is_empty()
                || proof.interpretation.trim().is_empty()
                || proof
                    .caller
                    .as_ref()
                    .is_some_and(|caller| caller.trim().is_empty())
                || !has_content_binding
                || !line_pair_is_consistent
                || !hashes_are_well_formed
                || (!proof.required
                    && (proof.expected_git_tracked != Some(false)
                        || (proof.file_sha256.is_none() && proof.range_sha256.is_none())))
                || proof
                    .must_contain
                    .iter()
                    .chain(&proof.forbidden_text)
                    .any(|anchor| anchor.is_empty())
        });
        let outcome = if proof_ids != sorted_proof_ids {
            Err((
                ERROR_ORDER_OR_DUPLICATE,
                "proofs must be ordered lexicographically by proof_id".to_string(),
            ))
        } else if proof_ids
            .iter()
            .any(|proof_id| !global_proof_ids.insert(*proof_id))
        {
            Err((
                ERROR_ORDER_OR_DUPLICATE,
                "proof_id must be globally unique".to_string(),
            ))
        } else if let Some(proof) = malformed_proof {
            Err((
                ERROR_SURFACE,
                format!(
                    "proof {} has incomplete identity, caller, immutable binding, line pair, hash, or text anchor",
                    proof.proof_id
                ),
            ))
        } else {
            Ok("proof identifiers are unique and ordered".to_string())
        };
        validator.check(
            "structure.proof_ids",
            Some(&subject.subject_id),
            None,
            outcome,
            proof_started,
            BTreeMap::new(),
        );
    }

    let finding_id_order: Vec<&str> = ledger
        .findings
        .iter()
        .map(|finding| finding.finding_id.as_str())
        .collect();
    let mut sorted_finding_ids = finding_id_order.clone();
    sorted_finding_ids.sort_unstable();
    let mut finding_ids = BTreeSet::new();
    for finding in &ledger.findings {
        let started = Instant::now();
        let unknown_refs: Vec<_> = finding
            .subject_ids
            .iter()
            .filter(|subject_id| !known_subjects.contains(subject_id.as_str()))
            .cloned()
            .collect();
        let mut sorted_refs = finding.subject_ids.clone();
        sorted_refs.sort();
        sorted_refs.dedup();
        let outcome = if finding_id_order != sorted_finding_ids {
            Err((
                ERROR_ORDER_OR_DUPLICATE,
                "findings must be ordered lexicographically by finding_id".to_string(),
            ))
        } else if !finding_ids.insert(finding.finding_id.as_str()) {
            Err((ERROR_FINDING, "duplicate finding_id".to_string()))
        } else if finding.subject_ids.is_empty()
            || sorted_refs != finding.subject_ids
            || !unknown_refs.is_empty()
        {
            Err((
                ERROR_FINDING,
                format!(
                    "finding subject refs must be non-empty, unique, ordered, and known: {unknown_refs:?}"
                ),
            ))
        } else if [
            finding.severity.as_str(),
            finding.status.as_str(),
            finding.summary.as_str(),
            finding.score_rationale.as_str(),
            finding.implementation_budget.as_str(),
            finding.correction_owner.as_str(),
            finding.successor_bead.as_str(),
        ]
        .iter()
        .any(|field| field.trim().is_empty())
            || !matches!(finding.severity.as_str(), "critical" | "major" | "minor")
            || !matches!(
                finding.status.as_str(),
                "open" | "accepted" | "corrected" | "closed"
            )
            || finding.opportunity_score == 0
            || finding.opportunity_score > 100
            || finding.relevance_score == 0
            || finding.relevance_score > 100
            || !finding.successor_bead.starts_with("bd-")
        {
            Err((
                ERROR_FINDING,
                "finding governance fields must be non-empty and opportunity/relevance scores must be in 1..=100"
                    .to_string(),
            ))
        } else {
            Ok("finding is owned and references governed subjects".to_string())
        };
        validator.check(
            "structure.finding",
            None,
            Some(&finding.finding_id),
            outcome,
            started,
            BTreeMap::new(),
        );
    }

    let mut provenance_edges = BTreeSet::new();
    for edge in &ledger.provenance_edges {
        let started = Instant::now();
        let known_endpoint = |endpoint: &str| {
            known_subjects.contains(endpoint)
                || finding_ids.contains(endpoint)
                || endpoint == ledger.owning_bead
                || endpoint.starts_with("artifact:")
                || endpoint.starts_with("decision:")
        };
        let outcome = if edge.from.trim().is_empty()
            || edge.relation.trim().is_empty()
            || edge.to.trim().is_empty()
            || !known_endpoint(&edge.from)
            || !known_endpoint(&edge.to)
            || !provenance_edges.insert((&edge.from, &edge.relation, &edge.to))
        {
            Err((
                ERROR_FINDING,
                format!(
                    "provenance edge has an empty or unknown endpoint: {} --{}--> {}",
                    edge.from, edge.relation, edge.to
                ),
            ))
        } else {
            Ok("provenance edge endpoints are governed".to_string())
        };
        validator.check(
            "structure.provenance",
            None,
            None,
            outcome,
            started,
            BTreeMap::new(),
        );
    }
}

fn validate_freshness(ledger: &ExecutionTruthLedger, validator: &mut Validator<'_>) {
    let started = Instant::now();
    let outcome = DateTime::parse_from_rfc3339(&ledger.source_cutoff_utc)
        .map_err(|error| {
            (
                ERROR_STALE,
                format!("source_cutoff_utc is not RFC3339: {error}"),
            )
        })
        .and_then(|cutoff| {
            let cutoff = cutoff.with_timezone(&Utc);
            let age = validator.context.as_of_utc.signed_duration_since(cutoff);
            if age.num_seconds() < 0 {
                return Err((
                    ERROR_STALE,
                    format!(
                        "validation as_of {} precedes source cutoff {}",
                        validator.context.as_of_utc, cutoff
                    ),
                ));
            }
            let max_age_seconds = ledger
                .max_age_days
                .checked_mul(86_400)
                .and_then(|seconds| i64::try_from(seconds).ok())
                .ok_or_else(|| {
                    (
                        ERROR_STALE,
                        format!(
                            "max_age_days {} cannot be represented safely",
                            ledger.max_age_days
                        ),
                    )
                })?;
            if age.num_seconds() > max_age_seconds {
                Err((
                    ERROR_STALE,
                    format!(
                        "ledger is {} seconds old; maximum is {} seconds ({} days)",
                        age.num_seconds(),
                        max_age_seconds,
                        ledger.max_age_days
                    ),
                ))
            } else {
                Ok(format!(
                    "ledger age {} days is within {}-day policy",
                    age.num_days(),
                    ledger.max_age_days
                ))
            }
        });
    validator.check(
        "freshness.source_cutoff",
        None,
        None,
        outcome,
        started,
        BTreeMap::new(),
    );
}

fn validate_tracker_bindings(ledger: &ExecutionTruthLedger, validator: &mut Validator<'_>) {
    let tracker_path = validator.repo_root.join(".beads/issues.jsonl");
    let started = Instant::now();
    let records = match load_jsonl_records(&tracker_path, "id") {
        Ok(records) => {
            validator.check(
                "tracker.load",
                None,
                None,
                Ok(format!("loaded {} tracker records", records.len())),
                started,
                BTreeMap::new(),
            );
            records
        }
        Err(reason) => {
            validator.check(
                "tracker.load",
                None,
                None,
                Err((ERROR_TRACKER_DRIFT, reason)),
                started,
                BTreeMap::new(),
            );
            return;
        }
    };

    for subject in ledger
        .subjects
        .iter()
        .filter(|subject| subject.kind == SubjectKind::Bead)
    {
        let started = Instant::now();
        let id = subject.subject_id.trim_start_matches("bead:");
        let outcome = records.get(id).map_or_else(
            || {
                Err((
                    ERROR_TRACKER_DRIFT,
                    format!("tracker record missing for {id}"),
                ))
            },
            |record| {
                let actual_title = record
                    .get("title")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                let actual_status = record
                    .get("status")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                if actual_title != subject.title || actual_status != subject.current_state {
                    Err((
                        ERROR_TRACKER_DRIFT,
                        format!(
                            "{id} drift: title/status expected {:?}/{:?}, got {:?}/{:?}",
                            subject.title, subject.current_state, actual_title, actual_status
                        ),
                    ))
                } else {
                    Ok(format!("{id} tracker state remains {actual_status}"))
                }
            },
        );
        validator.check(
            "tracker.binding",
            Some(&subject.subject_id),
            None,
            outcome,
            started,
            BTreeMap::new(),
        );
    }

    for subject in &ledger.subjects {
        let started = Instant::now();
        let owner_id = &subject.revalidation.owner_id;
        let outcome = records.get(owner_id).map_or_else(
            || {
                Err((
                    ERROR_OWNER,
                    format!(
                        "{} revalidation owner bead is absent from the live tracker: {owner_id}",
                        subject.subject_id
                    ),
                ))
            },
            |record| {
                let status = record
                    .get("status")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                if matches!(status, "open" | "in_progress" | "blocked" | "deferred") {
                    Ok(format!(
                        "{} revalidation owner is live with status {status}",
                        subject.subject_id
                    ))
                } else {
                    Err((
                        ERROR_OWNER,
                        format!(
                            "{} revalidation owner {owner_id} is not live: status={status:?}",
                            subject.subject_id
                        ),
                    ))
                }
            },
        );
        validator.check(
            "tracker.revalidation_owner",
            Some(&subject.subject_id),
            None,
            outcome,
            started,
            BTreeMap::new(),
        );
    }

    for finding in &ledger.findings {
        let started = Instant::now();
        let outcome = records.get(&finding.successor_bead).map_or_else(
            || {
                Err((
                    ERROR_OWNER,
                    format!(
                        "{} successor bead is absent from the live tracker: {}",
                        finding.finding_id, finding.successor_bead
                    ),
                ))
            },
            |record| {
                let status = record
                    .get("status")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                if finding.status == "open"
                    && !matches!(status, "open" | "in_progress" | "blocked" | "deferred")
                {
                    Err((
                        ERROR_OWNER,
                        format!(
                            "{} is open but successor {} is not live: status={status:?}",
                            finding.finding_id, finding.successor_bead
                        ),
                    ))
                } else {
                    Ok(format!(
                        "{} successor {} has status {status}",
                        finding.finding_id, finding.successor_bead
                    ))
                }
            },
        );
        validator.check(
            "tracker.finding_successor",
            None,
            Some(&finding.finding_id),
            outcome,
            started,
            BTreeMap::new(),
        );
    }
}

fn validate_claim_bindings(ledger: &ExecutionTruthLedger, validator: &mut Validator<'_>) {
    let matrix_path = validator
        .repo_root
        .join("docs/claim_to_proof_matrix_v1.json");
    let started = Instant::now();
    let matrix_bytes = match fs::read(&matrix_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            validator.check(
                "claim_matrix.load",
                None,
                None,
                Err((
                    ERROR_CLAIM_DRIFT,
                    format!("failed to read {}: {error}", matrix_path.display()),
                )),
                started,
                BTreeMap::new(),
            );
            return;
        }
    };
    let matrix: JsonValue = match serde_json::from_slice::<JsonValue>(&matrix_bytes) {
        Ok(matrix) => matrix,
        Err(error) => {
            validator.check(
                "claim_matrix.load",
                None,
                None,
                Err((
                    ERROR_CLAIM_DRIFT,
                    format!("claim matrix JSON malformed: {error}"),
                )),
                started,
                BTreeMap::new(),
            );
            return;
        }
    };
    let rows = matrix
        .get("claims")
        .and_then(JsonValue::as_array)
        .cloned()
        .unwrap_or_default();
    validator.check(
        "claim_matrix.load",
        None,
        None,
        if rows.is_empty() {
            Err((
                ERROR_CLAIM_DRIFT,
                "claim matrix has no claims array".to_string(),
            ))
        } else {
            Ok(format!("loaded {} claim rows", rows.len()))
        },
        started,
        BTreeMap::from([("claim_matrix".to_string(), sha256_hex(&matrix_bytes))]),
    );

    let mut by_id = BTreeMap::new();
    let mut duplicate_claim_ids = BTreeSet::new();
    for row in &rows {
        if let Some(id) = row.get("claim_id").and_then(JsonValue::as_str)
            && by_id.insert(id, row).is_some()
        {
            duplicate_claim_ids.insert(id);
        }
    }
    if !duplicate_claim_ids.is_empty() {
        validator.check(
            "claim_matrix.unique_ids",
            None,
            None,
            Err((
                ERROR_CLAIM_DRIFT,
                format!(
                    "claim matrix contains duplicate claim IDs: {}",
                    duplicate_claim_ids
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
            Instant::now(),
            BTreeMap::new(),
        );
    } else {
        validator.check(
            "claim_matrix.unique_ids",
            None,
            None,
            Ok("claim matrix claim IDs are unique".to_string()),
            Instant::now(),
            BTreeMap::new(),
        );
    }
    for subject in ledger
        .subjects
        .iter()
        .filter(|subject| subject.kind == SubjectKind::Claim)
    {
        let started = Instant::now();
        let id = subject.subject_id.trim_start_matches("claim:");
        let outcome = by_id.get(id).map_or_else(
            || Err((ERROR_CLAIM_DRIFT, format!("claim row missing for {id}"))),
            |row| {
                let title = row
                    .get("claim_text")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                let state = row
                    .get("allowed_state")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                if title != subject.title
                    || state != subject.current_state
                    || state != subject.claim_posture.stable_label()
                {
                    Err((
                        ERROR_CLAIM_DRIFT,
                        format!(
                            "{id} drift: expected title/state/posture {:?}/{:?}/{:?}, got {:?}/{:?}",
                            subject.title,
                            subject.current_state,
                            subject.claim_posture.stable_label(),
                            title,
                            state
                        ),
                    ))
                } else {
                    Ok(format!("{id} remains in {state} posture"))
                }
            },
        );
        validator.check(
            "claim_matrix.binding",
            Some(&subject.subject_id),
            None,
            outcome,
            started,
            BTreeMap::new(),
        );
    }
}

fn validate_proofs(ledger: &ExecutionTruthLedger, validator: &mut Validator<'_>) {
    for subject in &ledger.subjects {
        for proof in &subject.proofs {
            validate_probe(subject, proof, validator);
        }
    }
}

fn validate_probe(subject: &TruthSubject, proof: &EvidenceProbe, validator: &mut Validator<'_>) {
    let path_started = Instant::now();
    let relative = Path::new(&proof.path);
    if !safe_relative_path(relative) {
        validator.check(
            "proof.path",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            Err((
                ERROR_UNSAFE_PATH,
                format!("proof path must be repository-relative: {}", proof.path),
            )),
            path_started,
            BTreeMap::new(),
        );
        return;
    }
    let full_path = validator.repo_root.join(relative);
    let metadata = match fs::symlink_metadata(&full_path) {
        Ok(metadata) => metadata,
        Err(_) if !proof.required => {
            validator.check(
                "proof.optional_absence",
                Some(&subject.subject_id),
                Some(&proof.proof_id),
                Ok(format!(
                    "explicit local_optional proof is absent; retained hash was not revalidated: {}",
                    proof.path
                )),
                path_started,
                BTreeMap::new(),
            );
            return;
        }
        Err(_) => {
            validator.check(
                "proof.path",
                Some(&subject.subject_id),
                Some(&proof.proof_id),
                Err((
                    ERROR_MISSING_PROOF,
                    format!("proof file missing or not regular: {}", proof.path),
                )),
                path_started,
                BTreeMap::new(),
            );
            return;
        }
    };
    if metadata.file_type().is_symlink() {
        validator.check(
            "proof.path",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            Err((
                ERROR_UNSAFE_PATH,
                format!("proof path cannot be a symlink: {}", proof.path),
            )),
            path_started,
            BTreeMap::new(),
        );
        return;
    }
    if !metadata.is_file() {
        validator.check(
            "proof.path",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            Err((
                ERROR_MISSING_PROOF,
                format!("proof path is not a regular file: {}", proof.path),
            )),
            path_started,
            BTreeMap::new(),
        );
        return;
    }
    if metadata.len() > MAX_PROOF_FILE_BYTES {
        validator.check(
            "proof.path",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            Err((
                ERROR_MISSING_PROOF,
                format!(
                    "proof file exceeds {} byte validation bound: {}",
                    MAX_PROOF_FILE_BYTES, proof.path
                ),
            )),
            path_started,
            BTreeMap::new(),
        );
        return;
    }
    let path_is_contained = match (
        fs::canonicalize(validator.repo_root),
        fs::canonicalize(&full_path),
    ) {
        (Ok(root), Ok(proof_path)) => proof_path.starts_with(root),
        _ => false,
    };
    if !path_is_contained {
        validator.check(
            "proof.path",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            Err((
                ERROR_UNSAFE_PATH,
                format!("proof path resolves outside the repository: {}", proof.path),
            )),
            path_started,
            BTreeMap::new(),
        );
        return;
    }
    validator.check(
        "proof.path",
        Some(&subject.subject_id),
        Some(&proof.proof_id),
        Ok(format!("proof file present: {}", proof.path)),
        path_started,
        BTreeMap::new(),
    );

    let bytes = match fs::read(&full_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            validator.check(
                "proof.read",
                Some(&subject.subject_id),
                Some(&proof.proof_id),
                Err((ERROR_IO, format!("failed to read {}: {error}", proof.path))),
                Instant::now(),
                BTreeMap::new(),
            );
            return;
        }
    };
    let actual_file_hash = sha256_hex(&bytes);
    let mut hashes = BTreeMap::from([("proof_file".to_string(), actual_file_hash.clone())]);

    if let Some(expected) = proof.file_sha256.as_deref() {
        let started = Instant::now();
        let outcome = if actual_file_hash == expected {
            Ok("whole-file sha256 matches".to_string())
        } else {
            Err((
                ERROR_HASH_MISMATCH,
                format!(
                    "{} sha256 mismatch: expected {expected}, got {actual_file_hash}",
                    proof.path
                ),
            ))
        };
        validator.check(
            "proof.file_hash",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            outcome,
            started,
            hashes.clone(),
        );
    }

    let needs_text = proof.start_line.is_some()
        || proof.end_line.is_some()
        || !proof.must_contain.is_empty()
        || !proof.forbidden_text.is_empty()
        || !proof.json_assertions.is_empty();
    let text = if needs_text {
        match std::str::from_utf8(&bytes) {
            Ok(text) => Some(text),
            Err(error) => {
                validator.check(
                    "proof.text",
                    Some(&subject.subject_id),
                    Some(&proof.proof_id),
                    Err((
                        ERROR_CONTENT_DRIFT,
                        format!("{} is not UTF-8: {error}", proof.path),
                    )),
                    Instant::now(),
                    hashes.clone(),
                );
                None
            }
        }
    } else {
        None
    };

    if proof.start_line.is_some() || proof.end_line.is_some() {
        let started = Instant::now();
        let outcome = match (proof.start_line, proof.end_line, text) {
            (Some(start), Some(end), Some(text)) if start > 0 && end >= start => {
                match normalized_line_range(text, start, end) {
                    Some(range) => {
                        let actual = sha256_hex(range.as_bytes());
                        hashes.insert("source_range".to_string(), actual.clone());
                        match proof.range_sha256.as_deref() {
                            Some(expected) if expected == actual => {
                                Ok(format!("source range {start}-{end} sha256 matches"))
                            }
                            Some(expected) => Err((
                                ERROR_HASH_MISMATCH,
                                format!(
                                    "{}:{start}-{end} sha256 mismatch: expected {expected}, got {actual}",
                                    proof.path
                                ),
                            )),
                            None => Err((
                                ERROR_SOURCE_RANGE,
                                "source range requires range_sha256".to_string(),
                            )),
                        }
                    }
                    None => Err((
                        ERROR_SOURCE_RANGE,
                        format!("{} has no complete line range {start}-{end}", proof.path),
                    )),
                }
            }
            _ => Err((
                ERROR_SOURCE_RANGE,
                "start_line and end_line must both be present and form a valid range".to_string(),
            )),
        };
        validator.check(
            "proof.source_range",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            outcome,
            started,
            hashes.clone(),
        );
    }

    if !proof.must_contain.is_empty() {
        let started = Instant::now();
        let haystack = match (proof.start_line, proof.end_line, text) {
            (Some(start), Some(end), Some(text)) => normalized_line_range(text, start, end),
            (_, _, Some(text)) => Some(text.to_string()),
            _ => None,
        };
        let outcome = haystack.map_or_else(
            || {
                Err((
                    ERROR_CONTENT_DRIFT,
                    "cannot evaluate must_contain without UTF-8 text".to_string(),
                ))
            },
            |haystack| {
                let missing: Vec<_> = proof
                    .must_contain
                    .iter()
                    .filter(|needle| !haystack.contains(needle.as_str()))
                    .cloned()
                    .collect();
                if missing.is_empty() {
                    Ok(format!(
                        "all {} required text anchors present",
                        proof.must_contain.len()
                    ))
                } else {
                    Err((
                        ERROR_CONTENT_DRIFT,
                        format!("required anchors missing: {missing:?}"),
                    ))
                }
            },
        );
        validator.check(
            "proof.required_text",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            outcome,
            started,
            hashes.clone(),
        );
    }

    if !proof.forbidden_text.is_empty() {
        let started = Instant::now();
        let outcome = text.map_or_else(
            || {
                Err((
                    ERROR_FORBIDDEN_TEXT,
                    "cannot evaluate forbidden_text without UTF-8 text".to_string(),
                ))
            },
            |text| {
                let present: Vec<_> = proof
                    .forbidden_text
                    .iter()
                    .filter(|needle| text.contains(needle.as_str()))
                    .cloned()
                    .collect();
                if present.is_empty() {
                    Ok(format!(
                        "all {} forbidden tokens absent",
                        proof.forbidden_text.len()
                    ))
                } else {
                    Err((
                        ERROR_FORBIDDEN_TEXT,
                        format!("forbidden implementation tokens present: {present:?}"),
                    ))
                }
            },
        );
        validator.check(
            "proof.forbidden_text",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            outcome,
            started,
            hashes.clone(),
        );
    }

    if !proof.json_assertions.is_empty() {
        let started = Instant::now();
        let outcome = serde_json::from_slice::<JsonValue>(&bytes)
            .map_err(|error| {
                (
                    ERROR_JSON_ASSERTION,
                    format!("{} is not valid JSON: {error}", proof.path),
                )
            })
            .and_then(|json| {
                let mismatches: Vec<_> = proof
                    .json_assertions
                    .iter()
                    .filter_map(|assertion| {
                        let actual = json.pointer(&assertion.pointer);
                        (actual != Some(&assertion.expected)).then(|| {
                            format!(
                                "{} expected {}, got {}",
                                assertion.pointer,
                                assertion.expected,
                                actual
                                    .map(JsonValue::to_string)
                                    .unwrap_or_else(|| "<missing>".to_string())
                            )
                        })
                    })
                    .collect();
                if mismatches.is_empty() {
                    Ok(format!(
                        "all {} JSON assertions match",
                        proof.json_assertions.len()
                    ))
                } else {
                    Err((
                        ERROR_JSON_ASSERTION,
                        format!("JSON assertion drift: {}", mismatches.join("; ")),
                    ))
                }
            });
        validator.check(
            "proof.json_assertions",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            outcome,
            started,
            hashes.clone(),
        );
    }

    if let Some(expected) = proof.expected_git_tracked {
        let started = Instant::now();
        let outcome = git_tracking_state(validator.repo_root, &proof.path).and_then(|actual| {
            if actual == expected {
                Ok(format!("git_tracked={actual} matches ledger"))
            } else {
                Err((
                    ERROR_GIT_TRACKING,
                    format!(
                        "{} tracking drift: expected {expected}, got {actual}",
                        proof.path
                    ),
                ))
            }
        });
        validator.check(
            "proof.git_tracking",
            Some(&subject.subject_id),
            Some(&proof.proof_id),
            outcome,
            started,
            std::mem::take(&mut hashes),
        );
    }
}

fn validate_rendered_markdown(ledger: &ExecutionTruthLedger, validator: &mut Validator<'_>) {
    let started = Instant::now();
    let path = Path::new(&ledger.rendered_markdown_path);
    if !safe_relative_path(path) {
        validator.check(
            "markdown.drift",
            None,
            None,
            Err((
                ERROR_UNSAFE_PATH,
                "rendered_markdown_path must be repository-relative".to_string(),
            )),
            started,
            BTreeMap::new(),
        );
        return;
    }
    let expected = render_markdown(ledger);
    let full_path = validator.repo_root.join(path);
    let outcome = match fs::read_to_string(&full_path) {
        Ok(actual) if actual == expected => Ok("generated Markdown matches ledger".to_string()),
        Ok(_) => Err((
            ERROR_MARKDOWN_DRIFT,
            format!(
                "{} does not match deterministic renderer output",
                ledger.rendered_markdown_path
            ),
        )),
        Err(error) => Err((
            ERROR_MARKDOWN_DRIFT,
            format!(
                "failed to read rendered Markdown {}: {error}",
                ledger.rendered_markdown_path
            ),
        )),
    };
    validator.check(
        "markdown.drift",
        None,
        None,
        outcome,
        started,
        BTreeMap::from([(
            "rendered_markdown".to_string(),
            sha256_hex(expected.as_bytes()),
        )]),
    );
}

#[must_use]
pub fn render_markdown(ledger: &ExecutionTruthLedger) -> String {
    let mut out = String::new();
    out.push_str("# Execution-vs-Scaffold Truth Ledger v1\n\n");
    out.push_str(&format!(
        "> Generated deterministically from `docs/execution_truth_ledger_v1.json`. Do not edit this file by hand. Source cutoff: `{}`. Owning bead: `{}`.\n\n",
        ledger.source_cutoff_utc, ledger.owning_bead
    ));
    out.push_str("## Purpose\n\n");
    out.push_str(&ledger.purpose);
    out.push_str("\n\n");
    out.push_str("The evidence classes are facets, not a maturity ladder. A surface can be executable and simulated, or observed and test-only, without being production-wired.\n\n");
    out.push_str("## Classification vocabulary\n\n");
    out.push_str("| Class | Meaning |\n|---|---|\n");
    for (class, definition) in &ledger.classification_definitions {
        out.push_str(&format!(
            "| `{}` | {} |\n",
            markdown_cell(class),
            markdown_cell(definition)
        ));
    }
    out.push_str("\n## Governed surface\n\n");
    out.push_str(
        "| Subject | State/posture | Evidence facets | Current reality | Revalidation owner |\n",
    );
    out.push_str("|---|---|---|---|---|\n");
    for subject in &ledger.subjects {
        let classes = subject
            .classifications
            .iter()
            .map(|class| format!("`{}`", class.stable_label()))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "| `{}` | `{}` / `{}` | {} | {} | `{}` |\n",
            markdown_cell(&subject.subject_id),
            markdown_cell(&subject.current_state),
            subject.claim_posture.stable_label(),
            classes,
            markdown_cell(&subject.runtime_reality),
            markdown_cell(&subject.revalidation.owner_id)
        ));
    }
    out.push_str("\n## Detailed crosswalk\n\n");
    for subject in &ledger.subjects {
        out.push_str(&format!(
            "### `{}` — {}\n\n",
            subject.subject_id, subject.title
        ));
        out.push_str(&format!(
            "- Current state: `{}`; claim posture: `{}`.\n",
            subject.current_state,
            subject.claim_posture.stable_label()
        ));
        out.push_str(&format!(
            "- Runtime reality: {}.\n",
            subject.runtime_reality
        ));
        out.push_str(&format!("- User impact: {}.\n", subject.user_impact));
        out.push_str(&format!(
            "- Revalidation: owner `{}` ({}) runs `{}` when {}.\n",
            subject.revalidation.owner_id,
            subject.revalidation.role,
            subject.revalidation.command,
            subject.revalidation.trigger
        ));
        out.push_str(&format!(
            "- Fallback / kill / rollback: {} / {} / {}.\n",
            subject.revalidation.fallback,
            subject.revalidation.kill_rule,
            subject.revalidation.rollback
        ));
        out.push_str("- Limitations:\n");
        for limitation in &subject.limitations {
            out.push_str(&format!("  - {}\n", limitation));
        }
        out.push_str("- Downstream decisions:\n");
        for decision in &subject.downstream_decisions {
            out.push_str(&format!("  - {}\n", decision));
        }
        out.push_str("\n| Proof | Availability | Location | Caller | Interpretation |\n");
        out.push_str("|---|---|---|---|---|\n");
        for proof in &subject.proofs {
            let location = match (proof.start_line, proof.end_line) {
                (Some(start), Some(end)) => format!("{}:{}-{}", proof.path, start, end),
                _ => proof.path.clone(),
            };
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | {} | {} |\n",
                markdown_cell(&proof.proof_id),
                if proof.required {
                    "required"
                } else {
                    "local_optional"
                },
                markdown_cell(&location),
                markdown_cell(proof.caller.as_deref().unwrap_or("n/a")),
                markdown_cell(&proof.interpretation)
            ));
        }
        out.push('\n');
    }
    out.push_str("## Open truth findings\n\n");
    out.push_str(
        "| Finding | Severity | Status | Opportunity / relevance | Budget | Subjects | Correction owner | Summary and scoring rationale |\n",
    );
    out.push_str("|---|---|---|---|---|---|---|---|\n");
    for finding in &ledger.findings {
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` / `{}` | {} | {} | `{}` via `{}` | {} Score rationale: {} |\n",
            markdown_cell(&finding.finding_id),
            markdown_cell(&finding.severity),
            markdown_cell(&finding.status),
            finding.opportunity_score,
            finding.relevance_score,
            markdown_cell(&finding.implementation_budget),
            finding
                .subject_ids
                .iter()
                .map(|id| format!("`{}`", markdown_cell(id)))
                .collect::<Vec<_>>()
                .join(", "),
            markdown_cell(&finding.correction_owner),
            markdown_cell(&finding.successor_bead),
            markdown_cell(&finding.summary),
            markdown_cell(&finding.score_rationale)
        ));
    }
    out.push_str("\n## Scope boundaries\n\n");
    out.push_str("Assumptions:\n\n");
    for assumption in &ledger.assumptions {
        out.push_str(&format!("- {}\n", assumption));
    }
    out.push_str("\nExclusions:\n\n");
    for exclusion in &ledger.exclusions {
        out.push_str(&format!("- {}\n", exclusion));
    }
    out.push_str("\n## Legal and provenance\n\n");
    out.push_str(&format!(
        "Repository license: `{}`. Review owner: `{}`.\n\n",
        ledger.legal.repository_license, ledger.legal.review_owner
    ));
    for corpus in &ledger.legal.external_corpora {
        out.push_str(&format!(
            "- `{}` at `{}`: source {}, license `{}`, redistribution {}.\n",
            corpus.name,
            corpus.revision,
            corpus.source,
            corpus.license,
            corpus.redistribution.trim_end_matches('.')
        ));
    }
    out.push_str("\nProvenance edges:\n\n");
    for edge in &ledger.provenance_edges {
        out.push_str(&format!(
            "- `{}` --`{}`--> `{}`\n",
            edge.from, edge.relation, edge.to
        ));
    }
    out
}

pub fn write_events_jsonl(path: &Path, events: &[ValidationEvent]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    let mut output = String::new();
    for event in events {
        let line = serde_json::to_string(event)
            .map_err(|error| format!("failed to serialize event: {error}"))?;
        if line.len() > 8 * 1024 {
            return Err("serialized event exceeds 8 KiB bound".to_string());
        }
        output.push_str(&line);
        output.push('\n');
    }
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing event artifact {}",
            path.display()
        ));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("event artifact has no UTF-8 file name: {}", path.display()))?;
    let partial_sequence = EVENT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let partial_path = path.with_file_name(format!(
        "{file_name}.partial-{}-{partial_sequence}",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial_path)
        .map_err(|error| {
            format!(
                "failed to create recoverable event prefix {}: {error}",
                partial_path.display()
            )
        })?;
    file.write_all(output.as_bytes()).map_err(|error| {
        format!(
            "failed to write recoverable event prefix {}: {error}",
            partial_path.display()
        )
    })?;
    file.sync_all().map_err(|error| {
        format!(
            "failed to sync recoverable event prefix {}: {error}",
            partial_path.display()
        )
    })?;
    publish_without_replacement(&partial_path, path).map_err(|error| {
        format!(
            "failed to publish event artifact {} without replacement; recoverable prefix {} retained: {error}",
            path.display(),
            partial_path.display()
        )
    })
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
fn publish_without_replacement(partial_path: &Path, path: &Path) -> io::Result<()> {
    Ok(renameat_with(
        CWD,
        partial_path,
        CWD,
        path,
        RenameFlags::NOREPLACE,
    )?)
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "redox")))]
fn publish_without_replacement(partial_path: &Path, path: &Path) -> io::Result<()> {
    fs::hard_link(partial_path, path)?;
    fs::remove_file(partial_path)
}

fn load_jsonl_records(path: &Path, id_field: &str) -> Result<BTreeMap<String, JsonValue>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let mut records = BTreeMap::new();
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: JsonValue = serde_json::from_str(line).map_err(|error| {
            format!(
                "{} line {} is invalid JSON: {error}",
                path.display(),
                index + 1
            )
        })?;
        let id = record
            .get(id_field)
            .and_then(JsonValue::as_str)
            .ok_or_else(|| {
                format!(
                    "{} line {} missing string field {id_field}",
                    path.display(),
                    index + 1
                )
            })?
            .to_string();
        if records.insert(id.clone(), record).is_some() {
            return Err(format!(
                "{} line {} duplicates {id_field}={id:?}",
                path.display(),
                index + 1
            ));
        }
    }
    Ok(records)
}

fn normalized_line_range(text: &str, start: usize, end: usize) -> Option<String> {
    if start == 0 || end < start {
        return None;
    }
    let lines: Vec<&str> = text.lines().collect();
    if end > lines.len() {
        return None;
    }
    let mut range = lines[start - 1..end].join("\n");
    range.push('\n');
    Some(range)
}

fn git_tracking_state(
    repo_root: &Path,
    relative_path: &str,
) -> Result<bool, (&'static str, String)> {
    let inside = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .map_err(|error| {
            (
                ERROR_GIT_UNAVAILABLE,
                format!("cannot execute git for tracking proof: {error}"),
            )
        })?;
    if !inside.status.success() || String::from_utf8_lossy(&inside.stdout).trim() != "true" {
        return Err((
            ERROR_GIT_UNAVAILABLE,
            "repository tracking state cannot be verified".to_string(),
        ));
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["ls-files", "--full-name", "--", relative_path])
        .output()
        .map_err(|error| {
            (
                ERROR_GIT_UNAVAILABLE,
                format!("cannot execute git ls-files: {error}"),
            )
        })?;
    if !output.status.success() {
        return Err((
            ERROR_GIT_UNAVAILABLE,
            format!(
                "git ls-files failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|path| path == relative_path))
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn path_for_report(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn bounded_redacted_reason(reason: &str, repo_root: &Path) -> String {
    let root = repo_root.to_string_lossy();
    let mut redacted = reason.replace(root.as_ref(), "<repo>");
    for marker in [
        "API_KEY=",
        "api_key=",
        "ACCESS_TOKEN=",
        "access_token=",
        "TOKEN=",
        "token=",
        "SECRET=",
        "secret=",
        "PASSWORD=",
        "password=",
        "CREDENTIAL=",
        "credential=",
        "BEARER=",
        "bearer=",
        "Bearer ",
        "bearer ",
    ] {
        let mut search_from = 0;
        while let Some(relative_offset) = redacted[search_from..].find(marker) {
            let offset = search_from + relative_offset;
            let value_start = offset + marker.len();
            let value_end = redacted[value_start..]
                .find(char::is_whitespace)
                .map(|relative| value_start + relative)
                .unwrap_or(redacted.len());
            redacted.replace_range(value_start..value_end, "<redacted>");
            search_from = value_start + "<redacted>".len();
        }
    }
    if redacted.len() > MAX_EVENT_REASON_BYTES {
        let mut boundary = MAX_EVENT_REASON_BYTES;
        while !redacted.is_char_boundary(boundary) {
            boundary -= 1;
        }
        redacted.truncate(boundary);
        redacted.push('…');
    }
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn normalized_range_has_stable_terminal_newline() {
        assert_eq!(
            normalized_line_range("zero\none\ntwo\n", 2, 3).as_deref(),
            Some("one\ntwo\n")
        );
        assert!(normalized_line_range("one\n", 0, 1).is_none());
        assert!(normalized_line_range("one\n", 1, 2).is_none());
    }

    #[test]
    fn redaction_is_bounded_and_removes_repo_and_secret_values() {
        let reason = format!(
            "/workspace/private TOKEN=first tail TOKEN={} API_KEY=third token=fourth Bearer fifth",
            "x".repeat(MAX_EVENT_REASON_BYTES * 2),
        );
        let redacted = bounded_redacted_reason(&reason, Path::new("/workspace/private"));
        assert!(!redacted.contains("/workspace/private"));
        assert!(!redacted.contains("TOKEN=first"));
        assert!(!redacted.contains("TOKEN=xxx"));
        assert!(!redacted.contains("API_KEY=third"));
        assert!(!redacted.contains("token=fourth"));
        assert!(!redacted.contains("Bearer fifth"));
        assert!(redacted.contains("TOKEN=<redacted>"));
        assert!(redacted.contains("token=<redacted>"));
        assert!(redacted.contains("Bearer <redacted>"));
        assert!(redacted.len() <= MAX_EVENT_REASON_BYTES + '…'.len_utf8());
    }

    #[test]
    fn required_subject_ids_are_sorted_and_unique() {
        let mut sorted = REQUIRED_SUBJECT_IDS.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, REQUIRED_SUBJECT_IDS);
        let unique: BTreeSet<_> = REQUIRED_SUBJECT_IDS.iter().copied().collect();
        assert_eq!(unique.len(), REQUIRED_SUBJECT_IDS.len());
    }

    #[test]
    fn markdown_cell_escapes_table_delimiters_and_newlines() {
        assert_eq!(markdown_cell("a|b\nc"), "a\\|b c");
    }

    #[test]
    fn unsafe_proof_paths_fail_closed() {
        assert!(safe_relative_path(Path::new("docs/evidence.json")));
        assert!(!safe_relative_path(Path::new("../outside")));
        assert!(!safe_relative_path(Path::new("/absolute")));
    }

    #[test]
    fn duplicate_jsonl_authority_records_fail_closed() {
        let file = tempfile::NamedTempFile::new().expect("temporary JSONL");
        fs::write(
            file.path(),
            "{\"id\":\"bd-a\",\"status\":\"open\"}\n{\"id\":\"bd-a\",\"status\":\"closed\"}\n",
        )
        .expect("write duplicate JSONL");
        let error = load_jsonl_records(file.path(), "id").expect_err("duplicate IDs must fail");
        assert!(error.contains("duplicates id=\"bd-a\""));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn redaction_never_emits_generated_lowercase_token_values(
            secret in "[A-Za-z0-9._~-]{1,2048}",
        ) {
            let input = format!("prefix token={secret} suffix");
            let redacted = bounded_redacted_reason(&input, Path::new("/workspace"));
            let leaked_value = format!("token={secret}");
            prop_assert!(!redacted.contains(&leaked_value));
            prop_assert!(redacted.contains("token=<redacted>"));
            prop_assert!(redacted.len() <= MAX_EVENT_REASON_BYTES + '…'.len_utf8());
        }

        #[test]
        fn parent_traversal_is_never_a_safe_proof_path(
            segment in "[A-Za-z0-9_-]{1,32}",
        ) {
            let candidate = format!("../{segment}/evidence.json");
            prop_assert!(!safe_relative_path(Path::new(&candidate)));
        }
    }
}
