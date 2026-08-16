//! Executable verification-coverage contract for the performance/conformance bridge.
//!
//! The historical RGC coverage matrix mapped every issue to three wildcard
//! `cargo test` rows.  That proves that commands exist, not that a claimed
//! production branch ran.  This module replaces that convention with:
//!
//! - an exact row for every bridge task and every public claim;
//! - separate required-future and observed-current evidence states;
//! - a conservative inventory of existing harness families;
//! - one versioned event and artifact contract;
//! - live tracker, claim-matrix, source-signal, and inventory validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
use rustix::fs::{CWD, Mode, OFlags, RenameFlags, open, renameat_with};

pub const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.verification-coverage-contract.v1";
pub const REPORT_SCHEMA_VERSION: &str =
    "franken-engine.verification-coverage-contract.validation-report.v1";
pub const EVENT_SCHEMA_VERSION: &str = "franken-engine.verification-event.v1";
pub const RUN_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.verification-run-manifest.v2";
pub const ARTIFACT_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.verification-artifact-manifest.v1";
pub const TIER_R_PROBE_SCHEMA_VERSION: &str = "franken-engine.provisional-tier-r-probe.v2";
pub const COMPONENT: &str = "verification_coverage_contract";
pub const OWNING_BEAD: &str = "bd-performance-conformance-bridge-tu32j.22.1.1";
pub const BRIDGE_ROOT: &str = "bd-performance-conformance-bridge-tu32j";
pub const CONTRACT_PATH: &str = "docs/verification_coverage_contract_v1.json";
pub const RENDERED_MARKDOWN_PATH: &str = "docs/VERIFICATION_COVERAGE_CONTRACT_V1.md";
pub const SOURCE_CUTOFF_UTC: &str = "2026-08-16T08:59:15Z";
pub const MAX_AGE_DAYS: u64 = 14;
pub const TIER_R_IMPLEMENTATION_TRUTH: &str = "franken-core executes its own parser, lowering pipeline, and InterpreterCore as a real provisional reference lane; zero module families are formally graduated, so this evidence is parity-visible rather than certified Tier-R parity.";
pub const TIER_R_PROBE_CASES: &[(&str, &str, &str)] = &[
    (
        "arithmetic-completion",
        "(function () { return 1 + 2; })();",
        r#"{"Int":3}"#,
    ),
    (
        "object-member-update",
        "(function () { var o = {x: 5}; o.x += 3; return o.x; })();",
        r#"{"Int":8}"#,
    ),
    (
        "loop-completion",
        "(function () { var s = 0; for (var i = 0; i < 5; i++) { s += i; } return s; })();",
        r#"{"Int":10}"#,
    ),
];
pub const TIER_R_BRANCH_SIGNALS: &[&str] = &[
    "reference_parse_completed",
    "reference_lowering_completed",
    "reference_execution_started",
    "reference_execution_completed",
    "reference_capability_denied",
    "expected_observable_equal",
];

pub const ERROR_IO: &str = "FE-VCC-1001";
pub const ERROR_JSON: &str = "FE-VCC-1002";
pub const ERROR_SCHEMA: &str = "FE-VCC-1003";
pub const ERROR_SUBJECT_DRIFT: &str = "FE-VCC-1004";
pub const ERROR_OWNER: &str = "FE-VCC-1005";
pub const ERROR_CLASSIFICATION: &str = "FE-VCC-1006";
pub const ERROR_UNSAFE_PATH: &str = "FE-VCC-1007";
pub const ERROR_HASH_DRIFT: &str = "FE-VCC-1008";
pub const ERROR_GENERIC_RUNNER: &str = "FE-VCC-1009";
pub const ERROR_BRANCH_PROOF: &str = "FE-VCC-1010";
pub const ERROR_FORMAT_DUPLICATION: &str = "FE-VCC-1011";
pub const ERROR_EVENT_SCHEMA: &str = "FE-VCC-1012";
pub const ERROR_ARTIFACT_CONTRACT: &str = "FE-VCC-1013";
pub const ERROR_SECRET_LEAK: &str = "FE-VCC-1014";
pub const ERROR_ORDER_OR_DUPLICATE: &str = "FE-VCC-1015";
pub const ERROR_HISTORICAL_PROOF: &str = "FE-VCC-1016";
pub const ERROR_MARKDOWN_DRIFT: &str = "FE-VCC-1017";
pub const ERROR_TIER_R_TRUTH: &str = "FE-VCC-1018";
pub const ERROR_STALE: &str = "FE-VCC-1019";
pub const ERROR_BOUNDS: &str = "FE-VCC-1020";
pub const ERROR_RETRY_MASKING: &str = "FE-VCC-1021";
pub const ERROR_BUNDLE_INCOMPLETE: &str = "FE-VCC-1022";
pub const ERROR_SILENT_FALLBACK: &str = "FE-VCC-1023";
pub const ERROR_PROVENANCE: &str = "FE-VCC-1024";
pub const ERROR_GENERATION_DRIFT: &str = "FE-VCC-1025";
pub const ERROR_REPO_ROOT: &str = "FE-VCC-1026";
pub const ERROR_CLOCK_AUTHORITY: &str = "FE-VCC-1027";
pub const ERROR_OUTCOME_MISMATCH: &str = "FE-VCC-1028";
pub const ERROR_REPRODUCTION: &str = "FE-VCC-1029";

const MAX_CONTRACT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_EVENTS: usize = 4_096;
const MAX_EVENT_BYTES: usize = 32 * 1024;
const MAX_EVENT_STREAM_BYTES: usize = 16 * 1024 * 1024;
const MAX_REASON_BYTES: usize = 1_024;
const MAX_ID_BYTES: usize = 256;
const MAX_ARTIFACT_HASHES_PER_EVENT: usize = 64;
const MAX_HARNESS_MEMBERS: usize = 8_192;
const MAX_HARNESS_SCAN_FILES: usize = 32_768;
const MAX_HARNESS_SCAN_DIRECTORIES: usize = 8_192;
const MAX_HARNESS_SCAN_DEPTH: usize = 32;
const MAX_COVERAGE_ROWS: usize = 1_024;
const MAX_BUNDLE_FILES: usize = 256;
const MAX_BUNDLE_DIRECTORIES: usize = 256;
const MAX_BUNDLE_DEPTH: usize = 16;
const MAX_BUNDLE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BUNDLE_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const REQUIRED_ARTIFACT_FILES: &[&str] = &[
    "contract.json",
    "generated_contract.json",
    "rendered_contract.md",
    "validation_report.json",
    "run_manifest.json",
    "events.jsonl",
    "commands.txt",
    "env.json",
    "root.Cargo.lock",
    "tool.Cargo.lock",
    "repro.lock",
    "reproduction_record.json",
    "reproduction.stdout.log",
    "reproduction.stderr.log",
    "LEGAL.md",
    "provenance_graph.json",
    "tier_r_probe.json",
    "tier_r_build_environment.json",
    "tier_r_source_manifest.json",
    "tier_r_invocation.json",
    "tier_r_probe.stderr.log",
    "guest.stdout.log",
    "guest.stderr.log",
    "artifact_manifest.json",
];

const ALLOWED_EVENT_NAMES: &[&str] = &[
    "run_started",
    "contract_check",
    "attempt_failed",
    "run_completed",
];

const ALLOWED_REASON_CODES: &[&str] = &[
    "FE-VCC-0000",
    ERROR_IO,
    ERROR_JSON,
    ERROR_SCHEMA,
    ERROR_SUBJECT_DRIFT,
    ERROR_OWNER,
    ERROR_CLASSIFICATION,
    ERROR_UNSAFE_PATH,
    ERROR_HASH_DRIFT,
    ERROR_GENERIC_RUNNER,
    ERROR_BRANCH_PROOF,
    ERROR_FORMAT_DUPLICATION,
    ERROR_EVENT_SCHEMA,
    ERROR_ARTIFACT_CONTRACT,
    ERROR_SECRET_LEAK,
    ERROR_ORDER_OR_DUPLICATE,
    ERROR_HISTORICAL_PROOF,
    ERROR_MARKDOWN_DRIFT,
    ERROR_TIER_R_TRUTH,
    ERROR_STALE,
    ERROR_BOUNDS,
    ERROR_RETRY_MASKING,
    ERROR_BUNDLE_INCOMPLETE,
    ERROR_SILENT_FALLBACK,
    ERROR_PROVENANCE,
    ERROR_GENERATION_DRIFT,
    ERROR_REPO_ROOT,
    ERROR_CLOCK_AUTHORITY,
    ERROR_OUTCOME_MISMATCH,
    ERROR_REPRODUCTION,
    "FE-VCC-1099",
];

const REQUIRED_EVENT_FIELDS: &[&str] = &[
    "schema_version",
    "run_id",
    "trace_id",
    "test_id",
    "scenario_id",
    "seed",
    "attempt",
    "platform",
    "target",
    "tier",
    "security_profile",
    "phase",
    "sequence",
    "event",
    "decision",
    "reason_code",
    "reason",
    "error_class",
    "fallback",
    "rollback",
    "duration_ns",
    "resource_delta",
    "artifact_hashes",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationCoverageContract {
    pub schema_version: String,
    pub contract_id: String,
    pub owning_bead: String,
    pub source_cutoff_utc: String,
    pub max_age_days: u64,
    pub rendered_markdown_path: String,
    pub purpose: String,
    pub truth_posture: String,
    pub authority_sources: Vec<AuthoritySource>,
    pub classification_definitions: BTreeMap<String, String>,
    pub event_contract: EventContract,
    pub artifact_contract: ArtifactContract,
    pub compatibility: CompatibilityContract,
    pub harness_families: Vec<HarnessFamily>,
    pub coverage_rows: Vec<CoverageRow>,
    pub integrations: Vec<IntegrationContract>,
    pub provenance_edges: Vec<ProvenanceEdge>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySource {
    pub authority_id: String,
    pub path: String,
    pub selector: String,
    pub projection_sha256: String,
    pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventContract {
    pub schema_version: String,
    pub required_fields: Vec<String>,
    pub max_events: usize,
    pub max_event_bytes: usize,
    pub max_stream_bytes: usize,
    pub max_reason_bytes: usize,
    pub max_id_bytes: usize,
    pub max_artifact_hashes_per_event: usize,
    pub sequence_starts_at: u64,
    pub sequence_rule: String,
    pub retry_rule: String,
    pub guest_output_rule: String,
    pub redaction_markers: Vec<String>,
    pub decisions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactContract {
    pub run_manifest_schema_version: String,
    pub artifact_manifest_schema_version: String,
    pub required_files: Vec<String>,
    pub raw_sample_alternative: String,
    pub no_replace_publication: bool,
    pub exact_failure_exit_required: bool,
    pub first_failure_preserved: bool,
    pub hash_algorithm: String,
    pub max_files: usize,
    pub max_directories: usize,
    pub max_depth: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityContract {
    pub current_major: u32,
    pub accepted_schema_versions: Vec<String>,
    pub additive_minor_requires_fixture: bool,
    pub unknown_fields_rejected: bool,
    pub downgrade_forbidden: bool,
    pub migration_owner: String,
    pub migration_entrypoint: String,
    pub rollback_rule: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessExecutionClass {
    ProductionExecuting,
    TestOnly,
    MockOnly,
    Stale,
}

impl HarnessExecutionClass {
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProductionExecuting => "production_executing",
            Self::TestOnly => "test_only",
            Self::MockOnly => "mock_only",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReuseStatus {
    Reusable,
    Conditional,
    Rejected,
}

impl ReuseStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Reusable => "reusable",
            Self::Conditional => "conditional",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityMode {
    ContentHash,
    PathSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessFamily {
    pub family_id: String,
    pub title: String,
    pub purpose: String,
    pub execution_class: HarnessExecutionClass,
    pub reuse_status: ReuseStatus,
    pub integrity_mode: IntegrityMode,
    pub current_coverage_eligible: bool,
    pub owner: String,
    pub runner: String,
    pub emitted_event_schema: String,
    pub success_basis: String,
    pub source_inventory_signals: Vec<BranchSignal>,
    pub members: Vec<HarnessMember>,
    pub inventory_sha256: String,
    pub inventory_basis: String,
    pub limitations: Vec<String>,
    pub successor_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessMember {
    pub path: String,
    pub sha256: Option<String>,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchSignal {
    pub path: String,
    pub symbol: String,
    pub marker: String,
    pub interpretation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    BridgeTask,
    Claim,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    CandidateCurrentRun,
    HistoricalUnrecertified,
    RequiredFuture,
    TargetUnproven,
    HypothesisUnimplemented,
}

impl EvidenceState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CandidateCurrentRun => "candidate_current_run",
            Self::HistoricalUnrecertified => "historical_unrecertified",
            Self::RequiredFuture => "required_future",
            Self::TargetUnproven => "target_unproven",
            Self::HypothesisUnimplemented => "hypothesis_unimplemented",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageRow {
    pub row_id: String,
    pub subject_id: String,
    pub subject_kind: SubjectKind,
    pub title: String,
    pub authority_state: String,
    pub evidence_state: EvidenceState,
    pub independent_owner: String,
    pub required_verification_packs: Vec<String>,
    pub required_public_entrypoint: String,
    pub required_layers: Vec<String>,
    pub required_platforms: Vec<String>,
    pub required_tiers: Vec<String>,
    pub required_security_profiles: Vec<String>,
    pub current_runner_family_ids: Vec<String>,
    pub current_evidence: Vec<String>,
    pub gap_reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationContract {
    pub integration_id: String,
    pub role: String,
    pub classification: String,
    pub entrypoint: String,
    pub required_signals: Vec<String>,
    pub success_rule: String,
    pub refusal_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceEdge {
    pub from: String,
    pub relation: String,
    pub to: String,
}

#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub run_id: String,
    pub trace_id: String,
    pub test_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub attempt: u32,
    pub platform: String,
    pub target: String,
    pub tier: String,
    pub security_profile: String,
    pub as_of_utc: DateTime<Utc>,
    pub certifying_clock: bool,
}

impl ValidationContext {
    #[must_use]
    pub fn deterministic_for_tests(as_of_utc: DateTime<Utc>) -> Self {
        Self {
            run_id: "run-verification-coverage-contract-test".to_string(),
            trace_id: "trace-verification-coverage-contract-test".to_string(),
            test_id: "verification-coverage-contract".to_string(),
            scenario_id: "canonical-validation".to_string(),
            seed: 0,
            attempt: 1,
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            target: option_env!("TARGET").unwrap_or("host").to_string(),
            tier: "verification-control-plane".to_string(),
            security_profile: "evidence-on".to_string(),
            as_of_utc,
            certifying_clock: false,
        }
    }

    #[must_use]
    pub fn certifying_now() -> Self {
        let now = Utc::now();
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            now.timestamp_nanos_opt().unwrap_or_default()
        );
        Self {
            run_id: format!("run-vcc-{nonce}"),
            trace_id: format!("trace-vcc-{nonce}"),
            test_id: "verification-coverage-contract".to_string(),
            scenario_id: "canonical-validation".to_string(),
            seed: 0,
            attempt: 1,
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            target: format!("host:{}:{}", std::env::consts::OS, std::env::consts::ARCH),
            tier: "verification-control-plane".to_string(),
            security_profile: "evidence-on".to_string(),
            as_of_utc: now,
            certifying_clock: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDelta {
    pub cpu_time_ns: Option<i64>,
    pub wall_time_ns: Option<i64>,
    pub max_rss_bytes: Option<i64>,
    pub allocated_bytes: Option<i64>,
    pub io_read_bytes: Option<i64>,
    pub io_write_bytes: Option<i64>,
    pub measurement_sources: BTreeMap<String, String>,
}

impl ResourceDelta {
    fn validation_sample(duration_ns: u64) -> Self {
        let duration = i64::try_from(duration_ns).unwrap_or(i64::MAX);
        Self {
            cpu_time_ns: None,
            wall_time_ns: Some(duration),
            max_rss_bytes: None,
            allocated_bytes: None,
            io_read_bytes: None,
            io_write_bytes: None,
            measurement_sources: BTreeMap::from([
                (
                    "cpu_time_ns".to_string(),
                    "unavailable:not-measured-by-validator".to_string(),
                ),
                (
                    "wall_time_ns".to_string(),
                    "measured:std-time-instant".to_string(),
                ),
                (
                    "max_rss_bytes".to_string(),
                    "unavailable:not-measured-by-validator".to_string(),
                ),
                (
                    "allocated_bytes".to_string(),
                    "unavailable:not-measured-by-validator".to_string(),
                ),
                (
                    "io_read_bytes".to_string(),
                    "unavailable:not-measured-by-validator".to_string(),
                ),
                (
                    "io_write_bytes".to_string(),
                    "unavailable:not-measured-by-validator".to_string(),
                ),
            ]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationEvent {
    pub schema_version: String,
    pub run_id: String,
    pub trace_id: String,
    pub test_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub attempt: u32,
    pub platform: String,
    pub target: String,
    pub tier: String,
    pub security_profile: String,
    pub phase: String,
    pub sequence: u64,
    pub event: String,
    pub decision: String,
    pub reason_code: String,
    pub reason: String,
    pub error_class: Option<String>,
    pub fallback: String,
    pub rollback: String,
    pub duration_ns: u64,
    pub resource_delta: ResourceDelta,
    pub artifact_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationFinding {
    pub error_code: String,
    pub phase: String,
    pub reason: String,
    pub subject_id: Option<String>,
    pub family_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReport {
    pub schema_version: String,
    pub contract_path: String,
    pub contract_sha256: String,
    pub generated_contract_sha256: String,
    pub source_cutoff_utc: String,
    pub as_of_utc: String,
    pub certifying_clock: bool,
    pub status: String,
    pub bridge_task_count: usize,
    pub claim_count: usize,
    pub coverage_row_count: usize,
    pub harness_family_count: usize,
    pub harness_member_count: usize,
    pub checks_run: usize,
    pub error_count: usize,
    pub findings: Vec<ValidationFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationOutput {
    pub report: ValidationReport,
    pub events: Vec<VerificationEvent>,
}

impl ValidationOutput {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.report.error_count == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LiveIssue {
    id: String,
    title: String,
    status: String,
    issue_type: String,
    #[serde(default)]
    assignee: Option<String>,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    acceptance_criteria: String,
    #[serde(default)]
    dependencies: Vec<LiveDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LiveDependency {
    issue_id: String,
    depends_on_id: String,
    #[serde(rename = "type")]
    dependency_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimMatrix {
    schema_version: String,
    claims: Vec<LiveClaim>,
    freshness_eprocess_policy: FreshnessEprocessPolicy,
    freshness_tier_policy: FreshnessTierPolicy,
    generated_by: String,
    max_authored_freshness_days: u64,
    max_observed_freshness_days: u64,
    owning_bead: String,
    performance_evidence_policy: PerformanceEvidencePolicy,
    policy_id: String,
    state_order: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessEprocessPolicy {
    alpha_millionths: u64,
    horizon_days: u64,
    method: String,
    note: String,
    owning_bead: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessTierPolicy {
    adr: String,
    note: String,
    owning_bead: String,
    tiers: BTreeMap<String, FreshnessTier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreshnessTier {
    applies_to: String,
    days: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PerformanceEvidencePolicy {
    banned_observed_performance_fragments: Vec<String>,
    real_hot_path_observed_internal_evidence: RealHotPathObservedEvidence,
    throughput_denominator_target_evidence: ThroughputDenominatorTargetEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RealHotPathObservedEvidence {
    contract_gate: String,
    contract_schema: String,
    observed_scope: String,
    proof_wrapper: String,
    runtime_lane: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThroughputDenominatorTargetEvidence {
    claim_id: String,
    current_state: String,
    linked_artifact: String,
    measured_geomean_speedup_millionths: BaselineSpeedups,
    meets_3x_floor: bool,
    required_before_observed: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineSpeedups {
    node: u64,
    bun: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LiveClaim {
    claim_id: String,
    claim_text: String,
    allowed_state: String,
    actual_wording_state: String,
    #[serde(default)]
    artifact_path: Option<String>,
    claim_scope: String,
    owning_bead: String,
    verification_command: String,
    #[serde(flatten)]
    extra: BTreeMap<String, JsonValue>,
}

struct FamilySpec<'a> {
    family_id: &'a str,
    title: &'a str,
    purpose: &'a str,
    execution_class: HarnessExecutionClass,
    reuse_status: ReuseStatus,
    integrity_mode: IntegrityMode,
    current_coverage_eligible: bool,
    owner: &'a str,
    runner: &'a str,
    emitted_event_schema: &'a str,
    success_basis: &'a str,
    exact_paths: &'a [&'a str],
    scan_roots: &'a [(&'a str, &'a str, Option<&'a str>, bool)],
    exclusions: &'a [&'a str],
    signals: &'a [(&'a str, &'a str, &'a str, &'a str)],
    limitations: &'a [&'a str],
    successor_bead: &'a str,
}

const REVIEWED_E2E_PATHS: &[&str] = &[
    "scripts/e2e/execution_truth_ledger_smoke.sh",
    "scripts/e2e/verification_coverage_contract_smoke.sh",
    "scripts/e2e/ifc_release_gate_replay.sh",
    "scripts/e2e/live_guardplane_decision_smoke.sh",
    "scripts/e2e/live_ifc_declassification_smoke.sh",
    "scripts/e2e/frankenctl_cli_workflow.sh",
    "scripts/e2e/metamorphic_suite_replay.sh",
    "scripts/e2e/rgc_lockstep_oracle_pipeline_replay.sh",
    "scripts/e2e/security_conformance_runner_replay.sh",
    "scripts/e2e/rgc_verification_coverage_matrix_replay.sh",
    "scripts/e2e/control_plane_mock_inventory_replay.sh",
    "scripts/e2e/ambient_mock_guard_replay.sh",
];

/// Build the canonical contract from live tracker, claim, and repository
/// identities.  This generator records requirements and current truth; it does
/// not promote a future runner merely because its bead or filename exists.
pub fn generate_contract(repo_root: &Path) -> Result<VerificationCoverageContract, String> {
    ensure_repo_root(repo_root)?;
    let issues = load_issues(repo_root)?;
    let claims = load_claim_matrix(repo_root)?;
    let bridge_issues: Vec<LiveIssue> = issues
        .iter()
        .filter(|issue| issue.id == BRIDGE_ROOT || issue.id.starts_with(&format!("{BRIDGE_ROOT}.")))
        .cloned()
        .collect();
    let tasks: Vec<LiveIssue> = bridge_issues
        .iter()
        .filter(|issue| issue.issue_type == "task")
        .cloned()
        .collect();

    let harness_families = build_harness_families(repo_root)?;
    let coverage_rows = build_coverage_rows(&tasks, &bridge_issues, &claims.claims)?;
    let authority_sources = build_authority_sources(repo_root, &bridge_issues, &claims)?;

    Ok(VerificationCoverageContract {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        contract_id: "franken-engine-performance-conformance-bridge-verification-v1".to_string(),
        owning_bead: OWNING_BEAD.to_string(),
        source_cutoff_utc: SOURCE_CUTOFF_UTC.to_string(),
        max_age_days: MAX_AGE_DAYS,
        rendered_markdown_path: RENDERED_MARKDOWN_PATH.to_string(),
        purpose: "Map every bridge task and public claim to exact verification obligations without treating a filename, wildcard command, mock, historical closure, or target statement as current production proof.".to_string(),
        truth_posture: "The matrix is allowed to be complete while implementation coverage is incomplete: required_future, target_unproven, hypothesis_unimplemented, and historical_unrecertified are first-class non-passing evidence states. Only a current independently validated bundle may become observed proof.".to_string(),
        authority_sources,
        classification_definitions: BTreeMap::from([
            (
                "production_executing".to_string(),
                "The reviewed runner is capable of reaching a named production implementation branch. Static source markers are inventory hints only; current proof requires run-bound production instrumentation.".to_string(),
            ),
            (
                "test_only".to_string(),
                "The code is executable test machinery but has not proved a shipped public branch under the required profile.".to_string(),
            ),
            (
                "mock_only".to_string(),
                "The machinery can inject or model a fault but cannot establish feature success, performance, or equivalence.".to_string(),
            ),
            (
                "stale".to_string(),
                "The machinery encodes an obsolete tracker shape, denominator, schema, or branch assumption and is rejected as current proof.".to_string(),
            ),
            (
                "reusable".to_string(),
                "The reviewed family may be composed into a current verification pack after its exact limitations and event compatibility are satisfied.".to_string(),
            ),
            (
                "conditional".to_string(),
                "Useful logic exists, but current proof requires recertification, schema adaptation, branch instrumentation, or a stronger oracle.".to_string(),
            ),
            (
                "rejected".to_string(),
                "The family remains historical input only and cannot be selected by a current coverage row.".to_string(),
            ),
        ]),
        event_contract: EventContract {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            required_fields: REQUIRED_EVENT_FIELDS.iter().map(|field| (*field).to_string()).collect(),
            max_events: MAX_EVENTS,
            max_event_bytes: MAX_EVENT_BYTES,
            max_stream_bytes: MAX_EVENT_STREAM_BYTES,
            max_reason_bytes: MAX_REASON_BYTES,
            max_id_bytes: MAX_ID_BYTES,
            max_artifact_hashes_per_event: MAX_ARTIFACT_HASHES_PER_EVENT,
            sequence_starts_at: 1,
            sequence_rule: "Sequence is strictly contiguous within one run/trace stream; reorder, duplicate, truncation, or a record after run_completed fails closed.".to_string(),
            retry_rule: "Attempt N>1 requires a retained attempt_failed event for N-1 with the same test/scenario; a later pass cannot erase the prior failure.".to_string(),
            guest_output_rule: "Guest stdout and stderr are retained only in guest.stdout.log and guest.stderr.log, are never parsed as harness events, and are scanned for secrets.".to_string(),
            redaction_markers: vec![
                "authorization:".to_string(),
                "bearer ".to_string(),
                "api_key=".to_string(),
                "apikey=".to_string(),
                "password=".to_string(),
                "secret=".to_string(),
                "token=".to_string(),
                "private_key".to_string(),
            ],
            decisions: vec![
                "pass".to_string(),
                "fail".to_string(),
                "deny".to_string(),
                "fallback".to_string(),
                "cancel".to_string(),
                "crash".to_string(),
                "rollback".to_string(),
            ],
        },
        artifact_contract: ArtifactContract {
            run_manifest_schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
            artifact_manifest_schema_version: ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
            required_files: REQUIRED_ARTIFACT_FILES.iter().map(|path| (*path).to_string()).collect(),
            raw_sample_alternative: "A minimized_seed.json may replace samples.jsonl only for a deterministic failing reduction, and run_manifest.json must name that substitution.".to_string(),
            no_replace_publication: true,
            exact_failure_exit_required: true,
            first_failure_preserved: true,
            hash_algorithm: "sha256".to_string(),
            max_files: MAX_BUNDLE_FILES,
            max_directories: MAX_BUNDLE_DIRECTORIES,
            max_depth: MAX_BUNDLE_DEPTH,
            max_file_bytes: MAX_BUNDLE_FILE_BYTES,
            max_total_bytes: MAX_BUNDLE_TOTAL_BYTES,
        },
        compatibility: CompatibilityContract {
            current_major: 1,
            accepted_schema_versions: vec![
                CONTRACT_SCHEMA_VERSION.to_string(),
                EVENT_SCHEMA_VERSION.to_string(),
                RUN_MANIFEST_SCHEMA_VERSION.to_string(),
                ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
                TIER_R_PROBE_SCHEMA_VERSION.to_string(),
            ],
            additive_minor_requires_fixture: true,
            unknown_fields_rejected: true,
            downgrade_forbidden: true,
            migration_owner: "bd-performance-conformance-bridge-tu32j.22.2".to_string(),
            migration_entrypoint: "scripts/bridge/migrate_verification_bundle.sh".to_string(),
            rollback_rule: "Write a new version beside the old immutable bundle, verify both, switch consumers atomically, and retain the prior version until the clean-room capstone accepts the migration.".to_string(),
        },
        harness_families,
        coverage_rows,
        integrations: vec![
            IntegrationContract {
                integration_id: "canonical-contract-validator".to_string(),
                role: "canonical_production_path".to_string(),
                classification: "production_executing".to_string(),
                entrypoint: "./scripts/run_verification_coverage_contract_gate.sh ci".to_string(),
                required_signals: vec![
                    "generate_contract".to_string(),
                    "validate_contract_file".to_string(),
                    "contract_validation_completed".to_string(),
                    "artifact_bundle_validated".to_string(),
                ],
                success_rule: "The exact committed contract is regenerated from live authorities, validates, renders byte-identically, and publishes a complete no-replace bundle.".to_string(),
                refusal_rule: "Any missing authority, subject, branch marker, artifact, or exact hash exits nonzero and retains the first typed failure.".to_string(),
            },
            IntegrationContract {
                integration_id: "provisional-tier-r-candidate".to_string(),
                role: "reference_path".to_string(),
                classification: "provisional_not_certified_tier_r".to_string(),
                entrypoint: "cargo run --manifest-path tools/execution-truth-ledger/Cargo.toml --features tier-r-probe --bin franken_provisional_tier_r_probe".to_string(),
                required_signals: TIER_R_BRANCH_SIGNALS
                    .iter()
                    .map(|signal| (*signal).to_string())
                    .collect(),
                success_rule: "The real franken-core parser, lowering pipeline, and InterpreterCore execute an exact content-addressed corpus plus an exact VmDispatch denial probe. Runtime observables must equal independently declared expected values and semantic digests, with nonzero execution and IR hashes.".to_string(),
                refusal_rule: "This proves a live provisional reference candidate only. Franken-core has zero graduated module families, so the result must never be described as certified Tier R, full parity, or completion of any bridge semantic claim.".to_string(),
            },
        ],
        provenance_edges: build_provenance_edges(&tasks, &claims.claims)?,
        limitations: vec![
            "The canonical shipped semantics owner remains crates/franken-engine; the independently compilable franken-core probe is parity-visible but not a graduated Tier-R oracle.".to_string(),
            "Existing shell harnesses emit many incompatible legacy formats. They remain conservatively test-only or conditionally reusable until BRIDGE-21.2 and BRIDGE-21.3 migrate them.".to_string(),
            "Source inventory signals prove that reviewed symbols and call sites exist, not that a production branch executed. Certifying bundles must carry run-bound instrumentation and artifact hashes.".to_string(),
            "Observed claims in the older claim matrix are historical inputs. This contract does not silently promote them to current independently recertified evidence.".to_string(),
            "Optional Apple M5, PMU, NUMA, TEE, and native-JIT evidence stays required_future when the declared platform is unavailable; unavailability is an explicit record, never a pass.".to_string(),
        ],
    })
}

fn ensure_repo_root(repo_root: &Path) -> Result<(), String> {
    for required in [
        ".beads/issues.jsonl",
        "docs/claim_to_proof_matrix_v1.json",
        "docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md",
    ] {
        if !repo_root.join(required).is_file() {
            return Err(format!(
                "{ERROR_REPO_ROOT}: `{}` is not a FrankenEngine repository root; missing {required}",
                repo_root.display()
            ));
        }
    }
    Ok(())
}

fn load_issues(repo_root: &Path) -> Result<Vec<LiveIssue>, String> {
    let path = repo_root.join(".beads/issues.jsonl");
    let bytes = read_bounded_regular_file(&path, MAX_CONTRACT_BYTES)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| format!("{ERROR_JSON}: tracker is not UTF-8: {error}"))?;
    let mut issues = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let issue: LiveIssue = serde_json::from_str(line).map_err(|error| {
            format!(
                "{ERROR_JSON}: parse .beads/issues.jsonl line {}: {error}",
                index + 1
            )
        })?;
        issues.push(issue);
    }
    issues.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(issues)
}

fn load_claim_matrix(repo_root: &Path) -> Result<ClaimMatrix, String> {
    let path = repo_root.join("docs/claim_to_proof_matrix_v1.json");
    let bytes = read_bounded_regular_file(&path, MAX_CONTRACT_BYTES)?;
    let mut matrix: ClaimMatrix = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{ERROR_JSON}: parse {}: {error}", path.display()))?;
    validate_claim_matrix_freshness_policy(&matrix)?;
    matrix
        .claims
        .sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    Ok(matrix)
}

fn validate_claim_matrix_freshness_policy(matrix: &ClaimMatrix) -> Result<(), String> {
    let policy = &matrix.freshness_tier_policy;
    if matrix.max_observed_freshness_days == 0
        || matrix.max_authored_freshness_days == 0
        || matrix.max_observed_freshness_days > matrix.max_authored_freshness_days
    {
        return Err(format!(
            "{ERROR_SCHEMA}: claim-matrix freshness bounds must be positive and ordered: observed={} authored={}",
            matrix.max_observed_freshness_days, matrix.max_authored_freshness_days
        ));
    }
    if policy.adr.trim().is_empty()
        || policy.note.trim().is_empty()
        || policy.owning_bead.trim().is_empty()
        || policy.tiers.is_empty()
    {
        return Err(format!(
            "{ERROR_SCHEMA}: claim-matrix freshness tier policy requires an ADR, note, owner, and at least one tier"
        ));
    }

    let mut largest_tier_days = 0;
    for (tier_name, tier) in &policy.tiers {
        if tier_name.trim().is_empty()
            || tier.applies_to.trim().is_empty()
            || tier.days == 0
            || tier.days > matrix.max_authored_freshness_days
        {
            return Err(format!(
                "{ERROR_SCHEMA}: claim-matrix freshness tier `{tier_name}` must have a non-empty scope and a positive window no larger than max_authored_freshness_days"
            ));
        }
        largest_tier_days = largest_tier_days.max(tier.days);
    }
    if largest_tier_days != matrix.max_authored_freshness_days {
        return Err(format!(
            "{ERROR_SCHEMA}: max_authored_freshness_days={} must equal the largest declared tier window={largest_tier_days}",
            matrix.max_authored_freshness_days
        ));
    }
    Ok(())
}

fn build_authority_sources(
    repo_root: &Path,
    bridge_issues: &[LiveIssue],
    claims: &ClaimMatrix,
) -> Result<Vec<AuthoritySource>, String> {
    #[derive(Serialize)]
    struct IssueRequirementIdentity<'a> {
        id: &'a str,
        title: &'a str,
        issue_type: &'a str,
        description: &'a str,
        acceptance_criteria: &'a str,
        labels: Vec<&'a str>,
        dependencies: Vec<DependencyIdentity<'a>>,
    }
    #[derive(Serialize)]
    struct DependencyIdentity<'a> {
        depends_on_id: &'a str,
        dependency_type: &'a str,
    }
    let mut issue_projection: Vec<IssueRequirementIdentity<'_>> = bridge_issues
        .iter()
        .map(|issue| {
            let mut labels: Vec<&str> = issue.labels.iter().map(String::as_str).collect();
            labels.sort_unstable();
            let mut dependencies: Vec<DependencyIdentity<'_>> = issue
                .dependencies
                .iter()
                .map(|dependency| DependencyIdentity {
                    depends_on_id: &dependency.depends_on_id,
                    dependency_type: &dependency.dependency_type,
                })
                .collect();
            dependencies.sort_by(|left, right| {
                (left.depends_on_id, left.dependency_type)
                    .cmp(&(right.depends_on_id, right.dependency_type))
            });
            IssueRequirementIdentity {
                id: &issue.id,
                title: &issue.title,
                issue_type: &issue.issue_type,
                description: &issue.description,
                acceptance_criteria: &issue.acceptance_criteria,
                labels,
                dependencies,
            }
        })
        .collect();
    issue_projection.sort_by(|left, right| left.id.cmp(right.id));
    let issue_bytes = serde_json::to_vec(&issue_projection)
        .map_err(|error| format!("{ERROR_JSON}: serialize issue projection: {error}"))?;

    let claim_bytes = serde_json::to_vec(claims)
        .map_err(|error| format!("{ERROR_JSON}: serialize claim matrix projection: {error}"))?;

    let plan_path = repo_root.join("docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md");
    let plan_bytes = read_bounded_regular_file(&plan_path, MAX_CONTRACT_BYTES)?;
    let plan = std::str::from_utf8(&plan_bytes)
        .map_err(|error| format!("{ERROR_JSON}: plan is not UTF-8: {error}"))?;
    let section = select_markdown_section(plan, "## 18.")
        .ok_or_else(|| format!("{ERROR_SCHEMA}: plan has no Section 18"))?;

    let stale_path = repo_root.join("docs/rgc_verification_coverage_matrix_v1.json");
    let stale_bytes = read_bounded_regular_file(&stale_path, MAX_CONTRACT_BYTES)?;

    Ok(vec![
        AuthoritySource {
            authority_id: "bridge-requirement-identity".to_string(),
            path: ".beads/issues.jsonl".to_string(),
            selector: format!(
                "all {} bridge issue id/title/type/description/acceptance/label/dependency requirements; mutable status and assignee are validated separately",
                issue_projection.len()
            ),
            projection_sha256: sha256_hex(&issue_bytes),
            purpose: "Exact bridge scope and closure contract; wildcard selectors and title-only authority are forbidden.".to_string(),
        },
        AuthoritySource {
            authority_id: "claim-matrix".to_string(),
            path: "docs/claim_to_proof_matrix_v1.json".to_string(),
            selector: "complete typed claim matrix, with claim rows sorted by claim_id"
                .to_string(),
            projection_sha256: sha256_hex(&claim_bytes),
            purpose: "Exact public claim scope, current posture, state ordering, freshness policy, and performance-evidence policy.".to_string(),
        },
        AuthoritySource {
            authority_id: "bridge-plan-section-18".to_string(),
            path: "docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md".to_string(),
            selector: "Section 18 through the next level-2 heading or EOF".to_string(),
            projection_sha256: sha256_hex(section.as_bytes()),
            purpose: "Normative performance, conformance, Tier-R, security, evidence, and verification obligations.".to_string(),
        },
        AuthoritySource {
            authority_id: "rejected-rgc-predecessor".to_string(),
            path: "docs/rgc_verification_coverage_matrix_v1.json".to_string(),
            selector: "full historical file".to_string(),
            projection_sha256: sha256_hex(&stale_bytes),
            purpose: "Negative prior: obsolete scope, three wildcard rows, generic cargo commands, and stale br JSON assumptions.".to_string(),
        },
    ])
}

fn select_markdown_section<'a>(document: &'a str, heading_prefix: &str) -> Option<&'a str> {
    let start = document
        .match_indices(heading_prefix)
        .find(|(index, _)| *index == 0 || document.as_bytes().get(index - 1) == Some(&b'\n'))?
        .0;
    let remainder = &document[start..];
    let end = remainder
        .match_indices("\n## ")
        .next()
        .map_or(remainder.len(), |(index, _)| index + 1);
    Some(&remainder[..end])
}

fn build_harness_families(repo_root: &Path) -> Result<Vec<HarnessFamily>, String> {
    let aggregate_owner = "bd-performance-conformance-bridge-tu32j.22.27";
    let mut families = vec![family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "verification-coverage-contract",
            title: "BRIDGE-21.1 canonical coverage validator",
            purpose: "Generate and validate exact task/claim coverage, rich events, complete bundles, branch signals, and deterministic human rendering.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Reusable,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: true,
            owner: OWNING_BEAD,
            runner: "./scripts/run_verification_coverage_contract_gate.sh ci",
            emitted_event_schema: EVENT_SCHEMA_VERSION,
            success_basis: "The independently resolvable Rust validator executes its real generation and validation path, then the gate executes a real parser/lowering/interpreter reference probe and validates the resulting bundle.",
            exact_paths: &[
                "crates/franken-engine/src/verification_coverage_contract.rs",
                "crates/franken-engine/src/bin/franken_verification_coverage_contract.rs",
                "crates/franken-engine/tests/verification_coverage_contract_integration.rs",
                "scripts/run_verification_coverage_contract_gate.sh",
                "scripts/e2e/verification_coverage_contract_smoke.sh",
                "tools/execution-truth-ledger/Cargo.toml",
                "tools/execution-truth-ledger/Cargo.lock",
                "tools/execution-truth-ledger/src/lib.rs",
                "tools/execution-truth-ledger/src/tier_r_probe.rs",
            ],
            scan_roots: &[],
            exclusions: &[],
            signals: &[
                (
                    "crates/franken-engine/src/verification_coverage_contract.rs",
                    "generate_contract",
                    "pub fn generate_contract",
                    "The canonical producer derives exact rows from live authorities.",
                ),
                (
                    "crates/franken-engine/src/verification_coverage_contract.rs",
                    "validate_contract_file",
                    "pub fn validate_contract_file",
                    "The canonical consumer validates the committed contract against live state.",
                ),
                (
                    "scripts/run_verification_coverage_contract_gate.sh",
                    "public gate",
                    "franken_verification_coverage_contract",
                    "The public shell entrypoint invokes the Rust implementation rather than reimplementing its verdict in shell.",
                ),
            ],
            limitations: &[
                "Current certification covers the verification contract itself, not completion of future bridge implementation rows.",
                "The runtime reference probe is explicitly provisional until a canonical Tier-R owner graduates.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.27",
        },
    )?];

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "execution-truth-ledger",
            title: "BRIDGE-00.1 executable-vs-scaffold truth ledger",
            purpose: "Validate claim posture, tracker ownership, source/artifact probes, hashes, freshness, and deterministic truth rendering.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.1.1",
            runner: "./scripts/run_execution_truth_ledger_gate.sh ci",
            emitted_event_schema: "franken-engine.execution-truth-ledger.validation-event.v1",
            success_basis: "A dependency-minimal Rust validator runs against live tracker, claim, Git, source, and artifact state.",
            exact_paths: &[
                "crates/franken-engine/src/execution_truth_ledger.rs",
                "crates/franken-engine/src/bin/franken_execution_truth_ledger.rs",
                "crates/franken-engine/tests/execution_truth_ledger_integration.rs",
                "scripts/run_execution_truth_ledger_gate.sh",
                "scripts/e2e/execution_truth_ledger_smoke.sh",
            ],
            scan_roots: &[],
            exclusions: &[],
            signals: &[
                (
                    "crates/franken-engine/src/execution_truth_ledger.rs",
                    "validate_ledger_file",
                    "pub fn validate_ledger_file",
                    "The production validator reaches live evidence probes.",
                ),
                (
                    "scripts/e2e/execution_truth_ledger_smoke.sh",
                    "seeded failure suite",
                    "scenario_count",
                    "The E2E challenges the validator with adversarial mutations.",
                ),
            ],
            limitations: &[
                "Its v1 event schema predates the unified tier/profile/resource/fallback fields.",
                "Its closed bead is historical input until BRIDGE-21.6 independently recertifies it.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.6",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "engine-inline-unit-tests",
            title: "franken-engine inline unit/property tests",
            purpose: "Inline tests colocated with canonical engine modules.",
            execution_class: HarnessExecutionClass::TestOnly,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::PathSet,
            current_coverage_eligible: false,
            owner: aggregate_owner,
            runner: "rch exec -- env CARGO_TARGET_DIR=<unique> cargo test -p frankenengine-engine --lib",
            emitted_event_schema: "rust-test-human-output",
            success_basis: "Rust test functions execute production module code in a cfg(test) process.",
            exact_paths: &[],
            scan_roots: &[("crates/franken-engine/src", ".rs", Some("#[test]"), true)],
            exclusions: &[],
            signals: &[],
            limitations: &[
                "A passing library suite does not prove a shipped CLI/runtime branch, required profile, or artifact contract.",
                "Human libtest output is not the unified verification event schema.",
            ],
            successor_bead: aggregate_owner,
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "engine-integration-tests",
            title: "franken-engine integration test files",
            purpose: "Black-box and white-box integration coverage compiled as separate test crates.",
            execution_class: HarnessExecutionClass::TestOnly,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::PathSet,
            current_coverage_eligible: false,
            owner: aggregate_owner,
            runner: "rch exec -- env CARGO_TARGET_DIR=<unique> cargo test -p frankenengine-engine --tests",
            emitted_event_schema: "rust-test-human-output",
            success_basis: "Named integration binaries exercise public or semi-public engine APIs.",
            exact_paths: &[],
            scan_roots: &[("crates/franken-engine/tests", ".rs", None, true)],
            exclusions: &[
                "crates/franken-engine/tests/execution_truth_ledger_integration.rs",
                "crates/franken-engine/tests/verification_coverage_contract_integration.rs",
            ],
            signals: &[],
            limitations: &[
                "The directory includes disabled, scaffold, static-contract, and production-executing tests; filename presence is not branch proof.",
                "A generic all-tests command cannot identify which claimed branch executed.",
            ],
            successor_bead: aggregate_owner,
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "franken-core-reference-tests",
            title: "franken-core unit and integration tests",
            purpose: "Exercise the second parser/lowering/interpreter lane as a parity-visible reference candidate.",
            execution_class: HarnessExecutionClass::TestOnly,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::PathSet,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.2.1",
            runner: "rch exec -- env CARGO_TARGET_DIR=<unique> cargo test -p frankenengine-core",
            emitted_event_schema: "rust-test-human-output",
            success_basis: "Real franken-core code executes, including its own InterpreterCore wrappers.",
            exact_paths: &[],
            scan_roots: &[
                ("crates/franken-core/src", ".rs", Some("#[test]"), true),
                ("crates/franken-core/tests", ".rs", None, true),
            ],
            exclusions: &[],
            signals: &[
                (
                    "crates/franken-core/src/baseline_interpreter.rs",
                    "QuickJsLane::execute",
                    "pub fn execute(",
                    "The lane wrapper constructs and executes a real InterpreterCore.",
                ),
            ],
            limitations: &[
                "Zero module families are formally graduated and semantic changes are still duplicated.",
                "QuickJsLane and V8Lane share one InterpreterCore, so agreement between them is not independent differential proof.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.7",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "extension-host-tests",
            title: "extension-host inline and integration tests",
            purpose: "Exercise manifest, capability, process, network, and host-effect policy surfaces.",
            execution_class: HarnessExecutionClass::TestOnly,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::PathSet,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.15",
            runner: "rch exec -- env CARGO_TARGET_DIR=<unique> cargo test -p frankenengine-extension-host",
            emitted_event_schema: "rust-test-human-output",
            success_basis: "Tests execute the real extension-host crate, including mock-free loopback/process cases where named.",
            exact_paths: &[],
            scan_roots: &[
                (
                    "crates/franken-extension-host/src",
                    ".rs",
                    Some("#[test]"),
                    true,
                ),
                ("crates/franken-extension-host/tests", ".rs", None, true),
            ],
            exclusions: &[],
            signals: &[],
            limitations: &[
                "The family mixes real host authority with fault doubles and must be selected by named scenario rather than wholesale.",
                "Guest/public CLI reachability is not implied by a crate test.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.15",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "criterion-benches",
            title: "Criterion benchmark targets",
            purpose: "Microbenchmark and denominator component measurements.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::PathSet,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.8",
            runner: "rch exec -- env CARGO_TARGET_DIR=<unique> cargo bench -p frankenengine-engine --bench <named-bench>",
            emitted_event_schema: "criterion-json-and-human-output",
            success_basis: "Named benches invoke production functions and record real timing samples.",
            exact_paths: &[],
            scan_roots: &[("crates/franken-engine/benches", ".rs", None, true)],
            exclusions: &[],
            signals: &[],
            limitations: &[
                "Criterion success does not establish benchmark fairness, equivalent Node/Bun work, production profiles, or a 30-process claim sample.",
                "Current perf CI is a relative regression gate, not an absolute bridge target gate.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.8",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "workspace-support-and-control-plane-tests",
            title: "support, derive, metamorphic, DP, and control-plane workspace tests",
            purpose: "Inventory test identities outside the three primary runtime crates so workspace-level verification cannot silently omit control-plane, proof, macro, or oracle support.",
            execution_class: HarnessExecutionClass::TestOnly,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::PathSet,
            current_coverage_eligible: false,
            owner: aggregate_owner,
            runner: "rch exec -- env CARGO_TARGET_DIR=<unique> cargo test --workspace",
            emitted_event_schema: "rust-test-human-output",
            success_basis: "Workspace tests execute the real support, macro, metamorphic, proof, and control-plane integration crates.",
            exact_paths: &[],
            scan_roots: &[
                ("crates/dp/src", ".rs", Some("#[test]"), true),
                ("crates/dp/tests", ".rs", None, true),
                (
                    "crates/franken-engine-control-plane-integration-tests/src",
                    ".rs",
                    Some("#[test]"),
                    true,
                ),
                (
                    "crates/franken-engine-control-plane-integration-tests/tests",
                    ".rs",
                    None,
                    true,
                ),
                (
                    "crates/franken-engine-deterministic-derive/src",
                    ".rs",
                    Some("#[test]"),
                    true,
                ),
                (
                    "crates/franken-engine-deterministic-derive/tests",
                    ".rs",
                    None,
                    true,
                ),
                (
                    "crates/franken-engine-deterministic-trait/src",
                    ".rs",
                    Some("#[test]"),
                    true,
                ),
                (
                    "crates/franken-engine-fixed-layout-derive/src",
                    ".rs",
                    Some("#[test]"),
                    true,
                ),
                (
                    "crates/franken-engine-fixed-layout-derive/tests",
                    ".rs",
                    None,
                    true,
                ),
                (
                    "crates/franken-engine-test-support/src",
                    ".rs",
                    Some("#[test]"),
                    true,
                ),
                (
                    "crates/franken-metamorphic/src",
                    ".rs",
                    Some("#[test]"),
                    true,
                ),
                ("crates/franken-metamorphic/tests", ".rs", None, false),
            ],
            exclusions: &[],
            signals: &[],
            limitations: &[
                "This is an exact normalized test-identity inventory, not proof that every workspace test reaches a shipped runtime branch.",
                "The aggregate verifier must retain per-package results and may not replace them with one workspace exit code.",
            ],
            successor_bead: aggregate_owner,
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "adversarial-fuzz-targets",
            title: "engine and extension-host fuzz targets",
            purpose: "Mutation-driven parser, IR, governance, host, and protocol fault discovery.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::PathSet,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.24",
            runner: "./scripts/run_fuzz_adversarial_targets.sh ci",
            emitted_event_schema: "franken-engine.fuzz-adversarial.legacy-v1",
            success_basis: "cargo-fuzz executes real target functions with generated bytes under a bounded runner.",
            exact_paths: &["scripts/run_fuzz_adversarial_targets.sh"],
            scan_roots: &[
                (
                    "crates/franken-engine/fuzz/fuzz_targets",
                    ".rs",
                    None,
                    true,
                ),
                (
                    "crates/franken-extension-host/fuzz/fuzz_targets",
                    ".rs",
                    None,
                    true,
                ),
            ],
            exclusions: &[],
            signals: &[
                (
                    "scripts/run_fuzz_adversarial_targets.sh",
                    "run_fuzz_targets",
                    "cargo fuzz run",
                    "The runner launches real libFuzzer targets rather than listing them.",
                ),
            ],
            limitations: &[
                "The active script enumerates only a subset of discovered fuzz targets.",
                "Its legacy manifest omits several unified event/resource/provenance fields.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.24",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "test262-release-runner",
            title: "Test262 ES2020 runner and release gate",
            purpose: "Execute the selected Test262 profile and record per-case outcomes and high-water marks.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.18",
            runner: "./scripts/run_test262_es2020_gate.sh ci",
            emitted_event_schema: "franken-engine.test262-gate.legacy-v2",
            success_basis: "The Rust runner parses case metadata and invokes current engine execution for selected cases.",
            exact_paths: &[
                "scripts/run_test262_es2020_gate.sh",
                "crates/franken-engine/src/test262_release_gate.rs",
                "crates/franken-engine/src/bin/franken_test262_runner.rs",
                "crates/franken-engine/tests/test262_release_gate.rs",
                "crates/franken-engine/tests/test262_es2020_profile.toml",
                "crates/franken-engine/tests/test262_conformance_pins.toml",
            ],
            scan_roots: &[],
            exclusions: &[],
            signals: &[
                (
                    "scripts/run_test262_es2020_gate.sh",
                    "run_test",
                    "franken_test262_runner",
                    "The public gate launches the real Rust Test262 runner.",
                ),
                (
                    "crates/franken-engine/src/bin/franken_test262_runner.rs",
                    "case execution",
                    "case_execution",
                    "The runner retains case-execution evidence.",
                ),
            ],
            limitations: &[
                "The currently published full result remains far below the ES2020 exit gate.",
                "Harness include/flag/realm/negative semantics require BRIDGE-12 recertification.",
                "The shell artifact schema is legacy and contains hand-rendered JSON.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.18",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "replay-coverage-gate",
            title: "deterministic replay coverage gate",
            purpose: "Measure declared high-severity decision/nondeterminism replay coverage.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.24",
            runner: "./scripts/run_replay_coverage_metric_gate.sh ci",
            emitted_event_schema: "franken-engine.replay-coverage.legacy-v1",
            success_basis: "The gate executes the real replay coverage metric and anti-fabrication checks.",
            exact_paths: &["scripts/run_replay_coverage_metric_gate.sh"],
            scan_roots: &[],
            exclusions: &[],
            signals: &[
                (
                    "scripts/run_replay_coverage_metric_gate.sh",
                    "metric runner",
                    "replay_coverage_metric_gate",
                    "A named Rust metric target is compiled and run.",
                ),
            ],
            limitations: &[
                "Coverage applies to the declared decision/nondeterminism path, not complete JavaScript re-execution.",
                "Legacy events need migration to the unified schema.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.24",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "security-conformance-gates",
            title: "security conformance and IFC release gates",
            purpose: "Exercise capability, IFC, policy, containment, and security-corpus paths.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.15",
            runner: "./scripts/run_security_conformance_runner.sh ci",
            emitted_event_schema: "franken-engine.security-conformance.legacy-v1",
            success_basis: "Named runners invoke real engine security paths and reject remote-build local fallback.",
            exact_paths: &[
                "scripts/run_security_conformance_runner.sh",
                "scripts/e2e/security_conformance_runner_replay.sh",
                "scripts/run_ifc_release_gate.sh",
                "scripts/e2e/ifc_release_gate_replay.sh",
            ],
            scan_roots: &[],
            exclusions: &[],
            signals: &[
                (
                    "scripts/run_security_conformance_runner.sh",
                    "strict remote execution",
                    "rch_reject_local_fallback",
                    "The runner refuses a hidden local fallback for heavy proof.",
                ),
                (
                    "scripts/run_ifc_release_gate.sh",
                    "IFC release gate",
                    "ifc",
                    "The public IFC gate invokes named current checks.",
                ),
            ],
            limitations: &[
                "Retry logic must retain every failed attempt before it can satisfy the unified contract.",
                "Known interpreter IFC soundness gaps prevent treating this family as a proof of per-flow soundness.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.15",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "red-team-metric-gate",
            title: "red-team compromise-rate harness",
            purpose: "Execute the paired attacker scenario corpus and compute the compromise-rate metric.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.15",
            runner: "./scripts/run_red_team_compromise_rate_metric_gate.sh ci",
            emitted_event_schema: "franken-engine.red-team.legacy-v1",
            success_basis: "The gate runs real paired JavaScript/manifest scenarios through the attacker harness.",
            exact_paths: &["scripts/run_red_team_compromise_rate_metric_gate.sh"],
            scan_roots: &[(
                "crates/franken-engine/tests/red_team_scenarios",
                "",
                None,
                true,
            )],
            exclusions: &[],
            signals: &[
                (
                    "scripts/run_red_team_compromise_rate_metric_gate.sh",
                    "scenario execution",
                    "red_team",
                    "The gate selects and runs the real scenario corpus.",
                ),
            ],
            limitations: &[
                "The result is evidence for the finite harness corpus, not field compromise data.",
                "Scenario and event schemas require unified migration.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.15",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "public-runtime-smokes",
            title: "live guardplane, IFC, and frankenctl workflow smokes",
            purpose: "Drive shipped public examples and CLI workflows for selected runtime/security paths.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.25",
            runner: "./scripts/e2e/frankenctl_cli_workflow.sh",
            emitted_event_schema: "mixed-shell-legacy",
            success_basis: "The scripts invoke built public binaries/examples and compare real outputs.",
            exact_paths: &[
                "scripts/e2e/live_guardplane_decision_smoke.sh",
                "scripts/e2e/live_ifc_declassification_smoke.sh",
                "scripts/e2e/frankenctl_cli_workflow.sh",
            ],
            scan_roots: &[],
            exclusions: &[],
            signals: &[
                (
                    "scripts/e2e/frankenctl_cli_workflow.sh",
                    "frankenctl",
                    "cargo run -q -p frankenengine-engine --bin frankenctl -- doctor",
                    "The workflow drives the shipped CLI binary.",
                ),
            ],
            limitations: &[
                "The scripts do not share one event/artifact schema.",
                "A smoke path is narrower than the bridge user-journey and failure matrix.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.25",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "metamorphic-and-lockstep",
            title: "metamorphic and lockstep oracle runners",
            purpose: "Compare transformed programs, reference outputs, and execution lanes for divergences.",
            execution_class: HarnessExecutionClass::TestOnly,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.24",
            runner: "./scripts/run_metamorphic_suite.sh ci",
            emitted_event_schema: "mixed-oracle-legacy",
            success_basis: "The metamorphic suite executes real transformations and current engine paths.",
            exact_paths: &[
                "scripts/run_metamorphic_suite.sh",
                "scripts/e2e/metamorphic_suite_replay.sh",
                "scripts/run_rgc_lockstep_oracle_pipeline.sh",
                "scripts/e2e/rgc_lockstep_oracle_pipeline_replay.sh",
            ],
            scan_roots: &[],
            exclusions: &[],
            signals: &[
                (
                    "scripts/run_metamorphic_suite.sh",
                    "metamorphic execution",
                    "cargo",
                    "The runner invokes a named metamorphic suite.",
                ),
            ],
            limitations: &[
                "The current FrankenCore differential backend has historically used an engine-shaped shim; it is not credited as an independent Tier-R oracle.",
                "The lockstep shell requires external `ts` and uses a legacy event shape.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.24",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "claim-matrix-gate",
            title: "claim-to-proof matrix gate",
            purpose: "Validate claim wording state, artifact presence, freshness, and ownership metadata.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.6",
            runner: "./scripts/run_claim_to_proof_matrix_gate.sh ci",
            emitted_event_schema: "franken-engine.claim-matrix.legacy-v1",
            success_basis: "The shell gate parses the live claim matrix and checks declared evidence.",
            exact_paths: &[
                "scripts/run_claim_to_proof_matrix_gate.sh",
                "docs/claim_to_proof_matrix_v1.json",
            ],
            scan_roots: &[],
            exclusions: &[],
            signals: &[
                (
                    "scripts/run_claim_to_proof_matrix_gate.sh",
                    "matrix validation",
                    "state_rank",
                    "The gate evaluates claim-state ordering rather than checking file existence alone.",
                ),
            ],
            limitations: &[
                "The gate is not wired into current CI workflows.",
                "It validates metadata/artifacts but does not live-rerun every claim producer.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.6",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "mock-and-scaffold-detectors",
            title: "mock inventory and ambient-mock guard",
            purpose: "Find and classify mocks, placeholders, and ambient test authority; inject mock fixtures as negative evidence.",
            execution_class: HarnessExecutionClass::MockOnly,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.6",
            runner: "./scripts/run_control_plane_mock_inventory.sh ci",
            emitted_event_schema: "franken-engine.mock-inventory.legacy-v1",
            success_basis: "Useful as a detector and fault injector only; a clean inventory cannot prove feature success.",
            exact_paths: &[
                "crates/franken-engine/src/control_plane_mock_inventory.rs",
                "scripts/run_control_plane_mock_inventory.sh",
                "scripts/run_ambient_mock_guard.sh",
                "scripts/e2e/control_plane_mock_inventory_replay.sh",
                "scripts/e2e/ambient_mock_guard_replay.sh",
            ],
            scan_roots: &[],
            exclusions: &[],
            signals: &[],
            limitations: &[
                "Mocks and static scans may provoke or locate a failure but cannot establish production behavior, equivalence, security, or performance.",
                "Legacy reports need unified event and provenance migration before composition.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.6",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "legacy-shell-e2e-inventory",
            title: "remaining shell E2E and replay scripts",
            purpose: "Complete path inventory of shell scenarios not individually recertified above.",
            execution_class: HarnessExecutionClass::TestOnly,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::PathSet,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.3",
            runner: "inventory-only: select one named script after branch and schema recertification",
            emitted_event_schema: "mixed-unrecertified-shell-formats",
            success_basis: "Conservatively treated as test-only until a named review demonstrates production reach and trusted signals.",
            exact_paths: &[],
            scan_roots: &[("scripts/e2e", ".sh", None, true)],
            exclusions: REVIEWED_E2E_PATHS,
            signals: &[],
            limitations: &[
                "The inventory includes static scans, replays, fixtures, mock-only drills, no-mock drills, and real public workflows; a path or success exit alone is not proof.",
                "Duplicate hand-built JSON/event formats are explicitly noncanonical.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.3",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "active-ci-workflows",
            title: "active GitHub Actions workflows",
            purpose: "Inventory current build, quality, fuzz, conformance, performance, and distribution automation.",
            execution_class: HarnessExecutionClass::ProductionExecuting,
            reuse_status: ReuseStatus::Conditional,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-performance-conformance-bridge-tu32j.22.25",
            runner: "github-actions: .github/workflows",
            emitted_event_schema: "github-actions-plus-mixed-artifacts",
            success_basis: "Committed workflow jobs invoke real Cargo and shell gates on GitHub runners.",
            exact_paths: &[],
            scan_roots: &[
                (".github/workflows", ".yml", None, true),
                (".github/workflows", ".yaml", None, true),
            ],
            exclusions: &[],
            signals: &[],
            limitations: &[
                "Current workflows omit the claim-matrix and new verification-coverage gates.",
                "Several actions use mutable `master` toolchain labels and legacy artifact schemas.",
            ],
            successor_bead: "bd-performance-conformance-bridge-tu32j.22.25",
        },
    )?);

    families.push(family_from_spec(
        repo_root,
        FamilySpec {
            family_id: "rgc-wildcard-coverage-matrix",
            title: "historical RGC verification coverage matrix",
            purpose: "Retained negative prior for coverage-contract migration.",
            execution_class: HarnessExecutionClass::Stale,
            reuse_status: ReuseStatus::Rejected,
            integrity_mode: IntegrityMode::ContentHash,
            current_coverage_eligible: false,
            owner: "bd-1lsy.11.1",
            runner: "./scripts/run_rgc_verification_coverage_matrix_gate.sh ci",
            emitted_event_schema: "rgc.verification-coverage-matrix.legacy-v1",
            success_basis: "Historical artifact only; it cannot establish current success.",
            exact_paths: &[
                "docs/rgc_verification_coverage_matrix_v1.json",
                "crates/franken-engine/tests/rgc_verification_coverage_matrix.rs",
                "scripts/run_rgc_verification_coverage_matrix_gate.sh",
                "scripts/e2e/rgc_verification_coverage_matrix_replay.sh",
            ],
            scan_roots: &[],
            exclusions: &[],
            signals: &[],
            limitations: &[
                "It snapshots 63 historical RGC issues and maps them through three wildcard rows.",
                "Its Rust and shell readers parse `br list --json` as a top-level array although current br returns an object with an `issues` array.",
                "Generic unit/integration/E2E Cargo commands do not prove a claimed branch.",
            ],
            successor_bead: OWNING_BEAD,
        },
    )?);

    families.sort_by(|left, right| left.family_id.cmp(&right.family_id));
    Ok(families)
}

fn family_from_spec(repo_root: &Path, spec: FamilySpec<'_>) -> Result<HarnessFamily, String> {
    let mut paths: BTreeSet<String> = spec
        .exact_paths
        .iter()
        .map(|path| (*path).to_string())
        .collect();
    for (root, suffix, marker, required) in spec.scan_roots {
        let scan_root = repo_root.join(root);
        if !scan_root.is_dir() {
            if *required {
                return Err(format!(
                    "{ERROR_SUBJECT_DRIFT}: required harness scan root {root} is missing"
                ));
            }
            continue;
        }
        for path in walk_regular_files(repo_root, &scan_root)? {
            if !suffix.is_empty() && !path.ends_with(suffix) {
                continue;
            }
            if let Some(marker) = marker {
                let bytes =
                    read_bounded_regular_file(&repo_root.join(&path), MAX_BUNDLE_FILE_BYTES)?;
                let contents = std::str::from_utf8(&bytes).map_err(|error| {
                    format!("{ERROR_JSON}: scanned harness {path} is not UTF-8: {error}")
                })?;
                if !contents.contains(marker) {
                    continue;
                }
            }
            paths.insert(path);
        }
    }
    for exclusion in spec.exclusions {
        paths.remove(*exclusion);
    }
    if paths.len() > MAX_HARNESS_MEMBERS {
        return Err(format!(
            "{ERROR_BOUNDS}: family {} has {} members, limit {MAX_HARNESS_MEMBERS}",
            spec.family_id,
            paths.len()
        ));
    }
    let mut members = Vec::with_capacity(paths.len());
    let mut inventory_identities = Vec::new();
    for path in paths {
        if !safe_relative_path(Path::new(&path)) {
            return Err(format!(
                "{ERROR_UNSAFE_PATH}: unsafe harness member path `{path}`"
            ));
        }
        let absolute = repo_root.join(&path);
        let bytes = read_bounded_regular_file(&absolute, MAX_BUNDLE_FILE_BYTES)?;
        if spec.integrity_mode == IntegrityMode::ContentHash {
            inventory_identities.push(format!("{path}\0{}\0{}", bytes.len(), sha256_hex(&bytes)));
        } else {
            inventory_identities.extend(normalized_harness_identities(&path, &bytes));
        }
        members.push(HarnessMember {
            path,
            sha256: (spec.integrity_mode == IntegrityMode::ContentHash).then(|| sha256_hex(&bytes)),
            bytes: if spec.integrity_mode == IntegrityMode::ContentHash {
                bytes.len() as u64
            } else {
                0
            },
        });
    }
    inventory_identities.sort();
    inventory_identities.dedup();
    let inventory_sha256 = sha256_hex(inventory_identities.join("\n").as_bytes());
    let source_inventory_signals = spec
        .signals
        .iter()
        .map(|(path, symbol, marker, interpretation)| BranchSignal {
            path: (*path).to_string(),
            symbol: (*symbol).to_string(),
            marker: (*marker).to_string(),
            interpretation: (*interpretation).to_string(),
        })
        .collect();
    Ok(HarnessFamily {
        family_id: spec.family_id.to_string(),
        title: spec.title.to_string(),
        purpose: spec.purpose.to_string(),
        execution_class: spec.execution_class,
        reuse_status: spec.reuse_status,
        integrity_mode: spec.integrity_mode,
        current_coverage_eligible: spec.current_coverage_eligible,
        owner: spec.owner.to_string(),
        runner: spec.runner.to_string(),
        emitted_event_schema: spec.emitted_event_schema.to_string(),
        success_basis: spec.success_basis.to_string(),
        source_inventory_signals,
        members,
        inventory_sha256,
        inventory_basis: match spec.integrity_mode {
            IntegrityMode::ContentHash => {
                "Sorted path, byte length, and SHA-256 identities for every required member."
                    .to_string()
            }
            IntegrityMode::PathSet => {
                "Sorted member paths plus normalized Rust test/function, fuzz/bench, and shell scenario identities; this detects adding or removing a test inside an unchanged file while avoiding a whole-file content claim."
                    .to_string()
            }
        },
        limitations: spec
            .limitations
            .iter()
            .map(|item| (*item).to_string())
            .collect(),
        successor_bead: spec.successor_bead.to_string(),
    })
}

fn normalized_harness_identities(path: &str, bytes: &[u8]) -> Vec<String> {
    let mut identities = vec![format!("path:{path}")];
    let Ok(text) = std::str::from_utf8(bytes) else {
        identities.push(format!("non_utf8_sha256:{}", sha256_hex(bytes)));
        return identities;
    };
    let is_rust = path.ends_with(".rs");
    let is_shell = path.ends_with(".sh");
    for line in text.lines() {
        let doc_test_identity = is_rust
            && line.trim_start().starts_with("///")
            && ["```", "assert", "should_panic", "compile_fail", "no_run"]
                .iter()
                .any(|marker| line.contains(marker));
        let normalized = line.split("//").next().unwrap_or(line).trim();
        if normalized.is_empty() && !doc_test_identity {
            continue;
        }
        let meaningful = if is_rust {
            normalized.contains("#[test")
                || normalized.contains("::test")
                || normalized.contains("#[rstest")
                || normalized.contains("#[test_case")
                || normalized.contains("#[case")
                || normalized.contains("#[bench")
                || normalized.contains("proptest!")
                || normalized.contains("fuzz_target!")
                || normalized.contains("criterion_group!")
                || normalized.contains("criterion_main!")
                || doc_test_identity
                || normalized
                    .split_whitespace()
                    .any(|token| token == "fn" || token == "fn(")
        } else if is_shell {
            normalized.ends_with("() {")
                || normalized.contains("scenario_id")
                || normalized.contains("test_id")
                || normalized.contains("case_id")
                || normalized.starts_with("run_case ")
                || normalized.starts_with("run_scenario ")
        } else {
            false
        };
        if meaningful {
            let identity = if doc_test_identity {
                line.trim()
            } else {
                normalized
            };
            identities.push(format!(
                "symbol:{}",
                identity.split_whitespace().collect::<Vec<_>>().join(" ")
            ));
        }
    }
    identities
}

fn walk_regular_files(repo_root: &Path, root: &Path) -> Result<Vec<String>, String> {
    let mut pending = vec![(root.to_path_buf(), 0usize)];
    let mut files = Vec::new();
    let mut directories = 0usize;
    while let Some((directory, depth)) = pending.pop() {
        directories = directories.saturating_add(1);
        if directories > MAX_HARNESS_SCAN_DIRECTORIES {
            return Err(format!(
                "{ERROR_BOUNDS}: harness scan exceeds {MAX_HARNESS_SCAN_DIRECTORIES} directories"
            ));
        }
        if depth > MAX_HARNESS_SCAN_DEPTH {
            return Err(format!(
                "{ERROR_BOUNDS}: harness scan depth {depth} exceeds {MAX_HARNESS_SCAN_DEPTH}"
            ));
        }
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("{ERROR_IO}: read {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!("{ERROR_IO}: read {} entry: {error}", directory.display())
            })?;
            let file_type = entry.file_type().map_err(|error| {
                format!("{ERROR_IO}: inspect {}: {error}", entry.path().display())
            })?;
            if file_type.is_symlink() {
                return Err(format!(
                    "{ERROR_UNSAFE_PATH}: harness inventory contains symlink {}",
                    entry.path().display()
                ));
            }
            if file_type.is_dir() {
                let name = entry.file_name();
                if matches!(name.to_str(), Some("target" | "artifacts" | ".git")) {
                    continue;
                }
                pending.push((entry.path(), depth.saturating_add(1)));
            } else if file_type.is_file() {
                let entry_path = entry.path();
                let relative = entry_path.strip_prefix(repo_root).map_err(|error| {
                    format!(
                        "{ERROR_UNSAFE_PATH}: {} is outside {}: {error}",
                        entry_path.display(),
                        repo_root.display()
                    )
                })?;
                files.push(relative.to_string_lossy().replace('\\', "/"));
                if files.len() > MAX_HARNESS_SCAN_FILES {
                    return Err(format!(
                        "{ERROR_BOUNDS}: harness scan exceeds {MAX_HARNESS_SCAN_FILES} files"
                    ));
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

fn build_coverage_rows(
    tasks: &[LiveIssue],
    all_bridge_issues: &[LiveIssue],
    claims: &[LiveClaim],
) -> Result<Vec<CoverageRow>, String> {
    let issue_index: BTreeMap<&str, &LiveIssue> = all_bridge_issues
        .iter()
        .map(|issue| (issue.id.as_str(), issue))
        .collect();
    let mut rows = Vec::with_capacity(tasks.len() + claims.len());
    let mut sorted_tasks = tasks.to_vec();
    sorted_tasks.sort_by(|left, right| left.id.cmp(&right.id));

    for task in &sorted_tasks {
        let owner = verification_owner_for_task(&task.id);
        let required_public_entrypoint = required_entrypoint_for_task(task, &owner, &issue_index);
        let combined = format!(
            "{} {} {} {}",
            task.title,
            task.description,
            task.acceptance_criteria,
            task.labels.join(" ")
        );
        let evidence_state = if task.status == "closed" {
            EvidenceState::HistoricalUnrecertified
        } else if task.id == OWNING_BEAD {
            EvidenceState::CandidateCurrentRun
        } else {
            EvidenceState::RequiredFuture
        };
        let current_runner_family_ids = match task.id.as_str() {
            "bd-performance-conformance-bridge-tu32j.1.1" => {
                vec!["execution-truth-ledger".to_string()]
            }
            OWNING_BEAD => vec!["verification-coverage-contract".to_string()],
            _ => Vec::new(),
        };
        let current_evidence = match task.id.as_str() {
            "bd-performance-conformance-bridge-tu32j.1.1" => vec![
                "closed tracker record is historical only".to_string(),
                "scripts/run_execution_truth_ledger_gate.sh".to_string(),
                "scripts/e2e/execution_truth_ledger_smoke.sh".to_string(),
            ],
            OWNING_BEAD => vec![
                "candidate requires the current gate bundle and public E2E in this run".to_string(),
            ],
            _ => Vec::new(),
        };
        let gap_reason = match evidence_state {
            EvidenceState::CandidateCurrentRun => "The implementation and named public gate exist in this change, but only the current executed bundle may establish closure; self-declaration in this row is insufficient.".to_string(),
            EvidenceState::HistoricalUnrecertified => "The task is closed in historical tracker state, but the owning independent BRIDGE-21 pack has not recertified it under this contract.".to_string(),
            EvidenceState::RequiredFuture => format!(
                "The task remains {}; its exact runner, branch signals, and complete current artifact bundle are required future evidence.",
                task.status
            ),
            _ => unreachable!("task rows use only task evidence states"),
        };
        rows.push(CoverageRow {
            row_id: format!("task:{}", task.id),
            subject_id: task.id.clone(),
            subject_kind: SubjectKind::BridgeTask,
            title: task.title.clone(),
            authority_state: task.status.clone(),
            evidence_state,
            independent_owner: owner.clone(),
            required_verification_packs: vec![owner],
            required_public_entrypoint,
            required_layers: required_layers(&combined),
            required_platforms: required_platforms(&combined),
            required_tiers: required_tiers(&combined),
            required_security_profiles: required_security_profiles(&combined),
            current_runner_family_ids,
            current_evidence,
            gap_reason,
        });
    }

    let mut sorted_claims = claims.to_vec();
    sorted_claims.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
    for claim in &sorted_claims {
        let (owner, required_verification_packs) = verification_plan_for_claim(&claim.claim_id)?;
        let owner_issue = issue_index.get(owner.as_str()).copied();
        let required_public_entrypoint = owner_issue
            .and_then(|issue| extract_e2e_entrypoint(&issue.description))
            .unwrap_or_else(|| default_entrypoint_for_owner(&owner));
        let evidence_state = match claim.allowed_state.as_str() {
            "target" => EvidenceState::TargetUnproven,
            "hypothesis" => EvidenceState::HypothesisUnimplemented,
            _ => EvidenceState::HistoricalUnrecertified,
        };
        let combined = format!(
            "{} {} {} {}",
            claim.claim_text, claim.claim_scope, claim.allowed_state, claim.verification_command
        );
        let current_runner_family_ids =
            classify_claim_runner(&claim.verification_command, &claim.claim_scope);
        let current_evidence = claim
            .artifact_path
            .iter()
            .map(|path| format!("historical declared artifact: {path}"))
            .collect();
        let gap_reason = match evidence_state {
            EvidenceState::TargetUnproven => {
                "The public matrix explicitly labels this claim TARGET; a runner or artifact cannot promote it without satisfying the independent pack and claim gate.".to_string()
            }
            EvidenceState::HypothesisUnimplemented => {
                "The public matrix explicitly labels this claim HYPOTHESIS; TBD, simulated, string-matched, or input-only evidence is not implementation proof.".to_string()
            }
            EvidenceState::HistoricalUnrecertified => {
                "The public matrix says OBSERVED, but this bridge treats the prior owner, command, and artifact as historical inputs until a current independent pack reaches the claimed branch.".to_string()
            }
            _ => unreachable!("claim rows use only claim evidence states"),
        };
        rows.push(CoverageRow {
            row_id: format!("claim:{}", claim.claim_id),
            subject_id: claim.claim_id.clone(),
            subject_kind: SubjectKind::Claim,
            title: claim.claim_text.clone(),
            authority_state: claim.actual_wording_state.clone(),
            evidence_state,
            independent_owner: owner,
            required_verification_packs,
            required_public_entrypoint,
            required_layers: required_layers(&combined),
            required_platforms: required_platforms(&combined),
            required_tiers: required_tiers(&combined),
            required_security_profiles: required_security_profiles(&combined),
            current_runner_family_ids,
            current_evidence,
            gap_reason,
        });
    }

    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(rows)
}

fn verification_owner_for_task(task_id: &str) -> String {
    if task_id == "bd-performance-conformance-bridge-tu32j.15.8" {
        return "bd-performance-conformance-bridge-tu32j.22.29".to_string();
    }
    if task_id == "bd-performance-conformance-bridge-tu32j.22.27" {
        return "bd-performance-conformance-bridge-tu32j.22.30".to_string();
    }
    if task_id == "bd-performance-conformance-bridge-tu32j.22.30" {
        return "bd-performance-conformance-bridge-tu32j.20.6".to_string();
    }
    if matches!(
        task_id,
        "bd-performance-conformance-bridge-tu32j.22.28"
            | "bd-performance-conformance-bridge-tu32j.22.29"
            | "bd-performance-conformance-bridge-tu32j.22.31"
            | "bd-performance-conformance-bridge-tu32j.22.32"
    ) {
        return "bd-performance-conformance-bridge-tu32j.22.30".to_string();
    }
    let suffix = task_id
        .strip_prefix(&format!("{BRIDGE_ROOT}."))
        .unwrap_or_default();
    let workstream = suffix
        .split('.')
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or(0);
    match workstream {
        1..=21 => format!(
            "bd-performance-conformance-bridge-tu32j.22.{}",
            workstream + 5
        ),
        22 => "bd-performance-conformance-bridge-tu32j.22.30".to_string(),
        23 => "bd-performance-conformance-bridge-tu32j.22.28".to_string(),
        24 => "bd-performance-conformance-bridge-tu32j.22.31".to_string(),
        25 => "bd-performance-conformance-bridge-tu32j.22.32".to_string(),
        _ => "bd-performance-conformance-bridge-tu32j.22.27".to_string(),
    }
}

fn verification_plan_for_claim(claim_id: &str) -> Result<(String, Vec<String>), String> {
    let (primary, contributors): (&str, &[&str]) = match claim_id {
        "FE-CLAIM-001" => ("22.7", &["22.7", "22.15", "22.24", "22.25", "22.31"]),
        "FE-CLAIM-002" => ("22.15", &["22.15"]),
        "FE-CLAIM-003" => ("22.24", &["22.15", "22.24"]),
        "FE-CLAIM-004" => ("22.15", &["22.15", "22.25"]),
        "FE-CLAIM-004-TEE" => ("22.32", &["22.15", "22.16", "22.17", "22.25", "22.32"]),
        "FE-CLAIM-005" => ("22.31", &["22.15", "22.25", "22.31"]),
        "FE-CLAIM-006" => ("22.15", &["22.7", "22.15", "22.24"]),
        "FE-CLAIM-TEST262" => (
            "22.18",
            &[
                "22.18", "22.19", "22.20", "22.21", "22.22", "22.23", "22.28",
            ],
        ),
        "FE-CLAIM-007" => ("22.25", &["22.7", "22.25"]),
        "FE-CLAIM-008" => ("22.6", &["22.6", "22.25"]),
        "FE-CLAIM-009" => ("22.6", &["22.6", "22.25"]),
        "FE-CLAIM-010" => ("22.8", &["22.8", "22.24", "22.25"]),
        "FE-CLAIM-011" => ("22.15", &["22.15", "22.25"]),
        "FE-CLAIM-012" => ("22.15", &["22.8", "22.15", "22.25"]),
        "FE-CLAIM-013" => ("22.24", &["22.15", "22.24"]),
        "FE-CLAIM-014" => ("22.6", &["22.6", "22.15", "22.24", "22.25"]),
        "FE-CLAIM-015" => ("22.15", &["22.15", "22.24"]),
        "FE-CLAIM-016" => ("22.26", &["22.15", "22.25", "22.26"]),
        "FE-CLAIM-017" => ("22.26", &["22.7", "22.24", "22.26"]),
        "FE-CLAIM-018" => ("22.26", &["22.15", "22.26"]),
        "FE-CLAIM-019" => (
            "22.26",
            &[
                "22.10", "22.11", "22.12", "22.13", "22.14", "22.24", "22.26",
            ],
        ),
        "FE-CLAIM-020" => ("22.26", &["22.15", "22.24", "22.26"]),
        "FE-CLAIM-021" => ("22.26", &["22.15", "22.26"]),
        "FE-CLAIM-022" => ("22.24", &["22.24", "22.25"]),
        "FE-CLAIM-023" => ("22.25", &["22.16", "22.17", "22.25"]),
        "FE-CLAIM-024" => ("22.25", &["22.25"]),
        "FE-CLAIM-025" => ("22.6", &["22.6", "22.25", "22.30"]),
        "FE-CLAIM-026" => (
            "22.18",
            &[
                "22.18", "22.19", "22.20", "22.21", "22.22", "22.23", "22.25", "22.28",
            ],
        ),
        unknown => {
            return Err(format!(
                "{ERROR_OWNER}: claim {unknown} has no reviewed primary and contributor verification-pack mapping"
            ));
        }
    };
    let qualify = |suffix: &str| format!("{BRIDGE_ROOT}.{suffix}");
    let mut required: Vec<String> = contributors.iter().map(|suffix| qualify(suffix)).collect();
    required.sort();
    required.dedup();
    Ok((qualify(primary), required))
}

fn required_entrypoint_for_task(
    task: &LiveIssue,
    owner: &str,
    issue_index: &BTreeMap<&str, &LiveIssue>,
) -> String {
    if task.id == OWNING_BEAD {
        return "scripts/e2e/verification_coverage_contract_smoke.sh".to_string();
    }
    extract_e2e_entrypoint(&format!(
        "{}\n{}",
        task.description, task.acceptance_criteria
    ))
    .or_else(|| {
        issue_index.get(owner).and_then(|issue| {
            extract_e2e_entrypoint(&format!(
                "{}\n{}",
                issue.description, issue.acceptance_criteria
            ))
        })
    })
    .unwrap_or_else(|| default_entrypoint_for_owner(owner))
}

fn extract_e2e_entrypoint(description: &str) -> Option<String> {
    let tail = ["E2E SCRIPT:", "PUBLIC E2E:"]
        .iter()
        .find_map(|marker| description.split_once(marker).map(|(_, tail)| tail))?
        .trim_start();
    let token = tail
        .split_whitespace()
        .next()?
        .trim_matches(|character| matches!(character, '`' | '"' | '\'' | '('));
    let token = token.trim_end_matches(|character: char| {
        matches!(character, '`' | '"' | '\'' | ')' | ',' | ';' | '.')
    });
    token.starts_with("scripts/").then(|| token.to_string())
}

fn default_entrypoint_for_owner(owner: &str) -> String {
    match owner {
        "bd-performance-conformance-bridge-tu32j.22.27" => {
            "scripts/bridge/run_bridge_21_clean_room_e2e.sh".to_string()
        }
        "bd-performance-conformance-bridge-tu32j.20.3" => {
            "scripts/bridge/run_bridge_19_neutral_verifier_e2e.sh".to_string()
        }
        _ => format!("scripts/bridge/{}.sh", owner.replace(['.', '-'], "_")),
    }
}

fn classify_claim_runner(command: &str, scope: &str) -> Vec<String> {
    let command = command.to_ascii_lowercase();
    if command.contains("test262") {
        vec!["test262-release-runner".to_string()]
    } else if command.contains("red_team") || command.contains("red-team") {
        vec!["red-team-metric-gate".to_string()]
    } else if command.contains("replay_coverage") {
        vec!["replay-coverage-gate".to_string()]
    } else if command.contains("ifc") || command.contains("security_conformance") {
        vec!["security-conformance-gates".to_string()]
    } else if command.contains("claim_to_proof") {
        vec!["claim-matrix-gate".to_string()]
    } else if command.contains("live_guardplane")
        || command.contains("live_ifc")
        || command.contains("frankenctl")
    {
        vec!["public-runtime-smokes".to_string()]
    } else if command.contains("lockstep") || command.contains("metamorphic") {
        vec!["metamorphic-and-lockstep".to_string()]
    } else if scope == "performance" {
        vec!["criterion-benches".to_string()]
    } else {
        Vec::new()
    }
}

fn required_layers(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut layers: BTreeSet<String> = [
        "unit".to_string(),
        "property".to_string(),
        "golden".to_string(),
        "mutation".to_string(),
        "canonical_integration".to_string(),
        "public_e2e".to_string(),
        "production_branch_signal".to_string(),
        "tier_r_differential".to_string(),
        "replay".to_string(),
        "fault_recovery".to_string(),
        "artifact_integrity".to_string(),
        "redaction".to_string(),
    ]
    .into_iter()
    .collect();
    for (needles, layer) in [
        (
            &[
                "performance",
                "benchmark",
                "profil",
                "statistics",
                "latency",
            ][..],
            "performance_statistics",
        ),
        (
            &["security", "ifc", "capability", "guardplane", "evidence"][..],
            "security_profiles",
        ),
        (
            &[
                "conformance",
                "test262",
                "builtin",
                "language",
                "regexp",
                "annex",
            ][..],
            "conformance_oracle",
        ),
        (
            &["fuzz", "metamorphic", "differential", "translation"][..],
            "fuzz_metamorphic",
        ),
        (
            &["apple", "amd", "numa", "cross-platform", "architecture"][..],
            "cross_platform",
        ),
        (
            &["jit", "tier-i", "tier-b", "tier-o", "tier-a", "native"][..],
            "cross_tier_deopt",
        ),
        (
            &["research", "paper", "sota", "alien"][..],
            "research_reproduction",
        ),
    ] {
        if needles.iter().any(|needle| lower.contains(needle)) {
            layers.insert(layer.to_string());
        }
    }
    layers.into_iter().collect()
}

fn required_platforms(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut platforms = BTreeSet::from(["generic-linux-x86_64".to_string()]);
    if lower.contains("apple") || lower.contains("m4") || lower.contains("m5") {
        platforms.insert("apple-m4-aarch64".to_string());
        platforms.insert("apple-m5-aarch64-when-available".to_string());
    }
    if lower.contains("amd")
        || lower.contains("zen")
        || lower.contains("threadripper")
        || lower.contains("epyc")
        || lower.contains("numa")
    {
        platforms.insert("amd-zen5-x86_64".to_string());
        platforms.insert("high-core-numa-linux-x86_64".to_string());
    }
    if lower.contains("cross-platform") || lower.contains("reproduc") {
        platforms.insert("generic-macos-aarch64".to_string());
        platforms.insert("portable-no-jit".to_string());
        platforms.insert("windows-x86_64-msvc".to_string());
    }
    if lower.contains("windows") || lower.contains("msvc") {
        platforms.insert("windows-x86_64-msvc".to_string());
    }
    if lower.contains("sev-snp") {
        platforms.insert("amd-sev-snp-real-hardware".to_string());
    }
    if lower.contains("tdx") {
        platforms.insert("intel-tdx-real-hardware".to_string());
    }
    if lower.contains("fleet")
        || lower.contains("multi-host")
        || lower.contains("distributed")
        || lower.contains("fault domain")
    {
        platforms.insert("multi-process-local".to_string());
        platforms.insert("two-physical-host-two-fault-domain".to_string());
    }
    platforms.into_iter().collect()
}

fn required_tiers(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut tiers = BTreeSet::from(["tier-r".to_string()]);
    for (needle, tier) in [
        ("tier-i", "tier-i"),
        ("tier i", "tier-i"),
        ("tier-b", "tier-b"),
        ("tier b", "tier-b"),
        ("tier-o", "tier-o"),
        ("tier o", "tier-o"),
        ("tier-a", "tier-a"),
        ("tier a", "tier-a"),
        ("jit", "compiled-tier"),
        ("aot", "tier-a"),
    ] {
        if lower.contains(needle) {
            tiers.insert(tier.to_string());
        }
    }
    tiers.into_iter().collect()
}

fn required_security_profiles(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut profiles = BTreeSet::from(["security-off".to_string(), "full-containment".to_string()]);
    if [
        "security",
        "ifc",
        "capability",
        "guardplane",
        "evidence",
        "policy",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        profiles.insert("guardplane-on".to_string());
        profiles.insert("ifc-on".to_string());
        profiles.insert("evidence-on".to_string());
    }
    profiles.into_iter().collect()
}

fn build_provenance_edges(
    tasks: &[LiveIssue],
    claims: &[LiveClaim],
) -> Result<Vec<ProvenanceEdge>, String> {
    let mut edges = Vec::with_capacity((tasks.len() + claims.len()) * 4);
    for task in tasks {
        let subject = format!("task:{}", task.id);
        edges.push(ProvenanceEdge {
            from: subject.clone(),
            relation: "independently_verified_by".to_string(),
            to: verification_owner_for_task(&task.id),
        });
        edges.push(ProvenanceEdge {
            from: subject.clone(),
            relation: "emits".to_string(),
            to: EVENT_SCHEMA_VERSION.to_string(),
        });
        edges.push(ProvenanceEdge {
            from: subject,
            relation: "retains".to_string(),
            to: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        });
    }
    for claim in claims {
        let subject = format!("claim:{}", claim.claim_id);
        let (primary, contributors) = verification_plan_for_claim(&claim.claim_id)?;
        edges.push(ProvenanceEdge {
            from: subject.clone(),
            relation: "primary_independent_verifier".to_string(),
            to: primary,
        });
        for contributor in contributors {
            edges.push(ProvenanceEdge {
                from: subject.clone(),
                relation: "requires_verification_pack".to_string(),
                to: contributor,
            });
        }
        edges.push(ProvenanceEdge {
            from: subject.clone(),
            relation: "declared_in".to_string(),
            to: "docs/claim_to_proof_matrix_v1.json".to_string(),
        });
        edges.push(ProvenanceEdge {
            from: subject,
            relation: "requires_event_schema".to_string(),
            to: EVENT_SCHEMA_VERSION.to_string(),
        });
    }
    edges.sort_by(|left, right| {
        (&left.from, &left.relation, &left.to).cmp(&(&right.from, &right.relation, &right.to))
    });
    edges.dedup();
    Ok(edges)
}

struct Validator<'a> {
    repo_root: &'a Path,
    contract_path: &'a Path,
    context: &'a ValidationContext,
    contract_sha256: String,
    generated_contract_sha256: String,
    source_cutoff: String,
    bridge_task_count: usize,
    claim_count: usize,
    coverage_row_count: usize,
    harness_family_count: usize,
    harness_member_count: usize,
    checks_run: usize,
    sequence: u64,
    findings: Vec<ValidationFinding>,
    events: Vec<VerificationEvent>,
}

impl<'a> Validator<'a> {
    fn new(repo_root: &'a Path, contract_path: &'a Path, context: &'a ValidationContext) -> Self {
        let mut validator = Self {
            repo_root,
            contract_path,
            context,
            contract_sha256: String::new(),
            generated_contract_sha256: String::new(),
            source_cutoff: "unknown".to_string(),
            bridge_task_count: 0,
            claim_count: 0,
            coverage_row_count: 0,
            harness_family_count: 0,
            harness_member_count: 0,
            checks_run: 0,
            sequence: 0,
            findings: Vec::new(),
            events: Vec::new(),
        };
        validator.sequence = 1;
        validator.events.push(VerificationEvent {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            run_id: context.run_id.clone(),
            trace_id: context.trace_id.clone(),
            test_id: context.test_id.clone(),
            scenario_id: context.scenario_id.clone(),
            seed: context.seed,
            attempt: context.attempt,
            platform: context.platform.clone(),
            target: context.target.clone(),
            tier: context.tier.clone(),
            security_profile: context.security_profile.clone(),
            phase: "initialize".to_string(),
            sequence: validator.sequence,
            event: "run_started".to_string(),
            decision: "pass".to_string(),
            reason_code: "FE-VCC-0000".to_string(),
            reason: "verification coverage validation started".to_string(),
            error_class: None,
            fallback: "none".to_string(),
            rollback: "prior-valid-contract-preserved".to_string(),
            duration_ns: 0,
            resource_delta: ResourceDelta::validation_sample(0),
            artifact_hashes: BTreeMap::new(),
        });
        validator
    }

    fn check(
        &mut self,
        phase: &str,
        subject_id: Option<&str>,
        family_id: Option<&str>,
        outcome: Result<String, (&'static str, String)>,
        started: Instant,
        artifact_hashes: BTreeMap<String, String>,
    ) {
        self.checks_run += 1;
        self.sequence += 1;
        let duration_ns = started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        let (decision, reason_code, reason, error_class) = match outcome {
            Ok(reason) => ("pass".to_string(), "FE-VCC-0000".to_string(), reason, None),
            Err((code, reason)) => {
                let bounded = bounded_redacted(&reason, self.repo_root);
                self.findings.push(ValidationFinding {
                    error_code: code.to_string(),
                    phase: phase.to_string(),
                    reason: bounded.clone(),
                    subject_id: subject_id.map(str::to_string),
                    family_id: family_id.map(str::to_string),
                });
                (
                    "fail".to_string(),
                    code.to_string(),
                    bounded,
                    Some(error_class_for(code).to_string()),
                )
            }
        };
        self.events.push(VerificationEvent {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            run_id: self.context.run_id.clone(),
            trace_id: self.context.trace_id.clone(),
            test_id: self.context.test_id.clone(),
            scenario_id: self.context.scenario_id.clone(),
            seed: self.context.seed,
            attempt: self.context.attempt,
            platform: self.context.platform.clone(),
            target: self.context.target.clone(),
            tier: self.context.tier.clone(),
            security_profile: self.context.security_profile.clone(),
            phase: phase.to_string(),
            sequence: self.sequence,
            event: "contract_check".to_string(),
            decision,
            reason_code,
            reason: bounded_redacted(&reason, self.repo_root),
            error_class,
            fallback: "none".to_string(),
            rollback: "prior-valid-contract-preserved".to_string(),
            duration_ns,
            resource_delta: ResourceDelta::validation_sample(duration_ns),
            artifact_hashes,
        });
    }

    fn finish(mut self) -> ValidationOutput {
        self.sequence += 1;
        let initial_error_count = self.findings.len();
        self.events.push(VerificationEvent {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            run_id: self.context.run_id.clone(),
            trace_id: self.context.trace_id.clone(),
            test_id: self.context.test_id.clone(),
            scenario_id: self.context.scenario_id.clone(),
            seed: self.context.seed,
            attempt: self.context.attempt,
            platform: self.context.platform.clone(),
            target: self.context.target.clone(),
            tier: self.context.tier.clone(),
            security_profile: self.context.security_profile.clone(),
            phase: "finalize".to_string(),
            sequence: self.sequence,
            event: "run_completed".to_string(),
            decision: if initial_error_count == 0 {
                "pass"
            } else {
                "fail"
            }
            .to_string(),
            reason_code: if initial_error_count == 0 {
                "FE-VCC-0000"
            } else {
                "FE-VCC-1099"
            }
            .to_string(),
            reason: if initial_error_count == 0 {
                format!(
                    "coverage contract passed {} checks for {} exact rows",
                    self.checks_run, self.coverage_row_count
                )
            } else {
                format!(
                    "coverage contract failed with {initial_error_count} typed finding(s); first failure retained"
                )
            },
            error_class: (initial_error_count != 0).then(|| "validation_failure".to_string()),
            fallback: "none".to_string(),
            rollback: "prior-valid-contract-preserved".to_string(),
            duration_ns: 0,
            resource_delta: ResourceDelta::validation_sample(0),
            artifact_hashes: [
                ("contract.json", &self.contract_sha256),
                ("generated_contract.json", &self.generated_contract_sha256),
            ]
            .into_iter()
            .filter(|(_, hash)| is_sha256(hash))
            .map(|(name, hash)| (name.to_string(), hash.clone()))
            .collect(),
        });
        let mut event_bytes = Vec::new();
        for event in &self.events {
            if serde_json::to_writer(&mut event_bytes, event).is_ok() {
                event_bytes.push(b'\n');
            }
        }
        let event_report = validate_event_stream(&event_bytes);
        if event_report.error_count != 0 {
            let first_event_failure = event_report
                .findings
                .first()
                .map(|finding| {
                    bounded_redacted(
                        &format!(
                            "generated event stream violated {}: {}",
                            finding.error_code, finding.reason
                        ),
                        self.repo_root,
                    )
                })
                .unwrap_or_else(|| "generated event stream failed self-validation".to_string());
            for finding in event_report.findings {
                self.findings.push(ValidationFinding {
                    error_code: ERROR_EVENT_SCHEMA.to_string(),
                    phase: "events.self_validate".to_string(),
                    reason: bounded_redacted(
                        &format!(
                            "generated event stream violated {}: {}",
                            finding.error_code, finding.reason
                        ),
                        self.repo_root,
                    ),
                    subject_id: None,
                    family_id: None,
                });
            }
            if let Some(mut terminal) = self.events.pop() {
                let failure_sequence = terminal.sequence;
                let mut failure_event = terminal.clone();
                failure_event.phase = "events.self_validate".to_string();
                failure_event.sequence = failure_sequence;
                failure_event.event = "contract_check".to_string();
                failure_event.decision = "fail".to_string();
                failure_event.reason_code = ERROR_EVENT_SCHEMA.to_string();
                failure_event.reason = first_event_failure;
                failure_event.error_class = Some("schema".to_string());
                failure_event.duration_ns = 0;
                failure_event.resource_delta = ResourceDelta::validation_sample(0);
                failure_event.artifact_hashes.clear();
                self.events.push(failure_event);
                terminal.sequence = failure_sequence.saturating_add(1);
                terminal.decision = "fail".to_string();
                terminal.reason_code = "FE-VCC-1099".to_string();
                terminal.reason =
                    "generated event stream failed self-validation; first failure retained"
                        .to_string();
                terminal.error_class = Some("validation_failure".to_string());
                self.events.push(terminal);
            }
        }
        let error_count = self.findings.len();
        ValidationOutput {
            report: ValidationReport {
                schema_version: REPORT_SCHEMA_VERSION.to_string(),
                contract_path: path_for_report(self.repo_root, self.contract_path),
                contract_sha256: self.contract_sha256,
                generated_contract_sha256: self.generated_contract_sha256,
                source_cutoff_utc: self.source_cutoff,
                as_of_utc: self.context.as_of_utc.to_rfc3339(),
                certifying_clock: self.context.certifying_clock,
                status: if error_count == 0 { "pass" } else { "fail" }.to_string(),
                bridge_task_count: self.bridge_task_count,
                claim_count: self.claim_count,
                coverage_row_count: self.coverage_row_count,
                harness_family_count: self.harness_family_count,
                harness_member_count: self.harness_member_count,
                checks_run: self.checks_run,
                error_count,
                findings: self.findings,
            },
            events: self.events,
        }
    }
}

/// Validate the committed contract against live tracker, claim, source, and
/// harness state while always returning a structured failure report.
#[must_use]
pub fn validate_contract_file(
    repo_root: &Path,
    contract_path: &Path,
    context: &ValidationContext,
) -> ValidationOutput {
    let mut validator = Validator::new(repo_root, contract_path, context);
    let started = Instant::now();
    let bytes = match read_bounded_regular_file(contract_path, MAX_CONTRACT_BYTES) {
        Ok(bytes) => bytes,
        Err(reason) => {
            let code = file_error_code(&reason);
            validator.check(
                "contract.read",
                None,
                None,
                Err((code, reason)),
                started,
                BTreeMap::new(),
            );
            return validator.finish();
        }
    };
    validator.contract_sha256 = sha256_hex(&bytes);
    let contract: VerificationCoverageContract = match serde_json::from_slice(&bytes) {
        Ok(contract) => contract,
        Err(error) => {
            validator.check(
                "contract.parse",
                None,
                None,
                Err((
                    ERROR_JSON,
                    format!("parse {}: {error}", contract_path.display()),
                )),
                started,
                BTreeMap::from([(
                    "contract.json".to_string(),
                    validator.contract_sha256.clone(),
                )]),
            );
            return validator.finish();
        }
    };
    validator.source_cutoff = contract.source_cutoff_utc.clone();
    validator.coverage_row_count = contract.coverage_rows.len();
    validator.harness_family_count = contract.harness_families.len();
    validator.harness_member_count = contract
        .harness_families
        .iter()
        .map(|family| family.members.len())
        .sum();
    validator.bridge_task_count = contract
        .coverage_rows
        .iter()
        .filter(|row| row.subject_kind == SubjectKind::BridgeTask)
        .count();
    validator.claim_count = contract
        .coverage_rows
        .iter()
        .filter(|row| row.subject_kind == SubjectKind::Claim)
        .count();
    validator.check(
        "contract.parse",
        None,
        None,
        Ok(format!("parsed {} bytes under strict schema", bytes.len())),
        started,
        BTreeMap::from([(
            "contract.json".to_string(),
            validator.contract_sha256.clone(),
        )]),
    );

    let generated_started = Instant::now();
    let generated = match generate_contract(repo_root) {
        Ok(generated) => generated,
        Err(reason) => {
            validator.check(
                "contract.generate",
                None,
                None,
                Err((ERROR_GENERATION_DRIFT, reason)),
                generated_started,
                BTreeMap::new(),
            );
            return validator.finish();
        }
    };
    let generated_bytes = match canonical_json_bytes(&generated) {
        Ok(bytes) => bytes,
        Err(reason) => {
            validator.check(
                "contract.generate.serialize",
                None,
                None,
                Err((ERROR_JSON, reason)),
                generated_started,
                BTreeMap::new(),
            );
            return validator.finish();
        }
    };
    validator.generated_contract_sha256 = sha256_hex(&generated_bytes);
    validator.check(
        "contract.generate",
        None,
        None,
        Ok(format!(
            "regenerated {} task/claim rows from live authorities",
            generated.coverage_rows.len()
        )),
        generated_started,
        BTreeMap::from([(
            "generated_contract.json".to_string(),
            validator.generated_contract_sha256.clone(),
        )]),
    );

    validate_contract_structure(&contract, &generated, &mut validator);
    validate_authorities(&contract, &generated, &mut validator);
    validate_families(&contract, &mut validator);
    validate_coverage_rows(&contract, &generated, &mut validator);
    validate_integrations(&contract, &mut validator);
    validate_freshness(&contract, &mut validator);
    validate_generation_projection(&contract, &generated, &mut validator);
    validate_markdown(&contract, &mut validator);
    validator.finish()
}

fn validate_contract_structure(
    contract: &VerificationCoverageContract,
    generated: &VerificationCoverageContract,
    validator: &mut Validator<'_>,
) {
    let started = Instant::now();
    let outcome = if contract.schema_version != CONTRACT_SCHEMA_VERSION {
        Err((
            ERROR_SCHEMA,
            format!(
                "schema {} does not equal {CONTRACT_SCHEMA_VERSION}",
                contract.schema_version
            ),
        ))
    } else if contract.owning_bead != OWNING_BEAD {
        Err((
            ERROR_OWNER,
            format!(
                "owning bead {} does not equal {OWNING_BEAD}",
                contract.owning_bead
            ),
        ))
    } else if contract.rendered_markdown_path != RENDERED_MARKDOWN_PATH {
        Err((
            ERROR_SCHEMA,
            format!(
                "rendered path {} does not equal {RENDERED_MARKDOWN_PATH}",
                contract.rendered_markdown_path
            ),
        ))
    } else if contract.coverage_rows.len() > MAX_COVERAGE_ROWS {
        Err((
            ERROR_BOUNDS,
            format!(
                "{} coverage rows exceed limit {MAX_COVERAGE_ROWS}",
                contract.coverage_rows.len()
            ),
        ))
    } else if contract.event_contract.required_fields
        != REQUIRED_EVENT_FIELDS
            .iter()
            .map(|field| (*field).to_string())
            .collect::<Vec<_>>()
    {
        Err((
            ERROR_EVENT_SCHEMA,
            "required event field list is missing, reordered, or expanded without migration"
                .to_string(),
        ))
    } else if contract.artifact_contract.required_files
        != REQUIRED_ARTIFACT_FILES
            .iter()
            .map(|path| (*path).to_string())
            .collect::<Vec<_>>()
    {
        Err((
            ERROR_ARTIFACT_CONTRACT,
            "required artifact file list is missing, reordered, or changed without migration"
                .to_string(),
        ))
    } else if contract.classification_definitions != generated.classification_definitions {
        Err((
            ERROR_CLASSIFICATION,
            "classification definitions drifted from the canonical generator".to_string(),
        ))
    } else {
        Ok(format!(
            "schema, owner, bounds, {} event fields, and {} artifact files are canonical",
            contract.event_contract.required_fields.len(),
            contract.artifact_contract.required_files.len()
        ))
    };
    validator.check(
        "contract.structure",
        None,
        None,
        outcome,
        started,
        BTreeMap::new(),
    );
}

fn validate_authorities(
    contract: &VerificationCoverageContract,
    generated: &VerificationCoverageContract,
    validator: &mut Validator<'_>,
) {
    let started = Instant::now();
    let outcome = if contract.authority_sources != generated.authority_sources {
        Err((
            ERROR_SUBJECT_DRIFT,
            "authority projections differ from live bridge issues, claims, Plan Section 18, or the retained predecessor".to_string(),
        ))
    } else {
        Ok(format!(
            "{} authority projections match live state",
            contract.authority_sources.len()
        ))
    };
    validator.check(
        "authority.projections",
        None,
        None,
        outcome,
        started,
        BTreeMap::new(),
    );
}

fn validate_families(contract: &VerificationCoverageContract, validator: &mut Validator<'_>) {
    let live_issue_ids: BTreeSet<String> = match load_issues(validator.repo_root) {
        Ok(issues) => issues.into_iter().map(|issue| issue.id).collect(),
        Err(reason) => {
            let started = Instant::now();
            validator.check(
                "harness.authority",
                None,
                None,
                Err((ERROR_IO, reason)),
                started,
                BTreeMap::new(),
            );
            return;
        }
    };
    let family_ids: Vec<&str> = contract
        .harness_families
        .iter()
        .map(|family| family.family_id.as_str())
        .collect();
    let mut sorted_ids = family_ids.clone();
    sorted_ids.sort_unstable();
    let unique_ids: BTreeSet<_> = family_ids.iter().copied().collect();
    let ordering_started = Instant::now();
    let ordering_outcome = if family_ids != sorted_ids {
        Err((
            ERROR_ORDER_OR_DUPLICATE,
            "harness families are not sorted by family_id".to_string(),
        ))
    } else if unique_ids.len() != family_ids.len() {
        Err((
            ERROR_ORDER_OR_DUPLICATE,
            "duplicate harness family_id".to_string(),
        ))
    } else {
        Ok(format!(
            "{} harness family identifiers are sorted and unique",
            family_ids.len()
        ))
    };
    validator.check(
        "harness.order",
        None,
        None,
        ordering_outcome,
        ordering_started,
        BTreeMap::new(),
    );

    let canonical_formats: BTreeSet<&str> = contract
        .harness_families
        .iter()
        .filter(|family| family.current_coverage_eligible)
        .map(|family| family.emitted_event_schema.as_str())
        .collect();
    let format_started = Instant::now();
    let format_outcome = if canonical_formats != BTreeSet::from([EVENT_SCHEMA_VERSION]) {
        Err((
            ERROR_FORMAT_DUPLICATION,
            format!(
                "current coverage-eligible families advertise incompatible canonical formats: {canonical_formats:?}"
            ),
        ))
    } else {
        Ok("one canonical event schema governs all current coverage-eligible families".to_string())
    };
    validator.check(
        "harness.event_format",
        None,
        None,
        format_outcome,
        format_started,
        BTreeMap::new(),
    );

    for family in &contract.harness_families {
        let started = Instant::now();
        let member_paths: Vec<&str> = family
            .members
            .iter()
            .map(|member| member.path.as_str())
            .collect();
        let mut sorted_paths = member_paths.clone();
        sorted_paths.sort_unstable();
        let unique_paths: BTreeSet<_> = member_paths.iter().copied().collect();
        let outcome = if family.family_id.trim().is_empty()
            || family.title.trim().is_empty()
            || family.purpose.trim().is_empty()
            || family.owner.trim().is_empty()
            || family.runner.trim().is_empty()
            || family.success_basis.trim().is_empty()
            || family.successor_bead.trim().is_empty()
        {
            Err((
                ERROR_CLASSIFICATION,
                format!("family {} has a blank governed field", family.family_id),
            ))
        } else if !live_issue_ids.contains(&family.owner) {
            Err((
                ERROR_OWNER,
                format!(
                    "family {} owner {} is not a live tracker identity",
                    family.family_id, family.owner
                ),
            ))
        } else if !live_issue_ids.contains(&family.successor_bead) {
            Err((
                ERROR_OWNER,
                format!(
                    "family {} successor {} is not a live tracker identity",
                    family.family_id, family.successor_bead
                ),
            ))
        } else if family.members.is_empty() {
            Err((
                ERROR_CLASSIFICATION,
                format!("family {} has no concrete members", family.family_id),
            ))
        } else if family.members.len() > MAX_HARNESS_MEMBERS {
            Err((
                ERROR_BOUNDS,
                format!(
                    "family {} has {} members, limit {MAX_HARNESS_MEMBERS}",
                    family.family_id,
                    family.members.len()
                ),
            ))
        } else if member_paths != sorted_paths || unique_paths.len() != member_paths.len() {
            Err((
                ERROR_ORDER_OR_DUPLICATE,
                format!(
                    "family {} member paths are unsorted or duplicate",
                    family.family_id
                ),
            ))
        } else if family.current_coverage_eligible
            && family.execution_class != HarnessExecutionClass::ProductionExecuting
        {
            Err((
                ERROR_CLASSIFICATION,
                format!(
                    "family {} is coverage-eligible but classified {}",
                    family.family_id,
                    family.execution_class.label()
                ),
            ))
        } else if family.current_coverage_eligible && family.reuse_status != ReuseStatus::Reusable {
            Err((
                ERROR_CLASSIFICATION,
                format!(
                    "family {} is coverage-eligible but reuse is {}",
                    family.family_id,
                    family.reuse_status.label()
                ),
            ))
        } else if !is_sha256(&family.inventory_sha256) || family.inventory_basis.trim().is_empty() {
            Err((
                ERROR_HASH_DRIFT,
                format!(
                    "family {} has an invalid normalized inventory identity",
                    family.family_id
                ),
            ))
        } else if family.current_coverage_eligible && family.source_inventory_signals.is_empty() {
            Err((
                ERROR_BRANCH_PROOF,
                format!(
                    "family {} claims current production coverage without a reviewed source inventory signal; run-bound branch instrumentation remains separately required",
                    family.family_id
                ),
            ))
        } else if family.current_coverage_eligible && is_generic_test_runner(&family.runner) {
            Err((
                ERROR_GENERIC_RUNNER,
                format!(
                    "family {} uses generic runner `{}`",
                    family.family_id, family.runner
                ),
            ))
        } else if matches!(
            family.execution_class,
            HarnessExecutionClass::MockOnly | HarnessExecutionClass::Stale
        ) && family.current_coverage_eligible
        {
            Err((
                ERROR_HISTORICAL_PROOF,
                format!(
                    "{} family {} cannot establish current success",
                    family.execution_class.label(),
                    family.family_id
                ),
            ))
        } else if family.execution_class == HarnessExecutionClass::Stale
            && family.reuse_status != ReuseStatus::Rejected
        {
            Err((
                ERROR_HISTORICAL_PROOF,
                format!(
                    "stale family {} must be rejected, not {}",
                    family.family_id,
                    family.reuse_status.label()
                ),
            ))
        } else {
            validate_family_members_and_signals(family, validator.repo_root).map(|()| {
                format!(
                    "{} members classify as {}/{} with {} source inventory signal(s)",
                    family.members.len(),
                    family.execution_class.label(),
                    family.reuse_status.label(),
                    family.source_inventory_signals.len()
                )
            })
        };
        validator.check(
            "harness.family",
            None,
            Some(&family.family_id),
            outcome,
            started,
            BTreeMap::new(),
        );
    }
}

fn validate_family_members_and_signals(
    family: &HarnessFamily,
    repo_root: &Path,
) -> Result<(), (&'static str, String)> {
    let mut inventory_identities = Vec::new();
    for member in &family.members {
        let relative = Path::new(&member.path);
        if !safe_relative_path(relative) {
            return Err((
                ERROR_UNSAFE_PATH,
                format!(
                    "family {} has unsafe member path {}",
                    family.family_id, member.path
                ),
            ));
        }
        let absolute = repo_root.join(relative);
        let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
            (
                ERROR_IO,
                format!("inspect family member {}: {error}", member.path),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err((
                ERROR_UNSAFE_PATH,
                format!(
                    "family {} member {} is not a regular non-symlink file",
                    family.family_id, member.path
                ),
            ));
        }
        match family.integrity_mode {
            IntegrityMode::ContentHash => {
                if metadata.len() != member.bytes {
                    return Err((
                        ERROR_HASH_DRIFT,
                        format!(
                            "family {} member {} byte length changed from {} to {}",
                            family.family_id,
                            member.path,
                            member.bytes,
                            metadata.len()
                        ),
                    ));
                }
                let expected = member.sha256.as_deref().ok_or_else(|| {
                    (
                        ERROR_HASH_DRIFT,
                        format!(
                            "content-hash family {} member {} has no sha256",
                            family.family_id, member.path
                        ),
                    )
                })?;
                let actual = sha256_hex(
                    &read_bounded_regular_file(&absolute, MAX_BUNDLE_FILE_BYTES)
                        .map_err(|reason| (ERROR_IO, reason))?,
                );
                if actual != expected {
                    return Err((
                        ERROR_HASH_DRIFT,
                        format!(
                            "family {} member {} hash mismatch: expected {}, got {}",
                            family.family_id, member.path, expected, actual
                        ),
                    ));
                }
                inventory_identities
                    .push(format!("{}\0{}\0{}", member.path, member.bytes, expected));
            }
            IntegrityMode::PathSet => {
                if member.sha256.is_some() {
                    return Err((
                        ERROR_HASH_DRIFT,
                        format!(
                            "path-set family {} member {} must not imply content certification",
                            family.family_id, member.path
                        ),
                    ));
                }
                if member.bytes != 0 {
                    return Err((
                        ERROR_HASH_DRIFT,
                        format!(
                            "path-set family {} member {} must not imply byte-level content certification",
                            family.family_id, member.path
                        ),
                    ));
                }
                let bytes = read_bounded_regular_file(&absolute, MAX_BUNDLE_FILE_BYTES)
                    .map_err(|reason| (ERROR_IO, reason))?;
                inventory_identities.extend(normalized_harness_identities(&member.path, &bytes));
            }
        }
    }
    inventory_identities.sort();
    inventory_identities.dedup();
    let live_inventory_sha256 = sha256_hex(inventory_identities.join("\n").as_bytes());
    if live_inventory_sha256 != family.inventory_sha256 {
        return Err((
            ERROR_HASH_DRIFT,
            format!(
                "family {} normalized inventory changed: expected {}, got {}",
                family.family_id, family.inventory_sha256, live_inventory_sha256
            ),
        ));
    }
    for signal in &family.source_inventory_signals {
        if !safe_relative_path(Path::new(&signal.path))
            || signal.symbol.trim().is_empty()
            || signal.marker.trim().is_empty()
            || signal.interpretation.trim().is_empty()
        {
            return Err((
                ERROR_BRANCH_PROOF,
                format!(
                    "family {} has an invalid source inventory signal for {}",
                    family.family_id, signal.path
                ),
            ));
        }
        let bytes = read_bounded_regular_file(&repo_root.join(&signal.path), MAX_BUNDLE_FILE_BYTES)
            .map_err(|reason| (ERROR_BRANCH_PROOF, reason))?;
        let contents = std::str::from_utf8(&bytes).map_err(|error| {
            (
                ERROR_BRANCH_PROOF,
                format!(
                    "source inventory signal {} is not UTF-8: {error}",
                    signal.path
                ),
            )
        })?;
        if !contents.contains(&signal.marker) {
            return Err((
                ERROR_BRANCH_PROOF,
                format!(
                    "family {} source inventory signal {} no longer contains marker `{}`",
                    family.family_id, signal.symbol, signal.marker
                ),
            ));
        }
    }
    Ok(())
}

fn is_generic_test_runner(runner: &str) -> bool {
    let normalized = runner.split_whitespace().collect::<Vec<_>>().join(" ");
    matches!(
        normalized.as_str(),
        "cargo test"
            | "rch exec -- cargo test"
            | "rch exec -- env CARGO_TARGET_DIR=<unique> cargo test"
    ) || (normalized.contains("cargo test")
        && !normalized.contains(" --test ")
        && !normalized.contains(" --bin ")
        && !normalized.contains(" --lib")
        && !normalized.contains(" -p "))
}

fn validate_coverage_rows(
    contract: &VerificationCoverageContract,
    generated: &VerificationCoverageContract,
    validator: &mut Validator<'_>,
) {
    let live_issues = match load_issues(validator.repo_root) {
        Ok(issues) => issues,
        Err(reason) => {
            let started = Instant::now();
            validator.check(
                "coverage.authority",
                None,
                None,
                Err((ERROR_IO, reason)),
                started,
                BTreeMap::new(),
            );
            return;
        }
    };
    let live_issue_ids: BTreeSet<&str> =
        live_issues.iter().map(|issue| issue.id.as_str()).collect();
    let family_index: BTreeMap<&str, &HarnessFamily> = contract
        .harness_families
        .iter()
        .map(|family| (family.family_id.as_str(), family))
        .collect();
    let generated_index: BTreeMap<&str, &CoverageRow> = generated
        .coverage_rows
        .iter()
        .map(|row| (row.row_id.as_str(), row))
        .collect();

    let row_ids: Vec<&str> = contract
        .coverage_rows
        .iter()
        .map(|row| row.row_id.as_str())
        .collect();
    let mut sorted_row_ids = row_ids.clone();
    sorted_row_ids.sort_unstable();
    let unique_row_ids: BTreeSet<_> = row_ids.iter().copied().collect();
    let order_started = Instant::now();
    let order_outcome = if row_ids != sorted_row_ids {
        Err((
            ERROR_ORDER_OR_DUPLICATE,
            "coverage rows are not sorted by row_id".to_string(),
        ))
    } else if unique_row_ids.len() != row_ids.len() {
        Err((
            ERROR_ORDER_OR_DUPLICATE,
            "duplicate coverage row_id".to_string(),
        ))
    } else if contract.coverage_rows.len() != generated.coverage_rows.len() {
        Err((
            ERROR_SUBJECT_DRIFT,
            format!(
                "committed coverage has {} rows but live authorities require {}",
                contract.coverage_rows.len(),
                generated.coverage_rows.len()
            ),
        ))
    } else {
        Ok(format!(
            "{} exact coverage rows are sorted and unique",
            row_ids.len()
        ))
    };
    validator.check(
        "coverage.order",
        None,
        None,
        order_outcome,
        order_started,
        BTreeMap::new(),
    );

    for row in &contract.coverage_rows {
        let started = Instant::now();
        let outcome = match generated_index.get(row.row_id.as_str()) {
            None => Err((
                ERROR_SUBJECT_DRIFT,
                format!("row {} has no live task or claim authority", row.row_id),
            )),
            Some(expected) => validate_coverage_row(
                row,
                expected,
                &live_issue_ids,
                &family_index,
                validator.repo_root,
            ),
        };
        validator.check(
            "coverage.row",
            Some(&row.subject_id),
            None,
            outcome,
            started,
            BTreeMap::new(),
        );
    }
}

fn validate_coverage_row(
    row: &CoverageRow,
    expected: &CoverageRow,
    live_issue_ids: &BTreeSet<&str>,
    family_index: &BTreeMap<&str, &HarnessFamily>,
    repo_root: &Path,
) -> Result<String, (&'static str, String)> {
    if row.row_id.contains('*') || row.subject_id.contains('*') {
        return Err((
            ERROR_SUBJECT_DRIFT,
            format!("wildcard coverage is forbidden in {}", row.row_id),
        ));
    }
    if row.row_id.trim().is_empty()
        || row.subject_id.trim().is_empty()
        || row.title.trim().is_empty()
        || row.authority_state.trim().is_empty()
        || row.independent_owner.trim().is_empty()
        || row.required_verification_packs.is_empty()
        || row.required_public_entrypoint.trim().is_empty()
        || row.gap_reason.trim().is_empty()
    {
        return Err((
            ERROR_SCHEMA,
            format!("row {} has a blank governed field", row.row_id),
        ));
    }
    if row.subject_id == row.independent_owner {
        return Err((ERROR_OWNER, format!("row {} is self-owned", row.row_id)));
    }
    if !live_issue_ids.contains(row.independent_owner.as_str()) {
        return Err((
            ERROR_OWNER,
            format!(
                "row {} independent owner {} is not a live tracker identity",
                row.row_id, row.independent_owner
            ),
        ));
    }
    if !row
        .required_verification_packs
        .iter()
        .any(|pack| pack == &row.independent_owner)
    {
        return Err((
            ERROR_OWNER,
            format!(
                "row {} primary owner {} is absent from required verification packs",
                row.row_id, row.independent_owner
            ),
        ));
    }
    let mut sorted_packs = row.required_verification_packs.clone();
    sorted_packs.sort();
    sorted_packs.dedup();
    if sorted_packs != row.required_verification_packs {
        return Err((
            ERROR_ORDER_OR_DUPLICATE,
            format!(
                "row {} verification packs are unsorted or duplicate",
                row.row_id
            ),
        ));
    }
    for pack in &row.required_verification_packs {
        if pack == &row.subject_id || !live_issue_ids.contains(pack.as_str()) {
            return Err((
                ERROR_OWNER,
                format!(
                    "row {} has missing or self-owned required verification pack {}",
                    row.row_id, pack
                ),
            ));
        }
    }
    if immutable_row_projection(row) != immutable_row_projection(expected) {
        return Err((
            ERROR_SUBJECT_DRIFT,
            format!(
                "row {} requirement/owner/runner projection differs from live generated authority",
                row.row_id
            ),
        ));
    }
    if row.subject_kind == SubjectKind::BridgeTask
        && !status_transition_allowed(&row.authority_state, &expected.authority_state)
    {
        return Err((
            ERROR_SUBJECT_DRIFT,
            format!(
                "row {} tracker state changed incompatibly from {} to {}",
                row.row_id, row.authority_state, expected.authority_state
            ),
        ));
    }
    if row.evidence_state == EvidenceState::CandidateCurrentRun && row.authority_state == "closed" {
        return Err((
            ERROR_HISTORICAL_PROOF,
            format!(
                "row {} treats a closed historical task as current-run evidence",
                row.row_id
            ),
        ));
    }
    if row.current_evidence.iter().any(|item| {
        let lower = item.to_ascii_lowercase();
        lower == "tests pass" || lower == "all tests pass" || lower.contains("generic cargo test")
    }) {
        return Err((
            ERROR_GENERIC_RUNNER,
            format!("row {} contains generic test-success language", row.row_id),
        ));
    }
    let required_base = [
        "unit",
        "property",
        "golden",
        "mutation",
        "canonical_integration",
        "public_e2e",
        "production_branch_signal",
        "tier_r_differential",
        "replay",
        "fault_recovery",
        "artifact_integrity",
        "redaction",
    ];
    for layer in required_base {
        if !row
            .required_layers
            .iter()
            .any(|candidate| candidate == layer)
        {
            return Err((
                ERROR_SCHEMA,
                format!("row {} is missing required layer {layer}", row.row_id),
            ));
        }
    }
    if !row.required_tiers.iter().any(|tier| tier == "tier-r") {
        return Err((
            ERROR_TIER_R_TRUTH,
            format!(
                "row {} does not require Tier-R differential coverage",
                row.row_id
            ),
        ));
    }
    if !row
        .required_security_profiles
        .iter()
        .any(|profile| profile == "full-containment")
    {
        return Err((
            ERROR_SCHEMA,
            format!("row {} omits the full-containment profile", row.row_id),
        ));
    }
    for family_id in &row.current_runner_family_ids {
        let family = family_index.get(family_id.as_str()).ok_or_else(|| {
            (
                ERROR_CLASSIFICATION,
                format!(
                    "row {} references unknown harness family {family_id}",
                    row.row_id
                ),
            )
        })?;
        if row.evidence_state == EvidenceState::CandidateCurrentRun
            && !family.current_coverage_eligible
        {
            return Err((
                ERROR_CLASSIFICATION,
                format!(
                    "row {} current candidate uses ineligible family {family_id}",
                    row.row_id
                ),
            ));
        }
        if matches!(
            family.execution_class,
            HarnessExecutionClass::MockOnly | HarnessExecutionClass::Stale
        ) {
            return Err((
                ERROR_HISTORICAL_PROOF,
                format!(
                    "row {} selects {} family {family_id} as current evidence",
                    row.row_id,
                    family.execution_class.label()
                ),
            ));
        }
    }
    if row.evidence_state == EvidenceState::CandidateCurrentRun {
        let entrypoint = repo_root.join(&row.required_public_entrypoint);
        if !entrypoint.is_file() {
            return Err((
                ERROR_BRANCH_PROOF,
                format!(
                    "current candidate row {} entrypoint {} does not exist",
                    row.row_id, row.required_public_entrypoint
                ),
            ));
        }
    }
    Ok(format!(
        "{} maps exactly to owner {}, {} required layers, and {} current runner family/families with evidence state {}",
        row.row_id,
        row.independent_owner,
        row.required_layers.len(),
        row.current_runner_family_ids.len(),
        row.evidence_state.label()
    ))
}

fn immutable_row_projection(row: &CoverageRow) -> JsonValue {
    serde_json::json!({
        "row_id": row.row_id,
        "subject_id": row.subject_id,
        "subject_kind": row.subject_kind,
        "title": row.title,
        "evidence_state": row.evidence_state,
        "independent_owner": row.independent_owner,
        "required_verification_packs": row.required_verification_packs,
        "required_public_entrypoint": row.required_public_entrypoint,
        "required_layers": row.required_layers,
        "required_platforms": row.required_platforms,
        "required_tiers": row.required_tiers,
        "required_security_profiles": row.required_security_profiles,
        "current_runner_family_ids": row.current_runner_family_ids,
        "current_evidence": row.current_evidence,
        "gap_reason": row.gap_reason,
    })
}

fn status_transition_allowed(snapshot: &str, live: &str) -> bool {
    snapshot == live
        || (matches!(snapshot, "open" | "in_progress") && live == "closed")
        || (snapshot == "open" && live == "in_progress")
}

fn validate_integrations(contract: &VerificationCoverageContract, validator: &mut Validator<'_>) {
    let started = Instant::now();
    let integration_ids: BTreeSet<&str> = contract
        .integrations
        .iter()
        .map(|integration| integration.integration_id.as_str())
        .collect();
    let canonical = contract
        .integrations
        .iter()
        .find(|integration| integration.integration_id == "canonical-contract-validator");
    let reference = contract
        .integrations
        .iter()
        .find(|integration| integration.integration_id == "provisional-tier-r-candidate");
    let outcome = if integration_ids.len() != contract.integrations.len() {
        Err((
            ERROR_ORDER_OR_DUPLICATE,
            "duplicate integration_id".to_string(),
        ))
    } else if canonical.is_none() || reference.is_none() {
        Err((
            ERROR_BRANCH_PROOF,
            "canonical production or provisional reference integration is missing".to_string(),
        ))
    } else {
        let canonical = canonical.expect("checked above");
        let reference = reference.expect("checked above");
        if canonical.classification != "production_executing"
            || canonical.required_signals.len() < 4
            || canonical.entrypoint.trim().is_empty()
        {
            Err((
                ERROR_BRANCH_PROOF,
                "canonical validator integration lacks production classification, entrypoint, or trusted signals".to_string(),
            ))
        } else if reference.classification != "provisional_not_certified_tier_r"
            || reference.required_signals
                != TIER_R_BRANCH_SIGNALS
                    .iter()
                    .map(|signal| (*signal).to_string())
                    .collect::<Vec<_>>()
        {
            Err((
                ERROR_TIER_R_TRUTH,
                "reference integration must remain provisional and carry the exact ordered live parse/lower/execute/denial/oracle signal contract".to_string(),
            ))
        } else {
            Ok("canonical validator and provisional reference candidate are explicitly separated with trusted success and refusal rules".to_string())
        }
    };
    validator.check(
        "integration.contract",
        None,
        None,
        outcome,
        started,
        BTreeMap::new(),
    );
}

fn validate_freshness(contract: &VerificationCoverageContract, validator: &mut Validator<'_>) {
    let started = Instant::now();
    let outcome = if !validator.context.certifying_clock {
        Err((
            ERROR_CLOCK_AUTHORITY,
            "synthetic validation time is non-certifying; use a witnessed current clock for publishable freshness evidence".to_string(),
        ))
    } else {
        DateTime::parse_from_rfc3339(&contract.source_cutoff_utc)
            .map_err(|error| {
                (
                    ERROR_STALE,
                    format!(
                        "source cutoff {} is not RFC3339: {error}",
                        contract.source_cutoff_utc
                    ),
                )
            })
            .and_then(|cutoff| {
                let cutoff = cutoff.with_timezone(&Utc);
                let age = validator.context.as_of_utc.signed_duration_since(cutoff);
                let max_age = chrono::Duration::days(
                    i64::try_from(contract.max_age_days).unwrap_or(i64::MAX),
                );
                if age < chrono::Duration::zero() {
                    Err((
                        ERROR_STALE,
                        format!(
                            "validation time {} predates source cutoff {}",
                            validator.context.as_of_utc, cutoff
                        ),
                    ))
                } else if age > max_age {
                    Err((
                        ERROR_STALE,
                        format!(
                            "contract age {} seconds exceeds {} day limit",
                            age.num_seconds(),
                            contract.max_age_days
                        ),
                    ))
                } else {
                    Ok(format!(
                        "source cutoff is {} seconds old within {} day limit",
                        age.num_seconds(),
                        contract.max_age_days
                    ))
                }
            })
    };
    validator.check(
        "contract.freshness",
        None,
        None,
        outcome,
        started,
        BTreeMap::new(),
    );
}

fn validate_generation_projection(
    contract: &VerificationCoverageContract,
    generated: &VerificationCoverageContract,
    validator: &mut Validator<'_>,
) {
    let started = Instant::now();
    let committed_projection = static_contract_projection(contract);
    let generated_projection = static_contract_projection(generated);
    let committed_bytes = serde_json::to_vec(&committed_projection)
        .expect("static committed projection is infallibly serializable");
    let generated_bytes = serde_json::to_vec(&generated_projection)
        .expect("static generated projection is infallibly serializable");
    let outcome = if committed_projection != generated_projection {
        Err((
            ERROR_GENERATION_DRIFT,
            format!(
                "static generated projection differs: committed {}, live {}",
                sha256_hex(&committed_bytes),
                sha256_hex(&generated_bytes)
            ),
        ))
    } else {
        Ok(format!(
            "static generated projection matches at sha256 {}",
            sha256_hex(&generated_bytes)
        ))
    };
    validator.check(
        "contract.generation_drift",
        None,
        None,
        outcome,
        started,
        BTreeMap::new(),
    );
}

fn static_contract_projection(contract: &VerificationCoverageContract) -> JsonValue {
    let mut value =
        serde_json::to_value(contract).expect("verification contract is infallibly serializable");
    if let Some(rows) = value
        .get_mut("coverage_rows")
        .and_then(JsonValue::as_array_mut)
    {
        for row in rows {
            let is_task = row
                .get("subject_kind")
                .and_then(JsonValue::as_str)
                .is_some_and(|kind| kind == "bridge_task");
            if is_task && let Some(object) = row.as_object_mut() {
                object.remove("authority_state");
            }
        }
    }
    value
}

fn validate_markdown(contract: &VerificationCoverageContract, validator: &mut Validator<'_>) {
    let started = Instant::now();
    let path = validator.repo_root.join(&contract.rendered_markdown_path);
    let expected = render_markdown(contract);
    let outcome = match read_bounded_regular_file(&path, MAX_CONTRACT_BYTES).and_then(|bytes| {
        String::from_utf8(bytes)
            .map_err(|error| format!("{ERROR_JSON}: Markdown is not UTF-8: {error}"))
    }) {
        Ok(actual) if actual == expected => Ok(format!(
            "rendered Markdown is byte-identical at sha256 {}",
            sha256_hex(actual.as_bytes())
        )),
        Ok(actual) => Err((
            ERROR_MARKDOWN_DRIFT,
            format!(
                "{} differs from deterministic render: committed {}, expected {}",
                contract.rendered_markdown_path,
                sha256_hex(actual.as_bytes()),
                sha256_hex(expected.as_bytes())
            ),
        )),
        Err(reason) => Err((ERROR_MARKDOWN_DRIFT, reason)),
    };
    validator.check(
        "contract.markdown",
        None,
        None,
        outcome,
        started,
        BTreeMap::new(),
    );
}

/// Render the deterministic operator-facing contract.
#[must_use]
pub fn render_markdown(contract: &VerificationCoverageContract) -> String {
    let task_count = contract
        .coverage_rows
        .iter()
        .filter(|row| row.subject_kind == SubjectKind::BridgeTask)
        .count();
    let claim_count = contract.coverage_rows.len().saturating_sub(task_count);
    let member_count: usize = contract
        .harness_families
        .iter()
        .map(|family| family.members.len())
        .sum();
    let mut out = String::new();
    out.push_str("# Verification Coverage Contract V1\n\n");
    out.push_str(&format!(
        "_Generated deterministically from `{}`. Source cutoff: `{}`._\n\n",
        CONTRACT_PATH, contract.source_cutoff_utc
    ));
    out.push_str("## Outcome\n\n");
    out.push_str(&format!(
        "This contract maps **{task_count} exact bridge tasks** and **{claim_count} exact public claims** across **{} harness families** and **{member_count} concrete harness members**. It deliberately distinguishes required future coverage from current proof; a complete matrix is not a claim that implementation is complete.\n\n",
        contract.harness_families.len()
    ));
    out.push_str(&contract.truth_posture);
    out.push_str("\n\n");

    out.push_str("## Classification model\n\n");
    out.push_str("| Label | Meaning |\n|---|---|\n");
    for (label, meaning) in &contract.classification_definitions {
        out.push_str(&format!(
            "| `{}` | {} |\n",
            markdown_cell(label),
            markdown_cell(meaning)
        ));
    }
    out.push('\n');

    out.push_str("## Authority projections\n\n");
    out.push_str("| Authority | Path | Selector | SHA-256 | Purpose |\n|---|---|---|---|---|\n");
    for source in &contract.authority_sources {
        out.push_str(&format!(
            "| `{}` | `{}` | {} | `{}` | {} |\n",
            markdown_cell(&source.authority_id),
            markdown_cell(&source.path),
            markdown_cell(&source.selector),
            source.projection_sha256,
            markdown_cell(&source.purpose)
        ));
    }
    out.push('\n');

    out.push_str("## Harness inventory\n\n");
    out.push_str("| Family | Execution | Reuse | Current proof eligible | Members | Inventory SHA-256 | Runner | Owner | Limitation |\n|---|---:|---:|---:|---:|---|---|---|---|\n");
    for family in &contract.harness_families {
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | {} | {} | `{}` | `{}` | `{}` | {} |\n",
            markdown_cell(&family.family_id),
            family.execution_class.label(),
            family.reuse_status.label(),
            family.current_coverage_eligible,
            family.members.len(),
            family.inventory_sha256,
            markdown_cell(&family.runner),
            markdown_cell(&family.owner),
            markdown_cell(
                family
                    .limitations
                    .first()
                    .map(String::as_str)
                    .unwrap_or("none")
            )
        ));
    }
    out.push('\n');

    out.push_str("## Unified event contract\n\n");
    out.push_str(&format!(
        "- Schema: `{}`\n- Event bound: `{}` records, `{}` bytes/record, `{}` bytes/stream\n- Sequence: {}\n- Retry: {}\n- Guest output: {}\n\n",
        contract.event_contract.schema_version,
        contract.event_contract.max_events,
        contract.event_contract.max_event_bytes,
        contract.event_contract.max_stream_bytes,
        contract.event_contract.sequence_rule,
        contract.event_contract.retry_rule,
        contract.event_contract.guest_output_rule
    ));
    out.push_str("Required fields: ");
    out.push_str(
        &contract
            .event_contract
            .required_fields
            .iter()
            .map(|field| format!("`{field}`"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    out.push_str(".\n\n");

    out.push_str("## Artifact contract\n\n");
    out.push_str("Every successful or failed run retains: ");
    out.push_str(
        &contract
            .artifact_contract
            .required_files
            .iter()
            .map(|path| format!("`{path}`"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    out.push_str(&format!(
        ". The selected sample artifact obeys `{}`. Publication is no-replace; the first failure and exact nonzero exit are retained. Bundle limits are {} files, {} directories, depth {}, {} bytes/file, and {} bytes total.\n\n",
        contract.artifact_contract.raw_sample_alternative,
        contract.artifact_contract.max_files,
        contract.artifact_contract.max_directories,
        contract.artifact_contract.max_depth,
        contract.artifact_contract.max_file_bytes,
        contract.artifact_contract.max_total_bytes,
    ));

    out.push_str("## Exact coverage rows\n\n");
    out.push_str("| Subject | Kind | Authority state | Evidence state | Independent owner | Required packs | Platforms | Tiers | Public entrypoint | Required layers | Current runners |\n|---|---|---|---|---|---|---|---|---|---:|---|\n");
    for row in &contract.coverage_rows {
        out.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} | {} | `{}` | {} | {} |\n",
            markdown_cell(&row.subject_id),
            match row.subject_kind {
                SubjectKind::BridgeTask => "bridge_task",
                SubjectKind::Claim => "claim",
            },
            markdown_cell(&row.authority_state),
            row.evidence_state.label(),
            markdown_cell(&row.independent_owner),
            row.required_verification_packs
                .iter()
                .map(|pack| format!("`{}`", markdown_cell(pack)))
                .collect::<Vec<_>>()
                .join(", "),
            row.required_platforms
                .iter()
                .map(|platform| format!("`{}`", markdown_cell(platform)))
                .collect::<Vec<_>>()
                .join(", "),
            row.required_tiers
                .iter()
                .map(|tier| format!("`{}`", markdown_cell(tier)))
                .collect::<Vec<_>>()
                .join(", "),
            markdown_cell(&row.required_public_entrypoint),
            row.required_layers.len(),
            if row.current_runner_family_ids.is_empty() {
                "none".to_string()
            } else {
                row.current_runner_family_ids
                    .iter()
                    .map(|family| format!("`{}`", markdown_cell(family)))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
    }
    out.push('\n');

    out.push_str("## Production and reference integration\n\n");
    for integration in &contract.integrations {
        out.push_str(&format!(
            "### `{}`\n\n- Role: `{}`\n- Classification: `{}`\n- Entrypoint: `{}`\n- Success: {}\n- Refusal: {}\n\n",
            integration.integration_id,
            integration.role,
            integration.classification,
            integration.entrypoint,
            integration.success_rule,
            integration.refusal_rule
        ));
    }

    out.push_str("## Known limitations\n\n");
    for limitation in &contract.limitations {
        out.push_str(&format!("- {limitation}\n"));
    }
    out.push('\n');
    out.push_str("## Public verification\n\n");
    out.push_str("```bash\n");
    out.push_str("./scripts/run_verification_coverage_contract_gate.sh ci\n");
    out.push_str("./scripts/e2e/verification_coverage_contract_smoke.sh\n");
    out.push_str("```\n");
    out
}

/// Serialize a generated contract with stable indentation and a terminal
/// newline.
pub fn canonical_json_bytes(contract: &VerificationCoverageContract) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(contract)
        .map_err(|error| format!("{ERROR_JSON}: serialize contract: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventValidationReport {
    pub schema_version: String,
    pub status: String,
    pub event_count: usize,
    pub terminal_decision: Option<String>,
    pub first_failure: Option<FailureReference>,
    pub error_count: usize,
    pub findings: Vec<ValidationFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    Pass,
    Fail,
    Deny,
    Fallback,
    Cancel,
    Crash,
    Rollback,
}

impl RunOutcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Deny => "deny",
            Self::Fallback => "fallback",
            Self::Cancel => "cancel",
            Self::Crash => "crash",
            Self::Rollback => "rollback",
        }
    }

    const fn is_success(self) -> bool {
        matches!(self, Self::Pass)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureReference {
    pub sequence: u64,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleArtifactKind {
    RawSamples,
    MinimizedSeed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleArtifact {
    pub kind: SampleArtifactKind,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSample {
    pub schema_version: String,
    pub sample_id: String,
    pub seed: u64,
    pub outcome: RunOutcome,
    pub duration_ns: u64,
    pub artifact_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizedSeed {
    pub schema_version: String,
    pub seed: u64,
    pub original_sha256: String,
    pub reduced_sha256: String,
    pub reduction_steps: u64,
    pub reproduction_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunManifest {
    pub schema_version: String,
    pub run_id: String,
    pub trace_id: String,
    pub test_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub attempt: u32,
    pub platform: String,
    pub target: String,
    pub tier: String,
    pub security_profile: String,
    pub created_at_utc: String,
    pub clock_source: String,
    pub expected_outcome: RunOutcome,
    pub observed_outcome: RunOutcome,
    pub exit_code: i32,
    pub first_failure: Option<FailureReference>,
    pub reproduction_command: String,
    pub artifact_manifest: String,
    pub contract: String,
    pub generated_contract: String,
    pub rendered_markdown: String,
    pub validation_report: String,
    pub events: String,
    pub tier_r_probe: String,
    pub tier_r_source_manifest: String,
    pub tier_r_build_environment: String,
    pub sample_artifact: SampleArtifact,
    pub required_files: Vec<String>,
    pub guest_stdout: String,
    pub guest_stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub schema_version: String,
    pub hash_algorithm: String,
    pub files: Vec<ArtifactDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentManifest {
    pub schema_version: String,
    pub platform: String,
    pub target: String,
    pub tier: String,
    pub security_profile: String,
    pub rustc_version: String,
    pub cargo_version: String,
    pub toolchain: String,
    pub toolchain_role: String,
    pub repository_revision: String,
    pub source_state: String,
    pub source_tree_basis: String,
    pub source_identity_command: String,
    pub source_tree_sha256: String,
    pub source_diff_basis: Option<String>,
    pub source_diff_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproLock {
    pub schema_version: String,
    pub source_tree_sha256: String,
    pub cargo_lock_sha256: String,
    pub tool_lock_sha256: String,
    pub contract_sha256: String,
    pub generated_contract_sha256: String,
    pub commands_sha256: String,
    pub tier_r_source_sha256: String,
    pub tier_r_build_environment_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproductionRecord {
    pub schema_version: String,
    pub command: String,
    pub executed_at_utc: String,
    pub exit_code: i32,
    pub stdout_path: String,
    pub stdout_sha256: String,
    pub stderr_path: String,
    pub stderr_sha256: String,
    pub cleanup_complete: bool,
    pub rollback_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierRInvocationRecord {
    pub schema_version: String,
    pub command: String,
    pub executed_at_utc: String,
    pub exit_code: i32,
    pub stdout_path: String,
    pub stdout_sha256: String,
    pub stderr_path: String,
    pub stderr_sha256: String,
    pub executable_path: String,
    pub executable_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierRSourceManifest {
    pub schema_version: String,
    pub hash_algorithm: String,
    pub identity_basis: String,
    pub files: Vec<TierRSourceFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierRSourceFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierRBuildEnvironment {
    pub schema_version: String,
    pub rustc_verbose_version: String,
    pub cargo_version: String,
    pub host: String,
    pub target: String,
    pub profile: String,
    pub opt_level: String,
    pub requested_toolchain: Option<String>,
    pub active_features: Vec<String>,
    pub build_flags_source: String,
    pub build_flags_sha256: String,
    pub builder_identity_source: String,
    pub builder_identity_sha256: Option<String>,
    pub source_manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceGraph {
    pub schema_version: String,
    pub nodes: Vec<ProvenanceNode>,
    pub edges: Vec<ProvenanceEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceNode {
    pub node_id: String,
    pub kind: String,
    pub sha256: Option<String>,
    pub artifact_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierRProbeReport {
    pub schema_version: String,
    pub classification: String,
    pub run_id: String,
    pub trace_id: String,
    pub implementation_truth: String,
    pub reference_source_sha256: String,
    pub build_environment_sha256: String,
    pub probe_executable_sha256: String,
    pub status: String,
    pub scenarios: Vec<TierRProbeScenario>,
    pub denial: TierRDenialProbe,
    pub stage_events: Vec<TierRStageEvent>,
    pub branch_signals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierRStageEvent {
    pub sequence: u64,
    pub scenario_id: String,
    pub stage: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub decision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierRProbeScenario {
    pub scenario_id: String,
    pub source_sha256: String,
    pub reference_ir_sha256: String,
    pub expected_value: String,
    pub reference_value: String,
    pub reference_instructions: u64,
    pub reference_events: Vec<String>,
    pub expected_semantic_digest: String,
    pub reference_semantic_digest: String,
    pub decision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierRDenialProbe {
    pub scenario_id: String,
    pub error_class: String,
    pub capability: String,
    pub decision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleValidationReport {
    pub schema_version: String,
    pub bundle_path: String,
    pub status: String,
    pub checked_files: usize,
    pub event_count: usize,
    pub error_count: usize,
    pub findings: Vec<ValidationFinding>,
}

/// Parse and validate a unified event stream.  The returned report is itself
/// stable JSON and never treats malformed/truncated input as an empty pass.
#[must_use]
pub fn validate_event_stream(bytes: &[u8]) -> EventValidationReport {
    let mut findings = Vec::new();
    if bytes.len() > MAX_EVENT_STREAM_BYTES {
        findings.push(simple_finding(
            ERROR_BOUNDS,
            "events.bounds",
            format!(
                "event stream is {} bytes, limit {MAX_EVENT_STREAM_BYTES}",
                bytes.len()
            ),
        ));
        return event_report(0, None, None, findings);
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.utf8",
                format!("event stream is not UTF-8: {error}"),
            ));
            return event_report(0, None, None, findings);
        }
    };
    if !bytes.ends_with(b"\n") {
        findings.push(simple_finding(
            ERROR_EVENT_SCHEMA,
            "events.framing",
            "event stream must end with one newline-delimited complete record".to_string(),
        ));
    }
    let mut events = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.parse",
                format!("blank event line at {}", index + 1),
            ));
            continue;
        }
        if line.len() > MAX_EVENT_BYTES {
            findings.push(simple_finding(
                ERROR_BOUNDS,
                "events.bounds",
                format!(
                    "event line {} is {} bytes, limit {MAX_EVENT_BYTES}",
                    index + 1,
                    line.len()
                ),
            ));
            continue;
        }
        match serde_json::from_str::<VerificationEvent>(line) {
            Ok(event) => events.push(event),
            Err(error) => findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.parse",
                format!("parse event line {}: {error}", index + 1),
            )),
        }
    }
    if events.is_empty() {
        findings.push(simple_finding(
            ERROR_EVENT_SCHEMA,
            "events.empty",
            "event stream contains no valid records".to_string(),
        ));
        return event_report(0, None, None, findings);
    }
    if events.len() > MAX_EVENTS {
        findings.push(simple_finding(
            ERROR_BOUNDS,
            "events.bounds",
            format!("{} events exceed limit {MAX_EVENTS}", events.len()),
        ));
    }
    let first = &events[0];
    let stable_identity = (
        first.run_id.as_str(),
        first.trace_id.as_str(),
        first.test_id.as_str(),
        first.scenario_id.as_str(),
        first.seed,
        first.platform.as_str(),
        first.target.as_str(),
        first.tier.as_str(),
        first.security_profile.as_str(),
    );
    let allowed_decisions: BTreeSet<&str> = [
        "pass", "fail", "deny", "fallback", "cancel", "crash", "rollback",
    ]
    .into_iter()
    .collect();
    let allowed_events: BTreeSet<&str> = ALLOWED_EVENT_NAMES.iter().copied().collect();
    let allowed_reason_codes: BTreeSet<&str> = ALLOWED_REASON_CODES.iter().copied().collect();
    let mut failed_attempts: BTreeSet<(String, String, u32)> = BTreeSet::new();
    let mut completed_at = None;
    let mut check_count = 0usize;
    let mut first_failure = None;
    let mut saw_nonpassing_decision = false;
    let mut previous_attempt = first.attempt;
    for (index, event) in events.iter().enumerate() {
        let expected_sequence = u64::try_from(index).unwrap_or(u64::MAX) + 1;
        if event.sequence != expected_sequence {
            findings.push(simple_finding(
                ERROR_ORDER_OR_DUPLICATE,
                "events.sequence",
                format!(
                    "event index {} expected sequence {}, got {}",
                    index + 1,
                    expected_sequence,
                    event.sequence
                ),
            ));
        }
        if event.schema_version != EVENT_SCHEMA_VERSION {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.schema",
                format!(
                    "sequence {} schema {} does not equal {EVENT_SCHEMA_VERSION}",
                    event.sequence, event.schema_version
                ),
            ));
        }
        if (
            event.run_id.as_str(),
            event.trace_id.as_str(),
            event.test_id.as_str(),
            event.scenario_id.as_str(),
            event.seed,
            event.platform.as_str(),
            event.target.as_str(),
            event.tier.as_str(),
            event.security_profile.as_str(),
        ) != stable_identity
        {
            findings.push(simple_finding(
                ERROR_ORDER_OR_DUPLICATE,
                "events.identity",
                format!(
                    "sequence {} changes stable run/trace/test/scenario/seed/platform/target/tier/profile identity",
                    event.sequence
                ),
            ));
        }
        for (field, value) in [
            ("run_id", event.run_id.as_str()),
            ("trace_id", event.trace_id.as_str()),
            ("test_id", event.test_id.as_str()),
            ("scenario_id", event.scenario_id.as_str()),
            ("platform", event.platform.as_str()),
            ("target", event.target.as_str()),
            ("tier", event.tier.as_str()),
            ("security_profile", event.security_profile.as_str()),
            ("phase", event.phase.as_str()),
            ("event", event.event.as_str()),
            ("reason_code", event.reason_code.as_str()),
            ("fallback", event.fallback.as_str()),
            ("rollback", event.rollback.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > MAX_ID_BYTES {
                findings.push(simple_finding(
                    ERROR_BOUNDS,
                    "events.field",
                    format!(
                        "sequence {} field {field} is blank or exceeds {MAX_ID_BYTES} bytes",
                        event.sequence
                    ),
                ));
            }
        }
        if event.attempt == 0 {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.attempt",
                format!("sequence {} attempt must be at least 1", event.sequence),
            ));
        }
        if event.attempt < previous_attempt || event.attempt > previous_attempt.saturating_add(1) {
            findings.push(simple_finding(
                ERROR_RETRY_MASKING,
                "events.attempt",
                format!(
                    "sequence {} jumps attempt {} to {}",
                    event.sequence, previous_attempt, event.attempt
                ),
            ));
        }
        previous_attempt = event.attempt;
        if !allowed_decisions.contains(event.decision.as_str()) {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.decision",
                format!(
                    "sequence {} has unknown decision {}",
                    event.sequence, event.decision
                ),
            ));
        }
        if !allowed_events.contains(event.event.as_str()) {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.event",
                format!(
                    "sequence {} has unknown event {}",
                    event.sequence, event.event
                ),
            ));
        }
        if !allowed_reason_codes.contains(event.reason_code.as_str()) {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.reason_code",
                format!(
                    "sequence {} reason_code {} is not in the versioned reason-code registry",
                    event.sequence, event.reason_code
                ),
            ));
        }
        if event.reason.len() > MAX_REASON_BYTES {
            findings.push(simple_finding(
                ERROR_BOUNDS,
                "events.reason",
                format!(
                    "sequence {} reason is {} bytes, limit {MAX_REASON_BYTES}",
                    event.sequence,
                    event.reason.len()
                ),
            ));
        }
        let is_pass = event.decision == "pass";
        if (is_pass && event.reason_code != "FE-VCC-0000")
            || (!is_pass && event.reason_code == "FE-VCC-0000")
            || (is_pass && event.error_class.is_some())
            || (!is_pass && event.error_class.as_deref().is_none_or(str::is_empty))
        {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.decision_consistency",
                format!(
                    "sequence {} has inconsistent decision/reason_code/error_class",
                    event.sequence
                ),
            ));
        }
        if event.event == "run_started" && (index != 0 || !is_pass) {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.lifecycle",
                "run_started must be the first passing event".to_string(),
            ));
        }
        if event.event == "contract_check" {
            check_count += 1;
        }
        if event.event == "attempt_failed" && is_pass {
            findings.push(simple_finding(
                ERROR_RETRY_MASKING,
                "events.retry",
                format!(
                    "sequence {} attempt_failed cannot carry a pass decision",
                    event.sequence
                ),
            ));
        }
        if !is_pass && event.event != "run_completed" {
            saw_nonpassing_decision = true;
            if first_failure.is_none() {
                first_failure = Some(FailureReference {
                    sequence: event.sequence,
                    reason_code: event.reason_code.clone(),
                });
            }
        }
        if contains_secret_marker(
            &serde_json::to_string(event).expect("verification event is infallibly serializable"),
        ) {
            findings.push(simple_finding(
                ERROR_SECRET_LEAK,
                "events.redaction",
                format!("sequence {} contains a secret marker", event.sequence),
            ));
        }
        if event.artifact_hashes.len() > MAX_ARTIFACT_HASHES_PER_EVENT {
            findings.push(simple_finding(
                ERROR_BOUNDS,
                "events.artifact_hashes",
                format!(
                    "sequence {} has {} artifact hashes, limit {MAX_ARTIFACT_HASHES_PER_EVENT}",
                    event.sequence,
                    event.artifact_hashes.len()
                ),
            ));
        }
        for (name, hash) in &event.artifact_hashes {
            if !safe_relative_path(Path::new(name)) || !is_sha256(hash) {
                findings.push(simple_finding(
                    ERROR_EVENT_SCHEMA,
                    "events.artifact_hashes",
                    format!(
                        "sequence {} has invalid artifact hash {name}={hash}",
                        event.sequence
                    ),
                ));
            }
        }
        for (field, value) in [
            ("cpu_time_ns", event.resource_delta.cpu_time_ns),
            ("wall_time_ns", event.resource_delta.wall_time_ns),
            ("max_rss_bytes", event.resource_delta.max_rss_bytes),
            ("allocated_bytes", event.resource_delta.allocated_bytes),
            ("io_read_bytes", event.resource_delta.io_read_bytes),
            ("io_write_bytes", event.resource_delta.io_write_bytes),
        ] {
            let source = event.resource_delta.measurement_sources.get(field);
            let valid = match (value, source.map(String::as_str)) {
                (Some(value), Some(source)) => {
                    value >= 0
                        && source
                            .strip_prefix("measured:")
                            .is_some_and(|detail| !detail.trim().is_empty())
                }
                (None, Some(source)) => source
                    .strip_prefix("unavailable:")
                    .is_some_and(|detail| !detail.trim().is_empty()),
                _ => false,
            };
            if !valid {
                findings.push(simple_finding(
                    ERROR_EVENT_SCHEMA,
                    "events.resource_delta",
                    format!(
                        "sequence {} resource {field} must distinguish measured nonnegative data from explicit unavailability",
                        event.sequence
                    ),
                ));
            }
        }
        if event.resource_delta.measurement_sources.len() != 6 {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.resource_delta",
                format!(
                    "sequence {} resource measurement-source map must contain exactly six fields",
                    event.sequence
                ),
            ));
        }
        if event.fallback != "none"
            && !matches!(event.decision.as_str(), "fallback" | "fail" | "rollback")
        {
            findings.push(simple_finding(
                ERROR_SILENT_FALLBACK,
                "events.fallback",
                format!(
                    "sequence {} records fallback `{}` under decision `{}`",
                    event.sequence, event.fallback, event.decision
                ),
            ));
        }
        if event.decision == "fallback" && event.fallback == "none" {
            findings.push(simple_finding(
                ERROR_SILENT_FALLBACK,
                "events.fallback",
                format!(
                    "sequence {} declares fallback without naming the fallback path",
                    event.sequence
                ),
            ));
        }
        if event.decision == "rollback" && event.rollback == "none" {
            findings.push(simple_finding(
                ERROR_EVENT_SCHEMA,
                "events.rollback",
                format!(
                    "sequence {} declares rollback without naming the rollback action",
                    event.sequence
                ),
            ));
        }
        if event.attempt > 1
            && !failed_attempts.contains(&(
                event.test_id.clone(),
                event.scenario_id.clone(),
                event.attempt - 1,
            ))
        {
            findings.push(simple_finding(
                ERROR_RETRY_MASKING,
                "events.retry",
                format!(
                    "sequence {} attempt {} has no retained attempt_failed record for attempt {}",
                    event.sequence,
                    event.attempt,
                    event.attempt - 1
                ),
            ));
        }
        if event.event == "attempt_failed" {
            failed_attempts.insert((
                event.test_id.clone(),
                event.scenario_id.clone(),
                event.attempt,
            ));
        }
        if event.event == "run_completed" {
            if completed_at.replace(index).is_some() {
                findings.push(simple_finding(
                    ERROR_ORDER_OR_DUPLICATE,
                    "events.complete",
                    "event stream has multiple run_completed records".to_string(),
                ));
            }
        } else if completed_at.is_some() {
            findings.push(simple_finding(
                ERROR_ORDER_OR_DUPLICATE,
                "events.complete",
                format!("event {} appears after run_completed", index + 1),
            ));
        }
    }
    if events.first().map(|event| event.event.as_str()) != Some("run_started") {
        findings.push(simple_finding(
            ERROR_EVENT_SCHEMA,
            "events.lifecycle",
            "event stream must begin with run_started".to_string(),
        ));
    }
    if check_count == 0 {
        findings.push(simple_finding(
            ERROR_EVENT_SCHEMA,
            "events.lifecycle",
            "event stream must contain at least one contract_check".to_string(),
        ));
    }
    if completed_at != Some(events.len() - 1) {
        findings.push(simple_finding(
            ERROR_EVENT_SCHEMA,
            "events.truncation",
            "event stream does not end with exactly one run_completed record".to_string(),
        ));
    }
    let terminal_decision = events
        .last()
        .filter(|event| event.event == "run_completed")
        .map(|event| event.decision.clone());
    if saw_nonpassing_decision && terminal_decision.as_deref() == Some("pass") {
        findings.push(simple_finding(
            ERROR_RETRY_MASKING,
            "events.terminal",
            "run_completed cannot pass after a retained non-passing decision".to_string(),
        ));
    }
    if !saw_nonpassing_decision
        && terminal_decision
            .as_deref()
            .is_some_and(|decision| decision != "pass")
    {
        findings.push(simple_finding(
            ERROR_OUTCOME_MISMATCH,
            "events.terminal",
            "non-passing run_completed has no preceding first-failure event".to_string(),
        ));
    }
    event_report(events.len(), terminal_decision, first_failure, findings)
}

fn event_report(
    event_count: usize,
    terminal_decision: Option<String>,
    first_failure: Option<FailureReference>,
    findings: Vec<ValidationFinding>,
) -> EventValidationReport {
    let error_count = findings.len();
    EventValidationReport {
        schema_version: "franken-engine.verification-event.validation-report.v1".to_string(),
        status: if error_count == 0 { "pass" } else { "fail" }.to_string(),
        event_count,
        terminal_decision,
        first_failure,
        error_count,
        findings,
    }
}

/// Validate the provisional reference probe without promoting it to certified
/// Tier R.
#[must_use]
pub fn validate_tier_r_probe(report: &TierRProbeReport) -> Vec<ValidationFinding> {
    let mut findings = Vec::new();
    if report.schema_version != TIER_R_PROBE_SCHEMA_VERSION {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.schema",
            format!(
                "probe schema {} does not equal {TIER_R_PROBE_SCHEMA_VERSION}",
                report.schema_version
            ),
        ));
    }
    if report.classification != "provisional_not_certified_tier_r" {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.classification",
            format!(
                "probe classification {} must remain provisional_not_certified_tier_r",
                report.classification
            ),
        ));
    }
    if report.implementation_truth != TIER_R_IMPLEMENTATION_TRUTH
        || !is_sha256(&report.reference_source_sha256)
        || report.reference_source_sha256 == "0".repeat(64)
        || !is_sha256(&report.build_environment_sha256)
        || report.build_environment_sha256 == "0".repeat(64)
        || !is_sha256(&report.probe_executable_sha256)
        || report.probe_executable_sha256 == "0".repeat(64)
    {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.implementation",
            "reference implementation truth or content identity is missing or misleading"
                .to_string(),
        ));
    }
    if report.run_id.trim().is_empty()
        || report.trace_id.trim().is_empty()
        || report.run_id.len() > MAX_ID_BYTES
        || report.trace_id.len() > MAX_ID_BYTES
    {
        findings.push(simple_finding(
            ERROR_BOUNDS,
            "tier_r.identity",
            "probe run_id and trace_id must be nonblank and bounded".to_string(),
        ));
    }
    if report.status != "pass" || report.scenarios.len() != TIER_R_PROBE_CASES.len() {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.coverage",
            format!(
                "probe status {} with {} scenarios does not match the exact {}-case reference corpus",
                report.status,
                report.scenarios.len(),
                TIER_R_PROBE_CASES.len()
            ),
        ));
    }
    let mut scenario_ids = BTreeSet::new();
    let mut expected_stage_events = Vec::new();
    for scenario in &report.scenarios {
        if !scenario_ids.insert(scenario.scenario_id.as_str()) {
            findings.push(simple_finding(
                ERROR_ORDER_OR_DUPLICATE,
                "tier_r.scenario",
                format!("duplicate scenario {}", scenario.scenario_id),
            ));
        }
        let Some((_, source, expected)) = TIER_R_PROBE_CASES
            .iter()
            .find(|(scenario_id, _, _)| *scenario_id == scenario.scenario_id)
        else {
            findings.push(simple_finding(
                ERROR_TIER_R_TRUTH,
                "tier_r.scenario",
                format!("unknown scenario {}", scenario.scenario_id),
            ));
            continue;
        };
        let expected_digest = tier_r_expected_semantic_digest(expected);
        if scenario.decision != "pass"
            || scenario.expected_value != *expected
            || scenario.reference_value != *expected
            || scenario.source_sha256 != sha256_hex(source.as_bytes())
            || !is_sha256(&scenario.reference_ir_sha256)
            || scenario.reference_ir_sha256 == "0".repeat(64)
            || scenario.reference_instructions == 0
            || !scenario
                .reference_events
                .iter()
                .any(|event| event == "execution_started")
            || !scenario
                .reference_events
                .iter()
                .any(|event| event == "execution_completed")
            || scenario.expected_semantic_digest != expected_digest
            || scenario.reference_semantic_digest != expected_digest
        {
            findings.push(simple_finding(
                ERROR_TIER_R_TRUTH,
                "tier_r.scenario",
                format!(
                    "scenario {} lacks its exact source/value oracle, IR identity, branch events, nonzero execution, or observable equality",
                    scenario.scenario_id
                ),
            ));
        }
        let source_hash = sha256_hex(source.as_bytes());
        expected_stage_events.extend([
            TierRStageEvent {
                sequence: 0,
                scenario_id: scenario.scenario_id.clone(),
                stage: "reference_parse_completed".to_string(),
                input_sha256: source_hash.clone(),
                output_sha256: source_hash,
                decision: "pass".to_string(),
            },
            TierRStageEvent {
                sequence: 0,
                scenario_id: scenario.scenario_id.clone(),
                stage: "reference_lowering_completed".to_string(),
                input_sha256: scenario.source_sha256.clone(),
                output_sha256: scenario.reference_ir_sha256.clone(),
                decision: "pass".to_string(),
            },
            TierRStageEvent {
                sequence: 0,
                scenario_id: scenario.scenario_id.clone(),
                stage: "reference_execution_started".to_string(),
                input_sha256: scenario.reference_ir_sha256.clone(),
                output_sha256: scenario.reference_ir_sha256.clone(),
                decision: "pass".to_string(),
            },
            TierRStageEvent {
                sequence: 0,
                scenario_id: scenario.scenario_id.clone(),
                stage: "reference_execution_completed".to_string(),
                input_sha256: scenario.reference_ir_sha256.clone(),
                output_sha256: scenario.reference_semantic_digest.clone(),
                decision: "pass".to_string(),
            },
            TierRStageEvent {
                sequence: 0,
                scenario_id: scenario.scenario_id.clone(),
                stage: "expected_observable_equal".to_string(),
                input_sha256: scenario.expected_semantic_digest.clone(),
                output_sha256: scenario.reference_semantic_digest.clone(),
                decision: "pass".to_string(),
            },
        ]);
    }
    if report.denial.decision != "deny"
        || report.denial.error_class != "CapabilityDenied"
        || report.denial.capability != "VmDispatch"
    {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.denial",
            "reference probe did not prove fail-closed VmDispatch denial".to_string(),
        ));
    }
    let denial_hash = sha256_hex(b"VmDispatch");
    expected_stage_events.push(TierRStageEvent {
        sequence: 0,
        scenario_id: report.denial.scenario_id.clone(),
        stage: "reference_capability_denied".to_string(),
        input_sha256: denial_hash.clone(),
        output_sha256: denial_hash,
        decision: "deny".to_string(),
    });
    for (index, event) in expected_stage_events.iter_mut().enumerate() {
        event.sequence = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
    }
    if report.stage_events != expected_stage_events {
        findings.push(simple_finding(
            ERROR_BRANCH_PROOF,
            "tier_r.instrumentation",
            "run-bound Tier-R stage events are missing, reordered, duplicated, or inconsistent with scenario digests"
                .to_string(),
        ));
    }
    let expected_signals: Vec<String> = TIER_R_BRANCH_SIGNALS
        .iter()
        .map(|signal| (*signal).to_string())
        .collect();
    if report.branch_signals != expected_signals {
        findings.push(simple_finding(
            ERROR_BRANCH_PROOF,
            "tier_r.signal",
            "reference probe branch signals are missing, duplicated, reordered, or fabricated"
                .to_string(),
        ));
    }
    findings
}

fn canonical_tier_r_source_manifest_bytes(
    manifest: &TierRSourceManifest,
) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|error| format!("{ERROR_JSON}: serialize Tier-R source manifest: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn validate_tier_r_source_manifest(manifest: &TierRSourceManifest) -> Vec<ValidationFinding> {
    let mut findings = Vec::new();
    if manifest.schema_version != "franken-engine.tier-r-source-manifest.v1"
        || manifest.hash_algorithm != "sha256"
        || manifest.identity_basis != "canonical-json-path-bytes-content-sha256-v1"
    {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.source_manifest",
            "Tier-R source manifest schema, hash algorithm, or identity basis differs".to_string(),
        ));
    }
    if manifest.files.is_empty() || manifest.files.len() > MAX_HARNESS_SCAN_FILES {
        findings.push(simple_finding(
            ERROR_BOUNDS,
            "tier_r.source_manifest",
            "Tier-R source manifest file count is empty or exceeds its bound".to_string(),
        ));
    }
    let mut previous_path: Option<&str> = None;
    let mut paths = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for entry in &manifest.files {
        if !safe_relative_path(Path::new(&entry.path))
            || !paths.insert(entry.path.as_str())
            || previous_path.is_some_and(|previous| previous >= entry.path.as_str())
            || !is_sha256(&entry.sha256)
            || entry.bytes > MAX_BUNDLE_TOTAL_BYTES
        {
            findings.push(simple_finding(
                ERROR_TIER_R_TRUTH,
                "tier_r.source_manifest",
                format!(
                    "Tier-R source entry {} is unsafe, unordered, duplicate, unbounded, or unhashed",
                    entry.path
                ),
            ));
        }
        previous_path = Some(entry.path.as_str());
        total_bytes = total_bytes.saturating_add(entry.bytes);
    }
    if total_bytes > MAX_BUNDLE_TOTAL_BYTES {
        findings.push(simple_finding(
            ERROR_BOUNDS,
            "tier_r.source_manifest",
            "Tier-R source manifest aggregate input bytes exceed the bound".to_string(),
        ));
    }
    for required in [
        "Cargo.toml",
        "Cargo.lock",
        "tools/execution-truth-ledger/Cargo.toml",
        "tools/execution-truth-ledger/Cargo.lock",
        "tools/execution-truth-ledger/build.rs",
        "tools/execution-truth-ledger/src/lib.rs",
        "tools/execution-truth-ledger/src/tier_r_probe.rs",
        "crates/franken-engine/src/verification_coverage_contract.rs",
        "crates/franken-engine/src/bin/franken_verification_coverage_contract.rs",
        "crates/franken-core/Cargo.toml",
        "crates/franken-extension-host/Cargo.toml",
    ] {
        if !paths.contains(required) {
            findings.push(simple_finding(
                ERROR_TIER_R_TRUTH,
                "tier_r.source_manifest",
                format!("Tier-R source manifest omits required build input {required}"),
            ));
        }
    }
    if !paths
        .iter()
        .any(|path| path.starts_with("crates/franken-core/src/") && path.ends_with(".rs"))
    {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.source_manifest",
            "Tier-R source manifest omits the franken-core Rust source closure".to_string(),
        ));
    }
    if !paths
        .iter()
        .any(|path| path.starts_with("crates/franken-extension-host/src/") && path.ends_with(".rs"))
    {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.source_manifest",
            "Tier-R source manifest omits the local extension-host Rust dependency closure"
                .to_string(),
        ));
    }
    findings
}

fn canonical_tier_r_build_environment_bytes(
    environment: &TierRBuildEnvironment,
) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(environment)
        .map_err(|error| format!("{ERROR_JSON}: serialize Tier-R build environment: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[must_use]
pub fn validate_tier_r_build_environment(
    environment: &TierRBuildEnvironment,
) -> Vec<ValidationFinding> {
    let mut findings = Vec::new();
    if environment.schema_version != "franken-engine.tier-r-build-environment.v1"
        || environment.rustc_verbose_version.trim().is_empty()
        || environment.cargo_version.trim().is_empty()
        || environment.host.trim().is_empty()
        || environment.target.trim().is_empty()
        || environment.profile != "release"
        || environment.opt_level != "3"
        || !is_sha256(&environment.build_flags_sha256)
        || !is_sha256(&environment.source_manifest_sha256)
    {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.build_environment",
            "Tier-R builder compiler, target, profile, flags, or source identity is missing or invalid"
                .to_string(),
        ));
    }
    if environment.rustc_verbose_version.len() > 8 * 1024
        || environment.cargo_version.len() > 1024
        || environment.host.len() > MAX_ID_BYTES
        || environment.target.len() > MAX_ID_BYTES
        || environment
            .requested_toolchain
            .as_ref()
            .is_some_and(|toolchain| toolchain.trim().is_empty() || toolchain.len() > MAX_ID_BYTES)
        || !matches!(
            environment.build_flags_source.as_str(),
            "CARGO_ENCODED_RUSTFLAGS" | "RUSTFLAGS" | "none"
        )
    {
        findings.push(simple_finding(
            ERROR_BOUNDS,
            "tier_r.build_environment",
            "Tier-R builder environment strings or classifications are invalid".to_string(),
        ));
    }
    let mut sorted_features = environment.active_features.clone();
    sorted_features.sort();
    sorted_features.dedup();
    if sorted_features != environment.active_features
        || !environment
            .active_features
            .iter()
            .any(|feature| feature == "CARGO_FEATURE_TIER_R_PROBE")
    {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.build_environment",
            "Tier-R builder feature set is unordered, duplicate, or omits tier-r-probe".to_string(),
        ));
    }
    let builder_identity_valid = match (
        environment.builder_identity_source.as_str(),
        environment.builder_identity_sha256.as_deref(),
    ) {
        ("RCH_WORKER_ID" | "RCH_WORKER" | "HOSTNAME", Some(identity)) => is_sha256(identity),
        ("unavailable", None) => true,
        _ => false,
    };
    if !builder_identity_valid {
        findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "tier_r.build_environment",
            "Tier-R descriptive builder identity source and digest are inconsistent; this field is not an attestation"
                .to_string(),
        ));
    }
    findings
}

/// Digest the independently declared observable result for a Tier-R probe
/// case. Instruction counts and internal object identities are deliberately
/// excluded because an independent reference implementation may lower the same
/// semantics differently.
#[must_use]
pub fn tier_r_expected_semantic_digest(expected_value: &str) -> String {
    let payload = serde_json::json!({
        "value": expected_value,
        "console": [],
        "hostcalls": [],
        "hook_action": "none",
    });
    sha256_hex(
        &serde_json::to_vec(&payload)
            .expect("Tier-R expected-observable payload is infallibly serializable"),
    )
}

/// Bind a minimized deterministic seed to the exact replay command that
/// reconstructs it. The original input remains a separate commitment, while
/// this digest is recomputable from the retained bundle.
#[must_use]
pub fn minimized_seed_identity(seed: u64, reproduction_command: &str) -> String {
    let payload = serde_json::json!({
        "seed": seed,
        "reproduction_command": reproduction_command,
    });
    sha256_hex(
        &serde_json::to_vec(&payload)
            .expect("minimized-seed identity payload is infallibly serializable"),
    )
}

/// Write unified events atomically without replacing an existing artifact.
pub fn write_events_jsonl(path: &Path, events: &[VerificationEvent]) -> Result<(), String> {
    let mut bytes = Vec::new();
    for event in events {
        serde_json::to_writer(&mut bytes, event)
            .map_err(|error| format!("{ERROR_JSON}: serialize event: {error}"))?;
        bytes.push(b'\n');
    }
    let report = validate_event_stream(&bytes);
    if report.error_count != 0 {
        return Err(format!(
            "{ERROR_EVENT_SCHEMA}: refusing to publish invalid event stream: {:?}",
            report.findings
        ));
    }
    write_bytes_no_replace(path, &bytes)
}

/// Hash every regular bundle file except `artifact_manifest.json` and publish
/// the sorted manifest without replacement.
pub fn write_artifact_manifest(bundle_dir: &Path) -> Result<ArtifactManifest, String> {
    let metadata = fs::symlink_metadata(bundle_dir)
        .map_err(|error| format!("{ERROR_IO}: inspect {}: {error}", bundle_dir.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "{ERROR_UNSAFE_PATH}: bundle root {} must be a real directory",
            bundle_dir.display()
        ));
    }
    let mut files = walk_bundle_files(bundle_dir)?;
    files.retain(|path| path != "artifact_manifest.json");
    let mut digests = Vec::with_capacity(files.len());
    for path in files {
        let bytes = read_bounded_regular_file(&bundle_dir.join(&path), MAX_BUNDLE_FILE_BYTES)
            .map_err(|reason| format!("{reason}; bundle file {path}"))?;
        digests.push(ArtifactDigest {
            path,
            sha256: sha256_hex(&bytes),
            bytes: bytes.len() as u64,
        });
    }
    let manifest = ArtifactManifest {
        schema_version: ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
        hash_algorithm: "sha256".to_string(),
        files: digests,
    };
    let mut bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("{ERROR_JSON}: serialize artifact manifest: {error}"))?;
    bytes.push(b'\n');
    write_bytes_no_replace(&bundle_dir.join("artifact_manifest.json"), &bytes)?;
    Ok(manifest)
}

/// Validate a complete verification bundle, including event semantics,
/// reference-path truth, guest-output separation, provenance, and all hashes.
#[must_use]
pub fn validate_bundle(bundle_dir: &Path) -> BundleValidationReport {
    let mut findings = Vec::new();
    let mut checked_files = 0;
    let mut event_count = 0;
    let metadata = match fs::symlink_metadata(bundle_dir) {
        Ok(metadata) => metadata,
        Err(error) => {
            findings.push(simple_finding(
                ERROR_IO,
                "bundle.root",
                format!("inspect {}: {error}", bundle_dir.display()),
            ));
            return bundle_report(bundle_dir, 0, 0, findings);
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        findings.push(simple_finding(
            ERROR_UNSAFE_PATH,
            "bundle.root",
            format!("{} is not a real directory", bundle_dir.display()),
        ));
        return bundle_report(bundle_dir, 0, 0, findings);
    }
    let actual_files = match walk_bundle_files(bundle_dir) {
        Ok(files) => files,
        Err(reason) => {
            findings.push(simple_finding(
                if reason.contains(ERROR_UNSAFE_PATH) {
                    ERROR_UNSAFE_PATH
                } else if reason.contains(ERROR_BOUNDS) {
                    ERROR_BOUNDS
                } else {
                    ERROR_IO
                },
                "bundle.walk",
                reason,
            ));
            return bundle_report(bundle_dir, 0, 0, findings);
        }
    };
    for required in REQUIRED_ARTIFACT_FILES {
        if actual_files
            .binary_search_by(|candidate| candidate.as_str().cmp(required))
            .is_ok()
        {
            checked_files += 1;
        } else {
            findings.push(simple_finding(
                ERROR_BUNDLE_INCOMPLETE,
                "bundle.required",
                format!("missing required regular non-symlink artifact {required}"),
            ));
        }
    }
    if !findings.is_empty() {
        return bundle_report(bundle_dir, checked_files, event_count, findings);
    }

    let run_manifest: RunManifest =
        match parse_json_file(&bundle_dir.join("run_manifest.json"), 1024 * 1024) {
            Ok(manifest) => manifest,
            Err(reason) => {
                findings.push(simple_finding(
                    ERROR_ARTIFACT_CONTRACT,
                    "bundle.run_manifest",
                    reason,
                ));
                return bundle_report(bundle_dir, checked_files, event_count, findings);
            }
        };
    if run_manifest.schema_version != RUN_MANIFEST_SCHEMA_VERSION
        || run_manifest.artifact_manifest != "artifact_manifest.json"
        || run_manifest.contract != "contract.json"
        || run_manifest.generated_contract != "generated_contract.json"
        || run_manifest.rendered_markdown != "rendered_contract.md"
        || run_manifest.validation_report != "validation_report.json"
        || run_manifest.events != "events.jsonl"
        || run_manifest.tier_r_probe != "tier_r_probe.json"
        || run_manifest.tier_r_source_manifest != "tier_r_source_manifest.json"
        || run_manifest.tier_r_build_environment != "tier_r_build_environment.json"
        || run_manifest.guest_stdout != "guest.stdout.log"
        || run_manifest.guest_stderr != "guest.stderr.log"
    {
        findings.push(simple_finding(
            ERROR_ARTIFACT_CONTRACT,
            "bundle.run_manifest",
            "run manifest schema or canonical file bindings differ".to_string(),
        ));
    }
    for (field, value) in [
        ("run_id", run_manifest.run_id.as_str()),
        ("trace_id", run_manifest.trace_id.as_str()),
        ("test_id", run_manifest.test_id.as_str()),
        ("scenario_id", run_manifest.scenario_id.as_str()),
        ("platform", run_manifest.platform.as_str()),
        ("target", run_manifest.target.as_str()),
        ("tier", run_manifest.tier.as_str()),
        ("security_profile", run_manifest.security_profile.as_str()),
        (
            "reproduction_command",
            run_manifest.reproduction_command.as_str(),
        ),
    ] {
        if value.trim().is_empty() || value.len() > MAX_ID_BYTES.saturating_mul(8) {
            findings.push(simple_finding(
                ERROR_ARTIFACT_CONTRACT,
                "bundle.run_manifest",
                format!("{field} must be nonblank and bounded"),
            ));
        }
    }
    if run_manifest.attempt == 0 || run_manifest.clock_source != "witnessed_wall_clock" {
        findings.push(simple_finding(
            ERROR_CLOCK_AUTHORITY,
            "bundle.run_manifest",
            "attempt must be nonzero and certifying bundles require witnessed_wall_clock"
                .to_string(),
        ));
    }
    if (run_manifest.observed_outcome.is_success() && run_manifest.exit_code != 0)
        || (!run_manifest.observed_outcome.is_success() && run_manifest.exit_code == 0)
        || (run_manifest.observed_outcome.is_success() && run_manifest.first_failure.is_some())
        || (!run_manifest.observed_outcome.is_success() && run_manifest.first_failure.is_none())
    {
        findings.push(simple_finding(
            ERROR_OUTCOME_MISMATCH,
            "bundle.exit_status",
            format!(
                "expected {:?} / observed {:?} / exit {} / first_failure {:?} does not truthfully encode the observed process result",
                run_manifest.expected_outcome,
                run_manifest.observed_outcome,
                run_manifest.exit_code,
                run_manifest.first_failure
            ),
        ));
    }
    if DateTime::parse_from_rfc3339(&run_manifest.created_at_utc)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .is_none_or(|timestamp| {
            timestamp > Utc::now() + chrono::Duration::minutes(5)
                || Utc::now().signed_duration_since(timestamp)
                    > chrono::Duration::days(i64::try_from(MAX_AGE_DAYS).unwrap_or(i64::MAX))
        })
    {
        findings.push(simple_finding(
            ERROR_CLOCK_AUTHORITY,
            "bundle.time",
            format!("created_at_utc is invalid, future-dated, or older than {MAX_AGE_DAYS} days"),
        ));
    }
    if !safe_relative_path(Path::new(&run_manifest.sample_artifact.path))
        || !matches!(
            (
                &run_manifest.sample_artifact.kind,
                run_manifest.sample_artifact.path.as_str()
            ),
            (SampleArtifactKind::RawSamples, "samples.jsonl")
                | (SampleArtifactKind::MinimizedSeed, "minimized_seed.json")
        )
    {
        findings.push(simple_finding(
            ERROR_ARTIFACT_CONTRACT,
            "bundle.samples",
            "sample_artifact must select exactly samples.jsonl or minimized_seed.json".to_string(),
        ));
    }
    let present_sample_alternatives = ["samples.jsonl", "minimized_seed.json"]
        .iter()
        .filter(|candidate| {
            actual_files
                .binary_search_by(|path| path.as_str().cmp(candidate))
                .is_ok()
        })
        .count();
    if present_sample_alternatives != 1 {
        findings.push(simple_finding(
            ERROR_ARTIFACT_CONTRACT,
            "bundle.samples",
            format!(
                "bundle must contain exactly one sample alternative, found {present_sample_alternatives}"
            ),
        ));
    }
    let mut required_files = run_manifest.required_files.clone();
    let original_required_files = required_files.clone();
    required_files.sort();
    required_files.dedup();
    if required_files != original_required_files || required_files != actual_files {
        findings.push(simple_finding(
            ERROR_ARTIFACT_CONTRACT,
            "bundle.run_manifest",
            "run_manifest.required_files must be the sorted exact bundle inventory".to_string(),
        ));
    }

    let artifact_manifest: ArtifactManifest =
        match parse_json_file(&bundle_dir.join("artifact_manifest.json"), 4 * 1024 * 1024) {
            Ok(manifest) => manifest,
            Err(reason) => {
                findings.push(simple_finding(
                    ERROR_ARTIFACT_CONTRACT,
                    "bundle.artifact_manifest",
                    reason,
                ));
                return bundle_report(bundle_dir, checked_files, event_count, findings);
            }
        };
    if artifact_manifest.schema_version != ARTIFACT_MANIFEST_SCHEMA_VERSION
        || artifact_manifest.hash_algorithm != "sha256"
    {
        findings.push(simple_finding(
            ERROR_ARTIFACT_CONTRACT,
            "bundle.artifact_manifest",
            "artifact manifest schema/hash algorithm differs".to_string(),
        ));
    }
    match read_bounded_regular_file(&bundle_dir.join("artifact_manifest.json"), 4 * 1024 * 1024) {
        Ok(bytes) => match std::str::from_utf8(&bytes) {
            Ok(text) if contains_secret_marker(text) => findings.push(simple_finding(
                ERROR_SECRET_LEAK,
                "bundle.redaction",
                "artifact_manifest.json contains an unredacted secret marker/value".to_string(),
            )),
            Ok(_) => {}
            Err(error) => findings.push(simple_finding(
                ERROR_ARTIFACT_CONTRACT,
                "bundle.text",
                format!("artifact_manifest.json is not UTF-8: {error}"),
            )),
        },
        Err(reason) => findings.push(simple_finding(ERROR_IO, "bundle.text", reason)),
    }
    let manifest_paths: Vec<&str> = artifact_manifest
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    let mut sorted_manifest_paths = manifest_paths.clone();
    sorted_manifest_paths.sort_unstable();
    let unique_manifest_paths: BTreeSet<_> = manifest_paths.iter().copied().collect();
    if manifest_paths != sorted_manifest_paths
        || unique_manifest_paths.len() != manifest_paths.len()
    {
        findings.push(simple_finding(
            ERROR_ORDER_OR_DUPLICATE,
            "bundle.artifact_manifest",
            "artifact paths are unsorted or duplicate".to_string(),
        ));
    }
    let actual_without_manifest: Vec<String> = actual_files
        .iter()
        .filter(|path| *path != "artifact_manifest.json")
        .cloned()
        .collect();
    if actual_without_manifest
        != artifact_manifest
            .files
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>()
    {
        findings.push(simple_finding(
            ERROR_ARTIFACT_CONTRACT,
            "bundle.artifact_manifest",
            "artifact manifest does not enumerate every and only non-manifest file".to_string(),
        ));
    }
    let mut artifact_index = BTreeMap::new();
    for entry in &artifact_manifest.files {
        if !safe_relative_path(Path::new(&entry.path)) || !is_sha256(&entry.sha256) {
            findings.push(simple_finding(
                ERROR_UNSAFE_PATH,
                "bundle.artifact",
                format!("invalid artifact entry {}", entry.path),
            ));
            continue;
        }
        if artifact_index.insert(entry.path.clone(), entry).is_some() {
            findings.push(simple_finding(
                ERROR_ORDER_OR_DUPLICATE,
                "bundle.artifact",
                format!("duplicate artifact entry {}", entry.path),
            ));
            continue;
        }
        match read_bounded_regular_file(&bundle_dir.join(&entry.path), MAX_BUNDLE_FILE_BYTES) {
            Ok(bytes)
                if bytes.len() as u64 == entry.bytes && sha256_hex(&bytes) == entry.sha256 =>
            {
                checked_files += 1;
            }
            Ok(bytes) => findings.push(simple_finding(
                ERROR_HASH_DRIFT,
                "bundle.artifact",
                format!(
                    "{} expected {} bytes/{}, got {} bytes/{}",
                    entry.path,
                    entry.bytes,
                    entry.sha256,
                    bytes.len(),
                    sha256_hex(&bytes)
                ),
            )),
            Err(error) => findings.push(simple_finding(
                ERROR_IO,
                "bundle.artifact",
                format!("read {}: {error}", entry.path),
            )),
        }
    }
    for required in REQUIRED_ARTIFACT_FILES
        .iter()
        .copied()
        .filter(|path| *path != "artifact_manifest.json")
        .chain(std::iter::once(run_manifest.sample_artifact.path.as_str()))
    {
        if !artifact_index.contains_key(required) {
            findings.push(simple_finding(
                ERROR_BUNDLE_INCOMPLETE,
                "bundle.artifact_manifest",
                format!("artifact manifest omits mandatory artifact {required}"),
            ));
        }
    }

    let contract_copy = parse_json_file::<VerificationCoverageContract>(
        &bundle_dir.join("contract.json"),
        MAX_CONTRACT_BYTES,
    );
    let generated_copy = parse_json_file::<VerificationCoverageContract>(
        &bundle_dir.join("generated_contract.json"),
        MAX_CONTRACT_BYTES,
    );
    match (&contract_copy, &generated_copy) {
        (Ok(contract), Ok(generated)) => {
            for (path, value) in [
                ("contract.json", contract),
                ("generated_contract.json", generated),
            ] {
                match (
                    canonical_json_bytes(value),
                    read_bounded_regular_file(&bundle_dir.join(path), MAX_CONTRACT_BYTES),
                ) {
                    (Ok(expected), Ok(actual)) if expected == actual => {}
                    _ => findings.push(simple_finding(
                        ERROR_ARTIFACT_CONTRACT,
                        "bundle.contract_copy",
                        format!("{path} is not strict canonical contract JSON"),
                    )),
                }
            }
            if run_manifest.observed_outcome == RunOutcome::Pass && contract != generated {
                findings.push(simple_finding(
                    ERROR_GENERATION_DRIFT,
                    "bundle.contract_copy",
                    "a passing run must retain byte-identical committed and live-generated contracts"
                        .to_string(),
                ));
            }
            match read_bounded_regular_file(
                &bundle_dir.join("rendered_contract.md"),
                MAX_CONTRACT_BYTES,
            ) {
                Ok(markdown) if markdown == render_markdown(contract).as_bytes() => {}
                _ => findings.push(simple_finding(
                    ERROR_MARKDOWN_DRIFT,
                    "bundle.rendered_contract",
                    "rendered_contract.md differs from the retained canonical contract".to_string(),
                )),
            }
        }
        (Err(reason), _) | (_, Err(reason)) => findings.push(simple_finding(
            ERROR_ARTIFACT_CONTRACT,
            "bundle.contract_copy",
            reason.clone(),
        )),
    }

    let mut parsed_events = Vec::new();
    match read_bounded_regular_file(
        &bundle_dir.join("events.jsonl"),
        MAX_EVENT_STREAM_BYTES as u64,
    ) {
        Ok(bytes) => {
            let report = validate_event_stream(&bytes);
            event_count = report.event_count;
            findings.extend(report.findings.clone());
            parsed_events = bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .filter_map(|line| serde_json::from_slice::<VerificationEvent>(line).ok())
                .collect();
            if let Some(first) = parsed_events.first()
                && (first.run_id != run_manifest.run_id
                    || first.trace_id != run_manifest.trace_id
                    || first.test_id != run_manifest.test_id
                    || first.scenario_id != run_manifest.scenario_id
                    || first.seed != run_manifest.seed
                    || first.attempt != run_manifest.attempt
                    || first.platform != run_manifest.platform
                    || first.target != run_manifest.target
                    || first.tier != run_manifest.tier
                    || first.security_profile != run_manifest.security_profile)
            {
                findings.push(simple_finding(
                    ERROR_PROVENANCE,
                    "bundle.event_identity",
                    "event identity/context does not match run manifest".to_string(),
                ));
            }
            if report.terminal_decision.as_deref() != Some(run_manifest.observed_outcome.label())
                || report.first_failure != run_manifest.first_failure
            {
                findings.push(simple_finding(
                    ERROR_OUTCOME_MISMATCH,
                    "bundle.event_outcome",
                    format!(
                        "event terminal/first failure {:?}/{:?} differs from manifest {:?}/{:?}",
                        report.terminal_decision,
                        report.first_failure,
                        run_manifest.observed_outcome,
                        run_manifest.first_failure
                    ),
                ));
            }
        }
        Err(error) => findings.push(simple_finding(
            ERROR_IO,
            "bundle.events",
            format!("read events.jsonl: {error}"),
        )),
    }
    for event in &parsed_events {
        for (path, hash) in &event.artifact_hashes {
            match artifact_index.get(path) {
                Some(entry) if entry.sha256 == *hash => {}
                Some(entry) => findings.push(simple_finding(
                    ERROR_PROVENANCE,
                    "bundle.event_artifact",
                    format!(
                        "event sequence {} binds {path} to {hash}, manifest has {}",
                        event.sequence, entry.sha256
                    ),
                )),
                None => findings.push(simple_finding(
                    ERROR_PROVENANCE,
                    "bundle.event_artifact",
                    format!(
                        "event sequence {} binds unmanifested artifact {path}",
                        event.sequence
                    ),
                )),
            }
        }
    }

    let tier_path = bundle_dir.join("tier_r_probe.json");
    let tier_probe = match parse_json_file::<TierRProbeReport>(&tier_path, 4 * 1024 * 1024) {
        Ok(probe) => {
            if probe.run_id != run_manifest.run_id || probe.trace_id != run_manifest.trace_id {
                findings.push(simple_finding(
                    ERROR_PROVENANCE,
                    "bundle.tier_r_identity",
                    "Tier-R probe run/trace does not match run manifest".to_string(),
                ));
            }
            findings.extend(validate_tier_r_probe(&probe));
            Some(probe)
        }
        Err(reason) => {
            findings.push(simple_finding(
                ERROR_TIER_R_TRUTH,
                "bundle.tier_r_probe",
                reason,
            ));
            None
        }
    };
    let tier_source_manifest_sha = match read_bounded_regular_file(
        &bundle_dir.join("tier_r_source_manifest.json"),
        MAX_BUNDLE_FILE_BYTES,
    ) {
        Ok(bytes) => match serde_json::from_slice::<TierRSourceManifest>(&bytes) {
            Ok(source_manifest) => {
                findings.extend(validate_tier_r_source_manifest(&source_manifest));
                match canonical_tier_r_source_manifest_bytes(&source_manifest) {
                    Ok(canonical) if canonical == bytes => {}
                    _ => findings.push(simple_finding(
                        ERROR_TIER_R_TRUTH,
                        "bundle.tier_r_source_manifest",
                        "Tier-R source manifest is not strict canonical JSON".to_string(),
                    )),
                }
                let manifest_sha = sha256_hex(&bytes);
                if artifact_index
                    .get("tier_r_source_manifest.json")
                    .is_none_or(|entry| entry.sha256 != manifest_sha)
                    || tier_probe
                        .as_ref()
                        .is_none_or(|probe| probe.reference_source_sha256 != manifest_sha)
                {
                    findings.push(simple_finding(
                        ERROR_TIER_R_TRUTH,
                        "bundle.tier_r_source_manifest",
                        "Tier-R probe source identity is not bound to the manifested canonical source closure"
                            .to_string(),
                        ));
                }
                let expected_source_artifacts: BTreeSet<String> = source_manifest
                    .files
                    .iter()
                    .map(|entry| format!("tier_r_source/{}", entry.path))
                    .collect();
                let manifested_source_artifacts: BTreeSet<String> = artifact_index
                    .keys()
                    .filter(|path| path.starts_with("tier_r_source/"))
                    .cloned()
                    .collect();
                if expected_source_artifacts != manifested_source_artifacts {
                    findings.push(simple_finding(
                        ERROR_TIER_R_TRUTH,
                        "bundle.tier_r_source_manifest",
                        "retained Tier-R source files do not exactly match the source manifest"
                            .to_string(),
                    ));
                }
                for entry in &source_manifest.files {
                    let artifact_path = format!("tier_r_source/{}", entry.path);
                    if artifact_index.get(&artifact_path).is_none_or(|artifact| {
                        artifact.bytes != entry.bytes || artifact.sha256 != entry.sha256
                    }) {
                        findings.push(simple_finding(
                            ERROR_TIER_R_TRUTH,
                            "bundle.tier_r_source_manifest",
                            format!(
                                "retained Tier-R source {artifact_path} does not match its byte/hash commitment"
                            ),
                        ));
                    }
                }
                Some(manifest_sha)
            }
            Err(error) => {
                findings.push(simple_finding(
                    ERROR_TIER_R_TRUTH,
                    "bundle.tier_r_source_manifest",
                    format!("parse Tier-R source manifest: {error}"),
                ));
                None
            }
        },
        Err(reason) => {
            findings.push(simple_finding(
                ERROR_TIER_R_TRUTH,
                "bundle.tier_r_source_manifest",
                reason,
            ));
            None
        }
    };
    let tier_build_environment = match read_bounded_regular_file(
        &bundle_dir.join("tier_r_build_environment.json"),
        MAX_BUNDLE_FILE_BYTES,
    ) {
        Ok(bytes) => match serde_json::from_slice::<TierRBuildEnvironment>(&bytes) {
            Ok(build_environment) => {
                findings.extend(validate_tier_r_build_environment(&build_environment));
                match canonical_tier_r_build_environment_bytes(&build_environment) {
                    Ok(canonical) if canonical == bytes => {}
                    _ => findings.push(simple_finding(
                        ERROR_TIER_R_TRUTH,
                        "bundle.tier_r_build_environment",
                        "Tier-R build environment is not strict canonical JSON".to_string(),
                    )),
                }
                let build_environment_sha = sha256_hex(&bytes);
                if artifact_index
                    .get("tier_r_build_environment.json")
                    .is_none_or(|entry| entry.sha256 != build_environment_sha)
                    || tier_probe
                        .as_ref()
                        .is_none_or(|probe| probe.build_environment_sha256 != build_environment_sha)
                    || tier_source_manifest_sha.as_ref().is_none_or(|source_sha| {
                        build_environment.source_manifest_sha256 != *source_sha
                    })
                    || build_environment.target != run_manifest.target
                {
                    findings.push(simple_finding(
                        ERROR_TIER_R_TRUTH,
                        "bundle.tier_r_build_environment",
                        "Tier-R builder identity, target, source closure, artifact manifest, or probe binding differs"
                            .to_string(),
                    ));
                }
                Some((build_environment, build_environment_sha))
            }
            Err(error) => {
                findings.push(simple_finding(
                    ERROR_TIER_R_TRUTH,
                    "bundle.tier_r_build_environment",
                    format!("parse Tier-R build environment: {error}"),
                ));
                None
            }
        },
        Err(reason) => {
            findings.push(simple_finding(
                ERROR_TIER_R_TRUTH,
                "bundle.tier_r_build_environment",
                reason,
            ));
            None
        }
    };

    for nonempty in [
        "commands.txt",
        run_manifest.sample_artifact.path.as_str(),
        "repro.lock",
        "LEGAL.md",
        "tier_r_source_manifest.json",
        "tier_r_build_environment.json",
    ] {
        match artifact_index.get(nonempty) {
            Some(entry) if entry.bytes > 0 => {}
            Some(_) => findings.push(simple_finding(
                ERROR_BUNDLE_INCOMPLETE,
                "bundle.nonempty",
                format!("{nonempty} is empty"),
            )),
            None => findings.push(simple_finding(
                ERROR_BUNDLE_INCOMPLETE,
                "bundle.nonempty",
                format!("{nonempty} is not manifested"),
            )),
        }
    }

    let environment =
        parse_json_file::<EnvironmentManifest>(&bundle_dir.join("env.json"), 1024 * 1024);
    let environment = match environment {
        Ok(environment)
            if environment.schema_version == "franken-engine.verification-environment.v2"
                && environment.platform == run_manifest.platform
                && environment.target == run_manifest.target
                && environment.tier == run_manifest.tier
                && environment.security_profile == run_manifest.security_profile
                && !environment.rustc_version.trim().is_empty()
                && !environment.cargo_version.trim().is_empty()
                && !environment.toolchain.trim().is_empty()
                && environment.toolchain_role == "local_orchestrator"
                && is_git_object_id(&environment.repository_revision)
                && matches!(environment.source_state.as_str(), "clean" | "dirty")
                && environment.source_tree_basis
                    == "sorted-relative-path-mode-length-and-bytes-sha256-v1"
                && !environment.source_identity_command.trim().is_empty()
                && environment.source_identity_command.len() <= MAX_ID_BYTES.saturating_mul(8)
                && is_sha256(&environment.source_tree_sha256)
                && ((environment.source_state == "clean"
                    && environment.source_diff_basis.is_none()
                    && environment.source_diff_sha256.is_none())
                    || (environment.source_state == "dirty"
                        && environment.source_diff_basis.as_deref()
                            == Some("git-binary-patch-including-untracked-v1")
                        && environment
                            .source_diff_sha256
                            .as_deref()
                            .is_some_and(is_sha256))) =>
        {
            Some(environment)
        }
        Ok(_) => {
            findings.push(simple_finding(
                ERROR_ARTIFACT_CONTRACT,
                "bundle.environment",
                "env.json schema, run context, toolchain, or source identity is incomplete"
                    .to_string(),
            ));
            None
        }
        Err(reason) => {
            findings.push(simple_finding(
                ERROR_ARTIFACT_CONTRACT,
                "bundle.environment",
                reason,
            ));
            None
        }
    };
    match environment.as_ref().map(|environment| environment.source_state.as_str()) {
        Some("dirty") => match (
            environment
                .as_ref()
                .and_then(|environment| environment.source_diff_sha256.as_deref()),
            artifact_index.get("source.diff"),
        ) {
            (Some(expected), Some(entry)) if entry.sha256 == expected && entry.bytes > 0 => {}
            _ => findings.push(simple_finding(
                ERROR_REPRODUCTION,
                "bundle.environment",
                "dirty source state requires a nonempty manifested source.diff bound to source_diff_sha256"
                    .to_string(),
            )),
        },
        Some("clean") if artifact_index.contains_key("source.diff") => {
            findings.push(simple_finding(
                ERROR_REPRODUCTION,
                "bundle.environment",
                "clean source state must not carry a contradictory source.diff".to_string(),
            ));
        }
        _ => {}
    }

    let commands =
        match read_bounded_regular_file(&bundle_dir.join("commands.txt"), 4 * 1024 * 1024) {
            Ok(bytes) => bytes,
            Err(reason) => {
                findings.push(simple_finding(ERROR_IO, "bundle.commands", reason));
                Vec::new()
            }
        };
    let commands_text = match std::str::from_utf8(&commands) {
        Ok(text) => text,
        Err(error) => {
            findings.push(simple_finding(
                ERROR_ARTIFACT_CONTRACT,
                "bundle.commands",
                format!("commands.txt is not UTF-8: {error}"),
            ));
            ""
        }
    };
    if !commands_text
        .lines()
        .any(|line| line == run_manifest.reproduction_command)
    {
        findings.push(simple_finding(
            ERROR_REPRODUCTION,
            "bundle.commands",
            "reproduction_command is not an exact complete line in commands.txt".to_string(),
        ));
    }
    if environment.as_ref().is_some_and(|environment| {
        !commands_text
            .lines()
            .any(|line| line == environment.source_identity_command)
    }) {
        findings.push(simple_finding(
            ERROR_REPRODUCTION,
            "bundle.commands",
            "env.json source_identity_command is not an exact complete line in commands.txt"
                .to_string(),
        ));
    }
    validate_sample_artifact(bundle_dir, &run_manifest, &artifact_index, &mut findings);

    let reproduction = parse_json_file::<ReproductionRecord>(
        &bundle_dir.join("reproduction_record.json"),
        1024 * 1024,
    );
    match reproduction {
        Ok(record) => {
            validate_execution_record(
                bundle_dir,
                &artifact_index,
                "franken-engine.verification-reproduction-record.v1",
                &run_manifest.reproduction_command,
                &record.schema_version,
                &record.command,
                &record.executed_at_utc,
                record.exit_code,
                &record.stdout_path,
                &record.stdout_sha256,
                &record.stderr_path,
                &record.stderr_sha256,
                record.cleanup_complete && record.rollback_verified,
                &run_manifest.created_at_utc,
                &mut findings,
                "bundle.reproduction",
            );
        }
        Err(reason) => findings.push(simple_finding(
            ERROR_REPRODUCTION,
            "bundle.reproduction",
            reason,
        )),
    }

    let tier_invocation = parse_json_file::<TierRInvocationRecord>(
        &bundle_dir.join("tier_r_invocation.json"),
        1024 * 1024,
    );
    match tier_invocation {
        Ok(record) => {
            validate_execution_record(
                bundle_dir,
                &artifact_index,
                "franken-engine.tier-r-invocation.v1",
                &record.command,
                &record.schema_version,
                &record.command,
                &record.executed_at_utc,
                record.exit_code,
                &record.stdout_path,
                &record.stdout_sha256,
                &record.stderr_path,
                &record.stderr_sha256,
                true,
                &run_manifest.created_at_utc,
                &mut findings,
                "bundle.tier_r_invocation",
            );
            if record.stdout_path != "tier_r_probe.json"
                || record.stderr_path != "tier_r_probe.stderr.log"
                || record.exit_code != 0
                || record.executable_path != "tier_r_probe_executable"
            {
                findings.push(simple_finding(
                    ERROR_TIER_R_TRUTH,
                    "bundle.tier_r_invocation",
                    "Tier-R invocation paths, exit status, or executable path are invalid"
                        .to_string(),
                ));
            }
            match artifact_index.get(&record.executable_path) {
                Some(entry)
                    if entry.sha256 == record.executable_sha256
                        && is_sha256(&record.executable_sha256)
                        && tier_probe.as_ref().is_some_and(|probe| {
                            probe.probe_executable_sha256 == record.executable_sha256
                        }) => {}
                _ => findings.push(simple_finding(
                    ERROR_TIER_R_TRUTH,
                    "bundle.tier_r_invocation",
                    "Tier-R executable digest is not bound to a manifested executable artifact"
                        .to_string(),
                )),
            }
            if !commands_text.lines().any(|line| line == record.command) {
                findings.push(simple_finding(
                    ERROR_REPRODUCTION,
                    "bundle.tier_r_invocation",
                    "Tier-R invocation command is not an exact line in commands.txt".to_string(),
                ));
            }
        }
        Err(reason) => findings.push(simple_finding(
            ERROR_TIER_R_TRUTH,
            "bundle.tier_r_invocation",
            reason,
        )),
    }

    let validation_report = parse_json_file::<ValidationReport>(
        &bundle_dir.join("validation_report.json"),
        4 * 1024 * 1024,
    );
    match validation_report {
        Ok(report) => {
            let contract_hash = artifact_index
                .get("contract.json")
                .map(|entry| &entry.sha256);
            let generated_hash = artifact_index
                .get("generated_contract.json")
                .map(|entry| &entry.sha256);
            let report_time = DateTime::parse_from_rfc3339(&report.as_of_utc)
                .ok()
                .map(|timestamp| timestamp.with_timezone(&Utc));
            let manifest_time = DateTime::parse_from_rfc3339(&run_manifest.created_at_utc)
                .ok()
                .map(|timestamp| timestamp.with_timezone(&Utc));
            let expected_report_status = if run_manifest.observed_outcome.is_success() {
                "pass"
            } else {
                "fail"
            };
            let contract_shape_matches = contract_copy.as_ref().is_ok_and(|contract| {
                let bridge_task_count = contract
                    .coverage_rows
                    .iter()
                    .filter(|row| row.subject_kind == SubjectKind::BridgeTask)
                    .count();
                let claim_count = contract
                    .coverage_rows
                    .len()
                    .saturating_sub(bridge_task_count);
                let harness_member_count = contract
                    .harness_families
                    .iter()
                    .map(|family| family.members.len())
                    .sum::<usize>();
                report.source_cutoff_utc == contract.source_cutoff_utc
                    && report.bridge_task_count == bridge_task_count
                    && report.claim_count == claim_count
                    && report.coverage_row_count == contract.coverage_rows.len()
                    && report.harness_family_count == contract.harness_families.len()
                    && report.harness_member_count == harness_member_count
            });
            if report.schema_version != REPORT_SCHEMA_VERSION
                || !report.certifying_clock
                || report.status != expected_report_status
                || report.error_count != report.findings.len()
                || (report.status == "pass") != report.findings.is_empty()
                || report.checks_run == 0
                || report.checks_run.saturating_add(2) != event_count
                || (!run_manifest.observed_outcome.is_success()
                    && report
                        .findings
                        .first()
                        .map(|finding| finding.error_code.as_str())
                        != run_manifest
                            .first_failure
                            .as_ref()
                            .map(|failure| failure.reason_code.as_str()))
                || report.contract_path != CONTRACT_PATH
                || !contract_shape_matches
                || report_time.is_none()
                || manifest_time.is_none()
                || report_time
                    .zip(manifest_time)
                    .is_some_and(|(report, manifest)| {
                        (report - manifest).num_seconds().unsigned_abs() > 300
                    })
                || contract_hash != Some(&report.contract_sha256)
                || generated_hash != Some(&report.generated_contract_sha256)
            {
                findings.push(simple_finding(
                    ERROR_PROVENANCE,
                    "bundle.validation_report",
                    "validation report clock, outcome, or contract hashes differ from manifested run evidence"
                        .to_string(),
                ));
            }
        }
        Err(reason) => findings.push(simple_finding(
            ERROR_PROVENANCE,
            "bundle.validation_report",
            reason,
        )),
    }

    let repro_lock = parse_json_file::<ReproLock>(&bundle_dir.join("repro.lock"), 1024 * 1024);
    match repro_lock {
        Ok(lock) => {
            let matches_artifact = |path: &str, hash: &str| {
                artifact_index
                    .get(path)
                    .is_some_and(|entry| entry.sha256 == hash)
            };
            if lock.schema_version != "franken-engine.verification-repro-lock.v1"
                || !is_sha256(&lock.source_tree_sha256)
                || environment.as_ref().is_none_or(|environment| {
                    environment.source_tree_sha256 != lock.source_tree_sha256
                })
                || !matches_artifact("root.Cargo.lock", &lock.cargo_lock_sha256)
                || !matches_artifact("tool.Cargo.lock", &lock.tool_lock_sha256)
                || !matches_artifact("contract.json", &lock.contract_sha256)
                || !matches_artifact("generated_contract.json", &lock.generated_contract_sha256)
                || sha256_hex(&commands) != lock.commands_sha256
                || tier_source_manifest_sha
                    .as_ref()
                    .is_none_or(|manifest_sha| manifest_sha != &lock.tier_r_source_sha256)
                || tier_probe
                    .as_ref()
                    .is_none_or(|probe| probe.reference_source_sha256 != lock.tier_r_source_sha256)
                || tier_build_environment
                    .as_ref()
                    .is_none_or(|(_, build_environment_sha)| {
                        build_environment_sha != &lock.tier_r_build_environment_sha256
                    })
                || tier_probe.as_ref().is_none_or(|probe| {
                    probe.build_environment_sha256 != lock.tier_r_build_environment_sha256
                })
            {
                findings.push(simple_finding(
                    ERROR_PROVENANCE,
                    "bundle.repro_lock",
                    "repro.lock schema or source/lock/contract/command identities are unbound"
                        .to_string(),
                ));
            }
        }
        Err(reason) => findings.push(simple_finding(
            ERROR_PROVENANCE,
            "bundle.repro_lock",
            reason,
        )),
    }

    for entry in &artifact_manifest.files {
        match read_bounded_regular_file(&bundle_dir.join(&entry.path), MAX_BUNDLE_FILE_BYTES) {
            Ok(bytes) => match std::str::from_utf8(&bytes) {
                Ok(text)
                    if ((entry.path == "source.diff"
                        || entry.path.starts_with("tier_r_source/"))
                        && contains_high_confidence_source_secret(text))
                        || (entry.path != "source.diff"
                            && !entry.path.starts_with("tier_r_source/")
                            && contains_secret_marker(text)) =>
                {
                    findings.push(simple_finding(
                        ERROR_SECRET_LEAK,
                        "bundle.redaction",
                        format!("{} contains an unredacted secret marker/value", entry.path),
                    ));
                }
                Ok(_) => {}
                Err(error) if textual_artifact_path(&entry.path) => {
                    findings.push(simple_finding(
                        ERROR_ARTIFACT_CONTRACT,
                        "bundle.text",
                        format!(
                            "{} is declared textual but is not UTF-8: {error}",
                            entry.path
                        ),
                    ));
                }
                Err(_) => {}
            },
            Err(reason) => findings.push(simple_finding(ERROR_IO, "bundle.text", reason)),
        }
    }

    match parse_json_file::<ProvenanceGraph>(
        &bundle_dir.join("provenance_graph.json"),
        4 * 1024 * 1024,
    ) {
        Ok(graph) => validate_provenance_graph(&graph, &artifact_index, &mut findings),
        Err(reason) => findings.push(simple_finding(
            ERROR_PROVENANCE,
            "bundle.provenance",
            reason,
        )),
    }
    bundle_report(bundle_dir, checked_files, event_count, findings)
}

#[allow(clippy::too_many_arguments)]
fn validate_execution_record(
    bundle_dir: &Path,
    artifact_index: &BTreeMap<String, &ArtifactDigest>,
    expected_schema: &str,
    expected_command: &str,
    schema: &str,
    command: &str,
    executed_at_utc: &str,
    exit_code: i32,
    stdout_path: &str,
    stdout_sha256: &str,
    stderr_path: &str,
    stderr_sha256: &str,
    cleanup_and_rollback_verified: bool,
    run_created_at_utc: &str,
    findings: &mut Vec<ValidationFinding>,
    phase: &str,
) {
    let execution_time = DateTime::parse_from_rfc3339(executed_at_utc)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc));
    let run_time = DateTime::parse_from_rfc3339(run_created_at_utc)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc));
    let timestamp_valid = execution_time
        .zip(run_time)
        .is_some_and(|(execution, run)| {
            execution <= Utc::now() + chrono::Duration::minutes(5)
                && (execution - run).num_seconds().unsigned_abs() <= 300
        });
    if schema != expected_schema
        || command != expected_command
        || command.trim().is_empty()
        || exit_code != 0
        || !cleanup_and_rollback_verified
        || !timestamp_valid
        || !safe_relative_path(Path::new(stdout_path))
        || !safe_relative_path(Path::new(stderr_path))
        || !is_sha256(stdout_sha256)
        || !is_sha256(stderr_sha256)
    {
        findings.push(simple_finding(
            ERROR_REPRODUCTION,
            phase,
            "execution record schema/command/time/exit/cleanup/rollback/path/hash contract failed"
                .to_string(),
        ));
        return;
    }
    for (path, hash) in [(stdout_path, stdout_sha256), (stderr_path, stderr_sha256)] {
        match artifact_index.get(path) {
            Some(entry) if entry.sha256 == hash => {
                if let Ok(bytes) =
                    read_bounded_regular_file(&bundle_dir.join(path), MAX_BUNDLE_FILE_BYTES)
                    && sha256_hex(&bytes) != hash
                {
                    findings.push(simple_finding(
                        ERROR_HASH_DRIFT,
                        phase,
                        format!("{path} changed after artifact-manifest validation"),
                    ));
                }
            }
            _ => findings.push(simple_finding(
                ERROR_PROVENANCE,
                phase,
                format!("execution record output {path} is not bound to the artifact manifest"),
            )),
        }
    }
}

fn textual_artifact_path(path: &str) -> bool {
    [
        ".json", ".jsonl", ".txt", ".md", ".log", ".lock", ".sh", ".ps1", ".toml", ".diff",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

fn validate_sample_artifact(
    bundle_dir: &Path,
    run_manifest: &RunManifest,
    artifact_index: &BTreeMap<String, &ArtifactDigest>,
    findings: &mut Vec<ValidationFinding>,
) {
    let sample_artifact = &run_manifest.sample_artifact;
    match sample_artifact.kind {
        SampleArtifactKind::RawSamples => {
            let bytes = match read_bounded_regular_file(
                &bundle_dir.join(&sample_artifact.path),
                MAX_BUNDLE_FILE_BYTES,
            ) {
                Ok(bytes) => bytes,
                Err(reason) => {
                    findings.push(simple_finding(
                        ERROR_ARTIFACT_CONTRACT,
                        "bundle.samples",
                        reason,
                    ));
                    return;
                }
            };
            if !bytes.ends_with(b"\n") {
                findings.push(simple_finding(
                    ERROR_ARTIFACT_CONTRACT,
                    "bundle.samples",
                    "samples.jsonl must end with a complete newline-delimited record".to_string(),
                ));
            }
            let mut count = 0usize;
            for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
                if line.is_empty() {
                    continue;
                }
                count += 1;
                match serde_json::from_slice::<VerificationSample>(line) {
                    Ok(sample)
                        if sample.schema_version == "franken-engine.verification-sample.v1"
                            && !sample.sample_id.trim().is_empty()
                            && sample.sample_id.len() <= MAX_ID_BYTES
                            && sample.seed == run_manifest.seed
                            && sample.outcome == run_manifest.observed_outcome
                            && !sample.artifact_hashes.is_empty()
                            && sample.artifact_hashes.iter().all(|(path, hash)| {
                                safe_relative_path(Path::new(path))
                                    && is_sha256(hash)
                                    && artifact_index
                                        .get(path)
                                        .is_some_and(|entry| entry.sha256 == *hash)
                            }) => {}
                    Ok(_) => findings.push(simple_finding(
                        ERROR_ARTIFACT_CONTRACT,
                        "bundle.samples",
                        format!("sample line {} violates the sample schema", index + 1),
                    )),
                    Err(error) => findings.push(simple_finding(
                        ERROR_JSON,
                        "bundle.samples",
                        format!("parse sample line {}: {error}", index + 1),
                    )),
                }
            }
            if count == 0 {
                findings.push(simple_finding(
                    ERROR_BUNDLE_INCOMPLETE,
                    "bundle.samples",
                    "samples.jsonl contains no sample records".to_string(),
                ));
            } else if count > MAX_EVENTS {
                findings.push(simple_finding(
                    ERROR_BOUNDS,
                    "bundle.samples",
                    format!("samples.jsonl has {count} records, limit {MAX_EVENTS}"),
                ));
            }
        }
        SampleArtifactKind::MinimizedSeed => {
            match parse_json_file::<MinimizedSeed>(
                &bundle_dir.join(&sample_artifact.path),
                MAX_BUNDLE_FILE_BYTES,
            ) {
                Ok(seed)
                    if seed.schema_version == "franken-engine.verification-minimized-seed.v1"
                        && seed.seed == run_manifest.seed
                        && is_sha256(&seed.original_sha256)
                        && is_sha256(&seed.reduced_sha256)
                        && seed.original_sha256 != "0".repeat(64)
                        && seed.reduced_sha256
                            == minimized_seed_identity(
                                seed.seed,
                                &seed.reproduction_command,
                            )
                        && seed.original_sha256 != seed.reduced_sha256
                        && seed.reduction_steps > 0
                        && seed.reproduction_command == run_manifest.reproduction_command => {}
                Ok(_) => findings.push(simple_finding(
                    ERROR_ARTIFACT_CONTRACT,
                    "bundle.samples",
                    "minimized_seed.json lacks exact hashes, reduction provenance, or reproduction command"
                        .to_string(),
                )),
                Err(reason) => findings.push(simple_finding(
                    ERROR_ARTIFACT_CONTRACT,
                    "bundle.samples",
                    reason,
                )),
            }
        }
    }
}

fn validate_provenance_graph(
    graph: &ProvenanceGraph,
    artifact_index: &BTreeMap<String, &ArtifactDigest>,
    findings: &mut Vec<ValidationFinding>,
) {
    if graph.schema_version != "franken-engine.verification-provenance-graph.v1"
        || graph.nodes.is_empty()
        || graph.edges.is_empty()
    {
        findings.push(simple_finding(
            ERROR_PROVENANCE,
            "bundle.provenance",
            "provenance graph schema, nodes, or edges are incomplete".to_string(),
        ));
        return;
    }
    let mut node_index = BTreeMap::new();
    let mut kinds: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut represented_artifacts = BTreeSet::new();
    for node in &graph.nodes {
        if node.node_id.trim().is_empty()
            || node.node_id.len() > MAX_ID_BYTES
            || node.kind.trim().is_empty()
            || node.kind.len() > MAX_ID_BYTES
            || !matches!(
                node.kind.as_str(),
                "requirement" | "run" | "event_stream" | "artifact" | "verdict"
            )
            || node.sha256.as_deref().is_some_and(|hash| !is_sha256(hash))
            || node_index.insert(node.node_id.as_str(), node).is_some()
        {
            findings.push(simple_finding(
                ERROR_PROVENANCE,
                "bundle.provenance",
                format!("invalid or duplicate provenance node {}", node.node_id),
            ));
            continue;
        }
        kinds
            .entry(node.kind.as_str())
            .or_default()
            .insert(node.node_id.as_str());
        if node.kind == "requirement"
            && artifact_index
                .get("contract.json")
                .is_none_or(|entry| node.sha256.as_deref() != Some(entry.sha256.as_str()))
        {
            findings.push(simple_finding(
                ERROR_PROVENANCE,
                "bundle.provenance",
                format!(
                    "requirement node {} is not bound to the retained contract hash",
                    node.node_id
                ),
            ));
        }
        if let Some(path) = &node.artifact_path {
            let expected_kind = match path.as_str() {
                "run_manifest.json" => "run",
                "events.jsonl" => "event_stream",
                "validation_report.json" => "verdict",
                _ => "artifact",
            };
            if node.kind != expected_kind {
                findings.push(simple_finding(
                    ERROR_PROVENANCE,
                    "bundle.provenance",
                    format!(
                        "node {} binds {path} as {}, expected {expected_kind}",
                        node.node_id, node.kind
                    ),
                ));
            }
            if !safe_relative_path(Path::new(path)) {
                findings.push(simple_finding(
                    ERROR_PROVENANCE,
                    "bundle.provenance",
                    format!("node {} has unsafe artifact path {path}", node.node_id),
                ));
            } else {
                match (artifact_index.get(path), node.sha256.as_deref()) {
                    (Some(entry), Some(hash)) if entry.sha256 == hash => {
                        represented_artifacts.insert(path.as_str());
                    }
                    _ => findings.push(simple_finding(
                        ERROR_PROVENANCE,
                        "bundle.provenance",
                        format!(
                            "node {} artifact {path} is not bound to its manifested hash",
                            node.node_id
                        ),
                    )),
                }
            }
        } else if node.kind != "requirement" {
            findings.push(simple_finding(
                ERROR_PROVENANCE,
                "bundle.provenance",
                format!(
                    "{} node {} must bind a manifested artifact path and hash",
                    node.kind, node.node_id
                ),
            ));
        }
    }
    for path in artifact_index
        .keys()
        .map(String::as_str)
        .filter(|path| *path != "provenance_graph.json")
    {
        if !represented_artifacts.contains(path) {
            findings.push(simple_finding(
                ERROR_PROVENANCE,
                "bundle.provenance",
                format!("manifested artifact {path} has no hash-bound provenance node"),
            ));
        }
    }
    let mut adjacency: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut edge_identities = BTreeSet::new();
    for edge in &graph.edges {
        if edge.relation.trim().is_empty()
            || !node_index.contains_key(edge.from.as_str())
            || !node_index.contains_key(edge.to.as_str())
            || !edge_identities.insert((
                edge.from.as_str(),
                edge.relation.as_str(),
                edge.to.as_str(),
            ))
        {
            findings.push(simple_finding(
                ERROR_PROVENANCE,
                "bundle.provenance",
                format!(
                    "invalid, duplicate, or dangling provenance edge {} -{}-> {}",
                    edge.from, edge.relation, edge.to
                ),
            ));
            continue;
        }
        adjacency
            .entry(edge.from.as_str())
            .or_default()
            .insert(edge.to.as_str());
    }
    for required_kind in ["requirement", "run", "event_stream", "artifact", "verdict"] {
        if kinds.get(required_kind).is_none_or(BTreeSet::is_empty) {
            findings.push(simple_finding(
                ERROR_PROVENANCE,
                "bundle.provenance",
                format!("provenance graph has no {required_kind} node"),
            ));
        }
    }
    let required_reachable_kinds = ["run", "event_stream", "artifact", "verdict"];
    let mut reachable_from_any_requirement = BTreeSet::new();
    if let Some(requirements) = kinds.get("requirement") {
        for requirement in requirements {
            let mut pending = vec![*requirement];
            let mut visited = BTreeSet::new();
            while let Some(node_id) = pending.pop() {
                if !visited.insert(node_id) {
                    continue;
                }
                if let Some(next) = adjacency.get(node_id) {
                    pending.extend(next.iter().copied());
                }
            }
            reachable_from_any_requirement.extend(visited.iter().copied());
            for required_kind in required_reachable_kinds {
                let reachable = kinds
                    .get(required_kind)
                    .is_some_and(|nodes| nodes.iter().any(|node_id| visited.contains(node_id)));
                if !reachable {
                    findings.push(simple_finding(
                        ERROR_PROVENANCE,
                        "bundle.provenance",
                        format!("requirement {requirement} cannot reach a {required_kind} node"),
                    ));
                }
            }
        }
    }
    for node_id in node_index.keys() {
        if !reachable_from_any_requirement.contains(node_id) {
            findings.push(simple_finding(
                ERROR_PROVENANCE,
                "bundle.provenance",
                format!("node {node_id} is disconnected from every requirement root"),
            ));
        }
    }
    let verdict_nodes = kinds.get("verdict").cloned().unwrap_or_default();
    for node in graph
        .nodes
        .iter()
        .filter(|node| node.artifact_path.as_deref() != Some("validation_report.json"))
    {
        let mut pending = vec![node.node_id.as_str()];
        let mut visited = BTreeSet::new();
        while let Some(node_id) = pending.pop() {
            if !visited.insert(node_id) {
                continue;
            }
            if let Some(next) = adjacency.get(node_id) {
                pending.extend(next.iter().copied());
            }
        }
        if verdict_nodes.is_disjoint(&visited) {
            findings.push(simple_finding(
                ERROR_PROVENANCE,
                "bundle.provenance",
                format!("node {} cannot reach a verdict node", node.node_id),
            ));
        }
    }
    for node_id in node_index.keys() {
        let outgoing = adjacency
            .get(node_id)
            .is_some_and(|edges| !edges.is_empty());
        let incoming = graph.edges.iter().any(|edge| edge.to == **node_id);
        if !outgoing && !incoming {
            findings.push(simple_finding(
                ERROR_PROVENANCE,
                "bundle.provenance",
                format!("orphan provenance node {node_id}"),
            ));
        }
    }
}

fn bundle_report(
    bundle_dir: &Path,
    checked_files: usize,
    event_count: usize,
    findings: Vec<ValidationFinding>,
) -> BundleValidationReport {
    let error_count = findings.len();
    BundleValidationReport {
        schema_version: "franken-engine.verification-bundle.validation-report.v1".to_string(),
        bundle_path: bounded_redacted(&bundle_dir.display().to_string(), Path::new("")),
        status: if error_count == 0 { "pass" } else { "fail" }.to_string(),
        checked_files,
        event_count,
        error_count,
        findings,
    }
}

fn walk_bundle_files(bundle_dir: &Path) -> Result<Vec<String>, String> {
    let mut pending = vec![(bundle_dir.to_path_buf(), 0usize)];
    let mut files = Vec::new();
    let mut directory_count = 0usize;
    let mut total_bytes = 0u64;
    while let Some((directory, depth)) = pending.pop() {
        directory_count = directory_count.saturating_add(1);
        if directory_count > MAX_BUNDLE_DIRECTORIES {
            return Err(format!(
                "{ERROR_BOUNDS}: bundle has more than {MAX_BUNDLE_DIRECTORIES} directories"
            ));
        }
        if depth > MAX_BUNDLE_DEPTH {
            return Err(format!(
                "{ERROR_BOUNDS}: bundle directory depth {depth} exceeds {MAX_BUNDLE_DEPTH}"
            ));
        }
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("{ERROR_IO}: read {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| {
                format!("{ERROR_IO}: read {} entry: {error}", directory.display())
            })?;
            let file_type = entry.file_type().map_err(|error| {
                format!("{ERROR_IO}: inspect {}: {error}", entry.path().display())
            })?;
            if file_type.is_symlink() {
                return Err(format!(
                    "{ERROR_UNSAFE_PATH}: bundle contains symlink {}",
                    entry.path().display()
                ));
            }
            if file_type.is_dir() {
                pending.push((entry.path(), depth.saturating_add(1)));
            } else if file_type.is_file() {
                let entry_path = entry.path();
                let relative = entry_path
                    .strip_prefix(bundle_dir)
                    .map_err(|error| format!("{ERROR_UNSAFE_PATH}: bundle path escape: {error}"))?;
                let relative = relative.to_str().ok_or_else(|| {
                    format!(
                        "{ERROR_UNSAFE_PATH}: bundle path is not UTF-8: {}",
                        entry_path.display()
                    )
                })?;
                let relative = relative.replace('\\', "/");
                if !safe_relative_path(Path::new(&relative)) {
                    return Err(format!(
                        "{ERROR_UNSAFE_PATH}: bundle contains unsafe relative path {relative}"
                    ));
                }
                let metadata = entry.metadata().map_err(|error| {
                    format!("{ERROR_IO}: inspect bundle file {relative}: {error}")
                })?;
                if metadata.len() > MAX_BUNDLE_FILE_BYTES {
                    return Err(format!(
                        "{ERROR_BOUNDS}: bundle file {relative} is {} bytes, limit {MAX_BUNDLE_FILE_BYTES}",
                        metadata.len()
                    ));
                }
                total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
                    format!("{ERROR_BOUNDS}: bundle total-byte accounting overflow")
                })?;
                if total_bytes > MAX_BUNDLE_TOTAL_BYTES {
                    return Err(format!(
                        "{ERROR_BOUNDS}: bundle total bytes exceed {MAX_BUNDLE_TOTAL_BYTES}"
                    ));
                }
                files.push(relative);
                if files.len() > MAX_BUNDLE_FILES {
                    return Err(format!(
                        "{ERROR_BOUNDS}: bundle has more than {MAX_BUNDLE_FILES} files"
                    ));
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

fn parse_json_file<T: for<'de> Deserialize<'de>>(path: &Path, max_bytes: u64) -> Result<T, String> {
    let bytes = read_bounded_regular_file(path, max_bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("{ERROR_JSON}: parse {}: {error}", path.display()))
}

pub fn read_bounded_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{ERROR_IO}: inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{ERROR_UNSAFE_PATH}: {} is not a regular non-symlink file",
            path.display()
        ));
    }
    if metadata.len() > max_bytes {
        return Err(format!(
            "{ERROR_BOUNDS}: {} is {} bytes, limit {max_bytes}",
            path.display(),
            metadata.len()
        ));
    }
    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
    let file = fs::File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| format!("{ERROR_IO}: no-follow open {}: {error}", path.display()))?,
    );
    #[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "redox")))]
    let file = fs::File::open(path)
        .map_err(|error| format!("{ERROR_IO}: open {}: {error}", path.display()))?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len().min(max_bytes)).unwrap_or(usize::MAX));
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{ERROR_IO}: read {}: {error}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "{ERROR_BOUNDS}: {} exceeded {max_bytes} bytes while reading",
            path.display()
        ));
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("{ERROR_IO}: re-inspect {}: {error}", path.display()))?;
    if after.file_type().is_symlink() || !after.is_file() || after.len() != bytes.len() as u64 {
        return Err(format!(
            "{ERROR_UNSAFE_PATH}: {} changed type or length during bounded read",
            path.display()
        ));
    }
    Ok(bytes)
}

pub fn write_bytes_no_replace(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("{ERROR_IO}: create {}: {error}", parent.display()))?;
    }
    if path.exists() {
        return Err(format!(
            "{ERROR_ARTIFACT_CONTRACT}: refusing to overwrite {}",
            path.display()
        ));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "{ERROR_UNSAFE_PATH}: output path has no UTF-8 file name: {}",
                path.display()
            )
        })?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let partial = path.with_file_name(format!(
        "{file_name}.partial-{}-{sequence}",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| {
            format!(
                "{ERROR_IO}: create recoverable prefix {}: {error}",
                partial.display()
            )
        })?;
    file.write_all(bytes).map_err(|error| {
        format!(
            "{ERROR_IO}: write recoverable prefix {}: {error}",
            partial.display()
        )
    })?;
    file.sync_all().map_err(|error| {
        format!(
            "{ERROR_IO}: sync recoverable prefix {}: {error}",
            partial.display()
        )
    })?;
    publish_without_replacement(&partial, path).map_err(|error| {
        format!(
            "{ERROR_ARTIFACT_CONTRACT}: publish {} without replacement; recoverable prefix {} retained: {error}",
            path.display(),
            partial.display()
        )
    })
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
fn publish_without_replacement(partial: &Path, destination: &Path) -> io::Result<()> {
    Ok(renameat_with(
        CWD,
        partial,
        CWD,
        destination,
        RenameFlags::NOREPLACE,
    )?)
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "redox")))]
fn publish_without_replacement(partial: &Path, destination: &Path) -> io::Result<()> {
    fs::hard_link(partial, destination)?;
    fs::remove_file(partial)
}

fn simple_finding(code: &str, phase: &str, reason: String) -> ValidationFinding {
    ValidationFinding {
        error_code: code.to_string(),
        phase: phase.to_string(),
        reason: bounded_redacted(&reason, Path::new("")),
        subject_id: None,
        family_id: None,
    }
}

fn file_error_code(reason: &str) -> &'static str {
    if reason.contains(ERROR_UNSAFE_PATH) {
        ERROR_UNSAFE_PATH
    } else if reason.contains(ERROR_BOUNDS) {
        ERROR_BOUNDS
    } else {
        ERROR_IO
    }
}

fn error_class_for(code: &str) -> &'static str {
    match code {
        ERROR_IO => "io",
        ERROR_JSON | ERROR_SCHEMA | ERROR_EVENT_SCHEMA => "schema",
        ERROR_SUBJECT_DRIFT | ERROR_GENERATION_DRIFT => "authority_drift",
        ERROR_OWNER => "ownership",
        ERROR_CLASSIFICATION | ERROR_HISTORICAL_PROOF => "truth_classification",
        ERROR_UNSAFE_PATH => "path_safety",
        ERROR_HASH_DRIFT => "integrity",
        ERROR_GENERIC_RUNNER | ERROR_BRANCH_PROOF => "execution_coverage",
        ERROR_FORMAT_DUPLICATION => "format_migration",
        ERROR_ARTIFACT_CONTRACT | ERROR_BUNDLE_INCOMPLETE => "artifact_contract",
        ERROR_SECRET_LEAK => "redaction",
        ERROR_ORDER_OR_DUPLICATE => "ordering",
        ERROR_MARKDOWN_DRIFT => "rendering",
        ERROR_TIER_R_TRUTH => "reference_truth",
        ERROR_STALE => "freshness",
        ERROR_BOUNDS => "resource_bound",
        ERROR_RETRY_MASKING => "flake_masking",
        ERROR_SILENT_FALLBACK => "fallback",
        ERROR_PROVENANCE => "provenance",
        ERROR_REPO_ROOT => "repository",
        ERROR_CLOCK_AUTHORITY => "clock_authority",
        ERROR_OUTCOME_MISMATCH => "outcome_integrity",
        ERROR_REPRODUCTION => "reproduction",
        _ => "validation",
    }
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_git_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn path_for_report(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], " ")
}

fn contains_secret_marker(value: &str) -> bool {
    if let Ok(json) = serde_json::from_str::<JsonValue>(value)
        && json_contains_secret(&json)
    {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    [
        "authorization:",
        "bearer ",
        "api_key=",
        "apikey=",
        "password=",
        "secret=",
        "token=",
        "private_key=",
        "--token ",
        "--password ",
        "--secret ",
        "--api-key ",
    ]
    .iter()
    .any(|marker| {
        lower.match_indices(marker).any(|(start, _)| {
            let value_start = start + marker.len();
            let tail = &lower[value_start..];
            let candidate = tail
                .trim_start()
                .split(|character: char| {
                    character.is_whitespace()
                        || matches!(character, ',' | ';' | '"' | '\'' | '&' | '}' | ']')
                })
                .next()
                .unwrap_or_default();
            !candidate.is_empty()
                && !matches!(
                    candidate,
                    "<redacted>" | "redacted" | "<none>" | "none" | "<empty>"
                )
        })
    })
}

fn contains_high_confidence_source_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if [
        concat!("-----begin ", "private key-----"),
        concat!("-----begin rsa ", "private key-----"),
        concat!("-----begin ec ", "private key-----"),
        concat!("-----begin openssh ", "private key-----"),
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return true;
    }
    let known_prefixes = [
        "github_pat_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "sk_live_",
        "rk_live_",
        "akia",
    ];
    if lower
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    '"' | '\'' | '`' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
                )
        })
        .any(|candidate| {
            known_prefixes
                .iter()
                .any(|prefix| candidate.starts_with(prefix) && candidate.len() >= prefix.len() + 12)
        })
    {
        return true;
    }
    [
        "authorization:",
        "bearer ",
        "api_key=",
        "apikey=",
        "password=",
        "secret=",
        "token=",
        "private_key=",
        "--token ",
        "--password ",
        "--secret ",
        "--api-key ",
    ]
    .iter()
    .any(|marker| {
        lower.match_indices(marker).any(|(start, _)| {
            let value_start = start + marker.len();
            let candidate = lower[value_start..]
                .trim_start()
                .split(|character: char| {
                    character.is_whitespace()
                        || matches!(
                            character,
                            ',' | ';' | '"' | '\'' | '`' | '&' | '}' | ']' | ')'
                        )
                })
                .next()
                .unwrap_or_default()
                .trim_matches(|character: char| !character.is_ascii_alphanumeric());
            candidate.len() >= 20
                && candidate.bytes().any(|byte| byte.is_ascii_alphabetic())
                && candidate.bytes().any(|byte| byte.is_ascii_digit())
                && ![
                    "example",
                    "placeholder",
                    "not-a-credential",
                    "not_a_credential",
                    "redacted",
                    "fixture",
                    "dummy",
                ]
                .iter()
                .any(|word| candidate.contains(word))
        })
    })
}

fn json_contains_secret(value: &JsonValue) -> bool {
    match value {
        JsonValue::Object(object) => object.iter().any(|(key, value)| {
            let normalized = key.to_ascii_lowercase().replace(['-', '.'], "_");
            let sensitive = matches!(
                normalized.as_str(),
                "authorization"
                    | "bearer"
                    | "api_key"
                    | "apikey"
                    | "password"
                    | "secret"
                    | "token"
                    | "private_key"
                    | "access_token"
                    | "refresh_token"
            );
            (sensitive && !json_value_is_redacted(value)) || json_contains_secret(value)
        }),
        JsonValue::Array(values) => values.iter().any(json_contains_secret),
        JsonValue::String(text) => {
            if text.ends_with(':') || text.ends_with('=') || text.ends_with(' ') {
                false
            } else {
                let lower = text.to_ascii_lowercase();
                lower.starts_with("bearer ")
                    && !matches!(lower.as_str(), "bearer <redacted>" | "bearer redacted")
            }
        }
        _ => false,
    }
}

fn json_value_is_redacted(value: &JsonValue) -> bool {
    match value {
        JsonValue::Null => true,
        JsonValue::String(value) => matches!(
            value.to_ascii_lowercase().as_str(),
            "" | "<redacted>" | "redacted" | "<none>" | "none" | "<empty>"
        ),
        _ => false,
    }
}

fn bounded_redacted(value: &str, repo_root: &Path) -> String {
    if contains_secret_marker(value) {
        return "<redacted:secret-bearing-diagnostic>".to_string();
    }
    let root = repo_root.to_string_lossy();
    let mut output = if root.is_empty() {
        value.to_string()
    } else {
        value.replace(root.as_ref(), "<repo>")
    };
    for marker in [
        "authorization:",
        "bearer ",
        "api_key=",
        "apikey=",
        "password=",
        "secret=",
        "token=",
        "private_key",
    ] {
        loop {
            let lower = output.to_ascii_lowercase();
            let Some(start) = lower.find(marker) else {
                break;
            };
            let value_start = start + marker.len();
            let end = output[value_start..]
                .char_indices()
                .find(|(_, character)| {
                    character.is_whitespace()
                        || matches!(character, ',' | ';' | '"' | '\'' | '&' | '}' | ']')
                })
                .map_or(output.len(), |(offset, _)| value_start + offset);
            output.replace_range(start..end.max(value_start), "<redacted>");
        }
    }
    if output.len() > MAX_REASON_BYTES {
        let ellipsis = "…";
        let mut boundary = MAX_REASON_BYTES.saturating_sub(ellipsis.len());
        while !output.is_char_boundary(boundary) {
            boundary = boundary.saturating_sub(1);
        }
        output.truncate(boundary);
        output.push_str(ellipsis);
    }
    output
}
