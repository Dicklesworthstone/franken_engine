#![forbid(unsafe_code)]

//! Frozen, executable inventory of FrankenEngine's exposed internationalization
//! and locale-sensitive behavior.
//!
//! This module is deliberately a truth contract, not an ECMA-402
//! implementation.  It distinguishes:
//!
//! - behavior reachable through a shipped JavaScript execution path;
//! - internal HostCall implementations that are not reachable from JavaScript;
//! - names that are absent from both the engine and the product layer; and
//! - the independent ECMA-262 and ECMA-402 scoreboards.
//!
//! A source match alone never proves exposure.  Every exposed or absent row is
//! paired with a fresh-process probe, while bounded source slices explain the
//! exact branch or non-route that produced the observation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.intl-surface-contract.v1";
pub const VALIDATION_SCHEMA_VERSION: &str = "franken-engine.intl-surface-contract.validation.v1";
pub const EVENT_SCHEMA_VERSION: &str = "franken-engine.intl-surface-contract.event.v1";
pub const PROBE_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.intl-surface-contract.probe-report.v1";
pub const MUTATION_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.intl-surface-contract.mutation-report.v1";
pub const BUNDLE_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.intl-surface-contract.bundle-manifest.v1";
pub const CONTRACT_ID: &str = "franken-engine-intl-surface-v1";
pub const OWNING_BEAD: &str = "bd-performance-conformance-bridge-tu32j.27.1";
pub const CANONICAL_CONTRACT_PATH: &str = "docs/intl_surface_contract_v1.json";
pub const RENDERED_MARKDOWN_PATH: &str = "docs/INTL_SURFACE_CONTRACT_V1.md";

pub const ERROR_IO: &str = "FE-INTL-1001";
pub const ERROR_JSON: &str = "FE-INTL-1002";
pub const ERROR_SCHEMA: &str = "FE-INTL-1003";
pub const ERROR_CARDINALITY: &str = "FE-INTL-1004";
pub const ERROR_ORDER_OR_DUPLICATE: &str = "FE-INTL-1005";
pub const ERROR_REQUIRED_SURFACE: &str = "FE-INTL-1006";
pub const ERROR_OWNER: &str = "FE-INTL-1007";
pub const ERROR_EXPOSURE: &str = "FE-INTL-1008";
pub const ERROR_DESCRIPTOR: &str = "FE-INTL-1009";
pub const ERROR_SCOREBOARD: &str = "FE-INTL-1010";
pub const ERROR_PROBE_COVERAGE: &str = "FE-INTL-1011";
pub const ERROR_AUTHORITY: &str = "FE-INTL-1012";
pub const ERROR_AUTHORITY_HASH: &str = "FE-INTL-1013";
pub const ERROR_AUTHORITY_MARKER: &str = "FE-INTL-1014";
pub const ERROR_UNSAFE_PATH: &str = "FE-INTL-1015";
pub const ERROR_DISCOVERY: &str = "FE-INTL-1016";
pub const ERROR_DOC_CROSSWALK: &str = "FE-INTL-1017";
pub const ERROR_CANONICAL_JSON: &str = "FE-INTL-1018";
pub const ERROR_MARKDOWN_DRIFT: &str = "FE-INTL-1019";
pub const ERROR_PROCESS: &str = "FE-INTL-1020";
pub const ERROR_PROBE_RESULT: &str = "FE-INTL-1021";
pub const ERROR_OUTPUT_EXISTS: &str = "FE-INTL-1022";
pub const ERROR_MUTATION_SURVIVED: &str = "FE-INTL-1023";
pub const ERROR_BUNDLE: &str = "FE-INTL-1024";
pub const ERROR_REDACTION: &str = "FE-INTL-1025";
pub const ERROR_SEMANTIC_DRIFT: &str = "FE-INTL-1026";

const ENGINE_BASE_COMMIT: &str = "0fb96dea1";
const FRANKEN_NODE_BASE_COMMIT: &str = "5b3585be53cafcf20e79fc53707b75b2751bc26d";
const MAX_SURFACES: usize = 64;
const MAX_AUTHORITIES: usize = 64;
const MAX_PROBES: usize = 64;
const MAX_DISCOVERY_FILES: usize = 20_000;
const MAX_DISCOVERY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 4_096;
const MAX_PROCESS_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENT_REASON_BYTES: usize = 768;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub const REQUIRED_SURFACE_IDS: &[&str] = &[
    "date.prototype.to_locale_date_string",
    "date.prototype.to_locale_string",
    "date.prototype.to_locale_time_string",
    "date.prototype.to_string_locale_negative_control",
    "intl.global",
    "number.prototype.to_locale_string",
    "string.prototype.locale_compare",
    "string.prototype.to_locale_lower_case",
    "string.prototype.to_locale_upper_case",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntlSurfaceContract {
    pub schema_version: String,
    pub contract_id: String,
    pub owning_bead: String,
    pub purpose: String,
    pub source_cutoff: SourceCutoff,
    pub scoring_boundary: ScoringBoundary,
    pub provider_policy: ProviderPolicy,
    pub authorities: Vec<AuthoritySlice>,
    pub discovery_rules: Vec<DiscoveryRule>,
    pub documentation_crosswalk: Vec<DocumentationCrosswalk>,
    pub surfaces: Vec<SurfaceRow>,
    pub probes: Vec<ProbeSpec>,
    pub exclusions: Vec<String>,
    pub legal: LegalRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCutoff {
    pub engine_base_commit: String,
    pub franken_node_base_commit: String,
    pub authority_hash_algorithm: String,
    pub authority_scope: String,
    pub engine_root_hint: String,
    pub franken_node_root_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScoringBoundary {
    pub ecma262_profile: String,
    pub ecma262_rule: String,
    pub ecma402_profile: String,
    pub ecma402_rule: String,
    pub preservation_score_name: String,
    pub preservation_rule: String,
    pub contamination_kill_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderPolicy {
    pub default_locale: String,
    pub default_timezone: String,
    pub public_provider: String,
    pub internal_date_provider: String,
    pub internal_case_provider: String,
    pub collation_provider: String,
    pub data_versions: Vec<String>,
    pub ambient_environment_rule: String,
    pub upgrade_rule: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryId {
    FrankenEngine,
    FrankenNode,
}

impl RepositoryId {
    pub const fn label(self) -> &'static str {
        match self {
            Self::FrankenEngine => "franken_engine",
            Self::FrankenNode => "franken_node",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySlice {
    pub authority_id: String,
    pub repository: RepositoryId,
    pub path: String,
    pub start_anchor: String,
    pub end_anchor: String,
    pub sha256: String,
    pub required_markers: Vec<String>,
    pub forbidden_markers: Vec<String>,
    pub interpretation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRule {
    pub rule_id: String,
    pub repository: RepositoryId,
    pub roots: Vec<String>,
    pub file_extensions: Vec<String>,
    pub needles: Vec<String>,
    pub excluded_path_fragments: Vec<String>,
    pub expected_match_count: usize,
    pub interpretation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationCrosswalk {
    pub document_id: String,
    pub path: String,
    pub classification: String,
    pub required_text: Vec<String>,
    pub forbidden_text: Vec<String>,
    pub authority_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceCategory {
    IntlObject,
    StringMethod,
    NumberMethod,
    DateMethod,
    LocaleNegativeControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    ExposedProduction,
    AbsentProduction,
    InternalUnrouted,
    ExposedNegativeControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservationRelation {
    PreserveExactBehavior,
    PreserveAbsence,
    PreserveInternalNonCredit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptorContract {
    pub observable_from_javascript: bool,
    pub descriptor_kind: String,
    pub writable: Option<bool>,
    pub enumerable: Option<bool>,
    pub configurable: Option<bool>,
    pub function_name: Option<String>,
    pub function_length: Option<u32>,
    pub observation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceRow {
    pub surface_id: String,
    pub owner: String,
    pub category: SurfaceCategory,
    pub object_name: String,
    pub member_name: String,
    pub exposure: Exposure,
    pub production_routes: Vec<String>,
    pub internal_routes: Vec<String>,
    pub descriptor: DescriptorContract,
    pub locale_semantics: String,
    pub timezone_semantics: String,
    pub provider: String,
    pub data_version: String,
    pub error_semantics: String,
    pub fallback_semantics: String,
    pub capability_semantics: String,
    pub ecma262_score_relation: String,
    pub ecma402_score_relation: String,
    pub preservation_relation: PreservationRelation,
    pub ga_preservation_rule: String,
    pub authority_ids: Vec<String>,
    pub probe_ids: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeRunner {
    Frankenctl,
    FrankenNode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeExpectation {
    pub runner: ProbeRunner,
    pub expected_exit: i32,
    pub expected_console: Vec<String>,
    pub stderr_contains: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSpec {
    pub probe_id: String,
    pub surface_ids: Vec<String>,
    pub profile: String,
    pub locale: String,
    pub timezone: String,
    pub provider: String,
    pub data_version: String,
    pub source: String,
    pub environment: BTreeMap<String, String>,
    pub expectations: Vec<ProbeExpectation>,
    pub branch_authority_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalRecord {
    pub repository_license: String,
    pub external_runtime_data: Vec<String>,
    pub bundled_locale_data: String,
    pub review_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationFinding {
    pub reason_code: String,
    pub subject: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReport {
    pub schema_version: String,
    pub contract_id: String,
    pub decision: String,
    pub surface_count: usize,
    pub exposed_count: usize,
    pub absent_count: usize,
    pub internal_unrouted_count: usize,
    pub authority_count: usize,
    pub probe_count: usize,
    pub checks_run: usize,
    pub findings: Vec<ValidationFinding>,
}

impl ValidationReport {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.decision == "pass" && self.findings.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventContext {
    pub run_id: String,
    pub trace_id: String,
    pub test_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub attempt: u32,
    pub platform: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractEvent {
    pub schema_version: String,
    pub run_id: String,
    pub trace_id: String,
    pub test_id: String,
    pub scenario_id: String,
    pub seed: u64,
    pub attempt: u32,
    pub platform: String,
    pub target: String,
    pub profile: String,
    pub phase: String,
    pub sequence: u64,
    pub terminal: bool,
    pub decision: String,
    pub reason_code: String,
    pub reason: String,
    pub surface_id: Option<String>,
    pub owner: Option<String>,
    pub locale: Option<String>,
    pub timezone: Option<String>,
    pub provider: Option<String>,
    pub data_version: Option<String>,
    pub descriptor: Option<String>,
    pub input: Option<String>,
    pub result: Option<String>,
    pub error: Option<String>,
    pub fallback: Option<String>,
    pub duration_us: u64,
    pub resource_delta_bytes: i64,
    pub artifact_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeObservation {
    pub probe_id: String,
    pub runner: ProbeRunner,
    pub surface_ids: Vec<String>,
    pub profile: String,
    pub locale: String,
    pub timezone: String,
    pub provider: String,
    pub data_version: String,
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub console: Vec<String>,
    pub stderr_summary: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub decision: String,
    pub reason_code: String,
    pub duration_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeScoreboard {
    pub preservation_passed: usize,
    pub preservation_total: usize,
    pub ecma262_numerator_delta: i64,
    pub ecma262_denominator_delta: i64,
    pub ecma402_status: String,
    pub ecma402_passed: Option<usize>,
    pub ecma402_total: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeReport {
    pub schema_version: String,
    pub contract_id: String,
    pub decision: String,
    pub scoreboard: ProbeScoreboard,
    pub observations: Vec<ProbeObservation>,
    pub first_failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationResult {
    pub mutation_id: String,
    pub expected_reason_code: String,
    pub observed_reason_codes: Vec<String>,
    pub decision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationReport {
    pub schema_version: String,
    pub contract_id: String,
    pub decision: String,
    pub results: Vec<MutationResult>,
}

type ContractMutation = (
    &'static str,
    &'static str,
    Box<dyn Fn(&mut IntlSurfaceContract)>,
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    pub schema_version: String,
    pub contract_id: String,
    pub owning_bead: String,
    pub decision: String,
    pub source_cutoff: SourceCutoff,
    pub files: Vec<BundleFile>,
    pub reproduction_command: String,
}

#[derive(Debug, Clone)]
struct AuthoritySpec {
    authority_id: &'static str,
    repository: RepositoryId,
    path: &'static str,
    start_anchor: &'static str,
    end_anchor: &'static str,
    required_markers: &'static [&'static str],
    forbidden_markers: &'static [&'static str],
    interpretation: &'static str,
}

#[derive(Debug, Clone)]
pub struct ProbeRunConfig<'a> {
    pub repo_root: &'a Path,
    pub franken_node_root: &'a Path,
    pub contract_path: &'a Path,
    pub contract: &'a IntlSurfaceContract,
    pub frankenctl: &'a Path,
    pub franken_node: &'a Path,
    pub output_dir: &'a Path,
    pub context: EventContext,
}

/// Construct the canonical contract from bounded live authorities.
pub fn generate_contract(
    repo_root: &Path,
    franken_node_root: &Path,
) -> Result<IntlSurfaceContract, String> {
    let mut authorities = Vec::new();
    for spec in authority_specs() {
        authorities.push(materialize_authority(repo_root, franken_node_root, &spec)?);
    }
    authorities.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    Ok(canonical_contract_with_authorities(authorities))
}

fn canonical_contract_with_authorities(authorities: Vec<AuthoritySlice>) -> IntlSurfaceContract {
    let mut surfaces = canonical_surfaces();
    surfaces.sort_by(|left, right| left.surface_id.cmp(&right.surface_id));
    let mut probes = canonical_probes();
    probes.sort_by(|left, right| left.probe_id.cmp(&right.probe_id));

    IntlSurfaceContract {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        contract_id: CONTRACT_ID.to_string(),
        owning_bead: OWNING_BEAD.to_string(),
        purpose: "Freeze the exact shipped Intl and locale-sensitive surface before ECMA-402 implementation, preserving observable behavior and absence without crediting internal scaffolds.".to_string(),
        source_cutoff: SourceCutoff {
            engine_base_commit: ENGINE_BASE_COMMIT.to_string(),
            franken_node_base_commit: FRANKEN_NODE_BASE_COMMIT.to_string(),
            authority_hash_algorithm: "sha256 over UTF-8 bytes from the unique start anchor through the unique end anchor, inclusive".to_string(),
            authority_scope: "bounded implementation, route, documentation, test, and sibling dependency slices; unrelated repository bytes are outside the frozen digest".to_string(),
            engine_root_hint: "/dp/franken_engine".to_string(),
            franken_node_root_hint: "/dp/franken_node".to_string(),
        },
        scoring_boundary: ScoringBoundary {
            ecma262_profile: "ECMA-262 11th edition ES2020 normative profile".to_string(),
            ecma262_rule: "This contract changes neither numerator nor denominator. Frozen-surface preservation earns zero score points. String.prototype.localeCompare presence/coercion remains an ECMA-262 observable; collation quality never earns ECMA-262 pass credit here.".to_string(),
            ecma402_profile: "not selected by BRIDGE-26.1; BRIDGE-26.2 must pin the separate ECMA-402 2020 profile".to_string(),
            ecma402_rule: "No current row, including the callable localeCompare shortcut, counts as ECMA-402 conformance. A zero denominator is reported as not_measured, never 100%.".to_string(),
            preservation_score_name: "frozen_intl_surface_preservation".to_string(),
            preservation_rule: "Every probe-backed exposed, absent, and internal-non-credit row must retain its exact preservation relation; this is a compatibility score, not a conformance score.".to_string(),
            contamination_kill_rule: "Any report that adds preservation results to the ECMA-262 numerator/denominator, or renders an unselected ECMA-402 denominator as green, fails closed.".to_string(),
        },
        provider_policy: ProviderPolicy {
            default_locale: "No public Intl default exists. Internal date HostCalls hard-code/fallback to en-US; exposed localeCompare ignores locale arguments.".to_string(),
            default_timezone: "No public locale timezone provider exists. Ambient TZ is not consulted by the frozen exposed surface.".to_string(),
            public_provider: "none".to_string(),
            internal_date_provider: "hand-authored embedded en-US/en-GB/ja-JP tables in baseline_interpreter.rs; internal_unrouted and receives no public credit".to_string(),
            internal_case_provider: "Rust Unicode scalar to_lowercase/to_uppercase; internal_unrouted and locale arguments are ignored".to_string(),
            collation_provider: "deterministic Rust string ordering over the engine UTF-8 projection; locale/options are ignored".to_string(),
            data_versions: vec![
                "collation:utf8-projection-lexicographic-v1".to_string(),
                "internal-date:bd-1j1wy-inline-table-v1".to_string(),
                "internal-case:rust-unicode-build-version-unpinned".to_string(),
            ],
            ambient_environment_rule: "LANG, LC_ALL, and TZ must not change the frozen exposed results. Probe profiles C/UTC and hostile locale/TZ values are compared byte-for-byte.".to_string(),
            upgrade_rule: "BRIDGE-26.2 owns real Unicode/CLDR/tzdb/provider pins. Any provider or data change is a versioned migration and cannot rewrite this baseline.".to_string(),
        },
        authorities,
        discovery_rules: vec![DiscoveryRule {
            rule_id: "franken-node.no-independent-intl-shim".to_string(),
            repository: RepositoryId::FrankenNode,
            roots: vec!["crates/franken-node/src".to_string()],
            file_extensions: vec!["rs".to_string()],
            needles: vec![
                "Intl".to_string(),
                "localeCompare".to_string(),
                "toLocaleString".to_string(),
                "toLocaleDateString".to_string(),
                "toLocaleTimeString".to_string(),
                "toLocaleLowerCase".to_string(),
                "toLocaleUpperCase".to_string(),
            ],
            excluded_path_fragments: vec![],
            expected_match_count: 0,
            interpretation: "The product layer adds no independent Intl/locale compatibility shim; its native lane delegates to franken_engine.".to_string(),
        }],
        documentation_crosswalk: vec![
            DocumentationCrosswalk {
                document_id: "ecma262-profile-excludes-ecma402".to_string(),
                path: "docs/ECMA262_CONFORMANCE_TARGET.md".to_string(),
                classification: "binding-core-score-boundary".to_string(),
                required_text: vec![
                    "ECMA-402".to_string(),
                    "explicitly excludes ECMA-402 vectors".to_string(),
                ],
                forbidden_text: vec!["ECMA-402 conformance is complete".to_string()],
                authority_ids: vec!["engine.docs.ecma262-score-boundary".to_string()],
            },
            DocumentationCrosswalk {
                document_id: "bridge-plan-separate-intl-score".to_string(),
                path: "docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md".to_string(),
                classification: "authoritative-bridge-score-boundary".to_string(),
                required_text: vec![
                    "Annex B and ECMA-402 are separate scored tracks".to_string(),
                    "cannot inflate or".to_string(),
                    "depress the ES2020 normative headline".to_string(),
                ],
                forbidden_text: vec!["Intl is part of the ES2020 headline".to_string()],
                authority_ids: vec!["engine.docs.bridge-score-boundary".to_string()],
            },
            DocumentationCrosswalk {
                document_id: "stdlib-comment-no-intl-overclaim".to_string(),
                path: "crates/franken-engine/src/stdlib.rs".to_string(),
                classification: "source-documentation-corrected".to_string(),
                required_text: vec!["no exposed `Intl` global".to_string()],
                forbidden_text: vec!["Intl subset".to_string()],
                authority_ids: vec!["engine.stdlib.scope-comment".to_string()],
            },
        ],
        surfaces,
        probes,
        exclusions: vec![
            "String.prototype.normalize is Unicode-sensitive but not locale-sensitive; it remains in the ECMA-262 core track and is not an Intl preservation row.".to_string(),
            "Test262 intl402 profile selection, Unicode/CLDR/tzdb acquisition, normative-optional policy, and full constructors belong to BRIDGE-26.2 through BRIDGE-26.6.".to_string(),
            "Internal HostCall reachability from hand-authored IR is not a supported JavaScript or product API and receives no compatibility or conformance credit.".to_string(),
            "Node and Bun are reference runtimes only; their broader Intl surfaces do not define FrankenEngine's frozen baseline.".to_string(),
        ],
        legal: LegalRecord {
            repository_license: "MIT".to_string(),
            external_runtime_data: vec!["none acquired or redistributed by BRIDGE-26.1".to_string()],
            bundled_locale_data: "Existing hand-authored internal strings only; no CLDR/tzdb corpus is claimed or newly bundled.".to_string(),
            review_rule: "BRIDGE-26.2 must attach source and license records before any external locale data becomes authoritative.".to_string(),
        },
    }
}

/// Parse a contract with recursive unknown-field rejection supplied by the
/// `deny_unknown_fields` schema annotations.
pub fn parse_contract(bytes: &[u8]) -> Result<IntlSurfaceContract, String> {
    if bytes.len() > MAX_DISCOVERY_BYTES as usize {
        return Err(format!(
            "{ERROR_CARDINALITY}: contract bytes {} exceed {}",
            bytes.len(),
            MAX_DISCOVERY_BYTES
        ));
    }
    serde_json::from_slice(bytes).map_err(|error| format!("{ERROR_JSON}: {error}"))
}

/// Validate schema and cross-row invariants without consulting the filesystem.
#[must_use]
pub fn validate_contract(contract: &IntlSurfaceContract) -> ValidationReport {
    let mut validator = Validator::new(contract);
    validator.validate();
    validator.finish()
}

/// Validate the typed contract plus its bounded live authorities, discovery
/// rules, public documentation, canonical JSON, and rendered Markdown.
pub fn validate_contract_file(
    repo_root: &Path,
    franken_node_root: &Path,
    contract_path: &Path,
) -> ValidationReport {
    let bytes = match fs::read(contract_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return failed_report(
                ERROR_IO,
                contract_path.display().to_string(),
                error.to_string(),
            );
        }
    };
    let contract = match parse_contract(&bytes) {
        Ok(contract) => contract,
        Err(error) => {
            return failed_report(ERROR_JSON, contract_path.display().to_string(), error);
        }
    };
    let mut report = validate_contract(&contract);
    let mut checks = 0usize;

    let canonical = match canonical_json(&contract) {
        Ok(canonical) => canonical,
        Err(error) => {
            push_finding(&mut report, ERROR_JSON, "canonical-json", error);
            Vec::new()
        }
    };
    checks += 1;
    if !canonical.is_empty() && canonical != bytes {
        push_finding(
            &mut report,
            ERROR_CANONICAL_JSON,
            contract_path.display().to_string(),
            "contract is not canonical pretty JSON with one trailing newline",
        );
    }

    for authority in &contract.authorities {
        checks += validate_authority(repo_root, franken_node_root, authority, &mut report);
    }
    for rule in &contract.discovery_rules {
        checks += 1;
        match execute_discovery_rule(repo_root, franken_node_root, rule) {
            Ok(observed) if observed == rule.expected_match_count => {}
            Ok(observed) => push_finding(
                &mut report,
                ERROR_DISCOVERY,
                &rule.rule_id,
                format!(
                    "expected {} matches, observed {observed}",
                    rule.expected_match_count
                ),
            ),
            Err(error) => push_finding(&mut report, ERROR_DISCOVERY, &rule.rule_id, error),
        }
    }
    for doc in &contract.documentation_crosswalk {
        checks += validate_document(repo_root, doc, &mut report);
    }

    checks += 1;
    let markdown_path = repo_root.join(RENDERED_MARKDOWN_PATH);
    match fs::read(&markdown_path) {
        Ok(observed) => {
            let expected = render_markdown(&contract).into_bytes();
            if observed != expected {
                push_finding(
                    &mut report,
                    ERROR_MARKDOWN_DRIFT,
                    RENDERED_MARKDOWN_PATH,
                    "rendered Markdown differs from the typed contract",
                );
            }
        }
        Err(error) => push_finding(
            &mut report,
            ERROR_MARKDOWN_DRIFT,
            RENDERED_MARKDOWN_PATH,
            error.to_string(),
        ),
    }
    report.checks_run = report.checks_run.saturating_add(checks);
    report.decision = if report.findings.is_empty() {
        "pass".to_string()
    } else {
        "fail".to_string()
    };
    report
}

/// Produce bounded structured events for a validation report.  The final event
/// is the only terminal event in this sequence.
#[must_use]
pub fn validation_events(report: &ValidationReport, context: &EventContext) -> Vec<ContractEvent> {
    let mut events = Vec::new();
    events.push(base_event(
        context,
        "validation.start",
        0,
        false,
        "observe",
        "FE-INTL-0000",
        "validation started",
    ));
    for (index, finding) in report.findings.iter().enumerate() {
        let mut event = base_event(
            context,
            "validation.finding",
            index as u64 + 1,
            false,
            "fail",
            &finding.reason_code,
            &finding.message,
        );
        event.surface_id = Some(finding.subject.clone());
        events.push(event);
    }
    events.push(base_event(
        context,
        "validation.terminal",
        events.len() as u64,
        true,
        &report.decision,
        if report.passed() {
            "FE-INTL-0001"
        } else {
            report
                .findings
                .first()
                .map_or(ERROR_SCHEMA, |finding| finding.reason_code.as_str())
        },
        if report.passed() {
            "contract validation passed"
        } else {
            "contract validation failed"
        },
    ));
    events
}

/// Exercise the frozen production probes through fresh `frankenctl` and
/// `franken-node` processes.
pub fn run_probes(config: ProbeRunConfig<'_>) -> Result<ProbeReport, String> {
    let validation = validate_contract_file(
        config.repo_root,
        config.franken_node_root,
        config.contract_path,
    );
    if !validation.passed() {
        return Err(format!(
            "{ERROR_SCHEMA}: live contract validation failed before probes: {:?}",
            validation.findings
        ));
    }
    let input_contract = parse_contract(&fs::read(config.contract_path).map_err(|error| {
        format!(
            "{ERROR_IO}: read contract {}: {error}",
            config.contract_path.display()
        )
    })?)?;
    if input_contract != *config.contract {
        return Err(format!(
            "{ERROR_SCHEMA}: in-memory contract differs from the validated input snapshot"
        ));
    }
    let live_contract = generate_contract(config.repo_root, config.franken_node_root)?;
    if live_contract != *config.contract {
        return Err(format!(
            "{ERROR_SEMANTIC_DRIFT}: live authorities differ from the probe contract"
        ));
    }
    for (label, executable) in [
        ("frankenctl", config.frankenctl),
        ("franken-node", config.franken_node),
    ] {
        if !executable.is_file() {
            return Err(format!(
                "{ERROR_PROCESS}: {label} executable missing: {}",
                executable.display()
            ));
        }
    }
    if config.output_dir.exists() {
        return Err(format!(
            "{ERROR_OUTPUT_EXISTS}: output directory already exists: {}",
            config.output_dir.display()
        ));
    }
    fs::create_dir(config.output_dir)
        .map_err(|error| format!("{ERROR_IO}: create output directory: {error}"))?;
    for child in ["sources", "raw"] {
        fs::create_dir(config.output_dir.join(child))
            .map_err(|error| format!("{ERROR_IO}: create {child}: {error}"))?;
    }

    let mut observations = Vec::new();
    let mut events = Vec::new();
    let mut sequence = 0u64;
    for probe in &config.contract.probes {
        let source_path = config
            .output_dir
            .join("sources")
            .join(format!("{}.js", safe_file_component(&probe.probe_id)));
        write_create_new(&source_path, probe.source.as_bytes())?;

        for expectation in &probe.expectations {
            let executable = match expectation.runner {
                ProbeRunner::Frankenctl => config.frankenctl,
                ProbeRunner::FrankenNode => config.franken_node,
            };
            let runner_label = match expectation.runner {
                ProbeRunner::Frankenctl => "frankenctl",
                ProbeRunner::FrankenNode => "franken-node",
            };
            let raw_stem = format!("{}.{}", safe_file_component(&probe.probe_id), runner_label);
            let stdout_path = config
                .output_dir
                .join("raw")
                .join(format!("{raw_stem}.stdout"));
            let stderr_path = config
                .output_dir
                .join("raw")
                .join(format!("{raw_stem}.stderr"));
            let started = Instant::now();
            let (argv, output) = execute_probe_process(
                executable,
                config.frankenctl,
                &source_path,
                &stdout_path,
                &stderr_path,
                probe,
                expectation.runner,
            )?;
            let duration_us = saturating_micros(started.elapsed().as_micros());

            let exit_code = output.status.code().unwrap_or(128);
            let console = extract_console(expectation.runner, &output.stdout)?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_ok = exit_code == expectation.expected_exit;
            let console_ok = console == expectation.expected_console;
            let stderr_ok = expectation
                .stderr_contains
                .as_ref()
                .is_none_or(|needle| stderr.contains(needle));
            let decision = if exit_ok && console_ok && stderr_ok {
                "pass"
            } else {
                "fail"
            };
            let reason_code = if decision == "pass" {
                "FE-INTL-0200"
            } else {
                ERROR_PROBE_RESULT
            };
            let stderr_summary = redact_and_bound(&stderr, MAX_EVENT_REASON_BYTES)?;
            observations.push(ProbeObservation {
                probe_id: probe.probe_id.clone(),
                runner: expectation.runner,
                surface_ids: probe.surface_ids.clone(),
                profile: probe.profile.clone(),
                locale: probe.locale.clone(),
                timezone: probe.timezone.clone(),
                provider: probe.provider.clone(),
                data_version: probe.data_version.clone(),
                argv: argv.clone(),
                exit_code,
                console: console.clone(),
                stderr_summary: stderr_summary.clone(),
                stdout_sha256: sha256_hex(&output.stdout),
                stderr_sha256: sha256_hex(&output.stderr),
                decision: decision.to_string(),
                reason_code: reason_code.to_string(),
                duration_us,
            });
            for surface_id in &probe.surface_ids {
                let row = config
                    .contract
                    .surfaces
                    .iter()
                    .find(|row| &row.surface_id == surface_id)
                    .ok_or_else(|| {
                        format!(
                            "{ERROR_PROBE_COVERAGE}: probe {} references missing surface {surface_id}",
                            probe.probe_id
                        )
                    })?;
                let mut event = base_event(
                    &config.context,
                    "probe.observation",
                    sequence,
                    false,
                    decision,
                    reason_code,
                    if decision == "pass" {
                        "production probe matched the frozen observation"
                    } else {
                        "production probe diverged from the frozen observation"
                    },
                );
                sequence = sequence.saturating_add(1);
                event.scenario_id = probe.probe_id.clone();
                event.target = runner_label.to_string();
                event.profile = probe.profile.clone();
                event.surface_id = Some(surface_id.clone());
                event.owner = Some(row.owner.clone());
                event.locale = Some(probe.locale.clone());
                event.timezone = Some(probe.timezone.clone());
                event.provider = Some(probe.provider.clone());
                event.data_version = Some(probe.data_version.clone());
                event.descriptor = Some(redact_and_bound(
                    &serde_json::to_string(&row.descriptor)
                        .map_err(|error| format!("{ERROR_JSON}: descriptor: {error}"))?,
                    MAX_EVENT_REASON_BYTES,
                )?);
                event.input = Some(redact_and_bound(&probe.source, MAX_EVENT_REASON_BYTES)?);
                event.result = Some(redact_and_bound(
                    &format!("exit={exit_code};console={console:?}"),
                    MAX_EVENT_REASON_BYTES,
                )?);
                event.error = if stderr_summary.is_empty() {
                    None
                } else {
                    Some(stderr_summary.clone())
                };
                event.fallback = Some(row.fallback_semantics.clone());
                event.duration_us = duration_us;
                event.artifact_sha256 = Some(sha256_hex(&output.stdout));
                events.push(event);
            }
        }
    }
    observations
        .sort_by(|left, right| (&left.probe_id, left.runner).cmp(&(&right.probe_id, right.runner)));
    let first_failure = observations
        .iter()
        .find(|observation| observation.decision != "pass")
        .map(|observation| format!("{}:{:?}", observation.probe_id, observation.runner));
    let passed = config
        .contract
        .surfaces
        .iter()
        .filter(|row| {
            row.probe_ids.iter().all(|probe_id| {
                let expected = config
                    .contract
                    .probes
                    .iter()
                    .find(|probe| &probe.probe_id == probe_id)
                    .map_or(0, |probe| probe.expectations.len());
                let observed: Vec<&ProbeObservation> = observations
                    .iter()
                    .filter(|observation| &observation.probe_id == probe_id)
                    .collect();
                observed.len() == expected
                    && observed
                        .iter()
                        .all(|observation| observation.decision == "pass")
            })
        })
        .count();
    let overall_decision = if first_failure.is_none() && passed == config.contract.surfaces.len() {
        "pass"
    } else {
        "fail"
    };
    let terminal_reason = first_failure
        .as_deref()
        .unwrap_or("all frozen surface rows matched");
    let mut terminal = base_event(
        &config.context,
        "probe.terminal",
        sequence,
        true,
        overall_decision,
        if overall_decision == "pass" {
            "FE-INTL-0201"
        } else {
            ERROR_PROBE_RESULT
        },
        terminal_reason,
    );
    terminal.owner = Some(OWNING_BEAD.to_string());
    terminal.result = Some(format!(
        "preservation_passed={passed};preservation_total={}",
        config.contract.surfaces.len()
    ));
    events.push(terminal);
    let report = ProbeReport {
        schema_version: PROBE_REPORT_SCHEMA_VERSION.to_string(),
        contract_id: config.contract.contract_id.clone(),
        decision: overall_decision.to_string(),
        scoreboard: ProbeScoreboard {
            preservation_passed: passed,
            preservation_total: config.contract.surfaces.len(),
            ecma262_numerator_delta: 0,
            ecma262_denominator_delta: 0,
            ecma402_status: "not_measured_profile_unselected".to_string(),
            ecma402_passed: None,
            ecma402_total: None,
        },
        observations,
        first_failure,
    };
    write_create_new(
        &config.output_dir.join("probe_results.json"),
        &canonical_json(&report)?,
    )?;
    write_jsonl_create_new(&config.output_dir.join("events.jsonl"), &events)?;
    write_create_new(
        &config.output_dir.join("commands.txt"),
        render_probe_commands(&report).as_bytes(),
    )?;
    write_create_new(
        &config.output_dir.join("env.json"),
        &canonical_json(&probe_environment_manifest(config.contract))?,
    )?;
    write_create_new(
        &config.output_dir.join("LEGAL.md"),
        render_legal(config.contract).as_bytes(),
    )?;
    write_create_new(
        &config.output_dir.join("repro.lock"),
        render_probe_repro_lock(&config)?.as_bytes(),
    )?;
    seal_directory(
        config.output_dir,
        config.contract,
        "rerun scripts/bridge/run_bridge_26_intl_e2e.sh with the recorded binary and root arguments",
        &report.decision,
    )?;
    Ok(report)
}

/// Run in-memory mutants against the same validator used for the canonical
/// contract.  Success means every seeded defect was detected with its intended
/// stable reason code.
#[must_use]
pub fn run_mutation_suite(contract: &IntlSurfaceContract) -> MutationReport {
    let cases: Vec<ContractMutation> = vec![
        (
            "remove-exposed-member",
            ERROR_REQUIRED_SURFACE,
            Box::new(|candidate| {
                candidate
                    .surfaces
                    .retain(|row| row.surface_id != "string.prototype.locale_compare");
            }),
        ),
        (
            "duplicate-surface-id",
            ERROR_ORDER_OR_DUPLICATE,
            Box::new(|candidate| candidate.surfaces.push(candidate.surfaces[0].clone())),
        ),
        (
            "wrong-owner",
            ERROR_OWNER,
            Box::new(|candidate| candidate.surfaces[0].owner = "generic-tests".to_string()),
        ),
        (
            "false-exposed-intl-comment",
            ERROR_EXPOSURE,
            Box::new(|candidate| {
                let row = surface_mut(candidate, "intl.global");
                row.exposure = Exposure::ExposedProduction;
            }),
        ),
        (
            "hidden-date-route-substitution",
            ERROR_EXPOSURE,
            Box::new(|candidate| {
                let row = surface_mut(candidate, "date.prototype.to_locale_string");
                row.production_routes =
                    vec!["baseline_interpreter::execute_builtin_hostcall".to_string()];
            }),
        ),
        (
            "descriptor-fabrication",
            ERROR_DESCRIPTOR,
            Box::new(|candidate| {
                let row = surface_mut(candidate, "string.prototype.locale_compare");
                row.descriptor.observable_from_javascript = true;
                row.descriptor.writable = Some(true);
            }),
        ),
        (
            "core-score-contamination",
            ERROR_SCOREBOARD,
            Box::new(|candidate| {
                candidate.scoring_boundary.ecma262_rule =
                    "Add every preservation pass to the ES2020 numerator".to_string();
            }),
        ),
        (
            "intl-zero-denominator-green",
            ERROR_SCOREBOARD,
            Box::new(|candidate| {
                candidate.scoring_boundary.ecma402_rule =
                    "A zero denominator is complete and green".to_string();
            }),
        ),
        (
            "missing-probe",
            ERROR_PROBE_COVERAGE,
            Box::new(|candidate| {
                surface_mut(candidate, "number.prototype.to_locale_string")
                    .probe_ids
                    .clear();
            }),
        ),
        (
            "unknown-probe",
            ERROR_PROBE_COVERAGE,
            Box::new(|candidate| {
                surface_mut(candidate, "intl.global")
                    .probe_ids
                    .push("not-a-probe".to_string());
            }),
        ),
        (
            "locale-default-drift",
            ERROR_EXPOSURE,
            Box::new(|candidate| {
                candidate.provider_policy.default_locale = "ambient-host-default".to_string();
            }),
        ),
        (
            "timezone-default-drift",
            ERROR_EXPOSURE,
            Box::new(|candidate| {
                candidate.provider_policy.default_timezone = "ambient TZ".to_string();
            }),
        ),
        (
            "missing-data-version",
            ERROR_SEMANTIC_DRIFT,
            Box::new(|candidate| {
                surface_mut(candidate, "string.prototype.locale_compare")
                    .data_version
                    .clear();
            }),
        ),
        (
            "error-semantics-drift",
            ERROR_SEMANTIC_DRIFT,
            Box::new(|candidate| {
                surface_mut(candidate, "string.prototype.locale_compare").error_semantics =
                    "all errors are silently ignored".to_string();
            }),
        ),
        (
            "fallback-semantics-drift",
            ERROR_SEMANTIC_DRIFT,
            Box::new(|candidate| {
                surface_mut(candidate, "date.prototype.to_locale_string").fallback_semantics =
                    "ambient platform locale".to_string();
            }),
        ),
        (
            "hidden-compatibility-layer-substitution",
            ERROR_SEMANTIC_DRIFT,
            Box::new(|candidate| {
                candidate.discovery_rules[0].needles.clear();
                candidate.discovery_rules[0].expected_match_count = 0;
            }),
        ),
        (
            "missing-authority",
            ERROR_AUTHORITY,
            Box::new(|candidate| {
                candidate.authorities.remove(0);
            }),
        ),
        (
            "unsafe-authority-path",
            ERROR_UNSAFE_PATH,
            Box::new(|candidate| candidate.authorities[0].path = "../escape".to_string()),
        ),
        (
            "documentation-overclaim",
            ERROR_DOC_CROSSWALK,
            Box::new(|candidate| {
                candidate.documentation_crosswalk[0].forbidden_text.clear();
            }),
        ),
    ];
    let mut results = Vec::new();
    for (mutation_id, expected, mutate) in cases {
        let mut candidate = contract.clone();
        mutate(&mut candidate);
        let report = validate_contract(&candidate);
        let observed_reason_codes: Vec<String> = report
            .findings
            .iter()
            .map(|finding| finding.reason_code.clone())
            .collect();
        results.push(MutationResult {
            mutation_id: mutation_id.to_string(),
            expected_reason_code: expected.to_string(),
            decision: if observed_reason_codes
                .iter()
                .any(|observed| observed == expected)
            {
                "killed".to_string()
            } else {
                "survived".to_string()
            },
            observed_reason_codes,
        });
    }
    MutationReport {
        schema_version: MUTATION_REPORT_SCHEMA_VERSION.to_string(),
        contract_id: contract.contract_id.clone(),
        decision: if results.iter().all(|result| result.decision == "killed") {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        results,
    }
}

/// Render the generated operator document.  It intentionally says
/// "not measured" rather than converting the absent ECMA-402 denominator into
/// a percentage.
#[must_use]
pub fn render_markdown(contract: &IntlSurfaceContract) -> String {
    let mut out = String::new();
    out.push_str("# Intl Surface Contract V1\n\n");
    out.push_str("> Generated from `docs/intl_surface_contract_v1.json`; do not hand-edit.\n\n");
    out.push_str("## Honest headline\n\n");
    out.push_str(
        "The shipped FrankenEngine JavaScript surface has **no `Intl` global**. \
         `String.prototype.localeCompare` is callable through primitive-method resolution, \
         but it performs deterministic lexicographic comparison and ignores locale/options. \
         Date locale methods and locale-aware casing exist only as internal, unrouted HostCall \
         branches and receive no public or conformance credit.\n\n",
    );
    out.push_str("## Score boundary\n\n");
    out.push_str(&format!(
        "- ECMA-262: {}\n- ECMA-402: {}\n- Preservation: {}\n\n",
        contract.scoring_boundary.ecma262_rule,
        contract.scoring_boundary.ecma402_rule,
        contract.scoring_boundary.preservation_rule
    ));
    out.push_str("## Frozen surface\n\n");
    out.push_str(
        "| Surface | Exposure | Descriptor observation | ECMA-262 relation | ECMA-402 relation | GA rule |\n\
         |---|---|---|---|---|---|\n",
    );
    for row in &contract.surfaces {
        out.push_str(&format!(
            "| `{}` | `{:?}` | {} | {} | {} | {} |\n",
            row.surface_id,
            row.exposure,
            escape_markdown_cell(&row.descriptor.observation),
            escape_markdown_cell(&row.ecma262_score_relation),
            escape_markdown_cell(&row.ecma402_score_relation),
            escape_markdown_cell(&row.ga_preservation_rule),
        ));
    }
    out.push_str("\n## Provider and defaults\n\n");
    out.push_str(&format!(
        "- Public provider: `{}`\n- Default locale: {}\n- Default timezone: {}\n- Collation provider: {}\n- Ambient environment: {}\n\n",
        contract.provider_policy.public_provider,
        contract.provider_policy.default_locale,
        contract.provider_policy.default_timezone,
        contract.provider_policy.collation_provider,
        contract.provider_policy.ambient_environment_rule,
    ));
    out.push_str("## Reproduction\n\n");
    out.push_str(
        "Run `scripts/bridge/run_bridge_26_intl_e2e.sh --output-root <new-directory>`. \
         The script generates the registry twice, validates bounded source authorities, \
         kills the seeded mutation matrix, and runs each observation through fresh \
         `frankenctl` and `franken-node` processes. The ECMA-402 score remains \
         `not_measured_profile_unselected` until BRIDGE-26.2 selects its denominator.\n\n",
    );
    out.push_str("## Exclusions\n\n");
    for exclusion in &contract.exclusions {
        out.push_str(&format!("- {exclusion}\n"));
    }
    out
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| format!("{ERROR_JSON}: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn write_create_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{ERROR_UNSAFE_PATH}: output has no parent"))?;
    if !parent.is_dir() {
        return Err(format!(
            "{ERROR_IO}: output parent does not exist: {}",
            parent.display()
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            format!("{ERROR_OUTPUT_EXISTS}: {}", path.display())
        } else {
            format!("{ERROR_IO}: {}: {error}", path.display())
        }
    })?;
    file.write_all(bytes)
        .map_err(|error| format!("{ERROR_IO}: {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("{ERROR_IO}: sync {}: {error}", path.display()))
}

pub fn write_jsonl_create_new<T: Serialize>(path: &Path, rows: &[T]) -> Result<(), String> {
    let mut bytes = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut bytes, row).map_err(|error| format!("{ERROR_JSON}: {error}"))?;
        bytes.push(b'\n');
    }
    write_create_new(path, &bytes)
}

pub fn seal_directory(
    directory: &Path,
    contract: &IntlSurfaceContract,
    reproduction_command: &str,
    decision: &str,
) -> Result<BundleManifest, String> {
    let manifest_path = directory.join("run_manifest.json");
    if manifest_path.exists() {
        return Err(format!(
            "{ERROR_OUTPUT_EXISTS}: manifest already exists: {}",
            manifest_path.display()
        ));
    }
    let mut paths = Vec::new();
    collect_files(directory, directory, &mut paths)?;
    paths.retain(|path| path != Path::new("run_manifest.json"));
    paths.sort();
    let mut files = Vec::new();
    for relative in paths {
        let absolute = directory.join(&relative);
        let bytes = fs::read(&absolute)
            .map_err(|error| format!("{ERROR_IO}: {}: {error}", absolute.display()))?;
        files.push(BundleFile {
            path: relative.to_string_lossy().replace('\\', "/"),
            bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        });
    }
    let manifest = BundleManifest {
        schema_version: BUNDLE_MANIFEST_SCHEMA_VERSION.to_string(),
        contract_id: contract.contract_id.clone(),
        owning_bead: contract.owning_bead.clone(),
        decision: decision.to_string(),
        source_cutoff: contract.source_cutoff.clone(),
        files,
        reproduction_command: reproduction_command.to_string(),
    };
    write_create_new(&manifest_path, &canonical_json(&manifest)?)?;
    Ok(manifest)
}

fn authority_specs() -> Vec<AuthoritySpec> {
    vec![
        AuthoritySpec {
            authority_id: "engine.baseline.string-property-route",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/src/baseline_interpreter.rs",
            start_anchor: "    fn string_property_value(receiver: &str, key: &str) -> Value {",
            end_anchor: "    fn number_property_value(key: &str) -> Value {",
            required_markers: &[
                "\"localeCompare\" => Value::BuiltinFunction",
                "\"normalize\" => Value::BuiltinFunction",
            ],
            forbidden_markers: &["\"toLocaleLowerCase\" =>", "\"toLocaleUpperCase\" =>"],
            interpretation: "Primitive String property resolution exposes localeCompare but not locale casing.",
        },
        AuthoritySpec {
            authority_id: "engine.baseline.locale-compare-impl",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/src/baseline_interpreter.rs",
            start_anchor: "    fn string_locale_compare_impl(",
            end_anchor: "    fn string_normalize_impl(",
            required_markers: &["as_utf8_projection().cmp", "std::cmp::Ordering::Less"],
            forbidden_markers: &["Collator", "ICU", "locale_arg"],
            interpretation: "The exposed method uses deterministic lexicographic comparison and consumes only the first argument.",
        },
        AuthoritySpec {
            authority_id: "engine.baseline.number-property-route",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/src/baseline_interpreter.rs",
            start_anchor: "    fn number_property_value(key: &str) -> Value {",
            end_anchor: "    fn promise_property_value(key: &str) -> Value {",
            required_markers: &[
                "\"toFixed\" => Value::BuiltinFunction",
                "\"toString\" => Value::BuiltinFunction",
                "\"valueOf\" => Value::BuiltinFunction",
                "_ => Value::Undefined",
            ],
            forbidden_markers: &["\"toLocaleString\" =>"],
            interpretation: "Primitive Number property resolution exposes three non-locale methods and returns undefined for toLocaleString.",
        },
        AuthoritySpec {
            authority_id: "engine.baseline.runtime-global-injection",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/src/baseline_interpreter.rs",
            start_anchor: "    fn inject_runtime_globals(&mut self) -> Result<(), InterpreterError> {",
            end_anchor: "    fn inject_runtime_global_binding(",
            required_markers: &[
                "\"Promise\"",
                "\"Math\"",
                "\"Date\"",
                "\"Function\"",
                "\"console\"",
            ],
            forbidden_markers: &["\"Intl\""],
            interpretation: "Fresh realms inject supported globals explicitly and do not inject an Intl binding.",
        },
        AuthoritySpec {
            authority_id: "engine.baseline.internal-date-locale-hostcalls",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/src/baseline_interpreter.rs",
            start_anchor: "            \"builtin:DatePrototypeToLocaleString\" => {",
            end_anchor: "            \"builtin:ObjectPrototypeValueOf\" => {",
            required_markers: &[
                "DatePrototypeToLocaleDateString",
                "DatePrototypeToLocaleTimeString",
                "DatePrototypeToString",
                "format_date_with_locale",
            ],
            forbidden_markers: &[],
            interpretation: "Date locale implementations exist in HostCall dispatch, but the primitive/object JavaScript property route does not expose them.",
        },
        AuthoritySpec {
            authority_id: "engine.baseline.internal-date-locale-provider",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/src/baseline_interpreter.rs",
            start_anchor: "// Locale-aware date formatting implementation (bd-1j1wy)",
            end_anchor: "#[cfg(test)]\nmod active_builtin_regressions {",
            required_markers: &[
                "struct LocaleData",
                "\"en-US\" => LocaleData",
                "\"en-GB\" => LocaleData",
                "\"ja-JP\" => LocaleData",
                "Self::get_locale_data(\"en-US\")",
                "fn format_date_with_locale(",
                "fn format_timestamp_with_locale(",
            ],
            forbidden_markers: &["icu", "tzdb", "chrono"],
            interpretation: "The internal-only Date provider is a hand-authored three-locale table with simplified UTC-like arithmetic and en-US fallback.",
        },
        AuthoritySpec {
            authority_id: "engine.baseline.internal-locale-case-hostcalls",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/src/baseline_interpreter.rs",
            start_anchor: "            \"builtin:StringPrototypeToLocaleLowerCase\" => {",
            end_anchor: "                // Unknown builtin method - return undefined",
            required_markers: &[
                "StringPrototypeToLocaleUpperCase",
                "to_lowercase",
                "to_uppercase",
                "full locale support would require ICU",
            ],
            forbidden_markers: &[],
            interpretation: "Locale casing is internal-only and ignores the requested locale.",
        },
        AuthoritySpec {
            authority_id: "engine.intrinsics.locale-compare-row",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/src/intrinsics_table.rs",
            start_anchor: "            name: \"String.prototype.localeCompare\",",
            end_anchor: "            name: \"String.prototype.normalize\",",
            required_markers: &["string_locale_compare_impl", "JoinReceiverAndArgs"],
            forbidden_markers: &["DateTimeFormat"],
            interpretation: "The generated intrinsic table names localeCompare but does not define an Intl constructor.",
        },
        AuthoritySpec {
            authority_id: "engine.stdlib.scope-comment",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/src/stdlib.rs",
            start_anchor: "//! Coverage priorities",
            end_anchor: "use std::collections",
            required_markers: &["no exposed `Intl` global"],
            forbidden_markers: &["Intl subset"],
            interpretation: "Source documentation no longer promotes the nonexistent Intl global.",
        },
        AuthoritySpec {
            authority_id: "engine.frankenctl.production-route",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/src/bin/frankenctl.rs",
            start_anchor: "fn execute_run(args: RunArgs) -> Result<i32, String> {",
            end_anchor: "fn load_and_bind_data_contract(",
            required_markers: &[
                "ExecutionOrchestrator::try_new_with_runtime_authority",
                ".execute(&package)",
                "console_output",
            ],
            forbidden_markers: &["QuickJS", "V8"],
            interpretation: "The production probe enters the canonical parser/lowering/orchestrator/runtime path.",
        },
        AuthoritySpec {
            authority_id: "engine.docs.ecma262-score-boundary",
            repository: RepositoryId::FrankenEngine,
            path: "docs/ECMA262_CONFORMANCE_TARGET.md",
            start_anchor: "### Out of scope",
            end_anchor: "## Coverage surface",
            required_markers: &["ECMA-402", "explicitly excludes ECMA-402 vectors"],
            forbidden_markers: &["ECMA-402 conformance is complete"],
            interpretation: "The core ES2020 profile excludes the separate internationalization standard.",
        },
        AuthoritySpec {
            authority_id: "engine.docs.bridge-score-boundary",
            repository: RepositoryId::FrankenEngine,
            path: "docs/plans/PLAN_TO_CREATE_FRANKEN_ENGINE.md",
            start_anchor: "### 18.1 Outcome Definitions: Two Performance Scoreboards, One Conformance Gate",
            end_anchor: "### 18.2 P0 Decisions And Program Constitution",
            required_markers: &[
                "Annex B and ECMA-402 are separate scored tracks",
                "cannot inflate or",
                "depress the ES2020 normative headline",
            ],
            forbidden_markers: &["ECMA-402 is included in ES2020"],
            interpretation: "The bridge program requires an independent Intl scoreboard.",
        },
        AuthoritySpec {
            authority_id: "engine.tests.internal-date-locale",
            repository: RepositoryId::FrankenEngine,
            path: "crates/franken-engine/tests/locale_date_formatting.rs",
            start_anchor: "//! Integration tests for locale-aware date formatting (bd-1j1wy).",
            end_anchor: "fn test_config() -> InterpreterConfig {",
            required_markers: &["Date.prototype.toLocaleString", "en-US", "en-GB", "ja-JP"],
            forbidden_markers: &["frankenctl"],
            interpretation: "The historical locale-date suite calls hand-authored IR HostCalls and is test evidence, not proof of JavaScript exposure.",
        },
        AuthoritySpec {
            authority_id: "node.manifest.engine-dependency",
            repository: RepositoryId::FrankenNode,
            path: "crates/franken-node/Cargo.toml",
            start_anchor: "engine = [\"dep:frankenengine-engine\", \"dep:frankenengine-extension-host\"]",
            end_anchor: "blake3 = [\"dep:blake3\"]",
            required_markers: &["frankenengine-engine"],
            forbidden_markers: &["quickjs"],
            interpretation: "The product native lane consumes the canonical engine rather than defining a local Intl runtime.",
        },
        AuthoritySpec {
            authority_id: "node.dispatch.native-engine-route",
            repository: RepositoryId::FrankenNode,
            path: "crates/franken-node/src/ops/engine_dispatcher.rs",
            start_anchor: "    fn run_engine_native_guarded(",
            end_anchor: "    fn build_host_effect_ledger(",
            required_markers: &[
                "frankenengine_extension_host",
                "NativeEngineCancellation",
                "ExecutionOrchestrator::new_with_runtime_config_and_ambient_authority_grant",
                "orchestrator.execute(&package)",
            ],
            forbidden_markers: &["Intl", "localeCompare"],
            interpretation: "The product executes the sibling engine in its supervised native path and adds no locale shim at the boundary.",
        },
    ]
}

fn canonical_surfaces() -> Vec<SurfaceRow> {
    vec![
        surface(
            "intl.global",
            SurfaceCategory::IntlObject,
            "globalThis",
            "Intl",
            Exposure::AbsentProduction,
            vec![],
            vec![],
            absent_descriptor("`typeof Intl` evaluates to `undefined` in a fresh frankenctl/franken-node realm."),
            "No Intl namespace, constructor, locale negotiation, options processing, or locale data is exposed.",
            "No timezone surface.",
            "none",
            "none",
            "Property access beyond `typeof` would fail because the global binding is absent.",
            "No fallback; absence is observable.",
            "No capability can synthesize the missing binding.",
            "No ECMA-262 score delta; ECMA-402 remains a separate excluded profile.",
            "Zero ECMA-402 credit. Absence remains visible in the preservation score.",
            PreservationRelation::PreserveAbsence,
            "GA must not claim or accidentally expose a partial Intl namespace without a versioned migration.",
            vec![
                "engine.baseline.runtime-global-injection",
                "engine.docs.ecma262-score-boundary",
                "node.dispatch.native-engine-route",
            ],
            vec!["probe.intl-global-absent"],
            vec!["Absence does not waive the future ECMA-402 completion program."],
        ),
        surface(
            "string.prototype.locale_compare",
            SurfaceCategory::StringMethod,
            "String primitive synthetic prototype",
            "localeCompare",
            Exposure::ExposedProduction,
            vec![
                "frankenctl run -> ExecutionOrchestrator -> baseline interpreter -> string_property_value -> string_locale_compare_impl",
                "franken-node run --runtime franken-engine -> supervised native EngineDispatcher -> same engine route",
            ],
            vec![
                "builtin:StringPrototypeLocaleCompare HostCall duplicate implementation",
            ],
            DescriptorContract {
                observable_from_javascript: false,
                descriptor_kind: "synthetic primitive-method resolution; no exposed String.prototype object".to_string(),
                writable: None,
                enumerable: None,
                configurable: None,
                function_name: None,
                function_length: None,
                observation: "Calling works, but reading `.length` or `.name` fails with `type error: expected object, got function`; no property descriptor is observable.".to_string(),
            },
            "Compares the receiver UTF-8 projection lexicographically with ToString(first argument). Locale and options arguments are ignored.",
            "Timezone-independent.",
            "utf8-projection-lexicographic-v1",
            "collation:utf8-projection-lexicographic-v1",
            "Null/undefined receiver coercion follows the engine's primitive method rules; method metadata access currently errors.",
            "No locale fallback occurs because locale negotiation is not attempted.",
            "The ordinary VmDispatch/HeapAllocate execution profile applies; there is no Intl-specific capability.",
            "Method presence and core coercion remain observable; this contract contributes zero score points.",
            "Not ECMA-402 collation conformance. The shortcut receives zero Intl credit.",
            PreservationRelation::PreserveExactBehavior,
            "Preserve exact baseline outputs and environment independence until a signed provider migration intentionally supersedes them.",
            vec![
                "engine.baseline.string-property-route",
                "engine.baseline.locale-compare-impl",
                "engine.intrinsics.locale-compare-row",
                "engine.frankenctl.production-route",
                "node.dispatch.native-engine-route",
            ],
            vec![
                "probe.locale-compare-basic",
                "probe.locale-compare-env-hostile",
                "probe.locale-compare-locale-options-ignored",
                "probe.locale-compare-metadata-unobservable",
                "probe.locale-compare-undefined-coercion",
            ],
            vec![
                "Comparison is not locale-aware despite the method name.",
                "The implementation returns only -1, 0, or 1.",
            ],
        ),
        surface(
            "string.prototype.to_locale_lower_case",
            SurfaceCategory::StringMethod,
            "String primitive synthetic prototype",
            "toLocaleLowerCase",
            Exposure::InternalUnrouted,
            vec![],
            vec![
                "baseline interpreter HostCall builtin:StringPrototypeToLocaleLowerCase",
            ],
            absent_descriptor("`typeof \"I\".toLocaleLowerCase` evaluates to `undefined`; no descriptor is exposed."),
            "Internal HostCall applies Rust Unicode lowercase and ignores locale arguments.",
            "Timezone-independent.",
            "rust-unicode-case-internal",
            "internal-case:rust-unicode-build-version-unpinned",
            "Internal HostCall uses ordinary receiver coercion; no supported JavaScript call exists.",
            "No JavaScript fallback; the property is absent.",
            "Direct hand-authored IR still passes the normal HostCall capability gate, but that is not a supported public route.",
            "Absent from the frozen JavaScript core surface.",
            "Zero ECMA-402 credit; internal code is explicitly non-credit.",
            PreservationRelation::PreserveInternalNonCredit,
            "GA may preserve the internal branch, but must preserve public absence unless a reviewed route and provider migration lands.",
            vec![
                "engine.baseline.string-property-route",
                "engine.baseline.internal-locale-case-hostcalls",
            ],
            vec!["probe.locale-case-methods-absent"],
            vec!["No Turkish/Azeri/Lithuanian locale tailoring is implemented."],
        ),
        surface(
            "string.prototype.to_locale_upper_case",
            SurfaceCategory::StringMethod,
            "String primitive synthetic prototype",
            "toLocaleUpperCase",
            Exposure::InternalUnrouted,
            vec![],
            vec![
                "baseline interpreter HostCall builtin:StringPrototypeToLocaleUpperCase",
            ],
            absent_descriptor("`typeof \"i\".toLocaleUpperCase` evaluates to `undefined`; no descriptor is exposed."),
            "Internal HostCall applies Rust Unicode uppercase and ignores locale arguments.",
            "Timezone-independent.",
            "rust-unicode-case-internal",
            "internal-case:rust-unicode-build-version-unpinned",
            "Internal HostCall uses ordinary receiver coercion; no supported JavaScript call exists.",
            "No JavaScript fallback; the property is absent.",
            "Direct hand-authored IR still passes the normal HostCall capability gate, but that is not a supported public route.",
            "Absent from the frozen JavaScript core surface.",
            "Zero ECMA-402 credit; internal code is explicitly non-credit.",
            PreservationRelation::PreserveInternalNonCredit,
            "GA may preserve the internal branch, but must preserve public absence unless a reviewed route and provider migration lands.",
            vec![
                "engine.baseline.string-property-route",
                "engine.baseline.internal-locale-case-hostcalls",
            ],
            vec!["probe.locale-case-methods-absent"],
            vec!["No Turkish/Azeri/Lithuanian locale tailoring is implemented."],
        ),
        surface(
            "date.prototype.to_locale_string",
            SurfaceCategory::DateMethod,
            "Date instance",
            "toLocaleString",
            Exposure::InternalUnrouted,
            vec![],
            vec![
                "baseline interpreter HostCall builtin:DatePrototypeToLocaleString",
            ],
            absent_descriptor("`typeof new Date(0).toLocaleString` evaluates to `undefined`."),
            "Internal HostCall formats en-US/en-GB/ja-JP with hand-authored tables and falls back to en-US.",
            "Internal formatter performs raw UTC-like timestamp arithmetic and does not consult ambient TZ.",
            "inline-date-table-internal",
            "internal-date:bd-1j1wy-inline-table-v1",
            "Invalid/non-Date receivers return the string `Invalid Date` internally rather than a specification-accurate exception.",
            "Unsupported locale strings fall back to en-US internally.",
            "Normal HostCall capability dispatch only; no public locale capability.",
            "No core score credit because the JavaScript property is absent.",
            "Zero ECMA-402 credit; internal code is explicitly non-credit.",
            PreservationRelation::PreserveInternalNonCredit,
            "Preserve public absence and non-credit status until the canonical route is intentionally implemented.",
            vec![
                "engine.baseline.internal-date-locale-hostcalls",
                "engine.baseline.internal-date-locale-provider",
                "engine.tests.internal-date-locale",
            ],
            vec!["probe.date-locale-methods-absent"],
            vec!["Calendar arithmetic is deliberately simplified and not conformance-grade."],
        ),
        surface(
            "date.prototype.to_locale_date_string",
            SurfaceCategory::DateMethod,
            "Date instance",
            "toLocaleDateString",
            Exposure::InternalUnrouted,
            vec![],
            vec![
                "baseline interpreter HostCall builtin:DatePrototypeToLocaleDateString",
            ],
            absent_descriptor("`typeof new Date(0).toLocaleDateString` evaluates to `undefined`."),
            "Internal HostCall selects M/D/Y, D/M/Y, or Y-M-D for three hard-coded locale tags.",
            "Internal formatter ignores ambient TZ.",
            "inline-date-table-internal",
            "internal-date:bd-1j1wy-inline-table-v1",
            "Invalid/non-Date receivers return `Invalid Date` internally.",
            "Unknown locale falls back to en-US internally.",
            "Normal HostCall capability dispatch only; no public locale capability.",
            "No core score credit because the JavaScript property is absent.",
            "Zero ECMA-402 credit; internal code is explicitly non-credit.",
            PreservationRelation::PreserveInternalNonCredit,
            "Preserve public absence and non-credit status until the canonical route is intentionally implemented.",
            vec![
                "engine.baseline.internal-date-locale-hostcalls",
                "engine.baseline.internal-date-locale-provider",
                "engine.tests.internal-date-locale",
            ],
            vec!["probe.date-locale-methods-absent"],
            vec!["No calendar, numberingSystem, or options processing exists."],
        ),
        surface(
            "date.prototype.to_locale_time_string",
            SurfaceCategory::DateMethod,
            "Date instance",
            "toLocaleTimeString",
            Exposure::InternalUnrouted,
            vec![],
            vec![
                "baseline interpreter HostCall builtin:DatePrototypeToLocaleTimeString",
            ],
            absent_descriptor("`typeof new Date(0).toLocaleTimeString` evaluates to `undefined`."),
            "Internal HostCall renders fixed 24-hour HH:MM:SS for every locale.",
            "Internal formatter ignores ambient TZ.",
            "inline-date-table-internal",
            "internal-date:bd-1j1wy-inline-table-v1",
            "Invalid/non-Date receivers return `Invalid Date` internally.",
            "Unknown locale falls back to en-US data even though the time form is invariant.",
            "Normal HostCall capability dispatch only; no public locale capability.",
            "No core score credit because the JavaScript property is absent.",
            "Zero ECMA-402 credit; internal code is explicitly non-credit.",
            PreservationRelation::PreserveInternalNonCredit,
            "Preserve public absence and non-credit status until the canonical route is intentionally implemented.",
            vec![
                "engine.baseline.internal-date-locale-hostcalls",
                "engine.baseline.internal-date-locale-provider",
                "engine.tests.internal-date-locale",
            ],
            vec!["probe.date-locale-methods-absent"],
            vec!["No hour-cycle, timezone, or options processing exists."],
        ),
        surface(
            "number.prototype.to_locale_string",
            SurfaceCategory::NumberMethod,
            "Number primitive synthetic prototype",
            "toLocaleString",
            Exposure::AbsentProduction,
            vec![],
            vec![],
            absent_descriptor("`typeof (1234).toLocaleString` evaluates to `undefined`."),
            "No locale-sensitive number formatting path exists.",
            "Timezone-independent.",
            "none",
            "none",
            "Calling the absent value fails as an undefined function.",
            "No fallback.",
            "No capability can synthesize the missing method.",
            "No score delta; absence stays visible.",
            "Zero ECMA-402 credit.",
            PreservationRelation::PreserveAbsence,
            "GA must not claim NumberFormat or locale number formatting until a complete reviewed route lands.",
            vec![
                "engine.baseline.number-property-route",
                "node.dispatch.native-engine-route",
            ],
            vec!["probe.number-locale-method-absent"],
            vec!["Number.prototype.toString exists but is not locale-sensitive."],
        ),
        surface(
            "date.prototype.to_string_locale_negative_control",
            SurfaceCategory::LocaleNegativeControl,
            "Date instance",
            "toString",
            Exposure::ExposedNegativeControl,
            vec![
                "frankenctl/franken-node JavaScript Date instance -> generic object toString",
            ],
            vec![
                "builtin:DatePrototypeToString internal HostCall with fixed en-US formatter",
            ],
            DescriptorContract {
                observable_from_javascript: false,
                descriptor_kind: "synthetic generic object method".to_string(),
                writable: None,
                enumerable: None,
                configurable: None,
                function_name: None,
                function_length: None,
                observation: "`new Date(0).toString()` returns `[object Object]`, proving the hidden locale-aware Date HostCall is not the JavaScript route.".to_string(),
            },
            "The exposed result is generic and locale-insensitive; the internal fixed-en-US Date branch is not credited.",
            "Ambient TZ does not affect the exposed result.",
            "generic-object-stringification",
            "none",
            "Ordinary object toString behavior.",
            "No locale fallback.",
            "Ordinary VM dispatch.",
            "Negative control only; contributes no conformance points.",
            "Zero ECMA-402 credit.",
            PreservationRelation::PreserveExactBehavior,
            "Preserve this negative-control observation until Date method routing intentionally changes; then require an explicit migration.",
            vec![
                "engine.baseline.internal-date-locale-hostcalls",
                "engine.baseline.internal-date-locale-provider",
                "engine.frankenctl.production-route",
            ],
            vec!["probe.date-to-string-negative-control"],
            vec!["This row prevents an internal Date formatter from being misreported as public."],
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn surface(
    surface_id: &str,
    category: SurfaceCategory,
    object_name: &str,
    member_name: &str,
    exposure: Exposure,
    production_routes: Vec<&str>,
    internal_routes: Vec<&str>,
    descriptor: DescriptorContract,
    locale_semantics: &str,
    timezone_semantics: &str,
    provider: &str,
    data_version: &str,
    error_semantics: &str,
    fallback_semantics: &str,
    capability_semantics: &str,
    ecma262_score_relation: &str,
    ecma402_score_relation: &str,
    preservation_relation: PreservationRelation,
    ga_preservation_rule: &str,
    authority_ids: Vec<&str>,
    probe_ids: Vec<&str>,
    limitations: Vec<&str>,
) -> SurfaceRow {
    SurfaceRow {
        surface_id: surface_id.to_string(),
        owner: OWNING_BEAD.to_string(),
        category,
        object_name: object_name.to_string(),
        member_name: member_name.to_string(),
        exposure,
        production_routes: strings(production_routes),
        internal_routes: strings(internal_routes),
        descriptor,
        locale_semantics: locale_semantics.to_string(),
        timezone_semantics: timezone_semantics.to_string(),
        provider: provider.to_string(),
        data_version: data_version.to_string(),
        error_semantics: error_semantics.to_string(),
        fallback_semantics: fallback_semantics.to_string(),
        capability_semantics: capability_semantics.to_string(),
        ecma262_score_relation: ecma262_score_relation.to_string(),
        ecma402_score_relation: ecma402_score_relation.to_string(),
        preservation_relation,
        ga_preservation_rule: ga_preservation_rule.to_string(),
        authority_ids: strings(authority_ids),
        probe_ids: strings(probe_ids),
        limitations: strings(limitations),
    }
}

fn absent_descriptor(observation: &str) -> DescriptorContract {
    DescriptorContract {
        observable_from_javascript: false,
        descriptor_kind: "absent".to_string(),
        writable: None,
        enumerable: None,
        configurable: None,
        function_name: None,
        function_length: None,
        observation: observation.to_string(),
    }
}

fn canonical_probes() -> Vec<ProbeSpec> {
    vec![
        probe(
            "probe.intl-global-absent",
            vec!["intl.global"],
            "default",
            "C",
            "UTC",
            "none",
            "none",
            "console.log(typeof Intl);",
            env("C", "C", "UTC"),
            success_both(vec!["undefined"]),
            vec![
                "engine.frankenctl.production-route",
                "node.dispatch.native-engine-route",
            ],
        ),
        probe(
            "probe.locale-compare-basic",
            vec!["string.prototype.locale_compare"],
            "default",
            "C",
            "UTC",
            "utf8-projection-lexicographic-v1",
            "collation:utf8-projection-lexicographic-v1",
            "console.log(\"a\".localeCompare(\"b\")); console.log(\"x\".localeCompare(\"x\")); console.log(\"z\".localeCompare(\"a\"));",
            env("C", "C", "UTC"),
            success_both(vec!["-1", "0", "1"]),
            vec![
                "engine.baseline.string-property-route",
                "engine.baseline.locale-compare-impl",
                "engine.frankenctl.production-route",
            ],
        ),
        probe(
            "probe.locale-compare-env-hostile",
            vec!["string.prototype.locale_compare"],
            "hostile-env",
            "tr-TR",
            "Pacific/Honolulu",
            "utf8-projection-lexicographic-v1",
            "collation:utf8-projection-lexicographic-v1",
            "console.log(\"a\".localeCompare(\"b\")); console.log(\"x\".localeCompare(\"x\")); console.log(\"z\".localeCompare(\"a\"));",
            env("tr_TR.UTF-8", "tr_TR.UTF-8", "Pacific/Honolulu"),
            success_both(vec!["-1", "0", "1"]),
            vec![
                "engine.baseline.locale-compare-impl",
                "node.dispatch.native-engine-route",
            ],
        ),
        probe(
            "probe.locale-compare-locale-options-ignored",
            vec!["string.prototype.locale_compare"],
            "default",
            "de-DE,tr-TR",
            "UTC",
            "utf8-projection-lexicographic-v1",
            "collation:utf8-projection-lexicographic-v1",
            "console.log(\"A\".localeCompare(\"a\",\"tr\",{sensitivity:\"base\"})); console.log(\"ä\".localeCompare(\"z\",\"de\"));",
            env("C", "C", "UTC"),
            success_both(vec!["-1", "1"]),
            vec!["engine.baseline.locale-compare-impl"],
        ),
        probe(
            "probe.locale-compare-metadata-unobservable",
            vec!["string.prototype.locale_compare"],
            "default",
            "C",
            "UTC",
            "utf8-projection-lexicographic-v1",
            "collation:utf8-projection-lexicographic-v1",
            "console.log(\"a\".localeCompare.length);",
            env("C", "C", "UTC"),
            vec![ProbeExpectation {
                runner: ProbeRunner::Frankenctl,
                expected_exit: 2,
                expected_console: vec![],
                stderr_contains: Some("expected object, got function".to_string()),
            }],
            vec!["engine.baseline.string-property-route"],
        ),
        probe(
            "probe.locale-compare-undefined-coercion",
            vec!["string.prototype.locale_compare"],
            "default",
            "C",
            "UTC",
            "utf8-projection-lexicographic-v1",
            "collation:utf8-projection-lexicographic-v1",
            "console.log(\"undefined\".localeCompare()); console.log(\"2\".localeCompare(10));",
            env("C", "C", "UTC"),
            success_both(vec!["0", "1"]),
            vec!["engine.baseline.locale-compare-impl"],
        ),
        probe(
            "probe.locale-case-methods-absent",
            vec![
                "string.prototype.to_locale_lower_case",
                "string.prototype.to_locale_upper_case",
            ],
            "default",
            "tr-TR",
            "UTC",
            "none",
            "none",
            "console.log(typeof \"I\".toLocaleLowerCase); console.log(typeof \"i\".toLocaleUpperCase);",
            env("tr_TR.UTF-8", "tr_TR.UTF-8", "UTC"),
            success_both(vec!["undefined", "undefined"]),
            vec![
                "engine.baseline.string-property-route",
                "engine.baseline.internal-locale-case-hostcalls",
            ],
        ),
        probe(
            "probe.date-locale-methods-absent",
            vec![
                "date.prototype.to_locale_string",
                "date.prototype.to_locale_date_string",
                "date.prototype.to_locale_time_string",
            ],
            "default",
            "en-US",
            "UTC",
            "none",
            "none",
            "const d=new Date(0); console.log(typeof d.toLocaleString); console.log(typeof d.toLocaleDateString); console.log(typeof d.toLocaleTimeString);",
            env("en_US.UTF-8", "en_US.UTF-8", "UTC"),
            success_both(vec!["undefined", "undefined", "undefined"]),
            vec!["engine.baseline.internal-date-locale-hostcalls"],
        ),
        probe(
            "probe.number-locale-method-absent",
            vec!["number.prototype.to_locale_string"],
            "default",
            "de-DE",
            "UTC",
            "none",
            "none",
            "const n=1234; console.log(typeof n.toLocaleString);",
            env("de_DE.UTF-8", "de_DE.UTF-8", "UTC"),
            success_both(vec!["undefined"]),
            vec!["engine.baseline.string-property-route"],
        ),
        probe(
            "probe.date-to-string-negative-control",
            vec!["date.prototype.to_string_locale_negative_control"],
            "default",
            "en-US",
            "Pacific/Honolulu",
            "generic-object-stringification",
            "none",
            "const d=new Date(0); console.log(d.toString());",
            env("en_US.UTF-8", "en_US.UTF-8", "Pacific/Honolulu"),
            success_both(vec!["[object Object]"]),
            vec![
                "engine.baseline.internal-date-locale-hostcalls",
                "engine.frankenctl.production-route",
            ],
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn probe(
    probe_id: &str,
    surface_ids: Vec<&str>,
    profile: &str,
    locale: &str,
    timezone: &str,
    provider: &str,
    data_version: &str,
    source: &str,
    environment: BTreeMap<String, String>,
    expectations: Vec<ProbeExpectation>,
    branch_authority_ids: Vec<&str>,
) -> ProbeSpec {
    ProbeSpec {
        probe_id: probe_id.to_string(),
        surface_ids: strings(surface_ids),
        profile: profile.to_string(),
        locale: locale.to_string(),
        timezone: timezone.to_string(),
        provider: provider.to_string(),
        data_version: data_version.to_string(),
        source: format!("{source}\n"),
        environment,
        expectations,
        branch_authority_ids: strings(branch_authority_ids),
    }
}

fn success_both(console: Vec<&str>) -> Vec<ProbeExpectation> {
    let console = strings(console);
    vec![
        ProbeExpectation {
            runner: ProbeRunner::Frankenctl,
            expected_exit: 0,
            expected_console: console.clone(),
            stderr_contains: None,
        },
        ProbeExpectation {
            runner: ProbeRunner::FrankenNode,
            expected_exit: 0,
            expected_console: console,
            stderr_contains: None,
        },
    ]
}

fn env(lang: &str, lc_all: &str, timezone: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("LANG".to_string(), lang.to_string()),
        ("LC_ALL".to_string(), lc_all.to_string()),
        ("TZ".to_string(), timezone.to_string()),
    ])
}

fn strings(values: Vec<&str>) -> Vec<String> {
    values.into_iter().map(str::to_string).collect()
}

struct Validator<'a> {
    contract: &'a IntlSurfaceContract,
    findings: Vec<ValidationFinding>,
    checks_run: usize,
}

impl<'a> Validator<'a> {
    fn new(contract: &'a IntlSurfaceContract) -> Self {
        Self {
            contract,
            findings: Vec::new(),
            checks_run: 0,
        }
    }

    fn validate(&mut self) {
        self.check(
            self.contract.schema_version == CONTRACT_SCHEMA_VERSION,
            ERROR_SCHEMA,
            "schema_version",
            format!(
                "expected {CONTRACT_SCHEMA_VERSION}, got {}",
                self.contract.schema_version
            ),
        );
        self.check(
            self.contract.contract_id == CONTRACT_ID,
            ERROR_SCHEMA,
            "contract_id",
            format!("expected {CONTRACT_ID}, got {}", self.contract.contract_id),
        );
        self.check(
            self.contract.owning_bead == OWNING_BEAD,
            ERROR_OWNER,
            "owning_bead",
            "contract owner drifted",
        );
        self.check(
            !self.contract.surfaces.is_empty() && self.contract.surfaces.len() <= MAX_SURFACES,
            ERROR_CARDINALITY,
            "surfaces",
            "surface count is zero or exceeds the bound",
        );
        self.check(
            !self.contract.authorities.is_empty()
                && self.contract.authorities.len() <= MAX_AUTHORITIES,
            ERROR_CARDINALITY,
            "authorities",
            "authority count is zero or exceeds the bound",
        );
        self.check(
            !self.contract.probes.is_empty() && self.contract.probes.len() <= MAX_PROBES,
            ERROR_CARDINALITY,
            "probes",
            "probe count is zero or exceeds the bound",
        );
        self.validate_order_and_ids();
        self.validate_frozen_semantics();
        self.validate_scoreboard();
        self.validate_provider();
        self.validate_authority_references();
        self.validate_surfaces();
        self.validate_probes();
        self.validate_docs();
        self.validate_string_bounds();
    }

    fn validate_frozen_semantics(&mut self) {
        let expected = canonical_contract_with_authorities(self.contract.authorities.clone());
        self.check(
            self.contract == &expected,
            ERROR_SEMANTIC_DRIFT,
            "canonical-semantic-baseline",
            "the frozen registry differs from the versioned canonical baseline",
        );
    }

    fn validate_order_and_ids(&mut self) {
        let surface_ids: Vec<&str> = self
            .contract
            .surfaces
            .iter()
            .map(|row| row.surface_id.as_str())
            .collect();
        self.check_sorted_unique("surfaces", &surface_ids);
        let authority_ids: Vec<&str> = self
            .contract
            .authorities
            .iter()
            .map(|row| row.authority_id.as_str())
            .collect();
        self.check_sorted_unique("authorities", &authority_ids);
        let probe_ids: Vec<&str> = self
            .contract
            .probes
            .iter()
            .map(|row| row.probe_id.as_str())
            .collect();
        self.check_sorted_unique("probes", &probe_ids);

        let actual: BTreeSet<&str> = surface_ids.into_iter().collect();
        for required in REQUIRED_SURFACE_IDS {
            self.check(
                actual.contains(required),
                ERROR_REQUIRED_SURFACE,
                *required,
                "mandatory frozen surface row is missing",
            );
        }
    }

    fn validate_scoreboard(&mut self) {
        let scoring = &self.contract.scoring_boundary;
        self.check(
            scoring
                .ecma262_rule
                .contains("neither numerator nor denominator")
                && scoring.ecma262_rule.contains("zero score points"),
            ERROR_SCOREBOARD,
            "scoring_boundary.ecma262_rule",
            "ECMA-262 contamination guard is missing",
        );
        self.check(
            scoring.ecma402_rule.contains("No current row")
                && scoring.ecma402_rule.contains("not_measured")
                && scoring.ecma402_rule.contains("never 100%"),
            ERROR_SCOREBOARD,
            "scoring_boundary.ecma402_rule",
            "ECMA-402 unselected-denominator guard is missing",
        );
        self.check(
            scoring.contamination_kill_rule.contains("fails closed"),
            ERROR_SCOREBOARD,
            "scoring_boundary.contamination_kill_rule",
            "score contamination must fail closed",
        );
    }

    fn validate_provider(&mut self) {
        let policy = &self.contract.provider_policy;
        self.check(
            policy.public_provider == "none",
            ERROR_EXPOSURE,
            "provider_policy.public_provider",
            "BRIDGE-26.1 must not fabricate a public provider",
        );
        self.check(
            policy
                .default_locale
                .contains("No public Intl default exists")
                && !policy.default_locale.contains("ambient-host-default"),
            ERROR_EXPOSURE,
            "provider_policy.default_locale",
            "public default locale posture drifted",
        );
        self.check(
            policy
                .default_timezone
                .contains("No public locale timezone provider exists")
                && !policy.default_timezone.eq_ignore_ascii_case("ambient tz"),
            ERROR_EXPOSURE,
            "provider_policy.default_timezone",
            "public timezone posture drifted",
        );
        self.check(
            policy.ambient_environment_rule.contains("must not change"),
            ERROR_EXPOSURE,
            "provider_policy.ambient_environment_rule",
            "ambient locale/TZ independence is not frozen",
        );
    }

    fn validate_authority_references(&mut self) {
        let ids: BTreeSet<&str> = self
            .contract
            .authorities
            .iter()
            .map(|authority| authority.authority_id.as_str())
            .collect();
        let specs = authority_specs();
        self.check(
            self.contract.authorities.len() == specs.len(),
            ERROR_AUTHORITY,
            "authorities",
            "authority inventory differs from the canonical bounded source set",
        );
        for spec in &specs {
            let observed = self
                .contract
                .authorities
                .iter()
                .find(|authority| authority.authority_id == spec.authority_id);
            self.check(
                observed.is_some_and(|authority| {
                    authority.repository == spec.repository
                        && authority.path == spec.path
                        && authority.start_anchor == spec.start_anchor
                        && authority.end_anchor == spec.end_anchor
                        && authority.required_markers == strings(spec.required_markers.to_vec())
                        && authority.forbidden_markers == strings(spec.forbidden_markers.to_vec())
                        && authority.interpretation == spec.interpretation
                }),
                ERROR_AUTHORITY,
                spec.authority_id,
                "authority metadata differs from the canonical bounded slice",
            );
        }
        for authority in &self.contract.authorities {
            self.check(
                is_safe_relative_path(Path::new(&authority.path)),
                ERROR_UNSAFE_PATH,
                &authority.authority_id,
                "authority path is absolute or traverses",
            );
            self.check(
                is_sha256(&authority.sha256),
                ERROR_AUTHORITY_HASH,
                &authority.authority_id,
                "authority hash is not lowercase SHA-256",
            );
            self.check(
                !authority.start_anchor.is_empty()
                    && !authority.end_anchor.is_empty()
                    && authority.start_anchor != authority.end_anchor,
                ERROR_AUTHORITY,
                &authority.authority_id,
                "authority anchors must be nonempty and distinct",
            );
        }
        for row in &self.contract.surfaces {
            self.check(
                !row.authority_ids.is_empty(),
                ERROR_AUTHORITY,
                &row.surface_id,
                "surface has no authority",
            );
            for authority_id in &row.authority_ids {
                self.check(
                    ids.contains(authority_id.as_str()),
                    ERROR_AUTHORITY,
                    &row.surface_id,
                    format!("unknown authority {authority_id}"),
                );
            }
        }
        for probe in &self.contract.probes {
            for authority_id in &probe.branch_authority_ids {
                self.check(
                    ids.contains(authority_id.as_str()),
                    ERROR_AUTHORITY,
                    &probe.probe_id,
                    format!("unknown branch authority {authority_id}"),
                );
            }
        }
    }

    fn validate_surfaces(&mut self) {
        let probe_ids: BTreeSet<&str> = self
            .contract
            .probes
            .iter()
            .map(|probe| probe.probe_id.as_str())
            .collect();
        for row in &self.contract.surfaces {
            self.check(
                row.owner == OWNING_BEAD,
                ERROR_OWNER,
                &row.surface_id,
                "surface owner must be the specialized BRIDGE-26.1 registry",
            );
            self.check(
                !row.probe_ids.is_empty(),
                ERROR_PROBE_COVERAGE,
                &row.surface_id,
                "surface has no production observation probe",
            );
            for probe_id in &row.probe_ids {
                self.check(
                    probe_ids.contains(probe_id.as_str()),
                    ERROR_PROBE_COVERAGE,
                    &row.surface_id,
                    format!("unknown probe {probe_id}"),
                );
            }
            self.check(
                !row.data_version.is_empty(),
                ERROR_EXPOSURE,
                &row.surface_id,
                "data version must be explicit, including `none`",
            );
            match row.exposure {
                Exposure::ExposedProduction | Exposure::ExposedNegativeControl => {
                    self.check(
                        !row.production_routes.is_empty(),
                        ERROR_EXPOSURE,
                        &row.surface_id,
                        "exposed row lacks a production route",
                    );
                }
                Exposure::AbsentProduction => {
                    self.check(
                        row.production_routes.is_empty() && row.internal_routes.is_empty(),
                        ERROR_EXPOSURE,
                        &row.surface_id,
                        "absent row cannot carry production/internal routes",
                    );
                    self.check(
                        row.preservation_relation == PreservationRelation::PreserveAbsence,
                        ERROR_EXPOSURE,
                        &row.surface_id,
                        "absent row must preserve absence",
                    );
                }
                Exposure::InternalUnrouted => {
                    self.check(
                        row.production_routes.is_empty() && !row.internal_routes.is_empty(),
                        ERROR_EXPOSURE,
                        &row.surface_id,
                        "internal-unrouted row has a production route or no internal route",
                    );
                    self.check(
                        row.preservation_relation
                            == PreservationRelation::PreserveInternalNonCredit,
                        ERROR_EXPOSURE,
                        &row.surface_id,
                        "internal row must preserve non-credit status",
                    );
                }
            }
            if !row.descriptor.observable_from_javascript {
                self.check(
                    row.descriptor.writable.is_none()
                        && row.descriptor.enumerable.is_none()
                        && row.descriptor.configurable.is_none()
                        && row.descriptor.function_name.is_none()
                        && row.descriptor.function_length.is_none(),
                    ERROR_DESCRIPTOR,
                    &row.surface_id,
                    "unobservable descriptor cannot fabricate fields",
                );
            }
            self.check(
                !row.descriptor.observation.is_empty(),
                ERROR_DESCRIPTOR,
                &row.surface_id,
                "descriptor observation is empty",
            );
            self.check(
                row.ecma402_score_relation.contains("Zero ECMA-402 credit")
                    || row.ecma402_score_relation.contains("Not ECMA-402"),
                ERROR_SCOREBOARD,
                &row.surface_id,
                "row can be misread as ECMA-402 credit",
            );
        }

        if let Some(intl) = self
            .contract
            .surfaces
            .iter()
            .find(|row| row.surface_id == "intl.global")
        {
            self.check(
                intl.exposure == Exposure::AbsentProduction,
                ERROR_EXPOSURE,
                "intl.global",
                "a comment or type cannot promote the absent Intl global",
            );
        }
        if let Some(locale_compare) = self
            .contract
            .surfaces
            .iter()
            .find(|row| row.surface_id == "string.prototype.locale_compare")
        {
            self.check(
                locale_compare.exposure == Exposure::ExposedProduction
                    && locale_compare
                        .locale_semantics
                        .contains("lexicographically")
                    && locale_compare.locale_semantics.contains("ignored"),
                ERROR_EXPOSURE,
                "string.prototype.locale_compare",
                "callable shortcut semantics are not frozen honestly",
            );
            self.check(
                !locale_compare.descriptor.observable_from_javascript,
                ERROR_DESCRIPTOR,
                "string.prototype.locale_compare",
                "method metadata is not currently observable",
            );
        }
    }

    fn validate_probes(&mut self) {
        let surface_ids: BTreeSet<&str> = self
            .contract
            .surfaces
            .iter()
            .map(|row| row.surface_id.as_str())
            .collect();
        for probe in &self.contract.probes {
            self.check(
                !probe.surface_ids.is_empty(),
                ERROR_PROBE_COVERAGE,
                &probe.probe_id,
                "probe has no surface",
            );
            for surface_id in &probe.surface_ids {
                self.check(
                    surface_ids.contains(surface_id.as_str()),
                    ERROR_PROBE_COVERAGE,
                    &probe.probe_id,
                    format!("unknown surface {surface_id}"),
                );
            }
            let runners: BTreeSet<ProbeRunner> = probe
                .expectations
                .iter()
                .map(|expectation| expectation.runner)
                .collect();
            self.check(
                runners.contains(&ProbeRunner::Frankenctl),
                ERROR_PROBE_COVERAGE,
                &probe.probe_id,
                "every probe must exercise frankenctl",
            );
            if probe.probe_id != "probe.locale-compare-metadata-unobservable" {
                self.check(
                    runners.contains(&ProbeRunner::FrankenNode),
                    ERROR_PROBE_COVERAGE,
                    &probe.probe_id,
                    "every successful behavior probe must exercise franken-node",
                );
            }
            self.check(
                probe.environment.contains_key("LANG")
                    && probe.environment.contains_key("LC_ALL")
                    && probe.environment.contains_key("TZ"),
                ERROR_PROBE_COVERAGE,
                &probe.probe_id,
                "probe environment lacks LANG/LC_ALL/TZ",
            );
            self.check(
                probe.source.ends_with('\n') && probe.source.contains("console.log"),
                ERROR_PROBE_COVERAGE,
                &probe.probe_id,
                "probe source must be canonical and externally observable",
            );
        }
        let hostile = self
            .contract
            .probes
            .iter()
            .find(|probe| probe.probe_id == "probe.locale-compare-env-hostile");
        self.check(
            hostile.is_some_and(|probe| {
                probe.timezone == "Pacific/Honolulu"
                    && probe.locale == "tr-TR"
                    && probe
                        .environment
                        .get("LC_ALL")
                        .is_some_and(|value| value.starts_with("tr_"))
            }),
            ERROR_PROBE_COVERAGE,
            "probe.locale-compare-env-hostile",
            "host-default leakage probe is missing or weak",
        );
    }

    fn validate_docs(&mut self) {
        let authority_ids: BTreeSet<&str> = self
            .contract
            .authorities
            .iter()
            .map(|authority| authority.authority_id.as_str())
            .collect();
        self.check(
            self.contract.documentation_crosswalk.len() >= 3,
            ERROR_DOC_CROSSWALK,
            "documentation_crosswalk",
            "core, bridge, and source-documentation rows are mandatory",
        );
        for doc in &self.contract.documentation_crosswalk {
            self.check(
                is_safe_relative_path(Path::new(&doc.path)),
                ERROR_UNSAFE_PATH,
                &doc.document_id,
                "documentation path traverses",
            );
            self.check(
                !doc.required_text.is_empty()
                    && !doc.forbidden_text.is_empty()
                    && !doc.authority_ids.is_empty(),
                ERROR_DOC_CROSSWALK,
                &doc.document_id,
                "documentation row lacks required/forbidden/authority coverage",
            );
            for authority_id in &doc.authority_ids {
                self.check(
                    authority_ids.contains(authority_id.as_str()),
                    ERROR_DOC_CROSSWALK,
                    &doc.document_id,
                    format!("unknown authority {authority_id}"),
                );
            }
        }
    }

    fn validate_string_bounds(&mut self) {
        let json = match serde_json::to_value(self.contract) {
            Ok(json) => json,
            Err(error) => {
                self.find(
                    ERROR_JSON,
                    "contract",
                    format!("failed to serialize for bounds: {error}"),
                );
                return;
            }
        };
        let mut stack = vec![json];
        while let Some(value) = stack.pop() {
            match value {
                serde_json::Value::String(text) => self.check(
                    text.len() <= MAX_FIELD_BYTES,
                    ERROR_CARDINALITY,
                    "string-field",
                    format!("field exceeds {MAX_FIELD_BYTES} bytes"),
                ),
                serde_json::Value::Array(values) => stack.extend(values),
                serde_json::Value::Object(values) => stack.extend(values.into_values()),
                _ => {}
            }
        }
    }

    fn check_sorted_unique(&mut self, subject: &str, values: &[&str]) {
        let sorted = values.windows(2).all(|pair| pair[0] < pair[1]);
        self.check(
            sorted,
            ERROR_ORDER_OR_DUPLICATE,
            subject,
            "rows must be strictly sorted and unique",
        );
    }

    fn check(
        &mut self,
        condition: bool,
        code: &str,
        subject: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.checks_run = self.checks_run.saturating_add(1);
        if !condition {
            self.find(code, subject, message);
        }
    }

    fn find(&mut self, code: &str, subject: impl Into<String>, message: impl Into<String>) {
        self.findings.push(ValidationFinding {
            reason_code: code.to_string(),
            subject: subject.into(),
            message: message.into(),
        });
    }

    fn finish(self) -> ValidationReport {
        let exposed_count = self
            .contract
            .surfaces
            .iter()
            .filter(|row| {
                matches!(
                    row.exposure,
                    Exposure::ExposedProduction | Exposure::ExposedNegativeControl
                )
            })
            .count();
        let absent_count = self
            .contract
            .surfaces
            .iter()
            .filter(|row| row.exposure == Exposure::AbsentProduction)
            .count();
        let internal_unrouted_count = self
            .contract
            .surfaces
            .iter()
            .filter(|row| row.exposure == Exposure::InternalUnrouted)
            .count();
        ValidationReport {
            schema_version: VALIDATION_SCHEMA_VERSION.to_string(),
            contract_id: self.contract.contract_id.clone(),
            decision: if self.findings.is_empty() {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            surface_count: self.contract.surfaces.len(),
            exposed_count,
            absent_count,
            internal_unrouted_count,
            authority_count: self.contract.authorities.len(),
            probe_count: self.contract.probes.len(),
            checks_run: self.checks_run,
            findings: self.findings,
        }
    }
}

fn failed_report(code: &str, subject: String, message: String) -> ValidationReport {
    ValidationReport {
        schema_version: VALIDATION_SCHEMA_VERSION.to_string(),
        contract_id: CONTRACT_ID.to_string(),
        decision: "fail".to_string(),
        surface_count: 0,
        exposed_count: 0,
        absent_count: 0,
        internal_unrouted_count: 0,
        authority_count: 0,
        probe_count: 0,
        checks_run: 1,
        findings: vec![ValidationFinding {
            reason_code: code.to_string(),
            subject,
            message,
        }],
    }
}

fn push_finding(
    report: &mut ValidationReport,
    code: &str,
    subject: impl Into<String>,
    message: impl Into<String>,
) {
    report.findings.push(ValidationFinding {
        reason_code: code.to_string(),
        subject: subject.into(),
        message: message.into(),
    });
}

fn materialize_authority(
    repo_root: &Path,
    franken_node_root: &Path,
    spec: &AuthoritySpec,
) -> Result<AuthoritySlice, String> {
    let root = repository_root(repo_root, franken_node_root, spec.repository);
    let path = root.join(spec.path);
    let bytes =
        fs::read(&path).map_err(|error| format!("{ERROR_IO}: read {}: {error}", path.display()))?;
    let slice = extract_authority_slice(&bytes, spec.start_anchor, spec.end_anchor)?;
    let text = String::from_utf8_lossy(slice);
    for marker in spec.required_markers {
        if !text.contains(marker) {
            return Err(format!(
                "{ERROR_AUTHORITY_MARKER}: {} missing `{marker}`",
                spec.authority_id
            ));
        }
    }
    for marker in spec.forbidden_markers {
        if text.contains(marker) {
            return Err(format!(
                "{ERROR_AUTHORITY_MARKER}: {} contains forbidden `{marker}`",
                spec.authority_id
            ));
        }
    }
    Ok(AuthoritySlice {
        authority_id: spec.authority_id.to_string(),
        repository: spec.repository,
        path: spec.path.to_string(),
        start_anchor: spec.start_anchor.to_string(),
        end_anchor: spec.end_anchor.to_string(),
        sha256: sha256_hex(slice),
        required_markers: strings(spec.required_markers.to_vec()),
        forbidden_markers: strings(spec.forbidden_markers.to_vec()),
        interpretation: spec.interpretation.to_string(),
    })
}

fn validate_authority(
    repo_root: &Path,
    franken_node_root: &Path,
    authority: &AuthoritySlice,
    report: &mut ValidationReport,
) -> usize {
    let mut checks = 1usize;
    if !is_safe_relative_path(Path::new(&authority.path)) {
        push_finding(
            report,
            ERROR_UNSAFE_PATH,
            &authority.authority_id,
            "authority path is unsafe",
        );
        return checks;
    }
    let root = repository_root(repo_root, franken_node_root, authority.repository);
    let path = root.join(&authority.path);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            push_finding(
                report,
                ERROR_AUTHORITY,
                &authority.authority_id,
                error.to_string(),
            );
            return checks;
        }
    };
    let slice =
        match extract_authority_slice(&bytes, &authority.start_anchor, &authority.end_anchor) {
            Ok(slice) => slice,
            Err(error) => {
                push_finding(report, ERROR_AUTHORITY, &authority.authority_id, error);
                return checks;
            }
        };
    checks += 1;
    if sha256_hex(slice) != authority.sha256 {
        push_finding(
            report,
            ERROR_AUTHORITY_HASH,
            &authority.authority_id,
            "bounded authority bytes drifted",
        );
    }
    let text = String::from_utf8_lossy(slice);
    for marker in &authority.required_markers {
        checks += 1;
        if !text.contains(marker) {
            push_finding(
                report,
                ERROR_AUTHORITY_MARKER,
                &authority.authority_id,
                format!("missing required marker `{marker}`"),
            );
        }
    }
    for marker in &authority.forbidden_markers {
        checks += 1;
        if text.contains(marker) {
            push_finding(
                report,
                ERROR_AUTHORITY_MARKER,
                &authority.authority_id,
                format!("contains forbidden marker `{marker}`"),
            );
        }
    }
    checks
}

fn extract_authority_slice<'a>(
    bytes: &'a [u8],
    start_anchor: &str,
    end_anchor: &str,
) -> Result<&'a [u8], String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| format!("{ERROR_AUTHORITY}: authority is not UTF-8: {error}"))?;
    let starts: Vec<usize> = text
        .match_indices(start_anchor)
        .map(|(index, _)| index)
        .collect();
    if starts.len() != 1 {
        return Err(format!(
            "{ERROR_AUTHORITY}: start anchor match count {}, expected 1",
            starts.len()
        ));
    }
    let start = starts[0];
    let after_start = start + start_anchor.len();
    let tail = &text[after_start..];
    let ends: Vec<usize> = tail
        .match_indices(end_anchor)
        .map(|(index, _)| index)
        .collect();
    if ends.len() != 1 {
        return Err(format!(
            "{ERROR_AUTHORITY}: end anchor after start match count {}, expected 1",
            ends.len()
        ));
    }
    let end = after_start + ends[0] + end_anchor.len();
    Ok(&bytes[start..end])
}

fn execute_discovery_rule(
    repo_root: &Path,
    franken_node_root: &Path,
    rule: &DiscoveryRule,
) -> Result<usize, String> {
    let root = repository_root(repo_root, franken_node_root, rule.repository);
    let mut files = Vec::new();
    for relative in &rule.roots {
        let relative_path = Path::new(relative);
        if !is_safe_relative_path(relative_path) {
            return Err(format!(
                "{ERROR_UNSAFE_PATH}: discovery root `{relative}` is unsafe"
            ));
        }
        collect_discovery_files(
            &root.join(relative_path),
            &rule.file_extensions,
            &rule.excluded_path_fragments,
            &mut files,
        )?;
    }
    files.sort();
    files.dedup();
    if files.len() > MAX_DISCOVERY_FILES {
        return Err(format!(
            "{ERROR_CARDINALITY}: discovery files {} exceed {MAX_DISCOVERY_FILES}",
            files.len()
        ));
    }
    let mut bytes_read = 0u64;
    let mut matches = 0usize;
    for path in files {
        let bytes =
            fs::read(&path).map_err(|error| format!("{ERROR_IO}: {}: {error}", path.display()))?;
        bytes_read = bytes_read.saturating_add(bytes.len() as u64);
        if bytes_read > MAX_DISCOVERY_BYTES {
            return Err(format!(
                "{ERROR_CARDINALITY}: discovery bytes exceed {MAX_DISCOVERY_BYTES}"
            ));
        }
        let text = String::from_utf8_lossy(&bytes);
        for needle in &rule.needles {
            matches = matches.saturating_add(text.matches(needle).count());
        }
    }
    Ok(matches)
}

fn collect_discovery_files(
    root: &Path,
    extensions: &[String],
    excluded_fragments: &[String],
    out: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("{ERROR_IO}: {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "{ERROR_UNSAFE_PATH}: discovery path is symlink: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            let mut children = Vec::new();
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("{ERROR_IO}: {}: {error}", path.display()))?
            {
                let entry = entry.map_err(|error| format!("{ERROR_IO}: {error}"))?;
                children.push(entry.path());
            }
            children.sort();
            pending.extend(children.into_iter().rev());
        } else if metadata.is_file() {
            let rendered = path.to_string_lossy();
            if excluded_fragments
                .iter()
                .any(|fragment| rendered.contains(fragment))
            {
                continue;
            }
            let extension = path.extension().and_then(|value| value.to_str());
            if extension.is_some_and(|value| extensions.iter().any(|item| item == value)) {
                out.push(path);
            }
        }
        if pending.len().saturating_add(out.len()) > MAX_DISCOVERY_FILES {
            return Err(format!(
                "{ERROR_CARDINALITY}: discovery traversal exceeds {MAX_DISCOVERY_FILES}"
            ));
        }
    }
    Ok(())
}

fn validate_document(
    repo_root: &Path,
    doc: &DocumentationCrosswalk,
    report: &mut ValidationReport,
) -> usize {
    let mut checks = 1usize;
    if !is_safe_relative_path(Path::new(&doc.path)) {
        push_finding(
            report,
            ERROR_UNSAFE_PATH,
            &doc.document_id,
            "documentation path is unsafe",
        );
        return checks;
    }
    let path = repo_root.join(&doc.path);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            push_finding(
                report,
                ERROR_DOC_CROSSWALK,
                &doc.document_id,
                error.to_string(),
            );
            return checks;
        }
    };
    for required in &doc.required_text {
        checks += 1;
        if !text.contains(required) {
            push_finding(
                report,
                ERROR_DOC_CROSSWALK,
                &doc.document_id,
                format!("missing required text `{required}`"),
            );
        }
    }
    for forbidden in &doc.forbidden_text {
        checks += 1;
        if text.contains(forbidden) {
            push_finding(
                report,
                ERROR_DOC_CROSSWALK,
                &doc.document_id,
                format!("contains forbidden overclaim `{forbidden}`"),
            );
        }
    }
    checks
}

fn execute_probe_process(
    executable: &Path,
    frankenctl: &Path,
    source_path: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
    probe: &ProbeSpec,
    runner: ProbeRunner,
) -> Result<(Vec<String>, Output), String> {
    if !executable.is_file() {
        return Err(format!(
            "{ERROR_PROCESS}: executable missing: {}",
            executable.display()
        ));
    }
    let mut command = Command::new(executable);
    let argv = match runner {
        ProbeRunner::Frankenctl => vec![
            executable.display().to_string(),
            "run".to_string(),
            "--input".to_string(),
            source_path.display().to_string(),
            "--extension-id".to_string(),
            format!("intl-contract-{}", safe_file_component(&probe.probe_id)),
        ],
        ProbeRunner::FrankenNode => vec![
            executable.display().to_string(),
            "run".to_string(),
            source_path.display().to_string(),
            "--policy".to_string(),
            "balanced".to_string(),
            "--runtime".to_string(),
            "franken-engine".to_string(),
            "--engine-bin".to_string(),
            frankenctl.display().to_string(),
            "--console-only".to_string(),
            "--trace-id".to_string(),
            format!("intl-contract-{}", safe_file_component(&probe.probe_id)),
        ],
    };
    command.args(argv.iter().skip(1));
    for (key, value) in &probe.environment {
        command.env(key, value);
    }
    let stdout_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(stdout_path)
        .map_err(|error| format!("{ERROR_IO}: create {}: {error}", stdout_path.display()))?;
    let stderr_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(stderr_path)
        .map_err(|error| format!("{ERROR_IO}: create {}: {error}", stderr_path.display()))?;
    command.stdout(Stdio::from(stdout_file));
    command.stderr(Stdio::from(stderr_file));
    let mut child = command
        .spawn()
        .map_err(|error| format!("{ERROR_PROCESS}: spawn {}: {error}", executable.display()))?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("{ERROR_PROCESS}: wait {}: {error}", executable.display()))?
        {
            break status;
        }
        let stdout_bytes = fs::metadata(stdout_path).map_or(0, |metadata| metadata.len());
        let stderr_bytes = fs::metadata(stderr_path).map_or(0, |metadata| metadata.len());
        if stdout_bytes > MAX_PROCESS_OUTPUT_BYTES as u64
            || stderr_bytes > MAX_PROCESS_OUTPUT_BYTES as u64
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{ERROR_PROCESS}: {} output exceeded {} bytes",
                probe.probe_id, MAX_PROCESS_OUTPUT_BYTES
            ));
        }
        if started.elapsed() >= PROCESS_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{ERROR_PROCESS}: {} {:?} exceeded {} second timeout",
                probe.probe_id,
                runner,
                PROCESS_TIMEOUT.as_secs()
            ));
        }
        thread::sleep(PROCESS_POLL_INTERVAL);
    };
    let stdout = fs::read(stdout_path)
        .map_err(|error| format!("{ERROR_IO}: read {}: {error}", stdout_path.display()))?;
    let stderr = fs::read(stderr_path)
        .map_err(|error| format!("{ERROR_IO}: read {}: {error}", stderr_path.display()))?;
    let output = Output {
        status,
        stdout,
        stderr,
    };
    Ok((argv, output))
}

fn extract_console(runner: ProbeRunner, stdout: &[u8]) -> Result<Vec<String>, String> {
    match runner {
        ProbeRunner::Frankenctl => {
            if stdout.is_empty() {
                return Ok(Vec::new());
            }
            let value: serde_json::Value = serde_json::from_slice(stdout)
                .map_err(|error| format!("{ERROR_PROBE_RESULT}: frankenctl JSON: {error}"))?;
            let entries = value
                .get("console_output")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    format!("{ERROR_PROBE_RESULT}: frankenctl output lacks console_output")
                })?;
            entries
                .iter()
                .map(|entry| {
                    entry
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| format!("{ERROR_PROBE_RESULT}: console entry lacks message"))
                })
                .collect()
        }
        ProbeRunner::FrankenNode => Ok(String::from_utf8_lossy(stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect()),
    }
}

fn base_event(
    context: &EventContext,
    phase: &str,
    sequence: u64,
    terminal: bool,
    decision: &str,
    reason_code: &str,
    reason: &str,
) -> ContractEvent {
    ContractEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        run_id: context.run_id.clone(),
        trace_id: context.trace_id.clone(),
        test_id: context.test_id.clone(),
        scenario_id: context.scenario_id.clone(),
        seed: context.seed,
        attempt: context.attempt,
        platform: context.platform.clone(),
        target: context.target.clone(),
        profile: "contract-freeze".to_string(),
        phase: phase.to_string(),
        sequence,
        terminal,
        decision: decision.to_string(),
        reason_code: reason_code.to_string(),
        reason: redact_and_bound(reason, MAX_EVENT_REASON_BYTES)
            .unwrap_or_else(|_| "redaction_failed".to_string()),
        surface_id: None,
        owner: None,
        locale: None,
        timezone: None,
        provider: None,
        data_version: None,
        descriptor: None,
        input: None,
        result: None,
        error: None,
        fallback: None,
        duration_us: 0,
        resource_delta_bytes: 0,
        artifact_sha256: None,
    }
}

fn redact_and_bound(value: &str, max_bytes: usize) -> Result<String, String> {
    if value.contains('\0') {
        return Err(format!("{ERROR_REDACTION}: NUL is forbidden"));
    }
    let lower = value.to_ascii_lowercase();
    let sensitive = ["password=", "secret=", "token=", "authorization:"];
    let mut redacted = if sensitive.iter().any(|needle| lower.contains(needle)) {
        "[REDACTED]".to_string()
    } else {
        value.replace(['\r', '\n'], " ")
    };
    if redacted.len() > max_bytes {
        let mut boundary = max_bytes.saturating_sub(15).min(redacted.len());
        while boundary > 0 && !redacted.is_char_boundary(boundary) {
            boundary -= 1;
        }
        redacted.truncate(boundary);
        redacted.push_str("...[truncated]");
    }
    Ok(redacted)
}

fn render_probe_commands(report: &ProbeReport) -> String {
    let mut out = String::new();
    for observation in &report.observations {
        out.push_str(
            &observation
                .argv
                .iter()
                .map(|arg| shell_quote(arg))
                .collect::<Vec<_>>()
                .join(" "),
        );
        out.push('\n');
    }
    out
}

fn probe_environment_manifest(contract: &IntlSurfaceContract) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "franken-engine.intl-surface-contract.environment.v1",
        "declared_environment_keys": ["LANG", "LC_ALL", "TZ"],
        "source_cutoff": contract.source_cutoff,
        "provider_policy": contract.provider_policy,
        "wall_clock_is_semantically_ignored": true,
        "network_required": false
    })
}

fn render_legal(contract: &IntlSurfaceContract) -> String {
    format!(
        "# Legal and data provenance\n\n- Repository license: {}\n- External runtime data: {}\n- Bundled locale data: {}\n- Review rule: {}\n",
        contract.legal.repository_license,
        contract.legal.external_runtime_data.join("; "),
        contract.legal.bundled_locale_data,
        contract.legal.review_rule,
    )
}

fn render_probe_repro_lock(config: &ProbeRunConfig<'_>) -> Result<String, String> {
    Ok(format!(
        "schema_version=franken-engine.intl-surface-contract.repro-lock.v1\ncontract_id={}\ncontract_path={}\ncontract_sha256={}\nfrankenctl={}\nfrankenctl_sha256={}\nfranken_node={}\nfranken_node_sha256={}\nengine_base_commit={}\nfranken_node_base_commit={}\nseed={}\nattempt={}\n",
        config.contract.contract_id,
        config.contract_path.display(),
        sha256_file(config.contract_path)?,
        config.frankenctl.display(),
        sha256_file(config.frankenctl)?,
        config.franken_node.display(),
        sha256_file(config.franken_node)?,
        config.contract.source_cutoff.engine_base_commit,
        config.contract.source_cutoff.franken_node_base_commit,
        config.context.seed,
        config.context.attempt,
    ))
}

fn collect_files(base: &Path, current: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(current)
        .map_err(|error| format!("{ERROR_IO}: {}: {error}", current.display()))?
    {
        entries.push(entry.map_err(|error| format!("{ERROR_IO}: {error}"))?);
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("{ERROR_IO}: {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "{ERROR_UNSAFE_PATH}: bundle contains symlink: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_files(base, &path, out)?;
        } else if metadata.is_file() {
            out.push(
                path.strip_prefix(base)
                    .map_err(|error| format!("{ERROR_BUNDLE}: {error}"))?
                    .to_path_buf(),
            );
        }
        if out.len() > MAX_DISCOVERY_FILES {
            return Err(format!(
                "{ERROR_CARDINALITY}: bundle file count exceeds {MAX_DISCOVERY_FILES}"
            ));
        }
    }
    Ok(())
}

fn repository_root<'a>(
    repo_root: &'a Path,
    franken_node_root: &'a Path,
    repository: RepositoryId,
) -> &'a Path {
    match repository {
        RepositoryId::FrankenEngine => repo_root,
        RepositoryId::FrankenNode => franken_node_root,
    }
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path)
        .map_err(|error| format!("{ERROR_IO}: open {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("{ERROR_IO}: read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn safe_file_component(value: &str) -> String {
    let rendered: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect();
    rendered
}

fn shell_quote(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/._-:=".contains(&byte))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

fn surface_mut<'a>(contract: &'a mut IntlSurfaceContract, id: &str) -> &'a mut SurfaceRow {
    contract
        .surfaces
        .iter_mut()
        .find(|row| row.surface_id == id)
        .expect("canonical mutation surface must exist")
}

fn escape_markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn saturating_micros(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn roots() -> (PathBuf, PathBuf) {
        let engine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let node = engine.join("../franken_node");
        (engine, node)
    }

    fn contract() -> IntlSurfaceContract {
        let (engine, node) = roots();
        generate_contract(&engine, &node).expect("canonical contract generates")
    }

    fn assert_code(report: &ValidationReport, code: &str) {
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.reason_code == code),
            "missing {code}; findings={:?}",
            report.findings
        );
    }

    #[test]
    fn canonical_contract_validates() {
        let report = validate_contract(&contract());
        assert!(report.passed(), "{:?}", report.findings);
        assert_eq!(report.surface_count, REQUIRED_SURFACE_IDS.len());
        assert_eq!(report.exposed_count, 2);
        assert_eq!(report.absent_count, 2);
        assert_eq!(report.internal_unrouted_count, 5);
    }

    #[test]
    fn generation_is_deterministic() {
        let first = contract();
        let second = contract();
        assert_eq!(first, second);
        assert_eq!(
            canonical_json(&first).unwrap(),
            canonical_json(&second).unwrap()
        );
        assert_eq!(render_markdown(&first), render_markdown(&second));
    }

    #[test]
    fn required_surface_ids_are_strictly_sorted() {
        assert!(
            REQUIRED_SURFACE_IDS
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }

    #[test]
    fn missing_surface_fails() {
        let mut candidate = contract();
        candidate.surfaces.pop();
        assert_code(&validate_contract(&candidate), ERROR_REQUIRED_SURFACE);
    }

    #[test]
    fn duplicate_surface_fails() {
        let mut candidate = contract();
        candidate.surfaces.push(candidate.surfaces[0].clone());
        assert_code(&validate_contract(&candidate), ERROR_ORDER_OR_DUPLICATE);
    }

    #[test]
    fn reordered_surface_fails() {
        let mut candidate = contract();
        candidate.surfaces.swap(0, 1);
        assert_code(&validate_contract(&candidate), ERROR_ORDER_OR_DUPLICATE);
    }

    #[test]
    fn generic_owner_fails() {
        let mut candidate = contract();
        candidate.surfaces[0].owner = "tests".to_string();
        assert_code(&validate_contract(&candidate), ERROR_OWNER);
    }

    #[test]
    fn false_intl_exposure_fails() {
        let mut candidate = contract();
        surface_mut(&mut candidate, "intl.global").exposure = Exposure::ExposedProduction;
        assert_code(&validate_contract(&candidate), ERROR_EXPOSURE);
    }

    #[test]
    fn internal_route_cannot_become_production_route() {
        let mut candidate = contract();
        surface_mut(&mut candidate, "date.prototype.to_locale_string")
            .production_routes
            .push("internal hostcall".to_string());
        assert_code(&validate_contract(&candidate), ERROR_EXPOSURE);
    }

    #[test]
    fn unobservable_descriptor_cannot_fabricate_flags() {
        let mut candidate = contract();
        surface_mut(&mut candidate, "string.prototype.locale_compare")
            .descriptor
            .writable = Some(true);
        assert_code(&validate_contract(&candidate), ERROR_DESCRIPTOR);
    }

    #[test]
    fn locale_compare_must_remain_honest_about_ignored_options() {
        let mut candidate = contract();
        surface_mut(&mut candidate, "string.prototype.locale_compare").locale_semantics =
            "full locale-aware collation".to_string();
        assert_code(&validate_contract(&candidate), ERROR_EXPOSURE);
    }

    #[test]
    fn error_and_fallback_semantics_are_exactly_frozen() {
        let mut error_drift = contract();
        surface_mut(&mut error_drift, "string.prototype.locale_compare").error_semantics =
            "silently succeeds".to_string();
        assert_code(&validate_contract(&error_drift), ERROR_SEMANTIC_DRIFT);

        let mut fallback_drift = contract();
        surface_mut(&mut fallback_drift, "date.prototype.to_locale_string").fallback_semantics =
            "ambient host locale".to_string();
        assert_code(&validate_contract(&fallback_drift), ERROR_SEMANTIC_DRIFT);
    }

    #[test]
    fn authority_metadata_cannot_redirect_a_valid_hash() {
        let mut candidate = contract();
        candidate.authorities[0].path = "crates/franken-engine/src/stdlib.rs".to_string();
        assert_code(&validate_contract(&candidate), ERROR_AUTHORITY);
    }

    #[test]
    fn ecma262_contamination_fails() {
        let mut candidate = contract();
        candidate.scoring_boundary.ecma262_rule = "add preservation passes".to_string();
        assert_code(&validate_contract(&candidate), ERROR_SCOREBOARD);
    }

    #[test]
    fn zero_denominator_green_fails() {
        let mut candidate = contract();
        candidate.scoring_boundary.ecma402_rule = "100%".to_string();
        assert_code(&validate_contract(&candidate), ERROR_SCOREBOARD);
    }

    #[test]
    fn missing_probe_reference_fails() {
        let mut candidate = contract();
        surface_mut(&mut candidate, "intl.global").probe_ids.clear();
        assert_code(&validate_contract(&candidate), ERROR_PROBE_COVERAGE);
    }

    #[test]
    fn unknown_probe_reference_fails() {
        let mut candidate = contract();
        surface_mut(&mut candidate, "intl.global")
            .probe_ids
            .push("unknown".to_string());
        assert_code(&validate_contract(&candidate), ERROR_PROBE_COVERAGE);
    }

    #[test]
    fn every_success_probe_reaches_both_products() {
        let candidate = contract();
        for probe in &candidate.probes {
            if probe.probe_id == "probe.locale-compare-metadata-unobservable" {
                continue;
            }
            let runners: BTreeSet<_> = probe
                .expectations
                .iter()
                .map(|expectation| expectation.runner)
                .collect();
            assert!(runners.contains(&ProbeRunner::Frankenctl));
            assert!(runners.contains(&ProbeRunner::FrankenNode));
        }
    }

    #[test]
    fn hostile_environment_probe_is_distinct() {
        let candidate = contract();
        let basic = candidate
            .probes
            .iter()
            .find(|probe| probe.probe_id == "probe.locale-compare-basic")
            .unwrap();
        let hostile = candidate
            .probes
            .iter()
            .find(|probe| probe.probe_id == "probe.locale-compare-env-hostile")
            .unwrap();
        assert_eq!(basic.source, hostile.source);
        assert_ne!(basic.environment, hostile.environment);
        assert_eq!(basic.expectations, hostile.expectations);
    }

    #[test]
    fn authority_paths_reject_traversal() {
        let mut candidate = contract();
        candidate.authorities[0].path = "../escape".to_string();
        assert_code(&validate_contract(&candidate), ERROR_UNSAFE_PATH);
    }

    #[test]
    fn authority_hash_shape_is_enforced() {
        let mut candidate = contract();
        candidate.authorities[0].sha256 = "0".repeat(63);
        assert_code(&validate_contract(&candidate), ERROR_AUTHORITY_HASH);
    }

    #[test]
    fn authority_anchor_must_be_unique() {
        let bytes = b"start middle end start";
        let error = extract_authority_slice(bytes, "start", "end").unwrap_err();
        assert!(error.contains("start anchor match count"));
    }

    #[test]
    fn authority_end_anchor_must_follow_start_once() {
        let bytes = b"start end end";
        let error = extract_authority_slice(bytes, "start", "end").unwrap_err();
        assert!(error.contains("end anchor after start match count"));
    }

    #[test]
    fn authority_slice_includes_both_anchors() {
        let bytes = b"prefix START body END suffix";
        assert_eq!(
            extract_authority_slice(bytes, "START", "END").unwrap(),
            b"START body END"
        );
    }

    #[test]
    fn unknown_json_field_fails() {
        let candidate = contract();
        let mut value = serde_json::to_value(candidate).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("surprise".to_string(), serde_json::json!(true));
        let error = parse_contract(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert!(error.contains("unknown field"));
    }

    #[test]
    fn canonical_json_has_one_trailing_newline() {
        let bytes = canonical_json(&contract()).unwrap();
        assert!(bytes.ends_with(b"}\n"));
        assert!(!bytes.ends_with(b"}\n\n"));
    }

    #[test]
    fn redaction_masks_sensitive_fields() {
        assert_eq!(
            redact_and_bound("Authorization: bearer abc", 100).unwrap(),
            "[REDACTED]"
        );
        assert_eq!(redact_and_bound("token=abc", 100).unwrap(), "[REDACTED]");
    }

    #[test]
    fn redaction_bounds_utf8_without_splitting() {
        let value = "é".repeat(1_000);
        let bounded = redact_and_bound(&value, 100).unwrap();
        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(bounded.len() <= 100);
        assert!(bounded.ends_with("...[truncated]"));
    }

    #[test]
    fn validation_events_have_one_terminal() {
        let report = validate_contract(&contract());
        let events = validation_events(
            &report,
            &EventContext {
                run_id: "run".to_string(),
                trace_id: "trace".to_string(),
                test_id: "test".to_string(),
                scenario_id: "scenario".to_string(),
                seed: 7,
                attempt: 1,
                platform: "linux".to_string(),
                target: "x86_64".to_string(),
            },
        );
        assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
        assert!(
            events
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence)
        );
    }

    #[test]
    fn mutation_suite_kills_every_seed() {
        let report = run_mutation_suite(&contract());
        assert_eq!(report.decision, "pass", "{:?}", report.results);
        assert!(report.results.len() >= 16);
        assert!(
            report
                .results
                .iter()
                .all(|result| result.decision == "killed")
        );
    }

    #[test]
    fn create_new_refuses_overwrite() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("out");
        write_create_new(&path, b"first").unwrap();
        let error = write_create_new(&path, b"second").unwrap_err();
        assert!(error.contains(ERROR_OUTPUT_EXISTS));
        assert_eq!(fs::read(path).unwrap(), b"first");
    }

    #[test]
    fn bundle_manifest_is_written_last_and_excludes_itself() {
        let temp = tempdir().unwrap();
        write_create_new(&temp.path().join("a.txt"), b"a").unwrap();
        let candidate = contract();
        let manifest = seal_directory(temp.path(), &candidate, "rerun", "pass").unwrap();
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].path, "a.txt");
        assert!(temp.path().join("run_manifest.json").is_file());
        assert!(seal_directory(temp.path(), &candidate, "rerun", "pass").is_err());
    }

    #[test]
    fn markdown_never_claims_ecma402_percentage() {
        let markdown = render_markdown(&contract());
        assert!(markdown.contains("no `Intl` global"));
        assert!(markdown.contains("not_measured_profile_unselected"));
        assert!(!markdown.contains("100% ECMA-402"));
    }

    #[test]
    fn shell_quote_preserves_safe_arguments_and_quotes_spaces() {
        assert_eq!(shell_quote("/tmp/a-b"), "/tmp/a-b");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
    }

    #[test]
    fn safe_relative_paths_are_narrow() {
        assert!(is_safe_relative_path(Path::new("docs/file.json")));
        assert!(!is_safe_relative_path(Path::new("../file")));
        assert!(!is_safe_relative_path(Path::new("/absolute")));
        assert!(!is_safe_relative_path(Path::new("")));
    }
}
