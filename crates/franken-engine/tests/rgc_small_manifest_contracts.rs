#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

// --- Evidence Ledger Stitching ---
const STITCHING_JSON: &str = include_str!("../../../docs/rgc_evidence_ledger_stitching_v1.json");

// --- Theorem Mining Law Promotion ---
const LAW_MINING_JSON: &str =
    include_str!("../../../docs/rgc_theorem_mining_law_promotion_v1.json");

// --- Seqlock Reader Writer Contract ---
const SEQLOCK_JSON: &str = include_str!("../../../docs/rgc_seqlock_reader_writer_contract_v1.json");

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ===== Evidence Ledger Stitching Tests =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EvidenceLedgerStitching {
    schema_version: String,
    bead_id: String,
    required_artifacts: Vec<String>,
    required_query_fields: Vec<String>,
    artifact_kinds: Vec<String>,
    edge_kinds: Vec<String>,
}

fn parse_stitching() -> EvidenceLedgerStitching {
    serde_json::from_str(STITCHING_JSON).expect("evidence ledger stitching must parse")
}

#[test]
fn stitching_parses_with_expected_schema() {
    let s = parse_stitching();
    assert_eq!(
        s.schema_version,
        "franken-engine.rgc-evidence-ledger-stitching-docs.v1"
    );
}

#[test]
fn stitching_bead_id_is_valid() {
    let s = parse_stitching();
    assert!(s.bead_id.starts_with("bd-"));
}

#[test]
fn stitching_required_artifacts_include_standard_set() {
    let s = parse_stitching();
    let artifacts: BTreeSet<&str> = s.required_artifacts.iter().map(String::as_str).collect();
    for standard in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "env.json",
    ] {
        assert!(
            artifacts.contains(standard),
            "missing standard artifact: {standard}"
        );
    }
}

#[test]
fn stitching_required_artifacts_are_unique() {
    let s = parse_stitching();
    let mut seen = BTreeSet::new();
    for a in &s.required_artifacts {
        assert!(seen.insert(a.clone()), "duplicate artifact: {a}");
    }
}

#[test]
fn stitching_query_fields_include_traceability() {
    let s = parse_stitching();
    let fields: BTreeSet<&str> = s.required_query_fields.iter().map(String::as_str).collect();
    for required in ["trace_id", "decision_id", "policy_id", "evidence_entry_id"] {
        assert!(fields.contains(required), "missing query field: {required}");
    }
}

#[test]
fn stitching_query_fields_are_unique() {
    let s = parse_stitching();
    let mut seen = BTreeSet::new();
    for f in &s.required_query_fields {
        assert!(seen.insert(f.clone()), "duplicate query field: {f}");
    }
}

#[test]
fn stitching_artifact_kinds_are_nonempty() {
    let s = parse_stitching();
    assert!(
        !s.artifact_kinds.is_empty(),
        "artifact_kinds must not be empty"
    );
    for kind in &s.artifact_kinds {
        assert!(!kind.trim().is_empty(), "artifact kind must not be empty");
    }
}

#[test]
fn stitching_edge_kinds_are_nonempty_and_unique() {
    let s = parse_stitching();
    assert!(!s.edge_kinds.is_empty(), "edge_kinds must not be empty");
    let mut seen = BTreeSet::new();
    for kind in &s.edge_kinds {
        assert!(!kind.trim().is_empty(), "edge kind must not be empty");
        assert!(seen.insert(kind.clone()), "duplicate edge kind: {kind}");
    }
}

#[test]
fn stitching_top_level_keys_match_schema() {
    let raw: Value = serde_json::from_str(STITCHING_JSON).unwrap();
    let keys: BTreeSet<&str> = raw
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "schema_version",
            "bead_id",
            "required_artifacts",
            "required_query_fields",
            "artifact_kinds",
            "edge_kinds"
        ])
    );
}

// ===== Theorem Mining Law Promotion Tests =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct TheoremMiningContract {
    schema_version: String,
    bead_id: String,
    component: String,
    required_artifacts: Vec<String>,
    runner_script: String,
    replay_script: String,
    binary: String,
    default_artifact_root: String,
}

fn parse_law_mining() -> TheoremMiningContract {
    serde_json::from_str(LAW_MINING_JSON).expect("theorem mining contract must parse")
}

#[test]
fn law_mining_parses_with_expected_schema() {
    let m = parse_law_mining();
    assert_eq!(m.schema_version, "franken-engine.law-mining.contract.v1");
}

#[test]
fn law_mining_bead_id_is_valid() {
    let m = parse_law_mining();
    assert!(m.bead_id.starts_with("bd-"));
}

#[test]
fn law_mining_component_is_set() {
    let m = parse_law_mining();
    assert_eq!(m.component, "law_mining");
}

#[test]
fn law_mining_required_artifacts_include_standard_set() {
    let m = parse_law_mining();
    let artifacts: BTreeSet<&str> = m.required_artifacts.iter().map(String::as_str).collect();
    for standard in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "env.json",
    ] {
        assert!(
            artifacts.contains(standard),
            "missing standard artifact: {standard}"
        );
    }
}

#[test]
fn law_mining_required_artifacts_are_unique() {
    let m = parse_law_mining();
    let mut seen = BTreeSet::new();
    for a in &m.required_artifacts {
        assert!(seen.insert(a.clone()), "duplicate artifact: {a}");
    }
}

#[test]
fn law_mining_scripts_exist_in_repo() {
    let m = parse_law_mining();
    let root = repo_root();
    let runner = root.join(m.runner_script.trim_start_matches("./"));
    assert!(
        runner.exists(),
        "runner script must exist: {}",
        runner.display()
    );
    let replay = root.join(m.replay_script.trim_start_matches("./"));
    assert!(
        replay.exists(),
        "replay script must exist: {}",
        replay.display()
    );
}

#[test]
fn law_mining_binary_name_is_snake_case() {
    let m = parse_law_mining();
    assert!(
        m.binary
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
        "binary name must be snake_case: {}",
        m.binary
    );
}

#[test]
fn law_mining_artifact_root_is_repo_relative() {
    let m = parse_law_mining();
    assert!(!m.default_artifact_root.starts_with('/'));
    assert!(!m.default_artifact_root.contains(".."));
}

// ===== Seqlock Reader Writer Contract Tests =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SeqlockContract {
    schema_version: String,
    bead_id: String,
    required_artifacts: Vec<String>,
    candidate_policies: Vec<CandidatePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CandidatePolicy {
    candidate_id: String,
    max_retries: u64,
    max_writer_pressure_observations: u64,
}

fn parse_seqlock() -> SeqlockContract {
    serde_json::from_str(SEQLOCK_JSON).expect("seqlock contract must parse")
}

#[test]
fn seqlock_parses_with_expected_schema() {
    let s = parse_seqlock();
    assert_eq!(
        s.schema_version,
        "franken-engine.rgc-seqlock-reader-writer-contract-docs.v1"
    );
}

#[test]
fn seqlock_bead_id_is_valid() {
    let s = parse_seqlock();
    assert!(s.bead_id.starts_with("bd-"));
}

#[test]
fn seqlock_required_artifacts_include_standard_set() {
    let s = parse_seqlock();
    let artifacts: BTreeSet<&str> = s.required_artifacts.iter().map(String::as_str).collect();
    for standard in [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "env.json",
    ] {
        assert!(
            artifacts.contains(standard),
            "missing standard artifact: {standard}"
        );
    }
}

#[test]
fn seqlock_required_artifacts_are_unique() {
    let s = parse_seqlock();
    let mut seen = BTreeSet::new();
    for a in &s.required_artifacts {
        assert!(seen.insert(a.clone()), "duplicate artifact: {a}");
    }
}

#[test]
fn seqlock_candidate_ids_are_unique() {
    let s = parse_seqlock();
    let mut seen = BTreeSet::new();
    for policy in &s.candidate_policies {
        assert!(
            seen.insert(policy.candidate_id.clone()),
            "duplicate candidate_id: {}",
            policy.candidate_id
        );
    }
}

#[test]
fn seqlock_candidate_ids_are_kebab_case() {
    let s = parse_seqlock();
    for policy in &s.candidate_policies {
        assert!(
            policy
                .candidate_id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()),
            "candidate_id must be kebab-case: {}",
            policy.candidate_id
        );
    }
}

#[test]
fn seqlock_retry_budgets_are_bounded() {
    let s = parse_seqlock();
    for policy in &s.candidate_policies {
        assert!(
            policy.max_retries >= 1 && policy.max_retries <= 10,
            "max_retries for {} must be 1..=10, got {}",
            policy.candidate_id,
            policy.max_retries
        );
        assert!(
            policy.max_writer_pressure_observations >= 1
                && policy.max_writer_pressure_observations <= 5,
            "max_writer_pressure for {} must be 1..=5, got {}",
            policy.candidate_id,
            policy.max_writer_pressure_observations
        );
    }
}

#[test]
fn seqlock_has_at_least_three_candidates() {
    let s = parse_seqlock();
    assert!(
        s.candidate_policies.len() >= 3,
        "must have at least 3 candidate policies, got {}",
        s.candidate_policies.len()
    );
}

// ===== Cross-schema and structural enrichment =====

#[test]
fn cross_schema_all_bead_ids_are_distinct() {
    let st = parse_stitching();
    let lm = parse_law_mining();
    let sq = parse_seqlock();
    let ids: BTreeSet<&str> = [
        st.bead_id.as_str(),
        lm.bead_id.as_str(),
        sq.bead_id.as_str(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        ids.len(),
        3,
        "all three schemas must have distinct bead_ids"
    );
}

#[test]
fn cross_schema_all_schema_versions_are_distinct_and_prefixed() {
    let st = parse_stitching();
    let lm = parse_law_mining();
    let sq = parse_seqlock();
    let versions = [
        st.schema_version.as_str(),
        lm.schema_version.as_str(),
        sq.schema_version.as_str(),
    ];
    for v in &versions {
        assert!(
            v.starts_with("franken-engine."),
            "schema_version must start with franken-engine. prefix, got: {v}"
        );
    }
    let unique: BTreeSet<&str> = versions.into_iter().collect();
    assert_eq!(
        unique.len(),
        3,
        "all three schemas must have distinct schema_versions"
    );
}

#[test]
fn stitching_artifact_kinds_are_unique() {
    let s = parse_stitching();
    let mut seen = BTreeSet::new();
    for kind in &s.artifact_kinds {
        assert!(seen.insert(kind.clone()), "duplicate artifact_kind: {kind}");
    }
}

#[test]
fn law_mining_top_level_keys_match_schema() {
    let raw: Value = serde_json::from_str(LAW_MINING_JSON).unwrap();
    let keys: BTreeSet<&str> = raw
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "schema_version",
            "bead_id",
            "component",
            "required_artifacts",
            "runner_script",
            "replay_script",
            "binary",
            "default_artifact_root"
        ])
    );
}

#[test]
fn seqlock_top_level_keys_match_schema() {
    let raw: Value = serde_json::from_str(SEQLOCK_JSON).unwrap();
    let keys: BTreeSet<&str> = raw
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "schema_version",
            "bead_id",
            "required_artifacts",
            "candidate_policies"
        ])
    );
}

#[test]
fn seqlock_candidates_are_sorted_by_id() {
    let s = parse_seqlock();
    let ids: Vec<&str> = s
        .candidate_policies
        .iter()
        .map(|p| p.candidate_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(
        ids, sorted,
        "candidate_policies must be sorted by candidate_id"
    );
}
