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

use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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

// ===== Additional Evidence Ledger Stitching Tests =====

#[test]
fn stitching_required_artifacts_are_nonempty_strings() {
    let s = parse_stitching();
    for artifact in &s.required_artifacts {
        assert!(
            !artifact.trim().is_empty(),
            "artifact name must not be blank"
        );
    }
}

#[test]
fn stitching_required_query_fields_are_nonempty_strings() {
    let s = parse_stitching();
    assert!(
        !s.required_query_fields.is_empty(),
        "required_query_fields must not be empty"
    );
    for field in &s.required_query_fields {
        assert!(
            !field.trim().is_empty(),
            "query field name must not be blank"
        );
    }
}

#[test]
fn stitching_required_artifacts_include_trace_ids() {
    let s = parse_stitching();
    let artifacts: BTreeSet<&str> = s.required_artifacts.iter().map(String::as_str).collect();
    assert!(
        artifacts.contains("trace_ids.json"),
        "stitching artifacts must include trace_ids.json"
    );
}

#[test]
fn stitching_required_artifacts_include_evidence_bundle() {
    let s = parse_stitching();
    let artifacts: BTreeSet<&str> = s.required_artifacts.iter().map(String::as_str).collect();
    assert!(
        artifacts.contains("evidence_ledger_stitching_bundle.json"),
        "stitching artifacts must include evidence_ledger_stitching_bundle.json"
    );
}

#[test]
fn stitching_edge_kinds_contain_decision_produces_artifact() {
    let s = parse_stitching();
    let edge_kinds: BTreeSet<&str> = s.edge_kinds.iter().map(String::as_str).collect();
    assert!(
        edge_kinds.contains("decision_produces_artifact"),
        "edge_kinds must contain 'decision_produces_artifact'"
    );
}

#[test]
fn stitching_edge_kinds_contain_boundary_informs_decision() {
    let s = parse_stitching();
    let edge_kinds: BTreeSet<&str> = s.edge_kinds.iter().map(String::as_str).collect();
    assert!(
        edge_kinds.contains("boundary_informs_decision"),
        "edge_kinds must contain 'boundary_informs_decision'"
    );
}

#[test]
fn stitching_artifact_kinds_contain_benchmark_manifest() {
    let s = parse_stitching();
    let kinds: BTreeSet<&str> = s.artifact_kinds.iter().map(String::as_str).collect();
    assert!(
        kinds.contains("benchmark_manifest"),
        "artifact_kinds must include 'benchmark_manifest'"
    );
}

#[test]
fn stitching_query_fields_include_confidence_tier() {
    let s = parse_stitching();
    let fields: BTreeSet<&str> = s.required_query_fields.iter().map(String::as_str).collect();
    assert!(
        fields.contains("confidence_tier"),
        "required_query_fields must include 'confidence_tier'"
    );
}

#[test]
fn stitching_clone_is_independent() {
    let s = parse_stitching();
    let cloned = s.clone();
    assert_eq!(s, cloned, "clone must be equal to original");
    // Ensure they are independent types (debug roundtrip)
    let debug_orig = format!("{s:?}");
    let debug_clone = format!("{cloned:?}");
    assert_eq!(debug_orig, debug_clone);
}

// ===== Additional Law Mining Tests =====

#[test]
fn law_mining_required_artifacts_include_candidate_law_catalog() {
    let m = parse_law_mining();
    let artifacts: BTreeSet<&str> = m.required_artifacts.iter().map(String::as_str).collect();
    assert!(
        artifacts.contains("candidate_law_catalog.json"),
        "law mining artifacts must include candidate_law_catalog.json"
    );
}

#[test]
fn law_mining_required_artifacts_include_trace_ids() {
    let m = parse_law_mining();
    let artifacts: BTreeSet<&str> = m.required_artifacts.iter().map(String::as_str).collect();
    assert!(
        artifacts.contains("trace_ids.json"),
        "law mining artifacts must include trace_ids.json"
    );
}

#[test]
fn law_mining_runner_script_starts_with_dot_slash() {
    let m = parse_law_mining();
    assert!(
        m.runner_script.starts_with("./"),
        "runner_script must be repo-relative (start with ./): {}",
        m.runner_script
    );
}

#[test]
fn law_mining_replay_script_starts_with_dot_slash() {
    let m = parse_law_mining();
    assert!(
        m.replay_script.starts_with("./"),
        "replay_script must be repo-relative (start with ./): {}",
        m.replay_script
    );
}

#[test]
fn law_mining_artifact_root_contains_component_name() {
    let m = parse_law_mining();
    assert!(
        m.default_artifact_root.contains(&m.component),
        "default_artifact_root '{}' must contain component name '{}'",
        m.default_artifact_root,
        m.component
    );
}

#[test]
fn law_mining_clone_is_independent() {
    let m = parse_law_mining();
    let cloned = m.clone();
    assert_eq!(m, cloned, "clone must be equal to original");
    let debug_orig = format!("{m:?}");
    let debug_clone = format!("{cloned:?}");
    assert_eq!(debug_orig, debug_clone);
}

// ===== Additional Seqlock Tests =====

#[test]
fn seqlock_required_artifacts_include_retry_budget_policy() {
    let s = parse_seqlock();
    let artifacts: BTreeSet<&str> = s.required_artifacts.iter().map(String::as_str).collect();
    assert!(
        artifacts.contains("retry_budget_policy.json"),
        "seqlock artifacts must include retry_budget_policy.json"
    );
}

#[test]
fn seqlock_required_artifacts_include_seqlock_contract() {
    let s = parse_seqlock();
    let artifacts: BTreeSet<&str> = s.required_artifacts.iter().map(String::as_str).collect();
    assert!(
        artifacts.contains("seqlock_reader_writer_contract.json"),
        "seqlock artifacts must include seqlock_reader_writer_contract.json"
    );
}

#[test]
fn seqlock_candidate_policies_have_positive_bounds() {
    let s = parse_seqlock();
    for policy in &s.candidate_policies {
        assert!(
            policy.max_retries > 0,
            "max_retries for {} must be positive",
            policy.candidate_id
        );
        assert!(
            policy.max_writer_pressure_observations > 0,
            "max_writer_pressure_observations for {} must be positive",
            policy.candidate_id
        );
    }
}

#[test]
fn seqlock_candidate_ids_are_nonempty() {
    let s = parse_seqlock();
    for policy in &s.candidate_policies {
        assert!(
            !policy.candidate_id.trim().is_empty(),
            "candidate_id must not be blank"
        );
    }
}

#[test]
fn seqlock_clone_is_independent() {
    let s = parse_seqlock();
    let cloned = s.clone();
    assert_eq!(s, cloned, "clone must be equal to original");
    let debug_orig = format!("{s:?}");
    let debug_clone = format!("{cloned:?}");
    assert_eq!(debug_orig, debug_clone);
}

// ===== Additional Cross-Schema Tests =====

#[test]
fn cross_schema_all_have_standard_artifacts() {
    // All three schemas must include the four standard artifacts
    let st = parse_stitching();
    let lm = parse_law_mining();
    let sq = parse_seqlock();
    let standard = [
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "env.json",
    ];
    for schema_name in ["stitching", "law_mining", "seqlock"] {
        let artifacts: BTreeSet<&str> = match schema_name {
            "stitching" => st.required_artifacts.iter().map(String::as_str).collect(),
            "law_mining" => lm.required_artifacts.iter().map(String::as_str).collect(),
            _ => sq.required_artifacts.iter().map(String::as_str).collect(),
        };
        for standard_artifact in &standard {
            assert!(
                artifacts.contains(standard_artifact),
                "schema '{schema_name}' missing standard artifact: {standard_artifact}"
            );
        }
    }
}

#[test]
fn cross_schema_all_bead_ids_have_nested_format() {
    let st = parse_stitching();
    let lm = parse_law_mining();
    let sq = parse_seqlock();
    for id in [
        st.bead_id.as_str(),
        lm.bead_id.as_str(),
        sq.bead_id.as_str(),
    ] {
        // bead IDs should contain at least one dot after the bd- prefix
        assert!(
            id.contains('.'),
            "bead_id '{id}' must contain a '.' separator for hierarchical IDs"
        );
    }
}

#[test]
fn cross_schema_all_require_repro_lock() {
    let st = parse_stitching();
    let lm = parse_law_mining();
    let sq = parse_seqlock();
    for (name, artifacts) in [
        ("stitching", &st.required_artifacts),
        ("law_mining", &lm.required_artifacts),
        ("seqlock", &sq.required_artifacts),
    ] {
        let set: BTreeSet<&str> = artifacts.iter().map(String::as_str).collect();
        assert!(
            set.contains("repro.lock"),
            "schema '{name}' must require repro.lock for reproducibility"
        );
    }
}

#[test]
fn cross_schema_all_require_manifest_json() {
    let st = parse_stitching();
    let lm = parse_law_mining();
    let sq = parse_seqlock();
    for (name, artifacts) in [
        ("stitching", &st.required_artifacts),
        ("law_mining", &lm.required_artifacts),
        ("seqlock", &sq.required_artifacts),
    ] {
        let set: BTreeSet<&str> = artifacts.iter().map(String::as_str).collect();
        assert!(
            set.contains("manifest.json"),
            "schema '{name}' must require manifest.json"
        );
    }
}

#[test]
fn cross_schema_all_require_trace_ids() {
    let st = parse_stitching();
    let lm = parse_law_mining();
    let sq = parse_seqlock();
    for (name, artifacts) in [
        ("stitching", &st.required_artifacts),
        ("law_mining", &lm.required_artifacts),
        ("seqlock", &sq.required_artifacts),
    ] {
        let set: BTreeSet<&str> = artifacts.iter().map(String::as_str).collect();
        assert!(
            set.contains("trace_ids.json"),
            "schema '{name}' must require trace_ids.json for traceability"
        );
    }
}

#[test]
fn cross_schema_all_require_summary_md() {
    let st = parse_stitching();
    let lm = parse_law_mining();
    let sq = parse_seqlock();
    for (name, artifacts) in [
        ("stitching", &st.required_artifacts),
        ("law_mining", &lm.required_artifacts),
        ("seqlock", &sq.required_artifacts),
    ] {
        let set: BTreeSet<&str> = artifacts.iter().map(String::as_str).collect();
        assert!(
            set.contains("summary.md"),
            "schema '{name}' must require summary.md"
        );
    }
}

#[test]
fn seqlock_candidate_policies_serde_roundtrip() {
    let s = parse_seqlock();
    // Re-serialize to JSON and parse back; confirm policies are preserved
    let serialized =
        serde_json::to_string(&s.candidate_policies).expect("candidate_policies must serialize");
    let roundtripped: Vec<CandidatePolicy> =
        serde_json::from_str(&serialized).expect("candidate_policies must deserialize");
    assert_eq!(
        s.candidate_policies.len(),
        roundtripped.len(),
        "roundtrip must preserve all candidate policies"
    );
    for (orig, rt) in s.candidate_policies.iter().zip(roundtripped.iter()) {
        assert_eq!(orig.candidate_id, rt.candidate_id);
        assert_eq!(orig.max_retries, rt.max_retries);
        assert_eq!(
            orig.max_writer_pressure_observations,
            rt.max_writer_pressure_observations
        );
    }
}

#[test]
fn stitching_artifact_kinds_are_lowercase_snake_or_kebab() {
    let s = parse_stitching();
    for kind in &s.artifact_kinds {
        assert!(
            kind.chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c == '-'),
            "artifact_kind must be lowercase with underscores or hyphens: {kind}"
        );
    }
}

#[test]
fn stitching_edge_kinds_use_underscores() {
    let s = parse_stitching();
    for kind in &s.edge_kinds {
        assert!(
            kind.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "edge_kind must use only lowercase letters and underscores: {kind}"
        );
    }
}
