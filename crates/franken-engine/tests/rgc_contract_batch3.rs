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

use serde::Deserialize;

// --- Continuation Cliff Atlas ---
const CLIFF_JSON: &str = include_str!("../../../docs/rgc_continuation_cliff_atlas_v1.json");

// --- S3FIFO Baseline Comparator ---
const S3FIFO_JSON: &str = include_str!("../../../docs/rgc_s3fifo_baseline_comparator_v1.json");

// ===== Continuation Cliff Atlas =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ContinuationCliffAtlas {
    schema_version: String,
    status: String,
    primary_bead: String,
    generated_by: String,
    generated_at_utc: String,
    track: Track,
    margin_certificate_contract: MarginCertificateContract,
    witness_contract: WitnessContract,
    failure_policy: CliffFailurePolicy,
    logging_contract: LoggingContract,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Track {
    id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MarginCertificateContract {
    deterministic: bool,
    required_fields: Vec<String>,
    allowed_bands: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct WitnessContract {
    required_fields: Vec<String>,
    missing_neighborhood_escape_action: String,
    unstable_escape_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CliffFailurePolicy {
    mode: String,
    block_on_missing_neighborhood: bool,
    block_on_budget_crossing: bool,
    require_warning_preservation_for_near_cliff: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LoggingContract {
    component: String,
    required_fields: Vec<String>,
}

fn parse_cliff() -> ContinuationCliffAtlas {
    serde_json::from_str(CLIFF_JSON).expect("continuation cliff atlas must parse")
}

#[test]
fn cliff_parses_with_expected_schema() {
    let c = parse_cliff();
    assert_eq!(
        c.schema_version,
        "franken-engine.continuation-cliff-atlas.contract.v1"
    );
}

#[test]
fn cliff_status_is_active() {
    let c = parse_cliff();
    assert_eq!(c.status, "active");
}

#[test]
fn cliff_bead_ids_are_valid() {
    let c = parse_cliff();
    assert!(c.primary_bead.starts_with("bd-"));
    assert!(c.generated_by.starts_with("bd-"));
}

#[test]
fn cliff_generated_at_utc_is_iso8601() {
    let c = parse_cliff();
    assert!(c.generated_at_utc.ends_with('Z'));
    assert!(c.generated_at_utc.contains('T'));
}

#[test]
fn cliff_track_has_rgc_prefix() {
    let c = parse_cliff();
    assert!(c.track.id.starts_with("RGC-"));
}

#[test]
fn cliff_margin_certificate_is_deterministic() {
    let c = parse_cliff();
    assert!(c.margin_certificate_contract.deterministic);
}

#[test]
fn cliff_margin_required_fields_include_threat_and_band() {
    let c = parse_cliff();
    let fields: BTreeSet<&str> = c
        .margin_certificate_contract
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert!(fields.contains("threat_class_id"));
    assert!(fields.contains("cliff_band"));
}

#[test]
fn cliff_allowed_bands_include_expected_set() {
    let c = parse_cliff();
    let bands: BTreeSet<&str> = c
        .margin_certificate_contract
        .allowed_bands
        .iter()
        .map(String::as_str)
        .collect();
    for expected in [
        "stable",
        "near_cliff",
        "beyond_cliff",
        "missing_neighborhood",
    ] {
        assert!(bands.contains(expected), "missing band: {expected}");
    }
}

#[test]
fn cliff_allowed_bands_are_unique() {
    let c = parse_cliff();
    let mut seen = BTreeSet::new();
    for band in &c.margin_certificate_contract.allowed_bands {
        assert!(seen.insert(band.clone()), "duplicate band: {band}");
    }
}

#[test]
fn cliff_witness_missing_escape_is_fallback_safe() {
    let c = parse_cliff();
    assert_eq!(
        c.witness_contract.missing_neighborhood_escape_action,
        "fallback_safe"
    );
}

#[test]
fn cliff_witness_unstable_escape_actions_are_unique() {
    let c = parse_cliff();
    let mut seen = BTreeSet::new();
    for action in &c.witness_contract.unstable_escape_actions {
        assert!(
            seen.insert(action.clone()),
            "duplicate escape action: {action}"
        );
    }
}

#[test]
fn cliff_failure_policy_is_fail_closed_with_all_blocks() {
    let c = parse_cliff();
    assert_eq!(c.failure_policy.mode, "fail_closed");
    assert!(c.failure_policy.block_on_missing_neighborhood);
    assert!(c.failure_policy.block_on_budget_crossing);
    assert!(c.failure_policy.require_warning_preservation_for_near_cliff);
}

#[test]
fn cliff_logging_contract_includes_traceability() {
    let c = parse_cliff();
    let fields: BTreeSet<&str> = c
        .logging_contract
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    for required in ["trace_id", "decision_id", "policy_id"] {
        assert!(fields.contains(required), "missing log field: {required}");
    }
}

#[test]
fn cliff_operator_verification_nonempty() {
    let c = parse_cliff();
    assert!(!c.operator_verification.is_empty());
}

// ===== S3FIFO Baseline Comparator =====

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct S3FifoBaselineComparator {
    schema_version: String,
    bead_id: String,
    required_artifacts: Vec<String>,
    baseline_policy_name: String,
    candidate_policy_name: String,
    workload_classes: Vec<String>,
    trace_ids: Vec<String>,
    win_metrics: Vec<String>,
    replaced_surfaces: Vec<String>,
    untouched_surfaces: Vec<String>,
}

fn parse_s3fifo() -> S3FifoBaselineComparator {
    serde_json::from_str(S3FIFO_JSON).expect("s3fifo baseline comparator must parse")
}

#[test]
fn s3fifo_parses_with_expected_schema() {
    let s = parse_s3fifo();
    assert_eq!(
        s.schema_version,
        "franken-engine.rgc-s3fifo-baseline-comparator-contract.v1"
    );
}

#[test]
fn s3fifo_bead_id_is_valid() {
    let s = parse_s3fifo();
    assert!(s.bead_id.starts_with("bd-"));
}

#[test]
fn s3fifo_required_artifacts_include_standard_set() {
    let s = parse_s3fifo();
    let artifacts: BTreeSet<&str> = s.required_artifacts.iter().map(String::as_str).collect();
    for standard in ["run_manifest.json", "events.jsonl", "commands.txt"] {
        assert!(artifacts.contains(standard), "missing: {standard}");
    }
}

#[test]
fn s3fifo_required_artifacts_are_unique() {
    let s = parse_s3fifo();
    let mut seen = BTreeSet::new();
    for a in &s.required_artifacts {
        assert!(seen.insert(a.clone()), "duplicate artifact: {a}");
    }
}

#[test]
fn s3fifo_policy_names_are_snake_case() {
    let s = parse_s3fifo();
    for name in [&s.baseline_policy_name, &s.candidate_policy_name] {
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "policy name must be snake_case: {name}"
        );
    }
}

#[test]
fn s3fifo_policy_names_differ() {
    let s = parse_s3fifo();
    assert_ne!(
        s.baseline_policy_name, s.candidate_policy_name,
        "baseline and candidate must differ"
    );
}

#[test]
fn s3fifo_workload_classes_are_unique_and_snake_case() {
    let s = parse_s3fifo();
    let mut seen = BTreeSet::new();
    for wc in &s.workload_classes {
        assert!(
            wc.chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "workload class must be snake_case: {wc}"
        );
        assert!(seen.insert(wc.clone()), "duplicate workload class: {wc}");
    }
}

#[test]
fn s3fifo_trace_ids_match_workload_classes() {
    let s = parse_s3fifo();
    assert_eq!(
        s.trace_ids.len(),
        s.workload_classes.len(),
        "trace_ids and workload_classes must have same length"
    );
    for (wc, tid) in s.workload_classes.iter().zip(s.trace_ids.iter()) {
        assert!(
            tid.contains(wc),
            "trace_id '{tid}' should reference workload class '{wc}'"
        );
    }
}

#[test]
fn s3fifo_win_metrics_are_millionths_suffixed() {
    let s = parse_s3fifo();
    for metric in &s.win_metrics {
        assert!(
            metric.ends_with("_millionths"),
            "win metric must end with _millionths: {metric}"
        );
    }
}

#[test]
fn s3fifo_win_metrics_are_unique() {
    let s = parse_s3fifo();
    let mut seen = BTreeSet::new();
    for m in &s.win_metrics {
        assert!(seen.insert(m.clone()), "duplicate win metric: {m}");
    }
}

#[test]
fn s3fifo_replaced_and_untouched_are_disjoint() {
    let s = parse_s3fifo();
    let replaced: BTreeSet<&str> = s.replaced_surfaces.iter().map(String::as_str).collect();
    let untouched: BTreeSet<&str> = s.untouched_surfaces.iter().map(String::as_str).collect();
    let overlap: Vec<&&str> = replaced.intersection(&untouched).collect();
    assert!(
        overlap.is_empty(),
        "replaced and untouched must be disjoint: {:?}",
        overlap
    );
}

#[test]
fn deterministic_double_parse_both() {
    assert_eq!(parse_cliff(), parse_cliff());
    assert_eq!(parse_s3fifo(), parse_s3fifo());
}

// ===== Cross-schema and structural enrichment =====

#[test]
fn cross_schema_bead_ids_are_distinct() {
    let c = parse_cliff();
    let s = parse_s3fifo();
    assert_ne!(
        c.primary_bead, s.bead_id,
        "cliff primary_bead and s3fifo bead_id must be distinct"
    );
}

#[test]
fn cross_schema_versions_follow_franken_engine_prefix() {
    let c = parse_cliff();
    let s = parse_s3fifo();
    assert!(
        c.schema_version.starts_with("franken-engine."),
        "cliff schema_version must start with franken-engine. prefix"
    );
    assert!(
        s.schema_version.starts_with("franken-engine."),
        "s3fifo schema_version must start with franken-engine. prefix"
    );
    assert_ne!(
        c.schema_version, s.schema_version,
        "schema versions must differ between the two documents"
    );
}

#[test]
fn cliff_operator_verification_commands_reference_cliff_or_margin() {
    let c = parse_cliff();
    for cmd in &c.operator_verification {
        let lower = cmd.to_ascii_lowercase();
        assert!(
            lower.contains("cliff") || lower.contains("margin"),
            "operator verification command should reference cliff or margin: {cmd}"
        );
    }
}

#[test]
fn cliff_witness_required_fields_are_unique() {
    let c = parse_cliff();
    let mut seen = BTreeSet::new();
    for f in &c.witness_contract.required_fields {
        assert!(
            seen.insert(f.clone()),
            "duplicate witness required_field: {f}"
        );
    }
}

#[test]
fn cliff_logging_contract_component_is_nonempty() {
    let c = parse_cliff();
    assert!(
        !c.logging_contract.component.is_empty(),
        "logging contract component must not be empty"
    );
    assert!(
        !c.logging_contract.component.contains(' '),
        "logging contract component should be a single identifier without spaces"
    );
}

#[test]
fn s3fifo_top_level_keys_match_expected_set() {
    let raw: serde_json::Value = serde_json::from_str(S3FIFO_JSON).expect("s3fifo raw parse");
    let obj = raw.as_object().expect("top-level must be an object");
    let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = [
        "schema_version",
        "bead_id",
        "required_artifacts",
        "baseline_policy_name",
        "candidate_policy_name",
        "workload_classes",
        "trace_ids",
        "win_metrics",
        "replaced_surfaces",
        "untouched_surfaces",
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(keys, expected, "s3fifo top-level keys mismatch");
}

#[test]
fn s3fifo_replaced_and_untouched_items_are_unique_and_nonempty() {
    let s = parse_s3fifo();
    let mut replaced_seen = BTreeSet::new();
    for r in &s.replaced_surfaces {
        assert!(!r.is_empty(), "replaced_surfaces item must not be empty");
        assert!(
            replaced_seen.insert(r.clone()),
            "duplicate replaced_surface: {r}"
        );
    }
    let mut untouched_seen = BTreeSet::new();
    for u in &s.untouched_surfaces {
        assert!(!u.is_empty(), "untouched_surfaces item must not be empty");
        assert!(
            untouched_seen.insert(u.clone()),
            "duplicate untouched_surface: {u}"
        );
    }
}

// ===== Continuation Cliff Atlas — additional enrichment =====

#[test]
fn cliff_clone_independence() {
    let a = parse_cliff();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn cliff_debug_is_nonempty() {
    let c = parse_cliff();
    assert!(!format!("{c:?}").is_empty());
}

#[test]
fn cliff_track_name_is_nonempty() {
    let c = parse_cliff();
    assert!(!c.track.name.trim().is_empty());
}

#[test]
fn cliff_margin_required_fields_are_unique() {
    let c = parse_cliff();
    let mut seen = BTreeSet::new();
    for f in &c.margin_certificate_contract.required_fields {
        assert!(seen.insert(f.clone()), "duplicate margin field: {f}");
    }
}

#[test]
fn cliff_witness_required_fields_include_trace_id() {
    let c = parse_cliff();
    let fields: BTreeSet<&str> = c
        .witness_contract
        .required_fields
        .iter()
        .map(String::as_str)
        .collect();
    assert!(
        fields.contains("trace_id"),
        "witness fields must include trace_id"
    );
}

#[test]
fn cliff_logging_required_fields_are_unique() {
    let c = parse_cliff();
    let mut seen = BTreeSet::new();
    for f in &c.logging_contract.required_fields {
        assert!(seen.insert(f.clone()), "duplicate logging field: {f}");
    }
}

#[test]
fn cliff_generated_at_utc_is_nonempty() {
    let c = parse_cliff();
    assert!(!c.generated_at_utc.trim().is_empty());
}

#[test]
fn cliff_operator_verification_entries_are_nonempty() {
    let c = parse_cliff();
    for cmd in &c.operator_verification {
        assert!(!cmd.trim().is_empty());
    }
}

// ===== S3FIFO — additional enrichment =====

#[test]
fn s3fifo_clone_independence() {
    let a = parse_s3fifo();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn s3fifo_debug_is_nonempty() {
    let s = parse_s3fifo();
    assert!(!format!("{s:?}").is_empty());
}

#[test]
fn s3fifo_workload_classes_are_nonempty() {
    let s = parse_s3fifo();
    assert!(!s.workload_classes.is_empty());
}

#[test]
fn s3fifo_trace_ids_are_unique() {
    let s = parse_s3fifo();
    let mut seen = BTreeSet::new();
    for tid in &s.trace_ids {
        assert!(seen.insert(tid.clone()), "duplicate trace_id: {tid}");
    }
}

#[test]
fn s3fifo_replaced_surfaces_are_nonempty_list() {
    let s = parse_s3fifo();
    assert!(!s.replaced_surfaces.is_empty());
}

#[test]
fn s3fifo_win_metrics_count_at_least_two() {
    let s = parse_s3fifo();
    assert!(
        s.win_metrics.len() >= 2,
        "should have at least 2 win metrics"
    );
}

// ===== Cross-schema additional =====

#[test]
fn cross_schema_both_schemas_end_with_v1() {
    let c = parse_cliff();
    let s = parse_s3fifo();
    assert!(
        c.schema_version.ends_with(".v1"),
        "cliff schema should end with .v1"
    );
    assert!(
        s.schema_version.ends_with(".v1"),
        "s3fifo schema should end with .v1"
    );
}
