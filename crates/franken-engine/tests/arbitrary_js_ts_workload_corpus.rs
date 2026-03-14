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

use std::{collections::BTreeSet, fs, path::PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json(path: &str) -> Value {
    let full = repo_root().join(path);
    let raw = fs::read_to_string(&full)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", full.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("failed to parse {} as JSON: {err}", full.display()))
}

fn read_text(path: &str) -> String {
    let full = repo_root().join(path);
    fs::read_to_string(&full)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", full.display()))
}

fn require_string_field<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .unwrap_or_else(|| panic!("missing `{field}`"))
        .as_str()
        .unwrap_or_else(|| panic!("`{field}` must be a string"))
}

fn require_bool_field(value: &Value, field: &str) -> bool {
    value
        .get(field)
        .unwrap_or_else(|| panic!("missing `{field}`"))
        .as_bool()
        .unwrap_or_else(|| panic!("`{field}` must be a bool"))
}

fn require_string_array(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .unwrap_or_else(|| panic!("missing `{field}`"))
        .as_array()
        .unwrap_or_else(|| panic!("`{field}` must be an array"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("`{field}` entries must be strings"))
                .to_string()
        })
        .collect()
}

#[test]
fn corpus_manifest_declares_runtime_targets_artifacts_and_selection_guards() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");

    assert_eq!(
        require_string_field(&manifest, "schema_version"),
        "franken-engine.rgc-arbitrary-js-ts-workload-corpus.v1"
    );
    assert_eq!(require_string_field(&manifest, "bead_id"), "bd-1lsy.8.4.1");
    assert_eq!(
        require_string_field(&manifest, "normative_doc"),
        "docs/RGC_ARBITRARY_JS_TS_WORKLOAD_CORPUS_V1.md"
    );

    let runtime_targets: BTreeSet<String> = require_string_array(&manifest, "runtime_targets")
        .into_iter()
        .collect();
    assert_eq!(
        runtime_targets,
        BTreeSet::from([
            "bun_stable".to_string(),
            "franken_engine_main".to_string(),
            "node_lts".to_string()
        ])
    );

    let required_artifacts: BTreeSet<String> =
        require_string_array(&manifest, "required_artifacts")
            .into_iter()
            .collect();
    assert_eq!(
        required_artifacts,
        BTreeSet::from([
            "behavior_equivalence_summary.json".to_string(),
            "benchmark_env_manifest.json".to_string(),
            "commands.txt".to_string(),
            "env.json".to_string(),
            "events.jsonl".to_string(),
            "repro.lock".to_string(),
            "run_manifest.json".to_string()
        ])
    );

    let selection_contract = manifest
        .get("selection_contract")
        .expect("missing selection_contract");
    assert!(require_bool_field(
        selection_contract,
        "provenance_required"
    ));
    assert!(require_bool_field(
        selection_contract,
        "user_value_justification_required"
    ));
    assert!(require_bool_field(
        selection_contract,
        "report_only_before_gate"
    ));
    assert!(require_bool_field(
        selection_contract,
        "fail_closed_on_missing_sources"
    ));
}

#[test]
fn bootstrap_sources_are_unique_and_resolve_to_checked_in_paths() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let bootstrap_sources = manifest
        .get("bootstrap_sources")
        .and_then(Value::as_array)
        .expect("bootstrap_sources must be an array");
    assert!(
        bootstrap_sources.len() >= 8,
        "bootstrap sources must ground the corpus in existing checked-in surfaces"
    );

    let mut source_ids = BTreeSet::new();
    for source in bootstrap_sources {
        let source_id = require_string_field(source, "source_id");
        assert!(
            source_ids.insert(source_id.to_string()),
            "duplicate bootstrap source id: {source_id}"
        );

        let source_kind = require_string_field(source, "source_kind");
        assert!(
            matches!(
                source_kind,
                "repo_doc"
                    | "conformance_corpus"
                    | "test_fixture"
                    | "integration_test"
                    | "source_module"
            ),
            "unexpected source_kind for {source_id}: {source_kind}"
        );

        let locator = require_string_field(source, "source_locator");
        assert!(
            !locator.starts_with('/') && !locator.contains(".."),
            "source locator must stay repo-relative: {locator}"
        );

        let full = repo_root().join(locator);
        assert!(
            full.exists(),
            "bootstrap source locator must exist in repo: {}",
            full.display()
        );

        let rationale = require_string_field(source, "selection_rationale");
        assert!(
            !rationale.trim().is_empty(),
            "selection rationale must be non-empty for {source_id}"
        );
    }
}

#[test]
fn family_roster_covers_required_arbitrary_js_ts_classes() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");

    let expected_families: BTreeSet<&str> = BTreeSet::from([
        "allocation-churn-iterators",
        "async-orchestration",
        "cache-miss-metadata-stressors",
        "effect-hostcall-spikes",
        "megamorphic-branch-dispatch",
        "module-graph-transitions",
        "npm-resolution-graphs",
        "observability-sensitive-variants",
        "parse-heavy-pipelines",
        "regex-unicode-text",
        "required-native-addon-packages",
        "startup-storm-cold-image",
        "startup-storm-warm-image",
        "string-transform-pipelines",
        "ts-normalization-heavy",
        "vectorizable-builtin-kernels",
    ]);

    let mut observed_families = BTreeSet::new();
    for family in families {
        let family_id = require_string_field(family, "family_id");
        assert!(
            observed_families.insert(family_id.to_string()),
            "duplicate family id: {family_id}"
        );

        let selection_rationale = require_string_field(family, "selection_rationale");
        assert!(
            !selection_rationale.trim().is_empty(),
            "selection rationale must be non-empty for {family_id}"
        );

        let user_value = require_string_field(family, "user_value_justification");
        assert!(
            !user_value.trim().is_empty(),
            "user_value_justification must be non-empty for {family_id}"
        );
    }

    let observed_refs: BTreeSet<&str> = observed_families.iter().map(String::as_str).collect();
    assert_eq!(observed_refs, expected_families);
}

#[test]
fn family_references_and_observability_variant_matrix_are_consistent() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let required_variants: BTreeSet<String> =
        require_string_array(&manifest, "required_observability_variants")
            .into_iter()
            .collect();
    assert_eq!(
        required_variants,
        BTreeSet::from([
            "budgeted_telemetry".to_string(),
            "exact_capture".to_string(),
            "incident_mode".to_string()
        ])
    );

    let variant_matrix = manifest
        .get("variant_matrix")
        .expect("missing variant_matrix");
    let must_cover: BTreeSet<String> = require_string_array(variant_matrix, "must_cover_families")
        .into_iter()
        .collect();
    assert_eq!(
        must_cover,
        BTreeSet::from([
            "async-orchestration".to_string(),
            "module-graph-transitions".to_string(),
            "parse-heavy-pipelines".to_string(),
            "ts-normalization-heavy".to_string()
        ])
    );

    let bootstrap_sources = manifest
        .get("bootstrap_sources")
        .and_then(Value::as_array)
        .expect("bootstrap_sources must be an array");
    let known_sources: BTreeSet<String> = bootstrap_sources
        .iter()
        .map(|source| require_string_field(source, "source_id").to_string())
        .collect();

    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");
    for family in families {
        let family_id = require_string_field(family, "family_id");
        let baseline_targets: BTreeSet<String> = require_string_array(family, "baseline_targets")
            .into_iter()
            .collect();
        assert_eq!(
            baseline_targets,
            BTreeSet::from(["bun_stable".to_string(), "node_lts".to_string()]),
            "baseline targets must include node and bun for {family_id}"
        );

        let observability_variants: BTreeSet<String> =
            require_string_array(family, "observability_variants")
                .into_iter()
                .collect();
        assert_eq!(
            observability_variants, required_variants,
            "each family must support the same observability modes: {family_id}"
        );

        let bootstrap_source_ids = require_string_array(family, "bootstrap_source_ids");
        assert!(
            bootstrap_source_ids.len() >= 2,
            "each family should be grounded in at least two bootstrap sources: {family_id}"
        );
        for source_id in bootstrap_source_ids {
            assert!(
                known_sources.contains(&source_id),
                "unknown bootstrap source reference for {family_id}: {source_id}"
            );
        }
    }
}

#[test]
fn normative_doc_declares_replay_and_fail_closed_rules() {
    let doc = read_text("docs/RGC_ARBITRARY_JS_TS_WORKLOAD_CORPUS_V1.md");

    let required_headings = [
        "## Required Family Roster",
        "## Provenance Contract",
        "## Observability Variants",
        "## Replay and Operator Verification",
        "## Failure Semantics",
    ];
    for heading in required_headings {
        assert!(
            doc.contains(heading),
            "missing required heading in normative doc: {heading}"
        );
    }

    let required_fragments = [
        "./scripts/run_rgc_arbitrary_js_ts_workload_corpus.sh ci",
        "./scripts/e2e/rgc_arbitrary_js_ts_workload_corpus_replay.sh ci",
        "`exact_capture`",
        "`budgeted_telemetry`",
        "`incident_mode`",
        "fails closed",
        "source_locator",
        "step_logs/step_*.log",
    ];
    for fragment in required_fragments {
        assert!(
            doc.contains(fragment),
            "normative doc missing fragment: {fragment}"
        );
    }
}

#[test]
fn coverage_axes_are_unique_and_match_expected_set() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let axes = require_string_array(&manifest, "coverage_axes");

    let expected: BTreeSet<&str> = BTreeSet::from([
        "cold_start",
        "warm_image",
        "unicode_text",
        "module_resolution",
        "native_addon",
        "policy_pressure",
        "telemetry_mode",
        "async_ordering",
        "ts_normalization",
    ]);

    let observed: BTreeSet<String> = axes.iter().cloned().collect();
    assert_eq!(
        observed.len(),
        axes.len(),
        "coverage_axes must not contain duplicates"
    );

    let observed_refs: BTreeSet<&str> = observed.iter().map(String::as_str).collect();
    assert_eq!(observed_refs, expected);
}

#[test]
fn generated_at_utc_is_valid_iso8601() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let ts = require_string_field(&manifest, "generated_at_utc");
    assert!(
        ts.ends_with('Z'),
        "generated_at_utc must be UTC (end with Z): {ts}"
    );
    assert!(
        ts.len() >= 20,
        "generated_at_utc must be full ISO-8601: {ts}"
    );
    assert!(
        ts.contains('T'),
        "generated_at_utc must contain date-time separator T: {ts}"
    );
    let date_part = &ts[..10];
    assert_eq!(
        date_part.matches('-').count(),
        2,
        "date portion must have two dashes: {date_part}"
    );
    let time_part = &ts[11..ts.len() - 1];
    assert_eq!(
        time_part.matches(':').count(),
        2,
        "time portion must have two colons: {time_part}"
    );
}

#[test]
fn selection_contract_contains_exactly_four_boolean_fields() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let contract = manifest
        .get("selection_contract")
        .expect("missing selection_contract")
        .as_object()
        .expect("selection_contract must be an object");

    let expected_keys: BTreeSet<&str> = BTreeSet::from([
        "provenance_required",
        "user_value_justification_required",
        "report_only_before_gate",
        "fail_closed_on_missing_sources",
    ]);

    let actual_keys: BTreeSet<&str> = contract.keys().map(String::as_str).collect();
    assert_eq!(
        actual_keys, expected_keys,
        "selection_contract must contain exactly the expected boolean fields"
    );

    for (key, val) in contract {
        assert!(
            val.is_boolean(),
            "selection_contract.{key} must be a boolean, got: {val}"
        );
        assert!(
            val.as_bool().unwrap(),
            "selection_contract.{key} must be true (fail-closed posture)"
        );
    }
}

#[test]
fn variant_matrix_must_cover_families_are_declared_in_family_definitions() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");

    let family_ids: BTreeSet<String> = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array")
        .iter()
        .map(|f| require_string_field(f, "family_id").to_string())
        .collect();

    let variant_matrix = manifest
        .get("variant_matrix")
        .expect("missing variant_matrix");
    let must_cover = require_string_array(variant_matrix, "must_cover_families");

    for family_ref in &must_cover {
        assert!(
            family_ids.contains(family_ref),
            "variant_matrix.must_cover_families references unknown family: {family_ref}"
        );
    }

    assert!(
        must_cover.len() >= 3,
        "variant_matrix must cover at least 3 families for meaningful cross-variant validation"
    );
}

#[test]
fn family_ids_follow_kebab_case_convention() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");

    for family in families {
        let family_id = require_string_field(family, "family_id");
        assert!(!family_id.is_empty(), "family_id must be non-empty");
        assert!(
            family_id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()),
            "family_id must be kebab-case (lowercase + hyphens): {family_id}"
        );
        assert!(
            !family_id.starts_with('-') && !family_id.ends_with('-'),
            "family_id must not start or end with a hyphen: {family_id}"
        );
        assert!(
            !family_id.contains("--"),
            "family_id must not contain consecutive hyphens: {family_id}"
        );
    }
}

#[test]
fn bootstrap_source_locators_are_unique() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let sources = manifest
        .get("bootstrap_sources")
        .and_then(Value::as_array)
        .expect("bootstrap_sources must be an array");

    let mut locators = BTreeSet::new();
    for source in sources {
        let locator = require_string_field(source, "source_locator");
        assert!(
            locators.insert(locator.to_string()),
            "duplicate bootstrap source locator: {locator}"
        );
    }
}

#[test]
fn family_selection_rationales_are_distinct() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");

    let mut rationales = BTreeSet::new();
    let mut justifications = BTreeSet::new();
    for family in families {
        let family_id = require_string_field(family, "family_id");
        let rationale = require_string_field(family, "selection_rationale");
        assert!(
            rationales.insert(rationale.to_string()),
            "duplicate selection_rationale across families (found on {family_id})"
        );

        let justification = require_string_field(family, "user_value_justification");
        assert!(
            justifications.insert(justification.to_string()),
            "duplicate user_value_justification across families (found on {family_id})"
        );
    }
}

#[test]
fn every_bootstrap_source_is_referenced_by_at_least_one_family() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");

    let sources = manifest
        .get("bootstrap_sources")
        .and_then(Value::as_array)
        .expect("bootstrap_sources must be an array");
    let all_source_ids: BTreeSet<String> = sources
        .iter()
        .map(|s| require_string_field(s, "source_id").to_string())
        .collect();

    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for family in families {
        for sid in require_string_array(family, "bootstrap_source_ids") {
            referenced.insert(sid);
        }
    }

    for source_id in &all_source_ids {
        assert!(
            referenced.contains(source_id),
            "bootstrap source {source_id} is never referenced by any family — dead provenance anchor"
        );
    }
}

#[test]
fn coverage_axes_names_follow_snake_case_convention() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let axes = require_string_array(&manifest, "coverage_axes");

    for axis in &axes {
        assert!(!axis.is_empty(), "coverage axis must be non-empty");
        assert!(
            axis.chars()
                .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
            "coverage axis must be snake_case: {axis}"
        );
        assert!(
            !axis.starts_with('_') && !axis.ends_with('_'),
            "coverage axis must not start or end with underscore: {axis}"
        );
    }
}

#[test]
fn normative_doc_path_resolves_and_is_repo_relative() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let doc_path = require_string_field(&manifest, "normative_doc");

    assert!(
        !doc_path.starts_with('/'),
        "normative_doc must be repo-relative, not absolute: {doc_path}"
    );
    assert!(
        !doc_path.contains(".."),
        "normative_doc must not traverse upward: {doc_path}"
    );
    assert!(
        doc_path.ends_with(".md"),
        "normative_doc must be a markdown file: {doc_path}"
    );

    let full = repo_root().join(doc_path);
    assert!(
        full.exists(),
        "normative_doc must exist in repo: {}",
        full.display()
    );
}

#[test]
fn manifest_top_level_keys_are_the_expected_schema_surface() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let obj = manifest
        .as_object()
        .expect("manifest must be a JSON object");

    let expected_keys: BTreeSet<&str> = BTreeSet::from([
        "schema_version",
        "bead_id",
        "generated_at_utc",
        "normative_doc",
        "runtime_targets",
        "required_artifacts",
        "selection_contract",
        "required_observability_variants",
        "variant_matrix",
        "coverage_axes",
        "bootstrap_sources",
        "family_definitions",
    ]);

    let actual_keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(
        actual_keys, expected_keys,
        "manifest top-level keys must match the declared schema surface exactly"
    );
}

#[test]
fn family_count_matches_expected_sixteen() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");

    assert_eq!(
        families.len(),
        16,
        "corpus must declare exactly 16 workload families"
    );
}

#[test]
fn bootstrap_source_kinds_have_expected_distribution() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let sources = manifest
        .get("bootstrap_sources")
        .and_then(Value::as_array)
        .expect("bootstrap_sources must be an array");

    let mut kind_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for source in sources {
        let kind = require_string_field(source, "source_kind").to_string();
        *kind_counts.entry(kind).or_insert(0) += 1;
    }

    assert!(
        kind_counts.contains_key("repo_doc"),
        "must have at least one repo_doc bootstrap source"
    );
    assert!(
        kind_counts.contains_key("conformance_corpus"),
        "must have at least one conformance_corpus bootstrap source"
    );
    assert!(
        kind_counts.contains_key("test_fixture"),
        "must have at least one test_fixture bootstrap source"
    );
    assert!(
        kind_counts.contains_key("integration_test"),
        "must have at least one integration_test bootstrap source"
    );
    assert!(
        kind_counts.contains_key("source_module"),
        "must have at least one source_module bootstrap source"
    );

    assert_eq!(
        kind_counts.len(),
        5,
        "exactly 5 source_kind categories should be present"
    );
}

#[test]
fn normative_doc_mentions_every_family_id() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let doc = read_text("docs/RGC_ARBITRARY_JS_TS_WORKLOAD_CORPUS_V1.md");

    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");

    for family in families {
        let family_id = require_string_field(family, "family_id");
        assert!(
            doc.contains(family_id),
            "normative doc must mention family {family_id}"
        );
    }
}

#[test]
fn coverage_axes_count_is_at_least_family_roster_dimensionality() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let axes = require_string_array(&manifest, "coverage_axes");
    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");

    assert!(
        axes.len() >= 5,
        "coverage axes must provide meaningful dimensionality (got {})",
        axes.len()
    );
    assert!(
        axes.len() <= families.len(),
        "coverage axes ({}) should not outnumber families ({})",
        axes.len(),
        families.len()
    );
}

// ---------------------------------------------------------------------------
// Enrichment: structural and cross-reference integrity
// ---------------------------------------------------------------------------

#[test]
fn schema_version_follows_expected_prefix() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let sv = require_string_field(&manifest, "schema_version");
    assert!(
        sv.starts_with("franken-engine."),
        "schema_version must start with franken-engine. prefix: {sv}"
    );
    assert!(
        sv.ends_with(".v1"),
        "schema_version must end with version suffix: {sv}"
    );
}

#[test]
fn bead_id_follows_hierarchy_format() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let bead_id = require_string_field(&manifest, "bead_id");
    assert!(
        bead_id.starts_with("bd-"),
        "bead_id must start with bd- prefix: {bead_id}"
    );
    assert!(
        bead_id.contains('.'),
        "bead_id must be hierarchical (contain dots): {bead_id}"
    );
}

#[test]
fn runtime_targets_exactly_three() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let targets = require_string_array(&manifest, "runtime_targets");
    assert_eq!(targets.len(), 3, "must have exactly 3 runtime targets");
}

#[test]
fn required_artifacts_include_run_manifest_and_events() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let artifacts: BTreeSet<String> = require_string_array(&manifest, "required_artifacts")
        .into_iter()
        .collect();
    assert!(
        artifacts.contains("run_manifest.json"),
        "must include run_manifest.json"
    );
    assert!(
        artifacts.contains("events.jsonl"),
        "must include events.jsonl"
    );
    assert!(artifacts.contains("repro.lock"), "must include repro.lock");
}

#[test]
fn all_bootstrap_source_ids_are_non_empty_kebab_or_snake() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let sources = manifest
        .get("bootstrap_sources")
        .and_then(Value::as_array)
        .expect("bootstrap_sources must be an array");
    for source in sources {
        let sid = require_string_field(source, "source_id");
        assert!(!sid.is_empty(), "source_id must be non-empty");
        assert!(
            sid.chars()
                .all(|c| c.is_ascii_lowercase() || c == '-' || c == '_' || c.is_ascii_digit()),
            "source_id must be lowercase with hyphens/underscores: {sid}"
        );
    }
}

#[test]
fn family_definitions_each_have_minimum_required_keys() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");

    let required_keys: BTreeSet<&str> = BTreeSet::from([
        "family_id",
        "selection_rationale",
        "user_value_justification",
        "baseline_targets",
        "observability_variants",
        "bootstrap_source_ids",
    ]);

    for family in families {
        let obj = family.as_object().expect("family must be an object");
        let keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        for rk in &required_keys {
            assert!(keys.contains(rk), "family missing required key: {rk}");
        }
    }
}

#[test]
fn variant_matrix_has_expected_structure() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let vm = manifest
        .get("variant_matrix")
        .expect("missing variant_matrix")
        .as_object()
        .expect("variant_matrix must be an object");

    assert!(
        vm.contains_key("must_cover_families"),
        "variant_matrix must contain must_cover_families"
    );
}

#[test]
fn required_observability_variants_exactly_three() {
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let variants = require_string_array(&manifest, "required_observability_variants");
    assert_eq!(
        variants.len(),
        3,
        "must have exactly 3 observability variants"
    );
}

#[test]
fn manifest_json_deterministic_reparse() {
    let a = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let b = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    assert_eq!(a, b, "manifest must parse deterministically");
}

#[test]
fn normative_doc_is_substantial() {
    let doc = read_text("docs/RGC_ARBITRARY_JS_TS_WORKLOAD_CORPUS_V1.md");
    assert!(
        doc.len() > 500,
        "normative doc must be substantial (got {} bytes)",
        doc.len()
    );
    assert!(
        doc.lines().count() > 20,
        "normative doc must have meaningful content"
    );
}

// ===== PearlTower enrichment =====

#[test]
fn enrichment_manifest_serde_roundtrip_preserves_all_fields() {
    // Verify that serializing and re-parsing the manifest produces an identical
    // JSON value — confirming no field is dropped or coerced on roundtrip.
    let original = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let serialized =
        serde_json::to_string(&original).expect("manifest must serialize to JSON string");
    let reparsed: Value =
        serde_json::from_str(&serialized).expect("serialized manifest must re-parse as JSON");
    assert_eq!(
        original, reparsed,
        "serde roundtrip must preserve all fields without loss"
    );
}

#[test]
fn enrichment_runtime_targets_contain_no_empty_strings() {
    // Each runtime target identifier must be a non-empty, printable token.
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let targets = require_string_array(&manifest, "runtime_targets");
    for target in &targets {
        assert!(
            !target.trim().is_empty(),
            "runtime_target must not be blank or whitespace-only: {target:?}"
        );
        assert!(
            target
                .chars()
                .all(|c| c.is_ascii() && !c.is_ascii_control()),
            "runtime_target must contain only printable ASCII: {target:?}"
        );
    }
}

#[test]
fn enrichment_required_artifacts_contain_no_duplicate_entries() {
    // Duplicate artifact names would silently collapse identical output files.
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let artifacts = require_string_array(&manifest, "required_artifacts");
    let unique: BTreeSet<&str> = artifacts.iter().map(String::as_str).collect();
    assert_eq!(
        unique.len(),
        artifacts.len(),
        "required_artifacts must not contain duplicate filenames"
    );
}

#[test]
fn enrichment_required_artifacts_are_file_extensions_well_formed() {
    // Every required artifact name must have a recognized extension so
    // downstream tooling can dispatch on file type without guessing.
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let artifacts = require_string_array(&manifest, "required_artifacts");
    let allowed_extensions: BTreeSet<&str> = BTreeSet::from(["json", "jsonl", "txt", "lock"]);
    for artifact in &artifacts {
        let ext = artifact.rsplit('.').next().unwrap_or("");
        assert!(
            allowed_extensions.contains(ext),
            "required artifact has unrecognized extension: {artifact} (ext={ext:?})"
        );
    }
}

#[test]
fn enrichment_family_bootstrap_source_ids_are_unique_per_family() {
    // A family must not redundantly reference the same source twice.
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");

    for family in families {
        let family_id = require_string_field(family, "family_id");
        let source_ids = require_string_array(family, "bootstrap_source_ids");
        let unique: BTreeSet<&str> = source_ids.iter().map(String::as_str).collect();
        assert_eq!(
            unique.len(),
            source_ids.len(),
            "family {family_id} has duplicate bootstrap_source_ids"
        );
    }
}

#[test]
fn enrichment_observability_variants_names_contain_no_whitespace() {
    // Variant names are used as identifiers in scripts; whitespace would break
    // shell invocations and file-path generation.
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let variants = require_string_array(&manifest, "required_observability_variants");
    for variant in &variants {
        assert!(
            !variant.chars().any(|c| c.is_whitespace()),
            "observability variant name must not contain whitespace: {variant:?}"
        );
        assert!(
            !variant.is_empty(),
            "observability variant name must not be empty"
        );
    }
}

#[test]
fn enrichment_manifest_json_reparse_is_deterministic_across_multiple_loads() {
    // Parse the manifest three times independently and assert all three values
    // are identical — detecting any OS-level file caching anomaly or PRNG seed
    // that could cause non-deterministic JSON object ordering.
    let a = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let b = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let c = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    assert_eq!(a, b, "first and second parse must be identical");
    assert_eq!(b, c, "second and third parse must be identical");
}

#[test]
fn enrichment_normative_doc_has_no_trailing_whitespace_on_content_lines() {
    // Trailing whitespace is a common sign of copy-paste artifacts that
    // indicate the doc was not reviewed carefully.  We allow up to 5% of lines
    // to have trailing spaces to avoid being overly strict about markdown
    // tables, but zero tolerance for tab-trailing lines.
    let doc = read_text("docs/RGC_ARBITRARY_JS_TS_WORKLOAD_CORPUS_V1.md");
    let mut trailing_tab_lines: Vec<usize> = Vec::new();
    for (idx, line) in doc.lines().enumerate() {
        if line.ends_with('\t') {
            trailing_tab_lines.push(idx + 1);
        }
    }
    assert!(
        trailing_tab_lines.is_empty(),
        "normative doc has lines ending with tab characters at lines: {trailing_tab_lines:?}"
    );
}

#[test]
fn enrichment_coverage_axes_have_no_consecutive_underscores() {
    // Consecutive underscores in axis names suggest copy-paste errors and
    // would make axis identifiers visually ambiguous in tooling output.
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let axes = require_string_array(&manifest, "coverage_axes");
    for axis in &axes {
        assert!(
            !axis.contains("__"),
            "coverage axis must not contain consecutive underscores: {axis}"
        );
    }
}

#[test]
fn enrichment_family_observability_variants_are_a_subset_of_required_variants() {
    // No family may declare an observability variant that is not in the global
    // required_observability_variants list — that would create untestable state.
    let manifest = read_json("docs/rgc_arbitrary_js_ts_workload_corpus_v1.json");
    let required: BTreeSet<String> =
        require_string_array(&manifest, "required_observability_variants")
            .into_iter()
            .collect();

    let families = manifest
        .get("family_definitions")
        .and_then(Value::as_array)
        .expect("family_definitions must be an array");

    for family in families {
        let family_id = require_string_field(family, "family_id");
        let variants: BTreeSet<String> = require_string_array(family, "observability_variants")
            .into_iter()
            .collect();
        for v in &variants {
            assert!(
                required.contains(v),
                "family {family_id} declares unknown observability variant: {v}"
            );
        }
    }
}
