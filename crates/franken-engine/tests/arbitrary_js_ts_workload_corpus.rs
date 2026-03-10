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
