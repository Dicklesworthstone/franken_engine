use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use frankenengine_engine::supremacy_cell_matrix::{
    REQUIRED_BOARD_FAMILIES, SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION,
    SUPREMACY_CELL_MATRIX_SCHEMA_VERSION, SupremacyCellMatrixArtifact, WorkloadFamily,
    artifact_hash, build_interference_index, validate_artifact,
};

fn load_fixture() -> SupremacyCellMatrixArtifact {
    let path = Path::new("tests/fixtures/supremacy_cell_matrix_v1.json");
    let bytes = fs::read(path).expect("read supremacy cell matrix fixture");
    serde_json::from_slice(&bytes).expect("deserialize supremacy cell matrix fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/RGC_SUPREMACY_CELL_MATRIX_V1.md");
    fs::read_to_string(path).expect("read supremacy cell matrix doc")
}

fn load_runner_script() -> String {
    let path = Path::new("../../scripts/run_supremacy_cell_matrix_suite.sh");
    fs::read_to_string(path).expect("read supremacy cell matrix runner")
}

#[test]
fn supremacy_cell_matrix_fixture_versions_and_artifacts_are_stable() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        SUPREMACY_CELL_MATRIX_SCHEMA_VERSION.to_string()
    );
    assert_eq!(
        fixture.log_schema_version,
        SUPREMACY_CELL_MATRIX_LOG_SCHEMA_VERSION.to_string()
    );
    assert_eq!(
        fixture.required_artifacts,
        vec![
            "supremacy_cell_matrix.json",
            "run_manifest.json",
            "events.jsonl",
            "commands.txt",
        ]
    );
    assert_eq!(
        fixture.required_consumers,
        vec!["benchmark", "docs", "rollout", "ga"]
    );
}

#[test]
fn supremacy_cell_matrix_fixture_is_valid_and_complete() {
    let fixture = load_fixture();
    validate_artifact(&fixture).expect("fixture should validate");

    let families: BTreeSet<WorkloadFamily> = fixture
        .cell_families
        .iter()
        .map(|family| family.family)
        .collect();
    let required: BTreeSet<WorkloadFamily> = REQUIRED_BOARD_FAMILIES.iter().copied().collect();
    assert_eq!(families, required);

    let cell_families: BTreeSet<WorkloadFamily> =
        fixture.cells.iter().map(|cell| cell.family).collect();
    assert_eq!(cell_families, required);
}

#[test]
fn supremacy_cell_matrix_interference_index_has_expected_edges() {
    let fixture = load_fixture();
    let index = build_interference_index(&fixture).expect("index should build");

    let mixed_edges = index
        .get(&WorkloadFamily::MixedPackage)
        .expect("mixed package edges");
    assert!(mixed_edges.contains(&WorkloadFamily::Async));
    assert!(mixed_edges.contains(&WorkloadFamily::ModuleGraphs));
    assert!(mixed_edges.contains(&WorkloadFamily::TailLatency));

    let react_edges = index
        .get(&WorkloadFamily::ReactSsr)
        .expect("react ssr edges");
    assert!(react_edges.contains(&WorkloadFamily::ReactClient));
    assert!(react_edges.contains(&WorkloadFamily::MemoryPressure));
}

#[test]
fn supremacy_cell_matrix_hash_is_deterministic() {
    let fixture = load_fixture();
    let first = artifact_hash(&fixture).expect("hash should succeed");
    let second = artifact_hash(&fixture).expect("hash should succeed");

    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
}

#[test]
fn supremacy_cell_matrix_doc_has_required_sections_and_keywords() {
    let doc = load_doc();

    let required_sections = [
        "## Purpose",
        "## Matrix Dimensions",
        "## Required Families",
        "## Interference Model",
        "## Tail Decomposition",
        "## Verification",
    ];
    for section in required_sections {
        assert!(
            doc.contains(section),
            "required section missing from doc: {section}"
        );
    }

    let keywords = [
        "React",
        "cold-start",
        "module",
        "async",
        "mixed-package",
        "interference",
        "tail-latency",
        "rch",
        "supremacy_cell_matrix.json",
    ];
    for keyword in keywords {
        assert!(
            doc.contains(keyword),
            "required keyword missing from doc: {keyword}"
        );
    }

    let word_count = doc.split_whitespace().count();
    assert!(
        word_count >= 250,
        "doc should have at least 250 words, found {word_count}"
    );
}

#[test]
fn supremacy_cell_matrix_runner_script_requires_rch_and_contract_outputs() {
    let script = load_runner_script();

    for snippet in [
        "rch is required",
        "cargo check -p frankenengine-engine --test supremacy_cell_matrix",
        "cargo test -p frankenengine-engine --test supremacy_cell_matrix",
        "cargo clippy -p frankenengine-engine --test supremacy_cell_matrix -- -D warnings",
        "supremacy_cell_matrix.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
    ] {
        assert!(
            script.contains(snippet),
            "runner script missing required snippet: {snippet}"
        );
    }
}
