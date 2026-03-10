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

use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn adr_defines_sqlmodel_rust_boundary_rules_and_examples() {
    let adr_path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let adr = fs::read_to_string(&adr_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

    let required_clauses = [
        "## Companion Decision: `sqlmodel_rust` Boundary",
        "Use `sqlmodel_rust` (typed model layer on frankensqlite) when one or more are true:",
        "Use raw `/dp/frankensqlite` primitives when all are true:",
        "replay index",
        "benchmark ledger",
        "replacement lineage log",
        "IFC provenance index",
    ];

    for clause in required_clauses {
        assert!(
            adr.contains(clause),
            "ADR must include required sqlmodel boundary clause: {clause}"
        );
    }
}

#[test]
fn inventory_tracks_model_layer_choice_for_each_store() {
    let inventory_path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let inventory = fs::read_to_string(&inventory_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", inventory_path.display()));

    let required_clauses = [
        "Model layer",
        "raw frankensqlite",
        "sqlmodel_rust on frankensqlite",
        "Set the `Model layer` (`raw frankensqlite` or `sqlmodel_rust on frankensqlite`) with rationale.",
    ];

    for clause in required_clauses {
        assert!(
            inventory.contains(clause),
            "Inventory must include required sqlmodel traceability clause: {clause}"
        );
    }
}

#[test]
fn sqlmodel_adr_file_exists_and_is_nonempty() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(!content.is_empty());
}

#[test]
fn sqlmodel_inventory_file_exists_and_is_nonempty() {
    let path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(!content.is_empty());
}

#[test]
fn sqlmodel_boundary_references_typed_and_raw_layers() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("sqlmodel_rust"));
    assert!(content.contains("frankensqlite"));
}

#[test]
fn sqlmodel_boundary_references_persistence_boundary() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Persistence Boundary"));
}

#[test]
fn sqlmodel_inventory_references_store_categories() {
    let path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("replay index"));
    assert!(content.contains("evidence index"));
    assert!(content.contains("benchmark ledger"));
}

#[test]
fn sqlmodel_adr_mentions_typed_model_and_raw_criteria() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Use `sqlmodel_rust`"));
    assert!(content.contains("Use raw `/dp/frankensqlite`"));
}

#[test]
fn sqlmodel_inventory_mentions_rationale() {
    let path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let lower = content.to_ascii_lowercase();
    assert!(
        lower.contains("rationale"),
        "inventory must mention rationale for model layer choices"
    );
}

#[test]
fn sqlmodel_adr_mentions_companion_decision() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Companion Decision"));
}

#[test]
fn sqlmodel_adr_mentions_multi_table_relationships() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("multi-table relationships"));
}

#[test]
fn sqlmodel_adr_mentions_compile_time_alignment() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("compile-time model/schema alignment"));
}

#[test]
fn sqlmodel_inventory_lists_all_eight_stores() {
    let path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    for store in [
        "replay index",
        "evidence index",
        "benchmark ledger",
        "policy artifact cache",
        "PLAS witness store",
        "replacement lineage log",
        "IFC provenance index",
        "specialization index",
    ] {
        assert!(content.contains(store), "inventory missing store: {store}");
    }
}

#[test]
fn sqlmodel_adr_defines_decision_section() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Decision"));
}

#[test]
fn sqlmodel_adr_defines_scope_section() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Scope"));
}

#[test]
fn sqlmodel_inventory_mentions_migration_strategy() {
    let path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("Migration strategy"));
}

#[test]
fn sqlmodel_adr_has_rationale_section() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Rationale"));
}

#[test]
fn sqlmodel_adr_has_exception_process_section() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Exception Process"));
}

#[test]
fn sqlmodel_adr_has_consequences_section() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Consequences"));
}

#[test]
fn sqlmodel_adr_has_more_than_10_lines() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let line_count = content.lines().count();
    assert!(
        line_count > 10,
        "ADR should have >10 lines, got {line_count}"
    );
}

#[test]
fn sqlmodel_inventory_has_more_than_10_lines() {
    let path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let line_count = content.lines().count();
    assert!(
        line_count > 10,
        "inventory should have >10 lines, got {line_count}"
    );
}

#[test]
fn sqlmodel_adr_deterministic_double_read() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}

#[test]
fn sqlmodel_adr_file_exists() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    assert!(path.exists(), "ADR file must exist");
}

#[test]
fn sqlmodel_inventory_file_exists() {
    let path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    assert!(path.exists(), "inventory file must exist");
}

#[test]
fn sqlmodel_adr_has_minimum_word_count() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let word_count = content.split_whitespace().count();
    assert!(
        word_count >= 100,
        "ADR should have >= 100 words, got {word_count}"
    );
}

#[test]
fn sqlmodel_inventory_has_minimum_word_count() {
    let path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let word_count = content.split_whitespace().count();
    assert!(
        word_count >= 50,
        "inventory should have >= 50 words, got {word_count}"
    );
}

#[test]
fn sqlmodel_adr_mentions_frankensqlite() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("frankensqlite"),
        "ADR must mention frankensqlite"
    );
}

#[test]
fn sqlmodel_inventory_has_model_layer_table_structure() {
    let path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(
        content.contains("Model layer") && content.contains("raw frankensqlite"),
        "inventory must have model layer table with raw frankensqlite option"
    );
}

#[test]
fn sqlmodel_adr_has_context_section() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("## Context"),
        "ADR must have Context section"
    );
}

#[test]
fn sqlmodel_adr_mentions_sqlmodel_rust() {
    let path = repo_root().join("docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("sqlmodel_rust"),
        "ADR must mention sqlmodel_rust"
    );
}

#[test]
fn sqlmodel_inventory_deterministic_double_read() {
    let path = repo_root().join("docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}
