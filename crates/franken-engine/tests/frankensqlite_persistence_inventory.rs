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

#[test]
fn frankensqlite_inventory_contains_required_stores_and_sections() {
    let inventory_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let inventory = fs::read_to_string(&inventory_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", inventory_path.display()));

    let required_sections = [
        "## Database Topology",
        "## Store Inventory",
        "## Decision Boundary: Shared Vs Isolated",
        "## Review Gate Requirements",
        "## Traceability Matrix (10.15)",
    ];
    for section in required_sections {
        assert!(
            inventory.contains(section),
            "Inventory must contain required section: {section}"
        );
    }

    let required_stores = [
        "replay index",
        "evidence index",
        "benchmark ledger",
        "policy artifact cache",
        "PLAS witness store",
        "replacement lineage log",
        "IFC provenance index",
        "specialization index",
    ];
    for store in required_stores {
        assert!(
            inventory.contains(store),
            "Inventory must include required store entry: {store}"
        );
    }

    let required_columns = [
        "Model layer",
        "Data model",
        "Access pattern",
        "Consistency requirement",
        "Retention policy",
        "Frankensqlite integration point",
        "Migration strategy",
        "Deterministic replay requirement",
    ];
    for column in required_columns {
        assert!(
            inventory.contains(column),
            "Inventory must include required mapping field: {column}"
        );
    }
}

#[test]
fn frankensqlite_inventory_file_exists_and_is_nonempty() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(!content.is_empty());
}

#[test]
fn frankensqlite_inventory_references_traceability() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("Traceability"));
}

#[test]
fn frankensqlite_inventory_references_deterministic_replay() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("Deterministic replay"));
}

#[test]
fn frankensqlite_inventory_has_database_topology_content() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Database Topology"));
}

#[test]
fn frankensqlite_inventory_has_shared_vs_isolated_decision() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("Shared Vs Isolated"));
}

#[test]
fn frankensqlite_inventory_has_review_gate_requirements() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Review Gate Requirements"));
}

#[test]
fn frankensqlite_inventory_lists_shared_control_plane_db() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("control_plane.db"));
}

#[test]
fn frankensqlite_inventory_lists_isolated_databases() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("benchmark_ledger.db"));
    assert!(content.contains("plas_witness.db"));
    assert!(content.contains("replacement_lineage.db"));
}

#[test]
fn frankensqlite_inventory_has_operator_verification_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Operator Verification"));
}

#[test]
fn frankensqlite_inventory_mentions_scope_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Scope"));
}

#[test]
fn frankensqlite_inventory_references_upstream_adr() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("ADR-0004-frankensqlite-reuse-scope.md"));
}

#[test]
fn frankensqlite_inventory_mentions_retention_policy() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("Retention policy"));
}

#[test]
fn frankensqlite_inventory_has_store_inventory_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Store Inventory"));
}

#[test]
fn frankensqlite_inventory_has_traceability_matrix_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Traceability Matrix"));
}

#[test]
fn frankensqlite_inventory_has_database_topology_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Database Topology"));
}

#[test]
fn frankensqlite_inventory_has_more_than_10_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let line_count = content.lines().count();
    assert!(
        line_count > 10,
        "inventory should have >10 lines, got {line_count}"
    );
}

#[test]
fn frankensqlite_inventory_deterministic_double_read() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}

#[test]
fn frankensqlite_inventory_mentions_consistency_requirement() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("Consistency requirement"));
}

#[test]
fn frankensqlite_inventory_has_more_than_50_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.lines().count() > 50);
}

#[test]
fn frankensqlite_inventory_has_review_gate_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(content.contains("## Review Gate Requirements"));
}

#[test]
fn frankensqlite_inventory_file_path_is_valid() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    assert!(path.exists());
}

#[test]
fn frankensqlite_inventory_word_count_minimum() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let word_count = content.split_whitespace().count();
    assert!(
        word_count >= 200,
        "Inventory should have at least 200 words for adequate specification, got {word_count}"
    );
}

#[test]
fn frankensqlite_inventory_sections_appear_in_expected_order() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let ordered_sections = [
        "## Scope",
        "## Database Topology",
        "## Store Inventory",
        "## Decision Boundary: Shared Vs Isolated",
        "## Review Gate Requirements",
        "## Traceability Matrix",
        "## Operator Verification",
    ];
    let mut last_pos = 0;
    for section in ordered_sections {
        let pos = content.find(section).unwrap_or_else(|| {
            panic!("Inventory missing section: {section}");
        });
        assert!(
            pos >= last_pos,
            "Section `{section}` appears out of order (pos {pos} < last {last_pos})"
        );
        last_pos = pos;
    }
}

#[test]
fn frankensqlite_inventory_store_table_has_eight_data_rows() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let table_start = content.find("## Store Inventory").unwrap();
    let table_end = content.find("## Decision Boundary").unwrap();
    let table_section = &content[table_start..table_end];
    // Count pipe-delimited rows, excluding header and separator
    let pipe_rows: Vec<&str> = table_section
        .lines()
        .filter(|l| l.starts_with('|'))
        .collect();
    // header + separator + 8 stores = 10
    assert!(
        pipe_rows.len() >= 10,
        "Store inventory table should have at least 10 pipe rows (header+sep+8 stores), got {}",
        pipe_rows.len()
    );
}

#[test]
fn frankensqlite_inventory_shared_vs_isolated_has_three_criteria() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let boundary_pos = content
        .find("## Decision Boundary: Shared Vs Isolated")
        .unwrap();
    let review_pos = content.find("## Review Gate Requirements").unwrap();
    let boundary_section = &content[boundary_pos..review_pos];
    for n in 1..=3 {
        let marker = format!("{n}.");
        assert!(
            boundary_section.contains(&marker),
            "Shared Vs Isolated decision must list criterion {n}"
        );
    }
}

#[test]
fn frankensqlite_inventory_review_gate_has_six_steps() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let gate_pos = content.find("## Review Gate Requirements").unwrap();
    let trace_pos = content.find("## Traceability Matrix").unwrap();
    let gate_section = &content[gate_pos..trace_pos];
    for n in 1..=6 {
        let marker = format!("{n}.");
        assert!(
            gate_section.contains(&marker),
            "Review Gate must list step {n}"
        );
    }
}

#[test]
fn frankensqlite_inventory_traceability_maps_all_workflow_families() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let trace_pos = content.find("## Traceability Matrix").unwrap();
    let trace_section = &content[trace_pos..];
    let required_workflows = [
        "Witness workflows",
        "Replacement/promotion workflows",
        "Provenance/non-interference workflows",
        "Proof specialization workflows",
        "Benchmark governance workflows",
        "Replay/evidence governance workflows",
    ];
    for workflow in required_workflows {
        assert!(
            trace_section.contains(workflow),
            "Traceability matrix must map workflow: {workflow}"
        );
    }
}

#[test]
fn frankensqlite_inventory_model_layer_types_present() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(
        content.contains("raw frankensqlite"),
        "Inventory must reference `raw frankensqlite` model layer"
    );
    assert!(
        content.contains("sqlmodel_rust on frankensqlite"),
        "Inventory must reference `sqlmodel_rust on frankensqlite` model layer"
    );
}

#[test]
fn frankensqlite_inventory_bead_references_are_well_formed() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let bead_count = content.matches("`bd-").count();
    assert!(
        bead_count >= 3,
        "Inventory should reference at least 3 beads, found {bead_count}"
    );
}

#[test]
fn frankensqlite_inventory_frankensqlite_integration_points_present() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let required_points = [
        "frankensqlite::control_plane::replay_index",
        "frankensqlite::control_plane::evidence_index",
        "frankensqlite::benchmark::ledger",
        "frankensqlite::control_plane::policy_cache",
        "frankensqlite::analysis::plas_witness",
        "frankensqlite::replacement::lineage_log",
    ];
    for point in required_points {
        assert!(
            content.contains(point),
            "Inventory must list integration point: {point}"
        );
    }
}

#[test]
fn frankensqlite_inventory_is_not_empty() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(
        content.len() > 500,
        "Inventory should be substantial, got {} bytes",
        content.len()
    );
}

#[test]
fn frankensqlite_inventory_has_markdown_title() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    assert!(
        content.starts_with("# "),
        "Inventory must start with a top-level heading"
    );
}

#[test]
fn frankensqlite_inventory_no_todo_markers() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let todo_count = content.to_lowercase().matches("todo").count();
    assert!(
        todo_count == 0,
        "Inventory should not contain TODO markers, found {todo_count}"
    );
}

#[test]
fn frankensqlite_inventory_contains_determinism_keyword() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/FRANKENSQLITE_PERSISTENCE_INVENTORY.md");
    let content = fs::read_to_string(&path).expect("read inventory");
    let lower = content.to_lowercase();
    assert!(
        lower.contains("determinism") || lower.contains("deterministic"),
        "Inventory must reference determinism guarantees"
    );
}
