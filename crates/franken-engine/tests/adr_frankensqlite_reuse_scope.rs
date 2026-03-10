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
fn frankensqlite_reuse_scope_adr_contains_required_sections() {
    let adr_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let adr = fs::read_to_string(&adr_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

    let required_sections = [
        "## Decision",
        "## Scope",
        "## Rationale",
        "## Exception Process",
        "## Persistence Boundary Definition",
    ];
    for section in required_sections {
        assert!(
            adr.contains(section),
            "ADR must contain required section: {section}"
        );
    }

    let required_scope_items = [
        "replay index",
        "evidence index",
        "benchmark ledger",
        "policy cache",
        "witness stores",
        "lineage logs",
        "WAL/PRAGMA",
        "schema migration",
        "/dp/frankensqlite",
    ];
    for item in required_scope_items {
        assert!(
            adr.contains(item),
            "ADR must include required scope/boundary item `{item}`"
        );
    }
}

#[test]
fn frankensqlite_adr_file_exists_and_is_nonempty() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(!content.is_empty());
}

#[test]
fn frankensqlite_adr_references_companion_decision() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Companion Decision"));
}

#[test]
fn frankensqlite_adr_references_wal() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("WAL"));
}

#[test]
fn frankensqlite_adr_mentions_schema_migration() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("schema migration"));
}

#[test]
fn frankensqlite_adr_has_persistence_boundary_definition() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Persistence Boundary Definition"));
}

#[test]
fn frankensqlite_adr_has_rationale_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Rationale"));
}

#[test]
fn frankensqlite_adr_status_is_accepted() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Status: Accepted"));
}

#[test]
fn frankensqlite_adr_mentions_canonical_substrate() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("canonical substrate"));
}

#[test]
fn frankensqlite_adr_has_context_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Context"));
}

#[test]
fn frankensqlite_adr_has_decision_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Decision"));
}

#[test]
fn frankensqlite_adr_references_related_beads() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Related beads"));
}

#[test]
fn frankensqlite_adr_mentions_lineage_logs() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("lineage logs"));
}

#[test]
fn frankensqlite_adr_has_consequences_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Consequences"));
}

#[test]
fn frankensqlite_adr_has_compliance_signals_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Compliance Signals"));
}

#[test]
fn frankensqlite_adr_has_migration_policy_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Migration Policy"));
}

#[test]
fn frankensqlite_adr_has_more_than_10_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let line_count = content.lines().count();
    assert!(
        line_count > 10,
        "ADR should have >10 lines, got {line_count}"
    );
}

#[test]
fn frankensqlite_adr_deterministic_double_read() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}

#[test]
fn frankensqlite_adr_mentions_evidence_index() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("evidence index"));
}

#[test]
fn frankensqlite_adr_has_scope_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Scope"));
}

#[test]
fn frankensqlite_adr_has_operator_verification_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Operator Verification"));
}

#[test]
fn frankensqlite_adr_has_more_than_50_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.lines().count() > 50);
}

#[test]
fn frankensqlite_adr_word_count_minimum() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let word_count = content.split_whitespace().count();
    assert!(
        word_count >= 300,
        "ADR should have at least 300 words for adequate specification, got {word_count}"
    );
}

#[test]
fn frankensqlite_adr_sections_appear_in_expected_order() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let ordered_sections = [
        "## Context",
        "## Decision",
        "## Scope",
        "## Companion Decision",
        "## Persistence Boundary Definition",
        "## Rationale",
        "## Exception Process",
        "## Consequences",
        "## Compliance Signals",
        "## Migration Policy",
        "## Operator Verification",
    ];
    let mut last_pos = 0;
    for section in ordered_sections {
        let pos = content.find(section).unwrap_or_else(|| {
            panic!("ADR missing section: {section}");
        });
        assert!(
            pos >= last_pos,
            "Section `{section}` appears out of order (pos {pos} < last {last_pos})"
        );
        last_pos = pos;
    }
}

#[test]
fn frankensqlite_adr_references_plan_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("10.14"),
        "ADR must reference plan section 10.14"
    );
}

#[test]
fn frankensqlite_adr_has_date_field() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("Date:"),
        "ADR must include a Date field in its header"
    );
}

#[test]
fn frankensqlite_adr_has_owners_field() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("Owners:"),
        "ADR must include an Owners field in its header"
    );
}

#[test]
fn frankensqlite_adr_persistence_boundary_has_three_criteria() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let boundary_pos = content.find("## Persistence Boundary Definition").unwrap();
    let rationale_pos = content.find("## Rationale").unwrap();
    let boundary_section = &content[boundary_pos..rationale_pos];
    for n in 1..=3 {
        let marker = format!("{n}.");
        assert!(
            boundary_section.contains(&marker),
            "Persistence Boundary must list criterion {n}"
        );
    }
}

#[test]
fn frankensqlite_adr_exception_process_has_five_steps() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let exception_pos = content.find("## Exception Process").unwrap();
    let consequences_pos = content.find("## Consequences").unwrap();
    let exception_section = &content[exception_pos..consequences_pos];
    for n in 1..=5 {
        let marker = format!("{n}.");
        assert!(
            exception_section.contains(&marker),
            "Exception Process must list step {n}"
        );
    }
}

#[test]
fn frankensqlite_adr_references_repo_split_contract() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("REPO_SPLIT_CONTRACT.md"),
        "ADR must reference the repo split contract"
    );
}

#[test]
fn frankensqlite_adr_bead_references_are_well_formed() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let bead_count = content.matches("`bd-").count();
    assert!(
        bead_count >= 4,
        "ADR should reference at least 4 beads, found {bead_count}"
    );
}

#[test]
fn frankensqlite_adr_migration_policy_references_ci_script() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0004-frankensqlite-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("check_no_local_sqlite_wrappers"),
        "Migration Policy must reference CI enforcement script"
    );
}
