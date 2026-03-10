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
fn fastapi_reuse_scope_adr_contains_required_sections() {
    let adr_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let adr = fs::read_to_string(&adr_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

    let required_sections = [
        "## In-Scope Endpoint Classes",
        "## Out-of-Scope Interfaces",
        "## Required `fastapi_rust` Conventions and Components",
        "## Exception Process",
        "## Review Gate",
    ];
    for section in required_sections {
        assert!(
            adr.contains(section),
            "ADR must contain required section: {section}"
        );
    }

    let required_endpoint_classes = [
        "Health checks",
        "Control actions (`start`/`stop`/`quarantine`)",
        "Evidence export APIs",
        "Replay control APIs",
        "Benchmark result APIs",
    ];
    for endpoint_class in required_endpoint_classes {
        assert!(
            adr.contains(endpoint_class),
            "ADR must define in-scope endpoint class `{endpoint_class}`"
        );
    }
}

#[test]
fn fastapi_adr_file_exists_and_is_nonempty() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(!content.is_empty());
}

#[test]
fn fastapi_adr_references_exception_process() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Exception Process"));
    assert!(content.contains("Review Gate"));
}

#[test]
fn fastapi_adr_references_out_of_scope() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Out-of-Scope"));
}

#[test]
fn fastapi_adr_mentions_health_checks_endpoint_class() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Health checks"));
}

#[test]
fn fastapi_adr_mentions_required_conventions() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Required `fastapi_rust` Conventions"));
}

#[test]
fn fastapi_adr_mentions_replay_and_benchmark_apis() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Replay control APIs"));
    assert!(content.contains("Benchmark result APIs"));
}

#[test]
fn fastapi_adr_status_is_accepted() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Status: Accepted"));
}

#[test]
fn fastapi_adr_defines_error_response_envelope() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Error response envelope"));
}

#[test]
fn fastapi_adr_has_context_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Context"));
}

#[test]
fn fastapi_adr_has_decision_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Decision"));
}

#[test]
fn fastapi_adr_references_related_beads() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Related beads"));
}

#[test]
fn fastapi_adr_mentions_auth_middleware() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Authentication/authorization middleware"));
}

#[test]
fn fastapi_adr_has_non_goals_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Non-Goals"));
}

#[test]
fn fastapi_adr_has_consequences_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Consequences"));
}

#[test]
fn fastapi_adr_has_compliance_signals_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Compliance Signals"));
}

#[test]
fn fastapi_adr_has_more_than_10_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let line_count = content.lines().count();
    assert!(
        line_count > 10,
        "ADR should have >10 lines, got {line_count}"
    );
}

#[test]
fn fastapi_adr_deterministic_double_read() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}

#[test]
fn fastapi_adr_mentions_control_actions() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Control actions"));
}

#[test]
fn fastapi_adr_has_in_scope_endpoint_classes_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## In-Scope Endpoint Classes"));
}

#[test]
fn fastapi_adr_has_more_than_50_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.lines().count() > 50);
}

#[test]
fn fastapi_adr_file_path_exists() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    assert!(path.exists());
}

#[test]
fn fastapi_adr_word_count_minimum() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let word_count = content.split_whitespace().count();
    assert!(
        word_count >= 200,
        "ADR should have at least 200 words for adequate specification, got {word_count}"
    );
}

#[test]
fn fastapi_adr_sections_appear_in_expected_order() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let ordered_sections = [
        "## Context",
        "## Decision",
        "## In-Scope Endpoint Classes",
        "## Out-of-Scope Interfaces",
        "## Required `fastapi_rust` Conventions",
        "## Exception Process",
        "## Review Gate",
        "## Non-Goals",
        "## Consequences",
        "## Compliance Signals",
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
fn fastapi_adr_references_plan_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("10.14"),
        "ADR must reference plan section 10.14"
    );
}

#[test]
fn fastapi_adr_has_date_field() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("Date:"),
        "ADR must include a Date field in its header"
    );
}

#[test]
fn fastapi_adr_has_owners_field() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("Owners:"),
        "ADR must include an Owners field in its header"
    );
}

#[test]
fn fastapi_adr_endpoint_table_has_pipe_delimiters() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let in_scope_pos = content.find("## In-Scope Endpoint Classes").unwrap();
    let out_scope_pos = content.find("## Out-of-Scope Interfaces").unwrap();
    let table_section = &content[in_scope_pos..out_scope_pos];
    let pipe_lines: Vec<&str> = table_section
        .lines()
        .filter(|l| l.starts_with('|'))
        .collect();
    assert!(
        pipe_lines.len() >= 6,
        "Endpoint table should have header + separator + 5 rows, got {} pipe lines",
        pipe_lines.len()
    );
}

#[test]
fn fastapi_adr_five_convention_categories() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let conventions_pos = content
        .find("## Required `fastapi_rust` Conventions")
        .unwrap();
    let exception_pos = content.find("## Exception Process").unwrap();
    let conventions_section = &content[conventions_pos..exception_pos];
    for n in 1..=5 {
        let marker = format!("{n}.");
        assert!(
            conventions_section.contains(&marker),
            "Conventions section must list item {n}"
        );
    }
}

#[test]
fn fastapi_adr_exception_process_has_five_steps() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let exception_pos = content.find("## Exception Process").unwrap();
    let review_pos = content.find("## Review Gate").unwrap();
    let exception_section = &content[exception_pos..review_pos];
    for n in 1..=5 {
        let marker = format!("{n}.");
        assert!(
            exception_section.contains(&marker),
            "Exception Process must list step {n}"
        );
    }
}

#[test]
fn fastapi_adr_bead_references_are_well_formed() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let bead_count = content.matches("`bd-").count();
    assert!(
        bead_count >= 3,
        "ADR should reference at least 3 beads, found {bead_count}"
    );
}
