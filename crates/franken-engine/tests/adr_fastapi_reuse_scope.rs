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

#[test]
fn fastapi_adr_has_plan_references_field() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("Plan references:"),
        "ADR must include a Plan references field"
    );
}

#[test]
fn fastapi_adr_mentions_success_criterion() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("success criterion"),
        "ADR must reference success criterion"
    );
}

#[test]
fn fastapi_adr_mentions_fastapi_rust_path() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("/dp/fastapi_rust"),
        "ADR must reference the /dp/fastapi_rust path"
    );
}

#[test]
fn fastapi_adr_out_of_scope_mentions_internal_rpc() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let out_pos = content.find("## Out-of-Scope Interfaces").unwrap();
    let required_pos = content
        .find("## Required `fastapi_rust` Conventions")
        .unwrap();
    let out_section = &content[out_pos..required_pos];
    assert!(
        out_section.contains("Internal RPC"),
        "Out-of-Scope section must mention Internal RPC"
    );
}

#[test]
fn fastapi_adr_out_of_scope_mentions_vm_hot_path() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let out_pos = content.find("## Out-of-Scope Interfaces").unwrap();
    let required_pos = content
        .find("## Required `fastapi_rust` Conventions")
        .unwrap();
    let out_section = &content[out_pos..required_pos];
    assert!(
        out_section.contains("hot-path"),
        "Out-of-Scope section must mention VM hot-path"
    );
}

#[test]
fn fastapi_adr_consequences_mentions_positive_outcomes() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let consequences_pos = content.find("## Consequences").unwrap();
    let compliance_pos = content.find("## Compliance Signals").unwrap();
    let consequences_section = &content[consequences_pos..compliance_pos];
    let positive_count = consequences_section.matches("Positive:").count();
    assert!(
        positive_count >= 2,
        "Consequences section must have at least 2 positive outcomes, found {positive_count}"
    );
}

#[test]
fn fastapi_adr_consequences_mentions_cost() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let consequences_pos = content.find("## Consequences").unwrap();
    let compliance_pos = content.find("## Compliance Signals").unwrap();
    let consequences_section = &content[consequences_pos..compliance_pos];
    assert!(
        consequences_section.contains("Cost:"),
        "Consequences section must acknowledge a cost/tradeoff"
    );
}

#[test]
fn fastapi_adr_compliance_signals_reference_bd_3o95() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("bd-3o95"),
        "ADR compliance signals must reference bead bd-3o95"
    );
}

#[test]
fn fastapi_adr_compliance_signals_reference_bd_yqg5() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("bd-yqg5"),
        "ADR compliance signals must reference bead bd-yqg5"
    );
}

#[test]
fn fastapi_adr_review_gate_has_three_steps() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let review_pos = content.find("## Review Gate").unwrap();
    let non_goals_pos = content.find("## Non-Goals").unwrap();
    let review_section = &content[review_pos..non_goals_pos];
    for n in 1..=3 {
        let marker = format!("{n}.");
        assert!(
            review_section.contains(&marker),
            "Review Gate section must list step {n}"
        );
    }
}

#[test]
fn fastapi_adr_non_goals_mentions_runtime_internals() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let non_goals_pos = content.find("## Non-Goals").unwrap();
    let consequences_pos = content.find("## Consequences").unwrap();
    let non_goals_section = &content[non_goals_pos..consequences_pos];
    assert!(
        non_goals_section.contains("runtime internals"),
        "Non-Goals section must mention runtime internals"
    );
}

#[test]
fn fastapi_adr_convention_mentions_route_and_versioning() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let conventions_pos = content
        .find("## Required `fastapi_rust` Conventions")
        .unwrap();
    let exception_pos = content.find("## Exception Process").unwrap();
    let conventions_section = &content[conventions_pos..exception_pos];
    assert!(
        conventions_section.contains("versioning"),
        "Conventions section must mention versioning"
    );
}

#[test]
fn fastapi_adr_convention_mentions_pagination_and_filter() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let conventions_pos = content
        .find("## Required `fastapi_rust` Conventions")
        .unwrap();
    let exception_pos = content.find("## Exception Process").unwrap();
    let conventions_section = &content[conventions_pos..exception_pos];
    assert!(
        conventions_section.contains("pagination"),
        "Conventions section must mention pagination"
    );
}

#[test]
fn fastapi_adr_exception_process_mentions_time_bounded() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let exception_pos = content.find("## Exception Process").unwrap();
    let review_pos = content.find("## Review Gate").unwrap();
    let exception_section = &content[exception_pos..review_pos];
    assert!(
        exception_section.contains("time-bounded"),
        "Exception Process must state that exceptions are time-bounded"
    );
}

#[test]
fn fastapi_adr_context_mentions_sibling_repositories() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let context_pos = content.find("## Context").unwrap();
    let decision_pos = content.find("## Decision").unwrap();
    let context_section = &content[context_pos..decision_pos];
    assert!(
        context_section.contains("sibling repositories"),
        "Context section must mention sibling repositories"
    );
}

#[test]
fn fastapi_adr_title_includes_adr_number() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let first_line = content.lines().next().expect("ADR must have a first line");
    assert!(
        first_line.contains("ADR-0002"),
        "ADR title must contain its number ADR-0002"
    );
}

#[test]
fn fastapi_adr_title_mentions_reuse_scope() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let first_line = content.lines().next().expect("ADR must have a first line");
    assert!(
        first_line.contains("Reuse Scope"),
        "ADR title must mention Reuse Scope"
    );
}

#[test]
fn fastapi_adr_review_gate_mentions_divergence_exception() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let review_pos = content.find("## Review Gate").unwrap();
    let non_goals_pos = content.find("## Non-Goals").unwrap();
    let review_section = &content[review_pos..non_goals_pos];
    assert!(
        review_section.contains("diverging"),
        "Review Gate section must address divergence from the standard"
    );
}

#[test]
fn fastapi_adr_evidence_export_api_in_scope() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let in_scope_pos = content.find("## In-Scope Endpoint Classes").unwrap();
    let out_scope_pos = content.find("## Out-of-Scope Interfaces").unwrap();
    let in_scope_section = &content[in_scope_pos..out_scope_pos];
    assert!(
        in_scope_section.contains("Evidence export APIs"),
        "Evidence export APIs must appear in the In-Scope section"
    );
    assert!(
        in_scope_section.contains("pagination"),
        "Evidence export APIs entry must mention pagination"
    );
}

#[test]
fn fastapi_adr_line_endings_are_consistent() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let bytes = fs::read(&path).expect("read ADR bytes");
    let crlf_count = bytes.windows(2).filter(|w| w == b"\r\n").count();
    assert_eq!(
        crlf_count, 0,
        "ADR must use Unix line endings (no CRLF), found {crlf_count} CRLF sequences"
    );
}

#[test]
fn fastapi_adr_no_trailing_whitespace_on_any_line() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let offending: Vec<(usize, &str)> = content
        .lines()
        .enumerate()
        .filter(|(_, line)| line != &line.trim_end())
        .collect();
    assert!(
        offending.is_empty(),
        "ADR has trailing whitespace on {} line(s); first: line {}",
        offending.len(),
        offending.first().map(|(n, _)| n + 1).unwrap_or(0)
    );
}

#[test]
fn fastapi_adr_endpoint_table_columns_cover_reuse_requirement() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let in_scope_pos = content.find("## In-Scope Endpoint Classes").unwrap();
    let out_scope_pos = content.find("## Out-of-Scope Interfaces").unwrap();
    let table_section = &content[in_scope_pos..out_scope_pos];
    assert!(
        table_section.contains("Minimum reuse requirement"),
        "Endpoint table must have a 'Minimum reuse requirement' column header"
    );
}

#[test]
fn fastapi_adr_exception_process_mentions_rollback() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let exception_pos = content.find("## Exception Process").unwrap();
    let review_pos = content.find("## Review Gate").unwrap();
    let exception_section = &content[exception_pos..review_pos];
    assert!(
        exception_section.contains("rollback"),
        "Exception Process must mention rollback/remediation path"
    );
}

#[test]
fn fastapi_adr_compliance_mentions_release_checklist() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0002-fastapi-rust-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let compliance_pos = content.find("## Compliance Signals").unwrap();
    let compliance_section = &content[compliance_pos..];
    assert!(
        compliance_section.contains("Release checklist")
            || compliance_section.contains("release checklist"),
        "Compliance Signals section must mention the release checklist"
    );
}
