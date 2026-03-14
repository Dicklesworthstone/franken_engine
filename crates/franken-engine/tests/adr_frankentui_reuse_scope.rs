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
fn frankentui_reuse_scope_adr_contains_required_sections() {
    let adr_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let adr = fs::read_to_string(&adr_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

    let required_sections = [
        "## Decision",
        "## Scope",
        "## Rationale",
        "## Exception Process",
        "## Advanced TUI Boundary Definition",
    ];
    for section in required_sections {
        assert!(
            adr.contains(section),
            "ADR must contain required section: {section}"
        );
    }

    let required_scope_items = [
        "Operator dashboards",
        "Incident/replay viewers",
        "Policy explanation cards and control panels",
        "Simple CLI output",
        "/dp/frankentui",
    ];
    for item in required_scope_items {
        assert!(
            adr.contains(item),
            "ADR must include required scope/boundary item `{item}`"
        );
    }
}

#[test]
fn frankentui_adr_file_exists_and_is_nonempty() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(!content.is_empty());
}

#[test]
fn frankentui_adr_references_advanced_tui_boundary() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Advanced TUI Boundary"));
}

#[test]
fn frankentui_adr_references_operator_dashboards() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Operator dashboards"));
}

#[test]
fn frankentui_adr_mentions_incident_replay_viewers() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Incident/replay viewers"));
}

#[test]
fn frankentui_adr_mentions_exception_process() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Exception Process"));
}

#[test]
fn frankentui_adr_mentions_simple_cli_output_boundary() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Simple CLI output"));
}

#[test]
fn frankentui_adr_status_is_accepted() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Status: Accepted"));
}

#[test]
fn frankentui_adr_references_repo_split_contract() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("REPO_SPLIT_CONTRACT.md"));
}

#[test]
fn frankentui_adr_has_rationale_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Rationale"));
}

#[test]
fn frankentui_adr_has_decision_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Decision"));
}

#[test]
fn frankentui_adr_references_related_beads() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Related beads"));
}

#[test]
fn frankentui_adr_mentions_policy_explanation_cards() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("Policy explanation cards"));
}

#[test]
fn frankentui_adr_has_consequences_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Consequences"));
}

#[test]
fn frankentui_adr_has_compliance_signals_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Compliance Signals"));
}

#[test]
fn frankentui_adr_has_scope_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Scope"));
}

#[test]
fn frankentui_adr_has_more_than_10_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let line_count = content.lines().count();
    assert!(
        line_count > 10,
        "ADR should have >10 lines, got {line_count}"
    );
}

#[test]
fn frankentui_adr_deterministic_double_read() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}

#[test]
fn frankentui_adr_mentions_context_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Context"));
}

#[test]
fn frankentui_adr_has_exception_process_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.contains("## Exception Process"));
}

#[test]
fn frankentui_adr_has_more_than_50_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(content.lines().count() > 50);
}

#[test]
fn frankentui_adr_file_path_is_valid() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    assert!(path.exists());
}

#[test]
fn frankentui_adr_word_count_minimum() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let word_count = content.split_whitespace().count();
    assert!(
        word_count >= 200,
        "ADR should have at least 200 words for adequate specification, got {word_count}"
    );
}

#[test]
fn frankentui_adr_sections_appear_in_expected_order() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let ordered_sections = [
        "## Context",
        "## Decision",
        "## Scope",
        "## Advanced TUI Boundary Definition",
        "## Rationale",
        "## Exception Process",
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
fn frankentui_adr_references_plan_section() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("10.14"),
        "ADR must reference plan section 10.14"
    );
}

#[test]
fn frankentui_adr_has_date_field() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("Date:"),
        "ADR must include a Date field in its header"
    );
}

#[test]
fn frankentui_adr_has_owners_field() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("Owners:"),
        "ADR must include an Owners field in its header"
    );
}

#[test]
fn frankentui_adr_boundary_definition_has_three_criteria() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let boundary_pos = content.find("## Advanced TUI Boundary Definition").unwrap();
    let rationale_pos = content.find("## Rationale").unwrap();
    let boundary_section = &content[boundary_pos..rationale_pos];
    for n in 1..=3 {
        let marker = format!("{n}.");
        assert!(
            boundary_section.contains(&marker),
            "TUI Boundary Definition must list criterion {n}"
        );
    }
}

#[test]
fn frankentui_adr_exception_process_has_six_steps() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let exception_pos = content.find("## Exception Process").unwrap();
    let consequences_pos = content.find("## Consequences").unwrap();
    let exception_section = &content[exception_pos..consequences_pos];
    for n in 1..=6 {
        let marker = format!("{n}.");
        assert!(
            exception_section.contains(&marker),
            "Exception Process must list step {n}"
        );
    }
}

#[test]
fn frankentui_adr_bead_references_are_well_formed() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let bead_count = content.matches("`bd-").count();
    assert!(
        bead_count >= 4,
        "ADR should reference at least 4 beads, found {bead_count}"
    );
}

#[test]
fn frankentui_adr_exception_artifact_path_pattern() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("ADR-EXCEPTION-TUI-"),
        "ADR must define the exception artifact path pattern"
    );
}

#[test]
fn frankentui_adr_mentions_interactive_beyond_single_command() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    assert!(
        content.contains("Interactive beyond single-command"),
        "Boundary definition must include interactivity criterion"
    );
}

// --- enrichment tests (batch 1) ---

#[test]
fn frankentui_adr_heading_count_matches_expected() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let h2_count = content.lines().filter(|l| l.starts_with("## ")).count();
    // Context, Decision, Scope, Advanced TUI Boundary Definition,
    // Rationale, Exception Process, Consequences, Compliance Signals
    assert_eq!(
        h2_count, 8,
        "ADR should have exactly 8 level-2 headings, got {h2_count}"
    );
}

#[test]
fn frankentui_adr_has_exactly_one_h1_title() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let h1_count = content
        .lines()
        .filter(|l| l.starts_with("# ") && !l.starts_with("## "))
        .count();
    assert_eq!(
        h1_count, 1,
        "ADR must have exactly one H1 title, got {h1_count}"
    );
}

#[test]
fn frankentui_adr_no_todo_or_fixme_markers() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let upper = content.to_uppercase();
    assert!(!upper.contains("TODO"), "ADR must not contain TODO markers");
    assert!(
        !upper.contains("FIXME"),
        "ADR must not contain FIXME markers"
    );
    assert!(!upper.contains("HACK"), "ADR must not contain HACK markers");
}

#[test]
fn frankentui_adr_bytes_roundtrip_identical() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let bytes = fs::read(&path).expect("read bytes");
    let as_string = String::from_utf8(bytes.clone()).expect("valid utf-8");
    let back_to_bytes = as_string.into_bytes();
    assert_eq!(bytes, back_to_bytes, "bytes roundtrip must be lossless");
}

#[test]
fn frankentui_adr_no_trailing_whitespace_on_content_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    for (i, line) in content.lines().enumerate() {
        if !line.is_empty() {
            assert!(
                !line.ends_with(' '),
                "Line {} has trailing whitespace: {:?}",
                i + 1,
                line
            );
        }
    }
}

#[test]
fn frankentui_adr_cross_reference_repo_split_contract_exists() {
    let adr_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&adr_path).expect("read ADR");
    assert!(content.contains("REPO_SPLIT_CONTRACT.md"));

    // Verify the referenced file actually exists at the expected location.
    let repo_split =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/REPO_SPLIT_CONTRACT.md");
    assert!(
        repo_split.exists(),
        "Cross-referenced REPO_SPLIT_CONTRACT.md must exist at {}",
        repo_split.display()
    );
}

#[test]
fn frankentui_adr_cross_reference_agents_md_exists() {
    let adr_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&adr_path).expect("read ADR");
    assert!(
        content.contains("AGENTS.md"),
        "ADR must reference AGENTS.md"
    );

    let agents_md = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../AGENTS.md");
    assert!(
        agents_md.exists(),
        "Cross-referenced AGENTS.md must exist at {}",
        agents_md.display()
    );
}

#[test]
fn frankentui_adr_scope_section_lists_in_scope_and_out_of_scope() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let scope_pos = content.find("## Scope").unwrap();
    let next_section_pos = content[scope_pos + 8..]
        .find("## ")
        .map(|p| p + scope_pos + 8)
        .unwrap();
    let scope_section = &content[scope_pos..next_section_pos];
    assert!(
        scope_section.contains("In scope"),
        "Scope section must define 'In scope' items"
    );
    assert!(
        scope_section.contains("Out of scope"),
        "Scope section must define 'Out of scope' items"
    );
}

#[test]
fn frankentui_adr_in_scope_has_at_least_four_bullet_items() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let scope_pos = content.find("## Scope").unwrap();
    let next_section_pos = content[scope_pos + 8..]
        .find("## ")
        .map(|p| p + scope_pos + 8)
        .unwrap();
    let scope_section = &content[scope_pos..next_section_pos];
    let bullet_count = scope_section
        .lines()
        .filter(|l| l.starts_with("- "))
        .count();
    assert!(
        bullet_count >= 4,
        "Scope section must have at least 4 bullet items, got {bullet_count}"
    );
}

#[test]
fn frankentui_adr_consequences_has_positive_and_cost_entries() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let cons_pos = content.find("## Consequences").unwrap();
    let next_pos = content[cons_pos + 15..]
        .find("## ")
        .map(|p| p + cons_pos + 15)
        .unwrap_or(content.len());
    let consequences = &content[cons_pos..next_pos];
    let positive_count = consequences.matches("Positive").count();
    let cost_count = consequences.matches("Cost").count();
    assert!(
        positive_count >= 2,
        "Consequences must list at least 2 positive entries, got {positive_count}"
    );
    assert!(
        cost_count >= 1,
        "Consequences must list at least 1 cost entry, got {cost_count}"
    );
}

#[test]
fn frankentui_adr_compliance_signals_reference_beads() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let comp_pos = content.find("## Compliance Signals").unwrap();
    let compliance_section = &content[comp_pos..];
    let bead_count = compliance_section.matches("`bd-").count();
    assert!(
        bead_count >= 2,
        "Compliance Signals section must reference at least 2 beads, got {bead_count}"
    );
}

#[test]
fn frankentui_adr_exception_artifact_path_includes_template() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    // The exception artifact template path must be a markdown file in the adr/exceptions dir.
    assert!(
        content.contains("docs/adr/exceptions/ADR-EXCEPTION-TUI-"),
        "Exception artifact must specify full path template"
    );
    assert!(
        content.contains(".md"),
        "Exception artifact must be a markdown file"
    );
}

#[test]
fn frankentui_adr_exception_process_requires_status_approved() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let exception_pos = content.find("## Exception Process").unwrap();
    let consequences_pos = content.find("## Consequences").unwrap();
    let exception_section = &content[exception_pos..consequences_pos];
    assert!(
        exception_section.contains("Status: Approved"),
        "Exception artifact template must include Status: Approved"
    );
    assert!(
        exception_section.contains("Scope:"),
        "Exception artifact template must include Scope: lines"
    );
    assert!(
        exception_section.contains("expiry date"),
        "Exception process must mention an expiry date requirement"
    );
}

#[test]
fn frankentui_adr_metadata_header_is_within_first_10_lines() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let first_10: String = content.lines().take(10).collect::<Vec<_>>().join("\n");
    assert!(
        first_10.contains("Status:"),
        "Status field must appear in first 10 lines"
    );
    assert!(
        first_10.contains("Date:"),
        "Date field must appear in first 10 lines"
    );
    assert!(
        first_10.contains("Owners:"),
        "Owners field must appear in first 10 lines"
    );
    assert!(
        first_10.contains("Related beads:"),
        "Related beads field must appear in first 10 lines"
    );
}

#[test]
fn frankentui_adr_dp_frankentui_canonical_path_appears_in_decision_and_scope() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/adr/ADR-0003-frankentui-reuse-scope.md");
    let content = fs::read_to_string(&path).expect("read ADR");
    let decision_pos = content.find("## Decision").unwrap();
    let scope_pos = content.find("## Scope").unwrap();
    let boundary_pos = content.find("## Advanced TUI Boundary Definition").unwrap();
    let decision_section = &content[decision_pos..scope_pos];
    let scope_section = &content[scope_pos..boundary_pos];
    assert!(
        decision_section.contains("/dp/frankentui"),
        "Decision section must reference /dp/frankentui canonical path"
    );
    assert!(
        scope_section.contains("/dp/frankentui"),
        "Scope section must reference /dp/frankentui canonical path"
    );
}
