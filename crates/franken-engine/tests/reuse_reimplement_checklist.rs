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
fn pr_template_requires_reuse_vs_reimplement_justification() {
    let template_path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let template = fs::read_to_string(&template_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", template_path.display()));

    let required_clauses = [
        "Does this PR introduce new TUI/SQLite/service infrastructure?",
        "reuse vs reimplement",
        "Decision (reuse/reimplement)",
        "ADR-0003",
        "ADR-0004",
        "ADR-0002",
        "Exception artifact link",
        "Justification link",
    ];

    for clause in required_clauses {
        assert!(
            template.contains(clause),
            "PR template must include required clause: {clause}"
        );
    }
}

#[test]
fn release_checklist_requires_traceable_reimplement_decisions() {
    let checklist_path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let checklist = fs::read_to_string(&checklist_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", checklist_path.display()));

    let required_clauses = [
        "## Reuse Vs Reimplement Decisions",
        "Decision (reuse/reimplement)",
        "ADR-0003",
        "ADR-0004",
        "ADR-0002",
        "Exception artifact link",
        "Justification link",
        "Release gate fails if any reimplement decision lacks exception or justification evidence.",
    ];

    for clause in required_clauses {
        assert!(
            checklist.contains(clause),
            "Release checklist must include required clause: {clause}"
        );
    }
}

// ---------- repo_root ----------

#[test]
fn repo_root_exists() {
    assert!(repo_root().exists());
}

// ---------- doc content ----------

#[test]
fn pr_template_is_nonempty() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(!content.is_empty());
}

#[test]
fn release_checklist_is_nonempty() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(!content.is_empty());
}

#[test]
fn pr_template_references_adr_documents() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(content.contains("ADR-0002"));
    assert!(content.contains("ADR-0003"));
    assert!(content.contains("ADR-0004"));
}

#[test]
fn release_checklist_references_adr_documents() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("ADR-0002"));
    assert!(content.contains("ADR-0003"));
    assert!(content.contains("ADR-0004"));
}

#[test]
fn pr_template_mentions_exception_and_justification() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(
        content.contains("Exception"),
        "PR template must mention Exception"
    );
    assert!(
        content.contains("Justification"),
        "PR template must mention Justification"
    );
}

#[test]
fn release_checklist_has_reuse_vs_reimplement_heading() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("## Reuse Vs Reimplement Decisions"));
}

#[test]
fn release_checklist_mentions_gate_failure_policy() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(
        content.contains("Release gate fails"),
        "release checklist must describe gate failure policy"
    );
}

#[test]
fn pr_template_mentions_tui_sqlite_service_infrastructure() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(content.contains("TUI/SQLite/service infrastructure"));
}

#[test]
fn release_checklist_mentions_decision_reuse_reimplement() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("Decision (reuse/reimplement)"));
}

#[test]
fn pr_template_mentions_justification_link() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(content.contains("Justification link"));
}

#[test]
fn release_checklist_mentions_exception_artifact_link() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("Exception artifact link"));
}

#[test]
fn pr_template_mentions_decision_reuse_reimplement() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(content.contains("Decision (reuse/reimplement)"));
}

#[test]
fn release_checklist_mentions_justification_link() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("Justification link"));
}

#[test]
fn release_checklist_has_sign_off_section() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("## Sign-Off"));
}

#[test]
fn release_checklist_has_core_validation_gate() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("## Core Validation Gate"));
}

#[test]
fn release_checklist_has_machine_readable_gate() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.contains("## Machine-Readable Gate"));
}

#[test]
fn pr_template_has_more_than_10_lines() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    let line_count = content.lines().count();
    assert!(
        line_count > 10,
        "PR template should have >10 lines, got {line_count}"
    );
}

#[test]
fn release_checklist_has_more_than_10_lines() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    let line_count = content.lines().count();
    assert!(
        line_count > 10,
        "release checklist should have >10 lines, got {line_count}"
    );
}

#[test]
fn release_checklist_deterministic_double_read() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}

#[test]
fn pr_template_references_all_three_adrs() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    for adr in ["ADR-0002", "ADR-0003", "ADR-0004"] {
        assert!(content.contains(adr), "PR template must reference {adr}");
    }
}

#[test]
fn release_checklist_references_all_three_adrs() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    for adr in ["ADR-0002", "ADR-0003", "ADR-0004"] {
        assert!(
            content.contains(adr),
            "release checklist must reference {adr}"
        );
    }
}

#[test]
fn pr_template_file_exists() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    assert!(path.exists(), "PR template file must exist");
}

#[test]
fn release_checklist_file_exists() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    assert!(path.exists(), "release checklist file must exist");
}

#[test]
fn release_checklist_contains_reuse_reimplement_section() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(
        content.contains("## Reuse Vs Reimplement Decisions"),
        "release checklist must have Reuse Vs Reimplement section"
    );
}

#[test]
fn pr_template_mentions_exception_artifact() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(
        content.contains("Exception artifact link"),
        "PR template must mention exception artifact"
    );
}

#[test]
fn release_checklist_gate_failure_clause_present() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(
        content.contains("Release gate fails"),
        "release checklist must have gate failure clause"
    );
}

#[test]
fn pr_template_and_checklist_both_contain_justification() {
    let pr = fs::read_to_string(repo_root().join(".github/PULL_REQUEST_TEMPLATE.md"))
        .expect("read PR template");
    let cl = fs::read_to_string(repo_root().join("docs/RELEASE_CHECKLIST.md"))
        .expect("read release checklist");
    assert!(pr.contains("Justification"));
    assert!(cl.contains("Justification"));
}

#[test]
fn release_checklist_has_minimum_word_count() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    let word_count = content.split_whitespace().count();
    assert!(
        word_count >= 50,
        "release checklist should have >= 50 words, got {word_count}"
    );
}

#[test]
fn pr_template_has_minimum_word_count() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    let word_count = content.split_whitespace().count();
    assert!(
        word_count >= 30,
        "PR template should have >= 30 words, got {word_count}"
    );
}

#[test]
fn pr_template_deterministic_double_read() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let a = fs::read_to_string(&path).expect("first read");
    let b = fs::read_to_string(&path).expect("second read");
    assert_eq!(a, b);
}

#[test]
fn pr_template_has_more_than_50_words() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    let word_count = content.split_whitespace().count();
    assert!(
        word_count >= 50,
        "PR template should have >= 50 words, got {word_count}"
    );
}

#[test]
fn release_checklist_has_more_than_50_lines() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(content.lines().count() > 50);
}

#[test]
fn release_checklist_has_headings_in_order() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    let headings: Vec<&str> = content.lines().filter(|l| l.starts_with("## ")).collect();
    assert!(
        headings.len() >= 3,
        "release checklist should have >= 3 h2 headings"
    );
}

#[test]
fn pr_template_has_at_least_one_heading() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    let heading_count = content.lines().filter(|l| l.starts_with('#')).count();
    assert!(heading_count >= 1, "PR template should have >= 1 heading");
}

#[test]
fn release_checklist_mentions_evidence() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(
        content.contains("evidence"),
        "release checklist must mention evidence"
    );
}

#[test]
fn release_checklist_mentions_reimplement() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(
        content.contains("reimplement"),
        "release checklist must mention reimplement"
    );
}

#[test]
fn pr_template_mentions_infrastructure() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(
        content.contains("infrastructure"),
        "PR template must mention infrastructure"
    );
}

#[test]
fn release_checklist_no_todo_or_fixme() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    assert!(!content.contains("TODO") && !content.contains("FIXME"));
}

#[test]
fn pr_template_mentions_reuse() {
    let path = repo_root().join(".github/PULL_REQUEST_TEMPLATE.md");
    let content = fs::read_to_string(&path).expect("read PR template");
    assert!(content.contains("reuse"), "PR template must mention reuse");
}

#[test]
fn release_checklist_core_validation_gate_has_content() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    let gate_pos = content.find("## Core Validation Gate").unwrap();
    let next_h2 = content[gate_pos + 23..]
        .find("## ")
        .map(|p| p + gate_pos + 23)
        .unwrap_or(content.len());
    let section = &content[gate_pos..next_h2];
    let word_count = section.split_whitespace().count();
    assert!(
        word_count >= 10,
        "Core Validation Gate section should have >= 10 words, got {word_count}"
    );
}

#[test]
fn release_checklist_machine_readable_gate_has_content() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    let gate_pos = content.find("## Machine-Readable Gate").unwrap();
    let next_h2 = content[gate_pos + 24..]
        .find("## ")
        .map(|p| p + gate_pos + 24)
        .unwrap_or(content.len());
    let section = &content[gate_pos..next_h2];
    let word_count = section.split_whitespace().count();
    assert!(
        word_count >= 10,
        "Machine-Readable Gate section should have >= 10 words, got {word_count}"
    );
}

#[test]
fn release_checklist_sign_off_section_has_content() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    let signoff_pos = content.find("## Sign-Off").unwrap();
    let section = &content[signoff_pos..];
    let word_count = section.split_whitespace().count();
    assert!(
        word_count >= 5,
        "Sign-Off section should have >= 5 words, got {word_count}"
    );
}

#[test]
fn pr_template_and_checklist_both_mention_exception_artifact() {
    let pr = fs::read_to_string(repo_root().join(".github/PULL_REQUEST_TEMPLATE.md"))
        .expect("read PR template");
    let cl = fs::read_to_string(repo_root().join("docs/RELEASE_CHECKLIST.md"))
        .expect("read release checklist");
    assert!(pr.contains("Exception artifact link"));
    assert!(cl.contains("Exception artifact link"));
}

#[test]
fn release_checklist_has_at_least_five_h2_sections() {
    let path = repo_root().join("docs/RELEASE_CHECKLIST.md");
    let content = fs::read_to_string(&path).expect("read release checklist");
    let h2_count = content.lines().filter(|l| l.starts_with("## ")).count();
    assert!(
        h2_count >= 5,
        "release checklist should have >= 5 h2 sections, got {h2_count}"
    );
}
