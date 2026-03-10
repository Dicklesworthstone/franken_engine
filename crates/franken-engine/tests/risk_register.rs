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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_risk_register() -> String {
    let path = repo_root().join("docs/RISK_REGISTER.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn parse_table_row(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect()
}

fn parse_table_by_heading(doc: &str, heading: &str) -> (Vec<String>, Vec<Vec<String>>) {
    let lines: Vec<&str> = doc.lines().collect();
    let heading_idx = lines
        .iter()
        .position(|line| line.trim() == heading)
        .unwrap_or_else(|| panic!("missing heading: {heading}"));

    let mut i = heading_idx + 1;
    while i < lines.len() && lines[i].trim().is_empty() {
        i += 1;
    }

    assert!(
        i + 1 < lines.len(),
        "table for heading `{heading}` is incomplete"
    );

    let header_line = lines[i].trim();
    let separator_line = lines[i + 1].trim();
    assert!(
        header_line.starts_with('|') && separator_line.starts_with('|'),
        "heading `{heading}` must be followed by a markdown table"
    );
    let header = parse_table_row(header_line);

    let mut rows = Vec::new();
    i += 2;
    while i < lines.len() {
        let line = lines[i].trim();
        if !line.starts_with('|') {
            break;
        }
        rows.push(parse_table_row(line));
        i += 1;
    }

    (header, rows)
}

fn is_iso_date(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let (y, m, d) = (parts[0], parts[1], parts[2]);
    y.len() == 4
        && m.len() == 2
        && d.len() == 2
        && y.chars().all(|c| c.is_ascii_digit())
        && m.chars().all(|c| c.is_ascii_digit())
        && d.chars().all(|c| c.is_ascii_digit())
}

#[test]
fn risk_register_contains_required_sections() {
    let register = read_risk_register();

    let required_sections = [
        "# FrankenEngine Program Risk Register",
        "## Risk Schema",
        "## Active Risks",
        "## Review Cadence",
        "## Phase Gate Review Log",
        "## Update Procedure",
    ];

    for section in required_sections {
        assert!(
            register.contains(section),
            "risk register must contain section: {section}"
        );
    }
}

#[test]
fn active_risk_table_has_required_schema_and_values() {
    let register = read_risk_register();
    let (header, rows) = parse_table_by_heading(&register, "## Active Risks");

    let expected_header = vec![
        "Risk ID".to_string(),
        "Title".to_string(),
        "Severity".to_string(),
        "Likelihood".to_string(),
        "Impact Summary".to_string(),
        "Countermeasure Beads".to_string(),
        "Owner".to_string(),
        "Monitor".to_string(),
        "Review Cadence".to_string(),
        "Status".to_string(),
        "Last Reviewed".to_string(),
        "Evidence".to_string(),
    ];
    assert_eq!(header, expected_header);
    assert!(!rows.is_empty(), "active risk table must not be empty");

    let valid_severity: BTreeSet<&str> = ["Critical", "High", "Medium", "Low"]
        .iter()
        .copied()
        .collect();
    let valid_likelihood: BTreeSet<&str> = ["High", "Medium", "Low"].iter().copied().collect();
    let valid_status: BTreeSet<&str> = ["Open", "Mitigating", "Accepted", "Closed"]
        .iter()
        .copied()
        .collect();
    let mut seen_ids = BTreeSet::new();

    for row in rows {
        assert_eq!(
            row.len(),
            12,
            "every active risk row must have exactly 12 columns"
        );

        let risk_id = &row[0];
        assert!(
            risk_id.starts_with("R-")
                && risk_id.len() == 5
                && risk_id[2..].chars().all(|c| c.is_ascii_digit()),
            "risk id must match R-### format: {risk_id}"
        );
        assert!(
            seen_ids.insert(risk_id.clone()),
            "risk ids must be unique; duplicate: {risk_id}"
        );
        assert!(!row[1].is_empty(), "title is required for {risk_id}");
        assert!(
            valid_severity.contains(row[2].as_str()),
            "invalid severity for {risk_id}: {}",
            row[2]
        );
        assert!(
            valid_likelihood.contains(row[3].as_str()),
            "invalid likelihood for {risk_id}: {}",
            row[3]
        );
        assert!(
            !row[4].is_empty(),
            "impact summary is required for {risk_id}"
        );
        assert!(
            row[5].contains("bd-"),
            "countermeasure beads must reference bead ids for {risk_id}"
        );
        assert!(!row[6].is_empty(), "owner is required for {risk_id}");
        assert!(!row[7].is_empty(), "monitor is required for {risk_id}");
        assert!(
            !row[8].is_empty(),
            "review cadence is required for {risk_id}"
        );
        assert!(
            valid_status.contains(row[9].as_str()),
            "invalid status for {risk_id}: {}",
            row[9]
        );
        assert!(
            is_iso_date(&row[10]),
            "last reviewed must be YYYY-MM-DD for {risk_id}: {}",
            row[10]
        );
        assert!(
            !row[11].is_empty(),
            "evidence pointer is required for {risk_id}"
        );
    }
}

#[test]
fn review_cadence_contains_weekly_phase_and_incident_checks() {
    let register = read_risk_register();
    let required_lines = [
        "- Weekly: review active risk indicators and update status/owner actions.",
        "- Per-phase-gate: complete full risk review before gate sign-off.",
        "- Per-incident: add or amend risks discovered during incident analysis.",
    ];

    for line in required_lines {
        assert!(
            register.contains(line),
            "review cadence line is required: {line}"
        );
    }
}

#[test]
fn crossed_phase_gates_require_register_review_evidence() {
    let register = read_risk_register();
    let (header, rows) = parse_table_by_heading(&register, "## Phase Gate Review Log");

    let expected_header = vec![
        "Phase".to_string(),
        "Gate Status".to_string(),
        "Gate Date".to_string(),
        "Register Review Date".to_string(),
        "Reviewer".to_string(),
        "Evidence Link".to_string(),
        "Notes".to_string(),
    ];
    assert_eq!(header, expected_header);
    assert_eq!(rows.len(), 5, "phase gate table must include phases A-E");

    let mut phases = BTreeSet::new();
    for row in rows {
        assert_eq!(row.len(), 7, "phase gate rows must have 7 columns");

        let phase = row[0].as_str();
        phases.insert(phase.to_string());
        assert!(
            ["A", "B", "C", "D", "E"].contains(&phase),
            "unknown phase in gate table: {phase}"
        );

        let gate_status = row[1].as_str();
        assert!(
            ["Pending", "Crossed"].contains(&gate_status),
            "invalid gate status for phase {phase}: {gate_status}"
        );

        if gate_status == "Crossed" {
            assert!(
                is_iso_date(row[2].as_str()),
                "crossed phase {phase} must have gate date"
            );
            assert!(
                is_iso_date(row[3].as_str()),
                "crossed phase {phase} must have register review date"
            );
            assert!(
                !row[4].eq_ignore_ascii_case("pending"),
                "crossed phase {phase} must define reviewer"
            );
            assert!(
                !row[5].eq_ignore_ascii_case("pending"),
                "crossed phase {phase} must define evidence link"
            );
        }
    }

    let expected_phases: BTreeSet<String> = ["A", "B", "C", "D", "E"]
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert_eq!(phases, expected_phases, "phase gate table must cover A-E");
}

// ---------- helper function tests ----------

#[test]
fn is_iso_date_accepts_valid_dates() {
    assert!(is_iso_date("2026-01-15"));
    assert!(is_iso_date("2025-12-31"));
    assert!(is_iso_date("2024-06-01"));
}

#[test]
fn is_iso_date_rejects_malformed_inputs() {
    assert!(!is_iso_date("not-a-date"));
    assert!(!is_iso_date("2026/01/15"));
    assert!(!is_iso_date("26-01-15"));
    assert!(!is_iso_date("2026-1-5"));
    assert!(!is_iso_date(""));
}

#[test]
fn parse_table_row_splits_pipe_separated_cells() {
    let row = parse_table_row("| A | B | C |");
    assert_eq!(row, vec!["A", "B", "C"]);
}

#[test]
fn parse_table_row_trims_whitespace() {
    let row = parse_table_row("|  spaced  |  out  |");
    assert_eq!(row, vec!["spaced", "out"]);
}

// ---------- risk content invariants ----------

#[test]
fn at_least_five_active_risks() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Active Risks");
    assert!(
        rows.len() >= 5,
        "expected at least 5 active risks, got {}",
        rows.len()
    );
}

#[test]
fn at_least_one_critical_severity_risk() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Active Risks");
    let critical_count = rows
        .iter()
        .filter(|r| r.len() > 2 && r[2] == "Critical")
        .count();
    assert!(
        critical_count >= 1,
        "expected at least one Critical severity risk"
    );
}

#[test]
fn all_risk_titles_are_unique() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Active Risks");
    let mut titles = BTreeSet::new();
    for row in &rows {
        assert!(row.len() > 1);
        assert!(
            titles.insert(row[1].clone()),
            "duplicate risk title: {}",
            row[1]
        );
    }
}

#[test]
fn risk_ids_are_sequential_starting_from_001() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Active Risks");
    for (i, row) in rows.iter().enumerate() {
        let expected = format!("R-{:03}", i + 1);
        assert_eq!(
            row[0], expected,
            "risk IDs must be sequential; row {} has {}",
            i, row[0]
        );
    }
}

#[test]
fn update_procedure_section_has_content() {
    let register = read_risk_register();
    let lines: Vec<&str> = register.lines().collect();
    let idx = lines
        .iter()
        .position(|l| l.trim() == "## Update Procedure")
        .expect("update procedure heading");
    let content_after = lines[idx + 1..]
        .iter()
        .take(10)
        .any(|l| !l.trim().is_empty());
    assert!(content_after, "update procedure section must have content");
}

#[test]
fn risk_schema_section_defines_key_fields() {
    let register = read_risk_register();
    let lines: Vec<&str> = register.lines().collect();
    let idx = lines
        .iter()
        .position(|l| l.trim() == "## Risk Schema")
        .expect("risk schema heading");
    let section_content: String = lines[idx + 1..]
        .iter()
        .take_while(|l| !l.starts_with("## "))
        .cloned()
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        section_content.contains("Risk ID"),
        "risk schema must define Risk ID field"
    );
    assert!(
        section_content.contains("Severity"),
        "risk schema must define Severity field"
    );
}

#[test]
fn risk_register_file_exists_at_expected_path() {
    let path = repo_root().join("docs/RISK_REGISTER.md");
    assert!(path.exists(), "RISK_REGISTER.md must exist at docs/");
}

#[test]
fn phase_gate_table_has_valid_gate_statuses() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Phase Gate Review Log");
    for row in &rows {
        let status = row[1].as_str();
        assert!(
            ["Pending", "Crossed"].contains(&status),
            "gate status must be Pending or Crossed, got: {status}"
        );
    }
}

#[test]
fn no_risk_has_empty_monitor_field() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Active Risks");
    for row in &rows {
        assert!(row.len() > 7);
        assert!(
            !row[7].is_empty(),
            "monitor field must not be empty for {}",
            row[0]
        );
    }
}

#[test]
fn all_risks_reference_at_least_one_bead() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Active Risks");
    for row in &rows {
        assert!(row.len() > 5);
        assert!(
            row[5].contains("bd-"),
            "countermeasure must reference bead IDs for {}",
            row[0]
        );
    }
}

#[test]
fn risk_register_has_active_risks_section() {
    let register = read_risk_register();
    assert!(register.contains("## Active Risks"));
}

#[test]
fn risk_ids_are_nonempty() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Active Risks");
    for row in &rows {
        assert!(!row[0].trim().is_empty(), "risk ID must not be empty");
    }
}

#[test]
fn risk_register_is_nonempty() {
    let register = read_risk_register();
    assert!(!register.is_empty());
}

#[test]
fn risk_register_has_more_than_50_lines() {
    let register = read_risk_register();
    assert!(register.lines().count() > 50);
}

#[test]
fn risk_register_has_phase_gate_review_log_section() {
    let register = read_risk_register();
    assert!(register.contains("## Phase Gate Review Log"));
}

#[test]
fn risk_register_deterministic_double_read() {
    let a = read_risk_register();
    let b = read_risk_register();
    assert_eq!(a, b);
}

#[test]
fn is_iso_date_rejects_extra_segments() {
    assert!(!is_iso_date("2026-01-15-00"));
    assert!(!is_iso_date("2026-01"));
}

#[test]
fn parse_table_row_handles_single_cell() {
    let row = parse_table_row("| Only |");
    assert_eq!(row, vec!["Only"]);
}

#[test]
fn parse_table_row_handles_empty_cells() {
    let row = parse_table_row("|  |  |  |");
    assert_eq!(row, vec!["", "", ""]);
}

#[test]
fn active_risk_last_reviewed_dates_are_not_in_the_future() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Active Risks");
    for row in &rows {
        assert!(row.len() > 10);
        // Quick sanity: year should be <= 2026
        let year: u32 = row[10][..4].parse().expect("year must parse");
        assert!(
            year <= 2026,
            "last_reviewed date {} seems to be in the future for {}",
            row[10],
            row[0]
        );
    }
}

#[test]
fn all_risk_evidence_fields_are_nonempty() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Active Risks");
    for row in &rows {
        assert!(row.len() > 11);
        assert!(
            !row[11].trim().is_empty(),
            "evidence pointer must not be empty for {}",
            row[0]
        );
    }
}

#[test]
fn phase_gate_phases_are_unique() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Phase Gate Review Log");
    let mut phases = BTreeSet::new();
    for row in &rows {
        assert!(
            phases.insert(row[0].clone()),
            "duplicate phase in gate table: {}",
            row[0]
        );
    }
}

#[test]
fn risk_register_contains_title_heading() {
    let register = read_risk_register();
    assert!(register.contains("# FrankenEngine Program Risk Register"));
}

#[test]
fn risk_register_has_risk_schema_section() {
    let register = read_risk_register();
    assert!(register.contains("## Risk Schema"));
}

#[test]
fn risk_register_has_update_procedure_section() {
    let register = read_risk_register();
    assert!(register.contains("## Update Procedure"));
}

#[test]
fn risk_ids_start_with_r_prefix() {
    let register = read_risk_register();
    let (_, rows) = parse_table_by_heading(&register, "## Active Risks");
    for row in &rows {
        assert!(
            row[0].starts_with("R-"),
            "risk ID should start with 'R-', got: {}",
            row[0]
        );
    }
}

#[test]
fn risk_register_has_no_duplicate_headings() {
    let register = read_risk_register();
    let headings: Vec<&str> = register.lines().filter(|l| l.starts_with("## ")).collect();
    let unique: BTreeSet<&str> = headings.iter().copied().collect();
    assert_eq!(
        headings.len(),
        unique.len(),
        "risk register should not have duplicate ## headings"
    );
}
