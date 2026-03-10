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

fn read_spec() -> String {
    let path = repo_root().join("docs/EXTENSION_HEAVY_BENCHMARK_SUITE_V1.md");
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

#[test]
fn benchmark_spec_contains_required_sections() {
    let spec = read_spec();
    let required_sections = [
        "## Required Benchmark Families",
        "## Threat Scenario Matrix (Normative)",
        "## Scale Profile Matrix (Normative Defaults)",
        "## Per-Case Publication Requirements",
        "## Behavior-Equivalence Hard Gates",
        "## Scoring Formula (Binding)",
        "## Transparent Scoring Governance",
        "## Fairness and Denominator Contract",
        "## Required Metric Families",
        "## Workload and Result Schema Contract",
        "## Structured Event Contract",
        "## Reproducibility and Verifier Workflow",
        "## CI Publication Gate",
        "## Failure Semantics and Rollback",
        "## Publication and Standardization Contract",
        "## Independent Verifier Onboarding",
    ];

    for section in required_sections {
        assert!(
            spec.contains(section),
            "benchmark spec must include section: {section}"
        );
    }
}

#[test]
fn family_table_lists_all_required_families_with_required_profiles() {
    let spec = read_spec();
    let (header, rows) = parse_table_by_heading(&spec, "## Required Benchmark Families");

    let expected_header = vec![
        "Family ID".to_string(),
        "Purpose".to_string(),
        "Required Profiles".to_string(),
    ];
    assert_eq!(header, expected_header);
    assert_eq!(
        rows.len(),
        5,
        "exactly five benchmark families are required"
    );

    let expected_families: BTreeSet<String> = [
        "`boot-storm`",
        "`capability-churn`",
        "`mixed-cpu-io-agent-mesh`",
        "`reload-revoke-churn`",
        "`adversarial-noise-under-load`",
    ]
    .iter()
    .map(|item| (*item).to_string())
    .collect();

    let observed_families: BTreeSet<String> = rows.iter().map(|row| row[0].clone()).collect();
    assert_eq!(
        observed_families, expected_families,
        "family table must include the normative five families"
    );

    for row in rows {
        assert_eq!(row.len(), 3, "family rows must have 3 columns");
        assert!(
            row[2].contains("`S`") && row[2].contains("`M`") && row[2].contains("`L`"),
            "every family must require S/M/L profiles"
        );
    }
}

#[test]
fn scale_profile_matrix_includes_s_m_l_defaults() {
    let spec = read_spec();
    let (header, rows) =
        parse_table_by_heading(&spec, "## Scale Profile Matrix (Normative Defaults)");

    let expected_header = vec![
        "Profile".to_string(),
        "Extension Count".to_string(),
        "Event Rate (events/sec)".to_string(),
        "Dependency Graph Size".to_string(),
        "Policy Complexity Tier".to_string(),
    ];
    assert_eq!(header, expected_header);
    assert_eq!(rows.len(), 3, "scale matrix must include S/M/L rows");

    let expected_profiles: BTreeSet<String> = ["`S`", "`M`", "`L`"]
        .iter()
        .map(|item| (*item).to_string())
        .collect();
    let observed_profiles: BTreeSet<String> = rows.iter().map(|row| row[0].clone()).collect();
    assert_eq!(observed_profiles, expected_profiles);
}

#[test]
fn scoring_formula_and_threshold_clauses_are_declared() {
    let spec = read_spec();
    let required_fragments = [
        "score(engine, baseline) = exp(sum_i w_i * ln(throughput_engine_i / throughput_baseline_i))",
        "sum_i w_i = 1",
        "score_vs_node >= 3.0",
        "score_vs_bun >= 3.0",
    ];

    for fragment in required_fragments {
        assert!(
            spec.contains(fragment),
            "scoring section must contain: {fragment}"
        );
    }
}

#[test]
fn required_metric_families_and_event_keys_are_declared() {
    let spec = read_spec();
    let metric_fragments = [
        "throughput/latency under extension-heavy load",
        "containment quality",
        "replay correctness",
        "revocation/quarantine propagation",
        "adversarial resilience",
        "information-flow security",
        "security-proof specialization uplift",
    ];
    for fragment in metric_fragments {
        assert!(
            spec.contains(fragment),
            "required metric family missing: {fragment}"
        );
    }

    let event_keys = [
        "`trace_id`",
        "`decision_id`",
        "`policy_id`",
        "`component`",
        "`event`",
        "`outcome`",
        "`error_code`",
    ];
    for key in event_keys {
        assert!(spec.contains(key), "structured event key missing: {key}");
    }
}

#[test]
fn threat_scenario_matrix_declares_required_attack_categories() {
    let spec = read_spec();
    let required_scenarios = [
        "credential theft",
        "privilege escalation",
        "data exfiltration",
        "policy evasion",
        "supply-chain compromise",
    ];

    for scenario in required_scenarios {
        assert!(
            spec.contains(scenario),
            "threat scenario matrix missing scenario category fragment: {scenario}"
        );
    }

    let required_fields = [
        "`attack_category`",
        "`scenario_id`",
        "`expected_detection_outcome`",
        "`expected_containment_outcome`",
        "`expected_latency_bound_ms`",
        "`corpus_checksum_sha256`",
    ];
    for field in required_fields {
        assert!(
            spec.contains(field),
            "threat scenario matrix missing required field: {field}"
        );
    }
}

#[test]
fn verifier_workflow_and_bundle_requirements_are_explicit() {
    let spec = read_spec();
    let required_items = [
        "`env.json`",
        "`manifest.json`",
        "`repro.lock`",
        "`commands.txt`",
        "`results.json`",
        "frankenctl benchmark verify --bundle",
        "CI must fail publication",
    ];

    for item in required_items {
        assert!(
            spec.contains(item),
            "verifier/bundle requirement missing: {item}"
        );
    }
}

#[test]
fn transparent_scoring_and_publication_rules_are_explicit() {
    let spec = read_spec();
    let required_fragments = [
        "Published weights are mandatory",
        "No hidden or post-hoc adjustments",
        "version bump and changelog entry",
        "public review notes",
        "docs/CLAIM_LANGUAGE_POLICY.md",
        "`submission_id`",
        "`benchmark_version`",
        "`runtime_versions`",
        "`score_bundle_digest`",
        "`verifier_report_digest`",
    ];

    for fragment in required_fragments {
        assert!(
            spec.contains(fragment),
            "missing transparent scoring/publication requirement fragment: {fragment}"
        );
    }
}

#[test]
fn benchmark_spec_file_exists_and_is_nonempty() {
    let spec = read_spec();
    assert!(!spec.is_empty());
}

#[test]
fn parse_table_row_splits_correctly() {
    let row = "| a | b | c |";
    let cells = parse_table_row(row);
    assert_eq!(cells, vec!["a", "b", "c"]);
}

#[test]
fn parse_table_row_handles_empty_cells() {
    let row = "| a | | c |";
    let cells = parse_table_row(row);
    assert_eq!(cells.len(), 3);
    assert_eq!(cells[1], "");
}

#[test]
fn parse_table_by_heading_finds_families() {
    let spec = read_spec();
    let (header, rows) = parse_table_by_heading(&spec, "## Required Benchmark Families");
    assert!(!header.is_empty());
    assert!(!rows.is_empty());
    // All rows should have same column count as header
    for row in &rows {
        assert_eq!(row.len(), header.len());
    }
}

#[test]
fn benchmark_spec_deterministic_double_read() {
    let a = read_spec();
    let b = read_spec();
    assert_eq!(a, b);
}

#[test]
fn ci_publication_gate_declares_failure_and_blocking_criteria() {
    let spec = read_spec();
    for fragment in ["## CI Publication Gate", "CI must fail publication"] {
        assert!(
            spec.contains(fragment),
            "CI publication gate missing: {fragment}"
        );
    }
}

#[test]
fn failure_semantics_section_mentions_rollback() {
    let spec = read_spec();
    assert!(
        spec.contains("## Failure Semantics and Rollback"),
        "failure semantics section must exist"
    );
    assert!(
        spec.contains("rollback") || spec.contains("Rollback"),
        "failure semantics must discuss rollback"
    );
}

#[test]
fn benchmark_spec_mentions_fairness_contract() {
    let spec = read_spec();
    assert!(spec.contains("## Fairness and Denominator Contract"));
}

#[test]
fn benchmark_spec_mentions_reproducibility_workflow() {
    let spec = read_spec();
    assert!(spec.contains("## Reproducibility and Verifier Workflow"));
}

#[test]
fn benchmark_spec_workload_schema_section_exists() {
    let spec = read_spec();
    assert!(spec.contains("## Workload and Result Schema Contract"));
}

#[test]
fn independent_verifier_onboarding_section_exists_with_content() {
    let spec = read_spec();
    assert!(
        spec.contains("## Independent Verifier Onboarding"),
        "verifier onboarding section must exist"
    );
    // Should mention the verification process
    assert!(
        spec.contains("verify") || spec.contains("verifier") || spec.contains("Verifier"),
        "verifier onboarding must discuss verification"
    );
}

#[test]
fn benchmark_spec_has_more_than_100_lines() {
    let spec = read_spec();
    assert!(spec.lines().count() > 100, "spec should be substantial");
}

#[test]
fn benchmark_spec_deterministic_triple_read() {
    let a = read_spec();
    let b = read_spec();
    let c = read_spec();
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[test]
fn parse_table_row_preserves_order() {
    let row = parse_table_row("| Z | A | M |");
    assert_eq!(row, vec!["Z", "A", "M"]);
}

#[test]
fn benchmark_spec_mentions_extension() {
    let spec = read_spec();
    assert!(
        spec.contains("extension") || spec.contains("Extension"),
        "spec should mention extensions"
    );
}

#[test]
fn parse_table_row_handles_single_cell() {
    let row = parse_table_row("| only |");
    assert_eq!(row, vec!["only"]);
}

#[test]
fn benchmark_spec_file_path_exists() {
    let path = repo_root().join("docs/EXTENSION_HEAVY_BENCHMARK_SUITE_V1.md");
    assert!(path.exists());
}

// ---------- Additional spec invariant and parsing tests ----------

#[test]
fn scale_profile_matrix_has_monotonically_increasing_extension_counts() {
    let spec = read_spec();
    let (_header, rows) =
        parse_table_by_heading(&spec, "## Scale Profile Matrix (Normative Defaults)");

    // Build a map from profile name to extension count
    let mut profile_counts: Vec<(&str, u64)> = Vec::new();
    let order = ["`S`", "`M`", "`L`"];
    for profile_name in &order {
        let row = rows
            .iter()
            .find(|r| r[0] == *profile_name)
            .unwrap_or_else(|| panic!("missing profile {profile_name}"));
        let count_str = row[1].trim().replace([',', '_'], "");
        let count: u64 = count_str.parse().unwrap_or_else(|_| {
            panic!("extension count for {profile_name} must be numeric: '{count_str}'")
        });
        profile_counts.push((profile_name, count));
    }

    // S < M < L
    assert!(
        profile_counts[0].1 < profile_counts[1].1,
        "S extension count must be less than M"
    );
    assert!(
        profile_counts[1].1 < profile_counts[2].1,
        "M extension count must be less than L"
    );
}

#[test]
fn per_case_publication_requirements_section_has_content() {
    let spec = read_spec();
    let section_marker = "## Per-Case Publication Requirements";
    let idx = spec
        .find(section_marker)
        .expect("must contain Per-Case Publication Requirements section");
    let after_section = &spec[idx + section_marker.len()..];
    // Find next section or end of doc
    let next_section = after_section.find("\n## ").unwrap_or(after_section.len());
    let section_body = &after_section[..next_section];
    assert!(
        section_body.len() > 50,
        "Per-Case Publication Requirements section must have substantive content"
    );
}

#[test]
fn behavior_equivalence_hard_gates_section_mentions_gate_criteria() {
    let spec = read_spec();
    let section_marker = "## Behavior-Equivalence Hard Gates";
    assert!(
        spec.contains(section_marker),
        "behavior equivalence section must exist"
    );
    // Hard gates section should reference equivalence checking and failure
    let idx = spec.find(section_marker).unwrap();
    let section_tail = &spec[idx..std::cmp::min(idx + 2000, spec.len())];
    assert!(
        section_tail.contains("equivalence") || section_tail.contains("Equivalence"),
        "behavior equivalence section must discuss equivalence"
    );
}

#[test]
fn family_table_rows_all_have_nonempty_purpose() {
    let spec = read_spec();
    let (_header, rows) = parse_table_by_heading(&spec, "## Required Benchmark Families");
    for row in &rows {
        assert!(
            !row[1].trim().is_empty(),
            "family {} must have a non-empty purpose",
            row[0]
        );
    }
}

#[test]
fn parse_table_row_handles_leading_trailing_whitespace_in_cells() {
    let row = parse_table_row("|  spaced  |  padded  |  value  |");
    assert_eq!(row, vec!["spaced", "padded", "value"]);
}

#[test]
fn benchmark_spec_mentions_throughput() {
    let spec = read_spec();
    let lower = spec.to_lowercase();
    assert!(
        lower.contains("throughput"),
        "spec should mention throughput"
    );
}

#[test]
fn benchmark_spec_mentions_latency() {
    let spec = read_spec();
    let lower = spec.to_lowercase();
    assert!(lower.contains("latency"), "spec should mention latency");
}

#[test]
fn benchmark_spec_mentions_scoring() {
    let spec = read_spec();
    let lower = spec.to_lowercase();
    assert!(lower.contains("scor"), "spec should mention scoring");
}
