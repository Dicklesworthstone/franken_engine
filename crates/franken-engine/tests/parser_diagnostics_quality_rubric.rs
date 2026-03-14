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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, ParseBudgetKind, ParseDiagnosticEnvelope, ParseErrorCode, ParserBudget,
    ParserOptions,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ScoreDimension {
    dimension_id: String,
    description: String,
    weight_millionths: u32,
}

#[derive(Debug, Deserialize)]
struct BudgetOverride {
    max_source_bytes: u64,
    max_token_count: u64,
    max_recursion_depth: u64,
}

#[derive(Debug, Deserialize)]
struct RubricCase {
    case_id: String,
    family_id: String,
    goal: String,
    source: String,
    expected_error_code: String,
    expected_diagnostic_code: String,
    expected_budget_kind: Option<String>,
    require_span: bool,
    budget_override: Option<BudgetOverride>,
    replay_command: String,
}

#[derive(Debug, Deserialize)]
struct DiagnosticsQualityRubricFixture {
    schema_version: String,
    rubric_version: String,
    max_allowed_regression_millionths: u32,
    score_dimensions: Vec<ScoreDimension>,
    baseline_scores_millionths: BTreeMap<String, u32>,
    structured_log_required_keys: Vec<String>,
    cases: Vec<RubricCase>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaseEvaluation {
    case_id: String,
    family_id: String,
    expected_error_code: String,
    diagnostic_hash: String,
    budget_kind: Option<String>,
    score_by_dimension: BTreeMap<String, u32>,
    composite_score_millionths: u32,
    replay_command: String,
}

fn load_fixture() -> DiagnosticsQualityRubricFixture {
    let path = Path::new("tests/fixtures/parser_diagnostics_quality_rubric_v1.json");
    let bytes = fs::read(path).expect("read diagnostics quality fixture");
    serde_json::from_slice(&bytes).expect("deserialize diagnostics quality fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_DIAGNOSTICS_QUALITY_RUBRIC.md");
    fs::read_to_string(path).expect("read diagnostics quality rubric doc")
}

fn parse_goal(raw: &str) -> ParseGoal {
    match raw {
        "script" => ParseGoal::Script,
        "module" => ParseGoal::Module,
        other => panic!("unknown parse goal: {other}"),
    }
}

fn parse_error_code(raw: &str) -> ParseErrorCode {
    match raw {
        "empty_source" => ParseErrorCode::EmptySource,
        "invalid_goal" => ParseErrorCode::InvalidGoal,
        "unsupported_syntax" => ParseErrorCode::UnsupportedSyntax,
        "io_read_failed" => ParseErrorCode::IoReadFailed,
        "invalid_utf8" => ParseErrorCode::InvalidUtf8,
        "source_too_large" => ParseErrorCode::SourceTooLarge,
        "budget_exceeded" => ParseErrorCode::BudgetExceeded,
        other => panic!("unknown parse error code: {other}"),
    }
}

fn parse_budget_kind(raw: &str) -> ParseBudgetKind {
    match raw {
        "source_bytes" => ParseBudgetKind::SourceBytes,
        "token_count" => ParseBudgetKind::TokenCount,
        "recursion_depth" => ParseBudgetKind::RecursionDepth,
        other => panic!("unknown budget kind: {other}"),
    }
}

fn parser_options(case: &RubricCase) -> ParserOptions {
    let mut options = ParserOptions::default();
    if let Some(budget) = case.budget_override.as_ref() {
        options.budget = ParserBudget {
            max_source_bytes: budget.max_source_bytes,
            max_token_count: budget.max_token_count,
            max_recursion_depth: budget.max_recursion_depth,
        };
    }
    options
}

fn score_dimension(
    dimension_id: &str,
    case: &RubricCase,
    envelope: &ParseDiagnosticEnvelope,
    expected_error_code: ParseErrorCode,
    diagnostic_hash: &str,
) -> u32 {
    match dimension_id {
        "location_precision" => {
            if envelope.span.is_some() {
                1_000_000
            } else if case.require_span {
                0
            } else {
                500_000
            }
        }
        "message_clarity" => {
            if envelope.message_template.trim().len() >= 8 {
                1_000_000
            } else {
                0
            }
        }
        "actionable_hints" => {
            if envelope.message_template.split_whitespace().count() >= 3 {
                1_000_000
            } else {
                250_000
            }
        }
        "deterministic_wording" => {
            if envelope.parse_error_code == expected_error_code
                && envelope.diagnostic_code == case.expected_diagnostic_code
                && diagnostic_hash.starts_with("sha256:")
            {
                1_000_000
            } else {
                0
            }
        }
        other => panic!("unknown rubric dimension: {other}"),
    }
}

fn weighted_composite_score(
    score_by_dimension: &BTreeMap<String, u32>,
    dimensions: &[ScoreDimension],
) -> u32 {
    let mut numerator = 0_u128;
    for dimension in dimensions {
        let score = score_by_dimension
            .get(&dimension.dimension_id)
            .unwrap_or_else(|| panic!("missing score for dimension `{}`", dimension.dimension_id));
        numerator = numerator.saturating_add(
            u128::from(*score).saturating_mul(u128::from(dimension.weight_millionths)),
        );
    }
    (numerator / 1_000_000_u128) as u32
}

fn evaluate_case(
    parser: &CanonicalEs2020Parser,
    fixture_case: &RubricCase,
    fixture: &DiagnosticsQualityRubricFixture,
) -> CaseEvaluation {
    let goal = parse_goal(fixture_case.goal.as_str());
    let options = parser_options(fixture_case);
    let expected_error_code = parse_error_code(fixture_case.expected_error_code.as_str());

    let parse_error = parser
        .parse_with_options(fixture_case.source.as_str(), goal, &options)
        .expect_err("fixture case should produce parser diagnostic");

    assert_eq!(
        parse_error.code, expected_error_code,
        "unexpected parse error code for case `{}`",
        fixture_case.case_id
    );

    let envelope = parse_error.normalized_diagnostic();
    assert_eq!(
        envelope.diagnostic_code, fixture_case.expected_diagnostic_code,
        "unexpected diagnostic code for case `{}`",
        fixture_case.case_id
    );

    let expected_budget_kind = fixture_case
        .expected_budget_kind
        .as_deref()
        .map(parse_budget_kind);
    assert_eq!(
        envelope.budget_kind, expected_budget_kind,
        "unexpected budget kind for case `{}`",
        fixture_case.case_id
    );

    let diagnostic_hash = envelope.canonical_hash();
    let score_by_dimension = fixture
        .score_dimensions
        .iter()
        .map(|dimension| {
            (
                dimension.dimension_id.clone(),
                score_dimension(
                    dimension.dimension_id.as_str(),
                    fixture_case,
                    &envelope,
                    expected_error_code,
                    diagnostic_hash.as_str(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let composite_score_millionths =
        weighted_composite_score(&score_by_dimension, &fixture.score_dimensions);

    CaseEvaluation {
        case_id: fixture_case.case_id.clone(),
        family_id: fixture_case.family_id.clone(),
        expected_error_code: fixture_case.expected_error_code.clone(),
        diagnostic_hash,
        budget_kind: envelope.budget_kind.map(|kind| kind.as_str().to_string()),
        score_by_dimension,
        composite_score_millionths,
        replay_command: fixture_case.replay_command.clone(),
    }
}

fn evaluate_all_cases(fixture: &DiagnosticsQualityRubricFixture) -> Vec<CaseEvaluation> {
    let parser = CanonicalEs2020Parser;
    fixture
        .cases
        .iter()
        .map(|case| evaluate_case(&parser, case, fixture))
        .collect()
}

fn aggregate_scores(
    evaluations: &[CaseEvaluation],
    dimensions: &[ScoreDimension],
) -> BTreeMap<String, u32> {
    assert!(!evaluations.is_empty(), "evaluation set must not be empty");
    let count = evaluations.len() as u64;

    let mut aggregate = BTreeMap::new();
    for dimension in dimensions {
        let total = evaluations
            .iter()
            .map(|evaluation| {
                *evaluation
                    .score_by_dimension
                    .get(&dimension.dimension_id)
                    .unwrap_or_else(|| {
                        panic!(
                            "missing dimension score `{}` in case `{}`",
                            dimension.dimension_id, evaluation.case_id
                        )
                    })
            })
            .map(u64::from)
            .sum::<u64>();
        aggregate.insert(dimension.dimension_id.clone(), (total / count) as u32);
    }

    let composite_total = evaluations
        .iter()
        .map(|evaluation| u64::from(evaluation.composite_score_millionths))
        .sum::<u64>();
    aggregate.insert("composite".to_string(), (composite_total / count) as u32);

    aggregate
}

fn build_structured_log(evaluation: &CaseEvaluation) -> serde_json::Value {
    serde_json::json!({
        "trace_id": format!("trace-parser-diagnostics-rubric-{}", evaluation.case_id),
        "decision_id": format!("decision-parser-diagnostics-rubric-{}", evaluation.case_id),
        "policy_id": "policy-parser-diagnostics-rubric-v1",
        "component": "parser_diagnostics_quality_rubric",
        "event": "diagnostics_case_evaluated",
        "outcome": "pass",
        "error_code": null,
        "case_id": evaluation.case_id,
        "family_id": evaluation.family_id,
        "expected_error_code": evaluation.expected_error_code,
        "diagnostic_hash": evaluation.diagnostic_hash,
        "budget_kind": evaluation.budget_kind,
        "scores_millionths": evaluation.score_by_dimension,
        "composite_score_millionths": evaluation.composite_score_millionths,
        "replay_command": evaluation.replay_command,
    })
}

#[test]
fn diagnostics_rubric_doc_has_required_sections() {
    let doc = load_doc();
    let required_sections = [
        "## Scope",
        "## Contract Version",
        "## Rubric Dimensions",
        "## Golden Diagnostics Corpus Families",
        "## Baseline Delta and Regression Alarm Policy",
        "## Structured Log Contract",
        "## Deterministic Execution Contract",
        "## Required Artifacts",
        "## Operator Verification",
    ];

    for section in required_sections {
        assert!(
            doc.contains(section),
            "missing diagnostics rubric doc section: {section}"
        );
    }
}

#[test]
fn diagnostics_rubric_fixture_contract_is_well_formed() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-diagnostics-quality-rubric.v1"
    );
    assert_eq!(fixture.rubric_version, "1.0.0");
    assert!(!fixture.cases.is_empty());
    assert!(!fixture.score_dimensions.is_empty());

    let total_weight = fixture
        .score_dimensions
        .iter()
        .map(|dimension| {
            assert!(!dimension.description.trim().is_empty());
            u64::from(dimension.weight_millionths)
        })
        .sum::<u64>();
    assert_eq!(total_weight, 1_000_000);

    let required_baselines = [
        "location_precision",
        "message_clarity",
        "actionable_hints",
        "deterministic_wording",
        "composite",
    ];
    for key in required_baselines {
        assert!(
            fixture.baseline_scores_millionths.contains_key(key),
            "missing baseline score key `{key}`"
        );
    }

    let required_log_keys = [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ];
    let declared_keys = fixture
        .structured_log_required_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for key in required_log_keys {
        assert!(
            declared_keys.contains(key),
            "missing required structured log key `{key}`"
        );
    }
}

#[test]
fn diagnostics_rubric_cases_cover_major_families() {
    let fixture = load_fixture();
    let families = fixture
        .cases
        .iter()
        .map(|case| {
            case.family_id
                .split('.')
                .next()
                .unwrap_or_else(|| panic!("invalid family id `{}`", case.family_id))
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    let expected = ["goal", "input", "resource", "syntax"]
        .into_iter()
        .map(String::from)
        .collect::<BTreeSet<_>>();
    assert_eq!(families, expected);
}

#[test]
fn diagnostics_rubric_scores_are_deterministic_and_regression_bounded() {
    let fixture = load_fixture();

    let left = evaluate_all_cases(&fixture);
    let right = evaluate_all_cases(&fixture);
    assert_eq!(left, right);

    let aggregate = aggregate_scores(&left, &fixture.score_dimensions);
    for (metric, baseline) in &fixture.baseline_scores_millionths {
        let current = *aggregate
            .get(metric)
            .unwrap_or_else(|| panic!("missing aggregate metric `{metric}`"));
        let delta = i64::from(current) - i64::from(*baseline);
        assert!(
            delta >= -i64::from(fixture.max_allowed_regression_millionths),
            "diagnostics quality regression for `{metric}`: baseline={} current={} delta={} allowed={}",
            baseline,
            current,
            delta,
            fixture.max_allowed_regression_millionths,
        );
    }
}

#[test]
fn diagnostics_rubric_user_journey_logs_are_structured_and_replayable() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);

    let left_logs = evaluations
        .iter()
        .map(build_structured_log)
        .collect::<Vec<_>>();
    let right_logs = evaluate_all_cases(&fixture)
        .iter()
        .map(build_structured_log)
        .collect::<Vec<_>>();

    assert_eq!(left_logs, right_logs);

    for log in &left_logs {
        for key in &fixture.structured_log_required_keys {
            assert!(
                log.get(key.as_str()).is_some(),
                "structured log missing required key `{key}`"
            );
        }

        let replay_command = log["replay_command"]
            .as_str()
            .expect("replay command should be a string");
        assert!(
            replay_command.contains(
                "cargo test -p frankenengine-engine --test parser_diagnostics_quality_rubric"
            ),
            "unexpected replay command: {replay_command}"
        );
    }
}

// ---------- parse_goal helper ----------

#[test]
fn rubric_parse_goal_maps_script() {
    assert_eq!(parse_goal("script"), ParseGoal::Script);
}

#[test]
fn rubric_parse_goal_maps_module() {
    assert_eq!(parse_goal("module"), ParseGoal::Module);
}

#[test]
#[should_panic(expected = "unknown parse goal")]
fn rubric_parse_goal_panics_on_unknown() {
    parse_goal("eval");
}

// ---------- parse_error_code helper ----------

#[test]
fn rubric_parse_error_code_maps_all_known() {
    let codes = [
        ("empty_source", ParseErrorCode::EmptySource),
        ("invalid_goal", ParseErrorCode::InvalidGoal),
        ("unsupported_syntax", ParseErrorCode::UnsupportedSyntax),
        ("io_read_failed", ParseErrorCode::IoReadFailed),
        ("invalid_utf8", ParseErrorCode::InvalidUtf8),
        ("source_too_large", ParseErrorCode::SourceTooLarge),
        ("budget_exceeded", ParseErrorCode::BudgetExceeded),
    ];
    for (raw, expected) in codes {
        assert_eq!(parse_error_code(raw), expected);
    }
}

// ---------- parse_budget_kind helper ----------

#[test]
fn rubric_parse_budget_kind_maps_all_known() {
    let kinds = [
        ("source_bytes", ParseBudgetKind::SourceBytes),
        ("token_count", ParseBudgetKind::TokenCount),
        ("recursion_depth", ParseBudgetKind::RecursionDepth),
    ];
    for (raw, expected) in kinds {
        assert_eq!(parse_budget_kind(raw), expected);
    }
}

// ---------- ScoreDimension ----------

#[test]
fn score_dimensions_are_unique_and_sum_to_million() {
    let fixture = load_fixture();
    let mut ids = BTreeSet::new();
    let total: u64 = fixture
        .score_dimensions
        .iter()
        .map(|dim| {
            assert!(ids.insert(dim.dimension_id.clone()), "duplicate dimension");
            u64::from(dim.weight_millionths)
        })
        .sum();
    assert_eq!(total, 1_000_000);
}

// ---------- RubricCase ----------

#[test]
fn rubric_cases_have_unique_ids() {
    let fixture = load_fixture();
    let mut ids = BTreeSet::new();
    for case in &fixture.cases {
        assert!(ids.insert(case.case_id.clone()), "duplicate case id");
        assert!(!case.family_id.is_empty());
        assert!(!case.source.is_empty());
        assert!(!case.replay_command.is_empty());
    }
}

#[test]
fn rubric_cases_cover_expected_families() {
    let fixture = load_fixture();
    let families: BTreeSet<_> = fixture
        .cases
        .iter()
        .map(|case| case.family_id.split('.').next().unwrap().to_string())
        .collect();
    for expected in ["goal", "input", "resource", "syntax"] {
        assert!(families.contains(expected), "missing family: {expected}");
    }
}

// ---------- weighted_composite_score ----------

#[test]
fn rubric_weighted_composite_uniform_million() {
    let dims = vec![
        ScoreDimension {
            dimension_id: "a".to_string(),
            description: "dim a".to_string(),
            weight_millionths: 500_000,
        },
        ScoreDimension {
            dimension_id: "b".to_string(),
            description: "dim b".to_string(),
            weight_millionths: 500_000,
        },
    ];
    let mut scores = BTreeMap::new();
    scores.insert("a".to_string(), 1_000_000_u32);
    scores.insert("b".to_string(), 1_000_000_u32);
    assert_eq!(weighted_composite_score(&scores, &dims), 1_000_000);
}

#[test]
fn rubric_weighted_composite_zero() {
    let dims = vec![ScoreDimension {
        dimension_id: "x".to_string(),
        description: "dim x".to_string(),
        weight_millionths: 1_000_000,
    }];
    let mut scores = BTreeMap::new();
    scores.insert("x".to_string(), 0_u32);
    assert_eq!(weighted_composite_score(&scores, &dims), 0);
}

// ---------- evaluate_case ----------

#[test]
fn evaluate_case_produces_deterministic_hash() {
    let fixture = load_fixture();
    let parser = CanonicalEs2020Parser;
    let case = &fixture.cases[0];
    let left = evaluate_case(&parser, case, &fixture);
    let right = evaluate_case(&parser, case, &fixture);
    assert_eq!(left.diagnostic_hash, right.diagnostic_hash);
    assert!(left.diagnostic_hash.starts_with("sha256:"));
}

#[test]
fn evaluate_case_composite_is_within_bounds() {
    let fixture = load_fixture();
    let parser = CanonicalEs2020Parser;
    for case in &fixture.cases {
        let eval = evaluate_case(&parser, case, &fixture);
        assert!(eval.composite_score_millionths <= 1_000_000);
    }
}

// ---------- build_structured_log ----------

#[test]
fn structured_log_has_required_keys() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    let log = build_structured_log(&evaluations[0]);
    for key in &fixture.structured_log_required_keys {
        assert!(log.get(key.as_str()).is_some(), "missing key: {key}");
    }
}

#[test]
fn structured_log_trace_id_has_rubric_prefix() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    let log = build_structured_log(&evaluations[0]);
    let trace_id = log["trace_id"].as_str().unwrap();
    assert!(trace_id.starts_with("trace-parser-diagnostics-rubric-"));
}

// ---------- aggregate_scores ----------

#[test]
fn aggregate_scores_include_composite_key() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    let aggregate = aggregate_scores(&evaluations, &fixture.score_dimensions);
    assert!(aggregate.contains_key("composite"));
}

#[test]
fn aggregate_scores_include_all_dimensions() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    let aggregate = aggregate_scores(&evaluations, &fixture.score_dimensions);
    for dim in &fixture.score_dimensions {
        assert!(
            aggregate.contains_key(&dim.dimension_id),
            "missing dimension: {}",
            dim.dimension_id
        );
    }
}

#[test]
fn fixture_has_nonempty_schema_version() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.trim().is_empty());
}

#[test]
fn fixture_deterministic_double_load() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.cases.len(), b.cases.len());
}

#[test]
fn doc_has_more_than_50_lines() {
    let doc = load_doc();
    assert!(doc.lines().count() > 50);
}

// ---------- parse_error_code edge case ----------

#[test]
#[should_panic(expected = "unknown parse error code")]
fn rubric_parse_error_code_panics_on_unknown() {
    parse_error_code("nonexistent_code");
}

// ---------- parse_budget_kind edge case ----------

#[test]
#[should_panic(expected = "unknown budget kind")]
fn rubric_parse_budget_kind_panics_on_unknown() {
    parse_budget_kind("heap_limit");
}

// ---------- weighted_composite_score edge cases ----------

#[test]
fn rubric_weighted_composite_half_score() {
    let dims = vec![
        ScoreDimension {
            dimension_id: "a".to_string(),
            description: "dim a".to_string(),
            weight_millionths: 500_000,
        },
        ScoreDimension {
            dimension_id: "b".to_string(),
            description: "dim b".to_string(),
            weight_millionths: 500_000,
        },
    ];
    let mut scores = BTreeMap::new();
    scores.insert("a".to_string(), 1_000_000_u32);
    scores.insert("b".to_string(), 0_u32);
    assert_eq!(weighted_composite_score(&scores, &dims), 500_000);
}

// ---------- CaseEvaluation determinism ----------

#[test]
fn case_evaluation_clone_eq() {
    let fixture = load_fixture();
    let parser = CanonicalEs2020Parser;
    let case = &fixture.cases[0];
    let eval = evaluate_case(&parser, case, &fixture);
    let cloned = eval.clone();
    assert_eq!(eval, cloned);
}

// ---------- build_structured_log edge cases ----------

#[test]
fn structured_log_decision_id_has_rubric_prefix() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    let log = build_structured_log(&evaluations[0]);
    let decision_id = log["decision_id"].as_str().unwrap();
    assert!(decision_id.starts_with("decision-parser-diagnostics-rubric-"));
}

#[test]
fn structured_log_policy_id_is_rubric_v1() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    let log = build_structured_log(&evaluations[0]);
    assert_eq!(
        log["policy_id"].as_str().unwrap(),
        "policy-parser-diagnostics-rubric-v1"
    );
}

// ---------- fixture field validation ----------

#[test]
fn fixture_baseline_scores_are_within_million() {
    let fixture = load_fixture();
    for (key, value) in &fixture.baseline_scores_millionths {
        assert!(
            *value <= 1_000_000,
            "baseline score `{key}` exceeds 1_000_000: {value}"
        );
    }
}

// ---------- ScoreDimension field validation ----------

#[test]
fn score_dimension_description_is_nonempty() {
    let fixture = load_fixture();
    for dim in &fixture.score_dimensions {
        assert!(
            !dim.description.trim().is_empty(),
            "dimension `{}` has empty description",
            dim.dimension_id
        );
    }
}

#[test]
fn score_dimension_weight_is_nonzero() {
    let fixture = load_fixture();
    for dim in &fixture.score_dimensions {
        assert!(
            dim.weight_millionths > 0,
            "dimension `{}` has zero weight",
            dim.dimension_id
        );
    }
}

// ---------- RubricCase field validation ----------

#[test]
fn rubric_case_replay_commands_contain_test_name() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        assert!(
            case.replay_command
                .contains("parser_diagnostics_quality_rubric"),
            "case `{}` replay command missing test name: {}",
            case.case_id,
            case.replay_command
        );
    }
}

#[test]
fn rubric_case_expected_diagnostic_codes_are_nonempty() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        assert!(
            !case.expected_diagnostic_code.trim().is_empty(),
            "case `{}` has empty expected_diagnostic_code",
            case.case_id
        );
    }
}

#[test]
fn rubric_case_sources_are_nonempty() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        assert!(
            !case.source.is_empty(),
            "case `{}` has empty source",
            case.case_id
        );
    }
}

// ---------- weighted_composite_score edge cases ----------

#[test]
fn rubric_weighted_composite_unequal_weights() {
    let dims = vec![
        ScoreDimension {
            dimension_id: "a".to_string(),
            description: "dim a".to_string(),
            weight_millionths: 750_000,
        },
        ScoreDimension {
            dimension_id: "b".to_string(),
            description: "dim b".to_string(),
            weight_millionths: 250_000,
        },
    ];
    let mut scores = BTreeMap::new();
    scores.insert("a".to_string(), 1_000_000_u32);
    scores.insert("b".to_string(), 0_u32);
    assert_eq!(weighted_composite_score(&scores, &dims), 750_000);
}

#[test]
fn rubric_weighted_composite_three_dimensions() {
    let dims = vec![
        ScoreDimension {
            dimension_id: "a".to_string(),
            description: "dim a".to_string(),
            weight_millionths: 333_334,
        },
        ScoreDimension {
            dimension_id: "b".to_string(),
            description: "dim b".to_string(),
            weight_millionths: 333_333,
        },
        ScoreDimension {
            dimension_id: "c".to_string(),
            description: "dim c".to_string(),
            weight_millionths: 333_333,
        },
    ];
    let mut scores = BTreeMap::new();
    scores.insert("a".to_string(), 1_000_000_u32);
    scores.insert("b".to_string(), 1_000_000_u32);
    scores.insert("c".to_string(), 1_000_000_u32);
    let result = weighted_composite_score(&scores, &dims);
    // Should be very close to 1_000_000 (rounding may differ by 1)
    assert!((999_999..=1_000_000).contains(&result));
}

// ---------- evaluate_all_cases determinism ----------

#[test]
fn evaluate_all_cases_returns_same_count_as_fixture() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    assert_eq!(evaluations.len(), fixture.cases.len());
}

#[test]
fn evaluate_all_cases_all_hashes_start_with_sha256() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    for eval in &evaluations {
        assert!(
            eval.diagnostic_hash.starts_with("sha256:"),
            "case `{}` hash missing sha256 prefix: {}",
            eval.case_id,
            eval.diagnostic_hash
        );
    }
}

#[test]
fn evaluate_all_cases_case_ids_match_fixture() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    let eval_ids: Vec<&str> = evaluations.iter().map(|e| e.case_id.as_str()).collect();
    let fixture_ids: Vec<&str> = fixture.cases.iter().map(|c| c.case_id.as_str()).collect();
    assert_eq!(eval_ids, fixture_ids);
}

// ---------- build_structured_log field completeness ----------

#[test]
fn structured_log_component_is_rubric() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    for eval in &evaluations {
        let log = build_structured_log(eval);
        assert_eq!(
            log["component"].as_str().unwrap(),
            "parser_diagnostics_quality_rubric"
        );
    }
}

#[test]
fn structured_log_event_is_case_evaluated() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    let log = build_structured_log(&evaluations[0]);
    assert_eq!(log["event"].as_str().unwrap(), "diagnostics_case_evaluated");
}

#[test]
fn structured_log_outcome_is_pass() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    for eval in &evaluations {
        let log = build_structured_log(eval);
        assert_eq!(log["outcome"].as_str().unwrap(), "pass");
    }
}

#[test]
fn structured_log_error_code_is_null() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    for eval in &evaluations {
        let log = build_structured_log(eval);
        assert!(log["error_code"].is_null());
    }
}

// ---------- aggregate_scores cross-cutting ----------

#[test]
fn aggregate_scores_all_values_within_million() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    let aggregate = aggregate_scores(&evaluations, &fixture.score_dimensions);
    for (key, value) in &aggregate {
        assert!(
            *value <= 1_000_000,
            "aggregate `{key}` exceeds 1_000_000: {value}"
        );
    }
}

#[test]
fn aggregate_scores_keys_cover_all_dimensions_plus_composite() {
    let fixture = load_fixture();
    let evaluations = evaluate_all_cases(&fixture);
    let aggregate = aggregate_scores(&evaluations, &fixture.score_dimensions);
    assert_eq!(
        aggregate.len(),
        fixture.score_dimensions.len() + 1,
        "aggregate should have one key per dimension plus composite"
    );
}

// ---------- fixture structural invariants ----------

#[test]
fn fixture_max_regression_is_reasonable() {
    let fixture = load_fixture();
    assert!(
        fixture.max_allowed_regression_millionths <= 200_000,
        "max allowed regression seems too generous: {}",
        fixture.max_allowed_regression_millionths
    );
}

#[test]
fn fixture_structured_log_keys_are_unique() {
    let fixture = load_fixture();
    let set: BTreeSet<_> = fixture.structured_log_required_keys.iter().collect();
    assert_eq!(set.len(), fixture.structured_log_required_keys.len());
}
