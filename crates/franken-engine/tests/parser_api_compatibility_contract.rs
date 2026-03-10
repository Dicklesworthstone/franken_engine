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
use std::io::Cursor;
use std::path::{Path, PathBuf};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, Es2020Parser, ParseBudgetKind, ParseErrorCode, ParseEventIr,
    ParseEventMaterializationErrorCode, ParserBudget, ParserOptions, StreamInput,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct BudgetOverride {
    max_source_bytes: u64,
    max_token_count: u64,
    max_recursion_depth: u64,
}

#[derive(Debug, Deserialize)]
struct CompatibilityCase {
    case_id: String,
    input_kind: String,
    goal: String,
    source: String,
    expect_ok: bool,
    expected_error_code: Option<String>,
    expected_budget_kind: Option<String>,
    budget_override: Option<BudgetOverride>,
    replay_command: String,
}

#[derive(Debug, Deserialize)]
struct ParserApiCompatibilityFixture {
    schema_version: String,
    contract_version: String,
    api_schema_version: String,
    bead_id: String,
    max_allowed_regression_millionths: u32,
    required_doc_sections: Vec<String>,
    required_api_entries: Vec<String>,
    required_structured_log_keys: Vec<String>,
    migration_policy_markers: Vec<String>,
    ergonomics_slo_millionths: BTreeMap<String, u32>,
    compatibility_cases: Vec<CompatibilityCase>,
}

fn load_fixture() -> ParserApiCompatibilityFixture {
    let path = Path::new("tests/fixtures/parser_api_compatibility_contract_v1.json");
    let bytes = fs::read(path).expect("read parser API compatibility fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser API compatibility fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_API_COMPATIBILITY_CONTRACT.md");
    fs::read_to_string(path).expect("read parser API compatibility contract doc")
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
        other => panic!("unknown parse budget kind: {other}"),
    }
}

fn parser_options(case: &CompatibilityCase) -> ParserOptions {
    let mut options = ParserOptions::default();
    if let Some(override_budget) = case.budget_override.as_ref() {
        options.budget = ParserBudget {
            max_source_bytes: override_budget.max_source_bytes,
            max_token_count: override_budget.max_token_count,
            max_recursion_depth: override_budget.max_recursion_depth,
        };
    }
    options
}

fn temporary_case_path(case_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "franken_engine_parser_api_compatibility_{}_{}.js",
        case_id,
        std::process::id()
    ))
}

fn run_parse_with_options(
    parser: &CanonicalEs2020Parser,
    case: &CompatibilityCase,
) -> frankenengine_engine::parser::ParseResult<frankenengine_engine::ast::SyntaxTree> {
    let goal = parse_goal(case.goal.as_str());
    let options = parser_options(case);

    match case.input_kind.as_str() {
        "inline_str" => parser.parse_with_options(case.source.as_str(), goal, &options),
        "owned_string" => parser.parse_with_options(case.source.clone(), goal, &options),
        "path" => {
            let path = temporary_case_path(case.case_id.as_str());
            fs::write(&path, case.source.as_bytes()).expect("write path input test fixture");
            let result = parser.parse_with_options(path.clone(), goal, &options);
            let _ = fs::remove_file(path);
            result
        }
        "stream" => parser.parse_with_options(
            StreamInput::new(
                Cursor::new(case.source.as_bytes().to_vec()),
                format!("stream-{}", case.case_id),
            ),
            goal,
            &options,
        ),
        other => panic!("unknown input kind: {other}"),
    }
}

fn run_parse_with_event_ir(
    parser: &CanonicalEs2020Parser,
    case: &CompatibilityCase,
) -> (
    frankenengine_engine::parser::ParseResult<frankenengine_engine::ast::SyntaxTree>,
    ParseEventIr,
) {
    let goal = parse_goal(case.goal.as_str());
    let options = parser_options(case);

    match case.input_kind.as_str() {
        "inline_str" => parser.parse_with_event_ir(case.source.as_str(), goal, &options),
        "owned_string" => parser.parse_with_event_ir(case.source.clone(), goal, &options),
        "path" => {
            let path = temporary_case_path(case.case_id.as_str());
            fs::write(&path, case.source.as_bytes()).expect("write path input test fixture");
            let result = parser.parse_with_event_ir(path.clone(), goal, &options);
            let _ = fs::remove_file(path);
            result
        }
        "stream" => parser.parse_with_event_ir(
            StreamInput::new(
                Cursor::new(case.source.as_bytes().to_vec()),
                format!("stream-{}", case.case_id),
            ),
            goal,
            &options,
        ),
        other => panic!("unknown input kind: {other}"),
    }
}

fn run_parse_with_materialized_ast(
    parser: &CanonicalEs2020Parser,
    case: &CompatibilityCase,
) -> (
    frankenengine_engine::parser::ParseResult<frankenengine_engine::ast::SyntaxTree>,
    ParseEventIr,
    frankenengine_engine::parser::ParseEventMaterializationResult<
        frankenengine_engine::parser::MaterializedSyntaxTree,
    >,
) {
    let goal = parse_goal(case.goal.as_str());
    let options = parser_options(case);

    match case.input_kind.as_str() {
        "inline_str" => parser.parse_with_materialized_ast(case.source.as_str(), goal, &options),
        "owned_string" => parser.parse_with_materialized_ast(case.source.clone(), goal, &options),
        "path" => {
            let path = temporary_case_path(case.case_id.as_str());
            fs::write(&path, case.source.as_bytes()).expect("write path input test fixture");
            let result = parser.parse_with_materialized_ast(path.clone(), goal, &options);
            let _ = fs::remove_file(path);
            result
        }
        "stream" => parser.parse_with_materialized_ast(
            StreamInput::new(
                Cursor::new(case.source.as_bytes().to_vec()),
                format!("stream-{}", case.case_id),
            ),
            goal,
            &options,
        ),
        other => panic!("unknown input kind: {other}"),
    }
}

fn assert_required_event_keys(
    event_ir: &ParseEventIr,
    required_keys: &[String],
    case_id: &str,
    require_error_code: bool,
) {
    assert!(
        !event_ir.events.is_empty(),
        "event IR is empty for case `{case_id}`"
    );

    let required_error_code_key = required_keys.iter().any(|key| key == "error_code");
    let mut observed_error_code_key = false;

    for event in &event_ir.events {
        let value = serde_json::to_value(event).expect("serialize parse event");
        let object = value
            .as_object()
            .expect("parse event should serialize into a JSON object");

        for key in required_keys {
            if key == "error_code" {
                // `error_code` is only emitted for failing parse events.
                observed_error_code_key |= object.contains_key("error_code");
                continue;
            }
            assert!(
                object.contains_key(key),
                "case `{case_id}` parse event missing required key `{key}`"
            );
        }
    }

    if require_error_code && required_error_code_key {
        assert!(
            observed_error_code_key,
            "case `{case_id}` event IR is missing required `error_code` key on failing events"
        );
    }
}

#[test]
fn parser_api_contract_doc_contains_required_sections() {
    let fixture = load_fixture();
    let doc = load_doc();

    for section in &fixture.required_doc_sections {
        assert!(
            doc.contains(section.as_str()),
            "parser API compatibility doc missing section: {section}"
        );
    }
}

#[test]
fn parser_api_fixture_declares_stable_metadata() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-api-compatibility-contract.v1"
    );
    assert_eq!(fixture.contract_version, "1.0.0");
    assert_eq!(
        fixture.api_schema_version,
        "franken-engine.parser-public-api.v1"
    );
    assert_eq!(fixture.bead_id, "bd-2mds.1.10.3");

    assert!(
        !fixture.compatibility_cases.is_empty(),
        "compatibility fixture must define at least one case"
    );

    let expected_api_entries: BTreeSet<&str> = [
        "Es2020Parser::parse",
        "CanonicalEs2020Parser::parse_with_options",
        "CanonicalEs2020Parser::parse_with_event_ir",
        "CanonicalEs2020Parser::parse_with_materialized_ast",
        "CanonicalEs2020Parser::scalar_reference_grammar_matrix",
        "ParserInput<&str>",
        "ParserInput<String>",
        "ParserInput<PathBuf>",
        "ParserInput<StreamInput>",
    ]
    .into_iter()
    .collect();
    let actual_entries: BTreeSet<&str> = fixture
        .required_api_entries
        .iter()
        .map(String::as_str)
        .collect();
    assert_eq!(actual_entries, expected_api_entries);
}

#[test]
fn migration_policy_markers_are_documented() {
    let fixture = load_fixture();
    let doc = load_doc();

    for marker in &fixture.migration_policy_markers {
        assert!(
            doc.contains(marker.as_str()),
            "parser API compatibility doc missing migration marker: {marker}"
        );
    }
}

#[test]
fn stable_public_parser_api_entrypoints_execute() {
    fn parse_via_trait<P: Es2020Parser>(parser: &P, source: &str, goal: ParseGoal) -> bool {
        parser.parse(source, goal).is_ok()
    }

    let parser = CanonicalEs2020Parser;
    assert!(parse_via_trait(&parser, "alpha;", ParseGoal::Script));

    let options = ParserOptions::default();
    let tree = parser
        .parse_with_options("import dep from \"pkg\";", ParseGoal::Module, &options)
        .expect("parse_with_options should support module import vector");
    assert_eq!(tree.goal, ParseGoal::Module);

    let (ok_result, ok_event_ir) =
        parser.parse_with_event_ir("omega;", ParseGoal::Script, &ParserOptions::default());
    let ok_tree = ok_result.expect("parse_with_event_ir should parse script success vector");
    assert_eq!(ok_tree.body.len(), 1);
    assert_eq!(ok_event_ir.schema_version, ParseEventIr::schema_version());
    assert_eq!(
        ok_event_ir.contract_version,
        ParseEventIr::contract_version()
    );

    let (fail_result, fail_event_ir) = parser.parse_with_event_ir(
        "export default value;",
        ParseGoal::Script,
        &ParserOptions::default(),
    );
    let fail_error = fail_result.expect_err("script export should fail");
    assert_eq!(fail_error.code, ParseErrorCode::InvalidGoal);
    assert_eq!(
        fail_event_ir
            .events
            .last()
            .and_then(|event| event.error_code),
        Some(ParseErrorCode::InvalidGoal)
    );

    let (_tree_result, _event_ir, materialized) =
        parser.parse_with_materialized_ast("alpha;", ParseGoal::Script, &ParserOptions::default());
    let materialized = materialized.expect("materialized AST should succeed on parse success");
    assert!(materialized.root_node_id.starts_with("ast-node-"));
    assert_eq!(materialized.statement_nodes.len(), 1);

    let summary = parser.scalar_reference_grammar_matrix().summary();
    assert!(summary.family_count > 0);
}

#[test]
fn compatibility_vectors_are_deterministic_and_meet_slos() {
    let fixture = load_fixture();
    let doc = load_doc();
    let parser = CanonicalEs2020Parser;
    let selected_case = std::env::var("PARSER_API_COMPAT_CASE")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let single_case_replay_mode = selected_case.is_some();
    let selected_cases: Vec<&CompatibilityCase> = if let Some(case_id) = selected_case.as_deref() {
        let filtered_cases: Vec<&CompatibilityCase> = fixture
            .compatibility_cases
            .iter()
            .filter(|case| case.case_id == case_id)
            .collect();
        assert!(
            !filtered_cases.is_empty(),
            "PARSER_API_COMPAT_CASE requested unknown case `{case_id}`"
        );
        filtered_cases
    } else {
        fixture.compatibility_cases.iter().collect()
    };
    let case_count = selected_cases.len() as u64;

    let mut matched_outcomes = 0_u64;
    let mut exercised_input_kinds = BTreeSet::new();

    for case in selected_cases {
        exercised_input_kinds.insert(case.input_kind.as_str());
        assert!(
            case.replay_command.starts_with("PARSER_API_COMPAT_CASE=")
                || case
                    .replay_command
                    .starts_with("./scripts/run_parser_api_compatibility_gate.sh "),
            "case `{}` has non-canonical replay command: {}",
            case.case_id,
            case.replay_command
        );

        let result_one = run_parse_with_options(&parser, case);
        let result_two = run_parse_with_options(&parser, case);
        let (event_result_one, event_ir_one) = run_parse_with_event_ir(&parser, case);
        let (event_result_two, event_ir_two) = run_parse_with_event_ir(&parser, case);

        assert_required_event_keys(
            &event_ir_one,
            &fixture.required_structured_log_keys,
            case.case_id.as_str(),
            !case.expect_ok,
        );
        assert_required_event_keys(
            &event_ir_two,
            &fixture.required_structured_log_keys,
            case.case_id.as_str(),
            !case.expect_ok,
        );

        if case.expect_ok {
            let tree_one =
                result_one.expect("parse_with_options success case should parse on first run");
            let tree_two =
                result_two.expect("parse_with_options success case should parse on second run");
            assert_eq!(
                tree_one.canonical_hash(),
                tree_two.canonical_hash(),
                "success vector canonical hash drift for case `{}`",
                case.case_id
            );

            let event_tree_one = event_result_one
                .expect("parse_with_event_ir success case should parse on first run");
            let event_tree_two = event_result_two
                .expect("parse_with_event_ir success case should parse on second run");
            assert_eq!(
                event_tree_one.canonical_hash(),
                event_tree_two.canonical_hash(),
                "event-ir parse tree hash drift for case `{}`",
                case.case_id
            );
            assert_eq!(
                event_ir_one.canonical_hash(),
                event_ir_two.canonical_hash(),
                "event-ir canonical hash drift for case `{}`",
                case.case_id
            );

            let (_materialized_result_one, _materialized_event_ir_one, materialized_one) =
                run_parse_with_materialized_ast(&parser, case);
            let (_materialized_result_two, _materialized_event_ir_two, materialized_two) =
                run_parse_with_materialized_ast(&parser, case);
            let materialized_one = materialized_one
                .expect("materializer should succeed for successful compatibility vector");
            let materialized_two = materialized_two
                .expect("materializer should be deterministic for successful vectors");

            assert_eq!(
                materialized_one.root_node_id, materialized_two.root_node_id,
                "materialized root node drift for case `{}`",
                case.case_id
            );
            assert!(
                materialized_one.root_node_id.starts_with("ast-node-"),
                "unexpected materialized root node prefix for case `{}`",
                case.case_id
            );

            matched_outcomes = matched_outcomes.saturating_add(1);
        } else {
            let expected_code = parse_error_code(
                case.expected_error_code
                    .as_deref()
                    .expect("failing compatibility case must declare expected_error_code"),
            );

            let error_one = result_one.expect_err("failing vector should fail on first run");
            let error_two = result_two.expect_err("failing vector should fail on second run");
            assert_eq!(error_one.code, expected_code);
            assert_eq!(error_two.code, expected_code);

            let diagnostic_one = error_one.normalized_diagnostic();
            let diagnostic_two = error_two.normalized_diagnostic();
            assert_eq!(
                diagnostic_one.canonical_hash(),
                diagnostic_two.canonical_hash(),
                "normalized diagnostic drift for failing case `{}`",
                case.case_id
            );

            let expected_budget_kind = case.expected_budget_kind.as_deref().map(parse_budget_kind);
            assert_eq!(
                diagnostic_one.budget_kind, expected_budget_kind,
                "unexpected budget kind for failing case `{}`",
                case.case_id
            );

            let event_error_one =
                event_result_one.expect_err("failing vector should fail in parse_with_event_ir");
            let event_error_two =
                event_result_two.expect_err("failing vector should fail in parse_with_event_ir");
            assert_eq!(event_error_one.code, expected_code);
            assert_eq!(event_error_two.code, expected_code);
            assert_eq!(
                event_ir_one.canonical_hash(),
                event_ir_two.canonical_hash(),
                "event-ir drift for failing case `{}`",
                case.case_id
            );

            let (_materialized_result, _materialized_event_ir, materialized) =
                run_parse_with_materialized_ast(&parser, case);
            let materialized_error =
                materialized.expect_err("materializer must fail for failing parse vectors");
            assert_eq!(
                materialized_error.code,
                ParseEventMaterializationErrorCode::ParseFailedEventStream
            );

            matched_outcomes = matched_outcomes.saturating_add(1);
        }
    }

    let integration_success_rate =
        ((matched_outcomes.saturating_mul(1_000_000)) / case_count.max(1)) as u32;

    let required_input_kinds: BTreeSet<&str> = ["inline_str", "owned_string", "path", "stream"]
        .into_iter()
        .collect();
    let input_adapter_coverage = if single_case_replay_mode {
        // Fixture replay commands allow case-scoped execution; adapter coverage SLO is
        // only meaningful for full-matrix runs.
        1_000_000
    } else {
        let adapter_hits = required_input_kinds
            .iter()
            .filter(|kind| exercised_input_kinds.contains(*kind))
            .count() as u64;
        ((adapter_hits.saturating_mul(1_000_000)) / required_input_kinds.len() as u64) as u32
    };

    let readable_markers = fixture
        .migration_policy_markers
        .iter()
        .filter(|marker| doc.contains(marker.as_str()))
        .count() as u64;
    let migration_readability = ((readable_markers.saturating_mul(1_000_000))
        / fixture.migration_policy_markers.len().max(1) as u64)
        as u32;

    let actual_scores = BTreeMap::from([
        (
            "integration_success_rate".to_string(),
            integration_success_rate,
        ),
        ("input_adapter_coverage".to_string(), input_adapter_coverage),
        ("migration_readability".to_string(), migration_readability),
    ]);

    for (metric, baseline) in &fixture.ergonomics_slo_millionths {
        let score = actual_scores
            .get(metric)
            .unwrap_or_else(|| panic!("missing computed score for metric `{metric}`"));
        let minimum_allowed = baseline.saturating_sub(fixture.max_allowed_regression_millionths);
        assert!(
            *score >= minimum_allowed,
            "metric `{metric}` regressed below allowed floor: score={} floor={} baseline={} regression_budget={}",
            score,
            minimum_allowed,
            baseline,
            fixture.max_allowed_regression_millionths
        );
    }
}

// ---------- fixture invariants ----------

#[test]
fn fixture_case_ids_are_unique() {
    let fixture = load_fixture();
    let mut seen = BTreeSet::new();
    for case in &fixture.compatibility_cases {
        assert!(
            seen.insert(case.case_id.clone()),
            "duplicate case_id: {}",
            case.case_id
        );
    }
}

#[test]
fn fixture_covers_all_input_kinds() {
    let fixture = load_fixture();
    let kinds: BTreeSet<&str> = fixture
        .compatibility_cases
        .iter()
        .map(|c| c.input_kind.as_str())
        .collect();
    for expected in ["inline_str", "owned_string", "path", "stream"] {
        assert!(
            kinds.contains(expected),
            "fixture missing input_kind: {expected}"
        );
    }
}

#[test]
fn fixture_covers_both_goals() {
    let fixture = load_fixture();
    let goals: BTreeSet<&str> = fixture
        .compatibility_cases
        .iter()
        .map(|c| c.goal.as_str())
        .collect();
    assert!(goals.contains("script"), "fixture missing script goal");
    assert!(goals.contains("module"), "fixture missing module goal");
}

#[test]
fn fixture_has_both_success_and_failure_cases() {
    let fixture = load_fixture();
    let has_ok = fixture.compatibility_cases.iter().any(|c| c.expect_ok);
    let has_fail = fixture.compatibility_cases.iter().any(|c| !c.expect_ok);
    assert!(has_ok, "fixture must have at least one success case");
    assert!(has_fail, "fixture must have at least one failure case");
}

// ---------- ParseEventIr ----------

#[test]
fn parse_event_ir_schema_and_contract_versions_are_nonempty() {
    assert!(!ParseEventIr::schema_version().is_empty());
    assert!(!ParseEventIr::contract_version().is_empty());
}

#[test]
fn parse_event_ir_canonical_hash_is_deterministic() {
    let parser = CanonicalEs2020Parser;
    let (_, ir_a) =
        parser.parse_with_event_ir("alpha;", ParseGoal::Script, &ParserOptions::default());
    let (_, ir_b) =
        parser.parse_with_event_ir("alpha;", ParseGoal::Script, &ParserOptions::default());
    assert_eq!(ir_a.canonical_hash(), ir_b.canonical_hash());
}

#[test]
fn parse_event_ir_has_events_for_success_case() {
    let parser = CanonicalEs2020Parser;
    let (result, ir) =
        parser.parse_with_event_ir("42;", ParseGoal::Script, &ParserOptions::default());
    assert!(result.is_ok());
    assert!(!ir.events.is_empty());
}

#[test]
fn parse_event_ir_has_events_for_failure_case() {
    let parser = CanonicalEs2020Parser;
    let (result, ir) = parser.parse_with_event_ir("", ParseGoal::Script, &ParserOptions::default());
    assert!(result.is_err());
    assert!(!ir.events.is_empty());
}

#[test]
fn parse_event_ir_serde_roundtrip() {
    let parser = CanonicalEs2020Parser;
    let (_, ir) = parser.parse_with_event_ir("42;", ParseGoal::Script, &ParserOptions::default());
    let json = serde_json::to_string(&ir).expect("serialize");
    let recovered: ParseEventIr = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.canonical_hash(), ir.canonical_hash());
}

// ---------- MaterializedSyntaxTree ----------

#[test]
fn materialized_ast_root_node_id_starts_with_expected_prefix() {
    let parser = CanonicalEs2020Parser;
    let (_result, _ir, materialized) =
        parser.parse_with_materialized_ast("alpha;", ParseGoal::Script, &ParserOptions::default());
    let mat = materialized.expect("should succeed");
    assert!(mat.root_node_id.starts_with("ast-node-"));
}

#[test]
fn materialized_ast_statement_count_matches_parse_tree() {
    let parser = CanonicalEs2020Parser;
    let (result, _ir, materialized) = parser.parse_with_materialized_ast(
        "alpha;\nbeta;\ngamma;",
        ParseGoal::Script,
        &ParserOptions::default(),
    );
    let tree = result.expect("parse succeeds");
    let mat = materialized.expect("materialized succeeds");
    assert_eq!(mat.statement_nodes.len(), tree.body.len());
}

#[test]
fn materialized_ast_fails_for_parse_failure() {
    let parser = CanonicalEs2020Parser;
    let (_result, _ir, materialized) =
        parser.parse_with_materialized_ast("", ParseGoal::Script, &ParserOptions::default());
    let err = materialized.expect_err("should fail for empty source");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::ParseFailedEventStream
    );
}

// ---------- StreamInput ----------

#[test]
fn stream_input_parses_successfully() {
    let parser = CanonicalEs2020Parser;
    let stream = StreamInput::new(Cursor::new(b"42;".to_vec()), "test-stream");
    let result = parser.parse_with_options(stream, ParseGoal::Script, &ParserOptions::default());
    assert!(result.is_ok());
}

// ---------- ParseBudgetKind ----------

#[test]
fn parse_budget_kind_as_str_values() {
    assert_eq!(ParseBudgetKind::SourceBytes.as_str(), "source_bytes");
    assert_eq!(ParseBudgetKind::TokenCount.as_str(), "token_count");
    assert_eq!(ParseBudgetKind::RecursionDepth.as_str(), "recursion_depth");
}

#[test]
fn parse_budget_kind_serde_roundtrip() {
    for kind in [
        ParseBudgetKind::SourceBytes,
        ParseBudgetKind::TokenCount,
        ParseBudgetKind::RecursionDepth,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: ParseBudgetKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, kind);
    }
}

// ---------- ParserBudget ----------

#[test]
fn parser_budget_default_values() {
    let budget = ParserBudget::default();
    assert_eq!(budget.max_source_bytes, 1_048_576);
    assert_eq!(budget.max_token_count, 65_536);
    assert_eq!(budget.max_recursion_depth, 256);
}

#[test]
fn parser_budget_serde_roundtrip() {
    let budget = ParserBudget::default();
    let json = serde_json::to_string(&budget).expect("serialize");
    let recovered: ParserBudget = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.max_source_bytes, budget.max_source_bytes);
    assert_eq!(recovered.max_token_count, budget.max_token_count);
    assert_eq!(recovered.max_recursion_depth, budget.max_recursion_depth);
}

// ---------- ParseErrorCode coverage ----------

#[test]
fn parse_error_code_roundtrip_matches_all_variants() {
    for code in ParseErrorCode::ALL {
        let json = serde_json::to_string(&code).expect("serialize");
        let recovered: ParseErrorCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, code);
    }
}

// ---------- ParseEventMaterializationErrorCode ----------

#[test]
fn parse_event_materialization_error_code_as_str_is_nonempty() {
    let code = ParseEventMaterializationErrorCode::ParseFailedEventStream;
    assert!(!code.as_str().is_empty());
}

// ---------- helpers ----------

#[test]
fn parse_goal_helper_maps_correctly() {
    assert_eq!(parse_goal("script"), ParseGoal::Script);
    assert_eq!(parse_goal("module"), ParseGoal::Module);
}

#[test]
fn parse_error_code_helper_maps_all_codes() {
    let mappings = [
        ("empty_source", ParseErrorCode::EmptySource),
        ("invalid_goal", ParseErrorCode::InvalidGoal),
        ("unsupported_syntax", ParseErrorCode::UnsupportedSyntax),
        ("io_read_failed", ParseErrorCode::IoReadFailed),
        ("invalid_utf8", ParseErrorCode::InvalidUtf8),
        ("source_too_large", ParseErrorCode::SourceTooLarge),
        ("budget_exceeded", ParseErrorCode::BudgetExceeded),
    ];
    for (raw, expected) in mappings {
        assert_eq!(parse_error_code(raw), expected);
    }
}

#[test]
fn parse_budget_kind_helper_maps_all_kinds() {
    let mappings = [
        ("source_bytes", ParseBudgetKind::SourceBytes),
        ("token_count", ParseBudgetKind::TokenCount),
        ("recursion_depth", ParseBudgetKind::RecursionDepth),
    ];
    for (raw, expected) in mappings {
        assert_eq!(parse_budget_kind(raw), expected);
    }
}

// ---------- ParserOptions ----------

#[test]
fn parser_options_default_budget_serde_roundtrip() {
    let options = ParserOptions::default();
    let json = serde_json::to_string(&options).expect("serialize");
    let recovered: ParserOptions = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        recovered.budget.max_source_bytes,
        options.budget.max_source_bytes
    );
    assert_eq!(
        recovered.budget.max_token_count,
        options.budget.max_token_count
    );
    assert_eq!(
        recovered.budget.max_recursion_depth,
        options.budget.max_recursion_depth
    );
}

// ---------- ParseErrorCode ----------

#[test]
fn parse_error_code_all_as_str_is_nonempty() {
    for code in ParseErrorCode::ALL {
        let s = code.as_str();
        assert!(
            !s.is_empty(),
            "ParseErrorCode as_str should be nonempty for {code:?}"
        );
    }
}

// ---------- fixture ergonomics_slo ----------

#[test]
fn fixture_ergonomics_slo_keys_are_recognized() {
    let fixture = load_fixture();
    let known_keys: BTreeSet<&str> = [
        "integration_success_rate",
        "input_adapter_coverage",
        "migration_readability",
    ]
    .into_iter()
    .collect();
    for key in fixture.ergonomics_slo_millionths.keys() {
        assert!(
            known_keys.contains(key.as_str()),
            "unexpected ergonomics SLO key in fixture: {key}"
        );
    }
    assert!(
        !fixture.ergonomics_slo_millionths.is_empty(),
        "fixture must define at least one ergonomics SLO"
    );
}
