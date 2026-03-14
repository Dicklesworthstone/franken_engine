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

use std::fs;
use std::path::Path;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, ParseErrorCode, ParseEventKind, ParseEventMaterializationErrorCode,
    ParserOptions,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ReplayScenario {
    scenario_id: String,
    command: String,
    expected_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct EquivalenceCase {
    case_id: String,
    goal: String,
    source: String,
    corpus_tier: String,
    tamper_kind: String,
    expected_parse_error_code: Option<String>,
    expected_materialization_error_code: Option<String>,
    expect_statement_count: usize,
    expect_hash_parity: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MatrixDimensions {
    corpus_tiers: Vec<String>,
    seed_sweep: Vec<u64>,
    cross_arch_targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct ParserEventAstEquivalenceFixture {
    schema_version: String,
    contract_version: String,
    required_log_keys: Vec<String>,
    replay_command: String,
    matrix_dimensions: MatrixDimensions,
    cases: Vec<EquivalenceCase>,
    replay_scenarios: Vec<ReplayScenario>,
}

fn load_fixture() -> ParserEventAstEquivalenceFixture {
    let path = Path::new("tests/fixtures/parser_event_ast_equivalence_v1.json");
    let bytes = fs::read(path).expect("read parser event ast equivalence fixture");
    serde_json::from_slice(&bytes).expect("deserialize parser event ast equivalence fixture")
}

fn load_doc() -> String {
    let path = Path::new("../../docs/PARSER_EVENT_AST_EQUIVALENCE_REPLAY_CONTRACT.md");
    fs::read_to_string(path).expect("read parser event ast equivalence contract doc")
}

fn load_script() -> String {
    let path = Path::new("../../scripts/run_parser_event_ast_equivalence.sh");
    fs::read_to_string(path).expect("read parser event ast equivalence gate script")
}

fn parse_goal(goal: &str) -> ParseGoal {
    match goal {
        "script" => ParseGoal::Script,
        "module" => ParseGoal::Module,
        other => panic!("unsupported fixture goal: {other}"),
    }
}

fn parse_error_code(code: &str) -> ParseErrorCode {
    match code {
        "empty_source" => ParseErrorCode::EmptySource,
        "invalid_goal" => ParseErrorCode::InvalidGoal,
        "unsupported_syntax" => ParseErrorCode::UnsupportedSyntax,
        "io_read_failed" => ParseErrorCode::IoReadFailed,
        "invalid_utf8" => ParseErrorCode::InvalidUtf8,
        "source_too_large" => ParseErrorCode::SourceTooLarge,
        "budget_exceeded" => ParseErrorCode::BudgetExceeded,
        other => panic!("unsupported parse error code in fixture: {other}"),
    }
}

fn materialization_error_code(code: &str) -> ParseEventMaterializationErrorCode {
    match code {
        "parse_failed_event_stream" => ParseEventMaterializationErrorCode::ParseFailedEventStream,
        "statement_hash_mismatch" => ParseEventMaterializationErrorCode::StatementHashMismatch,
        "statement_count_mismatch" => ParseEventMaterializationErrorCode::StatementCountMismatch,
        "statement_index_mismatch" => ParseEventMaterializationErrorCode::StatementIndexMismatch,
        "statement_kind_mismatch" => ParseEventMaterializationErrorCode::StatementKindMismatch,
        "statement_span_mismatch" => ParseEventMaterializationErrorCode::StatementSpanMismatch,
        "source_hash_mismatch" => ParseEventMaterializationErrorCode::SourceHashMismatch,
        "ast_hash_mismatch" => ParseEventMaterializationErrorCode::AstHashMismatch,
        "missing_parse_started" => ParseEventMaterializationErrorCode::MissingParseStarted,
        "missing_parse_completed" => ParseEventMaterializationErrorCode::MissingParseCompleted,
        "invalid_event_sequence" => ParseEventMaterializationErrorCode::InvalidEventSequence,
        "goal_mismatch" => ParseEventMaterializationErrorCode::GoalMismatch,
        "mode_mismatch" => ParseEventMaterializationErrorCode::ModeMismatch,
        "inconsistent_event_envelope" => {
            ParseEventMaterializationErrorCode::InconsistentEventEnvelope
        }
        "source_parse_failed" => ParseEventMaterializationErrorCode::SourceParseFailed,
        "unsupported_contract_version" => {
            ParseEventMaterializationErrorCode::UnsupportedContractVersion
        }
        "unsupported_schema_version" => {
            ParseEventMaterializationErrorCode::UnsupportedSchemaVersion
        }
        other => panic!("unsupported materialization error code in fixture: {other}"),
    }
}

fn tamper_statement_hash_if_requested(
    case: &EquivalenceCase,
    event_ir: &mut frankenengine_engine::parser::ParseEventIr,
) {
    if case.tamper_kind != "statement_hash" {
        return;
    }

    let statement_event = event_ir
        .events
        .iter_mut()
        .find(|event| event.kind == ParseEventKind::StatementParsed)
        .expect("statement_hash tamper requires a statement event");

    statement_event.payload_hash =
        Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string());
}

fn emit_structured_events(fixture: &ParserEventAstEquivalenceFixture) -> Vec<Value> {
    fixture
        .cases
        .iter()
        .map(|case| {
            let outcome = if case.expected_materialization_error_code.is_some() {
                "fail"
            } else {
                "pass"
            };
            let error_code = case
                .expected_materialization_error_code
                .clone()
                .or_else(|| case.expected_parse_error_code.clone());

            json!({
                "schema_version": "franken-engine.parser-event-ast-equivalence.event.v1",
                "trace_id": format!("trace-parser-event-ast-equivalence-{}", case.case_id),
                "decision_id": format!("decision-parser-event-ast-equivalence-{}", case.case_id),
                "policy_id": "policy-parser-event-ast-equivalence-v1",
                "component": "parser_event_ast_equivalence_gate",
                "event": "scenario_evaluated",
                "scenario_id": case.case_id,
                "corpus_tier": case.corpus_tier,
                "outcome": outcome,
                "error_code": error_code,
                "replay_command": format!(
                    "PARSER_EVENT_AST_EQUIVALENCE_SCENARIO={} ./scripts/run_parser_event_ast_equivalence.sh test",
                    if case.expect_hash_parity { "parity" } else { "replay" }
                )
            })
        })
        .collect()
}

#[test]
fn parser_event_ast_equivalence_success_cases_have_hash_parity_and_stable_witnesses() {
    let fixture = load_fixture();
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    for case in &fixture.cases {
        if !case.expect_hash_parity || case.tamper_kind != "none" {
            continue;
        }

        let goal = parse_goal(&case.goal);
        let (parse_result, event_ir) =
            parser.parse_with_event_ir(case.source.as_str(), goal, &options);
        let syntax_tree = parse_result.expect("expected successful parse for parity case");
        let materialized = event_ir
            .materialize_from_source(case.source.as_str(), &options)
            .expect("expected successful materialization for parity case");

        assert!(event_ir.canonical_hash().starts_with("sha256:"));
        assert_eq!(
            materialized.statement_nodes.len(),
            case.expect_statement_count
        );
        assert_eq!(
            materialized.syntax_tree.canonical_hash(),
            syntax_tree.canonical_hash()
        );

        let (second_result, second_event_ir) =
            parser.parse_with_event_ir(case.source.as_str(), goal, &options);
        let second_syntax_tree = second_result.expect("expected successful second parse");
        let second_materialized = second_event_ir
            .materialize_from_source(case.source.as_str(), &options)
            .expect("expected successful second materialization");

        assert_eq!(event_ir.canonical_hash(), second_event_ir.canonical_hash());
        assert_eq!(materialized.root_node_id, second_materialized.root_node_id);
        assert_eq!(
            materialized.statement_nodes,
            second_materialized.statement_nodes
        );
        assert_eq!(
            second_materialized.syntax_tree.canonical_hash(),
            second_syntax_tree.canonical_hash()
        );
        assert_eq!(
            materialized.canonical_hash(),
            second_materialized.canonical_hash()
        );
    }
}

#[test]
fn parser_event_ast_equivalence_failure_case_has_replayable_error_codes() {
    let fixture = load_fixture();
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let case = fixture
        .cases
        .iter()
        .find(|case| case.case_id == "empty_source_failure_contract")
        .expect("fixture must include empty_source_failure_contract case");

    let goal = parse_goal(&case.goal);
    let (first_parse, first_event_ir) =
        parser.parse_with_event_ir(case.source.as_str(), goal, &options);
    let first_parse_err = first_parse.expect_err("empty source should fail parse");
    assert_eq!(
        first_parse_err.code,
        parse_error_code(
            case.expected_parse_error_code
                .as_deref()
                .expect("expected parse error code")
        )
    );

    let first_materialize_err = first_event_ir
        .materialize_from_source(case.source.as_str(), &options)
        .expect_err("empty-source event stream should fail materialization deterministically");
    assert_eq!(
        first_materialize_err.code,
        materialization_error_code(
            case.expected_materialization_error_code
                .as_deref()
                .expect("expected materialization error code")
        )
    );

    let (second_parse, second_event_ir) =
        parser.parse_with_event_ir(case.source.as_str(), goal, &options);
    let second_parse_err = second_parse.expect_err("second empty source parse should fail");
    let second_materialize_err = second_event_ir
        .materialize_from_source(case.source.as_str(), &options)
        .expect_err("second empty-source materialization should fail");

    assert_eq!(first_parse_err.code, second_parse_err.code);
    assert_eq!(first_materialize_err.code, second_materialize_err.code);
    assert_eq!(
        first_event_ir.canonical_hash(),
        second_event_ir.canonical_hash()
    );
    assert_eq!(case.expect_statement_count, 0);
}

#[test]
fn parser_event_ast_equivalence_tamper_detection_is_deterministic() {
    let fixture = load_fixture();
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions::default();

    let case = fixture
        .cases
        .iter()
        .find(|case| case.case_id == "tampered_statement_payload_hash")
        .expect("fixture must include tampered_statement_payload_hash case");
    let goal = parse_goal(&case.goal);

    let (parse_result, mut event_ir) =
        parser.parse_with_event_ir(case.source.as_str(), goal, &options);
    parse_result.expect("tamper case baseline parse should succeed");
    tamper_statement_hash_if_requested(case, &mut event_ir);

    let first_err = event_ir
        .materialize_from_source(case.source.as_str(), &options)
        .expect_err("tampered statement hash must fail materialization");
    assert_eq!(
        first_err.code,
        materialization_error_code(
            case.expected_materialization_error_code
                .as_deref()
                .expect("expected materialization error code")
        )
    );

    let (second_parse_result, mut second_event_ir) =
        parser.parse_with_event_ir(case.source.as_str(), goal, &options);
    second_parse_result.expect("second tamper baseline parse should succeed");
    tamper_statement_hash_if_requested(case, &mut second_event_ir);

    let second_err = second_event_ir
        .materialize_from_source(case.source.as_str(), &options)
        .expect_err("second tampered statement hash must fail materialization");

    assert_eq!(first_err.code, second_err.code);
    assert_eq!(first_err.sequence, second_err.sequence);
}

#[test]
fn parser_event_ast_equivalence_replay_scenarios_are_deterministic() {
    let fixture = load_fixture();

    assert_eq!(
        fixture.replay_command,
        "./scripts/e2e/parser_event_ast_equivalence_replay.sh"
    );

    let mut scenario_ids = fixture
        .replay_scenarios
        .iter()
        .map(|scenario| scenario.scenario_id.as_str())
        .collect::<Vec<_>>();
    scenario_ids.sort_unstable();
    assert_eq!(
        scenario_ids,
        ["full", "malformed", "matrix", "parity", "replay", "tamper"]
    );

    for scenario in &fixture.replay_scenarios {
        assert_eq!(scenario.expected_outcome, "pass");
        assert!(
            scenario
                .command
                .contains("./scripts/run_parser_event_ast_equivalence.sh test")
        );
        assert!(
            scenario
                .command
                .starts_with("PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=")
        );
        assert!(
            scenario.command.contains(&format!(
                "PARSER_EVENT_AST_EQUIVALENCE_SCENARIO={}",
                scenario.scenario_id
            )),
            "scenario command must encode its own scenario_id: {}",
            scenario.scenario_id
        );
    }
}

#[test]
fn parser_event_ast_equivalence_contract_doc_and_logs_are_well_formed() {
    let fixture = load_fixture();
    let doc = load_doc();

    assert!(doc.contains("bd-2mds.1.4.4"));
    assert!(doc.contains("./scripts/run_parser_event_ast_equivalence.sh ci"));
    assert!(doc.contains("./scripts/e2e/parser_event_ast_equivalence_replay.sh"));
    assert!(doc.contains("./scripts/e2e/parser_event_ast_equivalence_replay.sh matrix"));
    assert!(doc.contains("PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=matrix"));
    assert!(doc.contains("artifacts/parser_event_ast_equivalence/<timestamp>/run_manifest.json"));
    assert!(doc.contains("artifacts/parser_event_ast_equivalence/<timestamp>/matrix_summary.json"));

    let events = emit_structured_events(&fixture);
    assert_eq!(events.len(), fixture.cases.len());

    for event in events {
        for key in &fixture.required_log_keys {
            let value = event
                .get(key)
                .unwrap_or_else(|| panic!("missing required key in event: {key}"));
            if key == "error_code" {
                assert!(value.is_null() || value.as_str().is_some());
            } else {
                assert!(value.as_str().is_some_and(|text| !text.is_empty()));
            }
        }

        let schema_version = event
            .get("schema_version")
            .and_then(Value::as_str)
            .expect("schema_version must be a non-empty string");
        assert!(schema_version.starts_with("franken-engine.parser"));
    }
}

#[test]
fn parser_event_ast_equivalence_script_contains_fail_closed_rch_markers() {
    let script = load_script();
    let required_markers = [
        "rch_last_remote_exit_code",
        "rch_has_recoverable_artifact_timeout",
        "rch_reject_artifact_retrieval_failure",
        "Artifact retrieval failed",
        "rsync error: .*code 23",
        "running locally",
        "RCH-E326",
        "rch-remote-exit-marker-missing",
        "rch-artifact-retrieval-failed",
        "./scripts/e2e/parser_event_ast_equivalence_replay.sh",
    ];

    for marker in required_markers {
        assert!(
            script.contains(marker),
            "event->AST equivalence script missing fail-closed marker: {marker}"
        );
    }
}

// ---------- parse_goal helper ----------

#[test]
fn event_ast_parse_goal_script() {
    assert_eq!(parse_goal("script"), ParseGoal::Script);
}

#[test]
fn event_ast_parse_goal_module() {
    assert_eq!(parse_goal("module"), ParseGoal::Module);
}

#[test]
#[should_panic(expected = "unsupported fixture goal")]
fn event_ast_parse_goal_panics_on_unknown() {
    parse_goal("expression");
}

// ---------- parse_error_code helper ----------

#[test]
fn event_ast_parse_error_code_all_known() {
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

// ---------- materialization_error_code helper ----------

#[test]
fn event_ast_materialization_error_code_all_known() {
    let codes = [
        (
            "parse_failed_event_stream",
            ParseEventMaterializationErrorCode::ParseFailedEventStream,
        ),
        (
            "statement_hash_mismatch",
            ParseEventMaterializationErrorCode::StatementHashMismatch,
        ),
        (
            "statement_count_mismatch",
            ParseEventMaterializationErrorCode::StatementCountMismatch,
        ),
        (
            "statement_index_mismatch",
            ParseEventMaterializationErrorCode::StatementIndexMismatch,
        ),
        (
            "statement_kind_mismatch",
            ParseEventMaterializationErrorCode::StatementKindMismatch,
        ),
        (
            "statement_span_mismatch",
            ParseEventMaterializationErrorCode::StatementSpanMismatch,
        ),
        (
            "source_hash_mismatch",
            ParseEventMaterializationErrorCode::SourceHashMismatch,
        ),
        (
            "ast_hash_mismatch",
            ParseEventMaterializationErrorCode::AstHashMismatch,
        ),
        (
            "missing_parse_started",
            ParseEventMaterializationErrorCode::MissingParseStarted,
        ),
        (
            "missing_parse_completed",
            ParseEventMaterializationErrorCode::MissingParseCompleted,
        ),
        (
            "invalid_event_sequence",
            ParseEventMaterializationErrorCode::InvalidEventSequence,
        ),
        (
            "goal_mismatch",
            ParseEventMaterializationErrorCode::GoalMismatch,
        ),
        (
            "mode_mismatch",
            ParseEventMaterializationErrorCode::ModeMismatch,
        ),
        (
            "inconsistent_event_envelope",
            ParseEventMaterializationErrorCode::InconsistentEventEnvelope,
        ),
        (
            "source_parse_failed",
            ParseEventMaterializationErrorCode::SourceParseFailed,
        ),
        (
            "unsupported_contract_version",
            ParseEventMaterializationErrorCode::UnsupportedContractVersion,
        ),
        (
            "unsupported_schema_version",
            ParseEventMaterializationErrorCode::UnsupportedSchemaVersion,
        ),
    ];
    for (raw, expected) in codes {
        assert_eq!(materialization_error_code(raw), expected);
    }
}

// ---------- fixture loading ----------

#[test]
fn fixture_schema_version_is_v1() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.schema_version,
        "franken-engine.parser-event-ast-equivalence.v1"
    );
}

#[test]
fn fixture_has_both_parity_and_tamper_cases() {
    let fixture = load_fixture();
    assert!(fixture.cases.iter().any(|c| c.expect_hash_parity));
    assert!(fixture.cases.iter().any(|c| c.tamper_kind != "none"));
}

#[test]
fn fixture_case_ids_are_unique() {
    let fixture = load_fixture();
    let mut ids = std::collections::BTreeSet::new();
    for case in &fixture.cases {
        assert!(ids.insert(case.case_id.clone()), "duplicate case id");
    }
}

#[test]
fn parser_event_ast_equivalence_matrix_dimensions_contract_is_complete() {
    let fixture = load_fixture();
    assert_eq!(
        fixture.matrix_dimensions.corpus_tiers,
        vec![
            "core".to_string(),
            "edge".to_string(),
            "adversarial".to_string()
        ]
    );
    assert_eq!(fixture.matrix_dimensions.seed_sweep, vec![17, 43, 101]);
    assert_eq!(
        fixture.matrix_dimensions.cross_arch_targets,
        vec![
            "x86_64-unknown-linux-gnu".to_string(),
            "aarch64-unknown-linux-gnu".to_string()
        ]
    );
}

#[test]
fn parser_event_ast_equivalence_cases_cover_required_matrix_tiers() {
    let fixture = load_fixture();
    let required = fixture
        .matrix_dimensions
        .corpus_tiers
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let observed = fixture
        .cases
        .iter()
        .map(|case| case.corpus_tier.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    for tier in &required {
        assert!(
            observed.contains(tier),
            "missing required matrix corpus tier in cases: {tier}"
        );
    }
    for case in &fixture.cases {
        assert!(
            required.contains(case.corpus_tier.as_str()),
            "case uses unknown matrix corpus tier: {}",
            case.corpus_tier
        );
    }
}

// ---------- emit_structured_events ----------

#[test]
fn structured_events_count_matches_cases() {
    let fixture = load_fixture();
    let events = emit_structured_events(&fixture);
    assert_eq!(events.len(), fixture.cases.len());
}

#[test]
fn structured_events_have_trace_prefix() {
    let fixture = load_fixture();
    let events = emit_structured_events(&fixture);
    for event in &events {
        let trace_id = event["trace_id"].as_str().unwrap();
        assert!(trace_id.starts_with("trace-parser-event-ast-equivalence-"));
    }
}

// ---------- replay scenarios ----------

#[test]
fn replay_scenarios_have_six_entries() {
    let fixture = load_fixture();
    assert_eq!(fixture.replay_scenarios.len(), 6);
}

#[test]
fn replay_scenarios_all_expect_pass() {
    let fixture = load_fixture();
    for scenario in &fixture.replay_scenarios {
        assert_eq!(scenario.expected_outcome, "pass");
    }
}

#[test]
fn fixture_has_nonempty_replay_command() {
    let fixture = load_fixture();
    assert!(!fixture.replay_command.trim().is_empty());
}

#[test]
fn fixture_cases_have_nonempty_case_ids() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        assert!(
            !case.case_id.trim().is_empty(),
            "case must have non-empty case_id"
        );
    }
}

#[test]
fn fixture_required_log_keys_are_nonempty() {
    let fixture = load_fixture();
    assert!(!fixture.required_log_keys.is_empty());
    for key in &fixture.required_log_keys {
        assert!(!key.trim().is_empty());
    }
}

#[test]
fn fixture_has_nonempty_schema_version() {
    let fixture = load_fixture();
    assert!(!fixture.schema_version.trim().is_empty());
}

#[test]
fn fixture_has_nonempty_contract_version() {
    let fixture = load_fixture();
    assert!(!fixture.contract_version.trim().is_empty());
}

#[test]
fn fixture_deterministic_double_load() {
    let a = load_fixture();
    let b = load_fixture();
    assert_eq!(a.schema_version, b.schema_version);
    assert_eq!(a.contract_version, b.contract_version);
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde depth, event determinism, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn structured_events_pass_cases_have_no_error_code() {
    let fixture = load_fixture();
    let events = emit_structured_events(&fixture);
    for (event, case) in events.iter().zip(fixture.cases.iter()) {
        let outcome = event["outcome"].as_str().unwrap();
        if outcome == "pass" {
            assert!(
                event["error_code"].is_null(),
                "pass-outcome event for case {} must have null error_code",
                case.case_id
            );
        }
    }
}

#[test]
fn structured_events_fail_cases_have_error_code() {
    let fixture = load_fixture();
    let events = emit_structured_events(&fixture);
    for (event, case) in events.iter().zip(fixture.cases.iter()) {
        let outcome = event["outcome"].as_str().unwrap();
        if outcome == "fail" {
            assert!(
                event["error_code"].as_str().is_some(),
                "fail-outcome event for case {} must have non-null error_code",
                case.case_id
            );
        }
    }
}

#[test]
fn parse_error_code_serde_round_trip() {
    let codes = [
        ParseErrorCode::EmptySource,
        ParseErrorCode::InvalidGoal,
        ParseErrorCode::UnsupportedSyntax,
        ParseErrorCode::IoReadFailed,
        ParseErrorCode::InvalidUtf8,
        ParseErrorCode::SourceTooLarge,
        ParseErrorCode::BudgetExceeded,
    ];
    for code in &codes {
        let json = serde_json::to_string(code).expect("serialize");
        let recovered: ParseErrorCode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*code, recovered);
    }
}

#[test]
fn materialization_error_code_serde_round_trip() {
    let codes = [
        ParseEventMaterializationErrorCode::ParseFailedEventStream,
        ParseEventMaterializationErrorCode::StatementHashMismatch,
        ParseEventMaterializationErrorCode::SourceHashMismatch,
        ParseEventMaterializationErrorCode::AstHashMismatch,
        ParseEventMaterializationErrorCode::MissingParseStarted,
        ParseEventMaterializationErrorCode::InvalidEventSequence,
        ParseEventMaterializationErrorCode::GoalMismatch,
    ];
    for code in &codes {
        let json = serde_json::to_string(code).expect("serialize");
        let recovered: ParseEventMaterializationErrorCode =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*code, recovered);
    }
}

#[test]
fn parity_cases_all_have_tamper_kind_none() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        if case.expect_hash_parity {
            assert_eq!(
                case.tamper_kind, "none",
                "parity case {} should have tamper_kind=none but got {}",
                case.case_id, case.tamper_kind
            );
        }
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment batch: source-module types, serde, Display, Ord,
// canonical hashing, edge cases, inventory contract semantics
// ────────────────────────────────────────────────────────────

#[test]
fn corpus_tier_serde_round_trip_all_variants() {
    use frankenengine_engine::parser_event_ast_equivalence::CorpusTier;
    for tier in CorpusTier::ALL {
        let json = serde_json::to_string(tier).expect("serialize");
        let recovered: CorpusTier = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*tier, recovered);
        // Verify snake_case encoding
        let raw: String = serde_json::from_str(&json).expect("deserialize as string");
        assert_eq!(raw, tier.as_str());
    }
}

#[test]
fn corpus_tier_display_matches_as_str() {
    use frankenengine_engine::parser_event_ast_equivalence::CorpusTier;
    for tier in CorpusTier::ALL {
        assert_eq!(format!("{tier}"), tier.as_str());
    }
}

#[test]
fn corpus_tier_ordering_core_lt_edge_lt_adversarial() {
    use frankenengine_engine::parser_event_ast_equivalence::CorpusTier;
    assert!(CorpusTier::Core < CorpusTier::Edge);
    assert!(CorpusTier::Edge < CorpusTier::Adversarial);
    assert!(CorpusTier::Core < CorpusTier::Adversarial);
}

#[test]
fn corpus_tier_clone_and_copy() {
    use frankenengine_engine::parser_event_ast_equivalence::CorpusTier;
    let tier = CorpusTier::Edge;
    let cloned = tier.clone();
    let copied = tier;
    assert_eq!(cloned, copied);
    assert_eq!(tier, CorpusTier::Edge);
}

#[test]
fn corpus_tier_btreemap_key_ordering() {
    use frankenengine_engine::parser_event_ast_equivalence::CorpusTier;
    use std::collections::BTreeMap;
    let mut map = BTreeMap::new();
    map.insert(CorpusTier::Adversarial, 3);
    map.insert(CorpusTier::Core, 1);
    map.insert(CorpusTier::Edge, 2);
    let keys: Vec<_> = map.keys().collect();
    assert_eq!(
        keys,
        vec![
            &CorpusTier::Core,
            &CorpusTier::Edge,
            &CorpusTier::Adversarial
        ]
    );
}

#[test]
fn tamper_kind_serde_round_trip_all_variants() {
    use frankenengine_engine::parser_event_ast_equivalence::TamperKind;
    for kind in TamperKind::ALL {
        let json = serde_json::to_string(kind).expect("serialize");
        let recovered: TamperKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*kind, recovered);
        let raw: String = serde_json::from_str(&json).expect("deserialize as string");
        assert_eq!(raw, kind.as_str());
    }
}

#[test]
fn tamper_kind_display_matches_as_str() {
    use frankenengine_engine::parser_event_ast_equivalence::TamperKind;
    for kind in TamperKind::ALL {
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

#[test]
fn tamper_kind_ordering_none_lt_statement_hash() {
    use frankenengine_engine::parser_event_ast_equivalence::TamperKind;
    assert!(TamperKind::None < TamperKind::StatementHash);
    assert!(TamperKind::StatementHash < TamperKind::EventDeletion);
    assert!(TamperKind::EventDeletion < TamperKind::SequenceReorder);
}

#[test]
fn equivalence_verdict_serde_round_trip_all_variants() {
    use frankenengine_engine::parser_event_ast_equivalence::EquivalenceVerdict;
    for v in [EquivalenceVerdict::Pass, EquivalenceVerdict::Fail] {
        let json = serde_json::to_string(&v).expect("serialize");
        let recovered: EquivalenceVerdict = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, recovered);
    }
}

#[test]
fn equivalence_verdict_display_matches_as_str() {
    use frankenengine_engine::parser_event_ast_equivalence::EquivalenceVerdict;
    assert_eq!(format!("{}", EquivalenceVerdict::Pass), "pass");
    assert_eq!(format!("{}", EquivalenceVerdict::Fail), "fail");
}

#[test]
fn equivalence_specimen_serde_round_trip() {
    use frankenengine_engine::parser_event_ast_equivalence::{
        EquivalenceSpecimen, equivalence_corpus,
    };
    let corpus = equivalence_corpus();
    for spec in &corpus {
        let json = serde_json::to_string(spec).expect("serialize specimen");
        let recovered: EquivalenceSpecimen =
            serde_json::from_str(&json).expect("deserialize specimen");
        assert_eq!(spec.specimen_id, recovered.specimen_id);
        assert_eq!(spec.goal, recovered.goal);
        assert_eq!(spec.corpus_tier, recovered.corpus_tier);
        assert_eq!(spec.tamper_kind, recovered.tamper_kind);
        assert_eq!(spec.expect_parity, recovered.expect_parity);
        assert_eq!(
            spec.expected_statement_count,
            recovered.expected_statement_count
        );
    }
}

#[test]
fn specimen_evidence_serde_round_trip_all_fields() {
    use frankenengine_engine::parser_event_ast_equivalence::{
        CorpusTier, EquivalenceVerdict, SpecimenEvidence, TamperKind,
    };
    let ev = SpecimenEvidence {
        specimen_id: "test_specimen".to_string(),
        corpus_tier: CorpusTier::Edge,
        tamper_kind: TamperKind::StatementHash,
        verdict: EquivalenceVerdict::Fail,
        event_ir_hash: "sha256:abcd1234".to_string(),
        materialized_ast_hash: Some("sha256:deadbeef".to_string()),
        original_ast_hash: Some("sha256:cafebabe".to_string()),
        parse_error_code: None,
        materialization_error_code: Some("statement_hash_mismatch".to_string()),
        statement_count: 3,
        hash_parity: false,
        replay_stable: true,
    };
    let json = serde_json::to_string(&ev).expect("serialize");
    let recovered: SpecimenEvidence = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ev.specimen_id, recovered.specimen_id);
    assert_eq!(ev.corpus_tier, recovered.corpus_tier);
    assert_eq!(ev.tamper_kind, recovered.tamper_kind);
    assert_eq!(ev.verdict, recovered.verdict);
    assert_eq!(ev.event_ir_hash, recovered.event_ir_hash);
    assert_eq!(ev.materialized_ast_hash, recovered.materialized_ast_hash);
    assert_eq!(ev.original_ast_hash, recovered.original_ast_hash);
    assert_eq!(ev.parse_error_code, recovered.parse_error_code);
    assert_eq!(
        ev.materialization_error_code,
        recovered.materialization_error_code
    );
    assert_eq!(ev.statement_count, recovered.statement_count);
    assert_eq!(ev.hash_parity, recovered.hash_parity);
    assert_eq!(ev.replay_stable, recovered.replay_stable);
}

#[test]
fn specimen_evidence_canonical_hash_changes_with_different_verdicts() {
    use frankenengine_engine::parser_event_ast_equivalence::{
        CorpusTier, EquivalenceVerdict, SpecimenEvidence, TamperKind,
    };
    let base = SpecimenEvidence {
        specimen_id: "canonical_diff_test".to_string(),
        corpus_tier: CorpusTier::Core,
        tamper_kind: TamperKind::None,
        verdict: EquivalenceVerdict::Pass,
        event_ir_hash: "sha256:0000".to_string(),
        materialized_ast_hash: None,
        original_ast_hash: None,
        parse_error_code: None,
        materialization_error_code: None,
        statement_count: 1,
        hash_parity: true,
        replay_stable: true,
    };
    let mut altered = base.clone();
    altered.verdict = EquivalenceVerdict::Fail;
    assert_ne!(base.canonical_hash(), altered.canonical_hash());
}

#[test]
fn specimen_evidence_canonical_bytes_nonempty() {
    use frankenengine_engine::parser_event_ast_equivalence::{
        CorpusTier, EquivalenceVerdict, SpecimenEvidence, TamperKind,
    };
    let ev = SpecimenEvidence {
        specimen_id: "bytes_test".to_string(),
        corpus_tier: CorpusTier::Adversarial,
        tamper_kind: TamperKind::EventDeletion,
        verdict: EquivalenceVerdict::Fail,
        event_ir_hash: "sha256:ff".to_string(),
        materialized_ast_hash: None,
        original_ast_hash: None,
        parse_error_code: None,
        materialization_error_code: Some("statement_count_mismatch".to_string()),
        statement_count: 0,
        hash_parity: false,
        replay_stable: false,
    };
    let bytes = ev.canonical_bytes();
    assert!(!bytes.is_empty());
}

#[test]
fn equivalence_inventory_contract_satisfied_logic() {
    use frankenengine_engine::parser_event_ast_equivalence::{EquivalenceInventory, TierSummary};
    use std::collections::BTreeMap;

    // Satisfied: total > 0, failed == 0, replay_stable_count == total
    let mut per_tier = BTreeMap::new();
    per_tier.insert(
        "core".to_string(),
        TierSummary {
            total: 5,
            passed: 5,
            failed: 0,
        },
    );
    let inv = EquivalenceInventory {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        policy_id: "policy".to_string(),
        total: 5,
        passed: 5,
        failed: 0,
        parity_verified: 3,
        tamper_detected: 2,
        replay_stable_count: 5,
        per_tier,
        evidence: vec![],
    };
    assert!(inv.contract_satisfied());
}

#[test]
fn equivalence_inventory_contract_not_satisfied_when_failed_nonzero() {
    use frankenengine_engine::parser_event_ast_equivalence::{EquivalenceInventory, TierSummary};
    use std::collections::BTreeMap;

    let mut per_tier = BTreeMap::new();
    per_tier.insert(
        "core".to_string(),
        TierSummary {
            total: 5,
            passed: 4,
            failed: 1,
        },
    );
    let inv = EquivalenceInventory {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        policy_id: "policy".to_string(),
        total: 5,
        passed: 4,
        failed: 1,
        parity_verified: 3,
        tamper_detected: 1,
        replay_stable_count: 5,
        per_tier,
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn equivalence_inventory_contract_not_satisfied_when_empty() {
    use frankenengine_engine::parser_event_ast_equivalence::EquivalenceInventory;
    use std::collections::BTreeMap;

    let inv = EquivalenceInventory {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        policy_id: "policy".to_string(),
        total: 0,
        passed: 0,
        failed: 0,
        parity_verified: 0,
        tamper_detected: 0,
        replay_stable_count: 0,
        per_tier: BTreeMap::new(),
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn equivalence_inventory_contract_not_satisfied_when_replay_unstable() {
    use frankenengine_engine::parser_event_ast_equivalence::{EquivalenceInventory, TierSummary};
    use std::collections::BTreeMap;

    let mut per_tier = BTreeMap::new();
    per_tier.insert(
        "core".to_string(),
        TierSummary {
            total: 5,
            passed: 5,
            failed: 0,
        },
    );
    let inv = EquivalenceInventory {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        policy_id: "policy".to_string(),
        total: 5,
        passed: 5,
        failed: 0,
        parity_verified: 3,
        tamper_detected: 2,
        replay_stable_count: 4, // != total
        per_tier,
        evidence: vec![],
    };
    assert!(!inv.contract_satisfied());
}

#[test]
fn equivalence_inventory_serde_round_trip_full() {
    use frankenengine_engine::parser_event_ast_equivalence::run_equivalence_corpus;
    let inventory = run_equivalence_corpus();
    let json = serde_json::to_string_pretty(&inventory).expect("serialize");
    let recovered: frankenengine_engine::parser_event_ast_equivalence::EquivalenceInventory =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(inventory, recovered);
}

#[test]
fn equivalence_inventory_canonical_hash_prefix_and_length() {
    use frankenengine_engine::parser_event_ast_equivalence::run_equivalence_corpus;
    let inventory = run_equivalence_corpus();
    let hash = inventory.canonical_hash();
    assert!(hash.starts_with("sha256:"));
    // sha256 hex = 64 chars + "sha256:" prefix = 71 chars
    assert_eq!(hash.len(), 71);
}

#[test]
fn equivalence_run_manifest_serde_round_trip_full() {
    use frankenengine_engine::parser_event_ast_equivalence::{
        build_manifest, run_equivalence_corpus,
    };
    let inventory = run_equivalence_corpus();
    let manifest = build_manifest(
        &inventory,
        "trace-serde-test",
        "decision-serde-test",
        vec!["path/a.json".to_string(), "path/b.json".to_string()],
    );
    let json = serde_json::to_string(&manifest).expect("serialize");
    let recovered: frankenengine_engine::parser_event_ast_equivalence::EquivalenceRunManifest =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(manifest, recovered);
}

#[test]
fn equivalence_run_manifest_canonical_hash_changes_with_different_trace() {
    use frankenengine_engine::parser_event_ast_equivalence::{
        build_manifest, run_equivalence_corpus,
    };
    let inventory = run_equivalence_corpus();
    let m1 = build_manifest(&inventory, "trace-a", "decision-a", vec![]);
    let m2 = build_manifest(&inventory, "trace-b", "decision-a", vec![]);
    assert_ne!(m1.canonical_hash(), m2.canonical_hash());
}

#[test]
fn equivalence_run_manifest_uses_constants() {
    use frankenengine_engine::parser_event_ast_equivalence::{
        BEAD_ID, COMPONENT, MANIFEST_SCHEMA_VERSION, POLICY_ID, build_manifest,
        run_equivalence_corpus,
    };
    let inventory = run_equivalence_corpus();
    let manifest = build_manifest(&inventory, "t", "d", vec![]);
    assert_eq!(manifest.schema_version, MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest.policy_id, POLICY_ID);
    assert_eq!(manifest.component, COMPONENT);
    assert_eq!(manifest.bead_id, BEAD_ID);
}

#[test]
fn equivalence_event_serde_round_trip() {
    use frankenengine_engine::parser_event_ast_equivalence::{
        EquivalenceEvent, generate_events, run_equivalence_corpus,
    };
    let inventory = run_equivalence_corpus();
    let events = generate_events(&inventory);
    for event in &events {
        let json = serde_json::to_string(event).expect("serialize event");
        let recovered: EquivalenceEvent = serde_json::from_str(&json).expect("deserialize event");
        assert_eq!(event.specimen_id, recovered.specimen_id);
        assert_eq!(event.outcome, recovered.outcome);
        assert_eq!(event.error_code, recovered.error_code);
        assert_eq!(event.schema_version, recovered.schema_version);
    }
}

#[test]
fn generate_events_outcomes_match_evidence_verdicts() {
    use frankenengine_engine::parser_event_ast_equivalence::{
        generate_events, run_equivalence_corpus,
    };
    let inventory = run_equivalence_corpus();
    let events = generate_events(&inventory);
    for (event, ev) in events.iter().zip(inventory.evidence.iter()) {
        assert_eq!(event.outcome, ev.verdict.as_str());
        assert_eq!(event.specimen_id, ev.specimen_id);
        assert_eq!(event.corpus_tier, ev.corpus_tier.as_str());
    }
}

#[test]
fn tier_summary_serde_round_trip() {
    use frankenengine_engine::parser_event_ast_equivalence::TierSummary;
    let ts = TierSummary {
        total: 10,
        passed: 7,
        failed: 3,
    };
    let json = serde_json::to_string(&ts).expect("serialize");
    let recovered: TierSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ts, recovered);
}

#[test]
fn tier_summary_debug_is_nonempty() {
    use frankenengine_engine::parser_event_ast_equivalence::TierSummary;
    let ts = TierSummary {
        total: 0,
        passed: 0,
        failed: 0,
    };
    let dbg = format!("{ts:?}");
    assert!(dbg.contains("TierSummary"));
}

#[test]
fn fixture_tamper_cases_have_expected_materialization_error() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        if case.tamper_kind != "none" {
            assert!(
                case.expected_materialization_error_code.is_some(),
                "tamper case {} should have expected_materialization_error_code",
                case.case_id
            );
        }
    }
}

#[test]
fn fixture_failure_cases_with_parse_error_have_zero_statement_count() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        // Cases that expect a parse error should have statement_count=0
        // (the source never successfully parsed).
        if case.expected_parse_error_code.is_some() {
            assert_eq!(
                case.expect_statement_count, 0,
                "failure case {} with parse error should have expect_statement_count=0 but got {}",
                case.case_id, case.expect_statement_count
            );
        }
    }
}

#[test]
fn structured_events_decision_id_prefix() {
    let fixture = load_fixture();
    let events = emit_structured_events(&fixture);
    for event in &events {
        let decision_id = event["decision_id"].as_str().unwrap();
        assert!(
            decision_id.starts_with("decision-parser-event-ast-equivalence-"),
            "decision_id should have expected prefix: {decision_id}"
        );
    }
}

#[test]
fn structured_events_policy_id_is_consistent() {
    let fixture = load_fixture();
    let events = emit_structured_events(&fixture);
    for event in &events {
        let policy_id = event["policy_id"].as_str().unwrap();
        assert_eq!(policy_id, "policy-parser-event-ast-equivalence-v1");
    }
}

#[test]
fn structured_events_component_field_is_gate() {
    let fixture = load_fixture();
    let events = emit_structured_events(&fixture);
    for event in &events {
        let component = event["component"].as_str().unwrap();
        assert_eq!(component, "parser_event_ast_equivalence_gate");
    }
}

#[test]
fn fixture_replay_scenario_ids_are_unique() {
    let fixture = load_fixture();
    let mut ids = std::collections::BTreeSet::new();
    for scenario in &fixture.replay_scenarios {
        assert!(
            ids.insert(scenario.scenario_id.clone()),
            "duplicate replay scenario id: {}",
            scenario.scenario_id
        );
    }
}

#[test]
fn fixture_cases_goals_are_script_or_module() {
    let fixture = load_fixture();
    for case in &fixture.cases {
        assert!(
            case.goal == "script" || case.goal == "module",
            "unexpected goal in case {}: {}",
            case.case_id,
            case.goal
        );
    }
}

#[test]
fn equivalence_corpus_source_module_covers_all_tamper_kinds() {
    use frankenengine_engine::parser_event_ast_equivalence::{TamperKind, equivalence_corpus};
    let corpus = equivalence_corpus();
    let observed: std::collections::BTreeSet<_> = corpus.iter().map(|s| s.tamper_kind).collect();
    for kind in TamperKind::ALL {
        assert!(
            observed.contains(kind),
            "corpus missing tamper kind: {kind}"
        );
    }
}

#[test]
fn run_corpus_all_evidence_replay_stable() {
    use frankenengine_engine::parser_event_ast_equivalence::run_equivalence_corpus;
    let inventory = run_equivalence_corpus();
    for ev in &inventory.evidence {
        assert!(
            ev.replay_stable,
            "specimen {} should be replay stable",
            ev.specimen_id
        );
    }
}

#[test]
fn constants_fixed_one_is_million() {
    use frankenengine_engine::parser_event_ast_equivalence::FIXED_ONE;
    assert_eq!(FIXED_ONE, 1_000_000);
}
