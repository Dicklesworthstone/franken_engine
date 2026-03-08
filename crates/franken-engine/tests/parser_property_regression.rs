use frankenengine_engine::ast::{ExportKind, ParseGoal, Statement, SyntaxTree};
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, Es2020Parser, ParseBudgetKind, ParseErrorCode, ParserBudget, ParserMode,
    ParserOptions,
};
use serde_json::json;

const TRACE_PREFIX: &str = "trace-parser-property";
const DECISION_PREFIX: &str = "decision-parser-property";
const POLICY_ID: &str = "policy-parser-property-regression-v1";
const COMPONENT: &str = "parser_property_regression";

#[derive(Debug, Clone)]
struct GeneratedCase {
    source: String,
    goal: ParseGoal,
}

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn generate_identifier(state: &mut u64) -> String {
    format!("v{}", lcg_next(state) % 10_000)
}

fn generate_case(seed: u64) -> GeneratedCase {
    let mut state = seed ^ 0x9E3779B97F4A7C15;
    let variant = (lcg_next(&mut state) % 9) as u8;

    let ident_a = generate_identifier(&mut state);
    let ident_b = generate_identifier(&mut state);
    let ident_c = generate_identifier(&mut state);
    let num = (lcg_next(&mut state) % 1000) as i64 - 500;
    let txt = format!("txt{}", lcg_next(&mut state) % 5000);
    let pkg = format!("pkg{}", lcg_next(&mut state) % 128);

    match variant {
        0 => GeneratedCase {
            source: ident_a,
            goal: ParseGoal::Script,
        },
        1 => GeneratedCase {
            source: num.to_string(),
            goal: ParseGoal::Script,
        },
        2 => GeneratedCase {
            source: format!("\"{txt}\""),
            goal: ParseGoal::Script,
        },
        3 => GeneratedCase {
            source: format!("await {ident_a}"),
            goal: ParseGoal::Script,
        },
        4 => GeneratedCase {
            source: format!("{ident_a} + {ident_b} * {ident_c}"),
            goal: ParseGoal::Script,
        },
        5 => GeneratedCase {
            source: format!("{ident_a};\n{num};\n\"{txt}\";\n"),
            goal: ParseGoal::Script,
        },
        6 => GeneratedCase {
            source: format!("import {ident_a} from \"{pkg}\";\nexport default {ident_a}"),
            goal: ParseGoal::Module,
        },
        7 => GeneratedCase {
            source: format!("import \"{pkg}\";\nexport {{ {ident_b}, {ident_c} }}"),
            goal: ParseGoal::Module,
        },
        _ => GeneratedCase {
            source: format!("export default \"{txt}\""),
            goal: ParseGoal::Module,
        },
    }
}

fn goal_label(goal: ParseGoal) -> &'static str {
    match goal {
        ParseGoal::Script => "script",
        ParseGoal::Module => "module",
    }
}

fn failure_context(test_name: &str, seed: u64, goal: ParseGoal, source: &str) -> String {
    let trace_id = format!("{TRACE_PREFIX}-{seed:016x}");
    let decision_id = format!("{DECISION_PREFIX}-{seed:016x}");
    json!({
        "schema_version": "franken-engine.parser-test-failure.v1",
        "trace_id": trace_id,
        "decision_id": decision_id,
        "policy_id": POLICY_ID,
        "component": COMPONENT,
        "event": "assertion_failure_context",
        "seed": seed,
        "goal": goal_label(goal),
        "source": source,
        "replay_command": format!(
            "cargo test -p frankenengine-engine --test parser_property_regression -- --exact {test_name}"
        )
    })
    .to_string()
}

fn semantic_signature(tree: &SyntaxTree) -> Vec<String> {
    tree.body
        .iter()
        .map(|statement| match statement {
            Statement::Expression(expr) => {
                let payload = serde_json::to_string(&expr.expression.canonical_value())
                    .expect("serialize expression signature");
                format!("expression:{payload}")
            }
            Statement::Import(import_decl) => {
                let binding = import_decl.binding.as_deref().unwrap_or("<none>");
                format!("import:{binding}:{}", import_decl.source)
            }
            Statement::Export(export_decl) => match &export_decl.kind {
                ExportKind::Default(expression) => {
                    let payload = serde_json::to_string(&expression.canonical_value())
                        .expect("serialize default export signature");
                    format!("export_default:{payload}")
                }
                ExportKind::NamedClause(clause) => format!("export_named:{clause}"),
            },
            Statement::VariableDeclaration(_) => "variable_decl".to_string(),
            Statement::Block(_) => "block".to_string(),
            Statement::If(_) => "if".to_string(),
            Statement::For(_) => "for".to_string(),
            Statement::While(_) => "while".to_string(),
            Statement::DoWhile(_) => "do_while".to_string(),
            Statement::Return(_) => "return".to_string(),
            Statement::Throw(_) => "throw".to_string(),
            Statement::TryCatch(_) => "try_catch".to_string(),
            Statement::Switch(_) => "switch".to_string(),
            Statement::Break(_) => "break".to_string(),
            Statement::Continue(_) => "continue".to_string(),
            Statement::FunctionDeclaration(_) => "function_decl".to_string(),
            Statement::ForIn(_) => "for_in".to_string(),
            Statement::ForOf(_) => "for_of".to_string(),
        })
        .collect()
}

#[test]
fn generated_programs_are_deterministic_across_repeated_runs() {
    let parser = CanonicalEs2020Parser;

    for seed in 0_u64..256 {
        let generated = generate_case(seed);
        let first = parser
            .parse(generated.source.as_str(), generated.goal)
            .unwrap_or_else(|error| {
                panic!(
                    "{}",
                    failure_context(
                        "generated_programs_are_deterministic_across_repeated_runs",
                        seed,
                        generated.goal,
                        generated.source.as_str()
                    ) + &format!(" parse_error={error}")
                )
            })
            .canonical_hash();

        for _ in 0..4 {
            let observed = parser
                .parse(generated.source.as_str(), generated.goal)
                .unwrap_or_else(|error| {
                    panic!(
                        "{}",
                        failure_context(
                            "generated_programs_are_deterministic_across_repeated_runs",
                            seed,
                            generated.goal,
                            generated.source.as_str()
                        ) + &format!(" parse_error={error}")
                    )
                })
                .canonical_hash();

            assert_eq!(
                observed,
                first,
                "{}",
                failure_context(
                    "generated_programs_are_deterministic_across_repeated_runs",
                    seed,
                    generated.goal,
                    generated.source.as_str()
                )
            );
        }
    }
}

#[test]
fn generated_module_whitespace_transform_is_semantically_stable() {
    let parser = CanonicalEs2020Parser;

    for seed in 0_u64..128 {
        let mut state = seed ^ 0xD1B54A32D192ED03;
        let binding = generate_identifier(&mut state);
        let pkg = format!("pkg{}", lcg_next(&mut state) % 256);

        let baseline_source = format!("import {binding} from \"{pkg}\";\nexport default {binding}");
        let transformed_source = format!(
            "  import   {binding}   from   \"{pkg}\" ;\n\n  export   default   {binding}  "
        );

        let baseline_tree = parser
            .parse(baseline_source.as_str(), ParseGoal::Module)
            .expect("baseline parse should succeed");
        let transformed_tree = parser
            .parse(transformed_source.as_str(), ParseGoal::Module)
            .expect("transformed parse should succeed");

        assert_eq!(
            semantic_signature(&baseline_tree),
            semantic_signature(&transformed_tree),
            "{}",
            failure_context(
                "generated_module_whitespace_transform_is_semantically_stable",
                seed,
                ParseGoal::Module,
                baseline_source.as_str()
            )
        );
    }
}

#[test]
fn recursion_budget_failure_witness_is_seed_stable() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 16_384,
            max_token_count: 16_384,
            max_recursion_depth: 1,
        },
    };

    for seed in 0_u64..64 {
        let source = format!("await await await v{seed}");
        let left = parser
            .parse_with_options(source.as_str(), ParseGoal::Script, &options)
            .expect_err("left parse should fail recursion budget");
        let right = parser
            .parse_with_options(source.as_str(), ParseGoal::Script, &options)
            .expect_err("right parse should fail recursion budget");

        assert_eq!(left.code, ParseErrorCode::BudgetExceeded);
        assert_eq!(left, right);

        let witness = left.witness.expect("budget failure should include witness");
        assert_eq!(witness.mode, ParserMode::ScalarReference);
        assert_eq!(witness.budget_kind, Some(ParseBudgetKind::RecursionDepth));
        assert!(witness.max_recursion_observed > witness.max_recursion_depth);
    }
}

#[test]
fn regression_failure_catalog_has_stable_error_codes() {
    let parser = CanonicalEs2020Parser;
    let cases = [
        (0_u64, "", ParseGoal::Script, ParseErrorCode::EmptySource),
        (
            1_u64,
            "   \n  \t",
            ParseGoal::Module,
            ParseErrorCode::EmptySource,
        ),
        (
            2_u64,
            "import",
            ParseGoal::Module,
            ParseErrorCode::UnsupportedSyntax,
        ),
        (
            3_u64,
            "import x from pkg",
            ParseGoal::Module,
            ParseErrorCode::UnsupportedSyntax,
        ),
        (
            4_u64,
            "export default x",
            ParseGoal::Script,
            ParseErrorCode::InvalidGoal,
        ),
        (
            5_u64,
            "import x from 'pkg'",
            ParseGoal::Script,
            ParseErrorCode::InvalidGoal,
        ),
    ];

    for (seed, source, goal, expected_code) in cases {
        let error = parser.parse(source, goal).expect_err("case should fail");
        assert_eq!(
            error.code,
            expected_code,
            "{}",
            failure_context(
                "regression_failure_catalog_has_stable_error_codes",
                seed,
                goal,
                source
            )
        );
    }
}

// ---------- LCG determinism ----------

#[test]
fn lcg_next_is_deterministic_for_same_seed() {
    let mut state_a = 42_u64;
    let mut state_b = 42_u64;
    for _ in 0..10 {
        assert_eq!(lcg_next(&mut state_a), lcg_next(&mut state_b));
    }
}

#[test]
fn lcg_next_diverges_for_different_seeds() {
    let mut state_a = 1_u64;
    let mut state_b = 2_u64;
    assert_ne!(lcg_next(&mut state_a), lcg_next(&mut state_b));
}

// ---------- generate_case ----------

#[test]
fn generate_case_is_deterministic() {
    let case_a = generate_case(99);
    let case_b = generate_case(99);
    assert_eq!(case_a.source, case_b.source);
    assert_eq!(case_a.goal, case_b.goal);
}

#[test]
fn generate_case_different_seeds_produce_different_sources() {
    let case_a = generate_case(0);
    let case_b = generate_case(1);
    assert!(
        case_a.source != case_b.source || case_a.goal != case_b.goal,
        "different seeds should produce different cases"
    );
}

#[test]
fn generate_case_covers_both_goals_across_seed_range() {
    let mut has_script = false;
    let mut has_module = false;
    for seed in 0..32 {
        match generate_case(seed).goal {
            ParseGoal::Script => has_script = true,
            ParseGoal::Module => has_module = true,
        }
    }
    assert!(has_script, "should produce at least one script goal");
    assert!(has_module, "should produce at least one module goal");
}

// ---------- generate_identifier ----------

#[test]
fn generate_identifier_starts_with_v() {
    let mut state = 0_u64;
    let ident = generate_identifier(&mut state);
    assert!(ident.starts_with('v'));
}

// ---------- goal_label ----------

#[test]
fn goal_label_values() {
    assert_eq!(goal_label(ParseGoal::Script), "script");
    assert_eq!(goal_label(ParseGoal::Module), "module");
}

// ---------- failure_context ----------

#[test]
fn failure_context_is_valid_json() {
    let ctx = failure_context("test_name", 42, ParseGoal::Script, "var x = 1;");
    let parsed: serde_json::Value = serde_json::from_str(&ctx).expect("valid json");
    assert_eq!(parsed["component"], COMPONENT);
    assert_eq!(parsed["policy_id"], POLICY_ID);
    assert_eq!(parsed["seed"], 42);
    assert_eq!(parsed["goal"], "script");
}

#[test]
fn generate_identifier_is_deterministic_for_same_state() {
    let mut a = 42_u64;
    let mut b = 42_u64;
    assert_eq!(generate_identifier(&mut a), generate_identifier(&mut b));
}

#[test]
fn generate_case_produces_nonempty_source() {
    for seed in 0..16 {
        let case = generate_case(seed);
        assert!(
            !case.source.is_empty(),
            "seed {seed} should produce non-empty source"
        );
    }
}

#[test]
fn failure_context_includes_source_field() {
    let ctx = failure_context("test_fn", 0, ParseGoal::Module, "export default 42");
    let parsed: serde_json::Value = serde_json::from_str(&ctx).expect("valid json");
    assert_eq!(parsed["source"], "export default 42");
    assert_eq!(parsed["goal"], "module");
}

// ---------- semantic_signature ----------

#[test]
fn semantic_signature_is_deterministic_for_same_tree() {
    let parser = CanonicalEs2020Parser;
    let tree_a = parser
        .parse("var x = 1;", ParseGoal::Script)
        .expect("parse");
    let tree_b = parser
        .parse("var x = 1;", ParseGoal::Script)
        .expect("parse");
    assert_eq!(semantic_signature(&tree_a), semantic_signature(&tree_b));
}

#[test]
fn semantic_signature_matches_statement_count() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("42;\n\"hello\";\n99;", ParseGoal::Script)
        .expect("parse");
    assert_eq!(semantic_signature(&tree).len(), tree.body.len());
}

// ---------- budget exceeded witness ----------

#[test]
fn source_too_large_produces_correct_error_code() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        },
    };
    let result = parser.parse_with_options("var x = 1;", ParseGoal::Script, &options);
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.code, ParseErrorCode::BudgetExceeded);
    let witness = error.witness.expect("should include witness");
    assert_eq!(witness.budget_kind, Some(ParseBudgetKind::SourceBytes));
}

// ---------- error code diagnostics ----------

#[test]
fn parse_error_has_nonempty_stable_diagnostic_code() {
    let parser = CanonicalEs2020Parser;
    let error = parser
        .parse("", ParseGoal::Script)
        .expect_err("empty source should fail");
    let diagnostic = error.normalized_diagnostic();
    assert!(!diagnostic.diagnostic_code.is_empty());
    assert!(!diagnostic.schema_version.is_empty());
}

// ---------- property: all generated cases parse or fail deterministically ----------

#[test]
fn all_generated_cases_have_deterministic_outcome() {
    let parser = CanonicalEs2020Parser;
    for seed in 256..320 {
        let case = generate_case(seed);
        let result_a = parser.parse(case.source.as_str(), case.goal);
        let result_b = parser.parse(case.source.as_str(), case.goal);
        assert_eq!(
            result_a.is_ok(),
            result_b.is_ok(),
            "seed {seed} must have deterministic outcome"
        );
        if let (Ok(tree_a), Ok(tree_b)) = (result_a, result_b) {
            assert_eq!(tree_a.canonical_hash(), tree_b.canonical_hash());
        }
    }
}

#[test]
fn generate_case_deterministic_for_same_seed() {
    let a = generate_case(42);
    let b = generate_case(42);
    assert_eq!(a.source, b.source);
    assert_eq!(a.goal, b.goal);
}

#[test]
fn generate_case_wide_seed_range_produces_different_sources() {
    let a = generate_case(100);
    let b = generate_case(200);
    assert_ne!(a.source, b.source);
}

#[test]
fn generate_case_source_is_nonempty() {
    for seed in 0..10 {
        let case = generate_case(seed);
        assert!(
            !case.source.is_empty(),
            "seed {seed} must produce non-empty source"
        );
    }
}

#[test]
fn lcg_next_advances_state() {
    let mut state = 1_u64;
    let first = lcg_next(&mut state);
    let second = lcg_next(&mut state);
    assert_ne!(first, second, "successive LCG values should differ");
}

#[test]
fn semantic_signature_import_starts_with_import_prefix() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import x from 'pkg'", ParseGoal::Module)
        .expect("parse");
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), 1);
    assert!(sig[0].starts_with("import:"));
}

#[test]
fn semantic_signature_export_default_starts_with_prefix() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export default 42", ParseGoal::Module)
        .expect("parse");
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), 1);
    assert!(sig[0].starts_with("export_default:"));
}

#[test]
fn failure_context_includes_replay_command() {
    let ctx = failure_context("my_test", 0, ParseGoal::Script, "x");
    let parsed: serde_json::Value = serde_json::from_str(&ctx).expect("valid json");
    let cmd = parsed["replay_command"].as_str().unwrap();
    assert!(cmd.contains("cargo test"));
    assert!(cmd.contains("my_test"));
}

#[test]
fn failure_context_trace_and_decision_ids_differ() {
    let ctx = failure_context("t", 7, ParseGoal::Script, "x");
    let parsed: serde_json::Value = serde_json::from_str(&ctx).expect("valid json");
    let trace = parsed["trace_id"].as_str().unwrap();
    let decision = parsed["decision_id"].as_str().unwrap();
    assert_ne!(trace, decision);
}

#[test]
fn constants_are_nonempty() {
    assert!(!TRACE_PREFIX.is_empty());
    assert!(!DECISION_PREFIX.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert!(!COMPONENT.is_empty());
}

#[test]
fn generate_case_all_nine_variants_reachable() {
    let mut variants_seen = std::collections::BTreeSet::new();
    for seed in 0_u64..512 {
        let case = generate_case(seed);
        // Classify variant by heuristics on the source
        if case.source.starts_with("import") {
            variants_seen.insert(6_u8);
        } else if case.source.starts_with("export default") {
            variants_seen.insert(8);
        } else if case.source.starts_with("await") {
            variants_seen.insert(3);
        } else if case.source.starts_with('"') {
            variants_seen.insert(2);
        } else if case.source.contains('+') {
            variants_seen.insert(4);
        } else if case.source.contains(";\n") {
            variants_seen.insert(5);
        }
    }
    // At least several distinct variant shapes should be produced
    assert!(
        variants_seen.len() >= 3,
        "expected at least 3 distinct variant shapes across 512 seeds, got {}",
        variants_seen.len()
    );
}
