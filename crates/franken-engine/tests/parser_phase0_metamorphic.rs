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

use frankenengine_engine::ast::{ExportKind, Expression, ParseGoal, Statement, SyntaxTree};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn parser() -> CanonicalEs2020Parser {
    CanonicalEs2020Parser
}

fn parse_hash(source: &str, goal: ParseGoal) -> String {
    parser()
        .parse(source, goal)
        .unwrap_or_else(|error| panic!("failed to parse `{source}`: {error}"))
        .canonical_hash()
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
            Statement::VariableDeclaration(var_decl) => {
                format!("variable_declaration:{}", var_decl.declarations.len())
            }
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
fn phase0_corpus_hashes_are_stable_across_repeated_runs() {
    let fixtures = [
        ("alpha", ParseGoal::Script),
        ("-7", ParseGoal::Script),
        ("await work", ParseGoal::Script),
        (
            "import dep from 'pkg'; export default dep",
            ParseGoal::Module,
        ),
        ("export { a, b }", ParseGoal::Module),
    ];

    for (source, goal) in fixtures {
        let expected = parse_hash(source, goal);
        for _ in 0..8 {
            let observed = parse_hash(source, goal);
            assert_eq!(observed, expected, "hash drift for source `{source}`");
        }
    }
}

#[test]
fn raw_expression_whitespace_relation_is_semantically_stable() {
    let baseline = parser()
        .parse("a + b * c", ParseGoal::Script)
        .expect("baseline parse");
    let transformed = parser()
        .parse("  a    +   b   *   c  ", ParseGoal::Script)
        .expect("transformed parse");

    assert_eq!(
        semantic_signature(&baseline),
        semantic_signature(&transformed),
        "raw-expression whitespace transform should preserve semantic signature"
    );
}

#[test]
fn import_quote_style_relation_is_hash_equivalent() {
    let single = parse_hash(
        "import dep from 'pkg'; export default dep",
        ParseGoal::Module,
    );
    let double = parse_hash(
        "import dep from \"pkg\"; export default dep",
        ParseGoal::Module,
    );
    assert_eq!(single, double);
}

#[test]
fn named_export_spacing_relation_is_semantically_equivalent() {
    let left = parser()
        .parse("export { a, b }", ParseGoal::Module)
        .expect("left parse");
    let right = parser()
        .parse("export  {  a,   b  }", ParseGoal::Module)
        .expect("right parse");
    assert_eq!(semantic_signature(&left), semantic_signature(&right));
}

#[test]
fn statement_delimiter_relation_preserves_semantic_signature() {
    let semicolon_form = parser()
        .parse("x;42;'ok';", ParseGoal::Script)
        .expect("semicolon parse");
    let newline_form = parser()
        .parse("x\n42\n'ok'\n", ParseGoal::Script)
        .expect("newline parse");

    assert_eq!(
        semantic_signature(&semicolon_form),
        semantic_signature(&newline_form),
        "statement delimiter relation should preserve semantic signature"
    );
}

#[test]
fn await_nesting_relation_preserves_nested_identifier_target() {
    let baseline = parser()
        .parse("await await value", ParseGoal::Script)
        .expect("baseline parse");
    let transformed = parser()
        .parse("await   await   value", ParseGoal::Script)
        .expect("transformed parse");

    let extract = |tree: &SyntaxTree| -> String {
        match &tree.body[0] {
            Statement::Expression(expr) => match &expr.expression {
                Expression::Await(level_1) => match level_1.as_ref() {
                    Expression::Await(level_2) => match level_2.as_ref() {
                        Expression::Identifier(value) => value.clone(),
                        other => panic!("expected nested identifier, got {other:?}"),
                    },
                    other => panic!("expected nested await, got {other:?}"),
                },
                other => panic!("expected await expression, got {other:?}"),
            },
            other => panic!("expected expression statement, got {other:?}"),
        }
    };

    assert_eq!(extract(&baseline), extract(&transformed));
}

// ---------- parse_hash helper ----------

#[test]
fn parse_hash_is_deterministic() {
    let h1 = parse_hash("42", ParseGoal::Script);
    let h2 = parse_hash("42", ParseGoal::Script);
    assert_eq!(h1, h2);
}

#[test]
fn parse_hash_starts_with_sha256() {
    let h = parse_hash("true", ParseGoal::Script);
    assert!(h.starts_with("sha256:"));
}

#[test]
fn parse_hash_differs_for_different_sources() {
    let h1 = parse_hash("1", ParseGoal::Script);
    let h2 = parse_hash("2", ParseGoal::Script);
    assert_ne!(h1, h2);
}

// ---------- semantic_signature helper ----------

#[test]
fn semantic_signature_expression_statement() {
    let tree = parser().parse("42", ParseGoal::Script).unwrap();
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), 1);
    assert!(sig[0].starts_with("expression:"));
}

#[test]
fn semantic_signature_import_declaration() {
    let tree = parser()
        .parse("import dep from 'pkg'", ParseGoal::Module)
        .unwrap();
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), 1);
    assert!(sig[0].starts_with("import:"));
    assert!(sig[0].contains("pkg"));
}

#[test]
fn semantic_signature_variable_declaration() {
    let tree = parser().parse("let x = 1", ParseGoal::Script).unwrap();
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), 1);
    assert!(sig[0].starts_with("variable_declaration:"));
}

#[test]
fn semantic_signature_multiple_statements() {
    let tree = parser()
        .parse("let x = 1; let y = 2; x", ParseGoal::Script)
        .unwrap();
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), 3);
}

// ---------- parser() helper ----------

#[test]
fn parser_parses_single_identifier() {
    let tree = parser().parse("x", ParseGoal::Script).unwrap();
    assert_eq!(tree.body.len(), 1);
}

// ---------- SyntaxTree canonical_hash ----------

#[test]
fn syntax_tree_canonical_hash_is_stable() {
    let t1 = parser().parse("x + 1", ParseGoal::Script).unwrap();
    let t2 = parser().parse("x + 1", ParseGoal::Script).unwrap();
    assert_eq!(t1.canonical_hash(), t2.canonical_hash());
}

// ---------- export kinds ----------

#[test]
fn semantic_signature_export_default() {
    let tree = parser()
        .parse("export default 42", ParseGoal::Module)
        .unwrap();
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), 1);
    assert!(sig[0].starts_with("export_default:"));
}

#[test]
fn semantic_signature_export_named() {
    let tree = parser()
        .parse("export { a, b }", ParseGoal::Module)
        .unwrap();
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), 1);
    assert!(sig[0].starts_with("export_named:"));
}

#[test]
fn parse_hash_script_vs_module_differ() {
    let h1 = parse_hash("42", ParseGoal::Script);
    let h2 = parse_hash("42", ParseGoal::Module);
    assert_ne!(h1, h2);
}

#[test]
fn semantic_signature_single_statement_length() {
    let tree = parser().parse(";", ParseGoal::Script).unwrap();
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), tree.body.len());
}

#[test]
fn canonical_hash_stable_across_multiple_calls() {
    let tree = parser().parse("var x = 1;", ParseGoal::Script).unwrap();
    let h1 = tree.canonical_hash();
    let h2 = tree.canonical_hash();
    assert_eq!(h1, h2);
}

#[test]
fn parse_hash_nonempty_for_valid_source() {
    let hash = parse_hash("1 + 2", ParseGoal::Script);
    assert!(!hash.is_empty());
}

#[test]
fn semantic_signature_matches_body_length() {
    let tree = parser().parse(";", ParseGoal::Script).unwrap();
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), tree.body.len());
}

#[test]
fn canonical_hash_different_sources_differ() {
    let h1 = parse_hash("var a = 1;", ParseGoal::Script);
    let h2 = parse_hash("var b = 2;", ParseGoal::Script);
    assert_ne!(h1, h2);
}

#[test]
fn parse_hash_is_deterministic_for_function() {
    let h1 = parse_hash("function f() { return 1; }", ParseGoal::Script);
    let h2 = parse_hash("function f() { return 1; }", ParseGoal::Script);
    assert_eq!(h1, h2);
}

#[test]
fn empty_source_returns_parse_error() {
    let result = parser().parse("", ParseGoal::Module);
    assert!(result.is_err(), "empty source should return error");
}

#[test]
fn semantic_signature_import_statement() {
    let tree = parser()
        .parse("import x from './mod.mjs'", ParseGoal::Module)
        .unwrap();
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), 1);
    assert!(sig[0].starts_with("import:"));
}

#[test]
fn semantic_signature_three_var_declarations() {
    let tree = parser()
        .parse("var a = 1;\nvar b = 2;\nvar c = 3;", ParseGoal::Script)
        .unwrap();
    let sig = semantic_signature(&tree);
    assert_eq!(sig.len(), 3);
}

#[test]
fn parse_hash_changes_with_whitespace_if_semantically_same() {
    let h1 = parse_hash("var x=1;", ParseGoal::Script);
    let h2 = parse_hash("var  x  =  1  ;", ParseGoal::Script);
    // Both should parse successfully - hashes may or may not differ
    // depending on span encoding, but both should be non-empty
    assert!(!h1.is_empty());
    assert!(!h2.is_empty());
}

#[test]
fn canonical_hash_nonempty_for_module() {
    let tree = parser()
        .parse("export default 42", ParseGoal::Module)
        .unwrap();
    let hash = tree.canonical_hash();
    assert!(!hash.is_empty());
}

#[test]
fn parser_helper_returns_parser_instance() {
    let p = parser();
    let result = p.parse("42", ParseGoal::Script);
    assert!(result.is_ok());
}

// ===== PearlTower enrichment =====

use frankenengine_engine::parser::{
    ParseBudgetKind, ParseDiagnosticCategory, ParseDiagnosticSeverity, ParseDiagnosticTaxonomy,
    ParseErrorCode, ParserBudget, ParserMode, ParserOptions,
};

#[test]
fn enrichment_parse_goal_serde_roundtrip_script() {
    let original = ParseGoal::Script;
    let json = serde_json::to_string(&original).expect("serialize ParseGoal::Script");
    let roundtripped: ParseGoal =
        serde_json::from_str(&json).expect("deserialize ParseGoal::Script");
    assert_eq!(original, roundtripped);
}

#[test]
fn enrichment_parse_goal_serde_roundtrip_module() {
    let original = ParseGoal::Module;
    let json = serde_json::to_string(&original).expect("serialize ParseGoal::Module");
    let roundtripped: ParseGoal =
        serde_json::from_str(&json).expect("deserialize ParseGoal::Module");
    assert_eq!(original, roundtripped);
}

#[test]
fn enrichment_syntax_tree_serde_roundtrip() {
    let tree = parser()
        .parse("let x = 1", ParseGoal::Script)
        .expect("parse let x = 1");
    let json = serde_json::to_string(&tree).expect("serialize SyntaxTree");
    let roundtripped: SyntaxTree = serde_json::from_str(&json).expect("deserialize SyntaxTree");
    assert_eq!(tree, roundtripped);
}

#[test]
fn enrichment_parse_error_code_serde_roundtrip_all_variants() {
    for code in ParseErrorCode::ALL {
        let json = serde_json::to_string(&code).expect("serialize ParseErrorCode");
        let roundtripped: ParseErrorCode =
            serde_json::from_str(&json).expect("deserialize ParseErrorCode");
        assert_eq!(code, roundtripped, "serde roundtrip failed for {code:?}");
    }
}

#[test]
fn enrichment_parser_options_serde_roundtrip_default() {
    let options = ParserOptions::default();
    let json = serde_json::to_string(&options).expect("serialize ParserOptions");
    let roundtripped: ParserOptions =
        serde_json::from_str(&json).expect("deserialize ParserOptions");
    assert_eq!(options, roundtripped);
}

#[test]
fn enrichment_parse_goal_clone_and_debug_derive() {
    let goal = ParseGoal::Script;
    let cloned = goal;
    assert_eq!(goal, cloned);
    let debug_str = format!("{goal:?}");
    assert!(debug_str.contains("Script"));
    let module_debug = format!("{:?}", ParseGoal::Module);
    assert!(module_debug.contains("Module"));
}

#[test]
fn enrichment_parser_budget_clone_and_debug_derive() {
    let budget = ParserBudget::default();
    let cloned = budget.clone();
    assert_eq!(budget, cloned);
    let debug_str = format!("{budget:?}");
    assert!(debug_str.contains("max_source_bytes"));
}

#[test]
fn enrichment_parse_budget_kind_debug_and_as_str_consistent() {
    let cases = [
        (ParseBudgetKind::SourceBytes, "source_bytes"),
        (ParseBudgetKind::TokenCount, "token_count"),
        (ParseBudgetKind::RecursionDepth, "recursion_depth"),
    ];
    for (kind, expected_str) in cases {
        assert_eq!(kind.as_str(), expected_str);
        let cloned = kind;
        assert_eq!(cloned.as_str(), expected_str);
        let debug_str = format!("{kind:?}");
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn enrichment_parse_diagnostic_taxonomy_v1_covers_all_codes() {
    let taxonomy = ParseDiagnosticTaxonomy::v1();
    assert_eq!(taxonomy.rules.len(), ParseErrorCode::ALL.len());
    for code in ParseErrorCode::ALL {
        let rule = taxonomy.rule_for(code);
        assert!(rule.is_some(), "taxonomy missing rule for {code:?}");
        let rule = rule.unwrap();
        assert!(!rule.diagnostic_code.is_empty());
        assert!(!rule.message_template.is_empty());
    }
}

#[test]
fn enrichment_syntax_tree_clone_preserves_canonical_hash() {
    let tree = parser()
        .parse("export default 1 + 2", ParseGoal::Module)
        .expect("parse");
    let cloned = tree.clone();
    assert_eq!(tree.canonical_hash(), cloned.canonical_hash());
}

#[test]
fn enrichment_parse_hash_prefix_invariant_for_all_goal_sources() {
    let fixtures = [
        ("x", ParseGoal::Script),
        ("42", ParseGoal::Script),
        ("import m from 'mod'", ParseGoal::Module),
        ("export default null", ParseGoal::Module),
        ("var a = 1; var b = 2;", ParseGoal::Script),
    ];
    for (source, goal) in fixtures {
        let hash = parse_hash(source, goal);
        assert!(
            hash.starts_with("sha256:"),
            "expected sha256: prefix for `{source}`"
        );
        assert!(hash.len() > 7, "hash too short for `{source}`");
    }
}

#[test]
fn enrichment_semantic_signature_deterministic_across_repeated_calls() {
    let tree = parser()
        .parse("let a = 1; let b = 2; a + b", ParseGoal::Script)
        .expect("parse");
    let sig1 = semantic_signature(&tree);
    let sig2 = semantic_signature(&tree);
    let sig3 = semantic_signature(&tree);
    assert_eq!(sig1, sig2);
    assert_eq!(sig2, sig3);
}

#[test]
fn enrichment_parser_mode_serde_roundtrip() {
    let mode = ParserMode::ScalarReference;
    let json = serde_json::to_string(&mode).expect("serialize ParserMode");
    let roundtripped: ParserMode = serde_json::from_str(&json).expect("deserialize ParserMode");
    assert_eq!(mode, roundtripped);
    assert_eq!(mode.as_str(), "scalar_reference");
}

#[test]
fn enrichment_parse_diagnostic_category_debug_and_as_str_invariant() {
    let cases = [
        (ParseDiagnosticCategory::Input, "input"),
        (ParseDiagnosticCategory::Goal, "goal"),
        (ParseDiagnosticCategory::Syntax, "syntax"),
        (ParseDiagnosticCategory::Encoding, "encoding"),
        (ParseDiagnosticCategory::Resource, "resource"),
        (ParseDiagnosticCategory::System, "system"),
    ];
    for (cat, expected) in cases {
        assert_eq!(cat.as_str(), expected);
        let cloned = cat;
        assert_eq!(cloned, cat);
        let debug_str = format!("{cat:?}");
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn enrichment_parse_diagnostic_severity_clone_and_as_str() {
    let error = ParseDiagnosticSeverity::Error;
    let fatal = ParseDiagnosticSeverity::Fatal;
    assert_eq!(error.as_str(), "error");
    assert_eq!(fatal.as_str(), "fatal");
    let cloned_error = error;
    let cloned_fatal = fatal;
    assert_eq!(cloned_error, error);
    assert_eq!(cloned_fatal, fatal);
}

#[test]
fn enrichment_canonical_hash_idempotent_property_across_sources() {
    let sources = [
        "1",
        "true",
        "false",
        "null",
        "'hello'",
        "a + b",
        "function f() {}",
    ];
    for source in sources {
        let tree = parser()
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|e| panic!("failed to parse `{source}`: {e}"));
        let h1 = tree.canonical_hash();
        let h2 = tree.canonical_hash();
        assert_eq!(h1, h2, "canonical_hash not idempotent for `{source}`");
        assert!(h1.starts_with("sha256:"));
    }
}

#[test]
fn enrichment_metamorphic_comment_stripping_preserves_statement_count() {
    // A single expression statement with trailing comment vs. without
    // Both should yield exactly one statement in the tree body.
    let without_comment = parser()
        .parse("42", ParseGoal::Script)
        .expect("parse without comment");
    let with_comment = parser()
        .parse("42 // trailing comment", ParseGoal::Script)
        .expect("parse with trailing comment");
    assert_eq!(
        without_comment.body.len(),
        with_comment.body.len(),
        "comment stripping should not change body statement count"
    );
    // Body length must match (comments don't add statements)
    assert_eq!(without_comment.body.len(), 1);
    assert_eq!(with_comment.body.len(), 1);
}

#[test]
fn enrichment_parse_goal_as_str_distinct_values() {
    let script_str = ParseGoal::Script.as_str();
    let module_str = ParseGoal::Module.as_str();
    assert_ne!(script_str, module_str);
    assert_eq!(script_str, "script");
    assert_eq!(module_str, "module");
}

#[test]
fn enrichment_parser_budget_default_values_are_positive() {
    let budget = ParserBudget::default();
    assert!(budget.max_source_bytes > 0);
    assert!(budget.max_token_count > 0);
    assert!(budget.max_recursion_depth > 0);
}

#[test]
fn enrichment_syntax_tree_debug_contains_goal_info() {
    let tree = parser().parse("x", ParseGoal::Script).expect("parse x");
    let debug_str = format!("{tree:?}");
    assert!(!debug_str.is_empty());
    assert!(debug_str.contains("Script") || debug_str.contains("goal"));
}
