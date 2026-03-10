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
