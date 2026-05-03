#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use frankenengine_engine::ast::{
    BindingPattern, ExportDeclaration, ExportKind, Expression, ExpressionStatement, ImportClause,
    ImportDeclaration, ParseGoal, SourceSpan, Statement, SyntaxTree, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator,
};
use frankenengine_engine::parser_arena::{ArenaBudget, HandleAuditKind, ParserArena};

struct ArenaConformanceCase {
    id: &'static str,
    es_section: &'static str,
    source: &'static str,
    tree: SyntaxTree,
    audit_fragments: Vec<String>,
}

fn span_for(source: &str) -> SourceSpan {
    let end = u64::try_from(source.len()).expect("fixture source length should fit in u64");
    SourceSpan::new(0, end, 1, 1, 1, end.saturating_add(1))
}

fn tree(goal: ParseGoal, source: &'static str, body: Vec<Statement>) -> SyntaxTree {
    SyntaxTree {
        goal,
        body,
        span: span_for(source),
    }
}

fn expression_statement(source: &'static str, expression: Expression) -> Statement {
    Statement::Expression(ExpressionStatement {
        expression,
        span: span_for(source),
    })
}

fn identifier(name: &str) -> Expression {
    Expression::Identifier(name.to_string())
}

fn variable_declarator(
    source: &'static str,
    name: &str,
    initializer: Option<Expression>,
) -> VariableDeclarator {
    VariableDeclarator {
        pattern: BindingPattern::Identifier(name.to_string()),
        initializer,
        span: span_for(source),
    }
}

fn variable_declaration(
    source: &'static str,
    kind: VariableDeclarationKind,
    declarations: Vec<VariableDeclarator>,
) -> Statement {
    Statement::VariableDeclaration(VariableDeclaration {
        kind,
        declarations,
        span: span_for(source),
    })
}

fn module_import_default(source: &'static str, local: &str, module: &str) -> Statement {
    Statement::Import(ImportDeclaration {
        clause: ImportClause::Default {
            local: local.to_string(),
        },
        binding: Some(local.to_string()),
        source: module.to_string(),
        span: span_for(source),
    })
}

fn module_import_side_effect(source: &'static str, module: &str) -> Statement {
    Statement::Import(ImportDeclaration {
        clause: ImportClause::SideEffect,
        binding: None,
        source: module.to_string(),
        span: span_for(source),
    })
}

fn module_export_default(source: &'static str, expression: Expression) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::Default(expression),
        span: span_for(source),
    })
}

fn module_export_named(source: &'static str, clause: &str) -> Statement {
    Statement::Export(ExportDeclaration {
        kind: ExportKind::NamedClause(clause.to_string()),
        span: span_for(source),
    })
}

fn case(
    id: &'static str,
    es_section: &'static str,
    source: &'static str,
    goal: ParseGoal,
    body: Vec<Statement>,
    audit_fragments: Vec<String>,
) -> ArenaConformanceCase {
    ArenaConformanceCase {
        id,
        es_section,
        source,
        tree: tree(goal, source, body),
        audit_fragments,
    }
}

fn arena_conformance_cases() -> Vec<ArenaConformanceCase> {
    let float_bits = 1.5f64.to_bits();

    vec![
        case(
            "es2020-script-expression-identifier-roundtrip",
            "ECMA-262 13.2 IdentifierReference",
            "alpha;",
            ParseGoal::Script,
            vec![expression_statement("alpha;", identifier("alpha"))],
            vec![
                "expression_statement".to_string(),
                "identifier alpha".to_string(),
            ],
        ),
        case(
            "es2020-script-expression-string-literal-roundtrip",
            "ECMA-262 12.8.4 StringLiteral",
            "'hello';",
            ParseGoal::Script,
            vec![expression_statement(
                "'hello';",
                Expression::StringLiteral("hello".to_string()),
            )],
            vec!["string hello".to_string()],
        ),
        case(
            "es2020-script-expression-numeric-literal-roundtrip",
            "ECMA-262 12.8.3 NumericLiteral",
            "42;",
            ParseGoal::Script,
            vec![expression_statement("42;", Expression::NumericLiteral(42))],
            vec!["number 42".to_string()],
        ),
        case(
            "es2020-script-expression-float-literal-roundtrip",
            "ECMA-262 12.8.3 NumericLiteral",
            "1.5;",
            ParseGoal::Script,
            vec![expression_statement(
                "1.5;",
                Expression::FloatLiteral(float_bits),
            )],
            vec![format!("float bits:{float_bits}")],
        ),
        case(
            "es2020-script-expression-boolean-true-roundtrip",
            "ECMA-262 12.8.1 BooleanLiteral",
            "true;",
            ParseGoal::Script,
            vec![expression_statement(
                "true;",
                Expression::BooleanLiteral(true),
            )],
            vec!["boolean true".to_string()],
        ),
        case(
            "es2020-script-expression-boolean-false-roundtrip",
            "ECMA-262 12.8.1 BooleanLiteral",
            "false;",
            ParseGoal::Script,
            vec![expression_statement(
                "false;",
                Expression::BooleanLiteral(false),
            )],
            vec!["boolean false".to_string()],
        ),
        case(
            "es2020-script-expression-null-roundtrip",
            "ECMA-262 12.8.1 NullLiteral",
            "null;",
            ParseGoal::Script,
            vec![expression_statement("null;", Expression::NullLiteral)],
            vec!["null".to_string()],
        ),
        case(
            "es2020-script-expression-undefined-roundtrip",
            "ECMA-262 Annex B undefined binding convention",
            "undefined;",
            ParseGoal::Script,
            vec![expression_statement(
                "undefined;",
                Expression::UndefinedLiteral,
            )],
            vec!["undefined".to_string()],
        ),
        case(
            "es2020-module-top-level-await-identifier-roundtrip",
            "ECMA-262 15.3 Module top-level await",
            "await alpha;",
            ParseGoal::Module,
            vec![expression_statement(
                "await alpha;",
                Expression::Await(Box::new(identifier("alpha"))),
            )],
            vec!["await".to_string(), "identifier alpha".to_string()],
        ),
        case(
            "es2020-script-let-numeric-initializer-roundtrip",
            "ECMA-262 13.3 LexicalDeclaration",
            "let count = 7;",
            ParseGoal::Script,
            vec![variable_declaration(
                "let count = 7;",
                VariableDeclarationKind::Let,
                vec![variable_declarator(
                    "let count = 7;",
                    "count",
                    Some(Expression::NumericLiteral(7)),
                )],
            )],
            vec![
                "variable_declaration kind=let count=1".to_string(),
                "number 7".to_string(),
            ],
        ),
        case(
            "es2020-script-const-string-initializer-roundtrip",
            "ECMA-262 13.3 LexicalDeclaration",
            "const label = 'ok';",
            ParseGoal::Script,
            vec![variable_declaration(
                "const label = 'ok';",
                VariableDeclarationKind::Const,
                vec![variable_declarator(
                    "const label = 'ok';",
                    "label",
                    Some(Expression::StringLiteral("ok".to_string())),
                )],
            )],
            vec![
                "variable_declaration kind=const count=1".to_string(),
                "string ok".to_string(),
            ],
        ),
        case(
            "es2020-script-var-without-initializer-roundtrip",
            "ECMA-262 13.3 VariableStatement",
            "var pending;",
            ParseGoal::Script,
            vec![variable_declaration(
                "var pending;",
                VariableDeclarationKind::Var,
                vec![variable_declarator("var pending;", "pending", None)],
            )],
            vec!["variable_declaration kind=var count=1".to_string()],
        ),
        case(
            "es2020-script-multiple-declarators-roundtrip",
            "ECMA-262 13.3 VariableStatement",
            "let left = 1, right = 'r';",
            ParseGoal::Script,
            vec![variable_declaration(
                "let left = 1, right = 'r';",
                VariableDeclarationKind::Let,
                vec![
                    variable_declarator(
                        "let left = 1, right = 'r';",
                        "left",
                        Some(Expression::NumericLiteral(1)),
                    ),
                    variable_declarator(
                        "let left = 1, right = 'r';",
                        "right",
                        Some(Expression::StringLiteral("r".to_string())),
                    ),
                ],
            )],
            vec![
                "variable_declaration kind=let count=2".to_string(),
                "number 1".to_string(),
                "string r".to_string(),
            ],
        ),
        case(
            "es2020-module-default-import-roundtrip",
            "ECMA-262 16.2.2 Imports",
            "import alpha from './dep.mjs';",
            ParseGoal::Module,
            vec![module_import_default(
                "import alpha from './dep.mjs';",
                "alpha",
                "./dep.mjs",
            )],
            vec![
                "import binding=alpha source=./dep.mjs".to_string(),
                "span=1".to_string(),
            ],
        ),
        case(
            "es2020-module-side-effect-import-roundtrip",
            "ECMA-262 16.2.2 Imports",
            "import './polyfill.mjs';",
            ParseGoal::Module,
            vec![module_import_side_effect(
                "import './polyfill.mjs';",
                "./polyfill.mjs",
            )],
            vec!["import binding=_ source=./polyfill.mjs".to_string()],
        ),
        case(
            "es2020-module-export-default-expression-roundtrip",
            "ECMA-262 16.2.3 Exports",
            "export default 42;",
            ParseGoal::Module,
            vec![module_export_default(
                "export default 42;",
                Expression::NumericLiteral(42),
            )],
            vec!["export_default".to_string(), "number 42".to_string()],
        ),
        case(
            "es2020-module-export-named-clause-roundtrip",
            "ECMA-262 16.2.3 Exports",
            "export { alpha };",
            ParseGoal::Module,
            vec![module_export_named("export { alpha };", "alpha")],
            vec!["export_named clause=alpha".to_string()],
        ),
    ]
}

#[test]
fn parser_arena_conformance_harness_has_at_least_ten_named_cases() {
    let cases = arena_conformance_cases();
    let mut ids = BTreeSet::new();

    for case in &cases {
        assert!(
            ids.insert(case.id),
            "duplicate conformance case id {}",
            case.id
        );
        assert!(
            !case.es_section.is_empty(),
            "{} must name the ECMAScript source requirement",
            case.id
        );
        assert!(
            !case.source.is_empty(),
            "{} must carry a golden source input",
            case.id
        );
    }

    assert!(
        cases.len() >= 10,
        "parser_arena conformance harness must carry at least 10 named cases"
    );
}

#[test]
fn parser_arena_roundtrips_supported_es2020_golden_cases() {
    for case in arena_conformance_cases() {
        let arena = ParserArena::from_syntax_tree(&case.tree, ArenaBudget::default())
            .unwrap_or_else(|err| panic!("{} should build arena: {err}", case.id));
        let round_trip = arena
            .to_syntax_tree()
            .unwrap_or_else(|err| panic!("{} should materialize arena: {err}", case.id));

        assert_eq!(
            arena.statement_handles().len(),
            case.tree.body.len(),
            "{} should preserve the parser statement count",
            case.id
        );
        assert_eq!(
            round_trip.goal, case.tree.goal,
            "{} should preserve the parse goal",
            case.id
        );
        assert_eq!(
            round_trip.canonical_hash(),
            case.tree.canonical_hash(),
            "{} should preserve the SyntaxTree canonical hash",
            case.id
        );
        assert_eq!(
            arena.canonical_hash().expect("arena hash"),
            case.tree.canonical_hash(),
            "{} should expose the original canonical hash",
            case.id
        );
        assert!(
            arena.bytes_used() > 0,
            "{} should account for non-zero arena storage",
            case.id
        );
    }
}

#[test]
fn parser_arena_audit_entries_name_each_conformance_shape() {
    for case in arena_conformance_cases() {
        let arena = ParserArena::from_syntax_tree(&case.tree, ArenaBudget::default())
            .unwrap_or_else(|err| panic!("{} should build arena: {err}", case.id));
        let descriptors = arena
            .handle_audit_entries()
            .into_iter()
            .map(|entry| {
                assert_eq!(
                    entry.generation, 1,
                    "{} should emit generation-1 audit handles",
                    case.id
                );
                entry.descriptor
            })
            .collect::<Vec<_>>();

        for fragment in &case.audit_fragments {
            assert!(
                descriptors
                    .iter()
                    .any(|descriptor| descriptor.contains(fragment)),
                "{} should emit audit descriptor fragment {:?}; descriptors={:?}",
                case.id,
                fragment,
                descriptors
            );
        }
    }
}

#[test]
fn parser_arena_audit_jsonl_is_stable_for_conformance_cases() {
    for case in arena_conformance_cases() {
        let first = ParserArena::from_syntax_tree(&case.tree, ArenaBudget::default())
            .unwrap_or_else(|err| panic!("{} first arena should build: {err}", case.id));
        let second = ParserArena::from_syntax_tree(&case.tree, ArenaBudget::default())
            .unwrap_or_else(|err| panic!("{} second arena should build: {err}", case.id));

        assert_eq!(
            first.handle_audit_jsonl().expect("first audit jsonl"),
            second.handle_audit_jsonl().expect("second audit jsonl"),
            "{} should emit deterministic audit JSONL",
            case.id
        );
    }
}

#[test]
fn parser_arena_audit_kinds_cover_nodes_expressions_and_spans() {
    for case in arena_conformance_cases() {
        let arena = ParserArena::from_syntax_tree(&case.tree, ArenaBudget::default())
            .unwrap_or_else(|err| panic!("{} should build arena: {err}", case.id));
        let kinds = arena
            .handle_audit_entries()
            .into_iter()
            .map(|entry| entry.handle_kind)
            .collect::<BTreeSet<_>>();

        assert!(
            kinds.contains(&HandleAuditKind::Node),
            "{} should audit arena nodes",
            case.id
        );
        assert!(
            kinds.contains(&HandleAuditKind::Span),
            "{} should audit source spans",
            case.id
        );

        if case.tree.body.iter().any(|statement| {
            !matches!(
                statement,
                Statement::Import(_)
                    | Statement::Export(ExportDeclaration {
                        kind: ExportKind::NamedClause(_),
                        ..
                    })
            )
        }) {
            assert!(
                kinds.contains(&HandleAuditKind::Expression),
                "{} should audit expression slots when the source has expressions",
                case.id
            );
        }
    }
}
