use std::fs;
use std::io::Cursor;

use frankenengine_engine::ast::{
    BinaryOperator, CANONICAL_AST_CONTRACT_VERSION, CANONICAL_AST_HASH_ALGORITHM,
    CANONICAL_AST_HASH_PREFIX, CANONICAL_AST_SCHEMA_VERSION, ExportKind, Expression, ParseGoal,
    SourceSpan, Statement, SyntaxTree, VariableDeclarationKind,
};
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, Es2020Parser, MaterializedSyntaxTree,
    PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION, PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX,
    PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION, PARSE_EVENT_IR_CONTRACT_VERSION,
    PARSE_EVENT_IR_HASH_ALGORITHM, PARSE_EVENT_IR_HASH_PREFIX, PARSE_EVENT_IR_SCHEMA_VERSION,
    PARSER_DIAGNOSTIC_HASH_ALGORITHM, PARSER_DIAGNOSTIC_HASH_PREFIX,
    PARSER_DIAGNOSTIC_SCHEMA_VERSION, PARSER_DIAGNOSTIC_TAXONOMY_VERSION, ParseBudgetKind,
    ParseDiagnosticEnvelope, ParseErrorCode, ParseEventIr, ParseEventKind,
    ParseEventMaterializationErrorCode, ParserBudget, ParserMode, ParserOptions, StreamInput,
};

fn single_line_source_span(source: &str) -> SourceSpan {
    let width = source.len() as u64;
    SourceSpan::new(0, width, 1, 1, 1, width + 1)
}

#[test]
fn parser_goal_and_statement_hierarchy_are_emitted_deterministically() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("alpha;\n42;\n'hello';\nawait beta;\n", ParseGoal::Script)
        .expect("script parse should succeed");

    assert_eq!(tree.goal, ParseGoal::Script);
    assert_eq!(tree.body.len(), 4);
    assert!(matches!(
        &tree.body[0],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::Identifier(name) if name == "alpha")
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::NumericLiteral(42))
    ));
    assert!(matches!(
        &tree.body[2],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::StringLiteral(value) if value == "hello")
    ));
    assert!(matches!(
        &tree.body[3],
        Statement::Expression(expr) if matches!(&expr.expression, Expression::Await(_))
    ));
}

#[test]
fn parser_supports_let_and_const_variable_declarations() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("let left = 1;\nconst right = 2;", ParseGoal::Script)
        .expect("script parse should succeed");

    assert_eq!(tree.body.len(), 2);
    assert!(matches!(
        &tree.body[0],
        Statement::VariableDeclaration(decl)
            if decl.kind == VariableDeclarationKind::Let
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::VariableDeclaration(decl)
            if decl.kind == VariableDeclarationKind::Const
    ));
}

#[test]
fn parser_supports_named_and_namespace_import_forms() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "import { run, stop as halt } from \"pkg\";\nimport * as ns from \"pkg\";\nimport dep, { start } from \"pkg\";",
            ParseGoal::Module,
        )
        .expect("module parse should succeed");

    assert_eq!(tree.body.len(), 3);
    assert!(matches!(
        &tree.body[0],
        Statement::Import(import)
            if import.binding.is_none() && import.source == "pkg"
    ));
    assert!(matches!(
        &tree.body[1],
        Statement::Import(import)
            if import.binding.as_deref() == Some("ns") && import.source == "pkg"
    ));
    assert!(matches!(
        &tree.body[2],
        Statement::Import(import)
            if import.binding.as_deref() == Some("dep") && import.source == "pkg"
    ));
}

#[test]
fn parser_rejects_keyword_module_import_bindings() {
    let parser = CanonicalEs2020Parser;
    let error = parser
        .parse("import { run as for } from \"pkg\";", ParseGoal::Module)
        .expect_err("module import binding with keyword local name must fail");
    assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
}

#[test]
fn parser_supports_named_export_clause_forms() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "const local = 1;\nexport { local as published };\nexport { default as dep } from \"pkg\";",
            ParseGoal::Module,
        )
        .expect("module parse should succeed");

    assert_eq!(tree.body.len(), 3);
    assert!(matches!(
        &tree.body[1],
        Statement::Export(export)
            if matches!(&export.kind, ExportKind::NamedClause(clause) if clause == "{ local as published }")
    ));
    assert!(matches!(
        &tree.body[2],
        Statement::Export(export)
            if matches!(&export.kind, ExportKind::NamedClause(clause) if clause == "{ default as dep } from \"pkg\"")
    ));
}

#[test]
fn parser_emits_function_declaration_with_name_and_empty_body() {
    let parser = CanonicalEs2020Parser;
    let source = "function foo() {}";
    let script_tree = parser
        .parse(source, ParseGoal::Script)
        .expect("script parse should succeed");
    let module_tree = parser
        .parse(source, ParseGoal::Module)
        .expect("module parse should succeed");

    assert!(matches!(
        &script_tree.body[0],
        Statement::FunctionDeclaration(decl)
            if decl.name.as_deref() == Some("foo") && decl.params.is_empty() && decl.body.body.is_empty()
    ));
    assert!(matches!(
        &module_tree.body[0],
        Statement::FunctionDeclaration(decl)
            if decl.name.as_deref() == Some("foo") && decl.params.is_empty() && decl.body.body.is_empty()
    ));
    // Same source parsed with same goal should produce deterministic output.
    let script_tree_2 = parser
        .parse(source, ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(script_tree.canonical_hash(), script_tree_2.canonical_hash());
}

#[test]
fn parser_accepts_stream_and_file_inputs_with_equal_canonical_hash() {
    let parser = CanonicalEs2020Parser;
    let source = "import dep from \"pkg\";\nexport default dep;\n";

    let stream_tree = parser
        .parse(
            StreamInput::new(Cursor::new(source), "stdin"),
            ParseGoal::Module,
        )
        .expect("stream parse should succeed");

    let temp_path = std::env::temp_dir().join("franken_engine_parser_trait_ast_test.js");
    fs::write(&temp_path, source).expect("write temporary source file");
    let file_tree = parser
        .parse(temp_path.as_path(), ParseGoal::Module)
        .expect("file parse should succeed");

    assert_eq!(stream_tree.canonical_bytes(), file_tree.canonical_bytes());
    assert_eq!(stream_tree.canonical_hash(), file_tree.canonical_hash());
}

#[test]
fn script_goal_rejects_module_only_declarations() {
    let parser = CanonicalEs2020Parser;
    let error = parser
        .parse("export default value;", ParseGoal::Script)
        .expect_err("script goal should reject export");
    assert_eq!(error.code, ParseErrorCode::InvalidGoal);
}

#[test]
fn canonical_ast_contract_metadata_is_versioned_and_stable() {
    assert_eq!(
        CANONICAL_AST_CONTRACT_VERSION,
        "franken-engine.parser-ast.contract.v1"
    );
    assert_eq!(
        CANONICAL_AST_SCHEMA_VERSION,
        "franken-engine.parser-ast.schema.v1"
    );
    assert_eq!(CANONICAL_AST_HASH_ALGORITHM, "sha256");
    assert_eq!(CANONICAL_AST_HASH_PREFIX, "sha256:");

    assert_eq!(
        SyntaxTree::canonical_contract_version(),
        CANONICAL_AST_CONTRACT_VERSION
    );
    assert_eq!(
        SyntaxTree::canonical_schema_version(),
        CANONICAL_AST_SCHEMA_VERSION
    );
    assert_eq!(
        SyntaxTree::canonical_hash_algorithm(),
        CANONICAL_AST_HASH_ALGORITHM
    );
    assert_eq!(
        SyntaxTree::canonical_hash_prefix(),
        CANONICAL_AST_HASH_PREFIX
    );
}

#[test]
fn canonical_ast_hash_vector_script_numeric_signed_is_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("-7", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(
        tree.canonical_hash(),
        "sha256:d959b7cbce9a409871d9a288d6feb3c043bdf3ce6ee54ff39051909db432adc4"
    );
}

#[test]
fn canonical_ast_hash_vector_module_import_default_is_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import dep from \"pkg\"", ParseGoal::Module)
        .expect("module parse should succeed");
    assert_eq!(
        tree.canonical_hash(),
        "sha256:6f9b81a8dfbaad70c345e5508dd1fae29d3d6cfdc1d18954d3486abd00d75f6c"
    );
}

#[test]
fn canonical_ast_hash_vector_module_export_default_is_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("export default true", ParseGoal::Module)
        .expect("module parse should succeed");
    assert_eq!(
        tree.canonical_hash(),
        "sha256:ebb993de589945a2cf22f17db58200599ae3e1e6c21cd33a0fc59eab99fd8ef6"
    );
}

#[test]
fn canonical_parse_event_ir_metadata_is_versioned_and_stable() {
    assert_eq!(
        PARSE_EVENT_IR_CONTRACT_VERSION,
        "franken-engine.parser-event-ir.contract.v2"
    );
    assert_eq!(
        PARSE_EVENT_IR_SCHEMA_VERSION,
        "franken-engine.parser-event-ir.schema.v2"
    );
    assert_eq!(PARSE_EVENT_IR_HASH_ALGORITHM, "sha256");
    assert_eq!(PARSE_EVENT_IR_HASH_PREFIX, "sha256:");

    assert_eq!(
        ParseEventIr::contract_version(),
        PARSE_EVENT_IR_CONTRACT_VERSION
    );
    assert_eq!(
        ParseEventIr::schema_version(),
        PARSE_EVENT_IR_SCHEMA_VERSION
    );
    assert_eq!(
        ParseEventIr::canonical_hash_algorithm(),
        PARSE_EVENT_IR_HASH_ALGORITHM
    );
    assert_eq!(
        ParseEventIr::canonical_hash_prefix(),
        PARSE_EVENT_IR_HASH_PREFIX
    );
}

#[test]
fn canonical_parse_event_ir_hash_vector_script_numeric_signed_is_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("-7", ParseGoal::Script)
        .expect("script parse should succeed");
    let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    assert_eq!(
        ir.canonical_hash(),
        "sha256:23c6f89b4442da0d3ca21a3415901a6b19518f02f0b51b439cbb4aae0e70ea47"
    );
}

#[test]
fn canonical_parse_event_ir_hash_vector_module_import_default_is_stable() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("import dep from \"pkg\"", ParseGoal::Module)
        .expect("module parse should succeed");
    let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
    assert_eq!(
        ir.canonical_hash(),
        "sha256:37b99e6645feed7454a8e063844c70657cf20db5d92741dafa256a30ae21ad60"
    );
}

#[test]
fn canonical_parse_event_ir_provenance_ids_are_stable_for_identical_inputs() {
    let parser = CanonicalEs2020Parser;
    let source = "await work";
    let left_tree = parser
        .parse(source, ParseGoal::Script)
        .expect("left parse should succeed");
    let right_tree = parser
        .parse(source, ParseGoal::Script)
        .expect("right parse should succeed");
    let left_ir =
        ParseEventIr::from_syntax_tree(&left_tree, "<inline>", ParserMode::ScalarReference);
    let right_ir =
        ParseEventIr::from_syntax_tree(&right_tree, "<inline>", ParserMode::ScalarReference);
    assert_eq!(left_ir.canonical_hash(), right_ir.canonical_hash());
    assert_eq!(left_ir.events.len(), right_ir.events.len());
    for (left, right) in left_ir.events.iter().zip(right_ir.events.iter()) {
        assert_eq!(left.trace_id, right.trace_id);
        assert_eq!(left.decision_id, right.decision_id);
        assert_eq!(left.policy_id, right.policy_id);
        assert_eq!(left.component, right.component);
    }
}

#[test]
fn canonical_parse_event_ir_failure_vector_is_deterministic() {
    let parser = CanonicalEs2020Parser;
    let (result, event_ir) =
        parser.parse_with_event_ir("", ParseGoal::Script, &ParserOptions::default());
    let error = result.expect_err("empty source should fail");
    assert_eq!(error.code, ParseErrorCode::EmptySource);
    assert_eq!(event_ir.events.len(), 2);
    assert!(matches!(
        event_ir.events[0].kind,
        ParseEventKind::ParseStarted
    ));
    assert!(matches!(
        event_ir.events[1].kind,
        ParseEventKind::ParseFailed
    ));
    assert_eq!(
        event_ir.events[1].error_code,
        Some(ParseErrorCode::EmptySource)
    );
    assert!(
        event_ir
            .events
            .iter()
            .all(|event| event.trace_id.starts_with("trace-parser-event-"))
    );
}

#[test]
fn canonical_parse_event_ast_materializer_metadata_is_versioned_and_stable() {
    assert_eq!(
        PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION,
        "franken-engine.parser-event-ast-materializer.contract.v1"
    );
    assert_eq!(
        PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION,
        "franken-engine.parser-event-ast-materializer.schema.v1"
    );
    assert_eq!(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX, "ast-node-");
    assert_eq!(
        MaterializedSyntaxTree::contract_version(),
        PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION
    );
    assert_eq!(
        MaterializedSyntaxTree::schema_version(),
        PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION
    );
}

#[test]
fn canonical_parse_event_to_ast_hash_parity_is_deterministic() {
    let parser = CanonicalEs2020Parser;
    let source = "import dep from \"pkg\";\nexport default dep;\n";
    let options = ParserOptions::default();
    let (result, event_ir) = parser.parse_with_event_ir(source, ParseGoal::Module, &options);
    let tree = result.expect("parse should succeed");

    let materialized = event_ir
        .materialize_from_source(source, &options)
        .expect("materialization should succeed");
    assert_eq!(
        materialized.syntax_tree.canonical_hash(),
        tree.canonical_hash()
    );
    assert_eq!(materialized.statement_nodes.len(), tree.body.len());
}

#[test]
fn canonical_parse_event_to_ast_node_id_witnesses_are_stable() {
    let parser = CanonicalEs2020Parser;
    let source = "await work";
    let options = ParserOptions::default();
    let (left_result, left_ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &options);
    let (right_result, right_ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &options);
    assert!(left_result.is_ok());
    assert!(right_result.is_ok());

    let left = left_ir
        .materialize_from_source(source, &options)
        .expect("left materialization should succeed");
    let right = right_ir
        .materialize_from_source(source, &options)
        .expect("right materialization should succeed");
    assert_eq!(left.root_node_id, right.root_node_id);
    assert_eq!(left.statement_nodes, right.statement_nodes);
    assert_eq!(left.canonical_hash(), right.canonical_hash());
}

#[test]
fn canonical_parse_event_to_ast_tamper_detection_is_deterministic() {
    let parser = CanonicalEs2020Parser;
    let source = "alpha;";
    let options = ParserOptions::default();
    let (_result, mut event_ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &options);
    event_ir.events[1].payload_hash =
        Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string());

    let err = event_ir
        .materialize_from_source(source, &options)
        .expect_err("tampered payload hash should be rejected");
    assert_eq!(
        err.code,
        ParseEventMaterializationErrorCode::StatementHashMismatch
    );
    assert_eq!(err.sequence, Some(1));
}

#[test]
fn canonical_parse_with_materialized_ast_replay_contract_is_deterministic() {
    let parser = CanonicalEs2020Parser;
    let source = "-7";
    let options = ParserOptions::default();
    let (result, _event_ir, materialized_result) =
        parser.parse_with_materialized_ast(source, ParseGoal::Script, &options);
    let tree = result.expect("parse should succeed");
    let materialized = materialized_result.expect("materializer should succeed");
    assert_eq!(
        materialized.syntax_tree.canonical_hash(),
        tree.canonical_hash()
    );

    let (failed_result, _failed_ir, failed_materialized_result) =
        parser.parse_with_materialized_ast("", ParseGoal::Script, &ParserOptions::default());
    let parse_err = failed_result.expect_err("empty source should fail parse");
    assert_eq!(parse_err.code, ParseErrorCode::EmptySource);
    let materializer_err = failed_materialized_result
        .expect_err("failed parse should fail materialization deterministically");
    assert_eq!(
        materializer_err.code,
        ParseEventMaterializationErrorCode::ParseFailedEventStream
    );
}

#[test]
fn canonical_parse_diagnostics_metadata_is_versioned_and_stable() {
    assert_eq!(
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION,
        "franken-engine.parser-diagnostics.taxonomy.v1"
    );
    assert_eq!(
        PARSER_DIAGNOSTIC_SCHEMA_VERSION,
        "franken-engine.parser-diagnostics.schema.v1"
    );
    assert_eq!(PARSER_DIAGNOSTIC_HASH_ALGORITHM, "sha256");
    assert_eq!(PARSER_DIAGNOSTIC_HASH_PREFIX, "sha256:");

    assert_eq!(
        ParseDiagnosticEnvelope::taxonomy_version(),
        PARSER_DIAGNOSTIC_TAXONOMY_VERSION
    );
    assert_eq!(
        ParseDiagnosticEnvelope::schema_version(),
        PARSER_DIAGNOSTIC_SCHEMA_VERSION
    );
    assert_eq!(
        ParseDiagnosticEnvelope::canonical_hash_algorithm(),
        PARSER_DIAGNOSTIC_HASH_ALGORITHM
    );
    assert_eq!(
        ParseDiagnosticEnvelope::canonical_hash_prefix(),
        PARSER_DIAGNOSTIC_HASH_PREFIX
    );
}

#[test]
fn canonical_parse_diagnostics_hash_vector_script_empty_source_is_stable() {
    let parser = CanonicalEs2020Parser;
    let error = parser
        .parse("", ParseGoal::Script)
        .expect_err("empty source should be rejected");
    let diagnostics = error.normalized_diagnostic();
    assert_eq!(
        diagnostics.canonical_hash(),
        "sha256:0f8535a4bba696fd0f0fc51bbe13ed8c9e4a5d1e8dd8f84acb7ce228ad17f68a"
    );
}

#[test]
fn canonical_parse_diagnostics_hash_vector_budget_exceeded_token_count_is_stable() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1024,
            max_token_count: 1,
            max_recursion_depth: 64,
        },
    };
    let error = parser
        .parse_with_options("alpha beta", ParseGoal::Script, &options)
        .expect_err("token budget should fail");
    let diagnostics = ParseDiagnosticEnvelope::from_parse_error(&error);
    assert_eq!(
        diagnostics.canonical_hash(),
        "sha256:443c9fe5a7218a6bd060824b175744a1d4cb36de120e0bbecb70f13eea5a29e5"
    );
}

#[test]
fn canonical_parse_diagnostics_utf8_boundary_budget_vector_is_stable() {
    let parser = CanonicalEs2020Parser;
    let options = ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: 1024,
            max_token_count: 1,
            max_recursion_depth: 64,
        },
    };

    let error = parser
        .parse_with_options("é β", ParseGoal::Script, &options)
        .expect_err("utf-8 boundary-safe scanner should enforce budget deterministically");
    let diagnostics = ParseDiagnosticEnvelope::from_parse_error(&error);
    let witness = diagnostics
        .witness
        .as_ref()
        .expect("budget diagnostics should include witness");
    assert_eq!(diagnostics.budget_kind, Some(ParseBudgetKind::TokenCount));
    assert_eq!(witness.token_count, 2);
    assert_eq!(witness.max_token_count, 1);
    assert!(diagnostics.canonical_hash().starts_with("sha256:"));
}

// ---------------------------------------------------------------------------
// Control flow statement parsing integration tests
// ---------------------------------------------------------------------------

#[test]
fn parser_emits_if_statement_with_condition_and_branches() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("if (x) { y; } else { z; }", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(&tree.body[0], Statement::If(if_stmt) if if_stmt.alternate.is_some()));
}

#[test]
fn parser_emits_for_statement_with_body() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("for (let i = 0; i < 10; i++) { x; }", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(&tree.body[0], Statement::For(_)));
}

#[test]
fn parser_emits_while_statement() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("while (cond) { body; }", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(&tree.body[0], Statement::While(_)));
}

#[test]
fn parser_emits_do_while_statement() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("do { body; } while (cond)", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(&tree.body[0], Statement::DoWhile(_)));
}

#[test]
fn parser_emits_return_statement_with_argument() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("return 42", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(
        &tree.body[0],
        Statement::Return(ret) if ret.argument.is_some()
    ));
}

#[test]
fn parser_emits_return_statement_without_argument() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("return", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(
        &tree.body[0],
        Statement::Return(ret) if ret.argument.is_none()
    ));
}

#[test]
fn parser_emits_throw_statement() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("throw new Error('fail')", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(&tree.body[0], Statement::Throw(_)));
}

#[test]
fn parser_emits_try_catch_statement() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "try { risky(); } catch (e) { handle(); }",
            ParseGoal::Script,
        )
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(
        &tree.body[0],
        Statement::TryCatch(tc) if tc.handler.is_some()
    ));
}

#[test]
fn parser_emits_switch_statement_with_cases() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "switch (x) { case 1: a(); break; default: b(); }",
            ParseGoal::Script,
        )
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(
        &tree.body[0],
        Statement::Switch(sw) if sw.cases.len() == 2
    ));
}

#[test]
fn parser_emits_break_and_continue_statements() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("break\ncontinue", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 2);
    assert!(matches!(&tree.body[0], Statement::Break(_)));
    assert!(matches!(&tree.body[1], Statement::Continue(_)));
}

#[test]
fn parser_emits_block_statement() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("{ let x = 1; }", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(&tree.body[0], Statement::Block(_)));
}

#[test]
fn parser_emits_function_declaration_with_params_and_body() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("function add(a, b) { return a + b; }", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(
        &tree.body[0],
        Statement::FunctionDeclaration(decl)
            if decl.name.as_deref() == Some("add") && decl.params.len() == 2
    ));
}

#[test]
fn parser_emits_async_function_declaration() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "async function fetch() { return await get(); }",
            ParseGoal::Script,
        )
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(
        &tree.body[0],
        Statement::FunctionDeclaration(decl)
            if decl.name.as_deref() == Some("fetch") && decl.is_async
    ));
}

// ---------------------------------------------------------------------------
// Arrow function expression parsing integration tests
// ---------------------------------------------------------------------------

#[test]
fn parser_emits_arrow_function_expression_body() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const f = (x) => x + 1", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    assert!(matches!(
        &tree.body[0],
        Statement::VariableDeclaration(decl)
            if !decl.declarations.is_empty()
    ));
    // The initializer should be an arrow function.
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        assert!(
            matches!(init, Expression::ArrowFunction { params, is_async, .. }
                if params.len() == 1 && !is_async
            )
        );
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_emits_arrow_function_block_body() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const f = (a, b) => { return a + b; }", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        assert!(matches!(init, Expression::ArrowFunction { params, .. } if params.len() == 2));
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_emits_arrow_function_single_param_no_parens() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const f = x => x * 2", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        assert!(matches!(init, Expression::ArrowFunction { params, .. }
                if params.len() == 1 && params[0].name() == Some("x")));
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_emits_async_arrow_function() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "const f = async (url) => { return await fetch(url); }",
            ParseGoal::Script,
        )
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        assert!(matches!(init, Expression::ArrowFunction { is_async, .. } if *is_async));
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_emits_arrow_function_no_params() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const f = () => 42", ParseGoal::Script)
        .expect("script parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        assert!(matches!(
            init,
            Expression::ArrowFunction { params, .. } if params.is_empty()
        ));
    } else {
        panic!("expected VariableDeclaration");
    }
}

// ---------------------------------------------------------------------------
// For-in / for-of statements
// ---------------------------------------------------------------------------

#[test]
fn parser_emits_for_in_statement() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("for (let key in obj) { x; }", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::ForIn(stmt) = &tree.body[0] {
        assert_eq!(stmt.binding.as_identifier(), Some("key"));
        assert_eq!(stmt.binding_kind, Some(VariableDeclarationKind::Let));
        assert!(matches!(&stmt.object, Expression::Identifier(s) if s == "obj"));
    } else {
        panic!("expected ForIn, got {:?}", tree.body[0]);
    }
}

#[test]
fn parser_emits_for_of_statement() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("for (const item of items) { x; }", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::ForOf(stmt) = &tree.body[0] {
        assert_eq!(stmt.binding.as_identifier(), Some("item"));
        assert_eq!(stmt.binding_kind, Some(VariableDeclarationKind::Const));
        assert!(matches!(&stmt.iterable, Expression::Identifier(s) if s == "items"));
    } else {
        panic!("expected ForOf, got {:?}", tree.body[0]);
    }
}

#[test]
fn parser_emits_for_in_bare_binding() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("for (k in obj) { x; }", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::ForIn(stmt) = &tree.body[0] {
        assert_eq!(stmt.binding.as_identifier(), Some("k"));
        assert!(stmt.binding_kind.is_none());
    } else {
        panic!("expected ForIn");
    }
}

#[test]
fn parser_emits_for_of_with_var() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("for (var x of arr) { x; }", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::ForOf(stmt) = &tree.body[0] {
        assert_eq!(stmt.binding.as_identifier(), Some("x"));
        assert_eq!(stmt.binding_kind, Some(VariableDeclarationKind::Var));
    } else {
        panic!("expected ForOf");
    }
}

#[test]
fn parser_for_in_of_canonical_hashes_stable() {
    let parser = CanonicalEs2020Parser;
    let sources = ["for (let k in obj) { x; }", "for (const v of arr) { v; }"];
    for src in &sources {
        let a = parser.parse(*src, ParseGoal::Script).unwrap();
        let b = parser.parse(*src, ParseGoal::Script).unwrap();
        assert_eq!(a.canonical_hash(), b.canonical_hash());
    }
}

// ---------------------------------------------------------------------------
// New expressions
// ---------------------------------------------------------------------------

#[test]
fn parser_emits_new_expression_with_args() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("new Foo(1, 2)", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::Expression(expr_stmt) = &tree.body[0] {
        if let Expression::New { callee, arguments } = &expr_stmt.expression {
            assert!(matches!(callee.as_ref(), Expression::Identifier(s) if s == "Foo"));
            assert_eq!(arguments.len(), 2);
        } else {
            panic!("expected New expression, got {:?}", expr_stmt.expression);
        }
    } else {
        panic!("expected Expression statement");
    }
}

#[test]
fn parser_emits_new_expression_no_args() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("new Foo", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::Expression(expr_stmt) = &tree.body[0] {
        if let Expression::New { callee, arguments } = &expr_stmt.expression {
            assert!(matches!(callee.as_ref(), Expression::Identifier(s) if s == "Foo"));
            assert!(arguments.is_empty());
        } else {
            panic!("expected New expression, got {:?}", expr_stmt.expression);
        }
    } else {
        panic!("expected Expression statement");
    }
}

#[test]
fn parser_emits_new_expression_member_callee() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("new Foo.Bar()", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::Expression(expr_stmt) = &tree.body[0] {
        if let Expression::New { callee, arguments } = &expr_stmt.expression {
            assert!(matches!(callee.as_ref(), Expression::Member { .. }));
            assert!(arguments.is_empty());
        } else {
            panic!("expected New expression, got {:?}", expr_stmt.expression);
        }
    } else {
        panic!("expected Expression statement");
    }
}

#[test]
fn parser_emits_new_in_assignment() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const x = new Map()", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        assert!(matches!(init, Expression::New { .. }));
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_optional_chain_emits_member_expression() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const theme = config?.theme", ParseGoal::Script)
        .expect("parse should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0].initializer.as_ref().unwrap();
        if let Expression::OptionalMember {
            object,
            property,
            computed,
        } = init
        {
            assert!(!computed);
            assert!(matches!(object.as_ref(), Expression::Identifier(name) if name == "config"));
            assert!(matches!(property.as_ref(), Expression::Identifier(name) if name == "theme"));
        } else {
            panic!("expected OptionalMember, got {:?}", init);
        }
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_optional_chain_emits_computed_member_expression() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const value = config?.[key]", ParseGoal::Script)
        .expect("parse should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0].initializer.as_ref().unwrap();
        if let Expression::OptionalMember {
            object,
            property,
            computed,
        } = init
        {
            assert!(*computed);
            assert!(matches!(object.as_ref(), Expression::Identifier(name) if name == "config"));
            assert!(matches!(property.as_ref(), Expression::Identifier(name) if name == "key"));
        } else {
            panic!("expected OptionalMember, got {:?}", init);
        }
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_optional_chain_emits_call_expression() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const result = maybeFn?.(first, second)", ParseGoal::Script)
        .expect("parse should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0].initializer.as_ref().unwrap();
        if let Expression::OptionalCall { callee, arguments } = init {
            assert!(matches!(callee.as_ref(), Expression::Identifier(name) if name == "maybeFn"));
            assert_eq!(arguments.len(), 2);
            assert!(
                matches!(&arguments[..], [Expression::Identifier(first), Expression::Identifier(second)] if first == "first" && second == "second")
            );
        } else {
            panic!("expected OptionalCall, got {:?}", init);
        }
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_optional_chain_supports_nested_package_style_expression() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(
            "const result = plugins?.[name]?.factory?.(ctx) ?? fallback",
            ParseGoal::Script,
        )
        .expect("parse should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0].initializer.as_ref().unwrap();
        if let Expression::Binary {
            operator,
            left,
            right,
        } = init
        {
            assert_eq!(*operator, BinaryOperator::NullishCoalescing);
            assert!(matches!(right.as_ref(), Expression::Identifier(name) if name == "fallback"));
            if let Expression::OptionalCall { callee, arguments } = left.as_ref() {
                assert!(
                    matches!(&arguments[..], [Expression::Identifier(argument)] if argument == "ctx")
                );
                if let Expression::OptionalMember {
                    object,
                    property,
                    computed,
                } = callee.as_ref()
                {
                    assert!(!computed);
                    assert!(
                        matches!(property.as_ref(), Expression::Identifier(name) if name == "factory")
                    );
                    if let Expression::OptionalMember {
                        object,
                        property,
                        computed,
                    } = object.as_ref()
                    {
                        assert!(*computed);
                        assert!(
                            matches!(object.as_ref(), Expression::Identifier(name) if name == "plugins")
                        );
                        assert!(
                            matches!(property.as_ref(), Expression::Identifier(name) if name == "name")
                        );
                    } else {
                        panic!("expected nested OptionalMember, got {:?}", object);
                    }
                } else {
                    panic!("expected OptionalMember callee, got {:?}", callee);
                }
            } else {
                panic!("expected OptionalCall left operand, got {:?}", left);
            }
        } else {
            panic!("expected Binary, got {:?}", init);
        }
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_optional_chain_preserves_nullish_coalescing_precedence() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const theme = config?.theme ?? fallback", ParseGoal::Script)
        .expect("parse should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0].initializer.as_ref().unwrap();
        if let Expression::Binary {
            operator,
            left,
            right,
        } = init
        {
            assert_eq!(*operator, BinaryOperator::NullishCoalescing);
            assert!(matches!(left.as_ref(), Expression::OptionalMember { .. }));
            assert!(matches!(right.as_ref(), Expression::Identifier(name) if name == "fallback"));
        } else {
            panic!("expected Binary, got {:?}", init);
        }
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_rejects_optional_chain_assignment_target() {
    let parser = CanonicalEs2020Parser;
    let source = "config?.theme = value";
    let err = parser
        .parse(source, ParseGoal::Script)
        .expect_err("optional chaining assignment target should fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert_eq!(
        err.message,
        "optional chaining cannot be used as an assignment target"
    );
    assert_eq!(err.span, Some(single_line_source_span(source)));
}

#[test]
fn parser_rejects_optional_chain_constructor_position() {
    let parser = CanonicalEs2020Parser;
    let source = "new config?.theme()";
    let err = parser
        .parse(source, ParseGoal::Script)
        .expect_err("optional chaining constructor position should fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert_eq!(
        err.message,
        "optional chaining cannot be used in constructor position"
    );
    assert_eq!(err.span, Some(single_line_source_span(source)));
}

#[test]
fn parser_rejects_invalid_optional_chain_property_form() {
    let parser = CanonicalEs2020Parser;
    let source = "const value = config?.123";
    let err = parser
        .parse(source, ParseGoal::Script)
        .expect_err("invalid optional property should fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    assert_eq!(
        err.message,
        "optional chaining property access requires an identifier after `?.`"
    );
    assert_eq!(err.span, Some(single_line_source_span(source)));
}

// ---------------------------------------------------------------------------
// Template literals
// ---------------------------------------------------------------------------

#[test]
fn parser_emits_template_literal_no_expressions() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const s = `hello world`", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        if let Expression::TemplateLiteral {
            quasis,
            expressions,
        } = init
        {
            assert_eq!(quasis, &["hello world"]);
            assert!(expressions.is_empty());
        } else {
            panic!("expected TemplateLiteral, got {:?}", init);
        }
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_emits_template_literal_with_expression() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const s = `hello ${name}!`", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        if let Expression::TemplateLiteral {
            quasis,
            expressions,
        } = init
        {
            assert_eq!(quasis, &["hello ", "!"]);
            assert_eq!(expressions.len(), 1);
            assert!(matches!(&expressions[0], Expression::Identifier(s) if s == "name"));
        } else {
            panic!("expected TemplateLiteral, got {:?}", init);
        }
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_emits_template_literal_multiple_expressions() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const s = `${a} + ${b} = ${c}`", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        if let Expression::TemplateLiteral {
            quasis,
            expressions,
        } = init
        {
            assert_eq!(quasis, &["", " + ", " = ", ""]);
            assert_eq!(expressions.len(), 3);
        } else {
            panic!("expected TemplateLiteral, got {:?}", init);
        }
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_emits_template_literal_nested_braces() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const s = `result: ${obj.a}`", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        if let Expression::TemplateLiteral {
            quasis,
            expressions,
        } = init
        {
            assert_eq!(quasis, &["result: ", ""]);
            assert_eq!(expressions.len(), 1);
            assert!(matches!(&expressions[0], Expression::Member { .. }));
        } else {
            panic!("expected TemplateLiteral, got {:?}", init);
        }
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_template_literal_empty() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const s = ``", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0]
            .initializer
            .as_ref()
            .expect("should have initializer");
        if let Expression::TemplateLiteral {
            quasis,
            expressions,
        } = init
        {
            assert_eq!(quasis, &[""]);
            assert!(expressions.is_empty());
        } else {
            panic!("expected TemplateLiteral, got {:?}", init);
        }
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_emits_tagged_template_as_scaffold_call() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("render`hello ${name}`", ParseGoal::Script)
        .expect("parse should succeed");
    assert_eq!(tree.body.len(), 1);
    if let Statement::Expression(expr_stmt) = &tree.body[0] {
        if let Expression::Call { callee, arguments } = &expr_stmt.expression {
            assert!(matches!(callee.as_ref(), Expression::Identifier(name) if name == "render"));
            assert_eq!(arguments.len(), 1);
            assert!(matches!(
                &arguments[..],
                [Expression::TemplateLiteral { quasis, expressions }]
                    if quasis == &["hello ", ""] && matches!(&expressions[..], [Expression::Identifier(name)] if name == "name")
            ));
        } else {
            panic!(
                "expected scaffold call for tagged template, got {:?}",
                expr_stmt.expression
            );
        }
    } else {
        panic!("expected Expression statement");
    }
}

#[test]
fn parser_rejects_unbalanced_template_interpolation() {
    let parser = CanonicalEs2020Parser;
    let err = parser
        .parse("const s = `value: ${name`", ParseGoal::Script)
        .expect_err("unbalanced interpolation should fail");
    assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
}

// ---------------------------------------------------------------------------
// Numeric literal bases
// ---------------------------------------------------------------------------

#[test]
fn parser_emits_hex_numeric_literal() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const x = 0xFF", ParseGoal::Script)
        .expect("parse should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0].initializer.as_ref().unwrap();
        assert_eq!(*init, Expression::NumericLiteral(255));
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_emits_octal_numeric_literal() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const x = 0o77", ParseGoal::Script)
        .expect("parse should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0].initializer.as_ref().unwrap();
        assert_eq!(*init, Expression::NumericLiteral(63));
    } else {
        panic!("expected VariableDeclaration");
    }
}

#[test]
fn parser_emits_binary_numeric_literal() {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse("const x = 0b1010", ParseGoal::Script)
        .expect("parse should succeed");
    if let Statement::VariableDeclaration(decl) = &tree.body[0] {
        let init = decl.declarations[0].initializer.as_ref().unwrap();
        assert_eq!(*init, Expression::NumericLiteral(10));
    } else {
        panic!("expected VariableDeclaration");
    }
}

// ---------------------------------------------------------------------------
// Control flow determinism (canonical hash stability)
// ---------------------------------------------------------------------------

#[test]
fn parser_control_flow_canonical_hashes_are_deterministic() {
    let parser = CanonicalEs2020Parser;
    let sources = [
        "if (x) { y; }",
        "for (let i = 0; i < 10; i++) { x; }",
        "while (true) { break; }",
        "function foo(a) { return a; }",
        "const f = (x) => x + 1",
        "for (let k in obj) { k; }",
        "new Foo(1)",
        "const s = `hello ${x}`",
        "0xFF",
    ];
    for source in &sources {
        let tree1 = parser
            .parse(*source, ParseGoal::Script)
            .expect("parse should succeed");
        let tree2 = parser
            .parse(*source, ParseGoal::Script)
            .expect("parse should succeed");
        assert_eq!(
            tree1.canonical_hash(),
            tree2.canonical_hash(),
            "canonical hash should be deterministic for: {source}"
        );
        assert_eq!(
            tree1.canonical_bytes(),
            tree2.canonical_bytes(),
            "canonical bytes should be deterministic for: {source}"
        );
    }
}
