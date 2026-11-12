#![forbid(unsafe_code)]

//! Static import attributes survive parsing, persistence and every lowering
//! stage. Format validation belongs to the resolved loader; dynamic import
//! options are deliberately outside this contract.

use frankenengine_engine::ast::{ExportKind, NamedExportClause, ParseGoal, Statement, SyntaxTree};
use frankenengine_engine::import_attributes::{
    ImportAttributes, MAX_IMPORT_ATTRIBUTE_KEY_BYTES, MAX_IMPORT_ATTRIBUTE_VALUE_BYTES,
    MAX_IMPORT_ATTRIBUTES,
};
use frankenengine_engine::ir_contract::{
    Ir0Module, Ir1Op, Ir3Instruction, IrErrorCode, IrSchemaVersion, verify_ir0_hash,
    verify_ir1_source, verify_ir3_specialization,
};
use frankenengine_engine::js_string::JsString;
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, lower_ir0_to_ir1, lower_ir0_to_ir3, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};
use frankenengine_engine::parser_arena::{ArenaBudget, ParserArena};
use frankenengine_engine::ts_normalization::{
    TsNormalizationConfig, normalize_typescript_to_es2020,
};

fn parse(source: &str) -> SyntaxTree {
    CanonicalEs2020Parser
        .parse(source, ParseGoal::Module)
        .unwrap_or_else(|error| panic!("{source}: {error}"))
}

fn attributes(tree: &SyntaxTree) -> Vec<&ImportAttributes> {
    tree.body
        .iter()
        .filter_map(|statement| match statement {
            Statement::Import(import) => Some(&import.import_attributes),
            Statement::Export(export) => match &export.kind {
                ExportKind::NamedClause(clause) if clause.source().is_some() => {
                    Some(clause.import_attributes())
                }
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn context() -> LoweringContext {
    LoweringContext::new("static-attributes", "compile", "resolved-format")
}

#[test]
fn every_static_import_and_reexport_form_carries_attributes_through_ir3() {
    for source in [
        "import 'package-data' with { type: 'json' };",
        "import data from 'package-data' with { type: 'json' };",
        "import * as data from 'package-data' with { type: 'json' };",
        "import { default as data } from 'package-data' with { type: 'json' };",
        "import data, { default as same } from 'package-data' with { type: 'json' };",
        "import data, * as ns from 'package-data' with { type: 'json' };",
        "export { default as data } from 'package-data' with { type: 'json' };",
        "export {} from 'package-data' with { type: 'json' };",
        "export * from 'package-data' with { type: 'json' };",
        "export * as data from 'package-data' with { type: 'json' };",
    ] {
        let tree = parse(source);
        assert_eq!(attributes(&tree).len(), 1, "{source}");
        assert_eq!(attributes(&tree)[0].get("type"), Some("json"), "{source}");
        let ir0 = Ir0Module::from_syntax_tree(tree, "entry.mjs");
        let output = lower_ir0_to_ir3(&ir0, &context()).expect(source);
        let ir1: Vec<_> = output
            .ir1
            .ops
            .iter()
            .filter_map(|op| match op {
                Ir1Op::ImportModule {
                    specifier,
                    import_attributes,
                } => Some((specifier.as_str(), import_attributes.get("type"))),
                _ => None,
            })
            .collect();
        assert_eq!(ir1, [(Some("package-data"), Some("json"))], "{source}");
        let ir2: Vec<_> = output
            .ir2
            .ops
            .iter()
            .filter_map(|op| match &op.inner {
                Ir1Op::ImportModule {
                    import_attributes, ..
                } => import_attributes.get("type"),
                _ => None,
            })
            .collect();
        assert_eq!(ir2, ["json"], "{source}");
        let ir3: Vec<_> = output
            .ir3
            .instructions
            .iter()
            .filter_map(|op| match op {
                Ir3Instruction::ImportModule {
                    import_attributes, ..
                } => import_attributes.get("type"),
                _ => None,
            })
            .collect();
        assert_eq!(ir3, ["json"], "{source}");
    }
}

#[test]
fn repeated_specifiers_keep_each_distinct_attribute_request() {
    let tree = parse(
        "import 'pkg' with { type: 'json' }; import 'pkg'; import 'pkg' with { type: 'css' };",
    );
    let ir0 = Ir0Module::from_syntax_tree(tree, "entry.mjs");
    let output = lower_ir0_to_ir3(&ir0, &context()).unwrap();
    let requests: Vec<_> = output
        .ir3
        .instructions
        .iter()
        .filter_map(|op| match op {
            Ir3Instruction::ImportModule {
                import_attributes, ..
            } => Some(import_attributes.get("type")),
            _ => None,
        })
        .collect();
    assert_eq!(requests, [Some("json"), None, Some("css")]);
}

#[test]
fn quoted_delimiters_decoded_keys_comments_and_unknown_types_are_preserved() {
    let tree = parse(
        r#"import { "from 'ignored'" as value } from 'package-data'
        with { /* comment */ "f,rom:key": "a,b:c} from 'fake'", "typ\u0065": "json", };
        export * from './code.js' with { type: 'css', if: '' };"#,
    );
    let attrs = attributes(&tree);
    assert_eq!(attrs[0].get("f,rom:key"), Some("a,b:c} from 'fake'"));
    assert_eq!(attrs[0].get("type"), Some("json"));
    assert_eq!(attrs[1].get("type"), Some("css"));
    assert_eq!(attrs[1].get("if"), Some(""));
    let Statement::Import(import) = &tree.body[0] else {
        panic!("import")
    };
    assert_eq!(import.source.as_str(), Some("package-data"));
}

#[test]
fn malformed_attributes_and_decoded_duplicate_keys_are_syntax_errors() {
    for tail in [
        r#"with { type: 'json', "typ\u0065": 'json' }"#,
        r#"with { \u0074ype: 'json', type: 'json' }"#,
        "with { type: json }",
        "with { type: 1 }",
        "with { 1: 'json' }",
        "with { type 'json' }",
        "with { type: 'json' other: 'value' }",
        "with {,}",
        "with { type: 'json',, }",
        "with { ...other }",
        "with { type: 'json' } trailing",
        "with { type: 'json'",
        "with { type: 'json' }}",
    ] {
        for head in ["import 'pkg'", "export * from 'pkg'"] {
            let source = format!("{head} {tail};");
            let error = CanonicalEs2020Parser
                .parse(source.as_str(), ParseGoal::Module)
                .unwrap_err();
            assert_eq!(
                error.code,
                ParseErrorCode::InvalidSyntax,
                "{source}: {error}"
            );
        }
    }
}

#[test]
fn bounded_attributes_refuse_excess_data_and_ill_formed_strings_without_loss() {
    let boundary = format!(
        "import 'pkg' with {{ '{}': '{}' }};",
        "k".repeat(MAX_IMPORT_ATTRIBUTE_KEY_BYTES),
        "v".repeat(MAX_IMPORT_ATTRIBUTE_VALUE_BYTES)
    );
    assert_eq!(attributes(&parse(&boundary))[0].len(), 1);
    let too_many = (0..=MAX_IMPORT_ATTRIBUTES)
        .map(|index| format!("k{index}: ''"))
        .collect::<Vec<_>>()
        .join(",");
    let too_much = (0..5)
        .map(|index| format!("k{index}: '{}'", "v".repeat(1024)))
        .collect::<Vec<_>>()
        .join(",");
    for entries in [
        format!("'{}': ''", "k".repeat(MAX_IMPORT_ATTRIBUTE_KEY_BYTES + 1)),
        format!(
            "key: '{}'",
            "v".repeat(MAX_IMPORT_ATTRIBUTE_VALUE_BYTES + 1)
        ),
        too_many,
        too_much,
        r#""\uD800": 'json'"#.to_string(),
        r#"type: '\uDC00'"#.to_string(),
    ] {
        let source = format!("import 'pkg' with {{ {entries} }};");
        assert_eq!(
            CanonicalEs2020Parser
                .parse(source.as_str(), ParseGoal::Module)
                .unwrap_err()
                .code,
            ParseErrorCode::UnsupportedSyntax,
            "{source}"
        );
    }
}

#[test]
fn ast_and_ir_serialization_hashes_bind_attributes_without_changing_empty_wires() {
    let tree = parse(
        "import data from 'pkg' with { type: 'json' }; export { default as value } from 'pkg' with { type: 'json' };",
    );
    let wire = serde_json::to_string(&tree).unwrap();
    let restored: SyntaxTree = serde_json::from_str(&wire).unwrap();
    assert_eq!(restored, tree);
    assert_eq!(restored.canonical_hash(), tree.canonical_hash());
    assert!(wire.contains("$module_source"));
    assert_eq!(
        attributes(&restored)
            .iter()
            .map(|a| a.get("type"))
            .collect::<Vec<_>>(),
        [Some("json"), Some("json")]
    );

    let attributed = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree.clone(), "entry.mjs"),
        &context(),
    )
    .unwrap();
    let mut erased = tree;
    for statement in &mut erased.body {
        match statement {
            Statement::Import(import) => import.import_attributes = ImportAttributes::default(),
            Statement::Export(export) => {
                let ExportKind::NamedClause(clause) = &export.kind else {
                    unreachable!()
                };
                export.kind = ExportKind::NamedClause(NamedExportClause::new(
                    clause.canonical_head(),
                    clause.source().cloned(),
                ));
            }
            _ => unreachable!(),
        }
    }
    let erased = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(erased, "entry.mjs"),
        &context(),
    )
    .unwrap();
    assert_ne!(attributed.ir1.content_hash(), erased.ir1.content_hash());
    assert_ne!(attributed.ir2.content_hash(), erased.ir2.content_hash());
    assert_ne!(attributed.ir3.content_hash(), erased.ir3.content_hash());
    let plain: Ir1Op = serde_json::from_str(r#"{"ImportModule":{"specifier":"pkg"}}"#).unwrap();
    assert_eq!(
        serde_json::to_string(&plain).unwrap(),
        r#"{"ImportModule":{"specifier":"pkg"}}"#
    );

    let exact = NamedExportClause::new_with_import_attributes(
        "*",
        JsString::from_code_units(&[0xD800]),
        attributes(&restored)[0].clone(),
    );
    let exact_wire = serde_json::to_string(&exact).unwrap();
    assert!(exact_wire.contains("$wtf16"));
    assert_eq!(
        serde_json::from_str::<NamedExportClause>(&exact_wire).unwrap(),
        exact
    );
}

#[test]
fn typed_imports_cannot_be_downgraded_to_an_attribute_unaware_ir_schema() {
    let ir0 = Ir0Module::from_syntax_tree(
        parse("import data from 'pkg' with { type: 'json' };"),
        "entry.mjs",
    );
    let mut output = lower_ir0_to_ir3(&ir0, &context()).unwrap();
    let legacy = IrSchemaVersion {
        major: 0,
        minor: 17,
        patch: u32::MAX,
    };
    let mut legacy_ir0 = ir0.clone();
    legacy_ir0.header.schema_version = legacy;
    assert_eq!(
        verify_ir0_hash(&legacy_ir0, &legacy_ir0.content_hash())
            .unwrap_err()
            .code,
        IrErrorCode::SchemaVersionMismatch
    );
    assert!(lower_ir0_to_ir1(&legacy_ir0).is_err());
    output.ir1.header.schema_version = legacy;
    assert_eq!(
        verify_ir1_source(&output.ir1, &ir0.content_hash())
            .unwrap_err()
            .code,
        IrErrorCode::SchemaVersionMismatch
    );
    assert!(lower_ir1_to_ir2(&output.ir1).is_err());
    output.ir2.header.schema_version = legacy;
    assert!(lower_ir2_to_ir3(&output.ir2).is_err());
    output.ir3.header.schema_version = legacy;
    assert_eq!(
        verify_ir3_specialization(&output.ir3).unwrap_err().code,
        IrErrorCode::SchemaVersionMismatch
    );
    let mut plain = Ir0Module::from_syntax_tree(parse("import 'pkg';"), "plain.mjs");
    plain.header.schema_version = legacy;
    verify_ir0_hash(&plain, &plain.content_hash())
        .expect("ordinary historical imports stay readable");
    plain.header.schema_version = IrSchemaVersion {
        minor: IrSchemaVersion::CURRENT.minor + 1,
        ..IrSchemaVersion::CURRENT
    };
    assert!(
        lower_ir0_to_ir1(&plain).is_err(),
        "direct IR0 lowering must reject future schemas"
    );
}

#[test]
fn json_named_imports_and_reexports_refuse_nondefault_names() {
    for source in [
        "import { answer } from 'pkg' with { type: 'json' };",
        "import data, { answer as value } from 'pkg' with { type: 'json' };",
        "import { 'answer' as value } from 'pkg' with { type: 'json' };",
        "export { answer as value } from 'pkg' with { type: 'json' };",
        "export { 'answer' as value } from 'pkg' with { type: 'json' };",
    ] {
        let ir0 = Ir0Module::from_syntax_tree(parse(source), "entry.mjs");
        let error = lower_ir0_to_ir1(&ir0).expect_err(source);
        let frankenengine_engine::lowering_pipeline::LoweringPipelineError::UnsupportedSyntax(
            diagnostic,
        ) = error
        else {
            panic!("expected an explicit JSON export refusal: {source}");
        };
        assert_eq!(
            diagnostic.diagnostic_code, "json_default_export_only",
            "{source}"
        );
        assert!(diagnostic.span.is_some());
    }
}

#[test]
fn core_module_facades_never_erase_attributed_module_requests() {
    for source in [
        "import path from 'node:path' with { type: 'unsupported' }; path.join('a', 'b');",
        "import { readFileSync } from 'node:fs' with { type: 'unsupported' }; readFileSync('a');",
        "import * as fs from 'node:fs' with { type: 'unsupported' }; fs.readFileSync('a');",
        "import { once } from 'node:events' with { type: 'unsupported' }; once(null, 'event');",
        "export { basename } from 'node:path' with { type: 'unsupported' };",
        "export * as path from 'node:path' with { type: 'unsupported' };",
    ] {
        let ir0 = Ir0Module::from_syntax_tree(parse(source), "entry.mjs");
        let lowered = lower_ir0_to_ir3(&ir0, &context()).expect(source);
        let imports = lowered
            .ir3
            .instructions
            .iter()
            .filter(|instruction| {
                matches!(instruction, Ir3Instruction::ImportModule { import_attributes, .. }
                if import_attributes.get("type") == Some("unsupported"))
            })
            .count();
        assert_eq!(imports, 1, "{source}");
    }
}

#[test]
fn arena_roundtrips_and_charges_attribute_payload_and_audit_identity() {
    let tree = parse("import data from 'pkg' with { type: 'json' };");
    let arena = ParserArena::from_syntax_tree(&tree, ArenaBudget::default()).unwrap();
    assert_eq!(arena.to_syntax_tree().unwrap(), tree);
    let mut plain = tree.clone();
    let Statement::Import(import) = &mut plain.body[0] else {
        unreachable!()
    };
    import.import_attributes = ImportAttributes::default();
    let plain = ParserArena::from_syntax_tree(&plain, ArenaBudget::default()).unwrap();
    assert_eq!(arena.bytes_used() - plain.bytes_used(), 8);
    assert_ne!(
        arena.handle_audit_jsonl().unwrap(),
        plain.handle_audit_jsonl().unwrap()
    );
    let tight = ArenaBudget {
        max_bytes: arena.bytes_used() - 1,
        ..ArenaBudget::default()
    };
    assert!(ParserArena::from_syntax_tree(&tree, tight).is_err());
    let reexport = parse("export { default as value } from 'pkg' with { type: 'json' };");
    let arena = ParserArena::from_syntax_tree(&reexport, ArenaBudget::default()).unwrap();
    assert_eq!(arena.to_syntax_tree().unwrap(), reexport);
}

#[test]
fn typescript_normalization_retains_static_attribute_clauses() {
    let source = "import data from 'pkg' with { type: 'json' };\nexport { default as value } from 'pkg' with { type: 'json' };\nconst count: number = 1;";
    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace",
        "decision",
        "policy",
    )
    .unwrap();
    assert!(!output.normalized_source.contains(": number"));
    let tree = parse(&output.normalized_source);
    assert_eq!(
        attributes(&tree)
            .iter()
            .map(|attrs| attrs.get("type"))
            .collect::<Vec<_>>(),
        [Some("json"), Some("json")]
    );
}
