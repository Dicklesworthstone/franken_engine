#![forbid(unsafe_code)]

//! Import clauses must survive the arena without changing binding or lowering
//! semantics, and every additional owned name must participate in admission.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::ast::{
    ImportClause, ImportDeclaration, ImportSpecifier, ParseGoal, SourceSpan, Statement, SyntaxTree,
};
use frankenengine_engine::import_attributes::ImportAttributes;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::js_string::JsString;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};
use frankenengine_engine::parser_arena::{
    ArenaBudget, ArenaBudgetKind, ArenaError, HandleAuditKind, ParserArena,
};

fn tree(clause: ImportClause) -> SyntaxTree {
    let span = SourceSpan::new(0, 10, 1, 1, 1, 11);
    SyntaxTree {
        goal: ParseGoal::Module,
        body: vec![Statement::Import(ImportDeclaration {
            binding: clause.primary_binding().map(str::to_owned),
            clause,
            source: "module-data".into(),
            import_attributes: ImportAttributes::default(),
            span,
        })],
        span,
    }
}

fn arena(tree: &SyntaxTree) -> ParserArena {
    ParserArena::from_syntax_tree(tree, ArenaBudget::default()).expect("admit import tree")
}

fn descriptor(tree: &SyntaxTree) -> String {
    arena(tree)
        .handle_audit_entries()
        .into_iter()
        .find(|entry| entry.handle_kind == HandleAuditKind::Node)
        .expect("import node audit")
        .descriptor
}

fn named(import_name: &str, local_name: &str) -> ImportSpecifier {
    ImportSpecifier {
        import_name: import_name.into(),
        local_name: local_name.into(),
    }
}

fn assert_exact_byte_limit(tree: &SyntaxTree) {
    let needed = arena(tree).bytes_used();
    let exact = ArenaBudget {
        max_bytes: needed,
        ..ArenaBudget::default()
    };
    assert_eq!(
        ParserArena::from_syntax_tree(tree, exact)
            .expect("exact budget admits import")
            .to_syntax_tree()
            .unwrap(),
        *tree
    );
    let tight = ArenaBudget {
        max_bytes: needed - 1,
        ..exact
    };
    assert!(matches!(
        ParserArena::from_syntax_tree(tree, tight),
        Err(ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Bytes,
            ..
        })
    ));
}

#[test]
fn all_six_import_forms_keep_exact_tree_hash_and_lowering_through_arena() {
    for head in [
        "import 'module-data'",
        "import data from 'module-data'",
        "import * as data from 'module-data'",
        "import { default as data } from 'module-data'",
        "import data, { default as alias } from 'module-data'",
        "import data, * as ns from 'module-data'",
    ] {
        for tail in [";", " with { type: 'json' };"] {
            let source = format!("{head}{tail}");
            let original = CanonicalEs2020Parser
                .parse(source.as_str(), ParseGoal::Module)
                .unwrap_or_else(|error| panic!("{source}: {error}"));
            let retained = arena(&original);
            let restored = retained.to_syntax_tree().unwrap();
            assert_eq!(restored, original, "{source}");
            assert_eq!(
                retained.canonical_hash().unwrap(),
                original.canonical_hash()
            );
            assert_exact_byte_limit(&original);

            let context = LoweringContext::new("arena-imports", "compile", "clause-preservation");
            let direct = lower_ir0_to_ir3(
                &Ir0Module::from_syntax_tree(original, "entry.mjs"),
                &context,
            )
            .expect("lower original import");
            let through_arena = lower_ir0_to_ir3(
                &Ir0Module::from_syntax_tree(restored, "entry.mjs"),
                &context,
            )
            .expect("lower restored import");
            assert_eq!(
                through_arena.ir3.canonical_bytes(),
                direct.ir3.canonical_bytes(),
                "{source}"
            );
        }
    }
}

#[test]
fn import_audit_identity_distinguishes_clause_form_names_and_specifier_order() {
    let forms = [
        ImportClause::SideEffect,
        ImportClause::Default {
            local: "data".into(),
        },
        ImportClause::Namespace {
            local: "data".into(),
        },
        ImportClause::Named {
            specifiers: vec![named("default", "data")],
        },
        ImportClause::DefaultAndNamed {
            default: "data".into(),
            specifiers: vec![named("default", "alias")],
        },
        ImportClause::DefaultAndNamespace {
            default: "data".into(),
            namespace: "ns".into(),
        },
    ];
    let descriptors: BTreeSet<_> = forms
        .into_iter()
        .map(|clause| descriptor(&tree(clause)))
        .collect();
    assert_eq!(
        descriptors.len(),
        6,
        "every clause form has its own audit identity"
    );

    let clauses = [
        ImportClause::Named { specifiers: vec![] },
        ImportClause::Named {
            specifiers: vec![named("first", "local")],
        },
        ImportClause::Named {
            specifiers: vec![named("second", "local")],
        },
        ImportClause::Named {
            specifiers: vec![named("first", "other")],
        },
        ImportClause::Named {
            specifiers: vec![named("first", "a"), named("second", "b")],
        },
        ImportClause::Named {
            specifiers: vec![named("second", "b"), named("first", "a")],
        },
    ];
    let descriptors: BTreeSet<_> = clauses
        .into_iter()
        .map(|clause| {
            let original = tree(clause);
            assert_eq!(arena(&original).to_syntax_tree().unwrap(), original);
            descriptor(&original)
        })
        .collect();
    assert_eq!(
        descriptors.len(),
        6,
        "imported names, aliases and order remain distinct"
    );
}

#[test]
fn named_import_budget_includes_imported_names_and_local_aliases() {
    let small = tree(ImportClause::Named {
        specifiers: vec![named("x", "y")],
    });
    let imported = tree(ImportClause::Named {
        specifiers: vec![named(&"x".repeat(8193), "y")],
    });
    let aliased = tree(ImportClause::Named {
        specifiers: vec![named("x", &"y".repeat(8193))],
    });
    let small_bytes = arena(&small).bytes_used();
    for large in [&imported, &aliased] {
        assert_eq!(arena(large).bytes_used() - small_bytes, 8192);
        let budget = ArenaBudget {
            max_bytes: small_bytes + 4096,
            ..ArenaBudget::default()
        };
        assert!(matches!(
            ParserArena::from_syntax_tree(large, budget),
            Err(ArenaError::BudgetExceeded {
                kind: ArenaBudgetKind::Bytes,
                ..
            })
        ));
        assert_exact_byte_limit(large);
    }
}

#[test]
fn named_import_budget_accounts_for_specifier_backing_storage() {
    // Empty strings isolate the Vec backing allocation from string payload.
    // The arena accepts an already-built AST and must budget it even before
    // a later semantic verifier rejects these deliberately invalid names.
    let empty = tree(ImportClause::Named { specifiers: vec![] });
    let populated = tree(ImportClause::Named {
        specifiers: vec![named("", ""); 256],
    });
    let storage = u64::try_from(std::mem::size_of::<ImportSpecifier>() * 256).unwrap();
    let empty_bytes = arena(&empty).bytes_used();
    assert!(arena(&populated).bytes_used() >= empty_bytes + storage);
    let budget = ArenaBudget {
        max_bytes: empty_bytes + storage - 1,
        ..ArenaBudget::default()
    };
    assert!(matches!(
        ParserArena::from_syntax_tree(&populated, budget),
        Err(ArenaError::BudgetExceeded {
            kind: ArenaBudgetKind::Bytes,
            ..
        })
    ));
    assert_exact_byte_limit(&populated);
}

#[test]
fn legacy_binding_exact_source_and_attributes_survive_without_clause_reconstruction() {
    let mut original = tree(ImportClause::Named {
        specifiers: vec![named("exported", "alias")],
    });
    let Statement::Import(import) = &mut original.body[0] else {
        unreachable!()
    };
    import.source = JsString::from_code_units(&[0xD800, u16::from(b'x')]);
    import.import_attributes = ImportAttributes::new(BTreeMap::from([
        ("type".into(), "json".into()),
        ("custom".into(), "retained".into()),
    ]))
    .unwrap();
    let without_legacy = arena(&original).bytes_used();
    let Statement::Import(import) = &mut original.body[0] else {
        unreachable!()
    };
    // Preserve both public AST fields exactly instead of trusting the legacy
    // compatibility field to represent a complete clause.
    import.binding = Some("legacy".repeat(1024));
    let retained = arena(&original);
    assert_eq!(retained.to_syntax_tree().unwrap(), original);
    assert_eq!(retained.bytes_used() - without_legacy, 6 * 1024);
    assert_eq!(
        retained.canonical_hash().unwrap(),
        original.canonical_hash()
    );
    assert_exact_byte_limit(&original);
}
