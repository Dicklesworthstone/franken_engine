#![forbid(unsafe_code)]

//! Formatted ESM lists execute through the public core parser, lowering, and
//! module loader, including empty lists that still evaluate their dependency.

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_core::ast::{ExportKind, ParseGoal, Statement};
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};

fn assert_modules(files: &[(&str, &str)], entry: &str, expected: &[&str]) {
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "franken-core-module-specifiers-{}-{stamp}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&root).unwrap();
    for (name, source) in files {
        fs::write(root.join(name), source).unwrap();
    }
    let entry_path = root.join("entry.mjs");
    fs::write(&entry_path, entry).unwrap();

    let tree = CanonicalEs2020Parser
        .parse(entry, ParseGoal::Module)
        .unwrap_or_else(|error| panic!("entry must parse: {error}\n{entry}"));
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, entry_path.display().to_string()),
        &LoweringContext::new("named-specifiers", "named-specifiers", "named-specifiers"),
    )
    .expect("module entry must lower")
    .ir3;

    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::ModuleLoad,
        ]
        .into_iter()
        .collect();
        config.module_root = Some(root.display().to_string());
        let result = InterpreterCore::new(config, "named-specifiers")
            .execute(&module)
            .expect("module graph must execute");
        let actual: Vec<_> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn formatted_imports_and_reexports_execute_across_modules() {
    assert_modules(
        &[
            (
                "values.mjs",
                r#"
                const first = 19;
                const second = 23;
                function add(value) { return value + first; }
                export {
                    first,
                    second as remaining,
                    add as compute,
                };
                export default 2;
                "#,
            ),
            (
                "bridge.mjs",
                r#"
                export {
                    first as start,
                    remaining as end,
                    compute,
                    default as step,
                } from './values.mjs';
                "#,
            ),
        ],
        r#"
        import step, {
            first as direct,
            remaining,
            compute as directCompute,
        } from './values.mjs';
        import {
            start,
            end,
            compute,
            step as bridgeStep,
        } from './bridge.mjs';
        console.log(direct, remaining, start, end, step, bridgeStep, compute(1), directCompute(2));
        "#,
        &["19 23 19 23 2 2 20 21"],
    );
}

#[test]
fn comments_are_trivia_without_becoming_delimiters_or_identifier_text() {
    assert_modules(
        &[(
            "values.mjs",
            r#"
            const value = 40;
            const bonus = 2;
            export/**/{
                value /* commas , and braces } */ as/**/base,
                bonus, /* trailing , } */
            } /* trailing export trivia */;
            "#,
        )],
        r#"
        import/**/{
            base/**/as/**/answer,
            bonus, // trailing comma, } and from inside a comment
        } /* before from , } */ from /* before source */ './values.mjs' /* after source */;
        console.log(answer + bonus);
        "#,
        &["42"],
    );
}

#[test]
fn comment_only_empty_lists_still_evaluate_dependencies_once() {
    assert_modules(
        &[
            (
                "empty-import.mjs",
                "console.log('import evaluated'); export default 7;",
            ),
            (
                "empty-reexport.mjs",
                "console.log('reexport evaluated'); export const ignored = 1;",
            ),
            (
                "bridge.mjs",
                r#"
                export { /* empty, including a } */ } from './empty-reexport.mjs';
                export { /* no local bindings */ };
                export default 5;
                "#,
            ),
        ],
        r#"
        import { /* empty, including a } */ } from './empty-import.mjs';
        import fallback, { /* no named bindings */ } from './empty-import.mjs';
        import bridge, { /* still load the bridge */ } from './bridge.mjs';
        console.log(fallback, bridge);
        "#,
        &["import evaluated", "reexport evaluated", "7 5"],
    );
}

#[test]
fn escaped_and_unicode_names_resolve_after_export_head_canonicalization() {
    assert_modules(
        &[
            (
                "values.mjs",
                r#"
                const value = 41;
                const π = 1;
                export { v\u0061lue/**/as/**/v\u0061lue, π, };
                "#,
            ),
            (
                "bridge.mjs",
                r#"export { value as ren\u0061med, π, } from './values.mjs';"#,
            ),
        ],
        r#"
        import { ren\u0061med as \u0061nswer, π, } from './bridge.mjs';
        console.log(answer + π);
        "#,
        &["42"],
    );
}

#[test]
fn canonical_export_heads_keep_existing_wire_spelling_and_exact_module_sources() {
    for (source, expected_head) in [
        (
            "export { value, other as alias }",
            "{ value, other as alias }",
        ),
        ("export{value,other as alias}", "{value,other as alias}"),
        ("export { value, }", "{ value }"),
        (
            "export { value/**/as/**/alias, /* } */ }",
            "{ value as alias }",
        ),
        (r"export { v\u0061lue, }", "{ value }"),
        ("export { /* empty } */ }", "{}"),
    ] {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Module)
            .unwrap();
        let Statement::Export(export) = &tree.body[0] else {
            panic!("expected an export declaration");
        };
        let ExportKind::NamedClause(clause) = &export.kind else {
            panic!("expected a named export clause");
        };
        assert_eq!(clause.canonical_head(), expected_head, "{source}");
    }

    let tree = CanonicalEs2020Parser
        .parse(r#"export { value, } from "\uD800";"#, ParseGoal::Module)
        .unwrap();
    let Statement::Export(export) = &tree.body[0] else {
        panic!("expected an exact-source export declaration");
    };
    let ExportKind::NamedClause(clause) = &export.kind else {
        panic!("expected a named re-export clause");
    };
    assert_eq!(clause.canonical_head(), "{ value }");
    assert_eq!(clause.source().unwrap().code_units_vec(), vec![0xD800]);
}

#[test]
fn missing_entries_invalid_aliases_and_unsupported_names_remain_errors() {
    for list in [
        ",",
        "value,,",
        ",value",
        "value, /* missing */ , other",
        "/* missing */, value",
        "value, /* missing */ ,",
        "value other",
        "va/* split token */lue",
        "value a/* split keyword */s alias",
        "value as al/* split token */ias",
        "value as alias extra",
        r"value a\u0073 alias",
        "'quoted' as alias",
        "value as 'quoted'",
    ] {
        for source in [
            format!("import {{ {list} }} from './values.mjs';"),
            format!("import fallback, {{ {list} }} from './values.mjs';"),
            format!("export {{ {list} }};"),
            format!("export {{ {list} }} from './values.mjs';"),
        ] {
            let error = CanonicalEs2020Parser
                .parse(source.as_str(), ParseGoal::Module)
                .unwrap_err();
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source}");
        }
    }
    for source in [
        "import { value as same, other as same, } from './values.mjs';",
        "import { value, /* unterminated } from './values.mjs';",
        "export { value, /* unterminated };",
        "export { value, } fromage './values.mjs';",
        "export { value, } from './values.mjs' extra;",
    ] {
        assert!(
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Module)
                .is_err(),
            "{source}"
        );
    }
}
