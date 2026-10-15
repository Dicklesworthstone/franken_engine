//! Parser/lowerer regressions for the shared readline factory.
use super::*;

fn parse(source: &str) -> SyntaxTree {
    CanonicalEs2020Parser
        .parse_with_options(
            ParserSource { label: "readline-lowering.js".into(), text: source.into() },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("readline source parses")
}

#[test]
fn readline_source_uses_only_declared_globals_and_shared_private_dependencies() {
    let names: BTreeSet<String> = READLINE_GLOBALS.iter().map(|name| (*name).into()).collect();
    let mut expected = names.clone();
    expected.extend(READLINE_PLACEHOLDERS.iter().map(|(name, _)| (*name).into()));
    let mut pristine = parse_module_source(PureModule::Readline).expect("canonical parser");
    assert_eq!(super::tests::free_names(&mut pristine), expected);
    let mut protected = module_source(&names, PureModule::Readline).expect("protect guest globals");
    assert_eq!(
        super::tests::free_names(&mut protected),
        ["globalThis", EVENTS_MODULE_BINDING, STRING_DECODER_MODULE_BINDING]
            .into_iter().map(str::to_string).collect(),
    );
    assert_eq!(parse_module_source(PureModule::Readline).unwrap(), pristine);
}

#[test]
fn readline_aliases_and_promises_share_one_lazy_factory() {
    let original = parse(
        "const a=require('readline'); const b=require('node:readline/promises'); \
         function later(){ return require('node:readline'); }",
    );
    let rewritten = rewrite_util_requires(&original).unwrap().expect("readline used");
    let declarations: Vec<_> = rewritten.body.iter().filter_map(|statement| {
        if !is_module_declaration(statement) { return None; }
        let Statement::VariableDeclaration(declaration) = statement else { unreachable!() };
        let BindingPattern::Identifier(name) = &declaration.declarations[0].pattern else { unreachable!() };
        let Expression::Call { arguments, .. } = declaration.declarations[0].initializer.as_ref().unwrap()
        else { panic!("module must be a deferred loader") };
        assert_eq!(arguments.len(), 1, "one deferred initializer");
        Some(name.as_str())
    }).collect();
    assert_eq!(declarations, [EVENTS_MODULE_BINDING, STRING_DECODER_MODULE_BINDING, READLINE_MODULE_BINDING]);
    assert!(rewrite_util_requires(&rewritten).unwrap().is_none());
    assert_eq!(intrinsic_capability(READLINE_MODULE_BINDING), None);
    assert_eq!(intrinsic_capability("__franken_readline_events"), None);
}

#[test]
fn readline_preserves_shadowed_dynamic_and_unknown_module_requests() {
    for source in [
        "function f(require){return require('readline');}",
        "{ const require=loader; require('readline/promises'); }",
        "for(const require of loaders) require('node:readline');",
        "with(scope) require('readline');",
        "const name='readline'; require(name);",
        "require('readline/private');",
    ] {
        assert!(rewrite_util_requires(&parse(source)).unwrap().is_none(), "{source}");
    }
}

#[test]
fn readline_input_uses_the_real_shared_stream_module_not_a_finite_call_facade() {
    let tree = parse(
        "const {Readable}=require('stream'); const lines=require('readline'); \
         const input=Readable.from(['a\\n']); lines.createInterface({input});",
    );
    let rewritten = rewrite_util_requires(&tree).unwrap().expect("full stream handoff");
    assert!(rewritten.body.iter().any(|statement| {
        matches!(statement, Statement::VariableDeclaration(declaration)
            if matches!(declaration.declarations.as_slice(), [VariableDeclarator {
                pattern: BindingPattern::Identifier(name), ..
            }] if name == STREAM_MODULE_BINDING))
    }));
    assert!(rewrite_util_requires(&rewritten).unwrap().is_none());
}
