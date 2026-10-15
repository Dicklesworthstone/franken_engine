//! The same executable factory must parse, protect its realm dependencies,
//! and use the existing first-use module loader without acquiring I/O rights.
use super::*;

fn parse(source: &str) -> SyntaxTree {
    CanonicalEs2020Parser
        .parse_with_options(
            ParserSource { label: "diagnostics-channel.js".into(), text: source.into() },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("diagnostics program parses")
}

#[test]
fn aliases_and_deferred_calls_share_one_module_declaration() {
    let tree = parse(
        "const a=require('diagnostics_channel'); const b=require('node:diagnostics_channel'); \
         function later() { return require('diagnostics_channel').channel('later'); }",
    );
    let rewritten = rewrite_util_requires(&tree).unwrap().expect("diagnostics module");
    assert_eq!(rewritten.body.len(), tree.body.len() + 1);
    assert!(is_module_declaration(&rewritten.body[0]));
    assert!(rewrite_util_requires(&rewritten).unwrap().is_none());
    assert_eq!(intrinsic_capability(DIAGNOSTICS_CHANNEL_BINDING), None);
}

#[test]
fn shadowed_and_dynamic_requests_retain_their_original_authority_path() {
    for source in [
        "function f(require) { return require('diagnostics_channel'); }",
        "{ const require=loader; require('node:diagnostics_channel'); }",
        "for (const require of loaders) require('diagnostics_channel');",
        "with (scope) require('diagnostics_channel');",
        "const name='diagnostics_channel'; require(name);",
        "require('diagnostics_channel/unknown');",
    ] {
        assert!(rewrite_util_requires(&parse(source)).unwrap().is_none(), "{source}");
    }
}

#[test]
fn every_realm_dependency_is_declared_and_pristine_cached_syntax_is_preserved() {
    let expected: BTreeSet<String> = DIAGNOSTICS_CHANNEL_GLOBALS
        .iter().map(|name| (*name).into()).collect();
    let mut source = parse_module_source(PureModule::DiagnosticsChannel).unwrap();
    assert_eq!(super::tests::free_names(&mut source), expected);
    let mut protected = module_source(&expected, PureModule::DiagnosticsChannel).unwrap();
    assert_eq!(super::tests::free_names(&mut protected), BTreeSet::from(["globalThis".into()]));
    assert_eq!(parse_module_source(PureModule::DiagnosticsChannel).unwrap(), source);
}

#[test]
fn esm_imports_and_reexports_reach_the_same_protected_first_use_module() {
    use super::super::esm_core_imports::rewrite_core_module_imports;
    let module = |text: &str| {
        CanonicalEs2020Parser.parse_with_options(
            ParserSource { label: "diagnostics-import.mjs".into(), text: text.into() },
            ParseGoal::Module,
            &ParserOptions::default(),
        ).expect("module parses")
    };
    for source in [
        "import {channel as c,tracingChannel as t} from 'node:diagnostics_channel'; c('x'); t('y');",
        "import dc from 'diagnostics_channel'; dc.channel('x');",
        "import * as dc from 'node:diagnostics_channel'; dc.channel('x');",
        "export {channel as named,tracingChannel} from 'diagnostics_channel';",
        "export * as diagnostics from 'node:diagnostics_channel';",
    ] {
        let original = module(source);
        let imports = rewrite_core_module_imports(&original).expect("recognized core import");
        let lowered = rewrite_util_requires(&imports).unwrap().expect("shared diagnostics factory");
        assert_eq!(lowered.body.iter().filter(|s| is_module_declaration(s)).count(), 1);
        assert!(rewrite_core_module_imports(&imports).is_none());
        assert!(rewrite_util_requires(&lowered).unwrap().is_none());
        assert_eq!(original, module(source), "caller syntax remains pristine");
    }
    for source in [
        "import dc from './diagnostics_channel.mjs'; dc();",
        "import dc from 'diagnostics_channel/unknown'; dc();",
        "import require from './loader.mjs'; import dc from 'diagnostics_channel'; dc.channel('x');",
    ] {
        assert!(rewrite_core_module_imports(&module(source)).is_none(), "{source}");
    }
}
