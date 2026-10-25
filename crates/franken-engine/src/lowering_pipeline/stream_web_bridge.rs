//! Compose Node/Web adapters at the existing private dependency boundary.
//!
//! The final loader pass already turns module references into first-use loads.
//! Reuse an explicitly requested Web module; otherwise keep its canonical
//! initializer in a private lazy dependency of the stream module. Ordinary
//! stream imports do not initialize Web Streams, and direct-call facades gain
//! neither a module nor a dependency. Parsing/lowering are NOT deferred.

use std::collections::BTreeSet;

use super::super::super::with_statement::{
    Outcome, Walk, lexical_names, var_names, walk_expression,
};
use super::super::{
    ModuleRenamer, NativeModuleSource, PureModule, STREAM_MODULE_BINDING, WEB_STREAMS_BINDING,
    module_source, module_source_with_runtime_sources,
};
use crate::ast::{BindingPattern, Expression, Statement, SyntaxTree};

const GLOBALS: [&str; 13] = [
    "AbortController", "AbortSignal", "Array", "Blob", "Buffer", "Error", "EventTarget", "Object", "Promise",
    "Reflect", "Symbol", "TypeError", "Uint8Array",
];
// Both adapters and completion observation share the SAME lazy Web instance.
pub(super) const SOURCE: &str = concat!(
    "(function (stream, loadWeb) { return (",
    include_str!("stream_finished.js"),
    ")((",
    include_str!("stream_web_bridge.js"),
    ")(stream, loadWeb), loadWeb); })",
);
const TICK: &str = "__franken_stream_web_tick";
static INSTALLER: NativeModuleSource = NativeModuleSource::new("franken:stream/web-bridge", SOURCE);

struct CompletionTick;

impl Walk for CompletionTick {
    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if matches!(expression, Expression::Identifier(name) if name == TICK) {
            *expression = Expression::Identifier("%StreamNextTick".into());
            return Ok(());
        }
        walk_expression(self, expression)
    }
}

pub(super) fn compose(tree: &mut SyntaxTree, bindings: &BTreeSet<String>) -> Outcome {
    compose_with_runtime_sources(tree, bindings, false)
}

pub(super) fn compose_with_runtime_sources(
    tree: &mut SyntaxTree,
    bindings: &BTreeSet<String>,
    retain_runtime_sources: bool,
) -> Outcome {
    if !bindings.contains(STREAM_MODULE_BINDING) {
        return Ok(());
    }
    let mut names = BTreeSet::new();
    var_names(&tree.body, &mut names);
    lexical_names(&tree.body, &mut names);
    for statement in &tree.body {
        if let Statement::Import(import) = statement {
            names.extend(import.clause.binding_names().into_iter().map(str::to_string));
        }
    }
    // This reference is still a module VALUE. The enclosing loader pass will
    // turn it into a load, just like stream's events/string_decoder references.
    // Never make a second Web factory when the program already has one.
    let dependency = if bindings.contains(WEB_STREAMS_BINDING) {
        Expression::Identifier(WEB_STREAMS_BINDING.to_string())
    } else if retain_runtime_sources {
        // The private runtime factory needs immutable audit ranges from its
        // lazy Web dependency too. Ordinary source rewrites keep the legacy
        // template and native display policy.
        module_source_with_runtime_sources(&names, PureModule::WebStreams, true)?
    } else {
        module_source(&names, PureModule::WebStreams)?
    };
    let dependency = super::deferred(dependency)?;
    let mut installer = INSTALLER.expression()?;
    CompletionTick.expression(&mut installer)?;
    ModuleRenamer {
        through_global_object: GLOBALS.iter()
            .filter(|name| names.contains(**name))
            .map(|name| (*name).to_string()).collect(),
    }.expression(&mut installer)?;
    for statement in &mut tree.body {
        let Statement::VariableDeclaration(declaration) = statement else { continue; };
        let [declarator] = declaration.declarations.as_mut_slice() else { continue; };
        if !matches!(&declarator.pattern, BindingPattern::Identifier(name) if name == STREAM_MODULE_BINDING) {
            continue;
        }
        let original = declarator.initializer.take().ok_or_else(super::invalid)?;
        declarator.initializer = Some(Expression::Call {
            callee: Box::new(installer),
            arguments: vec![original, dependency],
            span: Some(declarator.span),
        });
        return Ok(());
    }
    Err(super::invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{is_module_declaration, rewrite_util_requires, rewrite_module_objects};
    use crate::ast::ParseGoal;
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    fn parse(source: &str) -> SyntaxTree {
        CanonicalEs2020Parser.parse_with_options(
            ParserSource { label: "stream-web-bridge-test.js".into(), text: source.into() },
            ParseGoal::Script, &ParserOptions::default(),
        ).expect("program parses")
    }

    #[test]
    fn installer_has_only_declared_realm_helpers_and_uses_pristine_cached_syntax() {
        let mut source = INSTALLER.expression().expect("canonical parser accepts installer");
        let expected: BTreeSet<String> = GLOBALS.iter().map(|s| (*s).into()).collect();
        let mut free = expected.clone();
        free.insert(TICK.into());
        assert_eq!(super::super::super::tests::free_names(&mut source), free);
        let pristine = source.clone();
        CompletionTick.expression(&mut source).unwrap();
        ModuleRenamer { through_global_object: expected }.expression(&mut source).unwrap();
        assert_eq!(
            super::super::super::tests::free_names(&mut source),
            BTreeSet::from(["globalThis".into(), "%StreamNextTick".into()]),
        );
        assert_eq!(INSTALLER.expression().unwrap(), pristine);
        assert_eq!(super::super::super::intrinsic_capability("%StreamNextTick"),
            Some("builtin:ProcessNextTick"));
    }

    #[test]
    fn adapters_use_the_existing_module_and_deferred_dependency_pass() {
        for source in [
            "const s=require('stream'); s.Readable.fromWeb(input);",
            "const {Writable}=require('node:stream'); Writable.toWeb(output);",
            "const s=require('stream'); const w=require('stream/web'); s.Writable.fromWeb(new w.WritableStream());",
        ] {
            let tree = parse(source);
            let before = rewrite_module_objects(&tree).unwrap().unwrap();
            let after = rewrite_util_requires(&tree).unwrap().unwrap();
            assert_eq!(after.body.len(), before.body.len(), "no extra top-level module or duplicated factory");
            assert_eq!(
                after.body.iter().filter(|s| is_module_declaration(s)).count(),
                before.body.iter().filter(|s| is_module_declaration(s)).count(),
            );
            assert!(rewrite_util_requires(&after).unwrap().is_none());
        }
    }

    #[test]
    fn explicit_web_dependency_is_a_reference_not_an_independent_factory() {
        let tree = parse("const s=require('stream'); const w=require('node:stream/web'); s.Readable.toWeb(input);");
        let mut objects = rewrite_module_objects(&tree).unwrap().unwrap();
        compose(&mut objects, &BTreeSet::from([STREAM_MODULE_BINDING.into(), WEB_STREAMS_BINDING.into()])).unwrap();
        struct Count(usize);
        impl Walk for Count {
            fn expression(&mut self, expression: &mut Expression) -> Outcome {
                if matches!(expression, Expression::Identifier(name) if name == WEB_STREAMS_BINDING) {
                    self.0 += 1;
                }
                walk_expression(self, expression)
            }
        }
        let mut references = Count(0);
        let statement = objects.body.iter_mut().find(|s| matches!(s,
            Statement::VariableDeclaration(d) if matches!(&d.declarations[0].pattern,
                BindingPattern::Identifier(name) if name == STREAM_MODULE_BINDING))).unwrap();
        references.statement(statement).unwrap();
        assert_eq!(references.0, 1, "one lazy reference to the explicitly requested Web module");
    }

    #[test]
    fn direct_facades_and_shadowed_loaders_do_not_acquire_bridge_dependencies() {
        for source in [
            "const {Readable}=require('stream'); Readable.from(['a']);",
            "function f(require) { return require('stream').Readable.fromWeb(input); }",
            "require('fs').readFileSync('input');",
        ] {
            let tree = parse(source);
            if let Some(mut rewritten) = rewrite_module_objects(&tree).unwrap() {
                let before = rewritten.clone();
                compose(&mut rewritten, &BTreeSet::new()).unwrap();
                assert_eq!(rewritten, before);
                assert!(!rewritten.body.iter().any(|s| matches!(s,
                    Statement::VariableDeclaration(d) if matches!(&d.declarations[0].pattern,
                        BindingPattern::Identifier(name) if name == STREAM_MODULE_BINDING))));
            }
        }
    }
}
