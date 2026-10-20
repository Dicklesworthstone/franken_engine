//! Add output cursor APIs to the existing lazy readline module instance.
//!
//! No Stream factory, terminal handle or second readline object is created.
//! Only the installed methods can write to caller-supplied output streams.

use std::collections::BTreeSet;

use super::super::{ModuleRenamer, NativeModuleSource, READLINE_MODULE_BINDING};
use super::super::super::with_statement::{
    Outcome, Walk, lexical_names, var_names, walk_expression,
};
use crate::ast::{BindingPattern, Expression, Statement, SyntaxTree};

const GLOBALS: [&str; 8] = [
    "Array", "Number", "Object", "Promise", "RangeError", "Reflect", "TypeError", "WeakMap",
];
const TICK: &str = "__franken_readline_cursor_tick";
static INSTALLER: NativeModuleSource = NativeModuleSource::new(
    "franken:readline/cursor",
    include_str!("readline_cursor.js"),
);

struct TickIntrinsic;

impl Walk for TickIntrinsic {
    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if matches!(expression, Expression::Identifier(name) if name == TICK) {
            *expression = Expression::Identifier("%StreamNextTick".into());
            return Ok(());
        }
        walk_expression(self, expression)
    }
}

pub(super) fn compose(tree: &mut SyntaxTree, bindings: &BTreeSet<String>) -> Outcome {
    if !bindings.contains(READLINE_MODULE_BINDING) {
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
    let mut installer = INSTALLER.expression()?;
    TickIntrinsic.expression(&mut installer)?;
    ModuleRenamer {
        through_global_object: GLOBALS
            .iter()
            .filter(|name| names.contains(**name))
            .map(|name| (*name).to_string())
            .collect(),
    }
    .expression(&mut installer)?;
    for statement in &mut tree.body {
        let Statement::VariableDeclaration(declaration) = statement else {
            continue;
        };
        let [declarator] = declaration.declarations.as_mut_slice() else {
            continue;
        };
        if !matches!(&declarator.pattern, BindingPattern::Identifier(name)
            if name == READLINE_MODULE_BINDING)
        {
            continue;
        }
        let original = declarator.initializer.take().ok_or_else(super::invalid)?;
        declarator.initializer = Some(Expression::Call {
            callee: Box::new(installer),
            arguments: vec![original],
            span: Some(declarator.span),
        });
        return Ok(());
    }
    Err(super::invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::{rewrite_module_objects, rewrite_util_requires};
    use crate::ast::ParseGoal;
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    fn parse(source: &str) -> SyntaxTree {
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "cursor-lowering.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("source parses")
    }

    #[test]
    fn private_installer_uses_declared_globals_and_the_existing_tick_intrinsic() {
        let mut source = INSTALLER.expression().expect("native source parses");
        let pristine = source.clone();
        let globals: BTreeSet<String> = GLOBALS.iter().map(|name| (*name).into()).collect();
        let mut expected = globals.clone();
        expected.insert(TICK.into());
        assert_eq!(super::super::super::tests::free_names(&mut source), expected);
        TickIntrinsic.expression(&mut source).unwrap();
        ModuleRenamer {
            through_global_object: globals,
        }
        .expression(&mut source)
        .unwrap();
        assert_eq!(
            super::super::super::tests::free_names(&mut source),
            BTreeSet::from(["globalThis".into(), "%StreamNextTick".into()]),
        );
        assert_eq!(INSTALLER.expression().unwrap(), pristine);
        assert_eq!(
            super::super::super::intrinsic_capability("%StreamNextTick"),
            Some("builtin:ProcessNextTick"),
        );
    }

    #[test]
    fn callbacks_and_promises_enrich_one_deferred_readline_instance() {
        for source in [
            "const r=require('readline'); r.clearLine(output, 0);",
            "const {Readline}=require('node:readline/promises'); new Readline(output);",
            "const r=require('readline'); const p=require('readline/promises'); r.promises===p;",
        ] {
            let tree = parse(source);
            let objects = rewrite_module_objects(&tree).unwrap().unwrap();
            let rewritten = rewrite_util_requires(&tree).unwrap().unwrap();
            assert_eq!(rewritten.body.len(), objects.body.len());
            assert!(rewrite_util_requires(&rewritten).unwrap().is_none());
            let count = rewritten.body.iter().filter(|statement| {
                matches!(statement, Statement::VariableDeclaration(declaration)
                    if matches!(&declaration.declarations[0].pattern,
                        BindingPattern::Identifier(name) if name == READLINE_MODULE_BINDING))
            }).count();
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn unrelated_and_shadowed_loaders_do_not_acquire_cursor_code() {
        for source in [
            "console.log(1);",
            "function f(require) { return require('readline'); }",
            "const {readFileSync}=require('fs'); readFileSync('data');",
        ] {
            let mut tree = parse(source);
            let original = tree.clone();
            compose(&mut tree, &BTreeSet::new()).unwrap();
            assert_eq!(tree, original);
        }
    }
}
