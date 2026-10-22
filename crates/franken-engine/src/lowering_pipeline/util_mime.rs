//! Install MIME records on the canonical, first-use util module object.
//! This adds no hostcall, authority, loader or separate module instance.

use std::collections::BTreeSet;

use super::super::{MODULE_BINDING, ModuleRenamer, NativeModuleSource};
use super::super::super::with_statement::{Outcome, Walk, lexical_names, var_names};
use crate::ast::{BindingPattern, Expression, Statement, SyntaxTree};

const GLOBALS: [&str; 8] = [
    "Array", "Map", "Object", "Reflect", "String", "Symbol", "TypeError", "WeakMap",
];
static INSTALLER: NativeModuleSource = NativeModuleSource::new(
    "franken:util/mime",
    include_str!("util_mime.js"),
);

pub(super) fn compose(tree: &mut SyntaxTree, bindings: &BTreeSet<String>) -> Outcome {
    if !bindings.contains(MODULE_BINDING) {
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
            if name == MODULE_BINDING)
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
    use super::super::super::{rewrite_module_objects, rewrite_util_requires, tests::free_names};
    use crate::ast::ParseGoal;
    use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    fn parse(text: &str, goal: ParseGoal) -> SyntaxTree {
        CanonicalEs2020Parser.parse_with_options(
            ParserSource { label: "mime-module.js".into(), text: text.into() },
            goal,
            &ParserOptions::default(),
        ).expect("MIME fixture parses")
    }

    #[test]
    fn mime_source_protects_every_dependency_and_reuses_pristine_cached_syntax() {
        let mut source = INSTALLER.expression().expect("native parser");
        let pristine = source.clone();
        let globals: BTreeSet<String> = GLOBALS.iter().map(|name| (*name).into()).collect();
        assert_eq!(free_names(&mut source), globals);
        ModuleRenamer { through_global_object: globals }.expression(&mut source).unwrap();
        assert_eq!(free_names(&mut source), BTreeSet::from(["globalThis".into()]));
        assert_eq!(INSTALLER.expression().unwrap(), pristine);
    }

    #[test]
    fn mime_exports_enrich_one_deferred_util_instance_without_new_declarations() {
        for source in [
            "const {MIMEType}=require('util'); new MIMEType('text/plain');",
            "const a=require('util'); const b=require('node:util'); a.MIMEType===b.MIMEType;",
            "function later(){return require('util').MIMEParams;} later();",
        ] {
            let original = parse(source, ParseGoal::Script);
            let objects = rewrite_module_objects(&original).unwrap().unwrap();
            let rewritten = rewrite_util_requires(&original).unwrap().unwrap();
            assert_eq!(objects.body.len(), rewritten.body.len());
            assert!(rewrite_util_requires(&rewritten).unwrap().is_none());
            assert_eq!(original, parse(source, ParseGoal::Script));
        }
    }

    #[test]
    fn mime_esm_imports_and_reexports_use_the_existing_util_module() {
        for source in [
            "import {MIMEType} from 'node:util'; new MIMEType('x/y');",
            "import * as u from 'util'; new u.MIMEParams();",
            "export {MIMEType as ContentType,MIMEParams} from 'node:util';",
        ] {
            let original = parse(source, ParseGoal::Module);
            let imported = super::super::super::super::esm_core_imports::rewrite_core_module_imports(&original)
                .expect("util ESM import");
            let rewritten = rewrite_util_requires(&imported).unwrap().unwrap();
            assert_eq!(rewritten.body.iter().filter(|statement| {
                super::super::super::is_module_declaration(statement)
            }).count(), 1);
            assert!(rewrite_util_requires(&rewritten).unwrap().is_none());
        }
    }

    #[test]
    fn unrelated_modules_and_user_loaders_do_not_initialize_mime() {
        for source in [
            "console.log(1);", "function f(require){return require('util');}",
            "const name='util';require(name);",
        ] {
            let mut tree = parse(source, ParseGoal::Script);
            let original = tree.clone();
            compose(&mut tree, &BTreeSet::new()).unwrap();
            assert_eq!(tree, original);
            assert!(rewrite_util_requires(&original).unwrap().is_none());
        }
    }
}
