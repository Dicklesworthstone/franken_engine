//! First-class filesystem facades over the existing native host-I/O boundary.
//!
//! Only free, literal core-module requires are rewritten. Creating the object
//! performs no I/O and confers no authority; every method invokes the ordinary
//! fs:read/fs:write HostCall under the calling interpreter's capability set.
//! Reserved intrinsic names cannot be spelled by guest source.

use std::collections::BTreeSet;

use super::super::LoweringPipelineError;
use super::super::with_statement::{
    FunctionBody, FunctionParts, Outcome, Search, Walk, lexical_names, var_names, walk_expression,
    walk_function, walk_switch_cases,
};
use super::scoped_walk;
use crate::ast::{
    BindingPattern, CatchClause, Expression, ParseGoal, SourceSpan, Statement, SwitchCase,
    SyntaxTree, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const MODULE_BINDING: &str = "%fs_module";
const SOURCE: &str = include_str!("fs_module.js");
const PLACEHOLDERS: [(&str, &str); 2] = [
    ("__franken_fs_read", "%FsRead"),
    ("__franken_fs_write", "%FsWrite"),
];
const GLOBALS: [&str; 3] = ["Promise", "Reflect", "TypeError"];

pub(super) fn intrinsic_capability(name: &str) -> Option<&'static str> {
    match name {
        "%FsRead" => Some("fs:read"),
        "%FsWrite" => Some("fs:write"),
        _ => None,
    }
}

fn require_member(expression: &Expression) -> Option<Option<&'static str>> {
    let Expression::Call {
        callee, arguments, ..
    } = expression
    else {
        return None;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name) if name == "require") {
        return None;
    }
    let [Expression::StringLiteral(specifier)] = arguments.as_slice() else {
        return None;
    };
    if *specifier == "fs" || *specifier == "node:fs" {
        Some(None)
    } else if *specifier == "fs/promises" || *specifier == "node:fs/promises" {
        Some(Some("promises"))
    } else {
        None
    }
}

const SEARCH: Search = Search {
    statement: |_| false,
    expression: |expression| require_member(expression).is_some(),
};

pub(super) fn is_module_declaration(statement: &Statement) -> bool {
    matches!(statement, Statement::VariableDeclaration(declaration)
        if matches!(declaration.declarations.as_slice(),
            [VariableDeclarator { pattern: BindingPattern::Identifier(name), .. }]
                if name == MODULE_BINDING))
}

pub(super) fn rewrite_fs_requires(
    tree: &SyntaxTree,
) -> Result<Option<SyntaxTree>, LoweringPipelineError> {
    if !tree
        .body
        .iter()
        .any(|statement| SEARCH.in_statement(statement))
    {
        return Ok(None);
    }
    let mut names = BTreeSet::new();
    var_names(&tree.body, &mut names);
    lexical_names(&tree.body, &mut names);
    let mut rewritten = tree.clone();
    let mut walker = RequireRewriter {
        scopes: vec![names.clone()],
        replaced: false,
    };
    walker.statements(&mut rewritten.body)?;
    if !walker.replaced {
        return Ok(None);
    }
    let span = rewritten.body.first().map_or_else(
        || SourceSpan::new(0, 0, 1, 1, 1, 1),
        |statement| *statement.span(),
    );
    rewritten.body.insert(
        0,
        Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier(MODULE_BINDING.to_string()),
                initializer: Some(module_source(&names)?),
                span,
            }],
            span,
        }),
    );
    Ok(Some(rewritten))
}

fn module_source(names: &BTreeSet<String>) -> Result<Expression, LoweringPipelineError> {
    let invalid = || LoweringPipelineError::InvariantViolation {
        detail: "the engine's filesystem module source failed to parse",
    };
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "franken:fs".into(),
                text: SOURCE.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|_| invalid())?;
    let [Statement::Expression(statement)] = tree.body.as_slice() else {
        return Err(invalid());
    };
    let mut expression = statement.expression.clone();
    ModuleRenamer { names }.expression(&mut expression)?;
    Ok(expression)
}

struct ModuleRenamer<'a> {
    names: &'a BTreeSet<String>,
}

impl Walk for ModuleRenamer<'_> {
    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if let Expression::Identifier(name) = expression {
            if let Some((_, intrinsic)) = PLACEHOLDERS.iter().find(|(source, _)| source == name) {
                *name = (*intrinsic).to_string();
            } else if GLOBALS.contains(&name.as_str()) && self.names.contains(name.as_str()) {
                let property = Expression::Identifier(std::mem::take(name));
                *expression = Expression::Member {
                    object: Box::new(Expression::Identifier("globalThis".to_string())),
                    property: Box::new(property),
                    computed: false,
                    span: None,
                };
            }
            return Ok(());
        }
        walk_expression(self, expression)
    }
}

struct RequireRewriter {
    scopes: Vec<BTreeSet<String>>,
    replaced: bool,
}

impl RequireRewriter {
    fn scoped(&mut self, names: BTreeSet<String>, walk: impl FnOnce(&mut Self) -> Outcome) -> Outcome {
        self.scopes.push(names);
        let result = walk(self);
        self.scopes.pop();
        result
    }
}

impl Walk for RequireRewriter {
    scoped_walk!();

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if !self.scopes.iter().any(|scope| scope.contains("require"))
            && let Some(member) = require_member(expression)
        {
            let module = Expression::Identifier(MODULE_BINDING.to_string());
            *expression = match member {
                None => module,
                Some(member) => Expression::Member {
                    object: Box::new(module),
                    property: Box::new(Expression::Identifier(member.to_string())),
                    computed: false,
                    span: None,
                },
            };
            self.replaced = true;
            return Ok(());
        }
        walk_expression(self, expression)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> SyntaxTree {
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource { label: "fs-rewrite-test.js".into(), text: source.into() },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("test source parses")
    }

    #[test]
    fn native_module_source_parses_with_protected_globals() {
        let names = GLOBALS.iter().map(|name| (*name).to_string()).collect();
        module_source(&names).expect("the shipped source parses and renames");
    }

    #[test]
    fn only_literal_free_filesystem_requires_are_rewritten() {
        for source in [
            "function f(require) { return require('fs'); }",
            "const require = name => name; require('node:fs');",
            "{ let require = name => name; require('fs/promises'); }",
            "require('fs/unsupported');",
            "const name = 'fs'; require(name);",
        ] {
            assert!(rewrite_fs_requires(&parse(source)).expect("rewrite").is_none(), "{source}");
        }
    }

    #[test]
    fn all_core_specifiers_share_one_program_module() {
        let tree = parse("const fs = require('fs'); require('node:fs'); require('fs/promises');");
        let rewritten = rewrite_fs_requires(&tree).expect("rewrite").expect("fs module");
        assert_eq!(rewritten.body.len(), tree.body.len() + 1);
        assert!(is_module_declaration(&rewritten.body[0]));
        assert!(rewrite_fs_requires(&rewritten).expect("idempotent").is_none());
    }

    #[test]
    fn intrinsics_reuse_native_capabilities_without_exposing_source_placeholders() {
        assert_eq!(intrinsic_capability("%FsRead"), Some("fs:read"));
        assert_eq!(intrinsic_capability("%FsWrite"), Some("fs:write"));
        assert_eq!(intrinsic_capability("__franken_fs_write"), None);
    }
}
