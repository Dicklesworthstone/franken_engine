//! ES module imports of Node core modules (bd-9vouw.181).
//!
//! The engine has no runtime module object for a Node core module. Lowering
//! recognizes the call forms of `require('<module>')` aliases instead (path,
//! os, url, querystring, util, zlib, crypto, timers, events), and an `import`
//! of one of those modules reached none of them: the import loaded nothing at
//! run time, and its opaque result was TopSecret, so nothing it produced
//! could be printed. When the module does not bind `require` itself, this
//! rewrite turns each such import into the CommonJS declaration Node's
//! interop gives it, first in the program, since imports run before the
//! module body:
//!
//! ```text
//! import path from 'node:path'          -> const path = require('node:path');
//! import * as path from 'node:path'     -> const path = require('node:path');
//! import { join, sep as s } from 'path' -> const { join } = require('path');
//!                                          const { sep: s } = require('path');
//! import 'node:path'                    -> (nothing; a builtin has no side effect)
//! ```
//!
//! A binding the program never names is dropped, so an unused import does not
//! keep a facade from recognizing the others. Forms the facades do not
//! recognize keep failing closed, as the ambient-authority refusal of
//! `require` in place of the opaque import.

use std::collections::BTreeSet;

use super::with_statement::{Outcome, Walk, lexical_names, var_names, walk_expression};
use crate::ast::{
    BindingPattern, ExportKind, Expression, ImportClause, ImportDeclaration, ImportSpecifier,
    ObjectPatternProperty, Statement, SyntaxTree, VariableDeclaration, VariableDeclarationKind,
    VariableDeclarator,
};

/// Core modules whose `require` aliases lowering recognizes (and path's
/// module object, `path_module.rs`). Loading one needs no authority;
/// members with effects carry their own capabilities.
const FACADE_MODULES: [&str; 12] = [
    "crypto",
    "events",
    "os",
    "path",
    "path/posix",
    "querystring",
    "timers",
    "timers/promises",
    "url",
    "util",
    "util/types",
    "zlib",
];

fn is_facade_import(statement: &Statement) -> bool {
    matches!(statement, Statement::Import(import)
    if import.source.as_str().is_some_and(|specifier| {
        FACADE_MODULES.contains(&specifier.strip_prefix("node:").unwrap_or(specifier))
    }))
}

/// `tree` with its imports of facade modules rewritten to `require`
/// declarations, or `None` when it has none or binds `require` itself.
pub(super) fn rewrite_core_module_imports(tree: &SyntaxTree) -> Option<SyntaxTree> {
    if !tree.body.iter().any(is_facade_import) {
        return None;
    }
    let mut root = BTreeSet::new();
    var_names(&tree.body, &mut root);
    lexical_names(&tree.body, &mut root);
    for statement in &tree.body {
        if let Statement::Import(import) = statement {
            root.extend(
                import
                    .clause
                    .binding_names()
                    .into_iter()
                    .map(str::to_string),
            );
        }
    }
    if root.contains("require") {
        return None;
    }
    let referenced = referenced_names(&tree.body);
    let mut body = Vec::with_capacity(tree.body.len());
    let mut rest = Vec::with_capacity(tree.body.len());
    for statement in &tree.body {
        match statement {
            Statement::Import(import) if is_facade_import(statement) => {
                body.extend(require_declarations(import, &referenced));
            }
            _ => rest.push(statement.clone()),
        }
    }
    body.append(&mut rest);
    Some(SyntaxTree {
        goal: tree.goal,
        body,
        span: tree.span,
    })
}

/// Every identifier the program's code names, in any scope, plus the words
/// of its local export clauses (`export { join }`).
fn referenced_names(statements: &[Statement]) -> BTreeSet<String> {
    struct Names(BTreeSet<String>);

    impl Walk for Names {
        fn expression(&mut self, expression: &mut Expression) -> Outcome {
            if let Expression::Identifier(name) = expression {
                self.0.insert(name.clone());
            }
            walk_expression(self, expression)
        }
    }

    let mut names = Names(BTreeSet::new());
    let mut body = statements.to_vec();
    // The walk visits every statement kind and never fails.
    let _ = names.statements(&mut body);
    for statement in statements {
        if let Statement::Export(export) = statement
            && let ExportKind::NamedClause(clause) = &export.kind
            && clause.source().is_none()
        {
            names.0.extend(
                clause
                    .canonical_head()
                    .split(|c: char| !(c == '$' || c == '_' || c.is_alphanumeric()))
                    .filter(|word| !word.is_empty())
                    .map(str::to_string),
            );
        }
    }
    names.0
}

/// The `const` declarations an import of a facade module becomes.
fn require_declarations(
    import: &ImportDeclaration,
    referenced: &BTreeSet<String>,
) -> Vec<Statement> {
    let alias = |local: &str| {
        referenced
            .contains(local)
            .then(|| require_declaration(import, BindingPattern::Identifier(local.to_string())))
    };
    let named = |specifiers: &[ImportSpecifier]| {
        specifiers
            .iter()
            .filter(|specifier| referenced.contains(&specifier.local_name))
            .map(|specifier| {
                if specifier.import_name == "default" {
                    return require_declaration(
                        import,
                        BindingPattern::Identifier(specifier.local_name.clone()),
                    );
                }
                let key = if is_identifier_name(&specifier.import_name) {
                    Expression::Identifier(specifier.import_name.clone())
                } else {
                    Expression::StringLiteral(specifier.import_name.as_str().into())
                };
                require_declaration(
                    import,
                    BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                        key,
                        value: BindingPattern::Identifier(specifier.local_name.clone()),
                        computed: false,
                        shorthand: specifier.import_name == specifier.local_name,
                    }]),
                )
            })
            .collect::<Vec<_>>()
    };
    match &import.clause {
        ImportClause::SideEffect => Vec::new(),
        ImportClause::Default { local } | ImportClause::Namespace { local } => {
            alias(local).into_iter().collect()
        }
        ImportClause::Named { specifiers } => named(specifiers),
        ImportClause::DefaultAndNamed {
            default,
            specifiers,
        } => alias(default)
            .into_iter()
            .chain(named(specifiers))
            .collect(),
        ImportClause::DefaultAndNamespace { default, namespace } => {
            alias(default).into_iter().chain(alias(namespace)).collect()
        }
    }
}

/// `const <pattern> = require('<source>');` at the import's span.
fn require_declaration(import: &ImportDeclaration, pattern: BindingPattern) -> Statement {
    Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern,
            initializer: Some(Expression::Call {
                callee: Box::new(Expression::Identifier("require".to_string())),
                arguments: vec![Expression::StringLiteral(import.source.clone())],
                span: Some(import.span),
            }),
            span: import.span,
        }],
        span: import.span,
    })
}

fn is_identifier_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first == '$' || first == '_' || first.is_alphabetic())
        && chars.all(|c| c == '$' || c == '_' || c.is_alphanumeric())
}
