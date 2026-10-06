//! ES module imports of Node core modules (bd-9vouw.181).
//!
//! The engine has no runtime module object for a Node core module. Lowering
//! recognizes the call forms of `require('<module>')` aliases instead (path,
//! os, url, querystring, util, zlib, crypto, timers, events), and an `import`
//! of one of those modules reached none of them: the import loaded nothing at
//! run time, and its opaque result was TopSecret, so nothing it produced
//! could be printed. When the module does not bind `require` itself, this
//! rewrite turns each such import into what Node's interop gives it, first in
//! the program, since imports run before the module body:
//!
//! ```text
//! import path from 'node:path'          -> const path = require('node:path');
//! import * as path from 'node:path'     -> const path = require('node:path');
//! import { join, sep as s } from 'path' -> const { join } = require('path');
//!                                          const { sep: s } = require('path');
//! import 'node:path'                    -> (nothing; a builtin has no side effect)
//! import { URL } from 'node:url'        -> (nothing; `URL` reads the global)
//! import { Buffer as B } from 'buffer'  -> const B = globalThis.Buffer;
//! import { createHash } from 'crypto'   -> const %core_import_0 = require('crypto');
//!                                          and each `createHash` the module
//!                                          names becomes %core_import_0.createHash
//! export { default as p } from 'path'   -> const %core_reexport_0 = require('node:path/posix');
//!                                          export { %core_reexport_0 as p };
//! export * as ns from 'node:path'       -> const %core_reexport_1 = require('node:path/posix');
//!                                          export { %core_reexport_1 as ns };
//! ```
//!
//! A re-export (bd-9vouw.221) is the import of each name under a hidden
//! local, exported by a local clause, so it lowers like `import { name as
//! hidden } from '<module>'; export { hidden as exported };`. Left as it
//! was, it loaded the module at run time, which no facade serves, and made
//! the whole module TopSecret.
//!
//! The last form is for the modules whose facade recognizes member calls on
//! an alias but no destructured binding (crypto, os, querystring,
//! timers/promises, zlib). A named export that is a realm global (Buffer,
//! URL, performance, the timers) is that global. A binding the program never
//! names is dropped, so an unused import does not keep a facade from
//! recognizing the others. Forms the facades do not recognize keep failing
//! closed, as the ambient-authority refusal of `require` in place of the
//! opaque import.

use std::collections::{BTreeMap, BTreeSet};

use super::util_module::scoped_walk;
use super::with_statement::{
    FunctionBody, FunctionParts, Outcome, Walk, lexical_names, var_names, walk_expression,
    walk_function, walk_statement, walk_switch_cases,
};
use crate::ast::{
    BindingPattern, CatchClause, ExportDeclaration, ExportKind, Expression, ImportClause,
    ImportDeclaration, ImportSpecifier, NamedExportClause, ObjectPatternProperty, Statement,
    SwitchCase, SyntaxTree, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};

/// Core modules whose `require` aliases lowering recognizes (and path's
/// module object, `path_module.rs`). Loading one needs no authority;
/// members with effects carry their own capabilities.
const FACADE_MODULES: [&str; 14] = [
    "assert",
    "assert/strict",
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

/// Named exports that are realm globals, by module.
const GLOBAL_EXPORTS: [(&str, &[&str]); 3] = [
    ("buffer", &["Buffer", "atob", "btoa"]),
    ("perf_hooks", &["performance"]),
    ("url", &["URL", "URLSearchParams"]),
];

/// Modules whose facade lowers member calls on an alias but recognizes no
/// destructured binding.
const MEMBER_MODULES: [&str; 4] = ["crypto", "os", "querystring", "zlib"];

/// Aliases the member rewrite declares. No source text can spell a `%` name.
const ALIAS_PREFIX: &str = "%core_import_";

/// The hidden locals a re-export declares.
const REEXPORT_PREFIX: &str = "%core_reexport_";

/// The module a core module specifier names, without `node:`, when the
/// rewrite handles it.
fn handled_module(specifier: &str) -> Option<&str> {
    let module = specifier.strip_prefix("node:").unwrap_or(specifier);
    (FACADE_MODULES.contains(&module) || GLOBAL_EXPORTS.iter().any(|(name, _)| *name == module))
        .then_some(module)
}

/// The module an import of a core module names, when the rewrite handles it.
fn rewritten_module(statement: &Statement) -> Option<&str> {
    let Statement::Import(import) = statement else {
        return None;
    };
    handled_module(import.source.as_str()?)
}

/// `export { ... } from '<module>'` or `export * as ns from '<module>'` of a
/// core module the rewrite handles, with that module. `export * from` is
/// left as it is.
fn reexported_module(
    statement: &Statement,
) -> Option<(&ExportDeclaration, &NamedExportClause, &str)> {
    let Statement::Export(export) = statement else {
        return None;
    };
    let ExportKind::NamedClause(clause) = &export.kind else {
        return None;
    };
    let head = clause.canonical_head();
    if !(head.starts_with('{') || head.starts_with("* as ")) {
        return None;
    }
    let module = handled_module(clause.source()?.as_str()?)?;
    Some((export, clause, module))
}

fn is_global_export(module: &str, name: &str) -> bool {
    GLOBAL_EXPORTS
        .iter()
        .any(|(owner, names)| *owner == module && names.contains(&name))
}

/// `tree` with its imports of core modules rewritten, or `None` when it has
/// none or binds `require` itself.
pub(super) fn rewrite_core_module_imports(tree: &SyntaxTree) -> Option<SyntaxTree> {
    if !tree.body.iter().any(|statement| {
        rewritten_module(statement).is_some() || reexported_module(statement).is_some()
    }) {
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
    let (referenced, exported) = referenced_names(&tree.body);
    let mut rewrite = Rewrite {
        referenced,
        exported,
        declarations: Vec::new(),
        renames: BTreeMap::new(),
        aliases: 0,
        reexports: 0,
    };
    let mut rest = Vec::with_capacity(tree.body.len());
    for statement in &tree.body {
        if let (Statement::Import(import), Some(module)) = (statement, rewritten_module(statement))
        {
            rewrite.import(import, module);
        } else if let Some((export, clause, module)) = reexported_module(statement) {
            rest.push(rewrite.reexport(export, clause, module));
        } else {
            rest.push(statement.clone());
        }
    }
    if !rewrite.renames.is_empty() {
        let mut renamer = Renamer {
            scopes: Vec::new(),
            renames: &rewrite.renames,
        };
        // The walk visits every statement kind and never fails.
        let _ = renamer.statements(&mut rest);
    }
    let mut body = rewrite.declarations;
    body.append(&mut rest);
    Some(SyntaxTree {
        goal: tree.goal,
        body,
        span: tree.span,
    })
}

/// Every identifier the program's code names, in any scope; and the words
/// of its local export clauses (`export { join }`).
fn referenced_names(statements: &[Statement]) -> (BTreeSet<String>, BTreeSet<String>) {
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
    let mut exported = BTreeSet::new();
    for statement in statements {
        if let Statement::Export(export) = statement
            && let ExportKind::NamedClause(clause) = &export.kind
            && clause.source().is_none()
        {
            exported.extend(
                clause
                    .canonical_head()
                    .split(|c: char| !(c == '$' || c == '_' || c.is_alphanumeric()))
                    .filter(|word| !word.is_empty())
                    .map(str::to_string),
            );
        }
    }
    let mut referenced = names.0;
    referenced.extend(exported.iter().cloned());
    (referenced, exported)
}

struct Rewrite {
    referenced: BTreeSet<String>,
    exported: BTreeSet<String>,
    declarations: Vec<Statement>,
    /// A named import of a member module: local -> (alias, export name).
    renames: BTreeMap<String, (String, String)>,
    aliases: usize,
    reexports: usize,
}

impl Rewrite {
    /// The import of a re-export's names under hidden locals, and the local
    /// clause that exports them in its place.
    fn reexport(
        &mut self,
        export: &ExportDeclaration,
        clause: &NamedExportClause,
        module: &str,
    ) -> Statement {
        let Some(source) = clause.source().cloned() else {
            return Statement::Export(export.clone());
        };
        let head = clause.canonical_head();
        let names = match head.strip_prefix("* as ") {
            Some(exported) => vec![("*".to_string(), exported.trim().to_string())],
            None => super::parse_named_export_clause_bindings(head),
        };
        let mut specifiers = Vec::new();
        let mut namespace = None;
        let mut exports = Vec::with_capacity(names.len());
        for (name, exported) in names {
            let local = format!("{REEXPORT_PREFIX}{}", self.reexports);
            self.reexports += 1;
            self.referenced.insert(local.clone());
            self.exported.insert(local.clone());
            exports.push(format!("{local} as {exported}"));
            if name == "*" {
                namespace = Some(local);
            } else {
                specifiers.push(ImportSpecifier {
                    import_name: name,
                    local_name: local,
                });
            }
        }
        let import = ImportDeclaration {
            clause: match namespace {
                Some(local) => ImportClause::Namespace { local },
                None => ImportClause::Named { specifiers },
            },
            binding: None,
            source,
            span: export.span,
        };
        self.import(&import, module);
        Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause(NamedExportClause::new(
                format!("{{ {} }}", exports.join(", ")),
                None,
            )),
            span: export.span,
        })
    }

    fn import(&mut self, import: &ImportDeclaration, module: &str) {
        match &import.clause {
            ImportClause::SideEffect => {}
            ImportClause::Default { local } | ImportClause::Namespace { local } => {
                self.alias(import, module, local);
            }
            ImportClause::Named { specifiers } => self.named(import, module, specifiers),
            ImportClause::DefaultAndNamed {
                default,
                specifiers,
            } => {
                self.alias(import, module, default);
                self.named(import, module, specifiers);
            }
            ImportClause::DefaultAndNamespace { default, namespace } => {
                self.alias(import, module, default);
                self.alias(import, module, namespace);
            }
        }
    }

    /// `const <local> = require(<source>);` when the program names `local`.
    /// A path module alias requires `node:path/posix`, which the path module
    /// object (path_module.rs) always serves: the path facade confirms only
    /// an alias used outside functions, and an imported `path` is usually
    /// used inside them. On POSIX `path.posix` is `path` itself.
    fn alias(&mut self, import: &ImportDeclaration, module: &str, local: &str) {
        if !self.referenced.contains(local) {
            return;
        }
        let pattern = BindingPattern::Identifier(local.to_string());
        self.declarations.push(if module == "path" {
            declaration(
                import,
                pattern,
                require_call(import, Expression::StringLiteral("node:path/posix".into())),
            )
        } else {
            require_declaration(import, pattern)
        });
    }

    fn named(&mut self, import: &ImportDeclaration, module: &str, specifiers: &[ImportSpecifier]) {
        let mut member_alias = None;
        for specifier in specifiers {
            let (name, local) = (&specifier.import_name, &specifier.local_name);
            if !self.referenced.contains(local) {
                continue;
            }
            if name == "default" {
                self.alias(import, module, local);
            } else if is_global_export(module, name) {
                if local != name {
                    self.declarations.push(declaration(
                        import,
                        BindingPattern::Identifier(local.clone()),
                        Expression::Member {
                            object: Box::new(Expression::Identifier("globalThis".to_string())),
                            property: Box::new(Expression::Identifier(name.clone())),
                            computed: false,
                            span: Some(import.span),
                        },
                    ));
                }
            } else if MEMBER_MODULES.contains(&module)
                && is_identifier_name(name)
                && !self.exported.contains(local)
            {
                let alias = member_alias
                    .get_or_insert_with(|| {
                        let alias = format!("{ALIAS_PREFIX}{}", self.aliases);
                        self.aliases += 1;
                        self.declarations.push(require_declaration(
                            import,
                            BindingPattern::Identifier(alias.clone()),
                        ));
                        alias
                    })
                    .clone();
                self.renames.insert(local.clone(), (alias, name.clone()));
            } else {
                let key = if is_identifier_name(name) {
                    Expression::Identifier(name.clone())
                } else {
                    Expression::StringLiteral(name.as_str().into())
                };
                self.declarations.push(require_declaration(
                    import,
                    BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                        key,
                        value: BindingPattern::Identifier(local.clone()),
                        computed: false,
                        shorthand: name == local,
                    }]),
                ));
            }
        }
    }
}

/// Replaces each unshadowed reference to a renamed import with the member
/// read on its alias.
struct Renamer<'a> {
    /// Names declared in each enclosing scope below the program, innermost
    /// last. The program's own scope cannot redeclare an import binding.
    scopes: Vec<BTreeSet<String>>,
    renames: &'a BTreeMap<String, (String, String)>,
}

impl Renamer<'_> {
    fn scoped(
        &mut self,
        names: BTreeSet<String>,
        walk: impl FnOnce(&mut Self) -> Outcome,
    ) -> Outcome {
        self.scopes.push(names);
        let outcome = walk(self);
        self.scopes.pop();
        outcome
    }
}

impl Walk for Renamer<'_> {
    scoped_walk!();

    /// A loop head's declaration scopes its names over the loop.
    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        let names = |pattern: &BindingPattern| {
            pattern
                .binding_names()
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<_>>()
        };
        let head = match &*statement {
            Statement::For(statement) => match statement.init.as_deref() {
                Some(Statement::VariableDeclaration(declaration)) => declaration
                    .declarations
                    .iter()
                    .flat_map(|declarator| names(&declarator.pattern))
                    .collect(),
                _ => BTreeSet::new(),
            },
            Statement::ForIn(statement) if statement.binding_kind.is_some() => {
                names(&statement.binding)
            }
            Statement::ForOf(statement) if statement.binding_kind.is_some() => {
                names(&statement.binding)
            }
            _ => BTreeSet::new(),
        };
        if head.is_empty() {
            return walk_statement(self, statement);
        }
        self.scoped(head, |walker| walk_statement(walker, statement))
    }

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if let Expression::Identifier(name) = expression
            && let Some((alias, member)) = self.renames.get(name.as_str())
            && !self
                .scopes
                .iter()
                .any(|scope| scope.contains(name.as_str()))
        {
            *expression = Expression::Member {
                object: Box::new(Expression::Identifier(alias.clone())),
                property: Box::new(Expression::Identifier(member.clone())),
                computed: false,
                span: None,
            };
            return Ok(());
        }
        walk_expression(self, expression)
    }
}

/// `const <pattern> = require('<source>');` at the import's span.
fn require_declaration(import: &ImportDeclaration, pattern: BindingPattern) -> Statement {
    declaration(
        import,
        pattern,
        require_call(import, Expression::StringLiteral(import.source.clone())),
    )
}

/// `require(<specifier>)` at the import's span.
fn require_call(import: &ImportDeclaration, specifier: Expression) -> Expression {
    Expression::Call {
        callee: Box::new(Expression::Identifier("require".to_string())),
        arguments: vec![specifier],
        span: Some(import.span),
    }
}

/// `const <pattern> = <initializer>;` at the import's span.
fn declaration(
    import: &ImportDeclaration,
    pattern: BindingPattern,
    initializer: Expression,
) -> Statement {
    Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Const,
        declarations: vec![VariableDeclarator {
            pattern,
            initializer: Some(initializer),
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
