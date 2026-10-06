//! `require('util')`, `require('node:util')` and `util/types` (bd-9vouw.109).
//!
//! Generic module loading needs file-system authority, so lowering refuses
//! a `require` read. util is a Node builtin with no authority: its members
//! format and inspect values, set up prototype chains, and wrap functions.
//! When a program has a `require('util')` whose `require` is the free
//! global, the rewrite puts
//!
//! ```text
//! const %util_module = <UTIL_SOURCE>;
//! ```
//!
//! first in the program and replaces each such call with `%util_module`
//! (`util/types` with `%util_module.types`), so every call returns the same
//! object. No source text can spell a `%` name. UTIL_SOURCE is engine-owned
//! JavaScript. It reads standard globals by name; one the program declares
//! at its top level (`const { TextEncoder } = require('util')`) is read
//! through `globalThis` instead. `inspect`, `format` and the internal type
//! tag behind `types` are HostCalls on the console formatter and the
//! engine's own object model: builtin:UtilInspect, builtin:UtilFormat and
//! builtin:UtilTypeTag. Everything else is ordinary JavaScript over the
//! engine's builtins, so labels and authority work as for user code.
//!
//! A `require` the program declares in an enclosing scope (a parameter, a
//! local function) is its own and is called as written. The filesystem facade
//! shares these hooks through `fs_module`; other unsupported specifiers and
//! `require` as a value keep the ambient-authority refusal.

use std::collections::BTreeSet;

// Both facades share the existing engine-owned syntax and intrinsic hooks.
// Filesystem methods carry no authority themselves: their native HostCalls
// still require the caller's FsRead/FsWrite capability at invocation.
#[path = "fs_module.rs"]
mod fs_module;

use super::LoweringPipelineError;
use super::with_statement::{
    FunctionBody, FunctionParts, Outcome, Search, Walk, lexical_names, var_names, walk_expression,
    walk_function, walk_switch_cases,
};
use crate::ast::{
    BindingPattern, CatchClause, Expression, ParseGoal, SourceSpan, Statement, SwitchCase,
    SyntaxTree, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

/// `util.inspect(value, { depth })`: the console formatter at a depth.
pub(super) const UTIL_INSPECT_CAPABILITY: &str = "builtin:UtilInspect";
/// `util.format(...args)`: console.log's formatting of an argument list.
pub(super) const UTIL_FORMAT_CAPABILITY: &str = "builtin:UtilFormat";
/// The engine's internal type of a value, for `util.types`.
pub(super) const UTIL_TYPE_TAG_CAPABILITY: &str = "builtin:UtilTypeTag";

const INSPECT_INTRINSIC: &str = "%UtilInspect";
const FORMAT_INTRINSIC: &str = "%UtilFormat";
const TYPE_TAG_INTRINSIC: &str = "%UtilTypeTag";

/// The program binding that caches the module object.
const MODULE_BINDING: &str = "%util_module";

/// UTIL_SOURCE spells the intrinsics with these names, which the parser
/// accepts, and the rewrite renames them to their `%` forms.
const PLACEHOLDERS: [(&str, &str); 3] = [
    ("__franken_util_inspect", INSPECT_INTRINSIC),
    ("__franken_util_format", FORMAT_INTRINSIC),
    ("__franken_util_type_tag", TYPE_TAG_INTRINSIC),
];

pub(super) fn intrinsic_capability(name: &str) -> Option<&'static str> {
    match name {
        INSPECT_INTRINSIC => Some(UTIL_INSPECT_CAPABILITY),
        FORMAT_INTRINSIC => Some(UTIL_FORMAT_CAPABILITY),
        TYPE_TAG_INTRINSIC => Some(UTIL_TYPE_TAG_CAPABILITY),
        _ => fs_module::intrinsic_capability(name),
    }
}

/// The module object, built once per program.
// Keep the executable source in one place for native lowering and differential tests.
const UTIL_SOURCE: &str = include_str!("util_module.js");

/// For `require(specifier)` with a util specifier, whatever `require`
/// names: `Some(None)` for the module (`util`, `node:util`), `Some(Some(m))`
/// for a subpath that is the module's member `m` (`util/types`).
fn util_require_member(expression: &Expression) -> Option<Option<&'static str>> {
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
    if *specifier == "util" || *specifier == "node:util" {
        Some(None)
    } else if *specifier == "util/types" || *specifier == "node:util/types" {
        Some(Some("types"))
    } else {
        None
    }
}

fn is_util_require_call(expression: &Expression) -> bool {
    util_require_member(expression).is_some()
}

const UTIL_REQUIRE_SEARCH: Search = Search {
    statement: |_| false,
    expression: is_util_require_call,
};

/// The standard globals UTIL_SOURCE reads by name. A program that declares
/// one at its top level would capture the module's reference, so the
/// module reads those through `globalThis` instead.
const MODULE_GLOBALS: [&str; 14] = [
    "Array",
    "Error",
    "JSON",
    "Map",
    "Object",
    "Promise",
    "Reflect",
    "Set",
    "String",
    "Symbol",
    "TextDecoder",
    "TextEncoder",
    "TypeError",
    "Uint8Array",
];

/// `const %util_module = <module>;`, which the rewrite puts first in the
/// program. Its initializer runs only engine-owned code.
pub(super) fn is_module_declaration(statement: &Statement) -> bool {
    if fs_module::is_module_declaration(statement) {
        return true;
    }
    matches!(
        statement,
        Statement::VariableDeclaration(declaration)
            if matches!(
                declaration.declarations.as_slice(),
                [VariableDeclarator {
                    pattern: BindingPattern::Identifier(name),
                    ..
                }] if name == MODULE_BINDING
            )
    )
}

/// `tree` with every free `require('util')` rewritten to the module, or
/// `None` when it has none.
pub(super) fn rewrite_util_requires(
    tree: &SyntaxTree,
) -> Result<Option<SyntaxTree>, LoweringPipelineError> {
    let fs_rewritten = fs_module::rewrite_fs_requires(tree)?;
    let tree = fs_rewritten.as_ref().unwrap_or(tree);
    if !tree
        .body
        .iter()
        .any(|statement| UTIL_REQUIRE_SEARCH.in_statement(statement))
    {
        return Ok(fs_rewritten);
    }
    let mut root = BTreeSet::new();
    var_names(&tree.body, &mut root);
    lexical_names(&tree.body, &mut root);
    let mut rewritten = tree.clone();
    let mut rewriter = UtilRewriter {
        scopes: vec![root.clone()],
        replaced: 0,
    };
    rewriter.statements(&mut rewritten.body)?;
    if rewriter.replaced == 0 {
        return Ok(fs_rewritten);
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
                initializer: Some(module_source(&root)?),
                span,
            }],
            span,
        }),
    );
    Ok(Some(rewritten))
}

fn parse_module_source() -> Result<Expression, LoweringPipelineError> {
    let parse_failed = || LoweringPipelineError::InvariantViolation {
        detail: "the engine's util module source failed to parse",
    };
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "franken:util".into(),
                text: UTIL_SOURCE.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|_| parse_failed())?;
    let [Statement::Expression(statement)] = tree.body.as_slice() else {
        return Err(parse_failed());
    };
    Ok(statement.expression.clone())
}

/// UTIL_SOURCE parsed, with its intrinsics renamed and the globals the
/// program declares (`program_names`) read through `globalThis`.
fn module_source(program_names: &BTreeSet<String>) -> Result<Expression, LoweringPipelineError> {
    let mut expression = parse_module_source()?;
    let mut renamer = ModuleRenamer {
        through_global_object: MODULE_GLOBALS
            .iter()
            .filter(|name| program_names.contains(**name))
            .map(|name| (*name).to_string())
            .collect(),
    };
    renamer.expression(&mut expression)?;
    Ok(expression)
}

struct ModuleRenamer {
    through_global_object: BTreeSet<String>,
}

impl Walk for ModuleRenamer {
    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if let Expression::Identifier(name) = expression {
            if let Some((_, intrinsic)) = PLACEHOLDERS
                .iter()
                .find(|(placeholder, _)| placeholder == name)
            {
                *name = (*intrinsic).to_string();
            } else if self.through_global_object.contains(name.as_str()) {
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

struct UtilRewriter {
    /// Names declared in each enclosing scope, innermost last.
    scopes: Vec<BTreeSet<String>>,
    replaced: usize,
}

impl UtilRewriter {
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

    /// `util_require_member` when `require` is the global one.
    fn util_require(&self, expression: &Expression) -> Option<Option<&'static str>> {
        if self.scopes.iter().any(|scope| scope.contains("require")) {
            return None;
        }
        util_require_member(expression)
    }
}

/// Function, block, catch and switch scopes, as the `with` rewrite tracks
/// them.
macro_rules! scoped_walk {
    () => {
        fn block(&mut self, statements: &mut [Statement]) -> Outcome {
            let mut names = BTreeSet::new();
            lexical_names(statements, &mut names);
            self.scoped(names, |walker| walker.statements(statements))
        }

        fn catch_clause(&mut self, clause: &mut CatchClause) -> Outcome {
            let mut names: BTreeSet<String> = clause.parameter.iter().cloned().collect();
            lexical_names(&clause.body.body, &mut names);
            self.scoped(names, |walker| walker.statements(&mut clause.body.body))
        }

        fn switch_cases(&mut self, cases: &mut [SwitchCase]) -> Outcome {
            let mut names = BTreeSet::new();
            for case in cases.iter() {
                lexical_names(&case.consequent, &mut names);
            }
            self.scoped(names, |walker| walk_switch_cases(walker, cases))
        }

        fn function(&mut self, function: FunctionParts<'_>) -> Outcome {
            let mut names = BTreeSet::new();
            names.extend(function.own_name.map(str::to_string));
            for param in function.params.iter() {
                names.extend(
                    param
                        .pattern
                        .binding_names()
                        .into_iter()
                        .map(str::to_string),
                );
            }
            if let FunctionBody::Block(block) = &function.body {
                var_names(&block.body, &mut names);
                lexical_names(&block.body, &mut names);
            }
            self.scoped(names, |walker| walk_function(walker, function))
        }
    };
}

pub(super) use scoped_walk;

impl Walk for UtilRewriter {
    scoped_walk!();

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if let Some(member) = self.util_require(expression) {
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
            self.replaced += 1;
            return Ok(());
        }
        walk_expression(self, expression)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The free names of an expression: identifiers no enclosing scope in it
    /// declares.
    struct FreeNames {
        scopes: Vec<BTreeSet<String>>,
        free: BTreeSet<String>,
    }

    impl FreeNames {
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

    impl Walk for FreeNames {
        scoped_walk!();

        fn expression(&mut self, expression: &mut Expression) -> Outcome {
            if let Expression::Identifier(name) = expression {
                if !self
                    .scopes
                    .iter()
                    .any(|scope| scope.contains(name.as_str()))
                {
                    self.free.insert(name.clone());
                }
                return Ok(());
            }
            walk_expression(self, expression)
        }
    }

    fn free_names(expression: &mut Expression) -> BTreeSet<String> {
        let mut walker = FreeNames {
            scopes: Vec::new(),
            free: BTreeSet::new(),
        };
        walker.expression(expression).expect("walks");
        walker.free
    }

    /// MODULE_GLOBALS lists every global UTIL_SOURCE reads; anything else
    /// it names is an intrinsic placeholder or `arguments`.
    #[test]
    fn module_globals_cover_the_module_source() {
        let mut expected: BTreeSet<String> =
            MODULE_GLOBALS.iter().map(|name| name.to_string()).collect();
        expected.extend(PLACEHOLDERS.iter().map(|(name, _)| name.to_string()));
        expected.insert("arguments".to_string());
        let free = free_names(&mut parse_module_source().expect("parses"));
        assert_eq!(free, expected);
    }

    /// A global the program declares is read through `globalThis`; the
    /// others keep their names.
    #[test]
    fn declared_globals_are_read_through_the_global_object() {
        let names = ["TextEncoder".to_string(), "unrelated".to_string()]
            .into_iter()
            .collect();
        let free = free_names(&mut module_source(&names).expect("builds"));
        assert!(!free.contains("TextEncoder"), "{free:?}");
        assert!(
            free.contains("TextDecoder") && free.contains("globalThis"),
            "{free:?}"
        );
        assert!(free.contains("%UtilInspect"), "{free:?}");
    }
}
