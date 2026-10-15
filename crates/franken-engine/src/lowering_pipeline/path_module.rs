//! `require('path')` as a module object (bd-9vouw.181).
//!
//! The path facade (bd-tu0c3) lowers the member calls and constant reads of
//! a program-level `path` alias (`const path = require('path')`) and of an
//! inline `require('path').join(...)` to `builtin:Path*` HostCalls. Every
//! other form found no module: a destructured `const { join } =
//! require('path')` (and so `import { join } from 'node:path'`), a
//! `require('path')` inside a function, one passed as a value, an inline
//! read of a function (`require('path').parse`), or a program-level alias a
//! function reads (the facade lowers the alias's uses in the program body
//! only; bd-9vouw.300). For those, the rewrite puts
//!
//! ```text
//! const %path_module = <PATH_SOURCE>;
//! ```
//!
//! first in the program and replaces the call with `%path_module`. No source
//! text can spell a `%` name. PATH_SOURCE is engine-owned JavaScript over
//! the facade's own HostCalls, each called with a fixed argument list:
//! `join` and `resolve` validate and concatenate their arguments as Node's
//! posix implementation does and leave normalization (and the working
//! directory) to builtin:PathNormalize / builtin:PathResolve. The calls the
//! facade claims keep their HostCall lowering unchanged.
//!
//! POSIX and Windows namespace values share this module object. Windows
//! normalization/basename/absolute tests reuse the existing Win32 HostCalls;
//! Windows composition uses the same logical cwd as PathResolve. No native
//! Windows filesystem, per-drive environment authority or I/O is introduced.

use std::collections::BTreeSet;

use super::LoweringPipelineError;
use super::util_module::scoped_walk;
use super::with_statement::{
    FunctionBody, FunctionParts, Outcome, Search, Walk, lexical_names, var_names, walk_expression,
    walk_class, walk_function, walk_statement, walk_switch_cases,
};
use crate::ast::{
    BindingPattern, CatchClause, Expression, MethodDefinition, ParseGoal, SourceSpan, Statement, SwitchCase,
    SyntaxTree, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

/// The program binding that caches the module object.
const MODULE_BINDING: &str = "%path_module";

/// PATH_SOURCE spells the facade's HostCalls with these names, which the
/// parser accepts, and the rewrite renames them to their `%` forms.
const INTRINSICS: [(&str, &str, &str); 12] = [
    (
        "__franken_path_normalize",
        "%PathNormalize",
        "builtin:PathNormalize",
    ),
    (
        "__franken_path_resolve",
        "%PathResolve",
        "builtin:PathResolve",
    ),
    (
        "__franken_path_relative",
        "%PathRelative",
        "builtin:PathRelative",
    ),
    (
        "__franken_path_basename",
        "%PathBasename",
        "builtin:PathBasename",
    ),
    (
        "__franken_path_dirname",
        "%PathDirname",
        "builtin:PathDirname",
    ),
    (
        "__franken_path_extname",
        "%PathExtname",
        "builtin:PathExtname",
    ),
    (
        "__franken_path_is_absolute",
        "%PathIsAbsolute",
        "builtin:PathIsAbsolute",
    ),
    ("__franken_path_parse", "%PathParse", "builtin:PathParse"),
    ("__franken_path_format", "%PathFormat", "builtin:PathFormat"),
    ("__franken_path_win32_join", "%PathWin32Join", "builtin:PathWin32Join"),
    ("__franken_path_win32_basename", "%PathWin32Basename", "builtin:PathWin32Basename"),
    ("__franken_path_win32_is_absolute", "%PathWin32IsAbsolute", "builtin:PathWin32IsAbsolute"),
];

pub(super) fn intrinsic_capability(name: &str) -> Option<&'static str> {
    INTRINSICS
        .iter()
        .find(|(_, intrinsic, _)| *intrinsic == name)
        .map(|(_, _, capability)| *capability)
}

/// The module object, built once per program. Node's posix `join` and
/// `resolve` with normalization delegated; the rest call the HostCall the
/// facade lowers the same member call to.
const PATH_SOURCE: &str = include_str!("path_module.js");

/// For `require(specifier)` with one of `specifiers`, whatever `require`
/// names.
fn is_require_call_of(expression: &Expression, specifiers: &[&str]) -> bool {
    let Expression::Call {
        callee, arguments, ..
    } = expression
    else {
        return false;
    };
    matches!(callee.as_ref(), Expression::Identifier(name) if name == "require")
        && matches!(arguments.as_slice(), [Expression::StringLiteral(specifier)]
            if specifiers.iter().any(|path| *specifier == *path))
}

fn is_path_require_call(expression: &Expression) -> bool {
    is_require_call_of(
        expression,
        &["path", "node:path", "path/posix", "node:path/posix", "path/win32", "node:path/win32"],
    )
}

/// A `require` of the specifiers the facade recognizes.
fn is_facade_require_call(expression: &Expression) -> bool {
    is_require_call_of(expression, &["path", "node:path"])
}

/// The facade's inline forms: a recognized method call or constant read on
/// `require('path')` or its `posix` / `win32` namespace.
fn is_facade_inline_use(expression: &Expression) -> bool {
    is_facade_use(expression, &is_facade_require_call)
}

fn is_facade_alias_use(expression: &Expression, aliases: &BTreeSet<String>) -> bool {
    is_facade_use(expression, &|value| matches!(value, Expression::Identifier(name) if aliases.contains(name)))
}

fn is_facade_use(expression: &Expression, receiver: &impl Fn(&Expression) -> bool) -> bool {
    match expression {
        Expression::Call { callee, .. } => matches!(callee.as_ref(),
        Expression::Member { object, property, computed: false, .. }
            if super::path_receiver_namespace_with(object, receiver)
                .zip(super::well_formed_static_name(property))
                .is_some_and(|(namespace, method)| {
                    super::path_method_capability(namespace, method).is_some()
                })),
        Expression::Member {
            object,
            property,
            computed,
            ..
        } => super::path_receiver_namespace_with(object, receiver)
            .zip(if *computed {
                super::well_formed_string_literal(property)
            } else {
                super::well_formed_static_name(property)
            })
            .is_some_and(|(namespace, name)| {
                super::path_namespace_property_constant(namespace, name).is_some()
            }),
        _ => false,
    }
}

const PATH_REQUIRE_SEARCH: Search = Search {
    statement: |_| false,
    expression: is_path_require_call,
};

/// `const %path_module = <module>;`, which the rewrite puts first in the
/// program. Its initializer runs only engine-owned code.
pub(super) fn is_module_declaration(statement: &Statement) -> bool {
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

/// `tree` with every free `require('path')` the facade cannot claim
/// rewritten to the module, or `None` when it has none.
pub(super) fn rewrite_path_requires(
    tree: &SyntaxTree,
) -> Result<Option<SyntaxTree>, LoweringPipelineError> {
    if !tree
        .body
        .iter()
        .any(|statement| PATH_REQUIRE_SEARCH.in_statement(statement))
    {
        return Ok(None);
    }
    let mut root = BTreeSet::new();
    var_names(&tree.body, &mut root);
    lexical_names(&tree.body, &mut root);
    for statement in &tree.body {
        if let Statement::Import(import) = statement {
            root.extend(import.clause.binding_names().into_iter().map(str::to_string));
        }
    }
    let mut rewritten = tree.clone();
    let mut rewriter = PathRewriter {
        scopes: vec![root.clone()],
        replaced: 0,
        function_aliases: aliases_read_in_functions(&tree.body)?,
        materialize_all: false,
    };
    for statement in &mut rewritten.body {
        rewriter.program_statement(statement)?;
    }
    if rewriter.replaced == 0 {
        return Ok(None);
    }
    // Once any path namespace/function escapes, ALL requests in this program
    // must observe that same mutable object. Otherwise a direct inline call
    // would silently ignore a mutation through the first-class namespace.
    rewritten = tree.clone();
    rewriter.materialize_all = true;
    for statement in &mut rewritten.body {
        rewriter.program_statement(statement)?;
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
        detail: "the engine's path module source failed to parse",
    };
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "franken:path".into(),
                text: PATH_SOURCE.into(),
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

/// Rename only engine intrinsics and protect the factory's Array binding.
fn module_source(program_names: &BTreeSet<String>) -> Result<Expression, LoweringPipelineError> {
    struct Renamer { protect_array: bool }

    impl Walk for Renamer {
        fn expression(&mut self, expression: &mut Expression) -> Outcome {
            if let Expression::Identifier(name) = expression {
                if let Some((_, intrinsic, _)) = INTRINSICS
                    .iter()
                    .find(|(placeholder, _, _)| placeholder == name)
                {
                    *name = (*intrinsic).to_string();
                } else if self.protect_array && name == "Array" {
                    *expression = Expression::Member {
                        object: Box::new(Expression::Identifier("globalThis".into())),
                        property: Box::new(Expression::Identifier("Array".into())),
                        computed: false,
                        span: None,
                    };
                }
                return Ok(());
            }
            walk_expression(self, expression)
        }
    }

    let mut expression = parse_module_source()?;
    Renamer { protect_array: program_names.contains("Array") }.expression(&mut expression)?;
    Ok(expression)
}

/// The program's facade aliases (`const path = require('path')` in the
/// program body) that a function, arrow or method reads. The facade lowers an
/// alias's uses in the program body only: a function's `path.basename(x)`
/// read an unbound `path` (or, with no use in the program body, the alias
/// stayed a runtime `require('path')`, which finds no module), bd-9vouw.300.
/// An alias used as a value, mutated, or read through an unsupported member
/// also escapes the call facade. Shadowing may conservatively materialize the
/// outer module, but never replaces the user's local binding.
fn aliases_read_in_functions(
    body: &[Statement],
) -> Result<BTreeSet<String>, LoweringPipelineError> {
    struct FunctionReads<'a> {
        aliases: &'a BTreeSet<String>,
        depth: usize,
        read: BTreeSet<String>,
    }

    impl Walk for FunctionReads<'_> {
        fn function(&mut self, function: FunctionParts<'_>) -> Outcome {
            self.depth += 1;
            let outcome = walk_function(self, function);
            self.depth -= 1;
            outcome
        }

        fn expression(&mut self, expression: &mut Expression) -> Outcome {
            if self.depth == 0 && is_facade_alias_use(expression, self.aliases) {
                if let Expression::Call { arguments, .. } = expression {
                    for argument in arguments { self.expression(argument)?; }
                }
                return Ok(());
            }
            if let Expression::Identifier(name) = expression
                && self.aliases.contains(name)
            {
                self.read.insert(name.clone());
            }
            walk_expression(self, expression)
        }
    }

    let mut aliases = BTreeSet::new();
    for statement in body {
        if let Statement::VariableDeclaration(declaration) = statement {
            for declarator in &declaration.declarations {
                if let (BindingPattern::Identifier(name), Some(initializer)) =
                    (&declarator.pattern, &declarator.initializer)
                    && is_facade_require_call(initializer)
                {
                    aliases.insert(name.clone());
                }
            }
        }
    }
    if aliases.is_empty() {
        return Ok(aliases);
    }
    let mut walker = FunctionReads {
        aliases: &aliases,
        depth: 0,
        read: BTreeSet::new(),
    };
    walker.statements(&mut body.to_vec())?;
    Ok(walker.read)
}

struct PathRewriter {
    /// Names declared in each enclosing scope, innermost last.
    scopes: Vec<BTreeSet<String>>,
    replaced: usize,
    /// Facade aliases with escaping/observable reads: they get the module.
    function_aliases: BTreeSet<String>,
    materialize_all: bool,
}

impl PathRewriter {
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

    /// A path `require` call whose `require` is the global one.
    fn is_free_path_require(&self, expression: &Expression) -> bool {
        !self.scopes.iter().any(|scope| scope.contains("require"))
            && is_path_require_call(expression)
    }
}

impl PathRewriter {
    /// A statement of the program body. The facade's alias, a declaration
    /// there binding a name to `require('path')`, keeps its call unless a
    /// function reads it.
    fn program_statement(&mut self, statement: &mut Statement) -> Outcome {
        let Statement::VariableDeclaration(declaration) = statement else {
            return self.statement(statement);
        };
        for declarator in &mut declaration.declarations {
            self.pattern(&mut declarator.pattern)?;
            match &mut declarator.initializer {
                Some(initializer)
                    if !self.materialize_all
                        && matches!(&declarator.pattern, BindingPattern::Identifier(name)
                        if !self.function_aliases.contains(name))
                        && is_facade_require_call(initializer) => {}
                Some(initializer) => self.expression(initializer)?,
                None => {}
            }
        }
        Ok(())
    }
}

impl Walk for PathRewriter {
    scoped_walk!();

    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        let mut names = BTreeSet::new();
        match &*statement {
            Statement::For(loop_statement) => {
                if let Some(initializer) = &loop_statement.init {
                    let initializer: &Statement = initializer;
                    lexical_names(std::slice::from_ref(initializer), &mut names);
                }
            }
            Statement::ForIn(loop_statement) if loop_statement.binding_kind.is_some() => {
                names.extend(loop_statement.binding.binding_names().into_iter().map(str::to_string));
            }
            Statement::ForOf(loop_statement) if loop_statement.binding_kind.is_some() => {
                names.extend(loop_statement.binding.binding_names().into_iter().map(str::to_string));
            }
            Statement::With(_) => { names.insert("require".into()); }
            _ => {}
        }
        self.scoped(names, |walker| walk_statement(walker, statement))
    }

    fn class(
        &mut self,
        name: Option<&str>,
        super_class: Option<&mut Expression>,
        body: &mut [MethodDefinition],
    ) -> Outcome {
        let names = name.map(str::to_string).into_iter().collect();
        self.scoped(names, |walker| walk_class(walker, super_class, body))
    }

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if !self.materialize_all && is_facade_inline_use(expression) {
            if let Expression::Call { arguments, .. } = expression {
                for argument in arguments {
                    self.expression(argument)?;
                }
            }
            return Ok(());
        }
        if self.is_free_path_require(expression) {
            let module = Expression::Identifier(MODULE_BINDING.to_string());
            *expression = if is_require_call_of(expression, &["path/win32", "node:path/win32"]) {
                Expression::Member {
                    object: Box::new(module),
                    property: Box::new(Expression::Identifier("win32".into())),
                    computed: false,
                    span: None,
                }
            } else { module };
            self.replaced += 1;
            return Ok(());
        }
        walk_expression(self, expression)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every placeholder PATH_SOURCE calls is renamed to an intrinsic the
    /// lowering turns into a HostCall.
    #[test]
    fn module_source_calls_only_intrinsics() {
        let source = format!("{:?}", module_source(&BTreeSet::new()).expect("builds"));
        assert!(!source.contains("__franken_path"), "{source}");
        for (_, intrinsic, capability) in INTRINSICS {
            assert!(source.contains(intrinsic), "{intrinsic}");
            assert_eq!(intrinsic_capability(intrinsic), Some(capability));
        }
    }
}

#[cfg(test)]
mod win32_tests {
    use super::*;

    fn parse(source: &str, goal: ParseGoal) -> SyntaxTree {
        CanonicalEs2020Parser.parse_with_options(
            ParserSource { label: "path-namespace-values.js".into(), text: source.into() },
            goal, &ParserOptions::default(),
        ).expect("fixture parses")
    }

    #[test]
    fn namespace_values_materialize_all_related_requests_once() {
        for source in [
            "const p=require('path/win32'); p.join('C:/', 'a');",
            "const {join}=require('node:path/win32'); join('C:/', 'a');",
            "const p=require('path'); const w=p.win32; w.join=f; require('path').win32.join('a');",
            "const p=require('path'); const f=p.join; f('a','b'); p.join('c','d');",
            "const p=require('path/posix'); const q=require('path'); p===q;",
        ] {
            let tree = parse(source, ParseGoal::Script);
            let rewritten = rewrite_path_requires(&tree).unwrap().expect("namespace materialized");
            assert_eq!(rewritten.body.len(), tree.body.len() + 1, "{source}");
            assert_eq!(rewritten.body.iter().filter(|s| is_module_declaration(s)).count(), 1);
            assert!(!rewritten.body.iter().any(|s| PATH_REQUIRE_SEARCH.in_statement(s)), "no direct call bypass: {source}");
            assert!(rewrite_path_requires(&rewritten).unwrap().is_none());
            assert_eq!(tree, parse(source, ParseGoal::Script), "input is immutable");
        }
    }

    #[test]
    fn direct_only_calls_keep_the_existing_native_fast_path() {
        for source in [
            "const p=require('path'); p.join('a','b'); p.sep;",
            "require('path').basename('/a/b');",
            "const p=require('path'); p.win32.join('C:/', 'a');",
        ] {
            assert!(rewrite_path_requires(&parse(source, ParseGoal::Script)).unwrap().is_none(), "{source}");
        }
    }

    #[test]
    fn namespace_rewrite_preserves_user_loaders_and_import_bindings() {
        for source in [
            "function f(require){return require('path/win32');}",
            "{const require=loader; require('node:path/win32');}",
            "for(const require of loaders) require('path/win32');",
            "for(const require in loaders) require('path/win32');",
            "for(let require=loader;test;update) require('path/win32');",
            "with(scope) require('path/win32');",
            "const C=class require { method(){return require('path/win32');} };",
            "const name='path/win32'; require(name);",
            "require('./path/win32');",
        ] {
            assert!(rewrite_path_requires(&parse(source, ParseGoal::Script)).unwrap().is_none(), "{source}");
        }
        let imported = parse("import require from './loader.mjs'; require('path/win32');", ParseGoal::Module);
        assert!(rewrite_path_requires(&imported).unwrap().is_none());
    }

    #[test]
    fn esm_windows_imports_and_reexports_use_the_existing_path_module() {
        for source in [
            "import w from 'node:path/win32'; w.join('C:/', 'a');",
            "import {join as build} from 'path/win32'; build('C:/', 'a');",
            "import * as w from 'path/win32'; w.parse('C:/a.txt');",
            "export {join as build, win32, posix} from 'node:path/win32';",
            "export * as windows from 'path/win32';",
        ] {
            let tree = parse(source, ParseGoal::Module);
            let expanded = super::super::esm_core_imports::rewrite_core_module_imports(&tree)
                .expect("Windows core imports are recognized");
            let lowered = rewrite_path_requires(&expanded).unwrap()
                .expect("imported values use the canonical namespace pair");
            assert_eq!(lowered.body.iter().filter(|s| is_module_declaration(s)).count(), 1);
            assert!(!lowered.body.iter().any(|s| PATH_REQUIRE_SEARCH.in_statement(s)));
            assert!(rewrite_path_requires(&lowered).unwrap().is_none());
            assert_eq!(tree, parse(source, ParseGoal::Module), "source AST is unchanged");
        }
        let shadowed = parse(
            "import require from './loader.mjs'; import w from 'path/win32'; w.join('a');",
            ParseGoal::Module,
        );
        assert!(super::super::esm_core_imports::rewrite_core_module_imports(&shadowed).is_none());
    }

    #[test]
    fn format_helper_protects_a_shadowed_array_binding() {
        let unprotected = module_source(&BTreeSet::new()).unwrap();
        let protected = module_source(&BTreeSet::from(["Array".into()])).unwrap();
        assert_ne!(unprotected, protected);
        assert!(format!("{protected:?}").contains("globalThis"));
        assert_eq!(intrinsic_capability("%PathWin32Join"), Some("builtin:PathWin32Join"));
        assert_eq!(intrinsic_capability("__franken_path_win32_join"), None);
    }
}
