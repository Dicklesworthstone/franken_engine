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
//! local function) is its own and is called as written. The same pure-module
//! lowering hook also materializes `events` over the native EventEmitter
//! constructor and EventsOnce hostcall (bd-305gi). No filesystem/module-load
//! authority is introduced. The filesystem facade shares these hooks through
//! `fs_module`; its methods retain their native fs:read/fs:write checks.
//! Other specifiers and `require` as a value keep their existing authority checks.

use std::collections::BTreeSet;

// Filesystem methods retain the caller's FsRead/FsWrite checks at invocation.
#[path = "fs_module.rs"]
mod fs_module;

use super::LoweringPipelineError;
use super::with_statement::{
    FunctionBody, FunctionParts, Outcome, Search, Walk, lexical_names, var_names, walk_class,
    walk_expression, walk_function, walk_statement, walk_switch_cases,
};
use crate::ast::{
    BindingPattern, CatchClause, Expression, MethodDefinition, ParseGoal, SourceSpan, Statement,
    SwitchCase, SyntaxTree, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
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
const EVENTS_MODULE_BINDING: &str = "%events_module";
const ASSERT_MODULE_BINDING: &str = "%assert_module";
const TIMERS_MODULE_BINDING: &str = "%timers_module";
const STRING_DECODER_MODULE_BINDING: &str = "%string_decoder_module";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PureModule {
    Util,
    Events,
    Assert,
    Timers,
    StringDecoder,
}

impl PureModule {
    fn binding(self) -> &'static str {
        match self {
            Self::Util => MODULE_BINDING,
            Self::Events => EVENTS_MODULE_BINDING,
            Self::Assert => ASSERT_MODULE_BINDING,
            Self::Timers => TIMERS_MODULE_BINDING,
            Self::StringDecoder => STRING_DECODER_MODULE_BINDING,
        }
    }
}

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
        "%EventsConstructorRef" => Some("builtin:EventEmitterConstructorRef"),
        "%EventsOnce" => Some("builtin:EventsOnce"),
        "%TimersPromisesSetTimeout" => Some("builtin:TimersPromisesSetTimeout"),
        "%TimersPromisesSetImmediate" => Some("builtin:TimersPromisesSetImmediate"),
        "%TimersPromisesSetInterval" => Some("builtin:TimersPromisesSetInterval"),
        _ => fs_module::intrinsic_capability(name),
    }
}

/// The module object, built once per program.
// Keep the executable source in one place for native lowering and differential tests.
const UTIL_SOURCE: &str = include_str!("util_module.js");
const EVENTS_SOURCE: &str = include_str!("events_module.js");
const ASSERT_SOURCE: &str = include_str!("assert_module.js");
const TIMERS_SOURCE: &str = include_str!("timers_module.js");
const STRING_DECODER_SOURCE: &str = include_str!("string_decoder_module.js");

const TIMERS_PLACEHOLDERS: [(&str, &str); 3] = [
    ("__franken_timers_timeout", "%TimersPromisesSetTimeout"),
    ("__franken_timers_immediate", "%TimersPromisesSetImmediate"),
    ("__franken_timers_interval", "%TimersPromisesSetInterval"),
];

// A private dependency, not an ambient HostCall or a public util property.
const ASSERT_PLACEHOLDERS: [(&str, &str); 1] = [("__franken_assert_util", MODULE_BINDING)];

const EVENTS_PLACEHOLDERS: [(&str, &str); 2] = [
    ("__franken_events_constructor", "%EventsConstructorRef"),
    ("__franken_events_once", "%EventsOnce"),
];

/// Recognize a literal pure-builtin request before resolving the `require`
/// binding. The optional member selects util's `types` submodule.
fn builtin_require_member(expression: &Expression) -> Option<(PureModule, Option<&'static str>)> {
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
        Some((PureModule::Util, None))
    } else if *specifier == "util/types" || *specifier == "node:util/types" {
        Some((PureModule::Util, Some("types")))
    } else if *specifier == "events" || *specifier == "node:events" {
        Some((PureModule::Events, None))
    } else if *specifier == "assert" || *specifier == "node:assert" {
        Some((PureModule::Assert, None))
    } else if *specifier == "assert/strict" || *specifier == "node:assert/strict" {
        Some((PureModule::Assert, Some("strict")))
    } else if *specifier == "timers" || *specifier == "node:timers" {
        Some((PureModule::Timers, None))
    } else if *specifier == "timers/promises" || *specifier == "node:timers/promises" {
        Some((PureModule::Timers, Some("promises")))
    } else if *specifier == "string_decoder" || *specifier == "node:string_decoder" {
        Some((PureModule::StringDecoder, None))
    } else {
        None
    }
}

fn is_builtin_require_call(expression: &Expression) -> bool {
    builtin_require_member(expression).is_some()
}

const BUILTIN_REQUIRE_SEARCH: Search = Search {
    statement: |_| false,
    expression: is_builtin_require_call,
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

const TIMERS_GLOBALS: [&str; 7] = [
    "Object",
    "setTimeout",
    "clearTimeout",
    "setImmediate",
    "clearImmediate",
    "setInterval",
    "clearInterval",
];

const STRING_DECODER_GLOBALS: [&str; 9] = [
    "ArrayBuffer",
    "Buffer",
    "DataView",
    "Object",
    "Reflect",
    "String",
    "TypeError",
    "Uint8Array",
    "WeakMap",
];

const EVENTS_GLOBALS: [&str; 11] = [
    "AbortController",
    "AbortSignal",
    "Array",
    "Error",
    "EventTarget",
    "Object",
    "Promise",
    "RangeError",
    "Reflect",
    "Symbol",
    "TypeError",
];

const ASSERT_GLOBALS: [&str; 10] = [
    "Array",
    "Error",
    "Map",
    "Object",
    "Reflect",
    "RegExp",
    "Set",
    "String",
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
                }] if name == MODULE_BINDING || name == EVENTS_MODULE_BINDING
                    || name == ASSERT_MODULE_BINDING || name == TIMERS_MODULE_BINDING
                    || name == STRING_DECODER_MODULE_BINDING
            )
    )
}

/// Materialize the requested pure builtin modules through the existing
/// lowering hook. Each is initialized once per program; shadowed `require`
/// calls and nonliteral specifiers are not rewritten.
pub(super) fn rewrite_util_requires(
    tree: &SyntaxTree,
) -> Result<Option<SyntaxTree>, LoweringPipelineError> {
    let fs_rewritten = fs_module::rewrite_fs_requires(tree)?;
    let tree = fs_rewritten.as_ref().unwrap_or(tree);
    if !tree
        .body
        .iter()
        .any(|statement| BUILTIN_REQUIRE_SEARCH.in_statement(statement))
    {
        return Ok(fs_rewritten);
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
    let mut rewritten = tree.clone();
    let mut rewriter = BuiltinRewriter {
        scopes: vec![root.clone()],
        modules: BTreeSet::new(),
    };
    rewriter.statements(&mut rewritten.body)?;
    // Enum ordering initializes util before assert. Capturing its comparator
    // in the engine-owned prelude avoids guest replacement of public exports.
    if rewriter.modules.contains(&PureModule::Assert) {
        rewriter.modules.insert(PureModule::Util);
    }
    if rewriter.modules.is_empty() {
        return Ok(fs_rewritten);
    }
    let span = rewritten.body.first().map_or_else(
        || SourceSpan::new(0, 0, 1, 1, 1, 1),
        |statement| *statement.span(),
    );
    let mut declarations = Vec::new();
    for module in rewriter.modules {
        declarations.push(Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier(module.binding().to_string()),
                initializer: Some(module_source(&root, module)?),
                span,
            }],
            span,
        }));
    }
    declarations.append(&mut rewritten.body);
    rewritten.body = declarations;
    Ok(Some(rewritten))
}

fn parse_module_source(module: PureModule) -> Result<Expression, LoweringPipelineError> {
    let (label, source) = match module {
        PureModule::Util => ("franken:util", UTIL_SOURCE),
        PureModule::Events => ("franken:events", EVENTS_SOURCE),
        PureModule::Assert => ("franken:assert", ASSERT_SOURCE),
        PureModule::Timers => ("franken:timers", TIMERS_SOURCE),
        PureModule::StringDecoder => ("franken:string_decoder", STRING_DECODER_SOURCE),
    };
    let parse_failed = || LoweringPipelineError::InvariantViolation {
        detail: "the engine's pure builtin module source failed to parse",
    };
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: label.into(),
                text: source.into(),
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
fn module_source(
    program_names: &BTreeSet<String>,
    module: PureModule,
) -> Result<Expression, LoweringPipelineError> {
    let mut expression = parse_module_source(module)?;
    let globals: &[&str] = match module {
        PureModule::Util => &MODULE_GLOBALS,
        PureModule::Events => &EVENTS_GLOBALS,
        PureModule::Assert => &ASSERT_GLOBALS,
        PureModule::Timers => &TIMERS_GLOBALS,
        PureModule::StringDecoder => &STRING_DECODER_GLOBALS,
    };
    let mut renamer = ModuleRenamer {
        through_global_object: globals
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
                .chain(EVENTS_PLACEHOLDERS.iter())
                .chain(ASSERT_PLACEHOLDERS.iter())
                .chain(TIMERS_PLACEHOLDERS.iter())
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

struct BuiltinRewriter {
    /// Names declared in each enclosing scope, innermost last.
    scopes: Vec<BTreeSet<String>>,
    modules: BTreeSet<PureModule>,
}

impl BuiltinRewriter {
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

    /// Recognize builtin requests only when `require` is the free name.
    fn builtin_require(
        &self,
        expression: &Expression,
    ) -> Option<(PureModule, Option<&'static str>)> {
        if self.scopes.iter().any(|scope| scope.contains("require")) {
            return None;
        }
        builtin_require_member(expression)
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

impl Walk for BuiltinRewriter {
    scoped_walk!();

    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        let mut names = BTreeSet::new();
        match statement {
            Statement::For(for_statement) => {
                if let Some(initializer) = &for_statement.init {
                    let initializer: &Statement = initializer;
                    lexical_names(std::slice::from_ref(initializer), &mut names);
                }
            }
            Statement::ForIn(for_statement) => {
                names.extend(
                    for_statement
                        .binding
                        .binding_names()
                        .into_iter()
                        .map(str::to_string),
                );
            }
            Statement::ForOf(for_statement) => {
                names.extend(
                    for_statement
                        .binding
                        .binding_names()
                        .into_iter()
                        .map(str::to_string),
                );
            }
            // A dynamic object environment can supply its own require.
            Statement::With(_) => {
                names.insert("require".to_string());
            }
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
        if let Some((kind, member)) = self.builtin_require(expression) {
            let module = Expression::Identifier(kind.binding().to_string());
            *expression = match member {
                None => module,
                Some(member) => Expression::Member {
                    object: Box::new(module),
                    property: Box::new(Expression::Identifier(member.to_string())),
                    computed: false,
                    span: None,
                },
            };
            self.modules.insert(kind);
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

    pub(super) fn free_names(expression: &mut Expression) -> BTreeSet<String> {
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
        let free = free_names(&mut parse_module_source(PureModule::Util).expect("parses"));
        assert_eq!(free, expected);
    }

    /// A global the program declares is read through `globalThis`; the
    /// others keep their names.
    #[test]
    fn declared_globals_are_read_through_the_global_object() {
        let names = ["TextEncoder".to_string(), "unrelated".to_string()]
            .into_iter()
            .collect();
        let free = free_names(&mut module_source(&names, PureModule::Util).expect("builds"));
        assert!(!free.contains("TextEncoder"), "{free:?}");
        assert!(
            free.contains("TextDecoder") && free.contains("globalThis"),
            "{free:?}"
        );
        assert!(free.contains("%UtilInspect"), "{free:?}");
    }
}

#[cfg(test)]
mod events_tests {
    use super::*;

    fn parse(source: &str, goal: ParseGoal) -> SyntaxTree {
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "events-rewrite.js".into(),
                    text: source.into(),
                },
                goal,
                &ParserOptions::default(),
            )
            .expect("test source parses")
    }

    #[test]
    fn only_literal_unshadowed_builtin_calls_are_materialized() {
        for source in [
            "function f(require) { return require('events'); }",
            "{ const require = f; require('events'); }",
            "try { throw f; } catch (require) { require('events'); }",
            "for (let require = f; test; update) require('events');",
            "for (const require of values) require('events');",
            "for (const require in values) require('events');",
            "const C = class require { method() { return require('events'); } };",
            "with (scope) { require('events'); }",
            "const name = 'events'; require(name);",
            "require('events/unknown');",
            "const value = require; value('events');",
        ] {
            let tree = parse(source, ParseGoal::Script);
            assert!(
                rewrite_util_requires(&tree).expect(source).is_none(),
                "{source}"
            );
        }
        let tree = parse(
            "import require from 'other'; require('events');",
            ParseGoal::Module,
        );
        assert!(
            rewrite_util_requires(&tree)
                .expect("import binding")
                .is_none()
        );
    }

    #[test]
    fn mixed_modules_have_one_private_declaration_each_and_rewrite_is_idempotent() {
        let tree = parse(
            "const E = require('events'); const other = require('node:events'); \
             function nested() { return require('events'); } \
             const util = require('util'); const types = require('util/types');",
            ParseGoal::Script,
        );
        let rewritten = rewrite_util_requires(&tree)
            .expect("rewrites")
            .expect("modules used");
        assert_eq!(rewritten.body.len(), tree.body.len() + 2);
        assert_eq!(
            rewritten
                .body
                .iter()
                .filter(|s| is_module_declaration(s))
                .count(),
            2
        );
        assert!(
            rewrite_util_requires(&rewritten)
                .expect("second pass")
                .is_none()
        );
    }

    #[test]
    fn event_intrinsics_are_builtin_capabilities_not_filesystem_authority() {
        for (_, intrinsic) in EVENTS_PLACEHOLDERS {
            assert!(
                intrinsic_capability(intrinsic)
                    .expect("intrinsic")
                    .starts_with("builtin:")
            );
        }
        assert_eq!(intrinsic_capability("__franken_events_once"), None);
        assert_eq!(intrinsic_capability("require"), None);
    }

    #[test]
    fn events_source_parses_with_every_used_global_shadowed() {
        let mut expected: BTreeSet<String> =
            EVENTS_GLOBALS.iter().map(|name| name.to_string()).collect();
        expected.extend(EVENTS_PLACEHOLDERS.iter().map(|(name, _)| name.to_string()));
        let free = super::tests::free_names(
            &mut parse_module_source(PureModule::Events).expect("events source parses"),
        );
        assert_eq!(free, expected, "all ambient names must be declared");
        let globals = EVENTS_GLOBALS.iter().map(|name| name.to_string()).collect();
        let protected = super::tests::free_names(
            &mut module_source(&globals, PureModule::Events).expect("protected module source"),
        );
        let mut expected: BTreeSet<String> = EVENTS_PLACEHOLDERS
            .iter()
            .map(|(_, name)| name.to_string())
            .collect();
        expected.insert("globalThis".to_string());
        assert_eq!(protected, expected);
    }
}

#[cfg(test)]
mod assert_tests {
    use super::*;

    fn parse(source: &str) -> SyntaxTree {
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "assert-rewrite.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("test source parses")
    }

    #[test]
    fn assert_dependency_is_initialized_before_all_aliases() {
        let tree = parse(
            "const a = require('assert'); const b = require('node:assert/strict'); \
             const u = require('util'); function f() { return require('assert/strict'); }",
        );
        let rewritten = rewrite_util_requires(&tree)
            .expect("rewrites")
            .expect("assert used");
        assert_eq!(rewritten.body.len(), tree.body.len() + 2);
        for (statement, expected) in rewritten
            .body
            .iter()
            .zip([MODULE_BINDING, ASSERT_MODULE_BINDING])
        {
            let Statement::VariableDeclaration(declaration) = statement else {
                panic!("expected private module declaration");
            };
            assert_eq!(
                declaration.declarations[0].pattern,
                BindingPattern::Identifier(expected.to_string())
            );
        }
        assert!(
            rewrite_util_requires(&rewritten)
                .expect("idempotent")
                .is_none()
        );
    }

    #[test]
    fn assert_requires_preserve_guest_bindings_and_authority_checks() {
        for source in [
            "function f(require) { return require('assert'); }",
            "{ let require = f; require('assert/strict'); }",
            "for (let require of values) require('node:assert');",
            "with (scope) require('assert');",
            "const name = 'assert'; require(name);",
            "require('assert/unknown');",
        ] {
            assert!(
                rewrite_util_requires(&parse(source))
                    .expect("rewrite")
                    .is_none(),
                "{source}"
            );
        }
        assert_eq!(intrinsic_capability("__franken_assert_util"), None);
        assert_eq!(intrinsic_capability(MODULE_BINDING), None);
    }

    #[test]
    fn assert_source_parses_and_protects_every_free_global() {
        let free = super::tests::free_names(
            &mut parse_module_source(PureModule::Assert).expect("shipped assert source parses"),
        );
        let mut expected: BTreeSet<String> =
            ASSERT_GLOBALS.iter().map(|name| name.to_string()).collect();
        expected.extend(
            [
                "__franken_assert_util",
                "__franken_util_type_tag",
                "arguments",
            ]
            .map(str::to_string),
        );
        assert_eq!(free, expected);
        let names = ASSERT_GLOBALS.iter().map(|name| name.to_string()).collect();
        let protected = super::tests::free_names(
            &mut module_source(&names, PureModule::Assert).expect("protected assert source"),
        );
        assert_eq!(
            protected,
            [
                MODULE_BINDING,
                TYPE_TAG_INTRINSIC,
                "globalThis",
                "arguments"
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        );
    }
}

#[cfg(test)]
mod timers_tests {
    use super::*;

    fn parse(source: &str) -> SyntaxTree {
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "timers-rewrite.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("source parses")
    }

    #[test]
    fn timer_aliases_share_one_private_module_and_do_not_schedule_at_load() {
        let tree = parse(
            "require('timers'); require('node:timers/promises'); require('timers/promises');",
        );
        let rewritten = rewrite_util_requires(&tree)
            .expect("rewrite")
            .expect("timer module");
        assert_eq!(rewritten.body.len(), tree.body.len() + 1);
        assert!(is_module_declaration(&rewritten.body[0]));
        assert!(
            rewrite_util_requires(&rewritten)
                .expect("idempotent")
                .is_none()
        );
    }

    #[test]
    fn timer_requires_preserve_source_bindings_and_nonliteral_loading() {
        for source in [
            "function f(require) { return require('timers'); }",
            "{ let require = f; require('timers/promises'); }",
            "for (let require of values) require('node:timers');",
            "with (scope) require('timers');",
            "const name = 'timers'; require(name);",
            "require('timers/unknown');",
        ] {
            assert!(
                rewrite_util_requires(&parse(source))
                    .expect("rewrite")
                    .is_none(),
                "{source}"
            );
        }
        assert_eq!(intrinsic_capability("__franken_timers_timeout"), None);
        for (_, intrinsic) in TIMERS_PLACEHOLDERS {
            let capability = format!("builtin:{}", &intrinsic[1..]);
            assert_eq!(intrinsic_capability(intrinsic), Some(capability.as_str()));
        }
    }

    #[test]
    fn timer_source_protects_every_realm_global_it_reads() {
        let free = super::tests::free_names(
            &mut parse_module_source(PureModule::Timers).expect("timer source parses"),
        );
        let mut expected: BTreeSet<String> =
            TIMERS_GLOBALS.iter().map(|name| name.to_string()).collect();
        expected.extend(TIMERS_PLACEHOLDERS.iter().map(|(name, _)| name.to_string()));
        expected.insert("arguments".to_string());
        assert_eq!(free, expected);
        let names = TIMERS_GLOBALS.iter().map(|name| name.to_string()).collect();
        let protected = super::tests::free_names(
            &mut module_source(&names, PureModule::Timers).expect("protected source"),
        );
        let mut expected: BTreeSet<String> = TIMERS_PLACEHOLDERS
            .iter()
            .map(|(_, name)| name.to_string())
            .collect();
        expected.extend(["globalThis", "arguments"].map(str::to_string));
        assert_eq!(protected, expected);
    }
}

#[cfg(test)]
mod string_decoder_tests {
    use super::*;

    fn parse(source: &str, goal: ParseGoal) -> SyntaxTree {
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "string-decoder-rewrite.js".into(),
                    text: source.into(),
                },
                goal,
                &ParserOptions::default(),
            )
            .expect("test source parses")
    }

    #[test]
    fn decoder_literals_share_one_private_module_without_loading_authority() {
        let tree = parse(
            "const a = require('string_decoder'); require('node:string_decoder'); \
             function nested() { return require('string_decoder'); }",
            ParseGoal::Script,
        );
        let rewritten = rewrite_util_requires(&tree)
            .expect("rewrite")
            .expect("decoder used");
        assert_eq!(rewritten.body.len(), tree.body.len() + 1);
        assert!(is_module_declaration(&rewritten.body[0]));
        assert!(
            rewrite_util_requires(&rewritten)
                .expect("idempotent")
                .is_none()
        );
    }

    #[test]
    fn decoder_requires_preserve_shadowing_and_nonliteral_loading() {
        for source in [
            "function f(require) { return require('string_decoder'); }",
            "{ let require = f; require('string_decoder'); }",
            "for (const require of values) require('node:string_decoder');",
            "with (scope) require('string_decoder');",
            "const name = 'string_decoder'; require(name);",
            "require('string_decoder/unknown');",
        ] {
            assert!(
                rewrite_util_requires(&parse(source, ParseGoal::Script))
                    .expect("rewrite")
                    .is_none(),
                "{source}"
            );
        }
        let tree = parse(
            "import require from 'other'; require('string_decoder');",
            ParseGoal::Module,
        );
        assert!(
            rewrite_util_requires(&tree)
                .expect("import shadow")
                .is_none()
        );
    }

    #[test]
    fn decoder_source_parses_and_protects_all_native_dependencies() {
        let free = super::tests::free_names(
            &mut parse_module_source(PureModule::StringDecoder).expect("shipped source parses"),
        );
        let names: BTreeSet<String> = STRING_DECODER_GLOBALS
            .iter()
            .map(|name| name.to_string())
            .collect();
        assert_eq!(free, names);
        let protected = super::tests::free_names(
            &mut module_source(&names, PureModule::StringDecoder).expect("protected decoder"),
        );
        assert_eq!(protected, ["globalThis".to_string()].into_iter().collect());
    }
}
