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
//! constructor and EventsOnce hostcall (bd-305gi), and `vm` (bd-9vouw.303):
//! Node's shape, whose every code-running entry point refuses with an
//! EvalError when called, so a package that loads `vm` for an optional
//! feature loads (jsonpath-plus). `stream` (bd-305gi.1) is engine-owned
//! JavaScript too: Node's Readable / Writable / Duplex / Transform /
//! PassThrough state machines, finished and pipeline, over the events
//! module's EventEmitter, string_decoder and the process.nextTick queue. It
//! serves the `require('stream')` calls the stream facade cannot claim
//! (`class X extends Transform`, `stream.Readable`, Duplex, finished, a
//! `require` inside a function, async iteration, ...); a top-level
//! destructure whose every name and use the facade serves keeps the facade's
//! HostCall lowering. No filesystem/module-load
//! authority is introduced. The filesystem facade shares these hooks through
//! `fs_module`; its methods retain their native fs:read/fs:write checks.
//! Other specifiers and `require` as a value keep their existing authority checks.

use std::collections::{BTreeMap, BTreeSet};

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
const VM_MODULE_BINDING: &str = "%vm_module";
const STREAM_MODULE_BINDING: &str = "%stream_module";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PureModule {
    Util,
    Events,
    Assert,
    Timers,
    StringDecoder,
    Vm,
    // After Events and StringDecoder: its declaration reads theirs.
    Stream,
}

impl PureModule {
    fn binding(self) -> &'static str {
        match self {
            Self::Util => MODULE_BINDING,
            Self::Events => EVENTS_MODULE_BINDING,
            Self::Assert => ASSERT_MODULE_BINDING,
            Self::Timers => TIMERS_MODULE_BINDING,
            Self::StringDecoder => STRING_DECODER_MODULE_BINDING,
            Self::Vm => VM_MODULE_BINDING,
            Self::Stream => STREAM_MODULE_BINDING,
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
        "%StreamNextTick" => Some("builtin:ProcessNextTick"),
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
const STREAM_SOURCE: &str = include_str!("stream_module.js");

const TIMERS_PLACEHOLDERS: [(&str, &str); 3] = [
    ("__franken_timers_timeout", "%TimersPromisesSetTimeout"),
    ("__franken_timers_immediate", "%TimersPromisesSetImmediate"),
    ("__franken_timers_interval", "%TimersPromisesSetInterval"),
];

/// `vm`: Node's members, but the engine has no vm contexts, so every entry
/// point that would run code refuses when called, as `eval` does without the
/// runtime.eval grant. Loading the module runs nothing.
const VM_SOURCE: &str = r#"(function () {
  'use strict';
  function refuse() {
    throw new EvalError('code generation from strings is not permitted: the vm module has no contexts in this engine');
  }
  function Script() {
    refuse();
  }
  function isContext(object) {
    if (object === null || (typeof object !== 'object' && typeof object !== 'function')) {
      throw new TypeError('The "object" argument must be of type object');
    }
    return false;
  }
  return {
    Script: Script,
    createContext: refuse,
    isContext: isContext,
    runInContext: refuse,
    runInNewContext: refuse,
    runInThisContext: refuse,
    compileFunction: refuse,
    createScript: refuse
  };
})()"#;

// A private dependency, not an ambient HostCall or a public util property.
const ASSERT_PLACEHOLDERS: [(&str, &str); 1] = [("__franken_assert_util", MODULE_BINDING)];

const EVENTS_PLACEHOLDERS: [(&str, &str); 2] = [
    ("__franken_events_constructor", "%EventsConstructorRef"),
    ("__franken_events_once", "%EventsOnce"),
];

// The events and string_decoder modules the stream module builds on (each
// declared before it), and the process.nextTick queue.
const STREAM_PLACEHOLDERS: [(&str, &str); 3] = [
    ("__franken_stream_events", EVENTS_MODULE_BINDING),
    (
        "__franken_stream_string_decoder",
        STRING_DECODER_MODULE_BINDING,
    ),
    ("__franken_stream_next_tick", "%StreamNextTick"),
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
    } else if *specifier == "vm" || *specifier == "node:vm" {
        Some((PureModule::Vm, None))
    } else if *specifier == "stream" || *specifier == "node:stream" {
        Some((PureModule::Stream, None))
    } else if *specifier == "stream/promises" || *specifier == "node:stream/promises" {
        Some((PureModule::Stream, Some("promises")))
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

const VM_GLOBALS: [&str; 2] = ["EvalError", "TypeError"];

const STREAM_GLOBALS: [&str; 15] = [
    "AggregateError",
    "Array",
    "Buffer",
    "Error",
    "Function",
    "Math",
    "Number",
    "Object",
    "Promise",
    "RangeError",
    "Set",
    "String",
    "Symbol",
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
                    || name == STRING_DECODER_MODULE_BINDING || name == VM_MODULE_BINDING
                    || name == STREAM_MODULE_BINDING
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
    // The stream facade keeps the declarations it claims: the rewrite does
    // not see their initializers.
    let claimed = if root.contains("require") {
        BTreeSet::new()
    } else {
        facade_claimed_stream_declarators(&tree.body)
    };
    for (index, statement) in rewritten.body.iter_mut().enumerate() {
        let held = take_claimed_initializers(statement, index, &claimed);
        let outcome = rewriter.statement(statement);
        restore_claimed_initializers(statement, held);
        outcome?;
    }
    // Enum ordering initializes util before assert. Capturing its comparator
    // in the engine-owned prelude avoids guest replacement of public exports.
    if rewriter.modules.contains(&PureModule::Assert) {
        rewriter.modules.insert(PureModule::Util);
    }
    // And events and string_decoder before stream, which reads both.
    if rewriter.modules.contains(&PureModule::Stream) {
        rewriter.modules.insert(PureModule::Events);
        rewriter.modules.insert(PureModule::StringDecoder);
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

/// The top-level `const { ... } = require('stream')` declarators, as
/// (statement, declarator) indexes, that the stream facade claims: each
/// destructured name is one it serves and its own pre-scan confirms, and
/// every reference to each local is one of its forms. The facade confirms
/// `Readable` by a single supported use, so `Readable.from(x)` beside
/// `class X extends Readable` would bind it to nothing; counting every
/// reference leaves such a program to the module instead.
fn facade_claimed_stream_declarators(body: &[Statement]) -> BTreeSet<(usize, usize)> {
    let lookup = BTreeMap::new();
    let confirmed = [
        (
            "Readable",
            super::confirmed_stream_readable_destructured_requires(body, &lookup),
        ),
        (
            "Writable",
            super::confirmed_stream_writable_destructured_requires(body, &lookup),
        ),
        (
            "PassThrough",
            super::confirmed_stream_passthrough_destructured_requires(body, &lookup),
        ),
        (
            "Transform",
            super::confirmed_stream_transform_destructured_requires(body, &lookup),
        ),
        (
            "pipeline",
            super::confirmed_stream_pipeline_destructured_requires(body, &lookup),
        ),
        (
            "promises",
            super::confirmed_stream_promises_destructured_requires(body, &lookup),
        ),
    ];
    let mut claimed = BTreeSet::new();
    for (statement_index, statement) in body.iter().enumerate() {
        let Statement::VariableDeclaration(declaration) = statement else {
            continue;
        };
        if declaration.kind != VariableDeclarationKind::Const {
            continue;
        }
        for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
            let Some(initializer) = &declarator.initializer else {
                continue;
            };
            if !matches!(
                builtin_require_member(initializer),
                Some((PureModule::Stream, None))
            ) {
                continue;
            }
            let BindingPattern::ObjectPattern(properties) = &declarator.pattern else {
                continue;
            };
            let served = !properties.is_empty()
                && properties.iter().all(|property| {
                    let Some(export) = (!property.computed)
                        .then(|| super::well_formed_static_name(&property.key))
                        .flatten()
                    else {
                        return false;
                    };
                    let BindingPattern::Identifier(local) = &property.value else {
                        return false;
                    };
                    confirmed
                        .iter()
                        .any(|(name, locals)| *name == export && locals.contains(local))
                        && every_reference_is_a_facade_form(body, local, export)
                });
            if served {
                claimed.insert((statement_index, declarator_index));
            }
        }
    }
    claimed
}

/// Whether each reference to `local` in `body` (at any depth, shadowed or
/// not) is one of the facade's forms for `export`, and none is inside a
/// function declaration. A declaration is hoisted and lowered before the
/// `const` that switches the facade on, so a form inside one constructed the
/// elided binding: undefined (split2's `new Transform(options)`).
fn every_reference_is_a_facade_form(body: &[Statement], local: &str, export: &str) -> bool {
    let mut counter = FacadeFormCounter {
        local,
        export,
        references: 0,
        forms: 0,
        function_declaration_depth: 0,
        in_function_declaration: false,
    };
    let mut body = body.to_vec();
    if counter.statements(&mut body).is_err() {
        return false;
    }
    counter.forms > 0 && counter.forms == counter.references && !counter.in_function_declaration
}

struct FacadeFormCounter<'a> {
    local: &'a str,
    export: &'a str,
    references: usize,
    forms: usize,
    /// How many function declarations enclose the walk's position.
    function_declaration_depth: usize,
    /// Whether a reference or form appeared inside a function declaration.
    in_function_declaration: bool,
}

impl Walk for FacadeFormCounter<'_> {
    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        let declaration = matches!(statement, Statement::FunctionDeclaration(_));
        self.function_declaration_depth += usize::from(declaration);
        let outcome = walk_statement(self, statement);
        self.function_declaration_depth -= usize::from(declaration);
        outcome
    }

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if matches!(expression, Expression::Identifier(name) if name == self.local) {
            self.references += 1;
            self.in_function_declaration |= self.function_declaration_depth > 0;
            return Ok(());
        }
        let form = match self.export {
            "Readable" => super::is_stream_readable_usage(expression, self.local),
            "Writable" | "PassThrough" | "Transform" => {
                super::is_stream_constructor_use(expression, self.local)
            }
            "pipeline" => super::is_stream_pipeline_direct_call(expression, self.local),
            "promises" => super::is_stream_promises_pipeline_call(expression, self.local),
            _ => false,
        };
        if form {
            self.forms += 1;
        }
        walk_expression(self, expression)
    }
}

/// Take the initializers of `statement`'s claimed declarators out while the
/// rewrite walks it.
fn take_claimed_initializers(
    statement: &mut Statement,
    statement_index: usize,
    claimed: &BTreeSet<(usize, usize)>,
) -> Vec<(usize, Expression)> {
    let Statement::VariableDeclaration(declaration) = statement else {
        return Vec::new();
    };
    let mut held = Vec::new();
    for (declarator_index, declarator) in declaration.declarations.iter_mut().enumerate() {
        if claimed.contains(&(statement_index, declarator_index))
            && let Some(initializer) = declarator.initializer.take()
        {
            held.push((declarator_index, initializer));
        }
    }
    held
}

fn restore_claimed_initializers(statement: &mut Statement, held: Vec<(usize, Expression)>) {
    let Statement::VariableDeclaration(declaration) = statement else {
        return;
    };
    for (declarator_index, initializer) in held {
        if let Some(declarator) = declaration.declarations.get_mut(declarator_index) {
            declarator.initializer = Some(initializer);
        }
    }
}

fn parse_module_source(module: PureModule) -> Result<Expression, LoweringPipelineError> {
    let (label, source) = match module {
        PureModule::Util => ("franken:util", UTIL_SOURCE),
        PureModule::Events => ("franken:events", EVENTS_SOURCE),
        PureModule::Assert => ("franken:assert", ASSERT_SOURCE),
        PureModule::Timers => ("franken:timers", TIMERS_SOURCE),
        PureModule::StringDecoder => ("franken:string_decoder", STRING_DECODER_SOURCE),
        PureModule::Vm => ("franken:vm", VM_SOURCE),
        PureModule::Stream => ("franken:stream", STREAM_SOURCE),
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
        PureModule::Vm => &VM_GLOBALS,
        PureModule::Stream => &STREAM_GLOBALS,
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
                .chain(STREAM_PLACEHOLDERS.iter())
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

    /// VM_SOURCE reads only VM_GLOBALS (bd-9vouw.303), and with all of them
    /// declared by the program it reads them through `globalThis`: no other
    /// ambient name, no intrinsic, no HostCall.
    #[test]
    fn vm_source_reads_only_its_globals() {
        let expected: BTreeSet<String> = VM_GLOBALS.iter().map(|name| name.to_string()).collect();
        let free = free_names(&mut parse_module_source(PureModule::Vm).expect("parses"));
        assert_eq!(free, expected);
        let protected = free_names(&mut module_source(&expected, PureModule::Vm).expect("builds"));
        assert_eq!(protected, BTreeSet::from(["globalThis".to_string()]));
    }

    /// STREAM_SOURCE reads only STREAM_GLOBALS, its placeholders and
    /// `arguments` (bd-305gi.1); its next-tick intrinsic is the
    /// process.nextTick queue's HostCall.
    #[test]
    fn stream_source_reads_only_its_globals() {
        let mut expected: BTreeSet<String> =
            STREAM_GLOBALS.iter().map(|name| name.to_string()).collect();
        expected.extend(STREAM_PLACEHOLDERS.iter().map(|(name, _)| name.to_string()));
        expected.insert("arguments".to_string());
        let free = free_names(&mut parse_module_source(PureModule::Stream).expect("parses"));
        assert_eq!(free, expected);
        assert_eq!(
            intrinsic_capability("%StreamNextTick"),
            Some("builtin:ProcessNextTick")
        );
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

    /// A top-level destructure whose every name and use the stream facade
    /// serves keeps its `require('stream')` for the facade (bd-305gi.1).
    #[test]
    fn stream_facade_keeps_the_declarations_it_claims() {
        for source in [
            "const { Readable } = require('stream'); Readable.from(['a']);",
            "const { Writable, PassThrough: P } = require('stream'); new Writable({}); new P();",
            "const { pipeline, Transform } = require('stream'); pipeline(a, new Transform({}), done);",
        ] {
            let tree = parse(source, ParseGoal::Script);
            assert!(
                rewrite_util_requires(&tree).expect(source).is_none(),
                "{source}"
            );
        }
    }

    /// Every other `require('stream')` gets the module, declared after the
    /// events and string_decoder modules it reads; a second pass changes
    /// nothing (bd-305gi.1).
    #[test]
    fn unclaimed_stream_requires_get_the_module_after_its_dependencies() {
        for source in [
            "const stream = require('stream'); stream.Readable;",
            "const { Readable } = require('stream'); Readable.from(['a']); class X extends Readable {}",
            "const { Duplex } = require('node:stream'); new Duplex();",
            "let { Readable } = require('stream'); new Readable();",
            "const { Transform } = require('stream'); function f() { return new Transform({}); }",
            "function f() { return require('stream').Transform; }",
            "const { pipeline } = require('stream/promises');",
        ] {
            let tree = parse(source, ParseGoal::Script);
            let rewritten = rewrite_util_requires(&tree).expect(source).expect(source);
            let declared: Vec<&str> = rewritten
                .body
                .iter()
                .filter(|statement| is_module_declaration(statement))
                .filter_map(|statement| match statement {
                    Statement::VariableDeclaration(declaration) => {
                        match declaration.declarations.as_slice() {
                            [
                                VariableDeclarator {
                                    pattern: BindingPattern::Identifier(name),
                                    ..
                                },
                            ] => Some(name.as_str()),
                            _ => None,
                        }
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                declared,
                [
                    EVENTS_MODULE_BINDING,
                    STRING_DECODER_MODULE_BINDING,
                    STREAM_MODULE_BINDING
                ],
                "{source}"
            );
            assert!(
                rewrite_util_requires(&rewritten)
                    .expect("second pass")
                    .is_none(),
                "{source}"
            );
        }
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
