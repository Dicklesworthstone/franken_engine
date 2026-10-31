//! First-class filesystem facades over the existing native host-I/O boundary.
//!
//! Only free, literal core-module requires are rewritten. Creating the object
//! performs no I/O and confers no authority; every method invokes the ordinary
//! fs:read/fs:write HostCall under the calling interpreter's capability set.
//! Reserved intrinsic names cannot be spelled by guest source.

use std::collections::{BTreeMap, BTreeSet};

use super::super::LoweringPipelineError;
use super::super::with_statement::{
    FunctionBody, FunctionParts, Outcome, Search, Walk, lexical_names, var_names, walk_class,
    walk_expression, walk_function, walk_pattern, walk_statement, walk_switch_cases,
};
use super::{NativeModuleSource, loop_head_names, scoped_walk};
#[cfg(test)]
use crate::ast::ParseGoal;
use crate::ast::{
    BindingPattern, CatchClause, Expression, MethodDefinition, SourceSpan, Statement, SwitchCase,
    SyntaxTree, UnaryOperator, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
#[cfg(test)]
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

pub(super) const MODULE_BINDING: &str = "%fs_module";
// Compose callbacks, directory iteration and copying on one filesystem object.
// All adapters retain the same private host calls and admission boundary.
const SOURCE: &str = concat!(
    "(", include_str!("fs_callbacks.js"), ")(",
    "(", include_str!("fs_recursive_readdir.js"), ")(",
    "(", include_str!("fs_directory.js"), ")((",
    include_str!("fs_copy.js"), ")(", include_str!("fs_module.js"), "))))",
);
pub(super) const SOURCE_BYTES: usize = SOURCE.len();
// One immutable parser template shared by fs and fs/promises. Every program
// still receives a clone before renaming and dependency/loader rewriting.
static FILESYSTEM_SOURCE: NativeModuleSource = NativeModuleSource::new("franken:fs", SOURCE);
const PROMISE_READ_INTRINSIC: &str = "%FsReadPromise";
const PLACEHOLDERS: [(&str, &str); 2] = [
    ("__franken_fs_read", "%FsRead"),
    ("__franken_fs_write", "%FsWrite"),
];
const GLOBALS: [&str; 18] = [
    "Promise",
    "Reflect",
    "TypeError",
    "Buffer",
    "Error",
    "RangeError",
    "Array",
    "WeakMap",
    "Symbol",
    "ArrayBuffer",
    "AggregateError",
    "Object",
    "String",
    "Uint8Array",
    "DataView",
    "queueMicrotask",
    "URL",
    "Date",
];

pub(super) fn intrinsic_capability(name: &str) -> Option<&'static str> {
    match name {
        "%FsRead" => Some("fs:read"),
        "%FsWrite" => Some("fs:write"),
        PROMISE_READ_INTRINSIC => Some(crate::capability::FS_READ_PROMISE_CAPABILITY),
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
    };
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

pub(super) fn has_ambient_fs_require(tree: &SyntaxTree) -> Result<bool, LoweringPipelineError> {
    if !tree
        .body
        .iter()
        .any(|statement| SEARCH.in_statement(statement))
    {
        return Ok(false);
    }
    // Call-only uses are already converted to the exact protected native
    // operation; access constants are plain data. Only the
    // remaining first-class module-object path should surface the legacy raw
    // require boundary to static authority analysis.
    if direct_fs_calls(tree)?.is_some() {
        return Ok(false);
    }
    Ok(rewrite_fs_requires(tree)?.is_some())
}

pub(super) fn rewrite_fs_requires(
    tree: &SyntaxTree,
) -> Result<Option<SyntaxTree>, LoweringPipelineError> {
    rewrite_fs_requires_with_runtime_sources(tree, false)
}

pub(super) fn rewrite_fs_requires_with_runtime_sources(
    tree: &SyntaxTree,
    retain_runtime_sources: bool,
) -> Result<Option<SyntaxTree>, LoweringPipelineError> {
    if !tree
        .body
        .iter()
        .any(|statement| SEARCH.in_statement(statement))
    {
        return Ok(None);
    }
    if let Some(rewritten) = direct_fs_calls(tree)? {
        return Ok(Some(rewritten));
    }
    let mut names = BTreeSet::new();
    var_names(&tree.body, &mut names);
    lexical_names(&tree.body, &mut names);
    // Imports are module-scope bindings too. Besides keeping an imported
    // require out of the builtin path, this protects the facade's realm
    // helpers from imports named Buffer, Promise, WeakMap, and so on.
    for statement in &tree.body {
        if let Statement::Import(import) = statement {
            names.extend(import.clause.binding_names().into_iter().map(str::to_string));
        }
    }
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
                initializer: Some(module_source_with_runtime_sources(&names, retain_runtime_sources)?),
                span,
            }],
            span,
        }),
    );
    Ok(Some(rewritten))
}

/// Lower call-only uses and access constants at their source sites. Inlining
/// the entire filesystem facade made these programs inherit the potential
/// flows of every unused method (bd-15w28). This uses the SAME native operation
/// table and protected intrinsics as that facade, not a different I/O backend.
///
/// Selection is whole-program: any observable module/function value, unknown
/// require, or source binding named require keeps the original object path.
/// In particular, never mix an inlined method with a mutable module object.
fn direct_fs_calls(tree: &SyntaxTree) -> Result<Option<SyntaxTree>, LoweringPipelineError> {
    let mut rewritten = tree.clone();
    if !expand_call_only_aliases(&mut rewritten)? {
        return Ok(None);
    }
    let mut walker = DirectFsCalls {
        compatible: true,
        rewrites: 0,
        assignment_target: false,
        promise_read: false,
        promise_mutated: false,
        function_depth: 0,
    };
    walker.statements(&mut rewritten.body)?;
    if !walker.compatible || walker.rewrites == 0 {
        return Ok(None);
    }
    if walker.promise_read {
        if walker.promise_mutated {
            return Ok(None);
        }
        let mut names = BTreeSet::new();
        var_names(&tree.body, &mut names);
        lexical_names(&tree.body, &mut names);
        // The native Promise path must not bypass a constructor the guest
        // substitutes before the lazy filesystem module is materialized.
        if names.contains("Promise") {
            return Ok(None);
        }
    }
    Ok(Some(rewritten))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DirectFsModule {
    Sync,
    Promises,
}

fn direct_fs_module(expression: &Expression) -> Option<DirectFsModule> {
    match require_member(expression) {
        Some(None) => return Some(DirectFsModule::Sync),
        Some(Some("promises")) => return Some(DirectFsModule::Promises),
        _ => {}
    }
    if let Expression::Member {
        object,
        property,
        computed: false,
        ..
    } = expression
        && require_member(object) == Some(None)
        && super::super::well_formed_static_name(property) == Some("promises")
    {
        return Some(DirectFsModule::Promises);
    }
    None
}

#[derive(Clone)]
struct DirectFsAlias {
    module: DirectFsModule,
    method: Option<String>,
}

fn inline_fs_require(module: DirectFsModule) -> Expression {
    Expression::Call {
        callee: Box::new(Expression::Identifier("require".to_string())),
        arguments: vec![Expression::StringLiteral(
            match module {
                DirectFsModule::Sync => "fs",
                DirectFsModule::Promises => "fs/promises",
            }
            .into(),
        )],
        span: None,
    }
}

/// Expand call-only const namespaces and named destructures into
/// the inline form. DirectFsCalls still owns operation/arity checks and loader
/// hygiene. Keep declaration order and lexical initialization points; any
/// incompatible use discards the entire tentative tree, not just that call.
fn expand_call_only_aliases(tree: &mut SyntaxTree) -> Result<bool, LoweringPipelineError> {
    let mut aliases = BTreeMap::new();
    let mut declarations = BTreeMap::new();
    for (statement_index, statement) in tree.body.iter().enumerate() {
        let Statement::VariableDeclaration(declaration) = statement else {
            continue;
        };
        if declaration.kind != VariableDeclarationKind::Const {
            continue;
        }
        for (declarator_index, declarator) in declaration.declarations.iter().enumerate() {
            let Some(module) = declarator.initializer.as_ref().and_then(direct_fs_module) else {
                continue;
            };
            let bindings = match &declarator.pattern {
                BindingPattern::Identifier(name) => vec![(
                    name.clone(),
                    DirectFsAlias {
                        module,
                        method: None,
                    },
                )],
                BindingPattern::ObjectPattern(properties) if !properties.is_empty() => {
                    let mut bindings = Vec::new();
                    for property in properties {
                        let BindingPattern::Identifier(local) = &property.value else {
                            return Ok(false);
                        };
                        let Some(method) = super::super::well_formed_static_name(&property.key)
                        else {
                            return Ok(false);
                        };
                        if property.computed {
                            return Ok(false);
                        }
                        let alias = if module == DirectFsModule::Sync && method == "promises" {
                            DirectFsAlias {
                                module: DirectFsModule::Promises,
                                method: None,
                            }
                        } else {
                            let supported = match module {
                                DirectFsModule::Sync => {
                                    super::super::fs_sync_builtin_spec(method).is_some()
                                }
                                DirectFsModule::Promises => {
                                    super::super::fs_promises_method_spec(method).is_some()
                                }
                            };
                            if !supported {
                                return Ok(false);
                            }
                            DirectFsAlias {
                                module,
                                method: Some(method.to_string()),
                            }
                        };
                        bindings.push((local.clone(), alias));
                    }
                    bindings
                }
                _ => return Ok(false),
            };
            for (name, alias) in &bindings {
                if name == "require" || aliases.insert(name.clone(), alias.clone()).is_some() {
                    return Ok(false);
                }
            }
            declarations.insert((statement_index, declarator_index), bindings);
        }
    }
    if aliases.is_empty() {
        return Ok(true);
    }
    let mut walker = CallOnlyAliases {
        aliases,
        initialized: BTreeSet::new(),
        used: BTreeSet::new(),
        function_depth: 0,
        compatible: true,
    };
    // Only root declarations qualify. Source-order processing catches reads
    // before a const initializes, including earlier declarators in one statement.
    for (statement_index, statement) in tree.body.iter_mut().enumerate() {
        if let Statement::VariableDeclaration(declaration) = statement {
            let mut replacements = Vec::new();
            for (index, mut declarator) in
                std::mem::take(&mut declaration.declarations).into_iter().enumerate()
            {
                if let Some(bindings) = declarations.get(&(statement_index, index)) {
                    for (name, _) in bindings {
                        walker.initialized.insert(name.clone());
                        replacements.push(VariableDeclarator {
                            pattern: BindingPattern::Identifier(name.clone()),
                            initializer: Some(Expression::UndefinedLiteral),
                            span: declarator.span,
                        });
                    }
                } else {
                    walker.pattern(&mut declarator.pattern)?;
                    if let Some(initializer) = &mut declarator.initializer {
                        walker.expression(initializer)?;
                    }
                    replacements.push(declarator);
                }
            }
            declaration.declarations = replacements;
        } else {
            walker.statement(statement)?;
        }
    }
    // An unused binding is not evidence for changing a bare module load.
    Ok(walker.compatible && walker.used.len() == walker.aliases.len())
}

struct CallOnlyAliases {
    aliases: BTreeMap<String, DirectFsAlias>,
    initialized: BTreeSet<String>,
    used: BTreeSet<String>,
    function_depth: usize,
    compatible: bool,
}

impl Walk for CallOnlyAliases {
    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        // Export clauses name bindings without visiting Identifier expressions.
        if matches!(statement, Statement::Export(_) | Statement::Import(_) | Statement::With(_)) {
            self.compatible = false;
        }
        if let Statement::FunctionDeclaration(function) = statement
            && function.name.as_ref().is_some_and(|name| self.aliases.contains_key(name))
        {
            self.compatible = false;
        }
        walk_statement(self, statement)
    }

    fn pattern(&mut self, pattern: &mut BindingPattern) -> Outcome {
        if pattern.binding_names().iter().any(|name| self.aliases.contains_key(*name)) {
            self.compatible = false;
        }
        if let BindingPattern::ObjectPattern(properties) = pattern
            && properties.iter().any(|property| property.computed
                || super::super::well_formed_static_name(&property.key) == Some("constructor"))
        {
            self.compatible = false;
        }
        walk_pattern(self, pattern)
    }

    fn function(&mut self, function: FunctionParts<'_>) -> Outcome {
        if function.own_name.is_some_and(|name| self.aliases.contains_key(name)) {
            self.compatible = false;
        }
        // A hoisted/escaping closure can run before the const initializer.
        // Without an interprocedural proof, do not erase its binding read.
        self.function_depth += 1;
        let outcome = walk_function(self, function);
        self.function_depth -= 1;
        outcome
    }

    fn catch_clause(&mut self, clause: &mut CatchClause) -> Outcome {
        if clause.parameter.as_ref().is_some_and(|name| self.aliases.contains_key(name)) {
            self.compatible = false;
        }
        self.block(&mut clause.body.body)
    }

    fn class(
        &mut self,
        name: Option<&str>,
        super_class: Option<&mut Expression>,
        body: &mut [MethodDefinition],
    ) -> Outcome {
        if name.is_some_and(|name| self.aliases.contains_key(name)) {
            self.compatible = false;
        }
        walk_class(self, super_class, body)
    }

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        // Named environment reads still traverse the lowering's IFC source
        // rules. Other process/global/module surfaces can obtain another loader
        // or a dynamic-code entry point and must retain observable module values.
        if let Expression::Member { object, property, computed: false, .. } = expression
            && matches!(object.as_ref(), Expression::Identifier(name) if name == "process")
            && !self.aliases.contains_key("process")
            && super::super::well_formed_static_name(property) == Some("env")
        {
            return Ok(());
        }
        if let Expression::Member {
            object,
            computed: false,
            ..
        } = expression
            && let Expression::Member {
                object,
                property,
                computed: false,
                ..
            } = object.as_mut()
            && super::super::well_formed_static_name(property) == Some("constants")
            && let Expression::Identifier(local) = object.as_ref()
            && self
                .aliases
                .get(local)
                .is_some_and(|alias| alias.module == DirectFsModule::Sync && alias.method.is_none())
            && self.function_depth == 0
            && self.initialized.contains(local)
        {
            // Only expand the receiver here. DirectFsCalls recognizes the
            // supported constants and excludes assignment/delete targets;
            // unknown properties still discard the entire tentative rewrite.
            self.used.insert(local.clone());
            **object = inline_fs_require(DirectFsModule::Sync);
            return Ok(());
        }
        if let Expression::Call { callee, arguments, .. } = expression {
            let selected = match callee.as_ref() {
                Expression::Identifier(local) => self.aliases.get(local).and_then(|alias| {
                    alias
                        .method
                        .as_ref()
                        .map(|method| (local.clone(), alias.module, method.clone()))
                }),
                Expression::Member {
                    object,
                    property,
                    computed: false,
                    ..
                } => {
                    if let Expression::Identifier(local) = object.as_ref()
                        && let Some(alias) = self.aliases.get(local)
                        && alias.method.is_none()
                    {
                        super::super::well_formed_static_name(property)
                            .map(|method| (local.clone(), alias.module, method.to_string()))
                    } else if let Expression::Member {
                        object: namespace,
                        property: member,
                        computed: false,
                        ..
                    } = object.as_ref()
                        && let Expression::Identifier(local) = namespace.as_ref()
                        && self.aliases.get(local).is_some_and(|alias| {
                            alias.module == DirectFsModule::Sync && alias.method.is_none()
                        })
                        && super::super::well_formed_static_name(member) == Some("promises")
                    {
                        super::super::well_formed_static_name(property).map(|method| {
                            (local.clone(), DirectFsModule::Promises, method.to_string())
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some((local, module, method)) = selected
                && self.function_depth == 0
                && self.initialized.contains(&local)
            {
                for argument in arguments.iter_mut() {
                    self.expression(argument)?;
                }
                // DirectFsCalls receives the original arguments and call span;
                // there is only one native operation/discriminator emitter.
                **callee = Expression::Member {
                    object: Box::new(inline_fs_require(module)),
                    property: Box::new(Expression::Identifier(method)),
                    computed: false,
                    span: None,
                };
                self.used.insert(local);
                return Ok(());
            }
        }
        if matches!(expression, Expression::Identifier(name)
            if self.aliases.contains_key(name)
                || matches!(name.as_str(), "eval" | "Function" | "globalThis" | "global"
                    | "self" | "window" | "Reflect" | "Object" | "process" | "module" | "exports"))
            || matches!(expression, Expression::This | Expression::SloppyThis | Expression::Raw(_))
        {
            // Argument/value escape, mutation, typeof and dynamic evaluation
            // can all make the elided module/function value observable.
            self.compatible = false;
        }
        // Reflection may recover code generation without spelling Function.
        // Numeric literal keys cannot name constructor or invoke guest key
        // coercion; still walk their receivers and any getter bodies below.
        if let Expression::Member { property, computed, .. }
            | Expression::OptionalMember { property, computed, .. } = expression
            && ((*computed && !matches!(property.as_ref(), Expression::NumericLiteral(_)))
                || super::super::well_formed_static_name(property) == Some("constructor"))
        {
            self.compatible = false;
        }
        walk_expression(self, expression)
    }
}

struct DirectFsCalls {
    compatible: bool,
    rewrites: usize,
    assignment_target: bool,
    promise_read: bool,
    promise_mutated: bool,
    function_depth: usize,
}

impl Walk for DirectFsCalls {
    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        // Imports and dynamic object environments can supply a different
        // loader or expose a module alias. Keep their existing scoped rewrite.
        if matches!(statement, Statement::Import(_) | Statement::With(_)) {
            self.compatible = false;
        }
        if let Statement::FunctionDeclaration(function) = statement
            && function.name.as_deref() == Some("require")
        {
            self.compatible = false;
        }
        walk_statement(self, statement)
    }

    fn pattern(&mut self, pattern: &mut BindingPattern) -> Outcome {
        if pattern.binding_names().contains(&"require") {
            self.compatible = false;
        }
        if let BindingPattern::ObjectPattern(properties) = pattern
            && properties.iter().any(|property| {
                property.computed
                    || super::super::well_formed_static_name(&property.key) == Some("constructor")
            })
        {
            // A destructure can recover Function without ever spelling that
            // global, and generated code can observe or replace fs methods.
            self.compatible = false;
        }
        walk_pattern(self, pattern)
    }

    fn function(&mut self, function: FunctionParts<'_>) -> Outcome {
        if function.own_name == Some("require") {
            self.compatible = false;
        }
        self.function_depth += 1;
        let result = walk_function(self, function);
        self.function_depth -= 1;
        result
    }

    fn catch_clause(&mut self, clause: &mut CatchClause) -> Outcome {
        if clause.parameter.as_deref() == Some("require") {
            self.compatible = false;
        }
        self.block(&mut clause.body.body)
    }

    fn class(
        &mut self,
        name: Option<&str>,
        super_class: Option<&mut Expression>,
        body: &mut [MethodDefinition],
    ) -> Outcome {
        if name == Some("require") {
            self.compatible = false;
        }
        walk_class(self, super_class, body)
    }

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if let Expression::Assignment { left, right, .. } = expression {
            let previous = self.assignment_target;
            self.assignment_target = true;
            let outcome = self.expression(left);
            self.assignment_target = previous;
            outcome?;
            return self.expression(right);
        }
        if let Expression::Unary {
            operator: UnaryOperator::Delete | UnaryOperator::StrictDelete,
            argument,
        } = expression
        {
            let previous = self.assignment_target;
            self.assignment_target = true;
            let outcome = self.expression(argument);
            self.assignment_target = previous;
            return outcome;
        }
        if self.assignment_target
            && matches!(expression, Expression::Identifier(name) if name == "Promise")
        {
            // Native module factories are lazy. A direct native Promise read
            // must not skip a constructor changed before the module load.
            self.promise_mutated = true;
        }
        if let Expression::Member {
            object,
            property,
            computed,
            ..
        } = expression
            && let Some(value) = super::super::fs_constants_member_value(
                object,
                property,
                *computed,
                &BTreeMap::new(),
            )
        {
            if self.assignment_target {
                self.compatible = false;
            } else {
                *expression = Expression::NumericLiteral(value);
                self.rewrites += 1;
            }
            return Ok(());
        }
        if let Expression::Member {
            object,
            property,
            computed: false,
            ..
        } = expression
            && matches!(object.as_ref(), Expression::Identifier(name) if name == "process")
            && super::super::well_formed_static_name(property) == Some("env")
        {
            // Preserve ordinary named environment inputs and their existing
            // IFC rules. This read does not expose a second module loader.
            return Ok(());
        }
        if let Expression::Call {
            callee, arguments, ..
        } = expression
            && let Expression::Member {
                object,
                property,
                computed: false,
                ..
            } = callee.as_ref()
            && direct_fs_module(object) == Some(DirectFsModule::Promises)
            && super::super::well_formed_static_name(property) == Some("readFile")
            && matches!(
                arguments.as_slice(),
                [Expression::StringLiteral(_)]
                    | [
                        Expression::StringLiteral(_),
                        Expression::StringLiteral(_)
                            | Expression::UndefinedLiteral
                            | Expression::NullLiteral
                    ]
            )
        {
            // The current authority collector does not summarize arbitrary
            // deferred guest functions. Keep those calls on the full facade
            // until it can prove their invoked host effects, rather than
            // reporting a newly direct nested read as authority-free.
            if self.function_depth != 0 {
                self.compatible = false;
                return Ok(());
            }
            // Literal paths cannot be branded FileHandles, and a primitive
            // encoding cannot introduce option getters or lifecycle semantics.
            // Preserve the call's operands/span and its native I/O completion;
            // this is not Promise.resolve(a synchronous read).
            arguments.resize(2, Expression::UndefinedLiteral);
            arguments.insert(0, Expression::StringLiteral("\0fsop:read".into()));
            **callee = Expression::Identifier(PROMISE_READ_INTRINSIC.to_string());
            self.promise_read = true;
            self.rewrites += 1;
            return Ok(());
        }
        if let Expression::Call { callee, arguments, .. } = expression
            && let Expression::Member { object, property, computed: false, .. } = callee.as_ref()
            && require_member(object) == Some(None)
            && let Some(method) = super::super::well_formed_static_name(property)
            && let Some(spec) = super::super::fs_sync_builtin_spec(method)
            // Recursive options need the shared directory collector, not the
            // native single-directory effect. Dynamic options fail this proof.
            && (method != "readdirSync"
                || arguments.get(1).is_none_or(|options| matches!(options,
                    Expression::UndefinedLiteral | Expression::NullLiteral
                    | Expression::StringLiteral(_))))
            && arguments.len() >= spec.min_args
            && arguments.len() <= spec.max_args
            && !arguments.iter().any(|argument| matches!(argument, Expression::SpreadElement(_)))
        {
            for argument in arguments.iter_mut() {
                self.expression(argument)?;
            }
            // A wrapper forwards its complete formal-parameter list. Preserve
            // omitted option values and evaluate each source argument once, in
            // order. Extra/spread arguments stay on the ordinary call path.
            arguments.resize(spec.max_args, Expression::UndefinedLiteral);
            // Always distinguish the operation from the guest path, including
            // read/write: a filename must never become dispatch metadata.
            arguments.insert(
                0,
                Expression::StringLiteral(format!("\0fsop:{}", spec.operation.as_str()).into()),
            );
            **callee = Expression::Identifier(
                match spec.capability {
                    "fs:read" => "%FsRead",
                    "fs:write" => "%FsWrite",
                    _ => {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "filesystem operation has no protected intrinsic",
                        });
                    }
                }
                .to_string(),
            );
            self.rewrites += 1;
            return Ok(());
        }
        if let Expression::Call {
            callee, arguments, ..
        } = expression
            && matches!(callee.as_ref(), Expression::Identifier(name) if name == "require")
            && matches!(arguments.as_slice(), [Expression::StringLiteral(specifier)]
                if specifier.as_str().is_some_and(|specifier|
                    super::super::is_http_module_specifier(specifier)
                        || super::super::is_https_module_specifier(specifier)))
        {
            // These fixed networking facades do not load guest modules or
            // expose the filesystem namespace. Leave their require intact for
            // the ordinary HTTP/HTTPS recognizers and authority checks. A
            // source binding named require still invalidates the whole proof.
            return Ok(());
        }
        if matches!(expression, Expression::Identifier(name)
            if matches!(name.as_str(), "require" | "eval" | "Function" | "globalThis" | "global"
                | "self" | "window" | "Reflect" | "Object" | "process" | "module" | "exports"))
            || matches!(
                expression,
                Expression::This | Expression::SloppyThis | Expression::Raw(_)
            )
        {
            // This includes escaping require, unclaimed/unknown methods,
            // callback/unsupported Promise APIs, bare module values and alternate loaders.
            // An inline require needs the same whole-program proof as a const
            // alias: eval or another loader can replace a method between calls.
            // Discard ALL tentative call-site rewrites in that case.
            self.compatible = false;
        }
        if let Expression::Member {
            property, computed, ..
        }
        | Expression::OptionalMember {
            property, computed, ..
        } = expression
            && ((*computed && !matches!(property.as_ref(), Expression::NumericLiteral(_)))
                || super::super::well_formed_static_name(property) == Some("constructor"))
        {
            // Reflection may recover dynamic evaluation without a named
            // loader/global (for example, (() => {}).constructor(...)).
            // Literal numeric indexing cannot recover that property. Its
            // receiver remains subject to the ordinary escape/mutation walk.
            self.compatible = false;
        }
        walk_expression(self, expression)
    }
}

#[cfg(test)]
fn module_source(names: &BTreeSet<String>) -> Result<Expression, LoweringPipelineError> {
    module_source_with_runtime_sources(names, false)
}

fn module_source_with_runtime_sources(
    names: &BTreeSet<String>,
    retain_runtime_sources: bool,
) -> Result<Expression, LoweringPipelineError> {
    // Keep the filesystem diagnostic at its existing boundary. The shared
    // carrier stores only pristine syntax, never renamed host-I/O intrinsics.
    let parsed = if retain_runtime_sources {
        FILESYSTEM_SOURCE.runtime_expression()
    } else {
        FILESYSTEM_SOURCE.expression()
    };
    let mut expression = parsed.map_err(|_| {
        LoweringPipelineError::InvariantViolation {
            detail: "the engine's filesystem module source failed to parse",
        }
    })?;
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
    fn scoped(
        &mut self,
        names: BTreeSet<String>,
        walk: impl FnOnce(&mut Self) -> Outcome,
    ) -> Outcome {
        self.scopes.push(names);
        let result = walk(self);
        self.scopes.pop();
        result
    }
}

impl Walk for RequireRewriter {
    scoped_walk!();

    fn statement(&mut self, statement: &mut Statement) -> Outcome {
        if let Statement::With(with_statement) = statement {
            // The object expression runs OUTSIDE the new object environment.
            // Its own free require can still load the builtin; the body may
            // instead resolve require through an object getter/unscopables.
            self.expression(&mut with_statement.object)?;
            let names = std::iter::once("require".to_string()).collect();
            return self.scoped(names, |walker| walker.statement(&mut with_statement.body));
        }
        let mut names = BTreeSet::new();
        loop_head_names(statement, &mut names);
        self.scoped(names, |walker| walk_statement(walker, statement))
    }

    fn class(
        &mut self,
        name: Option<&str>,
        super_class: Option<&mut Expression>,
        body: &mut [MethodDefinition],
    ) -> Outcome {
        // A named class expression has a private name binding, including
        // while its heritage is evaluated. It is not an ambient require.
        let names = name.map(str::to_string).into_iter().collect();
        self.scoped(names, |walker| walk_class(walker, super_class, body))
    }

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
        parse_goal(source, ParseGoal::Script)
    }

    fn parse_goal(source: &str, goal: ParseGoal) -> SyntaxTree {
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "fs-rewrite-test.js".into(),
                    text: source.into(),
                },
                goal,
                &ParserOptions::default(),
            )
            .expect("test source parses")
    }

    #[test]
    fn directory_iteration_uses_the_shared_module_without_erasing_loader_bindings() {
        for source in [
            "const { opendirSync: open } = require('fs'); open('tree', {recursive: true});",
            "const { opendir } = require('node:fs/promises'); opendir('tree');",
            "const fs = require('fs'); const d = fs.opendirSync('tree'); d.readSync(); d.closeSync();",
        ] {
            let tree = parse(source);
            assert!(direct_fs_calls(&tree).unwrap().is_none());
            let rewritten = rewrite_fs_requires(&tree).unwrap().expect("directory module");
            assert_eq!(rewritten.body.iter().filter(|s| is_module_declaration(s)).count(), 1);
            assert!(rewrite_fs_requires(&rewritten).unwrap().is_none());
        }
        for source in [
            "function scan(require) { return require('fs').opendirSync('tree'); }",
            "const require = custom; require('fs/promises').opendir('tree');",
        ] {
            assert!(rewrite_fs_requires(&parse(source)).unwrap().is_none());
        }
        let names = GLOBALS.iter().map(|name| (*name).to_string()).collect();
        let mut expression = module_source(&names).expect("all directory helpers protected");
        assert_eq!(
            super::super::tests::free_names(&mut expression),
            BTreeSet::from(["globalThis".into(), "%FsRead".into(), "%FsWrite".into(), "require".into()])
        );
    }

    #[test]
    fn recursive_copy_uses_one_filesystem_module_not_a_direct_or_ambient_call() {
        for source in [
            "const { cpSync } = require('fs'); cpSync('src', 'dst', {recursive: true});",
            "const { cp: copy } = require('node:fs/promises'); copy('src', 'dst');",
            "const fs = require('fs'); fs.promises.cp('src', 'dst');",
        ] {
            let tree = parse(source);
            assert!(direct_fs_calls(&tree).unwrap().is_none());
            let rewritten = rewrite_fs_requires(&tree).unwrap().expect("filesystem module");
            assert_eq!(rewritten.body.iter().filter(|s| is_module_declaration(s)).count(), 1);
            assert!(rewrite_fs_requires(&rewritten).unwrap().is_none());
        }
        let names = GLOBALS.iter().map(|name| (*name).to_string()).collect();
        let mut expression = module_source(&names).expect("protected composite source");
        assert_eq!(
            super::super::tests::free_names(&mut expression),
            BTreeSet::from(["globalThis".into(), "%FsRead".into(), "%FsWrite".into(), "require".into()])
        );
    }

    #[test]
    fn native_module_source_parses_with_protected_globals() {
        let names = GLOBALS.iter().map(|name| (*name).to_string()).collect();
        module_source(&names).expect("the shipped source parses and renames");
    }

    #[test]
    fn callbacks_keep_the_shared_object_and_never_take_the_sync_fast_path() {
        for source in [
            "const fs = require('fs'); fs.open('x', 'r', callback);",
            "const { read, write, stat } = require('node:fs'); read(fd, buffer, callback);",
            "require('fs').cp('src', 'dst', {recursive: true}, callback);",
        ] {
            let tree = parse(source);
            assert!(direct_fs_calls(&tree).unwrap().is_none(), "{source}");
            let rewritten = rewrite_fs_requires(&tree).unwrap().expect("callback module");
            assert_eq!(rewritten.body.iter().filter(|s| is_module_declaration(s)).count(), 1);
            assert!(rewrite_fs_requires(&rewritten).unwrap().is_none());
        }
        let tree = parse("function f(require) { return require('fs').open('x', callback); }");
        assert!(rewrite_fs_requires(&tree).unwrap().is_none());
    }

    #[test]
    fn cached_filesystem_syntax_matches_an_independent_fresh_parse() {
        let fresh = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "franken:fs".into(),
                    text: SOURCE.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("fresh filesystem source parses");
        let [Statement::Expression(statement)] = fresh.body.as_slice() else {
            panic!("one filesystem module expression");
        };
        let cached = FILESYSTEM_SOURCE.expression().expect("cached filesystem source");
        assert_eq!(cached, statement.expression, "exact syntax and source spans");
        assert_eq!(cached.canonical_value(), statement.expression.canonical_value());
    }

    #[test]
    fn cached_filesystem_syntax_does_not_share_global_or_intrinsic_rewrites() {
        let pristine = FILESYSTEM_SOURCE.expression().expect("raw parser template");
        let names = BTreeSet::from(["Buffer".to_string(), "Promise".to_string()]);
        let mut protected = module_source(&names).expect("protected clone");
        let protected_names = super::super::tests::free_names(&mut protected);
        assert!(protected_names.contains("globalThis"));
        assert!(!protected_names.contains("Buffer"));
        assert!(!protected_names.contains("Promise"));

        let mut ordinary = module_source(&BTreeSet::new()).expect("unprotected clone");
        let ordinary_names = super::super::tests::free_names(&mut ordinary);
        assert!(ordinary_names.contains("Buffer"));
        assert!(ordinary_names.contains("Promise"));
        assert!(!ordinary_names.contains("globalThis"));
        for intrinsic in ["%FsRead", "%FsWrite"] {
            assert!(ordinary_names.contains(intrinsic));
            assert!(protected_names.contains(intrinsic));
        }
        let mut cached = FILESYSTEM_SOURCE.expression().expect("still pristine");
        assert_eq!(cached, pristine);
        let cached_names = super::super::tests::free_names(&mut cached);
        for (placeholder, intrinsic) in PLACEHOLDERS {
            assert!(cached_names.contains(placeholder));
            assert!(!cached_names.contains(intrinsic));
        }
    }

    #[test]
    fn runtime_filesystem_syntax_retains_sources_in_a_separate_template() {
        struct Sources(usize);
        impl Walk for Sources {
            fn expression(&mut self, expression: &mut Expression) -> Outcome {
                if matches!(
                    expression,
                    Expression::Function {
                        source_text: Some(_),
                        ..
                    }
                ) {
                    self.0 += 1;
                }
                walk_expression(self, expression)
            }
        }
        let names = BTreeSet::new();
        let mut legacy = module_source(&names).unwrap();
        let mut runtime = module_source_with_runtime_sources(&names, true).unwrap();
        let mut before = Sources(0);
        before.expression(&mut legacy).unwrap();
        assert_eq!(before.0, 0);
        let mut retained = Sources(0);
        retained.expression(&mut runtime).unwrap();
        assert!(
            retained.0 > 0,
            "native filesystem closures retain their defining source"
        );
        assert_eq!(legacy.canonical_value(), runtime.canonical_value());
        let mut after = Sources(0);
        after
            .expression(&mut module_source(&names).unwrap())
            .unwrap();
        assert_eq!(
            after.0, 0,
            "runtime metadata does not contaminate script facade syntax"
        );
    }

    #[test]
    fn filesystem_cache_survives_mixed_module_loader_and_dependency_rewrites() {
        let first = parse("const fs = require('fs'); const alias = fs; alias.promises;");
        let expected = super::super::rewrite_util_requires(&first)
            .expect("first full rewrite")
            .expect("module loader");
        let pristine = FILESYSTEM_SOURCE.expression().expect("cache before mixed rewrite");
        let mixed = parse(
            "const Buffer = replacement; const Promise = other; \
             const fs = require('node:fs/promises'); const stream = require('stream'); \
             const util = require('util'); console.log(fs, stream, util);",
        );
        super::super::rewrite_util_requires(&mixed)
            .expect("mixed module rewrite")
            .expect("native dependencies");
        let repeated = super::super::rewrite_util_requires(&first)
            .expect("repeat full rewrite")
            .expect("same module loader");
        assert_eq!(repeated, expected);
        assert_eq!(FILESYSTEM_SOURCE.expression().unwrap(), pristine);
        assert!(super::super::rewrite_util_requires(&repeated).unwrap().is_none());
    }

    #[test]
    fn warmed_filesystem_cache_does_not_introduce_loaders_on_direct_calls() {
        module_source(&GLOBALS.iter().map(|name| (*name).to_string()).collect())
            .expect("warm and protect one private clone");
        let tree = parse("require('fs').readFileSync('input', 'utf8');");
        let rewritten = rewrite_fs_requires(&tree).unwrap().expect("direct call");
        assert_eq!(rewritten.body.len(), 1);
        assert!(!is_module_declaration(&rewritten.body[0]));
        let Statement::Expression(statement) = &rewritten.body[0] else {
            panic!("direct call statement");
        };
        let Expression::Call { callee, .. } = &statement.expression else {
            panic!("direct call expression");
        };
        assert_eq!(callee.as_ref(), &Expression::Identifier("%FsRead".into()));
    }

    #[test]
    fn authority_probe_distinguishes_module_values_from_mediated_calls() {
        assert!(
            has_ambient_fs_require(&parse("const fs = require('fs'); console.log(fs);"))
                .expect("scope-aware probe")
        );
        for source in [
            "require('fs').readFileSync('input');",
            "const fs = require('node:fs'); fs.writeFileSync('output', 'bytes');",
            "function f(require) { return require('fs'); }",
            "const require = loader; require('fs');",
            "require(name);",
        ] {
            assert!(
                !has_ambient_fs_require(&parse(source)).expect("scope-aware probe"),
                "{source}"
            );
        }
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
            assert!(
                rewrite_fs_requires(&parse(source))
                    .expect("rewrite")
                    .is_none(),
                "{source}"
            );
        }
    }

    #[test]
    fn all_core_specifiers_share_one_program_module() {
        let tree = parse("const fs = require('fs'); require('node:fs'); require('fs/promises');");
        let rewritten = rewrite_fs_requires(&tree)
            .expect("rewrite")
            .expect("fs module");
        assert_eq!(rewritten.body.len(), tree.body.len() + 1);
        assert!(is_module_declaration(&rewritten.body[0]));
        assert!(
            rewrite_fs_requires(&rewritten)
                .expect("idempotent")
                .is_none()
        );
    }

    #[test]
    fn intrinsics_reuse_native_capabilities_without_exposing_source_placeholders() {
        assert_eq!(intrinsic_capability("%FsRead"), Some("fs:read"));
        assert_eq!(intrinsic_capability("%FsWrite"), Some("fs:write"));
        assert_eq!(
            intrinsic_capability("%FsReadPromise"),
            Some(crate::capability::FS_READ_PROMISE_CAPABILITY)
        );
        assert_eq!(intrinsic_capability("%FsReadPromiseExtra"), None);
        assert_eq!(intrinsic_capability("__franken_fs_read_promise"), None);
        assert_eq!(intrinsic_capability("__franken_fs_write"), None);
    }

    #[test]
    fn imported_require_is_never_replaced_by_a_filesystem_intrinsic() {
        for declaration in [
            "import require from './loader.js';",
            "import { require } from './loader.js';",
            "import { load as require } from './loader.js';",
            "import * as require from './loader.js';",
        ] {
            for specifier in ["fs", "node:fs", "fs/promises", "node:fs/promises"] {
                let source = format!("{declaration} require('{specifier}');");
                assert!(
                    rewrite_fs_requires(&parse_goal(&source, ParseGoal::Module))
                        .expect("import-aware rewrite")
                        .is_none(),
                    "{source}"
                );
            }
        }
        let tree = parse_goal(
            "import { require as load } from './loader.js'; require('fs');",
            ParseGoal::Module,
        );
        assert!(rewrite_fs_requires(&tree).expect("free require").is_some());
    }

    #[test]
    fn imported_helpers_are_read_from_the_realm_not_the_guest_import() {
        struct QualifiedGlobals(BTreeSet<String>);
        impl Walk for QualifiedGlobals {
            fn expression(&mut self, expression: &mut Expression) -> Outcome {
                if let Expression::Member { object, property, computed: false, .. } = expression
                    && matches!(object.as_ref(), Expression::Identifier(name) if name == "globalThis")
                    && let Expression::Identifier(name) = property.as_ref()
                {
                    self.0.insert(name.clone());
                }
                walk_expression(self, expression)
            }
        }
        let source = format!(
            "import {{ {} }} from './guest-helpers.js'; require('fs');",
            GLOBALS.join(", ")
        );
        let mut rewritten = rewrite_fs_requires(&parse_goal(&source, ParseGoal::Module))
            .expect("rewrite")
            .expect("free filesystem require");
        let mut reads = QualifiedGlobals(BTreeSet::new());
        reads.statement(&mut rewritten.body[0]).expect("walk module prelude");
        assert_eq!(reads.0, GLOBALS.iter().map(|name| (*name).to_string()).collect());
    }

    #[test]
    fn lexical_loop_heads_do_not_become_filesystem_modules() {
        for source in [
            "for (let require = loader; ready; step()) { require('fs'); }",
            "for (const require of loaders) { require('node:fs'); }",
            "for (let require in loaders) { require('fs/promises'); }",
            "for (const { require } of loaders) { require('node:fs/promises'); }",
            "for (let require of require('fs')) {}",
        ] {
            assert!(rewrite_fs_requires(&parse(source)).expect("loop scope").is_none(), "{source}");
        }
    }

    #[test]
    fn named_class_scope_includes_heritage_computed_keys_and_methods() {
        for source in [
            "const C = class require { method() { return require('fs'); } };",
            "const C = class require extends require('fs') {};",
            "const C = class require { [require('fs')]() {} };",
        ] {
            assert!(rewrite_fs_requires(&parse(source)).expect("class scope").is_none(), "{source}");
        }
    }

    #[test]
    fn dynamic_object_environment_retains_its_own_require() {
        for source in [
            "with (loader) { require('fs'); }",
            "with (loader) { function f() { return require('node:fs'); } }",
            "with (outer) { with (inner) { require('fs/promises'); } }",
        ] {
            assert!(rewrite_fs_requires(&parse(source)).expect("object scope").is_none(), "{source}");
        }
    }

    fn require_count(tree: &SyntaxTree) -> usize {
        struct Counter(usize);
        impl Walk for Counter {
            fn expression(&mut self, expression: &mut Expression) -> Outcome {
                self.0 += usize::from(require_member(expression).is_some());
                walk_expression(self, expression)
            }
        }
        let mut tree = tree.clone();
        let mut counter = Counter(0);
        counter.statements(&mut tree.body).expect("count requires");
        counter.0
    }

    #[test]
    fn scope_guards_do_not_leak_into_free_siblings() {
        for source in [
            "for (const require of loaders) { require('fs'); } require('fs');",
            "const C = class require { method() { return require('fs'); } }; require('fs');",
            "with (loader) { require('fs'); } require('fs');",
        ] {
            let tree = parse(source);
            assert_eq!(require_count(&tree), 2);
            let rewritten = rewrite_fs_requires(&tree).expect("rewrite").expect("free sibling");
            assert_eq!(rewritten.body.len(), tree.body.len() + 1);
            assert!(is_module_declaration(&rewritten.body[0]));
            assert_eq!(require_count(&rewritten), 1, "retain exactly the shadowed call: {source}");
            assert_eq!(require_count(&tree), 2, "the input AST is immutable");
            assert!(rewrite_fs_requires(&rewritten).expect("idempotent").is_none());
        }
    }

    #[test]
    fn with_object_expression_is_evaluated_before_the_new_scope() {
        let tree = parse("with (require('fs')) { require('node:fs'); }");
        let rewritten = rewrite_fs_requires(&tree).expect("rewrite").expect("object operand");
        assert_eq!(require_count(&rewritten), 1);
        let Statement::With(statement) = &rewritten.body[1] else { panic!("with statement"); };
        assert!(matches!(&statement.object, Expression::Identifier(name) if name == MODULE_BINDING));
        assert!(rewrite_fs_requires(&rewritten).expect("idempotent").is_none());
    }

    #[test]
    fn direct_sync_calls_use_protected_operations_without_a_module_prelude() {
        for (method, arguments, discriminator, intrinsic, arity) in [
            ("readFileSync", "'input'", "read", "%FsRead", 3),
            ("writeFileSync", "'output', 'bytes'", "write", "%FsWrite", 4),
            ("appendFileSync", "'output', 'bytes'", "append", "%FsWrite", 4),
            ("statSync", "'input'", "stat", "%FsRead", 3),
            ("readSync", "fd, buffer, 0, 4, null", "read_fd", "%FsRead", 6),
            ("writeSync", "fd, buffer, 0, 4, null", "write_fd", "%FsWrite", 6),
            ("closeSync", "fd", "close_fd", "%FsWrite", 2),
        ] {
            for specifier in ["fs", "node:fs"] {
                let source = format!("require('{specifier}').{method}({arguments});");
                let tree = parse(&source);
                let original = serde_json::to_value(&tree).unwrap();
                let rewritten = rewrite_fs_requires(&tree).unwrap().expect("direct call");
                assert_eq!(rewritten.body.len(), 1);
                let Statement::Expression(statement) = &rewritten.body[0] else { panic!("call"); };
                let Expression::Call { callee, arguments, span } = &statement.expression else { panic!("call"); };
                assert!(matches!(callee.as_ref(), Expression::Identifier(name) if name == intrinsic));
                assert_eq!(arguments.len(), arity);
                assert_eq!(arguments[0], Expression::StringLiteral(format!("\0fsop:{discriminator}").into()));
                let Statement::Expression(original_statement) = &tree.body[0] else { panic!("call"); };
                let Expression::Call { span: original_span, .. } = &original_statement.expression else { panic!("call"); };
                assert_eq!(span, original_span);
                assert_eq!(serde_json::to_value(&tree).unwrap(), original);
                assert!(rewrite_fs_requires(&rewritten).unwrap().is_none());
            }
        }
    }

    #[test]
    fn direct_promise_reads_use_the_protected_native_completion_intrinsic() {
        for (prefix, receiver) in [
            ("", "require('fs/promises').readFile"),
            ("", "require('node:fs/promises').readFile"),
            ("", "require('fs').promises.readFile"),
            ("", "require('node:fs').promises.readFile"),
            ("const io = require('fs/promises');", "io.readFile"),
            ("const io = require('node:fs/promises');", "io.readFile"),
            ("const {readFile: read} = require('fs/promises');", "read"),
            ("const io = require('fs').promises;", "io.readFile"),
            ("const {readFile: read} = require('fs').promises;", "read"),
            ("const {promises: io} = require('fs');", "io.readFile"),
            ("const io = require('fs');", "io.promises.readFile"),
        ] {
            for args in ["'input'", "'input', 'utf8'", "'input', null"] {
                let source = format!("{prefix} {receiver}({args}); {receiver}({args});");
                let tree = parse(&source);
                let rewritten = direct_fs_calls(&tree)
                    .unwrap()
                    .expect("proven Promise reads");
                assert_eq!(rewritten.body.len(), tree.body.len(), "{source}");
                assert!(
                    !rewritten.body.iter().any(is_module_declaration),
                    "{source}"
                );
                assert_eq!(require_count(&rewritten), 0, "no ambient loader: {source}");
                assert!(!has_ambient_fs_require(&tree).unwrap(), "{source}");
                for (before, after) in tree
                    .body
                    .iter()
                    .rev()
                    .take(2)
                    .zip(rewritten.body.iter().rev().take(2))
                {
                    let Statement::Expression(before) = before else {
                        panic!("source call");
                    };
                    let Statement::Expression(after) = after else {
                        panic!("rewritten call");
                    };
                    let Expression::Call {
                        arguments, span, ..
                    } = &before.expression
                    else {
                        panic!("source call");
                    };
                    let mut native_arguments = arguments.clone();
                    native_arguments.resize(2, Expression::UndefinedLiteral);
                    native_arguments.insert(0, Expression::StringLiteral("\0fsop:read".into()));
                    assert_eq!(
                        after.expression,
                        Expression::Call {
                            callee: Box::new(Expression::Identifier(
                                PROMISE_READ_INTRINSIC.to_string()
                            )),
                            arguments: native_arguments,
                            span: *span,
                        }
                    );
                }
                assert_eq!(tree, parse(&source), "input syntax remains immutable");
                assert!(rewrite_fs_requires(&rewritten).unwrap().is_none());
            }
        }
    }

    #[test]
    fn promise_reads_keep_handles_options_writes_and_observable_modules_on_the_facade() {
        for source in [
            "require('fs/promises').readFile(handle, 'utf8');",
            "require('fs/promises').readFile(path(), 'utf8');",
            "require('fs/promises').readFile('x', options);",
            "require('fs/promises').readFile('x', {encoding: 'utf8'});",
            "require('fs/promises').readFile('x', {signal});",
            "require('fs/promises').readFile(...args);",
            "require('fs/promises').readFile('x', 'utf8', extra());",
            "require('fs/promises').writeFile('x', 'bytes');",
            "const io = require('fs/promises'); io.readFile('x'); consume(io);",
            "const io = require('fs/promises'); io.readFile = replacement; io.readFile('x');",
            "const io = require('fs'); io.promises.readFile = replacement; io.promises.readFile('x');",
            "const io = require('fs'); io.promises = replacement; io.promises.readFile('x');",
            "const {readFile: read} = require('fs/promises'); consume(read); read('x');",
            "const {readFile: read, writeFile: write} = require('fs/promises'); read('x');",
            "const Promise = replacement; require('fs/promises').readFile('x');",
            "Promise = replacement; require('fs/promises').readFile('x');",
            "Promise.prototype.then = replacement; require('fs/promises').readFile('x');",
            "({Promise} = replacement); require('fs/promises').readFile('x');",
            "delete Promise; require('fs/promises').readFile('x');",
            "eval(\"require('fs/promises').readFile = replacement\"); require('fs/promises').readFile('x');",
        ] {
            let tree = parse(source);
            assert!(direct_fs_calls(&tree).unwrap().is_none(), "{source}");
            let rewritten = rewrite_fs_requires(&tree)
                .unwrap()
                .expect("full filesystem facade");
            assert!(is_module_declaration(&rewritten.body[0]), "{source}");
            assert_eq!(tree, parse(source));
        }
    }

    #[test]
    fn deferred_promise_reads_keep_the_full_facade_authority_boundary() {
        for source in [
            "function load(){ return require('fs/promises').readFile('x','utf8'); } load();",
            "async function load(){ return await require('fs/promises').readFile('x','utf8'); } load();",
            "function* load(){ yield require('fs/promises').readFile('x','utf8'); } load().next();",
            "const load = () => require('fs/promises').readFile('x','utf8'); load();",
            "const holder = { load(){ return require('fs/promises').readFile('x','utf8'); } }; holder.load();",
            "class Loader { load(){ return require('fs/promises').readFile('x','utf8'); } } new Loader().load();",
            "Promise.resolve().then(() => require('fs/promises').readFile('x','utf8'));",
            "require('fs/promises').readFile('x','utf8'); function later(){ return require('fs/promises').readFile('y','utf8'); }",
        ] {
            let tree = parse(source);
            assert!(direct_fs_calls(&tree).unwrap().is_none(), "{source}");
            assert!(has_ambient_fs_require(&tree).unwrap(), "{source}");
            let rewritten = rewrite_fs_requires(&tree)
                .unwrap()
                .expect("retained facade");
            assert_eq!(
                rewritten
                    .body
                    .iter()
                    .filter(|statement| is_module_declaration(statement))
                    .count(),
                1,
                "{source}"
            );
        }
    }

    #[test]
    fn promise_aliases_preserve_temporal_and_loader_scope_boundaries() {
        for source in [
            "io.readFile('x'); const io = require('fs/promises');",
            "const before = io.readFile('x'), io = require('fs/promises');",
            "run(); const io = require('fs/promises'); function run() { io.readFile('x'); }",
            "const io = require('fs/promises'); function run() { io.readFile('x'); } run();",
            "const io = require('fs/promises'); { const io = other; io.readFile('x'); }",
            "const {readFile: read} = require('fs/promises'); function run(read) { read('x'); } read('x');",
            "function run(require) { require('fs/promises').readFile('x'); }",
            "const require = loader; require('fs/promises').readFile('x');",
            "with (scope) { require('fs/promises').readFile('x'); }",
        ] {
            let tree = parse(source);
            assert!(direct_fs_calls(&tree).unwrap().is_none(), "{source}");
            assert_eq!(tree, parse(source));
        }
    }

    #[test]
    fn direct_promise_reads_share_the_sync_boundary_without_unused_write_authority() {
        let tree =
            parse("const fs = require('fs'); fs.readFileSync('a'); fs.promises.readFile('b');");
        let rewritten = direct_fs_calls(&tree)
            .unwrap()
            .expect("mixed call-only reads");
        assert_eq!(rewritten.body.len(), 3);
        assert!(!rewritten.body.iter().any(is_module_declaration));
        let Statement::Expression(sync) = &rewritten.body[1] else {
            panic!("sync read");
        };
        let Expression::Call {
            callee, arguments, ..
        } = &sync.expression
        else {
            panic!("read");
        };
        assert_eq!(callee.as_ref(), &Expression::Identifier("%FsRead".into()));
        assert_eq!(
            arguments[0],
            Expression::StringLiteral("\0fsop:read".into())
        );
        let Statement::Expression(promise) = &rewritten.body[2] else {
            panic!("Promise read");
        };
        let Expression::Call { callee, .. } = &promise.expression else {
            panic!("read");
        };
        assert_eq!(
            callee.as_ref(),
            &Expression::Identifier(PROMISE_READ_INTRINSIC.to_string())
        );
        assert!(
            direct_fs_calls(&parse(
                "Promise = replacement; require('fs').readFileSync('x');"
            ))
            .unwrap()
            .is_some(),
            "sync reads do not observe the Promise constructor"
        );
    }

    #[test]
    fn direct_calls_preserve_arguments_and_discriminator_like_guest_paths() {
        let tree = parse("require('fs').readFileSync(path(), encoding());");
        let rewritten = direct_fs_calls(&tree).unwrap().unwrap();
        let Statement::Expression(original) = &tree.body[0] else { panic!("call"); };
        let Statement::Expression(lowered) = &rewritten.body[0] else { panic!("call"); };
        let Expression::Call { arguments: before, .. } = &original.expression else { panic!("args"); };
        let Expression::Call { arguments: after, .. } = &lowered.expression else { panic!("args"); };
        assert_eq!(&after[1..], before.as_slice(), "each operand appears exactly once in order");
        let tree = parse("require('fs').readFileSync('\\0fsop:unlink');");
        let rewritten = direct_fs_calls(&tree).unwrap().unwrap();
        let Statement::Expression(statement) = &rewritten.body[0] else { panic!("call"); };
        let Expression::Call { arguments, .. } = &statement.expression else { panic!("args"); };
        assert_eq!(arguments[0], Expression::StringLiteral("\0fsop:read".into()));
        assert_eq!(arguments[1], Expression::StringLiteral("\0fsop:unlink".into()));
    }

    #[test]
    fn literal_network_facades_preserve_direct_fs_calls_without_claiming_their_loads() {
        for specifier in ["http", "node:http", "https", "node:https"] {
            let tree = parse(&format!(
                "const fs = require('fs'); const net = require('{specifier}'); \
                 const data = fs.readFileSync('config.txt', 'utf8'); net.get(data);"
            ));
            let original = serde_json::to_value(&tree).unwrap();
            let rewritten = direct_fs_calls(&tree)
                .unwrap()
                .expect("independent core facade");
            assert_eq!(rewritten.body.len(), tree.body.len());
            assert_eq!(require_count(&rewritten), 0, "all filesystem loads are mediated");
            assert_eq!(rewritten.body[1], tree.body[1]);
            assert!(!rewritten.body.iter().any(is_module_declaration));
            let Statement::VariableDeclaration(declaration) = &rewritten.body[2] else {
                panic!("file-read declaration");
            };
            let Some(Expression::Call {
                callee, arguments, ..
            }) = &declaration.declarations[0].initializer
            else {
                panic!("protected file read");
            };
            assert_eq!(callee.as_ref(), &Expression::Identifier("%FsRead".into()));
            assert_eq!(
                arguments[0],
                Expression::StringLiteral("\0fsop:read".into())
            );
            assert_eq!(serde_json::to_value(&tree).unwrap(), original);
            assert!(rewrite_fs_requires(&rewritten).unwrap().is_none());
        }
        for source in [
            "const fs = require('fs'); require('./guest.cjs'); fs.readFileSync('x');",
            "const fs = require('fs'); const http = require('http'); consume(fs); fs.readFileSync('x');",
            "function f(require) { const fs = require('fs'); require('http'); fs.readFileSync('x'); }",
            "const fs = require('fs'); require(networkModule); fs.readFileSync('x');",
        ] {
            assert!(
                direct_fs_calls(&parse(source)).unwrap().is_none(),
                "{source}"
            );
        }
    }

    #[test]
    fn one_observable_or_unsupported_use_keeps_the_complete_module_path() {
        for suffix in [
            "const fs = require('fs');",
            "const read = require('fs').readFileSync;",
            "require('fs').readFileSync = replacement;",
            "require('fs/promises').readFile(handle);",
            "require('fs').readFile('x', callback);",
            "require('fs').readFileSync(...args);",
            "require('fs').readFileSync('x', 'utf8', extra());",
            "require('fs')[method]('x');",
            "require(name);",
            "const loader = require;",
        ] {
            let tree = parse(&format!("require('fs').readFileSync('input'); {suffix}"));
            let original = serde_json::to_value(&tree).unwrap();
            assert!(direct_fs_calls(&tree).unwrap().is_none(), "{suffix}");
            let rewritten = rewrite_fs_requires(&tree).unwrap().unwrap();
            assert!(is_module_declaration(&rewritten.body[0]), "{suffix}");
            assert_eq!(serde_json::to_value(&tree).unwrap(), original);
        }
    }

    #[test]
    fn direct_calls_never_claim_a_shadowed_or_dynamic_loader() {
        for source in [
            "function f(require) { require('fs').readFileSync('x'); }",
            "function require() {} require('fs').readFileSync('x');",
            "const f = function require() { require('fs').readFileSync('x'); };",
            "for (const require of loaders) { require('fs').readFileSync('x'); }",
            "try {} catch (require) { require('fs').readFileSync('x'); }",
            "const C = class require { method() { require('fs').readFileSync('x'); } };",
            "with (object) { require('fs').readFileSync('x'); }",
        ] {
            assert!(direct_fs_calls(&parse(source)).unwrap().is_none(), "{source}");
        }
    }

    #[test]
    fn inline_calls_keep_module_values_when_dynamic_code_can_observe_them() {
        for observer in [
            "eval(\"require('fs').readFileSync = replacement\");",
            "const load = Function('return require')(); load('fs').readFileSync = replacement;",
            "globalThis.require('fs').readFileSync = replacement;",
            "global.require('fs').readFileSync = replacement;",
            "self.require('fs').readFileSync = replacement;",
            "window.require('fs').readFileSync = replacement;",
            "module.require('fs').readFileSync = replacement;",
            "process.getBuiltinModule('fs').readFileSync = replacement;",
            "this.require('fs').readFileSync = replacement;",
            "Reflect.get(globalThis, 'require')('fs').readFileSync = replacement;",
            "Object.getOwnPropertyDescriptor(globalThis, 'require').value('fs').readFileSync = replacement;",
            "const load = (() => {}).constructor('return require')(); load('fs').readFileSync = replacement;",
            "const {constructor: C} = function () {}; C('return require')()('fs').readFileSync = replacement;",
            "const key = 'con' + 'structor'; const C = (() => {})[key]; C('return require')()('fs').readFileSync = replacement;",
            "const key = 'constructor'; const {[key]: C} = function () {}; C('return require')()('fs').readFileSync = replacement;",
        ] {
            // No namespace alias: this used to skip CallOnlyAliases' loader
            // guards and erase the observable lookup after the mutation.
            let tree = parse(&format!(
                "require('fs').readFileSync('before'); {observer} \
                 require('node:fs').readFileSync('after');"
            ));
            let original = tree.clone();
            assert!(direct_fs_calls(&tree).unwrap().is_none(), "{observer}");
            let rewritten = rewrite_fs_requires(&tree).unwrap().expect("shared module");
            assert!(is_module_declaration(&rewritten.body[0]), "{observer}");
            assert_eq!(tree, original, "a failed proof must not mutate its input");
        }
    }

    #[test]
    fn dynamic_loader_guards_preserve_direct_named_environment_inputs() {
        for source in [
            "require('fs').readFileSync(process.env.CONFIG, 'utf8');",
            "const fs = require('fs'); fs.writeFileSync('out', process.env.SECRET);",
        ] {
            let tree = parse(source);
            let rewritten = direct_fs_calls(&tree)
                .unwrap()
                .expect("named environment input");
            assert!(
                !rewritten.body.iter().any(is_module_declaration),
                "{source}"
            );
            assert_eq!(require_count(&rewritten), 0);
            assert_eq!(tree, parse(source));
        }
    }

    #[test]
    fn numeric_result_indexing_keeps_inline_and_bound_reads_direct() {
        for (prefix, receiver) in [
            ("", "require('fs')"),
            ("const fs = require('node:fs');", "fs"),
        ] {
            for suffix in ["[0]", ".split('\\n')[0]", "?.[0]"] {
                let source =
                    format!("{prefix} {receiver}.readFileSync('input.txt', 'utf8'){suffix};");
                let tree = parse(&source);
                let rewritten = direct_fs_calls(&tree)
                    .unwrap()
                    .expect("literal numeric index");
                assert_eq!(require_count(&rewritten), 0, "{source}");
                assert!(
                    !rewritten.body.iter().any(is_module_declaration),
                    "{source}"
                );
                assert_eq!(tree, parse(&source), "tentative rewrite changed the input");
            }
            for observer in [
                "const key = 'constructor'; const dynamic = (() => {})[key];",
                "const dynamic = (() => {})['constructor'];",
                "const key = 0; value[key];",
            ] {
                let source =
                    format!("{prefix} {receiver}.readFileSync('input.txt', 'utf8')[0]; {observer}");
                assert!(
                    direct_fs_calls(&parse(&source)).unwrap().is_none(),
                    "{source}"
                );
            }
            let mutation = format!(
                "{prefix} {receiver}[0] = replacement; \
                 {receiver}.readFileSync('input.txt', 'utf8')[0];"
            );
            assert!(
                direct_fs_calls(&parse(&mutation)).unwrap().is_none(),
                "{mutation}"
            );
        }
    }

    #[test]
    fn access_constants_use_the_native_values_without_constructing_a_module() {
        for (name, value) in [("F_OK", 0), ("X_OK", 1), ("W_OK", 2), ("R_OK", 4)] {
            for specifier in ["fs", "node:fs"] {
                for (prefix, module) in [
                    (String::new(), format!("require('{specifier}')")),
                    (
                        format!("const io = require('{specifier}');"),
                        "io".to_string(),
                    ),
                ] {
                    let source = format!("{prefix} {module}.constants.{name};");
                    let tree = parse(&source);
                    let rewritten = direct_fs_calls(&tree).unwrap().expect("constant read");
                    assert!(
                        !rewritten.body.iter().any(is_module_declaration),
                        "{source}"
                    );
                    let Some(Statement::Expression(statement)) = rewritten.body.last() else {
                        panic!("constant expression");
                    };
                    assert_eq!(statement.expression, Expression::NumericLiteral(value));
                    assert!(!has_ambient_fs_require(&tree).unwrap(), "{source}");
                    assert_eq!(tree, parse(&source));
                    assert!(rewrite_fs_requires(&rewritten).unwrap().is_none());
                }
            }
        }
        let tree = parse("const fs = require('fs'); fs.accessSync('x', fs.constants.R_OK);");
        let rewritten = direct_fs_calls(&tree)
            .unwrap()
            .expect("access call and its mode");
        let Statement::Expression(statement) = &rewritten.body[1] else {
            panic!("access call");
        };
        let Expression::Call {
            callee, arguments, ..
        } = &statement.expression
        else {
            panic!("access call");
        };
        assert_eq!(callee.as_ref(), &Expression::Identifier("%FsRead".into()));
        assert_eq!(
            arguments,
            &vec![
                Expression::StringLiteral("\0fsop:access".into()),
                Expression::StringLiteral("x".into()),
                Expression::NumericLiteral(4),
            ]
        );
    }

    #[test]
    fn access_constant_mutation_escape_and_lexical_reads_keep_the_module_path() {
        for module in ["require('fs')", "fs"] {
            for tail in [
                format!("{module}.constants.R_OK = 8;"),
                format!("{module}.constants.R_OK += 1;"),
                format!("{module}.constants.R_OK++;"),
                format!("delete {module}.constants.R_OK;"),
                format!("({{mode: {module}.constants.R_OK}} = source);"),
                format!("{module}.constants = replacement;"),
                format!("consume({module}.constants);"),
                format!("{module}.constants.UNKNOWN;"),
                format!("{module}.constants[key];"),
            ] {
                let prefix = if module == "fs" {
                    "const fs = require('fs');"
                } else {
                    ""
                };
                let source = format!("{prefix} {module}.constants.R_OK; {tail}");
                let tree = parse(&source);
                assert!(direct_fs_calls(&tree).unwrap().is_none(), "{source}");
                assert!(is_module_declaration(
                    &rewrite_fs_requires(&tree).unwrap().unwrap().body[0]
                ));
                assert_eq!(tree, parse(&source));
            }
        }
        for source in [
            "fs.constants.R_OK; const fs = require('fs');",
            "const fs = require('fs'); function mode() { return fs.constants.R_OK; } mode();",
            "const fs = require('fs'); { const fs = other; fs.constants.R_OK; }",
            "'use strict'; const fs = require('fs'); delete fs.constants.R_OK;",
            "'use strict'; delete require('fs').constants.R_OK;",
        ] {
            assert!(
                direct_fs_calls(&parse(source)).unwrap().is_none(),
                "{source}"
            );
        }
    }

    #[test]
    fn const_namespaces_and_named_destructures_reuse_the_inline_operation_emitter() {
        for (method, args, intrinsic, discriminator) in [
            ("readFileSync", "'x', 'utf8'", "%FsRead", "read"),
            ("writeFileSync", "'x', 'bytes'", "%FsWrite", "write"),
            ("appendFileSync", "'x', 'bytes'", "%FsWrite", "append"),
            ("statSync", "'x'", "%FsRead", "stat"),
            ("readSync", "fd, buffer, 0, 4, null", "%FsRead", "read_fd"),
            ("closeSync", "fd", "%FsWrite", "close_fd"),
        ] {
            for specifier in ["fs", "node:fs"] {
                for (declaration, callee) in [
                    (format!("const io = require('{specifier}');"), format!("io.{method}")),
                    (format!("const {{ {method} }} = require('{specifier}');"), method.to_string()),
                    (format!("const {{ {method}: operation }} = require('{specifier}');"), "operation".to_string()),
                ] {
                    let tree = parse(&format!("{declaration}\n{callee}({args});"));
                    let before = serde_json::to_value(&tree).unwrap();
                    let rewritten = direct_fs_calls(&tree).unwrap().expect("call-only alias");
                    assert_eq!(rewritten.body.len(), 2);
                    assert!(!is_module_declaration(&rewritten.body[0]));
                    let Statement::Expression(statement) = &rewritten.body[1] else { panic!("call"); };
                    let Expression::Call { callee, arguments, span } = &statement.expression else { panic!("call"); };
                    assert_eq!(callee.as_ref(), &Expression::Identifier(intrinsic.into()));
                    assert_eq!(arguments[0], Expression::StringLiteral(format!("\0fsop:{discriminator}").into()));
                    let inline = direct_fs_calls(&parse(&format!("require('fs').{method}({args});")))
                        .unwrap().unwrap();
                    let Statement::Expression(inline) = &inline.body[0] else { panic!("inline call"); };
                    let Expression::Call { arguments: inline_args, .. } = &inline.expression else { panic!("inline args"); };
                    assert_eq!(arguments, inline_args, "one shared emitter");
                    let Statement::Expression(original) = &tree.body[1] else { panic!("original call"); };
                    let Expression::Call { span: original_span, .. } = &original.expression else { panic!("original span"); };
                    assert_eq!(span, original_span);
                    assert_eq!(serde_json::to_value(&tree).unwrap(), before);
                    assert!(rewrite_fs_requires(&rewritten).unwrap().is_none());
                }
            }
        }
    }

    #[test]
    fn alias_expansion_keeps_declarator_order_and_non_alias_effects() {
        let tree = parse("const a = first(), { readFileSync: read, statSync: stat } = require('fs'), z = last(); read('x'); stat('x');");
        let rewritten = direct_fs_calls(&tree).unwrap().expect("multi-declarator aliases");
        let Statement::VariableDeclaration(before) = &tree.body[0] else { panic!("declaration"); };
        let Statement::VariableDeclaration(after) = &rewritten.body[0] else { panic!("declaration"); };
        assert_eq!(after.kind, VariableDeclarationKind::Const);
        assert_eq!(after.span, before.span);
        assert_eq!(after.declarations[0], before.declarations[0]);
        assert_eq!(after.declarations[3], before.declarations[2]);
        assert_eq!(after.declarations[1].pattern, BindingPattern::Identifier("read".into()));
        assert_eq!(after.declarations[2].pattern, BindingPattern::Identifier("stat".into()));
        for declarator in &after.declarations[1..3] {
            assert_eq!(declarator.initializer, Some(Expression::UndefinedLiteral));
            assert_eq!(declarator.span, before.declarations[1].span);
        }
    }

    #[test]
    fn aliases_in_loops_and_branches_are_claimed_only_after_initialization() {
        for tail in [
            "if (ready) fs.readFileSync('x'); else fs.existsSync('x');",
            "for (let i = 0; i < 3; i += 1) { fs.readFileSync('x'); }",
            "try { fs.readFileSync('x'); } catch (error) { report(error); }",
        ] {
            assert!(direct_fs_calls(&parse(&format!("const fs = require('fs'); {tail}")))
                .unwrap().is_some(), "{tail}");
        }
        for source in [
            "fs.readFileSync('x'); const fs = require('fs');",
            "const before = fs.readFileSync('x'), fs = require('fs');",
            "run(); const fs = require('fs'); function run() { fs.readFileSync('x'); }",
            "const fs = require('fs'); const run = () => fs.readFileSync('x'); run();",
            "const fs = require('fs'); function f(x = fs.readFileSync('x')) {} f();",
        ] {
            assert!(direct_fs_calls(&parse(source)).unwrap().is_none(), "{source}");
        }
    }

    #[test]
    fn one_escaped_mutated_or_unsupported_alias_preserves_the_whole_original_module() {
        for tail in [
            "consume(fs);",
            "const copy = fs;",
            "typeof fs;",
            "fs === fs;",
            "const read = fs.readFileSync;",
            "fs.readFileSync = replacement;",
            "delete fs.readFileSync;",
            "fs.readFileSync.call(null, 'x');",
            "fs.readFileSync(...args);",
            "fs.readFileSync('x', 'utf8', extra());",
            "fs[method]('x');",
            "fs.readFile('x', callback);",
            "fs.promises.readFile(handle);",
            "const other = require('node:fs'); consume(other);",
            "eval('fs');", "globalThis.inspect();", "Reflect.get(fs, 'readFileSync');",
            "const C = (() => {}).constructor; C('return fs')();",
            "const {constructor: C} = function () {}; C('return fs')();",
            "const C = Object.getOwnPropertyDescriptor(() => {}, 'constructor');",
            "global.eval('fs');", "module.require('fs').readFileSync = replacement;",
            "process.getBuiltinModule('fs').readFileSync = replacement;",
        ] {
            let tree = parse(&format!("const fs = require('fs'); fs.readFileSync('x'); {tail}"));
            let before = serde_json::to_value(&tree).unwrap();
            assert!(direct_fs_calls(&tree).unwrap().is_none(), "{tail}");
            assert_eq!(serde_json::to_value(&tree).unwrap(), before);
        }
    }

    #[test]
    fn alias_shadowing_never_rewrites_a_different_binding() {
        for tail in [
            "{ let fs = custom; fs.readFileSync('x'); }",
            "for (const fs of loaders) fs.readFileSync('x');",
            "try {} catch (fs) { fs.readFileSync('x'); }",
            "const C = class fs { read() { return fs.readFileSync('x'); } };",
            "function f(fs) { return fs.readFileSync('x'); }",
            "with (scope) { fs.readFileSync('x'); }",
        ] {
            let source = format!("const fs = require('fs'); fs.readFileSync('x'); {tail}");
            assert!(direct_fs_calls(&parse(&source)).unwrap().is_none(), "{tail}");
        }
        let tree = parse_goal("const fs = require('fs'); fs.readFileSync('x'); export { fs };", ParseGoal::Module);
        assert!(direct_fs_calls(&tree).unwrap().is_none());
    }

    #[test]
    fn process_named_aliases_keep_property_observations_on_the_object_path() {
        for source in [
            "const process = require('fs'); process.readFileSync('x'); process.env;",
            "const {readFileSync: process} = require('fs'); process('x'); process.env;",
        ] {
            // This is an alias property read, not the ambient environment
            // source. Eliding the declaration would change it into a throw.
            assert!(direct_fs_calls(&parse(source)).unwrap().is_none(), "{source}");
        }
    }

    #[test]
    fn partial_destructures_and_unused_aliases_are_not_elided() {
        for source in [
            "const fs = require('fs');",
            "const {readFileSync: read, statSync: stat} = require('fs'); read('x');",
            "const {readFileSync: read, promises} = require('fs'); read('x');",
            "const {readFileSync: read = fallback} = require('fs'); read('x');",
            "const {['readFileSync']: read} = require('fs'); read('x');",
            "const {readFileSync: read, ...rest} = require('fs'); read('x');",
            "const {readFile} = require('fs'); readFile('x', callback);",
            "const {readFile} = require('fs/promises'); readFile(handle);",
            "let fs = require('fs'); fs.readFileSync('x');",
            "const fs = require('fs'); fs.readFileSync('x'); const require = custom;",
        ] {
            assert!(direct_fs_calls(&parse(source)).unwrap().is_none(), "{source}");
        }
    }
    #[test]
    fn recursive_readdir_and_dynamic_options_never_bypass_the_directory_collector() {
        for source in [
            "require('fs').readdirSync('tree', {recursive: true});",
            "const fs = require('fs'); fs.readdirSync('tree', options);",
            "const {readdirSync: scan} = require('fs'); scan('tree', {recursive: true});",
            "require('fs').readdirSync('tree'); require('fs').readdirSync('tree', options);",
        ] {
            let tree = parse(source);
            assert!(direct_fs_calls(&tree).unwrap().is_none(), "{source}");
            let rewritten = rewrite_fs_requires(&tree).unwrap().expect("directory collector");
            assert_eq!(rewritten.body.iter().filter(|s| is_module_declaration(s)).count(), 1);
            assert!(rewrite_fs_requires(&rewritten).unwrap().is_none());
            assert_eq!(tree, parse(source));
        }
        for source in [
            "require('fs').readdirSync('tree');",
            "require('fs').readdirSync('tree', 'utf8');",
            "const {readdirSync: scan} = require('fs'); scan('tree', null);",
        ] {
            let rewritten = direct_fs_calls(&parse(source)).unwrap().expect("proven shallow");
            assert!(!rewritten.body.iter().any(is_module_declaration), "{source}");
        }
        let tree = parse("function f(require) { return require('fs').readdirSync('tree', {recursive:true}); }");
        assert!(rewrite_fs_requires(&tree).unwrap().is_none());
    }
}
