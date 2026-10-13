//! First-class filesystem facades over the existing native host-I/O boundary.
//!
//! Only free, literal core-module requires are rewritten. Creating the object
//! performs no I/O and confers no authority; every method invokes the ordinary
//! fs:read/fs:write HostCall under the calling interpreter's capability set.
//! Reserved intrinsic names cannot be spelled by guest source.

use std::collections::BTreeSet;

use super::super::LoweringPipelineError;
use super::super::with_statement::{
    FunctionBody, FunctionParts, Outcome, Search, Walk, lexical_names, var_names, walk_class,
    walk_expression, walk_function, walk_pattern, walk_statement, walk_switch_cases,
};
use super::{loop_head_names, scoped_walk};
use crate::ast::{
    BindingPattern, CatchClause, Expression, MethodDefinition, ParseGoal, SourceSpan, Statement,
    SwitchCase, SyntaxTree, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const MODULE_BINDING: &str = "%fs_module";
const SOURCE: &str = include_str!("fs_module.js");
const PLACEHOLDERS: [(&str, &str); 2] = [
    ("__franken_fs_read", "%FsRead"),
    ("__franken_fs_write", "%FsWrite"),
];
const GLOBALS: [&str; 11] = [
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
];

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
                initializer: Some(module_source(&names)?),
                span,
            }],
            span,
        }),
    );
    Ok(Some(rewritten))
}

/// Lower synchronous call-only uses at their original source sites. Inlining
/// the entire filesystem facade made these programs inherit the potential
/// flows of every unused method (bd-15w28). This uses the SAME native operation
/// table and protected intrinsics as that facade, not a different I/O backend.
///
/// Selection is whole-program: any observable module/function value, unknown
/// require, or source binding named require keeps the original object path.
/// In particular, never mix an inlined method with a mutable module object.
fn direct_fs_calls(tree: &SyntaxTree) -> Result<Option<SyntaxTree>, LoweringPipelineError> {
    let mut rewritten = tree.clone();
    let mut walker = DirectFsCalls {
        compatible: true,
        calls: 0,
    };
    walker.statements(&mut rewritten.body)?;
    Ok((walker.compatible && walker.calls != 0).then_some(rewritten))
}

struct DirectFsCalls {
    compatible: bool,
    calls: usize,
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
        walk_pattern(self, pattern)
    }

    fn function(&mut self, function: FunctionParts<'_>) -> Outcome {
        if function.own_name == Some("require") {
            self.compatible = false;
        }
        walk_function(self, function)
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
        if let Expression::Call { callee, arguments, .. } = expression
            && let Expression::Member { object, property, computed: false, .. } = callee.as_ref()
            && require_member(object) == Some(None)
            && let Some(method) = super::super::well_formed_static_name(property)
            && let Some(spec) = super::super::fs_sync_builtin_spec(method)
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
            arguments.insert(0, Expression::StringLiteral(
                format!("\0fsop:{}", spec.operation.as_str()).into(),
            ));
            **callee = Expression::Identifier(match spec.capability {
                "fs:read" => "%FsRead",
                "fs:write" => "%FsWrite",
                _ => return Err(LoweringPipelineError::InvariantViolation {
                    detail: "filesystem operation has no protected intrinsic",
                }),
            }.to_string());
            self.calls += 1;
            return Ok(());
        }
        if matches!(expression, Expression::Identifier(name) if name == "require") {
            // This includes escaping require, unclaimed/unknown methods,
            // callback/Promise APIs and bare module values. Discard ALL
            // tentative call-site rewrites if any such use is present.
            self.compatible = false;
        }
        walk_expression(self, expression)
    }
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
    fn one_observable_or_unsupported_use_keeps_the_complete_module_path() {
        for suffix in [
            "const fs = require('fs');",
            "const read = require('fs').readFileSync;",
            "require('fs').readFileSync = replacement;",
            "require('fs/promises').readFile('x');",
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
}
