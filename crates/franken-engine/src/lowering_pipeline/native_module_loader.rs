//! First-use initialization for engine-owned builtin modules.
//!
//! Both the filesystem and pure-module rewriters use this cache. A prelude
//! creates only the private loader; the actual module expression runs at the
//! original require site, and successful exports retain their identity.

use std::collections::BTreeSet;

use super::super::with_statement::{Outcome, Walk, walk_expression};
use super::{LoweringPipelineError, NativeModuleSource};
use crate::ast::{
    BindingPattern, Expression, SourceSpan, Statement, SyntaxTree,
    VariableDeclarationKind,
};
#[cfg(test)]
use crate::ast::ParseGoal;
#[cfg(test)]
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

#[path = "stream_web_bridge.rs"]
mod stream_web_bridge;

const SOURCE: &str = include_str!("native_module_loader.js");
// One immutable template for every builtin wrapper, including bridge-private
// dependencies. Cache syntax BEFORE inserting a program's initializer; each
// request still receives private syntax and creates private execution state.
static LOADER_SOURCE: NativeModuleSource =
    NativeModuleSource::new("franken:native-module-loader", SOURCE);
const INITIALIZER: &str = "__franken_native_module_initializer";

fn invalid() -> LoweringPipelineError {
    LoweringPipelineError::InvariantViolation {
        detail: "the engine's native module loader template is invalid",
    }
}

/// Finalize the existing fs/pure-module rewrite in one pass. Collect only
/// declarations the engine itself recognizes, convert their value references
/// (including private dependencies) to loads, then defer their initializers.
/// Do not run the reference walk over the newly generated loaders: their own
/// bindings are callable caches, not module values. No guest spelling can
/// collide with these reserved names.
pub(super) fn defer_modules(tree: &mut SyntaxTree) -> Outcome {
    let mut bindings = BTreeSet::new();
    let mut declarations = Vec::new();
    for (index, statement) in tree.body.iter().enumerate() {
        if !super::is_module_declaration(statement) {
            continue;
        }
        let Statement::VariableDeclaration(declaration) = statement else {
            return Err(invalid());
        };
        let [declarator] = declaration.declarations.as_slice() else {
            return Err(invalid());
        };
        let BindingPattern::Identifier(binding) = &declarator.pattern else {
            return Err(invalid());
        };
        if declaration.kind != VariableDeclarationKind::Const
            || declarator.initializer.is_none()
            || !bindings.insert(binding.clone())
        {
            return Err(invalid());
        }
        declarations.push(index);
    }
    if declarations.is_empty() {
        // Direct native calls introduce no module object or loader overhead.
        return Ok(());
    }
    stream_web_bridge::compose(tree, &bindings)?;
    ModuleReferences(&bindings).statements(&mut tree.body)?;
    for index in declarations {
        let Statement::VariableDeclaration(declaration) = &mut tree.body[index] else {
            return Err(invalid());
        };
        let initializer = declaration.declarations[0].initializer.take().ok_or_else(invalid)?;
        declaration.declarations[0].initializer = Some(deferred(initializer)?);
    }
    Ok(())
}

struct ModuleReferences<'a>(&'a BTreeSet<String>);

impl Walk for ModuleReferences<'_> {
    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if let Expression::Identifier(binding) = expression
            && self.0.contains(binding.as_str())
        {
            *expression = reference(binding, None);
            return Ok(());
        }
        walk_expression(self, expression)
    }
}

/// Embed the original initializer once, in the loader's deferred thunk. Do
/// not stringify the expression: reserved names, spans and intrinsic identity
/// must survive the transform. The source template is never guest-controlled.
pub(super) fn deferred(initializer: Expression) -> Result<Expression, LoweringPipelineError> {
    let mut expression = LOADER_SOURCE.expression().map_err(|_| invalid())?;
    let mut replacement = InitializerReplacement(Some(initializer));
    replacement.expression(&mut expression)?;
    if replacement.0.is_some() {
        return Err(invalid());
    }
    Ok(expression)
}

struct InitializerReplacement(Option<Expression>);

impl Walk for InitializerReplacement {
    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if matches!(expression, Expression::Identifier(name) if name == INITIALIZER) {
            *expression = self.0.take().ok_or_else(invalid)?;
            // The supplied AST is opaque here: only the engine template is
            // rewritten, even if a nested expression spells the placeholder.
            return Ok(());
        }
        walk_expression(self, expression)
    }
}

/// Read a private cached module at this execution site. Repeated aliases and
/// submodules all call the same loader; this creates no ambient require path.
pub(super) fn reference(binding: &str, span: Option<SourceSpan>) -> Expression {
    Expression::Call {
        callee: Box::new(Expression::Identifier(binding.to_string())),
        arguments: Vec::new(),
        span,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deferred_initializer_is_outside_the_cache_scope_and_appears_once() {
        let initializer = Expression::Call {
            callee: Box::new(Expression::Identifier("%NativeModuleProbe".into())),
            arguments: vec![Expression::StringLiteral("exact payload".into())],
            span: Some(SourceSpan::new(10, 20, 2, 1, 2, 11)),
        };
        let deferred = deferred(initializer.clone()).expect("template parses");
        let Expression::Call { callee, arguments, .. } = &deferred else {
            panic!("loader construction is a call");
        };
        // The initializer thunk is evaluated as the call's argument, not
        // defined inside its callee. Cache locals cannot capture its names.
        assert_eq!(arguments.len(), 1);
        struct Occurrences<'a> {
            expected: &'a Expression,
            count: usize,
        }
        impl Walk for Occurrences<'_> {
            fn expression(&mut self, expression: &mut Expression) -> Outcome {
                if &*expression == self.expected {
                    self.count += 1;
                }
                walk_expression(self, expression)
            }
        }
        let mut in_cache = Occurrences { expected: &initializer, count: 0 };
        in_cache.expression(&mut callee.as_ref().clone()).unwrap();
        assert_eq!(in_cache.count, 0);
        let mut in_thunk = Occurrences { expected: &initializer, count: 0 };
        in_thunk.expression(&mut arguments[0].clone()).unwrap();
        assert_eq!(in_thunk.count, 1);
    }

    #[test]
    fn replacing_the_template_never_rewrites_the_supplied_expression() {
        let initializer = Expression::Identifier(INITIALIZER.into());
        deferred(initializer).expect("replacement is opaque, not recursively substituted");
    }

    #[test]
    fn module_reference_retains_the_original_call_span_and_has_no_arguments() {
        let span = Some(SourceSpan::new(4, 18, 1, 5, 1, 19));
        assert_eq!(
            reference("%fs_module", span),
            Expression::Call {
                callee: Box::new(Expression::Identifier("%fs_module".into())),
                arguments: Vec::new(),
                span,
            }
        );
    }
}

#[cfg(test)]
mod rewrite_tests {
    use super::*;

    fn parse(source: &str) -> SyntaxTree {
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource { label: "deferred-module-test.js".into(), text: source.into() },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("test source parses")
    }

    fn initializer(statement: &Statement) -> &Expression {
        let Statement::VariableDeclaration(declaration) = statement else {
            panic!("expected a module or guest declaration");
        };
        declaration.declarations[0].initializer.as_ref().expect("initializer")
    }

    fn assert_loader_call(expression: &Expression, binding: &str) {
        let Expression::Call { callee, arguments, .. } = expression else {
            panic!("a require must invoke the loader at its execution site");
        };
        assert_eq!(callee.as_ref(), &Expression::Identifier(binding.into()));
        assert!(arguments.is_empty());
    }

    #[test]
    fn aliases_and_submodules_invoke_one_cache_at_the_original_sites() {
        let original = parse(
            "const first = require('util'); const second = require('node:util'); \
             const types = require('util/types');",
        );
        let rewritten = super::super::rewrite_util_requires(&original)
            .expect("rewrite").expect("module requested");
        assert_eq!(rewritten.body.len(), original.body.len() + 1);
        assert_loader_call(initializer(&rewritten.body[1]), "%util_module");
        assert_loader_call(initializer(&rewritten.body[2]), "%util_module");
        let Expression::Member { object, property, computed, .. } =
            initializer(&rewritten.body[3])
        else {
            panic!("types is a member of the cached module");
        };
        assert_loader_call(object, "%util_module");
        assert_eq!(property.as_ref(), &Expression::Identifier("types".into()));
        assert!(!computed);
        assert!(super::super::rewrite_util_requires(&rewritten).unwrap().is_none());
    }

    #[test]
    fn all_module_preludes_construct_loaders_instead_of_module_objects() {
        for specifier in [
            "util", "events", "assert", "timers", "string_decoder", "vm",
            "buffer", "querystring", "stream", "stream/consumers", "fs", "fs/promises",
        ] {
            let original = parse(&format!(
                "function unused() {{ return require('{specifier}'); }}"
            ));
            let rewritten = super::super::rewrite_util_requires(&original)
                .expect("rewrite").expect("deferred module");
            let mut declarations = 0;
            for statement in &rewritten.body {
                let Statement::VariableDeclaration(declaration) = statement else { continue; };
                let BindingPattern::Identifier(name) = &declaration.declarations[0].pattern else {
                    continue;
                };
                if !name.starts_with('%') { continue; }
                declarations += 1;
                assert!(super::super::is_module_declaration(statement), "classify {name}");
                let Expression::Call { arguments, .. } = initializer(statement) else {
                    panic!("loader construction for {specifier}");
                };
                // The template's one argument is the deferred initializer.
                // Eager module IIFEs have no such initializer argument.
                assert_eq!(arguments.len(), 1, "defer {name}");
            }
            assert!(declarations > 0, "{specifier}");
            assert!(super::super::rewrite_util_requires(&rewritten).unwrap().is_none());
        }
    }

    #[test]
    fn programs_without_native_modules_have_no_loader_prelude() {
        for source in [
            "console.log(42);",
            "function optional(require) { return require('fs'); }",
            "const dynamic = name; require(dynamic);",
        ] {
            assert!(
                super::super::rewrite_util_requires(&parse(source)).unwrap().is_none(),
                "{source}"
            );
        }
    }

    #[test]
    fn filesystem_only_early_return_uses_the_same_loader_pass() {
        for source in [
            "const fs = require('fs'); console.log(fs);",
            "const promises = require('fs/promises'); console.log(promises);",
        ] {
            let rewritten = super::super::rewrite_util_requires(&parse(source))
                .expect("rewrite").expect("filesystem module");
            let guest = rewritten.body.iter().find(|statement| {
                matches!(statement, Statement::VariableDeclaration(declaration)
                    if matches!(&declaration.declarations[0].pattern,
                        BindingPattern::Identifier(name) if name == "fs" || name == "promises"))
            }).expect("guest declaration remains");
            let value = initializer(guest);
            let value = match value {
                Expression::Member { object, .. } => object.as_ref(),
                other => other,
            };
            assert_loader_call(value, "%fs_module");
        }
    }

    #[test]
    fn module_values_in_callee_position_are_loaded_then_called() {
        let mut expression = Expression::Call {
            callee: Box::new(Expression::Identifier("%events_module".into())),
            arguments: vec![Expression::StringLiteral("argument".into())],
            span: None,
        };
        let bindings = BTreeSet::from(["%events_module".to_string()]);
        ModuleReferences(&bindings).expression(&mut expression).unwrap();
        let Expression::Call { callee, arguments, .. } = expression else { panic!("call"); };
        assert_loader_call(&callee, "%events_module");
        assert_eq!(arguments, vec![Expression::StringLiteral("argument".into())]);
    }

    #[test]
    fn dependency_values_become_loads_without_rewriting_native_intrinsics() {
        let bindings = BTreeSet::from([
            "%util_module".to_string(), "%events_module".to_string(),
            "%string_decoder_module".to_string(),
        ]);
        for binding in &bindings {
            let mut value = Expression::Identifier(binding.clone());
            ModuleReferences(&bindings).expression(&mut value).unwrap();
            assert_loader_call(&value, binding);
        }
        for intrinsic in ["%FsRead", "%FsWrite", "%EventsOnce", "%UtilInspect"] {
            let mut value = Expression::Identifier(intrinsic.into());
            ModuleReferences(&bindings).expression(&mut value).unwrap();
            assert_eq!(value, Expression::Identifier(intrinsic.into()));
        }
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::sync::Barrier;

    fn fresh_template() -> Expression {
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "franken:native-module-loader".into(),
                    text: SOURCE.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("independent template parse");
        let [Statement::Expression(statement)] = tree.body.as_slice() else {
            panic!("one template expression");
        };
        statement.expression.clone()
    }

    fn fresh_deferred(initializer: Expression) -> Expression {
        let mut expression = fresh_template();
        let mut replacement = InitializerReplacement(Some(initializer));
        replacement.expression(&mut expression).unwrap();
        assert!(replacement.0.is_none());
        expression
    }

    #[test]
    fn cached_wrappers_match_fresh_parses_without_caching_initializers() {
        let pristine = fresh_template();
        for index in 0..32 {
            let initializer = Expression::Call {
                callee: Box::new(Expression::Identifier(format!("%probe_{index}"))),
                arguments: vec![
                    Expression::StringLiteral(format!("payload-{index}").into()),
                    // A placeholder inside supplied syntax remains opaque.
                    Expression::Identifier(INITIALIZER.into()),
                ],
                span: Some(SourceSpan::new(10, 20, 2, 1, 2, 11)),
            };
            assert_eq!(
                deferred(initializer.clone()).unwrap(),
                fresh_deferred(initializer),
            );
            assert_eq!(LOADER_SOURCE.expression().unwrap(), pristine);
        }
        // Count actual parser attempts on the production template, not calls
        // to a model or a second test-only cache. Parallel tests may use it.
        assert_eq!(LOADER_SOURCE.parse_attempt_count(), 1);
    }

    #[test]
    fn parallel_wrappers_keep_distinct_payloads_with_one_template_parse() {
        let barrier = Barrier::new(8);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|worker| {
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        for index in 0..8 {
                            let initializer = Expression::StringLiteral(
                                format!("worker-{worker}-module-{index}").into(),
                            );
                            assert_eq!(
                                deferred(initializer.clone()).unwrap(),
                                fresh_deferred(initializer),
                            );
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle.join().expect("parallel module lowering");
            }
        });
        assert_eq!(LOADER_SOURCE.parse_attempt_count(), 1);
        assert_eq!(LOADER_SOURCE.expression().unwrap(), fresh_template());
    }

    #[test]
    fn mutating_a_wrapper_does_not_change_later_or_nested_wrappers() {
        let initializer = Expression::Identifier("%private_dependency".into());
        let expected = fresh_deferred(initializer.clone());
        let mut changed = deferred(initializer.clone()).unwrap();
        let Expression::Call { arguments, .. } = &mut changed else {
            panic!("module wrapper call");
        };
        arguments.push(Expression::StringLiteral("caller-local".into()));
        assert_ne!(changed, expected);
        assert_eq!(deferred(initializer).unwrap(), expected);
        assert_eq!(deferred(changed.clone()).unwrap(), fresh_deferred(changed));
        assert_eq!(LOADER_SOURCE.expression().unwrap(), fresh_template());
        assert_eq!(LOADER_SOURCE.parse_attempt_count(), 1);
    }
}
