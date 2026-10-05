//! `require('path')` as a module object (bd-9vouw.181).
//!
//! The path facade (bd-tu0c3) lowers the member calls and constant reads of
//! a program-level `path` alias (`const path = require('path')`) and of an
//! inline `require('path').join(...)` to `builtin:Path*` HostCalls. Every
//! other form found no module: a destructured `const { join } =
//! require('path')` (and so `import { join } from 'node:path'`), a
//! `require('path')` inside a function, one passed as a value, or an inline
//! read of a function (`require('path').parse`). For those, the rewrite puts
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
//! Not covered: `path.win32` (the facade's win32 forms still work on an
//! alias).

use std::collections::BTreeSet;

use super::LoweringPipelineError;
use super::util_module::scoped_walk;
use super::with_statement::{
    FunctionBody, FunctionParts, Outcome, Search, Walk, lexical_names, var_names, walk_expression,
    walk_function, walk_switch_cases,
};
use crate::ast::{
    BindingPattern, CatchClause, Expression, ParseGoal, SourceSpan, Statement, SwitchCase,
    SyntaxTree, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

/// The program binding that caches the module object.
const MODULE_BINDING: &str = "%path_module";

/// PATH_SOURCE spells the facade's HostCalls with these names, which the
/// parser accepts, and the rewrite renames them to their `%` forms.
const INTRINSICS: [(&str, &str, &str); 9] = [
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
const PATH_SOURCE: &str = r#"(function () {
  'use strict';
  function join() {
    var joined = '';
    for (var i = 0; i < arguments.length; i++) {
      var segment = arguments[i];
      if (typeof segment !== 'string') {
        __franken_path_normalize(segment);
      }
      if (segment.length > 0) {
        joined = joined.length === 0 ? segment : joined + '/' + segment;
      }
    }
    return joined.length === 0 ? '.' : __franken_path_normalize(joined);
  }
  // The HostCall scans from the last argument and names a bad one by its
  // position, so the argument goes where it was, after empty paths that do
  // not end the scan.
  function invalidResolveArgument(index, value) {
    switch (index) {
      case 0: return __franken_path_resolve(value);
      case 1: return __franken_path_resolve('', value);
      case 2: return __franken_path_resolve('', '', value);
      case 3: return __franken_path_resolve('', '', '', value);
      case 4: return __franken_path_resolve('', '', '', '', value);
      case 5: return __franken_path_resolve('', '', '', '', '', value);
      case 6: return __franken_path_resolve('', '', '', '', '', '', value);
      default: return __franken_path_resolve('', '', '', '', '', '', '', value);
    }
  }
  function resolve() {
    var resolved = '';
    for (var i = arguments.length - 1; i >= 0; i--) {
      var segment = arguments[i];
      if (typeof segment !== 'string') {
        invalidResolveArgument(i, segment);
      }
      if (segment.length === 0) {
        continue;
      }
      resolved = resolved.length === 0 ? segment : segment + '/' + resolved;
      if (segment.charCodeAt(0) === 47) {
        break;
      }
    }
    return __franken_path_resolve(resolved);
  }
  function normalize(path) {
    return __franken_path_normalize(path);
  }
  function isAbsolute(path) {
    return __franken_path_is_absolute(path);
  }
  function relative(from, to) {
    return __franken_path_relative(from, to);
  }
  function toNamespacedPath(path) {
    return path;
  }
  function dirname(path) {
    return __franken_path_dirname(path);
  }
  function basename(path, suffix) {
    return __franken_path_basename(path, suffix);
  }
  function extname(path) {
    return __franken_path_extname(path);
  }
  function format(pathObject) {
    return __franken_path_format(pathObject);
  }
  function parse(path) {
    return __franken_path_parse(path);
  }
  var path = {
    resolve: resolve,
    normalize: normalize,
    isAbsolute: isAbsolute,
    join: join,
    relative: relative,
    toNamespacedPath: toNamespacedPath,
    dirname: dirname,
    basename: basename,
    extname: extname,
    format: format,
    parse: parse,
    sep: '/',
    delimiter: ':',
    posix: undefined
  };
  path.posix = path;
  return path;
})()"#;

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
        &["path", "node:path", "path/posix", "node:path/posix"],
    )
}

/// A `require` of the specifiers the facade recognizes.
fn is_facade_require_call(expression: &Expression) -> bool {
    is_require_call_of(expression, &["path", "node:path"])
}

/// The facade's inline forms: a recognized method call or constant read on
/// `require('path')` or its `posix` / `win32` namespace.
fn is_facade_inline_use(expression: &Expression) -> bool {
    match expression {
        Expression::Call { callee, .. } => matches!(callee.as_ref(),
        Expression::Member { object, property, computed: false, .. }
            if super::path_receiver_namespace_with(object, &is_facade_require_call)
                .zip(super::well_formed_static_name(property))
                .is_some_and(|(namespace, method)| {
                    super::path_method_capability(namespace, method).is_some()
                })),
        Expression::Member {
            object,
            property,
            computed,
            ..
        } => super::path_receiver_namespace_with(object, &is_facade_require_call)
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
    let mut rewritten = tree.clone();
    let mut rewriter = PathRewriter {
        scopes: vec![root],
        replaced: 0,
    };
    for statement in &mut rewritten.body {
        rewriter.program_statement(statement)?;
    }
    if rewriter.replaced == 0 {
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
                initializer: Some(module_source()?),
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

/// PATH_SOURCE parsed, with its intrinsics renamed. It reads no global.
fn module_source() -> Result<Expression, LoweringPipelineError> {
    struct Renamer;

    impl Walk for Renamer {
        fn expression(&mut self, expression: &mut Expression) -> Outcome {
            if let Expression::Identifier(name) = expression {
                if let Some((_, intrinsic, _)) = INTRINSICS
                    .iter()
                    .find(|(placeholder, _, _)| placeholder == name)
                {
                    *name = (*intrinsic).to_string();
                }
                return Ok(());
            }
            walk_expression(self, expression)
        }
    }

    let mut expression = parse_module_source()?;
    Renamer.expression(&mut expression)?;
    Ok(expression)
}

struct PathRewriter {
    /// Names declared in each enclosing scope, innermost last.
    scopes: Vec<BTreeSet<String>>,
    replaced: usize,
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
    /// there binding a name to `require('path')`, keeps its call.
    fn program_statement(&mut self, statement: &mut Statement) -> Outcome {
        let Statement::VariableDeclaration(declaration) = statement else {
            return self.statement(statement);
        };
        for declarator in &mut declaration.declarations {
            self.pattern(&mut declarator.pattern)?;
            match &mut declarator.initializer {
                Some(initializer)
                    if matches!(declarator.pattern, BindingPattern::Identifier(_))
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

    fn expression(&mut self, expression: &mut Expression) -> Outcome {
        if is_facade_inline_use(expression) {
            if let Expression::Call { arguments, .. } = expression {
                for argument in arguments {
                    self.expression(argument)?;
                }
            }
            return Ok(());
        }
        if self.is_free_path_require(expression) {
            *expression = Expression::Identifier(MODULE_BINDING.to_string());
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
        let source = format!("{:?}", module_source().expect("builds"));
        assert!(!source.contains("__franken_path"), "{source}");
        for (_, intrinsic, capability) in INTRINSICS {
            assert!(source.contains(intrinsic), "{intrinsic}");
            assert_eq!(intrinsic_capability(intrinsic), Some(capability));
        }
    }
}
