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
//! local function) is its own and is called as written. Other specifiers
//! and `require` as a value keep the ambient-authority refusal.

use std::collections::BTreeSet;

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
        _ => None,
    }
}

/// The module object, built once per program.
const UTIL_SOURCE: &str = r#"(function () {
  'use strict';
  var promisifyCustom = Symbol.for('nodejs.util.promisify.custom');
  var typedArrayNames = ['Int8Array', 'Uint8Array', 'Uint8ClampedArray', 'Int16Array',
    'Uint16Array', 'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array',
    'BigInt64Array', 'BigUint64Array'];
  function typeTag(value) {
    return __franken_util_type_tag(value);
  }
  // Node's determineSpecificType.
  function specificType(value) {
    if (value === null || value === undefined) {
      return String(value);
    }
    switch (typeof value) {
      case 'bigint':
        return 'type bigint (' + value + 'n)';
      case 'number':
        return 'type number (' + (Object.is(value, -0) ? '-0' : String(value)) + ')';
      case 'boolean':
      case 'symbol':
        return 'type ' + typeof value + ' (' + String(value) + ')';
      case 'function':
        return 'function ' + value.name;
      case 'object':
        if (value.constructor && 'name' in value.constructor) {
          return 'an instance of ' + value.constructor.name;
        }
        return inspect(value, { depth: -1 });
      default:
        if (value.length > 28) {
          value = value.slice(0, 25) + '...';
        }
        return 'type string (' + (value.indexOf("'") === -1 ? "'" + value + "'"
          : JSON.stringify(value)) + ')';
    }
  }
  // ERR_INVALID_ARG_TYPE.
  function invalidArgType(name, type, value) {
    var kind = name.indexOf('.') === -1 ? 'argument' : 'property';
    var error = new TypeError('The "' + name + '" ' + kind + ' must be of type ' + type + '. Received ' +
      specificType(value));
    error.code = 'ERR_INVALID_ARG_TYPE';
    return error;
  }
  function validateFunction(value, name) {
    if (typeof value !== 'function') {
      throw invalidArgType(name, 'function', value);
    }
  }
  // Own properties of `source` onto `target`, as Object.defineProperties
  // of Object.getOwnPropertyDescriptors does.
  function copyOwnProperties(target, source, adjust) {
    var keys = Reflect.ownKeys(source);
    for (var i = 0; i < keys.length; i++) {
      var descriptor = Object.getOwnPropertyDescriptor(source, keys[i]);
      if (descriptor === undefined) {
        continue;
      }
      if (adjust) {
        adjust(keys[i], descriptor);
      }
      Object.defineProperty(target, keys[i], descriptor);
    }
    return target;
  }
  function inspect(value, options) {
    var depth = inspect.defaultOptions.depth;
    if (typeof options === 'boolean') {
      if (arguments.length > 2 && arguments[2] !== undefined) {
        depth = arguments[2];
      }
    } else if (options !== null && typeof options === 'object' && options.depth !== undefined) {
      depth = options.depth;
    }
    return __franken_util_inspect(value, depth === null ? Infinity : depth);
  }
  inspect.custom = Symbol.for('nodejs.util.inspect.custom');
  inspect.defaultOptions = { showHidden: false, depth: 2, colors: false, customInspect: true,
    showProxy: false, maxArrayLength: 100, maxStringLength: 10000, breakLength: 128,
    compact: 3, sorted: false, getters: false, numericSeparator: false };
  function format(...args) {
    return __franken_util_format(args);
  }
  function formatWithOptions(inspectOptions, ...args) {
    if (inspectOptions === null || typeof inspectOptions !== 'object') {
      throw invalidArgType('inspectOptions', 'object', inspectOptions);
    }
    return __franken_util_format(args);
  }
  function inherits(ctor, superCtor) {
    if (ctor === undefined || ctor === null) {
      throw invalidArgType('ctor', 'function', ctor);
    }
    if (superCtor === undefined || superCtor === null) {
      throw invalidArgType('superCtor', 'function', superCtor);
    }
    if (superCtor.prototype === undefined) {
      throw invalidArgType('superCtor.prototype', 'object', superCtor.prototype);
    }
    Object.defineProperty(ctor, 'super_', { value: superCtor, writable: true, configurable: true });
    Object.setPrototypeOf(ctor.prototype, superCtor.prototype);
  }
  function promisify(original) {
    validateFunction(original, 'original');
    if (original[promisifyCustom]) {
      var custom = original[promisifyCustom];
      validateFunction(custom, 'util.promisify.custom');
      return Object.defineProperty(custom, promisifyCustom, { value: custom, enumerable: false,
        writable: false, configurable: true });
    }
    function fn(...args) {
      var self = this;
      return new Promise(function (resolve, reject) {
        args.push(function (error, ...values) {
          if (error) {
            return reject(error);
          }
          resolve(values[0]);
        });
        Reflect.apply(original, self, args);
      });
    }
    Object.setPrototypeOf(fn, Object.getPrototypeOf(original));
    Object.defineProperty(fn, promisifyCustom, { value: fn, enumerable: false, writable: false,
      configurable: true });
    return copyOwnProperties(fn, original);
  }
  promisify.custom = promisifyCustom;
  function callbackifyOnRejected(reason, callback) {
    if (!reason) {
      var error = new Error('Promise was rejected with falsy value');
      error.code = 'ERR_FALSY_VALUE_REJECTION';
      error.reason = reason;
      reason = error;
    }
    return callback(reason);
  }
  function callbackify(original) {
    validateFunction(original, 'original');
    function callbackified(...args) {
      var maybeCallback = args.pop();
      validateFunction(maybeCallback, 'last argument');
      var callback = maybeCallback.bind(this);
      Reflect.apply(original, this, args).then(function (value) {
        callback(null, value);
      }, function (reason) {
        callbackifyOnRejected(reason, callback);
      });
    }
    return copyOwnProperties(callbackified, original, function (key, descriptor) {
      if (key === 'length' && typeof descriptor.value === 'number') {
        descriptor.value++;
      }
      if (key === 'name' && typeof descriptor.value === 'string') {
        descriptor.value += 'Callbackified';
      }
    });
  }
  function deprecate(fn) {
    validateFunction(fn, 'fn');
    function deprecated(...args) {
      if (new.target) {
        return Reflect.construct(fn, args, new.target);
      }
      return Reflect.apply(fn, this, args);
    }
    Object.setPrototypeOf(deprecated, fn);
    if (fn.prototype) {
      deprecated.prototype = fn.prototype;
    }
    return deprecated;
  }
  function debuglog() {
    var log = function () {};
    log.enabled = false;
    return log;
  }
  function deepEqual(a, b, seen) {
    if (Object.is(a, b)) {
      return true;
    }
    if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) {
      return false;
    }
    if (Object.getPrototypeOf(a) !== Object.getPrototypeOf(b)) {
      return false;
    }
    var tag = typeTag(a);
    if (tag !== typeTag(b)) {
      return false;
    }
    for (var i = 0; i < seen.length; i++) {
      if (seen[i][0] === a && seen[i][1] === b) {
        return true;
      }
    }
    seen.push([a, b]);
    if (tag === 'Date' && !Object.is(a.getTime(), b.getTime())) {
      return false;
    }
    if (tag === 'RegExp' &&
        (a.source !== b.source || a.flags !== b.flags || a.lastIndex !== b.lastIndex)) {
      return false;
    }
    if (tag.indexOf('Boxed') === 0 && !Object.is(a.valueOf(), b.valueOf())) {
      return false;
    }
    if (tag === 'Error' && (a.message !== b.message || a.name !== b.name)) {
      return false;
    }
    if (Array.isArray(a) && a.length !== b.length) {
      return false;
    }
    if (tag === 'Map') {
      if (a.size !== b.size) {
        return false;
      }
      for (var entry of a) {
        if (!b.has(entry[0]) || !deepEqual(entry[1], b.get(entry[0]), seen)) {
          return false;
        }
      }
    }
    if (tag === 'Set') {
      if (a.size !== b.size) {
        return false;
      }
      for (var member of a) {
        if (!b.has(member)) {
          return false;
        }
      }
    }
    var keysA = Object.keys(a);
    var keysB = Object.keys(b);
    if (keysA.length !== keysB.length) {
      return false;
    }
    for (var j = 0; j < keysA.length; j++) {
      var key = keysA[j];
      if (!Object.prototype.hasOwnProperty.call(b, key) || !deepEqual(a[key], b[key], seen)) {
        return false;
      }
    }
    return true;
  }
  function isDeepStrictEqual(a, b) {
    return deepEqual(a, b, []);
  }
  function tagIs(name) {
    return function (value) {
      return typeTag(value) === name;
    };
  }
  var types = {
    isDate: tagIs('Date'),
    isRegExp: tagIs('RegExp'),
    isMap: tagIs('Map'),
    isSet: tagIs('Set'),
    isWeakMap: tagIs('WeakMap'),
    isWeakSet: tagIs('WeakSet'),
    isPromise: tagIs('Promise'),
    isArrayBuffer: tagIs('ArrayBuffer'),
    isAnyArrayBuffer: tagIs('ArrayBuffer'),
    isDataView: tagIs('DataView'),
    isNativeError: tagIs('Error'),
    isProxy: tagIs('Proxy'),
    isGeneratorFunction: function (value) {
      var tag = typeTag(value);
      return tag === 'GeneratorFunction' || tag === 'AsyncGeneratorFunction';
    },
    isAsyncFunction: function (value) {
      var tag = typeTag(value);
      return tag === 'AsyncFunction' || tag === 'AsyncGeneratorFunction';
    },
    isGeneratorObject: tagIs('Generator'),
    isNumberObject: tagIs('BoxedNumber'),
    isStringObject: tagIs('BoxedString'),
    isBooleanObject: tagIs('BoxedBoolean'),
    isBigIntObject: tagIs('BoxedBigInt'),
    isSymbolObject: tagIs('BoxedSymbol'),
    isBoxedPrimitive: function (value) {
      return typeTag(value).indexOf('Boxed') === 0;
    },
    isTypedArray: function (value) {
      return typedArrayNames.indexOf(typeTag(value)) !== -1;
    },
    isArrayBufferView: function (value) {
      var tag = typeTag(value);
      return tag === 'DataView' || typedArrayNames.indexOf(tag) !== -1;
    }
  };
  typedArrayNames.forEach(function (name) {
    types['is' + name] = tagIs(name);
  });
  return {
    format: format,
    formatWithOptions: formatWithOptions,
    inspect: inspect,
    inherits: inherits,
    promisify: promisify,
    callbackify: callbackify,
    deprecate: deprecate,
    debuglog: debuglog,
    debug: debuglog,
    isDeepStrictEqual: isDeepStrictEqual,
    types: types,
    isArray: Array.isArray,
    TextEncoder: TextEncoder,
    TextDecoder: TextDecoder
  };
})()"#;

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
const MODULE_GLOBALS: [&str; 11] = [
    "Array",
    "Error",
    "JSON",
    "Object",
    "Promise",
    "Reflect",
    "String",
    "Symbol",
    "TextDecoder",
    "TextEncoder",
    "TypeError",
];

/// `const %util_module = <module>;`, which the rewrite puts first in the
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

/// `tree` with every free `require('util')` rewritten to the module, or
/// `None` when it has none.
pub(super) fn rewrite_util_requires(
    tree: &SyntaxTree,
) -> Result<Option<SyntaxTree>, LoweringPipelineError> {
    if !tree
        .body
        .iter()
        .any(|statement| UTIL_REQUIRE_SEARCH.in_statement(statement))
    {
        return Ok(None);
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
