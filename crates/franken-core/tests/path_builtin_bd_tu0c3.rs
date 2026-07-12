//! bd-tu0c3 (core mirror): `require('path')` as a pure-compute builtin.
//!
//! Mirror of the franken-engine path-module lowering interception: a
//! `const path = require('path')` binding that is actually USED as a
//! recognized `path` builtin is elided, member calls lower to `builtin:Path*`
//! hostcalls (posix semantics) and `sep`/`delimiter` property reads lower to
//! string constants. A bare/unused alias keeps core's existing behavior (a
//! `module:require` hostcall, which fails closed without the ModuleLoad
//! capability). Expected values are pinned against bun (Node-compatible
//! reference), matching the engine twin's
//! `tests/path_builtin_bd_tu0c3.rs`.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterError, QuickJsLane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

use std::collections::BTreeSet;

/// Parse -> IR0 -> IR3 -> execute on the QuickJS lane with the minimal
/// execution capabilities (core `builtin:*` hostcall tags are internal
/// dispatch tags — unmapped by `RuntimeCapability::from_tag_str` — so the
/// pure-compute path builtins need no extra grant, exactly like Math).
fn run(source: &str) -> Result<ExecutionResult, InterpreterError> {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_tu0c3");
    let context = LoweringContext::new("bd-tu0c3-trace", "bd-tu0c3-decision", "bd-tu0c3-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config).execute(&module, "bd-tu0c3-trace")
}

/// Completion value of a script whose final statement is an expression.
fn completion(source: &str) -> Value {
    run(source).expect("execution should succeed").value
}

fn completion_str(source: &str) -> Value {
    completion(source)
}

#[test]
fn join_segments_dots_empties_and_trailing_slash() {
    assert_eq!(
        completion_str("const path = require('path'); path.join('a', 'b', 'c');"),
        Value::str("a/b/c")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.join('a', 'b', '..', 'c');"),
        Value::str("a/c")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.join('a', '..', '..', 'b');"),
        Value::str("../b")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.join('a', '', 'b');"),
        Value::str("a/b")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.join('a/', 'b//');"),
        Value::str("a/b/")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.join();"),
        Value::str(".")
    );
}

#[test]
fn join_non_string_argument_is_a_type_error() {
    // Core has no error-object prototype machinery: the validation failure
    // surfaces as the plain host TypeError (the engine twin throws the
    // JS-catchable ERR_INVALID_ARG_TYPE TypeError object).
    let err = run("const path = require('path'); path.join('a', 1);")
        .expect_err("non-string join argument must fail");
    assert!(
        matches!(err, InterpreterError::TypeError { .. }),
        "expected TypeError, got {err:?}"
    );
}

#[test]
fn basename_ext_strip_and_trailing_slashes() {
    assert_eq!(
        completion_str("const path = require('path'); path.basename('/foo/bar/baz.txt');"),
        Value::str("baz.txt")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.basename('/foo/bar.html', '.html');"),
        Value::str("bar")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.basename('bar', 'longer-than-name');"),
        Value::str("bar")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.basename('/foo/bar///');"),
        Value::str("bar")
    );
}

#[test]
fn dirname_edges() {
    assert_eq!(
        completion_str("const path = require('path'); path.dirname('/a/b/c/');"),
        Value::str("/a/b")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.dirname('/');"),
        Value::str("/")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.dirname('a');"),
        Value::str(".")
    );
}

#[test]
fn extname_dotfile_rules() {
    assert_eq!(
        completion_str("const path = require('path'); path.extname('archive.tar.gz');"),
        Value::str(".gz")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.extname('.bashrc');"),
        Value::str("")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.extname('file.');"),
        Value::str(".")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.extname('/a.b/file');"),
        Value::str("")
    );
}

#[test]
fn normalize_dots_slashes_and_root() {
    assert_eq!(
        completion_str(
            "const path = require('path'); path.normalize('/foo/bar//baz/asdf/quux/..');"
        ),
        Value::str("/foo/bar/baz/asdf")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.normalize('a/b/');"),
        Value::str("a/b/")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.normalize('../a/../b');"),
        Value::str("../b")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.normalize('/..');"),
        Value::str("/")
    );
}

#[test]
fn resolve_right_to_left_with_synthetic_cwd() {
    assert_eq!(
        completion_str("const path = require('path'); path.resolve('/x', '/y', 'z');"),
        Value::str("/y/z")
    );
    assert_eq!(
        completion_str(
            "const path = require('path'); path.resolve('ignored', '/a', 'b', '..', 'c');"
        ),
        Value::str("/a/c")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.isAbsolute(path.resolve('a'));"),
        Value::Bool(true)
    );
}

#[test]
fn relative_walks_up_and_down() {
    assert_eq!(
        completion_str(
            "const path = require('path'); path.relative('/data/orandea/test/aaa', '/data/orandea/impl/bbb');"
        ),
        Value::str("../../impl/bbb")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.relative('/a/b/', '/a/b');"),
        Value::str("")
    );
}

#[test]
fn parse_decomposition_via_member_reads() {
    assert_eq!(
        completion_str(
            "const path = require('path'); const p = path.parse('/home/user/dir/file.txt'); p.root + '|' + p.dir + '|' + p.base + '|' + p.ext + '|' + p.name;"
        ),
        Value::str("/|/home/user/dir|file.txt|.txt|file")
    );
}

#[test]
fn format_precedence() {
    assert_eq!(
        completion_str(
            "const path = require('path'); path.format({ root: '/r/', dir: '/a', name: 'f', ext: '.txt', base: 'g.md' });"
        ),
        Value::str("/a/g.md")
    );
    assert_eq!(
        completion_str(
            "const path = require('path'); path.format({ root: '/', name: 'f', ext: '.txt' });"
        ),
        Value::str("/f.txt")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.format({ name: 'file', ext: '.js' });"),
        Value::str("file.js")
    );
}

#[test]
fn sep_and_delimiter_constants() {
    assert_eq!(
        completion_str("const path = require('path'); path.sep + path.delimiter;"),
        Value::str("/:")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.posix.sep + path.posix.delimiter;"),
        Value::str("/:")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.win32.sep + path.win32.delimiter;"),
        Value::str("\\;")
    );
}

#[test]
fn posix_and_win32_namespaces() {
    assert_eq!(
        completion_str("const path = require('path'); path.posix.join('a', 'b', '..', 'c');"),
        Value::str("a/c")
    );
    assert_eq!(
        completion_str("const path = require('path'); path.win32.join('a', 'b', 'c');"),
        Value::str("a\\b\\c")
    );
    assert_eq!(
        completion_str(
            "const path = require('path'); path.win32.basename('C:\\\\temp\\\\myfile.html');"
        ),
        Value::str("myfile.html")
    );
    assert_eq!(
        completion_str(
            "const path = require('path'); path.win32.isAbsolute('\\\\\\\\server\\\\share');"
        ),
        Value::Bool(true)
    );
    assert_eq!(
        completion_str("const path = require('path'); path.win32.isAbsolute('C:relative');"),
        Value::Bool(false)
    );
}

#[test]
fn node_path_specifier_and_inline_receiver() {
    assert_eq!(
        completion_str("const p = require('node:path'); p.extname('x.rs');"),
        Value::str(".rs")
    );
    assert_eq!(
        completion_str("require('path').join('a', 'b');"),
        Value::str("a/b")
    );
}

#[test]
fn unused_path_alias_keeps_module_require_fail_closed() {
    // The usage gate: a bare/unused `const path = require('path')` is NOT
    // recognized, so it keeps core's existing `module:require` lowering,
    // which fails closed here (ModuleLoad capability not granted).
    let err = run("const path = require('path'); 1;")
        .expect_err("unused path alias must keep the module:require denial");
    assert!(
        matches!(err, InterpreterError::CapabilityDenied { .. }),
        "expected CapabilityDenied for ungated module:require, got {err:?}"
    );
}
