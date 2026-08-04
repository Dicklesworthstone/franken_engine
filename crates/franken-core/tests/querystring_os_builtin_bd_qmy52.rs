//! bd-qmy52 (core mirror): `require('querystring')` and `require('os')` as
//! pure-compute builtins.
//!
//! Mirror of the franken-engine querystring/os lowering interception: a
//! `const qs = require('querystring')` / `const os = require('os')` binding
//! that is actually USED as a recognized builtin is elided, member calls
//! lower to `builtin:Querystring*` / `builtin:Os*` hostcalls,
//! `os.EOL`/`os.devNull` property reads lower to string constants, and
//! `os.constants` lowers to a 0-arg `builtin:OsConstants` hostcall. A
//! bare/unused alias keeps core's existing behavior (a `module:require`
//! hostcall, which fails closed without the ModuleLoad capability).
//! Querystring expected values are pinned against bun 1.3.14 (Node-compatible
//! reference); the os builtins return the fixed engine-contained values,
//! matching the engine twin's `tests/querystring_os_builtin_bd_qmy52.rs`.

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
/// pure-compute querystring/os builtins need no extra grant, exactly like
/// Math and path).
fn run(source: &str) -> Result<ExecutionResult, InterpreterError> {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_qmy52");
    let context = LoweringContext::new("bd-qmy52-trace", "bd-qmy52-decision", "bd-qmy52-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config).execute(&module, "bd-qmy52-trace")
}

/// Completion value of a script whose final statement is an expression.
fn completion(source: &str) -> Value {
    run(source).expect("execution should succeed").value
}

// -------------------------------------------------------------------------
// querystring
// -------------------------------------------------------------------------

#[test]
fn escape_and_unescape() {
    assert_eq!(
        completion("const qs = require('querystring'); qs.escape('a b&c=d/e');"),
        Value::str("a%20b%26c%3Dd%2Fe")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.escape(\"!'()*-._~ok\");"),
        Value::str("!'()*-._~ok")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.escape('中');"),
        Value::str("%E4%B8%AD")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.unescape('a%20b%26c');"),
        Value::str("a b&c")
    );
    // '+' is not decoded by unescape; malformed escapes stay literal.
    assert_eq!(
        completion("const qs = require('querystring'); qs.unescape('x+y');"),
        Value::str("x+y")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.unescape('a%2');"),
        Value::str("a%2")
    );
}

#[test]
fn parse_basic_and_plus_and_percent() {
    assert_eq!(
        completion("const qs = require('querystring'); qs.parse('foo=bar&abc=xyz').foo;"),
        Value::str("bar")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.parse('msg=hello+world').msg;"),
        Value::str("hello world")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.parse('a=%E4%B8%AD').a;"),
        Value::str("中")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.parse('flag&o=1').flag;"),
        Value::str("")
    );
}

#[test]
fn parse_repeated_keys_custom_sep_eq_and_max_keys() {
    assert_eq!(
        completion("const qs = require('querystring'); qs.parse('a=1&a=2&a=3').a.length;"),
        Value::Int(3)
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.parse('a=1&a=2&a=3').a[1];"),
        Value::str("2")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.parse('w:x;y:z', ';', ':').y;"),
        Value::str("z")
    );
    // maxKeys: 2 keeps the first two pairs only.
    assert_eq!(
        completion(
            "const qs = require('querystring'); typeof qs.parse('a=1&b=2&c=3', null, null, { maxKeys: 2 }).c;"
        ),
        Value::str("undefined")
    );
}

#[test]
fn stringify_pairs_arrays_and_primitives() {
    assert_eq!(
        completion("const qs = require('querystring'); qs.stringify({ abc: 'xyz', foo: 'bar' });"),
        Value::str("abc=xyz&foo=bar")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.stringify({ a: ['1', '2'], b: 'x' });"),
        Value::str("a=1&a=2&b=x")
    );
    // bun: empty-array values are skipped; space escapes to %20.
    assert_eq!(
        completion("const qs = require('querystring'); qs.stringify({ e: [], f: 'y' });"),
        Value::str("f=y")
    );
    assert_eq!(
        completion(
            "const qs = require('querystring'); qs.stringify({ a: 'x y', n: 42, t: true });"
        ),
        Value::str("a=x%20y&n=42&t=true")
    );
    // Nested objects/null become empty values; non-object input is ''.
    assert_eq!(
        completion("const qs = require('querystring'); qs.stringify({ a: { n: 1 }, b: 'ok' });"),
        Value::str("a=&b=ok")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.stringify(null);"),
        Value::str("")
    );
}

#[test]
fn decode_encode_aliases_and_node_specifier_and_inline_receiver() {
    assert_eq!(
        completion("const qs = require('querystring'); qs.decode('a=1').a;"),
        Value::str("1")
    );
    assert_eq!(
        completion("const qs = require('querystring'); qs.encode({ a: '1' });"),
        Value::str("a=1")
    );
    assert_eq!(
        completion("const qs = require('node:querystring'); qs.escape('a b');"),
        Value::str("a%20b")
    );
    assert_eq!(
        completion("require('querystring').escape('a b');"),
        Value::str("a%20b")
    );
}

// -------------------------------------------------------------------------
// os
// -------------------------------------------------------------------------

#[test]
fn os_property_constants() {
    assert_eq!(
        completion("const os = require('os'); os.EOL;"),
        Value::str("\n")
    );
    assert_eq!(
        completion("const os = require('os'); os.devNull;"),
        Value::str("/dev/null")
    );
}

#[test]
fn os_identity_methods_fixed_values() {
    assert_eq!(
        completion("const os = require('os'); os.platform();"),
        Value::str("linux")
    );
    assert_eq!(
        completion("const os = require('os'); os.arch();"),
        Value::str("x64")
    );
    assert_eq!(
        completion("const os = require('os'); os.type();"),
        Value::str("Linux")
    );
    assert_eq!(
        completion("const os = require('os'); os.endianness();"),
        Value::str("LE")
    );
    assert_eq!(
        completion("const os = require('os'); os.machine();"),
        Value::str("x86_64")
    );
    assert_eq!(
        completion("const os = require('os'); os.homedir();"),
        Value::str("/home")
    );
    assert_eq!(
        completion("const os = require('os'); os.tmpdir();"),
        Value::str("/tmp")
    );
    assert_eq!(
        completion("const os = require('os'); os.hostname();"),
        Value::str("localhost")
    );
}

#[test]
fn os_numeric_methods_fixed_values() {
    assert_eq!(
        completion("const os = require('os'); os.totalmem();"),
        Value::Int(17_179_869_184)
    );
    assert_eq!(
        completion("const os = require('os'); os.freemem();"),
        Value::Int(8_589_934_592)
    );
    assert_eq!(
        completion("const os = require('os'); os.availableParallelism();"),
        Value::Int(1)
    );
    assert_eq!(
        completion("const os = require('os'); os.uptime() > 0;"),
        Value::Bool(true)
    );
    assert_eq!(
        completion("const os = require('os'); os.loadavg().length;"),
        Value::Int(3)
    );
}

#[test]
fn os_shape_methods() {
    assert_eq!(
        completion("const os = require('os'); os.cpus()[0].model;"),
        Value::str("franken-virtual")
    );
    assert_eq!(
        completion("const os = require('os'); typeof os.cpus()[0].times.user;"),
        Value::str("number")
    );
    assert_eq!(
        completion("const os = require('os'); typeof os.networkInterfaces();"),
        Value::str("object")
    );
    assert_eq!(
        completion("const os = require('os'); os.userInfo().username;"),
        Value::str("franken")
    );
    assert_eq!(
        completion("const os = require('os'); os.userInfo().uid;"),
        Value::Int(0)
    );
}

#[test]
fn os_constants_nested_values() {
    assert_eq!(
        completion("const os = require('os'); os.constants.signals.SIGINT;"),
        Value::Int(2)
    );
    assert_eq!(
        completion("const os = require('os'); os.constants.signals.SIGTERM;"),
        Value::Int(15)
    );
    assert_eq!(
        completion("const os = require('os'); os.constants.errno.ENOENT;"),
        Value::Int(2)
    );
    assert_eq!(
        completion("const os = require('os'); os.constants.priority.PRIORITY_NORMAL;"),
        Value::Int(0)
    );
    assert_eq!(
        completion("const os = require('os'); typeof os.constants;"),
        Value::str("object")
    );
}

#[test]
fn os_priority_methods_and_validation() {
    assert_eq!(
        completion("const os = require('os'); os.getPriority();"),
        Value::Int(0)
    );
    assert_eq!(
        completion("const os = require('os'); os.getPriority(0);"),
        Value::Int(0)
    );
    assert_eq!(
        completion("const os = require('os'); typeof os.setPriority(0, 10);"),
        Value::str("undefined")
    );
    // Core has no error-object prototype machinery: the validation failures
    // surface as core's plain TypeError / RangeError variants (the engine
    // twin throws JS-catchable ERR_INVALID_ARG_TYPE / ERR_OUT_OF_RANGE
    // error objects).
    let err = run("const os = require('os'); os.setPriority('not-a-pid', 0);")
        .expect_err("non-number pid must fail");
    assert!(
        matches!(err, InterpreterError::TypeError { .. }),
        "expected TypeError for non-number pid, got {err:?}"
    );
    let err = run("const os = require('os'); os.setPriority(0, 1000);")
        .expect_err("out-of-range priority must fail");
    assert!(
        matches!(err, InterpreterError::RangeError { .. }),
        "expected RangeError for out-of-range priority, got {err:?}"
    );
}

#[test]
fn os_node_specifier_and_inline_receiver() {
    assert_eq!(
        completion("const os = require('node:os'); os.platform();"),
        Value::str("linux")
    );
    assert_eq!(completion("require('os').platform();"), Value::str("linux"));
    assert_eq!(completion("require('os').EOL;"), Value::str("\n"));
}

// -------------------------------------------------------------------------
// fail-closed contract
// -------------------------------------------------------------------------

#[test]
fn unused_querystring_alias_keeps_module_require_denial() {
    // A bare/unused `const qs = require('querystring')` is NOT recognized, so
    // it keeps core's existing `module:require` lowering, which fails closed
    // here (ModuleLoad capability not granted).
    let err = run("const qs = require('querystring'); 1;")
        .expect_err("unused querystring alias must keep the module:require denial");
    assert!(
        matches!(err, InterpreterError::CapabilityDenied { .. }),
        "expected CapabilityDenied for ungated module:require, got {err:?}"
    );
}

#[test]
fn unused_os_alias_keeps_module_require_denial() {
    let err = run("const os = require('os'); 1;")
        .expect_err("unused os alias must keep the module:require denial");
    assert!(
        matches!(err, InterpreterError::CapabilityDenied { .. }),
        "expected CapabilityDenied for ungated module:require, got {err:?}"
    );
}

#[test]
fn usage_only_inside_function_body_stays_fail_closed() {
    // Function bodies are opaque to the usage scan (fail-closed): a usage
    // reachable only through a function body does NOT confirm the alias.
    let err =
        run("const qs = require('querystring'); function f() { return qs.escape('a b'); } f();")
            .expect_err("function-body-only usage must not confirm the alias");
    assert!(
        matches!(err, InterpreterError::CapabilityDenied { .. }),
        "expected CapabilityDenied for function-body-only usage, got {err:?}"
    );
    let err = run("const os = require('os'); function f() { return os.platform(); } f();")
        .expect_err("function-body-only usage must not confirm the alias");
    assert!(
        matches!(err, InterpreterError::CapabilityDenied { .. }),
        "expected CapabilityDenied for function-body-only usage, got {err:?}"
    );
}

#[test]
fn unrecognized_method_does_not_confirm_the_aliases() {
    let err = run("const os = require('os'); os.notAMethod();")
        .expect_err("unrecognized-method-only usage must not confirm the alias");
    assert!(
        matches!(err, InterpreterError::CapabilityDenied { .. }),
        "expected CapabilityDenied for unrecognized-method-only usage, got {err:?}"
    );
}
