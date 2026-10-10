//! bd-qmy52: `require('querystring')` and `require('os')` as pure-compute
//! builtins.
//!
//! querystring is a first-class realm module (bd-305gi): its extracted,
//! destructured and deferred methods call the same `builtin:Querystring*`
//! hostcalls as the original direct-call facade. The lowering pipeline still
//! recognizes `const os = require('os')` bindings used as an os builtin,
//! elides that declaration and rewrites calls to `builtin:Os*` hostcalls.
//! The deterministic `os` property constants
//! (`os.EOL`, `os.devNull`) lower to string literals and `os.constants` to a
//! 0-arg `builtin:OsConstants` hostcall allocating the nested
//! `{ signals, errno, priority }` object. Bare/unused os aliases keep the
//! ambient-authority denial (fail-closed contract pinned below).
//!
//! The `os` builtins return FIXED engine-contained values (the engine has no
//! ambient authority); querystring escape/unescape/parse/stringify edge
//! behaviors are pinned against `bun` 1.3.14 (Node-compatible reference) runs
//! of the compat corpus at
//! `franken_node/crates/franken-node/tests/fixtures/compat_corpus/{querystring,os}/`.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};

/// Evaluate `src` and return the console output messages joined by newlines
/// (one line per `console.log`, args joined by single spaces — matching bun).
fn eval_console(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Evaluate `src` expecting an eval-time error; returns its display string.
fn eval_err(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(outcome) => panic!("expected eval error for {src:?}, got {outcome:?}"),
        Err(e) => format!("{e}"),
    }
}

// -------------------------------------------------------------------------
// querystring.parse
// -------------------------------------------------------------------------

#[test]
fn compat_corpus_0013_parse_preserves_pair_key_order_bd_n8eta() {
    let src = r#"
        const qs = require('querystring');
        const o = qs.parse('foo=bar&abc=xyz');
        console.log(Object.keys(o).join(','), o.foo, o.abc);
    "#;
    assert_eq!(eval_console(src), "foo,abc bar xyz");
}

#[test]
fn parse_repeated_keys_collect_into_arrays() {
    let src = r#"
        const qs = require('querystring');
        const o = qs.parse('a=1&a=2&a=3&b=solo');
        console.log(Array.isArray(o.a), o.a.join(','), Array.isArray(o.b), o.b);
    "#;
    assert_eq!(eval_console(src), "true 1,2,3 false solo");
}

#[test]
fn parse_custom_sep_and_eq() {
    let src = r#"
        const qs = require('querystring');
        const o = qs.parse('w:x;y:z', ';', ':');
        console.log(o.w, o.y);
        const m = qs.parse('w::x;;y::z', ';;', '::');
        console.log(m.w, m.y);
    "#;
    assert_eq!(eval_console(src), "x z\nx z");
}

#[test]
fn parse_max_keys_limits_pairs() {
    let src = r#"
        const qs = require('querystring');
        const o = qs.parse('a=1&b=2&c=3&d=4', null, null, { maxKeys: 2 });
        console.log(Object.keys(o).sort().join(','), Object.keys(o).length);
    "#;
    assert_eq!(eval_console(src), "a,b 2");
}

#[test]
fn parse_max_keys_zero_negative_and_infinity_are_unlimited() {
    // bun: maxKeys <= 0 and Infinity disable the limit entirely.
    let src = r#"
        const qs = require('querystring');
        console.log(Object.keys(qs.parse('a=1&b=2&c=3', null, null, { maxKeys: 0 })).length);
        console.log(Object.keys(qs.parse('a=1&b=2&c=3', null, null, { maxKeys: -1 })).length);
        console.log(Object.keys(qs.parse('a=1&b=2&c=3', null, null, { maxKeys: Infinity })).length);
    "#;
    assert_eq!(eval_console(src), "3\n3\n3");
}

#[test]
fn parse_empty_segment_consumes_a_max_keys_slot() {
    // bun: parse('&a=1', null, null, { maxKeys: 1 }) is {} — the leading
    // empty segment consumed the only pair slot; without a limit the same
    // input parses normally.
    let src = r#"
        const qs = require('querystring');
        console.log(Object.keys(qs.parse('&a=1', null, null, { maxKeys: 1 })).length);
        console.log(qs.parse('&a=1').a);
        console.log(qs.parse('a=1&&b=2').b);
    "#;
    assert_eq!(eval_console(src), "0\n1\n2");
}

#[test]
fn parse_empty_values_and_missing_eq() {
    let src = r#"
        const qs = require('querystring');
        const o = qs.parse('a=&b=&c=3');
        console.log(JSON.stringify(o.a), JSON.stringify(o.b), o.c);
        const f = qs.parse('flag&other');
        console.log(JSON.stringify(f.flag), JSON.stringify(f.other));
        const t = qs.parse('a=1&b');
        console.log(JSON.stringify(t.b));
    "#;
    assert_eq!(eval_console(src), "\"\" \"\" 3\n\"\" \"\"\n\"\"");
}

#[test]
fn parse_empty_key_and_second_eq_in_value() {
    // bun: parse('=5') is { '': '5' }; parse('a==b') is { a: '=b' }.
    let src = r#"
        const qs = require('querystring');
        console.log(qs.parse('=5')['']);
        console.log(qs.parse('a==b').a);
    "#;
    assert_eq!(eval_console(src), "5\n=b");
}

#[test]
fn parse_plus_decodes_to_space_in_keys_and_values() {
    let src = r#"
        const qs = require('querystring');
        console.log(qs.parse('msg=hello+world+again').msg);
        console.log(qs.parse('two+part=v')['two part']);
    "#;
    assert_eq!(eval_console(src), "hello world again\nv");
}

#[test]
fn parse_percent_decodes_unicode_and_space() {
    let src = r#"
        const qs = require('querystring');
        const o = qs.parse('a=%E4%B8%AD%E6%96%87&b=x%20y');
        console.log(o.a, o.b);
        console.log(qs.parse('%41=%42').A);
    "#;
    assert_eq!(eval_console(src), "中文 x y\nB");
}

#[test]
fn parse_invalid_escapes_stay_literal() {
    // bun: only a complete valid %XX escape triggers decoding; malformed
    // sequences pass through untouched.
    let src = r#"
        const qs = require('querystring');
        const o = qs.parse('a%2=x&b=%zz');
        console.log(o['a%2'], o.b);
    "#;
    assert_eq!(eval_console(src), "x %zz");
}

#[test]
fn parse_bracket_keys_are_literal_not_nested() {
    let src = r#"
        const qs = require('querystring');
        const o = qs.parse('a[b]=1&a[c]=2');
        console.log(o['a[b]'], o['a[c]'], typeof o.a);
    "#;
    assert_eq!(eval_console(src), "1 2 undefined");
}

#[test]
fn parse_empty_string_yields_empty_object() {
    let src = r#"
        const qs = require('querystring');
        const o = qs.parse('');
        console.log(Object.keys(o).length, typeof o);
    "#;
    assert_eq!(eval_console(src), "0 object");
}

#[test]
fn parse_non_string_input_yields_empty_object() {
    // bun: JSON.stringify(qs.parse(null)) is '{}'.
    let src = r#"
        const qs = require('querystring');
        console.log(Object.keys(qs.parse(null)).length);
        console.log(Object.keys(qs.parse(42)).length);
    "#;
    assert_eq!(eval_console(src), "0\n0");
}

#[test]
fn parse_falsy_sep_and_eq_use_defaults() {
    // bun: parse('a=1', '', '') is { a: '1' } — falsy sep/eq fall back to
    // '&' / '='.
    let src = r#"
        const qs = require('querystring');
        console.log(qs.parse('a=1', '', '').a);
    "#;
    assert_eq!(eval_console(src), "1");
}

// -------------------------------------------------------------------------
// querystring.stringify
// -------------------------------------------------------------------------

#[test]
fn stringify_basic_pairs() {
    let src = r#"
        const qs = require('querystring');
        console.log(qs.stringify({ abc: 'xyz', foo: 'bar' }));
    "#;
    assert_eq!(eval_console(src), "abc=xyz&foo=bar");
}

#[test]
fn compat_corpus_0010_stringify_uses_object_keys_insertion_order_bd_n8eta() {
    // Compat corpus querystring/0010: Node 20.19.4 and bun 1.3.14 both retain
    // this property-creation order through Object.keys and qs.stringify.
    let src = r#"
        const qs = require('querystring');
        const value = { foo: 'bar', baz: 'qux' };
        console.log(Object.keys(value).join(','));
        console.log(qs.stringify(value));
    "#;
    assert_eq!(eval_console(src), "foo,baz\nfoo=bar&baz=qux");
}

#[test]
fn stringify_array_values_expand_to_repeated_keys() {
    let src = r#"
        const qs = require('querystring');
        console.log(qs.stringify({ a: ['1', '2', '3'], b: 'x' }));
    "#;
    assert_eq!(eval_console(src), "a=1&a=2&a=3&b=x");
}

#[test]
fn stringify_empty_array_value_is_skipped() {
    // bun: stringify({ e: [], f: 'y' }) is 'f=y'.
    let src = r#"
        const qs = require('querystring');
        console.log(qs.stringify({ e: [], f: 'y' }));
    "#;
    assert_eq!(eval_console(src), "f=y");
}

#[test]
fn stringify_custom_sep_and_eq() {
    let src = r#"
        const qs = require('querystring');
        console.log(qs.stringify({ a: '1', b: '2' }, ';', ':'));
        console.log(qs.stringify({ a: '1', b: '2' }, '', ''));
    "#;
    assert_eq!(eval_console(src), "a:1;b:2\na=1&b=2");
}

#[test]
fn stringify_escapes_space_plus_and_unicode() {
    // bun: space -> %20 (never '+'), '+' -> %2B, multibyte chars byte-wise.
    let src = r#"
        const qs = require('querystring');
        console.log(qs.stringify({ a: 'x y', b: 'p+q' }));
        console.log(qs.stringify({ w: '中', v: 'café' }));
        console.log(qs.stringify({ 'k y': 'v&=' }));
    "#;
    assert_eq!(
        eval_console(src),
        "a=x%20y&b=p%2Bq\nw=%E4%B8%AD&v=caf%C3%A9\nk%20y=v%26%3D"
    );
}

#[test]
fn compat_corpus_0020_stringify_preserves_numeric_boolean_key_order_bd_n8eta() {
    let src = r#"
        const qs = require('querystring');
        console.log(qs.stringify({ n: 42, f: 1.5, t: true, x: false }));
    "#;
    assert_eq!(eval_console(src), "n=42&f=1.5&t=true&x=false");
}

#[test]
fn stringify_non_primitive_values_become_empty() {
    // bun: nested objects, null, undefined, NaN and Infinity all stringify
    // to an empty value.
    let src = r#"
        const qs = require('querystring');
        console.log(qs.stringify({ a: { nested: 1 }, b: 'ok' }));
        console.log(qs.stringify({ c: null }));
        console.log(qs.stringify({ a: undefined, b: null, c: NaN, d: Infinity }));
    "#;
    assert_eq!(eval_console(src), "a=&b=ok\nc=\na=&b=&c=&d=");
}

#[test]
fn stringify_non_object_input_is_empty_string() {
    // bun: stringify(undefined) | stringify(null) | stringify('str') are all ''.
    let src = r#"
        const qs = require('querystring');
        console.log(JSON.stringify(qs.stringify(undefined)));
        console.log(JSON.stringify(qs.stringify(null)));
        console.log(JSON.stringify(qs.stringify('str')));
    "#;
    assert_eq!(eval_console(src), "\"\"\n\"\"\n\"\"");
}

#[test]
fn stringify_parse_round_trip() {
    let src = r#"
        const qs = require('querystring');
        const s = qs.stringify({ a: 'x y', b: ['1', '2'] });
        console.log(s);
        const o = qs.parse(s);
        console.log(o.a, Array.isArray(o.b), o.b.join(','));
    "#;
    assert_eq!(eval_console(src), "a=x%20y&b=1&b=2\nx y true 1,2");
}

// -------------------------------------------------------------------------
// querystring.escape / unescape
// -------------------------------------------------------------------------

#[test]
fn escape_percent_encodes_outside_the_no_escape_set() {
    let src = r#"
        const qs = require('querystring');
        console.log(qs.escape('a b&c=d/e'));
        console.log(qs.escape('plain-safe_chars.ok'));
        console.log(qs.escape("!'()*-._~"));
    "#;
    assert_eq!(
        eval_console(src),
        "a%20b%26c%3Dd%2Fe\nplain-safe_chars.ok\n!'()*-._~"
    );
}

#[test]
fn escape_unicode_and_coercion() {
    // bun: qs.escape(42) is '42' (String() coercion before encoding).
    let src = r#"
        const qs = require('querystring');
        console.log(qs.escape('é'), qs.escape('中'));
        console.log(qs.escape(42), qs.escape(true));
    "#;
    assert_eq!(eval_console(src), "%C3%A9 %E4%B8%AD\n42 true");
}

#[test]
fn unescape_strict_decode_and_plus_preservation() {
    // bun: '+' is NOT decoded by unescape (only parse does plus-to-space).
    let src = r#"
        const qs = require('querystring');
        console.log(qs.unescape('a%20b%26c'), qs.unescape('%E4%B8%AD'));
        console.log(qs.unescape('x+y'));
    "#;
    assert_eq!(eval_console(src), "a b&c 中\nx+y");
}

#[test]
fn unescape_lenient_fallback_for_malformed_input() {
    // bun: malformed escapes stay literal ('%', '%z1', 'a%2'); an invalid
    // UTF-8 byte decodes to U+FFFD ('%FF').
    let src = r#"
        const qs = require('querystring');
        console.log(qs.unescape('%'), qs.unescape('%z1'), qs.unescape('a%2'));
        console.log(qs.unescape('%FF') === '�');
    "#;
    assert_eq!(eval_console(src), "% %z1 a%2\ntrue");
}

// -------------------------------------------------------------------------
// querystring module shapes: aliases, specifiers, inline receivers, spread
// -------------------------------------------------------------------------

#[test]
fn decode_and_encode_are_parse_and_stringify_aliases() {
    let src = r#"
        const qs = require('querystring');
        console.log(qs.decode('a=1').a);
        console.log(qs.encode({ a: '1' }));
    "#;
    assert_eq!(eval_console(src), "1\na=1");
}

#[test]
fn node_prefixed_querystring_specifier_is_recognized() {
    let src = r#"
        const qs = require('node:querystring');
        console.log(qs.escape('a b'));
    "#;
    assert_eq!(eval_console(src), "a%20b");
}

#[test]
fn inline_require_querystring_receiver() {
    let src = r#"
        console.log(require('querystring').escape('a b'));
        console.log(require('querystring').parse('a=1').a);
    "#;
    assert_eq!(eval_console(src), "a%20b\n1");
}

#[test]
fn querystring_spread_call_routes_through_reflect_apply() {
    let src = r#"
        const qs = require('querystring');
        const args = ['w:x;y:z', ';', ':'];
        const o = qs.parse(...args);
        console.log(o.w, o.y);
    "#;
    assert_eq!(eval_console(src), "x z");
}

#[test]
fn querystring_usage_inside_control_flow_confirms_the_alias() {
    let src = r#"
        const qs = require('querystring');
        try {
            console.log(qs.escape('a b'));
        } catch (e) {
            console.log('threw');
        }
    "#;
    assert_eq!(eval_console(src), "a%20b");
}

// -------------------------------------------------------------------------
// os constants (property reads)
// -------------------------------------------------------------------------

#[test]
fn os_eol_and_devnull_lower_to_string_constants() {
    let src = r#"
        const os = require('os');
        console.log(os.EOL === '\n', os.EOL.length);
        console.log(os.devNull, os.devNull === '/dev/null');
    "#;
    assert_eq!(eval_console(src), "true 1\n/dev/null true");
}

#[test]
fn os_constants_is_a_real_nested_object() {
    let src = r#"
        const os = require('os');
        console.log(typeof os.constants);
        console.log(typeof os.constants.signals);
        console.log(typeof os.constants.errno);
        console.log(typeof os.constants.priority);
    "#;
    assert_eq!(eval_console(src), "object\nobject\nobject\nobject");
}

#[test]
fn os_constants_signal_numbers_are_real_posix_values() {
    let src = r#"
        const os = require('os');
        console.log(os.constants.signals.SIGHUP === 1);
        console.log(os.constants.signals.SIGINT === 2);
        console.log(os.constants.signals.SIGKILL === 9);
        console.log(os.constants.signals.SIGTERM === 15);
        console.log(typeof os.constants.signals.SIGINT);
    "#;
    assert_eq!(eval_console(src), "true\ntrue\ntrue\ntrue\nnumber");
}

#[test]
fn os_constants_errno_and_priority_values() {
    let src = r#"
        const os = require('os');
        console.log(os.constants.errno.ENOENT === 2, os.constants.errno.ENOENT > 0);
        console.log(os.constants.errno.EACCES === 13, os.constants.errno.EEXIST === 17);
        console.log(os.constants.errno.EINVAL === 22);
        console.log(os.constants.priority.PRIORITY_NORMAL === 0);
        console.log(os.constants.priority.PRIORITY_HIGHEST === -20);
    "#;
    assert_eq!(eval_console(src), "true true\ntrue true\ntrue\ntrue\ntrue");
}

// -------------------------------------------------------------------------
// os identity/string methods (fixed engine-contained values)
// -------------------------------------------------------------------------

#[test]
fn os_platform_arch_type_endianness_machine() {
    let src = r#"
        const os = require('os');
        console.log(os.platform() === 'linux', typeof os.platform());
        console.log(os.arch() === 'x64');
        console.log(os.type() === 'Linux');
        console.log(os.endianness() === 'LE');
        console.log(os.machine() === 'x86_64');
    "#;
    assert_eq!(eval_console(src), "true string\ntrue\ntrue\ntrue\ntrue");
}

#[test]
fn os_platform_matches_injected_process_platform_shape() {
    // The injected `process` global carries the same fixed platform value as
    // the os builtin (both are engine-contained; no ambient read happens).
    let src = r#"
        const os = require('os');
        console.log(os.platform() === process.platform);
    "#;
    assert_eq!(eval_console(src), "true");
}

#[test]
fn os_release_version_hostname_are_nonempty_strings() {
    let src = r#"
        const os = require('os');
        console.log(typeof os.release(), os.release().length > 0);
        console.log(typeof os.version(), os.version().length > 0);
        console.log(typeof os.hostname(), os.hostname().length > 0);
    "#;
    assert_eq!(eval_console(src), "string true\nstring true\nstring true");
}

#[test]
fn os_homedir_tmpdir_interoperate_with_path_builtin() {
    // Mixed-family unit: `path` and `os` aliases confirmed independently in
    // one program (corpus fixtures 0007/0008 use exactly this shape).
    let src = r#"
        const os = require('os');
        const path = require('path');
        console.log(typeof os.homedir(), path.isAbsolute(os.homedir()));
        console.log(typeof os.tmpdir(), path.isAbsolute(os.tmpdir()), os.tmpdir().length > 0);
    "#;
    assert_eq!(eval_console(src), "string true\nstring true true");
}

// -------------------------------------------------------------------------
// os numeric/shape methods (fixed engine-contained values)
// -------------------------------------------------------------------------

#[test]
fn os_memory_uptime_and_parallelism_invariants() {
    let src = r#"
        const os = require('os');
        console.log(typeof os.totalmem(), os.totalmem() > 0, Number.isFinite(os.totalmem()));
        console.log(typeof os.freemem(), os.freemem() > 0, os.freemem() <= os.totalmem());
        console.log(typeof os.uptime(), os.uptime() > 0);
        console.log(typeof os.availableParallelism(), os.availableParallelism() > 0, Number.isInteger(os.availableParallelism()));
    "#;
    assert_eq!(
        eval_console(src),
        "number true true\nnumber true true\nnumber true\nnumber true true"
    );
}

#[test]
fn os_loadavg_is_three_nonnegative_numbers() {
    let src = r#"
        const os = require('os');
        const la = os.loadavg();
        console.log(Array.isArray(la), la.length);
        console.log(la.every((v) => typeof v === 'number' && v >= 0));
    "#;
    assert_eq!(eval_console(src), "true 3\ntrue");
}

#[test]
fn os_cpus_is_nonempty_with_typed_shape() {
    let src = r#"
        const os = require('os');
        const cpus = os.cpus();
        console.log(Array.isArray(cpus), cpus.length > 0);
        const c = cpus[0];
        console.log(typeof c.model, typeof c.speed, typeof c.times);
        console.log(typeof c.times.user === 'number' && typeof c.times.idle === 'number');
        console.log(typeof c.times.nice === 'number' && typeof c.times.sys === 'number' && typeof c.times.irq === 'number');
    "#;
    assert_eq!(
        eval_console(src),
        "true true\nstring number object\ntrue\ntrue"
    );
}

#[test]
fn os_network_interfaces_is_an_empty_object_map() {
    let src = r#"
        const os = require('os');
        const ni = os.networkInterfaces();
        console.log(typeof ni, ni !== null);
        console.log(Object.keys(ni).length);
    "#;
    assert_eq!(eval_console(src), "object true\n0");
}

#[test]
fn os_user_info_shape() {
    let src = r#"
        const os = require('os');
        const u = os.userInfo();
        console.log(typeof u.username, typeof u.uid, typeof u.gid, typeof u.homedir);
        console.log(u.shell === null || typeof u.shell === 'string');
        console.log(u.uid >= 0);
    "#;
    assert_eq!(eval_console(src), "string number number string\ntrue\ntrue");
}

// -------------------------------------------------------------------------
// os.getPriority / os.setPriority (argument validation)
// -------------------------------------------------------------------------

#[test]
fn get_priority_returns_zero_for_every_pid_form() {
    let src = r#"
        const os = require('os');
        console.log(typeof os.getPriority(), Number.isInteger(os.getPriority()));
        console.log(os.getPriority() >= -20 && os.getPriority() <= 19);
        console.log(os.getPriority(0) === os.getPriority());
        console.log(os.getPriority(0) === os.getPriority(process.pid));
        console.log(typeof process.pid, process.pid === 1);
    "#;
    // The PID is a fixed engine-contained shape value, never the host process id.
    assert_eq!(
        eval_console(src),
        "number true\ntrue\ntrue\ntrue\nnumber true"
    );
}

#[test]
fn get_priority_non_number_pid_throws_catchable_err_invalid_arg_type() {
    let src = r#"
        const os = require('os');
        try {
            os.getPriority('not-a-pid');
            console.log('no-throw');
        } catch (err) {
            console.log('threw:' + (err instanceof TypeError));
            console.log('code:' + err.code);
        }
    "#;
    assert_eq!(eval_console(src), "threw:true\ncode:ERR_INVALID_ARG_TYPE");
}

#[test]
fn set_priority_non_number_pid_throws_catchable_err_invalid_arg_type() {
    // Corpus fixture 0026: the thrown error must be a real, JS-catchable
    // TypeError (`instanceof` holds) carrying Node's ERR_INVALID_ARG_TYPE code.
    let src = r#"
        const os = require('os');
        try {
            os.setPriority('not-a-pid', 0);
            console.log('no-throw');
        } catch (err) {
            console.log('threw:' + (err instanceof TypeError));
            console.log('code:' + err.code);
        }
    "#;
    assert_eq!(eval_console(src), "threw:true\ncode:ERR_INVALID_ARG_TYPE");
}

#[test]
fn set_priority_out_of_range_throws_catchable_err_out_of_range() {
    // Corpus fixture 0027: an out-of-[-20, 19] priority is a JS-catchable
    // RangeError carrying Node's ERR_OUT_OF_RANGE code.
    let src = r#"
        const os = require('os');
        try {
            os.setPriority(0, 1000);
            console.log('no-throw');
        } catch (err) {
            console.log('threw:' + (err instanceof RangeError));
            console.log('code:' + err.code);
        }
    "#;
    assert_eq!(eval_console(src), "threw:true\ncode:ERR_OUT_OF_RANGE");
}

#[test]
fn set_priority_single_argument_form_and_valid_calls() {
    // Node: setPriority(priority) defaults pid to 0; a valid call returns
    // undefined. The single-argument form still range-checks the priority.
    let src = r#"
        const os = require('os');
        console.log(os.setPriority(0, 10) === undefined);
        console.log(os.setPriority(5) === undefined);
        try {
            os.setPriority(1000);
            console.log('no-throw');
        } catch (err) {
            console.log('threw:' + (err instanceof RangeError));
        }
    "#;
    assert_eq!(eval_console(src), "true\ntrue\nthrew:true");
}

// -------------------------------------------------------------------------
// os module shapes: specifiers, inline receivers, spread
// -------------------------------------------------------------------------

#[test]
fn node_prefixed_os_specifier_is_recognized() {
    let src = r#"
        const os = require('node:os');
        console.log(os.platform(), os.EOL === '\n');
    "#;
    assert_eq!(eval_console(src), "linux true");
}

#[test]
fn inline_require_os_receiver() {
    let src = r#"
        console.log(require('os').platform());
        console.log(require('os').EOL === '\n');
        console.log(require('os').constants.signals.SIGINT);
    "#;
    assert_eq!(eval_console(src), "linux\ntrue\n2");
}

#[test]
fn os_spread_call_routes_through_reflect_apply() {
    let src = r#"
        const os = require('os');
        const args = [0, 10];
        console.log(os.setPriority(...args) === undefined);
    "#;
    assert_eq!(eval_console(src), "true");
}

// -------------------------------------------------------------------------
// fail-closed contract
// -------------------------------------------------------------------------

#[test]
fn unused_querystring_alias_loads_without_filesystem_authority_bd_305gi() {
    // bd-305gi replaces the old syntactic usage gate: loading a pure module
    // is valid even when the program only detects its presence.
    assert_eq!(
        eval_console("const qs = require('querystring');\nconsole.log('reached');"),
        "reached"
    );
}

#[test]
fn unused_os_alias_keeps_ambient_denial() {
    let err = eval_err("const os = require('os');\nconsole.log('reached');");
    assert!(
        err.contains("ambient authority violation"),
        "expected ambient-authority denial for unused os alias, got: {err}"
    );
}

#[test]
fn querystring_usage_inside_function_body_uses_the_module_bd_305gi() {
    assert_eq!(
        eval_console(
            "const qs = require('querystring');\nfunction f() { return qs.escape('a b'); }\nconsole.log(f());",
        ),
        "a%20b"
    );
}

#[test]
fn os_usage_only_inside_function_body_stays_fail_closed() {
    let err = eval_err(
        "const os = require('os');\nfunction f() { return os.platform(); }\nconsole.log(f());",
    );
    assert!(
        err.contains("ambient authority violation"),
        "expected ambient-authority denial for function-body-only usage, got: {err}"
    );
}

#[test]
fn unrecognized_method_does_not_confirm_the_aliases() {
    // querystring is an ordinary module: an absent method throws TypeError
    // at invocation, so feature detection and catch handlers can work.
    assert_eq!(
        eval_console(
            "const qs = require('querystring'); try { qs.notAMethod('x'); } \
             catch (error) { console.log(error instanceof TypeError); }",
        ),
        "true"
    );
    // os still uses the pre-existing syntactic facade.
    let err = eval_err("const os = require('os');\nconsole.log(os.notAMethod());");
    assert!(
        err.contains("ambient authority violation"),
        "expected ambient-authority denial for unrecognized-method-only usage, got: {err}"
    );
}

#[test]
fn querystring_module_values_and_detached_methods_work_bd_305gi() {
    assert_eq!(
        eval_console(
            r#"
                const qs = require('querystring');
                const { parse, stringify, escape, unescape } = require('node:querystring');
                const alias = qs;
                function invoke(fn, value) { return fn(value); }
                console.log(typeof qs, typeof parse, alias === require('node:querystring'));
                console.log(qs.parse === qs.decode, qs.stringify === qs.encode);
                console.log(parse.name, parse.length, stringify.name, stringify.length,
                    escape.name, escape.length, unescape.name, unescape.length);
                console.log(parse('a=one&a=two').a.join(','));
                console.log(stringify({ a: ['one', 'two'], b: 'a b' }));
                console.log(invoke(escape, 'a b'), unescape('a%20b'));
                const key = 'escape';
                console.log(qs[key]('x+y'));
            "#,
        ),
        "object function true\ntrue true\nparse 4 stringify 4 qsEscape 1 qsUnescape 2\none,two\na=one&a=two&b=a%20b\na%20b a b\nx%2By"
    );
}

#[test]
fn querystring_methods_observe_property_mutation_bd_305gi() {
    assert_eq!(
        eval_console(
            r#"
                const qs = require('querystring');
                const original = qs.escape;
                qs.escape = value => 'wrapped:' + original(value);
                console.log(qs.escape('a b'));
                console.log(require('node:querystring').escape('c d'));
                delete qs.escape;
                console.log(typeof qs.escape, original('e f'));
            "#,
        ),
        "wrapped:a%20b\nwrapped:c%20d\nundefined e%20f"
    );
}

fn run_querystring_commonjs(
    source: &str,
    sibling: Option<&str>,
    lane: LaneChoice,
    builtin: bool,
) -> Result<Vec<String>, String> {
    run_querystring_commonjs_with_environment(source, sibling, lane, builtin, None)
}

fn run_querystring_commonjs_with_environment(
    source: &str,
    sibling: Option<&str>,
    lane: LaneChoice,
    builtin: bool,
    environment: Option<std::collections::BTreeMap<String, String>>,
) -> Result<Vec<String>, String> {
    let root = tempfile::tempdir().expect("module root");
    let entry = root.path().join("entry.cjs");
    std::fs::write(&entry, source).expect("entry source");
    if let Some(source) = sibling {
        std::fs::write(root.path().join("sibling.cjs"), source).expect("sibling source");
    }
    let mut capabilities = vec![
        "vm_dispatch".to_string(),
        "heap_allocate".to_string(),
        "console".to_string(),
        "module_load".to_string(),
    ];
    if builtin {
        capabilities.push("builtin".to_string());
    }
    if environment.is_some() {
        capabilities.push("env_read".to_string());
    }
    let package = ExtensionPackage {
        extension_id: "querystring-module-values".to_string(),
        source: source.to_string(),
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.path().display().to_string()),
        capabilities,
        version: "1.0.0".to_string(),
        metadata: Default::default(),
    };
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        parse_goal: ParseGoal::Script,
        commonjs_entry: true,
        ..OrchestratorConfig::default()
    });
    if let Some(environment) = environment {
        let provider =
            frankenengine_extension_host::host_io::EnvironmentSnapshotHostIo::new(environment)
                .expect("explicit environment fixture");
        orchestrator.set_host_io(std::sync::Arc::new(provider), None);
    }
    orchestrator
        .execute(&package)
        .map(|result| {
            result
                .console_output
                .into_iter()
                .map(|entry| entry.message)
                .collect()
        })
        .map_err(|error| format!("{error:?}"))
}

#[test]
fn querystring_dynamic_require_shares_realm_module_across_files_bd_305gi() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let lines = run_querystring_commonjs(
            r#"
                const qs = require('querystring');
                const name = 'node:querystring';
                const dynamic = require(name);
                const sibling = require('./sibling.cjs');
                console.log(qs === dynamic, qs === sibling, qs.parse === sibling.decode);
                console.log(qs.marker, sibling.stringify({ a: 'b c' }));
                const load = require;
                console.log(load('querystring') === qs);
            "#,
            Some(
                "const name = 'querystring'; const qs = require(name); \
                 qs.marker = 'from-sibling'; module.exports = qs;",
            ),
            lane,
            true,
        )
        .unwrap_or_else(|error| panic!("{lane:?}: {error}"));
        assert_eq!(
            lines,
            ["true true true", "from-sibling a=b%20c", "true"],
            "{lane:?}"
        );
    }
}

#[test]
fn querystring_dynamic_methods_keep_the_builtin_capability_gate_bd_305gi() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let error = run_querystring_commonjs(
            "const name = 'querystring'; const parse = require(name).parse; parse('a=1');",
            None,
            lane,
            false,
        )
        .expect_err("extracting a method must not grant Builtin authority");
        assert!(error.contains("CapabilityDenied"), "{lane:?}: {error}");
        assert!(
            error.contains("builtin:QuerystringParse"),
            "{lane:?}: {error}"
        );
    }
}

#[test]
fn querystring_cross_file_replacement_keeps_captured_secret_provenance_bd_305gi() {
    // Reflect.set is an internal labeled transfer. Ordinary property stores
    // have an Internal static clearance and refuse this closure before the
    // parent can observe the cached module, so use the explicit reflective
    // operation to exercise the actual result and egress boundary.
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let error = run_querystring_commonjs_with_environment(
            "const qs = require('querystring'); require('./sibling.cjs'); \
             console.log(qs.escape('public input'));",
            Some(
                "const qs = require('node:querystring'); \
                 const captured = process.env.PRIVATE_KEY; \
                 Reflect.set(qs, 'escape', () => captured);",
            ),
            lane,
            true,
            Some(std::collections::BTreeMap::from([(
                "PRIVATE_KEY".to_string(),
                "secret-fixture".to_string(),
            )])),
        )
        .expect_err("a cached module may contain a sibling's Secret-returning closure");
        assert!(
            error.contains("console:log:confidentiality"),
            "{lane:?}: the replacement must run and its result must stop at the sink: {error}"
        );
    }
}

#[test]
fn querystring_detached_methods_do_not_declassify_secret_inputs_bd_305gi() {
    use frankenengine_engine::baseline_interpreter::{
        InterpreterConfig, InterpreterCore, InterpreterError, Value,
    };
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::hash_tiers::ContentHash;
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::{CapabilityTag, Ir3Instruction, Ir3Module, RegRange};

    // A literal's spelling is not provenance. Seed the same bytes with two
    // real labels, then extract and call the realm module's native method.
    // This bypasses the static analysis and checks the runtime sink itself.
    let mut module = Ir3Module::new(ContentHash::compute(b"querystring-ifc"), "querystring-ifc");
    module.constant_pool = vec!["escape".into()];
    module.instructions = vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("builtin:QuerystringModule".into()),
            args: RegRange { start: 0, count: 0 },
            dst: 1,
        },
        Ir3Instruction::LoadStr {
            dst: 2,
            pool_index: 0,
        },
        Ir3Instruction::GetProperty {
            obj: 1,
            key: 2,
            dst: 3,
        },
        Ir3Instruction::Call {
            callee: 3,
            args: RegRange { start: 0, count: 1 },
            dst: 4,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("console:log".into()),
            args: RegRange { start: 4, count: 1 },
            dst: 5,
        },
        Ir3Instruction::Return { value: 4 },
    ];

    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for input_label in [Label::Public, Label::Secret] {
            let mut config = match lane {
                LaneChoice::QuickJs => InterpreterConfig::quickjs_defaults(),
                LaneChoice::V8 => InterpreterConfig::v8_defaults(),
            };
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "querystring-ifc");
            core.seed_register(0, Value::str("sensitive value"))
                .expect("seed querystring argument");
            core.set_register_label(0, input_label.clone())
                .expect("label querystring argument");

            let outcome = core.execute(&module);
            assert_eq!(
                core.get_register_label(4).expect("transformed label"),
                &input_label,
                "{lane:?}: the extracted method must preserve input provenance"
            );
            if input_label == Label::Public {
                assert_eq!(
                    outcome.expect("Public input may reach the console").value,
                    Value::str("sensitive%20value"),
                    "{lane:?}"
                );
                assert_eq!(core.console_output().len(), 1, "{lane:?}");
                assert_eq!(
                    core.console_output()[0].message,
                    "sensitive%20value",
                    "{lane:?}"
                );
            } else {
                assert!(
                    matches!(&outcome, Err(InterpreterError::CapabilityDenied { capability })
                        if capability == "console:log:confidentiality"),
                    "{lane:?}: Secret input must be refused at the sink: {outcome:?}"
                );
                assert!(core.console_output().is_empty(), "{lane:?}");
            }
        }
    }
}

#[test]
fn shadowed_require_remains_ordinary_lexical_user_code() {
    // A user binding named `require` must not be treated as the CJS loader:
    // the module recognizers decline, then the ordinary lexical closure and
    // property-call semantics remain available to the program.
    assert_eq!(
        eval_console(
            "const require = (name) => ({ escape: () => 'shadowed:' + name });\nconst qs = require('querystring');\nconsole.log(qs.escape('a'));",
        ),
        "shadowed:querystring"
    );
}

// -------------------------------------------------------------------------
// interplay
// -------------------------------------------------------------------------

#[test]
fn querystring_and_os_families_coexist_in_one_unit() {
    let src = r#"
        const qs = require('querystring');
        const os = require('os');
        console.log(qs.escape('a b') + os.EOL.length);
        console.log(qs.parse('p=' + os.platform()).p);
    "#;
    assert_eq!(eval_console(src), "a%20b1\nlinux");
}
