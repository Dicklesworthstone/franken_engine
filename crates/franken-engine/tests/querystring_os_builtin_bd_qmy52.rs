//! bd-qmy52: `require('querystring')` and `require('os')` as pure-compute
//! builtins.
//!
//! The lowering pipeline recognizes `const qs = require('querystring')` /
//! `const os = require('os')` bindings that are actually USED as a recognized
//! builtin (usage-gated exactly like the fs/http/path aliases), elides the
//! require declaration, and rewrites member calls to `builtin:Querystring*` /
//! `builtin:Os*` hostcalls. The deterministic `os` property constants
//! (`os.EOL`, `os.devNull`) lower to string literals and `os.constants` to a
//! 0-arg `builtin:OsConstants` hostcall allocating the nested
//! `{ signals, errno, priority }` object. Bare/unused aliases keep the
//! ambient-authority denial (fail-closed contract pinned below).
//!
//! The `os` builtins return FIXED engine-contained values (the engine has no
//! ambient authority); querystring escape/unescape/parse/stringify edge
//! behaviors are pinned against `bun` 1.3.14 (Node-compatible reference) runs
//! of the compat corpus at
//! `franken_node/crates/franken-node/tests/fixtures/compat_corpus/{querystring,os}/`.

use frankenengine_engine::HybridRouter;

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
fn parse_basic_pairs() {
    let src = r#"
        const qs = require('querystring');
        const o = qs.parse('foo=bar&abc=xyz');
        console.log(o.foo, o.abc);
    "#;
    assert_eq!(eval_console(src), "bar xyz");
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
    // Keys chosen already in the engine's deterministic (sorted) property
    // order so the assertion is order-independent (see DISC-013 pin below).
    let src = r#"
        const qs = require('querystring');
        console.log(qs.stringify({ abc: 'xyz', foo: 'bar' }));
    "#;
    assert_eq!(eval_console(src), "abc=xyz&foo=bar");
}

#[test]
fn stringify_key_order_is_engine_deterministic_order_disc_013() {
    // DISC-013 (bd-qporw): engine objects enumerate own string keys in
    // deterministic BTreeMap order, not ECMAScript insertion order. Node/bun
    // emit 'foo=bar&baz=qux' here; the engine's deterministic storage yields
    // the sorted order. This pin is intentional — it documents the known
    // divergence rather than conformance.
    let src = r#"
        const qs = require('querystring');
        console.log(qs.stringify({ foo: 'bar', baz: 'qux' }));
    "#;
    assert_eq!(eval_console(src), "baz=qux&foo=bar");
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
        console.log(qs.stringify({ v: 'café', w: '中' }));
        console.log(qs.stringify({ 'k y': 'v&=' }));
    "#;
    assert_eq!(
        eval_console(src),
        "a=x%20y&b=p%2Bq\nv=caf%C3%A9&w=%E4%B8%AD\nk%20y=v%26%3D"
    );
}

#[test]
fn stringify_numbers_and_booleans() {
    let src = r#"
        const qs = require('querystring');
        console.log(qs.stringify({ f: 1.5, n: 42, t: true, x: false }));
        console.log(qs.stringify({ a: [1, 'x', true] }));
    "#;
    assert_eq!(
        eval_console(src),
        "f=1.5&n=42&t=true&x=false\na=1&a=x&a=true"
    );
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
fn unused_querystring_alias_keeps_ambient_denial() {
    // The fail-closed contract (mirror of the fs/path usage gates): a
    // bare/unused `const qs = require('querystring')` is NOT recognized, so
    // the require call still hits the ambient-authority lowering denial.
    let err = eval_err("const qs = require('querystring');\nconsole.log('reached');");
    assert!(
        err.contains("ambient authority violation"),
        "expected ambient-authority denial for unused querystring alias, got: {err}"
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
fn querystring_usage_only_inside_function_body_stays_fail_closed() {
    // Function bodies are opaque to the usage scan (fail-closed): a usage
    // reachable only through a function body does NOT confirm the alias.
    let err = eval_err(
        "const qs = require('querystring');\nfunction f() { return qs.escape('a b'); }\nconsole.log(f());",
    );
    assert!(
        err.contains("ambient authority violation"),
        "expected ambient-authority denial for function-body-only usage, got: {err}"
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
    // `qs.notAMethod` / `os.notAMethod` are outside the recognized sets; with
    // no other usage the aliases stay unconfirmed and the requires denied.
    let err = eval_err("const qs = require('querystring');\nconsole.log(qs.notAMethod('x'));");
    assert!(
        err.contains("ambient authority violation"),
        "expected ambient-authority denial for unrecognized-method-only usage, got: {err}"
    );
    let err = eval_err("const os = require('os');\nconsole.log(os.notAMethod());");
    assert!(
        err.contains("ambient authority violation"),
        "expected ambient-authority denial for unrecognized-method-only usage, got: {err}"
    );
}

#[test]
fn shadowed_require_is_not_recognized_as_module_initializer() {
    // A user binding named `require` must not be treated as the CJS loader:
    // the recognizers decline (fail-closed) and the engine's pre-existing
    // bare-identifier ambient gate denies the reference regardless.
    let err = eval_err(
        "const require = (name) => ({ escape: () => 'shadowed:' + name });\nconst qs = require('querystring');\nconsole.log(qs.escape('a'));",
    );
    assert!(
        err.contains("ambient authority violation"),
        "expected the pre-existing ambient denial for shadowed require, got: {err}"
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
