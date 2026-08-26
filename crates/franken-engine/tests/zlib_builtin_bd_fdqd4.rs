//! bd-fdqd4: bounded pure-compute Node `zlib` builtins.

use frankenengine_engine::HybridRouter;

fn eval_console(source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn eval_error(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => panic!("expected eval failure for {source:?}, got {outcome:?}"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn gzip_sync_roundtrips_strings_buffers_empty_input_and_magic_header() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        const text = 'hello zlib world';
        const stringCompressed = zlib.gzipSync(text);
        const bufferCompressed = zlib.gzipSync(Buffer.from(text));
        console.log(zlib.gunzipSync(stringCompressed).toString('utf8'));
        console.log(stringCompressed.equals(bufferCompressed));
        console.log(stringCompressed[0], stringCompressed[1]);
        console.log(zlib.gunzipSync(zlib.gzipSync('')).length);
        "#,
    );
    assert_eq!(output, "hello zlib world\ntrue\n31 139\n0");
}

#[test]
fn zlib_and_raw_sync_roundtrip_and_unzip_autodetects_wrappers() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        const source = Buffer.from('wrapped and raw payload');
        const wrapped = zlib.deflateSync(source);
        const raw = zlib.deflateRawSync(source);
        console.log(zlib.inflateSync(wrapped).toString());
        console.log(zlib.inflateRawSync(raw).toString());
        console.log(zlib.unzipSync(wrapped).toString());
        console.log(zlib.unzipSync(zlib.gzipSync(source)).toString());
        "#,
    );
    assert_eq!(
        output,
        "wrapped and raw payload\nwrapped and raw payload\nwrapped and raw payload\nwrapped and raw payload"
    );
}

#[test]
fn levels_constants_large_input_and_all_byte_values_match_node_shapes() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        const repeated = 'a'.repeat(10000);
        const high = zlib.gzipSync(repeated, { level: 9 });
        const none = zlib.gzipSync(repeated, { level: 0 });
        console.log(high.length < none.length, zlib.gunzipSync(high).length);
        const bytes = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
        console.log(zlib.inflateSync(zlib.deflateSync(bytes)).equals(bytes));
        console.log(
          zlib.constants.Z_BEST_COMPRESSION,
          zlib.constants.Z_NO_COMPRESSION,
          zlib.constants.Z_DEFAULT_COMPRESSION,
          typeof zlib.constants.BROTLI_PARAM_QUALITY
        );
        "#,
    );
    assert_eq!(output, "true 10000\ntrue\n9 0 -1 number");
}

#[test]
fn preset_dictionary_roundtrips_and_missing_or_wrong_dictionary_needs_dictionary() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        const dictionary = Buffer.from('the quick brown fox');
        const compressed = zlib.deflateSync('the quick brown fox jumps', { dictionary });
        console.log(zlib.inflateSync(compressed, { dictionary }).toString());
        for (const options of [undefined, { dictionary: Buffer.from('wrong') }]) {
          try {
            zlib.inflateSync(compressed, options);
            console.log('no-throw');
          } catch (error) {
            console.log(error instanceof Error, error.code);
          }
        }
        "#,
    );
    assert_eq!(
        output,
        "the quick brown fox jumps\ntrue Z_NEED_DICT\ntrue Z_NEED_DICT"
    );
}

#[test]
fn gzip_ignores_dictionary_options_like_node() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        const dictionary = Buffer.from('ignored by gzip framing');
        const compressed = zlib.gzipSync('gzip dictionary option', { dictionary });
        console.log(zlib.gunzipSync(compressed, { dictionary }).toString());
        "#,
    );
    assert_eq!(output, "gzip dictionary option");
}

#[test]
fn malformed_sync_stream_throws_node_style_error() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        try {
          zlib.gunzipSync(Buffer.from('not gzip'));
          console.log('no-throw');
        } catch (error) {
          console.log(error instanceof Error, error.code);
        }
        "#,
    );
    assert_eq!(output, "true Z_DATA_ERROR");
}

#[test]
fn async_gzip_and_deflate_are_deferred_and_nested_alias_calls_survive() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        zlib.gzip('async gzip', (gzipError, compressed) => {
          console.log(gzipError === null);
          zlib.gunzip(compressed, (gunzipError, output) => {
            console.log(gunzipError === null, output.toString());
          });
        });
        zlib.deflate('async zlib', (deflateError, compressed) => {
          console.log(deflateError === null);
          zlib.inflate(compressed, (inflateError, output) => {
            console.log(inflateError === null, output.toString());
          });
        });
        console.log('sync');
        "#,
    );
    assert_eq!(output, "sync\ntrue\ntrue\ntrue async gzip\ntrue async zlib");
}

#[test]
fn async_malformed_stream_reports_error_and_explicit_undefined_result() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        zlib.gunzip(Buffer.from('bad'), (error, output) => {
          console.log(error instanceof Error, error.code, output === undefined);
        });
        console.log('sync');
        "#,
    );
    assert_eq!(output, "sync\ntrue Z_DATA_ERROR true");
}

#[test]
fn node_specifier_and_nested_parameter_shadowing_are_preserved() {
    let output = eval_console(
        r#"
        const zlib = require('node:zlib');
        console.log(zlib.gunzipSync(zlib.gzipSync('node-prefix')).toString());
        const local = ((zlib) => zlib.gzipSync('local'))({ gzipSync: (value) => value });
        console.log(local);
        "#,
    );
    assert_eq!(output, "node-prefix\nlocal");
}

#[test]
fn unsupported_or_unconsumed_module_aliases_remain_fail_closed() {
    for source in [
        "const zlib = require('zlib'); zlib;",
        "const zlib = require('zlib'); zlib.brotliCompressSync('x');",
        "const zlib = require('zlib'); zlib['gzipSync']('x');",
        "const name = 'zlib'; require(name).gzipSync('x');",
        "const zlib = require('zlib'); { const zlib = { gzipSync: (x) => x }; zlib.gzipSync('x'); }",
        "let zlib = require('zlib'); zlib = { gzipSync: (x) => x }; zlib.gzipSync('x');",
        "const zlib = require('zlib'); zlib.gzipSync = (x) => x; zlib.gzipSync('x');",
        "const zlib = require('zlib'); zlib.constants = {}; zlib.gzipSync('x');",
        "const zlib = require('zlib'); zlib.constants.Z_BEST_COMPRESSION = 1; console.log(zlib.constants.Z_BEST_COMPRESSION);",
        "const zlib = require('zlib'); consume(zlib); zlib.gzipSync('x');",
    ] {
        let error = eval_error(source);
        assert!(
            error.contains("require")
                || error.contains("ambient")
                || error.contains("capability")
                || error.contains("module"),
            "unexpected fail-closed error for {source:?}: {error}"
        );
    }
}

// bd-znj5l: the three residual product-corpus fixtures
// (/dp/franken_node compat_corpus/zlib tc::zlib::0004/0009/0016) replayed at
// the engine boundary with identical sources and expected stdout.

#[test]
fn brotli_sync_roundtrip_matches_fixture_tc_zlib_0004_bd_znj5l() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        const input = 'brotli roundtrip content';
        const out = zlib.brotliDecompressSync(zlib.brotliCompressSync(input)).toString('utf8');
        console.log(out);
        console.log(out === input);
        "#,
    );
    assert_eq!(output, "brotli roundtrip content\ntrue");
}

#[test]
fn brotli_decompress_corrupt_input_throws_error_like_fixture_tc_zlib_0009_bd_znj5l() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        try {
          zlib.brotliDecompressSync(Buffer.from([1, 2, 3, 4, 5]));
          console.log('no-throw');
        } catch (e) {
          console.log(e instanceof Error);
        }
        "#,
    );
    assert_eq!(output, "true");
}

#[ignore = "bd-znj5l residual: static IFC lane downgrades object literals with computed keys (even closed-primitive key exprs like zlib.constants.BROTLI_PARAM_QUALITY) out of FreshAggregate, so the options bag fails hostcall_exception_is_operand_derived and the compress result taints TopSecret. Runtime quality-param support is live (params_plain_key probes pass). Un-ignore when computed-key freshness inference lands."]
#[test]
fn brotli_quality_param_roundtrip_matches_fixture_tc_zlib_0016_bd_znj5l() {
    let output = eval_console(
        r#"
        const zlib = require('zlib');
        const opts = { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } };
        const c = zlib.brotliCompressSync('brotli with quality option', opts);
        console.log(zlib.brotliDecompressSync(c).toString('utf8'));
        "#,
    );
    assert_eq!(output, "brotli with quality option");
}
