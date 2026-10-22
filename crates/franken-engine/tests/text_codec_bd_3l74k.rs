//! bd-3l74k: TextEncoder and TextDecoder (WHATWG Encoding) as pure builtins.
//!
//! `typeof TextEncoder` was "undefined" (Node: "function"). The expected line
//! is Node v22.2.0's output for the same program: encode (BMP, astral and a
//! lone surrogate), encodeInto stopping at a whole character, decode with and
//! without a BOM, malformed utf-8 replaced or fatal, utf-16le, windows-1252
//! (`latin1`), an unsupported label, and ArrayBuffer/DataView/subarray inputs.
//!
//! No-claim: `decode`'s `stream` option; encodings other than utf-8,
//! utf-16le and windows-1252; the DOMException-style error codes Node attaches.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = "var te = new TextEncoder();\nvar r = [];\nr.push(te.encoding, Array.from(te.encode('AB')).join(), Array.from(te.encode('\u{e9}\u{20ac}\u{1d11e}')).join(), te.encode('\\ud800x').join(), te.encode().length, te.encode(5).join());\nr.push(Object.prototype.toString.call(te.encode('hi')), Object.keys(te).length, typeof TextEncoder, TextEncoder.name, te.encode.length, te.encodeInto.length);\nvar buf = new Uint8Array(4);\nvar res = te.encodeInto('a\u{20ac}b', buf);\nr.push(res.read, res.written, Array.from(buf).join());\nvar td = new TextDecoder();\nr.push(td.encoding, td.fatal, td.ignoreBOM, td.decode(new Uint8Array([72, 105])), td.decode(new Uint8Array([0xEF, 0xBB, 0xBF, 65])), td.decode(new Uint8Array([0xE2, 0x82])) === '\u{fffd}', td.decode(), td.decode(new Uint8Array([0xF0, 0x9D, 0x84, 0x9E]).buffer));\nvar tf = new TextDecoder('utf-8', { fatal: true });\ntry { tf.decode(new Uint8Array([0xFF])); r.push('nothrow'); } catch (e) { r.push(e.name); }\nr.push(new TextDecoder('utf-16le').decode(new Uint8Array([65, 0, 66, 0])), new TextDecoder('latin1').encoding, new TextDecoder('latin1').decode(new Uint8Array([0xE9, 0x80])));\ntry { new TextDecoder('nope'); } catch (e) { r.push(e.name); }\nr.push(new TextDecoder('utf-8', { ignoreBOM: true }).decode(new Uint8Array([0xEF, 0xBB, 0xBF, 65])).length);\nr.push(td.decode(new DataView(new Uint8Array([111, 107]).buffer)), td.decode(new Uint8Array([97, 98, 99]).subarray(1)));\nr.push(te.encode('hi') instanceof Uint8Array);\nconsole.log(r.join('|'));";

/// Node v22.2.0's output for `PROGRAM`.
const NODE_OUTPUT: &str = "utf-8|65,66|195,169,226,130,172,240,157,132,158|239,191,189,120|0|53|[object Uint8Array]|0|function|TextEncoder|0|2|2|4|97,226,130,172|utf-8|false|false|Hi|A|true||\u{1d11e}|TypeError|AB|windows-1252|\u{e9}\u{20ac}|RangeError|2|ok|bc|true";

fn console_output(source: &str) -> Result<String, String> {
    console_output_with_config(source, InterpreterConfig::quickjs_defaults(), None)
}

fn console_output_with_config(
    source: &str,
    mut config: InterpreterConfig,
    stress: Option<u64>,
) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "codec.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "codec.js"),
        &LoweringContext::new("codec-trace", "codec-decision", "codec-policy"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "codec");
    core.set_gc_stress_interval(stress);
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift: {source}"
    );
    let result = result.map_err(|error| format!("{error:?}"))?;
    Ok(result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

#[test]
fn text_encoder_and_decoder_match_node() {
    assert_eq!(console_output(PROGRAM).as_deref(), Ok(NODE_OUTPUT));
}

#[test]
fn prototype_codec_methods_are_callable_and_keep_receiver_validation() {
    let source = r#"
const encode = TextEncoder.prototype.encode;
const encodeInto = TextEncoder.prototype.encodeInto;
const decode = TextDecoder.prototype.decode;
const descriptor = Object.getOwnPropertyDescriptor(TextDecoder.prototype, 'decode');
console.log(typeof encode, typeof encodeInto, typeof decode,
  descriptor.value === decode, descriptor.writable, descriptor.configurable);
const encoder = new TextEncoder(), decoder = new TextDecoder();
console.log(encode.call(encoder, 'é').join(','));
const target = new Uint8Array(3), result = encodeInto.call(encoder, '€', target);
console.log(result.read, result.written, decode.call(decoder, target));
let refused = 0;
for (const method of [encode, encodeInto, decode]) {
  try { method.call({}); } catch (error) { if (error.name === 'TypeError') refused++; }
}
console.log(refused);
delete TextDecoder.prototype.decode;
console.log(typeof TextDecoder.prototype.decode, typeof decoder.decode, typeof decode);
TextDecoder.prototype.decode = decode;
console.log(decoder.decode(new Uint8Array([65])));
"#;
    let expected = "function function function true true true\n195,169\n1 3 €\n3\nundefined undefined function\nA";
    for config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        for stress in [None, Some(1), Some(7)] {
            assert_eq!(
                console_output_with_config(source, config.clone(), stress).as_deref(),
                Ok(expected),
                "GC={stress:?}"
            );
        }
    }
}
