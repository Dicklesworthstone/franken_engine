//! Stateful string decoding through the native parser/lowerer/interpreter.
//! The JS fixtures are also executed by the host differential runner, which
//! does not substitute for these native or memory-accounting tests.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn check(source: &str, expected: &str, goal: ParseGoal) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "string-decoder.js".into(),
                text: source.into(),
            },
            goal,
            &ParserOptions::default(),
        )
        .expect("decoder fixture parses");
    let lowered = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "string-decoder.js"),
        &LoweringContext::new("string-decoder", "bd-305gi", "builtin-only"),
    )
    .expect("decoder fixture lowers");
    for v8_profile in [false, true] {
        for stress in [None, Some(7)] {
            let mut config = if v8_profile {
                InterpreterConfig::v8_defaults()
            } else {
                InterpreterConfig::quickjs_defaults()
            };
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "string-decoder");
            core.set_gc_stress_interval(stress);
            let result = core
                .execute(&lowered.ir3)
                .expect("decoder fixture executes");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
            let actual = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(actual, expected, "v8={v8_profile}, GC={stress:?}");
        }
    }
}

const BASIC: &str = r#"
const module = require('string_decoder');
const other = require('node:string_decoder');
const Saved = ((value) => value)(module.StringDecoder);
const decoder = new Saved('UTF-8');
console.log(module === other, decoder instanceof Saved, decoder.encoding);
console.log(JSON.stringify(decoder.write(Buffer.from([0xe2]))), decoder.lastNeed, decoder.lastTotal);
console.log(JSON.stringify(decoder.write(Buffer.from([0x82]))), decoder.lastNeed);
console.log(decoder.end(Buffer.from([0xac])), decoder.lastNeed, decoder.lastTotal);
"#;

#[test]
fn module_values_and_split_utf8_preserve_identity_and_carry() {
    check(
        BASIC,
        "true true utf8\n\"\" 2 3\n\"\" 1\n€ 0 0",
        ParseGoal::Script,
    );
}

const SPLITS: &str = r#"
const { StringDecoder } = require('string_decoder');
const original = 'A€😀Z'; const input = Buffer.from(original);
let matches = 0;
for (let cut = 0; cut <= input.length; cut++) {
  const decoder = new StringDecoder();
  const result = decoder.write(input.subarray(0, cut)) + decoder.end(input.subarray(cut));
  if (result === original && decoder.lastNeed === 0) matches++;
}
const decoder = new StringDecoder(); let result = '';
for (let i = 0; i < input.length; i++) result += decoder.write(input.subarray(i, i + 1));
result += decoder.end();
console.log(matches, result === original, decoder.lastChar.length);
"#;

#[test]
fn every_valid_utf8_boundary_and_single_byte_chunks() {
    check(SPLITS, "10 true 4", ParseGoal::Script);
}

const MALFORMED: &str = r#"
const { StringDecoder } = require('node:string_decoder');
const decoder = new StringDecoder();
console.log(JSON.stringify(decoder.write(Buffer.from([0xe1, 0x81]))));
console.log(JSON.stringify(decoder.write(Buffer.from([0x41, 0xc0]))));
console.log(JSON.stringify(decoder.write(Buffer.from([0x80, 0xf5]))));
console.log(JSON.stringify(decoder.end()));
console.log(decoder.write(Buffer.from('again')), decoder.lastNeed);
"#;

#[test]
fn malformed_utf8_and_truncated_sequences_use_native_replacement_rules() {
    check(
        MALFORMED,
        "\"\"\n\"�A\"\n\"��\"\n\"�\"\nagain 0",
        ParseGoal::Script,
    );
}

const UTF16: &str = r#"
const { StringDecoder } = require('string_decoder');
const decoder = new StringDecoder('ucs-2');
console.log(decoder.encoding, JSON.stringify(decoder.write(Buffer.from([0x3d, 0xd8]))));
console.log(JSON.stringify(decoder.write(Buffer.from([0x00]))), decoder.lastNeed);
console.log(decoder.end(Buffer.from([0xde])), decoder.lastNeed);
console.log(JSON.stringify(decoder.write(Buffer.from([0x41]))), JSON.stringify(decoder.end()));
console.log(decoder.end(Buffer.from([0x42, 0x00])));
"#;

#[test]
fn utf16_surrogates_odd_bytes_and_reuse() {
    check(
        UTF16,
        "utf16le \"\"\n\"\" 1\n😀 0\n\"\" \"\"\nB",
        ParseGoal::Script,
    );
}

const BASE64: &str = r#"
const { StringDecoder } = require('string_decoder');
for (const encoding of ['base64', 'base64url']) {
  const decoder = new StringDecoder(encoding);
  const source = Buffer.from([0xfb, 0xff, 0xbe, 0x42]);
  let result = decoder.write(source.subarray(0, 1));
  console.log(result === '', decoder.lastNeed);
  result += decoder.write(source.subarray(1, 3));
  result += decoder.end(source.subarray(3));
  console.log(result, decoder.lastNeed);
}
"#;

#[test]
fn base64_quanta_and_url_safe_final_padding() {
    check(
        BASE64,
        "true 2\n+/++Qg== 0\ntrue 2\n-_--Qg 0",
        ParseGoal::Script,
    );
}

const VIEWS: &str = r#"
const { StringDecoder } = require('string_decoder');
const bytes = new Uint8Array([88, 88, 0xe2, 0x82, 0xac, 65, 89, 89]);
const decoder = new StringDecoder();
console.log(JSON.stringify(decoder.write(new DataView(bytes.buffer, 2, 2))));
console.log(decoder.end(new Uint8Array(bytes.buffer, 4, 2)));
const words = new Uint16Array(bytes.buffer, 2, 2);
Object.defineProperty(words, 'buffer', { value: new ArrayBuffer(0) });
Object.defineProperty(words, 'byteLength', { value: 0 });
console.log(new StringDecoder().end(words));
"#;

#[test]
fn view_byte_offsets_and_element_widths_do_not_decode_unrelated_backing_bytes() {
    check(VIEWS, "\"\"\n€A\n€A", ParseGoal::Script);
}

const COPY_CARRY: &str = r#"
const { StringDecoder } = require('string_decoder');
const first = new StringDecoder(); const second = new StringDecoder();
const chunk = Buffer.from([0xe2]);
first.write(chunk); second.write(Buffer.from([0xf0, 0x9f]));
chunk[0] = 65;
console.log(first.end(Buffer.from([0x82, 0xac])));
console.log(second.end(Buffer.from([0x98, 0x80])));
console.log(first.lastChar.length, first.lastChar !== first.lastChar);
"#;

#[test]
fn pending_bytes_are_copied_and_decoder_instances_do_not_share_state() {
    check(COPY_CARRY, "€\n😀\n4 true", ParseGoal::Script);
}

const STRINGS: &str = r#"
const { StringDecoder } = require('string_decoder');
const decoder = new StringDecoder();
decoder.write(Buffer.from([0xe2]));
console.log(decoder.write('already decoded'), decoder.lastNeed);
decoder.encoding = 'hex';
console.log(decoder.end('prefix:'), decoder.lastNeed);
console.log(decoder.end(Buffer.from([65])));
decoder.write(Buffer.from([0xe2]));
console.log(decoder.text(Buffer.from([88, 66, 67]), 1), decoder.lastNeed);
console.log(decoder.text('abcd', -2));
"#;

#[test]
fn strings_do_not_consume_pending_bytes_and_text_starts_a_fresh_sequence() {
    check(
        STRINGS,
        "already decoded 2\nprefix:� 0\nA\nBC 0\ncd",
        ParseGoal::Script,
    );
}

const VALIDATION: &str = r#"
const { StringDecoder } = require('string_decoder');
for (const encoding of [null, '', 'UTF-8', 'utf-16le', 'UCS2', 'binary', 'ASCII', 'HEX']) {
  console.log(new StringDecoder(encoding).encoding);
}
let unknown = 0;
for (const encoding of [false, 0, true, {}, 'invalid']) {
  try { new StringDecoder(encoding); }
  catch (error) { if (error instanceof TypeError && error.code === 'ERR_UNKNOWN_ENCODING') unknown++; }
}
let invalid = 0; const decoder = new StringDecoder();
for (const input of [undefined, null, false, 7, {}, [], new ArrayBuffer(0)]) {
  try { decoder.write(input); }
  catch (error) { if (error instanceof TypeError && error.code === 'ERR_INVALID_ARG_TYPE') invalid++; }
}
console.log(unknown, invalid);
"#;

#[test]
fn encoding_aliases_and_invalid_inputs_have_stable_error_codes() {
    check(
        VALIDATION,
        "utf8\nutf8\nutf8\nutf16le\nutf16le\nlatin1\nascii\nhex\n5 7",
        ParseGoal::Script,
    );
}

const SHADOWS: &str = r#"
const { StringDecoder } = require('string_decoder');
const Buffer = 0, WeakMap = 0, Object = 0, Reflect = 0, String = 0;
const ArrayBuffer = 0, Uint8Array = 0, DataView = 0, TypeError = 0;
const decoder = new StringDecoder('utf8');
console.log(decoder.end(globalThis.Buffer.from('protected')), Buffer, WeakMap);
"#;

#[test]
fn native_dependencies_are_not_captured_by_guest_global_declarations() {
    check(SHADOWS, "protected 0 0", ParseGoal::Script);
}

const SUBCLASS: &str = r#"
const { StringDecoder } = require('string_decoder');
class Decoder extends StringDecoder { decode(input) { return this.end(input); } }
const decoder = new Decoder('hex');
console.log(decoder instanceof Decoder, decoder instanceof StringDecoder);
console.log(decoder.decode(Buffer.from([0, 255, 16])));
const target = Object.create(StringDecoder.prototype);
StringDecoder.call(target, 'latin1');
console.log(target.end(Buffer.from([65, 255])).charCodeAt(1));
"#;

#[test]
fn subclasses_and_explicit_constructor_receivers_keep_their_own_decoder_state() {
    check(SUBCLASS, "true true\n00ff10\n255", ParseGoal::Script);
}

const ESM: &str = r#"
import decoderModule, { StringDecoder as Decoder } from 'node:string_decoder';
const decoder = new Decoder();
console.log(decoderModule.StringDecoder === Decoder);
decoder.write(Buffer.from([0xc2]));
console.log(decoder.end(Buffer.from([0xa2])));
"#;

#[test]
fn esm_default_and_named_exports_resolve_without_filesystem_authority() {
    check(ESM, "true\n¢", ParseGoal::Module);
}
