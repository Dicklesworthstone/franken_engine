//! Native TextDecoder regressions. Reference expectations are checked separately
//! under Node; only these tests execute the engine's parser/lowering/runtime.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn check(source: &str, expected: &str) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource { label: "text-decoder.js".into(), text: source.into() },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("decoder source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "text-decoder.js"),
        &LoweringContext::new("text-decoder", "bd-3l74k", "builtin-only"),
    )
    .expect("decoder source lowers")
    .ir3;
    for v8 in [false, true] {
        for stress in [None, Some(7)] {
            let mut config = if v8 {
                InterpreterConfig::v8_defaults()
            } else {
                InterpreterConfig::quickjs_defaults()
            };
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
            ].into_iter().collect();
            let mut core = InterpreterCore::new(config, "text-decoder");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module).expect("decoder executes");
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
            let output = result.console_output.iter().map(|entry| entry.message.as_str())
                .collect::<Vec<_>>().join("\n");
            assert_eq!(output, expected, "profile={v8}, GC={stress:?}");
        }
    }
}

const UTF16_INVALID: &str = r#"
for (const bytes of [[0,216], [0,220], [0,216,65], [0,216,65,0], [0,216,1,216,0,220]]) {
  const text = new TextDecoder('utf-16le').decode(new Uint8Array(bytes));
  const units = [];
  for (let i = 0; i < text.length; i++) units.push(text.charCodeAt(i));
  console.log(units.join(','));
  try { new TextDecoder('utf-16le', { fatal: true }).decode(new Uint8Array(bytes)); }
  catch (error) { console.log(error instanceof TypeError); }
}
"#;
#[test]
fn utf16_malformed_input_never_returns_lone_surrogates() {
    check(UTF16_INVALID, "65533\ntrue\n65533\ntrue\n65533\ntrue\n65533,65\ntrue\n65533,55297,56320\ntrue");
}

const UTF16_BIG_ENDIAN: &str = r#"
const bytes = new Uint8Array([254,255,0,65,216,61,222,0,254,255]);
for (const label of ['utf-16be', 'unicodefffe', ' UTF-16BE ']) {
  const decoder = new TextDecoder(label, { fatal: true });
  const text = decoder.decode(bytes);
  console.log(decoder.encoding, text.length, text.charCodeAt(0), text.codePointAt(1), text.charCodeAt(3));
}
const kept = new TextDecoder('utf-16be', { ignoreBOM: true }).decode(bytes);
console.log(kept.charCodeAt(0), kept.length);
"#;
#[test]
fn big_endian_labels_bom_and_supplementary_characters() {
    check(UTF16_BIG_ENDIAN, "utf-16be 4 65 128512 65279\nutf-16be 4 65 128512 65279\nutf-16be 4 65 128512 65279\n65279 5");
}

const UTF16_VIEW: &str = r#"
const input = new Uint8Array([255,0,65,216,61,222,0,255]);
const view = new DataView(input.buffer, 1, 6);
console.log(new TextDecoder('utf-16be').decode(view));
const decoder = new TextDecoder('utf-16be', { fatal: true });
try { decoder.decode(new Uint8Array([0])); } catch (error) { console.log(error instanceof TypeError); }
console.log(decoder.decode(new Uint8Array([0,66])));
"#;
#[test]
fn utf16_decode_respects_view_bounds_and_recovers_after_fatal_errors() {
    check(UTF16_VIEW, "A😀\ntrue\nB");
}

const UTF8_CHUNKS: &str = r#"
const decoder = new TextDecoder();
const output = [];
for (const chunk of [[226], [130], [172], [240], [159], [152], [128]]) {
  output.push(decoder.decode(new Uint8Array(chunk), { stream: true }));
}
output.push(decoder.decode());
console.log(JSON.stringify(output));
console.log(decoder.decode(new Uint8Array([226,130])).charCodeAt(0));
console.log(decoder.decode(new Uint8Array([172])).charCodeAt(0));
"#;
#[test]
fn utf8_incomplete_characters_wait_for_later_chunks_or_explicit_flush() {
    check(UTF8_CHUNKS, "[\"\",\"\",\"€\",\"\",\"\",\"\",\"😀\",\"\"]\n65533\n65533");
}

const UTF16_CHUNKS: &str = r#"
for (const encoding of ['utf-16le', 'utf-16be']) {
  const bytes = encoding === 'utf-16le' ? [255,254,61,216,0,222,65,0] : [254,255,216,61,222,0,0,65];
  const decoder = new TextDecoder(encoding);
  const out = [];
  for (const byte of bytes) out.push(decoder.decode(new Uint8Array([byte]), { stream: true }));
  out.push(decoder.decode());
  console.log(JSON.stringify(out));
}
"#;
#[test]
fn utf16_bom_surrogates_and_odd_bytes_cross_arbitrary_chunk_boundaries() {
    check(UTF16_CHUNKS, "[\"\",\"\",\"\",\"\",\"\",\"😀\",\"\",\"A\",\"\"]\n[\"\",\"\",\"\",\"\",\"\",\"😀\",\"\",\"A\",\"\"]");
}

const BOM_LIFETIME: &str = r#"
for (const ignoreBOM of [false, true]) {
  const d = new TextDecoder('utf-8', { ignoreBOM });
  let text = d.decode(undefined, { stream: true });
  for (const part of [[239], [], [187], [191], [65], [239,187,191]]) {
    text += d.decode(new Uint8Array(part), { stream: true });
  }
  text += d.decode();
  const codes = [];
  for (let i = 0; i < text.length; i++) codes.push(text.charCodeAt(i));
  console.log(codes.join(','));
  console.log(d.decode(new Uint8Array([239,187,191,66])).length);
}
"#;
#[test]
fn bom_filtering_is_once_per_stream_and_empty_chunks_do_not_consume_it() {
    check(BOM_LIFETIME, "65,65279\n1\n65279,65,65279\n2");
}

const FATAL_STREAM: &str = r#"
for (const encoding of ['utf-8', 'utf-16le', 'utf-16be']) {
  const d = new TextDecoder(encoding, { fatal: true });
  const prefix = encoding === 'utf-8' ? [226,130] : encoding === 'utf-16le' ? [0,216,65] : [216,0,65];
  console.log(d.decode(new Uint8Array(prefix), { stream: true }).length);
  try { d.decode(); } catch (error) { console.log(error instanceof TypeError); }
  const good = encoding === 'utf-8' ? [239,187,191,65] : encoding === 'utf-16le' ? [255,254,65,0] : [254,255,0,65];
  console.log(d.decode(new Uint8Array(good)));
}
const d = new TextDecoder('utf-8', { fatal: true });
try { d.decode(new Uint8Array([255,226]), { stream: true }); }
catch (error) { console.log(error instanceof TypeError); }
console.log(d.decode(new Uint8Array([239,187,191,66]), { stream: true }));
console.log(d.decode().length);
"#;
#[test]
fn fatal_mode_distinguishes_incomplete_from_malformed_and_resets_after_failure() {
    check(FATAL_STREAM, "0\ntrue\nA\n0\ntrue\nA\n0\ntrue\nA\ntrue\nB\n0");
}

const MALFORMED_STREAM: &str = r#"
for (const chunks of [[[226,130],[65]], [[237],[160,128]], [[240,159],[65,66]], [[239,187],[]]]) {
  const d = new TextDecoder();
  let text = '';
  for (const chunk of chunks) text += d.decode(new Uint8Array(chunk), { stream: true });
  text += d.decode();
  const codes = [];
  for (let i = 0; i < text.length; i++) codes.push(text.charCodeAt(i));
  console.log(codes.join(','));
}
const d = new TextDecoder('utf-16le');
console.log(d.decode(new Uint8Array([0,216,65]), { stream: true }).length);
console.log(d.decode().length, d.decode().length);
"#;
#[test]
fn malformed_prefixes_are_replaced_without_swallowing_following_characters() {
    check(MALFORMED_STREAM, "65533,65\n65533,65533,65533\n65533,65,66\n65533\n0\n1 0");
}

const COPIED_CARRY: &str = r#"
const d = new TextDecoder();
const backing = new Uint8Array([1,226,130,2]);
console.log(d.decode(new DataView(backing.buffer, 1, 2), { stream: true }).length);
backing[1] = 65;
backing[2] = 66;
const other = new TextDecoder();
console.log(other.decode(new Uint8Array([67])));
console.log(d.decode(new Uint8Array([172])));
console.log(d.decode().length);
"#;
#[test]
fn each_decoder_copies_only_its_own_carry_and_respects_view_bounds() {
    check(COPIED_CARRY, "0\nC\n€\n0");
}

const STREAM_OPTIONS: &str = r#"
const d = new TextDecoder();
const prefix = new Uint8Array([226,130]);
console.log(d.decode(prefix, Object.create({ stream: 'yes' })).length);
try { d.decode(new Uint8Array([172]), 'invalid'); } catch (error) { console.log(error instanceof TypeError); }
const marker = {};
try { d.decode(new Uint8Array([172]), { get stream() { throw marker; } }); }
catch (error) { console.log(error === marker); }
console.log(d.decode(new Uint8Array([172]), null));
const bytes = new Uint8Array([65]);
console.log(d.decode(bytes, { get stream() { bytes[0] = 66; return false; } }));
"#;
#[test]
fn stream_option_getters_and_failures_preserve_pending_state() {
    check(STREAM_OPTIONS, "0\ntrue\ntrue\n€\nB");
}

const ALL_SPLITS: &str = r#"
let cases = 0;
for (const encoding of ['utf-8', 'utf-16le', 'utf-16be']) {
  const bytes = encoding === 'utf-8' ? [239,187,191,65,226,130,172,240,159,152,128] : encoding === 'utf-16le' ? [255,254,65,0,172,32,61,216,0,222] : [254,255,0,65,32,172,216,61,222,0];
  for (let first = 0; first <= bytes.length; first++) {
    for (let second = first; second <= bytes.length; second++) {
      const d = new TextDecoder(encoding, { fatal: true });
      const a = d.decode(new Uint8Array(bytes.slice(0, first)), { stream: true });
      const b = d.decode(new Uint8Array(bytes.slice(first, second)), { stream: true });
      const c = d.decode(new Uint8Array(bytes.slice(second)));
      if (a + b + c !== 'A€😀') throw new Error('chunk boundary failure');
      cases++;
    }
  }
}
console.log(cases);
"#;
#[test]
fn every_three_chunk_partition_preserves_unicode_and_bom_semantics() {
    check(ALL_SPLITS, "210");
}

const SINGLE_BYTE_STREAM: &str = r#"
const d = new TextDecoder('latin1');
console.log(d.decode(new Uint8Array([128]), { stream: true }).charCodeAt(0));
console.log(d.decode(new Uint8Array([233]), { stream: true }).charCodeAt(0));
console.log(d.decode().length);
"#;
#[test]
fn single_byte_encodings_do_not_buffer_complete_bytes() {
    check(SINGLE_BYTE_STREAM, "8364\n233\n0");
}
