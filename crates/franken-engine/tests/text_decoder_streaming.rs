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
