//! Identifiers outside ASCII (ES2020 11.6: UnicodeIDStart, UnicodeIDContinue,
//! ZWNJ and ZWJ).
//!
//! The parser took identifier characters to be ASCII letters, digits, `_` and
//! `$`, so a non-ASCII binding such as pi failed with "unsupported binding
//! pattern", a non-ASCII key was an "invalid object shorthand property", and a
//! name that begins with a keyword followed by a non-ASCII letter ("for" +
//! U+00EA) read as that keyword. The Rust strings below spell the programs
//! with `\u{..}` escapes; the JS source holds the characters themselves,
//! except in `escaped_unicode`, which uses JS identifier escapes. Expected
//! lines are Node v22.2.0's output.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

/// (name, program, Node v22.2.0 output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "bindings",
        "var \u{3c0} = 3.14; function \u{192}(x) { return x * 2; } let \u{410}\u{411} = 1, \u{436} = 2; const \u{4e2d}\u{4e2d} = 'z'; console.log(\u{3c0}, \u{192}(2), \u{410}\u{411} + \u{436}, \u{4e2d}\u{4e2d});",
        "3.14 4 3 z",
    ),
    (
        "properties",
        "var o = { \u{e9}t\u{e9}: 1, get na\u{e9}ve() { return 2; }, m\u{3c0}() { return 3; } }; o.\u{e9}t\u{e9} += 1; console.log(o.\u{e9}t\u{e9}, o.na\u{e9}ve, o.m\u{3c0}(), Object.keys(o).join(','));",
        "2 2 3 \u{e9}t\u{e9},na\u{e9}ve,m\u{3c0}",
    ),
    (
        "keyword_prefixes",
        "var for\u{ea}t = 1, in\u{e9}s = 2, do\u{e9} = 3, let$ = 4; for\u{ea}t += in\u{e9}s; console.log(for\u{ea}t, do\u{e9}, let$);",
        "3 3 4",
    ),
    (
        "update_and_join",
        "var \u{3c0} = 1; var r = \u{3c0}++ + 2; var s = \u{3c0}-- - 1; console.log(r, s, \u{3c0});",
        "3 1 1",
    ),
    (
        "classes_and_params",
        "class K\u{e9} { constructor(x\u{3c0}) { this.v\u{3c0} = x\u{3c0}; } get \u{436}() { return this.v\u{3c0} * 10; } } const k = new K\u{e9}(4); console.log(k.v\u{3c0}, k.\u{436}, K\u{e9}.name);",
        "4 40 K\u{e9}",
    ),
    (
        "joiners_and_marks",
        "var a\u{200c}b = 1, a\u{200d}b = 2, caf\u{e9}\u{301} = 3; console.log(a\u{200c}b + a\u{200d}b, caf\u{e9}\u{301});",
        "3 3",
    ),
    (
        "escaped_unicode",
        "var \\u03c0x = 7; var \\u{1d4b3} = 8; console.log(\u{3c0}x, \\u{1d4b3});",
        "7 8",
    ),
];

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "ident.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "ident.js"),
        &LoweringContext::new("ident-trace", "ident-decision", "ident-policy"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "ident");
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
fn unicode_identifiers_match_node() {
    let mut mismatches = Vec::new();
    for (name, source, node) in CASES {
        match console_output(source) {
            Ok(output) if output == *node => {}
            other => mismatches.push(format!("{name}: node {node:?}, got {other:?}")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} programs differ from Node:\n{}",
        mismatches.len(),
        CASES.len(),
        mismatches.join("\n")
    );
}

/// A character that is not an identifier character still ends a name:
/// U+2014 EM DASH is neither ID_Start nor ID_Continue.
#[test]
fn non_identifier_characters_are_refused() {
    assert!(console_output("var a\u{2014}b = 1;").is_err());
}
