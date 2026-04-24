#![forbid(unsafe_code)]

use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{
    CanonicalEs2020Parser, ParseErrorCode, ParserBudget, ParserOptions, ParserSource, StreamInput,
};

const MALFORMED_OR_EDGE_INPUTS: &[&str] = &[
    "",
    "   ",
    "\n\n\t",
    "\0",
    "\u{feff}",
    "\u{2028}\u{2029}",
    "{",
    "}",
    "(",
    ")",
    "[",
    "]",
    "(((",
    ")))",
    "{{{",
    "}}}",
    "let",
    "let =",
    "let x =",
    "let x = ;",
    "let x == 1",
    "const x;",
    "const = 1;",
    "var ;",
    "var x = 1 2",
    "function",
    "function (",
    "function f(",
    "function f()",
    "function f(){",
    "return",
    "return return",
    "if",
    "if (",
    "if ()",
    "if (x)",
    "if (x) else",
    "for",
    "for (",
    "for (;;",
    "for (let x in)",
    "while",
    "while (",
    "do",
    "switch",
    "switch (x)",
    "switch (x) { case }",
    "try",
    "try {}",
    "try { } catch",
    "throw",
    "throw ;",
    "class",
    "class {",
    "class C extends",
    "import",
    "import {",
    "import x from",
    "import x from ;",
    "export",
    "export {",
    "export default",
    "export default ;",
    "await",
    "await ;",
    "`unterminated",
    "\"unterminated",
    "'unterminated",
    "/unterminated",
    "/* unterminated",
    "// trailing comment only",
    "1..",
    "0x",
    "0b2",
    "999999999999999999999999999999999999999999999999999999999999",
    "a +",
    "a ? b",
    "a =>",
    "=> a",
    "a?.",
    "obj[",
    "obj.",
    "new",
    "new.target",
    "super",
    "yield",
    "😊",
    "let \u{202e}x = 1;",
    "a\u{0000}b",
];

#[test]
fn parser_handles_malformed_script_inputs_without_panic() {
    let options = ParserOptions::default();
    for (index, source) in MALFORMED_OR_EDGE_INPUTS.iter().enumerate() {
        assert_parse_returns_cleanly(index, source, ParseGoal::Script, &options);
    }
}

#[test]
fn parser_handles_malformed_module_inputs_without_panic() {
    let options = ParserOptions::default();
    for (index, source) in MALFORMED_OR_EDGE_INPUTS.iter().enumerate() {
        assert_parse_returns_cleanly(index, source, ParseGoal::Module, &options);
    }
}

#[test]
fn parser_handles_edge_inputs_under_tight_budgets_without_panic() {
    let options = ParserOptions {
        budget: ParserBudget {
            max_source_bytes: 24,
            max_token_count: 4,
            max_recursion_depth: 2,
        },
        ..ParserOptions::default()
    };

    for (index, source) in MALFORMED_OR_EDGE_INPUTS.iter().enumerate() {
        assert_parse_returns_cleanly(index, source, ParseGoal::Script, &options);
    }
}

#[test]
fn parser_stream_input_rejects_invalid_utf8_without_panic() {
    let parser = CanonicalEs2020Parser;
    let invalid_inputs: &[&[u8]] = &[
        &[0xff],
        &[0xc0, 0xaf],
        &[0xe0, 0x80, 0x80],
        &[0xf0, 0x28, 0x8c, 0x28],
        b"let x = \xff;",
    ];

    for (index, bytes) in invalid_inputs.iter().enumerate() {
        let label = format!("invalid-utf8-{index}.js");
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            parser.parse_with_event_ir(
                StreamInput::new(Cursor::new(bytes.to_vec()), label.clone()),
                ParseGoal::Script,
                &ParserOptions::default(),
            )
        }));
        assert!(outcome.is_ok(), "invalid UTF-8 case {index} panicked");
        let (result, event_ir) = outcome.unwrap();
        assert_eq!(event_ir.goal, ParseGoal::Script);
        assert_eq!(event_ir.source_label, label);
        let error = result.expect_err("invalid UTF-8 must return an error");
        assert_eq!(error.code, ParseErrorCode::InvalidUtf8);
    }
}

fn assert_parse_returns_cleanly(
    index: usize,
    source: &str,
    goal: ParseGoal,
    options: &ParserOptions,
) {
    let parser = CanonicalEs2020Parser;
    let label = format!("input-validation-{goal:?}-{index}.js");
    let source = ParserSource {
        label: label.clone(),
        text: source.to_string(),
    };

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        parser.parse_with_event_ir(source, goal, options)
    }));
    assert!(
        outcome.is_ok(),
        "parser panicked for {goal:?} malformed/edge input {index}"
    );

    let (result, event_ir) = outcome.unwrap();
    assert_eq!(event_ir.goal, goal);
    assert_eq!(event_ir.source_label, label);

    match result {
        Ok(tree) => assert_eq!(tree.goal, goal),
        Err(error) => {
            assert!(!error.message.is_empty());
            assert_eq!(error.source_label, label);
        }
    }
}
