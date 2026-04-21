#![no_main]

use frankenengine_engine::parser::{
    CanonicalEs2020Parser, ParseDiagnosticEnvelope, ParseEventIr, ParseEventKind, ParseGoal,
    ParserBudget, ParserMode, ParserOptions,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 8 * 1024;
const MAX_SYNTHETIC_STATEMENTS: usize = 96;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let goal = parse_goal(data);
    let source = parser_source(data, goal);
    let parser = CanonicalEs2020Parser;
    let options = parser_options(data);

    let (result, event_ir) = parser.parse_with_event_ir(source.as_str(), goal, &options);
    assert_event_ir_envelope(&event_ir, goal);
    let _ = event_ir.canonical_hash();

    match result {
        Ok(tree) => {
            assert_eq!(tree.goal, goal);
            let materialized = event_ir
                .materialize_from_syntax_tree(&tree)
                .expect("successful parse event IR should materialize");
            assert_eq!(
                materialized.syntax_tree.canonical_hash(),
                tree.canonical_hash()
            );

            let (repeat, repeat_ir) = parser.parse_with_event_ir(source.as_str(), goal, &options);
            let repeat_tree = repeat.expect("successful parse should be deterministic");
            assert_eq!(repeat_tree.canonical_hash(), tree.canonical_hash());
            assert_eq!(repeat_ir.canonical_hash(), event_ir.canonical_hash());
        }
        Err(error) => {
            let diagnostic = ParseDiagnosticEnvelope::from_parse_error(&error);
            assert!(diagnostic.canonical_hash().starts_with("sha256:"));
            assert!(
                event_ir
                    .events
                    .iter()
                    .any(|event| matches!(event.kind, ParseEventKind::ParseFailed)),
                "failed parses must emit a parse_failed event"
            );
        }
    }
});

fn parser_options(data: &[u8]) -> ParserOptions {
    ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: MAX_INPUT_BYTES as u64,
            max_token_count: 16 + u64::from(byte(data, 1)),
            max_recursion_depth: 8 + u64::from(byte(data, 2) % 64),
        },
    }
}

fn parse_goal(data: &[u8]) -> ParseGoal {
    if byte(data, 0) & 1 == 0 {
        ParseGoal::Script
    } else {
        ParseGoal::Module
    }
}

fn parser_source(data: &[u8], goal: ParseGoal) -> String {
    match byte(data, 0) % 4 {
        0 => String::from_utf8_lossy(&data[1..]).into_owned(),
        1 => synthetic_source(data, goal),
        2 => format!(
            "{}\n{}",
            String::from_utf8_lossy(&data[1..data.len().min(257)]),
            synthetic_source(data, goal)
        ),
        _ => parenthesized_expression_source(data),
    }
}

fn synthetic_source(data: &[u8], goal: ParseGoal) -> String {
    let mut source = String::new();

    if goal == ParseGoal::Module && byte(data, 3) % 2 == 0 {
        source.push_str("import dep from \"pkg\";\n");
    }

    for (index, chunk) in data[1..]
        .chunks(4)
        .take(MAX_SYNTHETIC_STATEMENTS)
        .enumerate()
    {
        let opcode = chunk.first().copied().unwrap_or(0);
        let expr = expression(chunk.get(1).copied().unwrap_or(0), index);
        let ident = identifier(index);

        match opcode % 14 {
            0 => source.push_str(&format!("let {ident} = {expr};\n")),
            1 => source.push_str(&format!("const {ident} = {expr};\n")),
            2 => source.push_str(&format!("{ident};\n")),
            3 => source.push_str(&format!("{ident} = {expr};\n")),
            4 => source.push_str(&format!("if ({ident}) {{ {expr}; }} else {{ {ident}; }}\n")),
            5 => source.push_str(&format!("while ({ident}) {{ break; }}\n")),
            6 => source.push_str("for (let i = 0; i < 3; i++) { i; }\n"),
            7 => source.push_str(&format!("function f{index}() {{ return {expr}; }}\n")),
            8 => source.push_str(&format!("try {{ {ident}; }} catch (err) {{ err; }}\n")),
            9 => source.push_str(&format!("throw {expr};\n")),
            10 if goal == ParseGoal::Module => {
                source.push_str(&format!("export const {ident}_export = {expr};\n"));
            }
            11 if goal == ParseGoal::Module => {
                source.push_str(&format!("export default {expr};\n"))
            }
            12 => source.push_str(&format!("do {{ {ident}; }} while ({ident});\n")),
            _ => source.push_str(&format!("{expr};\n")),
        }
    }

    if source.trim().is_empty() {
        source.push_str("let seed = 1;\nseed;\n");
    }

    source
}

fn parenthesized_expression_source(data: &[u8]) -> String {
    let mut source = String::new();
    for (index, byte) in data.iter().copied().take(64).enumerate() {
        if index % 8 == 0 {
            source.push('\n');
        }
        source.push_str(&expression(byte, index));
        source.push(';');
    }
    source
}

fn expression(byte: u8, index: usize) -> String {
    match byte % 8 {
        0 => index.to_string(),
        1 => format!("\"s{}\"", byte % 32),
        2 => format!("{} + {}", index, byte),
        3 => format!("{} === {}", identifier(index), byte % 7),
        4 => format!("[{}, {}]", index, byte),
        5 => format!("{{value: {}}}", byte),
        6 => "true".to_string(),
        _ => identifier(index),
    }
}

fn identifier(index: usize) -> String {
    format!("v{}", index % MAX_SYNTHETIC_STATEMENTS)
}

fn assert_event_ir_envelope(event_ir: &ParseEventIr, goal: ParseGoal) {
    assert_eq!(event_ir.schema_version, ParseEventIr::schema_version());
    assert_eq!(event_ir.contract_version, ParseEventIr::contract_version());
    assert_eq!(event_ir.parser_mode, ParserMode::ScalarReference);
    assert_eq!(event_ir.goal, goal);
    assert!(!event_ir.events.is_empty());

    let first = event_ir.events.first().expect("non-empty event IR");
    assert_eq!(first.sequence, 0);
    assert!(matches!(first.kind, ParseEventKind::ParseStarted));

    for (expected_sequence, event) in event_ir.events.iter().enumerate() {
        assert_eq!(event.sequence, expected_sequence as u64);
        assert_eq!(event.parser_mode, event_ir.parser_mode);
        assert_eq!(event.goal, event_ir.goal);
        assert_eq!(event.source_label, event_ir.source_label);
        assert_eq!(event.trace_id, first.trace_id);
        assert_eq!(event.decision_id, first.decision_id);
        assert_eq!(event.policy_id, first.policy_id);
        assert_eq!(event.component, first.component);
    }

    let last = event_ir.events.last().expect("non-empty event IR");
    assert!(matches!(
        last.kind,
        ParseEventKind::ParseCompleted | ParseEventKind::ParseFailed
    ));
}

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(0)
}
