#![no_main]

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::jsx_tsx_parser::{
    JsxChild, JsxElement, JsxFragment, JsxNode, JsxParseError, JsxParseResult, JsxParserConfig,
    JsxRuntimeMode, parse_jsx,
};
use libfuzzer_sys::fuzz_target;

/// Span must satisfy: start_offset <= end_offset AND start_line <= end_line
/// AND when start_line == end_line, start_column <= end_column.
fn check_span(span: &SourceSpan, source_len: u64) {
    assert!(
        span.start_offset <= span.end_offset,
        "Span start_offset > end_offset: {:?}",
        span
    );
    assert!(
        span.end_offset <= source_len,
        "Span end_offset {} exceeds source length {}",
        span.end_offset,
        source_len
    );
    assert!(
        span.start_line <= span.end_line,
        "Span start_line > end_line: {:?}",
        span
    );
    if span.start_line == span.end_line {
        assert!(
            span.start_column <= span.end_column,
            "Single-line span has start_column > end_column: {:?}",
            span
        );
    }
    // Lines and columns are 1-based, never zero.
    assert!(span.start_line >= 1, "Span start_line must be 1-based");
    assert!(span.start_column >= 1, "Span start_column must be 1-based");
}

/// Recursively check every span on a JsxNode and all descendants.
fn walk_node_spans(node: &JsxNode, source_len: u64) {
    check_span(node.span(), source_len);
    match node {
        JsxNode::Element(el) => walk_element_spans(el, source_len),
        JsxNode::Fragment(frag) => walk_fragment_spans(frag, source_len),
    }
}

fn walk_element_spans(el: &JsxElement, source_len: u64) {
    check_span(&el.span, source_len);
    check_span(el.name.span(), source_len);
    for attr in &el.attributes {
        check_span(attr.span(), source_len);
    }
    for child in &el.children {
        walk_child_spans(child, source_len);
    }
}

fn walk_fragment_spans(frag: &JsxFragment, source_len: u64) {
    check_span(&frag.span, source_len);
    for child in &frag.children {
        walk_child_spans(child, source_len);
    }
}

fn walk_child_spans(child: &JsxChild, source_len: u64) {
    check_span(child.span(), source_len);
    match child {
        JsxChild::Text { .. } | JsxChild::ExpressionContainer { .. } => {}
        JsxChild::Element(el) => walk_element_spans(el, source_len),
        JsxChild::Fragment(frag) => walk_fragment_spans(frag, source_len),
    }
}

/// Assert structural invariants that hold for every Ok/Err the parser returns.
fn check_result_invariants(source_len: u64, result: &Result<JsxParseResult, JsxParseError>) {
    match result {
        Ok(parse_result) => {
            // Successful parse must round-trip through JSON without panicking.
            let serialized = serde_json::to_string(parse_result)
                .expect("JsxParseResult should always serialize");
            let _deserialized: serde_json::Value = serde_json::from_str(&serialized)
                .expect("Serialized JsxParseResult should deserialize");

            // Every span on every node must be well-formed and inside the source.
            walk_node_spans(&parse_result.node, source_len);

            // Diagnostics on a successful parse should still have well-formed spans.
            for diag in &parse_result.diagnostics {
                if let Some(span) = &diag.span {
                    check_span(span, source_len);
                }
            }
        }
        Err(err) => {
            // Error must round-trip through JSON without panicking.
            let _serialized =
                serde_json::to_string(err).expect("JsxParseError should always serialize");

            // Display must never panic and must produce a non-empty message.
            let display = format!("{err}");
            assert!(
                !display.is_empty(),
                "JsxParseError Display should produce a non-empty message"
            );

            // Structural invariant: FailClosed must carry at least one diagnostic
            // and every diagnostic span must be well-formed.
            if let JsxParseError::FailClosed { diagnostics } = err {
                assert!(
                    !diagnostics.is_empty(),
                    "FailClosed errors must carry at least one diagnostic"
                );
                for diag in diagnostics {
                    if let Some(span) = &diag.span {
                        check_span(span, source_len);
                    }
                }
            }
        }
    }
}

/// Re-run the parser with the same input/config and assert byte-for-byte determinism.
fn check_determinism(
    source: &str,
    config: &JsxParserConfig,
    first: &Result<JsxParseResult, JsxParseError>,
) {
    let second = parse_jsx(source, config);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "Parser should be deterministic across re-parses for the same input/config"
    );
    match (first, &second) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.node, b.node, "Deterministic parse: node mismatch");
            assert_eq!(
                a.diagnostics, b.diagnostics,
                "Deterministic parse: diagnostics mismatch"
            );
            assert_eq!(
                a.feature_families_used, b.feature_families_used,
                "Deterministic parse: feature_families_used mismatch"
            );
        }
        (Err(a), Err(b)) => {
            assert_eq!(a, b, "Deterministic parse: error mismatch");
        }
        _ => unreachable!("is_ok() guarded above"),
    }
}

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs that would slow down fuzzing.
    if data.is_empty() || data.len() > 4096 {
        return;
    }

    let source = String::from_utf8_lossy(data);

    // Configs we exercise on every input (cheap; covers the public surface).
    let config_default = JsxParserConfig::default();
    let config_tsx = JsxParserConfig {
        tsx_mode: true,
        ..JsxParserConfig::default()
    };
    let config_classic = JsxParserConfig {
        runtime_mode: JsxRuntimeMode::Classic,
        ..JsxParserConfig::default()
    };
    let config_namespaced = JsxParserConfig {
        allow_namespaced_names: true,
        ..JsxParserConfig::default()
    };

    let configs: [(&str, &JsxParserConfig); 4] = [
        ("default", &config_default),
        ("tsx", &config_tsx),
        ("classic", &config_classic),
        ("namespaced", &config_namespaced),
    ];

    let source_len = source.len() as u64;

    // Invariant: parsing never panics; serde and Display contracts hold; FailClosed carries
    // diagnostics; spans are well-formed and inside the source; and the same input + same
    // config produces byte-identical output across reparses.
    for (_label, config) in &configs {
        let result = parse_jsx(&source, config);
        check_result_invariants(source_len, &result);
        check_determinism(&source, config, &result);
    }

    // Depth-limit branch: very small max_depth must still uphold all invariants
    // (and is the cheapest way to drive the DepthExceeded error path during fuzzing).
    if source.len() < 100 {
        let config_shallow = JsxParserConfig {
            max_depth: 2,
            ..JsxParserConfig::default()
        };
        let result_shallow = parse_jsx(&source, &config_shallow);
        check_result_invariants(source_len, &result_shallow);
        check_determinism(&source, &config_shallow, &result_shallow);
    }
});
