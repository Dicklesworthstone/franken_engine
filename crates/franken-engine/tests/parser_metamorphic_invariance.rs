#![forbid(unsafe_code)]

use frankenengine_engine::jsx_tsx_parser::{
    JsxAttribute, JsxAttributeValue, JsxChild, JsxElementName, JsxNode, JsxParseResult,
    JsxParserConfig, parse_jsx,
};
use frankenengine_engine::parallel_parser::{self, ParallelConfig, ParseInput};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::simd_lexer::{LexerConfig, TokenKind};

#[derive(Debug, Clone, PartialEq, Eq)]
struct SemanticToken {
    kind: TokenKind,
    lexeme: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommentRange {
    start: u64,
    end: u64,
}

fn parser_config() -> ParallelConfig {
    ParallelConfig {
        min_parallel_bytes: 0,
        max_workers: 4,
        always_check_parity: true,
        lexer_config: LexerConfig {
            emit_tokens: true,
            ..LexerConfig::default()
        },
        ..ParallelConfig::default()
    }
}

fn parse_semantic_tokens(source: &str) -> Vec<SemanticToken> {
    let config = parser_config();
    let input = ParseInput {
        source,
        trace_id: "parser-metamorphic-invariance",
        run_id: "parser-metamorphic-invariance",
        epoch: SecurityEpoch::from_raw(1),
        config: &config,
    };
    let output = parallel_parser::parse(&input)
        .unwrap_or_else(|error| panic!("parallel parser failed for `{source}`: {error}"));
    let comment_ranges = comment_ranges(source);

    output
        .tokens
        .iter()
        .filter(|token| {
            !comment_ranges
                .iter()
                .any(|range| token.start < range.end && token.end > range.start)
        })
        .map(|token| SemanticToken {
            kind: token.kind,
            lexeme: source[token.start as usize..token.end as usize].to_string(),
        })
        .collect()
}

fn comment_ranges(source: &str) -> Vec<CommentRange> {
    let bytes = source.as_bytes();
    let mut ranges = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' => {
                index = skip_string(bytes, index);
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                let start = index;
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' && bytes[index] != b'\r' {
                    index += 1;
                }
                ranges.push(CommentRange {
                    start: start as u64,
                    end: index as u64,
                });
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let start = index;
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
                ranges.push(CommentRange {
                    start: start as u64,
                    end: index as u64,
                });
            }
            _ => index += 1,
        }
    }

    ranges
}

fn skip_string(bytes: &[u8], start: usize) -> usize {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index = (index + 2).min(bytes.len()),
            byte if byte == quote => return index + 1,
            b'\n' | b'\r' => return index,
            _ => index += 1,
        }
    }
    index
}

fn assert_parallel_invariant(name: &str, baseline: &str, transformed: &str) {
    let left = parse_semantic_tokens(baseline);
    let right = parse_semantic_tokens(transformed);
    assert_eq!(
        left, right,
        "parallel parser semantic-token invariant failed for {name}"
    );
}

fn parse_jsx_signature(source: &str) -> String {
    let result = parse_jsx(source, &JsxParserConfig::default())
        .unwrap_or_else(|error| panic!("JSX parser failed for `{source}`: {error}"));
    jsx_result_signature(&result)
}

fn jsx_result_signature(result: &JsxParseResult) -> String {
    jsx_node_signature(&result.node)
}

fn jsx_node_signature(node: &JsxNode) -> String {
    match node {
        JsxNode::Element(element) => format!(
            "element:{}:{}:attrs[{}]:children[{}]",
            element_name_signature(&element.name),
            element.self_closing,
            element
                .attributes
                .iter()
                .map(attribute_signature)
                .collect::<Vec<_>>()
                .join(","),
            child_signatures(&element.children).join(",")
        ),
        JsxNode::Fragment(fragment) => {
            format!(
                "fragment:children[{}]",
                child_signatures(&fragment.children).join(",")
            )
        }
    }
}

fn element_name_signature(name: &JsxElementName) -> String {
    match name {
        JsxElementName::Identifier { name, .. } => format!("id:{name}"),
        JsxElementName::MemberExpression { segments, .. } => {
            format!("member:{}", segments.join("."))
        }
        JsxElementName::NamespacedName {
            namespace, name, ..
        } => {
            format!("namespaced:{namespace}:{name}")
        }
    }
}

fn attribute_signature(attribute: &JsxAttribute) -> String {
    match attribute {
        JsxAttribute::Named { name, value, .. } => {
            format!("named:{name}={}", attribute_value_signature(value))
        }
        JsxAttribute::Spread { expression, .. } => {
            format!("spread:{}", normalize_js_expression(expression))
        }
    }
}

fn attribute_value_signature(value: &JsxAttributeValue) -> String {
    match value {
        JsxAttributeValue::StringLiteral { value } => format!("string:{value}"),
        JsxAttributeValue::Expression { expression } => {
            format!("expr:{}", normalize_js_expression(expression))
        }
        JsxAttributeValue::ImplicitTrue => "true".to_string(),
    }
}

fn child_signatures(children: &[JsxChild]) -> Vec<String> {
    children
        .iter()
        .filter_map(|child| match child {
            JsxChild::Text { value, .. } => {
                let normalized = normalize_text(value);
                (!normalized.is_empty()).then(|| format!("text:{normalized}"))
            }
            JsxChild::ExpressionContainer { expression, .. } => {
                let normalized = normalize_js_expression(expression);
                (!normalized.is_empty()).then(|| format!("expr:{normalized}"))
            }
            JsxChild::Element(element) => {
                Some(jsx_node_signature(&JsxNode::Element((**element).clone())))
            }
            JsxChild::Fragment(fragment) => {
                Some(jsx_node_signature(&JsxNode::Fragment((**fragment).clone())))
            }
        })
        .collect()
}

fn normalize_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_js_expression(value: &str) -> String {
    let stripped = strip_js_comments(value);
    stripped.split_whitespace().collect::<String>()
}

fn strip_js_comments(value: &str) -> String {
    let bytes = value.as_bytes();
    let ranges = comment_ranges(value);
    let mut output = String::new();
    let mut index = 0usize;

    for range in ranges {
        if index < range.start as usize {
            output.push_str(&value[index..range.start as usize]);
        }
        index = range.end as usize;
        if index < bytes.len() && bytes[index].is_ascii_whitespace() {
            output.push(' ');
        }
    }
    if index < value.len() {
        output.push_str(&value[index..]);
    }

    output
}

fn assert_jsx_invariant(name: &str, baseline: &str, transformed: &str) {
    let left = parse_jsx_signature(baseline);
    let right = parse_jsx_signature(transformed);
    assert_eq!(left, right, "JSX parser AST invariant failed for {name}");
}

macro_rules! parallel_mr {
    ($name:ident, $baseline:expr, $transformed:expr) => {
        #[test]
        fn $name() {
            assert_parallel_invariant(stringify!($name), $baseline, $transformed);
        }
    };
}

macro_rules! jsx_mr {
    ($name:ident, $baseline:expr, $transformed:expr) => {
        #[test]
        fn $name() {
            assert_jsx_invariant(stringify!($name), $baseline, $transformed);
        }
    };
}

parallel_mr!(
    parallel_whitespace_between_variable_tokens,
    "let alpha = 1;\nalpha + 2;",
    "let    alpha\t=\n1  ;\n\nalpha    +    2 ;"
);

parallel_mr!(
    parallel_block_comment_between_declaration_tokens,
    "let alpha = 1;\nalpha + 2;",
    "let /* declaration keyword gap */ alpha = 1;\nalpha + 2;"
);

parallel_mr!(
    parallel_line_comment_after_statement,
    "let alpha = 1;\nalpha + 2;",
    "let alpha = 1; // initialize alpha\nalpha + 2;"
);

parallel_mr!(
    parallel_block_comment_between_expression_terms,
    "total = left + right;",
    "total = left /* left operand complete */ + right;"
);

parallel_mr!(
    parallel_line_comment_between_two_statements,
    "first();\nsecond();\nthird();",
    "first();\n// preserve sequencing\nsecond();\nthird();"
);

parallel_mr!(
    parallel_multiline_block_comment_between_statements,
    "first();\nsecond();\nthird();",
    "first();\n/* preserve\n   sequencing */\nsecond();\nthird();"
);

parallel_mr!(
    parallel_whitespace_in_function_call,
    "run(alpha, beta, gamma);",
    "run(  alpha ,\n beta ,\t gamma  );"
);

parallel_mr!(
    parallel_comments_inside_argument_list,
    "run(alpha, beta, gamma);",
    "run(alpha, /* beta slot */ beta, // gamma follows\n gamma);"
);

parallel_mr!(
    parallel_whitespace_around_comparison_chain,
    "alpha == beta && gamma != delta;",
    "alpha\t==\tbeta\n&&\ngamma   !=   delta;"
);

parallel_mr!(
    parallel_comments_around_comparison_chain,
    "alpha == beta && gamma != delta;",
    "alpha == beta /* left condition */ && // right condition\n gamma != delta;"
);

parallel_mr!(
    parallel_whitespace_in_object_literal_tokens,
    "config = { enabled: true, limit: 3 };",
    "config={\n  enabled : true ,\n  limit : 3\n};"
);

parallel_mr!(
    parallel_comments_in_object_literal_tokens,
    "config = { enabled: true, limit: 3 };",
    "config = { /* flag */ enabled: true, // cap\n limit: 3 };"
);

jsx_mr!(
    jsx_whitespace_around_self_closing_boundary,
    "<Button disabled />",
    " \n<Button   disabled   />\n "
);

jsx_mr!(
    jsx_whitespace_between_named_attributes,
    "<Button label=\"Save\" disabled />",
    "<Button\n  label = \"Save\"\n  disabled\n/>"
);

jsx_mr!(
    jsx_block_comment_child_is_semantic_trivia,
    "<Panel><Button /></Panel>",
    "<Panel>{/* toolbar action */}<Button /></Panel>"
);

jsx_mr!(
    jsx_whitespace_text_is_semantic_trivia_between_children,
    "<Panel><Button /><Button /></Panel>",
    "<Panel>\n  <Button />\n  <Button />\n</Panel>"
);

jsx_mr!(
    jsx_whitespace_normalizes_text_child,
    "<Panel>Hello world</Panel>",
    "<Panel>\n  Hello   world\n</Panel>"
);

jsx_mr!(
    jsx_expression_child_whitespace_invariance,
    "<Panel>{count + 1}</Panel>",
    "<Panel>{ count  +\n 1 }</Panel>"
);

jsx_mr!(
    jsx_expression_child_comment_invariance,
    "<Panel>{count + 1}</Panel>",
    "<Panel>{count /* next */ + 1}</Panel>"
);

jsx_mr!(
    jsx_attribute_expression_whitespace_invariance,
    "<Panel count={count + 1} />",
    "<Panel count={ count  +\n 1 } />"
);

jsx_mr!(
    jsx_attribute_expression_comment_invariance,
    "<Panel count={count + 1} />",
    "<Panel count={count /* next */ + 1} />"
);

jsx_mr!(
    jsx_fragment_whitespace_between_children,
    "<><Button /><Panel /></>",
    "<>\n  <Button />\n  <Panel />\n</>"
);
