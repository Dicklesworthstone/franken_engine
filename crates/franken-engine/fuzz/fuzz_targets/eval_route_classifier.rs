#![no_main]

use frankenengine_engine::{HybridRouter, RouteReason};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 2048 {
        return;
    }

    let source = String::from_utf8_lossy(data);
    let first = HybridRouter::classify_source_route(&source);
    let second = HybridRouter::classify_source_route(&source);
    assert_eq!(first, second);

    match first {
        RouteReason::ContainsImportKeyword => {
            assert!(contains_identifier_token(&source, "import"));
        }
        RouteReason::ContainsAwaitKeyword => {
            assert!(contains_identifier_token(&source, "await"));
        }
        RouteReason::DirectEngineInvocation => {
            assert!(
                contains_identifier_token(&source, "direct")
                    || source.contains("direct_profile_invocation")
            );
        }
        RouteReason::DefaultQuickJsPath => {}
    }

    let encoded = serde_json::to_string(&first).expect("route reason should serialize");
    let decoded: RouteReason =
        serde_json::from_str(&encoded).expect("route reason should deserialize");
    assert_eq!(decoded, first);

    let escaped = escape_js_string(&source);
    assert_eq!(
        HybridRouter::classify_source_route(&format!("\"{escaped}\";")),
        RouteReason::DefaultQuickJsPath
    );
    assert_eq!(
        HybridRouter::classify_source_route(&format!("// {}\n0;", escape_line_comment(&source))),
        RouteReason::DefaultQuickJsPath
    );
    assert_eq!(
        HybridRouter::classify_source_route(&format!("/* {} */ 0;", escape_block_comment(&source))),
        RouteReason::DefaultQuickJsPath
    );

    let template_source = escape_template_expression(&source);
    let template_inner_route = HybridRouter::classify_source_route(&template_source);
    let template_route =
        HybridRouter::classify_source_route(&format!("`prefix ${{ {template_source} }} suffix`;"));
    if matches!(
        template_inner_route,
        RouteReason::ContainsImportKeyword | RouteReason::ContainsAwaitKeyword
    ) {
        assert_eq!(template_route, template_inner_route);
    }
});

fn contains_identifier_token(source: &str, token: &str) -> bool {
    source.match_indices(token).any(|(start, matched)| {
        let before = source[..start].chars().next_back();
        let after = source[start + matched.len()..].chars().next();
        !before.is_some_and(is_identifier_continue) && !after.is_some_and(is_identifier_continue)
    })
}

fn is_identifier_continue(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_ascii_alphanumeric() || !ch.is_ascii()
}

fn escape_js_string(source: &str) -> String {
    source.chars().fold(String::new(), |mut escaped, ch| {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ if ch.is_control() => escaped.push(' '),
            _ => escaped.push(ch),
        }
        escaped
    })
}

fn escape_line_comment(source: &str) -> String {
    source
        .chars()
        .map(|ch| if matches!(ch, '\n' | '\r') { ' ' } else { ch })
        .collect()
}

fn escape_block_comment(source: &str) -> String {
    escape_line_comment(source).replace("*/", "* /")
}

fn escape_template_expression(source: &str) -> String {
    source
        .chars()
        .map(|ch| {
            if matches!(ch, '`' | '{' | '}') {
                ' '
            } else {
                ch
            }
        })
        .collect()
}
