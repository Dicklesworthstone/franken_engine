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
