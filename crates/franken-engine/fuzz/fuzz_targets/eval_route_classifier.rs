#![no_main]

use frankenengine_engine::{HybridRouter, RouteReason};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }

    let source = String::from_utf8_lossy(data);
    let first = HybridRouter::classify_source_route(&source);
    let second = HybridRouter::classify_source_route(&source);
    assert_eq!(first, second);
    assert_ne!(first, RouteReason::DirectEngineInvocation);

    let encoded = serde_json::to_string(&first).expect("route reason should serialize");
    let decoded: RouteReason =
        serde_json::from_str(&encoded).expect("route reason should deserialize");
    assert_eq!(decoded, first);
});
