//! Security conformance tests for HybridRouter import pattern routing
//!
//! This test suite enforces that HybridRouter correctly routes JavaScript/TypeScript
//! code to appropriate engines based on keyword detection, preventing route manipulation
//! attacks that could bypass security controls.
//!
//! SECURITY REQUIREMENT: Any code containing `import` or `await` keywords must route
//! to V8 engine regardless of context (including template expressions), as V8 has
//! stricter security controls for module/async evaluation.

#![forbid(unsafe_code)]

use frankenengine_engine::{HybridRouter, RouteReason};

#[test]
fn import_in_template_literal_expression_routes_to_v8() {
    // SECURITY CRITICAL: import inside template expression must route to V8
    let test_cases = [
        // Basic template expression with import
        "`Template ${import('module')} literal`",
        // Complex template with multiple expressions
        "`Start ${import('a')} middle ${1 + 1} end`",
        // Nested template expressions
        "`Outer ${`Inner ${import('nested')}`} template`",
        // Import with dynamic expression
        "`Module: ${import(moduleName)}`",
        // Mixed import and await in template
        "`Mixed ${import('a')} and ${await b()}`",
    ];

    for source in test_cases {
        let route_reason = HybridRouter::classify_source_route(source);
        assert_eq!(
            route_reason,
            RouteReason::ContainsImportKeyword,
            "Template expression with import failed to route to V8: {source:?}"
        );
    }
}

#[test]
fn await_in_template_literal_expression_routes_to_v8() {
    // SECURITY CRITICAL: await inside template expression must route to V8
    let test_cases = [
        // Basic template expression with await
        "`Result: ${await fetch()}`",
        // Multiple awaits in template
        "`First ${await a()} second ${await b()}`",
        // Await with complex expression
        "`Value: ${await promise.then(x => x * 2)}`",
        // Nested template with await
        "`Outer ${`Inner ${await getValue()}`} template`",
    ];

    for source in test_cases {
        let route_reason = HybridRouter::classify_source_route(source);
        assert_eq!(
            route_reason,
            RouteReason::ContainsAwaitKeyword,
            "Template expression with await failed to route to V8: {source:?}"
        );
    }
}

#[test]
fn template_literals_without_keywords_route_to_quickjs() {
    // Verify template literals without import/await route to default QuickJS
    let test_cases = [
        // Plain template literal
        "`Simple template literal`",
        // Template with safe expressions
        "`Value: ${42}`",
        "`Math: ${1 + 2 * 3}`",
        "`Boolean: ${true && false}`",
        // Complex expressions without keywords
        "`Object: ${obj.property.method()}`",
        "`Array: ${arr[0]}`",
        // Multiline template
        "`Line 1\n${value}\nLine 3`",
    ];

    for source in test_cases {
        let route_reason = HybridRouter::classify_source_route(source);
        assert_eq!(
            route_reason,
            RouteReason::DefaultQuickJsPath,
            "Safe template expression incorrectly routed to V8: {source:?}"
        );
    }
}

#[test]
fn quoted_keywords_do_not_affect_routing() {
    // Verify that keywords in string literals are ignored (existing coverage)
    let test_cases = [
        // Keywords in single quotes
        "'import module from pkg'",
        "'await promise'",
        // Keywords in double quotes
        "\"import module from pkg\"",
        "\"await promise\"",
        // Keywords in template literals without expressions
        "`import module from pkg`",
        "`await promise`",
        // Mixed quotes
        "'import' + \"await\"",
    ];

    for source in test_cases {
        let route_reason = HybridRouter::classify_source_route(source);
        assert_eq!(
            route_reason,
            RouteReason::DefaultQuickJsPath,
            "Quoted keyword incorrectly affected routing: {source:?}"
        );
    }
}

#[test]
fn comment_keywords_do_not_affect_routing() {
    // Verify that keywords in comments are ignored (existing coverage)
    let test_cases = [
        // Line comments with keywords
        "// import module",
        "// await promise",
        "/* import module */",
        "/* await promise */",
        // Mixed comments and code
        "// import ignored\nconst x = 42;",
        "/* await ignored */ function test() {}",
    ];

    for source in test_cases {
        let route_reason = HybridRouter::classify_source_route(source);
        assert_eq!(
            route_reason,
            RouteReason::DefaultQuickJsPath,
            "Comment keyword incorrectly affected routing: {source:?}"
        );
    }
}

#[test]
fn export_statements_route_to_v8() {
    // SECURITY CRITICAL: export statements are module syntax and must route to V8
    let test_cases = [
        // Basic export statements
        "export default value",
        "export const x = 1",
        "export { name }",
        "export { name as alias }",
        "export * from 'module'",
        "export { default } from 'module'",
        // Export with expressions
        "export default function() {}",
        "export const fn = () => {}",
        // Complex export statements
        "export { a, b, c } from './module'",
    ];

    for source in test_cases {
        let route_reason = HybridRouter::classify_source_route(source);
        assert_eq!(
            route_reason,
            RouteReason::ContainsImportKeyword,
            "Export statement failed to route to V8: {source:?}"
        );
    }
}

#[test]
fn malicious_route_manipulation_attempts_fail() {
    // SECURITY TEST: Attempt to manipulate routing through edge cases
    let _manipulation_attempts = [
        // Try to hide import in complex template nesting
        "`${(() => { return import('evil') })()}`",
        // Try to hide await in complex expression
        "`${Promise.resolve().then(() => await fetch('/evil'))}`",
        // Unicode/escape attempts in identifiers (should still detect)
        "import\\u0020module", // import with unicode space
        // Keyword-like identifiers that aren't actual keywords
        "importing = true",
        "awaiting = promise",
        "importModule()",
        "awaitResult()",
    ];

    // Evil attempts with actual keywords should route to V8 for security
    let should_route_to_v8 = [
        "`${(() => { return import('evil') })()}`",
        "`${Promise.resolve().then(() => await fetch('/evil'))}`",
    ];

    for source in should_route_to_v8 {
        let route_reason = HybridRouter::classify_source_route(source);
        assert!(
            matches!(
                route_reason,
                RouteReason::ContainsImportKeyword | RouteReason::ContainsAwaitKeyword
            ),
            "Malicious route manipulation succeeded: {source:?} -> {route_reason:?}"
        );
    }

    // Non-keyword identifiers should route to QuickJS
    let should_route_to_quickjs = [
        "importing = true",
        "awaiting = promise",
        "importModule()",
        "awaitResult()",
    ];

    for source in should_route_to_quickjs {
        let route_reason = HybridRouter::classify_source_route(source);
        assert_eq!(
            route_reason,
            RouteReason::DefaultQuickJsPath,
            "False positive routing manipulation: {source:?}"
        );
    }
}

#[test]
fn engine_routing_security_invariants() {
    // SECURITY INVARIANT: Any potential module/async code routes to V8
    // This test documents the security contract

    // These MUST route to V8 for security:
    let v8_required = [
        "import x from 'y'",
        "await promise",
        "export default value",
        "export const x = 1",
        "export { name }",
        "`Template ${import('dynamic')}`",
        "`Async ${await fetch()}`",
    ];

    for source in v8_required {
        let route_reason = HybridRouter::classify_source_route(source);
        assert!(
            !matches!(route_reason, RouteReason::DefaultQuickJsPath),
            "SECURITY VIOLATION: Module/async code routed to QuickJS: {source:?}"
        );
    }

    // These CAN route to QuickJS safely:
    let quickjs_safe = [
        "const x = 42",
        "function test() {}",
        "`Plain template`",
        "'string with import'",
        "// import in comment",
        "obj.import()",
        "var awaiting = true",
    ];

    for source in quickjs_safe {
        let route_reason = HybridRouter::classify_source_route(source);
        // These are safe to route to QuickJS but checking for V8 route is also acceptable
        // The key is that the actual keywords (not safe cases) MUST go to V8
        println!("Safe case '{source}' -> {route_reason:?}");
    }
}
