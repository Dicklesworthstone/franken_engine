#![forbid(unsafe_code)]

use frankenengine_engine::{HybridRouter, RouteReason};

fn route(source: &str) -> RouteReason {
    HybridRouter::classify_source_route(source)
}

#[test]
fn mr_neutral_comment_and_literal_padding_preserves_route() {
    let cases = [
        ("1 + 1", RouteReason::DefaultQuickJsPath),
        ("await job()", RouteReason::ContainsAwaitKeyword),
        (
            "import value from 'pkg';",
            RouteReason::ContainsImportKeyword,
        ),
    ];

    for (source, expected) in cases {
        assert_eq!(route(source), expected);

        let padded_with_comments =
            format!("/* import noise */ 'await noise';\n{source}\n// await noise");
        assert_eq!(route(&padded_with_comments), expected);

        let padded_with_literals = format!("`literal import await`;\n{source}\n\"import await\";");
        assert_eq!(route(&padded_with_literals), expected);
    }
}

#[test]
fn mr_template_expression_keywords_preserve_code_position_route() {
    let direct_import = "import('pkg')";
    let templated_import = format!("const rendered = `${{{direct_import}}}`;");
    assert_eq!(route(direct_import), RouteReason::ContainsImportKeyword);
    assert_eq!(route(&templated_import), route(direct_import));

    let direct_await = "await job()";
    let templated_await = format!("const rendered = `${{{direct_await}}}`;");
    assert_eq!(route(direct_await), RouteReason::ContainsAwaitKeyword);
    assert_eq!(route(&templated_await), route(direct_await));

    assert_eq!(
        route("const rendered = `import await`;"),
        RouteReason::DefaultQuickJsPath
    );
}

#[test]
fn mr_import_dominates_await_under_order_and_nesting_transformations() {
    let variants = [
        "await job(); import value from 'pkg';",
        "import value from 'pkg'; await job();",
        "await job(); const rendered = `${import('pkg')}`;",
        "const rendered = `${await job(); import('pkg')}`;",
        "const rendered = `${import('pkg')}`; await job();",
    ];

    for source in variants {
        assert_eq!(route(source), RouteReason::ContainsImportKeyword);
    }

    assert_eq!(
        route("await job(); `import text only`;"),
        RouteReason::ContainsAwaitKeyword
    );
}
