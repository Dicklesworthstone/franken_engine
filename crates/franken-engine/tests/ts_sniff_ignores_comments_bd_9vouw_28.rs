//! bd-9vouw.28: comments never make a JavaScript source TypeScript.
//!
//! `source_looks_typescript` matched the raw text " as const" (so a comment
//! reading "identified as constructors" qualified) and header lines such as
//! "interface ..." inside block comments. The file was then run through TS
//! normalization, which mangled a `? 'null' : typeof v` ternary into a parse
//! error ("function expression requires a braced body"). That failed every
//! Test262 test whose description happened to trip the heuristic. Expected
//! execution values are what Node v22.2.0 prints for the same program.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ts_normalization::{SourceLanguage, classify_source_language};

#[test]
fn comments_do_not_classify_javascript_as_typescript() {
    for source in [
        "/* Built-in function objects that are not identified as constructors */ var a = 1;",
        "// interface Foo\nvar a = 1;",
        "/*\n  enum Colors\n  namespace N\n  type T = 1\n*/\nvar a = 1;",
        "// x!: number\nvar a = 1;",
    ] {
        assert_eq!(
            classify_source_language(Some("probe.js"), source),
            SourceLanguage::JavaScript,
            "{source:?}"
        );
    }
}

#[test]
fn real_typescript_is_still_detected() {
    assert_eq!(
        classify_source_language(None, "const colors = ['r', 'g'] as const;"),
        SourceLanguage::TypeScript
    );
    assert_eq!(
        classify_source_language(None, "interface Point { x: number }\nvar a = 1;"),
        SourceLanguage::TypeScript
    );
    // `as constructors` in code is not a const assertion either.
    assert_eq!(
        classify_source_language(None, "var as = 1; var constructors = 2; as, constructors;"),
        SourceLanguage::JavaScript
    );
}

#[test]
fn ternary_before_a_misleading_comment_runs() {
    let outcome = HybridRouter::default()
        .eval(
            "var f = function (v) { switch (v === null ? 'null' : typeof v) \
             { case 'string': return 's'; } }; /* identified as constructors */ f('x');",
        )
        .expect("plain JavaScript should run");
    assert_eq!(outcome.value, "s");
}
