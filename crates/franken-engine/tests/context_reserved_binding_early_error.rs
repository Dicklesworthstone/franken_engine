//! ES2020 11.6.2.2 / 12.1.1 early errors: strict code reserves
//! `implements`, `interface`, `let`, `package`, `private`, `protected`,
//! `public`, `static` and `yield`, and async functions and modules reserve
//! `await`; none can be a binding name there (escaped spellings included).
//! The parser accepted them (e.g. Test262
//! expressions/object/method-definition/async-await-as-binding-identifier.js
//! and expressions/class/async-method/await-as-binding-identifier.js in the
//! 2026-09-27 Node-calibrated sample). `yield` inside sloppy generators and
//! `await` used as an identifier reference are not covered.
//! Accept/reject verdicts are Node v22.2.0's for the same text.

use frankenengine_engine::parser_api_stability::parse_script;

#[test]
fn reserved_words_cannot_be_bound_in_their_contexts() {
    for source in [
        r#""use strict"; var implements;"#,
        r#""use strict"; function f(yield) {}"#,
        r#""use strict"; let static = 1;"#,
        "async function f() { var await; }",
        "async function f2(await) {}",
        "class C { async m() { let await = 1; } }",
        r"var o = { async m() { var await; } };",
    ] {
        let error = parse_script(source).expect_err("Node rejects this program");
        assert!(
            error
                .to_string()
                .contains("is a reserved word here and cannot be a binding name"),
            "{source}: {error}"
        );
    }
}

#[test]
fn the_same_names_are_bindable_elsewhere() {
    for source in [
        "var implements = 1;",
        "function f3(yield) {}",
        "function g() { var await = 1; }",
        "var static = 1;",
        "async function h() { var x = { await: 1 }; return x.await; }",
    ] {
        parse_script(source).unwrap_or_else(|error| panic!("{source} must parse: {error}"));
    }
}
