//! bd-9vouw.64 fields step 3: class field shapes from Test262's
//! class/elements suite that the first field parser mishandled: fields
//! without an initializer, fields after a generator method on the same line,
//! several computed-key fields on one line, string computed keys, identifier
//! keys written with Unicode escapes. Expected strings are Node v22.2.0's
//! output for the same programs.
//!
//! No-claim: fields separated only by a line break (no `;`) still do not
//! parse; the logical-line merger joins physical lines with a space before
//! the class body is parsed.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

#[test]
fn fields_without_initializer_are_own_undefined_properties() {
    check(
        "class C { a; b = 42; } const c = new C();
         [Object.keys(c).join(), c.a, c.b, Object.prototype.hasOwnProperty.call(c, 'a')].join(' ');",
        "a,b  42 true",
    );
}

#[test]
fn fields_after_a_generator_method_on_the_same_line() {
    check(
        "class C { *m() { return 42; } a; b = 42; } const c = new C();
         [c.m().next().value, Object.keys(c).join()].join(' ');",
        "42 a,b",
    );
    check(
        "class C { static *m() { return 1; } a = 1; static b = 2; } [new C().a, C.b].join(' ');",
        "1 2",
    );
}

#[test]
fn computed_key_fields_on_one_line() {
    check(
        "var x = 'p'; var y = 'q'; class C { [x]; [y] = 42; } const c = new C();
         [Object.keys(c).join(), c.q].join(' ');",
        "p,q 42",
    );
    check(
        "var x = 'p'; var y = 'q'; class C { *m() { return 1; } [x]; [y] = 42; } const c = new C();
         [Object.keys(c).join(), c.q].join(' ');",
        "p,q 42",
    );
    check(
        "class C { [10] = 'meep'; ['not initialized']; } const c = new C();
         [Object.keys(c).join(), c[10]].join(' ');",
        "10,not initialized meep",
    );
}

/// Keys spelled with `\u` escapes name the property they spell, for fields,
/// methods and object literal keys alike.
#[test]
fn escaped_identifier_keys() {
    check(
        "class C { \\u{6F} = 1; \\u2118 = 2; \\u0062() { return 'b'; } } const c = new C();
         [c.o, Object.keys(c).length, c.b(), ({ \\u0061: 7 }).a].join(' ');",
        "1 2 b 7",
    );
}
