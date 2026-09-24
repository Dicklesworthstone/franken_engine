//! bd-9vouw.52: `encodeURIComponent`, `decodeURIComponent`, `encodeURI` and
//! `decodeURI` are callable.
//!
//! The UTF-8 percent-codec hostcalls existed but no lowering routed a bare
//! call to them, so every call hit an undefined global. Expected strings are
//! what Node v22.2.0 prints for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

#[test]
fn uri_codecs_round_trip() {
    assert_eq!(
        eval_to_string(
            "[encodeURIComponent('é&'), decodeURIComponent('%C3%A9%26'), \
             encodeURI('http://x.y/a b?q=1&r=é'), decodeURI('a%20b'), \
             encodeURIComponent(12)].join('|');"
        ),
        "%C3%A9%26|é&|http://x.y/a%20b?q=1&r=%C3%A9|a b|12"
    );
}

#[test]
fn a_local_binding_shadows_the_global() {
    assert_eq!(
        eval_to_string(
            "function encodeURIComponent(x) { return 'local:' + x; } encodeURIComponent('a');"
        ),
        "local:a"
    );
}
