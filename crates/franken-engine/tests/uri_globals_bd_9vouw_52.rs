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

/// Decode (ES2020 18.2.6.1.2): `decodeURI` keeps the escapes of reserved
/// characters as written, a malformed escape or ill-formed UTF-8
/// (truncated, overlong, a surrogate, a 5-byte lead) is a catchable
/// `URIError: URI malformed`, and a missing argument is `undefined`. Before
/// this, `decodeURI` decoded `%2F` too, every malformed input came back
/// unchanged (so `try { decodeURIComponent(s) } catch` never caught), and
/// a call with no argument read a neighboring register.
#[test]
fn decode_keeps_reserved_escapes_and_rejects_malformed_input() {
    assert_eq!(
        eval_to_string(
            "[decodeURI('%2F%3B%41%23%3f'), decodeURIComponent('%2F%3B%41%23%3f'), \
             decodeURI('%C3%A9%20'), encodeURIComponent(), decodeURI()].join('|');"
        ),
        "%2F%3BA%23%3f|/;A#?|é |undefined|undefined"
    );
    assert_eq!(
        eval_to_string(
            "function attempt(f) { try { return f(); } catch (e) { \
             return e.name + ':' + e.message + ':' + (e instanceof URIError); } } \
             ['%', '%4', '%GG', '%+1', '%C0%80', '%E2%82', '%E2%82%', '%ED%A0%80', \
             '%F8%80%80%80%80', 'ok%41'].map((s) => attempt(() => decodeURIComponent(s))).join('|');"
        ),
        "URIError:URI malformed:true|URIError:URI malformed:true|URIError:URI malformed:true|\
         URIError:URI malformed:true|URIError:URI malformed:true|URIError:URI malformed:true|\
         URIError:URI malformed:true|URIError:URI malformed:true|URIError:URI malformed:true|okA"
    );
    assert_eq!(
        eval_to_string(
            "function safe(s) { try { return decodeURIComponent(s); } catch (e) { return 'raw:' + s; } } \
             ['a%20b', '%E0%A4%A', 'x%'].map(safe).join('|');"
        ),
        "a b|raw:%E0%A4%A|raw:x%"
    );
}
