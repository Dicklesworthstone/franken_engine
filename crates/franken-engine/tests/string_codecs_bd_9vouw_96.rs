#![forbid(unsafe_code)]
//! bd-9vouw.96 (part): `btoa`, `atob`, `escape` and `unescape` were not
//! defined ("btoa is not defined"). They are global functions now, both
//! intercepted calls and first-class values (`typeof`, `.map(btoa)`), and a
//! program's own declaration of the name still wins. Expected strings are
//! Node v22.2.0's completion values for the same programs.
//!
//! No-claim: Node throws a DOMException from btoa/atob; this engine throws
//! an Error with the same `name` (InvalidCharacterError), message and `code`,
//! so `e.constructor` is `Error`, not DOMException. `structuredClone` is
//! still missing (bd-9vouw.96).
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
fn btoa_and_atob_round_trip_latin1() {
    check(
        "[btoa('hello'), atob('aGVsbG8='), atob(' aGVs bG8 '), atob('aGVsbG8'), btoa(''), atob(''), \
         btoa(String.fromCharCode(255, 0, 128)), btoa(null), btoa(12), atob('YR')].join('|')",
        "aGVsbG8=|hello|hello|hello|||/wCA|bnVsbA==|MTI=|a",
    );
    check(
        "Array.from(atob('/wCA'), (c) => c.charCodeAt(0)).join()",
        "255,0,128",
    );
}

#[test]
fn btoa_and_atob_are_first_class_values() {
    check(
        "var f = btoa; [f('a'), ['a', 'b'].map(btoa).join(), typeof btoa, typeof atob, btoa.length, \
         atob.length, btoa.name].join('|')",
        "YQ==|YQ==,Yg==|function|function|1|1|btoa",
    );
    check(
        "function btoa(x) { return 'mine:' + x; } btoa('a')",
        "mine:a",
    );
}

#[test]
fn btoa_and_atob_errors() {
    check(
        "var r = []; for (const bad of [() => btoa('\\u20ac'), () => atob('*'), () => atob('a'), \
         () => atob('YQ='), () => atob('Y=Q=')]) { try { bad(); r.push('none'); } catch (e) { \
         r.push(e.name + ':' + e.message + ':' + e.code + ':' + (e instanceof Error)); } } r.join('|')",
        "InvalidCharacterError:Invalid character:5:true|InvalidCharacterError:Invalid character:5:true|\
         InvalidCharacterError:The string to be decoded is not correctly encoded.:5:true|\
         InvalidCharacterError:Invalid character:5:true|InvalidCharacterError:Invalid character:5:true",
    );
    check(
        "var r; try { btoa(); r = 'none'; } catch (e) { r = e.name + ':' + (e instanceof TypeError); } r",
        "TypeError:true",
    );
    check(
        "var r; try { btoa(Symbol('s')); r = 'none'; } catch (e) { r = e.name; } r",
        "TypeError",
    );
}

#[test]
fn escape_and_unescape_follow_annex_b() {
    check(
        "[escape('a b'), escape('\\u00e4\\u00f6\\u00fc\\u20ac'), escape('A-Za-z0-9@*_+-./'), \
         escape('\\u{1F600}'), escape(), escape.length, typeof escape].join('|')",
        "a%20b|%E4%F6%FC%u20AC|A-Za-z0-9@*_+-./|%uD83D%uDE00|undefined|1|function",
    );
    check(
        "[unescape('%u20AC%41%zz%4'), unescape('%uD83D%uDE00'), unescape('%E4'), unescape(), \
         unescape.length, unescape(escape('x\\u00ff\\u0100 y'))].join('|')",
        "\u{20ac}A%zz%4|\u{1F600}|\u{e4}|undefined|1|x\u{ff}\u{100} y",
    );
}
