//! bd-9vouw.373: `undefined`, `NaN` and `Infinity` are identifiers naming
//! the global object's non-writable properties (ES2020 18.1), so they can
//! be assigned and updated: unshadowed, the write is a no-op in sloppy code
//! and a TypeError in strict code; a local binding of that name takes the
//! update. The parser read them as constants and rejected every such
//! target as an early error, failing the whole program. The line is Node
//! v22.2.0's output for the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn undefined_nan_and_infinity_are_assignable_global_value_properties() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + "=" + f()); } catch (e) { out.push(name + "!" + e.constructor.name); } }
t("sloppy-undefined", function () { undefined = 5; return typeof undefined; });
t("sloppy-nan", function () { NaN = 1; return NaN !== NaN; });
t("sloppy-infinity", function () { Infinity = 0; return Infinity > 1e308; });
t("strict-nan", function () { "use strict"; NaN = 12; return "no"; });
t("strict-undefined", function () { "use strict"; undefined = 12; return "no"; });
t("strict-infinity", function () { "use strict"; Infinity = 12; return "no"; });
t("update-local", function () { var Infinity = 1; Infinity++; ++Infinity; Infinity += 1; return "ok"; });
t("delete", function () { return delete NaN; });
console.log(out.join(' '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "sloppy-undefined=undefined sloppy-nan=true sloppy-infinity=true strict-nan!TypeError strict-undefined!TypeError strict-infinity!TypeError update-local=ok delete=false",
        ]
    );
}
