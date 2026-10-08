//! bd-9vouw.378: TypedArray(object) reads an object whose @@iterator is
//! null or undefined as an array-like: GetMethod (ES2020 7.3.10) answers no
//! method. A non-callable method still throws, a generator method iterates,
//! and Array.from agrees. It threw a TypeError. The line is Node v22.2.0's
//! output for the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn typed_arrays_read_a_nullish_iterator_source_as_array_like() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + "=" + f()); } catch (e) { out.push(name + "!" + e.constructor.name); } }
t("ta-null", function () { return new Uint8Array({ [Symbol.iterator]: null, length: 2, 0: 7 }).join(); });
t("ta-undef", function () { return new Int16Array({ [Symbol.iterator]: undefined, length: 1, 0: 3 }).join(); });
t("from-null", function () { return Array.from({ [Symbol.iterator]: null, length: 2, 1: "b" }).join("|"); });
t("ta-not-callable", function () { return new Uint8Array({ [Symbol.iterator]: 1 }).length; });
t("ta-iter", function () { return new Uint8Array({ [Symbol.iterator]: function* () { yield 4; yield 5; } }).join(); });
t("shadow", function () { var proto = { [Symbol.iterator]: function* () { yield 9; } }; var o = Object.create(proto); o[Symbol.iterator] = null; o.length = 1; o[0] = 2; return Array.from(o).join(); });
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
        ["ta-null=7,0 ta-undef=3 from-null=|b ta-not-callable!TypeError ta-iter=4,5 shadow=2",]
    );
}
