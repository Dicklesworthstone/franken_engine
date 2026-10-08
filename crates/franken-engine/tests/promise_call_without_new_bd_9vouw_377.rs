//! bd-9vouw.377: Promise's [[Call]] throws a TypeError (ES2020 25.6.3.1
//! step 1) on every path: a plain call, Function.prototype.call and apply,
//! and Reflect.apply. apply builds its argument list first (the getter
//! runs). Construction (new, Reflect.construct, a subclass) still builds
//! promises. The call, apply and Reflect.apply forms returned a promise.
//! The line is Node v22.2.0's output for the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn promise_called_without_new_throws_on_every_call_path() {
    let source = r#"
var out = [];
function t(name, f) { try { var r = f(); out.push(name + "=" + (r instanceof Promise ? "promise" : typeof r)); } catch (e) { out.push(name + "!" + e.constructor.name); } }
t("call", function () { return Promise(function () {}); });
t("dot-call", function () { return Promise.call({}, function () {}); });
t("apply", function () { return Promise.apply(null, [function () {}]); });
t("reflect-apply", function () { return Reflect.apply(Promise, undefined, [function () {}]); });
var order = []; t("apply-order", function () { return Promise.apply(null, { get length() { order.push("length"); return 0; } }); }); out.push("order=" + order.join());
t("new", function () { return new Promise(function () {}); });
t("reflect-construct", function () { return Reflect.construct(Promise, [function () {}]); });
class P extends Promise {} t("subclass", function () { return new P(function () {}); });
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
            "call!TypeError dot-call!TypeError apply!TypeError reflect-apply!TypeError apply-order!TypeError order=length new=promise reflect-construct=promise subclass=promise",
        ]
    );
}
