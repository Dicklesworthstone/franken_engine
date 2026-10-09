//! bd-9vouw.379: a built-in prototype method, `constructor`, @@iterator or
//! getter (`Map.prototype.size`) is an existing own property: a
//! redefinition keeps the attributes its descriptor leaves out, an
//! assignment replaces only its value, a generic descriptor changes only
//! enumerable/configurable, and getOwnPropertyDescriptor reports the
//! redefined accessor. They were taken as absent: `{ value }` made the
//! method non-writable and non-configurable (the next redefinition threw)
//! and an assignment made it enumerable, so for-in over arrays listed it.
//! A frozen method and a getter-only write still fail. The line is Node
//! v22.2.0's output for the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn builtin_prototype_properties_keep_their_attributes_when_redefined() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + "=" + f()); } catch (e) { out.push(name + "!" + e.constructor.name); } }
function attrs(o, k) { var d = Object.getOwnPropertyDescriptor(o, k); return d === undefined ? "absent" : ("value" in d ? "data," + d.writable : "accessor") + "," + d.enumerable + "," + d.configurable; }
t("map", function () { Object.defineProperty(Array.prototype, "map", { value: function () { return "a"; } }); var first = [1].map() + ":" + attrs(Array.prototype, "map"); Object.defineProperty(Array.prototype, "map", { value: function () { return "b"; } }); return first + ":" + [1].map(); });
t("trim", function () { Object.defineProperty(String.prototype, "trim", { value: function () { return 1; } }); Object.defineProperty(String.prototype, "trim", { value: function () { return 2; } }); return " x ".trim() + ":" + attrs(String.prototype, "trim"); });
t("size", function () { var g = function () { return 8; }; Object.defineProperty(Map.prototype, "size", { get: function () { return 7; } }); Object.defineProperty(Map.prototype, "size", { get: g }); return new Map().size + ":" + attrs(Map.prototype, "size") + ":" + (Object.getOwnPropertyDescriptor(Map.prototype, "size").get === g); });
t("assign", function () { Array.prototype.forEach = Array.prototype.forEach; var ks = []; for (var k in [1, 2]) ks.push(k); return ks.join("/") + ":" + attrs(Array.prototype, "forEach") + ":" + Object.getOwnPropertyNames(Array.prototype).filter(function (k) { return k === "forEach"; }).length; });
t("hop", function () { Object.defineProperty(Object.prototype, "hasOwnProperty", { value: Object.prototype.hasOwnProperty }); return attrs(Object.prototype, "hasOwnProperty") + ":" + ({ a: 1 }).hasOwnProperty("a"); });
t("delete", function () { Object.defineProperty(Array.prototype, "copyWithin", { value: 1 }); return delete Array.prototype.copyWithin && typeof [].copyWithin + ":" + attrs(Array.prototype, "copyWithin"); });
t("fn-name", function () { Object.defineProperty(Function.prototype, "name", { value: "x" }); return Function.prototype.name + ":" + attrs(Function.prototype, "name"); });
t("iter", function () { var f = Array.prototype[Symbol.iterator]; Object.defineProperty(Array.prototype, Symbol.iterator, { value: f }); Object.defineProperty(Array.prototype, Symbol.iterator, { value: f }); return attrs(Array.prototype, Symbol.iterator) + ":" + [...[1, 2]].length; });
t("ctor", function () { Object.defineProperty(Set.prototype, "constructor", { value: 5 }); Object.defineProperty(Set.prototype, "constructor", { value: 6 }); return Set.prototype.constructor + ":" + attrs(Set.prototype, "constructor"); });
t("generic", function () { Object.defineProperty(Array.prototype, "includes", { enumerable: true }); var ks = []; for (var k in []) ks.push(k); return ks.join("/") + ":" + attrs(Array.prototype, "includes") + ":" + [1].includes(1); });
t("frozen", function () { Object.defineProperty(Date.prototype, "getDay", { writable: false, configurable: false }); var same = Reflect.defineProperty(Date.prototype, "getDay", { value: Date.prototype.getDay }); var other = Reflect.defineProperty(Date.prototype, "getDay", { value: 1 }); return same + ":" + other + ":" + attrs(Date.prototype, "getDay"); });
t("size-builtin", function () { Object.defineProperty(Set.prototype, "size", { enumerable: false }); return new Set([1, 2]).size + ":" + attrs(Set.prototype, "size"); });
t("then", function () { Object.defineProperty(Promise.prototype, "then", { writable: true }); return attrs(Promise.prototype, "then"); });
t("set-getter", function () { "use strict"; try { ArrayBuffer.prototype.byteLength = 1; } catch (e) { return e.constructor.name + ":" + attrs(ArrayBuffer.prototype, "byteLength"); } return "no error"; });
console.log(out.join(' | '));
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
            "map=a:data,true,false,true:b | trim=2:data,true,false,true | size=8:accessor,false,true:true | assign=0/1:data,true,false,true:1 | hop=data,true,false,true:true | delete=undefined:absent | fn-name=x:data,false,false,true | iter=data,true,false,true:2 | ctor=6:data,true,false,true | generic=includes:data,true,true,true:true | frozen=true:false:data,false,false,false | size-builtin=2:accessor,false,true | then=data,true,false,true | set-getter=TypeError:accessor,false,true",
        ]
    );
}
