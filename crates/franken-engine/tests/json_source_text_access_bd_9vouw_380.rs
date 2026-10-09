//! bd-9vouw.380: JSON.parse source text access, as Node v22 has it.
//! JSON.rawJSON(text) is a frozen null-prototype object holding one JSON
//! primitive's text, which JSON.stringify emits verbatim (a BigInt
//! replacer can keep every digit); padded text, an object or array, and
//! invalid JSON are SyntaxErrors. JSON.isRawJSON recognizes only its
//! results. A reviver gets a third argument whose `source` is the text of
//! a primitive that is still the parsed value. All three were missing. The
//! line is Node v22.2.0's output for the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn json_raw_json_and_reviver_source_text_match_node() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + "=" + f()); } catch (e) { out.push(name + "!" + e.constructor.name); } }
t("raw", function () { var r = JSON.rawJSON("12345678901234567890"); return [Object.getPrototypeOf(r) === null, Object.isFrozen(r), Object.keys(r).join(), r.rawJSON, JSON.isRawJSON(r)].join("/"); });
t("look-alike", function () { return JSON.isRawJSON(Object.freeze(Object.setPrototypeOf({ rawJSON: "1" }, null))) + "," + JSON.isRawJSON("1") + "," + JSON.isRawJSON(); });
t("stringify", function () { return JSON.stringify({ a: JSON.rawJSON("1e1000"), b: [JSON.rawJSON("\"x\""), JSON.rawJSON("null"), JSON.rawJSON("-0")] }); });
t("bigint", function () { return JSON.stringify({ n: 12345678901234567890n }, function (k, v) { return typeof v === "bigint" ? JSON.rawJSON(String(v)) : v; }); });
t("to-string", function () { return JSON.rawJSON({ toString: function () { return "true"; } }).rawJSON; });
t("bad-object", function () { return JSON.rawJSON("{}"); });
t("bad-array", function () { return JSON.rawJSON("[1]"); });
t("bad-space", function () { return JSON.rawJSON(" 1"); });
t("bad-tail", function () { return JSON.rawJSON("1\n"); });
t("bad-empty", function () { return JSON.rawJSON(""); });
t("bad-json", function () { return JSON.rawJSON("01"); });
t("bad-none", function () { return JSON.rawJSON(); });
t("symbol", function () { return JSON.rawJSON(Symbol()); });
t("members", function () { var d = Object.getOwnPropertyDescriptor(JSON, "rawJSON"); return [typeof JSON.rawJSON, JSON.rawJSON.name, JSON.rawJSON.length, JSON.isRawJSON.name, JSON.isRawJSON.length, d.writable, d.enumerable, d.configurable].join(); });
t("alias", function () { var raw = JSON.rawJSON, is = JSON.isRawJSON; return is(raw("2")); });
t("ctx", function () { var seen = []; JSON.parse("{\"a\": [1.50, true], \"b\": \"s\", \"c\": null}", function (k, v, ctx) { seen.push(k + ":" + JSON.stringify(ctx) + ":" + (Object.getPrototypeOf(ctx) === Object.prototype)); return v; }); return seen.join(";"); });
t("ctx-duplicate", function () { var seen = []; JSON.parse("{\"a\": 1, \"a\": 2.0}", function (k, v, ctx) { seen.push(k + ":" + ctx.source); return v; }); return seen.join(";"); });
t("ctx-modified", function () { var seen = []; JSON.parse("[1, 2, {\"x\": 3}]", function (k, v, ctx) { seen.push(k + ":" + ctx.source); if (k === "0") { this[1] = 5; this[2] = { x: 3 }; } return v; }); return seen.join(";"); });
t("ctx-appended", function () { var seen = []; JSON.parse("[1,[]]", function (k, v, ctx) { seen.push(k + ":" + ctx.source); if (v === 1) this[1].push("barf"); return this[k]; }); return seen.join(";"); });
t("ctx-same-value", function () { var seen = []; JSON.parse("[7]", function (k, v, ctx) { seen.push(k + ":" + ctx.source); return v; }); JSON.parse("[\"q\"]", function (k, v, ctx) { if (k === "") return v; this[0] = "q"; seen.push(k + ":" + ctx.source); return v; }); return seen.join(";"); });
console.log(out.join(" | "));
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
            "raw=true/true/rawJSON/12345678901234567890/true | look-alike=false,false,false | stringify={\"a\":1e1000,\"b\":[\"x\",null,-0]} | bigint={\"n\":12345678901234567890} | to-string=true | bad-object!SyntaxError | bad-array!SyntaxError | bad-space!SyntaxError | bad-tail!SyntaxError | bad-empty!SyntaxError | bad-json!SyntaxError | bad-none!SyntaxError | symbol!TypeError | members=function,rawJSON,1,isRawJSON,1,true,false,true | alias=true | ctx=0:{\"source\":\"1.50\"}:true;1:{\"source\":\"true\"}:true;a:{}:true;b:{\"source\":\"\\\"s\\\"\"}:true;c:{\"source\":\"null\"}:true;:{}:true | ctx-duplicate=a:2.0;:undefined | ctx-modified=0:1;1:undefined;x:undefined;2:undefined;:undefined | ctx-appended=0:1;0:undefined;1:undefined;:undefined | ctx-same-value=0:7;:undefined;0:\"q\"",
        ]
    );
}
