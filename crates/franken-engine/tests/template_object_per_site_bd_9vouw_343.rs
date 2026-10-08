//! bd-9vouw.343: a tagged template's strings array is its call site's one
//! template object (ES2020 12.2.9.3 GetTemplateObject): the same frozen
//! array on every evaluation of the site (a call, a loop iteration, an
//! arrow, a method), a different one for each site (two in one statement
//! too), with a frozen `raw` array that is non-writable, non-enumerable and
//! non-configurable. Each evaluation built a new mutable array whose `raw`
//! was an ordinary property, so a tag could not key a cache on it (lit,
//! styled-components, graphql-tag). The line is Node v22.2.0's output for
//! the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn tagged_templates_pass_their_call_sites_one_frozen_template_object() {
    let source = r#"
var out = [];
function id(s) { return s; }
function site() { return id`a${1}b`; }
var first = site(), second = site();
out.push("same-site=" + (first === second));
var loop = []; for (var i = 0; i < 3; i++) { loop.push(id`x`); }
out.push("loop=" + (loop[0] === loop[1] && loop[1] === loop[2]));
var a = id`same`, b = id`same`;
out.push("distinct-sites=" + (a !== b));
var both = [id`p`, id`p`]; out.push("one-statement=" + (both[0] !== both[1]));
out.push("frozen=" + Object.isFrozen(first) + "," + Object.isFrozen(first.raw) + "," + Array.isArray(first) + "," + Array.isArray(first.raw));
var d = Object.getOwnPropertyDescriptor(first, "raw"); out.push("raw-desc=" + [d.writable, d.enumerable, d.configurable].join());
out.push("keys=" + Object.keys(first).join("|") + ";" + first.length + ";" + first.raw.length);
out.push("strict-write=" + (function () { "use strict"; try { first[0] = "z"; return "no"; } catch (e) { return e.constructor.name; } })());
out.push("sloppy-write=" + (function () { first.foo = 1; return first.foo; })());
out.push("raw=" + String.raw`a\nb${2}c` + ";" + id`\u0041`[0] + id`\u0041`.raw[0]);
var arrow = () => id`q`; out.push("arrow=" + (arrow() === arrow()));
class K { m() { return id`k`; } } var k = new K(); out.push("method=" + (k.m() === k.m()));
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
            "same-site=true loop=true distinct-sites=true one-statement=true frozen=true,true,true,true raw-desc=false,false,false keys=0|1;2;2 strict-write=TypeError sloppy-write=undefined raw=a\\nb2c;A\\u0041 arrow=true method=true",
        ]
    );
}

/// A tagged template's invalid escape (`\01`, `\8`, `\xg`, `\u{110000}`, `\u12`)
/// is not a SyntaxError: its cooked string is undefined and its raw string
/// keeps the text (ES2018 template literal revision; Test262
/// tagged-template/invalid-escape-sequences). The parser rejected them as
/// it does in an untagged template. The line is Node v22.2.0's.
#[test]
fn tagged_template_invalid_escapes_cook_to_undefined() {
    let source = r#"
var out = [];
function tag(s) { return (s[0] === undefined) + ":" + s.raw[0] + ":" + s.length; }
out.push("octal=" + tag`\01`);
out.push("octal8=" + tag`\8`);
out.push("xbad=" + tag`\xg`);
out.push("ubad=" + tag`\u{110000}`);
out.push("ushort=" + tag`\u12`);
out.push("valid=" + tag`a\n`);
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
            "octal=true:\\01:1 octal8=true:\\8:1 xbad=true:\\xg:1 ubad=true:\\u{110000}:1 ushort=true:\\u12:1 valid=false:a\\n:1",
        ]
    );
}
