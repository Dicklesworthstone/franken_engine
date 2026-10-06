#![forbid(unsafe_code)]

//! Where a statement ends when the line ends without a semicolon, as npm
//! package sources write it:
//!
//! - bd-9vouw.194: a line ending with a regular-expression literal is a
//!   complete statement. Its closing `/` was taken for a division operator
//!   waiting for its right operand, so the next line joined it (json5's
//!   `module.exports.Space_Separator = /[...]/`, mime-types, fast-uri under
//!   ajv: "invalid assignment target").
//! - bd-9vouw.195: a line ending with an operator keyword (`new`, `in`,
//!   `instanceof`, `extends`) continues: babel's istanbul output writes
//!   `var d = new\n/*istanbul ignore start*/\n_base[...]()` (jsdiff), which
//!   ended at `new` and read it as a variable ("new is not defined").
//! - bd-9vouw.196: a do statement that is an else clause keeps its
//!   `while (...)`: minified `if(k)a();else do{..}while(c)` (preact) had the
//!   condition split off ("do-while requires a parenthesized condition"),
//!   and without a semicolon the next line became the body of a new
//!   `while (c)` loop and never ran.
//! - bd-9vouw.207: a lone `.` line continues a member access.
//! - bd-9vouw.212: a line ending with `function` or `class` continues.
//!
//! Expected lines are Node v22.2.0's output (Bun 1.4.2 prints the same).

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};

/// Runs `source` as a script, as frankenctl does, on both lanes.
fn run(source: &str) -> Vec<String> {
    let mut outputs = [LaneChoice::QuickJs, LaneChoice::V8].map(|lane| {
        let package = ExtensionPackage {
            extension_id: "statement-boundaries".to_string(),
            source: source.to_string(),
            source_file: None,
            module_root: None,
            capabilities: vec!["builtin".to_string()],
            version: "1.0.0".to_string(),
            metadata: Default::default(),
        };
        ExecutionOrchestrator::new(OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Script,
            ..OrchestratorConfig::default()
        })
        .execute(&package)
        .unwrap_or_else(|error| panic!("{lane:?}: {error}"))
        .console_output
        .into_iter()
        .map(|line| line.message)
        .collect::<Vec<_>>()
    });
    assert_eq!(outputs[0], outputs[1], "lanes disagree");
    std::mem::take(&mut outputs[0])
}

#[test]
fn a_line_ending_with_a_regular_expression_literal_is_complete_bd_9vouw_194() {
    let source = "var a = /x/\nvar b = /^\\s*([^;\\s]*)(?:;|\\s|$)/\nvar c = /[^#/:?]+/u\n\n// a comment line\nvar d = /^text\\//i\nvar e = 6 /\n  3\nconsole.log(String(a), String(b), String(c), String(d), a.test('x'), b.exec('  ab;c')[1], e)\n";
    assert_eq!(
        run(source),
        ["/x/ /^\\s*([^;\\s]*)(?:;|\\s|$)/ /[^#/:?]+/u /^text\\//i true ab 2"]
    );
}

#[test]
fn a_line_ending_with_an_operator_keyword_continues_bd_9vouw_195() {
    // `o.new` is a property name: that line ends.
    let source = "function Base() { this.v = 1 }\nvar lib = { 'default': Base }\nvar d = new\n/*istanbul ignore start*/\nlib\n/*istanbul ignore end*/\n[\n'default'\n]()\nvar o = { new: 2 }\nvar n = o.new\nvar t = 'v' in\n  d\nconsole.log(d.v, d instanceof Base, n, t)\n";
    assert_eq!(run(source), ["1 true 2 true"]);
}

/// bd-9vouw.195 follow-up: the line scanners read a word after a space as a
/// word of its own. They appended it to the word before (`k in` was `kin`,
/// `else return` was `elsereturn`), so `var t = k in` ended its line (the
/// .195 unit test failed in finalgate21/22) and the regex after
/// `else return` was read as a division.
#[test]
fn a_keyword_after_a_space_is_read_alone_bd_9vouw_195() {
    let source = "function f(s) { if (!s) return 0; else return /b+/.test(s) ? 2 : 1 }\nfunction g() { return new\nDate(0).getTime() }\nvar k = 'v', o = { v: 1 }\nvar t = k in\n  o\nconsole.log(f(''), f('abb'), f('a'), g(), t)\n";
    assert_eq!(run(source), ["0 2 1 0 true"]);
}

#[test]
fn a_do_statement_in_an_else_clause_keeps_its_condition_bd_9vouw_196() {
    // The last if statement's `while` on the next line is a loop of its own.
    let source = "var i = 0\nif (i > 5) i = 9; else do { i++ } while (i < 3)\nconsole.log('after', i)\nfunction f(k, a) { if (k) { a.z = 1 } else do { a.s = (a.s || 0) + 1 } while (a.s < 2); a.t = 4; return a }\nvar g = function (k, a) {if(k)a.z=1;else do{a.s=3}while(a.d);return a}\nconsole.log(JSON.stringify(f(1, {})), JSON.stringify(f(0, {})), JSON.stringify(g(0, {})))\nvar j = 0\nif (j) j = 1; else j = 2\nwhile (j < 5) j++\nconsole.log('loop', j)\n";
    assert_eq!(
        run(source),
        [
            "after 3",
            "{\"z\":1,\"t\":4} {\"s\":2,\"t\":4} {\"s\":3}",
            "loop 5"
        ]
    );
}

/// bd-9vouw.207: babel's istanbul output (jsdiff's json.js) puts the `.` of a
/// member access on a line of its own between comment lines; that line
/// continues the previous one and the line after it continues the dot. A
/// decimal point at a line end (`1.`) still ends its number.
#[test]
fn a_lone_dot_line_continues_a_member_access_bd_9vouw_207() {
    let source = "var _line = { lineDiff: { tokenize: 42 } };\nvar o = {};\no.tokenize =\n/*istanbul ignore start*/\n_line\n/*istanbul ignore end*/\n.\n/*istanbul ignore start*/\nlineDiff\n/*istanbul ignore end*/\n.tokenize;\nvar n = 1.\nvar m = 2\nconsole.log(o.tokenize, n + m);\n";
    assert_eq!(run(source), ["42 3"]);
}

/// bd-9vouw.212: `function` and `class` at a line end still need their name
/// or body. jsdiff's distance-iterator.js (istanbul) declares
/// `function\n/*istanbul ignore start*/\n_default\n/*istanbul ignore end*/\n(start, minLine, maxLine) {`,
/// which ended at `function` ("_default is not defined"). As property names
/// (`o.function`) they end the line, and `async` alone on a line is a
/// statement of its own (no line break may follow `async` in
/// `async function`).
#[test]
fn a_line_ending_with_function_or_class_continues_bd_9vouw_212() {
    let source = "var first = _default(1, 2, 3)()\nfunction\n/*istanbul ignore start*/\n_default\n/*istanbul ignore end*/\n(start, minLine, maxLine) {\n  return function iterator() { return start + minLine + maxLine }\n}\nvar g = function\nnamed\n(a) { return a + 5 }\nasync function\nnamedA\n(a) { return a + 7 }\nclass\nK\n{ m() { return 9 } }\nvar o = { function: 3, class: 4 }\nvar p = o.function\nvar q = o.class\nvar async = 5\nasync\nfunction h() { return 6 }\nconsole.log(first, g(1), new K().m(), p, q, async, h())\nnamedA(1).then(function (v) { console.log('async', v) })\n";
    assert_eq!(run(source), ["6 6 9 3 4 5 6", "async 8"]);
}

/// bd-9vouw.219: a for-in/of head's `in` / `of` is a whole word, with or
/// without spaces: minifiers write `for(const[k,v]of m)`, `for(const{a}of
/// xs)`, `for(const c of"abc")`, `for(const k in{...})` (ts-pattern), which
/// read as C-style headers ("for statement header must have three
/// semicolon-separated parts"). A loop variable spelled `index` or `of` and
/// an `in` test of a C-style loop keep their meaning.
#[test]
fn minified_for_in_of_heads_parse_bd_9vouw_219() {
    let source = "var out=[];for(const[n,r]of[[1,2],[3,4]])out.push(n+r);for(const{a,b}of[{a:1,b:2}])out.push(a*b);\nlet s=0;for(let[a]of[[5]])s+=a;for(var{b}of[{b:6}])s+=b;out.push(s);var t=[];for(t[0]of[7,8]);out.push(t[0]);\nfor(const x of\"ab\")out.push(x);for(const y of`cd`)out.push(y);for(const k in{p:1,q:2})out.push(k);\nfor(let index=0;index<2;index++)out.push('i'+index);var o={z:1},c=0;for(;'z'in o&&c<1;c++)out.push('in');for(let of of[9])out.push(of);\nconsole.log(out.join());\n";
    assert_eq!(run(source), ["3,7,2,11,8,a,b,c,d,p,q,i0,i1,in,9"]);
}

/// bd-9vouw.229: a for-in/of head that destructures into member targets
/// (`for ([o.a, o.b] of xs)`, `for ({ k: o.v, ...o.rest } of xs)`, defaults,
/// nesting, element targets, a labeled `continue`) assigns them at the start
/// of each iteration. The head was parsed as a binding pattern, which has no
/// member targets ("unsupported binding pattern"). Node v22.2.0 prints this
/// line; Bun 1.4.2 agrees.
#[test]
fn for_in_of_heads_destructure_into_member_targets_bd_9vouw_229() {
    let source = "const o = {}; const r = [];\nfor ([o.a, o.b] of [[1, 2], [3, 4]]) r.push(o.a + o.b);\nfor ({ k: o.v, ...o.rest } of [{ k: 5, x: 6 }]) r.push(o.v, JSON.stringify(o.rest));\nfor ([o.d = 9, [o.e]] of [[undefined, [7]]]) r.push(o.d, o.e);\nfor ([o.f] in { ab: 1 }) r.push(o.f);\nconst arr = [];\nfor ([arr[0], arr[1]] of [['p', 'q']]) r.push(arr.join(''));\nouter: for ([o.g] of [[1], [2], [3]]) { if (o.g === 2) continue outer; r.push('g' + o.g); }\nconsole.log(r.join(' '));\n";
    assert_eq!(run(source), ["3 7 5 {\"x\":6} 9 7 a pq g1 g3"]);
}
