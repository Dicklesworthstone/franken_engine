//! bd-9vouw.342: a tagged template's tag can itself be a tagged template
//! (ES2020 12.3: MemberExpression TemplateLiteral is left-associative), so
//! `rec`x``y${1}z``w`` calls rec with ['x'], its result with (['y', 'z'],
//! 1), and that result with ['w']. The parser split before the FIRST
//! top-level template and read `x``y${1}z``w` as one template with
//! backticks in its text. A member tag chains the same way, a template
//! nested in a substitution stays inside its template, and a template used
//! as a tag is a TypeError. Node v22.2.0 gives this line.

use frankenengine_engine::HybridRouter;

#[test]
fn chained_tagged_templates_apply_left_to_right() {
    let source = r#"
var seen = [];
function rec(s) { seen.push(s.join('|') + ':' + (arguments.length - 1)); return rec; }
rec`x``y${1}z``w`;
var obj = { t: function (s) { seen.push('m:' + s[0]); return obj.t; } };
obj.t`a``b`;
function id(s) { return s[0]; }
seen.push(id`${`in`}out`.length, typeof function () { return rec`p``q`; }());
var r;
try { r = `a``b`; } catch (e) { r = e.constructor.name; }
seen.push(r);
console.log(seen.join(' '));
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
        ["x:0 y|z:1 w:0 m:a m:b p:0 q:0 0 function TypeError"]
    );
}
