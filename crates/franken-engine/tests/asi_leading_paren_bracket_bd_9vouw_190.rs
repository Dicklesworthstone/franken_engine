#![forbid(unsafe_code)]

//! bd-9vouw.190: a line starting with `(` or `[` continues the expression
//! the previous line ended (no semicolon is inserted before them, ES2020
//! 11.9.1). Every webpack 4 bundle ends its bootstrap with `})` and passes
//! its modules on later lines after comment-only lines; the statement
//! splitter ended the statement at `})`, so the bundle's factory returned
//! the bootstrap function itself (handlebars 4.7.8: `m.compile` undefined).
//! A `}`-terminated declaration, `return` alone and a leading `;` still end
//! the statement. Expected line is Node v22.2.0's output (Bun 1.4.2 prints
//! the same).

use frankenengine_engine::HybridRouter;

#[test]
fn leading_paren_and_bracket_lines_continue_the_previous_expression() {
    let source = "var bundle = (function (modules) {\n  function req(id) { var module = { exports: {} }; modules[id](module, module.exports, req); return module.exports; }\n  return req(0);\n})\n/************************************************************************/\n/******/ ([\n/* 0 */\nfunction (module, exports) { module.exports = { kind: 'bundle' }; }\n]);\nfunction factory() {\n  return (function (m) { return m[0] + 1; })\n  // a comment line\n  ([41]);\n}\nvar x = (function (m) { return m[0] + 10; })\n([5]);\nvar list = [[1, 2], [3]]\n[1];\nvar calls = [];\nfunction declared() { calls.push('declared'); }\n(function () { calls.push('iife after a declaration'); })();\nfunction early() {\n  return\n  (1);\n}\nvar y = 1\n;[2, 3].forEach(function (v) { calls.push('leading semicolon ' + v); });\nconsole.log(bundle.kind, factory(), x, JSON.stringify(list), early(), calls.join(' | '));\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "bundle 42 15 [3] undefined iife after a declaration | leading semicolon 2 | leading semicolon 3"
        ]
    );
}
