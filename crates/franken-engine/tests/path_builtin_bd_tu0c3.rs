//! bd-tu0c3: `require('path')` as a pure-compute builtin.
//!
//! The lowering pipeline recognizes `const path = require('path')` bindings
//! that are actually USED as a recognized `path` builtin (usage-gated exactly
//! like the fs/http aliases), elides the require declaration, and rewrites
//! member calls to `builtin:Path*` hostcalls (posix semantics — the default
//! `path` on linux IS posix) and `sep`/`delimiter` property reads to string
//! constants. A bare/unused `const path = require('path')` keeps the
//! ambient-authority denial (fail-closed contract pinned below).
//!
//! Expected outputs are pinned against `bun` (Node-compatible reference) runs
//! of the compat corpus at
//! `franken_node/crates/franken-node/tests/fixtures/compat_corpus/path/`.

use frankenengine_engine::HybridRouter;

/// Evaluate `src` and return the console output messages joined by newlines
/// (one line per `console.log`, args joined by single spaces — matching bun).
fn eval_console(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Evaluate `src` expecting an eval-time error; returns its display string.
fn eval_err(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(outcome) => panic!("expected eval error for {src:?}, got {outcome:?}"),
        Err(e) => format!("{e}"),
    }
}

// -------------------------------------------------------------------------
// join
// -------------------------------------------------------------------------

#[test]
fn join_basic_segments() {
    let src = r#"
        const path = require('path');
        console.log(path.join('a', 'b', 'c'));
        console.log(path.join('foo', 'bar', 'baz.txt'));
    "#;
    assert_eq!(eval_console(src), "a/b/c\nfoo/bar/baz.txt");
}

#[test]
fn join_resolves_dot_dot_segments() {
    let src = r#"
        const path = require('path');
        console.log(path.join('a', 'b', '..', 'c'));
        console.log(path.join('a', '..', '..', 'b'));
        console.log(path.join('/x', 'y', '..', 'z'));
    "#;
    assert_eq!(eval_console(src), "a/c\n../b\n/x/z");
}

#[test]
fn join_drops_dot_segments() {
    let src = r#"
        const path = require('path');
        console.log(path.join('a', '.', 'b'));
        console.log(path.join('.', 'a'));
        console.log(path.join('a', './b', '.'));
    "#;
    assert_eq!(eval_console(src), "a/b\na\na/b");
}

#[test]
fn join_ignores_empty_segments() {
    let src = r#"
        const path = require('path');
        console.log(path.join('a', '', 'b'));
        console.log(path.join('', 'a', ''));
        console.log(path.join('', ''));
    "#;
    assert_eq!(eval_console(src), "a/b\na\n.");
}

#[test]
fn join_preserves_trailing_slash() {
    let src = r#"
        const path = require('path');
        console.log(path.join('a', 'b/'));
        console.log(path.join('a/', 'b//'));
    "#;
    assert_eq!(eval_console(src), "a/b/\na/b/");
}

#[test]
fn join_collapses_absolute_segments() {
    let src = r#"
        const path = require('path');
        console.log(path.join('/a', '/b'));
        console.log(path.join('a', '/b', 'c'));
    "#;
    assert_eq!(eval_console(src), "/a/b\na/b/c");
}

#[test]
fn join_empty_call_is_dot() {
    let src = r#"
        const path = require('path');
        console.log(path.join());
        console.log(path.join(''));
    "#;
    assert_eq!(eval_console(src), ".\n.");
}

#[test]
fn join_non_string_throws_catchable_err_invalid_arg_type() {
    // Corpus fixture 0008: the thrown error must be a real, JS-catchable
    // TypeError (`instanceof` holds) carrying Node's ERR_INVALID_ARG_TYPE code.
    let src = r#"
        const path = require('path');
        try {
          path.join('a', 1);
          console.log('no-throw');
        } catch (e) {
          console.log(e instanceof TypeError, e.code);
        }
    "#;
    assert_eq!(eval_console(src), "true ERR_INVALID_ARG_TYPE");
}

// -------------------------------------------------------------------------
// basename
// -------------------------------------------------------------------------

#[test]
fn basename_last_component() {
    let src = r#"
        const path = require('path');
        console.log(path.basename('/foo/bar/baz.txt'));
        console.log(path.basename('relative/dir/name'));
        console.log(path.basename('justname'));
    "#;
    assert_eq!(eval_console(src), "baz.txt\nname\njustname");
}

#[test]
fn basename_strips_matching_ext_suffix() {
    let src = r#"
        const path = require('path');
        console.log(path.basename('/foo/bar.html', '.html'));
        console.log(path.basename('archive.tar.gz', '.gz'));
    "#;
    assert_eq!(eval_console(src), "bar\narchive.tar");
}

#[test]
fn basename_keeps_non_matching_or_oversized_ext() {
    let src = r#"
        const path = require('path');
        console.log(path.basename('/foo/bar.txt', '.html'));
        console.log(path.basename('bar', 'longer-than-name'));
    "#;
    assert_eq!(eval_console(src), "bar.txt\nbar");
}

#[test]
fn basename_ext_equal_to_whole_basename_is_kept() {
    let src = r#"
        const path = require('path');
        console.log(path.basename('.html', '.html'));
    "#;
    assert_eq!(eval_console(src), ".html");
}

#[test]
fn basename_trims_trailing_slashes() {
    let src = r#"
        const path = require('path');
        console.log(path.basename('/foo/bar/'));
        console.log(path.basename('/foo/bar///'));
    "#;
    assert_eq!(eval_console(src), "bar\nbar");
}

// -------------------------------------------------------------------------
// dirname
// -------------------------------------------------------------------------

#[test]
fn dirname_drops_last_component_and_trailing_slash() {
    let src = r#"
        const path = require('path');
        console.log(path.dirname('/a/b/c'));
        console.log(path.dirname('a/b/c.txt'));
        console.log(path.dirname('/a/b/c/'));
    "#;
    assert_eq!(eval_console(src), "/a/b\na/b\n/a/b");
}

#[test]
fn dirname_root_and_bare_name_edges() {
    let src = r#"
        const path = require('path');
        console.log(path.dirname('/a'));
        console.log(path.dirname('/'));
        console.log(path.dirname('a'));
    "#;
    assert_eq!(eval_console(src), "/\n/\n.");
}

// -------------------------------------------------------------------------
// extname
// -------------------------------------------------------------------------

#[test]
fn extname_last_dot_of_final_component() {
    let src = r#"
        const path = require('path');
        console.log(path.extname('index.html'));
        console.log(path.extname('/dir/file.js'));
        console.log(path.extname('index.coffee.md'));
        console.log(path.extname('archive.tar.gz'));
    "#;
    assert_eq!(eval_console(src), ".html\n.js\n.md\n.gz");
}

#[test]
fn extname_dotfile_and_trailing_dot_rules() {
    let src = r#"
        const path = require('path');
        console.log(JSON.stringify(path.extname('.bashrc')));
        console.log(JSON.stringify(path.extname('/home/.hidden')));
        console.log(path.extname('.config.json'));
        console.log(JSON.stringify(path.extname('file.')));
        console.log(JSON.stringify(path.extname('file')));
        console.log(JSON.stringify(path.extname('/a.b/file')));
    "#;
    assert_eq!(eval_console(src), "\"\"\n\"\"\n.json\n\".\"\n\"\"\n\"\"");
}

// -------------------------------------------------------------------------
// normalize
// -------------------------------------------------------------------------

#[test]
fn normalize_resolves_dots_and_collapses_slashes() {
    let src = r#"
        const path = require('path');
        console.log(path.normalize('/foo/bar//baz/asdf/quux/..'));
        console.log(path.normalize('a/./b//c'));
    "#;
    assert_eq!(eval_console(src), "/foo/bar/baz/asdf\na/b/c");
}

#[test]
fn normalize_preserves_trailing_slash() {
    let src = r#"
        const path = require('path');
        console.log(path.normalize('a/b/'));
        console.log(path.normalize('/x//y/'));
        console.log(path.normalize('a/b'));
    "#;
    assert_eq!(eval_console(src), "a/b/\n/x/y/\na/b");
}

#[test]
fn normalize_leading_dot_dot_and_root_edges() {
    let src = r#"
        const path = require('path');
        console.log(path.normalize('../a/../b'));
        console.log(path.normalize('../../x'));
        console.log(path.normalize('/..'));
    "#;
    assert_eq!(eval_console(src), "../b\n../../x\n/");
}

// -------------------------------------------------------------------------
// resolve
// -------------------------------------------------------------------------

#[test]
fn resolve_always_yields_absolute_paths() {
    // The engine has no ambient cwd: resolve() uses a fixed synthetic "/"
    // base, so only predicates (never the cwd value) are asserted — exactly
    // what the compat corpus does.
    let src = r#"
        const path = require('path');
        console.log(path.isAbsolute(path.resolve('a')));
        console.log(path.isAbsolute(path.resolve('a', 'b/c')));
        console.log(path.isAbsolute(path.resolve()));
    "#;
    assert_eq!(eval_console(src), "true\ntrue\ntrue");
}

#[test]
fn resolve_right_to_left_until_absolute() {
    let src = r#"
        const path = require('path');
        console.log(path.resolve('/x', '/y', 'z') === '/y/z');
        console.log(path.resolve('ignored', '/a', 'b', '..', 'c') === '/a/c');
    "#;
    assert_eq!(eval_console(src), "true\ntrue");
}

#[test]
fn resolve_does_not_validate_args_left_of_absolute() {
    // Node's lazy right-to-left validation: arguments left of the rightmost
    // absolute segment are never inspected.
    let src = r#"
        const path = require('path');
        console.log(path.resolve(7, '/a') === '/a');
    "#;
    assert_eq!(eval_console(src), "true");
}

// -------------------------------------------------------------------------
// relative
// -------------------------------------------------------------------------

#[test]
fn relative_walks_up_and_down() {
    let src = r#"
        const path = require('path');
        console.log(path.relative('/data/orandea/test/aaa', '/data/orandea/impl/bbb'));
        console.log(path.relative('/a/b', '/a/b/c/d'));
    "#;
    assert_eq!(eval_console(src), "../../impl/bbb\nc/d");
}

#[test]
fn relative_identical_paths_are_empty() {
    let src = r#"
        const path = require('path');
        console.log(JSON.stringify(path.relative('/a/b', '/a/b')));
        console.log(JSON.stringify(path.relative('/a/b/', '/a/b')));
    "#;
    assert_eq!(eval_console(src), "\"\"\n\"\"");
}

// -------------------------------------------------------------------------
// parse / format
// -------------------------------------------------------------------------

#[test]
fn parse_absolute_path_decomposition() {
    let src = r#"
        const path = require('path');
        const p = path.parse('/home/user/dir/file.txt');
        console.log(p.root, p.dir, p.base, p.ext, p.name);
    "#;
    assert_eq!(eval_console(src), "/ /home/user/dir file.txt .txt file");
}

#[test]
fn parse_relative_multi_dot_decomposition() {
    let src = r#"
        const path = require('path');
        const p = path.parse('dir/sub/file.tar.gz');
        console.log(JSON.stringify(p.root), p.dir, p.base, p.ext, p.name);
    "#;
    assert_eq!(eval_console(src), "\"\" dir/sub file.tar.gz .gz file.tar");
}

#[test]
fn format_dir_base_and_name_ext() {
    let src = r#"
        const path = require('path');
        console.log(path.format({ dir: '/a/b', base: 'c.txt' }));
        console.log(path.format({ dir: 'rel/dir', base: 'f' }));
        console.log(path.format({ name: 'file', ext: '.js' }));
    "#;
    assert_eq!(eval_console(src), "/a/b/c.txt\nrel/dir/f\nfile.js");
}

#[test]
fn format_precedence_dir_base_over_root_name_ext() {
    let src = r#"
        const path = require('path');
        console.log(path.format({ root: '/r/', dir: '/a', name: 'f', ext: '.txt', base: 'g.md' }));
        console.log(path.format({ root: '/', name: 'f', ext: '.txt' }));
    "#;
    assert_eq!(eval_console(src), "/a/g.md\n/f.txt");
}

// -------------------------------------------------------------------------
// isAbsolute
// -------------------------------------------------------------------------

#[test]
fn is_absolute_posix() {
    let src = r#"
        const path = require('path');
        console.log(path.isAbsolute('/a/b'));
        console.log(path.isAbsolute('a/b'));
        console.log(path.isAbsolute('./a'));
        console.log(path.isAbsolute(''));
    "#;
    assert_eq!(eval_console(src), "true\nfalse\nfalse\nfalse");
}

// -------------------------------------------------------------------------
// sep / delimiter property constants
// -------------------------------------------------------------------------

#[test]
fn sep_and_delimiter_constants() {
    let src = r#"
        const path = require('path');
        console.log(path.sep, path.delimiter);
        console.log(path.posix.sep, path.posix.delimiter);
        console.log(JSON.stringify(path.win32.sep), path.win32.delimiter);
    "#;
    assert_eq!(eval_console(src), "/ :\n/ :\n\"\\\\\" ;");
}

#[test]
fn property_read_alone_confirms_the_alias() {
    // Corpus fixture 0030 uses ONLY property reads (no method call); the
    // usage gate must count them.
    let src = r#"
        const path = require('path');
        console.log(path.posix.sep, path.posix.delimiter);
    "#;
    assert_eq!(eval_console(src), "/ :");
}

// -------------------------------------------------------------------------
// posix / win32 namespaces
// -------------------------------------------------------------------------

#[test]
fn posix_namespace_maps_to_same_builtins() {
    let src = r#"
        const path = require('path');
        console.log(path.posix.join('a', 'b', '..', 'c'));
        console.log(path.posix.basename('/tmp/x.txt'));
        console.log(path.posix.isAbsolute('/y'));
    "#;
    assert_eq!(eval_console(src), "a/c\nx.txt\ntrue");
}

#[test]
fn win32_basename_handles_drive_and_both_separators() {
    let src = r#"
        const path = require('path');
        console.log(path.win32.basename('C:\\temp\\myfile.html'));
        console.log(path.win32.basename('C:/temp/other.html'));
        console.log(path.win32.basename('C:\\temp\\page.html', '.html'));
    "#;
    assert_eq!(eval_console(src), "myfile.html\nother.html\npage");
}

#[test]
fn win32_join_uses_backslash_separator() {
    let src = r#"
        const path = require('path');
        console.log(JSON.stringify(path.win32.join('a', 'b', 'c')));
        console.log(JSON.stringify(path.win32.join('a', '..', 'b')));
    "#;
    assert_eq!(eval_console(src), "\"a\\\\b\\\\c\"\n\"b\"");
}

#[test]
fn win32_is_absolute_drive_and_unc_awareness() {
    let src = r#"
        const path = require('path');
        console.log(path.win32.isAbsolute('C:\\foo'));
        console.log(path.win32.isAbsolute('\\\\server\\share'));
        console.log(path.win32.isAbsolute('C:relative'));
        console.log(path.win32.isAbsolute('foo\\bar'));
    "#;
    assert_eq!(eval_console(src), "true\ntrue\nfalse\nfalse");
}

// -------------------------------------------------------------------------
// require specifier / receiver shapes
// -------------------------------------------------------------------------

#[test]
fn node_path_specifier_is_recognized() {
    let src = r#"
        const path = require('node:path');
        console.log(path.join('a', 'b'));
    "#;
    assert_eq!(eval_console(src), "a/b");
}

#[test]
fn non_path_alias_name_is_recognized() {
    let src = r#"
        const p = require('path');
        console.log(p.extname('x.rs'));
    "#;
    assert_eq!(eval_console(src), ".rs");
}

#[test]
fn inline_require_receiver_is_recognized() {
    let src = r#"
        console.log(require('path').join('a', 'b'));
    "#;
    assert_eq!(eval_console(src), "a/b");
}

#[test]
fn usage_inside_try_block_confirms_the_alias() {
    // Corpus fixture 0008's shape: the ONLY usage is inside a try block, so
    // the usage scan must recurse through control-flow statements.
    let src = r#"
        const path = require('path');
        try {
          console.log(path.join('a', 'b'));
        } catch (e) {
          console.log('unreachable');
        }
    "#;
    assert_eq!(eval_console(src), "a/b");
}

// -------------------------------------------------------------------------
// fail-closed contract
// -------------------------------------------------------------------------

#[test]
fn unused_path_alias_keeps_ambient_denial() {
    // The fail-closed contract (mirror of the fs usage gate): a bare/unused
    // `const path = require('path')` is NOT recognized, so the require call
    // still hits the ambient-authority lowering denial.
    let err = eval_err("const path = require('path');\nconsole.log('reached');");
    assert!(
        err.contains("ambient authority violation"),
        "expected ambient-authority denial for unused path alias, got: {err}"
    );
}

#[test]
fn usage_only_inside_function_body_stays_fail_closed() {
    // Function bodies are opaque to the usage scan (fail-closed): a usage
    // reachable only through a function body does NOT confirm the alias.
    let err = eval_err(
        "const path = require('path');\nfunction f() { return path.join('a', 'b'); }\nconsole.log(f());",
    );
    assert!(
        err.contains("ambient authority violation"),
        "expected ambient-authority denial for function-body-only usage, got: {err}"
    );
}

#[test]
fn unrecognized_method_does_not_confirm_the_alias() {
    // `path.win32.dirname` is outside the recognized win32 subset; with no
    // other usage the alias stays unconfirmed and the require is denied.
    let err = eval_err("const path = require('path');\nconsole.log(path.win32.dirname('a\\\\b'));");
    assert!(
        err.contains("ambient authority violation"),
        "expected ambient-authority denial for unrecognized-method-only usage, got: {err}"
    );
}

#[test]
fn shadowed_require_is_not_recognized_as_path_module() {
    // A user binding named `require` must not be treated as the CJS loader:
    // the path recognizers decline (fail-closed), so nothing lowers to
    // `builtin:Path*`. The program still fails at lowering because the
    // engine's PRE-EXISTING bare-identifier ambient gate hardening denies
    // `require` references regardless of shadowing (red-team containment —
    // an ambient name cannot be laundered through a local binding).
    let err = eval_err(
        "const require = (name) => ({ join: () => 'shadowed:' + name });\nconst path = require('path');\nconsole.log(path.join('a', 'b'));",
    );
    assert!(
        err.contains("ambient authority violation"),
        "expected the pre-existing ambient denial for shadowed require, got: {err}"
    );
}

// -------------------------------------------------------------------------
// interplay
// -------------------------------------------------------------------------

#[test]
fn nested_calls_and_string_concat() {
    let src = r#"
        const path = require('path');
        console.log(path.dirname(path.join('/a', 'b', 'c.txt')) + path.sep + path.basename('/a/b/c.txt', path.extname('/a/b/c.txt')));
    "#;
    assert_eq!(eval_console(src), "/a/b/c");
}
