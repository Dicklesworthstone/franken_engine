//! Regression tests for franken_engine#1 and franken_engine#2.
//!
//! #1: the typed-hostcall classifier (`hostcall<"cap">(args)`) used a raw
//! substring search, so ordinary JavaScript whose string, template or regex
//! literals or comments merely spelled the DSL was routed through TypeScript
//! normalization, whose raw-substring stripper then rewrote the literal
//! (`'hostcall<"demo">'` became `'hostcall'`). Only typed calls in code
//! position may be classified, extracted or stripped; literal contents are
//! never altered, on the public preparation entry point, `frankenctl
//! compile` and `frankenctl run`.
//!
//! #2: native RegExp parsing recursed once per group nesting level without a
//! bound, and global matching retained every capture vector of every match
//! (with a fresh step budget per match) before any guest accounting. Both
//! now fail with an error under explicit bounds.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ts_normalization::{
    SourceLanguage, classify_source_language, prepare_source_entry_for_public_entrypoints,
};
use serde_json::Value;

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(prefix: &str, ext: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let unique = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("{prefix}_{nanos}_{unique}.{ext}"))
}

/// JavaScript whose literals and comments spell the typed-hostcall DSL but
/// which contains no typed call in code position.
const LITERAL_ONLY_SOURCES: &[(&str, &str)] = &[
    (
        "issue_example",
        "const label = 'hostcall<\"demo\">';\nconsole.log(label);\n",
    ),
    (
        "double_quoted_escapes",
        "const s = \"hostcall<\\\"x\\\">(1)\"; const t = \"a\\\\\"; s + t;\n",
    ),
    (
        "single_quoted_escaped_quote",
        "const s = 'it\\'s hostcall<\"x\">() \\\\'; s;\n",
    ),
    (
        "template_literal",
        "const n = 1; const t = `hostcall<\"x\">(${n})`; t;\n",
    ),
    (
        "nested_template",
        "const t = `${`hostcall<\"x\">()`} and ${'hostcall<\"y\">(z)'}`; t;\n",
    ),
    (
        "template_with_braces",
        "const o = { a: 1 }; const t = `${JSON.stringify({ k: 'hostcall<\"q\">()' })}`; t;\n",
    ),
    (
        "comments",
        "// hostcall<\"x\">()\n/* hostcall<\"y\">(1) */ const a = 1; a;\n",
    ),
    (
        "regex_literal",
        "const r = /hostcall<\"x\">\\(/; r.source;\n",
    ),
    (
        "regex_with_quote_before_string",
        "const r = /\"/; const s = 'hostcall<\"x\">()'; r.test(s);\n",
    ),
    (
        "marker_split_across_strings",
        "const a = 'hostcall<\"';\nconst b = '\">';\na + b;\n",
    ),
    (
        "comparison_chain",
        "const hostcall = 1; const r = hostcall<\"a\">0; r;\n",
    ),
];

#[test]
fn literal_contents_never_make_javascript_typescript() {
    for (name, source) in LITERAL_ONLY_SOURCES {
        assert_eq!(
            classify_source_language(Some("example.js"), source),
            SourceLanguage::JavaScript,
            "{name}"
        );
        let prepared =
            prepare_source_entry_for_public_entrypoints(source, "example.js", "t", "d", "p")
                .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            prepared.prepared_source, *source,
            "{name}: source rewritten"
        );
        assert!(!prepared.source_ingestion.normalization_applied, "{name}");
        assert_eq!(
            prepared.source_ingestion.original_source_hash,
            prepared.source_ingestion.normalized_source_hash,
            "{name}"
        );
        assert_eq!(
            prepared.source_ingestion.ts_capability_intent_count, 0,
            "{name}"
        );
    }
}

#[test]
fn real_typed_hostcalls_are_still_extracted_and_only_they_are_stripped() {
    let source = "const label = 'hostcall<\"demo\">'; // hostcall<\"c\">()\n\
                  const t = `hostcall<\"t\">()`;\n\
                  hostcall<\"fs.read\">(label, t);\n";
    assert_eq!(
        classify_source_language(Some("module.js"), source),
        SourceLanguage::TypeScript
    );
    let prepared = prepare_source_entry_for_public_entrypoints(source, "module.js", "t", "d", "p")
        .expect("typed hostcall source prepares");
    assert_eq!(
        prepared.prepared_source.trim_end(),
        "const label = 'hostcall<\"demo\">'; // hostcall<\"c\">()\n\
         const t = `hostcall<\"t\">()`;\n\
         hostcall(label, t);"
    );
    let intents = &prepared
        .normalization_output
        .as_ref()
        .expect("TS normalization ran")
        .capability_intents;
    assert_eq!(intents.len(), 1, "{intents:?}");
    assert_eq!(intents[0].capability, "fs.read");

    // TypeScript files: the same literal-preservation rule applies.
    let ts = "const s: string = 'hostcall<\"x\">()'; hostcall<\"net.fetch\">(s);\n";
    let prepared = prepare_source_entry_for_public_entrypoints(ts, "module.ts", "t", "d", "p")
        .expect("ts prepares");
    assert!(
        prepared.prepared_source.contains("'hostcall<\"x\">()'"),
        "{}",
        prepared.prepared_source
    );
    assert!(prepared.prepared_source.contains("hostcall(s)"));
    assert_eq!(prepared.source_ingestion.ts_capability_intent_count, 1);
}

#[test]
fn run_path_preserves_string_contents() {
    let outcome = HybridRouter::default()
        .eval("var a = 'hostcall<\"'; var b = '\">'; a + b;")
        .expect("plain JavaScript runs");
    assert_eq!(outcome.value, "hostcall<\"\">");
    // The old raw stripper removed `<"${'q'}">` from the template source.
    let outcome = HybridRouter::default()
        .eval("var q = 'q'; var t = `hostcall<\"${q}\">(`; t.length;")
        .expect("template runs");
    assert_eq!(outcome.value, "14");
}

#[test]
fn frankenctl_compile_and_run_do_not_rewrite_literals() {
    for (name, source) in LITERAL_ONLY_SOURCES {
        let source_path = temp_path(&format!("issue1_{name}"), "js");
        let artifact_path = temp_path(&format!("issue1_{name}_artifact"), "json");
        fs::write(&source_path, source).expect("write source");
        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args([
                "compile",
                "--input",
                source_path.to_str().expect("utf8"),
                "--out",
                artifact_path.to_str().expect("utf8"),
                "--goal",
                "script",
            ])
            .output()
            .expect("compile executes");
        assert!(
            output.status.success(),
            "{name}: compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout: Value = serde_json::from_slice(&output.stdout).expect("json stdout");
        let ingestion = &stdout["source_ingestion"];
        assert_eq!(
            ingestion["normalization_applied"],
            Value::Bool(false),
            "{name}"
        );
        assert_eq!(
            ingestion["original_source_hash"], ingestion["normalized_source_hash"],
            "{name}"
        );
        let _ = fs::remove_file(&source_path);
        let _ = fs::remove_file(&artifact_path);
    }

    let source_path = temp_path("issue1_run", "js");
    fs::write(
        &source_path,
        "var a = 'hostcall<\"';\nvar b = '\">';\na + b;\n",
    )
    .expect("write source");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            source_path.to_str().expect("utf8"),
            "--extension-id",
            "ext-issue1",
        ])
        .output()
        .expect("run executes");
    assert!(
        output.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: Value = serde_json::from_slice(&output.stdout).expect("json stdout");
    assert_eq!(stdout["execution_value"].as_str(), Some("hostcall<\"\">"));
    let _ = fs::remove_file(&source_path);
}

fn eval(source: &str) -> Result<String, String> {
    HybridRouter::default()
        .eval(source)
        .map(|outcome| outcome.value)
        .map_err(|error| format!("{error:?}"))
}

#[test]
fn pathologically_nested_regexp_is_a_syntax_error_not_a_crash() {
    // The issue's runtime shape: 200,000 nested groups.
    assert_eq!(
        eval(
            "try { new RegExp('('.repeat(200000) + 'a' + ')'.repeat(200000)); 'built' } \
             catch (e) { e.name }"
        ),
        Ok("SyntaxError".to_string())
    );
    // Look-around nesting cannot reach the automaton route at all.
    assert_eq!(
        eval(
            "try { new RegExp('(?=(?<=('.repeat(5000) + 'a' + ')))'.repeat(5000)); 'built' } \
             catch (e) { e.name }"
        ),
        Ok("SyntaxError".to_string())
    );
    // Ordinary nesting (with look-behind, so the backtracking parser runs)
    // still works.
    assert_eq!(
        eval("new RegExp('(?<=x)' + '('.repeat(40) + 'a' + ')'.repeat(40)).exec('xa')[40]"),
        Ok("a".to_string())
    );
}

#[test]
fn global_match_with_many_captures_fails_cleanly_instead_of_exhausting_memory() {
    // The issue's shape, through replace (which keeps every group): one
    // million empty matches with 65 capture slots each would need far more
    // than the guest memory limit; it must stop with an error.
    let error = eval(
        "const s = 'a'.repeat(1000000); s.replace(new RegExp('()'.repeat(64), 'g'), 'x').length",
    )
    .expect_err("an unbounded capture matrix must not be built");
    assert!(error.contains("memory budget exceeded"), "{error}");

    // String.prototype.match only keeps the whole-match span, so the same
    // pattern over a modest input still works and returns every match.
    assert_eq!(
        eval("'a'.repeat(1000).match(new RegExp('()'.repeat(64), 'g')).length"),
        Ok("1001".to_string())
    );
    // Ordinary global operations are unaffected.
    assert_eq!(
        eval("'a-b-c'.replace(/(?<=-)(\\w)/g, (m, g) => g.toUpperCase())"),
        Ok("a-B-C".to_string())
    );
    assert_eq!(
        eval("'a1b2c3'.split(/(\\d)/).join(',')"),
        Ok("a,1,b,2,c,3,".to_string())
    );
}

#[test]
fn overlapping_captured_text_is_bounded_in_replace_and_split() {
    // Each match captures the rest of the input, so the copied group text is
    // quadratic in the input length; replace and split must refuse it.
    for operation in ["replace(/(?=(a*))/g, '')", "split(/(?=(a*))/).length"] {
        let error = eval(&format!("'a'.repeat(60000).{operation}"))
            .expect_err("quadratic group text must not be materialized");
        assert!(
            error.contains("memory budget exceeded") || error.contains("step budget"),
            "{operation}: {error}"
        );
    }
}

// --- Review follow-ups (franken_engine#1/#2) ---

#[test]
fn typed_hostcalls_inside_template_substitutions_are_still_recognized() {
    let source = "const n = 1;\nconst t = `hostcall<\"text\">() ${hostcall<\"fs.read\">(n)}`;\n";
    assert_eq!(
        classify_source_language(Some("module.js"), source),
        SourceLanguage::TypeScript
    );
    let prepared = prepare_source_entry_for_public_entrypoints(source, "module.js", "t", "d", "p")
        .expect("prepares");
    assert_eq!(
        prepared.prepared_source.trim_end(),
        "const n = 1;\nconst t = `hostcall<\"text\">() ${hostcall(n)}`;"
    );
    assert_eq!(prepared.source_ingestion.ts_capability_intent_count, 1);
}

#[test]
fn long_single_line_sources_with_many_regex_literals_classify_quickly() {
    // Every `/` in regex position used to rescan the rest of its line.
    let source = format!("var r = [{}];", "/a/,".repeat(200_000));
    let started = std::time::Instant::now();
    assert_eq!(
        classify_source_language(Some("bundle.js"), &source),
        SourceLanguage::JavaScript
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "classification took {:?}",
        started.elapsed()
    );
}

#[test]
fn replacement_templates_cannot_expand_past_the_string_limit() {
    let error = eval("'a'.repeat(1000000).replace('a', \"$'\".repeat(1000)).length")
        .expect_err("a 1 GB replacement must not be built");
    assert!(error.contains("string allocation size exceeded"), "{error}");
    assert_eq!(
        eval("'abc'.replace('b', \"[$`|$&|$']\")"),
        Ok("a[a|b|c]c".to_string())
    );
}

#[test]
fn oversized_patterns_are_refused_before_parsing() {
    let thrown =
        eval("try { new RegExp('a'.repeat(2 * 1024 * 1024)); 'built' } catch (e) { e.name }")
            .expect("a catchable error");
    assert_eq!(thrown, "SyntaxError");
    let matched =
        eval("try { 'x'.match('a'.repeat(2 * 1024 * 1024)); 'matched' } catch (e) { e.name }");
    assert_ne!(matched, Ok("matched".to_string()), "{matched:?}");
}

#[test]
fn many_named_backreferences_resolve_in_linear_time() {
    let started = std::time::Instant::now();
    assert_eq!(
        eval("new RegExp('(?<a>x)' + '\\\\k<a>'.repeat(20000)).test('x'.repeat(20001))"),
        Ok("true".to_string())
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "took {:?}",
        started.elapsed()
    );
}

#[test]
fn replace_all_with_a_string_needle_is_charged() {
    let error = eval("'a'.repeat(9000000).replaceAll('a', '').length")
        .expect_err("9M retained matches must not be built");
    assert!(error.contains("memory budget exceeded"), "{error}");
    assert_eq!(
        eval("'a-b-c'.replaceAll('-', '+')"),
        Ok("a+b+c".to_string())
    );
}

#[test]
fn match_all_charges_the_instruction_budget() {
    // matchAll is lazy (bd-9vouw.476): each `next` runs, and charges, one
    // native exec, so consuming the 5,000 matches is what exhausts the budget.
    let error = HybridRouter::default()
        .eval_with_instruction_budget("[...'a'.repeat(5000).matchAll(/a/g)].length", 2_000)
        .map(|outcome| outcome.value)
        .map_err(|error| format!("{error:?}"))
        .expect_err("5,000 native exec iterations exceed a 2,000-instruction budget");
    assert!(error.contains("budget exhausted"), "{error}");
    assert_eq!(
        eval("[...'a1b2'.matchAll(/\\d/g)].map(m => m[0]).join(',')"),
        Ok("1,2".to_string())
    );
}
