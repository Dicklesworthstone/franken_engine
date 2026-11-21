//! bd-9vouw.62: engine-level differential ratchet over real npm packages.
//!
//! The engine's other corpora are hand-written snippets; real package code
//! combines constructs they miss. Each vendored package (unmodified source,
//! MIT license alongside it under tests/fixtures/npm_packages/) runs through
//! the real `frankenctl run` inside a minimal CommonJS wrapper, followed by a
//! fixed usage script; the expected line was produced by Node v22.2.0 on the
//! identical program text.
//!
//! Ratchet contract: every listed package must match Node exactly (a
//! regression fails the test). Nothing is silently skipped. All three pass
//! today; a vendored package that does not yet run gets an expected failure
//! class, as dayjs had until it ran (bd-9vouw.17), so that fixing it fails
//! the test until the entry is promoted.
//! No-claim: three single-file packages; multi-file packages need the module
//! loader and are franken_node's corpus.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Package {
    name: &'static str,
    file: &'static str,
    usage: &'static str,
    /// The line Node v22.2.0 prints, which the engine must print exactly.
    node_output: &'static str,
}

const PACKAGES: &[Package] = &[
    Package {
        name: "ms",
        file: "ms-2.1.3/index.js",
        usage: "console.log(m('2 days'), m('1h'), m(60000), m(2 * 60000, { long: true }), m('-3.5s'));",
        node_output: "172800000 3600000 1m 2 minutes -3500",
    },
    Package {
        name: "minimist",
        file: "minimist-1.2.8/index.js",
        usage: "const a = m(['-x', '3', '-y4', '-n5', '-abc', '--beep=boop', 'foo', 'bar', '--no-z']); console.log(JSON.stringify(a));",
        node_output: r#"{"_":["foo","bar"],"x":3,"y":4,"n":5,"a":true,"b":true,"c":true,"beep":"boop","z":false}"#,
    },
    Package {
        name: "dayjs",
        file: "dayjs-1.11.13/dayjs.min.js",
        usage: "const d = m('2020-01-31T12:00:00Z'); console.log(d.valueOf(), d.add(1, 'day').toISOString(), d.isValid(), m('invalid').isValid());",
        // Parses since 6a1955fc0 (`=` in a `?:` branch); runs since its UMD
        // header's `globalThis` fallback reaches the sanitized global object
        // (bd-9vouw.17, f0c8e3237).
        node_output: "1580472000000 2020-02-01T12:00:00.000Z true false",
    },
];

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("npm_packages")
}

fn scratch_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_npm_ratchet_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn program(package: &Package) -> String {
    let source = fs::read_to_string(fixture_root().join(package.file)).expect("vendored source");
    format!(
        "var module = {{ exports: {{}} }}; var exports = module.exports;\n\
         (function (module, exports) {{\n{source}\n}})(module, exports);\n\
         var m = module.exports;\n{}\n",
        package.usage
    )
}

#[test]
fn vendored_packages_are_mit_licensed_and_present() {
    for package in PACKAGES {
        let dir = fixture_root().join(package.file.split('/').next().expect("dir"));
        let license = ["LICENSE", "LICENSE.md"]
            .iter()
            .find_map(|name| fs::read_to_string(dir.join(name)).ok())
            .unwrap_or_else(|| panic!("{}: license text must be vendored", package.name));
        assert!(license.contains("MIT") || license.contains("Permission is hereby granted"));
    }
}

#[test]
fn real_npm_packages_ratchet_against_node() {
    let dir = scratch_dir();
    let mut problems = Vec::new();
    for package in PACKAGES {
        let input = dir.join(format!("{}.js", package.name));
        let report = dir.join(format!("{}.run.json", package.name));
        fs::write(&input, program(package)).expect("program");
        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args([
                "run",
                "--input",
                input.to_str().expect("utf8"),
                "--extension-id",
                "npm-ratchet",
                "--instruction-budget",
                "100000000",
                "--out",
                report.to_str().expect("utf8"),
            ])
            .output()
            .expect("frankenctl should execute");
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let printed = output.status.success().then(|| {
            let parsed: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&report).expect("report")).expect("json");
            parsed["console_output"]
                .as_array()
                .expect("console")
                .iter()
                .map(|entry| entry["message"].as_str().expect("message").to_string())
                .collect::<Vec<_>>()
                .join("\n")
        });
        if printed.as_deref() != Some(package.node_output) {
            problems.push(format!(
                "{}: REGRESSION, expected Node output {:?}, got {printed:?} (stderr: {})",
                package.name,
                package.node_output,
                stderr.lines().last().unwrap_or("")
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn parse_error_positions_point_at_offending_token_inside_multiline_wrappers() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

    // Reproduce the exact bd-9vouw.62 minimist-1.2.8 layout:
    // line 23 opens `module.exports = function (args) {`, line 143 opens a
    // `for` loop, and line 148 contains an invalid assignment target inside an
    // `if (...)` condition (`if (1 + 2 = 3)`). Previously this reported the
    // enclosing function start (line 23 col 1); Node v22 reports line 148 col 9.
    let mut minimist_lines = Vec::with_capacity(152);
    for n in 1..23 {
        minimist_lines.push(format!("// prelude line {n}"));
    }
    minimist_lines.push("module.exports = function (args) {".to_string()); // line 23
    for n in 24..143 {
        minimist_lines.push(format!("  var v{n} = {n};"));
    }
    minimist_lines.push("  for (var i = 0; i < args.length; i++) {".to_string()); // line 143
    for n in 144..148 {
        minimist_lines.push(format!("    var k{n} = args[{n}];"));
    }
    minimist_lines.push("    if (1 + 2 = 3) { return args; }".to_string()); // line 148, col 9 (`1 + 2`)
    minimist_lines.push("  }".to_string()); // line 149
    minimist_lines.push("};".to_string()); // line 150
    let minimist_source = minimist_lines.join("\n");

    let minimist_err = CanonicalEs2020Parser
        .parse(minimist_source.as_str(), ParseGoal::Script)
        .expect_err("`if (1 + 2 = 3)` on line 148 must fail to parse");
    let minimist_span = minimist_err
        .span
        .expect("parse error must carry a SourceSpan");
    assert_eq!(
        (minimist_span.start_line, minimist_span.start_column),
        (148, 9),
        "expected offending target span at line 148 col 9, got {minimist_err}"
    );

    // Also check a multi-line `&&` LHS inside an `if (...)` condition starting
    // on line 24 (`args.length !== 24 && ... && 1 + 2 = 3`): per ECMAScript
    // precedence the invalid LHS starts on line 24 col 5 (matching Node v22),
    // NOT the enclosing function (line 1) or `if` header (line 23).
    let mut chain_lines = Vec::with_capacity(152);
    chain_lines.push("module.exports = function (args) {".to_string()); // line 1
    for n in 2..23 {
        chain_lines.push(format!("  var v{n} = {n};"));
    }
    chain_lines.push("  if (".to_string()); // line 23
    for n in 24..148 {
        chain_lines.push(format!("    args.length !== {n} &&"));
    }
    chain_lines.push("    1 + 2 = 3".to_string()); // line 148
    chain_lines.push("  ) {".to_string()); // line 149
    chain_lines.push("    return args;".to_string()); // line 150
    chain_lines.push("  }".to_string()); // line 151
    chain_lines.push("};".to_string()); // line 152
    let chain_source = chain_lines.join("\n");

    let err = CanonicalEs2020Parser
        .parse(chain_source.as_str(), ParseGoal::Script)
        .expect_err("`args.length !== 24 && ... && 1 + 2 = 3` must fail to parse");
    let span = err.span.expect("parse error must carry a SourceSpan");
    assert_eq!(
        (span.start_line, span.start_column),
        (24, 5),
        "expected offending LHS span at line 24 col 5 (matching Node v22), got {err}"
    );

    // Also verify statement-level errors inside multi-line function bodies
    // report the offending statement's line/column rather than line 1.
    let uninitialized_const = "function wrapper() {\n  let ok = 1;\n  let ok2 = 2;\n  let ok3 = 3;\n  let ok4 = 4;\n  const missingInit;\n}\n";
    let stmt_err = CanonicalEs2020Parser
        .parse(uninitialized_const, ParseGoal::Script)
        .expect_err("uninitialized const on line 6 must fail to parse");
    let stmt_span = stmt_err.span.expect("statement parse error span");
    assert_eq!(
        (stmt_span.start_line, stmt_span.start_column),
        (6, 3),
        "expected offending const statement at line 6 col 3, got {stmt_err}"
    );
}
