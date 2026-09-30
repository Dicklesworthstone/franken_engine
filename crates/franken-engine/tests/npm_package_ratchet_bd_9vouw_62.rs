//! bd-9vouw.62: engine-level differential ratchet over real npm packages.
//!
//! The engine's other corpora are hand-written snippets; real package code
//! combines constructs they miss. Each vendored package (unmodified source,
//! MIT license alongside it under tests/fixtures/npm_packages/) runs through
//! the real `frankenctl run` inside a minimal CommonJS wrapper, followed by a
//! fixed usage script; the expected line was produced by Node v22.2.0 on the
//! identical program text.
//!
//! Ratchet contract: a package listed as `Passes` must match Node exactly (a
//! regression fails the test); a package listed as `KnownFailure` must still
//! fail with its recorded failure class, so a fix that makes it pass fails the
//! test until the entry is promoted to `Passes`. Nothing is silently skipped.
//! No-claim: three single-file packages; multi-file packages need the module
//! loader and are franken_node's corpus.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

enum Expect {
    /// Must print exactly this line (Node v22.2.0 output).
    Passes(&'static str),
    /// Must still fail, with stderr containing this failure class.
    KnownFailure(&'static str),
}

struct Package {
    name: &'static str,
    file: &'static str,
    usage: &'static str,
    node_output: &'static str,
    expect: Expect,
}

const PACKAGES: &[Package] = &[
    Package {
        name: "ms",
        file: "ms-2.1.3/index.js",
        usage: "console.log(m('2 days'), m('1h'), m(60000), m(2 * 60000, { long: true }), m('-3.5s'));",
        node_output: "172800000 3600000 1m 2 minutes -3500",
        expect: Expect::Passes("172800000 3600000 1m 2 minutes -3500"),
    },
    Package {
        name: "minimist",
        file: "minimist-1.2.8/index.js",
        usage: "const a = m(['-x', '3', '-y4', '-n5', '-abc', '--beep=boop', 'foo', 'bar', '--no-z']); console.log(JSON.stringify(a));",
        node_output: r#"{"_":["foo","bar"],"x":3,"y":4,"n":5,"a":true,"b":true,"c":true,"beep":"boop","z":false}"#,
        expect: Expect::Passes(
            r#"{"_":["foo","bar"],"x":3,"y":4,"n":5,"a":true,"b":true,"c":true,"beep":"boop","z":false}"#,
        ),
    },
    Package {
        name: "dayjs",
        file: "dayjs-1.11.13/dayjs.min.js",
        usage: "const d = m('2020-01-31T12:00:00Z'); console.log(d.valueOf(), d.add(1, 'day').toISOString(), d.isValid(), m('invalid').isValid());",
        node_output: "1580472000000 2020-02-01T12:00:00.000Z true false",
        // Parses since 6a1955fc0 (`=` in a `?:` branch); runs since its UMD
        // header's `globalThis` fallback reaches the sanitized global object
        // (bd-9vouw.17, f0c8e3237).
        expect: Expect::Passes("1580472000000 2020-02-01T12:00:00.000Z true false"),
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
        match (&package.expect, printed) {
            (Expect::Passes(line), Some(printed)) if printed == *line => {}
            (Expect::Passes(line), other) => problems.push(format!(
                "{}: REGRESSION, expected Node output {line:?}, got {other:?} (stderr: {})",
                package.name,
                stderr.lines().last().unwrap_or("")
            )),
            (Expect::KnownFailure(class), None) if stderr.contains(class) => {}
            (Expect::KnownFailure(_), Some(printed)) if printed == package.node_output => {
                problems.push(format!(
                    "{}: now matches Node; promote it to Expect::Passes",
                    package.name
                ));
            }
            (Expect::KnownFailure(class), other) => problems.push(format!(
                "{}: failure class changed (expected {class:?}); output {other:?}, stderr {}",
                package.name,
                stderr.lines().last().unwrap_or("")
            )),
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}
