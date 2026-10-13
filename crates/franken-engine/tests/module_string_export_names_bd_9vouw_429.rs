//! bd-9vouw.429: a module export name may be a string (ES2022 16.2.2
//! ModuleExportName): `export { a as "x-y" }`, `export { "x" as y } from`,
//! `export * as "ns" from`, `import { "x" as y } from`. The parser refused
//! each as unsupported syntax. An import or export that fits no form is a
//! SyntaxError, and so is an import attribute key the host does not support
//! (ES2025 16.2.1.7.1). Before, the parser refused these, so `Function`,
//! dynamic import and Test262 saw a refusal rather than a SyntaxError.
//! `export ... from` takes import attributes as an import does, and a
//! line ending in `with` continues onto the next. Expected output and
//! verdicts are Node v22.2.0's, except an unsupported attribute key: Node
//! throws a TypeError (ERR_IMPORT_ATTRIBUTE_UNSUPPORTED) where the
//! specification and Test262 require a SyntaxError.

use std::path::Path;
use std::process::Command;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};

fn run_module(root: &Path, entry: &str) -> Vec<String> {
    let report = root.join(format!("{entry}.report.json"));
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            root.join(entry).to_str().expect("utf8 path"),
            "--goal",
            "module",
            "--extension-id",
            "module-string-export-names",
            "--out",
            report.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "frankenctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).expect("read report")).expect("json");
    report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn string_export_names_link_through_exports_reexports_and_imports() {
    let root = tempfile::tempdir().expect("temp dir");
    for (name, source) in [
        (
            "fixture.mjs",
            "export { Mercury, Mercury as \"☿\", Mercury as \"a, b\" };\nfunction Mercury() { return \"m\"; }\n",
        ),
        (
            "reexport.mjs",
            "export { \"☿\" as Ami, \"a, b\" as \"c d\" } from './fixture.mjs';\nexport * as \"All\" from './fixture.mjs';\nexport * as \"x-y\" from './fixture.mjs';\n",
        ),
        (
            "main.mjs",
            "import { \"☿\" as planet, \"a, b\" as ab, Mercury } from './fixture.mjs';\nimport * as ns from './reexport.mjs';\nimport { Ami, \"c d\" as cd, All, \"x-y\" as xy } from './reexport.mjs';\nconsole.log(planet(), ab === Mercury, Object.keys(ns).join(\"|\"));\nconsole.log(Ami === planet, cd === planet, ns[\"c d\"] === planet, Object.keys(All).join(\"|\"), xy === All);\n",
        ),
    ] {
        std::fs::write(root.path().join(name), source).expect("write module");
    }
    assert_eq!(
        run_module(root.path(), "main.mjs"),
        [
            "m true All|Ami|c d|x-y",
            "true true true Mercury|a, b|☿ true",
        ]
    );
}

#[test]
fn export_from_takes_import_attributes_and_with_continues_the_line() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        root.path().join("fixture.mjs"),
        "export function Mercury() {}\n",
    )
    .expect("write fixture");
    std::fs::write(
        root.path().join("main.mjs"),
        "export { Mercury } from \"./fixture.mjs\" with {};\nexport * from \"./fixture.mjs\" with {};\nimport { Mercury as x } from \"./fixture.mjs\" with\n  {};\nconsole.log(\"valid\", typeof x);\n",
    )
    .expect("write main");
    assert_eq!(run_module(root.path(), "main.mjs"), ["valid function"]);
}

/// Each is a SyntaxError in Node v22.2.0 (the attribute key one a TypeError
/// there, a SyntaxError by the specification).
const SYNTAX_ERRORS: [&str; 14] = [
    "export { \"x\" };",
    "export { \"x\" as y };",
    "var a; export { a as \"\\uD800\" };",
    "export * as \"\\uDC00\" from \"./fixture.mjs\";",
    "import { \"\\uD800\" as z } from \"./fixture.mjs\";",
    "import { \"Mercury\" } from \"./fixture.mjs\";",
    "export {Mercury \\u0061s b} from \"./fixture.mjs\";",
    "import {} \\u0066rom \"./fixture.mjs\";",
    "import* \\u0061s self from \"./fixture.mjs\";",
    "import { Mercury, Mercury as Mercury } from \"./fixture.mjs\";",
    "import x from \"./fixture.mjs\" with { if: \"\" };",
    "export * from \"./fixture.mjs\" with { type: \"json\", \"typ\\u0065\": \"\" };",
    "export \\u0064efault 0;",
    "var a; export { a as \"b\", a as b };",
];

#[test]
fn malformed_imports_and_exports_are_syntax_errors() {
    let parser = CanonicalEs2020Parser;
    for source in SYNTAX_ERRORS {
        let error = parser.parse(source, ParseGoal::Module).expect_err(source);
        assert_eq!(error.code, ParseErrorCode::InvalidSyntax, "{source}");
    }
    for source in [
        "export { \"x\" } from \"./fixture.mjs\";",
        "export { \"x\" as \"y z\", a as \"\" } from \"./fixture.mjs\";",
        "var a; export { a as \"\\u{1F600}\", a as \"default\" };",
        "import { \"a, b\" as ab, \"from\" as f } from \"./fixture.mjs\";",
        "export * as \"x\" from \"./fixture.mjs\";",
    ] {
        parser
            .parse(source, ParseGoal::Module)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
    }
}
