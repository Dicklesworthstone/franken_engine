//! bd-9vouw.41: nested template literals through `frankenctl run`, against
//! Node v22.2.0 output.
//!
//! The string-slicing parser's scanners treated a backtick as a flat quote,
//! so the outer literal "closed" at the nested template's opening backtick.
//! The inner text (`<` / `>` in markup, `,` and `?:` in arrow bodies, a
//! backtick inside a string, `//` in a URL) then leaked out as top-level
//! syntax. Programs that build markup with `items.map(x => `<li>${x}</li>`)`
//! inside another template failed to parse or ran the wrong code.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// (case, source, Node v22.2.0 console output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "markup_in_map",
        r#"const n=2;
console.log(`a${`b${n*2}c`}d`, `${[1,2].map(x=>`<${x}>`).join("")}`);"#,
        "ab4cd <1><2>",
    ),
    (
        "attribute_markup_with_ternary",
        r#"const items=[{k:"a",v:1},{k:"b",v:2}];
const html = `<ul>${items.map(it => `<li class="${it.k}">${it.v > 1 ? `big ${it.v}` : `small`}</li>`).join("")}</ul>`;
console.log(html);"#,
        r#"<ul><li class="a">small</li><li class="b">big 2</li></ul>"#,
    ),
    (
        "backtick_in_substitution_string",
        r#"console.log(`a${"`"}b`, `c${'`'.length}d`);"#,
        "a`b c1d",
    ),
    (
        "url_in_nested_template_then_statement",
        r#"console.log(`${`http://x/${1}`}`); console.log(2);"#,
        "http://x/1\n2",
    ),
    (
        "conditional_and_comma_in_inner_template",
        r#"const f = (a, b) => `${a}${b}`;
console.log(`${[1, 2].map(n => `${n > 1 ? `>` : `<`},`).join('')}`, f(1, 2));"#,
        "<,>, 12",
    ),
    (
        "three_deep",
        r#"console.log(`1${`2${`3${4}3`}2`}1`);"#,
        "1234321",
    ),
    (
        "brace_in_substitution_string",
        r#"const o = { s: `x${"}"}y`, t: `p${ {a:1}.a }q` };
console.log(o.s, o.t);"#,
        "x}y p1q",
    ),
];

#[test]
fn nested_template_literals_match_node_bd_9vouw_41() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "fe_nested_templates_{}_{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("scratch dir");
    let mut failures = Vec::new();
    for (case, source, expected) in CASES {
        let input = dir.join(format!("{case}.js"));
        let report = dir.join(format!("{case}.run.json"));
        fs::write(&input, source).expect("write case");
        let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
            .args([
                "run",
                "--input",
                input.to_str().expect("utf8"),
                "--extension-id",
                "nested-templates",
                "--out",
                report.to_str().expect("utf8"),
            ])
            .output()
            .expect("frankenctl should execute");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let line = stderr
                .lines()
                .find(|line| line.contains("failed for"))
                .unwrap_or(&stderr)
                .to_string();
            failures.push(format!("{case}: {line}"));
            continue;
        }
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(&report).expect("read report")).expect("report json");
        let console = report["console_output"]
            .as_array()
            .expect("console_output")
            .iter()
            .map(|entry| entry["message"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        if console != *expected {
            failures.push(format!("{case}: expected {expected:?}, got {console:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
