//! Native shared-util regressions. The reference-host suite lives in
//! scripts/test_util_module.cjs; it is not a substitute for these runs.

use std::process::Command;

fn run_util_program(preamble: &str, goal: &str, body: &str) -> Vec<String> {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join(if goal == "module" { "entry.mjs" } else { "entry.cjs" });
    std::fs::write(&entry, format!("{preamble}\n{body}")).expect("write source");
    let report_path = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input"])
        .arg(&entry)
        .args(["--goal", goal, "--extension-id", "util-cli-collections", "--out"])
        .arg(&report_path)
        .output()
        .expect("execute native engine");
    assert!(
        output.status.success(),
        "native {goal} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report_path).expect("read report")).expect("report JSON");
    report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .map(|entry| entry["message"].as_str().expect("console message").to_owned())
        .collect()
}

#[test]
fn parse_args_negation_and_group_indices_share_the_native_cjs_and_esm_factory() {
    let body = r#"
const args = ['-vc', '--no-color', '-ofile', '--', '--color'];
const options = {
  verbose: { type: 'boolean', short: 'v' },
  color: { type: 'boolean', short: 'c', multiple: true, default: [true] },
  output: { type: 'string', short: 'o' }
};
const result = util.parseArgs({ args, options, allowNegative: true, allowPositionals: true, tokens: true });
if (Object.getPrototypeOf(result.values) !== null) throw new Error('values prototype');
console.log(JSON.stringify(result.values));
console.log(JSON.stringify(result.tokens.map(function (token) { return [token.kind, token.name, token.index]; })));
console.log(JSON.stringify(result.positionals));
console.log(JSON.stringify(args));
const unknown = util.parseArgs({ args: ['--no-color'], allowNegative: true, strict: false });
console.log(unknown.values.color);
try {
  util.parseArgs({ args: ['--no-color=yes'], options, allowNegative: true });
} catch (error) { console.log(error.code); }
try {
  util.parseArgs({ args: ['--no-output'], options, allowNegative: true });
} catch (error) { console.log(error.code); }
const group = util.parseArgs({ args: ['-' + 'v'.repeat(64), '-o', 'tail'], options, tokens: true });
console.log(group.tokens.length + ':' + group.tokens[64].index + ':' + group.values.output);
"#;
    let expected = vec![
        r#"{"verbose":true,"color":[true,false],"output":"file"}"#,
        r#"[["option","verbose",0],["option","color",0],["option","color",1],["option","output",2],["option-terminator",null,3],["positional",null,4]]"#,
        r#"["--color"]"#,
        r#"["-vc","--no-color","-ofile","--","--color"]"#,
        "false",
        "ERR_PARSE_ARGS_INVALID_OPTION_VALUE",
        "ERR_PARSE_ARGS_UNKNOWN_OPTION",
        "65:1:tail",
    ];
    for (preamble, goal) in [
        ("const util = require('node:util');", "script"),
        ("import * as util from 'node:util';", "module"),
    ] {
        assert_eq!(run_util_program(preamble, goal, body), expected);
    }
}
