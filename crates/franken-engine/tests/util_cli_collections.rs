//! Native shared-util regressions. The reference-host suite lives in
//! scripts/test_util_module.cjs; it is not a substitute for these runs.

use std::process::Command;

fn run_util_program(preamble: &str, goal: &str, body: &str) -> Vec<String> {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join(if goal == "module" {
        "entry.mjs"
    } else {
        "entry.cjs"
    });
    std::fs::write(&entry, format!("{preamble}\n{body}")).expect("write source");
    let report_path = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input"])
        .arg(&entry)
        .args([
            "--goal",
            goal,
            "--extension-id",
            "util-cli-collections",
            "--out",
        ])
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
        .map(|entry| {
            entry["message"]
                .as_str()
                .expect("console message")
                .to_owned()
        })
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

#[test]
fn native_util_and_assert_share_unordered_collection_semantics() {
    let body = r#"
const a = new Map(); const b = new Map();
for (let i = 0; i < 64; i++) a.set('package-' + i, { version: i });
for (let i = 63; i >= 0; i--) b.set('package-' + i, { version: i });
console.log(util.isDeepStrictEqual(a, b));
b.get('package-32').version = -1;
console.log(util.isDeepStrictEqual(a, b));
const shared = { x: 1 };
const left = new Map([[shared, 'a'], [{ x: 1 }, 'b'], ['primitive', 1]]);
const right = new Map([[shared, 'b'], [{ x: 1 }, 'a'], ['primitive', 1]]);
console.log(util.isDeepStrictEqual(left, right));
const loopA = new Map(); const loopB = new Map();
loopA.set('self', loopA); loopB.set('self', loopB);
console.log(util.isDeepStrictEqual(loopA, loopB));
console.log(util.isDeepStrictEqual(new Set([1, '1', NaN, null]), new Set([null, NaN, '1', 1])));
console.log(util.isDeepStrictEqual(new Map([[NaN, -0]]), new Map([[NaN, 0]])));
assert.deepStrictEqual(left, right);
assert.deepStrictEqual(loopA, loopB);
console.log('assert-shared-util');
"#;
    let expected = vec![
        "true",
        "false",
        "true",
        "true",
        "true",
        "false",
        "assert-shared-util",
    ];
    for (preamble, goal) in [
        (
            "const util = require('node:util'); const assert = require('node:assert/strict');",
            "script",
        ),
        (
            "import * as util from 'node:util'; import assert from 'node:assert/strict';",
            "module",
        ),
    ] {
        assert_eq!(run_util_program(preamble, goal, body), expected);
    }
}

#[test]
fn native_parse_env_is_shared_by_cjs_esm_and_shadowed_global_programs() {
    let body = r#"
const Object = 'guest shadow';
const String = 'guest shadow';
const parsed = parse('export PORT = 3000\nMESSAGE="first\\nsecond # literal"\nPORT=4000\nEMPTY=\nLITERAL=${HOME}');
console.log(parsed.PORT + ':' + typeof parsed.PORT);
console.log(JSON.stringify(parsed.MESSAGE));
console.log(JSON.stringify(parsed.EMPTY));
console.log(parsed.LITERAL);
console.log(globalThis.Object.keys(parsed).join(','));
const special = parse('__proto__=safe\nconstructor=ordinary\nZ=last\nA=first');
console.log(globalThis.Object.getPrototypeOf(special) === globalThis.Object.prototype);
console.log(globalThis.Object.prototype.hasOwnProperty.call(special, '__proto__'));
console.log(special.constructor);
console.log(globalThis.Object.keys(special).join(','));
console.log(JSON.stringify(parse('A="unclosed # literal\nB=next')));
console.log(JSON.stringify(parse('A="one\r\ntwo"\r\nB=three')));
console.log(globalThis.Object.keys(parse('\uE000=bmp\n\u{10000}=astral')).join(':'));
try { parse(7); } catch (error) { console.log(error.name + ':' + error.code); }
console.log(JSON.stringify(parse('FRESH=one')));
console.log(JSON.stringify(parse('FRESH=two')));
"#;
    let expected = vec![
        "4000:string",
        r#""first\nsecond # literal""#,
        r#""""#,
        "${HOME}",
        "EMPTY,LITERAL,MESSAGE,PORT",
        "true",
        "false",
        "ordinary",
        "A,Z,constructor",
        r#"{"A":"\"unclosed # literal","B":"next"}"#,
        r#"{"A":"one\ntwo","B":"three"}"#,
        "\u{E000}:\u{10000}",
        "TypeError:ERR_INVALID_ARG_TYPE",
        r#"{"FRESH":"one"}"#,
        r#"{"FRESH":"two"}"#,
    ];
    for (preamble, goal) in [
        ("const { parseEnv: parse } = require('util');", "script"),
        ("const { parseEnv: parse } = require('node:util');", "script"),
        ("import { parseEnv as parse } from 'node:util';", "module"),
        ("import util from 'util'; const parse = util.parseEnv;", "module"),
    ] {
        assert_eq!(run_util_program(preamble, goal, body), expected);
    }
}
