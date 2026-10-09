//! bd-9vouw.441: util.parseArgs, Node v22's command-line parser
//! (short groups, inline and separate values, `--`, multiple, defaults,
//! tokens, strict-mode and config errors). It was missing: "expected
//! function, got undefined". Expected lines are Node v22.2.0's for 26
//! configurations, its ERR_PARSE_ARGS_* and validation texts included.
//! Without `args` the engine parses none (frankenctl passes no
//! command-line arguments); every case here passes `args`.

use std::process::Command;

const PROGRAM: &str = r#"import util from 'node:util';
const cases = [
  { args: ['-f', '--bar', 'b'], options: { f: { type: 'boolean', short: 'f' }, bar: { type: 'string' } } },
  { args: ['-abc'], options: { a: { type: 'boolean', short: 'a' }, b: { type: 'boolean', short: 'b' }, c: { type: 'boolean', short: 'c' } } },
  { args: ['-abvalue'], options: { a: { type: 'boolean', short: 'a' }, bee: { type: 'string', short: 'b' } } },
  { args: ['-ofile.txt', 'pos'], allowPositionals: true, options: { output: { type: 'string', short: 'o' } } },
  { args: ['--name=x', '--name', 'y'], options: { name: { type: 'string', multiple: true } } },
  { args: ['--verbose', '--verbose'], options: { verbose: { type: 'boolean', multiple: true } } },
  { args: [], options: { port: { type: 'string', default: '8080' }, debug: { type: 'boolean', default: false } } },
  { args: ['a', '--', '--not-option', '-x'], allowPositionals: true, options: {} },
  { args: ['--unknown'], options: {} },
  { args: ['--unknown'], allowPositionals: true, options: {} },
  { args: ['-z'], options: {} },
  { args: ['pos'], options: {} },
  { args: ['--name'], options: { name: { type: 'string', short: 'n' } } },
  { args: ['--flag=yes'], options: { flag: { type: 'boolean' } } },
  { args: ['--name', '-v'], options: { name: { type: 'string' }, v: { type: 'boolean' } } },
  { args: ['-n', '--v'], options: { name: { type: 'string', short: 'n' } } },
  { args: ['--anything', 'x', '-q'], strict: false, options: {} },
  { args: ['--name=a', 'b'], strict: false, options: { name: { type: 'string' } } },
  { args: ['-f', 'x', '--', 'y'], tokens: true, allowPositionals: true, options: { f: { type: 'boolean', short: 'f' } } },
  { args: ['-ab', '--c=1'], tokens: true, strict: false, options: { a: { type: 'boolean', short: 'a' } } },
  { args: 'nope', options: {} },
  { args: [], options: { bad: { type: 'number' } } },
  { args: [], options: { bad: { type: 'string', short: 'ab' } } },
  { args: [], options: { bad: { type: 'string', default: 5 } } },
  { args: [], options: { bad: { type: 'boolean', multiple: true, default: [true, 'x'] } } },
  { args: ['--__proto__', 'x'], strict: false, options: {} },
];
for (const config of cases) {
  try {
    const result = util.parseArgs(config);
    console.log(JSON.stringify({ values: { ...result.values }, positionals: result.positionals, tokens: result.tokens }));
  } catch (e) {
    console.log(e.name + ' ' + e.code + ' ' + e.message);
  }
}
"#;

const EXPECTED: &[&str] = &[
    "{\"values\":{\"f\":true,\"bar\":\"b\"},\"positionals\":[]}",
    "{\"values\":{\"a\":true,\"b\":true,\"c\":true},\"positionals\":[]}",
    "{\"values\":{\"a\":true,\"bee\":\"value\"},\"positionals\":[]}",
    "{\"values\":{\"output\":\"file.txt\"},\"positionals\":[\"pos\"]}",
    "{\"values\":{\"name\":[\"x\",\"y\"]},\"positionals\":[]}",
    "{\"values\":{\"verbose\":[true,true]},\"positionals\":[]}",
    "{\"values\":{\"port\":\"8080\",\"debug\":false},\"positionals\":[]}",
    "{\"values\":{},\"positionals\":[\"a\",\"--not-option\",\"-x\"]}",
    "TypeError ERR_PARSE_ARGS_UNKNOWN_OPTION Unknown option '--unknown'",
    "TypeError ERR_PARSE_ARGS_UNKNOWN_OPTION Unknown option '--unknown'. To specify a positional argument starting with a '-', place it at the end of the command after '--', as in '-- \"--unknown\"",
    "TypeError ERR_PARSE_ARGS_UNKNOWN_OPTION Unknown option '-z'",
    "TypeError ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL Unexpected argument 'pos'. This command does not take positional arguments",
    "TypeError ERR_PARSE_ARGS_INVALID_OPTION_VALUE Option '-n, --name <value>' argument missing",
    "TypeError ERR_PARSE_ARGS_INVALID_OPTION_VALUE Option '--flag' does not take an argument",
    "TypeError ERR_PARSE_ARGS_INVALID_OPTION_VALUE Option '--name' argument is ambiguous.",
    "Did you forget to specify the option argument for '--name'?",
    "To specify an option argument starting with a dash use '--name=-XYZ'.",
    "TypeError ERR_PARSE_ARGS_INVALID_OPTION_VALUE Option '-n' argument is ambiguous.",
    "Did you forget to specify the option argument for '-n'?",
    "To specify an option argument starting with a dash use '--name=-XYZ' or '-n-XYZ'.",
    "{\"values\":{\"anything\":true,\"q\":true},\"positionals\":[\"x\"]}",
    "{\"values\":{\"name\":\"a\"},\"positionals\":[\"b\"]}",
    "{\"values\":{\"f\":true},\"positionals\":[\"x\",\"y\"],\"tokens\":[{\"kind\":\"option\",\"name\":\"f\",\"rawName\":\"-f\",\"index\":0},{\"kind\":\"positional\",\"index\":1,\"value\":\"x\"},{\"kind\":\"option-terminator\",\"index\":2},{\"kind\":\"positional\",\"index\":3,\"value\":\"y\"}]}",
    "{\"values\":{\"a\":true,\"b\":true,\"c\":\"1\"},\"positionals\":[],\"tokens\":[{\"kind\":\"option\",\"name\":\"a\",\"rawName\":\"-a\",\"index\":0},{\"kind\":\"option\",\"name\":\"b\",\"rawName\":\"-b\",\"index\":0},{\"kind\":\"option\",\"name\":\"c\",\"rawName\":\"--c\",\"index\":1,\"value\":\"1\",\"inlineValue\":true}]}",
    "TypeError ERR_INVALID_ARG_TYPE The \"args\" argument must be an instance of Array. Received type string ('nope')",
    "TypeError ERR_INVALID_ARG_TYPE The \"options.bad.type\" property must be ('string|boolean'). Received type string ('number')",
    "TypeError ERR_INVALID_ARG_VALUE The property 'options.bad.short' must be a single character. Received 'ab'",
    "TypeError ERR_INVALID_ARG_TYPE The \"options.bad.default\" property must be of type string. Received type number (5)",
    "TypeError ERR_INVALID_ARG_TYPE The \"options.bad.default[1]\" property must be of type boolean. Received type string ('x')",
    "{\"values\":{},\"positionals\":[\"x\"]}",
];

#[test]
fn util_parse_args_matches_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("parse_args.mjs");
    std::fs::write(&entry, PROGRAM).expect("write program");
    let report = root.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            entry.to_str().expect("utf8 path"),
            "--goal",
            "module",
            "--extension-id",
            "util-parse-args",
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
    let printed: Vec<String> = report["console_output"]
        .as_array()
        .expect("console_output")
        .iter()
        .filter_map(|entry| entry["message"].as_str())
        .flat_map(|message| message.split('\n').map(str::to_string))
        .collect();
    assert_eq!(printed, EXPECTED);
}
