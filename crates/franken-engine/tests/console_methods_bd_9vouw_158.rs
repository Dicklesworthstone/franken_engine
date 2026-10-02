//! bd-9vouw.158: the `console` methods besides log/error/warn/info.
//!
//! Only log, info, warn and error existed, so a package calling
//! console.debug, assert, count, group, time, dir or trace threw "expected
//! function, got undefined". They are now on the console object (and
//! lowered like console.log when called directly), with Node's output:
//! debug and dirxml are log, dir inspects its first argument, count prints
//! "label: n", group indents later output two spaces, assert writes
//! "Assertion failed[: ...]" to stderr and never throws, trace writes
//! "Trace: ..." to stderr, time/timeLog/timeEnd print "label: <elapsed>".
//! NODE_STDOUT is Node v22.2.0's stdout for PROGRAM and NODE_STDERR_LINES
//! the stderr lines that carry no process id or stack.
//!
//! table draws Node's box table (internal/cli_table) for arrays, objects,
//! Maps and Sets. NODE_TABLE_STDOUT is Node's stdout for TABLE.
//!
//! No-claim: console.table does not preview Map or Set iterators (Node does);
//! cell widths count code points, not East Asian display width; trace prints
//! no stack frames; elapsed times come from the engine's deterministic
//! instruction-tick clock (performance.now()), not wall time; Node's
//! process-warning prefix "(node:PID)" for unknown count/time labels is not
//! reproduced.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    ConsoleLevel, InterpreterConfig, InterpreterCore,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"console.debug('debug', 1, { a: 1 });
console.dirxml('dirxml', [1, 2]);
console.dir('a string');
console.dir({ a: { b: { c: { d: 1 } } } });
console.count(); console.count(); console.count('x'); console.count(undefined); console.countReset(); console.count();
console.group('outer', 1);
console.log('in outer');
console.group();
console.log('two\nlines');
console.info({ k: [1, 2] });
console.groupEnd();
console.groupCollapsed('collapsed');
console.debug('in collapsed');
console.groupEnd();
console.groupEnd();
console.groupEnd();
console.log('back');
console.assert(true, 'not shown');
console.assert(1 === 1);
console.clear();
const methods = ['debug', 'trace', 'dir', 'dirxml', 'time', 'timeEnd', 'timeLog', 'count', 'countReset', 'group', 'groupCollapsed', 'groupEnd', 'assert', 'clear'];
console.log(methods.map(function (m) { return typeof console[m]; }).join());
const { debug } = console; debug('destructured', debug.name, console.count.length);
console['count']('dynamic'); console[['count'][0]]('dynamic');
console.assert(false, '%s is %d', 'x', 5);
console.assert(0);
console.assert(null, { a: 1 });
console.trace('here', 2);
try { console.assert(false, 'still runs'); console.log('assert did not throw'); } catch (e) { console.log('threw', e); }"#;

const NODE_STDOUT: &str = r#"debug 1 { a: 1 }
dirxml [ 1, 2 ]
'a string'
{ a: { b: { c: [Object] } } }
default: 1
default: 2
x: 1
default: 3
default: 1
outer 1
  in outer
    two
    lines
    { k: [ 1, 2 ] }
  collapsed
    in collapsed
back
function,function,function,function,function,function,function,function,function,function,function,function,function,function
destructured debug 0
dynamic: 1
dynamic: 2
assert did not throw"#;

const NODE_STDERR_LINES: &[&str] = &[
    r#"Assertion failed: x is 5"#,
    r#"Assertion failed"#,
    r#"Assertion failed { a: 1 }"#,
    r#"Trace: here 2"#,
    r#"Assertion failed: still runs"#,
];

const TIMING: &str = r#"console.time('t');
let total = 0;
for (let i = 0; i < 50; i++) total += i;
console.timeLog('t', 'step', total);
console.timeEnd('t');
console.timeEnd('t');
console.time();
console.time();
console.timeEnd();"#;

const TABLE: &str = r#"console.table([{ a: 1, b: 'x' }, { a: 2, c: true }]);
console.table({ r1: { x: 1 }, r2: { y: [1, 2, 3, 4] } });
console.table([1, 'two', { three: 3 }]);
console.table(new Map([['k1', 1], ['k2', { v: 2 }]]));
console.table(new Set(['a', 'b']));
console.table([{ a: 1, b: 2 }, { a: 3, b: 4 }], ['a']);
console.table('not an object');
console.table([[1, 2], [3, 4]]);
console.table({ 10: 'ten', 2: 'two', b: { 1: 'x', a: 'y' } });
console.table([{ deep: { a: 1, b: 2, c: 3 }, list: [1, 2, 3, 4, 5] }]);
console.group('grouped');
console.table([{ a: 1 }]);
console.groupEnd();
console.table([]);"#;

const NODE_TABLE_STDOUT: &str = r#"┌─────────┬───┬─────┬──────┐
│ (index) │ a │ b   │ c    │
├─────────┼───┼─────┼──────┤
│ 0       │ 1 │ 'x' │      │
│ 1       │ 2 │     │ true │
└─────────┴───┴─────┴──────┘
┌─────────┬───┬──────────────────────────────┐
│ (index) │ x │ y                            │
├─────────┼───┼──────────────────────────────┤
│ r1      │ 1 │                              │
│ r2      │   │ [ 1, 2, 3, ... 1 more item ] │
└─────────┴───┴──────────────────────────────┘
┌─────────┬───────┬────────┐
│ (index) │ three │ Values │
├─────────┼───────┼────────┤
│ 0       │       │ 1      │
│ 1       │       │ 'two'  │
│ 2       │ 3     │        │
└─────────┴───────┴────────┘
┌───────────────────┬──────┬──────────┐
│ (iteration index) │ Key  │ Values   │
├───────────────────┼──────┼──────────┤
│ 0                 │ 'k1' │ 1        │
│ 1                 │ 'k2' │ { v: 2 } │
└───────────────────┴──────┴──────────┘
┌───────────────────┬────────┐
│ (iteration index) │ Values │
├───────────────────┼────────┤
│ 0                 │ 'a'    │
│ 1                 │ 'b'    │
└───────────────────┴────────┘
┌─────────┬───┐
│ (index) │ a │
├─────────┼───┤
│ 0       │ 1 │
│ 1       │ 3 │
└─────────┴───┘
not an object
┌─────────┬───┬───┐
│ (index) │ 0 │ 1 │
├─────────┼───┼───┤
│ 0       │ 1 │ 2 │
│ 1       │ 3 │ 4 │
└─────────┴───┴───┘
┌─────────┬─────┬─────┬────────┐
│ (index) │ 1   │ a   │ Values │
├─────────┼─────┼─────┼────────┤
│ 2       │     │     │ 'two'  │
│ 10      │     │     │ 'ten'  │
│ b       │ 'x' │ 'y' │        │
└─────────┴─────┴─────┴────────┘
┌─────────┬──────────┬───────────────────────────────┐
│ (index) │ deep     │ list                          │
├─────────┼──────────┼───────────────────────────────┤
│ 0       │ [Object] │ [ 1, 2, 3, ... 2 more items ] │
└─────────┴──────────┴───────────────────────────────┘
grouped
  ┌─────────┬───┐
  │ (index) │ a │
  ├─────────┼───┤
  │ 0       │ 1 │
  └─────────┴───┘
┌─────────┐
│ (index) │
├─────────┤
└─────────┘"#;

/// (stdout lines, stderr messages) of a program.
fn run(source: &str) -> (String, Vec<String>) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "console-methods.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "console-methods.js"),
        &LoweringContext::new("console-trace", "console-decision", "console-policy"),
    )
    .expect("lower")
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "console-methods");
    let result = core.execute(&module).expect("the program runs");
    let stdout = result
        .console_output
        .iter()
        .filter(|entry| matches!(entry.level, ConsoleLevel::Log | ConsoleLevel::Info))
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let stderr = result
        .console_output
        .iter()
        .filter(|entry| matches!(entry.level, ConsoleLevel::Warn | ConsoleLevel::Error))
        .map(|entry| entry.message.clone())
        .collect();
    (stdout, stderr)
}

#[test]
fn console_methods_write_what_node_writes() {
    let (stdout, stderr) = run(PROGRAM);
    assert_eq!(stdout, NODE_STDOUT);
    let first_lines = stderr
        .iter()
        .filter_map(|message| message.lines().next())
        .filter(|line| line.starts_with("Assertion failed") || line.starts_with("Trace:"))
        .collect::<Vec<_>>();
    assert_eq!(first_lines, NODE_STDERR_LINES);
}

#[test]
fn console_table_draws_what_node_draws() {
    let (stdout, stderr) = run(TABLE);
    assert_eq!(stdout, NODE_TABLE_STDOUT);
    assert!(stderr.is_empty(), "{stderr:?}");
}

/// timeLog/timeEnd print "label: <n>ms" (and the extra data); a second
/// timeEnd and a second time('default') only warn.
#[test]
fn console_timers_print_elapsed_time_and_warn_on_unknown_labels() {
    let (stdout, stderr) = run(TIMING);
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3, "{stdout}");
    let elapsed = |line: &str, label: &str| {
        let rest = line.strip_prefix(label).expect("label prefix");
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        rest[..end].parse::<f64>().is_ok_and(|value| value >= 0.0)
            && (rest[end..].starts_with("ms") || rest[end..].starts_with('s'))
    };
    assert!(elapsed(lines[0], "t: "), "{}", lines[0]);
    assert!(lines[0].ends_with(" step 1225"), "{}", lines[0]);
    assert!(elapsed(lines[1], "t: "), "{}", lines[1]);
    assert!(elapsed(lines[2], "default: "), "{}", lines[2]);
    assert_eq!(
        stderr,
        [
            "Warning: No such label 't' for console.timeEnd()",
            "Warning: Label 'default' already exists for console.time()",
        ]
    );
}
