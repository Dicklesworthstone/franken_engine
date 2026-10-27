//! bd-9vouw.438: node:events' static helpers: listenerCount(emitter,
//! name), getEventListeners, setMaxListeners(n, ...targets),
//! getMaxListeners and addAbortListener(signal, listener). Libraries that
//! share an AbortSignal across many requests call
//! `events.setMaxListeners(n, signal)`. Each was undefined, so calling it
//! threw "expected function, got undefined". Expected lines are Node
//! v22.2.0's, its error codes and messages included. An EventTarget's
//! listener list is not exposed (getEventListeners(target) is a typed
//! refusal) and is not exercised here.

use std::process::Command;

const PROGRAM: &str = r#"import events, { EventEmitter } from 'node:events';
const out = [];
const t = (name, f) => {
  try { out.push(name + ' = ' + JSON.stringify(f())); } catch (e) { out.push(name + ' ! ' + e.name + ' ' + (e.code || '') + ' ' + e.message); }
};
const e = new EventEmitter();
e.on('x', () => {});
e.on('x', () => {});
t('listenerCount', () => events.listenerCount(e, 'x'));
t('getEventListeners', () => events.getEventListeners(e, 'x').length);
t('setMaxListeners emitter', () => { events.setMaxListeners(3, e); return e.getMaxListeners(); });
t('getMaxListeners emitter', () => events.getMaxListeners(e));
const c = new AbortController();
t('setMaxListeners signal', () => { events.setMaxListeners(7, c.signal); return events.getMaxListeners(c.signal); });
t('getMaxListeners fresh signal', () => events.getMaxListeners(new AbortController().signal));
t('setMaxListeners negative', () => events.setMaxListeners(-1, e));
t('setMaxListeners string', () => events.setMaxListeners('5', e));
t('getEventListeners bad', () => events.getEventListeners(5, 'x'));
t('addAbortListener type', () => typeof events.addAbortListener(c.signal, () => {}));
t('addAbortListener bad listener', () => events.addAbortListener(c.signal, 5));
let fired = 0;
const c2 = new AbortController();
events.addAbortListener(c2.signal, () => { fired++; });
c2.abort();
t('addAbortListener fired', () => fired);
const c3 = new AbortController();
c3.abort();
events.addAbortListener(c3.signal, () => { console.log('already aborted: listener ran in a microtask'); });
out.push('sync end');
console.log(out.join('\n'));
"#;

const EXPECTED: &[&str] = &[
    "listenerCount = 2",
    "getEventListeners = 2",
    "setMaxListeners emitter = 3",
    "getMaxListeners emitter = 3",
    "setMaxListeners signal = 7",
    "getMaxListeners fresh signal = 10",
    "setMaxListeners negative ! RangeError ERR_OUT_OF_RANGE The value of \"setMaxListeners\" is out of range. It must be >= 0. Received -1",
    "setMaxListeners string ! TypeError ERR_INVALID_ARG_TYPE The \"setMaxListeners\" argument must be of type number. Received type string ('5')",
    "getEventListeners bad ! TypeError ERR_INVALID_ARG_TYPE The \"emitter\" argument must be an instance of EventEmitter or EventTarget. Received type number (5)",
    "addAbortListener type = \"object\"",
    "addAbortListener bad listener ! TypeError ERR_INVALID_ARG_TYPE The \"listener\" argument must be of type function. Received type number (5)",
    "addAbortListener fired = 1",
    "sync end",
    "already aborted: listener ran in a microtask",
];

#[test]
fn events_static_helpers_match_node() {
    let root = tempfile::tempdir().expect("temp dir");
    let entry = root.path().join("events_statics.mjs");
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
            "events-static-helpers",
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


/// Literal CommonJS requests and cross-file destructuring must reach the same
/// retained Events factory as an aliased require. Otherwise a later file
/// reinitializes the constructor, loses settings and replaces captured helpers.
#[test]
fn native_commonjs_events_helpers_share_cached_state_across_sources() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::LaneChoice;
    use frankenengine_engine::execution_orchestrator::LabFixtureExecutionOrchestratorExt as _;
    use frankenengine_engine::execution_orchestrator::{
        ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
    };

    let root = tempfile::tempdir().expect("native events root");
    let helper = r#"
const E = require('node:events');
const { once } = require('events');
module.exports = {
    E, once,
    readMax: function () { return E.defaultMaxListeners; },
    readCapture: function () { return E.captureRejections; }
};
"#;
    std::fs::write(root.path().join("native-events-helper.cjs"), helper).unwrap();
    let source = r#"
const E = require('events');
const load = require;
const alias = load('node:events');
const emitter = new E();
const listener = function () {};
emitter.on('data', listener);
console.log('helpers', E === alias, E.EventEmitter === E,
    E.listenerCount(emitter, 'data'), E.getEventListeners(emitter, 'data')[0] === listener);
(async function () {
    const iterator = E.on(emitter, 'data');
    const next = iterator.next();
    emitter.emit('data', 7, 'x');
    const item = await next;
    await iterator.return();
    console.log('iterator', item.value.join(','), emitter.listenerCount('data'));
    E.setMaxListeners(17, emitter);
    const controller = new AbortController();
    E.setMaxListeners(21, controller.signal);
    let aborted = 0;
    const disposable = E.addAbortListener(controller.signal, function () { aborted++; });
    controller.abort();
    console.log('settings', E.getMaxListeners(emitter), E.getMaxListeners(controller.signal),
        aborted, typeof disposable);
    const wait = E.once(emitter, 'done');
    emitter.emit('done', 42);
    console.log('once', (await wait)[0]);
    const emit = E.prototype.emit;
    E.defaultMaxListeners = 31;
    E.captureRejections = true;
    E.once = function () { return 91; };
    const helper = require('./native-events-helper.cjs');
    console.log('shared', helper.E === E, helper.once === E.once, helper.once(),
        helper.readMax(), helper.readCapture(), E.prototype.emit === emit);
})().catch(function (error) { console.log('FAIL', error.message); });
"#;
    let entry = root.path().join("app.cjs");
    std::fs::write(&entry, source).unwrap();
    let package = ExtensionPackage {
        extension_id: "native-events-values".into(),
        source: source.into(),
        source_file: Some(entry.display().to_string()),
        module_root: Some(root.path().display().to_string()),
        // Promise listeners and a live signal need no scheduling authority.
        capabilities: vec!["module_load".into(), "builtin".into()],
        version: "1.0.0".into(),
        metadata: Default::default(),
    };
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let result = ExecutionOrchestrator::new(OrchestratorConfig {
            force_lane: Some(lane),
            parse_goal: ParseGoal::Script,
            commonjs_entry: true,
            ..OrchestratorConfig::default()
        })
        .execute(&package)
        .unwrap_or_else(|error| panic!("native events execute in {lane:?}: {error}"));
        let actual: Vec<_> = result.console_output.iter()
            .map(|entry| entry.message.as_str()).collect();
        assert_eq!(actual, [
            "helpers true true 1 true",
            "iterator 7,x 1",
            "settings 17 21 1 object",
            "once 42",
            "shared true true 91 31 true true",
        ], "{lane:?}");
    }
}
