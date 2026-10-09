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
