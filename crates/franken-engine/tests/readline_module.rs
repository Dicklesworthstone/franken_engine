//! Native execution regressions. Host differential checks are not substitutes.
#![forbid(unsafe_code)]
use std::collections::BTreeMap;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};

fn run(source: &str, lane: LaneChoice) -> Vec<String> {
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane), ..OrchestratorConfig::default()
    });
    let package = ExtensionPackage {
        extension_id: "readline-native".into(), source: source.into(),
        source_file: None, module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(), metadata: BTreeMap::new(),
    };
    orchestrator.execute(&package).expect("native readline completion")
        .console_output.into_iter().map(|line| line.message).collect()
}

#[test]
fn native_readline_iterates_the_shared_stream_and_decoder_with_shadowed_globals() {
    let source = r#"
const readline = require('node:readline');
const {Readable} = require('node:stream');
const Object='guest', String='guest', WeakMap='guest', Date='guest';
const input=Readable.from([Buffer.from([65,13]),Buffer.from([10,195]),Buffer.from([169,10]),'last']);
const rl=readline.createInterface({input,crlfDelay:Infinity});
(async function(){const values=[];for await(const line of rl)values.push(line);
console.log('READLINE_COMPLETE',values.join('|'),rl.closed,readline===require('readline'));})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), ["READLINE_COMPLETE A|é|last true true"]);
    }
}

#[test]
fn native_questions_preserve_abort_identity_and_admit_a_later_answer() {
    let source = r#"
const stream=require('node:stream');const readline=require('readline');
const input=new stream.PassThrough(), control=new AbortController();
const rl=readline.promises.createInterface({input,terminal:false});
const pending=rl.question('stop?',{signal:control.signal});control.abort(false);
(async function(){try{await pending;}catch(error){console.log('QUESTION_ABORT',error.code,error.cause===false);}
const next=rl.question('value?');input.write('42\n');console.log('QUESTION_COMPLETE',await next);
rl.close();console.log('QUESTION_CLEANUP',input.listenerCount('data'),input.destroyed);})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), [
            "QUESTION_ABORT ABORT_ERR true", "QUESTION_COMPLETE 42", "QUESTION_CLEANUP 0 false",
        ]);
    }
}

#[test]
fn native_line_callbacks_support_reentrant_questions_and_complete_without_io_grants() {
    let source = r#"
const stream=require('stream'),readline=require('readline');
const input=new stream.PassThrough();const answers=[];const lines=[];
const rl=readline.createInterface({input,terminal:false,crlfDelay:Infinity});
rl.on('line',line=>lines.push(line));
rl.question('first?',first=>{answers.push(first);rl.question('second?',second=>answers.push(second));});
rl.on('close',()=>console.log('CALLBACK_COMPLETE',answers.join('|'),lines.join('|')));
input.end('one\ntwo\nthree\n');
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), ["CALLBACK_COMPLETE one|two three"]);
    }
}

#[test]
fn native_early_iterator_return_closes_the_interface_without_owning_input_destruction() {
    let source = r#"
const stream=require('stream'),readline=require('readline');
const input=new stream.PassThrough(),rl=readline.createInterface({input,terminal:false});
(async function(){const it=rl[Symbol.asyncIterator]();const first=it.next();input.write('a\nb\n');
console.log('ITERATOR_FIRST',(await first).value);await it.return();
console.log('ITERATOR_CLEANUP',(await it.next()).done,rl.closed,input.destroyed,input.listenerCount('data'));})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), ["ITERATOR_FIRST a", "ITERATOR_CLEANUP true true false 0"]);
    }
}

#[test]
fn native_cli_esm_readline_imports_use_the_canonical_module_factory() {
    let root = tempfile::tempdir().expect("temporary project");
    let entry = root.path().join("main.mjs");
    std::fs::write(&entry,
        "import {createInterface} from 'node:readline/promises';\
         import {Readable} from 'node:stream';\
         const rl=createInterface({input:Readable.from(['a\\r','\\nb\\n']),crlfDelay:Infinity});\
         (async function(){const lines=[];for await(const line of rl)lines.push(line);\
         console.log('ESM_READLINE_COMPLETE',lines.join('|'),rl.closed);})();"
    ).expect("write native ESM program");
    let report = root.path().join("report.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input"]).arg(&entry)
        .args(["--goal", "module", "--extension-id", "readline-esm", "--out"])
        .arg(&report).output().expect("execute native frankenctl");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let payload: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    let lines: Vec<_> = payload["console_output"].as_array().unwrap().iter()
        .map(|line| line["message"].as_str().unwrap()).collect();
    assert_eq!(lines, ["ESM_READLINE_COMPLETE a|b true"]);
}

#[test]
fn native_util_promisify_preserves_readline_answers_abort_and_followup_questions() {
    let source = r#"
const {PassThrough}=require('node:stream');
const {promisify}=require('node:util');
const rl=require('readline').createInterface({input:new PassThrough(),terminal:false});
const ask=promisify(rl.question).bind(rl);
(async function(){
  const first=ask('first?');rl.input.write('42\n');
  console.log('PROMISIFIED_ANSWER',await first);
  const control=new AbortController();
  const pending=ask('cancel?',{signal:control.signal});control.abort(false);
  try{await pending;}catch(error){console.log('PROMISIFIED_ABORT',error.code,error.cause===false);}
  const next=ask('next?');rl.input.write('\n');
  console.log('PROMISIFIED_EMPTY',(await next)==='');
  rl.close();
  try{await ask('closed?');}catch(error){console.log('PROMISIFIED_CLOSED',error.code);}
  console.log('PROMISIFIED_COMPLETE',rl.input.listenerCount('data'),rl.input.destroyed);
})();
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(source, lane), [
            "PROMISIFIED_ANSWER 42",
            "PROMISIFIED_ABORT ABORT_ERR true",
            "PROMISIFIED_EMPTY true",
            "PROMISIFIED_CLOSED ERR_USE_AFTER_CLOSE",
            "PROMISIFIED_COMPLETE 0 false",
        ]);
    }
}
