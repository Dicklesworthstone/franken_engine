//! bd-9vouw.167: a pending async call saves the live part of its register
//! window, not the whole window.
//!
//! Every `await` saved the activation's full register window: 4,096
//! registers on the V8 lane, which HybridRouter picks for any program with
//! `await`, about 268 KB of the budget per pending call. 2,000 async calls
//! pending at once asked for 537,006,182 bytes of the 512 MiB budget and were
//! refused (this file's first case, on the tree before the change). The
//! window's live prefix is saved now and resume clears the rest. Expected
//! strings are Node v22.2.0's output for the same programs.
//!
//! No-claim: a suspended generator and a cross-module async call still keep a
//! whole register file of the lane's width.

use frankenengine_engine::HybridRouter;

fn eval_with_console(source: &str) -> (String, String) {
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let console = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n");
    (outcome.value, console)
}

/// 2,000 async calls pending at once beside 3,000 globals, then resumed.
#[test]
fn two_thousand_pending_async_calls_fit_the_v8_lane_budget() {
    let mut source: String = (0..3000).map(|i| format!("var v{i} = {i};\n")).collect();
    source.push_str(
        "var ps = [];\n\
         async function wait(i) { await null; return i + v2999; }\n\
         for (var i = 0; i < 2000; i++) ps.push(wait(i));\n\
         Promise.all(ps).then(function (r) { console.log(r.length, r[0], r[1999]); });\n\
         ps.length + ' ' + typeof ps[1999].then;",
    );
    let (value, console) = eval_with_console(&source);
    assert_eq!(value, "2000 function");
    assert_eq!(console, "2000 2999 4998");
}

/// Locals live across several awaits survive each resumption.
#[test]
fn locals_survive_repeated_suspension() {
    let source = "async function step(i) {\n\
           var a = i * 2, b = 'k' + i, c = [i, i + 1];\n\
           await null;\n\
           var d = a + c[1];\n\
           await Promise.resolve(1);\n\
           return b + ':' + d + ':' + c.length;\n\
         }\n\
         var ps = [];\n\
         for (var i = 0; i < 1000; i++) ps.push(step(i));\n\
         Promise.all(ps).then(function (r) { console.log(r[0], r[999], r.length); });\n\
         'started';";
    let (value, console) = eval_with_console(source);
    assert_eq!(value, "started");
    assert_eq!(console, "k0:1:2 k999:2998:2 1000");
}
