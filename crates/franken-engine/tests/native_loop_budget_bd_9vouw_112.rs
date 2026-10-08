//! bd-9vouw.112: native element loops over a guest-chosen length stay inside
//! the instruction budget.
//!
//! Array.prototype methods loop natively over 0..ToLength(length), and an
//! array-like's length (or a real array's, `a.length = 2 ** 32 - 1`) is the
//! guest's choice. The holes of such a loop cost nothing else, so
//! `Array.prototype.includes.call({ length: 2 ** 40 }, 1)` ran for days past
//! any budget. Each hole a native read visits now counts against the
//! instruction budget, apart from the reported instruction count.
//!
//! copyWithin no longer buffers its source range, which aborted the process
//! for such a length; it copies element by element as the spec does.
//!
//! No-claim: present elements are bounded by the memory budget that holds
//! them, not charged per visit; loops that only write (`fill`) end at the
//! budget through the writes' own accounting.

#![forbid(unsafe_code)]

use std::time::{Duration, Instant};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const BUDGET: u64 = 100_000;

fn run(source: &str) -> Result<ExecutionResult, InterpreterError> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "native-loop-budget.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "native-loop-budget.js"),
        &LoweringContext::new("budget-trace", "budget-decision", "budget-policy"),
    )
    .expect("lowers")
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = BUDGET;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    InterpreterCore::new(config, "native-loop-budget").execute(&module)
}

fn console(result: &ExecutionResult) -> String {
    result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Each loop ends at the budget. Before this change, on main (723cfac0c,
/// frankenctl drill): copyWithin on the array-like and indexOf/join on the
/// sparse real array ran past 120 s; the array-like includes, join, fill,
/// reverse and find already ended at the budget and stay covered here.
#[test]
fn loops_over_a_guest_chosen_length_end_at_the_budget() {
    let huge = "{ length: 2 ** 40 }";
    let cases = [
        format!("Array.prototype.includes.call({huge}, 1);"),
        format!("Array.prototype.join.call({huge});"),
        format!("Array.prototype.copyWithin.call({huge}, 1, 0);"),
        format!("Array.prototype.reverse.call({huge});"),
        format!("Array.prototype.find.call({huge}, function () {{ return false; }});"),
        format!("Array.prototype.fill.call({huge}, 0);"),
        "var a = []; a.length = 2 ** 32 - 1; a.indexOf(1);".to_string(),
        "var a = []; a.length = 2 ** 32 - 1; a.join();".to_string(),
        "var a = [1]; a.length = 2 ** 32 - 1; a.lastIndexOf(2);".to_string(),
        // A DIRECT call reaches the generic copyWithin loop with no inline
        // callback context, so only a per-step charge stops it (v0.3.0 review).
        "var a = []; a.length = 2 ** 32 - 1; a.copyWithin(0, 1);".to_string(),
        "var o = { length: 2 ** 53 - 1, copyWithin: Array.prototype.copyWithin }; \
         o.copyWithin(1, 0);"
            .to_string(),
        // Below the string limit, so only the budget can stop it.
        "Array.prototype.toLocaleString.call({ length: 10000000 });".to_string(),
    ];
    for source in cases {
        let started = Instant::now();
        let outcome = run(&source);
        assert!(
            matches!(
                outcome,
                Err(InterpreterError::BudgetExhausted { budget: BUDGET, .. })
            ),
            "{source}: {outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{source} took {:?}",
            started.elapsed()
        );
    }
}

/// Ordinary arrays are unaffected, and a hole read is not an instruction:
/// `includes(9)` reads 997 holes, `includes(1)` stops at index 0, and both
/// report the same instruction count.
#[test]
fn present_elements_and_reported_counts_are_unchanged() {
    let result = run(
        "var a = [1, 2, 3]; console.log(a.indexOf(3), a.includes(2), a.join('-'), \
                      [3, 1, 2].reverse().join(), [1, , 3].includes(undefined));",
    )
    .expect("runs under the budget");
    assert_eq!(console(&result), "2 true 1-2-3 2,1,3 true");

    let scan = |needle: u32| {
        run(&format!(
            "var a = [1, 2, 3]; a.length = 1000; console.log(a.includes({needle}));"
        ))
        .expect("runs under the budget")
    };
    let (full, early) = (scan(9), scan(1));
    assert_eq!(
        (console(&full), console(&early)),
        ("false".into(), "true".into())
    );
    assert_eq!(full.instructions_executed, early.instructions_executed);
}

/// copyWithin copies one element at a time (it buffered the whole source
/// range, and `copyWithin.call({ length: 2 ** 40 }, 1, 0)` aborted the
/// process allocating it). Overlapping ranges still copy correctly, and a
/// hole deletes its target as in Node v22.2.0 (it wrote `undefined`).
#[test]
fn copy_within_copies_in_place_without_a_buffer() {
    let result = run(
        "console.log([1, 2, 3, 4, 5].copyWithin(0, 3).join(), [1, 2, 3, 4, 5].copyWithin(1, 0).join(), \
         [1, 2, 3, 4, 5].copyWithin(-2, -3, -1).join(), JSON.stringify(Object.keys([1, , 3, 4].copyWithin(2, 0))), \
         [1, , 3, 4].copyWithin(2, 0).length, \
         JSON.stringify(Array.prototype.copyWithin.call({ length: 5, 3: 1 }, 0, 3)));",
    )
    .expect("runs under the budget");
    assert_eq!(
        console(&result),
        r#"4,5,3,4,5 1,1,2,3,4 1,2,3,3,4 ["0","2"] 4 {"0":1,"3":1,"length":5}"#
    );
}

/// Native copies sized by the guest are charged before they are made
/// (v0.3.0 release review). `new Blob(parts)` accumulated every part in a
/// native buffer that was charged only once complete, so 64 parts of one
/// 8 MiB blob allocated 512 MiB natively before failing; it now fails at the
/// part that crosses the 64 MiB budget, so the request it reports stays near
/// the budget. `Intl.Segmenter#segment` checks its per-segment native
/// transient against the budget before splitting.
#[test]
fn guest_sized_native_copies_are_charged_before_allocation() {
    let outcome = run("var big = new Blob([new Uint8Array(8 * 1024 * 1024)]); \
         new Blob(new Array(64).fill(big));");
    match outcome {
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes,
            max_bytes,
            ..
        }) => assert!(
            requested_bytes < max_bytes.saturating_mul(2),
            "blob parts were copied past the budget before the check: \
             requested {requested_bytes} of {max_bytes}"
        ),
        other => panic!("blob of 64 x 8 MiB parts: {other:?}"),
    }

    // Under the budget it still works: 4 x 8 MiB parts make a 32 MiB blob.
    let result = run("var big = new Blob([new Uint8Array(8 * 1024 * 1024)]); \
         console.log(new Blob(new Array(4).fill(big)).size);")
    .expect("a 32 MiB blob fits a 64 MiB budget");
    assert_eq!(console(&result), "33554432");

    // The segmenter refuses up front: the request it reports is the
    // 96-bytes-per-code-unit transient, not a later per-record charge.
    let outcome = run("new Intl.Segmenter().segment('a'.repeat(2 ** 20));");
    match outcome {
        Err(InterpreterError::MemoryBudgetExceeded {
            requested_bytes, ..
        }) => assert!(
            requested_bytes >= (1u64 << 20) * 96,
            "segmenter failed after splitting, not on the pre-check: requested {requested_bytes}"
        ),
        other => panic!("segmenting 2^20 code units under a 64 MiB budget: {other:?}"),
    }
}

/// `TextEncoder#encodeInto` into a view whose buffer was transferred (length
/// 0, byte offset kept, backing empty) writes nothing; it sliced
/// `bytes[4..4]` of an empty backing and panicked (v0.3.0 release review).
#[test]
fn encode_into_a_detached_view_does_not_panic() {
    let result = run(
        "var ab = new ArrayBuffer(8), v = new Uint8Array(ab, 4); ab.transfer(); \
         var r = new TextEncoder().encodeInto('x', v); \
         console.log(r.read, r.written, v.length);",
    )
    .expect("encodeInto into a detached view runs");
    assert_eq!(console(&result), "0 0 0");
}
