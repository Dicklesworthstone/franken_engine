//! Regression coverage for bd-fqlfw.2.11.3 — the engine heap-object budget
//! lever (`HybridRouter::eval_with_budgets` / `--engine-memory-budget`).
//!
//! Root cause (Mode A of bd-fqlfw.2.11): the baseline interpreter heap is
//! append-only (no live-object reclamation), so the deterministic containment
//! budget of 100_000 heap objects counts *total* allocations. Object-allocating
//! benchmark loops (micro-object-creation, micro/macro-json-roundtrip,
//! memory-allocation-pressure) therefore fail closed with
//! `memory budget exceeded` even though only ~1 object is live at a time, and
//! `--engine-budget` only raised the *instruction* budget — there was no
//! operator lever for the memory budget.
//!
//! Fix (option (b), denominator posture): a heap-object budget override that
//! mirrors the instruction-budget lever. These tests pin three properties:
//!   1. the containment default is UNCHANGED (the bug still reproduces without
//!      the lever) — a regression guard against silently bumping the constant;
//!   2. raising the lever lets the corpus-shaped object loop run to completion
//!      and produce its observable console output;
//!   3. the lever is genuinely wired to the interpreter config (the same
//!      program's outcome flips with the budget), not a no-op.
//!
//! The interpreter heap routes only through `HybridRouter` (a bare lane does
//! not surface console output), so every case drives the public router API.

use frankenengine_engine::{EngineMemoryBudget, HybridRouter};

/// A high instruction budget so the loops below never trip the *instruction*
/// ceiling (the deterministic default is only 100_000 instructions); this
/// isolates the heap-object budget as the variable under test.
const HIGH_INSTRUCTION_BUDGET: u64 = 2_000_000_000;

/// A corpus-shaped loop that allocates one short-lived object per iteration
/// (only ~1 is ever live) and prints a deterministic observable. The iteration
/// count exceeds the 100_000 deterministic heap-object default so the
/// append-only heap crosses the ceiling.
const OBJECT_LOOP_SOURCE: &str = "var n=0; var i=0; \
     while(i<110000){ var obj={a:i,b:i+1}; n=n+1; i=i+1; } \
     console.log(n);";

fn console_text(outcome: &frankenengine_engine::EvalOutcome) -> String {
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn default_heap_budget_trips_on_object_allocating_loop() {
    // Reproduces the bead: with the containment default (no memory override),
    // even a high instruction budget cannot run the loop — the append-only heap
    // crosses 100_000 objects and the runtime fails closed. This is the
    // regression guard that the fix did NOT bump the default constant.
    let mut router = HybridRouter::default();
    let result = router.eval_with_budgets(OBJECT_LOOP_SOURCE, Some(HIGH_INSTRUCTION_BUDGET), None);
    let error = result.expect_err("default heap-object budget must fail closed on the object loop");
    let rendered = error.to_string().to_lowercase();
    assert!(
        rendered.contains("memory budget"),
        "expected a memory-budget fault, got: {error}"
    );
}

#[test]
fn memory_budget_override_lets_object_loop_complete() {
    // The fix: raising the heap-object ceiling lets the same loop run to
    // completion and emit its observable output (the divergence symptom in
    // bd-fqlfw.2.11 was empty stdout because the engine failed before the
    // console.log).
    let mut router = HybridRouter::default();
    let budget = EngineMemoryBudget {
        max_heap_objects: 1_000_000,
        max_total_memory_bytes: 512 * 1024 * 1024,
    };
    let outcome = router
        .eval_with_budgets(
            OBJECT_LOOP_SOURCE,
            Some(HIGH_INSTRUCTION_BUDGET),
            Some(budget),
        )
        .expect("raised heap-object budget must let the object loop complete");
    assert_eq!(
        console_text(&outcome),
        "110000",
        "the loop ran 110000 iterations and printed the count"
    );
}

#[test]
fn memory_budget_override_is_honored_in_both_directions() {
    // Proves the lever is genuinely threaded to the interpreter config rather
    // than a no-op: the SAME 100-object program fails under a tight override and
    // succeeds under a generous one. Stays well under the 100_000-instruction
    // default, so the default instruction budget suffices here.
    const SMALL_LOOP: &str = "var n=0; var i=0; \
         while(i<100){ var obj={a:i}; n=n+1; i=i+1; } \
         console.log(n);";

    let mut tight_router = HybridRouter::default();
    let tight = tight_router.eval_with_budgets(
        SMALL_LOOP,
        None,
        Some(EngineMemoryBudget {
            max_heap_objects: 30,
            max_total_memory_bytes: 512 * 1024 * 1024,
        }),
    );
    let tight_err = tight.expect_err("a 30-object ceiling must fail closed on a 100-object loop");
    assert!(
        tight_err
            .to_string()
            .to_lowercase()
            .contains("memory budget"),
        "expected a memory-budget fault under the tight override, got: {tight_err}"
    );

    let mut generous_router = HybridRouter::default();
    let generous = generous_router
        .eval_with_budgets(
            SMALL_LOOP,
            None,
            Some(EngineMemoryBudget {
                max_heap_objects: 10_000,
                max_total_memory_bytes: 512 * 1024 * 1024,
            }),
        )
        .expect("a 10000-object ceiling must let the same 100-object loop complete");
    assert_eq!(console_text(&generous), "100");
}

#[test]
fn unbudgeted_eval_is_unchanged_by_the_new_lever() {
    // The default `eval` path (no budgets) must behave exactly as before for
    // small programs — the lever is opt-in and must not perturb the default.
    let mut router = HybridRouter::default();
    let outcome = router
        .eval("var o = {a: 1, b: 2}; console.log(o.a + o.b);")
        .expect("small object program runs under the default budget");
    assert_eq!(console_text(&outcome), "3");
}
