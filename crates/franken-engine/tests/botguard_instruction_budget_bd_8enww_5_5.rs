#![forbid(unsafe_code)]

//! bd-8enww.5.5 (YTBG-E5): BotGuard-scale instruction budgets + execution logs.
//!
//! Real BotGuard payloads are heavy and adversarial. Without explicit budget
//! ergonomics and observability, a heavy-but-legitimate run looks like a hang and
//! an adversarial infinite loop looks like an arbitrary eval error. This suite
//! pins the budget contract end-to-end through the public `HybridRouter` surface:
//!
//!   AC#1 — a heavy synthetic fixture completes deterministically when the budget
//!          is raised EXPLICITLY (the containment default is never raised silently).
//!   AC#2 — an excessive/infinite loop stops with a deterministic budget error
//!          carrying structured consumed/limit metadata.
//!   AC#3 — budget accounting covers generated `Function` code, loops, AND
//!          exception paths against one shared counter (no hiding cost).
//!   AC#4 — execution logs distinguish a missing builtin, budget exhaustion, and a
//!          semantic mismatch as three separate signals.
//!
//! The "consumed steps" of the execution-budget log come from the public
//! `EvalOutcome.instructions_executed` counter surfaced by this bead; on a
//! budget-exhaustion fault the same pair is carried in the error message
//! ("instruction budget exhausted: consumed/limit"). The per-`Function` breakdown
//! comes from `EvalOutcome.generated_code_audit` (bd-8enww.3.4).
//!
//! Run with the structured log:
//!   cargo test -p frankenengine-engine --test botguard_instruction_budget_bd_8enww_5_5 -- --nocapture

use frankenengine_engine::{EvalOutcome, HybridRouter};

/// Mirrors `baseline_interpreter::DEFAULT_QUICKJS_BUDGET` — the containment
/// default applied to plain `HybridRouter::eval`. Kept as a local constant so a
/// silent change to the engine default is caught by the assertions below.
const DEFAULT_QUICKJS_BUDGET: u64 = 100_000;

/// A generous-but-bounded BotGuard-scale budget for heavy fixtures.
const RAISED_BUDGET: u64 = 50_000_000;

/// The heavy-but-terminating loop from the bd-8enww.5.2 spike (WhiteLynx). Each
/// iteration masks to 16 bits, so the running value stays bounded and the final
/// result is `sum(0..49999) mod 65536 = 1_249_975_000 mod 65536 = 6872`.
const HEAVY_LOOP: &str = "var s=0; for(var i=0;i<50000;i++){s=(s+i)&65535;} s";
const HEAVY_LOOP_RESULT: &str = "6872";

/// The classified stop reason for a single budgeted evaluation — the discriminant
/// an execution-budget log uses to tell failure modes apart.
#[derive(Debug, PartialEq, Eq)]
enum StopReason {
    Completed,
    BudgetExhausted,
    OtherFault,
}

/// One execution-budget log record: budget limit, consumed steps, stop reason,
/// generated-source IDs, and the top-level fixture ID (the Design's log fields).
#[derive(Debug)]
struct BudgetLog {
    fixture_id: String,
    budget_limit: u64,
    consumed_steps: u64,
    stop_reason: StopReason,
    value: Option<String>,
    error_message: Option<String>,
    generated_source_ids: Vec<String>,
}

impl BudgetLog {
    fn render(&self) {
        eprintln!(
            "[bd-8enww.5.5] fixture={} budget_limit={} consumed_steps={} stop_reason={:?} value={:?} generated_source_ids={:?} error={:?}",
            self.fixture_id,
            self.budget_limit,
            self.consumed_steps,
            self.stop_reason,
            self.value,
            self.generated_source_ids,
            self.error_message,
        );
    }
}

/// Parse the `consumed/limit` pair out of a budget-exhaustion fault message
/// (`...instruction budget exhausted: 100000/100000 [trace_id=… policy_id=…]`).
/// The structured fault appends diagnostic context after the limit, so each side
/// is read as its leading run of digits rather than the whole `/`-split token.
fn parse_budget_pair(message: &str) -> Option<(u64, u64)> {
    let tail = message.rsplit("exhausted:").next()?.trim();
    let mut parts = tail.split('/');
    let consumed = leading_u64(parts.next()?)?;
    let limit = leading_u64(parts.next()?)?;
    Some((consumed, limit))
}

/// The leading run of ASCII digits of `token` parsed as a `u64`, ignoring any
/// trailing whitespace or diagnostic context; `None` if it does not start with a
/// digit.
fn leading_u64(token: &str) -> Option<u64> {
    let digits: String = token
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u64>().ok()
}

/// Evaluate `source` under an explicit `budget` and reduce the result to one
/// execution-budget log record.
fn run_logged(fixture_id: &str, source: &str, budget: u64) -> BudgetLog {
    let mut router = HybridRouter::default();
    match router.eval_with_instruction_budget(source, budget) {
        Ok(outcome) => BudgetLog {
            fixture_id: fixture_id.to_string(),
            budget_limit: budget,
            consumed_steps: outcome.instructions_executed,
            stop_reason: StopReason::Completed,
            value: Some(outcome.value.clone()),
            error_message: None,
            generated_source_ids: generated_source_ids(&outcome),
        },
        Err(error) => {
            let message = error.to_string();
            let (stop_reason, consumed) = if message.contains("instruction budget exhausted") {
                let consumed = parse_budget_pair(&message)
                    .map(|(c, _)| c)
                    .unwrap_or(budget);
                (StopReason::BudgetExhausted, consumed)
            } else {
                (StopReason::OtherFault, 0)
            };
            BudgetLog {
                fixture_id: fixture_id.to_string(),
                budget_limit: budget,
                consumed_steps: consumed,
                stop_reason,
                value: None,
                error_message: Some(message),
                generated_source_ids: Vec::new(),
            }
        }
    }
}

fn generated_source_ids(outcome: &EvalOutcome) -> Vec<String> {
    outcome
        .generated_code_audit
        .iter()
        .map(|entry| entry.source_id.clone())
        .collect()
}

/// AC#1: the heavy synthetic fixture exhausts the containment default but
/// completes deterministically once the budget is raised explicitly, and the
/// public outcome surfaces the consumed-step count.
#[test]
fn heavy_fixture_completes_when_budget_raised_and_is_deterministic() {
    // Bounded by the default: same workload, default budget -> deterministic fault.
    let bounded = run_logged("heavy-loop@default", HEAVY_LOOP, DEFAULT_QUICKJS_BUDGET);
    bounded.render();
    assert_eq!(bounded.stop_reason, StopReason::BudgetExhausted);

    // Raised explicitly: completes with the spec-correct value.
    let mut router = HybridRouter::default();
    let first = router
        .eval_with_instruction_budget(HEAVY_LOOP, RAISED_BUDGET)
        .expect("heavy loop must complete once the budget is raised");
    let second = router
        .eval_with_instruction_budget(HEAVY_LOOP, RAISED_BUDGET)
        .expect("heavy loop must complete deterministically on re-run");

    assert_eq!(first.value, HEAVY_LOOP_RESULT);
    assert_eq!(first.value, second.value, "value must be deterministic");
    assert_eq!(
        first.instructions_executed, second.instructions_executed,
        "consumed steps must be deterministic across runs"
    );
    assert!(
        first.instructions_executed > DEFAULT_QUICKJS_BUDGET,
        "the heavy loop must genuinely require more than the default budget (consumed {})",
        first.instructions_executed
    );

    BudgetLog {
        fixture_id: "heavy-loop@raised".to_string(),
        budget_limit: RAISED_BUDGET,
        consumed_steps: first.instructions_executed,
        stop_reason: StopReason::Completed,
        value: Some(first.value),
        error_message: None,
        generated_source_ids: generated_source_ids(&second),
    }
    .render();
}

/// AC#2: an infinite loop stops at the default budget with a deterministic,
/// structured consumed/limit fault.
#[test]
fn infinite_loop_stops_with_deterministic_budget_metadata() {
    const INFINITE: &str = "var s=0; while(true){ s = s + 1; } s";

    let mut router_a = HybridRouter::default();
    let mut router_b = HybridRouter::default();
    let err_a = router_a
        .eval(INFINITE)
        .expect_err("an infinite loop must stop at the budget");
    let err_b = router_b
        .eval(INFINITE)
        .expect_err("an infinite loop must stop deterministically");

    let msg_a = err_a.to_string();
    assert!(
        msg_a.contains("instruction budget exhausted"),
        "stop reason must be a budget fault, got: {msg_a}"
    );
    assert_eq!(
        msg_a,
        err_b.to_string(),
        "the budget fault must be byte-identical across runs"
    );

    let (consumed, limit) =
        parse_budget_pair(&msg_a).expect("budget fault must carry a consumed/limit pair");
    assert_eq!(limit, DEFAULT_QUICKJS_BUDGET, "limit must be the default");
    assert_eq!(consumed, limit, "an infinite loop consumes the full budget");

    BudgetLog {
        fixture_id: "infinite-loop@default".to_string(),
        budget_limit: limit,
        consumed_steps: consumed,
        stop_reason: StopReason::BudgetExhausted,
        value: None,
        error_message: Some(msg_a),
        generated_source_ids: Vec::new(),
    }
    .render();
}

/// AC#3: the shared counter accounts for generated `Function` code, loops, and
/// exception paths — each, on its own, can exhaust the default budget and each
/// completes (with a non-trivial consumed-step count) once the budget is raised.
#[test]
fn budget_accounting_covers_generated_code_loops_and_exceptions() {
    // (a) generated Function code: a heavy loop inside `new Function(...)`.
    const GENERATED: &str = "var f = new Function(\"var s = 0; for (var i = 0; i < 50000; i = i + 1) { s = s + 1; } return s;\"); f();";
    let gen_default = run_logged("generated-loop@default", GENERATED, DEFAULT_QUICKJS_BUDGET);
    gen_default.render();
    assert_eq!(
        gen_default.stop_reason,
        StopReason::BudgetExhausted,
        "generated code must consume the shared budget (no hiding cost)"
    );

    let mut router = HybridRouter::default();
    let gen_ok = router
        .eval_with_instruction_budget(GENERATED, RAISED_BUDGET)
        .expect("generated loop completes once the budget is raised");
    assert_eq!(gen_ok.value, "50000");
    assert!(
        gen_ok.instructions_executed > DEFAULT_QUICKJS_BUDGET,
        "generated-code steps must be counted (consumed {})",
        gen_ok.instructions_executed
    );
    assert!(
        !gen_ok.generated_code_audit.is_empty(),
        "the generated function must appear in the audit trail"
    );

    // (b) exception path: throw+catch on every iteration.
    const EXCEPTIONS: &str = "var n = 0; for (var i = 0; i < 20000; i = i + 1) { try { throw i; } catch (e) { n = n + 1; } } n;";
    let exc_low = run_logged("exception-loop@low", EXCEPTIONS, 5_000);
    exc_low.render();
    assert_eq!(
        exc_low.stop_reason,
        StopReason::BudgetExhausted,
        "exception-path instructions must count against the budget"
    );

    let exc_ok = run_logged("exception-loop@raised", EXCEPTIONS, RAISED_BUDGET);
    exc_ok.render();
    assert_eq!(exc_ok.stop_reason, StopReason::Completed);
    assert_eq!(exc_ok.value.as_deref(), Some("20000"));
    assert!(
        exc_ok.consumed_steps > 20_000,
        "the try/catch overhead must be reflected in consumed steps (consumed {})",
        exc_ok.consumed_steps
    );
}

/// AC#4: missing builtin, budget exhaustion, and semantic mismatch surface as
/// three distinguishable signals in the execution log.
#[test]
fn execution_logs_distinguish_missing_builtin_budget_and_semantic_mismatch() {
    // Budget exhaustion -> Err with the budget fault marker.
    let budget = run_logged(
        "ac4-budget",
        "var s=0; while(true){ s = s + 1; } s",
        DEFAULT_QUICKJS_BUDGET,
    );
    budget.render();
    assert_eq!(budget.stop_reason, StopReason::BudgetExhausted);

    // Missing builtin -> Err, but NOT a budget fault. A bare reference to an
    // undeclared name resolves to `undefined` in this engine (the read does not
    // throw), so a *missing builtin* surfaces when the program tries to USE it:
    // the member access `noSuchBuiltin123.compute` is a property access on
    // `undefined`, a native TypeError — a runtime fault distinct from both a
    // budget exhaustion and a silent value-level mismatch.
    let missing = run_logged(
        "ac4-missing-builtin",
        "var r = noSuchBuiltin123.compute(42); r;",
        RAISED_BUDGET,
    );
    missing.render();
    assert_eq!(
        missing.stop_reason,
        StopReason::OtherFault,
        "a missing builtin must not be mistaken for a budget fault"
    );
    let missing_msg = missing
        .error_message
        .as_deref()
        .expect("a missing builtin must produce an error message");
    assert!(
        !missing_msg.contains("instruction budget exhausted"),
        "a missing builtin must read differently from a budget fault: {missing_msg}"
    );

    // Semantic mismatch -> the eval COMPLETES; the divergence is value-level, not
    // an error at all.
    let semantic = run_logged("ac4-semantic", "var x = 2 + 3; x;", RAISED_BUDGET);
    semantic.render();
    assert_eq!(semantic.stop_reason, StopReason::Completed);
    let value = semantic
        .value
        .as_deref()
        .expect("a completed eval has a value");
    assert_eq!(value, "5");
    let wrong_expectation = "6";
    assert_ne!(
        value, wrong_expectation,
        "a semantic mismatch is detectable by value comparison, with no error"
    );

    // The three signals are pairwise distinct.
    assert_ne!(budget.stop_reason, missing.stop_reason);
    assert_ne!(budget.stop_reason, semantic.stop_reason);
    assert_ne!(missing.stop_reason, semantic.stop_reason);
}

/// The surfaced consumed-step counter is real, not a constant: a heavier program
/// reports strictly more consumed steps than a trivial one.
#[test]
fn consumed_steps_counter_is_monotonic_with_work() {
    let mut router = HybridRouter::default();
    let light = router
        .eval_with_instruction_budget("1 + 1", RAISED_BUDGET)
        .expect("trivial expression completes");
    let heavy = router
        .eval_with_instruction_budget(HEAVY_LOOP, RAISED_BUDGET)
        .expect("heavy loop completes under a raised budget");

    assert!(
        heavy.instructions_executed > light.instructions_executed,
        "heavier work must consume more steps (heavy {} vs light {})",
        heavy.instructions_executed,
        light.instructions_executed
    );
}
