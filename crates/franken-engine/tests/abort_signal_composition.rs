//! Native composed-signal cancellation, not the JavaScript events facade.
//! Shared cases have Node reference outputs. NATIVE_* cases retain the
//! engine's documented synchronous listener-error policy (Node reports those
//! errors asynchronously). Every case runs on both profiles with GC stress.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn execute(
    source: &str,
    v8_profile: bool,
    stress: Option<u64>,
    budget: u64,
) -> Result<Vec<String>, InterpreterError> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "abort-composition.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("abort regression parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "abort-composition.js"),
        &LoweringContext::new("abort-composition", "cancel", "builtin-only"),
    )
    .expect("abort regression lowers")
    .ir3;
    let mut config = if v8_profile {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    config.instruction_budget = budget;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "abort-composition");
    core.set_gc_stress_interval(stress);
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "abort graph accounting (v8={v8_profile}, GC={stress:?})"
    );
    result.map(|result| {
        result
            .console_output
            .into_iter()
            .map(|entry| entry.message)
            .collect()
    })
}

fn check(source: &str, expected: &[&str]) {
    for v8_profile in [false, true] {
        for stress in [None, Some(7)] {
            let actual = execute(source, v8_profile, stress, 1_000_000_000)
                .expect("native cancellation completes");
            assert_eq!(actual, expected, "v8={v8_profile}, GC={stress:?}");
        }
    }
}

const NESTED: &str = r#"
const controller = new AbortController();
const first = AbortSignal.any([controller.signal]);
const second = AbortSignal.any([first]);
const third = AbortSignal.any([second]);
const reason = { token: 42 };
const order = [];
first.addEventListener('abort', () => order.push('first'));
second.addEventListener('abort', () => order.push('second'));
third.addEventListener('abort', () => order.push('third'));
controller.abort(reason);
console.log(first.aborted, second.aborted, third.aborted);
console.log(first.reason === reason, second.reason === reason, third.reason === reason);
try { third.throwIfAborted(); } catch (error) { console.log(error === reason); }
console.log(order.join(','));
"#;

#[test]
fn nested_compositions_abort_with_the_original_reason() {
    check(NESTED, &["true true true", "true true true", "true", "first,second,third"]);
}

const ROOT_ORDER: &str = r#"
const root = new AbortController();
const a = AbortSignal.any([root.signal]);
const child = AbortSignal.any([a]);
const b = AbortSignal.any([root.signal]);
const join = AbortSignal.any([b, child, a]);
const order = [];
root.signal.addEventListener('abort', () => {
  console.log(a.aborted, child.aborted, b.aborted, join.aborted);
  order.push('root');
});
a.addEventListener('abort', () => order.push('a'));
child.addEventListener('abort', () => order.push('child'));
b.addEventListener('abort', () => order.push('b'));
join.addEventListener('abort', () => order.push('join'));
root.abort('end');
console.log(order.join(','));
"#;

#[test]
fn flattened_registration_order_is_not_breadth_first_graph_order() {
    check(ROOT_ORDER, &["true true true true", "root,a,child,b,join"]);
}

const REENTRANT: &str = r#"
const a = new AbortController();
const b = new AbortController();
const first = AbortSignal.any([a.signal, b.signal]);
const last = AbortSignal.any([first]);
const winning = { first: true };
let calls = 0;
a.signal.addEventListener('abort', () => {
  console.log(first.aborted, last.aborted, last.reason === winning);
  b.abort('too late');
});
first.addEventListener('abort', () => { calls++; a.abort('again'); });
last.addEventListener('abort', () => calls++);
a.abort(winning);
console.log(calls, first.reason === winning, last.reason === winning, b.signal.reason);
"#;

#[test]
fn reentrant_other_source_cannot_replace_a_descendants_winning_reason() {
    check(REENTRANT, &["true true true", "2 true true too late"]);
}

const STOPPED_SOURCE: &str = r#"
const root = new AbortController();
const a = AbortSignal.any([root.signal]);
const b = AbortSignal.any([a]);
const target = new EventTarget();
let calls = 0;
target.addEventListener('work', () => calls++, { signal: b });
root.signal.addEventListener('abort', event => event.stopImmediatePropagation());
root.signal.addEventListener('abort', () => console.log('wrong source listener'));
b.addEventListener('abort', () => console.log('dependent', b.aborted));
root.abort();
target.dispatchEvent(new Event('work'));
console.log(calls, b.reason.name);
"#;

#[test]
fn stopping_the_source_event_does_not_skip_dependent_algorithms() {
    check(STOPPED_SOURCE, &["dependent true", "0 AbortError"]);
}

const CLEANUP: &str = r#"
const root = new AbortController();
const a = AbortSignal.any([root.signal]);
const b = AbortSignal.any([a]);
const target = new EventTarget();
let calls = 0;
const listener = () => calls++;
target.addEventListener('work', listener, { signal: b });
target.dispatchEvent(new Event('work'));
b.addEventListener('abort', () => target.dispatchEvent(new Event('work')));
root.abort();
target.addEventListener('work', () => calls += 10, { signal: b });
target.dispatchEvent(new Event('work'));
console.log(calls);
"#;

#[test]
fn dependent_listener_removal_precedes_its_abort_event() {
    check(CLEANUP, &["1"]);
}

const DIAMOND: &str = r#"
const root = new AbortController();
const a = AbortSignal.any([root.signal, root.signal]);
const b = AbortSignal.any([root.signal]);
const joined = AbortSignal.any([a, b, root.signal, a]);
const never = AbortSignal.any([]);
const nestedNever = AbortSignal.any([never]);
let calls = 0;
joined.addEventListener('abort', () => calls++);
root.abort(null);
root.abort('later');
console.log(joined.aborted, joined.reason === null, calls, never.aborted, nestedNever.aborted);
"#;

#[test]
fn duplicate_roots_diamonds_and_empty_compositions() {
    check(DIAMOND, &["true true 1 false false"]);
}

const PREABORTED: &str = r#"
for (const reason of [null, false, 0, '']) {
  const controller = new AbortController();
  const first = AbortSignal.abort(reason);
  const combined = AbortSignal.any([controller.signal, first, AbortSignal.abort('later')]);
  const nested = AbortSignal.any([combined]);
  let calls = 0;
  nested.addEventListener('abort', () => calls++);
  controller.abort('too late');
  console.log(nested.aborted, nested.reason === reason, calls);
}
try { AbortSignal.any([AbortSignal.abort('early'), {}]); }
catch (error) { console.log(error instanceof TypeError); }
"#;

#[test]
fn first_preaborted_reason_wins_but_every_input_is_validated() {
    check(PREABORTED, &["true true 0", "true true 0", "true true 0", "true true 0", "true"]);
}

const CREATED_DURING_ABORT: &str = r#"
const root = new AbortController();
const a = AbortSignal.any([root.signal]);
const b = AbortSignal.any([a]);
root.signal.addEventListener('abort', () => {
  const late = AbortSignal.any([b]);
  late.addEventListener('abort', () => console.log('wrong late event'));
  console.log(late.aborted, late.reason === root.signal.reason);
});
root.abort('reason');
console.log(b.aborted, b.reason);
"#;

#[test]
fn composing_during_dispatch_observes_already_published_state() {
    check(CREATED_DURING_ABORT, &["true true", "true reason"]);
}

const ROOTED_DURING_CALLBACKS: &str = r#"
const root = new AbortController();
const log = [];
(() => {
  const a = AbortSignal.any([root.signal]);
  const b = AbortSignal.any([a]);
  a.addEventListener('abort', () => log.push('a'));
  b.addEventListener('abort', () => log.push('b'));
})();
root.signal.addEventListener('abort', () => {
  for (let n = 0; n < 40; n++) {
    const allocation = { values: [n, n + 1] };
    if (allocation.values[0] !== n) throw new Error('bad allocation');
  }
  log.push('root');
});
root.abort();
console.log(log.join(','));
"#;

#[test]
fn pending_descendants_remain_rooted_while_a_source_callback_allocates() {
    check(ROOTED_DURING_CALLBACKS, &["root,a,b"]);
}

const DEEP: &str = r#"
const root = new AbortController();
let last = root.signal;
let calls = 0;
for (let n = 0; n < 64; n++) {
  last = AbortSignal.any([last, last]);
  last.addEventListener('abort', () => calls++);
}
root.abort(42);
console.log(last.aborted, last.reason, calls);
"#;

#[test]
fn deep_duplicate_compositions_do_not_require_recursive_abort_dispatch() {
    check(DEEP, &["true 42 64"]);
}

const NATIVE_SOURCE_ERROR: &str = r#"
const root = new AbortController();
const a = AbortSignal.any([root.signal]);
const b = AbortSignal.any([a]);
const target = new EventTarget();
let calls = 0;
const log = [];
const original = { failure: true };
root.signal.addEventListener('abort', () => { throw original; });
root.signal.addEventListener('abort', () => log.push('source-after'));
a.addEventListener('abort', () => { log.push('a'); throw new Error('second'); });
b.addEventListener('abort', () => log.push('b'));
target.addEventListener('work', () => calls++, { signal: b });
try { root.abort('canceled'); } catch (error) { console.log(error === original); }
target.dispatchEvent(new Event('work'));
root.abort('again');
console.log(log.join(','), calls, b.reason);
"#;

#[test]
fn guest_listener_errors_do_not_skip_dependent_cancellation_or_replace_first_error() {
    check(NATIVE_SOURCE_ERROR, &["true", "source-after,a,b 0 canceled"]);
}

const NATIVE_UNDEFINED_ERROR: &str = r#"
const root = new AbortController();
const a = AbortSignal.any([root.signal]);
const b = AbortSignal.any([a]);
let calls = 0;
a.addEventListener('abort', () => { throw undefined; });
b.addEventListener('abort', () => calls++);
let caught = false;
try { root.abort(false); } catch (error) { caught = error === undefined; }
console.log(caught, calls, b.aborted, b.reason === false);
"#;

#[test]
fn thrown_undefined_is_preserved_after_all_dependent_steps() {
    check(NATIVE_UNDEFINED_ERROR, &["true 1 true true"]);
}

#[test]
fn host_budget_refusal_is_not_downgraded_to_a_guest_listener_error() {
    let source = "const root = new AbortController(); \
        const child = AbortSignal.any([root.signal]); \
        root.signal.addEventListener('abort', () => { while (true) {} }); \
        root.abort();";
    for v8_profile in [false, true] {
        let error = execute(source, v8_profile, None, 10_000)
            .expect_err("a nonterminating listener must exhaust the host budget");
        assert!(matches!(error, InterpreterError::BudgetExhausted { .. }));
    }
}
