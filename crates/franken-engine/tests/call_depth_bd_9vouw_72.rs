//! bd-9vouw.72: plain JS recursion is no longer capped at 256 frames.
//!
//! A JS-to-JS call pushes a `CallFrame` and stays in the dispatch loop, so it
//! costs no native stack; the default call depth is now 10,000 (Node v22.2.0
//! takes 9,642 frames of the one-argument `d` below). A callee's register
//! window starts right above its caller's verified window instead of a fixed
//! `max_registers` stride, and the register file is capped at the larger of
//! 257 full-width windows (the old extent) and 16 registers per configured
//! frame, which bounds the register carriers the memory budget does not
//! charge. Nested run loops (builtin callbacks, accessors, async calls)
//! recurse on the native stack and keep a separate cap of 256. Each call's
//! memory accounting no longer walks the whole stack, and every program here
//! checks the running estimate against the full recompute afterwards.
//! Expected strings are Node v22.2.0's output for the same programs.
//!
//! The deep programs run with a 10M instruction budget: the default 100k
//! containment budget ends them before the depth limit.
//!
//! No-claim: recursion through a builtin callback or an async function stops
//! at 256 native levels (Node: thousands); a frame with ~100 live registers
//! reaches ~1,500 frames before the register-file cap.
//!
//! No mocks: real source through the parser, lowering and `InterpreterCore`
//! for both profiles, and `HybridRouter` for the native-stack cases.

#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "call-depth.js".into(),
                text: format!("const log = console.log;\n{source}"),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("call-depth source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "call-depth.js"),
        &LoweringContext::new("depth-trace", "depth-decision", "depth-policy"),
    )
    .expect("call-depth source must lower")
    .ir3
}

/// Both native profiles (256 and 4096 registers per full-width window), with
/// the instruction budget raised so the depth limit is what a program meets.
fn cores() -> impl Iterator<Item = InterpreterCore> {
    [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ]
    .into_iter()
    .map(|mut config| {
        config.instruction_budget = 10_000_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "call-depth")
    })
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for mut core in cores() {
        let result = core
            .execute(&module)
            .unwrap_or_else(|error| panic!("`{source}` failed: {error}"));
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected, "{source}");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "{source}"
        );
    }
}

const D: &str = "function d(n) { return n === 0 ? 0 : 1 + d(n - 1); }";

/// The bead's repro: `d(2000)` failed with "depth 256 exceeds max 256".
#[test]
fn plain_recursion_goes_past_256_frames() {
    assert_output(&format!("{D} log(d(2000), d(9000));"), &["2000 9000"]);
}

#[test]
fn mutual_recursion_goes_past_256_frames() {
    assert_output(
        "function even(n) { return n === 0 ? true : odd(n - 1); }
         function odd(n) { return n === 0 ? false : even(n - 1); }
         log(even(5001), odd(5001), even(8000));",
        &["false true true"],
    );
}

/// Recursive construction and traversal of a 3,000-node list, with the
/// objects each frame allocates surviving the recursion.
#[test]
fn recursive_build_and_walk_of_a_deep_list() {
    assert_output(
        "function build(n) { return n === 0 ? null : { v: n, next: build(n - 1) }; }
         function sum(node) { return node === null ? 0 : node.v + sum(node.next); }
         function depth(node) { let d = 0; while (node) { d++; node = node.next; } return d; }
         const list = build(3000);
         log(depth(list), sum(list));",
        &["3000 4501500"],
    );
}

/// Frames with several live locals: each callee window starts above its
/// caller's live registers, so no caller local is clobbered by a callee.
#[test]
fn callee_windows_do_not_clobber_caller_locals() {
    assert_output(
        "function w(n) {
           const a = n + 1, b = a * 2, c = b - 3, e = c + a, f = e * b, g = f - c, h = g + e, i = h - f, j = i + g, k = j - h;
           if (n === 0) return a + b + c + e + f + g + h + i + j + k;
           return w(n - 1) + (k - j + i - h + g - f + e - c + b - a);
         }
         log(w(1500));",
        &["-13528134742"],
    );
}

/// A call with more arguments than the callee has registers, a rest
/// parameter, and `arguments`, all at depth.
#[test]
fn extra_arguments_rest_and_arguments_object_at_depth() {
    assert_output(
        "function r(n, ...rest) { return n === 0 ? rest.length + arguments.length : r(n - 1, 1, 2, 3, 4, 5); }
         function x(n) { return n === 0 ? arguments.length : x(n - 1, 'a', 'b', 'c'); }
         log(r(1000, 9), x(1000));",
        &["11 4"],
    );
}

/// Uncaught runaway recursion still ends the run at the configured depth,
/// and the same core runs the next program normally.
#[test]
fn runaway_recursion_fails_closed_at_the_depth_limit() {
    let runaway = lower(&format!("{D} d(1e6);"));
    let next = lower(&format!("{D} log(d(100));"));
    for mut core in cores() {
        match core.execute(&runaway) {
            Err(InterpreterError::StackOverflow { depth, max }) => {
                assert_eq!((depth, max), (10_000, 10_000));
            }
            other => panic!("runaway recursion must overflow the stack: {other:?}"),
        }
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        let result = core.execute(&next).expect("the core must run again");
        assert_eq!(result.console_output[0].message, "100");
    }
}

/// A call with 60 arguments needs 60 contiguous registers (a call with more
/// than 64 stages them in an argument array, bd-9vouw.254), so `wide`'s
/// verified window is over 100 wide: in the 256-register profile the
/// register-file cap (160,016 slots at the default depth) binds long before
/// 10,000 frames. 100 frames run; 5,000 fail closed instead of growing the
/// file.
#[test]
fn wide_frames_meet_the_register_file_cap_before_the_depth_limit() {
    let arguments = vec!["n"; 60].join(", ");
    let wide = format!(
        "function zero() {{ return 0; }}
         function wide(n) {{ if (n === 0) return 0; return 1 + wide(n - 1) + zero({arguments}); }}"
    );
    let shallow = lower(&format!("{wide} log(wide(100));"));
    let deep = lower(&format!("{wide} wide(5000);"));
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = 10_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "call-depth-wide");
    let result = core.execute(&shallow).expect("100 wide frames fit");
    assert_eq!(result.console_output[0].message, "100");
    match core.execute(&deep) {
        Err(InterpreterError::StackOverflow { depth, max }) => {
            assert!(depth < 5_000 && max + 1 == depth, "{depth} {max}");
        }
        other => panic!("5,000 wide frames must meet the register-file cap: {other:?}"),
    }
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

/// A throw unwinds 3,000 frames to the outer catch, and one through 1,500
/// frames runs every `finally` on the way.
#[test]
fn throws_unwind_deep_stacks() {
    assert_output(
        "function f(n) { if (n === 0) throw new Error('bottom'); return f(n - 1); }
         let m = 'none';
         try { f(3000); } catch (e) { m = e.message; }
         function g(n) { try { return n === 0 ? h() : g(n - 1); } finally { cleanups++; } }
         function h() { throw 7; }
         let cleanups = 0; let c = 'none';
         try { g(1500); } catch (e) { c = e; }
         log(m, c, cleanups);",
        &["bottom 7 1501"],
    );
}

/// Each of 2,000 frames holds a closure over its own binding; a generator
/// runs at the bottom.
#[test]
fn closures_and_a_generator_at_depth() {
    assert_output(
        "function g(n) {
           const x = n; const h = () => x;
           if (n === 0) { function* gen() { yield h(); yield 5; } return [...gen()].join('+'); }
           return g(n - 1) + (h() === n ? '' : '!');
         }
         log(g(2000));",
        &["0+5"],
    );
}

/// 1,000 nested derived-class constructions: each `super()` initializes the
/// `this` of the frame below it.
#[test]
fn derived_constructors_at_depth() {
    assert_output(
        "class A { constructor(n) { this.n = n; } }
         class B extends A { constructor(n) { super(n); this.m = n > 0 ? new B(n - 1).m + 1 : 0; } }
         log(new B(1000).m);",
        &["1000"],
    );
}

/// A builtin callback 3,000 frames deep, and async recursion (which moves the
/// whole stack out and back at each await) below the native cap. Each async
/// call nests a native run loop, so these run on a thread with the stack the
/// engine provisions for its own execution thread.
#[test]
fn callbacks_and_async_calls_at_depth() {
    assert_output(
        "function d(n) { return n === 0 ? [1, 2, 3].map((x) => x * 2).join() : d(n - 1); }
         log(d(3000));",
        &["2,4,6"],
    );
    std::thread::Builder::new()
        .name("call-depth-async".into())
        .stack_size(256 * 1024 * 1024)
        .spawn(|| {
            assert_output(
                "async function a(n) { return n === 0 ? 'done' : a(n - 1); }
                 a(200).then((v) => log(v));",
                &["done"],
            );
            assert_output(
                "async function b(n) { if (n === 0) { await null; return 0; } return 1 + await b(n - 1); }
                 b(200).then((v) => log(v));",
                &["200"],
            );
        })
        .expect("async depth thread")
        .join()
        .expect("async recursion below the native cap must succeed");
}

/// Recursion through a builtin callback re-enters the run loop natively, so it
/// keeps the 256-level cap and fails closed, without overflowing the native
/// stack, past it.
#[test]
fn callback_recursion_keeps_the_native_run_loop_cap() {
    let source = |n: u32| {
        format!("function f(n) {{ return n === 0 ? 0 : [n].map((x) => f(x - 1))[0] + 1; }} f({n});")
    };
    let shallow = HybridRouter::default()
        .eval_with_instruction_budget(&source(100), 10_000_000)
        .expect("100 callback levels fit");
    assert_eq!(shallow.value, "100");
    let deep = HybridRouter::default().eval_with_instruction_budget(&source(1_000), 10_000_000);
    let message = format!("{deep:?}");
    assert!(
        message.contains("call stack overflow"),
        "1,000 callback levels must fail closed: {message}"
    );
}

/// A stack overflow is a catchable RangeError with V8's message, as in every
/// JS engine; an async function whose body overflows rejects with it. The
/// depth limit still holds afterwards: catching one unwinds the frames it
/// counted.
#[test]
fn stack_overflow_is_a_catchable_range_error() {
    assert_output(
        &format!(
            "{D}
             let caught = 'none';
             try {{ d(1e6); }} catch (e) {{
               caught = [e instanceof RangeError, e.name, e.message].join('|');
             }}
             log(caught, d(100));
             function r(n) {{ return r(n + 1); }}
             async function b() {{ r(0); }}
             b().catch((e) => log('rejected', e instanceof RangeError));"
        ),
        &[
            "true|RangeError|Maximum call stack size exceeded 100",
            "rejected true",
        ],
    );
}
