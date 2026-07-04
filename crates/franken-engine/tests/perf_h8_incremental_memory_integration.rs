//! PERF-H8.4 integration test (bd-o4cbn.13.4): memory-accounting telemetry
//! matches the eager reference across real end-to-end program execution.
//!
//! H8.1 replaced the per-execute eager `recompute_estimated_memory_bytes`
//! walk with incremental accounting applied at each write chokepoint. H8.2
//! proved incremental == eager under randomized low-level op sequences
//! (in-source proptest `incremental_memory_estimate_matches_eager`). This
//! file closes the loop end-to-end:
//!
//! 1. Real JS sources are parsed, lowered IR0 -> IR3, and executed through
//!    `InterpreterCore`; after every execution the incremental telemetry
//!    (`estimated_memory_bytes()`) must equal the eager reference walk
//!    (`recompute_estimated_memory_bytes()`).
//! 2. The post-execution telemetry series across the fixed program corpus is
//!    pinned by a checked-in golden (insta snapshot), so a silent change to
//!    the accounting algebra shows up as a reviewable snapshot diff.
//!    (The bead spec's "sampled at key IR3 instructions via the diagnostics
//!    bundle" is not implementable today — no memory metric is plumbed into
//!    `frankenctl runtime diagnostics` — so the series samples at program
//!    granularity through the public interpreter API instead.)
//! 3. A tight 10_000-iteration loop must complete within a generous
//!    wall-clock bound, guarding against the incremental accounting
//!    regressing into per-instruction full-state walks.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use std::collections::BTreeSet;
use std::time::Instant;

/// Mirror of the in-source `test_quickjs_config()`: production
/// `quickjs_defaults` starts with an empty capability set, so executing
/// lowered programs that dispatch, allocate, and call builtins requires
/// granting those capabilities explicitly.
fn h8_test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    config
}

/// Parse, lower, and execute one JS source end-to-end on a fresh core.
/// Returns the core (whose post-execution state carries the telemetry under
/// test) together with the execution result.
fn execute_source(label: &str, source: &str) -> (InterpreterCore, ExecutionResult) {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
        .unwrap_or_else(|err| panic!("program `{label}` should parse: {err:?}"));
    let ir0 = Ir0Module::from_syntax_tree(tree, format!("perf-h8-{label}.js"));
    let ctx = LoweringContext::new(
        format!("trace-perf-h8-{label}"),
        format!("decision-perf-h8-{label}"),
        format!("policy-perf-h8-{label}"),
    );
    let lowering = lower_ir0_to_ir3(&ir0, &ctx)
        .unwrap_or_else(|err| panic!("program `{label}` should lower to IR3: {err:?}"));

    let mut core = InterpreterCore::new(h8_test_config(), format!("trace-perf-h8-{label}"));
    let result = core
        .execute(&lowering.ir3)
        .unwrap_or_else(|err| panic!("program `{label}` should execute: {err:?}"));
    (core, result)
}

/// The fixed corpus: each program exercises a distinct memory-shape surface
/// the incremental accounting must track (register writes, object allocation,
/// property add/remove, arrays, closures, iterator state, nested scopes,
/// string growth). Labels are stable snapshot keys — append rather than
/// rename when extending.
fn representative_programs() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "register_arithmetic",
            "let a = 1; let b = 2; let c = a + b * 10; c;",
        ),
        (
            "object_allocation_and_property_writes",
            "const obj = { a: 1, b: 'two' }; obj.c = true; obj.d = { nested: 4 }; obj.a = 100; obj;",
        ),
        (
            "property_removal",
            "const obj = { keep: 1, drop: 'gone', also: [1, 2, 3] }; delete obj.drop; obj;",
        ),
        (
            "array_growth_and_overwrite",
            "const arr = []; for (let i = 0; i < 32; i++) { arr[i] = i * 2; } arr[0] = 'replaced'; arr.length;",
        ),
        (
            "closure_capture",
            "function make(n) { let acc = n; return function (m) { acc = acc + m; return acc; }; } const add = make(10); add(1); add(2); add(3);",
        ),
        (
            "for_in_iteration",
            "const src = { x: 1, y: 2, z: 3 }; let keys = ''; for (const k in src) { keys = keys + k; } keys;",
        ),
        (
            "for_of_iteration",
            "const src = [10, 20, 30, 40]; let total = 0; for (const v of src) { total = total + v; } total;",
        ),
        (
            "nested_scopes_and_string_growth",
            "let s = ''; { let inner = 'abc'; { let deeper = inner + 'def'; s = deeper + deeper; } } s.length;",
        ),
        // bd-s8u37 corpus extension: builtin surfaces whose direct
        // properties.insert/remove sites previously bypassed the incremental
        // accounting chokepoints.
        (
            "map_set_overwrite_delete",
            "const m = new Map(); m.set('alpha', 1); m.set('beta', 'two'); m.set('alpha', 'replaced-longer-value'); m.delete('beta'); m.size;",
        ),
        (
            "set_add_duplicate_delete",
            "const s = new Set(); s.add('one'); s.add(2); s.add('one'); s.delete(2); s.size;",
        ),
        (
            "set_seed_from_iterable_and_clear",
            "const s = new Set(['a', 'b', 'c', 'a']); const before = s.size; s.clear(); before + s.size;",
        ),
        (
            "map_seed_clear",
            "const m = new Map(); m.set('k1', 'v1'); m.set('k2', 'v2'); m.clear(); m.size;",
        ),
        (
            "array_reverse_including_sparse",
            "const dense = [1, 2, 3, 4]; dense.reverse(); const sparse = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]; delete sparse[3]; sparse.reverse(); dense[0] + sparse.length;",
        ),
        (
            "array_sort_with_holes",
            "const a = ['pear', 'apple', 'fig']; a.sort(); const holed = []; holed[0] = 'z'; holed[3] = 'a'; holed.sort(); a[0] + holed.length;",
        ),
        (
            "array_splice_remove_insert",
            "const a = ['a', 'b', 'c', 'd', 'e']; const removed = a.splice(1, 2, 'X'); a.length + removed.length;",
        ),
        (
            "object_define_property",
            "const o = { existing: 1 }; Object.defineProperty(o, 'added', { value: 'defined-value' }); Object.defineProperty(o, 'existing', { value: 'overwritten' }); o.added;",
        ),
    ]
}

/// Core H8.4 acceptance: after real end-to-end execution of every
/// representative program, the incremental memory telemetry equals the eager
/// full-state reference walk.
#[test]
fn incremental_memory_telemetry_matches_eager_reference_across_programs() {
    for (label, source) in representative_programs() {
        let (core, result) = execute_source(label, source);
        assert!(
            result.instructions_executed > 0,
            "program `{label}` should execute real instructions"
        );
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "program `{label}`: incremental memory telemetry drifted from the eager reference"
        );
    }
}

/// The post-execution telemetry series across the fixed corpus is pinned by
/// a checked-in golden. Any change to the accounting algebra (or to what the
/// interpreter retains after execution) must show up as a reviewed snapshot
/// diff rather than drifting silently.
#[test]
fn memory_telemetry_series_matches_checked_in_golden() {
    let mut lines = Vec::new();
    for (label, source) in representative_programs() {
        let (core, _) = execute_source(label, source);

        // Determinism guard: a fresh core executing the same program must
        // report the identical estimate, otherwise the golden is meaningless.
        let (rerun_core, _) = execute_source(label, source);
        assert_eq!(
            core.estimated_memory_bytes(),
            rerun_core.estimated_memory_bytes(),
            "program `{label}`: telemetry is not deterministic across fresh cores"
        );

        lines.push(format!(
            "{label}: estimated_memory_bytes={}",
            core.estimated_memory_bytes()
        ));
    }
    insta::assert_snapshot!("perf_h8_memory_telemetry_series", lines.join("\n"));
}

/// Tight-loop wall-clock guard: 10_000 iterations mutating live heap state
/// must stay far below the bound. Pre-H8, every execute-reset recomputed the
/// estimate eagerly; a regression re-introducing per-instruction (or
/// per-write full-state) walks shows up here as a gross slowdown. The bound
/// is intentionally generous to stay robust on loaded CI hosts.
#[test]
fn tight_loop_ten_thousand_iterations_within_generous_wall_clock_bound() {
    let source = "const obj = { total: 0 }; const arr = []; \
                  for (let i = 0; i < 10000; i++) { \
                    obj.total = obj.total + i; \
                    arr[i % 64] = obj.total; \
                  } \
                  obj.total;";

    // The loop body executes well past the default 100k instruction budget;
    // grant generous headroom so the test measures wall clock, not budget.
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
        .expect("tight-loop program should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "perf-h8-tight-loop.js");
    let ctx = LoweringContext::new(
        "trace-perf-h8-tight-loop",
        "decision-perf-h8-tight-loop",
        "policy-perf-h8-tight-loop",
    );
    let lowering = lower_ir0_to_ir3(&ir0, &ctx).expect("tight-loop program should lower");
    let mut config = h8_test_config();
    config.instruction_budget = 10_000_000;
    let mut core = InterpreterCore::new(config, "trace-perf-h8-tight-loop");

    let start = Instant::now();
    let result = core
        .execute(&lowering.ir3)
        .expect("tight-loop program should execute");
    let elapsed = start.elapsed();

    assert!(
        result.instructions_executed > 10_000,
        "loop should execute more than one instruction per iteration, got {}",
        result.instructions_executed
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "tight loop: incremental memory telemetry drifted from the eager reference"
    );
    // Generous upper bound (bead acceptance: runtime <= 10 s).
    assert!(
        elapsed.as_secs() < 10,
        "10k-iteration loop took {elapsed:?}, exceeding the generous 10 s bound"
    );
}
