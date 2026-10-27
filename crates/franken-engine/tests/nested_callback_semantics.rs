//! Guest callbacks invoked by builtins (forEach, map, reduce, find, ...).
//!
//! Same-module synchronous callbacks now run as nested calls above a native
//! boundary frame instead of an isolated activation that snapshotted and
//! cleared the whole execution state per call. These tests pin what that must
//! preserve:
//! - throws reach the caller's `try` and nothing below the builtin;
//! - `try`/`finally` inside callbacks;
//! - nested and recursive callbacks;
//! - thisArg and `arguments`;
//! - generators;
//! - early exits;
//! - native faults.
//!
//! Expected strings are what Node v22.2.0 prints for `String(eval(source))`.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn throws_cross_the_builtin_to_the_callers_handler() {
    check(
        "var r; try { [1, 2, 3].forEach(function (x) { if (x === 2) throw new Error('at ' + x); }); \
         r = 'none'; } catch (e) { r = e.message; } r",
        "at 2",
    );
    check(
        "var calls = 0; var r; try { [1, 2, 3].forEach(function () { calls++; null.x; }); } \
         catch (e) { r = e instanceof TypeError; } r + ',' + calls",
        "true,1",
    );
    check(
        "var out = []; try { try { [1].forEach(function () { throw 'inner'; }); } \
         finally { out.push('outer-finally'); } } catch (e) { out.push('caught ' + e); } out.join()",
        "outer-finally,caught inner",
    );
}

#[test]
fn handlers_inside_callbacks_stay_inside() {
    check(
        "[1, 2, 3].map(function (x) { try { if (x === 2) throw x * 10; return x; } \
         catch (e) { return 'c' + e; } }).join()",
        "1,c20,3",
    );
    check(
        "var log = []; var r; try { [1, 2].forEach(function (x) { try { if (x === 2) throw 'boom'; } \
         finally { log.push('f' + x); } }); } catch (e) { r = e; } log.join() + '|' + r",
        "f1,f2|boom",
    );
}

#[test]
fn nested_recursive_and_generator_callbacks() {
    check(
        "[[1, 2], [3]].map(function (row) { return row.map(function (v) { return v * 2; })\
         .reduce(function (a, b) { return a + b; }, 0); }).join()",
        "6,6",
    );
    check(
        "function depth(n) { return n === 0 ? 0 : 1 + [n - 1].map(depth)[0]; } depth(50)",
        "50",
    );
    check(
        "var total = 0; function* g() { yield 1; yield 2; } \
         [0, 0].forEach(function () { for (var v of g()) total += v; }); total",
        "6",
    );
}

#[test]
fn receivers_arguments_and_early_exits() {
    check(
        "var o = { k: 3 }; [1, 2].map(function (x) { return this.k * x + arguments.length; }, o).join()",
        "6,9",
    );
    check(
        "var found = [4, 9, 16].find(function (x) { return x > 5; }); \
         var idx = [4, 9, 16].findIndex(function (x) { return x > 10; }); \
         var some = [1, 2].some(function (x) { return x > 1; }); found + ',' + idx + ',' + some",
        "9,2,true",
    );
}

#[test]
fn scope_inert_methods_and_array_callbacks_preserve_results() {
    check(
        "function add(a,b) { return a+b; } var o={add}; \
         [o.add(20,22), add.call(o,19,23), add.apply(o,[18,24]), \
          [1,2,3,4].map(x=>x*3).filter(x=>x>6).reduce((a,b)=>a+b,0), \
          [1,2,3].every(x=>x>0), [1,2,3].findIndex(x=>x>1)].join('|')",
        "42|42|42|21|true|1",
    );
    check(
        "function make() { let kept = 40; return [x=>x+2, ()=>kept]; } \
         var fs=make(); var before=fs[1](); \
         var result=[1,2,3].map(fs[0]).join(); \
         before+'|'+result+'|'+fs[1]()",
        "40|3,4,5|40",
    );
}

#[test]
fn scope_inert_callbacks_keep_coercion_and_caught_errors() {
    check(
        "var seen=[]; function add(x) { return x+1; } \
         var obj={valueOf(){seen.push('coerce'); return 41;}}; \
         var first=[obj].map(add)[0]; \
         try { [1n].map(add); } catch(e) { seen.push(e instanceof TypeError); } \
         first+'|'+seen.join()+'|'+[2].map(add)[0]",
        "42|coerce,true|3",
    );
    check(
        "var seen=[]; function add(x) { return x+1; } \
         var obj={valueOf(){seen.push('coerce'); throw 'stop';}}; \
         try { [obj,2].map(add); } catch(e) { seen.push(e); } \
         seen.join()+'|'+[3].map(add)[0]",
        "coerce,stop|4",
    );
}
